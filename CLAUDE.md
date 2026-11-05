# Sandswap

Transparent remote code-execution sandbox for AI agents: one KVM microVM per
workload, virtio-fs rootfs sharing for persistence and agent switching,
hardware-level isolation, zero agent code changes. Go services (gateway, sandlot,
boxout) manage Rust components (the sandvmm VMM and the in-VM warden).

## Where the truth lives

`docs/how-it-works/concepts.md` + `docs/how-it-works/architecture.md` are the
**architecture and terminology canon**: every architectural fact is stated there
once and linked from everywhere else — never restated. This file is an index
plus repo rules, nothing more.

| Topic | Page(s) |
|---|---|
| Architecture, terminology, design principles, topologies | `docs/how-it-works/` (start at `concepts.md`, `architecture.md`) |
| Isolation & swap, threat model, guest-kernel hardening | `docs/how-it-works/isolation-and-swap.md`, `threat-model.md`, `guest-kernel-hardening.md` |
| SandFS volumes, templates, resilience, ownership & DNS | `docs/how-it-works/sandfs.md`, `templates.md`, `resilience.md`, `ownership-and-dns.md` |
| VM lifecycle, vsockguard, egress enabler, namespaces | `docs/how-it-works/vm-lifecycle.md`, `vsockguard.md`, `egress-enabler.md`, `namespaces.md` |
| Wire protocols (gRPC stream, warden vsock frames, VMM API) | `docs/reference/protocols.md` |
| HTTP APIs, MCP tools | `docs/reference/agent-api.md`, `human-api.md`, `mcp-tools.md`; `docs/integration/` |
| All CLI flags / YAML keys / defaults per component | `docs/operations/configuration/{gateway,sandlot,boxout,warden,sandns}.md` |
| Cross-component deployment alignment (stream caps, FileOp 16 MB chain, 50 MB `/agent/file` body) | `docs/operations/configuration/index.md` |
| Storage contract, observability/logging, release, etcd, sandctl | `docs/operations/` (`storage.md`, `observability.md`, `release.md`, …) |
| Deployment prerequisites, baremetal install | `docs/deployment/prerequisites.md`, `install-baremetal.md` |
| Test battery & script framework | `docs/testing/e2e.md`, `script-framework.md` |
| Building from source | `docs/building/` |
| Benchmarks | `docs/benchmark/` |

## Code layout

| Dir | Role |
|---|---|
| `common/` | Shared Go: stream proto (`proto/stream`), config defaults/validation, shell libs for deploy+e2e (`sh/`) |
| `gateway/` | HTTP + gRPC stream server: entry `cmd/main.go`, route wiring `app/`, handlers `handler/`, pool/lease/identity/registry/storage/stream packages |
| `sandlot/` | Per-node daemon, entry `cmd/main.go`; exec role = VM lifecycle (`core/`, `vmm/`), prov role = storage plane (`provision/`) |
| `boxout/` | Privileged VM-lifecycle sidecar for K8s (entry `main.go`, request protocol `server/`) |
| `dns/` | sandns resolver (self-built wire codec, `wire/`) |
| `sandctl/` | Operator CLI |
| `vmm/` | sandvmm — KVM VMM (fork of Cloud Hypervisor), Rust workspace |
| `warden/` | In-VM PID 1 (Rust): raw vsock server, mount/exec, seccomp |
| `kernel/` | Guest kernel build from the pinned cloud-hypervisor tree (source-only) |
| `initramfs/` | Minimal initramfs: warden + busybox |
| `network/vsockguard/` | BPF LSM guard on the warden vsock port |
| `build/` | `build.sh` + per-artifact scripts (`install-deps.sh`, `package-release.sh`, …) |
| `deploy/` | `baremetal/` + `k8s/` deployment scripts |
| `e2e/` | Test battery + matrix runner |
| `security/` | Host hardening & verification scripts, syscall census |
| `examples/` | Agent integrations (openai, eino, mcp, loadgen, …) |

## Build

```bash
sudo bash build/install-deps.sh   # one-shot idempotent prerequisite install
sudo bash build/build.sh all      # build everything + freshness check
bash build/build.sh check         # verify output/ newer than source, no build
# components: kernel warden initramfs vmm go sandctl examples proto rootfs-template ubuntu-rootfs vsockguard
```

`all` fails if any artifact is older than its newest source; the Ubuntu
rootfs-template layer is a chroot package install, so unprivileged `all` keeps
an existing complete template and fails with the sudo hint when none exists.
e2e scripts enforce
the same gate and auto-rebuild (`AUTO_REBUILD=0` to forbid). The warden build
the same gate and auto-rebuild (`AUTO_REBUILD=0` to forbid). The warden build
runs its Rust unit suite first (root additionally runs the ignored
mount/chroot/seccomp tests); `WARDEN_SKIP_TESTS=1` opts out. Kernel compiles
need ≥ 8 GB RAM and a real-disk `TMPDIR` (a /tmp tmpfs ENOSPCs).

## Tests

```bash
sudo bash ./run-round.sh          # full round: e2e + deploy matrix batteries
sudo bash ./run-round.sh --fast   # skip benchmark rows
sudo bash e2e/run-matrix.sh       # e2e battery alone (same flags)
sudo bash deploy/run-matrix.sh    # deploy battery alone
```

Matrix engine: `common/sh/matrix.sh`. Battery contents and framework rules:
`docs/testing/e2e.md`, `docs/testing/script-framework.md`.

## Repo rules for code changes

- **Canon**: `docs/how-it-works/concepts.md` + `architecture.md` define the
  terminology and architecture; facts are stated once there and linked, never
  restated. Legacy wording living in code strings is not drift to "fix".
  Before changing a subsystem, read its page in the map above first — this
  file deliberately carries no subsystem facts.
- **Measured-path logging**: no info-level per-op success logs in
  gateway/sandlot/warden. Debug output is gated with the gate checked BEFORE any
  formatting (slog/fmt args are eager); warden's `debug!` additionally needs the
  `max_level_debug` cargo feature. Details: `docs/operations/observability.md`.
- **Flag changes**: sync the default in the component's `config.Defaults()` AND
  its `docs/operations/configuration/` page. restart-required vs hot-reload is a
  deliberate classification — warden cmdline knobs stay restart-required (guest
  console UART tax).
- **Protocol changes** (stream, vsock frames, VMM API): land on both sides in
  one change with negotiated version windows; `e2e/protocol-version-e2e.sh`
  must pass.
- **Transport caps**: the alignment rules (gateway send-buffer ≥ sandlot
  max-concurrent-commands; the 16 MB FileOp chain across warden and gRPC; the
  50 MB `/agent/file` body limit) live in `docs/operations/configuration/index.md`
  and are authoritative when touching transport code.
- **Language**: English only across code and docs; no plan ids, date stamps, or
  session references in code or comments.

## Hard invariants

- `sandfs_id` is REQUIRED on every per-sandfs endpoint (agents discover ids via
  `GET /agent/sandfs`).
- The service-identity split (uids pinned in `common/sh/runtime.sh`) is
  load-bearing: identity drift is always fatal, never warned.
- The volumes filesystem must be mounted `nosuid,nodev` on every node
  (dev-only escape: sandlot `-allow-insecure-volumes`).
- The guest kernel is built from the pinned `ch-release-v7.2.8` tag only; the
  prebuilt-download path is refused by `kernel/build.sh`.

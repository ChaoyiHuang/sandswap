# Sandswap

Sandswap redefines the tinyVM by decoupling compute from disk: a tinyVM
acts as pure compute(only the kernel and PID 1 warden), while the agent's
rootfs (SandFS) is simply a directory(local or distributed). SandFS is
dynamically mounted into the tinyVM to execute commands with ultra-low
latency—~2.3 ms cold and ~0.96 ms warm. After just as little as 1 ms of
inactivity, SandFS is asynchronously unmounted to free up resources. Under
ideal conditions, benchmarks show a single tinyVM can be reused up to
183 times per second across different AI agents.

One KVM tinyVM per workload, virtio-fs rootfs sharing for persistence and
agent switching, hardware-level isolation, zero agent code changes. Go
services (gateway, sandlot,boxout) manage Rust components (the sandvmm VMM
and the in-VM warden).

Sandswap’s lifelines are ultra-low latency overhead on both the warm and cold
command-execution paths, and secure isolation when reusing tinyVMs across AI
agents. No changes should violate these lifelines. If a modification increases
command execution latency on either the warm or cold path, or compromises the
isolation security of cross-agent tinyVM reuse, human intervention is required
to evaluate the justification for the change.

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
| `common/` | Shared Go: stream proto (`proto/stream`), config defaults/validation, SandFS volume metadata (`sandfs/`), shell libs for deploy+e2e (`sh/`) |
| `gateway/` | HTTP + gRPC stream server: entry `cmd/main.go`, route wiring `app/`, handlers `handler/`, pool/lease/identity/registry/storage/stream packages |
| `sandlot/` | Per-node daemon, entry `cmd/main.go`; exec role = VM lifecycle (`core/`, `vmm/`), prov role = storage plane (`provision/`), refuse-to-start checks (`preflight/`) |
| `boxout/` | Privileged VM-lifecycle sidecar for K8s (entry `main.go`, startup plumbing `runtime/`, request protocol `server/`) |
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

Before each battery/round (and while it runs): check disk (≥ ~5 GB free) and
memory headroom against the next script's prerequisites; if short, clear build
intermediates in cost order — package caches / journals / stale logs, then
`go clean -cache`, then cargo `target/` dirs as the last resort. Never delete
`output/` and the kernel binary for space.

## Repo rules for code changes

- **Code is the authority**: verify every behavioral claim against the
  implementation before asserting it — quote the function, not the doc
  paragraph. Docs state intent and can drift ahead of or behind the code;
  doc prose, comments, and session memory are not evidence of behavior
  (`e2e/check-docs-truth.py` applies the same principle mechanically).
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
- **Script process kills**: kill by target PID, never by cmdline pattern —
  `pkill`/`pgrep -f` also match unrelated processes whose argv merely
  mentions a name (editors, invoking shells, the deploy script itself when
  called by absolute path). PID sources: systemd's registry (`MainPID`, unit
  `cgroup.procs`), the script's own `$!`/pidfile, or kernel identity —
  `/proc/<pid>/exe` resolving to our installed binary (a shared binary such
  as etcd additionally needs a sandswap instance marker in argv). Re-verify
  identity immediately before each kill. `bm_kill_leftover_processes` in
  `deploy/baremetal/deploy-lib.sh` is the one implementation.
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

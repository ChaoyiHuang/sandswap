---
title: VMM Integration
nav_order: 9
parent: Integration
---

# VMM Compatibility Requirements

Sandswap's microVM layer is currently `sandvmm`, a purpose-built fork of
Cloud Hypervisor v28.0 (see the [VMM README](../../vmm/README.md) for
provenance and layout). This page defines what Sandswap actually requires
from that layer, so that a **third-party VMM or hypervisor backend** —
QEMU, Firecracker, or a new build — can be adopted without redesigning
sandlot or the guest.

The requirements come in four layers:

1. the **control-plane contract** sandlot drives;
2. **functional requirements**;
3. the **hypervisor kernel API** the VMM itself sits on;
4. the **guest-side contract** — plus a closing list of what is explicitly
   NOT required.

## 1. Control-plane contract

`vmm/launcher.go` spawns the VMM as a child process and talks to it over a
dual-protocol API (raw control frames + HTTP) on a Unix-domain socket. A
replacement must provide equivalent behavior, either natively or through an
adapter in `sandlot/vmm/`.

### Startup flags

| Flag | Requirement |
|------|-------------|
| `--api-socket <path>` | API on that UDS path (socket removed & re-created by the caller before start) |
| `--seccomp <mode>` | passed from `microvm.vmm_seccomp`: `true` (default — the v28 per-thread allow-lists are installed with Trap/SIGSYS enforcement), `log` (audit mode: a missed rule is logged and allowed), or `false` (explicit escape hatch). `process` is rejected by the sandlot config and the sandvmm CLI (empty per-thread filters). |
| `--log-stderr` | all logs to stderr (the default file path is a sandbox-fork artifact that does not exist in containers) |
| `--api-gid <gid>` | **optional but recommended**: the API sockets are chowned `0660` to the sandvmm identity with this shared-group grant, so the sandlot identity — a group member — can connect; without it the sockets stay `0600` owner-only |
| `--api-token-fd <fd>` | per-VM API authentication token, read from an **inherited fd** (never argv/env/files). Enabled by `microvm.vmm_api_auth` / `-vmm-api-auth` (**default ON** — DAC + `--api-allowed-uid` alone put the canonical socket behind one uid boundary shared with the FUSE passthrough daemon; `false` is the explicit escape hatch for test tooling that drives the socket directly). When enabled, every canonical-socket connection starts with a 34-byte preface `[0xA5][version=1][32-byte challenge]`; the VMM answers `token XOR challenge` and only then accepts the first protocol byte. A sibling sandvmm that binds a fake listener at this VM's socket path cannot answer; a tokenless client is closed on its first two bytes. `sandlot/vmm/launcher.go` passes fd 3 and persists the token `0600` in `<sandbox>/state/api-token` for re-adopt (an unreadable token makes the survivor unattachable — re-adopt fails closed). When the flag is absent the VMM warns and serves unauthenticated (dev/server-tooling shape only); the socket still enforces `--api-allowed-uid` |
| `--sandswap-allowed-root <path>` | **repeatable** deployment path roots: every host path in `vm.create` (kernel/initramfs, serial/console log files, the virtio-fs `shared_dir`, …) must live under one of them, checked lexically AND canonically (a symlink inside a root cannot redirect out of it). The launcher derives them from the volumes dir, kernel/initramfs paths and the per-VM sandbox dir — a compromised sandlot cannot point the VMM at arbitrary host files |
| `--api-allowed-uid <uid>` | the only non-root uid admitted on the canonical socket (the sandlot identity); root tooling is also admitted. This fences off other shared-group local identities (sandprov/sandserv) from querying the real VMM. Embedded mode passes the sandlot's euid; boxout passes its `-allowed-uid` |

Production spawns (identity split on) wrap the exec through `setpriv` — the
full capability drop around the uid transition to the sandvmm identity
(**zero capabilities**), and the launcher verifies all four uid/gid values
in `/proc/<pid>/status` actually landed there before serving. The network
provider creates the persistent TAP owned by that uid and pre-configures its
MTU/bridge/up state, so the VMM's `TUNSETIFF` attach needs no
`CAP_NET_ADMIN` (owner match) and its MTU/enable ioctls are skipped when the
desired state is already in place.

### The dual-protocol API socket

One socket, two protocols, routed per connection by the first byte —
`0x01` → raw frame, ASCII method letter → HTTP. When the token feature is
enabled (`--api-token-fd`, the default), the first 34 bytes on every
connection are the authentication preface described above; the protocol
byte follows it. The preface is transport-independent: it wraps both the
raw and the HTTP framing, so the raw path keeps its raw advantage for the
request/response after the handshake. Both framings pass the same front
dispatcher: the `SO_PEERCRED` peer-uid verdict (plus the token preface)
is the single door into the API — the internal HTTP server behind the
dispatcher listens on a socket that is bound, anchored through
`/proc/self/fd` and unlinked, so no second reachable name exists.

- **raw control frames** — the default transport for the hot ops
  `vm.set-fs` + `sandvmm.ping`: length-prefixed binary, no HTTP/JSON,
  body ≤ 51,200 bytes, per-path ≤ PATH_MAX−1 (budgets byte-aligned with
  the HTTP envelope; the op table is pinned: PING = 0, SET_FS = 1).
- **HTTP/JSON** for the lifecycle endpoints below.

### HTTP endpoints (all `PUT`/`GET` under `/api/v1/`)

| Endpoint | Body (key fields) | Semantics |
|----------|-------------------|-----------|
| `GET /sandvmm.ping` | — | readiness probe; sandlot polls ≤ 30 s before `vm.create` |
| `PUT /vm.create` | full VM config JSON (below) | create VM in paused/created state |
| `PUT /vm.add-vsock` | `{"cid": <u64>}` | attach the vsock device **before boot**; a CID outside 3..=0xFFFFFFFE is refused, and a failed add-vsock **fails the launch** (a guest whose warden can never answer is not worth booting) |
| `PUT /vm.boot` | — | start vCPUs |
| `PUT /vm.set-fs` | `{"id": "<fs device id>", "tag": "<device tag>", "backendfs_config": {"allowed_dirs": [...], "alias": "<fresh per-generation alias>"}}` | **hot-swap the virtio-fs whitelist at runtime** under a new alias (the guest-visible root name; a superseded generation's alias fails ENOENT) — see §2. Two refusals are part of the contract: an **unknown device / immutable-field change / invalid or replayed alias** is a validation error, and the **reuse tripwire** (`previous-tenant-refs`) refuses the swap while the export being swapped away still holds open handles or un-FORGOTTEN inode references (sandlot retries once, then dirty-destroys the VM) |
| `PUT /sandvmm.shutdown` | — | tear the whole VMM process down cleanly |

The `vm.create` payload sandlot sends today:

```json
{
  "cpus":        {"boot_vcpus": N, "max_vcpus": N},
  "memory":      {"size": <bytes>},
  "payload":     {"kernel": "...", "initramfs": "...", "cmdline": "..."},
  "serial":      {"mode": "File", "file": "<sandbox>/serial.log"},
  "console":     {"mode": "File", "file": "<sandbox>/console.log"},
  "fs": [{
    "id": "vfs-rootfs",
    "tag": "sandswap",
    "backendfs_config": {"shared_dir": "<volumes dir>", "read_only": false, "allowed_dirs": []}
  }],
  "net": [ ... ]
}
```

Notes: `read_only` **must** be explicitly false (agent rootfs is writable);
`allowed_dirs` starts empty (no agent visible until the first `vm.set-fs`);
`net` is present only when a network spec was provisioned, and the guest
IP/gateway/DNS/MAC travel via kernel cmdline (`warden.*`), not the net config.

The route table above is the whole device surface, and it is deliberately
closed to *adding* devices: there is **no `vm.add-fs`** route (and `vm.create`
refuses a configuration with more than one fs device), and **no `vm.add-net`**
route either. One share per VM, fixed at boot and re-filtered by `vm.set-fs`;
one NIC per VM, fixed at `vm.create`. The VMM offers no way to attach a second
one of either
([why](../how-it-works/isolation-and-swap.md#4-the-host-side-boundary-the-virtio-fs-filter)).

### Process semantics

- **Outlives its supervisor**: spawned with `Setpgid` and deliberately
  **without** `Pdeathsig`, so a sandlot crash leaves the VM running for
  re-adoption (see [resilience.md](../how-it-works/resilience.md)).
- **Destroy path**: hard kill is `SIGKILL` on the process (spawned in its
  own process group via `Setpgid`, so it is the group leader); graceful
  path is `sandvmm.shutdown`.
- API responses: non-2xx bodies are surfaced verbatim in sandlot errors.

## 2. Functional requirements

| Requirement | Mandatory? | Details |
|-------------|-----------|---------|
| Direct kernel boot (PVH or equivalent) | **yes** | kernel + initramfs + cmdline, no firmware (OVMF/SeaBIOS) |
| virtio-fs, writable, with **runtime `allowed_dirs` hot-swap** | **yes** | PassthroughFs-style share of the host volumes dir, device tag `sandswap`, created once at boot and never hot-plugged. Paths outside the whitelist must resolve to **NotFound** inside the guest — this is the VMM half of cross-agent isolation (the guest-side bind mount is the other half). A VMM without runtime filter updates cannot support sub-second agent switching |
| ↳ **what the filter must hold** | **yes** | The whitelist is a *namespace* control at the share root, not only a visibility filter, and three properties make it hold: (1) **every** name-based operation whose parent is the share root is refused (`mkdir`/`mknod`/`create`/`symlink`/`link`/`unlink`/`rmdir`/all rename forms/xattrs — these handlers do not consult the filter themselves); (2) a guest-supplied name is exactly **one path component** (`.`, `..`, an embedded `/` are refused), because the host `*at()` calls treat the name as a path; (3) no host-side resolution **follows a guest-controlled symlink** — resolve with `RESOLVE_IN_ROOT`-style containment rooted at the parent descriptor plus `O_NOFOLLOW`, hold inodes as descriptors rather than paths, and reopen through `/proc/self/fd` only for regular files and directories. Every refusal answers a real `ENOENT`, so a hidden name and a missing name are indistinguishable. The enumeration, the per-operation table and the tests that pin it are in [Isolation and Swap §4](../how-it-works/isolation-and-swap.md#4-the-host-side-boundary-the-virtio-fs-filter) |
| vsock with **kernel vhost offload** | **yes** | The data path must be offloaded to `/dev/vhost-vsock`: `VHOST_SET_OWNER` → `VHOST_SET_MEM_TABLE` → per-vring `VHOST_SET_VRING_{NUM,ADDR,BASE,KICK,CALL,ERR}` → `VHOST_VSOCK_SET_GUEST_CID` → `VHOST_VSOCK_SET_RUNNING`. KICK must be the **KVM ioeventfd** the PCI transport already registered, CALL must be the **per-queue KVM irqfd** — that is what makes the path zero-VMEXIT. A userspace vsock device adds a VMM wakeup per RX batch and blows the latency budget |
| ACPI power button + S5 → **process exit** | **yes** | warden's shutdown path is `reboot(POWER_OFF)` in the guest → ACPI S5 write to the PM port → the VMM must translate this into process exit. This is what makes mount release after warden death fast; a VMM that keeps running after guest S5 breaks the crash-detection invariants |
| virtio-net on a pre-created TAP | optional | only when the node provisions a network spec; MAC is passed via cmdline |
| virtio-rng | recommended | guest entropy at early boot (every VM has one today: the `vm.create` payload omits `rng` and the API's serde default attaches `/dev/urandom`) |
| Serial + virtio-console to files | yes | `<sandbox>/serial.log` (earlyprintk/panic) and `<sandbox>/console.log` (guest main log, hvc0). The VMM's default console backend is Tty; the API caller must send `console: {mode:"File"}` or guest output leaks to sandvmm stdout. |
| CPUID masking | recommended | hide host-specific features for reproducibility; not security-critical here (isolation is KVM + the fs filter) |

## 3. Hypervisor kernel API

If the backend is not KVM, the replacement must offer equivalents of the
following (what `vmm/hypervisor/` consumes):

| Capability | Used for |
|-----------|----------|
| User memory regions backed by host mmap | guest RAM |
| In-kernel local APIC via **split irqchip** (or equivalent) | interrupt delivery |
| **irqfd** + **ioeventfd** registration | virtio notifications and the vhost-vsock zero-exit wiring; non-negotiable for §2 latency |
| MSI routing table (GSI) set as one atomic table | MSI-X vectors |
| vCPU state config: regs/sregs/fpu/MSRs/LAPIC, CPUID | boot + PVH entry |
| Run-loop exits: `Shutdown → exit`, `Reset → reboot`, PIO/MMIO dispatch to userspace devices | lifecycle |
| One-shot eventfd-based immediate exit | vCPU kick on shutdown |

KVM capabilities checked at startup today: `SignalMsi`, `TscDeadlineTimer`,
`SplitIrqchip`, `SetIdentityMapAddr`, `SetTssAddr`, `ImmediateExit`.
Host kernel floor: Sandswap's overall host-kernel requirement is ≥ 5.10,
which covers the vhost-vsock UAPI and every egress-identity part (see
[Egress Enabler Contract](../how-it-works/egress-enabler.md)).

## 4. Guest-side contract

To delimit responsibility: these live in the guest and must survive a VMM
swap unchanged — the kernel, the initramfs, and [warden](https://github.com/sandswap/sandswap)
(the in-VM PID 1) implement them:

- `warden.*` kernel cmdline parameters (network, countdown, exec limits);
- vsock server on **port 1024** (raw frame protocol, 10 ops: the nine
  mount/exec/file ops plus `OP_KEY_DELIVERY` — the per-VM session key is
  delivered over the first host vsock connection and never rides the kernel
  cmdline; every frame carries a nonce + HMAC-SHA256 tag — see
  [protocols.md](../reference/protocols.md));
- virtio-fs mounted from tag `sandswap` at `/mnt/volumes`;
- `eth0` located by MAC, configured via netlink.

A VMM change must not alter what the guest sees on these four points.

## 5. Explicitly NOT required

Live migration, snapshot/restore, block devices of any kind (qcow2/vhdx/
raw/virtio-blk), TPM, VFIO/vfio-user device passthrough, balloon, pmem,
vDPA, vhost-user backends, firmware boot, multi-architecture (the guest is
x86_64), nested virtualization/HyperV extensions, coalesced MMIO,
dirty-page logging. Carrying any of these is dead weight, not a feature.

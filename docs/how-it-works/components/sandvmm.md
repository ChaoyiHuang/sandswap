---
title: Sandvmm
nav_order: 3
parent: Components
grand_parent: How It Works
---

# Sandvmm

## 1. Overview

sandvmm is the KVM virtual machine monitor: one process per microVM,
running the guest on KVM and controlled by the sandlot over a Unix-socket
API. It is a fork of Cloud Hypervisor, trimmed and extended for Sandswap.
Source: `vmm/` (Rust). Provenance and the replacement contract:
[VMM Integration](../../integration/vmm.md).

## 2. Key Responsibilities

- **Boot microVMs**: direct PVH kernel + initramfs boot, no firmware.
  `vm.create` builds the VM paused; `vm.boot` starts the vCPUs.
- **Host the permanent virtio-fs device**: tag `sandswap`, the shared
  volumes dir, `read_only=false`. Created once at boot, never hot-plugged.
  `read_only=false` is deliberate (the VMM default is `true`): flat volumes
  and `workspace/` must be writable — the overlay mode's read-only rootfs
  is enforced by the guest-side overlay mount, not by the device flag.
  The share root is the volumes directory, but the sandvmm identity holds
  **no list permission on it** (mode `2710`, group traverse-only): the
  daemon reaches exactly one tenant directory per mount — the
  `allowed_dirs` entry — and the other tenants' directory names are
  derived and unguessable
  ([Storage](../../operations/storage.md) rows 10b–11).
- **Apply the `allowed_dirs` runtime filter** (`vm.set-fs`) — the VMM-level
  half of cross-agent isolation. The filter is a namespace control at the
  share root; see
  [Isolation and Swap §4](../isolation-and-swap.md#4-the-host-side-boundary-the-virtio-fs-filter).
- **Expose the vsock transport**: attach the vsock device before boot and
  offload the data path to kernel vhost-vsock — the zero-VMEXIT warm path.
- **Translate guest power-off into process exit**: the warden's
  `reboot(POWER_OFF)` → ACPI S5 → the sandvmm process exits. This is what
  makes mount release after warden death fast.
- **Serve diagnostics**: per-VM serial (`<sandbox>/serial.log`, earlyprintk)
  and virtio-console (`<sandbox>/console.log`, the warden's main log).

## 3. Interfaces / Data Flow

**Inputs:**

- CLI flags at spawn (`--api-socket`, `--log-stderr`, `--seccomp <mode>` —
  `log` by default (v28 filters in audit mode), `true` to enforce,
  `false` as an explicit escape hatch — and `--api-gid` when the API socket
  carries the shared-group grant).
- API calls on the per-VM socket
  (`/run/sandswap/vm/<id>/sandvmm.sock`): `vm.create`, `vm.boot`,
  `vm.add-vsock`, `vm.set-fs`, `sandvmm.ping`, `sandvmm.shutdown`.
- The socket is dual-protocol: raw control frames (default for the hot ops
  `vm.set-fs` + `sandvmm.ping`) and HTTP/JSON on the same connection, routed
  by the first byte.
- KVM ioctls: memory regions, vCPU state, irqfd/ioeventfd, MSI routing.

**Outputs:**

- API responses (non-2xx bodies surface verbatim in sandlot errors).
- KVM state: the running microVM.
- `<sandbox>/serial.log` — earlyprintk (earliest boot/panic).
- `<sandbox>/console.log` — the guest's main output channel (hvc0: kernel
  log-buffer replay, later printk, warden logs) and the guest-side timing
  source for benchmarks.

```
Sandlot                  sandvmm                   Guest
  │ vm.create (JSON)        │                         │
  │────────────────────────▶│ paused VM               │
  │ vm.add-vsock {cid}      │                         │
  │────────────────────────▶│ vsock device attached   │
  │ vm.boot                 │                         │
  │────────────────────────▶│ vCPUs start ────────────▶ kernel boots
  │ vm.set-fs (raw frame)   │                         │
  │────────────────────────▶│ allowed_dirs swapped    │
  │ ... warm path, 0.2 ms ...                         │
  │ sandvmm.shutdown / S5   │                         │
  │────────────────────────▶│ process exits           │
```

## 4. How It Processes

1. **Start**: the sandlot spawns the process with the API socket path and
   `--log-stderr`. The socket is owner-sandvmm (987), `0600` or `0660`
   with the shared-group grant.
2. **Create**: `vm.create` takes the full config JSON — vCPUs, memory,
   kernel/initramfs/cmdline, serial-to-file, the one fs device, and the
   optional net device. Extra fs devices and `vm.add-fs`/`vm.add-net`
   routes do not exist: one share, one NIC, fixed at boot.
3. **Attach vsock, boot**: `vm.add-vsock` must precede `vm.boot`. Boot is
   direct PVH — hundreds of milliseconds.
4. **Serve the hot op**: `vm.set-fs` updates the virtio-fs `allowed_dirs`
   filter at runtime (~0.2 ms). Paths outside the whitelist resolve to
   NotFound inside the guest. This swap — not a device re-create — is what
   makes agent switching sub-second.
5. **Run**: the epoll loop services KVM exits, virtio devices, and the
   API server. vhost-vsock offloads the warden data path to the kernel.
6. **Exit**: `sandvmm.shutdown` tears the process down cleanly; a guest
   ACPI S5 does the same. Hard kill is `SIGKILL` on the process group.
   The process deliberately outlives its supervisor (no `Pdeathsig`) so a
   sandlot crash leaves the VM re-adaptable.

## 5. State & Storage

sandvmm is **stateless**. The VM's state lives in KVM and the guest; the
process holds no durable state and writes no files except the per-VM
serial/console logs.
A killed process loses the VM by definition — the sandlot's crash
detection and re-adopt machinery own recovery. Disks are not used: the
rootfs is the virtio-fs share; block devices are deliberately absent.

Component configuration: flags are set by the sandlot (see
[Sandlot configuration](../../operations/configuration/sandlot.md)).
The full API a replacement must provide:
[VMM Integration](../../integration/vmm.md).

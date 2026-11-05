---
title: Boxout
nav_order: 5
parent: Components
grand_parent: How It Works
---

# Boxout

## 1. Overview

Boxout is the privileged sidecar for Kubernetes deployments: it takes over
everything privileged so the sandlot container can run unprivileged
(UID 65536 — the reserved sandbox identity, all capabilities dropped). It is
a posture choice, not a
default. Source: `boxout/` (Go, one binary). See [Topologies](../topologies.md).

## 2. Key Responsibilities

- **sandvmm lifecycle** for the pod's VMs: launch, kill, shutdown.
- **Network provisioning**: build the network provider (bridge /
  routed-ipv6) here instead of in sandlot — TAP/IP setup and the static
  egress baseline.
- **Egress identity stamping**: apply and remove the routed-IPv6 identity
  SNAT stamps on the sidecar side (netlink needs `CAP_NET_ADMIN`).
- **Host-side OverlayFS**: mount/unmount, tracking, and the periodic
  stale-overlay sweep — the same `core.OverlaySet` implementation the
  embedded mode uses.
- **BPF binding-region handoff**: create and pin the egress identity
  region, then chown it to the unprivileged sandlot (`0660`).
- **/proc re-adopt scanning** and crash detection for surviving VMs —
  parity with embedded mode.

## 3. Interfaces / Data Flow

**Inputs:**

- Newline-delimited JSON requests from sandlot over
  `/run/sandswap-boxout/boxout.sock`. The directory is boxout-private
  (root-owned `0711`, separate from the sandlot-writable `/run/sandswap`);
  SO_PEERCRED rejects any UID except `-allowed-uid`; the socket is
  `0600`, owner `allowed-uid`, secured through directory-fd
  `Fchownat`/`Fchmodat` with an inode re-check. With
  `-client-token-file` set, a per-connection HMAC-SHA256
  challenge-response (fresh nonces both directions, token never on the
  wire) runs before any request is read.
- The shared sandlot YAML: boxout watches it and hot-applies the
  `microvm.*` subset, so its create_vm parameter whitelist tracks the
  sandlot's live values.
- Its own flags (socket path, allowed UID).

**Outputs:**

- sandvmm processes spawned/killed on the host.
- Kernel state: TAP devices, addresses, nftables rules, identity SNAT
  stamps, OverlayFS mounts, the pinned bpffs region.
- JSON replies on the socket.

```
Sandlot (UID 65536)       Boxout (UID 0)            Host
  │ {op:"launch_vm",...}     │                         │
  │─────────────────────────▶│ verify peer UID         │
  │                          │ check param whitelist   │
  │                          │ spawn sandvmm ──────────▶ KVM process
  │ {ok}                     │                         │
  │◀─────────────────────────│                         │
  │ {op:"mount_overlay",...} │                         │
  │─────────────────────────▶│ mount on host ──────────▶ OverlayFS
  │ {ok}                     │                         │
  │◀─────────────────────────│                         │
```

## 4. How It Processes

1. **Start** as a privileged sidecar in the sandlot pod. Create/verify
   the private socket directory, bind `/run/sandswap-boxout/boxout.sock`,
   enforce the entry's owner/mode/inode, load the shared YAML.
2. **Verify every request**: read the peer's UID via SO_PEERCRED, reject
   anything but the configured sandlot UID.
3. **Whitelist parameters**: only the `microvm.*` values the shared YAML
   allows pass through — the caller cannot smuggle arbitrary kernel
   paths, memory sizes, binaries, or guest addresses. Pre-configured
   kernel/initramfs only; vcpus/memory/CID are range- and
   integrality-checked; sandbox dirs are pinned to
   `<instance root>/<vm_id>`; volume paths are opened with
   `openat2(RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS)` and must be direct
   children of the volumes root; network release/reclaim require the
   caller's own lease and re-derive the spec from persisted state.
4. **Execute the op**: spawn/kill/shutdown sandvmm, provision or tear
   down networking, mount/unmount overlays, apply/remove identity stamps,
   create the bpf region, or scan `/proc` for re-adoption.
5. **Reply** with a bounded JSON result. A wedged sidecar never blocks a
   mount or unmount: the stamp path degrades to unstamped egress (see
   [Egress Enabler Contract](../egress-enabler.md) §5).

The hot path stays in sandlot: `vm.set-fs`, the warden vsock exec, and
leases need zero privileges and never cross this socket. Everything
boxout does is privileged management-path work — off the response path.

## 5. State & Storage

Boxout is **effectively stateless**. It tracks host-side OverlayFS mounts
in memory for the stale-overlay sweep (overlay-only, capped, persisted
only on change to `<private state root>/boxout-overlays.json`); the durable
state it manages lives in the kernel (TAPs, mounts, bpffs pins) and is
re-derived after a sidecar restart by the pidfd/`/proc` re-adopt scan and
the overlay re-scan. Its instance lock and token file live in a private
root-only state directory. Configuration comes from the shared sandlot
YAML.

Component configuration:
[Boxout configuration](../../operations/configuration/boxout.md).

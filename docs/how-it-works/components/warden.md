---
title: Warden
nav_order: 4
parent: Components
grand_parent: How It Works
---

# Warden

## 1. Overview

The warden is PID 1 inside every microVM: it mounts the agent's SandFS and
runs the agent's commands as its own children, enforcing the guest-side
isolation profile. It is statically linked into a ~5 MB initramfs.
Source: `warden/` (Rust, musl). It listens on vsock port 1024 for exactly
one client — the node's sandlot.

## 2. Key Responsibilities

- **PID 1 duties**: mount proc/sys/dev, set up guest eth0 via netlink,
  write `resolv.conf`, reap SIGCHLD children.
- **Serve the raw vsock protocol** (`src/raw_server.rs`): the 9 ops —
  mount+exec, unmount, exec, mem-stats heartbeat, background exec
  start/status/kill, the cold-path async variants, and unified file I/O.
  Frames carry a version byte with negotiated echo; out-of-window peers are
  rejected so VM creation fails fast. Warm ops carry the mounted volume's
  identity and a mismatch is refused by name without executing.
- **Sandbox every exec** (`src/exec.rs`, `src/seccomp.rs`): chroot into
  the mounted rootfs, `NO_NEW_PRIVS`, the 82-syscall seccomp deny list,
  10 ambient capabilities (Docker's set minus NET_RAW/SETFCAP/SYS_CHROOT/
  SETPCAP/MKNOD), and a per-process `RLIMIT_AS` for sync execs.
- **Own the mount lifecycle** (`src/mount.rs`): the guest mount sequence
  (virtio-fs share → bind rootfs → masked proc/dev → capped tmpfs →
  resolv.conf) and the switch-time teardown chain. The hardening steps are
  fail-closed: a boot that cannot build the read-only busybox source
  powers the VM off instead of falling back to the writable initramfs
  copy, and a mount that cannot apply the read-only busybox flip, the
  masked `/proc`, or a secured `/dev` target is refused rather than
  served de-hardened.
- **Serialize mounts**: the process-global `MOUNT_GATE` read/write lock —
  mounts take the write side, in-flight execs and file ops take the read
  side. The warm-path "already mounted" check runs inside the read guard,
  so it cannot race an unmount.
- **Enforce the single countdown**: only mem-stats heartbeats reset it.
  Expiry with a live mount exits the warden — the last-resort mount
  release when the host goes silent.
- **Bound resource parking** (`src/raw_server.rs`): connection caps,
  body budgets, first-frame timeouts, and a log limiter keep a hostile or
  wedged peer from holding warden resources.

## 3. Interfaces / Data Flow

**Inputs:**

- Raw vsock frames from the sandlot on port 1024 (the only transport).
- Kernel cmdline + env + TOML config (`warden.*` keys; boot-time only).
- The virtio-fs share (`tag=sandswap`) mounted from the VMM.

**Outputs:**

- Reply frames: exec results, background exec ids, status + log tails,
  mem-stats heartbeats.
- Child processes: the agent's commands, running chrooted under the
  mounted rootfs.
- Serial-log lines (debug-gated; the UART costs ~83 µs/char).

```
Sandlot              Warden (PID 1)              Agent process
  │ MOUNT_AND_EXEC      │                           │
  │────────────────────▶│ MOUNT_GATE: take write    │
  │                     │ mount rootfs/workspace/home│
  │                     │ fork → pre_exec:           │
  │                     │   seccomp, caps, RLIMIT_AS │
  │                     │ chroot → exec ────────────▶│ runs
  │                     │ MOUNT_GATE: release        │
  │ result frame        │ pidfd wait                 │
  │◀────────────────────│                           │
  │ OP_UNMOUNT          │                           │
  │────────────────────▶│ MOUNT_GATE write: drain   │
  │                     │ cgroup.kill + poll empty  │
  │                     │ rule-A sweep → umounts    │
  │                     │ drop_caches → obj sweeps  │
  │ result frame        │                           │
  │◀────────────────────│                           │
```

## 4. How It Processes

1. **Boot**: mount proc/sys/dev, configure eth0 by MAC via netlink, write
   `resolv.conf`, start the SIGCHLD reaper, arm the countdown, and listen
   on vsock port 1024.
2. **Serve a frame**: read within the body budget, validate the version
   byte, dispatch the op. Malformed or hostile input (e.g. a mount-point
   escape) is rejected at the protocol layer — asserted by
   `e2e/warden-hostile.sh`.
3. **Mount+exec (cold path)**: take `MOUNT_GATE` for write, run the
   mount sequence (virtio-fs at `/mnt/volumes`, bind the SandFS at
   `/mnt/rootfs`, mask proc/dev, cap tmpfs with `size=`), then fork. The
   child's `pre_exec` installs seccomp, drops to the 10 ambient caps, sets
   `RLIMIT_AS`, and (background execs only) joins the per-agent cgroup
   before chroot and exec. Background execs self-migrate into the cgroup
   lazily created by the first one — sync-only mounts never pay for it.
4. **Wait**: sync execs wait on a pidfd (wakeup) plus the SIGCHLD registry
   (status). The reply carries exit status and bounded output.
5. **Unmount (switch/lease end)**: take `MOUNT_GATE` for write (drains
   in-flight execs first), `cgroup.kill` + poll empty, sweep leftover
   processes (SIGKILL all but PID 1), unmount the stack, drop caches,
   sweep kernel objects (SysV IPC, keyrings), and destroy
   dead-state TCP sockets via sock_diag. Nothing of agent A survives into
   agent B.
6. **Heartbeat**: answer `OP_MEM_STATS` with guest MemAvailable/MemTotal —
   the sandlot's recycle signal and the countdown's only resetter.

## 5. State & Storage

The warden is **stateless by design**, with a hard ~10-minute ceiling on
any guest state: every command result, background log, and mount exists
only while the mount lives. The SandFS workspace on shared storage is the
only persistence. What it does hold is deliberate and bounded:

- **Per-mount runtime state**: the mount stack, the per-agent cgroup
  (lazy), the background-exec registry, the `mounted_volume` identity.
  All of it dies at unmount or with the VM.
- **Nothing persists across VMs**: a recycled VM's next tenant meets a
  clean guest — the teardown chain plus the cross-tenant sweeps guarantee
  it.
- **OOM posture**: `oom_score_adj=-1000` — the warden is never the victim
  when an agent exhausts the VM.

Component configuration:
[Warden configuration](../../operations/configuration/warden.md).

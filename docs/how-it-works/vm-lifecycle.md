---
title: microVM Lifecycle
nav_order: 7
parent: How It Works
---

# microVM Lifecycle

A microVM is the unit of compute: one kernel, one warden, bound to one
SandFS at a time. Nodes keep a pool of them warm so a request never waits
for a boot.

The **sandlot** on each node owns the whole lifecycle — creating VMs,
binding them to SandFS instances, releasing, recycling, and cleaning up
after crashes. The gateway only picks *which node* (and the minimum spec)
a request goes to; the sandlot picks the actual VM. How a request finds
the right node is a separate story ([Ownership & DNS](ownership-and-dns.md)).

## 1. The states

```
                pool creation (verified)
   ┌──────────┐  ────────────────────────►  ┌────────────┐
   │ BOOTING  │                             │   CLEAN    │
   └──────────┘                             │ no rootfs  │
                                            └─────┬──────┘
                                                  │ agent request (cold):
                                                  │ set-fs swap + guest mount
         ┌────────────────────────────────────────┘
         ▼
   ┌───────────┐  last command done,     ┌────────────┐
   │  IN USE   │  sticky window opens    │   LEASED   │
   │  mounted, │────────────────────────►│  mounted,  │
   │ executing │◄────────────────────────│   idle     │
   └─────┬─────┘  next call within the   └─────┬──────┘
         │         window                      │ lease expired
         │ forced release                      │ (async, off the
         │ (template swap, SandFS delete,      │ request path)
         │ load-shed)                          │
         ▼                                     │
   ┌────────────┐◄─────────────────────────────┘
   │ RELEASING  │ unmount + cgroup.kill + set-fs clear
   └─────┬──────┘
         │
   ┌─────┴────────────┐
   ▼                  ▼
back to CLEAN    DESTROYED (recycle,
                  unmount failure, crash)
```

- **CLEAN** — pooled and warm: booted, healthy, no SandFS visible
  (`allowed_dirs` empty). The pool maintains a target count per spec
  (`-pool "small:2,medium:3,large:1"` keeps that many CLEAN VMs per
  spec).
- **IN USE** — a SandFS is mounted and commands are executing.
- **LEASED** — the commands finished; the sticky lease (100 ms idle
  window by default, capped by `-max-sticky-sec`) holds the VM mounted.
  The next call within the window returns the VM to IN USE without a
  remount — this is what makes an agent's consecutive calls warm. An
  active background exec holds the VM until its `lease_duration` (an
  absolute run-time cap that status polls do not extend).
- **RELEASING** — the lease expired; the unmount runs asynchronously,
  off the request path. The VM returns to CLEAN — or is destroyed, for
  any of the reasons in [What ends a microVM's
  life](#9-what-ends-a-microvms-life).

A cold request always goes CLEAN → IN USE: the VM is bound and the SandFS
mounted before the first command runs. LEASED is only ever reached from
IN USE, when the last command finishes and the sticky window opens.

One SandFS runs on one microVM, but its commands are not serialized:
sync execs and file ops run in parallel up to the spec's `exec_slots`
(the per-VM warden connection pool; defaults small=3, medium=4, large=5,
configurable per spec in the `specs` config). Mounts and unmounts,
though, are serialized per VM by the warden's `MOUNT_GATE` — an unmount
waits for in-flight commands to drain before killing the process group.

## 2. Birth: verified creation

Every microVM is created through a single verified path, and only a VM
that passes it enters the pool:

1. **Memory admission** — the host reserves the VM's full memory before
   anything else is allocated. Guests fault memory in lazily, so this is
   a ledger, not a check of current usage: a shortage aborts the creation
   and stops the pool scale-up, so the host is never overcommitted.
2. **CID claim** — the vsock CID is claimed at the moment of allocation
   and can never be handed to a second VM; every path either ends in a
   running VM or releases the claim.
3. **Boot** — TAP network provisioning, sandvmm launch, kernel +
   initramfs, warden as PID 1.
4. **Warden verification** — the VM enters the pool only after its
   warden answers. A VM that does not come up is torn down completely
   (network, CID, sandbox dir, memory reservation) and the pool refills
   asynchronously.

The pool is pre-created at startup and refilled in the background as VMs
are consumed or recycled.

## 3. Pool scaling: online, via config hot-reload

The pool target is not fixed at startup. Editing the sandlot's YAML
config (`pool` and `specs`) is picked up by the config watcher and
applied online — no restart:

- **Scale up** — new VMs are created in the background through the same
  verified path as at startup, while the existing pool keeps serving.
- **Scale down** — idle (CLEAN) VMs are destroyed immediately; busy VMs
  are marked `pendingDestroy` and removed when their current work ends.
  VMs with only sync commands in flight go first; VMs with active
  background execs last, so long-running work is never cut short.
- **Safety gate** — an edit that would overcommit host memory is
  rejected and the previous pool target is kept, so a bad edit cannot
  drive the node into OOM.

A pool change also triggers an immediate heartbeat, so the gateway
reconciles the node's new capacity without waiting for the next
heartbeat tick.

## 4. Release: back to CLEAN

When the sticky window expires, the gateway sends the unmount off the
response path — the agent's response has already returned. The warden
kills all agent processes, tears down the guest mounts, and drops
caches; the sandlot clears the virtio-fs filter. The VM is CLEAN again.

If the unmount does not clearly succeed — `EBUSY`, a D-state process, an
unreachable warden — the guest mount state is unknown, and a VM in an
unknown state is never reused. It is destroyed and replaced
(`destroyAndReplaceVM`); the replacement cost stays off the request
path. Destroying a VM is cheap; reusing one in an uncertain state is
not.

## 5. Recycle: bounded reuse

A VM that releases cleanly is still not reused indefinitely. The sandlot
bounds how much one VM may serve — commands, mounts, distinct agents —
and watches guest memory; past any bound it destroys and rebuilds the VM
instead of returning it to CLEAN:

- **Use count** — the number of commands the VM has served, counted per
  command, not per mount: every exec and file op advances it, warm and
  cold alike (a warm exec mounts nothing; a cold file op mounts but runs
  no process). `-max-uses` (`recycle.max_uses`) defaults to 100,000;
  `0` disables the trigger, `-1` is the unlimited sentinel.
- **Mount count** — the number of mount generations the VM has served,
  counted per successful cold attach: warm ops do not advance it, and
  joiners within one generation count once. `recycle.max_mounts`
  defaults to 10,000; `0` disables the trigger, `-1` is the unlimited
  sentinel. Cold selection also prefers VMs still below the bound.
- **Distinct agents** — how many different agents the VM has served over
  its lifetime. A mount that would take on one agent more than
  `recycle.max_distinct_agents` (default 300) destroys the VM instead of
  reusing it, and the pool replaces it. `0` disables the trigger, `-1`
  is the unlimited sentinel.
- **Guest memory pressure** — free guest memory, sampled from the
  warden's heartbeat stats, below a threshold: the smaller of
  `recycle.mem_percent` (default 10% of the VM's total memory) and
  `recycle.mem_abs_mb` (default 100 MiB absolute), sanity-capped at
  half the VM's RAM.

One more `recycle.*` key is a preference, not a bound:
`recycle.affinity_vms` (default 3) is how many recently-used VMs a
sandfs prefers to reuse — best-effort, in memory only; `0` disables it.

The rationale: a long-lived VM accumulates residual guest state — memory
fragmentation, leftover kernel state. None of it is incorrect, but a
fresh VM is deterministic, and the replacement is built off the request
path. At the default use-count limit, memory pressure is the trigger
that fires in practice.

## 6. Crashes: detection and teardown

Crash detection is layered so a dead VM is always detected:

- **pidfd monitor** — the host watches every sandvmm process directly
  through one epoll loop (the primary path; zero idle cost).
- **VMM ping poll** — the fallback where pidfd is unavailable (boxout
  mode) or the kernel predates pidfd.
- **Probe loop** — the periodic warden heartbeat; repeated failures mark
  the warden as lost.

Once death is confirmed, the teardown releases every SandFS binding to
the VM and ensures the sandvmm process is dead *before* the CID, network,
and sandbox dir are released — a replacement VM can never boot onto a
live vsock CID. If the destroy cannot be confirmed (a D-state process
the kill could not reap), the CID and memory reservation are
deliberately held until restart: one stranded CID is the safe direction.
The node reports the crash to the gateway, which applies a short, soft
scheduling penalty — scoring only, never a hard filter, so a single-node
deployment is never starved. The pool refills asynchronously.

## 7. Re-adopt: surviving a sandlot restart

microVMs run as independent host processes and do not die with the
sandlot. If the sandlot crashes, is OOM-killed, or is upgraded, its VMs
keep running. On restart, the sandlot re-adopts them:

1. **Scan** — find surviving sandvmm processes and re-attach. VMs that
   belong to no live instance, or whose API socket is dead, are
   destroyed as orphans.
2. **Clean** — release any mounts the survivors still hold, *before*
   reconnecting to the gateway, so no stale mount survives the restart.
   A survivor that cannot be cleaned within the cleanup budget is
   destroyed and replaced by the same rules as a failed release.
   Host-side overlay mounts whose SandFS was deleted while the sandlot
   was offline are cleaned up by the same pass.
3. **Report** — the re-adopted set is reported in the NodeHello, so the
   gateway reconciles its ownership state against reality instead of
   assuming an empty node.

Re-adopt is what makes sandlot restarts cheap: warm VMs are re-adopted
rather than destroyed and rebooted.

## 8. The warden countdown: the resilience backstop

Every warden runs a single countdown that exists purely as a backstop
for the resilience model ([Resilience](resilience.md)): it guarantees
that every mount is released within a bounded time even when the sandlot
itself is stuck.

- Only the sandlot's heartbeat (the memory-stats probe) resets it.
  Business RPCs deliberately do not — a busy VM whose sandlot is gone
  must still be released.
- A healthy sandlot heartbeats continuously, so the countdown never
  fires in normal operation. When the sandlot loses the gateway long
  enough to enter its cleanup phase, it stops heartbeating; if its own
  cleanup then hangs, the countdown expires and the warden powers the
  VM off. Powering off destroys the VM, and the mount is released with
  it.
- The countdown only runs while a SandFS is mounted; pooled CLEAN VMs
  are never killed by it.

The release guarantee is therefore layered: the sandlot cleans up within
its budget (`T_clean`); if it cannot, the warden destroys the VM at a
known deadline (`T_warden`); and the gateway's ownership timing
(`T_safe`) is sized so ownership never moves before both have had their
chance.

## 9. What ends a microVM's life

| Reason | What happens |
|---|---|
| Unmount did not clearly succeed | destroyed — a VM in an unknown state is never reused |
| Use count, mount count, or guest memory threshold | destroyed and rebuilt at release time |
| Distinct-agent cap reached on a new mount | VM destroyed and replaced; the mount is served by another VM |
| sandvmm death or warden loss | teardown chain; node briefly deprioritized; replacement boots |
| Cleanup stuck after gateway loss | the warden powers the VM off (countdown expiry) |
| A re-adopt survivor could not be cleaned | destroyed and replaced |
| Pool scale-down | idle VMs removed now; busy ones when they finish |
| A destroy could not be confirmed | CID + memory reservation held until restart — the safe direction |

In every case the pool refills in the background — the request path
never waits for a VM to be born or to die.

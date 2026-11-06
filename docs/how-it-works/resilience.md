---
title: Resilience
nav_order: 11
parent: How It Works
---

# Resilience Design: Tolerance First, Confirmed Switching

> [Ownership & DNS](ownership-and-dns.md) describes the normal path: a
> request routes DNS → gateway → node → microVM, ownership is claimed, the
> command executes. This page describes everything **beyond** the normal
> path — what happens when a component fails, restarts, hangs, or is
> partitioned — and how the system provides minimal latency while still
> guaranteeing that a sandfs is never double-mounted.
>
> The core paradigm is **tolerance first, confirmed switching** — transient
> failures are tolerated by default (ownership does not move, the agent
> retries), and switching happens only after living participants confirm it
> is safe. This is the hardest part of the design: every switching decision
> must be safe against every interleaving of failures, yet the normal path
> must pay nothing for it. See [Design Principles](design-principles.md) for
> the architecture principles. **The code is the only implementation
> truth** — this page covers the stable design and mechanisms; concrete
> constants, data structures, and file paths follow the code.

## 1. Design core: tolerance first, confirmed switching

**The default response to failure is tolerance**: for any brief component
failure (restart / upgrade / blip), ownership does not move and the agent
receives 503 + retry. If the owner recovers, service continues in place at
zero switching cost. **Switching is a rare, confirmed-safe, explicit
operation** — it happens only after living participants confirm "the old
mount has been released".

**Ownership is a plain etcd key with no lease**, persisting until explicitly
managed (create / update node_id / owner-release delete / migrated-takeover
CAS overwrite). It does not depend on time expiry — no expiry means no
"lease timeout triggers a switch" race to root any race in.

**The warden countdown is anchored at a fixed point in time**: mount release
is backstopped by a single warden countdown that only heartbeats reset,
anchored at the last heartbeat ≈ `T_tolerance` (fixed), so the moment mount
release completes is fixed at `T_tolerance + T_warden`. The switching
condition (presence key expiry = `T_safe`) is fixed at `T_safe`. The
minutes-level margin between two **fixed** anchors makes the safety invariant
hold unconditionally — `T_tolerance + T_warden < T_safe`.

**Complexity collapses to one invariant**: every old-mount release path
completes before the switching condition is satisfied.

### 1.1 Two orthogonal facts: placement and mount state

The ownership record's `node_id` is the **placement**: which node this sandfs
belongs to (the node of its most recent mount). It **survives unmounts** —
unmounting does not clear it, node reconnection does not clear it, and
takeover preserves it. It is an affinity fact, not a mount status. (The
routing-side view of ownership and placement — what DNS and node selection
do with them on the normal path — is
[Ownership & DNS](ownership-and-dns.md); this section is the failure-analysis view.)

**Mount state is transient, existing only in the owner gateway's memory; etcd
records nothing about it.** The justification: sandbox mount release has
never been guaranteed by gateway bookkeeping but by the sandlot's own clocks
— after a disconnect the sandlot holds the mount so in-flight commands finish
(that is `T_tolerance`'s core semantic), then cleans up; the mount is
necessarily released within `T_tolerance + T_warden` (the countdown
backstop), and a restart does not lose this (phase persistence). Combined
with the connect-clean invariant (§8.1) and principle 5 (one sandlot, one
gateway), two corollaries follow:

- **The gateway holding a node's live stream has, in memory, the entire truth
  of that node's mount state** (nobody else can mount onto that node).
- **A node connecting to any gateway proves the old mounts are released**
  (connect-clean; the migration path additionally completes cleanup +
  isolation first).

No etcd-side observer of mount state needs millisecond freshness — its
consumers (takeover decisions, reclamation) are all on the cold path after
the owner is judged dead. So in steady state **the etcd write load is zero
per execution cycle**: writes happen only when placement actually changes
(first mount, re-placement, takeover-preserving).

### 1.2 Three ownership states

```
HELD ── components healthy, sandfs mounted on one of the owner gateway's nodes
    │
    │ brief component failure (restart / upgrade / blip)
    ▼
TOLERATING ── ownership unchanged; if the owner recovers, continue in place;
    │           the agent gets 503 + retry
    │
    ├─ owner recovers (< tolerance window) → back to HELD (no switch, no race)
    │
    └─ confirmed condition met (owner release or migrated takeover) → SWITCHED
            │
            ▼
     SWITCHED ── after the old mount is confirmed released, a new owner
                 takes over + mounts
```

### 1.3 Two switching paths (the core mechanism)

> **Precondition A** (shared by both paths): the sandlot has been
> disconnected longer than `T_safe` (safe cleanup time), guaranteeing every
> cleanup path (sandlot self-clean / warden countdown) has completed and the
> old mount is released.

**Path "owner release" — the original gateway lets go (the owner actively
confirms):**
- The original gateway (G1) is still healthy (health-key staleness under the
  death threshold)
- G1 tracked the sandlot disconnect via its local OnDisconnect and confirmed
  via presence-key expiry that `T_safe` has passed (§7)
- G1 deletes the ownership keys of all sandfs on that node → the sandfs
  becomes unowned → any gateway can createOwnership
- **Semantics**: a living owner confirms "cleanup is complete, I let go"

**Path "migrated takeover" — the sandlot migrates (the sandlot confirms by
migrating):**
- After finishing self-cleanup + isolation, the sandlot connects to another
  gateway (G2)
- G2 receives the sandlot connection → re-adopt-light confirms the VMs are
  clean → precondition A is implicitly satisfied (the sandlot has been
  through `T_tolerance + T_clean + T_isolation > T_safe`)
- G2 forceTakeover (CAS overwrite of G1's persistent key)
- **Semantics**: a living sandlot confirms by migrating — "I have cleaned
  up, the new gateway may take me"

**Otherwise (neither confirmation path is satisfied): ownership does not
move.** No living participant can confirm → unchanged → safe (possibly
stuck, but never double-mounted).

### 1.4 In-VM exclusivity (one microVM, one SandFS)

The counterpart invariant inside the VM: **a microVM belongs to exactly one
SandFS at any time.** SandFS A's rootfs must be fully unmounted (and all of
A's processes dead) before SandFS B's rootfs can be mounted; processes from
two SandFS instances never coexist in the same VM. This is a **security
invariant**, not a best-effort goal.

It is why `MNT_DETACH` is forbidden despite being the standard cure for
EBUSY from D-state processes: detaching the mount while the D-state process
lives would leave A's process coexisting with B's mount. The defense layers
(chroot, seccomp, capability drops, vsock isolation) are defense-in-depth,
not security boundaries — the invariant's value is that even if every
technical defense failed, the attacker still could not harm another SandFS,
because the other SandFS's processes do not exist in the same VM. When
`umount()` stays EBUSY, the VM is destroyed instead (§8.1/§8.7): the warden
returns an error, and the sandlot's destroy-and-replace path kills the KVM
process — every guest process, D-state included, dies with it — and
recreates a replacement VM with guaranteed exclusive ownership.

## 2. Core principles

1. **Always persist; agents assume Sandswap is unreliable.** Agents handle
   all transient unavailability by retrying; a minutes-level tolerance window
   buys the elimination of double-mounting.
2. **The same sandfs executes on only one microVM at a time.** Prevents
   data corruption from concurrent writes (workspace/home on distributed
   shared storage, virtio-fs overlay).
3. **Sync-task failure → clean up → refuse → retry.** After a component
   failure, if the states of the components cannot be confirmed consistent,
   all state of the sync task in the microVM must be cleaned; new agent
   requests are refused (503 + Retry-After) until cleanup completes.
4. **Async-task failure → lost → retry.** Background-exec metadata lives only
   in gateway memory and is lost on component failure; cross-gateway async
   tasks cannot be recovered. The agent re-runs the whole task on error.
   Async tasks are not persisted to etcd (recovery cost far exceeds the
   complexity).
5. **Distributed multi-gateway is mandatory.** Multiple exec gateways are
   exposed to agents through the DNS layer (stateless ownership-based
   routing + power-of-two-choices; there is no load balancer in front of the
   gateway tier); cross-gateway coordination goes
   through etcd (ownership CAS + health key + presence key).
6. **5K+ microVM scalability.** Hot paths are O(1) or O(nodes × specs);
   presence keys are per-node — count = number of sandlots (tens to
   hundreds), independent of the number of sandfs (tens of thousands).
7. **Tolerance first**: the default response to any brief component failure
   is to **tolerate** (keep ownership, do not switch, agent retries), not to
   switch. Switching is rare, confirmed-safe, and explicit.
8. **Ownership changes as little as possible**: no lease TTL, no time-based
   expiry. It changes only after a living participant (the original gateway
   or the migrating sandlot) confirms safety.
9. **Cleanup precedes switching, and switching is confirmation-based, not
   timer-based**: all old-mount release paths complete before the switching
   condition is satisfied; the condition is a *confirmation* (conjunction
   decision / sandlot migration), not a *deadline*.

## 3. Failure model

### 3.1 Failure forms and detection

| Component | Crash | Hang (half-dead) | Network partition | Graceful shutdown |
|-----------|-------|------------------|-------------------|-------------------|
| **Gateway** | stream EOF → sandlot tolerance clock starts; the health key has no lease (plain key) — death is judged per-consumer by `last_healthy_ts` staleness (§5), triggering no switch | keepalive half-open ~8s → sandlot tolerance clock starts | partitioned from etcd → fail-closed, stop dispatching (§8.4) | HTTP stops accepting and drains (≤30s); health keeps refreshing during drain (peers neither judge it dead early nor grab its sandfs); after exit, staleness takes over — no explicit key removal needed; the stream is handled by the sandlot tolerance state machine |
| **Sandlot** | stream EOF → gateway stops refreshing the presence key; warden countdown starts | keepalive ~8s / write timeout → gateway stops refreshing presence; warden countdown starts | same as hang (from the gateway's view) | stream EOF |
| **Warden** | vsock EOF / countdown expiry → VM exits → sandvmm CRASHED | countdown expiry → VM exits; **hang (probe 3×3s failed) → sandlot kills sandvmm → CRASHED** | N/A (vsock is local) | N/A |
| **microVMM** | pidfd/cmd.Wait → CRASHED | Ping failure / warden probe failure → kill sandvmm → CRASHED | N/A (Unix socket) | shutdown API |
| **etcd** | connection lost → reconnect | N/A | unavailable → fail-closed, stop dispatching | N/A |

**Detecting silent failures**: the health value carries `last_healthy_ts`,
and staleness is a queryable continuous quantity. The human gateway's
low-frequency full scan groups by owner and emits a structured warning log
for stale-past-alert-threshold owners that still have sandfs pointing at
them; `/stats` exposes every gateway's `stale_sec` / `last_healthy_ts`.
"Owner dead and service unavailable" — a silent failure — is thus observable,
and manual response has data to go on (§13).

### 3.2 Recovery strategies

| Failure | Recovery | Agent view | Unavailability window |
|---------|----------|------------|----------------------|
| Gateway blip/restart | the ownership key naturally persists → continue in place, **zero extra machinery** | 503 → retry | blip duration (seconds) |
| Gateway permanently dead + sandlot alive | sandlot tolerates → self-cleans → isolates → connects to G2 → migrated takeover forceTakeover | 503 → retry | ~T_isolation (12min) |
| Sandlot crash/hang + gateway alive | warden countdown releases the old mount; G1 waits T_safe then owner-releases → other nodes can mount | 503 → retry | ~T_safe (11min) |
| Gateway + sandlot both dead | warden countdown releases the old mount; no living party confirms → ownership does not move (safe, stuck) | 503 (persistent) | until manual/backstop reclamation (§13) |
| Warden/sandvmm crash | VM destroyed → retry onto a new VM (pooled path); on warden hang the sandlot kills sandvmm first, then cleans | 503 → retry | immediate |
| etcd unavailable | everything fail-closed: the Claim fast path is gated on `etcdAlive` (cleared by the first failed health write, so within ≤1 health tick + the write timeout every Claim takes the etcd slow path → 503); before that gate trips, fresh in-memory entries (≤ `ownership-cache-ttl-sec` old) still serve — they are our own valid ownership, so the local window is safe, never a double-mount | 503 (all) | until etcd recovers |

## 4. Time model and configuration

### 4.1 Configurable times

| Symbol | Meaning | Reference | Minimum constraint |
|--------|---------|-----------|--------------------|
| `T_tolerance` | sandlot tolerance: how long after a disconnect before cleanup starts | 5 min | **≥ 5 min** (covers restart/upgrade/blip; shorter degenerates back to the race model) |
| `T_clean` | sandlot cleanup window: all VM cleanup must finish within it | 5 min | ≥ actual cleanup time (5000 VMs parallel-unmount in ~8s; ample headroom) |
| `T_warden` | warden countdown: how long without heartbeats before the VM exits | 5 min | **≥ T_clean** (cleanup must beat the countdown, else the warden backstop-kills) |
| `T_safe` | safe cleanup time: after this long disconnected, all cleanup paths have necessarily completed | 11 min | **> T_tolerance + T_warden** |
| `T_isolation` | sandlot isolation: how long after a disconnect before connecting to another gateway | 12 min | **> T_safe** (unlocked only after switching completes) |

### 4.2 Invariant relations (validated at configuration)

```
T_tolerance ≥ 5min                 // tolerance window covers transient failures
T_warden ≥ T_clean                 // cleanup must be able to finish, else warden backstop
T_safe > T_tolerance + T_warden    // switching allowed only after all cleanup paths finish
T_isolation > T_safe               // sandlot unlocked only after switching completes
```

The reference values satisfy `5 + 5 = 10 < 11 < 12` ✓. The presence-key TTL
is `T_safe` (§5).

### 4.3 How the gateway "understands" these times

The sandlot reports its own `T_tolerance` / `T_clean` / `T_warden` in
`NodeHello`. The gateway derives `T_safe = T_tolerance + T_warden + 60s` and
the presence-key TTL from them — the two sides always agree, no separate
configuration. The gateway validates the invariant relations on every node's
hello (`NodeHello`) and refuses the node if they are violated.

## 5. etcd data model

All cross-gateway coordination state lives in etcd, five key families with
one job each:

| Key | Lease | Refresh | Role | Lifecycle |
|---|---|---|---|---|
| `/sandswap/owner/{sandfs_id}` `{gateway_id, node_id, generation}` | **none** | `node_id` updated when placement changes (zero writes in steady state); mount state never enters etcd. `node_id == ""` ⟺ no node selectable, no mount ever dispatched (the claim writes a candidate placement, §7.8) | sandfs ownership | explicit create (with candidate placement) / placement-change CAS / owner-release delete / takeover CAS overwrite (placement preserved) |
| `/sandswap/health/{gateway_id}` `{last_healthy_ts, node_count}` | **none** (plain key) | value rewritten every 5s | gateway liveness | death judged by `last_healthy_ts` staleness, not key disappearance |
| `/sandswap/gateway/{gateway_id}` `{gateway_url, stream_addr}` | **none** | rewritten on address change | the single source of routing addresses | configuration-like; does not vanish on death |
| `/sandswap/load/{gateway_id}` | **TTL 10s** | KeepAlive every 2s | scheduling capacity signal | natural expiry |
| `/sandswap/node/{node_id}/presence` `{gateway_id}` | **TTL = T_safe** | KeepAlive on heartbeat | node connection tracking | natural expiry T_safe after disconnect |

### 5.1 Three orthogonal concerns, decoupled

| Concern | Key | Nature | Lifecycle |
|---|---|---|---|
| gateway identity + routing address | `/sandswap/gateway/{id}` | configuration | changes only on explicit rewrite, **does not vanish on death** |
| gateway liveness | `/sandswap/health/{id}` | dynamic state | dead = stale (judged by timestamp) |
| sandfs ownership | `/sandswap/owner/{id}` | changes on migration | changes only on migration |

`gateway_url` lives only in the registry key. A restart that changes the URL
writes one plain key and it takes effect globally at once (O(1), fresh) —
the next DNS/307 query returns the new address; there is no "owned sandfs
keeps returning the old address" staleness gap. If the owner dies during the
tolerance window, the registry plain key remains and DNS/307 can still return
the owner's address (tolerance does not degrade).

### 5.2 The health key: staleness, not disappearance

The health key is a plain key, **never TTL-deleted**, its value rewritten
every 5s. Death is judged purely by how long since `last_healthy_ts` was
last refreshed. This decouples "misjudgment resistance" (wants a long
threshold) from "detection speed" (wants a short one) — they are independent
knobs, not one lease-TTL constant; each consumer picks its own threshold,
configurable via flags and hot-reloadable:

| Threshold | Default | Consumer | Cost of misjudging |
|---|---|---|---|
| `route-stale-sec` | 20s | DNS owner branch + 307 redirect gate | low (at worst one extra 503) |
| `alert-stale-sec` | 30s | alert scan | medium (false-alarm noise) |
| `claim-dead-guard-sec` | 45s | time-guarded takeover (§7.6/§7.8) + the reap-stuck manual tools' death test | high (misjudge → double-mount) |

Threshold order: `route < alert < guard ≪ T_safe`. Key disappearance keeps
exactly one meaning — "never written" (treated as dead, defensively).

### 5.3 The ownership key has no lease

If the gateway dies the key stays; ownership never expires by time, only by
explicit management. This eliminates the "lease expiry triggers switching"
race at its root — no expiry, no race. `gateway_id` in the ownership key is
the key for the registry lookup; the routing address is deliberately NOT in
the ownership key (avoiding per-sandfs redundancy and refresh cost).

> **Orphan registry keys**: a permanently retired gateway leaves one plain
> `/sandswap/gateway/{id}` key behind (count = retained gateways ≪
> per-sandfs). Ops deletes it when the gateway is decommissioned; there is no
> code-level GC.

## 6. Ownership: no lease, changes only on confirmed conditions

### 6.1 The full release/takeover decision (lazy, checked on the Claim path)

No proactive scanning, no batch takeover. The condition check is **lazy** —
it runs when a request reaches a gateway's Claim path:

```
Claim(sandfs_id):
  Get /sandswap/owner/{sandfs_id}
  │
  ├── key absent (released by the owner) → createOwnership (with candidate
  │     placement, any gateway) → mount
  │
  ├── owner == self → check placement connectivity and mount state (memory):
  │     ├── placement node connected + not orphan-suspect → serve normally
  │     │     (mount state is all in memory; affinity decides the landing
  │     │     node; one placement-change write if landing ≠ placement)
  │     └── orphan-suspect (placement node disconnected, mount state
  │           unprovable) → interrogate presence (§7.5):
  │             absent / owned by another → clear suspect → serve;
  │             owned by self → 503 + retry
  │
  └── owner == G1 (someone else) → takeover decision (§7.6, unified):
        │
        ├── G1 dead (health stale past guard)?
        │     ├── placement node's presence owned by me + live stream
        │     │     (the node migrated to me) → signal = confirmation →
        │     │     forceTakeover (placement preserved) → mount
        │     ├── placement node's presence absent (≥ T_safe, mount release
        │     │     proven) or placement empty → time-guarded claim (§7.8)
        │     │     → forceTakeover
        │     └── otherwise (presence still owned by a living party) →
        │           503 + retry (tolerate)
        │
        └── G1 alive → 503 + retry (let G1 run its own owner-release)
```

No requests = no changes = no churn. The two switching paths stay distinct:
**owner release = delete after the three-part chain holds (§7.4) → anyone
createOwnership; takeover = forceTakeover (CAS overwrite)**. The etcd CAS
(ModRevision) guards concurrent takeovers against each other.

### 6.2 The ownership key's normal lifecycle

> **SandFS deletion** now rides a lifecycle gate: the record flips to
> `deleting` (new execs/file ops gated with a retryable `409 SANDFS_NOT_ACTIVE`), the
> mount holder drains (the same machinery as a template swap; on split
> deployments the exec gateway reacts via its identity watch), and only then
> does the terminal volume/record removal + ownership-key release happen.
> The release itself is the OWNER's: when the drain settles to `detached`
> the exec owner deletes the ownership key (releasing a key owned by
> another gateway is a no-op), and the human gateway's delete completes
> only when the key is observed absent (bounded poll). The time-order
> guarantees below are unchanged: the key is released only after the mounts
> are provably gone, so no peer can claim and mount a volume being deleted
> (and even a racing claim is refused at that gateway's own execution gate).
> Lifecycle status transitions are compare-and-set, so a slow attach/swap
> cannot overwrite a concurrent `deleting`.
>
> **Drain settle is mount-aware.** A drain answers "settled" only when the
> node-side lease is gone AND no cold mount dispatch is in flight for the
> sandfs — the mount lock's refcount counts a queued waiter, not just the
> holder, and the drain performs one final unmount sweep + re-check right
> before it settles. A request that resolved the record just before the
> lifecycle status landed therefore cannot mount after the drain declared
> itself done.

- **Create**: a gateway first claims a sandfs (CAS create, gateway_id +
  **candidate placement**). The candidate placement is the node chosen by
  the request path's `PeekNode` (score-only, reserves nothing), written with
  the claim CAS so that `placement == ""` is equivalent to "no node
  selectable, no mount ever dispatched" (§7.8).
- **Placement change**: written only when the mount's landing node differs
  from the etcd-recorded placement (a single ModRevision CAS; comparing
  ModRevision, not updating generation, is the real concurrency guard).
  Node affinity makes this happen almost only at first mount and
  re-placement — **execution count and etcd write volume are fully
  decoupled**. Unmount writes nothing: mount state is an in-memory bit.
- **Owner release**: the owner gateway, after the three-part chain holds
  (§7.4), explicitly deletes the ownership keys of all the node's sandfs.
- **Migrated takeover**: the new gateway CAS-overwrites after the sandlot's
  migration confirms.
- **Time-guarded claim**: owner dead with proof of mount release by time
  (placement node presence absent, or placement empty) — CAS overwrite after
  the guard window (§7.8).
- **Otherwise unchanged**: no lease expiry, no timers, no health-driven
  automatic transfer.

### 6.3 Node selection and scheduling policy (where placement comes from)

§6.2 answered *where placement is recorded and when it is written*. *How a
cold mount's landing node is chosen* — the filter → affinity → score
pipeline, the crash soft penalty, the binpack/spread policies, and the
two-layer scheduling model (gateway layer + node layer) — is normal-path
placement and is covered in [Ownership & DNS](ownership-and-dns.md)
(the Scheduling policies section). One resilience-relevant property bears
repeating
here: **affinity is unconditionally first** — neither the scheduling policy
nor the crash penalty may override the placement node, and binpack/spread
act only on new landings (no active migration). A failure therefore never
re-places a sandfs *by policy*; re-placement happens only through the
switching paths below, each of which must first prove the old mount
released.

## 7. Connection tracking and switch confirmation

Owner release and migrated takeover both need three questions answered:
① how do we know a sandlot disconnected (trigger / localization)? ② how do
we know how long ago (T_safe passed)? ③ how do we find that sandlot's sandfs
(without scanning tens of thousands)? The closed solution: **presence key
(a persistent etcd signal, presence) + local OnDisconnect events (in-process
state, real disconnect) + the nodeSandfs reverse index (localization)**,
three factors conjoined.

### 7.1 The presence key: a persistent etcd signal

The presence key uses lease + TTL + heartbeat refresh and natural expiry —
no explicit action is needed at the moment of disconnect:

```
OnConnect(node_id):
  Grant lease(TTL = T_safe)
  PUT /sandswap/node/{node_id}/presence = {gateway_id: self}  WithLease

while the sandlot heartbeats (stream alive):
  KeepAlive(lease)          // leader-local, non-consensus, cheap

disconnect / gateway death (no explicit action needed):
  heartbeats stop → nobody KeepAlives → the lease naturally expires after
  T_safe → the key disappears
```

**Key present = the sandlot is connected (or disconnected < T_safe, within
tolerance); key absent = the key was once written by some gateway and its
TTL has expired.**

The presence key provides: ① persistence (survives gateway restarts);
② natural expiry (does not depend on a write succeeding at the disconnect
instant); ③ crash-amnesia resistance (after G1 crashes and restarts it can
still read the key from etcd to judge whether T_safe has passed). Per-node —
count = sandlots (tens to hundreds), independent of sandfs count.

### 7.2 Why the presence key alone is not enough: partition forgery + localization

The presence key is **not sufficient** for owner release; two gaps:

**Gap 1 — partition forgery**: consider an etcd partition:
```
G1 partitioned from etcd, but G1 alive, sandlot A still connected to G1
(stream alive), the old mount still valid, still serving agents.
G1 cannot KeepAlive the presence key → the key expires after T_safe
(forged by the partition).
If owner release triggered merely on "presence key absent":
  → G2 createOwnership → mount
  → but G1's old mount is still alive (A keeps probing the warden through
    G1; the countdown never fires)
  → ⚠️ double-mount
```
Root cause: the presence key reflects "etcd reachability", not
"gateway + mount really alive". A partition splits the two apart. Any
liveness signal stored in etcd is forgeable whenever its producer (G1) is
cut off from the store (etcd) but actually alive.

**Gap 2 — localization**: the presence key is node-scoped. Owner release
needs "the sandfs on that node" to delete one by one — it cannot scan tens
of thousands of ownership keys. And "key absent" cannot distinguish "was
connected, then disconnected" from "never connected to this gateway" —
especially after a gateway restart, when memory is empty and nodes never
connected also GET empty.

### 7.3 The conjunction: local OnDisconnect events + the nodeSandfs index

Both gaps close with in-process state of the gateway (independent of etcd,
unforgeable by a partition):

**(a) Local OnDisconnect events — partition-forgery resistance + trigger.**

The gateway's stream service fires `OnDisconnect(node_id)` when a sandlot's
gRPC stream drops. This is the in-process event of "this node really
disconnected":
- During a partition G1 is still connected to the sandlot (stream alive) →
  OnDisconnect does not fire → owner release does not move.
  **Partition-forgery resistant.**
- OnDisconnect records the node_id into a "disconnected, pending judgment"
  set and starts a local T_safe timer. This is owner release's **trigger**
  (and closes gap 2's "connected-before vs never-connected": a node never
  connected to this gateway fires no OnDisconnect and never enters the set).

**(b) The nodeSandfs reverse index — locating the node's sandfs (no
ten-thousand-key scans).**

The gateway maintains an in-memory index `nodeSandfs map[nodeID] →
set(sandfsID)`, indexing "which sandfs belong to which node" by
**placement** (not mount state). Updates ride the placement-change path:

| Event | nodeSandfs update |
|---|---|
| mount (placement set to / changed to N) | `nodeSandfs[N].add(sandfsID)` |
| unmount | **unchanged** (placement survives unmount) |
| node reconnect | **unchanged** (affinity preserved; only the in-memory mount bit clears) |
| owner release (ownership delete) | `nodeSandfs[N].remove(sandfsID)` |
| taken over (watch shows ownership changed to someone else) | `nodeSandfs[old N].remove(sandfsID)` |
| gateway restart | rebuilt during fullLoad from each key's node_id (one pass, reusing the existing paginated GET) — affinity recovers across restarts too (placement takes over the old in-memory preferred-node's job) |

Owner release scans only `nodeSandfs[N]` (tens to hundreds per node), not
all ownership keys (tens of thousands). The scope is "everything placed on
that node" (including currently-idle ones) — releasing extra idle keys is
harmless (deletion = unowned; anyone may take them; no mount safety
involved).

### 7.4 The owner-release three-part chain (fully closed)

```
owner release (G1 releases all sandfs placed on node N) triggers iff:
  (0) local OnDisconnect(N) fired; N is in the "disconnected, pending" set
      ← trigger + partition-forgery resistance (a live stream never fires
        it) + confirms N was connected to G1 (so G1 wrote its presence key)
  (1) T_safe has elapsed since OnDisconnect(N)
      ← local timer: enough for the warden countdown to finish
        (T_tolerance + T_warden < T_safe)
  (2) N's presence key is absent in etcd — or present but owned by another
      gateway (N migrated after its cleanup + isolation, so its mounts are
      released)
      ← etcd cross-confirmation the TTL expired. ((0) guarantees G1 wrote
        it, so "absent" = expired, not "never existed")
  (3) own health key alive (staleness under the death threshold)
      ← G1 is alive and has the right to release
  → delete the ownership key for each sandfs in nodeSandfs[N]
```

Verified failure by failure (the safety core of the design):

| Failure | (0) OnDisconnect | (1) local timer | (2) presence | owner release | Result |
|---|---|---|---|---|---|
| **etcd partition** (G1 alive, A's stream alive, G1↔etcd cut) | ✗ stream alive, not fired | — | expired but forged | not triggered | mount kept; heals back in place. **No double-mount, no wrongful delete** |
| **A disconnects + G1 alive** | ✓ | ✓ past T_safe | ✓ expired | triggered | delete → other nodes mount. No double-mount |
| **N migrates to G2 before the sweep runs** | ✓ | ✓ past T_safe | present, owned by G2 | triggered — migration implies the old mounts are released | delete lets a fresh claim proceed. No double-mount |
| **A disconnects first, G1 crashes, etcd partitioned** | lost on G1 restart | lost | unreadable during partition | falls to the lazy Claim path (§7.5) | triggers after healing; the warden long since released. No double-mount |
| **G1 crashes, A blips and reconnects to G1** | ✗ A came back | — | expiry irrelevant | not triggered | re-Grant restores. Correct |

**(0)+(1) resist partition forgery; (2) resists crash amnesia** and provides
the cross-restart T_safe cross-confirmation. All three are necessary.

**Release/delete races (the covering invariant).** Every path that deletes or
loses an ownership record runs against the invariant *a gateway's live mounts
are always covered by an ownership record naming the mounting node*:

- Batch agent deletion writes the same per-sandfs tombstones as a single
  SandFS delete (the widest id-reuse window is exactly the many-ids-at-once
  case), and identity lazy-load backfills are revision-checked against the
  watch revision so a stale point-Get can never overwrite a newer watch
  copy. In-memory (single-node) reads return private copies, so a concurrent
  status write cannot tear a record.
- The owner-release sweep **tombstones** its in-flight deletes: while a
  record's delete is racing toward etcd, the lazy Claim path refuses to
  re-serve that sandfs (503 + retry) — otherwise a claim that legitimately
  re-mounted the sandfs inside the delete window would strand the fresh mount
  without a record. The tombstone clears when the delete lands, or expires
  after a short window (a permanently failed delete must not wedge the
  sandfs; the lazy path remains the backstop).
- A cold mount **publishes** its placement with a bounded-retry CAS; if the
  publish cannot be confirmed (the record was taken over or deleted, or etcd
  stays unreachable past the retry budget), the mount is **compensated** —
  torn down through the same success-gated unmount path as a lease expiry.
  The ownership watch applies the same compensation when it observes our
  record deleted while the local state still says mounted.
- Unmount teardown is **settled exactly once per mount**: lease expiry, the
  etcd self-fence, and the publish compensation can all run idempotent
  unmounts for the same sandfs concurrently; only the first settler frees the
  node's bound-VM reservation, so racing settlers cannot over-admit.

### 7.5 Restart and orphan-uncertain (orphan-suspect)

After G1 crashes and restarts, its local OnDisconnect records and timers are
lost ((0)/(1) gone). It does **not** scan proactively (avoiding a
ten-thousand-key ownership scan). Instead the **lazy Claim path**: when a
request arrives with `owner == self` and there is currently no live stream
for that node_id → check the presence key:

- **Present and owned by self** → tolerate (the node may be reconnecting;
  an unexpired presence key means the disconnect is < T_safe), 503 + retry.
- **Present and owned by someone else** → the node has migrated to another
  gateway → release.
- **Absent** → the node has truly been gone ≥ T_safe → release.

**Presence-key reliability**: on node connect the gateway grants + puts the
presence key. If that write fails (etcd temporarily unreachable), the node
is still accepted (marked presencePending) and the grant is retried on every
heartbeat and when etcd recovers; a gateway restart breaks the stream,
forcing the node to reconnect and redo OnConnect. The lazy path
**tolerates presence absence for presencePending nodes** (no premature
"already gone" judgment); for all other nodes, "key absent" reliably means
the node has truly been gone ≥ T_safe (all cleanup paths have finished).

After restart, fullLoad rebuilds `nodeSandfs`, and lazy Claim locates sandfs
through it. The presence key (persistent in etcd, crash-surviving) provides
the cross-restart T_safe cross-confirmation — the key to the conjunction
staying closed under crash amnesia.

### 7.6 The takeover decision (unified: signal-style + time-style)

```
migrated takeover (G2 forceTakeover of a sandfs) triggers iff:
  (1) the owner is someone else (G1) and G1 is dead (health stale past
      claim-dead-guard)
  (2) the ownership value's node_id is non-empty
  (3) locally there is a live stream for that node_id (the sandlot has
      migrated to G2, stream alive)
  (4) that node's presence key belongs to G2
  → forceTakeover (CAS overwrite of G1's persistent key, generation+1,
    placement preserved)
```

Before connecting to G2 the sandlot necessarily went through
`T_tolerance + T_clean + T_isolation > T_safe` — precondition A is
implicitly satisfied.

**No timing conflict**: the sandlot connects to G2 only after `T_isolation`
(12min), while the old gateway's presence key expired at `T_safe` (11min).
When G2 writes the new key the old one is already gone — no overwrite race.
**Reconnect recovery**: a sandlot reconnecting to its original gateway gets
a fresh OnConnect grant + put — the key returns and tolerance ends.

> **Use the signal when there is one, time when there is not (the unified
> decision table)**: placement usually exists (unmount does not
> blank it), so there is always a node to interrogate. The takeover decision
> dispatches on the placement node's presence state:

| owner dead + placement N's presence | Verdict | Action |
|---|---|---|
| owned by me + N connected to me (live stream) | the node has migrated to me; the old mount is necessarily released (the signal IS the confirmation) | **immediate CAS takeover** (placement N preserved) |
| absent (≥ T_safe: the node is dead, or its gateway self-fenced and the disconnect self-cleaned) | every mount-release path has necessarily finished | **time-guarded CAS takeover** (after the per-sandfs death-observation clock fills the guard; non-empty placement preserved, empty placement gets this claim's candidate — §7.8) |
| owned by the dead owner (still alive < T_safe) | an unreleased mount may exist (a partitioned pre-self-fence owner can hold background-exec mounts) | tolerate (503 + retry) |
| owned by another living gateway | that gateway is the only party eligible to take over | tolerate |

The rule is "**time path whenever presence is absent**" — not only
"when node_id is empty" — placement persistence widens the time
path's coverage from "never-mounted keys" to "every key whose node is
confirmed gone", eliminating the whole class of "record shows mounted → can
never auto-take-over" deadlocks. The time path's reliability is closed by
two mechanisms together: self-fencing (§8.5 — active unmount removes the
"partitioned-but-serving" trace ambiguity) + the connect-clean invariant
(§8.1 — a node connecting to any gateway proves old mounts released).

### 7.7 Routing-side staleness gates (directing requests after the owner dies)

Migrated takeover triggers passively on the Claim path, while the routing
layer (DNS owner branch + 307 redirect) is health-blind by default. If
requests kept going to a dead address after the owner died, migrated
takeover would never trigger — the requests would never reach the only party
eligible to take over (the one holding the node's live stream). Routing-side
staleness gates close this gap:

**DNS owner branch**:
- owner healthy (staleness < `route-stale-sec`) → resolve ownership →
  registry → return the owner's address.
- owner dead/stale (≥ `route-stale-sec`) → **not into random fallback**;
  instead read the ownership value's `node_id` → that node's presence-key
  value (= the gateway the node is currently connected to) →
  **presence-directed routing** to that living gateway. It alone in the
  cluster satisfies the takeover condition; direction eliminates
  round-robin guessing across gateways.
- presence absent (the node went nowhere) → fall into the no-owner
  fallback scheduling; gateways 503-tolerate per §6.1 until migration or
  manual action.

**307 redirect gate**: a non-owner gateway, on an ownership conflict,
redirects to the owner's registry address. Before redirecting it checks
owner-health staleness — owner dead/stale (≥ `route-stale-sec`) → the gate
returns an empty address → falls to 503 + retry, keeping the request on a
living gateway until the takeover condition forms. The anti-loop mechanism
is unchanged.

**Threshold ordering keeps it safe**: `route-stale(20s) < alert(30s) <
claim-dead-guard(45s) ≪ T_safe`. The routing gate fires before the
switching side's owner-dead verdict — in the "routing has re-targeted,
switching not yet authorized" window, requests are only 503-tolerated,
never wrongly taken over. After takeover completes, the ownership's
gateway_id is rewritten, the owner branch hits naturally, and the directed
bridge extinguishes itself — nothing to clean up.

### 7.8 Time-guarded claim (guard-clock details)

Keys whose owner is dead with no signal to interrogate (placement empty, or
the placement node's presence absent — see the §7.6 table) are tolerated by
default on Claim; with the owner permanently dead that is a permanent 503.
The time-guarded claim closes this gap:

```
time-guarded claim (G2 forceTakeover of a sandfs) triggers iff:
  (1) the placement node's presence key is absent (≥ T_safe, mount release
      proven) — or placement is empty, in which case no extra proof is
      needed: the claim itself writes a candidate placement (below), so
      empty placement ⟺ no node was selectable ⟺ no mount was ever
      dispatched
  (2) the owner's health is stale past claim-dead-guard (owner dead)
  (3) a per-sandfs death-observation clock: seeded at first observation,
      triggering after the claim-dead-guard protection window fills
  → forceTakeover (CAS overwrite comparing ModRevision; placement
    preserved)
```

**The claim writes the candidate placement (eliminating the
"dispatched-but-unrecorded" window)**: `createOwnership` writes a
**candidate placement** into the value; `forceTakeover` **preserves a
non-empty placement** (affinity survives takeover, §7.6) and **replaces an
empty placement with this claim's candidate** — the claim CAS is the
boundary of "a mount may be dispatched hereafter", so the candidate must
land in that same write, or the taken-over record would sit in a mountable
state with an empty node_id. The request path first picks a node via
`pool.PeekNode` (**score-only, reserves no capacity**, pure memory), then
writes it with the claim CAS. Hence the invariant:

> **`placement == ""` ⟺ no qualifying node selectable ⟺ no mount ever
> dispatched**

The millisecond window of "claimed, mount dispatched, placement not yet
written back" does not exist — with **zero added command-path latency**: the claim was already one etcd CAS write, the
candidate is just one more field, and node-picking is an in-memory score.
When the first mount lands on the candidate node, the write elimination
kicks in — a **net one-write reduction** vs before. If candidate and actual
landing differ (capacity changed between PeekNode and Acquire), the mount
records one placement-change write (cold path, async).

Claims fail closed (the etcdAlive gate), so a stale owner cannot create new
mounts inside the death-judgment window: health frozen ⟹ partition has
begun ⟹ that gateway's Claims are already gate-rejected ⟹ no
"judged-dead-then-mounted" orphans appear.

- **The anchor is the last-observation time, not creation time**: owner
  revival / takeover / watch-delete all clear the clock; a background sweep
  prevents leaks.
- **The claim must be a CAS overwrite** (ModRevision compare), not
  createOwnership (the key exists; CAS-create always fails).
- **Safety**: if a "dispatched-but-unrecorded" orphan mount existed, then
  with the node's stream gone (the accompanying consequence of owner death),
  both sandlot self-clean and the warden countdown release it before
  T_safe — neither depends on gateway bookkeeping. The claim-dead-guard
  (45s) is far below T_safe; within the protection window the old mount is
  long released.

### 7.9 The presence-key design choice

The presence key's TTL mechanism, versus writing a leased disconnect record
at disconnect time: the disconnect moment needs **no explicit action**
(stopping refresh is the effect), a same-crash gateway leaves nobody to
KeepAlive so expiry is natural, and the T_safe test is "key absent" rather
than a precise instant comparison "now - disconnect_time > T_safe". T_safe
is a conservative lower bound — the exact disconnect moment is not needed;
the key's expiry moment > the warden cleanup completion moment
(`T_tolerance + T_warden < T_safe`). Same no-explicit-action discipline as
the health key — but the health key carries no lease: it is a plain key whose
death is judged by how long since its last refresh.

### 7.10 Scalability

Presence keys are per-node (count = sandlots, tens to hundreds),
independent of sandfs count. KeepAlive rides node heartbeats every 30s —
O(sandlots), leader-local non-consensus writes. The nodeSandfs in-memory
index is O(total mounts), updates O(1). With multiple gateways coexisting,
each sandlot has exactly one presence key (principle 5: one sandlot, one
gateway) — no conflicts.

## 8. Layered self-protection

### 8.1 Sandlot: T_tolerance is the in-flight-command grace period; connect-clean

**T_tolerance's core semantic**: after a disconnect, **keep the mounts** so
in-flight commands keep running to completion. Commands run inside the VM
over vsock — the gateway being down does not affect them at all; that is
exactly why T_tolerance exists. Gateway upgrade windows are typically
10–30s while the sync-command contract target is ≤10s, so **in-flight sync
commands almost always land during blips and upgrades**.

**Hard invariant: before every stream connection, the sandlot releases all
its local mounts.** Cleanup timing unifies as `min(dial success, T_tolerance
expiry)`, **always before NodeHello**, pinned at two checkpoints:

| Checkpoint | Scenario | Why here |
|---|---|---|
| process start (after re-adopt, before the connect loop) | sandlot restart | after restart the process has no binding records (memory state) to report — cleanup is the only correct action |
| after dial succeeds, before hello (`rpc.Config.BeforeHello`) | reconnect within tolerance | the gateway is reachable, the grace period is over; not doing it at the disconnect instant is exactly what leaves the whole T_tolerance to in-flight commands |
| T_tolerance expiry (CLEANING) | gateway long gone | the original path: cleanup, isolate, change home — leave clean |

- The gateway treats OnConnect as "the node arrives with zero mounts" — its
  in-memory mount table is necessarily correct at that instant (nothing
  transient to reconstruct after a restart, no reconciliation protocol), and
  the cross-node double-mount of the gateway-restart scenario is
  structurally blocked.
- **Why no reconnect reconciliation**: at the sandlot layer there is only an
  `activeBgExecs` count, no exec_id→sandfs registry; the details live inside
  the warden with no query protocol; after a node restart even the bindings
  are gone. The reconciliation state space is `gateway memory × node memory`
  — four combinations, of which reconnect-cleanup is one; testability drops
  by an order of magnitude.
- The cost (established contract): **reconnection aborts still-running
  background execs** (sync commands have usually finished within the grace
  period). The workspace persists unharmed on shared storage; the agent
  recovers or rolls back per the abort contract (see the
  [Agent HTTP Integration](../integration/agent-http.md) abort contract, embedded in the MCP
  tool descriptions too).

**Persistent state** (sandlot-level cleanup state file `cleanup-state.json`):

```json
{
  "phase": "tolerating" | "cleaning" | "done" | "",
  "disconnect_time": "<RFC3339>"
}
```

Just these two fields. `""` is the connected/no-outage value — the record is
cleared to it when a connection succeeds, and a missing file reads as `""`.
No `cleanup_deadline` needed (it equals
`disconnect_time + T_tolerance + T_clean` — computable); **no `cleaned_vms`
list needed** — `OP_UNMOUNT` and `setFsAllowedDirs([])` are idempotent,
re-running cleanup on an already-cleaned VM is a ~1ms no-op. After a
restart, re-run cleanup for all VMs and let no-ops skip — no progress
tracking required.

> Note: this `cleanup-state.json` (resilience phase) and the per-VM
> `state.json` (VM re-adopt data: CID/PID/config) are two different files.
> Both live in the instance's private state root (`/run/sandswap-state/<tag>`,
> owner-only), never in the group-writable `/run/sandswap` runtime tree.

**State machine:**

```
CONNECTED ──stream drops──> TOLERATING
   ▲                        │ persist {phase, disconnect_time}
   │                        │ keep probing the warden (resets the countdown)
   │                        │ try reconnecting to the original gateway
   │                        │   (preferred IP)
   │                        │
   │                        ├── gateway recovers (reconnect ok) ──> CONNECTED (zero cleanup cost)
   │                        │
   │                        └── T_tolerance expiry ──> CLEANING
   │                            │ update persisted phase=cleaning
   │                            │ ★ stop heartbeats (anchors the warden
   │                            │   countdown, see 8.2)
   │                            │ concurrent OP_UNMOUNT of all mounted VMs
   │                            │   (idempotent)
   │                            │ setFsAllowedDirs([]) clears the virtio-fs
   │                            │   filter
   │                            │ unmount failure (D-state/EBUSY) → kill the
   │                            │   sandvmm process
   │                            │
   │                            ├── cleanup done ──> DONE ──wait T_isolation──>
   │                            │                    reconnect gateway ──> CONNECTED
   │                            │
   │                            └── crash + restart ──> read persisted state:
   │                                ├── phase=tolerating, within T_tolerance
   │                                │   → keep tolerating (heartbeat)
   │                                ├── phase=tolerating, past T_tolerance
   │                                │   → enter CLEANING
   │                                └── phase=cleaning → ★connect to no gateway,
   │                                    ★send no heartbeats, re-run cleanup on
   │                                    all VMs (idempotent no-ops) → DONE
```

**Key design points:**

- **TOLERATING**: keep probing the warden (every 3s, resetting the warden
  countdown); try only the original gateway, never another; persist
  `disconnect_time` so the tolerance clock **does not reset** across a crash
  restart (it keeps counting from the original disconnect). If the preferred
  IP briefly drops out of DNS answers because the gateway restarted with a
  new IP (routine in k8s), the sandlot dials the remembered IP directly
  (purely local information) instead of idling away the whole tolerance
  window — the change-home prohibition (TOLERATING dials only the
  preferred-IP, never another IP) remains the sole safety guarantee; DNS
  membership re-checks are not an extra gate. One deliberate exception:
  with no remembered gateway at all (a first connect, or a lost
  gateway-state.json) any resolved candidate is taken even during
  TOLERATING — connect-clean makes the landing safe, and with no home to
  stay loyal to there is nothing to preserve. The same direct dial is the
  fallback when DNS itself is unreachable or returns no answer: a DNS
  outage must not strand the node (the direct dial is safe in every phase —
  connect-clean + etcd ownership bound any landing), and each connect
  attempt re-resolves, so failover resumes once DNS recovers. If the gateway
  is truly dead, dialing the dead IP fails fast → retries until T_tolerance
  expires, then cleanup as usual.
- **CLEANING**: **stopping heartbeats is the closure point of the whole
  model** — it anchors the warden countdown to the fixed time T_tolerance
  (see 8.2). Unmount failure kills the sandvmm process directly (no retry,
  no MNT_DETACH — honoring the EBUSY→destroy policy of the in-VM
  exclusivity invariant). Cleanup must finish within T_clean; VMs that miss
  the deadline are force-killed as backstop — a residual mount is never
  left past T_safe.
- **Crash recovery**: reading `{phase, disconnect_time}` restores the entire
  context. A crash mid-cleanup, on restart, **persists in finishing the
  cleanup** — no gateway connection (inside the isolation window), no
  heartbeats (not disturbing the warden countdown), idempotent cleanup
  re-run. Even if the restart outlasts the remaining window, the warden
  countdown backstop-kills the residual VMs at `T_tolerance + T_warden` —
  cleanup completes via the backstop. A crash **while connected** is the one
  gap the persisted file cannot cover (the disconnect record is only written
  on an observed stream break), so a restart that re-adopts held mounts
  re-anchors TOLERATING at process start — otherwise a dead gateway plus
  unreachable DNS would hold the mounts forever (no clock in the normal
  phase, and the probe loop's heartbeats keep the warden countdowns fresh).
  A live gateway connects within milliseconds and clears the anchor.
- **Isolation (T_isolation)**: counted from `disconnect_time`; the state
  machine's phases structurally skip any gateway connection during it (the
  CLEANING/DONE phases never enter the dial path). Prevents a sandlot from
  reconnecting before cleanup is confirmed complete and being treated as an
  available node by a new gateway.

### 8.2 Warden: the countdown backstop

The warden runs a single countdown as the final backstop for mount release:

```
Rules:
  - only heartbeats (MemStats probes) reset the countdown
  - business RPCs (OP_UNMOUNT / OP_EXEC / ...) do not reset it
  - countdown expiry with a live mount → exit the VM (the mount dies with it)
```

**Why "only heartbeats reset" is the closure point** — it anchors the
countdown at the **last heartbeat ≈ T_tolerance** (when cleanup starts),
not at the sandlot's crash time:

```
             heartbeats keep resetting the countdown   heartbeats stop; countdown
                                                       decays from T_tolerance
             ┌──────────────────────────────┐   ┌──────────────────────────────┐
             │  tolerance phase T_tol(5min) │   │  cleanup phase T_clean(5min) │
 ──┬─────────┼──────────────────────────────┼───┼──────────────────────────────┼
t=0 gateway  │  countdown never expires     │   │  OP_UNMOUNT does not reset   │
drops;       │                              │   │  the countdown               │
every 3s     │                              │   │                              │
resets it    └──────────────────────────────┘   └──────────────┬───────────────┘
                               t=T_tolerance                   │   t=T_tolerance+T_warden (=10min)
                                                               ▼
                                              the countdown fires at a FIXED time
                                              (independent of when the sandlot crashed)
```

**This is the root cause of the race's elimination**: the countdown is
anchored at the fixed time T_tolerance, mount release completes at the fixed
`T_tolerance + T_warden` (= 10min), and the switching-allowed moment is the
fixed `T_safe` (= 11min). `10min < 11min` **holds unconditionally**,
independent of any failure timing.

Whatever the sandlot does during cleanup — crashes whenever, restarts or
not:
- sandlot finishes cleanup → OP_UNMOUNT releases the mount (≤ 10min);
- sandlot crashes and cannot restart → the countdown kills the VM at 10min,
  the mount dies with it;
- sandlot crashes and restarts → resumes cleanup (no heartbeats, no
  countdown reset), finishing before 10min — or the countdown backstops.

**On every path, mount release is ≤ T_tolerance + T_warden < T_safe.** The
switching condition (presence expiry = T_safe, plus the §7.4 local
OnDisconnect conjunction) necessarily comes after.

Further points:
- **vsock EOF does not trigger immediate release**: EOF only signals "the
  sandlot may be gone" — the countdown is already running (heartbeats
  stopped). If the sandlot blips and reconnects, fresh heartbeats reset the
  countdown and everything recovers — no irreversible warm loss.
- **Countdown expiry = `reboot(LINUX_REBOOT_CMD_POWER_OFF)`**: the warden,
  as PID 1, triggers ACPI power-off; the guest shutdown fires sandvmm's
  exit event → the sandvmm process exits → the virtio-fs connection drops →
  the mount dies with the VM. **Never `std::process::exit(1)` as the release
  mechanism** (the source keeps one only as an unreachable after-`reboot()`
  fallback) — for PID 1 it causes a kernel panic ("Attempted to kill init") →
  the VM hangs,
  sandvmm does not die, the mount is not released (double-mount risk).
  POWER_OFF is what makes sandvmm truly exit and the mount release fast.
  It fires only while a mount is live (not yet unmounted); clean unmounted
  VMs are untouched. Unmount failure (D-state/EBUSY) also goes through
  POWER_OFF (no MNT_DETACH).
- **Normal operation never triggers it**: in normal running, heartbeats
  reset every 3s; the countdown (5min) never expires.
- **Probing is naturally decoupled from the gateway stream**: the countdown
  watches only heartbeats (the sandlot→warden leg), independent of gateway
  health.

**The stuck-connection blind spot (per-request read timeouts)**: business
uses a **per-VM connection pool** (at most `exec_slots` resident
connections per VM, one in-flight request each — raw vsock frames carry no
correlation ID, the slot itself is the correlation key), while heartbeat
probes use **independent short-lived connections** (fresh every 3s, 2s
timeout). One blind spot remained: if a pooled connection wedges (written
to, never answered) while the warden still accepts new connections,
heartbeats keep succeeding and keep resetting the countdown → a stuck
request takes very long to surface. Fix: each pooled connection's
`SO_RCVTIMEO` is set **before every request, sized to that op's duration** —
execs use the request's timeout + 30s margin (default 180s exec → 210s),
clamped overall at T_warden (300s); non-exec ops use fixed defaults
(unmount/file 30s, status/kill 15s, mem_stats 5s). A wedge surfaces at
`~op_timeout + 30s` (TransportError → **that slot** is discarded; the next
acquire dials a fresh connection) instead of waiting a fixed six minutes;
at-most-once semantics are preserved (the read timeout always trails the
op's own declared timeout, so a legal slow command's response always fits).

**Pooling narrows the failure domain**: stuck/corrupt is **per-slot** — one
dead slot does not affect the VM's other slots, and other concurrent
requests keep serving normally (under the old single-connection scheme, one
wedged connection dragged every queued op of that VM into the same bad
socket). On VM destroy/crash, the pool reset closes idle slots and refuses
new dials; in-flight slots are discarded by their holders on release —
every destroy path (scale-down / recycle / dirty-VM replacement /
handleVMDied) must call it, or a dead VM's vsock connections leak until the
sandlot process exits.

**Unmount semantics under concurrent sync commands**: one sandfs may run up
to `exec_slots` concurrent sync commands. Unmount must therefore wait for
**all** in-flight commands — a wait completed **inside the warden**: the
MOUNT_GATE rwlock — execs/FileOps take the read lock, mount/unmount takes
the write lock, so OP_UNMOUNT's write lock naturally waits for the readers
to drain before running `cgroup.kill` (a blind kill must never land on a
still-running sync command). The sandlot-side mount mutex covers only
mount bookkeeping (overlay/allowed_dirs/volumes, ms-scale), **never waits
across execs** — otherwise one 300s command would block unmounts, FileOps,
and sibling execs. Cleanup-budget impact: one VM's unmount upper bound goes
from "one in-flight command" to "the longest in-flight command" — the bound
is unchanged (still a single command timeout ≤ 180s < T_clean 300s), the
expectation rises slightly. The countdown backstop is unchanged (anchored
only by heartbeats, independent of in-flight command count).

### 8.3 Gateway: tolerate, don't switch; take over only on confirmed conditions

- **Tolerate**: request → Claim → condition unmet → **503 + Retry-After**.
  No createOwnership, no forceTakeover, no ownership movement on health
  staleness.
- **Owner-release execution** (three-part chain, §7.4): on
  `OnDisconnect(node_id)`, record the node in the "disconnected, pending"
  set and start a local T_safe timer; when the timer expires, check the
  node's presence key; `OnDisconnect + T_safe elapsed + presence absent
  (or owned by another gateway after migration) + self healthy` all hold →
  delete the ownership key of every sandfs in
  `nodeSandfs[node_id]` and clear the node's index entry. **The chain is
  the core**: OnDisconnect resists partition forgery (a live stream never
  fires it), the presence key resists crash amnesia and provides the T_safe
  cross-confirmation, nodeSandfs locates (per-node, no ten-thousand-key
  scan). Presence expiry alone would be partition-forged (§7.2) — never
  release on it.
- **Orphan-uncertain resolution** (§7.5): after restart, in-memory mount
  state unknown; fullLoad marks keys whose placement node is not connected
  to me orphan-suspect (503 + retry); when a request arrives, interrogate
  the presence key: absent / owned by another → mount release proven →
  clear the suspect and serve; owned by self (disconnect < T_safe) →
  tolerate. A node reconnecting (necessarily clean, §8.1) clears it too.
- **Takeover decision** (§7.6, signal + time unified): on Claim, owner dead
  and the placement node's presence owned by me + live stream → immediate
  forceTakeover; presence absent or placement empty → forceTakeover after
  the per-sandfs death-observation clock fills claim-dead-guard. Takeover
  preserves placement.
- **Presence-key maintenance**: grant(T_safe) + put on OnConnect; KeepAlive
  while the stream lives (hooked on heartbeat); stop on disconnect (natural
  expiry, no explicit revocation).
- **nodeSandfs maintenance** (placement index): add/move on placement
  change; untouched by unmount and node reconnect (affinity survives
  both); remove on owner release / observed takeover. Rebuilt by fullLoad
  on restart (affinity recovers too).
- **Readiness gate**: `/ready` returns 200 only after startup loading (auth
  fullLoad + ownership fullLoad + nodeSandfs rebuild) completes; `/health`
  is liveness, always 200. The gRPC stream server starts as early as
  possible (sandlots need to reconnect). The readiness gate blocks agent
  HTTP traffic only, never sandlot reconnection.
- **Routing-address registration**: the addresses go into
  `/sandswap/gateway/{id}` as a **plain key** (no lease) when the health
  loop starts, rewritten immediately on change. Routing addresses are
  configuration — they do not vanish on death; fully decoupled from health
  (liveness) and ownership (placement).
- **Fail-closed**: the gateway detects etcd unreachability (health write
  failure → etcdAlive false) → the Claim fast path stops → the slow path's
  etcd failure → 503. Prevents a partitioned gateway from newly mounting
  sandfs during the partition (§8.4).
- **Self-fence** (§8.5): etcd write failures continuously exceeding
  `-etcd-fence-sec` (default 180s; hot-reloadable — a new value is
  re-validated against every connected node's `T_safe > fence + T_warden +
  heartbeat` and refused if it breaks the invariant) → **actively unmount**
  every mount it (bounded-parallel, releasing leases and bound capacity
  simultaneously), **keeping node streams connected**; when etcd recovers →
  unfence + re-grant presence for all connected nodes → continue in place.
  Release completes within `fence + T_clean`, so the T_safe formula needs
  no fence term.

### 8.4 etcd partition

A gateway alive but partitioned from etcd cannot KeepAlive its presence /
health keys → they expire. But the partitioned gateway is still connected to
its sandlots, the old mounts are still there, and it still serves the
mounted sandfs.

**The partition's safety guarantee comes from §7.4's chain — not from
fail-closed or active notification**:

The partitioned gateway (G1) is still connected to sandlot A (gRPC stream
alive) → `OnDisconnect(A)` does not fire → the chain's `(0)` fails → owner
release does not trigger → ownership does not move. Even with the presence
key expired by the partition (forged), the chain does not wrongly release.
**No double-mount, no wrongful ownership deletes.** After healing, G1
resumes KeepAlive; the presence key is valid again; service continues in
place.

**Why not active notification**: an etcd partition is a transient
failure; the partitioned G1 is actually alive, its mounts valid, its agents
served. If G1 broadcast all sandlots into tolerance → each sandlot stops
heartbeating after T_tolerance, self-cleans, releases all mounts → the whole
node's sandfs ownership gets owner-released one by one → **mass wrongful
ownership deletion**, directly contradicting principles 7 ("ownership
changes as little as possible") and 6 ("tolerance first"). After healing, G1
should have recovered in place; the broadcast would have churned the whole
node. The chain's "nothing moves during the partition" is the correct
tolerance semantic.

**What fail-closed does**: the gateway detects etcd unreachability (health
write failure → etcdAlive false) → the Claim fast path is disabled → the
slow path's etcd failure → 503. This stops the partitioned G1 from
**newly mounting** sandfs during the partition (avoiding races with other
gateways' takeovers after healing) — but it takes no part in switching
verdicts and does not prevent double-mounting; double-mount prevention is
§7.4's chain.

### 8.5 Self-fence: structurally closing the partition ambiguity

A partition leaves one ambiguity that must be closed: **"G1 partitioned from
etcd (alive, nodes still connected, background-exec mounts still alive)"
and "G1 truly dead" leave identical traces in etcd** — health and presence
equally expired. A side observer (takeover decisions, manual tools) cannot
tell them apart; reclaiming on that signal would double-mount; auto-reclaim is therefore
gated by the time proof, never by health/presence alone.

Closure: **a gateway unable to reach etcd past the loss threshold
(`-etcd-fence-sec`, default 180s) must stop acting as owner — actively
unmount everything it holds while keeping its sandlot connections; when etcd
recovers it lifts automatically.**

- **Active unmount, no stream break**: unmounts are dispatched one by one
  over the still-working node streams (bounded-parallel, 32 concurrent),
  releasing the corresponding leases and bound capacity. The release set is
  deliberately WIDER than "currently mounted": it is every sandfs with a
  non-empty placement that is mounted, **dispatching** (a cold mount in
  flight has no lease entry yet), or **suspect** (dispatch unconfirmed).
  While fenced, a mount confirmation is refused and compensated with an
  immediate forced unmount, and a new dispatch is refused outright
  (`ErrCoverageLost`) — so "health stale past fence ⇒ no live mounts" holds
  for the in-flight window too. The gateway does not depend on the
  node-side cleanup chain.
- **Why not break the stream**: after a break, release waits for the node's
  `T_tolerance + T_clean` (600s); plus the fence that is 780s > T_safe
  660s — the time ordering fails. And the node would idle out tolerance
  300s + isolation 720s before its capacity could move — a 300s etcd blip
  traded for 17 minutes of capacity loss. Active unmount finishes within
  `fence + T_clean`, so **the T_safe formula needs no fence term**, and the
  node pools stay warm.
- **In-place recovery**: etcd writes recover → unfence → re-grant presence
  for **all connected nodes** (the leases expired during the partition, not
  just the presencePending ones) → serve immediately — zero churn, zero
  reconnects.
- No conflict with tolerance-first: the loss threshold is generous
  (minutes); an etcd blip of tens of seconds does nothing; only a
  **persistent** partition steps down.
- Cost: status polls still work during the partition (in-memory leases, no
  etcd), so the active unmount aborts background execs that would have
  finished within the `[fence, fence+tolerance]` window. In exchange: the
  time formulas stay put + zero node churn + instant in-place recovery.

Hence the design's core time-ordering invariant (validated per node at
connect; violators are refused):

```
T_safe > loss threshold (fence) + T_warden + heartbeat interval (30s)
default: 660 > 180 + 300 + 30 = 510  ✓

T_safe > health tick (5s) + max exec timeout + heartbeat interval (30s)
default: 660 > 5 + 180 + 30 = 215  ✓ (validated at startup, on hot-reload
and against each node's reported T_safe at connect)
```

The two clocks must not cross — the worst case is a **partitioned but
alive** owner:

| Moment | Value |
|---|---|
| worst-case presence expiry | partition start − heartbeat interval + T_safe (the last KeepAlive may precede the partition by a full heartbeat period) |
| fence release completes | partition start + detection (≤1 health tick) + fence + T_clean (`T_clean ≤ T_warden` validated separately) |

With defaults: release completes ≈ 485s, worst-case presence expiry ≈ 630s,
margin 145s. **"Owner health stale + placement node presence absent" now
structurally excludes hidden live mounts** — the §7.6 table's time path and
§13.1's on-demand takeover are thereby airtight. The equivalent constraint
`fence < T_tolerance + heartbeat interval` means the loss threshold cannot
be raised carelessly (the default 180s is safe against T_tolerance=300s).

**Partition recovery**: the partition heals → G1 resumes KeepAlive on
presence/health → the keys are valid again → business as usual, zero churn.
If the partition persists until G1 itself hangs (gateway partitioned from
etcd AND hung) → the sandlot detects the G1 drop via stream keepalive
(~8s) → enters the normal tolerance path (§8.1) → self-clean after
T_tolerance → warden countdown backstop. That is the ordinary
gateway-dead path (§10.2/§10.4), dependent on no notification mechanism.

### 8.6 DNS: follow ownership, never switch

DNS is a pure stateless "resolve ownership → return address" router (except
stream-domain stickiness); its normal-path resolution is covered in
[Ownership & DNS](ownership-and-dns.md). Under failure, four behaviors
matter (all follow from "plain keys survive death" — DNS makes no switching
decision of its own):

- **Within the tolerance window**: the owner gateway may be dead but the
  ownership key remains (no lease) — DNS still returns the owner's address
  (`ownership.gateway_id → registry.gateway_url`, both plain keys,
  surviving owner death). The agent's connects fail and it retries. This
  correctly expresses "ownership unchanged — nowhere else can serve
  either".
- **Owner stale/dead** (§7.7): no dead addresses — the routing gates
  re-target to the gateway holding the placement node's presence
  (presence-directed), or fall to the no-owner scheduling; requests are
  only ever 503-tolerated in the "re-targeted, switching not yet
  authorized" window, never wrongly taken over.
- **Owner gone** (released): short-TTL negative cache; the scheduling
  fallback picks a healthy, routable gateway → that gateway
  createOwnership → subsequent requests flow normally.
- **etcd unreachable, nothing cached**: SERVFAIL (fail closed) — never a
  guess via scheduling.

Double-mount safety is enforced by the gateway's ownership CAS, independent
of DNS timing; a DNS routing mistake at worst causes one 307 redirect or
503 — no data loss.

### 8.7 sandvmm

The underlying KVM process, lifecycle managed by sandlot/boxout. Crash
detection (pidfd/cmd.Wait) → `handleVMDied` → destroy and replace.
Independent of ownership transfer. The sandlot cleanup phase's kill-sandvmm
reuses the existing destroy path.

**The warden-hang path actively kills sandvmm**: when warden probes fail
consecutively (3×3s) or the VMM API is unreachable, `handleVMDied` goes
through the lifecycle manager's `DestroyVM(target)` to **ensure the sandvmm
process is dead first** (embedded: kill/shutdown + confirm-dead; boxout: the
destroy RPC kills by PID) before releasing the CID/network/sandbox
directory — on an already-dead-process crash path this is an idempotent
no-op, but on the warden-hang path it prevents a "warden dead, VMM alive"
leak of the vsock CID and KVM resources. All destroy paths (scale-down /
recycle / crash) share the same target passing; no runtime re-lookup of the
VM table.

### 8.8 Request-path machinery (orthogonal to the ownership paradigm)

These serve the request hot path and failure cleanup; they run independently
of the ownership-transfer paradigm:

- **MountLock**: same-sandfs mutual exclusion during a cold mount (blocking
  wait, not immediate 503); when the holder finishes early, waiters execute
  immediately. No MountLock on the warm path (after the lease forms).
- **sandfsState**: AVAILABLE / CLEANING state machine — CLEANING refuses new
  requests (503 SANDBOX_CLEANING), guaranteeing no concurrency before
  cleanup completes.
- **Sticky lease / placement affinity**: consecutive same-agent calls reuse
  the VM (100ms idle window); placement (persistent in etcd) takes over the
  deleted in-memory preferred-node's full job — node affinity across
  restarts, unmounts, and takeovers.
- **L1 retry / L2 cleanup**: vsock transport error → L1 retry (fresh
  connection); non-retryable error → L2 enter-cleaning → 503 + Retry-After →
  async cleanup (unmount → ownership release; the send-time capacity bound is
  released synchronously on the failing request, before EnterCleaning).
- **Background execs are memory-only**: bg-exec metadata lives in gateway
  memory; unmount's cgroup.kill kills all bg execs; after failure →
  not_found → the agent re-creates them.
- **Per-agent cgroup + switch-time clearing**: cgroup created after mount,
  exec pgids written to cgroup.procs; on switch, cgroup.kill + poll-empty
  clears all agent processes (background included) before umount. Hard
  isolation guarantees no residual process reading the old agent's files.
- **etcd CAS (create / ModRevision)**: concurrency guard for ownership
  create and migrated-takeover forceTakeover.

## 9. Load balancing and saturation rebalance (min-idle watermark + voluntary shed)

All the ownership switching above (§1–§8) is **failure-driven**: the
owner-release chain and migrated takeover move ownership only after
confirming a failure. This section adds **load-driven** mechanisms whose
goal is to make "saturated" show up as something other than 503-retries —
cold-path load migrates to a peer gateway with idle capacity. These are the
first **non-failure-driven** ownership changes in the sandbox service, so
they are off by default, explicitly enabled, and multiply debounced.

**Motivation**: under binpack/spread scheduling + DNS
power-of-two-choices, when one sandlot's pool tops out (all VMs bound,
zero clean), a new sandfs's cold-mount `Acquire` finds no CLEAN VM →
`NO_AVAILABLE_SANDBOX` 503. On a single node that is normal backpressure;
but in a multi-gateway deployment, the same sandfs 503s forever against its
retained owner while the cluster has an idle peer that could serve — the
load never escapes. Two mechanisms rebalance it out.

### 9.1 Mechanism one: the min-idle watermark (sandlot side)

**Idea**: rather than waiting for the pool to top out and 503 passively, the
sandlot keeps a small CLEAN headroom to absorb bursts, reducing how often
the node hits zero-clean.

- Each spec's **effective pool target** = `target + max(1, floor(frac ×
  target))`, `frac` being `recycle.min_idle_floor_frac` /
  `-min-idle-floor-frac` (default 0 = off; 0.05 = 5%). Hot-reloadable.
- Applied to scale-up (ResizePool), ReconcilePool, and
  destroy-and-replace: pre-create CLEAN VMs as headroom; **not applied to
  scale-down** (recovery does not fire for headroom below target).
- Headroom ≠ idle guarantee: sustained load consumes the headroom too; it
  only guarantees "a burst finds a spare CLEAN VM instead of instant
  zero-clean". The sustained-saturation judgment above (§9.2) then triggers
  less often.

### 9.2 Mechanism two: voluntary shed (gateway side)

**Trigger (all must hold)**:

1. **Enabled**: `shed.enabled` / `-enable-load-shed` (default on,
   hot-reloadable);
2. **Sustained saturation**: all connected nodes zero-clean for ≥
   `shed.sat_sec` (hysteresis window, default 15s, resisting momentary
   spikes);
3. **An idle peer exists**: the peer-load monitor watches `/sandswap/load/`
   (each gateway publishes every 2s, TTL 10s, read-side freshness window
   15s tolerating a couple of missed publishes) and finds a fresh peer with
   `clean_vms > 0` (the peer's routing address is in the
   `/sandswap/gateway/{id}` registry key — only the capacity signal matters
   here);
4. **Rate limit**: at most `shed.rate_per_sec` per second (token bucket,
   anti-avalanche).

**The shed action (executed only on the cold-path `NO_AVAILABLE_SANDBOX`
branch)**:

- The cold attempt first **ends its dispatch record** (`EndDispatch`), then
  sheds. This order is load-bearing: the mount path sets `dispatching`
  before acquiring a VM, and shedding while that flag is still set was a
  guaranteed no-op (the shed refuses a dispatching entry) that nevertheless
  told the client to re-resolve — it re-resolved straight back to this
  gateway. Every caller is a FAILED cold attempt, so no mount can land
  afterward.
- `deleteOwnership(sandfs)`: delete the ownership key → the next DNS query
  finds no owner → falls back to scheduling (§8.6), which picks the idle
  peer;
- a `recentlyShed` cooldown mark (`shed.cooldown_sec`, default 30s): within
  the DNS cache window the client may still route back to us → during
  cooldown, re-claiming is refused (`ErrShedCooldown`), leaving the peer a
  claiming window;
- return a **raw HTTP 503 + Retry-After + `Connection: close`** (no JSON
  body, not an MCP isError result): the client must close the connection →
  re-resolve the sandfs DNS name → DNS now returns the peer.

**Why 503 + `Connection: close` suffices**: clients are arbitrary standard
HTTP/MCP clients with no custom error-code or protocol assumptions;
"re-resolve DNS" is standard client behavior on connection-close + 503.
**Convergence latency is not under Sandswap's control** (it is the client
resolver's cache ≈ the name's TTL); the owner keeps 503+close until the
peer claims. Dropping `Connection: close` would let the keep-alive
connection be reused — the client would never re-resolve DNS; the header is
mandatory.

**Why cold-path only**: the warm path (sticky-lease hit, 0.71ms) is the
performance core and must never be interrupted by load judgments on an
established warm sandfs; only the cold path (new mount) is worth giving up
ownership and re-routing.

**Cooldown convergence loop**: the peer claims (CAS createOwnership) → we
observe via watch that the new owner is not us → `ClearShed` clears the
cooldown → later no-owner events can be claimed normally. If the peer never
claims, the cooldown expires (the sweep) and claiming reopens.

### 9.3 Full timeline

```
client             gateway A (saturated owner)       DNS            peer gateway B (idle)
  │  exec(sandfs X)                                 │                │
  │──── POST /agent/execute ──────────────────────>│                │
  │    X cold path: Acquire → no CLEAN VM (sustained ≥ sat_sec)      │
  │    HasIdlePeer(B) ✓ → rate token ✓             │                │
  │    deleteOwnership(X) + recentlyShed(X)        │                │
  │<─── 503 + Retry-After + Connection: close      │                │
  │  (client closes the connection)                │                │
  │──── re-resolve X.sandswap ──>│── owner absent → scheduling picks B
  │<─── A record: gateway B ─────│                 │                │
  │  exec(sandfs X)                                │                │
  │───────────────────────────────────────────────>│  Claim(X)      │
  │                                                │  createOwnership(X) CAS ok
  │<──────────────────── 200 exec ─────────────────│  ClearShed (watch observed)
```

### 9.4 Boundary with the tolerance-first paradigm

- The shed is **voluntary, non-failure**: it touches none of the
  owner-release chain / migrated-takeover verdicts; it acts only on
  "self-saturated + idle peer exists" cold-path requests.
- Shed granularity is extremely fine: each shed affects the ownership of a
  **single sandfs**; no node-wide churn.
- Warm/sticky lease, owner release, and migrated takeover paths are entirely
  unchanged.
- DNS keeps its §8.6 stateless semantics: the shed's only effect is deleting
  the ownership key so DNS's natural fallback carries the load to the peer;
  DNS does not need to know the concept "shed".
- Independent of §8.4's etcd partition: the shed depends on the idle-peer
  check (reading `/sandswap/load/`); during a partition it reads stale/empty
  → no shed — safe.

### 9.5 Configuration summary

Gateway side (`shed:` section / flags, all hot-reloadable):

| Config | Default | Meaning |
|---|---|---|
| `enabled` / `-enable-load-shed` | true | master switch (default on) |
| `sat_sec` / `-shed-sat-sec` | 15 | sustained-saturation seconds (hysteresis window) |
| `rate_per_sec` / `-shed-rate-per-sec` | 1 | max sheds per second (token bucket) |
| `cooldown_sec` / `-shed-cooldown-sec` | 30 | recentlyShed cooldown window |
| `retry_after_sec` / `-shed-retry-after-sec` | 5 | the 503's Retry-After hint (≈ sandfs DNS TTL) |

Sandlot side: `recycle.min_idle_floor_frac` / `-min-idle-floor-frac`,
default 0 (off).

### 9.6 Known boundaries and debouncing

- **Cluster-wide saturation** (no idle peer): the idle check is false → no
  shed; behavior equals the feature being off (normal 503 backpressure).
- **Client keeps routing back within the DNS cache window**: during
  cooldown, always 503+close — never a second shed (never undoing one).
- **No upper bound promised on convergence latency**: the client's DNS
  resolver decides; Retry-After is only a hint.
- **min-idle headroom vs shed**: the watermark lowers zero-clean frequency
  and thus shed triggering; two complementary levers toward the same goal
  (avoid saturation deadlock), independently switchable.

## 10. End-to-end timelines (all paths)

### 10.1 Gateway blip/restart (most common; zero machinery)

```
t=0     G1 restarts (upgrade/blip). The ownership keys have no lease → they stay.
        The sandlot's stream briefly drops → tolerance clock starts (< T_tolerance)
t≈30s   G1 comes back; the sandlot reconnects to G1 (preferred). Presence key
        re-granted + put. Ownership unchanged throughout. No double-mount, no
        switch, no cleanup.

⚡ Cost: the blip duration only (seconds). The ownership keys naturally
  persist — zero extra machinery.
```

### 10.2 Gateway permanently dead + sandlot alive (migrated takeover)

```
t=0      G1 dies. The health key stops refreshing but does not vanish (no
         lease); G2 judges it dead past route-stale and the routing gate
         starts directing (§7.7) — but moves no ownership.
         G1 cannot KeepAlive the presence key → it expires at t=T_safe=11min.
         The sandlot detects the drop → tolerates T_tolerance (keeps probing
         the warden; the countdown keeps resetting)

t=5min   the sandlot starts self-cleanup: persists cleaning, ★stops heartbeats
         (the countdown starts decaying); concurrent OP_UNMOUNT of all VMs

t=10min  cleanup done (or the warden countdown backstop-kills stragglers at
         T_tolerance+T_warden=10min)

t=11min  the presence key expires (T_safe passed)

t=12min  the sandlot's isolation ends → connects to G2 → re-adopt-light →
         G2 writes the new presence key.
         An agent request reaches G2 → Claim → G1 dead + local live stream
         for A + presence owned by G2 → migrated takeover satisfied →
         forceTakeover → mount

         The old mount was released at t=10min < 12min → no double-mount ✓
```

### 10.3 Sandlot crash + gateway alive (owner release)

```
t=0      sandlot A crashes. G1's local OnDisconnect(A) fires → A enters the
         "disconnected, pending" set; a local T_safe timer starts. G1 also
         stops KeepAlive-ing the presence key.
         (If the sandlot merely blipped and reconnected within tolerance:
         the stream recovers, the presence key recovers, no cleanup at all.)

t=0~T_safe   the warden countdown (last heartbeat ≈ crash time) releases the
             old mount at t ≤ T_warden.
             Requests to G1 → Claim → owner=G1(self) → node_id=A, local stream
             down → 503 + retry

t=T_safe(11min)  the local timer expires. G1 checks the owner-release chain:
                 OnDisconnect(A) ✓ + T_safe elapsed ✓ + presence absent ✓ +
                 self healthy ✓
                 → delete the ownership key of every sandfs in nodeSandfs[A]
                 → the next request → createOwnership → routed to another
                   node, mounted

                 The old mount was released at t≤5min ≪ 11min → no
                 double-mount ✓
```

### 10.4 Gateway dead + sandlot dead (both-dead; safe-stuck)

```
t=0      G1 dies. Sandlot A dies too (permanently).
         The warden countdown releases the old mount at
         t ≤ T_tolerance+T_warden = 10min.
         Requests to G2 → Claim → G1 dead (health stale past guard) +
         sandlot A's presence expired, but G2 has no live local stream for A
         (the sandlot never came) → owner release unmet (G1 dead) + migrated
         takeover unmet → 503 + retry (persistent tolerance)

         ⚠️ No double-mount (the old mount is released; nobody moved
           ownership; nobody mounted)
         ⚠️ The sandfs is unavailable until manual cleanup or backstop
           reclamation (§13)
```

### 10.5 Combined failure (gateway hang + later sandlot crash)

```
t=0      G1 hangs. The sandlot detects at ~8s → tolerates → self-cleans at
         t=5min (stops heartbeats)
t=any    the sandlot crashes mid-cleanup (the scenario that produced a
         double-mount window in the race model)
         The warden countdown fires at the fixed t=T_tolerance+T_warden=10min
         → the old mount is released

         Requests to G2 → G1 dead + the sandlot never came (no local stream)
         → neither owner release nor migrated takeover satisfied → 503+retry.
         Ownership does not move. No double-mount. ✓

         The race model's double-mount window is entirely gone: no lease
         expiry triggers switching; there is no race.
```

## 11. Safety analysis

### 11.1 The single invariant

> **Every old-mount release path completes before the switching condition is
> satisfied (the conjunction holds / the sandlot's migration is confirmed).**

Proof (reference values):

| Old-mount release path | Completion time | < switching condition met? |
|---|---|---|
| sandlot self-clean (OP_UNMOUNT) | T_tolerance + T_clean = 10min | ✓ < T_safe = 11min |
| warden countdown backstop | T_tolerance + T_warden = 10min (fixed anchor) | ✓ < 11min |
| sandlot crash-recovery resume | ≤ 10min (countdown backstop) | ✓ < 11min |
| sandlot crashes within tolerance; countdown alone | ≤ T_warden = 5min | ✓ < 11min |

**The key**: the warden countdown is anchored at T_tolerance (the last
heartbeat) and does not drift with the sandlot's crash time; the
presence-key TTL = T_safe > T_tolerance + T_warden. The minutes-level margin
between two **fixed** anchors makes the invariant hold **unconditionally** —
the many seconds-level-margin invariants collapse to
this one.

### 11.2 Two-directional safety

- **Never switches too early**: switching requires a confirmed condition
  (owner release: OnDisconnect + local T_safe timer + presence expiry;
  migrated takeover: sandlot migration + presence owned by the new gateway;
  dead-owner claim: guard window + CAS). The local OnDisconnect resists etcd
  partition forgery (§7.4); the presence key guarantees T_safe passed → the
  old mount is released.
- **Never cleans up too late**: neither the warden countdown nor the
  presence key depends on the gateway being alive — they run to completion
  even with the gateway dead. Cleanup is self-protective (driven by the
  sandlot/warden themselves) and needs no external command.

### 11.3 Residual risks

1. **Both-dead stuck** (§10.4): safe but unavailable; needs the backstop
   (§13).
2. **Sandlot crash-restart takes > T_warden**: the countdown kills the VM
   first; the restarted resume becomes a no-op on already-dead VMs. Not a
   double-mount — cleanup simply finishes via the warden backstop.
3. **etcd partition**: a gateway alive but partitioned from etcd cannot
   KeepAlive its presence/health keys → they expire. But §7.4's chain
   guarantees owner release does not trigger then — the partitioned gateway
   is still connected to its sandlots (stream alive, no OnDisconnect), the
   local signal fails → ownership does not move; no double-mount, no
   wrongful delete. After healing, the gateway refreshes its keys and
   recovers in place. See §8.4.

## 12. Availability tradeoffs

| Scenario | Recovery window | Notes |
|---|---|---|
| gateway blip (recovers < T_tolerance) | **blip duration (seconds)** ✓ | ownership naturally persists; continue in place — the most common scenario is also the fastest |
| gateway persistent failure + sandlot alive | ~T_isolation (12min) | migrated takeover path |
| sandlot failure + gateway alive | ~T_safe (11min) | owner-release path; other nodes take over after release |
| owner dead + sandfs idle | ~claim-dead-guard (45s) | time-guarded claim (§7.8), far faster than T_safe |
| combined failures | **no double-mount** ✓ (possibly stuck) | safety first; both-dead needs manual/backstop action |
| agent view | 503 + retry | budget ≤ T_isolation; agents cope by retrying |

**The core tradeoff**: transient failure (most common) recovers **fast**
(seconds, in place); persistent failure (rare) recovers **slowly**
(11–12min) but **eliminates double-mounting**. This matches principle 1 —
agents already assume the system is unreliable and cope by retrying.
`T_tolerance` being configurable is the key lever: longer tolerance (e.g.
slow rolling upgrades) means raising it to 10min, with T_safe / T_isolation
derived accordingly. **The ≥5min minimum prevents degenerating back into the
race model by configuration.**

For agents, one operational consequence deserves emphasis (from the in-VM
exclusivity contract): a switch terminates all your processes immediately —
finish large writes within one exec (or use background exec with a sensible
`lease_duration`), `sync` at the end of execs holding critical data, and
keep intermediate state in files rather than process memory.

## 13. Residual risks and manual backstops

### 13.1 Final reclamation of both-dead (on-demand takeover + manual tools)

When G1 and the sandlot are both permanently dead, no living party can
confirm; ownership does not move; the sandfs is stuck (safe but
unavailable). **Stuck only matters when someone wants the sandfs** — an
unvisited stuck key is a few static bytes that harm no availability. So the
primary reclamation path is not background scanning but **on-demand takeover
on the request path** (the §7.6 decision table): someone asks for the
sandfs, the owner is dead, the placement node's presence is absent (time
proof of mount release) → time-guarded CAS takeover. Zero scanning cost, no
background load at 100K-key scale; the situations that delete these keys
(sandbox deletion) already have an explicit deletion path.

**Manual tools (ops acceleration)**:

After a human confirms "the node is not coming back" (operational knowledge,
not in etcd), batch reclamation can run immediately — no waiting for a
request or the time proof; the guard = the node's presence key gone / stale
past T_safe. The cleanup tools filter by gateway_id value, delete in
batches, and support dry-run:

- `POST /human/ownership/reap-stuck` (by owner gateway_id): idle sandfs
  (dead owner) are reaped immediately; the rest only when the node's
  presence key is absent (else skipped); a live owner is refused (409).
- `POST /human/ownership/reap-stuck-node` (by node_id): reclaims every
  sandfs **placed** on the dead node (placement is the selection key) whose
  owner gateway is ALSO dead — an alive owner's sandfs are skipped (its own
  release chain reclaims them; reaping would race a live owner's recovery);
  refused while the node's presence key is still alive.

See [Human API](../reference/human-api.md) for the request/response
schemas and operator workflows.

**Mounted-class keys auto-reclaim under the same proof**: mount state
never enters etcd, and the auto-takeover bar is uniformly the §7.6 time
proof — "owner dead + placement node presence absent". The partition-forgery problem for presence/health (both
gateway-proxy-written) is closed by self-fencing (§8.5): a gateway
partitioned past the threshold actively unmounts and stops serving, so
"health stale + presence absent" structurally excludes hidden live mounts.

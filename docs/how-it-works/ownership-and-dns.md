---
title: Ownership & DNS
nav_order: 10
parent: How It Works
---

# Ownership & DNS

> This page covers the **normal path**: how a request is routed — sandns →
> gateway → node → microVM — and the two facts (ownership, placement) the
> routing is built on. Everything that happens when a component *fails* is
> [Resilience](resilience.md). The code is the only implementation truth;
> this page covers the stable design and mechanisms.
>
> See [Design Principles](design-principles.md) for the architecture
> principles.

## 1. Role and scope

sandns, ownership, and placement exist for one purpose: **minimal end-to-end
latency** ([Design Principles](design-principles.md), Principle 2). Every
design choice here serves that goal. In steady state a command is pure
delivery —
the request travels agent → sandns → gateway → node → microVM with no
coordination on the command path: sandns hands it to the gateway that can
serve it immediately, ownership keeps a sandfs pinned to one gateway, and
placement keeps it pinned to one node, so nothing is re-decided per command;
the only shared coordination point (etcd) is read on demand with local
caching and written only when something actually changes. The same two facts
are also what enforce **never double-mounted** (Principle 4): ownership is
the exclusivity guard.

sandns is how AI agents and sandlots discover gateways. It serves three
resolution domains:

| Domain | Query form | Consumer | Purpose |
|--------|-----------|----------|---------|
| **sandfs domain** | `<sandfs_id>.sandfs.sandswap.local` | AI agents | Reach the owner gateway of a specific sandfs |
| **agent domain** | `sandswap.local` | AI agents | Bootstrap entry: reach a healthy exec gateway for `GET /agent/sandfs` discovery |
| **stream domain** | `sandswap-stream.local` | sandlot | Find the gateway to connect to |

The three domain names are deployment configuration (`domains.agent` /
`domains.stream` / `domains.sandfs` in sandns's config — see
[sandns configuration](../operations/configuration/sandns.md)); the names above are
what the shipped deployment configs use. Gateway addresses themselves are
never configured — each gateway self-registers its address into etcd (§4).

Sandbox guests are NOT consumers: a source in `guest_cidrs` gets NXDOMAIN
for every per-sandfs name (the answer reveals neither existence nor owner —
DNS carries no ownership proof) and REFUSED for the stream/agent zones, so
the zone cannot be used as a routing-topology or ownership oracle.

All agent execution operations (execute / file / exec-status / kill / MCP)
carry a `sandfs_id`, so per-sandfs routing is owner-aware. The one agent call
that structurally does not need one is `GET /agent/sandfs` — discovery, by
definition, runs before the agent knows any sandfs id. The shared agent
domain exists for exactly that bootstrap call: it resolves to one healthy
exec gateway picked by the
scheduling policy, and **any exec gateway can answer** — the identity store
is etcd-backed and cluster-wide, so discovery returns the same list wherever
the query lands. Everything after discovery addresses the per-sandfs domain.
(Spread/binpack is a *sandfs placement* policy; its unit is the sandfs, not
the agent — the agent domain does no per-agent stickiness.)

sandns is a **stateless router** (except sandlot stickiness in the stream
domain): health and load are all read from etcd; ownership is looked up on
demand via etcd + an LRU cache (§6). It takes no part in safety — the
gateway's ownership CAS prevents double-mounting; sandns only makes
routing *recommendations*. A sandns routing mistake at worst causes one
migrated takeover or one 307 redirect — no data loss.

### 1.1 Exec-plane state only; the human gateway is ownership-free

The sandns candidate set is built ENTIRELY from exec-plane state —
ownership records, node presence keys, and gateway health/routing
registrations are only ever written by exec gateways and their nodes. Two
invariants follow:

- **The human gateway holds no ownership**: it never claims, never takes
  over, never participates in the etcd-partition fence. Its only ownership
  touch is a release attempt during sandfs-delete teardown (after the
  unmount sweep + overlay cleanup, before the volume delete); releasing a
  key owned by another gateway is a no-op by design, so in a split
  deployment the OWNER releases it when its drain settles to `detached`,
  and the human gateway's delete completes only once the key is observed
  ABSENT (bounded poll) — it never assumes its own release worked. The
  human gateway's availability therefore depends on nothing beyond its own
  HTTP service and a connected prov set — no leases, no T_safe arithmetic.
- **Prov-role sandlot instances have ZERO etcd footprint**: a prov instance
  registers no presence, no health, no routing keys; it is never
  placement-eligible (`PeekNode` filters to exec-role instances) and never
  appears in any sandns answer. Its health signal is the stream connection
  itself.

## 2. The two facts: ownership and placement

Two words carry the whole routing model. They name two *different* facts
about a sandfs, stored in two different places:

- **Ownership** — *which gateway is responsible for this sandfs.* It is the
  exclusivity guard: only the owner may mount the sandfs, and any other
  gateway that receives a request for it either redirects (307) or refuses.
  Ownership lives in the etcd key `/sandswap/owner/{sandfs_id}` — a plain
  key with no lease: it never expires by time and changes only through
  explicit, confirmed operations (create / placement-change / owner-release
  delete / takeover CAS). The value is `{gateway_id, node_id, generation}`.
- **Placement** — *which node the sandfs belongs to* (the node of its most
  recent mount). It is an **affinity fact, not a mount status**: it survives
  unmounts, node reconnections, and takeovers. It is the `node_id` field of
  the ownership record. Node selection prefers the placement node
  (affinity — cache warmth beats capacity), and the two manual reclamation
  tools select by it.

**Mount state** — whether the sandfs is currently mounted on a node — is
transient: it exists only in the owner gateway's memory, never in etcd.
Steady-state etcd writes are therefore zero per execution cycle; the
ownership key is written only when ownership or placement actually changes.

The supporting etcd key families (all read by sandns; all written by the
components themselves — sandns polls no gateway HTTP endpoint):

| etcd key | Writer | Value — what is stored | Routing use |
|----------|--------|------------------------|-------------|
| `/sandswap/owner/{sandfs_id}` | gateway (CAS create; plain key, no lease) | `gateway_id` — the owner; `node_id` — the sandfs's placement (last node it mounted on, `""` = never placed); `generation` — bumped on every ownership change, orders concurrent takeovers | Owner lookup (on-demand Get + LRU); when the owner is stale/dead, `node_id` → presence-directed routing |
| `/sandswap/gateway/{gateway_id}` | gateway (plain key, self-registered at startup) | `gateway_url` — the address agents use (307 target, DNS answer); `stream_addr` — the host:port sandlots dial. Survives the gateway's death | The only address source for every branch; kept fresh via registry watch |
| `/sandswap/health/{gateway_id}` | gateway (plain key, no lease; rewritten every 5s) | `last_healthy_ts` — when the gateway last proved alive (death is judged by how stale this is, not by a lease); `node_count` | Health gate for the fallback pool and the owner-staleness branch (threshold `route_stale_sec`, default 20s) |
| `/sandswap/load/{gateway_id}` | gateway (lease 10s; rewritten every 2s) | `agg_duty_long` — mean per-node duty, the scheduling score; `clean_vms` — spare capacity; `self_pressured` — the gateway's own process-pressure flag | Scheduling score + capacity gate + self-pressure gate |
| `/sandswap/node/{node_id}/presence` | gateway (lease TTL = T_safe, KeepAlive on heartbeat) | the bare `gateway_id` the node is currently connected to | Presence-directed routing when the owner is stale/dead |

**Why not poll gateway HTTP**: the gateways already publish health and load
into etcd; reading a second source would duplicate it and disagree with it.
During an etcd partition the gateways themselves fail closed, so routing
could not reach a serving gateway either way — the outcome is 503 with or
without a poller.

## 3. The request path, end to end

One command request, cold, from the agent to the microVM. Four hops, each
with one decision:

```
agent ──sandns──▶ gateway ──node stream──▶ sandlot ──vsock──▶ microVM
            step 1                  steps 2–3           step 4
```

### 3.1 Step 1 — sandns picks a gateway

The agent resolves `<sandfs_id>.sandfs.sandswap.local`. The answer has three
branches, in order:

1. **Owner fresh** (ownership known; the owning gateway's health record is
   fresh — `last_healthy_ts` younger than `route_stale_sec`, default 20s) →
   return the owner's address (`gateway_id` → registry `gateway_url`). An
   owned sandfs must go back to its owner — rerouting it would trigger a
   switch; an overloaded owner is a capacity-planning problem, and moving
   owned sandfs is load-shed's job, not routing's.
2. **Owner stale/dead** (the owning gateway's health record is stale past
   `route_stale_sec` — the gateway is dead or cut off from etcd) → routing
   is now decided by the sandfs's **placement**: read the ownership value's
   `node_id` and ask that node's **presence key** which gateway it is
   currently connected to. Two cases:
   - **The node sits on a different, live gateway** — its sandlot
     reconnected to a peer while the old owner was down. Return *that*
     gateway's address (**presence-directed routing**): it holds the node,
     so it is the only gateway that can serve the mount, and the only one
     eligible to take over. Directing there eliminates guessing.
   - **The node is still attached to the dead owner, or has no live
     holder** (idle or never placed; presence absent, or naming a gateway
     that is itself stale) — there is no live peer to route to. Fall
     through to branch 3; whether and when the picked gateway may claim the
     sandfs is the takeover logic's business ([Resilience](resilience.md)).
3. **No owner** (never claimed, or released) → the scheduling policy
   (§5) picks a healthy gateway. Whichever gateway receives the request
   claims ownership — for an unowned sandfs, sandns's pick *is* the
   ownership decision.

Two properties of the owner branch:

- **The address is registry-sourced, never ownership-sourced**: a gateway
  restart with a new `--gateway-url` rewrites `/sandswap/gateway/{id}` once
  (O(1)) and the next query returns the new address — no per-sandfs
  staleness, because the address is not copied into a million ownership
  keys.
- **Fail-closed on etcd unreachability**: with ownership unknown and
  nothing cached, the query returns SERVFAIL (the client retries) rather
  than guessing via scheduling — a transient etcd blip must not reroute
  owned sandfs to non-owner gateways.

### 3.2 Step 2 — the gateway claims ownership

The request lands on a gateway. The **Claim path** is the gate every request
passes:

- **Owner is self** → serve (the warm path may short-circuit here; see
  below). The one failure corner — a self-owned sandfs whose placement node
  has disconnected (orphan-suspect) — is interrogated before serving; see
  [Resilience](resilience.md).
- **No owner** → `createOwnership` — a CAS create that writes
  `{gateway_id, candidate placement, generation}`. The candidate placement
  is the node picked by `PeekNode` (score-only, reserves nothing), so
  `node_id == ""` ⟺ no node could be selected ⟺ no mount was ever
  dispatched — the record never sits in a mountable state with an empty
  placement.
- **Owner is someone else** → a 307 redirect to the owner's registry
  address (after an owner-staleness check). The redirect is the safety net
  for sandns mistakes and stale client caches. A live owner needs only the
  redirect; a dead owner turns this branch into the failure-driven decision
  table — takeover, claim guards, tolerate-vs-take-over — covered in
  [Resilience](resilience.md).

### 3.3 Step 3 — the gateway picks a node

For a cold mount, the gateway's pool manager runs `Acquire` over its
connected nodes: **affinity → filter → score** (§5). It returns
`(node_id, floor_spec)` and atomically reserves one bound VM so the derived
clean count drops before a concurrent `Acquire` can read it. The gateway
never tracks individual VMs — node capacity (per spec: total / clean /
bound) is what the node's heartbeats report.

### 3.4 Step 4 — the sandlot picks a microVM

The gateway sends the VMCommand over the node's gRPC stream. The sandlot
resolves the target VM (`resolveVMForMount`):

- **Warm** — the sandfs is already bound to a live VM on this node → that
  VM (no remount; commands run in parallel up to the spec's `exec_slots`).
- **Cold** — the smallest-spec CLEAN (unbound, alive, spec-satisfying) VM
  is picked and bound (best-fit, not first-fit: a small sandfs should not
  waste a large VM).

The microVM lifecycle (states, verified creation, sticky lease, recycle,
re-adopt) is [microVM Lifecycle](vm-lifecycle.md).

### 3.5 One DNS lookup, then a long-lived connection

sandns is on the path once per **connection**, not per command. The agent
resolves the sandfs domain, connects, and then keeps the connection open —
an HTTP keep-alive session or a long-lived MCP session. Every subsequent
command rides that established connection: no name resolution, no
connection setup, only the request itself. Keeping per-command overhead at
this floor is the point of the design — DNS, ownership lookup, and
connection setup are all cold-path costs that the steady state never pays
again.

sandns is consulted again only when a new connection must be established:

- **The connection broke** (gateway dead, TCP reset, client restart) — the
  reconnect re-resolves; if ownership moved meanwhile, the answer follows
  it.
- **Load-shed closes the connection deliberately** — a saturated owner
  returns 503 + `Connection: close` so the client must drop the connection
  and re-resolve, letting the scheduling fallback route the next
  connection to an idle peer ([Resilience](resilience.md), saturation
  rebalance). The header is mandatory precisely because a keep-alive reuse
  would never consult sandns again; convergence is bounded by the client
  resolver's cache (≈ the name's TTL).
- **A plain 503 does not re-enter sandns** — the agent retries on the same
  connection or reconnects to the same owner. During the tolerance window
  that is exactly right: ownership has not moved, and nowhere else can
  serve.

### 3.6 The warm path

The above is the cold path. When the sticky lease is live (same sandfs,
within the 100 ms idle window), the request short-circuits at step 2: no
Claim write, no `Acquire`, no VM resolution — the gateway routes the command
straight to the bound VM over the cached node stream. This is why the warm
path is sub-millisecond.

## 4. How a sandlot finds a gateway

The stream domain `sandswap-stream.local` answers a sandlot's first-connect
query:

1. **Sticky hit** (keyed by sandlot IP) + gateway alive with a registered
   stream address → return the sticky gateway. Capacity is deliberately not
   re-checked: sticky is a soft affinity hint, and the duty cap gates only
   NEW placements.
2. Sticky expired → the scheduling policy picks one.
3. No healthy gateway → SERVFAIL.

**Stickiness keyed by sandlot IP (the client IP) is sound**: one sandlot
connects to one gateway (principle 5), so sticky = "this sandlot prefers
its previous gateway". This is the stream domain's only in-memory state —
small (few sandlots, long-lived connections, low query rate).

After the first connect, the sandlot keeps its own **preferred-IP memory**
and mostly stops asking sandns:

- **Normal reconnect**: prefer the remembered IP if sandns still lists it;
  otherwise pick a random resolved candidate. The randomness matters on
  headless-Service DNS (k8s): the multi-IP answer has a deterministic
  order, and always taking the first IP would herd every reconnecting
  sandlot onto the same gateway pod.
- **During TOLERATING** (gateway lost, within the tolerance window): dial
  the remembered IP **directly, even if sandns has already dropped it from the list** — a
  gateway restart briefly evicts the old IP from sandns, and requiring
  re-confirmation would idle the node through the whole tolerance window
  for a gateway that returns in seconds. The "only ever dial the
  remembered gateway" rule is itself the safety guarantee.
- **sandns unreachable or empty**: the same direct dial is the fallback — a
  sandns outage must not strand the node. Each connect attempt re-resolves,
  so failover resumes once sandns recovers.

The stream domain's candidate set comes entirely from etcd
self-registration: every gateway writes its routing address into
`/sandswap/gateway/{gateway_id}` at startup (registry = candidacy, health
= liveness, load = scoring), and the registry key's `stream_addr`
participates directly in resolution (A/SRV; IP or hostname targets both
supported). There is no static gateway configuration list; orphan
registry keys (a gateway permanently retired) are cleaned up by ops.

The failure-side behavior of this connection (the tolerance/cleanup/
isolation state machine, ownership transfer on migration) is
[Resilience](resilience.md).

## 5. Scheduling policies (both layers)

Placement happens on two orthogonal axes, both **binpack by default**, both
with the same "pack + hard-cap overflow" philosophy, independently
configured, hot-reloaded, and failing independently; each packs only
within confirmed-qualified candidates, with hard caps handling overflow:

- **Gateway layer (outer)** — sandns picking a gateway for an unowned
  sandfs or a sandlot (this section).
- **Node layer (inner)** — the owner gateway picking a sandlot node for a
  cold mount (below).

### 5.1 Gateway layer: binpack / spread

Applies to the sandfs domain's no-owner branch and the stream domain.
**Does not apply to owned sandfs** (they must go back to their owner).

- **binpack is the default** (a missing config value or anything other
  than `spread` normalizes to binpack): pick the highest `agg_duty_long`
  (stack onto the busiest; once full, the `duty_hard` cap excludes it and
  work naturally spills to the next). Lets idle gateways actually go idle.
- **spread**: pick the healthy gateway with the lowest `agg_duty_long`.
- **Gates** (applied before the policy): alive with compute
  (`node_count > 0`), a routable registry address, `clean_vms > 0`
  (capacity), not `self_pressured`, and `agg_duty_long < duty_hard`
  (default 0.85). The compute/capacity gates apply to the **sandfs-domain
  fallback only** — stream placement deliberately exempts them, because a
  compute-less gateway must remain a valid sandlot target or a drained
  cluster could never re-fill: the sandlot connecting IS what brings
  compute back (no deadlock).
- **Self-pressure gate**: every other signal is node-side, so a gateway
  whose own process is struggling while its sandlots idle looks like the
  BEST candidate (low duty). The gateway therefore publishes a
  `self_pressured` flag measuring its own process (sustained CPU as a % of
  GOMAXPROCS, managed memory vs the soft limit — process-scoped, so
  co-located VM compute never inflates it). A pressured gateway is
  excluded from new placement; a gateway with no load record yet
  (bootstrap) is never excluded. The gate deliberately does NOT touch the
  owner branch, presence-directed routing, or stream stickiness.
- **power-of-two-choices** (>2 candidates): deterministically picking the
  best gateway would concentrate every no-owner query within one
  load-publish window (2s) onto the same target — a thundering herd for
  spread, a single absorber for binpack after a gateway death. Instead:
  sample two healthy gateways at random and pick the one the policy
  prefers. With ≤2 candidates selection stays deterministic (the common
  two-gateway case is stable).

### 5.2 Node layer: filter → affinity → score

The owner gateway's cold-mount `Acquire` (returning the node that step 3 of
the request path uses, and the placement that gets recorded):

1. **Affinity (strong, unconditionally first)**: if the sandfs's placement
   node qualifies, return it directly. This is the payoff of placement
   surviving unmounts/reconnects/takeovers — neither the scheduling policy
   nor the crash penalty may override affinity.
2. **Filter (hard)**: node online, has a CLEAN VM satisfying the spec
   requirement (vcpus/memory), and under the hard caps — host-CPU / duty
   ceiling (0 = off; conservatively default-off) + a tail floor (nodes
   whose 60s min-clean window is below `max(1, FloorFrac · pool_target)`
   are excluded only when the host is simultaneously saturated —
   freshly-zeroed + high pressure = real saturation; low-pressure-zero is
   just a small pool).
3. **Score (policy)**: among the qualified nodes, take the best score.
   **binpack** (default) prefers high duty; **spread** prefers low duty.
   All components are normalized to [0,1] — the clean term is cleanFrac
   (fitting clean / pool_target, falling back to the cluster max when a
   node does not report pool_target) so no term can drown the others by
   raw magnitude (the clean term once used raw counts: 30 clean VMs gave
   a 3.0 term that swamped a busy node's 0.54 load term, making binpack
   nominal only). Both modes share one tail-risk penalty (60s peak duty +
   duty variance + zeroing frequency), so binpack prefers "busy but
   stable" nodes, not "busy and spiky" ones. Ties break on clean capacity.
4. **Crash soft penalty**: a node that reported a VM crash within the
   penalty window (2 minutes) is demoted in non-affinity selection
   (crash-free nodes strictly first; if all have crashed, fall back).
   Demote, never filter — a single-node deployment must never be starved.
   The penalty window only needs to cover one heartbeat — the heartbeat's
   totals are what actually remove the dead VM's capacity.

**binpack/spread act only on new landings**: there is no active migration
or eviction. An already-placed sandfs is re-placed passively only when its
placement node fails (no fitting CLEAN VM, disconnect, over the hard cap).
binpack cannot concentrate existing placements, cannot drain idle nodes —
concentration happens only gradually through where new sandfs land. This is
deliberate: the churn cost (remount + etcd writes + agent retries) exceeds
the concentration benefit.

## 6. sandns scalability: the owner cache and the watch model

This section is about sandns's scalability: what it caches, what it
watches, and why the sandfs-zone answering path stays cheap as the fleet
grows. The sandfs-domain owner lookup (§3.1, step 1) is an on-demand
LRU + TTL, measured from the last etcd confirmation:

- A million sandfs are not fully watched (RAM + event storm) — on-demand
  Get + LRU (capped at 1M entries, `owners.cache_max`; ~250-300MB at full
  occupancy — the cap is a memory bound, not a pre-allocation).
- Freshness is measured from `fetchedAt` (when the value was last confirmed
  against etcd), NOT from the last use: a continuously-queried sandfs still
  revalidates every TTL window (30s positive, 1s negative), so an ownership
  change (takeover/release) becomes visible within one TTL even for the
  busiest sandfs. Recency of use only decides LRU eviction.
- On etcd failure nothing is cached as "no owner": a stale-known owner is
  served as-is (stale-while-error, retry deferred ~500ms), and with
  nothing cached the query fails closed (SERVFAIL) rather than falling to
  spread/binpack.
- No owner → short negative cache (1s), then the scheduling fallback.

Implementation properties (all implemented, verified at 100k+ entries):
O(1) LRU eviction (hits only bump an atomic `lastUsed`; the background
evictor requeues entries used within a 30s grace window — an approximate
LRU with exact protection for actively-queried sandfs); lock-free hit path
for writers (`lastUsed` atomic, hits take only a read lock); singleflight
on miss (concurrent misses for the same sandfs collapse into one etcd Get,
bounded to 256 concurrent Gets); negative caching (1s). Scaling sandns to N
instances multiplies owner-cache misses (etcd reads) and health/load
watches (per-gateway, cheap) by N — a deployment cost, not a code defect.

sandns watches `/sandswap/gateway/`, `/sandswap/health/`, and `/sandswap/load/`
(per-gateway, O(gateways), bounded, independent of sandfs count), with a
full re-list every 30s as a safety net for missed watch events.
**Ownership is not watched** — the on-demand Get + LRU above is the
scalable substitute.

## 7. Multi-instance sandns deployment

To run multiple sandns instances, put an L4 LB in front (HAProxy / envoy /
keepalived+LVS) with source-IP consistent hashing → the same client always
lands on the same instance. This works because:

- **The sandfs domain is fully stateless** (etcd-driven + on-demand LRU):
  multiple instances are naturally safe, no cross-instance consistency
  needed.
- **Stream-domain stickiness stays local**: source-IP affinity guarantees
  the same sandlot lands on the same instance, so sticky needs no
  cross-instance sharing.
- Sticky is a soft affinity hint; double-mounting is enforced by the
  gateway's ownership CAS. Cross-instance sticky inconsistency at worst
  causes one extra migrated takeover / 307 redirect — no data loss.

What it takes: a health probe for the LB (DNS queries, or a minimal HTTP
`/health`), consistent config across instances (domains, etcd endpoints),
and §6's owner-cache etcd-read multiplication capacity-planned. Sticky
writes are last-writer-wins (a hint; 1800s expiry, self-healing).

## 8. HTTPS

Agents reach gateways over HTTPS (the `gateway_url` is already
`https://host:port`). This is a deployment / client-configuration concern:
the gateway just serves HTTPS, the agent uses `https://`. sandns returns the
host (A/CNAME); the agent initiates the HTTPS connection. sandns needs no
change for HTTPS.

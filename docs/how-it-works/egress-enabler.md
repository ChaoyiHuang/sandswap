---
title: Egress Enabler Contract
nav_order: 14
parent: How It Works
---

# Egress Enabler Contract

Sandswap implements no network policy; it makes "who is this traffic" a fact
the guest cannot forge. This page is the mechanism in full — the identity
model, both carriers, the binding-region format (FormatVersion 1), the
ordering guarantees, and the network baseline. For the integration side —
enablement, reader access, consumption rules, and solution patterns — see
the [Egress Integration](../integration/egress-integration.md).

> **Production responsibility boundary.** Sandswap provides the egress
> enabler — the unforgeable identity fact (**Carrier A**: binding region;
> **Carrier B**: identity-in-IPv6 address) and the per-VM TAP choke point —
> not a production egress policy. **Production MUST enable one carrier**:
> The node reports the binding mode it is running in every heartbeat and in
> `/stats` (`egress_bindings`); `none` means guest traffic is NOT attributable
> to an agent. Set `-require-egress-binding` (YAML
> `network.require_egress_binding`) in production so an unbound node refuses
> to start instead of only warning.
>
> Carrier A (`-binding-backend=shm|bpf`) or Carrier B
> (`-network-backend=routed-ipv6` + `-iid-template`), and install a
> third-party enforcer that consumes it with a default-deny allowlist.
> `off`/`none` are development/test defaults, not a production
> network-security posture. Blocking cloud metadata, the storage network and
> cluster Pod/Service CIDRs belongs to the deployer/enforcer's policy; the
> host input guard is the only Sandswap-provided default block
> (guest→host).

---

## 1. Scope: what Sandswap does and does not do

Sandswap gives third-party vendors the primitives to build per-agent network
security (firewalling, authorization, audit, credential control) on top of
microVM sandboxes. Sandswap itself implements **no network policy**.

Sandswap guarantees three things:

| Guarantee | Meaning |
|---|---|
| **Identity is unforgeable** | Every attachment (TAP device / guest IP) is bound to exactly one `(agent_id, sandfs_id, mount_epoch)` at any moment, and the guest cannot influence that binding. |
| **A choke point exists** | All guest egress traverses a per-VM TAP on the host. Enforcement installed on that path cannot be bypassed from inside the guest. |
| **Lifecycle is exact** | The binding is published *before* the mounted agent can emit any traffic, changes only at mount boundaries, and is revoked at unmount/destroy. |

Everything else is the vendor's solution: what to allow, what to inspect, what
credentials to inject, where to route. In particular Sandswap does **not**:
interpret policy semantics, hold CA or workload keys, run middleboxes, or ever
block the mount/exec hot path on an external component.

The one-sentence summary: **Sandswap turns "who is this traffic" into a fact
the guest cannot forge; the vendor decides what that traffic may do.**

### 1.1 Typical egress solutions

The two carriers (§3) are designed so that third parties can build a wide
range of egress security solutions on top of Sandswap — any combination of
the two carriers is allowed. The recurring designs:

| Pattern | Mechanism |
|---|---|
| TAP firewall | tc/XDP/eBPF or userspace enforcer on the TAP reads the binding region per flow → allow/deny (§3.1) |
| Identity-in-address policy | routed-IPv6 rules match the source address's identity bits — stateless, no shared state (§3.2) |
| TPROXY redirect | transparent proxy resolves the identity per flow, then applies per-destination policy |
| L7 MITM proxy | CA-pinned interception at L7; identity resolved before any outbound TLS leaves the node |
| Credential broker | short-lived, per-identity credentials injected at the proxy — secrets never enter the guest |

Each pattern is detailed with layouts and a go-live checklist in §5 of the
[Egress Integration](../integration/egress-integration.md).

## 2. Threat model

The adversary is arbitrary code running inside a microVM (the AI agent and
everything it executes). It can read anything inside its own VM (files, env,
its own processes' memory, its own interface addresses), emit arbitrary
packets from its own TAP (including spoofed source addresses), and attempt
guest-internal privilege escalation.

It cannot: touch the host, emit packets on another VM's TAP, alter host-side
nftables/eBPF enforcement, or cross the microVM boundary.

Consequences that drive this design:

1. **Any secret delivered into the guest is compromised** (it can be read and
   exfiltrated, e.g. into an LLM prompt). Identity material therefore never
   enters the guest. The identity lives in the host-side binding region, not
   in the VM.
2. **Anything enforced inside the guest is bypassable** (guest root / kernel
   exploit can flush guest nftables, unwrap in-guest proxies). All enforcement
   anchors are host-side, mirroring the vsockguard precedent.
3. Guest code *knowing* its own addresses is fine — knowing is not forging.
   Forgery is prevented by per-TAP source filtering on the host (§6).

## 3. Identity model — one identity, two carriers

The identity is a tuple Sandswap resolves on every mount:

```
(agent_id, sandfs_id, mount_epoch, vm_id)
```

- **agent_id** — the authenticated agent identity the gateway resolves from
  the caller's API key. Sandswap treats it as an opaque identifier: it is
  carried on every mount-bearing stream command, recorded by the node, and
  published to the binding region. It is not a secret.
- **sandfs_id** — the persistent sandbox volume identity (already the unit of
  addressing between gateway and node).
- **mount_epoch** — increments on every publish for an attachment, and is
  seeded from wall clock at every attachment registration — so generations
  never repeat across sandlot restarts or ifindex recycling either: a vendor
  cache keyed on `(ifindex, epoch)` can only ever match one tenant. Sandswap
  reuses pooled VMs across agents; the epoch guarantees a recycled attachment
  never shares a binding generation with its previous tenant (vendors use it
  to invalidate caches and to pin policy revisions).
- **vm_id** — the microVM the mount runs in (diagnostic correlation).

The same tuple is exposed through **two carriers** — one authoritative and
full-resolution (§3.1), one address-encoded and stateless (§3.2). A solution
may consume either or both:

### 3.1 Carrier A — binding region

A node-local shared-memory region (shm file or mmapable eBPF array map —
§4) keyed by the TAP's ifindex:

```
(tap ifindex) → { state, mount_epoch, agent_id, sandfs_id, vm_id }
```

It carries the identity strings in full (64-byte fixed fields) and the
complete u64 `mount_epoch`, with the mount lifecycle (publish / revoke /
erase) as its state machine. It is the **source of truth**: exact
attribution, unambiguous, and the only carrier that observes unmount
(`unbound`) and attachment death (slot erased). Its cost: readers must be
co-located on the node (same netns) and poll — there is no event stream.

### 3.2 Carrier B — identity-in-IPv6 address

With the routed-IPv6 backend and an IID template (declared per the
[Egress Integration](../integration/egress-integration.md)), the identity is
**encoded into the guest's egress source address** — enforcement points
anywhere on the path parse identity **statelessly from the address, zero
shared state**. The two 64-bit halves have different jobs: the first
answers **WHERE** (routing topology), the last answers **WHO** (business
identity).

```
fd00:5341:4e01:      <subnet>:        <IID>
|------- first 64 bits: WHERE -------|- last 64: WHO -|
  site prefix | attachment /64        agent/sandfs/epoch

fd00:5341:4e01:<subnet>::/64    one routed /64 per TAP — the VM's link
fd00:5341:4e01:<subnet>::1      host-side address on that /64 = its gateway
```

| Entity | Where it lives in the address | Lifetime |
|---|---|---|
| Host (node) | **Nowhere — the host is the router.** Each /64's `::1` is the host-side TAP address, i.e. that VM's gateway | — |
| microVM attachment | **subnet** (16 bits): one live attachment per /64 | assigned at VM provisioning, released at destroy, never reused while live |
| Business identity | **IID** (last 64 bits): `agent/sandfs/epoch` per the template | stamped at mount, removed at unmount |

**The SNAT rule is static; only the map element moves.** At VM provisioning
the provider installs, once per TAP, a per-TAP map and one
`oifname "<tap>" ip6 saddr <subnet>/64 snat ip6 to ip6 saddr map @<set>`
rule at `srcnat - 5`. A mount does **not** touch the rule: it adds the
identity `/128` on the TAP and one map element (guest boot IID → identity
address). An unmount removes the element and the `/128`; a rebind deletes
the previous element first. The rule/chain/map are deleted only when the VM
itself is released.

Measured on the nested review host (4 vCPU): the mount-side stamp is
**~0.4 ms** and the unmount-side unstamp **~0.8 ms**, both sub-ms
(interface lookup ~0.19 ms, `RTM_NEWADDR`/`DELADDR` ~0.1 ms, set-element
add/delete ~9 µs). The two implementation choices that make this hold:
the netlink sockets are **persistent** per protocol (opening/closing one per
request made `close(2)` after an nftables element delete wait for the
kernel's transaction/RCU cleanup — ~6 ms even for a missing key), and the
map's kernel set id is **cached at Provision** (the id is stable until the
map is deleted at Release), so the per-mount path has no GETSET round trip.
The static rule/map setup at provisioning still uses the `ip`/`nft` CLI and
is off the per-mount path.

**First 64 bits — the routing plane.**

- The **site prefix** is operator-set (`-network-v6-prefix`, default
  `fd00:5341:4e44::/48` — "SAND"; length a multiple of 8 bits and ≤ /48,
  since the address is `<prefix | 16-bit subnet | 64-bit IID>` and a longer
  prefix would overwrite the subnet index). It names the deployment:
  upstream routers reach every microVM with **one route to the prefix**,
  and boundary policy (allow / limit / scrub) covers the whole deployment
  in one rule.
- The **subnet index** picks the TAP's /64: 16 subnet bits in a /48 =
  65,535 attachments per host prefix; exhaustion fails provisioning loudly
  — never a silent reuse.
- The routed model has **no shared L2**: neighbor discovery cannot be
  spoofed, and VM-to-VM traffic must cross the host's L3 — the natural
  choke point. Resolving the first 64 bits yields **topology** (which
  attachment → which binding-region slot, §3.1), never business identity;
  the /64 is also the granularity for policy routing and per-VM QoS.

**Multi-host rule: every host gets its own disjoint prefix.** The prefix is
per-sandlot config and each host allocates subnets independently — two
hosts sharing one /48 would mint identical `(subnet, IID)` addresses on
both. Carve the site prefix per host:

```
site (one aggregate route):    fd00:5341:4e00::/40
host A (-network-v6-prefix):   fd00:5341:4e01::/48
host B (-network-v6-prefix):   fd00:5341:4e02::/48
```

Each host owns its full 65,535-attachment space; addresses stay globally
unique across the site and still aggregate into one site route.

**Last 64 bits — the identity, stamped at mount.** The guest boots with the
**fixed all-zero IID** — `<subnet>::`, the subnet-router anycast form, invalid
as a unicast identity (pooled VMs are provisioned CLEAN; the identity is not
known until mount). At every mount Sandswap adds a secondary identity-encoded
address — `<subnet> | IID-from-template`, inside the guest's own /64 — to the
TAP's host side and flips one SNAT map element (the rule reading it is
provisioned once) rewriting the guest's egress source to it; unmount removes
the stamp. A failed stamp degrades to unstamped egress — the guest's boot
IID, recognizably not an identity — "unknown address → deny" at the policy
point, never a wrong identity.

**Identity fields carry the ids verbatim** — no hash, no projection, no
truncation. Uniqueness is guaranteed at creation (the identity store
regenerates on collision), so the field IS the unique value, and the
suffix reads straight out of the address for debugging. `epoch` is the one
width-limited field: the template keeps only its low bits (`epoch:16`
repeats every 65 536 remounts of one attachment) — a recency marker ("this
remount differs from the last"), not a generation ID; that remains
Carrier A's full u64 `mount_epoch`. Both carriers are written by the same
publish path with the same epoch, so they never disagree.

**The template: what the 64 IID bits can contain.** A template is a
comma-separated `field:width` list, most-significant first; widths must sum
to exactly 64. Five field names exist:

| Field | Carries | Width rule |
|---|---|---|
| `agent` | the agent id's hex suffix, verbatim | **exactly 32** |
| `sandfs` | the sandfs id's hex suffix, verbatim | **exactly 32** |
| `epoch` | `mount_epoch`, low bits | any |
| `rand` | fresh random bits per mount | any |
| `deployment` | the operator-assigned deployment number, written into the template itself (`deployment:16=42`) | any |

Identifiers are minted as `<prefix>-<8 hex>` — exactly 32 unique random
bits — which is why the verbatim suffix is as unique as the id itself:
narrower identity fields would collide at birthday bounds and are rejected
at parse time, never shipped. The operator picks the layout per deployment;
examples:

| Template | Address semantics |
|---|---|
| `agent:32,sandfs:32` | deterministic — one stable address per sandfs for its whole life |
| `agent:32,epoch:32` | per-agent; each remount of a sandfs gets a new low half |
| `agent:32,epoch:16,rand:16` | per-agent; random per-mount part — addresses never repeat across rebinds |
| `sandfs:32,rand:32` | per-sandfs but unpredictable per mount |
| `deployment:16=42,agent:32,epoch:16` | deployment 42, per-agent + recency — distinguishable across deployments sharing one external route |

**Deployment numbering (multi-deployment sites).** When several sandswap
deployments share one external IPv6 route and one centralized
egress-security system, the `deployment` field tags every address with the
deployment's number, so tenants stay distinguishable even where agent/sandfs
ids overlap. The number is assigned by the operator's numbering plan (each
deployment configures it once, in its own template — Sandswap neither mints
nor checks cross-deployment uniqueness). The 64-bit budget still applies: a
deployment field comes out of the same 64 bits, so holding both identity
fields at their mandatory 32 bits leaves no room — pick one identity field
(`deployment:16=42,agent:32,epoch:16`), or keep both identities and
distinguish deployments by their site prefixes instead (the multi-host rule
above).

## 4. The binding region

One node-local, versioned, shared-memory region per sandlot instance. It is
the single source of truth for attachment→identity; there is **no event
stream**: readers poll the region (a full poll of thousands of slots is
microseconds) and enforcers that need cluster-wide aggregation export the
region themselves — that is part of the vendor's solution, not Sandswap's
surface.

### 4.1 Layout (FormatVersion 1, little-endian)

```
region:  [ header 4096 B ][ slot ifindex=0 ][ slot ifindex=1 ] ... [ slot MaxIfindex-1 ]
slot:    256 B fixed entry, keyed by the TAP's kernel ifindex

entry:   u32  magic 'SBR1'    @ 0
         u32  format_version @ 4      (1)
         u32  state           @ 8      (0 = unbound, 1 = mounted)
         u32  reserved        @ 12
         u64  mount_epoch     @ 16
         char agent_id[64]    @ 24     NUL-padded, truncated when longer
         char sandfs_id[64]   @ 88
         char vm_id[64]       @ 152
         char reserved[32]    @ 216
         u32  seq             @ 248    seqlock sequence — see §4.2
         u32  reserved        @ 252

header:  u32 magic, u32 format_version, u32 header_size(4096),
         u32 entry_size(256), u32 max_ifindex, u32 reserved,
         u64 global_seq (monotonic change counter), char backend_tag[16], ...
```

The sequence lives in the entry's last word, **outside** the payload word
range: writers publish payload with 8-byte atomic stores over `[0, 248)` and
store the sequence separately, so a payload store can never clobber the
sequence.

### 4.2 Reading a slot (seqlock)

The region is a plain shared table built for **concurrent readers and one
writer at the same time**: readers take no lock, never block, and never
disturb a publish. A consumer does a **direct lookup** — resolve the TAP's
ifindex once, then read exactly one slot at offset `4096 + ifindex·256`.
There is no scan, no registration call, and no requirement to consume the
region asynchronously: reading slots while sandlot writes them is the
designed use, made safe by the per-entry sequence counter:

```
s1 = load_acquire(seq)
if s1 is odd:   writer mid-update
snapshot payload            (plain aligned ≤ 8 B reads; never torn per word)
s2 = load_acquire(seq)
accept the snapshot only if s1 == s2
```

Writers store `seq = s+1` (odd), then the payload, then `seq = s+2` (even),
so a torn read is always **detected** (`s1 != s2`), never accepted. Both
legal consumer shapes follow from that guarantee:

- **Single-shot (kernel per-packet — tc/BPF/LSM):** one attempt per packet;
  a failed check (odd seq or `s1 != s2`) reads as *unidentified →
  default-deny* that packet or flow. The next packet re-reads naturally,
  and a publish is two stores (~ns), so the fail-closed case is
  statistically unobservable. No retry loop is needed.
- **Bounded retry (userspace helpers):** re-read until the check passes;
  a torn read is never returned (the reference implementation retries ≤ 64
  before reporting a stale read).

The header's `global_seq` (one u64 load) lets a poller that scans many
slots skip the rescan entirely when nothing changed anywhere.

**Initial state is a defined "no entry".** Both carriers are zero-filled at
creation — the shm file starts as a hole (`ftruncate`, holes read as zero
bytes) and the kernel zero-fills a fresh BPF array map — so every slot
begins invalid, and a consumer **can and must** judge that validity from
the entry itself:

| Observation | Meaning | Enforcer action |
|---|---|---|
| `magic == 0` | slot never written (no entry yet) | unidentified → default-deny |
| `magic != 'SBR1'` or `format_version != 1` | foreign / mismatched region | refuse — never interpret |
| `state == 0` (`unbound`) | attachment live, no sandfs mounted | unidentified → default-deny |
| `state == 1` (`mounted`) | valid binding: identity + epoch readable | enforce |

Cross-language note: writers use release semantics on the sequence stores;
readers use acquire semantics. In C/Rust, use acquire loads for `seq` and
plain (non-tearable) width reads for fields; the 8-byte fields are naturally
atomic on all supported architectures.

### 4.3 Lifecycle (Carrier A's state machine)

| Sandswap event | Binding-region effect |
|---|---|
| VM created (TAP provisioned) | slot reset (stale entry dropped) |
| sandfs mounted | publish `{mounted, epoch++ , agent, sandfs, vm}` + address stamp (Carrier B) with the same epoch |
| parallel execs of the same mount | no republish — a sandfs accepts concurrent execs, and two cold execs can race past the warm check before either marks the mount; re-entry with an unchanged identity is a continuation of the SAME generation (one epoch per mount, not per exec) |
| agent switched on the same VM | revoke old, publish new (new epoch) — and the switch can only run after the warden's mount gate has waited out the old mount's in-flight execs and killed its processes, so no old-identity traffic can follow the new publish |
| unmount (lease end, release, cleanup) | revoke → `unbound`, identity fields cleared; address stamp removed |
| VM destroyed / crashed / TAP released | slot erased |
| node restart + re-adopt | slots reset (a fresh process has no mounts; the CONNECT-CLEAN invariant guarantees the survivor VMs release all mounts before reconnection) |

`agent_id` is **required** on every mount-bearing command; a mount without it
is rejected. Unmount/attach-independent commands do not need it.

### 4.4 Carriers (configurable)

| Carrier | Flag | Mechanism | Notes |
|---|---|---|---|
| `shm` (carrier default) | `-binding-backend=shm` | file on tmpfs (`/dev/shm/sandswap-bindings`, mode 0640), `mmap MAP_SHARED` | zero dependencies; any local reader with file permission; sparse — only written slots cost memory; doubles as the restart snapshot |
| `bpf` | `-binding-backend=bpf` | `BPF_MAP_TYPE_ARRAY` created `BPF_F_MMAPABLE` (kernel ≥ 5.5), pinned to bpffs (`/sys/fs/bpf/sandswap/bindings`), `mmap`ed by the node | kernel-context readers (tc/XDP/LSM programs) do a plain array lookup; requires `CAP_BPF`/`CAP_SYS_ADMIN` to create + `bpf(2)` allowed by any syscall filter (bare-metal embedded: the sandlot carries ambient `CAP_SYS_ADMIN` and `deploy-egress-enabler.sh` installs the unit drop-in that admits `bpf(2)` — the stock unit's `SystemCallFilter=@system-service` excludes it; k8s boxout mode: boxout creates + pins, then hands it to the unprivileged sandlot as `chown <sandlot-uid>` `0660` — access-control details in §4.6); allocates eagerly (16 MB at the default `MaxIfindex`) |
| `off` (feature default) | `-binding-backend=off` | — | enabler disabled: zero behavior change, zero hot-path cost |

Both carriers are byte-identical for readers — one parser serves both, and a
vendor can support `shm` everywhere and add `bpf` where kernel-context
enforcement matters.

Slot key = TAP ifindex, bounded by `max_ifindex` (default 65536; Linux
ifindexes grow monotonically with interface churn — never reused until reboot).
A publish beyond the bound fails safe: the slot stays absent and enforcers
treat the attachment as unidentified (default-deny). Sandlot logs a warning
when a registered TAP lands within 10% of the bound. Operators of very
long-lived, high-churn hosts should budget explicitly: a recycle policy that
destroys and rebuilds VMs consumes ~2 ifindexes per cycle, so the default
65536 slots cover e.g. ~30k recycles (weeks at one per minute — raise the
bound well before that; a mismatched reopen of an existing region is rejected
loudly, never reinterpreted). The `shm` carrier is sparse (only written slots
cost memory), so a larger bound is nearly free there; the `bpf` carrier
allocates eagerly (256 B per slot).

**Kernel compatibility.** The writer's syscalls are restricted to a frozen
uAPI subset: `BPF_MAP_CREATE` passes a zero-filled attribute prefix the kernel
accepts on any version (extra trailing bytes are checked to be zero), and the
seqlock is plain aligned memory access — no kernel dependency beyond
`BPF_F_MMAPABLE` (v5.5) for the `bpf` carrier. The `shm` carrier has none.

### 4.5 What enforcers must do

- **Never classify from a private cache.** Read the region at flow
  establishment (per connection), then pin the flow's verdict. The region is
  an ns/µs-scale read; there is no reason to cache.
- Treat *absent slot* (zero magic), `unbound` state, a *failed
  magic/version check*, or out-of-range ifindex as **unidentified →
  default-deny** (your policy chooses the posture; the contract only fixes
  the meaning — §4.2).
- Key on the attachment (`ifindex`), use `mount_epoch` to detect agent
  switches, and pin policy revisions per epoch if your rules come from a
  central store.
- **ifindex is network-namespace-scoped.** Every reader (kernel or
  userspace) must observe the TAP in the same netns as the sandlot that
  publishes the region — on Kubernetes that means hostNetwork pods.

### 4.6 Region access control (who can read / write)

The region is a plain shared table; how far a reader may trust it is exactly
the node's host-security posture (see [Host Prerequisites](../deployment/prerequisites.md)):

- **Readers** are whoever the carrier's file permissions admit — and the two
  carriers differ in granularity:
  - `shm` (`0640`): the file's owner and group. Group membership is true
    read-only sharing — put your enforcer daemon's account in the file's
    group.
  - `bpf` pin: opening a pin is an `O_RDWR` open (`BPF_OBJ_GET` accepts only
    `file_flags=0`; `BPF_F_RDONLY`/`BPF_F_WRONLY` are rejected), so **the
    read set equals the write set** — group/other bits on a pin are write
    grants, not read grants. Userspace readers necessarily hold write;
    read-only consumers go through kernel context (tc/XDP/LSM programs reach
    the map via their own program, not the pin's DAC). Keep the pin's group
    dedicated (the k8s boxout handoff `0660` shape); never `0666`.
  "Readable by any local user" is a misconfiguration on either carrier. On
  Kubernetes the shm carrier is **pod-local** (`/dev/shm` of the sandlot
  pod) — a cross-pod reader needs a hostPath mount of `/dev/shm` or the
  `bpf` carrier.
- **Writers** are sandlot alone (embedded mode) or the sandlot/boxout pair
  (k8s) — nobody else. The writer verifies at open that it owns the region
  and refuses a foreign-owned or group/world-writable one loudly: a region
  file planted by another local user before the writer's first start would
  otherwise receive every published identity into memory that user
  controls. Anything that defeats those checks is a **host-level
  compromise** — the same trust event as a vsockguard bypass — not a
  Sandswap behavior to defend against in the region protocol.
- **Replacement detection is a reader duty.** The region file deliberately
  survives a sandlot restart, and an operator may legitimately remove and
  recreate it (e.g. after a service-UID migration). Old mappings keep
  serving the frozen old inode while publishes land in the new one. Watch
  the region's `st_dev`/`st_ino` (a cheap stat alongside your `global_seq`
  poll) and treat a change as full invalidation: default-deny until your
  reader re-attaches.
- **Carrier B needs none of this.** Identity-in-address (§3.2) has no
  shared state to guard — stamps are applied host-side via netlink
  (`CAP_NET_ADMIN` required) and read statelessly out of packet addresses.

## 5. Ordering guarantees (why the attribution is exact)

Sandswap's mount sequence:

```
overlay mount → warden unmount of any old volume (cgroup.kill + umount)
→ virtio-fs allowed_dirs swap → PUBLISH binding to the region
→ dispatch combined mount+exec RPC → warden mounts → exec → guest code exists
```

1. **Publish precedes traffic, by construction.** Guest processes do not exist
   before exec; the publish happens in the mount call stack before the exec is
   dispatched. No race window exists — this is not a "fast enough push"
   argument.
2. **Revoke follows process death.** Unmount's `cgroup.kill` (inside the
   warden) terminates every agent process before the mount goes away; the
   revoke lands after. In-flight flows were the old agent's — their
   attribution stays correct; no new flow can appear until the next publish.
   **This is not a network-cleanup lag.** Revoke clears the binding used by
   NEW flow lookups; packets already queued or held in conntrack keep the
   old stamp because they literally are the old agent's traffic. The guest
   holds no identity state of its own — the binding is host-side and the
   revoke is synchronous. Attributing those packets to the old identity is
   the truthful answer, not a leftover.
3. **Switch = revoke old + publish new (new epoch).** A cross-agent VM reuse
   never leaves the previous agent's identity attached, and never reuses a
   generation.
4. **Derived state follows the authoritative state.** The identity SNAT
   stamp (routed-ipv6 backend) is applied strictly AFTER the region
   publish, carrying the SAME epoch. If the stamp fails, the region stays
   authoritative (attribution-aware enforcers still see the mount); egress
   simply remains un-stamped — the address layer degrades to "unknown →
   deny" at the policy point, never to a wrong identity. The reverse order
   would leave a stamped address against a stale/failed region with nothing
   to re-publish it. Stamp writes are replace-on-same-key, so a sandlot
   restart self-heals on the next mount. In k8s/boxout mode the stamp and
   the unmount-side unstamp are relayed to the privileged sidecar over the
   same Unix-socket protocol that already carries network provisioning —
   bounded transport budget, and the same degrade-to-unstamped failure
   semantics (a wedged sidecar never blocks a mount or unmount).
5. **Restart is clean.** A restarted sandlot has no mounts (CONNECT-CLEAN
   invariant) and resets all slots it re-adopts; a stale entry from a crashed
   process is dropped at registration, never served to enforcers.

## 6. Network baseline (host-side, no policy semantics)

Installed per TAP at provision time (cold path), **on by default**
(`-egress-baseline=on`); requires nftables and is fail-closed: a missing
installation or a failed table install refuses to start (set
`egress_baseline: off` explicitly for a per-VM-only deployment). These are isolation primitives — they make the TAP a valid
identity anchor — not policy:

1. **Source-address anti-spoof**: only the assigned guest address may leave
   the TAP. This is what makes "the address is the identity" sound (§2:
   knowing ≠ forging).
2. **VM-to-VM isolation**, configurable: `-vm-to-vm-policy=deny` (default) |
   `allow`. Multi-agent systems that permit VM-to-VM traffic can open it;
   attribution still holds because each direction enters through its own TAP.
3. **Unmounted VMs have no egress — by the process model.** Guest processes
   exist only between mount and unmount (cgroup.kill clears them at
   unmount), a stale-mount VM is destroyed together with its TAP, and pool
   VMs at rest have nothing to emit with. The baseline is therefore
   deliberately STATIC (installed at provision, removed at release): a
   per-mount nftables flip measured +1.2 ms on the switch path and left a
   first-packet race — hot-path purity wins, and no correctness guarantee
   depends on the gate.
4. **Deterministic naming**: the TAP name is derived from the VM ID and the
   guest addressing scheme is documented, so vendor components locate
   attachments by `ifindex` without Sandswap-side registration calls.

Per-packet cost of the baseline is nanoseconds — invisible next to
virtio-net. There is zero per-mount nftables work.

## 7. Guest invariants

Vendor threat models rest on these Sandswap-maintained properties:

- The guest is fully untrusted and cannot reach the host (microVM boundary).
- Host-side enforcement (vsockguard BPF LSM, nftables baseline, binding
  region) is invisible and immutable from inside the guest.
- Guest networking is statically provisioned (no DHCP); DNS is injected via
  `resolv.conf` at boot.
- Trust-store customization (e.g. installing a MITM CA **public** certificate)
  is done by building it into the rootfs template. A CA private key must
  never enter the guest or the template.

## 8. Performance budget

| Path | Added cost |
|---|---|
| mount (cold) — one publish | one memory-write set, ~0.2 µs (bpf carrier update: ≤ 3 µs) |
| unmount — one revoke | same order |
| warm exec | zero (identity changes only at mount boundaries) |
| node steady state | zero: no goroutines, no polling, no syscalls, no etcd writes |
| baseline | static per-TAP (provision-time); zero per-mount nftables work |
| enforcer read (vendor side) | ns in kernel context (map lookup), ~100 ns userspace mmap |

Acceptance: `e2e/latency-benchmark-aiagent.sh` and
`e2e/latency-benchmark-unmount.sh` P50 deltas ≤ 1% with the enabler on
versus off.

## 9. Sandswap-side hard guarantees

1. **Hot-path purity**: vendor code never enters mount/exec/lease paths;
   Sandswap's own additions are one memory-write set per mount/unmount; the
   mount path never waits on an external component.
2. **Zero policy semantics**: Sandswap answers *who / on which attachment /
   when mounted-or-not*; it never answers *allowed or not*.
3. **Fail-safe defaults**: unknown/unidentified attachment ⇒ reads as
   unbound; VM-to-VM ⇒ deny unless enabled; a failed publish revokes rather
   than leaves a stale identity.
4. **Versioned contract**: the region layout is versioned; a FormatVersion
   mismatch refuses to open, never silently misreads.

## 10. Kernel requirements (host & microVM)

Two independent kernels matter: the HOST that runs sandlot/sandvmm, and the
microVM GUEST kernel built into the initramfs boot. Requirements are
per-feature-part — with the enabler off (`-binding-backend=off`, default) or
with the `shm` carrier + `bridge` backend, NO kernel version is required
beyond what Sandswap already needs.

### 10.1 Host kernel

| Feature part | Minimum host kernel | Why |
|---|---|---|
| Binding region, `shm` carrier | none | plain tmpfs file + mmap |
| Binding region, `bpf` carrier | **5.5** | `BPF_F_MMAPABLE` array maps |
| Network baseline (anti-spoof, VM-to-VM) | ~4.x (any distro LTS) | nftables netdev/bridge families |
| routed-ipv6 backend + identity stamp | **5.2** | inet-family nftables NAT |

**Practical floor: host kernel ≥ 5.5 covers every part — well below
Sandswap's overall host-kernel requirement of ≥ 5.10, so any host that can
run Sandswap runs every enabler part.**

No per-kernel-version maintenance is required: the writer uses only
decade-stable uAPI (rtnetlink `RTM_NEWADDR/DELADDR`; nftables batch framing +
set-element ops), passes zero-filled syscall attribute prefixes the kernel
accepts on any version, parses exactly ONE reply field (the nftables set id,
accepted in both its u32 and u64 wire forms, v4.18 boundary), and bounds every
kernel reply with a timeout. Rule/expression encoding — the version-sensitive
part — is owned by the `nft` CLI, not by Sandswap.

### 10.2 microVM (guest) kernel

| Network backend | Guest kernel requirement |
|---|---|
| `bridge` (IPv4) | none special |
| `routed-ipv6` (identity-in-address) | **`CONFIG_IPV6=y` is REQUIRED** |

The default `kernel/build.sh` build (the cloud-hypervisor/linux tree with
`ch_defconfig` plus `CONFIG_IPV6=y` and `CONFIG_INET_DIAG_DESTROY=y`) has
IPv6 compiled in and is what the deployment scripts install. Only the
dev-only `kernel/build.sh download` variant — the official v6.2 prebuilt,
built from `ch_defconfig` with `CONFIG_IPV6` unset — boots guests with no
IPv6 at all, where the identity-in-address pattern cannot function. Either
way, deploy `output/vmlinux.bin` to the node; the guest receives its static
v6 address/prefix/gateway via kernel cmdline (`net_ip6`, `net_prefix6`,
`net_gw6`).

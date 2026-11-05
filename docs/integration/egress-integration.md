---
title: Egress Integration
nav_order: 9
parent: Integration
---

# Egress Integration

For third-party network security vendors building per-agent policy
enforcement on Sandswap, and for the operators deploying those integrations.

The mechanism these integrations consume — the identity model, both carriers,
the binding-region format, the ordering guarantees and the network baseline —
is [Egress Enabler Contract](../how-it-works/egress-enabler.md). This guide is the
integration side only: turning the enablers on, getting access to what you
read, and the patterns and rules that make an enforcer correct.

## 1. Enabling the enablers

> **Production MUST enable one carrier.** `-binding-backend=off` and
> `-network-backend=none` are development/test defaults. Production must
> select **Carrier A** (`-binding-backend=shm|bpf`, a binding region) or
> **Carrier B** (`-network-backend=routed-ipv6` + `-iid-template`,
> identity-in-address), and install a third-party enforcer with a
> default-deny allowlist; Sandswap provides the identity fact and the TAP
> choke point, not the policy. Storage/metadata/cluster destination policy
> is the enforcer's/deployer's responsibility.

Sandlot flags (the same keys configure k8s/boxout deployments, where the
network provider and the binding-region handoff run in the privileged boxout
sidecar — same flags on both processes; sandlot opens the sidecar-pinned
region unprivileged):

| Flag | Default | Meaning |
|---|---|---|
| `-binding-backend` | `off` | `off` / `shm` / `bpf` — egress identity binding region carrier |
| `-binding-path` | per-backend | location override (shm file path / bpffs pin path) |
| `-egress-baseline` | `on` | egress network baseline (source anti-spoof + VM-to-VM posture); requires nftables. Fail-closed: missing nftables or a failed table install refuses to start; set `off` explicitly for a per-VM-only deployment |
| `-vm-to-vm-policy` | `deny` | guest-to-guest traffic posture (`deny` / `allow`) |
| `-network-backend` | `none` | `none` / `bridge` / `routed-ipv6` — `routed-ipv6` is required for Carrier B |
| `-network-v6-prefix` | `fd00:5341:4e44::/48` | routed-IPv6 site prefix (multiple of 8 bits, ≤ /48); one disjoint prefix per host — [Egress Enabler Contract](../how-it-works/egress-enabler.md) §3.2 |
| `-iid-template` | — | IPv6 interface-identifier layout — Carrier B; see §5.2 for the layouts |

Corresponding `config.yaml` keys live under `network:` (`bind_backend`,
`bind_path`, `egress_baseline`, `vm_to_vm`, `v6_prefix`, `iid_template`).
Per-flag detail: [Sandlot configuration](../operations/configuration/sandlot.md)
/ [Boxout configuration](../operations/configuration/boxout.md).

Both enablers are dormant or safe by default: `off` leaves the hot path
byte-identical to a build without the enabler, and the baseline is isolation
primitives only — it makes no policy decisions.

## 2. Reading the binding region (Carrier A)

The region is the interface; access control is ordinary file DAC — and the
two carriers differ:

- **`shm`**: put the enforcer daemon's account in the file's group (a
  dedicated group, nothing else in it). Group membership is true read-only
  sharing:

  ```bash
  sudo groupadd -r sandbind
  sudo usermod -aG sandbind <enforcer-account>
  ```

  On Kubernetes the shm region is **pod-local** — cross-pod readers need a
  hostPath `/dev/shm` mount or the `bpf` carrier.
- **`bpf` pin**: opening a pin is an `O_RDWR` open — group bits are *write*
  grants, so there is no read-only sharing in userspace; kernel programs read
  the map through their own loaded code. Keep the pin's group dedicated;
  never `0666`.

The full read/write model (writer-side open checks, replacement detection,
why no vsockguard-style guard is needed) is
[Egress Enabler Contract](../how-it-works/egress-enabler.md) §4.6 and
[Host Prerequisites](../deployment/prerequisites.md).

**How to read it** — the duties are part of the contract, not suggestions
([Egress Enabler Contract](../how-it-works/egress-enabler.md) §4.5):

- Never classify from a private cache; read the slot at flow establishment
  and pin the flow's verdict.
- Treat absent slot, `unbound`, a failed magic/version check, or an
  out-of-range ifindex as unidentified → default-deny.
- Key on the attachment (`ifindex`) and use `mount_epoch` to detect agent
  switches; ifindex is netns-scoped (hostNetwork on k8s).
- Watch the region's `st_dev`/`st_ino` alongside the `global_seq` poll: a
  replaced region invalidates old mappings.

## 3. Consuming the identity address (Carrier B)

No read access exists to set up — with `routed-ipv6` + an IID template the
identity is in the packet's source address, parsed statelessly per your
declared layout (§5.2). An address still carrying the guest's **boot IID**
(the fixed all-zero IID, `<subnet>::` — the subnet-anycast form) is *not* an
identity: treat it like any other unidentified source (default-deny).

Kernel requirements: the host needs ≥ 5.5 (nftables inet NAT plus BPF mmap);
the GUEST kernel must have `CONFIG_IPV6=y` (the default `kernel/build.sh`
build includes it — the prebuilt `download` variant is refused and does not
exist).

## 4. Guaranteeing "no traffic before policy is ready"

Integrations that must guarantee "no traffic flows before policy is ready"
should implement the **per-flow hold** at their enforcement point:

```
on flow establishment:
    read binding (epoch) from the region
    if my policy store has not loaded rules for (attachment, epoch):
        hold / drop the flow
    else: enforce
```

- Exec proceeds; only network flows are held. Non-network agent work is
  never disturbed.
- A wedged vendor control-plane degrades to "flows denied" — safe, visible,
  and diagnosable at the enforcement point.
- There is no fail-open paradox: policy not ready ⇒ flows held, full stop.

Sandswap deliberately does **not** offer a mount-blocking "policy-ready
gate": it would couple the mount hot path to an external component's
liveness (a wedged vendor daemon would stall every mount on the node), add
milliseconds of tail latency on every rebind, and its timeout posture
re-opens the very hole it exists to close (fail-open ⇒ code ran without
policy). Per-flow hold achieves the same strictness with strictly less
coupling. The binding region format reserves space for a future opt-in gate
if a compliance posture ever truly requires blocking non-network execution —
it is not implemented.

## 5. Solution patterns

Each pattern lists the enablers it consumes and what the vendor implements.

### 5.1 Node-local TAP firewall (L3/L4 per agent)

Read the region in a tc/eBPF program keyed on ifindex; enforce per-agent
domain/IP/port policy and quotas at the TAP; log per-agent audit trails.
*Consumes:* binding region + network baseline. *Covers:* egress allowlists,
quotas, audit. *L7:* no (see 5.4).

**The kernel fast path (works for ANY ethertype — IPv4, IPv6, L2).** The
cardinal rule: *never identify the flow from packet contents — identify it
from the attachment.* The packet's ingress TAP ifindex is already in the BPF
context (`skb->ifindex` at a tc hook on the TAP), it is not
guest-influenceable, and it is exactly the region's slot key. The whole data
path is two O(1) lookups:

```
attach per TAP (tc ingress/egress on tap-N — mirroring the baseline's
                 per-TAP chain pattern; NOT on the shared bridge, where the
                 context's ifindex is the bridge's and identity is lost):

  verdict = skb->ifindex                      # free: already in ctx
          → slot[N] array read                # bpf carrier: native array-map
                                               # lookup by key N (kernel ≥5.5)
          → seqlock check (seq even, unchanged) + state == mounted
          → agent_id / sandfs_id              # fixed 64 B NUL-padded fields
          → hash(id) → BPF_MAP_TYPE_LRU_HASH  # u64 key → rule set
          → enforce / log (with mount_epoch)
```

Rule maps should be keyed by a fixed-width hash of the identifier, not the
identifier string: hash the *full 64-byte NUL-padded field* (constant-time,
no early exit) with FNV-1a 64 and use the resulting u64 as the map key (at
64 bits, collisions are negligible). This is a kernel-side convenience key
only — it is NOT the value in the address: an identity-in-address IID field
carries the identifier's raw 32-bit hex suffix (§5.2), so an
address-bit→identity resolution is a direct comparison against the suffix of
the region's id strings. Agent-keyed and sandfs-keyed rule maps are two
separate maps consulted per your policy semantics. Pin the flow's verdict at
connection establishment (conntrack) and carry `mount_epoch` in audit logs;
the per-flow hold (§4) is the pattern for "no rules loaded for this epoch
yet".

**Userspace packet processors — ifindex still works; only the way you OBTAIN
it changes.** The slot key does not depend on kernel-context execution:

- **AF_PACKET on the TAP** (the natural userspace observation point on a
  node-local enforcer): every `recvmsg` returns `sockaddr_ll.sll_ifindex` —
  the key arrives per packet, same two-step lookup as the kernel path.
  Requires `CAP_NET_RAW` and the same netns as the TAP.
- **AF_XDP / DPDK-style ports**: the socket/queue is bound to ONE interface
  at setup — the ifindex is static per worker, resolved once; slot lookup per
  packet is a plain mmap read (`offset = 4096 + ifindex·256`, seqlock-check,
  read). mmap the shm file (0640, group-readable) or the bpffs pin; poll the
  header's `global_seq` (one u64 load) to skip rescanning when nothing
  changed.
- **Proxied paths (TPROXY, §5.3)**: a redirected flow arrives on a LOCAL
  socket — the original ifindex is absent from the socket metadata. Recover
  attribution from the flow's source address instead: on the bridge backend
  every VM has a static, 1:1-with-attachment IPv4 (maintain a source-IP →
  ifindex map from a netlink `RTM_NEWADDR` dump + change notifications); on
  routed-IPv6 skip translation entirely — the identity is IN the source
  address (§5.2). Never trust guest-supplied identity headers.

### 5.2 Identity-in-address + policy routing (IPv6)

With the routed-IPv6 backend, encode identity into the guest address via the
IID template (`-iid-template`, e.g. `agent:32,sandfs:32` — Sandswap fills the
fields, the vendor declares the layout). This is Carrier B of the identity
model ([Egress Enabler Contract](../how-it-works/egress-enabler.md) §3.2, which
also defines the address plan): the same tuple the binding region publishes,
with identity fields carried verbatim and only `epoch` width-limited.

**Supported layouts.** Fields are laid out most-significant first and must
sum to exactly 64 bits. Identity fields (`agent` / `sandfs`) are **required
to be exactly 32 bits** — they carry the id's raw suffix, and only that width
makes the address view as unique as the identifier space itself; narrower
identity fields (e.g. `sandfs:16`) would collide at birthday bounds and are
**rejected at startup**, never shipped. `epoch`, `rand`, and `deployment` are
non-unique and may take any width, including 0. `deployment` is the one
operator-assigned field: its value is written into the template itself
(`deployment:16=42`) and must fit the declared width (checked at startup):

| Layout | Attribution | Notes |
|---|---|---|
| `agent:32,epoch:32` | per agent + per-remount recency | **default choice** |
| `sandfs:32,epoch:32` | per sandfs + recency | |
| `agent:32,sandfs:32` | both identities, lossless | deterministic; a sandfs belongs to exactly one agent, so the pair is 1:1 with the sandfs — a stable per-sandfs address (stable address ⇒ stable policy) |
| `agent:32,rand:32` / `agent:32,epoch:16,rand:16` | per agent | `rand` pads the rest with fresh random bits (per-mount addresses never repeat) |
| `deployment:16=42,agent:32,epoch:16` | per deployment + per agent | multi-deployment sites sharing one external route: overlapping agent/sandfs ids across deployments stay distinguishable (see below) |

A layout with no `rand` field is deterministic — safe because every VM owns
its own /64, and the epoch changes on every remount.

**Deployment numbering (multi-deployment sites).** When several sandswap
deployments share one external IPv6 route and one centralized
egress-security system, the `deployment` field tags every address with the
deployment's number, so tenants stay distinguishable even where agent/sandfs
ids overlap. The number is assigned by the operator's numbering plan (each
deployment configures it once, in its own template — Sandswap neither mints
nor checks cross-deployment uniqueness), and the 64-bit budget still
applies: a deployment field comes out of the same 64 bits, so holding both
identity fields at their mandatory 32 bits leaves no room — pick one
identity field (`deployment:16=42,agent:32,epoch:16`), or keep both
identities and distinguish deployments by their site prefixes instead
([Egress Enabler Contract](../how-it-works/egress-enabler.md) §3.2, the
multi-host rule).

**Epoch width, and when `rand` is needed.** `rand` is a filler, never a
requirement: the fields must sum to exactly 64 bits (enforced at parse), so
any leftover width after the identity fields must go to `epoch` or `rand` —
choose `epoch` for counter-derived fill bits (each remount differs), `rand`
for fresh-random bits. The `epoch` field takes the **low bits** of the u64:
with one identity field it can be at most 32 bits wide, with two identity
fields there is no room (and none is needed). Because every VM owns its own
/64 and the epoch changes on every remount, addresses never repeat across
remounts even with zero `rand` — `agent:32,epoch:32` (the default choice)
needs no `rand` at all; `agent:32,sandfs:32` needs neither and buys a
stable per-sandfs address.

**No discriminator bit.** The layout is deployment-static and declared out
of band, so **position is the discriminator**: every parser knows from its
configuration which field is which (e.g. bits [63:32] = agent, [31:0] =
sandfs). A field value resolves against the region's full strings
(`agent-…` vs `sandfs-…`) whenever the type matters, and identity fields
are pinned to the full 32 bits they carry (a type tag would only subtract
entropy — startup rejects narrower identity fields anyway).

*Consumes:* routed-IPv6 backend + IID template + region. *Covers:*
centralized, stateless attribution across nodes.

### 5.3 Egress proxy with stamped identity

Transparently redirect TAP egress (TPROXY) to a userspace proxy; the proxy
strips guest-supplied identity headers, stamps flows with a short-TTL signed
header or PROXY-protocol TLV over a node-authenticated tunnel, and forwards
to a central policy gateway that accepts identity **only** from authenticated
node tunnels (a leaked header is worthless elsewhere).
*Consumes:* region + baseline. *Covers:* centralized L4 firewalling of any
protocol.

### 5.4 L7 inspection (MITM application firewall)

Terminate guest TLS at the proxy with a Sandswap-hosted CA (guests trust only
the **public** cert via template build; the private key never enters the
guest). Enables URL/method/content policy. Guests that bring their own CA
bundle or pin certificates simply fail to connect — a self-denial, not a
bypass.

### 5.5 Credential broker

Hold third-party credentials host-side, keyed by (agent, destination);
inject `Authorization` at the egress point. Agent code calls the service
without ever seeing the key — the "api-key in the sandfs, leaked into an
LLM" failure mode is eliminated by construction.

## 6. Limitations

- **Identity ≠ DLP.** If policy allows example.com, an agent can still
  encode secrets into allowed requests. Narrow allowlists, L7 inspection
  (5.4) and volume anomaly detection are policy-layer concerns.
- L4-only visibility for non-HTTP protocols unless MITM is deployed.
- MITM breaks certificate-pinned clients (self-denial) and gives the
  operator L7 visibility — a deployment decision, not a technical one.
- The binding region is node-local by contract; cluster aggregation is the
  vendor's pipeline.

## 7. Before you go live

- **Conformance.** §8 below
  lists the assertions the Sandswap-side suites pin down; run them against
  your deployment: `e2e/egress-identity.sh` (region publish/revoke/epoch +
  baseline chains, `BINDING_BACKEND=shm|bpf`) and `e2e/routed-ipv6.sh`
  (guest v6, stamp at mount, unstamp at unmount). `output/bindregdump`
  (`-watch`) is the reference reader.
- **Performance.** The `e2e/latency-benchmark-*` scripts double as the
  acceptance gate: P50 deltas ≤ 1% with the enabler on versus off.

## 8. Acceptance & conformance

The Sandswap-side suites (unit + e2e) assert, for each carrier:

1. publish lands before the mount's first flow can exist (ordering test);
2. switch publishes the new identity with a fresh epoch (no stale window);
3. unmount revokes (state `unbound`, identity cleared, epoch preserved);
4. destroy/unregister erases the slot;
5. re-adopt resets slots (no ghost identities after a node restart);
6. `agent_id` is required on mount-bearing commands;
7. both carriers decode identically; a mismatched/foreign region is rejected;
8. baseline: spoofed sources dropped, VM-to-VM matches the configured
   posture, unmounted VMs have no egress.

Performance acceptance is defined in the
[Egress Enabler Contract](../how-it-works/egress-enabler.md) §8 — run the
`e2e/latency-benchmark-*` scripts with the enabler on versus off (§7).

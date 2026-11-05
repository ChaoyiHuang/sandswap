---
title: Topologies
nav_order: 4
parent: How It Works
---

# Topologies

Sandswap deploys in a small set of physical shapes, in two environments:
**bare metal** first (one machine → single gateway + N nodes → multi-gateway
production), then the same shapes **on Kubernetes**. Everything else —
gateway modes, etcd, sandns, shared storage — composes on top. This page is the
conceptual map; the step-by-step installs live in
[Deployment](../deployment/index.md).

## 1. How to read the diagrams

- Each outer box is a **physical host** (bare metal) or a **pod** (Kubernetes);
  boxes inside it are processes or containers.
- Arrows are labeled `protocol :port`; the arrow names its initiator. One
  rule matters most: **every sandlot dials out** to the gateway, so nodes
  have no inbound ports.
- `[EXT]` marks a third-party system (etcd, shared storage) — Sandswap
  integrates with it but does not ship it.
- The two actors: **AI agents** (HTTP/MCP — execute code and files) and the
  **operator** (human API — SandFS/agent/template CRUD, ops).
- Inside every exec-role node runs the same stack — the diagrams below
  draw it compactly as `sandlot (exec role)`; expanded here once:

```
sandlot ──UDS──► sandvmm ──KVM──► microVM (warden, PID 1)
   ▲                                    │
   └───── vsock :1024 (hot path) ───────┘   bypasses the VMM
```

## 2. The shapes at a glance

| Shape | Gateway | Nodes | etcd | sandns | Storage |
|---|---|---|---|---|---|
| [1. One machine — in-memory](#5-1-one-machine--in-memory-store) | 1 × single-node (MemoryStore) | co-located | — | — | local disk |
| [2. One machine — etcd](#5-2-one-machine--etcd) | exec gateway + human gateway, co-located | co-located | local, single | — | local disk |
| [3. Single gateway + N nodes](#5-3-single-gateway--n-nodes--etcd) | exec gateway + human gateway, co-located | N | on the GW host | — | shared FS |
| [4. Multi-gateways + DNS](#5-4-production--multiple-gateways--dns) | 2+ exec gateway + 2+ human gateway | N | 3 hosts | sandns | shared FS |
| [Kubernetes](#6-kubernetes) | any of the above, pod-packaged | DaemonSet | StatefulSet | optional | shared FS via PV |

In the etcd shapes (2–4), SandFS volumes are often materialized from OCI
templates — the OCI registry is an optional external component
([Templates](templates.md)).

## 3. Gateway run modes

One binary, three roles (flag `-mode`; listeners per mode are tabulated in
the [Human API](../reference/human-api.md#listeners--run-modes)). The modes
determine which shapes below are possible:

- **single-node** (default): agent + human + stream listeners in one
  process, in-memory store persisted to a snapshot file, zero external
  dependencies. **Rejects `-etcd`** — the in-memory store is the point.
- **exec**: the exec gateway — `/agent/*` + `/mcp` + the gRPC stream;
  pool, lease, ownership claims. **Requires etcd** (identity is a read-only
  cache from watch). Has **no human endpoints** — so an etcd-backed
  deployment always pairs it with a human gateway for CRUD.
- **human**: the control plane — SandFS/agent/template CRUD + ownership
  ops on `:3100`; no pool, no nodes. **Requires etcd.**

Distributed deployments run ≥1 of each against one etcd cluster; state is
shared via watch, and ownership/health/presence coordination is entirely
etcd-driven (see [Resilience](resilience.md)). Multiple exec gateways are
fronted by sandns (see
[Ownership & DNS](ownership-and-dns.md)); a single exec gateway is
addressed directly and needs no DNS.

## 4. Sandlot run modes

The same binary, two roles (flag `-roles`; restart-required). Where the
gateway splits by listeners, sandlot splits by workload — execution versus
provision:

- **exec**: the execution role — microVM pool lifecycle, SandFS swap in/out
  (`set-fs`), and the warden vsock client. Dials the **exec gateway's**
  stream (`:9998`) and carries the exec plane end to end. Needs KVM and
  `/dev/vhost-vsock` on the host; its stream connection is sticky (never
  recycled).
- **prov**: the provision role — sandfs/template lifecycle on shared storage
  (volume ensure/delete, template pull/push/save/list). Dials the **human
  gateway's** prov stream (`:9998`; `:9996` when the human gateway is
  co-located with an exec gateway) and executes the ProvisionCommands
  behind SandFS CRUD. Needs no KVM and runs no VMs — storage-attached
  hosts, so template batches never contend with exec-path I/O. Its
  connections are non-sticky (re-picked per dial and recycled by age) so
  instances spread across prov peers.
- **exec,prov** (combined): one instance doing both — the single-node
  shape, and the compact variant of the bigger shapes.

A role-lock enforces one sandlot instance per host (a second instance is
refused at startup; `-allow-colocated-instances` is the simulation-only
escape hatch). The split mirrors the gateway split: exec sandlot instances pair
with exec gateway, prov sandlot instances pair with human gateway — the shapes
above show them as separate hosts.

## 5. Bare metal

### 5.1 One machine — in-memory store

Everything on one machine with local disk. Single-node mode keeps all
listeners (agent + MCP + human API + node stream) in one process, and
identity state is a snapshot file. No etcd, no DNS, no shared storage — the
smallest complete deployment.

```
        AI agents (HTTP / MCP)                operator
              │                                  │
              │ :3000 execute · file I/O ·       │ :3100 SandFS CRUD,
              │ MCP (same listener)              │ templates · stats
              └────────────────┬─────────────────┘
                               ▼
┌──────────────────────────────────────────────────────────────┐
│ one machine (local disk)                                     │
│                                                              │
│  ┌────────────────────────┐        ┌───────────────────────┐ │
│  │ gateway (human+exec)   │  gRPC  │ node (exec+prov)      │ │
│  │ :3000 agent + MCP      │◄──────►│ sandlot ──UDS──►      │ │
│  │ :3100 human API        │ bidi,  │   sandvmm ──KVM──►    │ │
│  │ :9998 node stream      │ sandlot│     microVM (warden)  │ │
│  │ identity: snapshot     │ dials  │ sandlot ──vsock :1024 │ │
│  │ file                   │ out    │   ──► warden (hot)    │ │
│  └───────────┬────────────┘        │ virtio-fs: the active │ │
│              │ create / seed       │ agent's dir ──► guest │ │
│              ▼                     │ /mnt/rootfs           │ │
│  ┌────────────────────────┐        └───────────┬───────────┘ │
│  │ volumes/ — local disk  │◄───────────────────┘             │
│  │ one dir per SandFS     │                                  │
│  └────────────────────────┘                                  │
└──────────────────────────────────────────────────────────────┘
```

- **Agent and operator have separate listeners in one process** — the agent
  API (`:3000`) and the human API (`127.0.0.1:3100`); the human listener is
  loopback-bound because the shipped shape is anonymous.
- **Sandlot with exec and prov roles** — on single-node machines, the merged
  `exec,prov` sandlot instance.
- **Same-machine lines**: gateway ↔ sandlot gRPC stream (`:9998`, sandlot
  dials out); node stack (UDS / KVM / vsock / virtio-fs); the node stack is
  expanded at the top of this page.
- Deploy: `deploy/baremetal/deploy-single-node.sh` (Quick Start).

### 5.2 One machine — etcd

The same single machine, but the gateway runs as two processes against a
local etcd: **exec** (agent traffic) + **human** (CRUD/ops), co-located with
the node and the volumes. Production-like semantics (etcd identity store,
split listeners) with a one-host footprint — a staging shape or the
binpacked core of a bigger deployment.

```
        AI agents (HTTP / MCP)                  operator
              │                                    │
              │ :3000 execute · file I/O ·         │ :3100 SandFS CRUD,
              │ MCP (same listener)                │ templates · ops
              ▼                                    ▼
┌─────────────────────────────────────────────────────────────────┐
│ one machine (local disk)                                        │
│                                                                 │
│  ┌──────────────────────┐    ┌───────────────────────────────┐  │
│  │ exec gateway         │    │ human gateway                 │  │
│  │ :3000 agent + MCP    │    │ :3100 CRUD · templates · ops  │  │
│  │ :9998 node stream    │    │ :9996 prov stream             │  │
│  └───────┬──────────┬───┘    └──────────────┬─────────┬──────┘  │
│          │          │ identity · ownership  │         │         │
│          │    ┌─────▼───────────────────────▼───┐     │         │
│          │    │ etcd (local, single process)    │     │         │
│          │    └─────────────────────────────────┘     │         │
│          │ gRPC bidi stream :9998    gRPC bidi stream │         │
│          │ (exec role — hot path)   :9996 · prov role │         │
│  ┌───────▼─────────────────────────┐    ┌─────────────▼───────┐ │
│  │ sandlot (exec role)             │    │ sandlot (prov role) │ │
│  └───────┬─────────────────────────┘    └─────────────┬───────┘ │
│          │ virtio-fs — the active                     │ volume +│
│          │ agent's directory                          │ template│
│  ┌╌╌╌╌╌╌╌▼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌▼╌╌╌╌╌╌╌┐ │
│  │ volumes/ — local disk, one directory per SandFS            │ │
│  └╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┘ │
└─────────────────────────────────────────────────────────────────┘
```

- **No DNS**: one exec gateway — agents address it directly.
- **Single etcd process** is fine at this scale; move etcd off-box (3-node
  cluster) before adding a second exec gateway.
- Deploy: `deploy/baremetal/deploy-one-machine-etcd.sh` — one command for
  the whole shape: co-located mTLS etcd (persistent) + exec/human gateways +
  one exec sandlot + one prov sandlot, local-disk volumes and templates. The
  exec and prov roles run as two sandlot processes — the one-machine layout
  the role-lock's explicit `-allow-colocated-instances` admission covers (a
  merged instance dials a single gateway address, and this shape's gateways
  are split).

### 5.3 Single gateway + N nodes — etcd

Scale out the node fleet: the gateway host keeps exec gateway +
human gateway co-located with etcd. Exec node hosts (×N, KVM) dial
exec gateway; dedicated prov node hosts (×M, storage-attached, no KVM)
dial human gateway. A shared filesystem replaces the local disk so any
node can serve any SandFS. Still no DNS — one exec gateway, addressed
directly.

```
        AI agents (HTTP / MCP)                   operator
              │                                     │
              │ :3000 execute · file I/O ·          │ :3100 SandFS CRUD,
              │ MCP (same listener)                 │ templates · ops
              ▼                                     ▼
┌─────────────────────────────────────────────────────────────────┐
│ gateway host                                                    │
│                                                                 │
│  ┌──────────────────────┐    ┌───────────────────────────────┐  │
│  │ exec gateway         │    │ human gateway                 │  │
│  │ :3000 agent + MCP    │    │ :3100 CRUD · templates · ops  │  │
│  │ :9998 node stream    │    │ :9996 prov stream             │  │
│  └───────┬──────────┬───┘    └──────────────┬─────────┬──────┘  │
│          │          │ identity · ownership  │         │         │
│          │    ┌─────▼───────────────────────▼───┐     │         │
│          │    │ etcd (single process —          │     │         │
│          │    │ move to a 3-node cluster        │     │         │
│          │    │ before adding GW #2)            │     │         │
│          │    └─────────────────────────────────┘     │         │
└──────────┼────────────────────────────────────────────┼─────────┘
           │ gRPC bidi stream :9998     gRPC bidi stream│
           │ every sandlot dials out   :9996 · prov role│
           │ (no inbound ports on nodes)                │
┌──────────┼────────────────────────┐ ┌─────────────────┼─────────┐
│ exec node hosts ×N (KVM on each)  │ │ prov node hosts ×M        │
│ every node runs:                  │ │ (storage-attached hosts,  │
│ sandlot (exec role)               │ │  no KVM needed)           │
│ warm microVM pool · vsock exec    │ │ sandlot (prov role)       │
└───────────────┬───────────────────┘ │ volume · template ops     │
                │ virtio-fs — the     └──────────┬────────────────┘
                │ active agent's directory       │ volume +
                │ crosses                        │ template writes
┌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌▼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌▼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┐
│ volumes [EXT] — shared FS (Cloud FS / NFS / CephFS / …),        │
│ one directory per SandFS — only sandlot (prov role) instances   │
│ write it (create / seed / delete); the gateways mount nothing   │
└╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┘
```

- **Gateway host**: no KVM needed — it never runs VMs, and it never touches
  SandFS/template storage: all volume and template work is done by the prov
  node hosts.
- **Exec node hosts** (×N): KVM + `/dev/vhost-vsock` + the shared storage.
  Each holds a pool of warm CLEAN microVMs; commands arrive over the one
  outbound stream.
- **Prov node hosts** (×M): storage-attached, no KVM — sandlot (prov role)
  performs all volume/template work for human gateway over its prov stream
  (`:9996`).
- Same-SandFS-on-any-node works because the volume directory is visible
  everywhere.
- Deploy: `deploy/baremetal/deploy-cluster-one-gw.sh`
  (`cluster-simple.sample.yaml`) — installs a co-located single-node etcd on
  the gateway host unless `etcd.endpoints` points at an existing cluster.
  The script deploys the **compact form** of this shape: exec node hosts ×N
  plus the prov instance on the gateway host (the diagram's dedicated prov
  hosts ×M speak the same protocol and are assembled from the same prov
  install steps). To rehearse this multi-host shape on a single machine:
  `deploy/baremetal/deploy-cluster-one-gw-simulation.sh` (N sandlot
  instances standing in for the node hosts, plain-http local etcd).

### 5.4 Production — multiple gateways + DNS

The full shape — every component group on its own hosts: exec gateway
hosts (×2+, one gateway each, agent traffic), human gateway hosts (×H,
SandFS/template management), a 3-host etcd cluster, sandns hosts
(×2+), N exec node hosts and M prov node hosts — all on shared storage,
TLS everywhere. Agents are spread across the exec gateways by owner-aware
DNS instead of a hardcoded address; the gateways coordinate through etcd.

```
         AI agents (HTTP / MCP)                    operator
         │                   │                        │
         │ :53               │ :3000 execute ·        │ :3100 SandFS CRUD,
         │ resolve           │ file I/O · MCP         │ templates · ops
         ▼                   ▼                        ▼
 ┌─────────────────┐  ┌─────────────────────────┐  ┌────────────────────────┐
 │ sandns hosts ×2+│  │ exec gateway hosts ×2+  │  │ human gateway hosts ×H │
 │ sandns :53      │  │ :3000 agent + MCP       │  │ :3100 CRUD + ops       │
 │ owner-aware     │  │ :9998 node stream       │  │ :9996 prov stream      │
 │ routing         │  └──────┬─────────┬────────┘  └─────┬───────────────┬──┘
 └───────┬─────────┘         │         │                 │               │
         │ watch (RO)        │         │ ownership ·     │ SandFS state  │
         │                   │         │ routing state   │               │
         │                   │   ┌─────▼─────────────────▼───────────┐   │
         └──────────────────────►│ etcd hosts ×3 [EXT] —             │   │
                             │   │ ownership · health · presence     │   │
                             │   │ placement · gateway registry      │   │
                             │   └───────────────────────────────────┘   │
                             │ gRPC bidi stream :9998    gRPC bidi stream│
                             │ every sandlot dials out  :9996 · prov role│
                             │ (DNS name via sandns)                     │
┌────────────────────────────┼──────┐ ┌──────────────────────────────────┼─┐
│ exec node hosts ×N (KVM on each)  │ │ prov node hosts ×M                 │
│ every node runs:                  │ │ (storage-attached, no KVM)         │
│ sandlot (exec role)               │ │ sandlot (prov role)                │
│ warm microVM pool · vsock exec    │ │ volume · template ops · OCI        │
└───────────────┬───────────────────┘ └──────────┬─────────────────────────┘
                │ virtio-fs — the                │
                │ active agent's directory       │ volume +
                │ crosses                        │ template ops
┌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌▼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌▼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┐
│ volumes [EXT] — shared FS (Cloud FS / NFS / CephFS / …)                   │
│ one directory per SandFS — only prov sandlot writes it                    │
│ (create/seed/delete); every exec node mounts it (virtio-fs)               │
└╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┘
```

- **Actors**: agents resolve `sandswap.local` via sandns (`:53`) and
  execute against the owning exec gateway (`:3000`); the operator uses the
  human gateway (`:3100`) for SandFS/agent/template CRUD and ownership ops.
- **Cross-host lines**: gateways ↔ etcd (ownership/health/presence/
  placement/registry), sandns → etcd (read-only watch), exec sandlot →
  exec gateway stream (`:9998` — sandlots resolve `sandswap-stream.local`
  through sandns), prov sandlot → human gateway prov stream
  (`:9998`), and everyone ↔ the shared storage.
- **What the second exec gateway adds**: horizontal capacity plus gateway
  failover — ownership moves, agents get owner-aware DNS answers and
  retryable 503s instead of outages ([Resilience](resilience.md),
  [Ownership & DNS](ownership-and-dns.md)).
- Deploy: `deploy/baremetal/deploy-cluster-multi-gw.sh`
  (`cluster-production.sample.yaml`; the diagram shows dedicated hosts per
  component — the sample binpacks the human gateway onto an exec host, a
  supported variant). To rehearse the whole
  shape on one machine: `deploy/baremetal/deploy-cluster-multi-gw-simulation.sh`
  (etcd + 2 exec gateways + human gateway + 2 sandlots + sandns, all co-located).

## 6. Kubernetes

Kubernetes changes the **packaging**, not the topology: the gateways
run as StatefulSets — exec gateway behind a **headless** Service,
human gateway behind its own Service — etcd a StatefulSet, the exec node
stack a DaemonSet with one pod per cluster node (`hostNetwork`), and the
prov sandlot instances a plain Deployment. The headless Service gives every gateway pod a stable FQDN
(`<pod>.gateway-exec.<ns>.svc`) that doubles as the gateway identity —
etcd's routing registry, owner-aware DNS, and 307 redirects all target it,
and the sandlot's last-gateway memory pins its pod across reconnects. (A
regular ClusterIP Service would defeat that pinning: its VIP routes to any
pod.) The StatefulSet keeps the pod name — and with it the FQDN and the
identity — across restarts. Sandlot's memory is the pod **IP** and it
re-dials that IP directly, so the deployment MUST keep gateway pod IPs
stable across restarts (e.g. CNI-level static IP assignment) — a sandlot
requirement on the deployment. The bare-metal
ladder maps directly — one gateway replica is the small shape, several
gateway replicas + DNS is the production shape — so one cluster picture
covers both:

```
           AI agents (HTTP / MCP)                      operator
            │                │                            │
            │ :53 — via      │ :3000 — exec               │ :3100 — human
            │ CoreDNS        │ gateway Service            │ gateway Service
            ▼                ▼                            ▼
   ┌───────────────────────────────────────────────────────────────────────┐
   │ namespace: sandswap                                                   │
   │                                                                       │
   │  ┌─────────────┐  ┌───────────────────────┐ ┌──────────────────────┐  │
   │  │ Deployment: │  │ StatefulSet ×2+       │ │ Deployment           │  │
   │  │ sandns      │  │ exec gateway          │ │ human gateway        │  │
   │  │             │  │ (headless Service)    │ │ (+ Service)          │  │
   │  └─────┬───────┘  └─────┬───────────┬─────┘ └─────┬──────────┬─────┘  │
   │        │ watch (RO)     │           │ etcd: read/ │          │        │
   │        │                │           │ write/watch │          │        │
   │        │                │     ┌─────▼─────────────▼───────┐  │        │
   │        └─────────────────────►│ StatefulSet: etcd [EXT] ×3│  │        │
   │                               └───────────────────────────┘  │        │
   │                         │ gRPC stream :9998 —                │        │
   │                         │ every exec sandlot pod             │        │
   │                         │ dials the exec gateway Svc         │        │
   │                         │                   prov stream :9996│        │
   │                         │                   prov sandlot pods│        │
   │ ┌───────────────────────┼─────────────┐  ┌───────────────────┼──────┐ │
   │ │ DaemonSet — one pod per cluster node│  │ Deployment:              │ │
   │ │ (hostNetwork): exec sandlot pods    │  │ sandlot(prov)            │ │
   │ │ embedded or boxout                  │  │ volume · template ops    │ │
   │ └───────────────┬─────────────────────┘  └────────────┬─────────────┘ │
   │                 │                                     │               │
   └─────────────────┼─────────────────────────────────────┼───────────────┘
                     │ virtio-fs — the                     │ volume +
                     │ active agent's directory            │ template ops
   ┌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌▼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌▼╌╌╌╌╌╌╌╌╌╌╌╌╌╌┐
   │ volumes [EXT] — the same Cloud FS / NFS / CephFS export,             │
   │ mounted into pods via PV / hostPath                                  │
   └╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┘
```

- The control plane packs the same way when present: human gateway
  behind its own Service, and the prov sandlot instances as a Deployment dialing
  its prov stream.
- CoreDNS forwards the sandswap zones to sandns, so pods keep their
  normal resolver and still resolve `sandswap.local` /
  `sandswap-stream.local` / `<sandfs_id>.sandfs.sandswap.local`.
- Everything else — actors, ports, etcd coordination, the stream — is
  identical to the bare-metal topologies above.
- Deploy: `deploy/k8s/deploy-k8s-embedded.sh` or
  `deploy/k8s/deploy-k8s-boxout.sh`.

#### The exec sandlot pod: embedded (default)

One privileged container holds the whole node stack:

```
┌─ DaemonSet pod, per cluster node — embedded ─────────────────┐
│                                                              │
│  ┌─ container: sandlot — UID 0, privileged ────────────────┐ │
│  │                                                         │ │
│  │   sandlot ──UDS──► sandvmm ──KVM──► microVM (warden)    │ │
│  │      ▲                                │                 │ │
│  │      └──── vsock :1024 (hot path) ────┘                 │ │
│  │                                                         │ │
│  │   everything privileged lives here: sandvmm lifecycle · │ │
│  │   TAP/network · host-side overlay mounts · /proc        │ │
│  │   re-adopt · crash detection                            │ │
│  └─────────────────────────────────────────────────────────┘ │
│                                                              │
│  hostNetwork · hostPID · initContainer: attach-vsockguard    │
│  hostPath: /dev/kvm, /dev/vhost-vsock, volumes,              │
│  kernel + initramfs + templates                              │
└──────────────────────────────────────────────────────────────┘
```

#### The exec sandlot pod: boxout

The same pod split by privilege: the unprivileged sandlot keeps the hot
path and delegates everything requiring root to the boxout sidecar over a
Unix socket:

```
┌─ DaemonSet pod, per cluster node — boxout ───────────────────┐
│                                                              │
│  ┌─ container: sandlot — UID 65536 (reserved), caps off ───┐ │
│  │   hot path only: gRPC stream · set-fs · warden vsock ·  │ │
│  │   sticky lease — zero privileges                        │ │
│  └──────────────────────┬──────────────────────────────────┘ │
│                         │ UDS /run/sandswap-boxout/          │
│                         │     boxout.sock (SO_PEERCRED)      │
│  ┌──────────────────────┴──────────────────────────────────┐ │
│  │  container: boxout — UID 0, privileged                  │ │
│  │   privileged path only: sandvmm lifecycle · network     │ │
│  │   provisioning · host-side overlay mounts · /proc       │ │
│  │   re-adopt · crash detection                            │ │
│  │   sandvmm ──KVM──► microVMs (warden)                    │ │
│  └─────────────────────────────────────────────────────────┘ │
│                                                              │
│  hostNetwork · hostPID · initContainer: attach-vsockguard    │
│  devices (/dev/kvm, /dev/vhost-vsock, /dev/net/tun) are      │
│  mounted into the boxout container only                      │
└──────────────────────────────────────────────────────────────┘
```

#### Choosing between embedded and boxout

| | Embedded | Boxout |
|---|---|---|
| Where | bare metal, K8s | K8s |
| sandlot runs as | root / privileged (UID 0) | unprivileged (UID 65536, the reserved sandbox identity — caps dropped) |
| Privileged path (sandvmm lifecycle, network provisioning, host OverlayFS mounts, /proc re-adopt, crash detection) | sandlot itself | delegated to the **boxout** sidecar (UID 0) over `/run/sandswap-boxout/boxout.sock` (private root-owned dir, SO_PEERCRED + optional HMAC challenge) |
| Hot path (set-fs, warden vsock exec, lease) | sandlot | sandlot — zero privileges needed |
| When to pick | nodes you fully control; simplest — **the default recommendation** | clusters where privileged workloads must be isolated/minimized |

**Boxout is a choice for a specific security posture, not an upgrade.**
Embedded is the default recommendation: fewer components, one process to
operate, and no privilege boundary to maintain in between. Boxout exists for
clusters whose policy forbids running sandlot itself as root — it trades
that isolation for an extra privileged sidecar, an extra hop
(sandlot → UDS → boxout) on the management path, and a wider component
surface to monitor and upgrade. Adding a component does not by itself make
performance, reliability, or security better; pick boxout only when your
threat model requires the sandlot itself to hold no privileges. The
mechanism is described in the [Boxout component page](components/boxout.md);
the deployment steps in
[Install — Kubernetes](../deployment/install-kubernetes.md).

## 7. Optional add-ons

- **OCI registry** — template pull/push ([Templates](templates.md)); optional
  external component, needed when SandFS volumes are materialized from OCI
  templates instead of local template directories.
- **sandns** — the owner-aware DNS service; routes across multiple exec
  gateways ([Ownership & DNS](ownership-and-dns.md)); deployed as part of the
  production install steps (bare metal systemd unit or k8s Deployment).
- **Egress enabler** — per-agent network identity stamping for third-party
  enforcers ([Egress Enabler Contract](egress-enabler.md)); dormant unless
  `-binding-backend` is set.

## 8. Cross-cutting requirements

Whichever topology you pick, plan for:

- **KVM on the nodes** (`/dev/kvm`, `/dev/vhost-vsock`) and the one-time
  host hardening (BPF LSM for vsockguard, sysctls, udev) —
  [Deployment → prerequisites & hardening](../deployment/index.md).
- **Shared storage** for anything multi-node (Cloud FS / NFS / CephFS / ...)
  — [SandFS](sandfs.md) for the contract,
  [Storage Backends](../integration/storage-backends.md) for the options.
- **TLS everywhere** in production, with SANs that cover the DNS domains
  and every exec gateway IP (the cross-host 307 redirect requirement).
- **Kernel versions**: host ≥ 5.10 covers everything (the strictest single
  feature is the egress enabler's `bpf` binding carrier, kernel ≥ 5.5); the
  routed-IPv6 egress pattern additionally needs guest-kernel IPv6 — included
  in the default `kernel/build.sh` build.

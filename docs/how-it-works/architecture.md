---
title: Architecture
nav_order: 2
parent: How It Works
---

# Architecture

Sandswap serves every AI agent request with an isolated sandbox on demand:
Sandswap attaches a warm pooled microVM with the agent's persistent
filesystem, and releases the VM when it goes idle. This page is the
structural view: the components, the optional ones, the connections, and
the flow of one request.

## 1. System context

Everything inside the Sandswap boundary is shipped as a Sandswap binary or
build artifact:

| Component | Kind | Present when | Role |
|-----------|------|--------------|------|
| **gateway** | Service | Always | The entry point: auth, SandFS registry, ownership, sticky lease, dispatch to nodes. Deployed as one combined process (single-node), or split into a **human gateway** (ops) and **exec gateways** (agent traffic) |
| **sandlot** | Daemon | Always — one per node | The node daemon: keeps a pool of warm microVMs ready, swaps the agent's SandFS in and out of a VM, and performs sandfs/template lifecycle on shared storage. Deployed as one combined instance (`-roles exec,prov`), or split into **exec sandlot** instances (compute) and **prov sandlot** instances (storage) |
| **sandvmm** | Process | Always — one per microVM | The KVM virtual machine monitor |
| **warden** | Process | Always — PID 1 in every microVM | Mounts the SandFS, runs the agent's commands |
| **sandns** | Service | Multi-gateway deployments | The owner-aware DNS service: answers "which gateway serves this SandFS?" and "which gateway serves this sandlot?" on DNS `:53` |
| **boxout** | Sidecar | Kubernetes (boxout mode) | Privileged helper so sandlot can run unprivileged |
| **kernel + initramfs** | Artifacts | Always | The boot image of every microVM (warden inside) |
| **vsockguard** | BPF LSM | Optional host hardening | Pins the host-side vsock transport against local users |

Around the boundary sit third-party systems Sandswap integrates with but
does not replace — none of them is required in the default single-node
deployment:

| External system | Used for | Needed when |
|-----------------|----------|-------------|
| **etcd** | Ownership, health, and routing records shared between gateways and sandns | Multi-gateway deployments |
| **Cloud FS / NFS / CephFS / ...** | Shared volumes storage | Multi-node deployments |
| **OCI registry** | Pull/push of rootfs templates | When templates are pulled or published |

The actors are **AI agents** (HTTP or MCP, the same listener) and
**operators** (human API: SandFS CRUD, templates).

## 2. Logical architecture

Solid boxes are Sandswap components; `[EXT]` marks a third-party system,
`[opt.]` a component needed only in specific deployments.

```
             AI agents                             operators
(HTTP :3000 / MCP, same listener)         (human API :3100 when split)
             │                                         │
             ▼                                         ▼
   ┌───────────────────┐                     ┌───────────────────┐
   │ exec gateway      │                     │ human gateway     │
   │ agent+MCP :3000   │                     │ human API :3100   │
   │ stream :9998      │                     │ prov stream :9998 │
   │ auth · ownership  │                     │ SandFS CRUD ·     │
   │ sticky lease      │                     │ templates CRUD    │
   └──────────────┬────┘                     └───┬───────────────┘
      ▲           │                              │     ▲
      │           │ownership               SandFS│     │ gRPC bidi stream
      │           │routing state           state │     │ (sandlot dial out)
      │           │     ┌───────────────┐        │     │
      │           │     │ sandns [opt.] │        │     │
      │           │     │ on DNS :53    │        │     │
      │           │     └──────▲────────┘        │     │
      │           │            │watch,read-only  │     │
      │           │  ┌╌╌╌╌╌╌╌╌╌┴╌╌╌╌╌╌╌╌╌┐       │     │
      │           └─►│    etcd [EXT]     │◄──────┘     │
      │              │    (multi-gw)     │             │
      │              └╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┘             │
      │ gRPC bidi stream(sandlot dial out)             │
┌─────▼─────────────────────────┐       ┌──────────────▼──────────────────┐
│ node × N — exec sandlot       │       │ instances × M — prov sandlot    │
│ sandvmm · microVMs (warden)   │       │ sandfs + template lifecycle     │
│ one SandFS per microVM        │       │ OCI pull/push [EXT]             │
│ at a time                     │       └──────────────┬──────────────────┘
└─────┬─────────────────────────┘                      │
      │ virtio-fs passthrough                          │ volume + template writes
      │ — only the active agent's                      │
      │ directory                                      │
      ▼                                                ▼
┌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┐
│      volumes + templates — one directory per SandFS                      │
│      local disk, or Cloud FS / NFS / CephFS / ... [EXT]                  │
└╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┘
```

Notes on lines not drawn:

- **Single-node mode is one combined gateway and one combined sandlot.** The
  diagram draws the split deployment — human gateway + exec gateway,
  prov sandlot + exec sandlot — because the two roles have different
  responsibilities and peers. Both splits are optional: in single-node mode
  one gateway process serves both listeners and accepts both stream roles,
  and one sandlot carries both roles (`-roles exec,prov`).
- **Agents and sandlots query sandns** (`:53`) to find the gateway they should
  talk to — multi-gateway deployments only; in single-node mode they address
  the gateway directly.
- **Gateways never touch the storage plane.** SandFS creation/seeding,
  template pull/push/save, and volume deletion are ProvisionCommands the
  gateway routes over the stream to a **prov sandlot** instance
  (deployed on storage-attached hosts, or the same host as the gateway in
  compact topologies). No gateway mounts anything from the volumes/templates
  trees or holds registry egress.

### 2.1 The three planes

- **Control plane** — the human gateway, the prov sandlot instances, and etcd:
  manage SandFS identities and templates, track ownership, and perform
  all sandfs/template storage work. Agent code never travels through it.
- **Exec plane** — the exec gateway, sandns (optional), and the exec sandlot
  nodes: gateway → sandlot → sandvmm → microVM (warden). Every command an
  agent runs travels this chain.
- **Storage plane** — the volumes + templates trees: one directory per
  SandFS on local disk or shared storage. Written ONLY by prov sandlot
  instances (creation, seeding, deletion, template pull/push) and the
  serving FUSE daemon (sandvmm); exec sandlot nodes read it via virtio-fs
  passthrough.

The central invariant lives in the exec plane: **one SandFS per microVM at
a time** — a microVM runs at most one SandFS, and Sandswap mounts one
SandFS in at most one microVM.

## 3. Inside a sandlot exec node

The exec sandlot node from the logical architecture — the one that runs
microVMs. A prov sandlot runs the same sandlot binary with no VM side:
no sandvmm, no warden clients, no pool — just storage operations against the
volumes/templates trees.

```
         ▲   to gateway :9998
         │   (gRPC bidi stream — sandlot dials out,
         │    the gateway never connects in)
┌────────┼──────────────────────────────────────────┐
│ node   │                                          │
│        │                                          │
│   ┌────┴───────────────────┐                      │
│   │ sandlot                │                      │
│   │ VM pool · SandFS swap  ├──►┌──────────────┐   │
│   │ warden client (vsock)  │   │ boxout       │   │
│   └─┬─────────────────────┬┘   │ [opt., K8s]  │   │
│     │  HTTP over UDS      │    └──────────────┘   │
│   ┌─▼──────────────┐      │ vsock :1024           │
│   │ sandvmm        │      │ direct to warden —    │
│   │ KVM · virtio-fs│      │ no sandvmm hop        │
│   └─┬──────────────┘      │                       │
│     │ KVM                 │                       │
│   ┌─▼──────────────────┐  │                       │
│   │ microVM            │  │                       │
│   │ warden (PID 1)     │◄─┘                       │
│   │ chroot: /mnt/rootfs│                          │
│   │ eth0 → host bridge │                          │
│   └────────┬───────────┘                          │
│            │ virtio-fs passthrough                │
│            │ — only the active                    │
│            │ agent's directory                    │
└────────────┼──────────────────────────────────────┘
             │
             │
┌─╌╌╌╌╌╌╌╌╌╌─▼─╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌──┐
│ volumes — one directory per SandFS │
│ local disk, or Cloud FS / NFS /    │
│ CephFS / ... [EXT]                 │
└──╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌──┘
```

The connections, one by one:

- **gRPC stream (up, `▲`)** — sandlot's only link to the rest of the
  platform. One persistent outbound connection to the gateway; the stream
  multiplexes all VM commands, events, and heartbeats.
- **HTTP over UDS (control)** — sandlot drives sandvmm: create, boot,
  `set-fs`, ping, shutdown. Rare, milliseconds, never on the hot path.
- **KVM** — sandvmm runs the microVM: its own kernel, warden as PID 1.
- **vsock `:1024` (business path)** — sandlot talks to the warden directly.
  The connection is carried by the kernel's vhost-vsock backend; sandvmm is
  not in the data path. Mount, exec, unmount, stats all travel here.
- **UDS to boxout (optional, Kubernetes)** — the privileged broker for
  sandvmm lifecycle, networking, and host-side overlay mounts.
- **virtio-fs passthrough (down)** — the guest sees exactly one SandFS
  directory; every write lands in the agent's persistent volume.
- **eth0 → host bridge** — guest egress to the internet; on egress-enabler
  nodes the traffic carries the Sandswap egress identity (see
  [Egress Enabler Contract](egress-enabler.md)).

## 4. Deployment views

### 4.1 Single-node (default)

One gateway process, one node, no external systems — identity state is an
in-process store persisted to a snapshot file:

```
External AI Agents/Human (HTTP/MCP)
        │
        ▼
┌─────────────────┐    gRPC bidirectional stream    ┌──────────────────┐
│ gateway         │◄───────────────────────────────►│ sandlot (node)   │
│ :3000 agent+MCP │    (sandlot dials out :9998)    │ exec+prov roles  │
│ +human API      │                                 │ ┌──────────────┐ │
│ :9998 exec+prov │                                 │ │ sandvmm      │ │
│ in-process      │                                 │ │  ┌────────┐  │ │
│ identity store  │                                 │ │  │microVM │  │ │
│ (snapshot file) │                                 │ │  │ warden │  │ │
└─────────────────┘                                 │ │  └────────┘  │ │
                                                    │ └──────────────┘ │
                                                    └──────────────────┘
```

Volumes live on local disk. This is the smallest complete deployment: every
component above except etcd, sandns, boxout, and the OCI registry.

### 4.2 Distributed

The human gateway (SandFS/template management) + exec gateway instances
(agent traffic) + etcd + sandns; N exec node hosts dial the exec gateway, M
prov sandlot instances dial the human gateway:

```
    ┌────────────┐    ┌─╌╌╌╌╌╌╌╌╌╌╌╌╌╌─┐
    │ sandns     │◄───│  etcd cluster  │
    │ on DNS :53 │    │  (state store) │
    └────────────┘    └─╌╌┬─╌╌╌╌╌╌╌╌─┬─┘
                          │          │
        ┌─────────────────▼──┐  ┌────▼───────────────┐
        │human gateway       │  │exec gateway        │
        │:3100 /human/*      │  │:3000 /agent/*      │
        │prov stream :9996   │  │:9998 node stream   │
        └─────────▲──────────┘  └─────────▲──────────┘
                  │                       │
                  │                       │
                  │ gRPC stream           │ gRPC stream
                  │ (sandlot dial out)    │ (sandlot dial out)
                  │                       │
        ┌─────────▼──────────┐            │
        │prov sandlot ×M     │            │
        │storage + OCI ops   │            │
        └────────────────────┘            │
                 ┌──────────────────┬─────┴────────────┐
                 │                  │                  │
          ┌──────▼──────┐    ┌──────▼──────┐    ┌──────▼──────┐
          │exec sandlot │    │exec sandlot │    │exec sandlot │
          │node-1       │    │node-2       │    │node-3       │
          │KVM microVMs │    │KVM microVMs │    │KVM microVMs │
          └─────────────┘    └─────────────┘    └─────────────┘
```

The human gateway and exec gateway share SandFS state via etcd: the human
gateway does SandFS CRUD with distributed locks; exec gateways serve agent
traffic — execution and `GET /agent/sandfs` discovery alike — from a
read-only cache synced by watch. Multiple exec gateways sit behind
owner-aware DNS (see [Ownership & DNS](ownership-and-dns.md)). The prov
sandlot instances under the human gateway dial its stream listener
(`:9996`) and execute the storage operations behind SandFS CRUD and
template commands.

### 4.3 Sandlot privilege modes: embedded vs boxout

Which modes a platform supports:

| Platform | Embedded | Boxout |
|----------|----------|--------|
| Bare metal | ✓ (the only mode) | — |
| Kubernetes | ✓ | ✓ |

The node diagrams show **embedded** mode: sandlot is privileged and manages
sandvmm directly — on bare metal this is the only mode. In **boxout** mode
(Kubernetes), sandlot runs unprivileged (UID 65536 — the reserved sandbox
identity, see [Prerequisites](../deployment/prerequisites.md) — all caps
dropped) and
delegates the privileged path — sandvmm lifecycle, network provisioning,
host-side OverlayFS mount/unmount, /proc re-adopt, crash detection — to a
privileged **boxout** sidecar (UID 0) over a Unix socket
(`/run/sandswap-boxout/boxout.sock` — a boxout-private root-owned 0711
directory separate from the sandlot-writable `/run/sandswap`;
SO_PEERCRED-verified, plus an optional per-connection HMAC
challenge-response where the token never crosses the wire). The hot path
(set-fs, warden vsock exec, lease) stays in sandlot and needs zero
privileges. See [Install — Kubernetes](../deployment/install-kubernetes.md).

## 5. Interface catalog

| Path | Transport | Initiator | Purpose |
|------|-----------|-----------|---------|
| Agent → gateway | HTTP `:3000` (MCP on the same listener) | agent | execute, file I/O, background exec status/kill, SandFS discovery |
| Operator → gateway | human API (same listener single-node; `:3100` split modes) | operator | SandFS CRUD, template pull/push/save |
| exec sandlot → gateway | gRPC bidi stream, TCP `:9998` (TLS/mTLS) | exec sandlot | VM commands, async events, heartbeats — one outbound connection per exec instance |
| prov sandlot → gateway | gRPC bidi stream, TCP `:9998` (TLS/mTLS) | prov sandlot | ProvisionCommands + responses (volume/template lifecycle). Roles are advertised in `NodeHello`; the gateway routes each plane only to matching role connections |
| exec sandlot → sandvmm | HTTP/1.1 over Unix socket | exec sandlot | VM create/boot, vsock attach, `set-fs`, ping, shutdown |
| exec sandlot → warden | vsock (vhost-vsock), port 1024 | exec sandlot | mount/exec/unmount, memory stats, background exec |
| exec sandlot → boxout | newline-JSON over Unix socket | exec sandlot | privileged lifecycle ops (boxout mode only) |
| gateway → etcd | gRPC read/write/watch | gateway | ownership, health, placement, gateway registry |
| sandns → etcd | gRPC watch (read-only) | sandns | routing tables |
| prov sandlot ↔ OCI registry | OCI distribution API | prov sandlot | template pull/push — the egress lives on the provision host, never on the gateway |
| exec sandlot → volumes | filesystem (virtio-fs) | exec sandlot | read-only overlay lowerdirs; the serving FUSE daemon (sandvmm) writes guest data |
| prov sandlot → volumes/templates | filesystem | prov sandlot | the ONLY writer of volume trees (create/seed/delete) and the template store |
| agents, sandlots → sandns | UDP/TCP `:53` | agent / sandlot | gateway address resolution (multi-gateway) |
| microVM → internet | guest eth0 → host bridge | guest | egress; identity-stamped on enabler nodes |

The three internal paths that carry all the traffic, in detail:

### 5.1 Gateway ↔ sandlot (gRPC bidirectional stream)

```
Sandlot ─── outbound TCP ───→ Gateway (:9998)
  │                                │
  │ NodeHello{roles:[exec|prov]} → │  (handshake; the gateway rejects an
  │ ←── HelloAck{…|reject_reason}  │   instance whose roles it cannot accept,
  │                                │   naming the reason)
  │                                │
  │ ←──────── VMCommand{...} ───── │  (exec role only)
  │ CommandResponse{...} ────────→ │
  │ ←── ProvisionCommand{…} ────── │  (prov role only)
  │ ProvisionResponse{…} ────────→ │
  │                                │
  │ VMEvent{VSOCK_READY} ────────→ │  (async events)
  │ Heartbeat ───────────────────→ │  (periodic)
```

No ports are exposed on sandlot. It initiates a single persistent TCP
connection to the gateway (TLS/mTLS), and the gateway sends commands on the
response half of the stream. The message catalog is in
[Internal Protocols](../reference/protocols.md).

### 5.2 sandlot ↔ sandvmm (HTTP + raw frames over Unix socket)

```
Sandlot ─── HTTP/1.1 | raw frames ───→ /run/sandswap/vm/<id>/sandvmm.sock
  HTTP/JSON — VM lifecycle (once per VM):
    PUT /api/v1/vm.create
    PUT /api/v1/vm.add-vsock      (vhost-vsock device, body {cid})
    PUT /api/v1/vm.boot
    PUT /api/v1/sandvmm.shutdown
  raw control frames — per-request hot ops (no HTTP/JSON framing):
    vm.set-fs                     (virtio-fs allowed_dirs swap — every cold attach)
    sandvmm.ping                  (health probes)
```

One socket, two protocols: sandvmm dispatches each connection by the first
byte on the wire (`0x01` → raw frame, ASCII method letter → HTTP). The hot
ops default to length-prefixed binary frames because they run on every cold
attach and probe cycle, where HTTP/JSON framing overhead is measurable
(sandlot `-setfs-transport=http` selects the legacy REST form). Frame layout
and budgets: [Internal Protocols](../reference/protocols.md).

No containerd, no shim — direct control of the VMM.

### 5.3 sandlot ↔ warden (raw vsock protocol)

```
Sandlot ─── kernel AF_VSOCK (guest CID, port 1024) ───→ MicroVM
  raw vsock protocol:
    OP_MOUNT_AND_EXEC (1)       — mount + exec in one RTT (cold)
    OP_UNMOUNT (2)              — unmount + cgroup.kill
    OP_EXEC (3)                 — exec only (warm)
    OP_MEM_STATS (4)            — heartbeat: guest memory stats
    OP_ASYNC_EXEC (5)           — start background exec (warm)
    OP_MOUNT_AND_ASYNC_EXEC (6) — mount + start background exec (cold, 1 RTT)
    OP_STATUS_EXEC (7)          — poll background exec status
    OP_KILL_EXEC (8)            — kill background exec
    OP_FILE (9)                 — file I/O (unified sub-opcode dispatch)
```

**vsock backend: kernel vhost-vsock — chosen for ultra-low latency.** The
sandlot↔warden channel is the hottest transport in the system: every exec,
file op, and stat crosses it, so the transport itself must add close to
nothing. The two conventional alternatives each add measurable cost —
emulating the vsock device inside the VMM process (userspace virtio) forces
a VMEXIT and a VMM context switch on every packet, and going over the guest
NIC (virtio-net + TCP/IP) adds a full network stack — sockets, TCP, a host
bridge — to the data path. With kernel vhost-vsock, the entire data
path is offloaded to the Linux kernel via `/dev/vhost-vsock`: at device
activation the VMM hands guest memory + virtqueues to a kernel vhost worker
and never touches a packet afterward — **zero VMEXIT per packet**, no VMM
context switch, and a bare kernel `AF_VSOCK` socket pair instead of a
network stack. This keeps the vsock hop off the critical path:
millisecond-scale end-to-end ops are dominated by the work being done, not
by the transport. The vhost ioctl ABI is frozen UAPI (kernel 4.8+), so one
VMM binary runs across kernel versions. (Runtime prerequisite:
`/dev/vhost-vsock` readable — sandlot checks at startup.)

**Connection pooling**: the warden accepts multiple concurrent vsock
connections. Business ops use a per-VM pool (up to `exec_slots` resident
connections, one in-flight request each); each connection's receive timeout
is re-set per request to the op's duration + 30 s margin (capped at the
warden countdown), so a wedged connection fails fast instead of
blocking forever. Heartbeat probes use separate short-lived connections
(fresh every 3 s) so they never queue behind a long sync exec.

**Security hardening: vsockguard.** The warden performs **zero
authentication** on this port — whatever process manages to `connect()` to
`(guest CID, 1024)` can send mount/exec frames and act as the sandlot.
Device-node permissions cannot close this: an AF_VSOCK `connect()` goes
through no device node, and `/dev/vhost-vsock` only gates CID registration,
not connecting to an existing guest — so any local user on the node can
dial the warden. **vsockguard** closes this gap in the kernel: a BPF LSM program
on the `socket_connect` hook denies `connect()` to `AF_VSOCK` port `1024`
for every UID except the sandlot service UID (held in a BPF map, written by
the loader at attach time); all other address families and ports pass
through untouched. Two operational notes: the kernel's `bpf` LSM must be
active (`/sys/kernel/security/lsm`) or the attached program is a silent
no-op — `vsockguardctl` refuses to attach otherwise — and vsockguard covers
*active impersonation* only; *passive sniffing* of an existing connection
is prevented by the host security invariants. Full story in
[Vsockguard](vsockguard.md).

## 6. Life of a request

One tool call, end to end — the cold path (idle VM, mount first):

```
 agent                 gateway              sandlot            warden
   │ POST /agent/execute  │                    │                  │
   ├─────────────────────►│                    │                  │
   │                      │ api_key → agent    │                  │
   │                      │ owns sandfs_id ✓   │                  │
   │                      │ claim ownership    │                  │
   │                      │ pick node · reserve│                  │
   │                      │ start sticky lease │                  │
   │                      ├───────────────────►│                  │
   │                      │                    │ bind idle pool VM│
   │                      │                    │ vm.set-fs        │
   │                      │                    │ allowed_dirs swap│
   │                      │                    │ OP_MOUNT_AND_EXEC│
   │                      │                    ├─────────────────►│
   │                      │                    │                  │ mount /mnt/rootfs
   │                      │                    │                  │ chroot → run cmd
   │                      │                    │◄─────────────────┤ status + output
   │                      │◄───────────────────┤ response         │
   │◄─────────────────────┤ result JSON        │                  │
   │                      │                    │                  │
```

A follow-up call from the same agent inside the sticky-lease window skips
the middle of the diagram: the VM is still mounted, so the gateway sends
one command and sandlot issues a single `OP_EXEC` on the cached vsock
connection — the warm path.

The lifecycle around a request:

**1. SandFS creation (one-time, human API).** The human gateway generates a
`sandfs_id` and creates the volume on the volumes storage — no mount yet.
Flat mode is seeded either by copying a local template directory or, for
OCI-origin templates, by streaming the layer blobs straight into the volume
with permissions applied inline (no blob cache — dedup is the storage
backend's job). Overlay mode creates `rootfs/` · `workspace/` · `home/` plus a
`.template` marker, with the template's OCI layers extracted once into the
shared content-addressed `layers/` cache. The SandFS is owned by an agent
identity: that agent authenticates with its provisioned `api_key`
(config-file injection — zero code changes) and names this `sandfs_id` on
every request.

**2. The warm pool (continuous, per node — not per request).** Each sandlot
keeps its own pool of **CLEAN** microVMs per spec: pre-created at startup
and refilled asynchronously as VMs are consumed or recycled. Creating a VM
is purely local node work — the gateway never commands it: sandlot launches
the sandvmm process with a permanent virtio-fs device (tag `sandswap`,
shared dir = volumes dir, writable), boots kernel + initramfs, and warden
starts as PID 1 listening on vsock:1024. The request path contains no boot:
if no CLEAN VM fits, the request fails
fast (`NO_AVAILABLE_SANDBOX`) while the pool refills in the background.

**3. Code execution (every tool call).** The sequence above. Gateway side:
authenticate the `api_key`, resolve `sandfs_id` and its ownership, pick a
node (filter → affinity → score, reserving one clean slot), open the lease,
and send a single mount-and-execute command. Sandlot side: bind a CLEAN VM
to the sandfs (one sandfs → one VM; a warm bound VM is reused), lazily
host-mount the read-only lowerdir in overlay mode, and swap the virtio-fs
filter (`allowed_dirs = [agent's dir]`, ~0.20 ms); the warden then performs
the guest mount (bind rootfs → `/mnt/rootfs`, plus workspace/home/tmpfs in
overlay mode) and runs the command in a chroot — mount and exec travel in a
single vsock round trip. Only the active agent's directory is visible to
the guest; every write lands on the agent's persistent volume.

**4. Sticky lease (same agent, consecutive calls).** Within the lease
window (default 100 ms) the VM is still mounted — the next call takes the
warm path. The 100 ms is a latency/VM-hold trade-off, not a functional
floor: `-sticky-ms` accepts down to 1 ms (the minimum; 0 is rejected), and
the load benchmark ran a 1 ms window with back-to-back follow-up calls
still landing warm — see
[baremetal-load](../benchmark/baremetal-load.md).

**5. Background exec (long-running tools).** `background: true` returns an
`exec_id` immediately; the warden spawns the process under `setsid`, logs
to a temp file, and adds it to the agent's cgroup. The agent polls status /
kills by id. The `lease_duration` is an absolute run-time cap (polling does
not extend it). Details in the
[Agent API Reference](../reference/agent-api.md).

**6. Release (async).** After the lease expires, the gateway sends the
unmount off the response path: the warden kills every agent process
(`cgroup.kill` on the lazily created agent cgroup), tears down mounts,
umounts, and drops caches; sandlot clears `allowed_dirs`. The VM returns to
the pool CLEAN — or sandlot destroys and replaces it when the unmount fails
(the exclusive-ownership guarantee) — and recycles at the `max_uses` /
memory-pressure thresholds rather than running forever.

**7. Agent B on the same microVM.** A new mount-and-execute with agent B's
volume: filter swap + bind-mount swap after killing A's processes. B cannot
see any of A's data — enforced at both the VMM level (`allowed_dirs`) and
inside the guest (chroot), with the memory-clearing chain in between (see
[Isolation and Swap](isolation-and-swap.md)).

## 7. Key design decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Isolation tech | KVM microVM (sandvmm) | Hardware-level isolation, no containerd needed |
| Boot method | Initramfs cold boot | No snapshot needed; kernel VFS cache naturally consistent |
| Agent volume role | **is** the rootfs | All writes inside the chroot persist naturally |
| Hot-swap mechanism | mount/umount + virtio-fs `allowed_dirs` | bind-mount swap + VMM-level directory filter; set-fs ~0.20 ms |
| OverlayFS mode | Read-only overlay + writable `workspace/` · `home/` | No upperdir/workdir, so it works on any shared filesystem — NFS, CephFS, Cloud FS, or newer storage systems; lazy mount, stateless overlay |
| Volume storage | Local disk or shared (Cloud FS / NFS / CephFS / ...) | Sandswap only sees directories — the storage backend is replaceable; shared storage lets any node serve any SandFS |
| Agent identity | API key (Bearer) | Config-file injection, zero code changes |
| microVM reuse | Sticky lease + async clean | Same-agent reuse skips remount |
| sandlot connectivity | Outbound gRPC stream | No ports exposed on sandlot; NAT-friendly |
| VMM control | HTTP + raw frames over Unix socket | Direct control, no containerd/shim layer; binary frames for per-request hot ops |
| Background exec | Per-agent cgroup + async API | Long-running tools survive across calls; cgroup.kill on release |

## 8. Failure behavior

The tolerance-first model answers every component failure: ownership
does not move, agents get retryable 503s, and Sandswap switches only after
living participants confirm the old mount is released — the
[Resilience](resilience.md) page is the full story (timelines, takeovers,
self-fencing, and the both-dead manual backstops).

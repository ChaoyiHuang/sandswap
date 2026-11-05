---
title: Gateway
nav_order: 1
parent: Components
grand_parent: How It Works
---

# Gateway

## 1. Overview

The Gateway is the entry point of Sandswap: agents send every request here,
and it dispatches the work to a node over a gRPC stream. It owns identity
and ownership records, runs the VM pool scheduler, and touches neither
shared storage nor VMs directly. Source: `gateway/` (Go).

One binary, three modes (`-mode`): **single-node** (the empty default —
both halves in one process), **exec**, and **human**. Each mode is a
strict subset of the same code.

## 2. Key Responsibilities

### 2.1 Single-node mode (`-mode=""`, default)

The unified shape: everything below in one process, on one host. Agents
and operators both hit `:3000`; nodes dial `:9998`; the in-process
`MemoryStore` (mandatory-persistence snapshot) replaces etcd.

### 2.2 exec role (exec mode; the exec half of single-node)

The exec plane's gateway half — the hot path:

- **Authenticate and authorize**: resolve the API key to an Agent and its
  SandFS ids; check ownership on every request. Digest lookups keep this
  in memory. Agent-facing surface and schemas:
  [Agent API Reference](../../reference/agent-api.md) ·
  [Agent HTTP Integration](../../integration/agent-http.md) ·
  [MCP Tools](../../reference/mcp-tools.md).
- **Schedule and lease**: match a SandFS to a node's VM pool, enforce the
  sticky lease window, cap the pool at `PoolSize`, penalize crashed nodes.
- **Proxy the hot path**: `/agent/execute`, `/agent/file`, exec
  status/kill, agent discovery. One bidirectional stream per node;
  commands multiplex by `commandId`.
- **Fleet coordination**: health keys, ownership CAS and takeover, the
  etcd-partition self-fence (active unmount when etcd is unreachable),
  maintenance watch.
- **MCP instructions file**: serves the `sandswap_guide` tool and the
  initialize-time guide from `/etc/sandswap/mcp-instructions.md`
  (hot-reloaded by an event-driven file watcher, placeholder-rendered
  from the live timeout/window flags).
- Serve `:3000` (agent HTTP + MCP, 12 tools) and `:9998` (exec stream).
  No human endpoints.

### 2.3 human role (human mode; the human half of single-node)

The control plane's gateway half — manage SandFS identities and templates,
and route all sandfs/template storage work to the prov sandlot instances. Full
request/response schemas: [Human API](../../reference/human-api.md).

- **SandFS lifecycle CRUD**: create (template ref + mode required — flat or
  overlay; the template's declared minimum resources resolve to a VM spec,
  overridable at create time), cursor-paginated list, get with lifecycle
  status, delete. Delete is gated and ordered: `deleting` refuses work
  (409 `SANDFS_NOT_ACTIVE`) → bounded drain of mounts → overlay cleanup →
  volume + record + ownership release, synchronously.
- **Template swap** (overlay mode): `detach-template` (gate execs → drain →
  `detached`, 202 + status when the drain outlives `wait_sec`) →
  `attach-template` (rewrites the `.template` marker via the provision
  plane,
  home policy keep/archive/reset) → or one-shot `swap-template`. The
  status machine lives on the SandFS record.
- **Template management**: pull from an OCI registry, push, list, and
  delete — delete runs the two-layer in-use check (409
  `TEMPLATE_IN_USE` + count/sample) then garbage-collects unreferenced
  layers.
- **Route storage work**: every volume/template op is a ProvisionCommand
  sent to a prov sandlot. The Gateway itself mounts no storage, holds
  no registry egress, and carries no write grant; with no prov instance
  connected, ops are a named 503.
- **Fleet oversight**: the ownership alert scan (full sweep per pass), the
  manual reclamation tools (`reap-stuck`, `reap-stuck-node`), and the
  maintenance switch (`POST /human/maintenance` — published to etcd first,
  so it is cluster-wide and survives restarts; agent traffic answers 503
  `MAINTENANCE` + `Retry-After` while on).
- **Human authentication**: api-key or OIDC (Keycloak-class IdP); scopes
  `sandswap:human` (CRUD), `sandswap:admin` (credential minting),
  `sandswap:ops` (observability and reclamation), checked per route.
- Serve `:3100` (human HTTP) and a prov-only stream listener. The binary
  default is `:9998` — the same port the exec gateway's stream uses — so
  a **co-located** human gateway moves its prov listener to `:9996`
  (which the deploy scripts use throughout). On its own host, the default
  stands. No pool, no leases, no storage mounts.

### 2.4 Shared core (all modes)

- **Identity store**: one `identity.Store` interface hides the backend
  (`MemoryStore` single-node, `EtcdStore` distributed).
- **Stream server**: role gate on every connection — exec gateways take
  exec connections, human gateways take prov, unified takes both;
  violations get a named `HelloAck.reject_reason`.
- **Ops surfaces**: `/health`, `/stats`, `/metrics`; cursor-paginated
  fleet-wide list endpoints.

## 3. Interfaces / Data Flow

**Inputs:**

- Agent HTTP + MCP on `:3000` (exec / single-node): execute, file, exec
  status/kill, SandFS discovery — authenticated by agent api-key.
- Human HTTP on `:3000` (single-node) or `:3100` (human): SandFS CRUD,
  template ops (pull/push/save/delete, detach/attach/swap), ownership
  reaping, maintenance — authenticated by api-key or OIDC (scopes checked
  per route).
- The MCP instructions file (`/etc/sandswap/mcp-instructions.md`,
  event-driven hot-reload — exec / single-node modes, the MCP-serving
  ones).
- gRPC `NodeStream` from sandlot nodes on `:9998`. Nodes dial out; the
  Gateway never dials in. The hello negotiates roles, protocol version,
  and resilience timings.
- etcd (exec / human modes): ownership, health, presence, registry,
  maintenance keys.

**Outputs:**

- VMCommands over exec-node streams: create/destroy VM, mount+exec,
  unmount, status, kill, file ops (exec role).
- ProvisionCommands over prov connections: EnsureVolume, DeleteVolume,
  PullTemplate, PushTemplate, SaveAsTemplate, ListTemplates, StatTemplate
  (human role).
- HTTP/JSON answers; named 503s (`MAINTENANCE`, storage shed) with
  `Retry-After`; 202 + status responses for drain-backed ops (detach,
  attach, delete).
- etcd writes: ownership CAS, health refresh, presence grants, registry
  entries, the maintenance flag (exec / human modes).

```
Agent            Gateway              Sandlot(exec)       Warden
  │ POST /execute    │                     │                 │
  │─────────────────▶│ auth → agent+sandfs │                 │
  │                  │ ownership check     │                 │
  │                  │ lease / acquire VM  │                 │
  │                  │ VMCommand(mount+exec, commandId)      │
  │                  │────────────────────▶│ vsock RPC       │
  │                  │                     │────────────────▶│
  │                  │                     │  mount + exec   │
  │                  │◀────────────────────│ result          │
  │◀─────────────────│ JSON result         │                 │
```

The human role's data flow — the Gateway routes, never touches storage:

```
Operator          Gateway(human)      Sandlot(prov)        Shared storage
  │ POST /human/     │                   │                   │
  │    sandfs        │                   │                   │
  │─────────────────▶│ scope check       │                   │
  │                  │ lifecycle gate    │                   │
  │                  │ ProvisionCommand{EnsureVolume, commandId}
  │                  │──────────────────▶│ validate id/ref   │
  │                  │                   │ materialize ─────▶│ volumes/<sf-…>/
  │                  │◀──────────────────│ result            │
  │◀─────────────────│ record settled    │                   │
```

Drain-backed ops (detach/attach/delete) widen the middle: the Gateway sets
the gate status first, the drain unmounts the SandFS on every exec node
over the exec streams (or via etcd identity watch on split deployments),
and only then do the prov sandlot instances rewrite the marker or delete the
volume.

## 4. How It Processes

**exec role — a request:**

1. **Authenticate**: the API key resolves to an Agent (`auth_resolve`).
   Every per-SandFS endpoint requires `sandfs_id`; agents discover their
   ids via `GET /agent/sandfs`.
2. **Authorize**: the SandFS record must belong to the caller; else the same
   `404 "sandfs not found"` as an unknown id (tenant-census protection).
3. **Gate**: 503 `MAINTENANCE` while the switch is on; 503 shed when
   saturated.
4. **Route**: single-node mode uses the local pool. Distributed mode reads
   ownership: fresh owner → serve; dead owner → CAS takeover after the
   claim guard; stale-but-tolerable → reroute (DNS/307) or serve.
5. **Lease and acquire**: the sticky lease (default 100 ms) reuses the
   still-mounted VM for the same agent. `pool.Acquire` picks a CLEAN VM
   and caps VMs at `PoolSize`.
6. **Dispatch and relay**: send the VMCommand over the node's stream
   (up to 2000 concurrent commands, 16 MB FileOps), relay the result as
   the HTTP response.
7. **Background**: refresh the etcd health key, watch maintenance and
   ownership keys, run the maxHold reaper, collect unmount stats, and
   watch the MCP-instructions file (event-driven hot-reload).

**human role — a storage op:**

1. **Authenticate and authorize**: api-key or OIDC; the request's scope
   (`sandswap:human` / `sandswap:admin` / `sandswap:ops`) must cover the
   route.
2. **Gate**: check the record's lifecycle status first — `deleting` /
   `detaching` refuse work with 409 `SANDFS_NOT_ACTIVE`.
3. **Build the ProvisionCommand** and pick a prov sandlot instance
   (round-robin; transport-failure retry across instances; a named 503
   when none is connected).
4. **Await and settle**: write the result back to the record (and etcd in
   distributed mode). Ops that need a drain run the async path — set the
   gate status, drain the mounts everywhere, then settle: the response is
   202 + status when the drain outlives `wait_sec`; the attach re-points
   the `.template` marker via a prov sandlot and returns the
   record
   to active. Delete follows the same machinery with a bounded drain and
   a synchronous volume + record + ownership release.
5. **Background**: the ownership staleness alert scan runs here — a full
   ownership-prefix sweep per pass, warning about owners whose health went
   stale while they still own sandfs. (Exec gateways detect peer death
   per-request via the Claim path instead, so they run no scan.) The scan
   runs off the request path.

## 5. State & Storage

The Gateway is **stateful but reconstructable**. It mounts no shared
storage; the workspace on shared storage — written only by prov
instances — is the recovery anchor.

- **Persisted (both roles)**: identity records — hash-only credentials;
  the snapshot file in single-node mode (mandatory persistence), etcd in
  exec/human modes. Each gateway also self-registers its registry entry.
- **Persisted (exec role)**: ownership/placement keys and health keys.
- **Persisted (human role)**: the maintenance flag (etcd, cluster-wide)
  and the settled SandFS/template record status (written back over etcd on
  split deployments).
- **Memory-only (exec role)**: VM pool state, sticky leases, in-flight
  mount state, stream connections. Mount state is never in etcd —
  steady-state etcd writes are zero per execution cycle.
- **Memory-only (human role)**: the prov connection set, in-flight
  ProvisionCommands, and the drain state of detaching/deleting records.
- **On restart**: reload identity from the store, re-read etcd, rebuild
  pools as nodes reconnect (exec). A human gateway restart loses nothing —
  records and gate statuses are in etcd/the record store, and prov
  instances redial (human). No reconciliation protocol: every node
  reconnects with zero mounts (the connect-clean invariant).

Component configuration:
[Gateway configuration](../../operations/configuration/gateway.md).
Wire protocol: [Internal Protocols](../../reference/protocols.md).

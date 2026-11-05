---
title: Agent API Reference
nav_order: 2
parent: Reference
---

# Agent API Reference

Served on the agent listener (`:3000`). Authenticated per-request with the
agent API key. All request and response bodies are `application/json` unless
noted. The MCP transport shares this listener (`POST /mcp`).

Field names, types, defaults, and status codes below are taken directly from
the handler structs and route registration in `gateway/` — the code is the source
of truth. For integration guidance (connection handling, retry/abort
semantics, worked examples) see the [HTTP guide](../integration/agent-http.md)
and the [MCP server](../integration/agent-mcp.md); for the behavior behind the
503/307 codes see [Resilience](../how-it-works/resilience.md).

## Authentication and addressing

Every request carries the agent's API key in either header:

1. `Authorization: Bearer <key>` — primary path.
2. `X-Sandswap-Api-Key: <key>` — survives cross-host 307 redirects (some HTTP
   clients strip `Authorization` on cross-host redirect; the custom header does
   not, so ownership-redirected requests keep their key).

The key resolves to an **Agent**; the `sandfs_id` in the request body selects
the **SandFS** and the gateway verifies the agent owns it. `sandfs_id` is
REQUIRED on every per-sandfs endpoint (missing → `400`) — requests address
their sandbox explicitly (no single-sandfs auto-resolution). Discover yours
with `GET /agent/sandfs`. An unknown sandfs and one owned by another agent
are answered **identically** (`404`, same body) — never a distinct 403, so
a tenant cannot census other tenants' ids.

`GET /health`, `GET /ready`, and (in exec mode) `GET /stats` + `GET /metrics`
do not require the API key; everything else does.

## Endpoint index

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | [`/agent/execute`](#post-agentexecute) | Run code, sync or background. |
| `POST` | [`/agent/exec/status`](#post-agentexecstatus) | Poll a background exec. |
| `POST` | [`/agent/exec/kill`](#post-agentexeckill) | Kill a background exec. |
| `POST` | [`/agent/file`](#post-agentfile) | Unified file I/O (7 actions). |
| `GET` | [`/agent/sandfs`](#get-agentsandfs) | List the agent's SandFS instances. |
| `POST` | [`/mcp`](#post-mcp) | MCP Streamable HTTP transport. |
| `GET` | [`/health` and `/ready`](#health-and-readiness) | Liveness / readiness. |
| `GET` | [`/stats` and `/metrics`](#stats-and-metrics-exec-mode) | Cluster stats (exec mode only). |

## `POST /agent/execute`

Execute code in a SandFS sandbox (sync or background).

**Request body** (`ExecuteRequest`) — body limit **10 MB**:

| Field | Type | Required | Description |
|-------|------|:--------:|-------------|
| `sandfs_id` | string | yes | SandFS instance to execute in. |
| `code` | string | yes | Code/command to execute. |
| `language` | string | no | `python`/`python3`, `node`/`javascript`/`js`, `ruby`/`rb`, `shell`/`sh`/`bash`. Unknown/empty → passed through as a raw shell command. Non-shell languages are wrapped with their interpreter (`/bin/sh -c`). |
| `timeout` | int | no | Sync command timeout in seconds. `0`/omitted = gateway default (`-default-exec-timeout-sec`, 30). Values above `-max-exec-timeout-sec` (180, must sit strictly below the warden's countdown) are **clamped**, not rejected. Ignored for background execs. Must be `>= 0`; a negative value returns `400`. |
| `background` | bool | no | `true` = start as a background exec, return `exec_id` immediately. `false` (default) = block until completion/timeout. |
| `lease_duration` | int | no | Background only: the exec's **absolute run-time cap** in seconds (`0`/omitted = the configured `-max-background-lease-sec` cap, default 1 h). The VM is held for up to this long; status polls do **not** extend it. Validated on every request — negative or above-cap → `400` — but otherwise ignored for sync execs. See [Background exec lifecycle](#background-exec-lifecycle). |

**Response** (`ExecuteResponse`, `200`):

| Field | Type | Notes |
|-------|------|-------|
| `stdout` | string | Command stdout (sync); omitted when empty/background. |
| `stderr` | string | Command stderr (sync); omitted when empty/background. |
| `exit_code` | int | Always present. Meaningful when `status=done`: the real process exit code (0–255; 128+signum for signal death, e.g. 137 = SIGKILL). `0` for `timed_out` and background starts. |
| `exec_id` | string | Background only — use with `/agent/exec/status` and `/agent/exec/kill`. |
| `status` | string | Sync: `done` \| `timed_out`. Background: `running`. |
| `exec_duration_ns` | uint64 | Warden-side wall time: spawn→wait on the warm path; warden total (mount + exec) on a cold (cross-agent) execute. |
| `sandlot_duration_ns` | uint64 | Sandlot dispatch→response time (sync exec). |
| `gateway_duration_ns` | uint64 | Gateway end-to-end wall time. |

**Concurrency.** Sync commands on the same SandFS run **in parallel**, up to the
VM spec's `exec_slots` (the sandlot's per-VM warden connection-pool size:
small=3, medium=4, large=5 by default; an omitted/`0` `exec_slots` in a custom
spec means 1 = serial). Requests beyond the pool size queue FIFO at the
sandlot, in arrival order. Two implications agents must account for:

- **No completion-order guarantee**: concurrent sync commands may complete out
  of order, and their filesystem side effects race — `write file A → exec
  reading A` issued concurrently are unordered (identical to running the two in
  parallel local shells). Issue dependent steps as sequential calls.
- File I/O (`/agent/file`) shares the same pool and is parallel with execs — a
  burst of parallel file reads is served concurrently.

**Serialization points that remain:** a VM runs for at most **one SandFS at a
time** (exclusive ownership), and mount/unmount/switch are serialized per VM
(order-of-ms; the exec itself is not). The cold path (first command after a
mount/switch) still costs a single warden round-trip — mount and the real
command travel together — so cold latency is unchanged by parallelism.

Ops signals in `/stats` per node: `peak_concurrent_execs` (observed
parallelism), `slot_wait_ms` / `slot_wait_events` (requests that queued because
`exec_slots` was exhausted — the pool-sizing signal), `recycle_triggers`
(unmounts that destroyed the VM instead of returning it to CLEAN).

Response header `X-Sandbox-Lease: hit` is set when the warm/sticky path was
taken (same agent, within the sticky window).

**Status codes:** `200` success; `400` bad request (missing `sandfs_id`/`code`,
negative `timeout`/`lease_duration`, `lease_duration` above the cap, invalid
JSON); `401` missing/invalid API key; `404` sandfs not found **or owned by
another agent** (identical response by design); `409 SANDFS_NOT_ACTIVE` (the
sandfs is mid template-swap or deletion — retryable); `413` body > 10 MB, or
the wrapped command exceeds the single-op wire cap (see
[size limits](#request-size-limits--timeouts); over MCP this carries
`error_code: EXEC_TOO_LARGE`); `502` RPC-level failure; `503` resilience error
(retryable — see [Error model](#error-model)); `307` ownership redirect (see
[Redirects](#redirects-307)).

```bash
GW=${GW:-https://sandswap.local:3000}
KEY=${KEY:-sk-sandswap-agent-…}
SF=${SF:-sandfs-8e4f2a91}
EXEC=${EXEC:-bg-exec-…}

curl -sS -X POST "$GW/agent/execute" \
  -H "Authorization: Bearer $KEY" -H "X-Sandswap-Api-Key: $KEY" \
  -H 'Content-Type: application/json' \
  -d '{"sandfs_id":"'$SF'","code":"echo hello","language":"shell"}'
```

```json
{"stdout":"hello\n","exit_code":0,"status":"done",
 "exec_duration_ns":412000,"sandlot_duration_ns":995000,"gateway_duration_ns":1120000}
```

## `POST /agent/exec/status`

Poll a background exec's liveness + captured log tail. Does **not** extend the
exec's lease. Exec status and kill deliberately skip the sandfs lifecycle gate:
mid-swap they answer `expired` once the drain clears the in-guest processes.

**Request body** (`ExecStatusRequest`) — body limit **1 MB**:

| Field | Type | Required | Description |
|-------|------|:--------:|-------------|
| `sandfs_id` | string | yes | SandFS instance. |
| `exec_id` | string | yes | Background exec ID from `/agent/execute`. |

**Response** (`ExecStatusResponse`, `200`):

| Field | Type | Notes |
|-------|------|-------|
| `status` | string | `running` \| `done` \| `killed` \| `not_found` \| `expired`. |
| `exit_code` | int | Serialized only when non-zero; meaningful when `status=done`. |
| `stdout` | string | Captured log tail. |
| `stderr` | string | Captured stderr tail. |

`expired` means no gateway holds the lease and no healthy owner exists — stop
polling. `not_found` means the exec was lost (node failure / cleanup) —
re-create it with a new `execute(background:true)`; do **not** retry the status
poll on that `exec_id`.

**Status codes:** `200`; `400` missing `sandfs_id`/`exec_id` or invalid JSON;
`401`; `404` sandfs not found or owned by another agent; `413` body > 1 MB;
`500` unexpected handler/RPC error; `503`/`307` as above.

```bash
curl -sS -X POST "$GW/agent/exec/status" \
  -H "Authorization: Bearer $KEY" -H "X-Sandswap-Api-Key: $KEY" \
  -H 'Content-Type: application/json' \
  -d '{"sandfs_id":"'$SF'","exec_id":"'$EXEC'"}'
```

## `POST /agent/exec/kill`

Kill a background exec by `exec_id` (SIGKILL the whole process group).

**Request body** (`ExecKillRequest`, body limit **1 MB**): same fields as
`ExecStatusRequest` (`sandfs_id`, `exec_id`, both required).

**Response** (`200`): `{ "status": "killed" | "not_found" | "expired" }` —
`not_found` means no such exec (idempotent: killing an already-finished exec
is a success, not an error).

**Status codes:** `200`; `400` missing fields or invalid JSON; `401`; `404`;
`413` body > 1 MB; `500`; `503`/`307` as above.

```bash
curl -sS -X POST "$GW/agent/exec/kill" \
  -H "Authorization: Bearer $KEY" -H "X-Sandswap-Api-Key: $KEY" \
  -H 'Content-Type: application/json' \
  -d '{"sandfs_id":"'$SF'","exec_id":"'$EXEC'"}'
```

## Background exec lifecycle

A background exec (`background: true`) returns an `exec_id` immediately and runs
in the VM. The VM is released (unmounted) when **any** of these occurs:

1. **Poll observes completion** — a `/agent/exec/status` returning `done` (or
   `not_found`) marks the exec finished; if no other background exec or in-flight
   sync exec holds the VM, it is released (after the 100 ms sync sticky window).
2. **Kill** — `/agent/exec/kill` marks the exec finished and releases likewise.
3. **`lease_duration` elapses** — the exec's absolute run-time cap. The VM is
   unmounted; unmount's `cgroup.kill` clears the still-running expired task.

`lease_duration` is an **absolute cap**, not an idle window: status polls do not
extend it. If a poll observes the exec still `running`, the lease is untouched.

**Overlap with other tasks on the same SandFS:**

- **Multiple background execs**: each has its own `lease_duration` deadline. When
  exec A's deadline elapses but exec B is still active, A is marked finished but
  the VM is **not** released (B holds it). The VM releases only when the last
  background exec finishes. The expired exec A keeps running in the guest until
  the VM is eventually released (its `cgroup.kill` clears A and B together) or
  the agent kills A.
- **Sync exec / file op during a background exec**: an in-flight sync exec or
  file op holds the VM (it cannot be released while the RPC is in progress), but
  it does **not** extend any background exec's deadline. A sync exec that
  completes arms a 100 ms sticky window, but an active background exec still
  dominates the hold.

This guarantees a background task runs at most `lease_duration` (unless another
task on the same SandFS keeps the VM alive longer), and the VM is reclaimed
promptly once nothing holds it.

## `POST /agent/file`

Unified file I/O — a single endpoint dispatching on the `action` field (7 ops).
Paths are resolved relative to the sandbox workspace (`/workspace` inside the
chroot); a leading `/` is trimmed and the path re-based onto the workspace —
the file API never sees the sandbox root (`/`). Read root-level files via
`/agent/execute` instead.

A single read or write carries at most the single-op wire cap
(**16 MiB − 64 KiB**; the warden's single-op cap is 16 MiB and the envelope
needs 64 KiB of gRPC headroom). Binary writes use `data_base64`, which inflates
~33%, so the HTTP body limit for this endpoint is **50 MB** (a 16 MB binary
write still fits).

**Request body** (`FileRequest`) — body limit **50 MB**:

| Field | Type | Required | Description |
|-------|------|:--------:|-------------|
| `sandfs_id` | string | yes | SandFS instance. |
| `action` | string | yes | `read` \| `write` \| `stat` \| `list_dir` \| `mkdir` \| `remove` \| `rename`. |
| `path` | string | yes* | Relative to the workspace; at most 4095 bytes (PATH_MAX−1), else `413 FILE_PATH_TOO_LONG`. *Required for all actions except `rename` (which requires both `path` and `new_path`). |
| `new_path` | string | rename | Destination path (same 4095-byte bound). |
| `data` | string | write | Text content (UTF-8). Mutually exclusive with `data_base64`. Empty/omitted = write an empty file (or truncate). |
| `data_base64` | string | write | Base64-encoded binary content (non-UTF-8 safe). Invalid base64 → `400`. |
| `offset` | *int64 | read/write | Byte offset. For write: `-1` (or `append:true`) = append, `>0` = sparse write (capped at `warden.max_file_read_bytes`, default 16 MB, so one op cannot mint an arbitrarily large apparent file), `0`/omitted = overwrite from the start. For read: start offset. |
| `length` | *int64 | read | Max bytes to read (`0`/omitted = to EOF, capped at the single-op wire cap). Values above the cap → `413`. |
| `append` | bool | write | Append mode (sets offset = -1). |
| `mode` | uint32 | write/mkdir | Permissions (`0` = default: `0644` for files, `0755` for directories), applied only when the file/directory is newly created; existing files keep their mode. |
| `recursive` | bool | remove | `rm -rf`. Bounded by the warden: max tree depth **200** and **65,536 entries** per call. A deeper/wider tree returns a named app-level error (`remove depth exceeds …` / `remove budget exceeded …`) instead of failing silently — the call is safe to re-issue (partial progress persists, idempotent continuation); bulk cleanup beyond the bounds belongs on `/agent/execute` (`rm -rf` in-guest), which holds no warden-side lock. |
| `depth` | uint32 | list_dir | Recursion depth (`0` = flat). Clamped to 64 by the warden. |

**Response** (`FileResponse`, `200`) — fields present depend on `action`:

| Field | Type | When |
|-------|------|------|
| `ok` | bool | `write`/`mkdir`/`remove`/`rename` success. |
| `data` | string | `read` of UTF-8 content. |
| `data_base64` | string | `read` of non-UTF-8 content. |
| `is_text` | *bool | `read` only — `true`/`false` (omitted for non-read ops). |
| `size` | int64 | `read`/`write` byte count (omitted when 0). |
| `entries` | array | `list_dir` — JSON array of entries, wrapped in `{"entries":[...]}`. Bounded by the same byte budget as a `read` and a hard 16,384-entry cap; a larger listing stops there and ends with one marker entry `{"name":"[truncated]","path":"[truncated]","file_type":"truncated","size":<entries returned>,"mode":0}`. |

**`stat` response** — `action=stat` returns the warden's entry JSON unchanged
(the gateway does not parse or rewrap it). Fields: `name`, `path`, `file_type`
(`file` \| `dir` \| `symlink`), `size` (bytes), `mode`, `modified_time`
(omitted when unavailable). The warden serializes this; it may evolve with
warden versions.

**Status codes:** `200`; `400` (missing `sandfs_id`/`action`/`path`, unknown
action, both `data` and `data_base64` set, invalid base64, or a warden
application-level error like file-not-found/permission-denied — the VM is **not**
released on these); `401`; `404` sandfs not found or owned by another agent
(identical response); `413` body > 50 MB, a read `length` / write payload
above the single-op wire cap (over MCP this carries
`error_code: FILE_TOO_LARGE`), or a path above PATH_MAX−1
(`FILE_PATH_TOO_LONG`); `500` unexpected handler/RPC error;
`503`/`307` as above.

```bash
curl -sS -X POST "$GW/agent/file" \
  -H "Authorization: Bearer $KEY" -H "X-Sandswap-Api-Key: $KEY" \
  -H 'Content-Type: application/json' \
  -d '{"sandfs_id":"'$SF'","action":"write","path":"notes.txt","data":"hello\n"}'

curl -sS -X POST "$GW/agent/file" \
  -H "Authorization: Bearer $KEY" -H "X-Sandswap-Api-Key: $KEY" \
  -H 'Content-Type: application/json' \
  -d '{"sandfs_id":"'$SF'","action":"read","path":"notes.txt"}'
```

## `GET /agent/sandfs`

List the authenticated agent's SandFS instances (metadata only — never reads
sandbox files).

**Addressing**: this call carries no `sandfs_id`, so it cannot use the
per-sandfs domain — reach it via the shared agent domain
(`https://sandswap.local:3000/agent/sandfs`) or any exec gateway address.
Any exec gateway answers: the identity store is etcd-backed and cluster-wide,
so the list is identical wherever the call lands (single-node mode: the
gateway's own address).

**Response** (`200`):

| Field | Type | Notes |
|-------|------|-------|
| `sandfs_list` | array | The agent's SandFS instances. |
| `sandfs_list[].sandfs_id` | string | Opaque id (`sandfs-…`). |
| `sandfs_list[].name` | string | Display name. |
| `sandfs_list[].description` | string | Operator-set description. |
| `sandfs_list[].template` | string | Template ref (omitted when empty). |
| `sandfs_list[].created_at` | string | RFC 3339 timestamp. |
| `sandfs_list[].status` | string | Lifecycle state (omitted when active: `""`). |

`status` is the lifecycle state (`""` = active). A non-empty value means the
sandbox is mid template-swap or deletion: execs and file ops are refused with
a retryable `409 SANDFS_NOT_ACTIVE` — back off and retry (the state is
transient; the operator's swap settles in seconds unless a long exec is
draining). Status/kill keep working and resolve to `expired` once the swap's
drain clears in-guest processes.

**Status codes:** `200`; `401` missing/invalid API key; `405` non-GET.

```bash
curl -sS "$GW/agent/sandfs" \
  -H "Authorization: Bearer $KEY" -H "X-Sandswap-Api-Key: $KEY"
```

## `POST /mcp`

MCP (Model Context Protocol) Streamable HTTP transport. The same API key
authenticates every request; `sandfs_id` in the tool arguments selects the
sandbox. The transport is **stateless**: there is no session, no
`Mcp-Session-Id`, and `initialize` is optional (it is still answered, echoing
the client's requested protocol version, for older clients). Methods:
`initialize`, `tools/list`, `tools/call`, `ping`. The method may travel in the
JSON-RPC body or in the `Mcp-Method` header (`Mcp-Name` supplies a `tools/call`
name when `params` is absent).

The 12 tools and their argument sets are in the [MCP Tools Reference](mcp-tools.md).

**Request body** — JSON-RPC 2.0, body limit **50 MB** (aligned with
`/agent/file`).

**Response** — a JSON-RPC response with HTTP `200` for every case except the
two transport-level outcomes below. `tools/list` responses carry
`Cache-Control: private, max-age=60` (the list is static per agent).

- **Ownership redirect**: a `tools/call` whose sandfs is owned by a healthy,
  routable other gateway answers `307` to that gateway's `/mcp`, with
  `X-Sandswap-Redirected: 1`. A request that already carries the header is
  never redirected again — it gets a JSON-RPC error `-32001` ("ownership
  conflict").
- **Voluntary load shed**: a raw `503` with `Retry-After` and
  `Connection: close`, no JSON-RPC body (the client must close and re-resolve
  DNS, as on the HTTP endpoints).

**JSON-RPC error codes:**

| Code | Meaning |
|------|---------|
| `-32700` | parse error |
| `-32600` | method not allowed (non-POST) / request body too large (> 50 MB) |
| `-32601` | method not found |
| `-32602` | invalid params |
| `-32001` | missing/invalid API key; also the stdio-transport encoding of an ownership redirect / ownership conflict and of a load-shed signal (the HTTP transport answers those with a `307` / raw `503`) |

Tool-level failures (sandbox unavailable, file not found, oversized payload, …)
are not JSON-RPC errors: they return a `tools/call` result with
`isError: true` and a text payload. Resilience failures serialize
`{error, error_code, retryable, retry_after_ms}`; named client refusals
(`FILE_TOO_LARGE`, `EXEC_TOO_LARGE`) carry
`{error, error_code, http_status, retryable: false}`.

```bash
curl -sS "$GW/mcp" \
  -H "Authorization: Bearer $KEY" -H "X-Sandswap-Api-Key: $KEY" \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

## Health and readiness

| Method | Path | Auth | Response |
|--------|------|------|----------|
| `GET` | `/health` | none | `200 {"status":"ok"}`. |
| `GET` | `/ready` | none | `200 {"status":"ready"}` once the identity snapshot (and, in distributed modes, ownership recovery) is loaded; otherwise `503 {"status":"not_ready"}`. Single-node always `ready`. |

Use `/ready` as a Kubernetes readinessProbe and `/health` as the livenessProbe.
While an exec-mode gateway is still loading its identity snapshot, every
non-liveness route answers `503` with
`{"error":"identity cache warming up","retry_after_sec":2}` and
`Retry-After: 2` (see [Error model](#error-model)).

```bash
curl -sS "$GW/health"
curl -sS "$GW/ready"
```

## Stats and metrics (exec mode)

In `-mode exec` the gateway has no human listener, so `GET /stats` and
`GET /metrics` ride the agent listener, gated by `-ops-token-file` (a bearer
token; without the flag both endpoints are disabled). The exec
`/stats` projection blanks per-tenant identifiers (`sandfs_id` and command
excerpts in `top_slow`) from every gateway's unmount stats; aggregate counters
and latencies remain. In single-node mode both endpoints live on the human
listener instead (see the [Human API Reference](human-api.md#get-stats--cluster-statistics)).

| Method | Path | Response |
|--------|------|----------|
| `GET` | `/stats` | The cluster `StatsReport` — same schema as the human listener's `/stats`. |
| `GET` / `HEAD` | `/metrics` | Prometheus text (`text/plain; version=0.0.4; charset=utf-8`), the same report projected. |

`/stats` answers `200`; `/metrics` answers `405` for methods other than
`GET`/`HEAD`.

```bash
curl -sS "$GW/stats"
curl -sS "$GW/metrics" | head
```

---

## Error model

### Resilience errors (retryable `503`, or `409` for the lifecycle gate)

When the sandbox is transiently unavailable, the gateway returns a JSON body
and a `Retry-After` header:

```json
{
  "error": "unmount in progress, retry",
  "error_code": "UNMOUNT_IN_PROGRESS",
  "retryable": true,
  "retry_after_ms": 1000
}
```

**`retry_after_ms` is a suggested poll interval, not a recovery deadline.** The
agent's only obligation is to re-issue the request (against its DNS-resolved
gateway) at roughly that cadence. Safety is never the client's concern:
server-side ownership guarantees no gateway mounts the sandfs before the
confirmed-condition switch completes (see [Resilience](../how-it-works/resilience.md)),
so polling earlier is merely wasteful — and manually trying other gateway
addresses gains nothing, because DNS and the 307 redirect always converge back
on the owner.

Two recovery classes sit behind these codes:

- **Local transients** (`UNMOUNT_IN_PROGRESS`, `CONCURRENT_MOUNT`,
  `NO_AVAILABLE_SANDBOX`, `SANDBOX_CLEANING`): resolved by the serving gateway
  in milliseconds to seconds — the next poll normally succeeds.
- **Resilience-clock bounded** (`OWNER_NODE_DOWN`, `OWNERSHIP_CONFLICT` marked
  ◐ below; also `NO_COMPUTE_NODES`, `OWNER_NO_COMPUTE`): most incidents in this
  class are seconds-level blips recovered by the next poll or two — that is why
  the poll interval stays short. If the failure persists, recovery is governed
  by the timing model (see [Resilience](../how-it-works/resilience.md)): the stale
  mount is released by the warden countdown at `T_tolerance + T_warden`
  (defaults 5 min + 5 min), ownership becomes releasable at
  `T_safe = T_tolerance + T_warden + 60 s` (default ≈11 min), and cross-gateway
  takeover additionally requires sandlot migration completed at `T_isolation`
  (default ≈12 min). Until then every gateway answers 503 — keep polling at
  `retry_after_ms`; do not hop addresses.

  Because one node/gateway failure 503s all its sandfs agents at the same
  instant, this class carries **±25% server-side jitter** on `retry_after_ms`
  so literal clients do not retry in synchronized waves. Clients SHOULD add
  their own random jitter on top and MAY back off progressively (e.g. double
  the interval up to ~60 s) after several consecutive identical 503s — the
  short base interval exists to catch seconds-level reconnects, not to require
  fixed-cadence polling through a full outage.

| `error_code` | HTTP | Meaning | `retry_after_ms` |
|--------------|------|---------|------------------|
| `SANDFS_NOT_ACTIVE` | 409 | SandFS mid template-swap or deletion (lifecycle gate) — wait for the operator's swap to settle, then retry. | 1000 |
| `SANDBOX_CLEANING` | 503 | SandFS in CLEANING state after a failure. | 10000 |
| `UNMOUNT_IN_PROGRESS` | 503 | A switch/unmount is in flight (dual-mount guard). | 1000 |
| `CONCURRENT_MOUNT` | 503 | Another cold mount for this sandfs is in progress. | 1000 |
| `NO_AVAILABLE_SANDBOX` | 503 | Over-subscribed node — retry (which re-routes to another node). | 1000 |
| `NO_COMPUTE_NODES` | 503 | No sandlot nodes connected. | 10000 (jittered) |
| `OWNER_NODE_DOWN` ◐ | 503 | Owner node down, takeover pending — may persist up to T_safe (≈11 min default) unless the node reconnects sooner. | 10000 (jittered) |
| `OWNER_NO_COMPUTE` | 503 | Owner has no compute capacity. | 10000 (jittered) |
| `OWNERSHIP_CONFLICT` ◐ | 503 | Another gateway owns the sandfs and no takeover condition is confirmed (only when that owner is unhealthy/unroutable — a healthy owner yields a 307 instead); takeover needs the owner dead AND the sandlot migrated here (≥ T_isolation) or the node's presence key gone. | 10000 (jittered) |
| `OWNERSHIP_LOST` | 503 | Ownership changed while a cold mount was being waited out (dispatch guard) — retry to re-resolve the owner. | 1000 (jittered) |
| `MOUNT_CONFLICT` | 503 | The cold mount this gateway just established lost the ownership race (the dispatch generation moved, or another node already holds the recorded mount). The duplicate mount was torn down; retry to re-resolve. | 1000 (jittered) |
| `NODE_UNAVAILABLE` | 503 | Node temporarily unreachable (stream transport error) — the command never reached the sandlot and the sandfs is **not** marked dirty. | 500 |
| `SHED_REBALANCE` | 503 | Voluntary load shed — ownership released. Raw transport response (no JSON body). | `shed-retry-after-sec`×1000 |
| `FILE_PATH_TOO_LONG` | 413 | A file path (`path`/`new_path`) exceeds PATH_MAX−1 (4095 bytes). Refused before the node stream is touched. | — |
| `MAINTENANCE` | 503 | The gateway is refusing agent traffic during a maintenance window. `Retry-After: 30`; a plain JSON body `{error, error_code}` (no `retryable`/`retry_after_ms` fields). | — |

The 409 lifecycle refusal is emitted with the same
`{error,error_code,retryable,retry_after_ms}` shape as the 503s.

### Redirects (307)

When the request's sandfs is owned by a **healthy, routable** other gateway, the
gateway returns `307 Temporary Redirect` to the owner's URL (original path+query
appended) with header `X-Sandswap-Redirected: 1`. 307 preserves method + body +
headers, so the replayed request arrives intact at the owner. A request that
already carries `X-Sandswap-Redirected: 1` is **never** redirected again
(anti-loop) — it gets a `503` instead. Applies to `/agent/execute`,
`/agent/file`, `/agent/exec/status`, `/agent/exec/kill`, and `/mcp`.

"Healthy, routable" uses the health-key staleness signal: an owner whose
`last_healthy_ts` is stale past `-route-stale-sec`
(default 20 s) is treated as **not routable** — no 307 is issued to it, and the
request falls to a `503` + retry (the client re-resolves DNS, which routes a
mounted sandfs to the gateway currently holding the node, or a new/unowned one
to a healthy gateway). This prevents a 307 from bouncing a request at a dead
owner.

### Voluntary load shed (`SHED_REBALANCE`)

When `-enable-load-shed` is on (the default) and the gateway is
sustained-saturated with an idle peer, it releases the sandfs's ownership and
returns a **raw transport-level `503`** + `Retry-After` + `Connection: close`
(no JSON body, not an MCP `isError` result). The client must close the
connection and re-resolve the sandfs DNS name so sandns routes it to
the peer. Disable with `-enable-load-shed=false`.

### Warming-up and maintenance refusals

Two gateway-level refusals happen before a handler runs:

- **Identity warming up** (exec/human modes): `503`,
  `{"error":"identity cache warming up","retry_after_sec":2}`,
  `Retry-After: 2`. `/health` and `/ready` are exempt.
- **Maintenance window**: `503`, `{"error": "...", "error_code": "MAINTENANCE"}`,
  `Retry-After: 30`. `/health`, `/ready`, `/stats`, and `/metrics` are exempt.

### Plain JSON errors

Non-resilience errors return `{"error": "<message>"}` with the appropriate
status (`400`, `401`, `404`, `405`, `413`, `500`, `502`).

---

## Request size limits & timeouts (summary)

| Endpoint | Body limit | Notes |
|----------|-----------|-------|
| `POST /agent/execute` | 10 MB | `code` payload. |
| `POST /agent/exec/status`, `/agent/exec/kill` | 1 MB | Small JSON; oversize returns `413`. |
| `POST /agent/file` | 50 MB | Single read/write content capped at 16 MiB − 64 KiB (the wire cap under the 16 MiB gRPC message limit); 50 MB body accommodates base64 inflation of a 16 MB binary write. |
| `POST /mcp` | 50 MB | JSON-RPC envelope; aligned with `/agent/file` so `file_write` can carry 16 MB binary content. |
| `GET /agent/sandfs` | — | No body expected. |
| Sync exec timeout | default 30 s, max 180 s (must stay < warden countdown 300 s) | `-default-exec-timeout-sec` / `-max-exec-timeout-sec`; agent `timeout` is clamped to max; negative `timeout` returns `400`. |
| Background lease | default cap 1 h | `lease_duration` = background exec absolute run-time cap (`0` = the configured `-max-background-lease-sec` cap); status polls do not extend it; above-cap / negative returns `400`. |
| Sticky lease | 100 ms, max 5 s | `-sticky-ms` / `-max-sticky-sec`. |
| Listener timeouts | read 30 s; write `-max-exec-timeout-sec` + 30 s | Keep-alive idle timeout `-idle-timeout` (default 1 h). |

---
title: Agent HTTP Integration
nav_order: 4
parent: Integration
---

# Agent HTTP Integration

How to connect an agent (or any client program) to Sandswap over plain
HTTP/JSON. The complete per-endpoint reference — field tables, status
codes, error codes, size limits — is the
[Agent API Reference](../reference/agent-api.md); if your framework speaks
MCP, see [Agent MCP Integration](agent-mcp.md) instead (same semantics,
one-to-one).

## 1. The model in five sentences

1. You get an **API key** (an operator creates your agent via the human API
   / `sandctl api agent create`; the key is returned exactly once).
2. You get one or more **SandFS instances** — persistent sandboxes, each
   created with a template and a volume mode.
3. Every request carries your key and addresses **exactly one SandFS** by
   its `sandfs_id` — there is no implicit "current sandbox".
4. Commands execute inside that SandFS's KVM microVM; stdout/stderr/exit
   code come back, and **everything the command wrote persists** in the
   SandFS for the next call.
5. Calls are plain HTTP/JSON or MCP tools — no SDK required, no agent-code
   changes beyond calling a tool backend.

## 2. Quickstart

```bash
GW=https://sandswap.local:3000          # agent listener
KEY=sk-sandswap-agent-…
SF=sandfs-8e4f2a91                      # from your operator, or GET /agent/sandfs

# Discover your SandFS instances (no sandfs_id needed for this one):
curl -sS "$GW/agent/sandfs" \
  -H "Authorization: Bearer $KEY" -H "X-Sandswap-Api-Key: $KEY"

# Execute a command (sync):
curl -sS -X POST "$GW/agent/execute" \
  -H "Authorization: Bearer $KEY" -H "X-Sandswap-Api-Key: $KEY" \
  -H 'Content-Type: application/json' \
  -d '{"sandfs_id":"'$SF'","code":"echo hello > hi.txt && cat hi.txt","language":"shell"}'
```

```json
{"stdout":"hello\n","exit_code":0,"status":"done",
 "exec_duration_ns":412000,"sandlot_duration_ns":995000,"gateway_duration_ns":1120000}
```

```bash
# The file persisted — read it back through the file API:
curl -sS -X POST "$GW/agent/file" \
  -H "Authorization: Bearer $KEY" -H "X-Sandswap-Api-Key: $KEY" \
  -H 'Content-Type: application/json' \
  -d '{"sandfs_id":"'$SF'","action":"read","path":"hi.txt"}'
```

```json
{"data":"hello\n","is_text":true,"size":6}
```

Full field tables for `POST /agent/execute`, `/agent/file`,
`/agent/exec/status`, `/agent/exec/kill`, and `GET /agent/sandfs` are the
[Agent API Reference](../reference/agent-api.md).

## 3. Authentication & addressing

Per-request API key, accepted in either header:

- `Authorization: Bearer <key>` — the primary path.
- `X-Sandswap-Api-Key: <key>` — **also send this one**: it survives
  cross-host 307 redirects (many HTTP clients, Go's included, strip
  `Authorization` when a redirect crosses hosts; the custom header does
  not), so an ownership-redirected request still authenticates at the owner
  gateway.

The key resolves to exactly one agent; the gateway verifies that agent owns
the addressed `sandfs_id`. An unknown id and one owned by another agent are
answered **identically** (`404`, same body) — never a distinct 403.
`sandfs_id` is required on every per-sandfs endpoint (missing → `400`) —
treat it as stable addressing: store it once at provisioning time, pass it
on every call. Discover your instances with `GET /agent/sandfs` (or
`list_sandfs` over MCP); the call carries no `sandfs_id` itself, so it goes
to any exec gateway address — the identity store is cluster-wide and the
answer is the same wherever it lands.

## 4. The life of a request

```
client ── POST /agent/execute (or MCP tool) ──▶ gateway
   auth: api_key → agent; owns sandfs_id? (else 404)
   claim: this gateway owns the sandfs? (else 307 to the owner / 503 retry)
   lease: sticky window? warm path : cold mount
   exec:  one command to the node → microVM → warden
◀── stdout / stderr / exit_code / *_duration_ns ──
   (background:true ⇒ returns exec_id immediately instead)
```

- **Warm path** (gateway P95 < 1 ms bare metal): your previous call was
  moments ago — the VM is still mounted; the command executes directly.
- **Cold/switch path** (gateway P95 ≈ 2.3 ms bare metal, ≈ 7.5 ms nested
  virtualization): the VM must (re)mount your SandFS first — still a single
  round trip, mount and exec travel together. Figures and per-stage
  breakdowns: [the benchmark chapter](../benchmark/baremetal.md).
- **Release** (0 ms to you): unmount and cleanup happen in the background
  after the sticky lease expires.

Response fields `gateway_duration_ns` / `sandlot_duration_ns` /
`exec_duration_ns` give per-stage timing on every sync exec, and the
`X-Sandbox-Lease: hit` header tells you which path served the call.

## 5. Hold one persistent connection

The per-call latency floor is set by connection setup, not the command: a
fresh TCP+TLS handshake rivals or exceeds the warm-path latency on a LAN
and dominates it on a WAN. Hold **one persistent connection** for the
process lifetime — HTTP/1.1 keep-alive, or (with `-agent-tls-cert` on the
listener) one HTTP/2 connection via ALPN multiplexing everything.

- **Create one HTTP client (one connection pool) per agent process** and
  reuse it for every request, concurrent ones included.
- **Disable the client-side idle timeout** (`IdleConnTimeout: 0` in Go) and
  let the gateway's `-idle-timeout` (default 3600 s) govern — it exists
  precisely to cover agent think-time between tool calls.
- **Size the idle pool for your concurrency**: Go's default
  `MaxIdleConnsPerHost` is 2, Python's `HTTPConnectionPool` 10 — a burst
  wider than the pool opens connections that get torn down afterward
  instead of reused.
- Keep **TCP keepalive probes** on the dialer (detects half-open peers,
  keeps NAT/LB mappings alive — note probes do not reset the gateway's idle
  timer; only a real request does).
- **No short overall client timeout** — sync execs legitimately run up to
  180 s. Bound individual requests with a per-request context.
- The connection doubles as the **affinity anchor**: while it stays open,
  your requests keep hitting the same gateway and its warm VMs. If
  something on the path would idle it out (a positive gateway idle timeout,
  an LB/NAT limit), send a cheap unauthenticated `GET /health` heartbeat
  under the shortest such timeout — minutes-scale cadence, not seconds.
- On `503` + `Connection: close` (a voluntary load shed): close, re-resolve
  DNS, reconnect — that is the intended rebalance path. Reconnecting costs
  exactly one handshake and no client reconnect logic: the API is stateless
  per request.

A runnable demonstration — one shared client, `httptrace` proof of
connection reuse, per-request timing, forced-reconnect recipes — lives in
[`examples/keepalive-sandswap`](https://github.com/ChaoyiHuang/sandswap/tree/main/examples/keepalive-sandswap).

## 6. Sync vs background execution

- **Sync** (default): blocks until completion or timeout (request `timeout`,
  default 30 s, capped at 180 s). Pass an explicit `timeout` when you know
  the command's scale; the server clamps it. Use for everything short-lived.
- **Background** (`background: true`): returns an `exec_id` immediately; the
  command keeps running in the VM. Poll with `POST /agent/exec/status`
  (status + captured log tails), kill with `POST /agent/exec/kill`.
  `lease_duration` is the **absolute** run-time cap — polling never extends
  it, and expiry kills the process group. Use for builds, training runs,
  servers; operators raise `-max-background-lease-sec` for genuinely long
  jobs. Your client's per-request deadline should exceed the exec `timeout`
  (leave room for transport + retries).

Full semantics: [Background exec lifecycle](../reference/agent-api.md#background-exec-lifecycle)
in the reference.

## 7. Design for the abort contract

The platform guarantees the **workspace survives every failure and
recovery**. In-flight commands keep running inside the microVM through a
gateway outage (the node holds the mount for a grace window, default
300 s), and are aborted when the mount is released. Recovery deliberately
clears state rather than reconstructing it:

- An error, timeout, or lost connection means the **result is UNKNOWN**, not
  "failed" — the command may well have completed. Do not blindly retry
  side-effectful commands.
- Make side effects **idempotent or checkpointed** (temp file + rename,
  progress markers, append-only action logs).
- Delivery is **at-least-once under transport loss** — a command that did
  run may run again; the idempotency rule is what makes that safe.
- After any abort, **read the workspace first**, then resume or roll back.
- `exec_id` handles may stop resolving after a recovery; a failed status
  query does not mean the work never ran.
- `exec_id` handles also stop resolving across a **template swap** or sandfs
  deletion (a retryable `409 SANDFS_NOT_ACTIVE` gates new work meanwhile):
  the drain that quiesces the volume clears in-guest processes, and status
  polls resolve to `expired`. Treat it like a recovery — read the workspace
  (it carried over), then re-issue work.

## 8. Retry correctly: cadence, not address-hopping

- A retryable `503` carries `retry_after_ms` — a **suggested poll
  interval**, not a recovery deadline. Re-issue at roughly that cadence.
- **Do not try other gateway addresses.** DNS and the 307 redirect converge
  on the owner; manual hopping gains nothing and fights the ownership
  machinery.
- Add your own jitter on top (the server already adds ±25% on the
  resilience-clock class), and back off progressively (e.g. doubling up to
  ~60 s) after several consecutive identical 503s. Persistent 503s during a
  node failure are expected for up to ~11–12 minutes, then resolve by
  themselves — see [Resilience](../how-it-works/resilience.md). The full
  code table is the [error model](../reference/agent-api.md#error-model).
- `not_found` from a background status poll means the handle is gone —
  re-create the task; `expired` means nothing holds the lease — stop
  polling.

## 9. Expect concurrency, not ordering

Sync commands and file ops on the same SandFS run in parallel (up to the
VM spec's `exec_slots`; FIFO queueing beyond). Concurrent calls may complete
out of order and their filesystem effects race — issue dependent steps as
sequential calls. A burst of parallel `file_read`s is fine and served
concurrently.

## 10. Worked examples

- **[examples/openai-sandswap](https://github.com/ChaoyiHuang/sandswap/tree/main/examples/openai-sandswap)**
  — official OpenAI SDKs, no framework; drives the gateway as a function
  tool backend (HTTP and MCP modes), including a benchmark mode.
- **[examples/eino-sandswap](https://github.com/ChaoyiHuang/sandswap/tree/main/examples/eino-sandswap)**
  — a CloudWeGo Eino framework agent: MCP tool discovery, code execution,
  file operations, and hot-switching between two agents sharing one pool.
- **[examples/keepalive-sandswap](https://github.com/ChaoyiHuang/sandswap/tree/main/examples/keepalive-sandswap)**
  — the connection-optimized client: stdlib only, `httptrace` proof of
  reuse, `-loop` mode demonstrating the full reconnect lifecycle.
- **[examples/mcp-sandswap](https://github.com/ChaoyiHuang/sandswap/tree/main/examples/mcp-sandswap)**
  — the minimal MCP client loop (see [Agent MCP Integration](agent-mcp.md)).

## 11. Checklist

- One connection pool per process, reused forever.
- Both auth headers on every request.
- `sandfs_id` stored once; address explicitly rather than re-discovering.
- Sync for short work with an explicit `timeout`; background + `lease_duration`
  for anything long.
- Idempotent side effects; read the workspace after any failure.
- Retry at `retry_after_ms` cadence with your own jitter; never hop addresses.
- Don't poll status faster than needed; prefer one `list_dir`/`stat` over N
  blind reads.

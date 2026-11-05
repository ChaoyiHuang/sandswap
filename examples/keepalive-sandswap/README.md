# Sandswap Keep-Alive Example

A minimal (stdlib-only, zero dependencies) Go program that demonstrates the
single most effective client-side latency optimization for the Sandswap agent
HTTP API: **hold one persistent HTTP connection for the process lifetime and
run every command over it**, instead of paying TCP connect + TLS handshake on
every call.

Background and the full client guidance live in
[`docs/integration/agent-http.md`](../../docs/integration/agent-http.md) →
*Use a persistent connection (HTTP keep-alive)*. In short: the gateway's
agent listener keeps an idle connection open for `-idle-timeout` (default
**3600 s**) precisely so an agent that pauses between tool calls reuses the
same connection — and the same gateway's warm VMs — for the whole session.

## What it shows

The program creates **one** `http.Client` (one connection pool) with the four
settings that matter:

| Setting | Value | Why |
|---------|-------|-----|
| `IdleConnTimeout` | `0` | Client never closes an idle connection; the gateway's 3600 s `IdleTimeout` governs. Go's default transport would drop it after 90 s idle — mid think-time. |
| `MaxIdleConnsPerHost` | `-pool` (default 8) | How many idle connections are *kept* for reuse. Go's default is **2**, so anything beyond 2 parallel requests gets torn down after the burst. |
| `DialContext` | `net.Dialer{KeepAlive: 30s}` | TCP keepalive probes: detect a half-open connection (peer vanished without FIN/RST) and keep NAT/LB port mappings alive. Note: probes do **not** reset the gateway's idle timer — only a real HTTP request does (that is the heartbeat's job, below). |
| `ForceAttemptHTTP2` | `true` | Over TLS, negotiate HTTP/2 via ALPN so concurrent requests multiplex over one connection. |

It then uses `httptrace` to prove the reuse per request:

1. `GET /health` — the **only** dial + TLS handshake of the run (reported as
   `conn=NEW` with the `dial`/`tls` cost).
2. N sequential `POST /agent/execute` — every one reported as `conn=reused`;
   the total drops to the round-trip floor.
3. One concurrent burst — HTTP/1.1 dials one extra connection per in-flight
   request (all visible in the trace); HTTP/2 multiplexes them over the one
   connection. Either way `-pool` decides how many survive for the next call.

Every request carries both `Authorization: Bearer <key>` and
`X-Sandswap-Api-Key: <key>` — the custom header survives the cross-host `307`
ownership redirect (Go strips `Authorization` on cross-host redirects), so a
redirected request authenticates at the owner gateway.

The client deliberately sets **no** overall `http.Client.Timeout`: a sync exec
may legitimately run up to `-max-exec-timeout-sec` (180 s). Individual requests
are bounded with a context instead.

## Long-lived session: heartbeat + auto-reconnect (`-loop`)

Can the connection stay up forever, and reconnect if it breaks? Yes — with one
gateway knob and one client habit, and **no explicit reconnect logic**:

**Gateway side — one knob:**

- `-idle-timeout` (default **3600 s**) is the only knob governing connection
  lifetime: it is how long an idle connection is kept before the server closes
  it. Raise it to comfortably exceed the agent's longest think-time (e.g.
  `-idle-timeout 86400` = 24 h), or set it to **`-1`** to never close idle
  connections server-side — the connection then lives until the client, TCP
  keepalive, an LB/NAT intermediary, or a restart ends it (values below `-1`
  are rejected at startup). Do **not** set 0 — Go then falls back to the 30 s
  `ReadTimeout` (the gateway warns at startup).
- Three events still close a connection regardless, all by design and none
  losing state: a voluntary load-shed (`503` + `Connection: close` — it wants
  you to re-resolve DNS), a gateway restart (graceful drain ≤ 30 s), and any
  LB/NAT idle timeout on the path (size it ≥ think-time, or heartbeat under
  it). A `307` ownership redirect doesn't close anything — the request just
  moves to the owner gateway's connection.

**Client side — the recipe this example implements:**

1. **One shared client** with `IdleConnTimeout: 0` and a TCP-keepalive dialer
   (see table above).
2. **Heartbeat** (`-ping`): a ticker sending an unauthenticated,
   side-effect-free `GET /health`. It is only needed when something on the
   path would close the connection for idleness — keep the interval **below
   the shortest idle timeout on the path**:
   - gateway `-idle-timeout` positive: heartbeat below it (or below an
     LB/NAT idle timeout, whichever is shorter), or the connection dies
     mid-think-time and the next command pays a handshake.
   - gateway `-idle-timeout -1` **and** a direct connection (no LB/NAT):
     nothing closes the connection for idleness — `-ping 0` is perfectly
     fine. The heartbeat then has one optional leftover use: noticing a
     break within seconds instead of at the next command (which reconnects
     anyway, so this is convenience, not correctness).
   The seconds-scale defaults are demo compression so a short run shows the
   mechanism; in production the cadence is minutes (e.g. half the shortest
   path idle timeout, or half your think-time).
3. **Let the transport reconnect.** HTTP transports redial transparently on
   the next request — there is no session state to rebuild: auth headers ride
   on *every* request. A broken connection costs exactly one handshake, then
   everything is warm again.
4. **Retry policy per the abort contract** (docs/integration/agent-http.md): idempotent
   commands (reads, `/health`) can simply be reissued; a failed side-effectful
   exec has an **unknown** result — read the workspace first, don't blindly
   re-run.

**Recipes to watch each behavior** (all verified against a stub gateway):

```bash
# Baseline: think-time gaps, one connection for the whole run
go run . -loop -addr https://gw:3000 -api-key $KEY -sandfs-id $SFS -think 5s -for 60s

# Force the break: gateway -idle-timeout 5, demo -think 7s -ping 0
# → every command after a 7s gap shows conn=NEW (idle-expired; auto-redialed)
go run . -loop ... -think 7s -for 22s -ping 0

# Heal it: add -ping 2s → the heartbeat resets the idle timer, one connection
go run . -loop ... -think 7s -for 22s -ping 2s

# Restart the gateway mid-loop → ping/exec FAIL while it's down, then the
# first request after it returns shows conn=NEW and everything is warm again.
```

Sample output from the restart scenario (`-think 3s -ping 2s`, gateway killed
at t≈7 s, back at t≈11 s; captured against a local stub gateway):

```
    6.0s  ping  GET /health  conn=reused (idle timer reset)
    6.0s  cmd #3   total=  1.64ms gateway=  1.90ms sandlot=  1.40ms exec=  0.90ms conn=reused lease=hit exit=0 out="keep-alive demo"
    8.0s  ping  GET /health  FAIL: ... connection refused — transport redials on the next request
    9.0s  cmd #4   FAIL: ... connection refused
   10.0s  ping  GET /health  FAIL: ... connection refused — transport redials on the next request
   12.0s  ping  GET /health  conn=NEW     (reconnected — one handshake re-paid, warm again)
   12.0s  cmd #5   total=  1.75ms gateway=  1.90ms sandlot=  1.40ms exec=  0.90ms conn=reused lease=hit exit=0 out="keep-alive demo"

[loop] done: 16 requests, 2 connection(s) dialed, 11 handshake(s) avoided, 3 failure(s)
[loop] a conn=NEW line above is the auto-reconnect — nothing else needed; the API is stateless per request.
```

No reconnect code anywhere in the demo — the shared transport does it. The
heartbeat's only job is to make the break *rare* and *noticed early*.

## Prerequisites

- A reachable gateway (`:3000`) and an agent API key.
- A SandFS instance owned by that agent (discover with `GET /agent/sandfs`,
  create via `POST /human/sandfs`).

## Run

```bash
# One-shot demo (connection reuse proof):
go run . -addr https://gateway:3000 \
         -api-key sk-sandswap-agent-... \
         -sandfs-id sandfs-xxx \
         [-ca ca.pem]        # self-signed gateway cert (env SANDSWAP_CA_CERT)
         [-runs 5]           # sequential executes after the connection is open
         [-burst 4]          # concurrent executes in the final burst
         [-pool 8]           # MaxIdleConnsPerHost

# Long-lived-session demo (heartbeat + auto-reconnect):
go run . -loop -addr https://gateway:3000 -api-key ... -sandfs-id ... \
         [-think 5s]         # pause between commands (agent think-time)
         [-for 60s]          # total demo duration
         [-ping 30s]         # GET /health heartbeat; set BELOW gateway -idle-timeout
         [-pool 8] [-ca ca.pem]
```

Every flag falls back to the env vars the other examples use:
`SANDSWAP_GATEWAY_URL` / `SANDSWAP_API_KEY` / `SANDSWAP_SANDFS_ID` /
`SANDSWAP_CA_CERT`. Plain-HTTP gateways work too (`http://...` — HTTP/1.1
keep-alive, no ALPN).

## Sample output

Numbers below come from a **local stub gateway** (fixed fake timings, no real
sandlot/microVM) — the shape is what matters. For real measured end-to-end
figures see `docs/benchmark/baremetal.md` (bare-metal warm P50 ≈ 0.7 ms).

```
Sandswap keep-alive demo
  gateway   : https://gateway:3000
  sandfs    : sandfs-abc
  transport : keep-alive (IdleConnTimeout=0, MaxIdleConnsPerHost=8)
  timings   : total = client total: request sent -> response received (whole chain)
              gateway = gateway end-to-end (includes sandlot); sandlot (includes exec); exec = inside the microVM (warden)

[1] GET /health — opens THE connection (dial + handshake, once)
  200 OK  total=  4.21ms  dial=  1.02ms  tls=  2.87ms  proto=HTTP/2.0  conn=NEW

[2] 5 sequential POST /agent/execute — all reuse that connection
  #1  200  total=  3.85ms  gateway=  1.90ms  sandlot=  1.40ms  exec=  0.90ms  conn=reused  lease=hit  exit=0  out="keep-alive demo"
  ...

[3] burst of 4 concurrent executes — pool sizing in action
  #1  200  total=  2.30ms  gateway=  1.90ms  sandlot=  1.40ms  exec=  0.90ms  conn=reused  lease=hit  exit=0
  ...

One client, one warm pool: no dial/TLS after step [1] unless the burst exceeded -pool.
```

**How to read the timings.** `total` is the client-side total: from handing
the request to the transport until the full response body has been read — the
network in both directions plus the entire internal chain. The other three are
the response's own measurement fields, and each one nests inside the previous:
`gateway ⊇ sandlot ⊇ exec`.

```
total  (what the client waits for)
├── client ↔ gateway network — TCP+TLS handshake on the FIRST request only;
│   afterwards just 1 RTT each way (this is the part connection reuse saves)
└── gateway end-to-end (gateway_duration_ns) — auth, lease, dispatch, and
    waiting for the sandlot's reply
    └── sandlot dispatch→response (sandlot_duration_ns) — VM lookup,
        dispatch, waiting for the warden's reply
        └── exec: warden spawn + run INSIDE the microVM (exec_duration_ns)
```

Every command traverses the whole chain — client → gateway → sandlot → vsock
→ warden → microVM → back — so the internal three layers run identically
whether the connection was reused or freshly dialed; reuse only shrinks the
top branch of the tree.

`lease=hit` (`X-Sandbox-Lease` response header) appears on a real gateway when
the command rode the warm/sticky VM path — the second half of the latency
story: a persistent connection keeps you on the gateway, and the sticky lease
keeps the VM mounted.

## Other languages, same recipe

- **Python**: module-level `requests.Session()` (or `httpx.Client`), and pass
  `HTTPAdapter(pool_connections=..., pool_maxsize=N)` when you exceed ~10
  parallel requests.
- **Node**: global `fetch`/undici pools keep-alive by default; avoid creating a
  new `Agent`/client per call and size `connections` to your parallelism.
- **curl per command**: pays the handshake every time — fine for probing, not
  for an agent loop.

---
title: Gateway
nav_order: 1
parent: Configuration
grand_parent: Operations
---

# Gateway Configuration

> Sources: `gateway/config/config.go` (YAML structure, defaults, reload classification) + `gateway/cmd/main.go` (CLI flags) + `gateway/app/` (mode wiring, hot-reload targets).
> Two entry points: `-config <yaml>` loads a config file; any CLI flag passed explicitly overrides the YAML value (only flags actually set on the command line are applied).
>
> **Time units**: all `*_sec` values are seconds; `sticky_ms` is milliseconds; window sizes are MB. Each table below states the unit explicitly.
>
> **Hot-reload vs restart**: a config-file change is applied live (hot-reload) or logged as "requires restart" (restart-required), per the `classifyField` summary at the bottom. CLI flags always take effect at process start regardless of class.


**Mode applicability.** Which sections matter for which `-mode`. `single-node`
is the empty default (one process, MemoryStore); `exec` and `human` are the
two cluster roles. A knob outside a mode's list is accepted but inert there.

| Section | single-node | exec | human |
|---|---|---|---|
| §1 Run mode / top level | ○ | ○ | ○ (per-row, see table) |
| §2 Identity + connection lifecycle | ○ | ○ | ○ |
| §3 Listeners | ○ (per-row) | ○ (per-row) | ○ (per-row) |
| §4 Stream transport | ○ | ○ | ○ |
| §5 Lease / Exec (agent path) | ○ | ○ | — |
| §6 Unmount stats | ○ | ○ | — |
| §7 Storage plane deadline | ○ | ○ | ○ |
| §8 Authn (human endpoints) | ○ | — | ○ |
| §9 Sched (placement) | ○ | ○ | — |
| §10 Shed (load shedding) | ○ (no peers → inert) | ○ | — |
| §11 Selfload gate | — | ○ | — |
| §12 Staleness thresholds | — (no etcd) | ○ | ○ |
| §13 Etcd-partition self-fence | — | ○ (mount-bearing) | ○ (health publish only) |
| §14 Identity store loading | — | ○ | ○ |
| §15 Single-node identity store | ○ | — | — |
| §16 Go runtime GC pacing | ○ | ○ | ○ |
| §17 MCP instructions file | ○ | ○ | — |
| §18 Logging / §19 Reload summary | ○ | ○ | ○ |

---

## 1. Run mode / top level
**Scope:** all modes; the per-row Modes column says which knob applies where.

**Background.** A gateway can run as a self-contained single process (single-node, in-memory state) or as one role in a distributed cluster backed by etcd: the *exec* gateway serves agents and owns sandfs; the *human* gateway is the control plane (SandFS CRUD, templates, ownership ops). Everything else in this file hangs off which mode you pick and where the shared etcd lives.

| CLI flag | YAML key | Default | What it does / why this default | Modes |
|---|---|---|---|---|
| `-config` | — | "" | Path to the YAML config file (optional). Explicit CLI flags override YAML values. | all |
| `-version` | — | — | Print the version (version / commit / build time, ldflags-stamped by `build/build.sh`) and exit. | all |
| `-mode` | `mode` | "" (single-node) | `""` = single-node (all-in-one, MemoryStore, no etcd); `human` = the human gateway (control plane) on `:3100`; `exec` = the exec gateway (`:3000` + `:9998`). Empty by default so a bare `gateway` binary just works; production clusters set `human`/`exec` explicitly per process. | n/a (this flag selects) |
| `-vol-root` | `vol_root` | `/var/sandswap/volumes` | Root of the shared volumes tree. Every SandFS volume lives under this, so all gateways/nodes must agree on it (typically a shared filesystem mount). | all |
| `-tombstone-ttl-sec` | — (CLI only) | 604800 (7 days) | How long a deleted SandFS id is remembered so a 32-bit id redraw cannot resurrect a stale name. Values below 1s are refused. Applies to both stores (the etcd tombstone lease and the memory snapshot). Restart-required. | all |
| `-identity-store` | `identity_store` | `<parent of vol_root>/identity-store.json` (the deployer sets `<parent of vol_root>/state/identity-store.json`) | Single-node identity store file: agents and SandFS records survive gateway restarts (see §15). Persistence is MANDATORY in single-node (MemoryStore) mode — an explicit empty value refuses to start. Single-node mode only — `human`/`exec` keep identity in etcd and ignore it. Restart-required; a corrupt snapshot, an unknown snapshot version, or a file locked by another gateway refuses the start. The deploy tooling keeps the store in the private `state/` subdirectory (0700, gateway identity): the state ROOT is root-owned 0755 because it may carry the guest TCB — a service identity must not be able to rename entries there. | single-node |
| `-etcd` | `etcd` | "" | etcd endpoints, **required** in `human`/`exec` mode (e.g. `https://etcd:2379`). Empty = single-node in-memory mode. | human + exec (required there) |
| `-etcd-ca` | `etcd_ca` | "" | CA bundle for etcd TLS. Set when etcd serves HTTPS. | human + exec |
| `-etcd-cert` | `etcd_cert` | "" | Client certificate for etcd mTLS — required when etcd runs `--client-cert-auth` (the k8s default). | human + exec |
| `-etcd-key` | `etcd_key` | "" | Client private key matching `etcd_cert`. | human + exec |
| `-allow-insecure-etcd` | `allow_insecure_etcd` | false | **Dev/test only.** Permit a non-loopback etcd endpoint without TLS. Default false: a non-loopback plaintext endpoint is cluster control (ownership/placement keys) reachable from the network, so startup refuses unless this flag (or YAML key) is set explicitly. Prefer `https://` or the `etcd_ca`/`etcd_cert`/`etcd_key` trio. | human + exec |

## 2. Identity + connection lifecycle
**Scope:** all modes. `gateway-url` / `gateway-stream-addr` only matter where routability matters (exec; optional in single-node).

**Background.** In a cluster, each gateway needs a stable identity so etcd records (ownership, health, routing addresses) survive process restarts, and a published address so peers (DNS, sandlot, other gateways) can find it. A connection from an agent is also the *affinity anchor*: while it stays open, the agent's requests keep hitting the same gateway and reuse its warm VMs.

| CLI flag | YAML key | Default | What it does / why this default | Modes |
|---|---|---|---|---|
| `-gateway-id` | `gateway_id` | "" (derived from hostname) | Stable identity: keys in etcd are namespaced by it. Deriving from the hostname works on bare metal; k8s injects the pod name so a rescheduled pod keeps its identity. | all |
| `-gateway-url` | `gateway_url` | "" | Routing address published to `/sandswap/gateway/{id}` (target of 307 redirects and owner-aware DNS answers). Empty = alive but not routable (acceptable for a human gateway, wrong for exec).  exec (optional single-node) | exec (optional single-node) |
| `-gateway-stream-addr` | `gateway_stream_addr` | "" | The sandlot-facing stream address (`:9998`), also published in the registry — it is how a sandlot knows where to reconnect.  exec | exec |
| `-idle-timeout` | `idle_timeout_sec` | 3600 | HTTP keep-alive idle timeout (seconds). A connection *is* the affinity anchor, so this should comfortably cover agent think-time between tool calls (1h default). `-1` = never close idle connections server-side — the connection then lives until the client, TCP keepalive, an intermediary (LB/NAT), or a restart ends it. Values below `-1` are rejected at startup (a `-3600` is a dropped sign, not an intent). Never set it to 0 (Go's http.Server falls back to the 30 s ReadTimeout; the gateway warns at startup). Restart-required. | all |

## 3. Listeners (agent / human / stream) — restart-required
**Scope:** per-row — `agent.*` serves the agent API (single-node, exec); `human.*` serves the control plane (single-node, human); `stream.*` serves sandlot connections (all three; prov-only in human mode).

**Background.** Each mode exposes different listeners; TLS material is loaded once at bind time, so certificate changes need a restart.

| CLI flag | YAML key | Default | Modes |
|---|---|---|---|
| `-agent-addr` | `agent.addr` | `:3000` | single-node, exec |
| `-agent-tls-cert` | `agent.tls_cert` | "" | single-node, exec |
| `-agent-tls-key` | `agent.tls_key` | "" | single-node, exec |
| `-agent-tls-ca` | `agent.tls_ca` | "" | single-node, exec |
| `-human-addr` | `human.addr` | `:3100` | single-node, human |
| `-human-tls-cert` | `human.tls_cert` | "" | single-node, human |
| `-human-tls-key` | `human.tls_key` | "" | single-node, human |
| `-human-tls-ca` | `human.tls_ca` | "" | single-node, human |
| `-stream-addr` | `stream.addr` | `:9998` | all (prov-only in human mode) |
| `-stream-tls-cert` | `stream.tls_cert` | "" | all (prov-only in human mode) |
| `-stream-tls-key` | `stream.tls_key` | "" | all (prov-only in human mode) |
| `-stream-tls-ca` | `stream.tls_ca` | "" | all (prov-only in human mode) |

`agent.*` = the agent-facing HTTP API; `human.*` = control-plane HTTP; `stream.*` = the gRPC bidirectional stream that sandlot nodes dial. A CA on `agent`/`stream` enables mTLS from clients. On the stream listener a client certificate is always required (the node-identity gate binds its CN to `NodeHello.node_id`): `-stream-tls-ca` makes it verified mTLS, and a listener started without `-stream-tls-cert/-key` (plaintext) refuses every node stream by name.

## 4. Stream concurrency / transport — restart-required
**Scope:** all modes (exec streams carry VM commands; human streams carry provision commands).

**Background.** Every sandlot↔gateway connection is ONE gRPC bidi stream multiplexing all VM commands by `commandId`. These knobs size that pipe: how many in-flight commands it absorbs (send buffer), how long a write may block (write timeout), and how much data HTTP/2 flow control lets move concurrently (windows) and per message (max message size). Defaults serve 2000 concurrent commands and 16 MB FileOp payloads. Deployment rule: gateway `-stream-send-buffer` ≥ sandlot `-max-concurrent-commands` (both 2000), and the 16 MB cap must hold end-to-end (warden limits + base64 headroom on the 50 MB HTTP body limit).

| CLI flag | YAML key | Default | Unit |
|---|---|---|---|
| `-stream-send-buffer` | `stream_concurrency.send_buffer_size` | 2000 | commands. **Minimum 1**  all (prov-only in human mode) |
| `-stream-write-timeout-sec` | `stream_concurrency.write_timeout_sec` | 30 | seconds. **Minimum 1**  all (prov-only in human mode) |
| `-stream-initial-window-mb` | `stream_concurrency.initial_window` | 64 | MB (per stream; ~4 concurrent 16 MB FileOps). **Minimum 1**  all (prov-only in human mode) |
| `-stream-conn-window-mb` | `stream_concurrency.initial_conn_window` | 128 | MB (per connection). **Minimum 1**  all (prov-only in human mode) |
| `-stream-max-msg-size-mb` | `stream_concurrency.max_msg_size` | 16 | MB. **Minimum 16** (the FileOp chain floor)  all (prov-only in human mode) |

> All five are validated at startup (restart-required knobs — no hot-reload case): every cap `>= 1`, the windows within int32 range (the gRPC option's type), `initial_window >= max_msg_size` (a max-size message must fit the per-stream window), `initial_conn_window >= initial_window`, and `max_msg_size >= 16 MB` (the FileOp chain floor, `common/config.ValidateStreamCaps` — shared with sandlot). Out-of-range values are rejected at startup — never silently substituted or overflowed.

## 5. Lease / Exec — hot-reload
**Scope:** single-node and exec — the agent execution path. Human gateways serve no agent traffic.

**Background.** The sticky lease is the "same agent's next call reuses its warm VM" window: after a VM is released it stays reserved for the agent for `sticky_ms`, capped by `max_sticky_sec` so a burst of idle VMs cannot accumulate. Exec timeouts bound sync exec calls; the background-lease cap bounds how long an async exec may keep its VM.

| CLI flag | YAML key | Default | Unit |
|---|---|---|---|
| `-sticky-ms` | `lease.sticky_ms` | 100 | milliseconds. **Minimum 1** — 0 and negative values are rejected at startup and refused on hot-reload (the previous value is kept) |
| `-max-sticky-sec` | `lease.max_sticky_sec` | 5 | seconds. **Minimum 1** — lower values silently disable the maxHold reaper safety net, so they are rejected the same way |
| `-default-exec-timeout-sec` | `exec.default_timeout_sec` | 30 | seconds. **Minimum 1** |
| `-max-exec-timeout-sec` | `exec.max_timeout_sec` | 180 | seconds. **Minimum 1, and >= `default_timeout_sec`** — out-of-range values are rejected at startup and refused on hot-reload (the old silent normalization — max<default becoming the default — is gone). Must also stay **strictly below** the warden countdown (default 300 s) so a max-length sync exec always finishes (and sends its response) before the warden's countdown can fire — the countdown must only ever trip a cleanup overrun, never a legal long exec. And it must satisfy the **T_safe headroom** `5 s (health tick) + max_exec_timeout + 30 s (node heartbeat) < T_safe` (660 s with the contract defaults): enforced at startup (the gateway refuses to start), on hot-reload (the value is refused and the old one kept) and against every node's reported `T_safe` at connect (a node whose timing cannot hold the configured max exec is rejected) — a maximum-length exec must not still hold its mount when the presence key expires |
| `-max-background-lease-sec` | `exec.max_background_lease_sec` | 3600 (1h) | seconds |

> **Why `sticky_ms` cannot be 0.** Concurrent sync commands are safe through two independent layers: commands whose RPCs overlap in time are held by the lease's in-flight refcount (window-independent), while commands arriving shortly *after* a previous one completed are bridged by the window-refresh chain — every arrival rewrites the release boundary to `now + sticky_ms`. With a 0 window, every refresh writes an instantly-stale boundary, so any command arriving right after a completion triggers an unmount + cold-remount instead of joining the warm VM. 1 ms is the minimum at which the refresh mechanism functions; a larger window is a pure latency/VM-hold trade-off (how gappy an arrival pattern still gets warm hits).

> `-max-background-lease-sec` is the absolute run-time cap on a background exec's `lease_duration` (seconds): polling does NOT extend it — at expiry the VM is unmounted (`cgroup.kill` cleans up the background process). 1h is a conservative floor; deployments running long async jobs (model training, long builds) should raise it (e.g. `86400` = 24h, `259200` = 72h). A request whose `lease_duration` exceeds the cap gets `400`.

## 6. Unmount stats — hot-reload
**Scope:** single-node and exec — only modes that hold mounts record unmounts.

**Background.** To see switch/unmount performance in production, the gateway keeps a **fixed-footprint** per-node unmount stats collector: per node it tracks mount/unmount/success/fail counts, unmounts under 5ms and 10ms, and the top-10 slowest unmounts (three latency tiers + that sandfs's last cold-mount command + reason). Everything runs on async paths (post-response on cold mount / lease expiry / failure cleanup / delete), so warm-exec latency is unaffected.

| CLI flag | YAML key | Default | Unit |
|---|---|---|---|
| `-unmount-stats-persist-sec` | `unmount_stats.persist_interval_sec` | 600 (10min) | seconds |

> **Hot-reload**: edit the YAML and the persist ticker picks up the new interval at the next tick — no restart. The snapshot is persisted asynchronously each interval to etcd `/sandswap/unmount-stats/{gatewayID}` (plain key, no lease) for `/stats` peer aggregation + offline ops. On restart the gateway overwrites its own key (counters restart at 0); a permanently retired gateway leaves an orphan key for ops to `etcdctl del` (same policy as `/sandswap/gateway/`). Single-node mode is memory-only. A node's entry is cleared when it disconnects and re-accumulates from 0 on reconnect. sandns never reads unmount data.

## 7. Storage plane — the gateway has none
**Scope:** all modes — every mode relays storage ops (single-node in-process).

**Background.** The gateway mounts no shared storage and holds no registry
credentials: every sandfs/template operation (`EnsureVolume`, `DeleteVolume`,
pull/push/save/list/stat) is a `ProvisionCommand` over the node stream to a
prov sandlot instance (see
[Sandlot — roles (exec / prov)](sandlot.md#11-roles-exec--prov--restart-required)).
Template store paths, the OCI registry, and its credentials are configured on
the PROV instance, not here.

| CLI flag | YAML key | Default | Modes |
|---|---|---|---|
| `-storage-op-deadline-sec` | `storage_op_deadline_sec` | 300 — bounds one storage op on the executing prov instance (template pulls can move GBs) | all |

The API surface is unchanged: `/human/templates*` and `/human/sandfs` relay to
the storage plane; while no prov instance is connected they return a named
503 ("storage plane unavailable") instead of a partial result.

## 8. Authn (OIDC for human endpoints) — restart-required
**Scope:** single-node and human — wherever human endpoints are served.

**Background.** Human-API endpoints can sit behind OIDC; the provider handle and JWKS refresh loop are initialized once at startup. An empty issuer does **not** silently mean "no auth": a human listener with no `authn.issuer` **refuses to start** unless the operator opts out explicitly with `-allow-anonymous-human` (`authn.allow_anonymous`), which still logs a Warn naming the full blast radius. The anonymous listener is additionally restricted to a **loopback** bind; exposing it on a LAN/ClusterIP address requires the second explicit acknowledgement `-allow-anonymous-human-public` (`authn.allow_anonymous_public`). Silence is never the way a control plane goes unauthenticated.

> **Production MUST use OIDC or mTLS. Anonymous mode is development/test only
> and must never be used in production.** The anonymous opt-out exists so a
> developer can run a local stack; it grants every human/ops/admin endpoint to
> any caller that can reach the listener. Production binds the human listener
> to the management network or an independent netns, with `authn.issuer`
> (OIDC) or mTLS.

| CLI flag | YAML key | Default | Modes |
|---|---|---|---|
| `-authn-issuer` | `authn.issuer` | "" (empty ⇒ human listener refuses to start) | single-node, human |
| `-allow-anonymous-human` | `authn.allow_anonymous` | false (explicit opt-out required to run unauthenticated) | single-node, human |
| `-allow-anonymous-human-public` | `authn.allow_anonymous_public` | false (anonymous listener binds loopback-only) | single-node, human |
| `-authn-client-id` | `authn.client_id` | "" | single-node, human |
| `-authn-jwks-refresh-sec` | `authn.jwks_refresh_sec` | 3600 (seconds) | single-node, human |
| `-authn-mtls-trust-cert` | `authn.mtls_trust_cert` | false | single-node, human |
| `-authn-scope-human` | `authn.scope_human` | `sandswap:human` | single-node, human |

**Ops endpoints on the exec-mode agent listener** (`/stats`, `/metrics`) are never served unauthenticated. CLI-only, no YAML key (restart-required; the token FILE's content hot-reloads on mtime change — rotation is a file write):

| CLI flag | Default | Semantics |
|---|---|---|
| `-ops-token-file` | "" (endpoints disabled: 404) | Root-owned file (0600, ≤256 bytes, non-empty — validated at startup) holding the bearer token. Requests without `Authorization: Bearer <token>` get 401. The agent API key is deliberately NOT accepted here: it is a tenant identity, and these are fleet-wide ops views. Single-node/human modes keep their OIDC/mTLS gate and ignore this flag. A file that becomes EMPTY after startup fails closed (401s) until a valid token returns — rotation by truncate-then-write keeps the closed window exactly as long as the file is broken. Prometheus `scrape_config` supports `bearer_token` natively. |
| `-authn-scope-admin` | `authn.scope_admin` | `sandswap:admin` | single-node, human |
| `-authn-scope-ops` | `authn.scope_ops` | `sandswap:ops` | single-node, human |

**Namespace claim** (no gateway flag — the claim name is fixed at
`sandswap_ns`): the multivalued OIDC claim granting control-plane
namespaces. Provisioning is IdP-side only — Keycloak needs the
`sandswap_ns` client scope with one multivalued user-attribute mapper
(`user.attribute` = `claim name` = `sandswap_ns`, `multivalued=true`,
`access.token.claim=true`); the working recipe is Phase 1 of
`e2e/oidc-keycloak.sh`. Grants: `["acme"]` = that namespace via
`/human/ns/acme/…`; `["*"]` = fleet (unscoped surface + every namespace);
absent = denied on both. An mTLS client certificate is accepted only when it
carries an explicit operator role URI SAN (`sandswap://role/ops`,
`sandswap://role/admin` or `sandswap://role/human`); a CA-verified
certificate without one is refused (401), because the human CA may also sign
certificates for other purposes. With an OIDC provider configured the marker
maps exactly: `role/admin` = fleet surface (human+admin+ops, namespace `*`),
`role/ops` = ops, `role/human` = human only (namespaces from
`sandswap://ns/<name>`). On an mTLS-only deployment (no OIDC) any operator
marker keeps the legacy full grant. Operator certificates must be minted
with the URI SAN matching the intended surface.
Conceptual model: [Namespaces](../../how-it-works/namespaces.md).

## 9. Sched (node placement) — hot-reload
**Scope:** single-node and exec — only modes that place VMs.

**Background.** When a request needs a VM, the gateway picks which sandlot node gets it. `binpack` packs work onto fewer nodes (so idle ones can be drained/scaled away); `spread` minimizes per-node contention. The weighted scorer tunes the trade-off, and the hard caps stop placement onto an overloaded host. Weight `0` = use the built-in default shown in the table; all values hot-reload so you can re-tune placement under live load.

| CLI flag | YAML key | Default | Unit |
|---|---|---|---|
| `-sched-policy` | `sched.policy` | binpack | binpack \| spread |
| `-sched-w-load` | `sched.w_load` | 0 (built-in 0.6) | weight |
| `-sched-w-host` | `sched.w_host` | 0 (built-in 0.3) | weight |
| `-sched-w-clean` | `sched.w_clean` | 0 (built-in 0.1) | weight |
| `-sched-w-daily` | `sched.w_daily` | 0 (built-in 0.2) | weight |
| `-sched-w-risk` | `sched.w_risk` | 0 (built-in 0.15) | weight |
| `-sched-host-cpu-hard` | `sched.host_cpu_hard` | 0 (disabled) | fraction 0–1 |
| `-sched-duty-hard` | `sched.duty_hard` | 0 (disabled) | fraction 0–1 |
| `-sched-floor-frac` | `sched.floor_frac` | 0 (built-in 0.2; negative = disable) | fraction |

## 10. Shed (voluntary load shedding) — hot-reload, default on
**Scope:** exec (single-node attaches an inert controller — there are no peers to shed to).

**Background.** When a gateway saturates, it can *refuse to re-claim* sandfs it just released: instead of a warm 200 the agent gets 503 + `Retry-After` + `Connection: close`, which makes the client re-resolve DNS and land on an idle peer. This is the standard-protocol-only rebalance path (no client-side assumptions). Enabled by default — it trades a bit of latency for cluster balance and is a no-op unless the preconditions hold (sustained saturation AND a genuinely idle peer, so a single-gateway deployment never sheds); cooldown prevents a shed sandfs from ping-ponging back. Disable explicitly with `-enable-load-shed=false` / `shed.enabled: false` to opt out.

| CLI flag | YAML key | Default | Unit |
|---|---|---|---|
| `-enable-load-shed` | `shed.enabled` | true (default on) | — |
| `-shed-sat-sec` | `shed.sat_sec` | 15 | seconds. `<= 0` = disable shedding on the saturation signal (documented sentinel) |
| `-shed-rate-per-sec` | `shed.rate_per_sec` | 1 | sheds/second. `<= 0` = disable (documented sentinel) |
| `-shed-cooldown-sec` | `shed.cooldown_sec` | 30 | seconds. **Minimum 0** — negative values are rejected at startup and refused on hot-reload (a negative window would let the next DNS resolution instantly undo a shed) |
| `-shed-retry-after-sec` | `shed.retry_after_sec` | 5 | seconds. **Minimum 1** — `<= 0` is rejected (it would be silently replaced by a hardcoded 5) |

## 11. Selfload (gateway self-pressure routing gate) — hot-reload
**Scope:** exec only — the flag is published into the etcd load record for sandns; single-node/human do not run a placement market.

**Background.** Every signal sandns scores gateways on is *node-side* (per-sandlot duty, clean VMs). A gateway whose own process is struggling while its sandlots idle is invisible to that picture — worse, low node duty makes binpack actively prefer it, funneling new traffic into the struggling gateway. The selfload gate closes that gap: the gateway measures **its own process's** resource pressure, publishes a `self_pressured` flag in the load record, and sandns excludes a pressured gateway from placement candidacy (no-owner fallback, agent domain, stream placement).

**What "self pressure" means — and deliberately does not.** The signals are process-scoped and sustained:

- **CPU** — the gateway process's CPU time (`/proc/self/stat`) as a percentage of GOMAXPROCS. On Go 1.25+ GOMAXPROCS honors the cgroup CPU quota, so in containers this is *quota saturation* and on a bare-metal host *real-core saturation*. VM compute on a co-located sandlot lands in the sandvmm process's stat, never ours; waiting for sandlots costs ~no process CPU. This is why in-flight request counts were *not* chosen as the gate: a high in-flight with idle CPU is downstream queueing (which node duty already covers), not gateway overload. In-flight is still published (`self_inflight`) as an observability field.
- **Memory** — Go-runtime-managed memory over the soft memory limit (`-gomemlimit` / `GOMEMLIMIT`). GC pressure from large buffers is the gateway's real memory-overload mode; without a limit configured the signal is simply absent.

Both signals are smoothed (EWMA, ~30s CPU / ~10s memory) and must stay over threshold for `sat_sec` before `self_pressured` flips — placement rides a seconds-long publish + watch + TTL chain, so reacting to spikes would be routing on stale noise. Sampling runs at the load-publish cadence (2s) — the consumers cannot see changes faster than that anyway, and the dt-aware EWMA stays correct at any cadence. Recovery is symmetric: the flag clears once the smoothed signal falls back under threshold (the exit is itself smoothed, which prevents flapping).

**Scope of the gate.** Placement of NEW traffic only. Owned sandfs keep routing to a pressured owner (affinity and mount correctness trump placement — migrating owned sandfs is load-shed's job, not routing's), presence-directed routing and stream stickiness are likewise unaffected. A gateway with no load record yet (bootstrap) is never excluded; a dying gateway's load key simply expires.

| YAML key | Default | Unit | Notes |
|---|---|---|---|
| `selfload.cpu_hard` | 85 | % of GOMAXPROCS | `<= 0` disables the CPU signal. |
| `selfload.mem_hard` | 0.90 | ratio | Managed memory / soft limit; `<= 0` disables. Inert unless a soft limit is set. |
| `selfload.sat_sec` | 10 | seconds | Sustain window before the flag flips; `0` = immediate. |

No CLI flags — YAML only. Ops visibility: `/stats` surfaces `self_cpu_pct` / `self_mem_pct` / `self_inflight` / `self_pressured` per gateway. sandns needs no configuration of its own: it honors the published flag like it honors `clean_vms`.

## 12. Staleness (health-death thresholds) — hot-reload
**Scope:** human and exec (etcd modes). The claim guard and ownership TTL act on exec; the alert scan and route-stale act on human.

**The problem this solves, in plain terms.** The cluster constantly needs to answer: *"is gateway X dead?"* — sandns must decide where to send agents, the 307 redirect must decide whether to bounce a request to the owner, a peer must decide whether to take over an owner's sandfs, and ops need an alarm before users notice.

The health record itself is simple: each gateway writes `/sandswap/health/{gw}` every 5s, and the value contains a timestamp (`last_healthy_ts`) — "when I was last alive". The key is a **plain etcd key with NO lease**: it is never auto-deleted, so it does not flip between "exists = alive" and "gone = dead". Death is judged purely by *how long since the last refresh* — and, crucially, **each consumer picks its own threshold** according to how expensive it is to be wrong:

- **Routing** (DNS, 307): being wrong is cheap — if you route to a gateway that is only napping (GC pause, brief etcd blip), it wakes up and serves the request normally; the client loses nothing. So routing uses the **shortest** threshold and reroutes the fastest.
- **Takeover** (claim-dead guard): being wrong is expensive — grabbing a sandfs that a live owner still owns is the one mistake that can corrupt state. So the takeover side waits much longer, and only after the full protection window does it CAS-take-over the (idle) sandfs.
- **Alerting**: alarms should be early and cheap — warn before the takeover side would act.

Design history: originally the health key carried a 14s lease, which made death a binary flip at 14s for everyone. That was too tight (one >14s GC pause got a gateway declared dead by the whole cluster) *and* too rigid (every consumer shared one death time). The lease is gone; the timestamp is the signal, and each consumer thresholds it independently. Ordering invariant: **route < alert < guard ≪ T_safe** (T_safe = 11 min by default — the takeover guard must stay far below it so takeover remains possible inside the resilience window).

| CLI flag | YAML key | Default | Unit | What it does / why this default |
|---|---|---|---|---|
| `-route-stale-sec` | `staleness.route_stale_sec` | 20 | seconds | Past this staleness, DNS stops routing to the owner (falls back to presence-directed routing or scheduling) and the 307 redirect refuses to bounce the request to the (likely dead) owner. 20s = ~4 missed refreshes at the 5s cadence; a live owner is never stale at 20s, and a false positive costs one retry at worst. |
| `-claim-dead-guard-sec` | `staleness.claim_dead_guard_sec` | 45 | seconds | Idle-claim protection window: a dead-owned IDLE sandfs must stay dead-and-untouched this long before a peer force-takes it over (CAS on the etcd record). 45s rides out any nap that route-stale would misjudge; mounted sandfs never use this (they take over instantly when the node physically migrates — a signal, not a timer). |
| `-alert-stale-sec` | `staleness.alert_stale_sec` | 30 | seconds | The human gateway's periodic scan logs a structured warning once an owner is stale past this while sandfs still point at it (stranded ownership). Warns *before* the 45s guard would enable takeover. |
| `-alert-scan-interval-sec` | `staleness.alert_scan_interval_sec` | 30 | seconds | Cadence of that scan — a FULL ownership-prefix sweep per pass on the human gateway. At a million ownership keys a 30s cadence costs ~1 core continuously on the control plane; 300s is a sane million-scale value. Min 10; hot-reloadable (the loop re-derives its timer each tick). |
| `-ownership-cache-ttl-sec` | `ownership.cache_ttl_sec` | 30 | seconds | Claim fast-path freshness window: how long a cached ownership entry may serve without re-validating against etcd. THE etcd read-load lever — steady linearizable Gets/s ≈ actively-queried sandfs ÷ TTL, and adding gateways does NOT divide it (each sandfs has exactly one owner gateway). Safety ceiling `min(2 × claim_dead_guard_sec, 300)` is validated at startup, on hot-reload, and re-checked whenever the guard changes (while this gateway is healthy no peer can take over its keys; the earliest a takeover can commit after our absence is ~2×guard, so a stale-serve window ≤ TTL cannot overlap it). Raising it only IMPROVES request latency (more fast-path hits, fewer etcd Gets on the request path). See [etcd Operations](../etcd.md) for the read-load math. |

> **Hot-reload**: yes — the ownership cache re-reads the thresholds under its mutex on every use, so a YAML edit applies live.
>
> **sandns is a separate process** and does not see these flags: it has its own `staleness.route_stale_sec` in the sandns config file (default 20, hot-reloadable there too). Keep the two aligned.

> **Bounds** (enforced at startup, and refused on hot-reload — the previous thresholds are kept): all three must be `>= 1` (`<= 0` would silently keep the default), and the judging-cost ordering must hold — `route_stale_sec <= claim_dead_guard_sec` and `alert_stale_sec <= claim_dead_guard_sec` (equal is allowed; the e2e compresses all three to the same second). Routing and alerting must give up on an owner no later than the takeover guard may rob it.
>
> Related ops surface: `/stats` reports per-gateway `last_healthy_ts` + `stale_sec`, and `healthy` = "fresh within the claim-dead guard". A permanently dead gateway's health key lingers in etcd (a few dozen bytes per gateway) — reclaim it manually like any orphan registry key.
>
> **Both-dead recovery is a manual tool, not an automatic reaper.** When a gateway *and* its node both die permanently, the ownership record is deliberately left alone: the presence key is written by the gateway on the node's behalf, so an etcd observer cannot tell "gateway died" from "gateway lost connectivity to etcd but everything still runs" — auto-reclaiming on such a signal could double-mount a disk. Reclaim with `POST /human/ownership/reap-stuck` (`sandctl api ownership reap-stuck <gw-id> [--dry-run] [--batch=N]`) for a dead owner's sandfs (idle ones immediately), or `POST /human/ownership/reap-stuck-node` (`sandctl api ownership reap-stuck-node <node-id> [--dry-run] [--batch=N]`) for all sandfs placed on a dead node at once — see [Human API](../../reference/human-api.md).

## 13. Etcd-partition self-fence — hot-reload
**Scope:** all etcd modes — every gateway publishes health; the unmount side of the fence only bites on exec (the human gateway holds no mounts).

**Background.** What happens if a gateway is alive but *partitioned from etcd* (network split, etcd outage)? It keeps serving agents but cannot publish health, so the cluster will eventually judge it dead and take its sandfs over — while it may still be holding mounts. The self-fence closes that gap deterministically instead of hoping someone notices: if the health-key write fails continuously for this long, the gateway **actively unmounts every sandfs it holds** while keeping its node streams connected (pools stay warm; recovery is in-place — presence is re-granted for all nodes once etcd is reachable again).

This is what makes the time-guarded takeover sound: "health stale past fence + T_clean" provably holds no mounts.

| CLI flag | YAML key | Default | Unit | What it does / why this default |
|---|---|---|---|---|
| `-etcd-fence-sec` | `staleness.etcd_fence_sec` | 180 | seconds | Continuous health-write failure window before self-fencing. Must satisfy `T_safe > fence + T_warden + 30s` (heartbeat) — validated per node at connect, and re-validated against every connected node when hot-reloaded (a value that breaks the invariant for any node is refused and the previous threshold kept). Generous by design: transient etcd blips never fence; recovery is automatic. Hot-reloadable. |

## 14. Identity store loading (etcd modes) — restart-required
**Scope:** human and exec.

**Background.** In `human`/`exec` mode the gateway loads the identity store (agents + sandfs records) from etcd at startup (and rebuilds it after etcd compaction). The hot path afterwards is local in-memory with zero network calls; these knobs only shape the bulk load and the cache-miss behavior.

| CLI flag | YAML key | Default | What it does / why this default |
|---|---|---|---|
| `-identity-load-page-size` | `identity_load.load_page_size` | 1000 | Keys per paginated range request (each page stays well under etcd request-size limits). |
| `-identity-load-workers` | `identity_load.load_workers` | 16 | Parallel key-range workers for the snapshot load. |
| `-identity-full-load-timeout-sec` | `identity_load.full_load_timeout_sec` | 120 | Deadline for one full snapshot load (startup and post-compaction rebuilds). |
| `-identity-lazy-load` | `identity_load.lazy_load` | true | On-demand point-Gets for cache misses after the initial snapshot (singleflight-collapsed, rate-limited, negative-cached). |
| `-identity-hot-only` | `identity_load.hot_only` | false | Skip loading/watching sandfs display metadata (name/description). Exec gateways should enable — they never render names. |

---

## 15. Single-node identity store (default mode) — restart-required
**Scope:** single-node only — `human`/`exec` keep identity in etcd and ignore this section.

**Background.** Without this, a single-node gateway restart orphaned every agent api key and every volume directory: identity lived only in process memory while the volume data survived on disk. The snapshot closes that gap — every agent/SandFS mutation rewrites a small JSON file, and startup loads it back. The file stores only SHA-256 digests of api keys (same contract as the etcd path); plaintext keys are shown to the operator exactly once, at creation.

**Startup contract.** Persistence is mandatory in this mode: the snapshot is always on, and an explicit empty `-identity-store=` refuses to start rather than silently disabling it (an operator asking to disable persistence is asking for the identity-loss bug this feature fixes — if you want identity in etcd instead, run the `human`/`exec` modes). Missing file = first boot, starts empty (any unclaimed `sandfs-*` directories are reported as orphan warnings — records are never auto-imported because owner/template metadata is unknowable from a directory). Corrupt JSON or unknown snapshot version = the gateway refuses to start; starting empty on a damaged identity file would silently orphan every volume. A second gateway on the same snapshot file is locked out (flock on `<path>.lock`) — two writers would otherwise silently overwrite each other. The kernel releases the lock on process death, so a crashed gateway never blocks restart.

**Restart matrix (single-node).**
- *Gateway restarts:* identity reloads from the snapshot; the node's warm VM pool survives (sandlot releases mounts at reconnect and re-announces itself); the first request per SandFS pays one cold mount. Volume data is untouched throughout.
- *Sandlot restarts:* no new mechanism — the gateway's identity store is in memory and unaffected; the node re-adopts surviving VMs from its own persisted state and re-announces capacity.
- *Either restart kills in-flight background execs* (mounts release at reconnect) and gateway-side exec registries (`/agent/exec/status` forgets exec_ids). Long-running work does not span a restart by design.
- *Unmount statistics* reset on gateway restart (metrics, not correctness).

**Operations.** `-vol-root` must stay stable across restarts (records store absolute volume paths; a different vol_root starts empty and warns about every directory). One gateway per snapshot file — use the default mode for exactly one process per volumes tree. Backup/restore is copying the snapshot file plus the volume tree; no special tooling. Hand-editing the file is supported only for repair: duplicate entries and records whose `rootfs_path` is empty or escapes `vol_root` are dropped with a warning at load.

**Relationship to `-etcd` (mode-scoped, not validated-mutually-exclusive).** The two options never take effect in the same process, and whichever side is ignored warns loudly at startup: single-node mode ignores `-etcd` (warns "etcd is ignored in single-node mode") and uses the snapshot; `human`/`exec` modes REQUIRE `-etcd` (refuse to start without it) and ignore an explicitly-passed `-identity-store` (warn "ignored in human/exec mode"). Passing both is therefore always a misconfiguration signal — check which mode you intended. Note the topology vs store distinction: a single MACHINE can absolutely run the etcd store (as the `human` + `exec` process pair); "single-node mode" refers to the one-process MemoryStore topology, and there the snapshot is not optional.

---

## 16. Go runtime GC pacing — restart-required
**Scope:** all modes.

**Background.** Go's concurrent GC paces itself by live-heap growth (default `GOGC=100`: collect when the heap doubles). The collector's mark/assist cycles compete with request-handling goroutines for cores, and at high request rates they surface as P95/P99 tail samples. These flags trade a modest, bounded heap increase for fewer GC cycles; `GOMEMLIMIT` (a soft limit the runtime respects by collecting harder as it is approached) bounds the worst case in memory-constrained deployments. `GOGC`/`GOMEMLIMIT` env vars always work natively — the flags only matter when you want to override or formalize the setting; with the flags left at their defaults, a set env var wins.

| CLI flag | YAML key | Default | What it does / why this default |
|---|---|---|---|
| `-gogc` | — | 0 (auto) | GC target percentage. Auto = honor the `GOGC` env var if set, else apply **200** (half the GC frequency of Go's default 100; the heap may grow proportionally before a collect). Positive = force that value. Negative = rejected at startup (a negative would disable the GC entirely). |
| `-gomemlimit` | — | "" (auto) | Runtime soft memory limit, e.g. `512MiB`, `8GiB` (binary units or raw bytes). Auto = honor the `GOMEMLIMIT` env var if set, else no limit. In k8s/containers set it to ~90% of the pod memory limit so the collector engages before the OOM killer does. |

## 17. MCP server — instructions file (file content hot-reload)
**Scope:** single-node and exec — the MCP server is agent-facing.

**Background.** The embedded MCP server returns an overall Sandswap guide to AI agents — how the sandbox works, failure semantics, efficient usage — on `initialize` (standard `instructions` field) and via the read-only `sandswap_guide` tool. The built-in default text is compiled in; deployments customize it by pointing this flag at their own markdown file, edited offline. The file's *content* is hot-reloaded (event-driven watcher, ~200 ms debounce, same mechanism as the YAML hot-reload — editor rename-saves and kubelet ConfigMap symlink swaps included); changing the configured *path* is restart-required. A missing/unreadable/oversized (> 1 MB)/empty file falls back to the built-in default with a Warn — never blocks startup. See [the MCP page](../../integration/agent-mcp.md#8-server-instructions) for the agent-facing view.

The guide (and the `execute` tool description) states the **sync-exec hard cap** — "sync execs are HARD-CAPPED at N seconds; anything longer MUST use `background:true`" — rendered at serve time from the live `-max-exec-timeout-sec` value (hot-reload aware), so the agent-visible bound always equals the enforced one. Likewise `{{sticky_ms}}` renders the live `-sticky-ms` idleness window; the quoted warm/cold latencies are the current bare-metal benchmark (P95 ≈ 0.96 ms / 2.3 ms). Custom files opt in with the same placeholders; files without them are served verbatim.

**No manual dump step is needed.** Point `-mcp-instructions-file` at a path and the file materializes itself:

- **Gateway, best effort at startup**: a configured-but-missing file is atomically written with the built-in default (create-if-missing only — an existing file is never overwritten). Works wherever the gateway process can write the directory (dev boxes, self-hosted). Where it cannot (production: bare metal runs `User=sandserv` against root-owned `/etc/sandswap`; k8s mounts the ConfigMap read-only at `runAsNonRoot`), the write silently degrades to the serve-the-default fallback — which is why the deploy tooling materializes the file with ITS privileges instead (below).
- **Deploy tooling (the production path)**: bare-metal scripts generate `/etc/sandswap/mcp-instructions.md` as root (generate-once — re-deploys never clobber operator edits) and write the `mcp.instructions_file` key; k8s `deploy-lib` seeds the `gateway-mcp-instructions` ConfigMap from the gateway binary the same way.
- `-print-mcp-instructions` remains for inspection/pipe-to-file workflows, not as a required step.

| CLI flag | YAML key | Default | What it does |
|---|---|---|---|
| `-mcp-instructions-file` | `mcp.instructions_file` | "" (built-in default) | Markdown file whose trimmed content replaces the served guide (initialize `instructions` + `sandswap_guide`). Missing file → materialized from the built-in default (best effort; see above). |
| `-print-mcp-instructions` | — (CLI only) | — | Print the built-in guide and exit (inspection / manual pipe-to-file; the normal flows above don't need it). The compiled default is the single source of truth — no second copy in deploy templates. |

**Standard file location:** bare metal `/etc/sandswap/mcp-instructions.md` (generated by the deploy scripts together with the `mcp.instructions_file` key — edit it directly, the gateway hot-reloads); Kubernetes `gateway-mcp-instructions` ConfigMap → `/etc/sandswap/mcp-instructions.md` in the pod (edit the ConfigMap; kubelet's atomic symlink swap triggers the watcher).

## 18. Logging
**Scope:** all modes.

| CLI flag | YAML key | Default | Meaning |
|---|---|---|---|
| `-log-level` | — (CLI only) | `info` | `info`\|`debug`. `debug` enables per-op success-path logging on the mount/exec/unmount hot paths; the default keeps errors/warnings + lifecycle events only — the gate is a package-level atomic checked before any formatting, so debug-off costs nothing on the response path. CLI-only (there is no `log_level` YAML key); read once at startup — changing it requires a restart. |

## 19. Hot-reload vs restart-required summary
**Scope:** all modes (the classification is mode-independent).

- **Hot-reload** (YAML edit applies live): `lease.*`, `exec.*`, `sched.*`, `shed.*`, `selfload.*`, `unmount_stats.persist_interval_sec`, `staleness.*` (incl. `etcd_fence_sec` and `ownership.cache_ttl_sec`), `mcp.instructions_file` **file content** (path is restart-required)
- **Restart-required** (logged as a warning, applied on next start): everything else — top level (`vol_root`/`mode`/`etcd`/etcd TLS/`identity_store`), identity (`gateway_id`/`gateway_url`/`gateway_stream_addr`/`idle_timeout`), the three listeners (incl. TLS), `stream_concurrency.*`, `authn.*`, the `identity_load` knobs

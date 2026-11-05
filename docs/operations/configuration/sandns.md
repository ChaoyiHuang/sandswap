---
title: Sandns
nav_order: 4
parent: Configuration
grand_parent: Operations
---

# Sandns Configuration

> Source: `dns/config.go` (YAML keys, defaults, validation) + `dns/main.go` (CLI, reload, signals).
>
> sandns is a YAML-only component: `-config <yaml>` (required) is the only meaningful flag (`-version` prints the version stamp and exits). There is **no static gateway list** — every gateway self-registers its routing addresses into `/sandswap/gateway/{id}` at startup, and sandns builds its candidate set entirely from etcd (registry = candidacy, health = liveness, load = scoring). Before any gateway has registered, stream/agent queries SERVFAIL and the sandfs zone falls back to its no-owner branch.

The design this configures (owner-aware per-sandfs zone, client-IP stickiness, scheduling policy) is described in [Ownership & DNS](../../how-it-works/ownership-and-dns.md).

---

## 1. Listener / etcd / forwarding — restart-required

**Background.** sandns serves UDP+TCP on one address, keeps its state (sticky mappings) in etcd, and forwards everything outside the Sandswap zones to upstream resolvers. These keys are read once at startup and are not re-read by the reload watcher.

| CLI flag | YAML key | Default | Meaning |
|---|---|---|---|
| — (required) | `listen_addr` | `0.0.0.0:53` | DNS listen address (UDP + TCP). Port 53 needs `CAP_NET_BIND_SERVICE` or a non-privileged port. When the address is a wildcard, dedicated loopback UDP listeners are bound on the same port (reported as a warning if they cannot bind) — they carry the ingress signal the recursive ACL trusts, and their loss fails host-local recursion closed, not open. |
| — | `etcd` | "" (required) | etcd endpoints (comma-separated, e.g. `https://etcd1:2379,...`). Gateway candidates, sticky state, and ownership all come from here. |
| — | `etcd_ca` | "" | CA bundle for etcd TLS. |
| — | `etcd_cert` | "" | Client certificate for etcd mTLS. |
| — | `etcd_key` | "" | Client private key matching `etcd_cert`. |
| — | `forwarders` | [] | Upstream resolvers (`host:port`) for non-Sandswap names. Empty = no forwarding (unresolved names fail). A forwarder that would re-enter this resolver — the same port on an address the configured listener actually receives on (a wildcard listener: every local address; an IP-literal listener: that exact address; `localhost`: loopback) — is **refused at startup**: the query would re-enter the process and each in-flight forward would hold a slot until timeout. A local stub resolver on a different port, or on a different specific address the listener does not bind, is fine. |
| — | `guest_cidrs` | [] | Sandbox guest source ranges. These sources are not control-plane consumers: every `<sandfs_id>.<sandfs>` query from one is answered **NXDOMAIN** (the answer reveals neither existence nor ownership — DNS carries no ownership proof), the stream/agent zones are **REFUSED**, and foreign zones are **REFUSED** instead of relayed (the resolver must not double as an open recursive resolver behind the host's egress identity). Set the sandbox subnet (`10.188.0.0/16` by default); empty disables the gate (dev) and logs a startup warning. |
| — | `recursive_acl` | `["127.0.0.1/32","::1/128"]` | Non-guest source ranges allowed to relay foreign zones. A **loopback** entry counts only when the packet also arrived over a loopback-address socket: sandns binds dedicated loopback listeners alongside a wildcard `listen_addr`, enables the IP_PKTINFO / IPV6_RECVPKTINFO socket options on them and requires the datagram's ingress interface to be `lo` (TCP uses the accepted connection's local address). `net.ipv4.route_localnet=1` source spoofing — and a packet addressed `127.0.0.1` that actually arrived on another interface — therefore cannot claim the host's recursion; if the control message cannot be enabled the socket binding remains the signal (logged as a warning), never the claimed source address. Non-loopback entries match by source address (UDP DNS has no stronger client identity). Empty ACL = loopback-only (defensive default). |

## 2. Domains — restart-required

**Background.** sandns serves up to three zones with different routing semantics: the stream domain places sandlots onto gateways; the per-sandfs zone is owner-aware (reads `/sandswap/owner/{id}` then `/sandswap/health/{gw}`); the agent domain resolves to one healthy exec gateway for the `GET /agent/sandfs` bootstrap discovery call.

| YAML key | Default | Meaning |
|---|---|---|
| `domains.stream` | "" (required) | Sandlot stream domain: resolves to the gateway a sandlot should dial (placement). Validation fails without it. |
| `domains.sandfs` | "" (zone disabled) | Per-sandfs owner-aware zone: `<sandfs_id>.<domain>` resolves to its OWNER gateway (CNAME for hostname targets, A for IPs); falls back to staleness-guarded/presence-directed routing or scheduling when there is no fresh owner. |
| `domains.agent` | "" | Shared agent domain (e.g. `sandswap.local`) — the bootstrap discovery entry: resolves to one healthy exec gateway for `GET /agent/sandfs` (any exec gateway answers from the cluster-wide etcd identity store; the call carries no `sandfs_id` so no per-sandfs domain can serve it); also the `sandctl dns agent` diagnostics target. |

> Routing gates: the sandfs-domain fallback additionally requires `node_count > 0` and `clean_vms > 0` (a gateway with no connected sandlots is in a failure state and must not receive new sandfs placements); the stream and agent-discovery domains do NOT gate on compute — a compute-less gateway is still a valid sandlot target (the sandlot connecting is what brings compute back) and a valid discovery target (the identity list is read from etcd regardless of sandlots).

## 3. TTL / sticky records — restart-required

**Background.** Client-IP stickiness maps a resolver's source IP to the gateway it was first routed to, so an agent's repeated connections keep landing on the gateway that holds its warm VMs. Sticky mappings persist to etcd (survive sandns restarts) and expire when unused.

| YAML key | Default | Meaning |
|---|---|---|
| `ttl` | 10 | DNS TTL (seconds) on served answers. Valid range [1, 86400]. |
| `sticky_expire` | 1800 | Sticky records expire after this many seconds without a query. |
| `sticky_sync_interval` | 5 | Seconds between sticky → etcd sync passes. Must be ≥ 1 (0 would panic the sync ticker). |
| `sticky_sync_batch` | 256 | MAXIMUM sticky entries flushed to etcd per sync pass (0 = unlimited). Each pass then fits inside its etcd timeout regardless of dirty-set size; the remainder is picked up by the next pass. |

## 4. Scheduling (gateway routing policy) — hot-reload

**Background.** How sandns picks a gateway for UNSOWNED sandfs and for stream-domain placement (owned sandfs always route to their owner — affinity, orthogonal to policy). `binpack` packs new work onto the busiest healthy gateway so lightly-loaded ones go idle (drain/scale-away); `spread` sends it to the most idle gateway. The duty cap excludes saturated gateways in BOTH policies, so binpack can never pile onto an overloaded gateway. Changes apply live via the config-file watcher.

| YAML key | Default | Meaning |
|---|---|---|
| `scheduling.policy` | `binpack` | `binpack` \| `spread`. Any value other than `spread` normalizes to `binpack`. |
| `scheduling.duty_hard` | 0.85 | Gateway-level `agg_duty_long` hard cap (0–1): a gateway at or above it is excluded from routing for new sandfs in both policies. `0` = disabled. |

## 5. Staleness (owner death threshold) — hot-reload

**Background.** sandns is a separate process, so the gateway's `-route-stale-sec` flag does not reach it — it has its own threshold with the same semantics: staleness past which the owner branch stops routing to an owner (falls back to presence-directed routing or scheduling). Judging wrong here is cheap (a napping owner serves the request fine once it wakes), so this is the fastest death threshold. A live owner refreshes its health key every 5s and is never stale at 20s.

| YAML key | Default | Meaning |
|---|---|---|
| `staleness.route_stale_sec` | 20 | Seconds since an owner gateway's `last_healthy_ts` past which it is treated as dead for routing. `0` = keep the default; negative values are rejected at load. Keep aligned with (≥) the gateway's `-route-stale-sec` — see [Gateway](gateway.md) §12. |

## 6. Operational sizing — restart-required

**Background.** The serving paths read these as plain values and the semaphores are constructed once at startup, so they are restart-required by design. Defaults are chosen to stay reasonable at large fleets (the owner cache holds a million-sandfs working set in ~300 MB at ~250 B per entry; smaller fleets only ever hold what they query). All bounds below are enforced at load — an out-of-range value fails startup.

| YAML key | Default | Valid range | Meaning |
|---|---|---|---|
| `owners.cache_max` | 1,000,000 | ≥ 1000 | Owner-cache entry bound (per-sandfs state). Must hold the hot working set or the hit rate collapses into an etcd read storm. |
| `owners.cache_ttl_sec` | 30 | [1, 3600] | How stale a positive owner entry may be before revalidation. Larger cuts the etcd read rate proportionally at the cost of slower ownership-change visibility. |
| `owners.neg_cache_ttl_sec` | 1 | [1, 300] | Negative (no-owner) entry TTL. Short so a real first-claim is picked up promptly. |
| `owners.etcd_timeout_ms` | 2000 | [100, 60000] | Bound on one on-demand owner etcd Get. |
| `owners.get_concurrency` | 256 | [0, 100000], 0 = unbounded | Concurrent owner etcd Gets on the query path; past the cap lookups fail fast (SERVFAIL/stale) instead of queueing. |
| `owners.rate_limit_per_source` | 100 | [0, 1000000], 0 = unbounded | Per-client-IP owner-lookup rate cap (lookups/s). A random-subdomain flood from one source is refused at this bound instead of reaching etcd; the response is a normal miss, not an error. |
| `owners.rate_limit_global` | 50000 | [0, 10000000], 0 = unbounded | Fleet-wide owner-lookup rate cap (lookups/s) across all sources; the backstop when the per-source cap is disabled or the flood is distributed. |
| `sticky_max` | 65536 | ≥ 1 | Client-IP sticky table bound (in-memory). |
| `max_concurrent_queries` | 2048 | ≥ 16 | Overall in-flight query bound (semaphore). |
| `forward_concurrency` | 128 | ≥ 0, 0 = unbounded | Concurrent upstream forwards. |
| `tcp_max_conns` | 256 | ≥ 1 | Concurrent TCP DNS connections. |

## 7. Hot-reload and signals

- **Hot-reload**: the config file is watched (fsnotify, debounced — same `common/config` ReloadWatcher sandlot uses). Only `scheduling.*` and `staleness.*` re-apply live; invalid values on reload (e.g. `duty_hard` outside [0,1]) are logged and ignored, keeping the previous settings. Everything else (`listen_addr`, `domains.*`, `etcd*`, `ttl`, `sticky_*`, `forwarders`, the §6 sizing knobs) requires a restart. Kubernetes ConfigMap mounts work too: the watcher detects the symlinked `..data` layout and reacts to kubelet's atomic updates.
- **Strict parsing**: unknown YAML keys fail at startup (an obsolete `gateways:` section is rejected, never accepted silently). Remove obsolete keys when upgrading.
- **SIGHUP**: clears all sticky records (`ClearAllSticky`) — the ops escape hatch when every client should be re-placed (e.g. after a topology change). Does not reload config and does not stop the process.
- **SIGINT/SIGTERM**: shutdown.

## 8. Worked example: sandns.yaml

The production shape from [Install (bare metal)](../../deployment/install-baremetal.md):

```yaml
listen_addr: "0.0.0.0:53"

domains:
  agent: sandswap.local           # agent discovery bootstrap (GET /agent/sandfs; any exec GW answers)
  stream: sandswap-stream.local   # sandlot stream domain
  sandfs: sandfs.sandswap.local   # per-sandfs owner-aware zone:
                                  #   <sandfs_id>.sandfs.sandswap.local → owner GW A record
                                  #   (candidates come entirely from etcd self-registration —
                                  #   no static gateway list)

etcd: "https://etcd1:2379,https://etcd2:2379,https://etcd3:2379"
etcd_ca: /etc/sandswap/certs/ca.crt
etcd_cert: /etc/sandswap/certs/etcd-client.crt
etcd_key: /etc/sandswap/certs/etcd-client.key

ttl: 10                          # DNS TTL (seconds)
sticky_expire: 1800              # sticky records expire after 30min without queries
sticky_sync_interval: 5          # sticky → etcd sync interval (seconds)
sticky_sync_batch: 256           # max sticky entries flushed per sync pass

forwarders:
  - 8.8.8.8:53
  - 8.8.4.4:53
```

(The `forwarders` block, plus `scheduling:`/`staleness:` if you deviate from the defaults, is where you extend it.)

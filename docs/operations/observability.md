---
title: Observability
nav_order: 6
parent: Operations
---

# Observability

What Sandswap exposes for monitoring and debugging, and how to read it.
Scraping `/metrics` with Prometheus is covered in
[Prometheus Integration](../integration/prometheus.md) (the metric
catalogue lives there); this page is the field view: the JSON stats, the
per-request latency fields, and where each component logs.

## 1. Collection surfaces

| Surface | Location | Precision | Content |
|---------|----------|-----------|---------|
| **execute response fields** | `POST /agent/execute` response body | ns | `gateway_duration_ns` (gateway E2E), `sandlot_duration_ns` (dispatch→response, incl. set-fs + vsock RTT), `exec_duration_ns` (warden share: spawn→wait warm / mount+exec cold) |
| **lease classification header** | `X-Sandbox-Lease: hit` on the same response | per request | hit = warm (sticky lease); absent = cold (cross-agent cold mount / first call) |
| **unmount statistics** | `GET /stats` → per-node `unmount_stats` | ms (integer-truncated) | `unmount_count/success/fail`, `under_5ms/under_10ms`, `top_slow[10]` (with `gateway_ms/sandlot_ms/warden_ms/command/reason` three-layer breakdown) |
| **MCP tool results** | the `execute` tool result | ns | same three `*_duration_ns` fields as the HTTP response |
| **Prometheus** | `/metrics` | scrape-time | the same stats projected to text — catalogue in [Prometheus Integration](../integration/prometheus.md) |

All timings come from monotonic clocks (Go `time.Since`, Rust `Instant`);
no wall-clock drift. Logging overhead on measured paths is bounded by
design — per-op success logs are debug-gated in all three processes
(below), so a production default log costs < 0.01 ms per request.

## 2. Derived latency relations

- `gRPC + gateway processing ≈ gateway_duration_ns − sandlot_duration_ns`
- `vsock RTT + set-fs + sandlot processing ≈ sandlot_duration_ns − exec_duration_ns`

Finer segments than these are only visible in component logs.

## 3. Reading `/stats`

`GET /stats` (human listener in single-node/human mode; agent listener in
exec mode, where it is `-ops-token-file`-gated and disabled without the
flag) serves the full cluster report: per-gateway health
(`healthy`, `stale_sec`, `last_healthy_ts`), node inventory with pool
state and VM counts, duty/load signals, the per-node `unmount_stats`
block, and exec-slot signals (`peak_concurrent_execs`, `slot_wait_ms`,
`slot_wait_events`, `recycle_triggers`). The same report, field by field,
is what [Troubleshooting](troubleshooting.md) walks through — go there for
"what value means what".

## 4. Log gating conventions

Per-op success lines are **debug-gated everywhere**, checked before any
formatting (slog args and `fmt.Sprintf` are eager — the gate wraps the
call):

| Component | Default output | Enable debug |
|---|---|---|
| gateway | errors/warnings + sparse lifecycle events | `-log-level debug` |
| sandlot | errors/warnings + sparse lifecycle events | `-debug` |
| warden | errors/warnings + lifecycle events | config `log_level` / `SANDSWAP_WARDEN_LOG_LEVEL`; `debug!` is a compile-time no-op without the slog `max_level_debug` feature |

The reason for the gate: per-op lines tax the cold path through the
slog-async drain (the legacy serial UART cost ~83 µs/char; warden userspace
now uses hvc0 → `console.log`), and at scale they flood the log.

## 5. Per-segment log lines (debug on)

| Segment | Log source | Example line |
|---------|-----------|--------------|
| Gateway E2E + warm/cold | gateway.log (JSON) | `"msg":"execute complete","leaseHit":true,"latency":"3.4ms"` |
| set-fs (allowed_dirs hot-swap) | sandlot.log | `mount-rootfs: set-fs allowed_dirs=[…] took 1.2ms` |
| vsock RT (cold/warm path) | sandlot.log | `mount-rootfs: cold mount_and_exec took 2.1ms` / `mount-rootfs: warm exec took 0.8ms` |
| warden unmount | sandlot.log | `warden unmount /mnt/rootfs took …ms` |
| warden exec / mount | warden console log (`console.log`) | `exec done in 3ms (spawn=1ms wait=1ms exit=0)`, `mount_and_exec done in 19ms (mount=7ms exit=0)` |

## 6. Verifying data integrity

```bash
# Read response fields directly
curl -s -X POST "$GATEWAY_URL/agent/execute" -H "Authorization: Bearer $KEY" \
  -H "Content-Type: application/json" \
  -d '{"sandfs_id":"...","code":"echo hi","language":"shell"}' \
  | python3 -m json.tool | grep duration

# Unmount statistics (human listener)
curl -s http://localhost:3100/stats | python3 -m json.tool | grep -A8 unmount_stats

# Component log samples (debug enabled)
grep '"execute complete"' /tmp/sandswap-logs/gateway.log | tail -5
grep "took" /tmp/sandswap-logs/sandlot.log | tail -8
```

Collection guarantees: unmount statistics are booked by the gateway at
mount/unmount completion (`unmount_count` + 1 means the unmount finished
and its three-layer latencies are recorded — the benchmark iterates
strictly serially on that); `top_slow` keeps the slowest 10 per node, so
multi-scenario benchmarks snapshot the diff at each scenario boundary and
samples do not pollute each other.

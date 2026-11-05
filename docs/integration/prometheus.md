---
title: Prometheus Integration
nav_order: 8
parent: Integration
---

# Prometheus Integration

`GET /metrics` serves the gateway's stats in **Prometheus text format**
(`text/plain; version=0.0.4`), so any Prometheus-compatible stack —
Prometheus, VictoriaMetrics, Grafana Agent, Alloy — scrapes it with zero
client libraries. This page is the integration wiring and the metric
catalogue; for reading the same data as JSON by hand (troubleshooting), see
[Observability](../operations/observability.md).

## 1. Design boundaries

- **Scrape-time projection only**: `/metrics` renders the same
  `StatsReport` that `/stats` serves — nothing is recorded on request
  paths. In etcd modes a scrape performs the same read-only prefix reads
  `/stats` does (`/sandswap/{load,health,gateway,unmount-stats}/`); in
  single-node the report is built from in-process state. A scrape never
  writes anywhere.
- **No client library**: the text is written by a small pure function
  (`gateway/handler/metrics.go`), unit-tested without a server.
- **Alerting and quota belong to your monitoring stack**: Sandswap exposes
  the signals; alert rules, dashboards, and capacity policy are yours to
  define.

## 2. Scraping

Where the endpoint lives depends on the gateway mode (same auth placement
as `/stats`):

| Mode | Scrape URL | Auth |
|---|---|---|
| single-node / human | human listener `:3100/metrics` | OIDC/mTLS when configured (`sandswap:ops` scope) |
| exec (distributed) | agent listener `:3000/metrics` | `-ops-token-file` bearer token (endpoint disabled without the flag) |

Example scrape config for a distributed deployment:

```yaml
scrape_configs:
  - job_name: sandswap
    metrics_path: /metrics
    static_configs:
      - targets:
          - gw-exec-1.example.com:3000
          - gw-exec-2.example.com:3000
    # human gateways (and single-node) instead:
    # - targets: ['gw-human-1.example.com:3100']
```

Counters (`*_total`) reset on gateway restart — standard Prometheus
semantics, use `rate()`/`increase()`, never raw deltas.

## 3. Metric catalogue

The single authoritative source is `WriteMetricsText` in
`gateway/handler/metrics.go`.

**Build**

| Metric | Labels | Meaning |
|---|---|---|
| `sandswap_build_info` | `version`, `commit` | always `1`; identify the running build by label |

**Cluster totals** (no labels)

`sandswap_cluster_gateways`, `sandswap_cluster_nodes`,
`sandswap_cluster_clean_vms`, `sandswap_cluster_total_vms`,
`sandswap_cluster_in_use_vms` — the cluster-wide view of gateway/node/VM
counts.

**Per gateway** (label `gateway_id`)

| Metric | Meaning |
|---|---|
| `sandswap_gateway_healthy` | 1 if the health key is fresh within the claim-dead guard |
| `sandswap_gateway_health_stale_seconds` | seconds since the gateway last refreshed its health key |
| `sandswap_gateway_nodes` | sandlot nodes connected |
| `sandswap_gateway_clean_vms` / `_total_vms` / `_in_use_vms` | VM pool per gateway |
| `sandswap_gateway_agg_duty_long` | mean long-window duty across its nodes (0..1) — the load-shed/binpack signal |
| `sandswap_gateway_self_cpu_pct` / `_self_mem_pct` | gateway process CPU (% GOMAXPROCS, EWMA) and managed memory (% of soft limit) |
| `sandswap_gateway_self_inflight` / `_self_pressured` | in-flight agent requests and the pressure flag (observability) |

**Per node** (labels include `gateway_id`, `node_id`)

| Metric | Meaning |
|---|---|
| `sandswap_node_clean_vms` / `_total_vms` | this node's pool |
| `sandswap_node_duty_long` | long-window duty (0..1) — scheduling weight |
| `sandswap_node_host_cpu_pct` | host CPU as seen by the node |
| `sandswap_node_mounts_total` | cold mounts performed |
| `sandswap_node_unmounts_total`, `_unmount_success_total`, `_unmount_fail_total` | unmount counter and outcomes |
| `sandswap_node_unmount_under_5ms_total`, `_under_10ms_total` | latency-bucket health of the release path |

## 4. Suggested starter alerts

Signals worth alerting on first (thresholds are site-specific):

- `sandswap_gateway_healthy == 0` for > 1 min — a gateway is dead or
  partitioned from etcd.
- `sandswap_gateway_health_stale_seconds` > 3× scrape interval, sustained —
  health refresh stalled before the binary flag flips.
- `increase(sandswap_node_unmount_fail_total[10m]) > 0` — unmount failures
  force destroy-and-replace churn; any sustained rate wants a look.
- `sandswap_cluster_clean_vms` near 0 while requests are active — pool
  exhaustion (`NO_AVAILABLE_SANDBOX` 503s follow).
- `sandswap_node_duty_long` sustained > 0.9 across all nodes — saturation;
  expect load-shed `503 + Connection: close` rebalancing.

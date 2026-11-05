// Copyright 2026 Chaoyi Huang. All rights reserved.
//
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE file at the root of this repository.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0.

package handler

import (
	"fmt"
	"net/http"
	"strings"

	"gateway/pool"
)

// Prometheus exposition of the SAME data /stats serves — a second projection,
// not a second instrumentation: the handler reads the snapshots that already
// exist (pool manager, load keys, unmount-stats recorder, staleness view) at
// scrape time and emits them in the Prometheus text format. Nothing records
// on any request path, and no prometheus client library is linked in — the
// format is small enough to emit by hand (format 0.0.4:
// https://prometheus.io/docs/instrumenting/exposition_formats/).
//
// Scope (deliberate): metrics EXPOSURE only. Alerting rules, dashboards, and
// quota enforcement live in the operator's external monitoring stack — this
// endpoint just gives that stack something to scrape, with the same auth
// placement as /stats (human listener in single-node/human modes, agent
// listener in exec mode).
//
// The freshness semantics are inherited from /stats by construction: the
// distributed view comes from the same etcd keys (peer unmount stats may lag
// by the persist interval), and the local view is real-time.

// metricsBuildVersion/Commit are set once at startup from the ldflags-backed
// vars in cmd/main.go (same pattern as SetDebugLogging).
var (
	metricsBuildVersion = "unknown"
	metricsBuildCommit  = "unknown"
)

// SetMetricsBuildInfo wires the gateway's build identity into the metrics
// endpoint (sandswap_build_info). Called once from cmd/main.go.
func SetMetricsBuildInfo(version, commit string) {
	if version != "" {
		metricsBuildVersion = version
	}
	if commit != "" {
		metricsBuildCommit = commit
	}
}

// MetricsContentType is the Prometheus text exposition content type.
const MetricsContentType = "text/plain; version=0.0.4; charset=utf-8"

// escapeLabel escapes a label value per the text format: backslash, quote,
// and newline must not appear raw.
func escapeLabel(v string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
	return r.Replace(v)
}

// escapeHelp collapses a help string to one line (newlines are not allowed).
func escapeHelp(v string) string {
	return strings.ReplaceAll(v, "\n", " ")
}

// writeMetric emits one sample line with the preceding HELP/TYPE comment
// lines. HELP/TYPE are emitted per metric NAME — samples sharing a name (same
// name, different label sets) must not repeat them, so the caller tracks
// which names already emitted theirs; this helper takes care of that via the
// emitted set.
func writeMetric(b *strings.Builder, emitted map[string]bool, name, help, typ string, labels string, value float64) {
	if !emitted[name] {
		if help != "" {
			fmt.Fprintf(b, "# HELP %s %s\n", name, escapeHelp(help))
		}
		fmt.Fprintf(b, "# TYPE %s %s\n", name, typ)
		emitted[name] = true
	}
	if labels != "" {
		fmt.Fprintf(b, "%s{%s} %v\n", name, labels, value)
	} else {
		fmt.Fprintf(b, "%s %v\n", name, value)
	}
}

// WriteMetricsText projects a StatsReport (the same shape /stats serves)
// into Prometheus text format. Pure function — unit-testable without a
// server. Counters (mounts/unmounts) reset on process restart, which
// Prometheus handles natively.
func WriteMetricsText(rep StatsReport) string {
	var b strings.Builder
	emitted := make(map[string]bool)

	// Build identity.
	writeMetric(&b, emitted, "sandswap_build_info",
		"Gateway build identity (value is always 1; scrape the labels).", "gauge",
		fmt.Sprintf(`version="%s",commit="%s"`, escapeLabel(metricsBuildVersion), escapeLabel(metricsBuildCommit)), 1)

	// Cluster totals.
	writeMetric(&b, emitted, "sandswap_cluster_gateways", "Gateways visible in the stats view.", "gauge", "", float64(rep.Totals.GatewayCnt))
	writeMetric(&b, emitted, "sandswap_cluster_nodes", "Sandlot nodes connected across gateways.", "gauge", "", float64(rep.Totals.NodeCount))
	writeMetric(&b, emitted, "sandswap_cluster_clean_vms", "CLEAN microVMs across the cluster.", "gauge", "", float64(rep.Totals.CleanVMs))
	writeMetric(&b, emitted, "sandswap_cluster_total_vms", "Total microVMs across the cluster.", "gauge", "", float64(rep.Totals.TotalVMs))
	writeMetric(&b, emitted, "sandswap_cluster_in_use_vms", "Bound (in-use) microVMs across the cluster.", "gauge", "", float64(rep.Totals.InUseVMs))

	for _, g := range rep.Gateways {
		gw := `gateway_id="` + escapeLabel(g.GatewayID) + `"`
		healthy := 0.0
		if g.Healthy {
			healthy = 1.0
		}
		writeMetric(&b, emitted, "sandswap_gateway_healthy",
			"1 if the gateway's health key is fresh within the claim-dead guard.", "gauge", gw, healthy)
		writeMetric(&b, emitted, "sandswap_gateway_nodes",
			"Sandlot nodes connected to this gateway.", "gauge", gw, float64(g.NodeCount))
		writeMetric(&b, emitted, "sandswap_gateway_clean_vms",
			"CLEAN microVMs held by this gateway's nodes.", "gauge", gw, float64(g.CleanVMs))
		writeMetric(&b, emitted, "sandswap_gateway_total_vms",
			"Total microVMs held by this gateway's nodes.", "gauge", gw, float64(g.TotalVMs))
		writeMetric(&b, emitted, "sandswap_gateway_in_use_vms",
			"Bound (in-use) microVMs (total minus clean).", "gauge", gw, float64(g.TotalVMs-g.CleanVMs))
		writeMetric(&b, emitted, "sandswap_gateway_agg_duty_long",
			"Mean long-window duty across this gateway's nodes (0..1).", "gauge", gw, g.AggDutyLong)
		writeMetric(&b, emitted, "sandswap_gateway_self_cpu_pct",
			"Gateway process CPU as % of GOMAXPROCS (EWMA).", "gauge", gw, g.SelfCPUPct)
		writeMetric(&b, emitted, "sandswap_gateway_self_mem_pct",
			"Gateway managed memory as % of the soft limit (0 when no limit).", "gauge", gw, g.SelfMemPct)
		writeMetric(&b, emitted, "sandswap_gateway_self_inflight",
			"In-flight requests on the agent listener (observability only).", "gauge", gw, float64(g.SelfInflight))
		writeMetric(&b, emitted, "sandswap_gateway_self_pressured",
			"1 if the gateway is under sustained self pressure (routing gate).", "gauge", gw, boolFloat(g.SelfPressured))
		writeMetric(&b, emitted, "sandswap_gateway_health_stale_seconds",
			"Seconds since the health key was last refreshed.", "gauge", gw, float64(g.StaleSec))

		// Per-node scheduling + unmount counters from the same report.
		for _, n := range g.Nodes {
			nl := gw + `,node_id="` + escapeLabel(n.NodeID) + `"`
			writeMetric(&b, emitted, "sandswap_node_clean_vms",
				"CLEAN microVMs on the node.", "gauge", nl, float64(n.CleanVMs))
			writeMetric(&b, emitted, "sandswap_node_total_vms",
				"Total microVMs on the node.", "gauge", nl, float64(n.TotalVMs))
			writeMetric(&b, emitted, "sandswap_node_duty_long",
				"Node long-window duty (0..1).", "gauge", nl, n.DutyLong)
			writeMetric(&b, emitted, "sandswap_node_host_cpu_pct",
				"Node host CPU %.", "gauge", nl, n.HostCPU)
		}
		for _, u := range g.UnmountStats {
			ul := gw + `,node_id="` + escapeLabel(u.NodeID) + `"`
			writeMetric(&b, emitted, "sandswap_node_mounts_total",
				"Cold mounts served on the node.", "counter", ul, float64(u.MountCount))
			writeMetric(&b, emitted, "sandswap_node_unmounts_total",
				"Unmount attempts on the node.", "counter", ul, float64(u.UnmountCount))
			writeMetric(&b, emitted, "sandswap_node_unmount_success_total",
				"Successful unmounts on the node.", "counter", ul, float64(u.UnmountSuccess))
			writeMetric(&b, emitted, "sandswap_node_unmount_fail_total",
				"Failed unmounts on the node (retried with backoff).", "counter", ul, float64(u.UnmountFail))
			writeMetric(&b, emitted, "sandswap_node_unmount_under_5ms_total",
				"Unmounts under 5ms (gateway E2E).", "counter", ul, float64(u.Under5ms))
			writeMetric(&b, emitted, "sandswap_node_unmount_under_10ms_total",
				"Unmounts under 10ms (gateway E2E).", "counter", ul, float64(u.Under10ms))
			// TopSlow is intentionally NOT projected: a top-N list is for
			// humans (/stats), not a time series.
		}
	}
	return b.String()
}

func boolFloat(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// Metrics handles GET /metrics — the Prometheus projection of the same
// report /stats serves (same sources, same freshness semantics).
func (h *HumanHandler) Metrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", http.MethodGet)
		writeJSONError(w, "method not allowed, use GET", http.StatusMethodNotAllowed)
		return
	}
	ctx := r.Context()
	rep, err := BuildStatsReport(ctx, h.etcdClient, h.gatewayID, h.pool, h.unmountSnapshot(), h.redactTenantIDs, h.logger)
	if err != nil {
		// A degraded etcd read still yields a (possibly empty) report — only
		// a total failure lands here; serve what the format needs to stay
		// scrapeable rather than 5xx-ing the scraper.
		rep = StatsReport{}
	}
	w.Header().Set("Content-Type", MetricsContentType)
	// Security-event counters (named isolation refusals) ride AFTER the main
	// report: same scrape, separate series, populated only from command-
	// failure paths (the doctrine: nothing recorded on request paths).
	w.Write([]byte(WriteMetricsText(rep)))
	w.Write([]byte(pool.WriteSecurityMetricsText()))
}

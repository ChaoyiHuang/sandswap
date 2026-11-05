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
	"strings"
	"testing"

	"gateway/lease"
	"gateway/stats"
)

// metricLines extracts the sample lines (no # comments) from an exposition.
func metricLines(t *testing.T, text string) []string {
	t.Helper()
	var out []string
	for _, l := range strings.Split(text, "\n") {
		if l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out
}

func fixtureReport() StatsReport {
	return StatsReport{
		Totals: StatsTotals{CleanVMs: 3, TotalVMs: 5, InUseVMs: 2, NodeCount: 1, GatewayCnt: 1},
		Gateways: []GatewayStats{
			{
				GatewayID:   "gw-1",
				Healthy:     true,
				NodeCount:   1,
				CleanVMs:    3,
				TotalVMs:    5,
				AggDutyLong: 0.42,
				SelfCPUPct:  11.5, SelfMemPct: 40, SelfInflight: 7, SelfPressured: false,
				StaleSec: 3,
				Nodes: []lease.NodeLoad{
					{NodeID: "node-a", CleanVMs: 3, TotalVMs: 5, DutyLong: 0.42, HostCPU: 55.5},
				},
				UnmountStats: []stats.NodeUnmountStats{
					{NodeID: "node-a", MountCount: 10, UnmountCount: 9, UnmountSuccess: 8, UnmountFail: 1, Under5ms: 5, Under10ms: 7},
				},
			},
		},
	}
}

// TestWriteMetricsTextShape verifies the format basics: HELP/TYPE precede
// every metric name exactly once, cluster totals appear, values render.
func TestWriteMetricsTextShape(t *testing.T) {
	SetMetricsBuildInfo("v-test", "cafe01")
	text := WriteMetricsText(fixtureReport())

	for name, want := range map[string]string{
		"sandswap_cluster_clean_vms":            "sandswap_cluster_clean_vms 3",
		"sandswap_cluster_in_use_vms":           "sandswap_cluster_in_use_vms 2",
		"sandswap_gateway_healthy":              `sandswap_gateway_healthy{gateway_id="gw-1"} 1`,
		"sandswap_gateway_in_use_vms":           `sandswap_gateway_in_use_vms{gateway_id="gw-1"} 2`,
		"sandswap_gateway_health_stale_seconds": `sandswap_gateway_health_stale_seconds{gateway_id="gw-1"} 3`,
		"sandswap_node_duty_long":               `sandswap_node_duty_long{gateway_id="gw-1",node_id="node-a"} 0.42`,
		"sandswap_node_unmount_fail_total":      `sandswap_node_unmount_fail_total{gateway_id="gw-1",node_id="node-a"} 1`,
		"sandswap_build_info":                   `sandswap_build_info{version="v-test",commit="cafe01"} 1`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("%s: sample %q not found in output:\n%s", name, want, text)
		}
	}

	// Every metric name has exactly one TYPE line.
	typeCount := map[string]int{}
	for _, l := range strings.Split(text, "\n") {
		if strings.HasPrefix(l, "# TYPE ") {
			typeCount[strings.Fields(l)[2]]++
		}
	}
	if len(typeCount) == 0 {
		t.Fatal("no TYPE lines emitted")
	}
	for name, n := range typeCount {
		if n != 1 {
			t.Errorf("metric %s has %d TYPE lines, want 1", name, n)
		}
	}

	// Counters are typed counter, gauges gauge.
	if typeCount["sandswap_node_mounts_total"] != 1 {
		t.Error("sandswap_node_mounts_total missing")
	}
	if !strings.Contains(text, "# TYPE sandswap_node_mounts_total counter") {
		t.Error("mounts metric must be typed counter")
	}
	if !strings.Contains(text, "# TYPE sandswap_gateway_clean_vms gauge") {
		t.Error("clean_vms metric must be typed gauge")
	}

	// No blank sample lines, no CRLF.
	for _, l := range metricLines(t, text) {
		if !strings.Contains(l, " ") && !strings.Contains(l, "{") {
			t.Errorf("malformed sample line: %q", l)
		}
	}
}

// TestWriteMetricsTextLabelEscaping pins the escaping rules: a gateway id
// containing a quote/backslash/newline must not break the format.
func TestWriteMetricsTextLabelEscaping(t *testing.T) {
	rep := StatsReport{Gateways: []GatewayStats{{GatewayID: `we"i\rd`}}}
	text := WriteMetricsText(rep)
	want := `gateway_id="we\"i\\rd"`
	if !strings.Contains(text, want) {
		t.Errorf("escaped label %q not found in:\n%s", want, text)
	}
}

// TestWriteMetricsTextEmptyReport verifies the scraper always gets a parseable
// document (build info + zero totals), never an error body.
func TestWriteMetricsTextEmptyReport(t *testing.T) {
	text := WriteMetricsText(StatsReport{})
	lines := metricLines(t, text)
	if len(lines) < 6 {
		t.Fatalf("empty report must still emit build info + cluster zeros, got %d lines:\n%s", len(lines), text)
	}
	if !strings.Contains(text, "sandswap_cluster_gateways 0") {
		t.Error("cluster gateways zero missing")
	}
}

// TestWriteMetricsTextOmitsTopSlow verifies the human-facing top-N slow list
// is deliberately not projected into the time-series view.
func TestWriteMetricsTextOmitsTopSlow(t *testing.T) {
	rep := fixtureReport()
	rep.Gateways[0].UnmountStats[0].TopSlow = []stats.SlowEntry{
		{SandfsID: "sandfs-1", Command: "secret-command", GatewayMs: 999},
	}
	text := WriteMetricsText(rep)
	if strings.Contains(text, "secret-command") || strings.Contains(text, "sandfs-1") {
		t.Error("TopSlow content leaked into metrics — it is /stats-only by design")
	}
}

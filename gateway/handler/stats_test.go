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
	"context"
	"strings"
	"testing"

	"gateway/pool"
	"gateway/stats"
)

// TestLocalStatsReportSingleNode verifies the MemoryStore (cli == nil) path:
// one self gateway entry, Healthy, with per-node clean/total rolled up into
// the same StatsReport shape the distributed path produces.
func TestLocalStatsReportSingleNode(t *testing.T) {
	pm := pool.NewManager(nil, nil)
	pm.AddNode("node-1")
	pm.UpdateNodeCapacity("node-1", []pool.SpecCapacity{{SpecID: "medium", Clean: 3, Total: 3}})

	rep, err := BuildStatsReport(context.Background(), nil, "gw-self", pm, nil, false, nil)
	if err != nil {
		t.Fatalf("BuildStatsReport: %v", err)
	}
	if len(rep.Gateways) != 1 {
		t.Fatalf("gateways: got %d, want 1", len(rep.Gateways))
	}
	gw := rep.Gateways[0]
	if gw.GatewayID != "gw-self" {
		t.Errorf("gateway_id: %q", gw.GatewayID)
	}
	if !gw.Healthy {
		t.Error("single-node self should be Healthy")
	}
	if gw.CleanVMs != 3 || gw.TotalVMs != 3 {
		t.Errorf("clean/total: %d/%d, want 3/3", gw.CleanVMs, gw.TotalVMs)
	}
	if rep.Totals.GatewayCnt != 1 || rep.Totals.CleanVMs != 3 || rep.Totals.TotalVMs != 3 {
		t.Errorf("totals: %+v", rep.Totals)
	}
	if rep.Totals.InUseVMs != 0 {
		t.Errorf("in_use: %d, want 0", rep.Totals.InUseVMs)
	}
}

// TestStatsPeerUnmountRedaction pins the tenant-visibility policy over
// the unmount projection's FLEET-WIDE sweep: the exec-mode /stats listener has
// no auth in front of it, and PEER gateways' snapshots arrive verbatim from
// their persisted /sandswap/unmount-stats/{gw} key — so redacting only the
// local snapshot left every other gateway's cross-tenant sandfs ids
// and command excerpts readable. RED with the sweep removed: the peer entry
// below keeps its sandfs_id + command.
func TestStatsPeerUnmountRedaction(t *testing.T) {
	slow := func(id, cmd string) stats.NodeUnmountStats {
		return stats.NodeUnmountStats{
			NodeID:       "n-1",
			UnmountCount: 7,
			Under5ms:     3,
			TopSlow:      []stats.SlowEntry{{SandfsID: id, Command: cmd, GatewayMs: 9}},
		}
	}

	// Redaction ON: a peer-shaped gateway entry (exactly the shape the etcd
	// merge produces) loses its foreign identifiers; the aggregates survive.
	on := StatsReport{Gateways: []GatewayStats{{
		GatewayID:    "gw-peer",
		UnmountStats: []stats.NodeUnmountStats{slow("sf-victim", "echo C-secret > /workspace/x")},
	}}}
	redactUnmountTenantIDs(&on)
	got := on.Gateways[0].UnmountStats[0]
	if got.TopSlow[0].SandfsID != "" || got.TopSlow[0].Command != "" {
		t.Fatalf("foreign tenant identifiers leaked from the redacted projection: %+v", got.TopSlow[0])
	}
	if got.UnmountCount != 7 || got.Under5ms != 3 || got.TopSlow[0].GatewayMs != 9 {
		t.Fatalf("utility lost: the aggregate numbers must survive redaction: %+v", got)
	}

	// Redaction OFF (the authenticated human API): the same entry is untouched.
	off := StatsReport{Gateways: []GatewayStats{{
		GatewayID:    "gw-peer",
		UnmountStats: []stats.NodeUnmountStats{slow("sf-victim", "echo C-secret > /workspace/x")},
	}}}
	if off.Gateways[0].UnmountStats[0].TopSlow[0].SandfsID != "sf-victim" {
		t.Fatal("setup: the ops view must carry the tenant fields")
	}

	// Wiring: the flag reaches the sweep through BuildStatsReport itself — the
	// same reader used for peers (single-node path here, no etcd needed).
	// A FRESH snapshot per call: the sweep mutates the report in place, and the
	// report holds the caller's slice.
	rep, err := BuildStatsReport(context.Background(), nil, "gw-self", nil,
		[]stats.NodeUnmountStats{slow("sf-local", "echo local")}, true, nil)
	if err != nil {
		t.Fatalf("BuildStatsReport: %v", err)
	}
	if id := rep.Gateways[0].UnmountStats[0].TopSlow[0].SandfsID; id != "" {
		t.Fatalf("BuildStatsReport(redact=true) kept the identifier %q", id)
	}
	rep, err = BuildStatsReport(context.Background(), nil, "gw-self", nil,
		[]stats.NodeUnmountStats{slow("sf-local", "echo local")}, false, nil)
	if err != nil {
		t.Fatalf("BuildStatsReport: %v", err)
	}
	if id := rep.Gateways[0].UnmountStats[0].TopSlow[0].SandfsID; id != "sf-local" {
		t.Fatalf("ops projection must be unchanged, got id %q", id)
	}
	// The rendered JSON is what actually leaves the process on the anonymous
	// listener: assert the strings are absent end to end.
	data, err := renderStatsJSON(on)
	if err != nil {
		t.Fatalf("renderStatsJSON: %v", err)
	}
	if strings.Contains(string(data), "sf-victim") || strings.Contains(string(data), "C-secret") {
		t.Fatalf("rendered /stats leaked tenant fields: %s", data)
	}
}

// TestLocalStatsReportNilPM verifies a nil pool manager still yields a
// 1-gateway report with zeroed counts (defensive — human-mode local fallback
// isn't used, but BuildStatsReport(cli==nil, pm==nil) must not panic).
func TestLocalStatsReportNilPM(t *testing.T) {
	rep, err := BuildStatsReport(context.Background(), nil, "gw-x", nil, nil, false, nil)
	if err != nil {
		t.Fatalf("BuildStatsReport: %v", err)
	}
	if len(rep.Gateways) != 1 || !rep.Gateways[0].Healthy {
		t.Fatalf("want 1 healthy self entry, got %+v", rep.Gateways)
	}
	if rep.Totals.TotalVMs != 0 {
		t.Errorf("totals total: %d, want 0", rep.Totals.TotalVMs)
	}
	if rep.Totals.GatewayCnt != 1 {
		t.Errorf("gateway_count: %d, want 1", rep.Totals.GatewayCnt)
	}
}

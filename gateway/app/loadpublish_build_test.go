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

package app

import (
	"context"
	"log/slog"
	"testing"

	"gateway/lease"
	"gateway/pool"
)

// TestBuildLoadValueEmpty verifies a gateway with no connected sandlots
// publishes a zero-capacity load record (node_count 0, clean_vms 0). The DNS
// treats a node_count==0 gateway as the fault state (excluded from agent
// routing), so this is the correct "alive but no compute" signal.
func TestBuildLoadValueEmpty(t *testing.T) {
	pm := pool.NewManager(nil, slog.Default())
	val := buildLoadValue("gw-1", pm, nil)
	if val.GatewayID != "gw-1" {
		t.Errorf("identity: got %+v", val)
	}
	if val.NodeCount != 0 || val.CleanVMs != 0 || val.AggDutyLong != 0 || val.MaxDuty != 0 {
		t.Errorf("empty manager: expected all-zero aggregates, got NodeCount=%d CleanVMs=%d agg=%v max=%v",
			val.NodeCount, val.CleanVMs, val.AggDutyLong, val.MaxDuty)
	}
	if len(val.Nodes) != 0 {
		t.Errorf("expected 0 nodes, got %d", len(val.Nodes))
	}
}

// TestBuildLoadValueSingleNode verifies the load record is built correctly from
// one node's metrics + capacity: agg==max==that node's duty_long, clean_vms ==
// the node's clean count, and the per-node entry carries every signal.
func TestBuildLoadValueSingleNode(t *testing.T) {
	pm := pool.NewManager(nil, slog.Default())
	pm.AddNode("node-1")
	pm.UpdateNodeMetrics("node-1", pool.NodeMetrics{
		DutyLong: 0.4, DutyShort: 0.3, DutyDaily: 0.2, DutyVar: 0.05,
		HostCPU: 55.0, HostMemAvailMB: 8192, ActiveSandfs: 3,
	})
	pm.UpdateNodeCapacity("node-1", []pool.SpecCapacity{
		{SpecID: "small", Total: 4},
		{SpecID: "medium", Total: 2},
	})
	// Clean is DERIVED (total - bound), not the heartbeat Clean
	// (diagnostics only). Bind 2 small + 1 medium so the derived clean =
	// (4-2)+(2-1) = 3, matching the pre-delegation Clean sum the test asserted.
	for i := 0; i < 2; i++ {
		pm.ReserveBound("node-1", "small")
	}
	pm.ReserveBound("node-1", "medium")

	val := buildLoadValue("gw-1", pm, nil)
	if val.NodeCount != 1 {
		t.Fatalf("NodeCount = %d, want 1", val.NodeCount)
	}
	if val.AggDutyLong != 0.4 || val.MaxDuty != 0.4 {
		t.Errorf("agg/max = %v/%v, want 0.4/0.4", val.AggDutyLong, val.MaxDuty)
	}
	// clean_vms is the SUM across specs: 2 + 1 = 3.
	if val.CleanVMs != 3 {
		t.Errorf("CleanVMs = %d, want 3 (sum across specs)", val.CleanVMs)
	}
	if len(val.Nodes) != 1 {
		t.Fatalf("expected 1 node entry, got %d", len(val.Nodes))
	}
	n := val.Nodes[0]
	if n.NodeID != "node-1" || n.DutyLong != 0.4 || n.HostCPU != 55.0 || n.HostMemAvail != 8192 || n.ActiveSandfs != 3 {
		t.Errorf("node entry mismatch: %+v", n)
	}
	if n.CleanVMs != 3 || n.TotalVMs != 6 {
		t.Errorf("node clean/total = %d/%d, want 3/6", n.CleanVMs, n.TotalVMs)
	}
}

// TestBuildLoadValueMultiNode verifies aggregation across nodes: agg is the
// MEAN of duty_long, max is the MAX, clean_vms is the SUM, and every node
// appears in the per-node list (order-independent - map iteration).
func TestBuildLoadValueMultiNode(t *testing.T) {
	pm := pool.NewManager(nil, slog.Default())
	pm.AddNode("node-a")
	pm.AddNode("node-b")
	pm.UpdateNodeMetrics("node-a", pool.NodeMetrics{DutyLong: 0.6})
	pm.UpdateNodeMetrics("node-b", pool.NodeMetrics{DutyLong: 0.2})
	pm.UpdateNodeCapacity("node-a", []pool.SpecCapacity{{SpecID: "s", Total: 10}})
	pm.UpdateNodeCapacity("node-b", []pool.SpecCapacity{{SpecID: "s", Total: 6}})
	// Derived clean. Bind 5 on node-a + 3 on node-b → 5+3 = 8.
	for i := 0; i < 5; i++ {
		pm.ReserveBound("node-a", "s")
	}
	for i := 0; i < 3; i++ {
		pm.ReserveBound("node-b", "s")
	}

	val := buildLoadValue("gw-1", pm, nil)
	if val.NodeCount != 2 {
		t.Fatalf("NodeCount = %d, want 2", val.NodeCount)
	}
	if val.AggDutyLong != 0.4 { // (0.6 + 0.2) / 2
		t.Errorf("AggDutyLong = %v, want 0.4 (mean)", val.AggDutyLong)
	}
	if val.MaxDuty != 0.6 {
		t.Errorf("MaxDuty = %v, want 0.6 (max)", val.MaxDuty)
	}
	if val.CleanVMs != 8 { // 5 + 3
		t.Errorf("CleanVMs = %d, want 8 (sum)", val.CleanVMs)
	}
	// Both nodes present (order-independent).
	seen := map[string]bool{}
	for _, n := range val.Nodes {
		seen[n.NodeID] = true
	}
	if !seen["node-a"] || !seen["node-b"] {
		t.Errorf("expected both nodes in list, got %v", seen)
	}
}

// TestBuildLoadValueContract verifies the built LoadValue marshals to the JSON
// the DNS consumes (agg_duty_long + clean_vms). This is the gateway-side
// write-path lock pairing dns/contract_test.go.
func TestBuildLoadValueContract(t *testing.T) {
	pm := pool.NewManager(nil, slog.Default())
	pm.AddNode("n1")
	pm.UpdateNodeMetrics("n1", pool.NodeMetrics{DutyLong: 0.42})
	pm.UpdateNodeCapacity("n1", []pool.SpecCapacity{{SpecID: "s", Clean: 7, Total: 7}})

	val := buildLoadValue("gw-1", pm, nil)
	_ = lease.LoadValue(val) // type assertion: buildLoadValue returns the contract type

	if val.AggDutyLong != 0.42 || val.CleanVMs != 7 {
		t.Errorf("contract values: agg=%v clean=%v, want 0.42/7", val.AggDutyLong, val.CleanVMs)
	}
}

// TestBuildLoadValueSelfPressure verifies the self-pressure fields flow from
// the monitor into the published record, in both the pressured and
// not-pressured states, and that a nil monitor (single-node) publishes
// zeros/false rather than skipping the fields (they are part of the contract).
func TestBuildLoadValueSelfPressure(t *testing.T) {
	pm := pool.NewManager(nil, slog.Default())
	pm.AddNode("n1")
	pm.UpdateNodeCapacity("n1", []pool.SpecCapacity{{SpecID: "s", Total: 1}})

	mon := lease.NewSelfPressureMonitor(85, 0.9, 10, nil)
	mon.SetPressureForTest(91.5, 0.42, true)
	val := buildLoadValue("gw-1", pm, mon)
	if !val.SelfPressured {
		t.Errorf("SelfPressured = false, want true")
	}
	if val.SelfCPUPct != 91.5 || val.SelfMemPct != 0.42 {
		t.Errorf("self cpu/mem = %v/%v, want 91.5/0.42", val.SelfCPUPct, val.SelfMemPct)
	}

	mon.SetPressureForTest(12.0, 0.30, false)
	val = buildLoadValue("gw-1", pm, mon)
	if val.SelfPressured {
		t.Errorf("SelfPressured = true, want false")
	}
	if val.SelfCPUPct != 12.0 || val.SelfMemPct != 0.30 {
		t.Errorf("self cpu/mem = %v/%v, want 12.0/0.30", val.SelfCPUPct, val.SelfMemPct)
	}

	// nil monitor (single-node): fields present but zero/false.
	val = buildLoadValue("gw-1", pm, nil)
	if val.SelfPressured || val.SelfCPUPct != 0 || val.SelfMemPct != 0 || val.SelfInflight != 0 {
		t.Errorf("nil monitor: expected zero self fields, got %+v", val)
	}
}

// TestStartLoadPublisherNilClient verifies the single-node guard: with a nil
// etcd client (single-node mode) the publisher is a no-op - no goroutine, no
// panic. The etcd publish loop itself requires a live etcd (integration tier).
func TestStartLoadPublisherNilClient(t *testing.T) {
	pm := pool.NewManager(nil, slog.Default())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Must return synchronously without starting any loop.
	startLoadPublisher(ctx, nil, "gw-1", pm, nil, slog.Default())
}

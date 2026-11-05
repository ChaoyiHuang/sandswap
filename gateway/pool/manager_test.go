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

package pool_test

import (
	"log/slog"
	"testing"

	"gateway/pool"
)

func TestAcquireNoNodes(t *testing.T) {
	pm := pool.NewManager(nil, slog.New(slog.DiscardHandler))
	if _, _, err := pm.Acquire("", 0, 0); err == nil {
		t.Error("expected error acquiring with no connected nodes")
	}
	if pm.NodeCount() != 0 {
		t.Errorf("expected 0 nodes, got %d", pm.NodeCount())
	}
}

func TestAcquirePrefersNodeWithMostCapacity(t *testing.T) {
	pm := pool.NewManager(nil, slog.New(slog.DiscardHandler))
	pm.AddNode("node1")
	pm.AddNode("node2")
	pm.UpdateNodeCapacity("node1", []pool.SpecCapacity{{SpecID: "small", Clean: 1, Total: 2}})
	pm.UpdateNodeCapacity("node2", []pool.SpecCapacity{{SpecID: "small", Clean: 3, Total: 3}})

	// No preferred node -> picks the node with the most clean fitting capacity.
	node, _, err := pm.Acquire("", 0, 0)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if node != "node2" {
		t.Errorf("expected node2 (most clean), got %s", node)
	}

	// Preferred node with capacity -> preferred (cache affinity).
	node, _, err = pm.Acquire("node1", 0, 0)
	if err != nil {
		t.Fatalf("acquire preferred: %v", err)
	}
	if node != "node1" {
		t.Errorf("expected node1 (preferred), got %s", node)
	}

	// Preferred node WITHOUT fitting capacity -> falls back to best capacity.
	pm.UpdateNodeCapacity("node1", []pool.SpecCapacity{{SpecID: "small", Total: 2}})
	for i := 0; i < 2; i++ {
		pm.ReserveBound("node1", "small")
	} // drain: clean = total - bound = 0
	node, _, err = pm.Acquire("node1", 0, 0)
	if err != nil {
		t.Fatalf("acquire after preferred drained: %v", err)
	}
	if node != "node2" {
		t.Errorf("expected node2 (preferred drained), got %s", node)
	}
}

func TestAcquireMinSpec(t *testing.T) {
	pm := pool.NewManager(nil, slog.New(slog.DiscardHandler))
	pm.AddNode("node1")
	pm.AddNode("node2")
	pm.UpdateNodeCapacity("node1", []pool.SpecCapacity{{SpecID: "small", Clean: 1, Total: 1}})
	pm.UpdateNodeCapacity("node2", []pool.SpecCapacity{{SpecID: "medium", Clean: 1, Total: 1}})

	// minSpec=medium (2 vcpu / 512MB): node1's small VMs don't satisfy -> node2.
	node, _, err := pm.Acquire("", 2, 512)
	if err != nil {
		t.Fatalf("acquire medium: %v", err)
	}
	if node != "node2" {
		t.Errorf("expected node2 (only medium capacity), got %s", node)
	}

	// minSpec=small (1 vcpu / 128MB): node1 satisfies.
	node, _, err = pm.Acquire("", 1, 128)
	if err != nil {
		t.Fatalf("acquire small: %v", err)
	}
	if node != "node2" { // node2 has more clean (1==1, tie -> first wins by map order; assert it's one of them)
		if node != "node1" {
			t.Errorf("expected node1 or node2 for small, got %s", node)
		}
	}

	// No clean capacity at all -> error.
	pm.UpdateNodeCapacity("node1", []pool.SpecCapacity{{SpecID: "small", Total: 1}})
	for i := 0; i < 1; i++ {
		pm.ReserveBound("node1", "small")
	} // drain: clean = total - bound = 0
	pm.UpdateNodeCapacity("node2", []pool.SpecCapacity{{SpecID: "medium", Total: 1}})
	for i := 0; i < 1; i++ {
		pm.ReserveBound("node2", "medium")
	} // drain: clean = total - bound = 0
	if _, _, err := pm.Acquire("", 0, 0); err == nil {
		t.Error("expected error when no node has clean capacity")
	}
}

func TestStatsAndRemoveNode(t *testing.T) {
	pm := pool.NewManager(nil, slog.New(slog.DiscardHandler))
	pm.AddNode("node1")
	pm.AddNode("node2")
	pm.UpdateNodeCapacity("node1", []pool.SpecCapacity{{SpecID: "small", Clean: 1, Total: 2}, {SpecID: "medium", Clean: 2, Total: 2}})
	pm.UpdateNodeCapacity("node2", []pool.SpecCapacity{{SpecID: "large", Clean: 1, Total: 1}})
	// small: 1 clean/2 total -> 1 bound (clean<total via the derived-clean rule).
	pm.ReserveBound("node1", "small")

	stats := pm.Stats()
	if stats["CLEAN"] != 4 {
		t.Errorf("expected 4 CLEAN, got %v", stats)
	}
	if stats["node_count"] != 2 {
		t.Errorf("expected 2 nodes, got %v", stats)
	}

	pm.RemoveNode("node2")
	if !pm.HasNode("node1") || pm.HasNode("node2") {
		t.Error("expected node1 present, node2 removed")
	}
	stats = pm.Stats()
	if stats["CLEAN"] != 3 {
		t.Errorf("expected 3 CLEAN after remove, got %v", stats)
	}
	if stats["node_count"] != 1 {
		t.Errorf("expected 1 node after remove, got %v", stats)
	}
}

func TestNodeMetricsSnapshot(t *testing.T) {
	pm := pool.NewManager(nil, slog.New(slog.DiscardHandler))
	pm.AddNode("node1")
	pm.AddNode("node2")

	// No metrics yet -> LoadSnapshot empty.
	if snap := pm.LoadSnapshot(); len(snap) != 0 {
		t.Errorf("expected empty load snapshot, got %v", snap)
	}

	pm.UpdateNodeMetrics("node1", pool.NodeMetrics{
		DutyLong: 0.4, DutyShort: 0.3, HostCPU: 50, HostMemAvailMB: 2048,
		ActiveSandfs: 3, TotalVMs: 5,
	})
	pm.UpdateNodeCapacity("node1", []pool.SpecCapacity{{SpecID: "small", Clean: 1, Total: 2}, {SpecID: "medium", Clean: 1, Total: 1}})
	pm.UpdateNodeCapacity("node2", []pool.SpecCapacity{{SpecID: "large", Clean: 2, Total: 2}})
	// Clean is DERIVED (total - bound), not the heartbeat's Clean
	// (diagnostics only). Reserve one medium VM on node1 so its clean = 3-1 = 2,
	// expressing the drained state the old Clean-authoritative model implied.
	pm.ReserveBound("node1", "medium")

	snap := pm.LoadSnapshot()
	if len(snap) != 1 {
		t.Fatalf("expected 1 node with metrics, got %d: %v", len(snap), snap)
	}
	if m := snap["node1"]; m.DutyLong != 0.4 || m.ActiveSandfs != 3 {
		t.Errorf("unexpected node1 metrics: %+v", m)
	}

	// Clean counts: node1 clean=2 total=3, node2 clean=2 total=2 (capacity only).
	counts := pm.NodeCleanCounts()
	if c := counts["node1"]; c[0] != 2 || c[1] != 3 {
		t.Errorf("expected node1 clean=2 total=3, got %v", c)
	}
	if c := counts["node2"]; c[0] != 2 || c[1] != 2 {
		t.Errorf("expected node2 clean=2 total=2, got %v", c)
	}

	// Empty heartbeat replaces capacity + metrics are independent.
	pm.UpdateNodeCapacity("node1", nil)
	counts = pm.NodeCleanCounts()
	if c := counts["node1"]; c[0] != 0 {
		t.Errorf("expected node1 clean=0 after empty capacity, got %v", c)
	}
	if snap := pm.LoadSnapshot(); len(snap) != 1 {
		t.Errorf("metrics should survive capacity update, got %d nodes", len(snap))
	}
}

// spreadPolicy returns the spread policy (binpack is the built-in default).
func spreadPolicy() pool.SchedPolicy {
	p := pool.DefaultSchedPolicy()
	p.Binpack = false
	return p
}

// TestAcquirePrefersIdleNode verifies the spread scorer prefers a low-duty node
// over a busy one with more clean capacity.
func TestAcquirePrefersIdleNode(t *testing.T) {
	pm := pool.NewManager(nil, slog.New(slog.DiscardHandler))
	pm.SetSchedPolicy(spreadPolicy())
	pm.AddNode("node-busy")
	pm.AddNode("node-idle")
	pm.UpdateNodeCapacity("node-busy", []pool.SpecCapacity{{SpecID: "small", Clean: 5, Total: 5}})
	pm.UpdateNodeCapacity("node-idle", []pool.SpecCapacity{{SpecID: "small", Clean: 1, Total: 1}})
	pm.UpdateNodeMetrics("node-busy", pool.NodeMetrics{DutyLong: 0.9, HostCPU: 80})
	pm.UpdateNodeMetrics("node-idle", pool.NodeMetrics{DutyLong: 0.1, HostCPU: 20})

	node, _, err := pm.Acquire("", 0, 0)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if node != "node-idle" {
		t.Errorf("expected node-idle (low duty), got %s", node)
	}
}

// TestAcquireAffinityPreferred verifies the preferredNode (ownership affinity)
// wins over a higher-scored other node while eligible.
func TestAcquireAffinityPreferred(t *testing.T) {
	pm := pool.NewManager(nil, slog.New(slog.DiscardHandler))
	pm.AddNode("node-preferred")
	pm.AddNode("node-idle")
	pm.UpdateNodeCapacity("node-preferred", []pool.SpecCapacity{{SpecID: "small", Clean: 1, Total: 1}})
	pm.UpdateNodeCapacity("node-idle", []pool.SpecCapacity{{SpecID: "small", Clean: 3, Total: 3}})
	pm.UpdateNodeMetrics("node-preferred", pool.NodeMetrics{DutyLong: 0.9, HostCPU: 80})
	pm.UpdateNodeMetrics("node-idle", pool.NodeMetrics{DutyLong: 0.0, HostCPU: 10})

	// Preferred node is busy but eligible -> affinity wins (cache warmth).
	node, _, err := pm.Acquire("node-preferred", 0, 0)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if node != "node-preferred" {
		t.Errorf("expected node-preferred (affinity), got %s", node)
	}

	// Preferred node drained (no clean) -> filtered, falls to scorer (node-idle).
	pm.UpdateNodeCapacity("node-preferred", []pool.SpecCapacity{{SpecID: "small", Total: 1}})
	for i := 0; i < 1; i++ {
		pm.ReserveBound("node-preferred", "small")
	} // drain: clean = total - bound = 0
	node, _, err = pm.Acquire("node-preferred", 0, 0)
	if err != nil {
		t.Fatalf("acquire after drain: %v", err)
	}
	if node != "node-idle" {
		t.Errorf("expected node-idle (preferred drained), got %s", node)
	}
}

// TestAcquireFilterCaps verifies the hard duty cap excludes a saturated node.
func TestAcquireFilterCaps(t *testing.T) {
	pm := pool.NewManager(nil, slog.New(slog.DiscardHandler))
	pm.AddNode("node-busy")
	pm.AddNode("node-idle")
	pm.UpdateNodeCapacity("node-busy", []pool.SpecCapacity{{SpecID: "small", Clean: 5, Total: 5}})
	pm.UpdateNodeCapacity("node-idle", []pool.SpecCapacity{{SpecID: "small", Clean: 1, Total: 1}})
	pm.UpdateNodeMetrics("node-busy", pool.NodeMetrics{DutyLong: 0.9, HostCPU: 80})
	pm.UpdateNodeMetrics("node-idle", pool.NodeMetrics{DutyLong: 0.1, HostCPU: 20})
	pm.SetSchedPolicy(pool.SchedPolicy{WLoad: 0.6, WHost: 0.3, WClean: 0.1, DutyHard: 0.5})

	node, _, err := pm.Acquire("node-busy", 0, 0)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	// node-busy is filtered by dutyHard=0.5 (duty 0.9) -> node-idle even as
	// the preferred node.
	if node != "node-idle" {
		t.Errorf("expected node-idle (busy node filtered), got %s", node)
	}
}

// TestAcquireBinpack verifies the binpack policy prefers the busy node.
func TestAcquireBinpack(t *testing.T) {
	pm := pool.NewManager(nil, slog.New(slog.DiscardHandler))
	pm.AddNode("node-busy")
	pm.AddNode("node-idle")
	pm.UpdateNodeCapacity("node-busy", []pool.SpecCapacity{{SpecID: "small", Clean: 1, Total: 1}})
	pm.UpdateNodeCapacity("node-idle", []pool.SpecCapacity{{SpecID: "small", Clean: 1, Total: 1}})
	pm.UpdateNodeMetrics("node-busy", pool.NodeMetrics{DutyLong: 0.9, HostCPU: 80})
	pm.UpdateNodeMetrics("node-idle", pool.NodeMetrics{DutyLong: 0.1, HostCPU: 20})
	pm.SetSchedPolicy(pool.SchedPolicy{Binpack: true, WLoad: 0.6, WHost: 0.3, WClean: 0.1})

	node, _, err := pm.Acquire("", 0, 0)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if node != "node-busy" {
		t.Errorf("expected node-busy (binpack prefers busy), got %s", node)
	}
}

// TestAcquireBinpackCleanNormalized is the regression test for the clean-term
// normalization: the WClean term used to be the RAW fitting-clean count (no
// upper bound), so a large-pool idle node's WClean*30 = 3.0 swamped a busy
// node's entire WLoad*0.9 = 0.54 — binpack was inert whenever clean counts
// differed by more than ~6. With cleanFrac (clean / pool target) the duty term
// decides again: the busy node wins despite far fewer clean VMs.
func TestAcquireBinpackCleanNormalized(t *testing.T) {
	pm := pool.NewManager(nil, slog.New(slog.DiscardHandler))
	pm.AddNode("node-busy")
	pm.AddNode("node-idle")
	pm.SetNodePoolTarget("node-busy", 2)
	pm.SetNodePoolTarget("node-idle", 40)
	pm.UpdateNodeCapacity("node-busy", []pool.SpecCapacity{{SpecID: "small", Clean: 2, Total: 2}})
	pm.UpdateNodeCapacity("node-idle", []pool.SpecCapacity{{SpecID: "small", Clean: 30, Total: 40}})
	pm.UpdateNodeMetrics("node-busy", pool.NodeMetrics{DutyLong: 0.9, HostCPU: 0})
	pm.UpdateNodeMetrics("node-idle", pool.NodeMetrics{DutyLong: 0.1, HostCPU: 0})
	pm.SetSchedPolicy(pool.SchedPolicy{Binpack: true, WLoad: 0.6, WHost: 0.3, WClean: 0.1, WDaily: 0.2})

	node, _, err := pm.Acquire("", 0, 0)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if node != "node-busy" {
		t.Errorf("expected node-busy (duty term must decide once clean is normalized), got %s", node)
	}
}

// TestAcquireCleanFracClusterMaxFallback verifies that a node without a pool
// target is normalized by the CLUSTER MAX pool target, not its raw count: with
// node-a (no target, clean 1) scored against node-b (target 10, clean 1),
// node-a's cleanFrac must be 1/10 — if the fallback were the raw count (1.0),
// node-a's WClean term would outweigh its duty deficit and it would win, which
// is exactly the unbounded-term defect this normalization removes.
func TestAcquireCleanFracClusterMaxFallback(t *testing.T) {
	pm := pool.NewManager(nil, slog.New(slog.DiscardHandler))
	pm.AddNode("node-a")
	pm.AddNode("node-b")
	pm.SetNodePoolTarget("node-b", 10)
	pm.UpdateNodeCapacity("node-a", []pool.SpecCapacity{{SpecID: "small", Clean: 1, Total: 1}})
	pm.UpdateNodeCapacity("node-b", []pool.SpecCapacity{{SpecID: "small", Clean: 1, Total: 1}})
	pm.UpdateNodeMetrics("node-a", pool.NodeMetrics{DutyLong: 0.3, HostCPU: 0})
	pm.UpdateNodeMetrics("node-b", pool.NodeMetrics{DutyLong: 0.4, HostCPU: 0})
	pm.SetSchedPolicy(pool.SchedPolicy{Binpack: true, WLoad: 0.6, WHost: 0.3, WClean: 0.1, WDaily: 0.2})

	node, _, err := pm.Acquire("", 0, 0)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if node != "node-b" {
		t.Errorf("expected node-b (node-a normalized by cluster max target, its duty deficit decides), got %s", node)
	}
}

// TestAcquireTailFloorRejectsSpikyNode verifies the 60s min-clean-window floor
// excludes a host-saturated node that recently hit zero clean (even if it
// currently has one), but NOT a low-CPU node (pool too small, not saturated).
func TestAcquireTailFloorRejectsSpikyNode(t *testing.T) {
	pm := pool.NewManager(nil, slog.New(slog.DiscardHandler))
	pm.AddNode("node-spiky")
	pm.AddNode("node-stable")
	pm.SetNodePoolTarget("node-spiky", 2)
	pm.SetNodePoolTarget("node-stable", 2)
	pm.UpdateNodeCapacity("node-spiky", []pool.SpecCapacity{{SpecID: "small", Clean: 1, Total: 2, MinCleanWindow: 0}})
	pm.UpdateNodeCapacity("node-stable", []pool.SpecCapacity{{SpecID: "small", Clean: 1, Total: 2, MinCleanWindow: 1}})
	// node-spiky is host-saturated (85% CPU) + hit zero clean -> floor rejects.
	pm.UpdateNodeMetrics("node-spiky", pool.NodeMetrics{HostCPU: 85})
	pm.UpdateNodeMetrics("node-stable", pool.NodeMetrics{HostCPU: 20})

	node, _, err := pm.Acquire("", 0, 0)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if node != "node-stable" {
		t.Errorf("expected node-stable (spiky+host-saturated node below floor), got %s", node)
	}
}

// TestAcquireTailFloorLowCPU not rejected: a node that hit zero clean but has
// low host CPU is NOT excluded (its pool is just too small for the
// min-idle floor; see docs/how-it-works/resilience.md).
func TestAcquireTailFloorLowCPU(t *testing.T) {
	pm := pool.NewManager(nil, slog.New(slog.DiscardHandler))
	pm.AddNode("node-small-pool")
	pm.SetNodePoolTarget("node-small-pool", 2)
	pm.UpdateNodeCapacity("node-small-pool", []pool.SpecCapacity{{SpecID: "small", Clean: 1, Total: 2, MinCleanWindow: 0}})
	pm.UpdateNodeMetrics("node-small-pool", pool.NodeMetrics{HostCPU: 20})

	node, _, err := pm.Acquire("", 0, 0)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if node != "node-small-pool" {
		t.Errorf("expected node-small-pool (low CPU, floor not applied), got %s", node)
	}
}

// TestAcquireTailFloorNoPoolTarget verifies the floor is skipped when the node
// has no pool_target (0 = no cap) — bootstrap/uncapped nodes pass.
func TestAcquireTailFloorNoPoolTarget(t *testing.T) {
	pm := pool.NewManager(nil, slog.New(slog.DiscardHandler))
	pm.AddNode("node-uncapped")
	pm.UpdateNodeCapacity("node-uncapped", []pool.SpecCapacity{{SpecID: "small", Clean: 1, Total: 1, MinCleanWindow: 0}})

	node, _, err := pm.Acquire("", 0, 0)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if node != "node-uncapped" {
		t.Errorf("expected node-uncapped (no pool_target, floor skipped), got %s", node)
	}
}

// TestAcquirePrefersDurableHeadroom verifies the spread scorer prefers a node
// with low duty_daily (durable headroom) over a momentarily-idle but
// chronically-busy node (long-window placement).
func TestAcquirePrefersDurableHeadroom(t *testing.T) {
	pm := pool.NewManager(nil, slog.New(slog.DiscardHandler))
	pm.SetSchedPolicy(spreadPolicy())
	pm.AddNode("node-idle-now")
	pm.AddNode("node-durable")
	pm.UpdateNodeCapacity("node-idle-now", []pool.SpecCapacity{{SpecID: "small", Clean: 1, Total: 1}})
	pm.UpdateNodeCapacity("node-durable", []pool.SpecCapacity{{SpecID: "small", Clean: 1, Total: 1}})
	// node-idle-now: idle right now but chronically busy (duty_daily 0.9).
	pm.UpdateNodeMetrics("node-idle-now", pool.NodeMetrics{DutyLong: 0.1, DutyDaily: 0.9, HostCPU: 20})
	// node-durable: moderately busy now but durable headroom (duty_daily 0.1).
	pm.UpdateNodeMetrics("node-durable", pool.NodeMetrics{DutyLong: 0.3, DutyDaily: 0.1, HostCPU: 20})

	node, _, err := pm.Acquire("", 0, 0)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if node != "node-durable" {
		t.Errorf("expected node-durable (low duty_daily, durable headroom), got %s", node)
	}
}

// TestAcquireBinpackPrefersBusyNode verifies the binpack default picks the
// busiest eligible node (work concentrates onto fewer nodes).
func TestAcquireBinpackPrefersBusyNode(t *testing.T) {
	pm := pool.NewManager(nil, slog.New(slog.DiscardHandler)) // default = binpack
	pm.AddNode("node-busy")
	pm.AddNode("node-idle")
	pm.UpdateNodeCapacity("node-busy", []pool.SpecCapacity{{SpecID: "small", Clean: 1, Total: 1}})
	pm.UpdateNodeCapacity("node-idle", []pool.SpecCapacity{{SpecID: "small", Clean: 1, Total: 1}})
	pm.UpdateNodeMetrics("node-busy", pool.NodeMetrics{DutyLong: 0.9, HostCPU: 80})
	pm.UpdateNodeMetrics("node-idle", pool.NodeMetrics{DutyLong: 0.1, HostCPU: 20})

	node, _, err := pm.Acquire("", 0, 0)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if node != "node-busy" {
		t.Errorf("expected node-busy (binpack prefers busy), got %s", node)
	}
}

// TestNodeScoreRiskPenalizesSpiky verifies the WRisk tail penalty: under binpack,
// a busy-but-spiky node (high 60s peak duty + zero-clean frequency) loses to a
// stable node with equal average duty, so binpack avoids packing onto a node
// that keeps tipping into no-clean-VM contention.
func TestNodeScoreRiskPenalizesSpiky(t *testing.T) {
	pm := pool.NewManager(nil, slog.New(slog.DiscardHandler)) // default = binpack
	pm.AddNode("node-stable")
	pm.AddNode("node-spiky")
	pm.UpdateNodeCapacity("node-stable", []pool.SpecCapacity{{SpecID: "small", Clean: 1, Total: 2}})
	pm.UpdateNodeCapacity("node-spiky", []pool.SpecCapacity{{SpecID: "small", Clean: 1, Total: 2, ZeroCleanCount: 5}})
	// Equal average duty; spiky has a 100% peak window + volatility.
	pm.UpdateNodeMetrics("node-stable", pool.NodeMetrics{DutyLong: 0.6, DutyVar: 0.0, MaxDutyWindow: 0.6, HostCPU: 30})
	pm.UpdateNodeMetrics("node-spiky", pool.NodeMetrics{DutyLong: 0.6, DutyVar: 0.2, MaxDutyWindow: 1.0, HostCPU: 30})

	node, _, err := pm.Acquire("", 0, 0)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if node != "node-stable" {
		t.Errorf("expected node-stable (WRisk penalizes spiky), got %s", node)
	}
}

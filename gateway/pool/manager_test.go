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
	"context"
	"errors"
	"log/slog"
	"sync"
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

// -----------------------------------------------------------------------
// Node management: AddNode (idempotent), RemoveNode (unknown), NodeIDs,
// HasNode, NodeCount.
// -----------------------------------------------------------------------

// TestAddNodeIdempotent verifies adding the same node ID twice does not create
// a duplicate or reset existing capacity/metrics.
func TestAddNodeIdempotent(t *testing.T) {
	pm := pool.NewManager(nil, slog.New(slog.DiscardHandler))
	pm.AddNode("node-1")
	pm.UpdateNodeCapacity("node-1", []pool.SpecCapacity{{SpecID: "small", Total: 3}})
	// Clean is derived (total - bound). Reserve one so clean=2,
	// expressing a drained state the old Clean-authoritative model implied.
	pm.ReserveBound("node-1", "small")
	pm.UpdateNodeMetrics("node-1", pool.NodeMetrics{DutyLong: 0.5})

	// Re-add: must not wipe state (capacity, bound, or metrics).
	pm.AddNode("node-1")
	if pm.NodeCount() != 1 {
		t.Errorf("expected 1 node after re-add, got %d", pm.NodeCount())
	}
	counts := pm.NodeCleanCounts()
	if c := counts["node-1"]; c[0] != 2 || c[1] != 3 {
		t.Errorf("capacity wiped by re-add: got clean=%d total=%d, want 2/3", c[0], c[1])
	}
	snap := pm.LoadSnapshot()
	if m := snap["node-1"]; m.DutyLong != 0.5 {
		t.Errorf("metrics wiped by re-add: DutyLong=%v, want 0.5", m.DutyLong)
	}
}

// TestRemoveNodeUnknown is a no-op (no panic, no side effect).
func TestRemoveNodeUnknown(t *testing.T) {
	pm := pool.NewManager(nil, slog.New(slog.DiscardHandler))
	pm.RemoveNode("no-such-node")
	if pm.NodeCount() != 0 {
		t.Errorf("expected 0 nodes, got %d", pm.NodeCount())
	}
}

// TestNodeIDsAndHasNode verifies the node listing and membership queries
// reflect the connected set.
func TestNodeIDsAndHasNode(t *testing.T) {
	pm := pool.NewManager(nil, slog.New(slog.DiscardHandler))
	pm.AddNode("node-a")
	pm.AddNode("node-b")
	pm.AddNode("node-c")

	if !pm.HasNode("node-a") || !pm.HasNode("node-b") || !pm.HasNode("node-c") {
		t.Error("HasNode returned false for a connected node")
	}
	if pm.HasNode("node-x") {
		t.Error("HasNode returned true for an unknown node")
	}
	if pm.NodeCount() != 3 {
		t.Errorf("NodeCount: got %d, want 3", pm.NodeCount())
	}

	ids := pm.NodeIDs()
	if len(ids) != 3 {
		t.Fatalf("NodeIDs: got %v, want 3 entries", ids)
	}
	if !containsNode(ids, "node-a") || !containsNode(ids, "node-b") || !containsNode(ids, "node-c") {
		t.Errorf("NodeIDs missing entries: %v", ids)
	}

	// Remove one - drops out of all queries.
	pm.RemoveNode("node-b")
	if pm.HasNode("node-b") {
		t.Error("HasNode returned true for removed node")
	}
	if pm.NodeCount() != 2 {
		t.Errorf("NodeCount after remove: got %d, want 2", pm.NodeCount())
	}
	ids = pm.NodeIDs()
	if containsNode(ids, "node-b") {
		t.Errorf("node-b should be gone from NodeIDs: %v", ids)
	}
}

func containsNode(ids []string, want string) bool {
	for _, id := range ids {
		if id == want {
			return true
		}
	}
	return false
}

// -----------------------------------------------------------------------
// UpdateNodeCapacity / UpdateNodeMetrics edge cases.
// -----------------------------------------------------------------------

// TestUpdateNodeCapacityUnknownNode is a no-op for a node that was never added.
func TestUpdateNodeCapacityUnknownNode(t *testing.T) {
	pm := pool.NewManager(nil, slog.New(slog.DiscardHandler))
	pm.UpdateNodeCapacity("ghost", []pool.SpecCapacity{{SpecID: "small", Total: 1}})
	if pm.HasNode("ghost") {
		t.Error("UpdateNodeCapacity should not create a node")
	}
	counts := pm.NodeCleanCounts()
	if _, ok := counts["ghost"]; ok {
		t.Error("ghost should not appear in NodeCleanCounts")
	}
}

// TestUpdateNodeMetricsUnknownNode is a no-op for a node that was never added.
func TestUpdateNodeMetricsUnknownNode(t *testing.T) {
	pm := pool.NewManager(nil, slog.New(slog.DiscardHandler))
	pm.UpdateNodeMetrics("ghost", pool.NodeMetrics{DutyLong: 0.5})
	snap := pm.LoadSnapshot()
	if _, ok := snap["ghost"]; ok {
		t.Error("ghost should not appear in LoadSnapshot")
	}
}

// TestUpdateNodeCapacityReplacesNotMerges verifies an empty heartbeat REPLACES
// the capacity map (stale entries must not persist - a stale non-zero count
// would keep the node routable forever per the doc comment).
func TestUpdateNodeCapacityReplacesNotMerges(t *testing.T) {
	pm := pool.NewManager(nil, slog.New(slog.DiscardHandler))
	pm.AddNode("node-1")
	pm.UpdateNodeCapacity("node-1", []pool.SpecCapacity{
		{SpecID: "small", Total: 3},
		{SpecID: "medium", Total: 1},
	})

	// Replace with a single-spec heartbeat - the old "medium" entry is gone.
	pm.UpdateNodeCapacity("node-1", []pool.SpecCapacity{{SpecID: "small", Total: 1}})
	counts := pm.NodeCleanCounts()
	if c := counts["node-1"]; c[0] != 1 || c[1] != 1 {
		t.Errorf("after replace: got clean=%d total=%d, want 1/1", c[0], c[1])
	}

	// Empty heartbeat -> all capacity gone (node has no live VMs).
	pm.UpdateNodeCapacity("node-1", nil)
	counts = pm.NodeCleanCounts()
	if c := counts["node-1"]; c[0] != 0 || c[1] != 0 {
		t.Errorf("after empty heartbeat: got clean=%d total=%d, want 0/0", c[0], c[1])
	}
}

// TestSetNodePoolTarget verifies the pool target is stored and survives until
// changed. Used by the tail-floor gate in nodeEligible.
func TestSetNodePoolTarget(t *testing.T) {
	pm := pool.NewManager(nil, slog.New(slog.DiscardHandler))
	pm.AddNode("node-1")
	pm.SetNodePoolTarget("node-1", 10)
	// Indirectly verify: the tail floor uses PoolTarget. A node with
	// MinCleanWindow=0, HostCPU>=80, and PoolTarget=2 is rejected.
	pm.UpdateNodeCapacity("node-1", []pool.SpecCapacity{{SpecID: "small", Total: 2, MinCleanWindow: 0}})
	pm.UpdateNodeMetrics("node-1", pool.NodeMetrics{HostCPU: 85})
	pm.SetNodePoolTarget("node-1", 2)

	if _, _, err := pm.Acquire("", 0, 0); err == nil {
		t.Error("expected node rejected by tail floor (PoolTarget=2, MinCleanWindow=0, HostCPU=85)")
	}

	// Raise MinCleanWindow above the floor -> node passes.
	pm.UpdateNodeCapacity("node-1", []pool.SpecCapacity{{SpecID: "small", Total: 2, MinCleanWindow: 1}})
	node, _, err := pm.Acquire("", 0, 0)
	if err != nil || node != "node-1" {
		t.Errorf("expected node-1 after raising MinCleanWindow, got %q err=%v", node, err)
	}
}

// TestSetNodePoolTargetUnknownNode is a no-op (no panic).
func TestSetNodePoolTargetUnknownNode(t *testing.T) {
	pm := pool.NewManager(nil, slog.New(slog.DiscardHandler))
	pm.SetNodePoolTarget("ghost", 10)
	// No panic, no node created.
	if pm.NodeCount() != 0 {
		t.Error("SetNodePoolTarget should not create a node")
	}
}

// -----------------------------------------------------------------------
// Acquire edge cases: preferred node not connected, wrong spec, filtered by
// host CPU cap, no eligible node error, tie-break on clean.
// -----------------------------------------------------------------------

// TestAcquirePreferredNotConnected verifies a preferred node that is not in the
// registry falls back to the scorer (no error, no stale routing).
func TestAcquirePreferredNotConnected(t *testing.T) {
	pm := pool.NewManager(nil, slog.New(slog.DiscardHandler))
	pm.AddNode("node-1")
	pm.UpdateNodeCapacity("node-1", []pool.SpecCapacity{{SpecID: "small", Total: 1}})

	node, _, err := pm.Acquire("node-missing", 0, 0)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if node != "node-1" {
		t.Errorf("expected fallback to node-1, got %s", node)
	}
}

// TestAcquirePreferredWrongSpec verifies a preferred node whose clean VMs do
// NOT satisfy minSpec falls back to the scorer.
func TestAcquirePreferredWrongSpec(t *testing.T) {
	pm := pool.NewManager(nil, slog.New(slog.DiscardHandler))
	pm.AddNode("node-pref")
	pm.AddNode("node-other")
	// node-pref only has small VMs (1 vcpu/128MB); minSpec=medium (2 vcpu/512MB).
	pm.UpdateNodeCapacity("node-pref", []pool.SpecCapacity{{SpecID: "small", Total: 1}})
	pm.UpdateNodeCapacity("node-other", []pool.SpecCapacity{{SpecID: "large", Total: 1}})

	node, _, err := pm.Acquire("node-pref", 2, 512)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if node != "node-other" {
		t.Errorf("expected fallback to node-other (large satisfies medium), got %s", node)
	}
}

// TestAcquirePreferredFilteredByHostCPUCap verifies the HostCPUHard filter
// (separate from DutyHard) excludes the preferred node.
func TestAcquirePreferredFilteredByHostCPUCap(t *testing.T) {
	pm := pool.NewManager(nil, slog.New(slog.DiscardHandler))
	pm.AddNode("node-pref")
	pm.AddNode("node-other")
	pm.UpdateNodeCapacity("node-pref", []pool.SpecCapacity{{SpecID: "small", Total: 1}})
	pm.UpdateNodeCapacity("node-other", []pool.SpecCapacity{{SpecID: "small", Total: 1}})
	pm.UpdateNodeMetrics("node-pref", pool.NodeMetrics{HostCPU: 95})
	pm.UpdateNodeMetrics("node-other", pool.NodeMetrics{HostCPU: 30})
	pm.SetSchedPolicy(pool.SchedPolicy{WLoad: 0.6, WHost: 0.3, WClean: 0.1, HostCPUHard: 80})

	node, _, err := pm.Acquire("node-pref", 0, 0)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if node != "node-other" {
		t.Errorf("expected node-other (node-pref filtered by HostCPUHard=80, CPU=95), got %s", node)
	}
}

// TestAcquireNoEligibleNodeError verifies the error message when nodes are
// connected but none has fitting clean capacity.
func TestAcquireNoEligibleNodeError(t *testing.T) {
	pm := pool.NewManager(nil, slog.New(slog.DiscardHandler))
	pm.AddNode("node-1")
	pm.AddNode("node-2")
	// Both have VMs but all are IN_USE (clean=0): bind all capacity.
	pm.UpdateNodeCapacity("node-1", []pool.SpecCapacity{{SpecID: "small", Total: 2}})
	pm.UpdateNodeCapacity("node-2", []pool.SpecCapacity{{SpecID: "medium", Total: 1}})
	for i := 0; i < 2; i++ {
		pm.ReserveBound("node-1", "small")
	}
	pm.ReserveBound("node-2", "medium")

	_, _, err := pm.Acquire("", 0, 0)
	if err == nil {
		t.Fatal("expected error when no node has clean capacity")
	}
}

// TestAcquireTieBreakOnClean verifies that when two nodes have the same score,
// the tie-break picks the one with more fitting clean capacity. Both nodes
// have identical metrics (so identical scores); node-2 has more clean VMs.
func TestAcquireTieBreakOnClean(t *testing.T) {
	pm := pool.NewManager(nil, slog.New(slog.DiscardHandler))
	pm.SetSchedPolicy(spreadPolicy())
	pm.AddNode("node-1")
	pm.AddNode("node-2")
	pm.UpdateNodeCapacity("node-1", []pool.SpecCapacity{{SpecID: "small", Total: 1}})
	pm.UpdateNodeCapacity("node-2", []pool.SpecCapacity{{SpecID: "small", Total: 5}})
	// Identical metrics -> identical score -> tie-break on clean.
	pm.UpdateNodeMetrics("node-1", pool.NodeMetrics{DutyLong: 0.3, HostCPU: 30})
	pm.UpdateNodeMetrics("node-2", pool.NodeMetrics{DutyLong: 0.3, HostCPU: 30})

	node, _, err := pm.Acquire("", 0, 0)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if node != "node-2" {
		t.Errorf("expected node-2 (tie-break: more clean=5 vs 1), got %s", node)
	}
}

// TestAcquireBootstrapNoMetrics verifies that when no node has metrics yet, the
// scorer falls back to the clean-capacity proxy (WClean * fittingClean). The
// node with more clean VMs wins.
func TestAcquireBootstrapNoMetrics(t *testing.T) {
	pm := pool.NewManager(nil, slog.New(slog.DiscardHandler))
	// Default policy has WClean=0.1; with no metrics, score = WClean * clean.
	pm.AddNode("node-1")
	pm.AddNode("node-2")
	pm.UpdateNodeCapacity("node-1", []pool.SpecCapacity{{SpecID: "small", Total: 2}})
	pm.UpdateNodeCapacity("node-2", []pool.SpecCapacity{{SpecID: "small", Total: 5}})

	node, _, err := pm.Acquire("", 0, 0)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if node != "node-2" {
		t.Errorf("expected node-2 (bootstrap: more clean=5 vs 2), got %s", node)
	}
}

// -----------------------------------------------------------------------
// Stats edge cases.
// -----------------------------------------------------------------------

// TestStatsEmpty verifies Stats on a manager with no nodes.
func TestStatsEmpty(t *testing.T) {
	pm := pool.NewManager(nil, slog.New(slog.DiscardHandler))
	stats := pm.Stats()
	if stats["CLEAN"] != 0 || stats["IN_USE"] != 0 || stats["node_count"] != 0 {
		t.Errorf("empty manager Stats: got %v, want all zeros", stats)
	}
}

// TestStatsIN_USE verifies IN_USE = total - clean (bound VMs).
func TestStatsIN_USE(t *testing.T) {
	pm := pool.NewManager(nil, slog.New(slog.DiscardHandler))
	pm.AddNode("node-1")
	// small: 2 clean / 5 total -> 3 bound. medium: 1 clean / 2 total -> 1 bound.
	pm.UpdateNodeCapacity("node-1", []pool.SpecCapacity{
		{SpecID: "small", Total: 5},
		{SpecID: "medium", Total: 2},
	})
	for i := 0; i < 3; i++ {
		pm.ReserveBound("node-1", "small")
	}
	pm.ReserveBound("node-1", "medium")
	stats := pm.Stats()
	if stats["CLEAN"] != 3 {
		t.Errorf("CLEAN: got %d, want 3", stats["CLEAN"])
	}
	if stats["IN_USE"] != 4 {
		t.Errorf("IN_USE: got %d, want 4 (total=7, clean=3)", stats["IN_USE"])
	}
	if stats["node_count"] != 1 {
		t.Errorf("node_count: got %d, want 1", stats["node_count"])
	}
}

// -----------------------------------------------------------------------
// UnmountSandfsFromAll / CleanupOverlayForSandFS with a recording fake client.
// -----------------------------------------------------------------------

// recordingClient records every call so tests can assert fan-out.
type recordingClient struct {
	mu         sync.Mutex
	unmounts   []unmountCall
	cleanups   []cleanupCall
	unmountErr error
	cleanupErr error
}

type unmountCall struct {
	nodeID, sandfsID, volumePath string
}

type cleanupCall struct {
	nodeID, volumePath string
}

func (c *recordingClient) UnmountRootfs(_ context.Context, nodeID, sandfsID, volumePath, volumeEpoch string) (pool.UnmountResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.unmounts = append(c.unmounts, unmountCall{nodeID, sandfsID, volumePath})
	return pool.UnmountResult{}, c.unmountErr
}

func (c *recordingClient) MountRootfsAndExecute(_ context.Context, _ pool.ExecRequest) (pool.ExecResult, error) {
	return pool.ExecResult{}, nil
}

func (c *recordingClient) StatusExec(_ context.Context, _, _, _ string) (pool.ExecResult, error) {
	return pool.ExecResult{}, nil
}

func (c *recordingClient) KillExec(_ context.Context, _, _, _ string) error { return nil }

func (c *recordingClient) FileOp(_ context.Context, _ string, _ pool.FileOpRequest) (pool.FileOpResult, error) {
	return pool.FileOpResult{}, nil
}

func (c *recordingClient) CleanupOverlay(_ context.Context, nodeID, volumePath string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cleanups = append(c.cleanups, cleanupCall{nodeID, volumePath})
	return c.cleanupErr
}

// TestUnmountSandfsFromAllFanOut verifies the manager calls UnmountRootfs on
// every connected node (best-effort: errors are logged, not returned).
func TestUnmountSandfsFromAllFanOut(t *testing.T) {
	rc := &recordingClient{}
	pm := pool.NewManager(rc, slog.New(slog.DiscardHandler))
	pm.AddNode("node-1")
	pm.AddNode("node-2")
	pm.AddNode("node-3")

	pm.UnmountSandfsFromAll("sandfs-abc", "/vol/sandfs-abc", "")

	rc.mu.Lock()
	defer rc.mu.Unlock()
	if len(rc.unmounts) != 3 {
		t.Fatalf("expected 3 unmount calls, got %d: %+v", len(rc.unmounts), rc.unmounts)
	}
	seen := map[string]bool{}
	for _, call := range rc.unmounts {
		if call.sandfsID != "sandfs-abc" || call.volumePath != "/vol/sandfs-abc" {
			t.Errorf("unexpected call: %+v", call)
		}
		seen[call.nodeID] = true
	}
	for _, want := range []string{"node-1", "node-2", "node-3"} {
		if !seen[want] {
			t.Errorf("node %q was not called", want)
		}
	}
}

// TestUnmountSandfsFromAllNilClient verifies a nil client is a safe no-op.
func TestUnmountSandfsFromAllNilClient(t *testing.T) {
	pm := pool.NewManager(nil, slog.New(slog.DiscardHandler))
	pm.AddNode("node-1")
	// Must not panic.
	pm.UnmountSandfsFromAll("sandfs-abc", "/vol/sandfs-abc", "")
}

// TestUnmountSandfsFromAllContinuesOnError verifies errors from one node do
// not stop the fan-out to the remaining nodes.
func TestUnmountSandfsFromAllContinuesOnError(t *testing.T) {
	rc := &recordingClient{unmountErr: errors.New("node down")}
	pm := pool.NewManager(rc, slog.New(slog.DiscardHandler))
	pm.AddNode("node-1")
	pm.AddNode("node-2")

	pm.UnmountSandfsFromAll("sandfs-x", "/vol/x", "")

	rc.mu.Lock()
	defer rc.mu.Unlock()
	if len(rc.unmounts) != 2 {
		t.Errorf("expected 2 calls (errors are non-fatal), got %d", len(rc.unmounts))
	}
}

// TestCleanupOverlayForSandFSFanOut verifies the manager calls CleanupOverlay
// on every connected node.
func TestCleanupOverlayForSandFSFanOut(t *testing.T) {
	rc := &recordingClient{}
	pm := pool.NewManager(rc, slog.New(slog.DiscardHandler))
	pm.AddNode("node-1")
	pm.AddNode("node-2")

	pm.CleanupOverlayForSandFS("sandfs-abc", "/vol/sandfs-abc")

	rc.mu.Lock()
	defer rc.mu.Unlock()
	if len(rc.cleanups) != 2 {
		t.Fatalf("expected 2 cleanup calls, got %d: %+v", len(rc.cleanups), rc.cleanups)
	}
	for _, call := range rc.cleanups {
		if call.volumePath != "/vol/sandfs-abc" {
			t.Errorf("unexpected volumePath: %+v", call)
		}
	}
}

// TestCleanupOverlayForSandFSNilClient verifies a nil client is a safe no-op.
func TestCleanupOverlayForSandFSNilClient(t *testing.T) {
	pm := pool.NewManager(nil, slog.New(slog.DiscardHandler))
	pm.AddNode("node-1")
	// Must not panic.
	pm.CleanupOverlayForSandFS("sandfs-abc", "/vol/sandfs-abc")
}

// -----------------------------------------------------------------------
// Concurrency: parallel Acquire / AddNode / RemoveNode / UpdateNodeCapacity.
// -----------------------------------------------------------------------

// TestManagerConcurrency verifies the manager is safe under concurrent access
// (no data races / panics). This is a smoke test, not a correctness proof -
// run with -race for real verification.
func TestManagerConcurrency(t *testing.T) {
	pm := pool.NewManager(nil, slog.New(slog.DiscardHandler))

	var wg sync.WaitGroup
	// Writers: add/remove nodes + update capacity/metrics.
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			nodeID := "node-" + string(rune('a'+idx))
			pm.AddNode(nodeID)
			pm.SetNodePoolTarget(nodeID, 4)
			for j := 0; j < 50; j++ {
				pm.UpdateNodeCapacity(nodeID, []pool.SpecCapacity{
					{SpecID: "small", Clean: uint32(j % 3), Total: uint32(j%5 + 1)},
				})
				pm.UpdateNodeMetrics(nodeID, pool.NodeMetrics{DutyLong: float64(j) / 50.0, HostCPU: float64(j)})
			}
			pm.RemoveNode(nodeID)
		}(i)
	}

	// Readers: Acquire + Stats + NodeIDs + LoadSnapshot.
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_, _, _ = pm.Acquire("", 1, 128)
				_ = pm.Stats()
				_ = pm.NodeIDs()
				_ = pm.LoadSnapshot()
				_ = pm.NodeCleanCounts()
				_ = pm.NodeCount()
			}
		}()
	}
	wg.Wait()
}

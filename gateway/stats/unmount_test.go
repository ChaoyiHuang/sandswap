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

package stats

import (
	"testing"
	"time"

	"gateway/pool"
)

// msToNs converts milliseconds to nanoseconds for the latency fields.
func msToNs(ms uint64) uint64 { return ms * 1_000_000 }

func TestRecordUnmount_CountersAndThresholds(t *testing.T) {
	s := NewUnmountStats(10, 0, nil, "gw", nil)

	// Two cold mounts on node-1 (second overwrites the last command for sfs-A).
	s.RecordMount("node-1", "sfs-A", "python3 -c 'print(1)'")
	s.RecordMount("node-1", "sfs-B", "sleep 5")
	// node-2 gets one mount but no unmounts yet (mount count tracked).
	s.RecordMount("node-2", "sfs-C", "echo hi")

	// Unmounts: 4ms (under 5ms), 7ms (under 10ms), 50ms (slow), failed.
	s.RecordUnmount("node-1", "sfs-A", "lease-expiry",
		pool.UnmountResult{WardenDurationNs: msToNs(1), SandlotDurationNs: msToNs(2), GatewayDurationNs: msToNs(4)}, true)
	s.RecordUnmount("node-1", "sfs-B", "lease-expiry",
		pool.UnmountResult{WardenDurationNs: msToNs(2), SandlotDurationNs: msToNs(3), GatewayDurationNs: msToNs(7)}, true)
	s.RecordUnmount("node-1", "sfs-A", "cleanup-after-failure",
		pool.UnmountResult{WardenDurationNs: msToNs(40), SandlotDurationNs: msToNs(45), GatewayDurationNs: msToNs(50)}, true)
	s.RecordUnmount("node-1", "sfs-X", "lease-expiry",
		pool.UnmountResult{}, false) // failed, gatewayNs=0 → no threshold bump

	snap := s.Snapshot()
	if len(snap) != 1 { // node-2 has mounts but no unmounts → still appears via mount count
		// node-2 recorded a mount so it should appear too.
		if len(snap) != 2 {
			t.Fatalf("snapshot len = %d, want 1 or 2", len(snap))
		}
	}

	var n1 *NodeUnmountStats
	for i := range snap {
		if snap[i].NodeID == "node-1" {
			n1 = &snap[i]
		}
	}
	if n1 == nil {
		t.Fatal("node-1 missing from snapshot")
	}
	if n1.MountCount != 2 {
		t.Errorf("mount_count = %d, want 2", n1.MountCount)
	}
	if n1.UnmountCount != 4 {
		t.Errorf("unmount_count = %d, want 4", n1.UnmountCount)
	}
	if n1.UnmountSuccess != 3 || n1.UnmountFail != 1 {
		t.Errorf("success/fail = %d/%d, want 3/1", n1.UnmountSuccess, n1.UnmountFail)
	}
	if n1.Under5ms != 1 {
		t.Errorf("under_5ms = %d, want 1", n1.Under5ms)
	}
	if n1.Under10ms != 2 {
		t.Errorf("under_10ms = %d, want 2", n1.Under10ms)
	}
}

func TestTopSlow_FixedCapAndOrder(t *testing.T) {
	s := NewUnmountStats(3, 0, nil, "gw", nil) // topN=3
	dur := []uint64{10, 50, 30, 90, 20, 70}
	for _, d := range dur {
		s.RecordMount("n", "sfs", "cmd")
		s.RecordUnmount("n", "sfs", "r",
			pool.UnmountResult{GatewayDurationNs: msToNs(d)}, true)
	}
	var n *NodeUnmountStats
	snap := s.Snapshot()
	for i := range snap {
		if snap[i].NodeID == "n" {
			n = &snap[i]
		}
	}
	if n == nil {
		t.Fatal("node n missing")
	}
	if len(n.TopSlow) != 3 {
		t.Fatalf("top_slow len = %d, want 3 (fixed cap)", len(n.TopSlow))
	}
	// Descending by gateway_ms: 90, 70, 50.
	want := []float64{90, 70, 50}
	for i, e := range n.TopSlow {
		if e.GatewayMs != want[i] {
			t.Errorf("top_slow[%d].gateway_ms = %.3f, want %.3f", i, e.GatewayMs, want[i])
		}
	}
	// mount/unmount counts: 6 mounts, 6 unmounts.
	if n.MountCount != 6 || n.UnmountCount != 6 {
		t.Errorf("mount/unmount = %d/%d, want 6/6", n.MountCount, n.UnmountCount)
	}
}

func TestTopSlow_EvictsSmallestWhenFull(t *testing.T) {
	s := NewUnmountStats(2, 0, nil, "gw", nil)
	s.RecordMount("n", "sfs", "cmd")
	s.RecordUnmount("n", "sfs", "r", pool.UnmountResult{GatewayDurationNs: msToNs(100)}, true)
	s.RecordMount("n", "sfs", "cmd2")
	s.RecordUnmount("n", "sfs", "r", pool.UnmountResult{GatewayDurationNs: msToNs(200)}, true)
	// Now full (100, 200). A faster one (50) must NOT enter.
	s.RecordMount("n", "sfs", "cmd3")
	s.RecordUnmount("n", "sfs", "r", pool.UnmountResult{GatewayDurationNs: msToNs(50)}, true)
	snap := s.Snapshot()
	var n *NodeUnmountStats
	for i := range snap {
		if snap[i].NodeID == "n" {
			n = &snap[i]
		}
	}
	if len(n.TopSlow) != 2 {
		t.Fatalf("top_slow len = %d, want 2", len(n.TopSlow))
	}
	if n.TopSlow[0].GatewayMs != 200 || n.TopSlow[1].GatewayMs != 100 {
		t.Errorf("top_slow = %.3f,%.3f, want 200,100", n.TopSlow[0].GatewayMs, n.TopSlow[1].GatewayMs)
	}
}

// TestTopSlow_PreservesSubMillisecondPrecision pins the top-N latencies to
// msFromNs's 3-decimal millisecond resolution: a whole-millisecond integer
// conversion would report 1.000/1.000/0.000 here instead of the measured
// 1.235/1.100/0.900.
func TestTopSlow_PreservesSubMillisecondPrecision(t *testing.T) {
	s := NewUnmountStats(10, 0, nil, "gw", nil)
	s.RecordMount("n", "sfs", "cmd")
	s.RecordUnmount("n", "sfs", "lease-expiry", pool.UnmountResult{
		GatewayDurationNs: 1_234_567,
		SandlotDurationNs: 1_100_000,
		WardenDurationNs:  900_000,
	}, true)

	snap := s.Snapshot()
	var n *NodeUnmountStats
	for i := range snap {
		if snap[i].NodeID == "n" {
			n = &snap[i]
		}
	}
	if n == nil {
		t.Fatal("node n missing")
	}
	if len(n.TopSlow) != 1 {
		t.Fatalf("top_slow len = %d, want 1", len(n.TopSlow))
	}
	e := n.TopSlow[0]
	if e.GatewayMs != 1.235 || e.SandlotMs != 1.1 || e.WardenMs != 0.9 {
		t.Errorf("top_slow latencies = %.3f/%.3f/%.3f, want 1.235/1.100/0.900",
			e.GatewayMs, e.SandlotMs, e.WardenMs)
	}
}

func TestRecordUnmount_CarriesCommandContext(t *testing.T) {
	s := NewUnmountStats(10, 0, nil, "gw", nil)
	s.RecordMount("n", "sfs-A", "python3 train.py")
	s.RecordUnmount("n", "sfs-A", "lease-expiry",
		pool.UnmountResult{GatewayDurationNs: msToNs(80)}, true)
	snap := s.Snapshot()
	var n *NodeUnmountStats
	for i := range snap {
		if snap[i].NodeID == "n" {
			n = &snap[i]
		}
	}
	if len(n.TopSlow) != 1 {
		t.Fatalf("top_slow len = %d, want 1", len(n.TopSlow))
	}
	if n.TopSlow[0].Command != "python3 train.py" {
		t.Errorf("command = %q, want %q", n.TopSlow[0].Command, "python3 train.py")
	}
	if n.TopSlow[0].Reason != "lease-expiry" {
		t.Errorf("reason = %q, want lease-expiry", n.TopSlow[0].Reason)
	}
	// lastCmd cleared after unmount.
	if _, ok := s.lastCmd["sfs-A"]; ok {
		t.Error("lastCmd not cleared after unmount")
	}
}

func TestCommandTruncate(t *testing.T) {
	long := make([]byte, commandTruncate+50)
	for i := range long {
		long[i] = 'a'
	}
	got := truncateCmd(string(long))
	if len(got) != commandTruncate+3 { // truncated + "..."
		t.Errorf("truncated len = %d, want %d", len(got), commandTruncate+3)
	}
	if truncateCmd("short") != "short" {
		t.Error("short command should be unchanged")
	}
}

func TestUpdateInterval(t *testing.T) {
	s := NewUnmountStats(10, 5*time.Second, nil, "gw", nil)
	// Initial interval stored.
	if got := time.Duration(s.intervalNs.Load()); got != 5*time.Second {
		t.Fatalf("initial interval = %v, want 5s", got)
	}
	// Hot-reload to a new value.
	s.UpdateInterval(30 * time.Second)
	if got := time.Duration(s.intervalNs.Load()); got != 30*time.Second {
		t.Errorf("after UpdateInterval = %v, want 30s", got)
	}
	// d <= 0 is ignored (keeps current).
	s.UpdateInterval(0)
	if got := time.Duration(s.intervalNs.Load()); got != 30*time.Second {
		t.Errorf("after UpdateInterval(0) = %v, want 30s (unchanged)", got)
	}
	// Nil receiver is a no-op (callers guard, but be defensive).
	var ns *UnmountStats
	ns.UpdateInterval(time.Second)
}

func TestNilReceiverSafe(t *testing.T) {
	var s *UnmountStats
	// These must not panic (callers guard with != nil, but be defensive).
	s.RecordMount("n", "s", "c")
	s.RecordUnmount("n", "s", "r", pool.UnmountResult{}, true)
	s.ForgetNode("n")
	if ss := s.Snapshot(); ss != nil {
		t.Errorf("nil Snapshot = %v, want nil", ss)
	}
}

func TestForgetNode_DropsEntry(t *testing.T) {
	s := NewUnmountStats(10, 0, nil, "gw", nil)
	s.RecordMount("node-A", "sfs-1", "cmd")
	s.RecordUnmount("node-A", "sfs-1", "lease-expiry",
		pool.UnmountResult{GatewayDurationNs: msToNs(50)}, true)
	s.RecordMount("node-B", "sfs-2", "cmd2")
	s.RecordUnmount("node-B", "sfs-2", "lease-expiry",
		pool.UnmountResult{GatewayDurationNs: msToNs(30)}, true)

	// Sanity: both nodes present.
	if got := len(s.Snapshot()); got != 2 {
		t.Fatalf("before forget: snapshot len = %d, want 2", got)
	}

	// node-A disconnects → its entry is dropped; node-B stays.
	s.ForgetNode("node-A")
	snap := s.Snapshot()
	if len(snap) != 1 {
		t.Fatalf("after forget: snapshot len = %d, want 1", len(snap))
	}
	if snap[0].NodeID != "node-B" {
		t.Errorf("remaining node = %q, want node-B", snap[0].NodeID)
	}
	if snap[0].UnmountCount != 1 {
		t.Errorf("node-B unmount_count = %d, want 1", snap[0].UnmountCount)
	}

	// Forgetting a node with no entry is a no-op (e.g. a never-recorded node).
	s.ForgetNode("node-Z")
	if len(s.Snapshot()) != 1 {
		t.Errorf("forget unknown node changed snapshot len to %d", len(s.Snapshot()))
	}
}

// ── Latency rings (the P95 fields the counters/top-N cannot produce) ───────

func TestDurationRing_Percentiles(t *testing.T) {
	// n=0: empty window → all zeroes.
	r0 := newDurationRing(8)
	if got := r0.snapshot(); got != (RingSnapshot{}) {
		t.Errorf("empty ring snapshot = %+v, want zeroes", got)
	}

	// n=1: every percentile is the single sample.
	r1 := newDurationRing(8)
	r1.add(msToNs(7))
	if got := r1.snapshot(); got.N != 1 || got.P50Ms != 7 || got.P95Ms != 7 || got.P99Ms != 7 || got.MaxMs != 7 {
		t.Errorf("n=1 snapshot = %+v, want all 7ms", got)
	}

	// n=2: nearest-rank convention sorted[int(n*p)] — p50/p95/p99 all index 1.
	r2 := newDurationRing(8)
	r2.add(msToNs(1))
	r2.add(msToNs(2))
	if got := r2.snapshot(); got.N != 2 || got.P50Ms != 2 || got.P95Ms != 2 || got.MaxMs != 2 {
		t.Errorf("n=2 snapshot = %+v, want p50=p95=max=2ms", got)
	}

	// n=100 (1..100ms): sorted[int(n*p)] → 51 / 96 / 100 / 100.
	r100 := newDurationRing(DefaultRecentN)
	for i := uint64(1); i <= 100; i++ {
		r100.add(msToNs(i))
	}
	got := r100.snapshot()
	if got.N != 100 || got.P50Ms != 51 || got.P95Ms != 96 || got.P99Ms != 100 || got.MaxMs != 100 {
		t.Errorf("n=100 snapshot = %+v, want n=100 p50=51 p95=96 p99=100 max=100", got)
	}
	// Monotonic: p50 ≤ p95 ≤ p99 ≤ max.
	if !(got.P50Ms <= got.P95Ms && got.P95Ms <= got.P99Ms && got.P99Ms <= got.MaxMs) {
		t.Errorf("percentiles not monotonic: %+v", got)
	}
}

func TestDurationRing_WraparoundKeepsNewest(t *testing.T) {
	r := newDurationRing(4)
	for _, v := range []uint64{1, 2, 3, 4, 5, 6} {
		r.add(msToNs(v))
	}
	got := r.snapshot()
	// Window = newest 4 (3,4,5,6): p50 index 2 → 5ms, p95 index 3 → 6ms.
	if got.N != 4 || got.P50Ms != 5 || got.P95Ms != 6 || got.MaxMs != 6 {
		t.Errorf("wraparound snapshot = %+v, want n=4 p50=5 p95=6 max=6", got)
	}
}

func TestRecordUnmount_FillsRecentRings(t *testing.T) {
	s := NewUnmountStats(10, 0, nil, "gw", nil)
	for i := uint64(1); i <= 100; i++ {
		s.RecordUnmount("n", "sfs", "lease-expiry",
			pool.UnmountResult{GatewayDurationNs: msToNs(i), WardenDurationNs: msToNs(2 * i)}, true)
	}
	var n *NodeUnmountStats
	snap := s.Snapshot()
	for i := range snap {
		if snap[i].NodeID == "n" {
			n = &snap[i]
		}
	}
	if n == nil {
		t.Fatal("node n missing")
	}
	// Gateway ring: 1..100ms → p95 = 96ms.
	if n.Recent.N != 100 || n.Recent.P95Ms != 96 || n.Recent.MaxMs != 100 {
		t.Errorf("recent = %+v, want n=100 p95=96 max=100", n.Recent)
	}
	// Warden ring: 2,4,...,200ms → p95 index 95 → 96*2 = 192ms.
	if n.RecentWarden.N != 100 || n.RecentWarden.P95Ms != 192 || n.RecentWarden.MaxMs != 200 {
		t.Errorf("recent_warden = %+v, want n=100 p95=192 max=200", n.RecentWarden)
	}
	// A zero-duration result must not pollute the rings (failure path).
	s.RecordUnmount("n", "sfs", "cleanup", pool.UnmountResult{}, false)
	snap = s.Snapshot()
	for i := range snap {
		if snap[i].NodeID == "n" && snap[i].Recent.N != 100 {
			t.Errorf("zero-duration unmount entered the ring: n=%d", snap[i].Recent.N)
		}
	}
}

func TestRecordLeaseFire_CountersAndRing(t *testing.T) {
	s := NewUnmountStats(10, 0, nil, "gw", nil)
	s.RecordLeaseFire("n", 500*time.Microsecond)  // under 1ms
	s.RecordLeaseFire("n", 1500*time.Microsecond) // under 2ms only
	s.RecordLeaseFire("n", 3*time.Millisecond)    // neither
	s.RecordLeaseFire("n", -time.Millisecond)     // ignored: not a late fire

	snap := s.Snapshot()
	if len(snap) != 1 {
		t.Fatalf("snapshot len = %d, want 1", len(snap))
	}
	lf := snap[0].LeaseFire
	if lf.Total != 3 || lf.Under1ms != 1 || lf.Under2ms != 2 {
		t.Errorf("lease_fire counters = %+v, want total=3 under1=1 under2=2", lf)
	}
	// Ring sorted [0.5, 1.5, 3]ms: p50 index 1 → 1.5ms, p95 index 2 → 3ms.
	if lf.P50Ms != 1.5 || lf.P95Ms != 3 || lf.MaxMs != 3 {
		t.Errorf("lease_fire percentiles = %+v, want p50=1.5 p95=3 max=3", lf)
	}

	// Nil receiver is a no-op (matches the other recorders).
	var nilStats *UnmountStats
	nilStats.RecordLeaseFire("n", time.Millisecond)
}

func TestSnapshot_EmptyRingsAreZero(t *testing.T) {
	s := NewUnmountStats(10, 0, nil, "gw", nil)
	s.RecordMount("n", "sfs", "cmd")
	snap := s.Snapshot()
	if len(snap) != 1 {
		t.Fatalf("snapshot len = %d, want 1", len(snap))
	}
	if snap[0].Recent != (RingSnapshot{}) || snap[0].RecentWarden != (RingSnapshot{}) {
		t.Errorf("rings before any unmount = %+v / %+v, want zeroes", snap[0].Recent, snap[0].RecentWarden)
	}
	if snap[0].LeaseFire.Total != 0 {
		t.Errorf("lease_fire.total = %d, want 0", snap[0].LeaseFire.Total)
	}
}

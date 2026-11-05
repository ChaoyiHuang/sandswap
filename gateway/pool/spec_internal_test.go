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
//
// Internal (package pool) tests for the bound-count bookkeeping
// and the sandlot no-VM error predicate.

package pool

import (
	"log/slog"
	"testing"

	pb "common/proto/stream"
)

// boundOf returns the Bound count for a node+spec (0 if absent).
func boundOf(pm *Manager, nodeID, spec string) uint32 {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	if n, ok := pm.nodes[nodeID]; ok {
		if c, ok := n.Capacity[spec]; ok {
			return c.Bound
		}
	}
	return 0
}

func newBoundManager(t *testing.T) *Manager {
	t.Helper()
	pm := NewManager(nil, slog.Default())
	pm.AddNode("n1")
	pm.UpdateNodeCapacity("n1", []SpecCapacity{
		{SpecID: "small", Total: 5},
		{SpecID: "medium", Total: 3},
	})
	return pm
}

// TestAdjustBound verifies the provisional->actual spec correction: a reserved
// "small" corrected to "medium" decrements small.Bound and increments
// medium.Bound; an equal correction is a no-op; empty specs default to
// "medium"; a missing node is a no-op.
func TestAdjustBound(t *testing.T) {
	pm := newBoundManager(t)
	pm.ReserveBound("n1", "small")
	if got := boundOf(pm, "n1", "small"); got != 1 {
		t.Fatalf("setup: small.Bound = %d, want 1", got)
	}

	// Correct small -> medium.
	pm.AdjustBound("n1", "small", "medium")
	if got := boundOf(pm, "n1", "small"); got != 0 {
		t.Errorf("small.Bound after adjust = %d, want 0", got)
	}
	if got := boundOf(pm, "n1", "medium"); got != 1 {
		t.Errorf("medium.Bound after adjust = %d, want 1", got)
	}

	// Equal -> no-op.
	pm.AdjustBound("n1", "medium", "medium")
	if got := boundOf(pm, "n1", "medium"); got != 1 {
		t.Errorf("equal adjust should be a no-op, medium.Bound = %d", got)
	}

	// Empty spec -> defaults to medium.
	pm.ReserveBound("n1", "small") // back to 1
	pm.AdjustBound("n1", "small", "")
	if got := boundOf(pm, "n1", "small"); got != 0 {
		t.Errorf("small.Bound after adjust-to-default = %d, want 0", got)
	}
	if got := boundOf(pm, "n1", "medium"); got != 2 {
		t.Errorf("medium.Bound after adjust-to-default = %d, want 2", got)
	}

	// Missing node -> no-op (no panic).
	pm.AdjustBound("ghost", "small", "medium")
}

// TestAdjustBoundRejectsUnadvertisedSpec pins a CommandResponse.spec
// outside the node's advertised table (or the built-in static table) must not
// create a capacity bucket, must not move the reservation, and must not be
// returned as the applied spec — the lease would then ReleaseBound a bucket
// nothing holds and leak the real bound forever.
func TestAdjustBoundRejectsUnadvertisedSpec(t *testing.T) {
	pm := newBoundManager(t)
	pm.ReserveBound("n1", "small")

	if got := pm.AdjustBound("n1", "small", "xl-bogus"); got != "small" {
		t.Errorf("AdjustBound = %q, want the provisional spec %q", got, "small")
	}
	if got := boundOf(pm, "n1", "small"); got != 1 {
		t.Errorf("small.Bound = %d, want 1 (reservation kept)", got)
	}
	pm.mu.Lock()
	_, bucketExists := pm.nodes["n1"].Capacity["xl-bogus"]
	pm.mu.Unlock()
	if bucketExists {
		t.Error("an unrecognized node-reported spec created a persistent capacity bucket")
	}
	if pm.ValidSpec("n1", "xl-bogus") {
		t.Error("ValidSpec accepted an unadvertised spec")
	}

	// A spec the node DID advertise is accepted and the reservation moves.
	pm.SetNodeSpecs("n1", []VMSpec{{ID: "xl", VCPUs: 16, MemoryMB: 4096}})
	if got := pm.AdjustBound("n1", "small", "xl"); got != "xl" {
		t.Errorf("AdjustBound = %q, want advertised spec %q", got, "xl")
	}
	if got := boundOf(pm, "n1", "small"); got != 0 {
		t.Errorf("small.Bound after accepted correction = %d, want 0", got)
	}
	if got := boundOf(pm, "n1", "xl"); got != 1 {
		t.Errorf("xl.Bound = %d, want 1", got)
	}

	// A built-in static spec stays valid without advertisement.
	if !pm.ValidSpec("n1", "large") {
		t.Error("ValidSpec rejected a built-in static spec")
	}
	if pm.ValidSpec("ghost", "small") {
		t.Error("ValidSpec accepted a spec on an unknown node")
	}
}

// TestSetNodePoolTargetClampsImplausible pins a hello-supplied
// pool_target in the billions must be clamped before it becomes the cluster
// normalization denominator (which would collapse every node's clean term),
// and the caller must learn it was clamped so it can log the drift by name.
func TestSetNodePoolTargetClampsImplausible(t *testing.T) {
	pm := newBoundManager(t) // adds n1
	applied, clamped := pm.SetNodePoolTarget("n1", 4_000_000_000)
	if !clamped || applied != maxPlausiblePoolTarget {
		t.Errorf("SetNodePoolTarget = (%d, %v), want (%d, true)", applied, clamped, maxPlausiblePoolTarget)
	}
	pm.mu.Lock()
	stored := pm.nodes["n1"].PoolTarget
	clusterMax := pm.maxPoolTargetLocked()
	pm.mu.Unlock()
	if stored != maxPlausiblePoolTarget || clusterMax != maxPlausiblePoolTarget {
		t.Errorf("stored target = %d, cluster max = %d, want both %d", stored, clusterMax, maxPlausiblePoolTarget)
	}
	if applied, clamped := pm.SetNodePoolTarget("n1", 8); clamped || applied != 8 {
		t.Errorf("in-range target = (%d, %v), want (8, false)", applied, clamped)
	}
}

// TestReleaseBound verifies the unmount release: decrements the bound count
// (derived clean rises, reusing the node), idempotent (saturates at 0), and a
// missing node/spec is a safe no-op.
func TestReleaseBound(t *testing.T) {
	pm := newBoundManager(t)
	pm.ReserveBound("n1", "small")
	pm.ReserveBound("n1", "small")
	if got := boundOf(pm, "n1", "small"); got != 2 {
		t.Fatalf("setup: small.Bound = %d, want 2", got)
	}

	pm.ReleaseBound("n1", "small")
	if got := boundOf(pm, "n1", "small"); got != 1 {
		t.Errorf("after release = %d, want 1", got)
	}
	pm.ReleaseBound("n1", "small")
	if got := boundOf(pm, "n1", "small"); got != 0 {
		t.Errorf("after second release = %d, want 0", got)
	}
	// Saturates at 0 (idempotent).
	pm.ReleaseBound("n1", "small")
	if got := boundOf(pm, "n1", "small"); got != 0 {
		t.Errorf("release past 0 = %d, want 0", got)
	}

	// Missing node / spec -> safe no-op.
	pm.ReleaseBound("ghost", "small")
	pm.ReleaseBound("n1", "nonexistent-spec")
}

// TestIsNoAvailableVM verifies the sandlot error predicate: only the
// "no available VM on node" over-subscription error is treated as no-capacity
// (the gateway retries on another node instead of EnterCleaning).
func TestIsNoAvailableVM(t *testing.T) {
	cases := []struct {
		err  string
		code string
		want bool
	}{
		{"no available VM on node", "", true},
		{"error: no available VM on node-3", "", true},
		{"mount failed: permission denied", "", false},
		{"", "", false},
		{"no available", "", false},                     // partial substring must not match
		{"some other failure", "NO_AVAILABLE_VM", true}, // structured code wins
		{"", "OTHER_CODE", false},
	}
	for _, c := range cases {
		resp := &pb.CommandResponse{Error: c.err, ErrorCode: c.code}
		if got := isNoAvailableVM(resp); got != c.want {
			t.Errorf("isNoAvailableVM(err=%q, code=%q) = %v, want %v", c.err, c.code, got, c.want)
		}
	}
}

// TestMaxSpecResources pins the ceiling source: the largest advertised
// spec across nodes, dominated by memory first (the resolveFloorSpec
// ordering), floored by the built-in table.
func TestMaxSpecResources(t *testing.T) {
	pm := newBoundManager(t) // n1, no advertised table
	if v, m := pm.MaxSpecResources(); v != 8 || m != 2048 {
		t.Errorf("no advertised specs: ceiling = (%d,%d), want the built-in large (8,2048)", v, m)
	}

	pm.SetNodeSpecs("n1", []VMSpec{
		{ID: "s", VCPUs: 1, MemoryMB: 128},
		{ID: "xl", VCPUs: 32, MemoryMB: 8192},
	})
	if v, m := pm.MaxSpecResources(); v != 32 || m != 8192 {
		t.Errorf("advertised xl(32,8192): ceiling = (%d,%d), want (32,8192)", v, m)
	}

	// Dominance is by memory, then vcpus: a many-vcpu/tiny-memory spec must
	// not raise the vcpu ceiling above the dominating spec (a clamped minimum
	// must stay satisfiable by ONE spec).
	pm.SetNodeSpecs("n1", []VMSpec{
		{ID: "a", VCPUs: 64, MemoryMB: 1024},
		{ID: "b", VCPUs: 2, MemoryMB: 4096},
	})
	if v, m := pm.MaxSpecResources(); v != 2 || m != 4096 {
		t.Errorf("dominated table: ceiling = (%d,%d), want the dominating spec b (2,4096)", v, m)
	}
	if v, m := StaticMaxSpecResources(); v != 8 || m != 2048 {
		t.Errorf("StaticMaxSpecResources = (%d,%d), want (8,2048)", v, m)
	}
}

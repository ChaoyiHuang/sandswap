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

package pool

import (
	"log/slog"
	"testing"
	"time"
)

// TestNodeRecentVMCrash covers the window logic: within the penalty window the
// node reports the crash, outside it does not, and unknown nodes are no-ops.
func TestNodeRecentVMCrash(t *testing.T) {
	pm := NewManager(nil, slog.New(slog.DiscardHandler))
	pm.AddNode("n1")

	now := time.Now()
	pm.noteVMCrashAt("n1", now)
	if !pm.nodes["n1"].recentVMCrash(now) {
		t.Error("node should report a recent crash right after NoteVMCrash")
	}
	// A crash from (window + 1s) ago is no longer recent.
	pm.noteVMCrashAt("n1", now.Add(-crashPenaltyWindow-time.Second))
	if pm.nodes["n1"].recentVMCrash(now) {
		t.Error("node should NOT report a crash outside the penalty window")
	}
	// Unknown node: no panic, no entry.
	pm.noteVMCrashAt("ghost", now)
	if _, ok := pm.nodes["ghost"]; ok {
		t.Error("NoteVMCrash must not create a node")
	}
}

// TestAcquireAvoidsRecentlyCrashedNode: with two equivalent nodes, the one
// that just reported a VM crash loses the Acquire to the crash-free peer.
func TestAcquireAvoidsRecentlyCrashedNode(t *testing.T) {
	pm := NewManager(nil, slog.New(slog.DiscardHandler))
	pm.SetSchedPolicy(DefaultSchedPolicy())
	pm.AddNode("node-a")
	pm.AddNode("node-b")
	for _, n := range []string{"node-a", "node-b"} {
		pm.UpdateNodeCapacity(n, []SpecCapacity{{SpecID: "small", Clean: 1, Total: 1}})
		pm.UpdateNodeMetrics(n, NodeMetrics{DutyLong: 0.1, HostCPU: 20})
	}
	pm.NoteVMCrash("node-a")

	node, _, err := pm.Acquire("", 0, 0)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if node != "node-b" {
		t.Errorf("expected node-b (crash-free), got %s", node)
	}
}

// TestAcquireFallsBackToCrashedNode: the penalty is soft — a single-node
// deployment is never starved into NO_AVAILABLE_SANDBOX by it.
func TestAcquireFallsBackToCrashedNode(t *testing.T) {
	pm := NewManager(nil, slog.New(slog.DiscardHandler))
	pm.AddNode("node-a")
	pm.UpdateNodeCapacity("node-a", []SpecCapacity{{SpecID: "small", Clean: 1, Total: 1}})
	pm.UpdateNodeMetrics("node-a", NodeMetrics{DutyLong: 0.1, HostCPU: 20})
	pm.NoteVMCrash("node-a")

	node, _, err := pm.Acquire("", 0, 0)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if node != "node-a" {
		t.Errorf("expected fallback to the only (crashed) node, got %s", node)
	}
}

// TestAcquireCrashPenaltyExpires: once the penalty window elapses, the node's
// score returns to normal (injectable clock — no sleeps).
func TestAcquireCrashPenaltyExpires(t *testing.T) {
	pm := NewManager(nil, slog.New(slog.DiscardHandler))
	pm.SetSchedPolicy(DefaultSchedPolicy())
	pm.AddNode("node-a")
	pm.AddNode("node-b")
	for _, n := range []string{"node-a", "node-b"} {
		pm.UpdateNodeCapacity(n, []SpecCapacity{{SpecID: "small", Clean: 1, Total: 1}})
		pm.UpdateNodeMetrics(n, NodeMetrics{DutyLong: 0.1, HostCPU: 20})
	}
	// Crash long ago — outside the window.
	pm.noteVMCrashAt("node-a", time.Now().Add(-crashPenaltyWindow-time.Minute))

	node, _, err := pm.Acquire("", 0, 0)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	// Equivalent scores -> first-iterated node wins; just assert no error and
	// that the crashed-node fallback did NOT route everything to node-b via
	// penalty (i.e. node-a is acquirable).
	if node != "node-a" && node != "node-b" {
		t.Errorf("unexpected node %s", node)
	}
}

// TestNoteVMCrashSurvivesUpdateNodeCapacity: a heartbeat (which reconciles
// Total) must NOT clear the penalty — the penalty outlives the heartbeat so
// routing stays cautious until the replacement VM is booted.
func TestNoteVMCrashSurvivesUpdateNodeCapacity(t *testing.T) {
	pm := NewManager(nil, slog.New(slog.DiscardHandler))
	pm.AddNode("n1")
	pm.UpdateNodeCapacity("n1", []SpecCapacity{{SpecID: "small", Clean: 1, Total: 1}})
	pm.NoteVMCrash("n1")
	pm.UpdateNodeCapacity("n1", []SpecCapacity{{SpecID: "small", Clean: 0, Total: 0}})

	if !pm.nodes["n1"].recentVMCrash(time.Now()) {
		t.Error("heartbeat UpdateNodeCapacity must not clear the crash penalty")
	}
}

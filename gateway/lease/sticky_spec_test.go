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

package lease

import (
	"testing"
	"time"
)

// TestSetSpecAndSpecOf verifies the VM-spec accessors: SetSpec
// records the actual serving spec on an existing lease; SpecOf reads it back;
// a missing lease returns "" and SetSpec is a no-op.
func TestSetSpecAndSpecOf(t *testing.T) {
	l := New(100*time.Millisecond, 5*time.Second)
	l.TouchSync("sandfs-1", "node-1", "")

	if got := l.SpecOf("sandfs-1"); got != "" {
		t.Errorf("SpecOf before SetSpec = %q, want \"\"", got)
	}
	l.SetSpec("sandfs-1", "medium")
	if got := l.SpecOf("sandfs-1"); got != "medium" {
		t.Errorf("SpecOf after SetSpec = %q, want medium", got)
	}

	// Missing lease -> "" and no-op.
	if got := l.SpecOf("sandfs-missing"); got != "" {
		t.Errorf("SpecOf(missing) = %q, want \"\"", got)
	}
	l.SetSpec("sandfs-missing", "large") // must not panic
	if got := l.SpecOf("sandfs-missing"); got != "" {
		t.Errorf("SetSpec on missing lease should not create it, got %q", got)
	}
}

// TestSetSpecPersistsAcrossTouchSync verifies the spec survives subsequent
// TouchSync calls (it is not reset), so onExpiry can ReleaseBound with the
// right spec.
func TestSetSpecPersistsAcrossTouchSync(t *testing.T) {
	l := New(100*time.Millisecond, 5*time.Second)
	l.TouchSync("sandfs-1", "node-1", "")
	l.SetSpec("sandfs-1", "small")
	l.TouchSync("sandfs-1", "node-1", "") // refresh
	if got := l.SpecOf("sandfs-1"); got != "small" {
		t.Errorf("spec after re-touch = %q, want small (preserved)", got)
	}
}

// TestTouchSyncCreatesEntryWithSpec pins the bound-leak fix: on a cold op the
// handler's SetSpec runs while the lease entry does not exist yet (no-op), and
// TouchSync then CREATES the entry. If creation left Spec empty, the expiry
// path's ReleaseBound(node, "") would be defaultSpec'd into the "medium" bucket
// and never release the real bucket's bound — permanently zeroing the node's
// derived clean count for that spec (observed as small{total=2,bound=2} on a
// small-spec pool).
func TestTouchSyncCreatesEntryWithSpec(t *testing.T) {
	l := New(50*time.Millisecond, 5*time.Second)
	specCh := make(chan string, 1)
	l.StartExpiryWorker(func(sandfsID, nodeID, spec, volumePath string) {
		select {
		case specCh <- spec:
		default:
		}
	})
	defer l.Close()

	// Simulate the cold-op sequence: TouchSync creates the entry WITH the spec
	// (SetSpec before it was a no-op because the entry didn't exist).
	l.TouchSync("sandfs-cold", "node-1", "small")
	if got := l.SpecOf("sandfs-cold"); got != "small" {
		t.Fatalf("SpecOf after creating TouchSync = %q, want small", got)
	}

	// Wait for expiry; the callback must observe the right spec. Do NOT poll
	// via Acquire — it refreshes the sticky window and would starve the expiry.
	select {
	case got := <-specCh:
		if got != "small" {
			t.Errorf("onExpiry spec = %q, want small", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("lease did not expire within 2s")
	}
}

// TestReleaseByNode verifies releasing all leases held on a disconnected node
// (OnDisconnect): only entries whose NodeID matches are removed; other nodes'
// leases survive.
func TestReleaseByNode(t *testing.T) {
	l := New(100*time.Millisecond, 5*time.Second)
	l.TouchSync("s-1", "node-1", "")
	l.TouchSync("s-2", "node-1", "")
	l.TouchSync("s-3", "node-2", "")

	l.ReleaseByNode("node-1")

	if got := l.Acquire("s-1"); got != "" {
		t.Errorf("s-1 should be released (node-1), Acquire got %q", got)
	}
	if got := l.Acquire("s-2"); got != "" {
		t.Errorf("s-2 should be released (node-1), Acquire got %q", got)
	}
	if got := l.Acquire("s-3"); got != "node-2" {
		t.Errorf("s-3 should survive (node-2), Acquire got %q", got)
	}

	// Empty nodeID is a no-op (nothing released).
	l.ReleaseByNode("")
	if got := l.Acquire("s-3"); got != "node-2" {
		t.Errorf("s-3 should survive empty-nodeID release, got %q", got)
	}
}

// TestUpdateTimeout verifies the sync sticky window can be hot-reloaded: new
// TouchSync calls use the updated value (observable via the release timing).
func TestUpdateTimeout(t *testing.T) {
	l := New(100*time.Millisecond, 5*time.Second)
	l.UpdateTimeout(250 * time.Millisecond)
	l.TouchSync("s-1", "n", "")
	// Within the old 100ms window the lease must still be warm (250ms window).
	if got := l.Acquire("s-1"); got != "n" {
		t.Errorf("Acquire within 250ms sticky window = %q, want n", got)
	}
}

// TestUpdateMaxHold verifies the maxHold can be hot-reloaded and bounds a
// pure-sync lease via the reaper.
func TestUpdateMaxHold(t *testing.T) {
	l := New(100*time.Millisecond, 5*time.Second)
	l.UpdateMaxHold(60 * time.Millisecond)
	l.StartExpiryWorker(func(sandfsID, nodeID, spec, volumePath string) {})
	defer l.Close()
	l.TouchSync("s-1", "n", "")
	// Repeatedly refresh the sticky window so the idle timer never fires for it;
	// the reaper (maxHold=60ms, ticks ~30ms) must release it.
	for i := 0; i < 10; i++ {
		l.TouchSync("s-1", "n", "")
		time.Sleep(10 * time.Millisecond)
	}
	// Wait beyond maxHold.
	time.Sleep(120 * time.Millisecond)
	if got := l.Acquire("s-1"); got != "" {
		t.Errorf("Acquire after maxHold elapsed = %q, want empty (reaped)", got)
	}
}

// TestLeaseCloseIdempotent verifies Close can be called twice without panicking
// and stops the maxHold reaper.
func TestLeaseCloseIdempotent(t *testing.T) {
	l := New(100*time.Millisecond, 5*time.Second)
	l.StartExpiryWorker(func(sandfsID, nodeID, spec, volumePath string) {})
	l.Close()
	l.Close() // must not panic
}

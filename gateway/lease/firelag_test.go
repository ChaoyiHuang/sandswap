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
	"sync"
	"testing"
	"time"
)

// fireLagRecorder captures recorder invocations.
type fireLagRecorder struct {
	mu    sync.Mutex
	nodes []string
	lags  []time.Duration
}

func (r *fireLagRecorder) record(nodeID string, lag time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.nodes = append(r.nodes, nodeID)
	r.lags = append(r.lags, lag)
}

func (r *fireLagRecorder) snapshot() ([]string, []time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.nodes...), append([]time.Duration(nil), r.lags...)
}

// installEntry seeds a lease entry directly and returns the gen evaluate must
// carry. Production entries are created by TouchSync/StartBgExec; seeding is
// how a test pins a specific state without sleeping through the timer.
func installEntry(l *Lease, sandfsID, nodeID string, mut func(e *LeaseEntry)) uint64 {
	s := l.shard(sandfsID)
	s.mu.Lock()
	defer s.mu.Unlock()
	e := &LeaseEntry{
		NodeID:  nodeID,
		gen:     1,
		bgExecs: make(map[string]*bgHold),
	}
	if mut != nil {
		mut(e)
	}
	s.entries[sandfsID] = e
	return e.gen
}

// TestFireLagRecorder_OnStickyExpiry pins the positive case: a timer callback
// that actually dispatches a release after a real sync sticky deadline reports
// (node, now - deadline), and the value is at least the deadline age observed
// at evaluate time.
func TestFireLagRecorder_OnStickyExpiry(t *testing.T) {
	l := New(time.Millisecond, time.Hour)
	l.onExpiry = func(string, string, string, string) {} // dispatch is a no-op; entry stays unmounting
	rec := &fireLagRecorder{}
	l.SetFireLagRecorder(rec.record)

	deadline := time.Now().Add(-5 * time.Millisecond)
	gen := installEntry(l, "sfs-1", "node-1", func(e *LeaseEntry) {
		e.syncStickyUntil = deadline
		e.syncStartedAt = deadline.Add(-10 * time.Millisecond)
	})
	l.evaluate("sfs-1", gen)

	nodes, lags := rec.snapshot()
	if len(nodes) != 1 || len(lags) != 1 {
		t.Fatalf("recorded %d fires, want exactly 1", len(nodes))
	}
	if nodes[0] != "node-1" {
		t.Errorf("recorded node = %q, want node-1", nodes[0])
	}
	if lags[0] < 5*time.Millisecond || lags[0] > time.Second {
		t.Errorf("recorded lag = %v, want ≥5ms and bounded", lags[0])
	}
}

// TestFireLagRecorder_NotRecordedWhileHeld pins the "only when a release is
// actually dispatched" half: a callback that finds the entry held (active RPC)
// or not yet due (future deadline) re-arms and must record nothing.
func TestFireLagRecorder_NotRecordedWhileHeld(t *testing.T) {
	l := New(time.Millisecond, time.Hour)
	l.onExpiry = func(string, string, string, string) {}
	rec := &fireLagRecorder{}
	l.SetFireLagRecorder(rec.record)

	// Held by an in-flight RPC: canRelease is false even though the sticky
	// deadline is past.
	genHeld := installEntry(l, "sfs-held", "node-1", func(e *LeaseEntry) {
		e.syncStickyUntil = time.Now().Add(-5 * time.Millisecond)
		e.activeExecs = 1
	})
	l.evaluate("sfs-held", genHeld)

	// Deadline still in the future: not due yet.
	genEarly := installEntry(l, "sfs-early", "node-1", func(e *LeaseEntry) {
		e.syncStickyUntil = time.Now().Add(time.Hour)
		e.syncStartedAt = time.Now()
	})
	l.evaluate("sfs-early", genEarly)

	if nodes, _ := rec.snapshot(); len(nodes) != 0 {
		t.Fatalf("recorded %d fires for held/early entries, want 0", len(nodes))
	}
}

// TestFireLagRecorder_NoStickyDeadline pins the zero-deadline case: a bg-born
// entry released when its bg hold expired has no sync sticky deadline, so the
// release is not a sticky fire and must not be reported.
func TestFireLagRecorder_NoStickyDeadline(t *testing.T) {
	l := New(time.Millisecond, time.Hour)
	l.onExpiry = func(string, string, string, string) {}
	rec := &fireLagRecorder{}
	l.SetFireLagRecorder(rec.record)

	gen := installEntry(l, "sfs-bg", "node-2", func(e *LeaseEntry) {
		e.bgExecs["exec-1"] = &bgHold{deadline: time.Now().Add(-time.Millisecond)}
	})
	l.evaluate("sfs-bg", gen)

	if nodes, _ := rec.snapshot(); len(nodes) != 0 {
		t.Fatalf("recorded %d fires without a sticky deadline, want 0", len(nodes))
	}

	// Nil recorder (the default) must not panic on a real fire.
	l.SetFireLagRecorder(nil)
	gen2 := installEntry(l, "sfs-nil", "node-2", func(e *LeaseEntry) {
		e.syncStickyUntil = time.Now().Add(-time.Millisecond)
	})
	l.evaluate("sfs-nil", gen2)
}

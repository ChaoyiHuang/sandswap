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
	"context"
	"testing"
	"time"
)

// A mount confirmation whose ownership generation moved while the RPC was in
// flight belongs to a superseded view: it must be rejected so the winner's
// placement is never overwritten.
func TestNoteMountedCheckedRejectsStaleGeneration(t *testing.T) {
	oc := NewOwnershipCacheForTest("gw-test")
	oc.SetOwnedForTest("sf-stale", "node-a")
	gen, err := oc.BeginDispatch("sf-stale")
	if err != nil {
		t.Fatalf("BeginDispatch: %v", err)
	}
	oc.mu.Lock()
	oc.cache["sf-stale"].generation = gen + 1 // a takeover/peer write landed
	oc.mu.Unlock()

	if !oc.NoteMountedChecked("sf-stale", "node-b", gen) {
		t.Fatal("stale-generation confirmation was accepted")
	}
	oc.mu.Lock()
	placement := oc.cache["sf-stale"].placement
	mounted := oc.cache["sf-stale"].mounted
	oc.mu.Unlock()
	if placement != "node-a" || mounted {
		t.Fatalf("winner record changed: placement=%q mounted=%v, want node-a/false", placement, mounted)
	}
}

// A confirmation on a different node while the recorded mount is live is the
// loser of a cross-node double mount: rejected, its node is the one to tear
// down.
func TestNoteMountedCheckedRejectsCrossNodeDuplicate(t *testing.T) {
	oc := NewOwnershipCacheForTest("gw-test")
	oc.SetOwnedForTest("sf-dup", "node-a")
	oc.mu.Lock()
	oc.cache["sf-dup"].mounted = true
	oc.mu.Unlock()

	gen, err := oc.BeginDispatch("sf-dup")
	if err != nil {
		t.Fatalf("BeginDispatch: %v", err)
	}
	if !oc.NoteMountedChecked("sf-dup", "node-b", gen) {
		t.Fatal("cross-node duplicate confirmation was accepted")
	}
	oc.mu.Lock()
	placement := oc.cache["sf-dup"].placement
	oc.mu.Unlock()
	if placement != "node-a" {
		t.Fatalf("placement = %q, want node-a (the live mount)", placement)
	}
}

// The normal path still records: same generation, no other live node.
func TestNoteMountedCheckedRecordsNormalConfirmation(t *testing.T) {
	oc := NewOwnershipCacheForTest("gw-test")
	oc.SetOwnedForTest("sf-ok", "")
	gen, err := oc.BeginDispatch("sf-ok")
	if err != nil {
		t.Fatalf("BeginDispatch: %v", err)
	}
	if oc.NoteMountedChecked("sf-ok", "node-a", gen) {
		t.Fatal("normal confirmation was reported as a conflict")
	}
	oc.mu.Lock()
	placement := oc.cache["sf-ok"].placement
	mounted := oc.cache["sf-ok"].mounted
	oc.mu.Unlock()
	if placement != "node-a" || !mounted {
		t.Fatalf("record = %q/%v, want node-a/true", placement, mounted)
	}
}

// An active background exec holds the lease's node: a sync op routed elsewhere
// must not rewrite NodeID (the expiry path frees the bound under that node).
func TestTouchSyncKeepsTheNodeOfActiveBgExecs(t *testing.T) {
	l := New(100*time.Millisecond, 5*time.Second)
	defer l.Close()
	l.StartBgExec("sf-bg", "node-a", "exec-1", time.Minute)
	l.TouchSync("sf-bg", "node-b", "small")

	s := l.shard("sf-bg")
	s.mu.Lock()
	node := s.entries["sf-bg"].NodeID
	s.mu.Unlock()
	if node != "node-a" {
		t.Fatalf("NodeID = %q, want node-a (held by the background exec)", node)
	}

	// Without a background exec the sync op owns the node.
	l.TouchSync("sf-sync", "node-a", "small")
	l.TouchSync("sf-sync", "node-b", "small")
	s = l.shard("sf-sync")
	s.mu.Lock()
	node = s.entries["sf-sync"].NodeID
	s.mu.Unlock()
	if node != "node-b" {
		t.Fatalf("NodeID = %q, want node-b for a pure-sync lease", node)
	}
}

// Preserve what the presence query was ABOUT: the answer is only valid for the
// placement/generation/revision snapshotted before the etcd call. A concurrent
// mount move must not be clobbered by the (stale) orphan resolution.
func TestResolveOrphanSuspectRejectsStalePresenceAnswer(t *testing.T) {
	defer testPresenceStateFn.Store(nil)
	oc := NewOwnershipCacheForTest("gw-test")
	oc.SetOwnedForTest("sf-move", "node-a")

	oc.mu.Lock()
	entry := oc.cache["sf-move"]
	entry.suspect = true
	oc.mu.Unlock()

	// While the presence answer is being produced, a fresh mount moves the
	// entry to node-b (the same object the caller holds, as the real
	// NoteMounted path does).
	oc.SetPresenceStateForTest(func(nodeID string) (presenceState, error) {
		oc.mu.Lock()
		entry.placement = "node-b"
		entry.generation++
		entry.modRev++
		entry.mounted = true
		entry.suspect = false
		oc.mu.Unlock()
		return presenceAbsent, nil
	})

	if oc.resolveOrphanSuspect(context.Background(), "sf-move", entry) {
		t.Fatal("stale presence answer resolved the orphan question")
	}
	oc.mu.Lock()
	placement, mounted := entry.placement, entry.mounted
	oc.mu.Unlock()
	if placement != "node-b" || !mounted {
		t.Fatalf("fresh mount state was clobbered: placement=%q mounted=%v", placement, mounted)
	}
}

// A mount confirmation that lands while this gateway is SELF-FENCED belongs to
// a dispatch superseded by the fence: it must be torn down (compensated), never
// recorded — the fence promised and released every mount.
func TestNoteMountedCheckedCompensatesWhenFenced(t *testing.T) {
	oc := NewOwnershipCacheForTest("gw-test")
	oc.SetOwnedForTest("sf-fenced", "node-a")
	gen, err := oc.BeginDispatch("sf-fenced")
	if err != nil {
		t.Fatalf("BeginDispatch: %v", err)
	}
	compensated := make(chan string, 1)
	oc.SetMountCompensator(func(id, node string) { compensated <- id + "/" + node })
	oc.mu.Lock()
	oc.fenced = true
	oc.mu.Unlock()

	if !oc.NoteMountedChecked("sf-fenced", "node-a", gen) {
		t.Fatal("a confirmation while self-fenced must be rejected (caller tears the mount down)")
	}
	select {
	case got := <-compensated:
		if got != "sf-fenced/node-a" {
			t.Fatalf("compensated %q, want sf-fenced/node-a", got)
		}
	case <-time.After(time.Second):
		t.Fatal("fenced confirmation was not compensated with an unmount")
	}
	oc.mu.Lock()
	mounted, dispatching := oc.cache["sf-fenced"].mounted, oc.cache["sf-fenced"].dispatching
	oc.mu.Unlock()
	if mounted || dispatching {
		t.Fatalf("fenced confirmation altered the entry: mounted=%v dispatching=%v", mounted, dispatching)
	}
	// While fenced, no NEW dispatch may start either.
	if _, err := oc.BeginDispatch("sf-fenced"); err == nil {
		t.Fatal("BeginDispatch admitted a cold mount while self-fenced")
	}
}

// MountedSandfs is the self-fence release set: it must include a cold mount in
// flight and an orphan-suspect placement, not just mounted==true — the fence's
// "no live mounts once fenced" proof would otherwise miss exactly the states it
// cannot rule out.
func TestMountedSandfsIncludesInFlightAndSuspect(t *testing.T) {
	oc := NewOwnershipCacheForTest("gw-test")
	oc.SetOwnedForTest("sf-mounted", "node-a")
	oc.SetOwnedForTest("sf-dispatching", "node-b")
	oc.SetOwnedForTest("sf-suspect", "node-c")
	oc.SetOwnedForTest("sf-idle", "node-d")
	oc.SetOwnedForTest("sf-unplaced", "")
	oc.mu.Lock()
	oc.cache["sf-mounted"].mounted = true
	oc.cache["sf-dispatching"].dispatching = true
	oc.cache["sf-suspect"].suspect = true
	oc.mu.Unlock()

	got := oc.MountedSandfs()
	for _, want := range []string{"sf-mounted", "sf-dispatching", "sf-suspect"} {
		if _, ok := got[want]; !ok {
			t.Errorf("release set missing %s (got %v)", want, got)
		}
	}
	for _, no := range []string{"sf-idle", "sf-unplaced"} {
		if _, ok := got[no]; ok {
			t.Errorf("release set must not include %s (got %v)", no, got)
		}
	}
}

// ValidateExecTiming pins the gateway-side timing headroom: health tick + max
// exec + heartbeat must stay strictly below T_safe.
func TestValidateExecTiming(t *testing.T) {
	if err := ValidateExecTiming(180*time.Second, DefaultTSafe()); err != nil {
		t.Fatalf("contract defaults must satisfy the invariant: %v", err)
	}
	// Exactly the boundary is refused (strictly below).
	if err := ValidateExecTiming(DefaultTSafe()-healthRefreshInterval-nodeHeartbeatInterval, DefaultTSafe()); err == nil {
		t.Fatal("boundary value accepted; the invariant must be strict")
	}
	if err := ValidateExecTiming(180*time.Second, 100*time.Second); err == nil {
		t.Fatal("max exec above the T_safe budget accepted")
	}
	if err := ValidateExecTiming(0, DefaultTSafe()); err == nil {
		t.Fatal("non-positive max exec accepted")
	}
	if got := DefaultTSafe(); got != time.Duration(defaultTimingToleranceSec+defaultTimingWardenSec+safeMarginSec)*time.Second {
		t.Fatalf("DefaultTSafe = %v, want the contract defaults", got)
	}
}

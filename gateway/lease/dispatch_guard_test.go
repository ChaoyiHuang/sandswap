// Copyright 2026 Chaoyi Huang. All rights reserved.
//
// SPDX-License-Identifier: BUSL-1.1
//
// Pins for the in-flight-mount ownership guards:
// the sweep and the shed must not delete the ownership record of an entry
// whose cold mount is dispatching, NoteMounted must compensate when the
// record vanished anyway, and the shed guard must count unmounting entries.
// Each guard is pinned at the unit seam.

package lease

import (
	"sync"
	"testing"
	"time"
)

func newDispatchTestCache(t *testing.T) *OwnershipCache {
	t.Helper()
	t.Cleanup(func() { testPresenceStateFn.Store(nil) })
	return NewOwnershipCacheForTest("gw-test")
}

func TestBeginDispatchGuards(t *testing.T) {
	oc := newDispatchTestCache(t)
	oc.SetOwnedForTest("sf-ok", "node-a")
	oc.SetOwnedForTest("sf-releasing", "node-a")
	oc.SetOwnedForTest("sf-suspect", "node-a")
	oc.mu.Lock()
	oc.cache["sf-releasing"].ownerReleasing = true
	oc.cache["sf-suspect"].suspect = true
	oc.mu.Unlock()

	if _, err := oc.BeginDispatch("sf-ok"); err != nil {
		t.Fatalf("healthy own entry must dispatch: %v", err)
	}
	if !oc.Dispatching("sf-ok") {
		t.Fatal("dispatching flag not set")
	}
	// Double dispatch is refused (the flag is the in-flight lock).
	if _, err := oc.BeginDispatch("sf-ok"); err != ErrCoverageLost {
		t.Fatalf("double dispatch must be ErrCoverageLost, got %v", err)
	}
	for _, id := range []string{"sf-missing", "sf-releasing", "sf-suspect"} {
		if _, err := oc.BeginDispatch(id); err != ErrCoverageLost {
			t.Fatalf("%s must refuse with ErrCoverageLost, got %v", id, err)
		}
	}
	oc.EndDispatch("sf-ok")
	if oc.Dispatching("sf-ok") {
		t.Fatal("EndDispatch must clear the flag")
	}
	oc.EndDispatch("sf-missing") // no-op, no panic
}

// The sweep (the trigger): a dispatching entry's record must NOT be
// flagged for release; a non-dispatching sibling still is. RED with the
// sweep's dispatching check disabled.
func TestOwnerReleaseSweepSkipsDispatching(t *testing.T) {
	oc := newDispatchTestCache(t)
	oc.SetOwnedForTest("sf-dispatch", "node-dead")
	oc.SetOwnedForTest("sf-idle", "node-dead")
	if _, err := oc.BeginDispatch("sf-dispatch"); err != nil {
		t.Fatal(err)
	}

	// Node dead past T_safe; presence absent (the sweep's release gates).
	oc.SetPresenceStateForTest(func(string) (presenceState, error) {
		return presenceAbsent, nil
	})
	oc.mu.Lock()
	oc.presenceTTLs["node-dead"] = time.Second
	oc.pendingOwnerRelease["node-dead"] = time.Now().Add(-2 * time.Second)
	oc.mu.Unlock()

	oc.ownerReleaseCheckAndRelease("node-dead")

	oc.mu.Lock()
	defer oc.mu.Unlock()
	if e, ok := oc.cache["sf-dispatch"]; !ok || e.ownerReleasing {
		t.Fatal("ESCAPE: sweep flagged/deleted the in-flight mount's record ")
	}
	if e, ok := oc.cache["sf-idle"]; !ok || !e.ownerReleasing {
		t.Fatal("control failed: the idle entry was not flagged for release")
	}
}

// The shed (the trigger): ShedOwnership must be a no-op for a
// dispatching entry. RED with the shed's dispatching check disabled.
func TestShedSkipsDispatching(t *testing.T) {
	oc := newDispatchTestCache(t)
	oc.SetOwnedForTest("sf-shed", "node-a")
	if _, err := oc.BeginDispatch("sf-shed"); err != nil {
		t.Fatal(err)
	}
	oc.ShedOwnership("sf-shed", 30)
	if _, ok := oc.cache["sf-shed"]; !ok {
		t.Fatal("ESCAPE: shed deleted the in-flight mount's record ")
	}
	oc.shedMu.Lock()
	_, cooling := oc.recentlyShed["sf-shed"]
	oc.shedMu.Unlock()
	if cooling {
		t.Fatal("cooldown armed for a skipped shed")
	}
	// Control: after EndDispatch the shed proceeds.
	oc.EndDispatch("sf-shed")
	oc.ShedOwnership("sf-shed", 30)
	if _, ok := oc.cache["sf-shed"]; ok {
		t.Fatal("control failed: shed after EndDispatch did not release")
	}
}

// NoteMountedChecked must refuse a confirmation that arrives after the entry
// became orphan-uncertain: the mount is a potential cross-node duplicate and
// the caller must tear it down.
func TestNoteMountedRefusesSuspectDispatch(t *testing.T) {
	oc := newDispatchTestCache(t)
	oc.SetOwnedForTest("sf-suspect-mount", "node-a")
	gen, err := oc.BeginDispatch("sf-suspect-mount")
	if err != nil {
		t.Fatalf("BeginDispatch: %v", err)
	}
	oc.mu.Lock()
	oc.cache["sf-suspect-mount"].suspect = true
	oc.mu.Unlock()

	if stale := oc.NoteMountedChecked("sf-suspect-mount", "node-a", gen); !stale {
		t.Fatal("a confirmation on a suspect entry must be treated as a conflict")
	}
	oc.mu.Lock()
	defer oc.mu.Unlock()
	if e := oc.cache["sf-suspect-mount"]; e == nil || !e.suspect || e.mounted {
		t.Fatal("suspect confirmation must not clear suspect or record the mount")
	}
}

// A dispatch in flight when the node disconnects is an orphan candidate: it
// must be marked suspect even though mounted was never set.
func TestOnNodeDisconnectMarksDispatchingSuspect(t *testing.T) {
	oc := newDispatchTestCache(t)
	oc.SetOwnedForTest("sf-dispatch-disc", "node-dead")
	if _, err := oc.BeginDispatch("sf-dispatch-disc"); err != nil {
		t.Fatalf("BeginDispatch: %v", err)
	}
	oc.OnNodeDisconnect("node-dead")
	oc.mu.Lock()
	defer oc.mu.Unlock()
	e := oc.cache["sf-dispatch-disc"]
	if e == nil {
		t.Fatal("entry vanished on disconnect")
	}
	if !e.suspect {
		t.Fatal("a dispatching entry was not marked suspect on disconnect")
	}
	if !e.dispatching {
		t.Fatal("the in-flight flag must survive for the release guard")
	}
}

// An unconfirmed dispatch (a transport error after the mount command was
// sent) must become orphan-uncertain: a retry cannot dispatch and a shed
// cannot release the record while the mount may be live.
func TestUnconfirmedDispatchBlocksRedispathAndShed(t *testing.T) {
	oc := newDispatchTestCache(t)
	oc.SetOwnedForTest("sf-unconfirmed", "node-a")
	if _, err := oc.BeginDispatch("sf-unconfirmed"); err != nil {
		t.Fatalf("BeginDispatch: %v", err)
	}
	oc.NoteDispatchUnconfirmed("sf-unconfirmed")
	if oc.Dispatching("sf-unconfirmed") {
		t.Fatal("unconfirmed dispatch must clear the in-flight flag")
	}
	if _, err := oc.BeginDispatch("sf-unconfirmed"); err != ErrCoverageLost {
		t.Fatalf("suspect entry allowed a re-dispatch: %v", err)
	}
	oc.ShedOwnership("sf-unconfirmed", 30)
	if _, ok := oc.cache["sf-unconfirmed"]; !ok {
		t.Fatal("shed released an unconfirmed mount's ownership record")
	}
}

// NoteMounted on a vanished record must compensate (unmount), not silently
// no-op — the uncovered-mount backstop for any delete path that races past
// the guards (takeover eviction included).
func TestNoteMountedMissingCompensates(t *testing.T) {
	oc := newDispatchTestCache(t)
	var mu sync.Mutex
	var gotID, gotNode string
	oc.SetMountCompensator(func(sandfsID, node string) {
		mu.Lock()
		gotID, gotNode = sandfsID, node
		mu.Unlock()
	})
	oc.NoteMounted("sf-vanished", "node-a")
	mu.Lock()
	defer mu.Unlock()
	if gotID != "sf-vanished" || gotNode != "node-a" {
		t.Fatalf("compensator not invoked with (sf-vanished,node-a), got (%s,%s)", gotID, gotNode)
	}
}

// NoteMounted success clears the flag and records the mount.
func TestNoteMountedClearsDispatching(t *testing.T) {
	oc := newDispatchTestCache(t)
	oc.SetOwnedForTest("sf-live", "node-a")
	if _, err := oc.BeginDispatch("sf-live"); err != nil {
		t.Fatal(err)
	}
	oc.NoteMounted("sf-live", "node-a")
	oc.mu.Lock()
	e := oc.cache["sf-live"]
	oc.mu.Unlock()
	if e == nil || e.dispatching || !e.mounted {
		t.Fatal("NoteMounted must clear dispatching and set mounted")
	}
}

// HasEntry counts unmounting entries (a failing unmount leaves the
// mount live through the whole RetryUnmount chain); HasActiveEntry does not
// — the shed guard must use HasEntry.
func TestHasEntryIncludesUnmounting(t *testing.T) {
	l := New(time.Second, 5*time.Second)
	l.StartExpiryWorker(func(sandfsID, nodeID, spec, volumePath string) {})
	s := l.shard("sf-u")
	s.mu.Lock()
	s.entries["sf-u"] = &LeaseEntry{
		NodeID:     "node-a",
		Spec:       "medium",
		gen:        1,
		bgExecs:    make(map[string]*bgHold),
		unmounting: true,
		waitDone:   make(chan struct{}),
	}
	s.mu.Unlock()
	if !l.HasEntry("sf-u") {
		t.Fatal("HasEntry must count unmounting entries")
	}
	if l.HasActiveEntry("sf-u") {
		t.Fatal("HasActiveEntry must exclude unmounting (control)")
	}
}

// pin: the foreign-PUT watch eviction must compensate a mounted entry
// (symmetric with the DELETE branch). RED without the eviction compensation.
func TestWatchEvictionCompensatesMounted(t *testing.T) {
	oc := newDispatchTestCache(t)
	oc.SetOwnedForTest("sf-evict", "node-a")
	oc.NoteMounted("sf-evict", "node-a")
	var mu sync.Mutex
	got := ""
	oc.SetMountCompensator(func(id, node string) { mu.Lock(); got = id + "/" + node; mu.Unlock() })

	// A foreign gateway's PUT arrives (takeover).
	oc.handleWatchEventForTest("sf-evict", "gw-other")
	mu.Lock()
	defer mu.Unlock()
	if got != "sf-evict/node-a" {
		t.Fatalf("foreign-PUT eviction of a mounted entry must compensate, got %q ", got)
	}
}

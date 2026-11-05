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

func TestMountLockSequentialAcquireRelease(t *testing.T) {
	ml := NewMountLock()

	tok, err := ml.Acquire("sandfs-1")
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	ml.Release(tok)

	tok, err = ml.Acquire("sandfs-1")
	if err != nil {
		t.Fatalf("acquire after release: %v", err)
	}
	ml.Release(tok)
}

func TestMountLockConcurrentMountBlocked(t *testing.T) {
	ml := NewMountLock()

	tok1, err := ml.Acquire("sandfs-1")
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	if _, err := ml.Acquire("sandfs-1"); err != ErrConcurrentMount {
		t.Errorf("expected ErrConcurrentMount, got %v", err)
	}
	tok2, err := ml.Acquire("sandfs-2")
	if err != nil {
		t.Fatalf("different sandfs acquire: %v", err)
	}
	ml.Release(tok1)
	ml.Release(tok2)
}

func TestMountLockReleaseWithoutAcquire(t *testing.T) {
	ml := NewMountLock()
	ml.Release(nil) // no-op

	tok, err := ml.Acquire("sandfs-1")
	if err != nil {
		t.Fatalf("acquire after no-op release: %v", err)
	}
	ml.Release(tok)
}

func TestMountLockDoubleRelease(t *testing.T) {
	ml := NewMountLock()
	tok, err := ml.Acquire("sandfs-1")
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	ml.Release(tok)
	ml.Release(tok) // double release is a no-op

	tok2, err := ml.Acquire("sandfs-1")
	if err != nil {
		t.Fatalf("acquire after double release: %v", err)
	}
	ml.Release(tok2)
}

// TestMountLockStaleReleaseDoesNotDrainSuccessor pins the defect a shared
// channel-based Release had: a late Release from a previous holder must not
// drain the current holder's token.
func TestMountLockStaleReleaseDoesNotDrainSuccessor(t *testing.T) {
	ml := NewMountLock()
	tok1, err := ml.Acquire("sandfs-1")
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	ml.Release(tok1)

	tok2, err := ml.Acquire("sandfs-1")
	if err != nil {
		t.Fatalf("successor acquire: %v", err)
	}
	ml.Release(tok1) // stale release: must not release tok2

	if _, err := ml.Acquire("sandfs-1"); err != ErrConcurrentMount {
		t.Fatalf("stale release drained the successor: got %v, want ErrConcurrentMount", err)
	}
	ml.Release(tok2)
	tok3, err := ml.Acquire("sandfs-1")
	if err != nil {
		t.Fatalf("acquire after real release: %v", err)
	}
	ml.Release(tok3)
}

func TestMountLockConcurrentSandfsIDs(t *testing.T) {
	ml := NewMountLock()
	const n = 100
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			sandfsID := "sandfs-" + string(rune('a'+idx%26))
			tok, err := ml.Acquire(sandfsID)
			if err == nil {
				ml.Release(tok)
			}
		}(i)
	}
	wg.Wait()
}

func TestMountLockAcquireWaitBlocksUntilRelease(t *testing.T) {
	ml := NewMountLock()
	holder, err := ml.Acquire("sandfs-1")
	if err != nil {
		t.Fatalf("holder acquire: %v", err)
	}

	type result struct {
		tok *MountLockToken
		err error
	}
	acquired := make(chan result, 1)
	start := time.Now()
	go func() {
		tok, err := ml.AcquireWait("sandfs-1", 2*time.Second)
		acquired <- result{tok, err}
	}()

	select {
	case r := <-acquired:
		t.Fatalf("AcquireWait returned before Release: %v", r.err)
	case <-time.After(50 * time.Millisecond):
	}

	ml.Release(holder)
	select {
	case r := <-acquired:
		if r.err != nil {
			t.Fatalf("AcquireWait after Release: %v", r.err)
		}
		if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
			t.Errorf("AcquireWait took %v; should be near-instant after Release", elapsed)
		}
		ml.Release(r.tok)
	case <-time.After(1 * time.Second):
		t.Fatal("AcquireWait did not acquire within 1s of Release")
	}
}

func TestMountLockSlotEvicted(t *testing.T) {
	ml := NewMountLock()
	tok, err := ml.Acquire("sandfs-1")
	if err != nil {
		t.Fatalf("holder acquire: %v", err)
	}
	if _, err := ml.AcquireWait("sandfs-1", 50*time.Millisecond); err != ErrConcurrentMount {
		t.Fatalf("expected ErrConcurrentMount on waiter timeout, got %v", err)
	}
	ml.Release(tok)

	ml.mu.Lock()
	n := len(ml.slots)
	ml.mu.Unlock()
	if n != 0 {
		t.Fatalf("expected slot eviction after release, %d slot(s) remain", n)
	}

	tok, err = ml.Acquire("sandfs-1")
	if err != nil {
		t.Fatalf("acquire after eviction: %v", err)
	}
	ml.Release(tok)
}

func TestMountLockWaiterKeepsSlotAlive(t *testing.T) {
	ml := NewMountLock()
	holder, err := ml.Acquire("sandfs-1")
	if err != nil {
		t.Fatalf("holder acquire: %v", err)
	}

	type result struct {
		tok *MountLockToken
		err error
	}
	acquired := make(chan result, 1)
	go func() {
		tok, err := ml.AcquireWait("sandfs-1", time.Second)
		acquired <- result{tok, err}
	}()
	time.Sleep(50 * time.Millisecond)

	ml.mu.Lock()
	n := len(ml.slots)
	refs := ml.slots["sandfs-1"].refs
	ml.mu.Unlock()
	if n != 1 || refs != 2 {
		t.Fatalf("waiter interest not tracked: slots=%d refs=%d, want 1/2", n, refs)
	}

	ml.Release(holder)
	var r result
	select {
	case r = <-acquired:
		if r.err != nil {
			t.Fatalf("waiter takeover failed: %v", r.err)
		}
	case <-time.After(time.Second):
		t.Fatal("waiter did not acquire within 1s of Release")
	}
	ml.mu.Lock()
	refs = ml.slots["sandfs-1"].refs
	ml.mu.Unlock()
	if refs != 1 {
		t.Fatalf("waiter-as-holder refs = %d, want 1", refs)
	}
	ml.Release(r.tok)

	ml.mu.Lock()
	n = len(ml.slots)
	ml.mu.Unlock()
	if n != 0 {
		t.Fatalf("slot not evicted after final release: %d remain", n)
	}
}

func TestMountLockAcquireWaitTimeout(t *testing.T) {
	ml := NewMountLock()
	tok, err := ml.Acquire("sandfs-1")
	if err != nil {
		t.Fatalf("holder acquire: %v", err)
	}
	start := time.Now()
	if _, err := ml.AcquireWait("sandfs-1", 100*time.Millisecond); err != ErrConcurrentMount {
		t.Errorf("expected ErrConcurrentMount on timeout, got %v", err)
	}
	if elapsed := time.Since(start); elapsed < 90*time.Millisecond || elapsed > 500*time.Millisecond {
		t.Errorf("AcquireWait took %v; want ~100ms", elapsed)
	}
	ml.Release(tok)
}

// TestMountLockInFlight pins the drain-facing probe: a held slot AND a queued
// waiter both count as in-flight (a waiter already passed the request's
// lifecycle gate and will mount as soon as the holder releases), and the slot
// clears once everyone is gone.
func TestMountLockInFlight(t *testing.T) {
	ml := NewMountLock()
	if ml.InFlight("sandfs-1") {
		t.Fatal("idle lock reported in-flight")
	}
	tok, err := ml.Acquire("sandfs-1")
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if !ml.InFlight("sandfs-1") {
		t.Fatal("holder not reported in-flight")
	}
	// A queued waiter keeps the probe true even after the holder releases and
	// before the waiter becomes the holder.
	done := make(chan *MountLockToken, 1)
	go func() {
		tok2, err := ml.AcquireWaitDefault("sandfs-1")
		if err != nil {
			done <- nil
			return
		}
		done <- tok2
	}()
	// Let the waiter register.
	deadline := time.Now().Add(time.Second)
	for {
		ml.mu.Lock()
		s := ml.slots["sandfs-1"]
		waiting := s != nil && s.refs > 1
		ml.mu.Unlock()
		if waiting || time.Now().After(deadline) {
			break
		}
		time.Sleep(time.Millisecond)
	}
	ml.Release(tok)
	// The waiter's token may already be the holder; either way in-flight.
	if !ml.InFlight("sandfs-1") {
		t.Fatal("queued waiter must count as in-flight after the holder released")
	}
	tok2 := <-done
	if tok2 == nil {
		t.Fatal("waiter acquire failed")
	}
	ml.Release(tok2)
	deadline = time.Now().Add(time.Second)
	for ml.InFlight("sandfs-1") {
		if time.Now().After(deadline) {
			t.Fatal("slot still in-flight after every token was released")
		}
		time.Sleep(time.Millisecond)
	}
}

// TestDispatchInFlightProcessRegistration pins the process-level handle the
// lifecycle drain uses: the handler constructors publish their lock and the
// probe reports its state; an unregistered process reports false.
func TestDispatchInFlightProcessRegistration(t *testing.T) {
	prev := processDispatchLock.Load()
	processDispatchLock.Store(nil)
	defer processDispatchLock.Store(prev)

	if DispatchInFlight("sandfs-reg") {
		t.Fatal("no registered lock: must report false")
	}
	ml := NewMountLock()
	RegisterDispatchLock(ml)
	RegisterDispatchLock(nil) // ignored
	tok, err := ml.Acquire("sandfs-reg")
	if err != nil {
		t.Fatal(err)
	}
	if !DispatchInFlight("sandfs-reg") {
		t.Fatal("registered holder not reported")
	}
	ml.Release(tok)
	if DispatchInFlight("sandfs-reg") {
		t.Fatal("released slot reported in-flight")
	}
}

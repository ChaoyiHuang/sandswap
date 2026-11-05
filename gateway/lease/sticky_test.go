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
	"sync/atomic"
	"testing"
	"time"
)

// TestLeaseIdleExpiry verifies the per-VM sync sticky timer fires ~at timeout
// and invokes onExpiry exactly once.
func TestLeaseIdleExpiry(t *testing.T) {
	var mu sync.Mutex
	var calls []string
	l := New(30*time.Millisecond, 5*time.Second)
	l.StartExpiryWorker(func(sandfsID, vmID, spec, volumePath string) {
		mu.Lock()
		calls = append(calls, vmID)
		mu.Unlock()
	})

	l.TouchSync("agent-a", "vm-1", "")

	// Before timeout: no expiry.
	time.Sleep(15 * time.Millisecond)
	mu.Lock()
	if len(calls) != 0 {
		mu.Unlock()
		t.Fatalf("expected no expiry before timeout, got %d", len(calls))
	}
	mu.Unlock()

	// After timeout: exactly one expiry.
	time.Sleep(60 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if len(calls) != 1 || calls[0] != "vm-1" {
		t.Fatalf("expected single expiry of vm-1, got %v", calls)
	}
}

// TestLeaseTouchSyncResets verifies a TouchSync within the sticky window resets
// the timer — no premature expiry.
func TestLeaseTouchSyncResets(t *testing.T) {
	var mu sync.Mutex
	var calls int
	l := New(40*time.Millisecond, 5*time.Second)
	l.StartExpiryWorker(func(sandfsID, vmID, spec, volumePath string) {
		mu.Lock()
		calls++
		mu.Unlock()
	})

	l.TouchSync("agent-a", "vm-1", "")
	time.Sleep(25 * time.Millisecond)  // within first window
	l.TouchSync("agent-a", "vm-1", "") // reset

	// 25ms after the reset: must not have expired.
	time.Sleep(25 * time.Millisecond)
	mu.Lock()
	if calls != 0 {
		mu.Unlock()
		t.Fatalf("expected no expiry after reset, got %d", calls)
	}
	mu.Unlock()

	// Past the reset deadline: exactly one expiry.
	time.Sleep(40 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if calls != 1 {
		t.Fatalf("expected single expiry after reset deadline, got %d", calls)
	}
}

// TestLeaseReleaseStopsTimer verifies explicit Release cancels the timer.
func TestLeaseReleaseStopsTimer(t *testing.T) {
	var mu sync.Mutex
	var calls int
	l := New(30*time.Millisecond, 5*time.Second)
	l.StartExpiryWorker(func(sandfsID, vmID, spec, volumePath string) {
		mu.Lock()
		calls++
		mu.Unlock()
	})

	l.TouchSync("agent-a", "vm-1", "")
	l.Release("agent-a")

	time.Sleep(80 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if calls != 0 {
		t.Fatalf("expected no expiry after explicit Release, got %d", calls)
	}
}

// TestLeaseNoDoubleReleaseOnConcurrentTouchSync verifies the gen guard: a timer
// that fires concurrently with a TouchSync must not release the (now-reset) lease.
func TestLeaseNoDoubleReleaseOnConcurrentTouchSync(t *testing.T) {
	var calls int64
	l := New(10*time.Millisecond, 5*time.Second)
	l.StartExpiryWorker(func(sandfsID, vmID, spec, volumePath string) {
		atomic.AddInt64(&calls, 1)
	})

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				l.TouchSync("agent-a", "vm-1", "")
				time.Sleep(3 * time.Millisecond)
			}
		}
	}()

	time.Sleep(100 * time.Millisecond)
	close(stop)
	wg.Wait()

	// After stopping, wait for the final idle timer to fire.
	time.Sleep(60 * time.Millisecond)

	if atomic.LoadInt64(&calls) == 0 {
		t.Fatal("expected at least one expiry after TouchSync loop stopped")
	}
	if atomic.LoadInt64(&calls) > 2 {
		t.Fatalf("expected at most 2 expiries (gen guard), got %d", atomic.LoadInt64(&calls))
	}
	if v := l.Acquire("agent-a"); v != "" {
		t.Fatalf("expected empty Acquire after expiry, got %q", v)
	}
}

// TestLeaseShardingDistributes verifies many agents land across shards and all
// expire correctly.
func TestLeaseShardingDistributes(t *testing.T) {
	seen := make(map[int]bool)
	for i := 0; i < 1000; i++ {
		seen[shardIndex("agent-"+itoa(i))] = true
	}
	if len(seen) < leaseShards/2 {
		t.Fatalf("shard distribution too skewed: only %d/%d shards used", len(seen), leaseShards)
	}

	var mu sync.Mutex
	expired := make(map[string]bool)
	l := New(20*time.Millisecond, 5*time.Second)
	l.StartExpiryWorker(func(sandfsID, vmID, spec, volumePath string) {
		mu.Lock()
		expired[sandfsID] = true
		mu.Unlock()
	})

	const n = 100
	for i := 0; i < n; i++ {
		l.TouchSync("agent-"+itoa(i), "vm-"+itoa(i), "")
	}

	time.Sleep(80 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if len(expired) != n {
		t.Fatalf("expected all %d leases to expire, got %d", n, len(expired))
	}
}

// TestLeaseMaxHoldReaper verifies the maxHold safety-net reaper on a pure-sync
// sandfs. Set idle >> maxHold and TouchSync once (no reset): the sticky timer
// won't fire for it, and the reaper must release once maxHold elapses.
func TestLeaseMaxHoldReaper(t *testing.T) {
	var mu sync.Mutex
	var calls int
	l := New(1*time.Hour, 60*time.Millisecond) // idle never fires; reaper must
	l.StartExpiryWorker(func(sandfsID, vmID, spec, volumePath string) {
		mu.Lock()
		calls++
		mu.Unlock()
	})

	l.TouchSync("agent-a", "vm-1", "") // syncStartedAt pinned, never reset

	time.Sleep(250 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if calls != 1 {
		t.Fatalf("expected maxHold reaper to release the stale entry once, got %d", calls)
	}
}

// itoa is a tiny local int→string to avoid importing strconv in a test hot loop.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var b [20]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		b[pos] = '-'
	}
	return string(b[pos:])
}

// ─── Background exec lease model ─────────────────────────────────

// TestLeaseStartBgExecOutlivesIdle verifies a background exec lease (deadline)
// outlives the global sync sticky timeout, and a sync exec between bg polls does
// NOT shorten the bg deadline (no lease extension).
func TestLeaseStartBgExecOutlivesIdle(t *testing.T) {
	var mu sync.Mutex
	var calls int
	l := New(30*time.Millisecond, 5*time.Second) // sync sticky 30ms
	l.StartExpiryWorker(func(sandfsID, vmID, spec, volumePath string) {
		mu.Lock()
		calls++
		mu.Unlock()
	})

	// Background exec: hold the VM for 500ms (absolute deadline).
	l.StartBgExec("agent-a", "vm-1", "exec-1", 500*time.Millisecond)

	// A sync exec 50ms in (past the 30ms sticky) must NOT release the VM — the
	// bg deadline (500ms) dominates and is NOT extended by the sync exec.
	time.Sleep(50 * time.Millisecond)
	l.TouchSync("agent-a", "vm-1", "") // sync exec; must not touch bg deadline

	time.Sleep(100 * time.Millisecond) // 150ms total — still within 500ms
	mu.Lock()
	if calls != 0 {
		mu.Unlock()
		t.Fatalf("bg lease released early (sync sticky fired): %d", calls)
	}
	mu.Unlock()

	// After the 500ms deadline (NOT extended by the sync TouchSync), expire.
	time.Sleep(500 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if calls != 1 {
		t.Fatalf("expected bg lease to expire once after its deadline, got %d", calls)
	}
}

// TestLeasePollDoesNotExtend verifies a status poll (running) does NOT extend
// the bg lease deadline.
func TestLeasePollDoesNotExtend(t *testing.T) {
	var mu sync.Mutex
	var calls int
	l := New(30*time.Millisecond, 5*time.Second)
	l.StartExpiryWorker(func(sandfsID, vmID, spec, volumePath string) {
		mu.Lock()
		calls++
		mu.Unlock()
	})

	l.StartBgExec("agent-a", "vm-1", "exec-1", 100*time.Millisecond)

	// Poll "running" at 40ms and 70ms — must NOT extend the 100ms deadline.
	// (In the handler, a running poll does nothing to the lease; here we simulate
	// by NOT calling MarkBgDone.)
	time.Sleep(40 * time.Millisecond)
	if got := l.Acquire("agent-a"); got != "vm-1" {
		t.Errorf("Acquire at 40ms = %q, want vm-1 (within deadline)", got)
	}
	time.Sleep(30 * time.Millisecond)
	if got := l.Acquire("agent-a"); got != "vm-1" {
		t.Errorf("Acquire at 70ms = %q, want vm-1 (within deadline)", got)
	}

	// After 100ms deadline (un-extended), the lease expires.
	time.Sleep(80 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if calls != 1 {
		t.Fatalf("expected one expiry at the un-extended deadline, got %d", calls)
	}
}

// TestLeaseBgDoneReleasesEarly verifies that marking a bg exec done (poll saw
// completion) releases the VM before the deadline elapses.
func TestLeaseBgDoneReleasesEarly(t *testing.T) {
	var mu sync.Mutex
	var calls int
	l := New(50*time.Millisecond, 5*time.Second)
	l.StartExpiryWorker(func(sandfsID, vmID, spec, volumePath string) {
		mu.Lock()
		calls++
		mu.Unlock()
	})

	// Bg exec with a 500ms deadline.
	l.StartBgExec("agent-a", "vm-1", "exec-1", 500*time.Millisecond)

	// Poll observes done at 40ms — should release (after the 50ms sync sticky
	// window, since no bg remains active).
	time.Sleep(40 * time.Millisecond)
	l.MarkBgDone("agent-a", "exec-1")

	time.Sleep(120 * time.Millisecond) // past the 50ms sticky
	mu.Lock()
	defer mu.Unlock()
	if calls != 1 {
		t.Fatalf("expected one early expiry after bg done, got %d", calls)
	}
}

// TestLeaseMultipleBgExecsOverlap verifies that when bg A's deadline elapses
// while bg B is still active, the VM is NOT released (B holds it). Only when B
// also finishes does the VM release.
func TestLeaseMultipleBgExecsOverlap(t *testing.T) {
	var mu sync.Mutex
	var calls int
	l := New(50*time.Millisecond, 5*time.Second)
	l.StartExpiryWorker(func(sandfsID, vmID, spec, volumePath string) {
		mu.Lock()
		calls++
		mu.Unlock()
	})

	// A: 100ms deadline. B: 300ms deadline.
	l.StartBgExec("agent-a", "vm-1", "exec-A", 100*time.Millisecond)
	l.StartBgExec("agent-a", "vm-1", "exec-B", 300*time.Millisecond)

	// At ~120ms, A's deadline has elapsed (marked done by evaluate) but B is
	// still active — no release.
	time.Sleep(120 * time.Millisecond)
	mu.Lock()
	if calls != 0 {
		mu.Unlock()
		t.Fatalf("VM released while B still active (A expired): %d", calls)
	}
	mu.Unlock()

	// B finishes (poll done) at ~150ms — after the 50ms sticky, release.
	l.MarkBgDone("agent-a", "exec-B")
	time.Sleep(120 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if calls != 1 {
		t.Fatalf("expected one release after B done, got %d", calls)
	}
}

// TestLeaseSyncExecDuringBg verifies an in-flight sync exec (BeginExec/EndExec)
// prevents release even when the bg deadline elapses mid-RPC.
func TestLeaseSyncExecDuringBg(t *testing.T) {
	var mu sync.Mutex
	var calls int
	l := New(50*time.Millisecond, 5*time.Second)
	l.StartExpiryWorker(func(sandfsID, vmID, spec, volumePath string) {
		mu.Lock()
		calls++
		mu.Unlock()
	})

	// Bg with a short 80ms deadline.
	l.StartBgExec("agent-a", "vm-1", "exec-1", 80*time.Millisecond)

	// A sync exec starts (BeginExec) before the deadline and ends after it.
	time.Sleep(60 * time.Millisecond) // 60ms in, 20ms before deadline
	l.BeginExec("agent-a")
	time.Sleep(60 * time.Millisecond) // now 120ms — deadline (80ms) elapsed mid-RPC

	// The lease must NOT have been released (activeExecs > 0).
	mu.Lock()
	if calls != 0 {
		mu.Unlock()
		t.Fatalf("lease released during in-flight sync exec: %d", calls)
	}
	mu.Unlock()

	// Sync exec ends — now the expired bg + sticky window drive release.
	l.EndExec("agent-a")
	time.Sleep(120 * time.Millisecond) // past sticky
	mu.Lock()
	defer mu.Unlock()
	if calls != 1 {
		t.Fatalf("expected one release after sync exec ended, got %d", calls)
	}
}

// TestLeaseKillBgReleases verifies killing a bg exec releases the VM.
func TestLeaseKillBgReleases(t *testing.T) {
	var mu sync.Mutex
	var calls int
	l := New(50*time.Millisecond, 5*time.Second)
	l.StartExpiryWorker(func(sandfsID, vmID, spec, volumePath string) {
		mu.Lock()
		calls++
		mu.Unlock()
	})

	l.StartBgExec("agent-a", "vm-1", "exec-1", 500*time.Millisecond)

	// Kill — MarkBgDone → release after sticky.
	l.MarkBgDone("agent-a", "exec-1")

	time.Sleep(120 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if calls != 1 {
		t.Fatalf("expected one expiry after kill, got %d", calls)
	}
}

// TestLeaseBgAfterSync verifies starting a bg exec after a sync exec extends
// the hold via the bg deadline (the sync sticky no longer governs).
func TestLeaseBgAfterSync(t *testing.T) {
	var mu sync.Mutex
	var calls int
	l := New(30*time.Millisecond, 5*time.Second)
	l.StartExpiryWorker(func(sandfsID, vmID, spec, volumePath string) {
		mu.Lock()
		calls++
		mu.Unlock()
	})

	// Sync exec (30ms sticky).
	l.TouchSync("agent-a", "vm-1", "")

	// Within the 30ms window, start a bg exec with a 200ms deadline.
	time.Sleep(15 * time.Millisecond)
	l.StartBgExec("agent-a", "vm-1", "exec-1", 200*time.Millisecond)

	// Past the original 30ms sticky — lease survives (bg deadline active).
	time.Sleep(50 * time.Millisecond)
	mu.Lock()
	if calls != 0 {
		mu.Unlock()
		t.Fatalf("lease expired early after bg exec started: %d", calls)
	}
	mu.Unlock()

	// Bg done → release after sticky.
	l.MarkBgDone("agent-a", "exec-1")
	time.Sleep(80 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if calls != 1 {
		t.Fatalf("expected one expiry, got %d", calls)
	}
}

// TestLeaseShorterBgDoesNotShorten verifies that a later bg exec with a shorter
// deadline does NOT cause early release while a longer-deadline bg is active.
// (Each bg has its OWN deadline; the VM releases only when none remain active.)
func TestLeaseShorterBgDoesNotShorten(t *testing.T) {
	var mu sync.Mutex
	var calls int
	l := New(50*time.Millisecond, 5*time.Second)
	l.StartExpiryWorker(func(sandfsID, vmID, spec, volumePath string) {
		mu.Lock()
		calls++
		mu.Unlock()
	})

	// exec-1: 300ms deadline.
	l.StartBgExec("agent-a", "vm-1", "exec-1", 300*time.Millisecond)

	// 50ms later, exec-2: 100ms deadline (shorter).
	time.Sleep(50 * time.Millisecond)
	l.StartBgExec("agent-a", "vm-1", "exec-2", 100*time.Millisecond)

	// At ~160ms, exec-2's deadline (100ms from its start at 50ms = 150ms) has
	// elapsed, but exec-1 (300ms) is still active — no release.
	time.Sleep(110 * time.Millisecond)
	mu.Lock()
	if calls != 0 {
		mu.Unlock()
		t.Fatalf("VM released while exec-1 still active (exec-2 expired): %d", calls)
	}
	mu.Unlock()

	// Mark exec-1 done → release after sticky.
	l.MarkBgDone("agent-a", "exec-1")
	time.Sleep(80 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if calls != 1 {
		t.Fatalf("expected one release after exec-1 done, got %d", calls)
	}
}

// ─── Dual-mount guard ────────────────────────────────────────────

// TestLeaseAcquireWaitBlocksDuringUnmount: while onExpiry's
// UnmountRootfs is in flight (entry unmounting=true), a concurrent AcquireWait
// BLOCKS — it does not return "" and fall through to a cold mount on another
// node (which would dual-mount). Once onExpiry finishes and defers Release,
// AcquireWait returns "" (cold path).
func TestLeaseAcquireWaitBlocksDuringUnmount(t *testing.T) {
	unmountStarted := make(chan struct{})
	unmountProceed := make(chan struct{})
	l := New(20*time.Millisecond, 5*time.Second)
	l.StartExpiryWorker(func(sandfsID, nodeID, spec, volumePath string) {
		defer l.Release(sandfsID)
		close(unmountStarted)
		<-unmountProceed
	})

	l.TouchSync("agent-a", "vm-1", "")

	select {
	case <-unmountStarted:
	case <-time.After(time.Second):
		t.Fatal("onExpiry did not start in time")
	}

	type res struct {
		n   string
		err error
	}
	resCh := make(chan res, 1)
	go func() {
		n, err := l.AcquireWait("agent-a", 2*time.Second)
		resCh <- res{n, err}
	}()
	select {
	case r := <-resCh:
		t.Fatalf("AcquireWait returned before unmount finished: n=%q err=%v", r.n, r.err)
	case <-time.After(50 * time.Millisecond):
		// good: still blocked
	}

	close(unmountProceed)
	select {
	case r := <-resCh:
		if r.err != nil || r.n != "" {
			t.Fatalf("after unmount, expected cold path ('', nil), got n=%q err=%v", r.n, r.err)
		}
	case <-time.After(time.Second):
		t.Fatal("AcquireWait did not unblock after unmount finished")
	}
}

// TestLeaseAcquireWaitTimeout: if the unmount doesn't finish within
// the wait timeout, AcquireWait returns ErrWaitForUnmount (handler 503+retry).
func TestLeaseAcquireWaitTimeout(t *testing.T) {
	l := New(20*time.Millisecond, 5*time.Second)
	l.StartExpiryWorker(func(sandfsID, nodeID, spec, volumePath string) {
		defer l.Release(sandfsID)
		time.Sleep(300 * time.Millisecond)
	})
	l.TouchSync("agent-a", "vm-1", "")
	time.Sleep(60 * time.Millisecond)

	_, err := l.AcquireWait("agent-a", 50*time.Millisecond)
	if err != ErrWaitForUnmount {
		t.Fatalf("expected ErrWaitForUnmount, got %v", err)
	}
	time.Sleep(300 * time.Millisecond)
}

// TestLeaseNoSpinDuringInFlightSync verifies the rearm policy: while an
// in-flight RPC is the sole remaining hold (sticky elapsed, no bg), NO timer is
// armed (the old 1ms fallback spun evaluate for the whole RPC duration); the
// completing EndExec rearms and releases promptly.
func TestLeaseNoSpinDuringInFlightSync(t *testing.T) {
	l := New(20*time.Millisecond, time.Hour)
	calls := make(chan struct{}, 1)
	l.StartExpiryWorker(func(sandfsID, nodeID, spec, volumePath string) { calls <- struct{}{} })

	l.TouchSync("agent-a", "vm-1", "")
	// Sync exec starts within the sticky window and outlives it.
	l.BeginExec("agent-a")

	time.Sleep(100 * time.Millisecond) // 5x sticky: old code would spin evaluate here

	shard := l.shard("agent-a")
	shard.mu.Lock()
	e := shard.entries["agent-a"]
	armed := e != nil && e.timer != nil
	shard.mu.Unlock()
	if e == nil {
		t.Fatal("lease entry vanished during in-flight sync exec")
	}
	if armed {
		t.Fatal("timer armed while in-flight RPC is the sole hold; evaluate would spin at 1ms")
	}
	select {
	case <-calls:
		t.Fatal("lease released during in-flight sync exec")
	default:
	}

	// EndExec rearms → release fires promptly.
	l.EndExec("agent-a")
	select {
	case <-calls:
	case <-time.After(time.Second):
		t.Fatal("lease not released after EndExec despite elapsed sticky window")
	}
}

// TestLeaseReapSkipsInFlightRPC: reapMaxHold must not release an
// entry whose syncStartedAt is past maxHold while a sync exec is still in
// flight — that would unmount the VM underneath the running command. After the
// RPC ends, the lease releases promptly.
func TestLeaseReapSkipsInFlightRPC(t *testing.T) {
	var mu sync.Mutex
	var calls int
	l := New(1*time.Hour, 50*time.Millisecond) // idle never fires; reaper interval 25ms
	l.StartExpiryWorker(func(sandfsID, nodeID, spec, volumePath string) {
		mu.Lock()
		calls++
		mu.Unlock()
	})

	l.TouchSync("agent-a", "vm-1", "") // anchors syncStartedAt
	l.BeginExec("agent-a")             // long-running sync exec

	time.Sleep(200 * time.Millisecond) // 4x maxHold, several reaper sweeps

	if got := l.Acquire("agent-a"); got != "vm-1" {
		t.Fatalf("warm lease yanked during in-flight sync exec: got %q", got)
	}
	mu.Lock()
	if calls != 0 {
		mu.Unlock()
		t.Fatalf("reapMaxHold fired onExpiry mid-exec %d time(s)", calls)
	}
	mu.Unlock()

	l.EndExec("agent-a")
	time.Sleep(120 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if calls != 1 {
		t.Fatalf("expected one release after EndExec, got %d", calls)
	}
}

// TestLeaseEvaluateNoDoubleOnExpiryAfterReapMaxHold: if reapMaxHold
// transitions an entry to unmounting and fires onExpiry (in flight), a racing
// evaluate with the same gen MUST NOT fire onExpiry a second time.
func TestLeaseEvaluateNoDoubleOnExpiryAfterReapMaxHold(t *testing.T) {
	var calls atomic.Int32
	started := make(chan struct{})
	proceed := make(chan struct{})
	l := New(1*time.Hour, 1*time.Millisecond) // idle never fires; reaper fires ~immediately
	l.StartExpiryWorker(func(sandfsID, nodeID, spec, volumePath string) {
		defer l.Release(sandfsID)
		calls.Add(1)
		close(started)
		<-proceed
	})

	l.TouchSync("agent-a", "vm-1", "") // gen=1

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("reaper's onExpiry did not start in time")
	}

	// onExpiry in flight (entry unmounting=true). Fire evaluate with the SAME
	// gen: the unmounting guard must make it a no-op (no second onExpiry).
	l.evaluate("agent-a", 1)

	if got := calls.Load(); got != 1 {
		t.Fatalf("expected onExpiry called once (reaper), got %d (double-fire bug)", got)
	}

	close(proceed)
	time.Sleep(50 * time.Millisecond)
}

// TestAcquireWaitReleasableTriggersUnmount verifies the fix for the
// mount-leak race: when a request's AcquireWait observes an entry whose sticky
// window already elapsed (timer-wheel lag), the entry must NOT be silently
// deleted — the unmount must be dispatched and AcquireWait must block until it
// completes, so the caller's subsequent cold mount cannot land on another node
// while the old VM still holds the mount.
func TestAcquireWaitReleasableTriggersUnmount(t *testing.T) {
	var calls atomic.Int32
	releaseGate := make(chan struct{}) // hold the unmount in flight
	l := New(20*time.Millisecond, 5*time.Second)
	l.StartExpiryWorker(func(sandfsID, nodeID, spec, volumePath string) {
		calls.Add(1)
		<-releaseGate // simulate an in-flight unmount RPC
		l.Release(sandfsID)
	})

	// Arm a lease whose sticky window expires almost immediately.
	l.TouchSync("sandfs-1", "node-1", "small")
	time.Sleep(60 * time.Millisecond) // sticky elapsed; the timer may or may not have fired yet

	done := make(chan struct{})
	var node string
	var err error
	go func() {
		defer close(done)
		node, err = l.AcquireWait("sandfs-1", 2*time.Second)
	}()

	// AcquireWait must observe the releasable entry, dispatch the unmount (async),
	// and block until it finishes — never return a cold path "" instantly while
	// the mount leaks.
	select {
	case <-done:
		t.Fatal("AcquireWait returned before the unmount completed (silent delete / cold-path fallthrough)")
	case <-time.After(100 * time.Millisecond):
	}

	close(releaseGate) // let the unmount finish
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("AcquireWait did not return after the unmount completed")
	}
	if node != "" || err != nil {
		t.Fatalf("expected cold-path return after unmount, got node=%q err=%v", node, err)
	}
	if calls.Load() == 0 {
		t.Fatal("no unmount dispatched for the releasable entry")
	}
	// The entry must be gone (released by the callback), not lingering unmounting.
	if n := l.Acquire("sandfs-1"); n != "" {
		t.Fatalf("entry leaked after unmount: node=%q", n)
	}
}

// TestAcquireReleasableTriggersUnmount is the non-blocking Acquire variant: it
// returns "" immediately (poll path must not block) but still dispatches the
// unmount instead of silently deleting the entry.
func TestAcquireReleasableTriggersUnmount(t *testing.T) {
	var calls atomic.Int32
	l := New(20*time.Millisecond, 5*time.Second)
	l.StartExpiryWorker(func(sandfsID, nodeID, spec, volumePath string) {
		calls.Add(1)
		l.Release(sandfsID)
	})

	l.TouchSync("sandfs-1", "node-1", "")
	time.Sleep(60 * time.Millisecond) // sticky elapsed

	if n := l.Acquire("sandfs-1"); n != "" {
		t.Fatalf("expected cold-path \"\" from releasable entry, got %q", n)
	}
	deadline := time.Now().Add(2 * time.Second)
	for calls.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if calls.Load() == 0 {
		t.Fatal("Acquire's releasable shortcut never dispatched the unmount")
	}
}

// TestRetryUnmountRedispatchesAfterFailure verifies the success-gated teardown:
// an expiry callback whose unmount FAILED (and therefore did not Release)
// gets re-dispatched by RetryUnmount with backoff until it succeeds.
func TestRetryUnmountRedispatchesAfterFailure(t *testing.T) {
	var calls atomic.Int32
	succeedOn := int32(3) // third attempt succeeds
	l := New(20*time.Millisecond, 5*time.Second)
	l.StartExpiryWorker(func(sandfsID, nodeID, spec, volumePath string) {
		if calls.Add(1) >= atomic.LoadInt32(&succeedOn) {
			l.Release(sandfsID) // success → teardown
			return
		}
		// Failure branch (mirrors the production wiring): keep the entry, retry.
		l.RetryUnmount(sandfsID, nodeID, spec)
	})

	l.TouchSync("sandfs-1", "node-1", "small")
	time.Sleep(60 * time.Millisecond) // sticky elapsed → evaluate → attempt 1

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if calls.Load() >= 3 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if calls.Load() < 3 {
		t.Fatalf("expected 3 unmount attempts (2 failures + success), got %d", calls.Load())
	}
	// Success released the entry — no further dispatches.
	time.Sleep(200 * time.Millisecond)
	if c := calls.Load(); c != 3 {
		t.Fatalf("expected dispatch to stop after success, got %d attempts", c)
	}
	if n := l.Acquire("sandfs-1"); n != "" {
		t.Fatalf("entry not released after successful retry: node=%q", n)
	}
}

// TestRetryUnmountNoopsOnReleasedEntry verifies a retry armed just before a
// Release (node disconnect, successful unmount elsewhere) does not resurrect
// the entry or re-dispatch.
func TestRetryUnmountNoopsOnReleasedEntry(t *testing.T) {
	var calls atomic.Int32
	l := New(20*time.Millisecond, 5*time.Second)
	l.StartExpiryWorker(func(sandfsID, nodeID, spec, volumePath string) {
		calls.Add(1)
		l.RetryUnmount(sandfsID, nodeID, spec) // always "fail" → always retry
	})

	l.TouchSync("sandfs-1", "node-1", "")
	time.Sleep(60 * time.Millisecond) // first dispatch
	first := calls.Load()
	if first == 0 {
		t.Fatal("first dispatch never ran")
	}
	l.ReleaseByNode("node-1") // node gone: entry deleted, retries must cancel
	time.Sleep(500 * time.Millisecond)
	if after := calls.Load(); after != first {
		t.Fatalf("retry dispatched after ReleaseByNode: before=%d after=%d", first, after)
	}
}

// ── Unmount settlement, panic recovery, pruning (unmount teardown paths) ──

// TestSettleUnmountExactlyOnce verifies the exactly-once guard for unmount
// teardown: concurrent idempotent unmounts (lease expiry racing the fence or
// the publish-failure compensation) must settle the entry exactly once, or the
// pool's bound count would be double-decremented (over-admitting one VM per
// occurrence).
func TestSettleUnmountExactlyOnce(t *testing.T) {
	l := New(100*time.Millisecond, 5*time.Second)
	l.TouchSync("s1", "n1", "medium")

	// SettleUnmount is atomic under the shard lock, so back-to-back settles
	// from "concurrent" unmount paths decide synchronously: exactly one wins.
	wins := 0
	if l.SettleUnmount("s1") {
		wins++
	}
	if l.SettleUnmount("s1") {
		wins++
	}
	if wins != 1 {
		t.Fatalf("SettleUnmount settled %d times, want exactly 1", wins)
	}
	// A third settle on the deleted entry also loses.
	if l.SettleUnmount("s1") {
		t.Fatal("third SettleUnmount returned true; entry was already settled")
	}
}

// TestDispatchExpiryPanicSchedulesRetry verifies that a panic inside onExpiry
// does not wedge the entry in `unmounting` forever (no timer, no retry, reaper
// skips unmounting entries): the recover must re-arm the retry chain, and a
// later successful dispatch must release the entry.
func TestDispatchExpiryPanicSchedulesRetry(t *testing.T) {
	l := New(100*time.Millisecond, 5*time.Second)
	var calls atomic.Int64
	l.StartExpiryWorker(func(sandfsID, nodeID, spec, volumePath string) {
		if calls.Add(1) == 1 {
			panic("boom: first expiry dispatch panics")
		}
		// Second dispatch succeeds and settles.
		if !l.SettleUnmount(sandfsID) {
			t.Errorf("retrying dispatch could not settle the entry (already gone?)")
		}
	})
	defer l.Close()

	l.TouchSync("s1", "n1", "medium")
	// Trigger the releasable shortcut synchronously: Acquire on a
	// past-sticky entry flips it to unmounting and dispatches on a goroutine.
	time.Sleep(150 * time.Millisecond) // sticky (100ms) elapses
	if got := l.Acquire("s1"); got != "" {
		t.Fatalf("Acquire on releasable entry = %q, want \"\"", got)
	}
	// The panic recovery schedules RetryUnmount with a 1s first backoff; the
	// retry must then succeed and release the entry (AcquireWait no longer
	// blocks on unmounting).
	deadline := time.Now().Add(5 * time.Second)
	for {
		s := l.shard("s1")
		s.mu.Lock()
		_, exists := s.entries["s1"]
		s.mu.Unlock()
		if !exists {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("entry still exists 5s after panicking dispatch: the recover did not re-arm the retry chain (permanent unmounting wedge)")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if calls.Load() < 2 {
		t.Fatalf("onExpiry dispatched %d times, want >= 2 (panic + successful retry)", calls.Load())
	}
}

// TestBgExecsPruned verifies that settled background holds are pruned on
// evaluation, bounding the map on long-lived entries (a chatty sandfs mixing
// bg execs with sync/file ops otherwise grows it for the entry's lifetime).
func TestBgExecsPruned(t *testing.T) {
	// Long sticky window so the entry itself stays alive (releasable=false)
	// while the bg deadlines pass — isolating the pruning from the release.
	// TouchSync first: an entry born from StartBgExec alone carries no sync
	// anchor and is releasable the moment its bg execs settle.
	l := New(1*time.Hour, 5*time.Second)
	l.TouchSync("s1", "n1", "medium")
	l.StartBgExec("s1", "n1", "e1", 40*time.Millisecond)
	l.StartBgExec("s1", "n1", "e2", 40*time.Millisecond)

	// The timer fires at the earliest deadline, marks both expired, prunes
	// them, and re-arms (the entry is retained by the sticky window).
	deadline := time.Now().Add(3 * time.Second)
	for {
		s := l.shard("s1")
		s.mu.Lock()
		e, ok := s.entries["s1"]
		n := 0
		if ok {
			n = len(e.bgExecs)
		}
		s.mu.Unlock()
		if !ok {
			t.Fatal("entry was released despite the long sticky window; test setup broken")
		}
		if n == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("bgExecs still holds %d settled entries after 3s; pruning is not bounding the map", n)
		}
		time.Sleep(20 * time.Millisecond)
	}
	// A late MarkBgDone for a pruned exec must be a harmless no-op (not a
	// resurrected hold).
	l.MarkBgDone("s1", "e1")
	s := l.shard("s1")
	s.mu.Lock()
	resurrected := len(s.entries["s1"].bgExecs)
	s.mu.Unlock()
	if resurrected != 0 {
		t.Fatalf("MarkBgDone resurrected %d pruned holds", resurrected)
	}
}

// TestForceUnmountCreatesEntryAndDispatches verifies the fence/compensation
// entry point: ForceUnmount on a sandfs with NO lease entry creates one born
// unmounting (blocking concurrent cold mounts on waitDone) and dispatches the
// expiry callback; on success the entry settles.
func TestForceUnmountCreatesEntryAndDispatches(t *testing.T) {
	l := New(100*time.Millisecond, 5*time.Second)
	dispatched := make(chan string, 1)
	l.StartExpiryWorker(func(sandfsID, nodeID, spec, volumePath string) {
		dispatched <- sandfsID
		// Settle as a successful unmount would.
		l.SettleUnmount(sandfsID)
	})
	defer l.Close()

	l.ForceUnmount("s1", "n1", "medium")
	select {
	case id := <-dispatched:
		if id != "s1" {
			t.Fatalf("dispatched sandfs = %q, want s1", id)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ForceUnmount did not dispatch onExpiry for the entry-less sandfs")
	}
	if l.HasActiveEntry("s1") {
		t.Fatal("entry still active after a settled ForceUnmount dispatch")
	}
}

// TestForceUnmountTransitionsLiveEntry verifies ForceUnmount on an existing
// warm entry flips it to unmounting (blocking AcquireWait) instead of racing
// a concurrent cold mount against the in-flight unmount.
func TestForceUnmountTransitionsLiveEntry(t *testing.T) {
	l := New(20*time.Millisecond, 1*time.Hour) // sticky keeps it warm
	block := make(chan struct{})
	l.StartExpiryWorker(func(sandfsID, nodeID, spec, volumePath string) {
		<-block // hold the unmount "RPC" in flight
		l.SettleUnmount(sandfsID)
	})
	defer l.Close()

	l.TouchSync("s1", "n1", "medium")
	// ForceUnmount dispatches onExpiry synchronously (the dispatchExpiry
	// contract) — run it on a goroutine so the unmount is observably in
	// flight while the main goroutine probes AcquireWait.
	go l.ForceUnmount("s1", "n1", "medium")

	// Wait for the transition to land (the goroutine may not have flagged the
	// entry yet when we probe).
	flipped := time.Now().Add(2 * time.Second)
	for l.HasActiveEntry("s1") {
		if time.Now().After(flipped) {
			t.Fatal("ForceUnmount did not flip the live entry to unmounting within 2s")
		}
		time.Sleep(5 * time.Millisecond)
	}
	// While the unmount is in flight, AcquireWait must block (dual-mount
	// guard), not return a warm node.
	if n, err := l.AcquireWait("s1", 100*time.Millisecond); err == nil && n != "" {
		t.Fatalf("AcquireWait during forced unmount = %q, want \"\" (blocked)", n)
	}
	close(block)
	deadline := time.Now().Add(2 * time.Second)
	for l.HasActiveEntry("s1") {
		if time.Now().After(deadline) {
			t.Fatal("entry still active after the forced unmount settled")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestHasActiveEntry verifies the read-only guard used by the shed path:
// true for a warm entry, false for none / unmounting.
func TestHasActiveEntry(t *testing.T) {
	l := New(20*time.Millisecond, 1*time.Hour)
	if l.HasActiveEntry("s1") {
		t.Fatal("HasActiveEntry true with no entry")
	}
	l.TouchSync("s1", "n1", "medium")
	if !l.HasActiveEntry("s1") {
		t.Fatal("HasActiveEntry false for a warm entry")
	}
	l.BeginExec("s1") // simulate in-flight RPC; still active
	if !l.HasActiveEntry("s1") {
		t.Fatal("HasActiveEntry false for an entry with an in-flight RPC")
	}
	l.EndExec("s1")
	// Releasable-but-not-yet-released: still an active entry.
	if !l.HasActiveEntry("s1") {
		t.Fatal("HasActiveEntry false for a releasable-but-alive entry")
	}
	l.Release("s1")
	if l.HasActiveEntry("s1") {
		t.Fatal("HasActiveEntry true after Release")
	}
}

// TestWarmTouchSyncDefeatsMaxHoldReaper verifies the lease-layer contract the
// file-handler warm path now relies on: continuous warm ops (AcquireWait +
// TouchSync, exactly what a warm /agent/file request does) keep the entry
// alive past maxHold — the reaper must not release a lease whose anchor keeps
// being refreshed.
func TestWarmTouchSyncDefeatsMaxHoldReaper(t *testing.T) {
	// Sticky (150ms) must exceed the loop gap (30ms) so every probe happens
	// warm; maxHold (300ms) is what the reaper would enforce against a stale
	// syncStartedAt anchor.
	l := New(150*time.Millisecond, 300*time.Millisecond)
	released := make(chan string, 4)
	l.StartExpiryWorker(func(sandfsID, nodeID, spec, volumePath string) {
		released <- sandfsID
	})
	defer l.Close()

	l.TouchSync("s1", "n1", "medium")           // cold mount anchors syncStartedAt
	deadline := time.Now().Add(2 * time.Second) // ~6x maxHold
	for time.Now().Before(deadline) {
		n, err := l.AcquireWait("s1", 100*time.Millisecond)
		if err != nil || n != "n1" {
			t.Fatalf("warm AcquireWait = %q, %v; want n1, nil", n, err)
		}
		l.TouchSync("s1", "n1", "medium") // warm op refreshes the anchor
		time.Sleep(30 * time.Millisecond) // reaper ticks at maxHold/2 = 150ms
	}
	select {
	case id := <-released:
		t.Fatalf("reaper released an actively-warm lease: %s", id)
	default:
	}
}

// TestLeaseNoSpinWhileBgActive: once the sync sticky window lapses while a
// background exec is still active, the per-entry timer must sit on the bg
// deadline — NOT spin evaluate at the 1ms rearm fallback. The pre-fix
// nextDeadline let the lapsed syncStickyUntil dominate min(bg deadlines,
// sticky), re-arming at ~1kHz for the whole bg duration (~180 rearms/200ms
// measured). The gen counter (bumped on every rearm) is sampled over a quiet
// window with no ops, so only timer-driven rearms move it.
func TestLeaseNoSpinWhileBgActive(t *testing.T) {
	cases := []struct {
		name   string
		sticky time.Duration
		touch  bool // TouchSync after StartBgExec (bg-born lease = false)
	}{
		{"default 100ms window lapsed while bg active", 100 * time.Millisecond, true},
		{"bg-born lease (no sync op ever)", 100 * time.Millisecond, false},
		{"minimum 1ms window while bg active", time.Millisecond, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var calls int32
			l := New(tc.sticky, 5*time.Second)
			l.StartExpiryWorker(func(sandfsID, nodeID, spec, volumePath string) {
				atomic.AddInt32(&calls, 1)
			})
			l.StartBgExec("agent-a", "vm-1", "e1", 500*time.Millisecond)
			if tc.touch {
				l.TouchSync("agent-a", "vm-1", "")
			}

			// Let the (short) sticky window lapse, then sample gen: timer
			// rearms during a quiet bg-active hold should be ~zero (one
			// evaluate when the window lapses re-arms straight to the bg
			// deadline at +500ms, outside the sampling window).
			time.Sleep(150 * time.Millisecond)
			shard := l.shard("agent-a")
			shard.mu.Lock()
			g0 := shard.entries["agent-a"].gen
			shard.mu.Unlock()
			time.Sleep(150 * time.Millisecond)
			shard.mu.Lock()
			g1 := shard.entries["agent-a"].gen
			shard.mu.Unlock()
			if d := g1 - g0; d > 3 {
				t.Fatalf("timer spin while bg exec active: %d rearms in 150ms (expected <=3)", d)
			}

			// No release while the bg exec is live, and exactly one once its
			// deadline elapses.
			if c := atomic.LoadInt32(&calls); c != 0 {
				t.Fatalf("lease released while bg exec active: %d calls", c)
			}
			deadline := time.Now().Add(2 * time.Second)
			for atomic.LoadInt32(&calls) == 0 && time.Now().Before(deadline) {
				time.Sleep(5 * time.Millisecond)
			}
			if c := atomic.LoadInt32(&calls); c != 1 {
				t.Fatalf("expected exactly one expiry after bg deadline, got %d", c)
			}
		})
	}
}

// TestLeaseMinimumWindowFutureBoundary: the smallest valid window (1ms) must
// still write a real future boundary on refresh — syncStickyUntil strictly
// after the TouchSync moment. A 0 window would write an instantly-stale
// boundary (the refresh mechanism the config validation rejects 0 for).
func TestLeaseMinimumWindowFutureBoundary(t *testing.T) {
	l := New(time.Millisecond, 5*time.Second)
	t0 := time.Now()
	l.TouchSync("agent-a", "vm-1", "")
	shard := l.shard("agent-a")
	shard.mu.Lock()
	e := shard.entries["agent-a"]
	if e == nil {
		shard.mu.Unlock()
		t.Fatal("TouchSync did not create a lease entry")
	}
	boundary := e.syncStickyUntil
	shard.mu.Unlock()
	if !boundary.After(t0) {
		t.Fatalf("1ms window wrote a non-future boundary: %v not after %v", boundary, t0)
	}
}

// TestLeaseWarmJoinWithinWindow: an arrival inside the sticky window takes the
// warm node (Acquire returns it and refreshes the window); once the refreshed
// boundary elapses with no further arrivals, exactly one expiry fires.
func TestLeaseWarmJoinWithinWindow(t *testing.T) {
	var calls int32
	l := New(30*time.Millisecond, 5*time.Second)
	l.StartExpiryWorker(func(sandfsID, nodeID, spec, volumePath string) {
		atomic.AddInt32(&calls, 1)
	})

	l.TouchSync("agent-a", "vm-1", "")
	time.Sleep(10 * time.Millisecond) // inside the 30ms window
	if n := l.Acquire("agent-a"); n != "vm-1" {
		t.Fatalf("arrival within sticky window did not join warm VM: got %q", n)
	}
	// Acquire refreshed the boundary to now+30ms; no further arrivals → the
	// lease releases after that and only then.
	time.Sleep(20 * time.Millisecond)
	if c := atomic.LoadInt32(&calls); c != 0 {
		t.Fatalf("lease released before the refreshed boundary: %d calls", c)
	}
	deadline := time.Now().Add(2 * time.Second)
	for atomic.LoadInt32(&calls) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if c := atomic.LoadInt32(&calls); c != 1 {
		t.Fatalf("expected exactly one expiry after refreshed boundary, got %d", c)
	}
}

// TestLeaseWindowRefreshedByArrival: each arrival rewrites the boundary
// (now + window), so a second arrival extends the hold past the ORIGINAL
// boundary — the refresh chain that makes a >=1ms window meaningful. A 0
// window cannot express this: every refresh would be instantly stale.
func TestLeaseWindowRefreshedByArrival(t *testing.T) {
	var calls int32
	l := New(30*time.Millisecond, 5*time.Second)
	l.StartExpiryWorker(func(sandfsID, nodeID, spec, volumePath string) {
		atomic.AddInt32(&calls, 1)
	})

	l.TouchSync("agent-a", "vm-1", "") // boundary T0+30ms
	time.Sleep(20 * time.Millisecond)
	if n := l.Acquire("agent-a"); n != "vm-1" {
		t.Fatalf("arrival within sticky window did not join warm VM: got %q", n)
	} // boundary now ~T0+50ms
	time.Sleep(25 * time.Millisecond) // ~T0+45ms: past the ORIGINAL boundary
	if c := atomic.LoadInt32(&calls); c != 0 {
		t.Fatalf("lease released before the arrival-refreshed boundary: %d calls", c)
	}
	if !l.HasActiveEntry("agent-a") {
		t.Fatal("lease entry gone before the refreshed boundary elapsed")
	}
	deadline := time.Now().Add(2 * time.Second)
	for atomic.LoadInt32(&calls) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if c := atomic.LoadInt32(&calls); c != 1 {
		t.Fatalf("expected exactly one expiry after refreshed boundary, got %d", c)
	}
}

// TestBgHoldLifecyclePinsW4Survivors pins the background-hold lifecycle edges
// the W4 lease mutation pass proved unpinned (all four survived every
// operator flip):
//
//  1. StartBgExec with NO explicit lease_duration (0 — the default shape)
//     must HOLD the entry for as long as the exec runs: the hold's deadline
//     is a far-future sentinel precisely so hasActiveBg stays true until
//     MarkBgDone. The <=-to-< flip released the VM while the exec ran.
//  2. MarkBgDone must make the done hold INACTIVE even with a far-future
//     deadline — "released when a poll sees done" is the no-cap contract.
//  3. StartExpiryWorker with syncMaxHold()==0 must DISABLE the reaper (the
//     0-sentinel: flipping <=-to-< turned "disabled" into reap-everything).
//  4. A panicking onExpiry must be RECOVERED by evaluate (the guard fires
//     in production; the ==-flip let the panic kill the timer goroutine).
//     Run via StartExpiryWorker's own goroutine wiring — a panic escaping
//     evaluate would crash the whole test binary, so survival IS the pin.
//
// entryActive reads the entry's active-bg state under the shard lock (the
// contract hasActiveBg documents).
func entryActive(l *Lease, sandfsID string) bool {
	s := l.shard(sandfsID)
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.entries[sandfsID]
	if e == nil {
		return false
	}
	return l.hasActiveBg(e, time.Now())
}

func TestBgHoldLifecyclePinsW4Survivors(t *testing.T) {
	l := New(100*time.Millisecond, 5*time.Second)

	// 1. zero lease_duration holds
	l.StartBgExec("sf-bg0", "node-1", "bg-1", 0)
	if !l.HasEntry("sf-bg0") {
		t.Fatal("zero-lease bg start must establish the entry")
	}
	// hasActiveBg MUST run under the shard lock (its contract): reading the
	// entries/bgExecs maps bare races the expiry timer's mutations — a fatal
	// concurrent map read/write under load.
	if !entryActive(l, "sf-bg0") {
		t.Fatal("zero-lease bg hold must be ACTIVE while the exec runs (far-future sentinel)")
	}

	// 2. MarkBgDone deactivates the hold despite the far-future deadline
	l.MarkBgDone("sf-bg0", "bg-1")
	if entryActive(l, "sf-bg0") {
		t.Fatal("a done hold must not keep the VM warm past its poll (done beats the far-future deadline)")
	}
	l.Close()

	// 3. syncMaxHold()==0 disables the reaper: StartExpiryWorker must return
	// without arming anything (l.done stays nil) — the disabled sentinel.
	l0 := New(100*time.Millisecond, 0) // maxHold 0 = reaper disabled
	l0.StartExpiryWorker(func(string, string, string, string) {})
	if l0.done != nil {
		t.Fatal("syncMaxHold()==0 must disable the maxHold reaper (0 is the off sentinel)")
	}
	l0.Close()

	// 4. panic recovery: a panicking onExpiry must not take down the caller
	// (evaluate's recover). StartExpiryWorker wires the goroutine; drive a
	// panicking expiry directly through evaluate with the worker wired.
	l1 := New(100*time.Millisecond, 5*time.Second)
	l1.StartExpiryWorker(func(string, string, string, string) { panic("boom") })
	l1.TouchSync("sf-panic", "node-1", "medium")
	l1.ForceUnmount("sf-panic", "node-1", "medium") // dispatches onExpiry → panics → recovered
	// reaching here without the binary crashing IS the assertion; the entry
	// lands wherever the (recovered) release path leaves it.
	time.Sleep(50 * time.Millisecond)
	l1.Close()
}

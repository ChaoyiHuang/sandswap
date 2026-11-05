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
// Package lease implements microVM leases for Sandswap sandboxes.
// Lease model (background-exec-aware):
// A lease keeps a microVM mounted for a sandfs so subsequent calls skip the
// virtio-fs allowed_dirs swap + mount overhead. A lease is released (the VM is
// unmounted) only when ALL of these hold:
//	activeExecs == 0              — no in-flight RPC (sync exec, file op, bg
//	                                start, status poll, kill) is running
//	no active bg exec              — every background exec is done (poll saw
//	                                done/killed/not_found) OR past its deadline
//	syncStickyUntil elapsed        — the 100ms post-sync-release window passed
// lease_duration is a background exec's ABSOLUTE run-time cap (maxHold), NOT an
// idle window. A status poll does NOT extend it. When the deadline elapses, the
// exec is marked done (expired) and the lease is re-evaluated; if nothing else
// holds the VM, it is unmounted (unmount's cgroup.kill clears the still-running
// expired task). If another bg exec or an in-flight sync exec still holds the
// VM, the expired exec stays marked done but the VM is retained until the last
// hold drops.
// Overlap rules:
//   - bg A (lease 300) + bg B (lease 500): A's deadline fires at T300, marks A
//     done, but B is still active → VM retained. At T500 B's deadline fires,
//     nothing holds → unmount (cgroup.kill clears A and B together).
//   - sync exec between bg polls: BeginExec/EndExec brackets the RPC; the sync
//     exec does NOT touch any bg deadline (no lease extension). After it ends a
//     100ms sticky window arms, but an active bg still dominates the hold.
// Idle timers: each entry has one time.AfterFunc, armed to the next release
// opportunity (min of active bg deadlines, syncStickyUntil, or the global
// maxHold safety cap for pure-sync sandboxes). On fire it re-evaluates under the
// shard lock; if release conditions hold it triggers onExpiry (unmount),
// otherwise it re-arms. The gen counter guards against stale fires.

package lease

import (
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// leaseShards is the number of independent lock shards. Each operation takes a
// single shard's lock for microseconds; sharding means distinct sandfs never
// contend on the same lock. 32 is enough to remove lock contention as a
// bottleneck well past 100k concurrent leases on commodity hardware.
const leaseShards = 32

// Lease holds microVMs for sandfs after execution completes. Each entry has its
// own timer (time.AfterFunc), so evaluation is independent per sandfs — no
// global ticker scanning the whole map. A low-frequency reaper remains as a
// safety net for the global maxHold cap on pure-sync sandboxes (a chatty
// sync-only sandfs that keeps re-TouchSyncing never lets the sticky timer fire;
// the reaper releases it once maxHold elapses).
type Lease struct {
	shards  [leaseShards]*leaseShard
	timeout atomic.Int64 // sync sticky window (default 100ms), int64 nanoseconds
	maxHold atomic.Int64 // absolute hold cap for pure-sync sandboxes (default 5s)

	// onExpiry is set once by StartExpiryWorker at startup, before any HTTP
	// request can call Touch. It is then only read by the timer/reaper
	// goroutines (happens-before via startup ordering; no further sync needed).
	onExpiry func(sandfsID, nodeID, spec, volumePath string)

	// fireLag records lease-fire punctuality: evaluate calls it with
	// (nodeID, now - syncStickyUntil) whenever it dispatches a release at or
	// after the entry's sync sticky deadline. Atomic so a late Set is safe;
	// nil = recording disabled (tests, gateways without a stats collector).
	fireLag atomic.Pointer[func(nodeID string, lag time.Duration)]

	done      chan struct{}
	closeOnce sync.Once
}

type leaseShard struct {
	mu      sync.Mutex
	entries map[string]*LeaseEntry // sandfsID → entry
}

// bgHold tracks one background exec's lease.
type bgHold struct {
	deadline time.Time // start + lease_duration; absolute run-time cap
	done     bool      // poll saw done/killed/not_found, or deadline expired
}

// LeaseEntry tracks a single sandfs's microVM lease.
type LeaseEntry struct {
	NodeID string
	// Spec is the actual VM spec serving this sandfs: set on the
	// cold mount so onExpiry can ReleaseBound(node, spec) and the derived clean
	// count rises on unmount. Empty = unknown/medium.
	Spec string
	// VolumePath is the record's host-side volume path at mount time. The
	// expiry unmount carries it so a stale/retried unmount cannot tear down a
	// newer generation of the same sandfs.
	VolumePath string
	// VolumeEpoch is the record's per-create volume identity at mount time;
	// the expiry unmount carries it for the node-side generation check.
	VolumeEpoch string
	// bgExecs tracks background execs by execID. An exec is "active" while
	// !done && now < deadline. The lease is retained while any active bg exec
	// exists. Polls do not extend deadline.
	bgExecs map[string]*bgHold
	// activeExecs is the in-flight RPC refcount (sync exec, file op, bg start,
	// status poll, kill). The lease is NOT released while > 0 — onExpiry would
	// race an in-flight exec (and the unmount RPC's 8s timeout can lose to a
	// long sync exec). BeginExec/EndExec must be paired (defer EndExec on the
	// error path).
	activeExecs int
	// syncStickyUntil is the moment the post-sync sticky window ends. Set by
	// TouchSync after a sync exec / file op completes; only consulted when there
	// is no active bg exec (bg deadlines dominate).
	syncStickyUntil time.Time
	// syncStartedAt anchors the global maxHold cap for pure-sync sandboxes. Reset
	// by each TouchSync so a chatty sync-only sandfs is bounded by maxHold even
	// though its sticky timer keeps getting re-armed.
	syncStartedAt time.Time
	// gen is bumped on every state change that re-arms the timer. The armed
	// timer captures the gen it was created with; on fire it re-checks gen under
	// the shard lock and no-ops if superseded. Guards the Go timer race where
	// Stop() returns false because the timer already fired.
	gen uint64
	// unmountRetries counts consecutive failed unmount attempts for this entry
	// (see RetryUnmount). It sizes the retry backoff and is reset by Release
	// (entry deletion) — a successful unmount always ends in Release.
	unmountRetries int
	// timer is the single per-entry timer, armed to the next release opportunity.
	timer *time.Timer
	// unmounting is set true by release-trigger while onExpiry's UnmountRootfs
	// is in flight. The entry is NOT deleted until onExpiry calls
	// Release, so a concurrent AcquireWait sees unmounting and blocks on
	// waitDone instead of cold-mounting on another node (dual-mount guard).
	unmounting bool
	waitDone   chan struct{}
}

// New creates a new lease manager.
func New(timeout, maxHold time.Duration) *Lease {
	l := &Lease{}
	l.timeout.Store(int64(timeout))
	l.maxHold.Store(int64(maxHold))
	for i := range l.shards {
		l.shards[i] = &leaseShard{entries: make(map[string]*LeaseEntry)}
	}
	return l
}

// shardIndex maps a sandfsID to a fixed shard via FNV-1a. Inline (no allocation)
// because this is on the request hot path.
func shardIndex(sandfsID string) int {
	var h uint32 = 2166136261
	for i := 0; i < len(sandfsID); i++ {
		h ^= uint32(sandfsID[i])
		h *= 16777619
	}
	return int(h % leaseShards)
}

func (l *Lease) shard(sandfsID string) *leaseShard {
	return l.shards[shardIndex(sandfsID)]
}

// SetFireLagRecorder installs the callback that records lease-fire punctuality.
// It is invoked by evaluate (the expiry timer callback) with the node holding
// the lease and how late the fire ran relative to the entry's sync sticky
// deadline — only when that deadline is set and the callback actually
// dispatches a release. Nil disables recording. Safe to call at any time;
// typical wiring is once at startup, before any traffic.
func (l *Lease) SetFireLagRecorder(fn func(nodeID string, lag time.Duration)) {
	if fn == nil {
		l.fireLag.Store(nil)
		return
	}
	l.fireLag.Store(&fn)
}

// reportFireLag invokes the recorder when a dispatched release followed a real
// sticky deadline. sticky is the entry's syncStickyUntil at dispatch time;
// zero (a bg-born entry, or one released by the maxHold anchor) is not a
// sticky fire and is not reported.
func (l *Lease) reportFireLag(nodeID string, sticky, now time.Time) {
	p := l.fireLag.Load()
	if p == nil || sticky.IsZero() || now.Before(sticky) {
		return
	}
	(*p)(nodeID, now.Sub(sticky))
}

// syncSticky returns the configured sync sticky window.
func (l *Lease) syncSticky() time.Duration {
	return time.Duration(l.timeout.Load())
}

// syncMaxHold returns the absolute hold cap for pure-sync sandboxes.
func (l *Lease) syncMaxHold() time.Duration {
	return time.Duration(l.maxHold.Load())
}

// hasActiveBg reports whether the entry has any active background exec
// (!done && now < deadline). Must be called under the shard lock.
func (l *Lease) hasActiveBg(e *LeaseEntry, now time.Time) bool {
	for _, h := range e.bgExecs {
		if !h.done && now.Before(h.deadline) {
			return true
		}
	}
	return false
}

// canRelease reports whether all release conditions hold: no in-flight RPC, no
// active bg exec, and the sync sticky window has elapsed. Must be called under
// the shard lock.
func (l *Lease) canRelease(e *LeaseEntry, now time.Time) bool {
	if e.activeExecs > 0 {
		return false
	}
	if l.hasActiveBg(e, now) {
		return false
	}
	// No active bg: the only remaining hold is the sync sticky window. Bound it
	// by the global maxHold so a chatty pure-sync sandfs never holds forever.
	sticky := e.syncStickyUntil
	if sticky.IsZero() {
		sticky = e.syncStartedAt.Add(l.syncMaxHold())
	}
	if now.Before(sticky) {
		return false
	}
	return true
}

// nextDeadline returns the earliest FUTURE moment the lease could next become
// releasable (min of active bg deadlines and syncStickyUntil). Zero means no
// future release opportunity is armed yet (entry should release immediately if
// canRelease holds, or wait for the in-flight RPC's EndExec). Must be called
// under the shard lock.
//
// A lapsed (already-elapsed) syncStickyUntil is NOT a release opportunity: with
// an active bg exec the next real opportunity is the earliest bg deadline.
// Counting the lapsed sticky let it dominate the min and drove rearmLocked into
// its 1ms fallback, spinning evaluate at ~1kHz for the whole bg exec duration.
// The same applies to a bg-born entry (never had a sync op): syncStartedAt is
// the zero Time, so the maxHold anchor must not be derived from it.
func (l *Lease) nextDeadline(e *LeaseEntry, now time.Time) time.Time {
	var earliest time.Time
	for _, h := range e.bgExecs {
		if h.done {
			continue
		}
		if earliest.IsZero() || h.deadline.Before(earliest) {
			earliest = h.deadline
		}
	}
	sticky := e.syncStickyUntil
	if sticky.IsZero() && !e.syncStartedAt.IsZero() {
		sticky = e.syncStartedAt.Add(l.syncMaxHold())
	}
	if sticky.After(now) && (earliest.IsZero() || sticky.Before(earliest)) {
		earliest = sticky
	}
	return earliest
}

// beginUnmountLocked transitions a releasable entry to unmounting (the state
// that blocks concurrent cold mounts on other nodes for the whole unmount RPC
// duration). It stops the entry's timer and returns the waitDone channel
// AcquireWait waiters block on. Caller MUST hold the shard lock and MUST
// dispatch onExpiry (or a retry of it) afterwards — this helper only flips the
// state. Extracted so evaluate, Acquire/AcquireWait's releasable shortcut, and
// reapMaxHold all enter the unmount identically (a divergent copy once let
// Acquire silently DELETE the entry instead, leaking the mount).
func (l *Lease) beginUnmountLocked(s *leaseShard, e *LeaseEntry, sandfsID string) chan struct{} {
	if e.timer != nil {
		e.timer.Stop()
		e.timer = nil
	}
	e.unmounting = true
	if e.waitDone == nil {
		e.waitDone = make(chan struct{})
	}
	return e.waitDone
}

// dispatchExpiry invokes the expiry callback on the calling goroutine (nil
// callback → direct Release). evaluate and the retry timer call it directly;
// Acquire spawns it on a goroutine so the (potentially 8s) unmount RPC never
// blocks the caller that observed the releasable entry.
//
// Panic-safe: a panic inside onExpiry must not wedge the entry in `unmounting`
// forever (no timer, no retry, the maxHold reaper skips unmounting entries —
// every future AcquireWait on this sandfs would 503 permanently). The recover
// re-arms the retry chain; onExpiry's teardown is success-gated and its bound
// release is SettleUnmount-guarded (exactly-once), so a re-run after a partial
// panic unwind is safe.
func (l *Lease) dispatchExpiry(sandfsID, nodeID, spec string) {
	volumePath := l.VolumePathOf(sandfsID)
	if l.onExpiry == nil {
		l.Release(sandfsID) // no callback (tests): release directly
		return
	}
	defer func() {
		if r := recover(); r != nil {
			slog.Error("lease onExpiry panic recovered; scheduling retry", "sandfsID", sandfsID, "panic", r)
			l.RetryUnmount(sandfsID, nodeID, spec)
		}
	}()
	l.onExpiry(sandfsID, nodeID, spec, volumePath)
}

// Acquire checks if a sandfs has a valid lease (warm path).
// Returns the nodeID if the entry exists and is still held, empty string
// otherwise. Does NOT bracket an in-flight RPC — callers doing a sync exec /
// file op must additionally use BeginExec/EndExec.
func (l *Lease) Acquire(sandfsID string) string {
	s := l.shard(sandfsID)
	now := time.Now()
	s.mu.Lock()
	e, ok := s.entries[sandfsID]
	if !ok {
		s.mu.Unlock()
		return ""
	}
	if e.unmounting {
		s.mu.Unlock()
		return ""
	}
	if l.canRelease(e, now) {
		// Releasable but the expiry timer hasn't dispatched yet (timer-wheel
		// lag under load). Trigger the unmount PROPERLY — beginUnmountLocked +
		// async dispatch — never a silent delete: deleting here would stop the
		// timer and leak the mounted VM (no unmount ever sent), and a later
		// cold mount that lands on another node would dual-mount the rootfs.
		nodeID, spec := e.NodeID, e.Spec
		l.beginUnmountLocked(s, e, sandfsID)
		s.mu.Unlock()
		go l.dispatchExpiry(sandfsID, nodeID, spec)
		return ""
	}
	// Warm: a sync exec arriving here will BeginExec after Acquire. Refresh the
	// sticky window so a sync exec on a warm lease does not immediately expire.
	// This does NOT extend any bg deadline.
	if !l.hasActiveBg(e, now) {
		e.syncStickyUntil = now.Add(l.syncSticky())
	}
	nodeID := e.NodeID
	l.rearmLocked(s, e, sandfsID, now)
	s.mu.Unlock()
	return nodeID
}

// ErrWaitForUnmount is returned by AcquireWait when an in-progress unmount has
// not completed within the wait timeout. The handler MUST 503 + retry (not fall
// through to a cold mount on another node), since the unmount may still be
// holding the mount — falling through would dual-mount.
var ErrWaitForUnmount = errors.New("lease: timed out waiting for in-progress unmount")

// AcquireWait is the blocking variant of Acquire for the request hot path. If an
// unmount is in progress (unmounting), it blocks on waitDone until the unmount
// completes (entry deleted -> cold path, returns "") or the timeout elapses
// (returns ErrWaitForUnmount -> 503+retry, no fall-through). The timeout MUST
// exceed the unmount RPC ctx (8s); MountLockWaitTimeout (10s) is the default.
// This closes the dual-mount window: a new request cannot cold-mount on any
// node until the in-flight unmount finishes.
func (l *Lease) AcquireWait(sandfsID string, timeout time.Duration) (string, error) {
	s := l.shard(sandfsID)
	now := time.Now()
	s.mu.Lock()
	e, ok := s.entries[sandfsID]
	if !ok {
		s.mu.Unlock()
		return "", nil // cold path
	}
	if e.unmounting {
		done := e.waitDone
		s.mu.Unlock()
		if done == nil {
			return "", nil // defensive: no signal chan, don't block
		}
		select {
		case <-done:
			return "", nil // unmount finished, entry deleted -> cold path
		case <-time.After(timeout):
			return "", ErrWaitForUnmount // 503+retry, do NOT fall through
		}
	}
	if l.canRelease(e, now) {
		// Releasable but the expiry timer hasn't dispatched yet (timer-wheel
		// lag under load). Trigger the unmount properly and BLOCK on its
		// completion — exactly the in-progress-unmount semantics below — so the
		// caller's subsequent cold mount cannot land on another node while the
		// old VM still holds the mount. A silent delete here would leak the
		// mount and open a dual-mount window (see Acquire).
		nodeID, spec := e.NodeID, e.Spec
		done := l.beginUnmountLocked(s, e, sandfsID)
		s.mu.Unlock()
		go l.dispatchExpiry(sandfsID, nodeID, spec)
		select {
		case <-done:
			return "", nil // unmount finished, entry deleted -> cold path
		case <-time.After(timeout):
			return "", ErrWaitForUnmount // unmount still running; 503+retry, no fall-through
		}
	}
	if !l.hasActiveBg(e, now) {
		e.syncStickyUntil = now.Add(l.syncSticky())
	}
	nodeID := e.NodeID
	l.rearmLocked(s, e, sandfsID, now)
	s.mu.Unlock()
	return nodeID, nil
}

// rearmLocked stops any in-flight timer and re-arms to the next release
// opportunity. Caller MUST hold the shard lock.
//
// When the only remaining hold is an in-flight RPC (activeExecs > 0) with no
// future deadline, NO timer is armed: EndExec/MarkBgDone call this again when
// the RPC completes. Arming the 1ms fallback here would make evaluate spin at
// 1ms for the whole RPC duration (any sync exec longer than the sticky window)
// — pure CPU burn proportional to concurrent long requests.
func (l *Lease) rearmLocked(s *leaseShard, e *LeaseEntry, sandfsID string, now time.Time) {
	if e.timer != nil {
		e.timer.Stop()
	}
	e.gen++
	next := l.nextDeadline(e, now)
	if next.IsZero() || !next.After(now) {
		if e.activeExecs > 0 {
			// Sole remaining hold is the in-flight RPC itself; it has no
			// deadline. The completing EndExec rearms — see doc above.
			e.timer = nil
			return
		}
		// No future hold — releasable now (or at the next bg start). Arm a tiny
		// deferred check so the caller's subsequent BeginExec (sync exec) can
		// still claim the warm node before release races it. 1ms is below the
		// unmount RPC latency, so a true release still completes promptly.
		next = now.Add(time.Millisecond)
	}
	d := next.Sub(now)
	if d <= 0 {
		d = time.Millisecond
	}
	gen := e.gen
	e.timer = time.AfterFunc(d, func() { l.evaluate(sandfsID, gen) })
}

// TouchSync arms/refreshes the sync sticky window after a sync exec or file op
// completes. It creates the lease if none exists (cold-path sync exec) and does
// NOT touch any bg deadline. On a lease with active bg execs the sticky window is
// still recorded but bg deadlines dominate the hold.
//
// spec is the actual VM spec that served this op (the same value AdjustBound
// moved the bound reservation to). It MUST be recorded at entry creation: the
// expiry path releases the bound via ReleaseBound(node, e.Spec), and
// defaultSpec("") would misroute an empty spec to the "medium" bucket —
// leaking the real bucket's bound until the node reads as fully bound. Callers
// that don't know the spec pass SpecOf(sandfsID) (the existing entry's value).
func (l *Lease) TouchSync(sandfsID, nodeID, spec string) {
	s := l.shard(sandfsID)
	now := time.Now()
	s.mu.Lock()
	e, ok := s.entries[sandfsID]
	if !ok {
		e = &LeaseEntry{
			NodeID:  nodeID,
			Spec:    spec,
			gen:     1,
			bgExecs: make(map[string]*bgHold),
		}
		s.entries[sandfsID] = e
	} else {
		if e.timer != nil {
			e.timer.Stop()
		}
		// An active background exec holds the VM on ITS node: the lease's
		// NodeID is that node, and a sync op routed elsewhere (stale
		// placement, a failover in progress) must not rewrite it. The expiry
		// path releases the bound reservation using this NodeID — rewriting
		// it would free the wrong node's bucket and mask a double attachment.
		if len(e.bgExecs) == 0 {
			e.NodeID = nodeID
		}
		if spec != "" {
			e.Spec = spec
		}
	}
	e.syncStickyUntil = now.Add(l.syncSticky())
	e.syncStartedAt = now // reset maxHold anchor
	e.gen++
	gen := e.gen
	next := l.nextDeadline(e, now)
	d := time.Millisecond
	if next.After(now) {
		d = next.Sub(now)
	}
	e.timer = time.AfterFunc(d, func() { l.evaluate(sandfsID, gen) })
	s.mu.Unlock()
}

// SetSpec records the actual VM spec serving a sandfs, so onExpiry
// can ReleaseBound(node, spec). Called after a cold mount confirms the spec.
// No-op if the lease doesn't exist (e.g. released).
func (l *Lease) SetSpec(sandfsID, spec string) {
	s := l.shard(sandfsID)
	s.mu.Lock()
	if e, ok := s.entries[sandfsID]; ok {
		e.Spec = spec
	}
	s.mu.Unlock()
}

// SpecOf returns the recorded VM spec for a sandfs's lease ("" if no lease).
// SetVolumePath records the volume path of the current mount generation. It
// no-ops when no lease entry exists (the caller runs it after TouchSync /
// StartBgExec, which create the entry).
func (l *Lease) SetVolumePath(sandfsID, path string) {
	if path == "" {
		return
	}
	s := l.shard(sandfsID)
	s.mu.Lock()
	if e, ok := s.entries[sandfsID]; ok {
		e.VolumePath = path
	}
	s.mu.Unlock()
}

// SetVolumeEpoch records the volume epoch of the current mount generation.
func (l *Lease) SetVolumeEpoch(sandfsID, epoch string) {
	if epoch == "" {
		return
	}
	s := l.shard(sandfsID)
	s.mu.Lock()
	if e, ok := s.entries[sandfsID]; ok {
		e.VolumeEpoch = epoch
	}
	s.mu.Unlock()
}

// VolumeEpochOf returns the recorded volume epoch ("" if unknown).
func (l *Lease) VolumeEpochOf(sandfsID string) string {
	s := l.shard(sandfsID)
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.entries[sandfsID]; ok {
		return e.VolumeEpoch
	}
	return ""
}

// VolumePathOf returns the recorded volume path ("" if unknown).
func (l *Lease) VolumePathOf(sandfsID string) string {
	s := l.shard(sandfsID)
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.entries[sandfsID]; ok {
		return e.VolumePath
	}
	return ""
}

func (l *Lease) SpecOf(sandfsID string) string {
	s := l.shard(sandfsID)
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.entries[sandfsID]; ok {
		return e.Spec
	}
	return ""
}

// StartBgExec registers a background exec with its absolute lease deadline and
// establishes the lease on the given node (the cold-mount caller has already
// Acquired the node). lease_duration is the exec's run-time cap; it is NOT
// extended by later polls.
func (l *Lease) StartBgExec(sandfsID, nodeID, execID string, leaseDuration time.Duration) {
	s := l.shard(sandfsID)
	now := time.Now()
	s.mu.Lock()
	e, ok := s.entries[sandfsID]
	if !ok {
		e = &LeaseEntry{
			NodeID:  nodeID,
			gen:     1,
			bgExecs: make(map[string]*bgHold),
		}
		s.entries[sandfsID] = e
	} else {
		if e.timer != nil {
			e.timer.Stop()
		}
		e.NodeID = nodeID
		if e.bgExecs == nil {
			e.bgExecs = make(map[string]*bgHold)
		}
	}
	deadline := now.Add(leaseDuration)
	if leaseDuration <= 0 {
		// No explicit lease: a background exec with no cap is held by the bg's
		// liveness alone (released when a poll sees done). Use a far-future
		// deadline so hasActiveBg stays true until MarkBgDone.
		deadline = now.Add(time.Hour * 24)
	}
	e.bgExecs[execID] = &bgHold{deadline: deadline, done: false}
	e.gen++
	gen := e.gen
	next := l.nextDeadline(e, now)
	d := time.Millisecond
	if next.After(now) {
		d = next.Sub(now)
	}
	e.timer = time.AfterFunc(d, func() { l.evaluate(sandfsID, gen) })
	s.mu.Unlock()
}

// MarkBgDone marks a background exec finished (poll saw done/killed/not_found, or
// the deadline expired). Re-evaluates release: if nothing else holds the VM it is
// unmounted; otherwise the timer is re-armed to the next opportunity.
func (l *Lease) MarkBgDone(sandfsID, execID string) {
	s := l.shard(sandfsID)
	now := time.Now()
	s.mu.Lock()
	e, ok := s.entries[sandfsID]
	if !ok {
		s.mu.Unlock()
		return
	}
	if h, ok := e.bgExecs[execID]; ok {
		h.done = true
	}
	l.rearmLocked(s, e, sandfsID, now)
	s.mu.Unlock()
}

// BeginExec increments the in-flight RPC refcount so the lease is not released
// (unmount triggered) while a sync exec / file op / status poll / kill / bg-start
// RPC is in progress on the VM. MUST be paired with EndExec (defer it). No-op if
// no lease exists (cold path establishes the lease mid-RPC via Acquire/AcquireWait
// + StartBgExec; the cold mount's own RPC is bracketed by the mountLock instead).
func (l *Lease) BeginExec(sandfsID string) {
	s := l.shard(sandfsID)
	s.mu.Lock()
	if e, ok := s.entries[sandfsID]; ok {
		e.activeExecs++
	}
	s.mu.Unlock()
}

// EndExec decrements the in-flight RPC refcount and re-evaluates release. MUST
// be paired with BeginExec (idempotent-safe: clamps at 0). Safe to call on a
// released/missing lease (no-op).
func (l *Lease) EndExec(sandfsID string) {
	s := l.shard(sandfsID)
	now := time.Now()
	s.mu.Lock()
	e, ok := s.entries[sandfsID]
	if !ok {
		s.mu.Unlock()
		return
	}
	if e.activeExecs > 0 {
		e.activeExecs--
	}
	l.rearmLocked(s, e, sandfsID, now)
	s.mu.Unlock()
}

// SettleUnmount records the completion of a sandfs's unmount and returns
// whether THIS caller was the first to settle it — the exactly-once guard for
// the unmount teardown paths (lease expiry, fence release, publish-failure
// compensation). Those paths run idempotent unmount RPCs that can succeed
// concurrently; each then frees the bound reservation, and an unguarded double
// settle would double-decrement the pool's bound count (over-admitting one VM
// per occurrence). The first settler deletes the entry (stopping its timer and
// waking AcquireWait waiters) and returns true; later settlers find no entry
// and return false, skipping the bound release. A fresh cold mount may start
// before the settler's ReleaseBound lands — bound is a plain counter, so the
// decrement commutes with new reservations.
func (l *Lease) SettleUnmount(sandfsID string) bool {
	s := l.shard(sandfsID)
	s.mu.Lock()
	e, ok := s.entries[sandfsID]
	if ok {
		if e.timer != nil {
			e.timer.Stop()
		}
		delete(s.entries, sandfsID)
		if e.waitDone != nil {
			close(e.waitDone)
		}
	}
	s.mu.Unlock()
	return ok
}

// HasActiveEntry reports whether a non-releasing lease entry exists for the
// sandfs (read-only, no state change). Used by the load-shed guard: shedding
// ownership while this gateway holds a warm lease would let a peer claim and
// mount while our VM still holds the volume — a dual-mount window lasting
// until our lease expires (a background exec can hold it for an hour).
func (l *Lease) HasActiveEntry(sandfsID string) bool {
	s := l.shard(sandfsID)
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[sandfsID]
	return ok && !e.unmounting
}

// EntryInfo returns the entry's node and spec (read-only). ok=false when no
// entry exists (released, settled, or never created). Used by the Drainer to
// seed ForceUnmount with the entry's placement.
func (l *Lease) EntryInfo(sandfsID string) (nodeID, spec string, ok bool) {
	s := l.shard(sandfsID)
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[sandfsID]
	if !ok {
		return "", "", false
	}
	return e.NodeID, e.Spec, true
}

// HasEntry reports whether ANY lease entry exists for the sandfs — including
// one in the unmounting state. The Drainer's settle criterion: an entry that
// survives means a mount may still be live (SettleUnmount deletes the entry
// only after a successful unmount; ReleaseByNode deletes it when the node is
// gone, in which case no mount is servable anyway).
func (l *Lease) HasEntry(sandfsID string) bool {
	s := l.shard(sandfsID)
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.entries[sandfsID]
	return ok
}

// ForceUnmount guarantees the sandfs's lease entry is in the unmounting state
// and (re)dispatches the expiry callback. Unlike RetryUnmount — which no-ops
// when the entry is missing — it CREATES the entry when absent: the etcd-fence
// release and the ownership publish-failure compensation must keep retrying an
// unmount for every mount the ownership side reports, even when the lease
// entry was lost, or "our health key is stale past the fence" would stop
// meaning "holds no live mounts". A created entry is born unmounting, so a
// concurrent AcquireWait blocks on it (dual-mount guard) exactly as for an
// ordinary release.
func (l *Lease) ForceUnmount(sandfsID, nodeID, spec string) {
	s := l.shard(sandfsID)
	s.mu.Lock()
	e, ok := s.entries[sandfsID]
	if !ok {
		e = &LeaseEntry{
			NodeID:     nodeID,
			Spec:       spec,
			gen:        1,
			bgExecs:    make(map[string]*bgHold),
			unmounting: true,
			waitDone:   make(chan struct{}),
		}
		s.entries[sandfsID] = e
	} else if !e.unmounting {
		l.beginUnmountLocked(s, e, sandfsID)
	}
	s.mu.Unlock()
	l.dispatchExpiry(sandfsID, nodeID, spec)
}

// Release explicitly releases a sandfs's lease and stops its timer. It also
// signals any AcquireWait waiter that an in-flight unmount has completed:
// onExpiry defers Release after UnmountRootfs so the entry stays
// unmounting (blocking new cold mounts) for the whole unmount duration.
// Idempotent.
func (l *Lease) Release(sandfsID string) {
	s := l.shard(sandfsID)
	s.mu.Lock()
	if e, ok := s.entries[sandfsID]; ok {
		if e.timer != nil {
			e.timer.Stop()
		}
		delete(s.entries, sandfsID)
		if e.waitDone != nil {
			close(e.waitDone)
		}
	}
	s.mu.Unlock()
}

// ReleaseByNode releases all leases whose sandfs is currently held on the given
// node. Used when a sandlot node disconnects (OnDisconnect): the sandfs held
// warm on that node can no longer be served there. The onExpiry callback is NOT
// called for these releases (the node is gone; the callback's unmount would fail).
func (l *Lease) ReleaseByNode(nodeID string) {
	if nodeID == "" {
		return
	}
	for _, s := range l.shards {
		s.mu.Lock()
		for sandfsID, e := range s.entries {
			if e.NodeID == nodeID {
				if e.timer != nil {
					e.timer.Stop()
				}
				delete(s.entries, sandfsID)
				// Close waitDone (mirrors Release) so any AcquireWait blocked on
				// this entry's in-progress unmount unblocks immediately instead of
				// waiting out the full MountLockWaitTimeout after the node is gone.
				if e.waitDone != nil {
					close(e.waitDone)
				}
			}
		}
		s.mu.Unlock()
	}
}

// evaluate is the timer callback: re-checks under the shard lock whether the
// entry is current (same gen) and now releasable; if so triggers onExpiry
// (unmount), otherwise re-arms to the next opportunity. A stale fire from a
// timer that was Stop()'d late is a no-op. onExpiry is called outside the lock
// so the (potentially slow, RPC-bearing) release path never blocks other leases
// in the same shard.
func (l *Lease) evaluate(sandfsID string, gen uint64) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("lease evaluate onExpiry panic recovered", "sandfsID", sandfsID, "panic", r)
		}
	}()

	s := l.shard(sandfsID)
	now := time.Now()
	s.mu.Lock()
	e, ok := s.entries[sandfsID]
	if !ok || e.gen != gen {
		// Superseded by a newer state change, or already released — do nothing.
		s.mu.Unlock()
		return
	}
	if e.unmounting {
		// onExpiry already in flight (reaper or a prior evaluate). Don't
		// double-trigger: that would double-call UnmountRootfs (idempotent,
		// harmless) AND double-call ReleaseBound (misroute).
		s.mu.Unlock()
		return
	}
	// Mark any bg exec whose deadline has passed as done (expired) before
	// re-evaluating, so hasActiveBg reflects reality.
	for _, h := range e.bgExecs {
		if !h.done && !now.Before(h.deadline) {
			h.done = true
		}
	}
	// Prune settled holds (done): they can never re-activate (hasActiveBg
	// ignores them), so removing them bounds the map on long-lived entries —
	// a chatty sandfs mixing bg execs with sync/file ops otherwise grows the
	// map for the entry's whole lifetime. A late MarkBgDone for a pruned
	// execID is a no-op (it was already done); a re-used execID re-registers
	// fresh via StartBgExec.
	for id, h := range e.bgExecs {
		if h.done {
			delete(e.bgExecs, id)
		}
	}
	if !l.canRelease(e, now) {
		// Not yet releasable — re-arm to the next opportunity.
		l.rearmLocked(s, e, sandfsID, now)
		s.mu.Unlock()
		return
	}
	nodeID := e.NodeID
	spec := e.Spec
	sticky := e.syncStickyUntil
	// Mark unmounting WITHOUT deleting. The entry stays alive
	// (unmounting=true) for the whole UnmountRootfs duration, so a concurrent
	// AcquireWait blocks instead of cold-mounting on another node (dual-mount).
	l.beginUnmountLocked(s, e, sandfsID)
	s.mu.Unlock()

	// Punctuality sample: this release was dispatched by the expiry timer, and
	// if the sync sticky deadline is set and already past, its lateness is the
	// 1ms-sticky metric. Reported only for a dispatch that really happens (all
	// release conditions held) — never for a re-arm/held entry.
	l.reportFireLag(nodeID, sticky, now)

	l.dispatchExpiry(sandfsID, nodeID, spec)
}

// RetryUnmount re-dispatches the expiry callback for an entry whose unmount
// FAILED: the mount is still live on the node, so the entry must stay
// (unmounting) and the bound VM must stay reserved until an unmount actually
// succeeds — tearing the state down anyway would leak the mount and let a
// later cold mount on another node dual-mount the rootfs. The retry runs with
// exponential backoff (1s → 30s cap, per-entry counter); a node disconnect
// (ReleaseByNode) or a successful unmount (Release) deletes the entry, which
// cancels pending retries. The caller is the expiry callback's failure branch.
func (l *Lease) RetryUnmount(sandfsID, nodeID, spec string) {
	s := l.shard(sandfsID)
	s.mu.Lock()
	e, ok := s.entries[sandfsID]
	if !ok || !e.unmounting {
		s.mu.Unlock()
		return // released/landed elsewhere — nothing to retry
	}
	e.unmountRetries++
	retries := e.unmountRetries
	s.mu.Unlock()

	delay := time.Second << uint(min(retries-1, 5)) // 1s,2s,4s,8s,16s,32s…
	if delay > 30*time.Second {
		delay = 30 * time.Second
	}
	time.AfterFunc(delay, func() {
		s := l.shard(sandfsID)
		s.mu.Lock()
		e, ok := s.entries[sandfsID]
		if !ok || !e.unmounting {
			s.mu.Unlock()
			return // resolved while we waited
		}
		s.mu.Unlock()
		l.dispatchExpiry(sandfsID, nodeID, spec)
	})
}

// reapMaxHold is the safety-net scan for the global maxHold cap on pure-sync
// sandboxes. A chatty sync-only sandfs keeps re-TouchSyncing (refreshing
// syncStickyUntil) so its sticky timer never fires for it; this reaper releases
// such leases once maxHold elapses since the last syncStartedAt. Sandboxes with
// active bg execs are governed by their bg deadlines, not this cap. Runs at
// maxHold/2 (≈2.5s). Each shard is locked briefly; onExpiry is called after all
// shards are unlocked.
func (l *Lease) reapMaxHold() {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("lease reapMaxHold onExpiry panic recovered", "panic", r)
		}
	}()

	type pending struct{ sandfsID, nodeID, spec string }
	var expired []pending
	now := time.Now()
	maxHold := l.syncMaxHold()
	for _, s := range l.shards {
		s.mu.Lock()
		for aid, e := range s.entries {
			if e.unmounting {
				continue
			}
			if e.activeExecs > 0 {
				// An RPC is in flight on this VM — releasing now would race it
				// (same reason canRelease requires activeExecs == 0). The entry
				// is reaped on a later sweep if still idle-past-maxHold; its own
				// timers handle release when the RPC ends.
				continue
			}
			if l.hasActiveBg(e, now) {
				continue // governed by bg deadlines
			}
			if !e.syncStartedAt.IsZero() && now.Sub(e.syncStartedAt) > maxHold {
				l.beginUnmountLocked(s, e, aid)
				expired = append(expired, pending{aid, e.NodeID, e.Spec})
			}
		}
		s.mu.Unlock()
	}
	if l.onExpiry != nil {
		// Bounded parallel dispatch: each onExpiry is an unmount RPC (up to the
		// 8s transport timeout), so serial calls would backlog when many leases
		// expire in one sweep. Entries are already marked unmounting under the
		// shard locks, so ordering/concurrency here cannot double-release.
		const expiryWorkers = 8
		var wg sync.WaitGroup
		sem := make(chan struct{}, expiryWorkers)
		for _, p := range expired {
			wg.Add(1)
			sem <- struct{}{}
			go func(p pending) {
				defer wg.Done()
				defer func() { <-sem }()
				l.onExpiry(p.sandfsID, p.nodeID, p.spec, l.VolumePathOf(p.sandfsID))
			}(p)
		}
		wg.Wait()
	}
}

// StartExpiryWorker installs the expiry callback and starts the maxHold
// safety-net reaper. Release evaluation is driven by per-entry timers armed in
// the state-change methods, NOT by this worker — so there is no global scan
// whose accuracy degrades with lease count. The reaper only enforces the
// maxHold cap on pure-sync sandboxes. The sweep interval is re-derived from
// the CURRENT maxHold on every iteration, so a hot-reloaded cap (e.g. lowered
// from 5s to 200ms) tightens the reaper's cadence too instead of lagging one
// old-interval behind.
func (l *Lease) StartExpiryWorker(onExpiry func(sandfsID, nodeID, spec, volumePath string)) {
	l.onExpiry = onExpiry
	if l.syncMaxHold() <= 0 {
		return
	}
	l.done = make(chan struct{})
	go func() {
		for {
			interval := l.syncMaxHold() / 2
			if interval <= 0 {
				interval = time.Second
			}
			t := time.NewTimer(interval)
			select {
			case <-t.C:
				t.Stop()
				l.reapMaxHold()
			case <-l.done:
				t.Stop()
				return
			}
		}
	}()
}

// UpdateTimeout atomically updates the sync sticky window. New TouchSync/Acquire
// calls use the new value; existing armed timers re-evaluate on fire.
func (l *Lease) UpdateTimeout(d time.Duration) {
	l.timeout.Store(int64(d))
}

// StickyWindow returns the currently configured sync sticky window (the value
// set by New/UpdateTimeout). Read-only; mainly for tests and observability.
func (l *Lease) StickyWindow() time.Duration {
	return time.Duration(l.timeout.Load())
}

// UpdateMaxHold atomically updates the pure-sync maxHold cap. The reaper picks
// up the new value on its next tick.
func (l *Lease) UpdateMaxHold(d time.Duration) {
	l.maxHold.Store(int64(d))
}

// MaxHoldCap returns the currently configured pure-sync maxHold cap. Read-only;
// mainly for tests and observability.
func (l *Lease) MaxHoldCap() time.Duration {
	return time.Duration(l.maxHold.Load())
}

// Close stops the maxHold reaper goroutine. Idempotent. Per-entry timers are NOT
// stopped here — they self-cancel on evaluation and are harmless if they fire
// after Close (onExpiry is a no-op on a released lease).
func (l *Lease) Close() {
	l.closeOnce.Do(func() {
		if l.done != nil {
			close(l.done)
		}
	})
}

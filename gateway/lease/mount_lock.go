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
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

// ErrConcurrentMount is returned by MountLock.Acquire when another cold mount
// for the same sandfsID is already in progress.
var ErrConcurrentMount = errors.New("concurrent mount in progress")

// processDispatchLock is the cold-mount lock of THIS PROCESS's exec handlers.
// A gateway process constructs exactly one MountLock and shares it between the
// execute and file handlers, so a single slot is exact. It is registered by the
// handler constructors because the lifecycle drain (which must not settle while
// a cold mount is in flight or queued) has no other handle on it: the inline
// single-node drain receives only the pool and lease, and the split-mode drain
// runs in the exec gateway process where the handlers own the lock.
var processDispatchLock atomic.Pointer[MountLock]

// RegisterDispatchLock publishes ml as the process's cold-mount lock. Safe to
// call with the same lock from several handlers; nil is ignored.
func RegisterDispatchLock(ml *MountLock) {
	if ml != nil {
		processDispatchLock.Store(ml)
	}
}

// DispatchInFlight reports whether this process has a cold mount for sandfsID
// in flight or queued for the lock. False when no handler registered a lock
// (tests, human-only gateways, single-node edges).
func DispatchInFlight(sandfsID string) bool {
	if ml := processDispatchLock.Load(); ml != nil {
		return ml.InFlight(sandfsID)
	}
	return false
}

// MountLock is a sandfs-level mutex that prevents two concurrent cold mounts
// from acquiring different microVMs for the same sandfs.
//
// Warm-path requests bypass the lock entirely: concurrent exec/file I/O on an
// already-mounted sandfs is allowed.
type MountLock struct {
	mu    sync.Mutex
	slots map[string]*mountSlot // sandfsID → per-sandfs mutex
}

// MountLockToken is one acquisition. Release consumes the token and only the
// holder that owns it can release the slot: a stale or double Release is a
// no-op and can never drain a successor's acquisition (the defect a shared
// channel-based semaphore had).
type MountLockToken struct {
	sandfsID string
	slot     *mountSlot
}

// mountSlot is a per-sandfs mutex plus a waiter broadcast and a refcount of
// registered interests (the holder until Release, each waiter until it
// acquires or times out). The refcount lets a slot be evicted once no
// goroutine can still interact with it.
type mountSlot struct {
	mu     sync.Mutex
	holder *MountLockToken
	notify chan struct{}
	refs   int
}

// NewMountLock creates a new MountLock.
func NewMountLock() *MountLock {
	return &MountLock{slots: make(map[string]*mountSlot)}
}

func (ml *MountLock) registerLocked(sandfsID string) *mountSlot {
	s, ok := ml.slots[sandfsID]
	if !ok {
		s = &mountSlot{notify: make(chan struct{})}
		ml.slots[sandfsID] = s
	}
	s.refs++
	return s
}

// unregister ends one interest. The slot is evicted once no interest remains
// and no holder owns it.
func (ml *MountLock) unregister(sandfsID string, s *mountSlot) {
	ml.mu.Lock()
	s.refs--
	evict := false
	if s.refs <= 0 && ml.slots[sandfsID] == s {
		s.mu.Lock()
		evict = s.holder == nil
		s.mu.Unlock()
	}
	if evict {
		delete(ml.slots, sandfsID)
	}
	ml.mu.Unlock()
}

// Acquire attempts to acquire the cold mount lock without blocking. On
// success the caller MUST Release the returned token, even on mount failure.
func (ml *MountLock) Acquire(sandfsID string) (*MountLockToken, error) {
	ml.mu.Lock()
	s := ml.registerLocked(sandfsID)
	ml.mu.Unlock()
	t := &MountLockToken{sandfsID: sandfsID, slot: s}
	s.mu.Lock()
	if s.holder == nil {
		s.holder = t
		s.mu.Unlock()
		return t, nil
	}
	s.mu.Unlock()
	ml.unregister(sandfsID, s)
	return nil, ErrConcurrentMount
}

// MountLockWaitTimeout bounds how long a concurrent same-sandfs request is
// held before falling back to 503+retry. A holder that finishes early wakes
// waiters immediately, so this is the worst case, not the typical wait.
const MountLockWaitTimeout = 10 * time.Second

// AcquireWait blocks up to timeout for an in-progress cold mount to finish.
// It returns ErrConcurrentMount on timeout.
func (ml *MountLock) AcquireWait(sandfsID string, timeout time.Duration) (*MountLockToken, error) {
	ml.mu.Lock()
	s := ml.registerLocked(sandfsID)
	ml.mu.Unlock()
	t := &MountLockToken{sandfsID: sandfsID, slot: s}
	deadline := time.Now().Add(timeout)
	for {
		s.mu.Lock()
		if s.holder == nil {
			s.holder = t
			s.mu.Unlock()
			return t, nil
		}
		ch := s.notify
		s.mu.Unlock()
		remain := time.Until(deadline)
		if remain <= 0 {
			ml.unregister(sandfsID, s)
			return nil, ErrConcurrentMount
		}
		timer := time.NewTimer(remain)
		select {
		case <-ch:
			timer.Stop()
		case <-timer.C:
			ml.unregister(sandfsID, s)
			return nil, ErrConcurrentMount
		}
	}
}

// AcquireWaitDefault acquires the cold mount lock with the default timeout.
func (ml *MountLock) AcquireWaitDefault(sandfsID string) (*MountLockToken, error) {
	return ml.AcquireWait(sandfsID, MountLockWaitTimeout)
}

// InFlight reports whether a cold mount for sandfsID is in flight (the slot is
// held) or QUEUED for it (a waiter registered but has not acquired yet). A
// waiter counts because it already passed the request's lifecycle gate and will
// mount as soon as the holder releases — a lifecycle drain that settles while a
// waiter is queued would write "detached" and let that mount land afterwards.
//
// The refcount is the authoritative signal: every Acquire/AcquireWait registers
// before waiting, the holder keeps its registration until Release, and the slot
// is evicted only at zero.
func (ml *MountLock) InFlight(sandfsID string) bool {
	ml.mu.Lock()
	defer ml.mu.Unlock()
	s, ok := ml.slots[sandfsID]
	return ok && s.refs > 0
}

// Release releases an acquisition. A nil token, a stale token, or a double
// Release is a no-op and never affects the current holder.
func (ml *MountLock) Release(t *MountLockToken) {
	if t == nil {
		return
	}
	s := t.slot
	s.mu.Lock()
	if s.holder != t {
		s.mu.Unlock()
		return
	}
	s.holder = nil
	close(s.notify)
	s.notify = make(chan struct{})
	s.mu.Unlock()
	ml.unregister(t.sandfsID, s)
}

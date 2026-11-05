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

package main

import (
	"sync"
	"time"
)

// Etcd-backed owner lookups are the only DNS path where one client packet can
// become one control-plane read. A source that enumerates valid-shaped sandfs
// IDs must not turn its query rate into etcd load, so the slow path (no fresh
// positive answer, no cached negative) is rate-limited per source IP and
// globally. Cache hits never consult the limiter — they do not touch etcd, so
// valid hot answers are unchanged.
//
// A source cannot evade the per-source cap by spoofing: guest traffic arrives
// on anti-spoofed TAPs, and a non-guest source that spoofs is already outside
// the recursive ACL for every non-sandswap zone. The global cap is the
// backstop for the whole resolver.
//
// Defaults: one source may start 100 new owner resolutions per second (a
// client retrying one name is served from its cache), and the resolver admits
// 50000 per second — above a million-sandfs fleet's steady-state revalidation
// rate (cache_ttl 30s ≈ 33k/s), so legitimate work is not throttled while a
// flood is bounded. 0 disables the respective limit.
var (
	ownerRatePerSource = 100
	ownerRateGlobal    = 50000
)

const (
	// ownerRateSourceMax bounds the per-source bucket table. Buckets are
	// disposable fixed-window counters; the table is swept on insert.
	ownerRateSourceMax = 65536

	// ownerRateSweepAge is how long an idle source bucket is kept. A source
	// that queries again after this starts a fresh bucket (which is the same
	// state a live but idle bucket would hold).
	ownerRateSweepAge = 10 * time.Second

	// ownerRateWindowNanos is the fixed accounting window. Fixed windows admit
	// up to 2× the rate across a boundary, which is acceptable for a load bound.
	ownerRateWindowNanos = int64(time.Second)
)

// ownerRateBucket is a fixed-window counter for one source (or the global
// budget). Its state is meaningless outside the current window.
type ownerRateBucket struct {
	start int64 // window start (UnixNano, window-aligned)
	count int
}

// allow consumes one token from the bucket. limit <= 0 means unlimited.
func (b *ownerRateBucket) allow(now int64, limit int) bool {
	if limit <= 0 {
		return true
	}
	windowStart := now - now%ownerRateWindowNanos
	if b.start != windowStart {
		b.start = windowStart
		b.count = 0
	}
	if b.count >= limit {
		return false
	}
	b.count++
	return true
}

// ownerRateLimiter bounds the etcd-bound owner-lookup slow path. A nil
// limiter (struct-literal test servers) allows everything.
type ownerRateLimiter struct {
	mu        sync.Mutex
	global    ownerRateBucket
	perSource map[string]*ownerRateBucket
	lastSweep int64
}

func newOwnerRateLimiter() *ownerRateLimiter {
	return &ownerRateLimiter{perSource: make(map[string]*ownerRateBucket)}
}

// allow consumes one token for source. The empty source (a direct provider
// call, not client traffic) is charged to the global budget only.
func (l *ownerRateLimiter) allow(source string) bool {
	if l == nil {
		return true
	}
	now := time.Now().UnixNano()
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.global.allow(now, ownerRateGlobal) {
		return false
	}
	if source == "" {
		return true
	}
	if l.perSource == nil {
		l.perSource = make(map[string]*ownerRateBucket)
	}
	b := l.perSource[source]
	if b == nil {
		l.evictLocked(now)
		b = &ownerRateBucket{}
		l.perSource[source] = b
	}
	return b.allow(now, ownerRatePerSource)
}

// evictLocked keeps the per-source table bounded: aged buckets are swept when
// the sweep interval has elapsed, and if the table is still at its cap the
// oldest-inserted arbitrary entries are dropped (the counter they hold is
// disposable). Caller holds l.mu.
func (l *ownerRateLimiter) evictLocked(now int64) {
	if len(l.perSource) < ownerRateSourceMax && now-l.lastSweep < int64(ownerRateSweepAge) {
		return
	}
	l.lastSweep = now
	cutoff := now - int64(ownerRateSweepAge)
	for src, b := range l.perSource {
		if b.start < cutoff {
			delete(l.perSource, src)
		}
	}
	for src := range l.perSource {
		if len(l.perSource) < ownerRateSourceMax {
			break
		}
		delete(l.perSource, src)
	}
}

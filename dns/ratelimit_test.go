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
	"testing"
	"time"
)

// withRates swaps the limiter's rate knobs for the test and restores them
// after (the bucket-level tests inject time directly; only the limiter-level
// tests need this).
func withRates(t *testing.T, perSource, global int) {
	t.Helper()
	oldPS, oldG := ownerRatePerSource, ownerRateGlobal
	ownerRatePerSource, ownerRateGlobal = perSource, global
	t.Cleanup(func() { ownerRatePerSource, ownerRateGlobal = oldPS, oldG })
}

// TestOwnerRateBucketWindowAndLimit pins the fixed-window counter: tokens are
// granted up to the limit inside one window, refused at the limit, and the
// window rollover resets the counter (a new window starts from zero, not from
// the previous count).
func TestOwnerRateBucketWindowAndLimit(t *testing.T) {
	var b ownerRateBucket
	now := int64(10 * time.Second) // window-aligned

	if !b.allow(now, 2) {
		t.Fatal("first token in a fresh window must be granted")
	}
	if !b.allow(now, 2) {
		t.Fatal("second token within the limit must be granted")
	}
	if b.allow(now, 2) {
		t.Fatal("third token at the limit must be refused")
	}
	// Mid-window: still the same window.
	if b.allow(now+time.Millisecond.Nanoseconds(), 2) {
		t.Fatal("the same window must keep refusing at the limit")
	}
	// Next window: counter resets to a fresh budget of two.
	next := now + ownerRateWindowNanos
	if !b.allow(next, 2) {
		t.Fatal("window rollover must reset the counter")
	}
	if !b.allow(next, 2) {
		t.Fatal("the new window's second token must be granted (fresh budget)")
	}
	if b.allow(next, 2) {
		t.Fatal("the new window's limit must still apply after two tokens")
	}
}

// TestOwnerRateBucketUnlimited pins the 0-sentinel: limit <= 0 means
// unlimited (the resolver's documented "0 disables the limit" contract) and
// never consumes state.
func TestOwnerRateBucketUnlimited(t *testing.T) {
	var b ownerRateBucket
	now := int64(5 * time.Second)
	for i := 0; i < 100; i++ {
		if !b.allow(now, 0) {
			t.Fatalf("limit=0 must be unlimited, refused at token %d", i)
		}
	}
	if !b.allow(now, -1) {
		t.Fatal("a negative limit must be treated as unlimited")
	}
	if b.start != 0 || b.count != 0 {
		t.Fatalf("unlimited checks must not mutate the bucket (start=%d count=%d)", b.start, b.count)
	}
}

// TestOwnerRateLimiterPerSource pins the per-source budget: two sources have
// independent buckets, one source hitting its cap does not affect the other,
// and the empty source (a direct provider call) is charged globally only.
func TestOwnerRateLimiterPerSource(t *testing.T) {
	withRates(t, 1, 50000)
	l := newOwnerRateLimiter()

	if !l.allow("10.0.0.1") {
		t.Fatal("first query from a source must be granted")
	}
	if l.allow("10.0.0.1") {
		t.Fatal("a source at its per-second cap must be refused")
	}
	if !l.allow("10.0.0.2") {
		t.Fatal("a different source has its own bucket")
	}
	if !l.allow("") {
		t.Fatal("the empty source (direct provider call) is charged globally only")
	}
	if _, ok := l.perSource[""]; ok {
		t.Fatal("the empty source must not materialize a per-source bucket")
	}
}

// TestOwnerRateLimiterGlobalBackstop pins the global budget: once the
// whole-resolver cap is spent, every source is refused regardless of its own
// bucket.
func TestOwnerRateLimiterGlobalBackstop(t *testing.T) {
	withRates(t, 100, 1)
	l := newOwnerRateLimiter()

	if !l.allow("10.0.0.1") {
		t.Fatal("the first query spends the global budget and must be granted")
	}
	if l.allow("10.0.0.2") {
		t.Fatal("an exhausted global budget must refuse every source")
	}
}

// TestOwnerRateLimiterNilAllowsAll pins the nil-receiver contract: struct
// literal test servers build no limiter, and absence must not deny.
func TestOwnerRateLimiterNilAllowsAll(t *testing.T) {
	var l *ownerRateLimiter
	if !l.allow("10.0.0.1") {
		t.Fatal("a nil limiter must allow everything")
	}
}

// TestOwnerRateLimiterEvictsAgedBuckets pins the table sweep: an idle source's
// bucket older than the sweep age is dropped on the next insert, keeping the
// per-source table bounded without a background goroutine.
func TestOwnerRateLimiterEvictsAgedBuckets(t *testing.T) {
	withRates(t, 100, 50000)
	l := newOwnerRateLimiter()
	now := time.Now().UnixNano()

	// An aged bucket (idle for far longer than ownerRateSweepAge) plus a stale
	// lastSweep so the next insert triggers the sweep.
	l.perSource["stale-source"] = &ownerRateBucket{start: now - int64(5*time.Minute) - int64(ownerRateSweepAge)}
	l.lastSweep = now - int64(5*time.Minute)

	if !l.allow("fresh-source") {
		t.Fatal("the triggering insert must be granted")
	}
	if _, ok := l.perSource["stale-source"]; ok {
		t.Fatal("an aged bucket must be swept on insert")
	}
	if _, ok := l.perSource["fresh-source"]; !ok {
		t.Fatal("the inserting source's bucket must exist")
	}
}

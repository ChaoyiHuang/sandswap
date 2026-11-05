// Copyright 2026 Chaoyi Huang. All rights reserved.
//
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE file at the root of this repository.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, your use of this software will be
// governed by the Apache License, Version 2.0.

package lease

// W4(a) lease mutation triage — wave 3 pins (ownership.go validation
// boundaries). The 211 ownership survivors split into families: etcd
// error/existence paths (nil-checks + Kvs==0 — owned by the fault-injected
// e2e battery with real etcd, unit-equivalent without faults), the load
// filter + placement index (etcd full-load path, same), the Claim fast-path
// freshness boundary (ttl-exact — semantic no-op), and the VALIDATION
// boundaries pinned here, where an exact-equality flip silently rejects a
// documented-LEGAL configuration:
//
//	validateTiming: T_clean == T_warden is legal (T_warden >= T_clean)
//	SetStalenessThresholds: ttl == ceil (2×guard) is legal
//	SetStalenessAndCacheTTL: cacheTTL == 1s is legal (>= 1s)

import (
	"testing"
	"time"

	pb "common/proto/stream"
)

// TestValidateTimingEqualityBoundaryPinsW4 pins the equality edge of
// T_warden >= T_clean: cleanup EXACTLY equal to the countdown is a valid
// shape (the >= flip of the validation rejects it — a silent config
// regression no strict-inequality case can catch).
func TestValidateTimingEqualityBoundaryPinsW4(t *testing.T) {
	// T_safe = 300 + 300 + 60 = 660; isolation 720 clears it.
	eq := &pb.NodeTiming{ToleranceSec: 300, WardenCountdownSec: 300, CleanupSec: 300, IsolationSec: 720}
	if err := validateTiming(eq); err != nil {
		t.Fatalf("cleanup == warden is a VALID shape (T_warden >= T_clean), rejected: %v", err)
	}
	// one second past the boundary must still be rejected (the pin is the
	// boundary, not a range shift)
	over := &pb.NodeTiming{ToleranceSec: 300, WardenCountdownSec: 299, CleanupSec: 300, IsolationSec: 720}
	if err := validateTiming(over); err == nil {
		t.Fatal("cleanup > warden by any amount must be rejected")
	}
}

// TestSetStalenessThresholdsTTLAtCeilingPinsW4 pins the guard/TTL pair's
// equality edge: a live TTL exactly AT the ceiling (2×guard) is legal —
// the > flip of the refusal check rejects it, tightening the documented
// ceiling without a config reason.
func TestSetStalenessThresholdsTTLAtCeilingPinsW4(t *testing.T) {
	oc := newTestCache(nil) // TTL 30s default, guard 45s default
	// TTL 20 == 2×guard(10): must be accepted; then a guard change whose
	// ceiling equals the live TTL must also be accepted.
	if err := oc.SetCacheTTL(20 * time.Second); err != nil {
		t.Fatalf("lower TTL: %v", err)
	}
	if err := oc.SetStalenessThresholds(0, 10*time.Second, 0); err != nil {
		t.Fatalf("guard whose ceiling (2×10=20) EQUALS the live TTL (20) must be accepted: %v", err)
	}
	// One second tighter is the violation the check exists for: restore the
	// default guard (45s → ceiling 90 ≥ 21), raise the TTL to 21, then lower
	// the guard to 10 — its 20s ceiling is now below the live 21s.
	if err := oc.SetStalenessThresholds(0, 45*time.Second, 0); err != nil {
		t.Fatalf("restore default guard: %v", err)
	}
	if err := oc.SetCacheTTL(21 * time.Second); err != nil {
		t.Fatalf("raise TTL under the default guard's ceiling: %v", err)
	}
	if err := oc.SetStalenessThresholds(0, 10*time.Second, 0); err == nil {
		t.Fatal("guard ceiling (20) BELOW live TTL (21) must be refused")
	}
}

// TestSetStalenessAndCacheTTLOneSecondPinsW4 pins the joint setter's floor
// edge: cacheTTL == 1s is the documented minimum (">= 1s") — the < flip
// rejects exactly-1s, a legal value.
func TestSetStalenessAndCacheTTLOneSecondPinsW4(t *testing.T) {
	oc := newTestCache(nil)
	if err := oc.SetStalenessAndCacheTTL(0, 0, 0, 1*time.Second); err != nil {
		t.Fatalf("cacheTTL == 1s is the documented minimum and must be accepted: %v", err)
	}
	if got := oc.cacheTTL(); got != 1*time.Second {
		t.Fatalf("accepted 1s TTL not applied: %v", got)
	}
	// below the floor is the refusal the check exists for
	if err := oc.SetStalenessAndCacheTTL(0, 0, 0, 999*time.Millisecond); err == nil {
		t.Fatal("cacheTTL < 1s must be refused")
	}
}

// TestOwnershipLoadRangesBucketed pins the -follow-up ownership load
// partition: the keyspace must be hex-bucketed (no serial chain — the 334-
// page serial scan was the cold-start long pole at 1M) and the union exact
// (under-coverage silently loses ownership records → false "unowned").
func TestOwnershipLoadRangesBucketed(t *testing.T) {
	ranges := ownershipLoadRanges()
	if len(ranges) < 16 {
		t.Fatalf("ownership keyspace not bucketed: %d ranges", len(ranges))
	}
	hit := func(key string) int {
		n := 0
		for _, r := range ranges {
			if key >= r.start && key < r.end {
				n++
			}
		}
		return n
	}
	for i := 0; i < len(ownerHexDigits); i++ {
		key := ownershipPrefix + "sandfs-" + string(ownerHexDigits[i]) + "0000000"
		if n := hit(key); n != 1 {
			t.Errorf("sandfs id bucket %q hit %d ranges, want 1", key, n)
		}
	}
	// The '0' and 'f' buckets must be distinct ranges (single-chain regression).
	var zeroIdx, fIdx int = -1, -1
	for i, r := range ranges {
		if ownershipPrefix+"sandfs-0aaaaaaa" >= r.start && ownershipPrefix+"sandfs-0aaaaaaa" < r.end {
			zeroIdx = i
		}
		if ownershipPrefix+"sandfs-faaaaaaa" >= r.start && ownershipPrefix+"sandfs-faaaaaaa" < r.end {
			fIdx = i
		}
	}
	if zeroIdx == fIdx || zeroIdx < 0 || fIdx < 0 {
		t.Fatalf("ownership not bucketed (zero=%d f=%d)", zeroIdx, fIdx)
	}
}

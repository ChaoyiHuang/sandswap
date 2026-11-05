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
	"testing"
	"time"

	pb "common/proto/stream"
)

// TestMountLockAcquireWaitDefault verifies the default-timeout wrapper
// AcquireWaitDefault: it acquires when free, blocks a concurrent holder until
// Release, then proceeds (the 10s timeout is only the worst-case bound, not
// the typical wait).
func TestMountLockAcquireWaitDefault(t *testing.T) {
	ml := NewMountLock()

	tok, err := ml.AcquireWaitDefault("s-1")
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}

	// A concurrent waiter blocks until Release.
	done := make(chan error, 1)
	go func() {
		t2, err := ml.AcquireWaitDefault("s-1")
		if err == nil {
			ml.Release(t2)
		}
		done <- err
	}()

	// Give the waiter a moment to enqueue, then confirm it is blocked.
	time.Sleep(50 * time.Millisecond)
	select {
	case err := <-done:
		t.Fatalf("waiter should be blocked while holder active, got %v", err)
	default:
	}

	ml.Release(tok)

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("waiter after release: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("waiter did not proceed after release")
	}
}

// TestStalenessDefaults verifies the default staleness thresholds and their
// ordering invariant: route (fast, cheap-to-be-wrong) < alert (early warning)
// < claim-dead guard (slow, expensive-to-be-wrong). The health key has no
// lease, so these thresholds ARE the per-consumer death times.
func TestStalenessDefaults(t *testing.T) {
	if defaultRouteStaleThreshold != 20*time.Second {
		t.Errorf("defaultRouteStaleThreshold = %v, want 20s", defaultRouteStaleThreshold)
	}
	if defaultAlertStaleThreshold != 30*time.Second {
		t.Errorf("defaultAlertStaleThreshold = %v, want 30s", defaultAlertStaleThreshold)
	}
	if defaultClaimDeadGuard != 45*time.Second {
		t.Errorf("defaultClaimDeadGuard = %v, want 45s", defaultClaimDeadGuard)
	}
	if !(defaultRouteStaleThreshold < defaultAlertStaleThreshold && defaultAlertStaleThreshold < defaultClaimDeadGuard) {
		t.Errorf("threshold ordering broken: route %v < alert %v < guard %v",
			defaultRouteStaleThreshold, defaultAlertStaleThreshold, defaultClaimDeadGuard)
	}
}

// TestOnNodeDisconnectRecordsPendingOwnerRelease verifies the owner-release trigger (0): a node
// disconnect records the node in the pendingOwnerRelease set (and stops tracking its
// presence lease), and a reconnect (OnNodeConnect) cancels the pending owner-release.
func TestOnNodeDisconnectRecordsPendingOwnerRelease(t *testing.T) {
	oc := NewOwnershipCacheForTest("gw-test")
	oc.OnNodeDisconnect("node-1")
	oc.mu.Lock()
	discTime, armed := oc.pendingOwnerRelease["node-1"]
	_, presenceTracked := oc.presenceLeases["node-1"]
	oc.mu.Unlock()
	if !armed || discTime.IsZero() {
		t.Fatal("OnNodeDisconnect should record the node in pendingOwnerRelease")
	}
	if presenceTracked {
		t.Error("OnNodeDisconnect should stop tracking the presence lease (natural expiry)")
	}

	// Reconnect cancels the pending owner-release. Valid timings so the
	// validation gate does not short-circuit before clearing the pending entry.
	oc.OnNodeConnect("node-1", &pb.NodeTiming{ToleranceSec: 300, WardenCountdownSec: 300, CleanupSec: 300, IsolationSec: 720})
	oc.mu.Lock()
	_, still := oc.pendingOwnerRelease["node-1"]
	oc.mu.Unlock()
	if still {
		t.Error("OnNodeConnect should cancel the pending owner-release")
	}
}

// TestTSafeForTiming verifies T_safe derivation: T_tolerance + T_warden + margin,
// with defaults for degenerate/missing timings.
func TestTSafeForTiming(t *testing.T) {
	if got := tSafeForTiming(&pb.NodeTiming{ToleranceSec: 300, WardenCountdownSec: 300}); got != 660*time.Second {
		t.Errorf("tSafeForTiming(300,300) = %v, want 660s", got)
	}
	// Degenerate timings fall back to defaults (300+300+60 = 660s), never a
	// pathologically short 60s.
	if got := tSafeForTiming(nil); got != 660*time.Second {
		t.Errorf("tSafeForTiming(nil) = %v, want 660s", got)
	}
	if got := tSafeForTiming(&pb.NodeTiming{}); got != 660*time.Second {
		t.Errorf("tSafeForTiming(0,0) = %v, want 660s", got)
	}
}

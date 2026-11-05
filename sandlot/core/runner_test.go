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

package core

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// fakeResolver is a test hostResolver that returns a fixed IP set (or error),
// simulating DNS responses — e.g. the remembered gateway IP dropping out of the
// Service's DNS answer during TOLERATING.
type fakeResolver func(ctx context.Context, host string) ([]string, error)

func (f fakeResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	return f(ctx, host)
}

// withResolver swaps the package-level hostResolver for a fake and restores it
// on test cleanup.
func withResolver(t *testing.T, f fakeResolver) {
	t.Helper()
	prev := hostResolver
	hostResolver = f
	t.Cleanup(func() { hostResolver = prev })
}

// withGatewayPick swaps the package-level gatewayPickIdx for a deterministic
// index source and restores it on test cleanup.
func withGatewayPick(t *testing.T, f func(n int) int) {
	t.Helper()
	prev := gatewayPickIdx
	gatewayPickIdx = f
	t.Cleanup(func() { gatewayPickIdx = prev })
}

// --- toleranceElapsed: tolerance clock anchored at persisted disconnect ---

func TestToleranceElapsed_WithinTolerance(t *testing.T) {
	// Disconnect 60s ago, tolerance 300s → not yet elapsed.
	now := time.Now()
	disconnect := now.Add(-60 * time.Second)
	if toleranceElapsed(disconnect, 300, now) {
		t.Error("toleranceElapsed = true with only 60s elapsed, want false")
	}
}

func TestToleranceElapsed_AfterTolerance(t *testing.T) {
	// Disconnect 301s ago, tolerance 300s → elapsed.
	now := time.Now()
	disconnect := now.Add(-301 * time.Second)
	if !toleranceElapsed(disconnect, 300, now) {
		t.Error("toleranceElapsed = false after 301s, want true")
	}
}

func TestToleranceElapsed_SurvivesRestart(t *testing.T) {
	// The tolerance clock is anchored to the ORIGINAL disconnect (persisted), not
	// to sandlot start. A restart at t=100s with disconnect at t=0 must NOT reset
	// the clock: 400s after disconnect is still past the 300s tolerance even
	// though the process has only been up 100s.
	now := time.Now()
	disconnect := now.Add(-400 * time.Second) // persisted disconnect
	// Process restarted 100s ago; the persisted disconnect_time is 400s old.
	_ = now.Add(-100 * time.Second) // processStart (informational)
	if !toleranceElapsed(disconnect, 300, now) {
		t.Error("toleranceElapsed = false 400s after persisted disconnect, want true")
	}
}

func TestToleranceElapsed_ExactBoundary(t *testing.T) {
	// Exactly at tolerance → elapsed (>= semantics).
	now := time.Now()
	disconnect := now.Add(-300 * time.Second)
	if !toleranceElapsed(disconnect, 300, now) {
		t.Error("toleranceElapsed = false exactly at tolerance, want true")
	}
}

// --- isolationRemaining: DONE wait before reconnect ---

func TestIsolationRemaining_Positive(t *testing.T) {
	// Disconnect 10min ago, isolation 720s (12min) → 2min remaining.
	now := time.Now()
	disconnect := now.Add(-10 * time.Minute)
	wait := isolationRemaining(disconnect, 720, now)
	if wait <= 0 || wait > 3*time.Minute {
		t.Errorf("isolationRemaining = %v, want ~2min", wait)
	}
}

func TestIsolationRemaining_Elapsed(t *testing.T) {
	// Disconnect 13min ago, isolation 720s (12min) → 0 remaining.
	now := time.Now()
	disconnect := now.Add(-13 * time.Minute)
	if wait := isolationRemaining(disconnect, 720, now); wait != 0 {
		t.Errorf("isolationRemaining = %v, want 0", wait)
	}
}

// --- resolveGatewayTarget: preferred-gateway reconnect ---

func TestResolveGatewayTarget_FirstConnect(t *testing.T) {
	// No remembered gateway: dial a resolved candidate (injected pick → index 0
	// for determinism; the random spread itself is covered by TestPickGatewayIP).
	withGatewayPick(t, func(n int) int { return 0 })
	withResolver(t, fakeResolver(func(ctx context.Context, host string) ([]string, error) {
		return []string{"10.0.0.1", "10.0.0.2"}, nil
	}))
	target, ip, err := resolveGatewayTarget(context.Background(), "gw.svc:9998", "", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ip != "10.0.0.1" || target != "10.0.0.1:9998" {
		t.Errorf("first connect: ip=%q target=%q, want 10.0.0.1 / 10.0.0.1:9998", ip, target)
	}
}

func TestResolveGatewayTarget_PreferredInDNS(t *testing.T) {
	// Remembered IP still listed by DNS → dial it (both TOLERATING and normal).
	withResolver(t, fakeResolver(func(ctx context.Context, host string) ([]string, error) {
		return []string{"10.0.0.2", "10.0.0.1"}, nil
	}))
	for _, failover := range []bool{false, true} {
		target, ip, err := resolveGatewayTarget(context.Background(), "gw.svc:9998", "10.0.0.1", failover)
		if err != nil {
			t.Fatalf("failover=%v: unexpected error: %v", failover, err)
		}
		if ip != "10.0.0.1" || target != "10.0.0.1:9998" {
			t.Errorf("failover=%v: ip=%q target=%q, want preferred 10.0.0.1", failover, ip, target)
		}
	}
}

func TestResolveGatewayTarget_ToleratingDialsRememberedIP(t *testing.T) {
	// Core regression for the gateway-IP-change idle-wait: the remembered IP has
	// dropped out of DNS (gateway restart, k8s endpoint propagation window), and
	// we are in TOLERATING (failoverAllowed=false). The old behavior refused to
	// dial and idled through the whole tolerance window; the fix dials the
	// remembered IP directly. The switch-home prohibition (only preferredIP is
	// ever dialed) is the safety guarantee, not the DNS membership check.
	withResolver(t, fakeResolver(func(ctx context.Context, host string) ([]string, error) {
		return []string{"10.0.0.9"}, nil // preferredIP 10.0.0.1 NOT listed
	}))
	target, ip, err := resolveGatewayTarget(context.Background(), "gw.svc:9998", "10.0.0.1", false)
	if err != nil {
		t.Fatalf("TOLERATING + preferred not in DNS: expected to dial remembered IP, got error: %v", err)
	}
	if ip != "10.0.0.1" || target != "10.0.0.1:9998" {
		t.Errorf("TOLERATING dial: ip=%q target=%q, want remembered 10.0.0.1 / 10.0.0.1:9998", ip, target)
	}
}

func TestResolveGatewayTarget_NormalFailoverAcceptsOther(t *testing.T) {
	// Preferred dropped from DNS but NOT in TOLERATING (failoverAllowed=true):
	// accept another resolved gateway. Normal failover path must not regress.
	withResolver(t, fakeResolver(func(ctx context.Context, host string) ([]string, error) {
		return []string{"10.0.0.9"}, nil // preferredIP 10.0.0.1 NOT listed
	}))
	target, ip, err := resolveGatewayTarget(context.Background(), "gw.svc:9998", "10.0.0.1", true)
	if err != nil {
		t.Fatalf("normal failover: unexpected error: %v", err)
	}
	if ip != "10.0.0.9" || target != "10.0.0.9:9998" {
		t.Errorf("normal failover: ip=%q target=%q, want 10.0.0.9", ip, target)
	}
}

func TestResolveGatewayTarget_DNSResolveError(t *testing.T) {
	// Resolver fails and there is no remembered gateway → nothing to dial,
	// propagate the error.
	withResolver(t, fakeResolver(func(ctx context.Context, host string) ([]string, error) {
		return nil, context.DeadlineExceeded
	}))
	_, _, err := resolveGatewayTarget(context.Background(), "gw.svc:9998", "", false)
	if err == nil {
		t.Error("expected error when resolver fails and no remembered gateway, got nil")
	}
}

func TestResolveGatewayTarget_DNSFailureFallsBackToRememberedIP(t *testing.T) {
	// DNS outage survival: the resolver errors but a gateway is remembered.
	// The sandlot must fall back to dialing the remembered IP directly — in
	// BOTH phases. The old behavior returned the error and left the sandlot
	// idling: in TOLERATING it burned the whole tolerance window and CLEANed
	// mounts whose gateway was alive; in the crash-restart case (phase "") it
	// held mounts forever. The direct dial is safe (connect-clean + etcd
	// ownership bound any landing) and every attempt re-resolves, so DNS
	// recovery restores failover naturally.
	withResolver(t, fakeResolver(func(ctx context.Context, host string) ([]string, error) {
		return nil, fmt.Errorf("all nameservers down")
	}))
	for _, failover := range []bool{false, true} {
		target, ip, err := resolveGatewayTarget(context.Background(), "gw.svc:9998", "10.0.0.1", failover)
		if err != nil {
			t.Fatalf("failover=%v: DNS failure with remembered gateway must direct-dial, got error: %v", failover, err)
		}
		if ip != "10.0.0.1" || target != "10.0.0.1:9998" {
			t.Errorf("failover=%v: DNS-failure fallback: ip=%q target=%q, want remembered 10.0.0.1", failover, ip, target)
		}
	}
}

func TestResolveGatewayTarget_DNSEmptyFallsBackToRememberedIP(t *testing.T) {
	// Empty answer set (NXDOMAIN-ish, no error) behaves like a resolver
	// failure: fall back to the remembered IP with memory, error without.
	withResolver(t, fakeResolver(func(ctx context.Context, host string) ([]string, error) {
		return []string{}, nil
	}))
	target, ip, err := resolveGatewayTarget(context.Background(), "gw.svc:9998", "10.0.0.1", false)
	if err != nil {
		t.Fatalf("empty DNS with remembered gateway must direct-dial, got error: %v", err)
	}
	if ip != "10.0.0.1" || target != "10.0.0.1:9998" {
		t.Errorf("empty-DNS fallback: ip=%q target=%q, want remembered 10.0.0.1", ip, target)
	}
	_, _, err = resolveGatewayTarget(context.Background(), "gw.svc:9998", "", true)
	if err == nil {
		t.Error("empty DNS without remembered gateway: expected error, got nil")
	}
}

func TestResolveGatewayTarget_FailoverPicksSpreadCandidate(t *testing.T) {
	// Normal failover with a multi-IP answer (k8s headless Service): the pick
	// comes from the whole set, not a fixed ips[0] — with injected index 2 the
	// third candidate must be dialed. Prevents every failover landing on the
	// same pod.
	withGatewayPick(t, func(n int) int { return 2 })
	withResolver(t, fakeResolver(func(ctx context.Context, host string) ([]string, error) {
		return []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}, nil
	}))
	target, ip, err := resolveGatewayTarget(context.Background(), "gw.svc:9998", "10.9.9.9", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ip != "10.0.0.3" || target != "10.0.0.3:9998" {
		t.Errorf("spread failover: ip=%q target=%q, want 10.0.0.3", ip, target)
	}
}

func TestPickGatewayIP(t *testing.T) {
	// Single-answer DNS (bare metal stream domain): the pick is that answer.
	if got := pickGatewayIP([]string{"10.0.0.7"}); got != "10.0.0.7" {
		t.Errorf("single-IP pick = %q, want 10.0.0.7", got)
	}
	// Multi-IP: injected index selects that candidate.
	withGatewayPick(t, func(n int) int { return 1 })
	if got := pickGatewayIP([]string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}); got != "10.0.0.2" {
		t.Errorf("multi-IP pick with idx 1 = %q, want 10.0.0.2", got)
	}
	// With the real random source the pick is always a member of the set
	// (indices in range) — the anti-herd property, without asserting exact
	// distribution.
	set := map[string]bool{"10.0.0.1": true, "10.0.0.2": true, "10.0.0.3": true}
	for i := 0; i < 100; i++ {
		if !set[pickGatewayIP([]string{"10.0.0.1", "10.0.0.2", "10.0.0.3"})] {
			t.Fatalf("pick outside candidate set at iteration %d", i)
		}
	}
}

// --- initialCleanupState: crash-while-CONNECTED tolerance re-anchor ---

func TestInitialCleanupState_ReanchorsWhenMountsHeld(t *testing.T) {
	// Crash during a healthy connection persists phase "" (the disconnect
	// record is only written on an observed stream break). Re-adopted mounts
	// must re-anchor TOLERATING at process start, else a dead gateway +
	// unreachable DNS holds the mounts forever (no clock in "", heartbeats
	// keep the warden countdowns fresh).
	now := time.Now()
	got := initialCleanupState(CleanupState{Phase: ""}, true, now)
	if got.Phase != CleanupPhaseTolerating {
		t.Errorf("phase = %q, want %q", got.Phase, CleanupPhaseTolerating)
	}
	if !got.DisconnectTime.Equal(now) {
		t.Errorf("DisconnectTime = %v, want anchor at now (%v)", got.DisconnectTime, now)
	}
}

func TestInitialCleanupState_NoMountsNoAnchor(t *testing.T) {
	// A clean fleet (idle node, or fresh start) keeps phase "": no tolerance
	// clock is invented, normal connect + free failover semantics apply.
	now := time.Now()
	got := initialCleanupState(CleanupState{Phase: ""}, false, now)
	if got.Phase != "" || !got.DisconnectTime.IsZero() {
		t.Errorf("clean start must keep the empty state, got %+v", got)
	}
}

func TestInitialCleanupState_PersistedPhaseWins(t *testing.T) {
	// A restart during an outage resumes the persisted phase EXACTLY — the
	// tolerance clock stays anchored to the original disconnect and must not
	// be reset by the re-anchor path (nor by mounts being held).
	original := time.Now().Add(-120 * time.Second)
	for _, phase := range []string{CleanupPhaseTolerating, CleanupPhaseCleaning, CleanupPhaseDone} {
		got := initialCleanupState(CleanupState{Phase: phase, DisconnectTime: original}, true, time.Now())
		if got.Phase != phase || !got.DisconnectTime.Equal(original) {
			t.Errorf("phase %q: got %+v, want the persisted state unchanged", phase, got)
		}
	}
}

// --- mayHoldUnreleasedMounts: the re-anchor's held-mounts signal ---

func TestMayHoldUnreleasedMounts(t *testing.T) {
	h := newTestHandler()
	if h.mayHoldUnreleasedMounts() {
		t.Error("empty handler: no VMs, want false")
	}
	h.mu.Lock()
	h.vms["vm-clean"] = &VMState{Volumes: map[string]struct{}{}}
	h.mu.Unlock()
	if h.mayHoldUnreleasedMounts() {
		t.Error("only CLEAN VMs (empty Volumes set), want false")
	}
	h.mu.Lock()
	h.vms["vm-mounted"] = &VMState{Volumes: map[string]struct{}{"/volumes/agent-a": {}}}
	h.mu.Unlock()
	if !h.mayHoldUnreleasedMounts() {
		t.Error("a VM holding a mounted volume, want true")
	}

	// A re-adopted survivor whose cleanup hasn't proven it clean counts as
	// held even though its in-memory Volumes set is empty (bindings do not
	// survive a restart) — the crash-while-CONNECTED re-anchor depends on it.
	h2 := newTestHandler()
	h2.markReadoptPending("vm-survivor")
	if !h2.mayHoldUnreleasedMounts() {
		t.Error("unproven re-adopted survivor, want true")
	}
	h2.clearReadoptPending("vm-survivor")
	if h2.mayHoldUnreleasedMounts() {
		t.Error("survivor cleanup proven, want false")
	}
}

func TestResolveGatewayTarget_BadAddr(t *testing.T) {
	// gatewayAddr not host:port → split error.
	_, _, err := resolveGatewayTarget(context.Background(), "no-port-here", "", true)
	if err == nil {
		t.Error("expected error for unparseable gateway addr, got nil")
	}
}

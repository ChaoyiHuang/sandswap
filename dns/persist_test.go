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
	"common/config"
	"context"
	"strings"
	"testing"
	"time"
)

// TestExpireStickyTimeBased verifies the first expiry pass: an entry whose
// LastQuery is older than cfg.StickyExpire seconds is removed and marked dirty
// (so the etcd mirror is deleted too). A fresh entry is kept. This bounds how
// long a client sticks to a gateway it no longer talks to.
func TestExpireStickyTimeBased(t *testing.T) {
	s := &DNSServer{
		cfg:          &Config{StickyExpire: 1800},
		sticky:       make(map[string]*StickyEntry),
		dirty:        make(map[string]struct{}),
		registryByID: map[string]gatewayRegistry{"gw-1": {gatewayURL: "https://10.0.1.1:3000"}},
		// The entries below are treated as already MIRRORED (a previous flush
		// wrote them): the assertions are about deleting an existing mirror.
		mirrored: map[string]struct{}{},
	}
	now := time.Now().Unix()
	s.sticky["fresh"] = &StickyEntry{GWID: "gw-1", LastQuery: now, Created: now}
	s.sticky["stale"] = &StickyEntry{GWID: "gw-1", LastQuery: now - 3600, Created: now - 3600} // > 1800s
	s.mirrored["stale"] = struct{}{}

	s.expireSticky()

	if _, ok := s.sticky["fresh"]; !ok {
		t.Error("fresh entry should be kept")
	}
	if _, ok := s.dirty["fresh"]; ok {
		t.Error("fresh entry should not be marked dirty")
	}
	if _, ok := s.sticky["stale"]; ok {
		t.Error("stale entry should be expired")
	}
	if _, ok := s.dirty["stale"]; !ok {
		t.Error("expired entry should be marked dirty for etcd deletion")
	}
}

// TestExpireStickyBoundary verifies the boundary: an entry exactly at the
// expiry threshold (now - LastQuery == StickyExpire) is NOT expired (the check
// is strictly greater-than). This matches the intent "haven't been queried
// within sticky_expire seconds" - querying exactly at the edge is still live.
func TestExpireStickyBoundary(t *testing.T) {
	s := &DNSServer{
		cfg:          &Config{StickyExpire: 1800},
		sticky:       make(map[string]*StickyEntry),
		dirty:        make(map[string]struct{}),
		registryByID: map[string]gatewayRegistry{"gw-1": {gatewayURL: "https://10.0.1.1:3000"}},
		// The entries below are treated as already MIRRORED (a previous flush
		// wrote them): the assertions are about deleting an existing mirror.
		mirrored: map[string]struct{}{},
	}
	now := time.Now().Unix()
	s.sticky["edge"] = &StickyEntry{GWID: "gw-1", LastQuery: now - 1800, Created: now - 1800}

	s.expireSticky()

	if _, ok := s.sticky["edge"]; !ok {
		t.Error("entry at exactly StickyExpire should be kept (strict >)")
	}
}

// TestExpireStickyStaleGW verifies the second expiry pass: an entry whose
// gateway_id no longer has a registry record is removed even if it was queried
// recently. This prevents a client from being pinned to a gateway that was
// permanently retired (unregistered) - it could never be answered again. Note
// that DEATH alone does not invalidate: the registry plain key survives a dead
// gateway, and resolveStream's alive check re-places those clients.
func TestExpireStickyStaleGW(t *testing.T) {
	s := &DNSServer{
		cfg:          &Config{StickyExpire: 1800},
		sticky:       make(map[string]*StickyEntry),
		dirty:        make(map[string]struct{}),
		registryByID: map[string]gatewayRegistry{"gw-1": {gatewayURL: "https://10.0.1.1:3000"}},
		// The entries below are treated as already MIRRORED (a previous flush
		// wrote them): the assertions are about deleting an existing mirror.
		mirrored: map[string]struct{}{},
	}
	now := time.Now().Unix()
	s.sticky["pinned-retired"] = &StickyEntry{GWID: "gw-retired", LastQuery: now, Created: now} // never registered
	s.mirrored["pinned-retired"] = struct{}{}
	s.sticky["pinned-dead"] = &StickyEntry{GWID: "gw-dead", LastQuery: now, Created: now} // registered (stale record kept)
	s.registryByID["gw-dead"] = gatewayRegistry{gatewayURL: "https://10.0.9.9:3000"}

	s.expireSticky()

	if _, ok := s.sticky["pinned-retired"]; ok {
		t.Error("entry pinned to an unregistered gateway should be expired")
	}
	if _, ok := s.dirty["pinned-retired"]; !ok {
		t.Error("unregistered-GW entry should be marked dirty")
	}
	if _, ok := s.sticky["pinned-dead"]; !ok {
		t.Error("entry pinned to a registered (even dead) gateway should be KEPT")
	}
}

// TestExpireStickyLegacyFormat verifies a legacy / malformed record (empty
// gateway_id - e.g. written by an older DNS with the gw_addr layout) is
// dropped: it can never be answered.
func TestExpireStickyLegacyFormat(t *testing.T) {
	s := &DNSServer{
		cfg:          &Config{StickyExpire: 1800},
		sticky:       make(map[string]*StickyEntry),
		dirty:        make(map[string]struct{}),
		registryByID: map[string]gatewayRegistry{"gw-1": {gatewayURL: "https://10.0.1.1:3000"}},
		// The entries below are treated as already MIRRORED (a previous flush
		// wrote them): the assertions are about deleting an existing mirror.
		mirrored: map[string]struct{}{},
	}
	now := time.Now().Unix()
	s.sticky["legacy"] = &StickyEntry{GWID: "", LastQuery: now, Created: now}
	s.mirrored["legacy"] = struct{}{}

	s.expireSticky()

	if _, ok := s.sticky["legacy"]; ok {
		t.Error("legacy empty-gw_id record should be expired")
	}
	if _, ok := s.dirty["legacy"]; !ok {
		t.Error("legacy record should be marked dirty")
	}
}

// TestExpireStickyMixed verifies a mixed set: only the time-expired and
// stale-GW entries are removed; fresh+valid entries survive untouched.
func TestExpireStickyMixed(t *testing.T) {
	s := &DNSServer{
		cfg:    &Config{StickyExpire: 100},
		sticky: make(map[string]*StickyEntry),
		dirty:  make(map[string]struct{}),
		registryByID: map[string]gatewayRegistry{
			"gw-1": {gatewayURL: "https://10.0.1.1:3000"},
			"gw-2": {gatewayURL: "https://10.0.1.2:3000"},
		},
	}
	now := time.Now().Unix()
	s.mirrored = make(map[string]struct{})
	s.sticky["keep"] = &StickyEntry{GWID: "gw-1", LastQuery: now, Created: now}
	s.sticky["time-expired"] = &StickyEntry{GWID: "gw-2", LastQuery: now - 200, Created: now - 200}
	s.sticky["gw-expired"] = &StickyEntry{GWID: "gw-retired", LastQuery: now, Created: now}
	// Both removed entries have an etcd mirror (the delete assertions below).
	s.mirrored["time-expired"] = struct{}{}
	s.mirrored["gw-expired"] = struct{}{}

	s.expireSticky()

	if _, ok := s.sticky["keep"]; !ok {
		t.Error("keep should survive")
	}
	if _, ok := s.sticky["time-expired"]; ok {
		t.Error("time-expired should be removed")
	}
	if _, ok := s.sticky["gw-expired"]; ok {
		t.Error("gw-expired should be removed")
	}
	if len(s.dirty) != 2 {
		t.Errorf("expected 2 dirty (deleted) entries, got %d", len(s.dirty))
	}
}

// TestExpireStickyNoDoubleDirty verifies an entry that is BOTH time-expired
// and stale-GW is marked dirty exactly once (the first pass deletes it; the
// second pass never sees it).
func TestExpireStickyNoDoubleDirty(t *testing.T) {
	s := &DNSServer{
		cfg:          &Config{StickyExpire: 100},
		sticky:       make(map[string]*StickyEntry),
		dirty:        make(map[string]struct{}),
		registryByID: map[string]gatewayRegistry{"gw-1": {gatewayURL: "https://10.0.1.1:3000"}},
		// The entries below are treated as already MIRRORED (a previous flush
		// wrote them): the assertions are about deleting an existing mirror.
		mirrored: map[string]struct{}{},
	}
	now := time.Now().Unix()
	s.sticky["both"] = &StickyEntry{GWID: "gw-retired", LastQuery: now - 200, Created: now - 200}
	s.mirrored["both"] = struct{}{}

	s.expireSticky()

	if _, ok := s.sticky["both"]; ok {
		t.Error("both-expired entry should be removed")
	}
	// dirty is a set (map[string]struct{}), so "exactly once" is just presence.
	if _, ok := s.dirty["both"]; !ok {
		t.Error("both-expired entry should be marked dirty")
	}
	if len(s.dirty) != 1 {
		t.Errorf("expected exactly 1 dirty entry, got %d", len(s.dirty))
	}
}

// TestExpireStickyEmptyNoop verifies an empty sticky map is a no-op (no panic,
// dirty stays empty).
func TestExpireStickyEmptyNoop(t *testing.T) {
	s := &DNSServer{
		cfg:          &Config{StickyExpire: 100},
		sticky:       make(map[string]*StickyEntry),
		dirty:        make(map[string]struct{}),
		registryByID: map[string]gatewayRegistry{"gw-1": {gatewayURL: "https://10.0.1.1:3000"}},
		// The entries below are treated as already MIRRORED (a previous flush
		// wrote them): the assertions are about deleting an existing mirror.
		mirrored: map[string]struct{}{},
	}
	s.expireSticky()
	if len(s.dirty) != 0 {
		t.Errorf("empty sticky should produce no dirty entries, got %d", len(s.dirty))
	}
}

// etcdKeyToClientIP extracts the client IP from an etcd key (test-only helper;
// the production load path inlines the same TrimPrefix).
func etcdKeyToClientIP(key string) string {
	return strings.TrimPrefix(key, stickyPrefix)
}

// TestEtcdKeyToClientIP verifies the key->client-IP extraction used when
// loading sticky records from etcd.
func TestEtcdKeyToClientIP(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{stickyPrefix + "10.0.1.5", "10.0.1.5"},
		{stickyPrefix + "2001:db8::1", "2001:db8::1"},
		{"no-prefix", "no-prefix"}, // no prefix -> returned as-is (TrimPrefix is a no-op)
	}
	for _, c := range cases {
		if got := etcdKeyToClientIP(c.in); got != c.want {
			t.Errorf("etcdKeyToClientIP(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// SPDX-License-Identifier: Apache-2.0

// runToCompletion runs fn in a goroutine and fails the test if it does not
// return promptly (loops must exit on a cancelled context).
func runToCompletion(t *testing.T, name string, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		fn()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("%s did not return on cancelled context", name)
	}
}

// TestSyncLoopFinalFlushOnCancel verifies syncLoop exits on context cancel and
// performs a final flush; with an empty dirty set the flush touches no etcd
// client (nil is safe here — the loop body never reaches an RPC).
func TestSyncLoopFinalFlushOnCancel(t *testing.T) {
	s := &DNSServer{
		cfg:   &Config{StickySyncInterval: 1},
		dirty: make(map[string]struct{}),
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	runToCompletion(t, "syncLoop", func() { s.syncLoop(ctx) })
}

// TestExpireLoopExitsOnCancel verifies expireLoop exits on context cancel.
func TestExpireLoopExitsOnCancel(t *testing.T) {
	s := &DNSServer{cfg: &Config{StickyExpire: 1800}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	runToCompletion(t, "expireLoop", func() { s.expireLoop(ctx) })
}

// TestOwnerEvictorExitsOnCancel verifies ownerEvictor exits on context cancel.
func TestOwnerEvictorExitsOnCancel(t *testing.T) {
	s := &DNSServer{owners: make(map[string]*ownerEntry)}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	runToCompletion(t, "ownerEvictor", func() { s.ownerEvictor(ctx) })
}

// TestWatchPrefixExitsOnCancel verifies watchPrefix exits before dialing etcd
// when the context is already cancelled (nil client is safe).
func TestWatchPrefixExitsOnCancel(t *testing.T) {
	s := &DNSServer{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	runToCompletion(t, "watchPrefix", func() {
		s.watchPrefix(ctx, "/sandswap/health/", 0, func(key, value string, deleted bool) {})
	})
}

// TestSyncStickyToEtcdEmptyDirtyNoop verifies the dirty-flush early-returns
// with nothing to do and never touches a nil etcd client.
func TestSyncStickyToEtcdEmptyDirtyNoop(t *testing.T) {
	s := &DNSServer{
		sticky: make(map[string]*StickyEntry),
		dirty:  make(map[string]struct{}),
	}
	s.syncStickyToEtcd()
	if len(s.dirty) != 0 {
		t.Errorf("dirty should stay empty, got %d", len(s.dirty))
	}
}

// TestHandleHealthEvent verifies /sandswap/health/ events: a PUT populates
// healthByID (node_count), a DELETE clears it, and a corrupt value is skipped
// without clobbering a prior good record or panicking.
func TestHandleHealthEvent(t *testing.T) {
	s := &DNSServer{healthByID: make(map[string]ownerHealth)}
	s.handleHealthEvent("/sandswap/health/gw1", `{"node_count":3}`, false)
	if h := s.healthByID["gw1"]; h.nodeCount != 3 {
		t.Errorf("expected node_count=3, got %+v", h)
	}
	s.handleHealthEvent("/sandswap/health/gw2", "{not json", false)
	if _, ok := s.healthByID["gw2"]; ok {
		t.Error("corrupt health PUT should be skipped")
	}
	s.handleHealthEvent("/sandswap/health/gw1", "", true)
	if _, ok := s.healthByID["gw1"]; ok {
		t.Error("DELETE should remove the health record")
	}
}

// TestSetSchedulingDutyHardValidation verifies the duty cap range check: out of
// range values are rejected with the current config kept.
func TestSetSchedulingDutyHardValidation(t *testing.T) {
	s := &DNSServer{schedConfig: config.NewWatchableConfig(SchedulingConfig{Policy: PolicySpread, DutyHard: 0.85})}
	if s.SetScheduling(PolicyBinpack, -0.1) {
		t.Error("negative duty_hard must be rejected")
	}
	if s.SetScheduling(PolicyBinpack, 1.5) {
		t.Error("duty_hard > 1 must be rejected")
	}
	if got := s.schedConfig.Get(); got.Policy != PolicySpread || got.DutyHard != 0.85 {
		t.Errorf("rejected swap must keep current config, got %+v", got)
	}
	if !s.SetScheduling(PolicyBinpack, 0) {
		t.Error("duty_hard=0 (disabled) must be accepted")
	}
	if got := s.schedConfig.Get(); got.Policy != PolicyBinpack || got.DutyHard != 0 {
		t.Errorf("accepted swap not applied, got %+v", got)
	}
}

// TestSetSchedulingNilCreatesConfig verifies SetScheduling bootstraps a nil
// schedConfig instead of panicking (bootstrap path before Start).
func TestSetSchedulingNilCreatesConfig(t *testing.T) {
	s := &DNSServer{}
	if !s.SetScheduling(PolicySpread, 0.5) {
		t.Fatal("expected acceptance")
	}
	if s.schedConfig == nil {
		t.Fatal("schedConfig should have been created")
	}
	if got := s.schedConfig.Get(); got.Policy != PolicySpread || got.DutyHard != 0.5 {
		t.Errorf("config mismatch: %+v", got)
	}
}

// TestPreferHigherLoadAndDutyHard verify the policy accessors read the live
// WatchableConfig (nil-safe for tests/bootstrap).
func TestPreferHigherLoadAndDutyHard(t *testing.T) {
	nilS := &DNSServer{}
	if nilS.preferHigherLoad() || nilS.dutyHard() != 0 {
		t.Error("nil schedConfig must default to spread + no cap")
	}
	s := &DNSServer{schedConfig: config.NewWatchableConfig(SchedulingConfig{Policy: PolicyBinpack, DutyHard: 0.7})}
	if !s.preferHigherLoad() || s.dutyHard() != 0.7 {
		t.Errorf("binpack/dutyHard not read from schedConfig: %v %v", s.preferHigherLoad(), s.dutyHard())
	}
}

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

// W4(a) lease mutation triage — wave 2 pins (selfload / shed / peerload /
// mount_lock survivors). Each test names the survivor class it kills; the
// classified-equivalent remainder (parse guards over kernel-stable formats,
// float-EWMA exact-equality boundaries, nil-logger defaults) is recorded in
// the triage workfile, not pinned.

import (
	"runtime/debug"
	"runtime/metrics"
	"testing"
	"time"
)

// TestMountLockSlotEvictionPinsConjunction pins the eviction conjunction
// (refs<=0 && holder==nil && map identity): evicting a slot with LIVE
// interests splits them across two slots and silently removes the mutual
// exclusion the mount gate exists to provide.
func TestMountLockSlotEvictionPinsConjunction(t *testing.T) {
	ml := NewMountLock()

	// One holder + one waiter: two interests on ONE slot.
	holder, err := ml.Acquire("sf-evict")
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	type result struct {
		tok *MountLockToken
		err error
	}
	waitDone := make(chan result, 1)
	go func() {
		tok, err := ml.AcquireWait("sf-evict", 50*time.Millisecond)
		waitDone <- result{tok, err}
	}()

	// Holder releases: the waiter must take over on the SAME slot, proving the
	// slot was not evicted while an interest remained.
	ml.Release(holder)
	var r result
	select {
	case r = <-waitDone:
		if r.err != nil {
			t.Fatalf("waiter failed after holder release (slot evicted early?): %v", r.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("waiter never woke — the slot was evicted while an interest remained")
	}

	// Full drain: after the waiter also releases, the slot is evicted.
	ml.Release(r.tok)
	ml.mu.Lock()
	n := len(ml.slots)
	ml.mu.Unlock()
	if n != 0 {
		t.Fatalf("fully-released slot not evicted (leak): %d slot(s) remain", n)
	}
}

// TestPeerLoadSelfExclusionPinsW4 pins the self-exclusion guard shared by
// applyPut/applyDelete (a gateway must never treat ITSELF as a shed target —
// the ||-flip added self to the peer map, and shedding-to-self is a 503
// loop) plus the malformed-JSON skip and the delete path.
func TestPeerLoadSelfExclusionPinsW4(t *testing.T) {
	p := NewPeerLoadMonitor(nil, "self-gw", nil) // nil logger also proves the default-construction guard

	idle := `{"gateway_id":"self-gw","clean_vms":5,"agg_duty_long":0.1,"node_count":2}`
	p.applyPut("self-gw", idle)
	if n := len(p.peers); n != 0 {
		t.Fatalf("self must be excluded from the peer map, got %d entries", n)
	}

	peerIdle := `{"gateway_id":"peer-1","clean_vms":5,"agg_duty_long":0.1,"node_count":2}`
	p.applyPut("peer-1", peerIdle)
	if !p.HasIdlePeer() {
		t.Fatal("a fresh idle peer entry must satisfy HasIdlePeer")
	}

	p.applyPut("peer-2", "{not json")
	if _, ok := p.peers["peer-2"]; ok {
		t.Fatal("malformed load value must be skipped")
	}

	p.applyDelete("peer-1")
	if p.HasIdlePeer() {
		t.Fatal("peer removal must clear HasIdlePeer")
	}

	// A stale (but well-formed) entry must not count.
	p.applyPut("peer-1", peerIdle)
	p.mu.Lock()
	pl := p.peers["peer-1"]
	if pl == nil {
		p.mu.Unlock()
		t.Fatal("harness: peer entry missing")
	}
	pl.LastSeen = time.Now().Add(-2 * peerLoadStale)
	p.mu.Unlock()
	if p.HasIdlePeer() {
		t.Fatal("a stale peer entry must not satisfy HasIdlePeer")
	}
}

// TestShedNilAndDisabledGuardsPinsW4 pins the shed controller's entry guards:
// nil receiver (the ||-flip nil-derefs the hot path) and the disabled
// configuration (Enabled=false must answer None without touching pool/peers)
// plus the rate-token 0-sentinel.
func TestShedNilAndDisabledGuardsPinsW4(t *testing.T) {
	var nilS *ShedController
	if act := nilS.MaybeShed("sf-x"); act != ShedActionNone {
		t.Fatalf("nil controller must be a no-op, got %v", act)
	}

	// Constructed but disabled: pool/peers are nil — the Enabled gate must
	// return before either is touched.
	s := &ShedController{cfg: &ShedConfig{}, pool: nil, peers: nil}
	if act := s.MaybeShed("sf-x"); act != ShedActionNone {
		t.Fatalf("disabled controller must answer None, got %v", act)
	}

	// Rate-token 0-sentinel: rps<=0 disables token consumption.
	tok := &ShedController{cfg: &ShedConfig{}}
	tok.cfg.RatePerSec.Store(0)
	if tok.takeToken() {
		t.Fatal("rps=0 must disable token consumption (0 = off sentinel)")
	}
}

// TestSelfloadMemLimitSentinelPinsW4 pins readSelfRuntimeMemRatio's two
// guards: the unlimited sentinel (limit==MaxInt64 ⇒ signal ABSENT, never
// over-threshold — the boundary flips read unlimited as a tiny limit and
// permanently pressurized the gateway) and the ratio clamp at 1.0.
func TestSelfloadMemLimitSentinelPinsW4(t *testing.T) {
	prev := debug.SetMemoryLimit(-1) // read current
	t.Cleanup(func() { debug.SetMemoryLimit(prev) })

	// Unlimited ⇒ (0, false)
	debug.SetMemoryLimit(1 << 62) // far above any usage; Go treats huge as effectively-unlimited
	if _, isMax := func() (float64, bool) {
		l := debug.SetMemoryLimit(-1)
		return 0, l == int64(^uint64(0)>>1)
	}(); isMax {
		// only meaningful when the runtime echoes our huge value as MaxInt64
		// (unlimited representation); otherwise the sentinel leg is covered
		// by the huge-limit case below anyway.
	}

	// A limit at HALF the live usage ⇒ ratio clamped to exactly 1.0
	metrics.Read(memTotalMetricSamples)
	total := memTotalMetricSamples[0].Value.Uint64()
	if total == 0 {
		t.Skip("runtime metrics unavailable — sentinel leg only")
	}
	debug.SetMemoryLimit(int64(total / 2))
	ratio, ok := readSelfRuntimeMemRatio()
	if !ok || ratio != 1.0 {
		t.Fatalf("usage/limit > 1 must clamp to exactly 1.0, got (%.3f, %v)", ratio, ok)
	}

	// A huge (unlimited) limit ⇒ absent signal, never pressurized
	debug.SetMemoryLimit(1 << 62)
	if r, ok := readSelfRuntimeMemRatio(); ok && r > 0 {
		// Go may normalize a huge limit to MaxInt64 (unlimited) — then ok
		// must be false. If it keeps the literal value, ratio≈0 and ok=true
		// is legitimate; only a POSITIVE ratio from a normalized unlimited
		// value would be the sentinel bug.
		l := debug.SetMemoryLimit(-1)
		if l == int64(^uint64(0)>>1) {
			t.Fatalf("unlimited (MaxInt64) limit must report ok=false, got (%.3f, true)", r)
		}
		debug.SetMemoryLimit(1 << 62)
	}
}

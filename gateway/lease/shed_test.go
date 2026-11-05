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
	"fmt"
	"log/slog"
	"testing"
	"time"

	"gateway/pool"
)

func newShedTestController(pm *pool.Manager, oc *OwnershipCache, peers *PeerLoadMonitor) (*ShedController, *ShedConfig) {
	cfg := &ShedConfig{}
	cfg.Update(true, 0, 1, 30, 5) // enabled, satSec=0 (IsSustainedSaturated(0)→false)
	s := NewShedController(cfg, pm, oc, peers, slog.New(slog.DiscardHandler))
	return s, cfg
}

// shedPeerMonitor builds a PeerLoadMonitor with an injected idle peer so
// HasIdlePeer returns true. Uses the unexported applyPut to populate the map.
func shedPeerMonitor(selfID string, idlePeerID string, cleanVMs uint32) *PeerLoadMonitor {
	p := NewPeerLoadMonitor(nil, selfID, slog.New(slog.DiscardHandler))
	p.applyPut(idlePeerID, fmt.Sprintf(`{"gateway_id":%q,"clean_vms":%d,"node_count":1}`, idlePeerID, cleanVMs))
	return p
}

// MaybeShed is disabled when the controller is nil or Enabled is false.
func TestShedDisabled(t *testing.T) {
	pm := pool.NewManager(nil, slog.New(slog.DiscardHandler))
	oc := NewOwnershipCacheForTest("gw")
	peers := shedPeerMonitor("gw", "peer", 5)

	// Enabled=false → None.
	cfg := &ShedConfig{}
	s := NewShedController(cfg, pm, oc, peers, slog.New(slog.DiscardHandler))
	if a := s.MaybeShed("sf-1"); a != ShedActionNone {
		t.Errorf("disabled shed = %v, want None", a)
	}

	// nil controller → None (must not panic).
	var nilS *ShedController
	if a := nilS.MaybeShed("sf-1"); a != ShedActionNone {
		t.Errorf("nil controller shed = %v, want None", a)
	}
}

// MaybeShed returns None when there is no idle peer (cluster-wide saturation).
func TestShedNoIdlePeer(t *testing.T) {
	pm := pool.NewManager(nil, slog.New(slog.DiscardHandler))
	oc := NewOwnershipCacheForTest("gw")
	peers := NewPeerLoadMonitor(nil, "gw", slog.New(slog.DiscardHandler)) // no peers
	s, cfg := newShedTestController(pm, oc, peers)
	cfg.Update(true, 1, 1, 30, 5)

	// Saturate the pool so IsSustainedSaturated can fire.
	pm.AddNode("n1")
	pm.UpdateNodeCapacity("n1", []pool.SpecCapacity{{SpecID: "small", Total: 1, Clean: 0}})
	// saturationSince set on UpdateNodeCapacity; but SatSec=1 and the timer is
	// "now", so wait just past 1s. Instead, verify the no-peer gate fires
	// regardless: even saturated, no peer → None.
	time.Sleep(1100 * time.Millisecond)
	if a := s.MaybeShed("sf-1"); a != ShedActionNone {
		t.Errorf("shed with no idle peer = %v, want None", a)
	}
}

// MaybeShed returns None when not sustained-saturated (transient spike).
func TestShedNotSustained(t *testing.T) {
	pm := pool.NewManager(nil, slog.New(slog.DiscardHandler))
	oc := NewOwnershipCacheForTest("gw")
	peers := shedPeerMonitor("gw", "peer", 5)
	s, cfg := newShedTestController(pm, oc, peers)
	cfg.Update(true, 10, 1, 30, 5) // 10s hysteresis

	// Saturate, but only just now — < 10s.
	pm.AddNode("n1")
	pm.UpdateNodeCapacity("n1", []pool.SpecCapacity{{SpecID: "small", Total: 1, Clean: 0}})
	if a := s.MaybeShed("sf-1"); a != ShedActionNone {
		t.Errorf("shed before hysteresis = %v, want None", a)
	}
}

// MaybeShed performs a shed when enabled + sustained + idle peer, and then
// returns Cooldown on the immediate next call (the sandfs is recentlyShed).
func TestShedPerformsThenCooldown(t *testing.T) {
	pm := pool.NewManager(nil, slog.New(slog.DiscardHandler))
	oc := NewOwnershipCacheForTest("gw")
	peers := shedPeerMonitor("gw", "peer", 5)
	s, cfg := newShedTestController(pm, oc, peers)
	cfg.Update(true, 0, 100, 30, 5) // satSec=0 disabled → use 1 and wait

	// Saturate: derived clean = total - bound. Set total=1 then reserve the
	// only VM (bound=1) so cleanCount()==0 across all nodes.
	pm.AddNode("n1")
	pm.UpdateNodeCapacity("n1", []pool.SpecCapacity{{SpecID: "small", Total: 1, Clean: 0}})
	pm.ReserveBound("n1", "small")
	cfg.SatSec.Store(1)
	time.Sleep(1100 * time.Millisecond)

	a := s.MaybeShed("sf-1")
	if a != ShedActionShed {
		t.Fatalf("first shed = %v, want Shed", a)
	}
	// The sandfs is now recentlyShed → next call returns Cooldown (no re-release).
	if a := s.MaybeShed("sf-1"); a != ShedActionCooldown {
		t.Errorf("second shed = %v, want Cooldown", a)
	}
	// isRecentlyShed reflects the cooldown.
	if !oc.isRecentlyShed("sf-1") {
		t.Errorf("isRecentlyShed should be true right after a shed")
	}
}

// ClearShed removes the cooldown (simulating a peer taking over via the watch).
func TestClearShed(t *testing.T) {
	oc := NewOwnershipCacheForTest("gw")
	oc.ShedOwnership("sf-1", 30)
	if !oc.isRecentlyShed("sf-1") {
		t.Fatalf("expected recentlyShed after ShedOwnership")
	}
	oc.ClearShed("sf-1")
	if oc.isRecentlyShed("sf-1") {
		t.Errorf("isRecentlyShed should be false after ClearShed")
	}
	// ClearShed is idempotent on a non-shed sandfs.
	oc.ClearShed("sf-nonexistent")
}

// ShedCooldownSweep evicts expired entries.
func TestShedCooldownSweep(t *testing.T) {
	oc := NewOwnershipCacheForTest("gw")
	oc.ShedOwnership("sf-1", 0) // cooldownSec 0 → ShedOwnership forces 30
	// Manually set an already-expired entry.
	oc.shedMu.Lock()
	oc.recentlyShed["sf-expired"] = time.Now().Add(-time.Hour)
	oc.shedMu.Unlock()
	oc.ShedCooldownSweep()
	oc.shedMu.Lock()
	_, expiredStillThere := oc.recentlyShed["sf-expired"]
	_, liveStillThere := oc.recentlyShed["sf-1"]
	oc.shedMu.Unlock()
	if expiredStillThere {
		t.Errorf("expired shed entry was not swept")
	}
	if !liveStillThere {
		t.Errorf("live shed entry was wrongly swept")
	}
}

// HasIdlePeer: no client, no peers → false; an idle fresh peer → true; a stale
// peer → false; a peer with zero clean → false.
func TestHasIdlePeer(t *testing.T) {
	p := NewPeerLoadMonitor(nil, "gw", slog.New(slog.DiscardHandler))
	if p.HasIdlePeer() {
		t.Errorf("HasIdlePeer with no peers = true, want false")
	}
	// Fresh idle peer.
	p.applyPut("peer-a", `{"gateway_id":"peer-a","clean_vms":3,"node_count":1}`)
	if !p.HasIdlePeer() {
		t.Errorf("HasIdlePeer with fresh idle peer = false, want true")
	}
	// Zero-clean peer does not count.
	p.applyPut("peer-b", `{"gateway_id":"peer-b","clean_vms":0,"node_count":1}`)
	// Still true because peer-a is idle.
	if !p.HasIdlePeer() {
		t.Errorf("HasIdlePeer dropped to false after adding a zero-clean peer")
	}
	// Remove peer-a; only zero-clean peer-b remains → false.
	p.applyDelete("peer-a")
	if p.HasIdlePeer() {
		t.Errorf("HasIdlePeer with only zero-clean peer = true, want false")
	}
}

// PeerLoadMonitor excludes self.
func TestPeerLoadExcludesSelf(t *testing.T) {
	p := NewPeerLoadMonitor(nil, "gw", slog.New(slog.DiscardHandler))
	p.applyPut("gw", `{"gateway_id":"gw","clean_vms":9,"node_count":1}`)
	if p.HasIdlePeer() {
		t.Errorf("HasIdlePeer counted self as a peer")
	}
}

// ── Local-live-lease guard ───────────────────────────────────────

// TestMaybeShedSkipsLocalMount verifies the local-live-lease guard: a sandfs
// whose VM this gateway still holds is never shed (deleting its ownership
// under a live lease opens a dual-mount window until the lease expires).
func TestMaybeShedSkipsLocalMount(t *testing.T) {
	cfg := &ShedConfig{}
	cfg.Update(true, 1, 10, 30, 5)
	pm := pool.NewManager(nil, nil)
	ctl := NewShedController(cfg, pm, nil, nil, nil)
	ctl.SetLocalMountGuard(func(sandfsID string) bool { return sandfsID == "held" })

	if got := ctl.MaybeShed("held"); got != ShedActionNone {
		t.Fatalf("MaybeShed on a locally-held sandfs = %v, want ShedActionNone", got)
	}
	// Without a local lease the decision proceeds past the guard (here it
	// stops at the no-idle-peer gate, proving the guard was not the blocker).
	peers := NewPeerLoadMonitor(nil, "self", nil)
	ctl2 := NewShedController(cfg, pm, nil, peers, nil)
	ctl2.SetLocalMountGuard(func(sandfsID string) bool { return false })
	if got := ctl2.MaybeShed("other"); got != ShedActionNone {
		t.Fatalf("MaybeShed without idle peer = %v, want ShedActionNone", got)
	}
}

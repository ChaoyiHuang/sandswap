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
	"context"
	"testing"
	"time"

	pb "common/proto/stream"
)

func TestPresenceKeyFormat(t *testing.T) {
	if got := presenceKey("node-7"); got != "/sandswap/node/node-7/presence" {
		t.Errorf("presenceKey = %q, want /sandswap/node/node-7/presence", got)
	}
}

// TestPresenceStateNilClient verifies the nil-client (test/single-node) mode:
// presence is assumed self-owned, owner is never dead, self is always healthy.
func TestPresenceStateNilClient(t *testing.T) {
	oc := NewOwnershipCacheForTest("gw-test")
	ctx := context.Background()

	state, err := oc.presenceState(ctx, "node-1")
	if err != nil || state != presenceSelf {
		t.Errorf("nil-client presenceState = (%v, %v), want (presenceSelf, nil)", state, err)
	}
	if oc.ownerDead(ctx, "gw-other") {
		t.Error("nil-client ownerDead must be false")
	}
	if !oc.selfHealthy(ctx) {
		t.Error("nil-client selfHealthy must be true")
	}
}

func TestMigratedTakeoverAllowedNilClient(t *testing.T) {
	ctx := context.Background()
	oc := NewOwnershipCacheForTest("gw-test")

	// No stream server and no test override -> no local node.
	if oc.migratedTakeoverAllowed(ctx, "node-1") {
		t.Error("no stream/override: takeover must not be allowed")
	}

	// Node connected to us + nil client (presence assumed self) -> allowed.
	oc.SetNodeConnectedForTest(func(nodeID string) bool { return nodeID == "node-1" })
	if !oc.migratedTakeoverAllowed(ctx, "node-1") {
		t.Error("connected node + presence-self: takeover should be allowed")
	}
	if oc.migratedTakeoverAllowed(ctx, "node-2") {
		t.Error("node not connected to us: takeover must be denied")
	}

	// Override saying disconnected -> denied even with presence-self default.
	oc.SetNodeConnectedForTest(func(string) bool { return false })
	if oc.migratedTakeoverAllowed(ctx, "node-1") {
		t.Error("disconnected node: takeover must be denied")
	}
	oc.SetNodeConnectedForTest(nil)
	if oc.migratedTakeoverAllowed(ctx, "node-1") {
		t.Error("override restored to nil (streamSrv nil): takeover must be denied")
	}
}

func TestValidateTiming(t *testing.T) {
	// T_safe = tolerance + warden + safeMarginSec(60). Isolation must exceed it.
	cases := []struct {
		name    string
		timing  *pb.NodeTiming
		wantErr bool
	}{
		{"nil", nil, true},
		{"degenerate", &pb.NodeTiming{}, true},
		{"zero tolerance", &pb.NodeTiming{WardenCountdownSec: 300, IsolationSec: 720}, true},
		{"cleanup > warden", &pb.NodeTiming{ToleranceSec: 300, WardenCountdownSec: 200, CleanupSec: 300, IsolationSec: 720}, true},
		{"zero isolation", &pb.NodeTiming{ToleranceSec: 300, WardenCountdownSec: 300, CleanupSec: 300}, true},
		{"isolation not exceeding T_safe", &pb.NodeTiming{ToleranceSec: 300, WardenCountdownSec: 300, CleanupSec: 300, IsolationSec: 660}, true}, // == T_safe (660) → reject
		{"valid", &pb.NodeTiming{ToleranceSec: 300, WardenCountdownSec: 300, CleanupSec: 300, IsolationSec: 720}, false},                         // 720 > 660
		{"valid cleanup below warden", &pb.NodeTiming{ToleranceSec: 60, WardenCountdownSec: 300, CleanupSec: 120, IsolationSec: 720}, false},
	}
	for _, c := range cases {
		err := validateTiming(c.timing)
		if (err != nil) != c.wantErr {
			t.Errorf("%s: validateTiming = %v, wantErr %v", c.name, err, c.wantErr)
		}
	}
}

func TestShedControllerRetryAfterSec(t *testing.T) {
	var nilCtl *ShedController
	if got := nilCtl.RetryAfterSec(); got != 5 {
		t.Errorf("nil controller = %d, want 5", got)
	}
	if got := (&ShedController{}).RetryAfterSec(); got != 5 {
		t.Errorf("nil cfg = %d, want 5", got)
	}

	cfg := &ShedConfig{}
	sc := NewShedController(cfg, nil, nil, nil, nil)
	cfg.Update(true, 10, 2, 30, 0)
	if got := sc.RetryAfterSec(); got != 5 {
		t.Errorf("unset RetryAfterSec = %d, want fallback 5", got)
	}
	cfg.Update(true, 10, 2, 30, 12)
	if got := sc.RetryAfterSec(); got != 12 {
		t.Errorf("configured RetryAfterSec = %d, want 12", got)
	}
	cfg.Update(false, -1, -1, -1, -3)
	if got := sc.RetryAfterSec(); got != 5 {
		t.Errorf("negative RetryAfterSec = %d, want fallback 5", got)
	}
	if cfg.Enabled.Load() {
		t.Error("Update(false,...) should disable shedding")
	}
	if cfg.SatSec.Load() != -1 || cfg.RatePerSec.Load() != -1 {
		t.Error("Update must store raw values; gating happens in MaybeShed")
	}
}

func TestPeerLoadApplyPutDelete(t *testing.T) {
	p := NewPeerLoadMonitor(nil, "self-gw", nil)

	// Self and empty IDs are ignored.
	p.applyPut("self-gw", `{"gateway_id":"self-gw","clean_vms":5,"node_count":2}`)
	p.applyPut("", `{"clean_vms":9,"node_count":9}`)
	if len(p.peers) != 0 {
		t.Fatalf("self/empty puts stored: %v", p.peers)
	}

	p.applyPut("gw-a", `{"gateway_id":"gw-a","clean_vms":4,"agg_duty_long":0.5,"node_count":2}`)
	pl := p.peers["gw-a"]
	if pl == nil || pl.CleanVMs != 4 || pl.NodeCount != 2 || pl.AggDutyLong != 0.5 {
		t.Fatalf("peer put mismatch: %+v", pl)
	}
	if !p.HasIdlePeer() {
		t.Error("fresh peer with clean VMs + nodes: HasIdlePeer should be true")
	}

	// Corrupt JSON is ignored (stale entry kept).
	p.applyPut("gw-a", "{not json")
	if p.peers["gw-a"] != pl {
		t.Error("corrupt put replaced a valid entry")
	}

	// Stale entries are skipped by HasIdlePeer.
	p.mu.Lock()
	p.peers["gw-stale"] = &PeerLoad{CleanVMs: 99, NodeCount: 9, LastSeen: time.Now().Add(-2 * peerLoadStale)}
	p.mu.Unlock()
	if !p.HasIdlePeer() {
		t.Error("one fresh idle peer must keep HasIdlePeer true despite stale peers")
	}
	p.mu.Lock()
	delete(p.peers, "gw-a")
	p.mu.Unlock()
	if p.HasIdlePeer() {
		t.Error("only stale peers left: HasIdlePeer must be false")
	}

	// Zero clean VMs or zero nodes disqualify a fresh peer.
	p.applyPut("gw-b", `{"clean_vms":0,"node_count":3}`)
	p.applyPut("gw-c", `{"clean_vms":3,"node_count":0}`)
	if p.HasIdlePeer() {
		t.Error("peers without clean capacity must not count as idle")
	}

	// Delete removes the entry; self/empty deletes are no-ops.
	p.applyDelete("gw-b")
	if _, ok := p.peers["gw-b"]; ok {
		t.Error("applyDelete did not remove the peer")
	}
	p.applyDelete("")
	p.applyDelete("self-gw")
	if len(p.peers) != 2 {
		t.Errorf("peers = %d, want 2 after deletes", len(p.peers))
	}

	// A nil monitor never reports an idle peer.
	var nilMonitor *PeerLoadMonitor
	if nilMonitor.HasIdlePeer() {
		t.Error("nil monitor must report no idle peer")
	}
}

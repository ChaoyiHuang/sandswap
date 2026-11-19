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
)

// TestPeerLoadSelfExclusion pins the self-exclusion guard shared by
// applyPut/applyDelete (a gateway must never treat ITSELF as a shed target —
// treating self as a peer makes shedding-to-self a 503 loop) plus the
// malformed-JSON skip and the delete path.
func TestPeerLoadSelfExclusion(t *testing.T) {
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

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
)

// TestReleaseOwnershipNilClient verifies ReleaseOwnership with a nil etcd client
// is cache-only (deletes the local entry, skips the async etcd mirror, no panic).
func TestReleaseOwnershipNilClient(t *testing.T) {
	oc := NewOwnershipCacheForTest("gw-test")
	oc.SetOwnedForTest("sandfs-1", "node-1")
	if !entryExists(oc, "sandfs-1") {
		t.Fatal("setup: entry should exist")
	}
	oc.ReleaseOwnership("sandfs-1")
	if entryExists(oc, "sandfs-1") {
		t.Error("ReleaseOwnership should delete the cache entry")
	}
	// Releasing a non-existent entry is a safe no-op.
	oc.ReleaseOwnership("sandfs-never")
}

// TestNoteMountedMissingEntry verifies NoteMounted on a sandfs with no cache
// entry is a safe no-op (does not create an entry).
func TestNoteMountedMissingEntry(t *testing.T) {
	oc := NewOwnershipCacheForTest("gw-test")
	oc.NoteMounted("sandfs-absent", "node-1")
	if entryExists(oc, "sandfs-absent") {
		t.Error("NoteMounted on a missing entry should not create one")
	}
}

// TestSetRoutingAddrs verifies the routing addresses (owner-address: gateway_url for 307/DNS,
// stream_addr for sandlot reconnect) are stored for the health-key writer.
func TestSetRoutingAddrs(t *testing.T) {
	oc := NewOwnershipCacheForTest("gw-test")
	oc.SetRoutingAddrs("https://gw-1:3000", "gw-1:9998")
	oc.mu.Lock()
	defer oc.mu.Unlock()
	if oc.gatewayURL != "https://gw-1:3000" {
		t.Errorf("gatewayURL = %q, want https://gw-1:3000", oc.gatewayURL)
	}
	if oc.streamAddr != "gw-1:9998" {
		t.Errorf("streamAddr = %q, want gw-1:9998", oc.streamAddr)
	}
}

// TestCurrentNodeCountOverride verifies the node-count override: when
// nodeCountFn is set, currentNodeCount uses it (so tests/a fault-injection can
// simulate compute-present/absent without a real stream server).
func TestCurrentNodeCountOverride(t *testing.T) {
	oc := NewOwnershipCacheForTest("gw-test") // nodeCountFn defaults to func() int { return 1 }
	if n := oc.currentNodeCount(); n != 1 {
		t.Errorf("default override: got %d, want 1", n)
	}
	oc.SetNodeCountFunc(func() int { return 0 }) // fault state
	if n := oc.currentNodeCount(); n != 0 {
		t.Errorf("fault override: got %d, want 0", n)
	}
	oc.SetNodeCountFunc(nil) // restore default -> falls to streamSrv (nil here) -> 0
	if n := oc.currentNodeCount(); n != 0 {
		t.Errorf("nil fn + nil streamSrv: got %d, want 0", n)
	}
}

// TestNodeConnectedNilStreamServer verifies NodeConnected returns true when
// there is no stream server (single-node mode: assume connected).
func TestNodeConnectedNilStreamServer(t *testing.T) {
	oc := NewOwnershipCacheForTest("gw-test") // streamSrv nil
	if !oc.NodeConnected("node-1") {
		t.Error("nil streamSrv: expected NodeConnected=true (single-node assumption)")
	}
}

// TestOwnershipAccessorsNilSafe verifies the GatewayID/Client accessors on a
// normally-constructed (non-nil) cache.
func TestOwnershipAccessorsNonNil(t *testing.T) {
	oc := NewOwnershipCacheForTest("gw-7")
	if oc.GatewayID() != "gw-7" {
		t.Errorf("GatewayID = %q, want gw-7", oc.GatewayID())
	}
	if oc.Client() != nil {
		t.Error("ForTest cache should have a nil client")
	}
}

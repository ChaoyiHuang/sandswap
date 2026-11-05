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
)

// TestLookupOwnerGatewayIDNilClient verifies the nil-etcd-client guard: with no
// client (single-node/local mode), LookupOwnerGatewayID returns an explicit
// error rather than panicking. The 307-redirect path treats this as "no
// redirect" (caller 503s + retries, which force-takes-over locally).
func TestLookupOwnerGatewayIDNilClient(t *testing.T) {
	gwID, err := LookupOwnerGatewayID(context.Background(), nil, "sandfs-1")
	if err == nil {
		t.Error("expected error for nil client")
	}
	if gwID != "" {
		t.Errorf("expected empty gwID, got %q", gwID)
	}
}

// TestOwnerGatewayURLNilClient verifies the OwnershipCache wrapper returns "" (no
// redirect) when the cache has no etcd client, without panicking.
func TestOwnerGatewayURLNilClient(t *testing.T) {
	oc := NewOwnershipCacheForTest("gw-test") // nil client
	if got := oc.OwnerGatewayURL(context.Background(), "sandfs-1"); got != "" {
		t.Errorf("nil client: expected \"\", got %q", got)
	}
	// A nil cache must also be safe (OwnerGatewayURL guards oc == nil).
	var nilOC *OwnershipCache
	if got := nilOC.OwnerGatewayURL(context.Background(), "sandfs-1"); got != "" {
		t.Errorf("nil cache: expected \"\", got %q", got)
	}
}

// TestOwnerGatewayURLGatewayIDNilSafe verifies the GatewayID/Client accessors are
// safe on a nil cache (used by handler code that may hold a nil cache in
// single-node mode).
func TestOwnerGatewayURLGatewayIDNilSafe(t *testing.T) {
	var nilOC *OwnershipCache
	if got := nilOC.GatewayID(); got != "" {
		t.Errorf("nil GatewayID(): expected \"\", got %q", got)
	}
	if got := nilOC.Client(); got != nil {
		t.Errorf("nil Client(): expected nil, got %v", got)
	}
}

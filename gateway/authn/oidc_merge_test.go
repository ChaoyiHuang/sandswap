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

package authn

import (
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

// jwkKey builds a test JWK key with the given kid and an optional "source"
// claim (to distinguish fresh vs stale versions of the same kid) and optional
// expiry.
func jwkKey(t *testing.T, kid, source string, exp *time.Time) jwk.Key {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	k, err := jwk.FromRaw(priv.Public())
	if err != nil {
		t.Fatal(err)
	}
	if kid != "" {
		if err := k.Set(jwk.KeyIDKey, kid); err != nil {
			t.Fatal(err)
		}
	}
	if source != "" {
		if err := k.Set("source", source); err != nil {
			t.Fatal(err)
		}
	}
	if exp != nil {
		// "exp" is the raw JWK claim key getJWKExpiry reads.
		if err := k.Set("exp", *exp); err != nil {
			t.Fatal(err)
		}
	}
	return k
}

// TestMergeKeySetsFreshWins verifies that when the same kid appears in both the
// stale and fresh sets, the FRESH version wins (rotated key takes precedence).
func TestMergeKeySetsFreshWins(t *testing.T) {
	stale := jwk.NewSet()
	fresh := jwk.NewSet()
	stale.AddKey(jwkKey(t, "kid-1", "stale", nil))
	fresh.AddKey(jwkKey(t, "kid-1", "fresh", nil))

	merged := mergeKeySets(stale, fresh, time.Minute, map[string]time.Time{})
	if merged.Len() != 1 {
		t.Fatalf("merged len = %d, want 1", merged.Len())
	}
	k, found := merged.LookupKeyID("kid-1")
	if !found {
		t.Fatal("kid-1 should be in merged")
	}
	src, _ := k.Get("source")
	if src != "fresh" {
		t.Errorf("merged kid-1 source = %v, want fresh (fresh must win)", src)
	}
}

// TestMergeKeySetsRetainsStaleWithoutExpiry verifies a stale key that is absent
// from fresh and carries no expiry is retained (grace period covers keys the
// IdP does not timestamp).
func TestMergeKeySetsRetainsStaleWithoutExpiry(t *testing.T) {
	stale := jwk.NewSet()
	fresh := jwk.NewSet()
	stale.AddKey(jwkKey(t, "stale-only", "stale", nil))

	merged := mergeKeySets(stale, fresh, time.Minute, map[string]time.Time{})
	if _, found := merged.LookupKeyID("stale-only"); !found {
		t.Error("stale key without expiry should be retained during grace")
	}
	if merged.Len() != 1 {
		t.Errorf("merged len = %d, want 1", merged.Len())
	}
}

// TestMergeKeySetsRetainsUnexpiredStale verifies a stale key with an expiry
// still inside the grace window is retained.
func TestMergeKeySetsRetainsUnexpiredStale(t *testing.T) {
	stale := jwk.NewSet()
	fresh := jwk.NewSet()
	exp := time.Now().Add(30 * time.Minute) // expires in the future
	stale.AddKey(jwkKey(t, "rotating", "stale", &exp))

	merged := mergeKeySets(stale, fresh, time.Minute, map[string]time.Time{})
	if _, found := merged.LookupKeyID("rotating"); !found {
		t.Error("stale key expiring in the future should be retained")
	}
}

// TestMergeKeySetsDropsExpiredStale verifies a stale key whose expiry is
// beyond the grace window is dropped (rotated-away key no longer honored).
func TestMergeKeySetsDropsExpiredStale(t *testing.T) {
	stale := jwk.NewSet()
	fresh := jwk.NewSet()
	exp := time.Now().Add(-2 * time.Hour) // long expired
	stale.AddKey(jwkKey(t, "old-key", "stale", &exp))

	merged := mergeKeySets(stale, fresh, time.Minute, map[string]time.Time{})
	if _, found := merged.LookupKeyID("old-key"); found {
		t.Error("stale key beyond grace should be dropped")
	}
	if merged.Len() != 0 {
		t.Errorf("merged len = %d, want 0", merged.Len())
	}
}

// A key that disappears from the JWKS is dropped after a bounded wall-clock
// grace even when it carries no "exp" (most IdPs publish none): otherwise a
// revoked signing key would stay valid forever.
func TestMergeKeySetsDropsRevokedKeyAfterGrace(t *testing.T) {
	stale := jwk.NewSet()
	fresh := jwk.NewSet()
	stale.AddKey(jwkKey(t, "revoked", "stale", nil))
	missing := map[string]time.Time{}

	merged := mergeKeySets(stale, fresh, time.Minute, missing)
	if _, found := merged.LookupKeyID("revoked"); !found {
		t.Fatal("key must be retained during the grace window")
	}
	// Simulate the grace elapsing.
	missing["revoked"] = time.Now().Add(-2 * time.Minute)
	merged = mergeKeySets(stale, fresh, time.Minute, missing)
	if _, found := merged.LookupKeyID("revoked"); found {
		t.Fatal("revoked key must be dropped after the bounded grace")
	}

	// A kid that reappears is served again and its absence marker is cleared.
	fresh.AddKey(jwkKey(t, "revoked", "fresh", nil))
	merged = mergeKeySets(stale, fresh, time.Minute, missing)
	if _, found := merged.LookupKeyID("revoked"); !found {
		t.Fatal("reappeared key must be used")
	}
	if _, still := missing["revoked"]; still {
		t.Fatal("absence marker must clear when the kid reappears")
	}
}

// A key published without a kid must still be revocable: absence tracking
// falls back to the RFC 7638 thumbprint, so the key is dropped after the
// grace like any kid-bearing key.
func TestMergeKeySetsRevokesKidlessKeyAfterGrace(t *testing.T) {
	k := jwkKey(t, "", "no-kid", nil)
	stale := jwk.NewSet()
	stale.AddKey(k)
	fresh := jwk.NewSet()
	missing := map[string]time.Time{}

	merged := mergeKeySets(stale, fresh, time.Minute, missing)
	if merged.Len() != 1 {
		t.Fatalf("kid-less key must be retained during the grace window, len=%d", merged.Len())
	}
	if len(missing) != 1 {
		t.Fatalf("absence marker count = %d, want 1 (thumbprint identity)", len(missing))
	}
	var id string
	for id = range missing {
	}
	if !strings.HasPrefix(id, "sha256:") {
		t.Fatalf("absence identity = %q, want an RFC 7638 thumbprint", id)
	}

	// Simulate the grace elapsing.
	missing[id] = time.Now().Add(-2 * time.Minute)
	merged = mergeKeySets(stale, fresh, time.Minute, missing)
	if merged.Len() != 0 {
		t.Fatal("kid-less key must be dropped after the bounded grace")
	}

	// The same key reappearing is served again and clears its marker.
	fresh.AddKey(k)
	merged = mergeKeySets(stale, fresh, time.Minute, missing)
	if merged.Len() != 1 {
		t.Fatal("reappeared kid-less key must be used")
	}
	if _, still := missing[id]; still {
		t.Fatal("absence marker must clear when the kid-less key reappears")
	}
}

// TestMergeKeySetsEmpty verifies empty inputs produce an empty set without
// panicking.
func TestMergeKeySetsEmpty(t *testing.T) {
	merged := mergeKeySets(jwk.NewSet(), jwk.NewSet(), time.Minute, map[string]time.Time{})
	if merged.Len() != 0 {
		t.Errorf("empty merge len = %d, want 0", merged.Len())
	}
}

// TestGetJWKExpiry verifies the key-expiry extractor: a key carrying an exp
// returns (exp, true); a key without one returns (zero, false).
func TestGetJWKExpiry(t *testing.T) {
	// Key with an expiry.
	exp := time.Now().Add(time.Hour)
	k := jwkKey(t, "k1", "", &exp)
	got, ok := getJWKExpiry(k)
	if !ok {
		t.Error("expected exp present")
	}
	if !got.Equal(exp) {
		t.Errorf("exp = %v, want %v", got, exp)
	}

	// Key without an expiry.
	k2 := jwkKey(t, "k2", "", nil)
	if _, ok := getJWKExpiry(k2); ok {
		t.Error("key without exp should report not-present")
	}
}

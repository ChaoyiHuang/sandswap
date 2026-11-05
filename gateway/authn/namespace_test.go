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

package authn

import (
	"context"
	"testing"
)

func rawClaims(v any) *TokenClaims {
	return &TokenClaims{
		Subject: "u",
		Raw:     map[string]any{NamespaceClaim: v},
	}
}

// TestNamespacesFromClaims pins the extraction grammar: multivalued arrays
// (the Keycloak mapper shape), bare strings, order-preserving dedup, and the
// drop rule for malformed entries (never widen a grant through a typo).
func TestNamespacesFromClaims(t *testing.T) {
	if got := NamespacesFromClaims(nil); got != nil {
		t.Errorf("nil claims ⇒ nil, got %v", got)
	}
	noClaim := &TokenClaims{Subject: "u", Raw: map[string]any{"email": "x@y"}}
	if got := NamespacesFromClaims(noClaim); got != nil {
		t.Errorf("absent claim ⇒ nil, got %v", got)
	}

	got := NamespacesFromClaims(rawClaims([]any{"acme", "beta-prod", "acme"}))
	if len(got) != 2 || got[0] != "acme" || got[1] != "beta-prod" {
		t.Errorf("array+dedup: got %v", got)
	}

	if got := NamespacesFromClaims(rawClaims("acme")); len(got) != 1 || got[0] != "acme" {
		t.Errorf("bare string: got %v", got)
	}

	// malformed entries dropped; wildcard kept
	got = NamespacesFromClaims(rawClaims([]any{"acme", "Not-A-Ns", "1bad", "a b", "*", 42, "x/y", ""}))
	if len(got) != 2 || got[0] != "acme" || got[1] != "*" {
		t.Errorf("drop rule: got %v", got)
	}

	// non-string/non-array claim shapes ⇒ nil (never a panic, never a grant)
	for _, v := range []any{42, true, []any{"ok", 7}, map[string]any{"a": "b"}} {
		got := NamespacesFromClaims(rawClaims(v))
		switch v.(type) {
		case []any:
			if len(got) != 1 || got[0] != "ok" { // valid strings survive inside a mixed array
				t.Errorf("mixed array: got %v", got)
			}
		default:
			if got != nil {
				t.Errorf("shape %T: expected nil, got %v", v, got)
			}
		}
	}
}

// TestNamespaceScopeFromContext pins the three resolution shapes:
// passthrough ⇒ fleet, authenticated-without-claim ⇒ empty (deny),
// claims ⇒ exactly the set.
func TestNamespaceScopeFromContext(t *testing.T) {
	// passthrough — no claims value in the context at all
	s := NamespaceScopeFromContext(context.Background())
	if !s.Fleet || s.Allows("anything-at-all") != true {
		t.Errorf("passthrough must resolve as fleet, got %+v", s)
	}

	// authenticated, no sandswap_ns claim — deny everywhere
	s = NamespaceScopeFromContext(WithTokenClaims(context.Background(), &TokenClaims{Subject: "u"}))
	if s.Fleet || len(s.Names) != 0 || s.Allows("default") {
		t.Errorf("empty claim must deny, got %+v", s)
	}

	// explicit set
	s = NamespaceScopeFromContext(WithTokenClaims(context.Background(), rawClaims([]any{"acme", "beta"})))
	if s.Fleet || !s.Allows("acme") || !s.Allows("beta") || s.Allows("default") || s.Allows("acm") {
		t.Errorf("explicit set wrong: %+v", s)
	}

	// wildcard ⇒ fleet (and Allows any ns)
	s = NamespaceScopeFromContext(WithTokenClaims(context.Background(), rawClaims([]any{"*"})))
	if !s.Fleet || !s.Allows("whatever") || len(s.Names) != 0 {
		t.Errorf("wildcard must be fleet-only, got %+v", s)
	}

	// wildcard plus explicit ⇒ fleet (the names are redundant but harmless)
	s = NamespaceScopeFromContext(WithTokenClaims(context.Background(), rawClaims([]any{"acme", "*"})))
	if !s.Fleet {
		t.Errorf("wildcard+explicit must be fleet, got %+v", s)
	}
}

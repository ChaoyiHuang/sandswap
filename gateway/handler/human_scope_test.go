// Copyright 2026 Chaoyi Huang. All rights reserved.
//
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE file at the root of this repository.

package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"gateway/authn"
)

func requestWithScopes(path string, scopes ...string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, path, nil)
	ctx := authn.WithTokenClaims(context.Background(), &authn.TokenClaims{Scopes: scopes})
	return r.WithContext(ctx)
}

func TestRequireOpsScope(t *testing.T) {
	human := requestWithScopes("/", authn.ScopeHuman)
	rec := httptest.NewRecorder()
	if requireOpsScope(rec, human) {
		t.Fatal("human-only token passed the ops gate")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("human-only status = %d, want %d", rec.Code, http.StatusForbidden)
	}

	for _, scope := range []string{authn.ScopeOps, authn.ScopeAdmin} {
		req := requestWithScopes("/", scope)
		rec = httptest.NewRecorder()
		if !requireOpsScope(rec, req) {
			t.Fatalf("%s token was refused by the ops gate", scope)
		}
	}
}

// Regression: even if a path reaches releaseOwnership by a route the mux
// misclassified, the handler itself must refuse a human-only caller before it
// touches ownership state.
func TestReleaseOwnershipRequiresOps(t *testing.T) {
	h := &HumanHandler{}

	rec := httptest.NewRecorder()
	h.releaseOwnership(rec, requestWithScopes("/human/ownership/release/sandfs-x", authn.ScopeHuman), "sandfs-x")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("human-only release status = %d, want %d", rec.Code, http.StatusForbidden)
	}

	rec = httptest.NewRecorder()
	h.releaseOwnership(rec, requestWithScopes("/human/ownership/release/sandfs-x", authn.ScopeOps), "sandfs-x")
	if rec.Code != http.StatusOK {
		t.Fatalf("ops release status = %d, want %d", rec.Code, http.StatusOK)
	}
}

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

package app

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"gateway/authn"
	gwconfig "gateway/config"
)

// scopeStub is the authnMiddleware stand-in: it stamps the request with
// exactly the scopes the test names, so the mux's routing + RequireScope
// wiring is what is under test (the real middleware only decides WHICH
// scopes a credential carries).
func scopeStub(scopes ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := &authn.TokenClaims{
				Subject: "test",
				Scopes:  scopes,
				Raw:     map[string]any{},
			}
			next.ServeHTTP(w, r.WithContext(authn.WithTokenClaims(r.Context(), claims)))
		})
	}
}

// The fleet-wide switches (maintenance, rotation) must NOT be reachable with
// a tenant credential. Tenant OIDC tokens carry exactly sandswap:human (the
// shipped realm's tenant role), so registering these paths under the /human/
// catch-all let any tenant 503 all agent traffic fleet-wide (maintenance) or
// close a live seed-rotation window mid-flight (rotation) — the exact fleet
// wedge the switches exist to prevent, aimed the other way.
func TestFleetSwitchesRequireOpsScope(t *testing.T) {
	sink := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	cases := []struct {
		name   string
		scopes []string
		method string
		path   string
		want   int
	}{
		{"tenant cannot flip maintenance", []string{authn.ScopeHuman}, http.MethodPost, "/human/maintenance", http.StatusForbidden},
		{"tenant cannot flip rotation", []string{authn.ScopeHuman}, http.MethodPost, "/human/rotation", http.StatusForbidden},
		{"tenant cannot read maintenance state", []string{authn.ScopeHuman}, http.MethodGet, "/human/maintenance", http.StatusForbidden},
		{"ops can flip maintenance", []string{authn.ScopeOps}, http.MethodPost, "/human/maintenance", http.StatusOK},
		{"ops can flip rotation", []string{authn.ScopeOps}, http.MethodPost, "/human/rotation", http.StatusOK},
		{"human scope still reaches sandfs CRUD", []string{authn.ScopeHuman}, http.MethodGet, "/human/sandfs", http.StatusOK},
		// The template store is cluster-level. Namespace users may LIST the
		// ops-provided templates (and create sandfs from them); template
		// CREATION/mutation (pull/push/delete/save-as-template) is ops/admin.
		{"tenant can list templates", []string{authn.ScopeHuman}, http.MethodGet, "/human/templates", http.StatusOK},
		{"tenant cannot pull a template ref", []string{authn.ScopeHuman}, http.MethodPost, "/human/templates/app:v1", http.StatusForbidden},
		{"tenant cannot delete a template ref", []string{authn.ScopeHuman}, http.MethodDelete, "/human/templates/app:v1", http.StatusForbidden},
		{"ops can list templates", []string{authn.ScopeOps}, http.MethodGet, "/human/templates", http.StatusOK},
		{"ops can pull a template ref", []string{authn.ScopeOps}, http.MethodPost, "/human/templates/app:v1", http.StatusOK},
		{"admin scope still reaches agent minting", []string{authn.ScopeAdmin}, http.MethodPost, "/human/agent", http.StatusOK},
		{"ops scope can mint agents too", []string{authn.ScopeOps}, http.MethodPost, "/human/agent", http.StatusOK},
		{"tenant cannot mint agents", []string{authn.ScopeHuman}, http.MethodPost, "/human/agent", http.StatusForbidden},
		{"ops scope still reaches ownership reclamation", []string{authn.ScopeOps}, http.MethodPost, "/human/ownership/reap-stuck", http.StatusOK},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mux := http.NewServeMux()
			registerHumanRoutes(mux, &gwconfig.GatewayConfig{}, sink, scopeStub(tc.scopes...))
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, nil))
			if rec.Code != tc.want {
				t.Fatalf("%s %s with scopes %v = %d, want %d (body: %s)",
					tc.method, tc.path, tc.scopes, rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}

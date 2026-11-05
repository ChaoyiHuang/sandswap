// Copyright 2026 Chaoyi Huang. All rights reserved.
//
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE file at the root of this repository.

package app

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Regression: a percent-encoded path must never reach the human mux. The
// mux matches escaped paths while the handler dispatches on the decoded path;
// an encoded slash can otherwise fall from an ops-only route to the human
// catch-all and execute the ops handler.
func TestGuardHumanPathRejectsEncodedPaths(t *testing.T) {
	called := false
	handler := guardHumanPath(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	for _, target := range []string{
		"/human/ownership%2Frelease/sandfs-x",
		"/human/ownership%2frelease/sandfs-x",
		"/human/templates%2Ffoo_v1",
		"/human/agent%2Fagent-x",
	} {
		called = false
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, target, nil)
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s: status = %d, want %d", target, rec.Code, http.StatusNotFound)
		}
		if called {
			t.Errorf("%s: encoded path reached the mux/handler", target)
		}
	}

	called = false
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/human/ownership/release/sandfs-x", nil)
	handler.ServeHTTP(rec, req)
	if !called {
		t.Fatal("plain path did not reach the mux/handler")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("plain path status = %d, want %d", rec.Code, http.StatusOK)
	}
}

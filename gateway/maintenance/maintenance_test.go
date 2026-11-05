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

package maintenance

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The switch must gate agent traffic, keep liveness reachable, and be
// reversible at runtime — that reversibility is the whole point (no gateway
// restart for a rotation window).
func TestSwitchGatesAgentTrafficOnly(t *testing.T) {
	var sw Switch
	var served []string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		served = append(served, r.URL.Path)
		w.WriteHeader(http.StatusOK)
	})
	h := sw.Middleware(next)

	do := func(path string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, nil))
		return rec
	}

	if rec := do("/agent/execute"); rec.Code != http.StatusOK {
		t.Fatalf("serving state must pass requests through, got %d", rec.Code)
	}

	sw.Set(true, "volume seed rotation")
	if !sw.On() {
		t.Fatal("switch must report on")
	}
	rec := do("/agent/execute")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("gated request must be 503, got %d", rec.Code)
	}
	if got := rec.Header().Get("Retry-After"); got != "30" {
		t.Errorf("Retry-After = %q, want 30", got)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("refusal body must be JSON: %v", err)
	}
	if body["error_code"] != "MAINTENANCE" {
		t.Errorf("error_code = %q, want MAINTENANCE", body["error_code"])
	}

	// Liveness and readiness must keep answering: an orchestrator that sees a
	// 503 on /health would restart the gateway and defeat the whole point.
	for _, p := range []string{"/health", "/ready", "/stats", "/metrics"} {
		if rec := do(p); rec.Code != http.StatusOK {
			t.Errorf("%s must stay reachable during maintenance, got %d", p, rec.Code)
		}
	}

	sw.Set(false, "")
	if rec := do("/agent/file"); rec.Code != http.StatusOK {
		t.Errorf("cleared switch must resume service, got %d", rec.Code)
	}
}

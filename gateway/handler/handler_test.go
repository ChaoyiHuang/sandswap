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
//
// Internal (package handler) tests for the small wiring accessors and error
// sentinels that the external-package tests cannot reach (unexported fields).

package handler

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"gateway/lease"
	"gateway/pool"
)

func TestUpdateMaxBackgroundLeaseSec(t *testing.T) {
	h := &ExecuteHandler{}
	h.maxBackgroundLeaseSec.Store(1234)

	h.UpdateMaxBackgroundLeaseSec(0)
	if got := h.maxBackgroundLeaseSec.Load(); got != DefaultMaxBackgroundLeaseSec {
		t.Errorf("sec<=0 must fall back to default: got %d, want %d", got, DefaultMaxBackgroundLeaseSec)
	}
	h.UpdateMaxBackgroundLeaseSec(-5)
	if got := h.maxBackgroundLeaseSec.Load(); got != DefaultMaxBackgroundLeaseSec {
		t.Errorf("negative sec must fall back to default: got %d", got)
	}
	h.UpdateMaxBackgroundLeaseSec(90)
	if got := h.maxBackgroundLeaseSec.Load(); got != 90 {
		t.Errorf("UpdateMaxBackgroundLeaseSec(90) stored %d, want 90", got)
	}
}

func TestExecuteHandlerSetShedController(t *testing.T) {
	h := &ExecuteHandler{}
	if h.shed != nil {
		t.Fatal("shed should default to nil (disabled)")
	}
	sc := lease.NewShedController(&lease.ShedConfig{}, nil, nil, nil, nil)
	h.SetShedController(sc)
	if h.shed != sc {
		t.Error("SetShedController did not wire the controller")
	}
}

func TestFileHandlerSetShedController(t *testing.T) {
	h := &FileHandler{}
	sc := lease.NewShedController(&lease.ShedConfig{}, nil, nil, nil, nil)
	h.SetShedController(sc)
	if h.shed != sc {
		t.Error("FileHandler.SetShedController did not wire the controller")
	}
}

func TestResilienceErrorMethod(t *testing.T) {
	e := &resilienceError{code: http.StatusServiceUnavailable, msg: "busy", errorCode: "SANDBOX_CLEANING", retryAfterMs: 250}
	if e.Error() != "busy" {
		t.Errorf("Error() = %q, want busy", e.Error())
	}
	msg, code, retryable, afterMs, shed, ok := AsResilienceError(e)
	if !ok || msg != "busy" || code != "SANDBOX_CLEANING" || !retryable || afterMs != 250 || shed {
		t.Errorf("AsResilienceError = (%q,%q,%v,%d,%v,%v)", msg, code, retryable, afterMs, shed, ok)
	}

	shedErr := &resilienceError{msg: "shed", shedRebalance: true}
	_, _, _, _, shedFlag, ok := AsResilienceError(shedErr)
	if !ok || !shedFlag {
		t.Errorf("shedRebalance flag lost: (%v, %v)", shedFlag, ok)
	}
}

// TestStatsHandlerWiring verifies NewStatsHandler builds a /stats-only
// HumanHandler and SetStatsClient stores the etcd client + gateway identity;
// with a nil etcd client GET /stats serves the local single-node report.
func TestStatsHandlerWiring(t *testing.T) {
	pm := pool.NewManager(nil, slog.New(slog.DiscardHandler))
	pm.AddNode("node-1")
	pm.UpdateNodeCapacity("node-1", []pool.SpecCapacity{{SpecID: "medium", Clean: 2, Total: 2}})

	h := NewStatsHandler(pm, slog.New(slog.DiscardHandler))
	if h.etcdClient != nil || h.gatewayID != "" {
		t.Fatal("NewStatsHandler must start unwired")
	}
	h.SetStatsClient(nil, "gw-stats")
	if h.gatewayID != "gw-stats" {
		t.Errorf("gatewayID = %q, want gw-stats", h.gatewayID)
	}

	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/stats", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("GET /stats = %d: %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	for _, want := range []string{`"gateway_id":"gw-stats"`, `"healthy":true`, `"clean_vms":2`} {
		if !contains(body, want) {
			t.Errorf("/stats body missing %s: %s", want, body)
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

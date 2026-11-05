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

	gwconfig "gateway/config"
	"gateway/identity"
)

// TestIdentityLoadOptions verifies the config→EtcdOption translation: base
// options are always present (TLS material, lazy-load, hot-only); loader knobs
// are appended only when set to positive values.
func TestIdentityLoadOptions(t *testing.T) {
	cfg := &gwconfig.GatewayConfig{}
	opts := identityLoadOptions(cfg)
	if len(opts) != 3 {
		t.Fatalf("default opts = %d, want 3 (tls/lazy/hot)", len(opts))
	}

	cfg.IdentityLoad.LoadPageSize = 500
	cfg.IdentityLoad.LoadWorkers = 8
	cfg.IdentityLoad.FullLoadTimeoutSec = 45
	cfg.EtcdCA = "/ca.pem"
	cfg.EtcdCert = "/cert.pem"
	cfg.EtcdKey = "/key.pem"
	cfg.IdentityLoad.LazyLoad = false
	cfg.IdentityLoad.HotOnly = true
	opts = identityLoadOptions(cfg)
	if len(opts) != 6 {
		t.Fatalf("full opts = %d, want 6", len(opts))
	}

	cfg.IdentityLoad.LoadPageSize = 0
	cfg.IdentityLoad.LoadWorkers = -1
	cfg.IdentityLoad.FullLoadTimeoutSec = 0
	if opts := identityLoadOptions(cfg); len(opts) != 3 {
		t.Errorf("non-positive loader knobs must not add options, got %d", len(opts))
	}
}

// TestGateUntilReadyNotReady verifies that while the identity snapshot is loading
// (Ready()==false), business requests get a fast 503 with Retry-After while
// liveness/readiness probes pass through untouched.
func TestGateUntilReadyNotReady(t *testing.T) {
	store := &identity.EtcdStore{}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})
	h := gateUntilReady(store, next)

	cases := []struct {
		path string
		code int
	}{
		{"/agent/execute", http.StatusServiceUnavailable},
		{"/human/sandfs", http.StatusServiceUnavailable},
		{"/health", http.StatusTeapot},
		{"/ready", http.StatusTeapot},
	}
	for _, c := range cases {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, c.path, nil))
		if w.Code != c.code {
			t.Errorf("GET %s = %d, want %d", c.path, w.Code, c.code)
		}
	}

	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/agent/execute", nil))
	if got := w.Header().Get("Retry-After"); got != "2" {
		t.Errorf("Retry-After = %q, want 2", got)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}

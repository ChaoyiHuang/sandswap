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

package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestProbeListenersCountsFailures pins the health-all gate semantics: an
// HTTP error status is a failure (not just a printed line), a transport
// error is a failure, and a healthy stack reports zero.
func TestProbeListenersCountsFailures(t *testing.T) {
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(ok.Close)
	unready := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A warming-up gateway: /health and /ready both answer 503.
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(unready.Close)

	g := Defaults()
	g.GatewayURL, g.HumanURL = ok.URL, unready.URL
	var out bytes.Buffer
	failed, total := probeListeners(g, &out)
	if total != 4 {
		t.Fatalf("total = %d, want 4", total)
	}
	if failed != 2 {
		t.Fatalf("failures = %d, want 2 (both human probes); output:\n%s", failed, out.String())
	}
	if n := strings.Count(out.String(), "FAIL"); n != 2 {
		t.Fatalf("FAIL lines = %d, want 2:\n%s", n, out.String())
	}

	// Unreachable listeners: every probe fails via the transport-error leg.
	g.GatewayURL, g.HumanURL = "http://127.0.0.1:1", "http://127.0.0.1:1"
	failed, _ = probeListeners(g, &out)
	if failed != 4 {
		t.Fatalf("failures = %d, want 4 against unreachable listeners", failed)
	}

	// A fully healthy stack: zero failures, no FAIL lines.
	g.GatewayURL, g.HumanURL = ok.URL, ok.URL
	out.Reset()
	failed, _ = probeListeners(g, &out)
	if failed != 0 {
		t.Fatalf("failures = %d, want 0; output:\n%s", failed, out.String())
	}
	if strings.Contains(out.String(), "FAIL") {
		t.Fatalf("healthy stack printed FAIL lines:\n%s", out.String())
	}
}

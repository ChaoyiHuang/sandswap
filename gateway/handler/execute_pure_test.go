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
// Internal (package handler) tests for the pure execution-policy and
// owner-redirect logic. These need access to unexported helpers
// (resolveTimeoutMs, redirectLocation, writeOwnerRedirect) and the handler's
// atomic timeout fields, hence package handler rather than handler_test.

package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestUpdateTimeouts verifies the hot-reload policy: 0/negative values are
// ignored (keep current), max < default is rejected, valid pairs are applied.
func TestUpdateTimeouts(t *testing.T) {
	h := &ExecuteHandler{}
	h.defaultTimeoutMs.Store(30000)
	h.maxTimeoutMs.Store(300000)

	h.UpdateTimeouts(0, 0) // ignored -> keep 30s/300s
	if got := h.defaultTimeoutMs.Load(); got != 30000 {
		t.Errorf("default after (0,0) = %d, want 30000", got)
	}
	if got := h.maxTimeoutMs.Load(); got != 300000 {
		t.Errorf("max after (0,0) = %d, want 300000", got)
	}

	h.UpdateTimeouts(120, 60) // max < default -> reject max, keep old
	if got := h.defaultTimeoutMs.Load(); got != 120000 {
		t.Errorf("default after (120,60) = %d, want 120000", got)
	}
	if got := h.maxTimeoutMs.Load(); got != 300000 {
		t.Errorf("max after (120,60) should keep 300000, got %d", got)
	}

	h.UpdateTimeouts(60, 120) // valid
	if got := h.defaultTimeoutMs.Load(); got != 60000 {
		t.Errorf("default after (60,120) = %d, want 60000", got)
	}
	if got := h.maxTimeoutMs.Load(); got != 120000 {
		t.Errorf("max after (60,120) = %d, want 120000", got)
	}
}

// TestResolveTimeoutMs verifies the edge timeout policy:
//   - 0 / negative (agent omitted) -> default
//   - above max -> clamped to max
//   - in range -> sandfs_seconds * 1000
//   - 7+ digit seconds: the unbounded agent-supplied value must be multiplied
//
// in int64 BEFORE any narrowing. The uint32 wrap turned
//
//	4 294 968 s into 704 ms — sailing past the clamp and killing a
//	"max-length" exec at 0.7 s — and 536 870 912 s wrapped to exactly 0,
//	the documented "warden default" sentinel. Both must clamp to max.
func TestResolveTimeoutMs(t *testing.T) {
	h := &ExecuteHandler{}
	h.defaultTimeoutMs.Store(30000)
	h.maxTimeoutMs.Store(300000)

	cases := []struct {
		in   int
		want uint32
	}{
		{0, 30000},    // omitted -> default
		{-5, 30000},   // negative -> default
		{5, 5000},     // in range
		{30, 30000},   // exactly default
		{600, 300000}, // above max -> clamp to max
		{100000, 300000},
		// The uint32 wrap family (seconds × 1000 overflows 2^32):
		{4294967, 300000},   // 4 294 967 000 ms, just over MaxUint32
		{4294968, 300000},   // the recorded wrap: uint32 math -> 704 ms
		{536870912, 300000}, // uint32 math -> exactly 0 ("warden default")
	}
	for _, c := range cases {
		if got := h.ResolveTimeoutMs(c.in); got != c.want {
			t.Errorf("ResolveTimeoutMs(%d) = %d, want %d", c.in, got, c.want)
		}
	}
}

// TestExecHTTPError verifies the HTTP-status-bearing error used throughout the
// execute/file handlers.
func TestExecHTTPError(t *testing.T) {
	e := &execHTTPError{code: http.StatusBadRequest, msg: "bad input"}
	if e.Error() != "bad input" {
		t.Errorf("Error() = %q, want %q", e.Error(), "bad input")
	}
	if e.code != http.StatusBadRequest {
		t.Errorf("code = %d, want 400", e.code)
	}
}

// TestOwnerRedirectErrorAndIsOwnerRedirect verifies the 307-redirect error
// sentinel and its type-assertion helper.
func TestOwnerRedirectErrorAndIsOwnerRedirect(t *testing.T) {
	e := &OwnerRedirectError{OwnerURL: "https://gw-2:3000"}
	if e.Error() != "redirect to owner gateway: https://gw-2:3000" {
		t.Errorf("Error() = %q", e.Error())
	}
	url, ok := IsOwnerRedirect(e)
	if !ok || url != "https://gw-2:3000" {
		t.Errorf("IsOwnerRedirect(owner) = (%q, %v), want (https://gw-2:3000, true)", url, ok)
	}
	// A non-owner error is not a redirect.
	if _, ok := IsOwnerRedirect(&execHTTPError{code: 500, msg: "x"}); ok {
		t.Error("IsOwnerRedirect(execHTTPError) should be false")
	}
	// nil is not a redirect.
	if _, ok := IsOwnerRedirect(nil); ok {
		t.Error("IsOwnerRedirect(nil) should be false")
	}
}

// TestRedirectLocation verifies the 307 Location builder: normal requests get
// owner base URL + original path+query; a request already carrying the
// anti-loop header is NOT redirected (empty Location) to prevent owner<->non-owner
// ping-pong.
func TestRedirectLocation(t *testing.T) {
	// Normal request -> owner base + full request URI (path + query).
	r := httptest.NewRequest("POST", "/agent/execute?sandfs_id=abc", nil)
	if loc := redirectLocation("https://gw-2:3000", r); loc != "https://gw-2:3000/agent/execute?sandfs_id=abc" {
		t.Errorf("redirectLocation = %q", loc)
	}

	// Anti-loop: a request carrying X-Sandswap-Redirected: 1 is never redirected.
	r2 := httptest.NewRequest("POST", "/agent/execute", nil)
	r2.Header.Set(RedirectHeader, "1")
	if loc := redirectLocation("https://gw-2:3000", r2); loc != "" {
		t.Errorf("anti-loop: redirectLocation = %q, want \"\"", loc)
	}

	// Empty owner URL -> just the request URI (defensive).
	r3 := httptest.NewRequest("GET", "/health", nil)
	if loc := redirectLocation("", r3); loc != "/health" {
		t.Errorf("empty owner: redirectLocation = %q", loc)
	}
}

// TestWriteOwnerRedirect verifies the actual 307 write: sets the anti-loop
// marker header, writes a 307 with the Location, and reports success. With the
// anti-loop header present it does nothing and reports false.
func TestWriteOwnerRedirect(t *testing.T) {
	// Normal -> 307 written, marker set.
	r := httptest.NewRequest("POST", "/agent/execute", nil)
	w := httptest.NewRecorder()
	if ok := writeOwnerRedirect(w, r, "https://gw-2:3000"); !ok {
		t.Fatal("expected redirect written")
	}
	if w.Code != http.StatusTemporaryRedirect {
		t.Errorf("status = %d, want 307", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != "https://gw-2:3000/agent/execute" {
		t.Errorf("Location = %q", loc)
	}
	if w.Header().Get(RedirectHeader) != "1" {
		t.Error("anti-loop marker header should be set on the 307 response")
	}

	// Anti-loop -> no redirect.
	r2 := httptest.NewRequest("POST", "/agent/execute", nil)
	r2.Header.Set(RedirectHeader, "1")
	w2 := httptest.NewRecorder()
	if ok := writeOwnerRedirect(w2, r2, "https://gw-2:3000"); ok {
		t.Error("expected no redirect for anti-loop request")
	}
	if w2.Code == http.StatusTemporaryRedirect {
		t.Error("anti-loop request must not produce a 307")
	}
}

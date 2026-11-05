// Copyright 2026 Chaoyi Huang. All rights reserved.
//
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE file at the root of this repository.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, this software will be governed by
// the Apache License, Version 2.0.

package handler

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func newOpsGate(t *testing.T, content string) (*OpsTokenGate, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ops.token")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	g, err := NewOpsTokenGate(path, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("NewOpsTokenGate(%q): %v", content, err)
	}
	return g, path
}

func gateDo(g *OpsTokenGate, auth string) *httptest.ResponseRecorder {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ops-data"))
	})
	req := httptest.NewRequest(http.MethodGet, "/stats", nil)
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	rec := httptest.NewRecorder()
	g.Wrap(inner).ServeHTTP(rec, req)
	return rec
}

// Construction fail-fast: a configured-but-broken credential file must
// refuse to boot, not serve open and not crash mid-serve.
func TestOpsTokenGateConstructionValidation(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	if _, err := NewOpsTokenGate(filepath.Join(t.TempDir(), "absent"), logger); err == nil {
		t.Fatal("missing file accepted")
	}
	for name, content := range map[string]string{"": "", "whitespace": "  \n \t "} {
		p := filepath.Join(t.TempDir(), "t")
		os.WriteFile(p, []byte(content), 0o600)
		if _, err := NewOpsTokenGate(p, logger); err == nil {
			t.Fatalf("empty %q accepted", name)
		}
	}
	p := filepath.Join(t.TempDir(), "big")
	os.WriteFile(p, make([]byte, OpsTokenMaxBytes+1), 0o600)
	if _, err := NewOpsTokenGate(p, logger); err == nil {
		t.Fatal("oversized file accepted")
	}
}

// The request matrix: no header, wrong scheme, wrong token → 401; the right
// token passes through to the handler.
func TestOpsTokenGateRequestMatrix(t *testing.T) {
	g, _ := newOpsGate(t, "  opswire-secret \n")
	cases := []struct {
		name string
		auth string
		want int
	}{
		{"no header", "", http.StatusUnauthorized},
		{"not bearer", "Basic opswire-secret", http.StatusUnauthorized},
		{"wrong token", "Bearer nope", http.StatusUnauthorized},
		{"right token (trimmed at load)", "Bearer opswire-secret", http.StatusOK},
		{"empty guess", "Bearer ", http.StatusUnauthorized},
	}
	for _, tc := range cases {
		if got := gateDo(g, tc.auth).Code; got != tc.want {
			t.Errorf("%s: code = %d, want %d", tc.name, got, tc.want)
		}
	}
}

// Rotation by file write: the mtime change re-reads the token. The new token
// serves, the old one stops serving — no restart involved.
func TestOpsTokenGateHotReload(t *testing.T) {
	g, path := newOpsGate(t, "old-token")
	if got := gateDo(g, "Bearer old-token").Code; got != http.StatusOK {
		t.Fatalf("old token before rotation: %d", got)
	}
	// mtime granularity: force a change the stat check can observe.
	time.Sleep(1100 * time.Millisecond)
	if err := os.WriteFile(path, []byte("new-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := gateDo(g, "Bearer new-token").Code; got != http.StatusOK {
		t.Fatalf("new token after rotation: %d", got)
	}
	if got := gateDo(g, "Bearer old-token").Code; got != http.StatusUnauthorized {
		t.Fatalf("old token after rotation: %d, want 401", got)
	}
}

// A rotation that lands the file in a BROKEN state (emptied) must fail
// CLOSED: the previous token is not installed-over with nothing, and once a
// valid file returns the gate reopens — the closed window is exactly the
// broken-file window.
func TestOpsTokenGateFailClosedOnBrokenRotation(t *testing.T) {
	g, path := newOpsGate(t, "good-token")
	if got := gateDo(g, "Bearer good-token").Code; got != http.StatusOK {
		t.Fatalf("pre-rotation: %d", got)
	}
	time.Sleep(1100 * time.Millisecond)
	os.WriteFile(path, []byte("   "), 0o600)
	if got := gateDo(g, "Bearer good-token").Code; got != http.StatusUnauthorized {
		t.Fatalf("broken rotation must fail closed, got %d", got)
	}
	time.Sleep(1100 * time.Millisecond)
	os.WriteFile(path, []byte("back-token"), 0o600)
	if got := gateDo(g, "Bearer back-token").Code; got != http.StatusOK {
		t.Fatalf("recovered rotation must reopen, got %d", got)
	}
}

// The disabled (empty-flag) handler is a 404, not a redirect to open data.
func TestOpsEndpointsDisabled(t *testing.T) {
	rec := httptest.NewRecorder()
	OpsEndpointsDisabled(rec, httptest.NewRequest(http.MethodGet, "/stats", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("code = %d, want 404", rec.Code)
	}
}

// A revoked (empty) token must reject the EMPTY bearer value — "Bearer " with
// a trailing space is preserved on HTTP/2, and ConstantTimeCompare("", "")
// would otherwise return 1 and open the gate.
func TestOpsTokenGateEmptyBearerNeverMatchesEmptyToken(t *testing.T) {
	g, path := newOpsGate(t, "good-token")
	time.Sleep(1100 * time.Millisecond)
	if err := os.WriteFile(path, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := gateDo(g, "Bearer ").Code; got != http.StatusUnauthorized {
		t.Fatalf("empty Bearer against a revoked token: code = %d, want 401", got)
	}
	if got := gateDo(g, "Bearer good-token").Code; got != http.StatusUnauthorized {
		t.Fatalf("withdrawn token served after revoke: code = %d, want 401", got)
	}
}

// Deleting the token file is a revocation, not a reason to keep serving the
// cached token.
func TestOpsTokenGateFileRemovedRevokes(t *testing.T) {
	g, path := newOpsGate(t, "good-token")
	if got := gateDo(g, "Bearer good-token").Code; got != http.StatusOK {
		t.Fatalf("pre-removal: %d", got)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if got := gateDo(g, "Bearer good-token").Code; got != http.StatusUnauthorized {
		t.Fatalf("token served after the file was removed: code = %d, want 401", got)
	}
}

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
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseExecMetrics(t *testing.T) {
	// Shape matches the MCP execute tool result JSON produced by the gateway
	// dispatch layer (gateway/mcp/dispatch.go handleExecute).
	text := `{"stdout":"hi\n","stderr":"","exit_code":0,"status":"done",` +
		`"exec_duration_ns":1500,"sandlot_duration_ns":250000,"gateway_duration_ns":300000}`
	s, ok := parseExecMetrics(text)
	if !ok {
		t.Fatal("parseExecMetrics returned ok=false for valid JSON")
	}
	if s.exit != 0 {
		t.Errorf("exit = %d, want 0", s.exit)
	}
	if math.Abs(s.execMs-0.0015) > 1e-9 {
		t.Errorf("execMs = %v, want 0.0015", s.execMs)
	}
	if math.Abs(s.sandlotMs-0.250) > 1e-9 {
		t.Errorf("sandlotMs = %v, want 0.250", s.sandlotMs)
	}
	if math.Abs(s.gatewayMs-0.300) > 1e-9 {
		t.Errorf("gatewayMs = %v, want 0.300", s.gatewayMs)
	}

	if _, ok := parseExecMetrics("not json"); ok {
		t.Error("parseExecMetrics accepted invalid JSON")
	}
	// Non-execute result (e.g. a file op) must not parse as metrics.
	if _, ok := parseExecMetrics(`{"ok":true,"size":4}`); ok {
		t.Error("parseExecMetrics accepted a non-execute result")
	}
}

func TestComputeStats(t *testing.T) {
	vals := []float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	st := computeStats(vals)
	if st.n != 10 || st.min != 1 || st.max != 10 {
		t.Errorf("n/min/max = %d/%v/%v, want 10/1/10", st.n, st.min, st.max)
	}
	if st.p50 != 6 { // sorted[10/2]=sorted[5]=6 (median-of-sorted indexing)
		t.Errorf("p50 = %v, want 6", st.p50)
	}
	if st.p95 != 10 { // sorted[9]=10 (n*95/100=9 clamped to n-1)
		t.Errorf("p95 = %v, want 10", st.p95)
	}
	if got := computeStats(nil); got.n != 0 {
		t.Errorf("empty stats n = %d, want 0", got.n)
	}
}

// TestBenchModeDispatch pins the E5 contract: EVERY non-empty
// SANDSWAP_BENCH_MODE — including a typo — is dispatched to runBenchmark,
// which names an unknown mode instead of the process silently falling
// through to the interactive agent loop.
func TestBenchModeDispatch(t *testing.T) {
	t.Setenv("SANDSWAP_API_KEY_A", "")
	t.Setenv("SANDSWAP_API_KEY_B", "")

	for _, mode := range []string{"htp", "MCP", "http ", "mcp\n", " "} {
		t.Setenv("SANDSWAP_BENCH_MODE", mode)
		got := benchMode()
		if got != mode {
			t.Fatalf("benchMode() = %q, want %q", got, mode)
		}
		err := runBenchmark(context.Background(), got)
		if err == nil || !strings.Contains(err.Error(), "unknown benchmark mode") {
			t.Errorf("runBenchmark(%q) = %v, want an 'unknown benchmark mode' error", got, err)
		}
	}

	// The empty value means "not in benchmark mode" (the agent loop).
	t.Setenv("SANDSWAP_BENCH_MODE", "")
	if got := benchMode(); got != "" {
		t.Errorf("benchMode() = %q, want empty for the agent loop", got)
	}

	// The valid modes must route into their benchmark implementations (both
	// fail fast on the missing API keys before any network access).
	for _, mode := range []string{"http", "mcp"} {
		err := runBenchmark(context.Background(), mode)
		if err == nil || !strings.Contains(err.Error(), "requires SANDSWAP_API_KEY_A") {
			t.Errorf("runBenchmark(%q) = %v, want the missing-keys error from its benchmark mode", mode, err)
		}
	}
}

// selfSignedCAPEM returns a valid self-signed CA certificate in PEM form for
// the CA-loading tests.
func selfSignedCAPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "sandswap-bench-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// TestNewHTTPBenchClientCA pins the E6 contract: a configured SANDSWAP_CA_CERT
// that cannot be read or parsed must surface an error, never silently fall
// back to the system trust store.
func TestNewHTTPBenchClientCA(t *testing.T) {
	t.Run("unset", func(t *testing.T) {
		t.Setenv("SANDSWAP_CA_CERT", "")
		client, err := newHTTPBenchClient()
		if err != nil {
			t.Fatalf("newHTTPBenchClient() error = %v, want nil", err)
		}
		tr := client.Transport.(*http.Transport)
		if tr.TLSClientConfig != nil {
			t.Errorf("TLSClientConfig = %+v, want nil without SANDSWAP_CA_CERT", tr.TLSClientConfig)
		}
	})

	t.Run("missing file", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "does-not-exist.pem")
		t.Setenv("SANDSWAP_CA_CERT", missing)
		if _, err := newHTTPBenchClient(); err == nil || !strings.Contains(err.Error(), "read CA cert") {
			t.Fatalf("newHTTPBenchClient() error = %v, want a 'read CA cert' error", err)
		}
	})

	t.Run("invalid PEM", func(t *testing.T) {
		bad := filepath.Join(t.TempDir(), "bad.pem")
		if err := os.WriteFile(bad, []byte("not a certificate"), 0o600); err != nil {
			t.Fatalf("write bad CA: %v", err)
		}
		t.Setenv("SANDSWAP_CA_CERT", bad)
		if _, err := newHTTPBenchClient(); err == nil || !strings.Contains(err.Error(), "failed to append CA cert") {
			t.Fatalf("newHTTPBenchClient() error = %v, want a 'failed to append CA cert' error", err)
		}
	})

	t.Run("valid PEM", func(t *testing.T) {
		good := filepath.Join(t.TempDir(), "ca.pem")
		if err := os.WriteFile(good, selfSignedCAPEM(t), 0o600); err != nil {
			t.Fatalf("write CA: %v", err)
		}
		t.Setenv("SANDSWAP_CA_CERT", good)
		client, err := newHTTPBenchClient()
		if err != nil {
			t.Fatalf("newHTTPBenchClient() error = %v, want nil", err)
		}
		tr := client.Transport.(*http.Transport)
		if tr.TLSClientConfig == nil || tr.TLSClientConfig.RootCAs == nil {
			t.Fatalf("TLSClientConfig.RootCAs not set for a valid CA (config = %+v)", tr.TLSClientConfig)
		}
	})
}

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
// Internal (package identity) tests for etcd store settings/options and the
// cache-routing helpers. These run without an etcd connection.

package identity

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	rpctypes "go.etcd.io/etcd/api/v3/v3rpc/rpctypes"
)

func TestNewEtcdSettingsDefaults(t *testing.T) {
	s := newEtcdSettings(nil)
	if s.tls != nil {
		t.Error("default tls should be nil (plaintext)")
	}
	if s.hotOnly {
		t.Error("default hotOnly should be false")
	}
	if !s.lazyLoad {
		t.Error("default lazyLoad should be true")
	}
	if s.loadPageSize != defaultLoadPageSize {
		t.Errorf("loadPageSize = %d, want %d", s.loadPageSize, defaultLoadPageSize)
	}
	if s.loadWorkers != defaultLoadWorkers {
		t.Errorf("loadWorkers = %d, want %d", s.loadWorkers, defaultLoadWorkers)
	}
	if s.fullLoadTimeout != defaultFullLoadTimeout {
		t.Errorf("fullLoadTimeout = %v, want %v", s.fullLoadTimeout, defaultFullLoadTimeout)
	}
}

func TestEtcdOptions(t *testing.T) {
	tlsCfg := &EtcdTLSConfig{CAFile: "/ca.pem"}
	s := newEtcdSettings([]EtcdOption{
		WithTLS(tlsCfg),
		WithHotOnly(true),
		WithLazyLoad(false),
		WithLoadPageSize(500),
		WithLoadWorkers(4),
		WithFullLoadTimeout(30 * time.Second),
	})
	if s.tls != tlsCfg {
		t.Error("WithTLS did not store the config")
	}
	if !s.hotOnly {
		t.Error("WithHotOnly(true) not applied")
	}
	if s.lazyLoad {
		t.Error("WithLazyLoad(false) not applied")
	}
	if s.loadPageSize != 500 || s.loadWorkers != 4 {
		t.Errorf("loader knobs = (%d, %d), want (500, 4)", s.loadPageSize, s.loadWorkers)
	}
	if s.fullLoadTimeout != 30*time.Second {
		t.Errorf("fullLoadTimeout = %v, want 30s", s.fullLoadTimeout)
	}

	// Invalid values must keep defaults.
	s2 := newEtcdSettings([]EtcdOption{
		WithLoadPageSize(0),
		WithLoadPageSize(-10),
		WithLoadWorkers(0),
		WithFullLoadTimeout(0),
		WithFullLoadTimeout(-time.Second),
	})
	if s2.loadPageSize != defaultLoadPageSize {
		t.Errorf("invalid page size applied: %d", s2.loadPageSize)
	}
	if s2.loadWorkers != defaultLoadWorkers {
		t.Errorf("invalid workers applied: %d", s2.loadWorkers)
	}
	if s2.fullLoadTimeout != defaultFullLoadTimeout {
		t.Errorf("invalid timeout applied: %v", s2.fullLoadTimeout)
	}
}

func TestApplyPutLockedRoutesByPrefix(t *testing.T) {
	s := newTestCacheStore()
	s.mu.Lock()
	defer s.mu.Unlock()

	agentData, _ := marshalAgentForEtcd(&Agent{ID: "agent-1", APIKeyHash: hashAPIKey("k")})
	recData, err := encodeSandfsRecord(&Record{ID: "sf-1", AgentID: "agent-1"})
	if err != nil {
		t.Fatalf("encodeSandfsRecord: %v", err)
	}
	metaData, err := encodeSandfsMeta(&sandfsMetaInfo{Name: "n"})
	if err != nil {
		t.Fatalf("encodeSandfsMeta: %v", err)
	}

	s.applyPutLocked("/p/agent/xyz", agentData)
	s.applyPutLocked("/p/sandfs/sf-1", recData)
	s.applyPutLocked("/p/meta/sandfs/sf-1", metaData)

	if _, ok := s.agents["agent-1"]; !ok {
		t.Error("agent put not routed to agents map")
	}
	if _, ok := s.sandfs["sf-1"]; !ok {
		t.Error("sandfs put not routed to sandfs map")
	}
	// Meta routing: the watch REFRESHES resident cache entries and
	// never INSERTS non-resident ones — otherwise the bounded display cache
	// would grow back into a full meta mirror through the watch stream.
	if _, ok := s.sandfsMeta["sf-1"]; ok {
		t.Error("non-resident meta put must NOT enter the bounded cache")
	}
	s.sandfsMeta["sf-1"] = &sandfsMetaInfo{Name: "stale"}
	s.applyPutLocked("/p/meta/sandfs/sf-1", metaData)
	if m, ok := s.sandfsMeta["sf-1"]; !ok || m.Name != "n" {
		t.Error("resident meta entry not refreshed by the watch put")
	}

	// Corrupt payloads are ignored silently.
	s.applyPutLocked("/p/sandfs/bad", []byte("{not json"))
	s.applyPutLocked("/p/agent/bad", []byte("{not json"))
	s.applyPutLocked("/p/meta/sandfs/bad", []byte("{not json"))
	if _, ok := s.sandfs["bad"]; ok {
		t.Error("corrupt sandfs value was stored")
	}
	if _, ok := s.agentApiKeyToID[hashAPIKey("k")]; !ok {
		t.Error("corrupt agent put clobbered the digest index")
	}

	// Unknown prefixes are ignored.
	s.applyPutLocked("/p/other/k", []byte("{}"))
}

func TestApplyPutLockedHotOnlySkipsMeta(t *testing.T) {
	s := newTestCacheStore()
	s.hotOnly = true
	s.mu.Lock()
	defer s.mu.Unlock()

	metaData, _ := encodeSandfsMeta(&sandfsMetaInfo{Name: "n"})
	s.applyPutLocked("/p/meta/sandfs/sf-1", metaData)
	if len(s.sandfsMeta) != 0 {
		t.Error("hotOnly store must skip meta puts")
	}
	s.applyDeleteLocked("/p/meta/sandfs/sf-1")
}

func TestApplyDeleteLockedUnknownPrefixNoop(t *testing.T) {
	s := newTestCacheStore()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.applyDeleteLocked("/p/other/k")
	if len(s.agents)+len(s.sandfs)+len(s.sandfsMeta) != 0 {
		t.Error("unknown-prefix delete touched the cache")
	}
}

func TestAllowsPackageInstall(t *testing.T) {
	cases := []struct {
		mode string
		want bool
	}{
		{"flat", true},
		{"overlay", false},
		{"", false},
		{"Flat", false},
	}
	for _, c := range cases {
		r := &Record{Mode: c.mode}
		if got := r.AllowsPackageInstall(); got != c.want {
			t.Errorf("AllowsPackageInstall(mode=%q) = %v, want %v", c.mode, got, c.want)
		}
	}
}

// TestEtcdKeyBuilders verifies the etcd key layouts used by the store:
// prefix + "agent/"|"sandfs/"|"meta/sandfs/"|"lock/" + id. These are the
// write-path contract for the identity keys.
func TestEtcdKeyBuilders(t *testing.T) {
	s := &EtcdStore{prefix: "/sandswap/identity/"}
	if got := s.agentKeyFor("deadbeef"); got != "/sandswap/identity/agent/deadbeef" {
		t.Errorf("agentKeyFor = %q", got)
	}
	if got := s.sandfsKeyFor("sandfs-1"); got != "/sandswap/identity/sandfs/sandfs-1" {
		t.Errorf("sandfsKeyFor = %q", got)
	}
	if got := s.sandfsMetaKeyFor("sandfs-1"); got != "/sandswap/identity/meta/sandfs/sandfs-1" {
		t.Errorf("sandfsMetaKeyFor = %q", got)
	}
	if got := s.lockKeyFor("agent-1"); got != "/sandswap/identity/lock/agent-1" {
		t.Errorf("lockKeyFor = %q", got)
	}
}

// TestHashAPIKey verifies the digest helper is deterministic, hex-encoded,
// and 64 chars (SHA-256) long.
func TestHashAPIKey(t *testing.T) {
	h1 := hashAPIKey("sk-sandswap-agent-secret")
	h2 := hashAPIKey("sk-sandswap-agent-secret")
	if h1 != h2 {
		t.Fatalf("hash not deterministic: %q vs %q", h1, h2)
	}
	if len(h1) != 64 {
		t.Errorf("hash length = %d, want 64 (sha256 hex)", len(h1))
	}
	if h1 == "sk-sandswap-agent-secret" {
		t.Error("hash must not be the identity function")
	}
}

// TestWatchNeedsRebuild pins the watch-recovery decision: ErrCompacted ALWAYS
// forces a snapshot rebuild. The regression this guards: an earlier
// `CompactRevision > watchRev+1` guard skipped the boundary case where the
// compaction horizon equals watchRev+1 EXACTLY — the loop then resubscribed at
// the same compacted-away revision forever (≤30s backoff spins) while the
// cache silently froze: no watch events, no drain triggers, until the NEXT
// compaction happened to advance the horizon (never, without auto-compaction).
func TestWatchNeedsRebuild(t *testing.T) {
	if !watchNeedsRebuild(rpctypes.ErrCompacted) {
		t.Fatal("ErrCompacted must rebuild — including the CompactRevision == watchRev+1 boundary")
	}
	// Wrapped forms (the loop receives the etcd error possibly layered).
	if !watchNeedsRebuild(fmt.Errorf("watch: %w", rpctypes.ErrCompacted)) {
		t.Fatal("wrapped ErrCompacted must rebuild")
	}
	// Plain disconnects must resume from the last revision, not rebuild.
	for _, err := range []error{context.Canceled, context.DeadlineExceeded, io.ErrUnexpectedEOF, fmt.Errorf("connection refused")} {
		if watchNeedsRebuild(err) {
			t.Fatalf("plain disconnect %v must NOT rebuild", err)
		}
	}
}

// TestMarshalUnmarshalAgentRoundTrip verifies an Agent survives the etcd
// serialization round-trip. Only the API key DIGEST is persisted — the
// plaintext never leaves the caller — plus the RFC3339Nano timestamp.
func TestMarshalUnmarshalAgentRoundTrip(t *testing.T) {
	created := time.Date(2026, 8, 7, 12, 30, 45, 123456789, time.UTC)
	a := &Agent{
		ID:         "agent-1",
		Name:       "tester",
		APIKey:     "sk-sandswap-agent-secret",
		APIKeyHash: hashAPIKey("sk-sandswap-agent-secret"),
		CreatedAt:  created,
	}

	data, err := marshalAgentForEtcd(a)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// The plaintext must NOT appear on the wire; the digest must.
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("raw decode: %v", err)
	}
	if _, ok := raw["api_key"]; ok {
		t.Errorf("plaintext api_key leaked to wire JSON: %v", raw)
	}
	if raw["api_key_hash"] != a.APIKeyHash {
		t.Errorf("api_key_hash missing from wire JSON: %v", raw)
	}

	back := decodeAgent(data)
	if back == nil {
		t.Fatal("decodeAgent returned nil")
	}
	if back.ID != "agent-1" || back.Name != "tester" || back.APIKeyHash != a.APIKeyHash {
		t.Errorf("round-trip mismatch: %+v", back)
	}
	if back.APIKey != "" {
		t.Errorf("decoded agent must carry no plaintext key, got %q", back.APIKey)
	}
	if !back.CreatedAt.Equal(created) {
		t.Errorf("CreatedAt = %v, want %v (RFC3339Nano precision)", back.CreatedAt, created)
	}
}

// TestUnmarshalAgentCorrupt verifies corrupt etcd data returns nil rather
// than a half-populated agent.
func TestUnmarshalAgentCorrupt(t *testing.T) {
	if decodeAgent([]byte("{not json")) != nil {
		t.Error("expected nil for corrupt agent JSON")
	}
}

// ── buildEtcdTLSConfig ──

// genEtcdCert writes a self-signed CA + a client cert signed by it, returning
// (caPath, certPath, keyPath).
func genEtcdCert(t *testing.T) (caPath, certPath, keyPath string) {
	t.Helper()
	dir := t.TempDir()
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-ca"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caPath = filepath.Join(dir, "ca.pem")
	os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0644)

	leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test-client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caTmpl, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	certPath = filepath.Join(dir, "cert.pem")
	os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), 0644)
	keyPath = filepath.Join(dir, "key.pem")
	os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(leafKey)}), 0600)
	return
}

// TestBuildEtcdTLSConfig verifies the etcd TLS builder:
//   - nil / all-empty -> plaintext (nil config)
//   - CA only -> server verification (RootCAs, no client cert)
//   - CA + cert + key -> mTLS (client cert loaded)
//   - cert without key -> hard error
//   - missing/invalid CA file -> hard error
func TestBuildEtcdTLSConfig(t *testing.T) {
	t.Run("nil", func(t *testing.T) {
		cfg, err := buildEtcdTLSConfig(nil)
		if err != nil || cfg != nil {
			t.Errorf("nil: expected (nil,nil), got (%v,%v)", cfg, err)
		}
	})

	t.Run("empty", func(t *testing.T) {
		cfg, err := buildEtcdTLSConfig(&EtcdTLSConfig{})
		if err != nil || cfg != nil {
			t.Errorf("empty: expected (nil,nil), got (%v,%v)", cfg, err)
		}
	})

	t.Run("CA only", func(t *testing.T) {
		ca, _, _ := genEtcdCert(t)
		cfg, err := buildEtcdTLSConfig(&EtcdTLSConfig{CAFile: ca})
		if err != nil {
			t.Fatalf("CA-only: %v", err)
		}
		if cfg == nil || cfg.RootCAs == nil {
			t.Fatal("expected non-nil config with RootCAs")
		}
		if len(cfg.Certificates) != 0 {
			t.Error("CA-only should not load a client cert")
		}
		if cfg.MinVersion < tls.VersionTLS12 {
			t.Error("expected MinVersion >= TLS 1.2")
		}
	})

	t.Run("mTLS", func(t *testing.T) {
		ca, cert, key := genEtcdCert(t)
		cfg, err := buildEtcdTLSConfig(&EtcdTLSConfig{CAFile: ca, CertFile: cert, KeyFile: key})
		if err != nil {
			t.Fatalf("mTLS: %v", err)
		}
		if len(cfg.Certificates) != 1 {
			t.Errorf("expected 1 client cert, got %d", len(cfg.Certificates))
		}
	})

	t.Run("cert without key", func(t *testing.T) {
		ca, cert, _ := genEtcdCert(t)
		if _, err := buildEtcdTLSConfig(&EtcdTLSConfig{CAFile: ca, CertFile: cert}); err == nil {
			t.Error("cert without key must be a hard error")
		}
	})

	t.Run("missing CA file", func(t *testing.T) {
		if _, err := buildEtcdTLSConfig(&EtcdTLSConfig{CAFile: "/nonexistent/ca.pem"}); err == nil {
			t.Error("missing CA file must error")
		}
	})

	t.Run("invalid CA PEM", func(t *testing.T) {
		dir := t.TempDir()
		p := filepath.Join(dir, "bad.pem")
		os.WriteFile(p, []byte("not a pem"), 0644)
		if _, err := buildEtcdTLSConfig(&EtcdTLSConfig{CAFile: p}); err == nil {
			t.Error("invalid CA PEM must error")
		}
	})
}

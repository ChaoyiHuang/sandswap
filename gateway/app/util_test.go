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
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	gwconfig "gateway/config"
)

// TestResolveGatewayID verifies gateway identity resolution: an explicit
// GatewayID is returned verbatim (stable identity across restarts for
// ownership/registry reclaim); otherwise it derives "mode-hostname".
func TestResolveGatewayID(t *testing.T) {
	// Explicit ID wins.
	cfg := &gwconfig.GatewayConfig{GatewayID: "gw-pod-0"}
	if got := resolveGatewayID(cfg, "exec"); got != "gw-pod-0" {
		t.Errorf("explicit GatewayID = %q, want gw-pod-0", got)
	}
	// Empty -> mode-hostname.
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "unknown"
	}
	cfg2 := &gwconfig.GatewayConfig{}
	if got := resolveGatewayID(cfg2, "exec"); got != "exec-"+hostname {
		t.Errorf("derived GatewayID = %q, want exec-%s", got, hostname)
	}
}

// TestResolveScopes verifies the OIDC scope defaults: an empty config falls
// back to the authn package defaults, a set value is returned verbatim.
func TestResolveScopes(t *testing.T) {
	if got := resolveScopeHuman(&gwconfig.GatewayConfig{}); got != "sandswap:human" {
		t.Errorf("default human scope = %q, want sandswap:human", got)
	}
	if got := resolveScopeAdmin(&gwconfig.GatewayConfig{}); got != "sandswap:admin" {
		t.Errorf("default admin scope = %q, want sandswap:admin", got)
	}
	if got := resolveScopeOps(&gwconfig.GatewayConfig{}); got != "sandswap:ops" {
		t.Errorf("default ops scope = %q, want sandswap:ops", got)
	}
	cfg := &gwconfig.GatewayConfig{}
	cfg.Authn.ScopeHuman = "custom:human"
	cfg.Authn.ScopeAdmin = "custom:admin"
	cfg.Authn.ScopeOps = "custom:ops"
	if got := resolveScopeHuman(cfg); got != "custom:human" {
		t.Errorf("configured human scope = %q", got)
	}
	if got := resolveScopeAdmin(cfg); got != "custom:admin" {
		t.Errorf("configured admin scope = %q", got)
	}
	if got := resolveScopeOps(cfg); got != "custom:ops" {
		t.Errorf("configured ops scope = %q", got)
	}
}

// genServerCert writes a CA + a server cert (ServerAuth EKU) + key, returning
// the paths. Used to exercise the TLS builders with real material.
func genServerCert(t *testing.T) (caPath, certPath, keyPath string) {
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
		Subject:      pkix.Name{CommonName: "test-server"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
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

// TestBuildStreamServerTLS verifies the gRPC stream TLS builder: missing
// cert/key is a hard error; valid material yields TLS 1.3; a CA enables
// required-client-cert mTLS.
func TestBuildStreamServerTLS(t *testing.T) {
	// Missing cert/key -> error.
	if _, err := buildStreamServerTLS("", "", ""); err == nil {
		t.Error("expected error for missing cert/key")
	}

	ca, cert, key := genServerCert(t)
	// No CA is a startup error: without verification, a self-signed cert with
	// CN=<node-id> is accepted as that node (node impersonation).
	if _, err := buildStreamServerTLS(cert, key, ""); err == nil {
		t.Fatal("stream TLS without -stream-tls-ca must be refused")
	}

	// With CA -> mTLS required.
	cfgMTLS, err := buildStreamServerTLS(cert, key, ca)
	if err != nil {
		t.Fatalf("build (mTLS): %v", err)
	}
	if cfgMTLS.ClientCAs == nil || cfgMTLS.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Error("CA should enable required-client-cert mTLS")
	}
	if cfgMTLS.MinVersion != tls.VersionTLS13 {
		t.Errorf("stream MinVersion = %v, want TLS 1.3", cfgMTLS.MinVersion)
	}

	// Invalid CA -> error.
	bad := filepath.Join(t.TempDir(), "bad.pem")
	os.WriteFile(bad, []byte("not a pem"), 0644)
	if _, err := buildStreamServerTLS(cert, key, bad); err == nil {
		t.Error("invalid CA PEM should error")
	}
}

// TestBuildHTTPServerTLS verifies the HTTP listener TLS builder: missing
// cert/key errors; valid material yields TLS 1.2+; a CA enables mTLS.
func TestBuildHTTPServerTLS(t *testing.T) {
	if _, err := buildHTTPServerTLS("", "", ""); err == nil {
		t.Error("expected error for missing cert/key")
	}

	ca, cert, key := genServerCert(t)
	cfg, err := buildHTTPServerTLS(cert, key, "")
	if err != nil {
		t.Fatalf("build (no CA): %v", err)
	}
	if len(cfg.Certificates) != 1 {
		t.Error("expected 1 server cert")
	}
	if cfg.MinVersion < tls.VersionTLS12 {
		t.Errorf("HTTP MinVersion = %v, want >= TLS 1.2", cfg.MinVersion)
	}

	cfgMTLS, err := buildHTTPServerTLS(cert, key, ca)
	if err != nil {
		t.Fatalf("build (mTLS): %v", err)
	}
	if cfgMTLS.ClientCAs == nil || cfgMTLS.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Error("CA should enable required-client-cert mTLS")
	}
}

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
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeClientEnv writes a contract file and points the loader at it for the
// duration of the test.
func writeClientEnv(t *testing.T, content string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "sandctl.env")
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	// The filesystem applies the process umask; pin the intended mode.
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	t.Setenv(ClientEnvOverrideEnv, p)
	return p
}

// TestLoadClientEnvFromOverride loads every supported key from an explicit
// contract and checks the values land on Global.
func TestLoadClientEnvFromOverride(t *testing.T) {
	writeClientEnv(t, `# client contract
gateway_url=https://127.0.0.1:3000
human_url=https://127.0.0.1:3100
dns_addr=127.0.0.1:53
etcd=https://127.0.0.1:2379
tls=true
ca=/etc/sandswap/certs/ca.crt
insecure=false
`, 0o644)

	g := Defaults()
	if err := g.LoadEnv(map[string]bool{}); err != nil {
		t.Fatalf("LoadEnv: %v", err)
	}
	if g.GatewayURL != "https://127.0.0.1:3000" || g.HumanURL != "https://127.0.0.1:3100" {
		t.Errorf("urls: %+v", g)
	}
	if g.DNSAddr != "127.0.0.1:53" || g.Etcd != "https://127.0.0.1:2379" {
		t.Errorf("addrs: %+v", g)
	}
	if !g.TLS || g.CA != "/etc/sandswap/certs/ca.crt" || g.Insecure {
		t.Errorf("tls material: %+v", g)
	}
	if g.RunDir != "./run" {
		t.Errorf("run-dir must stay the caller's, got %q", g.RunDir)
	}
}

// TestLoadClientEnvExplicitWins verifies a CLI-explicit flag is NOT
// overwritten by the contract.
func TestLoadClientEnvExplicitWins(t *testing.T) {
	writeClientEnv(t, "gateway_url=https://from-env:3000\ntls=true\n", 0o644)

	g := Defaults()
	g.GatewayURL = "https://from-cli:3000"
	if err := g.LoadEnv(map[string]bool{"gateway-url": true}); err != nil {
		t.Fatalf("LoadEnv: %v", err)
	}
	if g.GatewayURL != "https://from-cli:3000" {
		t.Errorf("explicit CLI flag must win, got %q", g.GatewayURL)
	}
	if !g.TLS {
		t.Error("non-explicit keys must still load")
	}
}

// TestLoadClientEnvOverrideMissingIsError: an explicit override that does not
// exist is a hard error, never a silent fallback to another contract.
func TestLoadClientEnvOverrideMissingIsError(t *testing.T) {
	t.Setenv(ClientEnvOverrideEnv, filepath.Join(t.TempDir(), "absent.env"))
	g := Defaults()
	if err := g.LoadEnv(map[string]bool{}); err == nil {
		t.Fatal("a missing explicit contract must be reported")
	}
}

// TestLoadClientEnvRefusesUnsafeFile: a group/world-writable contract or a
// symlinked one is refused.
func TestLoadClientEnvRefusesUnsafeFile(t *testing.T) {
	writeClientEnv(t, "gateway_url=https://x:3000\n", 0o666)
	g := Defaults()
	if err := g.LoadEnv(map[string]bool{}); err == nil {
		t.Fatal("a group/world-writable contract must be refused")
	}

	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("gateway_url=https://x:3000\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.env")
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}
	t.Setenv(ClientEnvOverrideEnv, link)
	g = Defaults()
	if err := g.LoadEnv(map[string]bool{}); err == nil {
		t.Fatal("a symlinked contract must be refused")
	}
}

// TestLoadClientEnvRefusesForeignOwner: under root, a contract owned by an
// unrelated identity is refused (unless it is the sudo-invoking user).
func TestLoadClientEnvRefusesForeignOwner(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to create a foreign-owned contract")
	}
	p := writeClientEnv(t, "gateway_url=https://x:3000\n", 0o644)
	if err := os.Chown(p, 65536, 65536); err != nil {
		t.Fatal(err)
	}
	g := Defaults()
	if err := g.LoadEnv(map[string]bool{}); err == nil {
		t.Fatal("a foreign-owned contract must be refused")
	}
}

// TestClientKeyFileIsolation pins the credential-isolation contract: a client
// key must be a 0600 regular file owned by the caller (or root).
func TestClientKeyFileIsolation(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "client.key")
	if err := os.WriteFile(key, []byte("KEY"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := checkClientKeyFile(key); err != nil {
		t.Fatalf("a 0600 caller-owned key must pass: %v", err)
	}
	if err := os.Chmod(key, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := checkClientKeyFile(key); err == nil {
		t.Fatal("a 0644 key must be refused")
	}
	if err := os.Chmod(key, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.key")
	if err := os.Symlink(key, link); err != nil {
		t.Fatal(err)
	}
	if err := checkClientKeyFile(link); err == nil {
		t.Fatal("a symlinked key must be refused")
	}
	if os.Geteuid() == 0 {
		if err := os.Chown(key, 65536, 65536); err != nil {
			t.Fatal(err)
		}
		if err := checkClientKeyFile(key); err == nil {
			t.Fatal("another identity's key must be refused")
		}
	}
}

// TestHTTPSClientRejectsLooseClientKey exercises the load path, not just the
// helper: a group/world-readable key must never reach the TLS stack.
func TestHTTPSClientRejectsLooseClientKey(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "client.crt")
	key := filepath.Join(dir, "client.key")
	if err := os.WriteFile(cert, []byte("not a cert"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, []byte("not a key"), 0o644); err != nil {
		t.Fatal(err)
	}
	g := Defaults()
	g.GatewayURL = "https://127.0.0.1:3000"
	g.ClientCert, g.ClientKey = cert, key
	if _, err := g.httpc(); err == nil || !strings.Contains(err.Error(), "group/world") {
		t.Fatalf("a loose client key must be refused by name, got %v", err)
	}
	// One-sided material is a configuration error, not a silent no-op.
	g.ClientKey = ""
	if _, err := g.httpc(); err == nil || !strings.Contains(err.Error(), "together") {
		t.Fatalf("one-sided client material must error, got %v", err)
	}
}

// TestEtcdTLSArgsUsesExplicitMaterialOnly: no run/certs discovery; the
// caller's explicit flags are the only source, and a loose key is refused.
func TestEtcdTLSArgsUsesExplicitMaterialOnly(t *testing.T) {
	g := Defaults()
	g.TLS = true
	args, err := g.etcdTLSArgs()
	if err != nil {
		t.Fatal(err)
	}
	if len(args) != 0 {
		t.Fatalf("no explicit material must yield no TLS args, got %v", args)
	}

	dir := t.TempDir()
	cert := filepath.Join(dir, "c.crt")
	key := filepath.Join(dir, "c.key")
	if err := os.WriteFile(cert, []byte("C"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, []byte("K"), 0o600); err != nil {
		t.Fatal(err)
	}
	g.CA = "/etc/sandswap/certs/ca.crt"
	g.ClientCert, g.ClientKey = cert, key
	args, err = g.etcdTLSArgs()
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	for _, want := range []string{"--cacert=/etc/sandswap/certs/ca.crt", "--cert=" + cert, "--key=" + key} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in %v", want, args)
		}
	}
	if err := os.Chmod(key, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := g.etcdTLSArgs(); err == nil {
		t.Fatal("a group-readable etcd client key must be refused")
	}
}

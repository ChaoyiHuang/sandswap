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

package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"common/config"
)

func TestDefaults(t *testing.T) {
	d := Defaults()
	if d.VolRoot != "/var/sandswap/volumes" {
		t.Errorf("VolRoot = %q, want /var/sandswap/volumes", d.VolRoot)
	}
	if d.Agent.Addr != ":3000" {
		t.Errorf("Agent.Addr = %q, want :3000", d.Agent.Addr)
	}
	if d.Human.Addr != ":3100" {
		t.Errorf("Human.Addr = %q, want :3100", d.Human.Addr)
	}
	if d.Stream.Addr != ":9998" {
		t.Errorf("Stream.Addr = %q, want :9998", d.Stream.Addr)
	}
	if d.Lease.StickyMs != 100 {
		t.Errorf("Lease.StickyMs = %d, want 100", d.Lease.StickyMs)
	}
	if d.Exec.DefaultTimeoutSec != 30 {
		t.Errorf("Exec.DefaultTimeoutSec = %d, want 30", d.Exec.DefaultTimeoutSec)
	}
	// The effective default (no flags, no YAML): must equal the warden's
	// default max_exec_timeout and stay strictly below the warden countdown
	// (300) — see ExecConfig in config.go. Was silently 300 once (flag default
	// 180 never reaches Defaults() unless explicitly passed).
	if d.Exec.MaxTimeoutSec != 180 {
		t.Errorf("Exec.MaxTimeoutSec = %d, want 180 (warden max_exec_timeout default; < warden countdown 300)", d.Exec.MaxTimeoutSec)
	}
	if d.Exec.MaxBackgroundLeaseSec != 3600 {
		t.Errorf("Exec.MaxBackgroundLeaseSec = %d, want 3600", d.Exec.MaxBackgroundLeaseSec)
	}
	if d.Authn.Issuer != "" {
		t.Errorf("Authn.Issuer = %q, want empty (no auth by default)", d.Authn.Issuer)
	}
	if d.Authn.JWKSRefreshSec != 3600 {
		t.Errorf("Authn.JWKSRefreshSec = %d, want 3600", d.Authn.JWKSRefreshSec)
	}
	if d.Authn.ScopeHuman != "sandswap:human" {
		t.Errorf("Authn.ScopeHuman = %q, want sandswap:human", d.Authn.ScopeHuman)
	}
	if d.Authn.ScopeAdmin != "sandswap:admin" {
		t.Errorf("Authn.ScopeAdmin = %q, want sandswap:admin", d.Authn.ScopeAdmin)
	}
	if d.Authn.ScopeOps != "sandswap:ops" {
		t.Errorf("Authn.ScopeOps = %q, want sandswap:ops", d.Authn.ScopeOps)
	}
}

func TestLoadFromFile(t *testing.T) {
	dir := t.TempDir()
	yamlPath := filepath.Join(dir, "gateway.yaml")

	content := `
vol_root: "/custom/volumes"
mode: "exec"
etcd: "http://etcd:2379"
agent:
  addr: ":4000"
  tls_cert: "/certs/agent.pem"
human:
  addr: ":5000"
stream:
  addr: ":8888"
lease:
  sticky_ms: 200
  max_sticky_sec: 10
exec:
  default_timeout_sec: 60
  max_timeout_sec: 600
authn:
  issuer: "https://identity.example.com/"
  client_id: "sandswap-api"
  jwks_refresh_sec: 1800
  mtls_trust_cert: true
  scope_human: "myapp:user"
  scope_admin: "myapp:power"
  scope_ops: "myapp:admin"
`
	if err := os.WriteFile(yamlPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadFromFile(yamlPath)
	if err != nil {
		t.Fatal(err)
	}

	if cfg.VolRoot != "/custom/volumes" {
		t.Errorf("VolRoot = %q, want /custom/volumes", cfg.VolRoot)
	}
	if cfg.Mode != "exec" {
		t.Errorf("Mode = %q, want exec", cfg.Mode)
	}
	if cfg.Agent.Addr != ":4000" {
		t.Errorf("Agent.Addr = %q, want :4000", cfg.Agent.Addr)
	}
	if cfg.Agent.TLSCert != "/certs/agent.pem" {
		t.Errorf("Agent.TLSCert = %q, want /certs/agent.pem", cfg.Agent.TLSCert)
	}
	if cfg.Human.Addr != ":5000" {
		t.Errorf("Human.Addr = %q, want :5000", cfg.Human.Addr)
	}
	if cfg.Stream.Addr != ":8888" {
		t.Errorf("Stream.Addr = %q, want :8888", cfg.Stream.Addr)
	}
	if cfg.Lease.StickyMs != 200 {
		t.Errorf("Lease.StickyMs = %d, want 200", cfg.Lease.StickyMs)
	}
	if cfg.Lease.MaxStickySec != 10 {
		t.Errorf("Lease.MaxStickySec = %d, want 10", cfg.Lease.MaxStickySec)
	}
	if cfg.Exec.DefaultTimeoutSec != 60 {
		t.Errorf("Exec.DefaultTimeoutSec = %d, want 60", cfg.Exec.DefaultTimeoutSec)
	}
	if cfg.Authn.Issuer != "https://identity.example.com/" {
		t.Errorf("Authn.Issuer = %q, want https://identity.example.com/", cfg.Authn.Issuer)
	}
	if cfg.Authn.ClientID != "sandswap-api" {
		t.Errorf("Authn.ClientID = %q, want sandswap-api", cfg.Authn.ClientID)
	}
	if cfg.Authn.JWKSRefreshSec != 1800 {
		t.Errorf("Authn.JWKSRefreshSec = %d, want 1800", cfg.Authn.JWKSRefreshSec)
	}
	if cfg.Authn.MTLSTrustCert != true {
		t.Errorf("Authn.MTLSTrustCert = %v, want true", cfg.Authn.MTLSTrustCert)
	}
	if cfg.Authn.ScopeHuman != "myapp:user" {
		t.Errorf("Authn.ScopeHuman = %q, want myapp:user", cfg.Authn.ScopeHuman)
	}
	if cfg.Authn.ScopeAdmin != "myapp:power" {
		t.Errorf("Authn.ScopeAdmin = %q, want myapp:power", cfg.Authn.ScopeAdmin)
	}
	if cfg.Authn.ScopeOps != "myapp:admin" {
		t.Errorf("Authn.ScopeOps = %q, want myapp:admin", cfg.Authn.ScopeOps)
	}
}

func TestLoadFromFilePartial(t *testing.T) {
	dir := t.TempDir()
	yamlPath := filepath.Join(dir, "gateway.yaml")

	// Only set a few fields — the rest should come from Defaults().
	content := `
lease:
  sticky_ms: 500
`
	if err := os.WriteFile(yamlPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadFromFile(yamlPath)
	if err != nil {
		t.Fatal(err)
	}

	// Overridden field.
	if cfg.Lease.StickyMs != 500 {
		t.Errorf("Lease.StickyMs = %d, want 500", cfg.Lease.StickyMs)
	}
	// Default values preserved for unset fields.
	if cfg.Agent.Addr != ":3000" {
		t.Errorf("Agent.Addr = %q, want :3000 (default)", cfg.Agent.Addr)
	}
	if cfg.Lease.MaxStickySec != 5 {
		t.Errorf("Lease.MaxStickySec = %d, want 5 (default)", cfg.Lease.MaxStickySec)
	}
}

func TestDiffHotReload(t *testing.T) {
	old := Defaults()
	new := Defaults()
	new.Lease.StickyMs = 200
	new.Exec.DefaultTimeoutSec = 60

	cs := old.Diff(new)
	if len(cs.HotReload) != 2 {
		t.Errorf("expected 2 hot-reload changes, got %d: %+v", len(cs.HotReload), cs.HotReload)
	}
	if len(cs.RestartReq) != 0 {
		t.Errorf("expected 0 restart-required changes, got %d: %+v", len(cs.RestartReq), cs.RestartReq)
	}
}

func TestDiffRestartRequired(t *testing.T) {
	old := Defaults()
	new := Defaults()
	new.Agent.Addr = ":4000"
	new.VolRoot = "/custom"

	cs := old.Diff(new)
	if len(cs.RestartReq) != 2 {
		t.Errorf("expected 2 restart-required changes, got %d: %+v", len(cs.RestartReq), cs.RestartReq)
	}
	if len(cs.HotReload) != 0 {
		t.Errorf("expected 0 hot-reload changes, got %d: %+v", len(cs.HotReload), cs.HotReload)
	}
}

func TestDiffMixed(t *testing.T) {
	old := Defaults()
	new := Defaults()
	new.Lease.StickyMs = 200
	new.Agent.Addr = ":4000"

	cs := old.Diff(new)
	if len(cs.HotReload) != 1 {
		t.Errorf("expected 1 hot-reload change, got %d", len(cs.HotReload))
	}
	if len(cs.RestartReq) != 1 {
		t.Errorf("expected 1 restart-required change, got %d", len(cs.RestartReq))
	}
	if cs.HotReload[0].Name != "lease.sticky_ms" {
		t.Errorf("hot-reload change = %q, want lease.sticky_ms", cs.HotReload[0].Name)
	}
	if cs.RestartReq[0].Name != "agent.addr" {
		t.Errorf("restart-required change = %q, want agent.addr", cs.RestartReq[0].Name)
	}
}

func TestDiffAuthnRestartRequired(t *testing.T) {
	old := Defaults()
	new := Defaults()
	new.Authn.Issuer = "https://new-issuer.example.com/"
	new.Authn.ScopeHuman = "myapp:user"

	cs := old.Diff(new)
	if len(cs.RestartReq) != 2 {
		t.Errorf("expected 2 restart-required changes (authn.issuer, authn.scope_human), got %d", len(cs.RestartReq))
	}
	if len(cs.HotReload) != 0 {
		t.Errorf("expected 0 hot-reload changes for authn, got %d", len(cs.HotReload))
	}
}

func TestClassifyField(t *testing.T) {
	tests := []struct {
		name string
		want config.ChangeClass
	}{
		{"lease.sticky_ms", config.ChangeHotReload},
		{"lease.max_sticky_sec", config.ChangeHotReload},
		{"exec.default_timeout_sec", config.ChangeHotReload},
		{"exec.max_timeout_sec", config.ChangeHotReload},
		// The bg-lease cap is documented hot-reloadable (CLAUDE.md, -max-background-lease-sec
		// help) and reload.go carries its dispatch case — the classifier must agree,
		// else a YAML edit lands in RestartReq and the callback never fires.
		{"exec.max_background_lease_sec", config.ChangeHotReload},
		// Restart-required
		{"vol_root", config.ChangeRestartRequired},
		{"mode", config.ChangeRestartRequired},
		{"etcd", config.ChangeRestartRequired},
		{"agent.addr", config.ChangeRestartRequired},
		{"agent.tls_cert", config.ChangeRestartRequired},
		{"human.addr", config.ChangeRestartRequired},
		{"stream.addr", config.ChangeRestartRequired},
		// Authn: all restart-required (OIDC provider needs re-initialization)
		{"authn.issuer", config.ChangeRestartRequired},
		{"authn.client_id", config.ChangeRestartRequired},
		{"authn.jwks_refresh_sec", config.ChangeRestartRequired},
		{"authn.mtls_trust_cert", config.ChangeRestartRequired},
		{"authn.scope_human", config.ChangeRestartRequired},
		{"authn.scope_ops", config.ChangeRestartRequired},
	}
	for _, tt := range tests {
		got := classifyField(tt.name)
		if got != tt.want {
			t.Errorf("classifyField(%q) = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestApplyFlagOverrides(t *testing.T) {
	cfg := Defaults()

	flags := &GatewayFlags{
		StickyMs:  300,
		AgentAddr: ":5000",
	}
	explicitSet := map[string]bool{
		"sticky-ms":  true,
		"agent-addr": true,
	}

	cfg.ApplyFlagOverrides(flags, explicitSet)

	if cfg.Lease.StickyMs != 300 {
		t.Errorf("Lease.StickyMs = %d, want 300 (flag override)", cfg.Lease.StickyMs)
	}
	if cfg.Agent.Addr != ":5000" {
		t.Errorf("Agent.Addr = %q, want :5000 (flag override)", cfg.Agent.Addr)
	}
	// Non-overridden fields should keep default.
	if cfg.Lease.MaxStickySec != 5 {
		t.Errorf("Lease.MaxStickySec = %d, want 5 (default, no override)", cfg.Lease.MaxStickySec)
	}
	if cfg.Human.Addr != ":3100" {
		t.Errorf("Human.Addr = %q, want :3100 (default, no override)", cfg.Human.Addr)
	}
}

func TestApplyFlagOverridesMCP(t *testing.T) {
	cfg := Defaults()

	// Explicit flag overrides YAML/default.
	cfg.MCP.InstructionsFile = "/from/yaml/guide.md"
	cfg.ApplyFlagOverrides(&GatewayFlags{MCPInstructionsFile: "/from/flag/guide.md"},
		map[string]bool{"mcp-instructions-file": true})
	if cfg.MCP.InstructionsFile != "/from/flag/guide.md" {
		t.Errorf("MCP.InstructionsFile = %q, want flag override", cfg.MCP.InstructionsFile)
	}

	// Unset flag keeps the YAML value.
	cfg2 := Defaults()
	cfg2.MCP.InstructionsFile = "/from/yaml/guide.md"
	cfg2.ApplyFlagOverrides(&GatewayFlags{MCPInstructionsFile: "/from/flag/guide.md"}, map[string]bool{})
	if cfg2.MCP.InstructionsFile != "/from/yaml/guide.md" {
		t.Errorf("MCP.InstructionsFile = %q, want YAML value kept", cfg2.MCP.InstructionsFile)
	}
}

func TestApplyFlagOverridesAuthn(t *testing.T) {
	cfg := Defaults()
	flags := &GatewayFlags{
		AuthnIssuer:     "https://identity.example.com/",
		AuthnClientID:   "my-client",
		AuthnScopeHuman: "myapp:user",
	}
	explicitSet := map[string]bool{
		"authn-issuer":      true,
		"authn-client-id":   true,
		"authn-scope-human": true,
	}

	cfg.ApplyFlagOverrides(flags, explicitSet)

	if cfg.Authn.Issuer != "https://identity.example.com/" {
		t.Errorf("Authn.Issuer = %q, want https://identity.example.com/", cfg.Authn.Issuer)
	}
	if cfg.Authn.ClientID != "my-client" {
		t.Errorf("Authn.ClientID = %q, want my-client", cfg.Authn.ClientID)
	}
	if cfg.Authn.ScopeHuman != "myapp:user" {
		t.Errorf("Authn.ScopeHuman = %q, want myapp:user", cfg.Authn.ScopeHuman)
	}
	// Non-overridden authn fields should keep defaults.
	if cfg.Authn.ScopeOps != "sandswap:ops" {
		t.Errorf("Authn.ScopeOps = %q, want sandswap:ops (default)", cfg.Authn.ScopeOps)
	}
	if cfg.Authn.JWKSRefreshSec != 3600 {
		t.Errorf("Authn.JWKSRefreshSec = %d, want 3600 (default)", cfg.Authn.JWKSRefreshSec)
	}
}

func TestApplyFlagOverridesNoExplicit(t *testing.T) {
	cfg := Defaults()
	flags := &GatewayFlags{StickyMs: 999}
	explicitSet := map[string]bool{} // nothing explicitly set

	cfg.ApplyFlagOverrides(flags, explicitSet)

	// Should remain at default since the flag wasn't explicitly set.
	if cfg.Lease.StickyMs != 100 {
		t.Errorf("Lease.StickyMs = %d, want 100 (default, flag not explicit)", cfg.Lease.StickyMs)
	}
}

func TestSchedPolicyFromConfig(t *testing.T) {
	// Default (spread, weights 0 -> built-in defaults, caps 0 disabled).
	p := SchedPolicyFromConfig(SchedConfig{Policy: "spread"})
	if p.Binpack {
		t.Error("expected spread by default")
	}
	if p.WLoad != 0.6 || p.WHost != 0.3 || p.WClean != 0.1 {
		t.Errorf("expected default weights 0.6/0.3/0.1, got %v/%v/%v", p.WLoad, p.WHost, p.WClean)
	}
	if p.HostCPUHard != 0 || p.DutyHard != 0 {
		t.Errorf("expected caps disabled by default, got %v/%v", p.HostCPUHard, p.DutyHard)
	}

	// Binpack + weight overrides + caps.
	p = SchedPolicyFromConfig(SchedConfig{
		Policy: "binpack", WLoad: 0.8, WHost: 0.1, WClean: 0.1, HostCPUHard: 90, DutyHard: 0.9,
	})
	if !p.Binpack {
		t.Error("expected binpack")
	}
	if p.WLoad != 0.8 || p.WHost != 0.1 {
		t.Errorf("expected overridden weights 0.8/0.1, got %v/%v", p.WLoad, p.WHost)
	}
	if p.HostCPUHard != 90 || p.DutyHard != 0.9 {
		t.Errorf("expected caps 90/0.9, got %v/%v", p.HostCPUHard, p.DutyHard)
	}
}

func TestIdleTimeout(t *testing.T) {
	// Default: positive seconds pass through as a duration.
	c := Defaults()
	if got := c.IdleTimeout(); got != 3600*time.Second {
		t.Errorf("IdleTimeout(default) = %v, want 1h", got)
	}
	// Zero passes through unchanged — http.Server then falls back to
	// ReadTimeout (30s); the startup warning is what catches it.
	c.IdleTimeoutSec = 0
	if got := c.IdleTimeout(); got != 0 {
		t.Errorf("IdleTimeout(0) = %v, want 0 (ReadTimeout fallback)", got)
	}
	// -1 = never close: http.Server cannot express that (0 → ReadTimeout,
	// negative → already-expired deadline), so it maps to the largest finite
	// duration. Values below -1 are rejected by the startup guard in cmd;
	// IdleTimeout() still maps them defensively if ever reached.
	c.IdleTimeoutSec = -1
	if got := c.IdleTimeout(); got != NeverCloseIdle {
		t.Errorf("IdleTimeout(-1) = %v, want NeverCloseIdle", got)
	}
	c.IdleTimeoutSec = -86400
	if got := c.IdleTimeout(); got != NeverCloseIdle {
		t.Errorf("IdleTimeout(-86400) = %v, want NeverCloseIdle", got)
	}
}

// TestValidateLease: sticky_ms and max_sticky_sec must both be >= 1. A 0
// sticky window breaks the window-refresh mechanism (post-completion
// concurrent arrivals can no longer join the warm VM); a <=0 maxHold silently
// disables the reaper safety net.
// TestValidateEtcd pins the cluster-control exposure rule: a non-loopback
// etcd endpoint must carry TLS (https or a CA/client pair), unless the
// operator explicitly opts into a dev-only plaintext topology.
func TestValidateEtcd(t *testing.T) {
	cases := []struct {
		name    string
		cfg     GatewayConfig
		wantErr bool
	}{
		{"single-node (no etcd)", GatewayConfig{}, false},
		{"loopback IPv4 plaintext", GatewayConfig{Etcd: "http://127.0.0.1:2379"}, false},
		{"loopback IPv6 plaintext", GatewayConfig{Etcd: "http://[::1]:2379"}, false},
		{"localhost plaintext", GatewayConfig{Etcd: "http://localhost:2379"}, false},
		{"non-loopback plaintext", GatewayConfig{Etcd: "http://10.0.0.5:2379"}, true},
		{"non-loopback plaintext with port only", GatewayConfig{Etcd: "etcd:2379"}, true},
		{"non-loopback https", GatewayConfig{Etcd: "https://etcd:2379"}, false},
		{"non-loopback with CA", GatewayConfig{Etcd: "http://etcd:2379", EtcdCA: "/ca.pem"}, false},
		{"non-loopback with client pair", GatewayConfig{Etcd: "http://etcd:2379", EtcdCert: "/c.pem", EtcdKey: "/k.pem"}, false},
		{"non-loopback explicit opt-out", GatewayConfig{Etcd: "http://10.0.0.5:2379", AllowInsecureEtcd: true}, false},
		{"cert without key", GatewayConfig{Etcd: "https://etcd:2379", EtcdCert: "/c.pem"}, true},
		{"key without cert", GatewayConfig{Etcd: "https://etcd:2379", EtcdKey: "/k.pem"}, true},
		{"mixed loopback + exposed", GatewayConfig{Etcd: "http://127.0.0.1:2379,http://10.0.0.5:2379"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.ValidateEtcd()
			if (err != nil) != tc.wantErr {
				t.Fatalf("ValidateEtcd() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestValidateLease(t *testing.T) {
	for _, tc := range []struct {
		name         string
		stickyMs     int
		maxStickySec int
		wantErr      bool
	}{
		{"defaults valid", 100, 5, false},
		{"minimum sticky 1ms valid", 1, 5, false},
		{"sticky 0 invalid", 0, 5, true},
		{"sticky negative invalid", -1, 5, true},
		{"max_sticky 0 invalid", 100, 0, true},
		{"max_sticky negative invalid", 100, -1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Defaults()
			cfg.Lease.StickyMs = tc.stickyMs
			cfg.Lease.MaxStickySec = tc.maxStickySec
			err := cfg.ValidateLease()
			if tc.wantErr && err == nil {
				t.Errorf("ValidateLease accepted sticky_ms=%d max_sticky_sec=%d, want error", tc.stickyMs, tc.maxStickySec)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("ValidateLease rejected sticky_ms=%d max_sticky_sec=%d: %v", tc.stickyMs, tc.maxStickySec, err)
			}
		})
	}
}

// TestValidateExec: exec timeouts must be >= 1 with max >= default. The
// constructor's silent normalization (max<default → default) hides a typo'd
// config; startup refuses instead (e2e exec-timeout-policy Phase 2 pins this).
func TestValidateExec(t *testing.T) {
	cases := []struct {
		name       string
		defaultSec int
		maxSec     int
		wantErr    bool
	}{
		{"defaults valid", 30, 180, false},
		{"minimums valid", 1, 1, false},
		{"default 0 invalid", 0, 180, true},
		{"max 0 invalid", 30, 0, true},
		{"max below default invalid", 5, 2, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Defaults()
			cfg.Exec.DefaultTimeoutSec = tc.defaultSec
			cfg.Exec.MaxTimeoutSec = tc.maxSec
			err := cfg.ValidateExec()
			if (err != nil) != tc.wantErr {
				t.Errorf("ValidateExec(default=%d max=%d) = %v, wantErr %v", tc.defaultSec, tc.maxSec, err, tc.wantErr)
			}
		})
	}
}

// TestValidateStreamConcurrency: transport knobs >= 1 and the shared
// window/message-size contract (int32 range, window >= message, 16MB chain).
func TestValidateStreamConcurrency(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*GatewayConfig)
		want bool
	}{
		{"defaults valid", func(c *GatewayConfig) {}, false},
		{"send buffer 0 invalid", func(c *GatewayConfig) { c.StreamConcurrency.SendBufferSize = 0 }, true},
		{"write timeout negative invalid", func(c *GatewayConfig) { c.StreamConcurrency.WriteTimeoutSec = -1 }, true},
		{"window 0 invalid", func(c *GatewayConfig) { c.StreamConcurrency.InitialWindow = 0 }, true},
		{"window over int32 invalid", func(c *GatewayConfig) { c.StreamConcurrency.InitialConnWindow = 1 << 31 }, true},
		{"window below msg size invalid", func(c *GatewayConfig) {
			c.StreamConcurrency.InitialWindow = c.StreamConcurrency.MaxMsgSize / 2
		}, true},
		{"conn window below stream window invalid", func(c *GatewayConfig) {
			c.StreamConcurrency.InitialConnWindow = c.StreamConcurrency.InitialWindow / 2
		}, true},
		{"msg size below 16MB chain invalid", func(c *GatewayConfig) { c.StreamConcurrency.MaxMsgSize = 8 << 20 }, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Defaults()
			tc.mut(&cfg)
			err := cfg.ValidateStreamConcurrency()
			if (err != nil) != tc.want {
				t.Errorf("ValidateStreamConcurrency() = %v, want %v", err, tc.want)
			}
		})
	}
}

// TestValidateStaleness: thresholds >= 1 and the judging-cost ordering — the
// takeover guard must not fire before routing/alerting (equal is legal: the
// e2e compresses all three to the same second).
func TestValidateStaleness(t *testing.T) {
	cases := []struct {
		name                string
		route, guard, alert int
		wantErr             bool
	}{
		{"defaults valid", 20, 45, 30, false},
		{"all equal valid (e2e timing compression)", 2, 2, 2, false},
		{"zero invalid", 0, 45, 30, true},
		{"route past guard invalid", 50, 45, 30, true},
		{"alert past guard invalid", 20, 45, 60, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateStalenessValues(tc.route, tc.guard, tc.alert)
			if (err != nil) != tc.wantErr {
				t.Errorf("ValidateStalenessValues(%d,%d,%d) = %v, wantErr %v", tc.route, tc.guard, tc.alert, err, tc.wantErr)
			}
		})
	}
}

// TestValidateShed: cooldown >= 0 (negative lets DNS instantly undo a shed),
// retry_after >= 1 (<= 0 is silently replaced by a hardcoded 5 downstream);
// sat/rate keep their documented <= 0 = disable sentinel.
func TestValidateShed(t *testing.T) {
	cases := []struct {
		name                 string
		cooldown, retryAfter int
		wantErr              bool
	}{
		{"defaults valid", 30, 5, false},
		{"cooldown 0 valid (no cooldown)", 0, 5, false},
		{"cooldown negative invalid", -1, 5, true},
		{"retry_after 0 invalid", 30, 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Defaults()
			cfg.Shed.CooldownSec = tc.cooldown
			cfg.Shed.RetryAfterSec = tc.retryAfter
			err := cfg.ValidateShed()
			if (err != nil) != tc.wantErr {
				t.Errorf("ValidateShed(cooldown=%d retryAfter=%d) = %v, wantErr %v", tc.cooldown, tc.retryAfter, err, tc.wantErr)
			}
		})
	}
}

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
	"time"
)

// TestLoadConfigSchedulingPolicy verifies scheduling.policy + duty_hard
// parsing, the binpack default, and rejection of invalid values.
func TestLoadConfigSchedulingPolicy(t *testing.T) {
	write := func(t *testing.T, body string) string {
		t.Helper()
		dir := t.TempDir()
		p := filepath.Join(dir, "config.yaml")
		if err := os.WriteFile(p, []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
		return p
	}

	base := `
listen_addr: "127.0.0.1:5353"
domains:
  agent: agent.sandswap.local
  stream: stream.sandswap.local
  sandfs: sandfs.sandswap.local
etcd: "http://localhost:2379"
`

	// No scheduling section → binpack default + default duty_hard.
	cfg, err := LoadConfig(write(t, base))
	if err != nil {
		t.Fatalf("load (default): %v", err)
	}
	if cfg.Scheduling.Policy != PolicyBinpack {
		t.Errorf("default policy = %q, want %q", cfg.Scheduling.Policy, PolicyBinpack)
	}
	if cfg.Scheduling.DutyHard != DutyHardDefault {
		t.Errorf("default duty_hard = %v, want %v", cfg.Scheduling.DutyHard, DutyHardDefault)
	}

	// Explicit binpack + custom duty_hard.
	cfg, err = LoadConfig(write(t, base+"\nscheduling:\n  policy: binpack\n  duty_hard: 0.9\n"))
	if err != nil {
		t.Fatalf("load (binpack): %v", err)
	}
	if cfg.Scheduling.Policy != PolicyBinpack {
		t.Errorf("binpack policy = %q, want %q", cfg.Scheduling.Policy, PolicyBinpack)
	}
	if cfg.Scheduling.DutyHard != 0.9 {
		t.Errorf("custom duty_hard = %v, want 0.9", cfg.Scheduling.DutyHard)
	}

	// Explicit duty_hard: 0 disables the cap.
	cfg, err = LoadConfig(write(t, base+"\nscheduling:\n  duty_hard: 0\n"))
	if err != nil {
		t.Fatalf("load (duty_hard 0): %v", err)
	}
	if cfg.Scheduling.DutyHard != 0 {
		t.Errorf("duty_hard 0 should disable the cap, got %v", cfg.Scheduling.DutyHard)
	}

	// Explicit spread.
	cfg, err = LoadConfig(write(t, base+"\nscheduling:\n  policy: spread\n"))
	if err != nil {
		t.Fatalf("load (spread): %v", err)
	}
	if cfg.Scheduling.Policy != PolicySpread {
		t.Errorf("spread policy = %q, want %q", cfg.Scheduling.Policy, PolicySpread)
	}

	// Invalid policy → rejected.
	if _, err := LoadConfig(write(t, base+"\nscheduling:\n  policy: random\n")); err == nil {
		t.Error("expected invalid policy to fail validation")
	} else if !strings.Contains(err.Error(), "scheduling.policy") {
		t.Errorf("expected scheduling.policy error, got %v", err)
	}

	// Out-of-range duty_hard → rejected.
	if _, err := LoadConfig(write(t, base+"\nscheduling:\n  duty_hard: 1.5\n")); err == nil {
		t.Error("expected out-of-range duty_hard to fail validation")
	}
}

// TestSchedulingConfigNormalized verifies Normalized maps empty/unknown to
// binpack and keeps spread.
func TestSchedulingConfigNormalized(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"", PolicyBinpack},
		{PolicySpread, PolicySpread},
		{PolicyBinpack, PolicyBinpack},
		{"whatever", PolicyBinpack}, // unknown → binpack
	}
	for _, c := range cases {
		if got := (SchedulingConfig{Policy: c.in}).Normalized().Policy; got != c.want {
			t.Errorf("Normalized(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// writeConfig is a test helper: writes body to a temp config.yaml and returns
// its path. Reused across the validation/default tests below.
func writeConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(p, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	return p
}

// A complete, valid config used as the base for the validation tests. Each
// validation case removes exactly one required field and asserts the load
// fails with a message naming that field. There is NO gateways section:
// gateway candidates are self-registered via etcd, never configured.
const validConfig = `
listen_addr: "127.0.0.1:5353"
domains:
  agent: agent.sandswap.local
  stream: stream.sandswap.local
  sandfs: sandfs.sandswap.local
etcd: "http://localhost:2379"
`

// TestLoadConfigValidation verifies every required-field check rejects the
// config with a message naming the field. Each subtest mutates exactly one
// field so a regression that loosens one check is caught independently.
//
// NOTE: listen_addr is intentionally absent here - it is defaulted to
// "0.0.0.0:53" BEFORE unmarshal, so the `if cfg.ListenAddr == ""` guard in
// LoadConfig is unreachable dead code (see TestLoadConfigListenAddrDefault).
func TestLoadConfigValidation(t *testing.T) {
	cases := []struct {
		name      string
		mutate    func(s string) string
		wantInErr string
	}{
		{"missing stream domain", func(s string) string { return strings.Replace(s, "stream: stream.sandswap.local", "# stream:", 1) }, "domains.stream"},
		{"missing etcd", func(s string) string { return strings.Replace(s, "etcd:", "#etcd:", 1) }, "etcd"},
		{"ttl zero", func(s string) string { return s + "\nttl: 0\n" }, "ttl"},
		{"ttl negative", func(s string) string { return s + "\nttl: -5\n" }, "ttl"},
		{"ttl too large", func(s string) string { return s + "\nttl: 100000\n" }, "ttl"},
		{"sticky_expire zero", func(s string) string { return s + "\nsticky_expire: 0\n" }, "sticky_expire"},
		{"sticky_sync_interval zero (ticker panic)", func(s string) string { return s + "\nsticky_sync_interval: 0\n" }, "sticky_sync_interval"},
		{"sticky_sync_batch negative", func(s string) string { return s + "\nsticky_sync_batch: -1\n" }, "sticky_sync_batch"},
		{"forwarder without port", func(s string) string { return s + "\nforwarders:\n  - 8.8.8.8\n" }, "forwarders"},
		{"agent equals stream", func(s string) string {
			return strings.Replace(s, "agent: agent.sandswap.local", "agent: stream.sandswap.local", 1)
		}, "must differ"},
		{"agent inside sandfs zone", func(s string) string {
			return strings.Replace(s, "agent: agent.sandswap.local", "agent: x.sandfs.sandswap.local", 1)
		}, "sandfs zone"},
		{"stream inside sandfs zone", func(s string) string {
			return strings.Replace(s, "stream: stream.sandswap.local", "stream: x.sandfs.sandswap.local", 1)
		}, "sandfs zone"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := LoadConfig(writeConfig(t, c.mutate(validConfig)))
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", c.wantInErr)
			}
			if !strings.Contains(err.Error(), c.wantInErr) {
				t.Errorf("expected error containing %q, got %v", c.wantInErr, err)
			}
		})
	}
}

// TestLoadConfigTrailingDotNormalized verifies a trailing dot on a domain is
// normalized away (queries are compared after their own trailing dot is
// trimmed — an unnormalized config value would silently never match).
func TestLoadConfigTrailingDotNormalized(t *testing.T) {
	cfg, err := LoadConfig(writeConfig(t, `
domains:
  stream: stream.sandswap.local.
etcd: "http://localhost:2379"
`))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Domains.Stream != "stream.sandswap.local" {
		t.Errorf("trailing dot not normalized: %q", cfg.Domains.Stream)
	}
}

// TestLoadConfigListenAddrDefault documents that listen_addr is OPTIONAL and
// defaults to "0.0.0.0:53" (the wildcard bind that coexists with
// systemd-resolved's 127.0.0.53:53 via ReuseAddr). LoadConfig's
// `if cfg.ListenAddr == ""` guard is therefore unreachable - kept as a
// defensive no-op, not a real requirement.
func TestLoadConfigListenAddrDefault(t *testing.T) {
	cfg, err := LoadConfig(writeConfig(t, `
domains:
  agent: agent.sandswap.local
  stream: stream.sandswap.local
etcd: "http://localhost:2379"
`))
	if err != nil {
		t.Fatalf("listen_addr omitted should load with default: %v", err)
	}
	if cfg.ListenAddr != "0.0.0.0:53" {
		t.Errorf("omitted listen_addr = %q, want default 0.0.0.0:53", cfg.ListenAddr)
	}
}

// TestLoadConfigStrictUnknownKey verifies parsing is STRICT: an unknown YAML
// key (here the dead "gateways:" section from the pre-self-registration era)
// fails at startup instead of being silently ignored.
func TestLoadConfigStrictUnknownKey(t *testing.T) {
	body := validConfig + `
gateways:
  - addr: "10.0.1.1:3000"
    stream_addr: "10.0.1.1:9998"
`
	if _, err := LoadConfig(writeConfig(t, body)); err == nil {
		t.Fatal("strict parsing must reject unknown keys (gateways: section)")
	}
}

// TestLoadConfigDefaults verifies the built-in defaults are applied when the
// YAML omits them. These defaults are the operational contract (e.g.
// StickyExpire=1800s bounds how long a client sticks to a dead gateway).
func TestLoadConfigDefaults(t *testing.T) {
	cfg, err := LoadConfig(writeConfig(t, validConfig))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	cases := []struct {
		name      string
		got, want interface{}
	}{
		{"ListenAddr", cfg.ListenAddr, "127.0.0.1:5353"},
		{"TTL", cfg.TTL, 10},
		{"StickyExpire", cfg.StickyExpire, 1800},
		{"StickySyncInterval", cfg.StickySyncInterval, 5},
		{"StickySyncBatch", cfg.StickySyncBatch, 256},
		{"Scheduling.Policy", cfg.Scheduling.Policy, PolicyBinpack},
		{"Scheduling.DutyHard", cfg.Scheduling.DutyHard, DutyHardDefault},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", c.name, c.got, c.want)
		}
	}
}

// TestLoadConfigKnobDefaults verifies the sizing-knob defaults: they are the
// large-fleet operational contract (a million-entry owner cache and a 30s
// revalidation TTL keep a million actively-queried sandfs inside etcd's
// serializable-read comfort zone), so a change here is a deliberate scale
// decision, not a tweak.
func TestLoadConfigKnobDefaults(t *testing.T) {
	cfg, err := LoadConfig(writeConfig(t, validConfig))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Owners.CacheMax != 1000000 {
		t.Errorf("owners.cache_max default = %d, want 1000000", cfg.Owners.CacheMax)
	}
	if cfg.Owners.CacheTTLSec != 30 {
		t.Errorf("owners.cache_ttl_sec default = %d, want 30", cfg.Owners.CacheTTLSec)
	}
	if cfg.Owners.NegCacheTTLSec != 1 {
		t.Errorf("owners.neg_cache_ttl_sec default = %d, want 1", cfg.Owners.NegCacheTTLSec)
	}
	if cfg.Owners.EtcdTimeoutMs != 2000 {
		t.Errorf("owners.etcd_timeout_ms default = %d, want 2000", cfg.Owners.EtcdTimeoutMs)
	}
	if cfg.Owners.GetConcurrency != 256 {
		t.Errorf("owners.get_concurrency default = %d, want 256", cfg.Owners.GetConcurrency)
	}
	if cfg.Owners.RateLimitPerSource != 100 {
		t.Errorf("owners.rate_limit_per_source default = %d, want 100", cfg.Owners.RateLimitPerSource)
	}
	if cfg.Owners.RateLimitGlobal != 50000 {
		t.Errorf("owners.rate_limit_global default = %d, want 50000", cfg.Owners.RateLimitGlobal)
	}
	if cfg.StickyMax != 65536 {
		t.Errorf("sticky_max default = %d, want 65536", cfg.StickyMax)
	}
	if cfg.MaxConcurrentQueries != 2048 {
		t.Errorf("max_concurrent_queries default = %d, want 2048", cfg.MaxConcurrentQueries)
	}
	if cfg.ForwardConcurrency != 128 {
		t.Errorf("forward_concurrency default = %d, want 128", cfg.ForwardConcurrency)
	}
	if cfg.TCPMaxConns != 256 {
		t.Errorf("tcp_max_conns default = %d, want 256", cfg.TCPMaxConns)
	}
}

// TestLoadConfigKnobValidation verifies out-of-range sizing knobs are
// rejected at load time (they construct tickers/semaphores or guard memory
// bounds — nonsense values must fail visibly, not silently disable a bound).
func TestLoadConfigKnobValidation(t *testing.T) {
	cases := []struct {
		key   string
		value string
	}{
		{"owners.cache_max", "999"},
		{"owners.cache_ttl_sec", "0"},
		{"owners.cache_ttl_sec", "3601"},
		{"owners.neg_cache_ttl_sec", "0"},
		{"owners.etcd_timeout_ms", "50"},
		{"owners.get_concurrency", "-1"},
		{"owners.rate_limit_per_source", "-1"},
		{"owners.rate_limit_global", "-1"},
		{"sticky_max", "0"},
		{"max_concurrent_queries", "8"},
		{"forward_concurrency", "-1"},
		{"tcp_max_conns", "0"},
	}
	for _, c := range cases {
		body := "etcd: http://127.0.0.1:2379\ndomains:\n  stream: s.svc\n" + c.key + ": " + c.value + "\n"
		if _, err := LoadConfig(writeConfig(t, body)); err == nil {
			t.Errorf("%s: %s should be rejected", c.key, c.value)
		}
	}
}

// TestApplyOperationalKnobs verifies the startup wiring copies the validated
// config into the operational package knobs (the serving paths and the
// semaphores read them); defaults are restored afterwards so other tests are
// unaffected.
func TestApplyOperationalKnobs(t *testing.T) {
	body := `etcd: http://127.0.0.1:2379
domains:
  stream: s.svc
owners:
  cache_max: 5000
  cache_ttl_sec: 7
  neg_cache_ttl_sec: 2
  etcd_timeout_ms: 500
  get_concurrency: 9
  rate_limit_per_source: 13
  rate_limit_global: 17
sticky_max: 4096
max_concurrent_queries: 64
forward_concurrency: 7
tcp_max_conns: 16
`
	cfg, err := LoadConfig(writeConfig(t, body))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	defer func() {
		def, derr := LoadConfig(writeConfig(t, validConfig))
		if derr != nil {
			t.Fatalf("reload defaults: %v", derr)
		}
		def.ApplyOperationalKnobs()
	}()

	cfg.ApplyOperationalKnobs()
	if ownerLRUMax != 5000 || ownerCacheTTL != 7*time.Second || ownerNegCacheTTL != 2*time.Second {
		t.Errorf("owner knobs not applied: max=%d ttl=%v neg=%v", ownerLRUMax, ownerCacheTTL, ownerNegCacheTTL)
	}
	if ownerEtcdTimeout != 500*time.Millisecond || ownerGetConcurrency != 9 {
		t.Errorf("owner etcd knobs not applied: timeout=%v conc=%d", ownerEtcdTimeout, ownerGetConcurrency)
	}
	if ownerRatePerSource != 13 || ownerRateGlobal != 17 {
		t.Errorf("owner rate-limit knobs not applied: src=%d global=%d", ownerRatePerSource, ownerRateGlobal)
	}
	if stickyMax != 4096 || maxConcurrentQueries != 64 || forwardConcurrency != 7 || maxTCPConns != 16 {
		t.Errorf("server knobs not applied: sticky=%d q=%d fwd=%d tcp=%d",
			stickyMax, maxConcurrentQueries, forwardConcurrency, maxTCPConns)
	}
}

// guest_cidrs is the guest-relay gate's source list: malformed entries must
// refuse startup (a silently empty list would re-open the relay for guests).
func TestLoadConfigGuestCIDRs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dns.yaml")
	base := "domains:\n  stream: stream.sandswap.local\n  sandfs: sandfs.sandswap.local\netcd: 127.0.0.1:2379\n"
	if err := os.WriteFile(path, []byte(base+"guest_cidrs: [\"10.188.0.0/16\", \"fd00::/64\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if len(cfg.GuestCIDRs) != 2 || cfg.GuestCIDRs[0] != "10.188.0.0/16" {
		t.Fatalf("guest_cidrs = %v", cfg.GuestCIDRs)
	}
	if err := os.WriteFile(path, []byte(base+"guest_cidrs: [\"not-a-cidr\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("a malformed guest_cidrs entry must be refused")
	}
}

// TestApplyReloadConfig pins the hot-reload decode target: the reload parses
// the REAL config file (a full Config), so strict decoding does not reject the
// file's unrelated keys, while unknown keys are still refused. A shadow struct
// carrying only the hot sections rejected every real file at its first
// unrelated key, so no edit ever hot-applied.
func TestApplyReloadConfig(t *testing.T) {
	s := &DNSServer{}
	full := []byte(`listen_addr: "127.0.0.1:5353"
domains:
  stream: stream.example
  sandfs: sandfs.example
etcd: http://127.0.0.1:2379
ttl: 10
scheduling:
  policy: spread
  duty_hard: 0.5
staleness:
  route_stale_sec: 7
`)
	applyReloadConfig(s, full)
	if s.schedConfig == nil {
		t.Fatal("scheduling was not hot-applied from a full config file")
	}
	if got := s.schedConfig.Get(); got.Policy != PolicySpread || got.DutyHard != 0.5 {
		t.Fatalf("scheduling hot-apply = %+v, want spread/0.5", got)
	}
	if s.routeStaleThreshold != 7*time.Second {
		t.Fatalf("route_stale_sec hot-apply = %v, want 7s", s.routeStaleThreshold)
	}

	// An unknown key must be refused and leave the live values untouched.
	bad := append(append([]byte(nil), full...), []byte("not_a_key: 1\n")...)
	applyReloadConfig(s, bad)
	if got := s.schedConfig.Get(); got.Policy != PolicySpread || got.DutyHard != 0.5 {
		t.Fatalf("a rejected reload changed scheduling: %+v", got)
	}
	if s.routeStaleThreshold != 7*time.Second {
		t.Fatalf("a rejected reload changed route_stale_sec: %v", s.routeStaleThreshold)
	}
}

// TestLoadConfigRefusesSelfForwarder pins the startup refusal of a forwarder
// that points back at this resolver's own listen port: the query would
// re-enter the process and hold a forward slot until timeout. Loopback,
// localhost, and this host's own addresses are provable self-references; a
// forwarder on a different port (e.g. a local stub resolver) stays legal.
func TestLoadConfigRefusesSelfForwarder(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dns.yaml")
	base := "listen_addr: \"0.0.0.0:5353\"\ndomains:\n  stream: stream.sandswap.local\netcd: 127.0.0.1:2379\n"
	write := func(body string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(base+body), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	for _, self := range []string{
		"127.0.0.1:5353",
		"localhost:5353",
		"[::1]:5353",
	} {
		write("forwarders: [\"" + self + "\"]\n")
		if _, err := LoadConfig(path); err == nil {
			t.Errorf("forwarder %q points at the resolver's own listen port; startup must refuse it", self)
		}
	}

	// A different port is not a self-reference (a local stub resolver shape),
	// and a remote upstream is always legal.
	write("forwarders: [\"127.0.0.1:53\", \"8.8.8.8:5353\"]\n")
	if _, err := LoadConfig(path); err != nil {
		t.Fatalf("non-self forwarders must be accepted: %v", err)
	}

	// A specific-address listener only receives its OWN address: the same
	// address/name on the same port is self, a remote host on that port is not.
	baseLoop := "listen_addr: \"127.0.0.1:5353\"\ndomains:\n  stream: stream.sandswap.local\netcd: 127.0.0.1:2379\n"
	writeBody := func(body string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(baseLoop+body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, self := range []string{"127.0.0.1:5353", "localhost:5353"} {
		writeBody("forwarders: [\"" + self + "\"]\n")
		if _, err := LoadConfig(path); err == nil {
			t.Errorf("forwarder %q reaches the specific loopback listener; startup must refuse it", self)
		}
	}
	writeBody("forwarders: [\"8.8.8.8:5353\", \"192.0.2.10:5353\"]\n")
	if _, err := LoadConfig(path); err != nil {
		t.Fatalf("remote forwarders on the listen port must be accepted: %v", err)
	}
}

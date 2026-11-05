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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDefaults verifies the built-in Global defaults.
func TestDefaults(t *testing.T) {
	g := Defaults()
	if g.RunDir != "./run" || g.BinDir != "./output" {
		t.Errorf("dir defaults: %+v", g)
	}
	if g.GatewayURL != "http://127.0.0.1:3000" || g.HumanURL != "http://127.0.0.1:3100" {
		t.Errorf("url defaults: %+v", g)
	}
	if g.DNSAddr != "127.0.0.1:8053" || g.Etcd != "http://127.0.0.1:2379" {
		t.Errorf("addr defaults: %+v", g)
	}
}

// TestGlobalPathHelpers verifies the client-side path layout and CertPath's
// absolute-path passthrough.
func TestGlobalPathHelpers(t *testing.T) {
	g := Defaults()
	cases := []struct{ got, want string }{
		{g.CertsDir(), "run/certs"},
		{g.AgentsFile(), "run/agents.json"},
	}
	for _, c := range cases {
		if c.got != filepath.FromSlash(c.want) {
			t.Errorf("got %q, want %q", c.got, c.want)
		}
	}
	if got := g.CertPath("/abs/ca.crt"); got != "/abs/ca.crt" {
		t.Errorf("absolute cert path should pass through, got %q", got)
	}
	if got := g.CertPath("ca.crt"); !strings.HasSuffix(got, filepath.Join("run", "certs", "ca.crt")) {
		t.Errorf("relative cert path should resolve under CertsDir, got %q", got)
	}
}

func TestSplitHostPort(t *testing.T) {
	cases := []struct {
		addr, def, host, port string
	}{
		{"127.0.0.1:8053", "53", "127.0.0.1", "8053"},
		{"example.com", "53", "example.com", "53"},
		{"[::1]:9998", "53", "[::1]", "9998"},
	}
	for _, c := range cases {
		h, p := splitHostPort(c.addr, c.def)
		if h != c.host || p != c.port {
			t.Errorf("splitHostPort(%q,%q) = (%q,%q), want (%q,%q)", c.addr, c.def, h, p, c.host, c.port)
		}
	}
}

func TestApplyGlobalFlag(t *testing.T) {
	g := Defaults()
	explicit := map[string]bool{}
	applyGlobalFlag(&g, explicit, "gateway-url", "https://gw:3000")
	applyGlobalFlag(&g, explicit, "human-url", "https://gw:3100")
	applyGlobalFlag(&g, explicit, "tls", "true")
	applyGlobalFlag(&g, explicit, "run-dir", "/tmp/run")
	applyGlobalFlag(&g, explicit, "bin-dir", "/tmp/bin")
	applyGlobalFlag(&g, explicit, "ca", "/etc/ca.crt")
	applyGlobalFlag(&g, explicit, "insecure", "true")
	if g.GatewayURL != "https://gw:3000" || g.HumanURL != "https://gw:3100" ||
		!g.TLS || g.RunDir != "/tmp/run" || g.BinDir != "/tmp/bin" ||
		g.CA != "/etc/ca.crt" || !g.Insecure {
		t.Errorf("applyGlobalFlag mismatch: %+v", g)
	}
	if !explicit["gateway-url"] || !explicit["tls"] {
		t.Errorf("explicit set not recorded: %v", explicit)
	}
	// globalFlagSpec and applyGlobalFlag must agree on the flag catalogue.
	for name := range globalFlagSpec {
		if name == "raw" || name == "dry-run" || name == "tls" || name == "insecure" {
			continue
		}
		if !explicit[name] {
			if _, ok := globalFlagSpec[name]; !ok {
				t.Errorf("flag %q missing from the spec", name)
			}
		}
	}
}

func TestAgentStoreRoundtrip(t *testing.T) {
	g := Defaults()
	g.RunDir = t.TempDir()

	rec := AgentRecord{AgentID: "a1", APIKey: "sk-xyz", Name: "test"}
	if err := addAgent(g, rec); err != nil {
		t.Fatalf("addAgent: %v", err)
	}
	// Dedup/update by id.
	rec.APIKey = "sk-rotated"
	if err := addAgent(g, rec); err != nil {
		t.Fatalf("addAgent update: %v", err)
	}
	recs := loadAgents(g)
	if len(recs) != 1 || recs[0].APIKey != "sk-rotated" {
		t.Errorf("expected single updated record, got %+v", recs)
	}

	key, err := resolveAgentKey(g, "a1", "")
	if err != nil || key != "sk-rotated" {
		t.Errorf("resolveAgentKey lookup: got (%q,%v)", key, err)
	}
	key, err = resolveAgentKey(g, "", "sk-explicit")
	if err != nil || key != "sk-explicit" {
		t.Errorf("explicit key must win: got (%q,%v)", key, err)
	}
	if _, err := resolveAgentKey(g, "", ""); err == nil {
		t.Error("no agent and no key should error")
	}
	if _, err := resolveAgentKey(g, "ghost", ""); err == nil {
		t.Error("unknown agent should error")
	}
}

// ── HTTP client against httptest.Server ────────────────────────

// TestRequestAgainstServer sends real requests through request() at an
// httptest.Server and checks method/path/body/auth/header handling end to end.
func TestRequestAgainstServer(t *testing.T) {
	var seen struct {
		method, path, auth, header string
		body                       map[string]any
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.method, seen.path = r.Method, r.URL.Path
		seen.auth = r.Header.Get("Authorization")
		seen.header = r.Header.Get("X-Ops")
		if r.Body != nil {
			var m map[string]any
			json.NewDecoder(r.Body).Decode(&m)
			seen.body = m
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true,"count":2}`))
	}))
	defer srv.Close()

	g := Global{}
	data, status, err := g.request(srv.URL, "post", "/agent/execute",
		map[string]any{"code": "echo hi"}, "tok123",
		map[string]string{"X-Ops": "1"})
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if status != 200 {
		t.Errorf("status = %d, want 200", status)
	}
	if seen.method != "POST" || seen.path != "/agent/execute" {
		t.Errorf("method/path: %s %s", seen.method, seen.path)
	}
	if seen.auth != "Bearer tok123" {
		t.Errorf("auth header: %q", seen.auth)
	}
	if seen.header != "1" {
		t.Errorf("extra header: %q", seen.header)
	}
	if seen.body["code"] != "echo hi" {
		t.Errorf("body: %v", seen.body)
	}
	var resp map[string]any
	if json.Unmarshal(data, &resp) != nil || resp["ok"] != true {
		t.Errorf("response body: %s", data)
	}
}

// TestRequestTrailingSlashBase verifies baseURL trailing slashes are trimmed.
func TestRequestTrailingSlashBase(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			t.Errorf("path = %q, want /health", r.URL.Path)
		}
		w.Write([]byte("{}"))
	}))
	defer srv.Close()
	g := Global{}
	if _, status, err := g.request(srv.URL+"/", "GET", "/health", nil, "", nil); err != nil || status != 200 {
		t.Errorf("request with trailing slash base failed: status=%d err=%v", status, err)
	}
}

// TestPrintRespRawAndErrorStatus exercises printResp output modes (raw JSON vs
// pretty-printed) and the stderr path for non-2xx statuses.
func TestPrintRespRawAndErrorStatus(t *testing.T) {
	g := Global{Raw: true}
	out := captureStdout(t, func() { g.printResp([]byte(`{"a":1}`), 200) })
	if strings.TrimSpace(out) != `{"a":1}` {
		t.Errorf("raw mode: got %q", out)
	}

	g.Raw = false
	out = captureStdout(t, func() { g.printResp([]byte(`{"a":1}`), 200) })
	if !strings.Contains(out, "\"a\": 1") {
		t.Errorf("pretty mode: got %q", out)
	}

	out = captureStdout(t, func() { g.printResp(nil, 200) })
	if strings.TrimSpace(out) != "(empty body)" {
		t.Errorf("empty body: got %q", out)
	}
}

// captureStdout swaps os.Stdout, runs fn, and returns what was printed.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	fn()
	os.Stdout = old
	w.Close()
	buf := make([]byte, 4096)
	n, _ := r.Read(buf)
	return string(buf[:n])
}

func TestAbsRunDir(t *testing.T) {
	g := Defaults()
	g.RunDir = t.TempDir()
	if !filepath.IsAbs(g.absRunDir()) {
		t.Errorf("absRunDir = %q, want absolute", g.absRunDir())
	}
}

func TestEtcdClientURL(t *testing.T) {
	g := Defaults()
	if got := g.etcdClientURL(); got != "http://127.0.0.1:2379" {
		t.Errorf("plain: %q", got)
	}
	g.TLS = true
	if got := g.etcdClientURL(); got != "https://127.0.0.1:2379" {
		t.Errorf("tls: %q", got)
	}

	// An explicit remote --etcd must reach every consumer verbatim.
	g.Etcd = "https://etcd.prod.internal:2379"
	if got := g.etcdClientURL(); got != "https://etcd.prod.internal:2379" {
		t.Errorf("remote: %q", got)
	}
	g.TLS = false
	if got := g.etcdClientURL(); got != "https://etcd.prod.internal:2379" {
		t.Errorf("remote (plain tls off): %q", got)
	}
	// A remote endpoint on a non-default port is remote too.
	g.Etcd = "http://10.0.0.5:12379"
	if got := g.etcdClientURL(); got != "http://10.0.0.5:12379" {
		t.Errorf("remote port: %q", got)
	}
	// The loopback default stays "this deployment's etcd": scheme follows --tls.
	g.Etcd = "http://127.0.0.1:2379"
	g.TLS = true
	if got := g.etcdClientURL(); got != "https://127.0.0.1:2379" {
		t.Errorf("loopback default under tls: %q", got)
	}
}

// ── httpc convenience wrappers ──────────────────────────────────

func newJSONServer(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		w.Write([]byte(body))
	}))
}

func TestGetJSONPostJSONDeleteJSON(t *testing.T) {
	srv := newJSONServer(t, 200, `{"ok":true}`)
	defer srv.Close()
	g := Global{}

	out := captureStdout(t, func() { g.getJSON(srv.URL, "/x", "tok", map[string]string{"H": "v"}) })
	if !strings.Contains(out, `"ok": true`) {
		t.Errorf("getJSON output: %q", out)
	}
	out = captureStdout(t, func() { g.postJSON(srv.URL, "/y", map[string]any{"a": 1}, "", nil) })
	if !strings.Contains(out, `"ok": true`) {
		t.Errorf("postJSON output: %q", out)
	}
	out = captureStdout(t, func() { g.deleteJSON(srv.URL, "/z", "", nil) })
	if !strings.Contains(out, `"ok": true`) {
		t.Errorf("deleteJSON output: %q", out)
	}
}

// TestGetJSONAnyFirstBaseWins verifies getJSONAny stops at the first base that
// answers < 500 (health lives on different listeners per mode).
func TestGetJSONAnyFirstBaseWins(t *testing.T) {
	hitA, hitB := false, false
	a := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hitA = true
		w.Write([]byte(`{"from":"a"}`))
	}))
	defer a.Close()
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hitB = true
		w.Write([]byte(`{}`))
	}))
	defer b.Close()

	g := Global{}
	out := captureStdout(t, func() { g.getJSONAny("/health", a.URL, b.URL) })
	if !hitA || hitB {
		t.Errorf("expected only base A probed, got a=%v b=%v", hitA, hitB)
	}
	if !strings.Contains(out, `"from": "a"`) {
		t.Errorf("output: %q", out)
	}
}

func TestBearerForAndAPIHeader(t *testing.T) {
	g := Global{}
	if k := bearerFor(g, "", "sk-explicit"); k != "sk-explicit" {
		t.Errorf("bearerFor explicit: %q", k)
	}
	if apiHeader(g) != nil {
		t.Error("apiHeader should return nil")
	}
}

func TestPrintClusterReport(t *testing.T) {
	rep := clusterReport{}
	rep.Gateways = append(rep.Gateways, clusterGatewayStats{
		GatewayID: "gw-a", Healthy: true, GatewayURL: "http://127.0.0.1:3000",
		NodeCount: 2, CleanVMs: 5, TotalVMs: 8, AggDutyLong: 0.42,
	})
	rep.Totals.CleanVMs = 5
	rep.Totals.TotalVMs = 8
	rep.Totals.InUseVMs = 3
	rep.Totals.NodeCount = 2
	rep.Totals.GatewayCnt = 1

	out := captureStdout(t, func() { printClusterReport(Global{}, rep, false) })
	for _, want := range []string{"CLUSTER  1 gateway(s)", "gw-a", "up"} {
		if !strings.Contains(out, want) {
			t.Errorf("table output missing %q:\n%s", want, out)
		}
	}

	out = captureStdout(t, func() { printClusterReport(Global{}, rep, true) })
	if !strings.Contains(out, `"gateway_id": "gw-a"`) {
		t.Errorf("raw output should be JSON:\n%s", out)
	}
}

func TestNewFlagSetParses(t *testing.T) {
	fs := newFlagSet("health-all")
	if err := fs.Parse(nil); err != nil {
		t.Errorf("parse: %v", err)
	}
}

func TestFindCachedEtcdctlNoPanic(t *testing.T) {
	p := findCachedEtcdctl()
	if p != "" {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("findCachedEtcdctl returned %q which does not exist", p)
		}
	}
}

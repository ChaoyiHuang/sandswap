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

// apiRecorder records the last request seen by the fake gateway/human server.
type apiRecorder struct {
	method, path, auth string
	body               map[string]any
}

func newRecordingServer(t *testing.T) (*httptest.Server, *apiRecorder) {
	t.Helper()
	rec := &apiRecorder{body: map[string]any{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.method = r.Method
		rec.path = r.URL.Path
		rec.auth = r.Header.Get("Authorization")
		var m map[string]any
		json.NewDecoder(r.Body).Decode(&m)
		if m == nil {
			m = map[string]any{}
		}
		rec.body = m
		w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(srv.Close)
	return srv, rec
}

func TestAPIExecute(t *testing.T) {
	srv, rec := newRecordingServer(t)
	g := Global{GatewayURL: srv.URL}
	captureStdout(t, func() {
		apiExecute(g, []string{"-code", "echo hi", "-sandfs", "sf1", "-api-key", "sk1",
			"-language", "python", "-timeout", "30"})
	})
	if rec.method != "POST" || rec.path != "/agent/execute" {
		t.Errorf("method/path: %s %s", rec.method, rec.path)
	}
	if rec.auth != "Bearer sk1" {
		t.Errorf("auth: %q", rec.auth)
	}
	if rec.body["code"] != "echo hi" || rec.body["sandfs_id"] != "sf1" ||
		rec.body["language"] != "python" || rec.body["timeout"] != float64(30) {
		t.Errorf("body: %v", rec.body)
	}
}

func TestAPIExecuteBackgroundFlags(t *testing.T) {
	srv, rec := newRecordingServer(t)
	g := Global{GatewayURL: srv.URL}
	captureStdout(t, func() {
		apiExecute(g, []string{"-code", "x", "-sandfs", "sf1", "-api-key", "k", "-background", "-lease", "600"})
	})
	if rec.body["background"] != true || rec.body["lease_duration"] != float64(600) {
		t.Errorf("body: %v", rec.body)
	}
}

func TestAPIExecStatusAndKill(t *testing.T) {
	g := Global{}

	srv1, rec1 := newRecordingServer(t)
	g.GatewayURL = srv1.URL
	// Documented order: positional first, flags after.
	captureStdout(t, func() { apiExecStatus(g, []string{"bg-1", "-api-key", "k", "-sandfs", "sf1"}) })
	if rec1.path != "/agent/exec/status" {
		t.Errorf("exec-status path: %s", rec1.path)
	}
	if rec1.body["exec_id"] != "bg-1" || rec1.body["sandfs_id"] != "sf1" {
		t.Errorf("exec-status body: %v", rec1.body)
	}

	srv2, rec2 := newRecordingServer(t)
	g.GatewayURL = srv2.URL
	// Flags-first order must still work and take the trailing positional.
	captureStdout(t, func() { apiExecKill(g, []string{"-api-key", "k", "-sandfs", "sf1", "bg-2"}) })
	if rec2.path != "/agent/exec/kill" {
		t.Errorf("exec-kill path: %s", rec2.path)
	}
	if rec2.body["exec_id"] != "bg-2" || rec2.body["sandfs_id"] != "sf1" {
		t.Errorf("exec-kill body: %v", rec2.body)
	}
}

func TestAPIFileActions(t *testing.T) {
	srv, rec := newRecordingServer(t)
	g := Global{GatewayURL: srv.URL, HumanURL: srv.URL}

	cases := []struct {
		args     []string
		path     string
		checkKey string
	}{
		{[]string{"-action", "write", "-path", "a.txt", "-data", "hello"}, "/agent/file", "data"},
		{[]string{"-action", "read", "-path", "a.txt", "-offset", "4", "-length", "10"}, "/agent/file", "length"},
		{[]string{"-action", "rename", "-path", "a.txt", "-new-path", "b.txt"}, "/agent/file", "new_path"},
		{[]string{"-action", "mkdir", "-path", "d", "-mode", "493"}, "/agent/file", "mode"},
		{[]string{"-action", "remove", "-path", "d", "-recursive"}, "/agent/file", "recursive"},
		{[]string{"-action", "list_dir", "-path", ".", "-depth", "3"}, "/agent/file", "depth"},
		{[]string{"-action", "stat", "-path", "a.txt"}, "/agent/file", ""},
	}
	for _, c := range cases {
		rec.body = map[string]any{}
		full := append([]string{"-sandfs", "sf1", "-api-key", "k"}, c.args...)
		captureStdout(t, func() { apiFile(g, full) })
		if rec.path != c.path {
			t.Errorf("%v: path = %s", c.args, rec.path)
		}
		if c.checkKey != "" {
			if _, ok := rec.body[c.checkKey]; !ok {
				t.Errorf("%v: body missing %q: %v", c.args, c.checkKey, rec.body)
			}
		}
	}
}

func TestAPIAgentCommands(t *testing.T) {
	srv, rec := newRecordingServer(t)
	g := Global{HumanURL: srv.URL, RunDir: t.TempDir()}

	captureStdout(t, func() { apiAgent(g, []string{"create", "-name", "bot"}) })
	if rec.path != "/human/agent" || rec.method != "POST" {
		t.Errorf("agent create: %s %s", rec.method, rec.path)
	}
	if rec.body["name"] != "bot" {
		t.Errorf("agent create body: %v", rec.body)
	}

	captureStdout(t, func() { apiAgent(g, []string{"list"}) })
	captureStdout(t, func() { apiAgent(g, []string{"delete", "agent-9"}) })
	if rec.method != "DELETE" || !strings.HasSuffix(rec.path, "/human/agent/agent-9") {
		t.Errorf("agent delete: %s %s", rec.method, rec.path)
	}
}

func TestAPISandFSCommands(t *testing.T) {
	srv, rec := newRecordingServer(t)
	g := Global{HumanURL: srv.URL, RunDir: t.TempDir()}

	captureStdout(t, func() {
		apiSandFS(g, []string{"create", "-agent", "a1", "-name", "fs1", "-template", "ubuntu:24.04",
			"-mode", "overlay", "-description", "d1", "-vcpus", "2", "-memory-mb", "512"})
	})
	if rec.path != "/human/sandfs" || rec.body["template"] != "ubuntu:24.04" ||
		rec.body["mode"] != "overlay" || rec.body["vcpus"] != float64(2) {
		t.Errorf("sandfs create: %v %v", rec.path, rec.body)
	}

	captureStdout(t, func() { apiSandFS(g, []string{"list"}) })
	captureStdout(t, func() { apiSandFS(g, []string{"delete", "sf-1"}) })
	captureStdout(t, func() { apiSandFS(g, []string{"save-template", "sf-1", "-name", "t1", "-version", "v2"}) })
	if rec.path != "/human/sandfs/sf-1/save-template" || rec.body["template_ref"] != "t1:v2" {
		t.Errorf("save-template: %s %v", rec.path, rec.body)
	}
}

func TestAPITemplateAndOwnership(t *testing.T) {
	srv, rec := newRecordingServer(t)
	g := Global{HumanURL: srv.URL}

	captureStdout(t, func() { apiTemplate(g, []string{"list"}) })
	if rec.path != "/human/templates" {
		t.Errorf("template list path: %s", rec.path)
	}
	captureStdout(t, func() { apiTemplate(g, []string{"pull", "ubuntu:24.04"}) })
	if !strings.HasSuffix(rec.path, "/human/templates/ubuntu:24.04") {
		t.Errorf("template pull path: %s", rec.path)
	}
	captureStdout(t, func() { apiTemplate(g, []string{"push", "ubuntu:24.04"}) })
	if !strings.HasSuffix(rec.path, "/push") {
		t.Errorf("template push path: %s", rec.path)
	}
	captureStdout(t, func() { apiOwnership(g, []string{"release", "sf-1"}) })
	if !strings.HasSuffix(rec.path, "/human/ownership/release/sf-1") {
		t.Errorf("ownership release path: %s", rec.path)
	}

	// reap-stuck: posts to /human/ownership/reap-stuck with the gateway_id +
	// dry_run + batch_size body.
	srv2, rec2 := newRecordingServer(t)
	g2 := Global{HumanURL: srv2.URL}
	captureStdout(t, func() { apiOwnership(g2, []string{"reap-stuck", "gw-dead", "--dry-run", "--batch=50"}) })
	if rec2.path != "/human/ownership/reap-stuck" {
		t.Errorf("reap-stuck path: %s", rec2.path)
	}
	if rec2.body["gateway_id"] != "gw-dead" {
		t.Errorf("reap-stuck gateway_id: %v", rec2.body["gateway_id"])
	}
	if rec2.body["dry_run"] != true {
		t.Errorf("reap-stuck dry_run: %v", rec2.body["dry_run"])
	}
	if rec2.body["batch_size"] != float64(50) {
		t.Errorf("reap-stuck batch_size: %v", rec2.body["batch_size"])
	}
}

func TestCmdAPIHealthReadyStats(t *testing.T) {
	srv, _ := newRecordingServer(t)
	g := Global{GatewayURL: srv.URL, HumanURL: srv.URL}

	for _, sub := range []string{"health", "ready"} {
		out := captureStdout(t, func() { cmdAPI(g, []string{sub}) })
		if !strings.Contains(out, `"ok": true`) {
			t.Errorf("%s output: %q", sub, out)
		}
	}
	out := captureStdout(t, func() { cmdAPI(g, []string{"stats"}) })
	if !strings.Contains(out, `"ok": true`) {
		t.Errorf("stats output: %q", out)
	}
}

// captureStderr mirrors captureStdout for the deprecation-warning assertions.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w
	fn()
	os.Stderr = old
	w.Close()
	buf := make([]byte, 4096)
	n, _ := r.Read(buf)
	return string(buf[:n])
}

// TestAPIKeyFromSources pins: --api-key still works but warns by name
// (argv is world-readable via /proc/<pid>/cmdline), and the key can come from
// SANDSWAP_API_KEY or SANDSWAP_API_KEY_FILE instead.
func TestAPIKeyFromSources(t *testing.T) {
	t.Setenv("SANDSWAP_API_KEY", "")
	t.Setenv("SANDSWAP_API_KEY_FILE", "")

	// Deprecated flag: honored, warned.
	var got string
	var err error
	warn := captureStderr(t, func() {
		got, err = apiKeyFromSources("sk-flag")
	})
	if err != nil || got != "sk-flag" {
		t.Fatalf("flag key = (%q, %v), want (sk-flag, nil)", got, err)
	}
	if !strings.Contains(warn, "--api-key") || !strings.Contains(warn, "/proc/") {
		t.Errorf("deprecation warning = %q, want it to name --api-key and /proc", warn)
	}

	// Environment variable: preferred, silent.
	t.Setenv("SANDSWAP_API_KEY", "sk-env")
	warn = captureStderr(t, func() {
		got, err = apiKeyFromSources("")
	})
	if err != nil || got != "sk-env" {
		t.Fatalf("env key = (%q, %v), want (sk-env, nil)", got, err)
	}
	if warn != "" {
		t.Errorf("env path must not warn, got %q", warn)
	}

	// File form (0600 credential file): contents trimmed.
	t.Setenv("SANDSWAP_API_KEY", "")
	keyFile := filepath.Join(t.TempDir(), "key")
	if werr := os.WriteFile(keyFile, []byte("  sk-file\n"), 0o600); werr != nil {
		t.Fatal(werr)
	}
	t.Setenv("SANDSWAP_API_KEY_FILE", keyFile)
	got, err = apiKeyFromSources("")
	if err != nil || got != "sk-file" {
		t.Fatalf("file key = (%q, %v), want (sk-file, nil)", got, err)
	}

	// Nothing set: empty, no error (the caller's required-key path handles it).
	t.Setenv("SANDSWAP_API_KEY_FILE", "")
	got, err = apiKeyFromSources("")
	if err != nil || got != "" {
		t.Fatalf("unset sources = (%q, %v), want (\"\", nil)", got, err)
	}

	// Unreadable file: named error, never a silent fallthrough.
	t.Setenv("SANDSWAP_API_KEY_FILE", filepath.Join(t.TempDir(), "missing"))
	if _, err = apiKeyFromSources(""); err == nil || !strings.Contains(err.Error(), "SANDSWAP_API_KEY_FILE") {
		t.Fatalf("missing key file: err = %v, want a named error", err)
	}
}

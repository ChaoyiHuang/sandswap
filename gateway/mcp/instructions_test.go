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

package mcp

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// testLogger discards Warn/Info output — the fallback and reload paths under
// test are asserted via return values / served text, not logs.
func testLogger() *slog.Logger { return slog.New(slog.DiscardHandler) }

// TestResolveInstructions_EmptyPath verifies no path configured → built-in
// default (the no-file deployment).
func TestResolveInstructions_EmptyPath(t *testing.T) {
	got := ResolveInstructions("", testLogger())
	if got != DefaultInstructions {
		t.Errorf("empty path: got %d bytes, want DefaultInstructions", len(got))
	}
}

// TestResolveInstructions_MissingFile_MaterializesDefault verifies a
// configured-but-missing file is MATERIALIZED from the built-in default (best
// effort) so ops has a file to edit — the served text is the default either
// way. The write is atomic (temp+rename): no partial file on a mid-write crash.
func TestResolveInstructions_MissingFile_MaterializesDefault(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nope.md")
	got := ResolveInstructions(path, testLogger())
	if got != DefaultInstructions {
		t.Error("missing file: want DefaultInstructions fallback")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("missing file was not materialized: %v", err)
	}
	if trimmed := strings.TrimSpace(string(data)); trimmed != DefaultInstructions {
		t.Error("materialized file content != DefaultInstructions")
	}
	// No temp-file litter from the atomic write.
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("materialization left %d entries, want exactly the guide file", len(entries))
	}
}

// TestResolveInstructions_MissingFile_UnwritablePath verifies the
// best-effort bound: when the path cannot be written (here: its would-be
// parent is a regular file — a stand-in for the production cases: root-owned
// config dir under a non-root gateway, or the read-only k8s ConfigMap mount),
// the gateway serves the built-in default WITHOUT error and without litter.
func TestResolveInstructions_MissingFile_UnwritablePath(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	got := ResolveInstructions(filepath.Join(blocker, "nope.md"), testLogger())
	if got != DefaultInstructions {
		t.Error("unwritable path: want DefaultInstructions fallback")
	}
}

// TestResolveInstructions_NeverOverwrites verifies materialization is
// strictly create-if-missing: an existing (even empty) file is never replaced
// by the default — operator edits and in-progress states stay untouched.
func TestResolveInstructions_NeverOverwrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "guide.md")
	if err := os.WriteFile(path, []byte("operator text"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := ResolveInstructions(path, testLogger()); got != "operator text" {
		t.Errorf("existing file: got %q, want operator text", got)
	}
	data, _ := os.ReadFile(path)
	if string(data) != "operator text" {
		t.Error("existing file was modified")
	}
}

// TestResolveInstructions_ValidFile verifies a readable file's content
// (whitespace-trimmed) replaces the default.
func TestResolveInstructions_ValidFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "guide.md")
	if err := os.WriteFile(path, []byte("\n  custom deployment guide  \n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := ResolveInstructions(path, testLogger()); got != "custom deployment guide" {
		t.Errorf("got %q, want trimmed custom text", got)
	}
}

// TestResolveInstructions_EmptyFile verifies an empty/whitespace-only file
// falls back to the default WITH a signal-grade fallback (no silent empty
// instructions on initialize / sandswap_guide).
func TestResolveInstructions_EmptyFile(t *testing.T) {
	for name, content := range map[string]string{"empty": "", "whitespace": " \n\t "} {
		path := filepath.Join(t.TempDir(), "guide.md")
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		if got := ResolveInstructions(path, testLogger()); got != DefaultInstructions {
			t.Errorf("%s file: want DefaultInstructions fallback, got %q", name, got)
		}
	}
}

// TestResolveInstructions_OversizedFile verifies a file beyond the size cap
// falls back to the default instead of loading it.
func TestResolveInstructions_OversizedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "huge.md")
	big := make([]byte, maxInstructionsBytes+1)
	if err := os.WriteFile(path, big, 0o644); err != nil {
		t.Fatal(err)
	}
	if got := ResolveInstructions(path, testLogger()); got != DefaultInstructions {
		t.Error("oversized file: want DefaultInstructions fallback")
	}
}

// TestCurrentInstructions_UnsetFallsBackToDefault verifies the nil-pointer
// fallback on a zero-value server (defensive; NewMCPServer always sets it).
func TestCurrentInstructions_UnsetFallsBackToDefault(t *testing.T) {
	s := &MCPServer{}
	if got := s.currentInstructions(); got != DefaultInstructions {
		t.Error("unset instructions: want DefaultInstructions fallback")
	}
}

// TestInstructions_ServedOnInitializeAndGuide verifies the same text flows to
// both delivery channels: the initialize result's instructions field and the
// sandswap_guide tool — and that SetInstructions swaps both (hot reload).
func TestInstructions_ServedOnInitializeAndGuide(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	conn := &mcpConnection{AgentKey: env.agentKey}

	// Default: both channels serve DefaultInstructions RENDERED (the
	// {{max_exec_timeout_sec}} placeholder becomes the live sync-exec cap).
	wantDefault := renderInstructions(DefaultInstructions, env.server.liveMaxExecTimeoutSec(), env.server.liveStickyMs())
	resp := env.server.handleInitialize(ctx, conn, &jsonRPCRequest{
		JSONRPC: "2.0", ID: json.RawMessage("1"), Method: "initialize",
	})
	if resp.Error != nil {
		t.Fatalf("initialize errored: %+v", resp.Error)
	}
	res := resp.Result.(mcpInitializeResult)
	if res.Instructions != wantDefault {
		t.Errorf("initialize instructions = %.80q..., want rendered DefaultInstructions", res.Instructions)
	}
	if strings.Contains(res.Instructions, "{{") {
		t.Error("initialize instructions still contain an unsubstituted placeholder")
	}
	guide, err := env.server.dispatchToolCall(ctx, conn, "sandswap_guide", nil)
	if err != nil {
		t.Fatalf("sandswap_guide errored: %v", err)
	}
	if guide.Content[0].Text != wantDefault {
		t.Errorf("guide text = %.80q..., want rendered DefaultInstructions", guide.Content[0].Text)
	}

	// Swap (hot reload path): both channels must reflect the new text.
	env.server.SetInstructions("custom deployment guide")
	resp = env.server.handleInitialize(ctx, conn, &jsonRPCRequest{
		JSONRPC: "2.0", ID: json.RawMessage("2"), Method: "initialize",
	})
	if res := resp.Result.(mcpInitializeResult); res.Instructions != "custom deployment guide" {
		t.Errorf("initialize instructions after swap = %q", res.Instructions)
	}
	guide, err = env.server.dispatchToolCall(ctx, conn, "sandswap_guide", nil)
	if err != nil {
		t.Fatalf("sandswap_guide errored after swap: %v", err)
	}
	if guide.Content[0].Text != "custom deployment guide" {
		t.Errorf("guide text after swap = %q", guide.Content[0].Text)
	}
}

// TestInstructionsFileWatcher_HotReload verifies the watcher picks up file
// changes — twice, including a rename-style replace (write-temp + rename is
// how editors save) — and stops applying changes after ctx cancel. The
// watcher is fsnotify-driven with a 200ms debounce; waitForInstructions
// absorbs the timing.
func TestInstructionsFileWatcher_HotReload(t *testing.T) {
	env := newTestEnv(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "guide.md")
	if err := os.WriteFile(path, []byte("guide v1"), 0o644); err != nil {
		t.Fatal(err)
	}
	env.server.SetInstructions(ResolveInstructions(path, testLogger()))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	env.server.StartInstructionsFileWatcher(ctx, path, testLogger())

	waitForInstructions(t, env.server, "guide v1")

	if err := os.WriteFile(path, []byte("guide v2"), 0o644); err != nil {
		t.Fatal(err)
	}
	waitForInstructions(t, env.server, "guide v2")

	// Rename-style replace (vim write-temp + rename): different inode.
	tmp := filepath.Join(dir, ".guide.md.tmp")
	if err := os.WriteFile(tmp, []byte("guide v3"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
	waitForInstructions(t, env.server, "guide v3")

	// Cancel stops the watcher: a later change must NOT be applied.
	cancel()
	time.Sleep(300 * time.Millisecond) // let the Stop goroutine run
	if err := os.WriteFile(path, []byte("guide v4"), 0o644); err != nil {
		t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond)
	if got := env.server.currentInstructions(); got != "guide v3" {
		t.Errorf("instructions changed after watcher stop: %q", got)
	}
}

// TestInstructionsFileWatcher_VanishedFileKeepsLastText verifies a file that
// disappears mid-flight keeps the last good text instead of regressing to the
// default, and reloads when the file comes back.
func TestInstructionsFileWatcher_VanishedFileKeepsLastText(t *testing.T) {
	env := newTestEnv(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "guide.md")
	if err := os.WriteFile(path, []byte("guide v1"), 0o644); err != nil {
		t.Fatal(err)
	}
	env.server.SetInstructions(ResolveInstructions(path, testLogger()))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	env.server.StartInstructionsFileWatcher(ctx, path, testLogger())

	waitForInstructions(t, env.server, "guide v1")

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond)
	if got := env.server.currentInstructions(); got != "guide v1" {
		t.Errorf("vanished file changed served text: %q", got)
	}

	if err := os.WriteFile(path, []byte("guide v3"), 0o644); err != nil {
		t.Fatal(err)
	}
	waitForInstructions(t, env.server, "guide v3")
}

// TestInstructionsFileWatcher_EmptyEditKeepsLastText verifies that an edit
// which empties the file (truncated, whitespace-only) does not blank the
// served instructions: instructionsFromBytes falls back to the default, but
// the operator intent was an edit — serving the default is the documented
// fallback for malformed input.
func TestInstructionsFileWatcher_EmptyEditKeepsLastText(t *testing.T) {
	env := newTestEnv(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "guide.md")
	if err := os.WriteFile(path, []byte("guide v1"), 0o644); err != nil {
		t.Fatal(err)
	}
	env.server.SetInstructions(ResolveInstructions(path, testLogger()))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	env.server.StartInstructionsFileWatcher(ctx, path, testLogger())

	waitForInstructions(t, env.server, "guide v1")

	// Truncate to empty: the documented fallback (malformed input → default)
	// applies — the served text becomes the built-in default, NOT an empty
	// string that initialize's omitempty would silently drop.
	if err := os.WriteFile(path, []byte("  \n"), 0o644); err != nil {
		t.Fatal(err)
	}
	waitForInstructions(t, env.server, DefaultInstructions)
}

// waitForInstructions polls until the server serves the wanted text or times
// out (watcher swap is asynchronous by design).
func waitForInstructions(t *testing.T, s *MCPServer, want string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if s.currentInstructions() == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("instructions never became %q (current: %.40q)", want, s.currentInstructions())
}

// TestDefaultInstructionsCarriesCapPlaceholder guards the sync-cap statement:
// the built-in guide must tell agents the hard cap via the serve-time
// placeholder — an agent that never learns the cap will run 5-minute builds
// as sync execs and have them killed.
func TestDefaultInstructionsCarriesServeTimePlaceholders(t *testing.T) {
	// The sync-exec cap: an agent that never learns the cap will run 5-minute
	// builds as sync execs and have them killed.
	if !strings.Contains(DefaultInstructions, maxExecTimeoutPlaceholder) {
		t.Errorf("DefaultInstructions must contain %s (the sync-exec cap statement for agents)", maxExecTimeoutPlaceholder)
	}
	// The sticky idleness window: the swap-out timing the guide tells agents
	// about is a config value (-sticky-ms), not a constant.
	if !strings.Contains(DefaultInstructions, stickyMsPlaceholder) {
		t.Errorf("DefaultInstructions must contain %s (the idleness window statement for agents)", stickyMsPlaceholder)
	}
}

// TestRenderInstructions verifies serve-time substitution: the placeholder
// becomes the live value, and texts without it are served verbatim (custom
// files only opt in by using it).
func TestRenderInstructions(t *testing.T) {
	if got := renderInstructions("capped at "+maxExecTimeoutPlaceholder+"s", 42, 5); got != "capped at 42s" {
		t.Errorf("renderInstructions = %q, want %q", got, "capped at 42s")
	}
	if got := renderInstructions("idles after ~"+stickyMsPlaceholder+"ms", 42, 250); got != "idles after ~250ms" {
		t.Errorf("renderInstructions = %q, want %q", got, "idles after ~250ms")
	}
	if got := renderInstructions("no placeholder here", 7, 9); got != "no placeholder here" {
		t.Errorf("renderInstructions without placeholders = %q, want verbatim", got)
	}
}

// TestRenderedInstructionsTracksLiveCap verifies the served guide follows the
// HOT-RELOADED exec cap: UpdateTimeouts swaps the atomic, and the next serve
// renders the new value without touching the stored text.
func TestRenderedInstructionsTracksLiveCap(t *testing.T) {
	env := newTestEnv(t)
	if env.execH == nil {
		t.Fatal("test env has no ExecuteHandler")
	}
	env.execH.UpdateTimeouts(30, 90)
	if got := env.server.renderedInstructions(); !strings.Contains(got, "HARD-CAPPED at 90 seconds") {
		t.Errorf("rendered guide with max=90: %q", firstLineWith(got, "HARD-CAPPED"))
	}
	env.execH.UpdateTimeouts(30, 60)
	if got := env.server.renderedInstructions(); !strings.Contains(got, "HARD-CAPPED at 60 seconds") {
		t.Errorf("rendered guide with max=60: %q", firstLineWith(got, "HARD-CAPPED"))
	}
}

// TestRenderedInstructionsTracksLiveSticky verifies the same for the sticky
// idleness window: lease.UpdateTimeout (the -sticky-ms hot-reload path) swaps
// the atomic and the next serve renders the new value.
func TestRenderedInstructionsTracksLiveSticky(t *testing.T) {
	env := newTestEnv(t)
	if env.lm == nil {
		t.Fatal("test env has no Lease")
	}
	env.lm.UpdateTimeout(250 * time.Millisecond)
	if got := env.server.renderedInstructions(); !strings.Contains(got, "After ~250 ms of idleness") {
		t.Errorf("rendered guide with sticky=250ms: %q", firstLineWith(got, "of idleness"))
	}
	env.lm.UpdateTimeout(100 * time.Millisecond)
	if got := env.server.renderedInstructions(); !strings.Contains(got, "After ~100 ms of idleness") {
		t.Errorf("rendered guide with sticky=100ms: %q", firstLineWith(got, "of idleness"))
	}
}

// firstLineWith returns the first line containing s (all of it, on error).
func firstLineWith(text, s string) string {
	for _, line := range strings.Split(text, "\n") {
		if strings.Contains(line, s) {
			return line
		}
	}
	return text
}

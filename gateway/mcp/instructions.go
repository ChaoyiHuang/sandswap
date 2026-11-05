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
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	commonconfig "common/config"
)

// DefaultInstructions is the built-in MCP server instructions: the overall
// Sandswap guide returned to agents on initialize (and on the sandswap_guide
// tool). Deliberately compact — one tight statement per concept — while still
// giving an agent a full and accurate mental model. Deployments override it
// wholesale with -mcp-instructions-file (offline-editable, hot-reloaded;
// materialize the default with `gateway -print-mcp-instructions`), so the
// default only needs to be correct and self-sufficient.
//
// The {{max_exec_timeout_sec}} and {{sticky_ms}} placeholders are rendered at
// SERVE time with the gateway's live values (hot-reload aware) — both here
// and in custom instruction files — so the agent-visible numbers always match
// the enforced ones no matter what -max-exec-timeout-sec / -sticky-ms (or a
// hot-reload) set them to.
const DefaultInstructions = `Sandswap runs your commands in hardware-isolated microVM sandboxes. A SandFS is your persistent workspace: a directory on shared storage that follows you across calls — the microVM itself holds nothing.

How it works:
- Every call is stateless: your API key + sandfs_id selects the sandbox; the SandFS is mounted into a microVM and your code runs inside it.
- A call reusing the still-mounted sandbox is warm (~0.96 ms mount+exec); a fresh mount is cold (~2.3 ms). After ~{{sticky_ms}} ms of idleness the sandbox is swapped out asynchronously, off the response path.

Choosing a SandFS:
- You may own several. Call list_sandfs first — it returns your instances with sandfs_id, name, description, and template. Pick the one whose name/description matches the task, then pass that sandfs_id to EVERY exec/file call for the task: files and processes live per-SandFS, so switching ids mid-task loses your work-in-progress view.
- If nothing matches the task, say so instead of guessing. A not-found error, or a non-empty "status" in the listing (a template swap or deletion in progress), means that SandFS is briefly unavailable — re-list and retry.

Working efficiently:
- Sync execs are HARD-CAPPED at {{max_exec_timeout_sec}} seconds: a larger requested timeout is clamped and the command killed at the cap. Any command that may run longer — builds, test suites, package installs, training — MUST use background:true (with lease_duration) and be polled via exec_status.
- Reasoning between steps may let the sandbox swap out. PREFER letting it swap when you can tolerate a cold remount (~2.3 ms): a swapped-out sandbox returns its microVM to the shared pool for other agents — better resource reuse. Only for latency-critical sequences should you hold the warm path across a pause: start a background exec (e.g. sleep 60, optionally with lease_duration) — the sandbox stays mounted until it ends.
- For long work use background:true: you get an exec_id to poll with exec_status (lease_duration caps the total runtime; exec_kill cancels). A status of "not_found" means the handle was lost — stop polling; re-create the job if its work is not already in the workspace.
- Read the SandFS's self-description before exploring blindly. Two independent READMEs with two access paths: "cat /README.md" via EXEC (base-template/environment docs; read-only in overlay-mode SandFS) — the file tools CANNOT see the sandbox root, a leading "/" in a file-tool path is silently re-based onto /workspace — and /workspace/README.md via the FILE TOOLS (this instance's current task state). On conflict: /workspace = task state, / = environment layout.
- Workspace files persist across switches, restarts, and aborts. Checkpoint idempotently (temp file + rename, progress markers) so interrupted work can resume.

Failure semantics:
- A 503 with retryable:true means retry the SAME request after retry_after_ms — do not modify it.
- An error or timeout means the result is UNKNOWN, not failed: the command may have run or still be running. Read the workspace first to see what completed, then resume or roll back instead of blindly rerunning.

Your deployment may replace or extend this guide (operator-configured).`

// maxInstructionsBytes bounds a custom instructions file (1 MB): far more than
// any guide needs, and it bounds memory against a misconfigured path. Applied
// to the bytes actually read (single bounded read, no stat-then-read race).
const maxInstructionsBytes = 1 << 20

// ResolveInstructions returns the MCP server instructions text: the file at
// path when readable, within the size cap, and non-empty, the built-in
// DefaultInstructions otherwise (no path configured, unreadable, oversized,
// or empty — a non-critical customization file never blocks startup; a Warn
// explains every fallback). Reads once with a bounded reader so a file that
// grows between stat and read cannot blow past the cap.
//
// A configured-but-MISSING file is first materialized from the built-in
// default (best effort, see materializeDefaultInstructions): the normal
// writers are the deploy flows (bare-metal root scripts / the k8s ConfigMap
// seed), which run with privileges the gateway process deliberately lacks
// (bare-metal User=sandserv vs root-owned /etc/sandswap; k8s read-only
// ConfigMap mount) — this is the developer/self-hosted fallback so pointing
// -mcp-instructions-file at a path needs no separate dump step.
func ResolveInstructions(path string, logger *slog.Logger) string {
	if path == "" {
		return DefaultInstructions
	}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) && materializeDefaultInstructions(path) {
			logger.Info("mcp instructions file missing; materialized the built-in default (edit the file; changes hot-reload)", "path", path)
			return DefaultInstructions
		}
		logger.Warn("mcp instructions file unavailable; using built-in default", "path", path, "error", err)
		return DefaultInstructions
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxInstructionsBytes+1))
	if err != nil {
		logger.Warn("mcp instructions file unreadable; using built-in default", "path", path, "error", err)
		return DefaultInstructions
	}
	return instructionsFromBytes(data, path, logger)
}

// materializeDefaultInstructions writes DefaultInstructions to path so the
// operator has a file to edit. BEST EFFORT ONLY: a write failure (no
// permission — e.g. the read-only ConfigMap mount, or a root-owned config dir
// under a non-root gateway — or a parent dir that does not exist) returns
// false and the caller keeps the serve-the-default fallback. Never overwrites
// anything: it is only called for a path that just failed to open with
// IsNotExist. Atomic (temp file + rename in the same dir) so a crash mid-write
// can never leave a partial guide behind.
func materializeDefaultInstructions(path string) bool {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".mcp-instructions-*")
	if err != nil {
		return false
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename
	if _, err := tmp.WriteString(DefaultInstructions + "\n"); err != nil {
		tmp.Close()
		return false
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return false
	}
	if err := tmp.Close(); err != nil {
		return false
	}
	return os.Rename(tmpName, path) == nil
}

// instructionsFromBytes validates raw file content into the served text:
// over-cap or empty-after-trim falls back to DefaultInstructions with a Warn
// (an empty instructions file serves nothing and gives the operator no signal
// — treat it like any other malformed input). Shared by ResolveInstructions
// (bounded read) and the reload callback (content delivered by the watcher).
func instructionsFromBytes(data []byte, path string, logger *slog.Logger) string {
	if len(data) > maxInstructionsBytes {
		logger.Warn("mcp instructions file exceeds size cap; using built-in default", "path", path, "size", len(data), "cap_bytes", maxInstructionsBytes)
		return DefaultInstructions
	}
	text := strings.TrimSpace(string(data))
	if text == "" {
		logger.Warn("mcp instructions file is empty; using built-in default", "path", path)
		return DefaultInstructions
	}
	return text
}

// SetInstructions atomically replaces the served instructions text (used at
// startup and by the file watcher on hot reload).
func (s *MCPServer) SetInstructions(text string) { s.instructions.Store(&text) }

// currentInstructions returns the instructions text served on initialize and
// the sandswap_guide tool. Falls back to the built-in default if unset.
func (s *MCPServer) currentInstructions() string {
	if p := s.instructions.Load(); p != nil {
		return *p
	}
	return DefaultInstructions
}

// Serve-time placeholders, substituted so the guide's stated numbers always
// equal the enforced ones: {{max_exec_timeout_sec}} → the live sync-exec cap,
// {{sticky_ms}} → the live sticky-lease idleness window.
const (
	maxExecTimeoutPlaceholder = "{{max_exec_timeout_sec}}"
	stickyMsPlaceholder       = "{{sticky_ms}}"
)

// Fallbacks used when the MCP server has no ExecuteHandler / Lease (unit
// tests): the gateway config defaults (gateway/config Defaults; the sticky
// window default is 100ms).
const (
	fallbackMaxExecTimeoutSec = 180
	fallbackStickyMs          = 100
)

// renderInstructions substitutes serve-time values into an instructions text.
// A no-op for placeholders a text does not contain, so hand-edited files are
// served verbatim unless they opt in.
func renderInstructions(text string, maxExecTimeoutSec, stickyMs int) string {
	text = strings.ReplaceAll(text, maxExecTimeoutPlaceholder, strconv.Itoa(maxExecTimeoutSec))
	return strings.ReplaceAll(text, stickyMsPlaceholder, strconv.Itoa(stickyMs))
}

// liveMaxExecTimeoutSec reads the live sync-exec cap (hot-reload aware).
func (s *MCPServer) liveMaxExecTimeoutSec() int {
	if s.execHandler != nil {
		return s.execHandler.MaxExecTimeoutSec()
	}
	return fallbackMaxExecTimeoutSec
}

// liveStickyMs reads the live sticky-lease idleness window in milliseconds
// (hot-reload aware; -sticky-ms / lease.sticky_ms).
func (s *MCPServer) liveStickyMs() int {
	if s.leaseMgr != nil {
		return int(s.leaseMgr.StickyWindow() / time.Millisecond)
	}
	return fallbackStickyMs
}

// renderedInstructions is what agents actually receive: the stored text with
// serve-time values substituted.
func (s *MCPServer) renderedInstructions() string {
	return renderInstructions(s.currentInstructions(), s.liveMaxExecTimeoutSec(), s.liveStickyMs())
}

// StartInstructionsFileWatcher hot-reloads the instructions file. It reuses
// the gateway's existing config-reload watcher (fsnotify, 200ms debounce,
// parent-dir watch — so the vim write-temp+rename pattern and kubelet's
// ConfigMap ..data symlink swap are handled) instead of a bespoke poller:
// one file-watch mechanism in the process, not two.
//
// Semantics: startup resolution already loaded the file (or fell back); the
// watcher then applies every on-disk change without a restart. A file that
// disappears mid-flight keeps the last good text — the watcher's read fails,
// the callback is never invoked, and regressing a live server to the default
// because a bind-mount hiccup is worse than serving slightly stale guidance.
// The file coming back fires a create event and re-resolves normally. The one
// uncovered corner (operator fixes an unreadable-at-startup file with chmod
// alone) requires no content event — re-saving the file triggers the reload.
//
// The startup-resolved path is pinned — pointing the deployment at a different
// file requires a restart. Returns when ctx is cancelled (watcher stopped).
// Call only when the path is non-empty (the built-in default needs no
// watcher).
func (s *MCPServer) StartInstructionsFileWatcher(ctx context.Context, path string, logger *slog.Logger) {
	rw, err := commonconfig.NewReloadWatcher(path, func(content []byte) {
		text := instructionsFromBytes(content, path, logger)
		if text == s.currentInstructions() {
			return
		}
		s.SetInstructions(text)
		logger.Info("mcp instructions reloaded from file", "path", path, "bytes", len(text))
	})
	if err != nil {
		// Same degrade posture as the config-reload wiring: a customization
		// file's watcher failing must not take the gateway down; the startup
		// text keeps serving.
		logger.Warn("failed to start mcp instructions file watcher; serving startup text without hot-reload", "path", path, "error", err)
		return
	}
	go func() {
		<-ctx.Done()
		rw.Stop()
	}()
}

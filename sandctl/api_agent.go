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
	"flag"
	"fmt"
	"os"
	"strings"
)

// ── api execute ─────────────────────────────────────────────────

func apiExecute(g Global, args []string) {
	fs := newFlagSet("api execute")
	var agentID, apiKey, sandfsID, code, language string
	var timeout int
	var background bool
	var lease int
	fs.StringVar(&agentID, "agent", "", "agent id (resolves api key from run/agents.json)")
	fs.StringVar(&apiKey, "api-key", "", "explicit api key (overrides --agent)")
	fs.StringVar(&sandfsID, "sandfs", "", "sandfs id (required)")
	fs.StringVar(&code, "code", "", "code/command to execute (required)")
	fs.StringVar(&language, "language", "shell", "language: shell|python|node|...")
	fs.IntVar(&timeout, "timeout", 0, "sync timeout seconds (0 = gateway default)")
	fs.BoolVar(&background, "background", false, "start as background exec, return exec_id")
	fs.IntVar(&lease, "lease", 0, "background exec absolute run-time cap in seconds")
	fs.Parse(args)

	if code == "" {
		fail("--code is required")
	}
	if sandfsID == "" {
		fail("--sandfs is required")
	}
	body := map[string]any{
		"sandfs_id": sandfsID,
		"code":      code,
		"language":  language,
	}
	if timeout != 0 {
		body["timeout"] = timeout
	}
	if background {
		body["background"] = true
	}
	if lease != 0 {
		body["lease_duration"] = lease
	}
	bearer := bearerFor(g, agentID, apiKeyOrExit(apiKey))
	raw := g.postJSON(g.GatewayURL, "/agent/execute", body, bearer, apiHeader(g))

	// For sync exec, surface stdout/exit_code prominently (the pretty JSON
	// already printed it; nothing extra needed). For background, hint the id.
	if background {
		var resp struct {
			ExecID string `json:"exec_id"`
		}
		if json.Unmarshal(raw, &resp) == nil && resp.ExecID != "" {
			fmt.Fprintf(os.Stderr, "\nexec_id: %s  (status: sandctl api exec-status %s)\n", resp.ExecID, resp.ExecID)
		}
	}
}

// ── api exec-status ─────────────────────────────────────────────

// parsePositionalAndFlags accepts BOTH documented orders:
//
//	api exec-status <exec-id> --agent ... --sandfs ...
//	api exec-status --agent ... --sandfs ... <exec-id>
//
// Go's flag package stops at the first non-flag argument, so a plain
// fs.Parse(args) would leave the flags after <exec-id> unparsed (live
// quick-start failure). Pull the leading positional out first when present.
func parsePositionalAndFlags(fs *flag.FlagSet, args []string) string {
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		id := args[0]
		fs.Parse(args[1:])
		if fs.NArg() > 0 {
			fail("unexpected positional argument %q", fs.Arg(0))
		}
		return id
	}
	fs.Parse(args)
	if fs.NArg() < 1 {
		return ""
	}
	return fs.Arg(0)
}

func apiExecStatus(g Global, args []string) {
	fs := newFlagSet("api exec-status")
	var agentID, apiKey, sandfsID string
	fs.StringVar(&agentID, "agent", "", "agent id")
	fs.StringVar(&apiKey, "api-key", "", "explicit api key")
	fs.StringVar(&sandfsID, "sandfs", "", "sandfs id (required)")
	execID := parsePositionalAndFlags(fs, args)
	if execID == "" {
		fail("api exec-status <exec-id>")
	}
	bearer := bearerFor(g, agentID, apiKeyOrExit(apiKey))
	body := map[string]any{"exec_id": execID, "sandfs_id": sandfsID}
	g.postJSON(g.GatewayURL, "/agent/exec/status", body, bearer, apiHeader(g))
}

// ── api exec-kill ───────────────────────────────────────────────

func apiExecKill(g Global, args []string) {
	fs := newFlagSet("api exec-kill")
	var agentID, apiKey, sandfsID string
	fs.StringVar(&agentID, "agent", "", "agent id")
	fs.StringVar(&apiKey, "api-key", "", "explicit api key")
	fs.StringVar(&sandfsID, "sandfs", "", "sandfs id (required)")
	execID := parsePositionalAndFlags(fs, args)
	if execID == "" {
		fail("api exec-kill <exec-id>")
	}
	bearer := bearerFor(g, agentID, apiKeyOrExit(apiKey))
	body := map[string]any{"exec_id": execID, "sandfs_id": sandfsID}
	g.postJSON(g.GatewayURL, "/agent/exec/kill", body, bearer, apiHeader(g))
}

// ── api file ────────────────────────────────────────────────────

func apiFile(g Global, args []string) {
	fs := newFlagSet("api file")
	var agentID, apiKey, sandfsID, action, path, newPath, data, dataB64 string
	var offset int64
	var length int64
	var appendMode bool
	var mode uint64
	var recursive bool
	var depth uint64
	fs.StringVar(&agentID, "agent", "", "agent id")
	fs.StringVar(&apiKey, "api-key", "", "explicit api key")
	fs.StringVar(&sandfsID, "sandfs", "", "sandfs id (required)")
	fs.StringVar(&action, "action", "", "read|write|stat|list_dir|mkdir|remove|rename (required)")
	fs.StringVar(&path, "path", "", "path relative to /workspace (required)")
	fs.StringVar(&newPath, "new-path", "", "rename destination")
	fs.StringVar(&data, "data", "", "text content (write)")
	fs.StringVar(&dataB64, "data-base64", "", "base64-encoded binary content (write)")
	fs.Int64Var(&offset, "offset", 0, "read/write byte offset")
	fs.Int64Var(&length, "length", 0, "read max bytes")
	fs.BoolVar(&appendMode, "append", false, "write: append mode")
	fs.Uint64Var(&mode, "mode", 0, "write/mkdir permissions (0 = default)")
	fs.BoolVar(&recursive, "recursive", false, "remove: rm -rf")
	fs.Uint64Var(&depth, "depth", 1, "list_dir recursion depth")
	fs.Parse(args)

	if action == "" || path == "" {
		fail("--action and --path are required")
	}
	if sandfsID == "" {
		fail("--sandfs is required")
	}
	body := map[string]any{"action": action, "path": path, "sandfs_id": sandfsID}
	switch action {
	case "write":
		if data != "" {
			body["data"] = data
		}
		if dataB64 != "" {
			body["data_base64"] = dataB64
		}
		if offset != 0 {
			body["offset"] = offset
		}
		if appendMode {
			body["append"] = true
		}
		if mode != 0 {
			body["mode"] = mode
		}
	case "read":
		if offset != 0 {
			body["offset"] = offset
		}
		if length != 0 {
			body["length"] = length
		}
	case "rename":
		if newPath == "" {
			fail("--new-path is required for rename")
		}
		body["new_path"] = newPath
	case "mkdir":
		if mode != 0 {
			body["mode"] = mode
		}
	case "remove":
		if recursive {
			body["recursive"] = true
		}
	case "list_dir":
		if depth != 0 {
			body["depth"] = depth
		}
	case "stat":
		// no extra fields
	default:
		fail("unknown action %q", action)
	}

	bearer := bearerFor(g, agentID, apiKeyOrExit(apiKey))
	g.postJSON(g.GatewayURL, "/agent/file", body, bearer, apiHeader(g))
}

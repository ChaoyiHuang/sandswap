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
	"fmt"
)

// mcpTool represents a single MCP tool definition.
type mcpTool struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	InputSchema map[string]interface{} `json:"inputSchema"`
}

// buildToolsList constructs the MCP tools list for a specific agent,
// embedding the agent's sandfs instances in the tool descriptions and
// input schemas (sandfs_id enum).
func (s *MCPServer) buildToolsList(agentID string) []mcpTool {
	sandfsList, err := s.identityStore.ListSandFSByAgent(agentID)
	if err != nil {
		s.logger.Warn("failed to list sandfs for tools list", "agentID", agentID, "error", err)
		sandfsList = nil // empty list, not nil deref
	}

	sandfsDesc := ""
	sandfsEnum := make([]string, 0, len(sandfsList))
	for _, sf := range sandfsList {
		sandfsEnum = append(sandfsEnum, sf.ID)
		desc := sf.Description
		if desc == "" {
			desc = "(no description)"
		}
		sandfsDesc += fmt.Sprintf("\n• %s (%s): %s", sf.Name, sf.ID, desc)
	}

	sandfsIDProp := map[string]interface{}{
		"type":        "string",
		"description": "SandFS instance ID",
	}
	if len(sandfsEnum) > 0 {
		sandfsIDProp["enum"] = sandfsEnum
	}

	// Abort contract. In-flight commands keep running inside the microVM
	// through a gateway outage (T_tolerance is their grace window), so a short
	// blip or a rolling restart usually lets a sync command finish — but a
	// reconnect, a long outage, or the etcd-partition self-fence releases the
	// mount and cuts it. Agents must be told explicitly: a timeout/network
	// error means "result UNKNOWN", not "failed", so blind retries risk double
	// side effects and treating an aborted run as a failure risks wrong
	// conclusions. The workspace on shared storage is durable across aborts,
	// which is what makes resume/rollback practical.
	const abortContract = " A brief outage (gateway restart/blip) usually lets a running sync command FINISH — but a long outage, node failure, or platform self-protection can abort it mid-run, and background execs are cut short more readily than sync ones. So an error or timeout means the result is UNKNOWN, not failed: make side effects idempotent or checkpoint them (temp file + rename, progress markers, append-only logs in the workspace); after an error, READ the workspace first to see what actually completed, then resume or roll back from there rather than blindly rerunning. Background exec handles (exec_id) may stop resolving after a recovery, and a failed status query does not mean the work never ran — trust the workspace. Workspace files always persist across aborts."

	// Sync-cap contract: the tool schema is the other place (besides the
	// server instructions) an agent learns the sync/background split. The cap
	// is read live from the ExecuteHandler (hot-reload aware), so the stated
	// bound always equals the enforced one.
	capDesc := fmt.Sprintf("Execute code in a SandFS sandbox. Sync commands should finish within ~10s and are HARD-CAPPED at %d seconds (a larger timeout is clamped and the command killed at the cap): anything that may run longer MUST use background:true with lease_duration, polled via exec_status. On 503 errors with retryable:true, retry the SAME request after retry_after_ms (do not change the request body).", s.liveMaxExecTimeoutSec())

	return []mcpTool{
		{
			Name:        "execute",
			Description: capDesc + abortContract + sandfsDesc,
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"sandfs_id":      sandfsIDProp,
					"code":           map[string]interface{}{"type": "string", "description": "Code or command to execute"},
					"language":       map[string]interface{}{"type": "string", "description": "Language: python, shell, node, etc."},
					"timeout":        map[string]interface{}{"type": "integer", "description": "Timeout in seconds (0 = default; values above the sync cap are clamped)"},
					"background":     map[string]interface{}{"type": "boolean", "description": "Start as background exec, return exec_id"},
					"lease_duration": map[string]interface{}{"type": "integer", "description": "VM hold duration in seconds for background execs"},
				},
				"required": []string{"sandfs_id", "code", "language"},
			},
		},
		{
			Name:        "file_read",
			Description: "Read a file from a SandFS sandbox (goes through microVM isolation)",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"sandfs_id": sandfsIDProp,
					"path":      map[string]interface{}{"type": "string", "description": "File path relative to /workspace"},
					"offset":    map[string]interface{}{"type": "integer", "description": "Byte offset"},
					"length":    map[string]interface{}{"type": "integer", "description": "Max bytes to read"},
				},
				"required": []string{"sandfs_id", "path"},
			},
		},
		{
			Name:        "file_write",
			Description: "Write a file in a SandFS sandbox (goes through microVM isolation)",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"sandfs_id":   sandfsIDProp,
					"path":        map[string]interface{}{"type": "string", "description": "File path relative to /workspace"},
					"data":        map[string]interface{}{"type": "string", "description": "Text content to write"},
					"data_base64": map[string]interface{}{"type": "string", "description": "Base64-encoded binary content (for non-UTF-8 data)"},
					"append":      map[string]interface{}{"type": "boolean", "description": "Append mode"},
					"mode":        map[string]interface{}{"type": "integer", "description": "File permissions (0 = default)"},
				},
				"required": []string{"sandfs_id", "path"},
			},
		},
		{
			Name:        "file_stat",
			Description: "Get file metadata in a SandFS sandbox",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"sandfs_id": sandfsIDProp,
					"path":      map[string]interface{}{"type": "string", "description": "File path relative to /workspace"},
				},
				"required": []string{"sandfs_id", "path"},
			},
		},
		{
			Name:        "file_list_dir",
			Description: "List directory contents in a SandFS sandbox",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"sandfs_id": sandfsIDProp,
					"path":      map[string]interface{}{"type": "string", "description": "Directory path relative to /workspace"},
					"depth":     map[string]interface{}{"type": "integer", "description": "Recursion depth"},
				},
				"required": []string{"sandfs_id", "path"},
			},
		},
		{
			Name:        "file_mkdir",
			Description: "Create a directory in a SandFS sandbox",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"sandfs_id": sandfsIDProp,
					"path":      map[string]interface{}{"type": "string", "description": "Directory path relative to /workspace"},
					"mode":      map[string]interface{}{"type": "integer", "description": "Directory permissions (0 = default)"},
				},
				"required": []string{"sandfs_id", "path"},
			},
		},
		{
			Name:        "file_remove",
			Description: "Remove a file or directory in a SandFS sandbox",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"sandfs_id": sandfsIDProp,
					"path":      map[string]interface{}{"type": "string", "description": "Path relative to /workspace"},
					"recursive": map[string]interface{}{"type": "boolean", "description": "Remove recursively (rm -rf)"},
				},
				"required": []string{"sandfs_id", "path"},
			},
		},
		{
			Name:        "file_rename",
			Description: "Rename/move a file in a SandFS sandbox",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"sandfs_id": sandfsIDProp,
					"path":      map[string]interface{}{"type": "string", "description": "Source path relative to /workspace"},
					"new_path":  map[string]interface{}{"type": "string", "description": "Destination path relative to /workspace"},
				},
				"required": []string{"sandfs_id", "path", "new_path"},
			},
		},
		{
			Name:        "exec_status",
			Description: "Poll a background exec's status and log tail. If status is \"not_found\", the exec was lost (e.g. node failure, cleanup). Re-create the exec with a new execute(background:true). Do NOT retry the status poll on a not_found exec_id.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"sandfs_id": sandfsIDProp,
					"exec_id":   map[string]interface{}{"type": "string", "description": "Background exec ID"},
				},
				"required": []string{"sandfs_id", "exec_id"},
			},
		},
		{
			Name:        "exec_kill",
			Description: "Kill a background exec by exec_id",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"sandfs_id": sandfsIDProp,
					"exec_id":   map[string]interface{}{"type": "string", "description": "Background exec ID"},
				},
				"required": []string{"sandfs_id", "exec_id"},
			},
		},
		{
			Name:        "list_sandfs",
			Description: "List available SandFS sandboxes with descriptions (from identity store, no microVM access)",
			InputSchema: map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			},
		},
		{
			Name: "sandswap_guide",
			Description: "Get the Sandswap usage guide: how the sandbox works, how to choose a SandFS " +
				"(list_sandfs), how to hold the warm path (background exec), SandFS self-description " +
				"(README.md at the workspace root or the sandbox root), failure semantics and recovery. " +
				"Call once before heavy use if the server did not provide instructions at connect.",
			InputSchema: map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			},
		},
	}
}

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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"unicode/utf8"

	"gateway/handler"
	"gateway/pool"
)

// dispatchToolCall routes a tool call to the appropriate handler.
// All file/execute operations go through the microVM — no direct filesystem access.
func (s *MCPServer) dispatchToolCall(ctx context.Context, conn *mcpConnection, toolName string, args map[string]interface{}) (*mcpToolCallResult, error) {
	switch toolName {
	case "execute":
		return s.handleExecute(ctx, conn, args)
	case "file_read":
		return s.handleFileOp(ctx, conn, "read", args)
	case "file_write":
		return s.handleFileOp(ctx, conn, "write", args)
	case "file_stat":
		return s.handleFileOp(ctx, conn, "stat", args)
	case "file_list_dir":
		return s.handleFileOp(ctx, conn, "list_dir", args)
	case "file_mkdir":
		return s.handleFileOp(ctx, conn, "mkdir", args)
	case "file_remove":
		return s.handleFileOp(ctx, conn, "remove", args)
	case "file_rename":
		return s.handleFileOp(ctx, conn, "rename", args)
	case "exec_status":
		return s.handleExecStatus(ctx, conn, args)
	case "exec_kill":
		return s.handleExecKill(ctx, conn, args)
	case "list_sandfs":
		return s.handleListSandfs(ctx, conn)
	case "sandswap_guide":
		return s.handleSandswapGuide()
	default:
		return nil, fmt.Errorf("unknown tool: %s", toolName)
	}
}

// getStringArg extracts a string argument from the tool call args.
func getStringArg(args map[string]interface{}, key string) string {
	if v, ok := args[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// getIntArg extracts an int argument from the tool call args.
func getIntArg(args map[string]interface{}, key string) int {
	if v, ok := args[key]; ok {
		switch n := v.(type) {
		case float64:
			return int(n)
		case json.Number:
			i, _ := n.Int64()
			return int(i)
		case string:
			i, _ := json.Number(n).Int64()
			return int(i)
		}
	}
	return 0
}

// getBoolArg extracts a bool argument from the tool call args.
func getBoolArg(args map[string]interface{}, key string) bool {
	if v, ok := args[key]; ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return false
}

// ── Execute ────────────────────────────────────────────────────

// resolveSandfsIDMCP validates the sandfs_id argument of a per-sandfs MCP
// tool call (execute, file, exec-status, exec-kill). The field is REQUIRED:
// tool schemas embed the agent's sandfs IDs as an enum so the LLM client can
// always address them explicitly.
func (s *MCPServer) resolveSandfsIDMCP(conn *mcpConnection, sandfsID string) (string, error) {
	if sandfsID != "" {
		return sandfsID, nil
	}
	return "", fmt.Errorf("sandfs_id is required")
}

func (s *MCPServer) handleExecute(ctx context.Context, conn *mcpConnection, args map[string]interface{}) (*mcpToolCallResult, error) {
	sandfsID, err := s.resolveSandfsIDMCP(conn, getStringArg(args, "sandfs_id"))
	if err != nil {
		return nil, err
	}

	req := handler.ExecuteRequest{
		SandfsID:      sandfsID,
		Code:          getStringArg(args, "code"),
		Language:      getStringArg(args, "language"),
		Timeout:       getIntArg(args, "timeout"),
		Background:    getBoolArg(args, "background"),
		LeaseDuration: getIntArg(args, "lease_duration"),
	}

	result, err := s.execHandler.ExecuteDirect(ctx, conn.AgentKey, req)
	if err != nil {
		return nil, err
	}

	resultJSON, _ := json.Marshal(map[string]interface{}{
		"stdout":              result.Stdout,
		"stderr":              result.Stderr,
		"exit_code":           result.ExitCode,
		"exec_id":             result.ExecID,
		"status":              result.Status,
		"exec_duration_ns":    result.ExecDurationNs,
		"sandlot_duration_ns": result.SandlotDurationNs,
		"gateway_duration_ns": result.GatewayDurationNs,
	})

	return &mcpToolCallResult{
		Content: []mcpContent{{Type: "text", Text: string(resultJSON)}},
	}, nil
}

// ── File operations ────────────────────────────────────────────

func (s *MCPServer) handleFileOp(ctx context.Context, conn *mcpConnection, action string, args map[string]interface{}) (*mcpToolCallResult, error) {
	sandfsID, err := s.resolveSandfsIDMCP(conn, getStringArg(args, "sandfs_id"))
	if err != nil {
		return nil, err
	}

	fileReq := pool.FileOpRequest{
		Action: action,
		Path:   getStringArg(args, "path"),
	}

	switch action {
	case "write":
		// Support both text (data) and binary (data_base64) content.
		if dataBase64 := getStringArg(args, "data_base64"); dataBase64 != "" {
			decoded, err := base64.StdEncoding.DecodeString(dataBase64)
			if err != nil {
				return nil, fmt.Errorf("invalid base64 in data_base64: %w", err)
			}
			fileReq.Data = decoded
		} else {
			fileReq.Data = []byte(getStringArg(args, "data"))
		}
		fileReq.Mode = uint32(getIntArg(args, "mode"))
		if getBoolArg(args, "append") {
			fileReq.Offset = -1
		}
	case "read":
		fileReq.Offset = int64(getIntArg(args, "offset"))
		fileReq.Length = int64(getIntArg(args, "length"))
	case "list_dir":
		fileReq.Depth = uint32(getIntArg(args, "depth"))
	case "mkdir":
		fileReq.Mode = uint32(getIntArg(args, "mode"))
	case "remove":
		fileReq.Recursive = getBoolArg(args, "recursive")
	case "rename":
		fileReq.NewPath = getStringArg(args, "new_path")
	}

	result, err := s.fileHandler.DoFileOpDirect(ctx, sandfsID, conn.AgentKey, fileReq)
	if err != nil {
		return nil, err
	}
	if !result.Success {
		// Application-level error from warden (file not found, permission denied, etc.)
		errMsg := result.Error
		if errMsg == "" {
			errMsg = "file operation failed"
		}
		return nil, fmt.Errorf("%s: %s", action, errMsg)
	}

	// Format result per action type — matches HTTP handler response shapes.
	var response interface{}
	switch action {
	case "read":
		isText := utf8.Valid(result.Data)
		if isText {
			response = map[string]interface{}{
				"ok":      true,
				"data":    string(result.Data),
				"is_text": true,
				"size":    len(result.Data),
			}
		} else {
			response = map[string]interface{}{
				"ok":          true,
				"data_base64": base64.StdEncoding.EncodeToString(result.Data),
				"is_text":     false,
				"size":        len(result.Data),
			}
		}
	case "stat":
		// Warden returns JSON metadata — parse and pass through as structured data.
		var statData interface{}
		if err := json.Unmarshal(result.Data, &statData); err != nil {
			// Fallback: return as string if not valid JSON.
			response = map[string]interface{}{"ok": true, "data": string(result.Data)}
		} else {
			response = statData
		}
	case "list_dir":
		// Warden returns a JSON array — wrap in {"entries": [...]}.
		var entries []interface{}
		if err := json.Unmarshal(result.Data, &entries); err != nil {
			response = map[string]interface{}{"ok": true, "entries": string(result.Data)}
		} else {
			response = map[string]interface{}{"entries": entries}
		}
	case "write":
		response = map[string]interface{}{"ok": true, "size": len(fileReq.Data)}
	default:
		// mkdir, remove, rename
		response = map[string]interface{}{"ok": true}
	}

	resultJSON, _ := json.Marshal(response)
	return &mcpToolCallResult{
		Content: []mcpContent{{Type: "text", Text: string(resultJSON)}},
	}, nil
}

// ── Exec status/kill ──────────────────────────────────────────

func (s *MCPServer) handleExecStatus(ctx context.Context, conn *mcpConnection, args map[string]interface{}) (*mcpToolCallResult, error) {
	sandfsID, err := s.resolveSandfsIDMCP(conn, getStringArg(args, "sandfs_id"))
	if err != nil {
		return nil, err
	}
	execID := getStringArg(args, "exec_id")
	if execID == "" {
		return nil, fmt.Errorf("exec_id is required")
	}

	result, err := s.execHandler.ExecStatusDirect(ctx, conn.AgentKey, sandfsID, execID)
	if err != nil {
		return nil, err
	}

	resultJSON, _ := json.Marshal(map[string]interface{}{
		"status":    result.Status,
		"exit_code": result.ExitCode,
		"stdout":    result.Stdout,
		"stderr":    result.Stderr,
	})
	return &mcpToolCallResult{
		Content: []mcpContent{{Type: "text", Text: string(resultJSON)}},
	}, nil
}

func (s *MCPServer) handleExecKill(ctx context.Context, conn *mcpConnection, args map[string]interface{}) (*mcpToolCallResult, error) {
	sandfsID, err := s.resolveSandfsIDMCP(conn, getStringArg(args, "sandfs_id"))
	if err != nil {
		return nil, err
	}
	execID := getStringArg(args, "exec_id")
	if execID == "" {
		return nil, fmt.Errorf("exec_id is required")
	}

	result, err := s.execHandler.ExecKillDirect(ctx, conn.AgentKey, sandfsID, execID)
	if err != nil {
		return nil, err
	}

	resultJSON, _ := json.Marshal(map[string]interface{}{"status": result.Status})
	return &mcpToolCallResult{
		Content: []mcpContent{{Type: "text", Text: string(resultJSON)}},
	}, nil
}

// ── List sandfs ───────────────────────────────────────────────

func (s *MCPServer) handleListSandfs(ctx context.Context, conn *mcpConnection) (*mcpToolCallResult, error) {
	sandfsList, err := s.identityStore.ListSandFSByAgent(conn.Agent.ID)
	if err != nil {
		return nil, err
	}

	summaries := make([]map[string]interface{}, 0, len(sandfsList))
	for _, sf := range sandfsList {
		summary := map[string]interface{}{
			"sandfs_id":   sf.ID,
			"name":        sf.Name,
			"description": sf.Description,
			"template":    sf.Template,
			"created_at":  sf.CreatedAt,
		}
		// Lifecycle status rides only when non-empty ("" = active), matching
		// the HTTP discovery endpoint's omitempty — the agent backs off and
		// re-lists when a swap/deletion is in progress.
		if sf.Status != "" {
			summary["status"] = sf.Status
		}
		summaries = append(summaries, summary)
	}

	resultJSON, _ := json.Marshal(map[string]interface{}{"sandfs_list": summaries})
	return &mcpToolCallResult{
		Content: []mcpContent{{Type: "text", Text: string(resultJSON)}},
	}, nil
}

// ── Sandswap guide ────────────────────────────────────────────

// handleSandswapGuide returns the server instructions text — no backend call.
// Stateless clients that skip the initialize handshake pull the same overall
// guide here on demand (handshake clients already get it on initialize).
// Rendered ({{max_exec_timeout_sec}} → the live cap), like initialize.
func (s *MCPServer) handleSandswapGuide() (*mcpToolCallResult, error) {
	return &mcpToolCallResult{
		Content: []mcpContent{{Type: "text", Text: s.renderedInstructions()}},
	}, nil
}

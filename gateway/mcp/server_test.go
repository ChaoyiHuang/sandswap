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
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"gateway/handler"
	"gateway/identity"
	"gateway/pool"
)

// ── resolveAgent ─────────────────────────────────────────────────

// TestResolveAgent_AlreadyResolved verifies a pre-resolved connection is a no-op.
func TestResolveAgent_AlreadyResolved(t *testing.T) {
	env := newTestEnv(t)
	conn := env.resolvedConn() // agent already set
	agent := conn.Agent

	if err := env.server.resolveAgent(conn); err != nil {
		t.Errorf("resolveAgent on pre-resolved conn should be no-op, got: %v", err)
	}
	if conn.Agent != agent {
		t.Error("resolveAgent replaced an already-resolved agent")
	}
}

// TestResolveAgent_InvalidKey verifies a bad API key yields "invalid api key".
func TestResolveAgent_InvalidKey(t *testing.T) {
	env := newTestEnv(t)
	conn := &mcpConnection{AgentKey: "sk-bogus"}

	err := env.server.resolveAgent(conn)
	if err == nil {
		t.Fatal("expected error for invalid api key")
	}
	if !strings.Contains(err.Error(), "invalid api key") {
		t.Errorf("expected 'invalid api key' error, got: %v", err)
	}
	if conn.Agent != nil {
		t.Error("conn.Agent should remain nil on failed resolve")
	}
}

// TestResolveAgent_Success verifies a valid key resolves the agent and builds
// the tools list.
func TestResolveAgent_Success(t *testing.T) {
	env := newTestEnv(t)
	conn := &mcpConnection{AgentKey: env.agentKey}

	if err := env.server.resolveAgent(conn); err != nil {
		t.Fatalf("resolveAgent: %v", err)
	}
	if conn.Agent == nil {
		t.Fatal("conn.Agent is nil after successful resolve")
	}
	if conn.Agent.ID != env.agentID {
		t.Errorf("agent ID = %q, want %q", conn.Agent.ID, env.agentID)
	}
	if len(conn.Tools) == 0 {
		t.Error("conn.Tools empty after resolve (should be built)")
	}
}

// ── handleRPC routing ────────────────────────────────────────────

// TestHandleRPC_Routing verifies method dispatch: known methods produce
// results; unknown methods produce a -32601 "method not found" error.
func TestHandleRPC_Routing(t *testing.T) {
	env := newTestEnv(t)
	conn := env.resolvedConn()
	ctx := context.Background()

	t.Run("ping_returns_empty_result", func(t *testing.T) {
		// ping does NOT call resolveAgent (lightweight liveness probe).
		rawConn := &mcpConnection{AgentKey: env.agentKey}
		resp := env.server.handleRPC(ctx, rawConn, &jsonRPCRequest{
			JSONRPC: "2.0", ID: json.RawMessage("1"), Method: "ping",
		})
		if resp.Error != nil {
			t.Errorf("ping should not error, got: %+v", resp.Error)
		}
		if _, ok := resp.Result.(map[string]interface{}); !ok {
			t.Errorf("ping result should be empty object, got: %T", resp.Result)
		}
	})

	t.Run("unknown_method_returns_32601", func(t *testing.T) {
		resp := env.server.handleRPC(ctx, conn, &jsonRPCRequest{
			JSONRPC: "2.0", ID: json.RawMessage("2"), Method: "resources/list",
		})
		if resp.Error == nil {
			t.Fatal("expected error for unknown method")
		}
		if resp.Error.Code != -32601 {
			t.Errorf("error code = %d, want -32601", resp.Error.Code)
		}
		if !strings.Contains(resp.Error.Message, "method not found") {
			t.Errorf("error message = %q, want 'method not found'", resp.Error.Message)
		}
	})
}

// ── handleInitialize ─────────────────────────────────────────────

// TestHandleInitialize_EchoesProtocolVersion verifies the server echoes the
// client's requested protocol version (known-version compatible).
func TestHandleInitialize_EchoesProtocolVersion(t *testing.T) {
	env := newTestEnv(t)
	conn := &mcpConnection{AgentKey: env.agentKey}
	ctx := context.Background()

	params, _ := json.Marshal(mcpInitializeParams{
		ProtocolVersion: "2025-09-01",
		ClientInfo:      mcpClientInfo{Name: "test-client", Version: "1.0"},
	})
	resp := env.server.handleInitialize(ctx, conn, &jsonRPCRequest{
		JSONRPC: "2.0", ID: json.RawMessage("1"), Method: "initialize", Params: params,
	})
	if resp.Error != nil {
		t.Fatalf("initialize errored: %+v", resp.Error)
	}
	result, ok := resp.Result.(mcpInitializeResult)
	if !ok {
		t.Fatalf("result not mcpInitializeResult: %T", resp.Result)
	}
	if result.ProtocolVersion != "2025-09-01" {
		t.Errorf("protocolVersion = %q, want 2025-09-01", result.ProtocolVersion)
	}
	if result.ServerInfo.Name != "sandswap-gateway" {
		t.Errorf("serverInfo.name = %q, want sandswap-gateway", result.ServerInfo.Name)
	}
	// Capabilities should advertise tools.
	caps, ok := result.Capabilities["tools"].(map[string]interface{})
	if !ok {
		t.Errorf("capabilities.tools missing or wrong type: %T", result.Capabilities["tools"])
	}
	_ = caps
}

// TestHandleInitialize_DefaultProtocolVersion verifies that when the client
// omits protocolVersion, the server falls back to the default.
func TestHandleInitialize_DefaultProtocolVersion(t *testing.T) {
	env := newTestEnv(t)
	conn := &mcpConnection{AgentKey: env.agentKey}
	ctx := context.Background()

	// No Params -> default version.
	resp := env.server.handleInitialize(ctx, conn, &jsonRPCRequest{
		JSONRPC: "2.0", ID: json.RawMessage("1"), Method: "initialize",
	})
	result := resp.Result.(mcpInitializeResult)
	if result.ProtocolVersion != "2025-03-26" {
		t.Errorf("default protocolVersion = %q, want 2025-03-26", result.ProtocolVersion)
	}
}

// TestHandleInitialize_InvalidKey verifies initialize rejects a bad API key.
func TestHandleInitialize_InvalidKey(t *testing.T) {
	env := newTestEnv(t)
	conn := &mcpConnection{AgentKey: "sk-bogus"}
	ctx := context.Background()

	resp := env.server.handleInitialize(ctx, conn, &jsonRPCRequest{
		JSONRPC: "2.0", ID: json.RawMessage("1"), Method: "initialize",
	})
	if resp.Error == nil || resp.Error.Code != -32001 {
		t.Errorf("expected -32001 for invalid key, got: %+v", resp.Error)
	}
}

// ── handleToolsList ──────────────────────────────────────────────

// TestHandleToolsList_Success verifies tools/list returns the agent's tools.
func TestHandleToolsList_Success(t *testing.T) {
	env := newTestEnv(t)
	conn := &mcpConnection{AgentKey: env.agentKey}
	ctx := context.Background()

	resp := env.server.handleToolsList(ctx, conn, &jsonRPCRequest{
		JSONRPC: "2.0", ID: json.RawMessage("1"), Method: "tools/list",
	})
	if resp.Error != nil {
		t.Fatalf("tools/list errored: %+v", resp.Error)
	}
	result, ok := resp.Result.(map[string]interface{})
	if !ok {
		t.Fatalf("result not a map: %T", resp.Result)
	}
	tools, ok := result["tools"].([]mcpTool)
	if !ok {
		t.Fatalf("tools not []mcpTool: %T", result["tools"])
	}
	if len(tools) == 0 {
		t.Error("expected non-empty tools list")
	}
}

// TestHandleToolsList_InvalidKey verifies tools/list rejects a bad key.
func TestHandleToolsList_InvalidKey(t *testing.T) {
	env := newTestEnv(t)
	conn := &mcpConnection{AgentKey: "sk-bogus"}
	ctx := context.Background()

	resp := env.server.handleToolsList(ctx, conn, &jsonRPCRequest{
		JSONRPC: "2.0", ID: json.RawMessage("1"), Method: "tools/list",
	})
	if resp.Error == nil || resp.Error.Code != -32001 {
		t.Errorf("expected -32001, got: %+v", resp.Error)
	}
}

// ── handleToolsCall ──────────────────────────────────────────────

// TestHandleToolsCall_InvalidKey verifies tools/call rejects a bad key before dispatch.
func TestHandleToolsCall_InvalidKey(t *testing.T) {
	env := newTestEnv(t)
	conn := &mcpConnection{AgentKey: "sk-bogus"}
	ctx := context.Background()

	params, _ := json.Marshal(mcpToolCallParams{Name: "list_sandfs"})
	resp := env.server.handleToolsCall(ctx, conn, &jsonRPCRequest{
		JSONRPC: "2.0", ID: json.RawMessage("1"), Method: "tools/call", Params: params,
	})
	if resp.Error == nil || resp.Error.Code != -32001 {
		t.Errorf("expected -32001, got: %+v", resp.Error)
	}
}

// TestHandleToolsCall_InvalidParams verifies malformed params produce -32602.
func TestHandleToolsCall_InvalidParams(t *testing.T) {
	env := newTestEnv(t)
	conn := env.resolvedConn()
	ctx := context.Background()

	resp := env.server.handleToolsCall(ctx, conn, &jsonRPCRequest{
		JSONRPC: "2.0", ID: json.RawMessage("1"), Method: "tools/call",
		Params: json.RawMessage(`{not valid json`),
	})
	if resp.Error == nil || resp.Error.Code != -32602 {
		t.Errorf("expected -32602 invalid params, got: %+v", resp.Error)
	}
}

// TestHandleToolsCall_GenericError verifies a non-resilience, non-redirect
// error is wrapped in an IsError result with the error message as text.
func TestHandleToolsCall_GenericError(t *testing.T) {
	env := newTestEnv(t)
	conn := env.resolvedConn()
	ctx := context.Background()

	// Empty code -> ExecuteDirect returns a generic execHTTPError before any RPC.
	params, _ := json.Marshal(mcpToolCallParams{
		Name:      "execute",
		Arguments: map[string]interface{}{"sandfs_id": env.sandfsID, "language": "shell"},
	})
	resp := env.server.handleToolsCall(ctx, conn, &jsonRPCRequest{
		JSONRPC: "2.0", ID: json.RawMessage("1"), Method: "tools/call", Params: params,
	})
	// Generic errors are returned as a Result (IsError=true), NOT as resp.Error.
	if resp.Error != nil {
		t.Fatalf("expected result-level error, got JSON-RPC error: %+v", resp.Error)
	}
	result, ok := resp.Result.(mcpToolCallResult)
	if !ok {
		t.Fatalf("result not mcpToolCallResult: %T", resp.Result)
	}
	if !result.IsError {
		t.Error("expected IsError=true for generic error")
	}
	if !strings.Contains(result.Content[0].Text, "code is required") {
		t.Errorf("error text = %q, want 'code is required'", result.Content[0].Text)
	}
	// redirectURL must NOT be set for generic errors.
	if resp.redirectURL != "" {
		t.Errorf("redirectURL should be empty for generic error, got %q", resp.redirectURL)
	}
}

// TestHandleToolsCall_ResilienceError verifies a resilience error (e.g.
// SANDBOX_CLEANING) is mapped to a structured IsError result preserving
// error_code, retryable, and retry_after_ms for AI-agent programmatic handling.
func TestHandleToolsCall_ResilienceError(t *testing.T) {
	env := newTestEnv(t)
	conn := env.resolvedConn()
	ctx := context.Background()

	// EnterCleaning makes DoFileOpDirect return a resilienceError
	// (SANDBOX_CLEANING) before the RPC.
	if err := env.ss.EnterCleaning(env.sandfsID); err != nil {
		t.Fatalf("EnterCleaning: %v", err)
	}
	env.fake.fileResult = pool.FileOpResult{Data: []byte("x"), Success: true}

	params, _ := json.Marshal(mcpToolCallParams{
		Name:      "file_read",
		Arguments: map[string]interface{}{"sandfs_id": env.sandfsID, "path": "f"},
	})
	resp := env.server.handleToolsCall(ctx, conn, &jsonRPCRequest{
		JSONRPC: "2.0", ID: json.RawMessage("1"), Method: "tools/call", Params: params,
	})
	if resp.Error != nil {
		t.Fatalf("expected result-level error, got JSON-RPC error: %+v", resp.Error)
	}
	result, ok := resp.Result.(mcpToolCallResult)
	if !ok {
		t.Fatalf("result not mcpToolCallResult: %T", resp.Result)
	}
	if !result.IsError {
		t.Error("expected IsError=true for resilience error")
	}
	// The text should be structured JSON with error_code + retryable + retry_after_ms.
	var errBody map[string]interface{}
	if err := json.Unmarshal([]byte(result.Content[0].Text), &errBody); err != nil {
		t.Fatalf("resilience error text not JSON: %v\nraw: %s", err, result.Content[0].Text)
	}
	if errBody["error_code"] != "SANDBOX_CLEANING" {
		t.Errorf("error_code = %v, want SANDBOX_CLEANING", errBody["error_code"])
	}
	if errBody["retryable"] != true {
		t.Errorf("retryable = %v, want true", errBody["retryable"])
	}
	if _, ok := errBody["retry_after_ms"]; !ok {
		t.Error("missing retry_after_ms in resilience error")
	}
}

// TestHandleToolsCall_OwnerRedirectHelper verifies handler.IsOwnerRedirect
// correctly extracts the owner URL from an OwnerRedirectError. The end-to-end
// path through handleToolsCall requires an etcd-backed OwnershipCache (covered
// by the ownership_e2e build-tagged tests); here we verify the helper that
// handleToolsCall relies on for the redirect decision.
func TestHandleToolsCall_OwnerRedirectHelper(t *testing.T) {
	ownerURL := "http://owner-gateway:3100"
	ore := &handler.OwnerRedirectError{OwnerURL: ownerURL}

	gotURL, ok := handler.IsOwnerRedirect(ore)
	if !ok {
		t.Fatal("IsOwnerRedirect returned ok=false for *OwnerRedirectError")
	}
	if gotURL != ownerURL {
		t.Errorf("owner URL = %q, want %q", gotURL, ownerURL)
	}

	// A generic error should not be detected as an owner redirect.
	_, ok = handler.IsOwnerRedirect(errGeneric("some rpc error"))
	if ok {
		t.Error("IsOwnerRedirect returned ok=true for a generic error")
	}
}

// errGeneric is a test error type for the redirect helper negative case.
type errGeneric string

func (e errGeneric) Error() string { return string(e) }

// TestHandleToolsCall_Success verifies a successful dispatch returns a
// non-error result with text content.
func TestHandleToolsCall_Success(t *testing.T) {
	env := newTestEnv(t)
	conn := env.resolvedConn()
	ctx := context.Background()
	env.fake.execResult = pool.ExecResult{Stdout: "done", ExitCode: 0, Status: "done"}

	params, _ := json.Marshal(mcpToolCallParams{
		Name: "execute",
		Arguments: map[string]interface{}{
			"sandfs_id": env.sandfsID, "code": "echo hi", "language": "shell",
		},
	})
	resp := env.server.handleToolsCall(ctx, conn, &jsonRPCRequest{
		JSONRPC: "2.0", ID: json.RawMessage("1"), Method: "tools/call", Params: params,
	})
	if resp.Error != nil {
		t.Fatalf("unexpected error: %+v", resp.Error)
	}
	result, ok := resp.Result.(*mcpToolCallResult)
	if !ok {
		t.Fatalf("result not *mcpToolCallResult: %T", resp.Result)
	}
	if result.IsError {
		t.Error("expected IsError=false for success")
	}
	if !strings.Contains(result.Content[0].Text, "done") {
		t.Errorf("result text = %q, want to contain 'done'", result.Content[0].Text)
	}
}

// ── HandleHTTPRequest ────────────────────────────────────────────

// doMCPRequest is a helper that POSTs a JSON-RPC request to the MCP HTTP
// endpoint with the given API key and returns the recorded response.
func doMCPRequest(t *testing.T, env *testEnv, apiKey string, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}
	w := httptest.NewRecorder()
	env.server.HandleHTTPRequest(w, req)
	return w
}

// TestHandleHTTPRequest_MethodNotAllowed verifies non-POST is rejected.
func TestHandleHTTPRequest_MethodNotAllowed(t *testing.T) {
	env := newTestEnv(t)
	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	w := httptest.NewRecorder()
	env.server.HandleHTTPRequest(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d (JSON-RPC errors are HTTP 200)", w.Code)
	}
	var resp jsonRPCResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Error == nil || resp.Error.Code != -32600 {
		t.Errorf("expected -32600, got: %+v", resp.Error)
	}
}

// TestHandleHTTPRequest_MissingAPIKey verifies a missing API key yields -32001.
func TestHandleHTTPRequest_MissingAPIKey(t *testing.T) {
	env := newTestEnv(t)
	w := doMCPRequest(t, env, "", `{"jsonrpc":"2.0","id":1,"method":"ping"}`)

	var resp jsonRPCResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Error == nil || resp.Error.Code != -32001 {
		t.Errorf("expected -32001 missing api key, got: %+v", resp.Error)
	}
}

// TestHandleHTTPRequest_ParseError verifies malformed JSON yields -32700.
func TestHandleHTTPRequest_ParseError(t *testing.T) {
	env := newTestEnv(t)
	w := doMCPRequest(t, env, env.agentKey, `{not valid json`)

	var resp jsonRPCResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Error == nil || resp.Error.Code != -32700 {
		t.Errorf("expected -32700 parse error, got: %+v", resp.Error)
	}
}

// TestHandleHTTPRequest_Ping verifies a successful ping over HTTP.
func TestHandleHTTPRequest_Ping(t *testing.T) {
	env := newTestEnv(t)
	w := doMCPRequest(t, env, env.agentKey, `{"jsonrpc":"2.0","id":1,"method":"ping"}`)

	var resp jsonRPCResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON response: %v\nbody: %s", err, w.Body.String())
	}
	if resp.Error != nil {
		t.Errorf("ping should not error: %+v", resp.Error)
	}
}

// TestHandleHTTPRequest_ToolsList verifies tools/list works over HTTP and sets
// the Cache-Control header (tools list is static per agent).
func TestHandleHTTPRequest_ToolsList(t *testing.T) {
	env := newTestEnv(t)
	w := doMCPRequest(t, env, env.agentKey, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)

	if cc := w.Header().Get("Cache-Control"); cc == "" {
		t.Error("expected Cache-Control header on tools/list")
	}
	var resp jsonRPCResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Error != nil {
		t.Fatalf("tools/list errored: %+v", resp.Error)
	}
}

// TestHandleHTTPRequest_Initialize verifies initialize works over HTTP.
func TestHandleHTTPRequest_Initialize(t *testing.T) {
	env := newTestEnv(t)
	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}`
	w := doMCPRequest(t, env, env.agentKey, body)

	var resp jsonRPCResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Error != nil {
		t.Fatalf("initialize errored: %+v", resp.Error)
	}
}

// TestHandleHTTPRequest_McpMethodHeader verifies the SEP-2243 Mcp-Method header
// fallback: when the body has no method, the method is read from the header.
func TestHandleHTTPRequest_McpMethodHeader(t *testing.T) {
	env := newTestEnv(t)
	// Body with no "method" field; method arrives via header.
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1}`))
	req.Header.Set("Authorization", "Bearer "+env.agentKey)
	req.Header.Set("Mcp-Method", "ping")
	w := httptest.NewRecorder()
	env.server.HandleHTTPRequest(w, req)

	var resp jsonRPCResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Error != nil {
		t.Errorf("Mcp-Method header fallback should succeed, got: %+v", resp.Error)
	}
}

// TestHandleHTTPRequest_McpNameHeader verifies the SEP-2243 Mcp-Name header
// fallback for tools/call: when method is tools/call but params are absent,
// the tool name is read from the Mcp-Name header.
func TestHandleHTTPRequest_McpNameHeader(t *testing.T) {
	env := newTestEnv(t)
	// Method via header, params absent -> Mcp-Name supplies the tool name.
	// list_sandfs needs no args, so it should succeed.
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call"}`))
	req.Header.Set("Authorization", "Bearer "+env.agentKey)
	req.Header.Set("Mcp-Name", "list_sandfs")
	w := httptest.NewRecorder()
	env.server.HandleHTTPRequest(w, req)

	var resp jsonRPCResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Error != nil {
		t.Fatalf("Mcp-Name header fallback should succeed, got: %+v", resp.Error)
	}
}

// TestHandleHTTPRequest_ToolsCallError verifies a dispatch error over HTTP is
// returned as an IsError result (not a JSON-RPC error).
func TestHandleHTTPRequest_ToolsCallError(t *testing.T) {
	env := newTestEnv(t)
	// exec_status without sandfs_id -> returns a dispatch error (sandfs_id is
	// required and checked first).
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"exec_status","arguments":{}}}`
	w := doMCPRequest(t, env, env.agentKey, body)

	var resp jsonRPCResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Error != nil {
		t.Fatalf("expected result-level error (not JSON-RPC error), got: %+v", resp.Error)
	}
	// The result should be an IsError mcpToolCallResult.
	raw, _ := json.Marshal(resp.Result)
	var result struct {
		IsError bool         `json:"isError"`
		Content []mcpContent `json:"content"`
	}
	json.Unmarshal(raw, &result)
	if !result.IsError {
		t.Error("expected IsError=true")
	}
	if !strings.Contains(result.Content[0].Text, "sandfs_id is required") {
		t.Errorf("error text = %q", result.Content[0].Text)
	}
}

// TestHandleHTTPRequest_BodyLimit verifies the 50MB request body limit is
// enforced (an oversized body yields a parse error).
func TestHandleHTTPRequest_BodyLimit(t *testing.T) {
	env := newTestEnv(t)
	// Build a >50MB body (50<<20 + 1 bytes). Use a large JSON string value.
	big := make([]byte, 51<<20) // 51 MB
	for i := range big {
		big[i] = 'a'
	}
	body := `{"jsonrpc":"2.0","id":1,"method":"ping","params":"` + string(big) + `"}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader([]byte(body)))
	req.Header.Set("Authorization", "Bearer "+env.agentKey)
	w := httptest.NewRecorder()
	env.server.HandleHTTPRequest(w, req)

	var resp jsonRPCResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	// an OVERSIZE body is answered distinctly from a parse error —
	// -32600 with a "too large" message, so clients know to send less
	// (conflated -32700 "parse error" misled them toward fixing their JSON).
	if resp.Error == nil {
		t.Fatal("expected error for oversized body")
	}
	if resp.Error.Code != -32600 {
		t.Errorf("expected -32600 request-too-large for oversized body, got code %d", resp.Error.Code)
	}
	if !strings.Contains(resp.Error.Message, "too large") {
		t.Errorf("oversize message should say too large, got %q", resp.Error.Message)
	}
}

// TestHandleHTTPRequest_APIKeyFromCustomHeader verifies the X-Sandswap-Api-Key
// header works (this is the header that survives cross-host 307 redirects).
func TestHandleHTTPRequest_APIKeyFromCustomHeader(t *testing.T) {
	env := newTestEnv(t)
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	req.Header.Set("X-Sandswap-Api-Key", env.agentKey)
	w := httptest.NewRecorder()
	env.server.HandleHTTPRequest(w, req)

	var resp jsonRPCResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Error != nil {
		t.Errorf("X-Sandswap-Api-Key should authenticate, got: %+v", resp.Error)
	}
}

// ── HandleStdio ──────────────────────────────────────────────────

// TestHandleStdio_MissingEnvKey verifies HandleStdio returns an error when
// SANDSWAP_API_KEY is not set.
func TestHandleStdio_MissingEnvKey(t *testing.T) {
	env := newTestEnv(t)
	t.Setenv("SANDSWAP_API_KEY", "")

	err := env.server.HandleStdio(context.Background())
	if err == nil {
		t.Fatal("expected error when SANDSWAP_API_KEY is unset")
	}
	if !strings.Contains(err.Error(), "SANDSWAP_API_KEY") {
		t.Errorf("error should mention SANDSWAP_API_KEY, got: %v", err)
	}
}

// TestHandleStdio_RoundTrip verifies the stdio transport reads a JSON-RPC
// request from stdin, dispatches it, and writes the response to stdout. Closes
// stdin (EOF) to make HandleStdio return.
func TestHandleStdio_RoundTrip(t *testing.T) {
	env := newTestEnv(t)
	t.Setenv("SANDSWAP_API_KEY", env.agentKey)

	// Redirect stdin.
	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	oldStdin := os.Stdin
	os.Stdin = stdinR
	defer func() { os.Stdin = oldStdin }()

	// Redirect stdout.
	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	oldStdout := os.Stdout
	os.Stdout = stdoutW
	defer func() { os.Stdout = oldStdout }()

	// Write a ping request then close stdin (EOF -> HandleStdio returns nil).
	go func() {
		_ = json.NewEncoder(stdinW).Encode(jsonRPCRequest{
			JSONRPC: "2.0", ID: json.RawMessage("1"), Method: "ping",
		})
		stdinW.Close()
	}()

	if err := env.server.HandleStdio(context.Background()); err != nil {
		t.Fatalf("HandleStdio: %v", err)
	}

	// Read the response from the captured stdout.
	stdoutW.Close()
	var resp jsonRPCResponse
	if err := json.NewDecoder(stdoutR).Decode(&resp); err != nil {
		t.Fatalf("decode stdout: %v", err)
	}
	if resp.Error != nil {
		t.Errorf("ping should not error: %+v", resp.Error)
	}
}

// TestHandleStdio_DecodeErrorAborts verifies that a non-EOF decode error
// (invalid JSON) aborts the session with an error rather than infinite-looping.
// This is a regression test for a bug where `continue` on a decode error caused
// an infinite loop because json.Decoder re-reads the same bad bytes forever.
func TestHandleStdio_DecodeErrorAborts(t *testing.T) {
	env := newTestEnv(t)
	t.Setenv("SANDSWAP_API_KEY", env.agentKey)

	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	oldStdin := os.Stdin
	os.Stdin = stdinR
	defer func() { os.Stdin = oldStdin }()

	_, stdoutW, _ := os.Pipe()
	oldStdout := os.Stdout
	os.Stdout = stdoutW
	defer func() { os.Stdout = oldStdout }()

	// Write invalid JSON, then close stdin.
	go func() {
		stdinW.Write([]byte("{not valid json"))
		stdinW.Close()
	}()

	done := make(chan error, 1)
	go func() { done <- env.server.HandleStdio(context.Background()) }()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected error for invalid JSON, got nil (would have infinite-looped before fix)")
		}
		if !strings.Contains(err.Error(), "invalid json-rpc message") {
			t.Errorf("error should mention 'invalid json-rpc message', got: %v", err)
		}
	case <-time.After(3 * time.Second):
		// Close stdin to unblock the goroutine so the test can exit cleanly.
		stdinR.Close()
		t.Fatal("HandleStdio hung on invalid JSON (infinite loop not fixed)")
	}
}

// TestHandleStdio_ContextCancel verifies HandleStdio returns ctx.Err() when the
// context is cancelled while blocked on stdin.
func TestHandleStdio_ContextCancel(t *testing.T) {
	env := newTestEnv(t)
	t.Setenv("SANDSWAP_API_KEY", env.agentKey)

	// stdin stays open (no EOF) so HandleStdio blocks on Decode.
	stdinR, _, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	oldStdin := os.Stdin
	os.Stdin = stdinR
	defer func() { os.Stdin = oldStdin }()

	// Redirect stdout so HandleStdio's writes don't pollute test output.
	_, stdoutW, _ := os.Pipe()
	oldStdout := os.Stdout
	os.Stdout = stdoutW
	defer func() { os.Stdout = oldStdout }()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- env.server.HandleStdio(ctx) }()

	cancel()
	select {
	case err := <-done:
		if err != context.Canceled {
			t.Errorf("expected context.Canceled, got: %v", err)
		}
	case <-time.After(2 * time.Second):
		// Close stdin to unblock the goroutine so the test can exit cleanly.
		stdinR.Close()
		t.Fatal("HandleStdio did not return after context cancel within 2s")
	}
}

// ── NewMCPServer ─────────────────────────────────────────────────

// TestNewMCPServer verifies the constructor wires all dependencies.
func TestNewMCPServer(t *testing.T) {
	env := newTestEnv(t)
	// Verify all fields were set by checking they're non-nil/non-empty.
	if env.server.identityStore == nil {
		t.Error("identityStore not wired")
	}
	if env.server.execHandler == nil {
		t.Error("execHandler not wired")
	}
	if env.server.fileHandler == nil {
		t.Error("fileHandler not wired")
	}
	if env.server.gatewayID != "gw-test" {
		t.Errorf("gatewayID = %q, want gw-test", env.server.gatewayID)
	}
}

// ── Identity-store error path ────────────────────────────────────────

// TestBuildToolsList_StoreError verifies a failing ListSandFSByAgent (e.g.
// store closed) does not panic - buildToolsList logs and returns a tools list
// with an empty sandfs enum.
func TestBuildToolsList_StoreError(t *testing.T) {
	env := newTestEnv(t)
	// Use a store that errors on ListSandFSByAgent.
	srv := NewMCPServer(
		&erroringStore{Agent: env.resolvedConn().Agent},
		env.execH, env.fileH, env.agentH, env.lm, env.pm, env.fake, "gw-test",
		DefaultInstructions, env.server.logger,
	)
	tools := srv.buildToolsList("any-agent")
	if len(tools) == 0 {
		t.Fatal("expected non-empty tools list even when store errors")
	}
	// No enum should be present (sandfs list failed).
	for _, tl := range tools {
		props, _ := tl.InputSchema["properties"].(map[string]interface{})
		if sandfsProp, has := props["sandfs_id"]; has {
			sp, _ := sandfsProp.(map[string]interface{})
			if _, hasEnum := sp["enum"]; hasEnum {
				t.Errorf("tool %q: should have no enum when store errors", tl.Name)
			}
		}
	}
}

// erroringStore is an identity.Store whose ListSandFSByAgent always errors.
// All other methods delegate to an embedded MemoryStore (initialized with the
// test agent) so ResolveAgent succeeds.
type erroringStore struct {
	*identity.Agent
}

func (s *erroringStore) ResolveAgent(apiKey string) (*identity.Agent, error) { return s.Agent, nil }
func (s *erroringStore) GetSandFS(sandfsID string) (*identity.Record, error) {
	return nil, errStore("get failed")
}
func (s *erroringStore) ListSandFSByAgent(agentID string) ([]*identity.Record, error) {
	return nil, errStore("list failed")
}
func (s *erroringStore) CreateAgent(req identity.CreateAgentRequest) (*identity.Agent, string, error) {
	return nil, "", errStore("not implemented")
}
func (s *erroringStore) DeleteAgent(agentID string) error { return errStore("not implemented") }
func (s *erroringStore) ListAgents() ([]*identity.Agent, error) {
	return nil, errStore("not implemented")
}
func (s *erroringStore) CreateSandFS(agentID string, req identity.CreateSandFSRequest) (*identity.Record, error) {
	return nil, errStore("not implemented")
}
func (s *erroringStore) DeleteSandFS(sandfsID string) error { return errStore("not implemented") }
func (s *erroringStore) ListAllSandFS() ([]*identity.Record, error) {
	return nil, errStore("not implemented")
}
func (s *erroringStore) SetRootFSPath(sandfsID, rootfsPath string) error {
	return errStore("not implemented")
}
func (s *erroringStore) SetMinResources(sandfsID string, vcpus uint32, memMB uint64) error {
	return errStore("not implemented")
}
func (s *erroringStore) SetSandfsStatus(sandfsID, status string) error {
	return errStore("not implemented")
}
func (s *erroringStore) UpdateSandfsTemplate(sandfsID, templateRef string, vcpus uint32, memMB uint64) error {
	return errStore("not implemented")
}
func (s *erroringStore) CountSandFSByTemplate(templateRef string) (int, []string) {
	return 0, nil
}

type errStore string

func (e errStore) Error() string { return string(e) }

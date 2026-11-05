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
	"strings"
	"testing"

	"gateway/handler"
	"gateway/pool"
)

// callTool drives one tools/call through the full JSON-RPC path and returns
// the tool result (fatals on a transport-level JSON-RPC error).
func callTool(t *testing.T, env *testEnv, conn *mcpConnection, name string, args map[string]interface{}) mcpToolCallResult {
	t.Helper()
	params, _ := json.Marshal(mcpToolCallParams{Name: name, Arguments: args})
	resp := env.server.handleToolsCall(context.Background(), conn, &jsonRPCRequest{
		JSONRPC: "2.0", ID: json.RawMessage("1"), Method: "tools/call", Params: params,
	})
	if resp.Error != nil {
		t.Fatalf("%s: JSON-RPC error: %+v", name, resp.Error)
	}
	switch r := resp.Result.(type) {
	case mcpToolCallResult:
		return r
	case *mcpToolCallResult:
		return *r
	default:
		t.Fatalf("%s: result not a tool result: %T", name, resp.Result)
		return mcpToolCallResult{}
	}
}

// namedToolError unmarshals a structured isError tool result and returns its
// error_code (fatals when the text is not the structured shape).
func namedToolError(t *testing.T, result mcpToolCallResult) (map[string]interface{}, string) {
	t.Helper()
	if !result.IsError {
		t.Fatal("expected isError=true")
	}
	var body map[string]interface{}
	if err := json.Unmarshal([]byte(result.Content[0].Text), &body); err != nil {
		t.Fatalf("tool error is not structured JSON: %v\nraw: %s", err, result.Content[0].Text)
	}
	code, _ := body["error_code"].(string)
	return body, code
}

// TestMCPFileOpWireSizeGate pins the MCP transport against the
// blast radius: the MCP body cap (50MB) is far above the node stream's gRPC
// message limit, and before this gate an oversize file_write/file_read went
// straight to DoFileOpDirect → the node stream's Send failed → the stream
// CLOSED → every co-tenant in-flight command on that sandlot died. RED with
// the gate removed: the oversize cases below reach the fake sandlot client
// (fileCalls>0) and return success instead of the named refusal.
func TestMCPFileOpWireSizeGate(t *testing.T) {
	old := handler.SetMaxFileOpDataBytesForTest(1024) // shrink the wire gate for the test
	defer handler.SetMaxFileOpDataBytesForTest(old)

	env := newTestEnv(t)
	conn := env.resolvedConn()

	// Oversize write: named 4xx-class refusal, and NOTHING on the wire.
	big := strings.Repeat("x", 2048)
	res := callTool(t, env, conn, "file_write", map[string]interface{}{
		"sandfs_id": env.sandfsID, "path": "out.txt", "data": big,
	})
	body, code := namedToolError(t, res)
	if code != "FILE_TOO_LARGE" {
		t.Fatalf("oversize write: error_code = %q, want FILE_TOO_LARGE (body %v)", code, body)
	}
	if body["retryable"] != false {
		t.Fatalf("oversize write must not be retryable: %v", body)
	}
	if body["http_status"] != float64(413) {
		t.Fatalf("oversize write must carry the 413-class status: %v", body)
	}
	if n := env.fake.fileCalls.Load(); n != 0 {
		t.Fatalf("oversize write reached the sandlot RPC (%d calls) — uncovered wire breach", n)
	}

	// Oversize read (requested length): same gate on the read path.
	res = callTool(t, env, conn, "file_read", map[string]interface{}{
		"sandfs_id": env.sandfsID, "path": "out.txt", "length": 2048,
	})
	if _, code := namedToolError(t, res); code != "FILE_TOO_LARGE" {
		t.Fatalf("oversize read: error_code = %q, want FILE_TOO_LARGE", code)
	}
	if n := env.fake.fileCalls.Load(); n != 0 {
		t.Fatalf("oversize read reached the sandlot RPC (%d calls) — uncovered wire breach", n)
	}

	// Boundary: data EXACTLY at the cap still flows (no off-by-one refusal).
	env.fake.fileResult = pool.FileOpResult{Success: true}
	res = callTool(t, env, conn, "file_write", map[string]interface{}{
		"sandfs_id": env.sandfsID, "path": "out.txt", "data": strings.Repeat("y", 1024),
	})
	if res.IsError {
		t.Fatalf("at-limit write must succeed, got %+v", res)
	}
	if n := env.fake.fileCalls.Load(); n != 1 {
		t.Fatalf("at-limit write must reach the sandlot RPC once, got %d", n)
	}
}

// TestMCPExecuteWireSizeGate pins the same gate on the OTHER MCP tool
// that can carry a large body: `execute`. Its command is a single gRPC message
// field, and the wrapped form can be up to 4× the code (shQuote inflates every
// embedded single quote), so the code length alone is not a safe bound. RED
// with the gate removed: the oversize case reaches the fake sandlot client.
func TestMCPExecuteWireSizeGate(t *testing.T) {
	old := handler.SetMaxFileOpDataBytesForTest(1024)
	defer handler.SetMaxFileOpDataBytesForTest(old)

	env := newTestEnv(t)
	conn := env.resolvedConn()

	res := callTool(t, env, conn, "execute", map[string]interface{}{
		"sandfs_id": env.sandfsID, "code": strings.Repeat("x", 2048),
	})
	if _, code := namedToolError(t, res); code != "EXEC_TOO_LARGE" {
		t.Fatalf("oversize execute: error_code = %q, want EXEC_TOO_LARGE", code)
	}
	if n := env.fake.execCalls.Load(); n != 0 {
		t.Fatalf("oversize execute reached the sandlot RPC (%d calls) — uncovered wire breach", n)
	}

	// The quote-inflation leg: a code string UNDER the cap whose WRAPPED shell
	// command (every ' becomes '\'' ) exceeds it must be refused too.
	quotes := strings.Repeat("'", 512) // 512 × 4 = 2048 bytes wrapped
	res = callTool(t, env, conn, "execute", map[string]interface{}{
		"sandfs_id": env.sandfsID, "code": quotes, "language": "python",
	})
	if _, code := namedToolError(t, res); code != "EXEC_TOO_LARGE" {
		t.Fatalf("quote-inflated execute: error_code = %q, want EXEC_TOO_LARGE", code)
	}
	if n := env.fake.execCalls.Load(); n != 0 {
		t.Fatalf("quote-inflated execute reached the sandlot RPC (%d calls)", n)
	}

	// Boundary: a wrapped command exactly at the cap still flows.
	res = callTool(t, env, conn, "execute", map[string]interface{}{
		"sandfs_id": env.sandfsID, "code": strings.Repeat("z", 1024),
	})
	if res.IsError {
		t.Fatalf("at-limit execute must succeed, got %+v", res)
	}
	if n := env.fake.execCalls.Load(); n != 1 {
		t.Fatalf("at-limit execute must reach the sandlot RPC once, got %d", n)
	}
}

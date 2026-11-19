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
//
// Package main implements a CLI test driver that connects to a Sandswap gateway's
// MCP server (POST /mcp) and exercises all 12 MCP tools through the full backend
// chain: gateway → gRPC stream → sandlot → vmm → warden.
// This is a deterministic e2e test — no LLM required. Uses the mcp-go client
// to call initialize, tools/list, and tools/call directly with exact arguments
// and asserts exact results.
// Usage:
//	go run . -gateway-url http://localhost:3000 -api-key sk-sandswap-agent-xxx
//	go run . -gateway-url http://localhost:3000 -api-key sk-sandswap-agent-xxx -sandfs-id sandfs-xxx

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/client/transport"
	"github.com/mark3labs/mcp-go/mcp"
)

var (
	gatewayURL = flag.String("gateway-url", "http://localhost:3000", "Gateway HTTP address (MCP endpoint at /mcp)")
	apiKey     = flag.String("api-key", "", "Agent API key (required)")
	sandfsID   = flag.String("sandfs-id", "", "SandFS instance ID (auto-detected from list_sandfs if omitted)")
	timeout    = flag.Duration("timeout", 120*time.Second, "Per-tool-call timeout")
)

// ── Test result tracking ──────────────────────────────────────

var (
	passCount int
	failCount int
)

type testCase struct {
	name string
	run  func(ctx context.Context, c *client.Client, sandfsID string) error
}

func pass(msg string) {
	passCount++
	fmt.Printf("  ✓ %s\n", msg)
}

func fail(msg string) {
	failCount++
	fmt.Printf("  ✗ %s\n", msg)
}

func failf(format string, args ...interface{}) {
	fail(fmt.Sprintf(format, args...))
}

// ── Helpers ───────────────────────────────────────────────────

// callTool calls a tool and returns the result. On error, returns nil + logs failure.
func callTool(ctx context.Context, c *client.Client, toolName string, args map[string]interface{}) (*mcp.CallToolResult, error) {
	result, err := c.CallTool(ctx, mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name:      toolName,
			Arguments: args,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("CallTool(%q) error: %w", toolName, err)
	}
	return result, nil
}

// toolText extracts the text content from a CallToolResult.
func toolText(result *mcp.CallToolResult) string {
	if result == nil {
		return ""
	}
	var texts []string
	for _, c := range result.Content {
		if tc, ok := c.(mcp.TextContent); ok {
			texts = append(texts, tc.Text)
		}
	}
	return strings.Join(texts, "\n")
}

// parseJSON is a helper to parse the tool result text as JSON.
func parseJSON(text string) map[string]interface{} {
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(text), &m); err != nil {
		return nil
	}
	return m
}

// ── Test cases ────────────────────────────────────────────────

// serverInstructions is the text the server returned on initialize — the
// sandswap_guide tool must serve the SAME text (both channels, one source).
var serverInstructions string

func testInitialize(ctx context.Context, c *client.Client, _ string) error {
	// Already initialized by the client, but verify capabilities.
	caps := c.GetServerCapabilities()
	// The gateway advertises {"tools": {}} in capabilities.
	if caps.Tools == nil {
		return fmt.Errorf("tools capability not advertised")
	}
	pass("initialize: server capabilities include tools")
	return nil
}

// testServerInstructions verifies the initialize result carried the overall
// Sandswap guide (MCP instructions field — agents get it injected as context).
// Content-agnostic: the deployment may have customized the text via
// -mcp-instructions-file, so only presence is asserted.
func testServerInstructions(ctx context.Context, c *client.Client, _ string) error {
	if serverInstructions == "" {
		return fmt.Errorf("initialize result has empty instructions")
	}
	passf("initialize: instructions present (%d bytes)", len(serverInstructions))
	return nil
}

func testToolsList(ctx context.Context, c *client.Client, _ string) error {
	tools, err := c.ListTools(ctx, mcp.ListToolsRequest{})
	if err != nil {
		return fmt.Errorf("ListTools error: %w", err)
	}

	expectedTools := []string{
		"execute", "file_read", "file_write", "file_stat", "file_list_dir",
		"file_mkdir", "file_remove", "file_rename", "exec_status", "exec_kill",
		"list_sandfs", "sandswap_guide",
	}

	found := make(map[string]bool)
	for _, t := range tools.Tools {
		found[t.Name] = true
	}

	var missing []string
	for _, name := range expectedTools {
		if !found[name] {
			missing = append(missing, name)
		}
	}

	if len(missing) > 0 {
		return fmt.Errorf("missing tools: %v (got %d tools total)", missing, len(tools.Tools))
	}

	passf("tools/list: all %d tools present", len(expectedTools))
	return nil
}

// testSandswapGuide verifies the guide tool serves the SAME text initialize
// returned (stateless clients that skip initialize pull it here on demand).
func testSandswapGuide(ctx context.Context, c *client.Client, _ string) error {
	result, err := callTool(ctx, c, "sandswap_guide", map[string]interface{}{})
	if err != nil {
		return err
	}
	text := toolText(result)
	if text == "" {
		return fmt.Errorf("sandswap_guide returned empty text")
	}
	if text != serverInstructions {
		return fmt.Errorf("sandswap_guide text (%d bytes) != initialize instructions (%d bytes)",
			len(text), len(serverInstructions))
	}
	passf("sandswap_guide: matches initialize instructions (%d bytes)", len(text))
	return nil
}

func testListSandfs(ctx context.Context, c *client.Client, _ string) error {
	result, err := callTool(ctx, c, "list_sandfs", map[string]interface{}{})
	if err != nil {
		return err
	}

	text := toolText(result)
	m := parseJSON(text)
	if m == nil {
		return fmt.Errorf("list_sandfs result is not valid JSON: %s", text)
	}

	list, ok := m["sandfs_list"]
	if !ok {
		return fmt.Errorf("list_sandfs result missing 'sandfs_list' key: %s", text)
	}

	arr, ok := list.([]interface{})
	if !ok {
		return fmt.Errorf("sandfs_list is not an array: %T", list)
	}

	if len(arr) == 0 {
		return fmt.Errorf("sandfs_list is empty — agent has no sandfs instances")
	}

	passf("list_sandfs: %d sandfs instance(s)", len(arr))
	return nil
}

func testExecute(ctx context.Context, c *client.Client, sid string) error {
	result, err := callTool(ctx, c, "execute", map[string]interface{}{
		"sandfs_id": sid,
		"code":      "echo hello_from_sandswap",
		"language":  "shell",
	})
	if err != nil {
		return err
	}

	text := toolText(result)
	m := parseJSON(text)
	if m == nil {
		return fmt.Errorf("execute result is not valid JSON: %s", text)
	}

	stdout, _ := m["stdout"].(string)
	if !strings.Contains(stdout, "hello_from_sandswap") {
		return fmt.Errorf("execute stdout does not contain 'hello_from_sandswap': %s", stdout)
	}

	exitCode, _ := m["exit_code"].(float64)
	if exitCode != 0 {
		return fmt.Errorf("execute exit_code = %v, expected 0", exitCode)
	}

	pass("execute: shell echo works, stdout correct, exit_code=0")
	return nil
}

func testFileWrite(ctx context.Context, c *client.Client, sid string) error {
	result, err := callTool(ctx, c, "file_write", map[string]interface{}{
		"sandfs_id": sid,
		"path":      "mcp_test.txt",
		"data":      "hello world from mcp e2e test",
	})
	if err != nil {
		return err
	}

	text := toolText(result)
	m := parseJSON(text)
	if m == nil {
		return fmt.Errorf("file_write result is not valid JSON: %s", text)
	}

	okVal, _ := m["ok"].(bool)
	if !okVal {
		return fmt.Errorf("file_write ok=false: %s", text)
	}

	pass("file_write: wrote mcp_test.txt")
	return nil
}

func testFileRead(ctx context.Context, c *client.Client, sid string) error {
	result, err := callTool(ctx, c, "file_read", map[string]interface{}{
		"sandfs_id": sid,
		"path":      "mcp_test.txt",
	})
	if err != nil {
		return err
	}

	text := toolText(result)
	m := parseJSON(text)
	if m == nil {
		return fmt.Errorf("file_read result is not valid JSON: %s", text)
	}

	data, _ := m["data"].(string)
	if !strings.Contains(data, "hello world from mcp e2e test") {
		return fmt.Errorf("file_read data does not match written content: %s", data)
	}

	pass("file_read: content matches what was written")
	return nil
}

func testFileStat(ctx context.Context, c *client.Client, sid string) error {
	result, err := callTool(ctx, c, "file_stat", map[string]interface{}{
		"sandfs_id": sid,
		"path":      "mcp_test.txt",
	})
	if err != nil {
		return err
	}

	text := toolText(result)
	if text == "" {
		return fmt.Errorf("file_stat returned empty result")
	}

	// stat returns JSON metadata for the file written at the top of this suite
	// ("hello world from mcp e2e test") — a non-JSON blob or metadata that does
	// not describe THAT file is garbage, not a pass. (The previous version
	// accepted any non-empty text and also passed on parse failure.)
	m := parseJSON(text)
	if m == nil {
		return fmt.Errorf("file_stat result is not valid JSON: %s", text)
	}

	if ft, _ := m["file_type"].(string); ft != "file" {
		return fmt.Errorf("file_stat file_type=%q, expected \"file\": %s", ft, text)
	}
	if size, ok := m["size"].(float64); !ok || size != float64(len("hello world from mcp e2e test")) {
		return fmt.Errorf("file_stat size=%v, expected %d: %s", m["size"], len("hello world from mcp e2e test"), text)
	}

	pass("file_stat: got metadata for mcp_test.txt")
	return nil
}

func testFileListDir(ctx context.Context, c *client.Client, sid string) error {
	result, err := callTool(ctx, c, "file_list_dir", map[string]interface{}{
		"sandfs_id": sid,
		"path":      ".",
	})
	if err != nil {
		return err
	}

	text := toolText(result)
	m := parseJSON(text)
	if m == nil {
		return fmt.Errorf("file_list_dir result is not valid JSON: %s", text)
	}

	entries, ok := m["entries"]
	if !ok {
		return fmt.Errorf("file_list_dir missing 'entries' key: %s", text)
	}

	// Verify mcp_test.txt appears in the listing.
	entriesJSON, _ := json.Marshal(entries)
	if !strings.Contains(string(entriesJSON), "mcp_test.txt") {
		return fmt.Errorf("mcp_test.txt not found in directory listing: %s", string(entriesJSON))
	}

	pass("file_list_dir: mcp_test.txt appears in listing")
	return nil
}

func testFileMkdir(ctx context.Context, c *client.Client, sid string) error {
	result, err := callTool(ctx, c, "file_mkdir", map[string]interface{}{
		"sandfs_id": sid,
		"path":      "mcp_subdir",
	})
	if err != nil {
		return err
	}

	text := toolText(result)
	m := parseJSON(text)
	if m == nil {
		return fmt.Errorf("file_mkdir result is not valid JSON: %s", text)
	}

	okVal, _ := m["ok"].(bool)
	if !okVal {
		return fmt.Errorf("file_mkdir ok=false: %s", text)
	}

	pass("file_mkdir: created mcp_subdir/")
	return nil
}

func testFileRename(ctx context.Context, c *client.Client, sid string) error {
	result, err := callTool(ctx, c, "file_rename", map[string]interface{}{
		"sandfs_id": sid,
		"path":      "mcp_test.txt",
		"new_path":  "mcp_renamed.txt",
	})
	if err != nil {
		return err
	}

	text := toolText(result)
	m := parseJSON(text)
	if m == nil {
		return fmt.Errorf("file_rename result is not valid JSON: %s", text)
	}

	okVal, _ := m["ok"].(bool)
	if !okVal {
		return fmt.Errorf("file_rename ok=false: %s", text)
	}

	pass("file_rename: mcp_test.txt → mcp_renamed.txt")
	return nil
}

func testFileRemove(ctx context.Context, c *client.Client, sid string) error {
	result, err := callTool(ctx, c, "file_remove", map[string]interface{}{
		"sandfs_id": sid,
		"path":      "mcp_renamed.txt",
	})
	if err != nil {
		return err
	}

	text := toolText(result)
	m := parseJSON(text)
	if m == nil {
		return fmt.Errorf("file_remove result is not valid JSON: %s", text)
	}

	okVal, _ := m["ok"].(bool)
	if !okVal {
		return fmt.Errorf("file_remove ok=false: %s", text)
	}

	pass("file_remove: deleted mcp_renamed.txt")
	return nil
}

func testBackgroundExecLifecycle(ctx context.Context, c *client.Client, sid string) error {
	// 1. Start a background exec
	result, err := callTool(ctx, c, "execute", map[string]interface{}{
		"sandfs_id":      sid,
		"code":           "sleep 120",
		"language":       "shell",
		"background":     true,
		"lease_duration": 300,
	})
	if err != nil {
		return fmt.Errorf("background execute error: %w", err)
	}

	text := toolText(result)
	m := parseJSON(text)
	if m == nil {
		return fmt.Errorf("background execute result is not valid JSON: %s", text)
	}

	execID, _ := m["exec_id"].(string)
	if execID == "" {
		return fmt.Errorf("background execute missing exec_id: %s", text)
	}

	status, _ := m["status"].(string)
	if status != "running" {
		return fmt.Errorf("background execute status=%q, expected 'running'", status)
	}

	passf("background exec: started exec_id=%s, status=running", execID)

	// 2. Poll status — should be "running"
	statusResult, err := callTool(ctx, c, "exec_status", map[string]interface{}{
		"sandfs_id": sid,
		"exec_id":   execID,
	})
	if err != nil {
		return fmt.Errorf("exec_status error: %w", err)
	}

	statusText := toolText(statusResult)
	statusM := parseJSON(statusText)
	if statusM == nil {
		return fmt.Errorf("exec_status result is not valid JSON: %s", statusText)
	}

	currentStatus, _ := statusM["status"].(string)
	if currentStatus != "running" {
		return fmt.Errorf("exec_status status=%q, expected 'running'", currentStatus)
	}

	pass("exec_status: background exec is running")

	// 3. Kill the background exec
	killResult, err := callTool(ctx, c, "exec_kill", map[string]interface{}{
		"sandfs_id": sid,
		"exec_id":   execID,
	})
	if err != nil {
		return fmt.Errorf("exec_kill error: %w", err)
	}

	killText := toolText(killResult)
	killM := parseJSON(killText)
	if killM == nil {
		return fmt.Errorf("exec_kill result is not valid JSON: %s", killText)
	}

	killStatus, _ := killM["status"].(string)
	if killStatus != "killed" {
		return fmt.Errorf("exec_kill status=%q, expected 'killed'", killStatus)
	}

	pass("exec_kill: background exec killed")
	return nil
}

func testExecuteWithStderr(ctx context.Context, c *client.Client, sid string) error {
	result, err := callTool(ctx, c, "execute", map[string]interface{}{
		"sandfs_id": sid,
		"code":      "echo stderr_test >&2",
		"language":  "shell",
	})
	if err != nil {
		return err
	}

	text := toolText(result)
	m := parseJSON(text)
	if m == nil {
		return fmt.Errorf("execute result is not valid JSON: %s", text)
	}

	stderr, _ := m["stderr"].(string)
	if !strings.Contains(stderr, "stderr_test") {
		// The e2e runs the stack it just built (same sandlot/warden), so there
		// is no "version limitation" to excuse a missing/empty stderr — this IS
		// the property the test exists for.
		return fmt.Errorf("execute stderr missing or does not contain 'stderr_test' (stderr=%q): %s", stderr, text)
	}

	pass("execute: stderr captured correctly")
	return nil
}

func testExecuteMissingSandfsIDRejected(ctx context.Context, c *client.Client, sid string) error {
	// sandfs_id is REQUIRED: omitting it must be a client error, even when the
	// agent owns exactly one sandfs. The MCP server surfaces handler errors as
	// IsError tool results (not JSON-RPC protocol errors), so both shapes are
	// checked here.
	result, err := callTool(ctx, c, "execute", map[string]interface{}{
		"code":     "echo should_not_run",
		"language": "shell",
	})
	if err != nil {
		if !strings.Contains(err.Error(), "sandfs_id is required") {
			return fmt.Errorf("expected 'sandfs_id is required', got: %w", err)
		}
		pass("execute: omitted sandfs_id rejected with 'sandfs_id is required'")
		return nil
	}
	text := ""
	isErr := false
	if result != nil {
		text = toolText(result)
		isErr = result.IsError
	}
	if !isErr {
		return fmt.Errorf("execute without sandfs_id unexpectedly succeeded (text=%q)", text)
	}
	if !strings.Contains(text, "sandfs_id is required") {
		return fmt.Errorf("expected 'sandfs_id is required' in error result, got: %q", text)
	}

	pass("execute: omitted sandfs_id rejected with 'sandfs_id is required'")
	return nil
}

func testFileWorkflow(ctx context.Context, c *client.Client, sid string) error {
	// Full write → read → stat → rename → remove workflow in a subdirectory.
	// This tests the complete file lifecycle in one test case.

	// Write
	writeResult, err := callTool(ctx, c, "file_write", map[string]interface{}{
		"sandfs_id": sid,
		"path":      "workflow/test.txt",
		"data":      "workflow content",
	})
	if err != nil {
		return fmt.Errorf("workflow write: %w", err)
	}
	writeM := parseJSON(toolText(writeResult))
	if okVal, _ := writeM["ok"].(bool); !okVal {
		return fmt.Errorf("workflow write ok=false")
	}

	// Read
	readResult, err := callTool(ctx, c, "file_read", map[string]interface{}{
		"sandfs_id": sid,
		"path":      "workflow/test.txt",
	})
	if err != nil {
		return fmt.Errorf("workflow read: %w", err)
	}
	readM := parseJSON(toolText(readResult))
	data, _ := readM["data"].(string)
	if data != "workflow content" {
		return fmt.Errorf("workflow read: data=%q, expected 'workflow content'", data)
	}

	// Rename
	renameResult, err := callTool(ctx, c, "file_rename", map[string]interface{}{
		"sandfs_id": sid,
		"path":      "workflow/test.txt",
		"new_path":  "workflow/renamed.txt",
	})
	if err != nil {
		return fmt.Errorf("workflow rename: %w", err)
	}
	renameM := parseJSON(toolText(renameResult))
	if okVal, _ := renameM["ok"].(bool); !okVal {
		return fmt.Errorf("workflow rename ok=false")
	}

	// Remove
	removeResult, err := callTool(ctx, c, "file_remove", map[string]interface{}{
		"sandfs_id": sid,
		"path":      "workflow/renamed.txt",
	})
	if err != nil {
		return fmt.Errorf("workflow remove: %w", err)
	}
	removeM := parseJSON(toolText(removeResult))
	if okVal, _ := removeM["ok"].(bool); !okVal {
		return fmt.Errorf("workflow remove ok=false")
	}

	// Clean up the workflow directory
	callTool(ctx, c, "file_remove", map[string]interface{}{
		"sandfs_id": sid,
		"path":      "workflow",
		"recursive": true,
	})

	pass("file workflow: write → read → rename → remove (all ok)")
	return nil
}

// ── Main ─────────────────────────────────────────────────────

func main() {
	flag.Parse()

	if *apiKey == "" {
		fmt.Fprintln(os.Stderr, "Error: -api-key is required")
		flag.Usage()
		os.Exit(1)
	}

	mcpEndpoint := *gatewayURL + "/mcp"

	fmt.Println("═══════════════════════════════════════════════════")
	fmt.Println("  Sandswap MCP E2E Test")
	fmt.Printf("  Gateway:  %s\n", *gatewayURL)
	fmt.Printf("  MCP:      %s\n", mcpEndpoint)
	fmt.Printf("  API Key:  %s...%s\n", (*apiKey)[:min(12, len(*apiKey))], func() string {
		if len(*apiKey) > 12 {
			return "(redacted)"
		}
		return ""
	}())
	fmt.Println("═══════════════════════════════════════════════════")
	fmt.Println()

	// Create MCP client with auth header.
	c, err := client.NewStreamableHttpClient(mcpEndpoint,
		transport.WithHTTPHeaders(map[string]string{
			"Authorization": "Bearer " + *apiKey,
		}),
		transport.WithHTTPTimeout(*timeout),
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create MCP client: %v\n", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	// Start + Initialize
	fmt.Println("Connecting to MCP server...")
	if err := c.Start(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to start MCP client: %v\n", err)
		os.Exit(1)
	}

	initResult, err := c.Initialize(ctx, mcp.InitializeRequest{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Initialized: server=%s v%s, protocol=%s\n\n",
		initResult.ServerInfo.Name,
		initResult.ServerInfo.Version,
		initResult.ProtocolVersion,
	)
	serverInstructions = initResult.Instructions

	// Auto-detect sandfs_id if not provided.
	resolvedSandfsID := *sandfsID
	if resolvedSandfsID == "" {
		// Use list_sandfs to find the first sandfs.
		result, err := callTool(ctx, c, "list_sandfs", map[string]interface{}{})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to list sandfs: %v\n", err)
			os.Exit(1)
		}
		m := parseJSON(toolText(result))
		if m == nil {
			fmt.Fprintln(os.Stderr, "list_sandfs returned invalid JSON")
			os.Exit(1)
		}
		list, _ := m["sandfs_list"].([]interface{})
		if len(list) == 0 {
			fmt.Fprintln(os.Stderr, "Agent has no sandfs instances")
			os.Exit(1)
		}
		first, _ := list[0].(map[string]interface{})
		resolvedSandfsID, _ = first["sandfs_id"].(string)
		if resolvedSandfsID == "" {
			fmt.Fprintln(os.Stderr, "Could not extract sandfs_id from list_sandfs result")
			os.Exit(1)
		}
		fmt.Printf("Auto-detected sandfs_id: %s\n\n", resolvedSandfsID)
	}

	// Run all test cases.
	tests := []testCase{
		{"initialize (verify capabilities)", testInitialize},
		{"initialize (server instructions)", testServerInstructions},
		{"tools/list (all 12 tools)", testToolsList},
		{"sandswap_guide (matches initialize instructions)", testSandswapGuide},
		{"list_sandfs", testListSandfs},
		{"execute (shell echo)", testExecute},
		{"file_write", testFileWrite},
		{"file_read", testFileRead},
		{"file_stat", testFileStat},
		{"file_list_dir", testFileListDir},
		{"file_mkdir", testFileMkdir},
		{"file_rename", testFileRename},
		{"file_remove", testFileRemove},
		{"background exec lifecycle (start→status→kill)", testBackgroundExecLifecycle},
		{"execute with stderr", testExecuteWithStderr},
		{"execute omitted sandfs_id rejected", testExecuteMissingSandfsIDRejected},
		{"file workflow (write→read→rename→remove)", testFileWorkflow},
	}

	fmt.Println("Running test cases:")
	fmt.Println("───────────────────────────────────────────────────")

	for _, tc := range tests {
		fmt.Printf("▸ %s\n", tc.name)
		testCtx, testCancel := context.WithTimeout(ctx, *timeout)
		if err := tc.run(testCtx, c, resolvedSandfsID); err != nil {
			failf("%s: %v", tc.name, err)
		}
		testCancel()
	}

	fmt.Println("───────────────────────────────────────────────────")
	fmt.Println()

	// Summary
	total := passCount + failCount
	fmt.Println("═══════════════════════════════════════════════════")
	if failCount == 0 {
		fmt.Printf("  ALL PASSED (%d/%d)\n", passCount, total)
	} else {
		fmt.Printf("  FAILED: %d/%d failed, %d/%d passed\n", failCount, total, passCount, total)
	}
	fmt.Println("═══════════════════════════════════════════════════")

	// Clean up
	c.Close()

	if failCount > 0 {
		os.Exit(1)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func passf(format string, args ...interface{}) {
	pass(fmt.Sprintf(format, args...))
}

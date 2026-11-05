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
	"errors"
	"strings"
	"testing"

	"gateway/pool"
)

// ── Pure arg-extraction helpers ──────────────────────────────────

func TestGetStringArg(t *testing.T) {
	t.Helper()
	cases := []struct {
		name string
		args map[string]interface{}
		key  string
		want string
	}{
		{name: "present string value", args: map[string]interface{}{"sandfs_id": "sf-1"}, key: "sandfs_id", want: "sf-1"},
		{name: "missing key returns empty", args: map[string]interface{}{"other": "x"}, key: "sandfs_id", want: ""},
		{name: "nil args returns empty", args: nil, key: "sandfs_id", want: ""},
		{name: "non-string value returns empty (not a panic)", args: map[string]interface{}{"sandfs_id": 123}, key: "sandfs_id", want: ""},
		{name: "empty string value preserved", args: map[string]interface{}{"sandfs_id": ""}, key: "sandfs_id", want: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := getStringArg(tc.args, tc.key); got != tc.want {
				t.Errorf("getStringArg(%+v, %q) = %q, want %q", tc.args, tc.key, got, tc.want)
			}
		})
	}
}

func TestGetIntArg(t *testing.T) {
	t.Helper()
	cases := []struct {
		name string
		args map[string]interface{}
		key  string
		want int
	}{
		{name: "float64 (json default for numbers)", args: map[string]interface{}{"timeout": float64(42)}, key: "timeout", want: 42},
		{name: "json.Number integer", args: map[string]interface{}{"timeout": json.Number("42")}, key: "timeout", want: 42},
		{name: "string integer", args: map[string]interface{}{"timeout": "42"}, key: "timeout", want: 42},
		{name: "missing returns 0", args: map[string]interface{}{}, key: "timeout", want: 0},
		{name: "nil args returns 0", args: nil, key: "timeout", want: 0},
		{name: "float64 truncates toward zero", args: map[string]interface{}{"timeout": float64(3.9)}, key: "timeout", want: 3},
		{name: "non-numeric string returns 0", args: map[string]interface{}{"timeout": "abc"}, key: "timeout", want: 0},
		{name: "bool value (wrong type) returns 0", args: map[string]interface{}{"timeout": true}, key: "timeout", want: 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := getIntArg(tc.args, tc.key); got != tc.want {
				t.Errorf("getIntArg(%+v, %q) = %d, want %d", tc.args, tc.key, got, tc.want)
			}
		})
	}
}

func TestGetBoolArg(t *testing.T) {
	t.Helper()
	cases := []struct {
		name string
		args map[string]interface{}
		key  string
		want bool
	}{
		{name: "true", args: map[string]interface{}{"background": true}, key: "background", want: true},
		{name: "false", args: map[string]interface{}{"background": false}, key: "background", want: false},
		{name: "missing returns false", args: map[string]interface{}{}, key: "background", want: false},
		{name: "nil args returns false", args: nil, key: "background", want: false},
		{name: "non-bool (string) returns false", args: map[string]interface{}{"background": "true"}, key: "background", want: false},
		{name: "non-bool (int) returns false", args: map[string]interface{}{"background": 1}, key: "background", want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := getBoolArg(tc.args, tc.key); got != tc.want {
				t.Errorf("getBoolArg(%+v, %q) = %v, want %v", tc.args, tc.key, got, tc.want)
			}
		})
	}
}

// ── dispatchToolCall routing ─────────────────────────────────────

// TestDispatchToolCall_Routing verifies that each known tool name dispatches
// to the correct handler (success path), and that an unknown tool name yields
// an "unknown tool" error. Each case exercises a success path so we confirm
// the routing actually reaches the handler rather than erroring early.
func TestDispatchToolCall_Routing(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	conn := env.resolvedConn()

	// Configure the fake for the success shape each tool expects.
	env.fake.execResult = pool.ExecResult{Stdout: "routed", ExitCode: 0, Status: "done"}
	env.fake.fileResult = pool.FileOpResult{Data: []byte("file-data"), Success: true}
	env.fake.statusResult = pool.ExecResult{Status: "running", ExitCode: 0, Stdout: "partial"}

	cases := []struct {
		tool string
		args map[string]interface{}
	}{
		{"execute", map[string]interface{}{"sandfs_id": env.sandfsID, "code": "echo hi", "language": "shell"}},
		{"file_read", map[string]interface{}{"sandfs_id": env.sandfsID, "path": "a.txt"}},
		{"file_write", map[string]interface{}{"sandfs_id": env.sandfsID, "path": "a.txt", "data": "x"}},
		{"file_stat", map[string]interface{}{"sandfs_id": env.sandfsID, "path": "a.txt"}},
		{"file_list_dir", map[string]interface{}{"sandfs_id": env.sandfsID, "path": "."}},
		{"file_mkdir", map[string]interface{}{"sandfs_id": env.sandfsID, "path": "d"}},
		{"file_remove", map[string]interface{}{"sandfs_id": env.sandfsID, "path": "d"}},
		{"file_rename", map[string]interface{}{"sandfs_id": env.sandfsID, "path": "a", "new_path": "b"}},
		{"exec_status", map[string]interface{}{"sandfs_id": env.sandfsID, "exec_id": "bg-1"}},
		{"exec_kill", map[string]interface{}{"sandfs_id": env.sandfsID, "exec_id": "bg-1"}},
		{"list_sandfs", nil},
	}
	for _, tc := range cases {
		t.Run(tc.tool, func(t *testing.T) {
			res, err := env.server.dispatchToolCall(ctx, conn, tc.tool, tc.args)
			if err != nil {
				t.Fatalf("dispatchToolCall(%q) returned unexpected error: %v", tc.tool, err)
			}
			if res == nil || len(res.Content) == 0 || res.Content[0].Text == "" {
				t.Fatalf("dispatchToolCall(%q) returned empty result: %+v", tc.tool, res)
			}
		})
	}

	// Unknown tool name must error (not panic, not silently succeed).
	t.Run("unknown_tool", func(t *testing.T) {
		_, err := env.server.dispatchToolCall(ctx, conn, "does_not_exist", nil)
		if err == nil {
			t.Fatal("expected error for unknown tool, got nil")
		}
		if !strings.Contains(err.Error(), "unknown tool") {
			t.Errorf("error should mention 'unknown tool', got: %v", err)
		}
	})
}

// ── handleExecute ────────────────────────────────────────────────

// TestHandleExecute_AutoResolveMultiple verifies that omitting sandfs_id with an
// agent that has multiple sandfs is rejected (ambiguous - the agent must pick).
func TestHandleExecute_AutoResolveMultiple(t *testing.T) {
	env := newTestEnv(t)
	env.addSandfs("second") // now 2 sandfs -> ambiguous
	ctx := context.Background()
	conn := env.resolvedConn()

	_, err := env.server.dispatchToolCall(ctx, conn, "execute", map[string]interface{}{
		"code":     "echo hi",
		"language": "shell",
		// sandfs_id intentionally omitted
	})
	if err == nil {
		t.Fatal("expected error when sandfs_id omitted with multiple sandfs")
	}
	if !strings.Contains(err.Error(), "sandfs_id is required") {
		t.Errorf("expected 'sandfs_id is required' error, got: %v", err)
	}
}

// TestHandleExecute_MissingSandfsIDRejected verifies sandfs_id is REQUIRED:
// omitting it is a client error regardless of how many sandfs the agent owns.
func TestHandleExecute_MissingSandfsIDRejected(t *testing.T) {
	env := newTestEnv(t) // exactly 1 sandfs — even then, omission must fail
	ctx := context.Background()
	conn := env.resolvedConn()

	_, err := env.server.dispatchToolCall(ctx, conn, "execute", map[string]interface{}{
		"code":     "echo hi",
		"language": "shell",
	})
	if err == nil {
		t.Fatal("expected error when sandfs_id is omitted")
	}
	if !strings.Contains(err.Error(), "sandfs_id is required") {
		t.Errorf("expected 'sandfs_id is required', got: %v", err)
	}
}

// TestHandleExecute_ResultShaping verifies all execute result fields are
// serialized into the MCP text content and that args forward correctly.
func TestHandleExecute_ResultShaping(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	conn := env.resolvedConn()
	env.fake.execResult = pool.ExecResult{
		Stdout: "out", Stderr: "err", ExitCode: 7, ExecID: "bg-9",
		Status: "done", ExecDurationNs: 111, SandlotDurationNs: 222,
	}

	res, err := env.server.dispatchToolCall(ctx, conn, "execute", map[string]interface{}{
		"sandfs_id":      env.sandfsID,
		"code":           "x",
		"language":       "python",
		"timeout":        float64(5),
		"background":     true,
		"lease_duration": float64(300),
	})
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}
	var got map[string]interface{}
	if err := json.Unmarshal([]byte(res.Content[0].Text), &got); err != nil {
		t.Fatalf("response not valid JSON: %v\nraw: %s", err, res.Content[0].Text)
	}
	checks := map[string]interface{}{
		"stdout":              "out",
		"stderr":              "err",
		"exit_code":           float64(7),
		"exec_id":             "bg-9",
		"status":              "done",
		"exec_duration_ns":    float64(111),
		"sandlot_duration_ns": float64(222),
	}
	for k, want := range checks {
		if got[k] != want {
			t.Errorf("response.%s = %v (%T), want %v (%T)", k, got[k], got[k], want, want)
		}
	}
	if _, ok := got["gateway_duration_ns"]; !ok {
		t.Error("response missing gateway_duration_ns")
	}

	// Verify the forwarded ExecRequest carried the parsed args.
	lr := env.fake.lastExec()
	if lr.TimeoutMs != 5000 {
		t.Errorf("timeout forwarding: got %d want 5000", lr.TimeoutMs)
	}
	if !lr.Background {
		t.Error("background flag not forwarded")
	}
	if lr.LeaseDurationMs != 300000 {
		t.Errorf("lease_duration forwarding: got %d want 300000", lr.LeaseDurationMs)
	}
}

// TestHandleExecute_EmptyCode verifies that empty code surfaces as an error
// (the handler rejects it before any RPC).
func TestHandleExecute_EmptyCode(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	conn := env.resolvedConn()

	_, err := env.server.dispatchToolCall(ctx, conn, "execute", map[string]interface{}{
		"sandfs_id": env.sandfsID,
		"language":  "shell",
	})
	if err == nil {
		t.Fatal("expected error for empty code")
	}
	if !strings.Contains(err.Error(), "code is required") {
		t.Errorf("expected 'code is required' error, got: %v", err)
	}
	if env.fake.execCalls.Load() != 0 {
		t.Errorf("expected zero exec RPCs, got %d", env.fake.execCalls.Load())
	}
}

// ── handleFileOp ─────────────────────────────────────────────────

// TestHandleFileOp_MissingSandfsIDRejected verifies sandfs_id is REQUIRED for
// file tools: omitting it is a client error even when the agent has one sandfs.
func TestHandleFileOp_MissingSandfsIDRejected(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	conn := env.resolvedConn()

	_, err := env.server.dispatchToolCall(ctx, conn, "file_read", map[string]interface{}{
		"path": "a.txt",
	})
	if err == nil {
		t.Fatal("expected error when sandfs_id is omitted")
	}
	if !strings.Contains(err.Error(), "sandfs_id is required") {
		t.Errorf("expected 'sandfs_id is required', got: %v", err)
	}
}

// TestHandleFileOp_WriteArgForwarding verifies that write-specific args (data,
// mode, append) are parsed and forwarded correctly to the sandlot FileOp RPC.
func TestHandleFileOp_WriteArgForwarding(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	conn := env.resolvedConn()
	env.fake.fileResult = pool.FileOpResult{Success: true}

	_, err := env.server.dispatchToolCall(ctx, conn, "file_write", map[string]interface{}{
		"sandfs_id": env.sandfsID,
		"path":      "out.txt",
		"data":      "hello",
		"mode":      float64(0644),
		"append":    true,
	})
	if err != nil {
		t.Fatalf("file_write failed: %v", err)
	}
	lr, _ := env.fake.lastFile()
	if lr.Action != "write" {
		t.Errorf("action = %q, want write", lr.Action)
	}
	if string(lr.Data) != "hello" {
		t.Errorf("data = %q, want hello", string(lr.Data))
	}
	if lr.Mode != 0644 {
		t.Errorf("mode = %o, want 0644", lr.Mode)
	}
	if lr.Offset != -1 {
		t.Errorf("append should set Offset=-1, got %d", lr.Offset)
	}
	if lr.Path != "out.txt" {
		t.Errorf("path = %q, want out.txt", lr.Path)
	}
}

// TestHandleFileOp_WriteBase64 verifies base64 binary content is decoded and
// forwarded, taking precedence over the text data field.
func TestHandleFileOp_WriteBase64(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	conn := env.resolvedConn()
	env.fake.fileResult = pool.FileOpResult{Success: true}

	raw := []byte{0x00, 0xff, 0x1a}
	_, err := env.server.dispatchToolCall(ctx, conn, "file_write", map[string]interface{}{
		"sandfs_id":   env.sandfsID,
		"path":        "bin.dat",
		"data_base64": base64.StdEncoding.EncodeToString(raw),
		"data":        "should-be-ignored",
	})
	if err != nil {
		t.Fatalf("file_write base64 failed: %v", err)
	}
	lr, _ := env.fake.lastFile()
	if string(lr.Data) != string(raw) {
		t.Errorf("decoded data = %v, want %v", lr.Data, raw)
	}
}

// TestHandleFileOp_WriteInvalidBase64 verifies a base64 decode error surfaces
// as an error before any RPC is attempted.
func TestHandleFileOp_WriteInvalidBase64(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	conn := env.resolvedConn()

	_, err := env.server.dispatchToolCall(ctx, conn, "file_write", map[string]interface{}{
		"sandfs_id":   env.sandfsID,
		"path":        "bin.dat",
		"data_base64": "!!!not-base64!!!",
	})
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
	if !strings.Contains(err.Error(), "invalid base64") {
		t.Errorf("expected 'invalid base64' error, got: %v", err)
	}
	if env.fake.fileCalls.Load() != 0 {
		t.Errorf("expected zero FileOp RPCs on decode error, got %d", env.fake.fileCalls.Load())
	}
}

// TestHandleFileOp_ReadArgForwarding verifies offset/length parsing for reads.
func TestHandleFileOp_ReadArgForwarding(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	conn := env.resolvedConn()
	env.fake.fileResult = pool.FileOpResult{Data: []byte("data"), Success: true}

	_, err := env.server.dispatchToolCall(ctx, conn, "file_read", map[string]interface{}{
		"sandfs_id": env.sandfsID,
		"path":      "f.txt",
		"offset":    float64(10),
		"length":    float64(20),
	})
	if err != nil {
		t.Fatalf("file_read failed: %v", err)
	}
	lr, _ := env.fake.lastFile()
	if lr.Offset != 10 {
		t.Errorf("offset = %d, want 10", lr.Offset)
	}
	if lr.Length != 20 {
		t.Errorf("length = %d, want 20", lr.Length)
	}
}

// TestHandleFileOp_ListDirDepth verifies depth forwarding.
func TestHandleFileOp_ListDirDepth(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	conn := env.resolvedConn()
	env.fake.fileResult = pool.FileOpResult{Data: []byte("[]"), Success: true}

	_, err := env.server.dispatchToolCall(ctx, conn, "file_list_dir", map[string]interface{}{
		"sandfs_id": env.sandfsID,
		"path":      ".",
		"depth":     float64(3),
	})
	if err != nil {
		t.Fatalf("file_list_dir failed: %v", err)
	}
	lr, _ := env.fake.lastFile()
	if lr.Depth != 3 {
		t.Errorf("depth = %d, want 3", lr.Depth)
	}
}

// TestHandleFileOp_MkdirMode verifies mode forwarding for mkdir.
func TestHandleFileOp_MkdirMode(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	conn := env.resolvedConn()
	env.fake.fileResult = pool.FileOpResult{Success: true}

	_, err := env.server.dispatchToolCall(ctx, conn, "file_mkdir", map[string]interface{}{
		"sandfs_id": env.sandfsID,
		"path":      "d",
		"mode":      float64(0755),
	})
	if err != nil {
		t.Fatalf("file_mkdir failed: %v", err)
	}
	lr, _ := env.fake.lastFile()
	if lr.Mode != 0755 {
		t.Errorf("mode = %o, want 0755", lr.Mode)
	}
}

// TestHandleFileOp_RemoveRecursive verifies recursive flag forwarding.
func TestHandleFileOp_RemoveRecursive(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	conn := env.resolvedConn()
	env.fake.fileResult = pool.FileOpResult{Success: true}

	_, err := env.server.dispatchToolCall(ctx, conn, "file_remove", map[string]interface{}{
		"sandfs_id": env.sandfsID,
		"path":      "d",
		"recursive": true,
	})
	if err != nil {
		t.Fatalf("file_remove failed: %v", err)
	}
	lr, _ := env.fake.lastFile()
	if !lr.Recursive {
		t.Error("recursive = false, want true")
	}
}

// TestHandleFileOp_RenameNewPath verifies new_path forwarding.
func TestHandleFileOp_RenameNewPath(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	conn := env.resolvedConn()
	env.fake.fileResult = pool.FileOpResult{Success: true}

	_, err := env.server.dispatchToolCall(ctx, conn, "file_rename", map[string]interface{}{
		"sandfs_id": env.sandfsID,
		"path":      "a",
		"new_path":  "b",
	})
	if err != nil {
		t.Fatalf("file_rename failed: %v", err)
	}
	lr, _ := env.fake.lastFile()
	if lr.NewPath != "b" {
		t.Errorf("new_path = %q, want b", lr.NewPath)
	}
}

// TestHandleFileOp_ReadResponseShaping verifies the read response is shaped per
// the HTTP handler contract: text data -> {ok,data,is_text:true,size}; binary
// data -> {ok,data_base64,is_text:false,size}.
func TestHandleFileOp_ReadResponseShaping(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	conn := env.resolvedConn()

	t.Run("text", func(t *testing.T) {
		env.fake.fileResult = pool.FileOpResult{Data: []byte("hello world"), Success: true}
		res, err := env.server.dispatchToolCall(ctx, conn, "file_read", map[string]interface{}{
			"sandfs_id": env.sandfsID, "path": "f",
		})
		if err != nil {
			t.Fatalf("file_read: %v", err)
		}
		var got map[string]interface{}
		json.Unmarshal([]byte(res.Content[0].Text), &got)
		if got["ok"] != true {
			t.Errorf("ok = %v, want true", got["ok"])
		}
		if got["data"] != "hello world" {
			t.Errorf("data = %v, want 'hello world'", got["data"])
		}
		if got["is_text"] != true {
			t.Errorf("is_text = %v, want true", got["is_text"])
		}
		if got["size"] != float64(11) {
			t.Errorf("size = %v, want 11", got["size"])
		}
	})

	t.Run("binary", func(t *testing.T) {
		env.fake.fileResult = pool.FileOpResult{Data: []byte{0xff, 0xfe, 0x00}, Success: true}
		res, err := env.server.dispatchToolCall(ctx, conn, "file_read", map[string]interface{}{
			"sandfs_id": env.sandfsID, "path": "f",
		})
		if err != nil {
			t.Fatalf("file_read: %v", err)
		}
		var got map[string]interface{}
		json.Unmarshal([]byte(res.Content[0].Text), &got)
		if got["is_text"] != false {
			t.Errorf("is_text = %v, want false", got["is_text"])
		}
		wantB64 := base64.StdEncoding.EncodeToString([]byte{0xff, 0xfe, 0x00})
		if got["data_base64"] != wantB64 {
			t.Errorf("data_base64 = %v, want %s", got["data_base64"], wantB64)
		}
		if got["size"] != float64(3) {
			t.Errorf("size = %v, want 3", got["size"])
		}
	})
}

// TestHandleFileOp_StatResponseShaping verifies stat passes through JSON
// metadata as structured data, with a string fallback for non-JSON.
func TestHandleFileOp_StatResponseShaping(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	conn := env.resolvedConn()

	t.Run("valid_json", func(t *testing.T) {
		env.fake.fileResult = pool.FileOpResult{Data: []byte(`{"size":42,"mode":"0644"}`), Success: true}
		res, err := env.server.dispatchToolCall(ctx, conn, "file_stat", map[string]interface{}{
			"sandfs_id": env.sandfsID, "path": "f",
		})
		if err != nil {
			t.Fatalf("file_stat: %v", err)
		}
		var got map[string]interface{}
		json.Unmarshal([]byte(res.Content[0].Text), &got)
		// stat returns the parsed object directly (not wrapped in {ok:...}).
		if got["size"] != float64(42) {
			t.Errorf("size = %v, want 42", got["size"])
		}
		if got["mode"] != "0644" {
			t.Errorf("mode = %v, want 0644", got["mode"])
		}
	})

	t.Run("non_json_fallback", func(t *testing.T) {
		env.fake.fileResult = pool.FileOpResult{Data: []byte("not json"), Success: true}
		res, err := env.server.dispatchToolCall(ctx, conn, "file_stat", map[string]interface{}{
			"sandfs_id": env.sandfsID, "path": "f",
		})
		if err != nil {
			t.Fatalf("file_stat: %v", err)
		}
		var got map[string]interface{}
		json.Unmarshal([]byte(res.Content[0].Text), &got)
		if got["ok"] != true {
			t.Errorf("ok = %v, want true", got["ok"])
		}
		if got["data"] != "not json" {
			t.Errorf("data = %v, want 'not json'", got["data"])
		}
	})
}

// TestHandleFileOp_ListDirResponseShaping verifies list_dir wraps a JSON array
// in {entries:[...]} with a string fallback for non-JSON.
func TestHandleFileOp_ListDirResponseShaping(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	conn := env.resolvedConn()

	t.Run("valid_json_array", func(t *testing.T) {
		env.fake.fileResult = pool.FileOpResult{Data: []byte(`[{"name":"a"},{"name":"b"}]`), Success: true}
		res, err := env.server.dispatchToolCall(ctx, conn, "file_list_dir", map[string]interface{}{
			"sandfs_id": env.sandfsID, "path": ".",
		})
		if err != nil {
			t.Fatalf("file_list_dir: %v", err)
		}
		var got map[string]interface{}
		json.Unmarshal([]byte(res.Content[0].Text), &got)
		entries, ok := got["entries"].([]interface{})
		if !ok {
			t.Fatalf("entries not an array: %T", got["entries"])
		}
		if len(entries) != 2 {
			t.Errorf("entries len = %d, want 2", len(entries))
		}
	})

	t.Run("non_json_fallback", func(t *testing.T) {
		env.fake.fileResult = pool.FileOpResult{Data: []byte("raw text"), Success: true}
		res, err := env.server.dispatchToolCall(ctx, conn, "file_list_dir", map[string]interface{}{
			"sandfs_id": env.sandfsID, "path": ".",
		})
		if err != nil {
			t.Fatalf("file_list_dir: %v", err)
		}
		var got map[string]interface{}
		json.Unmarshal([]byte(res.Content[0].Text), &got)
		if got["entries"] != "raw text" {
			t.Errorf("entries = %v, want 'raw text'", got["entries"])
		}
	})
}

// TestHandleFileOp_WriteResponseShaping verifies write returns {ok,size}.
func TestHandleFileOp_WriteResponseShaping(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	conn := env.resolvedConn()
	env.fake.fileResult = pool.FileOpResult{Success: true}

	res, err := env.server.dispatchToolCall(ctx, conn, "file_write", map[string]interface{}{
		"sandfs_id": env.sandfsID, "path": "f", "data": "12345",
	})
	if err != nil {
		t.Fatalf("file_write: %v", err)
	}
	var got map[string]interface{}
	json.Unmarshal([]byte(res.Content[0].Text), &got)
	if got["ok"] != true {
		t.Errorf("ok = %v, want true", got["ok"])
	}
	if got["size"] != float64(5) {
		t.Errorf("size = %v, want 5 (len of written data)", got["size"])
	}
}

// TestHandleFileOp_DefaultResponseShaping verifies mkdir/remove/rename return {ok:true}.
func TestHandleFileOp_DefaultResponseShaping(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	conn := env.resolvedConn()
	env.fake.fileResult = pool.FileOpResult{Success: true}

	for _, tool := range []string{"file_mkdir", "file_remove", "file_rename"} {
		t.Run(tool, func(t *testing.T) {
			args := map[string]interface{}{"sandfs_id": env.sandfsID, "path": "p"}
			if tool == "file_rename" {
				args["new_path"] = "q"
			}
			res, err := env.server.dispatchToolCall(ctx, conn, tool, args)
			if err != nil {
				t.Fatalf("%s: %v", tool, err)
			}
			var got map[string]interface{}
			json.Unmarshal([]byte(res.Content[0].Text), &got)
			if got["ok"] != true {
				t.Errorf("%s: ok = %v, want true", tool, got["ok"])
			}
		})
	}
}

// TestHandleFileOp_AppLevelError verifies that a non-zero Status from the
// warden (e.g. file not found) surfaces as a Go error, not a success result.
func TestHandleFileOp_AppLevelError(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	conn := env.resolvedConn()
	env.fake.fileResult = pool.FileOpResult{Success: false, Error: "no such file"}

	_, err := env.server.dispatchToolCall(ctx, conn, "file_read", map[string]interface{}{
		"sandfs_id": env.sandfsID, "path": "missing",
	})
	if err == nil {
		t.Fatal("expected error for non-zero status")
	}
	if !strings.Contains(err.Error(), "read:") {
		t.Errorf("error should be prefixed with action 'read:', got: %v", err)
	}
	if !strings.Contains(err.Error(), "no such file") {
		t.Errorf("error should contain warden message, got: %v", err)
	}
}

// TestHandleFileOp_AppLevelErrorEmpty verifies a non-zero status with empty
// Data falls back to a generic "file operation failed" message.
func TestHandleFileOp_AppLevelErrorEmpty(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	conn := env.resolvedConn()
	// Empty Error → dispatch substitutes the default "file operation failed".
	env.fake.fileResult = pool.FileOpResult{Success: false, Error: ""}

	_, err := env.server.dispatchToolCall(ctx, conn, "file_mkdir", map[string]interface{}{
		"sandfs_id": env.sandfsID, "path": "x",
	})
	if err == nil {
		t.Fatal("expected error for app-level failure with empty error")
	}
	if !strings.Contains(err.Error(), "file operation failed") {
		t.Errorf("expected generic 'file operation failed', got: %v", err)
	}
}

// ── handleExecStatus / handleExecKill ────────────────────────────

// TestHandleExecStatus_RequiresFields verifies both sandfs_id and exec_id are
// required; a missing sandfs_id is reported before the exec_id check.
func TestHandleExecStatus_RequiresFields(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	conn := env.resolvedConn()

	// Both omitted → sandfs_id error takes precedence.
	_, err := env.server.dispatchToolCall(ctx, conn, "exec_status", map[string]interface{}{})
	if err == nil {
		t.Fatal("expected error for missing sandfs_id")
	}
	if !strings.Contains(err.Error(), "sandfs_id is required") {
		t.Errorf("expected 'sandfs_id is required', got: %v", err)
	}

	// sandfs_id present + exec_id omitted → exec_id error.
	_, err = env.server.dispatchToolCall(ctx, conn, "exec_status", map[string]interface{}{
		"sandfs_id": env.sandfsID,
	})
	if err == nil {
		t.Fatal("expected error for missing exec_id")
	}
	if !strings.Contains(err.Error(), "exec_id is required") {
		t.Errorf("expected 'exec_id is required', got: %v", err)
	}
}

// TestHandleExecStatus_ResultShaping verifies the status response fields.
// Requires a warm lease so ExecStatusDirect takes the warm path and calls the
// sandlot RPC (otherwise it returns "expired" with no RPC).
func TestHandleExecStatus_ResultShaping(t *testing.T) {
	env := newTestEnv(t)
	env.warmLease()
	ctx := context.Background()
	conn := env.resolvedConn()
	env.fake.statusResult = pool.ExecResult{
		Status: "running", ExitCode: 0, Stdout: "log tail", Stderr: "warn",
	}

	res, err := env.server.dispatchToolCall(ctx, conn, "exec_status", map[string]interface{}{
		"sandfs_id": env.sandfsID, "exec_id": "bg-1",
	})
	if err != nil {
		t.Fatalf("exec_status: %v", err)
	}
	var got map[string]interface{}
	json.Unmarshal([]byte(res.Content[0].Text), &got)
	if got["status"] != "running" {
		t.Errorf("status = %v, want running", got["status"])
	}
	if got["exit_code"] != float64(0) {
		t.Errorf("exit_code = %v, want 0", got["exit_code"])
	}
	if got["stdout"] != "log tail" {
		t.Errorf("stdout = %v, want 'log tail'", got["stdout"])
	}
	if got["stderr"] != "warn" {
		t.Errorf("stderr = %v, want warn", got["stderr"])
	}
}

// TestHandleExecKill_RequiresFields verifies both sandfs_id and exec_id are
// required; a missing sandfs_id is reported before the exec_id check.
func TestHandleExecKill_RequiresFields(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	conn := env.resolvedConn()

	_, err := env.server.dispatchToolCall(ctx, conn, "exec_kill", map[string]interface{}{})
	if err == nil {
		t.Fatal("expected error for missing fields")
	}
	if !strings.Contains(err.Error(), "sandfs_id is required") {
		t.Errorf("expected 'sandfs_id is required', got: %v", err)
	}

	_, err = env.server.dispatchToolCall(ctx, conn, "exec_kill", map[string]interface{}{
		"sandfs_id": env.sandfsID,
	})
	if err == nil {
		t.Fatal("expected error for missing exec_id")
	}
	if !strings.Contains(err.Error(), "exec_id is required") {
		t.Errorf("expected 'exec_id is required', got: %v", err)
	}
}

// TestHandleExecKill_ResultShaping verifies the kill response.
// Requires a warm lease so ExecKillDirect takes the warm path (otherwise it
// returns "expired" without calling KillExec).
func TestHandleExecKill_ResultShaping(t *testing.T) {
	env := newTestEnv(t)
	env.warmLease()
	ctx := context.Background()
	conn := env.resolvedConn()

	res, err := env.server.dispatchToolCall(ctx, conn, "exec_kill", map[string]interface{}{
		"sandfs_id": env.sandfsID, "exec_id": "bg-1",
	})
	if err != nil {
		t.Fatalf("exec_kill: %v", err)
	}
	var got map[string]interface{}
	json.Unmarshal([]byte(res.Content[0].Text), &got)
	if got["status"] != "killed" {
		t.Errorf("status = %v, want killed", got["status"])
	}
}

// TestHandleExecKill_RPCError verifies a sandlot RPC error surfaces
// (the handler returns it directly for exec_kill). Requires a warm lease so
// KillExec is actually called.
func TestHandleExecKill_RPCError(t *testing.T) {
	env := newTestEnv(t)
	env.warmLease()
	ctx := context.Background()
	conn := env.resolvedConn()
	env.fake.killErr = errors.New("vsock connection refused")

	_, err := env.server.dispatchToolCall(ctx, conn, "exec_kill", map[string]interface{}{
		"sandfs_id": env.sandfsID, "exec_id": "bg-1",
	})
	if err == nil {
		t.Fatal("expected error from kill RPC failure")
	}
	if !strings.Contains(err.Error(), "vsock connection refused") {
		t.Errorf("error should contain RPC message, got: %v", err)
	}
}

// ── handleListSandfs ─────────────────────────────────────────────

// TestHandleListSandfs verifies the list response includes the agent's sandfs
// with its metadata fields.
func TestHandleListSandfs(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	conn := env.resolvedConn()

	res, err := env.server.dispatchToolCall(ctx, conn, "list_sandfs", nil)
	if err != nil {
		t.Fatalf("list_sandfs: %v", err)
	}
	var got struct {
		SandfsList []map[string]interface{} `json:"sandfs_list"`
	}
	if err := json.Unmarshal([]byte(res.Content[0].Text), &got); err != nil {
		t.Fatalf("invalid JSON: %v\nraw: %s", err, res.Content[0].Text)
	}
	if len(got.SandfsList) != 1 {
		t.Fatalf("expected 1 sandfs, got %d", len(got.SandfsList))
	}
	sf := got.SandfsList[0]
	if sf["sandfs_id"] != env.sandfsID {
		t.Errorf("sandfs_id = %v, want %s", sf["sandfs_id"], env.sandfsID)
	}
	if sf["name"] != "test-sandfs" {
		t.Errorf("name = %v, want test-sandfs", sf["name"])
	}
	if sf["description"] != "test description" {
		t.Errorf("description = %v, want 'test description'", sf["description"])
	}
	if sf["template"] != "test:v1" {
		t.Errorf("template = %v, want test:v1", sf["template"])
	}
	if _, ok := sf["created_at"]; !ok {
		t.Error("missing created_at field")
	}
}

// TestHandleListSandfs_Empty verifies an agent with no sandfs returns an empty list.
func TestHandleListSandfs_Empty(t *testing.T) {
	env := newTestEnv(t)
	if err := env.store.DeleteSandFS(env.sandfsID); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	conn := env.resolvedConn()

	res, err := env.server.dispatchToolCall(ctx, conn, "list_sandfs", nil)
	if err != nil {
		t.Fatalf("list_sandfs: %v", err)
	}
	var got struct {
		SandfsList []map[string]interface{} `json:"sandfs_list"`
	}
	json.Unmarshal([]byte(res.Content[0].Text), &got)
	if len(got.SandfsList) != 0 {
		t.Errorf("expected empty list, got %d", len(got.SandfsList))
	}
}

// TestHandleListSandfs_StoreError verifies that a ListSandFSByAgent failure
// surfaces as an error (not a panic or empty success).
func TestHandleListSandfs_StoreError(t *testing.T) {
	env := newTestEnv(t)
	conn := env.resolvedConn()
	// Swap in a store whose ListSandFSByAgent always errors.
	env.server.identityStore = &erroringStore{Agent: conn.Agent}

	_, err := env.server.dispatchToolCall(context.Background(), conn, "list_sandfs", nil)
	if err == nil {
		t.Fatal("expected error from failing ListSandFSByAgent")
	}
	if !strings.Contains(err.Error(), "list failed") {
		t.Errorf("error should contain 'list failed', got: %v", err)
	}
}

// TestHandleExecute_NilAgentNoSandfsID verifies that when conn.Agent is nil and
// sandfs_id is omitted (e.g. dispatchToolCall called without prior resolveAgent),
// the handler returns "sandfs_id is required" rather than nil-dereferencing.
func TestHandleExecute_NilAgentNoSandfsID(t *testing.T) {
	env := newTestEnv(t)
	// Unresolved conn (Agent nil) - simulates a direct dispatch without resolve.
	conn := &mcpConnection{AgentKey: env.agentKey}

	_, err := env.server.dispatchToolCall(context.Background(), conn, "execute", map[string]interface{}{
		"code": "x", "language": "shell",
	})
	if err == nil {
		t.Fatal("expected error for nil agent + omitted sandfs_id")
	}
	if !strings.Contains(err.Error(), "sandfs_id is required") {
		t.Errorf("expected 'sandfs_id is required', got: %v", err)
	}
}

// TestHandleExecStatus_AuthError verifies that a bad sandfs_id (not owned by
// agent) surfaces as an error from ExecStatusDirect, not a success "expired".
func TestHandleExecStatus_AuthError(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	conn := env.resolvedConn()

	_, err := env.server.dispatchToolCall(ctx, conn, "exec_status", map[string]interface{}{
		"sandfs_id": "sf-nonexistent", "exec_id": "bg-1",
	})
	if err == nil {
		t.Fatal("expected error for nonexistent sandfs_id")
	}
}

// TestHandleListSandfs_StatusSurfacesToAgent pins the lifecycle-status parity
// with the HTTP discovery endpoint: a non-active sandfs carries "status" in
// the listing (the agent backs off and re-lists), an active one omits it.
func TestHandleListSandfs_StatusSurfacesToAgent(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	conn := env.resolvedConn()

	fetch := func() map[string]interface{} {
		res, err := env.server.dispatchToolCall(ctx, conn, "list_sandfs", nil)
		if err != nil {
			t.Fatalf("list_sandfs: %v", err)
		}
		var got struct {
			SandfsList []map[string]interface{} `json:"sandfs_list"`
		}
		if err := json.Unmarshal([]byte(res.Content[0].Text), &got); err != nil {
			t.Fatalf("invalid JSON: %v\nraw: %s", err, res.Content[0].Text)
		}
		if len(got.SandfsList) != 1 {
			t.Fatalf("expected 1 sandfs, got %d", len(got.SandfsList))
		}
		return got.SandfsList[0]
	}

	// Active (status ""): the key must be ABSENT (omitempty parity).
	if sf := fetch(); func() bool { _, ok := sf["status"]; return ok }() {
		t.Errorf("active sandfs must not carry a status field: %v", sf)
	}

	// Non-active (a swap in progress): the key must be present and readable.
	if err := env.store.SetSandfsStatus(env.sandfsID, "detaching"); err != nil {
		t.Fatalf("set status: %v", err)
	}
	sf := fetch()
	if sf["status"] != "detaching" {
		t.Errorf("status = %v, want 'detaching'", sf["status"])
	}
}

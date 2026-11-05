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

package pool_test

import (
	"context"
	"testing"

	"gateway/pool"
)

// Compile-time guard: StubSandlotClient implements SandlotClient.
var _ pool.SandlotClient = (*pool.StubSandlotClient)(nil)

// TestNewStubSandlotClient verifies the constructor returns a non-nil client.
func TestNewStubSandlotClient(t *testing.T) {
	c := pool.NewStubSandlotClient()
	if c == nil {
		t.Fatal("NewStubSandlotClient returned nil")
	}
}

// TestStubUnmountRootfs verifies the stub returns nil (success) for unmount.
func TestStubUnmountRootfs(t *testing.T) {
	c := pool.NewStubSandlotClient()
	if _, err := c.UnmountRootfs(context.Background(), "node-1", "sandfs-1", "/vol/s1", ""); err != nil {
		t.Errorf("UnmountRootfs: got %v, want nil", err)
	}
}

// TestStubMountRootfsAndExecuteSync verifies the sync-exec stub returns a
// result with the executed command echoed in stdout and status "done".
func TestStubMountRootfsAndExecuteSync(t *testing.T) {
	c := pool.NewStubSandlotClient()
	res, err := c.MountRootfsAndExecute(context.Background(), pool.ExecRequest{
		NodeAddr:   "node-1",
		SandfsID:   "sandfs-1",
		VolumePath: "/vol/s1",
		Command:    "echo hello",
	})
	if err != nil {
		t.Fatalf("MountRootfsAndExecute: %v", err)
	}
	if res.Status != "done" {
		t.Errorf("Status: got %q, want done", res.Status)
	}
	if res.ExitCode != 0 {
		t.Errorf("ExitCode: got %d, want 0", res.ExitCode)
	}
	if res.Stdout != "executed: echo hello" {
		t.Errorf("Stdout: got %q, want 'executed: echo hello'", res.Stdout)
	}
}

// TestStubMountRootfsAndExecuteBackground verifies the background stub returns
// an exec_id and status "running".
func TestStubMountRootfsAndExecuteBackground(t *testing.T) {
	c := pool.NewStubSandlotClient()
	res, err := c.MountRootfsAndExecute(context.Background(), pool.ExecRequest{
		NodeAddr:   "node-1",
		SandfsID:   "sandfs-1",
		VolumePath: "/vol/s1",
		Command:    "sleep 60",
		Background: true,
	})
	if err != nil {
		t.Fatalf("MountRootfsAndExecute bg: %v", err)
	}
	if res.Status != "running" {
		t.Errorf("Status: got %q, want running", res.Status)
	}
	if res.ExecID != "stub-bg-1" {
		t.Errorf("ExecID: got %q, want stub-bg-1", res.ExecID)
	}
}

// TestStubStatusExec verifies the stub returns status "done" with exit code 0.
func TestStubStatusExec(t *testing.T) {
	c := pool.NewStubSandlotClient()
	res, err := c.StatusExec(context.Background(), "node-1", "sandfs-1", "bg-1")
	if err != nil {
		t.Fatalf("StatusExec: %v", err)
	}
	if res.Status != "done" {
		t.Errorf("Status: got %q, want done", res.Status)
	}
	if res.ExitCode != 0 {
		t.Errorf("ExitCode: got %d, want 0", res.ExitCode)
	}
}

// TestStubKillExec verifies the stub returns nil for kill.
func TestStubKillExec(t *testing.T) {
	c := pool.NewStubSandlotClient()
	if err := c.KillExec(context.Background(), "node-1", "sandfs-1", "bg-1"); err != nil {
		t.Errorf("KillExec: got %v, want nil", err)
	}
}

// TestStubFileOp verifies the stub returns status 0 (success) for file ops.
func TestStubFileOp(t *testing.T) {
	c := pool.NewStubSandlotClient()
	res, err := c.FileOp(context.Background(), "node-1", pool.FileOpRequest{
		SandfsID: "sandfs-1",
		Action:   "write",
		Path:     "data.txt",
		Data:     []byte("hello"),
	})
	if err != nil {
		t.Fatalf("FileOp: %v", err)
	}
	if !res.Success {
		t.Errorf("Success: got false, want true")
	}
}

// TestStubCleanupOverlay verifies the stub returns nil for overlay cleanup.
func TestStubCleanupOverlay(t *testing.T) {
	c := pool.NewStubSandlotClient()
	if err := c.CleanupOverlay(context.Background(), "node-1", "/vol/s1"); err != nil {
		t.Errorf("CleanupOverlay: got %v, want nil", err)
	}
}

// TestExecRequestFields verifies the ExecRequest struct carries all fields
// that the StreamSandlotClient maps to the proto. This is a compile-time +
// value check that catches a field rename or removal.
func TestExecRequestFields(t *testing.T) {
	req := pool.ExecRequest{
		NodeAddr:        "node-1",
		SandfsID:        "sandfs-1",
		VolumePath:      "/vol/s1",
		Command:         "echo hi",
		Background:      true,
		TimeoutMs:       5000,
		LeaseDurationMs: 300000,
		InstallPackages: true,
		MinSpec:         "medium",
	}
	if req.NodeAddr != "node-1" || req.SandfsID != "sandfs-1" || req.VolumePath != "/vol/s1" {
		t.Error("basic fields not set correctly")
	}
	if req.Command != "echo hi" || !req.Background || req.TimeoutMs != 5000 {
		t.Error("exec fields not set correctly")
	}
	if req.LeaseDurationMs != 300000 || !req.InstallPackages || req.MinSpec != "medium" {
		t.Error("scheduling fields not set correctly")
	}
}

// TestFileOpRequestFields verifies the FileOpRequest struct carries all fields.
func TestFileOpRequestFields(t *testing.T) {
	req := pool.FileOpRequest{
		SandfsID:   "sandfs-1",
		Action:     "write",
		Path:       "data/out.txt",
		NewPath:    "data/renamed.txt",
		Offset:     1024,
		Length:     4096,
		Mode:       0644,
		Recursive:  true,
		Depth:      3,
		Data:       []byte("content"),
		VolumePath: "/vol/s1",
		MinSpec:    "large",
	}
	if req.SandfsID != "sandfs-1" || req.Action != "write" || req.Path != "data/out.txt" {
		t.Error("basic fields not set correctly")
	}
	if req.NewPath != "data/renamed.txt" || req.Offset != 1024 || req.Length != 4096 {
		t.Error("I/O fields not set correctly")
	}
	if req.Mode != 0644 || !req.Recursive || req.Depth != 3 {
		t.Error("mode/recursive/depth not set correctly")
	}
	if string(req.Data) != "content" || req.VolumePath != "/vol/s1" || req.MinSpec != "large" {
		t.Error("data/volume/spec not set correctly")
	}
}

// TestExecResultFields verifies the ExecResult struct carries all response
// fields that the StreamSandlotClient maps from CommandResponse.
func TestExecResultFields(t *testing.T) {
	res := pool.ExecResult{
		Stdout:            "output",
		Stderr:            "errors",
		ExitCode:          42,
		ExecID:            "bg-1",
		Status:            "done",
		ExecDurationNs:    1000,
		SandlotDurationNs: 2000,
	}
	if res.Stdout != "output" || res.Stderr != "errors" || res.ExitCode != 42 {
		t.Error("output fields not set correctly")
	}
	if res.ExecID != "bg-1" || res.Status != "done" {
		t.Error("exec fields not set correctly")
	}
	if res.ExecDurationNs != 1000 || res.SandlotDurationNs != 2000 {
		t.Error("timing fields not set correctly")
	}
}

// TestFileOpResultFields verifies the FileOpResult struct.
func TestFileOpResultFields(t *testing.T) {
	res := pool.FileOpResult{
		Data:    []byte("file data"),
		Success: true,
	}
	if string(res.Data) != "file data" {
		t.Error("Data not set correctly")
	}
	if !res.Success {
		t.Error("Success not set correctly")
	}
}

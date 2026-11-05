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
// Internal test (package pool, not pool_test) to exercise the unexported
// actionName and truncateStr helpers directly.

package pool

import (
	"strings"
	"testing"

	pb "common/proto/stream"
)

// TestActionName covers all six command types with populated inner messages.
// The label format is a human-readable summary used in log lines; tests assert
// the exact format so a silent change to the logging contract is caught.
func TestActionName(t *testing.T) {
	cases := []struct {
		name string
		cmd  *pb.VMCommand
		want string
	}{
		{
			name: "unmount_rootfs",
			cmd: &pb.VMCommand{Action: &pb.VMCommand_UnmountRootfs{
				UnmountRootfs: &pb.UnmountRootfs{SandfsId: "s1", VolumePath: "/v/s1"},
			}},
			want: "UnmountRootfs(sandfs=s1, vol=/v/s1)",
		},
		{
			name: "mount_and_exec sync",
			cmd: &pb.VMCommand{Action: &pb.VMCommand_MountRootfsAndExecute{
				MountRootfsAndExecute: &pb.MountRootfsAndExecute{
					SandfsId: "s2", VolumePath: "/v/s2", Command: "echo hi", TimeoutMs: 5000,
				},
			}},
			want: `MountRootfsAndExecute(sandfs=s2, vol=/v/s2, cmd="echo hi", timeout=5000ms)`,
		},
		{
			name: "mount_and_exec bg",
			cmd: &pb.VMCommand{Action: &pb.VMCommand_MountRootfsAndExecute{
				MountRootfsAndExecute: &pb.MountRootfsAndExecute{
					SandfsId: "s3", VolumePath: "/v/s3", Command: "sleep 60", Background: true, TimeoutMs: 0,
				},
			}},
			want: `MountRootfsAndExecute(sandfs=s3, vol=/v/s3, cmd="sleep 60", timeout=0ms, bg=true)`,
		},
		{
			name: "mount_and_exec long command truncated",
			cmd: &pb.VMCommand{Action: &pb.VMCommand_MountRootfsAndExecute{
				MountRootfsAndExecute: &pb.MountRootfsAndExecute{
					SandfsId: "s4", VolumePath: "/v/s4",
					// > 80 chars so truncateStr (limit 80) appends "...".
					Command:   strings.Repeat("x", 100),
					TimeoutMs: 1000,
				},
			}},
			want: `MountRootfsAndExecute(sandfs=s4, vol=/v/s4, cmd="` + strings.Repeat("x", 80) + `...", timeout=1000ms)`,
		},
		{
			name: "status_exec",
			cmd: &pb.VMCommand{Action: &pb.VMCommand_StatusExec{
				StatusExec: &pb.StatusExec{SandfsId: "s5", ExecId: "bg-1"},
			}},
			want: "StatusExec(sandfs=s5, exec=bg-1)",
		},
		{
			name: "kill_exec",
			cmd: &pb.VMCommand{Action: &pb.VMCommand_KillExec{
				KillExec: &pb.KillExec{SandfsId: "s6", ExecId: "bg-2"},
			}},
			want: "KillExec(sandfs=s6, exec=bg-2)",
		},
		{
			name: "file_op",
			cmd: &pb.VMCommand{Action: &pb.VMCommand_FileOp{
				FileOp: &pb.FileOp{SandfsId: "s7", Action: "read", Path: "data.txt"},
			}},
			want: "FileOp(sandfs=s7, action=read, path=data.txt)",
		},
		{
			name: "cleanup_overlay",
			cmd: &pb.VMCommand{Action: &pb.VMCommand_CleanupOverlay{
				CleanupOverlay: &pb.CleanupOverlay{VolumePath: "/v/s8"},
			}},
			want: "CleanupOverlay(vol=/v/s8)",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := actionName(c.cmd); got != c.want {
				t.Errorf("actionName() = %q, want %q", got, c.want)
			}
		})
	}
}

// TestActionNameNilInner verifies the fallback labels when the oneof payload is
// present but the inner message pointer is nil. The code guards each case with
// a nil check and falls back to the bare action name.
func TestActionNameNilInner(t *testing.T) {
	cases := []struct {
		name string
		cmd  *pb.VMCommand
		want string
	}{
		{"nil unmount", &pb.VMCommand{Action: &pb.VMCommand_UnmountRootfs{}}, "UnmountRootfs"},
		{"nil mount", &pb.VMCommand{Action: &pb.VMCommand_MountRootfsAndExecute{}}, "MountRootfsAndExecute"},
		{"nil status", &pb.VMCommand{Action: &pb.VMCommand_StatusExec{}}, "StatusExec"},
		{"nil kill", &pb.VMCommand{Action: &pb.VMCommand_KillExec{}}, "KillExec"},
		{"nil fileop", &pb.VMCommand{Action: &pb.VMCommand_FileOp{}}, "FileOp"},
		{"nil cleanup", &pb.VMCommand{Action: &pb.VMCommand_CleanupOverlay{}}, "CleanupOverlay"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := actionName(c.cmd); got != c.want {
				t.Errorf("actionName() = %q, want %q", got, c.want)
			}
		})
	}
}

// TestActionNameUnknown verifies an unpopulated action (nil Action oneof)
// yields "Unknown".
func TestActionNameUnknown(t *testing.T) {
	cmd := &pb.VMCommand{CommandId: "x"} // no Action set
	if got := actionName(cmd); got != "Unknown" {
		t.Errorf("actionName() = %q, want Unknown", got)
	}
}

// TestTruncateStr covers the boundary cases: empty, short, exact, truncation
// with ellipsis, and maxLen=0.
func TestTruncateStr(t *testing.T) {
	cases := []struct {
		name   string
		s      string
		maxLen int
		want   string
	}{
		{"empty", "", 10, ""},
		{"short", "hi", 10, "hi"},
		{"exact", "exactly10", 10, "exactly10"}, // len==maxLen, no truncation
		{"truncate", "this is a very long string", 10, "this is a ..."},
		{"maxLen 0", "abc", 0, "..."},
		{"single char over", "abcdef", 5, "abcde..."},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := truncateStr(c.s, c.maxLen); got != c.want {
				t.Errorf("truncateStr(%q, %d) = %q, want %q", c.s, c.maxLen, got, c.want)
			}
		})
	}
}

// TestActionKindDropsTenantContent pins the descriptor used on the
// UN-GATED error-path log lines must not embed the tenant command excerpt, the
// volume path, or the file path — actionName embeds all three and stays on
// debug-gated lines only.
func TestActionKindDropsTenantContent(t *testing.T) {
	const secret = `curl -H "Authorization: Bearer sk-LIVE-SECRET"`
	cmds := []*pb.VMCommand{
		{Action: &pb.VMCommand_MountRootfsAndExecute{MountRootfsAndExecute: &pb.MountRootfsAndExecute{
			SandfsId: "s1", VolumePath: "/vol/tenant-a", Command: secret, TimeoutMs: 1000}}},
		{Action: &pb.VMCommand_FileOp{FileOp: &pb.FileOp{
			SandfsId: "s1", Action: "read", Path: "/home/agent/.ssh/id_rsa"}}},
		{Action: &pb.VMCommand_UnmountRootfs{UnmountRootfs: &pb.UnmountRootfs{
			SandfsId: "s1", VolumePath: "/vol/tenant-a"}}},
		{Action: &pb.VMCommand_CleanupOverlay{CleanupOverlay: &pb.CleanupOverlay{
			VolumePath: "/vol/tenant-a"}}},
	}
	for _, cmd := range cmds {
		got := actionKind(cmd)
		for _, banned := range []string{secret, "Authorization", "sk-LIVE-SECRET", "id_rsa", "/vol/tenant-a"} {
			if strings.Contains(got, banned) {
				t.Errorf("actionKind() = %q leaks tenant content %q", got, banned)
			}
		}
	}
	if got := actionKind(cmds[0]); !strings.Contains(got, "sandfs=s1") {
		t.Errorf("actionKind() = %q, want the sandfs id kept for correlation", got)
	}
	if got := actionKind(&pb.VMCommand{}); got != "Unknown" {
		t.Errorf("actionKind(empty) = %q, want Unknown", got)
	}
}

// TestFileOpFailureMessageMapsNamedCodes pins a NAMED node error code
// maps to a gateway-owned body and the raw node text is dropped; the empty
// code is the warden's app error (the agent's own ENOENT class) and passes
// through.
func TestFileOpFailureMessageMapsNamedCodes(t *testing.T) {
	const rawNodeText = "panic: /host/internal/path inode 42 fd 7"
	if got := fileOpFailureMessage(&pb.CommandResponse{ErrorCode: "FILE_TOO_LARGE", Error: rawNodeText}); strings.Contains(got, rawNodeText) || !strings.Contains(got, "cap") {
		t.Errorf("FILE_TOO_LARGE mapped to %q, want gateway-owned cap text without the raw node text", got)
	}
	if got := fileOpFailureMessage(&pb.CommandResponse{ErrorCode: "WEIRD code!", Error: rawNodeText}); strings.Contains(got, rawNodeText) || strings.Contains(got, "WEIRD") {
		t.Errorf("unknown malformed code mapped to %q, want a generic message without node text", got)
	}
	if got := fileOpFailureMessage(&pb.CommandResponse{ErrorCode: "SOME_NEW_CODE", Error: rawNodeText}); strings.Contains(got, rawNodeText) || !strings.Contains(got, "SOME_NEW_CODE") {
		t.Errorf("unknown well-formed code mapped to %q, want the code echoed (identifier shape) without node text", got)
	}
	if got := fileOpFailureMessage(&pb.CommandResponse{Error: "no such file or directory"}); got != "no such file or directory" {
		t.Errorf("app error (no code) = %q, want passthrough", got)
	}
}

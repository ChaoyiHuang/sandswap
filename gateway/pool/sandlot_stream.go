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

package pool

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	pb "common/proto/stream"
	"gateway/stream"
)

// hotPathDebug gates every per-op success-path log line on the command
// dispatch path (mount/exec/unmount/file/cleanup pre-send + response). A
// gateway serving tens of thousands of sandfs runs these ops thousands of
// times per second: each info record costs a JSON marshal + stderr write AND
// the actionName/truncateStr formatting sits directly on the measured path —
// and at that rate it floods the log. Normal completions therefore print
// nothing by default; the gate is checked BEFORE any formatting so a disabled
// gate costs a single atomic load. Enabled by `gateway -log-level debug`.
// Failure-path records (command failed / transport error) stay unconditional:
// that is the abnormal signal operators need.
var hotPathDebug atomic.Bool

// SetHotPathDebug flips the per-op success-log gate. Called once at startup
// from cmd/main.go (log-level debug enables it).
func SetHotPathDebug(on bool) { hotPathDebug.Store(on) }

// StreamSandlotClient implements SandlotClient using the bidirectional gRPC stream.
// Sandlot nodes initiate outbound connections to the gateway (no ports exposed).
type StreamSandlotClient struct {
	streamServer *stream.Server
}

// NewStreamSandlotClient creates a client backed by the stream server.
func NewStreamSandlotClient(s *stream.Server) *StreamSandlotClient {
	return &StreamSandlotClient{
		streamServer: s,
	}
}

// actionName extracts a human-readable action name from a VMCommand.
func actionName(cmd *pb.VMCommand) string {
	switch cmd.Action.(type) {
	case *pb.VMCommand_UnmountRootfs:
		if u := cmd.GetUnmountRootfs(); u != nil {
			return fmt.Sprintf("UnmountRootfs(sandfs=%s, vol=%s)", u.SandfsId, u.VolumePath)
		}
		return "UnmountRootfs"
	case *pb.VMCommand_MountRootfsAndExecute:
		if m := cmd.GetMountRootfsAndExecute(); m != nil {
			bg := ""
			if m.Background {
				bg = ", bg=true"
			}
			return fmt.Sprintf("MountRootfsAndExecute(sandfs=%s, vol=%s, cmd=%q, timeout=%dms%s)", m.SandfsId, m.VolumePath, truncateStr(m.Command, 80), m.TimeoutMs, bg)
		}
		return "MountRootfsAndExecute"
	case *pb.VMCommand_StatusExec:
		if s := cmd.GetStatusExec(); s != nil {
			return fmt.Sprintf("StatusExec(sandfs=%s, exec=%s)", s.SandfsId, s.ExecId)
		}
		return "StatusExec"
	case *pb.VMCommand_KillExec:
		if k := cmd.GetKillExec(); k != nil {
			return fmt.Sprintf("KillExec(sandfs=%s, exec=%s)", k.SandfsId, k.ExecId)
		}
		return "KillExec"
	case *pb.VMCommand_FileOp:
		if f := cmd.GetFileOp(); f != nil {
			return fmt.Sprintf("FileOp(sandfs=%s, action=%s, path=%s)", f.SandfsId, f.Action, f.Path)
		}
		return "FileOp"
	case *pb.VMCommand_CleanupOverlay:
		if c := cmd.GetCleanupOverlay(); c != nil {
			return fmt.Sprintf("CleanupOverlay(vol=%s)", c.VolumePath)
		}
		return "CleanupOverlay"
	default:
		return "Unknown"
	}
}

// actionKind names a command for UN-GATED lines — the error-path logs. It
// carries the op, the sandfs id and at most non-content identifiers (action
// name, exec id): never the tenant command excerpt, the volume path or the
// file path that actionName embeds. Those are secret-bearing tenant content
// ('s class: a command excerpt in an operator log is a leaked secret),
// and actionName's formatting sits directly on the measured path — so the
// full descriptor stays on the debug-gated success lines only.
func actionKind(cmd *pb.VMCommand) string {
	switch cmd.Action.(type) {
	case *pb.VMCommand_UnmountRootfs:
		if u := cmd.GetUnmountRootfs(); u != nil {
			return fmt.Sprintf("UnmountRootfs(sandfs=%s)", u.SandfsId)
		}
		return "UnmountRootfs"
	case *pb.VMCommand_MountRootfsAndExecute:
		if m := cmd.GetMountRootfsAndExecute(); m != nil {
			bg := ""
			if m.Background {
				bg = ", bg=true"
			}
			return fmt.Sprintf("MountRootfsAndExecute(sandfs=%s, timeout=%dms%s)", m.SandfsId, m.TimeoutMs, bg)
		}
		return "MountRootfsAndExecute"
	case *pb.VMCommand_StatusExec:
		if s := cmd.GetStatusExec(); s != nil {
			return fmt.Sprintf("StatusExec(sandfs=%s, exec=%s)", s.SandfsId, s.ExecId)
		}
		return "StatusExec"
	case *pb.VMCommand_KillExec:
		if k := cmd.GetKillExec(); k != nil {
			return fmt.Sprintf("KillExec(sandfs=%s, exec=%s)", k.SandfsId, k.ExecId)
		}
		return "KillExec"
	case *pb.VMCommand_FileOp:
		if f := cmd.GetFileOp(); f != nil {
			return fmt.Sprintf("FileOp(sandfs=%s, action=%s)", f.SandfsId, f.Action)
		}
		return "FileOp"
	case *pb.VMCommand_CleanupOverlay:
		return "CleanupOverlay"
	default:
		return "Unknown"
	}
}

// fileOpFailureMessage maps a node-reported file-op failure to the text a
// caller may see. A response with NO error code is the warden's app-level
// failure (the agent's own ENOENT/EACCES class) and passes through — the agent
// needs it to fix its call. A NAMED code is node-asserted metadata: it maps to
// a gateway-owned message and the raw node text is DROPPED, so a node-chosen
// string never becomes the caller-visible body of a named failure. An unknown
// code is echoed only when it has the shape of a code (bounded identifier),
// never as free text.
func fileOpFailureMessage(resp *pb.CommandResponse) string {
	switch code := resp.GetErrorCode(); code {
	case "":
		return resp.GetError()
	case "FILE_TOO_LARGE":
		return "file payload exceeds the single-op size cap (split the write or page the read with offset/length)"
	case "INVALID_ARGUMENT":
		return "file operation rejected: invalid argument"
	default:
		if sane := sanitizeErrorCode(code); sane != "" {
			return fmt.Sprintf("file operation failed (%s)", sane)
		}
		return "file operation failed"
	}
}

// sanitizeErrorCode bounds a node-asserted error code to an identifier shape
// ([A-Z0-9_], at most 64 chars, "" when it does not qualify) so the mapping
// above can echo it for diagnosis without ever forwarding arbitrary text.
func sanitizeErrorCode(code string) string {
	if len(code) == 0 || len(code) > 64 {
		return ""
	}
	for i := 0; i < len(code); i++ {
		c := code[i]
		if (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '_' {
			return ""
		}
	}
	return code
}

func truncateStr(s string, maxLen int) string {
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}

// TODO(batch-unmount): every unmount today is one VMCommand per sandfs. If
// large-batch concurrent unmounts ever become a real load (mass fence release,
// mass lease expiry, bulk SandFS deletion), consider a gateway→sandlot batch
// unmount command: one stream round trip per node carrying N sandfs IDs (new
// proto action + sandlot command handler; sandlot still fans out to per-VM
// warden unmounts locally, and per-sandfs stats/teardown stay per-entry).
// Deliberately not built for now — current unmount volumes fit comfortably in
// the stream's per-node command concurrency (sendCh 2000). Fan-out sites that
// would call it: fenceReleaseAllMounts, the lease-expiry workers,
// UnmountSandfsFromAll, and the two L2 cleanupAfterFailure paths.
//
// UnmountRootfs sends the unmount command (bind umount of /mnt/rootfs +
// virtio-fs allowed_dirs clear) over the persistent stream. Called on the async
// release path. Pairs with MountRootfsAndExecute. Sandlot resolves sandfs_id -> VM.
func (c *StreamSandlotClient) UnmountRootfs(ctx context.Context, nodeID, sandfsID, volumePath, volumeEpoch string) (UnmountResult, error) {
	nc, err := c.streamServer.GetNode(nodeID)
	if err != nil {
		return UnmountResult{}, fmt.Errorf("node %s not connected: %w", nodeID, err)
	}

	cmd := &pb.VMCommand{
		CommandId: uuid.New().String(),
		Action: &pb.VMCommand_UnmountRootfs{
			UnmountRootfs: &pb.UnmountRootfs{
				SandfsId:    sandfsID,
				VolumePath:  volumePath,
				VolumeEpoch: volumeEpoch,
			},
		},
	}

	if hotPathDebug.Load() {
		slog.Debug("[stream→sandlot] sending command", "node", nodeID, "cmd", actionName(cmd))
	}
	start := time.Now()

	respCh, err := nc.SendCommand(cmd)
	if err != nil {
		return UnmountResult{}, fmt.Errorf("send unmount-rootfs command: %w", err)
	}

	select {
	case resp := <-respCh:
		elapsed := time.Since(start)
		// Three-layer unmount latency for gateway stats (mirrors mount path).
		// warden = exec_duration_ns, sandlot = sandlot_duration_ns, gateway = E2E.
		res := UnmountResult{
			WardenDurationNs:  resp.ExecDurationNs,
			SandlotDurationNs: resp.SandlotDurationNs,
			GatewayDurationNs: uint64(elapsed.Nanoseconds()),
		}
		if !resp.Success {
			NoteSecurityEvent(resp.Error)
			slog.Error("[stream←sandlot] command failed", "node", nodeID, "cmd", actionKind(cmd), "elapsed", elapsed.String(), "error", resp.Error)
			return res, fmt.Errorf("unmount-rootfs failed: %s", resp.Error)
		}
		if hotPathDebug.Load() {
			slog.Debug("[stream←sandlot] command response", "node", nodeID, "cmd", actionName(cmd), "elapsed", elapsed.String())
		}
		return res, nil
	case <-ctx.Done():
		return UnmountResult{}, ctx.Err()
	}
}

// MountRootfsAndExecute sends the combined attach+execute command over the
// persistent stream and waits for the single response. Sandlot resolves
// sandfs_id to a VM (reuse if warm, else pick a CLEAN spec-satisfying VM).
func (c *StreamSandlotClient) MountRootfsAndExecute(ctx context.Context, req ExecRequest) (ExecResult, error) {
	nc, err := c.streamServer.GetNode(req.NodeAddr)
	if err != nil {
		return ExecResult{}, fmt.Errorf("node %s not connected: %w", req.NodeAddr, err)
	}

	msg := &pb.VMCommand{
		CommandId: uuid.New().String(),
		AgentId:   req.AgentID,
		Action: &pb.VMCommand_MountRootfsAndExecute{
			MountRootfsAndExecute: &pb.MountRootfsAndExecute{
				SandfsId:        req.SandfsID,
				VolumePath:      req.VolumePath,
				Command:         req.Command,
				Background:      req.Background,
				TimeoutMs:       req.TimeoutMs,
				LeaseDurationMs: req.LeaseDurationMs,
				InstallPackages: req.InstallPackages,
				MinSpec:         req.MinSpec,
				TemplateRef:     req.TemplateRef,
				VolumeMode:      req.VolumeMode,
				VolumeEpoch:     req.VolumeEpoch,
			},
		},
	}

	if hotPathDebug.Load() {
		slog.Debug("[stream→sandlot] sending command", "node", req.NodeAddr, "cmd", actionName(msg))
	}
	start := time.Now()

	respCh, err := nc.SendCommand(msg)
	if err != nil {
		return ExecResult{}, fmt.Errorf("send mount-rootfs-and-execute command: %w", err)
	}

	select {
	case resp := <-respCh:
		elapsed := time.Since(start)
		if !resp.Success {
			NoteSecurityEvent(resp.Error)
			slog.Error("[stream←sandlot] command failed", "node", req.NodeAddr, "cmd", actionKind(msg), "elapsed", elapsed.String(), "error", resp.Error)
			if isNoAvailableVM(resp) {
				return ExecResult{}, ErrNoAvailableSandbox
			}
			if resp.Error == stream.ErrConnectionClosed.Error() {
				// Preserve the transport sentinel: the mount may have landed
				// before the stream closed, so the caller must treat the
				// outcome as uncertain (L1 retry / suspect), not as a clean
				// application failure.
				return ExecResult{}, fmt.Errorf("mount-rootfs-and-execute failed: %w", stream.ErrConnectionClosed)
			}
			return ExecResult{}, fmt.Errorf("mount-rootfs-and-execute failed: %s", resp.Error)
		}
		if hotPathDebug.Load() {
			slog.Debug("[stream←sandlot] command response", "node", req.NodeAddr, "cmd", actionName(msg), "elapsed", elapsed.String(),
				"exitCode", resp.ExitCode, "execID", resp.ExecId, "status", resp.Status,
				"stdout", truncateStr(resp.Stdout, 200), "stderr", truncateStr(resp.Stderr, 100))
		}
		return ExecResult{
			Stdout:            resp.Stdout,
			Stderr:            resp.Stderr,
			ExitCode:          int(resp.ExitCode),
			ExecID:            resp.ExecId,
			Status:            resp.Status,
			ExecDurationNs:    resp.ExecDurationNs,
			SandlotDurationNs: resp.SandlotDurationNs,
			Spec:              resp.GetSpec(), // actual VM spec (bound correction)
		}, nil
	case <-ctx.Done():
		return ExecResult{}, ctx.Err()
	}
}

// StatusExec polls a background exec's liveness + captured log tail.
func (c *StreamSandlotClient) StatusExec(ctx context.Context, nodeID, sandfsID, execID string) (ExecResult, error) {
	nc, err := c.streamServer.GetNode(nodeID)
	if err != nil {
		return ExecResult{}, fmt.Errorf("node %s not connected: %w", nodeID, err)
	}
	msg := &pb.VMCommand{
		CommandId: uuid.New().String(),
		Action: &pb.VMCommand_StatusExec{
			StatusExec: &pb.StatusExec{SandfsId: sandfsID, ExecId: execID},
		},
	}
	respCh, err := nc.SendCommand(msg)
	if err != nil {
		return ExecResult{}, fmt.Errorf("send status_exec command: %w", err)
	}
	select {
	case resp := <-respCh:
		if !resp.Success {
			return ExecResult{}, fmt.Errorf("status_exec failed: %s", resp.Error)
		}
		return ExecResult{
			Stdout:            resp.Stdout,
			Stderr:            resp.Stderr,
			ExitCode:          int(resp.ExitCode),
			ExecID:            execID,
			Status:            resp.Status,
			ExecDurationNs:    resp.ExecDurationNs,
			SandlotDurationNs: resp.SandlotDurationNs,
		}, nil
	case <-ctx.Done():
		return ExecResult{}, ctx.Err()
	}
}

// KillExec SIGKILLs a background exec's process group by exec_id.
func (c *StreamSandlotClient) KillExec(ctx context.Context, nodeID, sandfsID, execID string) error {
	nc, err := c.streamServer.GetNode(nodeID)
	if err != nil {
		return fmt.Errorf("node %s not connected: %w", nodeID, err)
	}
	msg := &pb.VMCommand{
		CommandId: uuid.New().String(),
		Action: &pb.VMCommand_KillExec{
			KillExec: &pb.KillExec{SandfsId: sandfsID, ExecId: execID},
		},
	}
	respCh, err := nc.SendCommand(msg)
	if err != nil {
		return fmt.Errorf("send kill_exec command: %w", err)
	}
	select {
	case resp := <-respCh:
		if !resp.Success {
			return fmt.Errorf("kill_exec failed: %s", resp.Error)
		}
		// truthfully distinct — the exec_id was not in the warden's
		// registry; do NOT report the blanket "killed".
		if resp.Status == "not_found" {
			return ErrBgExecNotFound
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// FileOp sends a file I/O command to sandlot over the persistent stream.
// A single RPC covers all 7 sub-operations — the action field selects which.
func (c *StreamSandlotClient) FileOp(ctx context.Context, nodeID string, req FileOpRequest) (FileOpResult, error) {
	nc, err := c.streamServer.GetNode(nodeID)
	if err != nil {
		return FileOpResult{}, fmt.Errorf("node %s not connected: %w", nodeID, err)
	}

	cmd := &pb.VMCommand{
		CommandId: uuid.New().String(),
		AgentId:   req.AgentID,
		Action: &pb.VMCommand_FileOp{
			FileOp: &pb.FileOp{
				SandfsId:    req.SandfsID,
				Action:      req.Action,
				Path:        req.Path,
				NewPath:     req.NewPath,
				Offset:      req.Offset,
				Length:      req.Length,
				Mode:        req.Mode,
				Recursive:   req.Recursive,
				Depth:       req.Depth,
				Data:        req.Data,
				VolumePath:  req.VolumePath,
				MinSpec:     req.MinSpec,
				TemplateRef: req.TemplateRef,
				VolumeMode:  req.VolumeMode,
				VolumeEpoch: req.VolumeEpoch,
			},
		},
	}

	if hotPathDebug.Load() {
		slog.Debug("[stream→sandlot] sending command", "node", nodeID, "cmd", actionName(cmd))
	}
	start := time.Now()

	respCh, err := nc.SendCommand(cmd)
	if err != nil {
		return FileOpResult{}, fmt.Errorf("send file_op command: %w", err)
	}

	select {
	case resp := <-respCh:
		elapsed := time.Since(start)
		if !resp.Success {
			NoteSecurityEvent(resp.Error)
			slog.Error("[stream←sandlot] command failed", "node", nodeID, "cmd", actionKind(cmd), "elapsed", elapsed.String(), "error", resp.Error)
			if isNoAvailableVM(resp) {
				return FileOpResult{}, ErrNoAvailableSandbox
			}
			return FileOpResult{}, fmt.Errorf("file_op failed: %s", fileOpFailureMessage(resp))
		}
		// File ops return binary data via StdoutRaw (bytes) to avoid
		// protobuf string UTF-8 marshal errors. Fall back to Stdout
		// for backward compatibility with older sandlots.
		data := resp.StdoutRaw
		if len(data) == 0 && resp.Stdout != "" {
			data = []byte(resp.Stdout)
		}
		// Success=true means the RPC reached the warden and got a reply. An
		// app-level failure (ENOENT, EACCES) is carried in Error with empty
		// Data — returned as a result (Success=true, Error!="") so the caller
		// returns a 400 without invalidating the VM. Only resp.Success=false
		// (sandlot-side mount/transport failure) is a real error (handled above).
		if hotPathDebug.Load() {
			slog.Debug("[stream←sandlot] command response", "node", nodeID, "cmd", actionName(cmd), "elapsed", elapsed.String(),
				"dataLen", len(data), "appError", resp.Error != "")
		}
		return FileOpResult{
			Data:    data,
			Success: resp.Error == "", // app error (Error!="") → Success=false for the file-op semantics
			Error:   fileOpFailureMessage(resp),
			Spec:    resp.GetSpec(), // actual VM spec (file-op cold-mount path)
		}, nil
	case <-ctx.Done():
		return FileOpResult{}, ctx.Err()
	}
}

// CleanupOverlay asks sandlot to unmount a host-side read-only overlay mount.
// Best-effort: errors are logged but not propagated to the caller.
func (c *StreamSandlotClient) CleanupOverlay(ctx context.Context, nodeAddr, volumePath string) error {
	nc, err := c.streamServer.GetNode(nodeAddr)
	if err != nil {
		return fmt.Errorf("node %s not connected: %w", nodeAddr, err)
	}

	cmd := &pb.VMCommand{
		CommandId: uuid.New().String(),
		Action: &pb.VMCommand_CleanupOverlay{
			CleanupOverlay: &pb.CleanupOverlay{
				VolumePath: volumePath,
			},
		},
	}

	if hotPathDebug.Load() {
		slog.Debug("[stream→sandlot] sending command", "node", nodeAddr, "cmd", "CleanupOverlay", "volumePath", volumePath)
	}

	respCh, err := nc.SendCommand(cmd)
	if err != nil {
		return fmt.Errorf("send cleanup_overlay command: %w", err)
	}

	select {
	case resp := <-respCh:
		if !resp.Success {
			slog.Error("[stream←sandlot] cleanup_overlay failed", "node", nodeAddr, "volumePath", volumePath, "error", resp.Error)
			return fmt.Errorf("cleanup_overlay failed: %s", resp.Error)
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// isNoAvailableVM reports whether a sandlot response means "no CLEAN VM
// available on this node" (resolveVMForMount returned nil). This is an
// over-subscription / empty-pool condition, NOT a mount failure — the gateway
// retries on another node rather than EnterCleaning.
//
// It prefers the structured error_code field ("NO_AVAILABLE_VM") set by the
// sandlot, and falls back to substring matching on the human-readable error
// string for sandlots that predate the error_code field.
func isNoAvailableVM(resp *pb.CommandResponse) bool {
	if resp.GetErrorCode() == "NO_AVAILABLE_VM" {
		return true
	}
	return strings.Contains(resp.GetError(), "no available VM on node")
}

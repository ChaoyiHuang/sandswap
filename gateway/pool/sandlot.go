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
	"errors"
	"fmt"
	"time"
)

// ErrNoAvailableSandbox is returned when a sandlot node has no CLEAN VM
// available to serve a mount (resolveVMForMount returned nil: over-subscription
// or an empty pool). This is NOT a mount failure - the sandfs isn't dirty, the
// node just has no spare VM right now. The gateway retries on another node
// (NO_AVAILABLE_SANDBOX 503+retry) instead of EnterCleaning. With
// the gateway-authoritative clean count, the retry routes correctly:
// the over-subscribed node's derived clean is 0, so pool.Acquire picks another.
var ErrNoAvailableSandbox = errors.New("no available sandbox on node")

// ExecRequest carries the parameters for a MountRootfsAndExecute RPC.
// Under delegation the gateway addresses the workload by sandfs_id and selects a
// NODE; sandlot resolves the sandfs to a VM locally.
type ExecRequest struct {
	NodeAddr        string
	SandfsID        string
	AgentID         string // authenticated agent identity; forwarded to sandlot for the egress identity binding
	VolumePath      string
	Command         string
	Background      bool   // true = start_exec, return immediately with ExecID
	TimeoutMs       uint32 // 0 = warden default (sync only)
	LeaseDurationMs uint32 // 0 = default sticky lease (background only)
	InstallPackages bool   // true = retain the 10-cap install profile for package installation
	MinSpec         string // minimum VM spec the sandfs requires ("" = any)
	// TemplateRef is the overlay template the identity record expects this
	// volume to serve. Sandlot compares it with the ref its host-side overlay
	// was mounted from: a mismatch (template swapped while this node held the
	// old overlay) remounts from the volume's .template marker before the
	// guest mounts. Zero hot-path cost — a payload string + in-memory compare.
	TemplateRef string
	// VolumeMode is the identity record's mode ("flat"/"overlay"). The warden
	// mounts according to this value, never by probing the agent-writable
	// volume layout.
	VolumeMode string
	// VolumeEpoch is the per-create volume identity from the record; the node
	// compares it with the signed stamp before mounting.
	VolumeEpoch string
}

// ExecResult carries the reply. For sync exec: Stdout + Stderr + ExitCode + Status
// ("done"|"timed_out'). For background exec: ExecID + Status="running".
type ExecResult struct {
	Stdout         string
	Stderr         string // command stderr (sync exec only)
	ExitCode       int
	ExecID         string
	Status         string // "done" | "running" | "timed_out" | "killed" | "not_found" | "expired"
	ExecDurationNs uint64 // warden monotonic: full exec() call (warm sync); warden-side
	//                  total mount+exec (cold MountRootfsAndExecute); unmount wall time
	SandlotDurationNs uint64 // sandlot monotonic: dispatch-to-response (ns)
	// Spec is the actual VM spec that served the mount: the gateway
	// corrects its provisional bound reservation (under min_spec) to this spec.
	Spec string
}

// FileOpRequest carries the parameters for a FileOp RPC.
type FileOpRequest struct {
	SandfsID   string
	AgentID    string // authenticated agent identity; forwarded to sandlot for the egress identity binding
	Action     string // "read"|"write"|"stat"|"list_dir"|"mkdir"|"remove"|"rename"
	Path       string
	NewPath    string // rename only
	Offset     int64  // read/write
	Length     int64  // read
	Mode       uint32 // write/mkdir
	Recursive  bool   // remove
	Depth      uint32 // list_dir
	Data       []byte // write
	VolumePath string // host-side agent directory; sandlot mounts if not already mounted
	MinSpec    string // minimum VM spec for the cold-mount case ("" = any)
	// TemplateRef: same swap-staleness semantics as ExecRequest.TemplateRef.
	TemplateRef string
	// VolumeMode: same semantics as ExecRequest.VolumeMode (required on the
	// cold path; ignored when the volume is already mounted).
	VolumeMode string
	// VolumeEpoch: same semantics as ExecRequest.VolumeEpoch.
	VolumeEpoch string
}

// FileOpResult carries the reply. Data holds file bytes (read) or JSON (stat/list_dir).
// On an application-level failure (ENOENT, EACCES, ...) Success is false and
// Error holds the message; the VM is still healthy so the caller does NOT
// invalidate the connection.
type FileOpResult struct {
	Data    []byte
	Success bool
	Error   string
	// Spec is the actual VM spec that served the op (set when the op triggered a
	// cold mount). Used to correct a spec-bound mismatch on the file-op cold-mount path.
	Spec string
}

// UnmountResult carries the three-layer unmount latency from an UnmountRootfs
// RPC, mirroring the mount path's ExecResult duration fields. The gateway's
// unmount stats recorder consumes these to track per-node unmount latency
// (warden = cgroup.kill+teardown+umount+drop_caches; sandlot = handler total;
// gateway = stream-client E2E). Zero on transport/protocol error.
type UnmountResult struct {
	WardenDurationNs  uint64 // warden-monotonic unmount wall time (exec_duration_ns)
	SandlotDurationNs uint64 // sandlot handler total (sandlot_duration_ns)
	GatewayDurationNs uint64 // stream-client E2E (time.Since(send))
}

// UnmountRecorder is the subset of the gateway unmount-stats recorder used by
// the pool manager and execute handler to record mount/unmount events. Defined
// here (in pool, a leaf package) so pool/handler can record without importing
// the concrete stats type (stats imports pool to implement this interface —
// one-directional, no cycle).
type UnmountRecorder interface {
	// RecordMount records a successful cold mount (per-node mount count++) and
	// stores the sandfs's last cold-mount command for later unmount context.
	RecordMount(nodeID, sandfsID, command string)
	// RecordUnmount records an unmount attempt: per-node unmount/success/fail
	// counts, <5ms/<10ms tallies, and (if slow enough) a top-N slow entry
	// carrying the three-layer latencies + the sandfs's last command + reason.
	RecordUnmount(nodeID, sandfsID, reason string, r UnmountResult, success bool)
	// ForgetNode drops a node's stats entry when the sandlot disconnects, so its
	// stale unmount data does not linger in /stats or the next persisted snapshot.
	ForgetNode(nodeID string)
}

// SandlotClient defines the interface for communicating with Sandlot.
// In production, this uses the gRPC bidirectional stream (StreamSandlotClient).
// All workload RPCs address the sandfs by sandfs_id; sandlot resolves it to a VM.
type SandlotClient interface {
	// UnmountRootfs unmounts the sandfs's rootfs directory (/mnt/rootfs) from the
	// microVM holding it and clears the virtio-fs allowed_dirs filter. Sandlot
	// resolves sandfs_id -> VM. Idempotent (no-op if the sandfs isn't mounted here).
	// Called on the async release path. Pairs with MountRootfsAndExecute. Returns
	// the three-layer unmount latency (UnmountResult) for gateway stats.
	UnmountRootfs(ctx context.Context, nodeAddr, sandfsID, volumePath, volumeEpoch string) (UnmountResult, error)

	// MountRootfsAndExecute is the combined attach+execute RPC. Sandlot
	// idempotently ensures the agent directory at volumePath is mounted at
	// /mnt/rootfs (reusing the VM already bound to sandfs_id if warm; else picking
	// a CLEAN spec-satisfying VM), then runs cmd (sync) or starts it as a
	// background exec (Background=true). Returns Stdout/ExitCode (sync) or
	// ExecID/Status="running" (background).
	MountRootfsAndExecute(ctx context.Context, req ExecRequest) (ExecResult, error)

	// StatusExec polls a background exec: liveness + captured log tail.
	StatusExec(ctx context.Context, nodeAddr, sandfsID, execID string) (ExecResult, error)

	// KillExec SIGKILLs a background exec's process group by exec_id.
	KillExec(ctx context.Context, nodeAddr, sandfsID, execID string) error

	// FileOp sends a file I/O command to sandlot over the persistent stream.
	// A single method covers all 7 sub-operations (read, write, stat, list_dir,
	// mkdir, remove, rename) — the action field in FileOpRequest selects which.
	FileOp(ctx context.Context, nodeAddr string, req FileOpRequest) (FileOpResult, error)

	// CleanupOverlay asks sandlot to unmount a host-side read-only overlay mount
	// at <volumePath>/rootfs/ so the SandFS directory can be deleted. Best-effort:
	// errors are logged but do not fail the SandFS deletion. Sandlots that are
	// offline at cleanup time have their stale overlays reaped by the periodic
	// overlay reaper on restart.
	CleanupOverlay(ctx context.Context, nodeAddr, volumePath string) error
}

// ErrBgExecNotFound mirrors the sandlot's not_found kill status:
// the exec_id is not in the warden's registry. Callers report "not_found"
// rather than a fabricated "killed".
var ErrBgExecNotFound = errors.New("background exec not found")

// StubSandlotClient is a stub implementation for testing without a real Sandlot.
type StubSandlotClient struct{}

func NewStubSandlotClient() *StubSandlotClient {
	return &StubSandlotClient{}
}

func (c *StubSandlotClient) UnmountRootfs(ctx context.Context, nodeAddr, sandfsID, volumePath, volumeEpoch string) (UnmountResult, error) {
	time.Sleep(3 * time.Millisecond) // simulate hot-unplug
	return UnmountResult{}, nil
}

func (c *StubSandlotClient) MountRootfsAndExecute(ctx context.Context, req ExecRequest) (ExecResult, error) {
	// Stub: simulate attach + execute in one call
	time.Sleep(5 * time.Millisecond) // simulate mount
	if req.Background {
		return ExecResult{ExecID: "stub-bg-1", Status: "running"}, nil
	}
	return ExecResult{Stdout: fmt.Sprintf("executed: %s", req.Command), ExitCode: 0, Status: "done"}, nil
}

func (c *StubSandlotClient) StatusExec(ctx context.Context, nodeAddr, sandfsID, execID string) (ExecResult, error) {
	return ExecResult{Status: "done", ExitCode: 0}, nil
}

func (c *StubSandlotClient) KillExec(ctx context.Context, nodeAddr, sandfsID, execID string) error {
	return nil
}

func (c *StubSandlotClient) FileOp(ctx context.Context, nodeAddr string, req FileOpRequest) (FileOpResult, error) {
	time.Sleep(1 * time.Millisecond) // simulate vsock RTT
	return FileOpResult{Success: true}, nil
}

func (c *StubSandlotClient) CleanupOverlay(ctx context.Context, nodeAddr, volumePath string) error {
	return nil
}

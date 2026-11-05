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

package core

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	pb "common/proto/stream"
	"sandlot/vmm"
	"sandlot/warden"
)

// --- fake warden (in-process raw vsock protocol peer over net.Pipe) ---

const fakeWardenMagic = 0x53414e44

// fakeWardenSessionKey is the per-VM key both the fake warden and the client
// under test use, so frames exercise the same authentication path as
// production.
var fakeWardenSessionKey = bytes.Repeat([]byte{0x77}, 32)

const (
	fakeOpMountAndExec      = 1
	fakeOpUnmount           = 2
	fakeOpExec              = 3
	fakeOpAsyncExec         = 5
	fakeOpMountAndAsyncExec = 6
	fakeOpStatusExec        = 7
	fakeOpKillExec          = 8
	fakeOpFile              = 9
)

type fakeWarden struct {
	mu               sync.Mutex
	ops              []uint8
	execStatus       int32
	execStdout       string
	statusExecStatus int32
	killNotFound     bool
	fileSuccess      bool
	fileData         []byte
	// execBarrier, when non-nil, makes each barrier op wait until
	// `barrierCount` of them have arrived before replying — the concurrency
	// probe (a serialized handler can never gather 2 at once). barrierOp
	// selects which op it applies to; 0 means OP_EXEC.
	execBarrier  chan struct{}
	barrierOp    uint8
	barrierCount int
	execsArrived int
	// execHold, when non-nil, makes every OP_EXEC wait for it before replying
	// (holds the slot in use so a test can observe queuing).
	execHold chan struct{}
	// mountedReply overrides the response's mounted-volume assertion (the
	// section successful MOUNT-family ops carry). Empty = AUTO: derive from
	// the request's device_path basename, exactly what a correct warden
	// replies — so existing tests pass unchanged. A non-empty value is sent
	// verbatim, letting tests drive the sandlot-side identity cross-check
	// with a deliberately wrong volume.
	mountedReply string
	// execErrCode/execErrStderr, when code is non-zero, make warm OP_EXEC
	// replies carry that code + stderr — how tests drive the warden's named
	// refusals (volume_identity_mismatch) on the warm path.
	execErrCode   uint8
	execErrStderr string
	// lastExecIdentity / lastAsyncIdentity / lastFileIdentity record the
	// mounted-volume identity field the warm ops carried, decoded at the
	// protocol's fixed positions (OP_EXEC index 3, OP_ASYNC_EXEC index 2,
	// OP_FILE index 5). "" = absent or empty.
	lastExecIdentity  string
	lastAsyncIdentity string
	lastFileIdentity  string
	// mountErrCode, when non-zero, makes MOUNT-family replies carry that
	// warden code (2 = CODE_TRANSPORT_ERROR, 7 = superseded generation) —
	// how tests drive the "guest mount state unknown" path without tearing
	// down the pipe.
	mountErrCode uint8
	// mountHold, when non-nil, parks a mount-family reply until released —
	// lets a test interleave an unmount/switch while the mount RPC is
	// queued (the generation race).
	mountHold chan struct{}
	// unmountCode/unmountMounted drive the identity-bound unmount verdict
	// (8 = not mounted, 9 = mismatch with the live identity).
	unmountCode         uint8
	unmountMounted      string
	lastUnmountIdentity string
	// fileDropConn makes an OP_FILE connection close without a reply, i.e. a
	// real fd-level TransportError (code 2 replies are warden RPC errors and are
	// NOT retried) — the replay decision under test.
	fileDropConn bool
}

// fieldAt decodes the idx-th [u32 len][bytes] field of a request body ("" when
// absent or malformed) — the raw-frame view tests use to assert wire positions
// without importing the client's encoder.
func fieldAt(body []byte, idx int) string {
	pos := 0
	for i := 0; ; i++ {
		if pos+4 > len(body) {
			return ""
		}
		n := int(binary.BigEndian.Uint32(body[pos : pos+4]))
		pos += 4
		if pos+n > len(body) {
			return ""
		}
		if i == idx {
			return string(body[pos : pos+n])
		}
		pos += n
	}
}

// reply returns (code, exitCode, stdout, stderr, execDurationNs) for a given op.
// It encodes the mock's configured outcomes into the wire code/exitCode fields.
func (f *fakeWarden) reply(op uint8) (code uint8, exitCode uint8, stdout string, stderr string, durNs uint64) {
	switch op {
	case fakeOpExec:
		if f.execErrCode != 0 {
			// Drive the warden's named warm-op refusals (e.g.
			// volume_identity_mismatch) as a transport-error class reply.
			return f.execErrCode, 0, "", f.execErrStderr, 0
		}
		// execStatus is a real exit code (0–255). CODE_OK carries it.
		return 0, uint8(f.execStatus), f.execStdout, "", 0
	case fakeOpMountAndExec:
		if f.mountErrCode != 0 {
			return f.mountErrCode, 0, "", "mount transport", 0
		}
		// execStatus is a real exit code (0–255). CODE_OK carries it.
		return 0, uint8(f.execStatus), f.execStdout, "", 0
	case fakeOpAsyncExec, fakeOpMountAndAsyncExec:
		if f.mountErrCode != 0 {
			return f.mountErrCode, 0, "", "mount transport", 0
		}
		return 0, 0, "bg-exec-1", "", 0
	case fakeOpStatusExec:
		// statusExecStatus carries a warden code value directly (mock config).
		return uint8(f.statusExecStatus), 0, "log tail", "", 0
	case fakeOpFile:
		if f.fileSuccess {
			return 0, 0, string(f.fileData), "", 0
		}
		// APP_ERROR: message in stdout, VM healthy.
		return 1, 0, string(f.fileData), "", 0
	case fakeOpKillExec:
		if f.killNotFound {
			return 5, 0, "", "", 0 // CODE_BG_NOT_FOUND
		}
		return 0, 0, "", "", 0
	case fakeOpUnmount:
		if f.unmountCode != 0 {
			return f.unmountCode, 0, "", "", 0
		}
		return 0, 0, "", "", 750_000 // 0.75ms warden unmount wall time
	}
	return 0, 0, "", "", 0
}

func (f *fakeWarden) serve(conn net.Conn) {
	hdr := make([]byte, 10) // magic(4) + version(1) + op(1) + body_len(4)
	for {
		if _, err := io.ReadFull(conn, hdr); err != nil {
			return
		}
		op := hdr[5]
		blen := binary.BigEndian.Uint32(hdr[6:10])
		// Authenticated header: nonce + op-specific body MAC + tag follow the
		// base 10 bytes.
		auth := make([]byte, warden.WireNonceLen+warden.WireBodyMACLen+warden.WireTagLen)
		if _, err := io.ReadFull(conn, auth); err != nil {
			return
		}
		nonce := auth[:warden.WireNonceLen]
		body := make([]byte, blen)
		if _, err := io.ReadFull(conn, body); err != nil {
			return
		}
		f.mu.Lock()
		f.ops = append(f.ops, op)
		switch op {
		case fakeOpExec:
			f.lastExecIdentity = fieldAt(body, 3) // v2 identity position
		case fakeOpAsyncExec:
			f.lastAsyncIdentity = fieldAt(body, 2) // v2 identity position
		case fakeOpFile:
			f.lastFileIdentity = fieldAt(body, 5) // v2 identity position
		case fakeOpUnmount:
			f.lastUnmountIdentity = fieldAt(body, 1) // mount_point, identity, forced
		}
		code, exitCode, out, errMsg, durNs := f.reply(op)
		var barrier chan struct{}
		barrierOp := f.barrierOp
		if barrierOp == 0 {
			barrierOp = fakeOpExec
		}
		if op == barrierOp && f.execBarrier != nil {
			f.execsArrived++
			if f.execsArrived == f.barrierCount {
				close(f.execBarrier)
			}
			barrier = f.execBarrier
		}
		f.mu.Unlock()
		if op == fakeOpFile && f.fileDropConn {
			// True transport failure: close the socket instead of replying.
			conn.Close()
			return
		}
		if op == fakeOpExec && f.execHold != nil {
			hold := f.execHold
			<-hold
		}
		if (op == fakeOpMountAndExec || op == fakeOpMountAndAsyncExec) && f.mountHold != nil {
			hold := f.mountHold
			<-hold
		}
		if barrier != nil {
			select {
			case <-barrier:
			case <-time.After(3 * time.Second):
				// Never gathered: the requests were serialized. Reply with a
				// transport error so the handler call fails the test.
				respHdr := make([]byte, warden.WireResponseHeaderLen)
				binary.BigEndian.PutUint32(respHdr[0:4], fakeWardenMagic)
				// Negotiated echo, exactly like the real warden: the response
				// carries the REQUEST's version byte (the client rejects any
				// other value as a ProtocolVersionError). Hardcoding a
				// literal here would silently pin the fake to one protocol
				// version and break every core test on the next bump.
				respHdr[4] = hdr[4]
				respHdr[5] = 2 // CODE_TRANSPORT_ERROR
				tag := warden.ResponseTag(fakeWardenSessionKey, nonce, respHdr[4], respHdr[5], 0, 0, 0, 0, 0)
				copy(respHdr[28:], tag[:])
				if _, err := conn.Write(respHdr); err != nil {
					return
				}
				mac := warden.MountedTag(fakeWardenSessionKey, nonce, nil)
				if _, err := conn.Write(mac[:]); err != nil {
					return
				}
				continue
			}
		}

		// Response header: [magic(4)][version(1)][code(1)][exit_code(1)][reserved(1)][stdout_len(4)][stderr_len(4)][exec_duration_ns(8)][mounted_len(4)]
		// mounted assertion: AUTO (basename of the request's device_path —
		// what a correct warden replies) unless the test overrides it.
		mounted := ""
		if op == fakeOpUnmount && f.unmountMounted != "" {
			mounted = f.unmountMounted
		}
		if code == 0 && (op == fakeOpMountAndExec || op == fakeOpMountAndAsyncExec) {
			if f.mountedReply != "" {
				mounted = f.mountedReply
			} else if fl := int(binary.BigEndian.Uint32(body[0:4])); len(body) >= 4+fl && fl > 0 {
				mounted = filepath.Base(string(body[4 : 4+fl]))
			}
		}
		respHdr := make([]byte, warden.WireResponseHeaderLen)
		binary.BigEndian.PutUint32(respHdr[0:4], fakeWardenMagic)
		respHdr[4] = hdr[4] // negotiated echo — see the barrier path above
		respHdr[5] = code
		respHdr[6] = exitCode
		respHdr[7] = 0 // reserved
		binary.BigEndian.PutUint32(respHdr[8:12], uint32(len(out)))
		binary.BigEndian.PutUint32(respHdr[12:16], uint32(len(errMsg)))
		binary.BigEndian.PutUint64(respHdr[16:24], durNs)
		binary.BigEndian.PutUint32(respHdr[24:28], uint32(len(mounted)))
		tag := warden.ResponseTag(fakeWardenSessionKey, nonce, hdr[4], code, exitCode,
			uint32(len(out)), uint32(len(errMsg)), durNs, uint32(len(mounted)))
		copy(respHdr[28:], tag[:])
		if _, err := conn.Write(respHdr); err != nil {
			return
		}
		if len(out) > 0 {
			if _, err := conn.Write([]byte(out)); err != nil {
				return
			}
		}
		if len(errMsg) > 0 {
			if _, err := conn.Write([]byte(errMsg)); err != nil {
				return
			}
		}
		if len(mounted) > 0 {
			if _, err := conn.Write([]byte(mounted)); err != nil {
				return
			}
		}
		mac := warden.MountedTag(fakeWardenSessionKey, nonce, []byte(mounted))
		if _, err := conn.Write(mac[:]); err != nil {
			return
		}
	}
}

func (f *fakeWarden) recordedOps() []uint8 {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]uint8, len(f.ops))
	copy(out, f.ops)
	return out
}

// recordedExecIdentity returns the mounted-volume identity the last OP_EXEC
// carried ("" = absent or empty).
func (f *fakeWarden) recordedExecIdentity() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastExecIdentity
}

// recordedAsyncIdentity returns the mounted-volume identity the last
// OP_ASYNC_EXEC carried ("" = absent or empty).
func (f *fakeWarden) recordedAsyncIdentity() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastAsyncIdentity
}

// recordedFileIdentity returns the mounted-volume identity the last OP_FILE
// carried ("" = absent or empty).
func (f *fakeWarden) recordedFileIdentity() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastFileIdentity
}

// newFakeWardenClient builds a warden.Client whose transport end is wired to an
// in-process fake warden speaking the raw frame protocol.
func newFakeWardenClient(t *testing.T, cfg func(*fakeWarden)) (*warden.Client, *fakeWarden) {
	t.Helper()
	fw := &fakeWarden{statusExecStatus: 3} // codeBgRunning
	if cfg != nil {
		cfg(fw)
	}
	return dialFake(t, fw), fw
}

// dialFake creates one more warden.Client connection into fw over a fresh
// net.Pipe — the same thing the connection pool does when it grows a slot.
func dialFake(t *testing.T, fw *fakeWarden) *warden.Client {
	t.Helper()
	server, clientConn := net.Pipe()
	go fw.serve(server)
	t.Cleanup(func() {
		server.Close()
		clientConn.Close()
	})

	return warden.NewClientForTransport(clientConn, 42, warden.ReadTimeoutCapDefault, fakeWardenSessionKey)
}

func newCoreTestHandler() *Handler {
	h := newTestHandler()
	h.metrics = NewNodeMetricsCollector()
	return h
}

func mountVolume(h *Handler, vmID, sandfsID, volumePath string) *VMState {
	st := addTestVM(h, vmID, "medium", false)
	h.bindSandfs(sandfsID, vmID)
	if volumePath != "" {
		alias := "alias-" + sandfsID
		st.Volumes[volumePath] = struct{}{}
		st.mountIdentity = alias
		st.mountIdentityPath = volumePath
		st.ensureMountRecordsForTest(sandfsID, volumePath, alias)
	}
	return st
}

// --- fileSubOpFromAction ---

func TestFileSubOpFromAction(t *testing.T) {
	tests := []struct {
		action string
		want   uint8
	}{
		{"read", warden.SubOpRead},
		{"write", warden.SubOpWrite},
		{"stat", warden.SubOpStat},
		{"list_dir", warden.SubOpListDir},
		{"mkdir", warden.SubOpMakeDir},
		{"remove", warden.SubOpRemove},
		{"rename", warden.SubOpRename},
	}
	for _, tt := range tests {
		got, err := fileSubOpFromAction(tt.action)
		if err != nil || got != tt.want {
			t.Errorf("fileSubOpFromAction(%q) = (%d, %v), want (%d, nil)", tt.action, got, err, tt.want)
		}
	}
	if _, err := fileSubOpFromAction("chmod"); err == nil {
		t.Error("fileSubOpFromAction(chmod) = nil error, want error")
	}
}

// --- idempotent paths when the sandfs is not mounted on this node ---

func TestHandleUnmountRootfsNotBound(t *testing.T) {
	h := newCoreTestHandler()
	resp := h.handleUnmountRootfs(context.Background(), &pb.VMCommand{CommandId: "c1", AgentId: "agent-t"},
		&pb.UnmountRootfs{SandfsId: "sfs-x"})
	if !resp.Success || resp.VmId != "" {
		t.Errorf("resp = %+v, want success with empty VmId", resp)
	}
}

func TestHandleStatusExecNotBound(t *testing.T) {
	h := newCoreTestHandler()
	resp := h.handleStatusExec(context.Background(), &pb.VMCommand{CommandId: "c1", AgentId: "agent-t"},
		&pb.StatusExec{SandfsId: "sfs-x", ExecId: "bg-1"})
	if !resp.Success || resp.Status != "not_found" {
		t.Errorf("resp = %+v, want success + status=not_found", resp)
	}
}

func TestHandleKillExecNotBound(t *testing.T) {
	h := newCoreTestHandler()
	resp := h.handleKillExec(context.Background(), &pb.VMCommand{CommandId: "c1", AgentId: "agent-t"},
		&pb.KillExec{SandfsId: "sfs-x", ExecId: "bg-1"})
	// an unmounted sandfs has no execs to kill — the truthful answer
	// is not_found (idempotent success, but never a fabricated "killed").
	if !resp.Success || resp.Status != "not_found" {
		t.Errorf("resp = %+v, want success + status=not_found ", resp)
	}
}

// --- no available VM paths ---

func TestHandleMountRootfsAndExecuteNoVM(t *testing.T) {
	h := newCoreTestHandler()
	resp := h.handleMountRootfsAndExecute(context.Background(), &pb.VMCommand{CommandId: "c1", AgentId: "agent-t"},
		&pb.MountRootfsAndExecute{
			VolumeMode: "flat", SandfsId: "sfs-1", VolumePath: "/vol/a"})
	if resp.Success || resp.Error != "no available VM on node" {
		t.Errorf("resp = %+v, want failure 'no available VM on node'", resp)
	}
}

func TestHandleFileOpNotMountedOnNode(t *testing.T) {
	h := newCoreTestHandler()
	resp := h.handleFileOp(context.Background(), &pb.VMCommand{CommandId: "c1", AgentId: "agent-t"},
		&pb.FileOp{
			VolumeMode: "flat", SandfsId: "sfs-1", Action: "read"})
	if resp.Success || resp.Error != "sandfs not mounted on node" {
		t.Errorf("resp = %+v, want failure 'sandfs not mounted on node'", resp)
	}
}

func TestHandleFileOpColdNoVM(t *testing.T) {
	h := newCoreTestHandler()
	resp := h.handleFileOp(context.Background(), &pb.VMCommand{CommandId: "c1", AgentId: "agent-t"},
		&pb.FileOp{
			VolumeMode: "flat", SandfsId: "sfs-1", VolumePath: "/vol/a"})
	if resp.Success || resp.Error != "no available VM on node" {
		t.Errorf("resp = %+v, want failure 'no available VM on node'", resp)
	}
}

// --- warm/cold exec paths against the fake warden ---

func TestHandleMountRootfsAndExecuteWarmPath(t *testing.T) {
	h := newCoreTestHandler()
	agt, fw := newFakeWardenClient(t, func(f *fakeWarden) { f.execStdout = "warm-out" })
	st := mountVolume(h, "vm-a", "sfs-1", "/vol/a")
	st.seedWardenClient(agt)

	cmd := &pb.VMCommand{CommandId: "c1", AgentId: "agent-t"}
	req := &pb.MountRootfsAndExecute{
		VolumeMode: "flat",
		SandfsId:   "sfs-1",
		VolumePath: "/vol/a",
		Command:    "echo hi",
		TimeoutMs:  1000,
	}
	resp := h.handleMountRootfsAndExecute(context.Background(), cmd, req)
	if !resp.Success {
		t.Fatalf("warm exec failed: %s", resp.Error)
	}
	if resp.Status != "done" || resp.Stdout != "warm-out" || resp.ExitCode != 0 {
		t.Errorf("resp status/stdout/exit = %q/%q/%d, want done/warm-out/0", resp.Status, resp.Stdout, resp.ExitCode)
	}
	if resp.SandlotDurationNs == 0 {
		t.Error("SandlotDurationNs not set")
	}
	if st.useCount.Load() != 1 {
		t.Errorf("useCount = %d, want 1", st.useCount.Load())
	}
	ops := fw.recordedOps()
	if len(ops) != 1 || ops[0] != fakeOpExec {
		t.Errorf("ops = %v, want single OP_EXEC (warm path)", ops)
	}
}

func TestHandleMountRootfsAndExecuteColdSyncPath(t *testing.T) {
	h := newCoreTestHandler()
	agt, fw := newFakeWardenClient(t, func(f *fakeWarden) { f.execStdout = "cold-out" })
	st := mountVolume(h, "vm-a", "sfs-1", "")
	st.seedWardenClient(agt)

	resp := h.handleMountRootfsAndExecute(context.Background(), &pb.VMCommand{CommandId: "c1", AgentId: "agent-t"},
		&pb.MountRootfsAndExecute{
			VolumeMode: "flat",
			SandfsId:   "sfs-1",
			VolumePath: "/vol/b",
			Command:    "echo hi",
			TimeoutMs:  1000,
		})
	if !resp.Success {
		t.Fatalf("cold exec failed: %s", resp.Error)
	}
	if resp.Stdout != "cold-out" || resp.Status != "done" {
		t.Errorf("stdout/status = %q/%q, want cold-out/done", resp.Stdout, resp.Status)
	}
	if _, ok := st.Volumes["/vol/b"]; !ok {
		t.Error("volume not tracked after cold mount")
	}
	ops := fw.recordedOps()
	// Cold path keeps the ONE-RTT combined mount_and_exec with the REAL
	// command: the per-VM lock covers only the switch bookkeeping (never the
	// exec wait), so there is no placeholder round-trip.
	if len(ops) != 1 || ops[0] != fakeOpMountAndExec {
		t.Errorf("ops = %v, want single OP_MOUNT_AND_EXEC", ops)
	}
}

func TestHandleMountRootfsAndExecuteColdBackground(t *testing.T) {
	h := newCoreTestHandler()
	agt, _ := newFakeWardenClient(t, nil)
	st := mountVolume(h, "vm-a", "sfs-1", "")
	st.seedWardenClient(agt)

	resp := h.handleMountRootfsAndExecute(context.Background(), &pb.VMCommand{CommandId: "c1", AgentId: "agent-t"},
		&pb.MountRootfsAndExecute{
			VolumeMode: "flat",
			SandfsId:   "sfs-1",
			VolumePath: "/vol/b",
			Command:    "sleep 30",
			Background: true,
		})
	if !resp.Success {
		t.Fatalf("cold background exec failed: %s", resp.Error)
	}
	if resp.ExecId != "bg-exec-1" || resp.Status != "running" {
		t.Errorf("exec_id/status = %q/%q, want bg-exec-1/running", resp.ExecId, resp.Status)
	}
	if n := st.activeBgExecs.Load(); n != 1 {
		t.Errorf("activeBgExecs = %d, want 1", n)
	}
	if _, ok := st.Volumes["/vol/b"]; !ok {
		t.Error("volume not tracked after cold background mount")
	}
}

func TestHandleMountRootfsAndExecuteWarmBackground(t *testing.T) {
	h := newCoreTestHandler()
	agt, fw := newFakeWardenClient(t, nil)
	st := mountVolume(h, "vm-a", "sfs-1", "/vol/a")
	st.seedWardenClient(agt)

	resp := h.handleMountRootfsAndExecute(context.Background(), &pb.VMCommand{CommandId: "c1", AgentId: "agent-t"},
		&pb.MountRootfsAndExecute{
			VolumeMode: "flat",
			SandfsId:   "sfs-1",
			VolumePath: "/vol/a",
			Command:    "sleep 30",
			Background: true,
		})
	if !resp.Success {
		t.Fatalf("warm background exec failed: %s", resp.Error)
	}
	if n := st.activeBgExecs.Load(); n != 1 {
		t.Errorf("activeBgExecs = %d, want 1", n)
	}
	ops := fw.recordedOps()
	if len(ops) != 1 || ops[0] != fakeOpAsyncExec {
		t.Errorf("ops = %v, want single OP_ASYNC_EXEC", ops)
	}
}

// TestWarmExecCarriesMountedVolumeIdentity pins the sandlot side of the v2
// warm-op identity assertion: the OP_EXEC frame carries the alias this VM's
// mount record names — the identity the warden checks against what it
// actually holds. RED if the identity stops being threaded
// (the warden then reads an empty field and silently falls back to
// mount_active-only).
func TestWarmExecCarriesMountedVolumeIdentity(t *testing.T) {
	h := newCoreTestHandler()
	agt, fw := newFakeWardenClient(t, func(f *fakeWarden) { f.execStdout = "out" })
	st := mountVolume(h, "vm-a", "sfs-1", "/vol/sandfs-a")
	st.seedWardenClient(agt)

	resp := h.handleMountRootfsAndExecute(context.Background(), &pb.VMCommand{CommandId: "c1", AgentId: "agent-t"},
		&pb.MountRootfsAndExecute{
			VolumeMode: "flat", SandfsId: "sfs-1", VolumePath: "/vol/sandfs-a", Command: "echo hi", TimeoutMs: 1000})
	if !resp.Success {
		t.Fatalf("warm exec failed: %s", resp.Error)
	}
	if got := fw.recordedExecIdentity(); got != "alias-sfs-1" {
		t.Fatalf("OP_EXEC mounted-volume identity = %q, want %q", got, "alias-sfs-1")
	}
}

// TestWarmAsyncExecCarriesMountedVolumeIdentity is the OP_ASYNC_EXEC half of
// the pin above (identity field index 2).
func TestWarmAsyncExecCarriesMountedVolumeIdentity(t *testing.T) {
	h := newCoreTestHandler()
	agt, fw := newFakeWardenClient(t, nil)
	st := mountVolume(h, "vm-a", "sfs-1", "/vol/sandfs-a")
	st.seedWardenClient(agt)

	resp := h.handleMountRootfsAndExecute(context.Background(), &pb.VMCommand{CommandId: "c1", AgentId: "agent-t"},
		&pb.MountRootfsAndExecute{
			VolumeMode: "flat", SandfsId: "sfs-1", VolumePath: "/vol/sandfs-a", Command: "sleep 30", Background: true})
	if !resp.Success {
		t.Fatalf("warm background exec failed: %s", resp.Error)
	}
	if got := fw.recordedAsyncIdentity(); got != "alias-sfs-1" {
		t.Fatalf("OP_ASYNC_EXEC mounted-volume identity = %q, want %q", got, "alias-sfs-1")
	}
}

// TestWarmExecVolumeIdentityRefusalFailsTheCommand: when the warden refuses a
// warm op with its named volume_identity_mismatch (its mounted volume is not
// the one this sandlot's record names), the command must FAIL with that name
// surfaced — never be reported as a result, and never be retried into an exec
// against the skewed mount.
func TestWarmExecVolumeIdentityRefusalFailsTheCommand(t *testing.T) {
	h := newCoreTestHandler()
	agt, _ := newFakeWardenClient(t, func(f *fakeWarden) {
		f.execErrCode = 2 // CODE_TRANSPORT_ERROR — the warden's refusal class
		f.execErrStderr = `volume_identity_mismatch: warm op names volume "sandfs-b" but /mnt/rootfs holds "sandfs-a"; refusing without executing (sandlot bookkeeping skew)`
	})
	st := mountVolume(h, "vm-a", "sfs-1", "/vol/sandfs-b")
	st.seedWardenClient(agt)

	resp := h.handleMountRootfsAndExecute(context.Background(), &pb.VMCommand{CommandId: "c1", AgentId: "agent-t"},
		&pb.MountRootfsAndExecute{
			VolumeMode: "flat", SandfsId: "sfs-1", VolumePath: "/vol/sandfs-b", Command: "echo hi", TimeoutMs: 1000})
	if resp.Success {
		t.Fatalf("a named identity refusal must fail the command, got %+v", resp)
	}
	if !strings.Contains(resp.Error, "volume_identity_mismatch") {
		t.Fatalf("resp.Error = %q, want the named refusal surfaced", resp.Error)
	}
}

// TestFileOpCarriesMountedVolumeIdentity pins the OP_FILE half (identity field
// index 5, padded): the file op resolves paths inside the mounted volume, so
// the warden must be able to refuse a skew before touching any path.
func TestFileOpCarriesMountedVolumeIdentity(t *testing.T) {
	h := newCoreTestHandler()
	agt, fw := newFakeWardenClient(t, func(f *fakeWarden) {
		f.fileSuccess = true
		f.fileData = []byte("data")
	})
	st := mountVolume(h, "vm-a", "sfs-1", "/vol/sandfs-b")
	st.seedWardenClient(agt)

	resp := h.handleFileOp(context.Background(), &pb.VMCommand{CommandId: "c1", AgentId: "agent-t"},
		&pb.FileOp{
			VolumeMode: "flat", SandfsId: "sfs-1", VolumePath: "/vol/sandfs-b", Action: "read", Path: "x"})
	if !resp.Success {
		t.Fatalf("file op failed: %s", resp.Error)
	}
	if got := fw.recordedFileIdentity(); got != "alias-sfs-1" {
		t.Fatalf("OP_FILE mounted-volume identity = %q, want %q", got, "alias-sfs-1")
	}
}

func TestHandleStatusExecRunningAndDone(t *testing.T) {
	h := newCoreTestHandler()
	running, _ := newFakeWardenClient(t, func(f *fakeWarden) { f.statusExecStatus = 3 }) // codeBgRunning
	st := mountVolume(h, "vm-a", "sfs-1", "/vol/a")
	st.seedWardenClient(running)
	setBgExecs(st, 2)

	cmd := &pb.VMCommand{CommandId: "c1", AgentId: "agent-t"}
	req := &pb.StatusExec{SandfsId: "sfs-1", ExecId: "bg-exec-1"}

	resp := h.handleStatusExec(context.Background(), cmd, req)
	if !resp.Success || resp.Status != "running" || resp.Stdout != "log tail" {
		t.Errorf("running resp = %+v, want running + log tail", resp)
	}
	if n := st.activeBgExecs.Load(); n != 2 {
		t.Errorf("activeBgExecs after running poll = %d, want 2", n)
	}

	done, _ := newFakeWardenClient(t, func(f *fakeWarden) { f.statusExecStatus = 0 })
	st.seedWardenClient(done)

	resp = h.handleStatusExec(context.Background(), cmd, req)
	if !resp.Success || resp.Status != "done" || resp.ExitCode != 0 {
		t.Errorf("done resp = %+v, want done + exit 0", resp)
	}
	if n := st.activeBgExecs.Load(); n != 1 {
		t.Errorf("activeBgExecs after done = %d, want 1 (decremented)", n)
	}
}

func TestHandleKillExecBound(t *testing.T) {
	h := newCoreTestHandler()
	agt, _ := newFakeWardenClient(t, nil)
	st := mountVolume(h, "vm-a", "sfs-1", "/vol/a")
	st.seedWardenClient(agt)
	setBgExecs(st, 3)

	resp := h.handleKillExec(context.Background(), &pb.VMCommand{CommandId: "c1", AgentId: "agent-t"},
		&pb.KillExec{SandfsId: "sfs-1", ExecId: "bg-exec-1"})
	if !resp.Success || resp.Status != "killed" || resp.VmId != "vm-a" {
		t.Errorf("resp = %+v, want killed on vm-a", resp)
	}
	if n := st.activeBgExecs.Load(); n != 2 {
		t.Errorf("activeBgExecs = %d, want 2", n)
	}
}

func TestHandleFileOpReadWarm(t *testing.T) {
	h := newCoreTestHandler()
	agt, fw := newFakeWardenClient(t, func(f *fakeWarden) {
		f.fileData = []byte("hello file")
		f.fileSuccess = true
	})
	st := mountVolume(h, "vm-a", "sfs-1", "/vol/a")
	st.seedWardenClient(agt)

	resp := h.handleFileOp(context.Background(), &pb.VMCommand{CommandId: "c1", AgentId: "agent-t"},
		&pb.FileOp{
			VolumeMode: "flat", SandfsId: "sfs-1", VolumePath: "/vol/a", Action: "read", Path: "data.txt"})
	if !resp.Success {
		t.Fatalf("file read failed: %s", resp.Error)
	}
	if string(resp.StdoutRaw) != "hello file" || resp.ExitCode != 0 {
		t.Errorf("data/status = %q/%d, want 'hello file'/0", resp.StdoutRaw, resp.ExitCode)
	}
	ops := fw.recordedOps()
	if len(ops) != 1 || ops[0] != fakeOpFile {
		t.Errorf("ops = %v, want single OP_FILE", ops)
	}
	if st.useCount.Load() != 1 {
		t.Errorf("useCount = %d, want 1 (file ops advance the recycle counter)", st.useCount.Load())
	}
}

func TestHandleFileOpAppErrorStillCounts(t *testing.T) {
	h := newCoreTestHandler()
	// APP_ERROR (ENOENT-analog): code 1 with the message in stdout — the fake
	// needs fileData set for the message to surface in resp.Error.
	agt, _ := newFakeWardenClient(t, func(f *fakeWarden) {
		f.fileSuccess = false
		f.fileData = []byte("ENOENT: no such file or directory")
	})
	st := mountVolume(h, "vm-a", "sfs-1", "/vol/a")
	st.seedWardenClient(agt)

	resp := h.handleFileOp(context.Background(), &pb.VMCommand{CommandId: "c1", AgentId: "agent-t"},
		&pb.FileOp{
			VolumeMode: "flat", SandfsId: "sfs-1", VolumePath: "/vol/a", Action: "read", Path: "missing.txt"})
	if !resp.Success || resp.Error == "" {
		t.Fatalf("resp = %+v, want Success=true with an app-level Error", resp)
	}
	if st.useCount.Load() != 1 {
		t.Errorf("useCount = %d, want 1 (an app-level failure was still served by the VM)", st.useCount.Load())
	}
}

func TestHandleFileOpUnknownAction(t *testing.T) {
	h := newCoreTestHandler()
	agt, _ := newFakeWardenClient(t, nil)
	st := mountVolume(h, "vm-a", "sfs-1", "/vol/a")
	st.seedWardenClient(agt)

	resp := h.handleFileOp(context.Background(), &pb.VMCommand{CommandId: "c1", AgentId: "agent-t"},
		&pb.FileOp{
			VolumeMode: "flat", SandfsId: "sfs-1", VolumePath: "/vol/a", Action: "chmod", Path: "data.txt"})
	if resp.Success || resp.Error == "" {
		t.Errorf("resp = %+v, want failure for unknown action", resp)
	}
}

func TestHandleFileOpColdMountThenRead(t *testing.T) {
	h := newCoreTestHandler()
	agt, fw := newFakeWardenClient(t, func(f *fakeWarden) { f.fileData = []byte("cold"); f.fileSuccess = true })
	st := mountVolume(h, "vm-a", "sfs-1", "")
	st.seedWardenClient(agt)

	resp := h.handleFileOp(context.Background(), &pb.VMCommand{CommandId: "c1", AgentId: "agent-t"},
		&pb.FileOp{
			VolumeMode: "flat", SandfsId: "sfs-1", Action: "read", Path: "data.txt", VolumePath: "/vol/c"})
	if !resp.Success {
		t.Fatalf("cold file op failed: %s", resp.Error)
	}
	if string(resp.StdoutRaw) != "cold" {
		t.Errorf("data = %q, want cold", resp.StdoutRaw)
	}
	if _, ok := st.Volumes["/vol/c"]; !ok {
		t.Error("volume not tracked after cold file-op mount")
	}
	sawMount := false
	for _, op := range fw.recordedOps() {
		if op == fakeOpMountAndExec {
			sawMount = true
		}
	}
	if !sawMount {
		t.Errorf("no OP_MOUNT_AND_EXEC in %v (expected mount-only cold mount, empty command)", fw.recordedOps())
	}
	if st.useCount.Load() != 1 {
		t.Errorf("useCount = %d, want 1 (cold file op advances the recycle counter once)", st.useCount.Load())
	}
}

func TestHandleUnmountRootfsSuccess(t *testing.T) {
	h := newCoreTestHandler()
	agt, fw := newFakeWardenClient(t, nil)
	st := mountVolume(h, "vm-a", "sfs-1", "/vol/a")
	st.seedWardenClient(agt)
	setBgExecs(st, 1)

	resp := h.handleUnmountRootfs(context.Background(), &pb.VMCommand{CommandId: "c1", AgentId: "agent-t"},
		&pb.UnmountRootfs{SandfsId: "sfs-1", VolumePath: "/vol/a"})
	if !resp.Success || resp.VmId != "vm-a" || resp.Spec != "medium" {
		t.Fatalf("resp = %+v, want success on vm-a spec=medium", resp)
	}
	// The warden unmount wall time is threaded into exec_duration_ns, and the
	// sandlot total into sandlot_duration_ns (gateway unmount stats source).
	if resp.ExecDurationNs == 0 {
		t.Errorf("ExecDurationNs = 0, want warden unmount wall time")
	}
	if resp.SandlotDurationNs == 0 {
		t.Errorf("SandlotDurationNs = 0, want sandlot total unmount time")
	}
	if len(st.Volumes) != 0 {
		t.Errorf("Volumes = %v, want empty after unmount", st.Volumes)
	}
	if h.vmForSandfs("sfs-1") != nil {
		t.Error("binding not removed after unmount")
	}
	ops := fw.recordedOps()
	if len(ops) != 1 || ops[0] != fakeOpUnmount {
		t.Errorf("ops = %v, want single OP_UNMOUNT", ops)
	}
}

func TestHandleCleanupOverlaySuccess(t *testing.T) {
	h := newCoreTestHandler()
	resp := h.handleCleanupOverlay(context.Background(), &pb.VMCommand{CommandId: "c1", AgentId: "agent-t"},
		&pb.CleanupOverlay{VolumePath: "/vol/a"})
	if !resp.Success {
		t.Errorf("resp = %+v, want success", resp)
	}
}

// TestCommandVolumePathContained pins the embedded-mode containment guard on
// gateway-supplied volume paths (the boxout sidecar has the twin check): a
// path outside the configured volumes root — or a traversal, or an empty path
// where one is required — must be refused by name BEFORE it becomes a host
// mount source (cold exec/file-op mounts, set-fs allowed_dirs, the host-side
// overlay unmount). The fixture's volumes root is /vol.
func TestCommandVolumePathContained(t *testing.T) {
	cases := []struct {
		name string
		path string
		want string
	}{
		{"absolute escape", "/etc", "outside the volumes root"},
		{"traversal escape", "/vol/../../etc", "contains path traversal"},
		{"traversal inside root", "/vol/a/../b", "contains path traversal"},
		{"empty path", "", "volume_path is required"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newCoreTestHandler()
			addTestVM(h, "vm-a", "medium", false)
			h.bindSandfs("sfs-1", "vm-a")

			resp := h.handleMountRootfsAndExecute(context.Background(),
				&pb.VMCommand{CommandId: "c1", AgentId: "agent-t"},
				&pb.MountRootfsAndExecute{
					VolumeMode: "flat", SandfsId: "sfs-1", VolumePath: tc.path, Command: "true", TimeoutMs: 1000})
			if resp.Success || !strings.Contains(resp.Error, tc.want) {
				t.Errorf("mount-rootfs with %q: resp = %+v, want refusal containing %q", tc.path, resp, tc.want)
			}

			if tc.path == "" {
				// A file op with no volume_path is the documented
				// "not mounted on node" path, and cleanup keeps its
				// idempotent empty-path no-op (nothing to unmount); only a
				// clean refusal where a path IS supplied is the guard's job.
				resp = h.handleCleanupOverlay(context.Background(),
					&pb.VMCommand{CommandId: "c3", AgentId: "agent-t"},
					&pb.CleanupOverlay{VolumePath: ""})
				if !resp.Success {
					t.Errorf("cleanup-overlay with empty path: resp = %+v, want idempotent success", resp)
				}
				return
			}

			resp = h.handleFileOp(context.Background(),
				&pb.VMCommand{CommandId: "c2", AgentId: "agent-t"},
				&pb.FileOp{
					VolumeMode: "flat", SandfsId: "sfs-1", VolumePath: tc.path, Action: "read", Path: "x"})
			if resp.Success || !strings.Contains(resp.Error, tc.want) {
				t.Errorf("file-op with %q: resp = %+v, want refusal containing %q", tc.path, resp, tc.want)
			}

			resp = h.handleCleanupOverlay(context.Background(),
				&pb.VMCommand{CommandId: "c3", AgentId: "agent-t"},
				&pb.CleanupOverlay{VolumePath: tc.path})
			if resp.Success || !strings.Contains(resp.Error, tc.want) {
				t.Errorf("cleanup-overlay with %q: resp = %+v, want refusal containing %q", tc.path, resp, tc.want)
			}
		})
	}
}

// TestCommandVolumePathEmptyRootRefused pins the empty-root rule: a handler
// whose volumes root is unset (a construction bug) refuses every path rather
// than degenerating the containment test to "/".
func TestCommandVolumePathEmptyRootRefused(t *testing.T) {
	h := newCoreTestHandler()
	h.vmmCfg.VolumesDir = ""
	if err := h.checkVolumePathContained("/vol/a"); err == nil ||
		!strings.Contains(err.Error(), "no volumes root configured") {
		t.Errorf("err = %v, want named empty-root refusal", err)
	}
}

// TestCommandVolumePathTrailingSlashRoot pins the config-shape fix: a
// configured volumes root with a trailing slash (or a doubled separator) must
// not make every legitimate volume path fail containment. Both operands are
// cleaned before the prefix test.
func TestCommandVolumePathTrailingSlashRoot(t *testing.T) {
	h := newCoreTestHandler()
	h.vmmCfg.VolumesDir = "/vol/"
	if err := h.checkVolumePathContained("/vol/a"); err != nil {
		t.Errorf("trailing-slash root: err = %v, want the path accepted", err)
	}
	if err := h.checkVolumePathContained("/other/a"); err == nil {
		t.Error("trailing-slash root: an outside path must still be refused")
	}
	h.vmmCfg.VolumesDir = "/vol//"
	if err := h.checkVolumePathContained("/vol/a"); err != nil {
		t.Errorf("doubled-separator root: err = %v, want the path accepted", err)
	}
}

// TestHandleStatusExecDoneCountedOnce pins the once-per-exec decrement: the
// warden keeps a finished bg exec's registry entry until unmount and answers
// EVERY later poll with done/killed again — without the dedup, each repeat
// poll eats a sibling exec's count and the pool-destroy classification kills
// a VM whose background work is still running.
func TestHandleStatusExecDoneCountedOnce(t *testing.T) {
	h := newCoreTestHandler()
	done, _ := newFakeWardenClient(t, func(f *fakeWarden) { f.statusExecStatus = 0 }) // CODE_OK → "done"
	st := mountVolume(h, "vm-a", "sfs-1", "/vol/a")
	st.seedWardenClient(done)
	setBgExecs(st, 2) // exec A (polled below) + exec B (still running)

	cmd := &pb.VMCommand{CommandId: "c1", AgentId: "agent-t"}
	req := &pb.StatusExec{SandfsId: "sfs-1", ExecId: "bg-exec-1"}

	// First done report decrements: 2 → 1.
	if resp := h.handleStatusExec(context.Background(), cmd, req); !resp.Success || resp.Status != "done" {
		t.Fatalf("first done poll resp = %+v", resp)
	}
	if n := st.activeBgExecs.Load(); n != 1 {
		t.Fatalf("activeBgExecs after first done = %d, want 1", n)
	}

	// Repeat polls of the SAME exec must not decrement again (exec B is the
	// remaining 1) — exactly the warden's behavior for a polled-done exec.
	for i := 0; i < 3; i++ {
		if resp := h.handleStatusExec(context.Background(), cmd, req); !resp.Success || resp.Status != "done" {
			t.Fatalf("repeat done poll %d resp = %+v", i, resp)
		}
	}
	if n := st.activeBgExecs.Load(); n != 1 {
		t.Fatalf("activeBgExecs after repeat done polls = %d, want 1 (once per exec, not once per poll)", n)
	}

	// A DIFFERENT exec's done report still counts.
	reqB := &pb.StatusExec{SandfsId: "sfs-1", ExecId: "bg-exec-2"}
	if resp := h.handleStatusExec(context.Background(), cmd, reqB); !resp.Success {
		t.Fatalf("exec B done poll resp = %+v", resp)
	}
	if n := st.activeBgExecs.Load(); n != 0 {
		t.Fatalf("activeBgExecs after exec B done = %d, want 0", n)
	}
}

// TestHandleKillThenStatusNotDoubleCounted covers the cross-op double count:
// KillExec decrements, and the StatusExec that later reports the same exec as
// "killed" must not decrement it a second time (the warden keeps the entry,
// now flagged killed).
func TestHandleKillThenStatusNotDoubleCounted(t *testing.T) {
	h := newCoreTestHandler()
	agt, _ := newFakeWardenClient(t, nil) // kill replies success; status replies running by default
	st := mountVolume(h, "vm-a", "sfs-1", "/vol/a")
	st.seedWardenClient(agt)
	setBgExecs(st, 2)

	cmd := &pb.VMCommand{CommandId: "c1", AgentId: "agent-t"}
	if resp := h.handleKillExec(context.Background(), cmd, &pb.KillExec{SandfsId: "sfs-1", ExecId: "bg-exec-1"}); !resp.Success {
		t.Fatalf("kill resp = %+v", resp)
	}
	if n := st.activeBgExecs.Load(); n != 1 {
		t.Fatalf("activeBgExecs after kill = %d, want 1", n)
	}

	// The warden now reports the killed exec as CODE_BG_KILLED on every poll.
	killedView, _ := newFakeWardenClient(t, func(f *fakeWarden) { f.statusExecStatus = 4 }) // codeBgKilled
	st.seedWardenClient(killedView)
	if resp := h.handleStatusExec(context.Background(), cmd, &pb.StatusExec{SandfsId: "sfs-1", ExecId: "bg-exec-1"}); !resp.Success || resp.Status != "killed" {
		t.Fatalf("status-after-kill resp = %+v", resp)
	}
	if n := st.activeBgExecs.Load(); n != 1 {
		t.Fatalf("activeBgExecs after status-of-killed = %d, want 1 (kill already counted this exec)", n)
	}
}

// TestUnmountRecycleKeepsPendingDestroyThroughDestroyWindow pins the
// destroy-window exclusion: once an unmount decides to destroy (recycle policy
// or pool scale-down), pendingDestroy must stay SET until the async destroy
// removes the VM from the registry — the seconds-wide window contains a warden
// dial, a set-fs call and a kill, during which the VM must not be handed to a
// fresh cold mount.
func TestUnmountRecycleKeepsPendingDestroyThroughDestroyWindow(t *testing.T) {
	h := newCoreTestHandler()
	agt, _ := newFakeWardenClient(t, nil) // unmount replies success
	st := mountVolume(h, "vm-a", "sfs-1", "/vol/a")
	st.seedWardenClient(agt)

	// Make the recycle trigger fire on this unmount (use-count threshold).
	h.UpdateRecycleConfig(1, 0, 0, 0)
	st.useCount.Store(1)

	resp := h.handleUnmountRootfs(context.Background(), &pb.VMCommand{CommandId: "c1", AgentId: "agent-t"},
		&pb.UnmountRootfs{SandfsId: "sfs-1", VolumePath: "/vol/a"})
	if !resp.Success {
		t.Fatalf("unmount resp = %+v (%s)", resp, resp.Error)
	}

	// The flag must still be set the moment the response returns — the async
	// destroyAndReplaceVM has only just been spawned. resolveVMForMount skips
	// pendingDestroy VMs, so the doomed VM cannot be picked in the window.
	if !st.pendingDestroy.Load() {
		t.Fatal("pendingDestroy cleared at unmount response; the VM is selectable during the async destroy window")
	}

	// And the binding is gone: no sandfs resolves to this VM anymore.
	if vm := h.vmForSandfs("sfs-1"); vm != nil && !vm.pendingDestroy.Load() {
		t.Error("sfs-1 still resolves to a non-doomed VM after unmount")
	}
}

// --- mounted-volume identity cross-check (exclusive-ownership belt) ---

// TestHandleMountRootfsAndExecuteColdSyncMountedMismatch drives the sandlot
// side of the shadow-mount defense: the warden claims success but reports a
// DIFFERENT volume mounted at /mnt/rootfs than the one requested (the shape
// an out-of-band mount-only racing the switch window produces). The handler
// must NOT trust the exec output: the request fails, the volume is not
// tracked, and the VM is marked dirty (pendingDestroy) for destroy-and-replace.
func TestHandleMountRootfsAndExecuteColdSyncMountedMismatch(t *testing.T) {
	h := newCoreTestHandler()
	agt, fw := newFakeWardenClient(t, func(f *fakeWarden) {
		f.execStdout = "poisoned-output"
		f.mountedReply = "sandfs-attacker" // NOT basename("/vol/b")
	})
	st := mountVolume(h, "vm-a", "sfs-1", "")
	st.seedWardenClient(agt)

	resp := h.handleMountRootfsAndExecute(context.Background(), &pb.VMCommand{CommandId: "c1", AgentId: "agent-t"},
		&pb.MountRootfsAndExecute{
			VolumeMode: "flat",
			SandfsId:   "sfs-1",
			VolumePath: "/vol/b",
			Command:    "echo hi",
			TimeoutMs:  1000,
		})
	if resp.Success {
		t.Fatal("mismatched mounted identity must fail the request")
	}
	if resp.Stdout != "" {
		t.Errorf("exec output must be suppressed on identity mismatch, got %q", resp.Stdout)
	}
	// The error reaches the agent's API surface: it must NOT name either
	// volume (on-disk names are seed-derived and stay host-side — ambient
	// sandbox strings leak to third-party LLMs wholesale). The machine-
	// readable meaning is "different volume than requested".
	if strings.Contains(resp.Error, "sandfs-attacker") || strings.Contains(resp.Error, "/vol/b") {
		t.Errorf("error = %q must not name either volume (sanitized contract)", resp.Error)
	}
	if !strings.Contains(resp.Error, "different volume") {
		t.Errorf("error = %q, want it to state the identity mismatch", resp.Error)
	}
	if _, ok := st.Volumes["/vol/b"]; ok {
		t.Error("volume must NOT be tracked after an identity mismatch")
	}
	if !st.pendingDestroy.Load() {
		t.Error("VM must be marked dirty (pendingDestroy) after an identity mismatch")
	}
	_ = fw // ops recorded but irrelevant here
}

// TestHandleMountRootfsAndExecuteColdAsyncMountedMismatch is the background
// variant: a wrong mounted identity invalidates the returned exec_id — the
// exec started against a volume that is not this sandfs's.
func TestHandleMountRootfsAndExecuteColdAsyncMountedMismatch(t *testing.T) {
	h := newCoreTestHandler()
	agt, _ := newFakeWardenClient(t, func(f *fakeWarden) {
		f.mountedReply = "sandfs-attacker"
	})
	st := mountVolume(h, "vm-a", "sfs-1", "")
	st.seedWardenClient(agt)

	resp := h.handleMountRootfsAndExecute(context.Background(), &pb.VMCommand{CommandId: "c1", AgentId: "agent-t"},
		&pb.MountRootfsAndExecute{
			VolumeMode: "flat",
			SandfsId:   "sfs-1",
			VolumePath: "/vol/b",
			Command:    "sleep 100",
			Background: true,
		})
	if resp.Success || resp.ExecId != "" {
		t.Fatalf("resp = %+v, want failure without exec_id on identity mismatch", resp)
	}
	if !st.pendingDestroy.Load() {
		t.Error("VM must be marked dirty (pendingDestroy) after an identity mismatch")
	}
}

// TestHandleFileOpColdMountedMismatch covers the mount-only path (ensureMounted
// → MountOnly): a wrong mounted identity fails the file op before it runs.
func TestHandleFileOpColdMountedMismatch(t *testing.T) {
	h := newCoreTestHandler()
	agt, _ := newFakeWardenClient(t, func(f *fakeWarden) {
		f.mountedReply = "sandfs-attacker"
	})
	st := mountVolume(h, "vm-a", "sfs-1", "")
	st.seedWardenClient(agt)

	resp := h.handleFileOp(context.Background(), &pb.VMCommand{CommandId: "c1", AgentId: "agent-t"},
		&pb.FileOp{
			VolumeMode: "flat", SandfsId: "sfs-1", VolumePath: "/vol/b", Action: "read", Path: "x"})
	if resp.Success {
		t.Fatal("mismatched mounted identity must fail the file op")
	}
	if _, ok := st.Volumes["/vol/b"]; ok {
		t.Error("volume must NOT be tracked after an identity mismatch")
	}
	if !st.pendingDestroy.Load() {
		t.Error("VM must be marked dirty (pendingDestroy) after an identity mismatch")
	}
}

// TestColdMountCorrectIdentityAccepted pins the AUTO behavior: with no
// override the fake echoes the requested volume's basename (a correct
// warden), and the cold path succeeds exactly as before the belt existed.
func TestColdMountCorrectIdentityAccepted(t *testing.T) {
	h := newCoreTestHandler()
	agt, _ := newFakeWardenClient(t, func(f *fakeWarden) { f.execStdout = "ok" })
	st := mountVolume(h, "vm-a", "sfs-1", "")
	st.seedWardenClient(agt)

	resp := h.handleMountRootfsAndExecute(context.Background(), &pb.VMCommand{CommandId: "c1", AgentId: "agent-t"},
		&pb.MountRootfsAndExecute{
			VolumeMode: "flat", SandfsId: "sfs-1", VolumePath: "/vol/b", Command: "true", TimeoutMs: 1000})
	if !resp.Success {
		t.Fatalf("correct identity must succeed: %s", resp.Error)
	}
	if st.pendingDestroy.Load() {
		t.Error("VM must NOT be dirty-destroyed when identity matches")
	}
}

// TestHandleUnmountRootfsClearFailureDestroysVM pins: a FAILED
// allowed_dirs clear during unmount is fatal to the VM (dirty-destroy), not
// best-effort — reusing it would stack the next attach over a share root
// that still exports the previous tenant. RED with the old non-fatal path
// (response Success=true).
func TestHandleUnmountRootfsClearFailureDestroysVM(t *testing.T) {
	h := newCoreTestHandler()
	agt, _ := newFakeWardenClient(t, nil)
	st := mountVolume(h, "vm-a", "sfs-1", "/vol/a")
	st.seedWardenClient(agt)
	// A dead VMM socket: the set-fs clear fails.
	st.VM.Client = vmm.NewClient(filepath.Join(t.TempDir(), "missing-sandvmm.sock"))

	resp := h.handleUnmountRootfs(context.Background(), &pb.VMCommand{CommandId: "c1", AgentId: "agent-t"},
		&pb.UnmountRootfs{SandfsId: "sfs-1", VolumePath: "/vol/a"})
	if resp.Success {
		t.Fatalf("clear failure must fail the unmount, got success: %+v", resp)
	}
	if !strings.Contains(resp.Error, "clear allowed_dirs") {
		t.Fatalf("error should name the clear failure: %q", resp.Error)
	}
	// The VM is excluded from reuse for the destroy window.
	if !st.pendingDestroy.Load() {
		t.Fatal("VM not marked for dirty destroy after a failed clear")
	}
}

// TestHandleFileOpWireGate pins the sandlot-side defense-in-depth
// gate: an oversized FileOp payload is refused with FILE_TOO_LARGE before
// any VM resolution (an oversize RESPONSE would breach the gRPC limit and
// reset the stream). RED with the gate removed.
func TestHandleFileOpWireGate(t *testing.T) {
	old := maxFileOpDataBytes
	maxFileOpDataBytes = 1024
	defer func() { maxFileOpDataBytes = old }()

	h := newCoreTestHandler()
	cmd := &pb.VMCommand{CommandId: "c1", AgentId: "agent-t"}
	resp := h.handleFileOp(context.Background(), cmd, &pb.FileOp{
		VolumeMode: "flat",
		SandfsId:   "sfs-none", Action: "write", Path: "/x", Data: make([]byte, 2048),
	})
	if resp.Success || resp.ErrorCode != "FILE_TOO_LARGE" {
		t.Fatalf("oversize write must be refused FILE_TOO_LARGE, got %+v", resp)
	}
	resp = h.handleFileOp(context.Background(), cmd, &pb.FileOp{
		VolumeMode: "flat",
		SandfsId:   "sfs-none", Action: "read", Path: "/x", Length: 2048,
	})
	if resp.Success || resp.ErrorCode != "FILE_TOO_LARGE" {
		t.Fatalf("oversize read must be refused FILE_TOO_LARGE, got %+v", resp)
	}
}

// TestHandleKillExecNotFound pins the truthful not-found report:
// a kill of an unknown exec_id answers Status "not_found", never the blanket
// "killed". RED before the fix (client discarded the BG_NOT_FOUND code).
func TestHandleKillExecNotFound(t *testing.T) {
	h := newCoreTestHandler()
	agt, _ := newFakeWardenClient(t, func(f *fakeWarden) { f.killNotFound = true })
	st := mountVolume(h, "vm-a", "sfs-1", "/vol/a")
	st.seedWardenClient(agt)

	resp := h.handleKillExec(context.Background(), &pb.VMCommand{CommandId: "c1", AgentId: "agent-t"},
		&pb.KillExec{SandfsId: "sfs-1", ExecId: "bg-missing"})
	if !resp.Success || resp.Status != "not_found" {
		t.Fatalf("kill of unknown exec must report not_found, got %+v ", resp)
	}

	// Control: the success path still answers "killed".
	okWarden, _ := newFakeWardenClient(t, nil)
	st.seedWardenClient(okWarden)
	resp = h.handleKillExec(context.Background(), &pb.VMCommand{CommandId: "c2", AgentId: "agent-t"},
		&pb.KillExec{SandfsId: "sfs-1", ExecId: "bg-1"})
	if !resp.Success || resp.Status != "killed" {
		t.Fatalf("control kill must answer killed, got %+v", resp)
	}
}

// TestColdMountSetFsFailureDestroysVM pins the fail-closed set-fs rule on the mount path: a
// failed vm.set-fs must never leave the VM reusable — the VMM's exported
// set is uncertain (a timed-out update can apply late), so the only sound
// action is destroy + replace, mirroring the unmount clear path.
func TestColdMountSetFsFailureDestroysVM(t *testing.T) {
	h := newCoreTestHandler()
	st := mountVolume(h, "vm-a", "sfs-1", "")
	// A dead VMM socket makes the allowed_dirs swap fail.
	st.VM.Client = vmm.NewClient(filepath.Join(t.TempDir(), "missing-sandvmm.sock"))

	resp := h.handleMountRootfsAndExecute(context.Background(), &pb.VMCommand{CommandId: "c1", AgentId: "agent-t"},
		&pb.MountRootfsAndExecute{
			VolumeMode: "flat", SandfsId: "sfs-1", VolumePath: "/vol/x", Command: "true", TimeoutMs: 1000})
	if resp.Success {
		t.Fatalf("set-fs failure must fail the cold mount, got success: %+v", resp)
	}
	if !st.pendingDestroy.Load() {
		t.Fatal("VM must be dirty-destroyed after a failed set-fs")
	}
}

// TestColdMountStaleGenerationDoesNotDestroyVM pins the classification rule
// for a mount RPC that lost the generation race: an unmount/clear lands while
// the mount is queued, the warden answers mount_target_not_exported, and the
// stale request must fail WITHOUT destroying the VM (which may now be serving
// another tenant).
func TestColdMountStaleGenerationDoesNotDestroyVM(t *testing.T) {
	h := newCoreTestHandler()
	hold := make(chan struct{})
	fw := &fakeWarden{mountErrCode: 7, mountHold: hold} // 7 = target not exported
	st := mountVolume(h, "vm-a", "sfs-1", "")
	st.execSlots.Store(2) // the parked mount + the unmount need separate slots
	st.seedWardenClient(dialFake(t, fw))
	h.testDialFn = func(cid uint32, timeout time.Duration) (*warden.Client, error) {
		return dialFake(t, fw), nil
	}

	done := make(chan *pb.CommandResponse, 1)
	go func() {
		done <- h.handleMountRootfsAndExecute(context.Background(),
			&pb.VMCommand{CommandId: "c1", AgentId: "agent-t"},
			&pb.MountRootfsAndExecute{
				VolumeMode: "flat", SandfsId: "sfs-1", VolumePath: "/vol/x",
				Command: "true", TimeoutMs: 1000})
	}()

	// Wait until the mount RPC is parked in the fake warden.
	deadline := time.Now().Add(5 * time.Second)
	for {
		fw.mu.Lock()
		parked := false
		for _, op := range fw.ops {
			if op == fakeOpMountAndExec {
				parked = true
			}
		}
		fw.mu.Unlock()
		if parked {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("mount RPC never reached the fake warden")
		}
		time.Sleep(5 * time.Millisecond)
	}

	// Supersede the generation while the mount is queued.
	uresp := h.handleUnmountRootfs(context.Background(),
		&pb.VMCommand{CommandId: "u1", AgentId: "agent-t"},
		&pb.UnmountRootfs{SandfsId: "sfs-1", VolumePath: "/vol/x"})
	if !uresp.Success {
		t.Fatalf("interleaved unmount failed: %+v", uresp)
	}
	close(hold)

	resp := <-done
	if resp.Success {
		t.Fatalf("superseded mount must fail, got %+v", resp)
	}
	if st.pendingDestroy.Load() || st.dirtyDestroyScheduled.Load() {
		t.Fatal("a superseded mount must NOT destroy the VM")
	}
}

// TestUnmountIdentityMismatchLeavesLiveMount pins the tri-state unmount: a
// stale sandfs binding naming a generation the warden does not hold must drop
// only that binding, never the live mount or filter.
func TestUnmountIdentityMismatchLeavesLiveMount(t *testing.T) {
	h := newCoreTestHandler()
	agt, _ := newFakeWardenClient(t, func(f *fakeWarden) {
		f.unmountCode = 9 // CODE_UNMOUNT_MISMATCH
		f.unmountMounted = "other-generation-alias"
	})
	st := mountVolume(h, "vm-a", "sfs-1", "/vol/a")
	st.seedWardenClient(agt)

	resp := h.handleUnmountRootfs(context.Background(),
		&pb.VMCommand{CommandId: "u1", AgentId: "agent-t"},
		&pb.UnmountRootfs{SandfsId: "sfs-1", VolumePath: "/vol/a"})
	if !resp.Success {
		t.Fatalf("mismatched unmount must answer success to the gateway, got %+v", resp)
	}
	if h.vmForSandfs("sfs-1") != nil {
		t.Fatal("the stale binding must be dropped")
	}
	st.mountMu.Lock()
	defer st.mountMu.Unlock()
	if _, ok := st.Volumes["/vol/a"]; !ok {
		t.Fatal("the live mount must remain tracked")
	}
	if st.mountIdentity != "alias-sfs-1" {
		t.Fatalf("live identity changed to %q — the mismatched unmount tore down the wrong mount", st.mountIdentity)
	}
	if st.pendingDestroy.Load() {
		t.Fatal("a mismatched unmount must not destroy the VM")
	}
}

// TestColdMountTransportErrorDestroysVM pins the mount-state rule: a transport-class failure
// on the combined mount RPC does NOT prove the guest mount did not happen.
// Volumes was never set and the binding is dropped, so the gateway's later
// unmount would be a no-op; the VM must be destroyed instead of leaving an
// untracked mount that could be double-placed.
func TestColdMountTransportErrorDestroysVM(t *testing.T) {
	h := newCoreTestHandler()
	agt, _ := newFakeWardenClient(t, func(f *fakeWarden) { f.mountErrCode = 2 }) // CODE_TRANSPORT_ERROR
	st := mountVolume(h, "vm-a", "sfs-1", "")
	st.seedWardenClient(agt)

	resp := h.handleMountRootfsAndExecute(context.Background(), &pb.VMCommand{CommandId: "c1", AgentId: "agent-t"},
		&pb.MountRootfsAndExecute{
			VolumeMode: "flat", SandfsId: "sfs-1", VolumePath: "/vol/x", Command: "true", TimeoutMs: 1000})
	if resp.Success {
		t.Fatalf("transport error must fail the cold mount, got success: %+v", resp)
	}
	if !st.pendingDestroy.Load() {
		t.Fatal("VM must be dirty-destroyed after a mount transport error")
	}
}

// TestJoinerMismatchKeepsCreatorBinding pins the join rule: a request that
// does not own the in-flight generation must not clear the shared sandfs→VM
// binding on its way out; the creator still needs it when its mount lands.
func TestJoinerMismatchKeepsCreatorBinding(t *testing.T) {
	h := newTestHandler()
	st := &VMState{
		VM: &vmm.RunningVM{ID: "vm-1", GuestCID: 1 << 20},
		pendingMount: &pendingMount{
			sandfsID: "sf-a", volumePath: "/vol/a", alias: "gen-1", gen: 1,
			agentID: "agent-a", templateRef: "", volumeMode: "flat", volumeEpoch: "e1",
		},
	}
	h.bindSandfs("sf-a", "vm-1")

	_, _, _, err := h.ensureSwitchReady(context.Background(), st, "agent-b", "sf-a", "/vol/a", "", "flat", "e1")
	if err == nil {
		t.Fatal("a mismatched joiner was accepted")
	}
	if got, _ := h.bindings.lookup("sf-a"); got != "vm-1" {
		t.Fatalf("joiner failure cleared the creator's binding (got %q)", got)
	}
}

// TestFileOpJoinerMismatchKeepsCreatorBinding is the same rule on the file
// path: the join tuple includes agent/template/mode/epoch, and a mismatch
// leaves the creator's binding intact.
func TestFileOpJoinerMismatchKeepsCreatorBinding(t *testing.T) {
	h := newTestHandler()
	st := &VMState{
		VM: &vmm.RunningVM{ID: "vm-1", GuestCID: 1 << 20},
		pendingMount: &pendingMount{
			sandfsID: "sf-a", volumePath: "/vol/a", alias: "gen-1", gen: 1,
			agentID: "agent-a", templateRef: "", volumeMode: "flat", volumeEpoch: "e1",
		},
	}
	h.bindSandfs("sf-a", "vm-1")

	err := h.ensureMounted(context.Background(), st, "agent-b", "sf-a", "/vol/a", "", "flat", "e1")
	if err == nil {
		t.Fatal("a mismatched file-op joiner was accepted")
	}
	if got, _ := h.bindings.lookup("sf-a"); got != "vm-1" {
		t.Fatalf("file-op joiner failure cleared the creator's binding (got %q)", got)
	}
}

// TestUnmountStalePathIsIdempotentNoOp pins the generation binding: an
// unmount naming a volume the sandfs is no longer bound to is a superseded
// generation and must not touch the live tenant's mount or call the warden.
func TestUnmountStalePathIsIdempotentNoOp(t *testing.T) {
	h := newCoreTestHandler()
	agt, fw := newFakeWardenClient(t, nil)
	st := mountVolume(h, "vm-a", "sfs-1", "/vol/a")
	st.seedWardenClient(agt)

	resp := h.handleUnmountRootfs(context.Background(),
		&pb.VMCommand{CommandId: "u1", AgentId: "agent-t"},
		&pb.UnmountRootfs{SandfsId: "sfs-1", VolumePath: "/vol/b"})
	if !resp.Success {
		t.Fatalf("stale-path unmount must be an idempotent success: %+v", resp)
	}
	if _, ok := st.Volumes["/vol/a"]; !ok {
		t.Fatal("stale-path unmount tore down the live mount")
	}
	if st.mountIdentity != "alias-sfs-1" {
		t.Fatalf("live identity changed to %q", st.mountIdentity)
	}
	for _, op := range fw.recordedOps() {
		if op == fakeOpUnmount {
			t.Fatal("stale-path unmount called the warden")
		}
	}
}

// TestUnmountStaleEpochIsIdempotentNoOp is the epoch half of the same rule.
func TestUnmountStaleEpochIsIdempotentNoOp(t *testing.T) {
	h := newCoreTestHandler()
	agt, fw := newFakeWardenClient(t, nil)
	st := mountVolume(h, "vm-a", "sfs-1", "/vol/a")
	st.seedWardenClient(agt)
	if st.mountEpochBySandfs == nil {
		st.mountEpochBySandfs = make(map[string]string)
	}
	st.mountEpochBySandfs["sfs-1"] = "epoch-new"

	resp := h.handleUnmountRootfs(context.Background(),
		&pb.VMCommand{CommandId: "u1", AgentId: "agent-t"},
		&pb.UnmountRootfs{SandfsId: "sfs-1", VolumePath: "/vol/a", VolumeEpoch: "epoch-old"})
	if !resp.Success {
		t.Fatalf("stale-epoch unmount must be an idempotent success: %+v", resp)
	}
	if _, ok := st.Volumes["/vol/a"]; !ok {
		t.Fatal("stale-epoch unmount tore down the live mount")
	}
	for _, op := range fw.recordedOps() {
		if op == fakeOpUnmount {
			t.Fatal("stale-epoch unmount called the warden")
		}
	}
}

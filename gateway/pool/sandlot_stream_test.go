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
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"log"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"

	pb "common/proto/stream"
	"gateway/pool"
	"gateway/stream"
)

// -----------------------------------------------------------------------
// fakeConnectStream: a test double for pb.NodeStream_ConnectServer
// (grpc.BidiStreamingServer[NodeMessage, GatewayMessage]). It records every
// message the gateway Sends (HelloAck + VMCommands) and lets the test script
// inbound messages (responses) via recvCh. Modeled on the fakeStream in
// gateway/stream/server_test.go (internal test), replicated here because that
// type is package-private.
// -----------------------------------------------------------------------

type fakeConnectStream struct {
	mu     sync.Mutex
	sent   []*pb.GatewayMessage
	recvCh chan *pb.NodeMessage
	ctx    context.Context
	cancel context.CancelFunc
}

// newFakeConnectStream returns a fake stream whose Context carries a TLS peer
// certificate with CN == nodeID — the shape the gateway's node-identity gate
// requires (a credential-less stream is refused by name).
func newFakeConnectStream(nodeID string) *fakeConnectStream {
	leaf := &x509.Certificate{Subject: pkix.Name{CommonName: nodeID}}
	// The gateway binds stream roles to the certificate: a per-node pair
	// grants the roles its URI SANs name. These tests drive exec commands,
	// and the merged shape (exec+prov) is the common fleet certificate.
	for _, r := range []string{"exec", "prov"} {
		u, err := url.Parse("sandswap://role/" + r)
		if err != nil {
			panic(err)
		}
		leaf.URIs = append(leaf.URIs, u)
	}
	info := credentials.TLSInfo{State: tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}}
	base := peer.NewContext(context.Background(), &peer.Peer{AuthInfo: info})
	ctx, cancel := context.WithCancel(base)
	return &fakeConnectStream{
		recvCh: make(chan *pb.NodeMessage, 16),
		ctx:    ctx,
		cancel: cancel,
	}
}

func (f *fakeConnectStream) Recv() (*pb.NodeMessage, error) {
	select {
	case m, ok := <-f.recvCh:
		if !ok {
			return nil, io.EOF
		}
		return m, nil
	case <-f.ctx.Done():
		return nil, f.ctx.Err()
	}
}

func (f *fakeConnectStream) Send(msg *pb.GatewayMessage) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, msg)
	return nil
}

func (f *fakeConnectStream) sentMessages() []*pb.GatewayMessage {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]*pb.GatewayMessage, len(f.sent))
	copy(out, f.sent)
	return out
}

// sentCommands returns only the VMCommand messages (skips the initial HelloAck).
func (f *fakeConnectStream) sentCommands() []*pb.VMCommand {
	out := [](*pb.VMCommand){}
	for _, m := range f.sentMessages() {
		if cmd := m.GetVmCommand(); cmd != nil {
			out = append(out, cmd)
		}
	}
	return out
}

// ServerStream / BidiStreamingServer methods.
func (f *fakeConnectStream) Context() context.Context     { return f.ctx }
func (f *fakeConnectStream) SetHeader(metadata.MD) error  { return nil }
func (f *fakeConnectStream) SendHeader(metadata.MD) error { return nil }
func (f *fakeConnectStream) SetTrailer(metadata.MD)       {}
func (f *fakeConnectStream) SendMsg(m any) error          { return f.Send(m.(*pb.GatewayMessage)) }
func (f *fakeConnectStream) RecvMsg(m any) error {
	msg, err := f.Recv()
	if err != nil {
		return err
	}
	*(m.(**pb.NodeMessage)) = msg
	return nil
}

// close terminates the fake stream: cancel wakes any blocked Recv, and closing
// recvCh drives the readLoop into its removeNode path.
func (f *fakeConnectStream) close() {
	f.cancel()
	close(f.recvCh)
}

// startFakeNode creates a stream.Server, registers a sandlot node via a fake
// stream, and returns the fake stream + a done channel (receives Connect's
// return error). The caller MUST defer fs.close() and drain done (or defer
// waitForConnectDone) to avoid goroutine leaks.
func startFakeNode(t *testing.T, nodeID string) (*stream.Server, *fakeConnectStream, chan error) {
	t.Helper()
	srv := stream.NewServer("gw-test", log.New(io.Discard, "", 0), 0, 0)
	fs := newFakeConnectStream(nodeID)
	fs.recvCh <- &pb.NodeMessage{
		NodeId: nodeID,
		Payload: &pb.NodeMessage_Hello{Hello: &pb.NodeHello{
			NodeId: nodeID, Version: "test",
			// Real sandlots set this (rpc.ProtocolVersion); without it the
			// gateway's handshake version gate rejects the connect.
			ProtocolVersion: 1,
		}},
	}
	done := make(chan error, 1)
	go func() { done <- srv.Connect(fs) }()
	// Wait for registration.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := srv.GetNode(nodeID); err == nil {
			return srv, fs, done
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("node %q never registered", nodeID)
	return nil, nil, nil
}

// waitForConnectDone waits up to 2s for Connect to return after the fake stream
// is closed. Bounded to surface goroutine leaks as failures.
func waitForConnectDone(t *testing.T, done chan error, what string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for Connect to return: %s", what)
	}
}

// waitForCommand polls until at least one VMCommand appears in the fake
// stream's sent messages, then returns the most recent one.
func waitForCommand(t *testing.T, fs *fakeConnectStream) *pb.VMCommand {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cmds := fs.sentCommands(); len(cmds) > 0 {
			return cmds[len(cmds)-1]
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("no VMCommand sent on the stream")
	return nil
}

// waitForNewCommand polls until a command with an UNSEEN CommandId appears. The
// plain waitForCommand returns the most recent command immediately when the
// stream already carries an earlier one, which collides when firing multiple
// RPCs sequentially (TestStreamCommandIdUnique): the second wait would grab the
// first command again and respond to an already-returned call.
func waitForNewCommand(t *testing.T, fs *fakeConnectStream, seen map[string]bool) *pb.VMCommand {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		for _, c := range fs.sentCommands() {
			if !seen[c.CommandId] {
				return c
			}
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("no new VMCommand sent on the stream")
	return nil
}

// respondToCommand queues a CommandResponse matching the command's ID on the
// fake stream's recvCh. The readLoop picks it up and delivers it to the
// waiting StreamSandlotClient caller.
func respondToCommand(fs *fakeConnectStream, cmd *pb.VMCommand, resp *pb.CommandResponse) {
	resp.CommandId = cmd.CommandId
	fs.recvCh <- &pb.NodeMessage{
		Payload: &pb.NodeMessage_Response{Response: resp},
	}
}

// -----------------------------------------------------------------------
// StreamSandlotClient: command building + response mapping, using a fake
// gRPC stream (no real transport). Each test starts a fake node, calls the
// client method (which blocks on the response), captures the VMCommand sent,
// asserts its shape, then queues a response and asserts the result mapping.
// -----------------------------------------------------------------------

// TestStreamMountRootfsAndExecuteSync verifies the sync-exec command shape:
// all ExecRequest fields map to the right proto fields, and the CommandResponse
// maps back to ExecResult correctly.
func TestStreamMountRootfsAndExecuteSync(t *testing.T) {
	srv, fs, done := startFakeNode(t, "node-1")
	defer waitForConnectDone(t, done, "disconnect after sync exec")
	defer fs.close()

	client := pool.NewStreamSandlotClient(srv)
	req := pool.ExecRequest{
		NodeAddr:        "node-1",
		SandfsID:        "sandfs-abc",
		VolumePath:      "/vol/sandfs-abc",
		Command:         "python main.py",
		Background:      false,
		TimeoutMs:       30000,
		LeaseDurationMs: 0,
		InstallPackages: true,
		MinSpec:         "medium",
	}

	type outcome struct {
		res pool.ExecResult
		err error
	}
	outCh := make(chan outcome, 1)
	go func() {
		res, err := client.MountRootfsAndExecute(context.Background(), req)
		outCh <- outcome{res, err}
	}()

	cmd := waitForCommand(t, fs)

	// Assert command type + all fields.
	m := cmd.GetMountRootfsAndExecute()
	if m == nil {
		t.Fatalf("expected MountRootfsAndExecute action, got %T", cmd.Action)
	}
	if m.SandfsId != "sandfs-abc" {
		t.Errorf("SandfsId: got %q, want sandfs-abc", m.SandfsId)
	}
	if m.VolumePath != "/vol/sandfs-abc" {
		t.Errorf("VolumePath: got %q, want /vol/sandfs-abc", m.VolumePath)
	}
	if m.Command != "python main.py" {
		t.Errorf("Command: got %q, want python main.py", m.Command)
	}
	if m.Background {
		t.Error("Background: got true, want false")
	}
	if m.TimeoutMs != 30000 {
		t.Errorf("TimeoutMs: got %d, want 30000", m.TimeoutMs)
	}
	if m.LeaseDurationMs != 0 {
		t.Errorf("LeaseDurationMs: got %d, want 0", m.LeaseDurationMs)
	}
	if !m.InstallPackages {
		t.Error("InstallPackages: got false, want true")
	}
	if m.MinSpec != "medium" {
		t.Errorf("MinSpec: got %q, want medium", m.MinSpec)
	}
	if cmd.CommandId == "" {
		t.Error("CommandId should be non-empty (uuid)")
	}

	// Respond and assert result mapping.
	respondToCommand(fs, cmd, &pb.CommandResponse{
		Success:           true,
		Stdout:            "hello world",
		Stderr:            "warnings",
		ExitCode:          0,
		Status:            "done",
		ExecDurationNs:    1500000,
		SandlotDurationNs: 2100000,
	})

	select {
	case o := <-outCh:
		if o.err != nil {
			t.Fatalf("MountRootfsAndExecute: %v", o.err)
		}
		if o.res.Stdout != "hello world" {
			t.Errorf("Stdout: got %q, want hello world", o.res.Stdout)
		}
		if o.res.Stderr != "warnings" {
			t.Errorf("Stderr: got %q, want warnings", o.res.Stderr)
		}
		if o.res.ExitCode != 0 {
			t.Errorf("ExitCode: got %d, want 0", o.res.ExitCode)
		}
		if o.res.Status != "done" {
			t.Errorf("Status: got %q, want done", o.res.Status)
		}
		if o.res.ExecDurationNs != 1500000 {
			t.Errorf("ExecDurationNs: got %d, want 1500000", o.res.ExecDurationNs)
		}
		if o.res.SandlotDurationNs != 2100000 {
			t.Errorf("SandlotDurationNs: got %d, want 2100000", o.res.SandlotDurationNs)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("MountRootfsAndExecute did not return after response")
	}
}

// TestStreamMountRootfsAndExecuteBackground verifies background=true produces
// the right command + maps the ExecID/Status="running" response.
func TestStreamMountRootfsAndExecuteBackground(t *testing.T) {
	srv, fs, done := startFakeNode(t, "node-1")
	defer waitForConnectDone(t, done, "disconnect after bg exec")
	defer fs.close()

	client := pool.NewStreamSandlotClient(srv)
	req := pool.ExecRequest{
		NodeAddr:        "node-1",
		SandfsID:        "sandfs-bg",
		VolumePath:      "/vol/sandfs-bg",
		Command:         "train.py",
		Background:      true,
		TimeoutMs:       0,
		LeaseDurationMs: 300000,
		MinSpec:         "large",
	}

	outCh := make(chan struct {
		res pool.ExecResult
		err error
	}, 1)
	go func() {
		res, err := client.MountRootfsAndExecute(context.Background(), req)
		outCh <- struct {
			res pool.ExecResult
			err error
		}{res, err}
	}()

	cmd := waitForCommand(t, fs)
	m := cmd.GetMountRootfsAndExecute()
	if m == nil {
		t.Fatalf("expected MountRootfsAndExecute action, got %T", cmd.Action)
	}
	if !m.Background {
		t.Error("Background: got false, want true")
	}
	if m.LeaseDurationMs != 300000 {
		t.Errorf("LeaseDurationMs: got %d, want 300000", m.LeaseDurationMs)
	}
	if m.MinSpec != "large" {
		t.Errorf("MinSpec: got %q, want large", m.MinSpec)
	}

	respondToCommand(fs, cmd, &pb.CommandResponse{
		Success: true,
		ExecId:  "bg-xyz",
		Status:  "running",
	})

	select {
	case o := <-outCh:
		if o.err != nil {
			t.Fatalf("MountRootfsAndExecute bg: %v", o.err)
		}
		if o.res.ExecID != "bg-xyz" {
			t.Errorf("ExecID: got %q, want bg-xyz", o.res.ExecID)
		}
		if o.res.Status != "running" {
			t.Errorf("Status: got %q, want running", o.res.Status)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("background exec did not return")
	}
}

// TestStreamUnmountRootfs verifies the unmount command shape + nil on success.
func TestStreamUnmountRootfs(t *testing.T) {
	srv, fs, done := startFakeNode(t, "node-1")
	defer waitForConnectDone(t, done, "disconnect after unmount")
	defer fs.close()

	client := pool.NewStreamSandlotClient(srv)

	errCh := make(chan error, 1)
	go func() {
		_, err := client.UnmountRootfs(context.Background(), "node-1", "sandfs-u", "/vol/sandfs-u", "")
		errCh <- err
	}()

	cmd := waitForCommand(t, fs)
	u := cmd.GetUnmountRootfs()
	if u == nil {
		t.Fatalf("expected UnmountRootfs action, got %T", cmd.Action)
	}
	if u.SandfsId != "sandfs-u" {
		t.Errorf("SandfsId: got %q, want sandfs-u", u.SandfsId)
	}
	if u.VolumePath != "/vol/sandfs-u" {
		t.Errorf("VolumePath: got %q, want /vol/sandfs-u", u.VolumePath)
	}

	respondToCommand(fs, cmd, &pb.CommandResponse{Success: true})
	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("UnmountRootfs: got %v, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("UnmountRootfs did not return")
	}
}

// TestStreamStatusExec verifies the status_exec command shape + ExecResult
// mapping. Note: ExecID in the result echoes the INPUT exec_id, not the
// response's ExecId (the status poll echoes what was asked).
func TestStreamStatusExec(t *testing.T) {
	srv, fs, done := startFakeNode(t, "node-1")
	defer waitForConnectDone(t, done, "disconnect after status")
	defer fs.close()

	client := pool.NewStreamSandlotClient(srv)

	outCh := make(chan struct {
		res pool.ExecResult
		err error
	}, 1)
	go func() {
		res, err := client.StatusExec(context.Background(), "node-1", "sandfs-s", "bg-42")
		outCh <- struct {
			res pool.ExecResult
			err error
		}{res, err}
	}()

	cmd := waitForCommand(t, fs)
	s := cmd.GetStatusExec()
	if s == nil {
		t.Fatalf("expected StatusExec action, got %T", cmd.Action)
	}
	if s.SandfsId != "sandfs-s" {
		t.Errorf("SandfsId: got %q, want sandfs-s", s.SandfsId)
	}
	if s.ExecId != "bg-42" {
		t.Errorf("ExecId: got %q, want bg-42", s.ExecId)
	}

	respondToCommand(fs, cmd, &pb.CommandResponse{
		Success:  true,
		Status:   "done",
		Stdout:   "log tail",
		ExitCode: 0,
	})
	select {
	case o := <-outCh:
		if o.err != nil {
			t.Fatalf("StatusExec: %v", o.err)
		}
		if o.res.ExecID != "bg-42" {
			t.Errorf("ExecID: got %q, want bg-42 (echoes input)", o.res.ExecID)
		}
		if o.res.Status != "done" {
			t.Errorf("Status: got %q, want done", o.res.Status)
		}
		if o.res.Stdout != "log tail" {
			t.Errorf("Stdout: got %q, want log tail", o.res.Stdout)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("StatusExec did not return")
	}
}

// TestStreamKillExec verifies the kill_exec command shape + nil on success.
func TestStreamKillExec(t *testing.T) {
	srv, fs, done := startFakeNode(t, "node-1")
	defer waitForConnectDone(t, done, "disconnect after kill")
	defer fs.close()

	client := pool.NewStreamSandlotClient(srv)

	errCh := make(chan error, 1)
	go func() {
		errCh <- client.KillExec(context.Background(), "node-1", "sandfs-k", "bg-99")
	}()

	cmd := waitForCommand(t, fs)
	k := cmd.GetKillExec()
	if k == nil {
		t.Fatalf("expected KillExec action, got %T", cmd.Action)
	}
	if k.SandfsId != "sandfs-k" {
		t.Errorf("SandfsId: got %q, want sandfs-k", k.SandfsId)
	}
	if k.ExecId != "bg-99" {
		t.Errorf("ExecId: got %q, want bg-99", k.ExecId)
	}

	respondToCommand(fs, cmd, &pb.CommandResponse{Success: true})
	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("KillExec: got %v, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("KillExec did not return")
	}
}

// TestStreamFileOp verifies the file_op command carries ALL FileOpRequest
// fields and the response maps FileOpResult correctly (StdoutRaw precedence).
func TestStreamFileOp(t *testing.T) {
	srv, fs, done := startFakeNode(t, "node-1")
	defer waitForConnectDone(t, done, "disconnect after fileop")
	defer fs.close()

	client := pool.NewStreamSandlotClient(srv)
	fileData := []byte("file content here")
	req := pool.FileOpRequest{
		SandfsID:   "sandfs-f",
		Action:     "write",
		Path:       "data/out.txt",
		NewPath:    "",
		Offset:     0,
		Length:     0,
		Mode:       0644,
		Recursive:  false,
		Depth:      0,
		Data:       fileData,
		VolumePath: "/vol/sandfs-f",
		MinSpec:    "medium",
	}

	outCh := make(chan struct {
		res pool.FileOpResult
		err error
	}, 1)
	go func() {
		res, err := client.FileOp(context.Background(), "node-1", req)
		outCh <- struct {
			res pool.FileOpResult
			err error
		}{res, err}
	}()

	cmd := waitForCommand(t, fs)
	f := cmd.GetFileOp()
	if f == nil {
		t.Fatalf("expected FileOp action, got %T", cmd.Action)
	}
	if f.SandfsId != "sandfs-f" {
		t.Errorf("SandfsId: got %q, want sandfs-f", f.SandfsId)
	}
	if f.Action != "write" {
		t.Errorf("Action: got %q, want write", f.Action)
	}
	if f.Path != "data/out.txt" {
		t.Errorf("Path: got %q, want data/out.txt", f.Path)
	}
	if f.Mode != 0644 {
		t.Errorf("Mode: got %d, want 0644", f.Mode)
	}
	if string(f.Data) != "file content here" {
		t.Errorf("Data: got %q, want file content here", string(f.Data))
	}
	if f.VolumePath != "/vol/sandfs-f" {
		t.Errorf("VolumePath: got %q, want /vol/sandfs-f", f.VolumePath)
	}
	if f.MinSpec != "medium" {
		t.Errorf("MinSpec: got %q, want medium", f.MinSpec)
	}

	// FileOp success: ExitCode=0 means status 0.
	respondToCommand(fs, cmd, &pb.CommandResponse{Success: true, ExitCode: 0})
	select {
	case o := <-outCh:
		if o.err != nil {
			t.Fatalf("FileOp: %v", o.err)
		}
		if !o.res.Success {
			t.Errorf("Success: got false, want true")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("FileOp did not return")
	}
}

// TestStreamFileOpStdoutRawPrecedence verifies that when both StdoutRaw and
// Stdout are set, StdoutRaw takes precedence (binary-safe path).
func TestStreamFileOpStdoutRawPrecedence(t *testing.T) {
	srv, fs, done := startFakeNode(t, "node-1")
	defer waitForConnectDone(t, done, "disconnect after fileop raw")
	defer fs.close()

	client := pool.NewStreamSandlotClient(srv)
	req := pool.FileOpRequest{
		SandfsID: "sandfs-r",
		Action:   "read",
		Path:     "data.bin",
	}

	outCh := make(chan struct {
		res pool.FileOpResult
		err error
	}, 1)
	go func() {
		res, err := client.FileOp(context.Background(), "node-1", req)
		outCh <- struct {
			res pool.FileOpResult
			err error
		}{res, err}
	}()

	cmd := waitForCommand(t, fs)
	// Both fields set: StdoutRaw wins.
	respondToCommand(fs, cmd, &pb.CommandResponse{
		Success:   true,
		Stdout:    "fallback string",
		StdoutRaw: []byte{0x00, 0x01, 0xFF, 0x42},
	})
	select {
	case o := <-outCh:
		if o.err != nil {
			t.Fatalf("FileOp: %v", o.err)
		}
		if string(o.res.Data) != string([]byte{0x00, 0x01, 0xFF, 0x42}) {
			t.Errorf("Data: got %v, want binary [0x00 0x01 0xFF 0x42]", o.res.Data)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("FileOp did not return")
	}
}

// TestStreamFileOpStdoutFallback verifies that when StdoutRaw is empty but
// Stdout is set, the client falls back to Stdout (backward compat with older
// sandlots that don't set StdoutRaw).
func TestStreamFileOpStdoutFallback(t *testing.T) {
	srv, fs, done := startFakeNode(t, "node-1")
	defer waitForConnectDone(t, done, "disconnect after fileop fallback")
	defer fs.close()

	client := pool.NewStreamSandlotClient(srv)
	req := pool.FileOpRequest{SandfsID: "sandfs-fb", Action: "read", Path: "text.txt"}

	outCh := make(chan struct {
		res pool.FileOpResult
		err error
	}, 1)
	go func() {
		res, err := client.FileOp(context.Background(), "node-1", req)
		outCh <- struct {
			res pool.FileOpResult
			err error
		}{res, err}
	}()

	cmd := waitForCommand(t, fs)
	respondToCommand(fs, cmd, &pb.CommandResponse{
		Success: true,
		Stdout:  "plain text content",
	})
	select {
	case o := <-outCh:
		if o.err != nil {
			t.Fatalf("FileOp: %v", o.err)
		}
		if string(o.res.Data) != "plain text content" {
			t.Errorf("Data: got %q, want plain text content", string(o.res.Data))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("FileOp did not return")
	}
}

// TestStreamCleanupOverlay verifies the cleanup_overlay command shape.
func TestStreamCleanupOverlay(t *testing.T) {
	srv, fs, done := startFakeNode(t, "node-1")
	defer waitForConnectDone(t, done, "disconnect after cleanup")
	defer fs.close()

	client := pool.NewStreamSandlotClient(srv)

	errCh := make(chan error, 1)
	go func() {
		errCh <- client.CleanupOverlay(context.Background(), "node-1", "/vol/sandfs-co")
	}()

	cmd := waitForCommand(t, fs)
	co := cmd.GetCleanupOverlay()
	if co == nil {
		t.Fatalf("expected CleanupOverlay action, got %T", cmd.Action)
	}
	if co.VolumePath != "/vol/sandfs-co" {
		t.Errorf("VolumePath: got %q, want /vol/sandfs-co", co.VolumePath)
	}

	respondToCommand(fs, cmd, &pb.CommandResponse{Success: true})
	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("CleanupOverlay: got %v, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("CleanupOverlay did not return")
	}
}

// -----------------------------------------------------------------------
// Error paths: node not connected, command failed, context cancelled.
// -----------------------------------------------------------------------

// TestStreamMountRootfsNodeNotConnected verifies GetNode failure returns a
// descriptive error (no hang, no goroutine leak).
func TestStreamMountRootfsNodeNotConnected(t *testing.T) {
	srv, fs, done := startFakeNode(t, "node-1")
	defer waitForConnectDone(t, done, "disconnect")
	defer fs.close()

	client := pool.NewStreamSandlotClient(srv)
	_, err := client.MountRootfsAndExecute(context.Background(), pool.ExecRequest{
		NodeAddr: "node-missing",
	})
	if err == nil {
		t.Fatal("expected error for missing node")
	}
}

// TestStreamUnmountRootfsCommandFailed verifies a failed response
// (Success=false) maps to an error with the response's Error field.
func TestStreamUnmountRootfsCommandFailed(t *testing.T) {
	srv, fs, done := startFakeNode(t, "node-1")
	defer waitForConnectDone(t, done, "disconnect after failed unmount")
	defer fs.close()

	client := pool.NewStreamSandlotClient(srv)

	errCh := make(chan error, 1)
	go func() {
		_, err := client.UnmountRootfs(context.Background(), "node-1", "s1", "/v/s1", "")
		errCh <- err
	}()

	cmd := waitForCommand(t, fs)
	respondToCommand(fs, cmd, &pb.CommandResponse{
		Success: false,
		Error:   "warden: umount EBUSY",
	})
	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("expected error for failed command")
		}
		if !errors.Is(err, err) { // sanity: non-nil error
			t.Error("err should be non-nil")
		}
		// The error message should include the sandlot-side error.
		if !strings.Contains(err.Error(), "warden: umount EBUSY") {
			t.Errorf("error should contain 'warden: umount EBUSY', got: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("UnmountRootfs did not return after failed response")
	}
}

// TestStreamMountRootfsContextCancelled verifies context cancellation
// propagates as ctx.Err() and the call returns promptly.
func TestStreamMountRootfsContextCancelled(t *testing.T) {
	srv, fs, done := startFakeNode(t, "node-1")
	defer waitForConnectDone(t, done, "disconnect after cancel")
	defer fs.close()

	client := pool.NewStreamSandlotClient(srv)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := client.MountRootfsAndExecute(ctx, pool.ExecRequest{
		NodeAddr: "node-1",
		SandfsID: "s1",
	})
	if err == nil {
		t.Fatal("expected context deadline error")
	}
	// Should be context.DeadlineExceeded.
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("expected context.DeadlineExceeded, got: %v", err)
	}
}

// -----------------------------------------------------------------------
// Multi-command: verify CommandId is unique per call (no collision).
// -----------------------------------------------------------------------

// TestStreamCommandIdUnique verifies each RPC gets a unique CommandId (uuid),
// so the pending-response routing never collides.
func TestStreamCommandIdUnique(t *testing.T) {
	srv, fs, done := startFakeNode(t, "node-1")
	defer waitForConnectDone(t, done, "disconnect after multi-cmd")
	defer fs.close()

	client := pool.NewStreamSandlotClient(srv)

	// Fire two unmounts sequentially; each must get a distinct CommandId.
	seen := map[string]bool{}
	for i := 0; i < 2; i++ {
		errCh := make(chan error, 1)
		go func(idx int) {
			_, err := client.UnmountRootfs(context.Background(), "node-1",
				fmt.Sprintf("sandfs-%d", idx), fmt.Sprintf("/vol/%d", idx), "")
			errCh <- err
		}(i)

		cmd := waitForNewCommand(t, fs, seen)
		seen[cmd.CommandId] = true
		respondToCommand(fs, cmd, &pb.CommandResponse{Success: true})
		select {
		case err := <-errCh:
			if err != nil {
				t.Errorf("UnmountRootfs[%d]: %v", i, err)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("UnmountRootfs[%d] did not return", i)
		}
	}

	// Verify two distinct CommandIds.
	cmds := fs.sentCommands()
	if len(cmds) < 2 {
		t.Fatalf("expected >= 2 commands sent, got %d", len(cmds))
	}
	if cmds[0].CommandId == cmds[1].CommandId {
		t.Error("CommandIds should be unique per call")
	}
}

// Compile-time guard: StreamSandlotClient implements SandlotClient.
var _ pool.SandlotClient = (*pool.StreamSandlotClient)(nil)

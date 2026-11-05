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

package stream

import (
	"context"
	"errors"
	"io"
	"log"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/metadata"

	pb "common/proto/stream"
)

// fakeStream is a test double for pb.NodeStream_ConnectServer
// (grpc.BidiStreamingServer[NodeMessage, GatewayMessage]). It lets a test
// script a sandlot's inbound messages (Recv) and observe the gateway's outbound
// messages (Send) without a real gRPC transport.
//
// Recv behavior:
//   - A message queued on recvCh is returned in order.
//   - Closing recvCh makes Recv return io.EOF (sandlot called CloseSend /
//     disconnected cleanly) -> drives the readLoop into its removeNode path.
//   - Canceling ctx makes Recv return ctx.Err() (e.g. gateway shutdown).
type fakeStream struct {
	mu      sync.Mutex
	recvCh  chan *pb.NodeMessage
	sent    []*pb.GatewayMessage // messages the gateway Sent (HelloAck, VMCommand)
	sendErr error                // if set, Send returns this error (simulates a broken write side)
	ctx     context.Context
	cancel  context.CancelFunc
}

func newFakeStream() *fakeStream {
	ctx, cancel := context.WithCancel(context.Background())
	return &fakeStream{
		recvCh: make(chan *pb.NodeMessage, 16),
		ctx:    ctx,
		cancel: cancel,
	}
}

// newFakeStreamFor returns a fake stream whose Context carries a TLS peer
// certificate with CN == nodeID — the shape gRPC hands the handler after the
// mTLS handshake. The identity gate binds the hello's declared node_id to that
// CN, so every test that drives a full handshake must present a matching peer
// certificate; the certificate-less posture is a named refusal.
func newFakeStreamFor(nodeID string) *fakeStream {
	return newFakeStreamForRoles(nodeID, RoleExec, RoleProv)
}

// newFakeStreamForRoles presents a per-node certificate granting exactly the
// given role URI SANs.
func newFakeStreamForRoles(nodeID string, roles ...string) *fakeStream {
	ctx, cancel := context.WithCancel(peerCtxRoles(nodeID, roles...))
	return &fakeStream{
		recvCh: make(chan *pb.NodeMessage, 16),
		ctx:    ctx,
		cancel: cancel,
	}
}

func (f *fakeStream) Recv() (*pb.NodeMessage, error) {
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

func (f *fakeStream) Send(msg *pb.GatewayMessage) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.sendErr != nil {
		return f.sendErr
	}
	f.sent = append(f.sent, msg)
	return nil
}

// sentMessages returns a snapshot of what the gateway has Sent.
func (f *fakeStream) sentMessages() []*pb.GatewayMessage {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]*pb.GatewayMessage, len(f.sent))
	copy(out, f.sent)
	return out
}

func (f *fakeStream) Context() context.Context     { return f.ctx }
func (f *fakeStream) SetHeader(metadata.MD) error  { return nil }
func (f *fakeStream) SendHeader(metadata.MD) error { return nil }
func (f *fakeStream) SetTrailer(metadata.MD)       {}
func (f *fakeStream) SendMsg(m any) error          { return f.Send(m.(*pb.GatewayMessage)) }
func (f *fakeStream) RecvMsg(m any) error {
	msg, err := f.Recv()
	if err != nil {
		return err
	}
	*(m.(**pb.NodeMessage)) = msg
	return nil
}

// helloMsg builds a NodeMessage carrying a NodeHello.
func helloMsg(hello *pb.NodeHello) *pb.NodeMessage {
	return &pb.NodeMessage{NodeId: hello.NodeId, Payload: &pb.NodeMessage_Hello{Hello: hello}}
}

// startConnect queues a NodeHello on a fresh fakeStream and runs srv.Connect in
// a goroutine. It returns the fake stream and a buffered channel that receives
// Connect's return error when the stream terminates. The caller must arrange
// any OnConnect/OnDisconnect callbacks BEFORE calling this.
//
// A hello with no protocol version set gets the server's current version, so
// plain-connect tests pass the handshake gate; version-gate tests set their
// own (possibly invalid or zero) value explicitly BEFORE calling — any
// non-zero value is preserved.
func startConnect(t *testing.T, srv *Server, hello *pb.NodeHello) (*fakeStream, chan error) {
	t.Helper()
	if hello.GetProtocolVersion() == 0 {
		hello.ProtocolVersion = StreamProtocolVersion
	}
	fs := newFakeStreamFor(hello.NodeId)
	fs.recvCh <- helloMsg(hello)
	done := make(chan error, 1)
	go func() { done <- srv.Connect(fs) }()
	return fs, done
}

// waitForDone waits up to 2s for Connect to return; it does not assert on the
// error value (callers that care inspect done themselves). It exists to bound
// test runtime and surface goroutine leaks as a clear failure.
func waitForDone(t *testing.T, done chan error, what string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for Connect to return: %s", what)
	}
}

// silentLogger discards all gateway log output during tests.
func silentLogger() *log.Logger { return log.New(io.Discard, "", 0) }

// -------------------------------------------------------------------
// NewServer
// -------------------------------------------------------------------

// TestNewServer verifies NewServer creates an empty registry and stores the
// gateway identity. A nil logger must fall back to log.Default() (the ownership
// tests rely on NewServer not panicking on a nil logger).
func TestNewServer(t *testing.T) {
	t.Run("nil_logger_falls_back_to_default", func(t *testing.T) {
		srv := NewServer("gw-1", nil, 0, 0)
		if srv.gatewayID != "gw-1" {
			t.Errorf("gatewayID: got %q, want gw-1", srv.gatewayID)
		}
		if srv.logger == nil {
			t.Error("logger: expected non-nil (log.Default fallback)")
		}
		if srv.sendBufferSize != 64 {
			t.Errorf("sendBufferSize: got %d, want 64 (default)", srv.sendBufferSize)
		}
		if srv.writeTimeout != 30*time.Second {
			t.Errorf("writeTimeout: got %v, want 30s (default)", srv.writeTimeout)
		}
		if got := srv.Nodes(); len(got) != 0 {
			t.Errorf("new server should have no nodes, got %v", got)
		}
		if _, err := srv.GetNode("any"); !errors.Is(err, ErrNodeNotFound) {
			t.Errorf("GetNode on empty registry: got %v, want ErrNodeNotFound", err)
		}
	})

	t.Run("explicit_logger", func(t *testing.T) {
		lg := silentLogger()
		srv := NewServer("gw-2", lg, 2000, 10*time.Second)
		if srv.logger != lg {
			t.Error("explicit logger not stored")
		}
		if srv.sendBufferSize != 2000 {
			t.Errorf("sendBufferSize: got %d, want 2000", srv.sendBufferSize)
		}
		if srv.writeTimeout != 10*time.Second {
			t.Errorf("writeTimeout: got %v, want 10s", srv.writeTimeout)
		}
	})
}

// -------------------------------------------------------------------
// Connect handshake
// -------------------------------------------------------------------

// TestConnectHandshake verifies the full connect handshake: a sandlot sends
// NodeHello, the gateway registers the node, replies with a HelloAck carrying
// its gatewayID, and fires OnConnect with the new NodeConnection.
func TestConnectHandshake(t *testing.T) {
	srv := NewServer("gw-handshake", silentLogger(), 128, 0)

	ncCh := make(chan *NodeConnection, 1)
	srv.OnConnect(func(nc *NodeConnection) { ncCh <- nc })

	hello := &pb.NodeHello{NodeId: "node-1", Version: "v1.2.3", TotalCpus: 4, TotalMemoryMb: 4096}
	fs, done := startConnect(t, srv, hello)
	defer fs.cancel()

	var nc *NodeConnection
	select {
	case nc = <-ncCh:
	case <-time.After(time.Second):
		t.Fatal("OnConnect did not fire")
	}

	// Node is now registered and addressable - this is the contract
	// ownership.go's Claim relies on (GetNode must succeed for a connected node).
	got, err := srv.GetNode("node-1")
	if err != nil {
		t.Fatalf("GetNode after connect: %v", err)
	}
	if got != nc {
		t.Error("GetNode returned a different connection than OnConnect")
	}
	if nc.NodeID != "node-1" || nc.Version != "v1.2.3" || nc.Info != hello {
		t.Errorf("NodeConnection fields: id=%q ver=%q info-ptr=%p", nc.NodeID, nc.Version, nc.Info)
	}

	// HelloAck was sent with the gateway's identity.
	sent := fs.sentMessages()
	if len(sent) == 0 {
		t.Fatal("expected at least one Sent message (HelloAck)")
	}
	ack := sent[0].GetHelloAck()
	if ack == nil {
		t.Fatalf("first sent message is not HelloAck: %T", sent[0].Payload)
	}
	if ack.GatewayId != "gw-handshake" {
		t.Errorf("HelloAck.GatewayId: got %q, want gw-handshake", ack.GatewayId)
	}
	if ack.MaxConcurrentVms != 128 {
		t.Errorf("HelloAck.MaxConcurrentVms: got %d, want 128 (sendBufferSize)", ack.MaxConcurrentVms)
	}
	// NEGOTIATED ECHO: the ack stamps the HELLO's version (validated into the
	// supported range), not the gateway's own current version — that is what
	// lets a compat-window gateway ([min, newer]) serve an old sandlot in the
	// version it sent. Here the hello carried the current version, so the two
	// coincide; the window case is pinned by protocol-version-e2e.sh's S5.
	if ack.ProtocolVersion != hello.GetProtocolVersion() {
		t.Errorf("HelloAck.ProtocolVersion: got %d, want the hello's %d (negotiated echo)",
			ack.ProtocolVersion, hello.GetProtocolVersion())
	}

	// Nodes() lists the connected node (used by ownership's node_count health key).
	if got := srv.Nodes(); len(got) != 1 || got[0] != "node-1" {
		t.Errorf("Nodes(): got %v, want [node-1]", got)
	}

	// Tear down: clean EOF -> readLoop removeNode -> writeLoop exit.
	close(fs.recvCh)
	waitForDone(t, done, "clean disconnect")
}

// TestConnectProtocolVersionGate verifies the handshake version gate: a
// NodeHello whose protocol_version is unset (0 — a build from before
// versioning), older than the supported minimum, or newer than the current
// version is rejected with errStreamProtocolVersion BEFORE the node is
// registered, OnConnect fires, or an HelloAck is sent. Bypasses startConnect
// (which defaults an unset version) so even the zero case reaches the gate
// as-is.
func TestConnectProtocolVersionGate(t *testing.T) {
	cases := []struct {
		name string
		pv   uint32
	}{
		{"unset (pre-versioning build)", 0},
		{"older than minimum", uint32(StreamProtocolMinSupported) - 1},
		{"newer than current", uint32(StreamProtocolVersion) + 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := NewServer("gw-ver", silentLogger(), 128, 0)
			connects := make(chan *NodeConnection, 1)
			srv.OnConnect(func(nc *NodeConnection) { connects <- nc })

			fs := newFakeStream()
			fs.recvCh <- helloMsg(&pb.NodeHello{NodeId: "node-ver", ProtocolVersion: c.pv})
			done := make(chan error, 1)
			go func() { done <- srv.Connect(fs) }()
			defer fs.cancel()

			select {
			case err := <-done:
				if !errors.Is(err, errStreamProtocolVersion) {
					t.Fatalf("Connect error: got %v, want errStreamProtocolVersion", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("Connect did not return after version rejection")
			}

			// Nothing registered, no callbacks, no ack sent.
			if _, err := srv.GetNode("node-ver"); !errors.Is(err, ErrNodeNotFound) {
				t.Errorf("GetNode after rejection: got %v, want ErrNodeNotFound", err)
			}
			select {
			case nc := <-connects:
				t.Errorf("OnConnect fired for rejected node: %v", nc.NodeID)
			default:
			}
			if sent := fs.sentMessages(); len(sent) != 0 {
				t.Errorf("HelloAck sent to a rejected node: %v", sent)
			}
		})
	}
}

// TestConnectProtocolVersionAccepted pins the inclusive boundary: a hello at
// exactly the current version connects (the happy path is covered broadly
// elsewhere; this pins the gate's boundary math).
func TestConnectProtocolVersionAccepted(t *testing.T) {
	srv := NewServer("gw-ver-ok", silentLogger(), 128, 0)
	ncCh := make(chan *NodeConnection, 1)
	srv.OnConnect(func(nc *NodeConnection) { ncCh <- nc })

	fs, done := startConnect(t, srv, &pb.NodeHello{NodeId: "node-ver-ok", ProtocolVersion: uint32(StreamProtocolVersion)})
	defer fs.cancel()

	select {
	case <-ncCh:
	case <-time.After(time.Second):
		t.Fatal("OnConnect did not fire for a current-version hello")
	}
	close(fs.recvCh)
	waitForDone(t, done, "clean disconnect")
}

// TestConnectFirstRecvError verifies that if the very first Recv fails (sandlot
// disconnects before sending Hello), Connect returns that error and registers
// no node.
func TestConnectFirstRecvError(t *testing.T) {
	srv := NewServer("gw-recv-err", silentLogger(), 0, 0)
	connectFired := atomic.Int32{}
	srv.OnConnect(func(nc *NodeConnection) { connectFired.Add(1) })

	fs := newFakeStream()
	fs.cancel() // make Recv return ctx.Err immediately
	done := make(chan error, 1)
	go func() { done <- srv.Connect(fs) }()

	select {
	case err := <-done:
		if err == nil {
			t.Error("expected non-nil error when first Recv fails")
		}
	case <-time.After(time.Second):
		t.Fatal("Connect did not return after first Recv error")
	}
	if connectFired.Load() != 0 {
		t.Error("OnConnect must not fire when handshake never completes")
	}
	if got := srv.Nodes(); len(got) != 0 {
		t.Errorf("no node should be registered, got %v", got)
	}
}

// TestConnectNoHello verifies that a first message which is NOT a NodeHello
// terminates the stream with ErrExpectedHello (previously Connect returned a
// nil error, making gRPC treat the failed handshake as a successful stream).
func TestConnectNoHello(t *testing.T) {
	srv := NewServer("gw-no-hello", silentLogger(), 0, 0)
	srv.OnConnect(func(nc *NodeConnection) { t.Error("OnConnect must not fire without Hello") })

	fs := newFakeStream()
	// First message is a Heartbeat, not a Hello.
	fs.recvCh <- &pb.NodeMessage{NodeId: "node-x", Payload: &pb.NodeMessage_Heartbeat{Heartbeat: &pb.Heartbeat{}}}
	done := make(chan error, 1)
	go func() { done <- srv.Connect(fs) }()
	defer fs.cancel()

	select {
	case err := <-done:
		if !errors.Is(err, ErrExpectedHello) {
			t.Errorf("expected ErrExpectedHello, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Connect did not return for non-Hello first message")
	}
	if got := srv.Nodes(); len(got) != 0 {
		t.Errorf("no node should be registered, got %v", got)
	}
}

// TestConnectHelloAckSendFailure verifies that when the HelloAck Send fails
// (broken write side), the node is removed from the registry and Connect
// returns the send error. Because the node WAS briefly registered, onDisconnect
// fires (it is the registered connection being removed); handlers must be
// idempotent for a node whose OnConnect never fired.
func TestConnectHelloAckSendFailure(t *testing.T) {
	srv := NewServer("gw-send-fail", silentLogger(), 0, 0)

	disconnects := make(chan string, 4)
	srv.OnConnect(func(nc *NodeConnection) { t.Error("OnConnect must not fire when HelloAck Send fails") })
	srv.OnDisconnect(func(nc *NodeConnection) { disconnects <- nc.NodeID })

	fs := newFakeStreamFor("node-broken")
	fs.sendErr = errors.New("write side broken")
	fs.recvCh <- helloMsg(&pb.NodeHello{NodeId: "node-broken", ProtocolVersion: StreamProtocolVersion})
	done := make(chan error, 1)
	go func() { done <- srv.Connect(fs) }()
	defer fs.cancel()

	select {
	case err := <-done:
		if err == nil || err.Error() != "write side broken" {
			t.Errorf("expected send error, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Connect did not return after HelloAck Send failure")
	}

	// Node must not be reachable.
	if _, err := srv.GetNode("node-broken"); !errors.Is(err, ErrNodeNotFound) {
		t.Errorf("GetNode after failed handshake: got %v, want ErrNodeNotFound", err)
	}
	if got := srv.Nodes(); len(got) != 0 {
		t.Errorf("Nodes(): got %v, want empty", got)
	}
	select {
	case id := <-disconnects:
		if id != "node-broken" {
			t.Errorf("onDisconnect nodeID: got %q, want node-broken", id)
		}
	case <-time.After(time.Second):
		t.Error("onDisconnect should fire for the registered-then-removed node")
	}
}

// -------------------------------------------------------------------
// GetNode / Nodes contracts (consumed by lease/ownership.go)
// -------------------------------------------------------------------

// TestGetNodeContract is the core ownership contract: GetNode returns
// ErrNodeNotFound for a disconnected node (so Claim -> ErrOwnerNodeDown) and
// succeeds for a connected one. It also covers the "in-registry but closed"
// transient state.
func TestGetNodeContract(t *testing.T) {
	srv := NewServer("gw-get", silentLogger(), 0, 0)
	ncCh := make(chan *NodeConnection, 4)
	srv.OnConnect(func(nc *NodeConnection) { ncCh <- nc })

	fs, done := startConnect(t, srv, &pb.NodeHello{NodeId: "node-1"})
	defer fs.cancel()
	nc := <-ncCh

	// Connected -> found.
	if _, err := srv.GetNode("node-1"); err != nil {
		t.Errorf("connected node: GetNode err = %v", err)
	}
	// Wrong ID -> ErrNodeNotFound (-> Claim ErrOwnerNodeDown).
	if _, err := srv.GetNode("node-other"); !errors.Is(err, ErrNodeNotFound) {
		t.Errorf("unknown node: got %v, want ErrNodeNotFound", err)
	}

	// Closed-but-still-in-registry transient state: GetNode must STILL return
	// ErrNodeNotFound. This is the window the IsClosed() check in GetNode exists
	// for (e.g. writeLoop closed the connection before readLoop's removeNode
	// deletes it from the map).
	nc.Close()
	if _, err := srv.GetNode("node-1"); !errors.Is(err, ErrNodeNotFound) {
		t.Errorf("closed-but-in-registry node: got %v, want ErrNodeNotFound", err)
	}

	close(fs.recvCh)
	waitForDone(t, done, "disconnect after close")
}

// TestNodesAndCount verifies Nodes() reflects exactly the live (non-closed)
// connected nodes. ownership.currentNodeCount uses len(Nodes()) for the health
// key node_count (fault state: 0 nodes => fault).
func TestNodesAndCount(t *testing.T) {
	srv := NewServer("gw-nodes", silentLogger(), 0, 0)
	ncCh := make(chan *NodeConnection, 8)
	srv.OnConnect(func(nc *NodeConnection) { ncCh <- nc })

	if got := srv.Nodes(); len(got) != 0 {
		t.Fatalf("initial Nodes(): got %v, want empty", got)
	}

	fs1, done1 := startConnect(t, srv, &pb.NodeHello{NodeId: "node-a"})
	defer fs1.cancel()
	<-ncCh
	fs2, done2 := startConnect(t, srv, &pb.NodeHello{NodeId: "node-b"})
	defer fs2.cancel()
	<-ncCh

	got := srv.Nodes()
	if len(got) != 2 {
		t.Fatalf("after two connects: Nodes() = %v, want 2 entries", got)
	}
	if !contains(got, "node-a") || !contains(got, "node-b") {
		t.Errorf("Nodes() missing entries: %v", got)
	}

	// Disconnect node-a: it must drop out of Nodes() (and GetNode -> not found).
	close(fs1.recvCh)
	waitForDone(t, done1, "node-a disconnect")
	if _, err := srv.GetNode("node-a"); !errors.Is(err, ErrNodeNotFound) {
		t.Errorf("after disconnect GetNode(node-a): %v, want ErrNodeNotFound", err)
	}
	got = srv.Nodes()
	if len(got) != 1 || got[0] != "node-b" {
		t.Errorf("after node-a disconnect: Nodes() = %v, want [node-b]", got)
	}

	close(fs2.recvCh)
	waitForDone(t, done2, "node-b disconnect")
	if got := srv.Nodes(); len(got) != 0 {
		t.Errorf("after all disconnects: Nodes() = %v, want empty", got)
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// -------------------------------------------------------------------
// OnDisconnect semantics
// -------------------------------------------------------------------

// TestOnDisconnectFiresOnCleanDisconnect verifies that a clean sandlot
// disconnect (EOF) fires OnDisconnect exactly once with the right nodeID, and
// removes the node from the registry (this fires the owner-release
// OnDisconnect trigger).
func TestOnDisconnectFiresOnCleanDisconnect(t *testing.T) {
	srv := NewServer("gw-disc", silentLogger(), 0, 0)
	srv.OnConnect(func(*NodeConnection) {})

	var disconnects atomic.Int32
	var lastID atomic.Value
	srv.OnDisconnect(func(nc *NodeConnection) {
		disconnects.Add(1)
		lastID.Store(nc.NodeID)
	})

	fs, done := startConnect(t, srv, &pb.NodeHello{NodeId: "node-1"})
	defer fs.cancel()
	// Wait for registration (Connect runs in a goroutine; the handshake is async).
	waitForNode(t, srv, "node-1")

	close(fs.recvCh) // EOF -> readLoop removeNode
	waitForDone(t, done, "disconnect")

	if disconnects.Load() != 1 {
		t.Errorf("onDisconnect fired %d times, want 1", disconnects.Load())
	}
	if lastID.Load() != "node-1" {
		t.Errorf("onDisconnect nodeID: got %v, want node-1", lastID.Load())
	}
	if _, err := srv.GetNode("node-1"); !errors.Is(err, ErrNodeNotFound) {
		t.Errorf("after disconnect GetNode: %v, want ErrNodeNotFound", err)
	}
}

// TestOnDisconnectNotFiredOnDoubleRemove verifies removeNode does not fire
// onDisconnect when the node was already removed (the spurious-callback bug).
// Two connections for the same nodeID: the second's cleanup (removeNode(nc2))
// runs after the first already deleted the entry, so the second removeNode sees
// an empty registry and must NOT fire onDisconnect.
func TestOnDisconnectNotFiredOnDoubleRemove(t *testing.T) {
	srv := NewServer("gw-double", silentLogger(), 0, 0)

	var disconnects atomic.Int32
	srv.OnConnect(func(*NodeConnection) {})
	srv.OnDisconnect(func(nc *NodeConnection) { disconnects.Add(1) })

	// Register two connections directly (bypassing Connect) to control the
	// sequence precisely: nc1 is the active entry, then nc1 is removed, then
	// removeNode(nc1) is called a second time (as could happen if a lingering
	// readLoop defer raced with an explicit removal).
	nc1 := NewNodeConnection(&pb.NodeHello{NodeId: "node-1"}, newFakeStream(), 64)
	nc2 := NewNodeConnection(&pb.NodeHello{NodeId: "node-1"}, newFakeStream(), 64)

	srv.mu.Lock()
	srv.nodes["node-1"] = nc1
	srv.mu.Unlock()

	srv.removeNode(nc1) // active entry -> removed, onDisconnect fires (1).
	if disconnects.Load() != 1 {
		t.Fatalf("after first remove: disconnects = %d, want 1", disconnects.Load())
	}

	// Now nc2 is NOT in the registry. Calling removeNode(nc2) must be a no-op
	// for callbacks: it must not fire onDisconnect and must not panic.
	srv.removeNode(nc2)
	if disconnects.Load() != 1 {
		t.Errorf("after remove of absent connection: disconnects = %d, want 1 (no spurious fire)",
			disconnects.Load())
	}
	if !nc2.IsClosed() {
		t.Error("removeNode should still close the passed connection to release resources")
	}
}

// -------------------------------------------------------------------
// Reconnect race (the critical contract bug)
// -------------------------------------------------------------------

// TestReconnectRaceDoesNotClobberNewConnection verifies that when a sandlot
// reconnects (new connection, same nodeID) while the OLD connection's cleanup
// is still in flight, the old connection's removeNode does NOT delete or close
// the new connection, and does NOT fire onDisconnect for the new connection.
//
// Before the fix, removeNode(nodeID) keyed only on the string ID, so the old
// connection's readLoop defer would delete + close the NEW connection and fire
// onDisconnect - immediately killing the freshly-reconnected sandlot and
// churning ownership. This broke the ownership
// contract: a connected node would appear down (GetNode -> ErrNodeNotFound).
func TestReconnectRaceDoesNotClobberNewConnection(t *testing.T) {
	srv := NewServer("gw-race", silentLogger(), 0, 0)

	ncCh := make(chan *NodeConnection, 8)
	var disconnects atomic.Int32
	var disconnectIDs []string
	var dmu sync.Mutex
	srv.OnConnect(func(nc *NodeConnection) { ncCh <- nc })
	srv.OnDisconnect(func(nc *NodeConnection) {
		dmu.Lock()
		disconnectIDs = append(disconnectIDs, nc.NodeID)
		dmu.Unlock()
		disconnects.Add(1)
	})

	// First connection (old sandlot). Its readLoop blocks on Recv (empty recvCh).
	fs1, done1 := startConnect(t, srv, &pb.NodeHello{NodeId: "node-1", Version: "old"})
	defer fs1.cancel()
	nc1 := <-ncCh

	// Reconnect: same nodeID, new connection overwrites the registry entry.
	fs2, done2 := startConnect(t, srv, &pb.NodeHello{NodeId: "node-1", Version: "new"})
	defer fs2.cancel()
	nc2 := <-ncCh
	if nc1 == nc2 {
		t.Fatal("expected two distinct connections")
	}

	// nc2 is now the active connection.
	got, err := srv.GetNode("node-1")
	if err != nil || got != nc2 {
		t.Fatalf("after reconnect: GetNode = %v, %v; want nc2", got, err)
	}

	// The reconnect must have CLOSED the old connection (so its
	// writeLoop/readLoop goroutines exit promptly instead of leaking).
	if !nc1.IsClosed() {
		t.Error("old connection not closed on reconnect (goroutine leak)")
	}

	// Simulate the OLD connection's readLoop dying (EOF on its stream). This is
	// the race window: removeNode(nc1) runs while nc2 is the active entry.
	close(fs1.recvCh)
	waitForDone(t, done1, "old connection cleanup")

	// CRITICAL assertions: the new connection must survive.
	got, err = srv.GetNode("node-1")
	if err != nil {
		t.Fatalf("BUG: old connection cleanup clobbered new connection: GetNode err = %v", err)
	}
	if got != nc2 {
		t.Fatalf("BUG: active connection replaced after old cleanup: got %p, want nc2 %p", got, nc2)
	}
	if nc2.IsClosed() {
		t.Fatal("BUG: new connection was closed by old connection's cleanup")
	}

	// onDisconnect must NOT have fired: nc1 was no longer the active connection
	// when its removeNode ran, so no actual disconnect occurred from the
	// registry's perspective (the node is still connected via nc2).
	if disconnects.Load() != 0 {
		dmu.Lock()
		t.Fatalf("BUG: onDisconnect fired %d times during reconnect race: %v",
			disconnects.Load(), disconnectIDs)
		dmu.Unlock()
	}

	// Cleanly disconnect nc2 now; that IS a real disconnect and must fire once.
	close(fs2.recvCh)
	waitForDone(t, done2, "new connection disconnect")
	if disconnects.Load() != 1 {
		t.Errorf("after nc2 disconnect: onDisconnect fired %d times, want 1", disconnects.Load())
	}
	if _, err := srv.GetNode("node-1"); !errors.Is(err, ErrNodeNotFound) {
		t.Errorf("after final disconnect: GetNode = %v, want ErrNodeNotFound", err)
	}
}

// -------------------------------------------------------------------
// readLoop dispatch: responses, events, heartbeats
// -------------------------------------------------------------------

// TestReadLoopDispatchesCommandResponse verifies that a CommandResponse sent by
// the sandlot is routed to the waiting SendCommand caller via the connection's
// pending map (the warm-path command reply path).
func TestReadLoopDispatchesCommandResponse(t *testing.T) {
	srv := NewServer("gw-resp", silentLogger(), 0, 0)
	ncCh := make(chan *NodeConnection, 1)
	srv.OnConnect(func(nc *NodeConnection) { ncCh <- nc })

	fs, done := startConnect(t, srv, &pb.NodeHello{NodeId: "node-1"})
	defer fs.cancel()
	nc := <-ncCh

	// Send a command; writeLoop will drain sendCh and call stream.Send (recorded
	// in fs.sent). We just need the pending channel registered.
	cmd := &pb.VMCommand{CommandId: "cmd-7", Action: &pb.VMCommand_UnmountRootfs{UnmountRootfs: &pb.UnmountRootfs{}}}
	respCh, err := nc.SendCommand(cmd)
	if err != nil {
		t.Fatalf("SendCommand: %v", err)
	}

	// Sandlot replies with a matching response.
	fs.recvCh <- &pb.NodeMessage{
		NodeId: "node-1",
		Payload: &pb.NodeMessage_Response{Response: &pb.CommandResponse{
			CommandId: "cmd-7", Success: true, Stdout: "ok",
		}},
	}

	select {
	case resp := <-respCh:
		if !resp.Success || resp.CommandId != "cmd-7" || resp.Stdout != "ok" {
			t.Errorf("unexpected response: %+v", resp)
		}
	case <-time.After(time.Second):
		t.Fatal("response not delivered to SendCommand waiter")
	}

	// The command was actually written to the sandlot stream (writeLoop drains
	// sendCh asynchronously, so poll until it appears).
	deadline := time.Now().Add(time.Second)
	var found bool
	for time.Now().Before(deadline) && !found {
		for _, m := range fs.sentMessages() {
			if m.GetVmCommand() != nil && m.GetVmCommand().CommandId == "cmd-7" {
				found = true
			}
		}
		if !found {
			time.Sleep(2 * time.Millisecond)
		}
	}
	if !found {
		t.Error("VMCommand was not Sent on the stream")
	}

	close(fs.recvCh)
	waitForDone(t, done, "disconnect")
}

// TestReadLoopDispatchesVMEvent verifies async VM events reach the OnEvent
// callback with the originating connection.
func TestReadLoopDispatchesVMEvent(t *testing.T) {
	srv := NewServer("gw-event", silentLogger(), 0, 0)
	ncCh := make(chan *NodeConnection, 1)
	evCh := make(chan *pb.VMEvent, 4)
	srv.OnConnect(func(nc *NodeConnection) { ncCh <- nc })
	srv.OnEvent(func(nc *NodeConnection, ev *pb.VMEvent) {
		if nc.NodeID != "node-1" {
			t.Errorf("OnEvent connection: got %q, want node-1", nc.NodeID)
		}
		evCh <- ev
	})

	fs, done := startConnect(t, srv, &pb.NodeHello{NodeId: "node-1"})
	defer fs.cancel()
	<-ncCh

	fs.recvCh <- &pb.NodeMessage{
		NodeId: "node-1",
		Payload: &pb.NodeMessage_VmEvent{VmEvent: &pb.VMEvent{
			VmId: "vm-9", Message: "crashed",
		}},
	}
	select {
	case ev := <-evCh:
		if ev.VmId != "vm-9" || ev.Message != "crashed" {
			t.Errorf("unexpected event: %+v", ev)
		}
	case <-time.After(time.Second):
		t.Fatal("OnEvent did not fire")
	}

	close(fs.recvCh)
	waitForDone(t, done, "disconnect")
}

// TestReadLoopDispatchesHeartbeat verifies heartbeats reach OnHeartbeat. A
// heartbeat with zero VMs is itself meaningful (tells the gateway the node has
// no live VMs), so it must fire even with empty fields.
func TestReadLoopDispatchesHeartbeat(t *testing.T) {
	srv := NewServer("gw-hb", silentLogger(), 0, 0)
	ncCh := make(chan *NodeConnection, 1)
	hbCh := make(chan *pb.Heartbeat, 4)
	srv.OnConnect(func(nc *NodeConnection) { ncCh <- nc })
	srv.OnHeartbeat(func(nodeID string, vmCount uint32, vmIDs []string, vmMem []*pb.VmMemInfo, specCap []*pb.SpecCapacity, metrics *pb.NodeMetrics) {
		if nodeID != "node-1" {
			t.Errorf("OnHeartbeat nodeID: got %q, want node-1", nodeID)
		}
		hbCh <- &pb.Heartbeat{ActiveVmCount: vmCount, ActiveVmIds: vmIDs}
	})

	fs, done := startConnect(t, srv, &pb.NodeHello{NodeId: "node-1"})
	defer fs.cancel()
	<-ncCh

	// Non-empty heartbeat.
	fs.recvCh <- &pb.NodeMessage{
		NodeId:  "node-1",
		Payload: &pb.NodeMessage_Heartbeat{Heartbeat: &pb.Heartbeat{ActiveVmCount: 3, ActiveVmIds: []string{"a", "b", "c"}}},
	}
	select {
	case hb := <-hbCh:
		if hb.ActiveVmCount != 3 || len(hb.ActiveVmIds) != 3 {
			t.Errorf("unexpected heartbeat: %+v", hb)
		}
	case <-time.After(time.Second):
		t.Fatal("OnHeartbeat did not fire for non-empty heartbeat")
	}

	// Zero-VM heartbeat must still fire (stale-pool reconciliation signal).
	fs.recvCh <- &pb.NodeMessage{
		NodeId:  "node-1",
		Payload: &pb.NodeMessage_Heartbeat{Heartbeat: &pb.Heartbeat{ActiveVmCount: 0}},
	}
	select {
	case hb := <-hbCh:
		if hb.ActiveVmCount != 0 {
			t.Errorf("zero-VM heartbeat: got count %d, want 0", hb.ActiveVmCount)
		}
	case <-time.After(time.Second):
		t.Fatal("OnHeartbeat must fire for zero-VM heartbeat")
	}

	close(fs.recvCh)
	waitForDone(t, done, "disconnect")
}

// TestCallbacksNilSafe verifies the server does not panic when no callbacks are
// registered and a node connects/disconnects (default NewServer state).
func TestCallbacksNilSafe(t *testing.T) {
	srv := NewServer("gw-nil-cb", silentLogger(), 0, 0)
	// No OnConnect/OnDisconnect/OnEvent/OnHeartbeat registered.

	fs, done := startConnect(t, srv, &pb.NodeHello{NodeId: "node-1"})
	defer fs.cancel()
	waitForNode(t, srv, "node-1")

	// Drive an event + heartbeat + response through readLoop with nil callbacks.
	fs.recvCh <- &pb.NodeMessage{NodeId: "node-1", Payload: &pb.NodeMessage_VmEvent{VmEvent: &pb.VMEvent{}}}
	fs.recvCh <- &pb.NodeMessage{NodeId: "node-1", Payload: &pb.NodeMessage_Heartbeat{Heartbeat: &pb.Heartbeat{}}}
	fs.recvCh <- &pb.NodeMessage{NodeId: "node-1", Payload: &pb.NodeMessage_Response{Response: &pb.CommandResponse{CommandId: "nope"}}}

	close(fs.recvCh)
	waitForDone(t, done, "disconnect with nil callbacks")
}

// TestReadLoopNonEOFError exercises the readLoop error branch where Recv returns
// a non-EOF error (e.g. context cancel / transport reset). It must still close
// the connection, remove the node, and fire onDisconnect exactly once. This
// covers the `if err != io.EOF` log path that the clean-EOF test does not.
func TestReadLoopNonEOFError(t *testing.T) {
	srv := NewServer("gw-readerr", silentLogger(), 0, 0)
	ncCh := make(chan *NodeConnection, 1)
	var disconnects atomic.Int32
	srv.OnConnect(func(nc *NodeConnection) { ncCh <- nc })
	srv.OnDisconnect(func(nc *NodeConnection) { disconnects.Add(1) })

	fs, done := startConnect(t, srv, &pb.NodeHello{NodeId: "node-1"})
	defer fs.cancel()
	nc := <-ncCh

	// Cancel the stream context: Recv returns context.Canceled (non-EOF) ->
	// readLoop logs, closes nc, returns, defer removeNode fires onDisconnect.
	fs.cancel()
	waitForDone(t, done, "non-EOF read error")

	if disconnects.Load() != 1 {
		t.Errorf("onDisconnect fired %d times, want 1", disconnects.Load())
	}
	if !nc.IsClosed() {
		t.Error("connection should be closed after read error")
	}
	if _, err := srv.GetNode("node-1"); !errors.Is(err, ErrNodeNotFound) {
		t.Errorf("GetNode after read error: %v, want ErrNodeNotFound", err)
	}
}

// TestWriteLoopSendError exercises the writeLoop send-error branch: when
// stream.Send fails (broken write side), writeLoop closes the connection and
// returns the error, which propagates out of Connect. Any in-flight SendCommand
// waiter is released with a "connection closed" error response.
func TestWriteLoopSendError(t *testing.T) {
	srv := NewServer("gw-writeerr", silentLogger(), 0, 0)
	ncCh := make(chan *NodeConnection, 1)
	var disconnects atomic.Int32
	srv.OnConnect(func(nc *NodeConnection) { ncCh <- nc })
	srv.OnDisconnect(func(nc *NodeConnection) { disconnects.Add(1) })

	fs, done := startConnect(t, srv, &pb.NodeHello{NodeId: "node-1"})
	defer fs.cancel()
	nc := <-ncCh

	// Break the write side, then enqueue a command. writeLoop will drain sendCh,
	// call Send -> error, close nc, and return the error from Connect.
	fs.sendErr = errors.New("write broken")
	ch, err := nc.SendCommand(&pb.VMCommand{CommandId: "cmd-1"})
	if err != nil {
		t.Fatalf("SendCommand enqueue: %v", err)
	}

	// Connect must terminate with the send error.
	select {
	case err := <-done:
		if err == nil || err.Error() != "write broken" {
			t.Errorf("Connect return: got %v, want write broken", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Connect did not return after writeLoop Send error")
	}

	// The in-flight waiter is released (not left blocking forever).
	select {
	case resp := <-ch:
		if resp.Success {
			t.Error("waiter should get a failure response on connection close")
		}
		if resp.Error == "" {
			t.Error("waiter response should carry a non-empty error message")
		}
	case <-time.After(time.Second):
		t.Fatal("in-flight SendCommand waiter was not released by Close")
	}

	// readLoop is still blocked on Recv; unblock it so removeNode runs and the
	// node leaves the registry cleanly.
	fs.cancel()
	// Drain any remaining disconnect (readLoop's removeNode).
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if _, err := srv.GetNode("node-1"); errors.Is(err, ErrNodeNotFound) {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	if _, err := srv.GetNode("node-1"); !errors.Is(err, ErrNodeNotFound) {
		t.Errorf("GetNode after write-error teardown: %v, want ErrNodeNotFound", err)
	}
}

// TestCallbackRegistrationIsMutating verifies the On* setters actually replace
// the callback (last-writer-wins), so wiring order in cmd/main.go is safe.
func TestCallbackRegistrationIsMutating(t *testing.T) {
	srv := NewServer("gw-cb-reg", silentLogger(), 0, 0)

	var first, second atomic.Int32
	srv.OnConnect(func(*NodeConnection) { first.Add(1) })
	srv.OnConnect(func(*NodeConnection) { second.Add(1) })

	fs, done := startConnect(t, srv, &pb.NodeHello{NodeId: "node-1"})
	defer fs.cancel()
	waitForNode(t, srv, "node-1")

	if first.Load() != 0 {
		t.Error("first OnConnect was replaced and must not fire")
	}
	if second.Load() != 1 {
		t.Errorf("second OnConnect should have fired once, got %d", second.Load())
	}
	close(fs.recvCh)
	waitForDone(t, done, "disconnect")
}

// waitForNode polls GetNode until the node is registered or times out.
func waitForNode(t *testing.T, srv *Server, nodeID string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if _, err := srv.GetNode(nodeID); err == nil {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("node %q never registered", nodeID)
}

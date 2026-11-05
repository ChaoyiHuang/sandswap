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

package rpc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pb "common/proto/stream"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// fakeGateway is a gateway-side NodeStream server for tests. After the
// Hello/HelloAck handshake it delegates to afterAck.
type fakeGateway struct {
	pb.UnimplementedNodeStreamServer
	gatewayID string
	// ackVersion overrides the protocol version the fake gateway acks with.
	// 0 = this client build's ProtocolVersion (the realistic default).
	ackVersion uint32
	afterAck   func(stream pb.NodeStream_ConnectServer, hello *pb.NodeHello) error
}

func (f *fakeGateway) Connect(stream pb.NodeStream_ConnectServer) error {
	msg, err := stream.Recv()
	if err != nil {
		return err
	}
	hello := msg.GetHello()
	if hello == nil {
		return errors.New("expected NodeHello")
	}
	ackV := f.ackVersion
	if ackV == 0 {
		ackV = ProtocolVersion // unset = this build's version (realistic default)
	}
	if err := stream.Send(&pb.GatewayMessage{
		Payload: &pb.GatewayMessage_HelloAck{
			// Mirror a real gateway: the ack carries its stream protocol
			// version, which the client verifies symmetrically. ackVersion
			// (test-only) overrides it to drive the mismatch path.
			HelloAck: &pb.HelloAck{GatewayId: f.gatewayID, ProtocolVersion: ackV},
		},
	}); err != nil {
		return err
	}
	if f.afterAck != nil {
		return f.afterAck(stream, hello)
	}
	return nil
}

// startFakeGateway serves a fakeGateway on a Unix socket in a temp dir and
// returns the address to dial ("unix://...").
func startFakeGateway(t *testing.T, gw *fakeGateway) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "gw.sock")
	lis, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	srv := grpc.NewServer()
	pb.RegisterNodeStreamServer(srv, gw)
	go srv.Serve(lis)
	t.Cleanup(srv.Stop)
	return "unix://" + sock
}

func testNodeInfo() *pb.NodeHello {
	return &pb.NodeHello{NodeId: "node-1", Version: "test"}
}

func connectTest(t *testing.T, gw *fakeGateway, cfg Config) (*Client, *fakeGateway) {
	t.Helper()
	addr := startFakeGateway(t, gw)
	c, err := Connect(context.Background(), addr, testNodeInfo(), nil,
		log.New(os.Stderr, "rpc-test ", 0), cfg)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	t.Cleanup(c.Close)
	return c, gw
}

func waitForDone(t *testing.T, c *Client) {
	t.Helper()
	select {
	case <-c.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("Done() was not closed within 5s")
	}
}

// --- Connect happy path ---

func TestConnect_Success_FullFlow(t *testing.T) {
	nodeMsgs := make(chan *pb.NodeMessage, 16)
	addr := startFakeGateway(t, &fakeGateway{
		gatewayID: "gw-1",
		afterAck: func(stream pb.NodeStream_ConnectServer, hello *pb.NodeHello) error {
			if hello.NodeId != "node-1" {
				return fmt.Errorf("unexpected node id %q", hello.NodeId)
			}
			// Push a command right after the handshake.
			if err := stream.Send(&pb.GatewayMessage{
				Payload: &pb.GatewayMessage_VmCommand{
					VmCommand: &pb.VMCommand{CommandId: "cmd-1"},
				},
			}); err != nil {
				return err
			}
			for {
				msg, err := stream.Recv()
				if err != nil {
					return err
				}
				select {
				case nodeMsgs <- msg:
				default:
				}
			}
		},
	})

	c, err := Connect(context.Background(), addr, testNodeInfo(), nil,
		log.New(io.Discard, "", 0), Config{})
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer c.Close()

	// Gateway-pushed command lands on Commands().
	select {
	case cmd := <-c.Commands():
		if cmd.GetVmCommand().GetCommandId() != "cmd-1" {
			t.Errorf("command id = %q, want cmd-1", cmd.GetVmCommand().GetCommandId())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no command received on Commands()")
	}

	// Sandlot-side senders reach the gateway.
	if err := c.SendResponse(&pb.CommandResponse{CommandId: "cmd-1", Success: true}); err != nil {
		t.Fatalf("SendResponse: %v", err)
	}
	if err := c.SendEvent(&pb.VMEvent{VmId: "vm-9", Type: pb.VMEventType_VM_EVENT_CRASHED}); err != nil {
		t.Fatalf("SendEvent: %v", err)
	}
	if err := c.SendHeartbeat(2, []string{"a", "b"}, nil, nil, nil, "aabbccdd", true, "11223344"); err != nil {
		t.Fatalf("SendHeartbeat: %v", err)
	}

	sawResp, sawEvent, sawHb := false, false, false
	deadline := time.After(5 * time.Second)
	for !(sawResp && sawEvent && sawHb) {
		select {
		case msg := <-nodeMsgs:
			switch m := msg.Payload.(type) {
			case *pb.NodeMessage_Response:
				sawResp = true
				if m.Response.CommandId != "cmd-1" || !m.Response.Success {
					t.Errorf("response = %+v", m.Response)
				}
				if msg.NodeId != "node-1" {
					t.Errorf("node id = %q, want node-1", msg.NodeId)
				}
			case *pb.NodeMessage_VmEvent:
				sawEvent = true
			case *pb.NodeMessage_Heartbeat:
				sawHb = true
				if m.Heartbeat.ActiveVmCount != 2 {
					t.Errorf("heartbeat count = %d, want 2", m.Heartbeat.ActiveVmCount)
				}
				// The prov role's naming generations ride the heartbeat
				// (fingerprints only): the gateway projects them per node in
				// /stats, which is how a rotation proves fleet convergence.
				if m.Heartbeat.SeedGeneration != "aabbccdd" || !m.Heartbeat.SeedStaged ||
					m.Heartbeat.SeedStagedGeneration != "11223344" {
					t.Errorf("heartbeat seed report = (%q, %v, %q)",
						m.Heartbeat.SeedGeneration, m.Heartbeat.SeedStaged, m.Heartbeat.SeedStagedGeneration)
				}
			}
		case <-deadline:
			t.Fatalf("gateway did not receive all messages (resp=%v event=%v hb=%v)", sawResp, sawEvent, sawHb)
		}
	}

	select {
	case <-c.Done():
		t.Fatal("Done closed while connection is healthy")
	default:
	}
}

func TestConnect_CloseIsIdempotent(t *testing.T) {
	c, _ := connectTest(t, &fakeGateway{gatewayID: "gw"}, Config{})
	c.Close()
	waitForDone(t, c)
	c.Close()
	c.Close()
	if err := c.SendHeartbeat(0, nil, nil, nil, nil, "", false, ""); err == nil {
		t.Error("send after Close should fail")
	}
}

func TestConnect_ServerDropsStream_DoneClosed(t *testing.T) {
	c, _ := connectTest(t, &fakeGateway{gatewayID: "gw"}, Config{})
	// Server handler already returned (nil afterAck), tearing the stream down.
	// The client readLoop must notice and close the client.
	waitForDone(t, c)
}

func TestConnect_UnreachableGateway(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.sock")
	_, err := Connect(context.Background(), "unix://"+missing, testNodeInfo(), nil,
		log.New(io.Discard, "", 0), Config{})
	if err == nil {
		t.Fatal("Connect should fail against an unreachable gateway")
	}
}

func TestConnect_HelloAckError(t *testing.T) {
	addr := startFakeGateway(t, &fakeGateway{
		gatewayID: "gw",
		afterAck: func(stream pb.NodeStream_ConnectServer, hello *pb.NodeHello) error {
			// Consume the hello-triggered ack path then abort before anything else.
			return errors.New("handler aborted after ack")
		},
	})
	c, err := Connect(context.Background(), addr, testNodeInfo(), nil,
		log.New(io.Discard, "", 0), Config{})
	if err != nil {
		t.Fatalf("Connect should succeed at handshake: %v", err)
	}
	defer c.Close()
	waitForDone(t, c)
}

// --- manually constructed clients for loop/error-path coverage ---

// fakeStream implements pb.NodeStream_ConnectClient with stubbed Send/Recv.
type fakeStream struct {
	pb.NodeStream_ConnectClient
	sendErr   error
	blockSend chan struct{}
	recvMsgs  []*pb.GatewayMessage
	recvIdx   int
	recvErr   error
}

func (f *fakeStream) Send(m *pb.NodeMessage) error {
	if f.sendErr != nil {
		return f.sendErr
	}
	if f.blockSend != nil {
		<-f.blockSend
	}
	return nil
}

func (f *fakeStream) Recv() (*pb.GatewayMessage, error) {
	if f.recvIdx < len(f.recvMsgs) {
		m := f.recvMsgs[f.recvIdx]
		f.recvIdx++
		return m, nil
	}
	return nil, f.recvErr
}

func newLoopbackClient(stream pb.NodeStream_ConnectClient, cfg Config) *Client {
	if cfg.SendBufferSize <= 0 {
		cfg.SendBufferSize = 8
	}
	if cfg.RecvBufferSize <= 0 {
		cfg.RecvBufferSize = 8
	}
	if cfg.WriteTimeout <= 0 {
		cfg.WriteTimeout = 30 * time.Second
	}
	conn, err := grpc.NewClient("passthrough:///loopback",
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		panic(err)
	}
	c := &Client{
		conn:         conn,
		stream:       stream,
		logger:       log.New(io.Discard, "", 0),
		sendCh:       make(chan *pb.NodeMessage, cfg.SendBufferSize),
		recvCh:       make(chan *pb.GatewayMessage, cfg.RecvBufferSize),
		closeCh:      make(chan struct{}),
		nodeInfo:     testNodeInfo(),
		writeTimeout: cfg.WriteTimeout,
	}
	go c.readLoop()
	go c.writeLoop()
	return c
}

func TestReadLoop_DeliversThenClosesOnEOF(t *testing.T) {
	fs := &fakeStream{
		recvMsgs: []*pb.GatewayMessage{
			{Payload: &pb.GatewayMessage_VmCommand{VmCommand: &pb.VMCommand{CommandId: "c1"}}},
			{Payload: &pb.GatewayMessage_VmCommand{VmCommand: &pb.VMCommand{CommandId: "c2"}}},
		},
		recvErr: io.EOF,
	}
	c := newLoopbackClient(fs, Config{})
	defer c.Close()

	for _, want := range []string{"c1", "c2"} {
		select {
		case got := <-c.Commands():
			if got.GetVmCommand().GetCommandId() != want {
				t.Errorf("got command %q, want %q", got.GetVmCommand().GetCommandId(), want)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for command %q", want)
		}
	}
	waitForDone(t, c)
}

func TestWriteLoop_SendError_ClosesClient(t *testing.T) {
	fs := &fakeStream{sendErr: errors.New("EPIPE")}
	c := newLoopbackClient(fs, Config{})
	defer c.Close()

	if err := c.SendResponse(&pb.CommandResponse{CommandId: "x"}); err != nil {
		t.Fatalf("SendResponse queued: %v", err)
	}
	waitForDone(t, c)
}

func TestWriteLoop_WriteTimeout_ClosesClient(t *testing.T) {
	fs := &fakeStream{blockSend: make(chan struct{})} // Send blocks forever
	c := newLoopbackClient(fs, Config{WriteTimeout: 50 * time.Millisecond})
	defer c.Close()

	if err := c.SendResponse(&pb.CommandResponse{CommandId: "x"}); err != nil {
		t.Fatalf("SendResponse queued: %v", err)
	}
	waitForDone(t, c)
}

func TestSend_QueueFull(t *testing.T) {
	c := &Client{
		sendCh:   make(chan *pb.NodeMessage, 1),
		closeCh:  make(chan struct{}),
		nodeInfo: testNodeInfo(),
	}
	if err := c.SendResponse(&pb.CommandResponse{}); err != nil {
		t.Fatalf("first send should fit: %v", err)
	}
	err := c.SendResponse(&pb.CommandResponse{})
	if err == nil || err.Error() != "send queue full" {
		t.Errorf("second send err = %v, want send queue full", err)
	}
}

func TestSend_ClosedClient(t *testing.T) {
	c := &Client{
		sendCh:   make(chan *pb.NodeMessage, 1),
		closeCh:  make(chan struct{}),
		closed:   true,
		nodeInfo: testNodeInfo(),
	}
	err := c.SendEvent(&pb.VMEvent{})
	if err == nil || err.Error() != "connection closed" {
		t.Errorf("err = %v, want connection closed", err)
	}
}

func TestChannels_Returned(t *testing.T) {
	c := &Client{
		sendCh:  make(chan *pb.NodeMessage, 1),
		recvCh:  make(chan *pb.GatewayMessage, 1),
		closeCh: make(chan struct{}),
	}
	var cmds <-chan *pb.GatewayMessage = c.Commands()
	var done <-chan struct{} = c.Done()
	if cmds == nil || done == nil {
		t.Fatal("Commands/Done must return non-nil channels")
	}
}

// TestConnect_HelloAckVersionMismatch verifies the ACK-side version gate: a
// gateway that accepts our hello but acks with a protocol version we do not
// speak must abort the connect with the explicit mismatch message (both
// version numbers + the redeploy remedy) — never establish a session whose
// command semantics either side could misinterpret. This is the half the
// real-process drill cannot produce with symmetric constants (a gateway
// outside our range rejects the handshake before acking); the fake isolates it.
func TestConnect_HelloAckVersionMismatch(t *testing.T) {
	addr := startFakeGateway(t, &fakeGateway{gatewayID: "gw", ackVersion: 99})
	_, err := Connect(context.Background(), addr, testNodeInfo(), nil,
		log.New(io.Discard, "", 0), Config{})
	if err == nil {
		t.Fatal("Connect must fail when the gateway acks an unsupported protocol version")
	}
	for _, want := range []string{"99", "deploy matching gateway/sandlot builds"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing %q", err.Error(), want)
		}
	}
}

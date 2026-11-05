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
	"crypto/tls"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	pb "common/proto/stream"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
)

// Config holds the sandlot<->gateway gRPC stream transport parameters.
// Zero values fall back to safe defaults inside Connect.
type Config struct {
	// SendBufferSize is the sendCh capacity for outbound messages. Default 64.
	SendBufferSize int
	// RecvBufferSize is the recvCh capacity for incoming commands. Default 64.
	RecvBufferSize int
	// WriteTimeout bounds a blocking stream.Send (half-open detection). A
	// half-open TCP connection can block Send indefinitely on the write side
	// while the read side stays functional; this triggers a reconnect. Default 30s.
	WriteTimeout time.Duration
	// InitialWindow is the HTTP/2 per-stream flow-control window (bytes).
	InitialWindow int32
	// InitialConnWindow is the HTTP/2 per-connection window (bytes).
	InitialConnWindow int32
	// MaxMsgSize is the gRPC max send/recv message size (bytes).
	MaxMsgSize int
	// BeforeHello, when set, runs after the gRPC stream is established but
	// BEFORE the NodeHello is sent. It carries the reconnect half of the
	// reconnect-clean invariant: the sandlot releases every mount here, so the
	// gateway's OnConnect always meets a node with zero mounts (no
	// transient-state reconstruction, no reconciliation protocol, and a mount
	// can never survive into a connection where the gateway does not know about
	// it). Placing it after the dial — not at stream break — is what lets an
	// outage's in-flight commands use the whole T_tolerance window: they keep
	// running over vsock, unaffected by the gateway being gone, and are only
	// torn down once a gateway is actually reachable again.
	BeforeHello func()
}

// Client is a sandlot-side client connected to the gateway stream server.
type Client struct {
	// egressBinding is the node's egress identity-binding mode, reported on
	// every heartbeat (set once at startup).
	egressBinding string
	conn          *grpc.ClientConn
	stream        pb.NodeStream_ConnectClient
	logger        *log.Logger

	mu       sync.Mutex
	sendCh   chan *pb.NodeMessage
	recvCh   chan *pb.GatewayMessage
	closeCh  chan struct{}
	closed   bool
	nodeInfo *pb.NodeHello

	writeTimeout time.Duration
}

// Stream protocol version negotiation (gateway↔sandlot), sandlot side. Sent
// as NodeHello.protocol_version; must stay in lockstep with the gateway's
// stream.StreamProtocolVersion / StreamProtocolMinSupported. To evolve the
// protocol: make the change, bump this version on BOTH sides, and redeploy
// gateway+sandlot together.
//
// Version 1 is the INITIAL protocol and already includes the prov role
// (NodeHello.roles, ProvisionCommand/Response, HelloAck.reject_reason).
const ProtocolVersion = 1

// protocolVersionOK reports whether a gateway's HelloAck protocol version is
// speakable by this sandlot build. Extracted for unit testing.
func protocolVersionOK(ackVersion, ourVersion uint32) bool {
	return ackVersion == ourVersion
}

// Connect dials the gateway and establishes the bidirectional stream.
//
// tlsCfg enables TLS on the gateway<->sandlot stream. The connection is
// persistent (one per sandlot, heartbeat-kept), so the TLS 1.3 handshake is
// paid once at registration and the warm /agent/execute path only bears AES-GCM
// record encryption (microseconds, hardware-accelerated) — effectively zero
// latency burden. A nil tlsCfg falls back to plaintext (local dev/tests).
func Connect(ctx context.Context, gatewayAddr string, info *pb.NodeHello, tlsCfg *tls.Config, logger *log.Logger, cfg Config) (*Client, error) {
	if logger == nil {
		logger = log.Default()
	}

	// Apply safe defaults for zero-valued fields.
	sendBuf := cfg.SendBufferSize
	if sendBuf <= 0 {
		sendBuf = 64
	}
	recvBuf := cfg.RecvBufferSize
	if recvBuf <= 0 {
		recvBuf = 64
	}
	writeTimeout := cfg.WriteTimeout
	if writeTimeout <= 0 {
		writeTimeout = 30 * time.Second
	}

	var creds credentials.TransportCredentials
	if tlsCfg != nil {
		creds = credentials.NewTLS(tlsCfg)
	} else {
		creds = insecure.NewCredentials()
	}
	dialOpts := []grpc.DialOption{grpc.WithTransportCredentials(creds)}
	// gRPC keepalive detects a half-open gateway (partitioned, no FIN) in
	// ~Time+Timeout = ~8s instead of waiting for tcp_retries2 (~13-30min). This is
	// the sandlot-side trigger for entering TOLERATING (the state machine
	// tolerates the outage and cleans up after T_tolerance). PINGs go over the
	// always-open bidi stream; the gateway's enforcement policy (MinTime 5s) must
	// permit this cadence. PermitWithoutStream is set for safety though the
	// NodeStream bidi stream is always active.
	dialOpts = append(dialOpts, grpc.WithKeepaliveParams(keepalive.ClientParameters{
		Time:                6 * time.Second,
		Timeout:             2 * time.Second,
		PermitWithoutStream: true,
	}))
	// HTTP/2 flow-control windows + max message size. All commandId-multiplexed
	// messages share one HTTP/2 stream, so the per-stream window must accommodate
	// concurrent in-flight messages. MaxMsgSize must be >= the warden single-op
	// cap so a large FileOp payload is never rejected at gRPC.
	if cfg.InitialWindow > 0 {
		dialOpts = append(dialOpts, grpc.WithInitialWindowSize(cfg.InitialWindow))
	}
	if cfg.InitialConnWindow > 0 {
		dialOpts = append(dialOpts, grpc.WithInitialConnWindowSize(cfg.InitialConnWindow))
	}
	if cfg.MaxMsgSize > 0 {
		dialOpts = append(dialOpts, grpc.WithDefaultCallOptions(
			grpc.MaxCallSendMsgSize(cfg.MaxMsgSize),
			grpc.MaxCallRecvMsgSize(cfg.MaxMsgSize),
		))
	}
	conn, err := grpc.DialContext(ctx, gatewayAddr, dialOpts...)
	if err != nil {
		return nil, err
	}

	client := pb.NewNodeStreamClient(conn)
	stream, err := client.Connect(ctx)
	if err != nil {
		conn.Close()
		return nil, err
	}

	c := &Client{
		conn:         conn,
		stream:       stream,
		logger:       logger,
		sendCh:       make(chan *pb.NodeMessage, sendBuf),
		recvCh:       make(chan *pb.GatewayMessage, recvBuf),
		closeCh:      make(chan struct{}),
		nodeInfo:     info,
		writeTimeout: writeTimeout,
	}

	// Reconnect-clean invariant: release every mount BEFORE announcing
	// ourselves, so the gateway's OnConnect meets a node with zero mounts.
	if cfg.BeforeHello != nil {
		cfg.BeforeHello()
	}

	// Send NodeHello (carrying our stream protocol version — the gateway
	// rejects the handshake if it cannot speak it).
	info.ProtocolVersion = ProtocolVersion
	if err := stream.Send(&pb.NodeMessage{
		NodeId: info.NodeId,
		Payload: &pb.NodeMessage_Hello{
			Hello: info,
		},
	}); err != nil {
		conn.Close()
		return nil, err
	}

	// Wait for HelloAck. A gateway that rejected our protocol version
	// terminates the stream here; keep the error's context (a rejection
	// carries the gateway's supported range) so the reconnect loop logs
	// something diagnosable instead of a bare "connect failed".
	ackMsg, err := stream.Recv()
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("gateway %s handshake failed (this sandlot speaks stream protocol %d): %w",
			gatewayAddr, ProtocolVersion, err)
	}
	ack := ackMsg.GetHelloAck()
	// NAMED REJECTION: a non-empty reject_reason means the gateway is refusing
	// this connection (e.g. a prov instance dialing an exec-only gateway).
	// Surface the reason verbatim — the reconnect loop logs it and moves to
	// the next configured address instead of hammering an endpoint that will
	// never accept this instance's roles.
	if rr := ack.GetRejectReason(); rr != "" {
		conn.Close()
		return nil, fmt.Errorf("gateway %s rejected this connection: %s", gatewayAddr, rr)
	}
	// Symmetric version check against the NEGOTIATED ECHO: the gateway acks
	// the hello's protocol_version (validated into its supported range), so
	// the ack must equal the version WE sent. A mismatch means the peer does
	// not actually speak our version (pre-versioning build acks 0, or a peer
	// that ignored the echo contract) — fail fast rather than interpret
	// commands under contested semantics.
	if ackv := ack.GetProtocolVersion(); !protocolVersionOK(ackv, ProtocolVersion) {
		conn.Close()
		return nil, fmt.Errorf("gateway %s acks stream protocol version %d, this sandlot speaks %d — deploy matching gateway/sandlot builds",
			gatewayAddr, ackv, ProtocolVersion)
	}

	logger.Printf("connected to gateway at %s (gateway_id=%s)",
		gatewayAddr, ack.GetGatewayId())

	// Start read/write goroutines
	go c.readLoop()
	go c.writeLoop()

	return c, nil
}

// Commands returns the channel of incoming gateway commands.
func (c *Client) Commands() <-chan *pb.GatewayMessage {
	return c.recvCh
}

// Done returns a channel that is closed when the stream has died (read or write
// error, or an explicit Close). The reconnect loop in main selects on this to
// trigger a backoff retry instead of exiting. It is closed exactly once.
func (c *Client) Done() <-chan struct{} {
	return c.closeCh
}

// SendResponse sends a command response back to the gateway.
// sanitizeCommandResponse makes every string field valid UTF-8 before the
// protobuf marshal. Warden-controlled bytes (a malicious or compromised
// in-guest server) can carry arbitrary byte sequences; proto3 string fields
// reject invalid UTF-8 at marshal time, and the writeLoop closes the shared
// node stream on a marshal error — one hostile field would reset every
// tenant's command traffic on the node. Replacing the invalid bytes is lossless
// for the legitimate path (already-valid strings pass through unchanged).
func sanitizeCommandResponse(resp *pb.CommandResponse) {
	if resp == nil {
		return
	}
	const repl = "�"
	resp.CommandId = strings.ToValidUTF8(resp.CommandId, repl)
	resp.Error = strings.ToValidUTF8(resp.Error, repl)
	resp.VmId = strings.ToValidUTF8(resp.VmId, repl)
	resp.Stdout = strings.ToValidUTF8(resp.Stdout, repl)
	resp.ExecId = strings.ToValidUTF8(resp.ExecId, repl)
	resp.Status = strings.ToValidUTF8(resp.Status, repl)
	resp.Stderr = strings.ToValidUTF8(resp.Stderr, repl)
	resp.Spec = strings.ToValidUTF8(resp.Spec, repl)
	resp.ErrorCode = strings.ToValidUTF8(resp.ErrorCode, repl)
}

func (c *Client) SendResponse(resp *pb.CommandResponse) error {
	sanitizeCommandResponse(resp)
	return c.send(&pb.NodeMessage{
		NodeId: c.nodeInfo.NodeId,
		Payload: &pb.NodeMessage_Response{
			Response: resp,
		},
	})
}

// SendProvisionResponse sends a prov-role response back to the gateway.
func (c *Client) SendProvisionResponse(resp *pb.ProvisionResponse) error {
	return c.send(&pb.NodeMessage{
		NodeId: c.nodeInfo.NodeId,
		Payload: &pb.NodeMessage_ProvisionResponse{
			ProvisionResponse: resp,
		},
	})
}

// SendEvent sends an async VM event to the gateway.
func (c *Client) SendEvent(ev *pb.VMEvent) error {
	return c.send(&pb.NodeMessage{
		NodeId: c.nodeInfo.NodeId,
		Payload: &pb.NodeMessage_VmEvent{
			VmEvent: ev,
		},
	})
}

// SendHeartbeat sends a heartbeat to the gateway, including per-VM free memory
// (MemAvailable, bytes) for the OOM-B reclaim threshold, per-spec CLEAN/total
// capacity for node selection, and scheduling metrics. vmMem may be nil.
//
// seedGeneration / seedStagedGeneration are this PROV instance's naming
// generation fingerprints (volname.Fingerprint — never seed material), empty
// on exec-only instances. The gateway projects them per node in /stats: with
// storage ops spread across prov instances, a rotation must be able to prove
// that EVERY instance converged before the maintenance window closes.
// SetEgressBinding records the node's egress identity-binding mode for every
// subsequent heartbeat ("none"/"shm"/"bpf"/"routed-ipv6").
func (c *Client) SetEgressBinding(mode string) {
	c.mu.Lock()
	c.egressBinding = mode
	c.mu.Unlock()
}

func (c *Client) SendHeartbeat(vmCount uint32, vmIDs []string, vmMem []*pb.VmMemInfo, specCap []*pb.SpecCapacity, metrics *pb.NodeMetrics,
	seedGeneration string, seedStaged bool, seedStagedGeneration string) error {
	c.mu.Lock()
	egressBinding := c.egressBinding
	c.mu.Unlock()
	return c.send(&pb.NodeMessage{
		NodeId: c.nodeInfo.NodeId,
		Payload: &pb.NodeMessage_Heartbeat{
			Heartbeat: &pb.Heartbeat{
				ActiveVmCount:        vmCount,
				ActiveVmIds:          vmIDs,
				VmMem:                vmMem,
				SpecCapacity:         specCap,
				Metrics:              metrics,
				SeedGeneration:       seedGeneration,
				SeedStaged:           seedStaged,
				SeedStagedGeneration: seedStagedGeneration,
				EgressBinding:        egressBinding,
			},
		},
	})
}

func (c *Client) send(msg *pb.NodeMessage) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return errClosed
	}
	select {
	case c.sendCh <- msg:
		return nil
	default:
		return errQueueFull
	}
}

func (c *Client) readLoop() {
	for {
		msg, err := c.stream.Recv()
		if err != nil {
			c.logger.Printf("stream read error: %v", err)
			c.Close()
			return
		}
		select {
		case c.recvCh <- msg:
		case <-c.closeCh:
			return
		}
	}
}

func (c *Client) writeLoop() {
	timeout := c.writeTimeout
	// One reusable timer for the whole loop — a fresh time.After per message
	// would pile up unfired 30s timers in the runtime timer heap at stream
	// throughput.
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		select {
		case <-c.closeCh:
			return
		case msg := <-c.sendCh:
			// Write timeout: a half-open TCP connection can block Send
			// indefinitely on the write side while the read side (heartbeat)
			// stays functional. Bounding it triggers a reconnect so the sendCh
			// does not fill up and back-pressure the cmdSem.
			done := make(chan struct{})
			var sendErr error
			go func() {
				sendErr = c.stream.Send(msg)
				close(done)
			}()
			// Re-arm: the previous iteration may have exited its select via
			// done/closeCh with the timer still armed.
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(timeout)
			select {
			case <-done:
				if sendErr != nil {
					c.logger.Printf("stream write error: %v", sendErr)
					c.Close()
					return
				}
			case <-c.closeCh:
				// Disconnect during an in-flight Send: return immediately (the
				// Send goroutine's result is discarded).
				return
			case <-timer.C:
				c.logger.Printf("stream write timeout (%v), closing connection", timeout)
				c.Close()
				return
			}
		}
	}
}

// Close closes the client connection.
func (c *Client) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	c.closed = true
	close(c.closeCh)
	c.conn.Close()
}

var (
	errClosed    = errType("connection closed")
	errQueueFull = errType("send queue full")
)

type errType string

func (e errType) Error() string { return string(e) }

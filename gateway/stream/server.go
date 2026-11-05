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
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	pb "common/proto/stream"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

// Server is the gateway-side stream server that sandlot nodes connect to.
type Server struct {
	pb.UnimplementedNodeStreamServer

	mu           sync.RWMutex
	nodes        map[string]*NodeConnection
	onConnect    func(*NodeConnection)
	onDisconnect func(nc *NodeConnection) // invoked when a sandlot disconnects
	onEvent      func(*NodeConnection, *pb.VMEvent)
	onHeartbeat  func(nodeID string, vmCount uint32, vmIDs []string, vmMem []*pb.VmMemInfo, specCap []*pb.SpecCapacity, metrics *pb.NodeMetrics)
	gatewayID    string
	logger       *log.Logger
	// acceptedRoles is the set of connection roles this gateway serves,
	// derived from its mode/endpoints by the app wiring (exec-only gateway →
	// [exec]; human-only → [prov]; single-node/unified → both). A connection
	// advertising no accepted role is rejected with a named reason. nil
	// defaults to [exec] (the pre-roles shape).
	acceptedRoles []string

	// sendBufferSize is the per-node sendCh capacity (max in-flight commands
	// before ErrSendQueueFull). Also reported as MaxConcurrentVms in HelloAck.
	sendBufferSize int
	// writeTimeout is the max wait for a stream.Send; detects half-open TCP.
	writeTimeout time.Duration
}

// Stream protocol version negotiation (gateway↔sandlot). The stream protocol
// is the wire semantics of this .proto's messages; StreamProtocolVersion is
// what THIS build speaks (sent in HelloAck), and the gateway accepts a
// sandlot's NodeHello.protocol_version anywhere in
// [StreamProtocolMinSupported, StreamProtocolVersion]. A sandlot outside the
// range is REJECTED at the handshake — a mixed-version rolling upgrade fails
// fast with one clear log line instead of runtime misinterpretation of
// changed message semantics. To evolve the protocol: make the change, bump
// StreamProtocolVersion, and raise StreamProtocolMinSupported to the oldest
// version still handled correctly (no-compat policy: while no production
// fleets exist, keep them equal and redeploy gateway+sandlot together).
//
// Version 1 is the INITIAL protocol and already includes the prov role:
// NodeHello.roles (role advertisement), ProvisionCommand/ProvisionResponse
// (sandfs + template lifecycle ops, routed only to prov-advertising
// connections), and HelloAck.reject_reason (named handshake rejection for
// role mismatches). Pre-production: no compat window, no bumps yet.
const (
	StreamProtocolVersion      = 1
	StreamProtocolMinSupported = 1
)

// errStreamProtocolVersion rejects a sandlot whose NodeHello.protocol_version
// falls outside the supported range. Var (not const) so tests can match it.
var errStreamProtocolVersion = errors.New("stream protocol version unsupported")

// errStreamRoles rejects a sandlot advertising roles this gateway does not
// accept (e.g. a prov instance dialing an exec-only gateway). The rejected
// instance receives a HelloAck carrying reject_reason before the stream
// closes, so its log names the fix instead of a bare EOF.
var errStreamRoles = errors.New("connection roles not accepted")

// errStreamNodeIdentity rejects a sandlot whose declared node_id is not bound
// to the TLS client certificate it presented(). See verifyNodeIdentity.
var errStreamNodeIdentity = errors.New("stream node identity not bound")

// Known roles. A hello advertising anything else is rejected — an unknown
// role means a newer build with capabilities this gateway does not understand.
const (
	RoleExec = "exec"
	RoleProv = "prov"
)

// NewServer creates a new stream server. sendBufferSize sets the per-node
// in-flight command capacity (default 64 if <=0); writeTimeout bounds a
// blocking stream.Send for half-open detection.
func NewServer(gatewayID string, logger *log.Logger, sendBufferSize int, writeTimeout time.Duration) *Server {
	if logger == nil {
		logger = log.Default()
	}
	if sendBufferSize <= 0 {
		sendBufferSize = 64
	}
	if writeTimeout <= 0 {
		writeTimeout = 30 * time.Second
	}
	return &Server{
		nodes:          make(map[string]*NodeConnection),
		gatewayID:      gatewayID,
		logger:         logger,
		sendBufferSize: sendBufferSize,
		writeTimeout:   writeTimeout,
	}
}

// OnConnect registers a callback invoked when a sandlot connects.
func (s *Server) OnConnect(fn func(*NodeConnection)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onConnect = fn
}

// SetAcceptedRoles defines which connection roles this gateway serves. Call
// before serving (the app wiring derives it from the gateway's mode: exec
// listener → [exec], human listener → [prov], unified → both). nil/[]
// defaults to [exec].
func (s *Server) SetAcceptedRoles(roles []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(roles) == 0 {
		roles = []string{RoleExec}
	}
	s.acceptedRoles = append([]string(nil), roles...)
}

func (s *Server) roleAccepted(role string) bool {
	s.mu.RLock()
	accepted := s.acceptedRoles
	s.mu.RUnlock()
	if len(accepted) == 0 {
		accepted = []string{RoleExec}
	}
	for _, a := range accepted {
		if a == role {
			return true
		}
	}
	return false
}

// helloRoles normalizes a hello's role advertisement: empty means the
// pre-roles legacy shape (exec-only).
func helloRoles(hello *pb.NodeHello) []string {
	if r := hello.GetRoles(); len(r) > 0 {
		return r
	}
	return []string{RoleExec}
}

// OnDisconnect registers a callback invoked when a sandlot disconnects.
// The callback receives the disconnected connection (NodeID + advertised
// roles survive the close). Use this to clean up pool entries and release
// leases for VMs on the disconnected node — prov-only connections were never
// registered anywhere and must clean nothing.
func (s *Server) OnDisconnect(fn func(nc *NodeConnection)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onDisconnect = fn
}

// OnEvent registers a callback for async VM events.
func (s *Server) OnEvent(fn func(*NodeConnection, *pb.VMEvent)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onEvent = fn
}

// OnHeartbeat registers a callback invoked on each sandlot heartbeat. It carries
// the live VM count + id list, per-VM guest memory samples (for recycle) and
// per-spec clean/total capacity (for delegation: gateway node selection).
func (s *Server) OnHeartbeat(fn func(nodeID string, vmCount uint32, vmIDs []string, vmMem []*pb.VmMemInfo, specCap []*pb.SpecCapacity, metrics *pb.NodeMetrics)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onHeartbeat = fn
}

// Connect handles a bidirectional stream from a sandlot node.
func (s *Server) Connect(stream pb.NodeStream_ConnectServer) error {
	// Read NodeHello
	msg, err := stream.Recv()
	if err != nil {
		return err
	}

	hello := msg.GetHello()
	if hello == nil {
		return ErrExpectedHello
	}

	// Protocol version gate: reject BEFORE registering the node or running any
	// OnConnect machinery. The returned error also terminates the stream, so a
	// rejected sandlot sees its dial fail (and logs its own mismatch view — it
	// received no HelloAck). Zero means the field was not set at all (a build
	// from before versioning existed) — same verdict, clearer message.
	pv := hello.GetProtocolVersion()
	if pv < StreamProtocolMinSupported || pv > StreamProtocolVersion {
		s.logger.Printf("node %q rejected: stream protocol version %d outside supported range [%d,%d] (sandlot build %q) — deploy matching gateway/sandlot builds",
			hello.NodeId, pv, StreamProtocolMinSupported, StreamProtocolVersion, hello.Version)
		return fmt.Errorf("node %s: %w: got %d, supported [%d,%d]",
			hello.NodeId, errStreamProtocolVersion, pv, StreamProtocolMinSupported, StreamProtocolVersion)
	}

	// Node-identity gate(): the declared node_id must be BOUND to the
	// TLS client identity. Without it, one deployment-wide client certificate
	// lets any host that holds it claim another node's id — receive that
	// node's VMCommands (agent code, volume paths, file contents) and answer
	// them. The rule is exact-match CN == node_id; deployments mint one
	// client certificate per node (CN=<node-id>; the cert tooling does this).
	// A connection presenting NO certificate at all cannot be checked and is
	// REFUSED by name (a plaintext listener, or a TLS listener whose client
	// certificate requirement was misconfigured). Production deployments must
	// configure stream mTLS: -stream-tls-cert/-key on the gateway and
	// -stream-tls-ca to verify the per-node client certificates.
	if reason := s.verifyNodeIdentity(stream.Context(), hello.NodeId); reason != "" {
		s.logger.Printf("node %q rejected: %s (sandlot build %q)", hello.NodeId, reason, hello.Version)
		_ = stream.Send(&pb.GatewayMessage{
			Payload: &pb.GatewayMessage_HelloAck{
				HelloAck: &pb.HelloAck{
					GatewayId:       s.gatewayID,
					ProtocolVersion: pv,
					RejectReason:    reason,
				},
			},
		})
		return fmt.Errorf("node %s: %w: %s", hello.NodeId, errStreamNodeIdentity, reason)
	}

	// Role gate: the connection must advertise at least one role this gateway
	// accepts, and nothing outside the known set {exec, prov}. Rejection
	// carries a NAMED reason in the HelloAck (the instance logs it verbatim
	// and moves on to its next configured gateway address) instead of a bare
	// stream death the operator has to forensically reconstruct.
	advertised := helloRoles(hello)
	var unknown, unaccepted []string
	for _, r := range advertised {
		if r != RoleExec && r != RoleProv {
			unknown = append(unknown, r)
			continue
		}
		if !s.roleAccepted(r) {
			unaccepted = append(unaccepted, r)
		}
	}
	var rejectReason string
	switch {
	case len(unknown) > 0:
		rejectReason = fmt.Sprintf("unknown roles %v advertised (known: %s,%s) — deploy a matching gateway build", unknown, RoleExec, RoleProv)
	case len(unaccepted) > 0 && len(unaccepted) == len(advertised):
		s.mu.RLock()
		acc := s.acceptedRoles
		s.mu.RUnlock()
		if len(acc) == 0 {
			acc = []string{RoleExec}
		}
		rejectReason = fmt.Sprintf("roles not accepted: instance advertises %v but this gateway accepts %v — point prov instances at a human/unified gateway", advertised, acc)
	}
	if rejectReason != "" {
		s.logger.Printf("node %q rejected: %s (sandlot build %q)", hello.NodeId, rejectReason, hello.Version)
		// Best-effort named-rejection ack before the stream terminates; a
		// send failure just falls through to the returned error.
		_ = stream.Send(&pb.GatewayMessage{
			Payload: &pb.GatewayMessage_HelloAck{
				HelloAck: &pb.HelloAck{
					GatewayId:       s.gatewayID,
					ProtocolVersion: pv,
					RejectReason:    rejectReason,
				},
			},
		})
		return fmt.Errorf("node %s: %w: %s", hello.NodeId, errStreamRoles, rejectReason)
	}

	// Certificate-role binding: the advertised roles must be a SUBSET of the
	// role URIs on the verified client certificate. Self-reporting alone let
	// any node certificate join the storage plane; the certificate is the
	// issuance-time grant. (verifyNodeIdentity above already refused a
	// certificate-less stream, so the leaf is present here.)
	leaf, leafReason := peerLeaf(stream.Context())
	if leafReason == "" {
		leafReason = roleBindingRefusal(leaf, advertised)
	}
	if leafReason != "" {
		s.logger.Printf("node %q rejected: %s (sandlot build %q)", hello.NodeId, leafReason, hello.Version)
		_ = stream.Send(&pb.GatewayMessage{
			Payload: &pb.GatewayMessage_HelloAck{
				HelloAck: &pb.HelloAck{
					GatewayId:       s.gatewayID,
					ProtocolVersion: pv,
					RejectReason:    leafReason,
				},
			},
		})
		return fmt.Errorf("node %s: %w: %s", hello.NodeId, errStreamRoles, leafReason)
	}

	nc := NewNodeConnection(hello, stream, s.sendBufferSize)

	s.mu.Lock()
	// A sandlot reconnect (same nodeID, new stream) overwrites the registry
	// entry. Close the old connection so its writeLoop/readLoop goroutines exit
	// promptly (Close -> closeCh -> writeLoop returns -> Connect returns -> gRPC
	// cancels the old stream -> readLoop's Recv unblocks). Do NOT call
	// removeNode here: the old connection's cleanup must not fire onDisconnect
	// for a node that is actively reconnecting (removeNode's pointer guard
	// `cur == nc` already makes that a no-op once we overwrite the entry).
	if old, ok := s.nodes[hello.NodeId]; ok && old != nc {
		old.Close()
	}
	s.nodes[hello.NodeId] = nc
	onConnect := s.onConnect
	s.mu.Unlock()

	// Register cleanup NOW so a panic in onConnect (or any later step before
	// readLoop/writeLoop take over) cannot leave a registered-but-orphaned
	// connection. removeNode is idempotent (pointer guard `cur == nc`), so this
	// is safe alongside readLoop's own defer removeNode and the explicit call
	// on HelloAck-send failure below.
	defer s.removeNode(nc)

	s.logger.Printf("node %q connected (version=%s, cpus=%d, mem=%dMB, roles=%v)",
		hello.NodeId, hello.Version, hello.TotalCpus, hello.TotalMemoryMb, advertised)

	// Send HelloAck
	if err := stream.Send(&pb.GatewayMessage{
		Payload: &pb.GatewayMessage_HelloAck{
			HelloAck: &pb.HelloAck{
				GatewayId:        s.gatewayID,
				MaxConcurrentVms: uint32(s.sendBufferSize),
				// NEGOTIATED ECHO: ack the version the sandlot announced (it
				// passed the gate above, so it is within [Min, Current]) —
				// this connection speaks THAT version. This is what makes the
				// compat window work: a new gateway (say [1,2]) acks 1 to an
				// old sandlot, whose exact-match check then accepts. Aking our
				// own current version instead would abort every in-window old
				// peer at the ack check and make MinSupported decorative.
				ProtocolVersion: pv,
			},
		},
	}); err != nil {
		s.removeNode(nc)
		return err
	}

	if onConnect != nil {
		onConnect(nc)
	}

	// Read loop
	go s.readLoop(nc)

	// Write loop
	return s.writeLoop(nc)
}

func (s *Server) readLoop(nc *NodeConnection) {
	defer s.removeNode(nc)

	for {
		msg, err := nc.stream.Recv()
		if err != nil {
			if err != io.EOF {
				s.logger.Printf("node %q read error: %v", nc.NodeID, err)
			}
			nc.Close()
			return
		}

		switch {
		case msg.GetResponse() != nil:
			nc.deliverResponse(msg.GetResponse())

		case msg.GetProvisionResponse() != nil:
			nc.deliverProvisionResponse(msg.GetProvisionResponse())

		case msg.GetVmEvent() != nil:
			s.mu.RLock()
			onEvent := s.onEvent
			s.mu.RUnlock()
			if onEvent != nil {
				onEvent(nc, msg.GetVmEvent())
			}

		case msg.GetHeartbeat() != nil:
			hb := msg.GetHeartbeat()
			// Record the prov-role naming generations BEFORE the
			// callback: /stats reads them straight off the connection, and a
			// rotation's close-window proof must never depend on a consumer
			// having been wired. Only a PROV connection may feed this view:
			// the convergence gate blocks on what it sees, so an exec node
			// (or a legacy no-roles one) reporting a generation could wedge
			// the window with a generation it can never derive names from.
			if seedReportAdmissible(nc, hb) {
				nc.SetSeedReport(hb.GetSeedGeneration(), hb.GetSeedStaged(), hb.GetSeedStagedGeneration())
				nc.SetEgressBinding(hb.GetEgressBinding())
			}
			s.mu.RLock()
			onHeartbeat := s.onHeartbeat
			s.mu.RUnlock()
			// Always fire (no vmMem guard): a heartbeat with zero VMs is itself
			// meaningful — it tells the gateway the node has no live VMs, so any
			// pool entries for it are stale and should be reconciled away.
			if onHeartbeat != nil {
				onHeartbeat(nc.NodeID, hb.GetActiveVmCount(), hb.GetActiveVmIds(), hb.GetVmMem(), hb.GetSpecCapacity(), hb.GetMetrics())
			}
		}
	}
}

// writeSendTimeout is the fallback max time to wait for a stream Send to
// complete when NewServer is constructed without an explicit timeout. A
// half-open TCP connection can block Send indefinitely on the write side
// even while the read side (heartbeat) is still functional. This timeout
// detects such half-open connections and triggers a full disconnect + cleanup.
const writeSendTimeout = 30 * time.Second

func (s *Server) writeLoop(nc *NodeConnection) error {
	timeout := s.writeTimeout
	if timeout <= 0 {
		timeout = writeSendTimeout
	}
	// One reusable timer for the whole loop. time.After(timeout) per message
	// would leave an unfired 30s timer in the runtime timer heap for every
	// message sent — at stream throughput (thousands of msgs/s across nodes)
	// that is hundreds of thousands of live timers of pure GC/timer-wheel
	// pressure.
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	// One resident sender goroutine owns stream.Send for the connection's
	// lifetime, fed one message at a time via items. This replaces the prior
	// per-message goroutine: at high throughput that was thousands of
	// goroutine create/destroy cycles per second, and more importantly each
	// in-flight Send anchored a goroutine holding the message (up to 16MB for a
	// FileOp). With a resident sender only ONE message is ever in flight, and
	// on write timeout Close() cancels the gRPC stream, unblocking the single
	// in-flight Send so its message reference is released. items is buffered 1
	// so feeding it never blocks while the sender is busy with the previous
	// Send; ack is buffered 1 so the sender never blocks writing the result
	// when writeLoop has already moved on (e.g. after a timeout).
	type sendItem struct {
		msg *pb.GatewayMessage
		ack chan error
	}
	items := make(chan sendItem, 1)
	go func() {
		for it := range items {
			it.ack <- nc.stream.Send(it.msg)
		}
	}()
	defer close(items) // signal the resident sender to exit when writeLoop returns

	for {
		select {
		case <-nc.closeCh:
			return nil
		case msg := <-nc.sendCh:
			// Write timeout: if Send blocks beyond `timeout`, the
			// connection is likely half-open. Close it and trigger full
			// cleanup (OnDisconnect → RemoveNode + ReleaseByNode).
			ack := make(chan error, 1)
			// Re-arm: the previous iteration may have exited its select via
			// ack/closeCh with the timer still armed.
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(timeout)
			items <- sendItem{msg: msg, ack: ack}
			select {
			case err := <-ack:
				if err != nil {
					s.logger.Printf("node %q write error: %v", nc.NodeID, err)
					nc.Close()
					return err
				}
			case <-nc.closeCh:
				// Disconnect during an in-flight Send: return immediately so
				// Connect unwinds. The resident sender's in-flight Send
				// unblocks when the stream is cancelled; its result (written
				// to the buffered ack) is discarded.
				return nil
			case <-timer.C:
				s.logger.Printf("node %q write timeout (%v), closing connection", nc.NodeID, timeout)
				nc.Close()
				return io.ErrClosedPipe
			}
		}
	}
}

// GetNode returns the connection for a node ID.
func (s *Server) GetNode(nodeID string) (*NodeConnection, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	nc, ok := s.nodes[nodeID]
	if !ok || nc.IsClosed() {
		return nil, ErrNodeNotFound
	}
	return nc, nil
}

// NodeSeedReports returns every connected PROV node's latest
// naming-generation report, sorted by node id. Only nodes that reported one
// appear. The view is THIS gateway's connections: in a deployment with more
// than one human gateway, a prov instance dialed elsewhere is invisible here
// (see docs/integration/volume-seed.md — the rotation procedure must run the
// convergence check against every human gateway).
func (s *Server) NodeSeedReports() []NodeSeedReport {
	s.mu.RLock()
	conns := make([]*NodeConnection, 0, len(s.nodes))
	for _, nc := range s.nodes {
		if !nc.IsClosed() {
			conns = append(conns, nc)
		}
	}
	s.mu.RUnlock()

	out := make([]NodeSeedReport, 0, len(conns))
	for _, nc := range conns {
		rep := nc.SeedState()
		if rep == nil {
			continue
		}
		out = append(out, NodeSeedReport{NodeID: nc.NodeID, SeedReport: *rep})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].NodeID < out[j].NodeID })
	return out
}

// NodeEgressBindings returns each connected node's last reported egress
// identity-binding mode, sorted by node id. "none" means the node cannot
// attribute guest traffic to an agent (a dev/test posture).
func (s *Server) NodeEgressBindings() map[string]string {
	s.mu.RLock()
	conns := make([]*NodeConnection, 0, len(s.nodes))
	for _, nc := range s.nodes {
		if !nc.IsClosed() {
			conns = append(conns, nc)
		}
	}
	s.mu.RUnlock()
	out := make(map[string]string, len(conns))
	for _, nc := range conns {
		if mode := nc.EgressBinding(); mode != "" {
			out[nc.NodeID] = mode
		}
	}
	return out
}

// NodeSeedReport is one node's seed report, addressed by node id.
type NodeSeedReport struct {
	NodeID string `json:"node_id"`
	SeedReport
}

// verifyNodeIdentity checks the hello's declared node_id against the TLS
// client certificate the connection actually presented(). Returns "" to
// accept, or the NAMED rejection reason.
//
// The threat: nodes are addressable state. The gateway routes a sandfs's
// VMCommands by node_id, so a party that can claim another node's id receives
// that node's commands — agent code, volume paths, file contents — and its
// answers are accepted. With one deployment-wide client certificate every
// host holding that certificate could do exactly that. Binding requires one
// certificate per node: CN=<node-id>,
// which the cert tooling mints and the deployers install.
//
// A connection with NO client certificate has no identity to check and is
// REFUSED: accepting it would leave the stream unauthenticated while
// looking healthy. The TLS listener config makes this state unreachable: the
// gateway refuses to start the stream without -stream-tls-ca, and the TLS
// layer then requires and verifies a per-node certificate
// (RequireAndVerifyClientCert) before this handler sees the peer. A plaintext
// listener reaches this branch for every peer (there is no certificate to
// present) and is therefore refused by name.
func (s *Server) verifyNodeIdentity(ctx context.Context, nodeID string) string {
	leaf, reason := peerLeaf(ctx)
	if reason != "" {
		return reason
	}
	cn := leaf.Subject.CommonName
	if cn == nodeID {
		return ""
	}
	return fmt.Sprintf(
		"certificate CN %q does not match declared node_id %q — the stream plane binds node identity to the client certificate; "+
			"issue a per-node certificate with CN=<node-id> and point this instance at it (a shared client certificate is no longer accepted)",
		cn, nodeID)
}

// peerLeaf returns the verified TLS client leaf certificate. A non-empty
// reason means there is no certificate to inspect (a plaintext listener, or a
// TLS listener whose client-certificate requirement was misconfigured).
func peerLeaf(ctx context.Context) (*x509.Certificate, string) {
	p, ok := peer.FromContext(ctx)
	if !ok || p.AuthInfo == nil {
		return nil, noClientCertReason()
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return nil, noClientCertReason()
	}
	chain := tlsInfo.State.PeerCertificates
	if len(chain) == 0 {
		return nil, noClientCertReason()
	}
	return chain[0], ""
}

// Role markers are URI SANs on the per-node client certificate:
// sandswap://role/exec and sandswap://role/prov. The TLS layer has already
// verified the CA signature, so the markers are an issuance-time grant: a
// compromised node cannot claim a role its certificate was not issued for, and
// provisioning capacity scales by ISSUING A CERTIFICATE — never by editing
// gateway configuration (a static node-id allowlist would drift from the
// fleet, and every gateway replica would have to carry it).
const (
	roleURIScheme = "sandswap"
	roleURIHost   = "role"
)

// certRoles is the set of roles the certificate grants.
func certRoles(leaf *x509.Certificate) map[string]bool {
	roles := make(map[string]bool, 2)
	for _, u := range leaf.URIs {
		if u.Scheme != roleURIScheme || u.Host != roleURIHost {
			continue
		}
		switch strings.TrimPrefix(u.Path, "/") {
		case RoleExec:
			roles[RoleExec] = true
		case RoleProv:
			roles[RoleProv] = true
		}
	}
	return roles
}

// roleBindingRefusal returns a named refusal when any advertised role is not
// granted by the certificate. A certificate carrying NO role URI authorizes no
// role at all — there is deliberately no legacy fallback.
func roleBindingRefusal(leaf *x509.Certificate, advertised []string) string {
	granted := certRoles(leaf)
	var missing []string
	for _, r := range advertised {
		if !granted[r] {
			missing = append(missing, r)
		}
	}
	if len(missing) == 0 {
		return ""
	}
	return fmt.Sprintf(
		"certificate does not grant role(s) %v — the stream plane binds roles to the client certificate; "+
			"issue a per-node certificate carrying URI SAN %s://%s/<role> (exec, prov)",
		missing, roleURIScheme, roleURIHost)
}

// noClientCertReason is the named rejection for a stream that presented no
// client certificate. It names both halves of the fix: the node's client pair
// and the gateway's verifying CA.
func noClientCertReason() string {
	return "no TLS client certificate presented — the stream plane binds node identity to the client certificate; " +
		"configure the sandlot with -tls-cert/-tls-key and the gateway with -stream-tls-cert/-stream-tls-key/-stream-tls-ca (mTLS)"
}

// seedReportAdmissible decides whether one heartbeat may feed the
// naming-generation view: it must carry a generation AND come from a
// PROV-role connection. The convergence gate blocks on what it sees, so an
// exec node (or a legacy no-roles connection, which reads as exec) reporting
// a generation could wedge a rotation window with a generation it can never
// derive volume names from.
func seedReportAdmissible(nc *NodeConnection, hb *pb.Heartbeat) bool {
	if hb.GetSeedGeneration() == "" && !hb.GetSeedStaged() {
		return false
	}
	return nc.HasRole("prov")
}

// Nodes returns all connected node IDs (closed connections excluded).
func (s *Server) Nodes() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	ids := make([]string, 0, len(s.nodes))
	for id, nc := range s.nodes {
		if !nc.IsClosed() {
			ids = append(ids, id)
		}
	}
	return ids
}

// ProvNode returns a live connection advertising the given role (e.g.
// RoleProv for the provision client's routing). ErrNodeNotFound when none is
// connected — the provision client turns that into a named 503.
func (s *Server) RoleNode(role string) (*NodeConnection, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, nc := range s.nodes {
		if !nc.IsClosed() && nc.HasRole(role) {
			return nc, nil
		}
	}
	return nil, ErrNodeNotFound
}

// RoleNodes returns every live connection advertising the given role.
func (s *Server) RoleNodes(role string) []*NodeConnection {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*NodeConnection
	for _, nc := range s.nodes {
		if !nc.IsClosed() && nc.HasRole(role) {
			out = append(out, nc)
		}
	}
	return out
}

// removeNode deregisters a connection. It only removes the registry entry when
// it still points at THIS connection, so a reconnecting sandlot (same nodeID,
// new connection) is never clobbered by the old connection's cleanup, and
// onDisconnect fires exactly once per actual disconnect.
func (s *Server) removeNode(nc *NodeConnection) {
	s.mu.Lock()
	removed := false
	if cur, ok := s.nodes[nc.NodeID]; ok && cur == nc {
		delete(s.nodes, nc.NodeID)
		removed = true
	}
	// Close this (possibly already-closed) connection to release its pending
	// SendCommand waiters and unblock the writeLoop. Idempotent.
	nc.Close()
	onDisconnect := s.onDisconnect
	s.mu.Unlock()

	s.logger.Printf("node %q disconnected", nc.NodeID)

	// Fire the onDisconnect callback only when this connection was the active
	// one, and outside the lock so the callback (which may call
	// pool.RemoveNode + lease.ReleaseByNode) does not deadlock against a
	// concurrent GetNode or SendCommand. Gating on `removed` prevents (1) a
	// spurious callback when removeNode runs for an already-removed node, and
	// (2) the reconnect race where an old connection's cleanup would otherwise
	// delete + fire onDisconnect for a newer connection that replaced it.
	if removed && onDisconnect != nil {
		onDisconnect(nc)
	}
}

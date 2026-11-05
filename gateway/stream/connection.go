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
	"sync"
	"time"

	pb "common/proto/stream"
)

// NodeConnection represents an active sandlot connection.
type NodeConnection struct {
	NodeID  string
	Version string
	Info    *pb.NodeHello

	stream pb.NodeStream_ConnectServer

	mu          sync.Mutex
	pending     map[string]chan *pb.CommandResponse   // commandID -> response channel
	pendingProv map[string]chan *pb.ProvisionResponse // commandID -> provision response channel
	sendCh      chan *pb.GatewayMessage
	closeCh     chan struct{}
	closed      bool

	// seedMu guards seedReport: the prov role's naming generations this
	// node last reported (heartbeat). Only prov-role instances report one.
	seedMu     sync.Mutex
	egressMu   sync.Mutex
	egress     egressState
	seedReport *SeedReport
}

// egressMu guards egressBinding, the node's last reported egress
// identity-binding mode ("none"/"shm"/"bpf"/"routed-ipv6").
type egressState struct {
	mode        string
	updatedUnix int64
}

// SetEgressBinding records a heartbeat's egress identity-binding mode.
func (nc *NodeConnection) SetEgressBinding(mode string) {
	nc.egressMu.Lock()
	defer nc.egressMu.Unlock()
	nc.egress = egressState{mode: mode, updatedUnix: time.Now().Unix()}
}

// EgressBinding returns the last reported binding mode ("" when the node never
// reported one — an older build).
func (nc *NodeConnection) EgressBinding() string {
	nc.egressMu.Lock()
	defer nc.egressMu.Unlock()
	return nc.egress.mode
}

// SeedReport is a prov instance's naming-generation report, straight off its
// heartbeat. Fingerprints only (one-way 8-hex hashes) — never seed material.
//
// It exists so a rotation can prove that EVERY prov instance converged before
// the maintenance window closes: storage ops are spread across prov instances
// (the gateway re-picks per dial), so ONE instance still deriving names from
// the old generation silently splits tenants.
type SeedReport struct {
	Generation       string `json:"generation,omitempty"`
	Staged           bool   `json:"staged,omitempty"`
	StagedGeneration string `json:"staged_generation,omitempty"`
	// UpdatedUnix is when the last heartbeat carrying it was processed.
	UpdatedUnix int64 `json:"updated_unix,omitempty"`
}

// SetSeedReport records a heartbeat's naming-generation report.
func (nc *NodeConnection) SetSeedReport(generation string, staged bool, stagedGeneration string) {
	nc.seedMu.Lock()
	defer nc.seedMu.Unlock()
	nc.seedReport = &SeedReport{
		Generation:       generation,
		Staged:           staged,
		StagedGeneration: stagedGeneration,
		UpdatedUnix:      time.Now().Unix(),
	}
}

// SeedState returns the last report, or nil when this node never sent one
// (exec-only instances, or a prov instance from before the field existed).
func (nc *NodeConnection) SeedState() *SeedReport {
	nc.seedMu.Lock()
	defer nc.seedMu.Unlock()
	if nc.seedReport == nil {
		return nil
	}
	cp := *nc.seedReport
	return &cp
}

// NewNodeConnection creates a connection for a sandlot node. sendBufferSize
// sets the sendCh capacity (max in-flight commands before ErrSendQueueFull).
func NewNodeConnection(hello *pb.NodeHello, stream pb.NodeStream_ConnectServer, sendBufferSize int) *NodeConnection {
	if sendBufferSize <= 0 {
		sendBufferSize = 64
	}
	return &NodeConnection{
		NodeID:      hello.NodeId,
		Version:     hello.Version,
		Info:        hello,
		stream:      stream,
		pending:     make(map[string]chan *pb.CommandResponse),
		pendingProv: make(map[string]chan *pb.ProvisionResponse),
		sendCh:      make(chan *pb.GatewayMessage, sendBufferSize),
		closeCh:     make(chan struct{}),
	}
}

// Roles returns the capabilities this connection advertised. Empty
// NodeHello.roles means the pre-roles legacy shape: an exec node.
func (nc *NodeConnection) Roles() []string {
	if nc.Info == nil || len(nc.Info.GetRoles()) == 0 {
		return []string{"exec"}
	}
	return nc.Info.GetRoles()
}

// HasRole reports whether the connection serves the given role.
func (nc *NodeConnection) HasRole(role string) bool {
	for _, r := range nc.Roles() {
		if r == role {
			return true
		}
	}
	return false
}

// SendCommand sends a VMCommand to the sandlot and returns a channel that
// receives the response.
func (nc *NodeConnection) SendCommand(cmd *pb.VMCommand) (<-chan *pb.CommandResponse, error) {
	nc.mu.Lock()
	defer nc.mu.Unlock()

	if nc.closed {
		return nil, ErrConnectionClosed
	}

	ch := make(chan *pb.CommandResponse, 1)
	nc.pending[cmd.CommandId] = ch

	msg := &pb.GatewayMessage{
		Payload: &pb.GatewayMessage_VmCommand{VmCommand: cmd},
	}

	select {
	case nc.sendCh <- msg:
		return ch, nil
	default:
		delete(nc.pending, cmd.CommandId)
		close(ch)
		return nil, ErrSendQueueFull
	}
}

// SendProvisionCommand sends a ProvisionCommand (prov role: sandfs +
// template lifecycle) and returns a channel that receives the response. Same
// correlation machinery as SendCommand, keyed by commandID in a separate
// pending map so the two command families never collide.
func (nc *NodeConnection) SendProvisionCommand(cmd *pb.ProvisionCommand) (<-chan *pb.ProvisionResponse, error) {
	nc.mu.Lock()
	defer nc.mu.Unlock()

	if nc.closed {
		return nil, ErrConnectionClosed
	}

	ch := make(chan *pb.ProvisionResponse, 1)
	nc.pendingProv[cmd.CommandId] = ch

	msg := &pb.GatewayMessage{
		Payload: &pb.GatewayMessage_ProvisionCommand{ProvisionCommand: cmd},
	}

	select {
	case nc.sendCh <- msg:
		return ch, nil
	default:
		delete(nc.pendingProv, cmd.CommandId)
		close(ch)
		return nil, ErrSendQueueFull
	}
}

// deliverResponse routes a CommandResponse to the waiting caller.
func (nc *NodeConnection) deliverResponse(resp *pb.CommandResponse) {
	nc.mu.Lock()
	ch, ok := nc.pending[resp.CommandId]
	delete(nc.pending, resp.CommandId)
	nc.mu.Unlock()

	if ok {
		ch <- resp
		close(ch)
	}
}

// deliverProvisionResponse routes a ProvisionResponse to the waiting caller.
func (nc *NodeConnection) deliverProvisionResponse(resp *pb.ProvisionResponse) {
	nc.mu.Lock()
	ch, ok := nc.pendingProv[resp.CommandId]
	delete(nc.pendingProv, resp.CommandId)
	nc.mu.Unlock()

	if ok {
		ch <- resp
		close(ch)
	}
}

// Close marks the connection as closed and cleans up pending requests.
func (nc *NodeConnection) Close() {
	nc.mu.Lock()
	defer nc.mu.Unlock()

	if nc.closed {
		return
	}
	nc.closed = true

	for id, ch := range nc.pending {
		ch <- &pb.CommandResponse{
			CommandId: id,
			Success:   false,
			Error:     "connection closed",
		}
		close(ch)
	}
	nc.pending = nil

	for _, ch := range nc.pendingProv {
		// No synthetic response: a closed-empty channel reads as nil, which
		// storage.sendOne classifies as a TRANSPORT failure ("connection
		// closed") and retries on the next provision instance — ops are
		// idempotent, that failover is the design. A synthetic Success=false
		// response here masquerades as a node-side business refusal and
		// defeats the retry. The exec plane above keeps its synthetic
		// response: its waiters are not idempotent-retryable commands.
		close(ch)
	}
	nc.pendingProv = nil

	select {
	case <-nc.closeCh:
	default:
		close(nc.closeCh)
	}
}

// IsClosed returns whether the connection has been closed.
func (nc *NodeConnection) IsClosed() bool {
	nc.mu.Lock()
	defer nc.mu.Unlock()
	return nc.closed
}

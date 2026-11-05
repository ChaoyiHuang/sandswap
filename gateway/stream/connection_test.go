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
	"errors"
	"testing"
	"time"

	pb "common/proto/stream"
)

// newTestConn builds a NodeConnection with a fake stream and a fresh hello, for
// unit testing SendCommand/deliverResponse/Close without driving a full Connect.
func newTestConn(nodeID string) *NodeConnection {
	return NewNodeConnection(&pb.NodeHello{NodeId: nodeID, Version: "v1"}, newFakeStream(), 64)
}

// -------------------------------------------------------------------
// NewNodeConnection
// -------------------------------------------------------------------

// TestNewNodeConnection verifies the connection wrapper captures the hello
// identity and initializes the send/pending channels used by the command path.
func TestNewNodeConnection(t *testing.T) {
	hello := &pb.NodeHello{NodeId: "node-7", Version: "v9.9", TotalCpus: 8}
	nc := NewNodeConnection(hello, newFakeStream(), 8)

	if nc.NodeID != "node-7" {
		t.Errorf("NodeID: got %q, want node-7", nc.NodeID)
	}
	if nc.Version != "v9.9" {
		t.Errorf("Version: got %q, want v9.9", nc.Version)
	}
	if nc.Info != hello {
		t.Error("Info does not reference the original NodeHello")
	}
	if nc.IsClosed() {
		t.Error("new connection should not be closed")
	}
	if cap(nc.sendCh) != 8 {
		t.Errorf("sendCh capacity: got %d, want 8 (configured sendBufferSize)", cap(nc.sendCh))
	}
	if nc.pending == nil {
		t.Error("pending map should be initialized")
	}
}

// -------------------------------------------------------------------
// SendCommand
// -------------------------------------------------------------------

// TestSendCommandSuccess verifies the happy path: SendCommand registers a
// pending waiter and enqueues the VMCommand on sendCh (so writeLoop can send it
// to the sandlot). The returned channel is buffered and receives exactly one
// response.
func TestSendCommandSuccess(t *testing.T) {
	nc := newTestConn("node-1")
	cmd := &pb.VMCommand{CommandId: "cmd-1", Action: &pb.VMCommand_UnmountRootfs{UnmountRootfs: &pb.UnmountRootfs{}}}

	ch, err := nc.SendCommand(cmd)
	if err != nil {
		t.Fatalf("SendCommand: %v", err)
	}

	// The command was enqueued for the writeLoop to Send.
	select {
	case msg := <-nc.sendCh:
		if msg.GetVmCommand() == nil || msg.GetVmCommand().CommandId != "cmd-1" {
			t.Errorf("enqueued message: %+v", msg)
		}
	case <-time.After(time.Second):
		t.Fatal("VMCommand was not enqueued on sendCh")
	}

	// A pending waiter is registered; delivering a response reaches it.
	nc.deliverResponse(&pb.CommandResponse{CommandId: "cmd-1", Success: true, Stdout: "done"})
	select {
	case resp := <-ch:
		if !resp.Success || resp.Stdout != "done" {
			t.Errorf("unexpected response: %+v", resp)
		}
	case <-time.After(time.Second):
		t.Fatal("response not delivered")
	}

	// After delivery the pending entry is gone (no leak).
	nc.mu.Lock()
	left := len(nc.pending)
	nc.mu.Unlock()
	if left != 0 {
		t.Errorf("pending map should be empty after delivery, has %d", left)
	}
}

// TestSendCommandOnClosedConnection verifies SendCommand on a closed connection
// returns ErrConnectionClosed and does not enqueue anything.
func TestSendCommandOnClosedConnection(t *testing.T) {
	nc := newTestConn("node-1")
	nc.Close()

	_, err := nc.SendCommand(&pb.VMCommand{CommandId: "cmd-x"})
	if !errors.Is(err, ErrConnectionClosed) {
		t.Errorf("expected ErrConnectionClosed, got %v", err)
	}
	// Nothing should have been enqueued.
	select {
	case <-nc.sendCh:
		t.Error("closed connection should not enqueue a command")
	default:
	}
}

// TestSendCommandQueueFull verifies that when the sendCh buffer (cap 64) is
// full, SendCommand returns ErrSendQueueFull and cleans up its pending entry
// (so no leaked waiter that never gets a response). This protects the gateway
// from a slow sandlot write side back-pressuring unbounded memory growth.
func TestSendCommandQueueFull(t *testing.T) {
	nc := newTestConn("node-1")
	// Fill the send buffer completely (no writeLoop draining it).
	for i := 0; i < cap(nc.sendCh); i++ {
		nc.sendCh <- &pb.GatewayMessage{}
	}

	ch, err := nc.SendCommand(&pb.VMCommand{CommandId: "overflow"})
	if !errors.Is(err, ErrSendQueueFull) {
		t.Fatalf("expected ErrSendQueueFull, got %v", err)
	}
	// On queue-full SendCommand returns a nil channel (it closes the internal
	// waiter for cleanup but never exposes it). The caller must not receive a
	// channel it could block on.
	if ch != nil {
		t.Error("expected nil channel on queue-full, got non-nil")
	}

	// The pending entry for the overflow command must be cleaned up.
	nc.mu.Lock()
	_, present := nc.pending["overflow"]
	nc.mu.Unlock()
	if present {
		t.Error("pending entry for overflow command should be removed")
	}

	// Connection still usable for other ops (not closed).
	if nc.IsClosed() {
		t.Error("queue-full must not close the connection")
	}
}

// -------------------------------------------------------------------
// deliverResponse
// -------------------------------------------------------------------

// TestDeliverResponseUnknownCommand verifies a response for an unknown
// commandID (duplicate reply, or reply for a command never sent) is silently
// dropped without panicking.
func TestDeliverResponseUnknownCommand(t *testing.T) {
	nc := newTestConn("node-1")
	// Should not panic on an empty pending map.
	nc.deliverResponse(&pb.CommandResponse{CommandId: "ghost", Success: true})

	// Register a real waiter, then deliver for a different ID: real waiter stays.
	ch, _ := nc.SendCommand(&pb.VMCommand{CommandId: "real"})
	<-nc.sendCh // drain the enqueued command

	nc.deliverResponse(&pb.CommandResponse{CommandId: "ghost"})
	select {
	case <-ch:
		t.Error("real waiter should not receive a response meant for a ghost command")
	case <-time.After(20 * time.Millisecond):
		// good: still waiting
	}

	// Now deliver the real one.
	nc.deliverResponse(&pb.CommandResponse{CommandId: "real", Success: true})
	select {
	case resp := <-ch:
		if resp.CommandId != "real" {
			t.Errorf("got response %q, want real", resp.CommandId)
		}
	case <-time.After(time.Second):
		t.Error("real waiter did not receive its response")
	}
}

// TestDeliverResponseAfterClose verifies deliverResponse after Close does not
// panic (Close nils the pending map; reading a nil map is safe, writing is not
// - deliverResponse only reads).
func TestDeliverResponseAfterClose(t *testing.T) {
	nc := newTestConn("node-1")
	nc.Close()
	// Must not panic on nil pending map.
	nc.deliverResponse(&pb.CommandResponse{CommandId: "anything"})
}

// -------------------------------------------------------------------
// Close
// -------------------------------------------------------------------

// TestCloseIdempotent verifies Close can be called multiple times safely
// (readLoop and removeNode both call Close on the same connection).
func TestCloseIdempotent(t *testing.T) {
	nc := newTestConn("node-1")
	nc.Close()
	nc.Close() // must not panic (double close of closeCh would panic without the guard)
	nc.Close()
	if !nc.IsClosed() {
		t.Error("connection should be closed")
	}
}

// TestCloseReleasesPendingWaiters verifies Close fails all in-flight
// SendCommand waiters with an error response, so callers do not block forever
// when the sandlot disconnects mid-command.
func TestCloseReleasesPendingWaiters(t *testing.T) {
	nc := newTestConn("node-1")

	// Register several in-flight commands (don't drain sendCh so they stay pending).
	cmdIDs := []string{"c1", "c2", "c3"}
	chs := make([]<-chan *pb.CommandResponse, len(cmdIDs))
	for i, id := range cmdIDs {
		// Drain the enqueued message so SendCommand succeeds and the waiter stays
		// pending (waiting for the sandlot reply).
		ch, err := nc.SendCommand(&pb.VMCommand{CommandId: id})
		if err != nil {
			t.Fatalf("SendCommand(%s): %v", id, err)
		}
		<-nc.sendCh
		chs[i] = ch
	}

	nc.Close()

	for i, ch := range chs {
		select {
		case resp := <-ch:
			if resp.Success {
				t.Errorf("waiter %s: expected Success=false, got true", cmdIDs[i])
			}
			if resp.CommandId != cmdIDs[i] {
				t.Errorf("waiter %s: got CommandId %q", cmdIDs[i], resp.CommandId)
			}
			if resp.Error == "" {
				t.Errorf("waiter %s: expected non-empty error message", cmdIDs[i])
			}
		case <-time.After(time.Second):
			t.Errorf("waiter %s was not released by Close", cmdIDs[i])
		}
	}
}

// TestCloseClosesCloseCh verifies the closeCh signal is sent exactly once (used
// by writeLoop to terminate). The select-with-default guard must prevent a
// double-close panic.
func TestCloseClosesCloseCh(t *testing.T) {
	nc := newTestConn("node-1")
	select {
	case <-nc.closeCh:
		t.Fatal("closeCh should be open before Close")
	default:
	}
	nc.Close()
	select {
	case <-nc.closeCh:
		// good: writeLoop would now exit
	case <-time.After(time.Second):
		t.Fatal("closeCh should be closed after Close")
	}
}

// TestCloseFollowedBySendCommand verifies that after Close, new SendCommand
// calls fail fast with ErrConnectionClosed (not by blocking on a nil/nil send).
func TestCloseFollowedBySendCommand(t *testing.T) {
	nc := newTestConn("node-1")
	nc.Close()
	for i := 0; i < 5; i++ {
		if _, err := nc.SendCommand(&pb.VMCommand{CommandId: "x"}); !errors.Is(err, ErrConnectionClosed) {
			t.Errorf("SendCommand after Close #%d: got %v, want ErrConnectionClosed", i, err)
		}
	}
}

// -------------------------------------------------------------------
// IsClosed
// -------------------------------------------------------------------

// TestIsClosedTransitions verifies IsClosed reflects the close transition.
func TestIsClosedTransitions(t *testing.T) {
	nc := newTestConn("node-1")
	if nc.IsClosed() {
		t.Error("new connection should report open")
	}
	nc.Close()
	if !nc.IsClosed() {
		t.Error("closed connection should report closed")
	}
}

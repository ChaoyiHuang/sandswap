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

import "errors"

var (
	ErrConnectionClosed = errors.New("connection closed")
	ErrSendQueueFull    = errors.New("send queue full")
	ErrNodeNotFound     = errors.New("node not found")
	// ErrExpectedHello is returned by Connect when the first message received
	// from a sandlot is not a NodeHello. The handshake cannot proceed without
	// the node's identity, so the stream is terminated with this error (rather
	// than a nil error, which gRPC would interpret as a successful completion).
	ErrExpectedHello = errors.New("expected NodeHello as first message")
)

// IsStreamTransportError reports whether err is one of the stream-layer
// sentinel errors (connection closed, send queue full, node not found). These
// are transient gateway↔sandlot transport failures — the command never reached
// the sandlot, so the sandfs is NOT dirty. Callers should return a retryable
// 503 (NO_AVAILABLE_SANDBOX / NODE_UNAVAILABLE) and skip the heavy L2
// EnterCleaning + async-unmount path (which would needlessly block the sandfs
// for ~12s and fire an RPC at an already-dead/slow node).
//
// Errors are matched with errors.Is so this works through fmt.Errorf("%w", …)
// wrapping in pool.StreamSandlotClient.
func IsStreamTransportError(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, ErrConnectionClosed) ||
		errors.Is(err, ErrSendQueueFull) ||
		errors.Is(err, ErrNodeNotFound)
}

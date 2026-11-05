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

package config

import (
	"fmt"
	"math"
)

// The stream transport caps shared by the gateway and sandlot. Both sides
// accept the window/message sizes as YAML byte counts or CLI megabyte flags
// that are shifted to bytes before landing in the config struct — so the
// validation runs on BYTES and is identical for both components.
const (
	// Stream defaults shared by the gateway and sandlot. The values are
	// contract-aligned (gateway send buffer >= sandlot max concurrent
	// commands; both sides use the same HTTP/2 windows and message cap), so a
	// single named constant keeps the two Defaults() and the CLI flag defaults
	// from drifting apart.
	DefaultStreamSendBuffer            = 2000
	DefaultStreamRecvBuffer            = 2000
	DefaultStreamMaxConcurrentCommands = 2000
	DefaultStreamWriteTimeoutSec       = 30
	DefaultStreamInitialWindowMB       = 64
	DefaultStreamConnWindowMB          = 128
	DefaultStreamMaxMsgSizeMB          = 16

	// MinFileOpChainBytes is the documented floor of the 16MB FileOp chain:
	// the warden's max_file_read_bytes/max_body_len (env-tuned) and the gRPC
	// max message size must all be >= 16MB so a 16MB single-op payload is
	// never truncated or rejected mid-chain. The gateway/sandlot can only see
	// their own link, so this is enforced as a local floor.
	MinFileOpChainBytes = 16 << 20

	// MaxFilePathBytes bounds a workspace-relative path on every link of the
	// chain. Linux PATH_MAX is 4096 including the NUL, so a longer string can
	// never resolve; the warden's path walk is O(bytes), and an 8 MiB path
	// parked a blocking thread while it held the mount gate.
	MaxFilePathBytes = 4095

	// FileOpWireSlackBytes is the envelope headroom every FileOp payload
	// must leave under the gRPC max message size:
	// the wire message is payload + proto framing (ids, command metadata,
	// stdout/stderr sections). A payload sized at EXACTLY the max message
	// size overflows the limit by the envelope — and exceeding the gRPC
	// receive limit is a STREAM-LEVEL failure: the node stream resets and
	// every co-tenant in-flight command on that sandlot dies. 64 KiB slack
	// dwarfs any envelope this protocol produces.
	FileOpWireSlackBytes = 64 << 10
)

// MaxFileOpPayload returns the largest single FileOp data payload that is
// safe on a stream whose gRPC max message size is maxMsgSize (the chain
// floor guarantees maxMsgSize >= MinFileOpChainBytes at startup, so this is
// always a payload the documented 16MB chain can carry).
func MaxFileOpPayload(maxMsgSize int) int {
	limit := maxMsgSize - FileOpWireSlackBytes
	if limit < 1 {
		limit = 1
	}
	return limit
}

// ValidateStreamCaps checks the HTTP/2 flow-control windows and the gRPC max
// message size (all in bytes). Both are fed to gRPC options whose integer
// types (int32 for the windows) silently overflow or misbehave on out-of-range
// values, and the window-vs-message-size sizing rules are documented as
// must-hold deployment invariants — so they are validated, not hoped for:
//   - every cap >= 1 (0/negative = broken flow control or a zero message cap)
//   - windows <= MaxInt32 (grpc.InitialWindowSize takes an int32; a larger
//     int silently wraps negative)
//   - initialWindow >= maxMsgSize (a message must always fit the per-stream
//     window or a single large FileOp stalls)
//   - connWindow >= initialWindow (the per-connection window bounds the stream
//     window; the reverse is incoherent)
//   - maxMsgSize >= MinFileOpChainBytes (the 16MB FileOp chain)
func ValidateStreamCaps(initialWindow, connWindow, maxMsgSize int) error {
	for name, v := range map[string]int{
		"initial_window": initialWindow, "initial_conn_window": connWindow, "max_msg_size": maxMsgSize,
	} {
		if v < 1 {
			return fmt.Errorf("stream %s must be >= 1 byte, got %d", name, v)
		}
	}
	if initialWindow > math.MaxInt32 || connWindow > math.MaxInt32 {
		return fmt.Errorf("stream windows must be <= %d bytes (int32 range for the gRPC option): initial_window=%d initial_conn_window=%d",
			int32(math.MaxInt32), initialWindow, connWindow)
	}
	if maxMsgSize > math.MaxInt32 {
		return fmt.Errorf("stream max_msg_size must be <= %d bytes, got %d", int32(math.MaxInt32), maxMsgSize)
	}
	if initialWindow < maxMsgSize {
		return fmt.Errorf("stream initial_window (%d) must be >= max_msg_size (%d): a single max-size message must fit the per-stream window",
			initialWindow, maxMsgSize)
	}
	if connWindow < initialWindow {
		return fmt.Errorf("stream initial_conn_window (%d) must be >= initial_window (%d)",
			connWindow, initialWindow)
	}
	if maxMsgSize < MinFileOpChainBytes {
		return fmt.Errorf("stream max_msg_size (%d) must be >= %d: the 16MB FileOp chain (warden read/body caps + gRPC message size) breaks below it",
			maxMsgSize, MinFileOpChainBytes)
	}
	return nil
}

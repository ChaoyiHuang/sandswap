// Copyright 2026 Chaoyi Huang. All rights reserved.
//
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE file at the root of this repository.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, this software will be governed by
// the Apache License, Version 2.0.

package vmm

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"time"
)

// Raw control-frame protocol on the sandvmm API socket — the low-overhead
// transport for the per-request hot ops (vm.set-fs on every cold attach,
// sandvmm.ping health probes). HTTP/JSON stays for VM lifecycle operations;
// sandvmm dispatches per connection by the first byte (0x01 = raw frame,
// ASCII method letter = HTTP). Frame layout and budgets mirror the server
// side (vmm/src/api/http/raw.rs); the budgets are byte-for-byte what the
// HTTP path accepts today (body cap == micro_http payload cap, per-path cap
// == PATH_MAX-1).
const (
	rawProtoVersion = 1

	rawOpPing   = 0
	rawOpSetFs  = 1
	rawHdrLen   = 8
	rawRespHdr  = 8
	rawMaxBody  = 51_200 // == micro_http MAX_PAYLOAD_SIZE
	rawMaxResp  = 1024
	rawMaxPath  = 4095 // PATH_MAX-1: a longer path cannot exist on the host
	rawMaxPaths = 8
	rawMaxTag   = 32
	rawMaxID    = 64
	rawMaxAlias = 64

	rawStatusOK            = 0
	rawStatusErr           = 1
	rawStatusVersionReject = 2
)

// ErrRawProtocolVersion reports an out-of-range protocol version from the
// sandvmm side (rejection frame carries the server's own version). The
// caller should treat the pairing as broken: VM creation fails fast and the
// node's pool scale-up aborts — the same doctrine as the warden vsock
// version mismatch.
type ErrRawProtocolVersion struct {
	ServerVersion byte
	Message       string
}

func (e *ErrRawProtocolVersion) Error() string {
	return fmt.Sprintf("sandvmm raw protocol version mismatch: server speaks %d: %s", e.ServerVersion, e.Message)
}

// setFsUseHTTP selects the set-fs/ping transport process-wide: false (the
// default) speaks the raw frame protocol; true keeps the legacy HTTP path.
// It is configured ONCE at startup from -setfs-transport before any client
// exists (restart-required), so the atomic is a plain read on the hot path.
var setFsUseHTTP atomic.Bool

// ConfigureSetFsTransport selects the set-fs/ping transport: "raw" (default,
// highest performance) or "http" (legacy REST path). Any other value is
// rejected. Call once at process start, before any Client is used.
func ConfigureSetFsTransport(mode string) error {
	switch mode {
	case "raw":
		setFsUseHTTP.Store(false)
	case "http":
		setFsUseHTTP.Store(true)
	default:
		return fmt.Errorf("invalid setfs transport %q (want \"raw\" or \"http\")", mode)
	}
	return nil
}

// SetFsTransportDefault is the built-in default for the -setfs-transport flag.
const SetFsTransportDefault = "raw"

// deadlineFor derives a per-op deadline from ctx (the HTTP path already gets
// ctx cancellation; the raw path needs an explicit socket deadline).
func deadlineFor(ctx context.Context, fallback time.Duration) time.Time {
	if d, ok := ctx.Deadline(); ok {
		return d
	}
	return time.Now().Add(fallback)
}

// acquireRawConn returns the cached raw connection, dialing it on first use.
// Connection reuse is the whole point: one persistent UDS connection per VM
// answers every set-fs/ping with two syscalls (write frame, read response).
func (c *Client) acquireRawConn() (net.Conn, error) {
	if c.rawConn != nil {
		return c.rawConn, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := c.dialUnix(ctx)
	if err != nil {
		return nil, fmt.Errorf("dial sandvmm raw: %w", err)
	}
	c.rawConn = conn
	return conn, nil
}

// poisonRawConn drops the cached connection after ANY transport error so the
// next op re-dials a fresh one.
func (c *Client) poisonRawConn(conn net.Conn) {
	if c.rawConn == conn {
		c.rawConn = nil
	}
	conn.Close()
}

// rawRoundTrip sends one request frame and reads one response frame. The
// protocol is strictly ping-pong on one connection; c.rawMu serializes
// concurrent callers (set-fs runs under mountMu anyway — this is a safety
// net for ping racing a set-fs).
func (c *Client) rawRoundTrip(ctx context.Context, op byte, body []byte) error {
	c.rawMu.Lock()
	defer c.rawMu.Unlock()

	conn, err := c.acquireRawConn()
	if err != nil {
		return err
	}

	frame := make([]byte, rawHdrLen+len(body))
	frame[0] = rawProtoVersion
	frame[1] = op
	binary.BigEndian.PutUint16(frame[2:4], 0) // flags
	binary.BigEndian.PutUint32(frame[4:8], uint32(len(body)))
	copy(frame[rawHdrLen:], body)

	_ = conn.SetDeadline(deadlineFor(ctx, 5*time.Second))
	if _, err := conn.Write(frame); err != nil {
		c.poisonRawConn(conn)
		return fmt.Errorf("sandvmm raw write (op %d): %w", op, err)
	}

	var hdr [rawRespHdr]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		c.poisonRawConn(conn)
		return fmt.Errorf("sandvmm raw read header (op %d): %w", op, err)
	}
	version, rop, status := hdr[0], hdr[1], hdr[2]
	// reserved hdr[3] must be zero on the wire; tolerate-but-log is not
	// worth the branch — a nonzero value means a foreign speaker.
	if hdr[3] != 0 {
		c.poisonRawConn(conn)
		return fmt.Errorf("sandvmm raw: nonzero reserved byte in response header")
	}
	bodyLen := binary.BigEndian.Uint32(hdr[4:8])
	if bodyLen > rawMaxResp {
		c.poisonRawConn(conn)
		return fmt.Errorf("sandvmm raw: response body %d over cap %d", bodyLen, rawMaxResp)
	}
	msg := make([]byte, bodyLen)
	if bodyLen > 0 {
		if _, err := io.ReadFull(conn, msg); err != nil {
			c.poisonRawConn(conn)
			return fmt.Errorf("sandvmm raw read body (op %d): %w", op, err)
		}
	}

	switch status {
	case rawStatusOK:
		return nil
	case rawStatusVersionReject:
		return &ErrRawProtocolVersion{ServerVersion: version, Message: string(msg)}
	default:
		return fmt.Errorf("sandvmm raw op %d failed: %s", rop, string(msg))
	}
}

// encodeSetFsBody builds the SET_FS request body:
//
//	[u8 tag_len][tag][u8 id_len][id][u16 n_paths] + per path [u16 len][bytes]
//	[u8 alias_len][alias]
//
// The wire order is tag-first (matching the Rust parser); the ARGUMENT order
// is (id, tag) to mirror Client.SetFs. Validation mirrors the server side
// byte-for-byte and runs BEFORE anything is written to the socket, so an
// invalid argument never leaves a half frame on the wire.
func encodeSetFsBody(id, tag string, allowedDirs []string, alias string) ([]byte, error) {
	if l := len(tag); l == 0 || l > rawMaxTag {
		return nil, fmt.Errorf("set-fs tag length %d out of 1..=%d", l, rawMaxTag)
	}
	if l := len(id); l == 0 || l > rawMaxID {
		return nil, fmt.Errorf("set-fs id length %d out of 1..=%d", l, rawMaxID)
	}
	if len(allowedDirs) > rawMaxPaths {
		return nil, fmt.Errorf("set-fs allowed_dirs count %d exceeds %d", len(allowedDirs), rawMaxPaths)
	}
	if l := len(alias); l > rawMaxAlias {
		return nil, fmt.Errorf("set-fs alias length %d exceeds %d", l, rawMaxAlias)
	}
	if alias != "" && !validExportAlias(alias) {
		return nil, fmt.Errorf("set-fs alias %q must be one component of [A-Za-z0-9._-], 1..=%d bytes, not . or ..", alias, rawMaxAlias)
	}
	if (len(allowedDirs) == 0) != (alias == "") {
		return nil, fmt.Errorf("set-fs alias is required for a non-empty allowed_dirs and forbidden on the clear (dirs=%d alias=%q)", len(allowedDirs), alias)
	}
	body := make([]byte, 0, 5+len(tag)+len(id)+len(allowedDirs)*2+len(alias))
	body = append(body, byte(len(tag)))
	body = append(body, tag...)
	body = append(body, byte(len(id)))
	body = append(body, id...)
	body = binary.BigEndian.AppendUint16(body, uint16(len(allowedDirs)))
	for i, dir := range allowedDirs {
		if l := len(dir); l == 0 || l > rawMaxPath {
			return nil, fmt.Errorf("set-fs allowed_dirs[%d] length %d out of 1..=%d (PATH_MAX-1)", i, l, rawMaxPath)
		}
		if len(dir) > 0 && dir[0] != '/' {
			return nil, fmt.Errorf("set-fs allowed_dirs[%d] %q is not an absolute path", i, dir)
		}
		body = binary.BigEndian.AppendUint16(body, uint16(len(dir)))
		body = append(body, dir...)
	}
	body = append(body, byte(len(alias)))
	body = append(body, alias...)
	if len(body) > rawMaxBody {
		return nil, fmt.Errorf("set-fs frame body %d over cap %d", len(body), rawMaxBody)
	}
	return body, nil
}

// rawSetFs issues the SET_FS op over the raw frame protocol.
func (c *Client) rawSetFs(ctx context.Context, id, tag string, allowedDirs []string, alias string) error {
	body, err := encodeSetFsBody(id, tag, allowedDirs, alias)
	if err != nil {
		return err
	}
	return c.rawRoundTrip(ctx, rawOpSetFs, body)
}

// validExportAlias mirrors the VMM-side rule for the per-generation root
// name. Kept local so an invalid alias never leaves a half frame on the wire.
func validExportAlias(a string) bool {
	if a == "" || len(a) > rawMaxAlias || a == "." || a == ".." {
		return false
	}
	for i := 0; i < len(a); i++ {
		c := a[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '.' || c == '_' || c == '-' {
			continue
		}
		return false
	}
	return true
}

// rawPing issues the PING op over the raw frame protocol.
func (c *Client) rawPing(ctx context.Context) error {
	return c.rawRoundTrip(ctx, rawOpPing, nil)
}

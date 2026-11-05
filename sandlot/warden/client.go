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
//
// Package warden provides a minimal raw-vsock client for communicating
// with warden inside a running microVM.
// Wire protocol (see warden/src/raw_server.rs), version 2:
//	Request  = [u32 magic=0x53414e44][u8 version][u8 op][u32 body_len]
//	           [u8 nonce[16]][u8 tag[32]][body]
//	  body    = sequence of [u32 len][bytes] fields, in op-specific order
//	   (OP_MOUNT_AND_EXEC with an EMPTY command field = mount-only, no exec —
//	    see MountOnly)
//	Response = [u32 magic][u8 version][u8 code][u8 exit_code][u8 reserved]
//	           [u32 stdout_len][u32 stderr_len][u64 exec_duration_ns]
//	           [u32 mounted_len][u8 tag[32]][stdout][stderr][mounted]
//	  code: 0=OK (exit_code holds the real code for sync exec),
//	        1=APP_ERROR (business failure, VM healthy; message in stdout),
//	        2=TRANSPORT_ERROR (invalidate connection; message in stderr),
//	        3=BG_RUNNING, 4=BG_KILLED, 5=BG_NOT_FOUND, 6=TIMED_OUT.
//	  exit_code: 0–255 (0=success, 128+signum for signal death); only meaningful
//	             for sync exec on code=OK.
//	  tag: HMAC-SHA256 over the fixed header fields and the request nonce,
//	       keyed by the per-VM session key. A response whose tag does not
//	       verify is refused (the VM must be destroyed).
//	The mounted-volume identity field is part of the warm ops (OP_EXEC field 3,
//	OP_ASYNC_EXEC field 2, OP_FILE field 5) at fixed positions in the current
//	protocol layout.
// All integers are big-endian. The connection is one persistent AF_VSOCK socket
// per VM, cached and reused across calls (see stream/handler.go VMState.Warden).

package warden

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"

	commonconfig "common/config"
)

const (
	wardenVsockPort = 1024
	// connectTimeout bounds a blocking AF_VSOCK connect (SO_SNDTIMEO applies
	// to connect(2) for vsock). A guest that never answers the transport
	// request must not wedge a sandlot goroutine forever.
	connectTimeout = 30 * time.Second
	// writeTimeout bounds one request write. A hostile warden that stops
	// reading would otherwise block c.conn.Write forever (os.File on a
	// blocking fd has no Go deadline), holding an exec slot until the node's
	// command path stalls. hit on SO_SNDTIMEO; the error is a transport
	// error and the caller discards the connection.
	writeTimeout = 30 * time.Second

	// Per-request read-liveness scheme: the SO_RCVTIMEO on the cached warden
	// connection is re-set before every request to the op's own duration +
	// margin, so a wedged cached connection (response never arrives while the
	// transport stays open — heartbeats on separate short-lived connections keep
	// succeeding, which previously masked it) is detected at ~op_timeout+30s
	// instead of a fixed 360s. The cap is the warden_countdown (T_warden): a
	// read longer than that is moot anyway, the warden has already POWER_OFF'd
	// the VM. At-most-once is preserved: the read is never cut before the op's
	// own declared timeout, so a legit slow command's response (up to
	// max_exec_timeout) always fits.

	// ReadTimeoutCapDefault backs the read-timeout cap when the sandlot cannot
	// supply the warden_countdown (locks step with the warden's default T_warden).
	ReadTimeoutCapDefault = 5 * time.Minute

	// readTimeoutMargin is the headroom after the warden finishes an op at its
	// timeout: it must kill+reap the command (exec.rs bounded 500ms reap window),
	// drain the output pipes, and send the timed_out response. Measured <1s;
	// 30s is 30x headroom. Exported as ReadTimeoutMargin so the sandlot
	// startup check can validate the at-most-once invariant:
	// warden_countdown > warden_max_exec_timeout + margin.
	readTimeoutMargin = 30 * time.Second

	// ReadTimeoutMargin is the exported form of readTimeoutMargin (see above).
	ReadTimeoutMargin = readTimeoutMargin

	// Per-op default read timeouts, used when the op does not carry its own
	// explicit timeout field. Each covers that op's worst-case warden-side work:
	//   - unmount: cgroup.kill + reap (≤ cgroup_clear_timeout 5s) + umount +
	//     drop_caches (~8s) → 30s
	//   - file / async-exec: mount-independent, sub-second → 30s
	//   - status/kill: registry lookup + log tail → 15s
	//   - mem_stats: /proc/meminfo read → 5s
	// Exported so package core (readopt's ResetSurvivorsToClean) can dial a
	// fresh cleanup connection sized for an unmount.
	UnmountReadTimeout   = 30 * time.Second
	fileReadTimeout      = 30 * time.Second
	asyncExecReadTimeout = 30 * time.Second
	statusReadTimeout    = 15 * time.Second
	memStatsReadTimeout  = 5 * time.Second

	// defaultExecTimeout mirrors the warden's default_exec_timeout: used to size
	// the read timeout for an exec request with timeout==0 (the warden runs it
	// at its default).
	defaultExecTimeout = 30 * time.Second

	magic uint32 = 0x53414e44 // "SAND"

	// protocolVersion mirrors warden/src/raw_server.rs PROTOCOL_VERSION.
	// Both request and response frames carry it. Negotiation model: requests
	// carry OUR version; a warden that cannot speak it replies with a
	// transport-error frame whose header carries ITS version, and any response
	// whose version differs from ours is classified ProtocolVersionError (with
	// both version numbers) — the caller fails fast instead of retrying an
	// eternally incompatible peer. The warden's window is [1,1] (the header
	// carries the op-specific body MAC).
	protocolVersion uint8 = 1

	// Authenticated-header sizes. The nonce is a per-connection random prefix
	// plus a counter (no syscall per request); bodyMAC authenticates the
	// op-specific body fields (mount identity/target) that the header tag
	// cannot see; the tag is HMAC-SHA256 over the fixed header fields, the
	// nonce and the body MAC.
	nonceLen      = 16
	bodyMACLen    = 32
	tagLen        = 32
	reqBaseLen    = 10
	respBaseLen   = 28
	reqHeaderLen  = reqBaseLen + nonceLen + bodyMACLen + tagLen
	respHeaderLen = respBaseLen + tagLen
	// Domain separation labels; byte-for-byte identical to warden/src/auth.rs.
	requestAuthLabel  = "sandswap.warden.request.v1"
	responseAuthLabel = "sandswap.warden.response.v1"
	bodyMACLabel      = "sandswap.warden.body.v1"
	mountedMACLabel   = "sandswap.warden.mounted.v1"

	// fileOpVolumeIdentityIndex is the OP_FILE body position of the identity
	// field — a FIXED index (not "the last field") so the warden's read is a
	// single lookup. OP_FILE's op-specific fields end at index 4 (WRITE's
	// data), so 5 is free for every sub-op; shorter sub-ops are padded with
	// empty fields. OP_EXEC carries it at index 3 and OP_ASYNC_EXEC at index 2
	// (both appended last) — the positions are pinned on both sides.
	fileOpVolumeIdentityIndex = 5

	opMountAndExec      uint8 = 1  // sync: mount + exec (cold path, one RTT)
	opUnmount           uint8 = 2  // unmount + cgroup.kill
	opExec              uint8 = 3  // sync: exec only (warm path, already mounted)
	opMemStats          uint8 = 4  // heartbeat: guest MemAvailable/MemTotal
	opAsyncExec         uint8 = 5  // async: start background exec (warm path, already mounted)
	opMountAndAsyncExec uint8 = 6  // async: mount + start background exec (cold path, one RTT)
	opStatusExec        uint8 = 7  // async: poll status + log tail
	opKillExec          uint8 = 8  // async: kill background exec by exec_id
	opFile              uint8 = 9  // file I/O: unified sub-opcode dispatch
	opKeyDelivery       uint8 = 10 // first frame on a connection: deliver the per-VM key

	// File I/O sub-opcodes (carried in the first byte of the OP_FILE body).
	// Exported so handler.go can map proto action strings to sub-opcodes.
	SubOpRead    uint8 = 1
	SubOpWrite   uint8 = 2
	SubOpStat    uint8 = 3
	SubOpListDir uint8 = 4
	SubOpMakeDir uint8 = 5
	SubOpRemove  uint8 = 6
	SubOpRename  uint8 = 7

	// Response code values (mirror warden raw_server CODE_* constants). This is
	// the single field the client branches on, replacing the former overloaded
	// i32 status (which conflated exit codes, sentinels, and error classes).
	codeOk           uint8 = 0 // success; for sync exec, exitCode holds the real code
	codeAppError     uint8 = 1 // business failure (FileOp ENOENT, MemStats unreadable); VM healthy
	codeTransportErr uint8 = 2 // handler/transport/protocol error; invalidate the cached connection
	codeBgRunning    uint8 = 3 // status_exec: background exec still running
	codeBgKilled     uint8 = 4 // status_exec/kill_exec: killed by the agent
	codeBgNotFound   uint8 = 5 // status_exec/kill_exec: exec_id not in registry
	codeTimedOut     uint8 = 6 // sync exec exceeded its timeout
	// Generation-bound mount outcomes (app-level: the VM and connection stay
	// healthy). See warden/src/raw_server.rs CODE_MOUNT_*/CODE_UNMOUNT_*.
	codeMountTargetNotExported uint8 = 7
	codeUnmountNotMounted      uint8 = 8
	codeUnmountMismatch        uint8 = 9
)

// TransportError indicates a transport-level failure (fd read/write) on the
// cached vsock connection, as opposed to a warden RPC error (status=-1).
// A TransportError means the cached connection is broken and must be closed
// and re-established. Callers use errors.As to distinguish transport errors
// from warden RPC errors and decide whether retrying is safe.
type TransportError struct {
	Op  string // "write" or "read"
	Err error
}

func (e *TransportError) Error() string { return fmt.Sprintf("warden transport %s: %v", e.Op, e.Err) }
func (e *TransportError) Unwrap() error { return e.Err }

// ProtocolVersionError reports a warden protocol-version mismatch: the peer's
// frames carry a version this client cannot interpret (or the peer rejected
// ours — its reply frame then advertises its own version). It embeds
// TransportError so existing slot-discard logic (isWardenTransportErr via
// errors.As) treats the connection as unusable, while callers that can act on
// the mismatch (VM creation, re-adopt) detect it with errors.As and fail fast
// — retrying or destroying-and-recreating against the SAME warden build can
// never fix a version gap; only redeploying sandlot + initramfs together can.
type ProtocolVersionError struct {
	TransportError
	// Ours is the protocol version this client speaks; Theirs is the version
	// the peer's frame carried (0 if the peer sent nothing interpretable).
	Ours, Theirs uint8
}

func (e *ProtocolVersionError) Error() string {
	return fmt.Sprintf("warden protocol version mismatch: sandlot speaks %d, warden speaks %d — deploy matching sandlot/initramfs builds",
		e.Ours, e.Theirs)
}

// Unwrap exposes the embedded TransportError so errors.As walks
// ProtocolVersionError → TransportError → inner cause: the slot-discard
// classification (isWardenTransportErr) keeps matching while version-aware
// callers match the outer type. Without this, the promoted TransportError
// Unwrap would skip straight to the inner cause and lose the transport level.
func (e *ProtocolVersionError) Unwrap() error { return &e.TransportError }

// AuthError reports a response frame whose HMAC tag did not verify: the frame
// was not produced by a warden holding this VM's session key (a forged
// responder, a corrupted frame, or a stale VM from before a key change). The
// caller must destroy the VM — never trust the response. It embeds
// TransportError so the slot pool discards the connection via its normal
// transport-error path.
type AuthError struct {
	TransportError
}

func (e *AuthError) Error() string {
	return fmt.Sprintf("warden response authentication failed: %v", e.TransportError.Err)
}

// Unwrap exposes the embedded TransportError so errors.As(err, *TransportError)
// keeps classifying the connection as unusable.
func (e *AuthError) Unwrap() error { return &e.TransportError }

// IsAuthError reports whether err is a response-authentication failure.
func IsAuthError(err error) bool {
	var ae *AuthError
	return errors.As(err, &ae)
}

// Wire-layout constants exported for in-repo test doubles and diagnostic
// tools (the warden fake in core tests and sandlot/cmd/warden-probe speak the
// same bytes). The production client uses the internal aliases.
const (
	WireRequestHeaderLen  = reqHeaderLen
	WireResponseHeaderLen = respHeaderLen
	WireNonceLen          = nonceLen
	WireBodyMACLen        = bodyMACLen
	WireTagLen            = tagLen
)

// RequestTag exposes the request-tag computation to in-repo peers that build
// frames themselves (warden-probe / test fakes). nonce must be WireNonceLen
// bytes, bodyMAC WireBodyMACLen bytes (zeros for ops with no bound fields).
func RequestTag(key []byte, nonce []byte, version, op uint8, bodyLen uint32, bodyMAC []byte) [WireTagLen]byte {
	var n [nonceLen]byte
	copy(n[:], nonce)
	var bm [bodyMACLen]byte
	copy(bm[:], bodyMAC)
	return requestTag(key, version, op, bodyLen, &n, &bm)
}

// BodyMAC exposes the op-specific body-field MAC to in-repo peers.
func BodyMAC(key []byte, nonce []byte, op uint8, fields ...[]byte) [WireBodyMACLen]byte {
	var n [nonceLen]byte
	copy(n[:], nonce)
	return bodyMAC(key, &n, op, fields...)
}

// MountedTag exposes the mounted-identity MAC to in-repo peers.
func MountedTag(key []byte, nonce []byte, mounted []byte) [WireTagLen]byte {
	var n [nonceLen]byte
	copy(n[:], nonce)
	return mountedTag(key, &n, mounted)
}

// ResponseTag exposes the response-tag computation to in-repo peers that build
// frames themselves. nonce must be WireNonceLen bytes.
func ResponseTag(key []byte, nonce []byte, version, code, exitCode uint8, stdoutLen, stderrLen uint32, execDurationNs uint64, mountedLen uint32) [WireTagLen]byte {
	var n [nonceLen]byte
	copy(n[:], nonce)
	return responseTag(key, &n, version, code, exitCode, stdoutLen, stderrLen, execDurationNs, mountedLen)
}

// NewClientForTransport builds a Client over an arbitrary transport with an
// explicit session key. Intended for in-repo test doubles and diagnostics;
// production dials through Dial/DialWithCap/DialWithTimeout, which also mint
// the per-connection nonce prefix.
func NewClientForTransport(conn io.ReadWriteCloser, cid uint32, readTimeoutCap time.Duration, key []byte) *Client {
	var prefix [8]byte
	_, _ = rand.Read(prefix[:])
	return newClient(conn, cid, readTimeoutCap, key, prefix)
}

// DecodeSessionKey turns the persisted 64-hex-character per-VM key into the
// 32 raw bytes the wire codec uses. A missing or malformed key is a hard
// error: callers must not fall back to an unauthenticated connection.
func DecodeSessionKey(hexKey string) ([]byte, error) {
	key, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("warden session key is not valid hex: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("warden session key must decode to 32 bytes, got %d", len(key))
	}
	return key, nil
}

// requestTag computes HMAC-SHA256 over the fixed request header fields, the
// nonce and the op-specific body MAC. Byte-for-byte identical to
// warden/src/auth.rs::request_tag.
func requestTag(key []byte, version, op uint8, bodyLen uint32, nonce *[nonceLen]byte, bodyMAC *[bodyMACLen]byte) [tagLen]byte {
	// One fixed stack buffer, no interfaces and no allocations: this sits on
	// every request of the hot path.
	var msg [112]byte
	n := copy(msg[:], requestAuthLabel)
	msg[n] = version
	msg[n+1] = op
	n += 2
	binary.BigEndian.PutUint32(msg[n:], bodyLen)
	n += 4
	copy(msg[n:], nonce[:])
	n += nonceLen
	copy(msg[n:], bodyMAC[:])
	n += bodyMACLen
	return hmacSHA256(msg[:n], key)
}

// bodyMAC computes the op-specific body-field MAC, byte-for-byte identical to
// warden/src/auth.rs::body_mac: label || nonce || op || len0||f0 || len1||f1 ||
// len2||f2, absent fields encoded as zero length. It binds the warm-op
// mounted-volume identity and the cold mount op's
// (alias, mount_point, volume_mode) — the fields a compromised guest kernel
// could otherwise rewrite to redirect a mount or execute in another tenant's
// volume — while stdout/stderr/command payloads stay unhashed.
func bodyMAC(key []byte, nonce *[nonceLen]byte, op uint8, fields ...[]byte) [bodyMACLen]byte {
	var buf [512]byte
	n := copy(buf[:], bodyMACLabel)
	copy(buf[n:], nonce[:])
	n += nonceLen
	buf[n] = op
	n++
	for i := 0; i < 3; i++ {
		var f []byte
		if i < len(fields) {
			f = fields[i]
		}
		if n+4+len(f) > len(buf) {
			// Not reachable with the fixed protocol layouts; fail closed with
			// a MAC the warden will never accept rather than truncating.
			var zero [bodyMACLen]byte
			return zero
		}
		binary.BigEndian.PutUint32(buf[n:], uint32(len(f)))
		n += 4
		n += copy(buf[n:], f)
	}
	return hmacSHA256(buf[:n], key)
}

// mountedTag computes the MAC over the response's mounted-volume identity,
// byte-for-byte identical to warden/src/auth.rs::mounted_tag.
func mountedTag(key []byte, nonce *[nonceLen]byte, mounted []byte) [tagLen]byte {
	var msg [64 + 256]byte
	n := copy(msg[:], mountedMACLabel)
	copy(msg[n:], nonce[:])
	n += nonceLen
	if len(mounted) > len(msg)-n {
		// The mounted identity is a volume basename (tens of bytes); an
		// oversized value is a hostile frame.
		var zero [tagLen]byte
		return zero
	}
	n += copy(msg[n:], mounted)
	return hmacSHA256(msg[:n], key)
}

// responseTag computes HMAC-SHA256 over the fixed response header fields and
// the request nonce. Byte-for-byte identical to
// warden/src/auth.rs::response_tag.
func responseTag(key []byte, nonce *[nonceLen]byte, version, code, exitCode uint8, stdoutLen, stderrLen uint32, execDurationNs uint64, mountedLen uint32) [tagLen]byte {
	var msg [128]byte
	n := copy(msg[:], responseAuthLabel)
	copy(msg[n:], nonce[:])
	n += nonceLen
	msg[n] = version
	msg[n+1] = code
	msg[n+2] = exitCode
	n += 3
	binary.BigEndian.PutUint32(msg[n:], stdoutLen)
	n += 4
	binary.BigEndian.PutUint32(msg[n:], stderrLen)
	n += 4
	binary.BigEndian.PutUint64(msg[n:], execDurationNs)
	n += 8
	binary.BigEndian.PutUint32(msg[n:], mountedLen)
	n += 4
	return hmacSHA256(msg[:n], key)
}

// hmacSHA256 is HMAC-SHA256 for a short message with a 32-byte key, using
// fixed stack buffers only. The generic hmac.New path allocates a hash
// interface per tag (9-10 allocs measured); this path is the hot one.
func hmacSHA256(msg, key []byte) [tagLen]byte {
	var k [64]byte
	if len(key) != 32 || len(msg) > 256 {
		// Generic fallback for non-hot callers (tests/tools with odd keys) and
		// for messages beyond the stack buffer used below.
		mac := hmac.New(sha256.New, key)
		mac.Write(msg)
		var out [tagLen]byte
		copy(out[:], mac.Sum(nil))
		return out
	}
	copy(k[:], key)
	var ipad, opad [64]byte
	for i := 0; i < 64; i++ {
		ipad[i] = k[i] ^ 0x36
		opad[i] = k[i] ^ 0x5c
	}
	var inner [64 + 256]byte
	copy(inner[:64], ipad[:])
	copy(inner[64:], msg)
	ih := sha256.Sum256(inner[:64+len(msg)])
	var outer [64 + tagLen]byte
	copy(outer[:64], opad[:])
	copy(outer[64:], ih[:])
	return sha256.Sum256(outer[:])
}

// versionMismatch builds the ProtocolVersionError for a response frame whose
// version field is not ours.
func versionMismatch(theirs uint8) *ProtocolVersionError {
	return &ProtocolVersionError{
		TransportError: TransportError{Op: "read", Err: fmt.Errorf("response protocol version %d != %d", theirs, protocolVersion)},
		Ours:           protocolVersion,
		Theirs:         theirs,
	}
}

// Client is a vsock client connected to warden inside a microVM.
// A Client is NOT safe for concurrent use — the raw vsock protocol requires
// request/response frames to be atomic on the connection. Callers must
// serialize access (e.g., via VMState.execMu in stream/handler.go).
type Client struct {
	conn           rpcConn
	cid            uint32
	readTimeoutCap time.Duration // per-request read-timeout ceiling (warden_countdown)
	// Per-VM raw-protocol authentication. The request tag is computed over a
	// nonce built from a per-connection random prefix plus a counter, so
	// nonce generation costs no syscall; only the HMAC computation is added
	// to the request path.
	sessionKey    [32]byte
	hasSessionKey bool
	noncePrefix   [8]byte
	nonceSeq      uint64
	// lastRcvtimeo caches the SO_RCVTIMEO currently armed on the socket.
	// roundTrip/roundTripRaw re-arm it before every request; back-to-back ops
	// with the same timeout (the common case) then skip the setsockopt
	// syscall entirely. Only touched on the vsock path, serialized by the
	// caller's per-slot pool (the Client contract above).
	lastRcvtimeo time.Duration
	// lastSndtimeo caches SO_SNDTIMEO (the write/connect bound).
	lastSndtimeo time.Duration
}

// appendVolumeIdentity appends the warm-op mounted-volume identity field.
// mountedVolume is the identity of the volume the caller believes is mounted
// ("" allowed: present-but-empty makes the warden fall back to its
// mount_active-only check with a rate-limited warn).
func (c *Client) appendVolumeIdentity(fields [][]byte, mountedVolume string) [][]byte {
	return append(fields, strField(mountedVolume))
}

// rpcConn is the minimal transport the warden client needs: read/write/close.
// AF_VSOCK sockets cannot be wrapped with net.FileConn because Go's net
// package calls getsockname() internally and cannot parse AF_VSOCK (family
// 40) sockaddrs — it returns EAFNOSUPPORT. So we wrap the raw fd in *os.File
// directly; the read deadline is enforced at the kernel level via SO_RCVTIMEO
// (re-set per request, see roundTrip/roundTripRaw).
type rpcConn interface {
	io.Reader
	io.Writer
	io.Closer
}

// vsockConn wraps a raw AF_VSOCK socket fd as an rpcConn.
type vsockConn struct {
	f *os.File
}

func (c *vsockConn) Read(p []byte) (int, error)  { return c.f.Read(p) }
func (c *vsockConn) Write(p []byte) (int, error) { return c.f.Write(p) }
func (c *vsockConn) Close() error                { return c.f.Close() }

// setReadTimeout re-arms the kernel read deadline (SO_RCVTIMEO) for the next
// response on this connection. Called by roundTrip/roundTripRaw before every request.
func (c *vsockConn) setReadTimeout(d time.Duration) error {
	return unix.SetsockoptTimeval(int(c.f.Fd()), unix.SOL_SOCKET, unix.SO_RCVTIMEO, rcvtimeo(d))
}

// setWriteTimeout arms the kernel write deadline (SO_SNDTIMEO). A blocking
// write on a peer that stopped reading returns EAGAIN after this bound.
func (c *vsockConn) setWriteTimeout(d time.Duration) error {
	return unix.SetsockoptTimeval(int(c.f.Fd()), unix.SOL_SOCKET, unix.SO_SNDTIMEO, rcvtimeo(d))
}

// setConnWriteTimeout arms the write timeout; non-vsock test transports are
// untouched. Same cache/rollback discipline as setConnReadTimeout.
func (c *Client) setConnWriteTimeout(d time.Duration) error {
	if d > 0 && d == c.lastSndtimeo {
		return nil
	}
	armed := c.lastSndtimeo
	c.lastSndtimeo = d
	vc, ok := c.conn.(*vsockConn)
	if !ok {
		return nil
	}
	if err := vc.setWriteTimeout(d); err != nil {
		c.lastSndtimeo = armed
		return err
	}
	return nil
}

// setConnReadTimeout arms the kernel read timeout for the next response. The
// timeout is a property of the real AF_VSOCK socket, so non-vsock transports
// (the fake in tests) are untouched. A repeated identical value skips the
// syscall (see Client.lastRcvtimeo); d <= 0 always re-sets (a zero SO_RCVTIMEO
// DISABLES the timeout — never treated as "already armed"). A failed
// setsockopt rolls the cache back: the previously armed timeout is still live,
// so the next call must retry the arm rather than wrongly skip it.
func (c *Client) setConnReadTimeout(d time.Duration) error {
	if d > 0 && d == c.lastRcvtimeo {
		return nil // this timeout is already armed — skip the setsockopt
	}
	armed := c.lastRcvtimeo
	c.lastRcvtimeo = d
	vc, ok := c.conn.(*vsockConn)
	if !ok {
		return nil // non-vsock (test) transport: no kernel timeout to set
	}
	if err := vc.setReadTimeout(d); err != nil {
		c.lastRcvtimeo = armed // rollback: the old timeout is still the live one
		return err
	}
	return nil
}

// rcvtimeo converts a Go duration to a kernel timeval. Usec is microseconds
// (d%time.Second is nanoseconds — divide by time.Microsecond).
func rcvtimeo(d time.Duration) *unix.Timeval {
	return &unix.Timeval{
		Sec:  int64(d / time.Second),
		Usec: int64((d % time.Second) / time.Microsecond),
	}
}

// clampReadTimeout caps a computed read timeout to the connection's ceiling.
// A zero cap (test clients that never set one) means "no ceiling". A
// non-positive timeout falls back to the cap rather than 0: a zero SO_RCVTIMEO
// on Linux DISABLES the read timeout entirely, which would un-arm the
// transport-liveness bound this scheme exists to provide.
func clampReadTimeout(d, cap time.Duration) time.Duration {
	if d <= 0 {
		return cap // 0 cap = test mode: leave as-is (no ceiling)
	}
	if cap > 0 && d > cap {
		return cap
	}
	return d
}

// execReadTimeout sizes the read timeout for a sync exec call: the op's own
// command timeout + margin, capped at the connection ceiling. timeout==0
// (the warden runs the command at its default_exec_timeout) falls back to
// defaultExecTimeout.
func execReadTimeout(execTimeout, cap time.Duration) time.Duration {
	if execTimeout <= 0 {
		execTimeout = defaultExecTimeout
	}
	return clampReadTimeout(execTimeout+readTimeoutMargin, cap)
}

// Dial connects to the warden inside the VM with the given guest CID via kernel
// AF_VSOCK. This requires kernel vhost-vsock support (CID routing via
// /dev/vhost-vsock). The initial SO_RCVTIMEO is the default cap (a backstop
// only — each request re-sets it); pass the warden_countdown via DialWithCap
// so the cap bounds the per-request timeouts.
func Dial(cid uint32, key []byte) (*Client, error) {
	return DialWithCap(cid, ReadTimeoutCapDefault, key)
}

// DialWithCap connects with a per-request read-timeout cap — the warden_countdown
// (T_warden) for the cached connection. See roundTrip/roundTripRaw.
func DialWithCap(cid uint32, cap time.Duration, key []byte) (*Client, error) {
	return dial(cid, cap, key)
}

// DialWithTimeout connects with a custom SO_RCVTIMEO. Used by the heartbeat
// probe (short timeout, e.g. 2s) so a stuck warden is detected promptly without
// blocking on the cached connection's wmu lock. The probe sends only MemStats.
func DialWithTimeout(cid uint32, rcvto time.Duration, key []byte) (*Client, error) {
	return dial(cid, rcvto, key)
}

func dial(cid uint32, rcvto time.Duration, key []byte) (*Client, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("warden session key must be 32 bytes, got %d", len(key))
	}
	var prefix [8]byte
	if _, err := rand.Read(prefix[:]); err != nil {
		return nil, fmt.Errorf("warden nonce prefix: %w", err)
	}
	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM, 0)
	if err != nil {
		return nil, fmt.Errorf("vsock socket: %w", err)
	}

	sa := &unix.SockaddrVM{CID: cid, Port: wardenVsockPort}
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, rcvtimeo(rcvto)); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("vsock set SO_RCVTIMEO: %w", err)
	}
	// SO_SNDTIMEO bounds connect(2) on AF_VSOCK (a guest that never answers
	// must not wedge the caller) and every subsequent write.
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_SNDTIMEO, rcvtimeo(connectTimeout)); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("vsock set SO_SNDTIMEO: %w", err)
	}
	if err := unix.Connect(fd, sa); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("vsock connect to %d:%d: %w", cid, wardenVsockPort, err)
	}
	// Wrap the raw fd directly — net.FileConn would call getsockname(), which
	// fails on AF_VSOCK (Go can't parse family 40). SO_RCVTIMEO above already
	// enforces the read timeout at the kernel level.
	conn := &vsockConn{f: os.NewFile(uintptr(fd), "vsock")}
	cli := newClient(conn, cid, rcvto, key, prefix)
	// The warden starts with no key and serves nothing until this frame
	// arrives; every connection carries it (idempotent: the warden accepts a
	// repeat only when it matches the installed key). One extra RTT per
	// connection, never per command — connections are pooled and long-lived.
	if err := cli.deliverSessionKey(); err != nil {
		cli.Close()
		return nil, fmt.Errorf("warden key delivery: %w", err)
	}
	return cli, nil
}

// deliverSessionKey sends OP_KEY_DELIVERY with the per-VM key as its single
// field. The request tag is zero (the warden cannot hold a key before this
// frame); the RESPONSE is tagged with the delivered key, so a successful
// read back proves the warden installed it.
func (c *Client) deliverSessionKey() error {
	if !c.hasSessionKey {
		return fmt.Errorf("session key not configured")
	}
	nonce := c.nextNonce()
	body := encodeBody([][]byte{c.sessionKey[:]})
	frame := make([]byte, reqHeaderLen+len(body))
	binary.BigEndian.PutUint32(frame[0:4], magic)
	frame[4] = protocolVersion
	frame[5] = opKeyDelivery
	binary.BigEndian.PutUint32(frame[6:10], uint32(len(body)))
	copy(frame[10:10+nonceLen], nonce[:])
	// frame[10+nonceLen:reqHeaderLen] stays zero: no body MAC and no tag to
	// present before the key exists.
	copy(frame[reqHeaderLen:], body)
	if _, err := c.conn.Write(frame); err != nil {
		return fmt.Errorf("write key delivery: %w", err)
	}
	code, _, _, stderr, _, _, err := readResponseRaw(c.conn, c.sessionKey[:], &nonce)
	if err != nil {
		return err
	}
	if code != codeOk {
		return fmt.Errorf("warden refused key delivery: %s", stderr)
	}
	return nil
}

// newClient is the single Client constructor: dial and tests both go through
// it, so connection state (timeouts, cid, session key) is initialized
// identically.
func newClient(conn rpcConn, cid uint32, rcvto time.Duration, key []byte, prefix [8]byte) *Client {
	c := &Client{
		conn:           conn,
		cid:            cid,
		readTimeoutCap: rcvto,
		lastRcvtimeo:   rcvto,
		noncePrefix:    prefix,
	}
	if len(key) == 32 {
		copy(c.sessionKey[:], key)
		c.hasSessionKey = true
	}
	return c
}

// nextNonce returns the next request nonce: per-connection random prefix plus a
// monotonic counter. It costs no syscall and no allocation.
func (c *Client) nextNonce() [nonceLen]byte {
	var n [nonceLen]byte
	copy(n[:8], c.noncePrefix[:])
	binary.BigEndian.PutUint64(n[8:], atomic.AddUint64(&c.nonceSeq, 1))
	return n
}

func (c *Client) Close() error { return c.conn.Close() }

// execStatusCode maps a sync-exec response code to the status string the
// gateway/agent expects ("done" or "timed_out"). The mapping is centralized
// here so sandlot commands.go just threads the string through. exitCode is
// only meaningful for "done" (the real process exit code); for "timed_out" it
// is 0 (the command was killed mid-run, no exit code).
func execStatusCode(code uint8) string {
	if code == codeTimedOut {
		return "timed_out"
	}
	return "done"
}

// UnmountRootfs sends unmount_workspace(mount_point) to the warden. The warden
// RPC is still named unmount_workspace (separate wire protocol); this Go method
// is named UnmountRootfs for symmetry with MountRootfsAndExecute since every
// caller passes /mnt/rootfs. Returns the warden-monotonic unmount wall time in
// nanoseconds (cgroup.kill + teardown + umount + drop_caches), threaded up so
// sandlot can populate CommandResponse.exec_duration_ns for gateway unmount
// latency stats. 0 on transport/handler error.
func (c *Client) UnmountRootfs(identity string) (UnmountOutcome, string, uint64, error) {
	code, _, _, _, mounted, execDurationNs, err := c.roundTripRaw(
		opUnmount, UnmountReadTimeout,
		strField("/mnt/rootfs"), strField(identity), strField("0"))
	if err != nil {
		return UnmountRemoved, "", 0, err
	}
	switch code {
	case codeUnmountNotMounted:
		return UnmountNotMounted, mounted, execDurationNs, nil
	case codeUnmountMismatch:
		return UnmountMismatch, mounted, execDurationNs, nil
	default:
		return UnmountRemoved, mounted, execDurationNs, nil
	}
}

// UnmountRootfsForced tears down whatever is mounted without naming an
// identity. Reserved for re-adopt and dirty cleanup, where the previous
// generation's alias is unknowable and the VM is not selectable by design.
func (c *Client) UnmountRootfsForced() (uint64, error) {
	code, _, _, _, _, execDurationNs, err := c.roundTripRaw(
		opUnmount, UnmountReadTimeout,
		strField("/mnt/rootfs"), strField(""), strField("1"))
	if err != nil {
		return 0, err
	}
	if code == codeUnmountMismatch {
		// A forced unmount never returns mismatch; treat it as a protocol
		// violation rather than claiming a teardown that did not happen.
		return 0, fmt.Errorf("forced unmount answered mismatch")
	}
	return execDurationNs, nil
}

// ExecWorkspace runs a command directly via chroot, no container lifecycle.
// timeout is the command timeout (0 = use the warden's configured default); on
// timeout the warden kills the process group and returns status="timed_out".
// status is "done" (exitCode = real process exit code, 0–255, 128+signum for
// signal death) or "timed_out" (exitCode = 0). execDurationNs is the
// warden-monotonic command wall time in nanoseconds.
//
// mountedVolume is the mounted-volume identity asserted on this WARM op (the
// basename of the volume the caller's mount bookkeeping says is attached — see
// MountAndExec for the identity); the warden refuses the op if it names a
// volume other than the one it actually holds. "" sends a present-but-empty
// field (the warden warns and checks mount_active only).
func (c *Client) ExecWorkspace(command string, timeout time.Duration, installPackages bool, mountedVolume string) (string, string, int, string, uint64, error) {
	fields := c.appendVolumeIdentity(
		[][]byte{strField(command), strField(timeoutMs(timeout)), strField(installPkgs(installPackages))},
		mountedVolume)
	code, exitCode, stdout, stderr, execDurationNs, err := c.roundTrip(opExec, execReadTimeout(timeout, c.readTimeoutCap), fields...)
	if err != nil {
		return "", "", 0, "", 0, err
	}
	return stdout, stderr, int(exitCode), execStatusCode(code), execDurationNs, nil
}

// MountAndExec is the combined mount_workspace + exec_workspace call: it
// bind-mounts the agent directory then runs the command in a single vsock
// round-trip. volumeMode is the identity record's mode ("flat"/"overlay");
// the warden mounts by it and never probes the volume layout. Used on the
// cold/cross-agent sync path to save one vsock RTT
// versus separate Mount + ExecWorkspace calls. Response shape matches
// ExecWorkspace, plus mounted: the warden's exclusive-ownership assertion —
// the basename of the volume ACTUALLY left at /mnt/rootfs. The caller must
// cross-check it against filepath.Base(devicePath) (mismatch ⇒ twisted warden
// mount state ⇒ dirty-destroy the VM, never trust the exec output).
func (c *Client) MountAndExec(devicePath, mountPoint, command string, timeout time.Duration, installPackages bool, volumeMode string) (stdout, stderr string, exitCode int, status string, execDurationNs uint64, mounted string, err error) {
	code, exitCodeB, stdoutB, stderrB, mountedB, execDurationNs, err := c.roundTripRaw(opMountAndExec, execReadTimeout(timeout, c.readTimeoutCap),
		strField(devicePath), strField(mountPoint), strField("none"), strField(command), strField(timeoutMs(timeout)), strField(installPkgs(installPackages)), strField(volumeMode))
	if err != nil {
		return "", "", 0, "", 0, "", err
	}
	if code == codeMountTargetNotExported {
		return "", "", 0, "", 0, "", ErrMountTargetNotExported
	}
	return string(stdoutB), stderrB, int(exitCodeB), execStatusCode(code), execDurationNs, mountedB, nil
}

// MountOnly establishes the in-VM mount via OP_MOUNT_AND_EXEC with an EMPTY
// command — the warden mounts and skips the exec entirely (mount-only fast
// path; see is_mount_only in the warden). volumeMode is the identity record's
// mode ("flat"/"overlay"). Used by the cold FileOp path, which
// used to run `/bin/sh -c true` as a placeholder command just to reuse the
// combined op — a full spawn+wait+group-kill cycle whose output nobody reads.
// Read timeout is the file-op one (the mount is bounded guest-side work, no
// command runs). mounted carries the warden's actually-mounted volume
// basename (see MountAndExec).
func (c *Client) MountOnly(devicePath, mountPoint, volumeMode string) (mounted string, err error) {
	code, _, _, _, mountedB, _, err := c.roundTripRaw(opMountAndExec, fileReadTimeout,
		strField(devicePath), strField(mountPoint), strField("none"), strField(""), strField("0"), strField(""), strField(volumeMode))
	if err != nil {
		return "", err
	}
	if code == codeMountTargetNotExported {
		return "", ErrMountTargetNotExported
	}
	return mountedB, nil
}

// AsyncExec spawns a background exec: the warden forks the command chrooted
// (stdout/stderr redirected to a log file) and returns immediately with an
// exec_id. Used on the warm path (already mounted). The command survives across
// subsequent calls within the agent's lease; poll with StatusExec, kill with
// KillExec. The warden's per-agent cgroup.kill at unmount clears it on agent switch.
// mountedVolume carries the warm-path mounted-volume identity (see
// ExecWorkspace).
func (c *Client) AsyncExec(command string, installPackages bool, mountedVolume string) (execID string, err error) {
	fields := c.appendVolumeIdentity(
		[][]byte{strField(command), strField(installPkgs(installPackages))},
		mountedVolume)
	_, _, stdout, _, _, e := c.roundTrip(opAsyncExec, asyncExecReadTimeout, fields...)
	if e != nil {
		return "", e
	}
	return stdout, nil
}

// MountAndAsyncExec is the combined mount + async_exec call: it bind-mounts
// the agent directory then starts the background command in a single vsock
// round-trip. volumeMode is the identity record's mode ("flat"/"overlay").
// Used on the cold/cross-agent async path to save one RTT.
// Returns exec_id and the warden's actually-mounted volume basename (see
// MountAndExec) on success.
func (c *Client) MountAndAsyncExec(devicePath, mountPoint, command string, installPackages bool, volumeMode string) (execID, mounted string, err error) {
	code, _, stdoutB, _, mountedB, _, e := c.roundTripRaw(opMountAndAsyncExec, asyncExecReadTimeout,
		strField(devicePath), strField(mountPoint), strField("none"), strField(command), strField(installPkgs(installPackages)), strField(volumeMode))
	if e != nil {
		return "", "", e
	}
	if code == codeMountTargetNotExported {
		return "", "", ErrMountTargetNotExported
	}
	return string(stdoutB), mountedB, nil
}

// StatusExec reports a background exec's liveness + a tail of its output log.
// status is one of: "running", "done", "killed", "not_found". exitCode is
// best-effort (0 for done; the warden does not capture exit codes for
// background execs — agents should echo $? to the log if they need it).
func (c *Client) StatusExec(execID string) (logTail string, status string, exitCode int, err error) {
	code, _, stdout, _, _, e := c.roundTrip(opStatusExec, statusReadTimeout, strField(execID))
	if e != nil {
		return "", "", 0, e
	}
	switch code {
	case codeBgRunning:
		return stdout, "running", 0, nil
	case codeBgKilled:
		return stdout, "killed", 0, nil
	case codeBgNotFound:
		return stdout, "not_found", 0, nil
	default:
		// CODE_OK: natural exit. The warden does not capture bg exit codes
		// (the subreaper reaps without writing back); exitCode is 0.
		return stdout, "done", 0, nil
	}
}

// KillExec SIGKILLs a background exec's whole process group by exec_id.
// Returns nil on success; an error (possibly TransportError) on failure.
// ErrBgExecNotFound is returned by KillExec when the warden answers
// BG_NOT_FOUND — the exec_id is not (or no longer) in the registry. A
// distinct sentinel so callers report "not_found" truthfully instead of the
// blanket "killed".
var ErrBgExecNotFound = errors.New("background exec not found")

func (c *Client) KillExec(execID string) error {
	code, _, _, _, _, e := c.roundTrip(opKillExec, statusReadTimeout, strField(execID))
	if e != nil {
		return e
	}
	if code == codeBgNotFound {
		return ErrBgExecNotFound
	}
	return nil
}

// --- File I/O operations (OP_FILE) ---

// FileOpRequest carries the parameters for a single OP_FILE call.
// SubOp selects the operation; only the fields relevant to that sub-op
// are populated. All paths are relative to the chroot root (/mnt/rootfs).
type FileOpRequest struct {
	SubOp     byte   // one of subOpRead/subOpWrite/.../subOpRename
	Path      string // all ops
	NewPath   string // RENAME only (destination)
	Offset    int64  // READ/WRITE: byte offset (-1 = append for WRITE)
	Length    int64  // READ: max bytes to read (0 = up to cap)
	Mode      uint32 // WRITE/MKDIR: file/directory mode (0 = default)
	Recursive bool   // REMOVE: recursive (rm -rf)
	Depth     uint32 // LIST_DIR: recursion depth (0 = flat)
	Data      []byte // WRITE: raw file content (binary-safe)
	// MountedVolume is the mounted-volume identity asserted on this op (see
	// ExecWorkspace): the identity of the volume the caller believes is
	// mounted. "" sends a present-but-empty field (the warden then takes its
	// mount_active-only path with a rate-limited warn).
	MountedVolume string
}

// FileOpResponse carries the result of a single OP_FILE call.
// Data holds file bytes (READ) or JSON metadata (STAT/LIST_DIR). On an
// application-level failure (CODE_APP_ERROR: ENOENT, EACCES, ...) Success is
// false and Error holds the message; the VM is still healthy so the caller
// must NOT invalidate the cached connection.
type FileOpResponse struct {
	Data    []byte // READ: file bytes; STAT: JSON EntryInfo; LIST_DIR: JSON []EntryInfo
	Success bool   // true = CODE_OK, false = CODE_APP_ERROR
	Error   string // app-error message (Success=false only)
}

// EntryInfo mirrors the warden's EntryInfo struct (JSON-serialized in STAT/LIST_DIR).
type EntryInfo struct {
	Name         string `json:"name"`
	Path         string `json:"path"`
	FileType     string `json:"file_type"` // "file" | "dir" | "symlink"
	Size         uint64 `json:"size"`
	Mode         uint32 `json:"mode"`
	ModifiedTime string `json:"modified_time,omitempty"`
}

// FileOp sends a single OP_FILE request to the warden and returns the result.
// This is the unified entry point for all file I/O operations: the sub-opcode
// in req.SubOp selects which operation to perform. The mounted-volume identity
// (req.MountedVolume) rides the fixed index — file ops resolve paths inside the
// mounted volume, so a bookkeeping skew would touch the wrong tenant's files.
func (c *Client) FileOp(req FileOpRequest) (*FileOpResponse, error) {
	// Build the field list: sub_op (1 byte) + path + op-specific fields.
	subOpField := []byte{req.SubOp}
	pathField := strField(req.Path)

	var fields [][]byte
	switch req.SubOp {
	case SubOpRead:
		fields = [][]byte{
			subOpField,
			pathField,
			strField(strconv.FormatInt(req.Offset, 10)),
			strField(strconv.FormatInt(req.Length, 10)),
		}
	case SubOpWrite:
		fields = [][]byte{
			subOpField,
			pathField,
			strField(strconv.FormatInt(req.Offset, 10)),
			strField(strconv.FormatUint(uint64(req.Mode), 10)),
			req.Data, // raw bytes field (binary-safe)
		}
	case SubOpStat:
		fields = [][]byte{subOpField, pathField}
	case SubOpListDir:
		fields = [][]byte{
			subOpField,
			pathField,
			strField(strconv.FormatUint(uint64(req.Depth), 10)),
		}
	case SubOpMakeDir:
		fields = [][]byte{
			subOpField,
			pathField,
			strField(strconv.FormatUint(uint64(req.Mode), 10)),
		}
	case SubOpRemove:
		recStr := "0"
		if req.Recursive {
			recStr = "1"
		}
		fields = [][]byte{
			subOpField,
			pathField,
			strField(recStr),
		}
	case SubOpRename:
		fields = [][]byte{
			subOpField,
			pathField,
			strField(req.NewPath),
		}
	default:
		return nil, fmt.Errorf("unknown file sub_op: %d", req.SubOp)
	}

	// Fixed position (fileOpVolumeIdentityIndex): pad any gap a shorter sub-op
	// left with empty fields, then append the identity. The warden reads
	// exactly this index, so the padding is part of the ABI.
	for len(fields) < fileOpVolumeIdentityIndex {
		fields = append(fields, nil)
	}
	fields = append(fields, strField(req.MountedVolume))

	code, _, stdout, _, _, _, err := c.roundTripRaw(opFile, fileReadTimeout, fields...)
	if err != nil {
		return nil, err
	}
	if code == codeAppError {
		// Application-level failure (ENOENT, EACCES, ...): the VM is healthy,
		// do NOT invalidate the connection. The error message is in stdout.
		return &FileOpResponse{Data: nil, Success: false, Error: string(stdout)}, nil
	}
	return &FileOpResponse{Data: stdout, Success: true}, nil
}

// roundTripRaw is like roundTrip but returns stdout as raw []byte instead of
// string. Required for OP_FILE because file content (READ) is binary data
// that must not be lossily converted through string. Returns the response
// code, exit code, raw stdout, stderr, the warden's mounted-volume assertion
// (non-empty only on successful MOUNT-family ops — see MountAndExec), and
// bodyMACFieldValues returns the body fields whose bytes the op-specific MAC
// binds. The indices are the fixed protocol positions (see IDX_* in the
// warden and the field order of each op); everything else stays unhashed.
func bodyMACFieldValues(op uint8, fields [][]byte) [][]byte {
	at := func(i int) []byte {
		if i < len(fields) {
			return fields[i]
		}
		return nil
	}
	switch op {
	case opExec:
		return [][]byte{at(3)}
	case opAsyncExec:
		return [][]byte{at(2)}
	case opFile:
		return [][]byte{at(fileOpVolumeIdentityIndex)}
	case opMountAndExec:
		return [][]byte{at(0), at(1), at(6)}
	case opMountAndAsyncExec:
		return [][]byte{at(0), at(1), at(5)}
	case opUnmount:
		return [][]byte{at(0), at(1), at(2)}
	default:
		return nil
	}
}

// wall time. A CODE_TRANSPORT_ERROR is returned as a TransportError (caller
// invalidates the connection); other codes are returned for the caller to
// interpret.
func (c *Client) roundTripRaw(op uint8, readTimeout time.Duration, fields ...[]byte) (code uint8, exitCode uint8, stdout []byte, stderr string, mounted string, execDurationNs uint64, err error) {
	if !c.hasSessionKey {
		return 0, 0, nil, "", "", 0, &TransportError{Op: "auth", Err: errors.New("warden session key not configured")}
	}
	if err := c.setConnReadTimeout(clampReadTimeout(readTimeout, c.readTimeoutCap)); err != nil {
		return 0, 0, nil, "", "", 0, &TransportError{Op: "write", Err: fmt.Errorf("set SO_RCVTIMEO: %w", err)}
	}
	nonce := c.nextNonce()
	body := encodeBody(fields)
	var bm [bodyMACLen]byte
	if mf := bodyMACFieldValues(op, fields); mf != nil {
		bm = bodyMAC(c.sessionKey[:], &nonce, op, mf...)
	}
	frame := make([]byte, reqHeaderLen+len(body))
	binary.BigEndian.PutUint32(frame[0:4], magic)
	frame[4] = protocolVersion
	frame[5] = op
	binary.BigEndian.PutUint32(frame[6:10], uint32(len(body)))
	copy(frame[10:10+nonceLen], nonce[:])
	copy(frame[10+nonceLen:10+nonceLen+bodyMACLen], bm[:])
	tag := requestTag(c.sessionKey[:], protocolVersion, op, uint32(len(body)), &nonce, &bm)
	copy(frame[10+nonceLen+bodyMACLen:reqHeaderLen], tag[:])
	copy(frame[reqHeaderLen:], body)

	if err := c.setConnWriteTimeout(writeTimeout); err != nil {
		return 0, 0, nil, "", "", 0, &TransportError{Op: "write", Err: fmt.Errorf("set SO_SNDTIMEO: %w", err)}
	}
	if _, err := c.conn.Write(frame); err != nil {
		return 0, 0, nil, "", "", 0, &TransportError{Op: "write", Err: err}
	}

	code, exitCode, stdout, stderr, mounted, execDurationNs, rerr := readResponseRaw(c.conn, c.sessionKey[:], &nonce)
	if rerr != nil {
		var pve *ProtocolVersionError
		if errors.As(rerr, &pve) {
			// Pass the typed error through unwrapped — the generic wrap below
			// would bury the version numbers under a plain TransportError and
			// callers could not fail fast on them.
			return 0, 0, nil, "", "", 0, rerr
		}
		var ae *AuthError
		if errors.As(rerr, &ae) {
			// Likewise: callers must be able to distinguish a forged/tampered
			// response (destroy the VM) from an ordinary read failure.
			return 0, 0, nil, "", "", 0, rerr
		}
		return 0, 0, nil, "", "", 0, &TransportError{Op: "read", Err: rerr}
	}
	if code == codeTransportErr {
		return code, 0, nil, stderr, "", 0, classifyTransportRefusal(stderr)
	}
	return code, exitCode, stdout, stderr, mounted, execDurationNs, nil
}

// maxRespSegment caps one response segment (stdout / stderr) accepted off the
// wire, BEFORE any allocation. Legitimate warden responses are bounded far
// below (exec output pipes and file reads cap at ~16 MiB), so a length past
// this bound is a corrupt or hostile frame: attempting the make() straight
// from the u32 (two 0xFFFFFFFFs claim 8 GiB) would OOM-kill the whole node
// daemon over one bad frame. Two integer compares on the hot path — free.
const maxRespSegment = 32 << 20

// Typed sentinels for the warden's NAMED warm-op isolation refusals
// (raw_server.rs ERR_VOLUME_IDENTITY_*): the message carries the token as
// its leading word, so callers (and the gateway's security-event
// classifier) can branch on a typed error or a stable token instead of
// free-text drift. The warden's own text rides along unchanged.
var (
	// ErrVolumeIdentityMismatch — the warm op named a volume other than the
	// one the warden holds at /mnt/rootfs (sandlot bookkeeping skew).
	ErrVolumeIdentityMismatch = errors.New("volume_identity_mismatch")
	// ErrVolumeIdentityMissing — the warm op carried no identity at all.
	ErrVolumeIdentityMissing = errors.New("volume_identity_missing")
)

// classifyTransportRefusal wraps a transport-error stderr into the typed
// sentinel when it carries one of the warden's named isolation-refusal
// tokens, else the generic transport-error form. The named token stays
// prefix-visible in every wrap (the gateway's /metrics classifier matches
// it by substring). Pure.
func classifyTransportRefusal(stderr string) error {
	if strings.HasPrefix(stderr, "volume_identity_mismatch:") {
		return fmt.Errorf("%w: %s", ErrVolumeIdentityMismatch, stderr)
	}
	if strings.HasPrefix(stderr, "volume_identity_missing:") {
		return fmt.Errorf("%w: %s", ErrVolumeIdentityMissing, stderr)
	}
	return fmt.Errorf("warden rpc failed: %s", stderr)
}

// ErrMountTargetNotExported — the mount request named an alias the VMM's
// CURRENT filter generation does not export: the request lost the race to a
// later set-fs. The guest mount state is untouched (no bind, no exec), so the
// caller must NOT dirty-destroy a VM that may now be serving another tenant.
var ErrMountTargetNotExported = errors.New("mount_target_not_exported")

// UnmountOutcome is the warden's identity-bound teardown verdict.
type UnmountOutcome int

const (
	// UnmountRemoved — the named generation's mount was torn down.
	UnmountRemoved UnmountOutcome = iota
	// UnmountNotMounted — nothing was mounted (idempotent no-op).
	UnmountNotMounted
	// UnmountMismatch — the live mount carries a different identity; nothing
	// was torn down. current is the live identity (for logging only).
	UnmountMismatch
)

// maxRespTotal bounds the SUM of the three response segments before the
// single shared allocation. It matches the largest legitimate single-op
// payload (the 16 MiB gRPC message minus the envelope headroom).
const maxRespTotal = commonconfig.MinFileOpChainBytes - commonconfig.FileOpWireSlackBytes

// readResponseRaw reads one response frame and returns stdout as raw []byte.
// The stdout, stderr and mounted segments are contiguous on the stream, so
// they are read with ONE ReadFull into a shared buffer (two syscalls per
// response instead of four); the returned segments alias that buffer.
func readResponseRaw(r io.Reader, key []byte, nonce *[nonceLen]byte) (code uint8, exitCode uint8, stdout []byte, stderr string, mounted string, execDurationNs uint64, err error) {
	hdr := make([]byte, respHeaderLen)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return 0, 0, nil, "", "", 0, fmt.Errorf("read response header: %w", err)
	}
	m := binary.BigEndian.Uint32(hdr[0:4])
	if m != magic {
		return 0, 0, nil, "", "", 0, fmt.Errorf("bad response magic 0x%x", m)
	}
	// Version first: an unsupported peer may not share this header layout, so
	// its reply must be classified by the version byte, never by the tag.
	if hdr[4] != protocolVersion {
		return 0, 0, nil, "", "", 0, versionMismatch(hdr[4])
	}
	code = hdr[5]
	exitCode = hdr[6]
	// hdr[7] is reserved (ignored)
	stdoutLen := binary.BigEndian.Uint32(hdr[8:12])
	stderrLen := binary.BigEndian.Uint32(hdr[12:16])
	execDurationNs = binary.BigEndian.Uint64(hdr[16:24])
	mountedLen := binary.BigEndian.Uint32(hdr[24:28])
	expected := responseTag(key, nonce, hdr[4], code, exitCode, stdoutLen, stderrLen, execDurationNs, mountedLen)
	if !hmac.Equal(hdr[respBaseLen:respHeaderLen], expected[:]) {
		return 0, 0, nil, "", "", 0, &AuthError{TransportError: TransportError{
			Op:  "read",
			Err: errors.New("response tag mismatch (forged responder or corrupted frame)"),
		}}
	}

	stdoutB, stderrB, mountedB, mountedMAC, err := readResponseBody(r, stdoutLen, stderrLen, mountedLen)
	if err != nil {
		return 0, 0, nil, "", "", 0, err
	}
	// The header tag authenticated the mounted LENGTH before any body read;
	// this MAC authenticates the mounted CONTENT, so the exclusive-ownership
	// assertion the caller cross-checks cannot be rewritten by a kernel
	// implant.
	wantMounted := mountedTag(key, nonce, mountedB)
	if !hmac.Equal(mountedMAC, wantMounted[:]) {
		return 0, 0, nil, "", "", 0, &AuthError{TransportError: TransportError{
			Op:  "read",
			Err: errors.New("mounted-identity MAC mismatch (forged responder or corrupted frame)"),
		}}
	}
	return code, exitCode, stdoutB, string(stderrB), string(mountedB), execDurationNs, nil
}

// readResponseBody reads the stdout+stderr+mounted tail and the trailing
// mounted MAC of a response frame in a single ReadFull (they are contiguous on
// the stream) and returns the segments as views into one shared buffer.
// Segment lengths are validated against maxRespSegment before the allocation
// (see its doc).
func readResponseBody(r io.Reader, stdoutLen, stderrLen, mountedLen uint32) ([]byte, []byte, []byte, []byte, error) {
	if stdoutLen > maxRespSegment || stderrLen > maxRespSegment || mountedLen > maxRespSegment {
		return nil, nil, nil, nil, fmt.Errorf("response segment length %d/%d/%d exceeds %d (corrupt or hostile frame; connection discarded)",
			stdoutLen, stderrLen, mountedLen, maxRespSegment)
	}
	// The segments are contiguous on the wire and allocated in one make():
	// cap their SUM before the allocation. The gRPC command envelope is
	// 16 MiB, so a response that fits the per-segment cap but not the total
	// would otherwise allocate up to 96 MiB and then fail to marshal — a
	// hostile warden's cheap node-memory amplification.
	total := uint64(stdoutLen) + uint64(stderrLen) + uint64(mountedLen)
	if total > maxRespTotal {
		return nil, nil, nil, nil, fmt.Errorf("response total %d bytes exceeds %d (corrupt or hostile frame; connection discarded)",
			total, maxRespTotal)
	}
	body := make([]byte, int(stdoutLen)+int(stderrLen)+int(mountedLen)+tagLen)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("read response body: %w", err)
	}
	stderrEnd := int(stdoutLen) + int(stderrLen)
	mountedEnd := stderrEnd + int(mountedLen)
	return body[:stdoutLen], body[stdoutLen:stderrEnd], body[stderrEnd:mountedEnd], body[mountedEnd:], nil
}

// timeoutMs converts a Duration to the ASCII ms the warden expects (0 = default).
func timeoutMs(d time.Duration) string {
	return strconv.FormatUint(uint64(d.Milliseconds()), 10)
}

// installPkgs returns "1" if package installation mode is enabled, "" otherwise.
// This is the last field in the warden wire protocol for exec ops; the warden
// treats "" (missing) as false (strict mode) for backward compatibility.
func installPkgs(enabled bool) string {
	if enabled {
		return "1"
	}
	return ""
}

// MemStats asks the warden for the guest's MemAvailable and MemTotal in bytes
// (returned as "avail total" ASCII in the stdout field). Used by sandlot's
// heartbeat loop to feed the gateway's OOM-B VM reclaim threshold.
func (c *Client) MemStats() (avail, total uint64, err error) {
	code, _, stdout, _, _, e := c.roundTrip(opMemStats, memStatsReadTimeout)
	if e != nil {
		return 0, 0, e
	}
	if code == codeAppError {
		// /proc/meminfo unreadable — VM healthy, business failure (probe will
		// record a failure, not a connection invalidation).
		return 0, 0, fmt.Errorf("warden mem_stats failed: %s", stdout)
	}
	// The legitimate response is "avail total" (tens of bytes). Refuse a
	// long stdout before strings.Fields turns each token into a string
	// header: a 32 MiB "a a a ..." allocates ~256 MiB on the node.
	if len(stdout) > 4096 {
		return 0, 0, fmt.Errorf("warden mem_stats response too large (%d bytes)", len(stdout))
	}
	parts := strings.Fields(strings.TrimSpace(stdout))
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("warden mem_stats bad response: %q", stdout)
	}
	avail, err = strconv.ParseUint(parts[0], 10, 64)
	if err != nil {
		return 0, 0, err
	}
	total, err = strconv.ParseUint(parts[1], 10, 64)
	return avail, total, err
}

// encodeBody builds the request body: [u32 len][bytes] per field.
func encodeBody(fields [][]byte) []byte {
	var body []byte
	for _, f := range fields {
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(f)))
		body = append(body, l[:]...)
		body = append(body, f...)
	}
	return body
}

// roundTrip sends one request frame and reads one response frame, returning
// stdout as a string. Thin wrapper over roundTripRaw (the single wire codec —
// no parallel implementation to keep in sync). See roundTripRaw for the
// semantics of each return value.
func (c *Client) roundTrip(op uint8, readTimeout time.Duration, fields ...[]byte) (code uint8, exitCode uint8, stdout, stderr string, execDurationNs uint64, err error) {
	var stdoutB []byte
	code, exitCode, stdoutB, stderr, _, execDurationNs, err = c.roundTripRaw(op, readTimeout, fields...)
	if err != nil {
		return 0, 0, "", "", 0, err
	}
	return code, exitCode, string(stdoutB), stderr, execDurationNs, nil
}

// readResponse reads one response frame and returns stdout as a string. Thin
// wrapper over readResponseRaw (the single frame parser). The mounted-volume
// assertion is dropped here — only the MOUNT-family methods surface it.
func readResponse(r io.Reader, key []byte, nonce *[nonceLen]byte) (code uint8, exitCode uint8, stdout string, stderr string, execDurationNs uint64, err error) {
	var stdoutB []byte
	code, exitCode, stdoutB, stderr, _, execDurationNs, err = readResponseRaw(r, key, nonce)
	if err != nil {
		return 0, 0, "", "", 0, err
	}
	return code, exitCode, string(stdoutB), stderr, execDurationNs, nil
}

// strField is a trivial helper kept for symmetry with the request builder.
func strField(s string) []byte { return []byte(s) }

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

package warden

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// --- fakeConn: in-memory rpcConn for testing roundTrip without AF_VSOCK ---

// fakeConn implements rpcConn with controllable read/write behavior.
// Write stores frames to buf; Read returns from respBuf (or respErr).
type fakeConn struct {
	buf     bytes.Buffer // captures written frames
	respBuf bytes.Buffer // pre-loaded response frames
	respErr error        // if set, Read returns this error
	closed  bool
}

func (c *fakeConn) Read(p []byte) (int, error) {
	if c.respErr != nil {
		return 0, c.respErr
	}
	return c.respBuf.Read(p)
}

func (c *fakeConn) Write(p []byte) (int, error) {
	return c.buf.Write(p)
}

func (c *fakeConn) Close() error {
	c.closed = true
	return nil
}

// TestAuthTagCrossLanguageVector pins the wire bytes against the Rust
// implementation (warden/src/auth.rs). The two sides must produce identical
// tags for the same key/nonce/fields; a drift in label, field order, or key
// padding fails here before a deploy.
func TestAuthTagCrossLanguageVector(t *testing.T) {
	key := bytes.Repeat([]byte{0x11}, 32)
	var nonce [nonceLen]byte
	for i := range nonce {
		nonce[i] = byte(i)
	}
	bodyMACValue := bytes.Repeat([]byte{0x44}, 32)
	wantReq, _ := hex.DecodeString("a29e407ff863cad30227edba10159711ec1b9e74894fc25ee7577f2df0610a7d")
	var bm [bodyMACLen]byte
	copy(bm[:], bodyMACValue)
	gotReq := requestTag(key, 2, 1, 0, &nonce, &bm)
	if !bytes.Equal(gotReq[:], wantReq) {
		t.Fatalf("request tag = %x, want %x", gotReq, wantReq)
	}
	wantBody, _ := hex.DecodeString("30570df5bb0e09b601716dd1ce020cf1a86af46f05c963bec5d654e9641ab2b2")
	gotBody := bodyMAC(key, &nonce, 1, []byte("gen0"), []byte("/mnt/rootfs"), []byte("flat"))
	if !bytes.Equal(gotBody[:], wantBody) {
		t.Fatalf("body mac = %x, want %x", gotBody, wantBody)
	}
	wantMounted, _ := hex.DecodeString("dfc0589f316104b3cf7070a0d17800b1bec5b24f36c3e625741873033991d923")
	gotMounted := mountedTag(key, &nonce, []byte("sf-abc"))
	if !bytes.Equal(gotMounted[:], wantMounted) {
		t.Fatalf("mounted tag = %x, want %x", gotMounted, wantMounted)
	}
	wantResp, _ := hex.DecodeString("aa2103e82c4ca35abd951492965daf74fbd4080420a117f5ed0cac9d54769eab")
	gotResp := responseTag(key, &nonce, 1, 0, 0, 5, 7, 123456789, 9)
	if !bytes.Equal(gotResp[:], wantResp) {
		t.Fatalf("response tag = %x, want %x", gotResp, wantResp)
	}
}

// Test session key and nonce. Every response built for the tests is signed
// with these, matching the client under test.
var (
	testSessionKey  = bytes.Repeat([]byte{0x42}, 32)
	testNoncePrefix = [8]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	// The client's first nonce is prefix||1 (nextNonce increments from 0).
	testNonce = [nonceLen]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0, 0, 0, 0, 0, 0, 0, 1}
)

// signTestHeader writes the response tag for testNonce into hdr[respBaseLen:].
// The base fields (0..27) must already be filled.
func signTestHeader(hdr []byte) {
	stdoutLen := binary.BigEndian.Uint32(hdr[8:12])
	stderrLen := binary.BigEndian.Uint32(hdr[12:16])
	dur := binary.BigEndian.Uint64(hdr[16:24])
	mountedLen := binary.BigEndian.Uint32(hdr[24:28])
	tag := responseTag(testSessionKey, &testNonce, hdr[4], hdr[5], hdr[6], stdoutLen, stderrLen, dur, mountedLen)
	copy(hdr[respBaseLen:respHeaderLen], tag[:])
}

// newTestClient creates a Client with a fakeConn transport, built through the
// REAL constructor (newClient) so the negotiated-version initialization and
// the session-key setup are exercised exactly as dial does.
func newTestClient(fc *fakeConn) *Client {
	return newClient(fc, 42, ReadTimeoutCapDefault, testSessionKey, testNoncePrefix)
}

// testReadTimeout is the read-timeout argument used by the direct roundTrip
// call sites in these tests. The fakeConn has no kernel socket, so setConnReadTimeout
// is a no-op; the value only needs to be legal (nonzero, within cap).
const testReadTimeout = 30 * time.Second

// buildResponse builds a wire-format response frame (protocol version 1).
// code is the response category; exitCode is the process exit code (only
// meaningful for sync exec on code=codeOk).
func buildResponse(code uint8, exitCode uint8, stdout, stderr string) []byte {
	return buildResponseDur(code, exitCode, stdout, stderr, 0)
}

// buildResponseDur is buildResponse with an explicit exec_duration_ns, used to
// verify UnmountRootfs threads the warden unmount wall time back to its caller.
func buildResponseDur(code uint8, exitCode uint8, stdout, stderr string, execDurationNs uint64) []byte {
	return buildResponseFull(code, exitCode, stdout, stderr, execDurationNs, "")
}

// buildResponseFull builds one signed response frame. mounted is empty for
// every op except the MOUNT family.
func buildResponseFull(code uint8, exitCode uint8, stdout, stderr string, execDurationNs uint64, mounted string) []byte {
	var buf bytes.Buffer
	hdr := make([]byte, respHeaderLen)
	binary.BigEndian.PutUint32(hdr[0:4], magic)
	hdr[4] = protocolVersion
	hdr[5] = code
	hdr[6] = exitCode
	hdr[7] = 0 // reserved
	binary.BigEndian.PutUint32(hdr[8:12], uint32(len(stdout)))
	binary.BigEndian.PutUint32(hdr[12:16], uint32(len(stderr)))
	binary.BigEndian.PutUint64(hdr[16:24], execDurationNs)
	binary.BigEndian.PutUint32(hdr[24:28], uint32(len(mounted)))
	signTestHeader(hdr)
	buf.Write(hdr)
	buf.WriteString(stdout)
	buf.WriteString(stderr)
	buf.WriteString(mounted)
	mac := mountedTag(testSessionKey, &testNonce, []byte(mounted))
	buf.Write(mac[:])
	return buf.Bytes()
}

// buildResponseMounted is buildResponse with a non-empty mounted-volume
// assertion — the shape successful MOUNT-family ops reply with.
func buildResponseMounted(code uint8, exitCode uint8, stdout, stderr, mounted string) []byte {
	return buildResponseFull(code, exitCode, stdout, stderr, 0, mounted)
}

// --- TransportError type tests ---

func TestTransportErrorError(t *testing.T) {
	te := &TransportError{Op: "write", Err: errors.New("EPIPE")}
	got := te.Error()
	want := "warden transport write: EPIPE"
	if got != want {
		t.Errorf("TransportError.Error() = %q, want %q", got, want)
	}
}

func TestTransportErrorUnwrap(t *testing.T) {
	inner := errors.New("ECONNRESET")
	te := &TransportError{Op: "read", Err: inner}
	if unwrapped := te.Unwrap(); unwrapped != inner {
		t.Errorf("TransportError.Unwrap() = %v, want %v", unwrapped, inner)
	}
}

func TestTransportErrorAs(t *testing.T) {
	err := &TransportError{Op: "write", Err: errors.New("broken")}
	var te *TransportError
	if !errors.As(err, &te) {
		t.Fatal("errors.As failed to match TransportError")
	}
	if te.Op != "write" {
		t.Errorf("Op = %q, want %q", te.Op, "write")
	}
}

// --- roundTrip write failure → TransportError{Op: "write"} ---

func TestRoundTrip_WriteError_TransportError(t *testing.T) {
	// Make Write fail by using a conn that always errors on Write.
	c := newClient(&errorWriterConn{}, 42, ReadTimeoutCapDefault, testSessionKey, testNoncePrefix)

	_, _, _, _, _, err := c.roundTrip(opExec, testReadTimeout, strField("echo hi"))
	if err == nil {
		t.Fatal("roundTrip should fail on write error")
	}
	var te *TransportError
	if !errors.As(err, &te) {
		t.Fatalf("expected TransportError, got %T: %v", err, err)
	}
	if te.Op != "write" {
		t.Errorf("Op = %q, want %q", te.Op, "write")
	}
}

// errorWriterConn always fails on Write, succeeds on Read (never reached).
type errorWriterConn struct{}

func (c *errorWriterConn) Read(p []byte) (int, error)  { return 0, io.EOF }
func (c *errorWriterConn) Write(p []byte) (int, error) { return 0, errors.New("EPIPE") }
func (c *errorWriterConn) Close() error                { return nil }

// --- roundTrip read failure → TransportError{Op: "read"} ---

func TestRoundTrip_ReadError_TransportError(t *testing.T) {
	fc := &fakeConn{
		respErr: errors.New("ECONNRESET"),
	}
	c := newTestClient(fc)

	_, _, _, _, _, err := c.roundTrip(opExec, testReadTimeout, strField("echo hi"))
	if err == nil {
		t.Fatal("roundTrip should fail on read error")
	}
	var te *TransportError
	if !errors.As(err, &te) {
		t.Fatalf("expected TransportError, got %T: %v", err, err)
	}
	if te.Op != "read" {
		t.Errorf("Op = %q, want %q", te.Op, "read")
	}
}

// --- roundTrip RPC error (status=-1) → NOT TransportError ---

func TestRoundTrip_RPCError_NotTransportError(t *testing.T) {
	fc := &fakeConn{}
	resp := buildResponse(codeTransportErr, 0, "", "mount failed: ENOENT")
	fc.respBuf.Write(resp)
	c := newTestClient(fc)

	_, _, _, _, _, err := c.roundTrip(opMountAndExec, testReadTimeout, strField("/dev/none"), strField("/mnt/rootfs"))
	if err == nil {
		t.Fatal("roundTrip should fail on RPC error (status=-1)")
	}
	var te *TransportError
	if errors.As(err, &te) {
		t.Fatalf("RPC error should NOT be TransportError, got %T: %v", err, err)
	}
	// Verify it's the expected RPC error message.
	if got := err.Error(); got != "warden rpc failed: mount failed: ENOENT" {
		t.Errorf("error = %q, want %q", got, "warden rpc failed: mount failed: ENOENT")
	}
}

// --- roundTrip background-exec sentinels are NOT errors ---

func TestRoundTrip_BgRunning_NotError(t *testing.T) {
	fc := &fakeConn{}
	resp := buildResponse(codeBgRunning, 0, "partial log", "")
	fc.respBuf.Write(resp)
	c := newTestClient(fc)

	code, _, stdout, _, _, err := c.roundTrip(opStatusExec, testReadTimeout, strField("exec-1"))
	if err != nil {
		t.Fatalf("bgRunning should not be an error, got %v", err)
	}
	if code != codeBgRunning {
		t.Errorf("code = %d, want %d", code, codeBgRunning)
	}
	if stdout != "partial log" {
		t.Errorf("stdout = %q, want %q", stdout, "partial log")
	}
}

func TestRoundTrip_BgKilled_NotError(t *testing.T) {
	fc := &fakeConn{}
	resp := buildResponse(codeBgKilled, 0, "", "")
	fc.respBuf.Write(resp)
	c := newTestClient(fc)

	code, _, _, _, _, err := c.roundTrip(opStatusExec, testReadTimeout, strField("exec-1"))
	if err != nil {
		t.Fatalf("bgKilled should not be an error, got %v", err)
	}
	if code != codeBgKilled {
		t.Errorf("code = %d, want %d", code, codeBgKilled)
	}
}

func TestRoundTrip_BgNotFound_NotError(t *testing.T) {
	fc := &fakeConn{}
	resp := buildResponse(codeBgNotFound, 0, "", "")
	fc.respBuf.Write(resp)
	c := newTestClient(fc)

	code, _, _, _, _, err := c.roundTrip(opStatusExec, testReadTimeout, strField("exec-missing"))
	if err != nil {
		t.Fatalf("bgNotFound should not be an error, got %v", err)
	}
	if code != codeBgNotFound {
		t.Errorf("code = %d, want %d", code, codeBgNotFound)
	}
}

func TestRoundTrip_TimedOut_NotError(t *testing.T) {
	fc := &fakeConn{}
	resp := buildResponse(codeTimedOut, 0, "", "timed out after 30s")
	fc.respBuf.Write(resp)
	c := newTestClient(fc)

	code, _, _, _, _, err := c.roundTrip(opExec, testReadTimeout, strField("sleep 999"))
	if err != nil {
		t.Fatalf("timedOut should not be an error, got %v", err)
	}
	if code != codeTimedOut {
		t.Errorf("code = %d, want %d", code, codeTimedOut)
	}
}

// --- roundTrip success (status=0) ---

func TestRoundTrip_Success(t *testing.T) {
	fc := &fakeConn{}
	resp := buildResponse(codeOk, 0, "hello world", "")
	fc.respBuf.Write(resp)
	c := newTestClient(fc)

	code, _, stdout, stderr, _, err := c.roundTrip(opExec, testReadTimeout, strField("echo hello"))
	if err != nil {
		t.Fatalf("success: unexpected error %v", err)
	}
	if code != codeOk {
		t.Errorf("code = %d, want %d", code, codeOk)
	}
	if stdout != "hello world" {
		t.Errorf("stdout = %q, want %q", stdout, "hello world")
	}
	if stderr != "" {
		t.Errorf("stderr = %q, want empty", stderr)
	}
}

// --- roundTrip success with non-zero exit code (sync exec) ---

func TestRoundTrip_NonZeroExitCode(t *testing.T) {
	// A command that exits 1 is CODE_OK with exit_code=1 — NOT an error.
	// The transport succeeded; the command just returned non-zero.
	fc := &fakeConn{}
	resp := buildResponse(codeOk, 1, "", "command not found")
	fc.respBuf.Write(resp)
	c := newTestClient(fc)

	code, exitCode, stdout, stderr, _, err := c.roundTrip(opExec, testReadTimeout, strField("badcmd"))
	if err != nil {
		t.Fatalf("non-zero exit should not be an error, got %v", err)
	}
	if code != codeOk {
		t.Errorf("code = %d, want %d", code, codeOk)
	}
	if exitCode != 1 {
		t.Errorf("exitCode = %d, want 1", exitCode)
	}
	_ = stdout
	_ = stderr
}

// --- readResponse: bad magic ---

func TestReadResponse_BadMagic(t *testing.T) {
	var buf bytes.Buffer
	var m [4]byte
	binary.BigEndian.PutUint32(m[:], 0xDEADBEEF) // wrong magic
	buf.Write(m[:])
	// Pad the rest of the header + empty body
	buf.Write(make([]byte, respHeaderLen-4))

	_, _, _, _, _, err := readResponse(&buf, testSessionKey, &testNonce)
	if err == nil {
		t.Fatal("readResponse should fail on bad magic")
	}
	if got := err.Error(); got != "bad response magic 0xdeadbeef" {
		t.Errorf("error = %q, want bad magic message", got)
	}
}

// --- readResponse: truncated header ---

func TestReadResponse_TruncatedHeader(t *testing.T) {
	// Only 4 bytes instead of 16-byte header
	var buf bytes.Buffer
	buf.Write([]byte{0x53, 0x41, 0x4E, 0x44}) // magic only

	_, _, _, _, _, err := readResponse(&buf, testSessionKey, &testNonce)
	if err == nil {
		t.Fatal("readResponse should fail on truncated header")
	}
}

// --- readResponse: truncated body ---

func TestReadResponse_TruncatedBody(t *testing.T) {
	var buf bytes.Buffer
	hdr := make([]byte, respHeaderLen)
	binary.BigEndian.PutUint32(hdr[0:4], magic)
	hdr[4] = protocolVersion
	hdr[5] = codeOk
	hdr[6] = 0                                 // exit_code
	hdr[7] = 0                                 // reserved
	binary.BigEndian.PutUint32(hdr[8:12], 100) // stdout_len = 100 (but no body follows)
	binary.BigEndian.PutUint32(hdr[12:16], 0)  // stderr_len = 0
	binary.BigEndian.PutUint64(hdr[16:24], 0)  // exec_duration_ns
	binary.BigEndian.PutUint32(hdr[24:28], 0)  // mounted_len = 0
	signTestHeader(hdr)
	buf.Write(hdr)

	_, _, _, _, _, err := readResponse(&buf, testSessionKey, &testNonce)
	if err == nil {
		t.Fatal("readResponse should fail on truncated body")
	}
}

// --- request frame format verification ---

func TestRoundTrip_WireFormat(t *testing.T) {
	fc := &fakeConn{}
	// Load a valid success response so roundTrip completes.
	resp := buildResponse(codeOk, 0, "ok", "")
	fc.respBuf.Write(resp)
	c := newTestClient(fc)

	_, _, _, _, _, err := c.roundTrip(opMountAndExec, testReadTimeout,
		strField("/dev/vda"), strField("/mnt/rootfs"), strField("none"), strField("echo hi"), strField("30000"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify the written request frame.
	frame := fc.buf.Bytes()
	if len(frame) < reqHeaderLen {
		t.Fatalf("frame too short: %d bytes", len(frame))
	}

	// Check magic
	if got := binary.BigEndian.Uint32(frame[0:4]); got != magic {
		t.Errorf("magic = 0x%x, want 0x%x", got, magic)
	}

	// Check op
	if got := frame[5]; got != opMountAndExec {
		t.Errorf("op = %d, want %d", got, opMountAndExec)
	}

	// Check body_len
	bodyLen := binary.BigEndian.Uint32(frame[6:10])
	if bodyLen == 0 {
		t.Error("body_len should be > 0 for MountAndExec with fields")
	}

	// The authenticated header carries the nonce (prefix||counter, first
	// request = 1) and a tag that must verify over the fixed header fields.
	var gotNonce [nonceLen]byte
	copy(gotNonce[:], frame[10:10+nonceLen])
	if gotNonce != testNonce {
		t.Errorf("nonce = %x, want %x", gotNonce, testNonce)
	}
	var gotBodyMAC [bodyMACLen]byte
	copy(gotBodyMAC[:], frame[10+nonceLen:10+nonceLen+bodyMACLen])
	wantBodyMAC := bodyMAC(testSessionKey, &gotNonce, opMountAndExec,
		[]byte("/dev/vda"), []byte("/mnt/rootfs"), nil)
	if !bytes.Equal(gotBodyMAC[:], wantBodyMAC[:]) {
		t.Errorf("body MAC = %x, want %x", gotBodyMAC, wantBodyMAC)
	}
	wantTag := requestTag(testSessionKey, protocolVersion, opMountAndExec, bodyLen, &gotNonce, &gotBodyMAC)
	if !bytes.Equal(frame[10+nonceLen+bodyMACLen:reqHeaderLen], wantTag[:]) {
		t.Error("request tag does not verify over the frame header")
	}

	// The body should contain 5 length-prefixed fields
	body := frame[reqHeaderLen:] // base header + nonce + tag
	fieldCount := 0
	offset := 0
	for offset < len(body) {
		if offset+4 > len(body) {
			break
		}
		fLen := int(binary.BigEndian.Uint32(body[offset : offset+4]))
		offset += 4 + fLen
		fieldCount++
	}
	if fieldCount != 5 {
		t.Errorf("field count = %d, want 5", fieldCount)
	}
}

// --- UnmountRootfs delegates to roundTrip correctly ---

func TestUnmountRootfs(t *testing.T) {
	fc := &fakeConn{}
	const wantDur = uint64(1_500_000)                    // 1.5ms in ns
	resp := buildResponseDur(codeOk, 0, "", "", wantDur) // success
	fc.respBuf.Write(resp)
	c := newTestClient(fc)

	_, _, gotDur, err := c.UnmountRootfs("gen0")
	if err != nil {
		t.Fatalf("UnmountRootfs unexpected error: %v", err)
	}
	if gotDur != wantDur {
		t.Errorf("UnmountRootfs duration = %d ns, want %d ns", gotDur, wantDur)
	}

	// Verify op is UNMOUNT
	frame := fc.buf.Bytes()
	if frame[5] != opUnmount {
		t.Errorf("op = %d, want %d (opUnmount)", frame[5], opUnmount)
	}

	// Field order is the body-MAC contract: mount_point, identity, forced.
	body := frame[reqHeaderLen:]
	var fields [][]byte
	for offset := 0; offset < len(body); {
		if offset+4 > len(body) {
			t.Fatalf("truncated field length at offset %d", offset)
		}
		n := int(binary.BigEndian.Uint32(body[offset:]))
		offset += 4
		if offset+n > len(body) {
			t.Fatalf("truncated field value at offset %d", offset)
		}
		fields = append(fields, body[offset:offset+n])
		offset += n
	}
	if len(fields) != 3 || string(fields[0]) != "/mnt/rootfs" || string(fields[1]) != "gen0" || string(fields[2]) != "0" {
		t.Fatalf("unmount fields = %q, want [/mnt/rootfs gen0 0]", fields)
	}
	var nonce [nonceLen]byte
	copy(nonce[:], frame[10:10+nonceLen])
	var gotMAC [bodyMACLen]byte
	copy(gotMAC[:], frame[10+nonceLen:10+nonceLen+bodyMACLen])
	wantMAC := bodyMAC(testSessionKey, &nonce, opUnmount, fields...)
	if !bytes.Equal(gotMAC[:], wantMAC[:]) {
		t.Fatal("unmount body MAC does not cover mount_point/identity/forced")
	}
}

// --- ExecWorkspace delegates to roundTrip correctly ---

func TestExecWorkspace(t *testing.T) {
	fc := &fakeConn{}
	resp := buildResponse(codeOk, 0, "output", "")
	fc.respBuf.Write(resp)
	c := newTestClient(fc)

	stdout, stderr, exitCode, _, _, err := c.ExecWorkspace("ls -la", 0, false, "sandfs-a")
	if err != nil {
		t.Fatalf("ExecWorkspace unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("exitCode = %d, want 0", exitCode)
	}
	if stdout != "output" {
		t.Errorf("stdout = %q, want %q", stdout, "output")
	}
	if stderr != "" {
		t.Errorf("stderr = %q, want empty", stderr)
	}

	// Verify op is EXEC
	frame := fc.buf.Bytes()
	if frame[5] != opExec {
		t.Errorf("op = %d, want %d (opExec)", frame[5], opExec)
	}
}

// --- warm-op mounted-volume identity assertion (current layout) ---

// TestWarmOpsCarryVolumeIdentityAtPinnedPositions pins the send side of the
// identity assertion: each warm op carries the identity at the FIXED
// position the warden reads (raw_server.rs IDX_EXEC_VOLUME = 3,
// IDX_ASYNC_EXEC_VOLUME = 2, IDX_FILE_VOLUME = 5). A move on one side without
// the other would silently empty the warden's field and disable the check.
func TestWarmOpsCarryVolumeIdentityAtPinnedPositions(t *testing.T) {
	// OP_EXEC: identity at index 3 (after command, timeout_ms, install_packages).
	fc := &fakeConn{}
	fc.respBuf.Write(buildResponse(codeOk, 0, "out", ""))
	c := newTestClient(fc)
	if _, _, _, _, _, err := c.ExecWorkspace("echo hi", 0, false, "sandfs-a"); err != nil {
		t.Fatalf("ExecWorkspace: %v", err)
	}
	fields := parseRequestFields(t, fc.buf.Bytes())
	if len(fields) != 4 {
		t.Fatalf("OP_EXEC field count = %d, want 4 (identity at index 3)", len(fields))
	}
	if got := string(fields[3]); got != "sandfs-a" {
		t.Errorf("OP_EXEC identity field = %q, want sandfs-a", got)
	}

	// OP_ASYNC_EXEC: identity at index 2 (after command, install_packages).
	fc = &fakeConn{}
	fc.respBuf.Write(buildResponse(codeOk, 0, "bg-exec-1", ""))
	c = newTestClient(fc)
	if _, err := c.AsyncExec("sleep 1", false, "sandfs-a"); err != nil {
		t.Fatalf("AsyncExec: %v", err)
	}
	fields = parseRequestFields(t, fc.buf.Bytes())
	if len(fields) != 3 {
		t.Fatalf("OP_ASYNC_EXEC field count = %d, want 3 (identity at index 2)", len(fields))
	}
	if got := string(fields[2]); got != "sandfs-a" {
		t.Errorf("OP_ASYNC_EXEC identity field = %q, want sandfs-a", got)
	}

	// OP_FILE: identity at index 5, reachable from a short sub-op only via
	// explicit empty-field padding (READ uses fields 0..3) — the padding is
	// part of the ABI, so the gap fields must be present and empty.
	fc = &fakeConn{}
	fc.respBuf.Write(buildResponse(codeOk, 0, "data", ""))
	c = newTestClient(fc)
	if _, err := c.FileOp(FileOpRequest{SubOp: SubOpRead, Path: "f", MountedVolume: "sandfs-a"}); err != nil {
		t.Fatalf("FileOp: %v", err)
	}
	fields = parseRequestFields(t, fc.buf.Bytes())
	if len(fields) != fileOpVolumeIdentityIndex+1 {
		t.Fatalf("OP_FILE field count = %d, want %d", len(fields), fileOpVolumeIdentityIndex+1)
	}
	if got := string(fields[fileOpVolumeIdentityIndex]); got != "sandfs-a" {
		t.Errorf("OP_FILE identity field = %q, want sandfs-a", got)
	}
	if len(fields[4]) != 0 {
		t.Errorf("OP_FILE padding field 4 = %q, want empty", fields[4])
	}
}

// --- MemStats delegates correctly ---

func TestMemStats(t *testing.T) {
	fc := &fakeConn{}
	resp := buildResponse(codeOk, 0, "1048576 2097152", "") // 1MB avail, 2MB total
	fc.respBuf.Write(resp)
	c := newTestClient(fc)

	avail, total, err := c.MemStats()
	if err != nil {
		t.Fatalf("MemStats unexpected error: %v", err)
	}
	if avail != 1048576 {
		t.Errorf("avail = %d, want 1048576", avail)
	}
	if total != 2097152 {
		t.Errorf("total = %d, want 2097152", total)
	}
}

func TestMemStats_BadResponse(t *testing.T) {
	fc := &fakeConn{}
	resp := buildResponse(codeOk, 0, "garbage", "") // not "avail total"
	fc.respBuf.Write(resp)
	c := newTestClient(fc)

	_, _, err := c.MemStats()
	if err == nil {
		t.Fatal("MemStats should fail on bad response format")
	}
}

func TestMemStats_WardenError(t *testing.T) {
	fc := &fakeConn{}
	resp := buildResponse(codeTransportErr, 0, "internal error", "") // warden RPC error
	fc.respBuf.Write(resp)
	c := newTestClient(fc)

	_, _, err := c.MemStats()
	if err == nil {
		t.Fatal("MemStats should fail on warden error")
	}
}

// --- Client.Close ---

func TestClientClose(t *testing.T) {
	fc := &fakeConn{}
	c := newTestClient(fc)

	if err := c.Close(); err != nil {
		t.Fatalf("Close unexpected error: %v", err)
	}
	if !fc.closed {
		t.Error("Close should close underlying conn")
	}
}

// SPDX-License-Identifier: Apache-2.0

// parseRequestFields extracts the length-prefixed fields from a captured
// request frame body.
func parseRequestFields(t *testing.T, frame []byte) [][]byte {
	t.Helper()
	if len(frame) < reqHeaderLen {
		t.Fatalf("frame too short: %d bytes", len(frame))
	}
	body := frame[reqHeaderLen:]
	var fields [][]byte
	for off := 0; off < len(body); {
		if off+4 > len(body) {
			t.Fatalf("truncated field header at offset %d", off)
		}
		fl := int(binary.BigEndian.Uint32(body[off : off+4]))
		off += 4
		if off+fl > len(body) {
			t.Fatalf("truncated field body at offset %d (len %d)", off, fl)
		}
		fields = append(fields, body[off:off+fl])
		off += fl
	}
	return fields
}

// --- MountAndExec ---

func TestMountAndExec_Success(t *testing.T) {
	fc := &fakeConn{}
	resp := buildResponse(codeOk, 0, "hello from vm", "")
	fc.respBuf.Write(resp)
	c := newTestClient(fc)

	stdout, stderr, exitCode, _, durNs, _, err := c.MountAndExec("/dev/vda", "/mnt/rootfs", "echo hi", 30*time.Second, false, "flat")
	if err != nil {
		t.Fatalf("MountAndExec: %v", err)
	}
	if stdout != "hello from vm" || stderr != "" || exitCode != 0 {
		t.Errorf("got (%q, %q, %d)", stdout, stderr, exitCode)
	}
	if durNs != 0 {
		t.Errorf("durNs = %d, want 0", durNs)
	}

	fields := parseRequestFields(t, fc.buf.Bytes())
	if frame := fc.buf.Bytes(); frame[5] != opMountAndExec {
		t.Errorf("op = %d, want %d", frame[5], opMountAndExec)
	}
	if len(fields) != 7 {
		t.Fatalf("field count = %d, want 7", len(fields))
	}
	want := []string{"/dev/vda", "/mnt/rootfs", "none", "echo hi", "30000", ""}
	for i, w := range want {
		if string(fields[i]) != w {
			t.Errorf("field[%d] = %q, want %q", i, fields[i], w)
		}
	}
}

// --- MountOnly (empty-command OP_MOUNT_AND_EXEC) ---

func TestMountOnly_Success(t *testing.T) {
	// Mount-only rides the SAME combined op with an EMPTY command field —
	// the warden mounts and skips the exec. The wire shape must stay exactly
	// the combined op's (6 fields, command=""), so an old warden still runs
	// it harmlessly (`sh -c ''`) and the warden's field indices are stable.
	fc := &fakeConn{}
	resp := buildResponse(codeOk, 0, "", "")
	fc.respBuf.Write(resp)
	c := newTestClient(fc)

	mounted, err := c.MountOnly("/dev/vda", "/mnt/rootfs", "flat")
	if err != nil {
		t.Fatalf("MountOnly: %v", err)
	}
	if mounted != "" {
		t.Errorf("plain buildResponse carries no mounted assertion, got %q", mounted)
	}

	fields := parseRequestFields(t, fc.buf.Bytes())
	if frame := fc.buf.Bytes(); frame[5] != opMountAndExec {
		t.Errorf("op = %d, want %d (mount-only reuses the combined op)", frame[5], opMountAndExec)
	}
	if len(fields) != 7 {
		t.Fatalf("field count = %d, want 7", len(fields))
	}
	want := []string{"/dev/vda", "/mnt/rootfs", "none", "", "0", "", "flat"}
	for i, w := range want {
		if string(fields[i]) != w {
			t.Errorf("field[%d] = %q, want %q", i, fields[i], w)
		}
	}
}

func TestMountAndExec_NonZeroExitWithDuration(t *testing.T) {
	fc := &fakeConn{}
	resp := buildResponse(codeOk, 7, "", "boom") // exit code 7
	fc.respBuf.Write(resp)
	c := newTestClient(fc)

	_, _, exitCode, _, _, _, err := c.MountAndExec("/dev/vda", "/mnt/rootfs", "false", 0, true, "flat")
	if err != nil {
		t.Fatalf("non-zero exit should not be an error: %v", err)
	}
	if exitCode != 7 {
		t.Errorf("exitCode = %d, want 7", exitCode)
	}
	// installPackages=true and timeout=0 must appear on the wire.
	fields := parseRequestFields(t, fc.buf.Bytes())
	if string(fields[4]) != "0" || string(fields[5]) != "1" {
		t.Errorf("timeout/install fields = %q/%q, want 0/1", fields[4], fields[5])
	}
}

func TestMountAndExec_RPCError(t *testing.T) {
	fc := &fakeConn{}
	resp := buildResponse(codeTransportErr, 0, "", "mount failed: ENOENT")
	fc.respBuf.Write(resp)
	c := newTestClient(fc)

	_, _, _, _, _, _, err := c.MountAndExec("/dev/nope", "/mnt/rootfs", "ls", 0, false, "flat")
	if err == nil {
		t.Fatal("expected RPC error")
	}
	var te *TransportError
	if errors.As(err, &te) {
		t.Fatalf("RPC error should not be TransportError: %v", err)
	}
	if got := err.Error(); got != "warden rpc failed: mount failed: ENOENT" {
		t.Errorf("error = %q", got)
	}
}

// --- ExecWorkspace ---

func TestExecWorkspace_Fields(t *testing.T) {
	tests := []struct {
		name            string
		timeout         time.Duration
		installPackages bool
		wantTimeout     string
		wantInstall     string
	}{
		{"defaults", 0, false, "0", ""},
		{"with_timeout", 45 * time.Second, false, "45000", ""},
		{"install_packages", 0, true, "0", "1"},
		{"both", 90 * time.Second, true, "90000", "1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fc := &fakeConn{}
			fc.respBuf.Write(buildResponse(codeOk, 0, "", ""))
			c := newTestClient(fc)

			if _, _, _, _, _, err := c.ExecWorkspace("pip install x", tt.timeout, tt.installPackages, "sandfs-a"); err != nil {
				t.Fatalf("ExecWorkspace: %v", err)
			}
			frame := fc.buf.Bytes()
			if frame[5] != opExec {
				t.Errorf("op = %d, want %d", frame[5], opExec)
			}
			fields := parseRequestFields(t, frame)
			// Current layout: the identity field is appended at index 3 (see
			// TestWarmOpsCarryVolumeIdentityAtPinnedPositions).
			if len(fields) != 4 {
				t.Fatalf("field count = %d, want 4", len(fields))
			}
			if string(fields[1]) != tt.wantTimeout {
				t.Errorf("timeout field = %q, want %q", fields[1], tt.wantTimeout)
			}
			if string(fields[2]) != tt.wantInstall {
				t.Errorf("install field = %q, want %q", fields[2], tt.wantInstall)
			}
			if string(fields[3]) != "sandfs-a" {
				t.Errorf("identity field = %q, want %q", fields[3], "sandfs-a")
			}
		})
	}
}

func TestExecWorkspace_TimedOutStatus(t *testing.T) {
	fc := &fakeConn{}
	fc.respBuf.Write(buildResponse(codeTimedOut, 0, "", "timed out after 300s"))
	c := newTestClient(fc)

	_, _, _, status, _, err := c.ExecWorkspace("sleep 999", time.Second, false, "sandfs-a")
	if err != nil {
		t.Fatalf("timedOut should not be an error: %v", err)
	}
	if status != "timed_out" {
		t.Errorf("status = %q, want %q", status, "timed_out")
	}
}

// --- AsyncExec / MountAndAsyncExec ---

func TestAsyncExec_Success(t *testing.T) {
	fc := &fakeConn{}
	fc.respBuf.Write(buildResponse(codeOk, 0, "bg-abc123", ""))
	c := newTestClient(fc)

	execID, err := c.AsyncExec("python server.py", false, "sandfs-a")
	if err != nil {
		t.Fatalf("AsyncExec: %v", err)
	}
	if execID != "bg-abc123" {
		t.Errorf("execID = %q, want bg-abc123", execID)
	}
	frame := fc.buf.Bytes()
	if frame[5] != opAsyncExec {
		t.Errorf("op = %d, want %d", frame[5], opAsyncExec)
	}
	fields := parseRequestFields(t, frame)
	// Current layout: identity appended at index 2 (see
	// TestWarmOpsCarryVolumeIdentityAtPinnedPositions).
	if len(fields) != 3 {
		t.Fatalf("field count = %d, want 3", len(fields))
	}
	if string(fields[1]) != "" {
		t.Errorf("install field = %q, want empty", fields[1])
	}
	if string(fields[2]) != "sandfs-a" {
		t.Errorf("identity field = %q, want %q", fields[2], "sandfs-a")
	}
}

func TestAsyncExec_Error(t *testing.T) {
	fc := &fakeConn{}
	fc.respBuf.Write(buildResponse(codeTransportErr, 0, "", "spawn failed"))
	c := newTestClient(fc)

	execID, err := c.AsyncExec("x", false, "sandfs-a")
	if err == nil {
		t.Fatal("expected error")
	}
	if execID != "" {
		t.Errorf("execID = %q, want empty on error", execID)
	}
}

func TestMountAndAsyncExec_Success(t *testing.T) {
	fc := &fakeConn{}
	fc.respBuf.Write(buildResponse(codeOk, 0, "bg-77", ""))
	c := newTestClient(fc)

	execID, _, err := c.MountAndAsyncExec("/dev/vda", "/mnt/rootfs", "top", false, "flat")
	if err != nil {
		t.Fatalf("MountAndAsyncExec: %v", err)
	}
	if execID != "bg-77" {
		t.Errorf("execID = %q, want bg-77", execID)
	}
	frame := fc.buf.Bytes()
	if frame[5] != opMountAndAsyncExec {
		t.Errorf("op = %d, want %d", frame[5], opMountAndAsyncExec)
	}
	fields := parseRequestFields(t, frame)
	if len(fields) != 6 {
		t.Fatalf("field count = %d, want 6", len(fields))
	}
	if string(fields[2]) != "none" {
		t.Errorf("fs_type field = %q, want none", fields[2])
	}
	if string(fields[5]) != "flat" {
		t.Errorf("volume_mode field = %q, want flat", fields[5])
	}
}

func TestMountAndAsyncExec_Error(t *testing.T) {
	fc := &fakeConn{}
	fc.respBuf.Write(buildResponse(codeTransportErr, 0, "", "no such device"))
	c := newTestClient(fc)

	execID, _, err := c.MountAndAsyncExec("/dev/x", "/mnt/rootfs", "y", false, "flat")
	if err == nil || execID != "" {
		t.Fatalf("want error and empty execID, got (%q, %v)", execID, err)
	}
}

// --- StatusExec ---

func TestStatusExec_Statuses(t *testing.T) {
	tests := []struct {
		name       string
		code       uint8
		logTail    string
		wantStatus string
	}{
		{"running", codeBgRunning, "log line", "running"},
		{"killed", codeBgKilled, "", "killed"},
		{"not_found", codeBgNotFound, "", "not_found"},
		{"done", codeOk, "output", "done"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fc := &fakeConn{}
			fc.respBuf.Write(buildResponse(tt.code, 0, tt.logTail, ""))
			c := newTestClient(fc)

			logTail, status, _, err := c.StatusExec("bg-1")
			if err != nil {
				t.Fatalf("StatusExec: %v", err)
			}
			if logTail != tt.logTail {
				t.Errorf("logTail = %q, want %q", logTail, tt.logTail)
			}
			if status != tt.wantStatus {
				t.Errorf("status = %q, want %q", status, tt.wantStatus)
			}
			frame := fc.buf.Bytes()
			if frame[5] != opStatusExec {
				t.Errorf("op = %d, want %d", frame[5], opStatusExec)
			}
			fields := parseRequestFields(t, frame)
			if len(fields) != 1 || string(fields[0]) != "bg-1" {
				t.Errorf("fields = %q, want [bg-1]", fields)
			}
		})
	}
}

func TestStatusExec_TransportError(t *testing.T) {
	fc := &fakeConn{respErr: errors.New("ECONNRESET")}
	c := newTestClient(fc)

	_, _, _, err := c.StatusExec("bg-1")
	if err == nil {
		t.Fatal("expected transport error")
	}
	var te *TransportError
	if !errors.As(err, &te) || te.Op != "read" {
		t.Errorf("want TransportError{read}, got %v", err)
	}
}

// --- KillExec ---

func TestKillExec(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		fc := &fakeConn{}
		fc.respBuf.Write(buildResponse(codeOk, 0, "", ""))
		c := newTestClient(fc)

		if err := c.KillExec("bg-9"); err != nil {
			t.Fatalf("KillExec: %v", err)
		}
		frame := fc.buf.Bytes()
		if frame[5] != opKillExec {
			t.Errorf("op = %d, want %d", frame[5], opKillExec)
		}
		fields := parseRequestFields(t, frame)
		if len(fields) != 1 || string(fields[0]) != "bg-9" {
			t.Errorf("fields = %q, want [bg-9]", fields)
		}
	})

	t.Run("error", func(t *testing.T) {
		fc := &fakeConn{}
		fc.respBuf.Write(buildResponse(codeTransportErr, 0, "", "no such exec"))
		c := newTestClient(fc)

		err := c.KillExec("bg-missing")
		if err == nil || err.Error() != "warden rpc failed: no such exec" {
			t.Errorf("err = %v, want rpc failed message", err)
		}
	})
}

// --- UnmountRootfs error path ---

func TestUnmountRootfs_TransportError(t *testing.T) {
	c := newClient(&errorWriterConn{}, 42, ReadTimeoutCapDefault, testSessionKey, testNoncePrefix)
	_, _, _, err := c.UnmountRootfs("gen0")
	var te *TransportError
	if !errors.As(err, &te) || te.Op != "write" {
		t.Errorf("want TransportError{write}, got %v", err)
	}
}

// --- FileOp ---

func fileOpResp(data string, success bool) []byte {
	if success {
		return buildResponse(codeOk, 0, data, "")
	}
	return buildResponse(codeAppError, 0, data, "")
}

func TestFileOp_SubOps(t *testing.T) {
	tests := []struct {
		name        string
		req         FileOpRequest
		wantOp      uint8
		fieldChecks map[int]string // index -> expected field content
	}{
		{
			name: "read",
			req:  FileOpRequest{SubOp: SubOpRead, Path: "a/b.txt", Offset: 10, Length: 100},
			fieldChecks: map[int]string{
				0: "\x01",
				1: "a/b.txt",
				2: "10",
				3: "100",
			},
		},
		{
			name: "write",
			req:  FileOpRequest{SubOp: SubOpWrite, Path: "out.bin", Offset: -1, Mode: 0o644, Data: []byte{0xDE, 0xAD}},
			fieldChecks: map[int]string{
				1: "out.bin",
				2: "-1",
				3: "420",
				4: "\xde\xad", // raw data field
			},
		},
		{
			name: "stat",
			req:  FileOpRequest{SubOp: SubOpStat, Path: "x"},
			fieldChecks: map[int]string{
				0: "\x03",
				1: "x",
			},
		},
		{
			name: "list_dir",
			req:  FileOpRequest{SubOp: SubOpListDir, Path: "dir", Depth: 2},
			fieldChecks: map[int]string{
				2: "2",
			},
		},
		{
			name: "mkdir",
			req:  FileOpRequest{SubOp: SubOpMakeDir, Path: "newdir", Mode: 0o755},
			fieldChecks: map[int]string{
				2: "493",
			},
		},
		{
			name: "remove_recursive",
			req:  FileOpRequest{SubOp: SubOpRemove, Path: "tree", Recursive: true},
			fieldChecks: map[int]string{
				2: "1",
			},
		},
		{
			name: "remove_flat",
			req:  FileOpRequest{SubOp: SubOpRemove, Path: "f.txt"},
			fieldChecks: map[int]string{
				2: "0",
			},
		},
		{
			name: "rename",
			req:  FileOpRequest{SubOp: SubOpRename, Path: "old", NewPath: "new"},
			fieldChecks: map[int]string{
				2: "new",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fc := &fakeConn{}
			fc.respBuf.Write(fileOpResp(`{"ok":true}`, true))
			c := newTestClient(fc)

			got, err := c.FileOp(tt.req)
			if err != nil {
				t.Fatalf("FileOp(%s): %v", tt.name, err)
			}
			if !got.Success {
				t.Errorf("Success = false, want true")
			}
			if string(got.Data) != `{"ok":true}` {
				t.Errorf("data = %q", got.Data)
			}
			frame := fc.buf.Bytes()
			if frame[5] != opFile {
				t.Errorf("op = %d, want %d", frame[5], opFile)
			}
			fields := parseRequestFields(t, frame)
			// Current layout: every OP_FILE body is exactly fileOpVolumeIdentityIndex+1
			// fields — the identity sits at the fixed index and any gap a short
			// sub-op leaves is padded with empty fields (both are ABI).
			if want := fileOpVolumeIdentityIndex + 1; len(fields) != want {
				t.Fatalf("field count = %d, want %d (%q)", len(fields), want, fields)
			}
			if len(fields[fileOpVolumeIdentityIndex]) != 0 {
				t.Errorf("identity field = %q, want empty (no MountedVolume set)", fields[fileOpVolumeIdentityIndex])
			}
			for i := 2; i < fileOpVolumeIdentityIndex; i++ {
				if _, payload := tt.fieldChecks[i]; payload {
					continue
				}
				if len(fields[i]) != 0 {
					t.Errorf("padding field[%d] = %q, want empty", i, fields[i])
				}
			}
			for i, want := range tt.fieldChecks {
				if string(fields[i]) != want {
					t.Errorf("field[%d] = %q, want %q", i, fields[i], want)
				}
			}
		})
	}
}

func TestFileOp_WriteBinaryDataPreserved(t *testing.T) {
	data := make([]byte, 256)
	for i := range data {
		data[i] = byte(i)
	}
	fc := &fakeConn{}
	fc.respBuf.Write(fileOpResp("", true))
	c := newTestClient(fc)

	req := FileOpRequest{SubOp: SubOpWrite, Path: "bin.dat", Data: data}
	if _, err := c.FileOp(req); err != nil {
		t.Fatalf("FileOp write: %v", err)
	}
	frame := fc.buf.Bytes()
	fields := parseRequestFields(t, frame)
	// Current layout: the raw data rides field 4 and the identity field follows at
	// 5 — the data field's own 4-byte length prefix must still carry the exact
	// byte count (the "last field" shorthand no longer applies).
	if len(fields) != fileOpVolumeIdentityIndex+1 {
		t.Fatalf("field count = %d, want %d", len(fields), fileOpVolumeIdentityIndex+1)
	}
	if !bytes.Equal(fields[4], data) {
		t.Error("raw data bytes were mangled in transit")
	}
}

func TestFileOp_UnknownSubOp(t *testing.T) {
	fc := &fakeConn{}
	c := newTestClient(fc)

	_, err := c.FileOp(FileOpRequest{SubOp: 99, Path: "x"})
	if err == nil || err.Error() != "unknown file sub_op: 99" {
		t.Errorf("err = %v, want unknown sub_op error", err)
	}
}

func TestFileOp_RpcError(t *testing.T) {
	// A transport error (CODE_TRANSPORT_ERROR) is returned as a Go error,
	// not a FileOpResponse — the caller invalidates the cached connection.
	fc := &fakeConn{}
	fc.respBuf.Write(buildResponse(codeTransportErr, 0, "", "vsock broken"))
	c := newTestClient(fc)

	resp, err := c.FileOp(FileOpRequest{SubOp: SubOpWrite, Path: "f"})
	if err == nil {
		t.Fatal("expected RPC error")
	}
	if resp != nil {
		t.Errorf("response = %+v, want nil on transport error", resp)
	}
	var te *TransportError
	if errors.As(err, &te) {
		t.Errorf("RPC error should not be TransportError: %v", err)
	}
}

func TestFileOp_WriteTransportError(t *testing.T) {
	c := newClient(&errorWriterConn{}, 42, ReadTimeoutCapDefault, testSessionKey, testNoncePrefix)
	_, err := c.FileOp(FileOpRequest{SubOp: SubOpRead, Path: "f"})
	var te *TransportError
	if !errors.As(err, &te) || te.Op != "write" {
		t.Errorf("want TransportError{write}, got %v", err)
	}
}

// --- roundTripRaw / readResponseRaw framing edge cases ---

func TestRoundTripRaw_ReadErrorIsTransportError(t *testing.T) {
	fc := &fakeConn{respErr: errors.New("EIO")}
	c := newTestClient(fc)

	_, _, _, _, _, _, err := c.roundTripRaw(opFile, testReadTimeout, []byte("\x01"), strField("f"))
	var te *TransportError
	if !errors.As(err, &te) || te.Op != "read" {
		t.Errorf("want TransportError{read}, got %v", err)
	}
}

func buildRawFrame(code uint8, exitCode uint8, stdout, stderr []byte, durNs uint64, badMagic bool) []byte {
	var buf bytes.Buffer
	m := magic
	if badMagic {
		m = 0xBADF00D
	}
	hdr := make([]byte, respHeaderLen)
	binary.BigEndian.PutUint32(hdr[0:4], m)
	hdr[4] = protocolVersion
	hdr[5] = code
	hdr[6] = exitCode
	hdr[7] = 0 // reserved
	binary.BigEndian.PutUint32(hdr[8:12], uint32(len(stdout)))
	binary.BigEndian.PutUint32(hdr[12:16], uint32(len(stderr)))
	binary.BigEndian.PutUint64(hdr[16:24], durNs)
	binary.BigEndian.PutUint32(hdr[24:28], 0) // mounted_len
	signTestHeader(hdr)
	buf.Write(hdr)
	buf.Write(stdout)
	buf.Write(stderr)
	mac := mountedTag(testSessionKey, &testNonce, nil)
	buf.Write(mac[:])
	return buf.Bytes()
}

func TestReadResponseRaw_SuccessWithDuration(t *testing.T) {
	r := bytes.NewReader(buildRawFrame(codeOk, 0, []byte{0x00, 0xFF}, []byte("warn"), 123456789, false))
	code, exitCode, stdout, stderr, _, durNs, err := readResponseRaw(r, testSessionKey, &testNonce)
	if err != nil {
		t.Fatalf("readResponseRaw: %v", err)
	}
	if code != codeOk || durNs != 123456789 {
		t.Errorf("(code, durNs) = (%d, %d), want (%d, 123456789)", code, codeOk, durNs)
	}
	if exitCode != 0 {
		t.Errorf("exitCode = %d, want 0", exitCode)
	}
	if !bytes.Equal(stdout, []byte{0x00, 0xFF}) {
		t.Errorf("stdout = %x, want binary-safe bytes", stdout)
	}
	if stderr != "warn" {
		t.Errorf("stderr = %q, want warn", stderr)
	}
}

func TestReadResponseRaw_BadMagic(t *testing.T) {
	_, _, _, _, _, _, err := readResponseRaw(bytes.NewReader(buildRawFrame(codeOk, 0, nil, nil, 0, true)), testSessionKey, &testNonce)
	if err == nil {
		t.Fatal("expected bad magic error")
	}
	if got := err.Error(); got != "bad response magic 0xbadf00d" {
		t.Errorf("error = %q", got)
	}
}

func TestReadResponseRaw_TruncatedHeader(t *testing.T) {
	short := buildRawFrame(codeOk, 0, nil, nil, 0, false)[:respHeaderLen-5]
	if _, _, _, _, _, _, err := readResponseRaw(bytes.NewReader(short), testSessionKey, &testNonce); err == nil {
		t.Fatal("expected truncated header error")
	}
}

func TestReadResponseRaw_TruncatedStdoutBody(t *testing.T) {
	frame := buildRawFrame(codeOk, 0, []byte("longer than declared"), nil, 0, false)
	truncated := frame[:respHeaderLen+5]
	if _, _, _, _, _, _, err := readResponseRaw(bytes.NewReader(truncated), testSessionKey, &testNonce); err == nil {
		t.Fatal("expected truncated stdout error")
	}
}

func TestReadResponse_TruncatedStderrBody(t *testing.T) {
	var buf bytes.Buffer
	hdr := make([]byte, respHeaderLen)
	binary.BigEndian.PutUint32(hdr[0:4], magic)
	binary.BigEndian.PutUint32(hdr[8:12], 0)  // stdout_len = 0
	binary.BigEndian.PutUint32(hdr[12:16], 9) // stderr_len = 9, no body follows
	signTestHeader(hdr)
	buf.Write(hdr)
	if _, _, _, _, _, err := readResponse(&buf, testSessionKey, &testNonce); err == nil {
		t.Fatal("expected truncated stderr error")
	}
}

// --- MemStats parsing edges ---

func TestMemStats_BadNumber(t *testing.T) {
	fc := &fakeConn{}
	fc.respBuf.Write(buildResponse(codeOk, 0, "notanumber 2048", ""))
	c := newTestClient(fc)

	_, _, err := c.MemStats()
	if err == nil {
		t.Fatal("expected parse error for non-numeric avail")
	}
}

func TestMemStats_ThreeFields(t *testing.T) {
	fc := &fakeConn{}
	fc.respBuf.Write(buildResponse(codeOk, 0, "1024 2048 4096", ""))
	c := newTestClient(fc)

	_, _, err := c.MemStats()
	if err == nil || err.Error() != `warden mem_stats bad response: "1024 2048 4096"` {
		t.Errorf("err = %v, want bad-response error", err)
	}
}

func TestMemStats_TotalParseError(t *testing.T) {
	fc := &fakeConn{}
	fc.respBuf.Write(buildResponse(codeOk, 0, "1024 xyz", ""))
	c := newTestClient(fc)

	_, _, err := c.MemStats()
	if err == nil {
		t.Fatal("expected parse error for non-numeric total")
	}
}

// --- helpers ---

func TestTimeoutMs(t *testing.T) {
	tests := []struct {
		d    time.Duration
		want string
	}{
		{0, "0"},
		{time.Second, "1000"},
		{1500 * time.Millisecond, "1500"},
		{5 * time.Minute, "300000"},
	}
	for _, tt := range tests {
		if got := timeoutMs(tt.d); got != tt.want {
			t.Errorf("timeoutMs(%v) = %q, want %q", tt.d, got, tt.want)
		}
	}
}

func TestInstallPkgs(t *testing.T) {
	if got := installPkgs(true); got != "1" {
		t.Errorf("installPkgs(true) = %q, want 1", got)
	}
	if got := installPkgs(false); got != "" {
		t.Errorf("installPkgs(false) = %q, want empty", got)
	}
}

// --- setConnReadTimeout arm-cache + readResponseBody merged read ---

// TestSetConnReadTimeout_FailedArmNotCached proves the safety property of the
// skip cache: a setsockopt failure must roll lastRcvtimeo back, so the NEXT
// call with the same timeout RETRIES the arm (if the failed arm were cached as
// armed, the retry would be skipped and the socket left with the old timeout).
// Uses a real *vsockConn over a closed fd — setsockopt fails with EBADF.
func TestSetConnReadTimeout_FailedArmNotCached(t *testing.T) {
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Skipf("cannot create socket: %v", err)
	}
	unix.Close(fd) // closed: any setsockopt on it fails
	c := &Client{conn: &vsockConn{f: os.NewFile(uintptr(fd), "vsock-dead")}}

	if err := c.setConnReadTimeout(30 * time.Second); err == nil {
		t.Fatal("setsockopt on a closed fd must fail")
	}
	if c.lastRcvtimeo != 0 {
		t.Fatalf("failed arm must roll the cache back, got lastRcvtimeo=%v", c.lastRcvtimeo)
	}
	// The retry with the same value must ATTEMPT again (and fail again) —
	// a skip here would mean the failed arm was wrongly cached.
	if err := c.setConnReadTimeout(30 * time.Second); err == nil {
		t.Fatal("retry after a failed arm must re-attempt setsockopt (not skip)")
	}
}

// TestReadResponseBody_MergedRead verifies the single-ReadFull body read:
// stdout and stderr are contiguous on the stream and must come back as exact
// views into one buffer, and a short stream must surface as an error.
func TestReadResponseBody_MergedRead(t *testing.T) {
	// The mounted MAC (32 bytes) always trails the segments, so it is part of
	// the same single ReadFull.
	macBytes := bytes.Repeat([]byte{0x5a}, tagLen)
	r := strings.NewReader("OUTDATAERDATA" + string(macBytes))
	out, errOut, mnt, mac, err := readResponseBody(r, 7, 6, 0)
	if err != nil {
		t.Fatalf("readResponseBody: %v", err)
	}
	if string(out) != "OUTDATA" || string(errOut) != "ERDATA" {
		t.Fatalf("got out=%q err=%q", out, errOut)
	}
	if len(mnt) != 0 {
		t.Fatalf("mounted = %q, want empty", mnt)
	}
	if !bytes.Equal(mac, macBytes) {
		t.Fatalf("mounted mac = %x, want %x", mac, macBytes)
	}
	// Short stream (lengths claim more bytes than present) → error.
	if _, _, _, _, err := readResponseBody(strings.NewReader("abc"), 2, 2, 0); err == nil {
		t.Fatal("short body must error")
	}
	// Zero-length segments (e.g. an exec with no output) → empty views plus the
	// trailing MAC, no error.
	out, errOut, mnt, mac, err = readResponseBody(strings.NewReader(string(macBytes)), 0, 0, 0)
	if err != nil || len(out) != 0 || len(errOut) != 0 || len(mnt) != 0 || len(mac) != tagLen {
		t.Fatalf("empty body: out=%q err=%q mnt=%q mac=%d err=%v", out, errOut, mnt, len(mac), err)
	}
}

// --- protocol version negotiation tests ---

// buildResponseVersion is buildResponse with an explicit protocol version in
// the header — the shape a MISMATCHED warden sends (its own version, not
// ours).
func buildResponseVersion(v uint8, code uint8, exitCode uint8, stdout, stderr string) []byte {
	var buf bytes.Buffer
	hdr := make([]byte, respHeaderLen)
	binary.BigEndian.PutUint32(hdr[0:4], magic)
	hdr[4] = v
	hdr[5] = code
	hdr[6] = exitCode
	hdr[7] = 0
	binary.BigEndian.PutUint32(hdr[8:12], uint32(len(stdout)))
	binary.BigEndian.PutUint32(hdr[12:16], uint32(len(stderr)))
	binary.BigEndian.PutUint64(hdr[16:24], 0)
	binary.BigEndian.PutUint32(hdr[24:28], 0) // mounted_len
	// No valid tag is needed: the client checks the version byte first, so a
	// mismatched peer's frame is classified by version, never by the tag.
	buf.Write(hdr)
	buf.WriteString(stdout)
	buf.WriteString(stderr)
	return buf.Bytes()
}

// TestRoundTripProtocolVersionMismatch verifies the classification chain: a
// response frame carrying a different protocol version surfaces as
// ProtocolVersionError (with both version numbers) through a full RPC call —
// NOT wrapped into a generic TransportError — so callers (CreateVerifiedVM,
// redialWarden) can fail fast on it.
func TestRoundTripProtocolVersionMismatch(t *testing.T) {
	fc := &fakeConn{}
	fc.respBuf.Write(buildResponseVersion(protocolVersion+1, codeOk, 0, "1024 4096", ""))
	c := newTestClient(fc)

	_, _, err := c.MemStats()
	if err == nil {
		t.Fatal("MemStats against a mismatched-version warden must fail")
	}
	var pve *ProtocolVersionError
	if !errors.As(err, &pve) {
		t.Fatalf("error must classify as ProtocolVersionError, got %T: %v", err, err)
	}
	if pve.Ours != protocolVersion || pve.Theirs != protocolVersion+1 {
		t.Errorf("version numbers: got ours=%d theirs=%d, want %d/%d",
			pve.Ours, pve.Theirs, protocolVersion, protocolVersion+1)
	}
	// The same error must still classify as TransportError (embedded): the
	// slot-discard logic in core (isWardenTransportErr) relies on it.
	var te *TransportError
	if !errors.As(err, &te) {
		t.Error("ProtocolVersionError must remain a TransportError for slot discard")
	}
}

// TestReadResponseVersionMismatchLower covers the OTHER direction: an older
// warden (version 0 — pre-versioning build) is equally rejected.
func TestReadResponseVersionMismatchLower(t *testing.T) {
	fc := &fakeConn{respBuf: *bytes.NewBuffer(buildResponseVersion(0, codeOk, 0, "", ""))}
	_, _, _, _, _, err := readResponse(fc, testSessionKey, &testNonce)
	var pve *ProtocolVersionError
	if !errors.As(err, &pve) {
		t.Fatalf("readResponse must return ProtocolVersionError, got %T: %v", err, err)
	}
	if pve.Theirs != 0 {
		t.Errorf("Theirs = %d, want 0", pve.Theirs)
	}
}

// TestProtocolVersionErrorMessage pins the operator-facing diagnosis: the
// message names both versions and the remedy.
func TestProtocolVersionErrorMessage(t *testing.T) {
	e := versionMismatch(2)
	msg := e.Error()
	for _, want := range []string{"mismatch", "warden speaks 2"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message %q missing %q", msg, want)
		}
	}
}

// TestReadResponseRejectsOversizeSegmentLengths pins the response-length cap:
// the segment lengths come straight off the wire, and allocating from them
// unchecked lets one corrupt frame (0xFFFFFFFF/0xFFFFFFFF claims 8 GiB) OOM-
// kill the whole node daemon. The read must fail BEFORE any allocation —
// the test would itself die to the allocation under the old code.
func TestReadResponseRejectsOversizeSegmentLengths(t *testing.T) {
	// buildHostileSigned builds a frame with a VALID tag over the impossible
	// lengths, so the parser reaches (and must refuse at) the length caps
	// rather than stopping at authentication.
	buildHostileSigned := func(stdoutLen, stderrLen uint32) []byte {
		hdr := make([]byte, respHeaderLen)
		binary.BigEndian.PutUint32(hdr[0:4], magic)
		hdr[4] = protocolVersion
		hdr[5] = codeOk
		hdr[6] = 0
		hdr[7] = 0
		binary.BigEndian.PutUint32(hdr[8:12], stdoutLen)
		binary.BigEndian.PutUint32(hdr[12:16], stderrLen)
		binary.BigEndian.PutUint64(hdr[16:24], 0)
		binary.BigEndian.PutUint32(hdr[24:28], 0)
		signTestHeader(hdr)
		return hdr
	}

	for name, frame := range map[string][]byte{
		"both max u32":    buildHostileSigned(0xFFFFFFFF, 0xFFFFFFFF),
		"oversize stdout": buildHostileSigned(uint32(maxRespSegment+1), 0),
		"oversize stderr": buildHostileSigned(0, uint32(maxRespSegment+1)),
		"exactly at cap ok (no body needed for the check)": nil, // placeholder, filled below
	} {
		if frame == nil {
			continue
		}
		fc := &fakeConn{}
		fc.respBuf.Write(frame)
		c := newTestClient(fc)
		if _, _, err := c.MemStats(); err == nil {
			t.Errorf("%s: MemStats accepted a frame with impossible segment lengths, want error", name)
		} else if !strings.Contains(err.Error(), "exceeds") {
			t.Errorf("%s: error = %v, want it to name the length-cap refusal", name, err)
		}
	}

	// Boundary: a frame whose TOTAL is exactly maxRespTotal passes both gates
	// (they are strictly greater-than) and then fails on the missing body.
	fc := &fakeConn{}
	fc.respBuf.Write(buildHostileSigned(uint32(maxRespTotal), 0))
	c := newTestClient(fc)
	if _, _, err := c.MemStats(); err == nil || strings.Contains(err.Error(), "exceeds") {
		t.Errorf("at-total-cap length: err = %v, want a body-read error (not the length-cap refusal)", err)
	}

	// maxRespSegment is ABOVE maxRespTotal, so a single segment at the
	// per-segment cap is intentionally refused by the total gate first — the
	// per-segment check remains the pre-allocation guard for the three
	// segments combined. Either gate must fail closed without reading a body.
	fc2 := &fakeConn{}
	fc2.respBuf.Write(buildHostileSigned(uint32(maxRespSegment), 0))
	c2 := newTestClient(fc2)
	if _, _, err := c2.MemStats(); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("at-segment-cap length: err = %v, want the length-cap refusal", err)
	}
}

// --- mounted-volume assertion (28-byte header, mounted_len section) ---

func TestReadResponseRaw_MountedSection(t *testing.T) {
	// A successful MOUNT-family response carries the actually-mounted volume
	// basename in the third body section; the parser must surface it intact.
	r := bytes.NewReader(buildResponseMounted(codeOk, 0, "out", "err", "sandfs-abc123"))
	code, _, stdout, stderr, mounted, _, err := readResponseRaw(r, testSessionKey, &testNonce)
	if err != nil {
		t.Fatalf("readResponseRaw: %v", err)
	}
	if code != codeOk {
		t.Fatalf("code = %d, want %d", code, codeOk)
	}
	if string(stdout) != "out" || stderr != "err" {
		t.Errorf("stdout/stderr = %q/%q, want out/err", stdout, stderr)
	}
	if mounted != "sandfs-abc123" {
		t.Errorf("mounted = %q, want sandfs-abc123", mounted)
	}
}

func TestMountAndExec_CarriesMountedAssertion(t *testing.T) {
	fc := &fakeConn{}
	fc.respBuf.Write(buildResponseMounted(codeOk, 0, "hi\n", "", "sandfs-xyz"))
	c := newTestClient(fc)

	stdout, _, _, status, _, mounted, err := c.MountAndExec("/vols/sandfs-xyz", "/mnt/rootfs", "echo hi", 0, false, "flat")
	if err != nil {
		t.Fatalf("MountAndExec: %v", err)
	}
	if stdout != "hi\n" || status != "done" {
		t.Errorf("stdout/status = %q/%q, want hi\\n/done", stdout, status)
	}
	if mounted != "sandfs-xyz" {
		t.Errorf("mounted = %q, want sandfs-xyz (basename of the requested device path)", mounted)
	}
}

func TestMountAndAsyncExec_CarriesMountedAssertion(t *testing.T) {
	fc := &fakeConn{}
	fc.respBuf.Write(buildResponseMounted(codeOk, 0, "bg-7", "", "sandfs-xyz"))
	c := newTestClient(fc)

	execID, mounted, err := c.MountAndAsyncExec("/vols/sandfs-xyz", "/mnt/rootfs", "sleep 10", false, "flat")
	if err != nil {
		t.Fatalf("MountAndAsyncExec: %v", err)
	}
	if execID != "bg-7" {
		t.Errorf("execID = %q, want bg-7", execID)
	}
	if mounted != "sandfs-xyz" {
		t.Errorf("mounted = %q, want sandfs-xyz", mounted)
	}
}

// ── typed isolation-refusal sentinels ────────────────────────────────────

func TestClassifyTransportRefusal(t *testing.T) {
	// The warden sends the named token as the leading word of the transport
	// error's stderr; the typed sentinel must wrap it with the token intact.
	err := classifyTransportRefusal("volume_identity_mismatch: warm op volume identity does not match the mounted volume")
	if !errors.Is(err, ErrVolumeIdentityMismatch) {
		t.Errorf("mismatch refusal must wrap ErrVolumeIdentityMismatch, got %v", err)
	}
	if !strings.Contains(err.Error(), "volume_identity_mismatch") {
		t.Errorf("the named token must stay visible for string classifiers: %v", err)
	}
	err = classifyTransportRefusal("volume_identity_missing: warm op carries no mounted-volume identity")
	if !errors.Is(err, ErrVolumeIdentityMissing) {
		t.Errorf("missing refusal must wrap ErrVolumeIdentityMissing, got %v", err)
	}
	// Ordinary transport errors keep the generic form and NO sentinel.
	err = classifyTransportRefusal("exec: some ordinary failure")
	if errors.Is(err, ErrVolumeIdentityMismatch) || errors.Is(err, ErrVolumeIdentityMissing) {
		t.Errorf("ordinary failure must carry no identity sentinel: %v", err)
	}
	if !strings.Contains(err.Error(), "warden rpc failed") {
		t.Errorf("generic form preserved: %v", err)
	}
}

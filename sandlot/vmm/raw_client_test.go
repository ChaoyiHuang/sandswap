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
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeRawVMM is an in-process raw-frame server over a Unix socket that
// mirrors the sandvmm raw protocol (vmm/src/api/http/raw.rs). Each accepted
// connection answers frames from a configurable handler.
type fakeRawVMM struct {
	lis      net.Listener
	mu       sync.Mutex
	handler  func(op byte, body []byte) (status byte, msg string)
	lastOp   byte
	lastBody []byte
}

func newFakeRawVMM(t *testing.T, handler func(op byte, body []byte) (byte, string)) *fakeRawVMM {
	t.Helper()
	dir, err := os.MkdirTemp("", "rawvmm")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "sandvmm.sock")
	lis, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeRawVMM{lis: lis, handler: handler}
	go f.serve()
	t.Cleanup(func() { lis.Close() })
	return f
}

func (f *fakeRawVMM) serve() {
	for {
		conn, err := f.lis.Accept()
		if err != nil {
			return
		}
		go f.handle(conn)
	}
}

func (f *fakeRawVMM) handle(conn net.Conn) {
	defer conn.Close()
	var hdr [8]byte
	for {
		if _, err := io.ReadFull(conn, hdr[:]); err != nil {
			return
		}
		bodyLen := binary.BigEndian.Uint32(hdr[4:8])
		var body []byte
		if bodyLen > 0 {
			body = make([]byte, bodyLen)
			if _, err := io.ReadFull(conn, body); err != nil {
				return
			}
		}
		f.mu.Lock()
		f.lastOp = hdr[1]
		f.lastBody = body
		status, msg := f.handler(hdr[1], body)
		f.mu.Unlock()

		var resp [8]byte
		resp[0] = rawProtoVersion
		resp[1] = hdr[1]
		resp[2] = status
		binary.BigEndian.PutUint32(resp[4:8], uint32(len(msg)))
		if _, err := conn.Write(resp[:]); err != nil {
			return
		}
		if len(msg) > 0 {
			if _, err := conn.Write([]byte(msg)); err != nil {
				return
			}
		}
	}
}

func (f *fakeRawVMM) socket() string { return f.lis.Addr().String() }

func forceRawTransport(t *testing.T) {
	t.Helper()
	if err := ConfigureSetFsTransport("raw"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ConfigureSetFsTransport(SetFsTransportDefault) })
}

func TestRawClient_SetFsRoundTrip(t *testing.T) {
	forceRawTransport(t)
	f := newFakeRawVMM(t, func(op byte, body []byte) (byte, string) {
		if op != rawOpSetFs {
			return rawStatusErr, "not set-fs"
		}
		return rawStatusOK, ""
	})
	c := NewClient(f.socket())
	ctx := context.Background()

	if err := c.SetFs(ctx, "fs0", "sandswap", []string{"/var/sandswap/volumes/sandfs-a"}, "gen0"); err != nil {
		t.Fatalf("SetFs: %v", err)
	}
	// Same connection reused: a second call must also succeed.
	if err := c.SetFs(ctx, "fs0", "sandswap", nil, ""); err != nil {
		t.Fatalf("SetFs (clear): %v", err)
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if f.lastOp != rawOpSetFs {
		t.Fatalf("last op = %d, want set-fs", f.lastOp)
	}
	// Decode the clear body and check n_paths == 0.
	if n := binary.BigEndian.Uint16(f.lastBody[len(f.lastBody)-2:]); n != 0 {
		t.Fatalf("clear body n_paths = %d, want 0", n)
	}
	if c.rawConn == nil {
		t.Fatal("raw connection should be cached")
	}
}

func TestRawClient_PingRoundTrip(t *testing.T) {
	forceRawTransport(t)
	f := newFakeRawVMM(t, func(op byte, body []byte) (byte, string) {
		if op != rawOpPing {
			return rawStatusErr, "not ping"
		}
		return rawStatusOK, ""
	})
	c := NewClient(f.socket())
	if err := c.Ping(context.Background()); err != nil {
		t.Fatalf("Ping: %v", err)
	}
}

func TestRawClient_ErrorFrame(t *testing.T) {
	forceRawTransport(t)
	f := newFakeRawVMM(t, func(op byte, body []byte) (byte, string) {
		return rawStatusErr, "vm.set-fs: unknown fs device id \"bogus\""
	})
	c := NewClient(f.socket())
	err := c.SetFs(context.Background(), "bogus", "sandswap", []string{"/v/a"}, "gen0")
	if err == nil || !strings.Contains(err.Error(), "unknown fs device id") {
		t.Fatalf("err = %v, want server message surfaced", err)
	}
	// A frame-level error must keep the connection usable.
	if c.rawConn == nil {
		t.Fatal("connection should survive a frame-level error")
	}
}

func TestRawClient_VersionReject(t *testing.T) {
	forceRawTransport(t)
	// Server speaks version 7: the rejection frame carries ITS version, and
	// the client must classify it as *ErrRawProtocolVersion.
	sock := newVersionRejectVMM(t)
	c := NewClient(sock)
	err := c.Ping(context.Background())
	if err == nil {
		t.Fatal("want version error")
	}
	var ve *ErrRawProtocolVersion
	if !errors.As(err, &ve) {
		t.Fatalf("err = %T (%v), want *ErrRawProtocolVersion", err, err)
	}
	if ve.ServerVersion != 7 {
		t.Fatalf("server version = %d, want 7", ve.ServerVersion)
	}
}

// newVersionRejectVMM serves one connection whose response header claims
// server version 7 with STATUS_VERSION_REJECT.
func newVersionRejectVMM(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "rawvmm7")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "sandvmm.sock")
	lis, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		defer lis.Close()
		conn, err := lis.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		var hdr [8]byte
		if _, err := io.ReadFull(conn, hdr[:]); err != nil {
			return
		}
		var resp [8]byte
		resp[0] = 7 // server's own version
		resp[1] = hdr[1]
		resp[2] = rawStatusVersionReject
		msg := "protocol version 1 not supported (server speaks 7)"
		binary.BigEndian.PutUint32(resp[4:8], uint32(len(msg)))
		conn.Write(resp[:])
		conn.Write([]byte(msg))
		time.Sleep(50 * time.Millisecond) // let the client read before close
	}()
	return sock
}

func TestRawClient_TransportErrorRedials(t *testing.T) {
	forceRawTransport(t)
	f := newFakeRawVMM(t, func(op byte, body []byte) (byte, string) {
		return rawStatusOK, ""
	})
	c := NewClient(f.socket())
	if err := c.Ping(context.Background()); err != nil {
		t.Fatalf("Ping: %v", err)
	}

	// Kill the server side of the cached conn; the next op must see a
	// transport error and poison the cached connection, not reuse it.
	f.lis.Close()
	c.rawMu.Lock()
	conn := c.rawConn
	c.rawMu.Unlock()
	if conn == nil {
		t.Fatal("raw conn should be cached")
	}
	conn.Close()

	err := c.Ping(context.Background())
	if err == nil {
		t.Fatal("Ping should fail after connection death")
	}
	c.rawMu.Lock()
	poisoned := c.rawConn == nil
	c.rawMu.Unlock()
	if !poisoned {
		t.Fatal("transport error must poison the cached connection")
	}
}

func TestRawClient_ConnectDeadline(t *testing.T) {
	forceRawTransport(t)
	// Server that accepts but never answers: the ctx deadline must fire.
	dir, err := os.MkdirTemp("", "rawvmm-slow")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "sandvmm.sock")
	lis, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer lis.Close()
	go func() {
		for {
			conn, err := lis.Accept()
			if err != nil {
				return
			}
			// hold the connection open, answer nothing
			go func(c net.Conn) {
				time.Sleep(10 * time.Second)
				c.Close()
			}(conn)
		}
	}()

	c := NewClient(sock)
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	start := time.Now()
	err = c.Ping(ctx)
	if err == nil {
		t.Fatal("Ping should time out")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("deadline took %v, ctx deadline not honored", elapsed)
	}
}

func TestEncodeSetFsBody_Validation(t *testing.T) {
	tag, id := "sandswap", "fs0"
	long := "/" + strings.Repeat("a", rawMaxPath) // rawMaxPath+1 bytes: over

	if _, err := encodeSetFsBody(id, "", []string{"/v"}, ""); err == nil || !strings.Contains(err.Error(), "tag") {
		t.Errorf("empty tag: err = %v, want tag error", err)
	}
	if _, err := encodeSetFsBody(id, tag, []string{"relative/path"}, "gen0"); err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Errorf("relative path: err = %v, want absolute-path error", err)
	}
	if _, err := encodeSetFsBody(id, tag, []string{long}, "gen0"); err == nil || !strings.Contains(err.Error(), "PATH_MAX") {
		t.Errorf("oversize path: err = %v, want PATH_MAX error", err)
	}
	dirs := make([]string, rawMaxPaths+1)
	for i := range dirs {
		dirs[i] = "/v"
	}
	if _, err := encodeSetFsBody(id, tag, dirs, "gen0"); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("too many dirs: err = %v, want count error", err)
	}

	// Boundary: exactly PATH_MAX-1 bytes must pass (longest path that can
	// exist on the host — parity with what HTTP accepts today).
	maxLen := "/" + strings.Repeat("a", rawMaxPath-1)
	if len(maxLen) != rawMaxPath {
		t.Fatalf("fixture length %d, want %d", len(maxLen), rawMaxPath)
	}
	if _, err := encodeSetFsBody(id, tag, []string{maxLen}, "gen0"); err != nil {
		t.Errorf("max-length path rejected: %v", err)
	}

	// Body layout round-trip against the Rust parser's expectations.
	body, err := encodeSetFsBody(id, tag, []string{"/vol/a"}, "gen0")
	if err != nil {
		t.Fatal(err)
	}
	if body[0] != byte(len(tag)) || string(body[1:1+len(tag)]) != tag {
		t.Fatal("tag encoding mismatch")
	}
	off := 1 + len(tag)
	if body[off] != byte(len(id)) || string(body[off+1:off+1+len(id)]) != id {
		t.Fatal("id encoding mismatch")
	}
	off += 1 + len(id)
	if n := binary.BigEndian.Uint16(body[off : off+2]); n != 1 {
		t.Fatalf("n_paths = %d, want 1", n)
	}
	off += 2
	pl := binary.BigEndian.Uint16(body[off : off+2])
	if string(body[off+2:off+2+int(pl)]) != "/vol/a" {
		t.Fatal("path encoding mismatch")
	}
	off += 2 + int(pl)
	if off >= len(body) {
		t.Fatalf("body truncated before alias_len")
	}
	al := int(body[off])
	off++
	if al != len("gen0") || string(body[off:off+al]) != "gen0" {
		t.Fatalf("alias encoding mismatch: len=%d alias=%q", al, body[off:off+al])
	}
	off += al
	if len(body) != off {
		t.Fatalf("body length %d, want exactly one trailing alias (off=%d)", len(body), off)
	}
	// The alias is mandatory for a non-empty export and forbidden on a clear.
	if _, err := encodeSetFsBody(id, tag, []string{"/v/a"}, ""); err == nil {
		t.Errorf("missing alias for a non-empty export must be refused")
	}
	if _, err := encodeSetFsBody(id, tag, nil, "gen0"); err == nil {
		t.Errorf("an alias on the clear must be refused")
	}
	if _, err := encodeSetFsBody(id, tag, []string{"/v/a"}, ".."); err == nil {
		t.Errorf("a '..' alias must be refused")
	}
}

func TestConfigureSetFsTransport(t *testing.T) {
	if err := ConfigureSetFsTransport("bogus"); err == nil {
		t.Fatal("invalid mode accepted")
	}
	if err := ConfigureSetFsTransport("http"); err != nil {
		t.Fatal(err)
	}
	if !setFsUseHTTP.Load() {
		t.Fatal("http mode not applied")
	}
	if err := ConfigureSetFsTransport("raw"); err != nil {
		t.Fatal(err)
	}
	if setFsUseHTTP.Load() {
		t.Fatal("raw mode not applied")
	}
}

// IsPreviousTenantRefs classifies by the stable message token the VMM's
// PreviousTenantRefs Display carries on both set-fs transports; everything
// else (including a same-family InvalidFilter failure) must NOT classify.
func TestIsPreviousTenantRefs(t *testing.T) {
	raw := "sandvmm raw op 1 failed: previous-tenant-refs: open handles = 0, unforgotten inode refs = 2 — the export being swapped away is still in use; refusing"
	if !IsPreviousTenantRefs(errors.New(raw)) {
		t.Fatal("raw-frame tripwire error not classified")
	}
	if !IsPreviousTenantRefs(errors.New("vm.set-fs: previous-tenant-refs: open handles = 3, unforgotten inode refs = 0 — refusing")) {
		t.Fatal("HTTP-path tripwire error not classified")
	}
	for _, other := range []error{
		nil,
		errors.New("sandvmm raw op 1 failed: failed to init filter list: boom"),
		errors.New("sandvmm raw write (op 1): connection reset"),
	} {
		if IsPreviousTenantRefs(other) {
			t.Fatalf("non-tripwire error classified: %v", other)
		}
	}
}

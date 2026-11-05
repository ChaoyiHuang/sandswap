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

package core

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"sandlot/vmm"
)

// The boxout relay tests run a fake boxout sidecar on a temp Unix socket and
// pin the egress-identity wire contract (net_stamp_identity / net_mount_state)
// plus the failure semantics: a wedged or refusing boxout degrades the stamp,
// never the mount.

// Compile-time: in boxout mode the manager serves as the Handler's
// NetworkProvider, and binding.go discovers the identity hooks on it.
var (
	_ vmm.NetworkProvider = (*BoxoutManager)(nil)
	_ vmm.MountGater      = (*BoxoutManager)(nil)
	_ vmm.IdentityStamper = (*BoxoutManager)(nil)
)

// fakeBoxout is a minimal stand-in for the boxout sidecar: one response per
// connection, requests recorded for inspection.
type fakeBoxout struct {
	socketPath string
	ln         net.Listener

	mu        sync.Mutex
	requests  []map[string]any
	respond   func(reqType string) map[string]any // nil = ok:true
	silent    bool                                // accept but never respond
	connected chan struct{}                       // closed on first accept
}

func newFakeBoxout(t *testing.T) *fakeBoxout {
	t.Helper()
	dir := t.TempDir()
	ln, err := net.Listen("unix", filepath.Join(dir, "boxout.sock"))
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	f := &fakeBoxout{
		socketPath: ln.Addr().String(),
		ln:         ln,
		connected:  make(chan struct{}),
	}
	t.Cleanup(func() { _ = ln.Close() })
	go f.serve()
	return f
}

func (f *fakeBoxout) serve() {
	for {
		conn, err := f.ln.Accept()
		if err != nil {
			return
		}
		f.handle(conn)
	}
}

func (f *fakeBoxout) handle(conn net.Conn) {
	defer conn.Close()
	select {
	case <-f.connected:
	default:
		close(f.connected)
	}
	line, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil {
		return
	}
	var req map[string]any
	if err := json.Unmarshal(line, &req); err != nil {
		return
	}
	f.mu.Lock()
	f.requests = append(f.requests, req)
	respond := f.respond
	silent := f.silent
	f.mu.Unlock()
	if silent {
		select {} // hold the connection open without responding
	}
	resp := map[string]any{"ok": true}
	if respond != nil {
		resp = respond(req["type"].(string))
	}
	data, _ := json.Marshal(resp)
	conn.Write(append(data, '\n'))
}

func (f *fakeBoxout) recorded() []map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]map[string]any(nil), f.requests...)
}

func newRelayTestManager(t *testing.T, f *fakeBoxout) *BoxoutManager {
	t.Helper()
	return NewBoxoutManager(f.socketPath, "", log.New(os.Stderr, "[relay-test] ", 0))
}

func TestBoxoutManagerIdentityRelayWire(t *testing.T) {
	f := newFakeBoxout(t)
	m := newRelayTestManager(t, f)

	// Stamp relay must carry the full binding (same epoch the
	// region published).
	m.SetMountIdentity(context.Background(), "vm-1", "agent-a", "sandfs-b", 7)
	reqs := f.recorded()
	if len(reqs) != 1 {
		t.Fatalf("requests recorded = %d, want 1", len(reqs))
	}
	req := reqs[0]
	for k, want := range map[string]any{
		"type":      "net_stamp_identity",
		"vm_id":     "vm-1",
		"agent_id":  "agent-a",
		"sandfs_id": "sandfs-b",
		"epoch":     float64(7),
	} {
		if got := req[k]; got != want {
			t.Errorf("stamp request %s = %v, want %v", k, got, want)
		}
	}

	// Gate relay: unmount side (mounted=false) removes the stamp.
	m.SetMountState(context.Background(), "vm-1", false)
	reqs = f.recorded()
	if len(reqs) != 2 {
		t.Fatalf("requests after gate relay = %d, want 2", len(reqs))
	}
	gate := reqs[1]
	if gate["type"] != "net_mount_state" || gate["vm_id"] != "vm-1" {
		t.Errorf("gate request = %v", gate)
	}
	mounted, _ := gate["mounted"].(bool)
	if mounted {
		t.Errorf("gate request must carry mounted=false (unstamp), got %v", gate["mounted"])
	}
}

func TestBoxoutManagerRelayFailureTolerated(t *testing.T) {
	// ok:false (backend refused) and transport death must both degrade to a
	// log line — the stamp is derived state; the mount itself must proceed.
	for name, respond := range map[string]func(string) map[string]any{
		"refused":  func(string) map[string]any { return map[string]any{"ok": false, "error": "nope"} },
		"connfail": nil, // listener closed: dial fails
	} {
		t.Run(name, func(t *testing.T) {
			f := newFakeBoxout(t)
			if respond == nil {
				_ = f.ln.Close() // make dial fail
			} else {
				f.mu.Lock()
				f.respond = respond
				f.mu.Unlock()
			}
			m := newRelayTestManager(t, f)
			done := make(chan struct{})
			go func() {
				defer close(done)
				m.SetMountIdentity(context.Background(), "vm-2", "a", "s", 1)
				m.SetMountState(context.Background(), "vm-2", false)
			}()
			select {
			case <-done:
			// Each relay call carries its own identityRelayTimeout budget
			// (two calls → two budgets).
			case <-time.After(2*identityRelayTimeout + 3*time.Second):
				t.Fatal("relay calls must return promptly on refusal, not block")
			}
		})
	}
}

func TestBoxoutManagerRelayBoundedWhenSilent(t *testing.T) {
	f := newFakeBoxout(t)
	f.mu.Lock()
	f.silent = true // accept, never respond
	f.mu.Unlock()
	m := newRelayTestManager(t, f)

	start := time.Now()
	m.SetMountIdentity(context.Background(), "vm-3", "a", "s", 1)
	elapsed := time.Since(start)
	budget := identityRelayTimeout + 2*time.Second // slack for scheduling
	if elapsed > budget {
		t.Fatalf("silent boxout stalled the stamp for %v (budget %v)", elapsed, budget)
	}
	<-f.connected // make sure the request actually reached the fake sidecar
}

// TestBoxoutManagerTokenHandshake pins the client half of the mutual token
// handshake: the client answers the server's challenge and REFUSES to send a
// request when the server cannot prove it holds the same token (a squatter at
// the socket path). With matching tokens the request round-trips.
func TestBoxoutManagerTokenHandshake(t *testing.T) {
	const token = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	for _, tc := range []struct {
		name        string
		serverToken string
		wantErr     bool
	}{
		{"matching token", token, false},
		{"server without the token", "not-the-token", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			sock := filepath.Join(dir, "boxout.sock")
			ln, err := net.Listen("unix", sock)
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			defer ln.Close()
			tokFile := filepath.Join(dir, "token")
			if err := os.WriteFile(tokFile, []byte(token+"\n"), 0o600); err != nil {
				t.Fatalf("token file: %v", err)
			}
			sawRequest := make(chan struct{}, 1)
			go func() {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				defer conn.Close()
				rdr := bufio.NewReader(conn)
				nonce := make([]byte, boxoutAuthNonceBytes)
				if _, err := rand.Read(nonce); err != nil {
					return
				}
				fmt.Fprintf(conn, `{"type":"auth_challenge","nonce":"%s"}`+"\n", hex.EncodeToString(nonce))
				line, err := rdr.ReadBytes('\n')
				if err != nil {
					return
				}
				var resp struct {
					Type  string `json:"type"`
					HMAC  string `json:"hmac"`
					Nonce string `json:"nonce"`
				}
				if err := json.Unmarshal(line, &resp); err != nil || resp.Type != "auth_response" {
					return
				}
				fmt.Fprintf(conn, `{"type":"auth_ok","ok":true,"hmac":"%s"}`+"\n", authMAC(tc.serverToken, "server:"+resp.Nonce))
				if _, err := rdr.ReadBytes('\n'); err == nil {
					sawRequest <- struct{}{}
					conn.Write([]byte(`{"ok":true}` + "\n"))
				}
			}()
			m := NewBoxoutManager(sock, tokFile, log.New(os.Stderr, "[handshake-test] ", 0))
			err = m.ReleaseNetwork(context.Background(), "vm-1")
			if (err != nil) != tc.wantErr {
				t.Fatalf("ReleaseNetwork error = %v, wantErr %v", err, tc.wantErr)
			}
			select {
			case <-sawRequest:
				if tc.wantErr {
					t.Fatal("a request was delivered to an unauthenticated server")
				}
			case <-time.After(200 * time.Millisecond):
				if !tc.wantErr {
					t.Fatal("the request never reached the authenticated server")
				}
			}
		})
	}
}

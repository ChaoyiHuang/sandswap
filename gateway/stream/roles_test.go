// Copyright 2026 Chaoyi Huang. All rights reserved.
//
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE file at the root of this repository.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, sandswap's use of this software will be governed
// by the Apache License, Version 2.0.

package stream

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	pb "common/proto/stream"
)

// waitForSent polls the fake stream's recorded sends until at least one
// message lands (Send happens on the writeLoop goroutine).
func waitForSent(t *testing.T, fs *fakeStream) []*pb.GatewayMessage {
	t.Helper()
	for i := 0; i < 100; i++ {
		if sent := fs.sentMessages(); len(sent) > 0 {
			return sent
		}
		time.Sleep(5 * time.Millisecond)
	}
	return fs.sentMessages()
}

// The certificate is the role grant: an advertised role the leaf does not
// carry is refused by name, and a leaf with no role URI grants nothing (there
// is no legacy fallback). The TLS layer already verified the CA signature, so
// this is the issuance-time authorization.
func TestRoleBindingRefusal(t *testing.T) {
	leaf := func(roles ...string) *x509.Certificate {
		c := &x509.Certificate{Subject: pkix.Name{CommonName: "node-1"}}
		for _, r := range roles {
			u, err := url.Parse("sandswap://role/" + r)
			if err != nil {
				t.Fatal(err)
			}
			c.URIs = append(c.URIs, u)
		}
		return c
	}

	if got := roleBindingRefusal(leaf(RoleExec), []string{RoleExec}); got != "" {
		t.Fatalf("an exec cert advertising exec must be accepted, got %q", got)
	}
	if got := roleBindingRefusal(leaf(RoleExec, RoleProv), []string{RoleExec, RoleProv}); got != "" {
		t.Fatalf("a merged cert advertising both must be accepted, got %q", got)
	}
	got := roleBindingRefusal(leaf(RoleExec), []string{RoleProv})
	if got == "" {
		t.Fatal("an exec-only certificate must not be accepted for prov")
	}
	if !strings.Contains(got, "URI SAN") || !strings.Contains(got, "prov") {
		t.Fatalf("the refusal must name the missing role and the certificate fix, got %q", got)
	}
	if got := roleBindingRefusal(leaf(), []string{RoleExec}); got == "" {
		t.Fatal("a certificate with no role URI must authorize nothing")
	}
	// A URI with the right words but the wrong carrier is ignored.
	c := leaf()
	u, _ := url.Parse("https://role/prov")
	c.URIs = append(c.URIs, u)
	if got := roleBindingRefusal(c, []string{RoleProv}); got == "" {
		t.Fatal("only sandswap://role/<role> URIs grant roles")
	}
}

// End-to-end (fake-stream) shape of the certificate-role binding: a role the
// gateway would accept is still refused when the verified client certificate
// was not issued for it. This is the storage-plane escalation the binding
// closes (any node certificate could otherwise declare prov).
func TestConnectRefusesARoleTheCertificateDoesNotGrant(t *testing.T) {
	srv := NewServer("gw-roles", silentLogger(), 0, 0)
	srv.SetAcceptedRoles([]string{RoleExec, RoleProv})
	fs := newFakeStreamForRoles("node-roles", RoleExec) // certificate grants exec only
	fs.recvCh <- helloMsg(&pb.NodeHello{
		NodeId:          "node-roles",
		ProtocolVersion: StreamProtocolVersion,
		Roles:           []string{RoleProv},
	})
	done := make(chan error, 1)
	go func() { done <- srv.Connect(fs) }()
	if err := <-done; err == nil {
		t.Fatal("a prov role not granted by the certificate must be refused")
	}
	sent := waitForSent(t, fs)
	if len(sent) != 1 || sent[0].GetHelloAck() == nil {
		t.Fatalf("expected one HelloAck rejection, got %+v", sent)
	}
	if reason := sent[0].GetHelloAck().GetRejectReason(); !strings.Contains(reason, "does not grant") {
		t.Fatalf("refusal must name the certificate-role rule, got %q", reason)
	}
}

// Role gate matrix: which advertisements an exec-only / human-only / unified
// gateway accepts, and that every rejection carries a NAMED reason in the
// HelloAck (the instance logs it verbatim and moves to its next address).
func TestConnectRoleGate(t *testing.T) {
	cases := []struct {
		name        string
		accepted    []string
		advertised  []string
		wantReject  bool
		wantReasons []string
	}{
		// Empty advertisement = the legacy exec node shape.
		{"empty roles accepted as exec on exec gw", []string{RoleExec}, nil, false, nil},
		{"exec on exec gw", []string{RoleExec}, []string{"exec"}, false, nil},
		{"prov on prov gw", []string{RoleProv}, []string{"prov"}, false, nil},
		{"merged on unified gw", []string{RoleExec, RoleProv}, []string{"exec", "prov"}, false, nil},
		// Partial overlap serves the overlap: a merged instance on an exec
		// gateway is an exec connection there (the prov half simply has no
		// executor to talk to).
		{"merged on exec gw serves exec half", []string{RoleExec}, []string{"exec", "prov"}, false, nil},
		{"exec on prov gw refused", []string{RoleProv}, []string{"exec"}, true, []string{"roles not accepted", "human/unified gateway"}},
		{"prov on exec gw refused", []string{RoleExec}, []string{"prov"}, true, []string{"roles not accepted", "human/unified gateway"}},
		{"unknown role refused", []string{RoleExec, RoleProv}, []string{"frobnicate"}, true, []string{"unknown roles"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := NewServer("gw-roles", silentLogger(), 0, 0)
			srv.SetAcceptedRoles(tc.accepted)
			// Atomic + polled read: Connect sends the HelloAck BEFORE invoking
			// OnConnect, so observing the ack does NOT imply the callback has
			// run — a bare bool read here is both a data race (callback writes
			// on the Connect goroutine) and a timing flake (callback may land
			// after the assertion).
			var connected atomic.Bool
			srv.OnConnect(func(nc *NodeConnection) { connected.Store(true) })

			fs := newFakeStreamFor("node-roles")
			fs.recvCh <- helloMsg(&pb.NodeHello{
				NodeId:          "node-roles",
				ProtocolVersion: StreamProtocolVersion,
				Roles:           tc.advertised,
			})
			done := make(chan error, 1)
			go func() { done <- srv.Connect(fs) }()

			if tc.wantReject {
				err := <-done
				if err == nil {
					t.Fatal("expected a rejection error")
				}
				// The named reason rides in the HelloAck the instance received
				// BEFORE the stream died — no EOF forensics needed.
				sent := waitForSent(t, fs)
				if len(sent) != 1 || sent[0].GetHelloAck() == nil {
					t.Fatalf("expected one HelloAck rejection, got %+v", sent)
				}
				ack := sent[0].GetHelloAck()
				if ack.GetRejectReason() == "" {
					t.Fatal("rejection ack must carry reject_reason")
				}
				for _, want := range tc.wantReasons {
					if !strings.Contains(ack.GetRejectReason(), want) {
						t.Errorf("reject_reason should mention %q, got: %s", want, ack.GetRejectReason())
					}
				}
				if connected.Load() {
					t.Error("OnConnect must not fire for a rejected connection")
				}
				return
			}

			// Accepted: an ack WITHOUT a reject reason arrives, OnConnect
			// fires, and the connection is registered.
			sent := waitForSent(t, fs)
			if len(sent) == 0 || sent[0].GetHelloAck() == nil {
				t.Fatalf("expected HelloAck, got %+v", sent)
			}
			if rr := sent[0].GetHelloAck().GetRejectReason(); rr != "" {
				t.Fatalf("accepted connection got reject_reason %q", rr)
			}
			// The callback runs after the ack (production order) — wait for it
			// instead of racing it.
			for i := 0; i < 100 && !connected.Load(); i++ {
				time.Sleep(10 * time.Millisecond)
			}
			if !connected.Load() {
				t.Error("OnConnect must fire for an accepted connection")
			}
			close(fs.recvCh)
			<-done
		})
	}
}

// Roles()/HasRole() normalize the legacy shape: empty advertisement means
// exec.
func TestNodeConnectionRoles(t *testing.T) {
	nc := NewNodeConnection(&pb.NodeHello{NodeId: "n"}, nil, 0)
	if got := nc.Roles(); len(got) != 1 || got[0] != RoleExec {
		t.Fatalf("empty roles = %v, want [exec]", got)
	}
	if !nc.HasRole(RoleExec) || nc.HasRole(RoleProv) {
		t.Fatal("legacy shape must be exec-only")
	}
	nc = NewNodeConnection(&pb.NodeHello{NodeId: "n", Roles: []string{"prov"}}, nil, 0)
	if !nc.HasRole(RoleProv) || nc.HasRole(RoleExec) {
		t.Fatal("prov advertisement must be prov-only")
	}
}

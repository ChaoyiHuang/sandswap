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
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/url"
	"strings"
	"testing"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

// peerCtxRoles builds a stream context carrying a verified TLS peer whose leaf
// certificate has the given CN and role URI SANs — the shape gRPC hands the
// handler after RequireAndVerifyClientCert.
func peerCtxRoles(cn string, roles ...string) context.Context {
	leaf := &x509.Certificate{Subject: pkix.Name{CommonName: cn}}
	for _, r := range roles {
		u, err := url.Parse(roleURIScheme + "://" + roleURIHost + "/" + r)
		if err != nil {
			panic(err)
		}
		leaf.URIs = append(leaf.URIs, u)
	}
	info := credentials.TLSInfo{State: tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}}
	return peer.NewContext(context.Background(), &peer.Peer{AuthInfo: info})
}

// peerCtx is the common shape: a per-node certificate granted both roles.
func peerCtx(cn string) context.Context {
	return peerCtxRoles(cn, RoleExec, RoleProv)
}

// The node-identity gate: the declared node_id must equal the client certificate's
// CN. One deployment-wide certificate let any host that held it claim another
// node's id and receive that node's VMCommands; the binding makes the claim
// detectable at the handshake.
func TestVerifyNodeIdentityRequiresCertCNToMatch(t *testing.T) {
	s := NewServer("gw-test", nil, 8, 0)

	// Bound: CN == node_id.
	if got := s.verifyNodeIdentity(peerCtx("node-7"), "node-7"); got != "" {
		t.Fatalf("matching CN must be accepted, got rejection %q", got)
	}

	// Unbound: CN != node_id — the impersonation the gate exists to stop.
	got := s.verifyNodeIdentity(peerCtx("node-9"), "node-7")
	if got == "" {
		t.Fatal("a certificate for another node id must be rejected")
	}
	if !strings.Contains(got, "node-9") || !strings.Contains(got, "node-7") {
		t.Fatalf("the rejection must name both identities, got %q", got)
	}
	if !strings.Contains(got, "per-node certificate") {
		t.Fatalf("the rejection must tell the operator the fix, got %q", got)
	}

	// A shared deployment certificate: its CN is not a node id,
	// so it can never match — refused, never grandfathered.
	if got := s.verifyNodeIdentity(peerCtx("sandlot-client"), "node-7"); got == "" {
		t.Fatal("a shared deployment certificate must not be accepted for a specific node id")
	}
	if got := s.verifyNodeIdentity(peerCtx("sandlot"), "test-node-1"); got == "" {
		t.Fatal("a shared deployment certificate must not be accepted for a specific node id")
	}
}

// A stream presenting NO client certificate has no identity to check. It is
// REFUSED by name — accepting it was the pre-tightening posture ("verified by
// nothing, logged once"), which left the stream unauthenticated while
// looking healthy. The refusal must name both halves of the fix so the
// operator can repair a plaintext or misconfigured-TLS deployment from the
// log alone.
func TestVerifyNodeIdentityWithoutClientCertRefused(t *testing.T) {
	s := NewServer("gw-test", nil, 8, 0)

	refusal := func(ctx context.Context, what string) {
		t.Helper()
		got := s.verifyNodeIdentity(ctx, "node-7")
		if got == "" {
			t.Fatalf("%s: a credential-less stream must be refused", what)
		}
		for _, want := range []string{"no TLS client certificate", "node identity", "-tls-cert", "-stream-tls-ca"} {
			if !strings.Contains(got, want) {
				t.Fatalf("%s: refusal should mention %q, got %q", what, want, got)
			}
		}
	}

	// No peer in the context (plaintext listener).
	refusal(context.Background(), "peerless context")
	// A non-TLS AuthInfo (insecure credentials).
	refusal(peer.NewContext(context.Background(), &peer.Peer{AuthInfo: insecureAuthInfo{}}), "non-TLS auth info")
	// TLS transport with an empty peer chain (a TLS config that did not
	// require a client certificate — the listener always sets
	// RequireAndVerifyClientCert with a required CA, so this is the defensive
	// branch if a custom wiring regresses).
	emptyTLS := credentials.TLSInfo{State: tls.ConnectionState{}}
	refusal(peer.NewContext(context.Background(), &peer.Peer{AuthInfo: emptyTLS}), "empty peer chain")
}

type insecureAuthInfo struct{}

func (insecureAuthInfo) AuthType() string { return "insecure" }

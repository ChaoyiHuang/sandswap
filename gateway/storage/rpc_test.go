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

package storage

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"log"
	"math/big"
	"net"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	pb "common/proto/stream"
	"gateway/stream"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/test/bufconn"
)

// testServerTLS is the server half of the stream transport: TLS 1.3 with a
// certificate ALWAYS required (the identity gate binds hello.node_id to the
// client certificate CN, so an anonymous peer is refused). The certificate
// itself is not verified here; these tests exercise routing, not PKI.
func testServerTLS(t *testing.T) *tls.Config {
	t.Helper()
	return &tls.Config{
		Certificates: []tls.Certificate{selfSignedCert(t, "gw-test", true)},
		ClientAuth:   tls.RequireAnyClientCert,
		MinVersion:   tls.VersionTLS13,
	}
}

// testClientCreds presents a self-signed certificate whose CN is the node id
// the fake instance declares in its hello — exactly the binding the gateway
// enforces.
func testClientCreds(t *testing.T, nodeID string) credentials.TransportCredentials {
	t.Helper()
	return credentials.NewTLS(&tls.Config{
		Certificates:       []tls.Certificate{selfSignedCert(t, nodeID, false)},
		InsecureSkipVerify: true, // test-only: the gateway cert is throwaway
		MinVersion:         tls.VersionTLS13,
	})
}

func selfSignedCert(t *testing.T, cn string, server bool) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	usage := x509.ExtKeyUsageClientAuth
	if server {
		usage = x509.ExtKeyUsageServerAuth
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
	}
	if !server {
		// The gateway binds stream roles to the certificate's URI SANs.
		for _, r := range []string{"exec", "prov"} {
			u, err := url.Parse("sandswap://role/" + r)
			if err != nil {
				t.Fatalf("role uri: %v", err)
			}
			tmpl.URIs = append(tmpl.URIs, u)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// fakeProvNode plays a prov-role sandlot instance against a REAL stream
// server over bufconn: it handshakes with roles=[prov], then answers every
// ProvisionCommand with the scripted responder.
type fakeProvNode struct {
	respond func(cmd *pb.ProvisionCommand) *pb.ProvisionResponse
}

func startStreamWithNode(t *testing.T, respond func(cmd *pb.ProvisionCommand) *pb.ProvisionResponse) *stream.Server {
	t.Helper()
	srv := stream.NewServer("gw-test", log.New(&discardWriter{}, "", 0), 8, 5*time.Second)
	srv.SetAcceptedRoles([]string{stream.RoleProv})

	lis := bufconn.Listen(64 * 1024)
	grpcSrv := grpc.NewServer(grpc.Creds(credentials.NewTLS(testServerTLS(t))))
	pb.RegisterNodeStreamServer(grpcSrv, srv)
	go grpcSrv.Serve(lis)
	t.Cleanup(grpcSrv.Stop)

	conn, err := grpc.Dial("bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(testClientCreds(t, "prov-1")))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	st, err := pb.NewNodeStreamClient(conn).Connect(context.Background())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if err := st.Send(&pb.NodeMessage{NodeId: "prov-1", Payload: &pb.NodeMessage_Hello{Hello: &pb.NodeHello{
		NodeId: "prov-1", ProtocolVersion: 1, Roles: []string{"prov"},
	}}}); err != nil {
		t.Fatalf("hello: %v", err)
	}
	ack, err := st.Recv()
	if err != nil || ack.GetHelloAck().GetRejectReason() != "" {
		t.Fatalf("handshake: %v ack=%+v", err, ack)
	}
	go func() {
		for {
			msg, err := st.Recv()
			if err != nil {
				return
			}
			if cmd := msg.GetProvisionCommand(); cmd != nil {
				_ = st.Send(&pb.NodeMessage{NodeId: "prov-1", Payload: &pb.NodeMessage_ProvisionResponse{
					ProvisionResponse: respond(cmd),
				}})
			}
		}
	}()
	return srv
}

type discardWriter struct{}

func (d *discardWriter) Write(p []byte) (int, error) { return len(p), nil }

// startStreamServer creates the gateway-side stream server accepting prov
// connections over bufconn, with no nodes dialed yet (multi-node scenarios
// dial their own via dialProvNode).
func startStreamServer(t *testing.T) (*stream.Server, *bufconn.Listener) {
	t.Helper()
	srv := stream.NewServer("gw-failover", log.New(&discardWriter{}, "", 0), 8, 5*time.Second)
	srv.SetAcceptedRoles([]string{stream.RoleProv})

	lis := bufconn.Listen(64 * 1024)
	grpcSrv := grpc.NewServer(grpc.Creds(credentials.NewTLS(testServerTLS(t))))
	pb.RegisterNodeStreamServer(grpcSrv, srv)
	go grpcSrv.Serve(lis)
	t.Cleanup(grpcSrv.Stop)
	return srv, lis
}

// dialProvNode connects one fake prov node to the server's listener and runs
// its responder loop. It returns after the hello/ack handshake, so the node is
// registered server-side when it returns. The responder may call hangup to
// kill its own connection (a prov process dying) and return nil to leave the
// in-flight command unanswered — exactly a death MID-OP.
func dialProvNode(t *testing.T, lis *bufconn.Listener, nodeID string, respond func(cmd *pb.ProvisionCommand, hangup func()) *pb.ProvisionResponse) {
	t.Helper()
	conn, err := grpc.Dial("bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(testClientCreds(t, nodeID)))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	st, err := pb.NewNodeStreamClient(conn).Connect(context.Background())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if err := st.Send(&pb.NodeMessage{NodeId: nodeID, Payload: &pb.NodeMessage_Hello{Hello: &pb.NodeHello{
		NodeId: nodeID, ProtocolVersion: 1, Roles: []string{"prov"},
	}}}); err != nil {
		t.Fatalf("hello: %v", err)
	}
	ack, err := st.Recv()
	if err != nil || ack.GetHelloAck().GetRejectReason() != "" {
		t.Fatalf("handshake: %v ack=%+v", err, ack)
	}

	hangup := func() { _ = conn.Close() }
	go func() {
		for {
			msg, err := st.Recv()
			if err != nil {
				return
			}
			if cmd := msg.GetProvisionCommand(); cmd != nil {
				if resp := respond(cmd, hangup); resp != nil {
					_ = st.Send(&pb.NodeMessage{NodeId: nodeID, Payload: &pb.NodeMessage_ProvisionResponse{
						ProvisionResponse: resp,
					}})
				}
			}
		}
	}()
}

// A prov instance dying MID-OP (its stream torn down while a command is in
// flight) is a TRANSPORT failure: ops are idempotent, so roundTrip must fail
// over to the other connected instance. pick()'s rotation over the
// map-registered nodes is nondeterministic, so whichever node is contacted
// first kills itself without responding and the other one answers — the op
// succeeds only if the connection death is retried, not returned.
func TestRPCOpsFailoverOnConnectionDeath(t *testing.T) {
	srv, lis := startStreamServer(t)

	var died atomic.Bool
	var first atomic.Bool
	responder := func(cmd *pb.ProvisionCommand, hangup func()) *pb.ProvisionResponse {
		if first.CompareAndSwap(false, true) {
			died.Store(true)
			hangup()
			return nil // no response: the connection dies with the op in flight
		}
		return &pb.ProvisionResponse{CommandId: cmd.GetCommandId(), Success: true, RootfsPath: "/vols/survivor"}
	}
	dialProvNode(t, lis, "prov-a", responder)
	dialProvNode(t, lis, "prov-b", responder)

	ops := NewRPC(srv, 5*time.Second)
	res, err := ops.EnsureVolume(context.Background(), "sandfs-x", "overlay", "ubuntu:24.04")
	if err != nil {
		t.Fatalf("EnsureVolume must fail over to the surviving prov instance: %v", err)
	}
	if !died.Load() {
		t.Fatal("harness: the dying node was never contacted — failover not exercised")
	}
	if res.RootfsPath != "/vols/survivor" {
		t.Fatalf("result = %+v", res)
	}
}

// The full round trip: a storage op crosses the stream, reaches the prov
// node, and the response's fields land on the caller's result — plus the
// named-503 path when no prov instance is connected.
func TestRPCOpsRoundTrip(t *testing.T) {
	srv := startStreamWithNode(t, func(cmd *pb.ProvisionCommand) *pb.ProvisionResponse {
		ev := cmd.GetEnsureVolume()
		if ev == nil {
			return &pb.ProvisionResponse{CommandId: cmd.GetCommandId(), Success: false, Error: "unexpected op"}
		}
		return &pb.ProvisionResponse{
			CommandId:   cmd.GetCommandId(),
			Success:     true,
			RootfsPath:  "/var/sandswap/volumes/sandfs-x",
			MinVcpus:    2,
			MinMemoryMb: 256,
			Pulled:      true,
		}
	})
	ops := NewRPC(srv, 5*time.Second)

	res, err := ops.EnsureVolume(context.Background(), "sandfs-x", "overlay", "ubuntu:24.04")
	if err != nil {
		t.Fatalf("EnsureVolume: %v", err)
	}
	if res.RootfsPath != "/var/sandswap/volumes/sandfs-x" || res.MinVCPUs != 2 || res.MinMemoryMB != 256 || !res.MinOK {
		t.Fatalf("result = %+v", res)
	}
	// The auto-pull signal must survive the stream round trip (it drives the
	// create response's pull_status).
	if !res.Pulled {
		t.Fatalf("Pulled not mapped from the ProvisionResponse: %+v", res)
	}
}

func TestRPCOpsNoProvisioner(t *testing.T) {
	srv := stream.NewServer("gw-empty", log.New(&discardWriter{}, "", 0), 8, 5*time.Second)
	ops := NewRPC(srv, time.Second)
	if _, err := ops.EnsureVolume(context.Background(), "s", "overlay", "t"); err != ErrNoProvisioner {
		t.Fatalf("want ErrNoProvisioner, got %v", err)
	}
	if err := ops.DeleteVolume("s"); err != ErrNoProvisioner {
		t.Fatalf("DeleteVolume: want ErrNoProvisioner, got %v", err)
	}
}

// A node-side business failure surfaces as a typed error (not retried on
// another node): the gateway's HTTP layer maps it to the error text.
func TestRPCOpsNodeError(t *testing.T) {
	srv := startStreamWithNode(t, func(cmd *pb.ProvisionCommand) *pb.ProvisionResponse {
		return &pb.ProvisionResponse{CommandId: cmd.GetCommandId(), Success: false, ErrorCode: "TEMPLATE_NOT_FOUND", Error: "no ref"}
	})
	ops := NewRPC(srv, 2*time.Second)
	_, err := ops.EnsureVolume(context.Background(), "sandfs-x", "overlay", "missing:1")
	if err == nil || NodeErrorCode(err) != "TEMPLATE_NOT_FOUND" {
		t.Fatalf("want TEMPLATE_NOT_FOUND node error, got %v", err)
	}
}

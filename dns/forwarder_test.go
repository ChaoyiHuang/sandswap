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

package main

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// The forwarder is byte-level now (forwardRaw on top of dns/wire.Relay): the
// upstream's response must be relayed to the client VERBATIM. The stub
// upstreams below answer with miekg (reference implementation) and the
// assertions unpack our relayed bytes with miekg — the same differential
// discipline as the rest of the DNS tests.

// startStubDNS starts a local UDP DNS upstream that runs handler, returning
// its "ip:port" and a stop function. No network dependency beyond loopback.
func startStubDNS(t *testing.T, handler dns.HandlerFunc) (addr string, stop func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr = pc.LocalAddr().String()
	server := &dns.Server{PacketConn: pc, Handler: handler}
	go server.ActivateAndServe()
	return addr, func() { _ = server.Shutdown() }
}

// startStubDNSTCP is startStubDNS over TCP (length-framed transport).
func startStubDNSTCP(t *testing.T, handler dns.HandlerFunc) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr = ln.Addr().String()
	server := &dns.Server{Listener: ln, Net: "tcp", Handler: handler}
	go server.ActivateAndServe()
	return addr, func() { _ = server.Shutdown() }
}

// stubAHandler answers any question with a single A record (9.9.9.9).
func stubAHandler() dns.HandlerFunc {
	return func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if len(r.Question) > 0 {
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.ParseIP("9.9.9.9"),
			})
		}
		_ = w.WriteMsg(m)
	}
}

// closedPort grabs an ephemeral port and closes it — a forwarder address that
// fails immediately (ICMP refused) instead of timing out.
func closedPort(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := pc.LocalAddr().String()
	pc.Close()
	return addr
}

// TestForwardNoForwarders verifies that with no upstream forwarders
// configured, a non-Sandswap query gets SERVFAIL (the DNS does not recurse).
func TestForwardNoForwarders(t *testing.T) {
	s := &DNSServer{cfg: &Config{}}
	m := ask(t, s, "example.com.", dns.TypeA)
	if m.Rcode != dns.RcodeServerFailure {
		t.Errorf("expected SERVFAIL with no forwarders, got rcode=%d", m.Rcode)
	}
}

// TestForwardRelaysUpstream verifies a working forwarder's response is
// relayed verbatim (answer bytes preserved, nothing synthesized).
func TestForwardRelaysUpstream(t *testing.T) {
	addr, stop := startStubDNS(t, stubAHandler())
	defer stop()

	s := &DNSServer{cfg: &Config{Forwarders: []string{addr}}}
	m := ask(t, s, "example.com.", dns.TypeA)
	if m.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected NOERROR from upstream, got rcode=%d", m.Rcode)
	}
	if len(m.Answer) != 1 {
		t.Fatalf("expected 1 answer relayed, got %d", len(m.Answer))
	}
	if a, ok := m.Answer[0].(*dns.A); !ok || !a.A.Equal(net.ParseIP("9.9.9.9")) {
		t.Errorf("expected relayed A 9.9.9.9, got %v", m.Answer[0])
	}
}

// TestForwardAllFail verifies that when every configured forwarder is
// unreachable, the client gets SERVFAIL.
func TestForwardAllFail(t *testing.T) {
	s := &DNSServer{cfg: &Config{Forwarders: []string{closedPort(t)}}}
	m := ask(t, s, "example.com.", dns.TypeA)
	if m.Rcode != dns.RcodeServerFailure {
		t.Errorf("expected SERVFAIL when all forwarders fail, got rcode=%d", m.Rcode)
	}
}

// TestForwardFailover verifies the multi-forwarder failover: a dead first
// forwarder falls through to the working second one.
func TestForwardFailover(t *testing.T) {
	goodAddr, stop := startStubDNS(t, stubAHandler())
	defer stop()

	s := &DNSServer{cfg: &Config{Forwarders: []string{closedPort(t), goodAddr}}}
	m := ask(t, s, "example.com.", dns.TypeA)
	if len(m.Answer) != 1 {
		t.Fatalf("expected relayed answer from failover forwarder, got %d answers rcode=%d", len(m.Answer), m.Rcode)
	}
	if a, ok := m.Answer[0].(*dns.A); !ok || !a.A.Equal(net.ParseIP("9.9.9.9")) {
		t.Errorf("expected failover A 9.9.9.9, got %v", m.Answer[0])
	}
}

// TestForwardTCPTransportFollowsInbound verifies the S1 fix end-to-end: a
// query processed on the TCP transport is forwarded to the upstream over TCP
// (previously every forward went over UDP, breaking truncation retries and
// TCP-only clients). The stub upstream serves TCP and asserts it received the
// query over TCP.
func TestForwardTCPTransportFollowsInbound(t *testing.T) {
	// TCP stub upstream: answers any length-framed query with the same bytes
	// (QR set), and records the transport it served.
	gotTCP := make(chan struct{}, 1)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				var l [2]byte
				if _, err := readFull(c, l[:]); err != nil {
					return
				}
				q := make([]byte, int(l[0])<<8|int(l[1]))
				if _, err := readFull(c, q); err != nil {
					return
				}
				select {
				case gotTCP <- struct{}{}:
				default:
				}
				resp := append([]byte(nil), q...)
				resp[2] |= 0x80 // QR
				var ol [2]byte
				ol[0], ol[1] = byte(len(resp)>>8), byte(len(resp))
				c.Write(ol[:])
				c.Write(resp)
			}(conn)
		}
	}()

	s := &DNSServer{cfg: &Config{Forwarders: []string{ln.Addr().String()}}}
	m := unpackReply(t, s.answerQuery("tcp", "127.0.0.1", true, rawQuery(t, "example.com.", dns.TypeA)))
	if m.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected relayed NOERROR, got rcode=%d", m.Rcode)
	}
	select {
	case <-gotTCP:
	default:
		t.Error("upstream did not receive the query over TCP")
	}
	_ = time.Second
}

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
	"encoding/binary"
	"io"
	"net"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/miekg/dns"

	"dns/wire"
)

// TestServeRealSocket drives the REAL listeners (self-managed UDP + TCP from
// ListenAndServe) end-to-end: a UDP stream-domain query, a UDP sandfs-zone
// query, and a TCP forwarded query must all round-trip through actual sockets.
// The reply bytes are unpacked with miekg (differential, as everywhere).
func TestServeRealSocket(t *testing.T) {
	s := healthyServer()
	s.cfg.ListenAddr = "127.0.0.1:0" // ephemeral

	errCh := make(chan error, 1)
	go func() { errCh <- s.ListenAndServe() }()
	defer s.Close()

	// Wait for the listeners to be bound.
	var udpAddr *net.UDPAddr
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		s.mu.RLock()
		uc := s.udpConn
		s.mu.RUnlock()
		if uc != nil {
			udpAddr = uc.LocalAddr().(*net.UDPAddr)
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if udpAddr == nil {
		t.Fatal("UDP listener never bound")
	}

	udpRoundTrip := func(name string, qtype uint16) *dns.Msg {
		t.Helper()
		c, err := net.DialUDP("udp", nil, udpAddr)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := c.Write(rawQuery(t, name, qtype)); err != nil {
			t.Fatalf("udp write %q: %v", name, err)
		}
		buf := make([]byte, 65535)
		n, err := c.Read(buf)
		if err != nil {
			t.Fatalf("udp read %q: %v", name, err)
		}
		return unpackReply(t, buf[:n])
	}

	// 1. Stream domain over UDP → sticky placement answer (A record).
	m := udpRoundTrip("stream.sandswap.local.", dns.TypeA)
	if m.Rcode != dns.RcodeSuccess || len(m.Answer) != 1 {
		t.Fatalf("stream query: rcode=%d answers=%v", m.Rcode, m.Answer)
	}
	if a, ok := m.Answer[0].(*dns.A); !ok || !a.A.Equal(net.ParseIP("10.0.1.1")) {
		t.Errorf("stream answer = %v, want A 10.0.1.1", m.Answer[0])
	}
	// The placement created a sticky entry for our source IP.
	s.mu.RLock()
	_, sticky := s.sticky["127.0.0.1"]
	s.mu.RUnlock()
	if !sticky {
		t.Error("stream placement over the real socket should create a sticky entry")
	}

	// 2. Sandfs zone over UDP: no owner + healthy fallback → fallback A.
	m = udpRoundTrip("sandfs-abc123.sandfs.sandswap.local.", dns.TypeA)
	if m.Rcode != dns.RcodeSuccess || len(m.Answer) != 1 {
		t.Fatalf("sandfs query: rcode=%d answers=%v", m.Rcode, m.Answer)
	}
	if a, ok := m.Answer[0].(*dns.A); !ok || !a.A.Equal(net.ParseIP("10.0.1.1")) {
		t.Errorf("sandfs fallback answer = %v, want A 10.0.1.1", m.Answer[0])
	}

	// 3. UDP forwarded query from the host: the dedicated loopback socket
	// must classify the datagram as loopback-originated (IP_PKTINFO ingress)
	// and relay it upstream.
	udpAddr2, stopUDP := startStubDNS(t, stubAHandler())
	defer stopUDP()
	s.cfg.Forwarders = []string{udpAddr2}
	m = udpRoundTrip("example.com.", dns.TypeA)
	if m.Rcode != dns.RcodeSuccess || len(m.Answer) != 1 {
		t.Fatalf("udp forwarded query: rcode=%d answers=%v", m.Rcode, m.Answer)
	}
	if a, ok := m.Answer[0].(*dns.A); !ok || !a.A.Equal(net.ParseIP("9.9.9.9")) {
		t.Errorf("udp forwarded answer = %v, want A 9.9.9.9", m.Answer[0])
	}

	// 4. TCP forwarded query: TCP stub upstream answers, reply relayed framed.
	addr, stop := startStubDNSTCP(t, stubAHandler())
	defer stop()
	s.cfg.Forwarders = []string{addr}

	s.mu.RLock()
	tcpLn := s.tcpLn
	s.mu.RUnlock()
	if tcpLn == nil {
		t.Fatal("TCP listener never bound")
	}
	conn, err := net.DialTCP("tcp", nil, tcpLn.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	q := rawQuery(t, "example.com.", dns.TypeA)
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(q)))
	if _, err := conn.Write(append(l[:], q...)); err != nil {
		t.Fatal(err)
	}
	var rl [2]byte
	if _, err := readFull(conn, rl[:]); err != nil {
		t.Fatalf("tcp read reply length: %v", err)
	}
	reply := make([]byte, binary.BigEndian.Uint16(rl[:]))
	if _, err := readFull(conn, reply); err != nil {
		t.Fatalf("tcp read reply: %v", err)
	}
	m = unpackReply(t, reply)
	if m.Rcode != dns.RcodeSuccess || len(m.Answer) != 1 {
		t.Fatalf("tcp forwarded query: rcode=%d answers=%v", m.Rcode, m.Answer)
	}
	if a, ok := m.Answer[0].(*dns.A); !ok || !a.A.Equal(net.ParseIP("9.9.9.9")) {
		t.Errorf("forwarded answer = %v, want A 9.9.9.9", m.Answer[0])
	}

	select {
	case err := <-errCh:
		if err != nil && !strings.Contains(err.Error(), "closed") && !strings.Contains(err.Error(), "EOF") {
			t.Errorf("unexpected listener error: %v", err)
		}
	default:
	}
}

// TestServeTCPConnCap verifies the TCP connection bound: with maxTCPConns=1 a
// second concurrent connection is refused (closed immediately) while the
// first still holds its slot — without the cap, idle conns (one goroutine
// each, up to tcpIdleTimeout) would grow memory without limit under a
// slowloris-style connection flood.
func TestServeTCPConnCap(t *testing.T) {
	orig := maxTCPConns
	maxTCPConns = 1
	defer func() { maxTCPConns = orig }()

	s := healthyServer()
	s.cfg.ListenAddr = "127.0.0.1:0"

	errCh := make(chan error, 1)
	go func() { errCh <- s.ListenAndServe() }()
	defer s.Close()

	deadline := time.Now().Add(3 * time.Second)
	var ln net.Listener
	for time.Now().Before(deadline) {
		s.mu.RLock()
		ln = s.tcpLn
		s.mu.RUnlock()
		if ln != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if ln == nil {
		t.Fatal("TCP listener never bound")
	}

	// First connection holds the single slot (idle up to tcpIdleTimeout).
	c1, err := net.DialTCP("tcp", nil, ln.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer c1.Close()

	// Second connection is accepted then immediately closed: the read must see
	// EOF AT ONCE — without the cap it would instead hang until the read
	// deadline (the conn sits in readTCPFrame until the 30s idle timeout),
	// which is exactly the unbounded-hold behavior the cap prevents.
	c2, err := net.DialTCP("tcp", nil, ln.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	c2.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 64)
	n, err := c2.Read(buf)
	if err != io.EOF {
		t.Errorf("second conn should be closed immediately (io.EOF), got n=%d err=%v", n, err)
	}
}

// TestServfailForShortPacket pins the saturation-path guard: serveUDP answers
// an over-capacity query with servfailFor(pkt) using the client's raw bytes,
// and UDP delivers 0/1-byte datagrams. Without the length guard the ID echo
// panics the whole DNS process (no recover in this program) — exactly when the
// server is already under the abuse load the cap exists for. formerrFor and
// notimpFor carry the same guard.
func TestServfailForShortPacket(t *testing.T) {
	s := &DNSServer{}
	for _, pkt := range [][]byte{{}, {0x12}, {0x12, 0x34}} {
		got := s.servfailFor(pkt)
		if len(got) < 12 {
			t.Fatalf("servfailFor(%v): reply shorter than a DNS header (%d bytes)", pkt, len(got))
		}
		if got[2]&0x80 == 0 {
			t.Errorf("servfailFor(%v): QR bit not set", pkt)
		}
	}
	// The ID echo still works when it can (2-byte packet).
	if got := s.servfailFor([]byte{0xAB, 0xCD}); got[0] != 0xAB || got[1] != 0xCD {
		t.Errorf("servfailFor: ID not echoed, got %x %x", got[0], got[1])
	}
}

// A guest-sourced query must not use the control-plane resolver as an open
// recursive resolver: foreign zones are REFUSED for guest ranges, while host
// sources keep the upstream relay and sandswap-zone lookups still work for
// guests.
func TestGuestSourcesCannotRelayForeignZones(t *testing.T) {
	s := healthyServer()
	_, guestNet, err := net.ParseCIDR("10.188.0.0/16")
	if err != nil {
		t.Fatal(err)
	}
	s.guestNets = []*net.IPNet{guestNet}
	// Host management range allowed to forward (the ACL is explicit since the
	// open-resolver fix; loopback alone is the shipped default).
	_, hostNet, err := net.ParseCIDR("10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	s.recursiveNets = []*net.IPNet{hostNet}

	foreign := new(dns.Msg)
	foreign.SetQuestion("example.com.", dns.TypeA)
	pkt, err := foreign.Pack()
	if err != nil {
		t.Fatal(err)
	}
	assertRcode := func(remote string, q []byte, want int, label string) {
		t.Helper()
		reply := s.answerQuery("udp", remote, false, q)
		var out dns.Msg
		if err := out.Unpack(reply); err != nil {
			t.Fatalf("%s: unpack: %v", label, err)
		}
		if out.Rcode != want {
			t.Fatalf("%s: rcode = %d, want %d", label, out.Rcode, want)
		}
	}
	assertRcode("10.188.0.7", pkt, dns.RcodeRefused, "guest foreign zone")
	// Control: a host source is not gated — it falls through to the (empty)
	// forwarder set and answers SERVFAIL.
	assertRcode("10.0.0.5", pkt, dns.RcodeServerFailure, "host foreign zone")

	// The sandswap zones are control-plane topology: a guest source gets
	// NXDOMAIN for the sandfs zone (whoever owns the ID — the answer reveals
	// nothing) and REFUSED for the stream/agent zones, while the same queries
	// from a host source keep their normal answers (below).
	zone := new(dns.Msg)
	zone.SetQuestion("sandfs-abc123.sandfs.sandswap.local.", dns.TypeA)
	zpkt, err := zone.Pack()
	if err != nil {
		t.Fatal(err)
	}
	assertRcode("10.188.0.7", zpkt, dns.RcodeNameError, "guest sandfs zone")

	stream := new(dns.Msg)
	stream.SetQuestion("stream.sandswap.local.", dns.TypeA)
	spkt, err := stream.Pack()
	if err != nil {
		t.Fatal(err)
	}
	assertRcode("10.188.0.7", spkt, dns.RcodeRefused, "guest stream zone")

	// Non-guest behavior is unchanged: the host source still gets the sandfs
	// and stream answers it always did.
	reply := s.answerQuery("udp", "10.0.0.5", false, zpkt)
	var out dns.Msg
	if err := out.Unpack(reply); err != nil {
		t.Fatalf("host sandfs zone: unpack: %v", err)
	}
	if out.Rcode != dns.RcodeSuccess || len(out.Answer) != 1 {
		t.Fatalf("host sandfs zone: rcode=%d answers=%v, want NOERROR with the scheduling fallback", out.Rcode, out.Answer)
	}
	reply = s.answerQuery("udp", "10.0.0.5", false, spkt)
	if err := out.Unpack(reply); err != nil {
		t.Fatalf("host stream zone: unpack: %v", err)
	}
	if out.Rcode != dns.RcodeSuccess {
		t.Fatalf("host stream zone: rcode=%d, want NOERROR", out.Rcode)
	}
}

// The recursive-forward ACL is explicit: loopback only by default, every other
// source (including a forged UDP source) is refused — and a loopback SOURCE is
// trusted only when the packet also arrived over a loopback-address socket.
func TestRecursiveACLLoopbackOnlyByDefault(t *testing.T) {
	_, v4, _ := net.ParseCIDR("127.0.0.1/32")
	_, v6, _ := net.ParseCIDR("::1/128")
	s := &DNSServer{recursiveNets: []*net.IPNet{v4, v6}}
	for _, ip := range []string{"127.0.0.1", "::1"} {
		if !s.recursiveAllowed(ip, true) {
			t.Errorf("%s on a loopback ingress should be allowed to forward", ip)
		}
		// route_localnet spoof shape: loopback source address that arrived on
		// the wildcard listener is NOT a local client.
		if s.recursiveAllowed(ip, false) {
			t.Errorf("%s with a non-loopback ingress must not be allowed to forward", ip)
		}
	}
	for _, ip := range []string{"8.8.8.8", "10.1.2.3", "not-an-ip", ""} {
		if s.recursiveAllowed(ip, false) || s.recursiveAllowed(ip, true) {
			t.Errorf("%q must not be allowed to forward", ip)
		}
	}
}

// The zero-value server (no configured ACL) keeps its defensive loopback-only
// default, and that default follows the same ingress rule.
func TestRecursiveACLZeroValueLoopbackIngress(t *testing.T) {
	s := &DNSServer{}
	if !s.recursiveAllowed("127.0.0.1", true) {
		t.Error("zero-value server: loopback on loopback ingress should forward")
	}
	if s.recursiveAllowed("127.0.0.1", false) {
		t.Error("zero-value server: loopback source on a wildcard ingress must be refused")
	}
}

// An oversized forwarded UDP answer is truncated with TC=1 so the client
// retries over TCP. The truncated message keeps the QUESTION section (a
// header-only reply cannot be matched to the query) and clears the answer
// counts; small answers pass through unchanged.
func TestTruncateForwardedUDP(t *testing.T) {
	query := rawQuery(t, "example.com", dns.TypeA)
	questionEnd := len(query)
	big := append(append([]byte(nil), query...), make([]byte, 1400)...)
	big[2] |= 0x80 // QR
	big[7] = 3     // ANCOUNT: a body exists and must be stripped
	out := truncateForwardedUDP(big, udpClassicMax)
	if len(out) != questionEnd {
		t.Fatalf("truncated len = %d, want header+question %d", len(out), questionEnd)
	}
	if out[2]&0x02 == 0 {
		t.Fatal("TC bit not set on a truncated UDP answer")
	}
	// The question must be byte-identical to the query's.
	if string(out[wire.HeaderLen:]) != string(query[wire.HeaderLen:]) {
		t.Fatal("truncated answer dropped or altered the question section")
	}
	for i := 6; i < 12; i++ {
		if out[i] != 0 {
			t.Fatalf("AN/NS/AR count byte %d = %d, want 0", i, out[i])
		}
	}
	// QDCOUNT still describes the echoed question.
	if out[4] != 0 || out[5] != 1 {
		t.Fatalf("QDCOUNT = %d, want 1", int(out[4])<<8|int(out[5]))
	}

	// A larger advertised EDNS buffer admits the answer unchanged.
	if got := truncateForwardedUDP(big, forwardedUDPLimit(4096)); len(got) != len(big) {
		t.Fatalf("answer within the advertised limit was truncated: %d < %d", len(got), len(big))
	}

	small := append(append([]byte(nil), query...), make([]byte, 100)...)
	small[0] = 0x12
	if got := truncateForwardedUDP(small, udpClassicMax); len(got) != len(small) || got[0] != 0x12 {
		t.Fatal("small UDP answer must pass through unchanged")
	}

	// A response whose question cannot be parsed (a compression pointer in the
	// first question is never valid) degrades to a bare header.
	unparseable := make([]byte, wire.HeaderLen+600)
	unparseable[2] = 0x80
	unparseable[4], unparseable[5] = 0, 1 // QDCOUNT
	unparseable[wire.HeaderLen] = 0xC0    // pointer with no prior name
	unparseable[wire.HeaderLen+1] = 0x0C
	if got := truncateForwardedUDP(unparseable, udpClassicMax); len(got) != wire.HeaderLen {
		t.Fatalf("unparseable-question truncation len = %d, want %d", len(got), wire.HeaderLen)
	}
}

// forwardedUDPLimit floors at the classic 512, honors the client's advertised
// EDNS size, and caps the server ceiling.
func TestForwardedUDPLimit(t *testing.T) {
	cases := []struct{ advertised, want int }{
		{0, udpClassicMax},
		{1232, 1232},
		{65535, maxForwardedUDPSize},
	}
	for _, c := range cases {
		if got := forwardedUDPLimit(c.advertised); got != c.want {
			t.Errorf("forwardedUDPLimit(%d) = %d, want %d", c.advertised, got, c.want)
		}
	}
}

// stickyKey adds the cookie discriminator only when one is present.
func TestStickyKeyCookie(t *testing.T) {
	if got := stickyKey("10.0.0.5", nil); got != "10.0.0.5" {
		t.Fatalf("stickyKey without cookie = %q", got)
	}
	if got := stickyKey("10.0.0.5", []byte{1, 2, 3, 4, 5, 6, 7, 8}); got != "10.0.0.5|0102030405060708" {
		t.Fatalf("stickyKey with cookie = %q", got)
	}
}

// TestPKTInfoIfIndex pins the control-message parse the loopback-ingress
// check depends on: in_pktinfo carries the receiving interface index in its
// first 4 bytes (host byte order); an unparseable/foreign cmsg yields false
// so the caller fails closed.
func TestPKTInfoIfIndex(t *testing.T) {
	buf := make([]byte, syscall.CmsgSpace(4))
	binary.NativeEndian.PutUint64(buf[0:8], uint64(syscall.CmsgLen(4)))
	binary.NativeEndian.PutUint32(buf[8:12], uint32(syscall.IPPROTO_IP))
	binary.NativeEndian.PutUint32(buf[12:16], uint32(syscall.IP_PKTINFO))
	binary.NativeEndian.PutUint32(buf[16:20], 7)
	if idx, ok := pktinfoIfIndex(buf); !ok || idx != 7 {
		t.Fatalf("pktinfoIfIndex = (%d,%v), want (7,true)", idx, ok)
	}
	if _, ok := pktinfoIfIndex(nil); ok {
		t.Error("empty oob must not yield an interface index")
	}
	// Binding-only ingress: a loopback socket without pktinfo trusts the
	// binding; a wildcard socket never counts as loopback.
	if !(udpIngress{loopback: true}).loopbackOriginated(nil) {
		t.Error("loopback socket without pktinfo should trust its binding")
	}
	if (udpIngress{}).loopbackOriginated(nil) {
		t.Error("wildcard socket must never count as loopback ingress")
	}
}

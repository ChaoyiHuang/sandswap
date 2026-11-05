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

package wire

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// The tests in this file are DIFFERENTIAL: miekg/dns (the implementation this
// package replaces) is the reference. Queries are packed by miekg and parsed
// by us; replies are built by us and unpacked by miekg. Agreement on both
// directions is the equivalence evidence for the batch-5 switchover.

// miekgQuery packs a one-question query via the reference implementation.
// The Id is set AFTER SetQuestion (miekg randomizes it there).
func miekgQuery(t *testing.T, name string, qtype uint16, id uint16) []byte {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.Id = id
	m.RecursionDesired = true
	wire, err := m.Pack()
	if err != nil {
		t.Fatalf("miekg pack: %v", err)
	}
	return wire
}

func TestParseQueryDifferential(t *testing.T) {
	cases := []struct {
		name     string
		qname    string
		qtype    uint16
		wantName string // lowercase presentation
	}{
		{"simple A", "sandswap-stream.local", dns.TypeA, "sandswap-stream.local"},
		{"per-sandfs", "sandfs-3fa9c2e1.sandfs.sandswap.local", dns.TypeA, "sandfs-3fa9c2e1.sandfs.sandswap.local"},
		{"mixed case 0x0x0", "SaNdFs-AbC.SaNdFs.SandSwap.Local", dns.TypeAAAA, "sandfs-abc.sandfs.sandswap.local"},
		{"SRV", "sandswap-stream.local", dns.TypeSRV, "sandswap-stream.local"},
		{"root", ".", dns.TypeA, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			raw := miekgQuery(t, c.qname, c.qtype, 0x4242)
			q, err := ParseQuery(raw)
			if err != nil {
				t.Fatalf("ParseQuery: %v", err)
			}
			if q.ID != 0x4242 {
				t.Errorf("ID = %#x, want 0x4242", q.ID)
			}
			if q.Name() != c.wantName {
				t.Errorf("Name() = %q, want %q", q.Name(), c.wantName)
			}
			if q.QType != c.qtype {
				t.Errorf("QType = %d, want %d", q.QType, c.qtype)
			}
			if q.QClass != dns.ClassINET {
				t.Errorf("QClass = %d, want INET", q.QClass)
			}
			if !q.RD {
				t.Error("RD should be echoed true")
			}
			if q.Opcode != 0 {
				t.Errorf("Opcode = %d, want 0", q.Opcode)
			}
		})
	}

	// EDNS OPT in additional must be tolerated (ignored after the question).
	m := new(dns.Msg)
	m.SetQuestion("sandswap-stream.local.", dns.TypeA)
	m.SetEdns0(1232, false)
	raw, err := m.Pack()
	if err != nil {
		t.Fatalf("miekg pack edns: %v", err)
	}
	if _, err := ParseQuery(raw); err != nil {
		t.Errorf("query with EDNS OPT must parse, got %v", err)
	}
}

func TestParseQueryMalformed(t *testing.T) {
	good := miekgQuery(t, "a.b.c", dns.TypeA, 1)

	cases := []struct {
		name string
		buf  []byte
		want error
	}{
		{"empty", nil, ErrShort},
		{"header only", good[:11], ErrShort},
		{"qr set", func() []byte { b := clone(good); b[2] |= 0x80; return b }(), ErrNotQuery},
		{"qdcount zero", func() []byte { b := clone(good); b[4], b[5] = 0, 0; return b }(), ErrNoQuestion},
		{"truncated qname", good[:14], ErrTruncated},
		{"truncated qtype", good[:len(good)-2], ErrTruncated},
		{"pointer in qname", func() []byte {
			b := clone(good)
			b[12] = 0xC0 // compression pointer
			b[13] = 0x0C
			return b
		}(), ErrPointer},
		{"oversized label", func() []byte {
			b := clone(good)
			b[12] = 64 // > 63
			return b
		}(), ErrBadLabel},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := ParseQuery(c.buf); err != c.want {
				t.Errorf("ParseQuery err = %v, want %v", err, c.want)
			}
		})
	}

	// 255-octet name boundary: a 4×63-label name (4*(63+1)+1 = 257) is rejected
	// while it is being parsed — never panics, never overreads. (Labels of 64
	// would hit the per-label bound first; 63 is legal per label.)
	long := make([]byte, 0, 512)
	long = append(long, make([]byte, headerLen)...)
	long[5] = 1 // QDCOUNT = 1
	for i := 0; i < 4; i++ {
		long = append(long, 63)
		for j := 0; j < 63; j++ {
			long = append(long, 'a')
		}
	}
	long = append(long, 0, 0, 1, 0, 1)
	if _, err := ParseQuery(long); err != ErrNameTooLong {
		t.Errorf("oversized name err = %v, want %v", err, ErrNameTooLong)
	}
}

// TestBuildReplyDifferential builds replies with wire and unpacks them with
// miekg: header flags, byte-identical question echo (case preserved), and RR
// contents must all agree with the reference implementation's view.
func TestBuildReplyDifferential(t *testing.T) {
	raw := miekgQuery(t, "SaNdFs-AbC.SaNdFs.SandSwap.Local", dns.TypeA, 0x1337)
	q, err := ParseQuery(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	// CNAME + A chain answers (the owner-branch shape).
	answers := []RR{
		{Type: TypeCNAME, Name: "gateway-0.gateway-exec.sandswap.svc.cluster.local"},
	}
	reply, err := BuildReply(q, RcodeSuccess, 10, answers)
	if err != nil {
		t.Fatalf("BuildReply: %v", err)
	}

	m := new(dns.Msg)
	if err := m.Unpack(reply); err != nil {
		t.Fatalf("miekg unpack of our reply: %v", err)
	}
	if m.Id != 0x1337 {
		t.Errorf("reply ID = %#x", m.Id)
	}
	if !m.Response || !m.Authoritative {
		t.Errorf("reply flags: QR=%v AA=%v", m.Response, m.Authoritative)
	}
	if !m.RecursionDesired {
		t.Error("RD must be echoed")
	}
	if m.Rcode != 0 {
		t.Errorf("Rcode = %d", m.Rcode)
	}
	// Question echo is byte-identical → the mixed-case name survives intact.
	if len(m.Question) != 1 || m.Question[0].Name != "SaNdFs-AbC.SaNdFs.SandSwap.Local." {
		t.Errorf("question echo case not preserved: %+v", m.Question)
	}
	if len(m.Answer) != 1 {
		t.Fatalf("answers = %d", len(m.Answer))
	}
	cn, ok := m.Answer[0].(*dns.CNAME)
	if !ok {
		t.Fatalf("answer type = %T", m.Answer[0])
	}
	if cn.Target != "gateway-0.gateway-exec.sandswap.svc.cluster.local." {
		t.Errorf("CNAME target = %q", cn.Target)
	}
	if cn.Hdr.Name != "SaNdFs-AbC.SaNdFs.SandSwap.Local." {
		t.Errorf("owner name case not preserved: %q", cn.Hdr.Name)
	}
	if cn.Hdr.Ttl != 10 {
		t.Errorf("TTL = %d, want 10", cn.Hdr.Ttl)
	}

	// A / AAAA / SRV / NXDOMAIN / SERVFAIL shapes.
	q2, _ := ParseQuery(miekgQuery(t, "x.sandswap-stream.local", dns.TypeA, 7))
	for i, tc := range []struct {
		answers []RR
		rcode   int
		check   func(*testing.T, *dns.Msg)
	}{
		{[]RR{{Type: TypeA, A: net.ParseIP("10.0.1.9")}}, RcodeSuccess, func(t *testing.T, m *dns.Msg) {
			a := m.Answer[0].(*dns.A)
			if !a.A.Equal(net.ParseIP("10.0.1.9")) {
				t.Errorf("A = %v", a.A)
			}
		}},
		{[]RR{{Type: TypeAAAA, A: net.ParseIP("2001:db8::1")}}, RcodeSuccess, func(t *testing.T, m *dns.Msg) {
			aaaa := m.Answer[0].(*dns.AAAA)
			if !aaaa.AAAA.Equal(net.ParseIP("2001:db8::1")) {
				t.Errorf("AAAA = %v", aaaa.AAAA)
			}
		}},
		{[]RR{{Type: TypeSRV, Name: "gw.sandswap.local", Prio: 10, Weight: 50, Port: 9998}}, RcodeSuccess, func(t *testing.T, m *dns.Msg) {
			srv := m.Answer[0].(*dns.SRV)
			if srv.Port != 9998 || srv.Target != "gw.sandswap.local." {
				t.Errorf("SRV = %+v", srv)
			}
		}},
		{nil, RcodeNameError, func(t *testing.T, m *dns.Msg) {
			if m.Rcode != dns.RcodeNameError {
				t.Errorf("NXDOMAIN rcode = %d", m.Rcode)
			}
		}},
		{nil, RcodeServerFailure, func(t *testing.T, m *dns.Msg) {
			if m.Rcode != dns.RcodeServerFailure {
				t.Errorf("SERVFAIL rcode = %d", m.Rcode)
			}
		}},
	} {
		reply, err := BuildReply(q2, tc.rcode, 10, tc.answers)
		if err != nil {
			t.Fatalf("case %d: BuildReply: %v", i, err)
		}
		m := new(dns.Msg)
		if err := m.Unpack(reply); err != nil {
			t.Fatalf("case %d: miekg unpack: %v", i, err)
		}
		tc.check(t, m)
	}
}

// TestBuildReplyGuardrails verifies the builder's own validation: an IPv6 in
// an A record (the exact footgun miekg's packDataA silently truncated to 4
// bytes) and an IPv4 in an AAAA record are hard errors here, as are
// malformed target names and oversized replies.
func TestBuildReplyGuardrails(t *testing.T) {
	q, _ := ParseQuery(miekgQuery(t, "a.sandswap.local", dns.TypeA, 1))

	if _, err := BuildReply(q, RcodeSuccess, 10, []RR{{Type: TypeA, A: net.ParseIP("2001:db8::1")}}); err == nil {
		t.Error("A record with IPv6 must be rejected (miekg packed its first 4 bytes)")
	}
	if _, err := BuildReply(q, RcodeSuccess, 10, []RR{{Type: TypeAAAA, A: net.ParseIP("10.0.1.9")}}); err == nil {
		t.Error("AAAA record with IPv4 must be rejected")
	}
	if _, err := BuildReply(q, RcodeSuccess, 10, []RR{{Type: TypeCNAME, Name: "bad name"}}); err == nil {
		t.Error("CNAME target with space must be rejected")
	}
	if _, err := BuildReply(q, RcodeSuccess, 10, []RR{{Type: TypeCNAME, Name: strings.Repeat("a", 64)}}); err == nil {
		t.Error("63+ byte label must be rejected")
	}
	// A very long CNAME target chain pushes the reply over 512 bytes: error,
	// never a silent truncation.
	long := strings.Repeat("aaaaaaaaaa.", 20) + "example.com"
	if _, err := BuildReply(q, RcodeSuccess, 10, []RR{{Type: TypeCNAME, Name: long}, {Type: TypeCNAME, Name: long}, {Type: TypeCNAME, Name: long}}); err == nil {
		t.Error("oversized reply must be rejected, not truncated")
	}
}

// fakeUpstream runs a loopback UDP/TCP DNS "resolver" that answers with the
// query bytes' ID set as a response (QR set) — enough to exercise Relay.
func fakeUpstream(t *testing.T, network string) (addr string, queryCh chan []byte) {
	t.Helper()
	queryCh = make(chan []byte, 4)
	if network == "udp" {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { pc.Close() })
		go func() {
			buf := make([]byte, 65535)
			for {
				n, from, err := pc.ReadFrom(buf)
				if err != nil {
					return
				}
				q := append([]byte(nil), buf[:n]...)
				queryCh <- q
				resp := clone(q)
				resp[2] |= 0x80 // QR
				pc.WriteTo(resp, from)
			}
		}()
		return pc.LocalAddr().String(), queryCh
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
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
				q := make([]byte, binary.BigEndian.Uint16(l[:]))
				if _, err := readFull(c, q); err != nil {
					return
				}
				queryCh <- q
				resp := clone(q)
				resp[2] |= 0x80
				var ol [2]byte
				binary.BigEndian.PutUint16(ol[:], uint16(len(resp)))
				c.Write(ol[:])
				c.Write(resp)
			}(conn)
		}
	}()
	return ln.Addr().String(), queryCh
}

func readFull(c net.Conn, b []byte) (int, error) {
	total := 0
	for total < len(b) {
		n, err := c.Read(b[total:])
		if err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}

func TestRelayUDPRoundTrip(t *testing.T) {
	addr, qch := fakeUpstream(t, "udp")
	query := miekgQuery(t, "example.com", dns.TypeA, 0x77)
	resp, err := Relay(context.Background(), "udp", addr, query, 2*time.Second)
	if err != nil {
		t.Fatalf("Relay udp: %v", err)
	}
	if !bytes.Equal(resp[:2], query[:2]) {
		t.Errorf("response ID mismatch")
	}
	if resp[2]&0x80 == 0 {
		t.Error("response QR not set")
	}
	select {
	case got := <-qch:
		if !bytes.Equal(got, query) {
			t.Error("upstream received modified query bytes")
		}
	default:
		t.Error("upstream did not receive the query")
	}
}

func TestRelayTCPRoundTrip(t *testing.T) {
	addr, qch := fakeUpstream(t, "tcp")
	query := miekgQuery(t, "example.com", dns.TypeA, 0x88)
	resp, err := Relay(context.Background(), "tcp", addr, query, 2*time.Second)
	if err != nil {
		t.Fatalf("Relay tcp: %v", err)
	}
	if !bytes.Equal(resp[:2], query[:2]) {
		t.Errorf("response ID mismatch")
	}
	select {
	case got := <-qch:
		if !bytes.Equal(got, query) {
			t.Error("upstream received modified query bytes (framing broken?)")
		}
	default:
		t.Error("upstream did not receive the query")
	}
}

func TestRelayRejectsSpoofedID(t *testing.T) {
	addr, _ := fakeUpstream(t, "udp")
	query := clone(miekgQuery(t, "example.com", dns.TypeA, 1))
	// Corrupt the ID AFTER the relay would... simulate by sending our own
	// datagram race: not deterministic. Instead verify the checker directly.
	bad := clone(query)
	bad[0] ^= 0xFF
	if err := checkID(query, bad); err == nil {
		t.Error("checkID must reject mismatched IDs")
	}
	resp := clone(query)
	resp[2] |= 0x80
	if err := checkID(query, resp); err != nil {
		t.Errorf("checkID rejected a valid response: %v", err)
	}
	_ = addr
}

func TestRelayUnsupportedNetwork(t *testing.T) {
	if _, err := Relay(context.Background(), "unix", "x", make([]byte, 12), time.Second); err == nil {
		t.Error("unsupported network must error")
	}
}

func clone(b []byte) []byte { return append([]byte(nil), b...) }

// EDNS(0) COOKIE is surfaced as the 8-byte client cookie; queries without one
// (or with a malformed OPT) parse with no cookie.
func TestParseQueryEDNSCookie(t *testing.T) {
	m := new(dns.Msg)
	m.SetQuestion("sandswap-stream.local.", dns.TypeA)
	m.SetEdns0(1232, false)
	opt := m.IsEdns0()
	opt.Option = append(opt.Option, &dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: "0011223344556677"})
	raw, err := m.Pack()
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	q, err := ParseQuery(raw)
	if err != nil {
		t.Fatalf("ParseQuery: %v", err)
	}
	if len(q.Cookie) != 8 || q.Cookie[0] != 0x00 || q.Cookie[7] != 0x77 {
		t.Fatalf("cookie = %x, want 0011223344556677", q.Cookie)
	}
	// The OPT CLASS is the sender's UDP payload size (RFC 6891).
	if q.UDPSize != 1232 {
		t.Fatalf("UDPSize = %d, want 1232", q.UDPSize)
	}

	// Without EDNS the classic 512-byte limit applies.
	plainNoEDNS := miekgQuery(t, "a.b", dns.TypeA, 1)
	pq0, err := ParseQuery(plainNoEDNS)
	if err != nil {
		t.Fatal(err)
	}
	if pq0.UDPSize != 512 {
		t.Fatalf("UDPSize without EDNS = %d, want 512", pq0.UDPSize)
	}

	// Plain EDNS without a cookie: tolerated, no cookie.
	plain := new(dns.Msg)
	plain.SetQuestion("a.b.", dns.TypeA)
	plain.SetEdns0(1232, false)
	praw, _ := plain.Pack()
	pq, err := ParseQuery(praw)
	if err != nil {
		t.Fatal(err)
	}
	if pq.Cookie != nil {
		t.Fatalf("cookie = %x, want nil", pq.Cookie)
	}
}

// TestCheckIDRejectsQuestionMismatch pins the anti-spoofing half of the relay
// check: matching ID and QR are not enough — the response must echo the
// queried name (case-insensitively), type and class, so an off-path spoofer
// must also know the NAME it is answering for.
func TestCheckIDRejectsQuestionMismatch(t *testing.T) {
	query := miekgQuery(t, "one.example", dns.TypeA, 0x4242)

	// A valid response: same question, QR set.
	ok := clone(query)
	ok[2] |= 0x80
	if err := checkID(query, ok); err != nil {
		t.Fatalf("checkID rejected a matching response: %v", err)
	}

	// Same ID, different name.
	other := miekgQuery(t, "two.example", dns.TypeA, 0x4242)
	other[2] |= 0x80
	if err := checkID(query, other); err == nil {
		t.Fatal("checkID accepted a response for a different name")
	}
	// Same ID and name, different qtype.
	wrongType := miekgQuery(t, "one.example", dns.TypeAAAA, 0x4242)
	wrongType[2] |= 0x80
	if err := checkID(query, wrongType); err == nil {
		t.Fatal("checkID accepted a response for a different qtype")
	}
	// Case randomization must not matter (0x0x0).
	cased := miekgQuery(t, "ONE.Example", dns.TypeA, 0x4242)
	cased[2] |= 0x80
	if err := checkID(query, cased); err != nil {
		t.Fatalf("checkID must compare names case-insensitively: %v", err)
	}
	// A response with no question at all cannot be matched.
	noQ := clone(ok)
	noQ[4], noQ[5] = 0, 0
	if err := checkID(query, noQ); err == nil {
		t.Fatal("checkID accepted a response with no echoed question")
	}
}

// TestQuestionEndAndMatch covers the truncation/matching parser primitive:
// it locates the question boundary and compares questions case-insensitively.
func TestQuestionEndAndMatch(t *testing.T) {
	query := miekgQuery(t, "sandfs-abc.sandfs.local", dns.TypeSRV, 7)
	end, ok := QuestionEnd(query)
	if !ok || end != len(query) {
		t.Fatalf("QuestionEnd = (%d, %v), want (%d, true)", end, ok, len(query))
	}
	if !QuestionsMatch(query, query) {
		t.Fatal("a message's own question must match")
	}
	if _, ok := QuestionEnd(query[:end-1]); ok {
		t.Fatal("QuestionEnd must reject a truncated question")
	}
	if QuestionsMatch(query, miekgQuery(t, "other.sandfs.local", dns.TypeSRV, 7)) {
		t.Fatal("different names must not match")
	}
	if QuestionsMatch(query, []byte{0, 1, 2}) {
		t.Fatal("a short message must not match")
	}
}

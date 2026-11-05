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
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"strings"
	"syscall"
	"time"

	"dns/wire"
)

// maxConcurrentQueries bounds in-flight query processing (UDP packets + TCP
// messages). Beyond the cap a UDP query gets an inline SERVFAIL (clients
// retry) instead of an unbounded goroutine per packet — the flood bound. The
// default is sized by Little's law for the large-fleet read rate: cache hits
// serve in microseconds (a ~100k QPS load needs single-digit concurrency), and
// etcd-miss traffic is separately bounded by ownerGetConcurrency — the slot
// demand here comes from etcd latency spikes, which 2048 absorbs to ~120ms of
// degradation at 16.7k Gets/s before failing honestly. Configurable via
// max_concurrent_queries (restart-required).
var maxConcurrentQueries = 2048

// forwardConcurrency bounds concurrent upstream forwards (foreign-zone relay).
// A dedicated budget, much smaller than the query budget: forwarding is
// best-effort (truncation fallback + incidental foreign queries) while its
// slots are held the longest (sequential upstream attempts, seconds each) —
// sharing the full budget would let a foreign-query flood starve the
// authoritative answers. 0 = unbounded. Configurable via forward_concurrency
// (restart-required).
var forwardConcurrency = 128

// maxTCPConns bounds concurrent TCP DNS connections: idle conns each hold a
// goroutine up to tcpIdleTimeout, and querySem only bounds in-flight
// PROCESSING, so without a conn cap a slowloris-style connection flood grows
// memory without limit. Beyond the cap the connection is closed immediately —
// UDP is the primary transport and TCP clients retry. Configurable via
// tcp_max_conns (restart-required).
var maxTCPConns = 256

// tcpIdleTimeout closes idle TCP DNS connections (RFC 1035 §4.2.2 suggests
// idle shutdown; also bounds conn-goroutine lifetime under slowloris holds).
const tcpIdleTimeout = 30 * time.Second

// relayTimeout bounds one upstream forward attempt.
const relayTimeout = 3 * time.Second

// ListenAndServe starts the UDP and TCP DNS listeners and returns on the
// first error from the SURVIVING transport. Bind semantics on port 53 are
// asymmetric: a wildcard UDP bind coexists with systemd-resolved's stub
// (127.0.0.53:53, default on Ubuntu) under SO_REUSEADDR, but a wildcard TCP
// bind does NOT — REUSEADDR cannot overlap wildcard-over-specific on TCP
// (both sides would need SO_REUSEPORT, which resolved does not set). TCP is
// therefore degraded to best-effort: its bind failure is logged as a loud
// warning and the server keeps serving UDP. This is a deliberate
// portability-over-purity trade: the pre-rewrite server effectively ran
// UDP-only on stub-hosts (its TCP goroutine swallowed the bind error
// silently); every normal query is UDP anyway, and TCP only carries
// large-response truncation fallback. UDP bind failure REMAINS fatal — a
// DNS that cannot answer must not come up half-dead. Called in a goroutine
// from main; errors surface via the error channel.
func (s *DNSServer) ListenAndServe() error {
	udpAddr, err := net.ResolveUDPAddr("udp", s.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("resolve udp %s: %w", s.cfg.ListenAddr, err)
	}

	// Ingress classification for the recursive ACL. A packet read on a socket
	// bound to a loopback address is a host-local candidate; a packet read on
	// the wildcard socket is not, whatever source address it claims
	// (net.ipv4.route_localnet=1 lets a remote sender present 127.0.0.1). The
	// configured listener is already loopback when listen_addr names one;
	// otherwise dedicated loopback sockets on the same port carry the
	// host-local traffic. The loopback sockets additionally enable
	// IP_PKTINFO/IPV6_RECVPKTINFO and require the datagram's INGRESS interface
	// to be `lo`, which also closes the destination-spoof variant (a packet
	// addressed 127.0.0.1 that actually arrived on a non-loopback interface).
	// TCP needs none of this: the accepted connection's LOCAL address is the
	// ingress address (a TCP handshake cannot be spoofed).
	mainIngress := udpIngress{loopback: udpAddr.IP.IsLoopback()}
	var uc *net.UDPConn
	if mainIngress.loopback {
		uc, mainIngress.pktinfo, err = listenUDPReuseAddrPktinfo(udpAddr)
	} else {
		uc, err = listenUDPReuseAddr(udpAddr)
	}
	if err != nil {
		return fmt.Errorf("UDP DNS on %s: %w", s.cfg.ListenAddr, err)
	}
	var loopUDPs []boundUDP
	if udpAddr.IP.IsUnspecified() {
		loopUDPs = s.listenLoopbackUDP(udpAddr.Port)
	}

	lc := net.ListenConfig{Control: reuseAddrControl}
	ln, err := lc.Listen(context.Background(), "tcp", s.cfg.ListenAddr)
	if err != nil {
		// TCP unavailable — degrade, do not die (see the doc comment above):
		// on default-Ubuntu hosts resolved's stub blocks this bind forever,
		// and a hard failure would make the DNS unstartable exactly where
		// UDP serving works. Keep serving; publish a nil tcpLn (Close and
		// the tests tolerate it).
		log.Printf("WARNING: TCP DNS on %s unavailable (%v) — serving UDP only; "+
			"large-response truncation fallback disabled. On hosts with "+
			"systemd-resolved's stub listening, free :53 via DNSStubListener=no "+
			"or bind a specific address.", s.cfg.ListenAddr, err)
		s.mu.Lock()
		s.udpConn = uc
		s.tcpLn = nil
		s.loopbackUDP = udpConnsOf(loopUDPs)
		s.mu.Unlock()

		if s.querySem == nil {
			s.querySem = make(chan struct{}, maxConcurrentQueries)
		}
		if s.forwardSem == nil && forwardConcurrency > 0 {
			s.forwardSem = make(chan struct{}, forwardConcurrency)
		}
		errCh := make(chan error, 1+len(loopUDPs))
		go s.serveUDP(uc, mainIngress, errCh)
		for _, lu := range loopUDPs {
			go s.serveUDP(lu.conn, lu.ing, errCh)
		}
		return <-errCh
	}

	// Publish the listeners under the lock (Close and tests read them).
	s.mu.Lock()
	s.udpConn = uc
	s.tcpLn = ln
	s.loopbackUDP = udpConnsOf(loopUDPs)
	s.mu.Unlock()

	if s.querySem == nil {
		s.querySem = make(chan struct{}, maxConcurrentQueries)
	}
	if s.forwardSem == nil && forwardConcurrency > 0 {
		s.forwardSem = make(chan struct{}, forwardConcurrency)
	}

	errCh := make(chan error, 2+len(loopUDPs)) // buffered: every side must not leak
	go s.serveUDP(uc, mainIngress, errCh)
	for _, lu := range loopUDPs {
		go s.serveUDP(lu.conn, lu.ing, errCh)
	}
	go s.serveTCP(ln, errCh)
	return <-errCh
}

// listenLoopbackUDP binds the dedicated host-local UDP sockets for a wildcard
// listen address. SO_REUSEADDR is set on both the wildcard and the specific
// bind, which is what lets the kernel deliver 127.0.0.1/::1 datagrams to the
// specific socket and everything else to the wildcard one — the ingress signal
// the recursive ACL needs. A failed bind is a loud WARNING, not a startup
// failure: the affected queries (host-local forwarder use) fail CLOSED
// (REFUSED on the wildcard ingress) while the sandswap zones keep serving.
func (s *DNSServer) listenLoopbackUDP(port int) []boundUDP {
	addrs := []net.IP{net.IPv4(127, 0, 0, 1)}
	if s.cfg.ListenAddr != "" {
		if ua, err := net.ResolveUDPAddr("udp", s.cfg.ListenAddr); err == nil && ua.IP.To4() == nil {
			// A dual-stack wildcard ("[::]:53") also carries IPv4 loopback
			// traffic, so bind both families.
			addrs = append(addrs, net.IPv6loopback)
		}
	}
	var conns []boundUDP
	for _, ip := range addrs {
		c, pktinfo, err := listenUDPReuseAddrPktinfo(&net.UDPAddr{IP: ip, Port: port})
		if err != nil {
			log.Printf("WARNING: loopback UDP DNS on %s:%d unavailable (%v) — host-local foreign-zone queries through that address are REFUSED (loopback sources are only trusted on a loopback-address socket); sandswap zones are unaffected",
				ip, port, err)
			continue
		}
		conns = append(conns, boundUDP{conn: c, ing: udpIngress{loopback: true, pktinfo: pktinfo}})
	}
	return conns
}

// boundUDP couples one bound socket with its ingress classification. pktinfo
// reflects whether the control message could actually be enabled on THIS
// socket — claiming it when the option failed would fail every host-local
// query closed instead of falling back to the binding signal.
type boundUDP struct {
	conn *net.UDPConn
	ing  udpIngress
}

func udpConnsOf(bs []boundUDP) []*net.UDPConn {
	out := make([]*net.UDPConn, 0, len(bs))
	for _, b := range bs {
		out = append(out, b.conn)
	}
	return out
}

// udpIngress carries the transport facts the recursive ACL uses to judge a
// datagram's origin. loopback means the socket is bound to a loopback
// address; pktinfo means per-datagram destination/interface control messages
// are available (so the packet's actual ingress interface can be checked).
type udpIngress struct {
	loopback bool
	pktinfo  bool
}

// loopbackOriginated reports whether this datagram provably came from the
// host itself. With pktinfo available the datagram's INGRESS INTERFACE must
// be `lo` — this rejects both a spoofed loopback SOURCE (route_localnet) and
// a spoofed loopback DESTINATION that actually arrived on another interface.
// Without pktinfo the socket binding is the best available signal (the
// dedicated-listener contract, logged as a warning at bind time).
func (ing udpIngress) loopbackOriginated(oob []byte) bool {
	if !ing.loopback {
		return false
	}
	if !ing.pktinfo || loopbackIfIndex == 0 {
		return true
	}
	idx, ok := pktinfoIfIndex(oob)
	if !ok {
		return false // control data unreadable: fail closed
	}
	return idx == loopbackIfIndex
}

// loopbackIfIndex is the `lo` interface index, resolved once. 0 = the
// interface could not be resolved; the ingress check then falls back to the
// socket-binding signal.
var loopbackIfIndex = func() int {
	ifi, err := net.InterfaceByName("lo")
	if err != nil {
		return 0
	}
	return ifi.Index
}()

// pktinfoIfIndex extracts the receiving interface index from the control
// messages of one datagram: IP_PKTINFO (IPv4 sockets) or IPV6_PKTINFO
// (IPv6/dual-stack sockets; IPv4-mapped traffic reports the same ingress
// interface). The ifindex is the first 4 bytes of in_pktinfo and the 4 bytes
// after the 16-byte address in in6_pktinfo, in host byte order.
func pktinfoIfIndex(oob []byte) (int, bool) {
	if len(oob) == 0 {
		return 0, false
	}
	cmsgs, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return 0, false
	}
	for _, m := range cmsgs {
		switch {
		case m.Header.Level == syscall.IPPROTO_IP && m.Header.Type == syscall.IP_PKTINFO && len(m.Data) >= 4:
			return int(binary.NativeEndian.Uint32(m.Data[0:4])), true
		case m.Header.Level == syscall.IPPROTO_IPV6 && m.Header.Type == syscall.IPV6_PKTINFO && len(m.Data) >= 20:
			return int(binary.NativeEndian.Uint32(m.Data[16:20])), true
		}
	}
	return 0, false
}

// Close shuts down the listeners and the etcd client.
func (s *DNSServer) Close() {
	s.mu.Lock()
	uc, ln, loops := s.udpConn, s.tcpLn, s.loopbackUDP
	s.udpConn, s.tcpLn, s.loopbackUDP = nil, nil, nil
	s.mu.Unlock()
	if uc != nil {
		uc.Close()
	}
	for _, c := range loops {
		c.Close()
	}
	if ln != nil {
		ln.Close()
	}
	if s.etcdClient != nil {
		s.etcdClient.Close()
	}
}

// ── transport loops ────────────────────────────────────────────────────

func (s *DNSServer) serveUDP(conn *net.UDPConn, ing udpIngress, errCh chan<- error) {
	buf := make([]byte, 65535)
	oob := make([]byte, 128)
	for {
		var (
			n        int
			raddr    *net.UDPAddr
			err      error
			loopback bool
		)
		if ing.pktinfo {
			var oobn int
			n, oobn, _, raddr, err = conn.ReadMsgUDP(buf, oob)
			if err == nil {
				loopback = ing.loopbackOriginated(oob[:oobn])
			}
		} else {
			n, raddr, err = conn.ReadFromUDP(buf)
			loopback = ing.loopback
		}
		if err != nil {
			errCh <- fmt.Errorf("UDP DNS read: %w", err)
			return
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		select {
		case s.querySem <- struct{}{}:
			go func() {
				defer func() { <-s.querySem }()
				reply := s.answerQuery("udp", raddr.IP.String(), loopback, pkt)
				conn.WriteToUDP(reply, raddr)
			}()
		default:
			// Saturated: answer SERVFAIL inline rather than silently dropping
			// (UDP DNS clients treat SERVFAIL as retry-able; silence costs a
			// full client timeout).
			conn.WriteToUDP(s.servfailFor(pkt), raddr)
		}
	}
}

func (s *DNSServer) serveTCP(ln net.Listener, errCh chan<- error) {
	// Connection cap (slowloris bound): idle conns hold a goroutine each, so
	// an unbounded accept grows memory without limit; beyond the cap the
	// connection is closed immediately (UDP is the primary transport).
	sem := make(chan struct{}, maxTCPConns)
	for {
		conn, err := ln.Accept()
		if err != nil {
			errCh <- fmt.Errorf("TCP DNS accept: %w", err)
			return
		}
		select {
		case sem <- struct{}{}:
			go func() {
				defer func() { <-sem }()
				s.serveTCPConn(conn)
			}()
		default:
			conn.Close() // at the conn cap: refuse rather than grow unbounded
		}
	}
}

// serveTCPConn serves length-framed queries on one TCP connection
// (pipelining allowed; idle timeout bounds the connection's lifetime).
func (s *DNSServer) serveTCPConn(conn net.Conn) {
	defer conn.Close()
	remoteIP := tcpRemoteIP(conn)
	// The accepted connection's LOCAL address is its ingress: a client that
	// reached a loopback address connected from this host (a TCP handshake
	// cannot be carried out with a spoofed source).
	loopbackIngress := tcpLocalIsLoopback(conn)
	for {
		conn.SetReadDeadline(time.Now().Add(tcpIdleTimeout))
		pkt, err := readTCPFrame(conn)
		if err != nil {
			return // idle timeout / peer close / malformed framing
		}
		select {
		case s.querySem <- struct{}{}:
			func() {
				defer func() { <-s.querySem }()
				reply := s.answerQuery("tcp", remoteIP, loopbackIngress, pkt)
				conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
				if err := writeTCPFrame(conn, reply); err != nil {
					log.Printf("dns: tcp reply write: %v", err)
				}
			}()
		default:
			conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			writeTCPFrame(conn, s.servfailFor(pkt))
		}
	}
}

// isGuestSource reports whether remoteIP belongs to a configured sandbox
// guest range. An unparseable address is NOT a guest: the UDP/TCP paths always
// carry a peer IP, and failing toward "relay" would silently disable the
// refusal for a malformed source.
func (s *DNSServer) isGuestSource(remoteIP string) bool {
	if len(s.guestNets) == 0 {
		return false
	}
	ip := net.ParseIP(remoteIP)
	if ip == nil {
		return false
	}
	for _, n := range s.guestNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// recursiveAllowed reports whether a non-guest source may forward foreign
// zones (config.recursive_acl; empty = none, fail closed). loopbackIngress is
// the transport's own ingress classification (a listen socket bound to a
// loopback address, or a TCP connection accepted on one): a loopback SOURCE
// address alone is not proof of local origin — with net.ipv4.route_localnet=1
// a remote sender can present 127.0.0.1 to a wildcard listener — so the
// loopback ACL entry only applies when the packet actually arrived over a
// loopback-address socket.
func (s *DNSServer) recursiveAllowed(remoteIP string, loopbackIngress bool) bool {
	ip := net.ParseIP(remoteIP)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() && !loopbackIngress {
		return false
	}
	if len(s.recursiveNets) == 0 {
		// Defensive default matching config.Defaults(): loopback only. A
		// zero-value server must not become an open recursive resolver.
		return ip.IsLoopback()
	}
	for _, n := range s.recursiveNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// udpClassicMax is the RFC 1035 UDP payload limit. A forwarded answer larger
// than the client's advertised limit is truncated with TC=1 so the client
// retries over TCP; without the bound a large upstream response is relayed at
// full size to a (possibly spoofed) UDP source.
const udpClassicMax = 512

// maxForwardedUDPSize caps a relayed UDP answer even when the client advertises
// a larger EDNS buffer: forwarded control-plane answers are small, and the cap
// keeps a spoofed source's amplification bounded.
const maxForwardedUDPSize = 4096

// forwardedUDPLimit turns the client's advertised EDNS payload size into the
// ceiling for a relayed UDP answer: never below the classic 512, never above
// maxForwardedUDPSize.
func forwardedUDPLimit(advertised int) int {
	switch {
	case advertised < udpClassicMax:
		return udpClassicMax
	case advertised > maxForwardedUDPSize:
		return maxForwardedUDPSize
	default:
		return advertised
	}
}

// truncateForwardedUDP sets TC and strips the ANSWER body of an oversized
// forwarded UDP answer, keeping the header and the question section. Keeping
// the question is what makes the reply matchable: a client that receives a
// header-only message cannot associate it with its query (and the question is
// what our own response/question check compares). The AN/NS/AR counts are
// cleared so the body length is not implied; QDCOUNT still describes the one
// echoed question.
func truncateForwardedUDP(resp []byte, limit int) []byte {
	if limit < udpClassicMax {
		limit = udpClassicMax
	}
	if len(resp) <= limit || len(resp) < wire.HeaderLen {
		return resp
	}
	// Preferred shape: header + the one question we keep. QDCOUNT is pinned to
	// 1: an upstream claiming several questions would otherwise leave a count
	// the truncated section does not satisfy.
	if end, ok := wire.QuestionEnd(resp); ok && end >= wire.HeaderLen && end <= len(resp) {
		out := make([]byte, end)
		copy(out, resp[:end])
		out[2] |= 0x02 // TC
		out[4], out[5] = 0, 1
		for i := 6; i < 12; i++ {
			out[i] = 0 // AN/NS/AR
		}
		return out
	}
	// Unparseable question: degrade to a bare header, with QDCOUNT cleared too
	// (there is no question section in the output).
	out := make([]byte, wire.HeaderLen)
	copy(out, resp[:wire.HeaderLen])
	out[2] |= 0x02 // TC
	for i := 4; i < 12; i++ {
		out[i] = 0
	}
	return out
}

// stickyKey binds stream-gateway affinity to the source IP and, when present,
// the client's EDNS COOKIE. A UDP source spoofer cannot guess the victim
// resolver's random 8-byte client cookie, so it cannot overwrite the victim's
// sticky entry; cookie-less clients keep the source-IP key.
func stickyKey(remoteIP string, cookie []byte) string {
	if len(cookie) >= 8 {
		return remoteIP + "|" + hex.EncodeToString(cookie[:8])
	}
	return remoteIP
}

func tcpRemoteIP(conn net.Conn) string {
	if ta, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		return ta.IP.String()
	}
	return ""
}

// tcpLocalIsLoopback reports whether a TCP connection was accepted on a
// loopback address (the ingress signal for the recursive ACL).
func tcpLocalIsLoopback(conn net.Conn) bool {
	if ta, ok := conn.LocalAddr().(*net.TCPAddr); ok {
		return ta.IP.IsLoopback()
	}
	return false
}

// ── query dispatch (transport-agnostic, byte level) ─────────────────────

// answerQuery processes one raw DNS query and returns the raw reply. It is a
// pure function of (transport, client IP, ingress, bytes) — the test surface
// for the whole dispatch layer. Classification mirrors the previous handler:
// sandfs zone (suffix) > legacy agent domain (exact) > stream domain (exact) >
// forward upstream.
func (s *DNSServer) answerQuery(network, remoteIP string, loopbackIngress bool, pkt []byte) []byte {
	q, err := wire.ParseQuery(pkt)
	if err != nil {
		return formerrFor(pkt)
	}
	if q.Opcode != 0 {
		return notimpFor(pkt)
	}
	name := q.Name() // lowercase presentation, no trailing dot
	ttl := uint32(s.cfg.TTL)
	guest := s.isGuestSource(remoteIP)

	var isAgent, isStream bool
	if s.cfg.Domains.Agent != "" && name == s.cfg.Domains.Agent {
		isAgent = true
	}
	if name == s.cfg.Domains.Stream {
		isStream = true
	}
	// Per-sandfs zone: <sandfs_id>.<sandfs_domain>. The ID is shape-validated
	// here (garbage labels → NXDOMAIN with zero etcd access) — see
	// validSandfsID.
	if s.cfg.Domains.Sandfs != "" && strings.HasSuffix(name, "."+s.cfg.Domains.Sandfs) {
		// A guest source is never a sandfs owner in the resolver's view: DNS
		// transports no ownership proof, and the sandfs zone names are the
		// agent-facing control-plane entry. Answer NXDOMAIN for EVERY guest
		// lookup (whoever owns the ID) so the answer leaks neither existence
		// nor the owner's/gateways' addresses, and no etcd lookup is charged
		// to a guest source.
		if guest {
			return s.reply(q, wire.RcodeNameError, nil)
		}
		sandfsID := strings.TrimSuffix(name, "."+s.cfg.Domains.Sandfs)
		if !validSandfsID(sandfsID) {
			return s.reply(q, wire.RcodeNameError, nil)
		}
		return s.answerSandfs(q, sandfsID, ttl, remoteIP)
	}

	// The stream (sandlot placement) and agent (bootstrap discovery) zones are
	// control-plane topology: a guest source has no business reading them.
	if guest && (isAgent || isStream) {
		return s.reply(q, wire.RcodeRefused, nil)
	}

	if isAgent {
		if gwInfo := s.resolveAgent(); gwInfo != nil {
			if reply, ok := s.hostReply(q, ttl, gwInfo.AgentIP, 0); ok {
				return reply
			}
		}
		return s.reply(q, wire.RcodeServerFailure, nil)
	}

	if isStream {
		gwInfo := s.resolveStream(stickyKey(remoteIP, q.Cookie))
		if gwInfo == nil {
			return s.reply(q, wire.RcodeServerFailure, nil)
		}
		if reply, ok := s.hostReply(q, ttl, gwInfo.StreamIP, uint16(gwInfo.StreamPort)); ok {
			return reply
		}
		return s.reply(q, wire.RcodeServerFailure, nil)
	}

	// Not our domain. A sandbox guest must not use this resolver to reach
	// arbitrary names: that would make the host an open recursive resolver
	// behind the host's egress identity. The guest's general resolver is the
	// sandlot's configured network DNS.
	if guest {
		return s.reply(q, wire.RcodeRefused, nil)
	}
	// A foreign zone from a non-guest source is forwarded ONLY for an explicit
	// ACL member (default: loopback). Every other source — including a forged
	// UDP source — is refused: otherwise this host is an open recursive
	// resolver and a reflection/amplification amplifier.
	if !s.recursiveAllowed(remoteIP, loopbackIngress) {
		return s.reply(q, wire.RcodeRefused, nil)
	}
	resp := s.forwardRaw(network, pkt)
	if network == "udp" {
		resp = truncateForwardedUDP(resp, forwardedUDPLimit(q.UDPSize))
	}
	return resp
}

// answerSandfs resolves the owner-aware zone: owner known + routable → its
// address; ownership UNKNOWN (etcd unreachable, nothing cached) → SERVFAIL
// (fail closed); genuinely unowned → scheduling fallback; nothing eligible →
// SERVFAIL.
func (s *DNSServer) answerSandfs(q *wire.Query, sandfsID string, ttl uint32, remoteIP string) []byte {
	cname, ip, ok, err := s.resolveSandfsOwner(sandfsID, remoteIP)
	if err != nil {
		return s.reply(q, wire.RcodeServerFailure, nil)
	}
	if ok {
		if reply, rok := s.hostReply(q, ttl, firstNonEmpty(cname, ip), 0); rok {
			return reply
		}
		// Owner resolved to an invalid host shape: treat as unroutable and
		// fall through to the fallback rather than answering junk.
	}
	if host, pok := s.pickBySchedulingPolicy(); pok {
		if reply, rok := s.hostReply(q, ttl, host, 0); rok {
			return reply
		}
	}
	return s.reply(q, wire.RcodeServerFailure, nil)
}

// hostReply builds the qtype-branched answer for a target host (IP literal or
// hostname) under the queried name:
//
//	SRV  (srvPort != 0) → SRV record; target = the hostname, or the queried
//	                     name itself for an IP target (which resolves to the
//	                     A/AAAA separately)
//	A    + IPv4 host → A record
//	A    + IPv6 host → NOERROR, empty (no v4 addresses exist for this name)
//	AAAA + IPv6 host → AAAA record
//	AAAA + IPv4 host → NOERROR, empty
//	hostname target  → CNAME for any other qtype (the client resolver chases
//	                   it; CNAME is valid for every RR type)
//	anything else    → NOERROR, empty
func (s *DNSServer) hostReply(q *wire.Query, ttl uint32, host string, srvPort uint16) ([]byte, bool) {
	if host == "" {
		return nil, false
	}
	if q.QType == wire.TypeSRV && srvPort != 0 {
		target := host
		if net.ParseIP(host) != nil {
			target = q.Name() // self-referential target: the name itself has the A record
		}
		return s.reply(q, wire.RcodeSuccess, []wire.RR{{
			Type: wire.TypeSRV, Name: target, Prio: 10, Weight: 50, Port: srvPort,
		}}), true
	}
	if ip := net.ParseIP(host); ip != nil {
		switch q.QType {
		case wire.TypeA:
			if v4 := ip.To4(); v4 != nil {
				return s.reply(q, wire.RcodeSuccess, []wire.RR{{Type: wire.TypeA, A: v4}}), true
			}
			return s.reply(q, wire.RcodeSuccess, nil), true // v6-only name, A asked
		case wire.TypeAAAA:
			if ip.To4() == nil {
				return s.reply(q, wire.RcodeSuccess, []wire.RR{{Type: wire.TypeAAAA, A: ip}}), true
			}
			return s.reply(q, wire.RcodeSuccess, nil), true // v4-only name, AAAA asked
		default:
			return s.reply(q, wire.RcodeSuccess, nil), true
		}
	}
	// Hostname target: CNAME for any remaining qtype.
	return s.reply(q, wire.RcodeSuccess, []wire.RR{{Type: wire.TypeCNAME, Name: host}}), true
}

// forwardRaw relays a non-sandswap query to the configured upstreams, trying
// each in turn on error or upstream SERVFAIL; all failed → SERVFAIL. Bounded
// by the dedicated forward budget (see forwardConcurrency): a forwarded query
// holds its slot for up to relayTimeout per upstream, so sharing the query
// budget would let a foreign-query flood starve authoritative answers.
func (s *DNSServer) forwardRaw(network string, pkt []byte) []byte {
	if len(s.cfg.Forwarders) == 0 {
		return s.servfailFor(pkt)
	}
	if s.forwardSem != nil {
		select {
		case s.forwardSem <- struct{}{}:
		default:
			return s.servfailFor(pkt) // forward budget exhausted: fail fast
		}
		defer func() { <-s.forwardSem }()
	}
	for _, fwd := range s.cfg.Forwarders {
		ctx, cancel := context.WithTimeout(context.Background(), relayTimeout)
		resp, err := wire.Relay(ctx, network, fwd, pkt, relayTimeout)
		cancel()
		if err != nil || len(resp) < wire.HeaderLen {
			continue
		}
		if resp[3]&0x0F == wire.RcodeServerFailure {
			continue // upstream gave up too; try the next one
		}
		return resp
	}
	return s.servfailFor(pkt)
}

// reply encodes an authoritative reply for a parsed query; a BuildReply
// failure degrades to SERVFAIL (never a silent no-answer).
func (s *DNSServer) reply(q *wire.Query, rcode int, answers []wire.RR) []byte {
	b, err := wire.BuildReply(q, rcode, uint32(s.cfg.TTL), answers)
	if err != nil {
		log.Printf("dns: encode reply: %v", err)
		if b, err = wire.BuildReply(q, wire.RcodeServerFailure, 0, nil); err != nil {
			return servfailHeader(q.ID) // last resort: bare header
		}
	}
	return b
}

// servfailFor answers an (possibly unparseable) raw query with SERVFAIL. The
// ID is echoed when even a minimal parse succeeds; otherwise a zero-ID header
// is the best possible answer.
func (s *DNSServer) servfailFor(pkt []byte) []byte {
	if q, err := wire.ParseQuery(pkt); err == nil && q.Opcode == 0 {
		b, err := wire.BuildReply(q, wire.RcodeServerFailure, 0, nil)
		if err == nil {
			return b
		}
	}
	// Reached on the saturation path with client bytes that may be shorter than
	// a DNS header (a 0/1-byte datagram is delivered by UDP): the ID echo needs
	// the same length guard formerrFor/notimpFor carry.
	if len(pkt) < 2 {
		return servfailHeader(0)
	}
	return servfailHeader(uint16(pkt[0])<<8 | uint16(pkt[1]))
}

// formerrFor answers an unparseable query with FORMERR (bare header with the
// echoed ID; a malformed question must not be echoed back).
func formerrFor(pkt []byte) []byte {
	if len(pkt) < 2 {
		return servfailHeader(0)
	}
	b := servfailHeader(uint16(pkt[0])<<8 | uint16(pkt[1]))
	b[3] = wire.RcodeFormatError // QR set by servfailHeader
	return b
}

// notimpFor answers a well-formed query whose OPCODE we do not implement
// (IQUERY/STATUS/UPDATE/NOTIFY) with NOTIMP — RFC 1035 §4.1.1: FORMERR is for
// malformed messages, NOTIMP for unsupported operations. Like formerrFor, the
// question is not echoed.
func notimpFor(pkt []byte) []byte {
	if len(pkt) < 2 {
		return servfailHeader(0)
	}
	b := servfailHeader(uint16(pkt[0])<<8 | uint16(pkt[1]))
	b[3] = wire.RcodeNotImplemented // QR set by servfailHeader
	return b
}

func servfailHeader(id uint16) []byte {
	return []byte{
		byte(id >> 8), byte(id), // ID
		0x80, 0x02, // QR=1, RCODE=SERVFAIL
		0, 0, 0, 0, 0, 0, 0, 0,
	}
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// ── socket helpers ─────────────────────────────────────────────────────

func reuseAddrControl(network, address string, c syscall.RawConn) error {
	var serr error
	if err := c.Control(func(fd uintptr) {
		serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
	}); err != nil {
		return err
	}
	return serr
}

func listenUDPReuseAddr(addr *net.UDPAddr) (*net.UDPConn, error) {
	lc := net.ListenConfig{Control: reuseAddrControl}
	pc, err := lc.ListenPacket(context.Background(), "udp", addr.String())
	if err != nil {
		return nil, err
	}
	return pc.(*net.UDPConn), nil
}

// listenUDPReuseAddrPktinfo is listenUDPReuseAddr plus IP_PKTINFO (IPv4) /
// IPV6_RECVPKTINFO (IPv6). The returned flag reports whether the control
// message could be enabled; when it could not, the caller falls back to the
// socket-binding ingress signal (never to trusting the source address).
func listenUDPReuseAddrPktinfo(addr *net.UDPAddr) (*net.UDPConn, bool, error) {
	enabled := false
	lc := net.ListenConfig{Control: func(network, address string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) {
			if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
				serr = err
				return
			}
			var optErr error
			switch network {
			case "udp4":
				optErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_PKTINFO, 1)
			case "udp6":
				optErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_RECVPKTINFO, 1)
			default:
				return
			}
			if optErr == nil {
				enabled = true
			}
		}); err != nil {
			return err
		}
		return serr
	}}
	pc, err := lc.ListenPacket(context.Background(), "udp", addr.String())
	if err != nil {
		return nil, false, err
	}
	if !enabled {
		log.Printf("WARNING: IP_PKTINFO unavailable on the loopback DNS socket %s — ingress is judged by the socket binding alone (a packet addressed 127.0.0.1 that arrived on a non-loopback interface cannot be distinguished)", addr)
	}
	return pc.(*net.UDPConn), enabled, nil
}

// readTCPFrame reads one 2-byte-length-framed DNS message.
func readTCPFrame(conn net.Conn) ([]byte, error) {
	var l [2]byte
	if _, err := readFull(conn, l[:]); err != nil {
		return nil, err
	}
	n := int(l[0])<<8 | int(l[1])
	if n < wire.HeaderLen || n > 65535 {
		return nil, fmt.Errorf("bad tcp frame length %d", n)
	}
	msg := make([]byte, n)
	if _, err := readFull(conn, msg); err != nil {
		return nil, err
	}
	return msg, nil
}

func writeTCPFrame(conn net.Conn, msg []byte) error {
	if len(msg) > 65535 {
		return fmt.Errorf("reply too large for tcp frame")
	}
	frame := make([]byte, 2+len(msg))
	frame[0] = byte(len(msg) >> 8)
	frame[1] = byte(len(msg))
	copy(frame[2:], msg)
	_, err := conn.Write(frame)
	return err
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

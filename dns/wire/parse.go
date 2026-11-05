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
//
// Package wire is a minimal DNS wire-format implementation covering exactly
// what sandswap-dns serves: parsing inbound queries (header + first question),
// encoding authoritative replies with a fixed set of RRs (A/AAAA/CNAME/SRV,
// never compressed, always < 512 bytes so UDP needs no truncation path), and
// relaying everything else to upstream resolvers as opaque bytes (no parsing
// of foreign answers at all). This replaces the general-purpose miekg/dns
// dependency: its two hard parts — arbitrary RR parsing and arbitrary zone
// synthesis — do not exist here.

package wire

import (
	"errors"
	"strings"
)

// DNS constants (RFC 1035 §3.2.2 etc.) — local definitions so the package has
// no external DNS dependency.
const (
	TypeA     uint16 = 1
	TypeNS    uint16 = 2
	TypeCNAME uint16 = 5
	TypePTR   uint16 = 12
	TypeMX    uint16 = 15
	TypeTXT   uint16 = 16
	TypeAAAA  uint16 = 28
	TypeSRV   uint16 = 33
)

// Response codes.
const (
	RcodeSuccess        = 0
	RcodeFormatError    = 1
	RcodeServerFailure  = 2
	RcodeNameError      = 3 // NXDOMAIN
	RcodeNotImplemented = 4
	RcodeRefused        = 5
)

const (
	// HeaderLen is the fixed DNS header size (exported for callers that do
	// minimal byte-level checks on raw messages).
	HeaderLen = 12

	headerLen  = HeaderLen
	maxNameLen = 255 // RFC 1035: fully-qualified name ≤ 255 octets incl. root
	maxLabel   = 63
	maxUDPSize = 512 // classic UDP payload size; our replies stay far below
)

var (
	ErrShort       = errors.New("wire: message shorter than header")
	ErrNotQuery    = errors.New("wire: QR bit set (not a query)")
	ErrNoQuestion  = errors.New("wire: QDCOUNT is zero")
	ErrTruncated   = errors.New("wire: question truncated")
	ErrPointer     = errors.New("wire: compression pointer in question (not allowed)")
	ErrBadLabel    = errors.New("wire: label length out of bounds")
	ErrNameTooLong = errors.New("wire: name exceeds 255 octets")
)

// Query is a parsed inbound DNS query. Only the FIRST question is parsed
// (standard practice — resolvers send exactly one); additional sections are
// ignored but tolerated, including EDNS OPT in additional.
type Query struct {
	ID     uint16
	Opcode int  // 0 = standard query
	RD     bool // recursion desired (echoed in the reply)

	// Question is the raw wire bytes of the first question section
	// (QNAME + QTYPE + QCLASS), exactly as received — replies echo it verbatim
	// so the query-name case (0x0x0 randomization) is preserved.
	Question []byte

	// nameLower is the presentation form of QNAME, lowercased, no trailing
	// dot (e.g. "sandfs-abc.sandfs.sandswap.local"). The empty string is the
	// root name.
	nameLower string

	QType  uint16
	QClass uint16

	// Cookie is the EDNS(0) COOKIE client-cookie (option code 10, first 8
	// bytes) when the query carries one. The control-plane resolver uses it to
	// bind sticky affinity to a source that a UDP spoofer cannot impersonate.
	Cookie []byte

	// UDPSize is the largest UDP payload the client accepts: the EDNS(0) OPT
	// CLASS when present, else the RFC 1035 classic 512. A relayed UDP answer
	// larger than this must be truncated with TC=1.
	UDPSize int
}

// Name returns the query name in lowercase presentation form (no trailing
// dot). Domain matching everywhere in the DNS server is case-insensitive.
func (q *Query) Name() string { return q.nameLower }

// ParseQuery parses a DNS query message (header + first question). Errors are
// categorized so the caller can FORMERR/REFUSE appropriately; every parse step
// is bounds-checked — a hostile packet can never panic the parser.
func ParseQuery(buf []byte) (*Query, error) {
	if len(buf) < headerLen {
		return nil, ErrShort
	}
	id := uint16(buf[0])<<8 | uint16(buf[1])
	flags := uint16(buf[2])<<8 | uint16(buf[3])
	if flags&0x8000 != 0 { // QR
		return nil, ErrNotQuery
	}
	qdcount := int(buf[4])<<8 | int(buf[5])
	if qdcount < 1 {
		return nil, ErrNoQuestion
	}

	q := &Query{
		ID:     id,
		Opcode: int(flags>>11) & 0xF,
		RD:     flags&0x0100 != 0,
	}

	// Question section starts right after the fixed header.
	off := headerLen
	var labels []string
	nameOctets := 1 // root terminator counts toward the 255 limit
	for {
		if off >= len(buf) {
			return nil, ErrTruncated
		}
		l := int(buf[off])
		if l == 0 { // root label: end of QNAME
			off++
			break
		}
		if l&0xC0 == 0xC0 { // pointer — never valid inside a question
			return nil, ErrPointer
		}
		if l > maxLabel { // includes the reserved 0x40/0x80 length prefixes
			return nil, ErrBadLabel
		}
		if off+1+l > len(buf) {
			return nil, ErrTruncated
		}
		nameOctets += l + 1
		if nameOctets > maxNameLen {
			return nil, ErrNameTooLong
		}
		labels = append(labels, strings.ToLower(string(buf[off+1:off+1+l])))
		off += 1 + l
	}
	// QTYPE + QCLASS.
	if off+4 > len(buf) {
		return nil, ErrTruncated
	}
	q.QType = uint16(buf[off])<<8 | uint16(buf[off+1])
	q.QClass = uint16(buf[off+2])<<8 | uint16(buf[off+3])
	q.Question = buf[headerLen : off+4]
	q.nameLower = strings.Join(labels, ".")
	q.UDPSize = maxUDPSize
	if arcount := int(buf[10])<<8 | int(buf[11]); arcount > 0 {
		cookie, udpSize := parseEDNS(buf, off+4)
		q.Cookie = cookie
		if udpSize > 0 {
			q.UDPSize = udpSize
		}
	}
	return q, nil
}

// parseEDNS walks the additional section (bounded) for the EDNS(0) OPT record.
// It returns the COOKIE option's client cookie (first 8 bytes) and the OPT
// CLASS — the sender's UDP payload size (RFC 6891 §6.1.3) — or 0 when no OPT
// was seen. Every step is bounds-checked; a malformed record just ends the
// walk with no cookie (the query is still valid).
func parseEDNS(buf []byte, off int) (cookie []byte, udpSize int) {
	for i := 0; i < 8 && off < len(buf); i++ {
		switch {
		case buf[off] == 0:
			off++
		case buf[off]&0xC0 == 0xC0:
			if off+2 > len(buf) {
				return nil, udpSize
			}
			off += 2
		default:
			for off < len(buf) && buf[off] != 0 {
				l := int(buf[off])
				if l&0xC0 != 0 || off+1+l > len(buf) {
					return nil, udpSize
				}
				off += 1 + l
			}
			if off >= len(buf) {
				return nil, udpSize
			}
			off++
		}
		if off+10 > len(buf) {
			return nil, udpSize
		}
		recStart := off
		rtype := uint16(buf[off])<<8 | uint16(buf[off+1])
		off += 10 // type(2)+class(2)+ttl(4)+rdlen(2)
		rdlen := int(buf[off-2])<<8 | int(buf[off-1])
		if off+rdlen > len(buf) {
			return nil, udpSize
		}
		if rtype == 41 {
			// CLASS carries the sender's UDP payload size. Values below the
			// classic 512 are meaningless (RFC 6891 §6.2.5); treat them as the
			// floor rather than shrinking below what a non-EDNS client has.
			advertised := int(uint16(buf[recStart+2])<<8 | uint16(buf[recStart+3]))
			if advertised < maxUDPSize {
				advertised = maxUDPSize
			}
			udpSize = advertised
			data := buf[off : off+rdlen]
			for j := 0; j+4 <= len(data); {
				code := uint16(data[j])<<8 | uint16(data[j+1])
				l := int(data[j+2])<<8 | int(data[j+3])
				j += 4
				if j+l > len(data) {
					return nil, udpSize
				}
				if code == 10 && l >= 8 {
					out := make([]byte, 8)
					copy(out, data[j:j+8])
					return out, udpSize
				}
				j += l
			}
			return nil, udpSize
		}
		off += rdlen
	}
	return nil, udpSize
}

// QuestionEnd returns the offset just past the first question section
// (QNAME+QTYPE+QCLASS) of msg. It reports false when the message has no
// question or the section is malformed. Compression pointers are rejected:
// the FIRST question has no prior name to point at, so a pointer there is
// never valid (RFC 1035 §4.1.4).
func QuestionEnd(msg []byte) (int, bool) {
	_, _, _, end, ok := parseQuestion(msg)
	return end, ok
}

// parseQuestion parses the first question section of msg: the lowercased
// presentation name (no trailing dot), QTYPE, QCLASS and the offset just past
// the section.
func parseQuestion(msg []byte) (name string, qtype, qclass uint16, end int, ok bool) {
	if len(msg) < headerLen {
		return "", 0, 0, 0, false
	}
	if qdcount := int(msg[4])<<8 | int(msg[5]); qdcount < 1 {
		return "", 0, 0, 0, false
	}
	off := headerLen
	var labels []string
	nameOctets := 1 // root terminator counts toward the 255 limit
	for {
		if off >= len(msg) {
			return "", 0, 0, 0, false
		}
		l := int(msg[off])
		if l == 0 {
			off++
			break
		}
		if l&0xC0 == 0xC0 { // pointer in the first question: no prior name
			return "", 0, 0, 0, false
		}
		if l > maxLabel {
			return "", 0, 0, 0, false
		}
		if off+1+l > len(msg) {
			return "", 0, 0, 0, false
		}
		nameOctets += l + 1
		if nameOctets > maxNameLen {
			return "", 0, 0, 0, false
		}
		labels = append(labels, strings.ToLower(string(msg[off+1:off+1+l])))
		off += 1 + l
	}
	if off+4 > len(msg) {
		return "", 0, 0, 0, false
	}
	qtype = uint16(msg[off])<<8 | uint16(msg[off+1])
	qclass = uint16(msg[off+2])<<8 | uint16(msg[off+3])
	return strings.Join(labels, "."), qtype, qclass, off + 4, true
}

// QuestionsMatch reports whether resp echoes query's first question: the same
// name (DNS 0x0x0 case randomization makes this case-insensitive), QTYPE and
// QCLASS. A response whose question cannot be parsed never matches.
func QuestionsMatch(query, resp []byte) bool {
	qn, qt, qc, _, ok := parseQuestion(query)
	if !ok {
		return false
	}
	rn, rt, rc, _, ok := parseQuestion(resp)
	if !ok {
		return false
	}
	return qn == rn && qt == rt && qc == rc
}

// Flags returns the query's flag word (with QR cleared) — useful for echoing.
func (q *Query) flags() uint16 {
	f := uint16(q.Opcode&0xF) << 11
	if q.RD {
		f |= 0x0100
	}
	return f
}

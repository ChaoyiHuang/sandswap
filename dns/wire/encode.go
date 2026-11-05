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
	"errors"
	"fmt"
	"net"
)

// ErrReplyTooBig: our authoritative replies must stay under the classic 512-
// byte UDP size (names are bounded, one or two RRs — if this fires the caller
// has a bug, and SERVFAIL is safer than a truncated packet).
var ErrReplyTooBig = errors.New("wire: reply exceeds 512 bytes")

// RR is one answer record. Exactly one variant is used per Type:
//   - TypeA:    A (must be a 4-byte IPv4)
//   - TypeAAAA: A (must be a 16-byte IPv6)
//   - TypeCNAME: Name (uncompressed target)
//   - TypeSRV:  Prio/Weight/Port + Name target
type RR struct {
	Type   uint16
	A      net.IP
	Name   string
	Prio   uint16
	Weight uint16
	Port   uint16
}

// BuildReply encodes an authoritative reply for q: header (ID echoed, QR set,
// opcode echoed, AA set, RD echoed, RA cleared), the question section echoed
// BYTE-FOR-BYTE (preserving the query-name case), and answers under the
// original owner name. Names are never compressed (RFC 1035 compression is
// optional; receivers must accept uncompressed). TC is never set — the reply
// is guaranteed under 512 bytes or the builder errors. TTL is uniform across
// answers (the server's single configured TTL).
func BuildReply(q *Query, rcode int, ttl uint32, answers []RR) ([]byte, error) {
	if rcode < 0 || rcode > 0xF {
		rcode = RcodeServerFailure
	}
	flags := uint16(0x8000) | q.flags() | 0x0400 /* AA */ | uint16(rcode)

	buf := make([]byte, 0, maxUDPSize)
	buf = appendU16(buf, q.ID)
	buf = appendU16(buf, flags)
	buf = appendU16(buf, 1)                    // QDCOUNT: the echoed question
	buf = appendU16(buf, uint16(len(answers))) // ANCOUNT
	buf = appendU16(buf, 0)                    // NSCOUNT
	buf = appendU16(buf, 0)                    // ARCOUNT (no EDNS on our replies)
	buf = append(buf, q.Question...)

	// Owner name for every answer = the raw QNAME bytes (everything before
	// QTYPE in the echoed question — i.e. Question minus its last 4 bytes).
	owner := q.Question[:len(q.Question)-4]

	for _, rr := range answers {
		var rdata []byte
		switch rr.Type {
		case TypeA:
			v4 := rr.A.To4()
			if v4 == nil {
				return nil, fmt.Errorf("wire: A record with non-IPv4 %v", rr.A)
			}
			rdata = append(rdata, v4...)
		case TypeAAAA:
			if rr.A == nil || rr.A.To4() != nil || len(rr.A) != net.IPv6len {
				return nil, fmt.Errorf("wire: AAAA record with non-IPv6 %v", rr.A)
			}
			rdata = append(rdata, rr.A.To16()...)
		case TypeCNAME:
			n, err := encodeName(rr.Name)
			if err != nil {
				return nil, fmt.Errorf("wire: CNAME target: %w", err)
			}
			rdata = n
		case TypeSRV:
			n, err := encodeName(rr.Name)
			if err != nil {
				return nil, fmt.Errorf("wire: SRV target: %w", err)
			}
			rdata = appendU16(appendU16(appendU16(nil, rr.Prio), rr.Weight), rr.Port)
			rdata = append(rdata, n...)
		default:
			return nil, fmt.Errorf("wire: unsupported RR type %d", rr.Type)
		}

		buf = append(buf, owner...)
		buf = appendU16(buf, rr.Type)
		buf = appendU16(buf, q.QClass)
		buf = appendU32(buf, ttl)
		buf = appendU16(buf, uint16(len(rdata)))
		buf = append(buf, rdata...)
		if len(buf) > maxUDPSize {
			return nil, ErrReplyTooBig
		}
	}
	return buf, nil
}

// encodeName encodes a presentation-form name (no trailing dot) as an
// uncompressed wire name (labels + root). Validates label/name limits AND the
// hostname charset ([A-Za-z0-9-] plus label dots) — defense in depth so a
// future caller bug cannot emit an unresolvable junk name.
func encodeName(name string) ([]byte, error) {
	if name == "" {
		return []byte{0}, nil // root
	}
	out := make([]byte, 0, len(name)+2)
	total := 1
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			label := name[start:i]
			if len(label) == 0 {
				return nil, fmt.Errorf("empty label in %q", name)
			}
			if len(label) > maxLabel {
				return nil, fmt.Errorf("label exceeds 63 bytes in %q", name)
			}
			for _, r := range label {
				switch {
				case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-':
				default:
					return nil, fmt.Errorf("invalid character %q in %q", r, name)
				}
			}
			total += len(label) + 1
			if total > maxNameLen {
				return nil, fmt.Errorf("name %q exceeds 255 octets", name)
			}
			out = append(out, byte(len(label)))
			out = append(out, label...)
			start = i + 1
		}
	}
	return append(out, 0), nil
}

func appendU16(b []byte, v uint16) []byte {
	return append(b, byte(v>>8), byte(v))
}

func appendU32(b []byte, v uint32) []byte {
	return append(b, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

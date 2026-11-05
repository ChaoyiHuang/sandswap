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
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

// Relay forwards a raw DNS query to an upstream resolver and returns the raw
// response bytes. The query and answer are OPAQUE — no parsing, no rewriting:
// EDNS OPT, DNSSEC records, and upstream compression pass through untouched.
// The transport follows the caller's inbound transport ("udp"/"tcp"), fixing
// the truncation-retry path (a TCP-originated query must not be forwarded over
// UDP: upstream truncates at the client's advertised size, and relaying a
// TC=1 answer over TCP is undefined).
//
// Each call uses its own socket, so responses cannot be cross-delivered
// between concurrent queries; the response ID must still match the query ID
// (cheap spoof rejection on an unconnected-at-origin protocol).
func Relay(ctx context.Context, network, upstream string, query []byte, timeout time.Duration) ([]byte, error) {
	switch network {
	case "udp", "tcp":
	default:
		return nil, fmt.Errorf("wire: unsupported relay network %q", network)
	}
	if len(query) < headerLen {
		return nil, ErrShort
	}

	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, network, upstream)
	if err != nil {
		return nil, fmt.Errorf("wire: dial %s %s: %w", network, upstream, err)
	}
	defer conn.Close()
	deadline := time.Now().Add(timeout)
	conn.SetDeadline(deadline)

	if network == "tcp" {
		// RFC 1035 §4.2.2: TCP DNS messages carry a 2-byte length prefix.
		var l [2]byte
		binary.BigEndian.PutUint16(l[:], uint16(len(query)))
		if _, err := conn.Write(append(l[:], query...)); err != nil {
			return nil, fmt.Errorf("wire: tcp write query: %w", err)
		}
		resp, err := readTCPMessage(conn)
		if err != nil {
			return nil, err
		}
		return resp, checkID(query, resp)
	}

	if _, err := conn.Write(query); err != nil {
		return nil, fmt.Errorf("wire: udp write query: %w", err)
	}
	// One extra datagram buffer's worth; upstream replies to a stub query fit.
	buf := make([]byte, 65535)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("wire: udp read response: %w", err)
	}
	return buf[:n], checkID(query, buf[:n])
}

// readTCPMessage reads one length-prefixed DNS message from a TCP connection.
func readTCPMessage(conn net.Conn) ([]byte, error) {
	var l [2]byte
	if _, err := io.ReadFull(conn, l[:]); err != nil {
		return nil, fmt.Errorf("wire: tcp read length: %w", err)
	}
	n := binary.BigEndian.Uint16(l[:])
	if n < headerLen {
		return nil, fmt.Errorf("wire: tcp message length %d below header", n)
	}
	msg := make([]byte, n)
	if _, err := io.ReadFull(conn, msg); err != nil {
		return nil, fmt.Errorf("wire: tcp read message: %w", err)
	}
	return msg, nil
}

// checkID verifies resp is the response to query: the same ID, QR set, and —
// when the query carries a parseable question — the same question section. The
// question check forces an off-path spoofer to know the queried NAME in
// addition to the ID and the source port, not merely to win a random race.
func checkID(query, resp []byte) error {
	if len(resp) < headerLen {
		return ErrShort
	}
	qID := uint16(query[0])<<8 | uint16(query[1])
	rID := uint16(resp[0])<<8 | uint16(resp[1])
	if qID != rID {
		return fmt.Errorf("wire: response ID %d does not match query %d", rID, qID)
	}
	if resp[2]&0x80 == 0 {
		return fmt.Errorf("wire: response has QR bit cleared")
	}
	if _, _, _, _, ok := parseQuestion(query); ok {
		if !QuestionsMatch(query, resp) {
			return fmt.Errorf("wire: response question does not match the query")
		}
	}
	return nil
}

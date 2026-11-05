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

package network

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Hand-rolled netlink for the identity stamp's per-mount flips. Direct
// messages replace fork+exec of `ip`/`nft` (~3-8 ms each): with the PERSISTENT
// per-protocol sockets below and a set id cached at Provision, both the
// mount-side NEWSETELEM and the unmount-side DELSETELEM measure ~9 µs on a
// nested host (the caller-visible stamp/unstamp including the address ops is
// ~0.4/0.8 ms). Opening and closing a socket PER REQUEST was the trap: close(2)
// after an nftables element delete waits for the kernel's transaction/RCU
// cleanup (~6 ms measured, the same even for a missing key), so the socket
// must outlive the operation. Uses ONLY the frozen, decade-stable subset of
// the uAPI we need:
//
//	rtnetlink  (NETLINK_ROUTE):   RTM_NEWADDR / RTM_DELADDR   — add/delete the
//	                              identity address on the TAP
//	nfnetlink  (NETLINK_NETFILTER): NFT_MSG_NEWSETELEM / DELSETELEM — flip the
//	                              stamp element of a static snat-to-map rule
//
// Deliberately NOT hand-rolled: rule/expression encoding (the error-prone
// part — the static rule + map + chain are created once per TAP at provision
// with the `nft` CLI), dumps/parses (element deletion is by key, the ack
// carries nothing we need), or any of the link/route/qdisc machinery the
// full-featured netlink libraries cover. Everything used here comes from
// golang.org/x/sys/unix constants — zero new dependencies.
//
// Kernel compatibility: both message families use uAPI constants that have
// been stable for over a decade (RTM_NEWADDR since 2.6; nftables batch
// framing since 3.13, set-element ops since 3.17). The only field parsed OUT
// of a kernel reply is the set id in NFTA_SET_ID (attr 0x10), whose width
// changed to u64-BE in v4.18 — both the u32 and u64 forms are accepted here,
// so nothing in this file is expected to need per-kernel-version changes.
// Every receive is deadline-bounded (netlinkRecvTimeout) so a kernel that
// replies in an unexpected shape degrades to a bounded error, never a hang.
//
// Concurrency: each call opens and closes its own socket (netlink socket
// setup is ~10-20 µs; stamps happen once per mount/unmount).

const (
	// nlAlignTo is the netlink 4-byte alignment boundary (uAPI-fixed).
	nlAlignTo = 4

	// nlSeqBase is the sequence number of the first message we send on a
	// socket. Single-request conversations start here; a batch's first
	// message (BEGIN) takes nlSeqBase and each subsequent message increments.
	nlSeqBase = 1

	// nlRecvBufSize bounds a single netlink receive. Our targeted GETSET
	// reply is one small message; 4 KiB is generous.
	nlRecvBufSize = 4096

	// netlinkRecvTimeout bounds every kernel reply wait. Netlink replies are
	// produced synchronously inside the sendto syscall, so this never fires
	// in practice; it converts a hypothetical broken/foreign kernel into a
	// bounded error instead of a hang on the mount path.
	netlinkRecvTimeout = 2 * time.Second
)

// nlAlign rounds a netlink attribute/message length to the 4-byte boundary.
func nlAlign(n int) int {
	return (n + nlAlignTo - 1) & ^(nlAlignTo - 1)
}

// nlAttr appends one netlink attribute (type, payload), aligned. nested sets
// NLA_F_NESTED so the payload is parsed as a container of attributes.
func nlAttr(buf []byte, attrType uint16, nested bool, payload []byte) []byte {
	t := attrType
	if nested {
		t |= unix.NLA_F_NESTED
	}
	l := unix.NLA_HDRLEN + len(payload)
	buf = binary.LittleEndian.AppendUint16(buf, uint16(l))
	buf = binary.LittleEndian.AppendUint16(buf, t)
	buf = append(buf, payload...)
	return append(buf, make([]byte, nlAlign(l)-l)...)
}

// nlMsg assembles a complete netlink message: header + typed payload +
// attributes. pid 0 = kernel; the caller assigns the sequence.
func nlMsg(msgType uint16, flags uint16, seq uint32, payload, attrs []byte) []byte {
	total := unix.NLMSG_HDRLEN + len(payload) + len(attrs)
	buf := binary.LittleEndian.AppendUint32(nil, uint32(total))
	buf = binary.LittleEndian.AppendUint16(buf, msgType)
	buf = binary.LittleEndian.AppendUint16(buf, flags)
	buf = binary.LittleEndian.AppendUint32(buf, seq)
	buf = binary.LittleEndian.AppendUint32(buf, 0)
	buf = append(buf, payload...)
	return append(buf, attrs...)
}

// nlTalk opens a netlink socket for the given protocol, sends msg (whose
// header seq identifies the conversation), and waits for the kernel's
// NLMSG_ERROR ack carrying OUR sequence (error 0 = success). Netlink sockets
// can also receive unrelated traffic, so the seq match is what makes this
// deterministic.
func nlTalk(protocol int, msg []byte) error {
	return nlTalkSeq(protocol, msg, binary.LittleEndian.Uint32(msg[8:]))
}

// nlTalkSeq is nlTalk with an explicit ack-sequence: a batch shares one send
// and its ack (requested on the op message only — never on
// BATCH_BEGIN/END) carries the op's seq. Errors are matched on that seq and
// unwrapped as unix.Errno (errors.Is(err, unix.EEXIST) works).
// Persistent netlink sockets, one per protocol, guarded per socket. Opening
// and closing a socket per request was measured at ~6 ms per nftables
// element DELETE on a nested host even though send/recv are tens of
// microseconds: the cost is in close(2), which waits for the kernel's
// nf_tables transaction/RCU cleanup. Reusing one socket keeps that cleanup
// off the mount/unmount path entirely (measured: add/del ~9 µs each on a
// persistent socket).
type nlSock struct {
	mu sync.Mutex
	fd int // -1 when closed after an error; reopened on the next call
}

var (
	nlSocksMu sync.Mutex
	nlSocks   = map[int]*nlSock{}
)

func nlOpenSocket(protocol int) (int, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, protocol)
	if err != nil {
		return -1, fmt.Errorf("netlink socket: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		_ = unix.Close(fd)
		return -1, fmt.Errorf("netlink bind: %w", err)
	}
	setRecvTimeout(fd)
	return fd, nil
}

func nlSockFor(protocol int) (*nlSock, error) {
	nlSocksMu.Lock()
	defer nlSocksMu.Unlock()
	if s, ok := nlSocks[protocol]; ok {
		return s, nil
	}
	fd, err := nlOpenSocket(protocol)
	if err != nil {
		return nil, err
	}
	s := &nlSock{fd: fd}
	nlSocks[protocol] = s
	return s, nil
}

func nlTalkSeq(protocol int, msg []byte, ackSeq uint32) error {
	s, err := nlSockFor(protocol)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fd < 0 {
		fd, err := nlOpenSocket(protocol)
		if err != nil {
			return err
		}
		s.fd = fd
	}
	if err := unix.Sendto(s.fd, msg, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		_ = unix.Close(s.fd)
		s.fd = -1
		return fmt.Errorf("netlink send: %w", err)
	}
	if err := waitNetlinkError(s.fd, ackSeq); err != nil {
		// A timeout or malformed reply can leave unread messages queued;
		// drop the socket so the next call starts clean.
		_ = unix.Close(s.fd)
		s.fd = -1
		return err
	}
	return nil
}

// setRecvTimeout installs the bounded-reply deadline on a netlink socket.
func setRecvTimeout(fd int) {
	tv := unix.NsecToTimeval(int64(netlinkRecvTimeout))
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)
}

// waitNetlinkError receives until an NLMSG_ERROR for ackSeq arrives (errno 0
// = success) or the deadline expires. Non-matching messages are skipped.
func waitNetlinkError(fd int, ackSeq uint32) error {
	buf := make([]byte, nlRecvBufSize)
	for {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			return fmt.Errorf("netlink recv (seq %d): %w", ackSeq, err)
		}
		for off := 0; off+unix.NLMSG_HDRLEN <= n; {
			length := int(binary.LittleEndian.Uint32(buf[off:]))
			if length < unix.NLMSG_HDRLEN || off+length > n {
				break // malformed remainder; drop it
			}
			msgSeq := binary.LittleEndian.Uint32(buf[off+nlSeqOffset:])
			msgType := binary.LittleEndian.Uint16(buf[off+nlTypeOffset:])
			if msgSeq != ackSeq {
				off += nlAlign(length)
				continue // unrelated traffic: skip
			}
			if msgType == unix.NLMSG_ERROR {
				errno := binary.LittleEndian.Uint32(buf[off+unix.NLMSG_HDRLEN:])
				if errno == 0 {
					return nil // ack: success
				}
				return fmt.Errorf("netlink error (seq %d): %w", ackSeq, unix.Errno(errno))
			}
			off += nlAlign(length)
		}
	}
}

const (
	// nlTypeOffset / nlSeqOffset are nlmsghdr field offsets:
	// nlmsg_len u32 @0, nlmsg_type u16 @4, nlmsg_flags u16 @6, nlmsg_seq u32 @8.
	nlTypeOffset = 4
	nlSeqOffset  = 8
	// nlPayloadOffset is where a message's typed payload starts after the
	// 16-byte nlmsghdr.
	nlPayloadOffset = unix.NLMSG_HDRLEN
	// nfgenmsgLen is the fixed nfnetlink sub-header (nfgen_family, version,
	// res_id u16 BE) that sits between nlmsghdr and the attributes on every
	// nfnetlink message.
	nfgenmsgLen = 4
	// nftAttrOffset is where nftables attributes start (after nlmsghdr +
	// nfgenmsg).
	nftAttrOffset = nlPayloadOffset + nfgenmsgLen
)

// --- rtnetlink: interface address add/delete ---

// rtAddrAdd adds ip/prefixlen to the interface (RTM_NEWADDR, CREATE|EXCL).
// EEXIST is treated as success: the address already being assigned is exactly
// the desired end state (residue from a crashed unstamp), and failing the
// stamp over it would leave the mount unstamped forever.
func rtAddrAdd(ifindex uint32, ip net.IP, prefixlen int) error {
	err := rtAddrOp(unix.RTM_NEWADDR, unix.NLM_F_CREATE|unix.NLM_F_EXCL, ifindex, ip, prefixlen)
	if errors.Is(err, unix.EEXIST) {
		return nil
	}
	return err
}

// rtAddrDel removes ip/prefixlen from the interface (RTM_DELADDR).
func rtAddrDel(ifindex uint32, ip net.IP, prefixlen int) error {
	return rtAddrOp(unix.RTM_DELADDR, 0, ifindex, ip, prefixlen)
}

func rtAddrOp(msgType uint16, flags uint16, ifindex uint32, ip net.IP, prefixlen int) error {
	// IFA_F_NODAD: skip duplicate-address detection for addresses added via
	// rtnetlink (the identity-stamp /128 on the TAP). Without it the address
	// sits TENTATIVE for the ~1-2s DAD window after RTM_NEWADDR, and a
	// tentative address does not participate in source-address selection —
	// the egress identity stamp would not take effect until DAD completed.
	// (Ignored by the kernel on RTM_DELADDR.)
	ifa := unix.IfAddrmsg{
		Family:    unix.AF_INET6,
		Prefixlen: uint8(prefixlen),
		Flags:     unix.IFA_F_NODAD,
		Index:     ifindex,
	}
	payload := (*(*[unix.SizeofIfAddrmsg]byte)(unsafe.Pointer(&ifa)))[:]
	var attrs []byte
	ip16 := ip.To16()
	// For IPv6 the kernel reads the address from IFA_ADDRESS; IFA_LOCAL is
	// conventionally set to the same value by iproute2.
	attrs = nlAttr(attrs, unix.IFA_ADDRESS, false, ip16)
	attrs = nlAttr(attrs, unix.IFA_LOCAL, false, ip16)
	msg := nlMsg(msgType, unix.NLM_F_REQUEST|flags|unix.NLM_F_ACK, nlSeqBase, payload, attrs)
	return nlTalk(unix.NETLINK_ROUTE, msg)
}

// --- nfnetlink (nftables): named-set element add/delete ---
//
// uAPI enums not mirrored by x/sys/unix (or mirrored at stale positions —
// the set-attribute block was renumbered in v4.1, which is exactly why these
// are pinned locally). Values are uAPI-stable since v4.1/v4.18.

const (
	// nftMsgNewSet / nftMsgGetSet are the NFT_MSG_* message-type bases (the
	// full type is NFNL_SUBSYS_NFTABLES<<8 | base). NEWSET doubles as the
	// GETSET reply type (dump convention); GETSET is the targeted request.
	nftMsgNewSet = 9
	nftMsgGetSet = 10

	// nftMsgNewSetElem / nftMsgDelSetElem are the element-operation bases.
	nftMsgNewSetElem = unix.NFT_MSG_NEWSETELEM // 0x0c
	nftMsgDelSetElem = unix.NFT_MSG_DELSETELEM // 0x0e

	// NFT_MSG_BATCH_BEGIN / END frame the mandatory transaction envelope;
	// element ops outside a batch are rejected EINVAL on current kernels.
	nftMsgBatchBegin = 0x10
	nftMsgBatchEnd   = 0x11

	// NFTA_SET_ELEM_LIST_* attributes of NEWSETELEM/DELSETELEM.
	nftaSetElemListTable    = unix.NFTA_SET_ELEM_LIST_TABLE    // 0x1
	nftaSetElemListSet      = unix.NFTA_SET_ELEM_LIST_SET      // 0x2
	nftaSetElemListElements = unix.NFTA_SET_ELEM_LIST_ELEMENTS // 0x3 (nested)
	nftaSetElemListSetID    = 0x4                              // NFTA_SET_ELEM_LIST_SET_ID (u32 BE)

	// nftaListElem (NFTA_LIST_ELEM) wraps each element inside ELEMENTS. The
	// wrapper is mandatory: without it the kernel fails the whole message
	// with EINVAL (byte-verified against `nft` CLI batches via strace).
	nftaListElem = 0x1

	// Per-element attributes.
	nftaSetElemKey  = unix.NFTA_SET_ELEM_KEY  // 0x1 (nested)
	nftaSetElemData = unix.NFTA_SET_ELEM_DATA // 0x2 (nested)

	// NFTA_DATA_VALUE is the payload wrapper inside KEY/DATA.
	nftaDataValue = unix.NFTA_DATA_VALUE // 0x1

	// NFTA_SET_* attribute positions shared by the GETSET request and its
	// NEWSET reply. The set-attribute enum moved in v4.1 — the historical
	// x/sys positions (id at 0xa) do not match any kernel this decade; 0x10
	// is the current uAPI position.
	nftaSetTable = 0x1 // NUL-terminated table name
	nftaSetName  = 0x2 // NUL-terminated set name
	// nftaSetID carries the kernel-assigned set id: u64 BE since v4.18
	// (u32 BE before) — both widths are accepted when parsing.
	nftaSetID = 0x10
)

// nfProtoInet is NFPROTO_INET (numerically AF_UNIX, which is why the
// constants above look odd if read as socket families). The kernel resolves
// the table WITHIN this family — a mismatch fails the lookup with EINVAL.
const nfProtoInet = 0x1

// nftNfgenmsg builds the 4-byte nfgenmsg. family is NFPROTO_INET for our
// tables; resID is the subsystem id (htons-encoded) for BATCH_BEGIN/END and
// ZERO for the messages inside a batch — the kernel validates res_id of
// in-batch messages against the batch subsystem, and a stale res_id fails
// with EINVAL.
func nftNfgenmsg(family uint8, resID uint16) []byte {
	res := make([]byte, 2)
	binary.BigEndian.PutUint16(res, resID)
	return []byte{family, 0, res[0], res[1]}
}

func nftMsgType(base uint16) uint16 {
	return uint16(unix.NFNL_SUBSYS_NFTABLES)<<8 | base
}

// nftSetElemAdd inserts one map element: key (original address) -> data
// (identity address), both 16-byte IPv6. The set itself is provisioned once
// by the `nft` CLI (see routed6.go).
func nftSetElemAdd(table, set string, key, data []byte) error {
	return nftSetElemOp(nftMsgNewSetElem, table, set, key, data)
}

// nftSetElemAddID is nftSetElemAdd with a CACHED set id: the id is stable
// from the map's creation (Provision) to its deletion (Release), so the
// per-mount path skips the GETSET round trip entirely.
func nftSetElemAddID(table, set string, id uint32, key, data []byte) error {
	return nftSetElemOpID(nftMsgNewSetElem, table, set, id, key, data)
}

// nftSetElemDel removes the element identified by key.
func nftSetElemDel(table, set string, key []byte) error {
	return nftSetElemOp(nftMsgDelSetElem, table, set, key, nil)
}

// nftSetElemDelID is nftSetElemDel with a cached set id.
func nftSetElemDelID(table, set string, id uint32, key []byte) error {
	return nftSetElemOpID(nftMsgDelSetElem, table, set, id, key, nil)
}

// nftBatchOpSeq is the position of the op message inside every batch this
// file sends: BEGIN takes nlSeqBase, the op takes nlSeqBase+1, END the one
// after. The kernel's ack/error for the op carries this sequence.
const nftBatchOpSeq = nlSeqBase + 1

func nftSetElemOp(msgBase uint16, table, set string, key, data []byte) error {
	// Kernels dispatch nftables ops ONLY inside a batch envelope and want the
	// set id (not just the name) on element operations.
	id, err := nftResolveSetID(table, set)
	if err != nil {
		return err
	}
	return nftSetElemOpID(msgBase, table, set, id, key, data)
}

// nftSetElemOpID performs the element operation with an already-resolved set
// id (the per-mount hot path caches it at Provision).
func nftSetElemOpID(msgBase uint16, table, set string, id uint32, key, data []byte) error {
	build := func(msgBase uint16) []byte {
		var attrs []byte
		attrs = nlAttr(attrs, uint16(nftaSetElemListTable), false, append([]byte(table), 0))
		attrs = nlAttr(attrs, uint16(nftaSetElemListSet), false, append([]byte(set), 0))
		attrs = nlAttr(attrs, uint16(nftaSetElemListSetID), false, binary.BigEndian.AppendUint32(nil, id))

		// ELEMENTS (nested) { LIST_ELEM (nested) { KEY (nested) {VALUE},
		// DATA (nested) {VALUE} } } — see nftaListElem.
		var one []byte
		one = nlAttr(one, uint16(nftaSetElemKey), true,
			nlAttr(nil, uint16(nftaDataValue), false, key))
		if msgBase == nftMsgNewSetElem {
			one = nlAttr(one, uint16(nftaSetElemData), true,
				nlAttr(nil, uint16(nftaDataValue), false, data))
		}
		elem := nlAttr(nil, uint16(nftaListElem), true, one)
		attrs = nlAttr(attrs, uint16(nftaSetElemListElements), true, elem)

		return nlMsg(nftMsgType(msgBase), unix.NLM_F_REQUEST|unix.NLM_F_CREATE|unix.NLM_F_ACK, nftBatchOpSeq, nftNfgenmsg(nfProtoInet, 0), attrs)
	}
	// Map elements are immutable in nftables: same key + different data →
	// EEXIST (nf_tables_api.c nft_add_set_elem memcmp-clash). Replacement is
	// therefore DEL + re-CREATE as two batches.
	if err := nlTalkSeq(unix.NETLINK_NETFILTER, nftBatch(build(msgBase)), nftBatchOpSeq); err != nil {
		if !errors.Is(err, unix.EEXIST) || msgBase != nftMsgNewSetElem {
			return err
		}
		// Replace path (stale element from a crashed process / rebind):
		// delete the old element, tolerate its absence, then re-create.
		del := build(nftMsgDelSetElem)
		_ = nlTalkSeq(unix.NETLINK_NETFILTER, nftBatch(del), nftBatchOpSeq) // ENOENT tolerated
		return nlTalkSeq(unix.NETLINK_NETFILTER, nftBatch(build(nftMsgNewSetElem)), nftBatchOpSeq)
	}
	return nil
}

// nftResolveSetID resolves a named set/map's kernel-assigned id via a
// targeted NFT_MSG_GETSET (table + name attrs). Element operations want
// NFTA_SET_ELEM_LIST_SET_ID alongside the name. The id is returned in
// NFTA_SET_ID (attr 0x10) as u64 BE since v4.18, u32 BE before — both forms
// are accepted. Bounded: every receive carries netlinkRecvTimeout, and a
// reply that never yields an id errors out instead of retrying forever.
func nftResolveSetID(table, set string) (uint32, error) {
	var attrs []byte
	attrs = nlAttr(attrs, uint16(nftaSetTable), false, append([]byte(table), 0))
	attrs = nlAttr(attrs, uint16(nftaSetName), false, append([]byte(set), 0))
	msg := nlMsg(nftMsgType(nftMsgGetSet), unix.NLM_F_REQUEST, nlSeqBase, nftNfgenmsg(nfProtoInet, 0), attrs)

	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_NETFILTER)
	if err != nil {
		return 0, fmt.Errorf("netlink socket: %w", err)
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return 0, fmt.Errorf("netlink bind: %w", err)
	}
	setRecvTimeout(fd)
	if err := unix.Sendto(fd, msg, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return 0, fmt.Errorf("netlink send: %w", err)
	}

	buf := make([]byte, nlRecvBufSize)
	for {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			return 0, fmt.Errorf("netlink recv (getset %s/%s): %w", table, set, err)
		}
		for off := 0; off+unix.NLMSG_HDRLEN <= n; {
			length := int(binary.LittleEndian.Uint32(buf[off:]))
			if length < unix.NLMSG_HDRLEN || off+length > n {
				break
			}
			msgSeq := binary.LittleEndian.Uint32(buf[off+nlSeqOffset:])
			msgType := binary.LittleEndian.Uint16(buf[off+nlTypeOffset:])
			if msgSeq != nlSeqBase {
				off += nlAlign(length)
				continue // unrelated traffic: skip
			}
			if msgType == unix.NLMSG_ERROR {
				errno := binary.LittleEndian.Uint32(buf[off+unix.NLMSG_HDRLEN:])
				if errno == 0 { // impossible for GETSET; defensive
					off += nlAlign(length)
					continue
				}
				return 0, fmt.Errorf("getset %s/%s: %w", table, set, unix.Errno(errno))
			}
			if msgType == nftMsgType(nftMsgNewSet) {
				if id, ok := parseSetID(buf[off+nftAttrOffset:off+length], set); ok {
					return id, nil
				}
			}
			off += nlAlign(length)
		}
		// The GETSET reply for our seq has now been consumed without a usable
		// id (foreign kernel shape or wrong set) — fail bounded, don't spin.
		return 0, fmt.Errorf("getset %s/%s: reply carried no usable set id", table, set)
	}
}

// parseSetID scans a NEWSET reply's attribute stream for the set's id.
// NFTA_SET_NAME guards against a reply for a different set (defensive: a
// targeted GETSET answers only the requested one); NFTA_SET_ID carries the
// id in both historical widths (u64 BE since v4.18, u32 BE before).
func parseSetID(attrs []byte, set string) (uint32, bool) {
	off := 0
	id := uint32(0)
	nameOK := false
	idOK := false
	for off+4 <= len(attrs) {
		al := int(binary.LittleEndian.Uint16(attrs[off:]))
		at := int(binary.LittleEndian.Uint16(attrs[off+2:])) &^ unix.NLA_F_NESTED
		if al < 4 || off+al > len(attrs) {
			break // malformed remainder
		}
		payload := attrs[off+4 : off+al]
		switch at {
		case nftaSetName:
			nameOK = nulString(payload) == set
		case nftaSetID:
			switch len(payload) {
			case 8:
				id = uint32(binary.BigEndian.Uint64(payload))
				idOK = true
			case 4:
				id = binary.BigEndian.Uint32(payload)
				idOK = true
			}
		}
		off += nlAlign(al)
	}
	if idOK && (nameOK || set == "") {
		return id, true
	}
	return 0, false
}

// nulString reads a NUL-terminated attribute payload.
func nulString(payload []byte) string {
	if len(payload) > 0 && payload[len(payload)-1] == 0 {
		payload = payload[:len(payload)-1]
	}
	return string(payload)
}

// nftBatch frames nftables messages in the mandatory transaction envelope
// (NFNL_MSG_BATCH_BEGIN ... END, subsystem id in res_id). Message sequences
// are rewritten to nlSeqBase, nlSeqBase+1, ... so the op's ack matches
// nftBatchOpSeq.
func nftBatch(msgs ...[]byte) []byte {
	var out []byte
	out = append(out, nlMsg(nftMsgBatchBegin, unix.NLM_F_REQUEST, nlSeqBase, nftNfgenmsg(0, unix.NFNL_SUBSYS_NFTABLES), nil)...)
	seq := uint32(nlSeqBase + 1)
	for _, m := range msgs {
		binary.LittleEndian.PutUint32(m[nlSeqOffset:], seq)
		out = append(out, m...)
		seq++
	}
	out = append(out, nlMsg(nftMsgBatchEnd, unix.NLM_F_REQUEST, seq, nftNfgenmsg(0, unix.NFNL_SUBSYS_NFTABLES), nil)...)
	return out
}

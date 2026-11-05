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
// warden-probe — raw vsock client for talking to a warden inside a microVM
// DIRECTLY, bypassing sandlot/gateway. A testing/diagnostics tool: it exists
// because every other client reaches the warden through the full stack, so
// protocol-level edges (malformed frames, oversized bodies, hostile
// mount_points) had no way to be exercised. It both speaks the legit protocol
// (memstats/exec/mount/unmount) and injects deliberately broken frames.
// Usage:
//	warden-probe -cid <guest-cid> [-timeout 5s] [-key <hex> | -state <state.json>] <mode> [args...]
//	  The per-VM session key is REQUIRED for every mode whose frame must pass
//	  the warden's request authentication (memstats/exec/mount/unmount and the
//	  well-formed malformed-body probes). The deliberately unsigned header
//	  probes (bad-magic/bad-version/oversize/short-body/half-header/stall-body)
//	  need no key. -state extracts the key from the VM's state.json. Every
//	  authenticated run first delivers the key (OP_KEY_DELIVERY): the warden
//	  serves nothing before that frame.
// Modes:
//	memstats                          OP_MEM_STATS heartbeat
//	exec <cmd> [timeout_ms] [identity] OP_EXEC (warm path; identity at field 3)
//	mount-exec <alias> <mp> <cmd> [mode] OP_MOUNT_AND_EXEC (7-field cold path)
//	unmount <mp> [identity] [--forced] OP_UNMOUNT (identity-bound; MISMATCH tears down nothing)
//	bad-magic                         header magic 0xDEADBEEF
//	bad-version                       protocol version 99
//	unknown-op                        op=99
//	oversize                          body_len claims 32 MiB (> max_body_len)
//	short-body                        body_len claims 64, only 3 sent, then FIN
//	half-header                       5 header bytes, then FIN
//	field-past-end                    field length runs past body end
//	too-many-fields                   65 zero-length fields (> MAX_FIELDS=64)
//	mount-bad-mp                      OP_MOUNT_AND_EXEC with mount_point=/sys/fs/cgroup
//	unmount-bad-mp                    OP_UNMOUNT with mount_point=/proc
//	raw <hex>                         send arbitrary bytes as the whole frame
// Output (stable for e2e grepping):
//	resp code=<u8> exit=<u8> stdout_len=<n> stderr_len=<n> mounted_len=<n> dur_ns=<u64>
//	stdout <text>   (up to 4 KiB, single line, non-UTF8 as %q)
//	stderr <text>
//	eof             (peer closed without a response)
// Exit status: 0 when a response or documented EOF was observed, 1 on usage
// or transport errors. The CALLER decides whether the observed behavior is
// the expected one.

package main

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"sandlot/warden"
)

const (
	wardenPort      = 1024
	magic           = 0x53414e44 // "SAND"
	protocolVersion = 1
	opMountAndExec  = 1
	opUnmount       = 2
	opExec          = 3
	opMemStats      = 4
	opKeyDelivery   = 10
	nonceLen        = 16
	bodyMACLen      = 32
	tagLen          = 32
	reqHeaderLen    = 10 + nonceLen + bodyMACLen + tagLen
	respHeaderLen   = 28 + tagLen
	defaultReadWait = 5 * time.Second
)

// The authenticated request path: the probe signs with the per-VM key (from
// -key or the VM's state.json) and verifies the response tag. Malformed-frame
// modes deliberately send unsigned headers — they test rejection before auth.
var (
	probeKey    []byte
	probeNonce  [nonceLen]byte
	probeSigned bool
)

func main() {
	cid := flag.Uint("cid", 0, "guest vsock CID (required)")
	readWait := flag.Duration("timeout", defaultReadWait, "per-attempt read wait")
	hold := flag.Duration("hold", 0, "park the connection this long after sending (stall tests)")
	keyHex := flag.String("key", "", "per-VM session key (64 hex characters); required for signed modes")
	statePath := flag.String("state", "", "path to the VM's state/state.json (reads config.warden_session_key)")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: warden-probe -cid <guest-cid> [-timeout 5s] <mode> [args...]\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "modes: memstats | exec <cmd> [timeout_ms] | mount-exec <alias> <mp> <cmd> | unmount <mp> [identity] [--forced] |\n"+
			"  bad-magic | bad-version | unknown-op | oversize | short-body | half-header | field-past-end |\n"+
			"  too-many-fields | mount-bad-mp | unmount-bad-mp | stall-body <bytes> | raw <hex>\n")
	}
	flag.Parse()
	if *cid == 0 || flag.NArg() < 1 {
		flag.Usage()
		os.Exit(1)
	}
	mode := flag.Arg(0)
	args := flag.Args()[1:]

	if *keyHex == "" && *statePath != "" {
		*keyHex = keyFromState(*statePath)
	}
	if *keyHex != "" {
		k, err := warden.DecodeSessionKey(*keyHex)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warden-probe: %v\n", err)
			os.Exit(1)
		}
		probeKey = k
	}

	if err := run(uint32(*cid), *readWait, *hold, mode, args); err != nil {
		fmt.Fprintf(os.Stderr, "warden-probe: %v\n", err)
		os.Exit(1)
	}
}

// frame builds a well-formed AUTHENTICATED request: signed header (with the
// op-specific body MAC over the fields) + length-prefixed fields.
func frame(op uint8, fields ...[]byte) []byte {
	body := make([]byte, 0, 64)
	for _, f := range fields {
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(f)))
		body = append(body, l[:]...)
		body = append(body, f...)
	}
	if len(probeKey) != 32 {
		// Callers gate on needsKey; a missing key here would send a frame the
		// warden rejects, hiding the behavior under test.
		return headerWith(magic, protocolVersion, op, uint32(len(body)))
	}
	newProbeNonce()
	hdr := make([]byte, reqHeaderLen)
	binary.BigEndian.PutUint32(hdr[0:4], magic)
	hdr[4] = protocolVersion
	hdr[5] = op
	binary.BigEndian.PutUint32(hdr[6:10], uint32(len(body)))
	copy(hdr[10:10+nonceLen], probeNonce[:])
	bm := probeBodyMAC(op, fields)
	copy(hdr[10+nonceLen:10+nonceLen+bodyMACLen], bm[:])
	tag := warden.RequestTag(probeKey, probeNonce[:], protocolVersion, op, uint32(len(body)), bm[:])
	copy(hdr[10+nonceLen+bodyMACLen:reqHeaderLen], tag[:])
	probeSigned = true
	return append(hdr, body...)
}

// probeBodyMAC mirrors the sandlot client's op-specific body MAC field
// selection, so the probe's well-formed requests authenticate exactly like a
// real client's.
func probeBodyMAC(op uint8, fields [][]byte) [bodyMACLen]byte {
	at := func(i int) []byte {
		if i < len(fields) {
			return fields[i]
		}
		return nil
	}
	switch op {
	case opExec:
		return warden.BodyMAC(probeKey, probeNonce[:], op, at(3))
	case 5: // OP_ASYNC_EXEC
		return warden.BodyMAC(probeKey, probeNonce[:], op, at(2))
	case 9: // OP_FILE
		return warden.BodyMAC(probeKey, probeNonce[:], op, at(5))
	case opUnmount:
		return warden.BodyMAC(probeKey, probeNonce[:], op, at(0), at(1), at(2))
	case opMountAndExec:
		return warden.BodyMAC(probeKey, probeNonce[:], op, at(0), at(1), at(6))
	case 6: // OP_MOUNT_AND_ASYNC_EXEC
		return warden.BodyMAC(probeKey, probeNonce[:], op, at(0), at(1), at(5))
	default:
		return [bodyMACLen]byte{}
	}
}

func newProbeNonce() {
	if _, err := rand.Read(probeNonce[:]); err != nil {
		copy(probeNonce[:], []byte("probe-nonce-0001"))
	}
}

// signedBodyFrame builds a signed header over an arbitrary body — how the
// parser-edge modes (field lengths/count) reach the body parser past
// authentication. Those bodies are REJECTED during parsing, before the
// op-specific body-field MAC is checked, so the MAC is zero here.
func signedBodyFrame(op uint8, body []byte) []byte {
	if len(probeKey) != 32 {
		// Callers gate on needsKey; a missing key here would send a frame the
		// warden rejects, hiding the behavior under test.
		return headerWith(magic, protocolVersion, op, uint32(len(body)))
	}
	return append(signedHeaderOnly(op, uint32(len(body))), body...)
}

// signedHeaderOnly builds a signed header whose body_len is CLAIMED but not
// sent — the authenticated parking shape (the warden verifies the tag, reserves
// the body budget, then blocks in read_exact).
func signedHeaderOnly(op uint8, claimedBodyLen uint32) []byte {
	hdr := make([]byte, reqHeaderLen)
	binary.BigEndian.PutUint32(hdr[0:4], magic)
	hdr[4] = protocolVersion
	hdr[5] = op
	binary.BigEndian.PutUint32(hdr[6:10], claimedBodyLen)
	newProbeNonce()
	copy(hdr[10:10+nonceLen], probeNonce[:])
	// hdr[10+nonceLen:10+nonceLen+bodyMACLen] stays zero: no body to bind.
	if len(probeKey) == 32 {
		var zeroMAC [bodyMACLen]byte
		tag := warden.RequestTag(probeKey, probeNonce[:], protocolVersion, op, claimedBodyLen, zeroMAC[:])
		copy(hdr[10+nonceLen+bodyMACLen:reqHeaderLen], tag[:])
	}
	probeSigned = true
	return hdr
}

func strField(s string) []byte { return []byte(s) }

// headerWith builds a 10-byte UNSIGNED header with an explicit (possibly
// lying) version/op/body_len — the malformed-frame modes live here. These are
// rejected before or at the authenticated-header read, by design.
func headerWith(mag uint32, version, op uint8, bodyLen uint32) []byte {
	probeSigned = false
	hdr := make([]byte, 10)
	binary.BigEndian.PutUint32(hdr[0:4], mag)
	hdr[4] = version
	hdr[5] = op
	binary.BigEndian.PutUint32(hdr[6:10], bodyLen)
	return hdr
}

// needsKey reports whether a mode sends a frame that must pass the warden's
// authentication to reach the behavior under test.
func needsKey(mode string) bool {
	switch mode {
	case "bad-magic", "bad-version", "oversize", "short-body", "half-header", "raw":
		return false
	}
	return true
}

// keyFromState extracts the per-VM session key from a VM's state.json
// (config.warden_session_key). The key is delivered over the first host vsock
// connection, never the kernel cmdline, so there is no cmdline fallback.
// Readable by the sandlot identity (the state dir is owner-only) and by root;
// e2e runs the probe as the sandlot user.
func keyFromState(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warden-probe: read state %s: %v\n", path, err)
		return ""
	}
	var st struct {
		Config struct {
			WardenSessionKey string `json:"warden_session_key"`
		} `json:"config"`
	}
	if err := json.Unmarshal(data, &st); err != nil {
		fmt.Fprintf(os.Stderr, "warden-probe: parse state %s: %v\n", path, err)
		return ""
	}
	return st.Config.WardenSessionKey
}

func fieldHeader(n uint32) []byte {
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], n)
	return l[:]
}

// buildRequest returns the bytes to send plus whether the write side should
// be FIN'd right after (short-body / half-header need it to make read_exact
// hit EOF instead of blocking forever).
func buildRequest(mode string, args []string) (payload []byte, fin bool, err error) {
	switch mode {
	case "memstats":
		return frame(opMemStats), false, nil
	case "exec":
		if len(args) < 1 {
			return nil, false, fmt.Errorf("exec needs <command> [timeout_ms] [identity]")
		}
		timeoutMs := "0"
		if len(args) >= 2 {
			timeoutMs = args[1]
		}
		identity := ""
		if len(args) >= 3 {
			identity = args[2]
		}
		return frame(opExec, strField(args[0]), strField(timeoutMs), strField("0"), strField(identity)), false, nil
	case "mount-exec":
		if len(args) < 3 {
			return nil, false, fmt.Errorf("mount-exec needs <alias> <mount_point> <command> [mode]")
		}
		mode := "flat"
		if len(args) >= 4 {
			mode = args[3]
		}
		return frame(opMountAndExec,
			strField(args[0]), strField(args[1]), strField("none"),
			strField(args[2]), strField("0"), strField("0"), strField(mode)), false, nil
	case "unmount":
		if len(args) < 1 {
			return nil, false, fmt.Errorf("unmount needs <mount-point> [identity] [--forced]")
		}
		identity, forced := "", "0"
		if len(args) >= 2 {
			identity = args[1]
		}
		if len(args) >= 3 && args[2] == "--forced" {
			forced = "1"
		}
		return frame(opUnmount, strField(args[0]), strField(identity), strField(forced)), false, nil

	// ── malformed frames ────────────────────────────────────────────
	case "bad-magic":
		return headerWith(0xDEADBEEF, protocolVersion, opMemStats, 0), false, nil
	case "bad-version":
		return headerWith(magic, 99, opMemStats, 0), false, nil
	case "unknown-op":
		// Well-formed and AUTHENTICATED (an op the warden does not know):
		// the dispatch-level rejection is what this mode tests.
		return frame(99), false, nil
	case "oversize":
		// body_len claims 32 MiB — over the warden's max_body_len (16 MiB).
		// The warden must reject the frame without allocating the body.
		return headerWith(magic, protocolVersion, opExec, 32*1024*1024), false, nil
	case "short-body":
		// Claims a 64-byte body, sends 3, then FIN: read_exact must fail
		// (truncated request), never execute a defaulted command.
		return append(headerWith(magic, protocolVersion, opExec, 64), 0x01, 0x02, 0x03), true, nil
	case "half-header":
		// 5 bytes of header then FIN: even the fixed header is incomplete.
		return headerWith(magic, protocolVersion, opExec, 0)[:5], true, nil
	case "field-past-end":
		// One field declaring 100 bytes with only 5 in the body.
		body := append(fieldHeader(100), 's', 'h', 'o', 'r', 't')
		return signedBodyFrame(opExec, body), false, nil
	case "too-many-fields":
		// 65 zero-length fields (warden MAX_FIELDS=64): rejected DURING
		// parsing, before Vec allocation can blow up.
		body := make([]byte, 0, 65*4)
		for i := 0; i < 65; i++ {
			body = append(body, fieldHeader(0)...)
		}
		return signedBodyFrame(opExec, body), false, nil
	case "mount-bad-mp":
		// Hostile mount_point: must be refused by the warden's pin.
		return frame(opMountAndExec,
			strField("/var/sandswap/volumes/sandfs-probe"), strField("/sys/fs/cgroup"),
			strField("none"), strField("echo pwned"), strField("0"), strField("0"),
			strField("flat")), false, nil
	case "unmount-bad-mp":
		// OP_UNMOUNT body-MAC fields are [mount_point, identity, forced];
		// pad the optional tail so the frame authenticates before dispatch
		// (the mount_point pin is what this scenario tests).
		return frame(opUnmount, strField("/proc"), strField(""), strField("0")), false, nil
	case "stall-body":
		// Claims an N-byte body and sends NOTHING else (no FIN): the warden
		// reserves the in-flight body budget and parks in read_exact. With
		// -hold the probe keeps the connection open, holding the reservation —
		// the shape a hostile in-guest peer would use. The warden's DoS bounds
		// must reject it past the budget/cap (probe then sees immediate EOF).
		if len(args) < 1 {
			return nil, false, fmt.Errorf("stall-body needs <bytes>")
		}
		n, e := strconv.ParseUint(args[0], 10, 32)
		if e != nil {
			return nil, false, fmt.Errorf("bad byte count: %v", e)
		}
		// Authenticated header, body never sent: exercises the warden's
		// in-flight body-budget reservation. An unauthenticated peer cannot
		// reach that reservation at all (the tag is verified first), which is
		// itself the first DoS bound.
		return signedHeaderOnly(opExec, uint32(n)), false, nil
	case "raw":
		if len(args) < 1 {
			return nil, false, fmt.Errorf("raw needs <hex>")
		}
		b, e := hex.DecodeString(strings.Join(args, ""))
		if e != nil {
			return nil, false, fmt.Errorf("bad hex: %v", e)
		}
		probeSigned = false
		return b, false, nil
	}
	return nil, false, fmt.Errorf("unknown mode %q", mode)
}

// deliverKey sends OP_KEY_DELIVERY and verifies the response tag with the
// delivered key. The request tag is zero (the warden has no key yet); the
// RESPONSE is tagged with the delivered key, so a verified read proves the
// warden installed it.
func deliverKey(fd int, key []byte) error {
	var nonce [nonceLen]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return fmt.Errorf("key-delivery nonce: %w", err)
	}
	body := fieldHeader(uint32(len(key)))
	body = append(body, key...)
	frame := make([]byte, reqHeaderLen+len(body))
	binary.BigEndian.PutUint32(frame[0:4], magic)
	frame[4] = protocolVersion
	frame[5] = opKeyDelivery
	binary.BigEndian.PutUint32(frame[6:10], uint32(len(body)))
	copy(frame[10:10+nonceLen], nonce[:])
	// frame[10+nonceLen:reqHeaderLen] stays zero: the warden has no key yet.
	copy(frame[reqHeaderLen:], body)
	if _, err := unix.Write(fd, frame); err != nil {
		return fmt.Errorf("key-delivery write: %w", err)
	}
	hdr := make([]byte, respHeaderLen)
	if _, err := io.ReadFull(unixFdReader{fd}, hdr); err != nil {
		return fmt.Errorf("key-delivery response: %w", err)
	}
	if m := binary.BigEndian.Uint32(hdr[0:4]); m != magic {
		return fmt.Errorf("key-delivery: bad response magic 0x%x", m)
	}
	if hdr[5] != 0 {
		return fmt.Errorf("key-delivery refused: code=%d", hdr[5])
	}
	stdoutLen := binary.BigEndian.Uint32(hdr[8:12])
	stderrLen := binary.BigEndian.Uint32(hdr[12:16])
	durNs := binary.BigEndian.Uint64(hdr[16:24])
	mountedLen := binary.BigEndian.Uint32(hdr[24:28])
	want := warden.ResponseTag(key, nonce[:], hdr[4], hdr[5], hdr[6], stdoutLen, stderrLen, durNs, mountedLen)
	if !hmac.Equal(hdr[28:60], want[:]) {
		return fmt.Errorf("key-delivery: response tag mismatch (key not installed?)")
	}
	bodyLen := stdoutLen + stderrLen + mountedLen
	if bodyLen > 0 {
		// Drain the response body (errors carry text) so the connection is
		// positioned at the next frame.
		if _, err := io.ReadFull(unixFdReader{fd}, make([]byte, bodyLen)); err != nil {
			return fmt.Errorf("key-delivery body: %w", err)
		}
	}
	// The mounted-identity MAC always trails the body (empty here).
	var mountedMAC [tagLen]byte
	if _, err := io.ReadFull(unixFdReader{fd}, mountedMAC[:]); err != nil {
		return fmt.Errorf("key-delivery mounted mac: %w", err)
	}
	wantMounted := warden.MountedTag(key, nonce[:], nil)
	if !hmac.Equal(mountedMAC[:], wantMounted[:]) {
		return fmt.Errorf("key-delivery: mounted-identity MAC mismatch")
	}
	return nil
}

func run(cid uint32, readWait time.Duration, hold time.Duration, mode string, args []string) error {
	if needsKey(mode) && len(probeKey) != 32 {
		return fmt.Errorf("mode %q is authenticated: pass -key <64 hex> or -state <state.json>", mode)
	}
	payload, fin, err := buildRequest(mode, args)
	if err != nil {
		return err
	}

	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM, 0)
	if err != nil {
		return fmt.Errorf("vsock socket: %w", err)
	}
	defer unix.Close(fd)
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{
		Sec:  int64(readWait / time.Second),
		Usec: int64((readWait % time.Second) / time.Microsecond),
	}); err != nil {
		return fmt.Errorf("SO_RCVTIMEO: %w", err)
	}
	if err := unix.Connect(fd, &unix.SockaddrVM{CID: cid, Port: wardenPort}); err != nil {
		return fmt.Errorf("connect %d:%d: %w", cid, wardenPort, err)
	}
	if needsKey(mode) && len(probeKey) == 32 {
		if err := deliverKey(fd, probeKey); err != nil {
			// The warden closes a connection it refuses (connection cap, body
			// budget, shutdown). Report the documented `eof` sentinel — the
			// DoS/connection-cap probes classify acceptance from it — instead
			// of a delivery-specific error.
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				fmt.Println("eof")
				return nil
			}
			return err
		}
	}

	if _, err := unix.Write(fd, payload); err != nil {
		return fmt.Errorf("write frame: %w", err)
	}
	if fin {
		if err := unix.Shutdown(fd, unix.SHUT_WR); err != nil {
			return fmt.Errorf("shutdown write: %w", err)
		}
	}

	// Hold the connection open (stall tests): the parked warden-side read
	// keeps its budget reservation for this duration. BEFORE sleeping, do an
	// early EOF check with a short receive timeout: a warden-side rejection
	// (connection cap / body budget) closes the connection immediately, and
	// without this check that EOF would only be observed after the hold —
	// making an accepted and a rejected stall indistinguishable meanwhile.
	if hold > 0 {
		if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{
			Sec:  0,
			Usec: 250 * 1000,
		}); err != nil {
			return fmt.Errorf("SO_RCVTIMEO(early): %w", err)
		}
		var one [1]byte
		if _, err := io.ReadFull(unixFdReader{fd}, one[:]); err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				// The warden closed us before we even parked: rejected.
				fmt.Println("eof")
				return nil
			}
			if !isTimeout(err) {
				return fmt.Errorf("early read: %w", err)
			}
			// Timeout = still open = accepted (parked).
		}
		// Restore the caller's receive timeout for the real read below.
		if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{
			Sec:  int64(readWait / time.Second),
			Usec: int64((readWait % time.Second) / time.Microsecond),
		}); err != nil {
			return fmt.Errorf("SO_RCVTIMEO(restore): %w", err)
		}
		time.Sleep(hold)
	}

	// Read the 28-byte response header (may legitimately never come).
	// [magic(4)][version(1)][code(1)][exit_code(1)][reserved(1)][stdout_len(4)]
	// [stderr_len(4)][exec_duration_ns(8)][mounted_len(4)] — mirrors the
	// warden client (sandlot/warden/client.go).
	hdr := make([]byte, respHeaderLen)
	if _, err := io.ReadFull(unixFdReader{fd}, hdr); err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			fmt.Println("eof")
			return nil
		}
		return fmt.Errorf("read response header: %w", err)
	}
	if m := binary.BigEndian.Uint32(hdr[0:4]); m != magic {
		return fmt.Errorf("bad response magic 0x%x", m)
	}
	stdoutLen := binary.BigEndian.Uint32(hdr[8:12])
	stderrLen := binary.BigEndian.Uint32(hdr[12:16])
	durNs := binary.BigEndian.Uint64(hdr[16:24])
	mountedLen := binary.BigEndian.Uint32(hdr[24:28])
	auth := "n/a"
	if probeSigned && len(probeKey) == 32 {
		want := warden.ResponseTag(probeKey, probeNonce[:], hdr[4], hdr[5], hdr[6], stdoutLen, stderrLen, durNs, mountedLen)
		if hmac.Equal(hdr[28:60], want[:]) {
			auth = "ok"
		} else {
			auth = "BAD"
		}
	}
	stdout := make([]byte, stdoutLen)
	stderr := make([]byte, stderrLen)
	mounted := make([]byte, mountedLen)
	if stdoutLen > 0 {
		if _, err := io.ReadFull(unixFdReader{fd}, stdout); err != nil {
			return fmt.Errorf("read stdout: %w", err)
		}
	}
	if stderrLen > 0 {
		if _, err := io.ReadFull(unixFdReader{fd}, stderr); err != nil {
			return fmt.Errorf("read stderr: %w", err)
		}
	}
	if mountedLen > 0 {
		if _, err := io.ReadFull(unixFdReader{fd}, mounted); err != nil {
			return fmt.Errorf("read mounted: %w", err)
		}
	}
	var mountedMAC [tagLen]byte
	if _, err := io.ReadFull(unixFdReader{fd}, mountedMAC[:]); err != nil {
		return fmt.Errorf("read mounted mac: %w", err)
	}
	if probeSigned && len(probeKey) == 32 {
		wantMounted := warden.MountedTag(probeKey, probeNonce[:], mounted)
		if !hmac.Equal(mountedMAC[:], wantMounted[:]) {
			auth += "+mounted-BAD"
		}
	}
	fmt.Printf("resp code=%d exit=%d stdout_len=%d stderr_len=%d mounted_len=%d dur_ns=%d auth=%s\n",
		hdr[5], hdr[6], stdoutLen, stderrLen, mountedLen, durNs, auth)
	printSide("stdout", stdout)
	printSide("stderr", stderr)
	printSide("mounted", mounted)
	return nil
}

// isTimeout reports whether a read error is a receive timeout (EAGAIN with a
// socket receive timeout set, or ETIMEDOUT).
func isTimeout(err error) bool {
	var errno unix.Errno
	if errors.As(err, &errno) {
		return errno == unix.EAGAIN || errno == unix.EWOULDBLOCK || errno == unix.ETIMEDOUT
	}
	return false
}

func printSide(name string, b []byte) {
	if len(b) == 0 {
		return
	}
	const max = 4096
	shown := b
	trunc := ""
	if len(b) > max {
		shown = b[:max]
		trunc = fmt.Sprintf(" (+%d more)", len(b)-max)
	}
	oneLine := strings.ReplaceAll(string(shown), "\n", "\\n")
	fmt.Printf("%s %s%s\n", name, strconv.Quote(oneLine), trunc)
}

// unixFdReader adapts a raw fd to io.Reader for io.ReadFull.
type unixFdReader struct{ fd int }

func (r unixFdReader) Read(p []byte) (int, error) {
	n, err := unix.Read(r.fd, p)
	if n == 0 && err == nil {
		return 0, io.EOF
	}
	return n, err
}

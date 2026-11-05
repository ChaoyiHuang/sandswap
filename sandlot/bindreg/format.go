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
// Package bindreg implements Sandswap's egress identity binding region: a
// node-local, versioned, lock-free readable shared memory region that maps a
// microVM's network attachment (TAP ifindex) to the agent identity currently
// mounted in it.
// This is the core enabler of the egress identity contract (see
// docs/how-it-works/egress-enabler.md): Sandswap guarantees the binding is
// published BEFORE guest code can run (write happens in the mount call stack,
// ahead of the exec dispatch) and revoked at unmount; third-party network
// policy enforcers read it either from kernel context (eBPF program map
// lookup, ns-level) or from userspace (mmap, no syscall), and must never
// classify traffic from a private cache.
// Layout contract (little-endian, stable per FormatVersion):
//	region: [header 4096B][slot ifindex=0][slot ifindex=1]...[slot MaxIfindex-1]
//	slot:   fixed 256B Entry, indexed directly by the TAP's interface index.
// The seqlock protocol: writers publish under a per-entry sequence counter
// (odd = update in progress); readers retry until they observe an even,
// unchanged sequence. Readers that never want to retry can instead compare
// against the header's monotonically increasing GlobalSeq to detect "anything
// changed anywhere" with one load.

package bindreg

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	// FormatVersion is the binding-region format version. Bumped on any
	// layout change; readers must verify before interpreting.
	FormatVersion uint32 = 1

	// DefaultMaxIfindex bounds the slot array (indexed by TAP ifindex).
	// Linux ifindexes grow monotonically with interface churn; the default
	// covers ~65k churn events per host uptime. The shm carrier is sparse
	// (only written slots cost memory); the BPF carrier allocates eagerly, so
	// the default keeps that allocation at 16MB. Raise for very long-lived
	// hosts with heavy interface churn; a publish beyond the bound fails safe
	// (enforcers default-deny unidentified attachments).
	DefaultMaxIfindex uint32 = 1 << 16

	// HeaderSize is the reserved region header (one page).
	HeaderSize uint32 = 4096

	// EntrySize is the fixed slot size. 256B keeps offsets page-friendly and
	// leaves room for future fields within the same FormatVersion only via a
	// version bump — do not grow it silently.
	EntrySize uint32 = 256

	// IDLen is the fixed width of agent/sandfs/vm identifier fields. Longer
	// identifiers are truncated by the writer and NUL-terminated when they fit.
	IDLen = 64

	// RegionMagic is the magic in both the header and (copy of) each entry,
	// so a reader that lands mid-region can sanity-check it found a Sandswap
	// binding region.
	RegionMagic uint32 = 0x53524231 // "1BRS" little-endian
)

// State is the identity state of one TAP attachment.
type State uint32

const (
	// StateUnbound: the attachment exists (VM live, TAP up) but no sandfs is
	// mounted. Guest egress from such a VM should be denied by the platform
	// baseline; an enforcer seeing it must not attribute traffic to anyone.
	StateUnbound State = 0
	// StateMounted: the listed agent/sandfs is mounted in this VM.
	StateMounted State = 1
)

// ErrStaleRead is returned by Lookup when the seqlock kept colliding with a
// writer past the retry budget. Callers should retry; torn reads are never
// returned.
var ErrStaleRead = errors.New("bindreg: seqlock read retries exhausted")

// ErrOutOfRange reports an ifindex at or above the region's MaxIfindex. The
// entry cannot exist; callers must treat the attachment as unidentified
// (default-deny per the contract).
type ErrOutOfRange struct{ Ifindex, Max uint32 }

func (e *ErrOutOfRange) Error() string {
	return fmt.Sprintf("bindreg: ifindex %d >= region max %d", e.Ifindex, e.Max)
}

// entry field offsets within a 256B slot. Exposed for the golden-bytes test
// and for third-party readers implementing the format in other languages.
//
// CRITICAL: the seqlock sequence lives at offSeq (248), OUTSIDE the payload
// word range [0, offSeq). Writers publish the payload with 8-byte atomic
// stores over [0, 248) and store the sequence separately — a payload write
// can never clobber the sequence, and the sequence can never be mistaken for
// payload. Do not move any field across this boundary.
const (
	offMagic        = 0
	offVersion      = 4
	offState        = 8
	offReserved0    = 12 // 4B reserved, written as zero
	offEpoch        = 16
	offAgentID      = 24
	offSandfsID     = 88
	offVMID         = 152
	offReservedTail = 216 // 32B reserved, written as zero
	offSeq          = 248 // seqlock sequence, isolated from payload words
	offEntryEnd     = 256
)

// header field offsets within the first page.
const (
	offHdrMagic    = 0
	offHdrVersion  = 4
	offHdrSize     = 8
	offHdrEntrySz  = 12
	offHdrMaxIdx   = 16
	offHdrReserved = 20
	offGlobalSeq   = 24
	offBackendTag  = 32 // 16B
	offHdrEnd      = HeaderSize
)

// putString writes s into buf as NUL-padded fixed-width field, truncating
// (without NUL) when too long — the same rule the contract documents for
// third-party readers.
func putString(buf []byte, s string) {
	clear(buf)
	copy(buf, s) // truncation is documented behavior; no error
}

// getString reads a NUL-terminated fixed-width field.
func getString(buf []byte) string {
	for i, b := range buf {
		if b == 0 {
			return string(buf[:i])
		}
	}
	return string(buf)
}

// encodeEntry renders an entry payload into a PRIVATE buffer (never the shared
// slot): the seqlock protocol requires the writer to store the odd
// (invalidating) sequence FIRST, then the payload, then the even (valid)
// sequence, and every payload byte must be written with atomic stores so the
// compiler cannot reorder them across the sequence stores. See region.go.
func encodeEntry(buf []byte, st State, epoch uint64, agentID, sandfsID, vmID string) {
	clear(buf[:offEntryEnd]) // zero everything first (reserved ranges included)
	binary.LittleEndian.PutUint32(buf[offMagic:], RegionMagic)
	binary.LittleEndian.PutUint32(buf[offVersion:], FormatVersion)
	binary.LittleEndian.PutUint32(buf[offState:], uint32(st))
	binary.LittleEndian.PutUint64(buf[offEpoch:], epoch)
	putString(buf[offAgentID:offAgentID+IDLen], agentID)
	putString(buf[offSandfsID:offSandfsID+IDLen], sandfsID)
	putString(buf[offVMID:offVMID+IDLen], vmID)
}

// decodeEntry parses a slot's payload. The caller must have validated the
// sequence number (even and unchanged) around this call.
func decodeEntry(slot []byte) (Entry, error) {
	if got := binary.LittleEndian.Uint32(slot[offMagic:]); got != RegionMagic {
		return Entry{}, fmt.Errorf("bindreg: bad entry magic 0x%08x", got)
	}
	if got := binary.LittleEndian.Uint32(slot[offVersion:]); got != FormatVersion {
		return Entry{}, fmt.Errorf("bindreg: entry format version %d, want %d", got, FormatVersion)
	}
	return Entry{
		State:      State(binary.LittleEndian.Uint32(slot[offState:])),
		MountEpoch: binary.LittleEndian.Uint64(slot[offEpoch:]),
		AgentID:    getString(slot[offAgentID : offAgentID+IDLen]),
		SandfsID:   getString(slot[offSandfsID : offSandfsID+IDLen]),
		VMID:       getString(slot[offVMID : offVMID+IDLen]),
	}, nil
}

// Entry is one attachment's published binding (decoded form).
type Entry struct {
	State      State
	MountEpoch uint64
	AgentID    string
	SandfsID   string
	VMID       string
}

// encodeHeader writes the region header.
func encodeHeader(hdr []byte, maxIfindex uint32, backendTag string) {
	clear(hdr[:offHdrEnd])
	binary.LittleEndian.PutUint32(hdr[offHdrMagic:], RegionMagic)
	binary.LittleEndian.PutUint32(hdr[offHdrVersion:], FormatVersion)
	binary.LittleEndian.PutUint32(hdr[offHdrSize:], HeaderSize)
	binary.LittleEndian.PutUint32(hdr[offHdrEntrySz:], EntrySize)
	binary.LittleEndian.PutUint32(hdr[offHdrMaxIdx:], maxIfindex)
	binary.LittleEndian.PutUint64(hdr[offGlobalSeq:], 0)
	putString(hdr[offBackendTag:offBackendTag+16], backendTag)
}

// verifyHeader validates an existing region's header against this build's
// expectations. Returns the region's MaxIfindex.
func verifyHeader(hdr []byte) (uint32, error) {
	if len(hdr) < int(offHdrEnd) {
		return 0, fmt.Errorf("bindreg: region too small for header (%d B)", len(hdr))
	}
	if got := binary.LittleEndian.Uint32(hdr[offHdrMagic:]); got != RegionMagic {
		return 0, fmt.Errorf("bindreg: bad region magic 0x%08x", got)
	}
	if got := binary.LittleEndian.Uint32(hdr[offHdrVersion:]); got != FormatVersion {
		return 0, fmt.Errorf("bindreg: region format version %d, want %d (reader/writer mismatch)", got, FormatVersion)
	}
	if got := binary.LittleEndian.Uint32(hdr[offHdrSize:]); got != HeaderSize {
		return 0, fmt.Errorf("bindreg: header size %d, want %d", got, HeaderSize)
	}
	if got := binary.LittleEndian.Uint32(hdr[offHdrEntrySz:]); got != EntrySize {
		return 0, fmt.Errorf("bindreg: entry size %d, want %d", got, EntrySize)
	}
	return binary.LittleEndian.Uint32(hdr[offHdrMaxIdx:]), nil
}

// entryOffset returns the byte offset of an ifindex slot within the region.
func entryOffset(ifindex uint32) int {
	return int(HeaderSize + ifindex*EntrySize)
}

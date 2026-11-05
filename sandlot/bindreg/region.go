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

package bindreg

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync/atomic"
	"unsafe"
)

// Region is an opened binding region: an mmap'd [header + slot array] shared
// with third-party enforcers. Both backends (shm file, BPF mmapable array
// map) produce byte-identical layouts; only Open/Close differ.
//
// A Region is safe for concurrent use. All writes go through the seqlock so
// cross-language readers never observe a torn entry (they retry instead).
type Region struct {
	data       []byte // whole mmap'd region
	maxIfindex uint32
	backendTag string
	readOnly   bool
	cleanup    func() error // backend-specific unmap/release
	closed     bool
}

// Config selects the backend and its parameters.
type Config struct {
	// Backend selects the carrier: BackendShm (default) or BackendBPF.
	Backend Backend
	// Path overrides the backend's default location (shm file path or bpffs
	// pin path). Empty = per-backend default.
	Path string
	// MaxIfindex bounds the slot array (0 = DefaultMaxIfindex). When opening
	// an existing region, MaxIfindex is taken from its header and this value
	// must match (or be 0), guarding against silent format drift.
	MaxIfindex uint32
	// ReadOnly opens the region for reading only (bindregdump, vendor
	// reference readers). The carrier is attached without creating anything
	// (an absent region fails; it is never created by a reader) and mapped
	// PROT_READ; the writer-side integrity checks (owner, mode) are skipped —
	// readers are governed by file permissions alone. Publish/Revoke/
	// Unregister on a read-only region return an error instead of faulting on
	// the read-only mapping.
	ReadOnly bool
}

// Backend names a region carrier.
type Backend string

const (
	BackendOff Backend = "off" // enabler disabled; all ops are no-ops
	BackendShm Backend = "shm" // tmpfs file (/dev/shm), openable by any local reader
	BackendBPF Backend = "bpf" // BPF_F_MMAPABLE array map pinned to bpffs
)

// Default paths per backend.
const (
	DefaultShmPath = "/dev/shm/sandswap-bindings"
	DefaultBPFPath = "/sys/fs/bpf/sandswap/bindings"
)

// Resolve normalizes zero-valued config fields to their defaults.
func (c Config) Resolve() Config {
	if c.Backend == "" {
		c.Backend = BackendShm
	}
	if c.MaxIfindex == 0 {
		c.MaxIfindex = DefaultMaxIfindex
	}
	if c.Path == "" {
		switch c.Backend {
		case BackendBPF:
			c.Path = DefaultBPFPath
		default:
			c.Path = DefaultShmPath
		}
	}
	return c
}

// maxIfindexCap caps configured slot counts so a config typo cannot attempt
// a multi-TB region (1<<22 slots = 1 GiB at EntrySize 256 — far beyond any
// ifindex churn a host can generate).
const maxIfindexCap uint32 = 1 << 22

// Open opens (creating if absent) the binding region described by cfg.
func Open(cfg Config) (*Region, error) {
	cfg = cfg.Resolve()
	if cfg.MaxIfindex > maxIfindexCap {
		return nil, fmt.Errorf("bindreg: MaxIfindex %d exceeds cap %d", cfg.MaxIfindex, maxIfindexCap)
	}
	switch cfg.Backend {
	case BackendOff:
		return nil, fmt.Errorf("bindreg: backend %q cannot be opened", BackendOff)
	case BackendShm:
		return openShm(cfg)
	case BackendBPF:
		return openBPF(cfg)
	default:
		return nil, fmt.Errorf("bindreg: unknown backend %q", cfg.Backend)
	}
}

// regionBytes is the total on-media/mapped size of a region with n slots.
func regionBytes(n uint32) uint64 {
	return uint64(HeaderSize) + uint64(n)*uint64(EntrySize)
}

// wrapRegion finalizes an opened region after the backend mapped the bytes.
// Two invariants are enforced unconditionally:
//  1. the config's MaxIfindex matches the region header (format-drift guard
//     — Resolve() substitutes DefaultMaxIfindex for 0, so default-config
//     restarts against a differently-sized region fail loudly instead of
//     misreading), and
//  2. the header's bound fits inside the mapped bytes (without this,
//     slot() could slice past the mmap on a header/mapping mismatch).
func wrapRegion(data []byte, cfg Config, backendTag string, cleanup func() error) (*Region, error) {
	maxIdx, err := verifyHeader(data)
	if err != nil {
		_ = cleanup()
		return nil, err
	}
	if cfg.MaxIfindex != maxIdx {
		_ = cleanup()
		return nil, fmt.Errorf("bindreg: existing region holds max_ifindex %d, config wants %d", maxIdx, cfg.MaxIfindex)
	}
	if regionBytes(maxIdx) > uint64(len(data)) {
		_ = cleanup()
		return nil, fmt.Errorf("bindreg: region header claims %d slots (%d B) but only %d B are mapped", maxIdx, regionBytes(maxIdx), len(data))
	}
	return &Region{
		data:       data,
		maxIfindex: maxIdx,
		backendTag: backendTag,
		readOnly:   cfg.ReadOnly,
		cleanup:    cleanup,
	}, nil
}

// Close unmaps the region and releases backend resources. The backing storage
// persists (other processes hold their own mappings); Close only releases this
// process's view. The shm file, once created, is intentionally NOT deleted on
// Close — enforcers may outlive a sandlot restart; operators remove it when
// decommissioning a node.
func (r *Region) Close() error {
	if r == nil || r.closed {
		return nil
	}
	r.closed = true
	return r.cleanup()
}

func (r *Region) checkClosed() error {
	if r.closed {
		return fmt.Errorf("bindreg: region is closed")
	}
	return nil
}

// checkWritable gates every mutating op: a ReadOnly region is mapped
// PROT_READ, so an unguarded write would not "fail" — it would SIGSEGV.
func (r *Region) checkWritable() error {
	if r.readOnly {
		return fmt.Errorf("bindreg: region was opened read-only")
	}
	return r.checkClosed()
}

func (r *Region) slot(ifindex uint32) ([]byte, error) {
	if ifindex >= r.maxIfindex {
		return nil, &ErrOutOfRange{Ifindex: ifindex, Max: r.maxIfindex}
	}
	off := entryOffset(ifindex)
	return r.data[off : off+int(EntrySize)], nil
}

// publishSeq wraps a payload write in the seqlock protocol:
//
//	seq := s+1 (odd, invalidates)  →  payload (atomic stores)  →  seq := s+2
//
// Both the sequence stores and every payload byte store are atomic: on amd64
// these compile to plain MOV/XCHG (zero added cost) while making it
// IMPOSSIBLE for the compiler or CPU to reorder payload writes across the
// sequence stores. Readers symmetrically atomic-load, so a torn read can only
// ever be detected (s1 != s2), never accepted.
func publishSeq(slot []byte, payload *[EntrySize]byte) {
	seqPtr := (*uint32)(unsafePtr(slot[offSeq:]))
	seq := atomic.LoadUint32(seqPtr)
	atomic.StoreUint32(seqPtr, seq+1) // odd: readers must retry
	// Payload words cover [0, offSeq) only — offSeq sits alone in the entry's
	// last word, so these stores can never touch the sequence (see format.go).
	for i := 0; i < int(offSeq); i += 8 {
		atomic.StoreUint64((*uint64)(unsafePtr(slot[i:])), binary.LittleEndian.Uint64(payload[i:]))
	}
	atomic.StoreUint32(seqPtr, seq+2) // even: payload is stable
}

// atomicReadSlot snapshots the whole slot with atomic 8-byte loads into a
// private buffer. Slots are 8-aligned by construction (page-aligned mmap +
// 256B stride).
func atomicReadSlot(slot []byte) [EntrySize]byte {
	var out [EntrySize]byte
	for i := 0; i < int(EntrySize); i += 8 {
		binary.LittleEndian.PutUint64(out[i:], atomic.LoadUint64((*uint64)(unsafePtr(slot[i:]))))
	}
	return out
}

// Publish atomically sets slot[ifindex] to the mounted state with the given
// identity. It is the mount-path write: one seqlocked store set plus one
// global-counter bump — no syscalls, ~0.2µs.
func (r *Region) Publish(ifindex uint32, e Entry) error {
	if err := r.checkWritable(); err != nil {
		return err
	}
	slot, err := r.slot(ifindex)
	if err != nil {
		return err
	}
	var p [EntrySize]byte
	encodeEntry(p[:], StateMounted, e.MountEpoch, e.AgentID, e.SandfsID, e.VMID)
	publishSeq(slot, &p)
	r.bumpGlobalSeq()
	return nil
}

// Revoke atomically flips slot[ifindex] back to StateUnbound, clearing the
// identity fields (state=unbound is what enforcers key on; a stale identity
// string on an unbound attachment must never be attributable). This is the
// unmount-path write: one seqlocked store set.
func (r *Region) Revoke(ifindex uint32) error {
	if err := r.checkWritable(); err != nil {
		return err
	}
	slot, err := r.slot(ifindex)
	if err != nil {
		return err
	}
	var epoch uint64
	if e, ok, lerr := r.Lookup(ifindex); lerr == nil && ok {
		epoch = e.MountEpoch
	}
	var p [EntrySize]byte
	encodeEntry(p[:], StateUnbound, epoch, "", "", "")
	publishSeq(slot, &p)
	r.bumpGlobalSeq()
	return nil
}

// Unregister zeroes slot[ifindex] entirely — the attachment is gone (TAP
// destroyed / VM destroyed). After this, Lookup reports "no entry".
func (r *Region) Unregister(ifindex uint32) error {
	if err := r.checkWritable(); err != nil {
		return err
	}
	slot, err := r.slot(ifindex)
	if err != nil {
		return err
	}
	publishSeq(slot, &[EntrySize]byte{})
	r.bumpGlobalSeq()
	return nil
}

// Lookup reads slot[ifindex] through the seqlock retry loop. ok=false means
// "no entry" (never written, or zeroed by Unregister).
func (r *Region) Lookup(ifindex uint32) (e Entry, ok bool, err error) {
	if err := r.checkClosed(); err != nil {
		return Entry{}, false, err
	}
	slot, err := r.slot(ifindex)
	if err != nil {
		return Entry{}, false, err
	}
	for try := 0; try < seqlockRetries; try++ {
		s1 := atomic.LoadUint32((*uint32)(unsafePtr(slot[offSeq:])))
		if s1&1 != 0 {
			continue // writer mid-update
		}
		snap := atomicReadSlot(slot)
		if binary.LittleEndian.Uint32(snap[offMagic:]) != RegionMagic {
			return Entry{}, false, nil // never written
		}
		e, derr := decodeEntry(snap[:])
		s2 := atomic.LoadUint32((*uint32)(unsafePtr(slot[offSeq:])))
		if derr == nil && s1 == s2 {
			return e, true, nil
		}
		// Torn or mid-write: retry.
	}
	return Entry{}, false, ErrStaleRead
}

// GlobalSeq returns the region-wide change counter. Enforcer pollers read this
// single value to detect "anything changed anywhere" before rescanning slots.
func (r *Region) GlobalSeq() uint64 {
	return atomic.LoadUint64((*uint64)(unsafePtr(r.data[offGlobalSeq:])))
}

func (r *Region) bumpGlobalSeq() {
	atomic.AddUint64((*uint64)(unsafePtr(r.data[offGlobalSeq:])), 1)
}

// seqlockRetries bounds a reader's retry loop under a hypothetical endlessly
// writing publisher. Generous because a publish is two stores (~ns).
const seqlockRetries = 64

// MaxIfindex returns the region's slot count bound.
func (r *Region) MaxIfindex() uint32 { return r.maxIfindex }

// unsafePtr converts a byte slice offset to a pointer for atomic access at a
// computed offset (the atomic package's typed helpers need addressable
// variables; slice elements are addressable, but the offset arithmetic is
// dynamic, so we go through unsafe.Pointer).
func unsafePtr(b []byte) unsafe.Pointer {
	return unsafe.Pointer(&b[0])
}

// ResolveIfindex maps a TAP interface name to its kernel ifindex (the slot
// key). Callers should resolve once per attachment and cache the result.
func ResolveIfindex(tapName string) (uint32, error) {
	iface, err := net.InterfaceByName(tapName)
	if err != nil {
		return 0, fmt.Errorf("bindreg: interface %q: %w", tapName, err)
	}
	if iface.Index <= 0 {
		return 0, fmt.Errorf("bindreg: interface %q has invalid ifindex %d", tapName, iface.Index)
	}
	return uint32(iface.Index), nil
}

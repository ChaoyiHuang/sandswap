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
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/unix"
)

// The BPF carrier: a BPF_MAP_TYPE_ARRAY created with BPF_F_MMAPABLE and pinned
// to bpffs. The array is keyed by TAP ifindex (key_size=4) with EntrySize
// values, so the mmap'd map memory is byte-identical to the shm carrier's
// layout — one parser serves both. The region header shares the map's first
// HeaderSize bytes (= HeaderSize/EntrySize entries), keeping slot i for
// ifindex i at offset HeaderSize + i*EntrySize exactly like the shm file.
//
// Writers go through the mmap directly — no bpf() syscall per publish (~0.2µs
// of memory stores). Kernel-context readers (tc/XDP/LSM programs) do a plain
// array lookup; userspace readers mmap the pinned file.
//
// Requirements and caveats:
//   - kernel ≥ 5.5 (BPF_F_MMAPABLE) and CAP_BPF/CAP_SYS_ADMIN to CREATE.
//   - BPF array maps allocate all entries eagerly: the region costs
//     MaxIfindex*EntrySize of real memory (16MB at the default), unlike the
//     sparse tmpfs carrier.
//   - Sandlot in embedded mode is privileged. In k8s boxout mode boxout (UID 0
//     sidecar) creates + chmods the pin path and unprivileged sandlot writes
//     through the mmap — verify the bpffs permission model on the target
//     kernel before relying on that (contract doc, deployment notes).

// bpfMapCreateAttr mirrors the kernel's union bpf_attr prefix for
// BPF_MAP_CREATE (the kernel zero-fills anything beyond the caller's size, so
// passing exactly this prefix is valid on every supported kernel).
type bpfMapCreateAttr struct {
	mapType               uint32
	keySize               uint32
	valueSize             uint32
	maxEntries            uint32
	mapFlags              uint32
	innerMapFd            uint32
	numaNode              uint32
	mapName               [16]byte
	mapIfindex            uint32
	btfFd                 uint32
	btfKeyTypeID          uint32
	btfValueTypeID        uint32
	btfVmlinuxValueTypeID uint32
}

// bpfObjAttr mirrors union bpf_attr for BPF_OBJ_PIN / BPF_OBJ_GET. The path
// buffer must live OUTSIDE this struct: the kernel validates that all bytes
// beyond its known union prefix are zero, and a path inside the attr would
// trip that check (E2BIG).
type bpfObjAttr struct {
	pathname  uint64
	bpfFd     uint32
	fileFlags uint32
}

func sysBPF(cmd uintptr, attr unsafe.Pointer, size uintptr) (uintptr, error) {
	r1, _, errno := unix.Syscall(unix.SYS_BPF, cmd, uintptr(attr), size)
	if errno != 0 {
		return r1, errno
	}
	return r1, nil
}

func createMmapableArray(keySize, valueSize, maxEntries uint32, name string) (int, error) {
	var attr bpfMapCreateAttr
	attr.mapType = unix.BPF_MAP_TYPE_ARRAY
	attr.keySize = keySize
	attr.valueSize = valueSize
	attr.maxEntries = maxEntries
	attr.mapFlags = unix.BPF_F_MMAPABLE
	copy(attr.mapName[:], name) // kernel limit: 15 chars + NUL
	fd, err := sysBPF(unix.BPF_MAP_CREATE, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
	if err != nil {
		return 0, err
	}
	return int(fd), nil
}

// bpfObjGetOrPin pins fd at path (BPF_OBJ_PIN) or, when something is already
// pinned there (previous sandlot run), opens the existing object
// (BPF_OBJ_GET) so a restart re-attaches to the live region instead of
// failing on an occupied path — closing the freshly created fd in that case
// (the freshly created map is NOT the live region). BPF_OBJ_PIN returns 0 on
// success (it is NOT a file descriptor — do not close it); the caller keeps
// holding whichever fd is returned.
func bpfObjGetOrPin(fd int, path string) (int, error) {
	var attr bpfObjAttr
	var pathBuf [unix.PathMax]byte
	n := copy(pathBuf[:], path)
	if n >= len(pathBuf) {
		return 0, fmt.Errorf("bindreg: bpf path %q too long", path)
	}
	attr.pathname = uint64(uintptr(unsafe.Pointer(&pathBuf[0])))
	attr.bpfFd = uint32(fd)
	if _, err := sysBPF(unix.BPF_OBJ_PIN, unsafe.Pointer(&attr), unsafe.Sizeof(attr)); err == nil {
		return fd, nil
	} else if err != unix.EEXIST {
		return 0, fmt.Errorf("bindreg: pin %s: %w", path, err)
	}
	// OBJ_GET requires bpf_fd = 0 (kernels validate this); the pinned file
	// itself determines the object type.
	attr.bpfFd = 0
	opened, err := sysBPF(unix.BPF_OBJ_GET, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
	if err != nil {
		return 0, fmt.Errorf("bindreg: open pinned %s: %w", path, err)
	}
	if int(opened) != fd {
		_ = unix.Close(fd) // drop the orphaned fresh map; the pinned one is live
	}
	return int(opened), nil
}

// objGetPinned opens an already-pinned object (BPF_OBJ_GET with bpf_fd = 0 —
// kernels validate that the fd is zero for this command).
//
// Access semantics worth remembering: BPF_OBJ_GET accepts file_flags=0 only
// (BPF_F_RDONLY/BPF_F_WRONLY are rejected) and the open is O_RDWR — a caller
// needs BOTH read and write permission on the bpffs file, and the fd then
// permits mmap PROT_WRITE and BPF_MAP_UPDATE_ELEM. There is no read-only fd
// on a pin: DAC on a pin is all-or-nothing ("can open" = "can forge"), which
// is why the k8s boxout handoff is chown(sandlot)+0660 and why group bits on
// a pin are write grants, never read-only sharing (docs/deployment/prerequisites.md).
func objGetPinned(path string) (int, error) {
	var attr bpfObjAttr
	var pathBuf [unix.PathMax]byte
	if n := copy(pathBuf[:], path); n >= len(pathBuf) {
		return 0, fmt.Errorf("bindreg: bpf path %q too long", path)
	}
	attr.pathname = uint64(uintptr(unsafe.Pointer(&pathBuf[0])))
	opened, err := sysBPF(unix.BPF_OBJ_GET, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
	if err != nil {
		return 0, err
	}
	return int(opened), nil
}

// checkBPFPinOwnership validates the PIN's bpffs file before its map is used
// as a WRITE target: ownership must be root or this process (never a foreign
// identity — a pin is an all-or-nothing write grant, so a foreign owner can
// forge every published identity), it must not be world-writable, and a
// group-write bit is accepted only for the documented same-group handoff
// (boxout chowns the pin to the sandlot uid/gid, whose group IS the opener's
// egid). The stat is symlink-refusing: bpffs pins are regular files, so a
// symlink is a refusal.
func checkBPFPinOwnership(path string) error {
	var st unix.Stat_t
	if err := unix.Fstatat(unix.AT_FDCWD, path, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return fmt.Errorf("bindreg: stat pinned region %s: %w", path, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return fmt.Errorf("bindreg: pinned region %s is not a regular file (mode %04o) — refusing a symlink or special file", path, st.Mode&0o7777)
	}
	if st.Uid != 0 && st.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("bindreg: pinned region %s is owned by uid %d, this process runs as euid %d — a foreign-owned pin can forge every published identity; remove it and let the deployment's privileged side recreate it", path, st.Uid, os.Geteuid())
	}
	if st.Mode&0o002 != 0 {
		return fmt.Errorf("bindreg: pinned region %s is world-writable (mode %04o) — the write set must be the owner (plus the documented shared group); fix with chmod 0640/0660", path, st.Mode&0o7777)
	}
	if st.Mode&0o020 != 0 && st.Gid != uint32(os.Getegid()) {
		return fmt.Errorf("bindreg: pinned region %s is group-writable (mode %04o) for gid %d, which is not this process's egid %d — refusing a cross-group write grant", path, st.Mode&0o7777, st.Gid, os.Getegid())
	}
	return nil
}

// openBPF opens (or creates+pins) the binding region as a BPF_F_MMAPABLE
// array map and maps its memory. A ReadOnly open never creates: it attaches
// to the pin a writer made, and maps PROT_READ.
func openBPF(cfg Config) (*Region, error) {
	// +HeaderSize/EntrySize entries hold the region header ahead of the slots.
	totalEntries := int(cfg.MaxIfindex + HeaderSize/EntrySize)
	mapSize := EntrySize * uint32(totalEntries)

	var fd int
	if cfg.ReadOnly {
		// Readers never create: attach to the pinned map its writer made.
		// (Also the right shape for an unprivileged reader — no CAP_BPF
		// attempt that could only fail.) Readers run NONE of the ownership/
		// mode gates below: those are write-grant controls (a pin is an
		// all-or-nothing write grant), and a reader never writes — who may
		// READ is bpffs DAC's job, the same posture as the shm carrier.
		// The writer-side gate stays the anti-squatting control (a squatted
		// pin is refused at the sandlot's startup open, loudly), and the
		// header verification in wrapRegion rejects structurally foreign
		// maps before any slot is decoded.
		var err error
		if fd, err = objGetPinned(cfg.Path); err != nil {
			return nil, fmt.Errorf("bindreg: open pinned region %s: %w", cfg.Path, err)
		}
	} else {
		// BPF_OBJ_PIN does NOT create parent directories inside bpffs — a pin
		// at /sys/fs/bpf/sandswap/bindings fails with ENOENT unless sandswap/
		// exists. Best-effort: the CREATOR role (root/embedded, or the
		// privileged boxout sidecar) needs this; the unprivileged opener (k8s
		// boxout-mode sandlot) merely OBJ_GETs a map the sidecar pre-created,
		// and may lack the bpffs permissions to stat/mkdir — its failure must
		// not fail the open.
		_ = os.MkdirAll(filepath.Dir(cfg.Path), 0o711)
		var err error
		fd, err = createMmapableArray(4, EntrySize, uint32(totalEntries), "sandswap_bind")
		if err != nil {
			// Unprivileged opener (k8s/boxout mode: sandlot has no CAP_BPF
			// while the privileged boxout sidecar created + pinned + chmod'ed
			// the region): fall back to attaching to the pinned map. Access
			// to the mapping is then governed by the bpffs file's permission
			// bits.
			fd2, gerr := objGetPinned(cfg.Path)
			if gerr != nil {
				return nil, fmt.Errorf("bindreg: cannot create mmapable array map (%v; kernel ≥5.5 + CAP_BPF required) and cannot open pinned region %s: %w", err, cfg.Path, gerr)
			}
			fd = fd2
		} else {
			var perr error
			if fd, perr = bpfObjGetOrPin(fd, cfg.Path); perr != nil {
				return nil, perr
			}
		}
		// The pin (fresh or pre-existing) is now the live region: verify the
		// bpffs file's owner/mode before trusting it as the write target.
		if err := checkBPFPinOwnership(cfg.Path); err != nil {
			_ = unix.Close(fd)
			return nil, err
		}
	}
	cleanupClose := func() error { return unix.Close(fd) }

	prot := unix.PROT_READ | unix.PROT_WRITE
	if cfg.ReadOnly {
		prot = unix.PROT_READ
	}
	data, err := unix.Mmap(fd, 0, int(mapSize), prot, unix.MAP_SHARED)
	if err != nil {
		_ = cleanupClose()
		return nil, fmt.Errorf("bindreg: mmap bpf map %s: %w", cfg.Path, err)
	}

	// Fresh map memory is zero: stamp the header. A pre-existing pinned region
	// keeps its header, and wrapRegion verifies it below.
	if !cfg.ReadOnly && binary.LittleEndian.Uint32(data[offHdrMagic:]) == 0 {
		encodeHeader(data, cfg.MaxIfindex, string(BackendBPF))
	}

	return wrapRegion(data, cfg, string(BackendBPF), func() error {
		_ = unix.Close(fd)
		return unix.Munmap(data)
	})
}

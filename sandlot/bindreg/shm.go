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
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// shmFileMode is the region file's permission: owner rw, group r — enough
// for a co-located vendor enforcer running under a dedicated group, while
// other users get nothing. Operators widen it deliberately if their enforcer
// runs under a different account.
const shmFileMode = 0o640

// openShm opens (or creates) the binding region as a file on a tmpfs
// filesystem (/dev/shm by default). Any local reader with file permissions can
// mmap it read-only — this is the zero-dependency carrier for third-party
// enforcers, and the carrier used by CI/tests (no BPF stack required).
//
// Write-integrity model: the writer (sandlot) is the file's owner and the
// ONLY writer — enforcers need read, never write. Because the default path
// lives in a world-writable sticky directory (/dev/shm), the writer verifies
// after open that it owns the file and that no group/world write bit is set:
// a file pre-created (or symlinked) there by another local user before
// sandlot's first start would otherwise make sandlot publish every agent
// identity into memory that user owns and can rewrite — attribution forgery
// at the enforcers. Both checks fail loudly with remediation; O_NOFOLLOW
// closes the symlink variant outright. Readers (ReadOnly) skip these checks —
// who may read is DAC's job, not the reader's.
//
// The file is created 0640 and intentionally NOT deleted on Close: enforcers
// may outlive a sandlot restart, and the region doubles as the restart
// snapshot (a fresh sandlot re-opens the same file and rewrites it).
func openShm(cfg Config) (*Region, error) {
	regionSize := int64(regionBytes(cfg.MaxIfindex))

	// A WRITER's file-level owner/mode checks below do not cover the directory
	// holding the file: directory write alone is enough to unlink or replace
	// an entry, whatever the file's own mode says. The parent must be
	// root-owned and either closed to group/other write or root-owned STICKY
	// (the /dev/shm shape, where only an entry's owner or root may remove it).
	// Readers skip this: who may read is DAC's job, and a reader never creates
	// or replaces the region.
	if !cfg.ReadOnly {
		if err := checkRegionParent(cfg.Path); err != nil {
			return nil, err
		}
	}

	// O_NOFOLLOW: a symlink planted at the region path must fail loudly,
	// never redirect the writer into someone else's file.
	flags := unix.O_RDWR | unix.O_CREAT | unix.O_NOFOLLOW
	prot := unix.PROT_READ | unix.PROT_WRITE
	if cfg.ReadOnly {
		flags = unix.O_RDONLY | unix.O_NOFOLLOW
		prot = unix.PROT_READ
	}
	fd, err := unix.Open(cfg.Path, flags, shmFileMode)
	if err != nil {
		return nil, fmt.Errorf("bindreg: open %s: %w", cfg.Path, err)
	}
	cleanupClose := func() error { return unix.Close(fd) }

	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		_ = cleanupClose()
		return nil, fmt.Errorf("bindreg: stat %s: %w", cfg.Path, err)
	}

	if cfg.ReadOnly {
		// Reader: the region must already exist, fully sized by its writer.
		if st.Size == 0 {
			_ = cleanupClose()
			return nil, fmt.Errorf("bindreg: %s is empty — no writer has created the region", cfg.Path)
		}
		if st.Size != regionSize {
			_ = cleanupClose()
			return nil, fmt.Errorf("bindreg: %s holds %d B, want %d B (MaxIfindex mismatch or foreign file)", cfg.Path, st.Size, regionSize)
		}
	} else {
		// Writer: verify we own what we opened, and that it is not writable
		// by anyone else — the write set must be exactly this process (the
		// squatting/pre-creation threat in the comment above).
		if st.Uid != uint32(os.Geteuid()) {
			_ = cleanupClose()
			return nil, fmt.Errorf("bindreg: %s is owned by uid %d, this process runs as euid %d — refusing a foreign-owned region (pre-creation squatting: its owner could read and forge every published identity); remove the file and restart", cfg.Path, st.Uid, os.Geteuid())
		}
		if st.Mode&0o022 != 0 {
			_ = cleanupClose()
			return nil, fmt.Errorf("bindreg: %s is group/world-writable (mode %04o) — the write set must be the owner only; fix with chmod 0640", cfg.Path, st.Mode&0o777)
		}
		if st.Size == 0 {
			if err := unix.Ftruncate(int(fd), regionSize); err != nil {
				_ = cleanupClose()
				return nil, fmt.Errorf("bindreg: ftruncate %s to %d: %w", cfg.Path, regionSize, err)
			}
		} else if st.Size != regionSize {
			_ = cleanupClose()
			return nil, fmt.Errorf("bindreg: %s holds %d B, want %d B (MaxIfindex mismatch or foreign file)", cfg.Path, st.Size, regionSize)
		}
		// Normalize the mode regardless of the creating process's umask (a
		// restrictive umask would silently strip the vendor group's read bit).
		if err := unix.Fchmod(int(fd), shmFileMode); err != nil {
			_ = cleanupClose()
			return nil, fmt.Errorf("bindreg: chmod %s to %04o: %w", cfg.Path, shmFileMode, err)
		}
	}

	data, err := unix.Mmap(int(fd), 0, int(regionSize), prot, unix.MAP_SHARED)
	if err != nil {
		_ = cleanupClose()
		return nil, fmt.Errorf("bindreg: mmap %s: %w", cfg.Path, err)
	}

	existed := st.Size != 0
	if !existed && !cfg.ReadOnly {
		encodeHeader(data, cfg.MaxIfindex, string(BackendShm))
	}
	if !cfg.ReadOnly {
		// fsync the header/sizes so a crash right after first creation cannot
		// leave a zero-length file behind (the file lives on disk-backed tmpfs
		// swap paths in some deployments).
		_ = unix.Fsync(int(fd))
	}
	_ = unix.Close(fd) // mapping keeps the file alive

	r, err := wrapRegion(data, cfg, string(BackendShm), func() error {
		return unix.Munmap(data)
	})
	if err != nil {
		return nil, err
	}
	return r, nil
}

// ShmRegionSize reports the on-"disk" size a shm region for maxIfindex slots
// occupies. Exposed for deployment tooling and tests.
func ShmRegionSize(maxIfindex uint32) int64 {
	return int64(HeaderSize + maxIfindex*EntrySize)
}

// checkRegionParent validates the directory holding the shm region. The
// writer's post-open owner/mode check cannot see a directory that a local user
// can write: unlinking or renaming the region needs directory permission, not
// file permission. Root-owned is required so the check itself cannot be
// configured away by the writer identity; the sticky exemption is the
// world-writable-but-root-owned /dev/shm default, where only an entry's owner
// (the writer) or root may remove it.
func checkRegionParent(path string) error {
	dir := filepath.Dir(path)
	var st unix.Stat_t
	if err := unix.Stat(dir, &st); err != nil {
		return fmt.Errorf("bindreg: stat region parent %s: %w", dir, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return fmt.Errorf("bindreg: region parent %s is not a directory", dir)
	}
	if st.Uid != 0 {
		return fmt.Errorf("bindreg: region parent %s is owned by uid %d, not root — a local user who owns the directory can unlink or replace the region regardless of the file's own mode; point the carrier at a root-owned directory (or the sticky /dev/shm default)", dir, st.Uid)
	}
	if st.Mode&0o022 != 0 && st.Mode&unix.S_ISVTX == 0 {
		return fmt.Errorf("bindreg: region parent %s is group/world-writable (mode %04o) without the sticky bit — any local user could replace the region; use a root-owned sticky directory (e.g. /dev/shm) or a closed root-owned one", dir, st.Mode&0o7777)
	}
	return nil
}

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

// Package runtime holds the boxout sidecar's process-level startup plumbing:
// the listening socket lifecycle (private directory, bounded bind retry,
// verified handoff to the sandlot identity), the per-pod admission token,
// the one-instance-per-sandbox-root lock, the host memory budget, the
// sandvmm supplementary-group resolution, and the shared-config hot-reload
// watcher. main() stays wiring-only.

package runtime

import (
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

// PrepareSocketDir creates and validates the boxout socket directory: it must
// be a directory this (root) identity owns and no other identity can write
// (0711 = traverse only). A shared or non-root-owned directory would let a
// same-UID process replace the socket entry at will.
func PrepareSocketDir(dir string) error {
	if err := os.MkdirAll(dir, 0o711); err != nil {
		return fmt.Errorf("create: %w", err)
	}
	// MkdirAll honors the umask; normalize explicitly.
	if err := os.Chmod(dir, 0o711); err != nil {
		return fmt.Errorf("chmod: %w", err)
	}
	var st unix.Stat_t
	if err := unix.Lstat(dir, &st); err != nil {
		return fmt.Errorf("lstat: %w", err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return fmt.Errorf("%s is not a directory", dir)
	}
	if st.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("%s is owned by uid %d, not the boxout identity %d — the socket must live in a directory only the sidecar can write", dir, st.Uid, os.Geteuid())
	}
	if st.Mode&0o022 != 0 {
		return fmt.Errorf("%s is group/world-writable (mode %04o) — a same-UID process could replace the socket entry; use a boxout-private directory", dir, st.Mode&0o7777)
	}
	return nil
}

// ListenWithRetry binds the Unix socket with a bounded retry. A boxout restart
// racing the previous instance's teardown (the listener takes a moment to
// release the path) must not crash-loop the sidecar.
func ListenWithRetry(path string, logger *log.Logger) (net.Listener, error) {
	var lastErr error
	for attempt := 0; attempt < 5; attempt++ {
		lis, err := net.Listen("unix", path)
		if err == nil {
			return lis, nil
		}
		lastErr = err
		logger.Printf("listen %s (attempt %d/5): %v", path, attempt+1, err)
		time.Sleep(time.Duration(attempt+1) * 100 * time.Millisecond)
	}
	return nil, lastErr
}

// SecureListeningSocket hands the freshly bound socket to the sandlot identity
// 0600 and VERIFIES the result. Every operation is relative to an O_NOFOLLOW
// directory fd, never a path that resolves from /run: fchmod(2) on the
// listener's own descriptor would act on the sockfs inode, not the filesystem
// entry, so the directory-relative fchownat/fchmodat plus the inode-identity
// post-check is the fd-relative form that actually covers the entry. A
// mismatch (the entry was replaced between bind and chmod) fails startup.
func SecureListeningSocket(path string, uid int, logger *log.Logger) error {
	name := filepath.Base(path)
	dirFD, err := unix.Open(filepath.Dir(path), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open socket dir (no-follow): %w", err)
	}
	defer unix.Close(dirFD)
	var before unix.Stat_t
	if err := unix.Fstatat(dirFD, name, &before, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return fmt.Errorf("stat socket (no-follow): %w", err)
	}
	if before.Mode&unix.S_IFMT != unix.S_IFSOCK {
		return fmt.Errorf("%s is not a socket (mode %04o)", path, before.Mode&0o7777)
	}
	if err := unix.Fchownat(dirFD, name, uid, uid, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return fmt.Errorf("chown socket: %w", err)
	}
	if err := unix.Fchmodat(dirFD, name, 0o600, 0); err != nil {
		return fmt.Errorf("chmod socket: %w", err)
	}
	var after unix.Stat_t
	if err := unix.Fstatat(dirFD, name, &after, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return fmt.Errorf("stat socket after chmod: %w", err)
	}
	if after.Ino != before.Ino || after.Dev != before.Dev {
		return fmt.Errorf("socket entry at %s was replaced during permission setup (inode %d→%d) — refusing to serve", path, before.Ino, after.Ino)
	}
	if after.Mode&unix.S_IFMT != unix.S_IFSOCK || after.Uid != uint32(uid) || after.Mode&0o777 != 0o600 {
		return fmt.Errorf("socket %s is mode %04o uid %d after setup, want 0600 uid %d", path, after.Mode&0o7777, after.Uid, uid)
	}
	logger.Printf("socket %s: mode 0600 owner uid %d (verified)", path, uid)
	return nil
}

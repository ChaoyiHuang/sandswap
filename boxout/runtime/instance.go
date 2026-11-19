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

package runtime

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// HostMemoryLimitMB derives the default aggregate cap: 80% of MemTotal.
// 0 on an unreadable /proc/meminfo (the count limit still applies).
func HostMemoryLimitMB() uint64 {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				if kb, err := strconv.ParseUint(fields[1], 10, 64); err == nil {
					return kb / 1024 * 8 / 10
				}
			}
			break
		}
	}
	return 0
}

// AcquireInstanceLock enforces one boxout per sandbox root.
//
// boxout owns host-global state for its root — VM API sockets, host-side
// overlay mounts, the /proc re-adopt scan — so a second instance aimed at the
// same root would race every one of those. The lock file lives in the PRIVATE
// per-instance state root (/run/sandswap-state/<tag>, root-owned 0710), which
// the unprivileged sandlot cannot write; the descriptor is validated (regular
// file, owned by this identity, mode 0600) before the flock, so a file planted
// at the lock path makes the start fail closed instead of being "locked
// through". The file's CONTENT is written for operator diagnostics only and is
// never read or used for a decision.
func AcquireInstanceLock(stateRoot, sandboxRoot string, logger *log.Logger) (*os.File, error) {
	if err := os.MkdirAll(stateRoot, 0o710); err != nil {
		return nil, fmt.Errorf("boxout lock: create %s: %w", stateRoot, err)
	}
	rfd, err := unix.Open(stateRoot, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("boxout lock: open state root %s (no-follow): %w", stateRoot, err)
	}
	defer unix.Close(rfd)
	var rst unix.Stat_t
	if err := unix.Fstat(rfd, &rst); err != nil {
		return nil, fmt.Errorf("boxout lock: fstat state root: %w", err)
	}
	if rst.Mode&unix.S_IFMT != unix.S_IFDIR || rst.Uid != uint32(os.Geteuid()) {
		return nil, fmt.Errorf("boxout lock: state root %s is not a directory owned by uid %d (mode %04o, uid %d) — refusing to lock in it",
			stateRoot, os.Geteuid(), rst.Mode&0o777, rst.Uid)
	}

	const lockName = "boxout.lock"
	fd, err := unix.Openat(rfd, lockName, unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("boxout lock: open %s/%s (no-follow): %w", stateRoot, lockName, err)
	}
	keep := false
	defer func() {
		if !keep {
			unix.Close(fd)
		}
	}()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, fmt.Errorf("boxout lock: fstat lock file: %w", err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, fmt.Errorf("boxout lock: %s/%s is not a regular file (mode %04o)", stateRoot, lockName, st.Mode&0o777)
	}
	if st.Uid != uint32(os.Geteuid()) {
		return nil, fmt.Errorf("boxout lock: %s/%s is owned by uid %d, not the writer uid %d — refusing to use it",
			stateRoot, lockName, st.Uid, os.Geteuid())
	}
	if err := unix.Fchmod(fd, 0o600); err != nil {
		return nil, fmt.Errorf("boxout lock: chmod lock file: %w", err)
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, fmt.Errorf("another boxout instance already manages %s (lock %s/%s is held) — one boxout per sandbox root",
				sandboxRoot, stateRoot, lockName)
		}
		return nil, fmt.Errorf("boxout lock: flock: %w", err)
	}

	// Diagnostic line only (see the function comment): content is never read.
	_ = unix.Ftruncate(fd, 0)
	_, _ = syscall.Write(fd, []byte(fmt.Sprintf("%d|%s\n", os.Getpid(), sandboxRoot)))

	keep = true
	path := filepath.Join(stateRoot, lockName)
	logger.Printf("instance lock held for sandbox root %s (%s)", sandboxRoot, path)
	return os.NewFile(uintptr(fd), path), nil
}

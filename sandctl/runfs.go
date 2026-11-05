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

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
	"time"
	"unsafe"
)

// The agent-key cache lives under --run-dir, a directory the invoking user
// controls. A same-uid writer can replace entries there (or plant a symlink),
// so the cache is never read or written through a name-only path: the run root
// is anchored once with O_DIRECTORY|O_NOFOLLOW, every descendant is opened
// with openat2(RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS), and files are published
// with a temp file + renameat so the destination is replaced, never followed
// or truncated in place.

// openat2(2) plumbing. The syscall number is the generic syscall table entry
// (identical on the 64-bit architectures sandctl is built for); the resolve
// flags are the stable uapi values from include/uapi/linux/openat2.h.
const (
	sysOpenat2        = 437
	resolveNoSymlinks = 0x04
	resolveBeneath    = 0x08
	// oPath is O_PATH (Linux 2.6.39+): open for descriptor operations only.
	// The stdlib syscall package does not export it.
	oPath = 0x200000
)

// maxRunFileBytes bounds reads from client files. The agent cache and the
// deployer's client contract are tiny; anything larger is not a file this
// tool wrote.
const maxRunFileBytes = 1 << 20

// openHow mirrors struct open_how.
type openHow struct {
	Flags   uint64
	Mode    uint64
	Resolve uint64
}

// openat2Beneath opens a single path component below dirfd, refusing symlinks
// anywhere in the resolution (RESOLVE_NO_SYMLINKS) and escapes
// (RESOLVE_BENEATH). mode is applied only for O_CREAT/O_TMPFILE (openat2
// rejects a nonzero mode otherwise).
func openat2Beneath(dirfd int, name string, flags int, mode uint32) (int, error) {
	if !validRunComponent(name) {
		return -1, fmt.Errorf("invalid run path component %q", name)
	}
	p, err := syscall.BytePtrFromString(name)
	if err != nil {
		return -1, err
	}
	how := openHow{Flags: uint64(flags) | syscall.O_CLOEXEC, Resolve: resolveBeneath | resolveNoSymlinks}
	if flags&syscall.O_CREAT != 0 {
		how.Mode = uint64(mode)
	} else if mode != 0 {
		return -1, fmt.Errorf("mode must be zero without O_CREAT for %q", name)
	}
	fd, _, errno := syscall.Syscall6(sysOpenat2, uintptr(dirfd), uintptr(unsafe.Pointer(p)),
		uintptr(unsafe.Pointer(&how)), unsafe.Sizeof(how), 0, 0)
	if errno != 0 {
		return -1, &os.PathError{Op: "openat2", Path: name, Err: errno}
	}
	return int(fd), nil
}

// validRunComponent accepts exactly one plain path element: no separators, no
// NUL, no "." or "..". Every helper operates on a single component below an
// already-anchored directory, so this is the whole path grammar.
func validRunComponent(s string) bool {
	if s == "" || s == "." || s == ".." {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] == '/' || s[i] == 0 {
			return false
		}
	}
	return true
}

// openRunRoot anchors the cache root. A symlinked run dir is refused — the
// whole point of the anchor is that later operations cannot be redirected by
// a name another writer can replace.
func openRunRoot(runDir string, create bool) (*os.File, error) {
	if runDir == "" {
		return nil, errors.New("empty run dir")
	}
	if create {
		if err := os.MkdirAll(runDir, 0o700); err != nil {
			return nil, err
		}
	}
	fd, err := syscall.Open(runDir, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open run root %s (no-follow): %w", runDir, err)
	}
	return os.NewFile(uintptr(fd), runDir), nil
}

// openRunFile opens one file below an anchored directory without following a
// symlink. Callers that read untrusted entry types also pass O_NONBLOCK so a
// planted FIFO cannot block the open.
func openRunFile(dir *os.File, name string, flags int, mode uint32) (*os.File, error) {
	fd, err := openat2Beneath(int(dir.Fd()), name, flags, mode)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}

// lstatRunEntry returns the entry's metadata WITHOUT following a symlink (an
// O_PATH descriptor + fstat). The error is ENOENT when the entry is absent.
func lstatRunEntry(dir *os.File, name string) (os.FileInfo, error) {
	f, err := openRunFile(dir, name, oPath|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return f.Stat()
}

// readRunFile reads one small regular file below dir. Symlinks, FIFOs, device
// nodes and oversized entries are refused by name instead of blocking or
// reading through them.
func readRunFile(dir *os.File, name string, max int64) ([]byte, os.FileInfo, error) {
	f, err := openRunFile(dir, name, syscall.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, st, fmt.Errorf("%s is not a regular file (mode %s)", name, st.Mode())
	}
	if st.Size() > max {
		return nil, st, fmt.Errorf("%s is %d bytes, above the %d-byte cap", name, st.Size(), max)
	}
	data, err := io.ReadAll(io.LimitReader(f, max))
	if err != nil {
		return nil, st, err
	}
	return data, st, nil
}

// writeRunFileAtomic publishes data at dir/name via a temp file + renameat.
// renameat replaces whatever entry currently carries the name (a planted
// symlink included) instead of resolving through it, and the temp file is
// created O_EXCL|O_NOFOLLOW so an occupied temp name can never redirect the
// write. chown is applied to the temp descriptor before the rename, so the
// published file already carries its final owner.
func writeRunFileAtomic(dir *os.File, name string, data []byte, mode os.FileMode, uid, gid int, chown bool) error {
	tmp := fmt.Sprintf(".%s.tmp-%d-%d", name, os.Getpid(), time.Now().UnixNano())
	f, err := openRunFile(dir, tmp, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	published := false
	defer func() {
		if !published {
			_ = syscall.Unlinkat(int(dir.Fd()), tmp)
		}
	}()
	if chown {
		// Best-effort: an unprivileged caller can only chown to itself (a
		// no-op success), a root caller re-homes the file for the sudo user.
		_ = f.Chown(uid, gid)
	}
	if err := f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := syscall.Renameat(int(dir.Fd()), tmp, int(dir.Fd()), name); err != nil {
		return fmt.Errorf("publish %s: %w", name, err)
	}
	published = true
	return nil
}

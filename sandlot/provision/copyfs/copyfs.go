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

// Package copyfs implements the in-process equivalent of `cp -a src/. dst/`
// used by the storage plane. It exists so materialization and template save
// do not spawn a host `cp` (PATH surface + process cost); the copy semantics
// are the same archive copy the volume seeder has always used.
//
// The source tree is walked through directory file descriptors, never through
// paths: a component exchanged for a symlink between the classification and
// the open cannot redirect the copy outside the tree that was anchored at the
// start. Entries are copied by type — regular files, directories and symlinks
// only — so socket/FIFO/device nodes in a tenant volume can neither fail a
// backup nor block the copier.
package copyfs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// DefaultMaxFileBytes caps one regular file's APPARENT size in an archive
// copy. It bounds the damage a tenant-created sparse file can do when its
// volume is saved as a template: io.Copy materializes holes as zeros, so the
// apparent size is exactly how much data the destination receives. Overridable
// through provision.max_sparse_bytes.
const DefaultMaxFileBytes int64 = 8 << 30

// DefaultMaxEntries caps how many directory entries one copy may process (the
// same ceiling OCI layer extraction applies). The free-space budget alone
// admits millions of empty files — each one an inode on shared storage — so a
// tenant-built tree of tiny entries must fail loudly instead of filling the
// metadata store. Overridable through Limits.
const DefaultMaxEntries int64 = 1 << 20

// DefaultMaxDepth caps directory nesting. A rootfs is a handful of levels
// deep; anything past this is a pathological tree whose only effect is to make
// traversal unbounded. Overridable through Limits.
const DefaultMaxDepth = 128

// readdirBatch is how many names are pulled from a directory at a time. The
// walk must not slurp a guest-controlled directory wholesale (a flat volume can
// hold millions of names) — entries are counted and processed in bounded
// batches instead.
const readdirBatch = 256

// Limits bounds one archive copy. The zero value is usable (every cap takes
// its default).
type Limits struct {
	// MaxFileBytes caps one file's apparent size; 0 = DefaultMaxFileBytes, a
	// negative value disables the per-file cap (trusted sources such as
	// operator-provided templates).
	MaxFileBytes int64
	// MaxEntries caps the total entries processed; 0 = DefaultMaxEntries.
	// There is deliberately no "unlimited" form: the cap IS the protection.
	MaxEntries int64
	// MaxDepth caps directory nesting; 0 = DefaultMaxDepth.
	MaxDepth int
	// RootMode, when non-zero, is the mode of the TOP-LEVEL destination
	// directory, independent of the source root's mode. SaveAsTemplate uses
	// 0700 so the copy window under the shared template store is not
	// group-writable (the tree is normalized to the layer contract before
	// publish).
	RootMode os.FileMode
}

func (l Limits) maxFileBytes() int64 {
	if l.MaxFileBytes == 0 {
		return DefaultMaxFileBytes
	}
	return l.MaxFileBytes
}

func (l Limits) maxEntries() int64 {
	if l.MaxEntries <= 0 {
		return DefaultMaxEntries
	}
	return l.MaxEntries
}

func (l Limits) maxDepth() int {
	if l.MaxDepth <= 0 {
		return DefaultMaxDepth
	}
	return l.MaxDepth
}

// CopyDirRecursive copies srcDir into dstDir, preserving permissions and
// mtimes, and makes every entry GROUP-WRITABLE (dirs also setgid). The volume
// is shared between the service identities — the creating identity seeds it,
// sandvmm serves it and the agent writes through it — so seeded content must
// carry group access or the agent could not modify template files (e.g.,
// resolv.conf injection, package state). Ownership is NOT copied from the
// template (its root:root entries would be unwritable for the service
// identities); entries stay owned by the creating identity, and the setgid
// volume root keeps the group consistent.
// Equivalent to: cp -a srcDir/. dstDir/ + chmod -R g+rwX,g+s on dirs.
func CopyDirRecursive(srcDir, dstDir string) error {
	return CopyDirRecursiveContext(context.Background(), srcDir, dstDir)
}

// CopyDirRecursiveContext is CopyDirRecursive with a cancellation point: the
// storage plane moves GBs and a wire deadline that has already fired must be
// able to stop the copy.
func CopyDirRecursiveContext(ctx context.Context, srcDir, dstDir string) error {
	// Volume seeding copies operator-provided template content, not tenant
	// content: no per-file apparent-size cap (the free-space budget still
	// applies).
	return copyDir(ctx, srcDir, dstDir, true, Limits{MaxFileBytes: -1})
}

// CopyDirArchive is the plain archive copy (cp -a): permissions (including
// setuid/setgid/sticky), mtimes and symlinks are preserved exactly, with no
// group-write normalization. Use it where the destination has its own mode
// contract (template layers are normalized separately).
func CopyDirArchive(srcDir, dstDir string) error {
	return CopyDirArchiveContext(context.Background(), srcDir, dstDir)
}

// CopyDirArchiveContext is CopyDirArchive with a cancellation point.
func CopyDirArchiveContext(ctx context.Context, srcDir, dstDir string) error {
	return copyDir(ctx, srcDir, dstDir, false, Limits{})
}

// CopyDirArchiveContextLimit is CopyDirArchiveContext with explicit limits.
// Use it when the source is tenant-controlled (SaveAsTemplate).
func CopyDirArchiveContextLimit(ctx context.Context, srcDir, dstDir string, limits Limits) error {
	return copyDir(ctx, srcDir, dstDir, false, limits)
}

func copyDir(ctx context.Context, srcDir, dstDir string, groupWritable bool, limits Limits) error {
	absSrcRoot, err := filepath.Abs(srcDir)
	if err != nil {
		return err
	}
	// Anchor the source root on an fd. Every later lookup is relative to a
	// directory fd opened from this one, so replacing a path component with a
	// symlink cannot make the walk read a file outside the anchored tree.
	rootFD, err := unix.Open(srcDir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return &os.PathError{Op: "open", Path: srcDir, Err: err}
	}
	defer unix.Close(rootFD)

	var st unix.Stat_t
	if err := unix.Fstat(rootFD, &st); err != nil {
		return &os.PathError{Op: "fstat", Path: srcDir, Err: err}
	}
	if err := mkdirDestination(dstDir, &st, groupWritable); err != nil {
		return err
	}
	// The top-level directory's mode may be FIXED by the caller instead of
	// copied from the source (SaveAsTemplate stages under a template store the
	// FUSE daemon's group can write: the copy window must not be).
	if limits.RootMode != 0 {
		if err := os.Chmod(dstDir, limits.RootMode); err != nil {
			return err
		}
	}
	budget, err := copyBudget(dstDir)
	if err != nil {
		return err
	}
	walk := &copyWalk{budget: budget, maxEntries: limits.maxEntries(), maxDepth: limits.maxDepth()}
	return copyDirFD(ctx, rootFD, srcDir, dstDir, absSrcRoot, groupWritable, limits, walk, 0)
}

// copyBudget returns how many bytes a copy may write into dstDir's
// filesystem, leaving a reserve so one save cannot fill the shared store.
// The destination exists by the time this runs.
func copyBudget(dstDir string) (int64, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(dstDir, &st); err != nil {
		return 0, &os.PathError{Op: "statfs", Path: dstDir, Err: err}
	}
	bsize := int64(st.Bsize)
	if bsize <= 0 {
		bsize = 4096
	}
	avail := uint64(st.Bavail) * uint64(bsize)
	reserve := avail / 20
	if reserve < 256<<20 {
		reserve = 256 << 20
	}
	if avail <= reserve {
		return 0, fmt.Errorf("copyfs: destination %s has %d bytes available, below the copy reserve", dstDir, avail)
	}
	budget := avail - reserve
	if budget > math.MaxInt64 {
		budget = math.MaxInt64
	}
	return int64(budget), nil
}

// copyWalk carries one copy's remaining free-space budget and its traversal
// bounds. A single instance is threaded through the whole recursion.
type copyWalk struct {
	budget     int64
	entries    int64
	maxEntries int64
	maxDepth   int
}

// copyDirFD copies the entries of the directory open at dirFD into dstDir,
// which already exists with the source directory's mode. Names are pulled in
// bounded batches and counted against the entry cap as they are processed.
func copyDirFD(ctx context.Context, dirFD int, srcDir, dstDir, absSrcRoot string, groupWritable bool, limits Limits, walk *copyWalk, depth int) error {
	if depth > walk.maxDepth {
		return fmt.Errorf("copyfs: %s is nested deeper than the %d-level copy limit", absSrcRoot, walk.maxDepth)
	}
	return walkDirNames(dirFD, func(name string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		walk.entries++
		if walk.entries > walk.maxEntries {
			return fmt.Errorf("copyfs: copy of %s exceeds the %d-entry limit", absSrcRoot, walk.maxEntries)
		}
		srcPath := filepath.Join(srcDir, name)
		dstPath := filepath.Join(dstDir, name)

		var st unix.Stat_t
		if err := unix.Fstatat(dirFD, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			// A concurrently removed entry is not a copy failure: the source
			// volume is live tenant content. Names never contain '/', so the
			// name is a single component.
			if errors.Is(err, unix.ENOENT) {
				slog.Warn("copyfs: source entry vanished during copy; skipped", "path", srcPath)
				return nil
			}
			return &os.PathError{Op: "fstatat", Path: srcPath, Err: err}
		}

		switch st.Mode & unix.S_IFMT {
		case unix.S_IFDIR:
			return copySubdir(ctx, dirFD, name, srcPath, dstPath, absSrcRoot, groupWritable, limits, walk, depth)
		case unix.S_IFLNK:
			return copySymlink(dirFD, name, srcPath, dstPath, absSrcRoot, groupWritable, &st)
		case unix.S_IFREG:
			return copyRegular(ctx, dirFD, name, srcPath, dstPath, groupWritable, limits, walk)
		default:
			// Sockets, FIFOs and device nodes are tenant-plantable content that
			// has no business in a template layer. Skipping them keeps a save
			// from failing (AF_UNIX sockets open with ENXIO) or hanging (FIFO
			// opens block) on them.
			slog.Warn("copyfs: skipping special file", "path", srcPath,
				"mode", "0"+strconvOctal(st.Mode))
			return nil
		}
	})
}

func copySubdir(ctx context.Context, dirFD int, name, srcPath, dstPath, absSrcRoot string, groupWritable bool, limits Limits, walk *copyWalk, depth int) error {
	childFD, err := unix.Openat(dirFD, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		// The entry changed type between fstatat and open (replaced by a
		// symlink or removed). Skip it; the open is what makes a symlink
		// substitution harmless rather than followed.
		if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR) {
			slog.Warn("copyfs: source directory changed during copy; skipped", "path", srcPath, "err", err)
			return nil
		}
		return &os.PathError{Op: "openat", Path: srcPath, Err: err}
	}
	defer unix.Close(childFD)

	var st unix.Stat_t
	if err := unix.Fstat(childFD, &st); err != nil {
		return &os.PathError{Op: "fstat", Path: srcPath, Err: err}
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		slog.Warn("copyfs: source entry is no longer a directory; skipped", "path", srcPath)
		return nil
	}
	if err := mkdirDestination(dstPath, &st, groupWritable); err != nil {
		return err
	}
	return copyDirFD(ctx, childFD, srcPath, dstPath, absSrcRoot, groupWritable, limits, walk, depth+1)
}

func copySymlink(dirFD int, name, srcPath, dstPath, absSrcRoot string, groupWritable bool, st *unix.Stat_t) error {
	buf := make([]byte, 4096)
	n, err := unix.Readlinkat(dirFD, name, buf)
	if err != nil {
		if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.EINVAL) {
			// Removed or exchanged for a non-symlink since fstatat.
			slog.Warn("copyfs: source symlink changed during copy; skipped", "path", srcPath)
			return nil
		}
		return &os.PathError{Op: "readlinkat", Path: srcPath, Err: err}
	}
	target := string(buf[:n])

	// Preserve symlinks whose target resolves inside the source rootfs, skip
	// ones that escape it. Interpretation differs by form:
	//   - ABSOLUTE targets ("/usr/bin/mawk") resolve inside the guest chroot
	//     against the sandfs rootfs itself (<rootfs>/usr/bin/mawk), so they are
	//     safe exactly when they stay under srcDir after cleaning. Distro
	//     templates require them (/bin -> usr/bin, /etc/alternatives/*) —
	//     dropping or aborting on them would make every standard rootfs
	//     unusable.
	//   - RELATIVE targets ("../../etc/x") resolve against the link's own
	//     directory at copy time, so escaping ones could point at host files
	//     if anything ever follows them host-side.
	// Escaping links are skipped with a warning rather than failing the whole
	// seeding: their content does not exist in the sandbox anyway, so the
	// copied rootfs stays correct without the dangling entry.
	var resolved string
	if filepath.IsAbs(target) {
		resolved = filepath.Join(absSrcRoot, target)
	} else {
		resolved = filepath.Join(filepath.Dir(srcPath), target)
	}
	absResolved, _ := filepath.Abs(resolved)
	if !strings.HasPrefix(absResolved, absSrcRoot+string(os.PathSeparator)) && absResolved != absSrcRoot {
		slog.Warn("copyfs: skipping symlink escaping source rootfs",
			"symlink", srcPath, "target", target)
		return nil
	}
	if err := os.Symlink(target, dstPath); err != nil {
		return err
	}
	if !groupWritable {
		_ = os.Lchown(dstPath, int(st.Uid), int(st.Gid))
	}
	return nil
}

func copyRegular(ctx context.Context, dirFD int, name, srcPath, dstPath string, groupWritable bool, limits Limits, walk *copyWalk) error {
	// O_NONBLOCK makes the open harmless if the entry was exchanged for a
	// FIFO after the fstatat; the fstat on the returned fd then rejects
	// anything that is not a regular file.
	fd, err := unix.Openat(dirFD, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		switch {
		case errors.Is(err, unix.ENOENT), errors.Is(err, unix.ELOOP), errors.Is(err, unix.ENXIO):
			slog.Warn("copyfs: source file changed during copy; skipped", "path", srcPath, "err", err)
			return nil
		}
		return &os.PathError{Op: "openat", Path: srcPath, Err: err}
	}
	srcF := os.NewFile(uintptr(fd), srcPath)
	defer srcF.Close()

	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return &os.PathError{Op: "fstat", Path: srcPath, Err: err}
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		slog.Warn("copyfs: source entry is no longer a regular file; skipped", "path", srcPath)
		return nil
	}

	if st.Size < 0 {
		return fmt.Errorf("copyfs: %s reports a negative size", srcPath)
	}
	if max := limits.maxFileBytes(); max > 0 && st.Size > max {
		return fmt.Errorf("copyfs: %s is %d bytes, exceeding the %d-byte apparent-size cap (provision.max_sparse_bytes)", srcPath, st.Size, max)
	}
	// Charge the copy budget by the LARGER of the apparent size and the
	// allocated blocks. io.Copy materializes holes (so apparent size bounds the
	// bytes written) while a preallocated file can occupy more than its logical
	// length — taking the max counts both shapes instead of underwriting one.
	charge := st.Size
	if physical := st.Blocks * 512; physical > charge {
		charge = physical
	}
	if walk != nil && charge > walk.budget {
		return fmt.Errorf("copyfs: %s needs %d bytes, exceeding the destination's remaining copy budget of %d bytes", srcPath, charge, walk.budget)
	}

	statMode := os.FileMode(st.Mode)
	perm := statMode.Perm()
	dstF, err := os.OpenFile(dstPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	n, err := io.Copy(dstF, contextReader{ctx: ctx, r: srcF})
	if err != nil {
		dstF.Close()
		return err
	}
	if walk != nil {
		walk.budget -= n
	}
	if err := dstF.Close(); err != nil {
		return err
	}
	// Archive mode mirrors cp -a's ownership preservation (best-effort, see
	// the directory branch). Chown BEFORE chmod: chown clears setuid/setgid on
	// Linux.
	if !groupWritable {
		_ = os.Chown(dstPath, int(st.Uid), int(st.Gid))
	}
	want := statMode
	if groupWritable {
		// Group-writable and world-INVISIBLE: preserve the owner/group
		// execute bits the content needs (0644→0660, 0755→0770) while
		// clearing the other bits — `mode | 0o060` kept 0664/0775.
		want = (perm &^ 0o007) | 0o660
	}
	if err := os.Chmod(dstPath, want); err != nil {
		return err
	}
	times := []syscall.Timeval{
		{Sec: st.Atim.Sec, Usec: st.Atim.Nsec / 1000},
		{Sec: st.Mtim.Sec, Usec: st.Mtim.Nsec / 1000},
	}
	_ = syscall.Utimes(dstPath, times)
	return nil
}

func mkdirDestination(dstPath string, st *unix.Stat_t, groupWritable bool) error {
	statMode := os.FileMode(st.Mode)
	if err := os.MkdirAll(dstPath, statMode.Perm()); err != nil {
		return err
	}
	// Archive mode mirrors cp -a's ownership preservation (best-effort: an
	// unprivileged materializer cannot chown to a foreign uid, and the group
	// bits the normalization adds keep the layer readable). Chown BEFORE
	// chmod: chown clears setuid/setgid on Linux.
	if !groupWritable {
		_ = os.Chown(dstPath, int(st.Uid), int(st.Gid))
	}
	want := statMode
	if groupWritable {
		// Volume directories are EXACTLY 2770: owner+group rwx, setgid (so
		// new entries inherit the shared group), and no other bits.
		want = os.FileMode(0o2770) | os.ModeSetgid
	}
	return os.Chmod(dstPath, want)
}

// walkDirNames streams a directory's entries through fn in bounded batches.
// The dup exists because os.File takes ownership of the fd it is given; the
// walk keeps its own. Streaming (not Readdirnames(-1)) keeps a guest-controlled
// directory with millions of names from being materialized as one slice before
// the entry cap can reject it.
func walkDirNames(dirFD int, fn func(name string) error) error {
	dupFD, err := unix.Dup(dirFD)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(dupFD), "copyfs-dir")
	if f == nil {
		unix.Close(dupFD)
		return errors.New("copyfs: cannot wrap directory fd")
	}
	defer f.Close()
	for {
		names, rerr := f.Readdirnames(readdirBatch)
		for _, name := range names {
			if ferr := fn(name); ferr != nil {
				return ferr
			}
		}
		if rerr == io.EOF {
			return nil
		}
		if rerr != nil {
			return rerr
		}
	}
}

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (c contextReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}

func strconvOctal(v uint32) string {
	const digits = "01234567"
	if v == 0 {
		return "0"
	}
	var b [12]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = digits[v&7]
		v >>= 3
	}
	return string(b[i:])
}

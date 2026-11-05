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

package copyfs

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestCopyDirRecursivePreservesArchiveShape(t *testing.T) {
	src := t.TempDir()
	dst := t.TempDir()
	if err := os.MkdirAll(filepath.Join(src, "sub"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "sub", "file"), []byte("payload"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("sub/file", filepath.Join(src, "link")); err != nil {
		t.Fatal(err)
	}
	if err := CopyDirRecursive(src, dst); err != nil {
		t.Fatalf("CopyDirRecursive: %v", err)
	}

	b, err := os.ReadFile(filepath.Join(dst, "sub", "file"))
	if err != nil || string(b) != "payload" {
		t.Fatalf("copied file = %q, %v", b, err)
	}
	st, err := os.Stat(filepath.Join(dst, "sub", "file"))
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm()&0o060 != 0o060 {
		t.Fatalf("file mode = %o, want group-writable", st.Mode().Perm())
	}
	dstDir, err := os.Stat(filepath.Join(dst, "sub"))
	if err != nil {
		t.Fatal(err)
	}
	if dstDir.Mode()&os.ModeSetgid == 0 {
		t.Fatalf("dir mode = %o, want setgid", dstDir.Mode())
	}
	if target, err := os.Readlink(filepath.Join(dst, "link")); err != nil || target != "sub/file" {
		t.Fatalf("symlink = %q, %v; want sub/file", target, err)
	}
}

func TestCopyDirArchivePreservesExactModes(t *testing.T) {
	src := t.TempDir()
	dst := t.TempDir()
	if err := os.MkdirAll(filepath.Join(src, "private"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "private", "secret"), []byte("s"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := CopyDirArchive(src, dst); err != nil {
		t.Fatalf("CopyDirArchive: %v", err)
	}
	st, err := os.Stat(filepath.Join(dst, "private"))
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o750 {
		t.Fatalf("dir mode = %o, want 750", st.Mode().Perm())
	}
	st, err = os.Stat(filepath.Join(dst, "private", "secret"))
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o640 {
		t.Fatalf("file mode = %o, want 640", st.Mode().Perm())
	}
}

func TestCopyDirRecursiveSkipsEscapingSymlink(t *testing.T) {
	src := t.TempDir()
	dst := t.TempDir()
	if err := os.Symlink("../../etc/passwd", filepath.Join(src, "escape")); err != nil {
		t.Fatal(err)
	}
	if err := CopyDirRecursive(src, dst); err != nil {
		t.Fatalf("CopyDirRecursive: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dst, "escape")); !os.IsNotExist(err) {
		t.Fatalf("escaping symlink was copied (err=%v)", err)
	}
}

// A symlink in the source tree is never followed: an absolute link is copied
// as a link (it is interpreted inside the guest rootfs, never dereferenced on
// the host), a relative link escaping the source rootfs is dropped, and no
// target content is ever copied.
func TestCopyDirArchiveNeverFollowsSymlinkedDirectory(t *testing.T) {
	outside := t.TempDir()
	secret := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(secret, []byte("HOST SECRET"), 0o600); err != nil {
		t.Fatal(err)
	}
	src := t.TempDir()
	dst := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(src, "hostdir")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../../etc/passwd", filepath.Join(src, "escape-rel")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "plain.txt"), []byte("ok"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := CopyDirArchive(src, dst); err != nil {
		t.Fatalf("CopyDirArchive: %v", err)
	}

	st, err := os.Lstat(filepath.Join(dst, "hostdir"))
	if err != nil {
		t.Fatalf("absolute symlink was not preserved: %v", err)
	}
	if st.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("hostdir was materialized as %v, want a symlink", st.Mode())
	}
	if target, err := os.Readlink(filepath.Join(dst, "hostdir")); err != nil || target != outside {
		t.Fatalf("hostdir target = %q, %v; want %q", target, err, outside)
	}
	if _, err := os.Lstat(filepath.Join(dst, "escape-rel")); !os.IsNotExist(err) {
		t.Fatalf("escaping relative symlink was published (err=%v)", err)
	}
	if _, err := os.Stat(filepath.Join(dst, "plain.txt")); err != nil {
		t.Fatalf("regular file missing: %v", err)
	}

	// No file content may have been pulled through a link.
	err = filepath.Walk(dst, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.Mode().IsRegular() && info.Name() == "secret.txt" {
			t.Fatalf("symlink target content copied to %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// Sockets and FIFOs are tenant-plantable content that must neither fail the
// copy (AF_UNIX opens with ENXIO) nor block it (a FIFO open blocks).
func TestCopyDirArchiveSkipsSpecialFiles(t *testing.T) {
	src := t.TempDir()
	dst := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(src, "fifo"), 0o600); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("unix", filepath.Join(src, "sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := os.WriteFile(filepath.Join(src, "file.txt"), []byte("content"), 0o644); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() { done <- CopyDirArchive(src, dst) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("CopyDirArchive: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("CopyDirArchive blocked on a special file")
	}
	if _, err := os.Stat(filepath.Join(dst, "file.txt")); err != nil {
		t.Fatalf("regular file missing: %v", err)
	}
	for _, name := range []string{"fifo", "sock"} {
		if _, err := os.Lstat(filepath.Join(dst, name)); !os.IsNotExist(err) {
			t.Fatalf("special file %s was copied (err=%v)", name, err)
		}
	}
}

// An in-flight deadline must stop a large copy instead of holding a provision
// slot past the wire deadline.
func TestCopyDirArchiveContextCancellation(t *testing.T) {
	src := t.TempDir()
	dst := t.TempDir()
	for i := 0; i < 200; i++ {
		if err := os.WriteFile(filepath.Join(src, "f"+strconv.Itoa(i)), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := CopyDirArchiveContext(ctx, src, dst); err == nil {
		t.Fatal("copy with a cancelled context returned nil")
	}
}

// A tenant volume can contain a sparse file whose apparent size is enormous.
// io.Copy materializes the hole as zeros, so the apparent-size cap is what
// keeps SaveAsTemplate from filling shared storage.
func TestCopyDirArchiveLimitRejectsSparseHole(t *testing.T) {
	src := t.TempDir()
	dst := t.TempDir()
	f, err := os.Create(filepath.Join(src, "hole"))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(1 << 30); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	err = CopyDirArchiveContextLimit(context.Background(), src, dst, Limits{MaxFileBytes: 1 << 20})
	if err == nil {
		t.Fatal("1 GiB sparse file accepted under a 1 MiB cap")
	}
	if !strings.Contains(err.Error(), "apparent-size cap") {
		t.Fatalf("error = %v, want the apparent-size cap named", err)
	}
}

func TestCopyDirArchiveLimitRejectsOversizeFile(t *testing.T) {
	src := t.TempDir()
	dst := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "big"), make([]byte, 100), 0o644); err != nil {
		t.Fatal(err)
	}
	err := CopyDirArchiveContextLimit(context.Background(), src, dst, Limits{MaxFileBytes: 10})
	if err == nil {
		t.Fatal("100-byte file accepted under a 10-byte cap")
	}
	if !strings.Contains(err.Error(), "apparent-size cap") {
		t.Fatalf("error = %v, want the apparent-size cap named", err)
	}
}

func TestCopyDirArchiveLimitAllowsFilesUnderCap(t *testing.T) {
	src := t.TempDir()
	dst := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "small"), []byte("0123456789"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := CopyDirArchiveContextLimit(context.Background(), src, dst, Limits{MaxFileBytes: 100}); err != nil {
		t.Fatalf("file under the cap rejected: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dst, "small"))
	if err != nil || string(got) != "0123456789" {
		t.Fatalf("copied content = %q, %v", got, err)
	}
}

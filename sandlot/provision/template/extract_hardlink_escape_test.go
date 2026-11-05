// Copyright 2026 Chaoyi Huang. All rights reserved.
//
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE file at the root of this repository.

package template

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

// A later regular-file entry with the same name as an earlier symlink must
// REPLACE the link (tar semantics), not write through it and not fail. The
// fix unlinks the link before the O_NOFOLLOW create; this pins both the
// security property and the layer-replacement compatibility.
func TestExtractTarGzRegularFileReplacesSymlink(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "vol")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Simulate a prior layer's file that the symlink points at.
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("ORIGINAL"), 0o644); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	add := func(h *tar.Header, data string) {
		t.Helper()
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if data != "" {
			if _, err := tw.Write([]byte(data)); err != nil {
				t.Fatal(err)
			}
		}
	}
	add(&tar.Header{Name: "x", Typeflag: tar.TypeSymlink, Linkname: "victim", Mode: 0777}, "")
	add(&tar.Header{Name: "x", Typeflag: tar.TypeReg, Mode: 0644, Size: 8}, "REPLACED")
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}

	if err := extractTarGzToDir(bytes.NewReader(buf.Bytes()), dir, extractOptions{}); err != nil {
		t.Fatalf("extraction of a symlink→file replacement failed: %v", err)
	}
	fi, err := os.Lstat(filepath.Join(dir, "x"))
	if err != nil {
		t.Fatal(err)
	}
	if !fi.Mode().IsRegular() {
		t.Fatalf("x is not a regular file after replacement: %s", fi.Mode())
	}
	if b, err := os.ReadFile(filepath.Join(dir, "x")); err != nil || string(b) != "REPLACED" {
		t.Fatalf("x content = %q, %v; want REPLACED", b, err)
	}
	if b, err := os.ReadFile(victim); err != nil || string(b) != "ORIGINAL" {
		t.Fatalf("symlink target was modified: %q, %v; want ORIGINAL", b, err)
	}
}

// Regression: a TypeLink whose source is a SYMLINK relocates a link target
// that was validated relative to its original parent. The old extractor
// created the hardlink (link(2) links the symlink inode, not its target),
// and a following TypeReg through the relocated link wrote OUTSIDE the
// extraction directory. The fix refuses a hardlink to a symlink (and opens
// regular-file writes with O_NOFOLLOW).
//
// The escape target is deliberately one level above dir but still inside the
// test's temporary base, so a regression is caught without writing outside
// the test tree.
func TestExtractTarGzRefusesHardlinkedSymlinkEscape(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "vol")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	add := func(h *tar.Header, data string) {
		t.Helper()
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if data != "" {
			if _, err := tw.Write([]byte(data)); err != nil {
				t.Fatal(err)
			}
		}
	}
	add(&tar.Header{Name: "a/", Typeflag: tar.TypeDir, Mode: 0755}, "")
	add(&tar.Header{Name: "a/b/", Typeflag: tar.TypeDir, Mode: 0755}, "")
	// Valid at its original location: vol/a/b + ../pwned = vol/a/pwned.
	add(&tar.Header{Name: "a/b/x", Typeflag: tar.TypeSymlink, Linkname: "../pwned", Mode: 0777}, "")
	// link(2) would create a second name for the SYMLINK inode at vol/y;
	// the same linkname now resolves from vol to base/pwned.
	add(&tar.Header{Name: "y", Typeflag: tar.TypeLink, Linkname: "a/b/x", Mode: 0777}, "")
	add(&tar.Header{Name: "y", Typeflag: tar.TypeReg, Mode: 0644, Size: 5}, "PWNED")

	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}

	if err := extractTarGzToDir(bytes.NewReader(buf.Bytes()), dir, extractOptions{}); err == nil {
		t.Fatal("extraction accepted a hardlink to a symlink (escape primitive)")
	}
	if _, err := os.Stat(filepath.Join(base, "pwned")); err == nil {
		t.Fatal("VULNERABLE: extraction wrote outside the extraction dir via a hardlinked symlink")
	}
	// The in-tree target was never reached either: the extractor refused at
	// the TypeLink, before the TypeReg.
	if _, err := os.Stat(filepath.Join(dir, "a", "pwned")); err == nil {
		t.Fatal("extraction continued after the refused hardlink")
	}
}

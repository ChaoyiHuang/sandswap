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

package template

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNormalizeLinkTarget verifies symlink containment for tar extraction:
// relative targets that stay inside the extraction dir pass verbatim, absolute
// targets are rewritten to an equivalent tree-relative form, and anything that
// escapes the extraction dir is rejected.
func TestNormalizeLinkTarget(t *testing.T) {
	dir := t.TempDir()
	absDir, err := filepath.Abs(dir)
	if err != nil {
		t.Fatal(err)
	}
	sep := string(os.PathSeparator)
	linkPath := filepath.Join(absDir, "etc", "alternatives", "awk")

	cases := []struct {
		name     string
		linkname string
		want     string
		wantErr  bool
	}{
		{"empty target", "", "", true},
		// Distro-style absolute target: rewritten tree-relative, same guest semantics.
		{
			name:     "absolute rewritten to relative",
			linkname: "/usr/bin/mawk",
			want:     ".." + sep + ".." + sep + "usr" + sep + "bin" + sep + "mawk",
		},
		{
			name:     "absolute root-ish escape rejected",
			linkname: "/../..",
			wantErr:  true,
		},
		{
			name:     "relative in-tree kept",
			linkname: "../../usr/bin/mawk",
			want:     "../../usr/bin/mawk",
		},
		{
			name:     "relative sibling kept",
			linkname: "../awk.real",
			want:     "../awk.real",
		},
		{
			name:     "relative escaping rejected",
			linkname: "../../../../etc/shadow",
			wantErr:  true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := normalizeLinkTarget(c.linkname, linkPath, absDir, sep)
			if c.wantErr {
				if err == nil {
					t.Fatalf("normalizeLinkTarget(%q) = %q, want error", c.linkname, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("normalizeLinkTarget(%q): %v", c.linkname, err)
			}
			if got != c.want {
				t.Fatalf("normalizeLinkTarget(%q) = %q, want %q", c.linkname, got, c.want)
			}
		})
	}
}

// buildTestTarGz writes a tar.gz with the given entries.
func buildTestTarGz(t *testing.T, entries []tar.Header, contents [][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	for i, h := range entries {
		body := contents[i]
		h.Size = int64(len(body))
		if err := tw.WriteHeader(&h); err != nil {
			t.Fatal(err)
		}
		if len(body) > 0 {
			if _, err := tw.Write(body); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// TestExtractTarGzRewritesAbsoluteSymlinks verifies two things for a distro-like
// layer: (1) absolute symlinks are extracted as tree-relative links (preserving
// resolution once the template becomes the guest rootfs), and (2) a later
// regular-file entry written THROUGH such a link lands inside the extraction
// dir — never at the absolute host path.
func TestExtractTarGzRewritesAbsoluteSymlinks(t *testing.T) {
	dir := t.TempDir()

	data := buildTestTarGz(t,
		[]tar.Header{
			{Name: "usr/bin/", Typeflag: tar.TypeDir, Mode: 0755},
			{Name: "etc/alternatives/", Typeflag: tar.TypeDir, Mode: 0755},
			{Name: "usr/bin/mawk", Typeflag: tar.TypeReg, Mode: 0644},
			{Name: "etc/alternatives/awk", Typeflag: tar.TypeSymlink, Linkname: "/usr/bin/mawk"},
			// Regular-file write following the symlink above must be contained.
			{Name: "usr/bin/mawk", Typeflag: tar.TypeReg, Mode: 0755},
		},
		[][]byte{nil, nil, []byte("orig"), nil, []byte("payload")},
	)
	if err := extractTarGzToDir(bytes.NewReader(data), dir, extractOptions{}); err != nil {
		t.Fatalf("extractTarGzToDir: %v", err)
	}

	link := filepath.Join(dir, "etc", "alternatives", "awk")
	target, err := os.Readlink(link)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.IsAbs(target) || strings.HasPrefix(target, ".."+"/"+"..") && !strings.Contains(target, "usr") {
		t.Fatalf("symlink not rewritten tree-relative: %q", target)
	}

	// The follow-through write must have modified the file INSIDE the extraction
	// dir. Resolve through the link's own directory (as a real open(2) would).
	resolved := filepath.Join(filepath.Dir(link), target)
	if _, withinErr := os.Stat(resolved); withinErr != nil {
		t.Fatalf("rewritten symlink resolves outside extraction dir: %q", resolved)
	}
	got, err := os.ReadFile(resolved)
	if err != nil {
		t.Fatalf("read through rewritten symlink: %v", err)
	}
	if string(got) != "payload" {
		t.Fatalf("follow-through write content = %q, want payload", got)
	}
}

// TestExtractTarGzRejectsEscapingSymlink keeps the original attack from passing:
// a relative symlink climbing out of dir must fail extraction entirely.
func TestExtractTarGzRejectsEscapingSymlink(t *testing.T) {
	dir := t.TempDir()
	data := buildTestTarGz(t,
		[]tar.Header{{Name: "evil", Typeflag: tar.TypeSymlink, Linkname: "../../../outside"}},
		[][]byte{nil},
	)
	if err := extractTarGzToDir(bytes.NewReader(data), dir, extractOptions{}); err == nil {
		t.Fatal("escaping symlink extraction succeeded, want error")
	}
}

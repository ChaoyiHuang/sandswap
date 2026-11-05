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
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type tarFixtureEntry struct {
	typ  byte
	name string
	link string
	mode int64
}

func tarGzFixture(t *testing.T, entries ...tarFixtureEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		hdr := &tar.Header{Name: e.name, Typeflag: e.typ, Mode: e.mode, Linkname: e.link}
		if e.typ == tar.TypeReg {
			hdr.Size = 4
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("tar header %q: %v", e.name, err)
		}
		if e.typ == tar.TypeReg {
			if _, err := tw.Write([]byte("data")); err != nil {
				t.Fatalf("tar body %q: %v", e.name, err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// A "." / empty tar entry resolves to the extraction root itself. A symlink
// with that name would replace the staging dir with a link and get published
// as a layer; the extractor must refuse it and leave the root a directory.
func TestExtractRejectsRootEntries(t *testing.T) {
	cases := []struct {
		name  string
		entry tarFixtureEntry
	}{
		{"dot symlink", tarFixtureEntry{typ: tar.TypeSymlink, name: ".", link: "victim", mode: 0o777}},
		{"dot dir", tarFixtureEntry{typ: tar.TypeDir, name: ".", mode: 0o755}},
		{"empty name", tarFixtureEntry{typ: tar.TypeReg, name: "", mode: 0o644}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			data := tarGzFixture(t, tc.entry)
			if err := extractTarGzToDir(bytes.NewReader(data), dir, extractOptions{}); err == nil {
				t.Fatalf("root entry %q was accepted", tc.entry.name)
			}
			fi, err := os.Lstat(dir)
			if err != nil || !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
				t.Fatalf("extraction root was replaced (fi=%v err=%v)", fi, err)
			}
		})
	}
}

// WalkDir reports a symlinked root as a link and the normalize callback would
// skip it, silently normalizing nothing. A template root must be a real
// directory.
func TestNormalizeTemplateTreeRejectsSymlinkRoot(t *testing.T) {
	realDir := t.TempDir()
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(realDir, link); err != nil {
		t.Fatal(err)
	}
	if _, err := NormalizeTemplateTree(link); err == nil {
		t.Fatal("symlink root accepted")
	}
}

// Template layers are owner-write-only: group/other write bits on a
// tenant-chmod'ed entry must be cleared (and reported by the check gate).
func TestNormalizeTemplateTreeClearsGroupWrite(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "f")
	if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(f, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := NormalizeTemplateTree(dir); err != nil {
		t.Fatalf("normalize: %v", err)
	}
	fi, err := os.Stat(f)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		t.Fatalf("group/other write survived normalization: %o", fi.Mode().Perm())
	}
	if fi.Mode().Perm()&0o040 == 0 {
		t.Fatalf("group read was not added: %o", fi.Mode().Perm())
	}

	// The check gate must flag a hand-made writable entry.
	pre := filepath.Join(t.TempDir(), "g")
	if err := os.MkdirAll(pre, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(pre, 0o777); err != nil {
		t.Fatal(err)
	}
	v, err := ValidateTemplateTree(pre)
	if err != nil {
		t.Fatal(err)
	}
	if len(v) == 0 || !strings.Contains(v[0].Reason, "owner-write-only") {
		t.Fatalf("validate did not flag a group/other-writable entry: %+v", v)
	}
}

// A non-directory placeholder at a layer name must be reaped by the delete
// GC; skipping non-directories pinned the digest forever.
func TestDeleteTemplateReapsNonDirectoryLayerPlaceholder(t *testing.T) {
	templatesDir := t.TempDir()
	overlayBase := t.TempDir()
	m, err := NewManager(Config{TemplatesDir: templatesDir, OverlayBase: overlayBase, ResolveVolume: legacyResolver(overlayBase)})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	sandfsDir := filepath.Join(overlayBase, "flat-1")
	if err := os.MkdirAll(sandfsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	createMockRootfs(t, sandfsDir)
	if _, err := m.SaveAsTemplate(context.Background(), "flat-1", SaveAsTemplateRequest{TemplateRef: "gc:v1"}); err != nil {
		t.Fatalf("SaveAsTemplate: %v", err)
	}

	poison := filepath.Join(templatesDir, "layers", "poison")
	if err := os.WriteFile(poison, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(poison, old, old); err != nil {
		t.Fatal(err)
	}
	if err := m.DeleteTemplate("gc:v1", "overlay"); err != nil {
		t.Fatalf("DeleteTemplate: %v", err)
	}
	if _, err := os.Lstat(poison); !os.IsNotExist(err) {
		t.Fatalf("non-directory layer placeholder survived GC (err=%v)", err)
	}
}

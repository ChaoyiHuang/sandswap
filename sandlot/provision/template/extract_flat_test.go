// Copyright 2026 Chaoyi Huang. All rights reserved.
//
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE file at the root of this repository.
//
// As of the Change Date specified in that file, in accordance with the
// Business Source License, use of this software will be governed
// by the Apache License, Version 2.0.

package template

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// assertMode compares a path's permission bits (including setgid) against want.
func assertMode(t *testing.T, path string, want os.FileMode, what string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if info.Mode().Perm() != want.Perm() {
		t.Errorf("%s mode = %o, want %o (%s)", path, info.Mode().Perm(), want.Perm(), what)
	}
}

// TestExtractTarGzFlatVolumePolicy verifies the writable-volume permission
// policy applied when OCI layers materialize a flat SandFS: files gain
// group-write, directories gain group-write + setgid, file mtimes are
// restored from the tar headers. This must mirror copyDirRecursive's contract
// (registry package): the volume is shared between the two service
// identities, so group access is mandatory for the agent to write through it.
func TestExtractTarGzFlatVolumePolicy(t *testing.T) {
	dir := t.TempDir()
	mtime := time.Now().Add(-2 * time.Hour).UTC().Truncate(time.Second)

	data := buildTestTarGz(t,
		[]tar.Header{
			{Name: "etc/", Typeflag: tar.TypeDir, Mode: 0755},
			{Name: "etc/app.conf", Typeflag: tar.TypeReg, Mode: 0644, ModTime: mtime},
			{Name: "private/", Typeflag: tar.TypeDir, Mode: 0700},
			{Name: "private/secret", Typeflag: tar.TypeReg, Mode: 0600, ModTime: mtime},
			{Name: "usr/bin/", Typeflag: tar.TypeDir, Mode: 0755},
			{Name: "usr/bin/tool", Typeflag: tar.TypeReg, Mode: 0755, ModTime: mtime},
		},
		[][]byte{nil, []byte("cfg"), nil, []byte("s"), nil, []byte("#!/bin/sh")},
	)
	if err := extractTarGzToDir(bytes.NewReader(data), dir, extractOptions{flatVolume: true}); err != nil {
		t.Fatalf("extractTarGzToDir(flat): %v", err)
	}

	// Directories: perm | 0o2770 (+setgid) — MkdirAll's umask must not win.
	assertMode(t, filepath.Join(dir, "etc"), 0o2775, "flat dir")
	assertMode(t, filepath.Join(dir, "private"), 0o2770, "flat dir (0700 base)")
	assertMode(t, filepath.Join(dir, "usr", "bin"), 0o2775, "flat dir")

	// Files: perm | 0o060 (group read+write).
	assertMode(t, filepath.Join(dir, "etc", "app.conf"), 0o664, "flat file")
	assertMode(t, filepath.Join(dir, "private", "secret"), 0o660, "flat file (0600 base)")
	assertMode(t, filepath.Join(dir, "usr", "bin", "tool"), 0o775, "flat file (0755 base)")

	// File mtimes restored from the tar headers.
	for _, p := range []string{
		filepath.Join(dir, "etc", "app.conf"),
		filepath.Join(dir, "usr", "bin", "tool"),
	} {
		info, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if !info.ModTime().Equal(mtime) {
			t.Errorf("%s mtime = %v, want %v", p, info.ModTime(), mtime)
		}
	}
}

// TestExtractTarGzDefaultPolicyUnchanged pins the layer extraction primitive:
// without flatVolume, modes land EXACTLY as the tar recorded them — verbatim,
// no group-write, no setgid, no mtime rewrite, and (since the determinism
// fix) independent of the process umask. The sharing adjustment a layer DOES
// need (group READ for the FUSE daemon, dirs group-traversable) belongs to
// the materialization policy pass — materializeLayerFromTar →
// NormalizeTemplateTree, pinned by layer_modes_test.go.
func TestExtractTarGzDefaultPolicyUnchanged(t *testing.T) {
	dir := t.TempDir()
	data := buildTestTarGz(t,
		[]tar.Header{
			{Name: "etc/", Typeflag: tar.TypeDir, Mode: 0755},
			{Name: "etc/app.conf", Typeflag: tar.TypeReg, Mode: 0644},
		},
		[][]byte{nil, []byte("cfg")},
	)
	if err := extractTarGzToDir(bytes.NewReader(data), dir, extractOptions{}); err != nil {
		t.Fatalf("extractTarGzToDir(default): %v", err)
	}
	assertMode(t, filepath.Join(dir, "etc"), 0o755, "lowerdir dir")
	assertMode(t, filepath.Join(dir, "etc", "app.conf"), 0o644, "lowerdir file")
}

// TestExtractFlatLayersOverride pins the multi-layer ordering contract of
// ExtractFlatFromOCI: layers materialize bottom→top into the same directory,
// later layers overwriting earlier entries — the unpack equivalent of
// lowerdir stacking.
func TestExtractFlatLayersOverride(t *testing.T) {
	dir := t.TempDir()
	base := buildTestTarGz(t,
		[]tar.Header{
			{Name: "etc/", Typeflag: tar.TypeDir, Mode: 0755},
			{Name: "etc/app.conf", Typeflag: tar.TypeReg, Mode: 0644},
			{Name: "etc/base-only", Typeflag: tar.TypeReg, Mode: 0644},
		},
		[][]byte{nil, []byte("v1"), []byte("base")},
	)
	top := buildTestTarGz(t,
		[]tar.Header{
			{Name: "etc/app.conf", Typeflag: tar.TypeReg, Mode: 0644},
		},
		[][]byte{[]byte("v2")},
	)
	if err := extractTarGzToDir(bytes.NewReader(base), dir, extractOptions{flatVolume: true}); err != nil {
		t.Fatalf("base layer: %v", err)
	}
	if err := extractTarGzToDir(bytes.NewReader(top), dir, extractOptions{flatVolume: true}); err != nil {
		t.Fatalf("top layer: %v", err)
	}

	if got, _ := os.ReadFile(filepath.Join(dir, "etc", "app.conf")); string(got) != "v2" {
		t.Errorf("overridden file = %q, want v2", got)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "etc", "base-only")); string(got) != "base" {
		t.Errorf("base-only file = %q, want base", got)
	}
}

// TestExtractTarGzFlatSymlinkRewrite verifies the flat policy does not weaken
// containment: an absolute symlink is rewritten tree-relative (identical
// resolution inside the guest chroot, contained on the host), and a
// follow-through regular-file write lands inside the volume.
func TestExtractTarGzFlatSymlinkRewrite(t *testing.T) {
	dir := t.TempDir()
	data := buildTestTarGz(t,
		[]tar.Header{
			{Name: "usr/bin/", Typeflag: tar.TypeDir, Mode: 0755},
			{Name: "etc/alternatives/", Typeflag: tar.TypeDir, Mode: 0755},
			{Name: "usr/bin/mawk", Typeflag: tar.TypeReg, Mode: 0755},
			{Name: "etc/alternatives/awk", Typeflag: tar.TypeSymlink, Linkname: "/usr/bin/mawk"},
			{Name: "usr/bin/mawk", Typeflag: tar.TypeReg, Mode: 0755},
		},
		[][]byte{nil, nil, []byte("orig"), nil, []byte("payload")},
	)
	if err := extractTarGzToDir(bytes.NewReader(data), dir, extractOptions{flatVolume: true}); err != nil {
		t.Fatalf("extractTarGzToDir(flat): %v", err)
	}

	link := filepath.Join(dir, "etc", "alternatives", "awk")
	target, err := os.Readlink(link)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.IsAbs(target) {
		t.Fatalf("absolute symlink left on disk: %q", target)
	}
	resolved := filepath.Join(filepath.Dir(link), target)
	got, err := os.ReadFile(resolved)
	if err != nil {
		t.Fatalf("rewritten symlink resolves outside the volume: %q", resolved)
	}
	if string(got) != "payload" {
		t.Fatalf("follow-through write content = %q, want payload", got)
	}
}

// TestExtractTarGzShallowLinkEscapeContained pins the fix: a
// "shallow link" compound (`q -> "."` then `q/x -> ".."`) passes every
// LEXICAL containment check yet resolves ABOVE the extraction base at
// runtime. Entries under a symlinked ancestor must be skipped — nothing may
// land outside the extraction dir, and the compound's follow-through file
// must never be written.
func TestExtractTarGzShallowLinkEscapeContained(t *testing.T) {
	dir := t.TempDir()
	parent := filepath.Dir(dir)

	var buf bytes.Buffer
	gzw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gzw)
	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	must(tw.WriteHeader(&tar.Header{Name: "q", Typeflag: tar.TypeSymlink, Linkname: ".", Mode: 0o777}))
	must(tw.WriteHeader(&tar.Header{Name: "q/x", Typeflag: tar.TypeSymlink, Linkname: "..", Mode: 0o777}))
	must(tw.WriteHeader(&tar.Header{Name: "q/x/owned", Typeflag: tar.TypeReg, Mode: 0o644, Size: 5}))
	if _, err := tw.Write([]byte("PWNED")); err != nil {
		t.Fatal(err)
	}
	must(tw.Close())
	must(gzw.Close())

	if err := extractTarGzToDir(bytes.NewReader(buf.Bytes()), dir, extractOptions{}); err != nil {
		t.Fatalf("extractTarGzToDir: %v", err)
	}
	// The escaped witness (the blind probe wrote it at the PARENT of dir).
	if _, err := os.Lstat(filepath.Join(parent, "owned")); !os.IsNotExist(err) {
		t.Fatalf("ESCAPE: witness written outside the extraction dir: %v", err)
	}
	// And the runtime-climb link `q/x -> ..` never landed.
	if _, err := os.Lstat(filepath.Join(dir, "x")); !os.IsNotExist(err) {
		t.Fatalf("shallow-link runtime artifact `x` landed in the extraction dir: %v", err)
	}
}

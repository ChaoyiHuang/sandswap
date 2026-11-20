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

// The exported extraction seam must reproduce the runtime defaults exactly:
// gzip-only, root "." entries rejected, specials dropped silently. The
// opt-ins (plain tar, root "." dir skip, skip callback) are additive.

func buildPlainTar(t *testing.T, names []tarEntryAPI) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range names {
		hdr := &tar.Header{Name: e.name, Typeflag: e.typeflag, Mode: e.mode, Linkname: e.linkname}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

type tarEntryAPI struct {
	name     string
	typeflag byte
	mode     int64
	linkname string
}

func gzipBytes(b []byte) []byte {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write(b)
	zw.Close()
	return buf.Bytes()
}

func TestExtractTarTreeDefaultsRefusePlainTar(t *testing.T) {
	dir := t.TempDir()
	raw := buildPlainTar(t, []tarEntryAPI{{name: "a", typeflag: tar.TypeReg, mode: 0o644}})
	if _, err := ExtractTarTree(bytes.NewReader(raw), dir, ExtractOptions{}); err == nil {
		t.Fatal("plain tar accepted without the opt-in")
	}
	if _, err := ExtractTarTree(bytes.NewReader(gzipBytes(raw)), dir, ExtractOptions{}); err != nil {
		t.Fatalf("gzip stream refused by default policy: %v", err)
	}
}

func TestExtractTarTreeDefaultsRefuseRootDirEntry(t *testing.T) {
	dir := t.TempDir()
	entries := []tarEntryAPI{{name: "./", typeflag: tar.TypeDir, mode: 0o755}}
	raw := gzipBytes(buildPlainTar(t, entries))
	if _, err := ExtractTarTree(bytes.NewReader(raw), dir, ExtractOptions{}); err == nil {
		t.Fatal("root \".\" entry accepted without the opt-in")
	}
	dir2 := t.TempDir()
	if _, err := ExtractTarTree(bytes.NewReader(raw), dir2, ExtractOptions{AllowRootDirEntry: true}); err != nil {
		t.Fatalf("root \".\" directory refused with the opt-in: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir2, "a")); err == nil {
		t.Fatal("opt-in unexpectedly extracted an entry")
	}
	// Non-directory root entries stay refused even with the opt-in.
	bad := gzipBytes(buildPlainTar(t, []tarEntryAPI{{name: ".", typeflag: tar.TypeSymlink, mode: 0o777, linkname: "/etc"}}))
	if _, err := ExtractTarTree(bytes.NewReader(bad), t.TempDir(), ExtractOptions{AllowRootDirEntry: true}); err == nil {
		t.Fatal("non-directory root entry accepted")
	}
}

func TestExtractTarTreeReportsSkips(t *testing.T) {
	dir := t.TempDir()
	entries := []tarEntryAPI{
		{name: "sym", typeflag: tar.TypeSymlink, mode: 0o777, linkname: "elsewhere"},
		{name: "sym/under", typeflag: tar.TypeReg, mode: 0o644},
		{name: "fifo", typeflag: tar.TypeFifo, mode: 0o644},
	}
	report, err := ExtractTarTree(bytes.NewReader(gzipBytes(buildPlainTar(t, entries))), dir, ExtractOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.SkippedSymlinkAncestor) != 1 || report.SkippedSymlinkAncestor[0] != "sym/under" {
		t.Fatalf("symlink-ancestor skips = %v", report.SkippedSymlinkAncestor)
	}
	if len(report.Specials) != 1 || report.Specials[0].Name != "fifo" || report.Specials[0].Typeflag != tar.TypeFifo {
		t.Fatalf("specials = %+v", report.Specials)
	}
	// The symlink itself landed; the entry under it did not.
	if _, err := os.Lstat(filepath.Join(dir, "sym")); err != nil {
		t.Fatal("symlink missing")
	}
	if _, err := os.Lstat(filepath.Join(dir, "sym/under")); err == nil {
		t.Fatal("entry under symlink ancestor landed")
	}
}

func TestVolumeControlFilesMatchesContract(t *testing.T) {
	got := VolumeControlFiles()
	want := []string{".sandfs-id", ".provisioning", ".save-staging"}
	if len(got) != len(want) {
		t.Fatalf("control files = %v", got)
	}
	for i, w := range want {
		if got[i] != w {
			t.Fatalf("control files = %v, want %v", got, want)
		}
	}
	// The validate gate keys on the same names.
	for _, f := range []string{volumeIdentityFile, provisioningMarkerFile, saveStagingMarker} {
		if !strings.Contains(strings.Join(want, " "), f) {
			t.Fatalf("internal constant %q missing from the exported list", f)
		}
	}
}

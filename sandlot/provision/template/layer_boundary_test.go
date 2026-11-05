// Copyright 2026 Chaoyi Huang. All rights reserved.
//
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE file at the root of this repository.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, sandswap's use of this software will be governed
// by the Apache License, Version 2.0.

package template

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// a flat template's layer path is judged against the store trust
// boundary at CONSUME time — the flat twin of the overlay path's
// core.validateLayerID. Absolute paths outside every configured root refuse
// by name; relative paths stay under layers/; the store root itself, ".."
// escapes and symlinks out of the root all refuse.
func TestResolveFlatLayerPathTrustBoundary(t *testing.T) {
	store := t.TempDir()
	m, err := NewManager(Config{TemplatesDir: store})
	if err != nil {
		t.Fatal(err)
	}

	// Legit absolute (the local-template format): a directory inside the store.
	inner := filepath.Join(store, "local-tpl")
	if err := os.MkdirAll(inner, 0o755); err != nil {
		t.Fatal(err)
	}
	if got, err := m.ResolveFlatLayerPath(inner); err != nil || got != inner {
		t.Fatalf("store-internal absolute layer refused or rewritten: got %q, err %v", got, err)
	}

	// Legit relative (the OCI layer format): resolves under layers/.
	relLayer := filepath.Join(store, "layers", "sha256-abc")
	if err := os.MkdirAll(relLayer, 0o755); err != nil {
		t.Fatal(err)
	}
	if got, err := m.ResolveFlatLayerPath("sha256-abc"); err != nil || got != relLayer {
		t.Fatalf("store-relative layer refused or misresolved: got %q, err %v", got, err)
	}

	// Everything else refuses with the named class.
	for name, layerID := range map[string]string{
		"host directory":  "/etc",
		"outside via ..":  filepath.Join(store, "..", "etc"),
		"relative escape": "../../etc",
		"sibling prefix":  store + "-evil",
		"the store root":  store,
		"empty layer id":  "",
		"dot layer id":    ".",
	} {
		if _, err := m.ResolveFlatLayerPath(layerID); err == nil {
			t.Errorf("%s (%q): accepted, want refusal", name, layerID)
		} else if !errors.Is(err, ErrFlatLayerOutsideStore) {
			t.Errorf("%s (%q): wrong refusal class: %v", name, layerID, err)
		}
	}

	// Symlink leg: a link inside the store pointing at /etc must refuse (the
	// lexical check alone cannot see the shift).
	if err := os.Symlink("/etc", filepath.Join(store, "sneaky")); err != nil {
		t.Fatal(err)
	}
	if _, err := m.ResolveFlatLayerPath(filepath.Join(store, "sneaky")); !errors.Is(err, ErrFlatLayerOutsideStore) {
		t.Errorf("store-internal symlink to /etc: err %v, want ErrFlatLayerOutsideStore", err)
	}

	// An operator-configured flat scan root IS part of the boundary (the
	// shipped baremetal config keeps flat templates in a sibling directory).
	root := t.TempDir()
	scanTpl := filepath.Join(root, "ctpl", "v1")
	if err := os.MkdirAll(scanTpl, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := m.ScanFlatTemplates(root); err != nil {
		t.Fatal(err)
	}
	if got, err := m.ResolveFlatLayerPath(scanTpl); err != nil || got != scanTpl {
		t.Fatalf("configured flat scan root refused: got %q, err %v", got, err)
	}
}

// the extraction caps the tar ENTRY count as well as the bytes —
// block 512 B headers (each an inode) cannot be minted without bound.
func TestLayerEntryCountCapped(t *testing.T) {
	old := maxExtractedLayerEntries
	maxExtractedLayerEntries = 4 // 4 entries: the boundary is at/over
	defer func() { maxExtractedLayerEntries = old }()

	build := func(n int) []byte {
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		tw := tar.NewWriter(gz)
		for i := 0; i < n; i++ {
			hdr := &tar.Header{Name: fmt.Sprintf("f%03d", i), Typeflag: tar.TypeReg, Size: 0, Mode: 0644}
			if err := tw.WriteHeader(hdr); err != nil {
				t.Fatal(err)
			}
		}
		tw.Close()
		gz.Close()
		return buf.Bytes()
	}

	// At the boundary: exactly the cap still extracts.
	if err := extractTarGzToDir(bytes.NewReader(build(4)), t.TempDir(), extractOptions{}); err != nil {
		t.Fatalf("at-cap archive refused: %v", err)
	}
	// One over: loud named refusal, not silent truncation.
	err := extractTarGzToDir(bytes.NewReader(build(5)), t.TempDir(), extractOptions{})
	if err == nil {
		t.Fatal("entry-count cap not enforced: 5 entries extracted with the cap at 4")
	}
	if !strings.Contains(err.Error(), "entry-count cap") {
		t.Fatalf("unexpected error (want the entry-count cap): %v", err)
	}
	t.Logf("capped: %v", err)
}

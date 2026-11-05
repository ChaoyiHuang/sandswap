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
	"compress/gzip"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSaveAsTemplateRefusesStampIDMismatch pins the verified-id check: a volume
// whose SIGNED stamp names a different sandfs is a hand-rename/restore/mis-
// applied rotation, and snapshotting it would publish another tenant's data as
// this sandfs's template.
func TestSaveAsTemplateRefusesStampIDMismatch(t *testing.T) {
	base := t.TempDir()
	if err := os.MkdirAll(filepath.Join(base, "my-sandfs"), 0o755); err != nil {
		t.Fatal(err)
	}
	createMockRootfs(t, filepath.Join(base, "my-sandfs"))

	m, err := NewManager(Config{
		TemplatesDir:  t.TempDir(),
		OverlayBase:   base,
		ResolveVolume: legacyResolver(base),
		VerifyVolumeStamp: func(string) (VolumeStamp, bool, error) {
			return VolumeStamp{SandfsID: "someone-else", Mode: "flat"}, true, nil
		},
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	_, err = m.SaveAsTemplate(context.Background(), "my-sandfs", SaveAsTemplateRequest{TemplateRef: "mismatch:v1"})
	if err == nil || !strings.Contains(err.Error(), "different sandfs") {
		t.Fatalf("err = %v, want the identity-stamp refusal", err)
	}
	if m.refFileExists("mismatch:v1", "overlay") {
		t.Fatal("a refused save must not publish a ref")
	}

	// Control: the matching id saves.
	m2, err := NewManager(Config{
		TemplatesDir:  t.TempDir(),
		OverlayBase:   base,
		ResolveVolume: legacyResolver(base),
		VerifyVolumeStamp: func(string) (VolumeStamp, bool, error) {
			return VolumeStamp{SandfsID: "my-sandfs", Mode: "flat"}, true, nil
		},
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if _, err := m2.SaveAsTemplate(context.Background(), "my-sandfs", SaveAsTemplateRequest{TemplateRef: "matching:v1"}); err != nil {
		t.Fatalf("a matching verified stamp must save: %v", err)
	}
}

// TestPackTarGzClosesAndPropagates pins the archive-completeness contract: a
// successful pack produces a readable gzip tar, and a write failure that only
// surfaces at Close (ENOSPC on /dev/full) is RETURNED, never discarded — the
// old deferred Closes returned nil for a truncated archive that PushTemplate
// then published.
func TestPackTarGzClosesAndPropagates(t *testing.T) {
	src := t.TempDir()
	if err := os.MkdirAll(filepath.Join(src, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "sub", "f"), []byte("payload"), 0o644); err != nil {
		t.Fatal(err)
	}

	dst := filepath.Join(t.TempDir(), "layer.tar.gz")
	if err := packTarGz(src, dst); err != nil {
		t.Fatalf("packTarGz: %v", err)
	}
	f, err := os.Open(dst)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gzr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("the packed archive is not a readable gzip stream: %v", err)
	}
	defer gzr.Close()
	tr := tar.NewReader(gzr)
	found := false
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read packed tar: %v", err)
		}
		if hdr.Name == "sub/f" {
			found = true
		}
	}
	if !found {
		t.Fatal("packed archive is missing its entry (truncated publish?)")
	}

	// /dev/full accepts the open and fails every write with ENOSPC — the
	// error path only exists at Close/flush.
	if _, err := os.Stat("/dev/full"); err == nil {
		if err := packTarGz(src, "/dev/full"); err == nil {
			t.Fatal("packTarGz returned nil for an unwritable destination (dropped Close error)")
		}
	}
}

// TestResolveOverlayLayerPathContainment pins PushTemplate's layer trust
// boundary: an absolute layer id must resolve inside the template store, a
// relative one under layers/, and nothing may escape by traversal or symlink —
// the packing side must never publish a host file the ref file named.
func TestResolveOverlayLayerPathContainment(t *testing.T) {
	store := t.TempDir()
	m, err := NewManager(Config{TemplatesDir: store})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(store, "layers", "good"), 0o755); err != nil {
		t.Fatal(err)
	}

	for _, bad := range []string{"/etc", "../escape", "a/../../escape", ""} {
		if _, err := m.resolveOverlayLayerPath(bad); err == nil {
			t.Errorf("layer id %q resolved outside the store", bad)
		}
	}
	if got, err := m.resolveOverlayLayerPath("good"); err != nil {
		t.Errorf("a relative layer under layers/ must resolve: %v", err)
	} else if got != filepath.Join(store, "layers", "good") {
		t.Errorf("resolved path = %q", got)
	}
	abs := filepath.Join(store, "layers", "good")
	if _, err := m.resolveOverlayLayerPath(abs); err != nil {
		t.Errorf("an absolute layer inside the store must resolve: %v", err)
	}

	// A symlinked component must not move the resolved path out of the store.
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(store, "layers", "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := m.resolveOverlayLayerPath("link"); err == nil {
		t.Error("a symlinked layer escaped the store")
	}
}

// TestSaveAsTemplateHealsCrashAfterPublish pins the reachable heal branch: a
// crash between the atomic publish rename and the ref write leaves a target
// directory with no ref, and the sibling publish marker is the evidence that it
// is a save's own debris (the in-directory marker is stripped BEFORE the
// publish, which made the old branch unreachable and wedged the ref name).
func TestSaveAsTemplateHealsCrashAfterPublish(t *testing.T) {
	base := t.TempDir()
	if err := os.MkdirAll(filepath.Join(base, "my-sandfs"), 0o755); err != nil {
		t.Fatal(err)
	}
	createMockRootfs(t, filepath.Join(base, "my-sandfs"))
	store := t.TempDir()
	m, err := NewManager(Config{
		TemplatesDir:      store,
		OverlayBase:       base,
		ResolveVolume:     legacyResolver(base),
		VerifyVolumeStamp: func(string) (VolumeStamp, bool, error) { return VolumeStamp{}, false, nil },
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	// The crash artifact: a published layer directory with no ref and no
	// in-directory marker, plus the sibling publish marker.
	target := filepath.Join(store, "layers", "local-crash-v1")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "stale"), []byte("half"), 0o644); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(store, "layers", ".local-crash-v1.publishing")
	if err := os.WriteFile(marker, []byte("publishing\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := m.SaveAsTemplate(context.Background(), "my-sandfs", SaveAsTemplateRequest{TemplateRef: "crash:v1"}); err != nil {
		t.Fatalf("a save must heal its own crash debris, got %v", err)
	}
	if !m.refFileExists("crash:v1", "overlay") {
		t.Fatal("the healed save must publish its ref")
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("the publish marker must be removed once the ref exists")
	}
	if _, err := os.Stat(filepath.Join(target, "stale")); !os.IsNotExist(err) {
		t.Fatal("the aborted layer content must be replaced by the new save")
	}

	// Control: a directory with NO save evidence is foreign and still refused.
	foreign := filepath.Join(store, "layers", "local-foreign-v1")
	if err := os.MkdirAll(foreign, 0o755); err != nil {
		t.Fatal(err)
	}
	_, err = m.SaveAsTemplate(context.Background(), "my-sandfs", SaveAsTemplateRequest{TemplateRef: "foreign:v1"})
	if err == nil || !strings.Contains(err.Error(), "foreign directory") {
		t.Fatalf("err = %v, want the foreign-directory refusal", err)
	}
}

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
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"common/util"
)

// This file adds coverage-focused unit tests for the gateway/template package.
// It targets the 0% and <50% functions in manager.go: ref storage helpers,
// the scan/register family and SaveAsTemplate error paths, plus
// auth/pack/extract helpers, and the validation logic. Filesystem-based tests
// use t.TempDir (auto-cleaned); mount-based tests rely on the test running as
// root (the CI environment does) and otherwise skip.

// -----------------------------------------------------------------------------
// RefEntry.GetMode
// -----------------------------------------------------------------------------

// TestGetMode verifies that an empty Mode defaults to "overlay" (backward
// compatibility with pre-mode ref files), while explicit modes pass through.
func TestGetMode(t *testing.T) {
	cases := []struct {
		name string
		mode string
		want string
	}{
		{"empty defaults to overlay", "", "overlay"},
		{"flat", "flat", "flat"},
		{"overlay", "overlay", "overlay"},
		{"unknown passes through", "weird", "weird"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := RefEntry{Mode: c.mode}
			if got := e.GetMode(); got != c.want {
				t.Errorf("GetMode() = %q, want %q", got, c.want)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// parseTemplateRef / filenameToRef
// -----------------------------------------------------------------------------

func TestParseTemplateRef(t *testing.T) {
	cases := []struct {
		ref     string
		name    string
		version string
	}{
		{"sqlite:v1", "sqlite", "v1"},
		{"ubuntu:24.04", "ubuntu", "24.04"},
		{"sqlite", "sqlite", "local"}, // unversioned -> "local"
		{"", "", "local"},
		{"a:b:c", "a", "b:c"}, // SplitN(2): only the first colon splits
		{"sqlite:", "sqlite", ""},
		{"my_app:v1", "my_app", "v1"},
	}
	for _, c := range cases {
		t.Run(c.ref, func(t *testing.T) {
			n, v := parseTemplateRef(c.ref)
			if n != c.name || v != c.version {
				t.Errorf("parseTemplateRef(%q) = (%q,%q), want (%q,%q)", c.ref, n, v, c.name, c.version)
			}
		})
	}
}

// TestFilenameToRef_DottedVersions covers the filename -> ref conversion
// including dotted versions, which are the common case (24.04, 3.20, 1.0), and
// complements the basic cases in TestFilenameToRef above.
func TestFilenameToRef_DottedVersions(t *testing.T) {
	cases := []struct {
		base string
		want string
	}{
		{"ubuntu_24.04", "ubuntu:24.04"},
		{"alpine_3.20", "alpine:3.20"},
		{"sqlite_v1", "sqlite:v1"},
		{"simple", "simple"}, // no underscore -> no version
		{"", ""},
		{"my_app_v1", "my_app:v1"}, // last underscore splits (name may contain _)
	}
	for _, c := range cases {
		t.Run(c.base, func(t *testing.T) {
			if got := filenameToRef(c.base); got != c.want {
				t.Errorf("filenameToRef(%q) = %q, want %q", c.base, got, c.want)
			}
		})
	}
}

// TestRefFilenameRoundTrip verifies the round-trip property for refs whose
// version contains no underscore: RefToFilename(ref) -> filenameToRef == ref.
// Underscores inside the version are inherently ambiguous (the last underscore
// is treated as the name/version separator) and are documented here as a known
// limitation rather than asserted.
func TestRefFilenameRoundTrip(t *testing.T) {
	refs := []string{
		"sqlite:v1",
		"ubuntu:24.04",
		"alpine:3.20",
		"my_app:v1", // underscore in NAME is fine (last underscore splits)
		"simple",
	}
	for _, ref := range refs {
		got := filenameToRef(util.RefToFilename(ref))
		if got != ref {
			t.Errorf("round-trip %q -> %q -> %q (not identity)", ref, util.RefToFilename(ref), got)
		}
	}

	// Underscore inside the VERSION does not round-trip: "app:v1_beta" is
	// ambiguous and would be recovered as "app:v1:beta"-ish. This is an
	// accepted limitation of the underscore encoding; assert it so a future
	// change to the encoding is conscious of it.
	ambiguous := "app:v1_beta"
	round := filenameToRef(util.RefToFilename(ambiguous))
	if round == ambiguous {
		t.Fatalf("expected underscore-in-version to be ambiguous; got identity %q", round)
	}
	t.Logf("known ambiguity: %q encodes to %q and decodes to %q", ambiguous, util.RefToFilename(ambiguous), round)
}

// -----------------------------------------------------------------------------
// resolveLayerPath / ResolveLayerPath / TemplatesDir
// -----------------------------------------------------------------------------

func TestResolveLayerPath(t *testing.T) {
	templatesDir := t.TempDir()
	m := &Manager{templatesDir: templatesDir}

	cases := []struct {
		name    string
		layerID string
		want    string
	}{
		{"absolute path returned as-is", "/abs/path/to/layer", "/abs/path/to/layer"},
		{"relative path joined under layers/", "sha256-deadbeef", filepath.Join(templatesDir, "layers", "sha256-deadbeef")},
		{"local- relative layer", "local-sqlite-v1", filepath.Join(templatesDir, "layers", "local-sqlite-v1")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := m.ResolveLayerPath(c.layerID)
			if got != c.want {
				t.Errorf("ResolveLayerPath(%q) = %q, want %q", c.layerID, got, c.want)
			}
		})
	}
}

// TestManager_TemplatesDir verifies the getter returns the configured root.
func TestManager_TemplatesDir(t *testing.T) {
	templatesDir := t.TempDir()
	m, err := NewManager(Config{TemplatesDir: templatesDir, OverlayBase: t.TempDir(), ResolveVolume: legacyResolver(t.TempDir())})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if got := m.TemplatesDir(); got != templatesDir {
		t.Errorf("TemplatesDir() = %q, want %q", got, templatesDir)
	}
}

// -----------------------------------------------------------------------------
// ListLocalTemplates (disk scan, mode-suffix stripping, dedup)
// -----------------------------------------------------------------------------

// TestListLocalTemplates_ModeSuffixAndDedup asserts the fixed behavior:
// same-name flat+overlay collapse to one ref, and versions containing '.'
// (e.g. 24.04) are preserved. A legacy (mode-less) ref file is also recovered
// correctly rather than being truncated at the version's dot.
func TestListLocalTemplates_ModeSuffixAndDedup(t *testing.T) {
	templatesDir := t.TempDir()
	m, err := NewManager(Config{TemplatesDir: templatesDir, OverlayBase: t.TempDir(), ResolveVolume: legacyResolver(t.TempDir())})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	refsDir := filepath.Join(templatesDir, "refs")

	writeRef := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(refsDir, name), []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
	}

	// Refs must name REAL backing directories: ListLocalTemplates filters
	// ghosts whose layers no longer exist (RefEntryExists), so the fixtures
	// point at directories created here.
	// Outside templatesDir: the lazy rescan walks the scan roots, and a
	// directory planted there would be discovered as a template itself.
	realDir := filepath.Join(t.TempDir(), "fixture-rootfs")
	if err := os.MkdirAll(realDir, 0755); err != nil {
		t.Fatal(err)
	}
	// Same-name flat + overlay must collapse to a single ref entry.
	writeRef("ubuntu_24.04.flat.json", fmt.Sprintf(`{"name":"ubuntu","version":"24.04","mode":"flat","layers":[%q]}`, realDir))
	writeRef("ubuntu_24.04.overlay.json", fmt.Sprintf(`{"name":"ubuntu","version":"24.04","mode":"overlay","layers":[%q]}`, realDir))
	// Legacy (no mode suffix) with a dotted version must not be truncated.
	writeRef("debian_11.5.json", fmt.Sprintf(`{"name":"debian","version":"11.5","layers":[%q]}`, realDir))
	// Non-json files and directories must be ignored.
	writeRef("README", "ignore me")
	if err := os.MkdirAll(filepath.Join(refsDir, "subdir.json"), 0755); err != nil {
		t.Fatal(err)
	}

	got := m.ListLocalTemplates()
	want := map[string]bool{"ubuntu:24.04": true, "debian:11.5": true}
	if len(got) != len(want) {
		t.Fatalf("ListLocalTemplates = %v, want %d unique refs", got, len(want))
	}
	for _, r := range got {
		if !want[r] {
			t.Errorf("unexpected ref %q in %v", r, got)
		}
	}
	// ubuntu:24.04 must appear exactly once despite two mode files.
	count := 0
	for _, r := range got {
		if r == "ubuntu:24.04" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("ubuntu:24.04 appeared %d times, want 1 (flat+overlay dedup)", count)
	}
}

// TestListLocalTemplates_Empty asserts an empty refs/ dir yields nil/empty
// rather than erroring.
func TestListLocalTemplates_Empty(t *testing.T) {
	m, err := NewManager(Config{TemplatesDir: t.TempDir(), OverlayBase: t.TempDir(), ResolveVolume: legacyResolver(t.TempDir())})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if got := m.ListLocalTemplates(); len(got) != 0 {
		t.Errorf("empty refs dir: got %v, want empty", got)
	}
}

// -----------------------------------------------------------------------------
// RegisterLocalTemplate / RegisterFlatTemplate (error paths + path resolution)
// -----------------------------------------------------------------------------

func TestRegisterLocalTemplate_Errors(t *testing.T) {
	m, err := NewManager(Config{TemplatesDir: t.TempDir(), OverlayBase: t.TempDir(), ResolveVolume: legacyResolver(t.TempDir())})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	t.Run("nonexistent directory", func(t *testing.T) {
		if err := m.RegisterLocalTemplate("x:v1", filepath.Join(t.TempDir(), "nope")); err == nil {
			t.Error("expected error for nonexistent dir")
		}
	})
	t.Run("path is a file not a directory", func(t *testing.T) {
		f := filepath.Join(t.TempDir(), "file")
		if err := os.WriteFile(f, []byte("x"), 0644); err != nil {
			t.Fatal(err)
		}
		if err := m.RegisterLocalTemplate("x:v1", f); err == nil {
			t.Error("expected error when path is a file")
		}
	})
	t.Run("relative path is resolved to absolute", func(t *testing.T) {
		// Use a relative path; RegisterLocalTemplate must Abs() it before stat
		// and store the absolute path in the ref file.
		base := t.TempDir()
		rel, err := filepath.Rel(mustCwd(t), base)
		if err != nil {
			t.Skipf("cannot make relative path: %v", err)
		}
		if err := m.RegisterLocalTemplate("rel:v1", rel); err != nil {
			t.Fatalf("RegisterLocalTemplate relative: %v", err)
		}
		ref, err := m.LoadRefEntry("rel:v1", "overlay")
		if err != nil {
			t.Fatalf("LoadRefEntry: %v", err)
		}
		abs, _ := filepath.Abs(base)
		if len(ref.Layers) != 1 || ref.Layers[0] != abs {
			t.Errorf("stored layer = %v, want absolute %q", ref.Layers, abs)
		}
	})
}

func TestRegisterFlatTemplate_Errors(t *testing.T) {
	m, err := NewManager(Config{TemplatesDir: t.TempDir(), OverlayBase: t.TempDir(), ResolveVolume: legacyResolver(t.TempDir())})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	t.Run("nonexistent directory", func(t *testing.T) {
		if err := m.RegisterFlatTemplate("x:v1", filepath.Join(t.TempDir(), "nope")); err == nil {
			t.Error("expected error for nonexistent dir")
		}
	})
	t.Run("path is a file not a directory", func(t *testing.T) {
		f := filepath.Join(t.TempDir(), "file")
		if err := os.WriteFile(f, []byte("x"), 0644); err != nil {
			t.Fatal(err)
		}
		if err := m.RegisterFlatTemplate("x:v1", f); err == nil {
			t.Error("expected error when path is a file")
		}
	})
	t.Run("stores mode=flat", func(t *testing.T) {
		d := t.TempDir()
		createMockRootfs(t, d)
		if err := m.RegisterFlatTemplate("alpine:3.20", d); err != nil {
			t.Fatalf("RegisterFlatTemplate: %v", err)
		}
		ref, err := m.LoadRefEntry("alpine:3.20", "flat")
		if err != nil {
			t.Fatalf("LoadRefEntry flat: %v", err)
		}
		if ref.GetMode() != "flat" {
			t.Errorf("mode = %q, want flat", ref.GetMode())
		}
	})
}

// -----------------------------------------------------------------------------
// ScanLocalTemplates / ScanFlatTemplates (auto-discovery + skip rules)
// -----------------------------------------------------------------------------

// TestScanLocalTemplates_SkipsLayersAndRefs verifies the auto-scan does not
// recurse into the internal layers/ and refs/ directories of the unified
// storage layout.
func TestScanLocalTemplates_SkipsLayersAndRefs(t *testing.T) {
	templatesDir := t.TempDir()

	// Create a layer dir directly under templatesDir/layers that looks like a
	// rootfs; it must NOT be registered as a template.
	sneaky := filepath.Join(templatesDir, "layers", "sha256-sneaky")
	if err := os.MkdirAll(sneaky, 0755); err != nil {
		t.Fatal(err)
	}
	createMockRootfs(t, sneaky)
	// A refs dir with a json file must not be scanned as a template either.
	if err := os.MkdirAll(filepath.Join(templatesDir, "refs"), 0755); err != nil {
		t.Fatal(err)
	}

	// One legitimate versioned template.
	legit := filepath.Join(templatesDir, "sqlite", "v1")
	if err := os.MkdirAll(legit, 0755); err != nil {
		t.Fatal(err)
	}
	createMockRootfs(t, legit)

	m, err := NewManager(Config{TemplatesDir: templatesDir, OverlayBase: t.TempDir(), ResolveVolume: legacyResolver(t.TempDir())})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	// Only sqlite:v1 should be discoverable.
	if _, err := m.GetTemplate("sqlite:v1", "overlay"); err != nil {
		t.Errorf("expected sqlite:v1 to be registered: %v", err)
	}
	// The sneaky layer dir must not have been registered under any ref.
	for _, ref := range m.ListLocalTemplates() {
		if strings.Contains(ref, "sneaky") || strings.Contains(ref, "layers") || strings.Contains(ref, "sha256-sneaky") {
			t.Errorf("internal layers/ leaked into ListLocalTemplates: %q", ref)
		}
	}
}

// TestScanLocalTemplates_FlatRootfs verifies that a top-level directory that is
// itself a rootfs (has bin/etc/usr) is registered as an unversioned overlay
// template (backward-compatible flat-layout detection).
func TestScanLocalTemplates_FlatRootfs(t *testing.T) {
	templatesDir := t.TempDir()
	flatRootfs := filepath.Join(templatesDir, "myrootfs")
	if err := os.MkdirAll(flatRootfs, 0755); err != nil {
		t.Fatal(err)
	}
	createMockRootfs(t, flatRootfs)

	m, err := NewManager(Config{TemplatesDir: templatesDir, OverlayBase: t.TempDir(), ResolveVolume: legacyResolver(t.TempDir())})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	tmpl, err := m.GetTemplate("myrootfs", "overlay")
	if err != nil {
		t.Fatalf("expected myrootfs registered as overlay (version local): %v", err)
	}
	if tmpl.Name != "myrootfs" {
		t.Errorf("name = %q, want myrootfs", tmpl.Name)
	}
}

// TestScanLocalTemplates_NonexistentDir verifies a missing scan target errors.
func TestScanLocalTemplates_NonexistentDir(t *testing.T) {
	m, err := NewManager(Config{TemplatesDir: t.TempDir(), OverlayBase: t.TempDir(), ResolveVolume: legacyResolver(t.TempDir())})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if err := m.ScanLocalTemplates(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Error("expected error scanning nonexistent dir")
	}
}

// TestScanFlatTemplates covers the flat-templates scanner: versioned layout,
// flat layout, empty directory, and that all registrations are mode=flat.
func TestScanFlatTemplates(t *testing.T) {
	t.Run("versioned and flat layouts", func(t *testing.T) {
		flatDir := t.TempDir()
		// Versioned: ubuntu/24.04, ubuntu/26.04
		for _, ver := range []string{"24.04", "26.04"} {
			d := filepath.Join(flatDir, "ubuntu", ver)
			if err := os.MkdirAll(d, 0755); err != nil {
				t.Fatal(err)
			}
			createMockRootfs(t, d)
		}
		// Flat: alpine/ is itself a rootfs
		alpine := filepath.Join(flatDir, "alpine")
		if err := os.MkdirAll(alpine, 0755); err != nil {
			t.Fatal(err)
		}
		createMockRootfs(t, alpine)

		m, err := NewManager(Config{TemplatesDir: t.TempDir(), OverlayBase: t.TempDir(), ResolveVolume: legacyResolver(t.TempDir())})
		if err != nil {
			t.Fatalf("NewManager: %v", err)
		}
		if err := m.ScanFlatTemplates(flatDir); err != nil {
			t.Fatalf("ScanFlatTemplates: %v", err)
		}

		// All discovered templates must be flat mode.
		for _, ref := range []string{"ubuntu:24.04", "ubuntu:26.04", "alpine"} {
			entry, err := m.LoadRefEntry(ref, "flat")
			if err != nil {
				t.Errorf("LoadRefEntry(%q, flat): %v", ref, err)
				continue
			}
			if entry.GetMode() != "flat" {
				t.Errorf("ref %q mode = %q, want flat", ref, entry.GetMode())
			}
		}
		// And must NOT be loadable as overlay (no overlay ref file written).
		if _, err := m.LoadRefEntry("ubuntu:24.04", "overlay"); err == nil {
			t.Error("flat-scan template should not have an overlay ref file")
		}
	})

	t.Run("empty directory", func(t *testing.T) {
		m, err := NewManager(Config{TemplatesDir: t.TempDir(), OverlayBase: t.TempDir(), ResolveVolume: legacyResolver(t.TempDir())})
		if err != nil {
			t.Fatalf("NewManager: %v", err)
		}
		if err := m.ScanFlatTemplates(t.TempDir()); err != nil {
			t.Errorf("ScanFlatTemplates on empty dir: unexpected error %v", err)
		}
	})

	t.Run("nonexistent directory errors", func(t *testing.T) {
		m, err := NewManager(Config{TemplatesDir: t.TempDir(), OverlayBase: t.TempDir(), ResolveVolume: legacyResolver(t.TempDir())})
		if err != nil {
			t.Fatalf("NewManager: %v", err)
		}
		if err := m.ScanFlatTemplates(filepath.Join(t.TempDir(), "missing")); err == nil {
			t.Error("expected error scanning missing dir")
		}
	})
}

// TestScanFlatTemplates_NoDoubleScanIntoOverlay verifies that scanning a flat
// templates directory via ScanFlatTemplates does NOT accidentally register the
// same templates as overlay (mode isolation between the two scanners).
func TestScanFlatTemplates_NoDoubleScanIntoOverlay(t *testing.T) {
	flatDir := t.TempDir()
	d := filepath.Join(flatDir, "redis", "v1")
	if err := os.MkdirAll(d, 0755); err != nil {
		t.Fatal(err)
	}
	createMockRootfs(t, d)

	m, err := NewManager(Config{TemplatesDir: t.TempDir(), OverlayBase: t.TempDir(), ResolveVolume: legacyResolver(t.TempDir())})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if err := m.ScanFlatTemplates(flatDir); err != nil {
		t.Fatalf("ScanFlatTemplates: %v", err)
	}
	if _, err := m.LoadRefEntry("redis:v1", "overlay"); err == nil {
		t.Error("ScanFlatTemplates must not write overlay ref files")
	}
}

// -----------------------------------------------------------------------------
// scanRefs (startup validation, legacy + malformed tolerance)
// -----------------------------------------------------------------------------

// TestScanRefs_TolerantOfBadEntries verifies NewManager does not fail when refs/
// contains malformed JSON, refs pointing at missing layers, non-json files, or
// legacy (mode-less) ref files. Bad entries are silently skipped.
func TestScanRefs_TolerantOfBadEntries(t *testing.T) {
	templatesDir := t.TempDir()
	refsDir := filepath.Join(templatesDir, "refs")
	if err := os.MkdirAll(refsDir, 0755); err != nil {
		t.Fatal(err)
	}
	layersDir := filepath.Join(templatesDir, "layers")
	if err := os.MkdirAll(layersDir, 0755); err != nil {
		t.Fatal(err)
	}

	// A valid layer that exists.
	goodLayer := filepath.Join(layersDir, "local-good-v1")
	if err := os.MkdirAll(goodLayer, 0755); err != nil {
		t.Fatal(err)
	}

	// Malformed JSON -> skipped.
	os.WriteFile(filepath.Join(refsDir, "broken.overlay.json"), []byte("{not json"), 0644)
	// Valid JSON but first layer missing -> skipped.
	os.WriteFile(filepath.Join(refsDir, "ghost.overlay.json"),
		[]byte(`{"name":"ghost","version":"v1","mode":"overlay","layers":["local-missing-v1"]}`), 0644)
	// Non-json file -> skipped.
	os.WriteFile(filepath.Join(refsDir, "notes.txt"), []byte("hi"), 0644)
	// Legacy (mode-less) ref with a valid layer -> tolerated (no crash).
	os.WriteFile(filepath.Join(refsDir, "legacy_v1.json"),
		[]byte(`{"name":"legacy","version":"v1","layers":["local-good-v1"]}`), 0644)
	// A valid mode-suffixed ref with an existing layer -> discoverable.
	os.WriteFile(filepath.Join(refsDir, "good_v1.overlay.json"),
		[]byte(`{"name":"good","version":"v1","mode":"overlay","layers":["local-good-v1"]}`), 0644)

	m, err := NewManager(Config{TemplatesDir: templatesDir, OverlayBase: t.TempDir(), ResolveVolume: legacyResolver(t.TempDir())})
	if err != nil {
		t.Fatalf("NewManager with bad refs: %v", err)
	}

	// good:v1 must be loadable (mode-suffixed, layer present).
	if _, err := m.GetTemplate("good:v1", "overlay"); err != nil {
		t.Errorf("good:v1 should be loadable: %v", err)
	}
	// ghost:v1 was skipped because its layer is missing.
	if _, err := m.GetTemplate("ghost:v1", "overlay"); err == nil {
		t.Error("ghost:v1 should not be loadable (missing layer)")
	}
}

// -----------------------------------------------------------------------------
// SaveAsTemplate (full coverage: success, rejections, content copy)
// -----------------------------------------------------------------------------

func TestSaveAsTemplate_Success(t *testing.T) {
	templatesDir := t.TempDir()
	overlayBase := t.TempDir()
	m, err := NewManager(Config{TemplatesDir: templatesDir, OverlayBase: overlayBase, ResolveVolume: legacyResolver(overlayBase)})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	// A flat SandFS: directory directly under overlayBase, no .template marker.
	sandfsDir := filepath.Join(overlayBase, "flat-sandfs-1")
	if err := os.MkdirAll(sandfsDir, 0755); err != nil {
		t.Fatal(err)
	}
	createMockRootfs(t, sandfsDir)
	if err := os.WriteFile(filepath.Join(sandfsDir, "agent.txt"), []byte("hello"), 0644); err != nil {
		t.Fatal(err)
	}
	// Write a payload > 1KiB so the integer-KiB SizeKB field is non-zero.
	if err := os.WriteFile(filepath.Join(sandfsDir, "payload.bin"), bytes.Repeat([]byte("x"), 2048), 0644); err != nil {
		t.Fatal(err)
	}

	resp, err := m.SaveAsTemplate(context.Background(), "flat-sandfs-1", SaveAsTemplateRequest{
		TemplateRef: "saved:v2",
		Description: "from flat sandfs",
	})
	if err != nil {
		t.Fatalf("SaveAsTemplate: %v", err)
	}
	if resp.TemplateRef != "saved:v2" {
		t.Errorf("TemplateRef = %q", resp.TemplateRef)
	}

	// The saved layer must live under layers/local-<name>-<ver>/.
	expectedLayer := filepath.Join(templatesDir, "layers", "local-saved-v2")
	if resp.Path != expectedLayer {
		t.Errorf("Path = %q, want %q", resp.Path, expectedLayer)
	}
	if _, err := os.Stat(resp.Path); err != nil {
		t.Errorf("saved layer dir missing: %v", err)
	}
	// Content copied through.
	if _, err := os.Stat(filepath.Join(resp.Path, "agent.txt")); err != nil {
		t.Errorf("agent.txt not copied: %v", err)
	}
	if resp.SizeKB <= 0 {
		t.Errorf("SizeKB = %d, want > 0", resp.SizeKB)
	}

	// Ref file must store the RELATIVE layer path (OCI-style) and mode=overlay
	// so the saved template is consumed as an overlay lowerdir.
	entry, err := m.LoadRefEntry("saved:v2", "overlay")
	if err != nil {
		t.Fatalf("LoadRefEntry: %v", err)
	}
	if entry.GetMode() != "overlay" {
		t.Errorf("mode = %q, want overlay", entry.GetMode())
	}
	if len(entry.Layers) != 1 || entry.Layers[0] != "local-saved-v2" {
		t.Errorf("layers = %v, want [local-saved-v2] (relative)", entry.Layers)
	}
	// ResolveLayerPath must expand the relative path back to the absolute dir.
	if got := m.ResolveLayerPath(entry.Layers[0]); got != expectedLayer {
		t.Errorf("ResolveLayerPath = %q, want %q", got, expectedLayer)
	}
	// GetTemplate must see it.
	if _, err := m.GetTemplate("saved:v2", "overlay"); err != nil {
		t.Errorf("GetTemplate: %v", err)
	}
}

// A saved template is consumed as an overlay lowerdir, so anything the copy
// leaves in the layer shows at the merged root of every guest booted from it.
// The volume tree's control files are VOLUME state, not template content:
// the identity stamp would leak the source tenant's sandfs id, generation
// fingerprint and creation time across tenants.
func TestSaveAsTemplate_StripsVolumeControlFiles(t *testing.T) {
	templatesDir := t.TempDir()
	overlayBase := t.TempDir()
	m, err := NewManager(Config{TemplatesDir: templatesDir, OverlayBase: overlayBase, ResolveVolume: legacyResolver(overlayBase)})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	sandfsDir := filepath.Join(overlayBase, "flat-stamped")
	if err := os.MkdirAll(sandfsDir, 0755); err != nil {
		t.Fatal(err)
	}
	createMockRootfs(t, sandfsDir)
	if err := os.WriteFile(filepath.Join(sandfsDir, ".sandfs-id"),
		[]byte("sandfs_id: sandfs-abc123\ngeneration: deadbeef\ncreated_unix: 1700000000\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sandfsDir, ".provisioning"), []byte("provisioning\n"), 0644); err != nil {
		t.Fatal(err)
	}

	resp, err := m.SaveAsTemplate(context.Background(), "flat-stamped", SaveAsTemplateRequest{TemplateRef: "stripped:v1"})
	if err != nil {
		t.Fatalf("SaveAsTemplate: %v", err)
	}
	for _, residue := range []string{".sandfs-id", ".provisioning"} {
		if _, err := os.Stat(filepath.Join(resp.Path, residue)); err == nil {
			t.Errorf("volume control file %s survived into the saved layer — it would appear at every consuming guest's merged root", residue)
		}
	}
	// The source volume keeps its own stamp: stripping is copy-side only.
	if _, err := os.Stat(filepath.Join(sandfsDir, ".sandfs-id")); err != nil {
		t.Errorf("the source volume must keep its stamp: %v", err)
	}
	// Ordinary content still copies through.
	if _, err := os.Stat(filepath.Join(resp.Path, "etc")); err != nil {
		t.Errorf("template content missing: %v", err)
	}
}

func TestSaveAsTemplate_Rejections(t *testing.T) {
	m, err := NewManager(Config{TemplatesDir: t.TempDir(), OverlayBase: t.TempDir(), ResolveVolume: legacyResolver(t.TempDir())})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	t.Run("sandfs not found", func(t *testing.T) {
		_, err := m.SaveAsTemplate(context.Background(), "missing", SaveAsTemplateRequest{TemplateRef: "x:v1"})
		if err == nil || !strings.Contains(err.Error(), "sandfs not found") {
			t.Errorf("expected sandfs-not-found error, got %v", err)
		}
	})
	t.Run("overlay sandfs rejected (.template marker)", func(t *testing.T) {
		overlayBase := t.TempDir()
		m2, err := NewManager(Config{TemplatesDir: t.TempDir(), OverlayBase: overlayBase, ResolveVolume: legacyResolver(overlayBase)})
		if err != nil {
			t.Fatal(err)
		}
		d := filepath.Join(overlayBase, "ov-sandfs")
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, ".template"), []byte("base:v1"), 0644); err != nil {
			t.Fatal(err)
		}
		_, err = m2.SaveAsTemplate(context.Background(), "ov-sandfs", SaveAsTemplateRequest{TemplateRef: "x:v1"})
		if err == nil || !strings.Contains(err.Error(), "cannot save overlay SandFS") {
			t.Errorf("expected overlay rejection, got %v", err)
		}
	})
	t.Run("unversioned ref rejected", func(t *testing.T) {
		overlayBase := t.TempDir()
		m2, err := NewManager(Config{TemplatesDir: t.TempDir(), OverlayBase: overlayBase, ResolveVolume: legacyResolver(overlayBase)})
		if err != nil {
			t.Fatal(err)
		}
		d := filepath.Join(overlayBase, "f1")
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
		for _, bad := range []string{"nocolon", "name:local"} {
			_, err := m2.SaveAsTemplate(context.Background(), "f1", SaveAsTemplateRequest{TemplateRef: bad})
			if err == nil {
				t.Errorf("expected error for ref %q", bad)
			}
		}
	})
	t.Run("already exists", func(t *testing.T) {
		templatesDir := t.TempDir()
		overlayBase := t.TempDir()
		m2, err := NewManager(Config{TemplatesDir: templatesDir, OverlayBase: overlayBase, ResolveVolume: legacyResolver(overlayBase)})
		if err != nil {
			t.Fatal(err)
		}
		d := filepath.Join(overlayBase, "f2")
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
		req := SaveAsTemplateRequest{TemplateRef: "dup:v1"}
		if _, err := m2.SaveAsTemplate(context.Background(), "f2", req); err != nil {
			t.Fatalf("first save: %v", err)
		}
		if _, err := m2.SaveAsTemplate(context.Background(), "f2", req); err == nil {
			t.Error("expected already-exists error on second save")
		}
	})
}

// -----------------------------------------------------------------------------
// GetTemplate / LoadRefEntry error handling
// -----------------------------------------------------------------------------

func TestGetTemplate_NotFound(t *testing.T) {
	m, err := NewManager(Config{TemplatesDir: t.TempDir(), OverlayBase: t.TempDir(), ResolveVolume: legacyResolver(t.TempDir())})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if _, err := m.GetTemplate("missing:v1", "overlay"); err == nil {
		t.Error("expected error for missing template")
	}
}

// TestLoadRefEntry_BothModes verifies a same-name flat+overlay pair is loadable
// under each respective mode and that the wrong mode misses.
func TestLoadRefEntry_BothModes(t *testing.T) {
	m, err := NewManager(Config{TemplatesDir: t.TempDir(), OverlayBase: t.TempDir(), ResolveVolume: legacyResolver(t.TempDir())})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	d := t.TempDir()
	createMockRootfs(t, d)
	if err := m.RegisterLocalTemplate("pair:v1", d); err != nil {
		t.Fatal(err)
	}
	if err := m.RegisterFlatTemplate("pair:v1", d); err != nil {
		t.Fatal(err)
	}
	if _, err := m.LoadRefEntry("pair:v1", "overlay"); err != nil {
		t.Errorf("overlay mode: %v", err)
	}
	if _, err := m.LoadRefEntry("pair:v1", "flat"); err != nil {
		t.Errorf("flat mode: %v", err)
	}
}

// -----------------------------------------------------------------------------
// Layer dedup (same identifier -> same directory)
// -----------------------------------------------------------------------------

// TestLayerDedup_SharedDirectory verifies that two ref files referencing the
// same layer identifier resolve to the same on-disk directory. This is the
// storage-dedup invariant for OCI layers (same digest -> same dir) and for
// locally-saved templates (relative name -> single layersDir entry).
func TestLayerDedup_SharedDirectory(t *testing.T) {
	templatesDir := t.TempDir()
	m, err := NewManager(Config{TemplatesDir: templatesDir, OverlayBase: t.TempDir(), ResolveVolume: legacyResolver(t.TempDir())})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	layersDir := filepath.Join(templatesDir, "layers")

	// One shared layer directory (simulating a pulled OCI layer).
	shared := filepath.Join(layersDir, "sha256-shared")
	if err := os.MkdirAll(shared, 0755); err != nil {
		t.Fatal(err)
	}
	createMockRootfs(t, shared)

	// Two distinct ref files both reference the SAME relative layer id.
	for _, ref := range []string{"appA:v1", "appB:v1"} {
		name, ver := parseTemplateRef(ref)
		entry := RefEntry{Name: name, Version: ver, Mode: "overlay", Layers: []string{"sha256-shared"}}
		if err := m.writeRefFile(ref, entry); err != nil {
			t.Fatalf("writeRefFile %s: %v", ref, err)
		}
	}

	// Both refs resolve to the identical absolute path -> single dir on disk.
	a := m.ResolveLayerPath("sha256-shared")
	b := m.ResolveLayerPath("sha256-shared")
	if a != shared || b != shared {
		t.Errorf("dedup paths = %q / %q, want %q", a, b, shared)
	}
	// And both refs are independently loadable.
	for _, ref := range []string{"appA:v1", "appB:v1"} {
		e, err := m.LoadRefEntry(ref, "overlay")
		if err != nil {
			t.Errorf("LoadRefEntry %s: %v", ref, err)
			continue
		}
		if e.Layers[0] != "sha256-shared" {
			t.Errorf("ref %s layer = %q, want sha256-shared", ref, e.Layers[0])
		}
	}
}

// -----------------------------------------------------------------------------
// NewManager: auth error path + idempotent re-init
// -----------------------------------------------------------------------------

// TestNewManager_BadAuthErrors verifies a malformed auth config (bad cert/key
// paths) causes NewManager to fail with a setup-auth error rather than a panic.
func TestNewManager_BadAuthErrors(t *testing.T) {
	_, err := NewManager(Config{
		Registry:     "localhost:5000/repo",
		TemplatesDir: t.TempDir(),
		OverlayBase:  t.TempDir(),
		Auth:         AuthConfig{CertFile: "/nonexistent-cert", KeyFile: "/nonexistent-key"},
	})
	if err == nil || !strings.Contains(err.Error(), "setup auth") {
		t.Errorf("expected setup-auth error, got %v", err)
	}
}

// TestNewManager_IdempotentReinit verifies that re-creating a manager over the
// same templatesDir is safe and re-discovers existing templates (disk is the
// source of truth, no in-memory cache to corrupt).
func TestNewManager_IdempotentReinit(t *testing.T) {
	templatesDir := t.TempDir()
	m1, err := NewManager(Config{TemplatesDir: templatesDir, OverlayBase: t.TempDir(), ResolveVolume: legacyResolver(t.TempDir())})
	if err != nil {
		t.Fatalf("NewManager 1: %v", err)
	}
	d := t.TempDir()
	createMockRootfs(t, d)
	if err := m1.RegisterLocalTemplate("persist:v1", d); err != nil {
		t.Fatal(err)
	}

	// Second manager over the same dir must rediscover persist:v1.
	m2, err := NewManager(Config{TemplatesDir: templatesDir, OverlayBase: t.TempDir(), ResolveVolume: legacyResolver(t.TempDir())})
	if err != nil {
		t.Fatalf("NewManager 2: %v", err)
	}
	if _, err := m2.GetTemplate("persist:v1", "overlay"); err != nil {
		t.Errorf("persist:v1 not rediscovered: %v", err)
	}
	// No in-memory cache: ListLocalTemplates reads disk both times.
	list1 := m1.ListLocalTemplates()
	list2 := m2.ListLocalTemplates()
	if len(list1) != len(list2) {
		t.Errorf("ListLocalTemplates diverged across managers: %v vs %v", list1, list2)
	}
}

// -----------------------------------------------------------------------------
// PullTemplate / PushTemplate (error paths - registry integration out of scope)
// -----------------------------------------------------------------------------

func TestPullTemplate_NoRegistry(t *testing.T) {
	m, err := NewManager(Config{TemplatesDir: t.TempDir(), OverlayBase: t.TempDir(), ResolveVolume: legacyResolver(t.TempDir())})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.PullTemplate(context.Background(), "x:v1", ""); err == nil {
		t.Error("expected error pulling with no registry configured")
	}
}

func TestPushTemplate_NoRegistry(t *testing.T) {
	m, err := NewManager(Config{TemplatesDir: t.TempDir(), OverlayBase: t.TempDir(), ResolveVolume: legacyResolver(t.TempDir())})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.PushTemplate(context.Background(), "x:v1", ""); err == nil {
		t.Error("expected error pushing with no registry configured")
	}
}

func TestPushTemplate_TemplateNotFound(t *testing.T) {
	m, err := NewManager(Config{
		Registry:     "localhost:5000/repo",
		TemplatesDir: t.TempDir(),
		OverlayBase:  t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = m.PushTemplate(context.Background(), "missing:v1", "")
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected not-found error, got %v", err)
	}
}

// -----------------------------------------------------------------------------
// packTarGz / extractTarGzToDir (PullTemplate/PushTemplate helpers)
// -----------------------------------------------------------------------------

func TestPackTarGz_AndExtractRoundTrip(t *testing.T) {
	// Build a source tree with a file, a subdir+file, and a symlink.
	src := t.TempDir()
	if err := os.MkdirAll(filepath.Join(src, "sub"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "top.txt"), []byte("top"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "sub", "nested.txt"), []byte("nested"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("top.txt", filepath.Join(src, "link.txt")); err != nil {
		t.Fatal(err)
	}

	archive := filepath.Join(t.TempDir(), "layer.tar.gz")
	if err := packTarGz(src, archive); err != nil {
		t.Fatalf("packTarGz: %v", err)
	}

	// Verify the archive is a valid tar.gz containing the expected entries.
	if err := tarGzContains(archive, []string{"top.txt", "sub", "sub/nested.txt", "link.txt"}); err != nil {
		t.Fatalf("archive contents: %v", err)
	}

	// Round-trip: extract into a fresh dir and compare tree.
	dst := t.TempDir()
	archiveBytes, err := os.Open(archive)
	if err != nil {
		t.Fatal(err)
	}
	defer archiveBytes.Close()
	if err := extractTarGzToDir(archiveBytes, dst, extractOptions{}); err != nil {
		t.Fatalf("extractTarGzToDir: %v", err)
	}
	for _, p := range []string{"top.txt", "sub/nested.txt"} {
		if _, err := os.Stat(filepath.Join(dst, p)); err != nil {
			t.Errorf("extracted %s missing: %v", p, err)
		}
	}
	// Symlink must be reconstructed as a symlink with the original target.
	linkTarget, err := os.Readlink(filepath.Join(dst, "link.txt"))
	if err != nil {
		t.Errorf("readlink link.txt: %v", err)
	} else if linkTarget != "top.txt" {
		t.Errorf("link target = %q, want top.txt", linkTarget)
	}
}

// TestExtractTarGzToDir_HardLinkFallback verifies the hardlink branch (with a
// cross-device fallback copy when os.Link fails). We place both the target and
// the link in the same archive so the hardlink can succeed within dst.
func TestExtractTarGzToDir_HardLinkFallback(t *testing.T) {
	// Build a tar.gz manually containing a regular file + a hardlink to it.
	var buf bytes.Buffer
	gzw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gzw)
	if err := tw.WriteHeader(&tar.Header{Name: "base.txt", Mode: 0644, Size: 4, Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	tw.Write([]byte("base"))
	if err := tw.WriteHeader(&tar.Header{Name: "linked.txt", Mode: 0644, Typeflag: tar.TypeLink, Linkname: "base.txt"}); err != nil {
		t.Fatal(err)
	}
	tw.Close()
	gzw.Close()

	dst := t.TempDir()
	if err := extractTarGzToDir(bytes.NewReader(buf.Bytes()), dst, extractOptions{}); err != nil {
		t.Fatalf("extractTarGzToDir: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dst, "linked.txt"))
	if err != nil {
		t.Fatalf("read linked.txt: %v", err)
	}
	if string(data) != "base" {
		t.Errorf("linked.txt = %q, want base", string(data))
	}
}

// TestExtractTarGzToDir_BadGzip verifies a non-gzip stream errors cleanly.
func TestExtractTarGzToDir_BadGzip(t *testing.T) {
	dst := t.TempDir()
	if err := extractTarGzToDir(bytes.NewReader([]byte("not gzip at all")), dst, extractOptions{}); err == nil {
		t.Error("expected error for non-gzip input")
	}
}

// -----------------------------------------------------------------------------
// AuthConfig.toClient (cert branch)
// -----------------------------------------------------------------------------

func TestAuthConfig_ToClient_Cert(t *testing.T) {
	t.Run("cert + key", func(t *testing.T) {
		certPath, keyPath := generateTestCert(t)
		c, err := AuthConfig{CertFile: certPath, KeyFile: keyPath}.toClient()
		if err != nil {
			t.Fatalf("toClient: %v", err)
		}
		if c == nil || c.Client == nil {
			t.Error("expected http.Client configured for mTLS")
		}
	})
	t.Run("cert + key + CA", func(t *testing.T) {
		certPath, keyPath := generateTestCert(t)
		// Use the same cert as the CA bundle (self-signed).
		c, err := AuthConfig{CertFile: certPath, KeyFile: keyPath, CAFile: certPath}.toClient()
		if err != nil {
			t.Fatalf("toClient: %v", err)
		}
		if c == nil || c.Client == nil {
			t.Error("expected http.Client with CA pool")
		}
	})
	t.Run("bad CA file errors", func(t *testing.T) {
		certPath, keyPath := generateTestCert(t)
		_, err := AuthConfig{CertFile: certPath, KeyFile: keyPath, CAFile: "/nonexistent-ca"}.toClient()
		if err == nil || !strings.Contains(err.Error(), "read CA cert") {
			t.Errorf("expected read-CA error, got %v", err)
		}
	})
	t.Run("cert without key is rejected", func(t *testing.T) {
		// CertFile set but KeyFile empty is always a configuration mistake —
		// silently falling back to anonymous would surface far away as an
		// auth failure. Same for the mirror image.
		for _, cfg := range []AuthConfig{
			{CertFile: "/some-cert"},
			{KeyFile: "/some-key"},
		} {
			if _, err := cfg.toClient(); err == nil || !strings.Contains(err.Error(), "requires both cert and key") {
				t.Errorf("toClient(%+v): expected cert/key pairing error, got %v", cfg, err)
			}
		}
	})
	t.Run("CA file without a PEM certificate errors", func(t *testing.T) {
		// AppendCertsFromPEM returns false on garbage; ignoring it would leave
		// an empty pool and fail TLS verification far from the cause.
		caPath := filepath.Join(t.TempDir(), "not-a-cert.pem")
		if err := os.WriteFile(caPath, []byte("this is not a pem"), 0644); err != nil {
			t.Fatal(err)
		}
		if _, err := (AuthConfig{CAFile: caPath}).toClient(); err == nil || !strings.Contains(err.Error(), "read CA cert") {
			t.Errorf("expected read-CA error for garbage PEM, got %v", err)
		}
	})
}

// -----------------------------------------------------------------------------
// isVersionedTemplateDir / isRootfsDir (heuristics)
// -----------------------------------------------------------------------------

func TestIsVersionedTemplateDir(t *testing.T) {
	t.Run("nonexistent -> false", func(t *testing.T) {
		if isVersionedTemplateDir(filepath.Join(t.TempDir(), "nope")) {
			t.Error("nonexistent dir should not be versioned")
		}
	})
	t.Run("empty dir -> false", func(t *testing.T) {
		d := t.TempDir()
		if isVersionedTemplateDir(d) {
			t.Error("empty dir should not be versioned")
		}
	})
	t.Run("has rootfs marker (bin/) -> false (is itself a rootfs)", func(t *testing.T) {
		d := t.TempDir()
		if err := os.MkdirAll(filepath.Join(d, "bin"), 0755); err != nil {
			t.Fatal(err)
		}
		if isVersionedTemplateDir(d) {
			t.Error("dir with bin/ should be treated as a rootfs (flat)")
		}
	})
	t.Run("has files at top level -> false (looks like a rootfs)", func(t *testing.T) {
		d := t.TempDir()
		if err := os.MkdirAll(filepath.Join(d, "v1"), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "README"), []byte("x"), 0644); err != nil {
			t.Fatal(err)
		}
		if isVersionedTemplateDir(d) {
			t.Error("dir with top-level files should be flat")
		}
	})
	t.Run("subdirs that are rootfs -> true (versioned)", func(t *testing.T) {
		d := t.TempDir()
		v1 := filepath.Join(d, "v1")
		if err := os.MkdirAll(filepath.Join(v1, "bin"), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(v1, "etc"), 0755); err != nil {
			t.Fatal(err)
		}
		if !isVersionedTemplateDir(d) {
			t.Error("dir with rootfs-looking subdirs should be versioned")
		}
	})
	t.Run("subdirs that are NOT rootfs -> false (heuristic limitation)", func(t *testing.T) {
		// All subdirs, none look like a rootfs (no bin/etc/usr): the heuristic
		// conservatively treats it as flat. This documents the known limitation
		// that minimal version dirs without rootfs markers are misclassified.
		d := t.TempDir()
		if err := os.MkdirAll(filepath.Join(d, "v1", "data"), 0755); err != nil {
			t.Fatal(err)
		}
		if isVersionedTemplateDir(d) {
			t.Error("dir with non-rootfs subdirs should be flat per heuristic")
		}
	})
}

func TestIsRootfsDir(t *testing.T) {
	t.Run("has bin -> true", func(t *testing.T) {
		d := t.TempDir()
		os.MkdirAll(filepath.Join(d, "bin"), 0755)
		if !isRootfsDir(d) {
			t.Error("dir with bin/ should be a rootfs")
		}
	})
	t.Run("has etc -> true", func(t *testing.T) {
		d := t.TempDir()
		os.MkdirAll(filepath.Join(d, "etc"), 0755)
		if !isRootfsDir(d) {
			t.Error("dir with etc/ should be a rootfs")
		}
	})
	t.Run("has usr -> true", func(t *testing.T) {
		d := t.TempDir()
		os.MkdirAll(filepath.Join(d, "usr"), 0755)
		if !isRootfsDir(d) {
			t.Error("dir with usr/ should be a rootfs")
		}
	})
	t.Run("no markers -> false", func(t *testing.T) {
		d := t.TempDir()
		os.MkdirAll(filepath.Join(d, "workspace"), 0755)
		if isRootfsDir(d) {
			t.Error("dir without rootfs markers should not be a rootfs")
		}
	})
	t.Run("nonexistent -> false", func(t *testing.T) {
		if isRootfsDir(filepath.Join(t.TempDir(), "nope")) {
			t.Error("nonexistent dir should not be a rootfs")
		}
	})
}

// -----------------------------------------------------------------------------
// writeRefFile / loadRefFile round-trip (mode-suffixed filenames)
// -----------------------------------------------------------------------------

// TestWriteLoadRefFile_RoundTrip verifies the on-disk filename uses the
// mode suffix and that the entry round-trips losslessly.
func TestWriteLoadRefFile_RoundTrip(t *testing.T) {
	templatesDir := t.TempDir()
	m, err := NewManager(Config{TemplatesDir: templatesDir, OverlayBase: t.TempDir(), ResolveVolume: legacyResolver(t.TempDir())})
	if err != nil {
		t.Fatal(err)
	}
	entry := RefEntry{
		Name:        "myapp",
		Version:     "v3",
		Description: "desc",
		Mode:        "overlay",
		Layers:      []string{"/abs/path"},
	}
	if err := m.writeRefFile("myapp:v3", entry); err != nil {
		t.Fatal(err)
	}
	// Filename must be mode-suffixed.
	if _, err := os.Stat(filepath.Join(templatesDir, "refs", "myapp_v3.overlay.json")); err != nil {
		t.Errorf("mode-suffixed ref file not created: %v", err)
	}
	got, err := m.loadRefFile("myapp:v3", "overlay")
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != entry.Name || got.Version != entry.Version || got.GetMode() != "overlay" || len(got.Layers) != 1 || got.Layers[0] != "/abs/path" {
		t.Errorf("round-trip mismatch: %+v", got)
	}
	// Reading with the wrong mode must miss.
	if _, err := m.loadRefFile("myapp:v3", "flat"); err == nil {
		t.Error("loading with wrong mode should fail")
	}
}

// TestLoadRefFile_ParseError verifies a malformed ref file yields a parse error
// (not a panic) and a missing ref file yields a read error.
func TestLoadRefFile_ParseError(t *testing.T) {
	templatesDir := t.TempDir()
	m, err := NewManager(Config{TemplatesDir: templatesDir, OverlayBase: t.TempDir(), ResolveVolume: legacyResolver(t.TempDir())})
	if err != nil {
		t.Fatal(err)
	}
	// Malformed JSON at the expected path.
	badPath := filepath.Join(templatesDir, "refs", "bad_v1.overlay.json")
	if err := os.WriteFile(badPath, []byte("{not valid json"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := m.loadRefFile("bad:v1", "overlay"); err == nil || !strings.Contains(err.Error(), "parse ref file") {
		t.Errorf("expected parse ref file error, got %v", err)
	}
	// Missing file -> read error.
	if _, err := m.loadRefFile("missing:v1", "overlay"); err == nil || !strings.Contains(err.Error(), "read ref file") {
		t.Errorf("expected read ref file error, got %v", err)
	}
}

// TestScanRefs_MissingRefsDir verifies scanRefs tolerates a missing refs/
// directory (returns nil rather than erroring). This can happen if the
// directory is removed between NewManager calls.
func TestScanRefs_MissingRefsDir(t *testing.T) {
	templatesDir := t.TempDir()
	m, err := NewManager(Config{TemplatesDir: templatesDir, OverlayBase: t.TempDir(), ResolveVolume: legacyResolver(t.TempDir())})
	if err != nil {
		t.Fatal(err)
	}
	// Remove refs/ after construction; scanRefs must not error.
	if err := os.RemoveAll(m.refsDir()); err != nil {
		t.Fatal(err)
	}
	if err := m.scanRefs(); err != nil {
		t.Errorf("scanRefs with missing refs dir: unexpected error %v", err)
	}
}

// TestWriteRefFile_EmptyModeDefaultsToOverlay verifies writeRefFile normalizes
// an empty Mode to "overlay" in the on-disk filename (via GetMode).
func TestWriteRefFile_EmptyModeDefaultsToOverlay(t *testing.T) {
	templatesDir := t.TempDir()
	m, err := NewManager(Config{TemplatesDir: templatesDir, OverlayBase: t.TempDir(), ResolveVolume: legacyResolver(t.TempDir())})
	if err != nil {
		t.Fatal(err)
	}
	entry := RefEntry{Name: "n", Version: "v1", Layers: []string{"/x"}} // Mode empty
	if err := m.writeRefFile("n:v1", entry); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(templatesDir, "refs", "n_v1.overlay.json")); err != nil {
		t.Errorf("empty mode should write to .overlay.json: %v", err)
	}
}

// -----------------------------------------------------------------------------
// helpers
// -----------------------------------------------------------------------------

func mustCwd(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return wd
}

// tarGzContains checks that a tar.gz archive contains all of the named entries.
func tarGzContains(archivePath string, names []string) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer f.Close()
	gzr, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gzr.Close()
	tr := tar.NewReader(gzr)
	seen := map[string]bool{}
	for {
		hdr, err := tr.Next()
		if err != nil {
			break
		}
		seen[hdr.Name] = true
	}
	for _, n := range names {
		if !seen[n] {
			return fmt.Errorf("entry %q not found in archive (have %v)", n, keysOf(seen))
		}
	}
	return nil
}

func keysOf(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

// generateTestCert creates a self-signed cert + key PEM pair in temp files and
// returns their paths. Used to exercise the mTLS branch of AuthConfig.toClient.
func generateTestCert(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "sandswap-test"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("x509.CreateCertificate: %v", err)
	}
	dir := t.TempDir()
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644); err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalPKCS8: %v", err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		t.Fatal(err)
	}
	// Sanity: confirm the pair loads (same code path toClient uses).
	if _, err := tls.LoadX509KeyPair(certPath, keyPath); err != nil {
		t.Fatalf("generated cert/key do not load: %v", err)
	}
	return certPath, keyPath
}

// TestSaveAsTemplateUsesSignedStampMode pins the flat/overlay decision: a
// SIGNED stamp's mode is authoritative, so a tenant-planted .template marker
// in a flat volume cannot block its own backup. An absent/unsigned stamp is
// legacy and the marker still decides.
func TestSaveAsTemplateUsesSignedStampMode(t *testing.T) {
	newMgr := func(base string, verify func(string) (VolumeStamp, bool, error)) *Manager {
		t.Helper()
		m, err := NewManager(Config{
			TemplatesDir:      t.TempDir(),
			OverlayBase:       base,
			ResolveVolume:     legacyResolver(base),
			VerifyVolumeStamp: verify,
		})
		if err != nil {
			t.Fatalf("NewManager: %v", err)
		}
		return m
	}
	mkVolume := func(base, name string, marker bool) string {
		t.Helper()
		dir := filepath.Join(base, name)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		createMockRootfs(t, dir)
		if marker {
			if err := os.WriteFile(filepath.Join(dir, ".template"), []byte("base:v1"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		return dir
	}

	// Signed flat + a tenant-planted .template marker: must save.
	base1 := t.TempDir()
	mkVolume(base1, "flat-signed", true)
	m1 := newMgr(base1, func(string) (VolumeStamp, bool, error) {
		return VolumeStamp{SandfsID: "flat-signed", Mode: "flat"}, true, nil
	})
	if _, err := m1.SaveAsTemplate(context.Background(), "flat-signed", SaveAsTemplateRequest{TemplateRef: "saved-flat:v1"}); err != nil {
		t.Fatalf("signed flat volume with a .template marker was rejected: %v", err)
	}

	// Signed overlay: refused even without the marker.
	base2 := t.TempDir()
	mkVolume(base2, "overlay-signed", false)
	m2 := newMgr(base2, func(string) (VolumeStamp, bool, error) {
		return VolumeStamp{SandfsID: "overlay-signed", Mode: "overlay"}, true, nil
	})
	if _, err := m2.SaveAsTemplate(context.Background(), "overlay-signed", SaveAsTemplateRequest{TemplateRef: "saved-ov:v1"}); err == nil {
		t.Fatal("signed overlay volume was accepted")
	}

	// Unsigned legacy + marker: the marker still means overlay, refused.
	base3 := t.TempDir()
	mkVolume(base3, "legacy-overlay", true)
	m3 := newMgr(base3, func(string) (VolumeStamp, bool, error) { return VolumeStamp{}, false, nil })
	if _, err := m3.SaveAsTemplate(context.Background(), "legacy-overlay", SaveAsTemplateRequest{TemplateRef: "saved-legacy:v1"}); err == nil {
		t.Fatal("unsigned legacy volume with a .template marker was accepted")
	}
}

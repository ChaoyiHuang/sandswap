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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// storeFixture assembles a minimal healthy store: one overlay ref over a
// local- layer, one flat ref over an absolute in-store source directory, one
// content-addressed layer shared by nothing else yet referenced by the flat
// path's sibling — plus returns the paths tests mutate.
type storeFixture struct {
	store     string
	layersDir string
	refsDir   string
}

func shaLayerName(seed byte) string {
	return fmt.Sprintf("sha256-%064x", seed)
}

func newStoreFixture(t *testing.T) storeFixture {
	t.Helper()
	store := t.TempDir()
	f := storeFixture{
		store:     store,
		layersDir: filepath.Join(store, "layers"),
		refsDir:   filepath.Join(store, "refs"),
	}
	if err := os.MkdirAll(f.layersDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(f.refsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// A save-as-template-style layer + its ref.
	if err := os.MkdirAll(filepath.Join(f.layersDir, "local-myapp-v1", "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeRefFile(t, f.refsDir, "myapp_v1.overlay.json", map[string]any{
		"name": "myapp", "version": "v1", "mode": "overlay",
		"layers": []string{"local-myapp-v1"},
	})
	// A content-addressed OCI layer named by another overlay ref.
	if err := os.MkdirAll(filepath.Join(f.layersDir, shaLayerName(1)), 0o755); err != nil {
		t.Fatal(err)
	}
	writeRefFile(t, f.refsDir, "ubuntu_24.04.overlay.json", map[string]any{
		"name": "ubuntu", "version": "24.04", "mode": "overlay",
		"layers": []string{shaLayerName(1)},
	})
	// A flat ref over an absolute in-store source directory.
	src := filepath.Join(store, "flat-src", "v1")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	writeRefFile(t, f.refsDir, "rootfs_v1.flat.json", map[string]any{
		"name": "rootfs", "version": "v1", "mode": "flat",
		"layers": []string{src},
	})
	return f
}

func writeRefFile(t *testing.T, refsDir, name string, body map[string]any) {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(refsDir, name), data, 0o640); err != nil {
		t.Fatal(err)
	}
}

func TestValidateStore_Healthy(t *testing.T) {
	f := newStoreFixture(t)
	fs, err := ValidateStore(f.store, nil)
	if err != nil {
		t.Fatalf("ValidateStore: %v", err)
	}
	if len(fs) != 0 {
		t.Fatalf("expected no findings on a healthy store, got: %+v", fs)
	}
}

func TestValidateStore_NotAStore(t *testing.T) {
	dir := t.TempDir()
	if _, err := ValidateStore(dir, nil); err == nil {
		t.Fatal("expected an error for a directory with neither refs/ nor layers/")
	}
}

func TestValidateStore_RefIntegrity(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(t *testing.T, f storeFixture)
		wantRule string
		severity Severity
	}{
		{
			name: "entry names a different ref than the filename encodes",
			setup: func(t *testing.T, f storeFixture) {
				writeRefFile(t, f.refsDir, "collide_v1.overlay.json", map[string]any{
					"name": "somebody", "version": "else", "mode": "overlay",
					"layers": []string{"local-myapp-v1"},
				})
			},
			wantRule: "ref-identity", severity: SeverityError,
		},
		{
			name: "unparseable ref file",
			setup: func(t *testing.T, f storeFixture) {
				if err := os.WriteFile(filepath.Join(f.refsDir, "broken_v1.overlay.json"), []byte("{"), 0o640); err != nil {
					t.Fatal(err)
				}
			},
			wantRule: "ref-parse", severity: SeverityError,
		},
		{
			// The mode FIELD is only consumed at write time; readers select
			// the file by filename suffix. A parked bad value is a recording
			// defect, not a broken ref.
			name: "invalid mode value",
			setup: func(t *testing.T, f storeFixture) {
				writeRefFile(t, f.refsDir, "weird_v1.overlay.json", map[string]any{
					"name": "weird", "version": "v1", "mode": "chroot",
					"layers": []string{"local-myapp-v1"},
				})
			},
			wantRule: "ref-mode", severity: SeverityWarning,
		},
		{
			name: "partial identity records",
			setup: func(t *testing.T, f storeFixture) {
				writeRefFile(t, f.refsDir, "partial.overlay.json", map[string]any{
					"name":   "partial",
					"layers": []string{"local-myapp-v1"},
				})
			},
			wantRule: "ref-identity", severity: SeverityWarning,
		},
		{
			name: "OCI-only digests stored as overlay",
			setup: func(t *testing.T, f storeFixture) {
				writeRefFile(t, f.refsDir, "registryonly_v1.overlay.json", map[string]any{
					"name": "registryonly", "version": "v1", "mode": "overlay",
					"oci_layers": []map[string]any{{"digest": "sha256:" + strings.Repeat("ab", 32), "size": 10}},
				})
			},
			wantRule: "ref-mode", severity: SeverityError,
		},
		{
			name: "entry mode disagrees with filename suffix",
			setup: func(t *testing.T, f storeFixture) {
				writeRefFile(t, f.refsDir, "mixed_v1.flat.json", map[string]any{
					"name": "mixed", "version": "v1", "mode": "overlay",
					"layers": []string{"local-myapp-v1"},
				})
			},
			wantRule: "ref-mode", severity: SeverityWarning,
		},
		{
			name: "recorded mode empty while the filename says flat",
			setup: func(t *testing.T, f storeFixture) {
				writeRefFile(t, f.refsDir, "nomode_v1.flat.json", map[string]any{
					"name": "nomode", "version": "v1",
					"layers": []string{"local-myapp-v1"},
				})
			},
			wantRule: "ref-mode", severity: SeverityWarning,
		},
		{
			name: "mixed layer provenance",
			setup: func(t *testing.T, f storeFixture) {
				writeRefFile(t, f.refsDir, "mixedsrc_v1.flat.json", map[string]any{
					"name": "mixedsrc", "version": "v1", "mode": "flat",
					"layers":     []string{"local-myapp-v1"},
					"oci_layers": []map[string]any{{"digest": "sha256:" + strings.Repeat("ab", 32), "size": 10}},
				})
			},
			wantRule: "ref-layers", severity: SeverityWarning,
		},
		{
			name: "unparseable oci layer digest",
			setup: func(t *testing.T, f storeFixture) {
				writeRefFile(t, f.refsDir, "baddigest_v1.flat.json", map[string]any{
					"name": "baddigest", "version": "v1", "mode": "flat",
					"oci_layers": []map[string]any{{"digest": "sha256:nothex", "size": 10}},
				})
			},
			wantRule: "oci-layer", severity: SeverityError,
		},
		{
			name: "no layers and no oci_layers",
			setup: func(t *testing.T, f storeFixture) {
				writeRefFile(t, f.refsDir, "empty_v1.overlay.json", map[string]any{
					"name": "empty", "version": "v1", "mode": "overlay",
				})
			},
			wantRule: "ref-layers", severity: SeverityError,
		},
		{
			name: "legacy filename without mode suffix",
			setup: func(t *testing.T, f storeFixture) {
				writeRefFile(t, f.refsDir, "legacy_v1.json", map[string]any{
					"name": "legacy", "version": "v1",
					"layers": []string{"local-myapp-v1"},
				})
			},
			wantRule: "ref-legacy", severity: SeverityWarning,
		},
		{
			name: "legacy entry without name/version",
			setup: func(t *testing.T, f storeFixture) {
				writeRefFile(t, f.refsDir, "legacy2_v1.overlay.json", map[string]any{
					"mode":   "overlay",
					"layers": []string{"local-myapp-v1"},
				})
			},
			wantRule: "ref-identity", severity: SeverityWarning,
		},
		{
			name: "oci-origin flat ref records only digests",
			setup: func(t *testing.T, f storeFixture) {
				writeRefFile(t, f.refsDir, "registry_v1.flat.json", map[string]any{
					"name": "registry", "version": "v1", "mode": "flat",
					"oci_layers": []map[string]any{{"digest": "sha256:" + strings.Repeat("ab", 32), "size": 10}},
				})
			},
			wantRule: "", severity: SeverityInfo, // no finding expected
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newStoreFixture(t)
			tc.setup(t, f)
			fs, err := ValidateStore(f.store, nil)
			if err != nil {
				t.Fatalf("ValidateStore: %v", err)
			}
			got := findingsByRule(fs, tc.wantRule)
			if tc.wantRule == "" {
				return // no-finding case
			}
			if len(got) == 0 {
				t.Fatalf("expected a %s finding, got: %+v", tc.wantRule, fs)
			}
			if got[0].Severity != tc.severity {
				t.Errorf("finding severity = %s, want %s: %+v", got[0].Severity, tc.severity, got[0])
			}
		})
	}
}

func TestValidateStore_LayerTrustBoundary(t *testing.T) {
	tests := []struct {
		name     string
		layerID  func(f storeFixture) string
		mode     string
		flatRoot []string
		wantRule string
		severity Severity
	}{
		{
			name:     "mount-option separator in layer id",
			layerID:  func(f storeFixture) string { return "x:/etc" },
			mode:     "overlay",
			wantRule: "layer-id", severity: SeverityError,
		},
		{
			name:     "relative id escaping layers dir",
			layerID:  func(f storeFixture) string { return "../refs" },
			mode:     "overlay",
			wantRule: "layer-boundary", severity: SeverityError,
		},
		{
			name:     "absolute overlay layer outside the store",
			layerID:  func(f storeFixture) string { return "/etc" },
			mode:     "overlay",
			wantRule: "layer-boundary", severity: SeverityError,
		},
		{
			name: "symlinked layer slot pointing outside layers",
			layerID: func(f storeFixture) string {
				id := shaLayerName(9)
				outside := t.TempDir()
				if err := os.Symlink(outside, filepath.Join(f.layersDir, id)); err != nil {
					t.Fatal(err)
				}
				return id
			},
			mode:     "overlay",
			wantRule: "layer-boundary", severity: SeverityError,
		},
		{
			name: "flat absolute layer outside the store without flat roots",
			layerID: func(f storeFixture) string {
				d := t.TempDir()
				return d
			},
			mode:     "flat",
			wantRule: "layer-boundary", severity: SeverityWarning,
		},
		{
			name: "flat absolute layer outside every configured flat root",
			layerID: func(f storeFixture) string {
				return t.TempDir()
			},
			mode:     "flat",
			flatRoot: []string{t.TempDir()},
			wantRule: "layer-boundary", severity: SeverityError,
		},
		{
			name: "missing relative layer directory (store-owned cache)",
			layerID: func(f storeFixture) string {
				return shaLayerName(7)
			},
			mode:     "overlay",
			wantRule: "layer-missing", severity: SeverityError,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newStoreFixture(t)
			id := tc.layerID(f)
			// For the pass case, point the flat root at the id's parent.
			flatRoots := tc.flatRoot
			writeRefFile(t, f.refsDir, "probe_v1."+tc.mode+".json", map[string]any{
				"name": "probe", "version": "v1", "mode": tc.mode,
				"layers": []string{id},
			})
			fs, err := ValidateStore(f.store, flatRoots)
			if err != nil {
				t.Fatalf("ValidateStore: %v", err)
			}
			got := findingsByRule(fs, tc.wantRule)
			if len(got) == 0 {
				t.Fatalf("expected a %s finding, got: %+v", tc.wantRule, fs)
			}
			if got[0].Severity != tc.severity {
				t.Errorf("finding severity = %s, want %s: %+v", got[0].Severity, tc.severity, got[0])
			}
		})
	}
}

// TestValidateStore_NonRegularRefFile pins the tamper-safe reader: a FIFO
// or symlink at a ref name must be REPORTED, never opened (os.ReadFile on a
// FIFO blocks forever — the tool would hang on a hostile store).
func TestValidateStore_NonRegularRefFile(t *testing.T) {
	f := newStoreFixture(t)
	if err := unix.Mkfifo(filepath.Join(f.refsDir, "fifo_v1.overlay.json"), 0o640); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "elsewhere.json")
	if err := os.WriteFile(target, []byte(`{"name":"linked","version":"v1"}`), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(f.refsDir, "linked_v1.overlay.json")); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	var fs []Finding
	var err error
	go func() {
		fs, err = ValidateStore(f.store, nil)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("ValidateStore hung on a non-regular ref file")
	}
	if err != nil {
		t.Fatalf("ValidateStore: %v", err)
	}
	got := findingsByRule(fs, "ref-file")
	if len(got) != 2 {
		t.Fatalf("expected one finding per non-regular ref entry, got: %+v", fs)
	}
	for _, g := range got {
		if g.Severity != SeverityError {
			t.Errorf("non-regular ref entry severity = %s, want error", g.Severity)
		}
	}
}

// TestValidateStore_RelativeInvocation pins that a store given by a
// RELATIVE path judges in-store absolute layer ids as inside the store (the
// path pair must be normalized before filepath.Rel).
func TestValidateStore_RelativeInvocation(t *testing.T) {
	f := newStoreFixture(t)
	// The healthy fixture already contains an absolute flat layer inside the
	// store; validating from the store's parent by bare name must stay clean.
	parent, name := filepath.Split(strings.TrimSuffix(f.store, "/"))
	t.Chdir(parent)
	fs, err := ValidateStore(name, nil)
	if err != nil {
		t.Fatalf("ValidateStore: %v", err)
	}
	for _, finding := range fs {
		if finding.Rule == "layer-boundary" {
			t.Fatalf("relative invocation produced a false layer-boundary finding: %+v", finding)
		}
	}
}

// TestValidateStore_RelativeLayerSymlinkBoundary pins the per-consumer
// containment roots: a relative layer whose symlink leaves layers/ but
// stays inside the store MOUNTS (overlay resolves against the store) and
// SEEDS (flat roots union the store), so it is at most a packing warning —
// never an error. Leaving the store entirely is an error.
func TestValidateStore_RelativeLayerSymlinkBoundary(t *testing.T) {
	t.Run("inside the store", func(t *testing.T) {
		f := newStoreFixture(t)
		other := filepath.Join(f.store, "other")
		if err := os.MkdirAll(other, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("../other", filepath.Join(f.layersDir, "sub")); err != nil {
			t.Fatal(err)
		}
		writeRefFile(t, f.refsDir, "flaty_v1.flat.json", map[string]any{
			"name": "flaty", "version": "v1", "mode": "flat",
			"layers": []string{"sub"},
		})
		writeRefFile(t, f.refsDir, "overlayy_v1.overlay.json", map[string]any{
			"name": "overlayy", "version": "v1", "mode": "overlay",
			"layers": []string{"sub"},
		})
		fs, err := ValidateStore(f.store, nil)
		if err != nil {
			t.Fatalf("ValidateStore: %v", err)
		}
		for _, finding := range fs {
			if finding.Rule == "layer-boundary" && finding.Severity == SeverityError {
				t.Fatalf("in-store symlink layer falsely rejected: %+v", finding)
			}
		}
	})
	t.Run("outside the store", func(t *testing.T) {
		f := newStoreFixture(t)
		if err := os.Symlink(t.TempDir(), filepath.Join(f.layersDir, "out")); err != nil {
			t.Fatal(err)
		}
		writeRefFile(t, f.refsDir, "outy_v1.overlay.json", map[string]any{
			"name": "outy", "version": "v1", "mode": "overlay",
			"layers": []string{"out"},
		})
		fs, err := ValidateStore(f.store, nil)
		if err != nil {
			t.Fatalf("ValidateStore: %v", err)
		}
		got := findingsByRule(fs, "layer-boundary")
		if len(got) == 0 || got[0].Severity != SeverityError {
			t.Fatalf("outside-store symlink layer not refused: %+v", fs)
		}
	})
}

// TestValidateStore_MissingSourceDirIsWarning pins the severity split: an
// absolute (scan-root source) layer that is gone degrades (the ref is a
// durable record by design), while a missing relative layer is store
// corruption (the store owns its layers/ cache).
func TestValidateStore_MissingSourceDirIsWarning(t *testing.T) {
	f := newStoreFixture(t)
	gone := filepath.Join(f.store, "gone-source", "v1")
	writeRefFile(t, f.refsDir, "gone_v1.flat.json", map[string]any{
		"name": "gone", "version": "v1", "mode": "flat",
		"layers": []string{gone},
	})
	fs, err := ValidateStore(f.store, nil)
	if err != nil {
		t.Fatalf("ValidateStore: %v", err)
	}
	got := findingsByRule(fs, "layer-missing")
	if len(got) != 1 {
		t.Fatalf("expected one layer-missing finding, got: %+v", fs)
	}
	if got[0].Severity != SeverityWarning {
		t.Errorf("missing absolute source dir severity = %s, want warning", got[0].Severity)
	}
}

// TestValidateStore_RefIdentityEncodings pins the legal encodings so the
// identity check never false-positives on a legal ref: an underscore in the
// VERSION ("a:b_c") is indistinguishable from a name underscore by filename
// alone, and a bare ref records version "local" under its bare filename.
func TestValidateStore_RefIdentityEncodings(t *testing.T) {
	f := newStoreFixture(t)
	writeRefFile(t, f.refsDir, "a_b_c.overlay.json", map[string]any{
		"name": "a", "version": "b_c", "mode": "overlay",
		"layers": []string{"local-myapp-v1"},
	})
	writeRefFile(t, f.refsDir, "bare.overlay.json", map[string]any{
		"name": "bare", "version": "local", "mode": "overlay",
		"layers": []string{"local-myapp-v1"},
	})
	writeRefFile(t, f.refsDir, "explicit_local.overlay.json", map[string]any{
		"name": "explicit", "version": "local", "mode": "overlay",
		"layers": []string{"local-myapp-v1"},
	})
	fs, err := ValidateStore(f.store, nil)
	if err != nil {
		t.Fatalf("ValidateStore: %v", err)
	}
	for _, finding := range findingsByRule(fs, "ref-identity") {
		t.Fatalf("legal ref encoding falsely flagged: %+v", finding)
	}
}

// TestValidateStore_FlatLayerInsideConfiguredRoot pins the pass case: an
// absolute flat layer inside an operator-configured scan root is legal —
// exactly the roots flatLayerRoots unions at consume time.
func TestValidateStore_FlatLayerInsideConfiguredRoot(t *testing.T) {
	f := newStoreFixture(t)
	flatRoot := t.TempDir()
	id := filepath.Join(flatRoot, "myrootfs", "v1")
	if err := os.MkdirAll(id, 0o755); err != nil {
		t.Fatal(err)
	}
	writeRefFile(t, f.refsDir, "probe_v1.flat.json", map[string]any{
		"name": "probe", "version": "v1", "mode": "flat",
		"layers": []string{id},
	})
	fs, err := ValidateStore(f.store, []string{flatRoot})
	if err != nil {
		t.Fatalf("ValidateStore: %v", err)
	}
	for _, finding := range fs {
		if finding.Rule == "layer-boundary" {
			t.Fatalf("unexpected layer-boundary finding: %+v", finding)
		}
	}
}

func TestValidateStore_LayersHygiene(t *testing.T) {
	f := newStoreFixture(t)
	// Orphan: valid local- name, referenced by nobody.
	if err := os.MkdirAll(filepath.Join(f.layersDir, "local-lost-v9"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Writer debris: a staging dir, a publish marker, a save lock, a temp ref.
	if err := os.Mkdir(filepath.Join(f.layersDir, "."+shaLayerName(3)+".staging-123"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.layersDir, ".local-myapp-v1.publishing"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.refsDir, ".myapp_v1.save.lock"), []byte("x"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.refsDir, ".ref-abc.tmp"), []byte("x"), 0o640); err != nil {
		t.Fatal(err)
	}
	// Unrecognized layer name, still reachable via a ref.
	writeRefFile(t, f.refsDir, "odd_v1.overlay.json", map[string]any{
		"name": "odd", "version": "v1", "mode": "overlay",
		"layers": []string{"handmade-layer"},
	})
	if err := os.MkdirAll(filepath.Join(f.layersDir, "handmade-layer"), 0o755); err != nil {
		t.Fatal(err)
	}
	// A FILE at a layer slot.
	if err := os.WriteFile(filepath.Join(f.layersDir, "plainfile"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	fs, err := ValidateStore(f.store, nil)
	if err != nil {
		t.Fatalf("ValidateStore: %v", err)
	}
	for rule, want := range map[string]Severity{
		"layer-orphan": SeverityInfo,
		"store-debris": SeverityInfo,
		"layer-name":   SeverityWarning,
		"layer-slot":   SeverityWarning,
	} {
		got := findingsByRule(fs, rule)
		if len(got) == 0 {
			t.Errorf("expected at least one %s finding, got: %+v", rule, fs)
			continue
		}
		for _, g := range got {
			if g.Severity != want {
				t.Errorf("%s severity = %s, want %s", rule, g.Severity, want)
			}
		}
	}
	if hasSeverity(fs, SeverityError) {
		t.Errorf("hygiene findings must not include errors: %+v", fs)
	}
}

func TestValidateStore_SharedLayerReachability(t *testing.T) {
	f := newStoreFixture(t)
	// A second ref over the same content-addressed layer: still reachable.
	writeRefFile(t, f.refsDir, "ubuntu_beta.overlay.json", map[string]any{
		"name": "ubuntu", "version": "beta", "mode": "overlay",
		"layers": []string{shaLayerName(1)},
	})
	// Now remove BOTH refs naming it: the layer becomes an orphan (info).
	os.Remove(filepath.Join(f.refsDir, "ubuntu_24.04.overlay.json"))
	os.Remove(filepath.Join(f.refsDir, "ubuntu_beta.overlay.json"))
	fs, err := ValidateStore(f.store, nil)
	if err != nil {
		t.Fatalf("ValidateStore: %v", err)
	}
	orphans := 0
	for _, finding := range findingsByRule(fs, "layer-orphan") {
		if strings.HasSuffix(finding.Path, shaLayerName(1)) {
			orphans++
		}
	}
	if orphans == 0 {
		t.Fatalf("expected the shared layer to be reported unreachable, got: %+v", fs)
	}
}

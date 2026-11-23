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
	"syscall"
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

// TestValidateStore_GroupGrantAudit covers the store-side wiring of the
// static group audit (groupaudit.go): a group-grant-reliant entry under
// layers/ whose gid is not the STORE ROOT's group is an error finding, and
// re-settling the tree clears it. Root-only — it chowns to a foreign gid
// (non-root runs skip, same as TestSettleTreeGroup).
func TestValidateStore_GroupGrantAudit(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-only (chown to a foreign gid)")
	}
	f := newStoreFixture(t)
	// A reliant entry inside a layer: /etc/shadow-style file, no other-read.
	victim := filepath.Join(f.layersDir, "local-myapp-v1", "etc-shadow")
	if err := os.WriteFile(victim, []byte("x"), 0o640); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(f.store)
	if err != nil {
		t.Fatal(err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		t.Skip("no stat_t available")
	}
	storeGid, foreign := int(st.Gid), int(st.Gid)+1000
	if err := os.Chown(victim, -1, foreign); err != nil {
		t.Fatal(err)
	}
	fs, err := ValidateStore(f.store, nil)
	if err != nil {
		t.Fatalf("ValidateStore: %v", err)
	}
	gg := findingsByRule(fs, "group-grant")
	if len(gg) != 1 || gg[0].Severity != SeverityError || gg[0].Path != victim {
		t.Fatalf("expected one error group-grant finding on %s, got: %+v", victim, gg)
	}
	// Re-settling the store's layers clears the finding.
	if _, err := SettleTreeGroup(f.layersDir, storeGid); err != nil {
		t.Fatal(err)
	}
	fs, err = ValidateStore(f.store, nil)
	if err != nil {
		t.Fatalf("ValidateStore: %v", err)
	}
	if len(findingsByRule(fs, "group-grant")) != 0 {
		t.Fatalf("group-grant findings after settle: %+v", fs)
	}
}

// TestValidateStore_GroupGrantAuditSkipsStaging pins that writer-internal
// staging is never judged by the group audit: a pull in flight keeps its
// layer under .<layer>.staging-* until the writer has settled it, so a
// foreign gid there is mid-flight state, not a defect. The SAME wrong gid
// in a published layer IS a finding.
func TestValidateStore_GroupGrantAuditSkipsStaging(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-only (chown to a foreign gid)")
	}
	f := newStoreFixture(t)
	fi, err := os.Stat(f.store)
	if err != nil {
		t.Fatal(err)
	}
	storeGid := int(fi.Sys().(*syscall.Stat_t).Gid)
	foreign := storeGid + 1000
	// Staging twin of the fixture's layer, carrying the wrong gid on a
	// reliant entry.
	staging := filepath.Join(f.layersDir, ".local-myapp-v1.staging-123")
	if err := os.MkdirAll(filepath.Join(staging, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	stg := filepath.Join(staging, "etc", "shadow")
	if err := os.WriteFile(stg, []byte("x"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(stg, -1, foreign); err != nil {
		t.Fatal(err)
	}
	fs, err := ValidateStore(f.store, nil)
	if err != nil {
		t.Fatalf("ValidateStore: %v", err)
	}
	for _, finding := range findingsByRule(fs, "group-grant") {
		if strings.HasPrefix(finding.Path, staging) {
			t.Fatalf("group audit judged writer-internal staging: %+v", finding)
		}
	}
	// The same defect in the PUBLISHED layer is still caught.
	pub := filepath.Join(f.layersDir, "local-myapp-v1", "shadow")
	if err := os.WriteFile(pub, []byte("x"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(pub, -1, foreign); err != nil {
		t.Fatal(err)
	}
	fs, err = ValidateStore(f.store, nil)
	if err != nil {
		t.Fatalf("ValidateStore: %v", err)
	}
	gg := findingsByRule(fs, "group-grant")
	if len(gg) != 1 || gg[0].Path != pub {
		t.Fatalf("expected exactly the published entry flagged, got: %+v", gg)
	}
}

// TestValidateStore_GroupGrantAuditInStoreTree pins the third audit surface:
// an absolute layer dir a ref registers INSIDE the store outside layers/ —
// the shape `template-tool import --out <store>` publishes at
// <store>/<name>/<version> — is served like a layer tree and gets the same
// group audit. The same defect in a tree OUTSIDE the store (a flat scan root
// with its own group) must NOT be judged by check-store.
func TestValidateStore_GroupGrantAuditInStoreTree(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-only (chown to a foreign gid)")
	}
	f := newStoreFixture(t)
	fi, err := os.Stat(f.store)
	if err != nil {
		t.Fatal(err)
	}
	storeGid := int(fi.Sys().(*syscall.Stat_t).Gid)
	foreign := storeGid + 1000

	// A in-store template tree, registered by a legal flat ref.
	tree := filepath.Join(f.store, "inplace", "v1")
	if err := os.MkdirAll(filepath.Join(tree, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	reliant := filepath.Join(tree, "etc", "shadow")
	if err := os.WriteFile(reliant, []byte("x"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(reliant, -1, foreign); err != nil {
		t.Fatal(err)
	}
	writeRefFile(t, f.refsDir, "inplace_v1.flat.json", map[string]any{
		"name": "inplace", "version": "v1", "mode": "flat",
		"layers": []string{tree},
	})
	// An OUTSIDE flat scan root with the same defect: check-store must not
	// judge it (its group may legitimately differ per root).
	outside := t.TempDir()
	if err := os.MkdirAll(filepath.Join(outside, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	outReliant := filepath.Join(outside, "etc", "shadow")
	if err := os.WriteFile(outReliant, []byte("x"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(outReliant, -1, foreign); err != nil {
		t.Fatal(err)
	}
	writeRefFile(t, f.refsDir, "outside_v1.flat.json", map[string]any{
		"name": "outside", "version": "v1", "mode": "flat",
		"layers": []string{outside},
	})

	fs, err := ValidateStore(f.store, []string{outside})
	if err != nil {
		t.Fatalf("ValidateStore: %v", err)
	}
	var inStoreFlagged, outsideFlagged bool
	for _, g := range findingsByRule(fs, "group-grant") {
		if g.Path == reliant {
			inStoreFlagged = true
		}
		if g.Path == outReliant {
			outsideFlagged = true
		}
	}
	if !inStoreFlagged {
		t.Fatalf("in-store template tree not audited: %+v", findingsByRule(fs, "group-grant"))
	}
	if outsideFlagged {
		t.Fatalf("check-store judged a flat scan-root tree outside the store: %+v", findingsByRule(fs, "group-grant"))
	}
	// Settling the store's own trees clears the in-store finding.
	if _, err := SettleTreeGroup(tree, storeGid); err != nil {
		t.Fatal(err)
	}
	fs, err = ValidateStore(f.store, []string{outside})
	if err != nil {
		t.Fatalf("ValidateStore: %v", err)
	}
	for _, g := range findingsByRule(fs, "group-grant") {
		if g.Path == reliant {
			t.Fatalf("in-store finding survived the settle: %+v", g)
		}
	}
}

// TestValidateStore_ExpectedGroupCrossHost pins the cross-host form: a store
// moved with cp -a from a differently-numbered host is internally consistent
// (every tree carries the store root's group), so the default audit cannot
// see the defect — every consumer on THIS host EACCESes. An explicit
// expected gid must flag the store root and the reliant entries.
func TestValidateStore_ExpectedGroupCrossHost(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-only (chown to a foreign gid)")
	}
	f := newStoreFixture(t)
	// The store root itself rides the group grant (the deployment shape:
	// 2750 setgid, no other bits) and a layer carries a reliant entry.
	if err := os.Chmod(f.store, 0o750); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(f.store)
	if err != nil {
		t.Fatal(err)
	}
	storeGid := int(fi.Sys().(*syscall.Stat_t).Gid)
	reliant := filepath.Join(f.layersDir, "local-myapp-v1", "shadow")
	if err := os.WriteFile(reliant, []byte("x"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(reliant, -1, storeGid); err != nil {
		t.Fatal(err)
	}

	// Default: internally consistent, clean.
	fs, err := ValidateStore(f.store, nil)
	if err != nil {
		t.Fatalf("ValidateStore: %v", err)
	}
	if gg := findingsByRule(fs, "group-grant"); len(gg) != 0 {
		t.Fatalf("default audit flagged an internally consistent store: %+v", gg)
	}

	// Cross-host: the target's shared gid differs from the store's.
	want := storeGid + 1000
	fs, err = ValidateStoreWithExpectedGroup(f.store, nil, want)
	if err != nil {
		t.Fatalf("ValidateStoreWithExpectedGroup: %v", err)
	}
	var rootFlagged, entryFlagged bool
	for _, g := range findingsByRule(fs, "group-grant") {
		if g.Path == f.store {
			rootFlagged = true
		}
		if g.Path == reliant {
			entryFlagged = true
		}
	}
	if !rootFlagged {
		t.Fatalf("store root carrying a foreign group not flagged: %+v", findingsByRule(fs, "group-grant"))
	}
	if !entryFlagged {
		t.Fatalf("reliant layer entry not flagged against the expected gid: %+v", findingsByRule(fs, "group-grant"))
	}

	// An explicit gid that MATCHES is clean (the override is not a pessimism
	// switch).
	fs, err = ValidateStoreWithExpectedGroup(f.store, nil, storeGid)
	if err != nil {
		t.Fatalf("ValidateStoreWithExpectedGroup: %v", err)
	}
	if gg := findingsByRule(fs, "group-grant"); len(gg) != 0 {
		t.Fatalf("explicit matching gid flagged: %+v", gg)
	}
}

// TestValidateStore_InStoreTreesNotDoubleAudited pins the outermost pruning:
// when a ref names <store>/outer/v1 and another names a subtree inside it,
// the defect under the subtree is reported ONCE (the outer tree's audit
// covers it), not once per ref.
func TestValidateStore_InStoreTreesNotDoubleAudited(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-only (chown to a foreign gid)")
	}
	f := newStoreFixture(t)
	fi, err := os.Stat(f.store)
	if err != nil {
		t.Fatal(err)
	}
	storeGid := int(fi.Sys().(*syscall.Stat_t).Gid)
	outer := filepath.Join(f.store, "outer", "v1")
	nested := filepath.Join(outer, "nested")
	if err := os.MkdirAll(filepath.Join(nested, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	reliant := filepath.Join(nested, "etc", "shadow")
	if err := os.WriteFile(reliant, []byte("x"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(reliant, -1, storeGid+1000); err != nil {
		t.Fatal(err)
	}
	writeRefFile(t, f.refsDir, "outer_v1.flat.json", map[string]any{
		"name": "outer", "version": "v1", "mode": "flat", "layers": []string{outer},
	})
	writeRefFile(t, f.refsDir, "nested_v1.flat.json", map[string]any{
		"name": "nested", "version": "v1", "mode": "flat", "layers": []string{nested},
	})
	fs, err := ValidateStore(f.store, nil)
	if err != nil {
		t.Fatalf("ValidateStore: %v", err)
	}
	n := 0
	for _, g := range findingsByRule(fs, "group-grant") {
		if g.Path == reliant {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("reliant entry reported %d times, want 1 (nested trees pruned)", n)
	}
}

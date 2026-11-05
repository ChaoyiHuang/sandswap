// Copyright 2026 Chaoyi Huang. All rights reserved.
//
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE file at the root of this repository.

package template

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// The ref->filename encoding is NOT injective: RefToFilename replaces ':'
// with '_', so "a:b_c" and "a_b:c" both name refs/a_b_c.overlay.json. Ref
// files are immutable and must carry the name:version they were written for;
// these tests pin both halves of the fix (create-only publish + reader
// identity check), which together close the cross-tenant rootfs-substitution
// primitive.

func TestWriteRefFileIsCreateOnlyForSameAndCollidingRefs(t *testing.T) {
	m, err := NewManager(Config{TemplatesDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	victim := "a:b_c"
	if err := m.writeRefFile(victim, RefEntry{
		Name: "a", Version: "b_c", Mode: "overlay", Layers: []string{"sha256-victim"},
	}); err != nil {
		t.Fatalf("first write: %v", err)
	}
	// Same ref again: overwriting would re-point every volume mounting it.
	if err := m.writeRefFile(victim, RefEntry{
		Name: "a", Version: "b_c", Mode: "overlay", Layers: []string{"sha256-attacker"},
	}); !errors.Is(err, ErrRefExists) {
		t.Fatalf("same-ref rewrite: err = %v, want ErrRefExists", err)
	}
	// A DIFFERENT valid ref that encodes to the same filename must be refused
	// by the create-only publish before its entry identity is even relevant.
	if err := m.writeRefFile("a_b:c", RefEntry{
		Name: "a_b", Version: "c", Mode: "overlay", Layers: []string{"sha256-attacker"},
	}); !errors.Is(err, ErrRefExists) {
		t.Fatalf("colliding-ref rewrite: err = %v, want ErrRefExists", err)
	}
	// The victim's entry is untouched.
	entry, err := m.LoadRefEntry(victim, "overlay")
	if err != nil {
		t.Fatalf("load victim: %v", err)
	}
	if len(entry.Layers) != 1 || entry.Layers[0] != "sha256-victim" {
		t.Fatalf("victim ref was replaced: %+v", entry)
	}
}

func TestWriteRefFileRejectsEntryForAnotherRef(t *testing.T) {
	m, err := NewManager(Config{TemplatesDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.writeRefFile("a_b:c", RefEntry{
		Name: "a", Version: "b_c", Mode: "overlay", Layers: []string{"sha256-victim"},
	}); err == nil {
		t.Fatal("writeRefFile accepted an entry naming a different ref")
	}
}

func TestLoadRefEntryRejectsCollidingLegacyEntry(t *testing.T) {
	dir := t.TempDir()
	m, err := NewManager(Config{TemplatesDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	// Simulate a ref file written by a pre-fix (or otherwise colliding)
	// writer: the file is the victim's filename but the entry names the
	// attacker's ref. The reader must refuse it for the victim's ref, while
	// the entry's own ref still loads.
	refs := filepath.Join(dir, "refs")
	if err := os.MkdirAll(refs, 0o755); err != nil {
		t.Fatal(err)
	}
	data := []byte(`{"name":"a_b","version":"c","mode":"overlay","layers":["sha256-attacker"]}`)
	if err := os.WriteFile(filepath.Join(refs, "a_b_c.overlay.json"), data, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := m.LoadRefEntry("a:b_c", "overlay"); err == nil {
		t.Fatal("LoadRefEntry accepted an entry naming a different ref (collision)")
	}
	if _, err := m.LoadRefEntry("a_b:c", "overlay"); err != nil {
		t.Fatalf("entry's own ref should load: %v", err)
	}
}

func TestSaveAsTemplateRefusesAnExistingRefBeforeCopying(t *testing.T) {
	base := t.TempDir()
	vol := filepath.Join(base, "vol")
	if err := os.MkdirAll(vol, 0o755); err != nil {
		t.Fatal(err)
	}
	m, err := NewManager(Config{
		TemplatesDir: filepath.Join(base, "store"),
		ResolveVolume: func(string) (string, error) {
			return vol, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	const ref = "victim:v1"
	if err := m.writeRefFile(ref, RefEntry{
		Name: "victim", Version: "v1", Mode: "overlay", Layers: []string{"sha256-victim"},
	}); err != nil {
		t.Fatal(err)
	}
	_, err = m.SaveAsTemplate(context.Background(), "sandfs-attacker", SaveAsTemplateRequest{
		TemplateRef: ref,
	})
	if !errors.Is(err, ErrRefExists) {
		t.Fatalf("SaveAsTemplate over an existing ref: err = %v, want ErrRefExists", err)
	}
	// Nothing was copied under the attacker's layer name.
	if _, statErr := os.Stat(filepath.Join(base, "store", "layers", "local-victim-v1")); statErr == nil {
		t.Fatal("SaveAsTemplate copied a layer before refusing the existing ref")
	}
}

func TestPullTemplateRefusesAnExistingRefBeforeRegistryIO(t *testing.T) {
	m, err := NewManager(Config{TemplatesDir: t.TempDir()}) // no registry
	if err != nil {
		t.Fatal(err)
	}
	const ref = "victim:v1"
	if err := m.writeRefFile(ref, RefEntry{
		Name: "victim", Version: "v1", Mode: "overlay", Layers: []string{"sha256-victim"},
	}); err != nil {
		t.Fatal(err)
	}
	_, err = m.PullTemplate(context.Background(), ref, "overlay")
	if !errors.Is(err, ErrRefExists) {
		t.Fatalf("PullTemplate over an existing ref: err = %v, want ErrRefExists (and not the no-registry error)", err)
	}
}

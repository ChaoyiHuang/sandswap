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

package copyfs

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCopyRootModeOverridesSource pins the staging-root mode contract: an
// archive copy normally mirrors the source root's mode, but SaveAsTemplate must
// be able to keep its staging root owner-only while the copy runs (the
// template store's group includes the FUSE daemon). Subdirectories keep the
// source modes.
func TestCopyRootModeOverridesSource(t *testing.T) {
	src := t.TempDir()
	if err := os.Chmod(src, 0o770); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(src, "sub"), 0o750); err != nil {
		t.Fatal(err)
	}
	dst := t.TempDir()

	if err := CopyDirArchiveContextLimit(context.Background(), src, dst, Limits{RootMode: 0o700}); err != nil {
		t.Fatalf("copy: %v", err)
	}
	root, err := os.Stat(dst)
	if err != nil {
		t.Fatal(err)
	}
	if got := root.Mode().Perm(); got != 0o700 {
		t.Fatalf("destination root mode = %o, want 700 (RootMode must win over the source mode)", got)
	}
	sub, err := os.Stat(filepath.Join(dst, "sub"))
	if err != nil {
		t.Fatal(err)
	}
	if got := sub.Mode().Perm(); got != 0o750 {
		t.Fatalf("subdirectory mode = %o, want 750 (source modes preserved)", got)
	}

	// Control: the zero Limits still mirrors the source root's mode.
	dst2 := t.TempDir()
	if err := CopyDirArchive(src, dst2); err != nil {
		t.Fatalf("control copy: %v", err)
	}
	root2, err := os.Stat(dst2)
	if err != nil {
		t.Fatal(err)
	}
	if got := root2.Mode().Perm(); got != 0o770 {
		t.Fatalf("control root mode = %o, want the source 770", got)
	}
}

// TestCopyEntryCap pins the entry-count bound: the free-space budget alone
// admits millions of empty files, so a copy past the cap fails loudly instead
// of filling the shared store's metadata.
func TestCopyEntryCap(t *testing.T) {
	src := t.TempDir()
	for _, name := range []string{"a", "b", "c"} {
		if err := os.WriteFile(filepath.Join(src, name), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	err := CopyDirArchiveContextLimit(context.Background(), src, t.TempDir(), Limits{MaxEntries: 2})
	if err == nil || !strings.Contains(err.Error(), "2-entry limit") {
		t.Fatalf("err = %v, want the entry-count refusal", err)
	}
	// The default cap admits a normal tree.
	if err := CopyDirArchiveContextLimit(context.Background(), src, t.TempDir(), Limits{}); err != nil {
		t.Fatalf("default limits rejected a 3-entry tree: %v", err)
	}
}

// TestCopyDepthCap pins the nesting bound.
func TestCopyDepthCap(t *testing.T) {
	src := t.TempDir()
	if err := os.MkdirAll(filepath.Join(src, "a", "b", "c"), 0o755); err != nil {
		t.Fatal(err)
	}
	err := CopyDirArchiveContextLimit(context.Background(), src, t.TempDir(), Limits{MaxDepth: 1})
	if err == nil || !strings.Contains(err.Error(), "nested deeper") {
		t.Fatalf("err = %v, want the depth refusal", err)
	}
	if err := CopyDirArchiveContextLimit(context.Background(), src, t.TempDir(), Limits{MaxDepth: 8}); err != nil {
		t.Fatalf("a depth-3 tree must pass MaxDepth 8: %v", err)
	}
}

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

package main

import (
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// withTestLock points the role lock at a temp path for one test.
func withTestLock(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	old := roleLockPath
	roleLockPath = filepath.Join(dir, "sandlot.role")
	t.Cleanup(func() { roleLockPath = old })
	return roleLockPath
}

func TestRoleLockSingleInstance(t *testing.T) {
	withTestLock(t)
	logger := log.New(os.Stderr, "", 0)

	release, err := acquireRoleLock(logger, "host-a", []string{"exec"}, false)
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	if release == nil {
		t.Fatal("first acquire must return a release func")
	}

	// A second instance with a DIFFERENT node id on the same host: refused,
	// naming the three blessed shapes.
	_, err = acquireRoleLock(logger, "host-b", []string{"prov"}, false)
	if err == nil {
		t.Fatal("second instance must be refused")
	}
	for _, want := range []string{"at most ONE sandlot process per host", "exec,prov"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal should mention %q, got: %v", want, err)
		}
	}

	// The simulation escape hatch lets it through (returns nil release —
	// enforcement skipped, not held).
	release2, err := acquireRoleLock(logger, "host-b", []string{"prov"}, true)
	if err != nil {
		t.Fatalf("colocated acquire: %v", err)
	}
	if release2 != nil {
		t.Error("colocated acquire must not hold the lock")
	}

	// A DUPLICATE node_id is refused even with the escape hatch.
	_, err = acquireRoleLock(logger, "host-a", []string{"exec"}, true)
	if err == nil || !strings.Contains(err.Error(), "node_id") {
		t.Fatalf("duplicate node_id must be refused even colocated, got: %v", err)
	}

	release()
}

func TestRoleLockReacquireAfterRelease(t *testing.T) {
	withTestLock(t)
	logger := log.New(os.Stderr, "", 0)

	release, err := acquireRoleLock(logger, "host-a", []string{"prov"}, false)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	release()

	// After release the next instance takes the lock cleanly (process
	// replacement / restart path).
	release2, err := acquireRoleLock(logger, "host-a", []string{"prov"}, false)
	if err != nil {
		t.Fatalf("re-acquire after release: %v", err)
	}
	release2()
}

// TestRoleLockRefusesSymlink pins the O_NOFOLLOW open: a symlink planted at
// the group-writable lock path must not redirect the open/truncate at a
// victim file.
func TestRoleLockRefusesSymlink(t *testing.T) {
	lockPath := withTestLock(t)
	victim := filepath.Join(filepath.Dir(lockPath), "victim")
	if err := os.WriteFile(victim, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, lockPath); err != nil {
		t.Fatal(err)
	}
	logger := log.New(os.Stderr, "", 0)
	if _, err := acquireRoleLock(logger, "host-a", []string{"exec"}, false); err == nil {
		t.Fatal("symlinked role lock accepted")
	}
	if b, err := os.ReadFile(victim); err != nil || string(b) != "keep" {
		t.Fatalf("victim modified (b=%q err=%v)", b, err)
	}
}

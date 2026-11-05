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

package hostbin

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolvePinsAnAbsoluteExecutable(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "tool")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := resolve("tool", []string{filepath.Join(dir, "absent"), bin})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got != bin {
		t.Fatalf("resolve = %q, want %q", got, bin)
	}
}

func TestResolveRefusesMissingOrNonExecutable(t *testing.T) {
	dir := t.TempDir()
	plain := filepath.Join(dir, "plain")
	if err := os.WriteFile(plain, []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := resolve("plain", []string{plain}); err == nil {
		t.Fatal("a non-executable candidate must be refused")
	}
	if _, err := resolve("absent", []string{filepath.Join(dir, "absent")}); err == nil {
		t.Fatal("a missing binary must be refused")
	}
}

func TestPathFallsBackToAnAbsoluteLookPathResult(t *testing.T) {
	// Tests and small utility mains do not call Init; the fallback must still
	// return an absolute path (never a bare command name that would re-enter
	// PATH at exec time).
	dir := t.TempDir()
	bin := filepath.Join(dir, "hostbin-test-tool")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	if p := Path("hostbin-test-tool"); p != bin {
		t.Fatalf("Path(hostbin-test-tool) = %q, want %q", p, bin)
	}
}

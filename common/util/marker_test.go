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

package util

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestReadMarkerFile_RegularFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, ".template")
	if err := os.WriteFile(p, []byte("rootfs:v1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	data, ok, err := ReadMarkerFile(p)
	if err != nil || !ok {
		t.Fatalf("regular marker: ok=%v err=%v", ok, err)
	}
	if got := strings.TrimSpace(string(data)); got != "rootfs:v1" {
		t.Fatalf("content = %q", got)
	}
}

func TestReadMarkerFile_Missing(t *testing.T) {
	_, ok, err := ReadMarkerFile(filepath.Join(t.TempDir(), ".template"))
	if !errors.Is(err, fs.ErrNotExist) || ok {
		t.Fatalf("missing marker must be ErrNotExist: ok=%v err=%v", ok, err)
	}
}

func TestReadMarkerFile_SymlinkIsRejectedNotFollowed(t *testing.T) {
	// The attack: in flat mode the agent plants .template as a symlink to a
	// HOST path; a following read would hand the host file's content to the
	// caller (and a symlink to /dev/zero would read forever).
	dir := t.TempDir()
	secret := filepath.Join(dir, "host-secret")
	if err := os.WriteFile(secret, []byte("SECRET"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, ".template")
	if err := os.Symlink(secret, link); err != nil {
		t.Fatal(err)
	}
	data, ok, err := ReadMarkerFile(link)
	if err != nil || ok || data != nil {
		t.Fatalf("symlink must be reported as not-a-marker: data=%q ok=%v err=%v", data, ok, err)
	}
	// Same for a symlink to a device: it must not reach the open at all.
	if err := os.Symlink("/dev/zero", filepath.Join(dir, "zero-link")); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := ReadMarkerFile(filepath.Join(dir, "zero-link")); err != nil || ok {
		t.Fatalf("symlink to /dev/zero must be not-a-marker: ok=%v err=%v", ok, err)
	}
}

func TestReadMarkerFile_FifoDoesNotBlock(t *testing.T) {
	// The attack: a planted FIFO at the marker path makes a plain
	// os.ReadFile block forever (no writer), hanging the node's mount or
	// scan path. The read must return promptly with ok=false.
	dir := t.TempDir()
	p := filepath.Join(dir, ".template")
	if err := syscall.Mkfifo(p, 0o644); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}
	data, ok, err := ReadMarkerFile(p)
	if err != nil || ok || data != nil {
		t.Fatalf("FIFO must be not-a-marker: data=%q ok=%v err=%v", data, ok, err)
	}
}

func TestReadMarkerFile_OversizedRegularFileRejected(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, ".template")
	big := make([]byte, MaxMarkerBytes+1)
	if err := os.WriteFile(p, big, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := ReadMarkerFile(p); err != nil || ok {
		t.Fatalf("oversized marker must be not-a-marker: ok=%v err=%v", ok, err)
	}
	// Exactly at the cap is still read.
	if err := os.WriteFile(p, big[:MaxMarkerBytes], 0o644); err != nil {
		t.Fatal(err)
	}
	data, ok, err := ReadMarkerFile(p)
	if err != nil || !ok || len(data) != MaxMarkerBytes {
		t.Fatalf("at-cap marker must be read: len=%d ok=%v err=%v", len(data), ok, err)
	}
}

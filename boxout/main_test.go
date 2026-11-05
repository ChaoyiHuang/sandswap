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

package main

import (
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testMainLogger() *log.Logger { return log.New(io.Discard, "", 0) }

// The instance lock admits ONE boxout per sandbox root; a second acquire on
// the same state root is refused, and a distinct root gets its own lock.
func TestAcquireInstanceLockIsSingleton(t *testing.T) {
	stateRoot := filepath.Join(t.TempDir(), "state")
	first, err := acquireInstanceLock(stateRoot, "/run/sandswap/vm", testMainLogger())
	if err != nil {
		t.Fatalf("first lock: %v", err)
	}
	defer first.Close()

	if _, err := acquireInstanceLock(stateRoot, "/run/sandswap/vm", testMainLogger()); err == nil {
		t.Fatal("a second boxout for the same sandbox root must be refused")
	} else if !strings.Contains(err.Error(), "another boxout instance") {
		t.Fatalf("refusal %q must name the existing instance", err)
	}

	other, err := acquireInstanceLock(filepath.Join(t.TempDir(), "state-2"), "/run/sandswap/instance-x/vm", testMainLogger())
	if err != nil {
		t.Fatalf("a distinct sandbox root must get its own lock: %v", err)
	}
	other.Close()
}

// A symlink planted at the lock name is refused (O_NOFOLLOW) and its target is
// never touched.
func TestAcquireInstanceLockRefusesSymlinkFile(t *testing.T) {
	stateRoot := filepath.Join(t.TempDir(), "state")
	if err := os.MkdirAll(stateRoot, 0o710); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(stateRoot, "boxout.lock")); err != nil {
		t.Fatal(err)
	}
	if _, err := acquireInstanceLock(stateRoot, "/run/sandswap/vm", testMainLogger()); err == nil {
		t.Fatal("a symlinked lock file must be refused")
	}
	if data, _ := os.ReadFile(victim); string(data) != "keep" {
		t.Fatalf("the symlink target was modified: %q", data)
	}
}

// A symlinked state root would put the lock in an attacker-chosen directory.
func TestAcquireInstanceLockRefusesSymlinkedStateRoot(t *testing.T) {
	realDir := filepath.Join(t.TempDir(), "real-state")
	if err := os.MkdirAll(realDir, 0o710); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "state-link")
	if err := os.Symlink(realDir, link); err != nil {
		t.Fatal(err)
	}
	if _, err := acquireInstanceLock(link, "/run/sandswap/vm", testMainLogger()); err == nil {
		t.Fatal("a symlinked state root must be refused")
	}
}

// A lock file written by another identity is refused before the flock: the
// file itself must provably belong to this writer.
func TestAcquireInstanceLockRefusesForeignOwner(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to create a foreign-owned lock file")
	}
	stateRoot := filepath.Join(t.TempDir(), "state")
	if err := os.MkdirAll(stateRoot, 0o710); err != nil {
		t.Fatal(err)
	}
	lockPath := filepath.Join(stateRoot, "boxout.lock")
	if err := os.WriteFile(lockPath, []byte("1|/run/sandswap/vm\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(lockPath, 65536, 65536); err != nil {
		t.Fatal(err)
	}
	if _, err := acquireInstanceLock(stateRoot, "/run/sandswap/vm", testMainLogger()); err == nil {
		t.Fatal("a foreign-owned lock file must be refused")
	}
}

// TestSecureListeningSocket pins the socket handoff: the bound Unix socket is
// re-owned to the sandlot uid with mode 0600 and the post-check proves the
// entry is still the socket this listener created (a replacement during the
// permission setup is refused).
func TestSecureListeningSocket(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "sock")
	if err := prepareSocketDir(dir); err != nil {
		t.Fatalf("prepareSocketDir: %v", err)
	}
	st, err := os.Lstat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o711 {
		t.Fatalf("socket dir mode = %04o, want 0711", st.Mode().Perm())
	}
	sock := filepath.Join(dir, "boxout.sock")
	lis, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer lis.Close()
	// Hand the socket to uid 0 (this test runs as root in the deployment
	// drills; the production target is the sandlot uid).
	if err := secureListeningSocket(sock, 0, testMainLogger()); err != nil {
		t.Fatalf("secureListeningSocket: %v", err)
	}
	fi, err := os.Lstat(sock)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 || fi.Mode()&os.ModeSocket == 0 {
		t.Fatalf("socket mode = %v, want socket 0600", fi.Mode())
	}
	// A world-writable socket dir is NORMALIZED back to 0711 (the directory is
	// this sidecar's own), while a foreign-owned one is refused.
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := prepareSocketDir(dir); err != nil {
		t.Fatalf("prepareSocketDir must re-tighten its own directory: %v", err)
	}
	if st, _ := os.Lstat(dir); st.Mode().Perm() != 0o711 {
		t.Fatalf("socket dir mode after re-tighten = %04o, want 0711", st.Mode().Perm())
	}
	if os.Geteuid() == 0 {
		if err := os.Chown(dir, 12345, 12345); err != nil {
			t.Fatal(err)
		}
		if err := prepareSocketDir(dir); err == nil {
			t.Fatal("a foreign-owned socket dir must be refused")
		}
		if err := os.Chown(dir, 0, 0); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, 0o711); err != nil {
			t.Fatal(err)
		}
	}
	// A non-socket at the path is refused (never chmod/chown an arbitrary
	// file at the socket name).
	regular := filepath.Join(dir, "regular")
	if err := os.WriteFile(regular, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := secureListeningSocket(regular, 0, testMainLogger()); err == nil {
		t.Fatal("a regular file at the socket path must be refused")
	}
}

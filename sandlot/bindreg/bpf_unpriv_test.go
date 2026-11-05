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

package bindreg

import (
	"fmt"
	"os"
	"os/exec"
	"testing"
)

// TestBPFUnprivilegedWrite verifies the k8s/boxout deployment story
// end-to-end on the real kernel: a PRIVILEGED creator makes + pins + chmods
// the region (boxout's job), and an UNPRIVILEGED process (sandlot, uid 1001
// in production — uid 65534 here) opens it via BPF_OBJ_GET, mmap-writes a
// binding, and the write is visible to the creator.
//
// This is the empirical check the contract doc previously flagged as
// "verify the bpffs permission model on the target kernel".
func TestBPFUnprivilegedWrite(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to create + chmod the region")
	}
	if _, err := exec.LookPath("setpriv"); err != nil {
		t.Skipf("setpriv not available: %v", err)
	}

	const pinPath = "/sys/fs/bpf/sandswap-bindreg-unpriv-test"
	_ = os.Remove(pinPath)
	t.Cleanup(func() { _ = os.Remove(pinPath) })

	// 1. Privileged creator (boxout role): create + pin + hand off. The bpffs
	// ROOT is 0700 by default, so the operator step is: make the root
	// traversable (0711) for the unprivileged writer's UID, then hand the pin
	// to that UID with the documented owner-rw/group shape (owner 65534, 0660).
	// The owner/mode gate on open refuses a foreign-owned or world-writable
	// pin, so a bare chmod 0666 (the old fixture) is exactly what it rejects.
	creator, err := Open(Config{Backend: BackendBPF, Path: pinPath, MaxIfindex: 4096})
	if err != nil {
		t.Skipf("bpf carrier unavailable: %v", err)
	}
	defer creator.Close()
	rootStat, err := os.Stat("/sys/fs/bpf")
	if err != nil {
		t.Fatalf("stat bpffs root: %v", err)
	}
	rootMode := rootStat.Mode().Perm()
	restore := func() { _ = os.Chmod("/sys/fs/bpf", rootMode) }
	t.Cleanup(restore)
	if err := os.Chmod("/sys/fs/bpf", 0o711); err != nil {
		t.Fatalf("chmod bpffs root: %v", err)
	}
	if err := os.Chown(pinPath, 65534, 65534); err != nil {
		restore()
		t.Fatalf("chown pin path: %v", err)
	}
	if err := os.Chmod(pinPath, 0o660); err != nil {
		restore()
		t.Fatalf("chmod pin path: %v", err)
	}

	// 2. Unprivileged writer (sandlot role): re-exec this test binary as
	// uid/gid 65534 with no supplementary groups and no capabilities.
	want := Entry{State: StateMounted, MountEpoch: 41, AgentID: "agent-unpriv", SandfsID: "sfs-unpriv", VMID: "vm-unpriv"}
	cmd := exec.Command("setpriv", "--reuid=65534", "--regid=65534", "--clear-groups",
		os.Args[0], "-test.run=TestBPFUnprivilegedChild", "-test.v")
	cmd.Env = append(os.Environ(),
		"BINDREG_UNPRIV_CHILD=1",
		"BINDREG_UNPRIV_PATH="+pinPath,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("unprivileged child failed: %v\n%s", err, out)
	}

	// 3. The privileged creator must see the child's write through its own
	// mapping (shared memory, same page cache).
	got, ok, err := creator.Lookup(5)
	if err != nil || !ok {
		t.Fatalf("creator lookup after unprivileged write: ok=%v err=%v", ok, err)
	}
	if got != want {
		t.Fatalf("entry written by unprivileged process = %+v, want %+v", got, want)
	}
}

// TestBPFUnprivilegedChild runs as the dropped-privileges child of
// TestBPFUnprivilegedWrite. It exercises exactly the k8s sandlot path:
// BPF_MAP_CREATE fails (no CAP_BPF) → BPF_OBJ_GET the pinned map → mmap
// write. Exits 0 only if publish+readback succeeded.
func TestBPFUnprivilegedChild(t *testing.T) {
	if os.Getenv("BINDREG_UNPRIV_CHILD") != "1" {
		t.Skip("child helper — run via TestBPFUnprivilegedWrite")
	}
	path := os.Getenv("BINDREG_UNPRIV_PATH")
	if path == "" {
		fmt.Fprintln(os.Stderr, "child: BINDREG_UNPRIV_PATH not set")
		os.Exit(1)
	}
	if os.Geteuid() == 0 {
		fmt.Fprintln(os.Stderr, "child: expected to run unprivileged, got uid 0")
		os.Exit(1)
	}
	r, err := Open(Config{Backend: BackendBPF, Path: path, MaxIfindex: 4096})
	if err != nil {
		fmt.Fprintf(os.Stderr, "child: unprivileged open failed: %v\n", err)
		os.Exit(1)
	}
	defer r.Close()
	want := Entry{State: StateMounted, MountEpoch: 41, AgentID: "agent-unpriv", SandfsID: "sfs-unpriv", VMID: "vm-unpriv"}
	if err := r.Publish(5, want); err != nil {
		fmt.Fprintf(os.Stderr, "child: unprivileged publish failed: %v\n", err)
		os.Exit(1)
	}
	got, ok, err := r.Lookup(5)
	if err != nil || !ok || got != want {
		fmt.Fprintf(os.Stderr, "child: readback mismatch: ok=%v err=%v entry=%+v\n", ok, err, got)
		os.Exit(1)
	}
}

// TestBPFPinCreatesParentDirs: BPF_OBJ_PIN does not create parent directories
// in bpffs — a pinned path under a SUBDIRECTORY must work (the production
// default /sys/fs/bpf/sandswap/bindings has a sandswap/ parent). Skips when
// bpffs is unavailable.
func TestBPFPinCreatesParentDirs(t *testing.T) {
	const dir = "/sys/fs/bpf/sandswap-bindreg-mkdir-test"
	pinPath := dir + "/bindings"
	_ = os.RemoveAll(dir)
	t.Cleanup(func() { _ = os.Remove(pinPath); _ = os.Remove(dir) })

	r, err := Open(Config{Backend: BackendBPF, Path: pinPath, MaxIfindex: 1024})
	if err != nil {
		t.Skipf("bpf backend unavailable here: %v", err)
	}
	defer r.Close()
	if err := r.Publish(3, Entry{State: StateMounted, MountEpoch: 1, AgentID: "a"}); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if _, err := os.Stat(pinPath); err != nil {
		t.Fatalf("pinned file missing: %v", err)
	}
}

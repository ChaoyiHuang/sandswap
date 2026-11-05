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

package core

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestReadoptOneVMScanDeadlineDoesNotJudgeDead pins the re-adopt sweep's
// deadline semantics: when the scan's context is expired, a failing Ping says
// nothing about the VM's health (every Ping past the deadline fails instantly),
// so the VM must NOT be judged dead — no kill, no state removal. The buggy
// behavior killed every remaining LIVE VM in the sweep once the 60s startup
// budget ran out (e.g. behind a wedged sandvmm whose Ping blocked until the
// HTTP client timeout).
func TestReadoptOneVMScanDeadlineDoesNotJudgeDead(t *testing.T) {
	h := newTestHandler()
	root := t.TempDir()
	h.SandboxRoot = root

	vmDir := filepath.Join(root, "vm-live")
	if err := writeState(persistedState{
		VMID:       "vm-live",
		CID:        7,
		PID:        1, // init: never a sandvmm — the PID guard must also spare it
		SandboxDir: vmDir,
		APISocket:  filepath.Join(vmDir, "sandvmm.sock"),
		CreatedAt:  time.Now(),
	}, root); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // scan budget already gone: every Ping below fails on the ctx

	m := NewEmbeddedManager(h)
	info := m.readoptOneVM(ctx, vmDir, map[string]bool{})
	if info != nil {
		t.Fatalf("readoptOneVM returned info for a deadline-expired scan, want nil (no verdict)")
	}
	if _, err := os.Stat(testStatePath(vmDir)); err != nil {
		t.Fatalf("state.json removed by a deadline-expired scan (the VM was never judged dead by a real Ping): %v", err)
	}
}

// TestIsSandvmmProcWithSocket covers the PID-identity guard used before
// signaling a PID read from a pre-restart state.json: a recycled PID (an
// unrelated process) must never match, our own sandvmm argv must match by
// socket, and a missing /proc entry reads as no-match (already gone).
func TestIsSandvmmProcWithSocket(t *testing.T) {
	// PID 1 (init) is not a sandvmm — must never match.
	if isSandvmmProcWithSocket(1, "/run/x/sandvmm.sock", SandvmmIdentity{}) {
		t.Error("isSandvmmProcWithSocket(1) = true; init is not sandvmm")
	}
	// Nonexistent PID reads as gone → no match.
	if isSandvmmProcWithSocket(1<<22, "", SandvmmIdentity{}) {
		t.Error("isSandvmmProcWithSocket(unused-pid) = true; a missing process must not match")
	}
	// Pure argv-level matching logic is covered via apiSocketFromArgv /
	// isSandvmmArgv (parse helpers below); live-process matching for a real
	// sandvmm is exercised by the e2e re-adopt suite.
	if s := apiSocketFromArgv([]string{"sandvmm", "--api-socket", "/a/b.sock", "--log-stderr"}); s != "/a/b.sock" {
		t.Errorf("apiSocketFromArgv = %q, want /a/b.sock", s)
	}
	if !isSandvmmArgv([]string{"/usr/bin/sandvmm"}) {
		t.Error("isSandvmmArgv(/usr/bin/sandvmm) = false")
	}
	if isSandvmmArgv([]string{"nginx"}) {
		t.Error("isSandvmmArgv(nginx) = true")
	}
}

// TestKillByPidSparesNonSandvmm ensures the re-adopt kill path cannot signal a
// PID whose /proc identity is not the expected sandvmm (PID-reuse protection).
func TestKillByPidSparesNonSandvmm(t *testing.T) {
	h := newTestHandler()
	// PID 1 is init on every system we run on; killing it would be catastrophic.
	// The guard must skip it (and the call must obviously not kill the test).
	h.killByPid(1, "vm-x", "/run/sandswap/vm/vm-x/sandvmm.sock")
}

// TestOrphanSocketInScope pins the orphan sweep's ownership scoping: only a
// sandvmm whose --api-socket lives under THIS instance's sandbox root is a
// kill candidate. A socket in another instance's root (multi-instance hosts
// share /proc) or an empty/unknown socket must never match — the old sweep
// killed every sandvmm on the host, wiping sibling instances' fleets on
// restart.
func TestOrphanSocketInScope(t *testing.T) {
	root := "/run/sandswap/ia/vm"
	cases := []struct {
		name string
		sock string
		root string
		want bool
	}{
		{"own vm socket", root + "/pool-small-0/sandvmm.sock", root, true},
		{"nested deeper", root + "/x/y/sandvmm.sock", root, true},
		{"sibling instance", "/run/sandswap/ib/vm/pool-small-0/sandvmm.sock", root, false},
		{"default-root instance vs custom root", "/run/sandswap/vm/pool-small-0/sandvmm.sock", root, false},
		{"custom root vs default-root instance", root + "/pool-small-0/sandvmm.sock", "/run/sandswap/vm", false},
		{"empty socket (unattributable)", "", root, false},
		{"escape via ..", "/run/sandswap/ia/vm/../../ib/vm/x/sandvmm.sock", root, false},
		{"the root itself is not a vm socket", root, root, false},
	}
	for _, c := range cases {
		if got := orphanSocketInScope(c.sock, c.root); got != c.want {
			t.Errorf("%s: orphanSocketInScope(%q, %q) = %v, want %v", c.name, c.sock, c.root, got, c.want)
		}
	}
}

// TestWaitReadoptCleanup covers the reconnect-clean gate's three shapes:
// returns immediately when nothing is in flight, blocks until the tracked
// cleanup finishes, and gives up (false) at the context deadline so a hung
// cleanup cannot stall the reconnect forever.
func TestWaitReadoptCleanup(t *testing.T) {
	h := newTestHandler()

	// Nothing in flight: immediate true.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if !h.WaitReadoptCleanup(ctx) {
		t.Fatal("WaitReadoptCleanup with empty WG returned false, want true")
	}

	// One cleanup in flight: must BLOCK while it runs, then return true once
	// it finishes. Deterministic shape: hold the WG, prove the wait does not
	// return, then release and prove it completes.
	h.readoptWG.Add(1)
	returned := make(chan bool, 1)
	ctx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel2()
	go func() { returned <- h.WaitReadoptCleanup(ctx2) }()
	select {
	case <-returned:
		t.Fatal("WaitReadoptCleanup returned while its tracked cleanup was still in flight")
	case <-time.After(100 * time.Millisecond):
		// still blocked — correct.
	}
	h.readoptWG.Done()
	select {
	case ok := <-returned:
		if !ok {
			t.Fatal("WaitReadoptCleanup returned false after cleanup completed, want true")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("WaitReadoptCleanup did not return after cleanup completed")
	}

	// Cleanup stuck past the budget: false, not a hang.
	h.readoptWG.Add(1)
	ctx3, cancel3 := context.WithTimeout(context.Background(), 50*time.Millisecond)
	if h.WaitReadoptCleanup(ctx3) {
		t.Error("WaitReadoptCleanup returned true at deadline with cleanup still in flight")
	}
	cancel3()
	h.readoptWG.Done() // release for test teardown
}

// The /proc identity checks must accept BOTH shipped VMM binary names: the
// build output (`sandvmm`, used by dev/e2e and the k8s image) and the installed
// bare-metal name (`sandswap-sandvmm`, what microvm.vmm_binary points at).
func TestIsSandvmmBinaryName(t *testing.T) {
	for _, ok := range []string{"sandvmm", "sandswap-sandvmm", "sandswap-sandvmm (deleted)", "sandvmm (deleted)"} {
		if !isSandvmmBinaryName(ok) {
			t.Errorf("isSandvmmBinaryName(%q) = false, want true", ok)
		}
	}
	for _, bad := range []string{"", "sandvmm2", "not-sandvmm", "/usr/bin/sandvmm/x"} {
		if isSandvmmBinaryName(bad) {
			t.Errorf("isSandvmmBinaryName(%q) = true, want false", bad)
		}
	}
	if !isSandvmmArgv([]string{"/usr/local/bin/sandswap-sandvmm", "--api-socket", "/run/x"}) {
		t.Error("isSandvmmArgv must accept the installed binary name")
	}
	if isSandvmmArgv([]string{"/tmp/fake", "--api-socket", "/run/x"}) {
		t.Error("isSandvmmArgv must refuse a foreign argv[0]")
	}
}

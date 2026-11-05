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
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"sandlot/vmm"
)

// --- ResetSurvivorsToClean ---

func TestResetSurvivorsToClean_EmptyVMs(t *testing.T) {
	h := newTestHandler()
	h.ResetSurvivorsToClean(context.Background(), time.Time{})
}

func TestResetSurvivorsToClean_ClearsVolumes(t *testing.T) {
	h := newTestHandler()
	st := &VMState{
		Volumes: map[string]struct{}{
			"/vol/sandfs-abc": {},
			"/vol/sandfs-def": {},
		},
	}
	h.mu.Lock()
	h.vms["vm-test"] = st
	h.mu.Unlock()

	h.ResetSurvivorsToClean(context.Background(), time.Time{})

	st.mountMu.Lock()
	volCount := len(st.Volumes)
	st.mountMu.Unlock()
	if volCount != 0 {
		t.Errorf("expected Volumes to be cleared, got %d entries", volCount)
	}
}

func TestResetSurvivorsToClean_NilWardenNoPanic(t *testing.T) {
	h := newTestHandler()
	st := &VMState{
		Volumes: map[string]struct{}{"/vol/x": {}},
	}
	h.mu.Lock()
	h.vms["vm-nil-warden"] = st
	h.mu.Unlock()

	h.ResetSurvivorsToClean(context.Background(), time.Time{})

	st.mountMu.Lock()
	volCount := len(st.Volumes)
	st.mountMu.Unlock()
	if volCount != 0 {
		t.Errorf("expected Volumes cleared even with nil Warden, got %d", volCount)
	}
}

func TestResetSurvivorsToClean_MultipleVMs(t *testing.T) {
	h := newTestHandler()
	for i := 0; i < 3; i++ {
		st := &VMState{
			Volumes: map[string]struct{}{
				fmt.Sprintf("/vol/sandfs-%d", i): {},
			},
		}
		h.mu.Lock()
		h.vms[fmt.Sprintf("vm-%d", i)] = st
		h.mu.Unlock()
	}

	h.ResetSurvivorsToClean(context.Background(), time.Time{})

	h.mu.RLock()
	defer h.mu.RUnlock()
	for id, st := range h.vms {
		st.mountMu.Lock()
		volCount := len(st.Volumes)
		st.mountMu.Unlock()
		if volCount != 0 {
			t.Errorf("vm %s: expected Volumes cleared, got %d", id, volCount)
		}
	}
}

func TestResetSurvivorsToClean_NilVMNoPanic(t *testing.T) {
	h := newTestHandler()
	st := &VMState{
		VM:      nil,
		Volumes: map[string]struct{}{"/vol/x": {}},
	}
	h.mu.Lock()
	h.vms["vm-nil-vm"] = st
	h.mu.Unlock()

	h.ResetSurvivorsToClean(context.Background(), time.Time{})

	st.mountMu.Lock()
	volCount := len(st.Volumes)
	st.mountMu.Unlock()
	if volCount != 0 {
		t.Errorf("expected Volumes cleared even with nil VM, got %d", volCount)
	}
}

// --- parsePID ---

func TestParsePID(t *testing.T) {
	tests := []struct {
		input  string
		want   int
		wantOK bool
	}{
		{"1234", 1234, true},
		{"1", 1, true},
		{"0", 0, false},   // PID 0 is invalid
		{"-1", 0, false},  // non-digit
		{"abc", 0, false}, // non-digit
		{"12a3", 0, false},
		{"", 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, ok := parsePID(tt.input)
			if ok != tt.wantOK {
				t.Errorf("parsePID(%q) ok = %v, want %v", tt.input, ok, tt.wantOK)
			}
			if got != tt.want {
				t.Errorf("parsePID(%q) = %d, want %d", tt.input, got, tt.want)
			}
		})
	}
}

// --- isSandvmmArgv ---

func TestIsSandvmmArgv(t *testing.T) {
	tests := []struct {
		name string
		argv []string
		want bool
	}{
		{"sandvmm", []string{"/usr/bin/sandvmm", "--api-socket", "/tmp/test.sock"}, true},
		{"sandvmm no path", []string{"sandvmm"}, true},
		{"other process", []string{"/usr/bin/bash", "-c", "echo hi"}, false},
		{"empty", []string{}, false},
		{"similar name", []string{"sandvmm-debug"}, false}, // filepath.Base is "sandvmm-debug", not "sandvmm"
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isSandvmmArgv(tt.argv); got != tt.want {
				t.Errorf("isSandvmmArgv(%v) = %v, want %v", tt.argv, got, tt.want)
			}
		})
	}
}

// --- apiSocketFromArgv ---

func TestApiSocketFromArgv(t *testing.T) {
	tests := []struct {
		name string
		argv []string
		want string
	}{
		{"present", []string{"sandvmm", "--api-socket", "/tmp/test.sock"}, "/tmp/test.sock"},
		{"missing", []string{"sandvmm", "--seccomp", "false"}, ""},
		{"at end without value", []string{"sandvmm", "--api-socket"}, ""},
		{"empty", []string{}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := apiSocketFromArgv(tt.argv); got != tt.want {
				t.Errorf("apiSocketFromArgv(%v) = %q, want %q", tt.argv, got, tt.want)
			}
		})
	}
}

// --- probe sweep abandonment ---

// TestProbeAllVMsSweepAbandon drives the exact mass-hang scenario the sweep
// budget exists for: more VMs than worker slots, every probe hung. When the
// budget expires while the dispatcher is blocked on a worker slot, the sweep
// must cancel its Add and stop dispatching — the historical bug (a bare
// `break` exiting only the select) launched the goroutine anyway: its deferred
// wg.Done() drove the WaitGroup negative (process panic) and it received a
// sem token it never acquired, corrupting the worker count.
func TestProbeAllVMsSweepAbandon(t *testing.T) {
	h := newTestHandler()
	total := probeWorkers + 6 // more VMs than worker slots

	release := make(chan struct{})
	var probeCalls atomic.Int32
	h.testProbeFn = func(cid uint32) (uint64, uint64, error) {
		probeCalls.Add(1)
		<-release // hang every probe: all worker slots stay busy past the budget
		// Error (not success) so the post-release bookkeeping takes the
		// delete-on-nil-map path, which is safe on the test handler.
		return 0, 0, fmt.Errorf("released")
	}
	for i := 0; i < total; i++ {
		id := fmt.Sprintf("vm-%d", i)
		h.mu.Lock()
		h.vms[id] = &VMState{VM: &vmm.RunningVM{ID: id, GuestCID: uint32(100 + i)}}
		h.mu.Unlock()
	}

	start := time.Now()
	h.probeAllVMs()
	elapsed := time.Since(start)
	close(release) // let any in-flight probes finish (they fail, no teardown at 1 failure)

	if elapsed > probeSweepTimeout+500*time.Millisecond {
		t.Errorf("sweep took %v; want abandonment at the %v budget", elapsed, probeSweepTimeout)
	}
	if got := probeCalls.Load(); got > probeWorkers {
		t.Errorf("dispatched %d probes; want <= %d worker slots (the budget-expired dispatch must cancel its Add, not launch the goroutine)",
			got, probeWorkers)
	}
	// A (buggily) launched extra goroutine would run to completion here and
	// hit the double-Done panic; with the fix there is nothing left in flight.
	time.Sleep(150 * time.Millisecond)
}

// TestProbeLoopStopThenStartReArms pins the wakeup contract that the warden
// countdown depends on: OP_MEM_STATS from the probe loop is the ONLY heartbeat,
// so a Stop immediately followed by a Start must leave a RUNNING loop even
// while the previous goroutine is still unwinding. The old shape cleared its
// running flag from the old goroutine's defer, so the Start in that window was
// silently swallowed and the process was left with no probe loop — the
// countdown anchor would freeze and VMs would be POWER_OFF'd at
// anchor+T_warden.
func TestProbeLoopStopThenStartReArms(t *testing.T) {
	h := &Handler{logger: log.New(io.Discard, "", 0)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	h.StartProbeLoop(ctx)
	if h.probeLoop == nil {
		t.Fatal("loop not installed")
	}
	// Stop and Start with no delay: the old goroutine may not have exited yet.
	h.StopProbeLoop()
	h.StartProbeLoop(ctx)
	if h.probeLoop == nil {
		t.Fatal("Stop+Start left NO probe loop (the warden heartbeat would be dead)")
	}
	// And the second loop must survive the first goroutine's deferred cleanup.
	time.Sleep(100 * time.Millisecond)
	h.probeMu.Lock()
	alive := h.probeLoop != nil
	h.probeMu.Unlock()
	if !alive {
		t.Fatal("the old goroutine's cleanup cleared the NEW loop's token")
	}
	h.StopProbeLoop()
}

// A VM whose Volumes set is empty but whose cold mount is still pending must
// NOT be declared CLEAN and skipped: the late mount would land after the
// reconnect-clean announcement. With no RPC to complete it, the budget expires
// and the VM is destroyed instead of reused.
func TestResetSurvivorsToClean_DrainsPendingMount(t *testing.T) {
	h := newTestHandler()
	st := &VMState{
		VM:           &vmm.RunningVM{ID: "vm-pending", GuestCID: 1 << 20},
		pendingMount: &pendingMount{sandfsID: "sf-x", alias: "gen0"},
	}
	h.mu.Lock()
	h.vms["vm-pending"] = st
	h.mu.Unlock()

	h.ResetSurvivorsToClean(context.Background(), time.Now().Add(100*time.Millisecond))

	if !st.pendingDestroy.Load() {
		t.Fatal("a VM with a pending mount and empty Volumes was treated as CLEAN instead of destroyed")
	}
}

// TestResetSurvivorsRecyclesVMAtMountCap pins the re-adopt half of the
// dual-counter rule: a clean survivor whose persisted mount count is already
// at the cap must be destroyed+replaced, not reused forever (selection
// excludes it, so leaving it clean would strand capacity).
func TestResetSurvivorsRecyclesVMAtMountCap(t *testing.T) {
	h := newTestHandler()
	h.recycleMaxMounts.Store(1)
	st := &VMState{VM: &vmm.RunningVM{ID: "vm-cap", GuestCID: 1 << 20}, SpecID: "small"}
	st.mountCount.Store(1)
	h.mu.Lock()
	h.vms[st.VM.ID] = st
	h.mu.Unlock()

	h.ResetSurvivorsToClean(context.Background(), time.Now().Add(100*time.Millisecond))
	if !st.pendingDestroy.Load() {
		t.Fatal("a clean survivor at the mount-count cap was not recycled")
	}
}

// TestCapGuestLogsDoesNotFollowSymlink pins the fd-based log cap: a symlink
// planted at console.log/serial.log must never be followed (the sandbox dir
// is group-writable), while a real oversized log is still truncated.
func TestCapGuestLogsDoesNotFollowSymlink(t *testing.T) {
	h := newTestHandler()
	dir := t.TempDir()
	victim := filepath.Join(t.TempDir(), "victim")
	victimData := make([]byte, guestLogCapBytes+100)
	if err := os.WriteFile(victim, victimData, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(dir, "console.log")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "serial.log"), victimData, 0o600); err != nil {
		t.Fatal(err)
	}
	h.vms["vm-log"] = &VMState{Cfg: vmm.Config{SandboxDir: dir}}

	h.capGuestLogs()
	if fi, err := os.Stat(victim); err != nil || fi.Size() != int64(len(victimData)) {
		t.Fatalf("symlink target was truncated (fi=%v err=%v)", fi, err)
	}
	if fi, err := os.Stat(filepath.Join(dir, "serial.log")); err != nil || fi.Size() != 0 {
		t.Fatalf("regular oversized log was not truncated (fi=%v err=%v)", fi, err)
	}
}

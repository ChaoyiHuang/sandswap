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
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	pb "common/proto/stream"
	"sandlot/vmm"
)

// recordingLifecycleManager records DestroyVM targets so tests can assert what
// the teardown paths delegate to the lifecycle manager — including the
// regression: the target must be delivered even though the caller already
// deleted the VM from h.vms.
type recordingLifecycleManager struct {
	mu      sync.Mutex
	targets []*DestroyTarget
}

func (r *recordingLifecycleManager) DestroyVM(ctx context.Context, target *DestroyTarget) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.targets = append(r.targets, target)
	return nil
}

func (r *recordingLifecycleManager) CreateVM(context.Context, vmm.Config) (*VMLifecycleInfo, error) {
	return nil, fmt.Errorf("not supported in tests")
}
func (r *recordingLifecycleManager) ProvisionNetwork(context.Context, string) (vmm.VMNetSpec, error) {
	return vmm.VMNetSpec{}, nil
}
func (r *recordingLifecycleManager) ReleaseNetwork(context.Context, string) error { return nil }
func (r *recordingLifecycleManager) ReclaimNetwork(context.Context, string, vmm.VMNetSpec) error {
	return nil
}
func (r *recordingLifecycleManager) MountOverlay(context.Context, string, string) (string, error) {
	return "", nil
}
func (r *recordingLifecycleManager) UnmountOverlay(context.Context, string) error { return nil }
func (r *recordingLifecycleManager) VerifyVolumeID(context.Context, string, string, string) error {
	return nil
}
func (r *recordingLifecycleManager) ReadoptVMs(context.Context) ([]ReadoptedVMInfo, error) {
	return nil, nil
}
func (r *recordingLifecycleManager) RestoreMountedOverlays() {}
func (r *recordingLifecycleManager) CleanupStaleOverlays()   {}
func (r *recordingLifecycleManager) Stop()                   {}

func (r *recordingLifecycleManager) lastTarget() *DestroyTarget {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.targets) == 0 {
		return nil
	}
	return r.targets[len(r.targets)-1]
}

func (r *recordingLifecycleManager) callCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.targets)
}

// testStateWithVM builds a VMState with a real GuestCID + SandboxDir so the
// teardown path exercises CID release and carries a meaningful target.
func testStateWithVM(h *Handler, vmID string, cid uint32) *VMState {
	state := addTestVM(h, vmID, "small", false)
	state.VM.GuestCID = cid
	state.Cfg.SandboxDir = filepath.Join("/tmp/sandswap-test", vmID)
	return state
}

// TestHandleVMDied_DestroysThroughLifecycleManager: the crash teardown must
// delegate the kill+cleanup to the lifecycle manager with a target built from
// the captured state (not a map lookup), release the CID exactly once, mark
// destroying, and remove the VM from the map.
func TestHandleVMDied_DestroysThroughLifecycleManager(t *testing.T) {
	h := newTestHandler()
	rec := &recordingLifecycleManager{}
	h.vm = rec
	state := testStateWithVM(h, "vm1", 42)
	h.reserveCID(42)

	h.handleVMDied(state, fmt.Errorf("test crash"))

	if rec.callCount() != 1 {
		t.Fatalf("DestroyVM called %d times, want 1", rec.callCount())
	}
	target := rec.lastTarget()
	if target == nil {
		t.Fatal("no DestroyVM target recorded")
	}
	if target.VMID != "vm1" || target.SandboxDir != state.Cfg.SandboxDir {
		t.Errorf("target = %+v, want VMID vm1 + SandboxDir %s", target, state.Cfg.SandboxDir)
	}
	if target.VM == nil || target.VM.GuestCID != 42 {
		t.Errorf("target.VM = %+v, want the captured RunningVM with GuestCID 42", target.VM)
	}

	h.mu.Lock()
	_, inMap := h.vms["vm1"]
	h.mu.Unlock()
	if inMap {
		t.Error("VM still present in h.vms after teardown")
	}
	state.mu.Lock()
	destroying := state.destroying
	state.mu.Unlock()
	if !destroying {
		t.Error("state.destroying not set after teardown")
	}

	// CID released exactly once (idempotent free-list).
	h.mu.Lock()
	freeCount := 0
	for _, c := range h.cidFree {
		if c == 42 {
			freeCount++
		}
	}
	h.mu.Unlock()
	if freeCount != 1 {
		t.Errorf("CID 42 in free-list %d times, want exactly 1", freeCount)
	}
}

// TestHandleVMDied_IdempotentAcrossMonitors: concurrent teardown entries
// (crash path racing probe path) must run the lifecycle destroy exactly once.
func TestHandleVMDied_IdempotentAcrossMonitors(t *testing.T) {
	h := newTestHandler()
	rec := &recordingLifecycleManager{}
	h.vm = rec
	state := testStateWithVM(h, "vm1", 42)

	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h.handleVMDied(state, fmt.Errorf("concurrent teardown"))
		}()
	}
	wg.Wait()

	if rec.callCount() != 1 {
		t.Errorf("DestroyVM called %d times across 3 concurrent teardowns, want 1", rec.callCount())
	}
}

// TestDestroyVMByID_UsesTargetNotMap pins the destroy-kill regression: the
// target must reach the lifecycle manager even though the VM was already
// removed from h.vms before DestroyVM is invoked (the embedded impl used to
// re-look-up the map, miss, and skip the kill — leaking the sandvmm process
// and its state on every embedded-mode destroy).
func TestDestroyVMByID_UsesTargetNotMap(t *testing.T) {
	h := newTestHandler()
	rec := &recordingLifecycleManager{}
	h.vm = rec
	state := testStateWithVM(h, "vm1", 42)
	h.reserveCID(42)

	h.destroyVMByID("vm1")

	if rec.callCount() != 1 {
		t.Fatalf("DestroyVM called %d times, want 1", rec.callCount())
	}
	target := rec.lastTarget()
	if target == nil {
		t.Fatal("no DestroyVM target recorded")
	}
	if target.VM == nil {
		t.Fatal("target.VM is nil — the embedded kill would have been skipped (regression)")
	}
	if target.VMID != "vm1" || target.SandboxDir != state.Cfg.SandboxDir || target.VM.GuestCID != 42 {
		t.Errorf("target = %+v, want VMID vm1 / SandboxDir %s / GuestCID 42", target, state.Cfg.SandboxDir)
	}
	h.mu.Lock()
	_, inMap := h.vms["vm1"]
	h.mu.Unlock()
	if inMap {
		t.Error("VM still in h.vms after destroyVMByID")
	}
}

// TestReleaseCID_NoDuplicate: a double release must not put the CID on the
// free-list twice (that would hand one CID to two VMs).
func TestReleaseCID_NoDuplicate(t *testing.T) {
	h := newTestHandler()
	h.reserveCID(7)
	h.releaseCID(7)
	h.releaseCID(7) // double release (crash path racing destroy path)
	h.mu.Lock()
	freeCount := 0
	for _, c := range h.cidFree {
		if c == 7 {
			freeCount++
		}
	}
	h.mu.Unlock()
	if freeCount != 1 {
		t.Errorf("CID 7 in free-list %d times after double release, want 1", freeCount)
	}
	a := h.guestCID()
	b := h.guestCID()
	if a == b {
		t.Errorf("guestCID returned %d twice — duplicate free-list entry", a)
	}
}

// --- killVMM (real process kill for the re-adopted path) ---

// stubVMMServer answers sandvmm.ping and sandvmm.shutdown over a Unix socket.
// closeAfterShutdown marks the server dead on the shutdown request: pings then
// return 500 with Connection: close (so the client's keep-alive connection is
// dropped and the next dial — which fails — is forced) and the listener is
// closed, and onShutdown (if non-nil) fires — tests use it to kill the child
// process, simulating "the VMM exited after graceful shutdown".
func stubVMMServer(t *testing.T, closeAfterShutdown bool, onShutdown func()) (socketPath string, shutdownSeen func() bool) {
	t.Helper()
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "sandvmm.sock")
	l, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	var mu sync.Mutex
	seen := false
	dead := false
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/sandvmm.ping", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		isDead := dead
		mu.Unlock()
		if isDead {
			w.Header().Set("Connection", "close")
			http.Error(w, "vmm gone", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/api/v1/sandvmm.shutdown", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = true
		if closeAfterShutdown {
			dead = true
		}
		mu.Unlock()
		w.Header().Set("Connection", "close")
		w.WriteHeader(http.StatusOK)
		if closeAfterShutdown {
			go l.Close()
			if onShutdown != nil {
				go onShutdown()
			}
		}
	})
	srv := &http.Server{Handler: mux}
	go srv.Serve(l)
	t.Cleanup(func() {
		srv.Close()
		l.Close()
	})
	return sockPath, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return seen
	}
}

// startFakeSandvmm spawns a process whose /proc argv looks like a sandvmm
// invocation carrying apiSocket. The readopted force-kill re-verifies that
// shape before signaling (a reused PID must never be killed), so a plain
// `sleep` child would be refused.
func startFakeSandvmm(t *testing.T, apiSocket string) *exec.Cmd {
	t.Helper()
	bashBin, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not available")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "sandvmm")
	if lerr := os.Link(bashBin, bin); lerr != nil {
		data, rerr := os.ReadFile(bashBin)
		if rerr != nil {
			t.Fatalf("read bash: %v", rerr)
		}
		if werr := os.WriteFile(bin, data, 0o755); werr != nil {
			t.Fatalf("write fake sandvmm: %v", werr)
		}
	}
	cmd := exec.Command(bin, "-c", "trap '' TERM; while :; do sleep 1; done", "--api-socket", apiSocket)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start fake sandvmm: %v", err)
	}
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	})
	return cmd
}

// TestKillVMM_ReadoptedShutdownThenKill: a re-adopted VM whose VMM API keeps
// answering must be force-killed by PID after the confirm-dead timeout, and
// killVMM must confirm the death.
func TestKillVMM_ReadoptedShutdownThenKill(t *testing.T) {
	if testing.Short() {
		t.Skip("killVMM confirm-dead path takes ~5s")
	}
	h := newTestHandler()
	sock, _ := stubVMMServer(t, false, nil)

	child := startFakeSandvmm(t, sock)

	vm, err := vmm.Attach(context.Background(), vmm.AttachConfig{
		ID: "vm1", APISocket: sock, GuestCID: 9, PID: child.Process.Pid,
	}, nil)
	if err != nil {
		t.Fatalf("attach: %v", err)
	}

	start := time.Now()
	confirmed := h.killVMM(context.Background(), &DestroyTarget{
		VMID: "vm1", VM: vm, PID: child.Process.Pid, Readopted: true,
	})
	elapsed := time.Since(start)
	if !confirmed {
		t.Error("killVMM did not confirm the process death after force-kill")
	}
	if elapsed < 4*time.Second {
		t.Errorf("killVMM returned in %v; expected the ~5s confirm-dead wait before Kill", elapsed)
	}
	// The child is our process, so Wait reaps it and reports the kill.
	done := make(chan error, 1)
	go func() { done <- child.Wait() }()
	select {
	case werr := <-done:
		if werr == nil {
			t.Error("child exited cleanly — force-kill did not fire")
		}
	case <-time.After(2 * time.Second):
		t.Error("child still running after killVMM — force-kill did not fire")
	}
}

// TestKillVMM_ReadoptedFastConfirm: once the VMM API stops answering AND the
// process actually exited, the confirm-dead poll returns immediately and
// killVMM confirms death.
func TestKillVMM_ReadoptedFastConfirm(t *testing.T) {
	h := newTestHandler()

	child := startFakeSandvmm(t, "") // socket isn't needed for the fast path
	// Simulate a real graceful exit: when the shutdown request lands, the VMM
	// process dies too (Kill → Wait reaps our child).
	done := make(chan struct{})
	sock, shutdownSeen := stubVMMServer(t, true, func() {
		child.Process.Kill()
		_, _ = child.Process.Wait()
		close(done)
	})

	vm, err := vmm.Attach(context.Background(), vmm.AttachConfig{
		ID: "vm1", APISocket: sock, GuestCID: 9, PID: child.Process.Pid,
	}, nil)
	if err != nil {
		t.Fatalf("attach: %v", err)
	}

	start := time.Now()
	confirmed := h.killVMM(context.Background(), &DestroyTarget{
		VMID: "vm1", VM: vm, PID: child.Process.Pid, Readopted: true,
	})
	elapsed := time.Since(start)
	if !confirmed {
		t.Error("killVMM did not confirm the process death on the fast path")
	}
	if elapsed > 1500*time.Millisecond {
		t.Errorf("killVMM took %v; expected fast confirm-dead after API stop", elapsed)
	}
	if !shutdownSeen() {
		t.Error("graceful shutdown request was never sent")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Error("child did not exit")
	}
}

// TestKillVMM_UnconfirmedDeathSkipsCID pins an invariant: a process that
// ignores signals (simulated here by an API that stops answering while the
// process stays alive) leaves killVMM unconfirmed — DestroyVM must report the
// error so callers skip the CID release.
func TestKillVMM_UnconfirmedDeathSkipsCID(t *testing.T) {
	if testing.Short() {
		t.Skip("unconfirmed-death path takes ~2s")
	}
	h := newTestHandler()
	rec := &recordingLifecycleManager{}
	// Simulate a D-state process: API stops after shutdown, process alive.
	sock, _ := stubVMMServer(t, true, nil)

	child := startFakeSandvmm(t, sock)

	vm, err := vmm.Attach(context.Background(), vmm.AttachConfig{
		ID: "vm1", APISocket: sock, GuestCID: 9, PID: child.Process.Pid,
	}, nil)
	if err != nil {
		t.Fatalf("attach: %v", err)
	}

	// Via the real embedded path: DestroyVM must return the unconfirmed error.
	em := &embeddedManager{handler: h}
	err = em.DestroyVM(context.Background(), &DestroyTarget{
		VMID: "vm1", VM: vm, APISocket: sock, PID: child.Process.Pid, Readopted: true,
	})
	if err == nil {
		t.Error("DestroyVM returned nil despite the process surviving; CID would be released onto a live VM")
	}
	_ = rec
	if !childAlive(child.Process.Pid) && syscall.Kill(child.Process.Pid, 0) == nil {
		t.Log("process state changed during test")
	}
}

// childAlive reports whether pid is still alive (kill(pid, 0)).
func childAlive(pid int) bool {
	return syscall.Kill(pid, 0) == nil
}

// TestKillVMM_NilTargetSafety: nil / nil-VM targets are safe no-ops.
func TestKillVMM_NilTargetSafety(t *testing.T) {
	h := newTestHandler()
	h.killVMM(context.Background(), nil)              // must not panic
	h.killVMM(context.Background(), &DestroyTarget{}) // VM nil — must not panic
}

// --- stranded-resource metrics (unconfirmed-death destroys) ---

// erroringLifecycleManager fails every DestroyVM, simulating the
// unconfirmed-death path (D-state sandvmm / failed lifecycle RPC).
type erroringLifecycleManager struct {
	recordingLifecycleManager
}

func (e *erroringLifecycleManager) DestroyVM(context.Context, *DestroyTarget) error {
	return fmt.Errorf("death unconfirmed (D-state)")
}

// TestStrandedMetricsRecordedOnUnconfirmedDeath: both destroy paths that skip
// the CID + memory-reservation release must record the stranding, so the
// heartbeat can explain the silent pool-capacity loss.
func TestStrandedMetricsRecordedOnUnconfirmedDeath(t *testing.T) {
	// handleVMDied path.
	h := newTestHandler()
	h.vm = &erroringLifecycleManager{}
	st := testStateWithVM(h, "vm1", 42)
	st.Cfg.MemoryMB = 256
	h.reserveCID(42)
	h.handleVMDied(st, fmt.Errorf("crash"))
	if s := h.metrics.Snapshot(); s.StrandedReservationsMB != 256 || s.StrandedCIDs != 1 {
		t.Errorf("handleVMDied stranding = %dMB/%d CIDs, want 256MB/1", s.StrandedReservationsMB, s.StrandedCIDs)
	}

	// destroyVMByID path (accumulates).
	h2 := newTestHandler()
	h2.vm = &erroringLifecycleManager{}
	st2 := testStateWithVM(h2, "vm2", 43)
	st2.Cfg.MemoryMB = 512
	h2.destroyVMByID("vm2")
	if s := h2.metrics.Snapshot(); s.StrandedReservationsMB != 512 || s.StrandedCIDs != 1 {
		t.Errorf("destroyVMByID stranding = %dMB/%d CIDs, want 512MB/1", s.StrandedReservationsMB, s.StrandedCIDs)
	}
}

// TestStrandedMetricsZeroOnConfirmedDeath: the normal (confirmed) destroy
// releases everything and must not move the stranding gauges.
func TestStrandedMetricsZeroOnConfirmedDeath(t *testing.T) {
	h := newTestHandler()
	h.vm = &recordingLifecycleManager{}
	st := testStateWithVM(h, "vm1", 42)
	st.Cfg.MemoryMB = 256
	h.destroyVMByID("vm1")
	if s := h.metrics.Snapshot(); s.StrandedReservationsMB != 0 || s.StrandedCIDs != 0 {
		t.Errorf("confirmed death moved stranding gauges: %dMB/%d CIDs", s.StrandedReservationsMB, s.StrandedCIDs)
	}
}

// TestDestroyVMByIDDropsMemStatsEntry pins the heartbeat-snapshot cleanup on
// destroy: the probe loop only deletes entries it observed FAILING, so without
// an explicit delete here a VM destroyed between sweeps leaves a ghost
// VmMemInfo forever (slow leak + the heartbeat reporting a dead VM's memory
// to the gateway).
func TestDestroyVMByIDDropsMemStatsEntry(t *testing.T) {
	h := newTestHandler()
	h.memStats = make(map[string]*pb.VmMemInfo)
	addTestVM(h, "vm-gone", "small", false)
	h.memStatsMu.Lock()
	h.memStats["vm-gone"] = &pb.VmMemInfo{VmId: "vm-gone", MemTotalBytes: 1}
	h.memStats["vm-kept"] = &pb.VmMemInfo{VmId: "vm-kept", MemTotalBytes: 1}
	h.memStatsMu.Unlock()

	h.destroyVMByID("vm-gone")

	h.memStatsMu.RLock()
	defer h.memStatsMu.RUnlock()
	if _, ok := h.memStats["vm-gone"]; ok {
		t.Error("destroyed VM still present in memStats (ghost heartbeat entry)")
	}
	if _, ok := h.memStats["vm-kept"]; !ok {
		t.Error("unrelated memStats entry dropped by the destroy path")
	}
}

// TestHandleVMDiedDropsMemStatsEntry is the crash-path twin of the destroy
// test above: handleVMDied must clear the same snapshot entry.
func TestHandleVMDiedDropsMemStatsEntry(t *testing.T) {
	h := newTestHandler()
	h.memStats = make(map[string]*pb.VmMemInfo)
	st := addTestVM(h, "vm-died", "small", false)
	h.memStatsMu.Lock()
	h.memStats["vm-died"] = &pb.VmMemInfo{VmId: "vm-died", MemTotalBytes: 1}
	h.memStatsMu.Unlock()

	h.handleVMDied(st, fmt.Errorf("test crash"))

	h.memStatsMu.RLock()
	_, ok := h.memStats["vm-died"]
	h.memStatsMu.RUnlock()
	if ok {
		t.Error("crashed VM still present in memStats (ghost heartbeat entry)")
	}
}

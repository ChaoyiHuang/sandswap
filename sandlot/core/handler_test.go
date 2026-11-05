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
	"errors"
	"fmt"
	"log"
	"os"
	"sync/atomic"
	"testing"
	"time"

	pb "common/proto/stream"
	"sandlot/vmm"
)

// --- Test helpers (shared across test files in this package) ---

// newTestHandler creates a minimal Handler for unit tests. No real VMs, no
// network, no gateway client — just enough state to test error classification,
// pool resize, and pending-destroy logic.
func newTestHandler() *Handler {
	h := &Handler{
		vms:      make(map[string]*VMState),
		bindings: newBindingStore(),
		// Every fake volume path in this package lives under /vol: the
		// VolumesDir-containment guard on the mount/cleanup paths refuses
		// anything outside the configured root (and anything at all when the
		// root is empty), so the fixture must carry a real root.
		vmmCfg:          vmm.Config{VolumesDir: "/vol"},
		logger:          log.New(os.Stderr, "[test] ", log.LstdFlags|log.Lmsgprefix),
		overlayCache:    make(map[string]*overlayRefEntry),
		mountedOverlays: make(map[string]string),
		cidFree:         make([]uint32, 0),
		cidUsed:         make(map[uint32]bool),
		readoptPending:  make(map[string]struct{}),
		// Deterministic ledger: 8GB budget, MemAvailable pinned to 8GB so
		// admission outcomes don't depend on the test host's real memory.
		memLedger: newMemLedger(8192, func() (uint64, error) { return 8192, nil }),
	}
	h.vm = &noopVMLifecycleManager{}
	h.metrics = NewNodeMetricsCollector()
	// Mirror the production default (NewHandler): the distinct-agent cap is
	// on unless a test explicitly disables it.
	h.maxDistinctAgents.Store(300)
	return h
}

// noopVMLifecycleManager is a no-op VMLifecycleManager for unit tests. All
// methods return success (nil error / zero values) so that code paths
// exercising h.vm (destroyVMByID, handleCleanupOverlay, etc.) don't
// nil-deref. It performs no real VM/network/overlay operations.
type noopVMLifecycleManager struct{}

func (*noopVMLifecycleManager) CreateVM(context.Context, vmm.Config) (*VMLifecycleInfo, error) {
	return nil, fmt.Errorf("noopVMLifecycleManager: CreateVM not supported in tests")
}
func (*noopVMLifecycleManager) DestroyVM(context.Context, *DestroyTarget) error {
	return nil
}
func (*noopVMLifecycleManager) ProvisionNetwork(context.Context, string) (vmm.VMNetSpec, error) {
	return vmm.VMNetSpec{}, nil
}
func (*noopVMLifecycleManager) ReleaseNetwork(context.Context, string) error { return nil }
func (*noopVMLifecycleManager) ReclaimNetwork(context.Context, string, vmm.VMNetSpec) error {
	return nil
}
func (*noopVMLifecycleManager) MountOverlay(context.Context, string, string) (string, error) {
	return "", nil
}
func (*noopVMLifecycleManager) UnmountOverlay(context.Context, string) error { return nil }
func (*noopVMLifecycleManager) VerifyVolumeID(context.Context, string, string, string) error {
	return nil
}
func (*noopVMLifecycleManager) ReadoptVMs(context.Context) ([]ReadoptedVMInfo, error) {
	return nil, nil
}
func (*noopVMLifecycleManager) RestoreMountedOverlays() {}
func (*noopVMLifecycleManager) CleanupStaleOverlays()   {}
func (*noopVMLifecycleManager) Stop()                   {}

// newTestHandlerWithPool creates a handler with pool config and OnPoolChanged tracking.
func newTestHandlerWithPool() (*Handler, *atomic.Int32) {
	h := newTestHandler()
	var poolChanged atomic.Int32
	h.OnPoolChanged = func() {
		poolChanged.Add(1)
	}
	return h, &poolChanged
}

// ensureMountRecordsForTest seeds the per-binding identity maps for fixtures
// that construct a VMState without going through a real mount.
func (vm *VMState) ensureMountRecordsForTest(sandfsID, volumePath, alias string) {
	vm.mountMu.Lock()
	defer vm.mountMu.Unlock()
	if vm.mountAliasBySandfs == nil {
		vm.mountAliasBySandfs = make(map[string]string)
	}
	if vm.mountPathBySandfs == nil {
		vm.mountPathBySandfs = make(map[string]string)
	}
	vm.mountAliasBySandfs[sandfsID] = alias
	vm.mountPathBySandfs[sandfsID] = volumePath
}

// addTestVM adds a VM with the given ID and spec to the handler's vms map.
// If busy is true, a volume entry is added to simulate IN_USE. A busy VM is
// sync-handled by default (activeBgExecs=0). Use setBgExecs to mark it
// async-handled for sync/async priority tests.
func addTestVM(h *Handler, vmID, specID string, busy bool) *VMState {
	state := &VMState{
		VM:      &vmm.RunningVM{ID: vmID},
		Cfg:     vmm.Config{ID: vmID},
		SpecID:  specID,
		Volumes: make(map[string]struct{}),
	}
	if busy {
		state.Volumes["/vol/sandfs-test"] = struct{}{}
	}
	h.mu.Lock()
	h.vms[vmID] = state
	h.mu.Unlock()
	return state
}

// setBgExecs marks a VM as having N active background execs (async-handled).
func setBgExecs(state *VMState, n int64) {
	state.activeBgExecs.Store(n)
}

// --- guestCID ---

func TestGuestCID_StartsAt3(t *testing.T) {
	h := newTestHandler()
	cid := h.guestCID()
	if cid != 3 {
		t.Errorf("first CID = %d, want 3", cid)
	}
}

func TestGuestCID_MonotonicallyIncreasing(t *testing.T) {
	h := newTestHandler()
	prev := h.guestCID()
	for i := 0; i < 10; i++ {
		cid := h.guestCID()
		if cid <= prev {
			t.Errorf("CID %d should be > prev %d", cid, prev)
		}
		prev = cid
	}
}

func TestGuestCID_RespectsCidMax(t *testing.T) {
	h := newTestHandler()
	h.SetCIDMax(5) // allow CIDs 3, 4, 5
	h.guestCID()   // 3
	h.guestCID()   // 4
	h.guestCID()   // 5
	cid := h.guestCID()
	if cid != 0 {
		t.Errorf("expected 0 (range exhausted) when cidMax=5 and nextCID=6, got %d", cid)
	}
}

func TestGuestCID_IgnoresCidMaxZero(t *testing.T) {
	h := newTestHandler()
	h.SetCIDMax(0) // no limit
	for i := 0; i < 100; i++ {
		cid := h.guestCID()
		if cid == 0 {
			t.Fatal("CID should never be 0 when cidMax=0 (no limit)")
		}
	}
}

func TestGuestCID_Recycle(t *testing.T) {
	h := newTestHandler()
	// Allocate 3 CIDs: 3, 4, 5
	c1 := h.guestCID()
	c2 := h.guestCID()
	c3 := h.guestCID()
	if c1 != 3 || c2 != 4 || c3 != 5 {
		t.Fatalf("initial CIDs: %d,%d,%d; want 3,4,5", c1, c2, c3)
	}
	// Release c2 (4) and c1 (3) — out of order
	h.releaseCID(c2)
	h.releaseCID(c1)
	// Next allocation should reuse from free-list (LIFO: 3 then 4)
	c4 := h.guestCID()
	c5 := h.guestCID()
	if c4 != 3 {
		t.Errorf("first recycled CID = %d, want 3", c4)
	}
	if c5 != 4 {
		t.Errorf("second recycled CID = %d, want 4", c5)
	}
	// After free-list is drained, counter resumes
	c6 := h.guestCID()
	if c6 != 6 {
		t.Errorf("CID after free-list drain = %d, want 6", c6)
	}
}

func TestGuestCID_ExhaustAndRecover(t *testing.T) {
	h := newTestHandler()
	h.SetCIDMax(6) // allow CIDs 3, 4, 5, 6
	// Allocate all 4
	cids := make([]uint32, 0, 4)
	for i := 0; i < 4; i++ {
		cid := h.guestCID()
		if cid == 0 {
			t.Fatalf("allocation %d failed unexpectedly", i)
		}
		cids = append(cids, cid)
	}
	// Next allocation must fail (exhausted)
	cid := h.guestCID()
	if cid != 0 {
		t.Fatalf("expected 0 (exhausted), got %d", cid)
	}
	// Release one CID
	h.releaseCID(cids[1]) // release CID 4
	// Should now succeed with the released CID
	cid = h.guestCID()
	if cid != 4 {
		t.Errorf("after release, got CID %d, want 4", cid)
	}
}

func TestGuestCID_ReserveConflict(t *testing.T) {
	h := newTestHandler()
	// Allocate and release CID 3
	c1 := h.guestCID()
	if c1 != 3 {
		t.Fatalf("first CID = %d, want 3", c1)
	}
	h.releaseCID(c1) // 3 goes to free-list
	// Reserve CID 3 (simulating re-adopted VM)
	h.reserveCID(3)
	// Next allocation should NOT get 3 (it's reserved)
	c2 := h.guestCID()
	if c2 == 3 {
		t.Error("allocated reserved CID 3 from free-list")
	}
	if c2 != 4 {
		t.Errorf("expected CID 4 (skip reserved 3), got %d", c2)
	}
}

func TestGuestCID_ReserveBumpsCounter(t *testing.T) {
	h := newTestHandler()
	// Reserve a high CID (simulating re-adopted VM with CID 100)
	h.reserveCID(100)
	// Next allocation should skip past 100
	c1 := h.guestCID()
	if c1 != 3 {
		t.Errorf("first CID = %d, want 3", c1)
	}
	c2 := h.guestCID()
	if c2 != 4 {
		t.Errorf("second CID = %d, want 4", c2)
	}
	// Allocate until we approach 100
	for i := 0; i < 95; i++ { // already at 5, need to reach 99
		h.guestCID()
	}
	// Next should be 101 (100 is reserved)
	c := h.guestCID()
	if c != 101 {
		t.Errorf("CID after reserved 100 = %d, want 101", c)
	}
}

func TestGuestCID_ReleaseIdempotent(t *testing.T) {
	h := newTestHandler()
	c1 := h.guestCID() // 3
	h.releaseCID(c1)
	h.releaseCID(c1) // double release — should not panic or corrupt
	// Both free-list entries are 3; first allocation gets 3
	c2 := h.guestCID()
	if c2 != 3 {
		t.Errorf("after double release, CID = %d, want 3", c2)
	}
}

func TestGuestCID_ReleaseBelowMin(t *testing.T) {
	h := newTestHandler()
	// Releasing CID < 3 should be a no-op
	h.releaseCID(0)
	h.releaseCID(1)
	h.releaseCID(2)
	// Verify free-list is still empty
	h.mu.Lock()
	n := len(h.cidFree)
	h.mu.Unlock()
	if n != 0 {
		t.Errorf("free-list has %d entries after releasing CIDs < 3, want 0", n)
	}
}

// --- Re-adopt lifecycle tests ---

func TestGuestCID_ReadoptThenDestroy(t *testing.T) {
	// Simulate sandlot restart: re-adopt a VM with CID 5, then destroy it.
	// The CID should be released back to the free-list.
	h := newTestHandler()
	h.reserveCID(5) // re-adopt: mark CID 5 as in-use
	// New allocations should skip 5
	c1 := h.guestCID() // 3
	c2 := h.guestCID() // 4
	c3 := h.guestCID() // 6 (skipping reserved 5)
	if c1 != 3 || c2 != 4 || c3 != 6 {
		t.Fatalf("with CID 5 reserved: got %d,%d,%d; want 3,4,6", c1, c2, c3)
	}
	// Destroy the re-adopted VM: release CID 5
	h.releaseCID(5)
	// Next allocation should get 5 from the free-list
	c4 := h.guestCID()
	if c4 != 5 {
		t.Errorf("after releasing re-adopted CID 5, got %d, want 5", c4)
	}
}

func TestGuestCID_DeadVMReadopt(t *testing.T) {
	// Simulate sandlot restart where a VM is found dead.
	// Its CID should be released to the free-list for immediate reuse.
	h := newTestHandler()
	// Dead VM with CID 4: release its CID (readopt.go dead-VM path)
	h.releaseCID(4)
	// Next allocation should reuse 4 from the free-list
	c1 := h.guestCID()
	if c1 != 4 {
		t.Errorf("after dead-VM release of CID 4, got %d, want 4", c1)
	}
}

func TestGuestCID_ReadoptAttachFail(t *testing.T) {
	// Simulate: reserveCID called, then vmm.Attach fails.
	// The reserveCID must be undone by releaseCID.
	h := newTestHandler()
	h.reserveCID(3) // reserve before attach attempt
	// Attach fails → release
	h.releaseCID(3)
	// CID 3 should now be available from the free-list
	c1 := h.guestCID()
	if c1 != 3 {
		t.Errorf("after reserve+release of CID 3, got %d, want 3", c1)
	}
}

func TestGuestCID_MultipleReadopt(t *testing.T) {
	// Re-adopt VMs with CIDs 10, 20, 30 (out of order, sparse).
	// Verify allocations fill gaps and skip reserved CIDs.
	h := newTestHandler()
	h.reserveCID(10)
	h.reserveCID(20)
	h.reserveCID(30)
	// Allocations: 3,4,...,9,11,12,...,19,21,...
	cids := make([]uint32, 0, 15)
	for i := 0; i < 15; i++ {
		cids = append(cids, h.guestCID())
	}
	expected := []uint32{3, 4, 5, 6, 7, 8, 9, 11, 12, 13, 14, 15, 16, 17, 18}
	for i, got := range cids {
		if got != expected[i] {
			t.Errorf("allocation %d: got %d, want %d", i, got, expected[i])
		}
	}
	// Now destroy re-adopted VM with CID 20
	h.releaseCID(20)
	// Next allocation should get 20 from free-list
	c := h.guestCID()
	if c != 20 {
		t.Errorf("after releasing re-adopted CID 20, got %d, want 20", c)
	}
}

func TestGuestCID_PoolRecycle(t *testing.T) {
	// Simulate pool recycle: allocate CIDs, destroy, allocate again.
	// CIDs should be reused from the free-list.
	h := newTestHandler()
	h.SetCIDMax(10) // CIDs 3-10 (8 total)
	// Allocate all 8
	allocated := make([]uint32, 0, 8)
	for i := 0; i < 8; i++ {
		cid := h.guestCID()
		if cid == 0 {
			t.Fatalf("allocation %d failed", i)
		}
		allocated = append(allocated, cid)
	}
	// Should be exhausted
	if cid := h.guestCID(); cid != 0 {
		t.Fatalf("expected exhaustion, got CID %d", cid)
	}
	// Destroy all VMs (release all CIDs)
	for _, cid := range allocated {
		h.releaseCID(cid)
	}
	// Should be able to allocate 8 again from the free-list
	for i := 0; i < 8; i++ {
		cid := h.guestCID()
		if cid == 0 {
			t.Fatalf("re-allocation %d failed after releasing all CIDs", i)
		}
	}
	// Exhausted again
	if cid := h.guestCID(); cid != 0 {
		t.Fatalf("expected exhaustion after re-allocation, got CID %d", cid)
	}
}

// --- ProcessCommand: unknown type ---

func TestProcessCommand_UnknownType(t *testing.T) {
	h := newTestHandler()
	// ProcessCommand sends the response via client; with nil client it just logs.
	// We verify no panic with an empty command (no action set = default branch).
	cmd := &pb.VMCommand{CommandId: "test-unknown"}
	h.ProcessCommand(context.Background(), cmd)
}

// SPDX-License-Identifier: Apache-2.0

func TestNewHandlerDefaults(t *testing.T) {
	logger := log.New(os.Stderr, "[test] ", 0)
	h := NewHandler(nil, vmm.Config{}, &noopVMLifecycleManager{}, nil, logger)
	if h.SandboxRoot != defaultSandboxRoot {
		t.Errorf("SandboxRoot = %q, want %q", h.SandboxRoot, defaultSandboxRoot)
	}
	n, ids := h.ActiveVMs()
	if n != 0 || len(ids) != 0 {
		t.Errorf("ActiveVMs = (%d, %v), want (0, [])", n, ids)
	}
	h.Stop()
}

func TestHandlerSettersAndDelegates(t *testing.T) {
	h := newTestHandler()
	h.SetClient(nil)
	h.SetVMLifecycle(&noopVMLifecycleManager{})

	if _, err := h.ProvisionNetwork(context.Background(), "vm-1"); err != nil {
		t.Errorf("ProvisionNetwork = %v, want nil (noop manager)", err)
	}
	if err := h.ReleaseNetwork(context.Background(), "vm-1"); err != nil {
		t.Errorf("ReleaseNetwork = %v, want nil", err)
	}
	cfg := vmm.Config{ID: "vm-1"}
	if _, err := h.VMCreateAndAttach(context.Background(), cfg); err == nil {
		t.Error("VMCreateAndAttach with noop manager = nil error, want error")
	}
}

func TestUpdateVMMConfigPreservesWardenCountdown(t *testing.T) {
	h := newTestHandler()
	h.vmmCfg.WardenCountdownSec = 300

	h.UpdateVMMConfig(vmm.Config{MemoryMB: 512})
	h.mu.RLock()
	got := h.vmmCfg
	h.mu.RUnlock()
	if got.MemoryMB != 512 {
		t.Errorf("MemoryMB = %d, want 512", got.MemoryMB)
	}
	if got.WardenCountdownSec != 300 {
		t.Errorf("WardenCountdownSec = %d, want 300 (preserved)", got.WardenCountdownSec)
	}

	h.UpdateVMMConfig(vmm.Config{MemoryMB: 1024, WardenCountdownSec: 600})
	h.mu.RLock()
	got = h.vmmCfg
	h.mu.RUnlock()
	if got.WardenCountdownSec != 600 {
		t.Errorf("WardenCountdownSec = %d, want 600 (explicit)", got.WardenCountdownSec)
	}
}

func TestActiveVMsAndVMInfoList(t *testing.T) {
	h := newTestHandler()
	addTestVM(h, "vm-a", "small", false)
	addTestVM(h, "vm-b", "large", false)

	n, ids := h.ActiveVMs()
	if n != 2 || len(ids) != 2 {
		t.Fatalf("ActiveVMs = (%d, %v), want (2, 2 ids)", n, ids)
	}
	seen := map[string]bool{}
	for _, id := range ids {
		seen[id] = true
	}
	if !seen["vm-a"] || !seen["vm-b"] {
		t.Errorf("ids = %v, missing entries", ids)
	}

	infos := h.VMInfoList()
	specs := map[string]string{}
	for _, info := range infos {
		specs[info.VmId] = info.SpecId
	}
	if specs["vm-a"] != "small" || specs["vm-b"] != "large" {
		t.Errorf("VMInfoList specs = %v, want vm-a=small vm-b=large", specs)
	}
}

func TestVmStateLookup(t *testing.T) {
	h := newTestHandler()
	addTestVM(h, "vm-a", "small", false)
	if h.vmState("vm-a") == nil {
		t.Error("vmState(vm-a) = nil, want state")
	}
	if h.vmState("missing") != nil {
		t.Error("vmState(missing) != nil, want nil")
	}
}

func TestBindUnbindSandfs(t *testing.T) {
	h := newTestHandler()
	addTestVM(h, "vm-a", "small", false)

	h.bindSandfs("sfs-1", "vm-a")
	if h.vmForSandfs("sfs-1") == nil {
		t.Fatal("vmForSandfs(sfs-1) = nil after bind")
	}

	h.mu.RLock()
	bound := h.vmBoundToLocked("vm-a")
	notBound := h.vmBoundToLocked("other")
	h.mu.RUnlock()
	if !bound || notBound {
		t.Errorf("vmBoundToLocked: vm-a=%v other=%v, want true/false", bound, notBound)
	}

	h.unbindSandfs("sfs-1")
	if h.vmForSandfs("sfs-1") != nil {
		t.Error("vmForSandfs(sfs-1) != nil after unbind")
	}

	h.mu.RLock()
	stillBound := h.vmBoundToLocked("vm-a")
	h.mu.RUnlock()
	if stillBound {
		t.Error("vm-a still bound after unbindSandfs")
	}

	h.clearAllBindings()
	n := h.bindings.len()
	if n != 0 {
		t.Errorf("bindings len = %d after clearAllBindings, want 0", n)
	}
}

func TestBindSandfsEmptyDeletes(t *testing.T) {
	h := newTestHandler()
	h.bindSandfs("sfs-1", "vm-a")
	h.bindSandfs("sfs-1", "")
	if _, ok := h.bindings.lookup("sfs-1"); ok {
		t.Error("binding still present after bindSandfs with empty vmID")
	}
}

func TestClearBindingsForVM(t *testing.T) {
	h := newTestHandler()
	addTestVM(h, "vm-a", "small", false)
	addTestVM(h, "vm-b", "small", false)
	h.bindSandfs("sfs-1", "vm-a")
	h.bindSandfs("sfs-2", "vm-a")
	h.bindSandfs("sfs-3", "vm-b")

	h.clearBindingsForVM("vm-a")

	for _, sfs := range []string{"sfs-1", "sfs-2"} {
		if h.vmForSandfs(sfs) != nil {
			t.Errorf("%s still bound after clearBindingsForVM(vm-a)", sfs)
		}
	}
	if h.vmForSandfs("sfs-3") == nil {
		t.Error("sfs-3 binding removed by clearBindingsForVM(vm-a)")
	}
}

func TestResolveVMForMount(t *testing.T) {
	t.Run("no vms returns nil", func(t *testing.T) {
		h := newTestHandler()
		if st := h.resolveVMForMount("sfs-1", "", "agent-test"); st != nil {
			t.Errorf("resolveVMForMount with no VMs = %+v, want nil", st)
		}
	})

	t.Run("warm path reuses bound vm", func(t *testing.T) {
		h := newTestHandler()
		st := addTestVM(h, "vm-a", "medium", false)
		h.bindSandfs("sfs-1", "vm-a")
		got := h.resolveVMForMount("sfs-1", "", "agent-test")
		if got != st {
			t.Errorf("warm path returned different state, want bound vm-a")
		}
	})

	t.Run("stale binding rebinding to clean vm", func(t *testing.T) {
		h := newTestHandler()
		st := addTestVM(h, "vm-a", "medium", false)
		h.bindSandfs("sfs-1", "vm-gone")
		got := h.resolveVMForMount("sfs-1", "", "agent-test")
		if got != st {
			t.Fatalf("expected rebind to vm-a, got %v", got)
		}
		vmID, _ := h.bindings.lookup("sfs-1")
		if vmID != "vm-a" {
			t.Errorf("binding = %q, want vm-a", vmID)
		}
	})

	t.Run("bound vm pending destroy falls back", func(t *testing.T) {
		h := newTestHandler()
		old := addTestVM(h, "vm-old", "medium", false)
		old.pendingDestroy.Store(true)
		fresh := addTestVM(h, "vm-new", "medium", false)
		h.bindSandfs("sfs-1", "vm-old")
		got := h.resolveVMForMount("sfs-1", "", "agent-test")
		if got != fresh {
			t.Errorf("expected fallback to vm-new, got %v", got)
		}
	})

	t.Run("best fit smallest satisfying spec wins", func(t *testing.T) {
		h := newTestHandler()
		small := addTestVM(h, "vm-small", "small", false)
		addTestVM(h, "vm-large", "large", false)
		got := h.resolveVMForMount("sfs-1", "", "agent-test")
		if got != small {
			t.Errorf("best-fit picked %v, want vm-small", got)
		}
	})

	t.Run("min spec filters candidates", func(t *testing.T) {
		h := newTestHandler()
		large := addTestVM(h, "vm-large", "large", false)
		got := h.resolveVMForMount("sfs-1", "large", "agent-test")
		if got != large {
			t.Errorf("minSpec=large picked %v, want vm-large", got)
		}
	})

	t.Run("no candidate satisfies min spec", func(t *testing.T) {
		h := newTestHandler()
		addTestVM(h, "vm-medium", "medium", false)
		if st := h.resolveVMForMount("sfs-1", "large", "agent-test"); st != nil {
			t.Errorf("resolveVMForMount(minSpec=large) = %v, want nil", st)
		}
	})

	t.Run("bound vms are excluded from cold path", func(t *testing.T) {
		h := newTestHandler()
		addTestVM(h, "vm-a", "medium", false)
		h.bindSandfs("sfs-other", "vm-a")
		if st := h.resolveVMForMount("sfs-new", "", "agent-test"); st != nil {
			t.Errorf("bound VM selected for new sandfs: %v", st)
		}
	})
}

func TestSpecSatisfiesAndRank(t *testing.T) {
	tests := []struct {
		vmSpec, req string
		want        bool
	}{
		{"small", "small", true},
		{"medium", "small", true},
		{"large", "small", true},
		{"small", "medium", false},
		{"medium", "large", false},
		{"", "", true},
		{"unknown", "medium", true},
		{"medium", "unknown", true},
	}
	for _, tt := range tests {
		if got := specSatisfies(tt.vmSpec, tt.req); got != tt.want {
			t.Errorf("specSatisfies(%q, %q) = %v, want %v", tt.vmSpec, tt.req, got, tt.want)
		}
	}

	ranks := map[string]int{"small": 0, "medium": 1, "large": 2, "": 1, "weird": 1}
	for spec, want := range ranks {
		if got := specRank(spec); got != want {
			t.Errorf("specRank(%q) = %d, want %d", spec, got, want)
		}
	}
}

func TestSpecCapacityList(t *testing.T) {
	h := newTestHandler()
	addTestVM(h, "vm-small", "small", false)
	busy := addTestVM(h, "vm-medium", "medium", false)
	addTestVM(h, "vm-large", "large", false)
	busy.pendingDestroy.Store(false)
	h.bindSandfs("sfs-1", "vm-medium")
	pending := addTestVM(h, "vm-pending", "large", false)
	pending.pendingDestroy.Store(true)

	caps := h.SpecCapacityList()
	got := map[string]*pb.SpecCapacity{}
	for _, c := range caps {
		got[c.SpecId] = c
	}
	sc := got["small"]
	if sc == nil || sc.Total != 1 || sc.Clean != 1 {
		t.Errorf("small capacity = %+v, want total=1 clean=1", sc)
	}
	mc := got["medium"]
	if mc == nil || mc.Total != 1 || mc.Clean != 0 {
		t.Errorf("medium capacity = %+v, want total=1 clean=0", mc)
	}
	if c, ok := got["large"]; ok && c.Total != 1 {
		t.Errorf("pendingDestroy VM counted: %+v", c)
	}
	for spec, c := range got {
		if c.MinCleanWindow != c.Total {
			t.Errorf("%s MinCleanWindow = %d, want %d (empty window fallback)", spec, c.MinCleanWindow, c.Total)
		}
	}
}

func TestSpecCapacityListUsesMetricsWindow(t *testing.T) {
	h := newTestHandler()
	addTestVM(h, "vm-medium", "medium", false)
	h.metrics.Tick(1, 0, 0, map[string]uint32{"medium": 1}, 0, 0)

	caps := h.SpecCapacityList()
	if len(caps) != 1 {
		t.Fatalf("caps len = %d, want 1", len(caps))
	}
	c := caps[0]
	if c.SpecId != "medium" || c.Clean != 1 || c.Total != 1 {
		t.Errorf("capacity = %+v, want medium clean=1 total=1", c)
	}
	if c.MinCleanWindow != 1 || c.ZeroCleanCount != 0 {
		t.Errorf("window = min_clean=%d zeros=%d, want 1/0", c.MinCleanWindow, c.ZeroCleanCount)
	}
}

func TestTickMetricsSnapshot(t *testing.T) {
	h := newTestHandler()
	st := addTestVM(h, "vm-a", "medium", false)
	setBgExecs(st, 2)
	addTestVM(h, "vm-b", "small", false)
	h.bindSandfs("sfs-1", "vm-a")

	h.TickMetrics()
	snap := h.MetricsSnapshot()
	if snap.TotalVms != 2 {
		t.Errorf("TotalVms = %d, want 2", snap.TotalVms)
	}
	if snap.ActiveSandfs != 1 {
		t.Errorf("ActiveSandfs = %d, want 1", snap.ActiveSandfs)
	}
	if snap.ActiveBgExecs != 2 {
		t.Errorf("ActiveBgExecs = %d, want 2", snap.ActiveBgExecs)
	}
}

func TestTickMetricsPendingDestroyNotClean(t *testing.T) {
	h := newTestHandler()
	st := addTestVM(h, "vm-a", "medium", false)
	st.pendingDestroy.Store(true)

	h.TickMetrics()
	windows := h.metrics.Snapshot().SpecWindows
	w, ok := windows["medium"]
	if !ok {
		t.Fatal("medium window missing after TickMetrics")
	}
	if w[0] != 0 {
		t.Errorf("min_clean_window = %d, want 0 (only VM is pendingDestroy)", w[0])
	}
}

func TestSendEventWithoutClientDrops(t *testing.T) {
	h := newTestHandler()
	h.sendEvent(&pb.VMEvent{VmId: "vm-a", Type: pb.VMEventType_VM_EVENT_CRASHED})
	h.SetClient(nil)
	h.sendEvent(&pb.VMEvent{VmId: "vm-a"})
}

func TestCIDWrappers(t *testing.T) {
	h := newTestHandler()

	h.SetNextCID(2)
	if cid := h.AllocateCID(); cid != 3 {
		t.Errorf("AllocateCID after SetNextCID(2) = %d, want 3 (<3 ignored)", cid)
	}

	h.SetNextCID(10)
	if cid := h.AllocateCID(); cid != 11 {
		t.Errorf("AllocateCID after SetNextCID(10) = %d, want 11 (counter pre-increments)", cid)
	}

	h.ReleaseCID(10)
	if cid := h.AllocateCID(); cid != 10 {
		t.Errorf("AllocateCID after ReleaseCID(10) = %d, want 10 (free-list reuse)", cid)
	}
}

// TestCID_AllocateClaimsNoConflict pins the no-double-allocation invariant:
// from the moment AllocateCID returns, the CID is claimed (cidUsed) and can
// never be handed out again until it is released. Allocation must mark the
// claim explicitly — an allocated-but-unmarked CID would let a concurrent
// reserve/reuse path hand the same CID to two VMs.
func TestCID_AllocateClaimsNoConflict(t *testing.T) {
	h := newTestHandler()
	seen := make(map[uint32]bool)
	for i := 0; i < 50; i++ {
		cid := h.AllocateCID()
		if cid == 0 {
			t.Fatalf("allocation %d returned 0 (exhausted?)", i)
		}
		if seen[cid] {
			t.Fatalf("allocation %d returned CID %d twice — double allocation", i, cid)
		}
		seen[cid] = true
		h.mu.Lock()
		claimed := h.cidUsed[cid]
		h.mu.Unlock()
		if !claimed {
			t.Fatalf("allocation %d: CID %d was not marked claimed", i, cid)
		}
	}
}

// TestCID_ReleaseFreesExactlyOnce pins the release side of the same invariant:
// a released CID is unclaimed and reusable; a CID that was never allocated
// cannot be smuggled into the free-list in a way that conflicts with a live
// claim.
func TestCID_ReleaseFreesExactlyOnce(t *testing.T) {
	h := newTestHandler()
	cid := h.AllocateCID()

	h.mu.Lock()
	claimedBefore := h.cidUsed[cid]
	h.mu.Unlock()
	if !claimedBefore {
		t.Fatal("precondition: allocated CID should be claimed")
	}

	h.releaseCID(cid)
	h.mu.Lock()
	stillClaimed := h.cidUsed[cid]
	freeLen := len(h.cidFree)
	h.mu.Unlock()
	if stillClaimed {
		t.Error("CID still claimed after release")
	}
	if freeLen != 1 {
		t.Errorf("free-list len = %d after one release, want 1", freeLen)
	}

	// Double release must not duplicate the free-list entry.
	h.releaseCID(cid)
	h.mu.Lock()
	freeLen = len(h.cidFree)
	h.mu.Unlock()
	if freeLen != 1 {
		t.Errorf("free-list len = %d after double release, want 1", freeLen)
	}

	// The released CID must be reusable, and only once before being held again.
	re1 := h.AllocateCID()
	re2 := h.AllocateCID()
	if re1 != cid {
		t.Errorf("first realloc = %d, want %d (free-list reuse)", re1, cid)
	}
	if re2 == re1 {
		t.Errorf("second realloc = %d, equals the just-reallocated CID", re2)
	}
}

// TestCID_ReleaseUnclaimedNoop pins that releasing CID 0 (below the guest
// minimum) is a no-op, and that a stray release of a never-allocated but valid
// CID stays conflict-free: nobody else could hold it (the counter never reached
// it), so free-listing it is safe early reuse, not a double allocation.
func TestCID_ReleaseUnclaimedNoop(t *testing.T) {
	h := newTestHandler()
	h.releaseCID(0) // below min — ignored entirely
	h.mu.Lock()
	freeLen := len(h.cidFree)
	h.mu.Unlock()
	if freeLen != 0 {
		t.Errorf("free-list len = %d after releasing 0, want 0 (ignored)", freeLen)
	}
	if got := h.AllocateCID(); got != 3 {
		t.Errorf("allocation after stray release of 0 = %d, want 3", got)
	}

	// A stray release of a valid unclaimed CID may be reused early — safe,
	// since no live VM can hold it.
	h.releaseCID(99)
	if got := h.AllocateCID(); got != 99 {
		t.Errorf("allocation after stray release of 99 = %d, want 99 (harmless early reuse)", got)
	}
}

// TestSetFsTimeoutOutlivesVMMUpdateWindow pins the cross-component timing
// invariant behind the set-fs timeout: the VMM's set-fs timeout is 10 s and is
// authoritative (it cancels the queued update). The sandlot must wait past it
// so that decision reaches us before we give up.
func TestSetFsTimeoutOutlivesVMMUpdateWindow(t *testing.T) {
	if setFsTimeout <= 10*time.Second {
		t.Fatalf("setFsTimeout = %v, must exceed the VMM's 10s set-fs update window", setFsTimeout)
	}
}

func TestSetFsAllowedDirsNilClientIsNoop(t *testing.T) {
	if err := setFsAllowedDirs(context.Background(), nil, []string{"/vol/a"}, "gen0"); err != nil {
		t.Errorf("setFsAllowedDirs(nil client) = %v, want nil", err)
	}
}

// TestBoundVMsReverseIndexInvariant drives every binding mutation through its
// helper and asserts the boundVMs reverse index stays exactly equivalent to a
// full scan of bindings — the invariant vmBoundToLocked's O(1) lookup relies on.
func TestBoundVMsReverseIndexInvariant(t *testing.T) {
	h := newTestHandler()
	for i := 0; i < 5; i++ {
		id := fmt.Sprintf("vm-%d", i)
		h.mu.Lock()
		h.vms[id] = &VMState{VM: &vmm.RunningVM{ID: id, GuestCID: uint32(10 + i)}}
		h.mu.Unlock()
	}

	ops := []struct{ sandfs, vm string }{
		{"sfs-a", "vm-0"}, {"sfs-b", "vm-1"}, {"sfs-c", "vm-2"},
		{"sfs-a", ""},           // unbind via empty vmID
		{"sfs-b", "vm-3"},       // rebind to another VM
		{"sfs-d", "vm-0"},       // reuse a VM after its unbind
		{"sfs-nonexistent", ""}, // unbind of an absent entry
		{"sfs-e", "vm-4"},
	}
	check := func(stage string) {
		t.Helper()
		for id := range h.vms {
			want := false
			if sfs, ok := h.bindings.vmBound(id); ok {
				if cur, _ := h.bindings.lookup(sfs); cur == id {
					want = true
				}
			}
			if got := h.vmBoundToLocked(id); got != want {
				t.Fatalf("%s: vmBoundToLocked(%s) = %v, want %v (reverse index desync)", stage, id, got, want)
			}
		}
		for sfs := range map[string]struct{}{"sfs-a": {}, "sfs-b": {}, "sfs-c": {}, "sfs-d": {}, "sfs-e": {}, "sfs-f": {}} {
			if vm, ok := h.bindings.lookup(sfs); ok {
				if cur, _ := h.bindings.vmBound(vm); cur != sfs {
					t.Fatalf("%s: binding %s->%s has no reverse index entry", stage, sfs, vm)
				}
			}
		}
	}
	for i, op := range ops {
		h.bindSandfs(op.sandfs, op.vm)
		check(fmt.Sprintf("after bindSandfs op %d", i))
	}
	h.unbindSandfs("sfs-c")
	check("after unbindSandfs")
	h.clearBindingsForVM("vm-3")
	check("after clearBindingsForVM")
	h.bindSandfs("sfs-f", "vm-1")
	check("after rebind")
	h.clearAllBindings()
	check("after clearAllBindings")
	if n := h.bindings.len(); n != 0 {
		t.Fatalf("clearAllBindings left bindings=%d", n)
	}
	for id := range h.vms {
		if _, ok := h.bindings.vmBound(id); ok {
			t.Fatalf("clearAllBindings left VM %s occupied", id)
		}
	}
}

// setFsTripwireRetry: a tripwire refusal gets exactly ONE retry (absorbing
// in-flight FORGET lag), a persistent refusal is returned for the caller's
// dirty-destroy path, and non-tripwire errors never retry.
func TestSetFsTripwireRetry(t *testing.T) {
	calls := 0
	err := setFsTripwireRetry(func() error {
		calls++
		return errors.New("sandvmm raw op 1 failed: previous-tenant-refs: open handles = 0, unforgotten inode refs = 2")
	}, 0)
	if err == nil || !vmm.IsPreviousTenantRefs(err) {
		t.Fatalf("persistent refusal must surface, got %v", err)
	}
	if calls != 2 {
		t.Fatalf("tripwire refusal must retry exactly once, got %d calls", calls)
	}

	calls = 0
	err = setFsTripwireRetry(func() error {
		calls++
		if calls == 1 {
			return errors.New("previous-tenant-refs: transient FORGET lag")
		}
		return nil
	}, 0)
	if err != nil {
		t.Fatalf("clean second attempt must succeed, got %v", err)
	}
	if calls != 2 {
		t.Fatalf("expected 2 calls, got %d", calls)
	}

	calls = 0
	other := errors.New("sandvmm raw op 1 failed: failed to init filter list: boom")
	err = setFsTripwireRetry(func() error {
		calls++
		return other
	}, 0)
	if err != other || calls != 1 {
		t.Fatalf("non-tripwire error must not retry (calls=%d)", calls)
	}
}

// TestResolveVMForMountPrefersBelowRecycleThreshold pins the cold-selection
// half of the dual-counter recycle rule: a VM below either threshold wins over
// one at the cap. The at-cap VM is a LAST RESORT when it is the only clean
// candidate — a clean VM has no unmount coming to trigger its recycle, so
// excluding it outright would strand a pool whose threshold was lowered by a
// hot-reload (the normal unmount recycle then runs after that one mount).
func TestResolveVMForMountPrefersBelowRecycleThreshold(t *testing.T) {
	h := newTestHandler()
	h.recycleMaxMounts.Store(1)
	capVM := &VMState{VM: &vmm.RunningVM{ID: "vm-cap", GuestCID: 1 << 20}, SpecID: "small"}
	capVM.mountCount.Store(1)
	freshVM := &VMState{VM: &vmm.RunningVM{ID: "vm-fresh", GuestCID: 2 << 20}, SpecID: "small"}
	h.vms[capVM.VM.ID] = capVM
	h.vms[freshVM.VM.ID] = freshVM

	if got := h.resolveVMForMount("sf-x", "", "agent-a"); got == nil || got.VM.ID != "vm-fresh" {
		t.Fatalf("selection must prefer the VM below the cap, got %v", got)
	}
	delete(h.vms, freshVM.VM.ID)
	if got := h.resolveVMForMount("sf-y", "", "agent-a"); got == nil || got.VM.ID != "vm-cap" {
		t.Fatalf("the at-cap VM must be the last-resort candidate, got %v", got)
	}
}

// TestClearBindingsForVMsOnlyVerified pins the reset rule: only VMs whose
// cleanup was verified complete may lose their bindings; an unfinished VM
// keeps its binding so the destroy path still sees its mount.
func TestClearBindingsForVMsOnlyVerified(t *testing.T) {
	h := newTestHandler()
	h.bindSandfs("sf-a", "vm-a")
	h.bindSandfs("sf-b", "vm-b")

	h.clearBindingsForVMs(map[string]struct{}{"vm-a": {}})
	if _, ok := h.bindings.lookup("sf-a"); ok {
		t.Fatal("verified VM's binding was not cleared")
	}
	if got, _ := h.bindings.lookup("sf-b"); got != "vm-b" {
		t.Fatalf("unverified VM's binding was cleared (got %q)", got)
	}
	if _, ok := h.bindings.vmBound("vm-b"); !ok {
		t.Fatal("unverified VM's occupancy entry was removed")
	}
}

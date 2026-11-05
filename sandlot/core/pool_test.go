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
	"strings"
	"testing"

	"sandlot/vmm"
)

func TestEffectivePoolTargetDisabled(t *testing.T) {
	h := newTestHandler()
	// Default floor = 0 (disabled): effective == raw target.
	h.UpdateRecycleConfig(50, 10, 100, 0)
	for _, target := range []int{0, 1, 5, 100} {
		if got := h.effectivePoolTarget(target); got != target {
			t.Errorf("effectivePoolTarget(%d) with floor disabled = %d, want %d", target, got, target)
		}
	}
}

func TestEffectivePoolTargetFloor(t *testing.T) {
	h := newTestHandler()
	h.UpdateRecycleConfig(50, 10, 100, 0.05) // 5%
	cases := []struct {
		target, want int
	}{
		{0, 0},   // no target -> no expansion
		{1, 2},   // floor = max(1, floor(0.05)) = 1 -> 1+1
		{5, 6},   // floor = floor(0.25) = 0 -> max(1,...) = 1 -> 5+1
		{20, 21}, // floor = floor(1.0) = 1 -> 20+1
		{40, 42}, // floor = floor(2.0) = 2 -> 40+2
		{100, 105},
	}
	for _, c := range cases {
		if got := h.effectivePoolTarget(c.target); got != c.want {
			t.Errorf("effectivePoolTarget(%d) at 5%% = %d, want %d", c.target, got, c.want)
		}
	}
}

func TestEffectivePoolTargetClamp(t *testing.T) {
	h := newTestHandler()
	// Negative clamps to 0 (disabled).
	h.UpdateRecycleConfig(50, 10, 100, -0.5)
	if got := h.effectivePoolTarget(10); got != 10 {
		t.Errorf("effectivePoolTarget(10) with negative frac = %d, want 10 (disabled)", got)
	}
	// >1.0 clamps to 1.0 (floor == target).
	h.UpdateRecycleConfig(50, 10, 100, 2.0)
	if got := h.effectivePoolTarget(10); got != 20 {
		t.Errorf("effectivePoolTarget(10) with frac>1 = %d, want 20 (clamped to 1.0)", got)
	}
}

// TestShouldRecycleMemThresholds covers the min()-combination of the percent
// and absolute memory recycle thresholds across VM sizes. With pct=10 and
// abs=100MB:
//
//   - 128MB VM:  min(12.8MB, 100MB) = 12.8MB   (abs must NOT dominate — the
//     old max() logic put such VMs in permanent recycle state)
//   - 128GB VM:  min(12.8GB, 100MB) = 100MB    (pct must NOT dominate —
//     recycling while ~12.8GB is still free is unreasonable)
//   - 4GB VM:    min(409.6MB, 100MB) = 100MB
func TestShouldRecycleMemThresholds(t *testing.T) {
	h := newTestHandler()
	h.UpdateRecycleConfig(0 /*maxUses off*/, 10, 100, 0)

	mib := uint64(1024 * 1024)
	cases := []struct {
		name        string
		totalBytes  uint64
		availBytes  uint64
		wantRecycle bool
	}{
		// 128MB VM: threshold = 12.8MB (pct wins).
		{"small-avail-below-pct", 128 * mib, 10 * mib, true},
		{"small-avail-above-pct", 128 * mib, 20 * mib, false},
		// 90MB avail on a 128MB VM used to force-recycle via abs=100MB; now it's fine.
		{"small-mostly-free", 128 * mib, 90 * mib, false},
		// 4GB VM: threshold = 100MB (abs wins).
		{"mid-avail-below-abs", 4096 * mib, 50 * mib, true},
		{"mid-avail-above-abs", 4096 * mib, 200 * mib, false},
		// 128GB VM: threshold = 100MB (abs caps the 12.8GB pct threshold).
		{"large-avail-below-abs", 128 * 1024 * mib, 50 * mib, true},
		{"large-avail-under-pct-but-over-abs", 128 * 1024 * mib, 500 * mib, false},
	}
	for _, c := range cases {
		vm := &VMState{}
		vm.memTotal.Store(c.totalBytes)
		vm.memAvail.Store(c.availBytes)
		if got := h.shouldRecycle(vm); got != c.wantRecycle {
			t.Errorf("%s: shouldRecycle(total=%dMB avail=%dMB) = %v, want %v",
				c.name, c.totalBytes/mib, c.availBytes/mib, got, c.wantRecycle)
		}
	}

	// Sanity cap: pct disabled + abs >= MemTotal would put a small VM in
	// permanent recycle state; the threshold clamps to MemTotal/2 (64MB here).
	hCap := newTestHandler()
	hCap.UpdateRecycleConfig(0 /*maxUses off*/, 0 /*pct off*/, 100, 0)
	capCases := []struct {
		name        string
		availBytes  uint64
		wantRecycle bool
	}{
		{"abs-clamped-70mb-free", 70 * mib, false},
		{"abs-clamped-60mb-free", 60 * mib, true},
	}
	for _, c := range capCases {
		vm := &VMState{}
		vm.memTotal.Store(128 * mib)
		vm.memAvail.Store(c.availBytes)
		if got := hCap.shouldRecycle(vm); got != c.wantRecycle {
			t.Errorf("%s: shouldRecycle(total=128MB avail=%dMB) = %v, want %v",
				c.name, c.availBytes/mib, got, c.wantRecycle)
		}
	}
}

func TestShouldRecycleDisabledAndMissingData(t *testing.T) {
	mib := uint64(1024 * 1024)

	// Both mem knobs disabled → never recycle on memory.
	h := newTestHandler()
	h.UpdateRecycleConfig(0, 0, 0, 0)
	vm := &VMState{}
	vm.memTotal.Store(128 * mib)
	vm.memAvail.Store(1 * mib)
	if h.shouldRecycle(vm) {
		t.Error("shouldRecycle with both thresholds disabled = true, want false")
	}

	// No heartbeat sample yet (memAvail==0) → don't recycle on missing data.
	h2 := newTestHandler()
	h2.UpdateRecycleConfig(0, 10, 100, 0)
	vm2 := &VMState{}
	vm2.memTotal.Store(128 * mib)
	if h2.shouldRecycle(vm2) {
		t.Error("shouldRecycle with memAvail==0 = true, want false")
	}

	// maxUses still triggers independently of memory.
	h3 := newTestHandler()
	h3.UpdateRecycleConfig(5, 10, 100, 0)
	vm3 := &VMState{}
	vm3.useCount.Store(5)
	if !h3.shouldRecycle(vm3) {
		t.Error("shouldRecycle at useCount==maxUses = false, want true")
	}
}

func TestShouldRecycleMaxUsesUnlimited(t *testing.T) {
	mib := uint64(1024 * 1024)

	// -1 is the "unlimited" sentinel: no use count ever recycles, while the
	// memory thresholds keep working (the sentinel only disables the
	// use-count trigger, not the whole recycle decision).
	h := newTestHandler()
	h.UpdateRecycleConfig(-1, 0, 0, 0)
	vm := &VMState{}
	vm.useCount.Store(1 << 40) // far beyond any plausible limit
	vm.memTotal.Store(128 * mib)
	vm.memAvail.Store(128 * mib)
	if h.shouldRecycle(vm) {
		t.Error("shouldRecycle with maxUses=-1 and huge useCount = true, want false (unlimited)")
	}

	// Memory trigger still fires under the -1 sentinel.
	h2 := newTestHandler()
	h2.UpdateRecycleConfig(-1, 10, 100, 0)
	vm2 := &VMState{}
	vm2.useCount.Store(1 << 40)
	vm2.memTotal.Store(128 * mib)
	vm2.memAvail.Store(1 * mib)
	if !h2.shouldRecycle(vm2) {
		t.Error("shouldRecycle with maxUses=-1 and low MemAvailable = false, want true (memory threshold active)")
	}
}

// SPDX-License-Identifier: Apache-2.0

func TestParsePoolSeq(t *testing.T) {
	tests := []struct {
		vmID   string
		prefix string
		want   int
		ok     bool
	}{
		{"pool-medium-5", "", 5, true},
		{"pool-small-0", "", 0, true},
		{"sl1-pool-medium-7", "sl1-", 7, true},
		{"pool-high-mem-3", "", 3, true},
		{"vm-adhoc-1", "", 0, false},
		{"pool-medium", "", 0, false},
		{"pool-medium-x", "", 0, false},
		{"pool-medium-", "", 0, false},
	}
	for _, tt := range tests {
		got, ok := parsePoolSeq(tt.vmID, tt.prefix)
		if ok != tt.ok || got != tt.want {
			t.Errorf("parsePoolSeq(%q, %q) = (%d, %v), want (%d, %v)", tt.vmID, tt.prefix, got, ok, tt.want, tt.ok)
		}
	}
}

func TestAdvancePoolSeq(t *testing.T) {
	h := newTestHandler()
	addTestVM(h, "pool-medium-7", "medium", false)
	addTestVM(h, "pool-small-12", "small", false)
	addTestVM(h, "vm-adhoc", "", false)

	h.AdvancePoolSeq()

	h.mu.Lock()
	seq := h.nextPoolSeq
	h.mu.Unlock()
	if seq != 13 {
		t.Errorf("nextPoolSeq = %d, want 13 (max existing pool seq + 1)", seq)
	}
}

func TestAdvancePoolSeqWithPrefix(t *testing.T) {
	h := newTestHandler()
	h.SetPoolVMIDPrefix("sl1-")
	addTestVM(h, "sl1-pool-large-4", "large", false)

	h.AdvancePoolSeq()

	h.mu.Lock()
	seq := h.nextPoolSeq
	h.mu.Unlock()
	if seq != 5 {
		t.Errorf("nextPoolSeq = %d, want 5", seq)
	}
}

func TestPoolPrefixSetters(t *testing.T) {
	h := newTestHandler()
	if got := h.PoolVMIDPrefix(); got != "" {
		t.Errorf("default prefix = %q, want empty", got)
	}
	h.SetPoolVMIDPrefix("node9-")
	if got := h.PoolVMIDPrefix(); got != "node9-" {
		t.Errorf("prefix = %q, want node9-", got)
	}
}

func TestSetPoolSpecsAndCountVMsBySpec(t *testing.T) {
	h := newTestHandler()
	addTestVM(h, "pool-small-0", "small", false)
	addTestVM(h, "pool-small-1", "small", false)
	addTestVM(h, "pool-medium-0", "medium", false)

	if got := h.countVMsBySpec("small"); got != 2 {
		t.Errorf("countVMsBySpec(small) = %d, want 2", got)
	}
	if got := h.countVMsBySpec("medium"); got != 1 {
		t.Errorf("countVMsBySpec(medium) = %d, want 1", got)
	}
	if got := h.countVMsBySpec("large"); got != 0 {
		t.Errorf("countVMsBySpec(large) = %d, want 0", got)
	}

	specRes := map[string]SpecResources{"small": {VCPUs: 1, MemoryMB: 256}}
	h.SetPoolSpecs(map[string]int{"small": 2}, specRes)
	h.mu.RLock()
	specs := h.poolSpecs
	res := h.specResources
	h.mu.RUnlock()
	if specs["small"] != 2 || res["small"].MemoryMB != 256 {
		t.Errorf("SetPoolSpecs did not store state: %v / %v", specs, res)
	}
}

func TestResizePoolNoChangeNeeded(t *testing.T) {
	h, poolChanged := newTestHandlerWithPool()
	addTestVM(h, "pool-small-0", "small", false)

	h.ResizePool(map[string]int{"small": 1}, map[string]SpecResources{
		"small": {VCPUs: 1, MemoryMB: 256},
	})

	if n := poolChanged.Load(); n != 1 {
		t.Errorf("OnPoolChanged fired %d times, want 1", n)
	}
	if got := h.countVMsBySpec("small"); got != 1 {
		t.Errorf("countVMsBySpec(small) = %d, want 1", got)
	}
}

func TestResizePoolClearsStalePendingDestroy(t *testing.T) {
	h, _ := newTestHandlerWithPool()
	st := addTestVM(h, "pool-small-0", "small", false)
	st.pendingDestroy.Store(true)

	h.ResizePool(map[string]int{"small": 1}, map[string]SpecResources{
		"small": {VCPUs: 1, MemoryMB: 256},
	})

	if st.pendingDestroy.Load() {
		t.Error("pendingDestroy not cleared by ResizePool")
	}
}

func TestResizePoolMarksBusyVMPendingDestroy(t *testing.T) {
	h, _ := newTestHandlerWithPool()
	st := addTestVM(h, "pool-small-0", "small", true)

	h.ResizePool(map[string]int{"small": 0}, map[string]SpecResources{
		"small": {VCPUs: 1, MemoryMB: 256},
	})

	if !st.pendingDestroy.Load() {
		t.Error("excess busy VM not marked pendingDestroy by scale-down")
	}
	if h.countVMsBySpec("small") != 1 {
		t.Error("busy VM should be kept until its next unmount")
	}
}

func TestResizePoolUnknownSpecSkipped(t *testing.T) {
	h, poolChanged := newTestHandlerWithPool()
	h.ResizePool(map[string]int{"gold": 2}, nil)
	if n := poolChanged.Load(); n != 1 {
		t.Errorf("OnPoolChanged fired %d times, want 1", n)
	}
	if got := h.countVMsBySpec("gold"); got != 0 {
		t.Errorf("countVMsBySpec(gold) = %d, want 0", got)
	}
}

func TestReconcilePoolEmptySpecsIsNoop(t *testing.T) {
	h := newTestHandler()
	h.ReconcilePool()
	if got := h.countVMsBySpec(""); got != 0 {
		t.Errorf("ReconcilePool with no specs created %d VMs, want 0", got)
	}
}

func TestReconcilePoolCreateFailureRetriesLater(t *testing.T) {
	h := newTestHandler()
	h.SetPoolSpecs(
		map[string]int{"small": 2},
		map[string]SpecResources{"small": {VCPUs: 1, MemoryMB: 256}},
	)

	h.ReconcilePool()

	if got := h.countVMsBySpec("small"); got != 0 {
		t.Errorf("countVMsBySpec(small) = %d, want 0 (creation fails on noop manager, self-heal retries)", got)
	}
	h.mu.Lock()
	seq := h.nextPoolSeq
	cidUsed := len(h.cidUsed)
	h.mu.Unlock()
	if seq == 0 {
		t.Error("nextPoolSeq not advanced by failed create attempts")
	}
	// Leak check: whichever failure path fired (early memory-abort before the
	// CID is allocated, or a later launch failure), no CID may remain claimed.
	if cidUsed != 0 {
		t.Errorf("CID left reserved after failed create: %d in use", cidUsed)
	}
}

func TestCreatePoolVMInsufficientMemory(t *testing.T) {
	h := newTestHandler()
	h.createMu.Lock()
	defer h.createMu.Unlock()

	err := h.createPoolVM("small", SpecResources{VCPUs: 1, MemoryMB: 1 << 62})
	if err == nil {
		t.Fatal("createPoolVM with absurd memory = nil error, want ErrInsufficientMemory")
	}
	if !errors.Is(err, ErrInsufficientMemory) {
		t.Errorf("error = %v, want ErrInsufficientMemory", err)
	}

	h.mu.Lock()
	seq := h.nextPoolSeq
	h.mu.Unlock()
	if seq != 1 {
		t.Errorf("nextPoolSeq = %d, want 1 (seq consumed even on failure)", seq)
	}
}

func TestReadMemAvailableMB(t *testing.T) {
	mb, err := readMemAvailableMB()
	if err != nil {
		t.Skipf("/proc/meminfo unavailable: %v", err)
	}
	if mb == 0 {
		t.Error("readMemAvailableMB = 0, want > 0")
	}
}

// TestResizePoolScaleDownAlignsToFloor pins the floor's standing-pool
// semantics: scale-down destroys only down to the floor-EXPANDED target (the
// same effectivePoolTarget scale-up uses), so the 60s reconcile does not
// immediately re-create what the resize just destroyed.
func TestResizePoolScaleDownAlignsToFloor(t *testing.T) {
	h, _ := newTestHandlerWithPool()
	// Floor 0.5: target 2 -> effective 3.
	h.UpdateRecycleConfig(0, 0, 0, 0.5)
	for i := 0; i < 5; i++ {
		addTestVM(h, fmt.Sprintf("vm-%d", i), "small", false)
	}
	h.SetPoolSpecs(map[string]int{"small": 2}, map[string]SpecResources{
		"small": {VCPUs: 1, MemoryMB: 128},
	})
	h.ResizePool(map[string]int{"small": 2}, map[string]SpecResources{
		"small": {VCPUs: 1, MemoryMB: 128},
	})
	// 5 current, effTarget 3 -> exactly 2 destroyed, 3 kept (the raw-target
	// math would have destroyed 3 and left 2).
	if got := h.countVMsBySpec("small"); got != 3 {
		t.Errorf("after scale-down with floor: %d small VMs, want 3 (effTarget = target 2 + floor 1)", got)
	}
}

// TestNextPoolVMIDNeverCollidesWithGappedSurvivors pins the ID source for
// startup pre-creation: IDs come from the shared nextPoolSeq counter (advanced
// past every re-adopted survivor's seq at re-adopt), never from the survivor
// COUNT. A recycle/scale-down leaves holes in the survivor seq set, and the
// old "<count>+i" scheme re-landed on a LIVE seq — the collision unlinked the
// live VM's API socket and overwrote its registry entry.
func TestNextPoolVMIDNeverCollidesWithGappedSurvivors(t *testing.T) {
	h := newTestHandler()
	h.SetPoolVMIDPrefix("sl1-")

	// Simulate re-adopted survivors with GAPPED seqs {0, 2, 4} — exactly the
	// shape a recycle leaves behind. adoptReadoptedVM advances the counter
	// past each survivor's seq; AdvancePoolSeq does the same for map entries.
	for _, id := range []string{"sl1-pool-small-0", "sl1-pool-small-2", "sl1-pool-small-4"} {
		addTestVM(h, id, "small", false)
	}
	h.AdvancePoolSeq()

	live := map[string]bool{
		"sl1-pool-small-0": true,
		"sl1-pool-small-2": true,
		"sl1-pool-small-4": true,
	}
	seen := map[string]bool{}
	for i := 0; i < 10; i++ {
		id := h.NextPoolVMID("small")
		if live[id] {
			t.Fatalf("NextPoolVMID handed out %q — collides with a live re-adopted survivor", id)
		}
		if seen[id] {
			t.Fatalf("NextPoolVMID handed out %q twice", id)
		}
		seen[id] = true
	}
}

// TestCreateVerifiedVMRefusesDuplicateID pins the belt-and-braces guard: no
// creation path may register a VM under an ID that is already live — the
// registration would overwrite the existing entry (no teardown) and the
// derived sandbox/socket paths would collide with the live VM's.
func TestCreateVerifiedVMRefusesDuplicateID(t *testing.T) {
	h := newTestHandler()
	addTestVM(h, "pool-small-0", "small", false)

	_, err := h.CreateVerifiedVM(context.Background(), vmm.Config{ID: "pool-small-0", MemoryMB: 128}, "small")
	if err == nil {
		t.Fatal("CreateVerifiedVM accepted a duplicate live ID, want refusal")
	}
	if !strings.Contains(err.Error(), "already registered") {
		t.Errorf("refusal error = %q, want it to name the already-registered condition", err)
	}
}

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
	"io"
	"log"
	"testing"

	sandlotconfig "sandlot/config"
	"sandlot/vmm"
)

// newValidationHandler builds a Handler carrying the given min-idle floor, so
// ValidatePoolMemory's effective-target math matches what the runtime creates.
func newValidationHandler(t *testing.T, maxUses, memPct, memAbs int, floorFrac float64) *Handler {
	t.Helper()
	h := NewHandler(nil, vmm.Config{}, nil, nil, log.New(io.Discard, "", 0))
	h.UpdateRecycleConfig(maxUses, memPct, memAbs, floorFrac)
	return h
}

// --- ValidatePoolMemory: overcommit hard reject ---

func TestValidatePoolMemory_Accepts(t *testing.T) {
	// 2 medium VMs @ 256MB = 512MB total. Host 4096MB -> limit 3276MB. OK.
	pool := map[string]PoolEntry{
		"medium": {vcpus: 2, memMB: 256, count: 2},
	}
	h := newValidationHandler(t, 0, 0, 0, 0)
	if err := ValidatePoolMemory(h, pool, 4096); err != nil {
		t.Errorf("expected accept, got error: %v", err)
	}
}

func TestValidatePoolMemory_Rejects(t *testing.T) {
	// 10 large VMs @ 2048MB = 20480MB total. Host 4096MB -> limit 3276MB. Reject.
	pool := map[string]PoolEntry{
		"large": {vcpus: 4, memMB: 2048, count: 10},
	}
	h := newValidationHandler(t, 0, 0, 0, 0)
	if err := ValidatePoolMemory(h, pool, 4096); err == nil {
		t.Error("expected reject for overcommit, got nil")
	}
}

func TestValidatePoolMemory_EmptyPoolOK(t *testing.T) {
	pool := map[string]PoolEntry{}
	h := newValidationHandler(t, 0, 0, 0, 0)
	if err := ValidatePoolMemory(h, pool, 256); err != nil {
		t.Errorf("empty pool should always be accepted, got: %v", err)
	}
}

// TestValidatePoolMemory_FloorCounts: with a min-idle floor configured, the
// budget must cover the floor-expanded target (the pool the runtime actually
// creates and keeps), not the raw count — a raw-count check would silently
// oversubscribe by the floor extras.
func TestValidatePoolMemory_FloorCounts(t *testing.T) {
	// Raw: 4 × 500MB = 2000MB. Floor 0.25 → eff target 5 → 2500MB.
	// Host 2600MB → limit 80% = 2080MB: raw passes, effective must reject.
	pool := map[string]PoolEntry{
		"medium": {vcpus: 2, memMB: 500, count: 4},
	}
	hRaw := newValidationHandler(t, 0, 0, 0, 0)
	if err := ValidatePoolMemory(hRaw, pool, 2600); err != nil {
		t.Errorf("raw-count check should accept (2000MB < 2080MB), got: %v", err)
	}
	hFloor := newValidationHandler(t, 0, 0, 0, 0.25)
	if err := ValidatePoolMemory(hFloor, pool, 2600); err == nil {
		t.Error("floor-expanded check must reject (2500MB > 2080MB) — the floor VMs are really created")
	}
}

// --- ParsePoolSpec memory minimum ---

func TestParsePoolSpec_RejectsLowMemory(t *testing.T) {
	// A spec with memory below the minimum should be rejected.
	specs := map[string]sandlotconfig.SpecEntry{
		"tiny": {VCPUs: 1, MemoryMB: 16}, // below MinBootMemoryMB (64)
	}
	_, err := ParsePoolSpec("tiny:1", specs)
	if err == nil {
		t.Error("expected error for memory_mb below minimum, got nil")
	}
}

func TestParsePoolSpec_RejectsZeroVCPUs(t *testing.T) {
	// A zero-vCPU spec cannot boot — reject at parse time (startup AND
	// hot-reload both go through ParsePoolSpec) instead of failing later
	// inside KVM with a confusing per-VM error.
	specs := map[string]sandlotconfig.SpecEntry{
		"novcpu": {VCPUs: 0, MemoryMB: 128},
	}
	_, err := ParsePoolSpec("novcpu:1", specs)
	if err == nil {
		t.Error("expected error for vcpus=0, got nil")
	}
}

func TestParsePoolSpec_AcceptsValidMemory(t *testing.T) {
	specs := map[string]sandlotconfig.SpecEntry{
		"small": {VCPUs: 1, MemoryMB: 128},
	}
	m, err := ParsePoolSpec("small:2", specs)
	if err != nil {
		t.Fatalf("expected success, got: %v", err)
	}
	if m["small"].count != 2 || m["small"].memMB != 128 {
		t.Errorf("parsed entry = %+v, want count=2 memMB=128", m["small"])
	}
}

func TestParsePoolSpec_RejectsUnknownSpec(t *testing.T) {
	specs := map[string]sandlotconfig.SpecEntry{
		"small": {VCPUs: 1, MemoryMB: 128},
	}
	_, err := ParsePoolSpec("huge:1", specs)
	if err == nil {
		t.Error("expected error for unknown spec, got nil")
	}
}

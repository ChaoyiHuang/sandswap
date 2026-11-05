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

package registry

import (
	"os"
	"path/filepath"
	"testing"

	"gateway/identity"
	"gateway/storage/storagetest"
)

// TestCreateSandFS_RootFSPath tests that RootFSPath is correctly set
// for both flat and overlay modes.
func TestCreateSandFS_RootFSPath(t *testing.T) {
	volRoot := t.TempDir()
	reg := New(volRoot)

	// Create a test agent
	agent, agentKey, err := reg.Store().CreateAgent(identity.CreateAgentRequest{Name: "test-agent"})
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}

	// Storage plane: the test double (REAL volume dirs; no node-side
	// provision code in the gateway module).
	reg.SetStorageOps(storagetest.New(volRoot))

	// Test 1: Flat mode (explicit mode=flat)
	t.Run("FlatMode", func(t *testing.T) {
		rec, _, err := reg.CreateSandFS(t.Context(), agent.ID, identity.CreateSandFSRequest{
			Name:     "test-sandfs-flat",
			Template: "test:v1",
			Mode:     "flat",
		})
		if err != nil {
			t.Fatalf("CreateSandFS: %v", err)
		}

		// RootFSPath should point to sandfs directory
		expectedPath := filepath.Join(volRoot, rec.ID)
		if rec.RootFSPath != expectedPath {
			t.Errorf("RootFSPath = %s, want %s", rec.RootFSPath, expectedPath)
		}

		// Flat SandFS should NOT use OverlayFS
		if rec.UsesOverlayFS() {
			t.Error("UsesOverlayFS() = true, want false for flat SandFS")
		}

		// Verify directory was created
		if _, err := os.Stat(rec.RootFSPath); os.IsNotExist(err) {
			t.Error("RootFS directory not created")
		}

		// Verify agent API key resolves to the agent
		resolved, err := reg.Store().ResolveAgent(agentKey)
		if err != nil {
			t.Fatalf("ResolveAgent: %v", err)
		}
		if resolved.ID != agent.ID {
			t.Errorf("Resolved ID = %s, want %s", resolved.ID, agent.ID)
		}
	})

	// Test 2: Mode is required (no auto-detect) — omitting it errors.
	t.Run("ModeRequired", func(t *testing.T) {
		_, _, err := reg.CreateSandFS(t.Context(), agent.ID, identity.CreateSandFSRequest{
			Name:     "test-sandfs-nomode",
			Template: "test:v1",
			// Mode not specified → must error
		})
		if err == nil {
			t.Fatal("CreateSandFS: expected error for missing mode, got nil")
		}
	})
}

// TestRecord_UsesOverlayFS tests the UsesOverlayFS helper on identity.Record.
func TestRecord_UsesOverlayFS(t *testing.T) {
	tests := []struct {
		name     string
		template string
		want     bool
	}{
		{"empty template", "", false},
		{"with template", "python:v1", true},
		{"with template", "mysql:v2", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := &identity.Record{Template: tt.template}
			if got := rec.UsesOverlayFS(); got != tt.want {
				t.Errorf("UsesOverlayFS() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestCreateSandFSTemplateMinResourcesClamped pins the storage
// plane's declared template minimums are untrusted input that becomes a
// PERSISTENT placement requirement — a value above the largest advertised
// spec must be clamped to the ceiling, or the sandfs is pinned into
// permanent NO_AVAILABLE_SANDBOX while the record looks valid.
func TestCreateSandFSTemplateMinResourcesClamped(t *testing.T) {
	volRoot := t.TempDir()
	reg := New(volRoot)
	double := storagetest.New(volRoot)
	reg.SetStorageOps(double)
	reg.SetSpecCeiling(func() (uint32, uint64) { return 8, 2048 })

	agent, _, err := reg.Store().CreateAgent(identity.CreateAgentRequest{Name: "clamp-agent"})
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}

	// Absurd declared minimums (a hostile/misconfigured prov answer) clamp.
	double.SetMinResources(64, 999999)
	rec, _, err := reg.CreateSandFS(t.Context(), agent.ID, identity.CreateSandFSRequest{
		Name: "clamped", Template: "test:v1", Mode: "flat",
	})
	if err != nil {
		t.Fatalf("CreateSandFS: %v", err)
	}
	if rec.MinVCPUs != 8 || rec.MinMemoryMB != 2048 {
		t.Errorf("declared (64,999999) recorded as (%d,%d), want the ceiling (8,2048)", rec.MinVCPUs, rec.MinMemoryMB)
	}

	// A declared minimum under the ceiling passes through verbatim.
	double.SetMinResources(4, 1024)
	rec2, _, err := reg.CreateSandFS(t.Context(), agent.ID, identity.CreateSandFSRequest{
		Name: "verbatim", Template: "test:v1", Mode: "flat",
	})
	if err != nil {
		t.Fatalf("CreateSandFS: %v", err)
	}
	if rec2.MinVCPUs != 4 || rec2.MinMemoryMB != 1024 {
		t.Errorf("declared (4,1024) recorded as (%d,%d), want verbatim", rec2.MinVCPUs, rec2.MinMemoryMB)
	}

	// Default (no ceiling installed): the built-in table's largest spec.
	reg2 := New(t.TempDir())
	d2 := storagetest.New(reg2.VolRoot())
	reg2.SetStorageOps(d2)
	d2.SetMinResources(1000, 100000)
	agent2, _, err := reg2.Store().CreateAgent(identity.CreateAgentRequest{Name: "clamp-agent-2"})
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}
	rec3, _, err := reg2.CreateSandFS(t.Context(), agent2.ID, identity.CreateSandFSRequest{
		Name: "default-ceiling", Template: "test:v1", Mode: "flat",
	})
	if err != nil {
		t.Fatalf("CreateSandFS: %v", err)
	}
	if rec3.MinVCPUs != 8 || rec3.MinMemoryMB != 2048 {
		t.Errorf("default ceiling recorded (%d,%d), want built-in large (8,2048)", rec3.MinVCPUs, rec3.MinMemoryMB)
	}
}

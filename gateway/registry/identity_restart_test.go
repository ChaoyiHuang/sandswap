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

package registry_test

import (
	"os"
	"path/filepath"
	"testing"

	"gateway/identity"
	"gateway/registry"
)

// TestRegistryRestartRestoresIdentityAndVolumes simulates a full gateway restart
// through the real Registry surface: create an agent + a flat sandfs volume,
// release the identity store lock, reopen the snapshot into a second registry,
// and verify the old api key resolves and the surviving volume directory is
// reachable again.
func TestRegistryRestartRestoresIdentityAndVolumes(t *testing.T) {
	volRoot := t.TempDir()
	statePath := filepath.Join(volRoot, "identity-store.json")

	// First "process": create identity + volume.
	store1, err := identity.NewPersistentMemoryStore(volRoot, statePath, nil)
	if err != nil {
		t.Fatalf("NewPersistentMemoryStore (first): %v", err)
	}
	reg1 := registry.NewWithStore(store1, volRoot)
	installStorageDouble(t, reg1)

	agent, key, err := reg1.Store().CreateAgent(identity.CreateAgentRequest{Name: "restart-agent"})
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}
	rec, _, err := reg1.CreateSandFS(t.Context(), agent.ID, identity.CreateSandFSRequest{
		Name:     "restart-fs",
		Template: "test:v1",
		Mode:     "flat",
	})
	if err != nil {
		t.Fatalf("CreateSandFS: %v", err)
	}
	if _, err := os.Stat(rec.RootFSPath); err != nil {
		t.Fatalf("volume dir missing before restart: %v", err)
	}

	// Restart: release the lock, reopen the same snapshot.
	store1.Close()

	store2, err := identity.NewPersistentMemoryStore(volRoot, statePath, nil)
	if err != nil {
		t.Fatalf("NewPersistentMemoryStore (restart): %v", err)
	}
	defer store2.Close()
	reg2 := registry.NewWithStore(store2, volRoot)

	resolved, err := reg2.Store().ResolveAgent(key)
	if err != nil {
		t.Fatalf("old api key does not resolve after restart: %v", err)
	}
	if resolved.ID != agent.ID {
		t.Errorf("resolved agent = %s, want %s", resolved.ID, agent.ID)
	}

	got, err := reg2.Get(rec.ID)
	if err != nil {
		t.Fatalf("sandfs not reachable after restart: %v", err)
	}
	if got.RootFSPath != rec.RootFSPath {
		t.Errorf("RootFSPath = %s, want %s", got.RootFSPath, rec.RootFSPath)
	}
	if _, err := os.Stat(got.RootFSPath); err != nil {
		t.Errorf("volume dir missing after restart: %v", err)
	}
	if n := len(reg2.List()); n != 1 {
		t.Errorf("List() = %d records, want 1", n)
	}
}

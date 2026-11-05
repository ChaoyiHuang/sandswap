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

// TestNewWithStoreAccessors verifies the explicit-store constructor and its
// accessors: VolRoot passthrough, nil storage ops before SetStorageOps,
// and List() reflecting store contents.
func TestNewWithStoreAccessors(t *testing.T) {
	volRoot := t.TempDir()
	store := identity.NewMemoryStore(volRoot)
	reg := registry.NewWithStore(store, volRoot)

	if reg.VolRoot() != volRoot {
		t.Errorf("VolRoot = %q, want %q", reg.VolRoot(), volRoot)
	}
	if reg.Storage() != nil {
		t.Error("Storage should be nil before SetStorageOps")
	}
	if recs := reg.List(); len(recs) != 0 {
		t.Errorf("empty store List = %d records, want 0", len(recs))
	}

	installStorageDouble(t, reg)
	agentID := createTestAgent(t, reg)
	if _, _, err := reg.CreateSandFS(t.Context(), agentID, identity.CreateSandFSRequest{
		Name: "sf", Template: "test:v1", Mode: "flat",
	}); err != nil {
		t.Fatalf("CreateSandFS: %v", err)
	}

	recs := reg.List()
	if len(recs) != 1 || recs[0].AgentID != agentID {
		t.Errorf("List = %+v, want 1 record owned by %s", recs, agentID)
	}
}

// TestCreateSandFSOverlayMode verifies the overlay volume layout: rootfs/
// mount point, workspace/, home/, and the .template marker carrying the ref.
func TestCreateSandFSOverlayMode(t *testing.T) {
	volRoot := t.TempDir()
	reg := registry.New(volRoot)

	installStorageDouble(t, reg)

	agentID := createTestAgent(t, reg)
	rec, _, err := reg.CreateSandFS(t.Context(), agentID, identity.CreateSandFSRequest{
		Name: "ov-sf", Template: "py:v1", Mode: "overlay",
	})
	if err != nil {
		t.Fatalf("CreateSandFS overlay: %v", err)
	}

	for _, sub := range []string{"workspace", "home"} {
		st, err := os.Stat(filepath.Join(rec.RootFSPath, sub))
		if err != nil || !st.IsDir() {
			t.Errorf("%s/ missing or not a dir: %v", sub, err)
		}
	}
	marker, err := os.ReadFile(filepath.Join(rec.RootFSPath, ".template"))
	if err != nil || string(marker) != "py:v1" {
		t.Errorf(".template marker = %q (%v), want py:v1", string(marker), err)
	}
	if !rec.UsesOverlayFS() {
		t.Error("overlay record must report UsesOverlayFS")
	}
	if rec.AllowsPackageInstall() {
		t.Error("overlay record must not allow package install")
	}
}

// TestCreateSandFSInvalidModeAndMissingManager verifies the request validation
// errors: mode is required verbatim, and a template without a template manager
// cannot be resolved.
func TestCreateSandFSInvalidModeAndMissingManager(t *testing.T) {
	volRoot := t.TempDir()
	reg := registry.New(volRoot)
	agentID := createTestAgent(t, reg)

	if _, _, err := reg.CreateSandFS(t.Context(), agentID, identity.CreateSandFSRequest{
		Name: "bad-mode", Template: "test:v1", Mode: "squashfs",
	}); err == nil {
		t.Error("invalid mode must be rejected")
	}
	// Mode is exact and required: empty and case variants must not slip
	// through to a record that the node later refuses (or, worse, that a
	// future mode branch misreads).
	for _, mode := range []string{"", "FLAT", "Overlay"} {
		if _, _, err := reg.CreateSandFS(t.Context(), agentID, identity.CreateSandFSRequest{
			Name: "bad-mode-" + mode, Template: "test:v1", Mode: mode,
		}); err == nil {
			t.Errorf("mode %q must be rejected", mode)
		}
	}
	if _, _, err := reg.CreateSandFS(t.Context(), agentID, identity.CreateSandFSRequest{
		Name: "no-template", Template: "", Mode: "flat",
	}); err == nil {
		t.Error("an empty template must be rejected")
	}

	reg.SetStorageOps(nil)
	if _, _, err := reg.CreateSandFS(t.Context(), agentID, identity.CreateSandFSRequest{
		Name: "no-mgr", Template: "test:v1", Mode: "flat",
	}); err == nil {
		t.Error("template without manager must be rejected")
	}
}

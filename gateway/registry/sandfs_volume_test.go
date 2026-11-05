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
	"errors"
	"os"
	"path/filepath"
	"testing"

	"gateway/identity"
	"gateway/registry"
	"gateway/storage/storagetest"
)

// With the virtio-fs + bind-mount scheme, each sandfs's rootfs is a plain
// directory (no ext4 image, no UUID). These tests cover the registry's
// directory-based volume lifecycle: creation (seeded from a flat template),
// lookup, deletion, and cross-sandfs directory isolation.

// installStorageDouble wires the registry to the storage-plane test double
// (REAL volume dirs under the registry's root; the deep seeding semantics
// are tested where they live, in sandlot/provision/volume).
func installStorageDouble(t *testing.T, reg *registry.Registry) {
	t.Helper()
	reg.SetStorageOps(storagetest.New(reg.VolumeRoot()))
}

// createTestAgent creates a test agent and returns its ID.
func createTestAgent(t *testing.T, reg *registry.Registry) string {
	t.Helper()
	agent, _, err := reg.Store().CreateAgent(identity.CreateAgentRequest{Name: "test-agent"})
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}
	return agent.ID
}

// TestCreateSandFSPulledSignal pins the create path's auto-pull plumbing: the
// return follows the storage plane's signal (the handler's pull_status), and
// the boolean NOT the record carries it (records are persisted — a transient
// response value must never leak into the store).
func TestCreateSandFSPulledSignal(t *testing.T) {
	reg := registry.New(t.TempDir())
	double := storagetest.New(reg.VolumeRoot())
	reg.SetStorageOps(double)
	agentID := createTestAgent(t, reg)

	_, pulled, err := reg.CreateSandFS(t.Context(), agentID, identity.CreateSandFSRequest{
		Name: "local-hit", Template: "test:v1", Mode: "flat",
	})
	if err != nil {
		t.Fatalf("CreateSandFS: %v", err)
	}
	if pulled {
		t.Error("pulled = true for a local store hit, want false")
	}

	double.SetEnsurePulled(true)
	_, pulled, err = reg.CreateSandFS(t.Context(), agentID, identity.CreateSandFSRequest{
		Name: "registry-hit", Template: "test:v1", Mode: "flat",
	})
	if err != nil {
		t.Fatalf("CreateSandFS: %v", err)
	}
	if !pulled {
		t.Error("pulled = false after the storage plane reported an auto-pull, want true")
	}
}

func TestCreateSandFSVolumeIsDirectory(t *testing.T) {
	reg := registry.New(t.TempDir())
	installStorageDouble(t, reg)
	agentID := createTestAgent(t, reg)

	rec, _, err := reg.CreateSandFS(t.Context(), agentID, identity.CreateSandFSRequest{
		Name:     "dir-test-sandfs",
		Template: "test:v1",
		Mode:     "flat",
	})
	if err != nil {
		t.Fatalf("CreateSandFS: %v", err)
	}
	if rec.ID == "" {
		t.Error("expected sandfs_id")
	}
	if rec.AgentID != agentID {
		t.Errorf("expected agent_id %s, got %s", agentID, rec.AgentID)
	}
	if rec.RootFSPath == "" {
		t.Fatal("expected volume_path")
	}

	// The volume must be a directory (not an ext4 file).
	st, err := os.Stat(rec.RootFSPath)
	if err != nil {
		t.Fatalf("volume path missing: %v", err)
	}
	if !st.IsDir() {
		t.Fatalf("volume must be a directory, got mode %v", st.Mode())
	}

	// (The template CONTENT seeding semantics — symlink handling, mode
	// preservation, marker copies — live with the seeding code in
	// sandlot/provision/volume and are tested there. This side asserts the
	// registry's orchestration only: the volume directory exists and the
	// record maps to it.)

	// Get by sandfs_id returns the same sandfs.
	found, err := reg.Get(rec.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if found.ID != rec.ID {
		t.Errorf("sandfs ID mismatch: %s != %s", found.ID, rec.ID)
	}
}

func TestCreateSandFSWithoutTemplateReturnsError(t *testing.T) {
	reg := registry.New(t.TempDir())
	agentID := createTestAgent(t, reg)

	_, _, err := reg.CreateSandFS(t.Context(), agentID, identity.CreateSandFSRequest{
		Name: "no-template-sandfs",
	})
	if err == nil {
		t.Fatal("expected error when template is not specified")
	}
}

func TestCrossSandFSVolumesAreIsolatedDirectories(t *testing.T) {
	reg := registry.New(t.TempDir())
	installStorageDouble(t, reg)
	agentID := createTestAgent(t, reg)

	recA, _, err := reg.CreateSandFS(t.Context(), agentID, identity.CreateSandFSRequest{
		Name:     "sandfs-a",
		Template: "test:v1",
		Mode:     "flat",
	})
	if err != nil {
		t.Fatalf("CreateSandFS A: %v", err)
	}
	recB, _, err := reg.CreateSandFS(t.Context(), agentID, identity.CreateSandFSRequest{
		Name:     "sandfs-b",
		Template: "test:v1",
		Mode:     "flat",
	})
	if err != nil {
		t.Fatalf("CreateSandFS B: %v", err)
	}

	// Each sandfs gets its own distinct directory.
	if recA.RootFSPath == recB.RootFSPath {
		t.Fatal("sandfs A and B share the same volume path")
	}

	// Write sandfs A's data into its volume directory.
	aFile := filepath.Join(recA.RootFSPath, "secret.txt")
	if err := os.WriteFile(aFile, []byte("A-top-secret"), 0644); err != nil {
		t.Fatalf("write A secret: %v", err)
	}

	// SandFS A's data must NOT be visible inside sandfs B's volume directory.
	bView := filepath.Join(recB.RootFSPath, "secret.txt")
	if _, err := os.Stat(bView); err == nil {
		t.Fatal("cross-sandfs leak: A's secret.txt visible inside B's volume")
	}
}

func TestDeleteSandFSRemovesVolumeDirectory(t *testing.T) {
	reg := registry.New(t.TempDir())
	installStorageDouble(t, reg)
	agentID := createTestAgent(t, reg)

	rec, _, err := reg.CreateSandFS(t.Context(), agentID, identity.CreateSandFSRequest{
		Name:     "to-delete",
		Template: "test:v1",
		Mode:     "flat",
	})
	if err != nil {
		t.Fatalf("CreateSandFS: %v", err)
	}
	volPath := rec.RootFSPath
	if _, err := os.Stat(volPath); err != nil {
		t.Fatalf("volume missing before delete: %v", err)
	}

	// The terminal delete is gated: an ACTIVE record must be refused and the
	// volume must survive.
	if err := reg.Delete(rec.ID); !errors.Is(err, registry.ErrSandfsNotDeleting) {
		t.Fatalf("Delete on an active record: want ErrSandfsNotDeleting, got %v", err)
	}
	if _, err := os.Stat(volPath); err != nil {
		t.Fatalf("gated delete removed the volume: %v", err)
	}

	if err := reg.Store().SetSandfsStatus(rec.ID, identity.SandfsStatusDeleting); err != nil {
		t.Fatalf("set deleting: %v", err)
	}
	if err := reg.Delete(rec.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	if _, err := os.Stat(volPath); err == nil {
		t.Fatal("volume directory still exists after Delete")
	}

	// Idempotent retry: the record is gone; the volume cleanup still runs and
	// the missing record is not an error.
	if err := reg.Delete(rec.ID); err != nil {
		t.Fatalf("idempotent re-delete: %v", err)
	}
}

func TestListSandFSByAgent(t *testing.T) {
	reg := registry.New(t.TempDir())
	installStorageDouble(t, reg)

	agentA, _, _ := reg.Store().CreateAgent(identity.CreateAgentRequest{Name: "agent-a"})
	agentB, _, _ := reg.Store().CreateAgent(identity.CreateAgentRequest{Name: "agent-b"})

	reg.CreateSandFS(t.Context(), agentA.ID, identity.CreateSandFSRequest{Name: "sandfs-a1", Template: "test:v1", Mode: "flat"})
	reg.CreateSandFS(t.Context(), agentA.ID, identity.CreateSandFSRequest{Name: "sandfs-a2", Template: "test:v1", Mode: "flat"})
	reg.CreateSandFS(t.Context(), agentB.ID, identity.CreateSandFSRequest{Name: "sandfs-b1", Template: "test:v1", Mode: "flat"})

	listA, _ := reg.ListSandFSByAgent(agentA.ID)
	if len(listA) != 2 {
		t.Errorf("expected 2 sandfs for agent A, got %d", len(listA))
	}

	listB, _ := reg.ListSandFSByAgent(agentB.ID)
	if len(listB) != 1 {
		t.Errorf("expected 1 sandfs for agent B, got %d", len(listB))
	}
}

// TestCreateSandFSClearsStaleVolumeAtDerivedName pins the create path's guard
// against adopting a foreign tree: an orphaned volume left at the new id's
// derived name (a create whose cleanup raced its own materialization, its
// record long gone) must be CLEARED before the volume is materialized. The
// node-side adopt short-circuit only compares the identity stamp, and ids are
// 32 bits — a later create that draws the same id would otherwise "find" the
// orphan complete and serve the deleted tenant's content under the new record.
//
// The double's contract here matches the node's: EnsureVolume does NOT remove
// pre-existing entries at the derived name (the real op adopts an existing
// stamped tree), DeleteVolume does. The alias models the id collision itself:
// both creates resolve to the SAME on-disk name.
func TestCreateSandFSClearsStaleVolumeAtDerivedName(t *testing.T) {
	volRoot := t.TempDir()
	reg := registry.New(volRoot)
	double := storagetest.New(volRoot)
	reg.SetStorageOps(double)
	agentID := createTestAgent(t, reg)

	const staleName = "OLD-TENANT-CONTENT"
	alias := "sf-collided-name"
	double.SetVolumeAlias(alias)
	volDir := filepath.Join(volRoot, alias)

	// Create #1 on the shared name, then drop its record and leave the tree —
	// exactly the orphan a failed create can leave behind.
	first, _, err := reg.CreateSandFS(t.Context(), agentID, identity.CreateSandFSRequest{
		Name: "first-tenant", Template: "test:v1", Mode: "flat",
	})
	if err != nil {
		t.Fatalf("CreateSandFS #1: %v", err)
	}
	if err := os.WriteFile(filepath.Join(volDir, staleName), []byte("from a deleted tenant"), 0o644); err != nil {
		t.Fatalf("plant stale content: %v", err)
	}
	if err := reg.Store().DeleteSandFS(first.ID); err != nil {
		t.Fatalf("drop the orphan's record: %v", err)
	}

	// Create #2 draws the colliding id (same derived name) and must NOT see
	// the old tree.
	second, _, err := reg.CreateSandFS(t.Context(), agentID, identity.CreateSandFSRequest{
		Name: "second-tenant", Template: "test:v1", Mode: "flat",
	})
	if err != nil {
		t.Fatalf("CreateSandFS #2: %v", err)
	}
	if _, err := os.Stat(filepath.Join(volDir, staleName)); !os.IsNotExist(err) {
		t.Fatalf("the stale tree at the new id's derived name survived the create (stat err = %v) — it would be adopted as this tenant's volume", err)
	}
	if _, err := os.Stat(second.RootFSPath); err != nil {
		t.Fatalf("the fresh volume is missing: %v", err)
	}
}

// TestCreateSandFSRejectsStoragePlanePathOutsideRoot pins the ingress
// validation: the path the storage plane answers becomes the record's
// rootfs_path and is later handed to the exec node's allowed_dirs filter, so
// a path outside THIS deployment's volumes root must fail the create (and
// leave no record behind) instead of being stored.
func TestCreateSandFSRejectsStoragePlanePathOutsideRoot(t *testing.T) {
	volRoot := t.TempDir()
	reg := registry.New(volRoot)
	double := storagetest.New(volRoot)
	reg.SetStorageOps(double)
	agentID := createTestAgent(t, reg)

	for _, bad := range []string{
		"/etc/passwd",                      // arbitrary host path
		volRoot + "/../volumes-other/sf-x", // escape via ..
		volRoot,                            // the root itself is not a volume
		"relative/volume",                  // not absolute
	} {
		double.SetRootfsPathOverride(bad)
		rec, _, err := reg.CreateSandFS(t.Context(), agentID, identity.CreateSandFSRequest{
			Name: "bad-path", Template: "test:v1", Mode: "flat",
		})
		if err == nil {
			t.Fatalf("CreateSandFS accepted rootfs_path %q (record %+v)", bad, rec)
		}
		if rec != nil {
			t.Fatalf("CreateSandFS returned a record for a refused path %q", bad)
		}
		list, _ := reg.ListSandFSByAgent(agentID)
		if len(list) != 0 {
			t.Fatalf("refused create left %d record(s) behind", len(list))
		}
	}

	// The normal answer still passes (the guard is not a blanket refusal).
	double.SetRootfsPathOverride("")
	rec, _, err := reg.CreateSandFS(t.Context(), agentID, identity.CreateSandFSRequest{
		Name: "good-path", Template: "test:v1", Mode: "flat",
	})
	if err != nil {
		t.Fatalf("CreateSandFS with the double's normal path: %v", err)
	}
	if err := registry.ValidateVolumePath(volRoot, rec.RootFSPath); err != nil {
		t.Fatalf("stored rootfs_path does not satisfy the rule: %v", err)
	}
}

// TestValidateVolumePath pins the rule table itself: absolute, clean and
// strictly inside the volumes root — the same rule the operator re-point
// endpoint applies (one implementation, both callers).
func TestValidateVolumePath(t *testing.T) {
	root := "/var/lib/sandswap/volumes"
	ok := []string{root + "/sf-abc", root + "/sf-abc/rootfs"}
	for _, p := range ok {
		if err := registry.ValidateVolumePath(root, p); err != nil {
			t.Errorf("ValidateVolumePath(%q) = %v, want nil", p, err)
		}
	}
	bad := []string{
		"", root, root + "/", root + "/../etc", root + "/a/../..",
		"/etc/passwd", "sf-abc", root + "/sf-abc/", root + "x/sf-abc",
	}
	for _, p := range bad {
		if err := registry.ValidateVolumePath(root, p); err == nil {
			t.Errorf("ValidateVolumePath(%q) = nil, want a refusal", p)
		}
	}
}

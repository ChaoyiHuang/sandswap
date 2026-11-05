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

package volume

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// A signed stamp is the volume's completion proof: the quota hook runs before
// the stamp in the create path, so a marker beside a valid stamp is tenant
// debris (or an interrupted finalize), never a reason to wipe the tree.
func TestEnsureVolumeKeepsStampedVolumeWithPlantedMarker(t *testing.T) {
	p, _, _ := newFixture(t)
	ctx := context.Background()
	if _, err := p.EnsureVolume(ctx, "sandfs-1", "flat", "seed:v1"); err != nil {
		t.Fatalf("create: %v", err)
	}
	vol := volPath(p, "sandfs-1")
	sentinel := filepath.Join(vol, "tenant-data")
	if err := os.WriteFile(sentinel, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	// The flat volume root is the agent's chroot: this is tenant-plantable.
	if err := os.WriteFile(filepath.Join(vol, provisioningMarker), []byte("planted"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := p.EnsureVolume(ctx, "sandfs-1", "flat", "seed:v1"); err != nil {
		t.Fatalf("re-ensure of a stamped volume must be idempotent, got %v", err)
	}
	if _, err := os.Stat(sentinel); err != nil {
		t.Fatalf("tenant data was wiped: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(vol, provisioningMarker)); !os.IsNotExist(err) {
		t.Fatalf("the planted marker should be cleared, got %v", err)
	}
}

// os.Stat used to follow a tenant-planted `.provisioning -> <host path>`; the
// marker check must never resolve a guest-chosen path host-side. With a valid
// stamp the symlink is inert debris (the volume is still complete).
func TestEnsureVolumeIgnoresSymlinkedProvisioningMarker(t *testing.T) {
	p, _, _ := newFixture(t)
	ctx := context.Background()
	if _, err := p.EnsureVolume(ctx, "sandfs-1", "flat", "seed:v1"); err != nil {
		t.Fatalf("create: %v", err)
	}
	vol := volPath(p, "sandfs-1")
	sentinel := filepath.Join(vol, "tenant-data")
	if err := os.WriteFile(sentinel, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	hostTarget := filepath.Join(t.TempDir(), "host-file")
	if err := os.WriteFile(hostTarget, []byte("host"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(hostTarget, filepath.Join(vol, provisioningMarker)); err != nil {
		t.Fatal(err)
	}

	if _, err := p.EnsureVolume(ctx, "sandfs-1", "flat", "seed:v1"); err != nil {
		t.Fatalf("re-ensure: %v", err)
	}
	if _, err := os.Stat(sentinel); err != nil {
		t.Fatalf("tenant data was wiped through a symlinked marker: %v", err)
	}
	if hasProvisioningMarker(vol) {
		t.Fatal("a symlinked .provisioning must never count as the partial-run marker")
	}
}

// A regular marker with NO stamp is still a genuine partial run: wipe and
// redo (the stamp is written last).
func TestEnsureVolumeWipesUnstampedRegularMarker(t *testing.T) {
	p, volRoot, _ := newFixture(t)
	ctx := context.Background()
	volName := p.volumeName("sandfs-1")
	vol := filepath.Join(volRoot, volName)
	if err := os.MkdirAll(vol, 0o770); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(vol, provisioningMarker), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(vol, "partial"), []byte("garbage"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := p.EnsureVolume(ctx, "sandfs-1", "flat", "seed:v1"); err != nil {
		t.Fatalf("self-heal: %v", err)
	}
	if _, err := os.Stat(filepath.Join(vol, "partial")); !os.IsNotExist(err) {
		t.Fatalf("partial tree was not wiped: %v", err)
	}
	if _, err := os.Stat(filepath.Join(vol, "hello.txt")); err != nil {
		t.Fatalf("fresh seed missing: %v", err)
	}
}

// VerifyVolumeIdentity is read-only and must apply the same authority rule: a
// valid signed stamp is complete even beside a marker; a marker with no stamp
// is mid-provisioning.
func TestVerifyVolumeIdentityStampedVolumeWithMarker(t *testing.T) {
	p, _, vol := newOverlayFixture(t)
	if err := os.WriteFile(filepath.Join(vol, provisioningMarker), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := p.VerifyVolumeIdentity("sandfs-ov", vol); err != nil {
		t.Fatalf("a stamped volume with a planted marker must verify: %v", err)
	}

	if err := os.Remove(filepath.Join(vol, VolumeIdentityFile)); err != nil {
		t.Fatal(err)
	}
	err := p.VerifyVolumeIdentity("sandfs-ov", vol)
	if !errors.Is(err, ErrVolumeIdentityMismatch) {
		t.Fatalf("a marker with no stamp must be refused as mid-provisioning, got %v", err)
	}
}

// The in-use scan's layout signature must not follow a tenant symlink: a
// planted `workspace -> <host dir>` used to look like the overlay layout and
// could pin a template (a deleted-template DoS) while reading host paths.
func TestScanTemplateInUseIgnoresSymlinkedLayout(t *testing.T) {
	p, _, _ := newFixture(t)
	ctx := context.Background()
	id := "not-a-seed-name"
	vol := filepath.Join(p.VolRoot, id)
	if err := os.MkdirAll(vol, 0o770); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(vol, ".template"), []byte("pinned:v1"), 0o644); err != nil {
		t.Fatal(err)
	}
	hostDir := t.TempDir()
	for _, sub := range []string{"workspace", "home"} {
		if err := os.Symlink(hostDir, filepath.Join(vol, sub)); err != nil {
			t.Fatal(err)
		}
	}

	count, _, err := p.scanTemplateInUse(ctx, "pinned:v1")
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if count != 0 {
		t.Fatalf("a symlinked workspace/home must not count as overlay layout (count=%d)", count)
	}
}

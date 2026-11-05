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

// TestVerifyVolumeIdentity pins the read-only identity gate behind the
// gateway's rootfs-path repoint endpoint: only a real, complete,
// exactly-stamped directory this sandfs's names resolve to passes; every
// other shape — foreign stamp, missing stamp, missing directory, symlink,
// partial run, path outside the volumes root — is refused by name.
func TestVerifyVolumeIdentity(t *testing.T) {
	p, volRoot, _ := newFixture(t)

	// A real provisioned volume (EnsureVolume writes the .sandfs-id stamp).
	res, err := p.EnsureVolume(context.Background(), "sandfs-1", "flat", "seed:v1")
	if err != nil {
		t.Fatalf("EnsureVolume: %v", err)
	}
	if err := p.VerifyVolumeIdentity("sandfs-1", res.RootfsPath); err != nil {
		t.Fatalf("VerifyVolumeIdentity on its own volume = %v, want nil", err)
	}

	// A foreign sandfs id must not adopt sandfs-1's directory (the exact
	// repoint-the-record-at-someone-else's-volume shape).
	err = p.VerifyVolumeIdentity("sandfs-2", res.RootfsPath)
	if !errors.Is(err, ErrVolumeIdentityMismatch) {
		t.Fatalf("foreign-id verify: want ErrVolumeIdentityMismatch, got %v", err)
	}

	// The caller's own derived name that does not exist on disk.
	missing := filepath.Join(volRoot, p.Names.Current("sandfs-3"))
	if err := p.VerifyVolumeIdentity("sandfs-3", missing); !errors.Is(err, ErrVolumeIdentityMismatch) {
		t.Fatalf("missing-dir verify: want ErrVolumeIdentityMismatch, got %v", err)
	}

	// An unstamped directory (not a provisioned volume).
	plain := filepath.Join(volRoot, p.Names.Current("sandfs-4"))
	if err := os.MkdirAll(plain, 0o770); err != nil {
		t.Fatal(err)
	}
	if err := p.VerifyVolumeIdentity("sandfs-4", plain); !errors.Is(err, ErrVolumeIdentityMismatch) {
		t.Fatalf("unstamped-dir verify: want ErrVolumeIdentityMismatch, got %v", err)
	}

	// A symlink planted at the derived name is never a volume.
	link := filepath.Join(volRoot, p.Names.Current("sandfs-5"))
	if err := os.Symlink(res.RootfsPath, link); err != nil {
		t.Fatal(err)
	}
	if err := p.VerifyVolumeIdentity("sandfs-5", link); !errors.Is(err, ErrVolumeIdentityMismatch) {
		t.Fatalf("symlink verify: want ErrVolumeIdentityMismatch, got %v", err)
	}

	// A marker beside a VALID signed stamp is tenant debris, not
	// mid-provisioning: the stamp (written after the quota hook) is the
	// completion proof, and the marker lives in the agent-writable root.
	later, err := p.EnsureVolume(context.Background(), "sandfs-6", "flat", "seed:v1")
	if err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(later.RootfsPath, provisioningMarker)
	if err := os.WriteFile(marker, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := p.VerifyVolumeIdentity("sandfs-6", later.RootfsPath); err != nil {
		t.Fatalf("stamped volume with a planted marker must verify: %v", err)
	}
	// Without the stamp the same marker IS a genuine partial run.
	if err := os.Remove(filepath.Join(later.RootfsPath, VolumeIdentityFile)); err != nil {
		t.Fatal(err)
	}
	if err := p.VerifyVolumeIdentity("sandfs-6", later.RootfsPath); !errors.Is(err, ErrVolumeIdentityMismatch) {
		t.Fatalf("mid-provisioning verify: want ErrVolumeIdentityMismatch, got %v", err)
	}

	// Path shape: outside the volumes root, and a malformed id.
	if err := p.VerifyVolumeIdentity("sandfs-1", "/etc/passwd"); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("outside-root verify: want ErrInvalidArgument, got %v", err)
	}
	if err := p.VerifyVolumeIdentity("../evil", res.RootfsPath); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("malformed-id verify: want ErrInvalidArgument, got %v", err)
	}
}

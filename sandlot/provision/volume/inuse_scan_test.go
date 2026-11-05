// Copyright 2026 Chaoyi Huang. All rights reserved.
//
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE file at the root of this repository.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, sandswap's use of this software will be governed
// by the Apache License, Version 2.0.

package volume

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// testInUse runs DeleteTemplate's in-use decision for an overlay ref and
// reports whether the template was refused as in use.
func testInUse(t *testing.T, p *Provisioner, ref string) bool {
	t.Helper()
	err := p.DeleteTemplate(context.Background(), ref, "overlay", false)
	if err == nil {
		return false
	}
	var inUse *TemplateInUseError
	if !errors.As(err, &inUse) {
		t.Fatalf("DeleteTemplate(%s): want TemplateInUseError or success, got %v", ref, err)
	}
	return true
}

// TestScanTemplateInUseIgnoresOrphans pins that an orphaned volume directory —
// the tree the delete fallback parks as .<name>.orphan-<ts> when guest-planted
// modes block direct removal — cannot pin a template: its sandfs is gone, so
// the template has no user left. Without the skip the non-force delete path
// became unusable forever after one such delete (the operator would always
// have to force).
func TestScanTemplateInUseIgnoresOrphans(t *testing.T) {
	p, _, vol := newOverlayFixture(t)

	// The state RemoveAll leaves behind: the whole -populated- volume renamed
	// aside, marker and layout intact.
	orphan := filepath.Join(p.VolRoot, "."+filepath.Base(vol)+".orphan-1700000000")
	if err := os.Rename(vol, orphan); err != nil {
		t.Fatal(err)
	}
	if got := markerRef(t, orphan); got != "app:v1" {
		t.Fatalf("orphan fixture lost its marker: %q", got)
	}
	if testInUse(t, p, "app:v1") {
		t.Fatal("an orphaned volume directory pinned the template( regression)")
	}
}

// TestScanTemplateInUseIgnoresFlatVolumeMarker pins the layout guard against a
// FLAT volume: its directory IS the agent's chroot, so the agent can mint the
// overlay signature (.template + workspace/ + home/) itself and pin any
// template forever. The identity stamp is the node-side evidence the agent
// does not choose — the create asked for the mode, the storage plane wrote it — so a
// volume stamped flat is never counted in use, while a stamp that carries no
// mode (written before the field existed) stays conservative and counts.
func TestScanTemplateInUseIgnoresFlatVolumeMarker(t *testing.T) {
	p, _, _ := newOverlayFixture(t)

	// A real flat volume, then the plant: exactly what an agent inside the
	// volume can create through the FUSE daemon.
	if _, err := p.EnsureVolume(context.Background(), "sandfs-flat", "flat", "seed:v1"); err != nil {
		t.Fatal(err)
	}
	flatVol := volPath(p, "sandfs-flat")
	if err := os.WriteFile(filepath.Join(flatVol, ".template"), []byte("app:v2"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, sub := range []string{"workspace", "home"} {
		if err := os.MkdirAll(filepath.Join(flatVol, sub), 0o770); err != nil {
			t.Fatal(err)
		}
	}
	if st, ok, err := readVolumeStamp(flatVol); err != nil || !ok || st.Mode != "flat" {
		t.Fatalf("flat volume stamp mode = %q (ok=%v err=%v), want flat", st.Mode, ok, err)
	}
	if testInUse(t, p, "app:v2") {
		t.Fatal("a planted marker in a FLAT volume pinned the template( regression)")
	}

	// Legacy stamp without a mode: the same tree now counts (conservative —
	// never drop a template a live overlay volume might still mount).
	writeModeLessStamp(t, flatVol, "sandfs-flat")
	if !testInUse(t, p, "app:v2") {
		t.Fatal("a mode-less (legacy) stamp must stay conservative and count")
	}

	// The live overlay volume from the fixture still counts, stamped overlay.
	if !testInUse(t, p, "app:v1") {
		t.Fatal("the live overlay volume stopped counting as in use")
	}
	if st, ok, err := readVolumeStamp(volPath(p, "sandfs-ov")); err != nil || !ok || st.Mode != "overlay" {
		t.Fatalf("overlay volume stamp mode = %q (ok=%v err=%v), want overlay", st.Mode, ok, err)
	}
}

// writeModeLessStamp rewrites a volume's identity stamp in the pre-mode
// format (sandfs_id + generation + created_unix only).
func writeModeLessStamp(t *testing.T, vol, id string) {
	t.Helper()
	body := "sandfs_id: " + id + "\ngeneration: " + strings.Repeat("a", 8) + "\ncreated_unix: 1700000000\n"
	if err := os.WriteFile(filepath.Join(vol, VolumeIdentityFile), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

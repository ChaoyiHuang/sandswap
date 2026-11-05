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

// TestCheckReplyPath pins the classification the reply guard applies: a path
// strictly inside the volumes root passes; the root itself, a sibling, an
// escape and a relative path are refused.
func TestCheckReplyPath(t *testing.T) {
	root := "/var/lib/sandswap/volumes"
	cases := []struct {
		path string
		ok   bool
	}{
		{filepath.Join(root, "sf-abc"), true},
		{filepath.Join(root, "sf-abc", "rootfs"), true},
		{root, false}, // the root itself is not a volume
		{root + string(filepath.Separator), false}, // same, after Clean
		{filepath.Join(root, "..", "volumes2", "sf-x"), false},
		{filepath.Join(root, "..", "etc"), false},
		{"/etc/passwd", false},
		{"sf-relative", false},
		{"", false},
	}
	for _, c := range cases {
		err := checkReplyPath(root, c.path)
		if c.ok && err != nil {
			t.Errorf("checkReplyPath(%q) = %v, want nil", c.path, err)
		}
		if !c.ok && err == nil {
			t.Errorf("checkReplyPath(%q) = nil, want a refusal", c.path)
		}
	}
}

// TestEnsureVolumeRefusesReplyOutsideVolRoot drives a REAL EnsureVolume with
// the derivation subverted (the test seam rewrites the reply path the way a
// broken namer would): the op must fail instead of answering a path the
// gateway would store and later hand to the VMM's allowed_dirs filter. The
// same guard sits on the adopt short-circuit and on SwapTemplate.
func TestEnsureVolumeRefusesReplyOutsideVolRoot(t *testing.T) {
	p, _, _ := newFixture(t)
	p.testHookReplyRootfsPath = func(string) string { return "/etc/passwd" }

	_, err := p.EnsureVolume(context.Background(), "sandfs-1", "flat", "seed:v1")
	if !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("EnsureVolume with an escaping reply: want ErrInvalidArgument, got %v", err)
	}
	if !strings.Contains(err.Error(), "outside") {
		t.Fatalf("refusal must name the containment rule: %v", err)
	}

	// The guard is not a blanket refusal: without the seam the same call
	// answers the derived in-root path.
	p.testHookReplyRootfsPath = nil
	res, err := p.EnsureVolume(context.Background(), "sandfs-1", "flat", "seed:v1")
	if err != nil {
		t.Fatalf("EnsureVolume: %v", err)
	}
	if err := checkReplyPath(p.VolRoot, res.RootfsPath); err != nil {
		t.Fatalf("a normal reply must satisfy the guard: %v", err)
	}
}

// rewriteStampID replaces the sandfs_id line of a volume's identity stamp —
// what a name/record drift (or a truncated id stored in a shortened form)
// looks like on disk.
func rewriteStampID(t *testing.T, vol, id string) {
	t.Helper()
	stamp := filepath.Join(vol, VolumeIdentityFile)
	data, err := os.ReadFile(stamp)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "sandfs_id:") {
			continue
		}
		out = append(out, line)
	}
	updated := "sandfs_id: " + id + "\n" + strings.Join(out, "\n")
	if err := os.WriteFile(stamp, []byte(updated), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestEnsureVolumeAdoptRequiresExactStampID pins the adopt short-circuit's
// identity check: adopting an existing complete volume demands the stamp's id
// to be EXACTLY the requested one — a truncated (prefix) stamp, or a stamp
// for any other id, is refused, never adopted. The create path clears stale
// directories of its own (registry.CreateSandFS); this is the guarantee that
// must hold on the node regardless.
func TestEnsureVolumeAdoptRequiresExactStampID(t *testing.T) {
	p, _, vol := newOverlayFixture(t)

	// Exact stamp → adopt (idempotent create: no re-seed, content untouched).
	if err := os.WriteFile(filepath.Join(vol, "sentinel"), []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := p.EnsureVolume(context.Background(), "sandfs-ov", "overlay", "app:v1"); err != nil {
		t.Fatalf("idempotent re-ensure: %v", err)
	}
	if _, err := os.Stat(filepath.Join(vol, "sentinel")); err != nil {
		t.Fatalf("adopt must leave the volume untouched: %v", err)
	}

	// Truncated stamp id (a prefix of the requested id) → refusal, not adopt.
	rewriteStampID(t, vol, "sandfs-")
	if _, err := p.EnsureVolume(context.Background(), "sandfs-ov", "overlay", "app:v1"); !errors.Is(err, ErrVolumeIdentityMismatch) {
		t.Fatalf("prefix stamp: want ErrVolumeIdentityMismatch (no adopt), got %v", err)
	}
	// A stamp for another id entirely: same refusal.
	rewriteStampID(t, vol, "sandfs-other")
	if _, err := p.EnsureVolume(context.Background(), "sandfs-ov", "overlay", "app:v1"); !errors.Is(err, ErrVolumeIdentityMismatch) {
		t.Fatalf("foreign stamp: want ErrVolumeIdentityMismatch (no adopt), got %v", err)
	}
}

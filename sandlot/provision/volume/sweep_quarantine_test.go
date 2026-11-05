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
	"strings"
	"testing"
	"time"
)

// TestDeleteVolumeQuarantinesUnreadableStamp pins the destructive-cleanup
// convergence: a stamp file that EXISTS but is not a usable marker (the
// tenant's own flat volume root is agent-writable) must not block deletion
// forever. The volume is renamed aside — nothing erased, the id reusable — and
// the planted link is never followed.
func TestDeleteVolumeQuarantinesUnreadableStamp(t *testing.T) {
	p, _, _ := newFixture(t)
	ctx := context.Background()
	if _, err := p.EnsureVolume(ctx, "sandfs-q", "flat", "seed:v1"); err != nil {
		t.Fatalf("EnsureVolume: %v", err)
	}
	vol := volPath(p, "sandfs-q")
	if err := os.Remove(filepath.Join(vol, VolumeIdentityFile)); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/passwd", filepath.Join(vol, VolumeIdentityFile)); err != nil {
		t.Fatal(err)
	}

	if err := p.DeleteVolume(ctx, "sandfs-q"); err != nil {
		t.Fatalf("an unreadable stamp must converge by quarantine, got %v", err)
	}
	if _, err := os.Stat(vol); !os.IsNotExist(err) {
		t.Fatal("the volume path must be vacated (the id must be reusable)")
	}
	orphans, err := filepath.Glob(filepath.Join(p.VolRoot, "."+p.volumeName("sandfs-q")+".orphan-*"))
	if err != nil || len(orphans) != 1 {
		t.Fatalf("expected exactly one quarantined tree, got %v (err %v)", orphans, err)
	}
	if _, err := os.Stat(filepath.Join(orphans[0], "hello.txt")); err != nil {
		t.Fatalf("quarantine must PRESERVE the data for ops: %v", err)
	}
	if fi, err := os.Lstat(filepath.Join(orphans[0], VolumeIdentityFile)); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("the planted stamp must be moved as a link, never followed (fi=%v err=%v)", fi, err)
	}
}

// TestDeleteVolumeStillRefusesMismatchedStamp is the control: an unreadable
// stamp converges by quarantine, but a READABLE stamp naming another sandfs is
// the cross-tenant mix-up the identity check exists for — it must still refuse.
func TestDeleteVolumeStillRefusesMismatchedStamp(t *testing.T) {
	p, _, _ := newFixture(t)
	ctx := context.Background()
	vol := volPath(p, "sandfs-m")
	if err := os.MkdirAll(vol, 0o770); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(vol, VolumeIdentityFile), []byte("sandfs_id: someone-else\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := p.DeleteVolume(ctx, "sandfs-m")
	if !errors.Is(err, ErrVolumeIdentityMismatch) {
		t.Fatalf("a stamp naming another sandfs must refuse, got %v", err)
	}
	if _, serr := os.Stat(vol); serr != nil {
		t.Fatal("a refused delete must leave the directory in place")
	}
}

// TestVolumeEpochFormatValidated pins the epoch contract at every boundary: the
// create argument, the stamp writer, and the stamp reader. The epoch is a stamp
// FIELD (line-oriented, MAC-covered), so a value carrying a newline or any
// non-hex character is refused rather than allowed to reshape the file.
func TestVolumeEpochFormatValidated(t *testing.T) {
	p, _, _ := newFixture(t)
	ctx := context.Background()
	for _, bad := range []string{"ab\ncd", "ABCD", "xyz", strings.Repeat("a", 65)} {
		if _, err := p.EnsureVolume(ctx, "sandfs-e", "flat", "seed:v1", bad); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("EnsureVolume epoch %q: want ErrInvalidArgument, got %v", bad, err)
		}
	}

	dir := t.TempDir()
	if err := writeVolumeStamp(dir, "id", "flat", testSeed(), 1, "AB"); err == nil {
		t.Error("writeVolumeStamp accepted a non-lowercase-hex epoch")
	}
	if err := writeVolumeStamp(dir, "id", "flat", testSeed(), 1, "a0b1c2"); err != nil {
		t.Errorf("writeVolumeStamp rejected a valid epoch: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, VolumeIdentityFile), []byte("sandfs_id: id\nvolume_epoch: zz\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readVolumeStamp(dir); !errors.Is(err, ErrVolumeStampUnreadable) {
		t.Errorf("a malformed epoch must classify the stamp unreadable, got %v", err)
	}
}

// TestSweepOrphansReclaimsAgedOnly pins the orphan sweeper's safety envelope:
// only direct children matching the exact orphan shape, only real directories,
// and only past the age threshold are touched. Fresh orphans (a delete may
// still be finishing), symlinks and ordinary volume directories are left alone.
func TestSweepOrphansReclaimsAgedOnly(t *testing.T) {
	p, _, _ := newFixture(t)
	oldOrphan := filepath.Join(p.VolRoot, ".old.orphan-1000")
	if err := os.MkdirAll(oldOrphan, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(oldOrphan, "data"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	past := time.Now().Add(-2 * OrphanSweepAge)
	if err := os.Chtimes(oldOrphan, past, past); err != nil {
		t.Fatal(err)
	}

	fresh := filepath.Join(p.VolRoot, ".fresh.orphan-2000")
	if err := os.MkdirAll(fresh, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(p.VolRoot, ".link.orphan-3000")
	if err := os.Symlink(t.TempDir(), link); err != nil {
		t.Fatal(err)
	}
	plain := filepath.Join(p.VolRoot, "ordinary-volume")
	if err := os.MkdirAll(plain, 0o755); err != nil {
		t.Fatal(err)
	}

	removed, queued := p.SweepOrphans(OrphanSweepAge)
	if removed != 1 || queued != 0 {
		t.Fatalf("SweepOrphans = (%d removed, %d queued), want (1, 0)", removed, queued)
	}
	for _, keep := range []string{fresh, link, plain} {
		if _, err := os.Lstat(keep); err != nil {
			t.Fatalf("%s must be left alone: %v", keep, err)
		}
	}
	if _, err := os.Stat(oldOrphan); !os.IsNotExist(err) {
		t.Fatal("the aged orphan must be reclaimed")
	}
}

// TestRecordOrphansQueue pins the ops channel: deduplicated, one name per line,
// 0600 (a seed-derived name must not become group-readable in the shared
// volumes root).
func TestRecordOrphansQueue(t *testing.T) {
	p, _, _ := newFixture(t)
	p.recordOrphans([]string{"vol-a", "vol-b"})
	p.recordOrphans([]string{"vol-a", "vol-c"})

	path := filepath.Join(p.VolRoot, orphanQueueFile)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read queue: %v", err)
	}
	if got, want := string(data), "vol-a\nvol-b\nvol-c\n"; got != want {
		t.Fatalf("queue = %q, want %q (deduplicated, append-only)", got, want)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("queue mode = %o, want 600", fi.Mode().Perm())
	}
}

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
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"sandlot/provision/volname"
)

func scanSeed(n byte) []byte { return bytes.Repeat([]byte{n}, 32) }

// The scan is the shared reading behind the startup guard, the daemon promote
// gate and the tool's pre-flight: its skip rules and its classification must
// match the rotation tooling's, or the three disagree about what "a volume
// still on the old generation" means.
func TestScanGenerationStampsMixedTree(t *testing.T) {
	root := t.TempDir()
	seedA, seedB := scanSeed(1), scanSeed(2)
	fpA, fpB := volname.Fingerprint(seedA), volname.Fingerprint(seedB)

	mkVol := func(name string) string {
		p := filepath.Join(root, name)
		if err := os.Mkdir(p, 0o755); err != nil {
			t.Fatal(err)
		}
		return p
	}

	if err := writeVolumeStamp(mkVol("sf-a"), "id-a", "overlay", seedA, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	if err := writeVolumeStamp(mkVol("sf-f"), "id-f", "overlay", seedA, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	if err := writeVolumeStamp(mkVol("sf-b"), "id-b", "overlay", seedB, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	mkVol("sf-c") // no stamp at all
	pg := mkVol("sf-d")
	if err := os.WriteFile(filepath.Join(pg, VolumeIdentityFile), []byte("sandfs_id: id-d\ncreated_unix: 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	pt := mkVol("sf-e") // partial run: skipped by definition
	if err := os.WriteFile(filepath.Join(pt, provisioningMarker), []byte("provisioning\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Ignored classes: dot-prefixed debris, plain files, and symlinks —
	// including a symlink to a stamped directory OUTSIDE the root, which a
	// following scan would wrongly count.
	if err := os.Mkdir(filepath.Join(root, ".orphan"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "not-a-dir"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "sf-out")
	if err := os.Mkdir(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := writeVolumeStamp(outside, "id-out", "overlay", seedB, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "sf-link")); err != nil {
		t.Fatal(err)
	}

	res, err := ScanGenerationStamps(root, ScanOptions{Known: []string{fpA}, Seeds: [][]byte{seedA, seedB}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Complete {
		t.Error("all directories were scheduled; the scan must report complete")
	}
	if got := res.GenerationCount(fpA); got != 2 {
		t.Errorf("generation A count = %d, want 2", got)
	}
	if got := res.GenerationCount(fpB); got != 1 {
		t.Errorf("generation B count = %d, want 1", got)
	}
	if res.Foreign != 1 {
		t.Errorf("foreign = %d, want 1 (the generation-B volume)", res.Foreign)
	}
	if res.Unstamped != 1 {
		t.Errorf("unstamped = %d, want 1", res.Unstamped)
	}
	// sf-d carries a hand-written UNSIGNED stamp: no compatibility path, so it
	// is not "pre-generation" (legacy) but unauthenticated (tampering/mix-up).
	if res.PreGeneration != 0 {
		t.Errorf("pre-generation = %d, want 0 (unsigned stamps are not a usable generation)", res.PreGeneration)
	}
	if res.Unverified != 1 {
		t.Errorf("unverified = %d, want 1 (the unsigned stamp)", res.Unverified)
	}
	if res.Partial != 1 {
		t.Errorf("partial = %d, want 1", res.Partial)
	}
	if res.Sampled != 5 {
		t.Errorf("sampled = %d, want 5 (dot debris, files and symlinks are not volumes)", res.Sampled)
	}
	if res.ReadErrors != 0 {
		t.Errorf("read errors = %d, want 0", res.ReadErrors)
	}
	if got := res.LegacyCount(); got != 1 {
		t.Errorf("legacy = %d, want 1 (only the volume with no stamp; the unsigned one is unverified)", got)
	}
	if len(res.Examples) == 0 || len(res.Examples) > 3 {
		t.Errorf("examples = %v, want 1..3 entries", res.Examples)
	}
}

// Without Known there is nothing to be foreign TO: the histogram still comes
// back, the classification stays silent.
func TestScanGenerationStampsNoKnownSet(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "sf-a"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := writeVolumeStamp(filepath.Join(root, "sf-a"), "id-a", "overlay", scanSeed(9), time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	res, err := ScanGenerationStamps(root, ScanOptions{Seeds: [][]byte{scanSeed(9)}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.ByGeneration) != 1 || res.Foreign != 0 {
		t.Errorf("byGeneration=%v foreign=%d, want one entry and no foreign classification", res.ByGeneration, res.Foreign)
	}
}

// A root that does not exist holds no volumes. EnsureVolume owns the
// actionable "volumes root missing" error, so this must not be one — but the
// result must SAY the scan read nothing (RootMissing): an absent root and a
// clean empty tree look identical in every counter, and the promote gate
// refuses the former.
func TestScanGenerationStampsMissingRoot(t *testing.T) {
	res, err := ScanGenerationStamps(filepath.Join(t.TempDir(), "absent"), ScanOptions{})
	if err != nil {
		t.Fatalf("a missing root must not be an error: %v", err)
	}
	if !res.Complete || res.Sampled != 0 || len(res.ByGeneration) != 0 {
		t.Errorf("missing root = %+v, want an empty complete result", res)
	}
	if !res.RootMissing {
		t.Error("RootMissing = false for an absent root: callers cannot tell \"not scanned\" from \"clean\"")
	}
}

// The deadline bounds scheduling only, and it must be deterministic: a budget
// that has already expired schedules nothing and reports incomplete.
func TestScanGenerationStampsDeadline(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < 50; i++ {
		if err := os.Mkdir(filepath.Join(root, fmt.Sprintf("sf-%02d", i)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	res, err := ScanGenerationStamps(root, ScanOptions{Deadline: time.Nanosecond})
	if err != nil {
		t.Fatal(err)
	}
	if res.Complete {
		t.Error("an expired budget must report an incomplete scan")
	}
	if res.Sampled != 0 {
		t.Errorf("sampled = %d, want 0: nothing may be scheduled past the deadline", res.Sampled)
	}
}

// Workers exists so that a fleet-scale tree on shared storage finishes inside
// the deadline — the deadline's verdict is a REFUSAL at the promote gate
// ("the scan did not finish"), so serializing the per-volume I/O under the
// merge lock turns a clean tree into a refused rotation. The injected read
// makes each stamp take 15ms: 64 volumes with 16 workers either overlap
// (~4 batches, well inside the budget) or serialize (64 reads ≈ 1s, past it).
func TestScanGenerationStampsReadsConcurrently(t *testing.T) {
	root := t.TempDir()
	const vols = 64
	seedA := scanSeed(7)
	fpA := volname.Fingerprint(seedA)
	for i := 0; i < vols; i++ {
		dir := filepath.Join(root, fmt.Sprintf("sf-%03d", i))
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := writeVolumeStamp(dir, fmt.Sprintf("id-%03d", i), "overlay", seedA, time.Now().Unix()); err != nil {
			t.Fatal(err)
		}
	}

	res, err := ScanGenerationStamps(root, ScanOptions{
		Known:    []string{fpA},
		Seeds:    [][]byte{seedA},
		Workers:  16,
		Deadline: 250 * time.Millisecond,
		readStamp: func(volPath string) (volumeStamp, bool, error) {
			time.Sleep(15 * time.Millisecond)
			return readVolumeStamp(volPath)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Complete {
		t.Fatalf("16 workers must overlap their stamp reads: 64 reads of 15ms exceed the 250ms budget only when they serialize under the merge lock (sampled=%d)", res.Sampled)
	}
	if res.Sampled != vols {
		t.Fatalf("sampled = %d, want %d", res.Sampled, vols)
	}
	if got := res.GenerationCount(fpA); got != vols {
		t.Fatalf("generation count = %d, want %d", got, vols)
	}
}

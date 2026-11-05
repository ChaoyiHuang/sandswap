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
	"syscall"
	"testing"
	"time"
)

// The stamp is what turns a name that no longer matches its identity into an
// error instead of a silent second tree. The scenario it exists for is a SEED
// MIX-UP (half-applied rotation, restored backup, hand-rename): the same id
// now derives a different directory, so "the directory exists, carry on" would
// split the tenant's data.
func TestEnsureVolumeRefusesForeignstamp(t *testing.T) {
	p, _, _ := newFixture(t)
	ctx := context.Background()

	if _, err := p.EnsureVolume(ctx, "sandfs-owner", "flat", "seed:v1"); err != nil {
		t.Fatalf("create: %v", err)
	}
	// Simulate the mix-up: the directory a DIFFERENT id resolves to (or, as
	// here, the same directory asked for by another id) carries a foreign
	// stamp. Point the second id at the first one's directory by copying the
	// tree — exactly what a botched rotation/restore produces.
	ownerDir := volPath(p, "sandfs-owner")
	intruderDir := volPath(p, "sandfs-intruder")
	if err := os.MkdirAll(intruderDir, 0o770); err != nil {
		t.Fatal(err)
	}
	stamp, err := os.ReadFile(filepath.Join(ownerDir, VolumeIdentityFile))
	if err != nil {
		t.Fatalf("stamp missing on a created volume: %v", err)
	}
	if err := os.WriteFile(filepath.Join(intruderDir, VolumeIdentityFile), stamp, 0o644); err != nil {
		t.Fatal(err)
	}

	_, err = p.EnsureVolume(ctx, "sandfs-intruder", "flat", "seed:v1")
	if !errors.Is(err, ErrVolumeIdentityMismatch) {
		t.Fatalf("an existing directory stamped for another sandfs must be refused, got %v", err)
	}
	if !strings.Contains(err.Error(), "sandfs-owner") {
		t.Errorf("the refusal must name the stamped owner so the operator can see what happened: %v", err)
	}
}

// A complete-looking directory with NO stamp is an operator error (pre-stamp
// layout or a foreign tree) and must be surfaced, not adopted.
func TestEnsureVolumeRefusesUnstampedDirectory(t *testing.T) {
	p, _, _ := newFixture(t)
	if err := os.MkdirAll(volPath(p, "sandfs-legacy"), 0o770); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(volPath(p, "sandfs-legacy"), "somefile"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := p.EnsureVolume(context.Background(), "sandfs-legacy", "flat", "seed:v1")
	if !errors.Is(err, ErrVolumeIdentityMismatch) {
		t.Fatalf("an unstamped existing directory must be refused (run the migration), got %v", err)
	}
	if !strings.Contains(err.Error(), "migration") {
		t.Errorf("the refusal must point at the migration: %v", err)
	}
}

// The idempotent path must SURVIVE the new guard: a retried create of the same
// sandfs over its own complete volume still succeeds (that is the whole point
// of EnsureVolume's retry contract).
func TestEnsureVolumeIdempotentRetryStillSucceeds(t *testing.T) {
	p, _, _ := newFixture(t)
	ctx := context.Background()
	if _, err := p.EnsureVolume(ctx, "sandfs-retry", "flat", "seed:v1"); err != nil {
		t.Fatalf("first create: %v", err)
	}
	if _, err := p.EnsureVolume(ctx, "sandfs-retry", "flat", "seed:v1"); err != nil {
		t.Fatalf("retry over its own volume must succeed: %v", err)
	}
	st, ok, err := readVolumeStamp(volPath(p, "sandfs-retry"))
	if err != nil || !ok {
		t.Fatalf("stamp unreadable after retry: ok=%v err=%v", ok, err)
	}
	if st.SandfsID != "sandfs-retry" || st.Generation == "" || st.CreatedUnix == 0 {
		t.Errorf("stamp must carry id, generation fingerprint and creation time, got %+v", st)
	}
}

// The stamp must never carry seed material — only the one-way fingerprint.
func TestStampCarriesNoSeedMaterial(t *testing.T) {
	p, _, _ := newFixture(t)
	if _, err := p.EnsureVolume(context.Background(), "sandfs-secret", "flat", "seed:v1"); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(volPath(p, "sandfs-secret"), VolumeIdentityFile))
	if err != nil {
		t.Fatal(err)
	}
	seedHex := strings.ToLower(strings.TrimSpace(hexOf(p.Names.CurrentSeed())))
	for _, line := range strings.Split(string(raw), "\n") {
		if line == "" {
			continue
		}
		if strings.Contains(strings.ToLower(line), seedHex) {
			t.Fatalf("stamp leaks the seed bytes: %q", line)
		}
	}
	if !strings.Contains(string(raw), "generation: ") {
		t.Errorf("stamp must record the generation fingerprint, got %q", raw)
	}
}

// The DESTRUCTIVE half of the stamp guard: delete and swap must refuse a
// directory they cannot prove belongs to the named sandfs. Without the guard,
// a directory that landed at the wrong derived name (hand-rename, half-applied
// rotation, restored backup) is destroyed or home-rewritten as a silent
// cross-tenant hit.
func TestDeleteVolumeRefusesForeignStamp(t *testing.T) {
	p, _, _ := newFixture(t)
	if _, err := p.EnsureVolume(context.Background(), "sandfs-owner", "flat", "seed:v1"); err != nil {
		t.Fatalf("create: %v", err)
	}
	// The owner's tree now sits at the INTRUDER's derived name (the mix-up
	// shape): copy tree + stamp under the intruder's name.
	ownerDir := volPath(p, "sandfs-owner")
	intruderDir := volPath(p, "sandfs-intruder")
	if err := os.MkdirAll(intruderDir, 0o770); err != nil {
		t.Fatal(err)
	}
	stamp, err := os.ReadFile(filepath.Join(ownerDir, VolumeIdentityFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(intruderDir, VolumeIdentityFile), stamp, 0o644); err != nil {
		t.Fatal(err)
	}

	derr := p.DeleteVolume(context.Background(), "sandfs-intruder")
	if !errors.Is(derr, ErrVolumeIdentityMismatch) {
		t.Fatalf("delete of a foreign-stamped directory must be refused, got %v", derr)
	}
	if _, serr := os.Stat(intruderDir); serr != nil {
		t.Fatalf("the refused delete must leave the directory in place: %v", serr)
	}
	if !strings.Contains(derr.Error(), "sandfs-owner") {
		t.Errorf("the refusal must name the stamped owner so the operator can see what happened: %v", derr)
	}
}

// A directory carrying the partial-run marker is garbage by definition: the
// stamp exemption must let the self-heal path (and a delete racing it) clean
// it without a stamp.
func TestDeleteVolumeCleansPartialRun(t *testing.T) {
	p, _, _ := newFixture(t)
	vol := volPath(p, "sandfs-partial")
	if err := os.MkdirAll(vol, 0o770); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(vol, provisioningMarker), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := p.DeleteVolume(context.Background(), "sandfs-partial"); err != nil {
		t.Fatalf("delete of a marker-carrying partial tree: %v", err)
	}
	if _, err := os.Stat(vol); !os.IsNotExist(err) {
		t.Fatal("partial tree survived delete")
	}
}

// SwapTemplate is content-rewriting (home policy): the same ownership proof
// as deletion.
func TestSwapTemplateRefusesForeignStamp(t *testing.T) {
	p, _, _ := newFixture(t)
	if _, err := p.EnsureVolume(context.Background(), "sandfs-own2", "flat", "seed:v1"); err != nil {
		t.Fatalf("create: %v", err)
	}
	ownDir := volPath(p, "sandfs-own2")
	foreignDir := volPath(p, "sandfs-swapin")
	if err := os.MkdirAll(foreignDir, 0o770); err != nil {
		t.Fatal(err)
	}
	stamp, err := os.ReadFile(filepath.Join(ownDir, VolumeIdentityFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(foreignDir, VolumeIdentityFile), stamp, 0o644); err != nil {
		t.Fatal(err)
	}
	// Give it a marker so the refusal comes from the stamp guard, not the
	// no-marker check.
	_, err = p.SwapTemplate(context.Background(), "sandfs-swapin", "seed:v2", HomeKeep)
	if !errors.Is(err, ErrVolumeIdentityMismatch) {
		t.Fatalf("swap on a foreign-stamped directory must be refused, got %v", err)
	}
}

func hexOf(b []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, hexdigits[c>>4], hexdigits[c&0xf])
	}
	return string(out)
}

// ── Stamp hardening (planted entries, forgery, name binding) ─────────

// In flat mode the volume root is the tenant's chroot: .sandfs-id is
// tenant-writable. The host-side read must never follow a planted symlink
// (arbitrary host-file read) and must never block on a FIFO (the startup guard
// reads every volume; one FIFO parked the prov process forever).
func TestReadVolumeStampRejectsPlantedEntries(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("host secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	stampPath := filepath.Join(dir, VolumeIdentityFile)

	// 1. Symlink: an ERROR, never a followed read.
	if err := os.Symlink(victim, stampPath); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readVolumeStamp(dir); err == nil {
		t.Fatal("a symlinked stamp must be refused (never followed)")
	}

	// 2. FIFO: must return promptly (O_NONBLOCK + type check), not block.
	if err := os.Remove(stampPath); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(stampPath, 0o644); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if _, _, err := readVolumeStamp(dir); err == nil {
		t.Fatal("a FIFO stamp must be refused")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("the FIFO stamp blocked the read for %v", elapsed)
	}

	// 3. Oversized regular file: refused by the 4 KiB marker cap.
	if err := os.Remove(stampPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stampPath, make([]byte, 8<<10), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readVolumeStamp(dir); err == nil {
		t.Fatal("an oversized stamp must be refused")
	}

	// 4. A genuine small regular file still parses (control).
	if err := os.Remove(stampPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stampPath, []byte("sandfs_id: x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	st, ok, err := readVolumeStamp(dir)
	if err != nil || !ok || st.SandfsID != "x" {
		t.Fatalf("control stamp unreadable: st=%+v ok=%v err=%v", st, ok, err)
	}
}

// The signature binds id, mode AND the volume's directory name: a tenant that
// rewrites the file cannot make it verify, and a valid stamp copied to another
// volume does not verify there either.
func TestStampSignatureBindsIdModeAndVolumeName(t *testing.T) {
	p, _, _ := newFixture(t)
	if _, err := p.EnsureVolume(context.Background(), "sandfs-sig", "flat", "seed:v1"); err != nil {
		t.Fatalf("create: %v", err)
	}
	dir := volPath(p, "sandfs-sig")
	stampPath := filepath.Join(dir, VolumeIdentityFile)

	raw, err := os.ReadFile(stampPath)
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(raw), "mode: flat", "mode: overlay", 1)
	if tampered == string(raw) {
		t.Fatalf("test precondition: no mode line to tamper: %q", raw)
	}
	if err := os.WriteFile(stampPath, []byte(tampered), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := p.requireStampOwnership(dir, "sandfs-sig", "test", ""); err == nil {
		t.Fatal("a stamp with a tampered mode line must be refused")
	}

	// Re-sign, then copy the VALID stamp to another volume directory: the
	// directory name is in the MAC input, so it must not verify there.
	if err := writeVolumeStamp(dir, "sandfs-sig", "flat", p.Names.CurrentSeed(), 123); err != nil {
		t.Fatal(err)
	}
	valid, err := os.ReadFile(stampPath)
	if err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(p.VolRoot, "sf-other-name")
	if err := os.MkdirAll(other, 0o770); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(other, VolumeIdentityFile), valid, 0o644); err != nil {
		t.Fatal(err)
	}
	st, ok, err := readVolumeStamp(other)
	if err != nil || !ok {
		t.Fatalf("copied stamp unreadable: %v", err)
	}
	if p.stampSignatureOK(other, st) {
		t.Fatal("a stamp copied to another volume must not verify (directory name is MAC-bound)")
	}
}

// VerifyVolumeIdentity's whole security argument is the signature: a forged or
// unsigned stamp must never authorize a record repoint.
func TestVerifyVolumeIdentityRequiresASignature(t *testing.T) {
	p, _, _ := newFixture(t)
	if _, err := p.EnsureVolume(context.Background(), "sandfs-repoint", "flat", "seed:v1"); err != nil {
		t.Fatalf("create: %v", err)
	}
	dir := volPath(p, "sandfs-repoint")
	// A tenant-planted body naming the same id: previously accepted.
	forged := "sandfs_id: sandfs-repoint\ngeneration: deadbeef\nmode: flat\ncreated_unix: 1\n"
	if err := os.WriteFile(filepath.Join(dir, VolumeIdentityFile), []byte(forged), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := p.VerifyVolumeIdentity("sandfs-repoint", dir); err == nil {
		t.Fatal("an unsigned/forged stamp must not authorize a rootfs-path repoint")
	}
}

// The stamp writer must replace a planted symlink, never write through it
// (the rotation tooling used to run as root with shell redirection).
func TestWriteVolumeStampNeverFollowsAPlantedSymlink(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("host file"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(dir, VolumeIdentityFile)); err != nil {
		t.Fatal(err)
	}
	if err := writeVolumeStamp(dir, "id-sym", "flat", scanSeed(3), 1); err != nil {
		t.Fatalf("write over a planted symlink: %v", err)
	}
	if got, err := os.ReadFile(victim); err != nil || string(got) != "host file" {
		t.Fatalf("the symlink target was modified: %q err=%v", got, err)
	}
	fi, err := os.Lstat(filepath.Join(dir, VolumeIdentityFile))
	if err != nil || !fi.Mode().IsRegular() {
		t.Fatalf("the stamp entry must be replaced by a regular file, got %v (err=%v)", fi.Mode(), err)
	}
}

// A stamp signed by a seed no live generation derives is counted separately
// from an I/O error, so the strict gates can refuse on it.
func TestScanGenerationStampsCountsUnverifiedStamps(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "sf-a")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := writeVolumeStamp(dir, "id-a", "flat", scanSeed(1), 1); err != nil {
		t.Fatal(err)
	}
	res, err := ScanGenerationStamps(root, ScanOptions{Seeds: [][]byte{scanSeed(2)}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Unverified != 1 || res.ReadErrors != 0 || res.Unstamped != 0 {
		t.Fatalf("scan = %+v, want exactly one unverified stamp", res)
	}
}

// CheckVolumeID is the exec node's seedless gate: it binds the
// gateway-supplied (sandfs_id, volume_path) pair to the on-disk stamp.
func TestCheckVolumeIDBindsPathToSandfsID(t *testing.T) {
	dir := t.TempDir()
	if err := writeVolumeStamp(dir, "sandfs-a", "flat", scanSeed(1), 1); err != nil {
		t.Fatal(err)
	}
	if err := CheckVolumeID(dir, "sandfs-a"); err != nil {
		t.Fatalf("own id: %v", err)
	}
	// A foreign id on a valid volume is the attack shape: a compromised
	// gateway naming someone else's directory.
	if err := CheckVolumeID(dir, "sandfs-b"); !errors.Is(err, ErrVolumeIdentityMismatch) {
		t.Fatalf("foreign id: want ErrVolumeIdentityMismatch, got %v", err)
	}
	// Missing directory / missing stamp are identity mismatches, never a pass.
	missing := filepath.Join(dir, "does-not-exist")
	if err := CheckVolumeID(missing, "sandfs-a"); !errors.Is(err, ErrVolumeIdentityMismatch) {
		t.Fatalf("missing dir: want ErrVolumeIdentityMismatch, got %v", err)
	}
	if err := CheckVolumeID(t.TempDir(), "sandfs-a"); !errors.Is(err, ErrVolumeIdentityMismatch) {
		t.Fatalf("missing stamp: want ErrVolumeIdentityMismatch, got %v", err)
	}
	// A symlinked stamp is an unreadable stamp (readVolumeStamp's O_NOFOLLOW
	// rule) — never a match, even when the target names the right id.
	linkdir := t.TempDir()
	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, []byte("sandfs_id: sandfs-a\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(linkdir, VolumeIdentityFile)); err != nil {
		t.Fatal(err)
	}
	if err := CheckVolumeID(linkdir, "sandfs-a"); !errors.Is(err, ErrVolumeIdentityMismatch) {
		t.Fatalf("symlinked stamp: want ErrVolumeIdentityMismatch, got %v", err)
	}
	// Malformed ids are argument errors, not identity questions.
	if err := CheckVolumeID(dir, "../evil"); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("malformed id: want ErrInvalidArgument, got %v", err)
	}
	// A mount that carries an EMPTY epoch is refused: pre-epoch volumes have
	// no generation binding, so comparing "" == "" would defeat the guard.
	if err := CheckVolumeID(dir, "sandfs-a", ""); !errors.Is(err, ErrVolumeIdentityMismatch) {
		t.Fatalf("empty epoch: want ErrVolumeIdentityMismatch, got %v", err)
	}
	// Seedless semantics, pinned deliberately: an UNSIGNED stamp whose id
	// matches passes at the exec node. The HMAC proof lives on the prov
	// instance (VerifyVolumeIdentity); a compromised gateway has no storage
	// write to forge the victim's stamp, so equality is the containment this
	// gate claims.
	unsigned := t.TempDir()
	body := "sandfs_id: sandfs-a\ngeneration: g\nmode: flat\ncreated_unix: 1\n"
	if err := os.WriteFile(filepath.Join(unsigned, VolumeIdentityFile), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := CheckVolumeID(unsigned, "sandfs-a"); err != nil {
		t.Fatalf("unsigned but id-matching stamp: %v", err)
	}
}

// The rotation rename moves a volume (and its stamp) to a new seed-derived
// name. The stamp's MAC binds the OLD basename, so verification against the
// new path alone fails — and a re-stamp that loses volume_epoch makes every
// later mount fail the identity check. This pins the pre-rename verification
// the rotation tool uses to preserve mode/created/volume_epoch.
func TestRotationRenamePreservesStampFields(t *testing.T) {
	p, _, _ := newFixture(t)
	const epoch = "00112233445566778899aabbccddeeff"
	oldPath := volPath(p, "sandfs-rot")
	if _, err := p.EnsureVolume(context.Background(), "sandfs-rot", "flat", "seed:v1", epoch); err != nil {
		t.Fatalf("create: %v", err)
	}
	oldName := filepath.Base(oldPath)
	newPath := filepath.Join(filepath.Dir(oldPath), "sf-rotatedgeneration")
	if err := os.Rename(oldPath, newPath); err != nil {
		t.Fatalf("rename: %v", err)
	}
	seed := p.Names.CurrentSeed()

	// The current-name verification must fail (the MAC named the old dir)...
	if _, verified, err := VerifyVolumeStampForTool(newPath, [][]byte{seed}); err != nil || verified {
		t.Fatalf("current-name verify = (%v, %v), want verified=false", verified, err)
	}
	// ...and the pre-rename name must verify, so the tool preserves the epoch.
	present, verified, err := VerifyVolumeStampForToolAtName(newPath, oldName, [][]byte{seed})
	if err != nil || !present || !verified {
		t.Fatalf("previous-name verify = (present=%v verified=%v err=%v), want true/true", present, verified, err)
	}
	st, ok, err := ReadVolumeStampForTool(newPath)
	if err != nil || !ok {
		t.Fatalf("read stamp: ok=%v err=%v", ok, err)
	}
	if st.VolumeEpoch != epoch {
		t.Fatalf("stamp epoch = %q, want %q", st.VolumeEpoch, epoch)
	}
}

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
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"sandlot/provision/template"
	"sandlot/provision/volname"
)

// newFixture builds a Provisioner over temp dirs with one registered local
// flat template ("seed:v1") containing two files.
func newFixture(t *testing.T) (*Provisioner, string, string) {
	t.Helper()
	volRoot := t.TempDir()
	tplRoot := t.TempDir()

	mgr, err := template.NewManager(template.Config{TemplatesDir: filepath.Join(tplRoot, "store")})
	if err != nil {
		t.Fatal(err)
	}
	// The flat source lives INSIDE the store: the flat consume path only
	// accepts content under the store or a configured flat scan root
	//( trust boundary). Created after NewManager, so the constructor
	// scan does not auto-register it.
	src := filepath.Join(tplRoot, "store", "src")
	if err := os.MkdirAll(filepath.Join(src, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "hello.txt"), []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "sub", "deep.bin"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := mgr.RegisterFlatTemplate("seed:v1", src); err != nil {
		t.Fatal(err)
	}
	// A fixed test seed: the namer must be exercised (resolving by ID is the
	// production path; only a nil namer falls back to the legacy name).
	p, err := New(volRoot, mgr, testSeed())
	if err != nil {
		t.Fatalf("volume.New: %v", err)
	}
	return p, volRoot, src
}

func TestEnsureVolumeFlatSeedsAndRemovesMarker(t *testing.T) {
	p, _, _ := newFixture(t)

	res, err := p.EnsureVolume(context.Background(), "sandfs-1", "flat", "seed:v1")
	if err != nil {
		t.Fatalf("EnsureVolume: %v", err)
	}
	vol := volPath(p, "sandfs-1")
	if res.RootfsPath != vol {
		t.Fatalf("rootfs = %q, want %q", res.RootfsPath, vol)
	}
	// A locally registered template is a cache hit: pulled must stay false
	// (true would make the gateway report pull_status "pulled" for a local
	// seed).
	if res.Pulled {
		t.Error("Pulled = true for a locally registered template, want false")
	}
	if b, err := os.ReadFile(filepath.Join(vol, "hello.txt")); err != nil || string(b) != "hi" {
		t.Fatalf("seeded file missing/wrong: %q %v", b, err)
	}
	// The provisioning marker must be GONE on success — a later retry must
	// not mistake a complete volume for a partial one.
	if _, err := os.Stat(filepath.Join(vol, provisioningMarker)); !os.IsNotExist(err) {
		t.Fatalf("marker still present after success: %v", err)
	}
	// Seeded files carry the shared-group bits (group access for the serving
	// identities) and the volume dir is setgid.
	fi, err := os.Stat(vol)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeSetgid == 0 {
		t.Fatalf("volume dir not setgid: %v", fi.Mode())
	}
}

func TestEnsureVolumeHealsPartialRun(t *testing.T) {
	p, _, _ := newFixture(t)
	vol := volPath(p, "sandfs-2")
	if err := os.MkdirAll(vol, 0o770); err != nil {
		t.Fatal(err)
	}
	// A crashed half-seed: marker present + stale junk.
	if err := os.WriteFile(filepath.Join(vol, provisioningMarker), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(vol, "stale-junk"), []byte("garbage"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := p.EnsureVolume(context.Background(), "sandfs-2", "flat", "seed:v1"); err != nil {
		t.Fatalf("self-heal run: %v", err)
	}
	if _, err := os.Stat(filepath.Join(vol, "stale-junk")); !os.IsNotExist(err) {
		t.Fatal("partial-run junk survived the marker wipe")
	}
	if b, err := os.ReadFile(filepath.Join(vol, "hello.txt")); err != nil || string(b) != "hi" {
		t.Fatal("healed volume missing seeded content")
	}
}

func TestDeleteVolumeIdempotent(t *testing.T) {
	p, _, _ := newFixture(t)
	if _, err := p.EnsureVolume(context.Background(), "sandfs-3", "flat", "seed:v1"); err != nil {
		t.Fatal(err)
	}
	if err := p.DeleteVolume(context.Background(), "sandfs-3"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := os.Stat(volPath(p, "sandfs-3")); !os.IsNotExist(err) {
		t.Fatal("volume dir survived delete")
	}
	// ENOENT = success (retry on another node is always safe).
	if err := p.DeleteVolume(context.Background(), "sandfs-3"); err != nil {
		t.Fatalf("second delete must be a no-op success, got %v", err)
	}
}

// A cancelled provision deadline must free the slot WITHOUT renaming the tree
// aside; the volume stays for a retry.
func TestDeleteVolumeHonorsCancelledContext(t *testing.T) {
	p, _, _ := newFixture(t)
	if _, err := p.EnsureVolume(context.Background(), "sandfs-cancel", "flat", "seed:v1"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := p.DeleteVolume(ctx, "sandfs-cancel"); !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
	if _, err := os.Stat(volPath(p, "sandfs-cancel")); err != nil {
		t.Fatalf("volume removed despite cancellation: %v", err)
	}
	// Control: a live context deletes it.
	if err := p.DeleteVolume(context.Background(), "sandfs-cancel"); err != nil {
		t.Fatalf("control delete: %v", err)
	}
	if _, err := os.Stat(volPath(p, "sandfs-cancel")); !os.IsNotExist(err) {
		t.Fatal("control delete left the volume")
	}
}

// The storage plane never trusts the gateway's strings: traversal and
// malformed ids are rejected before any path is joined.
func TestValidateSandfsID(t *testing.T) {
	for _, bad := range []string{"", "..", "../escape", "a/b", "a\\b", ".hidden-start", string(make([]byte, 200))} {
		if err := ValidateSandfsID(bad); err == nil {
			t.Errorf("ValidateSandfsID(%q) should fail", bad)
		}
	}
	for _, good := range []string{"sandfs-abc123", "a", "x.y-z_w", "ID1234567890"} {
		if err := ValidateSandfsID(good); err != nil {
			t.Errorf("ValidateSandfsID(%q): %v", good, err)
		}
	}
}

func TestEnsureVolumeRejectsBadArgs(t *testing.T) {
	p, _, _ := newFixture(t)
	ctx := context.Background()
	if _, err := p.EnsureVolume(ctx, "../evil", "flat", "seed:v1"); err == nil {
		t.Fatal("traversal sandfs_id must be rejected")
	}
	if _, err := p.EnsureVolume(ctx, "sandfs-ok", "teleport", "seed:v1"); err == nil {
		t.Fatal("unknown mode must be rejected")
	}
	if _, err := p.EnsureVolume(ctx, "sandfs-ok", "flat", "../../etc/passwd"); err == nil {
		t.Fatal("traversal template ref must be rejected")
	}
}

// StatTemplate returns the declared min resources for sizing.
func TestStatTemplate(t *testing.T) {
	p, _, _ := newFixture(t)
	if v, m, ok := p.StatTemplate("seed:v1"); ok {
		t.Fatalf("unset min resources must report ok=false, got %d/%d", v, m)
	}
}

// A missing volumes root means an unprepared host: EnsureVolume must fail
// with the actionable setup step instead of minting the root itself (an
// implicit MkdirAll would create it owned by prov with prov's group, and
// every volume inside would then be unreachable to the exec sandlot (985)
// and unwritable for the FUSE daemon (987) — a node-wide outage).
func TestEnsureVolumeMissingVolRootFailsFast(t *testing.T) {
	p, volRoot, _ := newFixture(t)
	if err := os.RemoveAll(volRoot); err != nil {
		t.Fatal(err)
	}
	_, err := p.EnsureVolume(context.Background(), "sandfs-x", "flat", "seed:v1")
	if err == nil {
		t.Fatal("EnsureVolume succeeded with a missing volumes root")
	}
	if !strings.Contains(err.Error(), "host prep") {
		t.Errorf("error does not name the setup step: %v", err)
	}
	if _, statErr := os.Stat(volRoot); !os.IsNotExist(statErr) {
		t.Error("the provisioner created the volumes root instead of failing")
	}
}

// The .template marker is read cross-identity by the exec sandlot at mount
// time: a restrictive umask must not make it owner-only.
func TestTemplateMarkerUmaskImmune(t *testing.T) {
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)
	vol := t.TempDir()
	if err := writeTemplateMarker(vol, "tpl:v1"); err != nil {
		t.Fatalf("writeTemplateMarker: %v", err)
	}
	fi, err := os.Stat(filepath.Join(vol, ".template"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o644 {
		t.Errorf(".template mode = %04o under umask 077, want 0644", fi.Mode().Perm())
	}
}

// A promote that lands while a volume is being seeded must fail the create
// LOUDLY. The directory was named under the generation at entry; finalizing it
// after the promote would hand the caller a path that every later resolve
// misses (delete answers false success, a re-create builds a second tree) —
// and the rotation's own steps skip it (the rename skips .provisioning
// directories, --run skips records with no rootfs_path yet), so no guard would
// ever see it. The seam drives that interleaving deterministically.
func TestEnsureVolumeRefusesWhenGenerationMovesMidCreate(t *testing.T) {
	p, _, _ := newFixture(t)
	genB := bytes.Repeat([]byte{0x5A}, 32)

	var fired bool
	p.testHookEnsureVolumeSeeded = func() {
		if fired {
			return
		}
		fired = true
		// The operator's whole window completes while this create is seeding:
		// stage the new generation, rename nothing (this volume has no record
		// rootfs_path yet), promote.
		if err := p.Names.Stage(genB); err != nil {
			t.Fatalf("stage: %v", err)
		}
		if err := p.Names.ApplySeeds(genB, nil, true, false); err != nil {
			t.Fatalf("promote: %v", err)
		}
	}
	defer func() { p.testHookEnsureVolumeSeeded = nil }()

	retiredName := p.volumeName("sandfs-rot") // the generation live at entry
	res, err := p.EnsureVolume(context.Background(), "sandfs-rot", "flat", "seed:v1")
	if err == nil {
		t.Fatalf("a create finishing after the generation moved must fail loudly, not return %s", res.RootfsPath)
	}
	if !errors.Is(err, ErrRotationStaged) {
		t.Errorf("the refusal must carry the rotation sentinel (the gateway maps it to ROTATION_STAGED), got: %v", err)
	}
	// The refused tree must not look like a complete volume: the marker stays,
	// so scans report it as a partial run and never as a volume of any
	// generation.
	if _, serr := os.Stat(filepath.Join(p.VolRoot, retiredName, provisioningMarker)); serr != nil {
		t.Errorf("the refused tree must keep its %s marker (partial-run garbage, self-healable): %v", provisioningMarker, serr)
	}

	// The retry materializes a fresh volume under the new generation, and its
	// identity stamp names that same generation: name and stamp agree.
	res, err = p.EnsureVolume(context.Background(), "sandfs-rot", "flat", "seed:v1")
	if err != nil {
		t.Fatalf("retry after the rotation: %v", err)
	}
	want := filepath.Join(p.VolRoot, volname.Derive(genB, "sandfs-rot"))
	if res.RootfsPath != want {
		t.Errorf("retry rootfs = %q, want %q (the new generation's name)", res.RootfsPath, want)
	}
	st, ok, rerr := readVolumeStamp(want)
	if rerr != nil || !ok {
		t.Fatalf("retry volume has no readable stamp: ok=%v err=%v", ok, rerr)
	}
	if st.Generation != volname.Fingerprint(genB) {
		t.Errorf("stamp generation = %s, want %s", st.Generation, volname.Fingerprint(genB))
	}
}

// The tampered-ref sink: a tampered flat ref naming a host directory OUTSIDE the
// template store must refuse at ensure time — before copyDirRecursive seeds
// it into a tenant volume. The refs file is the untrusted artifact (shared
// storage: a peer node or a tampered store writes it); the layer path is
// judged at consume.
func TestEnsureVolumeFlatLayerOutsideStoreRefused(t *testing.T) {
	volRoot := t.TempDir()
	tplRoot := t.TempDir()
	store := filepath.Join(tplRoot, "store")

	// A host directory the store does not cover, with content that must never
	// reach a tenant volume.
	outside := filepath.Join(tplRoot, "host-dir")
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "secret"), []byte("host content"), 0o644); err != nil {
		t.Fatal(err)
	}

	mgr, err := template.NewManager(template.Config{TemplatesDir: store})
	if err != nil {
		t.Fatal(err)
	}
	// Hand-write the tampered ref (a legal refs/ filename, an illegal layer).
	refsDir := filepath.Join(store, "refs")
	if err := os.MkdirAll(refsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	refJSON := `{"name":"evil","version":"v1","mode":"flat","layers":["` + outside + `"]}`
	if err := os.WriteFile(filepath.Join(refsDir, "evil_v1.flat.json"), []byte(refJSON), 0o644); err != nil {
		t.Fatal(err)
	}

	p, err := New(volRoot, mgr, testSeed())
	if err != nil {
		t.Fatalf("volume.New: %v", err)
	}
	_, err = p.EnsureVolume(context.Background(), "sandfs-evil", "flat", "evil:v1")
	if err == nil {
		t.Fatal("flat layer outside the store was consumed")
	}
	if !errors.Is(err, template.ErrFlatLayerOutsideStore) {
		t.Fatalf("want the named refusal (ErrFlatLayerOutsideStore), got: %v", err)
	}
	t.Logf("refused: %v", err)

	// And nothing was copied.
	vol := volPath(p, "sandfs-evil")
	if _, serr := os.Stat(filepath.Join(vol, "secret")); serr == nil {
		t.Fatal("host content reached the tenant volume despite the refusal")
	}
}

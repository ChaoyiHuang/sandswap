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

package seed

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	sandlotconfig "sandlot/config"
	"sandlot/provision/volname"
	"sandlot/provision/volume"
)

// ─── fixtures ───

type fakeConfig struct {
	mu  sync.Mutex
	cfg sandlotconfig.SandlotConfig
}

func (f *fakeConfig) get() sandlotconfig.SandlotConfig {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.cfg
}

func (f *fakeConfig) set(cfg sandlotconfig.SandlotConfig) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cfg = cfg
}

func seedBytes(fill byte) []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = fill
	}
	return b
}

// writeSeedFile writes a hex seed (the documented form) and returns its path.
func writeSeedFile(t *testing.T, dir, name string, seed []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(hex.EncodeToString(seed)+"\n"), 0o600); err != nil {
		t.Fatalf("write seed %s: %v", name, err)
	}
	return p
}

// writeStamp stamps a volume directory with a SIGNED identity stamp under the
// given generation seed. Passing a seed no configured generation derives
// produces the seed-mix-up/tamper shape (the scan cannot authenticate it).
func writeStamp(t *testing.T, volRoot, name, id string, seed []byte) {
	t.Helper()
	dir := filepath.Join(volRoot, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := volume.WriteVolumeStampForTool(dir, id, "overlay", seed, 1); err != nil {
		t.Fatal(err)
	}
}

// writeForeignGenerationStamp writes a stamp whose signature verifies against
// signSeed but whose generation FIELD names a fingerprint that seed does not
// derive. The MAC covers the field, so this is only producible by whoever holds
// the seed (a migration/rotation bug, a stamp copied between generations) — the
// "foreign generation" reading, distinct from an unauthenticated (unverified)
// stamp.
func writeForeignGenerationStamp(t *testing.T, volRoot, name, id string, signSeed []byte, generation string) {
	t.Helper()
	dir := filepath.Join(volRoot, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	payload := fmt.Sprintf(
		"sandswap-volume-stamp-v1\nsandfs_id:%s\nvolume:%s\ngeneration:%s\nmode:overlay\nvolume_epoch:\ncreated_unix:1\n",
		id, name, generation,
	)
	mac := hmac.New(sha256.New, signSeed)
	mac.Write([]byte(payload))
	body := fmt.Sprintf("sandfs_id: %s\ngeneration: %s\nmode: overlay\nvolume_epoch: \ncreated_unix: 1\nsig: %s\n",
		id, generation, hex.EncodeToString(mac.Sum(nil)))
	if err := os.WriteFile(filepath.Join(dir, ".sandfs-id"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// writeUnsignedStamp places a stamp written by an unsigned build (or forged
// by a tenant): the scanner must never authenticate it.
func writeUnsignedStamp(t *testing.T, volRoot, name, id string) {
	t.Helper()
	dir := filepath.Join(volRoot, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf("sandfs_id: %s\ncreated_unix: 1\n", id)
	if err := os.WriteFile(filepath.Join(dir, ".sandfs-id"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

type harness struct {
	coord   *Coordinator
	namer   *volname.Map
	cfg     *fakeConfig
	volRoot string
	dir     string
}

func newHarness(t *testing.T, current []byte, allow bool) *harness {
	t.Helper()
	dir := t.TempDir()
	volRoot := filepath.Join(dir, "volumes")
	if err := os.MkdirAll(volRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	namer, err := volname.NewMap(current)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &fakeConfig{cfg: sandlotconfig.Defaults()}
	coord, err := New(Options{
		Config:                  cfg.get,
		Namer:                   namer,
		VolRoot:                 volRoot,
		StatePath:               filepath.Join(dir, StateFilename),
		Logger:                  log.New(os.Stderr, "[test] ", 0),
		AllowGenerationMismatch: allow,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &harness{coord: coord, namer: namer, cfg: cfg, volRoot: volRoot, dir: dir}
}

func (h *harness) setSeeds(t *testing.T, curPath, nextPath string) {
	t.Helper()
	cfg := sandlotconfig.Defaults()
	cfg.Provision.VolumeSeedFile = curPath
	cfg.Provision.VolumeSeedNextFile = nextPath
	h.cfg.set(cfg)
}

func (h *harness) state(t *testing.T) State {
	t.Helper()
	st, ok, err := ReadState(filepath.Join(h.dir, StateFilename))
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("no adoption record was written")
	}
	return st
}

// ─── transition lifecycle ───

// The full window: stage applies and is recorded; a promote with an un-renamed
// volume is refused BY THE DAEMON (the tool's gate is a pre-flight, not the
// enforcement); after the rename the promote lands.
func TestPromoteGateRefusesThenAllows(t *testing.T) {
	genA, genB := seedBytes(0xA1), seedBytes(0xB2)
	h := newHarness(t, genA, false)

	curPath := writeSeedFile(t, h.dir, "gen-a", genA)
	nextPath := writeSeedFile(t, h.dir, "gen-b", genB)
	h.setSeeds(t, curPath, "")
	if err := h.coord.Bootstrap(); err != nil {
		t.Fatal(err)
	}
	if err := h.coord.StartupGuard(); err != nil {
		t.Fatal(err)
	}

	// A volume created under generation A, not yet renamed.
	fpA, fpB := volname.Fingerprint(genA), volname.Fingerprint(genB)
	writeStamp(t, h.volRoot, "sf-one", "id-one", genA)

	h.setSeeds(t, curPath, nextPath)
	h.coord.Reconcile("test-stage")
	if !h.namer.HasNext() {
		t.Fatal("the staged generation must be applied")
	}
	if _, _, stagedFP := h.namer.GenerationSnapshot(); stagedFP != fpB {
		t.Fatalf("staged fingerprint = %s, want %s", stagedFP, fpB)
	}
	if st := h.state(t); !st.Staged || st.StagedFingerprint != fpB {
		t.Errorf("adoption record = %+v, want staged with %s", st, fpB)
	}

	// Promote while that volume still carries the old generation: refused.
	h.setSeeds(t, nextPath, "")
	h.coord.Reconcile("test-promote-early")
	if got := volname.Fingerprint(h.namer.CurrentSeed()); got != fpA {
		t.Fatalf("a refused promote must not move the current generation (now %s)", got)
	}
	if !h.namer.HasNext() {
		t.Error("a refused promote must keep the staging (the window stays open)")
	}
	if st := h.state(t); st.LastError == "" || !strings.Contains(st.LastError, "pre-promote generation") {
		t.Errorf("the refusal must be recorded with its reason, got %q", st.LastError)
	}

	// The rotation's rename step completes; the promote lands.
	writeStamp(t, h.volRoot, "sf-one", "id-one", genB)
	h.coord.Reconcile("test-promote")
	got := volname.Fingerprint(h.namer.CurrentSeed())
	if got != fpB {
		t.Fatalf("current fingerprint = %s, want the promoted %s", got, fpB)
	}
	if h.namer.HasNext() {
		t.Error("a promote must clear the staging")
	}
	if st := h.state(t); st.LastError != "" || st.Staged || st.CurrentFingerprint != fpB {
		t.Errorf("adoption record after promote = %+v", st)
	}
	if got := h.namer.Current("id-one"); got != volname.Derive(genB, "id-one") {
		t.Errorf("after promote the new generation must name volumes, got %s", got)
	}
}

// A CURRENT generation whose value changes outside the window is tampering:
// refused, alarmed, and never adopted — adopting it would orphan every volume
// at the next restart.
func TestTamperedCurrentIsRefusedAndNeverAdopted(t *testing.T) {
	genA, genEvil := seedBytes(0xC3), seedBytes(0xE5)
	h := newHarness(t, genA, false)

	curPath := writeSeedFile(t, h.dir, "gen-a", genA)
	h.setSeeds(t, curPath, "")
	if err := h.coord.Bootstrap(); err != nil {
		t.Fatal(err)
	}

	// An injector (or an attacker, or a rollback) replaces the current source's
	// value with a DIFFERENT, perfectly valid seed.
	writeSeedFile(t, h.dir, "gen-a", genEvil)
	h.coord.Reconcile("test-tamper")

	if got := volname.Fingerprint(h.namer.CurrentSeed()); got != volname.Fingerprint(genA) {
		t.Fatalf("a tampered current generation was adopted (now %s)", got)
	}
	if st := h.state(t); st.LastError == "" {
		t.Error("the tamper must be recorded in the adoption record")
	}
	if got := h.state(t).CurrentFingerprint; got != volname.Fingerprint(genA) {
		t.Errorf("the record must still name the generation actually in use, got %s", got)
	}
}

// A source that does not resolve yet (the injector has not materialized the
// staged file) is a retry, not a refusal: the live generations stay, and the
// moment the file appears the stage lands.
func TestUnresolvedNextIsRetriedThenStaged(t *testing.T) {
	genA, genB := seedBytes(0x11), seedBytes(0x22)
	h := newHarness(t, genA, false)

	curPath := writeSeedFile(t, h.dir, "gen-a", genA)
	nextPath := filepath.Join(h.dir, "gen-b-not-yet")
	h.setSeeds(t, curPath, nextPath)
	if err := h.coord.Bootstrap(); err != nil {
		t.Fatal(err)
	}
	if h.namer.HasNext() {
		t.Fatal("an unresolvable staged source must not stage anything")
	}
	h.coord.Reconcile("test-missing-next")
	if h.namer.HasNext() {
		t.Fatal("still nothing to stage")
	}
	if st := h.state(t); st.LastError == "" {
		t.Error("the unresolved source must be visible in the record")
	}

	// The injector materializes it; the next reconcile picks it up.
	writeSeedFile(t, h.dir, "gen-b-not-yet", genB)
	h.coord.Reconcile("test-next-appears")
	if !h.namer.HasNext() {
		t.Fatal("the staged generation must land once the source resolves")
	}
	if _, _, fp := h.namer.GenerationSnapshot(); fp != volname.Fingerprint(genB) {
		t.Errorf("staged fingerprint = %s, want %s", fp, volname.Fingerprint(genB))
	}
}

// An UNREADABLE generation stamp is an inconclusive reading of the disk-side
// authority, not an absent one: the volume it hides may still carry the
// generation the promote is about to drop, and the gate's own contract says an
// inconclusive scan refuses. (The directory was never renamed by --run either:
// the tool iterates records, so a rename that failed or a directory with no
// record is only ever visible through this scan.)
func TestPromoteGateRefusesUnreadableStamp(t *testing.T) {
	genA, genB := seedBytes(0x71), seedBytes(0x72)
	h := newHarness(t, genA, false)

	curPath := writeSeedFile(t, h.dir, "gen-a", genA)
	nextPath := writeSeedFile(t, h.dir, "gen-b", genB)
	h.setSeeds(t, curPath, "")
	if err := h.coord.Bootstrap(); err != nil {
		t.Fatal(err)
	}

	// A volume in the pre-promote generation whose stamp cannot be READ. The
	// tests run as root, where chmod 000 would not block the read, so a
	// DIRECTORY in the stamp's place is the faithful stand-in for the
	// guest-planted-mode / I/O-error class: os.ReadFile fails either way.
	writeStamp(t, h.volRoot, "sf-stuck", "id-stuck", genA)
	if err := os.Remove(filepath.Join(h.volRoot, "sf-stuck", ".sandfs-id")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(h.volRoot, "sf-stuck", ".sandfs-id"), 0o755); err != nil {
		t.Fatal(err)
	}

	h.setSeeds(t, curPath, nextPath)
	h.coord.Reconcile("test-stage")
	if !h.namer.HasNext() {
		t.Fatal("the staged generation must be applied")
	}

	h.setSeeds(t, nextPath, "")
	h.coord.Reconcile("test-promote-unreadable")

	if got := volname.Fingerprint(h.namer.CurrentSeed()); got != volname.Fingerprint(genA) {
		t.Fatalf("a promote with an unreadable stamp moved the current generation (now %s)", got)
	}
	if !h.namer.HasNext() {
		t.Error("the refusal must keep the staging (the window stays open)")
	}
	if st := h.state(t); !strings.Contains(st.LastError, "unreadable") {
		t.Errorf("the refusal must name the unreadable stamp, got %q", st.LastError)
	}
}

// A staged generation EQUAL to the current one is a NEXT-generation problem:
// the component's contract (Bootstrap's doc comment) says a bad NEXT
// generation is logged and skipped, because crash-looping is worse than
// running unstaged. The shape is reachable — rotate-volume-seed.sh --stage
// --seed-file <the current file> writes that key into the config and leaves it
// there when its adoption wait times out — and every restart of that prov host
// must keep working, not exit.
func TestBootstrapEqualStagedSeedRunsUnstaged(t *testing.T) {
	genA := seedBytes(0x91)
	h := newHarness(t, genA, false)

	curPath := writeSeedFile(t, h.dir, "gen-a", genA)
	nextPath := writeSeedFile(t, h.dir, "gen-dup", genA) // SAME material as current
	h.setSeeds(t, curPath, nextPath)

	if err := h.coord.Bootstrap(); err != nil {
		t.Fatalf("a staged generation equal to the current one must be logged and skipped, not fatal (a bad NEXT generation is logged and skipped; crash-looping there would be worse than running unstaged): %v", err)
	}
	if h.namer.HasNext() {
		t.Error("an equal staged generation must not be staged: a rotation would rename nothing")
	}
	if got := volname.Fingerprint(h.namer.CurrentSeed()); got != volname.Fingerprint(genA) {
		t.Errorf("the current generation moved: %s", got)
	}
	if st := h.state(t); st.Staged || st.CurrentFingerprint != volname.Fingerprint(genA) {
		t.Errorf("adoption record = %+v, want unstaged on the current generation", st)
	}

	// The runtime path agrees, non-fatally: the same tuple arriving through a
	// reconcile is a named refusal that never moves the map.
	h.coord.Reconcile("test-equal-next")
	if h.namer.HasNext() {
		t.Error("the reconcile path must not stage an equal generation either")
	}
	if st := h.state(t); st.LastError == "" {
		t.Error("the runtime refusal must be visible in the record")
	}
}

// ─── startup guard ───

func TestStartupGuardVerdicts(t *testing.T) {
	genA, genB := seedBytes(0x31), seedBytes(0x42)
	fpB := volname.Fingerprint(genB)

	t.Run("matching tree passes", func(t *testing.T) {
		h := newHarness(t, genA, false)
		writeStamp(t, h.volRoot, "sf-1", "id-1", genA)
		if err := h.coord.StartupGuard(); err != nil {
			t.Fatalf("a tree in the loaded generation must pass: %v", err)
		}
		if st := h.state(t); st.StartupScan == nil || st.StartupScan.Sampled != 1 || st.StartupScan.Foreign != 0 {
			t.Errorf("scan record = %+v", st.StartupScan)
		}
	})

	t.Run("staged generation also matches", func(t *testing.T) {
		h := newHarness(t, genA, false)
		if err := h.namer.Stage(genB); err != nil {
			t.Fatal(err)
		}
		writeStamp(t, h.volRoot, "sf-1", "id-1", genB) // already renamed
		writeStamp(t, h.volRoot, "sf-2", "id-2", genA) // not yet renamed
		if err := h.coord.StartupGuard(); err != nil {
			t.Fatalf("a partially rotated tree must pass: %v", err)
		}
	})

	t.Run("foreign generation refuses", func(t *testing.T) {
		h := newHarness(t, genA, false)
		// Signed by the LIVE seed but naming a generation it does not derive:
		// the tree-wide mix-up class, which stays fatal.
		writeForeignGenerationStamp(t, h.volRoot, "sf-1", "id-1", genA, fpB)
		err := h.coord.StartupGuard()
		if err == nil {
			t.Fatal("a tree no configured generation derives must refuse to start")
		}
		for _, want := range []string{"split tenants", "-allow-seed-generation-mismatch", fpB} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("refusal must mention %q, got: %v", want, err)
			}
		}
		if st := h.state(t); st.LastError == "" {
			t.Error("the refusal must be recorded")
		}
	})

	t.Run("foreign generation with the escape hatch", func(t *testing.T) {
		h := newHarness(t, genA, true)
		writeForeignGenerationStamp(t, h.volRoot, "sf-1", "id-1", genA, fpB)
		if err := h.coord.StartupGuard(); err != nil {
			t.Fatalf("the deliberate re-key path must be able to start: %v", err)
		}
	})

	t.Run("an unauthenticated stamp only warns", func(t *testing.T) {
		// One tampered stamp in an otherwise valid tree must not crash-loop
		// the storage plane: the volume is quarantined by every operation path
		// and the promote gate still refuses, but startup proceeds. (A tree
		// where EVERY sampled stamp is unverifiable is the tree-wide seed
		// mix-up case, which stays fatal below.)
		h := newHarness(t, genA, false)
		writeStamp(t, h.volRoot, "sf-2", "id-2", genA)
		writeUnsignedStamp(t, h.volRoot, "sf-1", "id-1")
		if err := h.coord.StartupGuard(); err != nil {
			t.Fatalf("an unsigned/unverifiable stamp must warn, not refuse to start: %v", err)
		}
		if st := h.state(t); st.StartupScan.Unverified != 1 {
			t.Errorf("the unverified stamp must be counted, got %+v", st.StartupScan)
		}
		if st := h.state(t); st.LastError == "" {
			t.Error("the unverified reading must be recorded for operators")
		}
		for _, name := range []string{"sf-1"} {
			if strings.Contains(h.state(t).LastError, name) {
				t.Errorf("the startup record must not carry a seed-derived volume name, got %q", h.state(t).LastError)
			}
		}
	})

	t.Run("an unstamped tree only warns", func(t *testing.T) {
		h := newHarness(t, genA, false)
		if err := os.MkdirAll(filepath.Join(h.volRoot, "sf-1"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := h.coord.StartupGuard(); err != nil {
			t.Fatalf("a tree with no stamps at all must not refuse to start: %v", err)
		}
		if st := h.state(t); st.StartupScan.Unstamped != 1 {
			t.Errorf("unstamped volumes must be counted, got %+v", st.StartupScan)
		}
	})

	t.Run("empty and missing roots pass", func(t *testing.T) {
		h := newHarness(t, genA, false)
		if err := h.coord.StartupGuard(); err != nil {
			t.Fatalf("an empty root must pass: %v", err)
		}
		h2 := newHarness(t, genA, false)
		if err := os.RemoveAll(h2.volRoot); err != nil {
			t.Fatal(err)
		}
		if err := h2.coord.StartupGuard(); err != nil {
			t.Fatalf("a missing root must pass (EnsureVolume owns that error): %v", err)
		}
	})
}

// An ABSENT volumes root is not "a clean tree with zero volumes": a promote
// against a root that was not read would drop the old generation while the
// real tree's volumes become unresolvable (delete answers false success,
// create builds a second tree). The startup guard deliberately stays lenient
// (an unprepared host must not become a crash-loop, and EnsureVolume owns the
// actionable error); the promote gate — the irreversible step — refuses.
func TestPromoteGateRefusesMissingRoot(t *testing.T) {
	genA, genB := seedBytes(0x51), seedBytes(0x52)
	h := newHarness(t, genA, false)

	curPath := writeSeedFile(t, h.dir, "gen-a", genA)
	nextPath := writeSeedFile(t, h.dir, "gen-b", genB)
	h.setSeeds(t, curPath, "")
	if err := h.coord.Bootstrap(); err != nil {
		t.Fatal(err)
	}
	h.setSeeds(t, curPath, nextPath)
	h.coord.Reconcile("test-stage")
	if !h.namer.HasNext() {
		t.Fatal("the staged generation must be applied")
	}

	// The root is unreadable at promote time (shared storage not mounted, a
	// config re-pointed at a path nothing created): the gate must refuse.
	if err := os.RemoveAll(h.volRoot); err != nil {
		t.Fatal(err)
	}
	h.setSeeds(t, nextPath, "")
	h.coord.Reconcile("test-promote-missing-root")

	if got := volname.Fingerprint(h.namer.CurrentSeed()); got != volname.Fingerprint(genA) {
		t.Fatalf("a promote against a missing volumes root moved the current generation (now %s)", got)
	}
	if !h.namer.HasNext() {
		t.Error("the refusal must keep the staging (the window stays open)")
	}
	if st := h.state(t); !strings.Contains(st.LastError, "does not exist") {
		t.Errorf("the refusal must name the absent root, got %q", st.LastError)
	}
}

// ─── runtime watching ───

// A new generation file appearing at a NEW path is picked up without any
// config edit only when the config already names it; what the watcher must
// catch is the file ARRIVING after the pointer moved — the injector ordering
// (pointer first, materialization second) that the plan calls routine.
func TestWatcherPicksUpMaterializedSource(t *testing.T) {
	genA, genB := seedBytes(0x77), seedBytes(0x88)
	h := newHarness(t, genA, false)
	curPath := writeSeedFile(t, h.dir, "gen-a", genA)
	nextPath := filepath.Join(h.dir, "gen-b")

	// The pointer names a file that does not exist yet.
	h.setSeeds(t, curPath, nextPath)
	if err := h.coord.Bootstrap(); err != nil {
		t.Fatal(err)
	}
	h.coord.Start() // installs watchers on both configured paths
	defer h.coord.Stop()

	// Bootstrap could not stage it; now the injector writes it.
	writeSeedFile(t, h.dir, "gen-b", genB)

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if h.namer.HasNext() {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if !h.namer.HasNext() {
		t.Fatal("the watcher did not pick up the materialized staged source")
	}
	if _, _, fp := h.namer.GenerationSnapshot(); fp != volname.Fingerprint(genB) {
		t.Fatalf("staged fingerprint = %s, want %s", fp, volname.Fingerprint(genB))
	}
}

// Under a writer that keeps replacing the current source with valid-looking
// values, the live current generation must NEVER move: each attempt is either
// a torn read (retried) or a tamper (refused). That invariant is what keeps an
// arbitrary injector from silently re-keying the tree.
func TestConcurrentReplacementNeverMovesCurrent(t *testing.T) {
	genA := seedBytes(0x99)
	h := newHarness(t, genA, false)
	curPath := writeSeedFile(t, h.dir, "gen-a", genA)
	h.setSeeds(t, curPath, "")
	if err := h.coord.Bootstrap(); err != nil {
		t.Fatal(err)
	}
	want := volname.Fingerprint(genA)

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { // the hostile/buggy writer: non-atomic in-place replacement
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			body := hex.EncodeToString(seedBytes(byte(i + 1)))
			_ = os.WriteFile(curPath, []byte(body), 0o600) // truncate+write, no rename
		}
	}()
	for i := 0; i < 200; i++ {
		h.coord.Reconcile("test-churn")
	}
	close(stop)
	wg.Wait()

	if got := volname.Fingerprint(h.namer.CurrentSeed()); got != want {
		t.Fatalf("the current generation moved under churn: %s (want %s)", got, want)
	}
}

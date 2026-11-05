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
	"io"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	commonconfig "common/config"
	sandlotconfig "sandlot/config"
	"sandlot/provision/volname"
)

// The rotation window's OPEN and CLOSE, driven through the real chain: a
// config-file edit → parse → flag reapply → validate → diff → the reload
// callback's seed trigger → the coordinator's resolution → the namer's
// transition table. The rotation drill caught this chain once silently
// dropping the staged key, so the pin lives here: the apply leg IS the
// coordinator, and this test is what keeps it wired to the config watcher.
func TestReloadChainStagesThenPromotes(t *testing.T) {
	dir := t.TempDir()
	genA, genB := seedBytes(0xC1), seedBytes(0xC2)
	seedA := writeSeedFile(t, dir, "seed-a", genA)
	seedBFile := writeSeedFile(t, dir, "seed-b", genB)
	volRoot := filepath.Join(dir, "volumes")
	if err := os.MkdirAll(volRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "sandlot.yaml")
	body := "roles: [exec,prov]\nmicrovm:\n  volumes_dir: " + volRoot +
		"\nprovision:\n  volume_seed_file: " + seedA + "\n"
	if err := os.WriteFile(cfgPath, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := sandlotconfig.LoadFromFile(cfgPath)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	cfg.ConfigFilePath = cfgPath
	// Config-file mode: no CLI flags set, so the reapplier has nothing to
	// override (mirrors the -config deployment shape).
	cfg.SetFlagReapplier(func(*sandlotconfig.SandlotConfig) {})

	namer, err := volname.NewMap(genA)
	if err != nil {
		t.Fatal(err)
	}
	live := commonconfig.NewWatchableConfig(cfg)
	coord, err := New(Options{
		Config:    func() sandlotconfig.SandlotConfig { return live.Get() },
		Namer:     namer,
		VolRoot:   volRoot,
		StatePath: filepath.Join(dir, StateFilename),
		Logger:    log.New(os.Stderr, "[reload-test] ", 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := coord.Bootstrap(); err != nil {
		t.Fatal(err)
	}

	cb := sandlotconfig.NewReloadCallback(live, &sandlotconfig.HotReloadTargets{
		ReconcileSeeds: func() error { return coord.Reconcile("config-reload") },
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	// The staged edit: the config gains volume_seed_next_file beside the
	// current generation's key — exactly what the rotation tooling writes.
	cb([]byte("roles: [exec,prov]\nmicrovm:\n  volumes_dir: " + volRoot +
		"\nprovision:\n  volume_seed_file: " + seedA +
		"\n  volume_seed_next_file: " + seedBFile + "\n"))
	if !namer.HasNext() {
		t.Fatal("the staged generation never reached the namer")
	}
	if _, _, fp := namer.GenerationSnapshot(); fp != volname.Fingerprint(genB) {
		t.Fatalf("staged fingerprint = %s, want %s", fp, volname.Fingerprint(genB))
	}

	// The promoting edit: re-point volume_seed_file at the staged file and drop
	// the staged key (what a correct --promote writes). The volume tree is
	// empty, so the completeness gate passes.
	cb([]byte("roles: [exec,prov]\nmicrovm:\n  volumes_dir: " + volRoot +
		"\nprovision:\n  volume_seed_file: " + seedBFile + "\n"))
	if got := volname.Fingerprint(namer.CurrentSeed()); got != volname.Fingerprint(genB) {
		t.Fatalf("current fingerprint = %s, want the promoted %s", got, volname.Fingerprint(genB))
	}
	if namer.HasNext() {
		t.Error("the promoting reload must clear the staging")
	}
	if st, ok, err := ReadState(filepath.Join(dir, StateFilename)); err != nil || !ok {
		t.Fatalf("adoption record: ok=%v err=%v", ok, err)
	} else if st.CurrentFingerprint != volname.Fingerprint(genB) {
		t.Errorf("adoption record names %s, want the promoted generation", st.CurrentFingerprint)
	}
}

// A seed edit on an instance with NO provision role is refused (the trigger is
// nil), leaving the reload otherwise applied.
func TestReloadSeedEditWithoutProvRole(t *testing.T) {
	cfg := sandlotconfig.Defaults()
	cfg.ConfigFilePath = "/etc/sandswap/sandlot.yaml"
	live := commonconfig.NewWatchableConfig(cfg)
	cb := sandlotconfig.NewReloadCallback(live, &sandlotconfig.HotReloadTargets{},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	// No ReconcileSeeds target: the case must be skipped without panicking.
	cb([]byte("provision:\n  volume_seed_file: /etc/sandswap/volume-seed\n"))
}

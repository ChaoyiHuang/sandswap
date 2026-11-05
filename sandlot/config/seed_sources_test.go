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

package config

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sandlot/provision/volname"
)

// writeSeedFile writes a hex seed and returns its path.
func writeSeedFile(t *testing.T, dir, name string, fill byte) (string, []byte) {
	t.Helper()
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = fill
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(hex.EncodeToString(raw)+"\n"), 0o600); err != nil {
		t.Fatalf("write seed %s: %v", name, err)
	}
	return p, raw
}

// The source descriptor is what the adoption state file, the reload logs and
// the host verifier print — it must name the injected channel without
// carrying any seed material.
func TestSeedSourcesReportChannels(t *testing.T) {
	dir := t.TempDir()
	curPath, curRaw := writeSeedFile(t, dir, "seed-cur", 0x11)
	nextPath, _ := writeSeedFile(t, dir, "seed-next", 0x22)

	p := ProvisionConfig{VolumeSeedFile: curPath, VolumeSeedNextFile: nextPath}
	srcs := p.SeedSources()
	if len(srcs) != 2 {
		t.Fatalf("sources = %+v, want both generations", srcs)
	}
	if srcs[0].Generation != "current" || srcs[0].Kind != SeedSourceFile || srcs[0].Path != curPath {
		t.Errorf("current source = %+v, want file:%s", srcs[0], curPath)
	}
	if srcs[1].Generation != "next" || srcs[1].Path != nextPath {
		t.Errorf("next source = %+v, want file:%s", srcs[1], nextPath)
	}
	if got := srcs[0].String(); got != "file:"+curPath {
		t.Errorf("String() = %q", got)
	}
	if !p.SeedConfigured("current") || !p.SeedConfigured("next") {
		t.Error("both generations are configured")
	}
	cur, src, err := p.CurrentSeed()
	if err != nil {
		t.Fatalf("current: %v", err)
	}
	if string(cur) != string(curRaw) || src.Path != curPath {
		t.Errorf("current resolved to %x via %+v", cur, src)
	}

	// An unconfigured source has no kind and is not "configured".
	if (ProvisionConfig{}).SeedConfigured("current") {
		t.Error("an empty provision block configures nothing")
	}
	if srcs := (ProvisionConfig{}).SeedSources(); len(srcs) != 0 {
		t.Errorf("sources = %+v, want none", srcs)
	}
}

// A missing NEXT source is a different class from a missing CURRENT one: an
// injector may not have materialized the staged file yet. Callers retry the
// former (the reload path refuses the transition and waits) and fail closed on
// the latter — so the two must be distinguishable by the error and by which
// method returns it.
func TestNextSeedFailureIsDistinguishableFromCurrent(t *testing.T) {
	dir := t.TempDir()
	curPath, _ := writeSeedFile(t, dir, "seed-cur", 0x33)

	p := ProvisionConfig{VolumeSeedFile: curPath, VolumeSeedNextFile: filepath.Join(dir, "not-materialized")}
	if _, _, err := p.CurrentSeed(); err != nil {
		t.Fatalf("the current generation must resolve: %v", err)
	}
	_, _, err := p.NextSeed()
	if err == nil {
		t.Fatal("an unreadable next source must be an error")
	}
	if !strings.HasPrefix(err.Error(), "provision.volume_seed_next:") {
		t.Errorf("next failure must name the next key, got: %v", err)
	}
	// The strict form (the reload path) refuses the edit whole.
	if _, _, err := p.VolumeSeeds(); err == nil {
		t.Error("VolumeSeeds must refuse a half-resolvable pair")
	}

	// No next configured at all is NOT an error: (nil, ..., nil).
	p2 := ProvisionConfig{VolumeSeedFile: curPath}
	next, src, err := p2.NextSeed()
	if err != nil || next != nil || src.Kind != "" {
		t.Errorf("unconfigured next = (%v, %+v, %v), want (nil, zero, nil)", next, src, err)
	}
	if _, next, err := p2.VolumeSeeds(); err != nil || next != nil {
		t.Errorf("strict form with no next = (%v, %v), want (nil, nil)", next, err)
	}
}

// Relative seed paths resolve against the config's directory — how the deploy
// scripts write them and what template-tool assumed. The daemon used to
// resolve them against its process CWD, so one config worked for the tool and
// failed for the instance.
func TestLoadResolvesRelativeSeedPaths(t *testing.T) {
	dir := t.TempDir()
	writeSeedFile(t, dir, "seed-cur", 0x44)
	writeSeedFile(t, dir, "seed-next", 0x55)
	cfgPath := filepath.Join(dir, "sandlot.yaml")
	body := "roles: [exec,prov]\nmicrovm:\n  volumes_dir: " + dir +
		"\nprovision:\n  volume_seed_file: seed-cur\n  volume_seed_next_file: ./seed-next\n"
	if err := os.WriteFile(cfgPath, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadFromFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Provision.VolumeSeedFile; got != filepath.Join(dir, "seed-cur") {
		t.Errorf("current seed path = %q, want it resolved against the config dir", got)
	}
	if got := cfg.Provision.VolumeSeedNextFile; got != filepath.Join(dir, "seed-next") {
		t.Errorf("next seed path = %q, want it resolved against the config dir", got)
	}
	// Absolute paths pass through untouched, and re-resolution is idempotent.
	cfg.ResolveSeedFilePaths("/somewhere/else")
	if got := cfg.Provision.VolumeSeedFile; got != filepath.Join(dir, "seed-cur") {
		t.Errorf("absolute paths must not be re-resolved, got %q", got)
	}
	if _, _, err := cfg.Provision.VolumeSeeds(); err != nil {
		t.Errorf("resolved pair must load: %v", err)
	}
}

// A seed-file flag is re-pinned on every reload, so a config that also names
// one is ambiguous: the file's value would be silently shadowed and a
// config-file promote would never reach the namer.
func TestVolumeSeedFileFlagConflicts(t *testing.T) {
	cfg := Defaults()
	cfg.Provision.VolumeSeedFile = "/etc/sandswap/volume-seed"
	flags := &SandlotFlags{ProvisionVolumeSeedFile: "/other/seed"}
	cfg.ApplyFlagOverrides(flags, map[string]bool{"volume-seed-file": true})
	err := cfg.ApplyError()
	if err == nil {
		t.Fatal("flag + config key for the same generation must be refused")
	}
	if !strings.Contains(err.Error(), "both set") || !strings.Contains(err.Error(), "re-pinned") {
		t.Errorf("refusal must name the ambiguity and the reason, got: %v", err)
	}

	// The flag alone (no config key) still applies — the flag-only shapes.
	cfg2 := Defaults()
	cfg2.ApplyFlagOverrides(flags, map[string]bool{"volume-seed-file": true})
	if err := cfg2.ApplyError(); err != nil {
		t.Fatalf("a flag-only shape must keep working: %v", err)
	}
	if cfg2.Provision.VolumeSeedFile != "/other/seed" {
		t.Errorf("flag value not applied: %q", cfg2.Provision.VolumeSeedFile)
	}

	// Symmetrically for the staged generation.
	cfg3 := Defaults()
	cfg3.Provision.VolumeSeedNextFile = "/etc/sandswap/volume-seed-next"
	cfg3.ApplyFlagOverrides(&SandlotFlags{ProvisionVolumeSeedNextFile: "/other/next"}, map[string]bool{"volume-seed-next-file": true})
	if cfg3.ApplyError() == nil {
		t.Error("flag + config key for the staged generation must be refused")
	}
}

// The inline form keeps working and is reported as the inline channel.
func TestInlineSeedSource(t *testing.T) {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = 0x66
	}
	p := ProvisionConfig{VolumeSeed: hex.EncodeToString(raw)}
	seed, src, err := p.CurrentSeed()
	if err != nil {
		t.Fatal(err)
	}
	if string(seed) != string(raw) {
		t.Error("inline seed did not decode to the configured bytes")
	}
	if src.Kind != SeedSourceInline || src.Path != "" {
		t.Errorf("source = %+v, want the inline channel with no path", src)
	}
	if got := volname.Fingerprint(seed); got == "" {
		t.Error("fingerprint must be derivable from the resolved seed")
	}
	// Inline and file for one generation stays refused as ambiguous.
	p2 := ProvisionConfig{VolumeSeed: hex.EncodeToString(raw), VolumeSeedFile: "/x"}
	if _, _, err := p2.CurrentSeed(); err == nil || !strings.Contains(err.Error(), "both set") {
		t.Errorf("inline + file must be refused, got: %v", err)
	}
}

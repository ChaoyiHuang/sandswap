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

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// testSeedHex is a valid 32-byte volume-name seed in its hex form (the shape
// `openssl rand -hex 32` produces and the deploy scripts write).
const testSeedHex = "5f4dcc3b5aa765d61d8327deb882cf99a3f7a6c1b0a4e2d8f1c3b5a79e0d2f4c"

// TestResolveSeed covers every seed-resolution outcome the rotation tool
// distinguishes: inline value, file value, the both-set refusal, the
// per-generation empty messages, and a value that decodes to nothing usable.
func TestResolveSeed(t *testing.T) {
	dir := t.TempDir()
	seedFile := filepath.Join(dir, "seed")
	if err := os.WriteFile(seedFile, []byte(testSeedHex), 0o600); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name    string
		cfg     ProvisionConfigLike
		gen     string
		wantErr string // "" = must succeed
	}{
		{
			name: "inline current",
			cfg:  ProvisionConfigLike{Seed: testSeedHex},
			gen:  "current",
		},
		{
			name: "seed from file",
			cfg:  ProvisionConfigLike{SeedFile: seedFile},
			gen:  "current",
		},
		{
			name: "inline next",
			cfg:  ProvisionConfigLike{SeedNext: testSeedHex},
			gen:  "next",
		},
		{
			name:    "current both set",
			cfg:     ProvisionConfigLike{Seed: testSeedHex, SeedFile: seedFile},
			gen:     "current",
			wantErr: "both set",
		},
		{
			name:    "next both set",
			cfg:     ProvisionConfigLike{SeedNext: testSeedHex, SeedNextFile: seedFile},
			gen:     "next",
			wantErr: "both set",
		},
		{
			name:    "no current seed",
			cfg:     ProvisionConfigLike{},
			gen:     "current",
			wantErr: "no current seed configured",
		},
		{
			name:    "no staged seed",
			cfg:     ProvisionConfigLike{},
			gen:     "next",
			wantErr: "no seed is staged",
		},
		{
			name:    "undecodable seed",
			cfg:     ProvisionConfigLike{Seed: "not hex nor base64 !!!"},
			gen:     "current",
			wantErr: "neither hex nor base64",
		},
		{
			name:    "weak seed",
			cfg:     ProvisionConfigLike{Seed: "abcd"},
			gen:     "current",
			wantErr: "need at least",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveSeed(tc.cfg, tc.gen)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("resolveSeed: %v", err)
				}
				if len(got) != 32 {
					t.Fatalf("decoded seed = %d bytes, want 32", len(got))
				}
				return
			}
			if err == nil {
				t.Fatal("expected an error, got success")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q must mention %q", err.Error(), tc.wantErr)
			}
		})
	}
}

// TestLoadProvSeedConfig verifies the real-loader path: a provision section
// with an inline seed round-trips, and the strict decoder rejects both a
// malformed file and an unknown key (a dead key must never silently yield an
// empty seed).
func TestLoadProvSeedConfig(t *testing.T) {
	dir := t.TempDir()

	good := filepath.Join(dir, "prov.yaml")
	if err := os.WriteFile(good, []byte("provision:\n  volume_seed: "+testSeedHex+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadProvSeedConfig(good)
	if err != nil {
		t.Fatalf("load valid config: %v", err)
	}
	if cfg.VolumeSeed != testSeedHex {
		t.Fatalf("VolumeSeed = %q, want the seeded value", cfg.VolumeSeed)
	}

	bad := filepath.Join(dir, "malformed.yaml")
	if err := os.WriteFile(bad, []byte("provision: ["), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadProvSeedConfig(bad); err == nil {
		t.Fatal("malformed YAML must fail the load")
	}

	unknown := filepath.Join(dir, "unknown-key.yaml")
	if err := os.WriteFile(unknown, []byte("provision:\n  volume_seed: "+testSeedHex+"\n  volume_seed_legacy: x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadProvSeedConfig(unknown); err == nil {
		t.Fatal("an unknown key must fail the strict load, not silently default")
	}

	if _, err := loadProvSeedConfig(filepath.Join(dir, "absent.yaml")); err == nil {
		t.Fatal("an absent config file must fail the load")
	}
}

// TestVolumeStampReadCmdArguments pins the command wrapper's validation: a
// missing --volume and an unknown --field are usage errors (exit 2), and a
// volume with no stamp reports absence with exit 0 (the caller decides what
// absent means).
func TestVolumeStampReadCmdArguments(t *testing.T) {
	if rc := volumeStampReadCmd(nil); rc != 2 {
		t.Fatalf("no --volume: rc = %d, want 2", rc)
	}
	if rc := volumeStampReadCmd([]string{"--volume", t.TempDir(), "--field", "nope"}); rc != 2 {
		t.Fatalf("unknown --field: rc = %d, want 2", rc)
	}
	if rc := volumeStampReadCmd([]string{"--volume", filepath.Join(t.TempDir(), "no-stamp-here")}); rc != 0 {
		t.Fatalf("absent stamp: rc = %d, want 0 (absence is not an error)", rc)
	}
}

// TestVolumeStampWriteAndReadRoundTrip drives the rotation tool's re-sign and
// read commands against a real volume directory: write with the prov config's
// current seed, then read every field back.
func TestVolumeStampWriteAndReadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	provConfig := filepath.Join(dir, "prov.yaml")
	if err := os.WriteFile(provConfig, []byte("provision:\n  volume_seed: "+testSeedHex+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	vol := filepath.Join(dir, "sandfs-abc123")
	if err := os.Mkdir(vol, 0o755); err != nil {
		t.Fatal(err)
	}

	if rc := volumeStampWriteCmd([]string{
		"--prov-config", provConfig,
		"--volume", vol,
		"--id", "sandfs-abc123",
		"--mode", "flat",
	}); rc != 0 {
		t.Fatalf("volume-stamp-write: rc = %d, want 0", rc)
	}

	if rc := volumeStampReadCmd([]string{"--volume", vol, "--field", "sandfs_id"}); rc != 0 {
		t.Fatalf("volume-stamp-read sandfs_id: rc = %d, want 0", rc)
	}
	if rc := volumeStampReadCmd([]string{"--volume", vol, "--field", "mode"}); rc != 0 {
		t.Fatalf("volume-stamp-read mode: rc = %d, want 0", rc)
	}

	// A bad generation is refused before anything is touched.
	if rc := volumeStampWriteCmd([]string{
		"--prov-config", provConfig,
		"--volume", vol,
		"--id", "sandfs-abc123",
		"--generation", "someday",
	}); rc != 2 {
		t.Fatalf("bad --generation: rc = %d, want 2", rc)
	}
	// A config without any seed refuses the write (exit 1, not a silent
	// default).
	empty := filepath.Join(dir, "empty.yaml")
	if err := os.WriteFile(empty, []byte("provision: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if rc := volumeStampWriteCmd([]string{
		"--prov-config", empty,
		"--volume", vol,
		"--id", "sandfs-abc123",
	}); rc != 1 {
		t.Fatalf("seedless config: rc = %d, want 1", rc)
	}
}

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
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"sandlot/config"
	"sandlot/provision/volname"
	"sandlot/provision/volume"
)

// volumeNameCmd implements the seed-derived volume directory naming helpers
// (see sandlot/provision/volname) that the rotation tooling drives:
//
//	template-tool volume-name --prov-config <path> --id <sandfs-id> [--generation current|next]
//	template-tool seed-generate [--out <file>]
//	template-tool seed-scan --prov-config <path> [--json]
//
// The seed is read from the prov config (inline value or the file it points
// at) and never appears in argv or stdout: a leaked seed makes every volume
// name guessable again. seed-scan reports the volumes root's generation
// histogram and the promote completeness verdict — the SAME reading the prov
// instance's own guard takes (sandlot/provision/volume.ScanGenerationStamps),
// so the tool's pre-flight and the daemon's enforcement can never disagree.
func volumeNameCmd(cmd string, args []string) int {
	switch cmd {
	case "seed-scan":
		return seedScanCmd(args)

	case "volume-stamp-read":
		return volumeStampReadCmd(args)

	case "volume-stamp-write":
		return volumeStampWriteCmd(args)

	case "seed-generate":
		fs := flag.NewFlagSet("seed-generate", flag.ContinueOnError)
		out := fs.String("out", "", "write the seed to this file (0600) instead of stdout")
		if err := fs.Parse(args); err != nil {
			return 2
		}
		seed := volname.GenerateSeed()
		if *out == "" {
			fmt.Println(seed)
			return 0
		}
		if err := os.WriteFile(*out, []byte(seed+"\n"), 0o600); err != nil {
			fmt.Fprintf(os.Stderr, "template-tool seed-generate: %v\n", err)
			return 1
		}
		fmt.Fprintf(os.Stderr, "template-tool: seed written to %s (keep it — every volume name derives from it)\n", *out)
		return 0
	default: // volume-name
		fs := flag.NewFlagSet("volume-name", flag.ContinueOnError)
		provConfig := fs.String("prov-config", "/etc/sandswap/sandlot-prov.yaml", "prov-role config carrying provision.volume_seed[_file]")
		id := fs.String("id", "", "sandfs id")
		generation := fs.String("generation", "current", "current | next (next requires a staged seed)")
		fingerprintOnly := fs.Bool("fingerprint", false, "print the generation's non-secret fingerprint instead of a derived name (for the volume identity stamp)")
		if err := fs.Parse(args); err != nil {
			return 2
		}
		if *id == "" && !*fingerprintOnly {
			fmt.Fprintln(os.Stderr, "template-tool volume-name: --id is required (or use --fingerprint)")
			return 2
		}
		switch *generation {
		case "current", "next":
		default:
			fmt.Fprintf(os.Stderr, "template-tool volume-name: --generation must be current or next (got %q)\n", *generation)
			return 2
		}
		pcfg, err := loadProvSeedConfig(*provConfig)
		if err != nil {
			fmt.Fprintf(os.Stderr, "template-tool volume-name: %v\n", err)
			return 1
		}
		// Resolve ONLY the generation asked for: a tool call for the current
		// name must not fail because a half-configured staged key sits in the
		// file, and vice versa.
		seed, err := resolveSeed(ProvisionConfigLike{
			Seed: pcfg.VolumeSeed, SeedFile: pcfg.VolumeSeedFile,
			SeedNext: pcfg.VolumeSeedNext, SeedNextFile: pcfg.VolumeSeedNextFile,
		}, *generation)
		if err != nil {
			fmt.Fprintf(os.Stderr, "template-tool volume-name: %v\n", err)
			return 1
		}
		if *fingerprintOnly {
			fmt.Println(volname.Fingerprint(seed))
			return 0
		}
		fmt.Println(volname.Derive(seed, *id))
		return 0
	}
}

// seedScanCmd reads every volume's generation stamp under the configured
// volumes root and prints the promote completeness verdict. Exit 0 = the
// promote gate passes, 1 = it refuses, 2 = the scan could not be made.
func seedScanCmd(args []string) int {
	fs := flag.NewFlagSet("seed-scan", flag.ContinueOnError)
	provConfig := fs.String("prov-config", "/etc/sandswap/sandlot-prov.yaml", "prov-role config (names the volumes root and the seed generations)")
	asJSON := fs.Bool("json", false, "print one JSON object on stdout (for tooling)")
	workers := fs.Int("workers", 16, "concurrent stamp reads")
	deadlineSec := fs.Int("deadline-sec", 30, "bound on how long new directories are scheduled")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := config.LoadFromFile(*provConfig)
	if err != nil {
		fmt.Fprintf(os.Stderr, "template-tool seed-scan: %v\n", err)
		return 2
	}
	cur, _, err := cfg.Provision.CurrentSeed()
	if err != nil {
		fmt.Fprintf(os.Stderr, "template-tool seed-scan: %v\n", err)
		return 2
	}
	curFP := volname.Fingerprint(cur)
	stagedFP := ""
	// A staged generation that does not resolve yet is not an error here: the
	// gate keys on the CURRENT generation, which is what a promote drops.
	if next, _, nerr := cfg.Provision.NextSeed(); nerr == nil && next != nil {
		stagedFP = volname.Fingerprint(next)
	}
	known := []string{curFP}
	if stagedFP != "" {
		known = append(known, stagedFP)
	}
	seeds := [][]byte{cur}
	if stagedFP != "" {
		if next, _, nerr := cfg.Provision.NextSeed(); nerr == nil && next != nil {
			seeds = append(seeds, next)
		}
	}
	res, err := volume.ScanGenerationStamps(cfg.MicroVM.VolumesDir, volume.ScanOptions{
		Known:    known,
		Seeds:    seeds,
		Workers:  *workers,
		Deadline: time.Duration(*deadlineSec) * time.Second,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "template-tool seed-scan: %v\n", err)
		return 2
	}
	// The verdict: a promote drops the current generation, so every volume
	// still carrying it — or carrying no usable generation at all — would
	// become permanently unresolvable (delete answers false success, create
	// builds a second tree). An unfinished scan cannot prove the tree is
	// clean, an ABSENT root was not scanned at all (a missing root reads as
	// zero volumes — the one case where "0 volumes" must be met with
	// suspicion, the daemon's gate refuses it too), and an unreadable stamp is
	// an inconclusive reading of the disk-side authority. This is the
	// irreversible step, so all three refuse.
	stale := res.GenerationCount(curFP)
	legacy := res.LegacyCount()
	pass := res.Complete && !res.RootMissing && stale == 0 && legacy == 0 && res.ReadErrors == 0 && res.Unverified == 0

	out := struct {
		VolumesRoot        string         `json:"volumes_root"`
		CurrentFingerprint string         `json:"current_fingerprint"`
		StagedFingerprint  string         `json:"staged_fingerprint,omitempty"`
		Sampled            int            `json:"sampled"`
		ByGeneration       map[string]int `json:"by_generation"`
		Unstamped          int            `json:"unstamped"`
		PreGeneration      int            `json:"pre_generation"`
		Foreign            int            `json:"foreign"`
		Examples           []string       `json:"examples"`
		Partial            int            `json:"partial"`
		ReadErrors         int            `json:"read_errors"`
		Unverified         int            `json:"unverified"`
		Complete           bool           `json:"complete"`
		RootMissing        bool           `json:"root_missing"`
		StaleCurrent       int            `json:"stale_current"`
		Legacy             int            `json:"legacy"`
		GatePass           bool           `json:"gate_pass"`
	}{
		VolumesRoot: cfg.MicroVM.VolumesDir, CurrentFingerprint: curFP, StagedFingerprint: stagedFP,
		Sampled: res.Sampled, ByGeneration: res.ByGeneration,
		Unstamped: res.Unstamped, PreGeneration: res.PreGeneration, Foreign: res.Foreign,
		Examples: res.Examples, Partial: res.Partial, ReadErrors: res.ReadErrors, Unverified: res.Unverified,
		Complete: res.Complete, RootMissing: res.RootMissing, StaleCurrent: stale, Legacy: legacy, GatePass: pass,
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(out); err != nil {
			fmt.Fprintf(os.Stderr, "template-tool seed-scan: %v\n", err)
			return 2
		}
	} else {
		fmt.Printf("volumes root:        %s\n", out.VolumesRoot)
		fmt.Printf("current generation:  %s (%d volume(s))\n", out.CurrentFingerprint, res.GenerationCount(curFP))
		if stagedFP != "" {
			fmt.Printf("staged generation:   %s (%d volume(s))\n", stagedFP, res.GenerationCount(stagedFP))
		}
		fmt.Printf("sampled:             %d (partial runs skipped: %d, unreadable stamps: %d, unauthenticated stamps: %d)\n", out.Sampled, out.Partial, out.ReadErrors, out.Unverified)
		fmt.Printf("no usable stamp:     %d unstamped + %d pre-generation\n", out.Unstamped, out.PreGeneration)
		fmt.Printf("unconfigured:        %d\n", out.Foreign)
		for _, ex := range out.Examples {
			fmt.Printf("  %s\n", ex)
		}
		if !out.Complete {
			fmt.Printf("PROMOTE GATE: REFUSE — the scan ran out of time after %d directories and cannot prove the tree is clean\n", out.Sampled)
		} else if res.RootMissing {
			fmt.Printf("PROMOTE GATE: REFUSE — the volumes root does not exist; nothing was scanned and a promote would strand the real tree\n")
		} else if res.ReadErrors > 0 {
			fmt.Printf("PROMOTE GATE: REFUSE — %d volume(s) carry an unreadable generation stamp; the reading is inconclusive\n", res.ReadErrors)
		} else if pass {
			fmt.Printf("PROMOTE GATE: PASS — no volume still carries the current generation\n")
		} else {
			fmt.Printf("PROMOTE GATE: REFUSE — %d volume(s) still carry the current generation %s and %d carry no usable stamp\n", stale, curFP, legacy)
		}
	}
	if pass {
		return 0
	}
	return 1
}

// resolveSeed returns the seed bytes for one generation, tolerating a broken
// or absent entry for the OTHER one.
func resolveSeed(p ProvisionConfigLike, generation string) ([]byte, error) {
	inline, file := p.Seed, p.SeedFile
	if generation == "next" {
		inline, file = p.SeedNext, p.SeedNextFile
	}
	if inline != "" && file != "" {
		return nil, fmt.Errorf("%s and its _file variant are both set — pick one", generation)
	}
	raw := inline
	if file != "" {
		b, err := os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("read %s seed file: %w", generation, err)
		}
		raw = string(b)
	}
	if strings.TrimSpace(raw) == "" {
		if generation == "next" {
			return nil, fmt.Errorf("no seed is staged (volume_seed_next[_file] unset)")
		}
		return nil, fmt.Errorf("no current seed configured (volume_seed[_file] unset)")
	}
	return volname.DecodeSeed(raw)
}

// ProvisionConfigLike is the slice of provision config a seed resolution needs
// (keeps this helper testable without the whole config type).
type ProvisionConfigLike struct {
	Seed, SeedFile, SeedNext, SeedNextFile string
}

// loadProvSeedConfig parses the provision section of a prov config file. It
// goes through the real loader (not a key scan) so a malformed file fails here
// instead of silently yielding an empty seed; the loader also resolves
// relative seed FILE paths against the config's directory (how the deploy
// scripts write them), so the tool and the running instance agree.
func loadProvSeedConfig(path string) (config.ProvisionConfig, error) {
	cfg, err := config.LoadFromFile(path)
	if err != nil {
		return config.ProvisionConfig{}, fmt.Errorf("load %s: %w", path, err)
	}
	return cfg.Provision, nil
}

// volumeStampReadCmd reads a volume's identity stamp through the hardened
// reader. The rotation tooling must never grep or redirect this file: in flat
// mode it lives in the tenant's chroot, where a planted symlink turns a
// root-run read/write into an arbitrary host-file operation.
func volumeStampReadCmd(args []string) int {
	fs := flag.NewFlagSet("volume-stamp-read", flag.ContinueOnError)
	volumePath := fs.String("volume", "", "volume directory")
	field := fs.String("field", "", "print only one field (sandfs_id|generation|mode|created_unix)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *volumePath == "" {
		fmt.Fprintln(os.Stderr, "template-tool volume-stamp-read: --volume is required")
		return 2
	}
	switch *field {
	case "", "sandfs_id", "generation", "mode", "created_unix":
	default:
		fmt.Fprintf(os.Stderr, "template-tool volume-stamp-read: unknown --field %q\n", *field)
		return 2
	}
	info, ok, err := volume.ReadVolumeStampForTool(*volumePath)
	if err != nil {
		// Exists but is unsafe/unreadable (symlink, FIFO, oversize, I/O):
		// tampering, not "absent". The caller must refuse to proceed.
		fmt.Fprintf(os.Stderr, "template-tool volume-stamp-read: %v\n", err)
		return 1
	}
	if !ok {
		return 0 // absent — the caller decides what that means
	}
	switch *field {
	case "sandfs_id":
		fmt.Println(info.SandfsID)
	case "generation":
		fmt.Println(info.Generation)
	case "mode":
		fmt.Println(info.Mode)
	case "created_unix":
		fmt.Printf("%d\n", info.CreatedUnix)
	default:
		fmt.Printf("sandfs_id: %s\ngeneration: %s\nmode: %s\ncreated_unix: %d\n",
			info.SandfsID, info.Generation, info.Mode, info.CreatedUnix)
	}
	return 0
}

// volumeStampWriteCmd re-signs a volume's identity stamp after a rotation
// rename. It preserves the mode and creation time from the existing stamp
// (both are covered by the MAC, so they must survive the re-sign), writes
// through CreateTemp+rename (O_EXCL, never a followed path), and refuses an
// existing entry that is not a plain readable file.
func volumeStampWriteCmd(args []string) int {
	fs := flag.NewFlagSet("volume-stamp-write", flag.ContinueOnError)
	provConfig := fs.String("prov-config", "/etc/sandswap/sandlot-prov.yaml", "prov-role config carrying provision.volume_seed[_file]")
	volumePath := fs.String("volume", "", "volume directory")
	id := fs.String("id", "", "sandfs id")
	generation := fs.String("generation", "current", "current | next")
	mode := fs.String("mode", "", "mode override (default: preserve the existing stamp's value)")
	created := fs.Int64("created-unix", 0, "creation time override (default: preserve, else now)")
	previousName := fs.String("previous-name", "", "directory name the existing stamp was signed for (rotation rename); enables preserving mode/created/volume_epoch across the rename")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *volumePath == "" || *id == "" {
		fmt.Fprintln(os.Stderr, "template-tool volume-stamp-write: --volume and --id are required")
		return 2
	}
	switch *generation {
	case "current", "next":
	default:
		fmt.Fprintf(os.Stderr, "template-tool volume-stamp-write: --generation must be current or next (got %q)\n", *generation)
		return 2
	}
	pcfg, err := loadProvSeedConfig(*provConfig)
	if err != nil {
		fmt.Fprintf(os.Stderr, "template-tool volume-stamp-write: %v\n", err)
		return 1
	}
	seed, err := resolveSeed(ProvisionConfigLike{
		Seed: pcfg.VolumeSeed, SeedFile: pcfg.VolumeSeedFile,
		SeedNext: pcfg.VolumeSeedNext, SeedNextFile: pcfg.VolumeSeedNextFile,
	}, *generation)
	if err != nil {
		fmt.Fprintf(os.Stderr, "template-tool volume-stamp-write: %v\n", err)
		return 1
	}
	// Preserve mode/created from the existing stamp (safe read) ONLY when its
	// signature verifies against a live generation seed. A tenant can rewrite
	// this file in flat mode; re-signing a tenant-chosen mode would turn a
	// forgery into authority. An unsafe entry (symlink/FIFO/oversize) is
	// tampering and refuses the write.
	existing, ok, err := volume.ReadVolumeStampForTool(*volumePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "template-tool volume-stamp-write: %v\n", err)
		return 1
	}
	seeds := [][]byte{seed}
	// The existing stamp may predate the rename and therefore be signed under
	// either the current or the staged generation.
	for _, gen := range []string{"current", "next"} {
		s, serr := resolveSeed(ProvisionConfigLike{
			Seed: pcfg.VolumeSeed, SeedFile: pcfg.VolumeSeedFile,
			SeedNext: pcfg.VolumeSeedNext, SeedNextFile: pcfg.VolumeSeedNextFile,
		}, gen)
		if serr == nil && len(s) > 0 {
			seeds = append(seeds, s)
		}
	}
	verified := false
	if ok {
		_, verified, err = volume.VerifyVolumeStampForToolAtName(*volumePath, *previousName, seeds)
		if err != nil {
			fmt.Fprintf(os.Stderr, "template-tool volume-stamp-write: %v\n", err)
			return 1
		}
	}
	effMode := *mode
	if effMode == "" && ok && verified {
		effMode = existing.Mode
	}
	effCreated := *created
	if effCreated == 0 && ok && verified && existing.CreatedUnix != 0 {
		effCreated = existing.CreatedUnix
	}
	effEpoch := ""
	if ok && verified {
		effEpoch = existing.VolumeEpoch
	}
	if effCreated == 0 {
		effCreated = time.Now().Unix()
	}
	if ok && !verified {
		fmt.Fprintln(os.Stderr, "template-tool volume-stamp-write: the existing stamp does not verify — NOT preserving its mode/created fields (pass --mode if the mode is known)")
	}
	if err := volume.WriteVolumeStampForTool(*volumePath, *id, effMode, seed, effCreated, effEpoch); err != nil {
		fmt.Fprintf(os.Stderr, "template-tool volume-stamp-write: %v\n", err)
		return 1
	}
	return 0
}

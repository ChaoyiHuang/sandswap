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
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
)

// StateFilename is the seed adoption record, written beside the role lock
// (same runtime directory, so it is tmpfs-backed and deliberately NOT
// durable). It answers ONE question — which generation did THIS process adopt
// — and nothing else: the config file remains the pointer authority, and the
// volume stamps remain the disk-side truth.
const StateFilename = "volume-seed-state.json"

// stateFileMode scopes the adoption record to its owner and the provision
// identity's group. The record carries fingerprints (never seed material), but
// it is operational metadata for the prov instance: no world-readable copy.
const stateFileMode = 0o640

// stateFileGroup resolves the group the record is scoped to: the provision
// identity's group (host prep exports SANDPROV_GROUP; the conventional name is
// the fallback). ok=false leaves the writer's own ownership in place.
func stateFileGroup() (int, bool) {
	name := os.Getenv("SANDPROV_GROUP")
	if name == "" {
		name = "sandprov"
	}
	if gid, err := strconv.Atoi(name); err == nil && gid >= 0 {
		return gid, true
	}
	g, err := user.LookupGroup(name)
	if err != nil {
		return 0, false
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil || gid < 0 {
		return 0, false
	}
	return gid, true
}

// scopeStateFile applies the record's ownership contract after the temp file
// is written: mode 0640 always, and root:<provision group> when this process
// can set it (a root-run prov instance — the k8s embedded shape). A non-root
// writer IS the provision identity on the baremetal shape, so its own
// ownership already names the intended reader. Best-effort: a host without
// the group keeps the writer's group (mode still blocks world access).
func scopeStateFile(path string) error {
	if err := os.Chmod(path, stateFileMode); err != nil {
		return err
	}
	if os.Geteuid() == 0 {
		if gid, ok := stateFileGroup(); ok {
			_ = os.Chown(path, 0, gid)
		}
	}
	return nil
}

// State is the adoption record. Fingerprints only, never seed material, so the
// file can be group-readable without weakening anything.
type State struct {
	PID                int    `json:"pid"`
	AdoptedUnix        int64  `json:"adopted_unix"`
	CurrentFingerprint string `json:"current_fingerprint"`
	StagedFingerprint  string `json:"staged_fingerprint,omitempty"`
	Staged             bool   `json:"staged"`
	// LastTransition is what the most recent accepted state did: "startup",
	// "none", "stage", "abort" or "promote".
	LastTransition string `json:"last_transition,omitempty"`
	// Sources describes every configured channel and whether it currently
	// reads. A source that is configured but not resolved is exactly the
	// "injector has not materialized it yet" state operators need to see.
	Sources []SourceState `json:"sources"`
	// StartupScan is the startup guard's reading of the volumes root (absent
	// when the root could not be read at all).
	StartupScan *ScanState `json:"startup_scan,omitempty"`
	// LastError is the most recent refusal OR startup guard warning. The live
	// generations were NOT changed by it — the record states what the process
	// runs, and the message states why it did not move (or what the startup
	// reading found).
	LastError string `json:"last_error,omitempty"`
}

// SourceState describes one configured seed channel.
type SourceState struct {
	Generation string `json:"generation"`
	Kind       string `json:"kind"`
	Path       string `json:"path,omitempty"`
	// Resolved reports whether the source reads successfully right now. It
	// never carries the value.
	Resolved bool `json:"resolved"`
}

// ScanState is the startup guard's reading of the volumes root.
type ScanState struct {
	Sampled       int  `json:"sampled"`
	Foreign       int  `json:"foreign"`
	Unstamped     int  `json:"unstamped"`
	PreGeneration int  `json:"pre_generation"`
	Unverified    int  `json:"unverified"` // signed by no live generation (or unsigned): tampered or a seed mix-up
	Complete      bool `json:"complete"`
}

// WriteState atomically replaces the record: tmp file in the SAME directory,
// fsync, rename (the repository's on-disk convention). A crash must never
// leave a half-written record that tooling would read as an adoption.
func WriteState(path string, st State) error {
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal seed state: %w", err)
	}
	data = append(data, '\n')

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".volume-seed-state.*")
	if err != nil {
		return fmt.Errorf("create seed state in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("write seed state: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("sync seed state: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("close seed state: %w", err)
	}
	if err := scopeStateFile(tmpName); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("scope seed state: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("install seed state: %w", err)
	}
	return nil
}

// ReadState reads an adoption record. ok=false means no record exists (the
// instance has not reached Bootstrap, or it is not a prov instance).
func ReadState(path string) (State, bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return State{}, false, nil
		}
		return State{}, false, fmt.Errorf("read seed state %s: %w", path, err)
	}
	var st State
	if err := json.Unmarshal(data, &st); err != nil {
		return State{}, false, fmt.Errorf("parse seed state %s: %w", path, err)
	}
	return st, true, nil
}

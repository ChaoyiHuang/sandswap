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

package core

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// CleanupState is the sandlot's persisted resilience-phase memory
// (tolerance-first): it survives a sandlot restart so the reconnect loop resumes
// the exact phase it was in when it died — a restart during TOLERATING must NOT
// reset the tolerance clock (that would stretch the double-mount window).
//
// Phase is one of:
//
//	""          — no outage in progress (normal / CONNECTED)
//	"tolerating" — stream is down, within T_tolerance; mounts are KEPT
//	               (in-flight commands keep running over vsock — this window
//	               is their grace period), keep probing, retry the preferred
//	               gateway only. Mounts are released at the reconnect (before
//	               the next hello — the reconnect-clean invariant) or when
//	               tolerance expires, whichever comes first. Ownership is
//	               untouched.
//	"cleaning"   — tolerance expired; stopped probing, concurrently unmounting
//	               all mounts (ResetSurvivorsToClean). Re-running the cleanup is
//	               idempotent (unmount on an already-clean VM is a no-op).
//	"done"       — cleanup finished; waiting out T_isolation before reconnecting.
//
// Cleanup is idempotent by construction: ResetSurvivorsToClean sets
// setFsAllowedDirs([]) + UnmountRootfs per VM, both safe to re-run on a clean
// VM. There is deliberately NO "cleaned_vms" list — a restart mid-cleanup
// re-cleans every VM, which is correct and cheap.
type CleanupState struct {
	Phase          string    `json:"phase"`
	DisconnectTime time.Time `json:"disconnect_time"`
}

// CleanupState phases (see type doc).
const (
	CleanupPhaseTolerating = "tolerating"
	CleanupPhaseCleaning   = "cleaning"
	CleanupPhaseDone       = "done"
)

// cleanupStatePath is the state file location — the instance's PRIVATE state
// root, never the shared runtime dir (which is group-writable by the service
// identities and where a planted symlink would redirect the read/write).
func cleanupStatePath(sandboxRoot string) string {
	return filepath.Join(StateRootFor(sandboxRoot), "cleanup-state.json")
}

// LoadCleanupState reads the persisted resilience phase; returns an empty state
// (phase "") on any error (missing file, corrupt JSON) — the sandlot then starts
// in the normal CONNECTED path.
func LoadCleanupState(sandboxRoot string) CleanupState {
	data, err := os.ReadFile(cleanupStatePath(sandboxRoot))
	if err != nil {
		return CleanupState{}
	}
	var s CleanupState
	if err := json.Unmarshal(data, &s); err != nil {
		return CleanupState{}
	}
	// Defensive: an unknown phase is treated as no-op (normal connect).
	switch s.Phase {
	case CleanupPhaseTolerating, CleanupPhaseCleaning, CleanupPhaseDone:
	default:
		return CleanupState{}
	}
	return s
}

// SaveCleanupState persists the resilience phase. Best-effort but atomic
// (tmp + fsync + rename): a torn write would read back as corrupt JSON and
// reset to phase "" — losing the outage memory — so we avoid it. A failed
// save means the phase is lost on crash; the re-adopt path (ReadoptVMs) resets
// survivors to CLEAN regardless, so a stale mount cannot survive a restart
// either way.
func SaveCleanupState(sandboxRoot string, s CleanupState) {
	data, err := json.Marshal(s)
	if err != nil {
		return
	}
	path := cleanupStatePath(sandboxRoot)
	_ = writeFileSync(path, data)
}

// writeFileSync atomically writes data to path (0600, fsync, rename). The
// temporary file is CreateTemp/O_EXCL, so a symlink planted at a predictable
// `path.tmp` is never followed, and the rename replaces a planted target
// link rather than writing through it.
func writeFileSync(path string, data []byte) error {
	dir := filepath.Dir(path)
	// The private state root may not exist on the first write after a reboot
	// (tmpfs); create it owner-only. A shared dir already exists and keeps its
	// mode.
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }()
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

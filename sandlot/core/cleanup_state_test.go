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
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCleanupStatePath(t *testing.T) {
	got := cleanupStatePath("/run/sandswap/vm")
	want := "/run/sandswap-state/default/cleanup-state.json"
	if got != want {
		t.Errorf("cleanupStatePath = %q, want %q", got, want)
	}
}

func TestCleanupStateRoundTrip(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vm")
	phases := []string{CleanupPhaseTolerating, CleanupPhaseCleaning, CleanupPhaseDone}
	for _, phase := range phases {
		at := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
		SaveCleanupState(root, CleanupState{Phase: phase, DisconnectTime: at})
		got := LoadCleanupState(root)
		if got.Phase != phase {
			t.Errorf("phase = %q, want %q", got.Phase, phase)
		}
		if !got.DisconnectTime.Equal(at) {
			t.Errorf("disconnect_time = %v, want %v", got.DisconnectTime, at)
		}
	}
}

func TestLoadCleanupStateMissingFile(t *testing.T) {
	got := LoadCleanupState(filepath.Join(t.TempDir(), "vm"))
	if got.Phase != "" {
		t.Errorf("phase = %q for missing file, want empty", got.Phase)
	}
}

func TestLoadCleanupStateCorruptJSON(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vm")
	path := cleanupStatePath(root)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := LoadCleanupState(root); got.Phase != "" {
		t.Errorf("phase = %q for corrupt JSON, want empty", got.Phase)
	}
}

func TestLoadCleanupStateUnknownPhase(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vm")
	SaveCleanupState(root, CleanupState{Phase: "bogus"})
	if got := LoadCleanupState(root); got.Phase != "" {
		t.Errorf("phase = %q for unknown phase, want empty (defensive reset)", got.Phase)
	}
}

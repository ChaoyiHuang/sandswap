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

package identity

import (
	"path/filepath"
	"testing"
	"time"
)

// TestTombstonesSurviveRestart pins the id-reuse guard across a single-node
// restart: the snapshot persists the tombstone map, so the store must restore
// it — dropping it lets a reused 32-bit id resurrect a name whose stale
// record may still exist on a lagging gateway.
func TestTombstonesSurviveRestart(t *testing.T) {
	volRoot := t.TempDir()
	path := filepath.Join(volRoot, "identity-store.json")
	s, err := NewPersistentMemoryStore(volRoot, path, nil)
	if err != nil {
		t.Fatalf("first open: %v", err)
	}
	const id = "sandfs-dead0001"
	s.mu.Lock()
	s.tombstones[id] = time.Now()
	s.persistLocked()
	s.mu.Unlock()
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	s2, err := NewPersistentMemoryStore(volRoot, path, nil)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() { s2.Close() })
	s2.mu.Lock()
	_, ok := s2.tombstones[id]
	s2.mu.Unlock()
	if !ok {
		t.Fatal("tombstone did not survive the restart")
	}
}

// TestTombstoneTTLConfigurable pins the operator knob: zero/negative is
// refused, a valid duration is adopted.
func TestTombstoneTTLConfigurable(t *testing.T) {
	old := TombstoneTTL()
	t.Cleanup(func() { _ = SetTombstoneTTL(old) })

	if err := SetTombstoneTTL(0); err == nil {
		t.Fatal("zero tombstone TTL accepted")
	}
	if err := SetTombstoneTTL(2 * time.Hour); err != nil {
		t.Fatalf("valid TTL rejected: %v", err)
	}
	if got := TombstoneTTL(); got != 2*time.Hour {
		t.Fatalf("TombstoneTTL() = %s, want 2h", got)
	}
}

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
	"context"
	"errors"
	"sync"
	"testing"
)

// verifyManager wraps the no-op manager to record VerifyVolumeID calls and
// inject failures.
type verifyManager struct {
	noopVMLifecycleManager
	mu    sync.Mutex
	calls int
	err   error
}

func (m *verifyManager) VerifyVolumeID(context.Context, string, string, string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls++
	return m.err
}

func (m *verifyManager) callCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls
}

// TestVerifyVolumeIdentityCachesPositiveResults pins the identity-check cost model: the
// stamp read happens once per (sandfs_id, volume_path) per process; hits pay
// nothing, failures are never cached, and an empty id is refused before the
// manager is consulted.
func TestVerifyVolumeIdentityCachesPositiveResults(t *testing.T) {
	h := newTestHandler()
	fm := &verifyManager{}
	h.vm = fm

	if err := h.verifyVolumeIdentity(context.Background(), "sfs-1", "/vol/a", ""); err != nil {
		t.Fatalf("first verify: %v", err)
	}
	if got := fm.callCount(); got != 1 {
		t.Fatalf("first verify calls = %d, want 1", got)
	}
	// A second attach of the same pair is a cache hit.
	if err := h.verifyVolumeIdentity(context.Background(), "sfs-1", "/vol/a", ""); err != nil {
		t.Fatalf("cached verify: %v", err)
	}
	if got := fm.callCount(); got != 1 {
		t.Fatalf("cached verify calls = %d, want 1 (no second read)", got)
	}
	// A failed check is refused with the generic sentinel and NOT cached: the
	// pair is re-checked on the next attempt (a transient failure must not
	// become a permanent allow).
	fm.err = errors.New("stamp names a different sandfs")
	if err := h.verifyVolumeIdentity(context.Background(), "sfs-2", "/vol/b", ""); !errors.Is(err, errVolumeIdentityCheckFailed) {
		t.Fatalf("mismatch error = %v, want the generic sentinel", err)
	}
	fm.err = nil
	if err := h.verifyVolumeIdentity(context.Background(), "sfs-2", "/vol/b", ""); err != nil {
		t.Fatalf("re-check after recovery: %v", err)
	}
	if got := fm.callCount(); got != 3 {
		t.Fatalf("calls = %d, want 3 (failed pair was not cached)", got)
	}
	// Empty sandfs id is refused before any manager call.
	before := fm.callCount()
	if err := h.verifyVolumeIdentity(context.Background(), "", "/vol/a", ""); err == nil {
		t.Fatal("empty sandfs id must be refused")
	}
	if got := fm.callCount(); got != before {
		t.Fatalf("empty id reached the manager (%d -> %d calls)", before, got)
	}
}

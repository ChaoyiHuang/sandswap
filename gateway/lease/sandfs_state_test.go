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

package lease

import (
	"testing"
)

func TestSandfsStateAvailableByDefault(t *testing.T) {
	ss := NewSandfsState()

	// A sandfs that was never touched should be available.
	if !ss.IsAvailable("sandfs-1") {
		t.Error("expected sandfs to be available by default")
	}
}

func TestSandfsStateEnterExitCleaning(t *testing.T) {
	ss := NewSandfsState()

	// Enter cleaning.
	if err := ss.EnterCleaning("sandfs-1"); err != nil {
		t.Fatalf("enter cleaning: %v", err)
	}

	// Should not be available while cleaning.
	if ss.IsAvailable("sandfs-1") {
		t.Error("expected sandfs to be unavailable during cleaning")
	}

	// Exit cleaning.
	ss.ExitCleaning("sandfs-1")

	// Should be available again.
	if !ss.IsAvailable("sandfs-1") {
		t.Error("expected sandfs to be available after cleaning completes")
	}
}

func TestSandfsStateDoubleEnterCleaning(t *testing.T) {
	ss := NewSandfsState()

	if err := ss.EnterCleaning("sandfs-1"); err != nil {
		t.Fatalf("first enter cleaning: %v", err)
	}

	// Second enter should return ErrSandfsCleaning.
	if err := ss.EnterCleaning("sandfs-1"); err != ErrSandfsCleaning {
		t.Errorf("expected ErrSandfsCleaning on double enter, got %v", err)
	}
}

func TestSandfsStateIndependentSandfs(t *testing.T) {
	ss := NewSandfsState()

	// Enter cleaning for sandfs-1.
	if err := ss.EnterCleaning("sandfs-1"); err != nil {
		t.Fatalf("enter cleaning sandfs-1: %v", err)
	}

	// sandfs-2 should still be available.
	if !ss.IsAvailable("sandfs-2") {
		t.Error("sandfs-2 should be unaffected by sandfs-1 cleaning")
	}

	// sandfs-1 should be unavailable.
	if ss.IsAvailable("sandfs-1") {
		t.Error("sandfs-1 should be unavailable during cleaning")
	}
}

func TestSandfsStateReEnterAfterExit(t *testing.T) {
	ss := NewSandfsState()

	// First cycle.
	if err := ss.EnterCleaning("sandfs-1"); err != nil {
		t.Fatalf("first enter: %v", err)
	}
	ss.ExitCleaning("sandfs-1")

	// Second cycle should work fine.
	if err := ss.EnterCleaning("sandfs-1"); err != nil {
		t.Fatalf("re-enter after exit: %v", err)
	}
	ss.ExitCleaning("sandfs-1")

	if !ss.IsAvailable("sandfs-1") {
		t.Error("expected available after second cleaning cycle")
	}
}

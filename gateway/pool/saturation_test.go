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

package pool_test

import (
	"log/slog"
	"testing"
	"time"

	"gateway/pool"
)

// IsSustainedSaturated is false when not all nodes are zero-clean.
func TestIsSustainedSaturatedNotSaturated(t *testing.T) {
	pm := pool.NewManager(nil, slog.New(slog.DiscardHandler))
	pm.AddNode("n1")
	pm.UpdateNodeCapacity("n1", []pool.SpecCapacity{{SpecID: "small", Total: 2, Clean: 2}})
	// derived clean = total - bound = 2 > 0 → not saturated.
	if pm.IsSustainedSaturated(1) {
		t.Errorf("IsSustainedSaturated true with clean VMs, want false")
	}
}

// IsSustainedSaturated requires the hysteresis window to elapse.
func TestIsSustainedSaturatedHysteresis(t *testing.T) {
	pm := pool.NewManager(nil, slog.New(slog.DiscardHandler))
	pm.AddNode("n1")
	pm.UpdateNodeCapacity("n1", []pool.SpecCapacity{{SpecID: "small", Total: 1, Clean: 0}})
	pm.ReserveBound("n1", "small") // derived clean = 0 → all-saturated
	// Immediately after saturation starts, a 5s window is NOT yet elapsed.
	if pm.IsSustainedSaturated(5) {
		t.Errorf("IsSustainedSaturated(5) true immediately, want false (hysteresis)")
	}
	// A 0-second window is always false (guard).
	if pm.IsSustainedSaturated(0) {
		t.Errorf("IsSustainedSaturated(0) should be false")
	}
}

// IsSustainedSaturated becomes true after the window elapses, and resets when
// capacity returns.
func TestIsSustainedSaturatedBecomesTrueAndResets(t *testing.T) {
	pm := pool.NewManager(nil, slog.New(slog.DiscardHandler))
	pm.AddNode("n1")
	pm.UpdateNodeCapacity("n1", []pool.SpecCapacity{{SpecID: "small", Total: 1, Clean: 0}})
	pm.ReserveBound("n1", "small") // all-saturated
	time.Sleep(1100 * time.Millisecond)
	if !pm.IsSustainedSaturated(1) {
		t.Errorf("IsSustainedSaturated(1) false after 1.1s saturated, want true")
	}
	// Release the bound → clean rises → saturation cleared.
	pm.ReleaseBound("n1", "small")
	if pm.IsSustainedSaturated(1) {
		t.Errorf("IsSustainedSaturated true after capacity returned, want false")
	}
}

// Saturation requires ALL nodes zero-clean; one clean node breaks it.
func TestIsSustainedSaturatedRequiresAllNodes(t *testing.T) {
	pm := pool.NewManager(nil, slog.New(slog.DiscardHandler))
	pm.AddNode("n1")
	pm.AddNode("n2")
	pm.UpdateNodeCapacity("n1", []pool.SpecCapacity{{SpecID: "small", Total: 1, Clean: 0}})
	pm.ReserveBound("n1", "small")                                                          // n1 saturated
	pm.UpdateNodeCapacity("n2", []pool.SpecCapacity{{SpecID: "small", Total: 2, Clean: 2}}) // n2 has clean
	time.Sleep(1100 * time.Millisecond)
	if pm.IsSustainedSaturated(1) {
		t.Errorf("IsSustainedSaturated true when one node still has clean, want false")
	}
}

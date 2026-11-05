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
	"errors"
	"sync"
)

// ErrSandfsCleaning is returned when a sandfs is in CLEANING state
// and cannot accept new requests.
var ErrSandfsCleaning = errors.New("sandfs is cleaning")

// DefaultRetryAfterMs is the default retry-after hint (10s) returned
// with 503 responses during CLEANING.
const DefaultRetryAfterMs = 10000

// sandfsEntryState represents the state of a sandfs in the state machine.
type sandfsEntryState int

const (
	// stateAvailable means the sandfs can accept new requests.
	stateAvailable sandfsEntryState = iota
	// stateCleaning means the sandfs is being cleaned up after a failure.
	// New execute/file requests are rejected with 503; exec/status and
	// exec/kill are still allowed (the VM may still be running).
	stateCleaning
)

// SandfsState tracks per-sandfs availability. On the success path it adds
// zero latency: IsAvailable returns true without touching the map when the
// sandfs has no entry (the common case). Only on the failure path does it
// transition to CLEANING and back.
//
// State machine:
//
//	AVAILABLE → EnterCleaning → CLEANING → ExitCleaning → AVAILABLE
//
// CLEANING duration is bounded by the L2 cleanup timeout (12s).
type SandfsState struct {
	mu     sync.Mutex
	states map[string]sandfsEntryState // sandfsID → state
}

// NewSandfsState creates a new SandfsState.
func NewSandfsState() *SandfsState {
	return &SandfsState{states: make(map[string]sandfsEntryState)}
}

// IsAvailable checks whether a sandfs can accept new requests.
// Fast path: sandfs not in the map → true (zero latency on success path).
func (ss *SandfsState) IsAvailable(sandfsID string) bool {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	st, ok := ss.states[sandfsID]
	if !ok {
		return true // No entry = never entered CLEANING = AVAILABLE
	}
	return st == stateAvailable
}

// EnterCleaning transitions a sandfs to CLEANING state.
// Returns ErrSandfsCleaning if the sandfs is already in CLEANING
// (prevents double-enter from concurrent failure paths).
func (ss *SandfsState) EnterCleaning(sandfsID string) error {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	st, ok := ss.states[sandfsID]
	if ok && st == stateCleaning {
		return ErrSandfsCleaning
	}
	ss.states[sandfsID] = stateCleaning
	return nil
}

// ExitCleaning transitions a sandfs back to AVAILABLE after cleanup completes.
// The entry is kept in the map (state=AVAILABLE) rather than deleted so that
// subsequent IsAvailable calls still hit the map instead of the "no entry = true"
// fast path. This avoids a subtle race where the map entry is deleted and
// immediately re-created by another EnterCleaning before the caller can observe
// the AVAILABLE state.
func (ss *SandfsState) ExitCleaning(sandfsID string) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	ss.states[sandfsID] = stateAvailable
}

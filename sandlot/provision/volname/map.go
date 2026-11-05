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

package volname

import (
	"fmt"
	"sync"
)

// Map holds the generation(s) of the volume-name seed. Two generations are
// live during a rotation: Current (what new volumes use and what existing
// volumes are expected to carry) and Next (what a rotation stages before any
// name moves). Operation resolution consults both — see
// Provisioner.resolveVolPath — so a partially rotated tree keeps working.
//
// Safe for concurrent use: the provision service runs operations on multiple
// goroutines and the seed is re-read on config reload.
type Map struct {
	mu      sync.RWMutex
	current []byte
	next    []byte
}

// NewMap validates and returns a Map with only the current generation set.
func NewMap(seed []byte) (*Map, error) {
	if err := ValidateSeed(seed); err != nil {
		return nil, err
	}
	return &Map{current: append([]byte(nil), seed...)}, nil
}

// Current returns the directory name for id under the current seed.
func (m *Map) Current(id string) string {
	m.mu.RLock()
	seed := m.current
	m.mu.RUnlock()
	return Derive(seed, id)
}

// CurrentSeed returns the current seed bytes. Callers that must STAMP a
// volume with the generation it was created under (rather than log it) need
// the material; it must never be written anywhere but a stamp's one-way
// fingerprint field or kept in memory.
func (m *Map) CurrentSeed() []byte {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]byte(nil), m.current...)
}

// NextSeed returns the staged (next) seed bytes, or nil when no rotation is
// staged. Same handling rule as CurrentSeed: verification of a stamp signed
// under the staging generation needs the material, never written anywhere but
// a one-way fingerprint.
func (m *Map) NextSeed() []byte {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if len(m.next) == 0 {
		return nil
	}
	return append([]byte(nil), m.next...)
}

// Next returns the directory name for id under the staged seed. Only valid
// while HasNext reports true.
func (m *Map) Next(id string) string {
	m.mu.RLock()
	seed := m.next
	m.mu.RUnlock()
	return Derive(seed, id)
}

// HasNext reports whether a rotation is staged.
func (m *Map) HasNext() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.next) > 0
}

// Stage sets the next generation (must validate; empty clears the staging).
func (m *Map) Stage(seed []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.stageLocked(seed)
}

// stageLocked is Stage's body; the caller holds m.mu.
func (m *Map) stageLocked(seed []byte) error {
	if len(seed) == 0 {
		m.next = nil
		return nil
	}
	if err := ValidateSeed(seed); err != nil {
		return err
	}
	if string(seed) == string(m.current) {
		return fmt.Errorf("staged seed equals the current seed — a rotation would rename nothing")
	}
	m.next = append([]byte(nil), seed...)
	return nil
}

// Promote makes the staged generation current and clears the staging. It is
// the only way a rotation completes: after it, new volumes (and the names the
// provisioner resolves first) use the new seed.
func (m *Map) Promote() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.next) == 0 {
		return fmt.Errorf("no staged seed to promote")
	}
	m.current = append([]byte(nil), m.next...)
	m.next = nil
	return nil
}

// Transition is what a config state asks the live map to do. Classify reports
// it without mutating, so a caller can gate an irreversible step — the promote
// completeness check — before the map moves.
type Transition int

const (
	// TransitionNone means the config already matches the live map.
	TransitionNone Transition = iota
	// TransitionStage opens the rotation window (creation freezes).
	TransitionStage
	// TransitionAbort drops the staged generation, current unchanged.
	TransitionAbort
	// TransitionPromote makes the staged generation current and drops the old
	// one, so a volume that was not renamed first becomes unresolvable — which
	// is exactly why callers gate this transition on a disk check.
	TransitionPromote
)

func (t Transition) String() string {
	switch t {
	case TransitionStage:
		return "stage"
	case TransitionAbort:
		return "abort"
	case TransitionPromote:
		return "promote"
	default:
		return "none"
	}
}

// classifyLocked is the whole decision table. The caller holds m.mu — read for
// Classify, write for ApplySeeds — so a dry run and the real application can
// never disagree about what a state means.
func (m *Map) classifyLocked(cur, next []byte, curConfigured, nextConfigured bool) (Transition, error) {
	if !curConfigured {
		return TransitionNone, fmt.Errorf("volume_seed disappeared from the config while the provision role is running — restart the instance instead of removing it live")
	}
	if nextConfigured {
		if err := ValidateSeed(next); err != nil {
			return TransitionNone, err
		}
		if len(m.next) > 0 {
			// Order matters: the current generation may only move through
			// promote or abort, so a moved current is refused BEFORE the
			// idempotent case — otherwise a config that flips volume_seed
			// alongside an unchanged volume_seed_next would be reported as
			// applied while the live map still runs the old current.
			if string(cur) != string(m.current) {
				return TransitionNone, fmt.Errorf("volume_seed changed while a rotation is staged — promote or abort first")
			}
			if string(next) == string(m.next) {
				return TransitionNone, nil // re-presented tuple: a no-op
			}
			return TransitionNone, fmt.Errorf("the staged generation changed while the rotation window is open — abort (remove volume_seed_next) and stage the new generation")
		}
		if string(next) == string(m.current) {
			return TransitionNone, fmt.Errorf("staged seed equals the current seed — a rotation would rename nothing")
		}
		if string(cur) != string(m.current) {
			return TransitionNone, fmt.Errorf("volume_seed changed at the same time as volume_seed_next appeared — the supported path is: stage (current unchanged), run the rotation, then promote")
		}
		return TransitionStage, nil
	}
	staged := len(m.next) > 0
	switch {
	case string(cur) == string(m.current):
		if !staged {
			return TransitionNone, nil
		}
		return TransitionAbort, nil
	case staged && string(cur) == string(m.next):
		return TransitionPromote, nil
	default:
		return TransitionNone, fmt.Errorf("volume_seed changed without a staged promotion — the supported path is: stage volume_seed_next, run the rotation, then promote")
	}
}

// Classify reports what ApplySeeds would do with this state, without changing
// anything. Promotion drops the old generation, so callers run the disk-side
// completeness check between Classify and ApplySeeds.
func (m *Map) Classify(cur, next []byte, curConfigured, nextConfigured bool) (Transition, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.classifyLocked(cur, next, curConfigured, nextConfigured)
}

// ApplySeeds applies a config-file state (the reload path) to the live map.
// Legal transitions, and only these:
//
//	next set,   current unchanged  -> stage       (the rotation window opens)
//	next empty, current unchanged  -> clear stage (the rotation is aborted)
//	next empty, current == staged  -> promote     (the rotation completes)
//
// Anything else is refused by name: a seed flipping without going through
// stage/promote would leave directories and the namer disagreeing, which is
// exactly what the volume identity stamp exists to catch — refusing here means
// it never gets that far.
//
// Two properties the seed-injection channels depend on:
//
//   - VALIDATE-THEN-MUTATE, all under ONE lock hold: a refused transition
//     leaves the live map untouched, which is what makes the caller's "live
//     namer unchanged" report true. (A split validate/mutate could stage a new
//     generation and only then notice the current seed moved, leaving the map
//     in a state no config describes — and two independent watchers calling
//     this concurrently is now the normal case, not a corner case.)
//   - IDEMPOTENT when the same tuple is re-presented (watchers and the poll do
//     that constantly), while a DIFFERENT staged value is refused: swapping the
//     staged generation mid-window would make --run rename volumes toward a
//     generation the promote completeness gate cannot see.
func (m *Map) ApplySeeds(cur, next []byte, curConfigured, nextConfigured bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	tr, err := m.classifyLocked(cur, next, curConfigured, nextConfigured)
	if err != nil {
		return err
	}
	switch tr {
	case TransitionStage:
		m.next = append([]byte(nil), next...)
	case TransitionAbort:
		m.next = nil
	case TransitionPromote:
		m.current = append([]byte(nil), m.next...)
		m.next = nil
	}
	return nil
}

// GenerationSnapshot reports whether a rotation is staged and the fingerprints
// of BOTH live generations (short non-secret hashes) — what the seed adoption
// state file records and what /stats-style observability projects. It never
// returns seed material.
func (m *Map) GenerationSnapshot() (staged bool, currentFP, stagedFP string) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if len(m.next) > 0 {
		return true, Fingerprint(m.current), Fingerprint(m.next)
	}
	return false, Fingerprint(m.current), ""
}

// Snapshot is the two-value form of GenerationSnapshot, for callers that only
// care about the current generation.
func (m *Map) Snapshot() (staged bool, currentFP string) {
	staged, cur, _ := m.GenerationSnapshot()
	return staged, cur
}

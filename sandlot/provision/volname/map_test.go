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
	"sync"
	"testing"
)

// ApplySeeds is the config-reload entry point: it must accept exactly the
// three legal transitions and refuse a bare seed flip (which would leave
// directories and the namer disagreeing).
func TestApplySeedsTransitions(t *testing.T) {
	s1, s2, s3 := seed32(t, 1), seed32(t, 2), seed32(t, 3)

	m, err := NewMap(s1)
	if err != nil {
		t.Fatal(err)
	}
	// Legal: stage.
	if err := m.ApplySeeds(s1, s2, true, true); err != nil {
		t.Fatalf("stage must be accepted: %v", err)
	}
	if !m.HasNext() {
		t.Fatal("staging must be visible")
	}
	// Illegal: flip the current seed while staged.
	if err := m.ApplySeeds(s3, s2, true, true); err == nil {
		t.Error("changing volume_seed while staged must be refused")
	}
	// Legal: promote (config now carries the staged value as current, no next).
	if err := m.ApplySeeds(s2, nil, true, false); err != nil {
		t.Fatalf("promotion must be accepted: %v", err)
	}
	if m.HasNext() {
		t.Error("promotion must clear the staging")
	}
	if got := m.Current("sandfs-x"); got != Derive(s2, "sandfs-x") {
		t.Errorf("after promotion the new generation must be current, got %s", got)
	}
	// Illegal: a bare flip with nothing staged.
	if err := m.ApplySeeds(s3, nil, true, false); err == nil {
		t.Error("a bare seed change must be refused (stage -> run -> promote)")
	}
	// Illegal: removing the seed from the config of a running prov.
	if err := m.ApplySeeds(nil, nil, false, false); err == nil {
		t.Error("removing volume_seed live must be refused")
	}
	// Legal: abort (staged key removed, current unchanged).
	if err := m.ApplySeeds(s2, s3, true, true); err != nil {
		t.Fatalf("staging again must be accepted: %v", err)
	}
	if err := m.ApplySeeds(s2, nil, true, false); err != nil {
		t.Fatalf("abort (clearing the staged key) must be accepted: %v", err)
	}
	if m.HasNext() {
		t.Error("abort must clear the staging")
	}
}

// A refused transition must not touch the live map: the reload path reports
// "live namer unchanged" on the error path, and that claim is only true if
// nothing was written before the refusal. The historical bug staged the new
// generation FIRST and only then noticed the current seed had moved, so the
// refusal left a staging behind.
func TestApplySeedsRefusalLeavesStateUntouched(t *testing.T) {
	s1, s2, s3 := seed32(t, 1), seed32(t, 2), seed32(t, 3)
	m, err := NewMap(s1)
	if err != nil {
		t.Fatal(err)
	}
	// current and next moved together (config edited by hand, or two writers
	// raced): refuse, and do NOT leave s3 staged.
	if err := m.ApplySeeds(s2, s3, true, true); err == nil {
		t.Fatal("current+next moving together must be refused")
	}
	if m.HasNext() {
		t.Error("a refused transition must not leave a staged generation behind")
	}
	if got := m.Current("id"); got != Derive(s1, "id") {
		t.Errorf("a refused transition must not move the current generation (got %s)", got)
	}

	// A bare flip is refused and equally inert.
	if err := m.ApplySeeds(s2, nil, true, false); err == nil {
		t.Fatal("a bare flip must be refused")
	}
	if m.HasNext() {
		t.Error("a refused bare flip must not stage anything")
	}
}

// The staged generation is frozen for the whole window: swapping it mid-run
// would rename volumes toward a generation the promote gate cannot see.
func TestApplySeedsStagedGenerationIsFrozen(t *testing.T) {
	s1, s2, s3 := seed32(t, 1), seed32(t, 2), seed32(t, 3)
	m, err := NewMap(s1)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.ApplySeeds(s1, s2, true, true); err != nil {
		t.Fatalf("stage must be accepted: %v", err)
	}
	// Re-presenting the identical tuple is the normal case (watcher + poll):
	// it must be a silent no-op, not an error.
	if err := m.ApplySeeds(s1, s2, true, true); err != nil {
		t.Fatalf("re-presenting the same staged tuple must be a no-op: %v", err)
	}
	// A DIFFERENT staged value is refused and leaves s2 staged.
	if err := m.ApplySeeds(s1, s3, true, true); err == nil {
		t.Fatal("swapping the staged generation mid-window must be refused")
	}
	staged, _, stagedFP := m.GenerationSnapshot()
	if !staged || stagedFP != Fingerprint(s2) {
		t.Errorf("the refusal must leave the original staged generation in place (staged=%v fp=%s)", staged, stagedFP)
	}
	// Abort, then the new value stages cleanly.
	if err := m.ApplySeeds(s1, nil, true, false); err != nil {
		t.Fatalf("abort must be accepted: %v", err)
	}
	if err := m.ApplySeeds(s1, s3, true, true); err != nil {
		t.Fatalf("re-staging after an abort must be accepted: %v", err)
	}
	if _, _, fp := m.GenerationSnapshot(); fp != Fingerprint(s3) {
		t.Errorf("staged fingerprint must follow the newly staged generation, got %s", fp)
	}
}

// Two seed sources (the config watcher and the seed-file watcher) call
// ApplySeeds concurrently in production. Whatever the interleaving, the map
// must always describe one of the two self-consistent states — never a torn
// one (current moved while a stale staging survives, which is what makes --run
// rename toward a generation the namer cannot resolve).
func TestApplySeedsConcurrentInvariant(t *testing.T) {
	s1, s3 := seed32(t, 1), seed32(t, 3)
	m, err := NewMap(s1)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				_ = m.ApplySeeds(s1, s3, true, true) // stage
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				_ = m.ApplySeeds(s1, nil, true, false) // abort
			}
		}()
	}
	wg.Wait()
	staged, curFP, stagedFP := m.GenerationSnapshot()
	if curFP != Fingerprint(s1) {
		t.Fatalf("current generation moved under stage/abort traffic: %s", curFP)
	}
	if staged && stagedFP != Fingerprint(s3) {
		t.Fatalf("a staged generation other than the presented one survived: %s", stagedFP)
	}
}

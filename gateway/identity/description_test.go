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
	"strings"
	"testing"
	"time"
)

// TestAgentDescriptionSurvivesSnapshotRestart pins the persisted display
// metadata: a restart must not silently drop an agent's description.
func TestAgentDescriptionSurvivesSnapshotRestart(t *testing.T) {
	volRoot := t.TempDir()
	path := filepath.Join(volRoot, "identity-store.json")
	s, err := NewPersistentMemoryStore(volRoot, path, nil)
	if err != nil {
		t.Fatalf("first open: %v", err)
	}
	agent, _, err := s.CreateAgent(CreateAgentRequest{Name: "a", Description: "hello"})
	if err != nil {
		t.Fatalf("create agent: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	s2, err := NewPersistentMemoryStore(volRoot, path, nil)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() { s2.Close() })
	got, err := s2.GetAgent(agent.ID)
	if err != nil {
		t.Fatalf("get agent after restart: %v", err)
	}
	if got.Description != "hello" {
		t.Fatalf("description after restart = %q, want hello", got.Description)
	}
}

// TestEtcdAgentDescriptionRoundTrip pins the etcd record shape: the
// description must ride the agent row, or a second gateway (and every
// restart) sees an empty description.
func TestEtcdAgentDescriptionRoundTrip(t *testing.T) {
	a := &Agent{
		ID:          "agent-1",
		Name:        "name",
		Description: "description",
		APIKeyHash:  "hash",
		CreatedAt:   time.Now().UTC(),
	}
	data, err := marshalAgentForEtcd(a)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got := decodeAgent(data)
	if got == nil {
		t.Fatal("decode returned nil")
	}
	if got.Description != "description" {
		t.Fatalf("description = %q, want description", got.Description)
	}
}

// TestValidateDescription pins the shared 200-rune/UTF-8 rule used by both
// Agent and SandFS creation.
func TestValidateDescription(t *testing.T) {
	if err := ValidateDescription(strings.Repeat("x", MaxDescriptionRunes)); err != nil {
		t.Fatalf("exactly %d runes rejected: %v", MaxDescriptionRunes, err)
	}
	if err := ValidateDescription(strings.Repeat("x", MaxDescriptionRunes+1)); err == nil {
		t.Fatal("over-limit description accepted")
	}
	if err := ValidateDescription(string([]byte{0xff})); err == nil {
		t.Fatal("invalid UTF-8 accepted")
	}
}

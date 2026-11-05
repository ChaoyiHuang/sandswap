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
	"strings"
	"sync"
	"testing"
)

// ─── Helpers ────────────────────────────────────────────────────

// mustCreateAgent creates an agent and fails the test on error. Used to reduce
// boilerplate in scenarios that need a pre-existing agent.
func mustCreateAgent(t *testing.T, s *MemoryStore, name string) (*Agent, string) {
	t.Helper()
	agent, key, err := s.CreateAgent(CreateAgentRequest{Name: name})
	if err != nil {
		t.Fatalf("CreateAgent(%q): %v", name, err)
	}
	if agent == nil {
		t.Fatalf("CreateAgent(%q): nil agent", name)
	}
	if key == "" {
		t.Fatalf("CreateAgent(%q): empty api key", name)
	}
	return agent, key
}

// mustCreateSandFS creates a sandfs owned by agentID and fails on error.
func mustCreateSandFS(t *testing.T, s *MemoryStore, agentID string, req CreateSandFSRequest) *Record {
	t.Helper()
	rec, err := s.CreateSandFS(agentID, req)
	if err != nil {
		t.Fatalf("CreateSandFS(%q): %v", req.Name, err)
	}
	if rec == nil {
		t.Fatalf("CreateSandFS(%q): nil record", req.Name)
	}
	return rec
}

// ─── CreateAgent ────────────────────────────────────────────────

// TestMemoryCreateAgent verifies CreateAgent assigns a unique ID, a well-formed
// API key, and populates the agent record fields. The API key is returned
// exactly once (the only time the plaintext leaves the store).
func TestMemoryCreateAgent(t *testing.T) {
	s := NewMemoryStore("/tmp/volroot")

	agent, key, err := s.CreateAgent(CreateAgentRequest{Name: "test-agent"})
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}

	// ID has the agent- prefix + 8 hex chars from the UUID.
	if !strings.HasPrefix(agent.ID, "agent-") {
		t.Errorf("agent.ID = %q, want prefix %q", agent.ID, "agent-")
	}
	if len(agent.ID) <= len("agent-") {
		t.Errorf("agent.ID = %q, too short", agent.ID)
	}

	// API key has the documented prefix and sufficient entropy (32 random bytes
	// -> 64 hex chars).
	const keyPrefix = "sk-sandswap-agent-"
	if !strings.HasPrefix(key, keyPrefix) {
		t.Errorf("api key = %q, want prefix %q", key, keyPrefix)
	}
	randomPart := strings.TrimPrefix(key, keyPrefix)
	if len(randomPart) < 32 {
		t.Errorf("api key random part length = %d, want >= 32", len(randomPart))
	}

	// The agent's APIKey field matches the returned plaintext key.
	if agent.APIKey != key {
		t.Errorf("agent.APIKey = %q, returned key = %q, want match", agent.APIKey, key)
	}

	// Name and timestamps are populated.
	if agent.Name != "test-agent" {
		t.Errorf("agent.Name = %q, want %q", agent.Name, "test-agent")
	}
	if agent.CreatedAt.IsZero() {
		t.Error("agent.CreatedAt is zero")
	}
}

// TestMemoryCreateAgentUnique verifies successive CreateAgent calls produce
// distinct agent IDs and API keys (no UUID/key collision).
func TestMemoryCreateAgentUnique(t *testing.T) {
	s := NewMemoryStore("/tmp/volroot")

	seenIDs := make(map[string]bool)
	seenKeys := make(map[string]bool)
	const n = 100

	for i := 0; i < n; i++ {
		agent, key, err := s.CreateAgent(CreateAgentRequest{Name: "agent"})
		if err != nil {
			t.Fatalf("CreateAgent %d: %v", i, err)
		}
		if seenIDs[agent.ID] {
			t.Fatalf("duplicate agent ID %s on iteration %d", agent.ID, i)
		}
		if seenKeys[key] {
			t.Fatalf("duplicate api key %s on iteration %d", key, i)
		}
		seenIDs[agent.ID] = true
		seenKeys[key] = true
	}
}

// ─── ResolveAgent (hot path) ────────────────────────────────────

// TestMemoryResolveAgent verifies the /agent/execute hot path: a valid API key
// resolves to the owning agent. This runs on every execute call and MUST be a
// local in-memory lookup. Agents are digest-indexed (like the etcd store), so
// a resolved agent carries no plaintext key — only the digest it matched.
func TestMemoryResolveAgent(t *testing.T) {
	s := NewMemoryStore("/tmp/volroot")
	agent, key, _ := s.CreateAgent(CreateAgentRequest{Name: "resolver"})

	resolved, err := s.ResolveAgent(key)
	if err != nil {
		t.Fatalf("ResolveAgent: %v", err)
	}
	if resolved.ID != agent.ID {
		t.Errorf("resolved.ID = %q, want %q", resolved.ID, agent.ID)
	}
	if resolved.Name != agent.Name {
		t.Errorf("resolved.Name = %q, want %q", resolved.Name, agent.Name)
	}
	if resolved.APIKey != "" {
		t.Errorf("resolved.APIKey = %q, want empty (plaintext never leaves CreateAgent)", resolved.APIKey)
	}
	if resolved.APIKeyHash != hashAPIKey(key) {
		t.Errorf("resolved.APIKeyHash mismatch")
	}
}

// TestMemoryResolveAgentInvalidKey verifies an unknown API key is rejected.
// This is the auth-failure path on the hot path - must return an error, not panic.
func TestMemoryResolveAgentInvalidKey(t *testing.T) {
	s := NewMemoryStore("/tmp/volroot")
	mustCreateAgent(t, s, "real-agent")

	if _, err := s.ResolveAgent("sk-sandswap-agent-deadbeef"); err == nil {
		t.Fatal("ResolveAgent with unknown key: expected error, got nil")
	}
}

// TestMemoryResolveAgentEmptyKey verifies an empty API key is rejected (no
// false-positive match on an empty string).
func TestMemoryResolveAgentEmptyKey(t *testing.T) {
	s := NewMemoryStore("/tmp/volroot")
	mustCreateAgent(t, s, "agent")

	if _, err := s.ResolveAgent(""); err == nil {
		t.Fatal("ResolveAgent(\"\"): expected error, got nil")
	}
}

// TestMemoryResolveAgentAfterDelete verifies a deleted agent's key no longer
// resolves (the api-key -> agent index entry is cleaned up on DeleteAgent).
func TestMemoryResolveAgentAfterDelete(t *testing.T) {
	s := NewMemoryStore("/tmp/volroot")
	agent, key, _ := s.CreateAgent(CreateAgentRequest{Name: "doomed"})

	if err := s.DeleteAgent(agent.ID); err != nil {
		t.Fatalf("DeleteAgent: %v", err)
	}

	if _, err := s.ResolveAgent(key); err == nil {
		t.Fatal("ResolveAgent after delete: expected error, got nil")
	}
}

// ─── GetSandFS ──────────────────────────────────────────────────

// TestMemoryGetSandFS verifies GetSandFS returns the record by ID (hot path).
func TestMemoryGetSandFS(t *testing.T) {
	s := NewMemoryStore("/tmp/volroot")
	agent, _ := mustCreateAgent(t, s, "owner")
	rec := mustCreateSandFS(t, s, agent.ID, CreateSandFSRequest{
		Name:        "my-sandfs",
		Description: "test volume",
		Template:    "ubuntu:v1",
		Mode:        "flat",
	})

	got, err := s.GetSandFS(rec.ID)
	if err != nil {
		t.Fatalf("GetSandFS: %v", err)
	}
	if got.ID != rec.ID {
		t.Errorf("got.ID = %q, want %q", got.ID, rec.ID)
	}
	if got.Name != "my-sandfs" {
		t.Errorf("got.Name = %q, want %q", got.Name, "my-sandfs")
	}
	if got.AgentID != agent.ID {
		t.Errorf("got.AgentID = %q, want %q", got.AgentID, agent.ID)
	}
	if got.Template != "ubuntu:v1" {
		t.Errorf("got.Template = %q, want %q", got.Template, "ubuntu:v1")
	}
	if got.Mode != "flat" {
		t.Errorf("got.Mode = %q, want %q", got.Mode, "flat")
	}
}

// TestMemoryGetSandFSNotFound verifies GetSandFS returns an error for an
// unknown sandfs ID.
func TestMemoryGetSandFSNotFound(t *testing.T) {
	s := NewMemoryStore("/tmp/volroot")

	_, err := s.GetSandFS("sandfs-nonexistent")
	if err == nil {
		t.Fatal("GetSandFS(unknown): expected error, got nil")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error = %q, want substring %q", err.Error(), "not found")
	}
}

// TestMemoryGetSandFSSnapshotContract pins the read contract: GetSandFS hands
// out a PRIVATE COPY (a snapshot). It used to return the store-owned object so
// the hot-path setters could mutate it in place; that made every reader race a
// concurrent writer (the status flip in particular). Writes still mutate the
// store-owned record in place — safe now, because no reader ever holds it:
// CreateSandFS is the only caller that keeps the live object (the registry
// fills rootfs_path/min-resources right after create).
func TestMemoryGetSandFSSnapshotContract(t *testing.T) {
	s := NewMemoryStore("/tmp/volroot")
	agent, _ := mustCreateAgent(t, s, "owner")
	rec := mustCreateSandFS(t, s, agent.ID, CreateSandFSRequest{Name: "shared"})

	got, _ := s.GetSandFS(rec.ID)
	if got == rec {
		t.Error("GetSandFS must return a copy, not the store-owned record")
	}
	if err := s.SetSandfsStatus(rec.ID, SandfsStatusDeleting); err != nil {
		t.Fatal(err)
	}
	if got.Status == SandfsStatusDeleting {
		t.Error("a previously returned record observed a later write")
	}
	// The create-time object is the live record: the registry's post-create
	// setters must be visible on it.
	if err := s.SetRootFSPath(rec.ID, "/tmp/volroot/sandfs-x"); err != nil {
		t.Fatal(err)
	}
	if rec.RootFSPath != "/tmp/volroot/sandfs-x" {
		t.Errorf("create-time record did not observe SetRootFSPath (got %q)", rec.RootFSPath)
	}
}

// ─── CreateSandFS ───────────────────────────────────────────────

// TestMemoryCreateSandFS verifies CreateSandFS assigns a unique ID and copies
// request fields into the record. RootFSPath is intentionally left empty -
// it's set by the Registry after volume creation (SetRootFSPath).
func TestMemoryCreateSandFS(t *testing.T) {
	s := NewMemoryStore("/tmp/volroot")
	agent, _ := mustCreateAgent(t, s, "owner")

	rec, err := s.CreateSandFS(agent.ID, CreateSandFSRequest{
		Name:        "vol-1",
		Description: "a test volume",
		Template:    "python:v2",
		Mode:        "overlay",
	})
	if err != nil {
		t.Fatalf("CreateSandFS: %v", err)
	}

	if !strings.HasPrefix(rec.ID, "sandfs-") {
		t.Errorf("rec.ID = %q, want prefix %q", rec.ID, "sandfs-")
	}
	if rec.AgentID != agent.ID {
		t.Errorf("rec.AgentID = %q, want %q", rec.AgentID, agent.ID)
	}
	if rec.Name != "vol-1" {
		t.Errorf("rec.Name = %q, want %q", rec.Name, "vol-1")
	}
	if rec.Description != "a test volume" {
		t.Errorf("rec.Description = %q, want %q", rec.Description, "a test volume")
	}
	if rec.Template != "python:v2" {
		t.Errorf("rec.Template = %q, want %q", rec.Template, "python:v2")
	}
	if rec.Mode != "overlay" {
		t.Errorf("rec.Mode = %q, want %q", rec.Mode, "overlay")
	}
	if rec.RootFSPath != "" {
		t.Errorf("rec.RootFSPath = %q, want empty (set later by Registry)", rec.RootFSPath)
	}
	if rec.CreatedAt.IsZero() {
		t.Error("rec.CreatedAt is zero")
	}
}

// TestMemoryCreateSandFSUnknownAgent verifies CreateSandFS rejects a sandfs
// creation for an agent that doesn't exist (ownership integrity).
func TestMemoryCreateSandFSUnknownAgent(t *testing.T) {
	s := NewMemoryStore("/tmp/volroot")

	_, err := s.CreateSandFS("agent-does-not-exist", CreateSandFSRequest{Name: "orphan"})
	if err == nil {
		t.Fatal("CreateSandFS with unknown agent: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "agent not found") {
		t.Errorf("error = %q, want substring %q", err.Error(), "agent not found")
	}
}

// TestMemoryCreateSandFSUniqueIDs verifies multiple sandfs for the same agent
// get distinct IDs.
func TestMemoryCreateSandFSUniqueIDs(t *testing.T) {
	s := NewMemoryStore("/tmp/volroot")
	agent, _ := mustCreateAgent(t, s, "owner")

	seen := make(map[string]bool)
	for i := 0; i < 50; i++ {
		rec, err := s.CreateSandFS(agent.ID, CreateSandFSRequest{Name: "vol"})
		if err != nil {
			t.Fatalf("CreateSandFS %d: %v", i, err)
		}
		if seen[rec.ID] {
			t.Fatalf("duplicate sandfs ID %s on iteration %d", rec.ID, i)
		}
		seen[rec.ID] = true
	}
}

// ─── ListSandFSByAgent ──────────────────────────────────────────

// TestMemoryListSandFSByAgent verifies the reverse index returns all sandfs
// owned by an agent and only those.
func TestMemoryListSandFSByAgent(t *testing.T) {
	s := NewMemoryStore("/tmp/volroot")
	agentA, _ := mustCreateAgent(t, s, "agent-a")
	agentB, _ := mustCreateAgent(t, s, "agent-b")

	// agentA owns 3 sandfs, agentB owns 1.
	recA1 := mustCreateSandFS(t, s, agentA.ID, CreateSandFSRequest{Name: "a1"})
	recA2 := mustCreateSandFS(t, s, agentA.ID, CreateSandFSRequest{Name: "a2"})
	recA3 := mustCreateSandFS(t, s, agentA.ID, CreateSandFSRequest{Name: "a3"})
	recB1 := mustCreateSandFS(t, s, agentB.ID, CreateSandFSRequest{Name: "b1"})

	recsA, err := s.ListSandFSByAgent(agentA.ID)
	if err != nil {
		t.Fatalf("ListSandFSByAgent(A): %v", err)
	}
	if len(recsA) != 3 {
		t.Fatalf("agentA sandfs count = %d, want 3", len(recsA))
	}
	gotIDs := map[string]bool{recA1.ID: true, recA2.ID: true, recA3.ID: true}
	for _, r := range recsA {
		if !gotIDs[r.ID] {
			t.Errorf("unexpected sandfs %s in agentA list", r.ID)
		}
		if r.AgentID != agentA.ID {
			t.Errorf("sandfs %s has AgentID %q, want %q", r.ID, r.AgentID, agentA.ID)
		}
	}

	recsB, err := s.ListSandFSByAgent(agentB.ID)
	if err != nil {
		t.Fatalf("ListSandFSByAgent(B): %v", err)
	}
	if len(recsB) != 1 || recsB[0].ID != recB1.ID {
		t.Errorf("agentB sandfs = %+v, want [%s]", recsB, recB1.ID)
	}
}

// TestMemoryListSandFSByAgentEmpty verifies an agent with no sandfs returns an
// empty (non-nil) slice, not an error.
func TestMemoryListSandFSByAgentEmpty(t *testing.T) {
	s := NewMemoryStore("/tmp/volroot")
	agent, _ := mustCreateAgent(t, s, "lonely")

	recs, err := s.ListSandFSByAgent(agent.ID)
	if err != nil {
		t.Fatalf("ListSandFSByAgent: %v", err)
	}
	if len(recs) != 0 {
		t.Errorf("expected 0 sandfs, got %d", len(recs))
	}
}

// TestMemoryListSandFSByAgentUnknown verifies a non-existent agent returns an
// empty slice (no error). The store doesn't distinguish "agent doesn't exist"
// from "agent has no sandfs" - callers verify agent existence separately.
func TestMemoryListSandFSByAgentUnknown(t *testing.T) {
	s := NewMemoryStore("/tmp/volroot")

	recs, err := s.ListSandFSByAgent("agent-ghost")
	if err != nil {
		t.Fatalf("ListSandFSByAgent(unknown): %v", err)
	}
	if len(recs) != 0 {
		t.Errorf("expected 0 sandfs for unknown agent, got %d", len(recs))
	}
}

// TestMemoryListSandFSByAgentDeepCopy verifies the returned records are deep
// copies - mutating them must not affect the store's internal state. This
// prevents callers from accidentally corrupting the identity store via the
// discovery endpoint (GET /agent/sandfs).
func TestMemoryListSandFSByAgentDeepCopy(t *testing.T) {
	s := NewMemoryStore("/tmp/volroot")
	agent, _ := mustCreateAgent(t, s, "owner")
	rec := mustCreateSandFS(t, s, agent.ID, CreateSandFSRequest{Name: "original"})

	list1, _ := s.ListSandFSByAgent(agent.ID)
	list1[0].Name = "MUTATED"
	list1[0].RootFSPath = "/injected"

	// Re-list: internal state must be unchanged.
	list2, _ := s.ListSandFSByAgent(agent.ID)
	if len(list2) != 1 {
		t.Fatalf("expected 1 sandfs, got %d", len(list2))
	}
	if list2[0].Name != "original" {
		t.Errorf("Name mutated through returned pointer: got %q, want %q", list2[0].Name, "original")
	}
	if list2[0].RootFSPath != "" {
		t.Errorf("RootFSPath mutated through returned pointer: got %q", list2[0].RootFSPath)
	}
	// The actual stored record is untouched.
	stored, _ := s.GetSandFS(rec.ID)
	if stored.Name != "original" {
		t.Errorf("stored Name corrupted: got %q", stored.Name)
	}
}

// ─── ListAllSandFS ──────────────────────────────────────────────

// TestMemoryListAllSandFS verifies the operator view returns every sandfs
// across all agents.
func TestMemoryListAllSandFS(t *testing.T) {
	s := NewMemoryStore("/tmp/volroot")
	agentA, _ := mustCreateAgent(t, s, "a")
	agentB, _ := mustCreateAgent(t, s, "b")

	mustCreateSandFS(t, s, agentA.ID, CreateSandFSRequest{Name: "a1"})
	mustCreateSandFS(t, s, agentA.ID, CreateSandFSRequest{Name: "a2"})
	mustCreateSandFS(t, s, agentB.ID, CreateSandFSRequest{Name: "b1"})

	recs, err := s.ListAllSandFS()
	if err != nil {
		t.Fatalf("ListAllSandFS: %v", err)
	}
	if len(recs) != 3 {
		t.Errorf("expected 3 sandfs, got %d", len(recs))
	}
}

// TestMemoryListAllSandFSEmpty verifies an empty store returns an empty slice.
func TestMemoryListAllSandFSEmpty(t *testing.T) {
	s := NewMemoryStore("/tmp/volroot")

	recs, err := s.ListAllSandFS()
	if err != nil {
		t.Fatalf("ListAllSandFS: %v", err)
	}
	if len(recs) != 0 {
		t.Errorf("expected 0 sandfs, got %d", len(recs))
	}
}

// TestMemoryListAllSandFSDeepCopy verifies the returned records are deep copies.
func TestMemoryListAllSandFSDeepCopy(t *testing.T) {
	s := NewMemoryStore("/tmp/volroot")
	agent, _ := mustCreateAgent(t, s, "owner")
	mustCreateSandFS(t, s, agent.ID, CreateSandFSRequest{Name: "orig"})

	recs, _ := s.ListAllSandFS()
	recs[0].Name = "MUTATED"
	recs[0].MinVCPUs = 99

	recs2, _ := s.ListAllSandFS()
	for _, r := range recs2 {
		if r.Name == "MUTATED" {
			t.Fatal("ListAllSandFS returned a pointer to internal state - not deep copied")
		}
		if r.MinVCPUs == 99 {
			t.Fatal("ListAllSandFS MinVCPUs mutated through returned pointer")
		}
	}
}

// ─── ListAgents ─────────────────────────────────────────────────

// TestMemoryListAgents verifies ListAgents returns all created agents.
func TestMemoryListAgents(t *testing.T) {
	s := NewMemoryStore("/tmp/volroot")

	// Empty store -> empty list.
	agents, err := s.ListAgents()
	if err != nil {
		t.Fatalf("ListAgents empty: %v", err)
	}
	if len(agents) != 0 {
		t.Errorf("expected 0 agents, got %d", len(agents))
	}

	mustCreateAgent(t, s, "a")
	mustCreateAgent(t, s, "b")

	agents, err = s.ListAgents()
	if err != nil {
		t.Fatalf("ListAgents: %v", err)
	}
	if len(agents) != 2 {
		t.Errorf("expected 2 agents, got %d", len(agents))
	}

	names := make(map[string]bool)
	for _, a := range agents {
		names[a.Name] = true
	}
	if !names["a"] || !names["b"] {
		t.Errorf("agent names = %v, want {a, b}", names)
	}
}

// ─── DeleteSandFS ───────────────────────────────────────────────

// TestMemoryDeleteSandFS verifies deleting a sandfs removes it from both the
// primary map and the per-agent reverse index.
func TestMemoryDeleteSandFS(t *testing.T) {
	s := NewMemoryStore("/tmp/volroot")
	agent, _ := mustCreateAgent(t, s, "owner")
	rec := mustCreateSandFS(t, s, agent.ID, CreateSandFSRequest{Name: "doomed"})

	if err := s.DeleteSandFS(rec.ID); err != nil {
		t.Fatalf("DeleteSandFS: %v", err)
	}

	// Primary map: gone.
	if _, err := s.GetSandFS(rec.ID); err == nil {
		t.Fatal("GetSandFS after delete: expected error, got nil")
	}
	// Reverse index: no longer listed under the agent.
	recs, _ := s.ListSandFSByAgent(agent.ID)
	if len(recs) != 0 {
		t.Errorf("ListSandFSByAgent after delete: expected 0, got %d", len(recs))
	}
	// ListAllSandFS: not present.
	all, _ := s.ListAllSandFS()
	for _, r := range all {
		if r.ID == rec.ID {
			t.Error("deleted sandfs still in ListAllSandFS")
		}
	}
}

// TestMemoryDeleteSandFSNotFound verifies deleting an unknown sandfs errors.
func TestMemoryDeleteSandFSNotFound(t *testing.T) {
	s := NewMemoryStore("/tmp/volroot")

	if err := s.DeleteSandFS("sandfs-ghost"); err == nil {
		t.Fatal("DeleteSandFS(unknown): expected error, got nil")
	}
}

// TestMemoryDeleteSandFSPreservesOthers verifies deleting one sandfs doesn't
// affect sibling sandfs under the same agent (reverse index slice integrity).
func TestMemoryDeleteSandFSPreservesOthers(t *testing.T) {
	s := NewMemoryStore("/tmp/volroot")
	agent, _ := mustCreateAgent(t, s, "owner")
	rec1 := mustCreateSandFS(t, s, agent.ID, CreateSandFSRequest{Name: "keep"})
	rec2 := mustCreateSandFS(t, s, agent.ID, CreateSandFSRequest{Name: "delete"})
	rec3 := mustCreateSandFS(t, s, agent.ID, CreateSandFSRequest{Name: "keep2"})

	if err := s.DeleteSandFS(rec2.ID); err != nil {
		t.Fatalf("DeleteSandFS: %v", err)
	}

	recs, _ := s.ListSandFSByAgent(agent.ID)
	if len(recs) != 2 {
		t.Fatalf("expected 2 remaining sandfs, got %d", len(recs))
	}
	got := map[string]bool{}
	for _, r := range recs {
		got[r.ID] = true
	}
	if !got[rec1.ID] || !got[rec3.ID] {
		t.Errorf("remaining sandfs = %v, want %s and %s", got, rec1.ID, rec3.ID)
	}
}

// TestMemoryDeleteSandFSAllThenRecreate verifies the reverse index slice is
// cleaned to empty and a subsequent create starts fresh (no nil/dangling entries).
func TestMemoryDeleteSandFSAllThenRecreate(t *testing.T) {
	s := NewMemoryStore("/tmp/volroot")
	agent, _ := mustCreateAgent(t, s, "owner")

	r1 := mustCreateSandFS(t, s, agent.ID, CreateSandFSRequest{Name: "1"})
	r2 := mustCreateSandFS(t, s, agent.ID, CreateSandFSRequest{Name: "2"})

	_ = s.DeleteSandFS(r1.ID)
	_ = s.DeleteSandFS(r2.ID)

	recs, _ := s.ListSandFSByAgent(agent.ID)
	if len(recs) != 0 {
		t.Fatalf("expected 0 after deleting all, got %d", len(recs))
	}

	// Recreate - reverse index should work.
	rec := mustCreateSandFS(t, s, agent.ID, CreateSandFSRequest{Name: "fresh"})
	recs, _ = s.ListSandFSByAgent(agent.ID)
	if len(recs) != 1 || recs[0].ID != rec.ID {
		t.Errorf("after recreate: expected [%s], got %+v", rec.ID, recs)
	}
}

// ─── DeleteAgent ────────────────────────────────────────────────

// TestMemoryDeleteAgent verifies deleting an agent removes the agent, its API
// key mapping, and all its sandfs records (cascade delete).
func TestMemoryDeleteAgent(t *testing.T) {
	s := NewMemoryStore("/tmp/volroot")
	agent, key, _ := s.CreateAgent(CreateAgentRequest{Name: "owner"})
	rec := mustCreateSandFS(t, s, agent.ID, CreateSandFSRequest{Name: "vol"})

	if err := s.DeleteAgent(agent.ID); err != nil {
		t.Fatalf("DeleteAgent: %v", err)
	}

	// Agent gone.
	agents, _ := s.ListAgents()
	for _, a := range agents {
		if a.ID == agent.ID {
			t.Error("deleted agent still in ListAgents")
		}
	}
	// API key no longer resolves.
	if _, err := s.ResolveAgent(key); err == nil {
		t.Error("deleted agent's API key still resolves")
	}
	// SandFS cascade-deleted.
	if _, err := s.GetSandFS(rec.ID); err == nil {
		t.Error("deleted agent's sandfs still retrievable")
	}
	recs, _ := s.ListSandFSByAgent(agent.ID)
	if len(recs) != 0 {
		t.Errorf("deleted agent's sandfs reverse index not cleared: %d", len(recs))
	}
}

// TestMemoryDeleteAgentNotFound verifies deleting an unknown agent errors.
func TestMemoryDeleteAgentNotFound(t *testing.T) {
	s := NewMemoryStore("/tmp/volroot")

	if err := s.DeleteAgent("agent-ghost"); err == nil {
		t.Fatal("DeleteAgent(unknown): expected error, got nil")
	}
}

// TestMemoryDeleteAgentPreservesOthers verifies deleting one agent doesn't
// affect another agent's sandfs.
func TestMemoryDeleteAgentPreservesOthers(t *testing.T) {
	s := NewMemoryStore("/tmp/volroot")
	agentA, _ := mustCreateAgent(t, s, "a")
	agentB, _ := mustCreateAgent(t, s, "b")
	recA := mustCreateSandFS(t, s, agentA.ID, CreateSandFSRequest{Name: "a-vol"})
	recB := mustCreateSandFS(t, s, agentB.ID, CreateSandFSRequest{Name: "b-vol"})

	if err := s.DeleteAgent(agentA.ID); err != nil {
		t.Fatalf("DeleteAgent(A): %v", err)
	}

	// Agent B and its sandfs untouched.
	if _, err := s.GetSandFS(recB.ID); err != nil {
		t.Errorf("agentB sandfs gone after deleting agentA: %v", err)
	}
	if _, err := s.GetSandFS(recA.ID); err == nil {
		t.Error("agentA sandfs should be cascade-deleted")
	}
	agents, _ := s.ListAgents()
	if len(agents) != 1 || agents[0].ID != agentB.ID {
		t.Errorf("ListAgents = %+v, want only agentB", agents)
	}
}

// TestMemoryDeleteAgentCascadesMultipleSandfs verifies all sandfs owned by the
// agent are removed (not just the first found).
func TestMemoryDeleteAgentCascadesMultipleSandfs(t *testing.T) {
	s := NewMemoryStore("/tmp/volroot")
	agent, _ := mustCreateAgent(t, s, "owner")
	for i := 0; i < 5; i++ {
		mustCreateSandFS(t, s, agent.ID, CreateSandFSRequest{Name: "vol"})
	}

	if err := s.DeleteAgent(agent.ID); err != nil {
		t.Fatalf("DeleteAgent: %v", err)
	}

	all, _ := s.ListAllSandFS()
	if len(all) != 0 {
		t.Errorf("expected 0 sandfs after cascade delete, got %d", len(all))
	}
}

// ─── SetRootFSPath / SetMinSpec ─────────────────────────────────

// TestMemorySetRootFSPath verifies SetRootFSPath updates the record. This is
// called by the Registry after volume creation to record the host path the
// warden will bind-mount.
func TestMemorySetRootFSPath(t *testing.T) {
	s := NewMemoryStore("/tmp/volroot")
	agent, _ := mustCreateAgent(t, s, "owner")
	rec := mustCreateSandFS(t, s, agent.ID, CreateSandFSRequest{Name: "vol"})

	const path = "/var/sandswap/volumes/sandfs-abc/rootfs"
	if err := s.SetRootFSPath(rec.ID, path); err != nil {
		t.Fatalf("SetRootFSPath: %v", err)
	}

	got, _ := s.GetSandFS(rec.ID)
	if got.RootFSPath != path {
		t.Errorf("RootFSPath = %q, want %q", got.RootFSPath, path)
	}
}

// TestMemorySetMinSpec verifies SetMinSpec updates the record. MinSpec comes
// from the template ref and gates VM sizing.
func TestMemorySetMinResources(t *testing.T) {
	s := NewMemoryStore("/tmp/volroot")
	agent, _ := mustCreateAgent(t, s, "owner")
	rec := mustCreateSandFS(t, s, agent.ID, CreateSandFSRequest{Name: "vol"})

	if err := s.SetMinResources(rec.ID, 2, 512); err != nil {
		t.Fatalf("SetMinResources: %v", err)
	}

	got, _ := s.GetSandFS(rec.ID)
	if got.MinVCPUs != 2 || got.MinMemoryMB != 512 {
		t.Errorf("MinVCPUs=%d MinMemoryMB=%d, want 2/512", got.MinVCPUs, got.MinMemoryMB)
	}
}

// TestMemorySettersNotFound verifies the field setters return an error when the
// sandfs doesn't exist. This matches EtcdStore.updateRecord, which returns
// "sandfs not found" - the Registry caller (registry/sandfs.go:132) checks this
// error to decide whether to roll back volume creation.
func TestMemorySettersNotFound(t *testing.T) {
	s := NewMemoryStore("/tmp/volroot")

	cases := []struct {
		name string
		fn   func() error
	}{
		{"SetRootFSPath", func() error { return s.SetRootFSPath("sandfs-ghost", "/x") }},
		{"SetMinResources", func() error { return s.SetMinResources("sandfs-ghost", 2, 512) }},
	}
	for _, c := range cases {
		if err := c.fn(); err == nil {
			t.Errorf("%s(unknown): expected error, got nil", c.name)
		} else if !strings.Contains(err.Error(), "not found") {
			t.Errorf("%s(unknown): error = %q, want substring %q", c.name, err.Error(), "not found")
		}
	}
}

// ─── Concurrency ────────────────────────────────────────────────

// TestMemoryStoreConcurrentResolve verifies ResolveAgent is safe under
// concurrent reads (RLock path). This is the /agent/execute hot path - multiple
// goroutines resolve API keys simultaneously.
func TestMemoryStoreConcurrentResolve(t *testing.T) {
	s := NewMemoryStore("/tmp/volroot")
	_, key := mustCreateAgent(t, s, "concurrent")

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)
	errs := make(chan error, goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			if _, err := s.ResolveAgent(key); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent ResolveAgent: %v", err)
	}
}

// TestMemoryStoreConcurrentCreate verifies CreateAgent/ResolveAgent under
// concurrent writes don't race (Lock path). The race detector would catch any
// missing synchronization.
func TestMemoryStoreConcurrentCreate(t *testing.T) {
	s := NewMemoryStore("/tmp/volroot")

	const goroutines = 20
	var wg sync.WaitGroup
	wg.Add(goroutines * 2)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			mustCreateAgent(t, s, "agent")
		}()
		go func() {
			defer wg.Done()
			_, _ = s.ListAgents()
		}()
	}
	wg.Wait()
}

// ─── Full lifecycle ─────────────────────────────────────────────

// TestMemoryStoreFullLifecycle exercises the complete agent+sandfs lifecycle:
// create agent -> create sandfs -> set fields -> resolve -> list -> delete
// sandfs -> delete agent. This verifies the maps and reverse index stay
// consistent across a realistic sequence of operations.
func TestMemoryStoreFullLifecycle(t *testing.T) {
	s := NewMemoryStore("/tmp/volroot")

	// 1. Create agent.
	agent, key, err := s.CreateAgent(CreateAgentRequest{Name: "lifecycle-agent"})
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}

	// 2. Resolve via API key (hot path).
	resolved, err := s.ResolveAgent(key)
	if err != nil {
		t.Fatalf("ResolveAgent: %v", err)
	}
	if resolved.ID != agent.ID {
		t.Fatalf("resolved.ID = %q, want %q", resolved.ID, agent.ID)
	}

	// 3. Create sandfs.
	rec, err := s.CreateSandFS(agent.ID, CreateSandFSRequest{
		Name:     "lifecycle-vol",
		Template: "ubuntu:v1",
		Mode:     "overlay",
	})
	if err != nil {
		t.Fatalf("CreateSandFS: %v", err)
	}

	// 4. Set fields (Registry post-create).
	if err := s.SetRootFSPath(rec.ID, "/data/vol/rootfs"); err != nil {
		t.Fatalf("SetRootFSPath: %v", err)
	}
	if err := s.SetMinResources(rec.ID, 2, 512); err != nil {
		t.Fatalf("SetMinResources: %v", err)
	}

	// 5. Verify fields persisted.
	got, err := s.GetSandFS(rec.ID)
	if err != nil {
		t.Fatalf("GetSandFS: %v", err)
	}
	if got.RootFSPath != "/data/vol/rootfs" {
		t.Errorf("RootFSPath = %q", got.RootFSPath)
	}
	if got.MinVCPUs != 2 || got.MinMemoryMB != 512 {
		t.Errorf("MinVCPUs=%d MinMemoryMB=%d, want 2/512", got.MinVCPUs, got.MinMemoryMB)
	}
	if !got.UsesOverlayFS() {
		t.Error("UsesOverlayFS = false, want true for overlay mode")
	}

	// 6. List by agent.
	recs, err := s.ListSandFSByAgent(agent.ID)
	if err != nil {
		t.Fatalf("ListSandFSByAgent: %v", err)
	}
	if len(recs) != 1 || recs[0].ID != rec.ID {
		t.Errorf("ListSandFSByAgent = %+v, want [%s]", recs, rec.ID)
	}

	// 7. Delete sandfs.
	if err := s.DeleteSandFS(rec.ID); err != nil {
		t.Fatalf("DeleteSandFS: %v", err)
	}
	if _, err := s.GetSandFS(rec.ID); err == nil {
		t.Fatal("GetSandFS after delete: expected error")
	}

	// 8. Delete agent.
	if err := s.DeleteAgent(agent.ID); err != nil {
		t.Fatalf("DeleteAgent: %v", err)
	}
	if _, err := s.ResolveAgent(key); err == nil {
		t.Fatal("ResolveAgent after delete: expected error")
	}
}

// TestNewPublicIDRegeneratesOnCollision verifies the regenerate-on-collision
// contract every creation path relies on: a taken ID is never returned (a
// silent overwrite would hand one identity two owners), and an
// endlessly-colliding exists() fails loudly instead of looping forever.
func TestNewPublicIDRegeneratesOnCollision(t *testing.T) {
	draws := 0
	id, err := newPublicID("agent-", func(id string) bool {
		draws++
		return draws <= 3 // first 3 draws collide, the 4th is free
	})
	if err != nil {
		t.Fatalf("newPublicID: %v", err)
	}
	if draws != 4 {
		t.Fatalf("exists called %d times, want 4 (3 collisions then a free draw)", draws)
	}
	if len(id) != len("agent-")+8 {
		t.Fatalf("id %q has wrong shape", id)
	}

	if _, err := newPublicID("agent-", func(string) bool { return true }); err == nil {
		t.Fatal("endlessly colliding exists() must error, not loop or return a duplicate")
	}
}

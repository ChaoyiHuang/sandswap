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
	"testing"
)

// ─── Record.UsesOverlayFS ──────────────────────────────────────

// TestUsesOverlayFS verifies the mode-detection logic on Record. The Sandswap
// design has two rootfs modes:
//   - flat:    plain directory bind-mount (no overlay). Template is copied via cp -a.
//   - overlay: read-only OverlayFS lowerdir (NO upperdir/workdir — mounts on any filesystem).
//
// UsesOverlayFS drives the warden's 5-step mount sequence (overlay needs the
// readonly bind + writable workspace/home bind mounts; flat needs only the single bind).
// A missing Mode (empty string) is treated as overlay - the gateway auto-detects
// mode, and an unspecified mode defaults to overlay (see store.go CreateSandFSRequest).
func TestUsesOverlayFS(t *testing.T) {
	cases := []struct {
		name     string
		template string
		mode     string
		want     bool
	}{
		// No template -> plain bind mount (no overlay regardless of mode).
		{"no template", "", "flat", false},
		{"no template overlay mode", "", "overlay", false},
		{"no template empty mode", "", "", false},

		// Flat mode -> bind mount, NOT overlay (even with a template).
		{"flat with template", "ubuntu:v1", "flat", false},

		// Overlay mode -> overlay.
		{"overlay with template", "ubuntu:v1", "overlay", true},

		// Empty mode with template -> defaults to overlay (auto-detect).
		{"empty mode with template (auto-detect)", "ubuntu:v1", "", true},

		// Unknown mode with template -> treated as overlay (only "flat" is
		// explicitly non-overlay; any other value, including typos, defaults
		// to overlay. This is permissive but safe - overlay is the default).
		{"unknown mode with template", "ubuntu:v1", "weird", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := &Record{Template: c.template, Mode: c.mode}
			if got := r.UsesOverlayFS(); got != c.want {
				t.Errorf("UsesOverlayFS() = %v, want %v (template=%q mode=%q)", got, c.want, c.template, c.mode)
			}
		})
	}
}

// ─── Store interface conformance ────────────────────────────────

// runStoreConformance runs the standard Store interface contract tests against
// any Store implementation. This ensures MemoryStore and EtcdStore behave
// identically on the contract surface (the /agent/execute hot path depends on
// both having the same ResolveAgent/GetSandFS semantics).
//
// Each subtest verifies one aspect of the contract. The factory returns a fresh
// empty Store for each subtest so they're independent.
func runStoreConformance(t *testing.T, factory func(t *testing.T) Store) {
	t.Helper()

	// ── Agent create + resolve (hot path) ──
	t.Run("agent create and resolve", func(t *testing.T) {
		s := factory(t)
		agent, key, err := s.CreateAgent(CreateAgentRequest{Name: "conf-agent"})
		if err != nil {
			t.Fatalf("CreateAgent: %v", err)
		}
		if agent.ID == "" {
			t.Fatal("agent.ID is empty")
		}
		if key == "" {
			t.Fatal("api key is empty")
		}
		if agent.APIKey != key {
			t.Fatalf("agent.APIKey %q != returned key %q", agent.APIKey, key)
		}

		resolved, err := s.ResolveAgent(key)
		if err != nil {
			t.Fatalf("ResolveAgent: %v", err)
		}
		if resolved.ID != agent.ID {
			t.Errorf("resolved.ID = %q, want %q", resolved.ID, agent.ID)
		}
	})

	// ── Resolve unknown key fails ──
	t.Run("resolve unknown key fails", func(t *testing.T) {
		s := factory(t)
		if _, err := s.ResolveAgent("sk-sandswap-agent-nonexistent"); err == nil {
			t.Fatal("ResolveAgent(unknown): expected error, got nil")
		}
	})

	// ── Resolve empty key fails ──
	t.Run("resolve empty key fails", func(t *testing.T) {
		s := factory(t)
		if _, err := s.ResolveAgent(""); err == nil {
			t.Fatal("ResolveAgent(\"\"): expected error, got nil")
		}
	})

	// ── CreateSandFS requires existing agent ──
	t.Run("create sandfs requires agent", func(t *testing.T) {
		s := factory(t)
		_, err := s.CreateSandFS("agent-nonexistent", CreateSandFSRequest{Name: "vol"})
		if err == nil {
			t.Fatal("CreateSandFS(unknown agent): expected error, got nil")
		}
		if !strings.Contains(err.Error(), "agent not found") {
			t.Errorf("error = %q, want substring %q", err.Error(), "agent not found")
		}
	})

	// ── GetSandFS not found ──
	t.Run("get sandfs not found", func(t *testing.T) {
		s := factory(t)
		_, err := s.GetSandFS("sandfs-nonexistent")
		if err == nil {
			t.Fatal("GetSandFS(unknown): expected error, got nil")
		}
	})

	// ── DeleteSandFS not found ──
	t.Run("delete sandfs not found", func(t *testing.T) {
		s := factory(t)
		if err := s.DeleteSandFS("sandfs-nonexistent"); err == nil {
			t.Fatal("DeleteSandFS(unknown): expected error, got nil")
		}
	})

	// ── DeleteAgent not found ──
	t.Run("delete agent not found", func(t *testing.T) {
		s := factory(t)
		if err := s.DeleteAgent("agent-nonexistent"); err == nil {
			t.Fatal("DeleteAgent(unknown): expected error, got nil")
		}
	})

	// ── Setters require existing sandfs ──
	// Both MemoryStore and EtcdStore must return an error when the target
	// sandfs doesn't exist. The Registry caller checks this to decide rollback.
	t.Run("setters require existing sandfs", func(t *testing.T) {
		s := factory(t)
		if err := s.SetRootFSPath("sandfs-ghost", "/x"); err == nil {
			t.Error("SetRootFSPath(unknown): expected error")
		}
		if err := s.SetMinResources("sandfs-ghost", 4, 2048); err == nil {
			t.Error("SetMinResources(unknown): expected error")
		}
	})

	// ── DeleteAgent cascades sandfs ──
	t.Run("delete agent cascades sandfs", func(t *testing.T) {
		s := factory(t)
		agent, key, _ := s.CreateAgent(CreateAgentRequest{Name: "owner"})
		rec, _ := s.CreateSandFS(agent.ID, CreateSandFSRequest{Name: "vol"})

		if err := s.DeleteAgent(agent.ID); err != nil {
			t.Fatalf("DeleteAgent: %v", err)
		}
		// API key no longer resolves.
		if _, err := s.ResolveAgent(key); err == nil {
			t.Error("deleted agent's key still resolves")
		}
		// SandFS cascade-deleted.
		if _, err := s.GetSandFS(rec.ID); err == nil {
			t.Error("deleted agent's sandfs still retrievable")
		}
	})

	// ── ListSandFSByAgent returns owned records only ──
	t.Run("list sandfs by agent", func(t *testing.T) {
		s := factory(t)
		agentA, _, _ := s.CreateAgent(CreateAgentRequest{Name: "a"})
		agentB, _, _ := s.CreateAgent(CreateAgentRequest{Name: "b"})
		recA, _ := s.CreateSandFS(agentA.ID, CreateSandFSRequest{Name: "a-vol"})
		s.CreateSandFS(agentB.ID, CreateSandFSRequest{Name: "b-vol"})

		recs, err := s.ListSandFSByAgent(agentA.ID)
		if err != nil {
			t.Fatalf("ListSandFSByAgent: %v", err)
		}
		if len(recs) != 1 || recs[0].ID != recA.ID {
			t.Errorf("ListSandFSByAgent(A) = %+v, want [%s]", recs, recA.ID)
		}
	})

	// ── ListSandFSByAgent empty returns empty ──
	t.Run("list sandfs by agent empty", func(t *testing.T) {
		s := factory(t)
		agent, _, _ := s.CreateAgent(CreateAgentRequest{Name: "lonely"})

		recs, err := s.ListSandFSByAgent(agent.ID)
		if err != nil {
			t.Fatalf("ListSandFSByAgent: %v", err)
		}
		if len(recs) != 0 {
			t.Errorf("expected 0, got %d", len(recs))
		}
	})

	// ── ListAllSandFS returns everything ──
	t.Run("list all sandfs", func(t *testing.T) {
		s := factory(t)
		agent, _, _ := s.CreateAgent(CreateAgentRequest{Name: "owner"})
		s.CreateSandFS(agent.ID, CreateSandFSRequest{Name: "1"})
		s.CreateSandFS(agent.ID, CreateSandFSRequest{Name: "2"})

		recs, err := s.ListAllSandFS()
		if err != nil {
			t.Fatalf("ListAllSandFS: %v", err)
		}
		if len(recs) != 2 {
			t.Errorf("expected 2, got %d", len(recs))
		}
	})

	// ── ListAgents returns all ──
	t.Run("list agents", func(t *testing.T) {
		s := factory(t)
		s.CreateAgent(CreateAgentRequest{Name: "a"})
		s.CreateAgent(CreateAgentRequest{Name: "b"})

		agents, err := s.ListAgents()
		if err != nil {
			t.Fatalf("ListAgents: %v", err)
		}
		if len(agents) != 2 {
			t.Errorf("expected 2, got %d", len(agents))
		}
	})

	// ── ListAllSandFS deep copy ──
	// Both implementations must deep-copy Records returned from ListAllSandFS
	// so callers can't mutate internal state.
	t.Run("list all sandfs deep copy", func(t *testing.T) {
		s := factory(t)
		agent, _, _ := s.CreateAgent(CreateAgentRequest{Name: "owner"})
		rec, _ := s.CreateSandFS(agent.ID, CreateSandFSRequest{Name: "orig"})

		recs, _ := s.ListAllSandFS()
		for _, r := range recs {
			if r.ID == rec.ID {
				r.Name = "MUTATED"
				r.RootFSPath = "/injected"
			}
		}
		recs2, _ := s.ListAllSandFS()
		for _, r := range recs2 {
			if r.ID == rec.ID {
				if r.Name != "orig" {
					t.Errorf("Name mutated through ListAllSandFS: got %q", r.Name)
				}
				if r.RootFSPath != "" {
					t.Errorf("RootFSPath mutated through ListAllSandFS: got %q", r.RootFSPath)
				}
			}
		}
	})

	// ── ListSandFSByAgent deep copy ──
	t.Run("list sandfs by agent deep copy", func(t *testing.T) {
		s := factory(t)
		agent, _, _ := s.CreateAgent(CreateAgentRequest{Name: "owner"})
		rec, _ := s.CreateSandFS(agent.ID, CreateSandFSRequest{Name: "orig"})

		recs, _ := s.ListSandFSByAgent(agent.ID)
		for _, r := range recs {
			if r.ID == rec.ID {
				r.Name = "MUTATED"
				r.MinVCPUs = 99
			}
		}
		recs2, _ := s.ListSandFSByAgent(agent.ID)
		for _, r := range recs2 {
			if r.ID == rec.ID {
				if r.Name != "orig" {
					t.Errorf("Name mutated through ListSandFSByAgent: got %q", r.Name)
				}
				if r.MinVCPUs == 99 {
					t.Error("MinVCPUs mutated through ListSandFSByAgent")
				}
			}
		}
	})

	// ── Setters mutate persisted record ──
	t.Run("setters mutate persisted record", func(t *testing.T) {
		s := factory(t)
		agent, _, _ := s.CreateAgent(CreateAgentRequest{Name: "owner"})
		rec, _ := s.CreateSandFS(agent.ID, CreateSandFSRequest{Name: "vol"})

		s.SetRootFSPath(rec.ID, "/data/rootfs")
		s.SetMinResources(rec.ID, 4, 2048)

		got, _ := s.GetSandFS(rec.ID)
		if got.RootFSPath != "/data/rootfs" {
			t.Errorf("RootFSPath = %q, want %q", got.RootFSPath, "/data/rootfs")
		}
		if got.MinVCPUs != 4 || got.MinMemoryMB != 2048 {
			t.Errorf("MinVCPUs=%d MinMemoryMB=%d, want 4/2048", got.MinVCPUs, got.MinMemoryMB)
		}
	})

	// ── DeleteSandFS preserves siblings ──
	t.Run("delete sandfs preserves siblings", func(t *testing.T) {
		s := factory(t)
		agent, _, _ := s.CreateAgent(CreateAgentRequest{Name: "owner"})
		keep, _ := s.CreateSandFS(agent.ID, CreateSandFSRequest{Name: "keep"})
		del, _ := s.CreateSandFS(agent.ID, CreateSandFSRequest{Name: "del"})

		s.DeleteSandFS(del.ID)

		if _, err := s.GetSandFS(keep.ID); err != nil {
			t.Errorf("sibling sandfs lost after delete: %v", err)
		}
		recs, _ := s.ListSandFSByAgent(agent.ID)
		if len(recs) != 1 || recs[0].ID != keep.ID {
			t.Errorf("after delete: expected [%s], got %+v", keep.ID, recs)
		}
	})
}

// TestMemoryStoreConformance runs the Store interface conformance suite against
// MemoryStore. This is the single-node default; EtcdStore conformance is
// covered by the identity_e2e build-tagged tests.
func TestMemoryStoreConformance(t *testing.T) {
	runStoreConformance(t, func(t *testing.T) Store {
		t.Helper()
		return NewMemoryStore("/tmp/volroot")
	})
}

// TestMemoryStoreSatisfiesInterface is a compile-time check that MemoryStore
// implements the Store interface. If a method is missing or has the wrong
// signature, this fails to compile.
func TestMemoryStoreSatisfiesInterface(t *testing.T) {
	var _ Store = (*MemoryStore)(nil)
	var _ Store = NewMemoryStore("/tmp/volroot")
}

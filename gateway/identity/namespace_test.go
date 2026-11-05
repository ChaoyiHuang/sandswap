// Copyright 2026 Chaoyi Huang. All rights reserved.
//
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE file at the root of this repository.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, your use of this software will be
// governed by the Apache License, Version 2.0.

// Namespace model unit tests: the name grammar, legacy normalization, the
// create-time stamping rules (agent from request; sandfs frozen from the
// agent), the per-namespace listing partition, and the etcd WIRE pins —
// namespace must ride the agent record and the HOT sandfs record (the
// human gateway's watch-fed cache is built from hot records only; a field
// dropped from either wire shape silently breaks per-ns routing, and only a
// wire-level pin catches that — the split-lifecycle whitelist lesson).

package identity

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestValidNamespace(t *testing.T) {
	valid := []string{"a", "acme", "beta-prod", "x9", "n" + strings.Repeat("x", 62)}
	for _, ns := range valid {
		if !ValidNamespace(ns) {
			t.Errorf("%q must be valid", ns)
		}
	}
	invalid := []string{
		"", "*", "Acme", "1abc", "-acme", "acme-", "a_b", "a.b", "a b", "a/b",
		"n" + strings.Repeat("x", 63), "中文",
	}
	for _, ns := range invalid {
		if ValidNamespace(ns) {
			t.Errorf("%q must be invalid", ns)
		}
	}
}

func TestNamespaceOrDefault(t *testing.T) {
	a := &Agent{}
	if a.NamespaceOrDefault() != DefaultNamespace || DefaultNamespace != "default" {
		t.Errorf("legacy agent must read as default, got %q", a.NamespaceOrDefault())
	}
	a.Namespace = "acme"
	if a.NamespaceOrDefault() != "acme" {
		t.Errorf("explicit ns must pass through, got %q", a.NamespaceOrDefault())
	}
	r := &Record{}
	if r.NamespaceOrDefault() != DefaultNamespace {
		t.Errorf("legacy record must read as default")
	}
	r.Namespace = "beta"
	if r.NamespaceOrDefault() != "beta" {
		t.Errorf("explicit record ns must pass through")
	}
}

func TestCreateAgentNamespace(t *testing.T) {
	s := NewMemoryStore(t.TempDir())

	// default stamping
	a, _, err := s.CreateAgent(CreateAgentRequest{Name: "legacy-shape"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if a.Namespace != DefaultNamespace {
		t.Errorf("no-ns create must stamp default, got %q", a.Namespace)
	}

	// explicit stamping
	a, _, err = s.CreateAgent(CreateAgentRequest{Name: "acme", Namespace: "acme"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if a.Namespace != "acme" {
		t.Errorf("explicit ns must be honored, got %q", a.Namespace)
	}

	// invalid ns refused (caller bug, never silently normalized)
	if _, _, err := s.CreateAgent(CreateAgentRequest{Name: "bad", Namespace: "Not-A-Ns"}); err == nil {
		t.Error("invalid namespace must be refused")
	}
}

func TestCreateSandFSInheritsAgentNamespace(t *testing.T) {
	s := NewMemoryStore(t.TempDir())
	acme, _, err := s.CreateAgent(CreateAgentRequest{Name: "a", Namespace: "acme"})
	if err != nil {
		t.Fatalf("agent: %v", err)
	}
	rec, err := s.CreateSandFS(acme.ID, CreateSandFSRequest{Name: "sf"})
	if err != nil {
		t.Fatalf("sandfs: %v", err)
	}
	if rec.Namespace != "acme" {
		t.Errorf("sandfs must freeze the agent's ns, got %q", rec.Namespace)
	}
	// persisted view agrees
	got, err := s.GetSandFS(rec.ID)
	if err != nil || got == nil {
		t.Fatalf("get: %v", err)
	}
	if got.Namespace != "acme" {
		t.Errorf("stored record ns: %q", got.Namespace)
	}
}

func TestListInNamespacePartition(t *testing.T) {
	s := NewMemoryStore(t.TempDir())
	acmeA, _, _ := s.CreateAgent(CreateAgentRequest{Name: "a1", Namespace: "acme"})
	betaA, _, _ := s.CreateAgent(CreateAgentRequest{Name: "a2", Namespace: "beta"})
	defA, _, _ := s.CreateAgent(CreateAgentRequest{Name: "a3"}) // default
	acmeSF, _ := s.CreateSandFS(acmeA.ID, CreateSandFSRequest{Name: "sf1"})
	betaSF, _ := s.CreateSandFS(betaA.ID, CreateSandFSRequest{Name: "sf2"})
	defSF, _ := s.CreateSandFS(defA.ID, CreateSandFSRequest{Name: "sf3"})

	agents := s.ListAgentsInNamespace("acme")
	if len(agents) != 1 || agents[0].ID != acmeA.ID {
		t.Errorf("acme agent partition wrong: %+v", agents)
	}
	sandfs := s.ListSandFSInNamespace("acme")
	if len(sandfs) != 1 || sandfs[0].ID != acmeSF.ID {
		t.Errorf("acme sandfs partition wrong: %+v", sandfs)
	}
	for _, pair := range []struct {
		ns   string
		sfID string
	}{{"beta", betaSF.ID}, {"default", defSF.ID}} {
		got := s.ListSandFSInNamespace(pair.ns)
		if len(got) != 1 || got[0].ID != pair.sfID {
			t.Errorf("%s partition wrong: %+v", pair.ns, got)
		}
	}
	// clones, not cache aliases: mutating the returned record must not leak
	if len(sandfs) == 1 {
		sandfs[0].Name = "mutated"
		fresh, _ := s.GetSandFS(acmeSF.ID)
		if fresh.Name == "mutated" {
			t.Error("ListSandFSInNamespace must return private copies")
		}
	}
}

// ── etcd WIRE pins ─────────────────────────────────────────────

// TestAgentWireCarriesNamespace pins the agent record's etcd wire shape: the
// field must marshal, carry the literal key "namespace", and round-trip.
func TestAgentWireCarriesNamespace(t *testing.T) {
	a := &Agent{
		ID: "agent-x", Name: "n", APIKeyHash: "h",
		CreatedAt: time.Now(), Namespace: "acme",
	}
	data, err := marshalAgentForEtcd(a)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var probe map[string]any
	if err := json.Unmarshal(data, &probe); err != nil {
		t.Fatalf("probe: %v", err)
	}
	if probe["namespace"] != "acme" {
		t.Errorf("wire must carry namespace:\"acme\", got %s", data)
	}
	decoded := decodeAgent(data)
	if decoded == nil || decoded.Namespace != "acme" {
		t.Errorf("round-trip lost namespace: %+v", decoded)
	}

	// legacy rows (no namespace key) decode with empty — normalized on read
	legacy := []byte(`{"agent_id":"a","name":"n","api_key_hash":"h","created_at":"2026-01-01T00:00:00Z"}`)
	if d := decodeAgent(legacy); d == nil || d.Namespace != "" {
		t.Errorf("legacy agent must decode with empty namespace")
	}
}

// TestSandfsHotWireCarriesNamespace pins the HOT record wire (the hot-wire
// whitelist lesson): namespace rides sandfs/<id> values, and meta does NOT need it.
func TestSandfsHotWireCarriesNamespace(t *testing.T) {
	rec := &Record{ID: "sandfs-x", AgentID: "agent-x", Namespace: "beta", Status: SandfsStatusDetaching}
	data, err := encodeSandfsRecord(rec)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	var probe map[string]any
	if err := json.Unmarshal(data, &probe); err != nil {
		t.Fatalf("probe: %v", err)
	}
	if probe["namespace"] != "beta" {
		t.Errorf("hot wire must carry namespace, got %s", data)
	}
	if probe["status"] != SandfsStatusDetaching {
		t.Errorf("status pin (regression of the original whitelist): %s", data)
	}
	decoded := decodeSandfsRecord(data)
	if decoded == nil || decoded.Namespace != "beta" || decoded.Status != SandfsStatusDetaching {
		t.Errorf("round-trip lost fields: %+v", decoded)
	}

	// legacy hot rows decode with empty namespace (normalized on read)
	legacy := []byte(`{"sandfs_id":"s","agent_id":"a"}`)
	if d := decodeSandfsRecord(legacy); d == nil || d.Namespace != "" {
		t.Errorf("legacy hot record must decode with empty namespace")
	}
}

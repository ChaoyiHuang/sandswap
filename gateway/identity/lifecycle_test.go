// Copyright 2026 Chaoyi Huang. All rights reserved.
//
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE file at the root of this repository.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, sandswap's use of this software will be governed
// by the Apache License, Version 2.0.

package identity

import (
	"testing"
)

// newLifecycleStore builds a MemoryStore with one agent, one overlay sandfs
// (template "app:v1") and one flat sandfs (same ref, flat mode — must NOT
// count as an overlay dependency).
func newLifecycleStore(t *testing.T) *MemoryStore {
	t.Helper()
	s := NewMemoryStore(t.TempDir())
	if _, _, err := s.CreateAgent(CreateAgentRequest{Name: "a"}); err != nil {
		t.Fatal(err)
	}
	agents, _ := s.ListAgents()
	agentID := agents[0].ID
	if _, err := s.CreateSandFS(agentID, CreateSandFSRequest{Name: "ov", Template: "app:v1", Mode: "overlay"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateSandFS(agentID, CreateSandFSRequest{Name: "fl", Template: "app:v1", Mode: "flat"}); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSetSandfsStatusValidatesValues(t *testing.T) {
	s := newLifecycleStore(t)
	recs, _ := s.ListAllSandFS()
	id := recs[0].ID

	for _, st := range []string{"", SandfsStatusDetaching, SandfsStatusDetached, SandfsStatusDeleting} {
		if err := s.SetSandfsStatus(id, st); err != nil {
			t.Fatalf("SetSandfsStatus(%q): %v", st, err)
		}
		rec, _ := s.GetSandFS(id)
		if rec.Status != st {
			t.Fatalf("status = %q, want %q", rec.Status, st)
		}
	}
	// A typo must be refused at the seam — never silently gate every exec.
	if err := s.SetSandfsStatus(id, "detaching "); err == nil {
		t.Fatal("invalid status accepted")
	}
	// Unknown sandfs: error, not silent success.
	if err := s.SetSandfsStatus("nope", SandfsStatusDetaching); err == nil {
		t.Fatal("unknown sandfs accepted")
	}
}

func TestUpdateSandfsTemplateSingleWrite(t *testing.T) {
	s := newLifecycleStore(t)
	recs, _ := s.ListAllSandFS()
	var id string
	for _, r := range recs {
		if r.Mode == "overlay" {
			id = r.ID
		}
	}
	// An attach only completes from detached — an active record refuses the
	// completion instead of silently overwriting a concurrent transition.
	if err := s.UpdateSandfsTemplate(id, "app:v2", 4, 8192); err != ErrSandfsNotDetached {
		t.Fatalf("active record: err = %v, want ErrSandfsNotDetached", err)
	}
	if err := s.SetSandfsStatus(id, SandfsStatusDetached); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateSandfsTemplate(id, "app:v2", 4, 8192); err != nil {
		t.Fatal(err)
	}
	rec, _ := s.GetSandFS(id)
	if rec.Template != "app:v2" || rec.MinVCPUs != 4 || rec.MinMemoryMB != 8192 || rec.Status != "" {
		t.Fatalf("record after UpdateSandfsTemplate: %+v", rec)
	}
}

// TestCompareAndSetSandfsStatus pins the conditional transition seam used by
// the lifecycle orchestration: the write lands only while the record still
// carries the observed status, and a losing CAS reports the status that is
// there instead (so the caller can decide without a second read).
func TestCompareAndSetSandfsStatus(t *testing.T) {
	s := newLifecycleStore(t)
	recs, _ := s.ListAllSandFS()
	id := recs[0].ID

	applied, current, err := s.CompareAndSetSandfsStatus(id, "", SandfsStatusDetaching)
	if err != nil || !applied || current != SandfsStatusDetaching {
		t.Fatalf("active→detaching: applied=%v current=%q err=%v", applied, current, err)
	}
	// A delete overrides the in-flight detach (delete wins in the lifecycle).
	applied, current, err = s.CompareAndSetSandfsStatus(id, SandfsStatusDetaching, SandfsStatusDeleting)
	if err != nil || !applied || current != SandfsStatusDeleting {
		t.Fatalf("detaching→deleting: applied=%v current=%q err=%v", applied, current, err)
	}
	// A detach may NOT overwrite a deletion.
	applied, current, err = s.CompareAndSetSandfsStatus(id, SandfsStatusDetaching, SandfsStatusDeleting)
	if err != nil || applied || current != SandfsStatusDeleting {
		t.Fatalf("lost CAS: applied=%v current=%q err=%v", applied, current, err)
	}
	if _, _, err := s.CompareAndSetSandfsStatus(id, "bogus", SandfsStatusDetached); err == nil {
		t.Fatal("invalid from-status accepted")
	}
}

// TestGetSandFSReturnsSnapshot pins the read contract: a record handed to a
// caller is a snapshot, so a later write is never observed through the old
// pointer.
func TestGetSandFSReturnsSnapshot(t *testing.T) {
	s := newLifecycleStore(t)
	recs, _ := s.ListAllSandFS()
	id := recs[0].ID
	snap, err := s.GetSandFS(id)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetSandfsStatus(id, SandfsStatusDeleting); err != nil {
		t.Fatal(err)
	}
	if snap.Status == SandfsStatusDeleting {
		t.Fatal("a previously returned record observed a later write (store-owned object leaked)")
	}
	fresh, _ := s.GetSandFS(id)
	if fresh.Status != SandfsStatusDeleting {
		t.Fatalf("fresh read status = %q, want deleting", fresh.Status)
	}
}

// TestDeleteAgentTombstonesSandfsIDs pins the batch-delete tombstone: ids
// removed with their agent are remembered exactly like single deletes.
func TestDeleteAgentTombstonesSandfsIDs(t *testing.T) {
	s := newLifecycleStore(t)
	agents, _ := s.ListAgents()
	agentID := agents[0].ID
	recs, _ := s.ListSandFSByAgent(agentID)
	if len(recs) == 0 {
		t.Fatal("setup: no sandfs")
	}
	if err := s.DeleteAgent(agentID); err != nil {
		t.Fatal(err)
	}
	for _, rec := range recs {
		s.mu.RLock()
		_, ok := s.tombstones[rec.ID]
		s.mu.RUnlock()
		if !ok {
			t.Fatalf("sandfs %s deleted with its agent but not tombstoned", rec.ID)
		}
	}
}

func TestCountSandFSByTemplateOverlayOnly(t *testing.T) {
	s := newLifecycleStore(t)
	count, sample := s.CountSandFSByTemplate("app:v1")
	if count != 1 {
		t.Fatalf("count = %d, want 1 (flat sandfs must not count)", count)
	}
	if len(sample) != 1 {
		t.Fatalf("sample = %v", sample)
	}
	// After swapping the overlay sandfs away, the count drops to zero — the
	// template becomes deletable. The attach completes only from `detached`.
	recs, _ := s.ListAllSandFS()
	for _, r := range recs {
		if r.Mode == "overlay" {
			if err := s.SetSandfsStatus(r.ID, SandfsStatusDetached); err != nil {
				t.Fatal(err)
			}
			if err := s.UpdateSandfsTemplate(r.ID, "app:v2", 0, 0); err != nil {
				t.Fatal(err)
			}
		}
	}
	if count, _ := s.CountSandFSByTemplate("app:v1"); count != 0 {
		t.Fatalf("count after swap-away = %d, want 0", count)
	}
}

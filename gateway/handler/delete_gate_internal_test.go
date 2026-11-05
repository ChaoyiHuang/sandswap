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

package handler

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"testing"
	"time"

	"gateway/identity"
	"gateway/registry"
	"gateway/storage/storagetest"
)

func newGateStore(t *testing.T) (*identity.MemoryStore, string) {
	t.Helper()
	store := identity.NewMemoryStore(t.TempDir())
	agent, _, err := store.CreateAgent(identity.CreateAgentRequest{Name: "gate-agent"})
	if err != nil {
		t.Fatalf("create agent: %v", err)
	}
	rec, err := store.CreateSandFS(agent.ID, identity.CreateSandFSRequest{
		Name: "gate-sandfs", Template: "test:v1", Mode: "flat",
	})
	if err != nil {
		t.Fatalf("create sandfs: %v", err)
	}
	return store, rec.ID
}

func gateStatus(t *testing.T, store identity.Store, id string) string {
	t.Helper()
	rec, err := store.GetSandFS(id)
	if err != nil {
		t.Fatalf("get sandfs: %v", err)
	}
	return rec.Status
}

// The pre-drain gate may take an ACTIVE record (the operator's delete wins);
// the post-drain gate must refuse it: active at that point means an attach
// completed after the drain.
func TestEnsureDeletingGateTransitions(t *testing.T) {
	store, id := newGateStore(t)
	h := &HumanHandler{identityStore: store, logger: slog.New(slog.DiscardHandler)}

	if _, err := h.ensureDeletingGate(id, true); !errors.Is(err, errDeleteBecameActive) {
		t.Fatalf("post-drain gate on an active record: want errDeleteBecameActive, got %v", err)
	}
	if got := gateStatus(t, store, id); got != "" {
		t.Fatalf("refused gate changed the status to %q", got)
	}

	if _, err := h.ensureDeletingGate(id, false); err != nil {
		t.Fatalf("pre-drain gate: %v", err)
	}
	if got := gateStatus(t, store, id); got != identity.SandfsStatusDeleting {
		t.Fatalf("pre-drain gate status = %q, want deleting", got)
	}

	// Detached is a valid pre-delete state (a swap settled); the post-drain
	// gate re-arms deleting so the terminal delete's guard accepts it.
	if err := store.SetSandfsStatus(id, identity.SandfsStatusDetached); err != nil {
		t.Fatal(err)
	}
	if _, err := h.ensureDeletingGate(id, true); err != nil {
		t.Fatalf("post-drain gate on detached: %v", err)
	}
	if got := gateStatus(t, store, id); got != identity.SandfsStatusDeleting {
		t.Fatalf("detached -> deleting status = %q", got)
	}

	// A provably missing record is success (the volume cleanup still runs).
	if _, err := h.ensureDeletingGate("sandfs-does-not-exist", false); err != nil {
		t.Fatalf("missing record: %v", err)
	}
}

// failingGetStore simulates an etcd outage: teardown must abort, not read the
// failure as "the record is absent".
type failingGetStore struct{ identity.Store }

func (failingGetStore) GetSandFS(string) (*identity.Record, error) {
	return nil, errors.New("etcd unavailable")
}

func TestTeardownAbortsOnStoreError(t *testing.T) {
	reg := registry.New(t.TempDir())
	reg.SetStorageOps(storagetest.New(reg.VolumeRoot()))
	agent, _, err := reg.Store().CreateAgent(identity.CreateAgentRequest{Name: "del-agent"})
	if err != nil {
		t.Fatal(err)
	}
	rec, _, err := reg.CreateSandFS(t.Context(), agent.ID, identity.CreateSandFSRequest{
		Name: "del-sandfs", Template: "test:v1", Mode: "flat",
	})
	if err != nil {
		t.Fatal(err)
	}

	h := NewHumanHandler(reg, nil, slog.New(slog.DiscardHandler))
	h.identityStore = failingGetStore{Store: reg.Store()}

	if err := h.teardownSandfs(rec.ID, 0); err == nil {
		t.Fatal("teardown succeeded on a store read failure")
	}
	if _, err := os.Stat(rec.RootFSPath); err != nil {
		t.Fatalf("volume was removed on a store read failure: %v", err)
	}
	if _, err := reg.Store().GetSandFS(rec.ID); err != nil {
		t.Fatalf("record was removed on a store read failure: %v", err)
	}
}

type fakeDrainer struct{}

func (fakeDrainer) Drain(string, string, string, time.Duration) bool { return true }

// The full delete path: gate -> drain (settles detached) -> re-gate -> delete.
func TestTeardownGatesThenDeletes(t *testing.T) {
	reg := registry.New(t.TempDir())
	reg.SetStorageOps(storagetest.New(reg.VolumeRoot()))
	agent, _, err := reg.Store().CreateAgent(identity.CreateAgentRequest{Name: "del-agent"})
	if err != nil {
		t.Fatal(err)
	}
	rec, _, err := reg.CreateSandFS(t.Context(), agent.ID, identity.CreateSandFSRequest{
		Name: "del-sandfs", Template: "test:v1", Mode: "flat",
	})
	if err != nil {
		t.Fatal(err)
	}

	h := NewHumanHandler(reg, nil, slog.New(slog.DiscardHandler))
	h.SetDrainer(fakeDrainer{})
	if err := h.teardownSandfs(rec.ID, 0); err != nil {
		t.Fatalf("teardown: %v", err)
	}
	if _, err := os.Stat(rec.RootFSPath); !os.IsNotExist(err) {
		t.Fatalf("volume still exists after delete: %v", err)
	}
	if _, err := reg.Store().GetSandFS(rec.ID); !errors.Is(err, identity.ErrSandFSNotFound) {
		t.Fatalf("record still exists after delete: %v", err)
	}
}

// staleNegativeStore simulates the lazy negative cache lagging a create: the
// cached read says absent, the linearizable read returns the record. The gate
// must consult the fresh read before licensing a terminal delete.
type staleNegativeStore struct {
	identity.Store
	cas   identity.StatusCASStore
	fresh *identity.Record
}

func (s *staleNegativeStore) GetSandFS(string) (*identity.Record, error) {
	return nil, fmt.Errorf("%w: stale negative cache", identity.ErrSandFSNotFound)
}

func (s *staleNegativeStore) GetSandFSFresh(string) (*identity.Record, error) {
	cp := *s.fresh
	return &cp, nil
}

func (s *staleNegativeStore) CompareAndSetSandfsStatus(id, from, to string) (bool, string, error) {
	return s.cas.CompareAndSetSandfsStatus(id, from, to)
}

func TestEnsureDeletingGateConfirmsAbsenceWithFreshRead(t *testing.T) {
	store, id := newGateStore(t)
	rec, err := store.GetSandFS(id)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetSandfsStatus(id, identity.SandfsStatusDetached); err != nil {
		t.Fatal(err)
	}
	rec.Status = identity.SandfsStatusDetached
	h := &HumanHandler{
		identityStore: &staleNegativeStore{Store: store, cas: store, fresh: rec},
		logger:        slog.New(slog.DiscardHandler),
	}
	if _, err := h.ensureDeletingGate(id, true); err != nil {
		t.Fatalf("fresh-read fallback: %v", err)
	}
	if got := gateStatus(t, store, id); got != identity.SandfsStatusDeleting {
		t.Fatalf("gate status = %q, want deleting", got)
	}
}

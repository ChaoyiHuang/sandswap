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

//go:build identity_e2e

// EtcdStore end-to-end tests. These require a running etcd at
// http://127.0.0.1:2379 and are excluded from the default `go test` run.
// Run with: go test -tags identity_e2e ./gateway/identity/
//
// The tests reuse the in-package runStoreConformance suite (from store_test.go)
// to verify EtcdStore satisfies the same Store contract as MemoryStore, then
// add etcd-specific scenarios: watch sync (cross-store propagation), distributed
// lock serialization, and cache/local-view consistency.

package identity

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"testing"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
)

const etcdEndpoint = "http://127.0.0.1:2379"

// newTestEtcdStore creates an EtcdStore with a unique etcd key prefix (so
// parallel test runs don't collide) and registers Close on test cleanup.
func newTestEtcdStore(t *testing.T) *EtcdStore {
	t.Helper()
	prefix := fmt.Sprintf("/sandswap-auth-test-%d/", time.Now().UnixNano())
	store, err := NewEtcdStore([]string{etcdEndpoint}, prefix, "/tmp/nonexistent-volroot", nil, slog.Default())
	if err != nil {
		t.Fatalf("NewEtcdStore: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

// newTestEtcdClient creates a raw etcd client for direct key manipulation
// (simulating external gateway writes). Follows the ownership_e2e_test.go pattern.
func newTestEtcdClient(t *testing.T) *clientv3.Client {
	t.Helper()
	cli, err := clientv3.New(clientv3.Config{
		Endpoints:   []string{etcdEndpoint},
		DialTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("etcd client: %v", err)
	}
	t.Cleanup(func() { cli.Close() })
	return cli
}

// ─── Conformance ────────────────────────────────────────────────

// TestEtcdStoreConformance runs the shared Store interface conformance suite
// against EtcdStore. This verifies the etcd-backed implementation has the
// same contract surface as MemoryStore (the /agent/execute hot path depends on
// identical ResolveAgent/GetSandFS/ListSandFSByAgent semantics).
func TestEtcdStoreConformance(t *testing.T) {
	runStoreConformance(t, func(t *testing.T) Store {
		t.Helper()
		return newTestEtcdStore(t)
	})
}

// TestEtcdStoreSatisfiesInterface is a compile-time check that EtcdStore
// implements the Store interface.
func TestEtcdStoreSatisfiesInterface(t *testing.T) {
	var _ Store = (*EtcdStore)(nil)
}

// ─── Agent create + resolve (hot path) ──────────────────────────

// TestEtcdResolveAgent verifies the /agent/execute hot path: a valid API key
// resolves to the owning agent via the local cache (no etcd round-trip).
func TestEtcdResolveAgent(t *testing.T) {
	s := newTestEtcdStore(t)

	agent, key, err := s.CreateAgent(CreateAgentRequest{Name: "etcd-agent"})
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}

	resolved, err := s.ResolveAgent(key)
	if err != nil {
		t.Fatalf("ResolveAgent: %v", err)
	}
	if resolved.ID != agent.ID {
		t.Errorf("resolved.ID = %q, want %q", resolved.ID, agent.ID)
	}
}

// TestEtcdResolveAgentAfterDelete verifies a deleted agent's key no longer
// resolves (the api-key index is cleaned up in both etcd and cache).
func TestEtcdResolveAgentAfterDelete(t *testing.T) {
	s := newTestEtcdStore(t)
	agent, key, _ := s.CreateAgent(CreateAgentRequest{Name: "doomed"})

	if err := s.DeleteAgent(agent.ID); err != nil {
		t.Fatalf("DeleteAgent: %v", err)
	}
	if _, err := s.ResolveAgent(key); err == nil {
		t.Fatal("ResolveAgent after delete: expected error, got nil")
	}
}

// ─── Watch sync (cross-store propagation) ──────────────────────

// TestEtcdWatchSyncSandFSCreate verifies the watch loop propagates a sandfs
// created on store1 to store2's local cache. This is the multi-node consistency
// guarantee: a sandfs created on gateway A is visible to gateway B within the
// watch propagation delay (~2-10ms).
func TestEtcdWatchSyncSandFSCreate(t *testing.T) {
	store1 := newTestEtcdStore(t)
	// store2 shares the same prefix -> receives watch events for store1's writes.
	prefix := store1.prefix
	store2, err := NewEtcdStore([]string{etcdEndpoint}, prefix, "/tmp/nonexistent-volroot", nil, slog.Default())
	if err != nil {
		t.Fatalf("store2: %v", err)
	}
	defer store2.Close()

	agent, _, err := store1.CreateAgent(CreateAgentRequest{Name: "watch-agent"})
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}
	rec, err := store1.CreateSandFS(agent.ID, CreateSandFSRequest{Name: "watch-sandfs"})
	if err != nil {
		t.Fatalf("CreateSandFS: %v", err)
	}

	// Wait for watch to propagate to store2.
	time.Sleep(2 * time.Second)

	// store2 sees the agent.
	resolved, err := store2.ResolveAgent(agent.APIKey)
	if err != nil {
		t.Fatalf("store2 ResolveAgent: %v", err)
	}
	if resolved.ID != agent.ID {
		t.Errorf("store2 resolved.ID = %q, want %q", resolved.ID, agent.ID)
	}

	// store2 sees the sandfs via the reverse index.
	recs, err := store2.ListSandFSByAgent(agent.ID)
	if err != nil {
		t.Fatalf("store2 ListSandFSByAgent: %v", err)
	}
	if len(recs) != 1 || recs[0].ID != rec.ID {
		t.Fatalf("store2 expected 1 sandfs %s, got %+v", rec.ID, recs)
	}

	// store2 sees it via GetSandFS too.
	got, err := store2.GetSandFS(rec.ID)
	if err != nil {
		t.Fatalf("store2 GetSandFS: %v", err)
	}
	if got.ID != rec.ID {
		t.Errorf("store2 GetSandFS.ID = %q, want %q", got.ID, rec.ID)
	}
}

// TestEtcdWatchSyncSandFSDelete verifies the watch loop propagates a sandfs
// deletion from store1 to store2 (cache invalidation).
func TestEtcdWatchSyncSandFSDelete(t *testing.T) {
	store1 := newTestEtcdStore(t)
	store2, err := NewEtcdStore([]string{etcdEndpoint}, store1.prefix, "/tmp/nonexistent-volroot", nil, slog.Default())
	if err != nil {
		t.Fatalf("store2: %v", err)
	}
	defer store2.Close()

	agent, _, _ := store1.CreateAgent(CreateAgentRequest{Name: "del-agent"})
	rec, _ := store1.CreateSandFS(agent.ID, CreateSandFSRequest{Name: "del-sandfs"})

	time.Sleep(2 * time.Second)

	if err := store1.DeleteSandFS(rec.ID); err != nil {
		t.Fatalf("DeleteSandFS: %v", err)
	}

	time.Sleep(2 * time.Second)

	// store2 no longer sees the sandfs.
	if _, err := store2.GetSandFS(rec.ID); err == nil {
		t.Error("store2 GetSandFS after delete: expected error, got nil")
	}
	recs, _ := store2.ListSandFSByAgent(agent.ID)
	if len(recs) != 0 {
		t.Errorf("store2 ListSandFSByAgent after delete: expected 0, got %d", len(recs))
	}
}

// TestEtcdWatchSyncAgentDelete verifies deleting an agent on store1 propagates
// to store2: the agent and its sandfs disappear from store2's cache.
func TestEtcdWatchSyncAgentDelete(t *testing.T) {
	store1 := newTestEtcdStore(t)
	store2, err := NewEtcdStore([]string{etcdEndpoint}, store1.prefix, "/tmp/nonexistent-volroot", nil, slog.Default())
	if err != nil {
		t.Fatalf("store2: %v", err)
	}
	defer store2.Close()

	agent, key, _ := store1.CreateAgent(CreateAgentRequest{Name: "del-agent"})
	rec, _ := store1.CreateSandFS(agent.ID, CreateSandFSRequest{Name: "del-vol"})

	time.Sleep(2 * time.Second)

	if err := store1.DeleteAgent(agent.ID); err != nil {
		t.Fatalf("DeleteAgent: %v", err)
	}

	time.Sleep(2 * time.Second)

	// store2: agent's key no longer resolves.
	if _, err := store2.ResolveAgent(key); err == nil {
		t.Error("store2 ResolveAgent after delete: expected error")
	}
	// store2: sandfs cascade-deleted.
	if _, err := store2.GetSandFS(rec.ID); err == nil {
		t.Error("store2 GetSandFS after agent delete: expected error")
	}
}

// ─── Field setters persist to etcd ──────────────────────────────

// TestEtcdSettersPersistAcrossStores verifies the field setters (SetRootFSPath,
// SetMinResources) write through to etcd, so a second store observes the updated
// values via watch. This is the Registry post-create path: the registry calls
// SetRootFSPath after volume creation, and other gateways must see the path to
// bind-mount.
func TestEtcdSettersPersistAcrossStores(t *testing.T) {
	store1 := newTestEtcdStore(t)
	store2, err := NewEtcdStore([]string{etcdEndpoint}, store1.prefix, "/tmp/nonexistent-volroot", nil, slog.Default())
	if err != nil {
		t.Fatalf("store2: %v", err)
	}
	defer store2.Close()

	agent, _, _ := store1.CreateAgent(CreateAgentRequest{Name: "owner"})
	rec, _ := store1.CreateSandFS(agent.ID, CreateSandFSRequest{Name: "vol"})

	if err := store1.SetRootFSPath(rec.ID, "/data/rootfs"); err != nil {
		t.Fatalf("SetRootFSPath: %v", err)
	}
	if err := store1.SetMinResources(rec.ID, 4, 2048); err != nil {
		t.Fatalf("SetMinResources: %v", err)
	}

	time.Sleep(2 * time.Second)

	// store2 sees the updated fields.
	got, err := store2.GetSandFS(rec.ID)
	if err != nil {
		t.Fatalf("store2 GetSandFS: %v", err)
	}
	if got.RootFSPath != "/data/rootfs" {
		t.Errorf("store2 RootFSPath = %q, want %q", got.RootFSPath, "/data/rootfs")
	}
	if got.MinVCPUs != 4 || got.MinMemoryMB != 2048 {
		t.Errorf("store2 MinVCPUs=%d MinMemoryMB=%d, want 4/2048", got.MinVCPUs, got.MinMemoryMB)
	}
}

// ─── External write (simulating another gateway) ───────────────

// TestEtcdExternalWritePropagates verifies a direct etcd PUT (simulating
// another gateway instance writing without going through this store) propagates
// to the local cache via watch.
func TestEtcdExternalWritePropagates(t *testing.T) {
	store := newTestEtcdStore(t)
	cli := newTestEtcdClient(t)

	// Directly write an agent record to etcd (bypassing the store).
	agent := &Agent{
		ID:        "agent-external1",
		Name:      "external",
		APIKey:    "sk-sandswap-agent-externalkey",
		CreatedAt: time.Now(),
	}
	data, err := marshalAgentForEtcd(agent)
	if err != nil {
		t.Fatalf("marshalAgentForEtcd: %v", err)
	}
	// The agent key is the api-key DIGEST (the hot auth path resolves a
	// presented key in one point Get) — planting it under the agent ID instead
	// still propagates via watch (the value is decoded, not the key), but the
	// entry could never be delete-evicted: applyDeleteLocked treats the key
	// suffix as the digest. Write the conforming key.
	key := store.agentKeyFor(hashAPIKey(agent.APIKey))
	ctx := cli.Ctx()
	if _, err := cli.Put(ctx, key, string(data)); err != nil {
		t.Fatalf("external Put: %v", err)
	}

	time.Sleep(2 * time.Second)

	// The store's cache picks up the external agent via watch.
	resolved, err := store.ResolveAgent("sk-sandswap-agent-externalkey")
	if err != nil {
		t.Fatalf("ResolveAgent after external write: %v", err)
	}
	if resolved.ID != agent.ID {
		t.Errorf("resolved.ID = %q, want %q", resolved.ID, agent.ID)
	}
}

// ─── Close idempotency ─────────────────────────────────────────

// TestEtcdStoreCloseIdempotent verifies Close can be called multiple times
// without panicking (the watchDone channel close is the concern).
func TestEtcdStoreCloseIdempotent(t *testing.T) {
	s := newTestEtcdStore(t)
	s.Close()
	s.Close() // must not panic
}

// ─── Full lifecycle ─────────────────────────────────────────────

// TestEtcdStoreFullLifecycle exercises the complete agent+sandfs lifecycle on
// etcd: create -> resolve -> set fields -> list -> delete. Mirrors the
// MemoryStore full lifecycle test to ensure behavioral parity.
func TestEtcdStoreFullLifecycle(t *testing.T) {
	s := newTestEtcdStore(t)

	agent, key, err := s.CreateAgent(CreateAgentRequest{Name: "lifecycle"})
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}

	resolved, err := s.ResolveAgent(key)
	if err != nil {
		t.Fatalf("ResolveAgent: %v", err)
	}
	if resolved.ID != agent.ID {
		t.Fatalf("resolved.ID = %q, want %q", resolved.ID, agent.ID)
	}

	rec, err := s.CreateSandFS(agent.ID, CreateSandFSRequest{
		Name:     "vol",
		Template: "ubuntu:v1",
		Mode:     "overlay",
	})
	if err != nil {
		t.Fatalf("CreateSandFS: %v", err)
	}

	s.SetRootFSPath(rec.ID, "/data/rootfs")
	s.SetMinResources(rec.ID, 2, 512)

	got, _ := s.GetSandFS(rec.ID)
	if got.RootFSPath != "/data/rootfs" || got.MinVCPUs != 2 || got.MinMemoryMB != 512 {
		t.Errorf("record fields not persisted: %+v", got)
	}
	if !got.UsesOverlayFS() {
		t.Error("UsesOverlayFS = false, want true for overlay mode")
	}

	recs, _ := s.ListSandFSByAgent(agent.ID)
	if len(recs) != 1 {
		t.Fatalf("ListSandFSByAgent: expected 1, got %d", len(recs))
	}

	if err := s.DeleteSandFS(rec.ID); err != nil {
		t.Fatalf("DeleteSandFS: %v", err)
	}
	if _, err := s.GetSandFS(rec.ID); err == nil {
		t.Fatal("GetSandFS after delete: expected error")
	}

	if err := s.DeleteAgent(agent.ID); err != nil {
		t.Fatalf("DeleteAgent: %v", err)
	}
	if _, err := s.ResolveAgent(key); err == nil {
		t.Fatal("ResolveAgent after delete: expected error")
	}
}

// ─── Agent ID uniqueness (32-bit IDs need atomic claiming) ──────

// TestEtcdAgentIDClaimLifecycle verifies the agentid/<id> ownership index that
// makes ID collisions claimable: an 8-hex ID suffix is only 32 random bits (the egress IID field width), so
// CreateAgent must atomically CLAIM the ID (create-only Txn on the index) and
// DeleteAgent must release it. The index rides alongside the agent record and
// is invisible to the auth caches (decodeAgent of a hash string fails).
func TestEtcdAgentIDClaimLifecycle(t *testing.T) {
	s := newTestEtcdStore(t)
	cli := newTestEtcdClient(t)

	agent, _, err := s.CreateAgent(CreateAgentRequest{Name: "claim-lifecycle"})
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}

	// Claim present while the agent lives, value = the agent's key hash.
	resp, err := cli.Get(context.Background(), s.agentIDKeyFor(agent.ID))
	if err != nil {
		t.Fatalf("get claim key: %v", err)
	}
	if len(resp.Kvs) != 1 || string(resp.Kvs[0].Value) != agent.APIKeyHash {
		t.Fatalf("claim key = %v, want exactly one entry holding the key hash", resp.Kvs)
	}
	if got, err := s.ResolveAgent(agent.APIKey); err != nil || got == nil || got.ID != agent.ID {
		t.Fatalf("agent record unreadable after claim: %v, %v", got, err)
	}

	if err := s.DeleteAgent(agent.ID); err != nil {
		t.Fatalf("DeleteAgent: %v", err)
	}
	resp, err = cli.Get(context.Background(), s.agentIDKeyFor(agent.ID))
	if err != nil {
		t.Fatalf("get claim key after delete: %v", err)
	}
	if len(resp.Kvs) != 0 {
		t.Fatalf("claim key survived DeleteAgent (%d entries) — the ID could never be reused", len(resp.Kvs))
	}
}

// TestEtcdConcurrentCreatesUniqueIDs drives concurrent agent + sandfs creates
// through the claim path: the create-only Txn (plus the per-ID lock) must make
// every returned ID distinct even when several gateways race.
func TestEtcdConcurrentCreatesUniqueIDs(t *testing.T) {
	s := newTestEtcdStore(t)

	const n = 24
	agentIDs := make(chan string, n)
	errs := make(chan error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a, _, err := s.CreateAgent(CreateAgentRequest{Name: "race"})
			if err != nil {
				errs <- err
				return
			}
			agentIDs <- a.ID
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent CreateAgent: %v", err)
	}
	seen := make(map[string]bool, n)
	for i := 0; i < n; i++ {
		id := <-agentIDs
		if seen[id] {
			t.Fatalf("duplicate agent id %q from concurrent creates", id)
		}
		seen[id] = true
	}

	// SandFS: the record key IS the ID, so uniqueness rides the same claim.
	recIDs := make(chan string, n)
	errs2 := make(chan error, n)
	agent, key, err := s.CreateAgent(CreateAgentRequest{Name: "race-sfs"})
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}
	_ = key
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := s.CreateSandFS(agent.ID, CreateSandFSRequest{Name: "race", Mode: "flat"})
			if err != nil {
				errs2 <- err
				return
			}
			recIDs <- r.ID
		}()
	}
	wg.Wait()
	close(errs2)
	for err := range errs2 {
		t.Fatalf("concurrent CreateSandFS: %v", err)
	}
	for i := 0; i < n; i++ {
		id := <-recIDs
		if seen[id] {
			t.Fatalf("duplicate sandfs id %q (or agent id reuse) from concurrent creates", id)
		}
		seen[id] = true
	}
}

// TestEtcdRecordWatcherFiresOnStatusChange pins the split-mode lifecycle
// trigger: store2 (the "human gateway") flips a record's status; store1 (the
// "exec gateway", built with WithRecordWatcher) must observe the change via
// its watch and fire the callback with (sandfsID, newStatus). This is the
// exact path the exec gateway's drain reacts to — a silent watcher here is a
// silent never-draining swap on split deployments.
func TestEtcdRecordWatcherFiresOnStatusChange(t *testing.T) {
	type fired struct{ id, status string }
	events := make(chan fired, 8)
	// store1 is the exec side: it installs the watcher.
	prefix := fmt.Sprintf("/sandswap-auth-test-%d/", time.Now().UnixNano())
	store1, err := NewEtcdStore([]string{etcdEndpoint}, prefix, "/tmp/nonexistent-volroot", nil, slog.Default(),
		WithRecordWatcher(func(sandfsID, status string) {
			events <- fired{sandfsID, status}
		}))
	if err != nil {
		t.Fatalf("store1: %v", err)
	}
	defer store1.Close()
	// store2 is the human side: same prefix, no watcher.
	store2, err := NewEtcdStore([]string{etcdEndpoint}, prefix, "/tmp/nonexistent-volroot", nil, slog.Default())
	if err != nil {
		t.Fatalf("store2: %v", err)
	}
	defer store2.Close()

	agent, _, err := store2.CreateAgent(CreateAgentRequest{Name: "watcher-agent"})
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}
	rec, err := store2.CreateSandFS(agent.ID, CreateSandFSRequest{Name: "watcher-sandfs", Template: "app:v1", Mode: "overlay"})
	if err != nil {
		t.Fatalf("CreateSandFS: %v", err)
	}
	time.Sleep(2 * time.Second) // watch established on store1

	if err := store2.SetSandfsStatus(rec.ID, SandfsStatusDetaching); err != nil {
		t.Fatalf("SetSandfsStatus: %v", err)
	}
	// Consume intermediate events: the create itself, the agent put, and any
	// earlier writes all fire the watcher with status "" — drain until the
	// event under test arrives (or time out).
	deadline := time.After(5 * time.Second)
	for {
		select {
		case ev := <-events:
			if ev.id == rec.ID && ev.status == SandfsStatusDetaching {
				goto settled_check
			}
			continue
		case <-deadline:
			t.Fatal("record watcher never fired for the detaching status (split-mode drain would never trigger)")
		}
	}
settled_check:

	// The settle write fires too (the drain's own "detached" write echoes back
	// through the watch — idempotent by design, but the callback must carry it).
	if err := store2.SetSandfsStatus(rec.ID, SandfsStatusDetached); err != nil {
		t.Fatalf("SetSandfsStatus(detached): %v", err)
	}
	select {
	case ev := <-events:
		if ev.status != SandfsStatusDetached {
			t.Fatalf("second event status = %q, want %q", ev.status, SandfsStatusDetached)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("watcher never fired for the settle write")
	}
}

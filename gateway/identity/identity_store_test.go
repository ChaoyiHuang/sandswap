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
	"bytes"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// ─── helpers ────────────────────────────────────────────────────

// mustNewPersistentStore creates a persisting store rooted at volRoot with the
// snapshot at path, failing the test on any startup error (corrupt snapshot,
// version mismatch, lock held). Tests that simulate a restart create a second
// store on the same path after Close-ing the first.
func mustNewPersistentStore(t *testing.T, volRoot, path string, logger *slog.Logger) *MemoryStore {
	t.Helper()
	s, err := NewPersistentMemoryStore(volRoot, path, logger)
	if err != nil {
		t.Fatalf("NewPersistentMemoryStore(%s): %v", path, err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// captureLogger returns a logger that records every record into buf so tests
// can assert on warnings (orphan scans, dropped records).
func captureLogger(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// writeSeedStore writes snap directly as the snapshot file, simulating what
// a previous gateway process left on disk.
func writeSeedStore(t *testing.T, path string, snap *storeSnapshot) {
	t.Helper()
	data, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("marshal seed snapshot: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write seed snapshot: %v", err)
	}
}

// seedTime returns a non-zero fixed timestamp for seed records.
func seedTime() time.Time { return time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC) }

// ─── roundtrip (the "restart" case) ─────────────────────────────

// TestIdentityStoreColdStartMissingDir is the first-boot-on-a-fresh-vol-root
// case: cleanup wiped <vol-root> entirely, so the snapshot's parent directory
// does not exist. The store must bootstrap the dir and start empty — not die
// on the lock-file open (the save path creates the dir too; startup must not
// be stricter than the first persist).
func TestIdentityStoreColdStartMissingDir(t *testing.T) {
	volRoot := t.TempDir()
	path := filepath.Join(volRoot, "volumes", "identity-store.json") // "volumes" absent
	s := mustNewPersistentStore(t, volRoot, path, nil)

	if st, err := os.Stat(volRoot); err != nil || !st.IsDir() {
		t.Fatalf("snapshot dir not created: %v", err)
	}
	// And the store is usable: a mutation must persist through the fresh dir.
	agent, key := mustCreateAgent(t, s, "first-boot")
	s.Close()

	s2 := mustNewPersistentStore(t, volRoot, path, nil)
	if _, err := s2.ResolveAgent(key); err != nil {
		t.Fatalf("api key lost across restart after cold start: %v", err)
	}
	_ = agent
}

// TestIdentityStoreRoundTripPreservesAuth is the core restart scenario: create an
// agent + sandfs, "restart" (second store on the same path), and verify the
// old api key still resolves and every record field survived.
func TestIdentityStoreRoundTripPreservesAuth(t *testing.T) {
	volRoot := t.TempDir()
	path := filepath.Join(volRoot, "state.json")
	s1 := mustNewPersistentStore(t, volRoot, path, nil)

	agent, key := mustCreateAgent(t, s1, "survivor")
	rec := mustCreateSandFS(t, s1, agent.ID, CreateSandFSRequest{
		Name:        "fs",
		Description: "restart test",
		Template:    "tpl:v1",
		Mode:        "flat",
		VCPUs:       2,
		MemoryMB:    512,
	})
	volPath := filepath.Join(volRoot, rec.ID)
	if err := os.MkdirAll(volPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := s1.SetRootFSPath(rec.ID, volPath); err != nil {
		t.Fatal(err)
	}
	if err := s1.SetMinResources(rec.ID, 4, 1024); err != nil {
		t.Fatal(err)
	}

	// "Restart": release the lock, reopen the same snapshot.
	s1.Close()
	s2 := mustNewPersistentStore(t, volRoot, path, nil)

	resolved, err := s2.ResolveAgent(key)
	if err != nil {
		t.Fatalf("old api key no longer resolves after restart: %v", err)
	}
	if resolved.ID != agent.ID || resolved.Name != "survivor" {
		t.Errorf("resolved = {%s %s}, want {%s survivor}", resolved.ID, resolved.Name, agent.ID)
	}
	if resolved.APIKey != "" {
		t.Errorf("resolved.APIKey = %q, want empty", resolved.APIKey)
	}

	got, err := s2.GetSandFS(rec.ID)
	if err != nil {
		t.Fatalf("GetSandFS after restart: %v", err)
	}
	if got.RootFSPath != volPath || got.Template != "tpl:v1" || got.Mode != "flat" ||
		got.Description != "restart test" || got.AgentID != agent.ID {
		t.Errorf("record fields lost in restart: %+v", got)
	}
	if got.MinVCPUs != 4 || got.MinMemoryMB != 1024 {
		t.Errorf("min resources lost in restart: vcpus=%d mem=%d", got.MinVCPUs, got.MinMemoryMB)
	}

	owned, err := s2.ListSandFSByAgent(agent.ID)
	if err != nil || len(owned) != 1 {
		t.Fatalf("ListSandFSByAgent after restart = %v, %v; want 1 record (reverse index rebuilt)", owned, err)
	}
}

// ─── file hygiene ───────────────────────────────────────────────

// TestIdentityStoreFileHasNoPlaintextKey verifies the digest-only contract: the
// snapshot carries the hash but never the plaintext key.
func TestIdentityStoreFileHasNoPlaintextKey(t *testing.T) {
	volRoot := t.TempDir()
	path := filepath.Join(volRoot, "state.json")
	s := mustNewPersistentStore(t, volRoot, path, nil)

	_, key := mustCreateAgent(t, s, "digest-only")

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), hashAPIKey(key)) {
		t.Error("snapshot does not contain the api key hash")
	}
	if strings.Contains(string(data), key) || strings.Contains(string(data), "sk-sandswap-agent-") {
		t.Error("snapshot contains plaintext api key material")
	}
}

// TestIdentityStoreFilePerm0600 verifies the snapshot is owner-only and no tmp
// file survives a successful write.
func TestIdentityStoreFilePerm0600(t *testing.T) {
	volRoot := t.TempDir()
	path := filepath.Join(volRoot, "state.json")
	s := mustNewPersistentStore(t, volRoot, path, nil)

	mustCreateAgent(t, s, "perm-check")

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("snapshot perm = %o, want 600", info.Mode().Perm())
	}
	if _, err := os.Stat(path + storeTmpSuffix); !os.IsNotExist(err) {
		t.Errorf("tmp file survived a successful write: %v", err)
	}
}

// TestPersistDisabledByDefault verifies a plain NewMemoryStore (registry.New
// path, all existing tests) never touches the filesystem.
func TestPersistDisabledByDefault(t *testing.T) {
	dir := t.TempDir()
	s := NewMemoryStore(dir)

	agent, _ := mustCreateAgent(t, s, "transient")
	mustCreateSandFS(t, s, agent.ID, CreateSandFSRequest{Name: "fs"})
	if err := s.DeleteAgent(agent.ID); err != nil {
		t.Fatal(err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Errorf("non-persisting store wrote to disk: %v, %v", entries, err)
	}
}

// ─── startup failure modes (fail-fast contract) ─────────────────

// TestIdentityStoreMissingFileStartsEmpty verifies first boot is a normal empty
// start, not an error.
func TestIdentityStoreMissingFileStartsEmpty(t *testing.T) {
	volRoot := t.TempDir()
	s := mustNewPersistentStore(t, volRoot, filepath.Join(volRoot, "state.json"), nil)

	agents, err := s.ListAgents()
	if err != nil || len(agents) != 0 {
		t.Errorf("agents = %v, %v; want empty", agents, err)
	}
	recs, err := s.ListAllSandFS()
	if err != nil || len(recs) != 0 {
		t.Errorf("sandfs = %v, %v; want empty", recs, err)
	}
}

// TestIdentityStoreCorruptFailsFast verifies a corrupt snapshot refuses to start —
// starting empty would silently orphan every volume directory.
func TestIdentityStoreCorruptFailsFast(t *testing.T) {
	volRoot := t.TempDir()
	path := filepath.Join(volRoot, "state.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewPersistentMemoryStore(volRoot, path, nil); err == nil {
		t.Fatal("corrupt snapshot must refuse to start, got nil error")
	}
}

// TestIdentityStoreVersionMismatchFailsFast verifies unknown (or absent) versions
// are a startup error, never a best-effort migration.
func TestIdentityStoreVersionMismatchFailsFast(t *testing.T) {
	volRoot := t.TempDir()
	path := filepath.Join(volRoot, "state.json")

	for name, snap := range map[string]*storeSnapshot{
		"future version": {Version: 99, Agents: []snapshotAgent{{AgentID: "agent-a", APIKeyHash: "h"}}},
		"absent version": {Agents: []snapshotAgent{{AgentID: "agent-a", APIKeyHash: "h"}}},
	} {
		t.Run(name, func(t *testing.T) {
			writeSeedStore(t, path, snap)
			_, err := NewPersistentMemoryStore(volRoot, path, nil)
			if err == nil {
				t.Fatal("version mismatch must refuse to start, got nil error")
			}
			if !strings.Contains(err.Error(), "version") {
				t.Errorf("error %q should mention the version", err)
			}
		})
	}
}

// TestStateLockExclusive verifies a second gateway on the same snapshot path
// refuses to start while the first holds the lock, and can start after the
// first releases it (restart handover).
func TestStateLockExclusive(t *testing.T) {
	volRoot := t.TempDir()
	path := filepath.Join(volRoot, "state.json")
	s1 := mustNewPersistentStore(t, volRoot, path, nil)

	if _, err := NewPersistentMemoryStore(volRoot, path, nil); err == nil {
		t.Fatal("second store on the same snapshot path must fail while the lock is held")
	}

	// Restart handover: first gateway exits (Close), second starts.
	if err := s1.Close(); err != nil {
		t.Fatal(err)
	}
	s2 := mustNewPersistentStore(t, volRoot, path, nil)
	_ = s2
}

// ─── load-time record validation ────────────────────────────────

// TestIdentityStoreLoadDropsEmptyRootFSPath verifies the Registry.CreateSandFS
// crash window (record persisted before SetRootFSPath) is dropped at load:
// the volume was never usable.
func TestIdentityStoreLoadDropsEmptyRootFSPath(t *testing.T) {
	volRoot := t.TempDir()
	path := filepath.Join(volRoot, "state.json")
	now := seedTime()
	writeSeedStore(t, path, &storeSnapshot{
		Version: IdentityStoreVersion,
		Agents:  []snapshotAgent{{AgentID: "agent-a", Name: "a", APIKeyHash: hashAPIKey("key-a"), CreatedAt: now}},
		SandFS: []snapshotRecord{
			{ID: "sandfs-good", AgentID: "agent-a", RootFSPath: filepath.Join(volRoot, "sandfs-good"), CreatedAt: now},
			{ID: "sandfs-incomplete", AgentID: "agent-a", RootFSPath: "", CreatedAt: now},
		},
	})

	s := mustNewPersistentStore(t, volRoot, path, nil)
	recs, err := s.ListAllSandFS()
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 || recs[0].ID != "sandfs-good" {
		t.Errorf("records = %v; want only sandfs-good (empty-rootfs record dropped)", ids(recs))
	}
}

// TestIdentityStoreRestoresNamespaceAndStatus pins the tenancy/lifecycle
// round-trip: an agent's namespace and a record's namespace + non-active
// status must survive a restart. Dropping them re-homes tenants in `default`
// (a cross-namespace IDOR) and turns an in-flight delete/swap back into an
// ACTIVE volume.
func TestIdentityStoreRestoresNamespaceAndStatus(t *testing.T) {
	volRoot := t.TempDir()
	path := filepath.Join(volRoot, "state.json")
	now := seedTime()
	writeSeedStore(t, path, &storeSnapshot{
		Version: IdentityStoreVersion,
		Agents: []snapshotAgent{{
			AgentID: "agent-acme", Name: "acme", APIKeyHash: hashAPIKey("key-acme"),
			CreatedAt: now, Namespace: "acme",
		}},
		SandFS: []snapshotRecord{{
			ID: "sandfs-acme", AgentID: "agent-acme", RootFSPath: filepath.Join(volRoot, "sandfs-acme"),
			CreatedAt: now, Namespace: "acme", Status: SandfsStatusDetaching,
		}},
	})

	s := mustNewPersistentStore(t, volRoot, path, nil)
	ag, err := s.GetAgent("agent-acme")
	if err != nil || ag.NamespaceOrDefault() != "acme" {
		t.Fatalf("agent namespace after reload = %q (err=%v), want acme", ag.Namespace, err)
	}
	rec, err := s.GetSandFS("sandfs-acme")
	if err != nil {
		t.Fatal(err)
	}
	if rec.NamespaceOrDefault() != "acme" {
		t.Errorf("record namespace after reload = %q, want acme", rec.Namespace)
	}
	if rec.Status != SandfsStatusDetaching {
		t.Errorf("record status after reload = %q, want %q", rec.Status, SandfsStatusDetaching)
	}
}

// TestIdentityStoreLoadDropsInvalidStatus: an unknown lifecycle value cannot
// be honored as a gate. Dropping the record is fail-closed (the orphan scan
// finds the volume); loading it as ACTIVE would be fail-open.
func TestIdentityStoreLoadDropsInvalidStatus(t *testing.T) {
	volRoot := t.TempDir()
	path := filepath.Join(volRoot, "state.json")
	now := seedTime()
	writeSeedStore(t, path, &storeSnapshot{
		Version: IdentityStoreVersion,
		SandFS: []snapshotRecord{
			{ID: "sandfs-bad", RootFSPath: filepath.Join(volRoot, "sandfs-bad"), CreatedAt: now, Status: "half-deleted"},
			{ID: "sandfs-ok", RootFSPath: filepath.Join(volRoot, "sandfs-ok"), CreatedAt: now, Status: SandfsStatusDeleting},
		},
	})
	s := mustNewPersistentStore(t, volRoot, path, nil)
	recs, err := s.ListAllSandFS()
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 || recs[0].ID != "sandfs-ok" {
		t.Errorf("records = %v; want only sandfs-ok (invalid status dropped)", ids(recs))
	}
}

// TestIdentityStoreLoadDropsEscapedRootFSPath verifies a hand-edited snapshot
// cannot point a mount outside the volume root (RootFSPath feeds the
// virtio-fs allowed_dirs filter).
func TestIdentityStoreLoadDropsEscapedRootFSPath(t *testing.T) {
	volRoot := t.TempDir()
	path := filepath.Join(volRoot, "state.json")
	now := seedTime()
	writeSeedStore(t, path, &storeSnapshot{
		Version: IdentityStoreVersion,
		SandFS: []snapshotRecord{
			{ID: "sandfs-abs", RootFSPath: "/etc", CreatedAt: now},
			{ID: "sandfs-rel", RootFSPath: filepath.Join(volRoot, "..", "sibling"), CreatedAt: now},
			{ID: "sandfs-root", RootFSPath: volRoot, CreatedAt: now},
			{ID: "sandfs-inside", RootFSPath: filepath.Join(volRoot, "sandfs-inside"), CreatedAt: now},
		},
	})

	s := mustNewPersistentStore(t, volRoot, path, nil)
	recs, _ := s.ListAllSandFS()
	if len(recs) != 1 || recs[0].ID != "sandfs-inside" {
		t.Errorf("records = %v; want only sandfs-inside (escaping paths dropped)", ids(recs))
	}
}

// TestIdentityStoreLoadKeepsMissingVolumeDir verifies a record whose volume
// directory disappeared (deleted behind our back) still loads — it fails
// loudly at mount time instead of silently losing the identity.
func TestIdentityStoreLoadKeepsMissingVolumeDir(t *testing.T) {
	volRoot := t.TempDir()
	path := filepath.Join(volRoot, "state.json")
	writeSeedStore(t, path, &storeSnapshot{
		Version: IdentityStoreVersion,
		SandFS:  []snapshotRecord{{ID: "sandfs-gone", RootFSPath: filepath.Join(volRoot, "sandfs-gone")}},
	})

	s := mustNewPersistentStore(t, volRoot, path, nil)
	if _, err := s.GetSandFS("sandfs-gone"); err != nil {
		t.Errorf("record with missing volume dir should still load: %v", err)
	}
}

// TestIdentityStoreLoadDropsAgentWithoutHash verifies a digest-less agent entry is
// unusable and skipped, and the empty key still fails resolution.
func TestIdentityStoreLoadDropsAgentWithoutHash(t *testing.T) {
	volRoot := t.TempDir()
	path := filepath.Join(volRoot, "state.json")
	writeSeedStore(t, path, &storeSnapshot{
		Version: IdentityStoreVersion,
		Agents: []snapshotAgent{
			{AgentID: "agent-hashless", APIKeyHash: ""},
			{AgentID: "agent-ok", APIKeyHash: hashAPIKey("key-ok")},
		},
	})

	s := mustNewPersistentStore(t, volRoot, path, nil)
	agents, _ := s.ListAgents()
	if len(agents) != 1 || agents[0].ID != "agent-ok" {
		t.Errorf("agents = %v; want only agent-ok", agentIDs(agents))
	}
	if _, err := s.ResolveAgent(""); err == nil {
		t.Error("ResolveAgent(\"\") must fail")
	}
	if _, err := s.ResolveAgent("key-ok"); err != nil {
		t.Errorf("valid seeded key must resolve: %v", err)
	}
}

// TestIdentityStoreAgentIDDeterministicOnLoad verifies loaded IDs occupy the ID
// space: newPublicID must generate around them (a collision would hand one
// identity two owners).
func TestIdentityStoreAgentIDDeterministicOnLoad(t *testing.T) {
	volRoot := t.TempDir()
	path := filepath.Join(volRoot, "state.json")
	writeSeedStore(t, path, &storeSnapshot{
		Version: IdentityStoreVersion,
		Agents:  []snapshotAgent{{AgentID: "agent-00000000", APIKeyHash: hashAPIKey("seed-key")}},
	})

	s := mustNewPersistentStore(t, volRoot, path, nil)
	for i := 0; i < 50; i++ {
		agent, _, err := s.CreateAgent(CreateAgentRequest{Name: "gen"})
		if err != nil {
			t.Fatal(err)
		}
		if agent.ID == "agent-00000000" {
			t.Fatalf("CreateAgent regenerated the loaded ID on iteration %d", i)
		}
	}
}

// TestIdentityStoreCleansStaleTmpFile verifies a tmp file left by a writer that
// died mid-write is removed after a successful load.
func TestIdentityStoreCleansStaleTmpFile(t *testing.T) {
	volRoot := t.TempDir()
	path := filepath.Join(volRoot, "state.json")
	writeSeedStore(t, path, &storeSnapshot{Version: IdentityStoreVersion})
	if err := os.WriteFile(path+storeTmpSuffix, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}

	mustNewPersistentStore(t, volRoot, path, nil)
	if _, err := os.Stat(path + storeTmpSuffix); !os.IsNotExist(err) {
		t.Errorf("stale tmp file was not cleaned up: %v", err)
	}
}

// ─── persist hooks ──────────────────────────────────────────────

// TestPersistOnEveryMutator walks every mutating Store method and asserts the
// file reflects each one — catching a mutator that forgot its persist hook.
func TestPersistOnEveryMutator(t *testing.T) {
	volRoot := t.TempDir()
	path := filepath.Join(volRoot, "state.json")
	s := mustNewPersistentStore(t, volRoot, path, nil)
	read := func() *storeSnapshot {
		t.Helper()
		snap, err := readIdentityStoreFile(path)
		if err != nil {
			t.Fatalf("read snapshot: %v", err)
		}
		return snap
	}

	agent, key := mustCreateAgent(t, s, "hooks")
	if got := read(); len(got.Agents) != 1 || got.Agents[0].APIKeyHash != hashAPIKey(key) {
		t.Errorf("CreateAgent not persisted: %+v", got.Agents)
	}

	rec := mustCreateSandFS(t, s, agent.ID, CreateSandFSRequest{Name: "fs", Template: "tpl:v1", Mode: "overlay"})
	if got := read(); len(got.SandFS) != 1 || got.SandFS[0].RootFSPath != "" {
		t.Errorf("CreateSandFS not persisted (or RootFSPath pre-set): %+v", got.SandFS)
	}

	volPath := filepath.Join(volRoot, rec.ID)
	if err := s.SetRootFSPath(rec.ID, volPath); err != nil {
		t.Fatal(err)
	}
	if got := read(); got.SandFS[0].RootFSPath != volPath {
		t.Errorf("SetRootFSPath not persisted: %+v", got.SandFS[0])
	}

	if err := s.SetMinResources(rec.ID, 2, 256); err != nil {
		t.Fatal(err)
	}
	if got := read(); got.SandFS[0].MinVCPUs != 2 || got.SandFS[0].MinMemoryMB != 256 {
		t.Errorf("SetMinResources not persisted: %+v", got.SandFS[0])
	}

	if err := s.DeleteSandFS(rec.ID); err != nil {
		t.Fatal(err)
	}
	if got := read(); len(got.SandFS) != 0 {
		t.Errorf("DeleteSandFS not persisted: %+v", got.SandFS)
	}

	agent2, _ := mustCreateAgent(t, s, "doomed")
	if err := s.DeleteAgent(agent2.ID); err != nil {
		t.Fatal(err)
	}
	got := read()
	if len(got.Agents) != 1 || got.Agents[0].AgentID != agent.ID {
		t.Errorf("DeleteAgent not persisted: %+v", got.Agents)
	}
}

// TestConcurrentMutationsPersistConsistently verifies the persist-under-lock
// model: concurrent creators must end with every one of them in the file
// (run under -race in CI).
func TestConcurrentMutationsPersistConsistently(t *testing.T) {
	volRoot := t.TempDir()
	path := filepath.Join(volRoot, "state.json")
	s := mustNewPersistentStore(t, volRoot, path, nil)

	const n = 20
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, err := s.CreateAgent(CreateAgentRequest{Name: "concurrent"}); err != nil {
				t.Errorf("CreateAgent: %v", err)
			}
		}()
	}
	wg.Wait()

	snap, err := readIdentityStoreFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Agents) != n {
		t.Errorf("snapshot has %d agents, want %d (a persist raced a mutation)", len(snap.Agents), n)
	}
	seen := map[string]bool{}
	for _, a := range snap.Agents {
		if seen[a.AgentID] {
			t.Errorf("duplicate agent id %s in snapshot", a.AgentID)
		}
		seen[a.AgentID] = true
	}
}

// ─── digest-only stored state ───────────────────────────────────

// TestAgentRecordsCarryDigestOnly verifies listing paths never leak the
// plaintext key: only the CreateAgent return value ever carries it.
func TestAgentRecordsCarryDigestOnly(t *testing.T) {
	s := NewMemoryStore(t.TempDir())
	_, key := mustCreateAgent(t, s, "digest")

	agents, err := s.ListAgents()
	if err != nil || len(agents) != 1 {
		t.Fatalf("ListAgents = %v, %v", agents, err)
	}
	if agents[0].APIKey != "" {
		t.Errorf("listed agent carries plaintext key %q", agents[0].APIKey)
	}
	if agents[0].APIKeyHash != hashAPIKey(key) {
		t.Error("listed agent digest mismatch")
	}
}

// ─── orphan diagnostics ─────────────────────────────────────────

// TestOrphanVolumeDirWarnOnly verifies unclaimed volume directories are
// reported (never imported, never deleted), with non-volume entries filtered
// out by the volume-directory shape check.
func TestOrphanVolumeDirWarnOnly(t *testing.T) {
	volRoot := t.TempDir()
	path := filepath.Join(volRoot, "identity-store.json")
	now := seedTime()

	// Volume directories are seed-derived: sf- + 26 lowercase base32 chars.
	knownDir := "sf-" + strings.Repeat("a", 26)
	orphanDir := "sf-" + strings.Repeat("b", 26)
	for _, d := range []string{orphanDir, knownDir, "templates", "notsandfs-12345678", "sf-shorthex"} {
		if err := os.MkdirAll(filepath.Join(volRoot, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	writeSeedStore(t, path, &storeSnapshot{
		Version: IdentityStoreVersion,
		SandFS:  []snapshotRecord{{ID: "sandfs-abcdef01", RootFSPath: filepath.Join(volRoot, knownDir), CreatedAt: now}},
	})

	var buf bytes.Buffer
	s := mustNewPersistentStore(t, volRoot, path, captureLogger(&buf))
	logs := buf.String()

	if !strings.Contains(logs, orphanDir) {
		t.Error("orphan volume directory was not reported")
	}
	if strings.Count(logs, "orphan volume directory") != 1 {
		t.Errorf("orphan report count = %d, want 1 (shape filter leaked an entry):\n%s", strings.Count(logs, "orphan volume directory"), logs)
	}
	if rec, err := s.GetSandFS("sandfs-abcdef01"); err != nil || rec == nil {
		t.Errorf("recorded sandfs must survive the orphan scan: %v, %v", rec, err)
	}
	if err := s.DeleteSandFS("sandfs-abcdef01"); err != nil {
		t.Error(err)
	}
	entries, _ := os.ReadDir(volRoot)
	found := false
	for _, e := range entries {
		if e.Name() == knownDir {
			found = true
		}
	}
	if !found {
		t.Error("orphan scan must not delete directories")
	}
}

// ids maps records to their IDs for readable assertion output.
func ids(recs []*Record) []string {
	out := make([]string, 0, len(recs))
	for _, r := range recs {
		out = append(out, r.ID)
	}
	return out
}

// agentIDs maps agents to their IDs.
func agentIDs(agents []*Agent) []string {
	out := make([]string, 0, len(agents))
	for _, a := range agents {
		out = append(out, a.ID)
	}
	return out
}

// TestStoreConformanceWithPersistence runs the shared Store contract suite
// against a persisting store: swallowing persist errors and rewriting the
// snapshot must not change any mutator's observable semantics. Each factory
// call gets its own path so subtests (and multiple stores within one subtest)
// never contend on the state lock.
func TestStoreConformanceWithPersistence(t *testing.T) {
	runStoreConformance(t, func(t *testing.T) Store {
		t.Helper()
		dir := t.TempDir() // unique per factory call — no lock contention between subtests
		path := filepath.Join(dir, "state.json")
		s, err := NewPersistentMemoryStore(dir, path, nil)
		if err != nil {
			t.Fatalf("NewPersistentMemoryStore: %v", err)
		}
		t.Cleanup(func() { s.Close() })
		return s
	})
}

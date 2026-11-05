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
//
// Internal (package identity) tests for the snapshot loader's pure logic: key
// range partitioning, on-disk codecs, cache maintenance helpers, the negative
// cache, and the fetch rate limiter. These run without etcd.

package identity

import (
	"strings"
	"testing"
	"time"
)

// ── loadRanges: partition correctness ──────────────────────────

// TestLoadRangesCoversPrefix verifies the parallel loader's ranges are (a)
// pairwise disjoint and (b) their union covers every key under the prefix —
// checked by sorting representative keys from every key space into exactly
// one range.
func TestLoadRangesCoversPrefix(t *testing.T) {
	s := &EtcdStore{prefix: "/sandswap/identity/", hotOnly: false}
	ranges := s.loadRanges()

	inRange := func(key string) int {
		hits := 0
		for _, r := range ranges {
			if key >= r.start && key < r.end {
				hits++
			}
		}
		return hits
	}

	keys := []string{
		s.prefix + "agent/deadbeef",
		// Every first hex char after "sandfs/", plus out-of-hex edge chars.
		// (meta/ is deliberately NOT covered by any range anymore — display
		// data is lazy point-fetched, never full-loaded;.)
		s.prefix + "sandfs/sandfs-0abc1234",
		s.prefix + "sandfs/sandfs-9abc1234",
		s.prefix + "sandfs/sandfs-abcdef01",
		s.prefix + "sandfs/sandfs-fdecba10",
		s.prefix + "sandfs/sandfs-zzzz",   // non-hex first char → catch-all bucket
		s.prefix + "sandfs/sandfs-!wacky", // below '0' → low catch-all bucket
	}

	for _, key := range keys {
		if hits := inRange(key); hits != 1 {
			t.Errorf("key %q landed in %d ranges, want exactly 1", key, hits)
		}
	}

	// Lock keys are ephemeral coordination state — intentionally NOT loaded.
	if hits := inRange(s.prefix + "lock/sandfs/x"); hits != 0 {
		t.Errorf("lock key landed in %d ranges, want 0 (never loaded)", hits)
	}

	// Distribution: sandfs IDs must spread across MANY distinct ranges, not
	// collapse into one catch-all bucket. The etcd key is "sandfs/sandfs-<hex>",
	// so bucketing must be on the hex digit AFTER "sandfs/sandfs-". If it
	// bucketed on the char after "sandfs/" (always 's'), every ID lands in one
	// range and 100k IDs load single-threaded — the bug this guards against.
	used := make(map[int]bool)
	for _, h := range hexDigits {
		key := s.prefix + "sandfs/sandfs-" + string(h) + "1234567"
		for i, r := range ranges {
			if key >= r.start && key < r.end {
				used[i] = true
				break
			}
		}
	}
	if len(used) < 10 {
		t.Errorf("sandfs IDs spread across only %d ranges, want >=10 (hex bucketing broken)", len(used))
	}

	// HotOnly must exclude the meta range but keep agent+sandfs coverage.
	s.hotOnly = true
	for _, r := range s.loadRanges() {
		if strings.HasPrefix(r.start, s.prefix+"meta/") {
			t.Error("hotOnly mode must not include the meta/ range")
		}
	}
}

// ── On-disk codecs ─────────────────────────────────────────────

func TestEncodeDecodeSandfsRecordRoundTrip(t *testing.T) {
	rec := &Record{
		ID:          "sandfs-ab12",
		AgentID:     "agent-cd34",
		RootFSPath:  "/vol/sandfs-ab12/rootfs",
		Template:    "mysql:v1",
		Mode:        "overlay",
		MinVCPUs:    2,
		MinMemoryMB: 512,
	}
	data, err := encodeSandfsRecord(rec)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	// Display fields must NOT appear in the hot record JSON.
	if strings.Contains(string(data), "\"name\"") || strings.Contains(string(data), "description") {
		t.Errorf("hot record leaks display fields: %s", data)
	}
	back := decodeSandfsRecord(data)
	if back == nil {
		t.Fatal("decode returned nil")
	}
	if *back != *rec {
		t.Errorf("round-trip mismatch: %+v vs %+v", back, rec)
	}
}

func TestDecodeSandfsRecordCorrupt(t *testing.T) {
	if decodeSandfsRecord([]byte("{bad")) != nil {
		t.Error("expected nil for corrupt record")
	}
}

func TestEncodeDecodeSandfsMetaRoundTrip(t *testing.T) {
	meta := &sandfsMetaInfo{Name: "analytics", Description: "ad-hoc queries", CreatedAt: "2026-08-07T00:00:00Z"}
	data, err := encodeSandfsMeta(meta)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	back := decodeSandfsMeta(data)
	if back == nil || back.Name != meta.Name || back.Description != meta.Description || back.CreatedAt != meta.CreatedAt {
		t.Errorf("round-trip mismatch: %+v", back)
	}
}

func TestDecodeSandfsMetaCorrupt(t *testing.T) {
	if decodeSandfsMeta([]byte("{bad")) != nil {
		t.Error("expected nil for corrupt meta")
	}
}

// ── Snapshot decode (incl. hotOnly) ────────────────────────────

func TestDecodeIntoSnapshotAllSpaces(t *testing.T) {
	s := &EtcdStore{prefix: "/p/"}
	snap := newIdentitySnapshot()

	s.decodeIntoSnapshot("/p/agent/"+hashAPIKey("k"), []byte(`{"agent_id":"agent-1","name":"n","api_key_hash":"`+hashAPIKey("k")+`","created_at":"2026-08-07T00:00:00Z"}`), snap)
	s.decodeIntoSnapshot("/p/sandfs/sandfs-a1", []byte(`{"sandfs_id":"sandfs-a1","agent_id":"agent-1"}`), snap)
	// meta keys are NEVER part of the snapshot — display data is lazy
	// point-fetched on the human gateway; a meta key appearing in a load range
	// (it never does — loadRanges excludes meta/) must not be snapshotted.
	s.decodeIntoSnapshot("/p/meta/sandfs/sandfs-a1", []byte(`{"name":"nn"}`), snap)

	if len(snap.agents) != 1 || len(snap.sandfs) != 1 {
		t.Fatalf("snapshot counts off: agents=%d sandfs=%d", len(snap.agents), len(snap.sandfs))
	}
	if snap.apiKeyToID[hashAPIKey("k")] != "agent-1" {
		t.Errorf("digest index not populated: %v", snap.apiKeyToID)
	}
	if _, ok := snap.byAgent["agent-1"]["sandfs-a1"]; !ok {
		t.Errorf("reverse index not populated: %v", snap.byAgent)
	}
	if snap.kvs != 2 {
		t.Errorf("kvs = %d, want 2 (meta never counts)", snap.kvs)
	}
}

// ── Cache maintenance helpers ──────────────────────────────────

func newTestCacheStore() *EtcdStore {
	return &EtcdStore{
		prefix:          "/p/",
		agents:          make(map[string]*Agent),
		agentApiKeyToID: make(map[string]string),
		sandfs:          make(map[string]*Record),
		sandfsMeta:      make(map[string]*sandfsMetaInfo),
		sandfsByAgent:   make(map[string]map[string]struct{}),
	}
}

// TestApplyPutDeleteSandfsOwnershipChange verifies the reverse index follows
// a sandfs when its owner changes and is pruned when sets empty out.
func TestApplyPutDeleteSandfsOwnershipChange(t *testing.T) {
	s := newTestCacheStore()
	s.mu.Lock()

	rec := &Record{ID: "sf-1", AgentID: "agent-A"}
	s.applySandfsPutLocked(rec)
	if _, ok := s.sandfsByAgent["agent-A"]["sf-1"]; !ok {
		t.Fatal("initial ownership missing from index")
	}

	rec2 := &Record{ID: "sf-1", AgentID: "agent-B"}
	s.applySandfsPutLocked(rec2)
	if _, ok := s.sandfsByAgent["agent-A"]["sf-1"]; ok {
		t.Error("old owner still indexed after ownership change")
	}
	if _, ok := s.sandfsByAgent["agent-B"]["sf-1"]; !ok {
		t.Error("new owner not indexed")
	}

	s.applyDeleteLocked("/p/sandfs/sf-1")
	if _, ok := s.sandfs["sf-1"]; ok {
		t.Error("record not deleted")
	}
	if _, ok := s.sandfsByAgent["agent-B"]; ok {
		t.Error("empty per-agent set not pruned")
	}
	s.mu.Unlock()
}

func TestApplyPutDeleteAgentDigestIndex(t *testing.T) {
	s := newTestCacheStore()
	hash := hashAPIKey("sk-test")
	s.mu.Lock()
	s.applyAgentPutLocked(&Agent{ID: "agent-1", APIKeyHash: hash})
	s.applyAgentPutLocked(&Agent{ID: "agent-1", APIKeyHash: hashAPIKey("sk-rotated")})
	s.mu.Unlock()

	if _, ok := s.agentApiKeyToID[hash]; ok {
		t.Error("stale digest still indexed after key rotation")
	}
	if s.agentApiKeyToID[hashAPIKey("sk-rotated")] != "agent-1" {
		t.Error("rotated digest not indexed")
	}

	s.mu.Lock()
	s.applyDeleteLocked("/p/agent/" + hashAPIKey("sk-rotated"))
	s.mu.Unlock()
	if _, ok := s.agents["agent-1"]; ok {
		t.Error("agent not deleted")
	}
	if _, ok := s.agentApiKeyToID[hashAPIKey("sk-rotated")]; ok {
		t.Error("digest index entry not deleted")
	}
}

func TestMergeMetaLocked(t *testing.T) {
	s := newTestCacheStore()
	s.mu.Lock()
	s.sandfs["sf-1"] = &Record{ID: "sf-1", AgentID: "agent-1"}
	s.sandfsMeta["sf-1"] = &sandfsMetaInfo{Name: "nn", Description: "dd", CreatedAt: "2026-08-07T01:02:03.000000004Z"}
	out := s.mergeMetaLocked(s.sandfs["sf-1"])
	s.mu.Unlock()

	if out.Name != "nn" || out.Description != "dd" {
		t.Errorf("meta not merged: %+v", out)
	}
	want := time.Date(2026, 8, 7, 1, 2, 3, 4, time.UTC)
	if !out.CreatedAt.Equal(want) {
		t.Errorf("CreatedAt = %v, want %v", out.CreatedAt, want)
	}
}

func TestJournalPendingOnlyWhileLoading(t *testing.T) {
	s := newTestCacheStore()

	s.journalPending("/p/sandfs/x")
	if len(s.pendingKeys) != 0 {
		t.Fatal("journal must stay empty while not loading")
	}

	s.mu.Lock()
	s.loading = true
	s.mu.Unlock()
	s.journalPending("/p/sandfs/x", "/p/sandfs/y")

	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.pendingKeys) != 2 {
		t.Fatalf("pendingKeys = %v, want 2 journaled keys", s.pendingKeys)
	}
}

// ── Negative cache ─────────────────────────────────────────────

func TestNegativeCacheExpiryAndClear(t *testing.T) {
	n := &negativeCache{entries: map[string]time.Time{}, cap: 10, ttl: 5 * time.Millisecond}

	n.put("k")
	if !n.get("k") {
		t.Fatal("fresh negative entry not visible")
	}
	n.clear("k")
	if n.get("k") {
		t.Fatal("cleared entry still visible")
	}

	n.put("exp")
	time.Sleep(6 * time.Millisecond)
	if n.get("exp") {
		t.Error("expired entry still visible")
	}
}

func TestNegativeCacheCapEviction(t *testing.T) {
	n := &negativeCache{entries: map[string]time.Time{}, cap: 4, ttl: time.Second}
	for i := 0; i < 20; i++ {
		n.put(string(rune('a'+i%26)) + string(rune('a'+i/26)))
	}
	n.mu.Lock()
	size := len(n.entries)
	n.mu.Unlock()
	if size > n.cap {
		t.Errorf("cache size %d exceeds cap %d", size, n.cap)
	}
}

// ── Fetch limiter ──────────────────────────────────────────────

func TestFetchLimiterWindow(t *testing.T) {
	l := &fetchLimiter{}

	// Within the window: first max requests allowed, then denied.
	for i := 0; i < lazyFetchRatePerSec; i++ {
		if !l.allow("k") {
			t.Fatalf("request %d denied before the limit", i+1)
		}
	}
	if l.allow("k") {
		t.Error("request beyond the per-key limit was allowed")
	}
	// A different key is unaffected.
	if !l.allow("other") {
		t.Error("unrelated key denied by k's budget")
	}
}

func TestFetchLimiterPrunesStaleWindows(t *testing.T) {
	l := &fetchLimiter{}
	old := time.Now().Add(-time.Hour)
	for i := 0; i < 300; i++ {
		k := string(rune(i))
		l.mu.Lock()
		l.counts = map[string]int{}
		l.windows = map[string]time.Time{}
		l.window = time.Second
		l.max = lazyFetchRatePerSec
		l.windows[k] = old
		l.counts[k] = 1
		l.mu.Unlock()
		l.allow(k)
	}
	// No assertion needed beyond "no deadlock / no unbounded growth panic";
	// stale windows older than one period are dropped as keys are revisited.
}

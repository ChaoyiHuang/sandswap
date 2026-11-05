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

package lease

import (
	"log"
	"testing"
	"time"

	"go.etcd.io/etcd/api/v3/mvccpb"
	clientv3 "go.etcd.io/etcd/client/v3"
	"log/slog"

	"gateway/stream"
)

// newTestCache builds an OwnershipCache with a nil etcd client (local/test
// mode). The nil-client guards in ownership.go make every method safe without
// etcd: async etcd mirrors are skipped and claimFromEtcd returns permissive.
func newTestCache(streamSrv *stream.Server) *OwnershipCache {
	oc := &OwnershipCache{
		gatewayID:           "gw-test",
		streamSrv:           streamSrv,
		logger:              slog.Default(),
		cache:               make(map[string]*ownershipEntry),
		nodeSandfs:          make(map[string]map[string]struct{}),
		pendingOwnerRelease: make(map[string]time.Time),
		presenceLeases:      make(map[string]clientv3.LeaseID),
		presenceTTLs:        make(map[string]time.Duration),
		presenceWardenSecs:  make(map[string]int),
		watchDone:           make(chan struct{}),
		healthDone:          make(chan struct{}),
		// Tests simulate a healthy compute-present gateway. Without this,
		// currentNodeCount() returns 0 (nil/empty streamSrv) and checkEntry
		// returns ErrOwnerNoCompute. Tests that exercise the fault state set
		// nodeCountFn to return 0 explicitly.
		nodeCountFn: func() int { return 1 },
	}
	// Tests assume etcd is reachable so the fast-path cache is exercised.
	oc.etcdAlive.Store(true)
	oc.cacheTTLNS.Store(int64(defaultCacheTTL))
	oc.alertScanIntervalNS.Store(int64(defaultAlertScanInterval))
	oc.releaseBatchSem = make(chan struct{}, releaseBatchConcurrency)
	return oc
}

// setEntry inserts/overwrites a cache entry directly. fresh=false makes it
// older than the live cache TTL (whatever the cache is configured with) so
// Claim takes the slow path.
func setEntry(oc *OwnershipCache, sandfsID, placement string, fresh bool) {
	oc.mu.Lock()
	defer oc.mu.Unlock()
	ct := time.Now()
	if !fresh {
		ct = ct.Add(-(time.Duration(oc.cacheTTLNS.Load()) + time.Second))
	}
	oc.cache[sandfsID] = &ownershipEntry{
		gatewayID:  oc.gatewayID,
		placement:  placement,
		published:  placement,
		claimTime:  ct,
		generation: 1,
	}
}

func entryPlacement(oc *OwnershipCache, sandfsID string) string {
	oc.mu.Lock()
	defer oc.mu.Unlock()
	if e, ok := oc.cache[sandfsID]; ok {
		return e.placement
	}
	return "<missing>"
}

// entryClaimAge returns the entry's claimTime age (for the reconnect assertions: a
// reconnect must NOT refresh it, so the stale-cache fast path stays cold).
func entryClaimAge(oc *OwnershipCache, sandfsID string) time.Duration {
	oc.mu.Lock()
	defer oc.mu.Unlock()
	if e, ok := oc.cache[sandfsID]; ok {
		return time.Since(e.claimTime)
	}
	return 0
}

func entryExists(oc *OwnershipCache, sandfsID string) bool {
	oc.mu.Lock()
	defer oc.mu.Unlock()
	_, ok := oc.cache[sandfsID]
	return ok
}

func (oc *OwnershipCache) nodeSandfsHas(nodeID, sandfsID string) bool {
	oc.mu.Lock()
	defer oc.mu.Unlock()
	_, ok := oc.nodeSandfs[nodeID][sandfsID]
	return ok
}

func (oc *OwnershipCache) cacheHas(sandfsID string) bool {
	oc.mu.Lock()
	defer oc.mu.Unlock()
	_, ok := oc.cache[sandfsID]
	return ok
}

// TestOwnershipClaimFastPath verifies a fresh cache entry makes Claim take the
// in-memory fast path (no etcd), returning the cached preferredNode.
func TestOwnershipClaimFastPath(t *testing.T) {
	oc := newTestCache(nil)
	setEntry(oc, "sandfs-1", "node-1", true)

	pn, err := oc.Claim("sandfs-1", "")
	if err != nil {
		t.Fatalf("Claim fast path: %v", err)
	}
	if pn != "node-1" {
		t.Errorf("expected preferredNode node-1, got %q", pn)
	}
}

// TestOwnershipEtcdAliveGuardsFastPath: when etcd is unreachable
// (etcdAlive=false, KeepAlive failed), the Claim fast-path is disabled even for a
// fresh cache entry, so a mount can't be served from a stale cache during an etcd
// outage. The slow path (nil client here) returns permissive ("", nil) instead of
// the cached node - in production it would 503 (etcd Get error).
func TestOwnershipEtcdAliveGuardsFastPath(t *testing.T) {
	oc := newTestCache(nil)
	setEntry(oc, "sandfs-1", "node-1", true) // fresh cache entry

	// etcd reachable: fast-path returns the cached preferred node.
	if p, err := oc.Claim("sandfs-1", ""); err != nil || p != "node-1" {
		t.Fatalf("etcd alive: expected node-1, got %q err=%v", p, err)
	}

	// etcd partitioned (KeepAlive failed): fast-path disabled -> slow path.
	oc.etcdAlive.Store(false)
	if p, err := oc.Claim("sandfs-1", ""); err != nil || p != "" {
		t.Fatalf("etcd down: expected slow-path permissive '', got %q err=%v", p, err)
	}

	// etcd recovers: fast-path re-enabled.
	oc.etcdAlive.Store(true)
	if p, err := oc.Claim("sandfs-1", ""); err != nil || p != "node-1" {
		t.Fatalf("etcd recovered: expected node-1, got %q err=%v", p, err)
	}
}

// TestOwnershipClaimFaultState verifies: a gateway that owns a sandfs but has
// NO compute (node_count == 0) returns ErrOwnerNoCompute on its own Claim, so the
// handler emits 503 + retry_after (instead of succeeding at Claim and 503-ing at
// pool.Acquire). The agent retries -> re-resolves -> owner-aware DNS routes it to
// a healthy gateway. No ownership is released (no churn on transient blips).
func TestOwnershipClaimFaultState(t *testing.T) {
	oc := newTestCache(nil)
	oc.SetNodeCountFunc(func() int { return 0 }) // fault state: no sandlot
	setEntry(oc, "sandfs-1", "node-1", true)

	_, err := oc.Claim("sandfs-1", "")
	if err != ErrOwnerNoCompute {
		t.Fatalf("expected ErrOwnerNoCompute in fault state, got %v", err)
	}
	// Ownership is NOT released - the cache entry is intact for when the sandlot
	// reconnects (transient blip recovery).
	oc.mu.Lock()
	_, stillOwned := oc.cache["sandfs-1"]
	oc.mu.Unlock()
	if !stillOwned {
		t.Errorf("fault-state Claim should NOT release ownership (churn on transient blips)")
	}
}

// TestOwnershipPlacementServeability verifies the placement serveability table:
// never-placed (placement "") -> OK; placed + reachable node -> OK; placed +
// orphan-uncertain (suspect) -> ErrOwnerNodeDown.
func TestOwnershipPlacementServeability(t *testing.T) {
	// never placed: placement="" -> OK
	oc := newTestCache(nil)
	setEntry(oc, "s-idle", "", true)
	if _, err := oc.Claim("s-idle", ""); err != nil {
		t.Errorf("never placed: expected OK, got %v", err)
	}

	// placed + streamSrv=nil (single-node): node assumed reachable -> OK
	oc2 := newTestCache(nil)
	setEntry(oc2, "s-active", "node-1", true)
	if _, err := oc2.Claim("s-active", ""); err != nil {
		t.Errorf("placed + nil streamSrv: expected OK, got %v", err)
	}

	// placed + orphan-uncertain (node NOT registered -> unreachable) -> ErrOwnerNodeDown
	emptySrv := stream.NewServer("gw-test", log.New(nil, "", 0), 0, 0)
	oc3 := newTestCache(emptySrv)
	setEntry(oc3, "s-down", "node-1", true)
	oc3.mu.Lock()
	oc3.cache["s-down"].suspect = true
	oc3.mu.Unlock()
	_, err := oc3.Claim("s-down", "")
	if err != ErrOwnerNodeDown {
		t.Errorf("placed + orphan-uncertain: expected ErrOwnerNodeDown, got %v", err)
	}

	// gatewayID mismatch -> ErrOwnershipConflict
	oc4 := newTestCache(nil)
	oc4.mu.Lock()
	oc4.cache["s-conflict"] = &ownershipEntry{
		gatewayID: "gw-other",
		claimTime: time.Now(),
	}
	oc4.mu.Unlock()
	_, err = oc4.Claim("s-conflict", "")
	if err != ErrOwnershipConflict {
		t.Errorf("gatewayID mismatch: expected ErrOwnershipConflict, got %v", err)
	}
}

// TestOwnershipPlacementLifecycle verifies the placement lifecycle: set on
// mount (NoteMounted), moved on re-placement (Acquire downgrade), cleared on
// watch conflict (ownership lost).
func TestOwnershipPlacementLifecycle(t *testing.T) {
	oc := newTestCache(nil)

	// First mount to node-1 (NoteMounted replaces the old
	// UpdateNodeID+SetPreferredNode pair).
	setEntry(oc, "sandfs-1", "", true)
	oc.NoteMounted("sandfs-1", "node-1")
	pn, _ := oc.Claim("sandfs-1", "")
	if pn != "node-1" {
		t.Fatalf("expected node-1, got %q", pn)
	}

	// Acquire downgrade to node-2 -> placement moved. A real re-placement is
	// preceded by the lease expiry's unmount (which clears the transient
	// mounted flag); without it the cross-node guard sees a live duplicate.
	oc.NoteUnmounted("sandfs-1")
	oc.NoteMounted("sandfs-1", "node-2")
	pn, _ = oc.Claim("sandfs-1", "")
	if pn != "node-2" {
		t.Errorf("after downgrade: expected node-2, got %q", pn)
	}

	// Watch conflict: another gateway overwrites our generation -> cache
	// invalidated, preferredNode gone. Claim falls to slow path (nil client ->
	// permissive "", nil).
	ev := &clientv3.Event{
		Type: clientv3.EventTypePut,
		Kv: &mvccpb.KeyValue{
			Key:   []byte(ownershipPrefix + "sandfs-1"),
			Value: []byte(`{"gateway_id":"gw-other","node_id":"","generation":99}`),
		},
	}
	oc.handleWatchEvent(ev)
	if entryExists(oc, "sandfs-1") {
		t.Error("expected cache entry invalidated after watch conflict")
	}
	pn, err := oc.Claim("sandfs-1", "")
	if err != nil {
		t.Fatalf("Claim after conflict (nil client): expected permissive nil, got %v", err)
	}
	if pn != "" {
		t.Errorf("expected empty placement after conflict, got %q", pn)
	}
}

// TestOwnershipNoteNodeReconnected verifies that a node reconnect clears the
// transient mount state for everything placed on it, PRESERVES the placement
// (affinity survives reconnect), and leaves other nodes' entries untouched.
func TestOwnershipNoteNodeReconnected(t *testing.T) {
	oc := newTestCache(nil)
	setEntry(oc, "s-1", "node-1", true)
	setEntry(oc, "s-2", "node-1", true)
	setEntry(oc, "s-3", "node-2", true)

	oc.NoteNodeReconnected("node-1")

	// Placement preserved on every entry — affinity survives reconnect.
	if p := entryPlacement(oc, "s-1"); p != "node-1" {
		t.Errorf("s-1 placement: expected node-1 (preserved), got %q", p)
	}
	if p := entryPlacement(oc, "s-2"); p != "node-1" {
		t.Errorf("s-2 placement: expected node-1 (preserved), got %q", p)
	}
	if p := entryPlacement(oc, "s-3"); p != "node-2" {
		t.Errorf("s-3 placement: expected node-2 (untouched), got %q", p)
	}
}

// TestOwnershipClearNodeIDByNodeDoesNotRefreshClaimTime verifies: a
// sandlot reconnect must NOT refresh the cache entry's claimTime. During the
// disconnect window another gateway may have force-taken-over ownership; a
// refreshed claimTime would make the Claim fast-path (`time.Since(claimTime) <
// cache TTL`) trust the stale cache and double-mount. Keeping the old
// claimTime forces the etcd slow-path re-validation.
func TestOwnershipClearNodeIDByNodeDoesNotRefreshClaimTime(t *testing.T) {
	oc := newTestCache(nil)
	ttl := 200 * time.Millisecond
	oc.SetCacheTTLForTest(ttl)
	setEntry(oc, "s-1", "node-1", true) // fresh now
	ageBefore := entryClaimAge(oc, "s-1")
	if ageBefore > time.Second {
		t.Fatalf("precondition: entry should be fresh, claimAge=%v", ageBefore)
	}

	// Simulate a disconnect that outlasts the cache TTL, then the reconnect.
	time.Sleep(ttl + 100*time.Millisecond)
	oc.NoteNodeReconnected("node-1")

	if p := entryPlacement(oc, "s-1"); p != "node-1" {
		t.Fatalf("s-1 placement: expected node-1 (preserved), got %q", p)
	}
	// claimTime must NOT have been refreshed: the entry stays stale.
	if age := entryClaimAge(oc, "s-1"); age < ttl {
		t.Errorf("claimTime was refreshed by NoteNodeReconnected (age=%v < ttl); stale fast-path would trust a force-taken-over sandfs", age)
	}
}

// TestOwnershipCacheExpiry verifies that a stale cache entry (claimTime older
// than cacheMaxAge) forces Claim onto the slow path. With nil client the slow
// path is permissive (no panic).
func TestOwnershipCacheExpiry(t *testing.T) {
	oc := newTestCache(nil)
	setEntry(oc, "sandfs-1", "node-1", false) // stale

	pn, err := oc.Claim("sandfs-1", "")
	if err != nil {
		t.Fatalf("stale Claim (nil client slow path): %v", err)
	}
	if pn != "" {
		t.Errorf("expected empty preferredNode from permissive slow path, got %q", pn)
	}
}

// TestOwnershipWatchConflict verifies handleWatchEvent cache invalidation:
// PUT by another gateway -> delete entry; PUT by us -> update; DELETE -> delete.
func TestOwnershipWatchConflict(t *testing.T) {
	oc := newTestCache(nil)
	setEntry(oc, "sandfs-1", "node-1", true)

	// PUT by our own gateway with new generation+node_id -> entry updated.
	ev := &clientv3.Event{
		Type: clientv3.EventTypePut,
		Kv: &mvccpb.KeyValue{
			Key:   []byte(ownershipPrefix + "sandfs-1"),
			Value: []byte(`{"gateway_id":"gw-test","node_id":"node-2","generation":5}`),
		},
	}
	oc.handleWatchEvent(ev)
	if nid := entryPlacement(oc, "sandfs-1"); nid != "node-2" {
		t.Errorf("own PUT: expected placement node-2, got %q", nid)
	}

	// PUT by another gateway -> entry invalidated.
	ev2 := &clientv3.Event{
		Type: clientv3.EventTypePut,
		Kv: &mvccpb.KeyValue{
			Key:   []byte(ownershipPrefix + "sandfs-1"),
			Value: []byte(`{"gateway_id":"gw-other","node_id":"","generation":6}`),
		},
	}
	oc.handleWatchEvent(ev2)
	if entryExists(oc, "sandfs-1") {
		t.Error("other-gateway PUT: expected entry invalidated")
	}

	// Re-add, then DELETE -> invalidated.
	setEntry(oc, "sandfs-1", "node-1", true)
	ev3 := &clientv3.Event{
		Type: clientv3.EventTypeDelete,
		Kv: &mvccpb.KeyValue{
			Key: []byte(ownershipPrefix + "sandfs-1"),
		},
	}
	oc.handleWatchEvent(ev3)
	if entryExists(oc, "sandfs-1") {
		t.Error("DELETE: expected entry invalidated")
	}
}

// TestOwnershipCloseIdempotent verifies Close can be called multiple times
// without panicking ().
func TestOwnershipCloseIdempotent(t *testing.T) {
	oc := newTestCache(nil)
	oc.Close()
	oc.Close() // must not panic
}

// TestOwnershipNoteMountedNilClientNoPanic verifies the async etcd write
// paths (NoteMounted, NoteNodeReconnected) don't panic when client is nil
// (nil-client guard).
func TestOwnershipNoteMountedNilClientNoPanic(t *testing.T) {
	oc := newTestCache(nil)
	setEntry(oc, "sandfs-1", "node-1", true)

	// NoteMounted spawns an async writeNodeIDInEtcd goroutine; with nil
	// client it must return early, not panic. The cache is updated synchronously
	// to node-2.
	oc.NoteMounted("sandfs-1", "node-2")
	// NoteNodeReconnected matches on the placement (node-2 after the mount
	// above), clearing the transient mount state without an etcd write.
	oc.NoteNodeReconnected("node-2")

	// Give the async goroutines a moment; the test passes if nothing panics.
	time.Sleep(100 * time.Millisecond)

	// Cache should reflect the synchronous updates: placement preserved,
	// mount state cleared.
	if p := entryPlacement(oc, "sandfs-1"); p != "node-2" {
		t.Errorf("after NoteNodeReconnected: expected placement node-2 (preserved), got %q", p)
	}
}

// TestNodeSandfsMaintenance verifies the placement reverse index (nodeID →
// set of sandfsID) is maintained on placement changes: mount add, unmount
// KEEP (placement survives unmount — owner-release locates placed sandfs,
// mounted or not), and node move (old removed, new added).
func TestNodeSandfsMaintenance(t *testing.T) {
	oc := newTestCache(nil)
	oc.SetOwnedForTest("s-1", "node-1")

	// Placed on node-1 → add.
	if !oc.nodeSandfsHas("node-1", "s-1") {
		t.Error("after mount: nodeSandfs[node-1] should contain s-1")
	}

	// Unmount: placement survives → the index KEEPS the sandfs under node-1.
	oc.NoteUnmounted("s-1")
	if !oc.nodeSandfsHas("node-1", "s-1") {
		t.Error("after unmount: nodeSandfs[node-1] should still contain s-1 (placement survives unmount)")
	}

	// Re-placement to node-2 → old removed, new added.
	oc.NoteMounted("s-1", "node-2")
	if oc.nodeSandfsHas("node-1", "s-1") {
		t.Error("after move: nodeSandfs[node-1] should not contain s-1")
	}
	if !oc.nodeSandfsHas("node-2", "s-1") {
		t.Error("after move: nodeSandfs[node-2] should contain s-1")
	}
}

// TestNoteNodeReconnectedKeepsPlacementIndex verifies the reconnect keeps the
// placement index intact: it is keyed on placement (not mount state), so
// owner-release can still locate everything placed on the node.
func TestNoteNodeReconnectedKeepsPlacementIndex(t *testing.T) {
	oc := newTestCache(nil)
	oc.SetOwnedForTest("s-1", "node-1")
	oc.SetOwnedForTest("s-2", "node-1")

	oc.NoteNodeReconnected("node-1")

	if len(oc.nodeSandfs["node-1"]) != 2 {
		t.Errorf("reconnect should keep the placement index: got %d entries, want 2", len(oc.nodeSandfs["node-1"]))
	}
}

// TestForgetOwnershipRemovesNodeSandfs verifies owner-release delete (deleteOwnership) and
// migrated-takeover watch-takeover (forgetOwnership) drop the sandfs from the reverse index.
func TestForgetOwnershipRemovesNodeSandfs(t *testing.T) {
	oc := newTestCache(nil)
	oc.SetOwnedForTest("s-1", "node-1")

	oc.deleteOwnership("s-1")
	if oc.nodeSandfsHas("node-1", "s-1") {
		t.Error("deleteOwnership should remove s-1 from nodeSandfs[node-1]")
	}
	if _, ok := oc.nodeSandfs["node-1"]; ok {
		t.Error("empty nodeSandfs[node-1] entry should be pruned after deleteOwnership")
	}
	if oc.cacheHas("s-1") {
		t.Error("deleteOwnership should drop the cache entry")
	}

	// forgetOwnership (watch-takeover path) — re-mount then forget.
	oc.SetOwnedForTest("s-2", "node-2")
	oc.forgetOwnership("s-2")
	if oc.nodeSandfsHas("node-2", "s-2") {
		t.Error("forgetOwnership should remove s-2 from nodeSandfs[node-2]")
	}
}

// ── Owner-release tombstone ──────────────────────────────────────

// TestOwnerReleasingTombstoneBlocksClaim verifies the owner-release tombstone:
// while the sweep's etcd delete is in flight, Claim refuses to serve the
// sandfs (ErrOwnerNodeDown → 503+retry); past ownerReleaseClaimWindow the
// tombstone stops refusing (a permanently failed delete must not wedge it).
func TestOwnerReleasingTombstoneBlocksClaim(t *testing.T) {
	oc := NewOwnershipCacheForTest("gw-a")
	oc.SetOwnedForTest("s1", "n1")

	if _, err := oc.Claim("s1", ""); err != nil {
		t.Fatalf("Claim on untombed entry: %v", err)
	}

	oc.mu.Lock()
	oc.cache["s1"].ownerReleasing = true
	oc.cache["s1"].releasingSince = time.Now()
	oc.mu.Unlock()

	if _, err := oc.Claim("s1", ""); err != ErrOwnerNodeDown {
		t.Fatalf("Claim during owner-release = %v, want ErrOwnerNodeDown", err)
	}

	// Elapsed tombstone: claims resume (the failed-delete backstop).
	oc.mu.Lock()
	oc.cache["s1"].releasingSince = time.Now().Add(-ownerReleaseClaimWindow - time.Second)
	oc.mu.Unlock()
	node, err := oc.Claim("s1", "")
	if err != nil {
		t.Fatalf("Claim past the tombstone window: %v", err)
	}
	if node != "n1" {
		t.Fatalf("Claim past the tombstone window = %q, want n1", node)
	}
}

// TestUpdateFenceThreshold validates the hot-reload path for the etcd-partition
// self-fence threshold. A value that keeps T_safe > fence + warden + heartbeat
// for every connected node applies; one that breaks the invariant for ANY
// node is refused with the previous threshold kept. A disconnected node's
// timings must not veto the change (its safety is its own tolerance chain),
// and a zero value is refused outright.
func TestUpdateFenceThreshold(t *testing.T) {
	oc := newTestCache(nil)
	// Simulate two connected nodes (local mode: nil streamSrv means
	// NodeConnected is always true). Default timings: tolerance=300,
	// warden=300 -> tSafe = 300+300+60 = 660s. floor = fence + 300 + 30.
	oc.mu.Lock()
	oc.presenceTTLs["node-a"] = 660 * time.Second
	oc.presenceWardenSecs["node-a"] = 300
	oc.presenceTTLs["node-b"] = 660 * time.Second
	oc.presenceWardenSecs["node-b"] = 300
	oc.mu.Unlock()

	// 120s keeps 660 > 120+300+30=450 for both nodes -> applies.
	if err := oc.UpdateFenceThreshold(120 * time.Second); err != nil {
		t.Fatalf("valid raise rejected: %v", err)
	}
	oc.mu.Lock()
	got := oc.fenceThreshold
	oc.mu.Unlock()
	if got != 120*time.Second {
		t.Errorf("fenceThreshold = %v, want 120s", got)
	}

	// 360s breaks node-a's invariant (660 <= 360+300+30=690) -> refused,
	// previous value kept.
	if err := oc.UpdateFenceThreshold(360 * time.Second); err == nil {
		t.Error("invariant-breaking raise accepted, want refusal")
	}
	oc.mu.Lock()
	got = oc.fenceThreshold
	oc.mu.Unlock()
	if got != 120*time.Second {
		t.Errorf("fenceThreshold changed on refused update: %v, want 120s", got)
	}

	// A disconnected node's stale timings must not veto: drop node-b's
	// connectivity by pointing the cache at a stream server without it...
	// (local mode always reports connected, so instead clear its records the
	// way OnNodeDisconnect does.)
	oc.mu.Lock()
	delete(oc.presenceWardenSecs, "node-b")
	delete(oc.presenceTTLs, "node-b")
	oc.mu.Unlock()
	// node-a still limits: 330s keeps 660 > 330+300+30=660? No (not >), so
	// 329s is the boundary-legal max.
	if err := oc.UpdateFenceThreshold(330 * time.Second); err == nil {
		t.Log("330s accepted (boundary semantics: tSafe must EXCEED the floor)")
		t.Error("expected refusal at the exact boundary (tSafe must be strictly greater)")
	}
	if err := oc.UpdateFenceThreshold(329 * time.Second); err != nil {
		t.Fatalf("329s should apply (660 > 659), got: %v", err)
	}

	// Non-positive values are refused outright.
	if err := oc.UpdateFenceThreshold(0); err == nil {
		t.Error("zero threshold accepted, want refusal")
	}
}

// TestFenceClockResetsOnHealedBlip is the regression guard for the self-fence
// anchor: the clock must be armed by the FIRST failed health write of a
// CONTINUOUS outage and cleared by any successful write. A healed
// sub-threshold blip that left the anchor behind would make a later single
// failed write compute an elapsed time far past the threshold — fencing
// (mass-unmounting every mount) on one transient error.
func TestFenceClockResetsOnHealedBlip(t *testing.T) {
	oc := newTestCache(nil)
	oc.mu.Lock()
	oc.fenceThreshold = 180 * time.Second
	oc.mu.Unlock()

	t0 := time.Now()

	// First failure arms the clock; no fire yet.
	if down, _, fire := oc.noteHealthWriteFailure(t0); fire || down != 0 {
		t.Fatalf("first failure: down=%v fire=%v, want 0/false", down, fire)
	}
	// A continuous outage short of the threshold does not fire.
	if _, _, fire := oc.noteHealthWriteFailure(t0.Add(179 * time.Second)); fire {
		t.Fatal("outage short of the threshold fired the fence")
	}
	// Crossing the threshold does.
	if _, _, fire := oc.noteHealthWriteFailure(t0.Add(181 * time.Second)); !fire {
		t.Fatal("continuous outage past the threshold must fire")
	}

	// Heal the outage (the fence-never-engaged case), then fail once much
	// later: the clock must restart, not fire off the stale anchor.
	oc.noteHealthWriteSuccess()
	oc.mu.Lock()
	cleared := oc.etcdDownSince.IsZero()
	oc.mu.Unlock()
	if !cleared {
		t.Fatal("successful write must clear the outage anchor")
	}
	if down, _, fire := oc.noteHealthWriteFailure(t0.Add(10 * time.Minute)); fire || down != 0 {
		t.Fatalf("failure after a healed blip: down=%v fire=%v, want 0/false (stale anchor)", down, fire)
	}
}

// ── Claim cache TTL (ownership.cache_ttl_sec) ──────────────────────────────

// TestSetCacheTTLValidation covers the safety bounds: >= 1s, <= min(2×guard,
// 300s absolute). The 2×guard coupling is the pause/recover corner proof (see
// SetCacheTTL): the stale-serve window (<= TTL) must never overlap the earliest
// possible takeover commit (~2×guard after our last health write).
func TestSetCacheTTLValidation(t *testing.T) {
	oc := newTestCache(nil) // guard defaults to 45s → ceiling min(90, 300)=90s

	if err := oc.SetCacheTTL(500 * time.Millisecond); err == nil {
		t.Errorf("TTL < 1s accepted")
	}
	if err := oc.SetCacheTTL(91 * time.Second); err == nil {
		t.Errorf("TTL > 2×guard (90s default) accepted")
	}
	if err := oc.SetCacheTTL(90 * time.Second); err != nil {
		t.Errorf("TTL == 2×guard refused: %v", err)
	}
	if got := oc.cacheTTL(); got != 90*time.Second {
		t.Errorf("accepted TTL not applied: %v", got)
	}

	// Raise the guard: the ceiling follows 2×guard up to the absolute 300s cap.
	if err := oc.SetStalenessThresholds(0, 200*time.Second, 0); err != nil {
		t.Fatalf("raise guard: %v", err)
	}
	if err := oc.SetCacheTTL(301 * time.Second); err == nil {
		t.Errorf("TTL above the 300s absolute cap accepted (guard=200 → 2×guard=400 but cap 300)")
	}
	if err := oc.SetCacheTTL(300 * time.Second); err != nil {
		t.Errorf("TTL == 300s cap refused: %v", err)
	}
}

// TestSetStalenessThresholdsGuardTTLPair verifies the reverse direction of the
// pair invariant: lowering the guard below TTL/2 is refused (it would tighten
// the TTL safety ceiling under the TTL the process is serving with).
func TestSetStalenessThresholdsGuardTTLPair(t *testing.T) {
	oc := newTestCache(nil) // TTL 30s (default), guard 45s (default via <=0 fallback)
	if err := oc.SetStalenessThresholds(0, 10*time.Second, 0); err == nil {
		t.Fatalf("guard=10 with live TTL=30 accepted (ceiling 2×10=20 < 30)")
	}
	// Lower the TTL first, then the guard change is accepted.
	if err := oc.SetCacheTTL(15 * time.Second); err != nil {
		t.Fatalf("lower TTL: %v", err)
	}
	if err := oc.SetStalenessThresholds(0, 10*time.Second, 0); err != nil {
		t.Fatalf("guard=10 with TTL=15 refused: %v", err)
	}
}

// TestSetStalenessAndCacheTTL verifies the joint setter: a config-valid
// guard/TTL pair is accepted in ONE call even when the live state (defaults)
// makes the sequential setters reject the guard leg first (guard=2s vs live
// TTL=30s: ceiling 2×2=4 < 30) — the startup-wiring trap this setter exists
// for. An invalid pair is refused without mutating anything.
func TestSetStalenessAndCacheTTL(t *testing.T) {
	oc := newTestCache(nil) // TTL 30s (default), guard 45s (default via <=0 fallback)

	if err := oc.SetStalenessAndCacheTTL(0, 2*time.Second, 0, 2*time.Second); err != nil {
		t.Fatalf("joint pair (guard=2s, ttl=2s) refused: %v", err)
	}
	if got := oc.cacheTTL(); got != 2*time.Second {
		t.Errorf("joint TTL not applied: %v", got)
	}
	if oc.claimDeadGuard != 2*time.Second {
		t.Errorf("joint guard not applied: %v", oc.claimDeadGuard)
	}

	// Invalid pair (ttl above the incoming guard's ceiling): refused, and the
	// previously applied pair survives untouched.
	if err := oc.SetStalenessAndCacheTTL(0, 2*time.Second, 0, 5*time.Second); err == nil {
		t.Fatalf("ttl=5s with guard=2s accepted (ceiling 4)")
	}
	if got := oc.cacheTTL(); got != 2*time.Second {
		t.Errorf("refused joint call mutated TTL: %v", got)
	}

	// TTL floor: sub-second refused (SetCacheTTL semantics, no zero sentinel).
	if err := oc.SetStalenessAndCacheTTL(0, 0, 0, 500*time.Millisecond); err == nil {
		t.Fatalf("sub-second TTL accepted")
	}

	// Zero guard falls back to the LIVE guard for the ceiling: a route-only
	// change with the live pair applies; a TTL above the live ceiling refuses.
	if err := oc.SetStalenessAndCacheTTL(3*time.Second, 0, 0, 2*time.Second); err != nil {
		t.Errorf("route-only change with live pair refused: %v", err)
	}
	if err := oc.SetStalenessAndCacheTTL(0, 0, 0, 90*time.Second); err == nil {
		t.Fatalf("ttl=90s with zero guard (live guard=2s → ceiling 4s) accepted")
	}
}

// TestClaimRespectsCacheTTL drives the fast/slow boundary off the LIVE TTL:
// fresh under the TTL, expired past it (SetCacheTTLForTest lets the test run
// sub-second without the production >= 1s floor).
func TestClaimRespectsCacheTTL(t *testing.T) {
	oc := newTestCache(nil)
	oc.SetCacheTTLForTest(200 * time.Millisecond)

	setEntry(oc, "sandfs-ttl", "node-1", true)
	pn, err := oc.Claim("sandfs-ttl", "")
	if err != nil || pn != "node-1" {
		t.Fatalf("fresh fast path: pn=%q err=%v", pn, err)
	}

	time.Sleep(300 * time.Millisecond)
	// Expired now: with a nil etcd client the slow path is permissive and
	// returns an empty placement — the observable difference from the fast
	// path's cached placement.
	pn, err = oc.Claim("sandfs-ttl", "")
	if err != nil {
		t.Fatalf("expired slow path: %v", err)
	}
	if pn != "" {
		t.Errorf("expired entry served from fast path (pn=%q); TTL not enforced", pn)
	}
}

// TestSetAlertScanIntervalValidation: the scan is a full ownership sweep on the
// human gateway — a floor of 10s keeps a misconfigured value from turning the
// control plane into a constant full scan.
func TestSetAlertScanIntervalValidation(t *testing.T) {
	oc := newTestCache(nil)
	if err := oc.SetAlertScanInterval(9 * time.Second); err == nil {
		t.Errorf("interval < 10s accepted")
	}
	if err := oc.SetAlertScanInterval(300 * time.Second); err != nil {
		t.Errorf("interval 300s refused: %v", err)
	}
}

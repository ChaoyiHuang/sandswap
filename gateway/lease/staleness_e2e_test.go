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

//go:build ownership_e2e

// Internal-package (lease) e2e tests for the health-staleness judgment and the
// time-protected CAS claim. These run against a real etcd at
// 127.0.0.1:2379 (started by e2e/ownership.sh) and call the unexported
// ownerStaleness / ownerDead / selfHealthy / ScanStaleOwners / Claim directly.
// They are in package lease (not lease_test) so they can reach the unexported
// helpers and the deadSince map.

package lease

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
)

// stalenessEtcdEndpoint is the plain-http etcd the tagged e2e tests drive.
// Overridable so the suite can run beside a deployed (mTLS) etcd that already
// owns 2379: SANDSWAP_TEST_ETCD_ENDPOINT=http://127.0.0.1:12379 //   go test -tags ownership_e2e ./lease/
var stalenessEtcdEndpoint = func() string {
	if v := os.Getenv("SANDSWAP_TEST_ETCD_ENDPOINT"); v != "" {
		return v
	}
	return "http://127.0.0.1:2379"
}()

func stalenessEtcdClient(t *testing.T) *clientv3.Client {
	t.Helper()
	cli, err := clientv3.New(clientv3.Config{
		Endpoints:   []string{stalenessEtcdEndpoint},
		DialTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("etcd client: %v", err)
	}
	t.Cleanup(func() { cli.Close() })
	return cli
}

// newStalenessCache builds an OwnershipCache backed by a real etcd, with a
// buffer-backed logger so tests can assert warn output. The cache's bootstrap
// full-load populates oc.cache with every pre-existing ownership key, so seed
// ownership keys BEFORE calling this.
func newStalenessCache(t *testing.T, gwID string, logBuf *strings.Builder) *OwnershipCache {
	t.Helper()
	cli := stalenessEtcdClient(t)
	var logger *slog.Logger
	if logBuf != nil {
		logger = slog.New(slog.NewTextHandler(logBuf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	} else {
		logger = slog.Default()
	}
	oc, err := NewOwnershipCache(cli, gwID, nil, logger)
	if err != nil {
		t.Fatalf("NewOwnershipCache: %v", err)
	}
	t.Cleanup(func() { oc.Close() })
	oc.SetNodeCountFunc(func() int { return 1 })
	return oc
}

// putHealthWithTS seeds a /sandswap/health/{gw} value with a custom
// last_healthy_ts under no lease (the staleness helper reads the value, not the
// lease). An empty ts omits the field (legacy/corrupt case).
func putHealthWithTS(t *testing.T, cli *clientv3.Client, gwID, ts string) {
	t.Helper()
	val := map[string]interface{}{"node_count": 1}
	if ts != "" {
		val["last_healthy_ts"] = ts
	}
	data, _ := json.Marshal(val)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := cli.Put(ctx, healthPrefix+gwID, string(data)); err != nil {
		t.Fatalf("put health %s: %v", gwID, err)
	}
}

func putOwnershipRaw(t *testing.T, cli *clientv3.Client, sandfsID, gwID, nodeID string, gen uint64) {
	t.Helper()
	val := OwnershipValue{GatewayID: gwID, NodeID: nodeID, Generation: gen}
	data, _ := json.Marshal(val)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := cli.Put(ctx, ownershipPrefix+sandfsID, string(data)); err != nil {
		t.Fatalf("put ownership %s: %v", sandfsID, err)
	}
}

// TestOwnerStalenessE2E verifies the staleness helper against a real etcd: a
// fresh key returns present+small stale; an absent key returns not-present
// (dead); a stale-ts key returns present+large stale; a corrupt/legacy value
// fails-alive.
func TestOwnerStalenessE2E(t *testing.T) {
	oc := newStalenessCache(t, "gw-stale-self", nil)
	cli := stalenessEtcdClient(t)
	ctx := context.Background()
	freshGW, deadGW, corruptGW := "gw-stale-fresh", "gw-stale-dead", "gw-stale-corrupt"
	t.Cleanup(func() {
		cli.Delete(ctx, healthPrefix+freshGW)
		cli.Delete(ctx, healthPrefix+deadGW)
		cli.Delete(ctx, healthPrefix+corruptGW)
	})

	// Fresh: timestamp = now.
	putHealthWithTS(t, cli, freshGW, time.Now().Format(time.RFC3339))
	stale, present := oc.ownerStaleness(ctx, freshGW)
	if !present {
		t.Fatal("fresh key: present=false, want true")
	}
	if stale > 5*time.Second {
		t.Errorf("fresh key: stale=%v, want <=5s", stale)
	}

	// Absent: no key → present=false (dead).
	stale, present = oc.ownerStaleness(ctx, deadGW)
	if present {
		t.Fatal("absent key: present=true, want false (dead)")
	}

	// Stale timestamp: 2 minutes ago → present + large stale.
	putHealthWithTS(t, cli, freshGW, time.Now().Add(-2*time.Minute).Format(time.RFC3339))
	stale, present = oc.ownerStaleness(ctx, freshGW)
	if !present {
		t.Fatal("stale-ts key: present=false, want true")
	}
	if stale < 90*time.Second {
		t.Errorf("stale-ts key: stale=%v, want >=90s", stale)
	}

	// Corrupt value (no timestamp) → fail-alive: present=true, stale=0.
	putHealthWithTS(t, cli, corruptGW, "")
	stale, present = oc.ownerStaleness(ctx, corruptGW)
	if !present {
		t.Fatal("corrupt key: present=false, want true (fail-alive)")
	}
	if stale != 0 {
		t.Errorf("corrupt key: stale=%v, want 0 (fail-alive)", stale)
	}
}

// TestSelfHealthyStalenessE2E verifies selfHealthy flips to false once the self
// health value goes stale past the claim-dead guard, and is false when the key
// is absent (lease expired).
func TestSelfHealthyStalenessE2E(t *testing.T) {
	oc := newStalenessCache(t, "gw-self-healthy", nil)
	oc.SetCacheTTLForTest(time.Second)             // test opts out of the TTL≤2×guard production pair-check
	oc.SetStalenessThresholds(0, 2*time.Second, 0) // claim-dead guard = 2s for the test
	cli := stalenessEtcdClient(t)
	ctx := context.Background()
	gwID := "gw-self-healthy"
	t.Cleanup(func() { cli.Delete(ctx, healthPrefix+gwID) })

	// Fresh self → healthy.
	putHealthWithTS(t, cli, gwID, time.Now().Format(time.RFC3339))
	if !oc.selfHealthy(ctx) {
		t.Fatal("fresh self health: selfHealthy=false, want true")
	}

	// Self value stale past guard (2s) but key present → unhealthy.
	putHealthWithTS(t, cli, gwID, time.Now().Add(-10*time.Second).Format(time.RFC3339))
	if oc.selfHealthy(ctx) {
		t.Fatal("stale self value (past guard): selfHealthy=true, want false")
	}

	// Self key absent (lease expired) → unhealthy.
	cli.Delete(ctx, healthPrefix+gwID)
	if oc.selfHealthy(ctx) {
		t.Fatal("absent self key: selfHealthy=true, want false")
	}
}

// TestOwnerDeadStalenessE2E verifies ownerDead fires on an absent key (the
// normal 14s-lease-expiry death) AND on a present-but-stale-past-guard key (the
// rare backstop), and does NOT fire on a fresh key.
func TestOwnerDeadStalenessE2E(t *testing.T) {
	oc := newStalenessCache(t, "gw-dead-judge", nil)
	oc.SetCacheTTLForTest(time.Second)             // test opts out of the TTL≤2×guard production pair-check
	oc.SetStalenessThresholds(0, 2*time.Second, 0) // guard = 2s
	cli := stalenessEtcdClient(t)
	ctx := context.Background()
	freshGW, staleGW, absentGW := "gw-dead-fresh", "gw-dead-stale", "gw-dead-absent"
	t.Cleanup(func() {
		cli.Delete(ctx, healthPrefix+freshGW)
		cli.Delete(ctx, healthPrefix+staleGW)
	})

	putHealthWithTS(t, cli, freshGW, time.Now().Format(time.RFC3339))
	if oc.ownerDead(ctx, freshGW) {
		t.Fatal("fresh owner: ownerDead=true, want false")
	}

	// Absent key → dead.
	if !oc.ownerDead(ctx, absentGW) {
		t.Fatal("absent owner key: ownerDead=false, want true")
	}

	// Present but stale past guard → dead (backstop).
	putHealthWithTS(t, cli, staleGW, time.Now().Add(-10*time.Second).Format(time.RFC3339))
	if !oc.ownerDead(ctx, staleGW) {
		t.Fatal("stale-present owner (past guard): ownerDead=false, want true")
	}
}

// TestStalenessAlertScanE2E verifies the alert scan warns about a stale peer
// owner with stranded sandfs and stays quiet about a fresh one. ScanStaleOwners
// does a full ownership-prefix scan, so peer-owned keys are detected regardless
// of the local cache (which only holds self-owned entries).
func TestStalenessAlertScanE2E(t *testing.T) {
	cli := stalenessEtcdClient(t)
	ctx := context.Background()
	// Distinct ids per run so leftover keys from a prior failed run (same fixed
	// peer id) do not inflate the count.
	suf := time.Now().Format("150405.000000")
	stalePeer, freshPeer := "gw-alert-stale-"+suf, "gw-alert-fresh-"+suf
	staleSandfs := []string{"sandfs-alert-stale-" + suf + "-1", "sandfs-alert-stale-" + suf + "-2"}
	freshSandfs := []string{"sandfs-alert-fresh-" + suf + "-1"}

	// Seed ownership keys owned by the peers (idle).
	for _, sf := range staleSandfs {
		putOwnershipRaw(t, cli, sf, stalePeer, "", 1)
	}
	for _, sf := range freshSandfs {
		putOwnershipRaw(t, cli, sf, freshPeer, "", 1)
	}

	var buf strings.Builder
	oc := newStalenessCache(t, "gw-alert-self-"+suf, &buf)
	oc.SetStalenessThresholds(0, 0, 2*time.Second) // alert threshold = 2s

	// Fresh peer health, stale peer health (10s ago, past the 2s alert threshold).
	putHealthWithTS(t, cli, freshPeer, time.Now().Format(time.RFC3339))
	putHealthWithTS(t, cli, stalePeer, time.Now().Add(-10*time.Second).Format(time.RFC3339))

	t.Cleanup(func() {
		cli.Delete(ctx, healthPrefix+stalePeer)
		cli.Delete(ctx, healthPrefix+freshPeer)
		for _, sf := range append(append([]string{}, staleSandfs...), freshSandfs...) {
			cli.Delete(ctx, ownershipPrefix+sf)
		}
	})

	buf.Reset()
	stale, err := oc.ScanStaleOwners(ctx)
	if err != nil {
		t.Fatalf("ScanStaleOwners: %v", err)
	}
	if got := stale[stalePeer]; got != 2 {
		t.Errorf("stale peer stranded count = %d, want 2 (full map=%v)", got, stale)
	}
	if _, ok := stale[freshPeer]; ok {
		t.Errorf("fresh peer reported as stale (should be quiet): %v", stale)
	}
	out := buf.String()
	if !strings.Contains(out, "owner_gateway_id="+stalePeer) {
		t.Errorf("alert scan did not warn about stale peer %q (output=%q)", stalePeer, out)
	}
	if strings.Contains(out, "owner_gateway_id="+freshPeer) {
		t.Errorf("alert scan warned about fresh peer %q (should be quiet)", freshPeer)
	}
	if !strings.Contains(out, "stuck_sandfs=2") {
		t.Errorf("alert scan output missing stuck_sandfs=2 (output=%q)", out)
	}
}

// TestClaimDeadIdleWritesCandidatePlacementE2E verifies the never-placed
// invariant survives a dead-idle takeover: when the dead owner's record has an
// EMPTY node_id (never placed — nothing to interrogate), the takeover CAS must
// write the claim's OWN candidate placement, not preserve the empty value.
// Preserving "" would let a record sit in etcd with node_id empty while its
// new owner dispatches a mount, breaking "node_id == ” ⟺ no mount was ever
// dispatched". A non-empty placement, by contrast,
// must be preserved (affinity survives takeovers).
func TestClaimDeadIdleWritesCandidatePlacementE2E(t *testing.T) {
	suf := time.Now().Format("150405.000000")
	deadOwner := "gw-dead-cand-" + suf
	claimerID := "gw-claimer-cand-" + suf
	sandfsID := "sandfs-deadcand-" + suf
	const candidateNode = "node-candidate"

	cli := stalenessEtcdClient(t)
	ctx := context.Background()
	// Seed: NEVER-PLACED record (node_id "") owned by deadOwner.
	putOwnershipRaw(t, cli, sandfsID, deadOwner, "", 1)
	t.Cleanup(func() {
		cli.Delete(ctx, ownershipPrefix+sandfsID)
		cli.Delete(ctx, healthPrefix+deadOwner)
	})

	oc := newStalenessCache(t, claimerID, nil)
	oc.SetCacheTTLForTest(time.Second)             // test opts out of the TTL≤2×guard production pair-check
	oc.SetStalenessThresholds(0, 2*time.Second, 0) // claim-dead guard = 2s

	// Within the guard → tolerate, record untouched.
	if _, err := oc.Claim(sandfsID, candidateNode); err != ErrOwnershipConflict {
		t.Fatalf("within guard: Claim err = %v, want ErrOwnershipConflict", err)
	}
	if owner := ownerGwID(t, cli, sandfsID); owner != deadOwner {
		t.Fatalf("within guard: owner = %q, want %q", owner, deadOwner)
	}

	// Past the guard → CAS takeover writes OUR candidate as the placement.
	time.Sleep(2500 * time.Millisecond)
	if _, err := oc.Claim(sandfsID, candidateNode); err != nil {
		t.Fatalf("past guard: Claim err = %v, want nil (takeover)", err)
	}
	owner, placedNode := ownerGwAndNode(t, cli, sandfsID)
	if owner != claimerID {
		t.Fatalf("past guard: owner = %q, want %q (takeover)", owner, claimerID)
	}
	if placedNode != candidateNode {
		t.Fatalf("past guard: node_id = %q, want %q (candidate must be written, empty must not survive)", placedNode, candidateNode)
	}
}

// ownerGwAndNode reads an ownership record's gateway_id + node_id from etcd.
func ownerGwAndNode(t *testing.T, cli *clientv3.Client, sandfsID string) (gwID, nodeID string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	resp, err := cli.Get(ctx, ownershipPrefix+sandfsID)
	if err != nil || len(resp.Kvs) == 0 {
		t.Fatalf("get ownership %s: err=%v kvs=%d", sandfsID, err, len(resp.Kvs))
	}
	var val OwnershipValue
	if err := json.Unmarshal(resp.Kvs[0].Value, &val); err != nil {
		t.Fatalf("unmarshal ownership: %v", err)
	}
	return val.GatewayID, val.NodeID
}

// TestClaimDeadIdlePreservesNonEmptyPlacementE2E guards the OTHER direction of
// the dead-idle takeover placement rule: a record with a NON-empty placement
// (on a node whose presence key is gone — provably released) must keep that
// placement across the takeover, even though the claim carries a different
// candidate. The node remains the right affinity and re-placement costs an
// etcd write; overwriting it with the candidate would churn affinity on every
// dead-owner takeover.
func TestClaimDeadIdlePreservesNonEmptyPlacementE2E(t *testing.T) {
	suf := time.Now().Format("150405.000000")
	deadOwner := "gw-dead-preserve-" + suf
	claimerID := "gw-claimer-preserve-" + suf
	sandfsID := "sandfs-deadpreserve-" + suf
	const oldNode = "node-old-placement"
	const candidateNode = "node-different-candidate"

	cli := stalenessEtcdClient(t)
	ctx := context.Background()
	// Seed: PLACED record (node_id = oldNode) owned by deadOwner. No presence
	// key for oldNode → nodePresenceGone true → time-guarded claim path.
	putOwnershipRaw(t, cli, sandfsID, deadOwner, oldNode, 1)
	t.Cleanup(func() {
		cli.Delete(ctx, ownershipPrefix+sandfsID)
		cli.Delete(ctx, healthPrefix+deadOwner)
	})

	oc := newStalenessCache(t, claimerID, nil)
	oc.SetCacheTTLForTest(time.Second)             // test opts out of the TTL≤2×guard production pair-check
	oc.SetStalenessThresholds(0, 2*time.Second, 0) // claim-dead guard = 2s

	// Within the guard → tolerate.
	if _, err := oc.Claim(sandfsID, candidateNode); err != ErrOwnershipConflict {
		t.Fatalf("within guard: Claim err = %v, want ErrOwnershipConflict", err)
	}

	// Past the guard → takeover succeeds, ownership transfers, but the
	// NON-empty placement is PRESERVED (candidate must NOT overwrite it).
	time.Sleep(2500 * time.Millisecond)
	if _, err := oc.Claim(sandfsID, candidateNode); err != nil {
		t.Fatalf("past guard: Claim err = %v, want nil (takeover)", err)
	}
	owner, placedNode := ownerGwAndNode(t, cli, sandfsID)
	if owner != claimerID {
		t.Fatalf("past guard: owner = %q, want %q (takeover)", owner, claimerID)
	}
	if placedNode != oldNode {
		t.Fatalf("past guard: node_id = %q, want %q (non-empty placement must be preserved, not replaced by candidate %q)", placedNode, oldNode, candidateNode)
	}
}

// TestClaimDeadIdleTimeGuardE2E verifies the time-protected CAS claim for a
// dead-owned IDLE sandfs: within the claim-dead-guard window a peer tolerates
// (ErrOwnershipConflict, ownership unchanged); once the guard elapses (owner
// still dead) the peer CAS-takes-over. Also verifies owner revival clears the
// clock (no premature takeover) and restarts a fresh window on a later death.
func TestClaimDeadIdleTimeGuardE2E(t *testing.T) {
	suf := time.Now().Format("150405.000000")
	deadOwner := "gw-dead-idle-" + suf
	claimerID := "gw-claimer-" + suf
	sandfsID := "sandfs-deadidle-" + suf

	cli := stalenessEtcdClient(t)
	ctx := context.Background()
	// Seed: idle sandfs owned by deadOwner (no health key → ownerDead true).
	putOwnershipRaw(t, cli, sandfsID, deadOwner, "", 1)
	t.Cleanup(func() {
		cli.Delete(ctx, ownershipPrefix+sandfsID)
		cli.Delete(ctx, healthPrefix+deadOwner)
	})

	oc := newStalenessCache(t, claimerID, nil)
	oc.SetCacheTTLForTest(time.Second)             // test opts out of the TTL≤2×guard production pair-check
	oc.SetStalenessThresholds(0, 2*time.Second, 0) // claim-dead guard = 2s

	// Pass 1: within the guard → ErrOwnershipConflict, ownership unchanged.
	if _, err := oc.Claim(sandfsID, ""); err != ErrOwnershipConflict {
		t.Fatalf("within guard: Claim err = %v, want ErrOwnershipConflict", err)
	}
	if owner := ownerGwID(t, cli, sandfsID); owner != deadOwner {
		t.Fatalf("within guard: ownership changed to %q, want still %q", owner, deadOwner)
	}
	// deadSince was seeded.
	oc.deadSinceMu.Lock()
	_, seeded := oc.deadSince[sandfsID]
	oc.deadSinceMu.Unlock()
	if !seeded {
		t.Fatal("within guard: deadSince clock not seeded")
	}

	// Pass 2: wait past the guard → CAS takeover succeeds, ownership transfers.
	time.Sleep(2500 * time.Millisecond)
	if _, err := oc.Claim(sandfsID, ""); err != nil {
		t.Fatalf("past guard: Claim err = %v, want nil (takeover)", err)
	}
	if owner := ownerGwID(t, cli, sandfsID); owner != claimerID {
		t.Fatalf("past guard: owner = %q, want %q (takeover)", owner, claimerID)
	}
	// deadSince cleared on successful takeover.
	oc.deadSinceMu.Lock()
	_, stillSeeded := oc.deadSince[sandfsID]
	oc.deadSinceMu.Unlock()
	if stillSeeded {
		t.Fatal("past guard: deadSince not cleared after takeover")
	}
}

// TestClaimDeadIdleRevivalClearsClockE2E verifies that if a dead owner revives
// within the guard window, the death clock is cleared and no takeover happens
// (the owner recovered); a subsequent death starts a fresh guard window.
func TestClaimDeadIdleRevivalClearsClockE2E(t *testing.T) {
	suf := time.Now().Format("150405.000000")
	deadOwner := "gw-revive-" + suf
	claimerID := "gw-claimer-rev-" + suf
	sandfsID := "sandfs-revive-" + suf

	cli := stalenessEtcdClient(t)
	ctx := context.Background()
	putOwnershipRaw(t, cli, sandfsID, deadOwner, "", 1)
	t.Cleanup(func() {
		cli.Delete(ctx, ownershipPrefix+sandfsID)
		cli.Delete(ctx, healthPrefix+deadOwner)
	})

	oc := newStalenessCache(t, claimerID, nil)
	oc.SetCacheTTLForTest(time.Second)             // test opts out of the TTL≤2×guard production pair-check
	oc.SetStalenessThresholds(0, 3*time.Second, 0) // guard = 3s

	// Pass 1: dead owner → seed clock, tolerate.
	if _, err := oc.Claim(sandfsID, ""); err != ErrOwnershipConflict {
		t.Fatalf("pass 1: err = %v, want ErrOwnershipConflict", err)
	}

	// Owner revives (fresh health key) before the guard elapses.
	putHealthWithTS(t, cli, deadOwner, time.Now().Format(time.RFC3339))
	// Pass 2: owner alive → tolerate, NO takeover, clock cleared.
	if _, err := oc.Claim(sandfsID, ""); err != ErrOwnershipConflict {
		t.Fatalf("pass 2 (owner revived): err = %v, want ErrOwnershipConflict", err)
	}
	if owner := ownerGwID(t, cli, sandfsID); owner != deadOwner {
		t.Fatalf("pass 2: ownership changed to %q, want still %q", owner, deadOwner)
	}
	oc.deadSinceMu.Lock()
	_, seeded := oc.deadSince[sandfsID]
	oc.deadSinceMu.Unlock()
	if seeded {
		t.Fatal("pass 2: deadSince not cleared after owner revival")
	}

	// Owner dies again → fresh guard window starts (must wait the FULL guard,
	// not the remainder of the old one). Kill the health key and immediately
	// Claim: should still tolerate (fresh window just seeded).
	cli.Delete(ctx, healthPrefix+deadOwner)
	if _, err := oc.Claim(sandfsID, ""); err != ErrOwnershipConflict {
		t.Fatalf("pass 3 (re-dead, fresh window): err = %v, want ErrOwnershipConflict", err)
	}
	if owner := ownerGwID(t, cli, sandfsID); owner != deadOwner {
		t.Fatalf("pass 3: ownership changed to %q, want still %q (fresh window not elapsed)", owner, deadOwner)
	}
}

// ownerGwID reads the ownership key's gateway_id for a sandfs.
func ownerGwID(t *testing.T, cli *clientv3.Client, sandfsID string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	resp, err := cli.Get(ctx, ownershipPrefix+sandfsID)
	if err != nil || len(resp.Kvs) == 0 {
		t.Fatalf("get ownership %s: err=%v kvs=%d", sandfsID, err, len(resp.Kvs))
	}
	var val OwnershipValue
	if err := json.Unmarshal(resp.Kvs[0].Value, &val); err != nil {
		t.Fatalf("unmarshal ownership: %v", err)
	}
	return val.GatewayID
}

// TestReapStuckOwnershipE2E verifies the manual both-dead reclamation tool
// against a real etcd: idle sandfs of a dead owner are reaped; mounted sandfs
// are reaped only if the node's presence key is gone (else skipped); dry-run
// reports without deleting; a live owner is refused.
func TestReapStuckOwnershipE2E(t *testing.T) {
	suf := time.Now().Format("150405.000000")
	deadOwner := "gw-reap-dead-" + suf
	claimerID := "gw-reap-self-" + suf
	nodeAlive := "node-reap-alive-" + suf // mounted, presence still present → skip
	nodeGone := "node-reap-gone-" + suf   // mounted, presence absent → reap
	idle1 := "sandfs-reap-idle1-" + suf
	idle2 := "sandfs-reap-idle2-" + suf
	mountedAlive := "sandfs-reap-mounted-alive-" + suf
	mountedGone := "sandfs-reap-mounted-gone-" + suf

	cli := stalenessEtcdClient(t)
	ctx := context.Background()
	// Seed: dead owner owns 2 idle + 2 mounted sandfs. No health key → dead.
	putOwnershipRaw(t, cli, idle1, deadOwner, "", 1)
	putOwnershipRaw(t, cli, idle2, deadOwner, "", 1)
	putOwnershipRaw(t, cli, mountedAlive, deadOwner, nodeAlive, 1)
	putOwnershipRaw(t, cli, mountedGone, deadOwner, nodeGone, 1)
	// nodeAlive presence present; nodeGone presence absent.
	cli.Put(ctx, presencePrefix+nodeAlive+"/presence", deadOwner)
	t.Cleanup(func() {
		for _, sf := range []string{idle1, idle2, mountedAlive, mountedGone} {
			cli.Delete(ctx, ownershipPrefix+sf)
		}
		cli.Delete(ctx, presencePrefix+nodeAlive+"/presence")
		cli.Delete(ctx, healthPrefix+deadOwner)
	})

	oc := newStalenessCache(t, claimerID, nil)

	// Dry-run: reports idle1+idle2+mountedGone as reaped (3), mountedAlive skipped (1).
	rep, err := oc.ReapStuckOwnership(ctx, deadOwner, true, 10)
	if err != nil {
		t.Fatalf("dry-run ReapStuckOwnership: %v", err)
	}
	if rep.ReapedCount != 3 || rep.SkippedCount != 1 {
		t.Fatalf("dry-run report: reaped=%d skipped=%d, want 3/1 (report=%+v)", rep.ReapedCount, rep.SkippedCount, rep)
	}
	// Nothing actually deleted in dry-run.
	for _, sf := range []string{idle1, idle2, mountedAlive, mountedGone} {
		if !ownsKey(t, cli, sf) {
			t.Errorf("dry-run deleted %s (should only report)", sf)
		}
	}

	// Real run: deletes idle1+idle2+mountedGone; mountedAlive survives.
	rep, err = oc.ReapStuckOwnership(ctx, deadOwner, false, 10)
	if err != nil {
		t.Fatalf("ReapStuckOwnership: %v", err)
	}
	if rep.ReapedCount != 3 {
		t.Fatalf("reaped=%d, want 3 (report=%+v)", rep.ReapedCount, rep)
	}
	for _, sf := range []string{idle1, idle2, mountedGone} {
		if ownsKey(t, cli, sf) {
			t.Errorf("reaped key %s still present", sf)
		}
	}
	if !ownsKey(t, cli, mountedAlive) {
		t.Error("mountedAlive (presence present) was reaped — must be skipped")
	}

	// Live owner is refused.
	liveOwner := "gw-reap-live-" + suf
	putHealthWithTS(t, cli, liveOwner, time.Now().Format(time.RFC3339))
	putOwnershipRaw(t, cli, "sandfs-reap-live-1-"+suf, liveOwner, "", 1)
	t.Cleanup(func() {
		cli.Delete(ctx, healthPrefix+liveOwner)
		cli.Delete(ctx, ownershipPrefix+"sandfs-reap-live-1-"+suf)
	})
	if _, err := oc.ReapStuckOwnership(ctx, liveOwner, false, 10); err == nil {
		t.Fatal("ReapStuckOwnership on a LIVE owner must error (refuse to reap live owner)")
	}
}

// ownsKey reports whether an ownership key exists for a sandfs.
func ownsKey(t *testing.T, cli *clientv3.Client, sandfsID string) bool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	resp, err := cli.Get(ctx, ownershipPrefix+sandfsID)
	if err != nil {
		t.Fatalf("get ownership %s: %v", sandfsID, err)
	}
	return len(resp.Kvs) > 0
}

// TestReapStuckNodeOwnershipE2E verifies the node-granularity manual
// reclamation tool against a real etcd: a dead node's mounted sandfs (with dead
// owners) are reaped; sandfs whose owner is still alive are skipped; a node
// whose presence key is still present is refused (live node).
func TestReapStuckNodeOwnershipE2E(t *testing.T) {
	suf := time.Now().Format("150405.000000")
	deadOwner := "gw-node-dead-" + suf
	liveOwner := "gw-node-live-" + suf
	claimerID := "gw-node-self-" + suf
	nodeGone := "node-gone-" + suf   // presence absent → eligible
	nodeAlive := "node-alive-" + suf // presence present → whole call refused
	mountedDead := "sandfs-node-mounted-dead-" + suf
	mountedLive := "sandfs-node-mounted-live-" + suf

	cli := stalenessEtcdClient(t)
	ctx := context.Background()
	// Dead owner: one mounted sandfs on nodeGone.
	putOwnershipRaw(t, cli, mountedDead, deadOwner, nodeGone, 1)
	// Live owner: one mounted sandfs on nodeGone (must be skipped).
	putHealthWithTS(t, cli, liveOwner, time.Now().Format(time.RFC3339))
	putOwnershipRaw(t, cli, mountedLive, liveOwner, nodeGone, 1)
	// nodeGone presence absent; nodeAlive presence present.
	t.Cleanup(func() {
		cli.Delete(ctx, ownershipPrefix+mountedDead)
		cli.Delete(ctx, ownershipPrefix+mountedLive)
		cli.Delete(ctx, healthPrefix+deadOwner)
		cli.Delete(ctx, healthPrefix+liveOwner)
		cli.Delete(ctx, presencePrefix+nodeGone+"/presence")
		cli.Delete(ctx, presencePrefix+nodeAlive+"/presence")
	})

	oc := newStalenessCache(t, claimerID, nil)

	// Dry-run on nodeGone: mountedDead reaped (1), mountedLive skipped (1).
	rep, err := oc.ReapStuckNodeOwnership(ctx, nodeGone, true, 10)
	if err != nil {
		t.Fatalf("dry-run ReapStuckNodeOwnership: %v", err)
	}
	if rep.ReapedCount != 1 || rep.SkippedCount != 1 {
		t.Fatalf("dry-run report: reaped=%d skipped=%d, want 1/1 (report=%+v)", rep.ReapedCount, rep.SkippedCount, rep)
	}
	for _, sf := range []string{mountedDead, mountedLive} {
		if !ownsKey(t, cli, sf) {
			t.Errorf("dry-run deleted %s (should only report)", sf)
		}
	}

	// Real run on nodeGone: deletes mountedDead; mountedLive survives (live owner).
	rep, err = oc.ReapStuckNodeOwnership(ctx, nodeGone, false, 10)
	if err != nil {
		t.Fatalf("ReapStuckNodeOwnership: %v", err)
	}
	if rep.ReapedCount != 1 {
		t.Fatalf("reaped=%d, want 1 (report=%+v)", rep.ReapedCount, rep)
	}
	if ownsKey(t, cli, mountedDead) {
		t.Error("mountedDead (dead owner, node gone) was not reaped")
	}
	if !ownsKey(t, cli, mountedLive) {
		t.Error("mountedLive (live owner) was reaped — must be skipped")
	}

	// Live node (presence present) → refused.
	cli.Put(ctx, presencePrefix+nodeAlive+"/presence", deadOwner)
	putOwnershipRaw(t, cli, "sandfs-node-alive-1-"+suf, deadOwner, nodeAlive, 1)
	t.Cleanup(func() { cli.Delete(ctx, ownershipPrefix+"sandfs-node-alive-1-"+suf) })
	if _, err := oc.ReapStuckNodeOwnership(ctx, nodeAlive, false, 10); err == nil {
		t.Fatal("ReapStuckNodeOwnership on a LIVE node (presence present) must error")
	}
}

// putOwnershipCorrupt seeds an ownership key with non-JSON bytes (ops-written
// key, truncated write, foreign format) — the input that used to drive the
// deterministic claimFromEtcd ↔ createOwnership infinite cycle.
func putOwnershipCorrupt(t *testing.T, cli *clientv3.Client, sandfsID string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := cli.Put(ctx, ownershipPrefix+sandfsID, "{not-json"); err != nil {
		t.Fatalf("put corrupt ownership %s: %v", sandfsID, err)
	}
}

// TestClaimCorruptValueOverwriteE2E pins the bounded-claim fix: a corrupt
// ownership value must be overwritten via the ModRevision CAS (never retried
// forever — the old createOwnership Version==0 CAS can never succeed on an
// existing key, so the recursive shape looped indefinitely and stack-overflowed
// the gateway). The claim must return quickly, leave valid ownership behind,
// and clear the death clock.
func TestClaimCorruptValueOverwriteE2E(t *testing.T) {
	suf := time.Now().Format("150405.000000")
	sandfsID := "sandfs-corrupt-" + suf
	claimerID := "gw-corrupt-" + suf

	cli := stalenessEtcdClient(t)
	ctx := context.Background()
	putOwnershipCorrupt(t, cli, sandfsID)
	t.Cleanup(func() {
		cli.Delete(ctx, ownershipPrefix+sandfsID)
	})

	oc := newStalenessCache(t, claimerID, nil)

	// The bug was a hang (unbounded recursion → goroutine stack overflow), so
	// the claim MUST fail fast: bound it at 5s and fail the test if it hangs.
	type result struct {
		node string
		err  error
	}
	resCh := make(chan result, 1)
	go func() {
		node, err := oc.Claim(sandfsID, "")
		resCh <- result{node, err}
	}()
	select {
	case res := <-resCh:
		if res.err != nil && res.err != ErrClaimRetryExhausted {
			t.Fatalf("Claim on corrupt value: err = %v", res.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Claim on corrupt value hung — unbounded recursion is back")
	}

	// The key must now hold OUR valid record with a sane generation.
	ctx2, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	resp, err := cli.Get(ctx2, ownershipPrefix+sandfsID)
	if err != nil || len(resp.Kvs) == 0 {
		t.Fatalf("get ownership after claim: err=%v kvs=%d", err, len(resp.Kvs))
	}
	var val OwnershipValue
	if err := json.Unmarshal(resp.Kvs[0].Value, &val); err != nil {
		t.Fatalf("ownership still corrupt after claim: %v", err)
	}
	if val.GatewayID != claimerID {
		t.Errorf("owner = %q, want %q", val.GatewayID, claimerID)
	}
	if val.Generation < 1 {
		t.Errorf("generation = %d, want >= 1", val.Generation)
	}

	// Death clock must be clear (clearDeadSince ran before the overwrite).
	oc.deadSinceMu.Lock()
	_, seen := oc.deadSince[sandfsID]
	oc.deadSinceMu.Unlock()
	if seen {
		t.Error("death clock still seeded for a sandfs we now own")
	}

	// Second Claim on the now-valid key: no error, no churn (generation
	// unchanged — we must not re-claim over our own record).
	genBefore := val.Generation
	// Evict the cache so the slow path re-reads etcd.
	oc.mu.Lock()
	delete(oc.cache, sandfsID)
	oc.mu.Unlock()
	if _, err := oc.Claim(sandfsID, ""); err != nil {
		t.Fatalf("second Claim: err = %v", err)
	}
	resp2, err := cli.Get(ctx2, ownershipPrefix+sandfsID)
	if err != nil || len(resp2.Kvs) == 0 {
		t.Fatalf("get ownership after second claim: err=%v", err)
	}
	var val2 OwnershipValue
	if err := json.Unmarshal(resp2.Kvs[0].Value, &val2); err != nil {
		t.Fatalf("unmarshal after second claim: %v", err)
	}
	if val2.Generation != genBefore {
		t.Errorf("generation churned %d → %d on a stable key", genBefore, val2.Generation)
	}
}

// TestClaimNoOwnerRacesE2E: two gateways racing to claim the same absent key —
// exactly one create CAS wins; the loser's CAS loses, the loop re-reads into
// the winner's record and returns the normal conflict (503+retry semantics),
// never ErrClaimRetryExhausted and never a hang (pins the CAS-lost → retry →
// converge path without unbounded growth).
func TestClaimNoOwnerRacesE2E(t *testing.T) {
	suf := time.Now().Format("150405.000000")
	cli := stalenessEtcdClient(t)
	ctx := context.Background()

	for i := 0; i < 10; i++ {
		sandfsID := fmt.Sprintf("sandfs-race-%s-%d", suf, i)
		ocA := newStalenessCache(t, "gw-race-a-"+suf, nil)
		ocB := newStalenessCache(t, "gw-race-b-"+suf, nil)
		t.Cleanup(func() { cli.Delete(ctx, ownershipPrefix+sandfsID) })

		type res struct {
			node string
			err  error
		}
		chA := make(chan res, 1)
		chB := make(chan res, 1)
		go func() { n, e := ocA.Claim(sandfsID, ""); chA <- res{n, e} }()
		go func() { n, e := ocB.Claim(sandfsID, ""); chB <- res{n, e} }()
		ra, rb := <-chA, <-chB

		wins, losses := 0, 0
		for name, r := range map[string]res{"A": ra, "B": rb} {
			if r.err == ErrClaimRetryExhausted {
				t.Fatalf("iter %d: %s burned the retry budget on a simple race", i, name)
			}
			switch r.err {
			case nil:
				wins++
			case ErrOwnershipConflict, ErrShedCooldown:
				// Loser: tolerates and lets the client retry/redirect. The
				// dead-owner idle path may also fire when the winner has no
				// health key (test caches don't run StartHealthLoop) — still
				// an ErrOwnershipConflict while the 45s claim-dead guard runs.
				losses++
			default:
				t.Fatalf("iter %d: %s Claim err = %v", i, name, r.err)
			}
		}
		if wins != 1 || losses != 1 {
			t.Fatalf("iter %d: want exactly one winner, got wins=%d losses=%d", i, wins, losses)
		}
		if owner := ownerGwID(t, cli, sandfsID); owner != "gw-race-a-"+suf && owner != "gw-race-b-"+suf {
			t.Fatalf("iter %d: owner = %q, want one of the racers", i, owner)
		}
	}
}

// TestReapDeleteCAS_SkipsMovedRecord pins the reap race guard: a blind Delete could remove an ownership record a LIVE gateway
// CAS-claimed between the reaper's scan and its delete — an idle dead-owned
// sandfs is claimable by any gateway after the claim-dead guard, which is
// exactly the retrying-client pattern around a dead owner — re-opening the
// sandfs to a second claim (dual mount). The delete must CAS on the scanned
// ModRevision and leave a moved record untouched.
func TestReapDeleteCAS_SkipsMovedRecord(t *testing.T) {
	suf := time.Now().Format("150405.000000")
	sf := "sandfs-reapcas-" + suf
	deadOwner := "gw-reapcas-dead-" + suf
	liveOwner := "gw-reapcas-live-" + suf

	cli := stalenessEtcdClient(t)
	ctx := context.Background()
	putOwnershipRaw(t, cli, sf, deadOwner, "", 1)
	t.Cleanup(func() { cli.Delete(ctx, ownershipPrefix+sf) })

	oc := newStalenessCache(t, "gw-reapcas-self-"+suf, nil)

	// Scan revision.
	resp, err := cli.Get(ctx, ownershipPrefix+sf)
	if err != nil || len(resp.Kvs) == 0 {
		t.Fatalf("get ownership: err=%v kvs=%d", err, len(resp.Kvs))
	}
	scannedRev := resp.Kvs[0].ModRevision

	// A live gateway CAS-claims the record between scan and delete.
	putOwnershipRaw(t, cli, sf, liveOwner, "", 1)

	deleted, err := oc.reapDeleteCAS(ctx, sf, scannedRev)
	if err != nil {
		t.Fatalf("reapDeleteCAS: %v", err)
	}
	if deleted {
		t.Fatal("reapDeleteCAS deleted a record that moved on since the scan — live owner's record destroyed")
	}
	if got := ownerGwID(t, cli, sf); got != liveOwner {
		t.Fatalf("record owner = %q, want the live claimant %q (record must survive)", got, liveOwner)
	}

	// And with the CURRENT revision it deletes (the normal path still works).
	resp, err = cli.Get(ctx, ownershipPrefix+sf)
	if err != nil || len(resp.Kvs) == 0 {
		t.Fatalf("re-get ownership: err=%v", err)
	}
	deleted, err = oc.reapDeleteCAS(ctx, sf, resp.Kvs[0].ModRevision)
	if err != nil {
		t.Fatalf("reapDeleteCAS (current rev): %v", err)
	}
	if !deleted {
		t.Fatal("reapDeleteCAS refused an unchanged record — the normal reap path is broken")
	}
}

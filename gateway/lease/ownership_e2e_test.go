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

package lease_test

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	pb "common/proto/stream"
	"gateway/identity"
	"gateway/lease"

	clientv3 "go.etcd.io/etcd/client/v3"
)

// etcdEndpoint is the plain-http etcd the tagged ownership e2e drives
// (e2e/ownership.sh starts its own on 2379). Overridable for the same reason
// as stalenessEtcdEndpoint: a deployed mTLS etcd squatting on 2379 on a dev
// host otherwise makes every client call hang (plain HTTP against a TLS
// listener) — SANDSWAP_TEST_ETCD_ENDPOINT=http://127.0.0.1:12379 go test ...
var etcdEndpoint = func() string {
	if v := os.Getenv("SANDSWAP_TEST_ETCD_ENDPOINT"); v != "" {
		return v
	}
	return "http://127.0.0.1:2379"
}()

func newEtcdClient(t *testing.T) *clientv3.Client {
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

func newTestStore(t *testing.T) *identity.EtcdStore {
	t.Helper()
	prefix := fmt.Sprintf("/sandswap-test-%d/", time.Now().UnixNano())
	store, err := identity.NewEtcdStore([]string{etcdEndpoint}, prefix, "/tmp/nonexistent-volroot", nil, slog.Default())
	if err != nil {
		t.Fatalf("NewEtcdStore: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

func newTestOwnershipCache(t *testing.T, gatewayID string) *lease.OwnershipCache {
	t.Helper()
	cli := newEtcdClient(t)
	oc, err := lease.NewOwnershipCache(cli, gatewayID, nil, slog.Default())
	if err != nil {
		t.Fatalf("NewOwnershipCache: %v", err)
	}
	t.Cleanup(func() { oc.Close() })
	// streamSrv is nil here → the default node_count would be 0 (fault state).
	// These tests simulate a healthy compute-present gateway, so report node_count 1.
	oc.SetNodeCountFunc(func() int { return 1 })
	oc.StartHealthLoop()
	oc.StartWatch()
	// Mirror the exec-gateway wiring: the owner-release sweep is started
	// explicitly there (never by the constructor).
	oc.StartOwnerReleaseSweep()
	return oc
}

// TestClaimRefreshPreservesDispatching pins the slow-path Claim contract: an
// entry refreshed from etcd while a mount is in flight must keep the
// dispatching flag, or the owner-release sweep and load shedding can delete
// the record under the live mount.
func TestClaimRefreshPreservesDispatching(t *testing.T) {
	cli := newEtcdClient(t)
	oc, err := lease.NewOwnershipCache(cli, "gw-dispatch", nil, slog.Default())
	if err != nil {
		t.Fatalf("NewOwnershipCache: %v", err)
	}
	t.Cleanup(func() { oc.Close() })
	oc.SetNodeCountFunc(func() int { return 1 }) // healthy compute-present gateway
	oc.SetCacheTTLForTest(time.Millisecond)

	id := fmt.Sprintf("sandfs-dispatch-%d", time.Now().UnixNano())
	key := lease.OwnershipKeyForTest(id)
	t.Cleanup(func() { _, _ = cli.Delete(context.Background(), key) })
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	val, _ := json.Marshal(lease.OwnershipValue{GatewayID: "gw-dispatch", NodeID: "node-a", Generation: 1})
	if _, err := cli.Put(ctx, key, string(val)); err != nil {
		t.Fatalf("seed record: %v", err)
	}

	oc.SetOwnedForTest(id, "node-a")
	if _, err := oc.BeginDispatch(id); err != nil {
		t.Fatalf("BeginDispatch: %v", err)
	}
	time.Sleep(5 * time.Millisecond) // force the slow path past the cache TTL

	if _, err := oc.Claim(id, ""); err != nil {
		t.Fatalf("slow-path Claim: %v", err)
	}
	if !oc.Dispatching(id) {
		t.Fatal("slow-path Claim refresh dropped the in-flight mount flag")
	}
	oc.EndDispatch(id)
}

// ── Test 1: CAS claim — first gateway wins, second gets conflict ──
func TestCASClaim(t *testing.T) {
	oc1 := newTestOwnershipCache(t, "gw-1")
	oc2 := newTestOwnershipCache(t, "gw-2")

	sandfsID := "sandfs-cas-test"

	_, err := oc1.Claim(sandfsID, "")
	if err != nil {
		t.Fatalf("gw-1 Claim: %v", err)
	}

	_, err = oc2.Claim(sandfsID, "")
	if err != lease.ErrOwnershipConflict {
		t.Fatalf("expected ErrOwnershipConflict, got: %v", err)
	}
}

// ── Test 2: ownership has NO lease — it persists across the owner's death ──
func TestOwnershipNoLeasePersists(t *testing.T) {
	oc1 := newTestOwnershipCache(t, "gw-nolease-1")
	sandfsID := "sandfs-nolease"

	if _, err := oc1.Claim(sandfsID, ""); err != nil {
		t.Fatalf("gw-1 Claim: %v", err)
	}

	// The ownership key must be a plain (no-lease) key.
	cli := newEtcdClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := cli.Get(ctx, "/sandswap/owner/"+sandfsID)
	if err != nil || len(resp.Kvs) == 0 {
		t.Fatal("ownership key missing after claim")
	}
	if resp.Kvs[0].Lease != 0 {
		t.Fatalf("ownership key has lease %d — requires a plain (no-lease) key", resp.Kvs[0].Lease)
	}

	// "Death": gw-1 closes. Nothing expires the key (no lease), so it persists.
	oc1.Close()
	time.Sleep(2 * time.Second)
	resp, err = cli.Get(ctx, "/sandswap/owner/"+sandfsID)
	if err != nil || len(resp.Kvs) == 0 {
		t.Fatal("ownership key vanished after owner Close — keys must persist (no lease)")
	}
}

// TestMigratedTakeoverBlocked verifies migrated takeover's tolerance branch: gw-1 owns a
// sandfs on node N and dies. gw-2 has no node N connected to it (no stream server)
// → migrated-takeover not satisfied → 503 (ErrOwnershipConflict). Ownership is NOT moved on the
// owner's death alone — switching needs a confirmed condition (node migration, or
// the owner's own owner-release release).
func TestMigratedTakeoverBlocked(t *testing.T) {
	// Clean slate: remove keys left by a previous run.
	cli0 := newEtcdClient(t)
	cctx, ccancel := context.WithTimeout(context.Background(), 5*time.Second)
	cli0.Delete(cctx, "/sandswap/owner/sandfs-b2")
	cli0.Delete(cctx, "/sandswap/health/gw-b2-1")
	cli0.Delete(cctx, "/sandswap/health/gw-b2-2")
	cli0.Delete(cctx, "/sandswap/node/node-b2/presence")
	ccancel()

	oc1 := newTestOwnershipCache(t, "gw-b2-1")
	oc2 := newTestOwnershipCache(t, "gw-b2-2")
	sandfsID := "sandfs-b2"

	if _, err := oc1.Claim(sandfsID, ""); err != nil {
		t.Fatalf("gw-1 Claim: %v", err)
	}
	oc1.NoteMounted(sandfsID, "node-b2")
	oc1.Close() // gw-1 dies

	// The health key has NO lease — it stays behind with a frozen
	// last_healthy_ts. Death is judged by staleness, so shrink gw-2's
	// claim-dead guard and wait past it (gw-1's last health write can lag its
	// Close by up to the 5s refresh interval).
	oc2.SetCacheTTLForTest(time.Second) // test opts out of the TTL≤2×guard production pair-check
	oc2.SetStalenessThresholds(0, 2*time.Second, 0)
	time.Sleep(6 * time.Second)

	// gw-2 has no local node N → migrated-takeover blocked → tolerate (conflict).
	_, err := oc2.Claim(sandfsID, "")
	if err != lease.ErrOwnershipConflict {
		t.Fatalf("expected ErrOwnershipConflict (migrated-takeover blocked: no migrated node), got %v", err)
	}
}

// TestMigratedTakeoverAfterMigration verifies migrated takeover's takeover branch end-to-end
// against etcd: gw-1 owns a sandfs on node N and dies; N migrates to gw-2 (live
// stream + gw-2's presence key) → gw-2 force-takes-over the ownership.
func TestMigratedTakeoverAfterMigration(t *testing.T) {
	// Clean slate: remove keys left by a previous run of this test (the migrated-takeover
	// takeover leaves the sandfs owned by gw-b2m-2, which would otherwise look
	// like a pre-existing owner to a fresh gw-b2m-1).
	cli0 := newEtcdClient(t)
	cctx, ccancel := context.WithTimeout(context.Background(), 5*time.Second)
	cli0.Delete(cctx, "/sandswap/owner/sandfs-b2m")
	cli0.Delete(cctx, "/sandswap/health/gw-b2m-1")
	cli0.Delete(cctx, "/sandswap/health/gw-b2m-2")
	cli0.Delete(cctx, "/sandswap/node/node-b2m/presence")
	ccancel()

	oc1 := newTestOwnershipCache(t, "gw-b2m-1")
	oc2 := newTestOwnershipCache(t, "gw-b2m-2")
	sandfsID := "sandfs-b2m"

	if _, err := oc1.Claim(sandfsID, ""); err != nil {
		t.Fatalf("gw-1 Claim: %v", err)
	}
	oc1.NoteMounted(sandfsID, "node-b2m")
	oc1.Close() // gw-1 dies

	// The health key has NO lease — it stays behind with a frozen
	// last_healthy_ts. Death is judged by staleness, so shrink gw-2's
	// claim-dead guard and wait past it (gw-1's last health write can lag its
	// Close by up to the 5s refresh interval).
	oc2.SetCacheTTLForTest(time.Second) // test opts out of the TTL≤2×guard production pair-check
	oc2.SetStalenessThresholds(0, 2*time.Second, 0)
	time.Sleep(6 * time.Second)

	// N "migrates" to gw-2: live stream (test hook) + presence key owned by gw-2.
	oc2.SetNodeConnectedForTest(func(nodeID string) bool { return nodeID == "node-b2m" })
	oc2.OnNodeConnect("node-b2m", &pb.NodeTiming{ToleranceSec: 5, WardenCountdownSec: 5, IsolationSec: 120})

	if _, err := oc2.Claim(sandfsID, ""); err != nil {
		t.Fatalf("migrated takeover: gw-2 should force-take-over after node migration, got %v", err)
	}

	// Verify the ownership is now gw-2's.
	cli := newEtcdClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	resp, err := cli.Get(ctx, "/sandswap/owner/"+sandfsID)
	if err != nil || len(resp.Kvs) == 0 {
		t.Fatal("ownership key missing after migrated takeover takeover")
	}
	var ov lease.OwnershipValue
	if err := json.Unmarshal(resp.Kvs[0].Value, &ov); err != nil {
		t.Fatalf("unmarshal ownership: %v", err)
	}
	if ov.GatewayID != "gw-b2m-2" {
		t.Fatalf("migrated takeover takeover: owner = %q, want gw-b2m-2", ov.GatewayID)
	}
}

// ── Test 3: Watch conflict — external etcd write invalidates cache ──
func TestWatchConflict(t *testing.T) {
	oc1 := newTestOwnershipCache(t, "gw-watch-1")

	sandfsID := "sandfs-watch-test"

	// Clean up stale no-lease keys from a previous run. The external gw-external
	// ownership written below has no lease and persists across runs; without this,
	// the first Claim would hit the stale key and, with the dead-owner wait logic,
	// return ErrOwnershipConflict instead of claiming.
	{
		c := newEtcdClient(t)
		cctx, ccancel := context.WithTimeout(context.Background(), 5*time.Second)
		c.Delete(cctx, "/sandswap/owner/"+sandfsID)
		c.Delete(cctx, "/sandswap/health/gw-external")
		ccancel()
	}

	_, err := oc1.Claim(sandfsID, "")
	if err != nil {
		t.Fatalf("gw-1 Claim: %v", err)
	}

	// Simulate another gateway writing to etcd directly. The external gateway is
	// ALIVE (health key present) → the owner keeps the sandfs; we tolerate
	// (ErrOwnershipConflict). Health expiry alone never triggers a transfer.
	cli := newEtcdClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Write health key for the external gateway (alive with compute).
	healthKey := "/sandswap/health/gw-external"
	healthVal, _ := json.Marshal(lease.GatewayHealthValue{
		LastHealthyTS: time.Now().Format(time.RFC3339),
		NodeCount:     1,
	})
	// The health key is a plain key (no lease) — a live gateway just refreshes
	// its value; absence only means the owner never wrote it.
	if _, err := cli.Put(ctx, healthKey, string(healthVal)); err != nil {
		t.Fatalf("put health key: %v", err)
	}

	// Write ownership for the external gateway.
	key := "/sandswap/owner/" + sandfsID
	val := lease.OwnershipValue{GatewayID: "gw-external", NodeID: "", Generation: 99}
	data, _ := json.Marshal(val)
	_, err = cli.Put(ctx, key, string(data))
	if err != nil {
		t.Fatalf("external put: %v", err)
	}

	// Wait for watch to deliver the event.
	time.Sleep(2 * time.Second)

	_, err = oc1.Claim(sandfsID, "")
	if err != lease.ErrOwnershipConflict {
		t.Fatalf("expected conflict after external write, got: %v", err)
	}
}

// ── Test 3b: ALIVE-but-fault owner is tolerated (no fault takeover) ──
// tolerance-first: an owner that is ALIVE but compute-less (health key present,
// node_count==0) is NOT taken over. The agent 503s + retries; the owner may
// recover, or owner-release / migrated takeover release later under a confirmed condition. Ownership is never
// moved on a fault signal alone.
func TestFaultStateOwnerTolerated(t *testing.T) {
	oc := newTestOwnershipCache(t, "gw-fault-tol")
	cli := newEtcdClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sandfsID := "sandfs-fault-tolerate"

	// External gateway "gw-fault" owns it and is ALIVE but compute-less.
	val := lease.OwnershipValue{GatewayID: "gw-fault", NodeID: "", Generation: 1}
	data, _ := json.Marshal(val)
	if _, err := cli.Put(ctx, "/sandswap/owner/"+sandfsID, string(data)); err != nil {
		t.Fatalf("put ownership: %v", err)
	}
	healthKey := "/sandswap/health/gw-fault"
	healthVal, _ := json.Marshal(lease.GatewayHealthValue{
		LastHealthyTS: time.Now().Format(time.RFC3339),
		NodeCount:     0, // fault state
	})
	if _, err := cli.Put(ctx, healthKey, string(healthVal)); err != nil {
		t.Fatalf("put health: %v", err)
	}
	time.Sleep(1 * time.Second) // let the local cache observe / or fall through to etcd

	// A healthy gateway must TOLERATE, not take over (fault ≠ takeover trigger).
	if _, err := oc.Claim(sandfsID, ""); err != lease.ErrOwnershipConflict {
		t.Fatalf("owner alive+fault must be tolerated (ErrOwnershipConflict), got: %v", err)
	}
}

// ── Test 4: placement lifecycle (NoteMounted + NoteNodeReconnected) ──
func TestNodeIDLifecycle(t *testing.T) {
	oc := newTestOwnershipCache(t, "gw-nodeid")

	sandfsID := "sandfs-nodeid-test"

	_, err := oc.Claim(sandfsID, "")
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}

	oc.NoteMounted(sandfsID, "node-1")

	// streamSrv is nil → Claim assumes connected, no ErrOwnerNodeDown.
	_, err = oc.Claim(sandfsID, "")
	if err != nil {
		t.Fatalf("Claim after NoteMounted: %v", err)
	}

	oc.NoteNodeReconnected("node-1")

	_, err = oc.Claim(sandfsID, "")
	if err != nil {
		t.Fatalf("Claim after NoteNodeReconnected: %v", err)
	}
}

// ── Test 5: owner-release three-part chain releases ownership on node loss ──
func TestOwnerReleaseThreePartChain(t *testing.T) {
	lease.SetSafeMarginSecForTest(0) // T_safe = tolerance + warden + 0 → short
	defer lease.SetSafeMarginSecForTest(60)
	lease.SetOwnerReleaseSweepIntervalForTest(200 * time.Millisecond)
	defer lease.SetOwnerReleaseSweepIntervalForTest(30 * time.Second)

	oc := newTestOwnershipCache(t, "gw-b1-chain")
	cli := newEtcdClient(t)
	sandfsID := "sandfs-b1-chain"

	if _, err := oc.Claim(sandfsID, ""); err != nil {
		t.Fatalf("Claim: %v", err)
	}
	// Mount on node-b1 (registers in the placement index).
	oc.NoteMounted(sandfsID, "node-b1")
	// Node connects → presence key granted with T_safe = 1+1+0 = 2s.
	oc.OnNodeConnect("node-b1", &pb.NodeTiming{ToleranceSec: 1, WardenCountdownSec: 1, IsolationSec: 10})

	// Node disconnects → pendingOwnerRelease armed.
	oc.OnNodeDisconnect("node-b1")

	// The presence key expires ~2s later; the sweep then releases the sandfs.
	deadline := time.Now().Add(8 * time.Second)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		resp, err := cli.Get(ctx, "/sandswap/owner/"+sandfsID)
		cancel()
		if err == nil && len(resp.Kvs) == 0 {
			break // released
		}
		if time.Now().After(deadline) {
			t.Fatal("owner-release did not release ownership within deadline")
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// ── Test 6: owner-release canceled on reconnect ──
func TestOwnerReleaseCanceledOnReconnect(t *testing.T) {
	lease.SetSafeMarginSecForTest(0)
	defer lease.SetSafeMarginSecForTest(60)
	lease.SetOwnerReleaseSweepIntervalForTest(200 * time.Millisecond)
	defer lease.SetOwnerReleaseSweepIntervalForTest(30 * time.Second)

	oc := newTestOwnershipCache(t, "gw-b1-cancel")
	cli := newEtcdClient(t)
	sandfsID := "sandfs-b1-cancel"

	if _, err := oc.Claim(sandfsID, ""); err != nil {
		t.Fatalf("Claim: %v", err)
	}
	oc.NoteMounted(sandfsID, "node-b1c")
	oc.OnNodeConnect("node-b1c", &pb.NodeTiming{ToleranceSec: 1, WardenCountdownSec: 1, IsolationSec: 10})
	oc.OnNodeDisconnect("node-b1c")

	// Reconnect well before T_safe (2s) elapses → cancels the pending owner-release.
	time.Sleep(200 * time.Millisecond)
	oc.OnNodeConnect("node-b1c", &pb.NodeTiming{ToleranceSec: 1, WardenCountdownSec: 1, IsolationSec: 10})

	// Wait past the original T_safe; ownership must NOT be released.
	time.Sleep(3 * time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	resp, err := cli.Get(ctx, "/sandswap/owner/"+sandfsID)
	if err != nil || len(resp.Kvs) == 0 {
		t.Fatal("ownership released despite reconnect — owner-release cancel failed")
	}
}

// ── Test 6b: the constructor alone must not run the owner-release sweep ──
// The sweep is exec-gateway machinery, started explicitly via
// StartOwnerReleaseSweep; the human gateway constructs the cache without the
// sweep (its pendingOwnerRelease inputs only exist behind the exec-role
// stream wiring). This test arms EVERY chain input — pending disconnect past
// T_safe, presence key expired, own health key fresh, sandfs placed on the
// node — against a cache whose wiring omitted the starter, and asserts the
// record survives. Red against a constructor that auto-started the loop; a
// real-etcd client is required (the loop no-ops on nil client, so that
// variant would pass either way).
func TestOwnerReleaseSweepNotStartedByConstructor(t *testing.T) {
	lease.SetSafeMarginSecForTest(0) // T_safe = tolerance + warden + 0 → 2s
	defer lease.SetSafeMarginSecForTest(60)
	lease.SetOwnerReleaseSweepIntervalForTest(200 * time.Millisecond)
	defer lease.SetOwnerReleaseSweepIntervalForTest(30 * time.Second)

	cli := newEtcdClient(t)
	// Deliberately NOT newTestOwnershipCache: that helper mirrors the full
	// exec wiring, sweep included. Construct bare, then start only the loops
	// a sweep-less wiring (the human gateway shape) legitimately runs.
	oc, err := lease.NewOwnershipCache(cli, "gw-no-sweep", nil, slog.Default())
	if err != nil {
		t.Fatalf("NewOwnershipCache: %v", err)
	}
	t.Cleanup(func() { oc.Close() })
	oc.SetNodeCountFunc(func() int { return 1 })
	oc.StartHealthLoop()

	const nodeID = "node-no-sweep"
	sandfsID := "sandfs-no-sweep"
	if _, err := oc.Claim(sandfsID, ""); err != nil {
		t.Fatalf("Claim: %v", err)
	}
	oc.NoteMounted(sandfsID, nodeID)
	oc.OnNodeConnect(nodeID, &pb.NodeTiming{ToleranceSec: 1, WardenCountdownSec: 1, IsolationSec: 10})
	oc.OnNodeDisconnect(nodeID)
	discTime := time.Now()

	// Wait until leg (2) of the chain is observably true — the presence key
	// has expired — so the only release prerequisite left for an auto-started
	// sweep is the local T_safe timer handled below. Polling instead of a
	// fixed sleep keeps the negative window robust under scheduling delays (a
	// fixed wait tuned for an idle host degrades into a false pass when the
	// host is loaded and the presence lease expires late).
	presenceDeadline := time.Now().Add(15 * time.Second)
	for {
		pctx, pcancel := context.WithTimeout(context.Background(), 2*time.Second)
		pres, perr := cli.Get(pctx, "/sandswap/node/"+nodeID+"/presence")
		pcancel()
		if perr != nil {
			t.Fatalf("get presence key: %v", perr)
		}
		if len(pres.Kvs) == 0 {
			break
		}
		if time.Now().After(presenceDeadline) {
			t.Fatal("presence key never expired; cannot establish the negative owner-release window")
		}
		time.Sleep(100 * time.Millisecond)
	}
	// Presence expiry does not imply leg (1): the last keep-alive can predate
	// the disconnect, so expiry may land just BEFORE the local T_safe timer.
	// Wait out the local timer (tolerance 1s + warden 1s + margin 0), then a
	// few sweep intervals: an auto-started loop would have deleted the record.
	tSafe := 2 * time.Second
	if remain := tSafe - time.Since(discTime); remain > 0 {
		time.Sleep(remain)
	}
	time.Sleep(5 * 200 * time.Millisecond)

	getCtx, getCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer getCancel()
	resp, err := cli.Get(getCtx, "/sandswap/owner/"+sandfsID)
	if err != nil {
		t.Fatalf("get ownership key: %v", err)
	}
	if len(resp.Kvs) == 0 {
		t.Fatal("ownership released without StartOwnerReleaseSweep — the constructor must not run the exec-gateway sweep")
	}
}

// ── Test 7: sandfsByAgent reverse index () ──
func TestSandfsByAgentReverseIndex(t *testing.T) {
	store := newTestStore(t)

	agent, _, err := store.CreateAgent(identity.CreateAgentRequest{Name: "test-agent"})
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}

	var sandfsIDs []string
	for i := 0; i < 3; i++ {
		rec, err := store.CreateSandFS(agent.ID, identity.CreateSandFSRequest{
			Name: fmt.Sprintf("sandfs-%d", i),
		})
		if err != nil {
			t.Fatalf("CreateSandFS %d: %v", i, err)
		}
		sandfsIDs = append(sandfsIDs, rec.ID)
	}

	recs, err := store.ListSandFSByAgent(agent.ID)
	if err != nil {
		t.Fatalf("ListSandFSByAgent: %v", err)
	}
	if len(recs) != 3 {
		t.Fatalf("expected 3 sandfs, got %d", len(recs))
	}

	gotIDs := make(map[string]bool)
	for _, r := range recs {
		gotIDs[r.ID] = true
	}
	for _, id := range sandfsIDs {
		if !gotIDs[id] {
			t.Fatalf("missing sandfs %s in ListSandFSByAgent result", id)
		}
	}

	err = store.DeleteSandFS(sandfsIDs[0])
	if err != nil {
		t.Fatalf("DeleteSandFS: %v", err)
	}

	recs, err = store.ListSandFSByAgent(agent.ID)
	if err != nil {
		t.Fatalf("ListSandFSByAgent after delete: %v", err)
	}
	if len(recs) != 2 {
		t.Fatalf("expected 2 sandfs after delete, got %d", len(recs))
	}

	err = store.DeleteAgent(agent.ID)
	if err != nil {
		t.Fatalf("DeleteAgent: %v", err)
	}

	recs, err = store.ListSandFSByAgent(agent.ID)
	if err != nil {
		t.Fatalf("ListSandFSByAgent after agent delete: %v", err)
	}
	if len(recs) != 0 {
		t.Fatalf("expected 0 sandfs after agent delete, got %d", len(recs))
	}
}

// ── Test 8: EtcdStore watch maintains sandfsByAgent ──
func TestSandfsByAgentWatchSync(t *testing.T) {
	prefix := fmt.Sprintf("/sandswap-watch-test-%d/", time.Now().UnixNano())

	store1, err := identity.NewEtcdStore([]string{etcdEndpoint}, prefix, "/tmp/nonexistent-volroot", nil, slog.Default())
	if err != nil {
		t.Fatalf("store1: %v", err)
	}
	defer store1.Close()

	store2, err := identity.NewEtcdStore([]string{etcdEndpoint}, prefix, "/tmp/nonexistent-volroot", nil, slog.Default())
	if err != nil {
		t.Fatalf("store2: %v", err)
	}
	defer store2.Close()

	agent, _, err := store1.CreateAgent(identity.CreateAgentRequest{Name: "watch-agent"})
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}

	rec, err := store1.CreateSandFS(agent.ID, identity.CreateSandFSRequest{Name: "watch-sandfs"})
	if err != nil {
		t.Fatalf("CreateSandFS: %v", err)
	}

	// Wait for watch to propagate to store2.
	time.Sleep(2 * time.Second)

	recs, err := store2.ListSandFSByAgent(agent.ID)
	if err != nil {
		t.Fatalf("store2 ListSandFSByAgent: %v", err)
	}
	if len(recs) != 1 || recs[0].ID != rec.ID {
		t.Fatalf("store2 expected 1 sandfs with ID %s, got %d", rec.ID, len(recs))
	}

	err = store1.DeleteSandFS(rec.ID)
	if err != nil {
		t.Fatalf("DeleteSandFS: %v", err)
	}

	time.Sleep(2 * time.Second)

	recs, err = store2.ListSandFSByAgent(agent.ID)
	if err != nil {
		t.Fatalf("store2 ListSandFSByAgent after delete: %v", err)
	}
	if len(recs) != 0 {
		t.Fatalf("store2 expected 0 sandfs after delete, got %d", len(recs))
	}
}

// ── Test 9: ListAllSandFS deep copy ──
func TestListAllSandFSDeepCopy(t *testing.T) {
	store := newTestStore(t)

	agent, _, err := store.CreateAgent(identity.CreateAgentRequest{Name: "dc-agent"})
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}

	_, err = store.CreateSandFS(agent.ID, identity.CreateSandFSRequest{Name: "dc-sandfs"})
	if err != nil {
		t.Fatalf("CreateSandFS: %v", err)
	}

	recs, err := store.ListAllSandFS()
	if err != nil {
		t.Fatalf("ListAllSandFS: %v", err)
	}

	// Mutate returned record.
	recs[0].Name = "MUTATED"

	// Get again — should not be affected.
	recs2, err := store.ListAllSandFS()
	if err != nil {
		t.Fatalf("ListAllSandFS 2: %v", err)
	}

	for _, r := range recs2 {
		if r.Name == "MUTATED" {
			t.Fatal("ListAllSandFS returned a pointer to internal state — not deep copied")
		}
	}
}

// ── Test 10: Close idempotency ──
func TestOwnershipCloseIdempotent(t *testing.T) {
	oc := newTestOwnershipCache(t, "gw-close-idem")

	oc.Close()
	oc.Close() // should not panic
}

// ── Test 11: LookupOwnerGatewayID + OwnerGatewayURL (307-redirect resolver) ──
// Resolves ownership → gateway_id, then the REGISTRY key (/sandswap/gateway/{gw})
// for the routing address (a plain key that survives the owner's death), so the
// redirect works even during tolerance (owner possibly dead but ownership
// unchanged). The address is NO LONGER in the ownership key.

// lookupOwnerHelper seeds the ownership key and calls LookupOwnerGatewayID.
func lookupOwnerHelper(t *testing.T, sandfsID string, ownerJSON string) (string, error) {
	t.Helper()
	cli := newEtcdClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if ownerJSON != "" {
		if _, err := cli.Put(ctx, "/sandswap/owner/"+sandfsID, ownerJSON); err != nil {
			t.Fatalf("put owner: %v", err)
		}
	}
	return lease.LookupOwnerGatewayID(ctx, cli, sandfsID)
}

func TestLookupOwnerGatewayIDNoOwner(t *testing.T) {
	if _, err := lookupOwnerHelper(t, "sandfs-no-owner", ""); err == nil {
		t.Error("expected error for no owner")
	}
}

func TestLookupOwnerGatewayIDCorruptOwner(t *testing.T) {
	if _, err := lookupOwnerHelper(t, "sandfs-corrupt", "{not json"); err == nil {
		t.Error("expected error for corrupt ownership value")
	}
}

func TestLookupOwnerGatewayIDEmptyGatewayID(t *testing.T) {
	owner, _ := json.Marshal(lease.OwnershipValue{Generation: 1}) // no gateway_id
	if _, err := lookupOwnerHelper(t, "sandfs-empty-gw", string(owner)); err == nil {
		t.Error("expected error for ownership record without gateway_id")
	}
}

func TestLookupOwnerGatewayIDHappyPath(t *testing.T) {
	owner, _ := json.Marshal(lease.OwnershipValue{GatewayID: "gw-happy", Generation: 1})
	gwID, err := lookupOwnerHelper(t, "sandfs-happy-url", string(owner))
	if err != nil {
		t.Fatalf("happy path: %v", err)
	}
	if gwID != "gw-happy" {
		t.Errorf("happy path: gwID=%q, want gw-happy", gwID)
	}
}

// TestOwnerGatewayUGHRegistersEnvResolution: the redirect URL is resolved via the
// gateway REGISTRY key, not the ownership key. Owner gw-tol has a registry key;
// an owner with no registry key is unroutable ("").
func TestOwnerGatewayURLFromRegistry(t *testing.T) {
	oc := newTestOwnershipCache(t, "gw-redirect")
	cli := newEtcdClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sandfsID := "sandfs-registry-redirect"
	// Clean up stale keys from a previous run.
	cli.Delete(ctx, "/sandswap/owner/"+sandfsID)
	cli.Delete(ctx, "/sandswap/gateway/gw-tol")
	cli.Delete(ctx, "/sandswap/health/gw-tol")

	// Self ownership → no redirect even with a registry key.
	ownerSelf, _ := json.Marshal(lease.OwnershipValue{GatewayID: "gw-redirect", Generation: 1})
	cli.Put(ctx, "/sandswap/owner/"+sandfsID, string(ownerSelf))
	if url := oc.OwnerGatewayURL(ctx, sandfsID); url != "" {
		t.Errorf("self ownership must not redirect, got %q", url)
	}

	// Remote owner gw-tol WITH a registry key AND a fresh health key → redirect.
	ownerRemote, _ := json.Marshal(lease.OwnershipValue{GatewayID: "gw-tol", Generation: 1})
	cli.Put(ctx, "/sandswap/owner/"+sandfsID, string(ownerRemote))
	reg, _ := json.Marshal(lease.GatewayRegistryValue{GatewayURL: "https://gw-tol:3000"})
	cli.Put(ctx, "/sandswap/gateway/gw-tol", string(reg))
	hv, _ := json.Marshal(lease.GatewayHealthValue{LastHealthyTS: time.Now().Format(time.RFC3339), NodeCount: 1})
	cli.Put(ctx, "/sandswap/health/gw-tol", string(hv))
	if url := oc.OwnerGatewayURL(ctx, sandfsID); url != "https://gw-tol:3000" {
		t.Errorf("registry-backed redirect (fresh owner): got %q, want https://gw-tol:3000", url)
	}

	// Owner health goes stale past the route-stale threshold → NO redirect
	// (fall back to 503+retry so the client re-resolves via DNS to a live
	// gateway instead of bouncing to a dead owner). Shrink the threshold so the
	// test runs in seconds.
	oc.SetStalenessThresholds(2*time.Second, 0, 0)
	staleHV, _ := json.Marshal(lease.GatewayHealthValue{LastHealthyTS: time.Now().Add(-30 * time.Second).Format(time.RFC3339), NodeCount: 1})
	cli.Put(ctx, "/sandswap/health/gw-tol", string(staleHV))
	if url := oc.OwnerGatewayURL(ctx, sandfsID); url != "" {
		t.Errorf("stale owner must not redirect (fall back to 503+retry), got %q", url)
	}

	// Owner health key absent (lease expired) → NO redirect.
	cli.Delete(ctx, "/sandswap/health/gw-tol")
	if url := oc.OwnerGatewayURL(ctx, sandfsID); url != "" {
		t.Errorf("dead owner (no health key) must not redirect, got %q", url)
	}

	// Remote owner with NO registry key → unroutable (""), no redirect.
	// This is the "alive-but-unroutable gateway" shape, and the tolerance case
	// still resolves when the owner HAS a registry key (it survives death).
	oc.SetStalenessThresholds(15*time.Second, 0, 0) // restore default-ish for the no-registry case
	cli.Put(ctx, "/sandswap/health/gw-tol", string(hv))
	cli.Delete(ctx, "/sandswap/gateway/gw-tol")
	if url := oc.OwnerGatewayURL(ctx, sandfsID); url != "" {
		t.Errorf("owner with no registry key must not redirect, got %q", url)
	}

	// No owner → "".
	cli.Delete(ctx, "/sandswap/owner/"+sandfsID)
	if url := oc.OwnerGatewayURL(ctx, sandfsID); url != "" {
		t.Errorf("no owner must not redirect, got %q", url)
	}
}

// TestPresenceKeyLifecycle verifies the presence key end-to-end: OnNodeConnect
// grants it, heartbeats keep it alive past T_safe, and stopping heartbeats lets
// it naturally expire at T_safe (no explicit revocation on disconnect).
func TestPresenceKeyLifecycle(t *testing.T) {
	lease.SetSafeMarginSecForTest(0) // T_safe = tolerance + warden + 0 → short
	defer lease.SetSafeMarginSecForTest(60)

	oc := newTestOwnershipCache(t, "gw-presence")
	cli := newEtcdClient(t)
	nodeID := "node-presence"

	oc.OnNodeConnect(nodeID, &pb.NodeTiming{ToleranceSec: 1, WardenCountdownSec: 1, IsolationSec: 10}) // T_safe = 2s

	// Presence key exists after connect.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	resp, err := cli.Get(ctx, "/sandswap/node/"+nodeID+"/presence")
	if err != nil || len(resp.Kvs) == 0 {
		t.Fatal("presence key missing after OnNodeConnect")
	}
	if string(resp.Kvs[0].Value) != "gw-presence" {
		t.Fatalf("presence value = %q, want gw-presence", resp.Kvs[0].Value)
	}

	// Heartbeats keep it alive past T_safe (which would otherwise expire it).
	for i := 0; i < 4; i++ {
		time.Sleep(1 * time.Second)
		oc.OnNodeHeartbeat(nodeID)
	}
	ctx2, cancel2 := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel2()
	resp, err = cli.Get(ctx2, "/sandswap/node/"+nodeID+"/presence")
	if err != nil || len(resp.Kvs) == 0 {
		t.Fatal("presence key expired despite heartbeats")
	}

	// Stop heartbeats → key naturally expires ~2s later (T_safe).
	deadline := time.Now().Add(6 * time.Second)
	for {
		ctx3, cancel3 := context.WithTimeout(context.Background(), 3*time.Second)
		resp, _ = cli.Get(ctx3, "/sandswap/node/"+nodeID+"/presence")
		cancel3()
		if len(resp.Kvs) == 0 {
			break // expired
		}
		if time.Now().After(deadline) {
			t.Fatal("presence key did not expire after heartbeats stopped")
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// TestOwnershipPersistsAcrossRestart verifies v2 restart recovery: ownership keys
// are plain (no lease), so a gateway restart simply full-loads them back — no
// lease reuse dance, no expiry storm. The same gateway id re-adopts its sandfs
// and serves a Claim as the owner.
func TestOwnershipPersistsAcrossRestart(t *testing.T) {
	gw := "gw-persist-restart"
	sandfsID := "sandfs-persist-restart"
	cli := newEtcdClient(t)

	// Clean slate: remove keys left by a previous run of this test.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	cli.Delete(ctx, "/sandswap/owner/"+sandfsID)
	cli.Delete(ctx, "/sandswap/health/"+gw)
	cancel()

	oc1 := newTestOwnershipCache(t, gw)
	if _, err := oc1.Claim(sandfsID, ""); err != nil {
		t.Fatalf("oc1 Claim: %v", err)
	}
	oc1.Close() // "crash"

	// Restart: oc2 with the SAME gateway id re-adopts via full-load (no lease
	// to keep alive, the key simply persists).
	oc2 := newTestOwnershipCache(t, gw)
	if !oc2.Ready() {
		t.Fatal("oc2 not ready after NewOwnershipCache")
	}
	if _, err := oc2.Claim(sandfsID, ""); err != nil {
		t.Fatalf("oc2 Claim after restart (re-adopted ownership): %v", err)
	}
}

// TestHealthKeyPublishesNodeCount verifies health-key semantics: node_count is
// published immediately (no startup grace). A compute-less gateway writes
// node_count=0 right away — the value is informational (DNS routing), not a
// switch trigger (ownership no longer churns on it).
func TestHealthKeyPublishesNodeCount(t *testing.T) {
	gw := "gw-pub-health"
	cli := newEtcdClient(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	cli.Delete(ctx, "/sandswap/health/"+gw)
	cancel()

	// No SetNodeCountFunc → node_count=0 (compute-less gateway).
	oc, err := lease.NewOwnershipCache(cli, gw, nil, slog.Default())
	if err != nil {
		t.Fatalf("NewOwnershipCache: %v", err)
	}
	t.Cleanup(func() { oc.Close() })
	oc.StartHealthLoop()

	// node_count=0 must publish immediately — no startup grace withhold.
	deadline := time.Now().Add(3 * time.Second)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		resp, _ := cli.Get(ctx, "/sandswap/health/"+gw)
		cancel()
		if len(resp.Kvs) > 0 {
			var hv lease.GatewayHealthValue
			json.Unmarshal(resp.Kvs[0].Value, &hv)
			if hv.NodeCount == 0 {
				break // published the fault immediately — correct
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("health key did not publish node_count=0 immediately (no startup grace)")
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// TestHealthKeyPublishesFaultImmediately verifies that on losing compute the
// health key publishes node_count=0 right away (no disconnect grace — the
// value is informational, and only owner-release / migrated takeover confirmed conditions govern switching).
func TestHealthKeyPublishesFaultImmediately(t *testing.T) {
	gw := "gw-pub-fault"
	cli := newEtcdClient(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	cli.Delete(ctx, "/sandswap/health/"+gw)
	cancel()

	oc, err := lease.NewOwnershipCache(cli, gw, nil, slog.Default())
	if err != nil {
		t.Fatalf("NewOwnershipCache: %v", err)
	}
	t.Cleanup(func() { oc.Close() })
	oc.SetNodeCountFunc(func() int { return 1 })
	oc.StartHealthLoop()
	oc.TouchHealth()
	time.Sleep(500 * time.Millisecond)

	// Loses compute → node_count=0 published immediately (no disconnect grace).
	oc.SetNodeCountFunc(func() int { return 0 })
	oc.TouchHealth()
	time.Sleep(500 * time.Millisecond)
	ctx, cancel = context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	resp, err := cli.Get(ctx, "/sandswap/health/"+gw)
	if err != nil || len(resp.Kvs) == 0 {
		t.Fatal("health key missing")
	}
	var hv lease.GatewayHealthValue
	json.Unmarshal(resp.Kvs[0].Value, &hv)
	if hv.NodeCount != 0 {
		t.Fatalf("node_count after losing compute = %d, want 0 (published immediately, no grace)", hv.NodeCount)
	}
}

// TestRegistryDecouplingPublishesAddressesInRegisterOnly verifies the routing
// decoupling end-to-end against real etcd: the gateway's address lives ONLY in
// the /sandswap/gateway/{gw} plain key (written by SetRoutingAddrs +
// StartHealthLoop), while the health and ownership keys are pure (no
// gateway_url / stream_addr). Routing is configuration, not liveness/ownership.
func TestRegistryDecouplingPublishesAddressesInRegisterOnly(t *testing.T) {
	gw := "gw-registry-decouple"
	sf := "sandfs-registry-decouple"
	cli := newEtcdClient(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	cli.Delete(ctx, "/sandswap/health/"+gw)
	cli.Delete(ctx, "/sandswap/gateway/"+gw)
	cli.Delete(ctx, "/sandswap/owner/"+sf)
	cancel()

	oc, err := lease.NewOwnershipCache(cli, gw, nil, slog.Default())
	if err != nil {
		t.Fatalf("NewOwnershipCache: %v", err)
	}
	t.Cleanup(func() { oc.Close() })
	oc.SetNodeCountFunc(func() int { return 1 })
	// Set the routing address — SetRoutingAddrs must write the registry key.
	oc.SetRoutingAddrs("https://gw-registry-decouple:3000", "gw-registry-decouple:9998")
	oc.StartHealthLoop()
	oc.StartWatch()

	// The registry key is written (address as configuration, plain key).
	deadline := time.Now().Add(3 * time.Second)
	var gotReg lease.GatewayRegistryValue
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		resp, _ := cli.Get(ctx, "/sandswap/gateway/"+gw)
		cancel()
		if len(resp.Kvs) > 0 {
			json.Unmarshal(resp.Kvs[0].Value, &gotReg)
			if gotReg.GatewayURL == "https://gw-registry-decouple:3000" {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("gateway registry key not written with gateway_url by SetRoutingAddrs/StartHealthLoop")
		}
		time.Sleep(100 * time.Millisecond)
	}
	if gotReg.GatewayURL != "https://gw-registry-decouple:3000" || gotReg.StreamAddr != "gw-registry-decouple:9998" {
		t.Errorf("registry key = %+v, want gateway_url/stream_addr", gotReg)
	}

	// The health key must NOT carry the address (liveness only: node_count).
	ctx, cancel = context.WithTimeout(context.Background(), 3*time.Second)
	hr, _ := cli.Get(ctx, "/sandswap/health/"+gw)
	cancel()
	if len(hr.Kvs) == 0 {
		t.Fatal("health key missing")
	}
	var hb map[string]interface{}
	json.Unmarshal(hr.Kvs[0].Value, &hb)
	if _, ok := hb["gateway_url"]; ok {
		t.Error("health key must NOT carry gateway_url (address lives in the registry key)")
	}
	if _, ok := hb["stream_addr"]; ok {
		t.Error("health key must NOT carry stream_addr (address lives in the registry key)")
	}

	// Claim → ownership key is pure (gateway_id/node_id/generation, no address).
	if _, err := oc.Claim(sf, ""); err != nil {
		t.Fatalf("Claim: %v", err)
	}
	ctx, cancel = context.WithTimeout(context.Background(), 3*time.Second)
	or, _ := cli.Get(ctx, "/sandswap/owner/"+sf)
	cancel()
	if len(or.Kvs) == 0 {
		t.Fatal("ownership key missing")
	}
	var ob map[string]interface{}
	json.Unmarshal(or.Kvs[0].Value, &ob)
	if _, ok := ob["gateway_url"]; ok {
		t.Error("ownership key must NOT carry gateway_url (per-sandfs would be redundant + stale)")
	}
	if ob["gateway_id"] != gw {
		t.Errorf("ownership gateway_id = %v, want %q", ob["gateway_id"], gw)
	}
}

// ── Watch keepalive resubscription + uncovered-mount compensation ──

// TestWatchKeepaliveResubscribeDeliversNewEventsE2E drives the ownership watch
// through a keepalive resubscription and then delivers three more events. With
// the old implementation (uncanceled abandoned watcher + resubscribe from the
// boot revision), the abandoned substream's unread channel wedges the etcd
// client's SHARED watch dispatcher by the second post-restart event — the
// third never arrives, and both the ownership and identity caches silently
// stop updating with no error anywhere.
func TestWatchKeepaliveResubscribeDeliversNewEventsE2E(t *testing.T) {
	prev := lease.SetWatchKeepaliveIntervalForTest(1200 * time.Millisecond)
	defer lease.SetWatchKeepaliveIntervalForTest(prev)

	cli := newEtcdClient(t)
	oc, err := lease.NewOwnershipCache(cli, "gw-keepalive", nil, slog.Default())
	if err != nil {
		t.Fatalf("NewOwnershipCache: %v", err)
	}
	t.Cleanup(func() { oc.Close() })
	oc.SetNodeCountFunc(func() int { return 1 })
	oc.StartWatch()

	sandfsID := fmt.Sprintf("sandfs-keepalive-%d", time.Now().UnixNano())
	oc.SetOwnedForTest(sandfsID, "node-1")

	put := func(node string) {
		t.Helper()
		val, _ := json.Marshal(lease.OwnershipValue{GatewayID: "gw-keepalive", NodeID: node, Generation: 1})
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if _, err := cli.Put(ctx, "/sandswap/owner/"+sandfsID, string(val)); err != nil {
			t.Fatalf("put %s: %v", node, err)
		}
	}
	waitPlacement := func(want string) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for {
			node, cerr := oc.Claim(sandfsID, "")
			if cerr == nil && node == want {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("placement never became %q (last: %q, %v) — the watch stopped delivering events after the keepalive resubscription", want, node, cerr)
			}
			time.Sleep(50 * time.Millisecond)
		}
	}

	// E1 is delivered on the first subscription.
	put("node-1")
	waitPlacement("node-1")

	// Idle past the keepalive (1.2s) plus the 1s resubscribe backoff.
	time.Sleep(3 * time.Second)

	// E2..E4 arrive AFTER the resubscription. With the old implementation the
	// shared watch stream wedges by E3 and E4 is never delivered.
	put("node-2")
	put("node-3")
	put("node-4")
	waitPlacement("node-4")
}

// TestWatchDeleteCompensatesMountedEntryE2E verifies the DELETE-side
// compensation: when the watch observes our ownership record deleted while the
// cache still reports the sandfs mounted (an owner-release sweep racing a
// fresh mount, a manual release, or a SandFS deletion), the uncovered mount
// must be torn down — otherwise a peer can claim and dual-mount until our
// lease expires.
func TestWatchDeleteCompensatesMountedEntryE2E(t *testing.T) {
	oc := newTestOwnershipCache(t, "gw-delcomp")
	sandfsID := fmt.Sprintf("sandfs-delcomp-%d", time.Now().UnixNano())

	// Seed the cache entry first so the watch is interested in the key, then
	// publish our record and let the watch adopt it, then mark it mounted
	// (placement == published → no publish write, as under node affinity).
	oc.SetOwnedForTest(sandfsID, "node-1")
	cli := newEtcdClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	val, _ := json.Marshal(lease.OwnershipValue{GatewayID: "gw-delcomp", NodeID: "node-1", Generation: 1})
	if _, err := cli.Put(ctx, "/sandswap/owner/"+sandfsID, string(val)); err != nil {
		t.Fatalf("put: %v", err)
	}
	time.Sleep(1 * time.Second) // watch adopts the record into the cache entry
	oc.NoteMounted(sandfsID, "node-1")

	compensated := make(chan string, 1)
	oc.SetMountCompensator(func(id, node string) { compensated <- id })

	dctx, dcancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer dcancel()
	if _, err := cli.Delete(dctx, "/sandswap/owner/"+sandfsID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	select {
	case id := <-compensated:
		if id != sandfsID {
			t.Fatalf("compensated sandfs = %q, want %q", id, sandfsID)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("DELETE of a mounted entry did not trigger compensation (uncovered live mount)")
	}
}

// TestPublishForeignRecordCompensatesE2E verifies the publish-side
// compensation: a cold mount whose placement publish discovers the record
// taken over by a peer (CAS lost / no-baseline re-anchor finds a foreign
// owner) must tear the mount down instead of silently dropping the write —
// the invariant "this gateway's live mounts are covered by its ownership
// record" is what the takeover soundness proofs rely on.
func TestPublishForeignRecordCompensatesE2E(t *testing.T) {
	oc := newTestOwnershipCache(t, "gw-pubcomp")
	sandfsID := fmt.Sprintf("sandfs-pubcomp-%d", time.Now().UnixNano())

	// The etcd record was taken over by a peer BEFORE our cache ever observed
	// it (no CAS baseline in the entry).
	cli := newEtcdClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	val, _ := json.Marshal(lease.OwnershipValue{GatewayID: "gw-peer", NodeID: "node-9", Generation: 2})
	if _, err := cli.Put(ctx, "/sandswap/owner/"+sandfsID, string(val)); err != nil {
		t.Fatalf("put: %v", err)
	}

	oc.SetOwnedForTest(sandfsID, "node-1") // cache entry; modRev == 0 (no baseline)
	compensated := make(chan string, 1)
	oc.SetMountCompensator(func(id, node string) { compensated <- id })

	// Successful cold mount on node-2: the placement change triggers the
	// publish, whose no-baseline re-anchor finds the foreign record.
	oc.NoteMounted(sandfsID, "node-2")

	select {
	case id := <-compensated:
		if id != sandfsID {
			t.Fatalf("compensated sandfs = %q, want %q", id, sandfsID)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("publish against a foreign record did not compensate (uncovered live mount)")
	}
}

// A delayed owner-release delete must not remove a record that was re-claimed
// after the release snapshot was taken: the delete is bound to the observed
// ModRevision, so a changed record survives (and a matching one is deleted).
func TestOwnerReleaseDelayedDeleteCAS(t *testing.T) {
	oc := newTestOwnershipCache(t, "gw-cas-del")
	cli := newEtcdClient(t)
	ctx := context.Background()
	id := fmt.Sprintf("sandfs-delay-%d", time.Now().UnixNano())
	key := lease.OwnershipKeyForTest(id)
	t.Cleanup(func() { _, _ = cli.Delete(context.Background(), key) })

	if _, err := cli.Put(ctx, key, `{"gateway_id":"gw-old","node_id":"node-a","generation":1}`); err != nil {
		t.Fatalf("seed record: %v", err)
	}
	resp, err := cli.Get(ctx, key)
	if err != nil || len(resp.Kvs) != 1 {
		t.Fatalf("read seed record: %v %v", err, resp)
	}
	releasedRev := resp.Kvs[0].ModRevision

	// The delete is queued; meanwhile a new claim rewrites the record.
	if _, err := cli.Put(ctx, key, `{"gateway_id":"gw-new","node_id":"node-b","generation":2}`); err != nil {
		t.Fatalf("re-claim record: %v", err)
	}
	oc.DeleteOwnershipKeysCASForTest([]lease.OwnershipDeleteForTest{{ID: id, ModRev: releasedRev}})

	got, err := cli.Get(ctx, key)
	if err != nil {
		t.Fatalf("read after delayed delete: %v", err)
	}
	if len(got.Kvs) != 1 || !strings.Contains(string(got.Kvs[0].Value), `"gw-new"`) {
		t.Fatalf("delayed delete removed or replaced the re-claimed record: %v", got.Kvs)
	}

	// With the CURRENT baseline the same path must delete it.
	currentRev := got.Kvs[0].ModRevision
	oc.DeleteOwnershipKeysCASForTest([]lease.OwnershipDeleteForTest{{ID: id, ModRev: currentRev}})
	got, err = cli.Get(ctx, key)
	if err != nil {
		t.Fatalf("read after matching delete: %v", err)
	}
	if len(got.Kvs) != 0 {
		t.Fatalf("CAS delete with the current baseline did not remove the record")
	}
}

// TestReleaseOwnershipCAS pins the single-key release rule: a peer's record
// (written after a takeover) is left intact, while our own record is deleted.
// The old blind Delete erased whichever record was current.
func TestReleaseOwnershipCAS(t *testing.T) {
	oc := newTestOwnershipCache(t, "gw-release-cas")
	cli := newEtcdClient(t)
	ctx := context.Background()
	id := fmt.Sprintf("sandfs-release-%d", time.Now().UnixNano())
	key := lease.OwnershipKeyForTest(id)
	t.Cleanup(func() { _, _ = cli.Delete(context.Background(), key) })

	if _, err := cli.Put(ctx, key, `{"gateway_id":"gw-peer","node_id":"node-b","generation":2}`); err != nil {
		t.Fatalf("seed peer record: %v", err)
	}
	if err := oc.ReleaseOwnershipSync(id, 1); err != nil {
		t.Fatalf("release of a peer record must be a no-op, got error: %v", err)
	}
	got, err := cli.Get(ctx, key)
	if err != nil {
		t.Fatalf("read after peer release: %v", err)
	}
	if len(got.Kvs) != 1 || !strings.Contains(string(got.Kvs[0].Value), `"gw-peer"`) {
		t.Fatalf("a peer's ownership record was deleted by our release: %v", got.Kvs)
	}

	if _, err := cli.Put(ctx, key, `{"gateway_id":"gw-release-cas","node_id":"node-a","generation":1}`); err != nil {
		t.Fatalf("seed own record: %v", err)
	}
	if err := oc.ReleaseOwnershipSync(id, 1); err != nil {
		t.Fatalf("release own record: %v", err)
	}
	got, err = cli.Get(ctx, key)
	if err != nil {
		t.Fatalf("read after own release: %v", err)
	}
	if len(got.Kvs) != 0 {
		t.Fatalf("own ownership record was not released")
	}
}

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

//go:build shed_e2e

// Shed-rebalance coordination e2e against a REAL etcd. Exercises the voluntary
// load-shed lifecycle across two independent gateway coordination instances:
//   - owner A is sustained-saturated and an idle peer B exists → MaybeShed
//     releases A's ownership (deleteOwnership lands in etcd);
//   - A refuses to re-claim during the shed cooldown (ErrShedCooldown);
//   - B claims via CAS (createOwnership) → ownership moves to B;
//   - A's ownership watch observes B's claim and clears the cooldown
//     (ClearShed), so A can claim normally again after a later release.
//
// The pool saturation (IsSustainedSaturated) and peer-idle (HasIdlePeer) gates
// use the real pool.Manager and PeerLoadMonitor; only the load record for B is
// seeded through a direct etcd write (a peer gateway publishes the same record
// every ~2s in production). Run via e2e/load-shed.sh (needs a local etcd).
package lease

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"gateway/pool"

	clientv3 "go.etcd.io/etcd/client/v3"
)

const shedE2EEtcdEndpoint = "http://127.0.0.1:2379"

func shedE2EEtcd(t *testing.T) *clientv3.Client {
	t.Helper()
	cli, err := clientv3.New(clientv3.Config{
		Endpoints:   []string{shedE2EEtcdEndpoint},
		DialTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("shed e2e etcd client: %v", err)
	}
	t.Cleanup(func() { cli.Close() })
	return cli
}

func shedE2ECache(t *testing.T, cli *clientv3.Client, gwID string) *OwnershipCache {
	t.Helper()
	oc, err := NewOwnershipCache(cli, gwID, nil, slog.Default())
	if err != nil {
		t.Fatalf("NewOwnershipCache(%s): %v", gwID, err)
	}
	t.Cleanup(func() { oc.Close() })
	oc.SetNodeCountFunc(func() int { return 1 })
	oc.StartHealthLoop()
	oc.StartWatch()
	return oc
}

// shedE2EPeer seeds the /sandswap/load/{gwID} record a peer gateway publishes
// every ~2s (TTL 10s) and returns it for later cleanup. The load record carries
// capacity + duty only — the peer's routing address lives in its /sandswap/gateway
// registry key (not tested here; HasIdlePeer only needs the capacity signal).
func shedE2EPeer(t *testing.T, cli *clientv3.Client, gwID string, cleanVMs uint32) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	val := fmt.Sprintf(`{"gateway_id":%q,"clean_vms":%d,"node_count":1}`,
		gwID, cleanVMs)
	if _, err := cli.Put(ctx, "/sandswap/load/"+gwID, val); err != nil {
		t.Fatalf("seed peer load %s: %v", gwID, err)
	}
}

func shedE2EOwner(t *testing.T, cli *clientv3.Client, sandfsID string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	resp, err := cli.Get(ctx, "/sandswap/owner/"+sandfsID)
	if err != nil || len(resp.Kvs) == 0 {
		return ""
	}
	var ov OwnershipValue
	if json.Unmarshal(resp.Kvs[0].Value, &ov) != nil {
		return ""
	}
	return ov.GatewayID
}

func shedE2EWaitForOwner(t *testing.T, cli *clientv3.Client, sandfsID, want string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if got := shedE2EOwner(t, cli, sandfsID); got == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("owner of %s = %q, want %q", sandfsID, shedE2EOwner(t, cli, sandfsID), want)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func shedE2EWaitForNoOwner(t *testing.T, cli *clientv3.Client, sandfsID string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if shedE2EOwner(t, cli, sandfsID) == "" {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("ownership of %s still present after shed", sandfsID)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// saturatedPool returns a pool.Manager whose single node is fully zero-clean
// (total=1, then the only VM is bound) — the gateway as a whole is saturated.
func saturatedPool(t *testing.T) *pool.Manager {
	t.Helper()
	pm := pool.NewManager(nil, slog.New(slog.DiscardHandler))
	pm.AddNode("node-shed-e2e")
	pm.UpdateNodeCapacity("node-shed-e2e", []pool.SpecCapacity{{SpecID: "small", Total: 1, Clean: 0}})
	pm.ReserveBound("node-shed-e2e", "small") // derived clean = total - bound = 0
	return pm
}

func shedE2ECleanup(t *testing.T, cli *clientv3.Client, keys ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, k := range keys {
		cli.Delete(ctx, k)
	}
}

// shedE2EWipeLoad clears every /sandswap/load/ record. Peer-load keys persist
// (no TTL once the publisher is gone) and would leak between tests, making a
// later test's HasIdlePeer see a stale idle peer from an earlier one.
func shedE2EWipeLoad(t *testing.T, cli *clientv3.Client) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cli.Delete(ctx, "/sandswap/load/", clientv3.WithPrefix())
}

// ── Full shed lifecycle across two real coordination instances ──
func TestShedRebalanceLifecycle(t *testing.T) {
	cli := shedE2EEtcd(t)
	const (
		gwA      = "gw-shed-e2e-a"
		gwB      = "gw-shed-e2e-b"
		sandfsID = "sandfs-shed-e2e-lc"
	)
	shedE2ECleanup(t, cli,
		"/sandswap/owner/"+sandfsID, "/sandswap/health/"+gwA, "/sandswap/health/"+gwB,
		"/sandswap/load/"+gwA, "/sandswap/load/"+gwB)
	shedE2EWipeLoad(t, cli)

	ocA := shedE2ECache(t, cli, gwA)
	ocB := shedE2ECache(t, cli, gwB)

	// A owns the sandfs (as a normal cold mount would have claimed it).
	if _, err := ocA.Claim(sandfsID, ""); err != nil {
		t.Fatalf("A claim: %v", err)
	}
	shedE2EWaitForOwner(t, cli, sandfsID, gwA, 3*time.Second)

	// B is an idle peer (publishes clean_vms>0). A's PeerLoadMonitor watches
	// the real /sandswap/load/ prefix and must observe it.
	shedE2EPeer(t, cli, gwB, 3)
	peerMon := NewPeerLoadMonitor(cli, gwA, slog.Default())
	peerCtx, peerCancel := context.WithCancel(context.Background())
	defer peerCancel()
	peerMon.Start(peerCtx)
	peerMon.refresh(context.Background()) // immediate pickup (watch is async)
	if !peerMon.HasIdlePeer() {
		t.Fatal("peer monitor did not see idle peer B")
	}

	// A is sustained-saturated: build the pool, let the hysteresis window elapse,
	// then confirm the saturated state holds.
	pm := saturatedPool(t)
	time.Sleep(1100 * time.Millisecond)
	if !pm.IsSustainedSaturated(1) {
		t.Fatal("pool should be saturated (zero clean)")
	}

	cfg := &ShedConfig{}
	cfg.Update(true, 1, 100, 30, 5) // enabled, 1s hysteresis, ample rate, 30s cooldown
	shed := NewShedController(cfg, pm, ocA, peerMon, slog.Default())

	if act := shed.MaybeShed(sandfsID); act != ShedActionShed {
		t.Fatalf("MaybeShed = %v, want Shed", act)
	}
	shedE2EWaitForNoOwner(t, cli, sandfsID, 3*time.Second) // deleteOwnership landed in etcd

	// A must refuse to re-claim during the cooldown (a client routed back by
	// the DNS cache window would otherwise undo the shed).
	if _, err := ocA.Claim(sandfsID, ""); err != ErrShedCooldown {
		t.Fatalf("A re-claim during cooldown = %v, want ErrShedCooldown", err)
	}

	// B claims it (CAS createOwnership) — the rebalance lands.
	if _, err := ocB.Claim(sandfsID, ""); err != nil {
		t.Fatalf("B claim: %v", err)
	}
	shedE2EWaitForOwner(t, cli, sandfsID, gwB, 3*time.Second)

	// A's ownership watch sees B's claim → ClearShed, so the cooldown is gone.
	deadline := time.Now().Add(5 * time.Second)
	for ocA.isRecentlyShed(sandfsID) {
		if time.Now().After(deadline) {
			t.Fatal("A still in shed cooldown after B claimed (watch ClearShed failed)")
		}
		time.Sleep(100 * time.Millisecond)
	}

	// After B releases, A can claim normally again (cooldown cleared, not a
	// lingering ErrShedCooldown).
	shedE2ECleanup(t, cli, "/sandswap/owner/"+sandfsID)
	shedE2EWaitForNoOwner(t, cli, sandfsID, 3*time.Second)
	if _, err := ocA.Claim(sandfsID, ""); err != nil {
		t.Fatalf("A claim after B release = %v, want success (cooldown cleared)", err)
	}
}

// ── Cluster-wide saturation (no idle peer): ownership is NOT released ──
func TestShedNoIdlePeerKeepsOwnership(t *testing.T) {
	cli := shedE2EEtcd(t)
	const (
		gwA      = "gw-shed-e2e-np"
		sandfsID = "sandfs-shed-e2e-np"
	)
	shedE2ECleanup(t, cli, "/sandswap/owner/"+sandfsID, "/sandswap/health/"+gwA,
		"/sandswap/load/"+gwA)
	shedE2EWipeLoad(t, cli)

	ocA := shedE2ECache(t, cli, gwA)
	if _, err := ocA.Claim(sandfsID, ""); err != nil {
		t.Fatalf("A claim: %v", err)
	}

	// No peers → HasIdlePeer false even though A is saturated.
	peerMon := NewPeerLoadMonitor(cli, gwA, slog.Default())
	peerMon.refresh(context.Background())
	pm := saturatedPool(t)
	time.Sleep(1100 * time.Millisecond)
	cfg := &ShedConfig{}
	cfg.Update(true, 1, 100, 30, 5)
	shed := NewShedController(cfg, pm, ocA, peerMon, slog.Default())

	if act := shed.MaybeShed(sandfsID); act != ShedActionNone {
		t.Fatalf("MaybeShed with no idle peer = %v, want None", act)
	}
	shedE2EWaitForOwner(t, cli, sandfsID, gwA, 3*time.Second) // ownership untouched
}

// ── Shedding disabled: nothing changes ──
func TestShedDisabledKeepsOwnership(t *testing.T) {
	cli := shedE2EEtcd(t)
	const (
		gwA      = "gw-shed-e2e-dis"
		sandfsID = "sandfs-shed-e2e-dis"
	)
	shedE2ECleanup(t, cli, "/sandswap/owner/"+sandfsID, "/sandswap/health/"+gwA,
		"/sandswap/load/"+gwA, "/sandswap/load/gw-shed-e2e-dis-peer")
	shedE2EWipeLoad(t, cli)

	ocA := shedE2ECache(t, cli, gwA)
	if _, err := ocA.Claim(sandfsID, ""); err != nil {
		t.Fatalf("A claim: %v", err)
	}
	shedE2EPeer(t, cli, "gw-shed-e2e-dis-peer", 3)
	peerMon := NewPeerLoadMonitor(cli, gwA, slog.Default())
	peerMon.refresh(context.Background())
	pm := saturatedPool(t)
	time.Sleep(1100 * time.Millisecond)

	cfg := &ShedConfig{} // Enabled=false (zero value)
	shed := NewShedController(cfg, pm, ocA, peerMon, slog.Default())
	if act := shed.MaybeShed(sandfsID); act != ShedActionNone {
		t.Fatalf("MaybeShed with shedding disabled = %v, want None", act)
	}
	shedE2EWaitForOwner(t, cli, sandfsID, gwA, 3*time.Second)
}

// ── Not yet sustained-saturated (transient spike): no shed ──
func TestShedNotSustainedKeepsOwnership(t *testing.T) {
	cli := shedE2EEtcd(t)
	const (
		gwA      = "gw-shed-e2e-ts"
		sandfsID = "sandfs-shed-e2e-ts"
	)
	shedE2ECleanup(t, cli, "/sandswap/owner/"+sandfsID, "/sandswap/health/"+gwA,
		"/sandswap/load/"+gwA, "/sandswap/load/gw-shed-e2e-ts-peer")
	shedE2EWipeLoad(t, cli)

	ocA := shedE2ECache(t, cli, gwA)
	if _, err := ocA.Claim(sandfsID, ""); err != nil {
		t.Fatalf("A claim: %v", err)
	}
	shedE2EPeer(t, cli, "gw-shed-e2e-ts-peer", 3)
	peerMon := NewPeerLoadMonitor(cli, gwA, slog.Default())
	peerMon.refresh(context.Background())
	pm := saturatedPool(t) // saturated just now
	cfg := &ShedConfig{}
	cfg.Update(true, 60, 100, 30, 5) // 60s hysteresis ≫ elapsed
	shed := NewShedController(cfg, pm, ocA, peerMon, slog.Default())

	if act := shed.MaybeShed(sandfsID); act != ShedActionNone {
		t.Fatalf("MaybeShed before hysteresis = %v, want None", act)
	}
	shedE2EWaitForOwner(t, cli, sandfsID, gwA, 3*time.Second)
}

// ── Cooldown expiry: after the window A can re-claim ──
func TestShedCooldownExpiresThenReclaim(t *testing.T) {
	cli := shedE2EEtcd(t)
	const (
		gwA      = "gw-shed-e2e-cd"
		sandfsID = "sandfs-shed-e2e-cd"
	)
	shedE2ECleanup(t, cli, "/sandswap/owner/"+sandfsID, "/sandswap/health/"+gwA,
		"/sandswap/load/"+gwA)
	shedE2EWipeLoad(t, cli)

	ocA := shedE2ECache(t, cli, gwA)
	// No peer claims the shed sandfs (simulates a peer that never picks it up).
	ocA.ShedOwnership(sandfsID, 1) // 1s cooldown
	if !ocA.isRecentlyShed(sandfsID) {
		t.Fatal("expected recentlyShed right after ShedOwnership")
	}
	shedE2EWaitForNoOwner(t, cli, sandfsID, 3*time.Second)

	// Within the cooldown → refused.
	if _, err := ocA.Claim(sandfsID, ""); err != ErrShedCooldown {
		t.Fatalf("claim during cooldown = %v, want ErrShedCooldown", err)
	}

	// After the window elapses (isRecentlyShed evicts opportunistically) A can
	// re-claim — the shed did not land, so no permanent refusal.
	time.Sleep(1500 * time.Millisecond)
	if _, err := ocA.Claim(sandfsID, ""); err != nil {
		t.Fatalf("claim after cooldown expiry = %v, want success", err)
	}
	shedE2EWaitForOwner(t, cli, sandfsID, gwA, 3*time.Second)
}

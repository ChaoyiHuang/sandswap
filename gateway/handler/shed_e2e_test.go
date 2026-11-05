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

// HTTP-transport e2e of the voluntary load shed against a REAL etcd. Drives the
// actual /agent/execute handler with a saturated pool + an idle peer gateway:
//   - the shed branch emits a RAW 503 + Retry-After + Connection: close (no
//     JSON body — a tool-result error would go to the LLM, not a transport
//     retry), and releases the sandfs's ownership in etcd;
//   - a second request during the cooldown still gets the shed-503 (no re-claim,
//     so a DNS-cache-window retry can't undo the shed);
//   - an idle peer then claims the now-unowned sandfs (CAS) — the rebalance
//     lands.
//
// Requires a local etcd at 127.0.0.1:2379. Run via e2e/load-shed.sh.
package handler_test

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"gateway/lease"
	"gateway/pool"

	clientv3 "go.etcd.io/etcd/client/v3"
)

func shedHTTPEtcd(t *testing.T) *clientv3.Client {
	t.Helper()
	cli, err := clientv3.New(clientv3.Config{
		Endpoints:   []string{"http://127.0.0.1:2379"},
		DialTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("shed http e2e etcd client: %v", err)
	}
	t.Cleanup(func() { cli.Close() })
	return cli
}

func shedHTTPCache(t *testing.T, cli *clientv3.Client, gwID string) *lease.OwnershipCache {
	t.Helper()
	oc, err := lease.NewOwnershipCache(cli, gwID, nil, slog.Default())
	if err != nil {
		t.Fatalf("NewOwnershipCache(%s): %v", gwID, err)
	}
	t.Cleanup(func() { oc.Close() })
	oc.SetNodeCountFunc(func() int { return 1 })
	oc.StartHealthLoop()
	oc.StartWatch()
	return oc
}

// TestShedHTTPTransportEndToEnd exercises the real handler shed path: raw 503 +
// Connection: close + Retry-After, ownership released in etcd, cooldown 503 on a
// DNS-cache-window retry, then the peer claims it.
func TestShedHTTPTransportEndToEnd(t *testing.T) {
	cli := shedHTTPEtcd(t)
	const (
		gwA = "gw-http-shed-a"
		gwB = "gw-http-shed-b"
	)
	sandfsID := "sandfs-http-shed"
	for _, k := range []string{
		"/sandswap/owner/" + sandfsID, "/sandswap/health/" + gwA, "/sandswap/health/" + gwB,
		"/sandswap/load/" + gwA, "/sandswap/load/" + gwB,
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		cli.Delete(ctx, k)
		cancel()
	}
	// Peer-load keys persist and would leak between test runs — clear them all so
	// HasIdlePeer reflects only the peer we seed below.
	{
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		cli.Delete(ctx, "/sandswap/load/", clientv3.WithPrefix())
		cancel()
	}

	// Real handler stack (in-memory identity store + stub sandlot client), with a
	// REAL etcd-backed OwnershipCache wired through the shed controller.
	sc := pool.NewStubSandlotClient()
	execH, _, humanH, _, pm, _, _, _, apiKey, agentID := setupResilienceGateway(t, sc)
	sandfsID = createResilienceSandFS(t, humanH, agentID)

	ocA := shedHTTPCache(t, cli, gwA)
	ocB := shedHTTPCache(t, cli, gwB)

	// A owns the sandfs (as a normal cold mount would have claimed it).
	if _, err := ocA.Claim(sandfsID, ""); err != nil {
		t.Fatalf("A claim: %v", err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		resp, _ := cli.Get(ctx, "/sandswap/owner/"+sandfsID)
		cancel()
		if len(resp.Kvs) > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("A ownership not visible in etcd")
		}
		time.Sleep(100 * time.Millisecond)
	}

	// B is an idle peer. Seed its /sandswap/load record (a peer gateway publishes
	// this every ~2s) and have A's PeerLoadMonitor observe it.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	_, _ = cli.Put(ctx, "/sandswap/load/"+gwB,
		fmt.Sprintf(`{"gateway_id":%q,"clean_vms":3,"node_count":1}`, gwB))
	cancel()
	peerMon := lease.NewPeerLoadMonitor(cli, gwA, slog.Default())
	peerCtx, peerCancel := context.WithCancel(context.Background())
	t.Cleanup(peerCancel)
	peerMon.Start(peerCtx) // initial refresh + watch pick up the seeded load key
	if !peerMon.HasIdlePeer() {
		t.Fatal("peer monitor did not see idle peer B")
	}

	// Saturate A's pool (all 5 medium VMs bound → zero clean) and let the
	// hysteresis window elapse.
	for i := 0; i < 5; i++ {
		pm.ReserveBound("localhost", "medium")
	}
	time.Sleep(1100 * time.Millisecond)

	cfg := &lease.ShedConfig{}
	cfg.Update(true, 1, 100, 30, 5)
	shedCtl := lease.NewShedController(cfg, pm, ocA, peerMon, slog.Default())
	execH.SetShedController(shedCtl)

	// 1st request: the saturated owner sheds — raw transport 503, Connection:
	// close, Retry-After, NO JSON body.
	w := doResilienceExecute(t, execH, apiKey, sandfsID, "echo hi")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("shed request code = %d, want 503", w.Code)
	}
	if cc := w.Header().Get("Connection"); cc != "close" {
		t.Fatalf("shed request Connection header = %q, want \"close\"", cc)
	}
	if ra := w.Header().Get("Retry-After"); ra == "" {
		t.Error("shed request missing Retry-After header")
	}
	if w.Body.Len() != 0 {
		t.Errorf("shed request body = %q, want empty (raw 503, not JSON)", w.Body.String())
	}

	// Ownership released in etcd.
	deadline = time.Now().Add(3 * time.Second)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		resp, _ := cli.Get(ctx, "/sandswap/owner/"+sandfsID)
		cancel()
		if len(resp.Kvs) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("ownership not released in etcd after shed")
		}
		time.Sleep(100 * time.Millisecond)
	}

	// 2nd request during the cooldown (client routed back within the DNS cache
	// window): still the shed-503, ownership still not re-claimed.
	w2 := doResilienceExecute(t, execH, apiKey, sandfsID, "echo hi")
	if w2.Code != http.StatusServiceUnavailable {
		t.Fatalf("cooldown request code = %d, want 503", w2.Code)
	}
	if cc := w2.Header().Get("Connection"); cc != "close" {
		t.Fatalf("cooldown request Connection header = %q, want \"close\"", cc)
	}

	// The idle peer claims the now-unowned sandfs — the rebalance lands.
	if _, err := ocB.Claim(sandfsID, ""); err != nil {
		t.Fatalf("peer B claim after shed: %v", err)
	}
	deadline = time.Now().Add(3 * time.Second)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		resp, _ := cli.Get(ctx, "/sandswap/owner/"+sandfsID)
		cancel()
		if len(resp.Kvs) > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("peer B ownership not visible in etcd")
		}
		time.Sleep(100 * time.Millisecond)
	}
}

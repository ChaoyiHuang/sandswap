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

//go:build dns_e2e

// Package main (dns_e2e build tag) integration tests for the etcd-coupled DNS
// paths: loadStickyFromEtcd, syncStickyToEtcd, refreshOwnerAndHealth,
// resolveOwnerFromEtcd. These require a real etcd at 127.0.0.1:2379:
//
//	etcd &                             # start etcd
//	go test -tags dns_e2e ./...
//
// They are excluded from the default `go test` run, matching the repo's
// ownership_e2e_test.go convention. The pure-logic paths (handlers, parsing,
// routing) are covered by the default unit tests.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"common/config"

	clientv3 "go.etcd.io/etcd/client/v3"
)

const dnsEtcdEndpoint = "http://127.0.0.1:2379"

func dnsEtcdClient(t *testing.T) *clientv3.Client {
	t.Helper()
	cli, err := clientv3.New(clientv3.Config{Endpoints: []string{dnsEtcdEndpoint}, DialTimeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("etcd client: %v", err)
	}
	t.Cleanup(func() { cli.Close() })
	return cli
}

// dnsServerWithEtcd builds a DNSServer wired to a real etcd client (maps
// initialized; candidates start empty — they come from self-registered
// registry keys) for integration testing. Returns the server and the
// underlying client for seeding/verifying etcd state.
func dnsServerWithEtcd(t *testing.T) (*DNSServer, *clientv3.Client) {
	t.Helper()
	cli := dnsEtcdClient(t)
	return &DNSServer{
		cfg:                 &Config{TTL: 10, StickyExpire: 1800, Domains: DomainsConfig{Stream: "s"}},
		sticky:              make(map[string]*StickyEntry),
		dirty:               make(map[string]struct{}),
		owners:              make(map[string]*ownerEntry),
		healthByID:          make(map[string]ownerHealth),
		loadByID:            make(map[string]gwLoad),
		registryByID:        make(map[string]gatewayRegistry),
		gwAddrs:             make(map[string]GWInfo),
		routeStaleThreshold: defaultDNSRouteStaleThreshold,
		etcdClient:          cli,
	}, cli
}

func putJSON(t *testing.T, cli *clientv3.Client, key string, v interface{}) {
	t.Helper()
	data, _ := json.Marshal(v)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := cli.Put(ctx, key, string(data)); err != nil {
		t.Fatalf("put %s: %v", key, err)
	}
}

// TestE2ELoadStickyFromEtcd verifies startup sticky load: valid entries are
// hydrated into the sticky map; corrupt entries are skipped (not fatal).
func TestE2ELoadStickyFromEtcd(t *testing.T) {
	s, cli := dnsServerWithEtcd(t)
	ip1 := fmt.Sprintf("10.9.0.%d-load", time.Now().UnixNano()%200)
	ip2 := fmt.Sprintf("10.9.0.%d-bad", time.Now().UnixNano()%199)

	putJSON(t, cli, stickyPrefix+ip1, StickyEntry{GWID: "gw-e2e", LastQuery: 1, Created: 1})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := cli.Put(ctx, stickyPrefix+ip2, "{not json"); err != nil {
		t.Fatal(err)
	}

	s.loadStickyFromEtcd()

	if e, ok := s.sticky[ip1]; !ok || e.GWID != "gw-e2e" {
		t.Errorf("valid sticky not loaded: %+v ok=%v", e, ok)
	}
	if _, ok := s.sticky[ip2]; ok {
		t.Error("corrupt sticky should be skipped, not loaded")
	}
}

// TestE2ESyncStickyBatch verifies the sticky_sync_batch bound against a real
// etcd: a pass flushes at most N entries, deferring the rest to the next pass
// (each pass then fits inside its etcd timeout regardless of dirty-set size),
// and repeated passes eventually drain the set completely.
func TestE2ESyncStickyBatch(t *testing.T) {
	s, cli := dnsServerWithEtcd(t)
	s.cfg.StickySyncBatch = 2
	suf := fmt.Sprintf("%d", time.Now().UnixNano())
	ips := []string{
		"10.9.7.1" + suf[len(suf)-2:],
		"10.9.7.2" + suf[len(suf)-2:],
		"10.9.7.3" + suf[len(suf)-2:],
		"10.9.7.4" + suf[len(suf)-2:],
		"10.9.7.5" + suf[len(suf)-2:],
	}
	t.Cleanup(func() {
		for _, ip := range ips {
			cli.Delete(context.Background(), stickyPrefix+ip)
		}
	})

	for _, ip := range ips {
		s.sticky[ip] = &StickyEntry{GWID: "gw-e2e", LastQuery: 5, Created: 5}
		s.dirty[ip] = struct{}{}
	}

	countPersisted := func() int {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		resp, err := cli.Get(ctx, stickyPrefix, clientv3.WithPrefix())
		if err != nil {
			t.Fatalf("get sticky prefix: %v", err)
		}
		return len(resp.Kvs)
	}

	// Pass 1: at most batch=2 flushed, ≥3 still dirty.
	before := countPersisted()
	s.syncStickyToEtcd()
	after1 := countPersisted()
	if after1-before > 2 {
		t.Fatalf("pass 1 flushed %d entries, batch cap is 2", after1-before)
	}
	s.mu.RLock()
	dirtyLeft := len(s.dirty)
	s.mu.RUnlock()
	if dirtyLeft < len(ips)-2 {
		t.Fatalf("pass 1 should leave ≥%d dirty, got %d", len(ips)-2, dirtyLeft)
	}

	// Repeated passes drain the set entirely.
	for i := 0; i < len(ips); i++ {
		s.syncStickyToEtcd()
	}
	s.mu.RLock()
	dirtyLeft = len(s.dirty)
	s.mu.RUnlock()
	if dirtyLeft != 0 {
		t.Fatalf("repeated passes should drain the dirty set, %d left", dirtyLeft)
	}
	if got := countPersisted() - before; got != len(ips) {
		t.Fatalf("expected all %d entries persisted, got %d", len(ips), got)
	}
}

// TestE2ESyncStickyToEtcd verifies the dirty-flush: a new sticky entry is Put
// to etcd; a deleted entry is Delete-d. Retry-on-error is covered by the
// contract (re-add to dirty) - this test verifies the happy path persists.
func TestE2ESyncStickyToEtcd(t *testing.T) {
	s, cli := dnsServerWithEtcd(t)
	ip := fmt.Sprintf("10.9.1.%d", time.Now().UnixNano()%250)

	// Put path: sticky entry + dirty -> sync -> key present in etcd.
	s.sticky[ip] = &StickyEntry{GWID: "gw-e2e", LastQuery: 5, Created: 5}
	s.dirty[ip] = struct{}{}
	s.syncStickyToEtcd()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	resp, err := cli.Get(ctx, stickyPrefix+ip)
	if err != nil || len(resp.Kvs) == 0 {
		t.Fatalf("expected sticky key in etcd after sync: err=%v kvs=%d", err, len(resp.Kvs))
	}
	var got StickyEntry
	if json.Unmarshal(resp.Kvs[0].Value, &got) != nil || got.GWID != "gw-e2e" {
		t.Errorf("persisted sticky mismatch: %+v", got)
	}

	// Delete path: remove from sticky, mark dirty -> sync -> key gone from etcd.
	delete(s.sticky, ip)
	s.dirty[ip] = struct{}{}
	s.syncStickyToEtcd()
	resp, err = cli.Get(ctx, stickyPrefix+ip)
	if err != nil || len(resp.Kvs) != 0 {
		t.Errorf("expected sticky key deleted from etcd, got kvs=%d err=%v", len(resp.Kvs), err)
	}
}

// TestE2ERefreshOwnerAndHealth verifies the full re-list rebuilds healthByID,
// loadByID, registryByID, and the gwAddrs placement candidates from the
// /sandswap/health + /sandswap/load + /sandswap/gateway prefixes.
func TestE2ERefreshOwnerAndHealth(t *testing.T) {
	s, cli := dnsServerWithEtcd(t)
	gwID := fmt.Sprintf("gw-%d", time.Now().UnixNano()%1000)

	putJSON(t, cli, "/sandswap/health/"+gwID, map[string]interface{}{
		"node_count": 2,
	})
	putJSON(t, cli, "/sandswap/load/"+gwID, map[string]interface{}{
		"agg_duty_long": 0.55,
		"clean_vms":     4,
	})
	// Routing addresses live in the gateway registry (plain configuration key,
	// self-registered by the gateway); the re-list parses them into gwAddrs.
	putJSON(t, cli, "/sandswap/gateway/"+gwID, map[string]interface{}{
		"gateway_url": "https://10.0.1.1:3000",
		"stream_addr": "10.0.1.1:9998",
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s.refreshOwnerAndHealth(ctx)

	if h, ok := s.healthByID[gwID]; !ok || h.nodeCount != 2 {
		t.Errorf("healthByID not rebuilt: %+v ok=%v", h, ok)
	}
	if l, ok := s.loadByID[gwID]; !ok || l.aggDutyLong != 0.55 || l.cleanVMs != 4 {
		t.Errorf("loadByID not rebuilt: %+v ok=%v", l, ok)
	}
	if r, ok := s.registryByID[gwID]; !ok || r.gatewayURL != "https://10.0.1.1:3000" {
		t.Errorf("registryByID not rebuilt: %+v ok=%v", r, ok)
	}
	// gwAddrs: the self-registered addresses become the placement candidate.
	if info := s.gwAddrs[gwID]; info.AgentIP != "10.0.1.1" || info.StreamPort != 9998 {
		t.Errorf("gwAddrs not rebuilt from self-registration: %+v", info)
	}

	// Cleanup the seeded keys so they don't leak across test runs.
	cli.Delete(context.Background(), "/sandswap/health/"+gwID)
	cli.Delete(context.Background(), "/sandswap/load/"+gwID)
	cli.Delete(context.Background(), "/sandswap/gateway/"+gwID)
}

// TestE2EResolveOwnerFromEtcd verifies on-demand owner resolution: a
// /sandswap/owner/{id} key carrying gateway_id is returned; a missing owner
// returns an empty ownerResolution.
func TestE2EResolveOwnerFromEtcd(t *testing.T) {
	s, cli := dnsServerWithEtcd(t)
	sandfsID := fmt.Sprintf("sandfs-e2e-%d", time.Now().UnixNano()%1000)
	gwID := "gw-owner-test"

	putJSON(t, cli, "/sandswap/owner/"+sandfsID, map[string]interface{}{"gateway_id": gwID})

	if got, err := s.resolveOwnerFromEtcd(sandfsID); err != nil || got.gatewayID != gwID {
		t.Errorf("resolveOwnerFromEtcd: got (%+v, %v), want gateway_id %q", got, err, gwID)
	}
	if got, err := s.resolveOwnerFromEtcd("sandfs-nonexistent"); err != nil || got.gatewayID != "" {
		t.Errorf("missing owner: got (%+v, %v), want empty", got, err)
	}

	cli.Delete(context.Background(), "/sandswap/owner/"+sandfsID)
}

// TestE2EStalenessRouting verifies the owner-branch staleness gate and
// presence-directed routing against a real etcd:
//   - A FRESH owner resolves to the owner's registry gateway_url.
//   - A DEAD owner (no health key) with a mounted node whose presence names a
//     live peer routes to that peer (presence-directed recovery).
//   - A DEAD owner with an idle sandfs (no node_id) falls through (no answer).
//   - A DEAD owner whose presence still names the dead owner falls through.
func TestE2EStalenessRouting(t *testing.T) {
	s, cli := dnsServerWithEtcd(t)
	ctx := context.Background()
	suf := fmt.Sprintf("%d", time.Now().UnixNano())
	deadOwner, livePeer := "gw-dead-"+suf, "gw-live-"+suf
	nodeID := "node-stale-" + suf
	sandfsMounted := "sandfs-mounted-" + suf
	sandfsIdle := "sandfs-idle-" + suf
	sandfsFresh := "sandfs-fresh-" + suf
	sandfsDeadPresence := "sandfs-deadpresence-" + suf

	// Ownership keys.
	putJSON(t, cli, "/sandswap/owner/"+sandfsFresh, map[string]interface{}{"gateway_id": livePeer, "node_id": ""})
	putJSON(t, cli, "/sandswap/owner/"+sandfsMounted, map[string]interface{}{"gateway_id": deadOwner, "node_id": nodeID})
	putJSON(t, cli, "/sandswap/owner/"+sandfsIdle, map[string]interface{}{"gateway_id": deadOwner, "node_id": ""})
	putJSON(t, cli, "/sandswap/owner/"+sandfsDeadPresence, map[string]interface{}{"gateway_id": deadOwner, "node_id": nodeID + "-2"})

	// Presence: nodeID held by livePeer; nodeID+"-2" still held by deadOwner.
	cli.Put(ctx, "/sandswap/node/"+nodeID+"/presence", livePeer)
	cli.Put(ctx, "/sandswap/node/"+nodeID+"-2/presence", deadOwner)

	// Health: livePeer fresh, deadOwner absent (dead).
	putJSON(t, cli, "/sandswap/health/"+livePeer, map[string]interface{}{"last_healthy_ts": time.Now().Format(time.RFC3339), "node_count": 1})

	// Registry: both have gateway_urls.
	putJSON(t, cli, "/sandswap/gateway/"+deadOwner, map[string]interface{}{"gateway_url": "https://10.0.1.8:3000"})
	putJSON(t, cli, "/sandswap/gateway/"+livePeer, map[string]interface{}{"gateway_url": "https://10.0.1.9:3000"})

	// Populate healthByID from etcd (refreshOwnerAndHealth) + registryByID via the
	// watch handler (parsing the seeded JSON, as the watch would).
	s.refreshOwnerAndHealth(ctx)
	regResp, _ := cli.Get(ctx, "/sandswap/gateway/", clientv3.WithPrefix())
	for _, kv := range regResp.Kvs {
		s.handleGatewayEvent(string(kv.Key), string(kv.Value), false)
	}

	t.Cleanup(func() {
		for _, sf := range []string{sandfsFresh, sandfsMounted, sandfsIdle, sandfsDeadPresence} {
			cli.Delete(ctx, "/sandswap/owner/"+sf)
		}
		cli.Delete(ctx, "/sandswap/node/"+nodeID+"/presence")
		cli.Delete(ctx, "/sandswap/node/"+nodeID+"-2/presence")
		cli.Delete(ctx, "/sandswap/health/"+livePeer)
		cli.Delete(ctx, "/sandswap/gateway/"+deadOwner)
		cli.Delete(ctx, "/sandswap/gateway/"+livePeer)
	})

	// Fresh owner → resolves to the owner.
	if _, ip, ok, err := s.resolveSandfsOwner(sandfsFresh); err != nil || !ok || ip != "10.0.1.9" {
		t.Errorf("fresh owner: got (ip=%q ok=%v err=%v), want 10.0.1.9", ip, ok, err)
	}
	// Dead owner, mounted, presence → livePeer → routes to livePeer.
	if _, ip, ok, err := s.resolveSandfsOwner(sandfsMounted); err != nil || !ok || ip != "10.0.1.9" {
		t.Errorf("dead owner + presence→livePeer: got (ip=%q ok=%v err=%v), want 10.0.1.9", ip, ok, err)
	}
	// Dead owner, idle (no node) → no answer (falls through).
	if _, _, ok, err := s.resolveSandfsOwner(sandfsIdle); err != nil || ok {
		t.Errorf("dead owner + idle: expected no answer (err=%v)", err)
	}
	// Dead owner, presence still names the dead owner → no answer.
	if _, _, ok, err := s.resolveSandfsOwner(sandfsDeadPresence); err != nil || ok {
		t.Errorf("dead owner + presence→deadOwner: expected no answer (err=%v)", err)
	}
}

// TestE2ESelfPressureRouting verifies the self-pressure routing gate against a
// real etcd:
//   - A gateway whose load record carries self_pressured=true (sustained
//     gateway-process resource pressure) is excluded from the no-owner
//     scheduling fallback, the agent domain, and stream placement — even though
//     it is the busiest with clean capacity (node-side signals favor it).
//   - An OWNED sandfs still resolves to its pressured owner (affinity and
//     mount correctness trump placement; moving owned sandfs is load-shed's
//     job).
//   - Recovery: when the pressure clears (next load record says false), the
//     gateway becomes a candidate again.
//   - Bootstrap: a gateway with health + registry but no load record yet is
//     not excluded.
func TestE2ESelfPressureRouting(t *testing.T) {
	s, cli := dnsServerWithEtcd(t)
	s.schedConfig = config.NewWatchableConfig(SchedulingConfig{Policy: PolicyBinpack, DutyHard: 0})
	s.cfg.Domains = DomainsConfig{Stream: "stream-e2e.local"}
	ctx := context.Background()
	suf := fmt.Sprintf("%d", time.Now().UnixNano())
	gwHot, gwCalm, gwNew := "gw-pressured-"+suf, "gw-calm-"+suf, "gw-new-"+suf
	sandfsOwned := "sandfs-pressured-owned-" + suf
	sandfsUnowned := "sandfs-pressured-unowned-" + suf

	// gwHot: busiest, clean capacity, but self-pressured. gwCalm: calmer peer.
	// gwNew is NOT registered here: with 3 routable candidates the scheduling
	// pick enters the power-of-two-choices regime, which is RANDOM by design —
	// every deterministic assertion below (incl. recovery) is only valid in the
	// ≤2-candidate regime. gwNew joins at the bootstrap step instead.
	putJSON(t, cli, "/sandswap/health/"+gwHot, map[string]interface{}{"last_healthy_ts": time.Now().Format(time.RFC3339), "node_count": 2})
	putJSON(t, cli, "/sandswap/health/"+gwCalm, map[string]interface{}{"last_healthy_ts": time.Now().Format(time.RFC3339), "node_count": 2})
	putJSON(t, cli, "/sandswap/gateway/"+gwHot, map[string]interface{}{"gateway_url": "https://10.0.1.1:3000", "stream_addr": "10.0.1.1:9998"})
	putJSON(t, cli, "/sandswap/gateway/"+gwCalm, map[string]interface{}{"gateway_url": "https://10.0.1.2:3000", "stream_addr": "10.0.1.2:9998"})
	putJSON(t, cli, "/sandswap/load/"+gwHot, map[string]interface{}{
		"gateway_id": gwHot, "agg_duty_long": 0.9, "clean_vms": 5, "node_count": 2,
		"self_cpu_pct": 91.5, "self_mem_pct": 0.42, "self_inflight": 130, "self_pressured": true,
	})
	putJSON(t, cli, "/sandswap/load/"+gwCalm, map[string]interface{}{
		"gateway_id": gwCalm, "agg_duty_long": 0.5, "clean_vms": 3, "node_count": 2,
		"self_cpu_pct": 12.0, "self_mem_pct": 0.30, "self_inflight": 4, "self_pressured": false,
	})
	putJSON(t, cli, "/sandswap/owner/"+sandfsOwned, map[string]interface{}{"gateway_id": gwHot, "node_id": ""})

	// Hydrate the DNS view from etcd exactly as the watches would.
	s.refreshOwnerAndHealth(ctx)
	for _, prefix := range []string{"/sandswap/gateway/", "/sandswap/load/"} {
		resp, _ := cli.Get(ctx, prefix, clientv3.WithPrefix())
		for _, kv := range resp.Kvs {
			key := string(kv.Key)
			if strings.HasPrefix(key, "/sandswap/gateway/") {
				s.handleGatewayEvent(key, string(kv.Value), false)
			} else {
				s.handleLoadEvent(key, string(kv.Value), false)
			}
		}
	}

	t.Cleanup(func() {
		for _, gw := range []string{gwHot, gwCalm, gwNew} {
			cli.Delete(ctx, "/sandswap/health/"+gw)
			cli.Delete(ctx, "/sandswap/gateway/"+gw)
			cli.Delete(ctx, "/sandswap/load/"+gw)
		}
		cli.Delete(ctx, "/sandswap/owner/"+sandfsOwned)
	})

	// 1. No-owner fallback: the pressured gateway is skipped despite being the
	// busiest (binpack) with clean capacity.
	if host, ok := s.pickBySchedulingPolicy(); !ok || host != "10.0.1.2" {
		t.Errorf("fallback: expected gw-calm host, got %q ok=%v", host, ok)
	}
	// The unowned sandfs resolves through the same fallback.
	if _, _, ok, err := s.resolveSandfsOwner(sandfsUnowned); err != nil || ok {
		t.Errorf("unowned sandfs should have no owner answer (err=%v)", err)
	}

	// 2. Agent domain: picks the calm gateway.
	if gw := s.resolveAgent(); gw == nil || gw.AgentIP != "10.0.1.2" {
		t.Errorf("agent domain: expected 10.0.1.2, got %+v", gw)
	}

	// 3. Stream domain: a fresh sandlot is placed on the calm gateway.
	if gw := s.resolveStream("10.7.7.7"); gw == nil || gw.StreamIP != "10.0.1.2" {
		t.Errorf("stream domain: expected 10.0.1.2, got %+v", gw)
	}

	// 4. Owned sandfs: still resolves to the pressured OWNER (affinity).
	if _, ip, ok, err := s.resolveSandfsOwner(sandfsOwned); err != nil || !ok || ip != "10.0.1.1" {
		t.Errorf("owned by pressured gw: got (ip=%q ok=%v err=%v), want 10.0.1.1", ip, ok, err)
	}

	// 5. Recovery: pressure clears → the gateway is a candidate again and, as
	// the busiest under binpack, WINS the next fallback pick.
	putJSON(t, cli, "/sandswap/load/"+gwHot, map[string]interface{}{
		"gateway_id": gwHot, "agg_duty_long": 0.9, "clean_vms": 5, "node_count": 2,
		"self_cpu_pct": 20.0, "self_mem_pct": 0.30, "self_inflight": 5, "self_pressured": false,
	})
	resp, _ := cli.Get(ctx, "/sandswap/load/"+gwHot)
	s.handleLoadEvent("/sandswap/load/"+gwHot, string(resp.Kvs[0].Value), false)
	if host, ok := s.pickBySchedulingPolicy(); !ok || host != "10.0.1.1" {
		t.Errorf("recovery: expected gw-hot host, got %q ok=%v", host, ok)
	}

	// 6. Bootstrap: with only a (re-)pressured gateway and a no-record gateway,
	// the no-record gateway is picked (absent record = not excluded). gwNew
	// joins only NOW (see the setup note) — its health + registry are hydrated
	// through the same handlers the watch would drive.
	putJSON(t, cli, "/sandswap/load/"+gwHot, map[string]interface{}{
		"gateway_id": gwHot, "agg_duty_long": 0.9, "clean_vms": 5, "node_count": 2,
		"self_cpu_pct": 91.5, "self_mem_pct": 0.42, "self_inflight": 130, "self_pressured": true,
	})
	resp, _ = cli.Get(ctx, "/sandswap/load/"+gwHot)
	s.handleLoadEvent("/sandswap/load/"+gwHot, string(resp.Kvs[0].Value), false)
	putJSON(t, cli, "/sandswap/health/"+gwNew, map[string]interface{}{"last_healthy_ts": time.Now().Format(time.RFC3339), "node_count": 2})
	putJSON(t, cli, "/sandswap/gateway/"+gwNew, map[string]interface{}{"gateway_url": "https://10.0.1.3:3000", "stream_addr": "10.0.1.3:9998"})
	gwNewHealth, _ := json.Marshal(map[string]interface{}{"last_healthy_ts": time.Now().Format(time.RFC3339), "node_count": 2})
	gwNewRegistry, _ := json.Marshal(map[string]interface{}{"gateway_url": "https://10.0.1.3:3000", "stream_addr": "10.0.1.3:9998"})
	s.handleHealthEvent("/sandswap/health/"+gwNew, string(gwNewHealth), false)
	s.handleGatewayEvent("/sandswap/gateway/"+gwNew, string(gwNewRegistry), false)
	s.mu.Lock()
	delete(s.loadByID, gwCalm)
	delete(s.healthByID, gwCalm)
	delete(s.registryByID, gwCalm)
	delete(s.gwAddrs, gwCalm)
	s.mu.Unlock()
	if host, ok := s.pickBySchedulingPolicy(); !ok || host != "10.0.1.3" {
		t.Errorf("bootstrap: expected gw-new host, got %q ok=%v", host, ok)
	}
}

// TestE2ESchedulingExcludesZeroComputeGateways pins the exec-plane-only
// scheduling fence: a gateway whose health record carries node_count == 0
// (exactly what a human gateway looks like — no sandlots, no compute) must
// NEVER enter the no-owner scheduling pool, even with a valid, freshly
// refreshed routing address and no load record (bootstrap). Its exec-shaped
// twin (same records, node_count > 0) must be selectable. Together the two
// halves prove the discriminator is the compute gate — not address
// validation, staleness, or the clean-VM/load gate.
func TestE2ESchedulingExcludesZeroComputeGateways(t *testing.T) {
	s, cli := dnsServerWithEtcd(t)
	ctx := context.Background()
	suf := fmt.Sprintf("%d", time.Now().UnixNano())
	humanGw, execGw := "gw-human-"+suf, "gw-exec-"+suf

	// Human-gateway shape: self-registered addresses (so AgentIP validation
	// passes) + a health key with zero nodes. NO load record — the
	// "bootstrap" state, so the ONLY excluding gate is node_count == 0.
	putJSON(t, cli, "/sandswap/gateway/"+humanGw, map[string]interface{}{
		"gateway_url": "https://10.6.0.9:3100",
		"stream_addr": "10.6.0.9:9996",
	})
	putJSON(t, cli, "/sandswap/health/"+humanGw, map[string]interface{}{
		"node_count": 0,
	})

	// Exec-gateway shape: same address quality + compute and a passing load
	// record — the control that must remain selectable.
	putJSON(t, cli, "/sandswap/gateway/"+execGw, map[string]interface{}{
		"gateway_url": "https://10.6.0.10:3000",
		"stream_addr": "10.6.0.10:9998",
	})
	putJSON(t, cli, "/sandswap/health/"+execGw, map[string]interface{}{
		"node_count": 2,
	})
	putJSON(t, cli, "/sandswap/load/"+execGw, map[string]interface{}{
		"agg_duty_long": 0.0,
		"clean_vms":     3,
	})
	t.Cleanup(func() {
		for _, k := range []string{"gateway", "health", "load"} {
			_, _ = cli.Delete(ctx, "/sandswap/"+k+"/"+humanGw)
			_, _ = cli.Delete(ctx, "/sandswap/"+k+"/"+execGw)
		}
	})

	s.refreshOwnerAndHealth(ctx)

	// Precondition: the human gateway's address parsed — without this the
	// exclusion below would be vacuous (excluded by address validation
	// instead of the compute gate).
	if a := s.gwAddrs[humanGw].AgentIP; a == "" {
		t.Fatalf("precondition broken: human gateway address did not parse into gwAddrs — test would pass vacuously")
	}

	host, ok := s.pickBySchedulingPolicy()
	if !ok {
		t.Fatalf("no scheduling candidate — the exec-shaped gateway must be selectable")
	}
	if host == "10.6.0.9" {
		t.Errorf("zero-compute (human) gateway %q scheduled for sandfs resolution — exec-plane-only fence broken", humanGw)
	}
	if host != "10.6.0.10" {
		t.Errorf("expected the exec gateway host 10.6.0.10, got %q", host)
	}
}

// TestE2ENewDNSServerInitialRefresh verifies the constructor's SYNCHRONOUS
// initial refresh: health/registry state is present the instant NewDNSServer
// returns — before Start() — closing the cold-start window where a query
// arriving with empty maps would judge every gateway dead (stream SERVFAIL)
// and spill owned sandfs onto non-owner gateways via the scheduling fallback.
func TestE2ENewDNSServerInitialRefresh(t *testing.T) {
	cli := dnsEtcdClient(t)
	gw := fmt.Sprintf("gw-init-%d", time.Now().UnixNano()%100000)
	putJSON(t, cli, "/sandswap/health/"+gw, map[string]interface{}{
		"last_healthy_ts": time.Now().Format(time.RFC3339),
		"node_count":      2,
	})
	putJSON(t, cli, "/sandswap/gateway/"+gw, map[string]interface{}{
		"gateway_url": "https://10.0.4.5:3000",
		"stream_addr": "10.0.4.5:9998",
	})
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		cli.Delete(ctx, "/sandswap/health/"+gw)
		cli.Delete(ctx, "/sandswap/gateway/"+gw)
	})

	cfg := &Config{
		ListenAddr: "127.0.0.1:0",
		Etcd:       dnsEtcdEndpoint,
		Domains:    DomainsConfig{Stream: "stream.sandswap.local"},
	}
	s, err := NewDNSServer(cfg)
	if err != nil {
		t.Fatalf("NewDNSServer: %v", err)
	}
	defer s.Close()

	s.mu.RLock()
	h, hasHealth := s.healthByID[gw]
	_, hasReg := s.registryByID[gw]
	ip := s.gwAddrs[gw].AgentIP
	s.mu.RUnlock()
	if !hasHealth || h.nodeCount != 2 {
		t.Errorf("healthByID not refreshed at construction: %+v ok=%v", h, hasHealth)
	}
	if !hasReg || ip != "10.0.4.5" {
		t.Errorf("registry/gwAddrs not refreshed at construction: ip=%q ok=%v", ip, hasReg)
	}
}

// TestE2EPresenceRouteCache verifies the presence read cache against a real
// etcd: the first dead-owner query fetches and caches the holder; a query
// within the TTL is served from cache even after the key is DELETED (no
// re-read); past the TTL the absence is observed and the answer falls through
// to the scheduling fallback.
func TestE2EPresenceRouteCache(t *testing.T) {
	s, cli := dnsServerWithEtcd(t)
	node := fmt.Sprintf("node-pc-%d", time.Now().UnixNano()%100000)
	s.mu.Lock()
	s.healthByID["gw-peer"] = ownerHealth{nodeCount: 1, lastHealthyTS: time.Now()}
	s.registryByID["gw-peer"] = gatewayRegistry{gatewayURL: "https://10.0.3.4:3000"}
	s.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := cli.Put(ctx, "/sandswap/node/"+node+"/presence", "gw-peer"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cli.Delete(context.Background(), "/sandswap/node/"+node+"/presence") })

	if _, ip, ok := s.presenceRoute(node, "gw-dead"); !ok || ip != "10.0.3.4" {
		t.Fatalf("first read: expected holder routing, got ip=%q ok=%v", ip, ok)
	}
	// Delete the key: within the TTL the cached holder still routes.
	if _, err := cli.Delete(context.Background(), "/sandswap/node/"+node+"/presence"); err != nil {
		t.Fatal(err)
	}
	if _, ip, ok := s.presenceRoute(node, "gw-dead"); !ok || ip != "10.0.3.4" {
		t.Fatalf("cached read within TTL: expected holder routing, got ip=%q ok=%v", ip, ok)
	}
	// Past the TTL the absence is observed → fall through.
	time.Sleep(presenceCacheTTL + 150*time.Millisecond)
	if _, _, ok := s.presenceRoute(node, "gw-dead"); ok {
		t.Error("post-TTL read of a deleted key must fall through")
	}
}

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

//go:build stats_e2e

// E2e test of the distributed /stats aggregation against a REAL etcd: verifies
// BuildStatsReport merges /sandswap/{load,health,gateway}/ keys by gateway id,
// marks Healthy from the health key, and rolls up totals. Requires a local etcd
// at 127.0.0.1:2379. Run via: etcd & then `go test -tags stats_e2e ./handler/`.
package handler_test

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"gateway/handler"
	"gateway/lease"
	"gateway/stats"

	clientv3 "go.etcd.io/etcd/client/v3"
)

const statsEtcdEndpoint = "http://127.0.0.1:2379"

func newStatsEtcdClient(t *testing.T) *clientv3.Client {
	t.Helper()
	cli, err := clientv3.New(clientv3.Config{
		Endpoints:   []string{statsEtcdEndpoint},
		DialTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("etcd client: %v", err)
	}
	// Wipe the sandswap keyspace so the test is hermetic.
	_, _ = cli.Delete(context.Background(), "/sandswap/", clientv3.WithPrefix())
	t.Cleanup(func() {
		_, _ = cli.Delete(context.Background(), "/sandswap/", clientv3.WithPrefix())
		cli.Close()
	})
	return cli
}

func putJSON(t *testing.T, cli *clientv3.Client, key string, val any) {
	t.Helper()
	data, err := json.Marshal(val)
	if err != nil {
		t.Fatalf("marshal %s: %v", key, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := cli.Put(ctx, key, string(data)); err != nil {
		t.Fatalf("put %s: %v", key, err)
	}
}

// TestEtcdStatsReportAggregate verifies the distributed path: gw-1 (healthy,
// with load+health+registry, local — uses the in-memory unmount snapshot),
// gw-2 (healthy, just booted, no load key yet), gw-3 (dead — stale load key, no
// health key → Healthy=false). gw-1 and gw-3 carry persisted unmount-stats keys
// so peer aggregation is exercised.
func TestEtcdStatsReportAggregate(t *testing.T) {
	cli := newStatsEtcdClient(t)

	lv1 := lease.LoadValue{
		GatewayID: "gw-1", NodeCount: 1, CleanVMs: 2, AggDutyLong: 0.3,
		SelfCPUPct: 91.5, SelfMemPct: 0.42, SelfInflight: 13, SelfPressured: true,
		Nodes: []lease.NodeLoad{{NodeID: "node-1", CleanVMs: 2, TotalVMs: 3, ActiveSandfs: 1}},
	}
	putJSON(t, cli, "/sandswap/load/gw-1", lv1)
	putJSON(t, cli, "/sandswap/health/gw-1", lease.GatewayHealthValue{LastHealthyTS: "x", NodeCount: 1})
	putJSON(t, cli, "/sandswap/gateway/gw-1", lease.GatewayRegistryValue{GatewayURL: "http://127.0.0.1:3000", StreamAddr: "127.0.0.1:9998"})

	putJSON(t, cli, "/sandswap/health/gw-2", lease.GatewayHealthValue{LastHealthyTS: "x", NodeCount: 1})
	putJSON(t, cli, "/sandswap/gateway/gw-2", lease.GatewayRegistryValue{GatewayURL: "http://127.0.0.1:3010", StreamAddr: "127.0.0.1:9999"})

	lv3 := lease.LoadValue{
		GatewayID: "gw-3", NodeCount: 2, CleanVMs: 0,
		Nodes: []lease.NodeLoad{{NodeID: "n-a", TotalVMs: 2}, {NodeID: "n-b", TotalVMs: 2}},
	}
	putJSON(t, cli, "/sandswap/load/gw-3", lv3)

	// Persisted unmount-stats for gw-1 (overridden by the local in-memory
	// snapshot below) and gw-3 (peer, read from etcd). gw-2 has none.
	putJSON(t, cli, "/sandswap/unmount-stats/gw-1", stats.GatewayUnmountStats{
		GatewayID: "gw-1",
		Nodes:     []stats.NodeUnmountStats{{NodeID: "node-1", MountCount: 99}}, // stale — overridden
	})
	putJSON(t, cli, "/sandswap/unmount-stats/gw-3", stats.GatewayUnmountStats{
		GatewayID: "gw-3",
		Nodes:     []stats.NodeUnmountStats{{NodeID: "n-a", UnmountCount: 7, Under5ms: 3}},
	})

	// The local gateway (gw-1) injects a fresh in-memory snapshot.
	localSnap := []stats.NodeUnmountStats{{NodeID: "node-1", MountCount: 5, UnmountCount: 4}}

	rep, err := handler.BuildStatsReport(context.Background(), cli, "gw-1", nil, localSnap, false, nil)
	if err != nil {
		t.Fatalf("BuildStatsReport: %v", err)
	}
	if len(rep.Gateways) != 3 {
		t.Fatalf("gateways: got %d, want 3", len(rep.Gateways))
	}
	byID := map[string]handler.GatewayStats{}
	for _, g := range rep.Gateways {
		byID[g.GatewayID] = g
	}
	if g := byID["gw-1"]; !g.Healthy || g.CleanVMs != 2 || g.TotalVMs != 3 || g.GatewayURL != "http://127.0.0.1:3000" {
		t.Errorf("gw-1: %+v", g)
	}
	// Self-pressure signals surface in the ops view.
	if g := byID["gw-1"]; !g.SelfPressured || g.SelfCPUPct != 91.5 || g.SelfMemPct != 0.42 || g.SelfInflight != 13 {
		t.Errorf("gw-1 self-pressure: %+v", g)
	}
	// gw-1 unmount: local snapshot overrides the stale persisted value.
	if g := byID["gw-1"]; len(g.UnmountStats) != 1 || g.UnmountStats[0].MountCount != 5 || g.UnmountStats[0].UnmountCount != 4 {
		t.Errorf("gw-1 unmount (local override): %+v", g.UnmountStats)
	}
	if g := byID["gw-2"]; !g.Healthy || g.TotalVMs != 0 {
		t.Errorf("gw-2 (no load key): %+v", g)
	}
	// gw-2 has no unmount-stats key → field omitted.
	if g := byID["gw-2"]; g.UnmountStats != nil {
		t.Errorf("gw-2 unmount should be nil, got %+v", g.UnmountStats)
	}
	if g := byID["gw-3"]; g.Healthy {
		t.Errorf("gw-3 should be unhealthy (no health key): %+v", g)
	}
	// gw-3 unmount: peer, read from the persisted etcd value.
	if g := byID["gw-3"]; len(g.UnmountStats) != 1 || g.UnmountStats[0].NodeID != "n-a" || g.UnmountStats[0].UnmountCount != 7 || g.UnmountStats[0].Under5ms != 3 {
		t.Errorf("gw-3 unmount (peer persisted): %+v", g.UnmountStats)
	}
	if rep.Totals.CleanVMs != 2 || rep.Totals.TotalVMs != 7 || rep.Totals.GatewayCnt != 3 {
		t.Errorf("totals: %+v", rep.Totals)
	}
	if rep.Totals.InUseVMs != 5 {
		t.Errorf("in_use: %d, want 5", rep.Totals.InUseVMs)
	}

	// with the agent-listener policy on, EVERY gateway's tenant
	// identifiers are gone — gw-3 here is a PEER, whose snapshot arrives
	// verbatim from its persisted /sandswap/unmount-stats/gw-3 key (the exact
	// path that leaked cross-tenant ids before the projection-time sweep), and
	// gw-1's local snapshot rides the same pass. Aggregates survive.
	putJSON(t, cli, "/sandswap/unmount-stats/gw-3", stats.GatewayUnmountStats{
		GatewayID: "gw-3",
		Nodes: []stats.NodeUnmountStats{{
			NodeID: "n-a", UnmountCount: 7, Under5ms: 3,
			TopSlow: []stats.SlowEntry{{SandfsID: "sf-victim", Command: "echo C-secret", GatewayMs: 9}},
		}},
	})
	redacted, err := handler.BuildStatsReport(context.Background(), cli, "gw-1", nil, []stats.NodeUnmountStats{{
		NodeID: "node-1", UnmountCount: 4,
		TopSlow: []stats.SlowEntry{{SandfsID: "sf-local", Command: "echo local"}},
	}}, true, nil)
	if err != nil {
		t.Fatalf("BuildStatsReport(redact): %v", err)
	}
	seenPeer := false
	for _, g := range redacted.Gateways {
		for _, n := range g.UnmountStats {
			for _, s := range n.TopSlow {
				if s.SandfsID != "" || s.Command != "" {
					t.Fatalf("tenant fields leaked for gateway %s: %+v", g.GatewayID, s)
				}
				if g.GatewayID == "gw-3" && s.GatewayMs == 9 {
					seenPeer = true
				}
			}
		}
	}
	if !seenPeer {
		t.Fatal("the peer's aggregate latency entry must survive redaction")
	}
	fmt.Println("ok")
}

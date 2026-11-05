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

package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"

	"gateway/lease"
	"gateway/pool"
	"gateway/stats"
)

// StatsReport is the unified cluster-stats shape returned by GET /stats and
// consumed by `sandctl pool`. It is identical in single-node (MemoryStore) and
// distributed (etcd) modes: single-node produces a one-gateway report from the
// local pool manager; distributed aggregates every gateway's
// /sandswap/load + /sandswap/health + /sandswap/gateway keys from etcd — the
// same keys the DNS reads, so the views match by construction.
type StatsReport struct {
	Gateways []GatewayStats `json:"gateways"`
	Totals   StatsTotals    `json:"totals"`
	// Maintenance reports the service-refusal switch (see
	// gateway/maintenance); omitted when the switch is not wired in this
	// process. Rotation tooling polls it to confirm the window is open before
	// moving any directory.
	Maintenance *MaintenanceState `json:"maintenance,omitempty"`
	// Rotation reports the volume-seed rotation window switch: while on, SandFS
	// creation is refused fleet-wide (a creation would be named in the
	// generation being retired). Omitted when unwired in this process.
	Rotation *MaintenanceState `json:"rotation,omitempty"`
	// ProvSeeds lists every connected prov instance's naming generations
	// (fingerprints only). A rotation reads this to prove the whole prov fleet
	// converged before the maintenance window closes: storage ops are spread
	// across prov instances, so one straggler would silently split tenants.
	ProvSeeds []ProvSeedState `json:"prov_seeds,omitempty"`
	// EgressBindings lists each connected node's egress identity-binding mode
	// ("shm"/"bpf"/"routed-ipv6", or "none" = guest traffic is NOT attributable
	// to an agent). Operators use it to assert that production nodes run with
	// the enabler on (the sandlot refuses to start unbound only when
	// require_egress_binding is set).
	EgressBindings []EgressBindingState `json:"egress_bindings,omitempty"`
}

// EgressBindingState is one node's egress identity-binding mode as projected
// into /stats.
type EgressBindingState struct {
	NodeID  string `json:"node_id"`
	Binding string `json:"binding"`
}

// ProvSeedState is one prov instance's naming-generation state as projected
// into /stats. Fingerprints only — never seed material.
type ProvSeedState struct {
	NodeID           string `json:"node_id"`
	Generation       string `json:"generation,omitempty"`
	Staged           bool   `json:"staged,omitempty"`
	StagedGeneration string `json:"staged_generation,omitempty"`
	// AgeSec is the age of the heartbeat that carried it: a stale entry means
	// the instance stopped reporting, so its generation is no longer evidence
	// of anything.
	AgeSec int64 `json:"age_sec"`
}

// MaintenanceState mirrors the maintenance switch for /stats.
type MaintenanceState struct {
	Refusing bool   `json:"refusing"`
	Reason   string `json:"reason,omitempty"`
}

// StatsTotals is the cluster-wide rollup.
type StatsTotals struct {
	CleanVMs   uint32 `json:"clean_vms"`
	TotalVMs   uint32 `json:"total_vms"`
	InUseVMs   uint32 `json:"in_use_vms"`
	NodeCount  int    `json:"node_count"`
	GatewayCnt int    `json:"gateway_count"`
}

// GatewayStats is one gateway's contribution to the report. Nodes reuses
// lease.NodeLoad (the /sandswap/load per-node contract shape).
type GatewayStats struct {
	GatewayID   string  `json:"gateway_id"`
	Healthy     bool    `json:"healthy"`     // /sandswap/health/{gw} fresh within the claim-dead guard
	GatewayURL  string  `json:"gateway_url"` // /sandswap/gateway/{gw}
	StreamAddr  string  `json:"stream_addr"`
	NodeCount   int     `json:"node_count"`
	CleanVMs    uint32  `json:"clean_vms"`
	TotalVMs    uint32  `json:"total_vms"`
	AggDutyLong float64 `json:"agg_duty_long"`
	// Self-pressure signals from the gateway's own process (see
	// lease.SelfPressureMonitor): sustained process CPU (vs GOMAXPROCS) and
	// managed-memory/soft-limit ratio; self_pressured is the DNS routing
	// eligibility gate; self_inflight is observability-only.
	SelfCPUPct    float64 `json:"self_cpu_pct"`
	SelfMemPct    float64 `json:"self_mem_pct"`
	SelfInflight  uint32  `json:"self_inflight"`
	SelfPressured bool    `json:"self_pressured"`
	// LastHealthyTS is the health key's last_healthy_ts (RFC3339); StaleSec is
	// how many seconds since it. Ops-visible staleness: the health key has no
	// lease, so staleness IS the liveness signal — a value going stale means
	// the owner is failing to refresh (GC pause / etcd trouble); past the
	// claim-dead guard Healthy flips to false.
	LastHealthyTS string           `json:"last_healthy_ts,omitempty"`
	StaleSec      int64            `json:"stale_sec"`
	Nodes         []lease.NodeLoad `json:"nodes,omitempty"`
	// UnmountStats is this gateway's per-node unmount latency/counters
	// (counters + top-10 slowest). The LOCAL gateway uses a fresh in-memory
	// snapshot; PEER gateways use their persisted
	// /sandswap/unmount-stats/{gw} etcd value (up to the last persist interval).
	// Aggregated for all gateways, same as load/health/registry. nil/omitted
	// when a gateway has no unmount stats (disabled or never persisted).
	UnmountStats []stats.NodeUnmountStats `json:"unmount_stats,omitempty"`
}

// BuildStatsReport assembles the cluster stats report.
//
//   - cli == nil (single-node MemoryStore): the report is built from the local
//     pool manager only — one "gateway" entry (self), Healthy=true, nodes from
//     pm.LoadSnapshot() + pm.NodeCleanCounts().
//   - cli != nil (distributed exec/human): the report aggregates every gateway's
//     /sandswap/load/{gw} (pool counts + per-node load), /sandswap/health/{gw}
//     (liveness), /sandswap/gateway/{gw} (routing addrs), and
//     /sandswap/unmount-stats/{gw} (per-node unmount latency/counters) from etcd.
//     The local gateway's own load key is included like any peer (the load
//     publisher writes it). This mirrors dns/resolver.go:refreshOwnerAndHealth —
//     same keys, same parse — so /stats and the DNS see the same cluster view.
//
// Unmount stats are aggregated for ALL gateways, same as load/health/registry:
//   - the LOCAL gateway's entry uses localUnmountSnapshot (fresh from the
//     in-memory recorder, real-time);
//   - PEER gateways use their persisted /sandswap/unmount-stats/{gw} snapshot
//     (up to the last persist interval, default 600s).
//
// The DNS never reads unmount stats (it only consumes /sandswap/load); the
// unmount-stats key exists solely for /stats aggregation + ops offline inspection.
//
// localUnmountSnapshot is this gateway's own unmount stats snapshot (from the
// local recorder). nil = unmount stats disabled (field omitted on the local entry).
//
// redactTenantIDs is the LISTENER's tenant-visibility policy, applied here —
// at projection time — to EVERY gateway's unmount snapshot(): the local
// snapshot arrives from the caller's recorder and the PEER snapshots arrive
// verbatim from their persisted /sandswap/unmount-stats/{gw} key, whose
// top_slow entries carry the tenant's sandfs_id and a 120-char command excerpt
// (code, paths, embedded tokens). Redacting only the local snapshot
// left every OTHER gateway's cross-tenant identifiers readable on the exec
// mode agent listener, which has no auth in front of /stats. Aggregate
// counters and latency fields are the metric's purpose and survive; the
// authenticated human API passes false and keeps the full view.
func BuildStatsReport(ctx context.Context, cli *clientv3.Client, localGWID string, pm *pool.Manager, localUnmountSnapshot []stats.NodeUnmountStats, redactTenantIDs bool, logger *slog.Logger) (StatsReport, error) {
	var (
		rep StatsReport
		err error
	)
	if cli == nil {
		rep = localStatsReport(localGWID, pm, localUnmountSnapshot)
	} else {
		rep, err = etcdStatsReport(ctx, cli, localGWID, localUnmountSnapshot, logger)
	}
	if redactTenantIDs {
		redactUnmountTenantIDs(&rep)
	}
	return rep, err
}

// redactUnmountTenantIDs blanks the per-tenant fields (top_slow sandfs_id +
// command excerpt) of every gateway's unmount projection in place. One
// implementation for local and peer entries alike — see BuildStatsReport.
func redactUnmountTenantIDs(rep *StatsReport) {
	for i := range rep.Gateways {
		snap := rep.Gateways[i].UnmountStats
		for j := range snap {
			for k := range snap[j].TopSlow {
				snap[j].TopSlow[k].SandfsID = ""
				snap[j].TopSlow[k].Command = ""
			}
		}
	}
}

// localStatsReport builds a one-gateway report from the local pool manager
// (single-node MemoryStore mode). Same shape as the distributed report.
// Iterates over ALL connected nodes (via NodeCleanCounts, which covers every
// node's capacity) — not just nodes with metrics — so a freshly-booted node
// with no heartbeat metrics yet still appears with its clean/total counts.
// Metrics (duty/host) are merged in when available.
func localStatsReport(gatewayID string, pm *pool.Manager, localUnmountSnapshot []stats.NodeUnmountStats) StatsReport {
	rep := StatsReport{}
	if pm == nil {
		rep.Totals.GatewayCnt = 1
		rep.Gateways = []GatewayStats{{GatewayID: gatewayID, Healthy: true, UnmountStats: localUnmountSnapshot}}
		return rep
	}
	counts := pm.NodeCleanCounts() // all nodes (capacity-based)
	snap := pm.LoadSnapshot()      // nodes with metrics (may be a subset)

	gw := GatewayStats{
		GatewayID: gatewayID,
		Healthy:   true,
		NodeCount: len(counts),
	}
	var clean, total uint32
	nodeIDs := make([]string, 0, len(counts))
	for id := range counts {
		nodeIDs = append(nodeIDs, id)
	}
	sort.Strings(nodeIDs)
	for _, id := range nodeIDs {
		c := counts[id]
		nl := lease.NodeLoad{
			NodeID:   id,
			CleanVMs: c[0],
			TotalVMs: c[1],
		}
		if m, ok := snap[id]; ok {
			nl.DutyLong = m.DutyLong
			nl.DutyShort = m.DutyShort
			nl.DutyDaily = m.DutyDaily
			nl.DutyVar = m.DutyVar
			nl.HostCPU = m.HostCPU
			nl.HostMemAvail = m.HostMemAvailMB
			nl.ActiveSandfs = m.ActiveSandfs
			nl.PeakConcurrentExecs = m.PeakConcurrentExecs
			nl.SlotWaitMS = m.SlotWaitMS
			nl.SlotWaitEvents = m.SlotWaitEvents
			nl.RecycleTriggers = m.RecycleTriggers
			nl.StrandedReservationsMB = m.StrandedReservationsMB
			nl.StrandedCIDs = m.StrandedCIDs
		}
		gw.Nodes = append(gw.Nodes, nl)
		clean += c[0]
		total += c[1]
	}
	gw.CleanVMs = clean
	gw.TotalVMs = total
	gw.AggDutyLong = avgDuty(snap)
	gw.UnmountStats = localUnmountSnapshot

	rep.Gateways = []GatewayStats{gw}
	rep.Totals = StatsTotals{
		CleanVMs:   clean,
		TotalVMs:   total,
		InUseVMs:   total - clean,
		NodeCount:  len(counts),
		GatewayCnt: 1,
	}
	return rep
}

// etcdStatsReport aggregates /sandswap/{load,health,gateway,unmount-stats}/
// from etcd into a multi-gateway report. Each gateway with a load OR health OR
// registry OR unmount-stats key appears; load provides the pool counts, health
// provides liveness, the registry provides routing addrs, unmount-stats provides
// per-node unmount latency/counters. The LOCAL gateway's unmount entry uses
// localGWUnmountSnapshot (fresh in-memory); PEERS use their persisted
// /sandswap/unmount-stats/{gw} snapshot (up to the last persist interval).
func etcdStatsReport(ctx context.Context, cli *clientv3.Client, localGWID string, localGWUnmountSnapshot []stats.NodeUnmountStats, logger *slog.Logger) (StatsReport, error) {
	// Collect every gateway id seen across the prefixes.
	gwOrder := []string{}
	gwSet := map[string]struct{}{}

	loads := map[string]lease.LoadValue{}
	if resp, err := cli.Get(ctx, "/sandswap/load/", clientv3.WithPrefix()); err == nil {
		for _, kv := range resp.Kvs {
			gwID := string(kv.Key)[len("/sandswap/load/"):]
			var lv lease.LoadValue
			if err := json.Unmarshal(kv.Value, &lv); err == nil {
				loads[gwID] = lv
				if _, ok := gwSet[gwID]; !ok {
					gwSet[gwID] = struct{}{}
					gwOrder = append(gwOrder, gwID)
				}
			}
		}
	} else if logger != nil {
		logger.Warn("stats: etcd get load prefix", "error", err)
	}

	// healths carries liveness; healthTS carries the last_healthy_ts value for
	// staleness reporting. The health key has no lease, so Healthy is judged by
	// staleness: fresh within the claim-dead guard = healthy; a corrupt or
	// missing timestamp stays healthy (fail-alive, same as the consumers in
	// gateway/lease).
	healths := map[string]bool{}
	healthTS := map[string]string{}
	if resp, err := cli.Get(ctx, "/sandswap/health/", clientv3.WithPrefix()); err == nil {
		for _, kv := range resp.Kvs {
			gwID := string(kv.Key)[len("/sandswap/health/"):]
			healths[gwID] = true
			var hv lease.GatewayHealthValue
			if json.Unmarshal(kv.Value, &hv) == nil {
				healthTS[gwID] = hv.LastHealthyTS
				if t, perr := time.Parse(time.RFC3339, hv.LastHealthyTS); perr == nil {
					if time.Since(t) > lease.DefaultClaimDeadGuard {
						healths[gwID] = false // stale past the guard → dead
					}
				}
			}
			if _, ok := gwSet[gwID]; !ok {
				gwSet[gwID] = struct{}{}
				gwOrder = append(gwOrder, gwID)
			}
		}
	} else if logger != nil {
		logger.Warn("stats: etcd get health prefix", "error", err)
	}

	registries := map[string]lease.GatewayRegistryValue{}
	if resp, err := cli.Get(ctx, "/sandswap/gateway/", clientv3.WithPrefix()); err == nil {
		for _, kv := range resp.Kvs {
			gwID := string(kv.Key)[len("/sandswap/gateway/"):]
			var rv lease.GatewayRegistryValue
			if err := json.Unmarshal(kv.Value, &rv); err == nil {
				registries[gwID] = rv
				if _, ok := gwSet[gwID]; !ok {
					gwSet[gwID] = struct{}{}
					gwOrder = append(gwOrder, gwID)
				}
			}
		}
	} else if logger != nil {
		logger.Warn("stats: etcd get gateway prefix", "error", err)
	}

	// Per-gateway unmount stats snapshots. The local gateway's snapshot is
	// injected fresh from localGWUnmountSnapshot (real-time); peers use the
	// persisted value here (up to the last persist interval).
	unmountSnaps := map[string][]stats.NodeUnmountStats{}
	if resp, err := cli.Get(ctx, "/sandswap/unmount-stats/", clientv3.WithPrefix()); err == nil {
		for _, kv := range resp.Kvs {
			gwID := string(kv.Key)[len("/sandswap/unmount-stats/"):]
			var uv stats.GatewayUnmountStats
			if err := json.Unmarshal(kv.Value, &uv); err == nil {
				unmountSnaps[gwID] = uv.Nodes
				if _, ok := gwSet[gwID]; !ok {
					gwSet[gwID] = struct{}{}
					gwOrder = append(gwOrder, gwID)
				}
			}
		}
	} else if logger != nil {
		logger.Warn("stats: etcd get unmount-stats prefix", "error", err)
	}

	sort.Strings(gwOrder)

	rep := StatsReport{}
	var totClean, totTotal uint32
	totNodes := 0
	for _, gwID := range gwOrder {
		gw := GatewayStats{
			GatewayID:  gwID,
			Healthy:    healths[gwID],
			GatewayURL: registries[gwID].GatewayURL,
			StreamAddr: registries[gwID].StreamAddr,
		}
		if ts := healthTS[gwID]; ts != "" {
			gw.LastHealthyTS = ts
			if t, perr := time.Parse(time.RFC3339, ts); perr == nil {
				if d := time.Since(t); d > 0 {
					gw.StaleSec = int64(d.Seconds())
				}
			}
		}
		if lv, ok := loads[gwID]; ok {
			gw.NodeCount = lv.NodeCount
			gw.CleanVMs = lv.CleanVMs
			gw.AggDutyLong = lv.AggDutyLong
			gw.SelfCPUPct = lv.SelfCPUPct
			gw.SelfMemPct = lv.SelfMemPct
			gw.SelfInflight = lv.SelfInflight
			gw.SelfPressured = lv.SelfPressured
			gw.Nodes = lv.Nodes
			// total_vms = sum of per-node TotalVMs (LoadValue carries clean_vms
			// at the top level but not total; derive from nodes).
			var t uint32
			for _, n := range lv.Nodes {
				t += n.TotalVMs
			}
			gw.TotalVMs = t
			// Normalize node order to node_id ascending so /stats output is stable
			// and aligns with unmount_stats (also node_id-sorted) for a human
			// reading both arrays by index. loadpublish writes Nodes in map-iteration
			// order (non-deterministic); this sorts only the /stats view, not the
			// persisted load key.
			sort.Slice(gw.Nodes, func(i, j int) bool { return gw.Nodes[i].NodeID < gw.Nodes[j].NodeID })
		}
		// Unmount stats: local gateway uses the fresh in-memory snapshot; peers
		// use their persisted /sandswap/unmount-stats/{gw} value.
		if gwID == localGWID && localGWUnmountSnapshot != nil {
			gw.UnmountStats = localGWUnmountSnapshot
		} else if us, ok := unmountSnaps[gwID]; ok {
			gw.UnmountStats = us
		}
		totClean += gw.CleanVMs
		totTotal += gw.TotalVMs
		totNodes += gw.NodeCount
		rep.Gateways = append(rep.Gateways, gw)
	}
	rep.Totals = StatsTotals{
		CleanVMs:   totClean,
		TotalVMs:   totTotal,
		InUseVMs:   totTotal - totClean,
		NodeCount:  totNodes,
		GatewayCnt: len(rep.Gateways),
	}
	return rep, nil
}

// avgDuty returns the mean duty_long across a node snapshot (0 if empty).
func avgDuty(snap map[string]pool.NodeMetrics) float64 {
	if len(snap) == 0 {
		return 0
	}
	var sum float64
	for _, m := range snap {
		sum += m.DutyLong
	}
	return sum / float64(len(snap))
}

// renderStatsJSON marshals a StatsReport for the /stats handler. Errors are
// impossible in practice (struct of plain types) but handled defensively.
func renderStatsJSON(rep StatsReport) ([]byte, error) {
	data, err := json.Marshal(rep)
	if err != nil {
		return nil, fmt.Errorf("marshal stats: %w", err)
	}
	return data, nil
}

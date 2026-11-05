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

// LoadValue is the JSON stored at /sandswap/load/{gateway_id}. Each exec gateway
// rewrites it every ~2s under a TTL lease. The DNS module (a separate Go module)
// watches this key for owner-aware routing; the human gateway reads it for the
// global /stats view. These field names are the cross-module contract — the DNS
// side mirrors them.
type LoadValue struct {
	GatewayID   string  `json:"gateway_id"`
	LastUpdate  string  `json:"last_update"`
	AggDutyLong float64 `json:"agg_duty_long"`   // mean of per-node duty_long
	MaxDuty     float64 `json:"max_duty_window"` // max of per-node duty_long
	CleanVMs    uint32  `json:"clean_vms"`       // sum of per-node CLEAN VMs (routing capacity)
	NodeCount   int     `json:"node_count"`
	// Self-pressure (process-scoped, sustained — see SelfPressureMonitor):
	// the DNS gates routing eligibility on self_pressured; the other three are
	// observability (self_mem_pct is 0 when no soft memory limit is set).
	SelfCPUPct    float64 `json:"self_cpu_pct"`   // EWMA τ=30s, % of GOMAXPROCS
	SelfMemPct    float64 `json:"self_mem_pct"`   // EWMA τ=10s, managed-mem / soft limit
	SelfInflight  uint32  `json:"self_inflight"`  // agent-listener in-flight (observability only)
	SelfPressured bool    `json:"self_pressured"` // sustained self-pressure gate signal
	// Routing addresses deliberately live in /sandswap/gateway/{gw}, NOT here —
	// this key is lease-bound and disappears on death, and a peer's address must
	// survive for the shed path (HasIdlePeer) to resolve where to route.
	Nodes []NodeLoad `json:"nodes,omitempty"`
}

// NodeLoad is one sandlot node's scheduling signals within a LoadValue.
type NodeLoad struct {
	NodeID       string  `json:"node_id"`
	DutyLong     float64 `json:"duty_long"`
	DutyShort    float64 `json:"duty_short"`
	DutyDaily    float64 `json:"duty_daily"`
	DutyVar      float64 `json:"duty_var"`
	HostCPU      float64 `json:"host_cpu_pct"`
	HostMemAvail uint64  `json:"host_mem_avail_mb"`
	ActiveSandfs uint32  `json:"active_sandfs"`
	CleanVMs     uint32  `json:"clean_vms"`
	TotalVMs     uint32  `json:"total_vms"`
	// PeakConcurrentExecs: node's all-time peak concurrent sync execs (0 =
	// serial historic peak). Visible in /stats.
	PeakConcurrentExecs uint32 `json:"peak_concurrent_execs"`
	// SlotWaitMs / SlotWaitEvents: warden-pool queue wait (EWMA ms + count).
	SlotWaitMS     float64 `json:"slot_wait_ms"`
	SlotWaitEvents uint64  `json:"slot_wait_events"`
	// RecycleTriggers: cumulative recycle-after-unmount destroys.
	RecycleTriggers uint64 `json:"recycle_triggers"`
	// StrandedReservationsMB / StrandedCIDs: resources held by unconfirmed-death
	// destroys (released only at sandlot restart). Visible in /stats.
	StrandedReservationsMB uint64 `json:"stranded_reservations_mb"`
	StrandedCIDs           uint32 `json:"stranded_cids"`
}

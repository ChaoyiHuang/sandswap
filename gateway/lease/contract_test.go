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
	"encoding/json"
	"testing"
)

// This file locks the WRITE side of the cross-module JSON contract between the
// gateway and the DNS. The DNS (a separate Go module) reads these records via
// field-name-based JSON unmarshaling; a silent tag rename on the gateway side
// would break owner-aware routing with no compile error. These tests assert the
// gateway's structs marshal to the field names the DNS parser expects.
//
// Reader-side mirror: dns/contract_test.go.

// TestLoadValueContract verifies lease.LoadValue marshals to the JSON shape the
// DNS reads: agg_duty_long + clean_vms (consumed by the DNS for headroom
// scoring + the routing-capacity gate), plus node_count. The DNS parser mirrors
// these exact tags - this test fails if a tag drifts.
func TestLoadValueContract(t *testing.T) {
	lv := LoadValue{
		GatewayID:   "gw-1",
		LastUpdate:  "2026-08-07T00:00:00Z",
		AggDutyLong: 0.42,
		MaxDuty:     0.9,
		CleanVMs:    7,
		NodeCount:   3,
		Nodes: []NodeLoad{{
			NodeID:   "n1",
			DutyLong: 0.42,
			CleanVMs: 7,
		}},
		SelfCPUPct:    91.5,
		SelfMemPct:    0.42,
		SelfInflight:  12,
		SelfPressured: true,
	}
	data, err := json.Marshal(lv)
	if err != nil {
		t.Fatal(err)
	}

	// Mirror of the DNS handleLoadEvent anonymous parse struct.
	var dnsSide struct {
		AggDutyLong   float64 `json:"agg_duty_long"`
		CleanVMs      uint32  `json:"clean_vms"`
		SelfPressured bool    `json:"self_pressured"`
	}
	if err := json.Unmarshal(data, &dnsSide); err != nil {
		t.Fatalf("dns-side parse: %v", err)
	}
	if dnsSide.AggDutyLong != 0.42 {
		t.Errorf("agg_duty_long: got %v, want 0.42 (tag contract break?)", dnsSide.AggDutyLong)
	}
	if dnsSide.CleanVMs != 7 {
		t.Errorf("clean_vms: got %v, want 7 (tag contract break?)", dnsSide.CleanVMs)
	}
	if !dnsSide.SelfPressured {
		t.Error("self_pressured: got false, want true (tag contract break?)")
	}

	// Verify the full key set is present (no accidental omitempty on a
	// routing-relevant field). gateway_url is deliberately NOT a load field — it
	// lives in /sandswap/gateway/{gw} (see TestGatewayRegistryValueContract).
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"gateway_id", "last_update", "agg_duty_long", "max_duty_window", "clean_vms", "node_count", "nodes",
		"self_cpu_pct", "self_mem_pct", "self_inflight", "self_pressured"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("LoadValue JSON missing key %q (contract break)", key)
		}
	}
	if _, ok := raw["gateway_url"]; ok {
		t.Error("LoadValue JSON must NOT carry gateway_url (routing lives in the registry key)")
	}
}

// TestLoadValueOmitempty verifies Nodes is omitted when empty, so a
// compute-less/human gateway's load record carries no per-node detail.
func TestLoadValueOmitempty(t *testing.T) {
	data, err := json.Marshal(LoadValue{GatewayID: "gw-1", AggDutyLong: 0.1, CleanVMs: 1})
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	if _, ok := raw["nodes"]; ok {
		t.Error("nil nodes should be omitted")
	}
	// Routing-relevant fields must NOT be omitempty (a 0 clean_vms is a real
	// "full" signal, not "absent").
	if _, ok := raw["clean_vms"]; !ok {
		t.Error("clean_vms must always be present (not omitempty) - 0 means full")
	}
}

// TestNodeLoadContract verifies per-node load signals marshal with the expected
// field names (the human /stats view reads these; the DNS does not, but the
// shape is part of the published contract).
func TestNodeLoadContract(t *testing.T) {
	nl := NodeLoad{
		NodeID: "n1", DutyLong: 0.5, DutyShort: 0.4, DutyDaily: 0.3, DutyVar: 0.1,
		HostCPU: 60.0, HostMemAvail: 4096, ActiveSandfs: 2, CleanVMs: 3, TotalVMs: 5,
	}
	data, _ := json.Marshal(nl)
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"node_id", "duty_long", "duty_short", "duty_daily", "duty_var", "host_cpu_pct", "host_mem_avail_mb", "active_sandfs", "clean_vms", "total_vms"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("NodeLoad JSON missing key %q", key)
		}
	}
}

// TestGatewayHealthValueContract verifies GatewayHealthValue marshals to the
// shape the DNS reads: only liveness + compute signals (node_count is the
// fault-state signal). Routing addresses live in the /sandswap/gateway/{gw}
// registry key, NOT the health key — this key is lease-bound and disappears on
// death, while the registry must survive for tolerance. node_count MUST
// round-trip as 0 when the gateway is compute-less - the DNS excludes
// node_count==0 from agent routing, so a default-to-1 would route into a dead
// gateway.
func TestGatewayHealthValueContract(t *testing.T) {
	t.Run("compute present", func(t *testing.T) {
		hv := GatewayHealthValue{
			LastHealthyTS: "2026-08-07T00:00:00Z",
			NodeCount:     2,
		}
		data, _ := json.Marshal(hv)
		// Mirror of the DNS handleHealthEvent anonymous parse struct.
		var dnsSide struct {
			NodeCount int `json:"node_count"`
		}
		if err := json.Unmarshal(data, &dnsSide); err != nil {
			t.Fatal(err)
		}
		if dnsSide.NodeCount != 2 {
			t.Errorf("node_count: got %v, want 2", dnsSide.NodeCount)
		}
		// The health key must NOT carry routing addresses anymore.
		var raw map[string]json.RawMessage
		if err := json.Unmarshal(data, &raw); err != nil {
			t.Fatal(err)
		}
		if _, ok := raw["gateway_url"]; ok {
			t.Error("health key must NOT carry gateway_url (routing lives in the registry key)")
		}
		if _, ok := raw["stream_addr"]; ok {
			t.Error("health key must NOT carry stream_addr (routing lives in the registry key)")
		}
	})

	t.Run("fault state node_count 0", func(t *testing.T) {
		hv := GatewayHealthValue{LastHealthyTS: "t", NodeCount: 0}
		data, _ := json.Marshal(hv)
		var dnsSide struct {
			NodeCount int `json:"node_count"`
		}
		if err := json.Unmarshal(data, &dnsSide); err != nil {
			t.Fatal(err)
		}
		if dnsSide.NodeCount != 0 {
			t.Errorf("fault state: node_count = %v, want 0 (must not default to 1)", dnsSide.NodeCount)
		}
	})

	t.Run("node_count always present", func(t *testing.T) {
		hv := GatewayHealthValue{LastHealthyTS: "t", NodeCount: 0}
		data, _ := json.Marshal(hv)
		var raw map[string]json.RawMessage
		if err := json.Unmarshal(data, &raw); err != nil {
			t.Fatal(err)
		}
		// node_count must always be present (0 is a meaningful fault state).
		if _, ok := raw["node_count"]; !ok {
			t.Error("node_count must always be present (not omitempty)")
		}
	})
}

// TestGatewayRegistryValueContract verifies the new /sandswap/gateway/{gw}
// registry key shape: gateway_url + stream_addr as CONFIGURATION (plain key).
// The DNS and the 307 redirect resolve a sandfs via ownership.gateway_id →
// this key's gateway_url. Empty addresses are omitempty (a human/admin gateway
// registers no routing target).
func TestGatewayRegistryValueContract(t *testing.T) {
	rv := GatewayRegistryValue{
		GatewayURL: "https://10.0.1.1:3000",
		StreamAddr: "10.0.1.1:9998",
	}
	data, err := json.Marshal(rv)
	if err != nil {
		t.Fatal(err)
	}
	// Mirror of the DNS handleGatewayEvent anonymous parse struct.
	var dnsSide struct {
		GatewayURL string `json:"gateway_url"`
		StreamAddr string `json:"stream_addr"`
	}
	if err := json.Unmarshal(data, &dnsSide); err != nil {
		t.Fatal(err)
	}
	if dnsSide.GatewayURL != "https://10.0.1.1:3000" {
		t.Errorf("gateway_url: got %q (contract break?)", dnsSide.GatewayURL)
	}
	if dnsSide.StreamAddr != "10.0.1.1:9998" {
		t.Errorf("stream_addr: got %q (contract break?)", dnsSide.StreamAddr)
	}

	// Empty addresses omitted (alive-but-unroutable gateway).
	dataEmpty, _ := json.Marshal(GatewayRegistryValue{})
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(dataEmpty, &raw); err != nil {
		t.Fatal(err)
	}
	if len(raw) != 0 {
		t.Errorf("empty GatewayRegistryValue should marshal to {} (omitempty), got %v", raw)
	}
}

// TestOwnershipValueContract verifies the ownership record shape. The DNS reads
// /sandswap/owner/{id} for the gateway_id; the gateway_id field name is the
// contract.
func TestOwnershipValueContract(t *testing.T) {
	ov := OwnershipValue{GatewayID: "gw-1", NodeID: "node-1", Generation: 5}
	data, _ := json.Marshal(ov)
	// Mirror of the DNS resolveOwnerFromEtcd parse struct.
	var dnsSide struct {
		GatewayID string `json:"gateway_id"`
	}
	if err := json.Unmarshal(data, &dnsSide); err != nil {
		t.Fatal(err)
	}
	if dnsSide.GatewayID != "gw-1" {
		t.Errorf("gateway_id: got %q (contract break?)", dnsSide.GatewayID)
	}
}

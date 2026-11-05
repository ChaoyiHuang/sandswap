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

package core

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// GatewayState is the sandlot's memory of its last gateway: a reconnect
// returns to the SAME gateway (its pod IP) instead of a random one, so the
// sandlot's ownership/lease/pool state and CLEAN VMs stay warm. Persisted as a
// small JSON file next to the per-VM sandbox root.
type GatewayState struct {
	LastGatewayIP string `json:"last_gateway_ip"`
}

// gatewayStatePath is the state file location — the instance's PRIVATE state
// root, never the shared runtime dir.
func gatewayStatePath(sandboxRoot string) string {
	return filepath.Join(StateRootFor(sandboxRoot), "gateway-state.json")
}

// LoadGatewayState reads the last gateway IP; returns an empty state on any
// error (missing file, corrupt JSON) — the sandlot then resolves fresh.
func LoadGatewayState(sandboxRoot string) GatewayState {
	data, err := os.ReadFile(gatewayStatePath(sandboxRoot))
	if err != nil {
		return GatewayState{}
	}
	var s GatewayState
	if err := json.Unmarshal(data, &s); err != nil {
		return GatewayState{}
	}
	return s
}

// SaveGatewayState persists the last gateway IP. Best-effort but atomic
// (tmp + fsync + rename): a torn write would read back as corrupt JSON and
// silently reset that memory — a failed save just means the next restart
// resolves fresh (the memory is a soft optimization, not a correctness requirement).
func SaveGatewayState(sandboxRoot string, s GatewayState) {
	data, err := json.Marshal(s)
	if err != nil {
		return
	}
	path := gatewayStatePath(sandboxRoot)
	_ = writeFileSync(path, data)
}

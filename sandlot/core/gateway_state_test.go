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
	"os"
	"path/filepath"
	"testing"
)

func TestGatewayStatePath(t *testing.T) {
	got := gatewayStatePath("/run/sandswap/vm")
	want := "/run/sandswap-state/default/gateway-state.json"
	if got != want {
		t.Errorf("gatewayStatePath = %q, want %q", got, want)
	}
}

func TestGatewayStateRoundTrip(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vm")
	SaveGatewayState(root, GatewayState{LastGatewayIP: "10.0.0.5"})
	got := LoadGatewayState(root)
	if got.LastGatewayIP != "10.0.0.5" {
		t.Errorf("LastGatewayIP = %q, want 10.0.0.5", got.LastGatewayIP)
	}

	SaveGatewayState(root, GatewayState{LastGatewayIP: "10.0.0.6"})
	if got := LoadGatewayState(root); got.LastGatewayIP != "10.0.0.6" {
		t.Errorf("LastGatewayIP after overwrite = %q, want 10.0.0.6", got.LastGatewayIP)
	}
}

func TestLoadGatewayStateMissingFile(t *testing.T) {
	got := LoadGatewayState(filepath.Join(t.TempDir(), "vm"))
	if got.LastGatewayIP != "" {
		t.Errorf("LastGatewayIP = %q for missing file, want empty", got.LastGatewayIP)
	}
}

func TestLoadGatewayStateCorruptJSON(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vm")
	path := gatewayStatePath(root)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := LoadGatewayState(root); got.LastGatewayIP != "" {
		t.Errorf("LastGatewayIP = %q for corrupt JSON, want empty", got.LastGatewayIP)
	}
}

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

package config

import "testing"

// TestReloadDiffSkipsNonYAMLFields pins the ConfigFilePath noise fix: a field
// tagged yaml:"-" is not part of the file's surface, so a reload (which
// decodes a fresh struct where such fields are zero) must not report it as a
// change. Before the fix EVERY reload logged "config change requires restart,
// field=ConfigFilePath", burying the real diff lines operators grep for.
func TestReloadDiffSkipsNonYAMLFields(t *testing.T) {
	old := Defaults()
	old.ConfigFilePath = "/etc/sandswap/sandlot.yaml"
	fresh := Defaults() // what a reload decodes: ConfigFilePath zero

	cs := old.Diff(fresh)
	for _, fc := range cs.RestartReq {
		if fc.Name == "ConfigFilePath" {
			t.Errorf("yaml:\"-\" field reported as a change: %+v", fc)
		}
	}
	if !cs.Empty() {
		t.Errorf("two default configs must diff empty, got %+v", cs)
	}
}

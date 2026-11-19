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

package runtime

import (
	"io"
	"log"
	"testing"

	sandlotconfig "sandlot/config"
)

// TestStartConfigReloadNoConfigPath pins the no-watcher branch: a config
// without a file path (flags-only startup) returns a nil watcher and never
// touches the server — the sidecar runs with tinyvm hot-reload disabled, as
// documented.
func TestStartConfigReloadNoConfigPath(t *testing.T) {
	cfg := sandlotconfig.Defaults()
	if cfg.ConfigFilePath != "" {
		t.Fatalf("Defaults() must not set ConfigFilePath (got %q) — fix the test, not the code", cfg.ConfigFilePath)
	}
	if w := StartConfigReload(cfg, nil, log.New(io.Discard, "", 0)); w != nil {
		t.Fatal("no config path must yield a nil watcher (hot-reload disabled)")
	}
}

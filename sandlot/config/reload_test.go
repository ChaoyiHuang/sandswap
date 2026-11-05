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

import (
	"io"
	"log/slog"
	"testing"

	"common/config"
)

// TestReloadKeepsCLIFlagOverrides pins the sandlot half of the precedence
// contract: a flag-provided pool spec must survive a config-file edit. The
// callback used to decode into Defaults() only, so the first edit cleared
// `pool` and ResizePool(nil) wiped the node's pool maintenance until restart.
func TestReloadKeepsCLIFlagOverrides(t *testing.T) {
	flags := &SandlotFlags{PoolSpec: "small:2"}
	explicit := map[string]bool{"pool": true}

	cfg := Defaults()
	cfg.ApplyFlagOverrides(flags, explicit)
	if err := cfg.ApplyError(); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if cfg.Pool != "small:2" {
		t.Fatalf("startup override not applied: pool=%q", cfg.Pool)
	}
	cfg.SetFlagReapplier(func(c *SandlotConfig) { c.ApplyFlagOverrides(flags, explicit) })

	w := config.NewWatchableConfig(cfg)
	cb := NewReloadCallback(w, &HotReloadTargets{}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	cb([]byte("recycle:\n  max_uses: 50000\n"))

	if got := w.Get().Pool; got != "small:2" {
		t.Errorf("pool after reload = %q, want the flag value \"small:2\" (the edit reverted it)", got)
	}
	if got := w.Get().Recycle.MaxUses; got != 50000 {
		t.Errorf("the edited key did not apply: max_uses = %d", got)
	}
}

// TestReloadRefusesUnrepresentableFlagValue: a flag value that cannot be
// represented (a negative warden timeout, whose int→uint wrap would disable the
// warden's last-resort mount release) is refused BEFORE the swap.
func TestReloadRefusesUnrepresentableFlagValue(t *testing.T) {
	flags := &SandlotFlags{WardenMaxExecTimeoutSec: -1}
	explicit := map[string]bool{"warden-max-exec-timeout-sec": true}

	cfg := Defaults()
	cfg.SetFlagReapplier(func(c *SandlotConfig) { c.ApplyFlagOverrides(flags, explicit) })

	w := config.NewWatchableConfig(cfg)
	cb := NewReloadCallback(w, &HotReloadTargets{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	before := w.Get()

	cb([]byte("recycle:\n  max_uses: 50000\n"))

	if got := w.Get(); got.Recycle.MaxUses != before.Recycle.MaxUses {
		t.Errorf("an edit was applied despite an unrepresentable flag override (max_uses=%d)", got.Recycle.MaxUses)
	}
}

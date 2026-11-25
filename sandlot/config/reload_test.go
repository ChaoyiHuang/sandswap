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
	"errors"
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

// TestReloadVetoesUnverifiedKernelChange pins the hot-reload TCB gate: a
// kernel/initramfs edit must pass the same pin check an exec-role start runs,
// and a failing check refuses the WHOLE revision — the live config keeps the
// last verified pair instead of the file outrunning it. Edits that do not
// touch the boot artifacts never invoke the check.
func TestReloadVetoesUnverifiedKernelChange(t *testing.T) {
	discard := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := Defaults()
	w := config.NewWatchableConfig(cfg)
	calls := 0
	cb := NewReloadCallback(w, &HotReloadTargets{
		VerifyTinyVM: func(c *SandlotConfig) error {
			calls++
			return errors.New("guest TCB pin is unavailable")
		},
	}, discard)

	cb([]byte("tinyvm:\n  kernel: /tmp/other-vmlinux.bin\n"))
	if calls != 1 {
		t.Fatalf("the TCB check ran %d times for a kernel edit, want 1", calls)
	}
	if got := w.Get().TinyVM.Kernel; got != DefaultKernelPath {
		t.Errorf("a vetoed kernel edit was applied: kernel = %q", got)
	}

	// A resources-only edit changes nothing the node boots: no TCB check, and
	// the edit applies.
	cb([]byte("tinyvm:\n  default_vcpus: 4\n"))
	if calls != 1 {
		t.Errorf("the TCB check ran for a non-artifact edit (%d calls)", calls)
	}
	if got := w.Get().TinyVM.DefaultVCPUs; got != 4 {
		t.Errorf("a resources-only edit did not apply: vcpus = %d", got)
	}

	// A passing check lets the edit through.
	w2 := config.NewWatchableConfig(Defaults())
	cb2 := NewReloadCallback(w2, &HotReloadTargets{
		VerifyTinyVM: func(c *SandlotConfig) error { return nil },
	}, discard)
	cb2([]byte("tinyvm:\n  initramfs: /opt/tcb/initramfs.cpio.gz\n"))
	if got := w2.Get().TinyVM.Initramfs; got != "/opt/tcb/initramfs.cpio.gz" {
		t.Errorf("a verified initramfs edit did not apply: %q", got)
	}
}

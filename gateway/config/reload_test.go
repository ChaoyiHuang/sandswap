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
	"time"

	"common/config"

	"gateway/lease"
	"gateway/pool"
)

// reloadSpy captures the values pushed to the function-field targets.
type reloadSpy struct {
	defT, maxT               int
	u, p, tok, cert, key, ca string
}

// reloadTargets builds a HotReloadTargets with a real Lease + Pool and a spy
// recording the function-field calls.
func reloadTargets() (*HotReloadTargets, *lease.Lease, *pool.Manager, *reloadSpy) {
	lm := lease.New(100*time.Millisecond, 5*time.Second)
	pm := pool.NewManager(nil, slog.Default())
	s := &reloadSpy{}
	t := &HotReloadTargets{
		LeaseMgr:           lm,
		PoolMgr:            pm,
		UpdateExecTimeouts: func(d, m int) { s.defT = d; s.maxT = m },
	}
	return t, lm, pm, s
}

// TestApplyHotReloadEmptyDiff verifies a no-op reload (old==new) applies
// nothing and does not call the targets.
func TestApplyHotReloadEmptyDiff(t *testing.T) {
	tg, _, _, s := reloadTargets()
	old := Defaults()
	ApplyHotReload(old, old, tg, slog.Default())
	if s.defT != 0 || s.maxT != 0 {
		t.Errorf("empty diff should not call UpdateExecTimeouts, got def=%d max=%d", s.defT, s.maxT)
	}
}

// TestApplyHotReloadExecTimeouts verifies an exec timeout change is pushed to
// the handler via UpdateExecTimeouts with the NEW values.
func TestApplyHotReloadExecTimeouts(t *testing.T) {
	tg, _, _, s := reloadTargets()
	old := Defaults()
	new := old
	new.Exec.DefaultTimeoutSec = 60
	new.Exec.MaxTimeoutSec = 600
	ApplyHotReload(old, new, tg, slog.Default())
	if s.defT != 60 || s.maxT != 600 {
		t.Errorf("exec timeouts: got def=%d max=%d, want 60/600", s.defT, s.maxT)
	}
}

// TestApplyHotReloadLeaseTimeouts verifies lease sticky/max_sticky changes are
// pushed to the Lease manager without panicking.
func TestApplyHotReloadLeaseTimeouts(t *testing.T) {
	tg, _, _, _ := reloadTargets()
	old := Defaults()
	new := old
	new.Lease.StickyMs = 250
	new.Lease.MaxStickySec = 12
	ApplyHotReload(old, new, tg, slog.Default())
	// No observable getter on Lease; the test verifies the dispatch reaches the
	// lease target without panic. The behavioral effect is covered by the lease
	// package's own TestLeaseIdleExpiry / TestLeaseMaxHoldReaper.
}

// TestApplyHotReloadSchedPolicy verifies the sched.policy hot-reload takes
// effect behaviorally: under binpack (default) Acquire picks the HIGHER-duty
// node; after reloading to spread it picks the LOWER-duty node. This proves
// SetSchedPolicy was actually invoked with the new policy.
func TestApplyHotReloadSchedPolicy(t *testing.T) {
	tg, _, pm, _ := reloadTargets()
	pm.AddNode("a")
	pm.AddNode("b")
	// Both nodes eligible (clean VM, low host CPU so the tail floor doesn't apply).
	pm.UpdateNodeMetrics("a", pool.NodeMetrics{DutyLong: 0.8, HostCPU: 0})
	pm.UpdateNodeMetrics("b", pool.NodeMetrics{DutyLong: 0.2, HostCPU: 0})
	pm.UpdateNodeCapacity("a", []pool.SpecCapacity{{SpecID: "s", Clean: 2, Total: 2}})
	pm.UpdateNodeCapacity("b", []pool.SpecCapacity{{SpecID: "s", Clean: 2, Total: 2}})

	// Default pool policy is binpack -> prefer the busier node (a).
	got, _, err := pm.Acquire("", 0, 0)
	if err != nil {
		t.Fatalf("Acquire (binpack): %v", err)
	}
	if got != "a" {
		t.Errorf("binpack: Acquire picked %q, want a (busier)", got)
	}

	// Hot-reload binpack -> spread.
	old := Defaults() // binpack
	new := old
	new.Sched.Policy = "spread"
	ApplyHotReload(old, new, tg, slog.Default())

	// Under spread, Acquire should now prefer the idle node (b).
	got, _, err = pm.Acquire("", 0, 0)
	if err != nil {
		t.Fatalf("Acquire (spread): %v", err)
	}
	if got != "b" {
		t.Errorf("spread after reload: Acquire picked %q, want b (idler)", got)
	}
}

// TestApplyHotReloadRestartRequiredNotApplied verifies a restart-required
// change (vol_root) is NOT hot-applied: the exec-timeout target is untouched.
func TestApplyHotReloadRestartRequiredNotApplied(t *testing.T) {
	tg, _, _, s := reloadTargets()
	old := Defaults()
	new := old
	new.VolRoot = "/new/volumes" // restart-required
	ApplyHotReload(old, new, tg, slog.Default())
	if s.defT != 0 || s.maxT != 0 {
		t.Errorf("restart-required change should not trigger hot-reload, got def=%d max=%d", s.defT, s.maxT)
	}
}

// TestApplyHotReloadNilTargets verifies nil targets and nil function fields do
// not panic (the handler may run without a template manager, etc.).
func TestApplyHotReloadNilTargets(t *testing.T) {
	old := Defaults()
	new := old
	new.Exec.DefaultTimeoutSec = 60
	// Nil targets, nil function fields - must not panic.
	ApplyHotReload(old, new, &HotReloadTargets{}, slog.Default())
	ApplyHotReload(old, new, nil, slog.Default())
}

// TestNewReloadCallbackValid verifies the reload callback parses YAML, swaps
// the live config, and applies hot-reloadable changes (exec timeouts).
func TestNewReloadCallbackValid(t *testing.T) {
	tg, _, _, s := reloadTargets()
	wc := config.NewWatchableConfig(Defaults())
	cb := NewReloadCallback(wc, tg, slog.Default())

	cb([]byte(`
exec:
  default_timeout_sec: 45
  max_timeout_sec: 450
`))
	if s.defT != 45 || s.maxT != 450 {
		t.Errorf("callback: exec timeouts got def=%d max=%d, want 45/450", s.defT, s.maxT)
	}
	// The live config was swapped.
	if wc.Get().Exec.DefaultTimeoutSec != 45 {
		t.Errorf("callback: live config not swapped, default=%d", wc.Get().Exec.DefaultTimeoutSec)
	}
}

// TestNewReloadCallbackInvalidYAML verifies a malformed config file is rejected
// without panicking and without applying any change (the live config is kept).
func TestNewReloadCallbackInvalidYAML(t *testing.T) {
	tg, _, _, s := reloadTargets()
	wc := config.NewWatchableConfig(Defaults())
	cb := NewReloadCallback(wc, tg, slog.Default())

	cb([]byte("exec: [invalid yaml"))
	if s.defT != 0 || s.maxT != 0 {
		t.Errorf("invalid YAML should not apply changes, got def=%d max=%d", s.defT, s.maxT)
	}
	// Live config unchanged.
	if wc.Get().Exec.DefaultTimeoutSec != 30 {
		t.Errorf("invalid YAML should keep live config, got default=%d", wc.Get().Exec.DefaultTimeoutSec)
	}
}

// TestApplyHotReloadFenceSec verifies staleness.etcd_fence_sec is classified
// hot-reloadable and dispatched to the UpdateFenceSec target (nil target is
// safely skipped — human/single-node modes wire no fence controller). The
// threshold's own accept/refuse logic lives in the lease package
// (TestUpdateFenceThreshold).
func TestApplyHotReloadFenceSec(t *testing.T) {
	var gotSec int
	called := false
	tg := &HotReloadTargets{
		UpdateFenceSec: func(sec int) { gotSec = sec; called = true },
	}
	old := Defaults()
	new := old
	new.Staleness.EtcdFenceSec = old.Staleness.EtcdFenceSec + 60
	ApplyHotReload(old, new, tg, slog.Default())
	if !called {
		t.Fatal("UpdateFenceSec not invoked for a staleness.etcd_fence_sec change")
	}
	if gotSec != new.Staleness.EtcdFenceSec {
		t.Errorf("UpdateFenceSec sec = %d, want %d", gotSec, new.Staleness.EtcdFenceSec)
	}

	// Nil target (modes without a fence controller): must not panic and must
	// still classify the change as hot-reload (i.e. not a restart warning).
	ApplyHotReload(old, new, nil, slog.Default())

	// Unchanged fence value: no dispatch.
	called = false
	ApplyHotReload(old, old, tg, slog.Default())
	if called {
		t.Error("UpdateFenceSec invoked without a fence value change")
	}
}

// TestApplyHotReloadLeaseRefusesOutOfRange: lease.sticky_ms < 1 and
// lease.max_sticky_sec < 1 are refused on hot-reload — the previous effective
// value is kept (same refusal pattern as the etcd-fence invariant). A 0 sticky
// window breaks the window-refresh mechanism; a <=0 maxHold disables the
// reaper safety net.
func TestApplyHotReloadLeaseRefusesOutOfRange(t *testing.T) {
	for _, tc := range []struct {
		name        string
		stickyMs    int
		maxSticky   int
		wantSticky  time.Duration
		wantMaxHold time.Duration
	}{
		{"sticky_ms=0 refused", 0, 5, 100 * time.Millisecond, 5 * time.Second},
		{"sticky_ms=-5 refused", -5, 5, 100 * time.Millisecond, 5 * time.Second},
		{"max_sticky_sec=0 refused", 100, 0, 100 * time.Millisecond, 5 * time.Second},
		{"max_sticky_sec=-1 refused", 100, -1, 100 * time.Millisecond, 5 * time.Second},
		{"sticky_ms=1 accepted", 1, 5, time.Millisecond, 5 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tg, lm, _, _ := reloadTargets() // lease born 100ms / 5s
			old := Defaults()
			new := old
			new.Lease.StickyMs = tc.stickyMs
			new.Lease.MaxStickySec = tc.maxSticky
			ApplyHotReload(old, new, tg, slog.Default())
			if got := lm.StickyWindow(); got != tc.wantSticky {
				t.Errorf("effective sticky window = %v, want %v", got, tc.wantSticky)
			}
			if got := lm.MaxHoldCap(); got != tc.wantMaxHold {
				t.Errorf("effective maxHold cap = %v, want %v", got, tc.wantMaxHold)
			}
		})
	}
}

// TestApplyHotReloadExecTimeoutsRefused: out-of-range exec timeouts are
// refused on hot-reload (keeping the previous values) — the same bounds as the
// startup guard. The handler's silent normalization must not paper over a bad
// edit.
func TestApplyHotReloadExecTimeoutsRefused(t *testing.T) {
	for _, tc := range []struct {
		name        string
		defT, maxT  int
		wantApplied bool
	}{
		{"valid change applied", 60, 600, true},
		{"default 0 refused", 0, 600, false},
		{"max below default refused", 5, 2, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tg, _, _, s := reloadTargets() // spy starts at 0
			old := Defaults()
			new := old
			new.Exec.DefaultTimeoutSec = tc.defT
			new.Exec.MaxTimeoutSec = tc.maxT
			ApplyHotReload(old, new, tg, slog.Default())
			applied := s.defT == tc.defT && s.maxT == tc.maxT
			if applied != tc.wantApplied {
				t.Errorf("exec timeouts applied=%v (spy def=%d max=%d), want applied=%v", applied, s.defT, s.maxT, tc.wantApplied)
			}
		})
	}
}

// TestApplyHotReloadStalenessRefused: staleness thresholds violating the
// >= 1 / ordering bounds are refused, keeping the previous thresholds.
func TestApplyHotReloadStalenessRefused(t *testing.T) {
	var gotRoute, gotGuard, gotAlert int
	called := false
	tg, _, _, _ := reloadTargets()
	tg.UpdateStalenessThresholds = func(r, g, a int) { gotRoute, gotGuard, gotAlert = r, g, a; called = true }

	// Invalid edit: route past guard.
	old := Defaults()
	new := old
	new.Staleness.RouteStaleSec = 100
	new.Staleness.ClaimDeadGuardSec = 45
	ApplyHotReload(old, new, tg, slog.Default())
	if called {
		t.Errorf("inverted ordering must be refused (callback invoked with %d/%d/%d)", gotRoute, gotGuard, gotAlert)
	}

	// Valid edit passes through.
	new.Staleness.RouteStaleSec = 10
	ApplyHotReload(old, new, tg, slog.Default())
	if !called || gotRoute != 10 || gotGuard != 45 || gotAlert != 30 {
		t.Errorf("valid staleness edit not applied: called=%v got %d/%d/%d", called, gotRoute, gotGuard, gotAlert)
	}
}

// TestApplyHotReloadShedRefused: cooldown < 0 / retry_after < 1 are refused
// (keeping the previous shed config); sat/rate keep their documented <= 0 =
// disable sentinel and pass through.
func TestApplyHotReloadShedRefused(t *testing.T) {
	var got [5]int
	called := false
	tg, _, _, _ := reloadTargets()
	tg.UpdateShedConfig = func(enabled bool, satSec, ratePerSec, cooldownSec, retryAfterSec int) {
		got = [5]int{satSec, ratePerSec, cooldownSec, retryAfterSec, 0}
		called = true
	}

	old := Defaults()
	new := old
	new.Shed.CooldownSec = -5
	ApplyHotReload(old, new, tg, slog.Default())
	if called {
		t.Errorf("negative cooldown must be refused (callback invoked with %v)", got)
	}

	new.Shed.CooldownSec = 60
	new.Shed.RatePerSec = 0 // documented disable sentinel — must pass
	ApplyHotReload(old, new, tg, slog.Default())
	if !called || got[2] != 60 || got[1] != 0 {
		t.Errorf("valid shed edit not applied: called=%v got %v", called, got)
	}
}

// TestReloadKeepsCLIFlagOverrides pins the precedence contract ACROSS a reload:
// a value supplied by an explicit CLI flag must survive a config-file edit.
// The callback used to decode into Defaults() only, so the first unrelated edit
// reverted every flag-provided value (probe: -sticky-ms 500 → 100,
// -route-stale-sec 25 → 20 on a sched.policy edit; a raised -etcd-fence-sec
// dropped back to 180 mid-partition).
func TestReloadKeepsCLIFlagOverrides(t *testing.T) {
	flags := &GatewayFlags{StickyMs: 500, StalenessRouteStaleSec: 25}
	explicit := map[string]bool{"sticky-ms": true, "route-stale-sec": true}

	cfg := Defaults()
	cfg.ApplyFlagOverrides(flags, explicit)
	if cfg.Lease.StickyMs != 500 || cfg.Staleness.RouteStaleSec != 25 {
		t.Fatalf("startup override not applied: sticky=%d route=%d", cfg.Lease.StickyMs, cfg.Staleness.RouteStaleSec)
	}
	cfg.SetFlagReapplier(func(c *GatewayConfig) { c.ApplyFlagOverrides(flags, explicit) })

	w := config.NewWatchableConfig(cfg)
	cb := NewReloadCallback(w, &HotReloadTargets{}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	// An edit that touches an UNRELATED key (and omits the flag-provided ones).
	cb([]byte("sched:\n  policy: spread\n"))

	got := w.Get()
	if got.Lease.StickyMs != 500 {
		t.Errorf("sticky_ms after reload = %d, want the flag value 500 (the edit reverted it)", got.Lease.StickyMs)
	}
	if got.Staleness.RouteStaleSec != 25 {
		t.Errorf("route_stale_sec after reload = %d, want the flag value 25", got.Staleness.RouteStaleSec)
	}
	if got.Sched.Policy != "spread" {
		t.Errorf("the edited key did not apply: policy = %q", got.Sched.Policy)
	}
}

// TestReloadRefusesInvalidStorageDeadline: the watcher must refuse the edit and
// keep the old config — the value used to PANIC from inside the goroutine.
func TestReloadRefusesInvalidStorageDeadline(t *testing.T) {
	cfg := Defaults()
	w := config.NewWatchableConfig(cfg)
	cb := NewReloadCallback(w, &HotReloadTargets{}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	cb([]byte("storage_op_deadline_sec: 0\n"))

	if got := w.Get().StorageOpDeadlineSec; got != cfg.StorageOpDeadlineSec {
		t.Errorf("invalid edit was applied: storage_op_deadline_sec = %d, want the previous %d", got, cfg.StorageOpDeadlineSec)
	}
}

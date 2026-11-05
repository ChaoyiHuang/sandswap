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
	"runtime/debug"
	"testing"
)

func TestWatchableConfigGetSet(t *testing.T) {
	wc := NewWatchableConfig(42)
	if got := wc.Get(); got != 42 {
		t.Errorf("Get() = %v, want 42", got)
	}
}

func TestWatchableConfigSwap(t *testing.T) {
	wc := NewWatchableConfig("old")
	old := wc.Swap("new")
	if old != "old" {
		t.Errorf("Swap() old = %v, want old", old)
	}
	if got := wc.Get(); got != "new" {
		t.Errorf("Get() after Swap = %v, want new", got)
	}
}

func TestWatchableConfigStruct(t *testing.T) {
	type testCfg struct {
		Timeout int    `yaml:"timeout"`
		Name    string `yaml:"name"`
	}
	wc := NewWatchableConfig(testCfg{Timeout: 100, Name: "alpha"})

	got := wc.Get()
	if got.Timeout != 100 || got.Name != "alpha" {
		t.Errorf("Get() = %+v, want {Timeout:100, Name:alpha}", got)
	}

	old := wc.Swap(testCfg{Timeout: 200, Name: "beta"})
	if old.Timeout != 100 || old.Name != "alpha" {
		t.Errorf("Swap() old = %+v, want original", old)
	}

	got = wc.Get()
	if got.Timeout != 200 || got.Name != "beta" {
		t.Errorf("Get() after Swap = %+v, want {Timeout:200, Name:beta}", got)
	}
}

func TestChangeSetEmpty(t *testing.T) {
	cs := ChangeSet{}
	if !cs.Empty() {
		t.Error("Empty() should be true for zero ChangeSet")
	}
	cs.HotReload = append(cs.HotReload, FieldChange{Name: "x"})
	if cs.Empty() {
		t.Error("Empty() should be false after adding a change")
	}
}

func TestDiffConfigsNoChange(t *testing.T) {
	type inner struct {
		X int `yaml:"x"`
	}
	type outer struct {
		A int    `yaml:"a"`
		B string `yaml:"b"`
		C inner  `yaml:"c"`
	}

	old := outer{A: 1, B: "hello", C: inner{X: 10}}
	cs := DiffConfigs(old, old, "", func(string) ChangeClass { return ChangeHotReload })
	if !cs.Empty() {
		t.Errorf("DiffConfigs of identical structs should be empty, got %+v", cs)
	}
}

func TestDiffConfigsHotReload(t *testing.T) {
	type cfg struct {
		TimeoutMs int    `yaml:"timeout_ms"`
		Addr      string `yaml:"addr"`
	}

	old := cfg{TimeoutMs: 100, Addr: ":3000"}
	new := cfg{TimeoutMs: 200, Addr: ":3000"}

	classify := func(name string) ChangeClass {
		if name == "timeout_ms" {
			return ChangeHotReload
		}
		return ChangeRestartRequired
	}

	cs := DiffConfigs(old, new, "", classify)
	if len(cs.HotReload) != 1 || cs.HotReload[0].Name != "timeout_ms" {
		t.Errorf("expected 1 hot-reload change for timeout_ms, got %+v", cs.HotReload)
	}
	if len(cs.RestartReq) != 0 {
		t.Errorf("expected 0 restart-required changes, got %+v", cs.RestartReq)
	}
	if cs.HotReload[0].Old != "100" || cs.HotReload[0].New != "200" {
		t.Errorf("wrong old/new values: old=%s new=%s", cs.HotReload[0].Old, cs.HotReload[0].New)
	}
}

func TestDiffConfigsRestartRequired(t *testing.T) {
	type cfg struct {
		Addr string `yaml:"addr"`
		Port int    `yaml:"port"`
	}

	old := cfg{Addr: ":3000", Port: 80}
	new := cfg{Addr: ":4000", Port: 80}

	classify := func(name string) ChangeClass {
		if name == "addr" {
			return ChangeRestartRequired
		}
		return ChangeHotReload
	}

	cs := DiffConfigs(old, new, "", classify)
	if len(cs.RestartReq) != 1 || cs.RestartReq[0].Name != "addr" {
		t.Errorf("expected 1 restart-required change for addr, got %+v", cs.RestartReq)
	}
	if len(cs.HotReload) != 0 {
		t.Errorf("expected 0 hot-reload changes, got %+v", cs.HotReload)
	}
}

func TestDiffConfigsNested(t *testing.T) {
	type lease struct {
		TimeoutMs  int `yaml:"timeout_ms"`
		MaxHoldSec int `yaml:"max_hold_sec"`
	}
	type cfg struct {
		Lease lease  `yaml:"lease"`
		Addr  string `yaml:"addr"`
	}

	old := cfg{Lease: lease{TimeoutMs: 100, MaxHoldSec: 5}, Addr: ":3000"}
	new := cfg{Lease: lease{TimeoutMs: 200, MaxHoldSec: 5}, Addr: ":3000"}

	classify := func(name string) ChangeClass {
		if name == "lease.timeout_ms" {
			return ChangeHotReload
		}
		return ChangeRestartRequired
	}

	cs := DiffConfigs(old, new, "", classify)
	if len(cs.HotReload) != 1 || cs.HotReload[0].Name != "lease.timeout_ms" {
		t.Errorf("expected hot-reload change for lease.timeout_ms, got %+v", cs.HotReload)
	}
}

func TestDiffConfigsMultipleChanges(t *testing.T) {
	type cfg struct {
		TimeoutMs int    `yaml:"timeout_ms"`
		Addr      string `yaml:"addr"`
	}

	old := cfg{TimeoutMs: 100, Addr: ":3000"}
	new := cfg{TimeoutMs: 200, Addr: ":4000"}

	classify := func(name string) ChangeClass {
		if name == "timeout_ms" {
			return ChangeHotReload
		}
		return ChangeRestartRequired
	}

	cs := DiffConfigs(old, new, "", classify)
	if len(cs.HotReload) != 1 {
		t.Errorf("expected 1 hot-reload change, got %d", len(cs.HotReload))
	}
	if len(cs.RestartReq) != 1 {
		t.Errorf("expected 1 restart-required change, got %d", len(cs.RestartReq))
	}
}

func TestYamlName(t *testing.T) {
	tests := []struct {
		tag      string
		fallback string
		want     string
	}{
		{"timeout_ms,omitempty", "Timeout", "timeout_ms"},
		{"name", "Name", "name"},
		{"", "Name", "Name"},
		{"-", "Name", "Name"},
		{",omitempty", "Name", "Name"},
	}
	for _, tt := range tests {
		got := yamlName(tt.tag, tt.fallback)
		if got != tt.want {
			t.Errorf("yamlName(%q, %q) = %q, want %q", tt.tag, tt.fallback, got, tt.want)
		}
	}
}

// --- ParseMemoryLimit / ApplyGCTuning (GC pacing) ---

func TestParseMemoryLimit(t *testing.T) {
	cases := []struct {
		in   string
		want int64
	}{
		{"1048576", 1 << 20},
		{"64KiB", 1 << 16},
		{"512MiB", 512 << 20},
		{"8GiB", 8 << 30},
		{"1TiB", 1 << 40},
		{"8gib", 8 << 30},   // case-insensitive
		{" 4MiB ", 4 << 20}, // surrounding space tolerated
		{"8 GiB", 8 << 30},  // space between number and unit tolerated
	}
	for _, c := range cases {
		got, err := ParseMemoryLimit(c.in)
		if err != nil || got != c.want {
			t.Errorf("ParseMemoryLimit(%q) = %d, %v; want %d, nil", c.in, got, err, c.want)
		}
	}
	for _, bad := range []string{"", "   ", "8GB", "-4MiB", "0GiB", "abcMiB", "999999999999TiB"} {
		if got, err := ParseMemoryLimit(bad); err == nil {
			t.Errorf("ParseMemoryLimit(%q) = %d; want error", bad, got)
		}
	}
}

func TestApplyGCTuningRejectsNegativeGOGC(t *testing.T) {
	// A negative SetGCPercent would DISABLE the collector entirely — must be
	// rejected, not silently applied.
	if _, err := ApplyGCTuning(-1, ""); err == nil {
		t.Fatal("negative gogc must be rejected")
	}
}

func TestApplyGCTuningGOGCForcedAndRestored(t *testing.T) {
	prev := debug.SetGCPercent(150)
	st, err := ApplyGCTuning(300, "")
	if err != nil {
		t.Fatalf("ApplyGCTuning: %v", err)
	}
	if st.GOGCSet != 300 || st.GOGCPrev != 150 {
		t.Fatalf("got set=%d prev=%d, want 300/150", st.GOGCSet, st.GOGCPrev)
	}
	debug.SetGCPercent(prev) // restore for the rest of the test binary
}

func TestApplyGCTuningGOGCZeroAppliesDefaultWhenEnvUnset(t *testing.T) {
	// gogc=0 means AUTO: with no GOGC env var, DefaultGOGC (200) applies.
	// This pins the 0-arm against a "gogc > 0" -> "gogc >= 0" drift, which
	// would call SetGCPercent(0) and DISABLE the collector entirely.
	t.Setenv("GOGC", "")
	prev := debug.SetGCPercent(120)
	st, err := ApplyGCTuning(0, "")
	if err != nil {
		t.Fatalf("ApplyGCTuning: %v", err)
	}
	if st.GOGCSet != DefaultGOGC || st.GOGCPrev != 120 {
		t.Fatalf("got set=%d prev=%d, want %d/120", st.GOGCSet, st.GOGCPrev, DefaultGOGC)
	}
	debug.SetGCPercent(prev) // restore
}

func TestApplyGCTuningGOGCZeroLeavesEnvValueAlone(t *testing.T) {
	// gogc=0 with the GOGC env var SET: the runtime already applied it at
	// startup — ApplyGCTuning must not touch the percent at all (no call:
	// both GOGCSet and GOGCPrev stay 0). Under the ">= 0" drift this would
	// call SetGCPercent(0) and leave the collector disabled.
	t.Setenv("GOGC", "300")
	prev := debug.SetGCPercent(120)
	st, err := ApplyGCTuning(0, "")
	if err != nil {
		t.Fatalf("ApplyGCTuning: %v", err)
	}
	if st.GOGCSet != 0 || st.GOGCPrev != 0 {
		t.Fatalf("got set=%d prev=%d, want 0/0 (auto must not touch the env-set percent)", st.GOGCSet, st.GOGCPrev)
	}
	if cur := debug.SetGCPercent(prev); cur != 120 {
		t.Fatalf("GC percent was moved: read back %d, want 120", cur)
	}
}

func TestApplyGCTuningMemLimitRoundTrip(t *testing.T) {
	prev := debug.SetMemoryLimit(1 << 30)
	st, err := ApplyGCTuning(0, "2GiB") // gogc=0 + GOGC env unset in tests → auto-applies; irrelevant here
	if err != nil {
		t.Fatalf("ApplyGCTuning: %v", err)
	}
	if st.MemLimitSet != 2<<30 || st.MemLimitPrev != 1<<30 {
		t.Fatalf("got set=%d prev=%d, want 2GiB/1GiB", st.MemLimitSet, st.MemLimitPrev)
	}
	debug.SetMemoryLimit(prev) // restore
}

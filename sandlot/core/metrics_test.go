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
	"sync"
	"testing"
	"time"
)

func TestEwmAlpha(t *testing.T) {
	// Smaller tau -> larger alpha (faster decay toward the new value).
	a1 := ewmAlpha(15 * time.Second)
	a2 := ewmAlpha(5 * time.Minute)
	a3 := ewmAlpha(24 * time.Hour)
	if a1 <= a2 || a2 <= a3 {
		t.Errorf("expected alpha(15s) > alpha(5min) > alpha(1day), got %v > %v > %v", a1, a2, a3)
	}
	// Alphas must be in (0,1).
	for _, a := range []float64{a1, a2, a3} {
		if a <= 0 || a >= 1 {
			t.Errorf("expected alpha in (0,1), got %v", a)
		}
	}
}

func TestEwmaConverges(t *testing.T) {
	s := 0.0
	const a = 0.1
	for i := 0; i < 200; i++ {
		s = ewma(s, a, 1.0)
	}
	if s < 0.99 {
		t.Errorf("expected EWMA to converge near 1.0, got %v", s)
	}
}

func TestCollectorDutyConvergesToBusyRatio(t *testing.T) {
	c := NewNodeMetricsCollector()
	// 2 VMs, 1 with an in-flight exec at each tick -> busy ratio 0.5.
	// duty_long τ=5min converges to ~96% after 1000 ticks.
	for i := 0; i < 1000; i++ {
		c.ExecStart(time.Now())
		c.Tick(2, 1, 0, nil, 20, 4096)
		c.ExecComplete(10 * time.Millisecond)
	}
	snap := c.Snapshot()
	if snap.DutyLong < 0.45 || snap.DutyLong > 0.55 {
		t.Errorf("expected duty_long near 0.5, got %v", snap.DutyLong)
	}
	if snap.DutyShort < 0.4 || snap.DutyShort > 0.6 {
		t.Errorf("expected duty_short near 0.5, got %v", snap.DutyShort)
	}
	if snap.ActiveSandfs != 1 || snap.TotalVMs != 2 {
		t.Errorf("expected active_sandfs=1 total_vms=2, got %d %d", snap.ActiveSandfs, snap.TotalVMs)
	}
}

func TestCollectorAllVMsBusy(t *testing.T) {
	c := NewNodeMetricsCollector()
	// 3 VMs, 3 in-flight execs -> busy ratio 1.0.
	for i := 0; i < 1000; i++ {
		c.ExecStart(time.Now())
		c.ExecStart(time.Now())
		c.ExecStart(time.Now())
		c.Tick(3, 3, 2, nil, 80, 1024)
		c.ExecComplete(5 * time.Millisecond)
		c.ExecComplete(5 * time.Millisecond)
		c.ExecComplete(5 * time.Millisecond)
	}
	snap := c.Snapshot()
	if snap.DutyLong < 0.95 {
		t.Errorf("expected duty_long near 1.0, got %v", snap.DutyLong)
	}
	if snap.ActiveBgExecs != 2 {
		t.Errorf("expected active_bg_execs=2, got %d", snap.ActiveBgExecs)
	}
}

func TestCollectorExecRateConverges(t *testing.T) {
	c := NewNodeMetricsCollector()
	// 3 completions per tick -> exec_rate converges toward 3.
	for i := 0; i < 200; i++ {
		c.ExecStart(time.Now())
		c.ExecStart(time.Now())
		c.ExecStart(time.Now())
		c.ExecComplete(10 * time.Millisecond)
		c.ExecComplete(10 * time.Millisecond)
		c.ExecComplete(10 * time.Millisecond)
		c.Tick(3, 3, 0, nil, 10, 2048)
	}
	if r := c.Snapshot().ExecRate; r < 2.5 {
		t.Errorf("expected exec_rate to converge near 3, got %v", r)
	}
}

func TestCollectorAvgExecMS(t *testing.T) {
	c := NewNodeMetricsCollector()
	// avg_exec_ms τ=5min -> ~96% convergence after 1000 ticks.
	for i := 0; i < 1000; i++ {
		c.ExecStart(time.Now())
		c.ExecComplete(20 * time.Millisecond)
		c.Tick(1, 1, 0, nil, 10, 2048)
	}
	if a := c.Snapshot().AvgExecMS; a < 17 || a > 23 {
		t.Errorf("expected avg_exec_ms near 20, got %v", a)
	}
}

func TestCollectorHostPressure(t *testing.T) {
	c := NewNodeMetricsCollector()
	for i := 0; i < 200; i++ {
		c.Tick(1, 1, 0, nil, 60, 2048)
	}
	snap := c.Snapshot()
	if snap.HostCPU < 50 || snap.HostCPU > 70 {
		t.Errorf("expected host_cpu near 60, got %v", snap.HostCPU)
	}
	if snap.HostMemAvail < 1500 || snap.HostMemAvail > 2500 {
		t.Errorf("expected host_mem_avail near 2048, got %v", snap.HostMemAvail)
	}
}

func TestCollectorIdleDuration(t *testing.T) {
	c := NewNodeMetricsCollector()
	c.ExecStart(time.Now())
	c.ExecComplete(5 * time.Millisecond)
	c.Tick(1, 1, 0, nil, 10, 2048)
	time.Sleep(20 * time.Millisecond)
	if d := c.Snapshot().IdleDurationMS; d < 10 {
		t.Errorf("expected idle_duration_ms > 0, got %d", d)
	}
}

func TestCollectorConcurrentSafety(t *testing.T) {
	c := NewNodeMetricsCollector()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				c.ExecStart(time.Now())
				c.ExecComplete(5 * time.Millisecond)
				c.Tick(2, 1, 1, nil, 30, 2048)
				_ = c.Snapshot()
			}
		}()
	}
	wg.Wait()
	// No panic / race — run with -race in CI.
	if s := c.Snapshot(); s.TotalVMs != 2 {
		t.Errorf("expected total_vms=2, got %d", s.TotalVMs)
	}
}

func TestReadProcStat(t *testing.T) {
	total, idle, ok := readProcStat()
	if !ok || total == 0 {
		t.Fatalf("expected /proc/stat parse ok with total>0, got ok=%v total=%d", ok, total)
	}
	if idle > total {
		t.Errorf("expected idle <= total, got idle=%d total=%d", idle, total)
	}
}

func TestReadHostMemAvailMB(t *testing.T) {
	if m := readHostMemAvailMB(); m == 0 {
		t.Errorf("expected host MemAvailable > 0, got 0")
	}
}

func TestRingWindowMinZero(t *testing.T) {
	w := newRingWindow(5)
	// Window not full -> min not available.
	if _, ok := w.min(); ok {
		t.Error("expected min unavailable before window fills")
	}
	for _, v := range []uint32{2, 0, 3, 0, 1} {
		w.push(v)
	}
	if m, ok := w.min(); !ok || m != 0 {
		t.Errorf("expected min 0, got %d ok=%v", m, ok)
	}
	if z := w.zeroCount(); z != 2 {
		t.Errorf("expected 2 zeros, got %d", z)
	}
	// Slide the zeros out: 5 pushes of 4 -> the window holds only 4s.
	for i := 0; i < 5; i++ {
		w.push(4)
	}
	if m, _ := w.min(); m != 4 {
		t.Errorf("expected min 4 after sliding zeros out, got %d", m)
	}
	if z := w.zeroCount(); z != 0 {
		t.Errorf("expected 0 zeros after slide, got %d", z)
	}
}

func TestRingWindowMax(t *testing.T) {
	w := newRingWindow(4)
	for _, v := range []uint32{10, 20, 5, 15} {
		w.push(v)
	}
	if m, ok := w.max(); !ok || m != 20 {
		t.Errorf("expected max 20, got %d ok=%v", m, ok)
	}
	if !w.isFull() {
		t.Error("expected window full after 4 pushes")
	}
}

func TestCollectorSpecWindowExtrema(t *testing.T) {
	c := NewNodeMetricsCollector()
	// 5 ticks with spec "medium" clean=1, 5 with clean=0 -> window (after 60
	// ticks all-zero pushes) min=0. To keep the test fast, push 60 times with
	// a 0/1 pattern and verify min + zero_count reflect the pattern.
	for i := 0; i < 60; i++ {
		cleans := map[string]uint32{"medium": 1}
		if i >= 30 {
			cleans = map[string]uint32{"medium": 0}
		}
		c.Tick(1, 1, 0, cleans, 10, 2048)
	}
	snap := c.Snapshot()
	w, ok := snap.SpecWindows["medium"]
	if !ok {
		t.Fatalf("expected spec window for medium, got %v", snap.SpecWindows)
	}
	if w[0] != 0 {
		t.Errorf("expected min_clean_window=0 (second half zero), got %d", w[0])
	}
	if w[1] < 25 {
		t.Errorf("expected zero_clean_count >= 25 (30 zero ticks), got %d", w[1])
	}
}

func TestCollectorMaxDutyWindow(t *testing.T) {
	c := NewNodeMetricsCollector()
	// All-busy first half, idle second half -> max_duty_window ~1.0.
	for i := 0; i < 60; i++ {
		if i < 30 {
			c.ExecStart(time.Now())
			c.Tick(1, 1, 0, map[string]uint32{"medium": 0}, 10, 2048)
			c.ExecComplete(5 * time.Millisecond)
		} else {
			c.Tick(1, 1, 0, map[string]uint32{"medium": 1}, 10, 2048)
		}
	}
	snap := c.Snapshot()
	if snap.MaxDutyWindow < 0.9 {
		t.Errorf("expected max_duty_window near 1.0, got %v", snap.MaxDutyWindow)
	}
}

// --- parallel-exec grayscale signals ---

func TestPeakConcurrentExecs(t *testing.T) {
	c := NewNodeMetricsCollector()
	now := time.Now()
	c.ExecStart(now)
	c.ExecStart(now)
	c.ExecStart(now)
	c.ExecComplete(10 * time.Millisecond)
	c.ExecComplete(10 * time.Millisecond)
	c.ExecComplete(10 * time.Millisecond)
	if got := c.Snapshot().PeakConcurrent; got != 3 {
		t.Errorf("PeakConcurrent = %d, want 3", got)
	}
}

func TestSlotWaitAndRecycleSignals(t *testing.T) {
	c := NewNodeMetricsCollector()
	c.RecordSlotWait(150 * time.Millisecond)
	c.RecordSlotWait(50 * time.Millisecond)
	c.RecordRecycleTrigger()
	c.RecordRecycleTrigger()
	c.RecordRecycleTrigger()
	s := c.Snapshot()
	if s.SlotWaitEvents != 2 {
		t.Errorf("SlotWaitEvents = %d, want 2", s.SlotWaitEvents)
	}
	// The EWMA starts at 0 and converges slowly (alpha from execDurTau), so
	// the invariant is "queueing moved it off zero, bounded by the samples" —
	// not a value between the two samples.
	if s.SlotWaitMS <= 0 || s.SlotWaitMS > 150 {
		t.Errorf("SlotWaitMS = %v, want >0 and <=150 after two queued acquires", s.SlotWaitMS)
	}
	if s.RecycleTriggers != 3 {
		t.Errorf("RecycleTriggers = %d, want 3", s.RecycleTriggers)
	}
	// Never queueing leaves the signal at exactly zero (the "pool is big
	// enough" reading ops rely on).
	fresh := NewNodeMetricsCollector()
	if got := fresh.Snapshot(); got.SlotWaitMS != 0 || got.SlotWaitEvents != 0 {
		t.Errorf("fresh collector = %v/%d, want 0/0", got.SlotWaitMS, got.SlotWaitEvents)
	}
}

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
	"context"
	"net/http"
	"net/http/httptest"
	"runtime"
	"sync"
	"testing"
	"time"
)

// fakeReaders lets tests drive the sampler state machine without pinning real
// CPUs: cpu returns synthetic utime+stime ticks, mem a synthetic ratio.
type fakeReaders struct {
	mu    sync.Mutex
	tick  uint64 // cumulative fake CPU ticks
	cpu   bool   // reader ok flag
	mem   float64
	memOK bool
}

func (f *fakeReaders) readCPU() (uint64, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.tick, f.cpu
}

func (f *fakeReaders) readMem() (float64, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.mem, f.memOK
}

// advanceCPU bumps the fake tick counter by `cores` seconds worth of ticks
// (selfClkTck ticks per CPU-second).
func (f *fakeReaders) advanceCPU(cores float64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tick += uint64(cores * selfClkTck)
}

// newTestMonitor wires a monitor to fake readers with the given thresholds.
func newTestMonitor(cpuHard, memHard float64, satSec int) (*SelfPressureMonitor, *fakeReaders) {
	m := NewSelfPressureMonitor(cpuHard, memHard, satSec, nil)
	f := &fakeReaders{cpu: true}
	m.readSelfCPU = f.readCPU
	m.readSelfMemRatio = f.readMem
	return m, f
}

// TestSelfPressureCPUSustain verifies the CPU path end-to-end through the
// sampler: EWMA warms toward a saturated reading, and only after the sustain
// window does pressured flip — then falls back immediately when the reading
// drops. CPU normalization: advancing ticks equivalent to GOMAXPROCS cores
// per second must read as ~100%.
func TestSelfPressureCPUSustain(t *testing.T) {
	// Low threshold + 0 sustain window: pressured as soon as the EWMA crosses.
	m, f := newTestMonitor(50, 0, 0)
	now := time.Now()

	// First sample initializes the baseline only.
	m.sample(now)
	if m.Pressured() {
		t.Fatal("pressured after baseline sample")
	}

	// One second at 100% of GOMAXPROCS. EWMA α at dt=1s, τ=30s is small, so a
	// single sample does NOT cross 50% — the EWMA itself is the first layer
	// of spike rejection.
	f.advanceCPU(float64(gomaxprocsForTest()))
	m.sample(now.Add(time.Second))
	cpu, _, _ := m.Snapshot()
	if cpu >= 50 {
		t.Fatalf("single saturated sample crossed threshold: cpu=%v (EWMA must smooth)", cpu)
	}

	// Sustained saturation: 60 more seconds at full CPU. The EWMA converges
	// to ~100 and pressured flips (satSec=0 → immediately once over).
	for i := 0; i < 60; i++ {
		f.advanceCPU(float64(gomaxprocsForTest()))
		m.sample(now.Add(time.Second * time.Duration(2+i)))
	}
	if !m.Pressured() {
		cpu, _, _ := m.Snapshot()
		t.Fatalf("sustained saturation did not pressure: cpu=%v", cpu)
	}

	// Drop to idle: the sustain clock resets on the first below-threshold
	// sample, but the EWMA (τ=30s) decays only gradually — pressured clears
	// once the EWMA itself falls under the threshold (~21s at 100→50, τ=30s).
	// This exit-side smoothing is intentional: symmetric hysteresis prevents
	// flapping around the threshold.
	for i := 0; i < 45; i++ {
		m.sample(now.Add(time.Second * time.Duration(62+i)))
	}
	if m.Pressured() {
		cpu, _, _ := m.Snapshot()
		t.Fatalf("pressured did not clear after idle decay: cpu=%v", cpu)
	}
}

// TestSelfPressureSustainWindow verifies the hysteresis window itself: with
// satSec=3, three+ consecutive over-threshold samples are required. The
// memory-only path is used because its first sample seeds the EWMA directly
// (no baseline tick needed), so the EWMA equals the raw ratio from sample
// one and the window — not the smoothing — is what's under test.
func TestSelfPressureSustainWindow(t *testing.T) {
	m, f := newTestMonitor(0, 0.5, 3)
	now := time.Now()

	// Memory-only: first sample seeds EWMA = 0.9 (> 0.5) and starts the clock.
	f.mem, f.memOK = 0.9, true
	m.sample(now)
	if m.Pressured() {
		t.Fatal("pressured on first over-threshold sample despite satSec=3")
	}

	// Samples 2 and 3: still inside the window.
	m.sample(now.Add(1 * time.Second))
	m.sample(now.Add(2 * time.Second))
	if m.Pressured() {
		t.Fatal("pressured before the sustain window elapsed (satSec=3)")
	}

	// Sample 4 crosses 3s sustained.
	m.sample(now.Add(3 * time.Second))
	if !m.Pressured() {
		t.Fatal("pressured did not flip after 3s sustained over-threshold")
	}
}

// TestSelfPressureMemNoLimit verifies the memory signal is ABSENT when no
// soft limit is configured (ok=false): the ratio stays 0 and a memHard of
// anything > 0 never pressures.
func TestSelfPressureMemNoLimit(t *testing.T) {
	m, f := newTestMonitor(0, 0.5, 0)
	now := time.Now()
	for i := 0; i < 10; i++ {
		m.sample(now.Add(time.Duration(i) * time.Second))
	}
	if m.Pressured() {
		t.Fatal("pressured with no memory signal")
	}
	if _, mem, _ := m.Snapshot(); mem != 0 {
		t.Fatalf("mem ratio = %v, want 0 (no limit configured)", mem)
	}
	_ = f
}

// TestSelfPressureDisabledSignals verifies cpuHard/memHard <= 0 disable their
// signal: a fully saturated CPU with cpuHard=0 never pressures.
func TestSelfPressureDisabledSignals(t *testing.T) {
	m, f := newTestMonitor(0, 0, 0)
	now := time.Now()
	m.sample(now)
	for i := 0; i < 60; i++ {
		f.advanceCPU(float64(gomaxprocsForTest()) * 4) // 400% (over-subscribed)
		m.sample(now.Add(time.Duration(i+1) * time.Second))
	}
	if m.Pressured() {
		t.Fatal("pressured with both signals disabled")
	}
}

// TestSelfPressureHotReload verifies Update takes effect immediately on the
// next sample: raising the threshold above the current reading releases
// pressure; lowering it re-pressures (after the window).
func TestSelfPressureHotReload(t *testing.T) {
	m, f := newTestMonitor(0, 0.5, 0)
	now := time.Now()
	f.mem, f.memOK = 0.9, true
	m.sample(now)
	if !m.Pressured() {
		t.Fatal("expected pressured with mem 0.9 >= 0.5")
	}

	// Raise the threshold: next sample releases.
	m.Update(0, 0.95, 0)
	m.sample(now.Add(time.Second))
	if m.Pressured() {
		t.Fatal("hot-raised threshold did not release pressure")
	}

	// Lower it again: re-pressures.
	m.Update(0, 0.5, 0)
	m.sample(now.Add(2 * time.Second))
	if !m.Pressured() {
		t.Fatal("hot-lowered threshold did not re-pressure")
	}
}

// TestSelfPressureCPUReadFailureIsFailOpen verifies a failing /proc read does
// not fabricate pressure: the EWMA keeps its previous value and the baseline
// is not rolled forward (a later successful read measures over its true
// interval).
func TestSelfPressureCPUReadFailureIsFailOpen(t *testing.T) {
	m, f := newTestMonitor(10, 0, 0)
	now := time.Now()
	m.sample(now) // baseline

	// Reader fails mid-stream: no EWMA movement, no pressure.
	f.mu.Lock()
	f.cpu = false
	f.mu.Unlock()
	for i := 0; i < 10; i++ {
		m.sample(now.Add(time.Duration(i+1) * time.Second))
	}
	if m.Pressured() {
		t.Fatal("failed reads fabricated pressure")
	}
}

// TestSelfPressureMiddlewareCounting verifies the in-flight counter pairs
// entry/exit, including a panicking handler recovered downstream (the
// middleware must still decrement).
func TestSelfPressureMiddlewareCounting(t *testing.T) {
	m, _ := newTestMonitor(85, 0.9, 10)
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/boom" {
			panic("test panic")
		}
		// Hold until released so the in-flight count is observable.
		<-r.Context().Done()
	})
	h := m.Middleware(withTestRecovery(inner))

	srv := httptest.NewServer(h)
	defer srv.Close()

	// Two parked requests + immediate completions.
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/park", nil)
			ctx, cancel := context.WithCancel(req.Context())
			req = req.WithContext(ctx)
			go func() {
				time.Sleep(100 * time.Millisecond)
				cancel()
			}()
			_, _ = http.DefaultClient.Do(req)
		}()
	}
	time.Sleep(50 * time.Millisecond)
	if _, _, in := m.Snapshot(); in < 1 {
		t.Fatalf("in-flight = %d during parked requests, want >= 1", in)
	}
	wg.Wait()

	// A panicking handler (recovered by the test recovery wrapper, which sits
	// INSIDE the middleware like withRecovery does in main.go) must still
	// decrement.
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/boom", nil)
	_, _ = http.DefaultClient.Do(req)
	if _, _, in := m.Snapshot(); in != 0 {
		t.Fatalf("in-flight = %d after all requests done, want 0", in)
	}
}

// TestSelfPressureNilMonitor verifies the nil contract: no pressure, zero
// snapshot, passthrough middleware.
func TestSelfPressureNilMonitor(t *testing.T) {
	var m *SelfPressureMonitor
	if m.Pressured() {
		t.Fatal("nil monitor pressured")
	}
	if cpu, mem, in := m.Snapshot(); cpu != 0 || mem != 0 || in != 0 {
		t.Fatal("nil monitor snapshot non-zero")
	}
	called := false
	h := m.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/x", nil))
	if !called {
		t.Fatal("nil middleware did not pass through")
	}
}

// gomaxprocsForTest isolates the GOMAXPROCS read for the CPU normalization
// assertions (the sampler re-reads it every sample; both see the same value
// in a test process).
func gomaxprocsForTest() int {
	return runtime.GOMAXPROCS(0)
}

// withTestRecovery mirrors main.go's withRecovery placement relative to the
// middleware: recovery INSIDE, counter OUTSIDE, so a recovered panic still
// unwinds through the decrement.
func withTestRecovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			_ = recover() // swallow: the test only cares about the counter
		}()
		next.ServeHTTP(w, r)
	})
}

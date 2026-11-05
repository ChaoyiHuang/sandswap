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
	"log/slog"
	"math"
	"net/http"
	"os"
	"runtime"
	"runtime/debug"
	"runtime/metrics"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// Self-pressure time constants, mirroring the sandlot host-signal EWMAs
// (sandlot/core/metrics.go hostCPUTau/hostMemTau) so gateway-side and
// node-side resource signals smooth identically.
const (
	selfCPUTau = 30 * time.Second
	selfMemTau = 10 * time.Second
)

// selfSampleInterval is the sampling cadence. It aligns with the load
// publisher's 2s rewrite (cmd/loadpublish.go loadPublishInterval) — the only
// consumer of these signals reads them no faster than that, so a faster tick
// is unobservable oversampling. Slower is also more accurate, not less: the
// EWMA alpha is dt-aware, and /proc CPU counters have 10ms tick granularity,
// so a longer integration window averages out quantization noise. The default
// sat_sec=10 sustain window still resolves in 5 samples.
const selfSampleInterval = 2 * time.Second

// selfClkTck is the clock ticks-per-second used by /proc/<pid>/stat CPU
// counters. 100 is the universal Linux value (USER_HZ); the kernel does not
// expose it to userspace in a portable way.
const selfClkTck = 100.0

// SelfPressureMonitor measures the GATEWAY PROCESS's own resource pressure —
// deliberately process-scoped, in contrast to the node-side signals the load
// record already carries (agg_duty_long, clean_vms, per-node host_cpu_pct):
//
//   - CPU: /proc/self/stat utime+stime delta, normalized by GOMAXPROCS. On Go
//     1.25+ GOMAXPROCS honors the cgroup CPU quota, so in containers this is
//     quota saturation and on bare metal it is real-core saturation. VM
//     compute on a co-located sandlot and co-tenant processes never inflate
//     it (their time lands in THEIR stat, not ours), and waiting on sandlots
//     costs ~no process CPU — no downstream-queueing conflation.
//   - Memory: Go-runtime-managed memory / soft memory limit
//     (debug.SetMemoryLimit(-1), which includes GOMEMLIMIT). GC pressure from
//     large buffers is the gateway's real memory-overload mode. No limit set
//     → the signal is absent (0, never over threshold).
//
// Both are EWMAs (τ above); `pressured` flips only after EITHER signal stays
// over its threshold for a sustained window (satSec), mirroring
// pool.Manager.saturationSince semantics — placement decisions ride a ~2s
// publish + DNS watch + TTL chain, so reacting to spikes would be routing on
// stale noise (see docs/how-it-works/ownership-and-dns.md).
//
// A nil *SelfPressureMonitor is a valid no-op: Pressured() == false,
// Snapshot() == zeros, Middleware() == passthrough.
type SelfPressureMonitor struct {
	logger *slog.Logger

	// Injectable readers (same pattern as sandlot's hostCPUSampler): unit
	// tests and the e2e suite drive the sustain/decay state machine without
	// pinning real CPUs. readSelfCPU returns utime+stime in clock ticks;
	// readSelfMemRatio returns managed-memory / soft-limit in [0,1] (ok=false
	// when no limit is configured).
	readSelfCPU      func() (ticks uint64, ok bool)
	readSelfMemRatio func() (ratio float64, ok bool)

	// Hot-reloadable thresholds (floats via atomic bits, like ShedConfig's
	// atomics). cpuHard/memHard <= 0 disables that signal; satSec <= 0 means
	// immediate (no sustain window).
	cpuHardBits atomic.Uint64
	memHardBits atomic.Uint64
	satSec      atomic.Int64

	// inflight counts requests currently executing on the agent listener
	// (observability only — published, never gated on: a high in-flight with
	// idle CPU is downstream queueing, which node duty already covers).
	inflight atomic.Int32

	// Sampler state — only the Start goroutine touches these; readers go
	// through the atomics below.
	lastTicks uint64
	lastTime  time.Time
	lastMemAt time.Time
	cpuEWMA   float64
	memEWMA   float64
	overSince time.Time

	// Published state (atomic so the load publisher and /stats read
	// lock-free).
	pressured  atomic.Bool
	cpuPctBits atomic.Uint64
	memPctBits atomic.Uint64
}

// NewSelfPressureMonitor builds a monitor with the default /proc + runtime
// readers and the given thresholds (defaults live in gateway/config). Pass
// cpuHard/memHard <= 0 to disable a signal; satSec <= 0 for immediate flip.
func NewSelfPressureMonitor(cpuHard, memHard float64, satSec int, logger *slog.Logger) *SelfPressureMonitor {
	if logger == nil {
		logger = slog.Default()
	}
	m := &SelfPressureMonitor{
		logger:           logger,
		readSelfCPU:      readSelfProcStat,
		readSelfMemRatio: readSelfRuntimeMemRatio,
	}
	m.cpuHardBits.Store(floatBits(cpuHard))
	m.memHardBits.Store(floatBits(memHard))
	m.satSec.Store(int64(satSec))
	return m
}

// Update hot-reloads the thresholds (config-file reload path).
func (m *SelfPressureMonitor) Update(cpuHard, memHard float64, satSec int) {
	if m == nil {
		return
	}
	m.cpuHardBits.Store(floatBits(cpuHard))
	m.memHardBits.Store(floatBits(memHard))
	m.satSec.Store(int64(satSec))
}

// Pressured reports whether the gateway has been under sustained self
// pressure. Nil-safe: a missing monitor never pressures.
func (m *SelfPressureMonitor) Pressured() bool {
	if m == nil {
		return false
	}
	return m.pressured.Load()
}

// Snapshot returns the latest smoothed signals for publication/observability.
// Nil-safe.
func (m *SelfPressureMonitor) Snapshot() (cpuPct, memRatio float64, inflight int32) {
	if m == nil {
		return 0, 0, 0
	}
	return bitsFloat(m.cpuPctBits.Load()), bitsFloat(m.memPctBits.Load()), m.inflight.Load()
}

// Middleware wraps an HTTP handler with the in-flight counter. One atomic add
// on entry + one on exit (~tens of ns) — four to five orders of magnitude
// below the measured warm path, no allocation, no formatting, so it stays out
// of the latency-tuning discipline's blast radius. Nil-safe passthrough.
func (m *SelfPressureMonitor) Middleware(next http.Handler) http.Handler {
	if m == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.inflight.Add(1)
		defer m.inflight.Add(-1)
		next.ServeHTTP(w, r)
	})
}

// SetPressureForTest pins the published state (test/e2e only — mirrors the
// OwnershipCache.SetOwnedForTest pattern): the sampler keeps running but its
// next EWMA update overwrites the values, so tests wanting a stable pinned
// state should not Start the loop.
func (m *SelfPressureMonitor) SetPressureForTest(cpuPct, memRatio float64, pressured bool) {
	if m == nil {
		return
	}
	m.cpuPctBits.Store(floatBits(cpuPct))
	m.memPctBits.Store(floatBits(memRatio))
	m.pressured.Store(pressured)
}

// Start runs the sampling loop (selfSampleInterval) until ctx is cancelled.
// Each tick: sample CPU% + mem ratio, EWMA them, then apply the sustain
// window. The first tick only initializes the CPU delta baseline.
func (m *SelfPressureMonitor) Start(ctx context.Context) {
	if m == nil {
		return
	}
	t := time.NewTicker(selfSampleInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.sample(time.Now())
		}
	}
}

// sample is one tick: EWMA-update both signals and evaluate the sustain
// window. Runs only on the Start goroutine (the state it touches above is
// goroutine-local).
func (m *SelfPressureMonitor) sample(now time.Time) {
	// CPU: delta ticks over delta wall time, normalized by GOMAXPROCS. A
	// failed read keeps the previous EWMA (fail-open: a flaky /proc must not
	// fabricate pressure), but the baseline is NOT rolled forward so a gap
	// between two successful reads is measured against its true interval.
	if ticks, ok := m.readSelfCPU(); ok {
		if !m.lastTime.IsZero() {
			dt := now.Sub(m.lastTime)
			if secs := dt.Seconds(); secs > 0 {
				cores := float64(ticks-m.lastTicks) / selfClkTck / secs
				pct := cores / float64(runtime.GOMAXPROCS(0)) * 100
				m.cpuEWMA = ewma(m.cpuEWMA, ewmaAlpha(dt, selfCPUTau), pct)
				m.cpuPctBits.Store(floatBits(m.cpuEWMA))
			}
		}
		m.lastTicks, m.lastTime = ticks, now
	}

	// Memory: ratio in [0,1] against the soft limit; absent without a limit.
	if ratio, ok := m.readSelfMemRatio(); ok {
		if !m.lastMemAt.IsZero() {
			m.memEWMA = ewma(m.memEWMA, ewmaAlpha(now.Sub(m.lastMemAt), selfMemTau), ratio)
		} else {
			m.memEWMA = ratio // first sample seeds directly
		}
		m.lastMemAt = now
		m.memPctBits.Store(floatBits(m.memEWMA))
	}

	// Sustain window (either signal over threshold starts the clock; both
	// below resets immediately — mirroring pool saturationSince).
	cpuHard := bitsFloat(m.cpuHardBits.Load())
	memHard := bitsFloat(m.memHardBits.Load())
	over := (cpuHard > 0 && m.cpuEWMA >= cpuHard) || (memHard > 0 && m.memEWMA >= memHard)
	if !over {
		m.overSince = time.Time{}
		m.pressured.Store(false)
		return
	}
	if m.overSince.IsZero() {
		m.overSince = now
	}
	if now.Sub(m.overSince) >= time.Duration(m.satSec.Load())*time.Second {
		m.pressured.Store(true)
	}
}

// readSelfProcStat reads utime+stime (clock ticks) from /proc/self/stat.
// Fields 14+15 (1-indexed) follow the possibly-spaced comm field in parens —
// parse from the LAST ')' so a comm containing spaces cannot shift fields.
func readSelfProcStat() (uint64, bool) {
	data, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return 0, false
	}
	s := string(data)
	i := strings.LastIndexByte(s, ')')
	if i < 0 || i+2 > len(s) {
		return 0, false
	}
	// After ") " the remaining fields start at field 3 (state): utime is
	// field 14 → index 11, stime field 15 → index 12.
	fields := strings.Fields(s[i+2:])
	if len(fields) < 13 {
		return 0, false
	}
	utime, err1 := strconv.ParseUint(fields[11], 10, 64)
	stime, err2 := strconv.ParseUint(fields[12], 10, 64)
	if err1 != nil || err2 != nil {
		return 0, false
	}
	return utime + stime, true
}

// memTotalMetricPath is the runtime/metrics path for the total memory
// managed by the Go runtime (heap + stacks + runtime structures) — the same
// set the soft memory limit accounts against.
const memTotalMetricPath = "/memory/classes/total:bytes"

var memTotalMetricSamples = []metrics.Sample{{Name: memTotalMetricPath}}

// readSelfRuntimeMemRatio returns managed memory / soft memory limit.
// ok=false when no soft limit is configured (the signal is absent — never
// over threshold).
func readSelfRuntimeMemRatio() (float64, bool) {
	limit := debug.SetMemoryLimit(-1)
	if limit <= 0 || limit == math.MaxInt64 {
		return 0, false
	}
	metrics.Read(memTotalMetricSamples)
	v := memTotalMetricSamples[0].Value
	if v.Kind() != metrics.KindUint64 {
		return 0, false
	}
	ratio := float64(v.Uint64()) / float64(limit)
	if ratio > 1 {
		ratio = 1
	}
	return ratio, true
}

// ewma/ewmaAlpha mirror sandlot/core/metrics.go: s = (1−α)·s + α·x with
// α = 1 − exp(−dt/τ). Duplicated (3 lines) rather than shared across Go
// modules.
func ewma(s, alpha, x float64) float64 {
	return (1-alpha)*s + alpha*x
}

func ewmaAlpha(dt time.Duration, tau time.Duration) float64 {
	if dt <= 0 {
		return 0
	}
	return 1 - math.Exp(-dt.Seconds()/tau.Seconds())
}

func floatBits(f float64) uint64 {
	return math.Float64bits(f)
}

func bitsFloat(b uint64) float64 {
	return math.Float64frombits(b)
}

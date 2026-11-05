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
	"math"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Time constants for the EWMA signals
const (
	dutyShortTau = 15 * time.Second
	dutyLongTau  = 5 * time.Minute
	dutyDailyTau = 24 * time.Hour
	dutyVarTau   = 10 * time.Minute
	hostCPUTau   = 30 * time.Second
	hostMemTau   = 10 * time.Second
	execRateTau  = 60 * time.Second
	execDurTau   = 5 * time.Minute
	gapTau       = 5 * time.Minute
	hourlyTau    = 7 * 24 * time.Hour
)

// ewmAlpha returns the EWMA decay factor α = 1 − exp(−Δt/τ) for a 1s tick and a
// time constant τ. For a 1s tick α = 1 − exp(−1/τ_seconds).
func ewmAlpha(tau time.Duration) float64 {
	return 1 - math.Exp(-1.0/tau.Seconds())
}

// ewma applies one EWMA update: s = (1−α)·s + α·x.
func ewma(s, alpha, x float64) float64 {
	return (1-alpha)*s + alpha*x
}

// ringWindow tracks the exact min/max and zero-count of a value over a sliding
// window (60 samples = 60s at a 1s tick). Used for the tail-floor signals
// (min_clean_window, zero_clean_count, max_duty_window).
type ringWindow struct {
	buf    []uint32
	next   int
	filled int
}

func newRingWindow(size int) *ringWindow {
	return &ringWindow{buf: make([]uint32, size)}
}

func (r *ringWindow) push(v uint32) {
	r.buf[r.next] = v
	r.next = (r.next + 1) % len(r.buf)
	if r.filled < len(r.buf) {
		r.filled++
	}
}

// min returns the window minimum and whether the window is filled yet.
func (r *ringWindow) min() (uint32, bool) {
	if r.filled == 0 {
		return 0, false
	}
	m := r.buf[0]
	for i := 1; i < r.filled; i++ {
		if r.buf[i] < m {
			m = r.buf[i]
		}
	}
	return m, true
}

// max returns the window maximum and whether the window is filled yet.
func (r *ringWindow) max() (uint32, bool) {
	if r.filled == 0 {
		return 0, false
	}
	m := r.buf[0]
	for i := 1; i < r.filled; i++ {
		if r.buf[i] > m {
			m = r.buf[i]
		}
	}
	return m, true
}

// zeroCount returns the number of window samples equal to zero.
func (r *ringWindow) zeroCount() uint32 {
	var z uint32
	for i := 0; i < r.filled; i++ {
		if r.buf[i] == 0 {
			z++
		}
	}
	return z
}

// isFull reports whether the window has accumulated `size` samples.
func (r *ringWindow) isFull() bool {
	return r.filled >= len(r.buf)
}

// NodeMetricsSnapshot is a point-in-time copy of the collector's signals.
type NodeMetricsSnapshot struct {
	DutyShort      float64 // EWMA busy ratio (0..1), τ=15s
	DutyLong       float64 // EWMA busy ratio, τ=5min
	DutyDaily      float64 // EWMA busy ratio, τ≈1day (durable headroom)
	DutyVar        float64 // temporal volatility of duty
	ExecRate       float64 // EWMA execs/sec
	AvgExecMS      float64 // EWMA exec duration (ms)
	AvgGapMS       float64 // EWMA inter-exec gap (ms)
	HostCPU        float64 // host CPU utilization percent
	HostMemAvail   uint64  // host MemAvailable (MiB)
	ActiveSandfs   uint32  // sandfs bound on this node
	ActiveBgExecs  uint32  // running background execs across VMs
	TotalVMs       uint32  // live VMs
	IdleDurationMS int64   // ms since the last exec started (0 if none)
	MaxDutyWindow  float64 // 60s peak busy ratio (tail signal)
	PeakConcurrent uint32  // high-water mark of concurrent sync execs
	// SlotWaitMS/SlotWaitEvents: warden-pool acquire queue wait. Non-trivial
	// values mean the spec's exec_slots is undersized for the concurrency.
	SlotWaitMS     float64
	SlotWaitEvents uint64
	// RecycleTriggers: cumulative POLICY recycles — a VM deliberately destroyed
	// instead of returned to CLEAN (lifetime caps incl. the distinct-agent
	// cap, the memory threshold, or pool scale-down). Failure-driven dirty
	// destroys are not counted.
	RecycleTriggers uint64
	// StrandedReservationsMB / StrandedCIDs: guest-memory reservations (MiB)
	// and vsock CIDs held by VMs whose destroy could NOT confirm process death
	// (D-state sandvmm, failed lifecycle RPC). Released only by a sandlot
	// restart; gauges since process start. This is the silent pool-capacity
	// loss behind otherwise-puzzling RESOURCE SHORTAGE alarms.
	StrandedReservationsMB uint64
	StrandedCIDs           uint32
	SpecWindows            map[string][2]uint32 // specID -> {min_clean_window, zero_clean_count}
}

// NodeMetricsCollector computes the scheduling-relevant load signals for a
// sandlot node All state is O(1): EWMA scalars plus a
// 24-bucket hourly pattern. Update rhythm: a 1s tick for continuous/state
// signals (duty, host pressure, exec rate) and exec events for value-carrying
// signals (avg exec duration, inter-exec gap). Thread-safe.
type NodeMetricsCollector struct {
	mu sync.Mutex

	dutyShort float64
	dutyLong  float64
	dutyDaily float64
	dutyVar   float64
	hourly    [24]float64

	hostCPU      float64
	hostMemAvail uint64

	execRate  float64
	avgExecMS float64
	avgGapMS  float64

	activeExecs   uint32 // in-flight command execs
	peakExecs     uint32 // high-water mark of concurrent in-flight execs
	execsLastTick uint32 // completions since the last tick
	lastExecAt    time.Time

	slotWaitMS      float64 // EWMA of slot-queue wait (ms; 0 = never queued)
	slotWaitEvents  uint64  // cumulative acquires that had to queue
	recycleTriggers uint64  // cumulative unmounts that hit recycle/pending-destroy

	strandedReservationsMB uint64 // memory stranded by unconfirmed-death destroys
	strandedCIDs           uint32 // CIDs stranded the same way

	activeSandfs  uint32
	activeBgExecs uint32
	totalVMs      uint32

	// Tail signals: 60s sliding windows (exact, ring buffers).
	specWindows map[string]*ringWindow // specID -> clean-count window
	dutyWindow  *ringWindow            // busy ratio × 1000
}

// NewNodeMetricsCollector creates a collector with zeroed EWMA state (a fresh
// node converges over a few τ; the gateway treats no-data as full headroom).
func NewNodeMetricsCollector() *NodeMetricsCollector {
	return &NodeMetricsCollector{
		specWindows: make(map[string]*ringWindow),
		dutyWindow:  newRingWindow(60),
	}
}

// ExecStart records the start of a command exec: updates the inter-exec gap and
// lastExecAt (which drives idle_duration), and increments the in-flight count.
func (c *NodeMetricsCollector) ExecStart(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.lastExecAt.IsZero() && now.After(c.lastExecAt) {
		gapMS := float64(now.Sub(c.lastExecAt).Milliseconds())
		c.avgGapMS = ewma(c.avgGapMS, ewmAlpha(gapTau), gapMS)
	}
	c.lastExecAt = now
	c.activeExecs++
	if c.activeExecs > c.peakExecs {
		c.peakExecs = c.activeExecs
	}
}

// RecordSlotWait records a warden-pool acquire that had to QUEUE (all
// exec_slots in flight). Grayscale signal: a non-trivial slot_wait_ms means
// the spec's exec_slots is undersized for the observed concurrency.
func (c *NodeMetricsCollector) RecordSlotWait(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.slotWaitMS = ewma(c.slotWaitMS, ewmAlpha(execDurTau), float64(d.Milliseconds()))
	c.slotWaitEvents++
}

// RecordRecycleTrigger records an unmount that destroyed the VM instead of
// returning it to CLEAN (recycle policy or pool scale-down). Grayscale signal:
// a high rate means memory/age thresholds fire too eagerly for the workload.
func (c *NodeMetricsCollector) RecordRecycleTrigger() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.recycleTriggers++
}

// RecordStranded records resources stranded by a destroy that could NOT
// confirm process death (the CID + memory reservation stay held until the next
// sandlot restart). Surfaced in the heartbeat so "why is my pool shrinking"
// has an answer before RESOURCE SHORTAGE puzzles an operator.
func (c *NodeMetricsCollector) RecordStranded(memMB uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.strandedReservationsMB += memMB
	c.strandedCIDs++
}

// ExecComplete records the completion of a command exec: decrements the
// in-flight count and updates the exec-duration EWMA.
func (c *NodeMetricsCollector) ExecComplete(duration time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.activeExecs > 0 {
		c.activeExecs--
	}
	c.execsLastTick++
	c.avgExecMS = ewma(c.avgExecMS, ewmAlpha(execDurTau), float64(duration.Milliseconds()))
}

// Tick is called every ~1s with the current pool/host state. It updates the
// duty EWMA (busy ratio = in-flight execs / total VMs, capped at 1), the exec
// rate, the host pressure EWMAs, the hourly pattern bucket, and the 60s
// tail-signal windows (per-spec min-clean/zero-count + max-duty).
// specCleans maps specID -> current CLEAN VM count (specs absent are pushed as 0
// if previously tracked — they dropped to zero).
func (c *NodeMetricsCollector) Tick(totalVMs, activeSandfs, activeBgExecs uint32, specCleans map[string]uint32, hostCPU float64, hostMemAvail uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Busy ratio: fraction of pool VMs with an in-flight exec (capped at 1).
	busy := float64(c.activeExecs)
	if totalVMs > 0 && busy > float64(totalVMs) {
		busy = float64(totalVMs)
	}
	ratio := 0.0
	if totalVMs > 0 {
		ratio = busy / float64(totalVMs)
	}

	c.dutyShort = ewma(c.dutyShort, ewmAlpha(dutyShortTau), ratio)
	c.dutyLong = ewma(c.dutyLong, ewmAlpha(dutyLongTau), ratio)
	c.dutyDaily = ewma(c.dutyDaily, ewmAlpha(dutyDailyTau), ratio)
	// duty_var: temporal volatility = EWMA of (short − long)².
	c.dutyVar = ewma(c.dutyVar, ewmAlpha(dutyVarTau), (c.dutyShort-c.dutyLong)*(c.dutyShort-c.dutyLong))

	hour := time.Now().Hour()
	c.hourly[hour] = ewma(c.hourly[hour], ewmAlpha(hourlyTau), ratio)

	// Exec rate: EWMA of execs completed per tick.
	c.execRate = ewma(c.execRate, ewmAlpha(execRateTau), float64(c.execsLastTick))
	c.execsLastTick = 0

	c.hostCPU = ewma(c.hostCPU, ewmAlpha(hostCPUTau), hostCPU)
	c.hostMemAvail = uint64(ewma(float64(c.hostMemAvail), ewmAlpha(hostMemTau), float64(hostMemAvail)))

	c.activeSandfs = activeSandfs
	c.activeBgExecs = activeBgExecs
	c.totalVMs = totalVMs

	// Tail-signal windows.
	c.dutyWindow.push(uint32(ratio * 1000))
	for spec, clean := range specCleans {
		w, ok := c.specWindows[spec]
		if !ok {
			w = newRingWindow(60)
			c.specWindows[spec] = w
		}
		w.push(clean)
	}
	// Previously-tracked specs now absent -> dropped to 0 VMs.
	for spec := range c.specWindows {
		if _, ok := specCleans[spec]; !ok {
			c.specWindows[spec].push(0)
		}
	}
}

// Snapshot returns a point-in-time copy of the collector's signals.
func (c *NodeMetricsCollector) Snapshot() NodeMetricsSnapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	snap := NodeMetricsSnapshot{
		DutyShort:     c.dutyShort,
		DutyLong:      c.dutyLong,
		DutyDaily:     c.dutyDaily,
		DutyVar:       c.dutyVar,
		ExecRate:      c.execRate,
		AvgExecMS:     c.avgExecMS,
		AvgGapMS:      c.avgGapMS,
		HostCPU:       c.hostCPU,
		HostMemAvail:  c.hostMemAvail,
		ActiveSandfs:  c.activeSandfs,
		ActiveBgExecs: c.activeBgExecs,
		TotalVMs:      c.totalVMs,
		// Parallel-exec grayscale signals.
		PeakConcurrent:  c.peakExecs,
		SlotWaitMS:      c.slotWaitMS,
		SlotWaitEvents:  c.slotWaitEvents,
		RecycleTriggers: c.recycleTriggers,
		// Unconfirmed-death stranding (gauge since process start).
		StrandedReservationsMB: c.strandedReservationsMB,
		StrandedCIDs:           c.strandedCIDs,
		SpecWindows:            make(map[string][2]uint32, len(c.specWindows)),
	}
	if m, ok := c.dutyWindow.max(); ok {
		snap.MaxDutyWindow = float64(m) / 1000.0
	}
	for spec, w := range c.specWindows {
		if minClean, ok := w.min(); ok {
			snap.SpecWindows[spec] = [2]uint32{minClean, w.zeroCount()}
		}
	}
	if !c.lastExecAt.IsZero() {
		d := time.Since(c.lastExecAt).Milliseconds()
		if d < 0 {
			d = 0
		}
		snap.IdleDurationMS = d
	}
	return snap
}

// hostCPUSampler reads the host CPU busy percentage from /proc/stat, computing
// the delta between successive samples (the fraction of ticks spent not idle).
type hostCPUSampler struct {
	mu          sync.Mutex
	lastTotal   uint64
	lastIdle    uint64
	initialized bool
}

// sample returns the CPU busy percent since the last sample (0 on the first).
func (s *hostCPUSampler) sample() float64 {
	total, idle, ok := readProcStat()
	if !ok {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.initialized {
		s.initialized = true
		s.lastTotal, s.lastIdle = total, idle
		return 0
	}
	dTotal := total - s.lastTotal
	dIdle := idle - s.lastIdle
	s.lastTotal, s.lastIdle = total, idle
	if dTotal == 0 {
		return 0
	}
	busy := 1.0 - float64(dIdle)/float64(dTotal)
	if busy < 0 {
		busy = 0
	}
	if busy > 1 {
		busy = 1
	}
	return busy * 100
}

// readProcStat parses the first (aggregate) line of /proc/stat and returns
// (totalJiffies, idleJiffies). idle = idle + iowait.
func readProcStat() (total, idle uint64, ok bool) {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0, 0, false
	}
	line := string(data)
	// "cpu  user nice system idle iowait irq softirq steal guest guest_nice"
	fields := strings.Fields(line)
	if len(fields) < 8 || fields[0] != "cpu" {
		return 0, 0, false
	}
	var vals [8]uint64
	// fields[1..8] = user nice system idle iowait irq softirq steal — the
	// previous bound (i <= 7) never read steal, so the CPU total omitted it and
	// the idle% denominator was wrong on steal-heavy hosts (nested virt).
	for i := 1; i <= 8 && i < len(fields); i++ {
		v, err := strconv.ParseUint(fields[i], 10, 64)
		if err != nil {
			return 0, 0, false
		}
		vals[i-1] = v
	}
	// vals: 0=user 1=nice 2=system 3=idle 4=iowait 5=irq 6=softirq 7=steal
	idle = vals[3] + vals[4]
	for _, v := range vals {
		total += v
	}
	return total, idle, true
}

// readHostMemAvailMB returns the host's MemAvailable in MiB from /proc/meminfo.
func readHostMemAvailMB() uint64 {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "MemAvailable:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				if v, err := strconv.ParseUint(fields[1], 10, 64); err == nil {
					return v / 1024 // KiB -> MiB
				}
			}
			return 0
		}
	}
	return 0
}

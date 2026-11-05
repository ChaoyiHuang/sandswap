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
//
// Package stats implements the gateway-side unmount statistics collector.
// It records per-sandlot-node unmount latency and counts, mirroring the mount
// path's three-layer latency breakdown (warden / sandlot / gateway E2E) but for
// the async release path. The record footprint per node is FIXED: a handful of
// counters + a top-N (default 10) list of the slowest unmounts. All recording
// happens off the warm exec critical path — RecordMount is post-response on a
// cold mount, RecordUnmount runs on the async lease-expiry / failure-cleanup /
// delete paths.
// A snapshot is asynchronously persisted to etcd under
// /sandswap/unmount-stats/{gatewayID} every PersistInterval (default 10min,
// configurable) so peer gateways' /stats can aggregate it. In single-node mode
// (no etcd) the snapshot is served only from the local /stats handler.

package stats

import (
	"context"
	"encoding/json"
	"log/slog"
	"math"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"

	"gateway/pool"
)

// DefaultTopN is the fixed number of slowest unmounts retained per node.
const DefaultTopN = 10

// DefaultRecentN is the capacity of each node's latency ring. The ring is a
// rolling window (the last N samples), not a histogram: it answers "what did
// the recent unmount / lease-fire latency look like" — the P95 that the
// counters and the top-N list cannot produce. 1024 samples is ~8 KiB per ring,
// a fixed footprint per node.
const DefaultRecentN = 1024

// UnderMs thresholds for the fast-unmount tally (fixed by design).
const (
	under5msNs  = uint64(5 * time.Millisecond)
	under10msNs = uint64(10 * time.Millisecond)
)

// commandTruncate caps the stored last-command context so a pathological command
// can't inflate the fixed record footprint.
const commandTruncate = 120

// SlowEntry is one recorded slow unmount (a member of a node's top-N).
// The latency fields are float milliseconds at microsecond resolution
// (msFromNs) so a sub-millisecond component does not collapse to a whole
// millisecond.
type SlowEntry struct {
	SandfsID  string  `json:"sandfs_id,omitempty"`
	GatewayMs float64 `json:"gateway_ms"`
	SandlotMs float64 `json:"sandlot_ms"`
	WardenMs  float64 `json:"warden_ms"`
	Command   string  `json:"command,omitempty"`
	Reason    string  `json:"reason,omitempty"`
	Timestamp string  `json:"timestamp"`
}

// RingSnapshot is the percentile summary of one latency ring, in milliseconds.
// P50/P95/P99 use the nearest-rank convention shared with the benchmark
// scripts (sorted[int(n*p)], clamped to the last sample); MaxMs is the window
// maximum. A ring with no samples reports N=0 and zeroes.
type RingSnapshot struct {
	N     int     `json:"n"`
	P50Ms float64 `json:"p50_ms"`
	P95Ms float64 `json:"p95_ms"`
	P99Ms float64 `json:"p99_ms"`
	MaxMs float64 `json:"max_ms"`
}

// LeaseFireSnapshot is the lease-fire punctuality summary. A "fire" is a
// lease-expiry timer callback that actually dispatched the unmount at (or
// after) its sync sticky deadline; lag = actual fire time - sticky deadline.
// Under1ms/Under2ms are strict (<) tallies. P50/P95/Max come from the recent
// ring; Total is the lifetime counter.
type LeaseFireSnapshot struct {
	Total    uint64  `json:"total"`
	Under1ms uint64  `json:"under_1ms"`
	Under2ms uint64  `json:"under_2ms"`
	MaxMs    float64 `json:"max_ms"`
	P50Ms    float64 `json:"p50_ms"`
	P95Ms    float64 `json:"p95_ms"`
}

// NodeUnmountStats is the fixed-footprint per-node record exposed in /stats and
// persisted to etcd. TopSlow is sorted descending by GatewayMs. Recent /
// RecentWarden / LeaseFire are rolling-window summaries (see RingSnapshot).
type NodeUnmountStats struct {
	NodeID         string            `json:"node_id"`
	MountCount     uint64            `json:"mount_count"`
	UnmountCount   uint64            `json:"unmount_count"`
	UnmountSuccess uint64            `json:"unmount_success"`
	UnmountFail    uint64            `json:"unmount_fail"`
	Under5ms       uint64            `json:"under_5ms"`
	Under10ms      uint64            `json:"under_10ms"`
	TopSlow        []SlowEntry       `json:"top_slow"`
	Recent         RingSnapshot      `json:"recent"`
	RecentWarden   RingSnapshot      `json:"recent_warden"`
	LeaseFire      LeaseFireSnapshot `json:"lease_fire"`
}

// GatewayUnmountStats is one gateway's persisted snapshot (the etcd value shape
// for /sandswap/unmount-stats/{gatewayID}).
type GatewayUnmountStats struct {
	GatewayID  string             `json:"gateway_id"`
	LastUpdate string             `json:"last_update"`
	Nodes      []NodeUnmountStats `json:"nodes"`
}

// UnmountStats is the gateway-wide collector. It implements pool.UnmountRecorder.
// Safe for concurrent use. A nil UnmountStats is a valid no-op recorder only via
// the interface-nil guard at call sites — methods on a nil receiver panic, so
// callers must check `!= nil` first (as the wiring does).
type UnmountStats struct {
	mu    sync.Mutex
	nodes map[string]*nodeStats // nodeID -> stats
	// lastCmd keys the last cold-mount command by (nodeID, sandfsID) so a
	// disconnecting node's pending entries can be reaped by ForgetNode. A
	// sandfsID-only key would leak entries when a node crashes with mounted
	// sandfs that never get unmounted on this gateway.
	lastCmd map[string]string // lastCmdKey(nodeID, sandfsID) -> command
	topN    int
	// etcd persistence wiring. cli == nil → single-node mode (in-memory only).
	cli       *clientv3.Client
	gatewayID string
	// intervalNs is the persist interval in nanoseconds, stored atomically so it
	// is hot-reloadable (UpdateInterval swaps it without restarting StartPersist;
	// the ticker re-reads it on each tick and resets to the new interval).
	intervalNs atomic.Int64
	logger     *slog.Logger
}

type nodeStats struct {
	mountCount     uint64
	unmountCount   uint64
	unmountSuccess uint64
	unmountFail    uint64
	under5ms       uint64
	under10ms      uint64
	topSlow        []SlowEntry // sorted desc by GatewayMs, capped at topN
	// Rolling latency windows (gateway / warden unmount, lease-fire lag). Fixed
	// capacity, preallocated on node creation — recording never allocates.
	recent       durationRing
	recentWarden durationRing
	leaseFire    durationRing
	// Lease-fire lifetime counters (the ring only proves recent behaviour).
	leaseFireTotal  uint64
	leaseFireUnder1 uint64
	leaseFireUnder2 uint64
}

// NewUnmountStats constructs a collector. topN <= 0 falls back to DefaultTopN.
// persistInterval <= 0 falls back to 10min. cli may be nil (single-node mode).
func NewUnmountStats(topN int, persistInterval time.Duration, cli *clientv3.Client, gatewayID string, logger *slog.Logger) *UnmountStats {
	if topN <= 0 {
		topN = DefaultTopN
	}
	if persistInterval <= 0 {
		persistInterval = 10 * time.Minute
	}
	if logger == nil {
		logger = slog.Default()
	}
	s := &UnmountStats{
		nodes:     make(map[string]*nodeStats),
		lastCmd:   make(map[string]string),
		topN:      topN,
		cli:       cli,
		gatewayID: gatewayID,
		logger:    logger,
	}
	s.intervalNs.Store(int64(persistInterval))
	return s
}

// UpdateInterval atomically swaps the persist interval. Hot-reloadable: the
// running StartPersist goroutine picks up the new value on its next tick and
// resets its ticker. d <= 0 is ignored (keeps the current interval).
func (s *UnmountStats) UpdateInterval(d time.Duration) {
	if s == nil || d <= 0 {
		return
	}
	s.intervalNs.Store(int64(d))
}

// RecordMount records a successful cold mount: bumps the node's mount count and
// stores the sandfs's last cold-mount command for the eventual unmount's
// slow-entry context. The command is truncated. Implements pool.UnmountRecorder.
func (s *UnmountStats) RecordMount(nodeID, sandfsID, command string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ns := s.nodeLocked(nodeID)
	ns.mountCount++
	if command != "" {
		s.lastCmd[lastCmdKey(nodeID, sandfsID)] = truncateCmd(command)
	}
}

// lastCmdKey is the composite map key for lastCmd. The NUL separator cannot
// appear in node/sandfs IDs (hex-derived), so the pair is unambiguous.
func lastCmdKey(nodeID, sandfsID string) string {
	return nodeID + "\x00" + sandfsID
}

// RecordUnmount records an unmount attempt: bumps unmount/success/fail counts,
// the <5ms/<10ms tallies, and (if it ranks) a top-N slow entry carrying the
// three-layer latencies + the sandfs's last command + reason. Implements
// pool.UnmountRecorder.
func (s *UnmountStats) RecordUnmount(nodeID, sandfsID, reason string, r pool.UnmountResult, success bool) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ns := s.nodeLocked(nodeID)
	ns.unmountCount++
	if success {
		ns.unmountSuccess++
	} else {
		ns.unmountFail++
	}
	gatewayNs := r.GatewayDurationNs
	if gatewayNs > 0 {
		ns.recent.add(gatewayNs)
		if gatewayNs < under5msNs {
			ns.under5ms++
		}
		if gatewayNs < under10msNs {
			ns.under10ms++
		}
	}
	if r.WardenDurationNs > 0 {
		ns.recentWarden.add(r.WardenDurationNs)
	}
	// Insert into the top-N slowest (by gateway E2E). Pull + clear the last
	// command so the entry carries the command whose residual processes (if any)
	// drove the slow cgroup.kill/umount.
	entry := SlowEntry{
		SandfsID:  sandfsID,
		GatewayMs: msFromNs(gatewayNs),
		SandlotMs: msFromNs(r.SandlotDurationNs),
		WardenMs:  msFromNs(r.WardenDurationNs),
		Command:   s.lastCmd[lastCmdKey(nodeID, sandfsID)],
		Reason:    reason,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}
	delete(s.lastCmd, lastCmdKey(nodeID, sandfsID))
	insertSlow(&ns.topSlow, s.topN, entry)
}

// Snapshot returns a deep copy of every node's stats for /stats reporting.
// Returns nil if there are no nodes recorded yet. Ring copies are taken under
// the lock; sorting/percentile work happens after it is released, so a scrape
// never blocks a recording for longer than the copy.
func (s *UnmountStats) Snapshot() []NodeUnmountStats {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	if len(s.nodes) == 0 {
		s.mu.Unlock()
		return nil
	}
	type rawNode struct {
		entry NodeUnmountStats
		gw    []uint64
		wd    []uint64
		lf    []uint64
		lfTot uint64
		lfU1  uint64
		lfU2  uint64
	}
	raws := make([]rawNode, 0, len(s.nodes))
	for nodeID, ns := range s.nodes {
		raws = append(raws, rawNode{
			entry: NodeUnmountStats{
				NodeID:         nodeID,
				MountCount:     ns.mountCount,
				UnmountCount:   ns.unmountCount,
				UnmountSuccess: ns.unmountSuccess,
				UnmountFail:    ns.unmountFail,
				Under5ms:       ns.under5ms,
				Under10ms:      ns.under10ms,
				TopSlow:        append([]SlowEntry(nil), ns.topSlow...),
			},
			gw:    ns.recent.values(),
			wd:    ns.recentWarden.values(),
			lf:    ns.leaseFire.values(),
			lfTot: ns.leaseFireTotal,
			lfU1:  ns.leaseFireUnder1,
			lfU2:  ns.leaseFireUnder2,
		})
	}
	s.mu.Unlock()

	out := make([]NodeUnmountStats, 0, len(raws))
	for _, r := range raws {
		entry := r.entry
		entry.Recent = ringSnapshot(r.gw)
		entry.RecentWarden = ringSnapshot(r.wd)
		lf := ringSnapshot(r.lf)
		entry.LeaseFire = LeaseFireSnapshot{
			Total:    r.lfTot,
			Under1ms: r.lfU1,
			Under2ms: r.lfU2,
			MaxMs:    lf.MaxMs,
			P50Ms:    lf.P50Ms,
			P95Ms:    lf.P95Ms,
		}
		out = append(out, entry)
	}
	// Stable order for readable /stats output.
	sort.Slice(out, func(i, j int) bool { return out[i].NodeID < out[j].NodeID })
	return out
}

// ringSnapshot summarizes an unsorted sample slice (empty → zeroes).
func ringSnapshot(v []uint64) RingSnapshot {
	if len(v) == 0 {
		return RingSnapshot{}
	}
	sort.Slice(v, func(i, j int) bool { return v[i] < v[j] })
	return RingSnapshot{
		N:     len(v),
		P50Ms: percentileMs(v, 0.50),
		P95Ms: percentileMs(v, 0.95),
		P99Ms: percentileMs(v, 0.99),
		MaxMs: msFromNs(v[len(v)-1]),
	}
}

// RecordLeaseFire records one lease-expiry timer fire that dispatched an
// unmount: lag is how late the timer callback ran relative to the entry's
// sync sticky deadline. This is the 1ms-punctuality metric — the sticky window
// only means anything if the expiry actually fires on time under load.
// Recording happens on the timer callback path (unmount dispatch), never on
// the exec path. Negative lags are ignored (clock skew / a caller that fired
// early is not a late fire).
func (s *UnmountStats) RecordLeaseFire(nodeID string, lag time.Duration) {
	if s == nil || lag < 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ns := s.nodeLocked(nodeID)
	v := uint64(lag)
	ns.leaseFireTotal++
	if v < uint64(time.Millisecond) {
		ns.leaseFireUnder1++
	}
	if v < uint64(2*time.Millisecond) {
		ns.leaseFireUnder2++
	}
	ns.leaseFire.add(v)
}

// StartPersist periodically writes the snapshot to etcd under
// /sandswap/unmount-stats/{gatewayID} as a PLAIN key (no lease TTL) for ops/human
// offline inspection. A restart with the same gatewayID overwrites its own key
// (the gateway does not read it back — counters start fresh); orphan keys from a
// permanently retired gateway are reclaimed by ops (etcdctl del), matching the
// /sandswap/gateway/{gw} convention. No-op when cli is nil (single-node mode).
// Blocks until ctx is cancelled.
func (s *UnmountStats) StartPersist(ctx context.Context) {
	if s == nil || s.cli == nil {
		return
	}
	key := "/sandswap/unmount-stats/" + s.gatewayID

	write := func() {
		gw := GatewayUnmountStats{
			GatewayID:  s.gatewayID,
			LastUpdate: time.Now().UTC().Format(time.RFC3339),
			Nodes:      s.Snapshot(),
		}
		data, err := json.Marshal(gw)
		if err != nil {
			s.logger.Warn("unmount-stats: marshal", "error", err)
			return
		}
		pctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if _, err := s.cli.Put(pctx, key, string(data)); err != nil {
			s.logger.Warn("unmount-stats: put", "error", err)
		}
	}
	write()
	// Re-read the interval each tick so UpdateInterval (hot-reload) takes effect
	// without restarting the goroutine. Reset is a no-op when the interval is
	// unchanged and cheap, so calling it every tick is harmless. The atomic read
	// is lock-free and stays off every request path.
	curInterval := func() time.Duration {
		d := time.Duration(s.intervalNs.Load())
		if d <= 0 {
			d = 10 * time.Minute
		}
		return d
	}
	t := time.NewTicker(curInterval())
	defer t.Stop()
	for {
		select {
		case <-t.C:
			write()
			t.Reset(curInterval())
		case <-ctx.Done():
			return
		}
	}
}

// ForgetNode drops a node's stats entry (counters + top-10 slow) from the local
// recorder. Called when a sandlot node disconnects so its stale unmount data does
// not linger in /stats or the next persisted etcd snapshot. A reconnecting node
// (same nodeID) starts fresh. No-op if the node has no entry.
func (s *UnmountStats) ForgetNode(nodeID string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.nodes, nodeID)
	// Reap this node's pending last-command entries (sandfs it mounted but
	// never unmounted here — e.g. it crashed with active mounts). Per-node
	// cardinality is bounded by the node's pool size (dozens–hundreds), so a
	// full scan is cheap and avoids an unbounded leak across node churn.
	prefix := nodeID + "\x00"
	for k := range s.lastCmd {
		if strings.HasPrefix(k, prefix) {
			delete(s.lastCmd, k)
		}
	}
}

// nodeLocked returns the node's stats, creating it if absent. Caller MUST hold s.mu.
func (s *UnmountStats) nodeLocked(nodeID string) *nodeStats {
	ns, ok := s.nodes[nodeID]
	if !ok {
		ns = &nodeStats{
			topSlow:      make([]SlowEntry, 0, s.topN),
			recent:       newDurationRing(DefaultRecentN),
			recentWarden: newDurationRing(DefaultRecentN),
			leaseFire:    newDurationRing(DefaultRecentN),
		}
		s.nodes[nodeID] = ns
	}
	return ns
}

// durationRing is a fixed-capacity rolling window of nanosecond samples.
// Insertion is O(1) and allocation-free; snapshotting allocates a copy so the
// percentile computation runs outside the collector lock.
type durationRing struct {
	buf []uint64
	pos int
	n   int
}

func newDurationRing(capacity int) durationRing {
	if capacity <= 0 {
		capacity = DefaultRecentN
	}
	return durationRing{buf: make([]uint64, capacity)}
}

// add appends one sample, overwriting the oldest once full.
func (r *durationRing) add(v uint64) {
	if len(r.buf) == 0 {
		return
	}
	r.buf[r.pos] = v
	r.pos = (r.pos + 1) % len(r.buf)
	if r.n < len(r.buf) {
		r.n++
	}
}

// values returns the current window in insertion order (a copy).
func (r *durationRing) values() []uint64 {
	if r.n == 0 {
		return nil
	}
	if r.n < len(r.buf) {
		return append([]uint64(nil), r.buf[:r.n]...)
	}
	// Full ring: the oldest sample sits at pos.
	out := make([]uint64, 0, r.n)
	out = append(out, r.buf[r.pos:]...)
	out = append(out, r.buf[:r.pos]...)
	return out
}

// snapshot summarizes the window. n=0 → all zeroes.
func (r *durationRing) snapshot() RingSnapshot {
	v := r.values()
	if len(v) == 0 {
		return RingSnapshot{}
	}
	sort.Slice(v, func(i, j int) bool { return v[i] < v[j] })
	return RingSnapshot{
		N:     len(v),
		P50Ms: percentileMs(v, 0.50),
		P95Ms: percentileMs(v, 0.95),
		P99Ms: percentileMs(v, 0.99),
		MaxMs: msFromNs(v[len(v)-1]),
	}
}

// percentileMs returns the p-th percentile (0..1) of ascending-sorted ns
// samples in milliseconds. Index convention matches the benchmark scripts:
// sorted[int(n*p)], clamped to the last sample.
func percentileMs(sorted []uint64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(float64(len(sorted)) * p)
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return msFromNs(sorted[idx])
}

// msFromNs converts nanoseconds to a 3-decimal millisecond value (µs
// resolution — sub-millisecond lease-fire lags must not collapse to 0).
func msFromNs(ns uint64) float64 {
	return math.Round(float64(ns)/1e3) / 1e3
}

// insertSlow keeps top sorted descending by GatewayMs, capped at n. If the slice
// is not yet full the entry is always inserted; once full, the entry replaces the
// smallest (last) only if it is slower.
func insertSlow(top *[]SlowEntry, n int, e SlowEntry) {
	arr := *top
	// Find the first index whose GatewayMs is < e.GatewayMs (descending order).
	idx := sort.Search(len(arr), func(i int) bool { return arr[i].GatewayMs < e.GatewayMs })
	if len(arr) < n {
		// Room: insert at idx.
		arr = append(arr, SlowEntry{})
		copy(arr[idx+1:], arr[idx:])
		arr[idx] = e
		*top = arr
		return
	}
	// Full: only keep if it beats the smallest (last).
	if e.GatewayMs <= arr[len(arr)-1].GatewayMs {
		return
	}
	// Drop the last, insert at idx (idx < n here since the new entry beats the
	// last, so idx <= len-1).
	copy(arr[idx+1:], arr[idx:len(arr)-1])
	arr[idx] = e
	*top = arr
}

func truncateCmd(s string) string {
	if len(s) <= commandTruncate {
		return s
	}
	return s[:commandTruncate] + "..."
}

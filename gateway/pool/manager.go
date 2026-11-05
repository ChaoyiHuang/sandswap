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
// Package pool manages compute nodes (sandlots) and their per-spec VM capacity.
// Under delegation the gateway no longer
// tracks individual microVMs: sandlot owns the VM pool + VM<->sandfs binding.
// The gateway selects a NODE for a cold mount based on the node's per-spec clean
// capacity (reported by sandlot heartbeats) and routes workload RPCs by
// sandfs_id; sandlot resolves the sandfs to a VM locally.

package pool

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"strings"
	"sync"
	"time"
)

// SpecCapacity is one spec's VM availability on a node. The gateway derives
// clean = total - bound for ROUTING: total is reconciled from the
// sandlot heartbeat (stable), bound is tracked from the gateway's OWN
// mount/unmount actions (send-time reservation), so clean is real-time accurate
// for this gateway - unlike the sandlot's heartbeat clean, which lags by ~30s
// and can't be reconciled due to in-flight RPCs. The Clean field below is the
// raw heartbeat view (kept for diagnostics/bootstrap); routing uses cleanCount().
type SpecCapacity struct {
	SpecID string
	Total  uint32
	// Clean is the sandlot heartbeat's clean count (diagnostics only - NOT used
	// for routing, which uses cleanCount() = total - bound). Kept so bootstrap
	// and tests can express capacity without bound bookkeeping.
	Clean uint32
	// Bound is the count of VMs of this spec the gateway has bound (mount
	// dispatched / lease held). Gateway-tracked; NOT reconciled from heartbeat.
	Bound uint32
	// MinCleanWindow is the 60s-window minimum CLEAN count for this spec (tail
	// floor). 0 means the node hit zero clean for this spec in the last 60s.
	MinCleanWindow uint32
	// ZeroCleanCount is the number of 60s-window ticks where clean hit 0.
	ZeroCleanCount uint32
}

// cleanCount returns the derived clean count (total - bound, saturated at 0)
// used for ROUTING. This is real-time accurate for this gateway's actions -
// NOT the sandlot's heartbeat Clean (which lags ~30s and breaks reuse-nodeA
// when bound returns to 0). Saturates so an in-flight over-reservation
// (bound > total transiently) reads as 0 clean, not negative.
func (c *SpecCapacity) cleanCount() uint32 {
	if c.Bound >= c.Total {
		return 0
	}
	return c.Total - c.Bound
}

// NodeMetrics mirrors a sandlot node.s scheduling signals,
// aggregated from heartbeats for load publishing + node scoring.
type NodeMetrics struct {
	DutyShort      float64
	DutyLong       float64
	DutyDaily      float64 // EWMA busy ratio τ≈1day (durable headroom)
	DutyVar        float64
	ExecRate       float64
	AvgExecMS      float64
	AvgGapMS       float64
	HostCPU        float64
	HostMemAvailMB uint64
	ActiveSandfs   uint32
	ActiveBgExecs  uint32
	TotalVMs       uint32
	IdleDurationMS int64
	MaxDutyWindow  float64
	// PeakConcurrentExecs: node's all-time peak concurrent sync execs
	// (0 = serial historic peak). Reported in the heartbeat NodeMetrics.
	PeakConcurrentExecs uint32
	// SlotWaitMS / SlotWaitEvents: warden-pool queue wait (EWMA ms + count).
	// Non-trivial wait ⇒ the spec's exec_slots is undersized.
	SlotWaitMS     float64
	SlotWaitEvents uint64
	// RecycleTriggers: cumulative POLICY recycles — a VM deliberately destroyed
	// instead of returned to CLEAN (lifetime caps incl. the distinct-agent
	// cap, the memory threshold, or pool scale-down). High rate ⇒ thresholds
	// too eager for the workload.
	RecycleTriggers uint64
	// StrandedReservationsMB / StrandedCIDs: memory reservations (MiB) + CIDs
	// held by VMs whose destroy could not confirm process death (D-state
	// sandvmm, failed lifecycle RPC) — released only at sandlot restart. The
	// silent pool-capacity shrink behind RESOURCE SHORTAGE.
	StrandedReservationsMB uint64
	StrandedCIDs           uint32
}

// Node represents a compute node running sandlot + sandvmm.
type Node struct {
	ID         string
	PoolTarget int // intended pool size (from NodeHello.pool_target). 0 = no cap.
	// Capacity maps specID -> clean/total VM counts, updated from heartbeats.
	Capacity map[string]*SpecCapacity
	// Specs maps specID -> {vcpus, memory_mb}, learned from NodeHello.specs at
	// connect. The gateway matches a sandfs's required vcpus/memory against these
	// concrete resources (not spec names) and resolves the floor specID to send
	// to sandlot. A specID absent here falls back to the static spec table.
	Specs map[string]VMSpec
	// Metrics holds the node's latest scheduling signals, updated from heartbeats.
	Metrics *NodeMetrics
	// lastVMCrash is the wall-clock time of the most recent VM_EVENT_CRASHED
	// this node reported (NoteVMCrash). Zero = no crash in the node's lifetime.
	// All Node writers hold m.mu, so no extra lock is needed. A node reconnect
	// (RemoveNode + AddNode) starts clean — a crash is not sticky across a
	// node restart.
	lastVMCrash time.Time
}

// hasClean reports whether the node has a CLEAN VM whose resources satisfy the
// required vcpus/memory (0 = no requirement on that dimension).
func (n *Node) hasClean(minVCPUs uint32, minMemoryMB uint64) bool {
	for spec, c := range n.Capacity {
		if c.cleanCount() > 0 && n.specSatisfies(spec, minVCPUs, minMemoryMB) {
			return true
		}
	}
	return false
}

// fittingClean returns the total CLEAN VM count across specs satisfying the
// required vcpus/memory.
func (n *Node) fittingClean(minVCPUs uint32, minMemoryMB uint64) uint32 {
	var total uint32
	for spec, c := range n.Capacity {
		if c.cleanCount() > 0 && n.specSatisfies(spec, minVCPUs, minMemoryMB) {
			total += c.cleanCount()
		}
	}
	return total
}

// specSatisfies reports whether the named spec on this node meets the required
// vcpus/memory (0 = no requirement on that dimension). Resources come from the
// learned Specs table; a specID absent there falls back to the static table.
func (n *Node) specSatisfies(specID string, minVCPUs uint32, minMemoryMB uint64) bool {
	if minVCPUs == 0 && minMemoryMB == 0 {
		return true // no requirement — any spec works
	}
	vcpus, memMB, ok := n.specResources(specID)
	if !ok {
		return false
	}
	return vcpus >= minVCPUs && memMB >= minMemoryMB
}

// specResources returns the vcpus/memory_mb for a specID, consulting the learned
// Specs table first and the static spec table as a fallback. ok=false if neither
// knows the specID.
func (n *Node) specResources(specID string) (vcpus uint32, memMB uint64, ok bool) {
	if n.Specs != nil {
		if s, found := n.Specs[specID]; found {
			return s.VCPUs, s.MemoryMB, true
		}
	}
	if s, found := staticSpec(specID); found {
		return s.VCPUs, s.MemoryMB, true
	}
	return 0, 0, false
}

// resolveFloorSpec returns the specID of the smallest spec on this node (by
// memory, then vcpus) that satisfies the required vcpus/memory — the floor sent
// to sandlot as min_spec (sandlot best-fits the actual clean VM). Returns "" if
// no spec satisfies. Caller holds m.mu (read-only on n).
func (n *Node) resolveFloorSpec(minVCPUs uint32, minMemoryMB uint64) string {
	if minVCPUs == 0 && minMemoryMB == 0 {
		return "" // no requirement → sandlot picks any clean VM (empty min_spec)
	}
	var floorID string
	var floorVCPUs uint32
	var floorMem uint64
	for spec := range n.Capacity {
		if !n.specSatisfies(spec, minVCPUs, minMemoryMB) {
			continue
		}
		v, m, _ := n.specResources(spec)
		if floorID == "" || m < floorMem || (m == floorMem && v < floorVCPUs) {
			floorID = spec
			floorVCPUs = v
			floorMem = m
		}
	}
	return floorID
}

// VMSpec defines a VM resource specification (kept for spec helpers; the
// gateway no longer tracks individual VMs).
type VMSpec struct {
	ID       string // "small", "medium", "large", etc.
	VCPUs    uint32
	MemoryMB uint64
	// ExecSlots is the node's declared per-VM sync-command concurrency (the
	// sandlot's per-VM warden connection-pool size). Informational for the
	// gateway (capacity display / /stats); enforcement lives in sandlot.
	ExecSlots uint32
}

// Built-in static spec table — a fallback for specIDs absent from a node's
// learned Specs table (e.g., a spec reported in a heartbeat before NodeHello
// processing, or a node that omits specs). The learned table is authoritative.
var staticSpecs = map[string]VMSpec{
	"small":  {ID: "small", VCPUs: 2, MemoryMB: 256, ExecSlots: 3},
	"medium": {ID: "medium", VCPUs: 4, MemoryMB: 1024, ExecSlots: 4},
	"large":  {ID: "large", VCPUs: 8, MemoryMB: 2048, ExecSlots: 5},
}

// staticSpec looks up a specID in the built-in table.
func staticSpec(specID string) (VMSpec, bool) {
	s, ok := staticSpecs[specID]
	return s, ok
}

// StaticMaxSpecResources is the largest resource shape in the built-in spec
// table — the ceiling a human gateway (which holds no pool) clamps storage-
// plane-declared minimums against().
func StaticMaxSpecResources() (vcpus uint32, memMB uint64) {
	return largestOf(staticSpecs)
}

// MaxSpecResources is the largest advertised spec across connected nodes
// (learned tables), floored by the built-in table. The human gateway clamps a
// storage-plane-declared minimum resource against this ceiling before it
// becomes a PERSISTENT placement requirement: a value above every advertised
// spec would make Pool.Acquire refuse forever (permanent
// NO_AVAILABLE_SANDBOX). The ceiling is a spec that DOMINATES the others
// (memory first, then vcpus — the resolveFloorSpec ordering), so a clamped
// minimum is satisfiable by at least that spec.
func (m *Manager) MaxSpecResources() (vcpus uint32, memMB uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	vcpus, memMB = largestOf(staticSpecs)
	for _, n := range m.nodes {
		v, mem := largestOf(n.Specs)
		if mem > memMB || (mem == memMB && v > vcpus) {
			vcpus, memMB = v, mem
		}
	}
	return vcpus, memMB
}

// largestOf returns the spec dominating the table by (memory, then vcpus) —
// the same ordering resolveFloorSpec uses.
func largestOf(table map[string]VMSpec) (vcpus uint32, memMB uint64) {
	for _, s := range table {
		if s.MemoryMB > memMB || (s.MemoryMB == memMB && s.VCPUs > vcpus) {
			vcpus, memMB = s.VCPUs, s.MemoryMB
		}
	}
	return vcpus, memMB
}

// SchedPolicy configures node placement.
type SchedPolicy struct {
	// Binpack vs spread: binpack (default) prefers busy nodes (higher duty) so
	// work concentrates onto fewer nodes; spread prefers idle nodes (lower duty).
	Binpack bool

	// Scorer weights. Every component is normalized to [0,1]: duty/cpu ratios
	// are fractions already, and the clean term is cleanFrac (fitting clean
	// count / pool target) — so no weight can be swamped by an unbounded one.
	WLoad  float64 // load term (duty_long for binpack, 1-duty_long for spread)
	WHost  float64 // host headroom (1 - host_cpu/100)
	WClean float64 // cleanFrac: fitting clean VMs / pool target (bootstrap/tie-break proxy when no metrics)
	WDaily float64 // durable headroom (1 - duty_daily)
	WRisk  float64 // tail-risk penalty: 60s peak duty + duty volatility + zero-clean frequency

	// Hard filter caps (0 disables that cap). Conservative by default — headroom
	// is a scoring preference, not a hard gate.
	HostCPUHard float64 // reject nodes above this host CPU %
	DutyHard    float64 // reject nodes above this duty_long

	// FloorFrac is the tail-floor fraction: a node is rejected when its 60s
	// min_clean_window for a fitting spec is below max(1, FloorFrac·pool_target).
	// Gates on the TAIL (a node that recently hit zero clean is excluded even if
	// it currently has one). 0 = disabled.
	FloorFrac float64
}

// DefaultSchedPolicy returns the binpack defaults: binpack concentrates new
// placements onto busy nodes; the tail-risk penalty + floor + hasClean guard
// keep it from overloading a spiky or exhausted node.
func DefaultSchedPolicy() SchedPolicy {
	return SchedPolicy{
		Binpack:   true,
		WLoad:     0.6,
		WHost:     0.3,
		WClean:    0.1,
		WDaily:    0.2,
		WRisk:     0.15,
		FloorFrac: 0.2,
	}
}

// Manager selects compute nodes for cold mounts. It does NOT track individual
// VMs (sandlot owns them); it tracks per-node per-spec clean capacity from
// heartbeats and picks a node that can serve a sandfs's min_spec.
type Manager struct {
	mu     sync.Mutex
	nodes  map[string]*Node
	client SandlotClient
	logger *slog.Logger
	sched  SchedPolicy

	// unmountStats records per-node unmount latency/counters. nil = recording
	// disabled (tests). Set via SetUnmountRecorder before serving requests.
	unmountStats UnmountRecorder

	// saturationSince tracks the wall-clock time (Unix monotonic via time.Now)
	// since ALL connected nodes simultaneously had zero derived clean VMs across
	// every spec (i.e. the gateway is fully saturated). Zero means "not currently
	// all-saturated". Used by IsSustainedSaturated to gate voluntary load
	// shedding: only shed ownership after saturation has persisted >= a threshold,
	// avoiding reactions to transient spikes. Updated in UpdateNodeCapacity /
	// ReserveBound / ReleaseBound / AdjustBound (the same paths that move clean
	// counts).
	saturationSince time.Time
}

// NewManager creates a new node-capacity manager. client may be nil in tests.
func NewManager(client SandlotClient, logger *slog.Logger) *Manager {
	if logger == nil {
		logger = slog.Default()
	}
	return &Manager{
		nodes:  make(map[string]*Node),
		client: client,
		logger: logger,
		sched:  DefaultSchedPolicy(),
	}
}

// SetSchedPolicy updates the placement policy (weights + binpack/spread + caps).
// Wired from the hot-reloadable sched config; the default is binpack
// (DefaultSchedPolicy / config.Sched).
func (m *Manager) SetSchedPolicy(p SchedPolicy) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sched = p
}

// SetUnmountRecorder wires the per-node unmount stats recorder. nil disables
// recording (tests). Called once at startup before serving requests.
func (m *Manager) SetUnmountRecorder(r UnmountRecorder) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.unmountStats = r
}

// AddNode registers a sandlot node. Called when sandlot connects via the stream.
func (m *Manager) AddNode(nodeID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.nodes[nodeID]; !ok {
		m.nodes[nodeID] = &Node{ID: nodeID, Capacity: make(map[string]*SpecCapacity)}
		m.logger.Info("node registered", "nodeID", nodeID)
	}
	m.recomputeSaturationLocked()
}

// maxPlausiblePoolTarget bounds NodeHello.pool_target(). The target
// scales the gateway's cleanFraction normalization (a node's own target, else
// the cluster max as the shared denominator) and the tail-floor threshold — a
// node-chosen value in the billions would become the cluster denominator and
// collapse the clean term fleet-wide. No memory-admissible real pool
// approaches this bound: the node's own config-time admission requires
// sum(count × specMem) ≤ 80% host MemTotal, and VM overhead keeps real pools
// in the tens-to-hundreds. This is a plausibility bound, not a capacity check.
const maxPlausiblePoolTarget = 10000

// SetNodePoolTarget sets the node's intended pool size, as reported in
// NodeHello.pool_target, clamped to maxPlausiblePoolTarget. Returns the
// applied value and whether the report was clamped, so the caller can log the
// drift by name (the caller owns the logger context of the hello).
func (m *Manager) SetNodePoolTarget(nodeID string, target int) (applied int, clamped bool) {
	if target > maxPlausiblePoolTarget {
		target = maxPlausiblePoolTarget
		clamped = true
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if node, ok := m.nodes[nodeID]; ok {
		node.PoolTarget = target
	}
	return target, clamped
}

// Crash-penalty scheduling signal. A node that just reported a VM crash
// (VM_EVENT_CRASHED) is deprioritized for new cold mounts for a short window:
// the heartbeat's Total is what actually removes the dead VM from capacity
// (~30s cadence), so without this the node still looks capacity-rich and may
// win an Acquire whose mount then fails with NO_AVAILABLE_SANDBOX (a wasted
// RTT). The penalty is deliberately soft — scoring only, never a hard filter —
// so a single-node deployment is never starved by it, and it never feeds the
// saturation/shedding signals (a cosmetic penalty must not look like load).
const (
	// crashPenaltyWindow is how long a recent crash deprioritizes a node.
	// Must exceed one heartbeat (30s): the heartbeat reconciles Total, and the
	// margin covers the replacement VM's boot. Not a flag on purpose — promote
	// to -crash-penalty-window-sec only if ops needs to tune it.
	crashPenaltyWindow = 2 * time.Minute
)

// NoteVMCrash records a VM crash reported by nodeID (stream VM_EVENT_CRASHED,
// wired in gateway/cmd/main.go's wireStreamCallbacks). It does NOT touch
// capacity: the node's own heartbeat reconciles Total, and there is no
// vmID→sandfs mapping to release a lease with. Unknown nodeID (node already
// disconnected) is a no-op.
func (m *Manager) NoteVMCrash(nodeID string) {
	m.noteVMCrashAt(nodeID, time.Now())
}

// noteVMCrashAt is the injectable-clock core of NoteVMCrash (internal tests).
func (m *Manager) noteVMCrashAt(nodeID string, now time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if node, ok := m.nodes[nodeID]; ok {
		node.lastVMCrash = now
		m.logger.Info("node reported VM crash; deprioritizing for new mounts",
			"nodeID", nodeID, "window_sec", int(crashPenaltyWindow.Seconds()))
	}
}

// recentVMCrash reports whether the node reported a crash within
// crashPenaltyWindow. Caller holds m.mu.
func (n *Node) recentVMCrash(now time.Time) bool {
	return !n.lastVMCrash.IsZero() && now.Sub(n.lastVMCrash) < crashPenaltyWindow
}

// RemoveNode removes a sandlot node and its capacity. Called when a sandlot
// disconnects (OnDisconnect callback). No per-VM cleanup — sandlot owns VMs.
// Also drops the node's unmount stats entry so stale data does not linger in
// /stats or the next persisted etcd snapshot; a reconnecting node starts fresh.
func (m *Manager) RemoveNode(nodeID string) {
	m.mu.Lock()
	recorder := m.unmountStats
	delete(m.nodes, nodeID)
	m.logger.Info("node removed from pool", "nodeID", nodeID)
	m.recomputeSaturationLocked()
	m.mu.Unlock()
	if recorder != nil {
		// ForgetNode takes the recorder's own lock; call outside m.mu to keep the
		// lock ordering single-directional (m.mu never nests recorder.mu).
		recorder.ForgetNode(nodeID)
	}
}

// SetNodeSpecs records a node's spec definitions (specID → {vcpus, memory_mb})
// learned from NodeHello.specs at connect. The gateway matches a sandfs's
// required vcpus/memory against these concrete resources and resolves the floor
// specID to send to sandlot. Idempotent; replaces any prior table.
func (m *Manager) SetNodeSpecs(nodeID string, specs []VMSpec) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n, ok := m.nodes[nodeID]
	if !ok {
		return
	}
	table := make(map[string]VMSpec, len(specs))
	for _, s := range specs {
		if s.ID == "" {
			continue
		}
		table[s.ID] = s
	}
	n.Specs = table
}

// UpdateNodeCapacity replaces a node's per-spec clean/total VM counts from a
// heartbeat. Under delegation the gateway uses this for node selection. The map
// is REPLACED (not merged): an empty heartbeat means the node has no live VMs
// (all destroyed / pendingDestroy), so stale entries must not persist — a stale
// non-zero count would keep the node routable and inflate /stats forever.
func (m *Manager) UpdateNodeCapacity(nodeID string, caps []SpecCapacity) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n, ok := m.nodes[nodeID]
	if !ok {
		return
	}
	// Reconcile ONLY total (stable, not affected by in-flight RPCs). Preserve
	// Bound (gateway-tracked) - clean is derived = total - bound, NOT reconciled
	// from the sandlot heartbeat. Replacing the whole map (as the
	// old code did) would wipe Bound and revert clean to the stale heartbeat view.
	seen := make(map[string]bool, len(caps))
	for i := range caps {
		c := caps[i]
		existing := n.Capacity[c.SpecID]
		if existing == nil {
			existing = &SpecCapacity{SpecID: c.SpecID}
			n.Capacity[c.SpecID] = existing
		}
		existing.Total = c.Total
		existing.Clean = c.Clean // heartbeat view (diagnostics); routing uses cleanCount()
		existing.MinCleanWindow = c.MinCleanWindow
		existing.ZeroCleanCount = c.ZeroCleanCount
		seen[c.SpecID] = true
	}
	// Drop specs no longer reported, but only if bound==0 (don't drop a spec with
	// an in-flight bound reservation).
	for spec, c := range n.Capacity {
		if !seen[spec] && c.Bound == 0 {
			delete(n.Capacity, spec)
		}
	}
	m.recomputeSaturationLocked()
}

// defaultSpec normalizes an empty spec to "medium" (specRank's default for
// unknown specs), so a reservation under "" doesn't sit in a phantom bucket.
func defaultSpec(spec string) string {
	if spec == "" {
		return "medium"
	}
	return spec
}

// ReserveBound increments the bound count for a spec on a node - a send-time
// reservation when a cold-mount RPC is dispatched, so the derived clean count
// drops immediately (before the response). The spec is provisional (min_spec)
// until AdjustBound corrects it to the actual spec from the response.
func (m *Manager) ReserveBound(nodeID, spec string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reserveBoundLocked(nodeID, spec)
}

// reserveBoundLocked is the lock-free core of ReserveBound. Caller holds m.mu.
// Used by Acquire so the bound increment happens atomically with node selection
// — without this, concurrent cold mounts all see the same clean=1 node and pick
// it before any reservation drops the derived clean, causing N-1 spurious
// NO_AVAILABLE_SANDBOX rejections (thundering-herd on a single clean VM).
func (m *Manager) reserveBoundLocked(nodeID, spec string) {
	spec = defaultSpec(spec)
	n, ok := m.nodes[nodeID]
	if !ok {
		return
	}
	c := n.Capacity[spec]
	if c == nil {
		c = &SpecCapacity{SpecID: spec}
		n.Capacity[spec] = c
	}
	c.Bound++
	m.recomputeSaturationLocked()
}

// in the mount response. Decrements provSpec, increments actualSpec. No-op if
// equal.
//
// The node-reported actualSpec is only trusted when this node can ACCOUNT for
// it: it must name a spec in the node's advertised table (or the built-in
// static table). An unrecognized string must never become a persistent
// capacity bucket — it would inflate the map, skew the derived clean counts,
// and leak the provisional bound (ReleaseBound would target a bucket nothing
// holds). Returns the spec the reservation now sits under; callers record
// THAT value on the lease.
func (m *Manager) AdjustBound(nodeID, provSpec, actualSpec string) string {
	provSpec = defaultSpec(provSpec)
	actualSpec = defaultSpec(actualSpec)
	if provSpec == actualSpec {
		return actualSpec
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	n, ok := m.nodes[nodeID]
	if !ok {
		return provSpec
	}
	if _, _, known := n.specResources(actualSpec); !known {
		m.logger.Warn("pool: node-reported actual spec is outside the node's advertised spec table; keeping the provisional reservation",
			"nodeID", nodeID, "provSpec", provSpec, "reportedSpec", actualSpec)
		return provSpec
	}
	if c := n.Capacity[provSpec]; c != nil && c.Bound > 0 {
		c.Bound--
	}
	c := n.Capacity[actualSpec]
	if c == nil {
		c = &SpecCapacity{SpecID: actualSpec}
		n.Capacity[actualSpec] = c
	}
	c.Bound++
	m.recomputeSaturationLocked()
	return actualSpec
}

// ValidSpec reports whether spec is a specID this pool can account for on the
// node: one the node advertised in its spec table, or a built-in static spec.
// The gateway's spec-sensitive bookkeeping (the unmount lease's recorded spec
// in particular) must only ever hold validated values — a node-reported string
// that fails this check must fall back to the gateway-chosen spec, never
// overwrite accounting state.
func (m *Manager) ValidSpec(nodeID, spec string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	n, ok := m.nodes[nodeID]
	if !ok {
		return false
	}
	_, _, known := n.specResources(spec)
	return known
}

// ReleaseBound decrements the bound count (unmount frees the VM). The derived
// clean count rises, making the node eligible for reuse (e.g. nodeA
// after a lease-expiry unmount, since pool.Acquire(nodeA) now sees real-time
// clean). Idempotent (saturates at 0).
func (m *Manager) ReleaseBound(nodeID, spec string) {
	spec = defaultSpec(spec)
	m.mu.Lock()
	defer m.mu.Unlock()
	n, ok := m.nodes[nodeID]
	if !ok {
		return
	}
	if c := n.Capacity[spec]; c != nil && c.Bound > 0 {
		c.Bound--
	}
	m.recomputeSaturationLocked()
}

// UpdateNodeMetrics stores a node's latest scheduling signals from a heartbeat.
func (m *Manager) UpdateNodeMetrics(nodeID string, metrics NodeMetrics) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if n, ok := m.nodes[nodeID]; ok {
		mm := metrics
		n.Metrics = &mm
	}
}

// LoadSnapshot returns each connected node's latest metrics, keyed by node ID.
// Nodes with no metrics yet are absent (the load publisher treats them as
// full-headroom/no-data).
func (m *Manager) LoadSnapshot() map[string]NodeMetrics {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]NodeMetrics, len(m.nodes))
	for id, n := range m.nodes {
		if n.Metrics != nil {
			out[id] = *n.Metrics
		}
	}
	return out
}

// NodeCleanCounts returns each node's aggregate clean + total VM counts
// (nodeID -> {clean, total}), for the load publisher.
func (m *Manager) NodeCleanCounts() map[string][2]uint32 {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string][2]uint32, len(m.nodes))
	for id, n := range m.nodes {
		var clean, total uint32
		for _, c := range n.Capacity {
			clean += c.cleanCount()
			total += c.Total
		}
		out[id] = [2]uint32{clean, total}
	}
	return out
}

// Acquire picks a node to serve a sandfs requiring minVCPUs/minMemoryMB, using
// the Filter → Affinity → Scorer pipeline:
//  1. Filter (hard): node connected with a fitting CLEAN VM, and under the
//     optional host/duty caps.
//  2. Affinity (strong): the preferredNode (ownership cache-affinity) is
//     returned if it passes the filter — cache warmth beats capacity.
//  3. Scorer (policy): among remaining eligible nodes, pick the highest score
//     (binpack default: prefer high duty + low host pressure, capped by the
//     hard filters; spread flips the duty terms to prefer idle nodes).
//
// It returns the chosen nodeID plus the floor specID resolved on that node (the
// smallest spec satisfying the requirement; "" when the requirement is empty →
// sandlot picks any clean VM). Returns ("", "", err) when no node is eligible.
//
// Acquire atomically reserves one bound VM under the returned (nodeID, spec) so
// the derived clean count drops before a concurrent Acquire can read it. The
// caller MUST pair this with either AdjustBound(nodeID, spec, actualSpec) on a
// successful mount response (correcting the provisional spec) or
// ReleaseBound(nodeID, spec) on a failure/abort — otherwise the bound leaks and
// the VM stays over-reserved. Do NOT call ReserveBound separately after Acquire;
// it is already done.
func (m *Manager) Acquire(preferredNode string, minVCPUs uint32, minMemoryMB uint64) (string, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	node, spec, err := m.selectNodeLocked(preferredNode, minVCPUs, minMemoryMB)
	if err != nil {
		return "", "", err
	}
	// Atomically reserve the bound capacity for this cold mount so the derived
	// clean count drops before another concurrent Acquire reads it.
	m.reserveBoundLocked(node, spec)
	return node, spec, nil
}

// PeekNode runs the same filter/score selection as Acquire but reserves
// NOTHING: it answers "which node would serve this sandfs right now". Used to
// pick the CANDIDATE PLACEMENT written into the ownership record at claim time,
// so a record's node_id is never empty while a mount exists (see
// createOwnership). Because it takes no capacity, the subsequent real Acquire
// may land elsewhere if capacity shifted in between — NoteMounted then
// publishes the corrected placement (one cold-path write).
//
// An empty result (error) is itself meaningful and is what makes the invariant
// hold: no node could be selected, so no mount can possibly be dispatched.
func (m *Manager) PeekNode(preferredNode string, minVCPUs uint32, minMemoryMB uint64) (string, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.selectNodeLocked(preferredNode, minVCPUs, minMemoryMB)
}

// selectNodeLocked picks the node+spec to serve a cold mount WITHOUT reserving
// capacity. Caller holds m.mu.
func (m *Manager) selectNodeLocked(preferredNode string, minVCPUs uint32, minMemoryMB uint64) (string, string, error) {
	if len(m.nodes) == 0 {
		return "", "", errors.New("no compute nodes connected")
	}

	// Affinity: preferredNode (ownership cache-affinity) if eligible. Kept
	// unconditional on the crash penalty on purpose: preferredNode is the node
	// the sandfs is already mounted on / migrated to — overriding it would
	// break affinity for a cosmetic penalty.
	if preferredNode != "" {
		if n, ok := m.nodes[preferredNode]; ok && m.nodeEligible(n, minVCPUs, minMemoryMB) {
			spec := n.resolveFloorSpec(minVCPUs, minMemoryMB)
			if hotPathDebug.Load() {
				m.logger.Info("selected node (preferred)", "node", preferredNode, "minVCPUs", minVCPUs, "minMemMB", minMemoryMB, "spec", spec)
			}
			return preferredNode, spec, nil
		}
	}

	// Filter + score the rest, preferring nodes with no recent VM crash
	// (soft preference: nodeEligible is NOT touched — a hard filter would turn
	// "one node crashed" into NO_AVAILABLE_SANDBOX on single-node deployments).
	now := time.Now()
	// cleanFrac fallback denominators, computed ONCE per selection pass: every
	// node without its own pool target shares the cluster max pool target, and
	// when no node reports one, the batch's max fitting-clean count is the
	// scale. Computing them inside nodeScore would rescan all nodes per scored
	// node — O(n²) per selection for the same pass-invariant values.
	clusterMaxTarget := m.maxPoolTargetLocked()
	batchMaxClean := uint32(0)
	if clusterMaxTarget == 0 {
		batchMaxClean = m.maxFittingCleanLocked(minVCPUs, minMemoryMB)
	}
	bestNode := ""
	bestSpec := ""
	bestScore := math.Inf(-1)
	bestClean := uint32(0)
	bestCrashFreeNode := ""
	bestCrashFreeSpec := ""
	bestCrashFreeScore := math.Inf(-1)
	bestCrashFreeClean := uint32(0)
	for _, n := range m.nodes {
		if !m.nodeEligible(n, minVCPUs, minMemoryMB) {
			continue
		}
		score := m.nodeScore(n, minVCPUs, minMemoryMB, clusterMaxTarget, batchMaxClean)
		clean := n.fittingClean(minVCPUs, minMemoryMB)
		// Tie-break on clean capacity when scores are close.
		if score > bestScore || (score == bestScore && clean > bestClean) {
			bestScore = score
			bestClean = clean
			bestNode = n.ID
			bestSpec = n.resolveFloorSpec(minVCPUs, minMemoryMB)
		}
		if !n.recentVMCrash(now) {
			if score > bestCrashFreeScore || (score == bestCrashFreeScore && clean > bestCrashFreeClean) {
				bestCrashFreeScore = score
				bestCrashFreeClean = clean
				bestCrashFreeNode = n.ID
				bestCrashFreeSpec = n.resolveFloorSpec(minVCPUs, minMemoryMB)
			}
		}
	}
	// Every eligible node has a recent crash → fall back to the best of them
	// (the penalty must never starve a deployment, only deprioritize).
	selectedScore := bestCrashFreeScore
	if bestCrashFreeNode == "" {
		bestCrashFreeNode = bestNode
		bestCrashFreeSpec = bestSpec
		selectedScore = bestScore
	}
	bestNode, bestSpec = bestCrashFreeNode, bestCrashFreeSpec
	if bestNode == "" {
		// Snapshot every node's capacity so the refusal is diagnosable: per-spec
		// total/bound/clean is exactly what the filter above rejected on.
		for _, n := range m.nodes {
			caps := make([]string, 0, len(n.Capacity))
			for specName, c := range n.Capacity {
				caps = append(caps, fmt.Sprintf("%s{total=%d,bound=%d,clean=%d}", specName, c.Total, c.Bound, c.cleanCount()))
			}
			m.logger.Warn("node rejected by filter",
				"node", n.ID, "minVCPUs", minVCPUs, "minMemMB", minMemoryMB,
				"capacity", strings.Join(caps, ","), "recentCrash", n.recentVMCrash(now))
		}
		// WRAP THE SENTINEL: the handlers' named retryable refusal
		// (503 NO_AVAILABLE_SANDBOX + retry_after_ms) is keyed on
		// errors.Is(..., ErrNoAvailableSandbox). A bare errors.New here made
		// the PLACEMENT half of the same condition answer as an unclassified
		// error (observed: /agent/file returned {"error":"no available
		// sandbox on connected nodes"} with no error_code/retryable field,
		// while /agent/execute's node-side variant carried both).
		return "", "", fmt.Errorf("%w: no node with capacity for minVCPUs=%d minMemMB=%d", ErrNoAvailableSandbox, minVCPUs, minMemoryMB)
	}
	if hotPathDebug.Load() {
		m.logger.Info("selected node (scored)", "node", bestNode, "minVCPUs", minVCPUs, "minMemMB", minMemoryMB, "spec", bestSpec, "score", selectedScore)
	}
	return bestNode, bestSpec, nil
}

// nodeEligible applies the hard Filter: the node must have a fitting CLEAN VM
// and stay under the optional host/duty caps (0 = cap disabled). Caller holds m.mu.
func (m *Manager) nodeEligible(n *Node, minVCPUs uint32, minMemoryMB uint64) bool {
	if !n.hasClean(minVCPUs, minMemoryMB) {
		return false
	}
	if n.Metrics != nil {
		if m.sched.DutyHard > 0 && n.Metrics.DutyLong > m.sched.DutyHard {
			return false
		}
		if m.sched.HostCPUHard > 0 && n.Metrics.HostCPU > m.sched.HostCPUHard {
			return false
		}
	}
	// Tail floor: require at least one fitting spec
	// whose 60s min-clean window is at/above the floor. Applied ONLY when the
	// node is ALSO host-saturated (host_cpu high) — a node that recently hit
	// zero clean with high host pressure is genuinely saturated; a low-CPU node
	// that hit zero just has a pool that is too small (not a reason to exclude).
	if m.sched.FloorFrac > 0 && n.PoolTarget > 0 && n.Metrics != nil &&
		n.Metrics.HostCPU >= tailFloorHostCPU {
		floor := uint32(math.Ceil(m.sched.FloorFrac * float64(n.PoolTarget)))
		if floor < 1 {
			floor = 1
		}
		ok := false
		for spec, c := range n.Capacity {
			if c.cleanCount() == 0 || !n.specSatisfies(spec, minVCPUs, minMemoryMB) {
				continue
			}
			if c.MinCleanWindow >= floor {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

// tailFloorHostCPU is the host-CPU saturation threshold (%) above which the
// tail floor rejects a node that recently hit zero clean.
const tailFloorHostCPU = 80.0

// allNodesSaturatedLocked reports whether EVERY connected node has zero derived
// clean VMs across all specs (the gateway as a whole cannot serve a cold mount
// of any spec right now). Caller holds m.mu. Returns true for zero nodes only
// if there are nodes but all are empty — i.e. it requires >=1 node to be
// "saturated"; with zero connected nodes that is a different failure
// (NO_COMPUTE_NODES) handled elsewhere.
func (m *Manager) allNodesSaturatedLocked() bool {
	if len(m.nodes) == 0 {
		return false
	}
	for _, n := range m.nodes {
		anyClean := false
		for _, c := range n.Capacity {
			if c.cleanCount() > 0 {
				anyClean = true
				break
			}
		}
		if !anyClean {
			continue // this node is saturated; need ALL to be saturated
		}
		return false
	}
	return true
}

// recomputeSaturationLocked updates saturationSince based on the current
// all-saturated state. Called from every path that changes derived clean counts
// (UpdateNodeCapacity, ReserveBound, ReleaseBound, AdjustBound, AddNode,
// RemoveNode) so the timer is always consistent with live capacity. Caller
// holds m.mu.
func (m *Manager) recomputeSaturationLocked() {
	if m.allNodesSaturatedLocked() {
		if m.saturationSince.IsZero() {
			m.saturationSince = time.Now()
		}
	} else {
		m.saturationSince = time.Time{}
	}
}

// IsSustainedSaturated reports whether the gateway has been fully saturated
// (all nodes zero clean) for at least minSec seconds. This is the shed trigger
// condition: only shed ownership after saturation has persisted past a
// hysteresis window, so transient spikes (a 2s load-publish blip, a brief burst)
// do not trigger ownership migration. Returns false when not saturated or when
// the saturation has not yet lasted minSec.
func (m *Manager) IsSustainedSaturated(minSec int) bool {
	if minSec <= 0 {
		return false
	}
	m.mu.Lock()
	since := m.saturationSince
	m.mu.Unlock()
	if since.IsZero() {
		return false
	}
	return time.Since(since) >= time.Duration(minSec)*time.Second
}

// maxPoolTargetLocked returns the largest pool target across connected nodes
// (0 when no node reports one). Caller holds m.mu.
func (m *Manager) maxPoolTargetLocked() int {
	max := 0
	for _, n := range m.nodes {
		if n.PoolTarget > max {
			max = n.PoolTarget
		}
	}
	return max
}

// cleanFrac normalizes the node's fitting clean count to [0,1] by the given
// denominator, so the WClean score term is commensurate with the other [0,1]
// components (duty/cpu ratios) instead of an unbounded raw count that swamped
// them (a node with 30 clean VMs scored 3.0 vs a busy node's 0.54 max duty
// term — the load policy was inert). The denominator is the node's own pool
// target, falling back to the cluster max pool target for nodes that don't
// report one, and finally to the largest fitting-clean count in the current
// selection batch (bootstrap, before any node reports a target) — so relative
// clean ordering stays IN the score, not just the tie-break. The result is
// clamped at 1 so a transiently over-provisioned pool (total above target
// while shrinking) cannot overweight the term.
func (n *Node) cleanFrac(minVCPUs uint32, minMemoryMB uint64, denom uint32) float64 {
	if denom < 1 {
		denom = 1
	}
	frac := float64(n.fittingClean(minVCPUs, minMemoryMB)) / float64(denom)
	if frac > 1 {
		frac = 1
	}
	return frac
}

// maxFittingCleanLocked returns the largest fitting-clean count across
// connected nodes (0 when none). The cleanFrac bootstrap denominator when no
// node reports a pool target. Caller holds m.mu.
func (m *Manager) maxFittingCleanLocked(minVCPUs uint32, minMemoryMB uint64) uint32 {
	var max uint32
	for _, n := range m.nodes {
		if c := n.fittingClean(minVCPUs, minMemoryMB); c > max {
			max = c
		}
	}
	return max
}

// nodeScore computes the placement score for an eligible node (higher = better).
// Spread prefers idle nodes (high idle headroom); binpack flips the load + durable
// terms to prefer busy nodes. The tail-risk penalty (WRisk) applies in both modes:
// it pushes away nodes whose 60s peak duty, duty volatility, or zero-clean
// frequency is high, so binpack lands on a busy-but-stable node rather than a
// busy-but-spiky one that repeatedly tips into no-clean-VM contention. When the
// node has no metrics yet, cleanFrac is the proxy (bootstrap).
//
// clusterMaxTarget / batchMaxClean are the once-per-pass cleanFrac fallback
// denominators (see selectNodeLocked) — the node's own pool target wins, the
// cluster max covers nodes that don't report one, and the batch's max clean
// count is the bootstrap scale when nothing reports a target.
//
// Note: the recent-VM-crash signal is NOT part of this score. It is enforced
// exclusively by Acquire's two-tier selection (crash-free nodes strictly
// preferred), which is decidable and testable — a subtractive penalty inside
// the score could not dominate the bounded cleanFrac term and would be inert
// for ordering anyway (every node in the crash-free tier is equally
// unpenalized, every node in the crashed tier equally penalized).
// Caller holds m.mu.
func (m *Manager) nodeScore(n *Node, minVCPUs uint32, minMemoryMB uint64, clusterMaxTarget int, batchMaxClean uint32) float64 {
	denom := uint32(n.PoolTarget)
	if denom == 0 {
		denom = uint32(clusterMaxTarget)
	}
	if denom == 0 {
		denom = batchMaxClean
	}
	if n.Metrics == nil {
		// No metrics yet — clean capacity proxy.
		return m.sched.WClean * n.cleanFrac(minVCPUs, minMemoryMB, denom)
	}
	score := 0.0
	if m.sched.Binpack {
		score += m.sched.WLoad * n.Metrics.DutyLong // prefer busy (binpack)
	} else {
		score += m.sched.WLoad * (1 - n.Metrics.DutyLong) // prefer idle (spread)
	}
	score += m.sched.WHost * (1 - n.Metrics.HostCPU/100.0)
	// Durable headroom: prefer nodes with low duty_daily — a momentary lull on a
	// chronically-busy node is a poor long-lived placement.
	if m.sched.Binpack {
		score += m.sched.WDaily * n.Metrics.DutyDaily
	} else {
		score += m.sched.WDaily * (1 - n.Metrics.DutyDaily)
	}
	score += m.sched.WClean * n.cleanFrac(minVCPUs, minMemoryMB, denom)
	// Tail-risk penalty (both policies).
	if m.sched.WRisk > 0 {
		risk := n.Metrics.MaxDutyWindow + n.Metrics.DutyVar + n.maxFittingZeroClean(minVCPUs, minMemoryMB)/60.0
		score -= m.sched.WRisk * risk
	}
	return score
}

// maxFittingZeroClean returns the max 60s zero-clean count over specs fitting
// the required vcpus/memory (0 if none) — the frequency with which the node's
// pool hit zero clean for a usable spec. Caller holds m.mu.
func (n *Node) maxFittingZeroClean(minVCPUs uint32, minMemoryMB uint64) float64 {
	var max uint32
	for spec, c := range n.Capacity {
		if n.specSatisfies(spec, minVCPUs, minMemoryMB) && c.ZeroCleanCount > max {
			max = c.ZeroCleanCount
		}
	}
	return float64(max)
}

// HasNode reports whether a node is currently connected.
func (m *Manager) HasNode(nodeID string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.nodes[nodeID]
	return ok
}

// NodeCount returns the number of connected sandlot nodes.
func (m *Manager) NodeCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.nodes)
}

// NodeIDs returns the connected node IDs.
func (m *Manager) NodeIDs() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	ids := make([]string, 0, len(m.nodes))
	for id := range m.nodes {
		ids = append(ids, id)
	}
	return ids
}

// Stats returns cluster-wide pool statistics (O(1), no per-VM state). The shape
// mirrors the legacy per-VM format (CLEAN/IN_USE + node_count) so consumers that
// sum the fields as a "total VM" proxy keep working; LEASED/RELEASING are not
// tracked under delegation (lease state lives in the lease manager, VM states in
// sandlot). IN_USE = bound VMs (total minus clean).
func (m *Manager) Stats() map[string]int {
	m.mu.Lock()
	defer m.mu.Unlock()
	totalClean := 0
	totalVMs := 0
	for _, n := range m.nodes {
		for _, c := range n.Capacity {
			totalClean += int(c.cleanCount())
			totalVMs += int(c.Total)
		}
	}
	return map[string]int{
		"CLEAN":      totalClean,
		"IN_USE":     totalVMs - totalClean,
		"node_count": len(m.nodes),
	}
}

// UnmountSandfsFromAll asks every connected node to unmount the sandfs
// (idempotent: the node holding it unmounts; others no-op). Used by SandFS
// deletion before the volume is removed, by cleanup after a failure, and by
// the Drainer's retry loop. Best-effort: errors are logged but not returned —
// the bool reports whether EVERY connected node acknowledged success.
//
// TODO(batch-unmount): sequential per-node RPC — delete-time path, not latency
// critical today. A batch unmount command would only matter for bulk SandFS
// deletion (see the StreamSandlotClient.UnmountRootfs TODO).
func (m *Manager) UnmountSandfsFromAll(sandfsID, volumePath, volumeEpoch string) bool {
	if m.client == nil {
		return true // no node transport: nothing connected, nothing to unmount
	}
	// Read the recorder once under the lock (SetUnmountRecorder writes it); the
	// per-node unmount RPCs then run lock-free.
	m.mu.Lock()
	recorder := m.unmountStats
	m.mu.Unlock()
	allOK := true
	for _, nodeID := range m.NodeIDs() {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		res, err := m.client.UnmountRootfs(ctx, nodeID, sandfsID, volumePath, volumeEpoch)
		cancel()
		if err != nil {
			m.logger.Warn("unmount sandfs on node failed (non-fatal)", "node", nodeID, "sandfsID", sandfsID, "error", err)
			allOK = false
		}
		if recorder != nil {
			recorder.RecordUnmount(nodeID, sandfsID, "delete", res, err == nil)
		}
	}
	return allOK
}

// CleanupOverlayForSandFS asks every connected node to unmount a host-side
// read-only overlay for the SandFS (idempotent: only the node holding it has
// the overlay mounted). Best-effort: errors are logged, the bool reports
// whether every connected node acknowledged. Stale overlays on offline nodes
// are handled by sandlot's overlay reaper and, for template swaps, by the
// mount-time expected-ref check.
func (m *Manager) CleanupOverlayForSandFS(sandfsID, volumePath string) bool {
	if m.client == nil {
		return true
	}
	allOK := true
	for _, nodeID := range m.NodeIDs() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err := m.client.CleanupOverlay(ctx, nodeID, volumePath)
		cancel()
		if err != nil {
			m.logger.Warn("cleanup_overlay failed (non-fatal; reaper will handle)",
				"node", nodeID, "sandfsID", sandfsID, "error", err)
			allOK = false
		}
	}
	return allOK
}

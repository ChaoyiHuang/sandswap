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
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"sandlot/warden"
)

// SpecResources describes the resource parameters for a VM spec.
// Used by ResizePool to create new VMs with the right vcpus/memory.
type SpecResources struct {
	VCPUs    uint32
	MemoryMB uint64
	// ExecSlots is the per-VM warden connection-pool size (sync-command
	// concurrency). 0 = 1 (serial). See config.SpecEntry.ExecSlots.
	ExecSlots int
}

// ErrInsufficientMemory signals that a VM creation was aborted because the
// host lacks free memory. Creation stops and the shortage is surfaced (log +
// VMEvent alarm); callers must NOT immediately retry — the host does not grow
// memory on a retry. ResizePool treats it as fatal for the whole scale-up
// (aborts remaining creations) to avoid driving the host into OOM.
var ErrInsufficientMemory = errors.New("insufficient host memory for VM creation")

// errInsufficientMemory is the internal alias used by the memLedger.
var errInsufficientMemory = ErrInsufficientMemory

// SetPoolSpecs sets the initial pool target and spec resources. Called once at
// startup after preCreateVMs so that subsequent ResizePool calls can diff
// correctly. The specResources map is needed by destroyAndReplaceVM to create
// replacement VMs with the correct vcpus/memory when a VM is destroyed on unmount
// (pendingDestroy or recycle).
func (h *Handler) SetPoolSpecs(specs map[string]int, specRes map[string]SpecResources) {
	h.mu.Lock()
	h.poolSpecs = specs
	h.specResources = specRes
	h.mu.Unlock()
}

// SetPoolVMIDPrefix sets an optional prefix for pool VM IDs. Used by
// multi-instance deployments (instance.id set) to prevent VM ID collisions
// across sandlot instances on the same host: each instance generates
// "<prefix>pool-<spec>-<seq>" instead of "pool-<spec>-<seq>".
func (h *Handler) SetPoolVMIDPrefix(prefix string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.poolVMIDPrefix = prefix
}

// PoolVMIDPrefix returns the current pool VM ID prefix ("" when unset).
// Used by cmd/main.go's pre-create path so startup pool VMs get the same
// instance prefix as ResizePool-created VMs (otherwise multi-instance hosts
// collide on "pool-<spec>-<seq>" in the gateway's byID index).
func (h *Handler) PoolVMIDPrefix() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.poolVMIDPrefix
}

// UpdateRecycleConfig atomically updates the recycle parameters + the min-idle
// floor fraction. Hot-reloadable.
func (h *Handler) UpdateRecycleConfig(maxUses, memPercent, memAbsMB int, minIdleFloorFrac float64) {
	// Atomic stores - no h.mu needed (avoids a data race with shouldRecycle).
	h.recycleMaxUses.Store(int64(maxUses))
	h.recycleMemPercent.Store(int64(memPercent))
	h.recycleMemAbsMB.Store(int64(memAbsMB))
	// Clamp negatives to 0 (disabled) and cap at 1.0. Store as basis points
	// (frac*10000) for atomic int64 access.
	if minIdleFloorFrac < 0 {
		minIdleFloorFrac = 0
	} else if minIdleFloorFrac > 1 {
		minIdleFloorFrac = 1
	}
	h.minIdleFloorFracBps.Store(int64(minIdleFloorFrac * 10000))
}

// UpdateReusePolicy applies the mount-count/distinct-agent/affinity policy.
// Atomic stores; safe to call on hot-reload.
func (h *Handler) UpdateReusePolicy(maxMounts, maxDistinctAgents, affinityVMs int) {
	h.recycleMaxMounts.Store(int64(maxMounts))
	h.maxDistinctAgents.Store(int64(maxDistinctAgents))
	h.affinityVMs.Store(int64(affinityVMs))
}

// UpdateVMBatchConcurrency sets the pool's batch worker counts (restart-
// required config: applied once at startup). Values below 1 are clamped to 1
// so a hand-built handler cannot deadlock a batch.
func (h *Handler) UpdateVMBatchConcurrency(create, destroy int) {
	if create < 1 {
		create = 1
	}
	if destroy < 1 {
		destroy = 1
	}
	h.vmCreateConcurrency.Store(int64(create))
	h.vmDestroyConcurrency.Store(int64(destroy))
}

// createConcurrency returns the configured batch-create worker count.
func (h *Handler) createConcurrency() int {
	n := int(h.vmCreateConcurrency.Load())
	if n < 1 {
		return 1
	}
	return n
}

// destroyConcurrency returns the configured batch-destroy worker count.
func (h *Handler) destroyConcurrency() int {
	n := int(h.vmDestroyConcurrency.Load())
	if n < 1 {
		return 1
	}
	return n
}

// runCreateBatch runs up to count VM creation calls with the configured
// concurrency. `create` returns (ok, err); isFatal classifies an error as
// node-wide (memory shortage, protocol-version mismatch). A fatal result stops
// STARTING new work — calls already in flight finish normally — and is
// returned to the caller. Non-fatal errors are logged by the create callback
// and do not stop the batch. Returns the number of successful creations.
func (h *Handler) runCreateBatch(count int, create func() (bool, error), isFatal func(error) bool) (int, error) {
	if count <= 0 {
		return 0, nil
	}
	limit := h.createConcurrency()
	if limit > count {
		limit = count
	}
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		created int
		fatal   error
		stop    atomic.Bool
	)
	sem := make(chan struct{}, limit)
	for i := 0; i < count; i++ {
		if stop.Load() {
			break
		}
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			if stop.Load() {
				return
			}
			ok, err := create()
			mu.Lock()
			if ok {
				created++
			}
			if err != nil && isFatal(err) && fatal == nil {
				fatal = err
			}
			mu.Unlock()
			if err != nil && isFatal(err) {
				stop.Store(true)
			}
		}()
	}
	wg.Wait()
	return created, fatal
}

// isFatalCreateError reports the node-wide create failures that make further
// attempts pointless: host memory exhaustion and a warden protocol mismatch
// (every VM from this initramfs fails identically until redeploy).
func isFatalCreateError(err error) bool {
	return errors.Is(err, errInsufficientMemory) || IsProtocolVersionMismatch(err)
}

// effectivePoolTarget returns the target count for a spec, expanded by the
// min-idle floor: target + max(1, floor(frac*target)) when the floor
// fraction is enabled. The extra VMs are pre-created CLEAN headroom so a burst
// doesn't immediately tip the spec into zero-clean. Returns the raw target when
// the floor is 0 (disabled). A floor of max(1, ...) guarantees at least one
// spare even for small targets.
//
// The floor is part of the standing pool definition: ResizePool scales BOTH
// directions against this expanded target, and validatePoolMemory (cmd) uses
// the exported wrapper so the budget check and the created pool share one
// source of math — a raw-target check would let the real pool exceed the
// host budget by the floor extras.
func (h *Handler) effectivePoolTarget(target int) int {
	bps := h.minIdleFloorFracBps.Load()
	if bps <= 0 || target <= 0 {
		return target
	}
	floor := int(float64(target) * float64(bps) / 10000.0)
	if floor < 1 {
		floor = 1
	}
	return target + floor
}

// EffectivePoolTarget is the exported form of effectivePoolTarget, used by
// cmd's pool-memory validation so the budget covers what the pool will
// actually create and keep (target + floor).
func (h *Handler) EffectivePoolTarget(target int) int {
	return h.effectivePoolTarget(target)
}

// ResizePool adjusts the pool to match the new target spec. It scales up by
// creating new VMs and scales down by destroying idle (not IN_USE) VMs.
// The specs map provides the resource parameters for each spec name.
// This is the primary hot-reload entry point for pool changes.
//
// Scale-up: for each spec where current count < target, create shortfall VMs.
// Scale-down: for each spec where current count > target, destroy excess idle
// VMs (those not currently serving an agent) and mark remaining busy VMs as
// pendingDestroy so they will be destroyed on their next unmount.
func (h *Handler) ResizePool(newSpecs map[string]int, specResources map[string]SpecResources) {
	h.mu.Lock()
	oldSpecs := h.poolSpecs
	if oldSpecs == nil {
		oldSpecs = make(map[string]int)
	}
	h.poolSpecs = newSpecs
	h.specResources = specResources

	// Clear all pendingDestroy flags — the new target will be recalculated
	// from scratch below. Stale flags from a previous resize could cause
	// incorrect behavior (e.g., a cancelled scale-down still destroying VMs).
	// Exception: the flag a scheduleDirtyVMDestroy set to exclude a dirty VM
	// (uncertain guest mount state) from reuse stays — clearing it would let
	// resolveVMForMount hand that VM to a new mount inside its async destroy
	// window.
	for _, state := range h.vms {
		if state.dirtyDestroyScheduled.Load() {
			continue
		}
		state.pendingDestroy.Store(false)
	}
	h.mu.Unlock()

	h.logger.Printf("ResizePool: target=%v (was %v)", newSpecs, oldSpecs)

	// --- Scale up: create VMs for specs that need more ---
	// createMu serializes creation across ResizePool/ReconcilePool/destroyAndReplaceVM.
	h.createMu.Lock()
	aborted := false
	for specName, target := range newSpecs {
		if aborted {
			break
		}
		current := h.countVMsBySpec(specName)
		effTarget := h.effectivePoolTarget(target)
		if current >= effTarget {
			continue
		}
		res, ok := specResources[specName]
		if !ok {
			h.logger.Printf("ResizePool: unknown spec %q, skipping scale-up", specName)
			continue
		}
		shortfall := effTarget - current
		h.logger.Printf("ResizePool: scaling up %s: %d → %d (target=%d + floor, creating %d, concurrency=%d)",
			specName, current, effTarget, target, shortfall, h.createConcurrency())
		created, fatal := h.runCreateBatch(shortfall, func() (bool, error) {
			err := h.createPoolVM(specName, res)
			if err != nil && !isFatalCreateError(err) {
				h.logger.Printf("ResizePool: createPoolVM %s failed: %v (will retry via self-heal)", specName, err)
			}
			return err == nil, err
		}, isFatalCreateError)
		if fatal != nil {
			if errors.Is(fatal, errInsufficientMemory) {
				h.logger.Printf("ResizePool: aborting scale-up: insufficient host memory (created %d/%d for %s)", created, shortfall, specName)
			} else {
				// Node-level incompatibility (initramfs warden vs sandlot
				// build): every subsequent create fails identically. Abort
				// the whole scale-up — only redeploying the pair fixes it.
				h.logger.Printf("ResizePool: aborting scale-up: %v", fatal)
			}
			aborted = true
			break
		}
	}
	h.createMu.Unlock()

	// --- Scale down: destroy excess idle VMs for specs that need fewer ---
	// The floor is part of the standing pool definition: scale-down aligns to
	// the SAME floor-expanded target as scale-up (effTarget), so the 60s
	// reconcile doesn't immediately re-create what we just destroyed (the old
	// raw-target math churned one destroy+boot cycle per scale-down).
	for specName, target := range newSpecs {
		current := h.countVMsBySpec(specName)
		effTarget := h.effectivePoolTarget(target)
		if current <= effTarget {
			continue
		}
		excess := current - effTarget
		h.logger.Printf("ResizePool: scaling down %s: %d → %d (target=%d + floor, removing %d idle)", specName, current, effTarget, target, excess)
		h.destroyIdleVMs(specName, excess)
	}

	// Specs present in old but absent in new: destroy all idle VMs of that spec.
	for specName := range oldSpecs {
		if _, ok := newSpecs[specName]; ok {
			continue // still present, handled above
		}
		current := h.countVMsBySpec(specName)
		if current > 0 {
			h.logger.Printf("ResizePool: spec %s removed from pool, destroying %d idle VMs", specName, current)
			h.destroyIdleVMs(specName, current)
		}
	}
	// Notify caller (e.g., to trigger an immediate heartbeat so the gateway
	// reconciles the new pool state without waiting for the 30s ticker).
	if h.OnPoolChanged != nil {
		h.OnPoolChanged()
	}
}

// ReconcilePool fills gaps left by transient creation failures: for each spec
// in poolSpecs, if countVMsBySpec < target, create the missing VMs. Called by
// the 60s self-heal ticker (runServeLoop) so the pool recovers without waiting
// for an operator to trigger a config reload. Idempotent and safe to call
// concurrently with ResizePool: the createPoolVM calls are serialized by
// createMu, preventing double-creation.
func (h *Handler) ReconcilePool() {
	h.mu.RLock()
	specs := h.poolSpecs
	res := h.specResources
	h.mu.RUnlock()
	if len(specs) == 0 {
		return
	}

	h.createMu.Lock()
	defer h.createMu.Unlock()
	for specName, target := range specs {
		current := h.countVMsBySpec(specName)
		effTarget := h.effectivePoolTarget(target)
		if current >= effTarget {
			continue
		}
		r, ok := res[specName]
		if !ok {
			continue
		}
		shortfall := effTarget - current
		h.logger.Printf("ReconcilePool: filling gap %s: %d -> %d (target=%d + floor, creating %d, concurrency=%d)",
			specName, current, effTarget, target, shortfall, h.createConcurrency())
		_, fatal := h.runCreateBatch(shortfall, func() (bool, error) {
			err := h.createPoolVM(specName, r)
			if err != nil && !isFatalCreateError(err) {
				// Other errors: log and continue; next tick will retry.
				h.logger.Printf("ReconcilePool: createPoolVM %s failed: %v", specName, err)
			}
			return err == nil, err
		}, isFatalCreateError)
		if fatal != nil {
			if errors.Is(fatal, errInsufficientMemory) {
				h.logger.Printf("ReconcilePool: aborting %s fill due to insufficient memory", specName)
			} else {
				// Same verdict as ResizePool: no VM this node boots can
				// pass the warden handshake; stop creating (each retry is
				// a boot+destroy cycle for nothing until ops redeploys).
				h.logger.Printf("ReconcilePool: aborting %s fill: %v", specName, fatal)
			}
			break
		}
	}
}

// countVMsBySpec returns the number of VMs currently in the handler with the
// given spec ID.
func (h *Handler) countVMsBySpec(specID string) int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	count := 0
	for _, state := range h.vms {
		if state.SpecID == specID {
			count++
		}
	}
	return count
}

// NextPoolVMID allocates the next unique pool VM ID for a spec from the shared
// nextPoolSeq counter. Re-adopted survivors advance the counter past their own
// seqs at registration (adoptReadoptedVM), so IDs from this counter can never
// collide with a live survivor. Deriving seqs from the survivor COUNT instead
// (the old startup pre-create scheme) collides whenever the survivor seq set
// has gaps — destroyed-by-recycle or scale-down VMs leave holes, and
// "<count>+i" then re-lands on a live seq; the collision unlinks the live VM's
// API socket, launches a second sandvmm on the same path, and overwrites the
// registry entry, leaking the original VM forever. Used by createPoolVM AND
// startup preCreateVMs so both share one source of uniqueness.
func (h *Handler) NextPoolVMID(specName string) string {
	h.mu.Lock()
	seq := h.nextPoolSeq
	h.nextPoolSeq++
	prefix := h.poolVMIDPrefix
	h.mu.Unlock()
	return fmt.Sprintf("%spool-%s-%d", prefix, specName, seq)
}

// createPoolVM creates a single pool VM of the given spec. This mirrors the
// logic in cmd/main.go preCreateVMs but runs inside the handler so it can be
// triggered by hot-reload without involving main.go.
//
// Returns an error if the VM could not be created. The caller (ResizePool)
// treats a memory-shortage error as fatal for the whole resize: it aborts
// remaining scale-up so the host isn't driven into OOM. Other errors (e.g.
// TAP busy) are logged but do not abort - the 60s self-heal ticker will retry.
//
// createMu MUST be held by the caller (ResizePool/ReconcilePool/destroyAndReplaceVM)
// to prevent concurrent double-creation.
func (h *Handler) createPoolVM(specName string, res SpecResources) error {
	vmID := h.NextPoolVMID(specName)

	h.mu.Lock()
	cfg := h.vmmCfg // copy current default config
	sandboxRoot := h.SandboxRoot
	h.mu.Unlock()

	cfg.ID = vmID
	cfg.SandboxDir = filepath.Join(sandboxRoot, vmID)
	cfg.VCPUs = res.VCPUs
	cfg.MemoryMB = res.MemoryMB

	// CreateVerifiedVM owns the whole lifecycle: memory admission before
	// anything is allocated, CID + network + launch, a SYNCHRONOUS warden
	// check, and complete teardown of any VM that does not come up (it never
	// enters h.vms unless verified). errInsufficientMemory propagates so
	// ResizePool can abort the rest of the scale-up instead of grinding the
	// host against its memory ceiling.
	if _, err := h.CreateVerifiedVM(context.Background(), cfg, specName); err != nil {
		h.logger.Printf("ResizePool: create VM %s failed: %v", vmID, err)
		return err
	}
	h.logger.Printf("ResizePool: VM %s created and verified (spec=%s)", vmID, specName)
	return nil
}

// destroyIdleVMs removes up to count idle (not IN_USE) VMs of the given spec.
// Any shortfall (busy VMs that can't be destroyed immediately) is marked
// pendingDestroy so they are destroyed on their next unmount.
//
// Selection priority (user requirement: prefer sync-handled VMs, then async):
//  1. idle VMs          -> destroy immediately
//  2. sync-handled busy -> mark pendingDestroy (activeBgExecs==0; no background
//     work to lose; sync execs finish in seconds so the
//     deferred destroy fires fast and the pool shrinks
//     quickly)
//  3. async-handled busy -> mark pendingDestroy last (activeBgExecs>0; preserves
//     long-running background work; accepts slower shrink)
//
// Concurrency: mountMu.TryLock (NOT Lock) so an unmount in progress does not
// block ResizePool; the in-flight counter (inFlight, atomic) reports warden
// RPCs in flight without any lock probing. This avoids holding h.mu.RLock
// while blocked (which would stall all h.mu writers).
func (h *Handler) destroyIdleVMs(specName string, count int) {
	h.mu.RLock()
	var idle, syncBusy, asyncBusy []string
	for id, state := range h.vms {
		if state.SpecID != specName {
			continue
		}
		// destroying is guarded by state.mu everywhere else; read it the same
		// way here (a bare read races destroyVMByID/handleVMDied's write).
		state.mu.Lock()
		destroying := state.destroying
		state.mu.Unlock()
		if destroying {
			continue // already being torn down (avoids double-accounting)
		}
		// TryLock avoids blocking on an unmount RPC (which waits out the
		// warden's in-flight execs and can take as long as the longest one).
		if state.mountMu.TryLock() {
			// The idle verdict must match readopt's busy predicate: no
			// recorded mount, no pending generation that may still land, no
			// in-flight warden RPC, AND no sandfs binding. Checking Volumes
			// alone destroyed VMs in the window between set-fs/pendingMount
			// (or a fresh binding) and acquireWarden, recording a successful
			// attach against a destroyed state. h.mu is held (RLock), so the
			// binding read is exact for the duration of the scan.
			busy := len(state.Volumes) > 0 || state.pendingMount != nil || h.vmBoundToLocked(id)
			bg := state.activeBgExecs.Load()
			inFlight := state.inFlight.Load()
			state.mountMu.Unlock()
			switch {
			case !busy && inFlight == 0:
				idle = append(idle, id)
			case bg > 0:
				asyncBusy = append(asyncBusy, id) // has background work - defer
			default:
				syncBusy = append(syncBusy, id) // sync-origin, no bg work - prefer
			}
		} else {
			// mountMu held => unmount/switch in progress. Classified as
			// sync-handled (preferred).
			syncBusy = append(syncBusy, id)
		}
	}
	h.mu.RUnlock()

	destroyed := 0
	// 1. Destroy idle VMs first, in parallel batches (default 10). The
	// per-VM teardown path is independent (registry entry, sandvmm process,
	// network, CID, memory reservation), so a pool scale-down no longer pays
	// the sum of every teardown.
	if n := len(idle); n > 0 {
		if n > count {
			n = count
		}
		limit := h.destroyConcurrency()
		if limit > n {
			limit = n
		}
		var wg sync.WaitGroup
		sem := make(chan struct{}, limit)
		for _, id := range idle[:n] {
			sem <- struct{}{}
			wg.Add(1)
			go func(vmID string) {
				defer wg.Done()
				defer func() { <-sem }()
				h.logger.Printf("ResizePool: destroying idle VM %s (spec=%s)", vmID, specName)
				h.destroyVMByID(vmID)
			}(id)
		}
		wg.Wait()
		destroyed = n
	}

	// 2. Mark sync-handled busy VMs (preferred - frees up fast, no bg work lost).
	marked := h.markBusyForDestroy(syncBusy, count-destroyed, specName, "sync")
	destroyed += marked

	// 3. Mark async-handled busy VMs last (preserve background work).
	markedAsync := h.markBusyForDestroy(asyncBusy, count-destroyed, specName, "async")
	destroyed += markedAsync

	if destroyed < count {
		h.logger.Printf("ResizePool: destroyed/marked %d/%d %s VMs (insufficient busy VMs)",
			destroyed, count, specName)
	} else {
		h.logger.Printf("ResizePool: destroyed/marked %d/%d %s VMs", destroyed, count, specName)
	}
}

// markBusyForDestroy marks (or immediately destroys) up to quota busy VMs from
// ids. Returns the number handled.
//
// At mark time each VM is re-checked under mountMu.TryLock + the in-flight
// counter to close the TOCTOU window: a VM collected as "busy" may have
// been unmounted (Volumes
// cleared) between collection and marking. If it became idle, destroy it
// immediately instead of setting a stale pendingDestroy flag that would never
// fire (the VM won't receive another unmount). This prevents the idle-VM-leak.
func (h *Handler) markBusyForDestroy(ids []string, quota int, specName, kind string) int {
	handled := 0
	for _, id := range ids {
		if handled >= quota {
			break
		}
		h.mu.RLock()
		state, ok := h.vms[id]
		h.mu.RUnlock()
		if !ok {
			continue // destroyed between collection and marking
		}
		state.mu.Lock()
		isDestroying := state.destroying
		state.mu.Unlock()
		if isDestroying {
			continue
		}
		// Re-check liveness under TryLock. The predicate is the SAME one
		// selection and readopt use: no recorded mount, no pending generation,
		// no in-flight warden RPC, and no sandfs binding. If the VM became
		// idle (or was never actually attached) in the window, destroy it now
		// rather than set a never-firing flag. The binding read runs after
		// mountMu is released: the bind helpers take h.mu, and blocking on
		// h.mu while holding mountMu would invert the lock order selection
		// depends on.
		if state.mountMu.TryLock() {
			idleNow := len(state.Volumes) == 0 && state.pendingMount == nil && state.inFlight.Load() == 0
			state.mountMu.Unlock()
			if idleNow {
				h.mu.RLock()
				bound := h.vmBoundToLocked(id)
				h.mu.RUnlock()
				if !bound {
					h.logger.Printf("ResizePool: VM %s became idle; destroying immediately (TOCTOU close)", id)
					h.destroyVMByID(id)
					handled++
					continue
				}
			}
		}
		// Still busy (or mountMu held by an unmount/switch) -> set pendingDestroy.
		// Fires on the next unmount (sync: seconds; async: when bg work ends).
		state.pendingDestroy.Store(true)
		h.logger.Printf("ResizePool: marking %s busy VM %s as pending-destroy (bg=%d, will destroy on unmount)",
			kind, id, state.activeBgExecs.Load())
		handled++
	}
	return handled
}

// destroyVMByID destroys a single VM by ID. Used by ResizePool for scale-down
// and the dirty-destroy path. It mirrors the core logic of handleVMDied's
// teardown but does not send a stream response.
func (h *Handler) destroyVMByID(vmID string) {
	ctx := context.Background()

	h.mu.Lock()
	state, ok := h.vms[vmID]
	if ok {
		delete(h.vms, vmID)
		state.mu.Lock()
		state.destroying = true
		state.mu.Unlock()
	}
	h.mu.Unlock()
	if ok {
		h.clearBindingsForVM(vmID) // release any sandfs bound to the destroyed VM
		h.unregisterBinding(state) // attachment is going away: erase its identity slot
		// Drop the heartbeat snapshot too: the probe loop only deletes entries
		// for VMs it observed FAILING, so a VM destroyed between sweeps would
		// leave a ghost entry forever (slow leak + the heartbeat reporting a
		// dead VM's memory stats to the gateway).
		h.memStatsMu.Lock()
		delete(h.memStats, vmID)
		h.memStatsMu.Unlock()
	}

	if !ok {
		return
	}

	// Best-effort unmount on a fresh short-timeout connection so a reused CID
	// never inherits a stale mount. Deliberately NOT a pooled slot: the pool's
	// slots may all be held by in-flight execs, and this is a one-shot
	// teardown dial that must not queue behind them.
	if key, kerr := warden.DecodeSessionKey(state.Cfg.WardenSessionKey); kerr == nil {
		if agt, err := warden.DialWithTimeout(state.VM.GuestCID, 2*time.Second, key); err == nil {
			_, _ = agt.UnmountRootfsForced()
			agt.Close()
		}
	}
	// Tear down the warden connection pool: idle slots are closed and further
	// dials refused; holders of in-flight slots discard them on release. Must
	// run on EVERY destroy path (scale-down, recycle, dirty-VM replace), or
	// pooled vsock connections to a dead VM leak for the sandlot's lifetime.
	state.wardenPoolFor().reset()

	// Clear virtio-fs allowed_dirs
	_ = setFsAllowedDirs(ctx, state.VM.Client, nil, "")

	// Delegate privileged kill + cleanup to VMLifecycleManager. The target is
	// built from the state captured BEFORE the map delete — DestroyVM must NOT
	// re-look-up h.vms (it would miss and skip the kill, leaking the process).
	target := &DestroyTarget{
		VMID:       vmID,
		VM:         state.VM,
		APISocket:  state.VM.APISocket,
		PID:        state.VM.PID(),
		Readopted:  state.VM.Readopted(),
		SandboxDir: state.Cfg.SandboxDir,
		WaitDone:   state.waitDone,
	}
	if err := h.vm.DestroyVM(ctx, target); err != nil {
		// Unconfirmed death (D-state) or a failed destroy RPC: do NOT release
		// the CID — a replacement VM on a live vsock CID fails at device
		// activation. The memory reservation stays held too (admission stays
		// conservative; both self-heal at restart). Quarantine the VM and
		// refuse NEW VM creation until a retry confirms death: the orphan may
		// still export its old volume, and a replacement on this node could
		// double-mount the same sandfs.
		h.metrics.RecordStranded(state.Cfg.MemoryMB)
		h.logger.Printf("ResizePool: vm.DestroyVM for %s; CID + memory-reservation release SKIPPED: %v", vmID, err)
		h.noteQuarantined(vmID, target, state.VM.GuestCID, state.Cfg.MemoryMB)
		return
	}
	// (the fresh-VM waitDone wait + network release + state/dir removal moved
	// into DestroyVM / killVMM — single-sourced for both destroy paths)

	// Return the CID to the free-list so it can be reused by a future VM.
	h.releaseCID(state.VM.GuestCID)
	// Return the VM's memory reservation to the ledger (symmetry with the
	// admit in CreateVerifiedVM / the force-reserve at re-adopt).
	h.memLedger.release(state.Cfg.MemoryMB)

	h.logger.Printf("ResizePool: VM %s destroyed", vmID)
}

// destroyAndReplaceVM destroys a VM and, if the pool target still needs VMs of
// that spec, creates a replacement. Used by the deferred-destroy path
// (pendingDestroy / shouldRecycle) in handleUnmountRootfs: after a successful
// unmount, the VM is idle and can be safely destroyed. If the pool target
// hasn't changed (recycle) or was only partially reduced (scale-down that
// later reversed), a replacement VM is created to maintain the target count.
func (h *Handler) destroyAndReplaceVM(vmID, specID string) {
	h.destroyVMByID(vmID)

	// Check if the pool target still needs VMs of this spec.
	if specID == "" {
		// No spec — on-demand VM, no replacement needed.
		if h.OnPoolChanged != nil {
			h.OnPoolChanged()
		}
		return
	}
	h.mu.RLock()
	target, inPool := h.poolSpecs[specID]
	res, hasRes := h.specResources[specID]
	h.mu.RUnlock()
	if inPool && hasRes {
		// The count check runs UNDER createMu: a concurrent destroyAndReplaceVM
		// (or ResizePool/ReconcilePool) reading the count outside the lock could
		// both see the same shortfall before either createPoolVM registers its
		// VM, over-provisioning to target+1.
		h.createMu.Lock()
		current := h.countVMsBySpec(specID)
		// Use the floor-expanded target: a destroyed pool VM is always
		// replaced (floor included) so the spare headroom is maintained.
		effTarget := h.effectivePoolTarget(target)
		if current < effTarget {
			h.logger.Printf("destroyAndReplaceVM: replacing %s VM (current=%d, effTarget=%d)",
				specID, current, effTarget)
			h.createPoolVM(specID, res)
		}
		h.createMu.Unlock()
	}
	// Trigger immediate heartbeat so gateway reconciles the changed pool.
	if h.OnPoolChanged != nil {
		h.OnPoolChanged()
	}
}

// AdvancePoolSeq advances nextPoolSeq past all existing pool-* VM IDs. Called
// after ReadoptVMs and preCreateVMs so that subsequent createPoolVM calls
// generate VM IDs that never collide with existing VMs. Without this, a VM
// created by preCreateVMs (e.g. pool-medium-0) could be overwritten by a
// ResizePool call that also generates pool-medium-0 — the colliding TAP name
// causes sandvmm's TUNSETIFF to fail with EBUSY.
func (h *Handler) AdvancePoolSeq() {
	h.mu.Lock()
	defer h.mu.Unlock()
	prefix := h.poolVMIDPrefix
	for id := range h.vms {
		if seq, ok := parsePoolSeq(id, prefix); ok && seq >= h.nextPoolSeq {
			h.nextPoolSeq = seq + 1
		}
	}
}

// parsePoolSeq extracts the numeric sequence from a pool VM ID like
// "pool-medium-5" → 5 (or "<prefix>pool-medium-5" → 5 with a prefix).
// Returns (0, false) for non-pool IDs or unparseable seq. Uses LastIndex to
// handle spec names containing hyphens (e.g. "pool-high-mem-3" → 3).
func parsePoolSeq(vmID, prefix string) (int, bool) {
	if !strings.HasPrefix(vmID, prefix+"pool-") {
		return 0, false
	}
	lastDash := strings.LastIndex(vmID, "-")
	if lastDash < 0 {
		return 0, false
	}
	seq, err := strconv.Atoi(vmID[lastDash+1:])
	if err != nil {
		return 0, false
	}
	return seq, true
}

// shouldRecycle reports whether the VM should be destroyed+recreated instead
// of reused on its next unmount. Checks useCount and guest memory stats against
// the recycle config thresholds. Reads recycle config + VM mem atomically
// (no h.mu needed - avoids data races with UpdateRecycleConfig/VMMemStats).
//
// Memory threshold combination is min() over the enabled signals (AND): the
// guest must drop below EVERY active threshold before recycling. Each signal
// acts as a cap on the other, which keeps both small and large microVMs sane:
//
//	small VM (128MB), pct=10 abs=100MB: min(12.8MB, 100MB) = 12.8MB  → pct decides
//	large VM (128GB), pct=10 abs=100MB: min(12.8GB, 100MB) = 100MB   → abs decides
//
// The old max() (OR) combination was pathological at both ends: on a 128MB VM
// abs=100MB (>78% of MemTotal) put it in permanent recycle state, and on a
// 128GB VM pct=10 recycled while ~12.8GB was still available.
func (h *Handler) shouldRecycle(vm *VMState) bool {
	// maxUses semantics: > 0 recycles at this use count, 0 disables the
	// use-count trigger, -1 is the "unlimited" sentinel (same runtime effect
	// as 0). Config validation (RecycleConfig.Validate) rejects every other
	// negative, so this guard never sees one.
	maxUses := h.recycleMaxUses.Load()
	if maxUses > 0 && vm.useCount.Load() >= uint64(maxUses) {
		return true
	}
	maxMounts := h.recycleMaxMounts.Load()
	if maxMounts > 0 && vm.mountCount.Load() >= uint64(maxMounts) {
		return true
	}
	pct := h.recycleMemPercent.Load()
	absMB := h.recycleMemAbsMB.Load()
	if pct == 0 && absMB == 0 {
		return false
	}
	total := vm.memTotal.Load()
	avail := vm.memAvail.Load()
	// memAvail==0 means we never got a heartbeat sample — don't recycle on
	// missing data.
	if avail == 0 {
		return false
	}
	var threshold uint64
	haveThreshold := false
	if pct > 0 && total > 0 {
		threshold = total * uint64(pct) / 100
		haveThreshold = true
	}
	if absMB > 0 {
		abs := uint64(absMB) * 1024 * 1024
		if !haveThreshold || abs < threshold {
			threshold = abs
			haveThreshold = true
		}
	}
	if !haveThreshold {
		return false
	}
	// Sanity cap: never recycle a VM that still has more than half of its RAM
	// available, regardless of config. Guards against pathological settings
	// (e.g. abs >= MemTotal, or pct >= 50) that would keep the VM in permanent
	// recycle state.
	if total > 0 && threshold > total/2 {
		threshold = total / 2
	}
	return avail < threshold
}

// readMemAvailableMB returns the host's MemAvailable in MiB (0 on error).
// MemAvailable is the realistic free memory (accounts for reclaimable cache),
// unlike MemFree. Used as the memLedger's live-pressure gate.
func readMemAvailableMB() (uint64, error) {
	return readMeminfoFieldMB("MemAvailable:")
}

// readHostMemTotalMB returns the host's MemTotal in MiB (0 on error). Sizes the
// memLedger's budget; 0 disables the ledger cap (the MemAvailable gate still
// applies).
func readHostMemTotalMB() uint64 {
	mb, err := readMeminfoFieldMB("MemTotal:")
	if err != nil {
		return 0
	}
	return mb
}

// readMeminfoFieldMB reads one "<Field>: N kB" line from /proc/meminfo and
// returns N in MiB.
func readMeminfoFieldMB(field string) (uint64, error) {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, field) {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				if kb, err := strconv.ParseUint(fields[1], 10, 64); err == nil {
					return kb / 1024, nil
				}
			}
		}
	}
	return 0, fmt.Errorf("%s not found in /proc/meminfo", strings.TrimSuffix(field, ":"))
}

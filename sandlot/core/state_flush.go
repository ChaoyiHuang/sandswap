// Copyright 2026 Chaoyi Huang. All rights reserved.
//
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE file at the root of this repository.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, this software will be governed by
// the Apache License, Version 2.0.

package core

import (
	"context"
	"os"
	"path/filepath"
	"time"
)

// stateFlushInterval bounds how long a reuse-accounting change (a mount
// generation, a counted mount) can sit unflushed when nothing semantic
// happened. A crash loses at most one interval of mount_count increments —
// the same accepted semantics the old per-mount async write carried ("a
// crash may lose the last increment, never the mount itself").
const stateFlushInterval = 15 * time.Second

// stateKickCoalesce is the delay between a kick and its drain. Every kick is
// already represented in the dirty set, so a short wait folds a burst of
// mounts into one write per affected VM instead of one drain per event.
const stateKickCoalesce = 100 * time.Millisecond

// orphanDirGrace is how long an unrecognized sandbox dir may exist before the
// runtime reconcile removes it. A VM mid-creation writes its state before
// registerReadyVM enters it into h.vms; the grace must exceed that window by
// a wide margin (creation completes in seconds; the reconcile tick is 60s, so
// the grace also spans at least two passes).
const orphanDirGrace = 2 * time.Minute

// markStateDirty records that vm's reuse accounting changed and the state
// file should be rewritten on the next drain. Called from markVolumeMounted
// with the caller holding the VM's mountMu; the work here is O(1) — no
// snapshot, no goroutine. The flusher reads the LATEST counters at drain
// time, which is what makes concurrent mounts on one VM coalesce to the
// newest values instead of racing last-write-wins.
//
// semantic marks a change whose loss would weaken a cross-restart policy:
// a NEW distinct agent on this VM. It kicks the flusher so the agent set is
// persisted within the coalesce window rather than the tick interval — the
// distinct-agent cap (e.g. max_distinct_agents: 1) is only enforced across
// restarts by what state.json remembers. Pure mount-count changes do not
// kick: their loss only lets a VM serve a few extra generations before the
// next threshold check.
func (h *Handler) markStateDirty(vm *VMState, semantic bool) {
	if vm == nil || vm.VM == nil {
		return
	}
	vmID := vm.VM.ID
	h.stateDirtyMu.Lock()
	if h.stateDirty == nil {
		h.stateDirty = make(map[string]struct{})
	}
	h.stateDirty[vmID] = struct{}{}
	h.stateDirtyMu.Unlock()
	if semantic {
		// Non-blocking: a kick while one is pending means the pending drain
		// already covers this change. A nil channel (test handlers built as
		// bare structs) takes the default branch — the mark is still recorded.
		select {
		case h.stateKick <- struct{}{}:
		default:
		}
	}
}

// StartStateFlusher starts the single background writer for per-VM reuse
// accounting. One goroutine for the node, ever: mount paths only mark dirty.
// The loop exits (after a final drain) on ctx cancellation or
// StopStateFlusher, whichever comes first.
func (h *Handler) StartStateFlusher(ctx context.Context) {
	// Lazy init: bare-struct test handlers skip NewHandler. Startup-only, so
	// the unsynchronized write races nothing.
	if h.stateFlusherStop == nil {
		h.stateFlusherStop = make(chan struct{})
	}
	h.stateFlusherWG.Add(1)
	go h.stateFlusherLoop(ctx)
}

func (h *Handler) stateFlusherLoop(ctx context.Context) {
	defer h.stateFlusherWG.Done()
	ticker := time.NewTicker(stateFlushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			h.drainStateDirty()
			return
		case <-h.stateFlusherStop:
			h.drainStateDirty()
			return
		case <-h.stateKick:
			t := time.NewTimer(stateKickCoalesce)
			select {
			case <-t.C:
			case <-ctx.Done():
				t.Stop()
				h.drainStateDirty()
				return
			case <-h.stateFlusherStop:
				t.Stop()
				h.drainStateDirty()
				return
			}
			h.drainStateDirty()
		case <-ticker.C:
			h.drainStateDirty()
		}
	}
}

// StopStateFlusher stops the flusher after a final drain. Idempotent and safe
// to call when the flusher was never started.
func (h *Handler) StopStateFlusher() {
	h.stateFlusherOnce.Do(func() {
		if h.stateFlusherStop != nil {
			close(h.stateFlusherStop)
		}
	})
	h.stateFlusherWG.Wait()
}

// drainStateDirty writes the reuse accounting of every dirty VM. Snapshotting
// happens HERE, under the VM's mountMu, so the write always carries the
// newest consistent generation — event-time snapshots are what allowed two
// concurrent mounts' writes to land out of order and lose the newer counter.
func (h *Handler) drainStateDirty() {
	h.stateDirtyMu.Lock()
	dirty := h.stateDirty
	h.stateDirty = make(map[string]struct{})
	h.stateDirtyMu.Unlock()
	for vmID := range dirty {
		st := h.vmState(vmID)
		if st == nil {
			// Destroyed since marked: its sandbox dir and state file went
			// with it — nothing to write.
			continue
		}
		st.mountMu.Lock()
		mountCount := st.mountCount.Load()
		countedGen := st.mountCountedGen
		agents := make([]string, 0, len(st.distinctAgents))
		for a := range st.distinctAgents {
			agents = append(agents, a)
		}
		sandboxDir := st.Cfg.SandboxDir
		st.mountMu.Unlock()
		if sandboxDir == "" {
			continue
		}
		if err := UpdateStateRuntime(sandboxDir, h.SandboxRoot, mountCount, countedGen, agents); err != nil {
			h.logger.Printf("flush reuse accounting for %s (will retry): %v", sandboxDir, err)
			// Keep the VM dirty for the next tick — one attempt per
			// interval, so a permanently unwritable state file cannot spin.
			// Liveness is checked OUTSIDE stateDirtyMu: nesting it under the
			// map lock would create a stateDirtyMu -> h.mu edge that the mark
			// path (mountMu -> stateDirtyMu) does not have.
			if h.vmState(vmID) != nil {
				h.stateDirtyMu.Lock()
				if h.stateDirty == nil {
					h.stateDirty = make(map[string]struct{})
				}
				h.stateDirty[vmID] = struct{}{}
				h.stateDirtyMu.Unlock()
			}
		}
	}
}

// ReconcileSandboxDirs removes per-VM sandbox directories no live VM owns —
// the runtime twin of the startup scan in ReadoptVMsFromDisk. Debris sources
// it converges: a destroy whose dir removal failed (mount point, permission),
// a torn removeSandboxDir that died between quarantine rename and delete
// (leaving a .trash-* dir), and a dead VMM whose dir the startup scan's
// removeState left behind because it was not yet empty.
//
// Safety against creation: a VM mid-boot has its sandbox dir on disk before
// registerReadyVM enters it into h.vms, and its sandvmm is alive. A dir is
// therefore only removed when it has been absent from the live set for
// orphanDirGrace (spanning multiple 60s ticks), and never while its state
// names a live VM. Foreign instances are out of scope by construction: this
// lists h.SandboxRoot only, and every instance has its own root.
func (h *Handler) ReconcileSandboxDirs(ctx context.Context) {
	entries, err := os.ReadDir(h.SandboxRoot)
	if err != nil {
		if !os.IsNotExist(err) {
			h.logger.Printf("sandbox dir reconcile: read %s: %v", h.SandboxRoot, err)
		}
		return
	}

	// Live by VM id AND by each VM's configured sandbox dir base name —
	// creation names dirs after the VM id, but the running VM's Cfg is the
	// authoritative mapping.
	h.mu.RLock()
	live := make(map[string]struct{}, len(h.vms))
	for id, st := range h.vms {
		live[id] = struct{}{}
		if st != nil && st.Cfg.SandboxDir != "" {
			live[filepath.Base(st.Cfg.SandboxDir)] = struct{}{}
		}
	}
	h.mu.RUnlock()

	// One /proc scan per tick: every dir this reaper must not touch.
	heldSockets := liveSandvmmSockets(h.sandvmmIdentity())
	now := time.Now()
	onDisk := make(map[string]struct{}, len(entries))
	var toClean []string
	h.orphanDirMu.Lock()
	if h.orphanDirSeen == nil {
		// Bare-struct handlers (tests) skip NewHandler; production inits there.
		h.orphanDirSeen = make(map[string]time.Time)
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		onDisk[name] = struct{}{}
		if _, ok := live[name]; ok {
			delete(h.orphanDirSeen, name)
			continue
		}
		// Belt and suspenders: a dir whose state.json names a live VM is that
		// VM's home under a different name — never touched here.
		if st, err := loadState(filepath.Join(h.SandboxRoot, name)); err == nil {
			if _, ok := live[st.VMID]; ok {
				delete(h.orphanDirSeen, name)
				continue
			}
		}
		// Liveness gate: a live sandvmm serving this dir's socket means the
		// directory is in use by SOME instance (co-located instances may share
		// the sandbox root in benchmark/test deployments). Removing its state
		// or killing the VMM here would destroy another instance's running
		// microVM; the startup /proc sweep owns orphaned-live-VMM cleanup.
		if _, held := heldSockets[filepath.Join(h.SandboxRoot, name, "sandvmm.sock")]; held {
			delete(h.orphanDirSeen, name)
			continue
		}
		first, seen := h.orphanDirSeen[name]
		if !seen {
			h.orphanDirSeen[name] = now
			continue
		}
		if now.Sub(first) < orphanDirGrace {
			continue
		}
		delete(h.orphanDirSeen, name)
		toClean = append(toClean, name)
	}
	// Drop tracking for names that vanished through other paths (destroy,
	// startup scan) so the map cannot outgrow the tree it watches.
	for name := range h.orphanDirSeen {
		if _, ok := onDisk[name]; !ok {
			delete(h.orphanDirSeen, name)
		}
	}
	h.orphanDirMu.Unlock()

	for _, name := range toClean {
		vmDir := filepath.Join(h.SandboxRoot, name)
		h.logger.Printf("sandbox dir reconcile: removing orphan dir %s (no live VM for over %s)",
			vmDir, orphanDirGrace)
		// The state twin (the private state-root dir holding state.json) goes
		// first: removeState is a no-op when it never existed, and reaping it
		// prevents a live-looking state.json from surviving its VM.
		removeState(vmDir)
		h.cleanupOrphanDir(ctx, vmDir)
		if ctx.Err() != nil {
			return
		}
	}
}

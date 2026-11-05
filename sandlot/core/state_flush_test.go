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
	"testing"
	"time"

	"sandlot/vmm"
)

// seedFlushVM registers a VM in h.vms, creates its sandbox dir, and writes a
// baseline state.json so UpdateStateRuntime's load-modify-write has a file to
// modify. Returns the VMState.
func seedFlushVM(t *testing.T, h *Handler, vmID string) *VMState {
	t.Helper()
	st := addTestVM(h, vmID, "medium", false)
	st.Cfg.SandboxDir = filepath.Join(h.SandboxRoot, vmID)
	if err := os.MkdirAll(st.Cfg.SandboxDir, 0o700); err != nil {
		t.Fatalf("mkdir sandbox dir: %v", err)
	}
	s := stateFromConfig(vmID, st.Cfg, filepath.Join(st.Cfg.SandboxDir, "sandvmm.sock"), 4242, "medium")
	if err := writeState(s, h.SandboxRoot); err != nil {
		t.Fatalf("seed writeState: %v", err)
	}
	return st
}

// setFlushAgents installs the distinct-agent set the way markVolumeMounted
// would (under mountMu), plus the mount counters of that many generations.
func setFlushAgents(st *VMState, mountCount uint64, countedGen int64, agents ...string) {
	st.mountMu.Lock()
	defer st.mountMu.Unlock()
	st.distinctAgents = make(map[string]struct{}, len(agents))
	for _, a := range agents {
		st.distinctAgents[a] = struct{}{}
	}
	st.mountCount.Store(mountCount)
	st.mountCountedGen = countedGen
}

func dirtyLen(h *Handler) int {
	h.stateDirtyMu.Lock()
	defer h.stateDirtyMu.Unlock()
	return len(h.stateDirty)
}

// TestDrainStateDirtyWritesLatestSnapshot pins the coalescing contract: many
// marks on one VM are ONE dirty entry, and the drain writes the drain-time
// snapshot — the newest counters and the full agent set — exactly once per
// VM, leaving the dirty set empty.
func TestDrainStateDirtyWritesLatestSnapshot(t *testing.T) {
	h := newCoreTestHandler()
	h.SandboxRoot = t.TempDir()
	st := seedFlushVM(t, h, "vm-a")

	// Three mount generations, two agents — what three cold mounts from two
	// different agents would have accumulated.
	setFlushAgents(st, 3, 3, "agent-a", "agent-b")

	h.markStateDirty(st, true)
	h.markStateDirty(st, false)
	h.markStateDirty(st, false)
	if got := dirtyLen(h); got != 1 {
		t.Fatalf("dirty set = %d entries, want 1 (marks coalesce per VM)", got)
	}

	h.drainStateDirty()

	loaded, err := loadState(st.Cfg.SandboxDir)
	if err != nil {
		t.Fatalf("loadState after drain: %v", err)
	}
	if loaded.MountCount != 3 {
		t.Errorf("persisted MountCount = %d, want 3 (latest, not per-event)", loaded.MountCount)
	}
	if loaded.MountCountedGen != 3 {
		t.Errorf("persisted MountCountedGen = %d, want 3", loaded.MountCountedGen)
	}
	got := map[string]struct{}{}
	for _, a := range loaded.DistinctAgents {
		got[a] = struct{}{}
	}
	if len(got) != 2 {
		t.Errorf("persisted DistinctAgents = %v, want both agent-a and agent-b", loaded.DistinctAgents)
	}
	if _, ok := got["agent-a"]; !ok {
		t.Errorf("persisted DistinctAgents = %v, want agent-a", loaded.DistinctAgents)
	}
	if _, ok := got["agent-b"]; !ok {
		t.Errorf("persisted DistinctAgents = %v, want agent-b", loaded.DistinctAgents)
	}
	if got := dirtyLen(h); got != 0 {
		t.Errorf("dirty set after drain = %d, want 0", got)
	}

	// An empty drain is a no-op, not an error.
	h.drainStateDirty()
	if got := dirtyLen(h); got != 0 {
		t.Errorf("dirty set after empty drain = %d, want 0", got)
	}
}

// TestDrainStateDirtySkipsDeadAndRetriesFailures pins the two drain edge
// paths: a VM destroyed since its mark is skipped silently (its dir went with
// it), and a failed write re-marks the VM so the next tick retries — bounded
// to one attempt per interval, never a spin.
func TestDrainStateDirtySkipsDeadAndRetriesFailures(t *testing.T) {
	h := newCoreTestHandler()
	h.SandboxRoot = t.TempDir()

	// Destroyed since marked: never in h.vms, must not panic and must not
	// leave a sticky dirty entry.
	dead := &VMState{VM: &vmm.RunningVM{ID: "vm-gone"}}
	h.markStateDirty(dead, false)
	h.drainStateDirty()
	if got := dirtyLen(h); got != 0 {
		t.Fatalf("dead VM left %d dirty entries, want 0", got)
	}

	// Live VM whose state file is missing (state twin never written): the
	// write fails and the VM is re-marked for the next tick.
	st := addTestVM(h, "vm-nostate", "medium", false)
	st.Cfg.SandboxDir = filepath.Join(h.SandboxRoot, "vm-nostate")
	h.markStateDirty(st, false)
	h.drainStateDirty()
	if got := dirtyLen(h); got != 1 {
		t.Fatalf("failed write left %d dirty entries, want 1 (retry pending)", got)
	}
	h.stateDirtyMu.Lock()
	_, requeued := h.stateDirty["vm-nostate"]
	h.stateDirtyMu.Unlock()
	if !requeued {
		t.Fatal("failed write must re-mark vm-nostate for retry")
	}

	// Once the state file exists, the retry succeeds and clears the entry.
	s := stateFromConfig("vm-nostate", st.Cfg, filepath.Join(st.Cfg.SandboxDir, "sandvmm.sock"), 4242, "medium")
	if err := writeState(s, h.SandboxRoot); err != nil {
		t.Fatalf("seed writeState: %v", err)
	}
	setFlushAgents(st, 1, 1, "agent-a")
	h.drainStateDirty()
	if got := dirtyLen(h); got != 0 {
		t.Fatalf("successful retry left %d dirty entries, want 0", got)
	}
	loaded, err := loadState(st.Cfg.SandboxDir)
	if err != nil || loaded.MountCount != 1 {
		t.Fatalf("retry write did not land: %v %+v", err, loaded)
	}
}

// TestStateFlusherKickPersistsSemanticChange wires the whole path end to
// end: a semantic mark (a NEW agent) must reach state.json through the kick
// path well within the tick interval, and StopStateFlusher must be idempotent.
func TestStateFlusherKickPersistsSemanticChange(t *testing.T) {
	h := newCoreTestHandler()
	h.SandboxRoot = t.TempDir()
	// newTestHandler builds a bare struct: the kick channel must exist for
	// the semantic-change kick to reach the flusher (production inits it in
	// NewHandler).
	h.stateKick = make(chan struct{}, 1)
	st := seedFlushVM(t, h, "vm-a")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.StartStateFlusher(ctx)
	defer h.StopStateFlusher()

	setFlushAgents(st, 1, 1, "agent-late")
	h.markStateDirty(st, true)

	deadline := time.Now().Add(3 * time.Second)
	for {
		loaded, err := loadState(st.Cfg.SandboxDir)
		if err == nil && loaded.MountCount == 1 && len(loaded.DistinctAgents) == 1 && loaded.DistinctAgents[0] == "agent-late" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("semantic change not flushed within kick window; state=%+v err=%v", loaded, err)
		}
		time.Sleep(20 * time.Millisecond)
	}

	// Idempotent stop (also exercised by the deferred call).
	h.StopStateFlusher()
	h.StopStateFlusher()
}

// TestReconcileSandboxDirsLifecycle pins the runtime orphan reconcile: live
// VMs' dirs are never touched (by dir name OR by the VMID inside state.json),
// a fresh unknown dir is only recorded (creation grace), and a dir that
// stayed ownerless past the grace is removed — together with its state twin.
func TestReconcileSandboxDirsLifecycle(t *testing.T) {
	h := newCoreTestHandler()
	h.SandboxRoot = t.TempDir()
	// Production NewHandler inits this; the bare test handler needs it for
	// the aging injections below (ReconcileSandboxDirs also lazily inits, but
	// only once it runs — after the injections).
	h.orphanDirSeen = make(map[string]time.Time)
	ctx := context.Background()

	// 1. Live VM, dir named after it.
	seedFlushVM(t, h, "vm-live")

	// 2. Live VM whose dir carries a different name — the state.json VMID is
	// the belt-and-suspenders that must save it.
	renamed := addTestVM(h, "vm-renamed", "medium", false)
	renamed.Cfg.SandboxDir = filepath.Join(h.SandboxRoot, "weird-dir")
	if err := os.MkdirAll(renamed.Cfg.SandboxDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	s := stateFromConfig("vm-renamed", renamed.Cfg, filepath.Join(renamed.Cfg.SandboxDir, "sandvmm.sock"), 4242, "medium")
	if err := writeState(s, h.SandboxRoot); err != nil {
		t.Fatalf("writeState: %v", err)
	}

	// 3. Fresh orphan (no live VM, no state): first sight — grace applies.
	if err := os.MkdirAll(filepath.Join(h.SandboxRoot, "vm-fresh"), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	// 4. Aged orphan with a state twin: past grace — must go, both trees.
	if err := os.MkdirAll(filepath.Join(h.SandboxRoot, "vm-old"), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	oldCfg := vmm.Config{ID: "vm-old", SandboxDir: filepath.Join(h.SandboxRoot, "vm-old")}
	if err := writeState(stateFromConfig("vm-old", oldCfg, filepath.Join(oldCfg.SandboxDir, "sandvmm.sock"), 1, ""), h.SandboxRoot); err != nil {
		t.Fatalf("writeState: %v", err)
	}
	h.orphanDirMu.Lock()
	h.orphanDirSeen["vm-old"] = time.Now().Add(-3 * time.Minute)
	h.orphanDirMu.Unlock()

	// 5. Stray non-dir entry at the root: ignored.
	if err := os.WriteFile(filepath.Join(h.SandboxRoot, "stray.txt"), []byte("x"), 0o600); err != nil {
		t.Fatalf("write stray: %v", err)
	}

	h.ReconcileSandboxDirs(ctx)

	assertDir := func(name string, want bool) {
		t.Helper()
		_, err := os.Stat(filepath.Join(h.SandboxRoot, name))
		if want && err != nil {
			t.Fatalf("dir %s must survive the reconcile: %v", name, err)
		}
		if !want && err == nil {
			t.Fatalf("dir %s must be removed by the reconcile", name)
		}
	}
	assertDir("vm-live", true)
	assertDir("weird-dir", true)
	assertDir("vm-fresh", true) // inside the grace
	assertDir("vm-old", false)
	if _, err := os.Stat(filepath.Join(h.SandboxRoot, "stray.txt")); err != nil {
		t.Fatalf("stray non-dir entry must be ignored: %v", err)
	}
	// The state twin went with the sandbox dir: no live-looking state.json
	// survives its VM.
	if _, err := loadState(filepath.Join(h.SandboxRoot, "vm-old")); err != errNoState {
		t.Fatalf("aged orphan's state twin must be reaped, loadState err = %v, want errNoState", err)
	}
	// The fresh orphan is now tracked, not forgotten.
	h.orphanDirMu.Lock()
	_, tracked := h.orphanDirSeen["vm-fresh"]
	h.orphanDirMu.Unlock()
	if !tracked {
		t.Fatal("fresh orphan must be tracked for the grace window")
	}

	// Age the fresh orphan past the grace: the next pass removes it.
	h.orphanDirMu.Lock()
	h.orphanDirSeen["vm-fresh"] = time.Now().Add(-3 * time.Minute)
	h.orphanDirMu.Unlock()
	h.ReconcileSandboxDirs(ctx)
	assertDir("vm-fresh", false)
}

// TestMarkVolumeMountedMarksDirtyAndKicks pins the mark-level integration:
// every successful cold mount marks the VM dirty, and ONLY a mount that
// admitted a NEW agent kicks the flusher (a semantic change must not wait out
// the tick; a repeat mount by the same agent must not kick).
func TestMarkVolumeMountedMarksDirtyAndKicks(t *testing.T) {
	h := newCoreTestHandler()
	h.SandboxRoot = t.TempDir()
	h.stateKick = make(chan struct{}, 1)

	st := mountVolume(h, "vm-a", "sfs-1", "")
	st.ensureMountRecordsForTest("sfs-1", "/vol/x", "alias-x")
	gen := st.mountGen.Load()

	kickPending := func() bool {
		select {
		case <-h.stateKick:
			return true
		default:
			return false
		}
	}

	if got := h.markVolumeMounted(st, "sfs-1", "/vol/x", "alias-x", "", "agent-t", gen); got != mountMarked {
		t.Fatalf("first mark verdict = %v, want mountMarked", got)
	}
	if got := dirtyLen(h); got != 1 {
		t.Fatalf("dirty set after first mark = %d, want 1", got)
	}
	if !kickPending() {
		t.Fatal("a mount admitting a NEW agent must kick the flusher")
	}

	if got := h.markVolumeMounted(st, "sfs-1", "/vol/x", "alias-x", "", "agent-t", gen); got != mountMarked {
		t.Fatalf("repeat mark verdict = %v, want mountMarked", got)
	}
	if kickPending() {
		t.Fatal("a repeat mount by the SAME agent must not kick (already drained into the pending kick or none needed)")
	}

	if got := h.markVolumeMounted(st, "sfs-1", "/vol/x", "alias-x", "", "agent-u", gen); got != mountMarked {
		t.Fatalf("second-agent mark verdict = %v, want mountMarked", got)
	}
	if !kickPending() {
		t.Fatal("a mount admitting a SECOND distinct agent must kick the flusher")
	}
}

// TestDistinctAgentTrackingDisabledWithCapOff pins the many-tenant behaviour:
// with the lifetime cap off, a VM must not accumulate a distinct-agent set
// (it would grow without bound) and admitting a new agent must not kick the
// semantic state flusher (there is no cross-restart cap to persist).
func TestDistinctAgentTrackingDisabledWithCapOff(t *testing.T) {
	h := newCoreTestHandler()
	h.SandboxRoot = t.TempDir()
	h.stateKick = make(chan struct{}, 1)
	h.maxDistinctAgents.Store(-1)

	st := mountVolume(h, "vm-a", "sfs-1", "")
	st.ensureMountRecordsForTest("sfs-1", "/vol/x", "alias-x")
	gen := st.mountGen.Load()
	if got := h.markVolumeMounted(st, "sfs-1", "/vol/x", "alias-x", "", "agent-t", gen); got != mountMarked {
		t.Fatalf("mark verdict = %v, want mountMarked", got)
	}
	if len(st.distinctAgents) != 0 {
		t.Fatalf("distinctAgents = %d entries with the cap off, want 0", len(st.distinctAgents))
	}
	select {
	case <-h.stateKick:
		t.Fatal("a mount with the distinct-agent cap off must not kick the state flusher")
	default:
	}
}

// TestDistinctAgentCapRecordsRecycleMetric pins the benchmark/ops signal: a
// mount refused by the lifetime cap schedules a policy recycle and must bump
// the node's recycle counter (the same counter /stats projects), exactly once.
func TestDistinctAgentCapRecordsRecycleMetric(t *testing.T) {
	h := newCoreTestHandler()
	h.SandboxRoot = t.TempDir()
	h.maxDistinctAgents.Store(1)
	h.stateKick = make(chan struct{}, 1)

	st := mountVolume(h, "vm-a", "sfs-1", "")
	st.ensureMountRecordsForTest("sfs-1", "/vol/x", "alias-x")
	gen := st.mountGen.Load()
	setFlushAgents(st, 1, gen, "agent-a") // the VM has already served its one agent

	if got := h.markVolumeMounted(st, "sfs-1", "/vol/x", "alias-x", "", "agent-b", gen); got != mountMarkDirtyDestroy {
		t.Fatalf("mark verdict = %v, want mountMarkDirtyDestroy", got)
	}
	snap := h.metrics.Snapshot()
	if snap.RecycleTriggers != 1 {
		t.Fatalf("recycle triggers = %d, want 1", snap.RecycleTriggers)
	}
	if !st.pendingDestroy.Load() || !st.dirtyDestroyScheduled.Load() {
		t.Fatal("cap refusal did not schedule the dirty destroy")
	}
}

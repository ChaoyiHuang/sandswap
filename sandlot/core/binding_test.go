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
	"path/filepath"
	"testing"

	pb "common/proto/stream"
	"sandlot/bindreg"
	"sandlot/vmm"
)

// newBindingTestHandler opens a throwaway shm binding region and attaches it
// to a core test handler. The returned lookup closure reads the region.
func newBindingTestHandler(t *testing.T) (*Handler, *bindreg.Region, func(uint32) (bindreg.Entry, bool, error)) {
	t.Helper()
	h := newCoreTestHandler()
	cfg := bindreg.Config{Backend: bindreg.BackendShm, Path: filepath.Join(t.TempDir(), "bind")}
	r, err := bindreg.Open(cfg)
	if err != nil {
		t.Fatalf("open bindreg: %v", err)
	}
	t.Cleanup(func() { _ = r.Close() })
	h.SetBindRegion(r)
	return h, r, func(idx uint32) (bindreg.Entry, bool, error) {
		e, ok, err := r.Lookup(idx)
		return e, ok, err
	}
}

const bindTestIfindex = uint32(123)

// coldExec runs a cold sync exec on vm-a for sandfs/volume, as agent. The VM
// state is REUSED across calls (a real pooled VM is reused across agents), so
// consecutive mounts exercise the same bindEpoch counter, as in production.
func coldExec(t *testing.T, h *Handler, agent, sandfs, volume string) *pb.CommandResponse {
	t.Helper()
	agt, _ := newFakeWardenClient(t, nil)
	st := h.vmState("vm-a")
	if st == nil {
		st = addTestVM(h, "vm-a", "medium", false)
		st.tapIfindex.Store(bindTestIfindex)
	}
	h.bindSandfs(sandfs, "vm-a")
	st.seedWardenClient(agt)
	return h.handleMountRootfsAndExecute(context.Background(),
		&pb.VMCommand{CommandId: "c1", AgentId: agent},
		&pb.MountRootfsAndExecute{
			VolumeMode: "flat",
			SandfsId:   sandfs,
			VolumePath: volume,
			Command:    "echo hi",
			TimeoutMs:  1000,
		})
}

func TestBindingPublishOnColdMount(t *testing.T) {
	h, _, lookup := newBindingTestHandler(t)
	resp := coldExec(t, h, "agent-1", "sfs-1", "/vol/1")
	if !resp.Success {
		t.Fatalf("cold exec failed: %s", resp.Error)
	}
	e, ok, err := lookup(bindTestIfindex)
	if err != nil || !ok {
		t.Fatalf("lookup after cold mount: ok=%v err=%v", ok, err)
	}
	if e.State != bindreg.StateMounted || e.AgentID != "agent-1" || e.SandfsID != "sfs-1" || e.VMID != "vm-a" {
		t.Fatalf("published entry = %+v", e)
	}
}

// TestBindingSwapRevokesOldPublishesNew is the identity-exactness core: when
// the same VM is switched from agent-1 to agent-2, the attachment must never
// carry agent-1's identity once agent-2's mount begins, and after the switch
// it must read agent-2 with a NEW epoch (no generation reuse).
func TestBindingSwapRevokesOldPublishesNew(t *testing.T) {
	h, _, lookup := newBindingTestHandler(t)

	resp := coldExec(t, h, "agent-1", "sfs-1", "/vol/1")
	if !resp.Success {
		t.Fatalf("first mount failed: %s", resp.Error)
	}
	first, _, err := lookup(bindTestIfindex)
	if err != nil {
		t.Fatalf("lookup after first mount: %v", err)
	}
	resp = coldExec(t, h, "agent-2", "sfs-2", "/vol/2")
	if !resp.Success {
		t.Fatalf("second mount failed: %s", resp.Error)
	}

	e, ok, err := lookup(bindTestIfindex)
	if err != nil || !ok {
		t.Fatalf("lookup after swap: ok=%v err=%v", ok, err)
	}
	if e.AgentID != "agent-2" || e.SandfsID != "sfs-2" {
		t.Fatalf("after swap entry = %+v, want agent-2/sfs-2", e)
	}
	if e.MountEpoch <= first.MountEpoch {
		t.Fatalf("epoch after swap = %d, must exceed first mount's %d (generations never reused)", e.MountEpoch, first.MountEpoch)
	}
}

// TestBindingEpochSeedNeverRepeats guards the restart-uniqueness property: a
// vendor cache keyed on (ifindex, epoch) must never match a previous tenant's
// generation after a sandlot restart or an ifindex recycle — so every
// registration seeds the epoch counter from wall clock, not from zero.
func TestBindingEpochSeedNeverRepeats(t *testing.T) {
	h, _, lookup := newBindingTestHandler(t)

	publish := func(agent string) bindreg.Entry {
		t.Helper()
		// Each mount cycle re-registers the VM (restart/recycle) and mounts.
		st := addTestVM(h, "vm-a", "medium", false)
		st.Cfg.NetSpec = &vmm.VMNetSpec{NetConfig: map[string]any{"tap": "lo"}}
		h.initBindingSlot(st)
		st.tapIfindex.Store(bindTestIfindex) // same attachment across "restarts"
		resp := coldExec(t, h, agent, "sfs-1", "/vol/1")
		if !resp.Success {
			t.Fatalf("mount as %s failed: %s", agent, resp.Error)
		}
		e, ok, err := lookup(bindTestIfindex)
		if err != nil || !ok {
			t.Fatalf("lookup after mount as %s: ok=%v err=%v", agent, ok, err)
		}
		return e
	}

	a := publish("agent-1")
	b := publish("agent-2")
	if a.MountEpoch == 0 || b.MountEpoch == 0 {
		t.Fatalf("epochs must be non-zero: %d, %d", a.MountEpoch, b.MountEpoch)
	}
	if b.MountEpoch == a.MountEpoch {
		t.Fatalf("epoch %d repeated across registrations — a vendor cache keyed on (ifindex, epoch) could misattribute agent-1's rules to agent-2", b.MountEpoch)
	}
}

func TestBindingRevokeOnUnmount(t *testing.T) {
	h, _, lookup := newBindingTestHandler(t)
	resp := coldExec(t, h, "agent-1", "sfs-1", "/vol/1")
	if !resp.Success {
		t.Fatalf("cold exec failed: %s", resp.Error)
	}

	// Unmount via the gateway command path.
	if r := h.handleUnmountRootfs(context.Background(), &pb.VMCommand{CommandId: "c2"},
		&pb.UnmountRootfs{SandfsId: "sfs-1", VolumePath: "/vol/1"}); !r.Success {
		t.Fatalf("unmount failed: %s", r.Error)
	}
	e, ok, err := lookup(bindTestIfindex)
	if err != nil || !ok {
		t.Fatalf("lookup after unmount: ok=%v err=%v (entry must remain, state=unbound)", ok, err)
	}
	if e.State != bindreg.StateUnbound || e.AgentID != "" || e.SandfsID != "" {
		t.Fatalf("revoked entry = %+v, want unbound with identity cleared", e)
	}
}

func TestBindingAgentIDRequiredOnColdMount(t *testing.T) {
	h, _, lookup := newBindingTestHandler(t)
	resp := coldExec(t, h, "", "sfs-1", "/vol/1")
	if resp.Success {
		t.Fatalf("cold mount without agent_id must fail")
	}
	if _, ok, err := lookup(bindTestIfindex); ok || err != nil {
		t.Fatalf("failed mount must not publish: ok=%v err=%v", ok, err)
	}
}

func TestBindingDisabledIsNoOp(t *testing.T) {
	// No SetBindRegion: the whole enabler is inert — mount path unchanged.
	h := newCoreTestHandler()
	resp := coldExec(t, h, "agent-1", "sfs-1", "/vol/1")
	if !resp.Success {
		t.Fatalf("cold exec failed with enabler off: %s", resp.Error)
	}
}

func TestBindingInitSlotUnregistersStaleEntry(t *testing.T) {
	h, r, lookup := newBindingTestHandler(t)
	// Simulate a stale entry on the ifindex (previous tenant / crashed process).
	if err := r.Publish(bindTestIfindex, bindreg.Entry{State: bindreg.StateMounted,
		MountEpoch: 99, AgentID: "agent-old", SandfsID: "sfs-old", VMID: "vm-old"}); err != nil {
		t.Fatalf("seed stale entry: %v", err)
	}
	st := addTestVM(h, "vm-a", "medium", false)
	st.Cfg.NetSpec = &vmm.VMNetSpec{NetConfig: map[string]any{"tap": "lo"}} // resolve a REAL interface (loopback always exists)
	h.initBindingSlot(st)
	if st.tapIfindex.Load() == 0 {
		t.Fatal("initBindingSlot did not resolve ifindex for an existing interface")
	}
	if _, ok, err := lookup(st.tapIfindex.Load()); ok || err != nil {
		t.Fatalf("stale entry must be unregistered at registration: ok=%v err=%v", ok, err)
	}
}

// TestBindingParallelSameIdentityOneGeneration covers parallel cold execs on
// one sandfs: two execs can both pass the warm check before either marks
// Volumes, so publishBindingLocked re-enters with an UNCHANGED identity. That
// must be a continuation of the same generation — no epoch bump, no stamp
// churn — while a real switch (different identity) and a post-revoke re-mount
// each get a fresh generation.
func TestBindingParallelSameIdentityOneGeneration(t *testing.T) {
	h, _, lookup := newBindingTestHandler(t)
	st := addTestVM(h, "vm-a", "medium", false)
	st.tapIfindex.Store(bindTestIfindex)

	st.mountMu.Lock()
	h.publishBindingLocked(st, "agent-1", "sfs-1")
	h.publishBindingLocked(st, "agent-1", "sfs-1") // parallel re-entry, same identity
	st.mountMu.Unlock()

	first, ok, err := lookup(bindTestIfindex)
	if err != nil || !ok {
		t.Fatalf("lookup after first mount: ok=%v err=%v", ok, err)
	}

	// A real switch is a new generation, strictly after the first.
	st.mountMu.Lock()
	h.publishBindingLocked(st, "agent-2", "sfs-2")
	st.mountMu.Unlock()
	swapped, ok, err := lookup(bindTestIfindex)
	if err != nil || !ok {
		t.Fatalf("lookup after switch: ok=%v err=%v", ok, err)
	}
	if swapped.AgentID != "agent-2" || swapped.MountEpoch <= first.MountEpoch {
		t.Fatalf("switch = agent-2 epoch %d (must exceed %d), got %+v", swapped.MountEpoch, first.MountEpoch, swapped)
	}

	// Revoke (unmount) clears the record: re-mounting the SAME identity must
	// still publish a fresh generation.
	h.revokeBinding(st)
	st.mountMu.Lock()
	h.publishBindingLocked(st, "agent-2", "sfs-2")
	st.mountMu.Unlock()
	remount, ok, err := lookup(bindTestIfindex)
	if err != nil || !ok {
		t.Fatalf("lookup after re-mount: ok=%v err=%v", ok, err)
	}
	if remount.State != bindreg.StateMounted || remount.MountEpoch <= swapped.MountEpoch {
		t.Fatalf("re-mount after revoke must be a fresh mounted generation: %+v (prev epoch %d)", remount, swapped.MountEpoch)
	}
}

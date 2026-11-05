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
	"strings"
	"testing"
	"time"

	pb "common/proto/stream"
	"sandlot/warden"
)

// TestColdMountNotExportedCurrentGenerationDestroysVM pins the fail-closed
// branch a superseded-generation check used to shadow: an unbind ran BEFORE the
// vmForSandfs comparison, so every not-exported mount looked superseded (nil !=
// state) and the dirty destroy never fired. In the CURRENT generation the
// set-fs succeeded but the filter does not export the alias: the guest mount
// state is unproven, so the VM must never return to the pool.
func TestColdMountNotExportedCurrentGenerationDestroysVM(t *testing.T) {
	h := newCoreTestHandler()
	agt, fw := newFakeWardenClient(t, func(f *fakeWarden) { f.mountErrCode = 7 })
	st := mountVolume(h, "vm-a", "sfs-1", "")
	st.seedWardenClient(agt)
	h.testDialFn = func(uint32, time.Duration) (*warden.Client, error) {
		return dialFake(t, fw), nil
	}

	resp := h.handleMountRootfsAndExecute(context.Background(),
		&pb.VMCommand{CommandId: "c1", AgentId: "agent-t"},
		&pb.MountRootfsAndExecute{
			VolumeMode: "flat", SandfsId: "sfs-1", VolumePath: "/vol/x", Command: "true", TimeoutMs: 1000})
	if resp.Success {
		t.Fatalf("a not-exported mount must fail, got %+v", resp)
	}
	if !strings.Contains(resp.Error, "not exported") {
		t.Fatalf("want the not-exported refusal, got %q", resp.Error)
	}
	if !st.dirtyDestroyScheduled.Load() || !st.pendingDestroy.Load() {
		t.Fatal("a current-generation not-exported mount must dirty-destroy the VM (fail-closed)")
	}
	if bound := h.vmForSandfs("sfs-1"); bound != nil {
		t.Fatalf("the failed mount must release the binding, still bound to %s", bound.VM.ID)
	}
}

// TestMarkVolumeMountedStaleVerdicts pins the three discard paths: a mark whose
// generation moved, whose per-sandfs alias record no longer matches, or whose
// binding another VM won is UNRECORDED (the caller then tears the guest mount
// down explicitly) — never a silent "return false" that leaves a live mount
// tracked nowhere.
func TestMarkVolumeMountedStaleVerdicts(t *testing.T) {
	t.Run("generation moved", func(t *testing.T) {
		h := newCoreTestHandler()
		st := mountVolume(h, "vm-a", "sfs-1", "")
		st.ensureMountRecordsForTest("sfs-1", "/vol/x", "alias-x")
		gen := st.mountGen.Load()
		st.mountGen.Add(1) // unmounted/switched while the RPC was in flight
		if got := h.markVolumeMounted(st, "sfs-1", "/vol/x", "alias-x", "", "agent-t", gen); got != mountMarkUnrecorded {
			t.Fatalf("stale generation verdict = %v, want unrecorded", got)
		}
		if len(st.Volumes) != 0 {
			t.Fatal("a stale generation must not record a mount")
		}
	})

	t.Run("alias record replaced", func(t *testing.T) {
		h := newCoreTestHandler()
		st := mountVolume(h, "vm-a", "sfs-1", "")
		gen := st.mountGen.Load()
		// The binding record belongs to a different generation than this RPC.
		st.ensureMountRecordsForTest("sfs-1", "/vol/x", "other-alias")
		if got := h.markVolumeMounted(st, "sfs-1", "/vol/x", "alias-x", "", "agent-t", gen); got != mountMarkUnrecorded {
			t.Fatalf("mismatched binding verdict = %v, want unrecorded", got)
		}
	})

	t.Run("another VM owns the sandfs", func(t *testing.T) {
		h := newCoreTestHandler()
		st := mountVolume(h, "vm-a", "sfs-1", "")
		addTestVM(h, "vm-b", "medium", false)
		st.ensureMountRecordsForTest("sfs-1", "/vol/x", "alias-x")
		gen := st.mountGen.Load()
		h.bindSandfs("sfs-1", "vm-b") // the binding moved to another VM mid-RPC
		if got := h.markVolumeMounted(st, "sfs-1", "/vol/x", "alias-x", "", "agent-t", gen); got != mountMarkUnrecorded {
			t.Fatalf("lost-race verdict = %v, want unrecorded", got)
		}
	})

	t.Run("current generation records", func(t *testing.T) {
		h := newCoreTestHandler()
		st := mountVolume(h, "vm-a", "sfs-1", "")
		st.ensureMountRecordsForTest("sfs-1", "/vol/x", "alias-x")
		gen := st.mountGen.Load()
		if got := h.markVolumeMounted(st, "sfs-1", "/vol/x", "alias-x", "", "agent-t", gen); got != mountMarked {
			t.Fatalf("current-generation verdict = %v, want recorded", got)
		}
		if _, ok := st.Volumes["/vol/x"]; !ok {
			t.Fatal("the current generation's mount must be recorded")
		}
	})
}

// TestDiscardUnrecordedMountIsIdentityBound pins the teardown behind a discarded
// mark: the warden unmount names THIS request's alias (so a VM that has since
// switched tenants is not disturbed), and a mismatch leaves the live mount and
// its records untouched.
func TestDiscardUnrecordedMountIsIdentityBound(t *testing.T) {
	h := newCoreTestHandler()
	agt, fw := newFakeWardenClient(t, func(f *fakeWarden) {
		f.unmountCode = 9 // CODE_UNMOUNT_MISMATCH: the guest holds another generation
		f.unmountMounted = "newer-generation"
	})
	st := mountVolume(h, "vm-a", "sfs-1", "/vol/new")
	st.seedWardenClient(agt)
	h.testDialFn = func(uint32, time.Duration) (*warden.Client, error) {
		return dialFake(t, fw), nil
	}

	h.discardUnrecordedMount(st, "superseded-alias")

	fw.mu.Lock()
	gotIdentity := fw.lastUnmountIdentity
	fw.mu.Unlock()
	if gotIdentity != "superseded-alias" {
		t.Fatalf("discard unmount identity = %q, want the superseded generation's alias", gotIdentity)
	}
	if _, ok := st.Volumes["/vol/new"]; !ok {
		t.Fatal("a mismatched unmount must not clear the live tenant's mount record")
	}
	if h.vmForSandfs("sfs-1") == nil {
		t.Fatal("a mismatched unmount must not release the live binding")
	}
}

// TestFileOpRetryOnlyIdempotentOps pins the replay rule: an APPEND write
// (offset -1, O_APPEND at the warden) is never replayed after a transport error
// — its first attempt may have landed, and a replay duplicates the payload.
// A read is side-effect free and retries once on a fresh slot.
func TestFileOpRetryOnlyIdempotentOps(t *testing.T) {
	countFileOps := func(fw *fakeWarden) int {
		fw.mu.Lock()
		defer fw.mu.Unlock()
		n := 0
		for _, op := range fw.ops {
			if op == fakeOpFile {
				n++
			}
		}
		return n
	}

	t.Run("append write is not replayed", func(t *testing.T) {
		h := newCoreTestHandler()
		agt, fw := newFakeWardenClient(t, func(f *fakeWarden) { f.fileDropConn = true })
		st := mountVolume(h, "vm-a", "sfs-1", "/vol/a")
		st.seedWardenClient(agt)
		h.testDialFn = func(uint32, time.Duration) (*warden.Client, error) {
			return dialFake(t, fw), nil
		}

		resp := h.handleFileOp(context.Background(),
			&pb.VMCommand{CommandId: "c1", AgentId: "agent-t"},
			&pb.FileOp{VolumeMode: "flat", SandfsId: "sfs-1", VolumePath: "/vol/a", Action: "write", Path: "log", Offset: -1, Data: []byte("x")})
		if resp.Success {
			t.Fatalf("a file-op transport error must fail, got %+v", resp)
		}
		if n := countFileOps(fw); n != 1 {
			t.Fatalf("append write issued %d file ops, want exactly 1 (no replay)", n)
		}
	})

	t.Run("offset write and read are replayed", func(t *testing.T) {
		h := newCoreTestHandler()
		agt, fw := newFakeWardenClient(t, func(f *fakeWarden) { f.fileDropConn = true })
		st := mountVolume(h, "vm-a", "sfs-1", "/vol/a")
		st.seedWardenClient(agt)
		h.testDialFn = func(uint32, time.Duration) (*warden.Client, error) {
			return dialFake(t, fw), nil
		}

		resp := h.handleFileOp(context.Background(),
			&pb.VMCommand{CommandId: "c1", AgentId: "agent-t"},
			&pb.FileOp{VolumeMode: "flat", SandfsId: "sfs-1", VolumePath: "/vol/a", Action: "write", Path: "f", Offset: 0, Data: []byte("x")})
		if resp.Success {
			t.Fatalf("a file-op transport error must fail, got %+v", resp)
		}
		if n := countFileOps(fw); n != 2 {
			t.Fatalf("offset write issued %d file ops, want 2 (one retry)", n)
		}

		fw.mu.Lock()
		fw.ops = nil
		fw.mu.Unlock()
		resp = h.handleFileOp(context.Background(),
			&pb.VMCommand{CommandId: "c2", AgentId: "agent-t"},
			&pb.FileOp{VolumeMode: "flat", SandfsId: "sfs-1", VolumePath: "/vol/a", Action: "read", Path: "f"})
		if resp.Success {
			t.Fatalf("a file-op transport error must fail, got %+v", resp)
		}
		if n := countFileOps(fw); n != 2 {
			t.Fatalf("read issued %d file ops, want 2 (one retry)", n)
		}
	})
}

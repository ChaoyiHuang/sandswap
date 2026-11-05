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

import "testing"

// TestDestroyIdleVMsTreatsBoundOrPendingAsBusy pins the scale-down idle
// predicate to the same shape selection and readopt use: no recorded mount AND
// no pending generation AND no in-flight warden RPC AND no sandfs binding. The
// excluded windows were real: a sandfs is bound (or a generation is pending)
// between set-fs and the first markVolumeMounted, and with Volumes empty and
// inFlight zero that VM looked idle — destroying it mid-attach recorded a
// successful attach against a destroyed state and resurrected the binding.
func TestDestroyIdleVMsTreatsBoundOrPendingAsBusy(t *testing.T) {
	h := newTestHandler()
	mgr := &concurrentDestroyManager{}
	h.SetVMLifecycle(mgr)

	// Bound but not yet mounted (the attach-in-progress window).
	bound := addTestVM(h, "bound", "small", false)
	bound.VM.GuestCID = 101
	h.bindSandfs("sfs-bound", "bound")

	// A generation is landing (pendingMount set, Volumes still empty).
	pending := addTestVM(h, "pending", "small", false)
	pending.VM.GuestCID = 102
	pending.pendingMount = &pendingMount{sandfsID: "sfs-pending", volumePath: "/vol/p", alias: "alias-p"}

	// A warden RPC is in flight (file op on a warm mount, no Volumes record).
	inFlight := addTestVM(h, "in-flight", "small", false)
	inFlight.VM.GuestCID = 103
	inFlight.inFlight.Store(1)

	// Truly idle: nothing attached, no binding, no work.
	idle := addTestVM(h, "idle", "small", false)
	idle.VM.GuestCID = 104

	h.destroyIdleVMs("small", 4)

	if got := mgr.calls.Load(); got != 1 {
		t.Fatalf("DestroyVM calls = %d, want 1 (only the truly idle VM)", got)
	}
	if h.vmState("idle") != nil {
		t.Fatal("the truly idle VM must be destroyed")
	}
	for _, id := range []string{"bound", "pending", "in-flight"} {
		if h.vmState(id) == nil {
			t.Fatalf("VM %s was destroyed although it is attach/in-flight busy", id)
		}
	}
	if !bound.pendingDestroy.Load() || !pending.pendingDestroy.Load() || !inFlight.pendingDestroy.Load() {
		t.Fatal("busy-but-idle-looking VMs must be marked pending-destroy, not destroyed")
	}
}

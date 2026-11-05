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

// TestResolveVMForMountSkipsReadoptPending pins the re-adopt selection gate: a
// re-adopted survivor whose pre-restart mount is not yet PROVEN released (and
// whose cleanup failure now destroys it) must never receive a new mount, in
// either the warm-binding or the cold best-fit branch.
func TestResolveVMForMountSkipsReadoptPending(t *testing.T) {
	h := newTestHandler()
	addTestVM(h, "vm-1", "small", false)

	h.markReadoptPending("vm-1")
	if vm := h.resolveVMForMount("sfs-1", "small", "agent-test"); vm != nil {
		t.Fatalf("pending survivor selected on the cold path: %+v", vm)
	}

	// Once its cleanup is proven (clearReadoptPending), it is selectable and
	// the binding is recorded.
	h.clearReadoptPending("vm-1")
	vm := h.resolveVMForMount("sfs-1", "small", "agent-test")
	if vm == nil || vm.VM.ID != "vm-1" {
		t.Fatalf("clean survivor not selected: %+v", vm)
	}

	// The warm-binding branch must also refuse a VM that became pending
	// again (a later re-adopt/cleanup skew): the stale binding is dropped and
	// no pending VM is handed out.
	h.markReadoptPending("vm-1")
	if vm := h.resolveVMForMount("sfs-1", "small", "agent-test"); vm != nil {
		t.Fatalf("pending survivor selected through the warm binding: %+v", vm)
	}
	h.clearReadoptPending("vm-1")
	vm = h.resolveVMForMount("sfs-1", "small", "agent-test")
	if vm == nil || vm.VM.ID != "vm-1" {
		t.Fatalf("survivor not selectable after cleanup: %+v", vm)
	}
}

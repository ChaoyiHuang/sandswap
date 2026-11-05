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
	"fmt"
	"sync"
	"testing"
)

func TestBindingStoreBasics(t *testing.T) {
	s := newBindingStore()
	if vm, ok := s.lookup("sfs-1"); ok || vm != "" {
		t.Fatalf("lookup on empty store = %q,%v", vm, ok)
	}
	if !s.claimVM("vm-1", "sfs-1") {
		t.Fatal("claimVM on a free VM failed")
	}
	if cur, installed := s.install("sfs-1", "vm-1"); !installed || cur != "" {
		t.Fatalf("install = %q,%v, want empty,true", cur, installed)
	}
	if vm, ok := s.lookup("sfs-1"); !ok || vm != "vm-1" {
		t.Fatalf("lookup = %q,%v after install", vm, ok)
	}
	if sfs, ok := s.vmBound("vm-1"); !ok || sfs != "sfs-1" {
		t.Fatalf("vmBound = %q,%v after install", sfs, ok)
	}
	if n := s.len(); n != 1 {
		t.Fatalf("len = %d, want 1", n)
	}
	if vm, ok := s.remove("sfs-1"); !ok || vm != "vm-1" {
		t.Fatalf("remove = %q,%v", vm, ok)
	}
	if _, ok := s.vmBound("vm-1"); ok {
		t.Fatal("VM still occupied after remove")
	}
	if n := s.len(); n != 0 {
		t.Fatalf("len = %d after remove, want 0", n)
	}
}

// TestBindingStoreClaimExclusive pins the per-VM exclusivity: many sandfs race
// for one VM and exactly one wins; a loser's install must not displace the
// owner; releasing the VM lets the next claimer in.
func TestBindingStoreClaimExclusive(t *testing.T) {
	s := newBindingStore()
	const racers = 64
	var wg sync.WaitGroup
	var mu sync.Mutex
	winners := make(map[string]struct{})
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sfs := fmt.Sprintf("sfs-%d", i)
			if s.claimVM("vm-1", sfs) {
				mu.Lock()
				winners[sfs] = struct{}{}
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()
	if len(winners) != 1 {
		t.Fatalf("claimVM winners = %d, want exactly 1", len(winners))
	}
	var owner string
	for sfs := range winners {
		owner = sfs
	}
	if _, installed := s.install("sfs-loser", "vm-1"); installed {
		t.Fatalf("install displaced the owner %q (installed=%v)", owner, installed)
	}
	s.releaseVM("vm-1", owner)
	if !s.claimVM("vm-1", "sfs-next") {
		t.Fatal("claimVM after release failed")
	}
}

// TestBindingStoreInstallJoin pins the per-sandfs exclusivity: two installers
// for the same sandfs on different VMs — one installs, the other gets the
// existing binding back and must release its own VM claim.
func TestBindingStoreInstallJoin(t *testing.T) {
	s := newBindingStore()
	if !s.claimVM("vm-1", "sfs-1") || !s.claimVM("vm-2", "sfs-1") {
		t.Fatal("claims for distinct VMs must both succeed")
	}
	if cur, installed := s.install("sfs-1", "vm-1"); !installed || cur != "" {
		t.Fatalf("first install = %q,%v, want installed", cur, installed)
	}
	cur, installed := s.install("sfs-1", "vm-2")
	if installed || cur != "vm-1" {
		t.Fatalf("second install = %q,%v, want vm-1,false", cur, installed)
	}
	s.releaseVM("vm-2", "sfs-1")
	if sfs, ok := s.vmBound("vm-2"); ok {
		t.Fatalf("loser's VM still occupied by %q", sfs)
	}
	if n := s.len(); n != 1 {
		t.Fatalf("len = %d, want 1 (one binding)", n)
	}
}

func TestBindingStoreRebind(t *testing.T) {
	s := newBindingStore()
	if !s.claimVM("vm-1", "sfs-1") {
		t.Fatal("claim failed")
	}
	if _, installed := s.install("sfs-1", "vm-1"); !installed {
		t.Fatal("install failed")
	}
	// A different VM now owns the sandfs: the stale mount must be discarded.
	if s.rebindIfOwnerOrFree("sfs-1", "vm-2") {
		t.Fatal("rebind to a non-owner VM succeeded")
	}
	// The owner's completion is idempotent and does not double-count.
	if !s.rebindIfOwnerOrFree("sfs-1", "vm-1") {
		t.Fatal("owner rebind failed")
	}
	if n := s.len(); n != 1 {
		t.Fatalf("len = %d after owner rebind, want 1", n)
	}
	// Free re-establishment after a joiner failure.
	s.remove("sfs-1")
	if !s.claimVM("vm-1", "sfs-1") {
		t.Fatal("re-claim failed")
	}
	if !s.rebindIfOwnerOrFree("sfs-1", "vm-1") {
		t.Fatal("free rebind failed")
	}
	if n := s.len(); n != 1 {
		t.Fatalf("len = %d after free rebind, want 1", n)
	}
}

// TestBindingStoreRemoveVM pins the destroy path: the VM's binding is dropped
// in both directions and the counter follows; removeIfOwner refuses a
// mismatched owner.
func TestBindingStoreRemoveVM(t *testing.T) {
	s := newBindingStore()
	if !s.claimVM("vm-1", "sfs-1") {
		t.Fatal("claim failed")
	}
	if _, installed := s.install("sfs-1", "vm-1"); !installed {
		t.Fatal("install failed")
	}
	if sfs, ok := s.removeVM("vm-1"); !ok || sfs != "sfs-1" {
		t.Fatalf("removeVM = %q,%v", sfs, ok)
	}
	if _, ok := s.lookup("sfs-1"); ok {
		t.Fatal("binding survived removeVM")
	}
	if _, ok := s.vmBound("vm-1"); ok {
		t.Fatal("occupancy survived removeVM")
	}
	if n := s.len(); n != 0 {
		t.Fatalf("len = %d after removeVM, want 0", n)
	}
	// A mismatched owner is refused; the true owner is removed.
	if !s.claimVM("vm-2", "sfs-2") {
		t.Fatal("claim failed")
	}
	if _, installed := s.install("sfs-2", "vm-2"); !installed {
		t.Fatal("install failed")
	}
	if s.removeIfOwner("sfs-other", "vm-2") {
		t.Fatal("removeIfOwner removed a binding owned by another sandfs")
	}
	if !s.removeIfOwner("sfs-2", "vm-2") {
		t.Fatal("removeIfOwner refused the true owner")
	}
	if n := s.len(); n != 0 {
		t.Fatalf("len = %d after removeIfOwner, want 0", n)
	}
}

func TestBindingStoreAffinity(t *testing.T) {
	s := newBindingStore()
	s.recordAffinity("sfs-1", "a", 3)
	s.recordAffinity("sfs-1", "b", 3)
	s.recordAffinity("sfs-1", "c", 3)
	s.recordAffinity("sfs-1", "a", 3) // move to front
	got := s.affinityOf("sfs-1")
	want := []string{"a", "c", "b"}
	if len(got) != len(want) {
		t.Fatalf("affinity = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("affinity = %v, want %v", got, want)
		}
	}
	for i := 0; i < 10; i++ {
		s.recordAffinity("sfs-2", fmt.Sprintf("vm-%d", i), 3)
	}
	if n := len(s.affinityOf("sfs-2")); n != 3 {
		t.Fatalf("affinity cap = %d entries, want 3", n)
	}
	if n := len(s.affinityOf("sfs-3")); n != 0 {
		t.Fatalf("affinity leaked across sandfs: %d entries", n)
	}
	// A zero/negative limit disables the hint without panicking.
	s.recordAffinity("sfs-4", "vm", 0)
	if n := len(s.affinityOf("sfs-4")); n != 0 {
		t.Fatalf("limit=0 recorded %d entries", n)
	}
}

// TestBindingStoreConcurrentChurn hammers the store with the same operation
// mix the hot path produces (claim, install, lookup, rebind, three removal
// paths) under -race, then asserts the counter and both indexes drain to a
// consistent empty state. Any lost count or dangling reverse entry fails it.
func TestBindingStoreConcurrentChurn(t *testing.T) {
	s := newBindingStore()
	const workers = 32
	const ops = 200
	const vmSpace = 97
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < ops; i++ {
				vm := fmt.Sprintf("vm-%d", (w*ops+i)%vmSpace)
				sfs := fmt.Sprintf("sfs-%d-%d", w, i%7)
				s.lookup(sfs)
				s.affinityOf(sfs)
				s.vmBound(vm)
				if !s.claimVM(vm, sfs) {
					continue
				}
				if cur, installed := s.install(sfs, vm); !installed {
					// Another request owns this sandfs (or VM): release ours
					// exactly like the resolve loop does, then move on.
					s.releaseVM(vm, sfs)
					_ = cur
					continue
				}
				s.recordAffinity(sfs, vm, 3)
				if !s.rebindIfOwnerOrFree(sfs, vm) {
					t.Errorf("rebind of the just-installed owner failed")
				}
				switch i % 3 {
				case 0:
					s.remove(sfs)
				case 1:
					s.removeVM(vm)
				default:
					s.removeIfOwner(sfs, vm)
				}
			}
		}(w)
	}
	wg.Wait()
	// Drain whatever the three removal paths left behind.
	for w := 0; w < workers; w++ {
		for k := 0; k < 7; k++ {
			s.remove(fmt.Sprintf("sfs-%d-%d", w, k))
		}
	}
	if n := s.len(); n != 0 {
		t.Fatalf("binding count = %d after drain, want 0", n)
	}
	for vm := 0; vm < vmSpace; vm++ {
		if sfs, ok := s.vmBound(fmt.Sprintf("vm-%d", vm)); ok {
			t.Fatalf("vm-%d still occupied by %q after drain", vm, sfs)
		}
	}
	// And every sandfs key must be gone from the forward index.
	for w := 0; w < workers; w++ {
		for k := 0; k < 7; k++ {
			if vm, ok := s.lookup(fmt.Sprintf("sfs-%d-%d", w, k)); ok {
				t.Fatalf("sfs-%d-%d still bound to %q after drain", w, k, vm)
			}
		}
	}
}

// TestResolveVMForMountConcurrentInvariants exercises the handler-level claim:
// 32 sandfs race for 8 VMs — one sandfs per VM, one VM per sandfs, and the
// store counter agrees with the successful assignments.
func TestResolveVMForMountConcurrentInvariants(t *testing.T) {
	h := newTestHandler()
	const vms = 8
	for i := 0; i < vms; i++ {
		addTestVM(h, fmt.Sprintf("vm-%d", i), "small", false)
	}
	const sandfsCount = 32
	results := make([]string, sandfsCount)
	var wg sync.WaitGroup
	for i := 0; i < sandfsCount; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sfs := fmt.Sprintf("sfs-%d", i)
			if st := h.resolveVMForMount(sfs, "", fmt.Sprintf("agent-%d", i)); st != nil {
				results[i] = st.VM.ID
			}
		}(i)
	}
	wg.Wait()

	owner := make(map[string]string)
	assigned := 0
	for i, vm := range results {
		if vm == "" {
			continue
		}
		assigned++
		sfs := fmt.Sprintf("sfs-%d", i)
		if prev, ok := owner[vm]; ok {
			t.Fatalf("VM %s assigned to both %s and %s", vm, prev, sfs)
		}
		owner[vm] = sfs
		if got, ok := h.bindings.lookup(sfs); !ok || got != vm {
			t.Fatalf("binding %s = %q,%v, want %s", sfs, got, ok, vm)
		}
		if got, ok := h.bindings.vmBound(vm); !ok || got != sfs {
			t.Fatalf("occupancy %s = %q,%v, want %s", vm, got, ok, sfs)
		}
	}
	if assigned > vms {
		t.Fatalf("assigned %d sandfs onto %d VMs", assigned, vms)
	}
	if n := h.bindings.len(); int(n) != assigned {
		t.Fatalf("binding count = %d, want %d", n, assigned)
	}
	// Every assigned VM must be reusable once its sandfs unmounts.
	for i, vm := range results {
		if vm == "" {
			continue
		}
		h.unbindSandfs(fmt.Sprintf("sfs-%d", i))
		if _, ok := h.bindings.vmBound(vm); ok {
			t.Fatalf("VM %s still occupied after unbind", vm)
		}
	}
	if n := h.bindings.len(); n != 0 {
		t.Fatalf("binding count = %d after unbind, want 0", n)
	}
}

// TestResolveVMForMountSameSandfsJoin pins the same-sandfs race: concurrent
// resolves of one sandfs all converge on a single VM and a single binding.
func TestResolveVMForMountSameSandfsJoin(t *testing.T) {
	h := newTestHandler()
	for i := 0; i < 6; i++ {
		addTestVM(h, fmt.Sprintf("vm-%d", i), "small", false)
	}
	const racers = 16
	results := make([]string, racers)
	var wg sync.WaitGroup
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if st := h.resolveVMForMount("sfs-shared", "", "agent-a"); st != nil {
				results[i] = st.VM.ID
			}
		}(i)
	}
	wg.Wait()
	first := ""
	for i, vm := range results {
		if vm == "" {
			t.Fatalf("racer %d got no VM", i)
		}
		if first == "" {
			first = vm
			continue
		}
		if vm != first {
			t.Fatalf("racers split across VMs: %q vs %q", first, vm)
		}
	}
	if got, ok := h.bindings.lookup("sfs-shared"); !ok || got != first {
		t.Fatalf("binding = %q,%v, want %s", got, ok, first)
	}
	if n := h.bindings.len(); n != 1 {
		t.Fatalf("binding count = %d, want 1", n)
	}
}

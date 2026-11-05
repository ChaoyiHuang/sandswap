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
	"sync"
	"sync/atomic"
)

// bindingStore holds the sandfs<->VM delegation binding, the reverse VM index
// (VM occupancy), and the per-sandfs affinity hints behind sharded locks.
//
// Why not one global mutex: at 32+ paced lanes the cold-switch rate reaches
// ~5k mounts/s and ~5k unmounts/s, and every mount/unmount used to take the
// Handler's global write lock (resolveVMForMount, markVolumeMounted,
// unbindSandfs). Go's RWMutex blocks NEW readers once a writer is pending, so
// a single binding write stalled VM selection for every lane — the measured
// result was a bimodal switch cycle (~7.5 ms vs ~14.5 ms) and sandlot handler
// P95 of 12-21 ms with the warden op itself at ~1.6 ms. The real exclusivity
// requirements are per sandfs (one sandfs -> at most one VM) and per VM (one
// VM -> at most one sandfs); both fit sharded locks plus a per-VM claim.
//
// Locking: each sandfs shard guards one sandfsID-keyed map; each VM shard
// guards one vmID-keyed occupancy map. A method that needs both always takes
// the sandfs shard first and the VM shard second (the two shard arrays are
// distinct, so this fixed order is acyclic); single-shard methods take only
// the VM shard. No method here takes the Handler mutex.
type bindingStore struct {
	shards   [bindingShardCount]bindingShard
	vmShards [bindingShardCount]vmShard
	count    atomic.Int64 // live sandfs -> VM bindings
}

const bindingShardCount = 64

type bindingShard struct {
	mu       sync.RWMutex
	bySandfs map[string]string   // sandfsID -> vmID
	affinity map[string][]string // sandfsID -> recently used VM ids (bounded)
}

type vmShard struct {
	mu   sync.RWMutex
	byVM map[string]string // vmID -> sandfsID (occupancy)
}

func newBindingStore() *bindingStore {
	s := &bindingStore{}
	for i := range s.shards {
		s.shards[i].bySandfs = make(map[string]string)
		s.shards[i].affinity = make(map[string][]string)
	}
	for i := range s.vmShards {
		s.vmShards[i].byVM = make(map[string]string)
	}
	return s
}

// shardIndex is FNV-1a over the key. Stable across processes; no seed needed
// (the shard choice carries no security meaning).
func shardIndex(key string) int {
	h := uint64(1469598103934665603)
	for i := 0; i < len(key); i++ {
		h ^= uint64(key[i])
		h *= 1099511628211
	}
	return int(h % bindingShardCount)
}

// lookup returns the VM bound to sandfsID.
func (s *bindingStore) lookup(sandfsID string) (string, bool) {
	sh := &s.shards[shardIndex(sandfsID)]
	sh.mu.RLock()
	vmID, ok := sh.bySandfs[sandfsID]
	sh.mu.RUnlock()
	return vmID, ok
}

// vmBound returns the sandfs occupying vmID, if any.
func (s *bindingStore) vmBound(vmID string) (string, bool) {
	sh := &s.vmShards[shardIndex(vmID)]
	sh.mu.RLock()
	sandfsID, ok := sh.byVM[vmID]
	sh.mu.RUnlock()
	return sandfsID, ok
}

// claimVM reserves vmID for sandfsID. It fails when the VM is already occupied
// by a different sandfs — the atomic per-VM exclusivity that selection and the
// binding install rely on.
func (s *bindingStore) claimVM(vmID, sandfsID string) bool {
	sh := &s.vmShards[shardIndex(vmID)]
	sh.mu.Lock()
	defer sh.mu.Unlock()
	if cur, ok := sh.byVM[vmID]; ok && cur != sandfsID {
		return false
	}
	sh.byVM[vmID] = sandfsID
	return true
}

// releaseVM drops vmID's claim when it still names sandfsID.
func (s *bindingStore) releaseVM(vmID, sandfsID string) {
	sh := &s.vmShards[shardIndex(vmID)]
	sh.mu.Lock()
	if cur, ok := sh.byVM[vmID]; ok && cur == sandfsID {
		delete(sh.byVM, vmID)
	}
	sh.mu.Unlock()
}

// install binds sandfsID -> vmID. When the sandfs is already bound it returns
// the existing VM and false (the caller must release its own claim and join the
// winner). The caller is expected to have claimed vmID first via claimVM.
func (s *bindingStore) install(sandfsID, vmID string) (existing string, installed bool) {
	sh := &s.shards[shardIndex(sandfsID)]
	vsh := &s.vmShards[shardIndex(vmID)]
	sh.mu.Lock()
	vsh.mu.Lock()
	defer vsh.mu.Unlock()
	defer sh.mu.Unlock()
	if cur, ok := sh.bySandfs[sandfsID]; ok {
		return cur, false
	}
	if cur, ok := vsh.byVM[vmID]; ok && cur != sandfsID {
		return "", false
	}
	sh.bySandfs[sandfsID] = vmID
	vsh.byVM[vmID] = sandfsID
	s.count.Add(1)
	return "", true
}

// rebindIfOwnerOrFree atomically re-establishes sandfsID -> vmID after a mount
// completed, unless another VM owns the binding (in which case it returns false
// and the caller must discard its mount result). This is the markVolumeMounted
// path's "lost the binding race" guard.
func (s *bindingStore) rebindIfOwnerOrFree(sandfsID, vmID string) bool {
	sh := &s.shards[shardIndex(sandfsID)]
	vsh := &s.vmShards[shardIndex(vmID)]
	sh.mu.Lock()
	vsh.mu.Lock()
	defer vsh.mu.Unlock()
	defer sh.mu.Unlock()
	if cur, ok := sh.bySandfs[sandfsID]; ok && cur != vmID {
		return false
	}
	if cur, ok := vsh.byVM[vmID]; ok && cur != sandfsID {
		return false
	}
	if _, ok := sh.bySandfs[sandfsID]; !ok {
		s.count.Add(1)
	}
	sh.bySandfs[sandfsID] = vmID
	vsh.byVM[vmID] = sandfsID
	return true
}

// remove drops sandfsID's binding (and the VM claim it owns). The sandfs
// shard is held across the VM-shard update so a concurrent rebind cannot
// resurrect a binding that is being torn down; the lock order is always
// sandfs shard -> VM shard, matching install/rebind.
func (s *bindingStore) remove(sandfsID string) (string, bool) {
	sh := &s.shards[shardIndex(sandfsID)]
	sh.mu.Lock()
	vmID, ok := sh.bySandfs[sandfsID]
	if !ok {
		sh.mu.Unlock()
		return "", false
	}
	vsh := &s.vmShards[shardIndex(vmID)]
	vsh.mu.Lock()
	delete(sh.bySandfs, sandfsID)
	if cur, ok := vsh.byVM[vmID]; ok && cur == sandfsID {
		delete(vsh.byVM, vmID)
	}
	vsh.mu.Unlock()
	sh.mu.Unlock()
	s.count.Add(-1)
	return vmID, true
}

// removeIfOwner drops sandfsID's binding only when it still targets vmID.
func (s *bindingStore) removeIfOwner(sandfsID, vmID string) bool {
	sh := &s.shards[shardIndex(sandfsID)]
	vsh := &s.vmShards[shardIndex(vmID)]
	sh.mu.Lock()
	vsh.mu.Lock()
	cur, ok := sh.bySandfs[sandfsID]
	if !ok || cur != vmID {
		vsh.mu.Unlock()
		sh.mu.Unlock()
		return false
	}
	delete(sh.bySandfs, sandfsID)
	if c, ok := vsh.byVM[vmID]; ok && c == sandfsID {
		delete(vsh.byVM, vmID)
	}
	vsh.mu.Unlock()
	sh.mu.Unlock()
	s.count.Add(-1)
	return true
}

// removeVM drops whatever sandfs occupies vmID (VM destroy/recycle). The
// sandfs id is read first under a read lock (no lock held across the read),
// then both shards are taken in the sandfs -> VM order and the ownership is
// re-validated: a concurrent claim of the same VM by another sandfs must not
// lose its bookkeeping.
func (s *bindingStore) removeVM(vmID string) (string, bool) {
	j := shardIndex(vmID)
	s.vmShards[j].mu.RLock()
	sandfsID, ok := s.vmShards[j].byVM[vmID]
	s.vmShards[j].mu.RUnlock()
	if !ok {
		return "", false
	}
	sh := &s.shards[shardIndex(sandfsID)]
	vsh := &s.vmShards[j]
	sh.mu.Lock()
	vsh.mu.Lock()
	removed := ""
	if cur, bound := sh.bySandfs[sandfsID]; bound && cur == vmID {
		delete(sh.bySandfs, sandfsID)
		removed = sandfsID
	}
	if cur, held := vsh.byVM[vmID]; held && cur == sandfsID {
		delete(vsh.byVM, vmID)
	}
	vsh.mu.Unlock()
	sh.mu.Unlock()
	if removed != "" {
		s.count.Add(-1)
	}
	return removed, removed != ""
}

// affinityOf returns a copy of sandfsID's recent-VM list.
func (s *bindingStore) affinityOf(sandfsID string) []string {
	sh := &s.shards[shardIndex(sandfsID)]
	sh.mu.RLock()
	src := sh.affinity[sandfsID]
	out := append([]string(nil), src...)
	sh.mu.RUnlock()
	return out
}

// recordAffinity moves vmID to the front of sandfsID's recent-VM list and caps
// it at limit.
func (s *bindingStore) recordAffinity(sandfsID, vmID string, limit int) {
	if limit <= 0 {
		return
	}
	sh := &s.shards[shardIndex(sandfsID)]
	sh.mu.Lock()
	list := sh.affinity[sandfsID]
	next := make([]string, 0, len(list)+1)
	next = append(next, vmID)
	for _, v := range list {
		if v == vmID {
			continue
		}
		if len(next) >= limit {
			break
		}
		next = append(next, v)
	}
	if len(next) > limit {
		next = next[:limit]
	}
	sh.affinity[sandfsID] = next
	sh.mu.Unlock()
}

// len reports the number of live sandfs -> VM bindings.
func (s *bindingStore) len() int64 { return s.count.Load() }

// clearAll drops every binding, VM claim, and affinity hint (tests / full
// reset).
func (s *bindingStore) clearAll() {
	for i := range s.shards {
		sh := &s.shards[i]
		sh.mu.Lock()
		for k := range sh.bySandfs {
			delete(sh.bySandfs, k)
		}
		for k := range sh.affinity {
			delete(sh.affinity, k)
		}
		sh.mu.Unlock()
	}
	for i := range s.vmShards {
		sh := &s.vmShards[i]
		sh.mu.Lock()
		for k := range sh.byVM {
			delete(sh.byVM, k)
		}
		sh.mu.Unlock()
	}
	s.count.Store(0)
}

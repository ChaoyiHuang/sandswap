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
	"container/list"
	"crypto/sha256"
	"sync"
)

// volIDCacheCapacity bounds the per-node cache of verified (sandfs_id,
// volume_path) bindings. The stamp is immutable for a given path and
// sandswap keeps sandfs placement stable, so a node's working set is its
// placed volumes; 64Ki entries (~6-8 MB at roughly 80-100 B/entry including
// map/list overhead) leaves ample headroom. An evicted entry costs ONE
// cold-attach stamp read on the next mount of that volume to this node —
// never anything on the warm path. The cache is an optimization only: a miss
// re-runs the check, and the check never trusts the cache for a binding it
// has not verified in this process.
const volIDCacheCapacity = 65536

// volIDKey is a SHA-256 of (sandfs_id, volume_path). Hashing keeps entries
// small regardless of path length; 256 bits makes a deliberate collision
// (which would let a mismatched pair reuse a verified entry) infeasible.
type volIDKey [sha256.Size]byte

func volIDKeyFor(sandfsID, volumePath string, volumeEpoch ...string) volIDKey {
	h := sha256.New()
	h.Write([]byte(sandfsID))
	h.Write([]byte{0}) // domain separator: id||0||path is unambiguous
	h.Write([]byte(volumePath))
	if len(volumeEpoch) > 0 {
		h.Write([]byte{0})
		h.Write([]byte(volumeEpoch[0]))
	}
	var k volIDKey
	copy(k[:], h.Sum(nil))
	return k
}

type volIDCacheEntry struct {
	key volIDKey
}

// volIDCache is a mutex-guarded LRU of POSITIVE verification results. Only
// successful checks are inserted: a mismatch is refused at the call site and
// never cached.
type volIDCache struct {
	mu       sync.Mutex
	capacity int
	lru      *list.List
	entries  map[volIDKey]*list.Element
}

func newVolIDCache(capacity int) *volIDCache {
	if capacity <= 0 {
		capacity = volIDCacheCapacity
	}
	return &volIDCache{
		capacity: capacity,
		lru:      list.New(),
		entries:  make(map[volIDKey]*list.Element, capacity),
	}
}

// Lookup reports whether (sandfsID, volumePath) was verified earlier in this
// process and marks it most-recently-used.
func (c *volIDCache) Lookup(sandfsID, volumePath string, volumeEpoch ...string) bool {
	k := volIDKeyFor(sandfsID, volumePath, volumeEpoch...)
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.entries[k]; ok {
		c.lru.MoveToFront(el)
		return true
	}
	return false
}

// Insert records a successful verification and evicts the least-recently-used
// entry when the capacity is exceeded.
func (c *volIDCache) Insert(sandfsID, volumePath string, volumeEpoch ...string) {
	k := volIDKeyFor(sandfsID, volumePath, volumeEpoch...)
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.entries[k]; ok {
		c.lru.MoveToFront(el)
		return
	}
	el := c.lru.PushFront(&volIDCacheEntry{key: k})
	c.entries[k] = el
	for len(c.entries) > c.capacity {
		back := c.lru.Back()
		if back == nil {
			break
		}
		c.lru.Remove(back)
		delete(c.entries, back.Value.(*volIDCacheEntry).key)
	}
}

// Len reports the number of cached entries (tests / metrics).
func (c *volIDCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

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

func TestVolIDCacheHitMissAndEviction(t *testing.T) {
	c := newVolIDCache(2)
	if c.Lookup("a", "/v/a") {
		t.Fatal("empty cache reported a hit")
	}
	c.Insert("a", "/v/a")
	c.Insert("b", "/v/b")
	if !c.Lookup("a", "/v/a") || !c.Lookup("b", "/v/b") {
		t.Fatal("inserted entries must hit")
	}
	// a and b were touched in that order, so a is LRU when c arrives.
	c.Insert("c", "/v/c")
	if c.Len() != 2 {
		t.Fatalf("Len = %d, want capacity 2", c.Len())
	}
	if c.Lookup("a", "/v/a") {
		t.Fatal("the least-recently-used entry must have been evicted")
	}
	if !c.Lookup("b", "/v/b") || !c.Lookup("c", "/v/c") {
		t.Fatal("surviving entries must still hit")
	}
	// Re-inserting a cached pair must not grow the set.
	c.Insert("b", "/v/b")
	if c.Len() != 2 {
		t.Fatalf("re-insert grew the cache to %d", c.Len())
	}
}

func TestVolIDCacheKeySeparatesIDAndPath(t *testing.T) {
	c := newVolIDCache(8)
	c.Insert("a", "/v/a")
	if c.Lookup("b", "/v/a") {
		t.Fatal("the same path with a different sandfs id must not reuse a hit")
	}
	if c.Lookup("a", "/v/b") {
		t.Fatal("the same id with a different path must not reuse a hit")
	}
	if c.Lookup("a", "/v/a") != true {
		t.Fatal("the exact verified pair must hit")
	}
}

func TestVolIDCacheIsBounded(t *testing.T) {
	c := newVolIDCache(4)
	for i := 0; i < 100; i++ {
		c.Insert(fmt.Sprintf("id-%d", i), fmt.Sprintf("/v/%d", i))
	}
	if c.Len() != 4 {
		t.Fatalf("Len = %d, want bounded capacity 4", c.Len())
	}
}

func TestVolIDCacheConcurrentAccess(t *testing.T) {
	c := newVolIDCache(64)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 500; j++ {
				id := fmt.Sprintf("id-%d", (n+j)%32)
				path := fmt.Sprintf("/v/%d", (n+j)%32)
				c.Insert(id, path)
				_ = c.Lookup(id, path)
			}
		}(i)
	}
	wg.Wait()
	if c.Len() > 64 {
		t.Fatalf("Len = %d exceeds capacity", c.Len())
	}
}

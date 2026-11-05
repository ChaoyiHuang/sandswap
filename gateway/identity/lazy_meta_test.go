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

// pins: the loader range shape (fully hex-bucketed, meta excluded),
// the bounded lazy display-meta cache, the page-retry backoff, and the
// exec-plane guarantee that the lazy path never touches a client.

package identity

import (
	"strings"
	"testing"
	"time"
)

// inRange mirrors etcd's half-open [start, end) range semantics.
func inRange(k keyRange, key string) bool { return key >= k.start && key < k.end }

func rangeHits(ranges []keyRange, key string) int {
	n := 0
	for _, r := range ranges {
		if inRange(r, key) {
			n++
		}
	}
	return n
}

// TestLoadRangesCoverageAndNoMeta pins the loader shape:
//   - meta/ keys fall in ZERO ranges (display data is lazy-fetched, never
//     part of the snapshot — a regression re-adding the meta range fails);
//   - every agent-digest and sandfs-ID bucket key lands in EXACTLY ONE range
//     (the union is exact: under-coverage silently drops records, overlap
//     would decode twice);
//   - no bucket is reachable by a single unbounded serial chain: the largest
//     contiguous span must be a hex bucket (this test enforces the exact
//     partition; the chain property is a consequence of bucketing agent/ by
//     digest hex — pinned here by asserting 'a'-..'f'-prefixed keys are in
//     buckets, not one catch-all).
func TestLoadRangesCoverageAndNoMeta(t *testing.T) {
	s := &EtcdStore{prefix: "/p/"}
	ranges := s.loadRanges()

	// meta: never loaded, in either mode.
	for _, r := range ranges {
		if strings.Contains(r.start, "meta") || strings.Contains(r.end, "meta") {
			t.Fatalf("meta range reappeared: [%s, %s)", r.start, r.end)
		}
	}
	if n := rangeHits(ranges, "/p/meta/sandfs/sandfs-1aaaaaaa"); n != 0 {
		t.Fatalf("meta key hit %d range(s) — display data must not load", n)
	}

	// Coverage: hex-bucketed agent digests and sandfs IDs, every digit.
	for i := 0; i < len(hexDigits); i++ {
		h := string(hexDigits[i])
		agentKey := "/p/agent/" + h + strings.Repeat("0", 62)
		if n := rangeHits(ranges, agentKey); n != 1 {
			t.Errorf("agent key %s hit %d ranges, want exactly 1", agentKey, n)
		}
		sfKey := "/p/sandfs/sandfs-" + h + strings.Repeat("0", 7)
		if n := rangeHits(ranges, sfKey); n != 1 {
			t.Errorf("sandfs key %s hit %d ranges, want exactly 1", sfKey, n)
		}
	}
	// The agent range family must partition (no single chain): the '0' bucket
	// and the 'f' bucket must be DIFFERENT ranges (a regression collapsing
	// agent/ back to one wide range would put both hits in the same entry).
	zeroKey := "/p/agent/" + strings.Repeat("0", 64)
	fKey := "/p/agent/" + strings.Repeat("f", 64)
	var zeroRange, fRange int = -1, -1
	for i, r := range ranges {
		if inRange(r, zeroKey) {
			zeroRange = i
		}
		if inRange(r, fKey) {
			fRange = i
		}
	}
	if zeroRange < 0 || fRange < 0 || zeroRange == fRange {
		t.Fatalf("agent keyspace is not bucketed (zero=%d f=%d)", zeroRange, fRange)
	}
}

// TestMetaCacheBounded pins the display-meta cache's hard entry cap: the
// 1M-key unbounded mirror was the memory cost; the cap is the fix.
func TestMetaCacheBounded(t *testing.T) {
	s := newTestCacheStore()
	s.mu.Lock()
	for i := 0; i < metaCacheMaxEntries+64; i++ {
		s.metaCachePutLocked(strings.Repeat("x", 1)+strings.Repeat("y", i%32)+string(rune('a'+i%26))+strings.Repeat("z", i/26%4)+"-"+itoa(i), &sandfsMetaInfo{Name: "n"})
	}
	n := len(s.sandfsMeta)
	s.mu.Unlock()
	if n > metaCacheMaxEntries {
		t.Fatalf("cache exceeded cap: %d > %d", n, metaCacheMaxEntries)
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

// TestLoadPageRetryDelay pins the retry backoff: doubling from the base,
// hard-capped — and never zero (a zero delay would spin the loader against
// a saturated backend).
func TestLoadPageRetryDelay(t *testing.T) {
	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, loadPageRetryCap, loadPageRetryCap}
	for i, w := range want {
		got := loadPageRetryDelay(i + 1)
		if got != w {
			t.Errorf("attempt %d: got %v, want %v", i+1, got, w)
		}
		if got <= 0 {
			t.Errorf("attempt %d: non-positive delay", i+1)
		}
	}
}

// TestMergeMetaLazyNeverTouchesClient pins the exec-plane guarantee: the lazy
// path must be a strict no-op without a live client — hotOnly stores never
// fetch (display IO on the exec plane is forbidden), and a nil client can
// never panic a unit-constructed store.
func TestMergeMetaLazyNeverTouchesClient(t *testing.T) {
	rec := &Record{ID: "sandfs-x", Name: "hot"}

	hot := &EtcdStore{hotOnly: true}
	out := hot.mergeMetaLazy(rec)
	if out != rec || out.Name != "hot" {
		t.Fatalf("hotOnly lazy merge must be a no-op, got %+v", out)
	}

	nonhot := &EtcdStore{sandfsMeta: make(map[string]*sandfsMetaInfo)}
	out = nonhot.mergeMetaLazy(rec)
	if out != rec || out.Name != "hot" {
		t.Fatalf("nil-client lazy merge must be a no-op, got %+v", out)
	}
}

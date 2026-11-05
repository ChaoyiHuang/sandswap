// Copyright 2026 Chaoyi Huang. All rights reserved.
//
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE file at the root of this repository.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, your use of this software will be governed
// by the Apache License, Version 2.0.
//
// loadprobe — the mechanism probe (diagnostics tool; product-tree
// precedent: scalepopulator, warden-probe). It replays the identity loader's
// EXACT read shape against a populated etcd — same 18 disjoint ranges
// (agent/ + meta/ + the 16 hex buckets under sandfs/), same semaphore
// concurrency, same page size, same pinned-revision reads, same cursor
// advance — and records the per-page latency distribution the loader never
// logs. This is how the "16 workers saturate the backend" hypothesis gets
// measured instead of guessed:
//
//	P1  workers=1, pinned vs current rev   → revision-history cost
//	P2  workers=1/2/4/8/16, pinned         → the concurrency knee
//	P3  workers=16, full pass + etcd CPU   → the degradation curve
//
// It never writes, never decodes values (counts only), and stops at
// -max-pages / -budget-secs so a pathological backend cannot hang the probe.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
)

type keyRange struct{ start, end string }

// hexDigits mirrors identity.etcd.go's bucket alphabet.
const hexDigits = "0123456789abcdef"

// loadRanges mirrors EtcdStore.loadRanges (post- shape): agent/ and
// sandfs/ both hex-bucketed, meta/ deliberately absent (display data is lazy
// point-fetched behind a bounded cache, never full-loaded). Kept verbatim so
// the probe's concurrency footprint is the loader's.
func loadRanges(prefix string) []keyRange {
	var ranges []keyRange
	ab := prefix + "agent/"
	ranges = append(ranges, keyRange{ab, ab + "0"})
	for i := 0; i < len(hexDigits)-1; i++ {
		ranges = append(ranges, keyRange{ab + string(hexDigits[i]), ab + string(hexDigits[i+1])})
	}
	ranges = append(ranges, keyRange{ab + "f", prefix + "agent0"})
	bp := prefix + "sandfs/" + "sandfs-"
	ranges = append(ranges, keyRange{prefix + "sandfs/", bp + "0"})
	for i := 0; i < len(hexDigits)-1; i++ {
		ranges = append(ranges, keyRange{bp + string(hexDigits[i]), bp + string(hexDigits[i+1])})
	}
	ranges = append(ranges, keyRange{bp + "f", prefix + "sandfs0"})
	return ranges
}

type pageRec struct {
	rangeIdx int
	page     int
	ms       int64
	keys     int
	err      string
}

func main() {
	endpoints := flag.String("endpoints", "127.0.0.1:12379", "etcd endpoints")
	prefix := flag.String("prefix", "/sandswap/identity/", "identity store prefix")
	workers := flag.Int("workers", 16, "loader concurrency (semaphore size)")
	pageSize := flag.Int("page-size", 1000, "keys per page (loader default)")
	pinned := flag.Bool("pinned", true, "read at a pinned snapshot revision (loader default)")
	maxPages := flag.Int("max-pages", 0, "stop after N pages total (0 = full pass)")
	budgetSecs := flag.Int("budget-secs", 900, "global wall-clock budget")
	perPageSecs := flag.Int("per-page-secs", 120, "per-page deadline (probe safety net)")
	cpuPID := flag.Int("cpu-pid", 0, "optional PID to sample CPU% (e.g. the etcd process)")
	label := flag.String("label", "run", "label for the summary line")
	flag.Parse()

	cli, err := clientv3.New(clientv3.Config{Endpoints: []string{*endpoints}, DialTimeout: 5 * time.Second})
	if err != nil {
		fmt.Fprintf(os.Stderr, "etcd client: %v\n", err)
		os.Exit(1)
	}
	defer cli.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(*budgetSecs)*time.Second)
	defer cancel()

	// Pin the snapshot revision exactly like fullLoadOnce (one lightweight Get).
	var snapRev int64
	if *pinned {
		head, err := cli.Get(ctx, *prefix, clientv3.WithLimit(1))
		if err != nil {
			fmt.Fprintf(os.Stderr, "snapshot revision Get: %v\n", err)
			os.Exit(1)
		}
		snapRev = head.Header.Revision
	}

	// Optional CPU sampling of a target PID (etcd) via /proc/<pid>/stat deltas.
	var cpuSamples []float64
	cpuStop := make(chan struct{})
	if *cpuPID > 0 {
		go func() {
			read := func() (float64, bool) {
				b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", *cpuPID))
				if err != nil {
					return 0, false
				}
				s := string(b)
				i := strings.LastIndexByte(s, ')')
				if i < 0 {
					return 0, false
				}
				f := strings.Fields(s[i+2:])
				if len(f) < 15 {
					return 0, false
				}
				var ut, st float64
				fmt.Sscanf(f[11], "%f", &ut)
				fmt.Sscanf(f[12], "%f", &st)
				return ut + st, true
			}
			prev, ok := read()
			if !ok {
				return
			}
			t := time.NewTicker(time.Second)
			defer t.Stop()
			for {
				select {
				case <-cpuStop:
					return
				case <-t.C:
					cur, ok := read()
					if !ok {
						continue
					}
					hz := 100.0 // CLK_TCK on x86_64
					cpuSamples = append(cpuSamples, (cur-prev)/hz*100)
					prev = cur
				}
			}
		}()
	}

	type result struct {
		pages, keys int64
		recs        []pageRec
	}
	var pagesLeft int64 = int64(*maxPages)
	if *maxPages <= 0 {
		pagesLeft = 1 << 60
	}

	ranges := loadRanges(*prefix) // the post- loader shape (agent+sandfs, no meta)
	sem := make(chan struct{}, max1(*workers))
	var wg sync.WaitGroup
	res := result{}
	var mu sync.Mutex
	start := time.Now()

	for i, r := range ranges {
		wg.Add(1)
		go func(i int, r keyRange) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			cursor := r.start
			page := 0
			for {
				if ctx.Err() != nil {
					return
				}
				if atomic.AddInt64(&pagesLeft, -1) < 0 {
					return // page cap reached
				}
				opts := []clientv3.OpOption{
					clientv3.WithRange(r.end),
					clientv3.WithLimit(int64(*pageSize)),
				}
				if *pinned {
					opts = append(opts, clientv3.WithRev(snapRev))
				}
				pctx, pcancel := context.WithTimeout(ctx, time.Duration(*perPageSecs)*time.Second)
				t0 := time.Now()
				resp, err := cli.Get(pctx, cursor, opts...)
				ms := time.Since(t0).Milliseconds()
				pcancel()
				page++
				rec := pageRec{rangeIdx: i, page: page, ms: ms}
				if err != nil {
					rec.err = err.Error()
					mu.Lock()
					res.recs = append(res.recs, rec)
					mu.Unlock()
					// Probing posture: record and continue to the next page of
					// this range (the loader aborts — that difference is the
					// loader's own finding, not the probe's to replicate).
					continue
				}
				rec.keys = len(resp.Kvs)
				mu.Lock()
				res.recs = append(res.recs, rec)
				res.pages++
				res.keys += int64(len(resp.Kvs))
				mu.Unlock()
				if !resp.More {
					return
				}
				cursor = string(resp.Kvs[len(resp.Kvs)-1].Key) + "\x00"
			}
		}(i, r)
	}
	wg.Wait()
	close(cpuStop)
	wall := time.Since(start)

	// ── Report ──────────────────────────────────────────────────────
	mu.Lock()
	recs := res.recs
	mu.Unlock()
	lat := make([]int64, 0, len(recs))
	errs := 0
	for _, r := range recs {
		if r.err != "" {
			errs++
			continue
		}
		lat = append(lat, r.ms)
	}
	sort.Slice(lat, func(a, b int) bool { return lat[a] < lat[b] })
	q := func(p float64) int64 {
		if len(lat) == 0 {
			return 0
		}
		return lat[min1(len(lat)-1, int(float64(len(lat))*p))]
	}
	// Histogram buckets the loader's world cares about.
	buckets := []int64{100, 500, 2000, 10000, 60000}
	counts := make([]int, len(buckets)+1)
	for _, v := range lat {
		placed := false
		for bi, b := range buckets {
			if v < b {
				counts[bi]++
				placed = true
				break
			}
		}
		if !placed {
			counts[len(buckets)]++
		}
	}
	var cpuAvg, cpuMax float64
	for _, c := range cpuSamples {
		cpuAvg += c
		if c > cpuMax {
			cpuMax = c
		}
	}
	if len(cpuSamples) > 0 {
		cpuAvg /= float64(len(cpuSamples))
	}

	fmt.Printf("RESULT %s: workers=%d pinned=%v pages=%d keys=%d errs=%d wall=%.1fs | page-ms p50=%d p95=%d p99=%d max=%d | hist <100ms:%d <500ms:%d <2s:%d <10s:%d <60s:%d >=60s:%d",
		*label, *workers, *pinned, res.pages, res.keys, errs, wall.Seconds(),
		q(0.50), q(0.95), q(0.99), q(1.0),
		counts[0], counts[1], counts[2], counts[3], counts[4], counts[5])
	if len(cpuSamples) > 0 {
		fmt.Printf(" | etcd-cpu avg=%.0f%% max=%.0f%%", cpuAvg, cpuMax)
	}
	fmt.Println()

	// Slowest pages (up to 5) — the degradation shape.
	sort.Slice(recs, func(a, b int) bool { return recs[a].ms > recs[b].ms })
	for i, r := range recs {
		if i >= 5 {
			break
		}
		label := fmt.Sprintf("range#%d page#%d", r.rangeIdx, r.page)
		if r.err != "" {
			fmt.Printf("  SLOWEST %s: %dms ERR %s\n", label, r.ms, r.err)
		} else {
			fmt.Printf("  SLOWEST %s: %dms keys=%d\n", label, r.ms, r.keys)
		}
	}
}

func max1(n int) int {
	if n < 1 {
		return 1
	}
	return n
}
func min1(a, b int) int {
	if a < b {
		return a
	}
	return b
}

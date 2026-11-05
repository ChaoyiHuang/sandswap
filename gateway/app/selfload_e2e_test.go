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

//go:build selfload_e2e

// E2E of the gateway self-pressure signal against a REAL etcd, exercising the
// production chain with the REAL readers and the REAL publisher loop:
//
//   - the 1s sampler loop with the default /proc/self/stat + runtime readers
//     flips self-pressure on under a real CPU burn (threshold + satSec kept
//     tiny so a short burn suffices) and releases after a hot threshold raise;
//   - the real startLoadPublisher (lease grant + immediate write) publishes
//     the self_* fields into /sandswap/load/{gw}, and a follow-up publish
//     reflects recovery (pressured → false).
//
// Requires a local etcd at 127.0.0.1:2379. Run via e2e/self-pressure-gate.sh.
package app

import (
	"context"
	"encoding/json"
	"log/slog"
	"runtime"
	"testing"
	"time"

	"gateway/lease"
	"gateway/pool"

	clientv3 "go.etcd.io/etcd/client/v3"
)

func selfLoadEtcd(t *testing.T) *clientv3.Client {
	t.Helper()
	cli, err := clientv3.New(clientv3.Config{
		Endpoints:   []string{"http://127.0.0.1:2379"},
		DialTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("selfload e2e etcd client: %v", err)
	}
	t.Cleanup(func() { cli.Close() })
	return cli
}

// waitFor polls f until it returns true or the deadline passes.
func waitFor(d time.Duration, f func() bool) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if f() {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return f()
}

// TestSelfLoadE2ESamplerLoop drives the REAL sampler (default /proc + runtime
// readers, selfSampleInterval ticker) with a real CPU burn: a near-zero CPU
// threshold plus a 1s sustain window flips pressured within a few ticks; a
// hot-reload raising the threshold above any reachable CPU releases it on the
// next tick.
func TestSelfLoadE2ESamplerLoop(t *testing.T) {
	mon := lease.NewSelfPressureMonitor(0.0001, 0, 1, slog.Default())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go mon.Start(ctx)

	// Burn CPU across all Ps so the process CPU% is unambiguous.
	stop := make(chan struct{})
	var done []chan struct{}
	for i := 0; i < runtime.GOMAXPROCS(0); i++ {
		ch := make(chan struct{})
		done = append(done, ch)
		go func() {
			defer close(ch)
			for {
				select {
				case <-stop:
					return
				default:
				}
			}
		}()
	}
	// Baseline tick + one EWMA tick + sustain at the 2s cadence: well inside
	// 15s even on a loaded CI box.
	if !waitFor(15*time.Second, mon.Pressured) {
		close(stop)
		t.Fatal("real sampler did not flip pressured under a full-core burn")
	}
	close(stop)
	for _, ch := range done {
		<-ch
	}

	// Hot-reload the threshold above any reachable CPU: the next sample must
	// release (below threshold resets immediately).
	mon.Update(1e9, 0, 1)
	if !waitFor(6*time.Second, func() bool { return !mon.Pressured() }) {
		t.Fatal("real sampler did not release after hot threshold raise")
	}
}

// TestSelfLoadE2EPublisherChain runs the REAL startLoadPublisher against a
// real etcd: the immediate first write publishes the pinned self_* state under
// the TTL lease, the next ~2s tick reflects a recovery re-pin.
func TestSelfLoadE2EPublisherChain(t *testing.T) {
	cli := selfLoadEtcd(t)
	const gwID = "gw-selfload-e2e"
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		cli.Delete(ctx, "/sandswap/load/"+gwID)
		cancel()
	})

	pm := pool.NewManager(nil, slog.Default())
	mon := lease.NewSelfPressureMonitor(85, 0.9, 10, slog.Default())
	mon.SetPressureForTest(91.5, 0.42, true)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go startLoadPublisher(ctx, cli, gwID, pm, mon, slog.Default())

	readKey := func() lease.LoadValue {
		t.Helper()
		rctx, rcancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer rcancel()
		resp, err := cli.Get(rctx, "/sandswap/load/"+gwID)
		if err != nil {
			t.Fatalf("get load key: %v", err)
		}
		if len(resp.Kvs) == 0 {
			t.Fatal("load key not published")
		}
		var lv lease.LoadValue
		if err := json.Unmarshal(resp.Kvs[0].Value, &lv); err != nil {
			t.Fatalf("load key JSON: %v", err)
		}
		return lv
	}

	// First write happens immediately at publisher start.
	if !waitFor(5*time.Second, func() bool {
		return readKeyOK(cli, gwID, func(lv lease.LoadValue) bool { return lv.SelfPressured })
	}) {
		t.Fatal("publisher never wrote the pressured load key")
	}
	lv := readKey()
	if !lv.SelfPressured {
		t.Errorf("published SelfPressured = false, want true")
	}
	if lv.SelfCPUPct != 91.5 || lv.SelfMemPct != 0.42 {
		t.Errorf("published self cpu/mem = %v/%v, want 91.5/0.42", lv.SelfCPUPct, lv.SelfMemPct)
	}

	// Recovery re-pin: the next ~2s tick must publish the cleared state.
	mon.SetPressureForTest(20.0, 0.30, false)
	if !waitFor(6*time.Second, func() bool {
		return readKeyOK(cli, gwID, func(lv lease.LoadValue) bool { return !lv.SelfPressured && lv.SelfCPUPct == 20.0 })
	}) {
		lv := readKey()
		t.Fatalf("publisher did not reflect recovery: %+v", lv.SelfPressured)
	}
}

// readKeyOK is the non-fatal read used inside waitFor polling.
func readKeyOK(cli *clientv3.Client, gwID string, check func(lease.LoadValue) bool) bool {
	rctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	resp, err := cli.Get(rctx, "/sandswap/load/"+gwID)
	if err != nil || len(resp.Kvs) == 0 {
		return false
	}
	var lv lease.LoadValue
	if json.Unmarshal(resp.Kvs[0].Value, &lv) != nil {
		return false
	}
	return check(lv)
}

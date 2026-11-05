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
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"
)

// TestUpdateVMBatchConcurrency pins the defaults and the >=1 clamp. The
// handlers used by tests are struct literals (no NewHandler), so the getters
// must still return a usable worker count.
func TestUpdateVMBatchConcurrency(t *testing.T) {
	h := newTestHandler()
	if got := h.createConcurrency(); got != 1 {
		t.Errorf("zero-value create concurrency = %d, want 1", got)
	}
	if got := h.destroyConcurrency(); got != 1 {
		t.Errorf("zero-value destroy concurrency = %d, want 1", got)
	}

	h.UpdateVMBatchConcurrency(5, 10)
	if got := h.createConcurrency(); got != 5 {
		t.Errorf("create concurrency = %d, want 5", got)
	}
	if got := h.destroyConcurrency(); got != 10 {
		t.Errorf("destroy concurrency = %d, want 10", got)
	}

	h.UpdateVMBatchConcurrency(0, -3)
	if got := h.createConcurrency(); got != 1 {
		t.Errorf("create concurrency after 0 = %d, want 1", got)
	}
	if got := h.destroyConcurrency(); got != 1 {
		t.Errorf("destroy concurrency after -3 = %d, want 1", got)
	}
}

// TestRunCreateBatchBoundsConcurrency proves a batch never exceeds the
// configured worker count while actually running in parallel (a serial
// implementation would report maxConcurrent == 1).
func TestRunCreateBatchBoundsConcurrency(t *testing.T) {
	h := newTestHandler()
	h.UpdateVMBatchConcurrency(3, 10)

	const tasks = 12
	var (
		current atomic.Int64
		peak    atomic.Int64
		started atomic.Int64
	)
	created, fatal := h.runCreateBatch(tasks, func() (bool, error) {
		started.Add(1)
		n := current.Add(1)
		for {
			old := peak.Load()
			if n <= old || peak.CompareAndSwap(old, n) {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
		current.Add(-1)
		return true, nil
	}, isFatalCreateError)

	if fatal != nil {
		t.Fatalf("fatal = %v, want nil", fatal)
	}
	if created != tasks {
		t.Errorf("created = %d, want %d", created, tasks)
	}
	if started.Load() != tasks {
		t.Errorf("started = %d, want %d", started.Load(), tasks)
	}
	if got := peak.Load(); got > 3 {
		t.Errorf("peak concurrency = %d, want <= 3", got)
	} else if got < 2 {
		t.Errorf("peak concurrency = %d, want >= 2 (batch must run in parallel)", got)
	}
}

// TestRunCreateBatchStopsStartingOnFatal: a node-wide failure (memory
// exhaustion / warden protocol mismatch) stops new work while in-flight calls
// finish. Not every task may start.
func TestRunCreateBatchStopsStartingOnFatal(t *testing.T) {
	h := newTestHandler()
	h.UpdateVMBatchConcurrency(2, 10)

	const tasks = 50
	var started atomic.Int64
	created, fatal := h.runCreateBatch(tasks, func() (bool, error) {
		n := started.Add(1)
		time.Sleep(5 * time.Millisecond)
		if n == 1 {
			return false, fmt.Errorf("admission: %w", ErrInsufficientMemory)
		}
		return true, nil
	}, isFatalCreateError)

	if !errors.Is(fatal, ErrInsufficientMemory) {
		t.Fatalf("fatal = %v, want ErrInsufficientMemory", fatal)
	}
	if started.Load() >= tasks {
		t.Errorf("started = %d, want < %d (fatal must stop new work)", started.Load(), tasks)
	}
	// At most one extra call can have been admitted concurrently with the
	// fatal one (worker count 2), so the bound is tasks-independent and small.
	if started.Load() > 4 {
		t.Errorf("started = %d after the first fatal, want a small in-flight tail", started.Load())
	}
	if created < 0 || created > int(started.Load()) {
		t.Errorf("created = %d outside [0,%d]", created, started.Load())
	}
}

// TestRunCreateBatchNonFatalErrorsDoNotStop: a per-VM failure (e.g. TAP busy)
// is retried by the next self-heal tick; the rest of the batch must still run.
func TestRunCreateBatchNonFatalErrorsDoNotStop(t *testing.T) {
	h := newTestHandler()
	h.UpdateVMBatchConcurrency(2, 10)

	const tasks = 6
	var started atomic.Int64
	created, fatal := h.runCreateBatch(tasks, func() (bool, error) {
		started.Add(1)
		time.Sleep(2 * time.Millisecond)
		return false, errors.New("tap busy")
	}, isFatalCreateError)

	if fatal != nil {
		t.Fatalf("fatal = %v, want nil for a non-fatal error", fatal)
	}
	if created != 0 {
		t.Errorf("created = %d, want 0", created)
	}
	if started.Load() != tasks {
		t.Errorf("started = %d, want all %d tasks attempted", started.Load(), tasks)
	}
}

// concurrentDestroyManager records the peak number of concurrent DestroyVM
// calls. It embeds the package's noop manager for every other method.
type concurrentDestroyManager struct {
	noopVMLifecycleManager
	current atomic.Int64
	peak    atomic.Int64
	calls   atomic.Int64
	delay   time.Duration
}

func (m *concurrentDestroyManager) DestroyVM(context.Context, *DestroyTarget) error {
	m.calls.Add(1)
	n := m.current.Add(1)
	for {
		old := m.peak.Load()
		if n <= old || m.peak.CompareAndSwap(old, n) {
			break
		}
	}
	time.Sleep(m.delay)
	m.current.Add(-1)
	return nil
}

// TestDestroyIdleVMsRunsConcurrently proves pool scale-down tears down idle
// VMs in parallel batches bounded by concurrency.vm_destroy.
func TestDestroyIdleVMsRunsConcurrently(t *testing.T) {
	h := newTestHandler()
	h.UpdateVMBatchConcurrency(5, 3)
	mgr := &concurrentDestroyManager{delay: 20 * time.Millisecond}
	h.SetVMLifecycle(mgr)

	const vms = 12
	for i := 0; i < vms; i++ {
		state := addTestVM(h, fmt.Sprintf("idle-%02d", i), "small", false)
		state.VM.GuestCID = uint32(100 + i)
	}

	h.destroyIdleVMs("small", vms)

	if got := mgr.calls.Load(); got != vms {
		t.Errorf("DestroyVM calls = %d, want %d", got, vms)
	}
	if got := mgr.peak.Load(); got > 3 {
		t.Errorf("peak destroy concurrency = %d, want <= 3", got)
	} else if got < 2 {
		t.Errorf("peak destroy concurrency = %d, want >= 2 (batch must run in parallel)", got)
	}
	if h.countVMsBySpec("small") != 0 {
		t.Errorf("idle VMs remain in the registry after scale-down")
	}
}

// TestDestroyIdleVMsRespectsCount: the parallel batch must only destroy the
// requested number, leaving the rest for later passes.
func TestDestroyIdleVMsRespectsCount(t *testing.T) {
	h := newTestHandler()
	h.UpdateVMBatchConcurrency(5, 4)
	mgr := &concurrentDestroyManager{}
	h.SetVMLifecycle(mgr)

	const vms = 10
	for i := 0; i < vms; i++ {
		state := addTestVM(h, fmt.Sprintf("idle-%02d", i), "small", false)
		state.VM.GuestCID = uint32(200 + i)
	}

	h.destroyIdleVMs("small", 3)

	if got := mgr.calls.Load(); got != 3 {
		t.Errorf("DestroyVM calls = %d, want exactly 3", got)
	}
	if got := h.countVMsBySpec("small"); got != vms-3 {
		t.Errorf("remaining VMs = %d, want %d", got, vms-3)
	}
}

// Compile-time check: the fake still satisfies the lifecycle interface.
var _ VMLifecycleManager = (*concurrentDestroyManager)(nil)

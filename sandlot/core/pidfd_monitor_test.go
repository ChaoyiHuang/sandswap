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
	"log"
	"os/exec"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestPidfdMonitorFiresOnExit verifies the centralized epoll monitor detects a
// watched process's exit and invokes the onExit callback. This is the crash
// detection path for re-adopted microVMs at scale (one epoll loop, zero idle
// CPU). Skipped on kernels without pidfd.
func TestPidfdMonitorFiresOnExit(t *testing.T) {
	mon, err := newPidfdMonitor(log.New(nil, "", 0))
	if err != nil {
		t.Skipf("pidfd monitor unavailable: %v", err)
	}
	go mon.run()
	defer mon.Stop()

	cmd := exec.Command("sleep", "0.3")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pid := cmd.Process.Pid

	var (
		mu    sync.Mutex
		fired string
		wg    sync.WaitGroup
	)
	wg.Add(1)
	if err := mon.Add("vm-test", pid, func(vmID string) {
		mu.Lock()
		fired = vmID
		mu.Unlock()
		wg.Done()
	}); err != nil {
		t.Skipf("pidfd_open unavailable (kernel <5.3?): %v", err)
	}

	// The callback should fire shortly after the child exits (~0.3s).
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("onExit did not fire within 3s of process exit")
	}
	mu.Lock()
	if fired != "vm-test" {
		t.Fatalf("onExit fired with %q, want vm-test", fired)
	}
	mu.Unlock()
	cmd.Wait()
}

// TestPidfdMonitorRemoveNoFire verifies that Remove stops a watched VM's exit
// from firing onExit (the graceful-destroy path: destroy removes the VM from
// the monitor before killing it, so the monitor must not double-clean).
func TestPidfdMonitorRemoveNoFire(t *testing.T) {
	mon, err := newPidfdMonitor(log.New(nil, "", 0))
	if err != nil {
		t.Skipf("pidfd monitor unavailable: %v", err)
	}
	go mon.run()
	defer mon.Stop()

	cmd := exec.Command("sleep", "5")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cmd.Process.Kill(); cmd.Wait() }()

	fired := make(chan string, 1)
	if err := mon.Add("vm-rm", cmd.Process.Pid, func(vmID string) {
		fired <- vmID
	}); err != nil {
		t.Skipf("pidfd_open unavailable: %v", err)
	}

	mon.Remove("vm-rm")
	// Give the epoll loop a moment to process the removal, then confirm no fire.
	select {
	case id := <-fired:
		t.Fatalf("onExit fired after Remove for %s", id)
	case <-time.After(300 * time.Millisecond):
		// good — no spurious fire
	}
}

// ensure unix import is used even if both tests skip
var _ = unix.POLLIN

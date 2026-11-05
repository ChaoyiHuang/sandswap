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

package config

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestReloadWatcherBasic(t *testing.T) {
	// Create a temp config file.
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "test.yaml")

	if err := os.WriteFile(cfgPath, []byte("key: value1\n"), 0644); err != nil {
		t.Fatal(err)
	}

	var received []byte
	ready := make(chan struct{}, 1)

	rw, err := NewReloadWatcher(cfgPath, func(content []byte) {
		received = content
		select {
		case ready <- struct{}{}:
		default:
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer rw.Stop()

	// Write new content.
	newContent := []byte("key: value2\n")
	if err := os.WriteFile(cfgPath, newContent, 0644); err != nil {
		t.Fatal(err)
	}

	// Wait for the callback (debounce + some slack).
	select {
	case <-ready:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for reload callback")
	}

	if string(received) != string(newContent) {
		t.Errorf("received content = %q, want %q", received, newContent)
	}
}

func TestReloadWatcherDebounce(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "test.yaml")

	if err := os.WriteFile(cfgPath, []byte("v: 1\n"), 0644); err != nil {
		t.Fatal(err)
	}

	callCount := 0
	ready := make(chan struct{}, 1)

	rw, err := NewReloadWatcher(cfgPath, func(content []byte) {
		callCount++
		if callCount == 1 {
			select {
			case ready <- struct{}{}:
			default:
			}
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer rw.Stop()

	// Rapidly write multiple times — should coalesce into one callback.
	for i := 0; i < 5; i++ {
		if err := os.WriteFile(cfgPath, []byte("v: new\n"), 0644); err != nil {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Wait for the coalesced callback.
	select {
	case <-ready:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for reload callback")
	}

	// After debounce, there should have been exactly 1 call.
	// Allow a small window for any straggler.
	time.Sleep(500 * time.Millisecond)
	if callCount != 1 {
		t.Errorf("expected 1 debounced callback, got %d", callCount)
	}
}

func TestReloadWatcherStop(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "test.yaml")

	if err := os.WriteFile(cfgPath, []byte("key: value1\n"), 0644); err != nil {
		t.Fatal(err)
	}

	callCount := 0
	rw, err := NewReloadWatcher(cfgPath, func(content []byte) {
		callCount++
	})
	if err != nil {
		t.Fatal(err)
	}

	rw.Stop()

	// Write after stop — should NOT trigger callback.
	if err := os.WriteFile(cfgPath, []byte("key: value2\n"), 0644); err != nil {
		t.Fatal(err)
	}

	time.Sleep(500 * time.Millisecond)
	if callCount != 0 {
		t.Errorf("expected 0 callbacks after Stop(), got %d", callCount)
	}

	// Double Stop should not panic.
	rw.Stop()
}

// TestReloadWatcherSerializesConcurrentChanges verifies that onChange is
// never called concurrently: while a slow onChange is in flight, a second
// config change does NOT start a second onChange. The second change is
// coalesced and processed (with the latest content) only after the first
// completes.
func TestReloadWatcherSerializesConcurrentChanges(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "test.yaml")
	if err := os.WriteFile(cfgPath, []byte("v: 1\n"), 0644); err != nil {
		t.Fatal(err)
	}

	var (
		mu           sync.Mutex
		inFlight     int
		maxInFlight  int
		callCount    int
		contents     []string
		gate         = make(chan struct{}) // blocks onChange until released
		releaseFirst = make(chan struct{})
	)
	_ = gate

	rw, err := NewReloadWatcher(cfgPath, func(content []byte) {
		mu.Lock()
		inFlight++
		if inFlight > maxInFlight {
			maxInFlight = inFlight
		}
		callCount++
		contents = append(contents, string(content))
		mu.Unlock()

		// First call blocks until the test releases it, simulating a long
		// resize. Subsequent calls return immediately.
		if callCount == 1 {
			<-releaseFirst
		}

		mu.Lock()
		inFlight--
		mu.Unlock()
	})
	if err != nil {
		t.Fatal(err)
	}
	defer rw.Stop()

	// Trigger first reload (v:1 -> v:2) and wait for it to enter onChange.
	os.WriteFile(cfgPath, []byte("v: 2\n"), 0644)
	// Wait until the first onChange is blocking on releaseFirst.
	waitFor := func(cond func() bool, timeout time.Duration) {
		deadline := time.Now().Add(timeout)
		for time.Now().Before(deadline) {
			if cond() {
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
		t.Fatal("timed out waiting for condition")
	}
	waitFor(func() bool {
		mu.Lock()
		defer mu.Unlock()
		return callCount == 1
	}, 2*time.Second)

	// While the first onChange is in flight, trigger a second change (v:3)
	// and give the watcher time to (incorrectly) start a concurrent onChange.
	os.WriteFile(cfgPath, []byte("v: 3\n"), 0644)
	time.Sleep(400 * time.Millisecond) // debounce + slack

	// Release the first onChange.
	close(releaseFirst)

	// Wait for the second (coalesced) reload to complete.
	waitFor(func() bool {
		mu.Lock()
		defer mu.Unlock()
		return callCount >= 2
	}, 2*time.Second)

	mu.Lock()
	defer mu.Unlock()
	if maxInFlight > 1 {
		t.Errorf("onChange ran concurrently: maxInFlight=%d (want <=1)", maxInFlight)
	}
	// The second reload must reflect the LATEST content (v:3), not a stale
	// snapshot from when the second change was detected.
	if len(contents) < 2 {
		t.Fatalf("expected >=2 calls, got %d (%v)", len(contents), contents)
	}
	if contents[1] != "v: 3\n" {
		t.Errorf("second reload content = %q, want %q (latest)", contents[1], "v: 3\n")
	}
}

// TestReloadWatcherCoalescesRapidChanges verifies that many rapid saves
// during an in-flight reload collapse into a single follow-up reload with
// the latest content (no goroutine pile-up, no lost update).
func TestReloadWatcherCoalescesRapidChanges(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "test.yaml")
	if err := os.WriteFile(cfgPath, []byte("v: 0\n"), 0644); err != nil {
		t.Fatal(err)
	}

	var (
		mu          sync.Mutex
		callCount   int
		lastContent string
		release     = make(chan struct{})
	)
	rw, err := NewReloadWatcher(cfgPath, func(content []byte) {
		mu.Lock()
		callCount++
		lastContent = string(content)
		mu.Unlock()
		// Block every call so rapid changes pile up behind a single in-flight
		// reload; they must coalesce.
		<-release
	})
	if err != nil {
		t.Fatal(err)
	}
	defer rw.Stop()

	// Trigger first reload.
	os.WriteFile(cfgPath, []byte("v: 1\n"), 0644)
	// Wait for the first onChange to be blocking.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		c := callCount
		mu.Unlock()
		if c == 1 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	// Fire many rapid changes while the first reload is blocked.
	for i := 2; i <= 10; i++ {
		os.WriteFile(cfgPath, []byte("v: "+itoa(i)+"\n"), 0644)
		time.Sleep(10 * time.Millisecond)
	}

	// Release all blocked reloads. After draining, allow new ones to proceed
	// by making release non-blocking for subsequent calls.
	close(release)

	// Wait for things to settle: callCount stops growing.
	settle := time.Now().Add(2 * time.Second)
	for time.Now().Before(settle) {
		mu.Lock()
		c := callCount
		mu.Unlock()
		if c >= 2 {
			// Give a little more time for any straggler, then break.
			time.Sleep(300 * time.Millisecond)
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	mu.Lock()
	defer mu.Unlock()
	// We must have applied the LATEST content (v:10). callCount should be
	// small (coalesced), not 10.
	if lastContent != "v: 10\n" {
		t.Errorf("last applied content = %q, want %q", lastContent, "v: 10\n")
	}
	if callCount > 5 {
		t.Errorf("expected coalesced callCount <=5, got %d (rapid changes should collapse)", callCount)
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	if i < 0 {
		return "-" + itoa(-i)
	}
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

// TestReloadWatcherConfigMapSymlinkSwap simulates a kubelet ConfigMap volume
// update: the config path is a symlink to <dir>/..data/<name>, and an update
// atomically swaps ..data to a freshly written timestamped dir — no event ever
// carries the config's own filename. The watcher must still fire.
func TestReloadWatcherConfigMapSymlinkSwap(t *testing.T) {
	root := t.TempDir()
	cfgPath := filepath.Join(root, "sandns.yaml")

	// Volume layout: root/<name> -> root/..data/<name>; ..data -> root/..2026_09_15_0/
	writeVersion := func(tag, content string) {
		tsDir := filepath.Join(root, ".."+tag)
		if err := os.MkdirAll(tsDir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(tsDir, "sandns.yaml"), []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
		// Atomic swap: new symlink then rename over ..data (kubelet's pattern).
		tmp := filepath.Join(root, "..data-tmp")
		os.Remove(tmp)
		if err := os.Symlink(tsDir, tmp); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(tmp, filepath.Join(root, "..data")); err != nil {
			t.Fatal(err)
		}
		// The visible config file: a stable symlink to ..data/sandns.yaml.
		os.Remove(cfgPath)
		if err := os.Symlink(filepath.Join("..data", "sandns.yaml"), cfgPath); err != nil {
			t.Fatal(err)
		}
	}

	writeVersion("v1", "policy: v1\n")

	var got string
	gotCh := make(chan string, 4)
	rw, err := NewReloadWatcher(cfgPath, func(content []byte) {
		got = string(content)
		select {
		case gotCh <- string(content):
		default:
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer rw.Stop()

	// kubelet update: write a new timestamped dir and swap ..data onto it.
	writeVersion("v2", "policy: v2\n")

	select {
	case c := <-gotCh:
		if c != "policy: v2\n" {
			t.Errorf("reloaded content = %q, want v2", c)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("ConfigMap-style ..data swap did not trigger a reload")
	}
	_ = got
}

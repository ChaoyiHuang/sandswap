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

package runtime

import (
	"io"
	"log"
	"net"
	"path/filepath"
	"testing"
	"time"
)

// TestListenWithRetryFreePath pins the happy path: a free socket path binds
// on the first attempt (no retry backoff paid on a clean start).
func TestListenWithRetryFreePath(t *testing.T) {
	p := filepath.Join(t.TempDir(), "boxout.sock")
	start := time.Now()
	lis, err := ListenWithRetry(p, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatalf("free path: %v", err)
	}
	defer lis.Close()
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Fatalf("free path must bind immediately, took %v (backoff paid?)", elapsed)
	}
}

// TestListenWithRetryRecoversAfterRelease pins the restart race the retry
// exists for: the previous instance's listener still holds the path, releases
// it a moment later, and the bounded retry must then bind — a boxout restart
// racing its own teardown must not crash-loop the sidecar.
func TestListenWithRetryRecoversAfterRelease(t *testing.T) {
	p := filepath.Join(t.TempDir(), "boxout.sock")
	blocker, err := net.Listen("unix", p)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		// Release between attempt 2 and 3 (backoff: 100ms, 200ms, ...).
		time.Sleep(350 * time.Millisecond)
		blocker.Close()
	}()
	lis, err := ListenWithRetry(p, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatalf("must bind after the holder released: %v", err)
	}
	lis.Close()
}

// TestListenWithRetryExhausts pins the bound: a path that stays held for all
// five attempts returns the last error (the sidecar surfaces it and exits —
// never an infinite loop).
func TestListenWithRetryExhausts(t *testing.T) {
	p := filepath.Join(t.TempDir(), "boxout.sock")
	blocker, err := net.Listen("unix", p)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close()
	start := time.Now()
	lis, err := ListenWithRetry(p, log.New(io.Discard, "", 0))
	if err == nil {
		lis.Close()
		t.Fatal("a permanently held path must exhaust the retries and error")
	}
	// 5 attempts with 100+200+300+400ms sleeps between them.
	if elapsed := time.Since(start); elapsed < 900*time.Millisecond {
		t.Fatalf("gave up after only %v — the bounded retry budget was not used", elapsed)
	}
}

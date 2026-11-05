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
//
//! Test-only cross-module serialization.
//!
//! `waitpid(-1)` reap probes are process-wide: cargo runs tests in parallel
//! threads, so a reap probe in one test can steal another test's child exit
//! status (its `.status()`/`.output()` then fails with ECHILD). Any test that
//! spawns real children or runs reap probes MUST hold this lock — a per-module
//! mutex is not enough, the hazard is cross-module (this exact race made
//! seccomp.rs's spawn-based tests fail with ECHILD whenever an exec.rs reap
//! probe ran concurrently).

use std::sync::{Mutex, MutexGuard, PoisonError};

/// Serializes tests that spawn real children or rely on waitpid(-1) reap
/// probes. The data is just `()`.
static TEST_PROC_LOCK: Mutex<()> = Mutex::new(());

/// Poison-tolerant acquisition of [`TEST_PROC_LOCK`]. One test panicking while
/// holding the lock poisons it; with plain `.lock().unwrap()` every LATER
/// waiter then fails with PoisonError too — a single flaky assertion once
/// reported as 3/10 failed tests (1 real + 2 cascade), drowning the signal.
/// Recovering the guard keeps the mutual exclusion (the data is just `()`)
/// and lets each test's own assertions decide pass/fail.
pub fn proc_lock() -> MutexGuard<'static, ()> {
    TEST_PROC_LOCK
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
}

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
// Sandswap warden — SIGCHLD reaper + exit-status registry.
// The warden is PID 1 / a subreaper, so any orphaned child gets reaped here.
// With concurrent sync execs (parallel vsock connections, one exec per
// connection), the exec path can no longer wait on its child directly: a
// waitpid(-1) from one exec would race-reap — and steal the exit status of —
// another exec's child. Instead EVERY reaped child goes through this module:
//   - do_exec registers (pid → oneshot sender) in the same WAIT_PID_LOCKER
//     critical section as spawn(), so the reaper can never observe the child
//     before it is registered (that would leave do_exec waiting on a status
//     nobody will ever deliver).
//   - reap_one() is the single waitpid(-1) entry point. It reaps one zombie;
//     if the pid is registered, the raw wait status is forwarded to the
//     waiter and the reaped child is invisible to the caller; otherwise it is
//     reported as an orphan (a finished background-exec shell, or any
//     untracked child — logged and dropped).
// WAIT_PID_LOCKER now only covers the spawn→register window (and each reap
// probe). It is no longer held across a child wait, which is what allows
// multiple sync execs to run concurrently.

use anyhow::{anyhow, Result};
use capctl::prctl::set_subreaper;
use slog::{debug, error, info, Logger};
use std::collections::HashMap;
use std::sync::{Mutex as StdMutex, OnceLock};
use tokio::select;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::watch::Receiver;

/// Held by do_exec only across its spawn() + register_exit_waiter() pair, and
/// by reap_one()/reap_zombie() across each waitpid probe. This closes the
/// window where the reaper could reap a just-spawned child that is not yet
/// registered (the waiter would then block forever). It is NOT held across
/// child waits (the rc.local boot path holds it across its blocking wait —
/// inside a spawn_blocking thread).
///
/// A std (not tokio) mutex: no holder awaits while holding it, and a sync
/// holder (mount.rs's blocking fallback-reap loop) must be able to take it.
pub static WAIT_PID_LOCKER: StdMutex<()> = StdMutex::new(());

/// A registered waiter receives the raw waitpid status word of its child.
type ExitTx = tokio::sync::oneshot::Sender<i32>;

fn exit_tx_map() -> &'static StdMutex<HashMap<i32, ExitTx>> {
    static MAP: OnceLock<StdMutex<HashMap<i32, ExitTx>>> = OnceLock::new();
    MAP.get_or_init(|| StdMutex::new(HashMap::new()))
}

/// Register a waiter for `pid`'s exit. Called by do_exec in the same
/// WAIT_PID_LOCKER critical section as spawn().
pub fn register_exit_waiter(pid: i32, tx: ExitTx) {
    exit_tx_map().lock().unwrap().insert(pid, tx);
}

/// Drop a waiter without delivering a status (do_exec fell back to a direct
/// waitpid of its own child — the registry entry must not linger and fire on
/// an unrelated later waitpid).
pub fn cancel_exit_waiter(pid: i32) -> Option<ExitTx> {
    exit_tx_map().lock().unwrap().remove(&pid)
}

/// Deliver `raw` as the exit status of `pid` to its registered waiter.
/// Returns true if a waiter existed. Split out of reap_one so the forwarding
/// logic is unit-testable without real waitpid calls.
pub fn forward_exit(pid: i32, raw: i32) -> bool {
    match exit_tx_map().lock().unwrap().remove(&pid) {
        Some(tx) => {
            let _ = tx.send(raw);
            true
        }
        None => false,
    }
}

/// Outcome of one reap probe.
pub enum Reaped {
    /// No child was ready to be reaped.
    Nothing,
    /// Reaped and forwarded to its registered waiter — the caller must not
    /// treat it as its own.
    Forwarded,
    /// Reaped but nobody was waiting: a natural orphan (e.g. an exited
    /// background-exec shell) or an untracked child.
    Orphan(i32),
}

/// Lock WAIT_PID_LOCKER, surviving a poisoned guard: a panicked holder must
/// not permanently take down reaping (the registry map is only mutated under
/// the same lock, so a panic mid-critical-section leaves at worst a stale
/// entry that cancel_exit_waiter/forward_exit already tolerate).
pub fn lock_reaper() -> std::sync::MutexGuard<'static, ()> {
    WAIT_PID_LOCKER.lock().unwrap_or_else(|e| e.into_inner())
}

/// The single waitpid(-1) entry point. `flags` is a WNOHANG combination (the
/// reaper never blocks — a blocking wait is only ever done by a specific pid).
/// Holds WAIT_PID_LOCKER across the probe so a concurrent spawn+register
/// cannot be interleaved with the reap.
pub async fn reap_one(flags: i32) -> Reaped {
    reap_zombie(flags)
}

/// Sync twin of reap_one for blocking contexts (spawn_blocking paths that
/// cannot await): identical lock + waitpid + forward_exit semantics. Blocking
/// code MUST reap through this (or reap_one) — a bare waitpid(-1) silently
/// discards a registered child's status and hangs its waiter until timeout.
pub fn reap_zombie(flags: i32) -> Reaped {
    let _lock = lock_reaper();
    let mut status: i32 = 0;
    let pid = unsafe { libc::waitpid(-1, &mut status, flags) };
    if pid <= 0 {
        return Reaped::Nothing;
    }
    if forward_exit(pid, status) {
        return Reaped::Forwarded;
    }
    Reaped::Orphan(pid)
}

async fn handle_sigchild(logger: Logger) -> Result<()> {
    loop {
        // Drain every ready zombie; stop when there is nothing left. Forwarded
        // exits are silent here — the waiting exec gets the status.
        match reap_one(libc::WNOHANG | libc::__WALL).await {
            Reaped::Nothing => return Ok(()),
            Reaped::Forwarded => {}
            Reaped::Orphan(pid) => {
                // Tenant-controlled volume: a double-fork loop can produce
                // orphans at will. A per-exit INFO line would tax the hvc0
                // console on a measured path and flood the host log; keep it
                // debug-gated (a no-op in release builds).
                debug!(logger, "reaped orphan child"; "pid" => pid);
            }
        }
    }
}

pub async fn setup_signal_handler(logger: Logger, mut shutdown: Receiver<bool>) -> Result<()> {
    let logger = logger.new(o!("subsystem" => "signals"));

    set_subreaper(true)
        .map_err(|err| anyhow!(err).context("failed to setup agent as a child subreaper"))?;

    let mut sigchild_stream = signal(SignalKind::child())?;

    loop {
        select! {
            _ = shutdown.changed() => {
                info!(logger, "got shutdown request");
                break;
            }

            _ = sigchild_stream.recv() => {
                let result = handle_sigchild(logger.clone()).await;

                if let Err(e) = result {
                    error!(logger, "failed to handle signal"; "error" => format!("{:?}", e));
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── exit-status registry ────────────────────────────────────────

    #[tokio::test]
    async fn forward_exit_delivers_to_registered_waiter() {
        let (tx, mut rx) = tokio::sync::oneshot::channel::<i32>();
        let pid = 999_999; // synthetic: never a real child in tests
        register_exit_waiter(pid, tx);
        assert!(forward_exit(pid, 0x0500)); // raw status: exit code 5
        assert_eq!(rx.try_recv().unwrap(), 0x0500);
        // One-shot: a second forward finds no waiter.
        assert!(!forward_exit(pid, 0));
    }

    #[tokio::test]
    async fn forward_exit_unregistered_pid_is_orphan() {
        assert!(!forward_exit(999_998, 0));
    }

    #[tokio::test]
    async fn cancel_exit_waiter_removes_entry() {
        let (tx, rx) = tokio::sync::oneshot::channel::<i32>();
        let pid = 999_997;
        register_exit_waiter(pid, tx);
        assert!(cancel_exit_waiter(pid).is_some());
        // Cancelled: forward finds no waiter, and the receiver sees the drop.
        assert!(!forward_exit(pid, 0));
        assert!(rx.await.is_err());
    }
}

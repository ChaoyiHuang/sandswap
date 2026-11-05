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

//! The rule-A process sweep and the unmount final-state gate.
//!
//! FAIL-CLOSED RULE: the kernel prints `/proc/<pid>/stat` field 2
//! (comm) as raw bytes, and `prctl(PR_SET_NAME)` lets a tenant store any
//! byte there. `std::fs::read_to_string` therefore returns
//! `Err(InvalidData)` for such a process — and the old predicates treated
//! that Err as "the process vanished", so both the sweep and the final gate
//! skipped a LIVE process. The same fail-open existed for any other read
//! error and for a failed `/proc` scan.
//!
//! The fix is threefold and deliberately does not depend on the text being
//! UTF-8:
//!   * `/proc/<pid>/stat` is read as BYTES and decoded lossily. The comm is
//!     parenthesized; everything after the LAST ')' is plain decimal ASCII,
//!     and a lossy replacement inside the comm cannot create a ')' after the
//!     real terminator, so the parse stays correct for arbitrary comm bytes.
//!   * A line that cannot be parsed, or a read that fails for any reason
//!     OTHER than ENOENT (a genuine vanish), is treated as a live user
//!     process: the sweep targets it and the gate reports it unclean.
//!   * A `/proc` scan failure is an ERROR, never an empty listing: the
//!     unmount refuses to declare the VM clean and the sandlot destroys it.

use std::fs;
use std::io;

/// Kernel flag bit marking a kernel thread (`PF_KTHREAD`). Field 9 of
/// `/proc/<pid>/stat`, printed in decimal.
const PF_KTHREAD: u64 = 0x0020_0000;

/// The two parsed facts the predicates need from a stat line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StatFacts {
    /// state is Z/X/x (zombie / dead).
    dead: bool,
    /// PF_KTHREAD is set.
    kthread: bool,
}

/// Parse the numeric fields after the LAST ')' of a `/proc/<pid>/stat` line.
///
/// Layout: `pid (comm) state ppid pgrp session tty_nr tpgid flags ...`.
/// The comm is parenthesized and may contain spaces and parens, so the
/// fields are parsed from the last ')' exactly as procps does. Everything
/// after that is decimal ASCII; a malformed/truncated tail returns None and
/// the callers fail CLOSED.
fn parse_stat_facts(stat: &str) -> Option<StatFacts> {
    let (_, rest) = stat.rsplit_once(')')?;
    let mut fields = rest.split_whitespace();
    let state = fields.next()?.as_bytes().first().copied()?;
    // After state: ppid(4) pgrp(5) session(6) tty_nr(7) tpgid(8) | flags(9)
    let flags = fields.nth(5)?;
    let flags: u64 = flags.parse().ok()?;
    Some(StatFacts {
        dead: matches!(state, b'Z' | b'X' | b'x'),
        kthread: flags & PF_KTHREAD != 0,
    })
}

/// Read `/proc/<pid>/stat` into `buf` (cleared first; the capacity is reused
/// across pids — the sweep and the gate walk dozens of stat files per
/// unmount, and a fresh allocation per read was measurable churn).
///
/// `Ok(None)` means the pid vanished between the `read_dir` snapshot and
/// this read (ENOENT) — the only error that is provably "not a live
/// process". Every other error is propagated so the caller can fail closed.
fn read_proc_stat_into(pid: i32, buf: &mut Vec<u8>) -> io::Result<Option<()>> {
    buf.clear();
    let res = fs::File::open(format!("/proc/{pid}/stat")).and_then(|mut f| {
        use std::io::Read;
        f.read_to_end(buf)
    });
    match res {
        Ok(_) => Ok(Some(())),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Parse the two facts out of raw stat bytes (lossy decode — see the module
/// doc: the numeric tail after the LAST ')' is ASCII regardless of comm).
fn parse_stat_facts_lossy(stat: &[u8]) -> Option<StatFacts> {
    parse_stat_facts(&String::from_utf8_lossy(stat))
}

/// One pid's rule-A decision, shared by the scan loop and the test-facing
/// predicate so the classification cannot drift between sweep and gate.
#[derive(Debug, PartialEq, Eq)]
enum ProcKind {
    /// PID 0/1 (swapper, the warden) — never touched.
    Init,
    /// No /proc entry left (raced exit) — nothing to signal or report.
    Vanished,
    /// Live kernel thread (PF_KTHREAD, not dead) — exempt from both the
    /// sweep and the final gate; recorded for the gate's shared set.
    Kthread,
    /// Zombie/dead state — not a sweep target (holds no mount; the reap
    /// windows collect it), still read fresh by the gate (unclean).
    Zombie,
    /// Live userspace, or a line/read that cannot prove otherwise —
    /// fail-closed: signalled by the sweep.
    Target,
}

/// Classify one pid by its `/proc/<pid>/stat`. `buf` is scratch, reused
/// across calls. The fail-closed rules of the byte predicates apply:
/// an unparseable line or an unreadable stat is a Target, never a skip.
fn classify_proc(pid: i32, buf: &mut Vec<u8>) -> ProcKind {
    if pid <= 1 {
        return ProcKind::Init;
    }
    match read_proc_stat_into(pid, buf) {
        // Vanished between readdir and here — nothing to kill.
        Ok(None) => ProcKind::Vanished,
        Ok(Some(())) => match parse_stat_facts_lossy(buf) {
            Some(f) if f.kthread && !f.dead => ProcKind::Kthread,
            Some(f) if f.dead => ProcKind::Zombie,
            Some(_) => ProcKind::Target,
            // Unparseable — never treat that as "vanished".
            None => ProcKind::Target,
        },
        // Unreadable — never treat that as "vanished".
        Err(_) => ProcKind::Target,
    }
}

/// True when a raw stat line describes a live userspace process.
///
/// This is the pure (non-fail-closed) predicate: a malformed line returns
/// false. The sweep/gate call sites use the *bytes* variant below, which
/// treats an unparseable line as a target/unclean instead — this str form
/// is the unit-test face of that predicate (mount/tests.rs), hence the
/// test-only gate.
#[cfg(test)]
pub(crate) fn stat_line_is_live_userspace(stat: &str) -> bool {
    matches!(parse_stat_facts(stat), Some(f) if !f.dead && !f.kthread)
}

/// FAIL-CLOSED sweep-target decision over raw stat bytes.
///
/// A line that cannot be parsed is a target: the caller only reaches this
/// point after a successful read, and an unparseable kernel line does not
/// exist, so the line belongs to a process whose comm the kernel emitted in
/// a form we could not decode — kill it (a no-op if it was a racing exit).
///
/// Test-only face of `classify_proc`'s Target arm (production classifies
/// through the enum so the sweep and the gate cannot drift).
#[cfg(test)]
pub(crate) fn stat_bytes_are_sweep_target(stat: &[u8]) -> bool {
    match parse_stat_facts_lossy(stat) {
        Some(f) => !f.dead && !f.kthread,
        None => true,
    }
}

/// FAIL-CLOSED final-gate decision over raw stat bytes.
///
///   - dead state ('Z'/'X'/'x'): unclean (unreaped process table);
///   - kernel thread: exempt (never holds a mount, ignores signals);
///   - any other live state: unclean;
///   - unparseable: unclean (fail closed).
pub(crate) fn stat_bytes_are_unclean(stat: &[u8]) -> bool {
    match parse_stat_facts_lossy(stat) {
        Some(f) => f.dead || !f.kthread,
        None => true,
    }
}

/// True when `pid` is a sweep target: a LIVE USERSPACE process other than 0
/// (swap) and 1 (the warden itself).
///
/// Kernel threads and zombies are NOT targets, and counting them was a
/// measured latency bug: /proc lists kernel threads like any task (kthreadd
/// is pid 2 and is always there), they ignore every signal and never die, so
/// a sweep round that "killed" them never observed an empty round and the
/// caller ran its FULL 8-round budget on every unmount — 8 × 25 ms = 200 ms
/// added to every agent switch, on the hot path (the pre-sweep unmount floor
/// is single-digit ms). Zombies are already dead and hold no mount — the
/// reap windows around
/// the sweep collect them; signalling one is a no-op that must not reset the
/// round budget either.
///
/// Fail-closed: an unreadable stat (any error but ENOENT) is a target. A pid
/// that vanished (ENOENT) is not.
///
/// Test-only: production sweeps through `sweep_once`/`classify_proc` (which
/// also records the kthread classification the gate reuses); this predicate
/// is the unit-test face of that decision.
#[cfg(test)]
pub(crate) fn sweep_target_pid(pid: i32) -> bool {
    let mut buf = Vec::new();
    classify_proc(pid, &mut buf) == ProcKind::Target
}

/// The task state character (field 3 of `/proc/<pid>/stat`: `R S D Z T t I X x`),
/// parsed with the same LAST-')' comm rule as the predicates above.
/// Test-only: production reads states through the byte fail-closed forms.
#[cfg(test)]
pub(crate) fn proc_stat_state(stat: &str) -> Option<char> {
    let (_, rest) = stat.rsplit_once(')')?;
    rest.split_whitespace()
        .next()
        .and_then(|s| s.chars().next())
}

/// True when a `/proc/<pid>/stat` line describes a task that makes the guest
/// NOT provably clean at the unmount final gate:
///   - 'Z' — an unreaped zombie (nothing pins a mount with a corpse, but an
///     unreaped process means the process table is not clean);
///   - ANY other live userspace state ('R', 'S', 'D', 'T', ...). The rule-A
///     sweep has already SIGKILLed every non-init userspace process by the
///     time this runs, and the bounded sweep's 8x25ms budget can miss a
///     child forked after its last scan. A surviving R/S task is a live
///     tenant process: it pins /mnt/rootfs (EBUSY on the final umount at
///     best) and can race the teardown lstat->umount (the `/tmp -> /dev`
///     class). Refusing to reuse the VM is the only sound decision; the
///     sandlot destroys it instead. Kernel threads ('D' by design) are
///     exempted by the PF_KTHREAD check, so a healthy VM is not destroyed on
///     their account.
///
/// The str form is the pure predicate (malformed → false); call sites use
/// `stat_bytes_are_unclean` / this function via the byte reader. Test-only
/// gate for the same reason as `stat_line_is_live_userspace`.
#[cfg(test)]
pub(crate) fn stat_line_is_unclean(stat: &str) -> bool {
    match parse_stat_facts(stat) {
        Some(f) => f.dead || !f.kthread,
        None => true, // fail closed
    }
}

/// Rule-A sweep: SIGKILL every userland process except PID 1. The exclusive-
/// ownership invariant in its bluntest form: an unmounted VM is CLEAN — zero
/// mounts and nothing alive except the warden. This closes the straggler
/// class that BOTH other clears miss: a sync-exec descendant that called
/// setsid() escapes the finish-tail kill(-pgid), and sync execs never join
/// the per-agent cgroup (deliberately, see exec.rs) so cgroup.kill does not
/// cover them either.
///
/// Gated to PID 1: unit tests run unmount_workspace on a host where "kill
/// everything but init" would be catastrophic. Every round propagates a
/// `/proc` scan failure: the caller must refuse to reuse the VM rather than
/// assume the guest is clean.
///
/// CONTRACT: `Ok` is returned ONLY after a round observed ZERO live
/// userspace targets — the one observation that licenses "nothing alive
/// remains". A round budget exhausted while rounds still signal targets is
/// an ERROR: the guest is not provably clean, so the unmount must fail and
/// the sandlot must destroy the VM. Returning Ok on the exhausted path would
/// let a forker survive past the budget, and the final gate could then miss
/// a recycled pid.
///
/// On success, also returns the pids this sweep classified as live kernel
/// threads — HINTS FOR OBSERVABILITY ONLY, never an exemption: `unclean_pids`
/// re-reads every pid (a pid is not an identity). A dead-state kthread is
/// deliberately not recorded.
pub(crate) fn sweep_non_init_processes() -> io::Result<Vec<i32>> {
    if std::process::id() != 1 {
        return Ok(Vec::new());
    }
    // LOOP until a scan observes nothing left. A single pass is
    // beatable by a forker that spawns AFTER our /proc snapshot — the child
    // was never in the listing, survives the pass, and pins the mount (a
    // setsid'd forker demonstrates exactly that). Each
    // round kills what it sees and sleeps briefly for the exits to land; a
    // round that kills nothing ends the loop. The bound keeps a pathological
    // fork-bomb from stalling the unmount; exhausting it FAILS the unmount
    // (see CONTRACT above) instead of proceeding on an unproven guest.
    const MAX_ROUNDS: usize = 8;
    let mut kthreads = Vec::new();
    run_sweep(
        || sweep_once(&mut kthreads),
        MAX_ROUNDS,
        || std::thread::sleep(std::time::Duration::from_millis(25)),
    )?;
    Ok(kthreads)
}

/// The bounded convergence loop, with the round function and the wait
/// injected so the budget-exhaustion contract is unit-testable without
/// PID 1, real kills, or real sleeps.
///
/// `Ok` ⟺ some round signalled zero targets. `Err` when the budget is
/// exhausted while targets are still being signalled — the caller (the
/// unmount) turns that into VM destruction.
pub(crate) fn run_sweep<R, S>(mut round: R, max_rounds: usize, mut wait: S) -> io::Result<()>
where
    R: FnMut() -> io::Result<usize>,
    S: FnMut(),
{
    let mut last_killed = 0usize;
    for _ in 0..max_rounds {
        last_killed = round()?;
        if last_killed == 0 {
            return Ok(());
        }
        wait();
    }
    Err(io::Error::other(format!(
        "process sweep did not converge after {} rounds (the last round signalled {} live task(s)) — refusing to reuse this VM",
        max_rounds, last_killed
    )))
}

/// One SIGKILL pass over /proc; returns how many targets were signalled.
/// Every pid classified as a live kernel thread is appended to `kthreads`
/// (deduplicated) for the final gate's shared set.
///
/// A failed `/proc` scan or a failed directory entry read is an ERROR (fail
/// closed at the caller): an empty listing must never be mistaken for a
/// clean guest.
pub(crate) fn sweep_once(kthreads: &mut Vec<i32>) -> io::Result<usize> {
    let entries = fs::read_dir("/proc")?;
    let mut killed = 0usize;
    let mut buf = Vec::with_capacity(256);
    for entry in entries {
        let entry = entry?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<i32>().ok())
        else {
            continue;
        };
        match classify_proc(pid, &mut buf) {
            ProcKind::Target => {
                unsafe {
                    let _ = libc::kill(pid, libc::SIGKILL);
                }
                killed += 1;
            }
            ProcKind::Kthread => {
                if !kthreads.contains(&pid) {
                    kthreads.push(pid);
                }
            }
            ProcKind::Init | ProcKind::Vanished | ProcKind::Zombie => {}
        }
    }
    Ok(killed)
}

/// Pids above 1 that fail the unmount final gate (see `stat_bytes_are_unclean`).
///
/// `kthread_hints` are the pids THIS unmount's sweep classified as live
/// kernel threads. They are **never trusted as an exemption**: a pid is not
/// an identity — a kernel thread can exit and its pid be recycled to a
/// userspace process, and the sweep's own rounds can observe that recycling
/// (a pid recorded as `Kthread` in one round can appear as a live `Target`
/// in a later one). A pid-only exemption would let such a recycled pid skip
/// the gate entirely: a fail-open in the last control that proves the guest
/// clean.
///
/// Every pid in /proc is therefore READ and judged fresh. A hint hit only
/// emits a debug line, because it means the sweep raced a forker (or the
/// kernel recycled a thread's pid) — an audit signal, not permission to
/// skip. Pids not in the set are judged exactly as before.
///
/// A failed `/proc` scan is an ERROR, and an unreadable per-pid stat is
/// treated as unclean — both fail closed. `Ok(None)` from the reader (a pid
/// that vanished) is skipped: it has no process table entry left to report.
pub(crate) fn unclean_pids(kthread_hints: &[i32]) -> io::Result<Vec<i32>> {
    let mut out = Vec::new();
    let entries = fs::read_dir("/proc")?;
    let mut buf = Vec::with_capacity(256);
    for entry in entries {
        let entry = entry?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<i32>().ok())
        else {
            continue;
        };
        if pid <= 1 {
            continue;
        }
        if kthread_hints.contains(&pid) {
            // Observability only — the pid is still read and judged below.
            // A pid is not an identity: the hint names a kernel thread seen
            // during the sweep; this entry may be a recycled userspace task.
            slog_scope::debug!(
                "final gate: pid {} was a kernel thread during the sweep but is present now — reading it fresh (pid reuse is not an exemption)",
                pid
            );
        }
        match read_proc_stat_into(pid, &mut buf) {
            Ok(None) => {}
            Ok(Some(())) => {
                if stat_bytes_are_unclean(&buf) {
                    out.push(pid);
                }
            }
            // Unreadable: never treat that as "vanished".
            Err(_) => out.push(pid),
        }
    }
    out.sort_unstable();
    Ok(out)
}

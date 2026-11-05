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
// Sandswap warden — logger setup.
// A simple line drain (level + module + message) over the writer (a pipe to
// the vsock logger task, or stdout), level-filtered and made async so logging
// never blocks the exec path. The returned guard flushes on drop. Plain text
// is enough — the deploy/test harness greps raw_server's info! lines
// ("mount_and_exec done in Nms", etc.), not JSON fields.

use slog::{Drain, Logger, OwnedKVList, Record};
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

// DEBUG_TRACE_ENABLED mirrors the logger's level into a plain atomic so hot
// paths can skip building debug-only payloads (formatted strings, step
// vectors) BEFORE any formatting work — the same doctrine that gates the
// per-op log lines themselves: slog arguments are eager at the call site, and
// the console drain makes every avoided line a real win on a measured path.
static DEBUG_TRACE_ENABLED: AtomicBool = AtomicBool::new(false);

/// debug_trace_enabled reports whether Debug-level records reach the drain.
/// Checked before constructing debug-only diagnostics (see mount_workspace's
/// per-step timing): one relaxed atomic load when disabled.
pub(crate) fn debug_trace_enabled() -> bool {
    DEBUG_TRACE_ENABLED.load(Ordering::Relaxed)
}

struct LineDrain<W: Write + Send + 'static>(Mutex<W>);

impl<W: Write + Send + 'static> Drain for LineDrain<W> {
    type Ok = ();
    type Err = std::io::Error;
    fn log(&self, record: &Record, _kv: &OwnedKVList) -> Result<(), Self::Err> {
        let mut w = self.0.lock().unwrap();
        writeln!(w, "{} {} {}", record.level(), record.module(), record.msg())
    }
}

/// Whether the debug-only payload builders (see debug_trace_enabled) should
/// run at `level`: only when records at Debug actually reach the drain.
/// slog's Level order is Critical < Error < Warning < Info < Debug < Trace, so
/// Debug-and-more-verbose is `level >= Debug` (the former `<= Debug` also
/// matched the Info default and kept constructing every trace payload).
fn debug_gate_for(level: slog::Level) -> bool {
    level >= slog::Level::Debug
}

pub fn create_logger<W>(level: slog::Level, writer: W) -> (Logger, slog_async::AsyncGuard)
where
    W: Write + Send + Sync + 'static,
{
    DEBUG_TRACE_ENABLED.store(debug_gate_for(level), Ordering::Relaxed);
    let drain = LineDrain(Mutex::new(writer)).fuse();
    let (async_drain, guard) = slog_async::Async::new(drain)
        .thread_name("slog-async-logger".into())
        .build_with_guard();
    // The level filter must sit BEFORE the async queue, not inside it: the
    // logger's `is_enabled` consults the outermost drain, so a filter outside
    // makes slog's macros drop a disabled level at the call site (no record
    // construction, no AsyncRecord formatting, no queue slot). Wrapping the
    // inner drain instead put the filter on the consumer thread, where every
    // disabled record had already paid the full formatting and channel cost.
    let filtered = slog::LevelFilter::new(async_drain, level);
    (Logger::root(filtered.fuse(), slog::o!()), guard)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_gate_is_debug_and_below_only() {
        for level in [
            slog::Level::Critical,
            slog::Level::Error,
            slog::Level::Warning,
            slog::Level::Info,
        ] {
            assert!(!debug_gate_for(level), "{level:?} must not enable traces");
        }
        for level in [slog::Level::Debug, slog::Level::Trace] {
            assert!(debug_gate_for(level), "{level:?} must enable traces");
        }
    }

    #[test]
    fn logger_filters_before_the_async_queue() {
        // The default level is Info: Debug records must be disabled at the
        // LOGGER (i.e. the outer filter), so the slog macros never build them.
        let (logger, guard) = create_logger(slog::Level::Info, Vec::new());
        assert!(!debug_trace_enabled());
        assert!(!logger.is_enabled(slog::Level::Debug));
        assert!(logger.is_enabled(slog::Level::Info));
        drop(guard);

        // Debug raises the gate and the logger admits the level.
        let (logger, guard) = create_logger(slog::Level::Debug, Vec::new());
        assert!(debug_trace_enabled());
        assert!(logger.is_enabled(slog::Level::Debug));
        drop(guard);

        // Restore the process-wide gate so sibling tests see the default.
        DEBUG_TRACE_ENABLED.store(debug_gate_for(slog::Level::Info), Ordering::Relaxed);
    }
}

/// A logger that discards everything (NOP logger for the shutdown tail).
pub fn discard_logger() -> Logger {
    Logger::root(slog::Discard, slog::o!())
}

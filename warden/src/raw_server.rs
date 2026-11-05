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
// Sandswap raw vsock protocol — the sandlot↔warden transport.
// Fixed 90-byte request header (10-byte base + 16-byte nonce + 32-byte
// op-specific body-field MAC + 32-byte tag) +
// length-prefixed fields and a 60-byte response header (28-byte base + 32-byte
// tag). Every request carries an HMAC-SHA256 tag over the base header fields
// and the nonce, keyed by the per-VM session key; the warden verifies it
// BEFORE reading or reserving memory for the body, and every response carries
// a tag bound to the request nonce so the sandlot can refuse a forged
// responder. The tag costs a small SHA-256 computation and no extra syscall
// (the nonce is a per-connection prefix plus a counter). Connections are
// served concurrently (task per connection): sandlot
// keeps a POOL of per-VM connections (one in-flight request each, sized by the
// spec's exec_slots) plus short-lived probe connections. Per-VM mutual
// exclusion that used to come from the sandlot's execMu now lives here:
//   - mount/unmount take the sandbox::MOUNT_GATE write guard (serialize with
//     each other and wait out in-flight execs);
//   - sync exec / file ops take the read guard (touch the mounted workspace).
// All verified isolation logic is reused unchanged:
//   - mount::mount_workspace  (virtio-fs allowed_dirs semantics, ④ tmpfs sh, ③ readahead)
//   - mount::unmount_workspace (directed page-cache drop, no global sync)
//   - AgentService::do_exec    (setsid + kill(-pgid), CString hoist)
// This module is a thin transport; it touches none of that.

use anyhow::Result;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::Instant;

use slog::{debug, Logger};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;
use tokio_vsock::{VsockAddr, VsockListener, VsockStream, VMADDR_CID_ANY, VMADDR_CID_HOST};

use crate::exec::AgentService;
use crate::mount::mount_workspace;
use crate::sandbox::Sandbox;
use warden::frame_parse::parse_field_spans;

/// vsock port the warden listens on (matches sandlot wardenVsockPort).
pub const PORT: u32 = 1024;

/// Frame magic = "SAND" (0x53414e44). Guards against garbage / misrouted reads.
const MAGIC: u32 = 0x53414e44;

/// Wire protocol version. Both request and response frames carry this.
/// Negotiation model: a request whose version falls outside
/// [PROTOCOL_MIN_ACCEPTED, PROTOCOL_VERSION] is answered with ONE
/// transport-error frame (this header still carries OUR version, so a
/// versioned client classifies it precisely) and the connection is closed.
///
/// The warm-op mounted-volume identity field (see the IDX_*_VOLUME constants)
/// is part of THIS layout — there is no separate protocol version for it; it
/// is always present at its fixed position.
pub const PROTOCOL_VERSION: u8 = 1;

/// Minimum request protocol version this warden accepts. The window is [1,1].
const PROTOCOL_MIN_ACCEPTED: u8 = 1;

/// Request nonce, body-field MAC and tag lengths in the authenticated header.
const NONCE_LEN: usize = 16;
const BODY_MAC_LEN: usize = 32;
const TAG_LEN: usize = 32;
/// Base request header: magic(4) + version(1) + op(1) + body_len(4).
const REQ_BASE_HEADER_LEN: usize = 10;
/// Full request header: base + nonce + op-specific body-field MAC + tag.
const REQ_HEADER_LEN: usize = REQ_BASE_HEADER_LEN + NONCE_LEN + BODY_MAC_LEN + TAG_LEN;
/// Response header: magic(4) + version(1) + code(1) + exit_code(1) +
/// reserved(1) + stdout_len(4) + stderr_len(4) + exec_duration_ns(8) +
/// mounted_len(4) + tag(32).
const RESP_BASE_HEADER_LEN: usize = 28;
const RESP_HEADER_LEN: usize = RESP_BASE_HEADER_LEN + TAG_LEN;

/// version_supported reports whether this warden can interpret a request
/// frame carrying version v. Extracted as a pure function for unit testing.
fn version_supported(v: u8) -> bool {
    v >= PROTOCOL_MIN_ACCEPTED && v <= PROTOCOL_VERSION
}

const OP_MOUNT_AND_EXEC: u8 = 1; // sync: mount + exec (cold path, one RTT)
const OP_UNMOUNT: u8 = 2; // unmount + cgroup.kill
const OP_EXEC: u8 = 3; // sync: exec only (warm path, already mounted)
const OP_MEM_STATS: u8 = 4; // heartbeat: guest MemAvailable/MemTotal
const OP_ASYNC_EXEC: u8 = 5; // async: start background exec (warm path, already mounted)
const OP_MOUNT_AND_ASYNC_EXEC: u8 = 6; // async: mount + start background exec (cold path, one RTT)
const OP_STATUS_EXEC: u8 = 7; // async: poll status + log tail
const OP_KILL_EXEC: u8 = 8; // async: kill background exec by exec_id
const OP_FILE: u8 = 9; // file I/O: unified sub-opcode dispatch
/// Key delivery: the FIRST frame on the first host connection. It is the one
/// unauthenticated op (the warden has no key yet); the reply is tagged with
/// the delivered key, so the sandlot learns the key was installed. Once
/// initialized, a repeat delivery with the same key is an idempotent ack.
const OP_KEY_DELIVERY: u8 = 10;

// Mounted-volume identity field positions (current protocol layout, warm ops). The field
// carries the BASENAME of the volume the sandlot's mount bookkeeping believes
// is attached — the same identity the MOUNT-family responses echo in
// `mounted` and the sandlot cross-checks there. The warden refuses a warm op
// whose identity differs from Sandbox::mounted_volume — the only place that
// knows what is actually mounted — so a sandlot bookkeeping skew can never
// execute one tenant's command inside another tenant's rootfs().
//
// FIXED indices, named per op, so the read is one field lookup and can never
// drift into another payload of the same op:
//   OP_EXEC       = 3  (0 command, 1 timeout_ms, 2 install_packages)
//   OP_ASYNC_EXEC = 2  (0 command, 1 install_packages)
//   OP_FILE       = 5  (0 sub_op, 1 path, 2..4 sub-op-specific; WRITE's data
//                       rides field 4, so 5 is free for every sub-op and the
//                       sandlot pads any gap with empty fields)
// A v1 frame simply lacks the field; `field_bytes` reads it as empty, which
// is the documented rolling-upgrade path (mount_active-only + rate-limited
// warn). OP_STATUS_EXEC/OP_KILL_EXEC deliberately carry NO identity: they
// execute nothing and resolve no path under the mounted rootfs (kill targets
// the warden's own registry by exec_id, status reads a tmpfs log), and they
// are documented to stay answerable after a mount is torn down — asserting a
// volume on them would turn that legit `not_found` race into a false refusal.
const IDX_EXEC_VOLUME: usize = 3;
const IDX_ASYNC_EXEC_VOLUME: usize = 2;
const IDX_FILE_VOLUME: usize = 5;

/// Name of the warm-op refusal when the request's mounted-volume identity does
/// not match the volume the warden actually holds. Carried as the leading
/// token of the transport-error message — the named outcome an operator greps
/// for (the sandlot surfaces the message verbatim in the command error).
const ERR_VOLUME_IDENTITY_MISMATCH: &str = "volume_identity_mismatch";

/// Name of the warm-op refusal when the request carries NO mounted-volume
/// identity at all. An empty field is a protocol/bookkeeping failure, not a
/// licence to execute against whatever happens to be mounted: fail closed with
/// its own named outcome (the cold combined ops are the only calls with no
/// identity by design and they pass `None`, not an empty field).
const ERR_VOLUME_IDENTITY_MISSING: &str = "volume_identity_missing";

// single countdown: the warden releases a stale mount as a last
// resort by exiting the VM. The anchor is the sandlot heartbeat (OP_MEM_STATS):
// only heartbeats reset it; business RPCs (mount/exec/unmount/file) deliberately
// do NOT. The sandlot stops heartbeating at T_tolerance (stream-loss tolerance
// expired), so a mount still live at T_tolerance + T_warden means cleanup did
// not finish in time — POWER_OFF the VM to force-release the sandfs. The guest
// ACPI power-off fires the VMM's exit event, so the sandvmm process exits and the
// virtio-fs connection drops, releasing the mount (the mount dies with the VM).
// NB: only when a SandFS is still mounted (mount_active) — an already-unmounted
// VM is left alone. T_warden (default 300s) >> T_clean (sandlot cleanup budget),
// so the sandlot always has room to unmount normally. Unmounted VMs are never
// killed (countdown no-ops without a live mount), so clean VMs survive into the
// gateway's reconnect reconcile.
const COUNTDOWN_TICK: std::time::Duration = std::time::Duration::from_secs(1);

/// Maximum number of length-prefixed fields in one request body. Every op in
/// How often the bg-log watchdog sweeps background exec logs for size caps
/// (see spawn_bg_log_watchdog).
const BG_LOG_SWEEP: std::time::Duration = std::time::Duration::from_secs(30);

/// Tail size kept when a background exec log is truncated by the watchdog —
/// the same byte budget the relay keeps live (warden.bg_log_tail_bytes), so the
/// watchdog's rewrite and the status tail agree on what "the tail" is.
fn bg_log_tail_bytes() -> u64 {
    crate::AGENT_CONFIG.bg_log_tail_bytes as u64
}

/// Aggregate budget for ALL bg logs together, as a multiple of the per-log
/// cap (warden.max_bg_log_bytes). Between sweeps, N concurrent writers can
/// each grow to the per-log cap — the aggregate bound shrinks every log to
/// its tail in the very next sweep, capping the multi-writer transient at
/// (sweep window × total write rate) + budget instead of N × cap.
const BG_LOG_TOTAL_BUDGET_MULT: u64 = 4;

// ── vsock transport DoS bounds ─────────────────────────────────────────
//
// Every request is authenticated (nonce + HMAC tag over the fixed header,
// verified BEFORE the body is read — see auth.rs), so a peer without the
// per-VM session key cannot reach dispatch or park a body allocation. A peer
// can still reach the accept loop and park a CONNECTION, and an authenticated
// peer (the sandlot, or a compromised sandlot holding the key) can park the
// documented resources. Two resources a peer can park without limit, and the
// one window in which it can stall:
//
//   1. CONNECTIONS: every accepted connection spawned a serving task. Bounded
//      by CONN_COUNT vs MAX_CONNS (16: exec_slots ≤ 5 +
//      short-lived heartbeat probes + reconnect burst headroom). Excess
//      connections are accepted-then-closed — the sandlot slot pool dials
//      lazily and discards broken connections by design, so this only ever
//      affects a peer far beyond legitimate patterns.
//   2. BODY PRE-ALLOCATIONS: read_request pre-allocates `body_len` (≤
//      max_body_len) before read_exact; a peer that sends a valid header and
//      never delivers the body parks the allocation forever. BODY_BUDGET
//      tracks RESERVED bytes across all in-flight reads (reservation released
//      when the request is dropped after dispatch). A parsed request keeps
//      exactly ONE body allocation — fields are byte ranges into it, not
//      copies — so the reservation is an exact bound on the memory a request
//      can hold. Default 6 × max_body_len.
//   3. FIRST-FRAME STALL: a connected peer that sends nothing parks its task
//      until the first frame. The sandlot dials lazily (acquire → dial →
//      request), so a legitimate first frame follows the dial immediately;
//      pooled connections idle BETWEEN requests by design and are never
//      timed out after their first frame.
//
// Latency: all three sit on cold paths (accept, first frame) or cost two
// atomic ops per request (~ns against a µs-ms op) — the per-op hot path is
// untouched.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// Concurrent-connection cap: covers the largest per-VM slot pool
/// (exec_slots = 5 on the large spec) plus short-lived heartbeat probes and
/// reconnect bursts with headroom. A constant, not a knob: the value is
/// derived from system facts (slot-pool size), participates in no
/// cross-component deployment invariant, and a settable bound is one
/// misconfiguration away from "off" in production.
const MAX_CONNS: usize = 16;

/// In-flight body budget, as a multiple of max_body_len. The largest
/// per-VM slot pool (exec_slots = 5 on the large spec) must be able to have
/// every slot's max-size OP_FILE body in flight at once; 4 was one short and
/// made a legal five-way burst fail with WouldBlock (a spurious transport
/// error). 6 keeps that headroom without the 8× worst case exceeding a small
/// VM's RAM. Tracks max_body_len automatically.
const BODY_BUDGET_MAX_BODIES: usize = 6;

/// How long a freshly connected peer may sit before its first frame. The
/// sandlot dials lazily (acquire → dial → request), so legitimate first
/// frames are immediate; 30s is orders of magnitude beyond any legitimate
/// dial-to-frame gap.
const FIRST_FRAME_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
/// Idle bound for an authenticated (post-delivery) connection. Pooled
/// connections are reused between ops, but a connection that sends nothing for
/// this long is released so a local peer cannot park slots forever. Matches the
/// warden countdown scale; the sandlot re-dials on demand.
const POST_DELIVERY_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

/// Currently served connections (incremented at accept, decremented when the
/// serving task ends).
static CONN_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Bytes still available under the global in-flight body budget (initialized
/// once at serve() start to BODY_BUDGET_MAX_BODIES × max_body_len).
static BODY_BUDGET: AtomicUsize = AtomicUsize::new(0);

/// Whether the connection that would bring the count to `count` should be
/// served under cap `cap`. Extracted for unit testing.
fn conn_allowed(count: usize, cap: usize) -> bool {
    count <= cap
}

/// RAII body-budget reservation: subtracts `len` from BODY_BUDGET up front and
/// adds it back on drop (body completed or read failed — either way the
/// pre-allocation is no longer parked mid-read).
struct BodyReservation {
    len: usize,
}

impl BodyReservation {
    /// Reserve `len` budget bytes; None when the budget cannot cover it (the
    /// caller must fail the read — the connection cannot resync mid-body).
    fn acquire(len: usize) -> Option<Self> {
        if len == 0 {
            // Zero-byte bodies allocate nothing.
            return Some(BodyReservation { len: 0 });
        }
        let mut cur = BODY_BUDGET.load(Ordering::Acquire);
        loop {
            if cur < len {
                return None;
            }
            match BODY_BUDGET.compare_exchange_weak(
                cur,
                cur - len,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Some(BodyReservation { len }),
                Err(actual) => cur = actual,
            }
        }
    }
}

impl Drop for BodyReservation {
    fn drop(&mut self) {
        if self.len > 0 {
            BODY_BUDGET.fetch_add(self.len, Ordering::AcqRel);
        }
    }
}

/// Hostile-peer log limiter: cap rejections, first-frame timeouts, budget
/// rejections, and aborted connections repeat at FLOOD rate under attack.
/// Printing each would (a) burn the slog-async drain thread and the serial
/// UART (~83µs/char) contending with the guest's 2 vCPUs, and (b) flood the
/// 128-slot async channel, crowding out the logs that matter (countdown
/// firing, cgroup degradation). The limiter prints the FIRST event of a
/// window immediately, then at most one line per window carrying how many
/// events were suppressed. Window: 60s — an operator needs the edges
/// (attack started / still ongoing / ended), not per-event noise.
const MISBEHAVIOR_LOG_WINDOW_MS: u64 = 60_000;

/// Hostile-peer categories. The limiter is PER CATEGORY: a keyless flooder
/// must not suppress the authentication-failure or connection-cap lines (the
/// ones an operator actually needs).
#[derive(Clone, Copy)]
enum Misbehavior {
    PeerCID,
    ConnCap,
    ConnEnded,
    FirstFrameTimeout,
    KeyNotDelivered,
    AuthFailed,
    BodyBudget,
    BodyMAC,
    HeartbeatNonHost,
}

impl Misbehavior {
    fn idx(self) -> usize {
        self as usize
    }
}

const MISBEHAVIOR_CATEGORIES: usize = 9;

struct MisbehaviorSlot {
    last_ms: AtomicU64,
    suppressed: AtomicU64,
}

static MISBEHAVIOR: [MisbehaviorSlot; MISBEHAVIOR_CATEGORIES] = [const {
    MisbehaviorSlot {
        last_ms: AtomicU64::new(0),
        suppressed: AtomicU64::new(0),
    }
}; MISBEHAVIOR_CATEGORIES];

/// Gate one hostile-peer log line for a category: returns Some(suppressed)
/// when a line should be printed now (the caller includes the suppressed
/// count), None when this event was counted as suppressed. Atomics only —
/// call sites are on the async hot path.
fn misbehavior_gate(category: Misbehavior) -> Option<u64> {
    let slot = &MISBEHAVIOR[category.idx()];
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let mut last = slot.last_ms.load(Ordering::Acquire);
    loop {
        let due = last == 0 || now.saturating_sub(last) >= MISBEHAVIOR_LOG_WINDOW_MS;
        if !due {
            slot.suppressed.fetch_add(1, Ordering::AcqRel);
            return None;
        }
        match slot
            .last_ms
            .compare_exchange_weak(last, now, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => return Some(slot.suppressed.swap(0, Ordering::AcqRel)),
            Err(actual) => last = actual,
        }
    }
}

/// Served-connection guard: decrements CONN_COUNT when the serving task ends.
/// The count was already RESERVED by the accept loop (fetch_add BEFORE the
/// cap decision, rolled back on refuse — see serve): a load-then-check raced
/// the spawned task's increment and could admit a burst past the cap.
struct ConnGuard;

impl ConnGuard {
    /// Adopt the slot reserved by the accept loop (no increment here).
    fn assumed() -> Self {
        ConnGuard
    }
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        CONN_COUNT.fetch_sub(1, Ordering::AcqRel);
    }
}

// Response `code` values — the single field the sandlot client branches on.
// Replaces the former overloaded `i32 status` (which conflated exit codes,
// sentinels, and error classes). exit_code is carried separately as a u8.
pub(crate) const CODE_OK: u8 = 0; // success; for sync exec, exit_code holds the real code
pub(crate) const CODE_APP_ERROR: u8 = 1; // business failure (FileOp ENOENT, MemStats unreadable); VM healthy
pub(crate) const CODE_TRANSPORT_ERROR: u8 = 2; // handler/transport/protocol error; sandlot invalidates the connection
pub(crate) const CODE_BG_RUNNING: u8 = 3; // status_exec: background exec still running
pub(crate) const CODE_BG_KILLED: u8 = 4; // status_exec/kill_exec: killed by the agent
pub(crate) const CODE_BG_NOT_FOUND: u8 = 5; // status_exec/kill_exec: exec_id not in registry
pub(crate) const CODE_TIMED_OUT: u8 = 6; // sync exec exceeded its timeout
pub(crate) const CODE_MOUNT_TARGET_NOT_EXPORTED: u8 = 7; // mount alias not in the current filter generation (VM healthy)
pub(crate) const CODE_UNMOUNT_NOT_MOUNTED: u8 = 8; // unmount idempotent no-op (nothing was mounted)
pub(crate) const CODE_UNMOUNT_MISMATCH: u8 = 9; // unmount identity differs from the live mount; nothing torn down

// Maximum request body size is configurable via AgentConfig.max_body_len
// (kernel cmdline warden.max_body_len / env MAX_BODY_LEN, default 16 MiB).
// Bounds a single OP_FILE WRITE data payload and any request body, preventing
// a malformed frame from triggering a multi-GB allocation. Kept in lockstep
// with max_file_read_bytes so read and write single-op caps are uniform.

/// Serve the raw vsock protocol until the VM shuts down. Binds VMADDR_CID_ANY
/// on `port` and accepts connections one at a time; each connection is served
/// inline (request -> dispatch -> response) until EOF, then we re-accept.
pub async fn serve(sandbox: Arc<Mutex<Sandbox>>, port: u32) -> Result<()> {
    // The per-VM key is delivered over the first host vsock connection
    // (OP_KEY_DELIVERY) and is never taken from the kernel command line. Until
    // it arrives the warden listens but serves nothing: every non-delivery op
    // is refused while the key is absent (fail closed).
    if crate::auth::session_key().is_none() {
        println!("raw vsock server awaiting session-key delivery from the host");
    }

    let mut listener = VsockListener::bind(VsockAddr::new(VMADDR_CID_ANY, port))
        .map_err(|e| anyhow::anyhow!("bind vsock {} failed: {}", port, e))?;
    println!("raw vsock server listening on port {}", port);

    // Start the warden countdown (single countdown: heartbeat-anchored
    // last-resort mount release).
    spawn_warden_countdown(sandbox.clone());

    // Start the bg-log watchdog (bounds runaway background exec log growth on
    // the RAM-backed initramfs rootfs).
    {
        let s = sandbox.lock().await;
        spawn_bg_log_watchdog(s.bg_execs.clone());
    }

    // Initialize the in-flight body budget once: BODY_BUDGET_MAX_BODIES ×
    // the configured max_body_len (tracks the 16 MB chain automatically).
    BODY_BUDGET.store(
        crate::AGENT_CONFIG
            .max_body_len
            .saturating_mul(BODY_BUDGET_MAX_BODIES),
        Ordering::Release,
    );

    // Accept-error backoff: a persistent accept failure (EMFILE, ENODEV, ...)
    // must not turn the accept loop into a hot spin that floods the log and
    // burns CPU. Doubles from 100ms up to 5s; reset on the next success.
    let mut accept_backoff = std::time::Duration::from_millis(100);
    const ACCEPT_BACKOFF_MAX: std::time::Duration = std::time::Duration::from_secs(5);

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                // Transient accept errors are logged and retried; the listener
                // stays open. A persistent failure would loop here logging,
                // which is preferable to tearing down PID 1 — but with backoff.
                slog_scope::error!(
                    "raw_server: accept failed: {} (retrying in {:?})",
                    e,
                    accept_backoff
                );
                tokio::time::sleep(accept_backoff).await;
                accept_backoff = std::cmp::min(accept_backoff * 2, ACCEPT_BACKOFF_MAX);
                continue;
            }
        };
        accept_backoff = std::time::Duration::from_millis(100);
        // Peer gate: only the HOST may speak the warden protocol. The sandlot
        // — and every host-side probe tool — connects from CID 2, the same
        // hypervisor-assigned fact the heartbeat gate relies on. With the
        // shipped guest kernel an in-guest process cannot even reach the port
        // (no vsock loopback transport; a cross-VM packet is dropped by
        // vhost-vsock before it reaches this listener), but those are
        // kernel-config facts, not designed controls: this gate makes the
        // refusal the warden's own semantics, so a kernel/build drift
        // (CONFIG_VSOCKETS_LOOPBACK=y, a userspace vsock backend that routes
        // guest→guest) can never silently re-expose the raw protocol —
        // including the empty-identity warm-op path — to in-guest peers. One
        // integer compare per accept, never on the request path.
        let peer_cid = peer.cid();
        if !peer_allowed(peer_cid) {
            if let Some(supp) = misbehavior_gate(Misbehavior::PeerCID) {
                slog_scope::warn!(
                    "raw_server: refusing non-host peer cid={} — only the sandlot may speak the warden protocol (+{} suppressed)",
                    peer_cid, supp
                );
            }
            drop(stream);
            continue;
        }
        // Connection cap (DoS bound, see the statics above). The slot is
        // reserved with fetch_add BEFORE the decision (rolled back on refuse)
        // so the accounting is exact under a reconnect burst — the old
        // load-then-check raced the spawned task's ConnGuard increment.
        // Accepted-then-closed: the sandlot treats an immediate close as a
        // transport error, discards the connection, and re-dials — only a
        // peer far beyond legitimate patterns (slots + probes + burst) ever
        // sees it.
        let count = CONN_COUNT.fetch_add(1, Ordering::AcqRel) + 1;
        if !conn_allowed(count, MAX_CONNS) {
            CONN_COUNT.fetch_sub(1, Ordering::AcqRel); // release the refused slot
            if let Some(supp) = misbehavior_gate(Misbehavior::ConnCap) {
                slog_scope::warn!(
                    "raw_server: connection cap {} reached; closing excess connections (+{} suppressed)",
                    MAX_CONNS, supp
                );
            }
            drop(stream); // close immediately
            continue;
        }
        // Serve each connection concurrently. The sandlot's per-VM slot pool
        // (one in-flight request per connection, parallel sync execs across
        // slots) and the heartbeat probe connections (a fresh short-lived
        // connection per sandlot probe) can all be accepted and served in
        // parallel — a long sync exec on one slot never blocks the probe's
        // MemStats or another slot's exec. Concurrent ops on one VM are
        // guarded in-warden by the sandbox::MOUNT_GATE gate.
        let sb = sandbox.clone();
        tokio::spawn(async move {
            let _conn_guard = ConnGuard::assumed();
            if let Err(e) = handle_connection(stream, peer_cid, sb).await {
                // Hostile peers produce these at flood rate (malformed frames
                // etc.); legit sandlot teardown is EOF (Ok path, silent). The
                // warden-side suppression loses nothing operationally: the
                // sandlot logs its own dial/transport failures.
                if let Some(supp) = misbehavior_gate(Misbehavior::ConnEnded) {
                    slog_scope::error!(
                        "raw_server: connection ended: {} (+{} suppressed)",
                        e,
                        supp
                    );
                }
            }
        });
    }
}

async fn handle_connection(
    mut stream: VsockStream,
    peer_cid: u32,
    sandbox: Arc<Mutex<Sandbox>>,
) -> Result<()> {
    // First-frame timeout (DoS bound): a freshly connected peer must send its
    // first frame within the configured window. The sandlot dials lazily
    // (acquire → dial → request), so legitimate first frames are immediate;
    // POOLED connections are deliberately NOT limited between requests —
    // they idle by design between ops.
    let fft = FIRST_FRAME_TIMEOUT;
    let mut first = true;
    // Delivery is a one-shot handshake: a failed delivery (bad key, non-host
    // peer, malformed body) closes the connection instead of leaving an
    // unauthenticated slot parked forever, and a second delivery on the same
    // connection is refused. This is what lets a host-local process hold at
    // most one slot per attempt instead of 16 forever.
    let mut key_delivery_seen = false;
    loop {
        let read_fut = read_request(&mut stream);
        let req = if first {
            first = false;
            match tokio::time::timeout(fft, read_fut).await {
                Ok(r) => r,
                Err(_) => {
                    if let Some(supp) = misbehavior_gate(Misbehavior::FirstFrameTimeout) {
                        slog_scope::warn!(
                            "raw_server: peer sent no frame within {:?}; closing (+{} suppressed)",
                            fft,
                            supp
                        );
                    }
                    return Ok(());
                }
            }
        } else {
            // Authenticated connections are idle between ops by design, but
            // "idle forever" would let one local peer park every slot. A
            // silent connection past the bound is closed; the sandlot dials
            // again on the next op.
            match tokio::time::timeout(POST_DELIVERY_IDLE_TIMEOUT, read_fut).await {
                Ok(r) => r,
                Err(_) => return Ok(()),
            }
        };
        let req = match req {
            Ok(r) => r,
            // sandlot closed the cached connection (VM destroy) — clean EOF, no
            // release action (release is governed by the countdown, which fires
            // only on a live mount + heartbeat silence).
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            // Budget rejection (see read_request): already reported at
            // bounded rate; close silently.
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(()),
            Err(e) => return Err(e.into()),
        };
        // Negotiated echo: the warden answers in the version the peer sent
        // (see Response::version). The out-of-range rejection in read_request
        // keeps OUR version instead, so an exact-match client still classifies
        // it as a version mismatch.
        let req_version = req.version;
        let req_nonce = req.nonce;
        let op = req.op;
        let mut resp = dispatch(&sandbox, req, peer_cid).await;
        resp.version = req_version;
        if let Err(e) = write_response(&mut stream, &resp, &req_nonce).await {
            return Err(e.into());
        }
        if op == OP_KEY_DELIVERY {
            if delivery_connection_done(key_delivery_seen, resp.code) {
                return Ok(());
            }
            key_delivery_seen = true;
        }
    }
}

/// Whether an OP_KEY_DELIVERY response ends the connection: a SECOND delivery
/// (one-shot handshake) or a FAILED install leaves no reason to keep the slot.
fn delivery_connection_done(seen_before: bool, code: u8) -> bool {
    seen_before || code != CODE_OK
}

/// Dispatch rule: only the heartbeat op (OP_MEM_STATS) resets the countdown
/// anchor. Business RPCs (mount/exec/unmount/file) deliberately do NOT — they
/// must not mask a silent sandlot (the cached connection can be wedged while
/// heartbeats, sent on separate probe connections, keep flowing). Extracted as
/// a pure function for unit testing.
fn heartbeat_op(op: u8) -> bool {
    op == OP_MEM_STATS
}

/// Whether `cid` may speak the warden protocol at all: only the host. The
/// accept-time gate in serve() enforces it for every connection (and the
/// heartbeat's own CID check below stays as defense in depth). Extracted as
/// a pure function for unit testing, mirroring heartbeat_resets_countdown.
fn peer_allowed(cid: u32) -> bool {
    cid == VMADDR_CID_HOST
}

/// Whether this op from this peer resets the countdown anchor.
///
/// The anchor means "the SANSLOT is alive" — the sandlot is a host process,
/// so only a heartbeat arriving over a connection FROM THE HOST may reset
/// it. This is the one op with a VM-wide side effect: a reset from inside
/// the guest would keep a mount alive past the last-resort release, and
/// once the platform re-places the sandfs that is a double mount (see
/// docs/how-it-works/isolation-and-swap.md, "The warden's vsock port").
/// The shipped guest kernel cannot even make such a connection (no vsock
/// loopback transport — a guest's connect() to its own CID fails ENODEV),
/// so this gate is defense in depth for a kernel/config change; it costs
/// one integer compare. Extracted as a pure function for unit testing.
fn heartbeat_resets_countdown(op: u8, peer_cid: u32) -> bool {
    heartbeat_op(op) && peer_cid == VMADDR_CID_HOST
}

/// countdown_expired reports whether the warden countdown has passed: no
/// heartbeat for warden_countdown. Extracted as a pure function for testing.
fn countdown_expired(
    last_heartbeat: Instant,
    now: Instant,
    warden_countdown: std::time::Duration,
) -> bool {
    now.duration_since(last_heartbeat) > warden_countdown
}

/// should_exit_vm is the countdown decision: heartbeat silence longer than
/// warden_countdown AND a SandFS is still mounted (not unmounted) → power off
/// the VM to force-release the mount. If the SandFS was already unmounted
/// (mount_active false) the countdown is a no-op: a clean VM must survive so
/// the sandlot can reuse it — there is no live mount to release, so exiting
/// would only waste a warm VM. This is the explicit "only when there's a
/// SandFS that hasn't been unmounted" guard.
fn should_exit_vm(
    last_heartbeat: Instant,
    now: Instant,
    mount_active: bool,
    warden_countdown: std::time::Duration,
) -> bool {
    countdown_expired(last_heartbeat, now, warden_countdown) && mount_active
}

/// spawn_warden_countdown runs the single countdown: every tick, if no heartbeat
/// has arrived within warden_countdown and a SandFS is still mounted, power off
/// the VM to force-release the sandfs mount. This is the last-resort release
/// that bounds the mount-clearing window at T_tolerance + T_warden regardless of
/// sandlot / gateway state.
fn spawn_warden_countdown(sandbox: Arc<Mutex<Sandbox>>) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(COUNTDOWN_TICK);
        tick.tick().await; // skip the immediate first tick
        loop {
            tick.tick().await;
            // mount_active is the authoritative "is a SandFS mounted right now?"
            // signal — set true on mount, false on unmount. The countdown only
            // fires when a mount is live; an already-unmounted (clean) VM is
            // left alone. See Sandbox::mount_active.
            let (last_heartbeat, mount_active) = {
                let s = sandbox.lock().await;
                (s.last_heartbeat, s.mount_active)
            };
            // The countdown must never write bookkeeping into the mounted
            // SandFS or the shared /mnt/volumes virtio-fs export — those are
            // agent-owned persistent storage. Diagnostics go to the global
            // slog logger (forwarded to the vsock log port or stderr fallback).
            let wc = crate::AGENT_CONFIG.warden_countdown;
            if should_exit_vm(last_heartbeat, Instant::now(), mount_active, wc) {
                slog_scope::error!(
                    "warden countdown expired with a live mount; powering off VM to force-release"
                );
                // Power off the VM via ACPI so the virtio-fs connection drops and
                // the mount is released (the design's "mount dies with the VM").
                // NB: std::process::exit(1) would only kill PID 1 → kernel panic
                // ("Attempted to kill init") → the VM HANGS, not exits: sandvmm
                // stays alive and the sandfs mount stays stuck. reboot(POWER_OFF)
                // actually terminates the VM, so sandvmm exits and the host can
                // reclaim the sandfs. This mirrors the normal shutdown path
                // (main.rs). Fallback to exit(1) only if the reboot syscall
                // returns (it never should on success).
                let _ = unsafe { libc::reboot(libc::LINUX_REBOOT_CMD_POWER_OFF) };
                std::process::exit(1);
            }
        }
    });
}

struct Request {
    op: u8,
    /// The protocol version the request carried — echoed back on the response
    /// (negotiated echo, see Response::version).
    version: u8,
    /// The per-request nonce that authenticated this frame. The response tag is
    /// bound to it, so only the client that issued this request can accept the
    /// response.
    nonce: [u8; NONCE_LEN],
    /// Keyed MAC over the op-specific body fields the header tag cannot see
    /// (the warm-op mounted-volume identity, or a cold mount's
    /// alias/mount_point/volume_mode). Verified after the body is parsed.
    body_mac: [u8; BODY_MAC_LEN],
    /// The request body exactly as read off the wire. Field views are byte
    /// ranges into this buffer (`field_spans`), never copies: the request
    /// holds ONE body allocation, so the in-flight budget below accounts for
    /// its memory exactly.
    body: Vec<u8>,
    /// Byte ranges of the length-prefixed fields inside `body`, in wire
    /// order. Parsing produced these ranges; they are always in bounds and
    /// never overlap.
    field_spans: Vec<std::ops::Range<usize>>,
    /// The in-flight body budget reservation. Held until this request (and
    /// its body) is dropped at the end of dispatch, so the budget bounds the
    /// memory of requests being processed — not just bodies parked mid-read.
    _budget: Option<BodyReservation>,
}

impl Request {
    /// Raw bytes of field `i` (empty slice when absent). Allocation-free.
    fn field_bytes(&self, i: usize) -> &[u8] {
        self.field_spans
            .get(i)
            .map(|span| &self.body[span.clone()])
            .unwrap_or(&[])
    }
}

struct Response {
    /// Protocol version stamped into the response header. NEGOTIATED ECHO:
    /// handle_connection sets this to the REQUEST's version, so the client
    /// always sees the version it sent (the window is [1,1] today). The
    /// out-of-range REJECTION frame deliberately keeps OUR version instead
    /// (see read_request): a peer must classify it as a version mismatch and
    /// fail fast, not retry forever against an incompatible warden.
    version: u8,
    /// Response category (CODE_*). The single field the sandlot client branches
    /// on: CODE_TRANSPORT_ERROR invalidates the cached connection; CODE_APP_ERROR
    /// is a business failure with a healthy VM; CODE_OK carries success (and, for
    /// sync exec, the real exit code in `exit_code`).
    code: u8,
    /// Process exit code for sync exec on CODE_OK (0–255, 128+signum for signal
    /// death). 0 for all other ops and for non-OK codes.
    exit_code: u8,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    /// Mounted-volume identity (basename, e.g. "sf-a51f3c2d9e...") — the exclusive-
    /// ownership assertion the sandlot cross-checks. Non-empty ONLY on
    /// successful MOUNT-family ops (OP_MOUNT_AND_EXEC including mount-only,
    /// OP_MOUNT_AND_ASYNC_EXEC): "this op left <basename> mounted at
    /// /mnt/rootfs". Empty on every other op and on every error response, so
    /// the sandlot's assert (== basename of the path it requested) detects a
    /// twisted warden mount state even when the op otherwise claims success.
    mounted: Vec<u8>,
    /// Monotonic wall time in nanoseconds of the operation this response closes.
    /// For the warm sync exec (OP_EXEC) this is spawn-to-wait; for the cold
    /// combined op (OP_MOUNT_AND_EXEC) it is the WARDEN-SIDE TOTAL (mount +
    /// exec), so latency stats attribute the in-guest mount to warden
    /// (sandlot_duration_ns − exec_duration_ns is then sandlot proc + set-fs +
    /// vsock); for OP_UNMOUNT it is the unmount_workspace wall time
    /// (cgroup.kill + teardown + umount + drop_caches). 0 for all other ops
    /// and for error responses.
    exec_duration_ns: u64,
}

impl Response {
    fn ok() -> Self {
        Response {
            version: PROTOCOL_VERSION,
            code: CODE_OK,
            exit_code: 0,
            stdout: Vec::new(),
            stderr: Vec::new(),
            mounted: Vec::new(),
            exec_duration_ns: 0,
        }
    }
    /// ok_exec is CODE_OK with a real process exit code (sync exec done path).
    fn ok_exec(exit_code: u8, stdout: Vec<u8>, stderr: Vec<u8>, exec_duration_ns: u64) -> Self {
        Response {
            version: PROTOCOL_VERSION,
            code: CODE_OK,
            exit_code,
            stdout,
            stderr,
            mounted: Vec::new(),
            exec_duration_ns,
        }
    }
    /// ok_timed is Response::ok with a measured wall time. Used by OP_UNMOUNT so
    /// sandlot can thread the warden-side unmount latency up to the gateway stats
    /// recorder (mirroring exec_duration_ns on the exec path).
    fn ok_timed(exec_duration_ns: u64) -> Self {
        Response {
            version: PROTOCOL_VERSION,
            code: CODE_OK,
            exit_code: 0,
            stdout: Vec::new(),
            stderr: Vec::new(),
            mounted: Vec::new(),
            exec_duration_ns,
        }
    }
    /// Transport/handler/protocol error. The sandlot client treats this as a
    /// TransportError: it invalidates the cached vsock connection and re-dials.
    /// The message goes into stderr.
    fn err(what: &str, e: impl std::fmt::Display) -> Self {
        Response {
            version: PROTOCOL_VERSION,
            code: CODE_TRANSPORT_ERROR,
            exit_code: 0,
            stdout: Vec::new(),
            stderr: format!("{}: {}", what, e).into_bytes(),
            mounted: Vec::new(),
            exec_duration_ns: 0,
        }
    }
    /// Application-level error (e.g., FileOp ENOENT/EACCES, MemStats unreadable).
    /// CODE_APP_ERROR signals "operation failed but the transport/VM is healthy" —
    /// the caller should NOT release the VM, only CODE_TRANSPORT_ERROR triggers
    /// that. The message goes into stdout so the gateway can relay it to the
    /// client as a structured error.
    fn app_err(what: &str, e: impl std::fmt::Display) -> Self {
        Response {
            version: PROTOCOL_VERSION,
            code: CODE_APP_ERROR,
            exit_code: 0,
            stdout: format!("{}: {}", what, e).into_bytes(),
            stderr: Vec::new(),
            mounted: Vec::new(),
            exec_duration_ns: 0,
        }
    }
    /// Application-level error with an explicit code (mount/unmount
    /// generation outcomes): the transport and VM stay healthy, so the
    /// sandlot must not discard the connection.
    fn app_code(code: u8, what: &str, e: impl std::fmt::Display) -> Self {
        Response {
            version: PROTOCOL_VERSION,
            code,
            exit_code: 0,
            stdout: format!("{}: {}", what, e).into_bytes(),
            stderr: Vec::new(),
            mounted: Vec::new(),
            exec_duration_ns: 0,
        }
    }
}

/// Read one request frame: [u32 magic][u8 version][u8 op][u32 body_len][body],
/// where body is a sequence of [u32 len][bytes] fields.
async fn read_request(stream: &mut VsockStream) -> std::io::Result<Request> {
    // Read the 10-byte base header first, so an out-of-range version can be
    // answered in the version the peer understands before the authenticated
    // header (whose layout that peer does not share) is consumed.
    let mut hdr = [0u8; REQ_BASE_HEADER_LEN];
    stream.read_exact(&mut hdr).await?;
    let magic = u32::from_be_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
    if magic != MAGIC {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("bad magic 0x{:x}", magic),
        ));
    }
    let version = hdr[4];
    if !version_supported(version) {
        // Answer with ONE transport-error frame carrying our supported range,
        // then fail the read (handle_connection closes). A bare close would
        // leave the sandlot client with a generic EOF; this way the operator
        // sees "warden speaks [1,1], request was 2" — an actionable deploy
        // mismatch, not a mystery transport flap. The nonce is zero here: the
        // peer cannot be a supported client, and the supported client checks
        // the version byte before the tag.
        let _ = write_response(
            stream,
            &Response::err(
                "protocol version",
                format!(
                    "request version {} unsupported; this warden speaks [{},{}] (redeploy sandlot + initramfs together)",
                    version, PROTOCOL_MIN_ACCEPTED, PROTOCOL_VERSION
                ),
            ),
            &[0u8; NONCE_LEN],
        )
        .await;
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "unsupported protocol version {} (supported [{},{}])",
                version, PROTOCOL_MIN_ACCEPTED, PROTOCOL_VERSION
            ),
        ));
    }
    let op = hdr[5];
    let body_len = u32::from_be_bytes([hdr[6], hdr[7], hdr[8], hdr[9]]) as usize;
    let max_body_len = crate::AGENT_CONFIG.max_body_len;
    if body_len > max_body_len {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "request too large: {} bytes (max {})",
                body_len, max_body_len
            ),
        ));
    }

    // Authenticate the fixed header BEFORE reading or reserving memory for the
    // body. A peer without the per-VM key therefore cannot even park a body,
    // and a tampered op/length/nonce is refused before dispatch.
    //
    // KEY_DELIVERY is the one exception: the warden has no key yet on the
    // first connection, so its request tag cannot be checked. The op is
    // accepted only from the host CID (dispatch re-checks), carries exactly
    // one 32-byte field, and the response is tagged with the delivered key
    // (or the already-installed key on an idempotent re-delivery), which
    // authenticates the warden to the sandlot.
    let mut auth = [0u8; REQ_HEADER_LEN - REQ_BASE_HEADER_LEN];
    stream.read_exact(&mut auth).await?;
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&auth[..NONCE_LEN]);
    let mut body_mac = [0u8; BODY_MAC_LEN];
    body_mac.copy_from_slice(&auth[NONCE_LEN..NONCE_LEN + BODY_MAC_LEN]);
    let header_tag = &auth[NONCE_LEN + BODY_MAC_LEN..];
    if op != OP_KEY_DELIVERY {
        let key = crate::auth::session_key().ok_or_else(|| {
            if let Some(supp) = misbehavior_gate(Misbehavior::KeyNotDelivered) {
                slog_scope::warn!(
                    "raw_server: op {} before session-key delivery; closing (+{} suppressed)",
                    op, supp
                );
            }
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "warden session key not delivered yet",
            )
        })?;
        let expected =
            crate::auth::request_tag(&key, version, op, body_len as u32, &nonce, &body_mac);
        if !crate::auth::ct_eq(header_tag, &expected) {
            if let Some(supp) = misbehavior_gate(Misbehavior::AuthFailed) {
                slog_scope::warn!(
                    "raw_server: request authentication failed (wrong or missing per-VM key); closing connection (+{} suppressed)",
                    supp
                );
            }
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "request authentication failed",
            ));
        }
    }

    // In-flight body budget (DoS bound, see BODY_BUDGET): reserve before the
    // pre-allocation. The reservation is moved into the Request and released
    // when dispatch drops it, so it bounds both parked reads and the ONE body
    // allocation an in-flight request holds (fields are ranges into it, not
    // copies).
    let budget = BodyReservation::acquire(body_len).ok_or_else(|| {
        if let Some(supp) = misbehavior_gate(Misbehavior::BodyBudget) {
            slog_scope::warn!(
                "raw_server: in-flight body budget exhausted ({} bytes requested) (+{} suppressed)",
                body_len,
                supp
            );
        }
        std::io::Error::new(
            // WouldBlock is only ever produced HERE in read_request (tokio's
            // read_exact surfaces EAGAIN internally, never as WouldBlock) —
            // handle_connection closes such connections SILENTLY: the warn
            // above already reported the event at bounded rate.
            std::io::ErrorKind::WouldBlock,
            "in-flight body budget exhausted",
        )
    })?;
    let mut body = vec![0u8; body_len];
    stream.read_exact(&mut body).await?;

    let field_spans = parse_field_spans(&body)?;
    let req = Request {
        op,
        version,
        nonce,
        body_mac,
        body,
        field_spans,
        _budget: Some(budget),
    };
    verify_body_mac(&req)?;
    Ok(req)
}

/// Field indices whose bytes are bound by the op-specific body MAC (absent
/// entries mean "empty"). The mount/identity fields are the ones a compromised
/// guest kernel could otherwise rewrite to redirect a mount or execute against
/// a different tenant's volume.
fn body_mac_fields(op: u8) -> Option<[usize; 3]> {
    match op {
        OP_EXEC => Some([IDX_EXEC_VOLUME, usize::MAX, usize::MAX]),
        OP_ASYNC_EXEC => Some([IDX_ASYNC_EXEC_VOLUME, usize::MAX, usize::MAX]),
        OP_FILE => Some([IDX_FILE_VOLUME, usize::MAX, usize::MAX]),
        OP_MOUNT_AND_EXEC => Some([0, 1, 6]),
        OP_MOUNT_AND_ASYNC_EXEC => Some([0, 1, 5]),
        OP_UNMOUNT => Some([0, 1, 2]),
        _ => None,
    }
}

fn verify_body_mac(req: &Request) -> std::io::Result<()> {
    // KEY_DELIVERY (and every op with no bound field) must pass WITHOUT a key:
    // the delivery itself arrives before any key exists.
    if body_mac_fields(req.op).is_none() {
        return Ok(());
    }
    let key = crate::auth::session_key().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "warden session key not delivered yet",
        )
    })?;
    // body_mac_fields only ever names indices 0..=MAX_BODY_MAC_FIELD; a
    // fixed array keeps this allocation-free on the exec hot path.
    let mut fields: [&[u8]; MAX_BODY_MAC_FIELD + 1] = [&[]; MAX_BODY_MAC_FIELD + 1];
    for (i, slot) in fields.iter_mut().enumerate() {
        *slot = req.field_bytes(i);
    }
    verify_body_mac_with_key(&key, req.op, &fields, &req.nonce, &req.body_mac)
}

/// Highest field index `body_mac_fields` binds. The array in
/// `verify_body_mac` is sized to cover exactly the fields the MAC can name.
const MAX_BODY_MAC_FIELD: usize = 6;

/// Verify the op-specific body MAC over the named field slices. Indices
/// beyond the supplied slice fall back to the empty slice (the same semantics
/// the wire had when absent fields were simply missing).
fn verify_body_mac_with_key(
    key: &[u8],
    op: u8,
    fields: &[&[u8]],
    nonce: &[u8; NONCE_LEN],
    body_mac: &[u8; BODY_MAC_LEN],
) -> std::io::Result<()> {
    let Some(indices) = body_mac_fields(op) else {
        return Ok(());
    };
    let empty: &[u8] = &[];
    let get = |i: usize| -> &[u8] {
        if i == usize::MAX {
            empty
        } else {
            fields.get(i).copied().unwrap_or(empty)
        }
    };
    let expected = crate::auth::body_mac(
        key,
        nonce,
        op,
        &[get(indices[0]), get(indices[1]), get(indices[2])],
    );
    if !crate::auth::ct_eq(body_mac, &expected) {
        if let Some(supp) = misbehavior_gate(Misbehavior::BodyMAC) {
            slog_scope::warn!(
                "raw_server: request body authentication failed (mount/identity field rewritten); closing connection (+{} suppressed)",
                supp
            );
        }
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "request body authentication failed",
        ));
    }
    Ok(())
}

/// Write one response frame (60-byte header):
/// [u32 magic][u8 version][u8 code][u8 exit_code][u8 reserved][u32 stdout_len][u32 stderr_len][u64 exec_duration_ns][u32 mounted_len][u8 tag[32]][stdout][stderr][mounted][mounted_mac[32]]
///
/// The trailing mounted_mac is a keyed MAC over the mounted bytes, bound to the
/// request nonce: the header tag authenticates the mounted LENGTH before any
/// body is read, and this MAC authenticates the mounted CONTENT before the
/// caller trusts the exclusive-ownership assertion.
///
/// Uses writev (write_vectored) so the header + body sections are emitted in
/// a single syscall with NO intermediate buffer concatenation — the
/// stdout/stderr Vec<u8> from drain_pipe are referenced in-place.
/// Encode the 60-byte response header into a fixed array. Extracted from
/// write_response so the wire layout can be unit-tested without a vsock stream.
/// The tag is HMAC-SHA256 over the fixed fields above and the request nonce,
/// keyed by the per-VM session key; the sandlot refuses a response whose tag
/// does not verify.
fn encode_response_header(resp: &Response, nonce: &[u8; NONCE_LEN]) -> [u8; RESP_HEADER_LEN] {
    let mut hdr = [0u8; RESP_HEADER_LEN];
    hdr[0..4].copy_from_slice(&MAGIC.to_be_bytes());
    hdr[4] = resp.version;
    hdr[5] = resp.code;
    hdr[6] = resp.exit_code;
    hdr[7] = 0; // reserved
    let stdout_len = resp.stdout.len() as u32;
    let stderr_len = resp.stderr.len() as u32;
    let mounted_len = resp.mounted.len() as u32;
    hdr[8..12].copy_from_slice(&stdout_len.to_be_bytes());
    hdr[12..16].copy_from_slice(&stderr_len.to_be_bytes());
    hdr[16..24].copy_from_slice(&resp.exec_duration_ns.to_be_bytes());
    hdr[24..28].copy_from_slice(&mounted_len.to_be_bytes());
    let key = crate::auth::session_key().unwrap_or([0u8; 32]);
    let tag = crate::auth::response_tag(
        &key,
        nonce,
        resp.version,
        resp.code,
        resp.exit_code,
        stdout_len,
        stderr_len,
        resp.exec_duration_ns,
        mounted_len,
    );
    hdr[RESP_BASE_HEADER_LEN..RESP_HEADER_LEN].copy_from_slice(&tag);
    hdr
}

async fn write_response(
    stream: &mut VsockStream,
    resp: &Response,
    nonce: &[u8; NONCE_LEN],
) -> std::io::Result<()> {
    let hdr = encode_response_header(resp, nonce);
    // Keyed MAC over the mounted identity CONTENT (the header tag covers only
    // its length). The key delivery path installs the key before responding,
    // so the empty mounted MAC there is keyed with the delivered key too.
    let key = crate::auth::session_key().unwrap_or([0u8; 32]);
    let mounted_mac = crate::auth::mounted_tag(&key, nonce, &resp.mounted);

    use std::io::IoSlice;
    // Scatter the header + body sections in one writev syscall, no copy
    // into a single buffer. vsock frames are small and the kernel writes them
    // atomically in practice; if it ever returns a partial write, fall back to
    // a single concatenated write_all for the remainder.
    // Empty sections are skipped entirely (an empty iovec is legal but
    // pointless); the mounted MAC is always present, and the partial-write
    // fallback below walks the same order.
    let mut bufs = vec![IoSlice::new(&hdr), IoSlice::new(&resp.stdout)];
    if !resp.stderr.is_empty() {
        bufs.push(IoSlice::new(&resp.stderr));
    }
    if !resp.mounted.is_empty() {
        bufs.push(IoSlice::new(&resp.mounted));
    }
    bufs.push(IoSlice::new(&mounted_mac));
    let total =
        RESP_HEADER_LEN + resp.stdout.len() + resp.stderr.len() + resp.mounted.len() + TAG_LEN;
    let n = stream.write_vectored(&bufs).await?;
    if n < total {
        // Partial write (rare on vsock): concatenate the unwritten tail and
        // send it with write_all. Walk the segments skipping `n` written bytes.
        let segments: [&[u8]; 5] =
            [&hdr, &resp.stdout, &resp.stderr, &resp.mounted, &mounted_mac];
        let mut combined = Vec::with_capacity(total - n);
        let mut skip = n;
        for seg in segments {
            if skip >= seg.len() {
                skip -= seg.len();
                continue;
            }
            combined.extend_from_slice(&seg[skip..]);
            skip = 0;
        }
        stream.write_all(&combined).await?;
    }
    Ok(())
}

fn field(req: &Request, i: usize) -> String {
    String::from_utf8_lossy(req.field_bytes(i)).into_owned()
}

/// Raw bytes of field `i` (empty slice when absent) — the allocation-free twin
/// of `field()` for the mounted-volume identity comparison, which sits on the
/// warm exec/file hot path. Invalid UTF-8 is deliberately NOT replaced: the
/// identity is compared byte-for-byte against a known-good basename, so a
/// lossy conversion could only ever turn a mismatch into… still a mismatch,
/// at the cost of an allocation.
fn field_bytes(req: &Request, i: usize) -> &[u8] {
    req.field_bytes(i)
}

/// Protocol hardening: the warden only ever mounts/unmounts the single fixed
/// workspace mount point. Processes inside the guest can open their own vsock
/// connection to this server (documented in docs/how-it-works/threat-model.md
/// "vsock channel security" — seccomp does not block socket/connect), so the
/// wire's mount_point is attacker-reachable. An arbitrary mount_point would
/// let a hostile agent bind its own volume (allowed_dirs still permits it)
/// over warden-critical guest paths — e.g. /sys/fs/cgroup, which would
/// silently defeat the per-agent cgroup memory cap AND the cgroup.kill
/// agent-switch clearing (the exclusive-ownership invariant) — or umount the
/// warden's own /proc. The sandlot always sends MOUNT_POINT exactly
/// ("/mnt/rootfs", see sandlot/core/commands.go), so pinning is wire-compatible.
/// Extracted as a pure function for unit testing.
fn validate_mount_point(mp: &str) -> bool {
    mp == crate::mount::MOUNT_POINT
}

/// Mount-only request: an OP_MOUNT_AND_EXEC whose command is EMPTY asks the
/// warden to establish the mount and nothing else (the cold FileOp path —
/// sandlot's ensureMounted; see the dispatch branch). Whitespace is NOT
/// mount-only: a blank-but-nonempty string is still a real shell command.
/// Extracted as a pure function so the semantics boundary is unit-testable.
fn is_mount_only(command: &str) -> bool {
    command.is_empty()
}

/// The identity record's volume mode. The warden mounts according to this
/// value and NEVER probes the volume's on-disk layout: a flat volume is agent-
/// writable, so a planted `rootfs/` directory must not be able to choose
/// overlay semantics for the next mount. Empty/unknown is refused (the field
/// ships with the protocol; there is no legacy window to keep).
fn validate_volume_mode(mode: &str) -> bool {
    mode == "flat" || mode == "overlay"
}

/// Standard rejection for an invalid/absent volume_mode. TRANSPORT_ERROR:
/// the peer violated the protocol record contract.
fn volume_mode_rejected() -> Response {
    Response::err(
        "volume_mode",
        anyhow::anyhow!("volume_mode must be exactly \"flat\" or \"overlay\" (record-driven mount)"),
    )
}

/// Standard rejection for a mount request whose alias is absent or invalid.
/// TRANSPORT_ERROR: the peer violated the generation contract. There is no
/// constant-alias fallback — a missing alias must never mount anything.
fn export_alias_rejected() -> Response {
    Response::err(
        "alias",
        anyhow::anyhow!(
            "alias must be one component of [A-Za-z0-9._-], 1..=64 bytes, not . or .. (per-generation mount identity)"
        ),
    )
}

/// Standard rejection response for a mount_point that fails
/// validate_mount_point. TRANSPORT_ERROR: the peer violated the protocol.
/// Whether an unmount frame has NOTHING to detach. A failed mount leaves
/// mount_active=false with a possible partial stack behind, so the forced
/// (re-adopt/dirty cleanup) path must run the teardown whenever the dirty
/// marker is set — mount_active alone does not prove the guest is clean.
fn unmount_has_nothing_to_do(active: bool, dirty: bool) -> bool {
    // A failed mount can leave mount_active=false with a partial stack behind;
    // only "no active mount AND no recorded dirty state" is a no-op. The
    // forced flag selects the teardown path, not whether dirty work remains.
    !active && !dirty
}

fn mount_point_rejected() -> Response {
    Response::err(
        "mount_point",
        anyhow::anyhow!(
            "mount_point must be exactly {} (protocol hardening)",
            crate::mount::MOUNT_POINT
        ),
    )
}

async fn dispatch(sandbox: &Arc<Mutex<Sandbox>>, mut req: Request, peer_cid: u32) -> Response {
    // Hold the sandbox lock only long enough to clone the logger + agent cgroup
    // path; do NOT hold it across mount/exec (mount_workspace takes its own
    // locks, do_exec spawns a child + registry wait).
    let (logger, agent_cgroup_path, bg_execs) = {
        let mut s = sandbox.lock().await;
        // single countdown: only heartbeats (OP_MEM_STATS) FROM THE HOST PEER
        // reset the anchor. Business RPCs deliberately do NOT — they must not
        // mask a silent sandlot (see heartbeat_op) — and neither may a
        // guest-originated heartbeat (see heartbeat_resets_countdown).
        if heartbeat_op(req.op) {
            if heartbeat_resets_countdown(req.op, peer_cid) {
                s.last_heartbeat = Instant::now();
            } else if let Some(supp) = misbehavior_gate(Misbehavior::HeartbeatNonHost) {
                slog_scope::warn!(
                    "raw_server: heartbeat from non-host peer cid={} ignored; countdown anchor untouched (+{} suppressed)",
                    peer_cid, supp
                );
            }
        }
        let cg_path = s
            .agent_cgroup
            .as_ref()
            .map(|cg| cg.path().to_string_lossy().into_owned());
        (s.logger.clone(), cg_path, s.bg_execs.clone())
    };

    // Defense-in-depth mount checks for the warm-path ops (exec / async_exec /
    // file) happen INSIDE the mount_gate read guard in each branch below — an
    // exec with no mount means the chroot target /mnt/rootfs is stale or
    // absent, which would fork a command in the wrong namespace. Checking
    // under the guard (not up front) closes the check→exec TOCTOU against a
    // concurrent unmount. The same guard call asserts the request's mounted-
    // volume identity when the op carries one (mount_read_guard). The cold
    // mount ops, unmount, heartbeat, and background status/kill are
    // unaffected (status/kill may legitimately run as an agent polls a bg
    // exec after the mount was torn down by a concurrent switch — return
    // not_found/killed).

    match req.op {
        OP_MOUNT_AND_EXEC => {
            // Sync exec cold path: mount + exec in one RTT.
            // Field 0 is the mount identity — this generation's export alias
            // (field 2, the legacy fs_type, is ignored: the mount is always a
            // bind). The alias is the capability the VMM filter currently
            // presents; a superseded generation's alias does not resolve.
            let alias = field(&req, 0);
            let mount_point = field(&req, 1);
            let _fs_type = field(&req, 2);
            let command = field(&req, 3);
            let timeout = parse_timeout_ms(&field(&req, 4));
            let install_packages = field(&req, 5) == "1";
            let volume_mode = field(&req, 6);
            if !validate_mount_point(&mount_point) {
                return mount_point_rejected();
            }
            if !crate::mount::validate_export_alias(&alias) {
                return export_alias_rejected();
            }
            if !validate_volume_mode(&volume_mode) {
                return volume_mode_rejected();
            }
            let start = Instant::now();
            let mount_start = Instant::now();
            // Snapshot the clean flag and mark dirty up front (conservative:
            // even a deduped mount leaves it dirty — the next mount then pays
            // the full defensive sweep, which is only slower, never wrong).
            let known_clean = {
                let mut s = sandbox.lock().await;
                let clean = s.mounts_clean;
                s.mounts_clean = false;
                clean
            };
            let mounted_id = match ensure_mounted_once(
                sandbox,
                &bg_execs,
                &logger,
                &alias,
                crate::mount::open_volume_anchor,
                |vol| {
                    mount_workspace(&logger, vol, &alias, &mount_point, &volume_mode, known_clean)
                },
            )
            .await
            {
                Ok(id) => id,
                Err(e) => {
                    // Full chain (anyhow Display shows only the outermost
                    // context — the errno two levels down would otherwise
                    // stay invisible on the wire).
                    let msg = format!("{:#}", e);
                    error!(logger, "mount_workspace failed: {}", msg);
                    if msg.contains(crate::mount::ERR_MOUNT_TARGET_NOT_EXPORTED) {
                        return Response::app_code(
                            CODE_MOUNT_TARGET_NOT_EXPORTED,
                            "mount_workspace",
                            msg,
                        );
                    }
                    return Response::err("mount_workspace", msg);
                }
            };
            // Mount-only fast path (empty command): the cold FileOp mount
            // (sandlot's ensureMounted) used to run `/bin/sh -c true` here just
            // to reuse the combined op — a full spawn+wait+group-kill cycle
            // whose output nobody reads. An empty command means "establish the
            // mount, nothing else". Wire-compatible in both directions: an old
            // warden given "" runs `sh -c ''` (exit 0, harmless, just slower);
            // an old sandlot never sends "" (it sends "true"). No protocol
            // version bump: the wire format is unchanged.
            if is_mount_only(&command) {
                let exec_duration_ns = start.elapsed().as_nanos() as u64;
                debug!(
                    logger,
                    "mount_and_exec done in {}ms (mount-only, no exec)",
                    start.elapsed().as_millis()
                );
                return Response {
                    version: PROTOCOL_VERSION,
                    code: CODE_OK,
                    exit_code: 0,
                    stdout: Vec::new(),
                    stderr: Vec::new(),
                    mounted: mounted_id.into_bytes(),
                    exec_duration_ns,
                };
            }
            // No agent-cgroup creation on the sync path: sync execs do not
            // join the cgroup (exec.rs deliberately ignores the path), and the
            // cgroupfs mkdir + memory.max write costs ms inside a KVM microVM.
            // The cgroup is created lazily by the first BACKGROUND exec
            // (OP_ASYNC_EXEC / OP_MOUNT_AND_ASYNC_EXEC) — the only consumer of
            // the memory cap and cgroup.kill clearing.
            let mount_ms = mount_start.elapsed().as_millis();
            let exec_start = Instant::now();
            let resp = exec(
                sandbox,
                &logger,
                &command,
                // Cold op: the wire carries no identity field, but the exec
                // must still ASSERT the volume this op just mounted. The mount
                // gate is released when ensure_mounted_once returns, so a
                // concurrent cold mount for a DIFFERENT volume can self-heal
                // (unmount this one, mount its own) before this exec acquires
                // the read gate. Passing the mounted identity makes that
                // interleaving a named volume_identity_mismatch refusal instead
                // of running this tenant's command inside the other volume's
                // rootfs (volume_identity_mismatch; one byte compare).
                Some(mounted_id.as_bytes()),
                timeout,
                install_packages,
            )
            .await;
            // exec_fn µs granularity: ms truncation hides the difference between
            // a 1ms and a 2.4ms exec() that the op-level ms rounds together.
            // debug level: per-op lines tax the measured path through the serial
            // UART (~83µs/char) even printed post-op under tight request gaps;
            // enable with warden.log=debug.
            debug!(
                logger,
                "mount_and_exec done in {}ms (mount={}ms exec_fn={}µs exit={})",
                start.elapsed().as_millis(),
                mount_ms,
                exec_start.elapsed().as_micros(),
                resp.exit_code
            );
            // exec_duration_ns on the wire carries the WARDEN-SIDE TOTAL for
            // this op (mount + exec) — "the operation this response closes",
            // same semantics as OP_UNMOUNT's warden wall time. This is the
            // attribution the latency stats want: warden processing (incl.
            // the mount) is warden's share, and sandlot_duration_ns −
            // exec_duration_ns reduces to sandlot proc + set-fs + vsock.
            // (spawn→wait granularity stays in the console.log line above.)
            // The mounted identity rides EVERY response that got past a
            // successful mount (mount failures returned early, unstamped):
            // the assertion is about WHICH volume is mounted, not about the
            // exec's outcome — a timed-out or failed exec on a correctly
            // mounted volume must still carry the identity, or the sandlot's
            // cross-check would dirty-destroy a perfectly good VM.
            let mut resp = Response {
                version: PROTOCOL_VERSION,
                exec_duration_ns: start.elapsed().as_nanos() as u64,
                ..resp
            };
            resp.mounted = mounted_id.into_bytes();
            resp
        }
        OP_UNMOUNT => {
            let mount_point = field(&req, 0);
            let identity = field(&req, 1);
            let forced = field(&req, 2) == "1";
            if !validate_mount_point(&mount_point) {
                return mount_point_rejected();
            }
            let start = Instant::now();
            // Exclusive mount gate across the whole teardown: waits for all
            // in-flight sync execs / file ops (read guards) to finish, and
            // blocks new ones from starting until the mount is gone —
            // cgroup.kill below must not kill a concurrently running sync
            // exec, and the umount must not race a fresh mount.
            let _mount_gate = crate::sandbox::MOUNT_GATE.write().await;
            // Identity-bound teardown: an unmount names the generation's
            // alias, exactly like the mount that created it. A request whose
            // identity does not match the LIVE mount must tear down nothing —
            // otherwise a stale binding (or a replayed frame) removes the
            // tenant that is currently being served. `forced` is reserved for
            // re-adopt/dirty cleanup, where the previous identity is unknown
            // by construction and the VM is not selectable.
            let (active, current, dirty) = {
                let s = sandbox.lock().await;
                (s.mount_active, s.mounted_volume.clone(), s.mount_dirty)
            };
            // A failed mount leaves mount_active=false with a possible partial
            // stack behind. The forced (re-adopt/dirty cleanup) path must tear
            // that down too — mount_active alone does not prove the guest is
            // clean. Ordinary identity-bound unmounts keep the fast early
            // return: a VM with no active mount and no recorded dirty state has
            // nothing to detach.
            if unmount_has_nothing_to_do(active, dirty) {
                return Response {
                    version: PROTOCOL_VERSION,
                    code: CODE_UNMOUNT_NOT_MOUNTED,
                    exit_code: 0,
                    stdout: Vec::new(),
                    stderr: Vec::new(),
                    mounted: current.unwrap_or_default().into_bytes(),
                    exec_duration_ns: 0,
                };
            }
            let current_str = current.clone().unwrap_or_default();
            if current.as_deref() != Some(identity.as_str()) {
                if !forced {
                    // Name the refusal without naming either volume: the
                    // requester may be a stale sandlot binding, not an
                    // attacker, but neither side's capability should echo.
                    return Response {
                        version: PROTOCOL_VERSION,
                        code: CODE_UNMOUNT_MISMATCH,
                        exit_code: 0,
                        stdout: b"unmount_identity_mismatch: live mount identity does not match the request; nothing torn down".to_vec(),
                        stderr: Vec::new(),
                        mounted: current_str.into_bytes(),
                        exec_duration_ns: 0,
                    };
                }
                warn!(
                    logger,
                    "forced unmount: tearing down an identity that does not match the request (forced cleanup of a non-selectable VM)"
                );
            }
            // Take the owned AgentCgroup from sandbox — avoids reconstructing from
            // path string (which caused triple rmdir: reconstructed Drop + explicit
            // remove_dir + owned Drop). Now the cgroup dir is removed exactly once
            // by AgentCgroup::Drop when unmount_workspace returns.
            let agent_cgroup = {
                let mut s = sandbox.lock().await;
                s.agent_cgroup.take()
            };
            // Fallback path (no cgroup): collect background exec pgids here, in
            // async context, so the sync unmount_workspace does not need to hold
            // the tokio::Mutex across blocking syscalls. When a cgroup is present
            // (normal path) cgroup.kill handles clearing and this is empty.
            let fallback_pgids: Vec<i32> = if agent_cgroup.is_none() {
                bg_execs
                    .lock()
                    .await
                    .iter()
                    .filter(|(_, bg)| bg.pgid > 0)
                    .map(|(_, bg)| bg.pgid)
                    .collect()
            } else {
                Vec::new()
            };
            // Run the sync unmount (cgroup.kill + reap + umount + drop_caches) on
            // a blocking-pool thread: kill_and_reap and the EBUSY retry use
            // std::thread::sleep, which must not pin an async worker (the probe
            // loop's MemStats heartbeats run on the same runtime).
            let mp = mount_point.clone();
            let unmount_result = tokio::task::spawn_blocking(move || {
                crate::mount::unmount_workspace(&mp, agent_cgroup, fallback_pgids)
            })
            .await;
            match unmount_result {
                Ok(Ok(())) => {
                    // The SandFS is now unmounted — clear mount_active so the
                    // warden countdown no-ops (a clean VM must survive for
                    // reuse; there's no live mount to release).
                    set_mount_active(sandbox, false).await;
                    // Full teardown completed: /mnt/rootfs provably carries no
                    // leftover child mounts, so the next mount may skip its
                    // defensive try_umount sweeps. The mounted-volume identity
                    // is cleared with it — at any moment it must name only the
                    // CURRENT agent's volume (never a prior one).
                    {
                        let mut s = sandbox.lock().await;
                        s.mounts_clean = true;
                        s.mount_dirty = false;
                        s.mounted_volume = None;
                    }
                    // Remove warden-side bg log files before clearing the
                    // registry (logs live on initramfs tmpfs, never in the
                    // SandFS — see exec::cleanup_bg_logs).
                    crate::exec::cleanup_bg_logs(&bg_execs).await;
                    bg_execs.lock().await.clear();
                    debug!(
                        logger,
                        "unmount_workspace done in {}ms (mnt={})",
                        start.elapsed().as_millis(),
                        mount_point
                    );
                    // Carry the warden-side unmount wall time so sandlot can
                    // populate CommandResponse.exec_duration_ns and the gateway
                    // can record per-node unmount latency stats (mirroring the
                    // exec path's exec_duration_ns).
                    Response::ok_timed(start.elapsed().as_nanos() as u64)
                }
                Ok(Err(e)) => {
                    // The teardown could not prove the tree clean. Record it so
                    // the forced path retries instead of trusting mount_active.
                    let mut s = sandbox.lock().await;
                    s.mount_dirty = true;
                    s.mounts_clean = false;
                    drop(s);
                    Response::err("unmount_workspace", e)
                }
                Err(join_err) => {
                    let mut s = sandbox.lock().await;
                    s.mount_dirty = true;
                    s.mounts_clean = false;
                    drop(s);
                    Response::err("unmount_workspace", anyhow::anyhow!("{}", join_err))
                }
            }
        }
        OP_KEY_DELIVERY => {
            // Only the host may hand the warden its key (the accept gate
            // already enforces host-only peers; this is defense in depth).
            if peer_cid != VMADDR_CID_HOST {
                return Response::err(
                    "key_delivery",
                    anyhow::anyhow!("key delivery is accepted only from the host CID"),
                );
            }
            let key = field_bytes(&req, 0);
            if key.len() != 32 {
                return Response::err(
                    "key_delivery",
                    anyhow::anyhow!("key must be exactly 32 bytes (got {})", key.len()),
                );
            }
            let mut k = [0u8; 32];
            k.copy_from_slice(key);
            match crate::auth::install_session_key(k) {
                Ok(()) => {
                    // The response tag is computed with the now-installed key
                    // (encode_response_header reads the store), proving to the
                    // sandlot that delivery succeeded.
                    Response::ok()
                }
                Err(()) => Response::err(
                    "key_delivery",
                    anyhow::anyhow!("a different session key is already installed; refusing overwrite"),
                ),
            }
        }
        OP_EXEC => {
            // Sync exec warm path: already mounted, just exec. The mount
            // check — and the mounted-volume identity assertion (field 3,
            // see IDX_EXEC_VOLUME) — happen inside exec() under the read guard.
            let command = field(&req, 0);
            let timeout = parse_timeout_ms(&field(&req, 1));
            let install_packages = field(&req, 2) == "1";
            exec(
                sandbox,
                &logger,
                &command,
                Some(field_bytes(&req, IDX_EXEC_VOLUME)),
                timeout,
                install_packages,
            )
            .await
        }
        OP_MEM_STATS => {
            match (
                crate::exec_cgroup::read_mem_available_bytes(),
                crate::exec_cgroup::read_mem_total_bytes(),
            ) {
                (Some(avail), Some(total)) => Response {
                    version: PROTOCOL_VERSION,
                    code: CODE_OK,
                    exit_code: 0,
                    stdout: format!("{} {}", avail, total).into_bytes(),
                    stderr: Vec::new(),
                    mounted: Vec::new(),
                    exec_duration_ns: 0,
                },
                // Reading /proc/meminfo failed — the VM is healthy (the warden
                // is up and serving), this is a business failure, not a
                // transport error. APP_ERROR so the sandlot probe records a
                // probe failure (not a connection invalidation).
                _ => {
                    Response::app_err("mem_stats", anyhow::anyhow!("could not read /proc/meminfo"))
                }
            }
        }
        OP_ASYNC_EXEC => {
            // Async exec warm path: already mounted, just start background exec.
            // Read gate + mount check: the spawn must not race a concurrent
            // unmount (the cgroup the pgid is written into could vanish).
            // The identity rides field 2 (see IDX_ASYNC_EXEC_VOLUME).
            let _mount_gate =
                match mount_read_guard(sandbox, Some(field_bytes(&req, IDX_ASYNC_EXEC_VOLUME)))
                    .await
                {
                    Ok(g) => g,
                    Err(r) => return r,
                };
            let command = field(&req, 0);
            let install_packages = field(&req, 1) == "1";
            // Lazy cgroup creation: sync-only mounts never created one, but a
            // background exec needs it (memory cap + cgroup.kill at unmount).
            // The dispatch-time snapshot may be stale (None) — re-ensure here
            // under the read gate, mirroring OP_MOUNT_AND_ASYNC_EXEC.
            let cg_path = match agent_cgroup_path {
                Some(p) => Some(p),
                None => ensure_agent_cgroup(sandbox, crate::mount::MOUNT_POINT).await,
            };
            // Stamp the exec with the mount generation it is spawned under.
            // The read guard above pins the generation for this spawn (an
            // unmount takes the write guard), so the stamp cannot go stale
            // between here and the registry insert.
            let mount_generation = sandbox.lock().await.mount_generation;
            async_exec(
                &logger,
                &command,
                cg_path.as_deref(),
                &bg_execs,
                install_packages,
                mount_generation,
            )
            .await
        }
        OP_MOUNT_AND_ASYNC_EXEC => {
            // Async exec cold path: mount + start background exec in one RTT.
            // Field 0 is this generation's export alias (see the sync branch).
            let alias = field(&req, 0);
            let mount_point = field(&req, 1);
            let _fs_type = field(&req, 2);
            let command = field(&req, 3);
            let install_packages = field(&req, 4) == "1";
            let volume_mode = field(&req, 5);
            if !validate_mount_point(&mount_point) {
                return mount_point_rejected();
            }
            if !crate::mount::validate_export_alias(&alias) {
                return export_alias_rejected();
            }
            if !validate_volume_mode(&volume_mode) {
                return volume_mode_rejected();
            }
            let start = Instant::now();
            let mount_start = Instant::now();
            // Snapshot + mark dirty, same as the sync combined path.
            let known_clean = {
                let mut s = sandbox.lock().await;
                let clean = s.mounts_clean;
                s.mounts_clean = false;
                clean
            };
            let mounted_id = match ensure_mounted_once(
                sandbox,
                &bg_execs,
                &logger,
                &alias,
                crate::mount::open_volume_anchor,
                |vol| {
                    mount_workspace(&logger, vol, &alias, &mount_point, &volume_mode, known_clean)
                },
            )
            .await
            {
                Ok(id) => id,
                Err(e) => {
                    // Full chain (anyhow Display shows only the outermost
                    // context — the errno two levels down would otherwise
                    // stay invisible on the wire).
                    let msg = format!("{:#}", e);
                    error!(logger, "mount_workspace failed: {}", msg);
                    if msg.contains(crate::mount::ERR_MOUNT_TARGET_NOT_EXPORTED) {
                        return Response::app_code(
                            CODE_MOUNT_TARGET_NOT_EXPORTED,
                            "mount_workspace",
                            msg,
                        );
                    }
                    return Response::err("mount_workspace", msg);
                }
            };
            // Background execs are the cgroup's only consumer — create it here
            // (lazily; sync-only mounts never pay the cgroupfs cost).
            let cg_path = ensure_agent_cgroup(sandbox, &mount_point).await;
            let mount_ms = mount_start.elapsed().as_millis();
            // Read gate + mount check around the spawn (same guard as the sync
            // combined path): a concurrent unmount must not rip the mount out
            // between the gate drop above and the pgid registration below.
            // The identity assertion is the same one the sync cold path makes:
            // the mount gate was released when ensure_mounted_once returned, so
            // the volume must still be the one THIS op mounted when the spawn
            // runs (a concurrent different-volume mount self-heals in between).
            let mut resp = {
                let _gate = match mount_read_guard(sandbox, Some(mounted_id.as_bytes())).await {
                    Ok(g) => g,
                    Err(r) => return r,
                };
                // The mount just established this generation; stamp the exec
                // with it under the read guard (see OP_ASYNC_EXEC).
                let mount_generation = sandbox.lock().await.mount_generation;
                async_exec(
                    &logger,
                    &command,
                    cg_path.as_deref(),
                    &bg_execs,
                    install_packages,
                    mount_generation,
                )
                .await
            };
            // Exclusive-ownership assertion rides every response that got
            // past a successful mount (see the sync combined path).
            resp.mounted = mounted_id.into_bytes();
            debug!(
                logger,
                "mount_and_async_exec done in {}ms (mount={}ms exec_id={:?})",
                start.elapsed().as_millis(),
                mount_ms,
                if resp.code == CODE_OK {
                    Some(String::from_utf8_lossy(&resp.stdout).into_owned())
                } else {
                    None
                }
            );
            resp
        }
        OP_STATUS_EXEC => {
            let exec_id = field(&req, 0);
            let mount_generation = sandbox.lock().await.mount_generation;
            status_exec(&logger, &exec_id, &bg_execs, mount_generation).await
        }
        OP_KILL_EXEC => {
            let exec_id = field(&req, 0);
            let mount_generation = sandbox.lock().await.mount_generation;
            kill_exec(&logger, &exec_id, &bg_execs, mount_generation).await
        }
        OP_FILE => {
            // File I/O: unified sub-opcode dispatch. All paths are resolved
            // inside the workspace base with canonicalize + prefix check.
            // Read gate + mount check: file ops touch the mounted workspace —
            // a concurrent unmount must wait for them (and vice versa). The
            // mounted-volume identity rides field 5 (see IDX_FILE_VOLUME):
            // file ops resolve paths INSIDE the mounted volume, so a skew
            // would read/write the wrong tenant's files.
            let _mount_gate =
                match mount_read_guard(sandbox, Some(field_bytes(&req, IDX_FILE_VOLUME))).await {
                    Ok(g) => g,
                    Err(r) => return r,
                };
            // sub_op is the first byte of field[0]; use first() (not index 0)
            // so an empty sub-op field degrades to 0/unknown instead of
            // panicking — a malformed frame must never kill PID 1.
            let sub_op = req.field_bytes(0).first().copied().unwrap_or(0);
            let path = field(&req, 1); // field[1] = path (all sub-ops)
            let max_file_read_bytes = crate::AGENT_CONFIG.max_file_read_bytes;
            // A positive write offset is a sparse-hole request; cap it by the
            // same single-op size budget so one OP_FILE cannot mint an
            // arbitrarily large apparent file (SaveAsTemplate would then
            // materialize the hole into shared storage).
            let max_sparse_offset = i64::try_from(max_file_read_bytes).unwrap_or(i64::MAX);
            // All file ops are blocking std::fs work (up to max_file_read_bytes
            // over virtio-fs, possibly a network-backed volume) — run each on
            // the blocking pool so a slow or large file op never pins an async
            // worker (heartbeats and other slots must keep being served). base
            // is &'static (OnceLock) — no per-op PathBuf clone.
            let base: &Path = workspace_base();
            match sub_op {
                crate::files::SUB_OP_READ => {
                    let offset: i64 = field(&req, 2).parse().unwrap_or(0);
                    let length: u64 = field(&req, 3).parse().unwrap_or(0);
                    let res = tokio::task::spawn_blocking(move || {
                        crate::files::read_file(base, &path, offset, length, max_file_read_bytes)
                    })
                    .await;
                    match res {
                        Ok(Ok(data)) => Response {
                            version: PROTOCOL_VERSION,
                            code: CODE_OK,
                            exit_code: 0,
                            stdout: data,
                            stderr: Vec::new(),
                            mounted: Vec::new(),
                            exec_duration_ns: 0,
                        },
                        Ok(Err(e)) => Response::app_err("file_read", e),
                        Err(e) => Response::err("file_read", anyhow::anyhow!("{}", e)),
                    }
                }
                crate::files::SUB_OP_WRITE => {
                    let offset: i64 = field(&req, 2).parse().unwrap_or(0);
                    let mode: u32 = field(&req, 3).parse().unwrap_or(0);
                    // MOVE the body into the blocking task (no payload copy):
                    // the write payload can be up to max_body_len (16 MB), and
                    // the field is a byte range into the body. The empty range
                    // stands in for an absent field.
                    let data_span = req.field_spans.get(4).cloned().unwrap_or(0..0);
                    let body = std::mem::take(&mut req.body);
                    let res = tokio::task::spawn_blocking(move || {
                        crate::files::write_file(
                            base,
                            &path,
                            offset,
                            mode,
                            &body[data_span],
                            max_sparse_offset,
                        )
                    })
                    .await;
                    match res {
                        Ok(Ok(())) => Response::ok(),
                        Ok(Err(e)) => Response::app_err("file_write", e),
                        Err(e) => Response::err("file_write", anyhow::anyhow!("{}", e)),
                    }
                }
                crate::files::SUB_OP_STAT => {
                    let res =
                        tokio::task::spawn_blocking(move || crate::files::stat_file(base, &path))
                            .await;
                    match res {
                        Ok(Ok(info)) => {
                            let json = serde_json::to_vec(&info).unwrap_or_default();
                            Response {
                                version: PROTOCOL_VERSION,
                                code: CODE_OK,
                                exit_code: 0,
                                stdout: json,
                                stderr: Vec::new(),
                                mounted: Vec::new(),
                                exec_duration_ns: 0,
                            }
                        }
                        Ok(Err(e)) => Response::app_err("file_stat", e),
                        Err(e) => Response::err("file_stat", anyhow::anyhow!("{}", e)),
                    }
                }
                crate::files::SUB_OP_LIST_DIR => {
                    let depth: u32 = field(&req, 2).parse().unwrap_or(0);
                    // The listing carries the same byte budget as a read
                    // (max_file_read_bytes) MINUS a fixed envelope headroom:
                    // the per-entry cost estimate covers JSON overhead, but
                    // the array framing plus the response envelope must still
                    // fit under the chain's gRPC message limit. Without the
                    // margin a listing at the budget could produce a JSON body
                    // that, plus the envelope, exceeds the node stream's max
                    // message size — resetting the shared stream.
                    let list_budget = max_file_read_bytes.saturating_sub(64 * 1024);
                    let res = tokio::task::spawn_blocking(move || {
                        crate::files::list_dir(base, &path, depth, list_budget)
                    })
                    .await;
                    match res {
                        Ok(Ok(entries)) => {
                            let json = serde_json::to_vec(&entries).unwrap_or_default();
                            Response {
                                version: PROTOCOL_VERSION,
                                code: CODE_OK,
                                exit_code: 0,
                                stdout: json,
                                stderr: Vec::new(),
                                mounted: Vec::new(),
                                exec_duration_ns: 0,
                            }
                        }
                        Ok(Err(e)) => Response::app_err("file_list_dir", e),
                        Err(e) => Response::err("file_list_dir", anyhow::anyhow!("{}", e)),
                    }
                }
                crate::files::SUB_OP_MAKE_DIR => {
                    let mode: u32 = field(&req, 2).parse().unwrap_or(0);
                    let res = tokio::task::spawn_blocking(move || {
                        crate::files::make_dir(base, &path, mode)
                    })
                    .await;
                    match res {
                        Ok(Ok(())) => Response::ok(),
                        Ok(Err(e)) => Response::app_err("file_make_dir", e),
                        Err(e) => Response::err("file_make_dir", anyhow::anyhow!("{}", e)),
                    }
                }
                crate::files::SUB_OP_REMOVE => {
                    let recursive: bool = field(&req, 2) == "1" || field(&req, 2) == "true";
                    let res = tokio::task::spawn_blocking(move || {
                        crate::files::remove_path(base, &path, recursive)
                    })
                    .await;
                    match res {
                        Ok(Ok(())) => Response::ok(),
                        Ok(Err(e)) => Response::app_err("file_remove", e),
                        Err(e) => Response::err("file_remove", anyhow::anyhow!("{}", e)),
                    }
                }
                crate::files::SUB_OP_RENAME => {
                    let new_path = field(&req, 2);
                    let res = tokio::task::spawn_blocking(move || {
                        crate::files::rename_path(base, &path, &new_path)
                    })
                    .await;
                    match res {
                        Ok(Ok(())) => Response::ok(),
                        Ok(Err(e)) => Response::app_err("file_rename", e),
                        Err(e) => Response::err("file_rename", anyhow::anyhow!("{}", e)),
                    }
                }
                _ => Response {
                    version: PROTOCOL_VERSION,
                    code: CODE_TRANSPORT_ERROR,
                    exit_code: 0,
                    stdout: Vec::new(),
                    stderr: format!("unknown file sub_op: {}", sub_op).into_bytes(),
                    mounted: Vec::new(),
                    exec_duration_ns: 0,
                },
            }
        }
        op => Response {
            version: PROTOCOL_VERSION,
            code: CODE_TRANSPORT_ERROR,
            exit_code: 0,
            stdout: Vec::new(),
            stderr: format!("unknown op {}", op).into_bytes(),
            mounted: Vec::new(),
            exec_duration_ns: 0,
        },
    }
}

/// Run a chrooted command via the shared verified do_exec and pack the
/// result. status mirrors the process exit code on success (0 = ok); a nonzero
/// exit code is still a successful *transport*, surfaced as status=exit_code so
/// sandlot can distinguish "exec ran, exit N" from "transport/handler error".
/// A command timeout surfaces as CODE_TIMED_OUT (no magic exit-code sentinel).
///
/// Holds the mount_gate read guard across the whole exec: an unmount (write
/// guard) waits for every in-flight sync exec before its cgroup.kill, and the
/// warm-path mount check runs INSIDE the guard so a concurrent unmount cannot
/// slip between check and fork (TOCTOU fix — the sandlot's execMu no longer
/// serializes this). `identity` is the warm path's mounted-volume assertion;
/// the cold combined op passes None (it mounted the requested volume itself).
async fn exec(
    sandbox: &Arc<Mutex<Sandbox>>,
    logger: &Logger,
    command: &str,
    identity: Option<&[u8]>,
    timeout: std::time::Duration,
    install_packages: bool,
) -> Response {
    let _mount_gate = match mount_read_guard(sandbox, identity).await {
        Ok(g) => g,
        Err(r) => return r,
    };
    let start = Instant::now();
    match AgentService::do_exec(logger, command, start, timeout, install_packages).await {
        Ok((outcome, spawn_ms, wait_ms)) => {
            let exec_duration_ns = start.elapsed().as_nanos() as u64;
            match outcome {
                crate::exec::ExecOutcome::Done(r) => {
                    // debug level: this fires on EVERY warm exec — at info it
                    // keeps the console drain thread ~80% busy under back-to-back
                    // execs (5ms gaps, ~50 chars/line), taxing every next op.
                    debug!(
                        logger,
                        "exec done in {}ms (spawn={}ms wait={}ms exit={})",
                        start.elapsed().as_millis(),
                        spawn_ms,
                        wait_ms,
                        r.exit_code
                    );
                    // r.stdout/r.stderr are already Vec<u8> (drained straight from
                    // the child pipe), so they move into the frame body with zero copy.
                    Response::ok_exec(r.exit_code, r.stdout, r.stderr, exec_duration_ns)
                }
                crate::exec::ExecOutcome::TimedOut(r) => {
                    // debug level: timeouts are per-op outcomes the agent can
                    // trigger in a loop; at info they flood the serial console
                    // and crowd the log channel. The response code
                    // (CODE_TIMED_OUT) carries the outcome.
                    debug!(
                        logger,
                        "exec timed out after {}ms (spawn={}ms wait={}ms)",
                        start.elapsed().as_millis(),
                        spawn_ms,
                        wait_ms,
                    );
                    // CODE_TIMED_OUT carries the partial output in stdout; exit_code
                    // is 0 (no real exit code — the command was killed mid-run).
                    Response {
                        version: PROTOCOL_VERSION,
                        code: CODE_TIMED_OUT,
                        exit_code: 0,
                        stdout: r.stdout,
                        stderr: r.stderr,
                        mounted: Vec::new(),
                        exec_duration_ns,
                    }
                }
            }
        }
        Err(e) => Response::err("exec", e),
    }
}

/// Resolve a requested timeout (milliseconds) against the configured default
/// and max. 0 (or unparsable, mapped to 0 by the caller) selects the default;
/// anything above max is clamped to max. Extracted as a pure function so the
/// clamp semantics are unit-testable without the global config.
fn resolve_timeout(
    requested_ms: u64,
    default: std::time::Duration,
    max: std::time::Duration,
) -> std::time::Duration {
    let d = if requested_ms == 0 {
        default
    } else {
        std::time::Duration::from_millis(requested_ms)
    };
    if d > max {
        max
    } else {
        d
    }
}

/// Parse a timeout_ms field (ASCII u64). Empty/0 => use the configured default.
/// Clamped to max_exec_timeout. Used by OP_EXEC/OP_MOUNT_AND_EXEC.
fn parse_timeout_ms(s: &str) -> std::time::Duration {
    let cfg = &crate::AGENT_CONFIG;
    let requested: u64 = s.trim().parse().unwrap_or(0);
    resolve_timeout(requested, cfg.default_exec_timeout, cfg.max_exec_timeout)
}

/// Derive a stable cgroup name from the mount point (e.g. "/mnt/rootfs" →
/// "rootfs"). The cgroup dir is `/sys/fs/cgroup/sandswap-agent-{name}`.
fn cg_name_for(mount_point: &str) -> String {
    let trimmed = mount_point.trim_end_matches('/');
    let last = trimmed.rsplit('/').next().unwrap_or("rootfs");
    if last.is_empty() {
        "rootfs".to_string()
    } else {
        last.to_string()
    }
}

/// Ensure the per-agent cgroup exists for `mount_point`, creating it if
/// missing. Called only where a BACKGROUND exec is about to spawn (the
/// cgroup's only consumer — memory cap + cgroup.kill clearing); sync-only
/// cold mounts deliberately skip it: the cgroupfs mkdir + memory.max write
/// costs ms inside a KVM microVM and sync execs never join the cgroup.
/// Returns the cgroup path.
async fn ensure_agent_cgroup(sandbox: &Arc<Mutex<Sandbox>>, mount_point: &str) -> Option<String> {
    let mut s = sandbox.lock().await;
    // Fast path: cgroup already exists.
    if let Some(cg) = &s.agent_cgroup {
        let path = cg.path().to_string_lossy().into_owned();
        return Some(path);
    }
    // Slow path: create cgroup while holding the sandbox lock.
    // This prevents two concurrent MOUNT_AND_EXEC from both seeing None and
    // each creating a cgroup (the second would overwrite the first, leaking it).
    let (mem_pct, mem_total) = {
        (
            crate::AGENT_CONFIG.agent_mem_percent,
            crate::exec_cgroup::read_mem_total_bytes().unwrap_or(0),
        )
    };
    let cg_name = cg_name_for(mount_point);
    match crate::exec_cgroup::AgentCgroup::create(&cg_name, mem_total, mem_pct) {
        Ok(Some(cg)) => {
            let path = cg.path().to_string_lossy().into_owned();
            s.agent_cgroup = Some(cg);
            Some(path)
        }
        // Degradation must be VISIBLE: without the cgroup the agent loses both
        // the memory cap and the cgroup.kill agent-switch clearing (unmount
        // falls back to killing only registered bg-exec pgids). Never silent.
        Ok(None) => {
            slog_scope::error!(
                "ensure_agent_cgroup: cgroup unavailable — agent runs WITHOUT memory cap and cgroup.kill clearing (mkdir failed; see exec_cgroup logs)"
            );
            None
        }
        Err(e) => {
            slog_scope::error!(
                "ensure_agent_cgroup: create failed ({}) — agent runs WITHOUT memory cap and cgroup.kill clearing",
                e
            );
            None
        }
    }
}

/// set_mount_active updates the Sandbox::mount_active flag under the sandbox
/// lock. Called on successful mount (true) and on unmount (false). This flag is
/// the warden countdown's authoritative "is a SandFS currently mounted?" guard.
///
/// Every transition also advances Sandbox::mount_generation, the stamp that
/// background execs carry: once the mount state moves (a switch), an exec_id
/// registered under the old generation can neither be polled (its log belongs
/// to the previous tenant) nor killed (its pgid may have been recycled).
async fn set_mount_active(sandbox: &Arc<Mutex<Sandbox>>, active: bool) {
    let mut s = sandbox.lock().await;
    if s.mount_active != active {
        s.mount_generation = s.mount_generation.wrapping_add(1);
        s.mount_active = active;
    }
}

/// The workspace base for OP_FILE (MOUNT_POINT + WORKSPACE_DIR). Only the
/// LEXICAL path is cached per VM lifetime: canonicalizing here would pin the
/// FIRST agent's resolution for every later attach — in flat mode /workspace
/// is agent-controlled, and an agent whose /workspace is a symlink would
/// poison the base for the next agent's file ops. The per-op canonicalize in
/// files.rs (validate_path_under / resolve_parent) resolves against the
/// CURRENT mount, so containment stays correct across agent switches.
fn workspace_base() -> &'static Path {
    static BASE: OnceLock<PathBuf> = OnceLock::new();
    BASE.get_or_init(|| {
        PathBuf::from(format!(
            "{}{}",
            crate::mount::MOUNT_POINT,
            crate::mount::WORKSPACE_DIR
        ))
    })
}

/// Bounded background-exec log growth. BG logs live on the RAM-backed
/// initramfs rootfs (see exec::BG_LOG_DIR) and are otherwise only cleaned at
/// unmount — a `while true; do echo spam; done` background exec would eat the
/// guest's memory until the VM dies. Every BG_LOG_SWEEP, check each registered
/// bg log's size; past the configured cap (warden.max_bg_log_bytes, 0 = off)
/// keep only the configured tail. When the AGGREGATE across all logs
/// exceeds BG_LOG_TOTAL_BUDGET_MULT × the per-log cap, every log is shrunk to
/// its tail instead (bounding the multi-writer transient between sweeps).
/// The writing process keeps its file offset, so its next write lands at the
/// old offset past EOF — the skipped region is a sparse hole that costs no
/// tmpfs pages, which is what actually bounds memory usage (apparent file
/// size still grows).
fn spawn_bg_log_watchdog(bg_execs: Arc<Mutex<HashMap<String, crate::sandbox::BgExec>>>) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(BG_LOG_SWEEP);
        tick.tick().await; // skip the immediate first tick
        loop {
            tick.tick().await;
            let cap = crate::AGENT_CONFIG.max_bg_log_bytes;
            if cap == 0 {
                continue;
            }
            let paths: Vec<String> = {
                let map = bg_execs.lock().await;
                map.values().map(|bg| bg.log_path.clone()).collect()
            };
            if paths.is_empty() {
                continue;
            }
            let total_budget = (cap as u64).saturating_mul(BG_LOG_TOTAL_BUDGET_MULT);
            // Blocking tmpfs metadata/truncate work on the blocking pool: one
            // pass gathers sizes (deciding per-log caps against the shared
            // total budget), the second truncates.
            let results = tokio::task::spawn_blocking(move || {
                let mut sizes: Vec<(String, u64)> = Vec::with_capacity(paths.len());
                let mut total: u64 = 0;
                for p in &paths {
                    let len = std::fs::metadata(p).map(|m| m.len()).unwrap_or(0);
                    total = total.saturating_add(len);
                    sizes.push((p.clone(), len));
                }
                let over_total = total > total_budget;
                let mut truncated = Vec::new();
                for (p, len) in sizes {
                    let effective = effective_log_cap(cap, over_total, bg_log_tail_bytes() as usize);
                    if truncate_log_past_cap(&p, effective, bg_log_tail_bytes()) {
                        truncated.push((p, len));
                    }
                }
                (truncated, over_total)
            })
            .await;
            match results {
                Ok((truncated, over_total)) => {
                    for (path, len) in truncated {
                        slog_scope::warn!(
                            "bg log watchdog: truncated {} ({} bytes) past cap — kept tail{}",
                            path,
                            len,
                            if over_total {
                                " (aggregate budget breach)"
                            } else {
                                ""
                            }
                        );
                    }
                }
                Err(e) => {
                    slog_scope::warn!("bg log watchdog: sweep join failed: {}", e);
                }
            }
        }
    });
}

/// Per-log effective cap for one sweep: the configured per-log cap, or the
/// tail-keep floor when the aggregate across logs already breached the total
/// budget (shrinking every log bounds the multi-writer transient). Pure for
/// unit tests.
fn effective_log_cap(per_log_cap: usize, over_total_budget: bool, tail_keep: usize) -> usize {
    if over_total_budget {
        tail_keep
    } else {
        per_log_cap
    }
}

/// One watchdog sweep step: if `path` exceeds `cap` bytes, rewrite it to the
/// last `keep` bytes. Returns whether a truncation happened. Blocking (called
/// from spawn_blocking).
fn truncate_log_past_cap(path: &str, cap: usize, keep: u64) -> bool {
    use std::io::{Read, Seek, SeekFrom, Write};
    let len = match std::fs::metadata(path) {
        Ok(m) => m.len(),
        Err(_) => return false,
    };
    if len <= cap as u64 || len <= keep {
        return false;
    }
    let mut f = match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
    {
        Ok(f) => f,
        Err(_) => return false,
    };
    let tail_start = len - keep;
    if f.seek(SeekFrom::Start(tail_start)).is_err() {
        return false;
    }
    let mut tail = Vec::with_capacity(keep as usize);
    // Cap the read: the log is being appended, so read_to_end could copy the
    // growth past `keep` (up to the agent's free RAM) into the warden.
    // Fully qualified: this File is open for both read and write, so
    // `by_ref` is ambiguous between io::Read and io::Write.
    if std::io::Read::by_ref(&mut f).take(keep).read_to_end(&mut tail).is_err() {
        return false;
    }
    if f.set_len(0).is_err() {
        return false;
    }
    if f.seek(SeekFrom::Start(0)).is_err() {
        return false;
    }
    // A failed tail rewrite must not report success: the caller's warn line
    // (and the operator's trust in "kept tail") depends on it.
    f.write_all(&tail).is_ok()
}

/// Cold-mount gate: serialize concurrent cold mounts on the MOUNT_GATE write
/// guard, run `mount` at most once per volume, and ENFORCE VOLUME IDENTITY:
/// the sandbox tracks which volume's basename is currently mounted at
/// /mnt/rootfs. A request for the SAME volume while mounted is the duplicate
/// cold-mount case and skips the redundant mount_workspace (which a later
/// unmount would only peel one layer of). A request for a DIFFERENT volume
/// while mounted means the warden's mount state was twisted out-of-band — a
/// peer holding the VM's session key (a compromised sandlot, or a spoofed
/// mount-only raced into the switch window before the sandlot's set-fs swaps
/// allowed_dirs): the stale mount is TORN DOWN and the requested volume
/// mounted in its place — a self-healing switch. A dedup-skip here would
/// instead run the new agent's exec inside the OLD agent's rootfs.
/// The heal runs the FULL unmount sequence (mirrors OP_UNMOUNT, including the
/// rule-A non-init process sweep); if it fails (EBUSY/D-state) an error is
/// returned and the sandlot destroys the VM (exclusive-ownership semantics).
/// Returns the mounted basename on success — carried on the wire so the
/// sandlot can cross-check it (see Response::mounted).
async fn ensure_mounted_once<F, Fut, P>(
    sandbox: &Arc<Mutex<Sandbox>>,
    bg_execs: &Arc<Mutex<HashMap<String, crate::sandbox::BgExec>>>,
    logger: &Logger,
    alias: &str,
    probe: P,
    mount: F,
) -> anyhow::Result<String>
where
    F: FnOnce(crate::mount::RootAnchor) -> Fut,
    Fut: std::future::Future<Output = Result<(), anyhow::Error>>,
    P: FnOnce(&Logger, &str) -> anyhow::Result<crate::mount::RootAnchor>,
{
    let _gate = crate::sandbox::MOUNT_GATE.write().await;
    let requested = alias.to_string();
    // Dedupe against the CURRENT mount's identity. The identity is this
    // generation's alias, minted by the sandlot after its set-fs; only a
    // request from the same generation can name it.
    let current = {
        let s = sandbox.lock().await;
        (s.mount_active, s.mounted_volume.clone(), s.mount_dirty)
    };
    if current.0 && current.1.as_deref() == Some(alias) {
        return Ok(requested);
    }

    // PROBE FIRST (before any teardown): opening the requested generation's
    // alias is the atomic gate between the VMM filter and this mount. A
    // request that lost the race to a later set-fs names an alias the root
    // no longer exports, so the open fails ENOENT and we MUST NOT tear down
    // the mount that is currently serving the other tenant. The same anchor
    // is then used by the mount, keeping the cold path at one lookup.
    crate::mount::fuse_ops_begin();
    let anchor = match probe(logger, alias) {
        Ok(a) => a,
        Err(e) => {
            crate::mount::fuse_ops_end();
            return Err(e);
        }
    };

    if current.0 || current.2 {
        let stale = current.1.clone();
        slog_scope::warn!(
            "cold mount: /mnt/rootfs holds {} but {} was requested — tearing down stale mount (self-heal)",
            stale.as_deref().unwrap_or("<unknown>"),
            requested
        );
        let agent_cgroup = {
            let mut s = sandbox.lock().await;
            s.agent_cgroup.take()
        };
        let fallback_pgids: Vec<i32> = if agent_cgroup.is_none() {
            bg_execs
                .lock()
                .await
                .iter()
                .filter(|(_, bg)| bg.pgid > 0)
                .map(|(_, bg)| bg.pgid)
                .collect()
        } else {
            Vec::new()
        };
        let mp = crate::mount::MOUNT_POINT.to_string();
        let unmount_result = tokio::task::spawn_blocking(move || {
            crate::mount::unmount_workspace(&mp, agent_cgroup, fallback_pgids)
        })
        .await;
        match unmount_result {
            Ok(Ok(())) => {
                set_mount_active(sandbox, false).await;
                {
                    let mut s = sandbox.lock().await;
                    s.mounts_clean = true;
                    s.mount_dirty = false;
                    s.mounted_volume = None;
                }
                crate::exec::cleanup_bg_logs(bg_execs).await;
                bg_execs.lock().await.clear();
            }
            Ok(Err(e)) => {
                sandbox.lock().await.mount_dirty = true;
                crate::mount::fuse_ops_end();
                return Err(anyhow::anyhow!(
                    "stale-mount self-heal unmount failed: {} — VM must be destroyed to maintain exclusive-ownership invariant",
                    e
                ))
            }
            Err(join_err) => {
                sandbox.lock().await.mount_dirty = true;
                crate::mount::fuse_ops_end();
                return Err(anyhow::anyhow!(
                    "stale-mount self-heal unmount join failed: {}",
                    join_err
                ))
            }
        }
    }
    if let Err(e) = mount(anchor).await {
        // A mount that failed mid-way may have left a partial stack behind
        // (the rootfs bind happens first; workspace/home/proc masking come
        // after). mount_active was never set, so nothing else would ever tear
        // it down: run the full teardown now and let its outcome decide
        // whether the VM is reusable.
        {
            let mut s = sandbox.lock().await;
            s.mounts_clean = false;
            s.mount_dirty = true;
            s.mounted_volume = None;
        }
        let mp = crate::mount::MOUNT_POINT.to_string();
        let cleanup = tokio::task::spawn_blocking(move || {
            crate::mount::unmount_workspace(&mp, None, Vec::new())
        })
        .await;
        let clean = match cleanup {
            Ok(Ok(())) => {
                let mut s = sandbox.lock().await;
                s.mounts_clean = true;
                s.mount_dirty = false;
                true
            }
            Ok(Err(cleanup_err)) => {
                warn!(
                    logger,
                    "mount failed and the partial-stack teardown also failed: {} — the VM must be destroyed",
                    cleanup_err
                );
                false
            }
            Err(join_err) => {
                warn!(
                    logger,
                    "mount failed and the partial-stack teardown panicked: {} — the VM must be destroyed",
                    join_err
                );
                false
            }
        };
        crate::mount::fuse_ops_end();
        if clean {
            return Err(e);
        }
        return Err(anyhow::anyhow!(
            "{} — a partial mount stack could not be torn down; the VM must be destroyed",
            e
        ));
    }
    set_mount_active(sandbox, true).await;
    {
        let mut s = sandbox.lock().await;
        s.mounted_volume = Some(requested.clone());
        s.mount_dirty = false;
    }
    Ok(requested)
}

/// Verdict of the warm-op mounted-volume identity assertion.
#[derive(Debug, PartialEq, Eq)]
enum WarmIdentity {
    /// The field names the volume the warden actually holds — proceed.
    Match,
    /// No identity to assert: the field is absent or empty. This is a
    /// protocol/bookkeeping failure — REFUSE without executing. The cold
    /// combined mount ops are the only callers with no identity by design,
    /// and they pass `None` (not an empty field).
    Missing,
    /// The field names a DIFFERENT volume than the one held — refuse.
    Mismatch,
}

/// Classify a warm op's mounted-volume identity field against the volume the
/// warden actually holds at /mnt/rootfs.
///
/// Semantics: an empty or absent field is `Missing` and is refused; a non-empty
/// field that does not equal `mounted` is `Mismatch` — including the case where
/// the warden holds NO identity (it cannot confirm the claim, so it refuses).
/// The comparison is one Option compare over raw bytes — no allocation, no
/// /proc read — so the warm-op hot path pays nothing for the common (match)
/// case.
///
/// WHY the warden refuses instead of trusting the caller: the identity lives
/// in the sandlot's in-memory volume map, whose only invariant is that every
/// mutation site is guarded. The warden is the ONE place that knows what is
/// mounted, so a bookkeeping skew (sandlot believes volume X is warm, guest
/// holds Y) must be caught here — otherwise X's command would execute inside
/// Y's rootfs: a cross-tenant exec with no backstop at all. An empty identity
/// has the same failure mode with no volume claim to check, so it is refused
/// rather than defaulted to "whatever is mounted". Extracted as a pure
/// function for unit testing.
fn warm_identity_verdict(mounted: Option<&str>, identity: &[u8]) -> WarmIdentity {
    if identity.is_empty() {
        return WarmIdentity::Missing;
    }
    match mounted {
        Some(m) if m.as_bytes() == identity => WarmIdentity::Match,
        _ => WarmIdentity::Mismatch,
    }
}

/// Acquire the MOUNT_GATE read guard and verify a SandFS is mounted INSIDE it
/// (closing the check→exec TOCTOU against a concurrent unmount). The caller
/// must hold the returned guard for the whole op touching the workspace.
///
/// `identity` is Some for the ops whose frames carry the mounted-volume
/// identity field (OP_EXEC / OP_ASYNC_EXEC / OP_FILE, at the documented fixed
/// positions) and None for ops with no such field by design (the cold
/// combined mount ops, which establish the mount themselves and get the same
/// assertion from ensure_mounted_once). A non-empty identity that does not
/// match the held volume is refused WITHOUT executing — a named
/// volume_identity_mismatch transport error; an empty identity is refused by
/// name too (volume_identity_missing) — it is a bookkeeping failure, never a
/// licence to run against the current mount.
/// Err carries the standard transport-error response.
async fn mount_read_guard(
    sandbox: &Arc<Mutex<Sandbox>>,
    identity: Option<&[u8]>,
) -> Result<tokio::sync::RwLockReadGuard<'static, ()>, Response> {
    let guard = crate::sandbox::MOUNT_GATE.read().await;
    let s = sandbox.lock().await;
    if !s.mount_active {
        return Err(Response::err(
            "exec",
            anyhow::anyhow!("no SandFS mounted (exec/file requires an active mount)"),
        ));
    }
    if let Some(identity) = identity {
        match warm_identity_verdict(s.mounted_volume.as_deref(), identity) {
            WarmIdentity::Match => {}
            WarmIdentity::Mismatch => {
                // The mounted volume's REAL (seed-derived) basename is a
                // host-side secret: the alias contract keeps it out of every
                // guest-pathable string. The sandlot forwards this error to
                // the agent verbatim, so the message must not name either
                // side — the named error code is the machine-readable signal.
                return Err(Response::err(
                    ERR_VOLUME_IDENTITY_MISMATCH,
                    anyhow::anyhow!(
                        "warm op volume identity does not match the mounted volume; refusing without executing (sandlot bookkeeping skew)"
                    ),
                ));
            }
            WarmIdentity::Missing => {
                // An empty field is a bookkeeping/protocol failure: the
                // caller cannot name the volume it believes is mounted, so
                // executing would run inside whatever happens to be there.
                // The cold combined ops are the only legitimate no-identity
                // callers and they pass `None` (this arm is reachable only
                // from an actual empty field). Refuse by name, without
                // naming either volume.
                return Err(Response::err(
                    ERR_VOLUME_IDENTITY_MISSING,
                    anyhow::anyhow!(
                        "warm op carries no mounted-volume identity; refusing without executing (sandlot bookkeeping failure)"
                    ),
                ));
            }
        }
    }
    Ok(guard)
}

/// async_exec wrapper: spawn a background exec, return exec_id in stdout.
async fn async_exec(
    logger: &Logger,
    command: &str,
    agent_cgroup_path: Option<&str>,
    bg_execs: &Arc<tokio::sync::Mutex<HashMap<String, crate::sandbox::BgExec>>>,
    install_packages: bool,
    mount_generation: u64,
) -> Response {
    match crate::exec::start_exec(
        logger,
        command,
        agent_cgroup_path,
        bg_execs,
        install_packages,
        mount_generation,
    )
    .await
    {
        Ok(exec_id) => Response {
            version: PROTOCOL_VERSION,
            code: CODE_OK,
            exit_code: 0,
            stdout: exec_id.into_bytes(),
            stderr: Vec::new(),
            mounted: Vec::new(),
            exec_duration_ns: 0,
        },
        Err(e) => Response::err("async_exec", e),
    }
}

/// status_exec wrapper: return liveness code + log tail.
async fn status_exec(
    logger: &Logger,
    exec_id: &str,
    bg_execs: &Arc<tokio::sync::Mutex<HashMap<String, crate::sandbox::BgExec>>>,
    mount_generation: u64,
) -> Response {
    match crate::exec::status_exec(logger, exec_id, bg_execs, mount_generation).await {
        Ok((code, tail)) => Response {
            version: PROTOCOL_VERSION,
            code,
            exit_code: 0,
            stdout: tail,
            stderr: Vec::new(),
            mounted: Vec::new(),
            exec_duration_ns: 0,
        },
        Err(e) => Response::err("status_exec", e),
    }
}

/// kill_exec wrapper: kill a background exec by exec_id.
async fn kill_exec(
    logger: &Logger,
    exec_id: &str,
    bg_execs: &Arc<tokio::sync::Mutex<HashMap<String, crate::sandbox::BgExec>>>,
    mount_generation: u64,
) -> Response {
    match crate::exec::kill_exec(logger, exec_id, bg_execs, mount_generation).await {
        Ok(code) => Response {
            version: PROTOCOL_VERSION,
            code,
            exit_code: 0,
            stdout: Vec::new(),
            stderr: Vec::new(),
            mounted: Vec::new(),
            exec_duration_ns: 0,
        },
        Err(e) => Response::err("kill_exec", e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio_vsock::{VMADDR_CID_HYPERVISOR, VMADDR_CID_LOCAL};
    use warden::frame_parse::{parse_fields, MAX_FIELDS};

    fn test_logger() -> Logger {
        Logger::root(slog::Discard, slog::o!())
    }

    /// Unit tests exercise the fold/heal bookkeeping; the production probe is
    /// a FUSE lookup against the mounted virtio-fs share, unavailable here.
    fn fake_probe(_l: &Logger, _a: &str) -> anyhow::Result<crate::mount::RootAnchor> {
        crate::mount::RootAnchor::open("/tmp", _l)
            .ok_or_else(|| anyhow::anyhow!("test anchor unavailable"))
    }

    // ── protocol version gate ──────────────────────────────────────

    #[test]
    fn version_gate_accepts_supported_range() {
        // Every version in [PROTOCOL_MIN_ACCEPTED, PROTOCOL_VERSION] is
        // accepted — the inclusive boundaries included.
        for v in PROTOCOL_MIN_ACCEPTED..=PROTOCOL_VERSION {
            assert!(version_supported(v), "version {v} must be supported");
        }
    }

    #[test]
    fn version_gate_rejects_out_of_range() {
        // 0 is "unset / pre-versioning build"; above the current version is a
        // newer client than this warden. Both are rejected (fail fast), and
        // the subtraction stays panic-free (u8::MIN has no predecessor).
        assert!(!version_supported(0));
        assert!(!version_supported(PROTOCOL_VERSION.saturating_add(1)));
        if PROTOCOL_MIN_ACCEPTED > 0 {
            assert!(!version_supported(PROTOCOL_MIN_ACCEPTED - 1));
        }
        assert!(!version_supported(u8::MAX));
    }

    // ── vsock transport DoS bounds ─────────────────────────────────

    #[test]
    fn conn_cap_semantics() {
        // The count passed is the connection ABOUT to be served (the accept
        // loop reserves with fetch_add BEFORE this decision): under a cap of
        // 16, connections 1..=16 are allowed, the 17th is not.
        assert!(conn_allowed(1, 16));
        assert!(conn_allowed(16, 16));
        assert!(!conn_allowed(17, 16));
    }

    #[test]
    fn key_delivery_is_one_shot_and_failure_closes() {
        // First successful delivery: keep serving.
        assert!(!delivery_connection_done(false, CODE_OK));
        // Duplicate delivery: close (one-shot handshake).
        assert!(delivery_connection_done(true, CODE_OK));
        // Failed delivery (bad key/non-host/malformed): close, never park an
        // unauthenticated slot.
        assert!(delivery_connection_done(false, CODE_TRANSPORT_ERROR));
        assert!(delivery_connection_done(false, CODE_APP_ERROR));
    }

    #[test]
    fn misbehavior_gate_first_immediate_then_window_suppression() {
        let reset = |cat: Misbehavior| {
            let s = &MISBEHAVIOR[cat.idx()];
            s.last_ms.store(0, Ordering::Release);
            s.suppressed.store(0, Ordering::Release);
        };
        reset(Misbehavior::AuthFailed);
        reset(Misbehavior::BodyBudget);

        // First event of a window prints immediately, carrying the (zero)
        // suppressed count.
        assert_eq!(misbehavior_gate(Misbehavior::AuthFailed), Some(0));
        // Events inside the window are suppressed and counted.
        for _ in 0..100 {
            assert_eq!(misbehavior_gate(Misbehavior::AuthFailed), None);
        }
        let auth = &MISBEHAVIOR[Misbehavior::AuthFailed.idx()];
        assert_eq!(auth.suppressed.load(Ordering::Acquire), 100);
        // A DIFFERENT category is independent: a keyless flooder cannot
        // suppress the auth-failure / connection-cap lines.
        assert_eq!(misbehavior_gate(Misbehavior::BodyBudget), Some(0));
        // Force the window closed by backdating the last-print time.
        let past = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
            - MISBEHAVIOR_LOG_WINDOW_MS
            - 1;
        auth.last_ms.store(past, Ordering::Release);
        // The next event prints the accumulated suppressed count and resets.
        assert_eq!(misbehavior_gate(Misbehavior::AuthFailed), Some(100));
        assert_eq!(auth.suppressed.load(Ordering::Acquire), 0);
        reset(Misbehavior::AuthFailed);
        reset(Misbehavior::BodyBudget);
    }

    #[test]
    fn body_reservation_acquire_release_and_exhaustion() {
        // The only BODY_BUDGET mutator among tests (cargo runs tests in
        // parallel within this module — this test owns the static for its
        // duration).
        BODY_BUDGET.store(1000, Ordering::Release);
        // Zero-byte bodies never reserve.
        let z = BodyReservation::acquire(0).unwrap();
        assert_eq!(BODY_BUDGET.load(Ordering::Acquire), 1000);
        drop(z);
        // Acquire subtracts; a request that does not fit is denied while a
        // smaller one still succeeds; drop restores.
        {
            let res = BodyReservation::acquire(600).unwrap();
            assert_eq!(BODY_BUDGET.load(Ordering::Acquire), 400);
            assert!(BodyReservation::acquire(500).is_none());
            let res2 = BodyReservation::acquire(400).unwrap();
            assert_eq!(BODY_BUDGET.load(Ordering::Acquire), 0);
            drop(res2);
            drop(res);
        }
        assert_eq!(BODY_BUDGET.load(Ordering::Acquire), 1000);
        // Larger than the whole budget: denied.
        assert!(BodyReservation::acquire(1001).is_none());
    }

    // ── heartbeat_op: countdown reset rule ────────────────────────

    #[test]
    fn test_heartbeat_op_resets_countdown() {
        // OP_MEM_STATS FROM THE HOST PEER is the only combination that
        // resets the countdown anchor.
        assert!(heartbeat_op(OP_MEM_STATS));
        assert!(heartbeat_resets_countdown(OP_MEM_STATS, VMADDR_CID_HOST));
    }

    #[test]
    fn test_heartbeat_from_non_host_peer_does_not_reset() {
        // A guest-originated heartbeat — any CID that is not the host: a
        // guest CID, the local/hypervisor aliases, the wildcard — must NOT
        // touch the anchor. Resetting it from inside the guest would defeat
        // the last-resort mount release and can lead to a double mount once
        // the platform re-places the sandfs.
        for cid in [
            3u32,
            4,
            1000,
            VMADDR_CID_LOCAL,
            VMADDR_CID_HYPERVISOR,
            VMADDR_CID_ANY,
        ] {
            assert!(
                !heartbeat_resets_countdown(OP_MEM_STATS, cid),
                "heartbeat from cid {cid} must not reset the countdown"
            );
        }
        // ...and no other op resets it, from any peer.
        for op in [
            OP_EXEC,
            OP_UNMOUNT,
            OP_MOUNT_AND_EXEC,
            OP_FILE,
            OP_ASYNC_EXEC,
        ] {
            assert!(!heartbeat_resets_countdown(op, VMADDR_CID_HOST));
        }
    }

    #[test]
    fn test_peer_gate_admits_only_the_host() {
        // The accept-time protocol gate: CID 2 (the sandlot, and every
        // host-side probe tool) is the only admitted peer. Guest CIDs, the
        // local/hypervisor aliases, and the wildcard are refused — a kernel
        // or backend drift that makes in-guest dialing reachable can then
        // still not speak the protocol.
        assert!(peer_allowed(VMADDR_CID_HOST));
        for cid in [
            3u32,
            4,
            1000,
            VMADDR_CID_LOCAL,
            VMADDR_CID_HYPERVISOR,
            VMADDR_CID_ANY,
        ] {
            assert!(!peer_allowed(cid), "peer cid {cid} must be refused");
        }
    }

    #[test]
    fn test_business_ops_do_not_reset_countdown() {
        // Mount/exec/unmount/file deliberately do NOT reset: they must not mask
        // a silent sandlot (the cached connection can be wedged while probes on
        // separate connections keep flowing).
        assert!(!heartbeat_op(OP_MOUNT_AND_EXEC));
        assert!(!heartbeat_op(OP_UNMOUNT));
        assert!(!heartbeat_op(OP_EXEC));
        assert!(!heartbeat_op(OP_ASYNC_EXEC));
        assert!(!heartbeat_op(OP_MOUNT_AND_ASYNC_EXEC));
        assert!(!heartbeat_op(OP_STATUS_EXEC));
        assert!(!heartbeat_op(OP_KILL_EXEC));
        assert!(!heartbeat_op(OP_FILE));
    }

    // ── countdown_expired / should_exit_vm ────────────────────────

    #[test]
    fn test_countdown_not_expired_when_recent_heartbeat() {
        let last = Instant::now();
        let now = Instant::now();
        assert!(!countdown_expired(last, now, Duration::from_secs(300)));
    }

    #[test]
    fn test_countdown_expired_after_warden_countdown() {
        // Last heartbeat 301s ago, countdown 300s → expired.
        let last = Instant::now() - Duration::from_secs(301);
        let now = Instant::now();
        assert!(countdown_expired(last, now, Duration::from_secs(300)));
    }

    #[test]
    fn test_should_exit_vm_expired_and_mounted() {
        let last = Instant::now() - Duration::from_secs(301);
        assert!(should_exit_vm(
            last,
            Instant::now(),
            true,
            Duration::from_secs(300)
        ));
    }

    #[test]
    fn test_should_exit_vm_expired_but_not_mounted() {
        // Unmounted → no-op: clean VMs survive into the reconnect reconcile.
        let last = Instant::now() - Duration::from_secs(301);
        assert!(!should_exit_vm(
            last,
            Instant::now(),
            false,
            Duration::from_secs(300)
        ));
    }

    #[test]
    fn test_should_exit_vm_mounted_but_heartbeat_recent() {
        // Fresh heartbeat → not expired, even with a live mount.
        let last = Instant::now();
        assert!(!should_exit_vm(
            last,
            Instant::now(),
            true,
            Duration::from_secs(300)
        ));
    }

    // ── flash disconnect / reconnect recovery ─────────────────────

    #[test]
    fn test_flash_disconnect_reconnect_recovers() {
        // Flash disconnect: sandlot stops heartbeating briefly, then reconnects
        // and resumes probes. The countdown is anchored at the last heartbeat —
        // once probes resume (heartbeat_op resets last_heartbeat) the countdown
        // restarts and the VM is not released.
        let t0 = Instant::now();
        // sandlot stops probing for a while (well under warden_countdown)...
        let t1 = t0 + Duration::from_secs(60);
        assert!(!countdown_expired(t0, t1, Duration::from_secs(300)));
        // ...reconnect: heartbeat resets the anchor to t1.
        let t2 = t1 + Duration::from_secs(120);
        assert!(!countdown_expired(t1, t2, Duration::from_secs(300)));
        // Still far from expiry at t1+220s.
        let t3 = t2 + Duration::from_secs(100);
        assert!(!countdown_expired(t2, t3, Duration::from_secs(300)));
    }

    #[test]
    fn unmount_runs_when_a_partial_mount_is_recorded_dirty() {
        // No active mount and no dirty record: nothing to detach.
        assert!(unmount_has_nothing_to_do(false, false));
        // A failed mount recorded dirty MUST run the teardown even though
        // mount_active is false — the forced flag selects the method, not
        // whether dirty work remains.
        assert!(!unmount_has_nothing_to_do(false, true));
        // An identity-bound unmount on an active mount always runs.
        assert!(!unmount_has_nothing_to_do(true, false));
        assert!(!unmount_has_nothing_to_do(true, true));
    }

    #[test]
    fn test_unmount_op_does_not_reset_but_no_exit_when_unmounted() {
        // A cleanup OP_UNMOUNT does not reset the countdown (heartbeat_op rule);
        // but once unmounted the countdown no-ops, so the VM survives.
        let last = Instant::now() - Duration::from_secs(301);
        assert!(!heartbeat_op(OP_UNMOUNT)); // unmount doesn't reset
        assert!(!should_exit_vm(
            last,
            Instant::now(),
            false,
            Duration::from_secs(300)
        )); // unmounted → no exit
    }

    // ── parse_fields: wire frame robustness ──────────────────────────

    /// Encode a sequence of fields into a body ([u32 len][bytes] per field).
    fn encode_body(fields: &[&[u8]]) -> Vec<u8> {
        let mut body = Vec::new();
        for f in fields {
            body.extend_from_slice(&(f.len() as u32).to_be_bytes());
            body.extend_from_slice(f);
        }
        body
    }

    #[test]
    fn parse_fields_empty_body() {
        // No fields — valid (an op with no args).
        assert!(parse_fields(&[]).unwrap().is_empty());
    }

    #[test]
    fn parse_fields_single() {
        let body = encode_body(&[b"hello"]);
        let fields = parse_fields(&body).unwrap();
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0], b"hello");
    }

    #[test]
    fn parse_fields_multiple_preserves_order() {
        // Field order is op-specific (e.g. MOUNT_AND_EXEC: device, mount_point,
        // fs_type, command, timeout, install). Order must be preserved exactly.
        let body = encode_body(&[b"dev", b"/mnt/rootfs", b"none", b"echo hi"]);
        let fields = parse_fields(&body).unwrap();
        assert_eq!(
            fields
                .iter()
                .map(|f| String::from_utf8_lossy(f).into_owned())
                .collect::<Vec<_>>(),
            vec!["dev", "/mnt/rootfs", "none", "echo hi"]
        );
    }

    #[test]
    fn parse_fields_empty_field_is_valid() {
        // A zero-length field is legal (e.g. install_packages="" for strict
        // mode). It must be parsed as an empty Vec, not rejected.
        let body = encode_body(&[b"", b"x"]);
        let fields = parse_fields(&body).unwrap();
        assert_eq!(fields.len(), 2);
        assert!(fields[0].is_empty());
        assert_eq!(fields[1], b"x");
    }

    #[test]
    fn parse_fields_truncated_length_header_rejected() {
        // Body ends with 1-3 bytes — not enough for a 4-byte length header.
        // Previously this was silently ignored (loop condition `pos+4 <=
        // body.len()`); now it must error so a truncated frame cannot be
        // executed as a shorter request.
        let mut body = encode_body(&[b"ok"]);
        body.push(0xAB); // dangling 1 byte, no full length header
        let err = parse_fields(&body).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn parse_fields_field_length_past_end_rejected() {
        // A field declares more bytes than the body holds. Must error, not
        // silently drop the field (which could default a missing arg).
        let mut body = Vec::new();
        body.extend_from_slice(&100u32.to_be_bytes()); // flen=100
        body.extend_from_slice(b"short"); // only 5 bytes follow
        let err = parse_fields(&body).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn parse_fields_no_dangling_bytes_after_fields() {
        // Two complete fields, then a dangling partial header (3 bytes).
        let mut body = encode_body(&[b"a", b"b"]);
        body.extend_from_slice(&[0, 0, 0]); // 3 bytes, no full length header
        let err = parse_fields(&body).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    // ── field(): missing-field default ───────────────────────────────

    #[test]
    fn field_missing_returns_empty() {
        // A request with fewer fields than the op expects: field() returns ""
        // rather than panicking. The op dispatch treats "" per its semantics
        // (e.g. install_packages="" → strict mode, timeout="" → default).
        // Only command, no timeout/install fields.
        let req = request(OP_EXEC, &[b"echo hi"]);
        assert_eq!(field(&req, 0), "echo hi");
        assert_eq!(field(&req, 1), ""); // missing timeout → default
        assert_eq!(field(&req, 2), ""); // missing install → strict
        assert_eq!(field(&req, 99), ""); // way out of range
    }

    // ── OP_FILE sub_op: empty-field safety ───────────────────────────

    #[test]
    fn file_sub_op_from_empty_field_is_zero_not_panic() {
        // A malformed OP_FILE frame with an empty sub-op field must degrade to
        // sub_op=0 (unknown → error response), NOT panic on v[0]. PID 1 must
        // never die from a bad frame.
        let req = request(OP_FILE, &[b"", b"somepath"]);
        let sub_op = req.field_bytes(0).first().copied().unwrap_or(0);
        assert_eq!(sub_op, 0); // unknown sub_op → dispatched as error, no panic
    }

    // ── encode_response_header: wire layout ─────────────────────────

    #[test]
    fn encode_response_header_layout() {
        // Verify the exact byte layout of the 60-byte response header:
        // [magic(4)][version(1)][code(1)][exit_code(1)][reserved(1)][stdout_len(4)][stderr_len(4)][exec_duration_ns(8)][mounted_len(4)][tag(32)]
        let resp = Response {
            version: PROTOCOL_VERSION,
            code: CODE_OK,
            exit_code: 42,
            stdout: vec![0xAB; 10],
            stderr: vec![0xCD; 5],
            mounted: b"sandfs-xy".to_vec(),
            exec_duration_ns: 0x0123_4567_89AB_CDEF,
        };
        let hdr = encode_response_header(&resp, &[0u8; NONCE_LEN]);
        assert_eq!(&hdr[0..4], &MAGIC.to_be_bytes());
        assert_eq!(hdr[4], PROTOCOL_VERSION);
        assert_eq!(hdr[5], CODE_OK);
        assert_eq!(hdr[6], 42);
        assert_eq!(hdr[7], 0); // reserved
        assert_eq!(u32::from_be_bytes([hdr[8], hdr[9], hdr[10], hdr[11]]), 10);
        assert_eq!(u32::from_be_bytes([hdr[12], hdr[13], hdr[14], hdr[15]]), 5);
        assert_eq!(
            u64::from_be_bytes([
                hdr[16], hdr[17], hdr[18], hdr[19], hdr[20], hdr[21], hdr[22], hdr[23]
            ]),
            0x0123_4567_89AB_CDEF
        );
        assert_eq!(u32::from_be_bytes([hdr[24], hdr[25], hdr[26], hdr[27]]), 9);
        // The tag is the last 32 bytes and must not be all-zero for a real
        // response (the key is set by the test process in this module only
        // when AGENT_CONFIG is initialized; a zero tag is still a valid
        // 32-byte field, so assert only the length here).
        assert_eq!(hdr.len(), RESP_HEADER_LEN);
    }

    #[test]
    fn encode_response_header_total_length_60() {
        // The header MUST stay 60 bytes so the sandlot client's respHeaderLen
        // constant stays valid. Pre-production policy (see the constant's doc
        // above): the layout evolves freely with sandlot + initramfs shipping
        // together — change this, respHeaderLen, and this test in one commit.
        let resp = Response::ok();
        assert_eq!(
            encode_response_header(&resp, &[0u8; NONCE_LEN]).len(),
            RESP_HEADER_LEN
        );
    }

    // ── ensure_mounted_once: concurrent cold-mount dedup + identity ────

    fn test_sandbox() -> Arc<Mutex<Sandbox>> {
        let logger = slog::Logger::root(slog::Discard, slog::o!());
        Arc::new(Mutex::new(Sandbox::new(&logger).expect("sandbox")))
    }

    fn test_bg_execs() -> Arc<Mutex<HashMap<String, crate::sandbox::BgExec>>> {
        Arc::new(Mutex::new(HashMap::new()))
    }

    #[tokio::test]
    async fn mount_generation_advances_on_each_mount_state_transition() {
        // Background execs are stamped with this value and status/kill
        // resolve only within the current generation, so every transition
        // (mount, unmount) must advance it exactly once.
        let sb = test_sandbox();
        assert_eq!(sb.lock().await.mount_generation, 0);
        set_mount_active(&sb, true).await;
        assert_eq!(sb.lock().await.mount_generation, 1);
        // A redundant "active" (the cold-mount dedup path) is not a new
        // generation: the same mount's execs stay resolvable.
        set_mount_active(&sb, true).await;
        assert_eq!(sb.lock().await.mount_generation, 1);
        set_mount_active(&sb, false).await;
        assert_eq!(sb.lock().await.mount_generation, 2);
        set_mount_active(&sb, false).await;
        assert_eq!(sb.lock().await.mount_generation, 2);
    }

    /// Counting mount closure: increments `attempts`, optionally sleeps to
    /// widen the dedup window, then returns `ok`.
    async fn counting_mount(
        attempts: Arc<std::sync::atomic::AtomicUsize>,
        delay_ms: u64,
        ok: bool,
    ) -> Result<(), anyhow::Error> {
        attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if delay_ms > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
        }
        if ok {
            Ok(())
        } else {
            Err(anyhow::anyhow!("mount failed"))
        }
    }

    #[tokio::test]
    async fn cold_mount_dedup_runs_mount_once() {
        let sb = test_sandbox();
        let bg = test_bg_execs();
        let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut handles = Vec::new();
        for _ in 0..4 {
            let sb = sb.clone();
            let bg = bg.clone();
            let attempts = attempts.clone();
            handles.push(tokio::spawn(async move {
                // 4 parallel cold mounts of the SAME volume racing the same
                // write gate: exactly ONE mount_workspace call may run (the
                // widen sleep makes the dedup window explicit).
                ensure_mounted_once(&sb, &bg, &test_logger(), "sandfs-a", fake_probe, move |_vol| {
                    counting_mount(attempts, 20, true)
                })
                .await
            }));
        }
        for h in handles {
            h.await.unwrap().unwrap();
        }
        assert_eq!(
            attempts.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "mount_workspace must run exactly once across concurrent cold mounts"
        );
        assert!(sb.lock().await.mount_active);
        assert_eq!(
            sb.lock().await.mounted_volume.as_deref(),
            Some("sandfs-a"),
            "identity must be recorded from the device_path basename"
        );
    }

    #[tokio::test]
    #[ignore = "requires root: the self-heal path performs real mount/unmount cleanup"]
    async fn cold_mount_failure_leaves_inactive_and_retryable() {
        // The failed mount is recorded dirty, so the RETRY below runs the
        // stale-mount self-heal — unmount_workspace's fallback path, whose
        // global reap_zombie(WNOHANG|__WALL) loop harvests process-wide
        // zombies. Hold the suite's proc lock or it steals a sibling test's
        // probe children (a strace + addr2line session localized exactly
        // this theft).
        let _proc_guard = crate::test_sync::proc_lock();
        let sb = test_sandbox();
        let bg = test_bg_execs();
        let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let a1 = attempts.clone();
        let r = ensure_mounted_once(&sb, &bg, &test_logger(), "sandfs-a", fake_probe, move |_vol| {
            counting_mount(a1, 0, false)
        })
        .await;
        assert!(r.is_err());
        // Failure must NOT set mount_active: a retry attempts again instead of
        // being skipped as an already-mounted duplicate.
        assert!(!sb.lock().await.mount_active);
        assert!(sb.lock().await.mounted_volume.is_none());
        let r = ensure_mounted_once(&sb, &bg, &test_logger(), "sandfs-a", fake_probe, |_vol| async {
            Ok::<(), anyhow::Error>(())
        })
        .await;
        assert!(r.is_ok());
        assert!(sb.lock().await.mount_active);
        assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn same_volume_dedup_skips_without_remount() {
        // Warm duplicate (same identity, mount_active): zero additional mount
        // calls, identity unchanged.
        let sb = test_sandbox();
        let bg = test_bg_execs();
        let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let a1 = attempts.clone();
        ensure_mounted_once(&sb, &bg, &test_logger(), "sandfs-a", fake_probe, move |_vol| {
            counting_mount(a1, 0, true)
        })
        .await
        .unwrap();
        let a2 = attempts.clone();
        let id = ensure_mounted_once(&sb, &bg, &test_logger(), "sandfs-a", fake_probe, move |_vol| {
            counting_mount(a2, 0, true)
        })
        .await
        .unwrap();
        assert_eq!(id, "sandfs-a");
        assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test]
    #[ignore = "requires root: the self-heal path performs real mount/unmount cleanup"]
    async fn different_volume_self_heals_instead_of_dedup_skip() {
        // The heal below runs unmount_workspace (fallback path): its global
        // reap loop is process-wide, so the suite's proc lock is mandatory.
        let _proc_guard = crate::test_sync::proc_lock();
        // The shadow-mount scenario: /mnt/rootfs holds sandfs-a (twisted by an
        // out-of-band mount-only), a mount for sandfs-b arrives. The stale
        // mount must be TORN DOWN (heal) and sandfs-b mounted — a dedup-skip
        // would run B's exec inside A's rootfs. The heal's unmount runs on a
        // never-mounted temp path (EINVAL → idempotent success), so the
        // observable effect here is: heal completed, mount ran for B,
        // identity now B.
        let sb = test_sandbox();
        let bg = test_bg_execs();
        let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let a1 = attempts.clone();
        ensure_mounted_once(&sb, &bg, &test_logger(), "sandfs-a", fake_probe, move |_vol| {
            counting_mount(a1, 0, true)
        })
        .await
        .unwrap();
        let mounts_before = attempts.load(std::sync::atomic::Ordering::SeqCst);
        assert_eq!(mounts_before, 1);
        let a2 = attempts.clone();
        let id = ensure_mounted_once(&sb, &bg, &test_logger(), "sandfs-b", fake_probe, move |_vol| {
            counting_mount(a2, 0, true)
        })
        .await
        .expect("identity mismatch must self-heal, not fail");
        assert_eq!(id, "sandfs-b");
        assert_eq!(
            attempts.load(std::sync::atomic::Ordering::SeqCst),
            2,
            "the heal must be followed by a real mount of the requested volume"
        );
        assert!(sb.lock().await.mount_active);
        assert_eq!(sb.lock().await.mounted_volume.as_deref(), Some("sandfs-b"));
    }

    #[tokio::test]
    #[ignore = "requires root: the self-heal path performs real mount/unmount cleanup"]
    async fn heal_mount_failure_leaves_unmounted_and_retryable() {
        // Heal succeeded but the requested volume fails to mount: mount_active
        // stays false (retryable) — the stale volume must NOT be reported as
        // still-good.
        //
        // The heal runs unmount_workspace (fallback path): its global reap
        // loop is process-wide, so the suite's proc lock is mandatory.
        let _proc_guard = crate::test_sync::proc_lock();
        let sb = test_sandbox();
        let bg = test_bg_execs();
        let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let a1 = attempts.clone();
        ensure_mounted_once(&sb, &bg, &test_logger(), "sandfs-a", fake_probe, move |_vol| {
            counting_mount(a1, 0, true)
        })
        .await
        .unwrap();
        let a2 = attempts.clone();
        let r = ensure_mounted_once(&sb, &bg, &test_logger(), "sandfs-b", fake_probe, move |_vol| {
            counting_mount(a2, 0, false)
        })
        .await;
        assert!(r.is_err());
        assert!(!sb.lock().await.mount_active);
        assert!(sb.lock().await.mounted_volume.is_none());
    }

    // ── warm-op mounted-volume identity ────────────────────────────────

    /// Build a Request the way read_request would: encode the fields into a
    /// wire body and parse their spans back out of it (so the test exercises
    /// the same body/spans representation the dispatch path uses).
    fn request(op: u8, fields: &[&[u8]]) -> Request {
        let mut body = Vec::new();
        let mut field_spans = Vec::with_capacity(fields.len());
        for f in fields {
            let start = body.len() + 4;
            body.extend_from_slice(&(f.len() as u32).to_be_bytes());
            body.extend_from_slice(f);
            field_spans.push(start..start + f.len());
        }
        assert_eq!(
            parse_field_spans(&body).expect("test body must parse"),
            field_spans
        );
        Request {
            op,
            version: PROTOCOL_VERSION,
            nonce: [0u8; NONCE_LEN],
            body_mac: [0u8; BODY_MAC_LEN],
            body,
            field_spans,
            _budget: None,
        }
    }

    #[test]
    fn body_mac_binds_mount_fields_and_identity() {
        let key = [0x11u8; 32];
        let nonce = [0u8; NONCE_LEN];
        let fields: [&[u8]; 7] = [
            b"gen0",
            b"/mnt/rootfs",
            b"none",
            b"echo hi",
            b"0",
            b"0",
            b"flat",
        ];
        let good = crate::auth::body_mac(
            &key,
            &nonce,
            OP_MOUNT_AND_EXEC,
            &[fields[0], fields[1], fields[6]],
        );
        assert!(verify_body_mac_with_key(&key, OP_MOUNT_AND_EXEC, &fields, &nonce, &good).is_ok());

        // Rewriting the mount point (the hostile-mount-point injection) or the
        // volume mode invalidates a MAC computed over the original fields.
        let tampered_mp: [&[u8]; 7] = [
            fields[0],
            b"/sys/fs/cgroup",
            fields[2],
            fields[3],
            fields[4],
            fields[5],
            fields[6],
        ];
        assert!(
            verify_body_mac_with_key(&key, OP_MOUNT_AND_EXEC, &tampered_mp, &nonce, &good).is_err()
        );
        let tampered_mode: [&[u8]; 7] = [
            fields[0],
            fields[1],
            fields[2],
            fields[3],
            fields[4],
            fields[5],
            b"overlay",
        ];
        assert!(
            verify_body_mac_with_key(&key, OP_MOUNT_AND_EXEC, &tampered_mode, &nonce, &good)
                .is_err()
        );

        // Warm-op mounted-volume identity: same rule.
        let warm: [&[u8]; 4] = [b"echo hi", b"0", b"", b"sf-alice"];
        let warm_mac = crate::auth::body_mac(&key, &nonce, OP_EXEC, &[warm[3]]);
        assert!(verify_body_mac_with_key(&key, OP_EXEC, &warm, &nonce, &warm_mac).is_ok());
        let warm_tampered: [&[u8]; 4] = [warm[0], warm[1], warm[2], b"sf-bob"];
        assert!(
            verify_body_mac_with_key(&key, OP_EXEC, &warm_tampered, &nonce, &warm_mac).is_err()
        );

        // OP_UNMOUNT binds mount_point/identity/forced [0,1,2]: flipping ANY
        // of the three (forced would otherwise let a peer force-unmount the
        // current tenant) must invalidate the MAC.
        let unmount: [&[u8]; 3] = [b"/mnt/rootfs", b"gen0", b"1"];
        let unmount_mac = crate::auth::body_mac(&key, &nonce, OP_UNMOUNT, &unmount);
        assert!(
            verify_body_mac_with_key(&key, OP_UNMOUNT, &unmount, &nonce, &unmount_mac).is_ok()
        );
        for (field, tampered) in [
            (0usize, [b"/sys".as_slice(), b"gen0", b"1"]),
            (1, [b"/mnt/rootfs", b"gen1", b"1"]),
            (2, [b"/mnt/rootfs", b"gen0", b"0"]),
        ] {
            assert!(
                verify_body_mac_with_key(&key, OP_UNMOUNT, &tampered, &nonce, &unmount_mac).is_err(),
                "OP_UNMOUNT field {field} is not covered by the body MAC"
            );
        }

        // Ops with no bound field accept any MAC (the field is unused).
        let no_fields: [&[u8]; 0] = [];
        assert!(
            verify_body_mac_with_key(
                &key,
                OP_MEM_STATS,
                &no_fields,
                &nonce,
                &[0xAA; BODY_MAC_LEN]
            )
            .is_ok()
        );
    }

    /// A sandbox that reports a live mount of `volume` — the state a
    /// successful ensure_mounted_once leaves behind.
    async fn sandbox_holding_volume(volume: &str) -> Arc<Mutex<Sandbox>> {
        let sb = test_sandbox();
        {
            let mut s = sb.lock().await;
            s.mount_active = true;
            s.mounted_volume = Some(volume.to_string());
        }
        sb
    }

    #[test]
    fn warm_identity_verdict_semantics() {
        // Match: the field names the held volume.
        assert_eq!(
            warm_identity_verdict(Some("sandfs-a"), b"sandfs-a"),
            WarmIdentity::Match
        );
        // Mismatch: a different volume — the exact skew this check exists for.
        assert_eq!(
            warm_identity_verdict(Some("sandfs-a"), b"sandfs-b"),
            WarmIdentity::Mismatch
        );
        // Empty field: no identity claim → fail closed (Missing).
        assert_eq!(
            warm_identity_verdict(Some("sandfs-a"), b""),
            WarmIdentity::Missing
        );
        assert_eq!(warm_identity_verdict(None, b""), WarmIdentity::Missing);
        // Nothing held but a claim made: cannot confirm → refuse (conservative).
        assert_eq!(
            warm_identity_verdict(None, b"sandfs-a"),
            WarmIdentity::Mismatch
        );
        // Garbage bytes never match a real basename.
        assert_eq!(
            warm_identity_verdict(Some("sandfs-a"), b"sandfs-\xff"),
            WarmIdentity::Mismatch
        );
    }

    #[test]
    fn warm_identity_field_positions_are_pinned() {
        // Wire ABI shared with the sandlot's field builders (client.go
        // appendVolumeIdentity / fileOpVolumeIdentityIndex). Moving a position
        // here without moving it there silently disables the whole assertion
        // (the warden would read an empty field and fail closed as Missing), so
        // the numbers are pinned literally.
        assert_eq!(IDX_EXEC_VOLUME, 3);
        assert_eq!(IDX_ASYNC_EXEC_VOLUME, 2);
        assert_eq!(IDX_FILE_VOLUME, 5);
    }

    #[tokio::test]
    async fn warm_exec_identity_mismatch_is_a_named_refusal_and_never_execs() {
        // The identity pin: the warden holds one volume, the warm op claims
        // sandfs-b. The op must be REFUSED by name and the command must not be
        // attempted (the refusal is returned by the read guard, which runs
        // strictly before AgentService::do_exec — nothing spawns).
        let sb = sandbox_holding_volume("sandfs-a").await;
        // OP_EXEC wire order: 0 command, 1 timeout_ms, 2 install_packages,
        // 3 mounted-volume identity.
        let resp = dispatch(
            &sb,
            request(OP_EXEC, &[b"true", b"", b"", b"sandfs-b"]),
            VMADDR_CID_HOST,
        )
        .await;
        // Transport-error class: a failed RPC, never a result the sandlot
        // could mistake for the command's outcome.
        assert_eq!(resp.code, CODE_TRANSPORT_ERROR);
        let stderr = String::from_utf8_lossy(&resp.stderr);
        assert!(
            stderr.starts_with(ERR_VOLUME_IDENTITY_MISMATCH),
            "refusal must be named {ERR_VOLUME_IDENTITY_MISMATCH:?}, got {stderr:?}"
        );
        // The refusal must not disturb the warden's own bookkeeping — the
        // held volume is still what it was.
        assert_eq!(
            sb.lock().await.mounted_volume.as_deref(),
            Some("sandfs-a"),
            "a refused op must not clear or rewrite the mounted identity"
        );
    }

    #[tokio::test]
    async fn warm_exec_missing_identity_is_a_named_refusal_and_never_execs() {
        // An empty identity field is a bookkeeping failure: the caller cannot
        // name the volume it believes is mounted. Executing would run inside
        // whatever happens to be there, so the guard must refuse by name
        // before AgentService::do_exec is reached.
        let sb = sandbox_holding_volume("sandfs-a").await;
        let resp = dispatch(
            &sb,
            request(OP_EXEC, &[b"true", b"", b"", b""]),
            VMADDR_CID_HOST,
        )
        .await;
        assert_eq!(resp.code, CODE_TRANSPORT_ERROR);
        let stderr = String::from_utf8_lossy(&resp.stderr);
        assert!(
            stderr.starts_with(ERR_VOLUME_IDENTITY_MISSING),
            "refusal must be named {ERR_VOLUME_IDENTITY_MISSING:?}, got {stderr:?}"
        );
        assert_eq!(
            sb.lock().await.mounted_volume.as_deref(),
            Some("sandfs-a"),
            "a refused op must not clear or rewrite the mounted identity"
        );
    }

    #[tokio::test]
    async fn warm_ops_refuse_empty_identity_but_accept_no_field() {
        let sb = sandbox_holding_volume("sandfs-a").await;
        // Matching identity: proceed.
        assert!(mount_read_guard(&sb, Some(b"sandfs-a")).await.is_ok());
        // Empty field (unnamed mount): fail closed by name.
        let err = mount_read_guard(&sb, Some(b""))
            .await
            .expect_err("an empty identity field must be refused");
        assert_eq!(err.code, CODE_TRANSPORT_ERROR);
        assert!(
            String::from_utf8_lossy(&err.stderr).starts_with(ERR_VOLUME_IDENTITY_MISSING),
            "refusal must be named {ERR_VOLUME_IDENTITY_MISSING:?}, got {:?}",
            String::from_utf8_lossy(&err.stderr)
        );
        // No field by design (cold combined mount op): proceed unchecked.
        assert!(mount_read_guard(&sb, None).await.is_ok());
        // No mount at all: refused regardless of identity (existing behavior).
        let empty = test_sandbox();
        assert!(mount_read_guard(&empty, None).await.is_err());
    }

    #[tokio::test]
    async fn cold_exec_identity_refuses_a_swap_between_mount_and_exec() {
        // The cold mount+exec gap (mount gate released when
        // ensure_mounted_once returns): a concurrent cold mount for another
        // volume can self-heal the mount before this op's exec. The cold ops
        // must therefore pass the volume they just mounted as the identity —
        // the same guard the warm paths use. Pin the verdict: with B held,
        // the identity an OP_MOUNT_AND_EXEC for A would pass is refused by
        // name, and the matching identity still proceeds.
        let sb = sandbox_holding_volume("sandfs-b").await;
        let err = mount_read_guard(&sb, Some(b"sandfs-a"))
            .await
            .expect_err("a cold exec whose volume was swapped away must be refused");
        assert_eq!(err.code, CODE_TRANSPORT_ERROR);
        assert!(
            String::from_utf8_lossy(&err.stderr).starts_with(ERR_VOLUME_IDENTITY_MISMATCH),
            "refusal must be named {ERR_VOLUME_IDENTITY_MISMATCH:?}, got {:?}",
            String::from_utf8_lossy(&err.stderr)
        );
        // The op that mounted B itself still proceeds.
        assert!(mount_read_guard(&sb, Some(b"sandfs-b")).await.is_ok());
        // And the refusal did not disturb the held identity.
        assert_eq!(sb.lock().await.mounted_volume.as_deref(), Some("sandfs-b"));
    }

    #[tokio::test]
    async fn warm_file_op_refuses_mismatch_at_the_pinned_position() {
        // The OP_FILE identity sits at field 5 (its op-specific fields end at
        // 4); a mismatch there must refuse too — file ops resolve paths inside
        // the mounted volume.
        let sb = sandbox_holding_volume("sandfs-a").await;
        let req = request(
            OP_FILE,
            &[
                &[crate::files::SUB_OP_STAT],
                b"x",
                b"",
                b"",
                b"",
                b"sandfs-b",
            ],
        );
        let resp = dispatch(&sb, req, VMADDR_CID_HOST).await;
        assert_eq!(resp.code, CODE_TRANSPORT_ERROR);
        assert!(String::from_utf8_lossy(&resp.stderr).starts_with(ERR_VOLUME_IDENTITY_MISMATCH));
    }

    #[tokio::test]
    async fn warm_async_exec_refuses_mismatch_at_the_pinned_position() {
        // Driven through the guard (not dispatch): the assertion is about the
        // field POSITION (OP_ASYNC_EXEC = index 2), and this way the check is
        // proven to sit in front of the async spawn.
        let sb = sandbox_holding_volume("sandfs-a").await;
        let req = request(OP_ASYNC_EXEC, &[b"true", b"", b"sandfs-b"]);
        let res = mount_read_guard(&sb, Some(field_bytes(&req, IDX_ASYNC_EXEC_VOLUME))).await;
        let err = res.expect_err("mismatch must be refused");
        assert!(
            String::from_utf8_lossy(&err.stderr).starts_with(ERR_VOLUME_IDENTITY_MISMATCH),
            "refusal must be named, got {:?}",
            String::from_utf8_lossy(&err.stderr)
        );
    }

    /// The gate accepts the current wire shape end-to-end: the version byte is
    /// inside the accepted window, and the identity field carried by a warm op
    /// does not disturb field parsing (command/timeout/packages still read from
    /// their own indices).
    #[test]
    fn warm_op_field_parsing_stay_stable() {
        assert!(version_supported(PROTOCOL_VERSION));
        assert_eq!(PROTOCOL_MIN_ACCEPTED, PROTOCOL_VERSION);
        let req = request(OP_EXEC, &[b"echo hi", b"1500", b"1", b"sandfs-a"]);
        assert_eq!(field(&req, 0), "echo hi");
        assert_eq!(field(&req, 1), "1500");
        assert_eq!(field(&req, 2), "1");
        assert_eq!(field_bytes(&req, IDX_EXEC_VOLUME), &b"sandfs-a"[..]);
        // A frame that omits the field reads as empty (Missing → refused).
        let short = request(OP_EXEC, &[b"echo hi", b"1500", b"1"]);
        assert!(field_bytes(&short, IDX_EXEC_VOLUME).is_empty());
    }

    #[test]
    fn encode_response_header_each_code() {
        // Every code value must round-trip into the header's code byte.
        for &code in &[
            CODE_OK,
            CODE_APP_ERROR,
            CODE_TRANSPORT_ERROR,
            CODE_BG_RUNNING,
            CODE_BG_KILLED,
            CODE_BG_NOT_FOUND,
            CODE_TIMED_OUT,
        ] {
            let resp = Response {
                version: PROTOCOL_VERSION,
                code,
                exit_code: 0,
                stdout: Vec::new(),
                stderr: Vec::new(),
                mounted: Vec::new(),
                exec_duration_ns: 0,
            };
            assert_eq!(
                encode_response_header(&resp, &[0u8; NONCE_LEN])[5],
                code
            );
        }
    }

    // ── validate_mount_point: protocol hardening ────────────────────

    #[test]
    fn mount_point_exact_match_accepted() {
        assert!(validate_mount_point(crate::mount::MOUNT_POINT));
        assert!(validate_mount_point("/mnt/rootfs"));
    }

    #[test]
    fn mount_point_hijack_attempts_rejected() {
        // A hostile in-guest process steering the mount elsewhere must be
        // refused — /sys/fs/cgroup shadowing defeats cgroup.kill; /proc
        // breaks the warden's own /proc; traversal forms must not slip
        // through either.
        for mp in [
            "/sys/fs/cgroup",
            "/proc",
            "/sys",
            "/dev",
            "/etc",
            "/tmp/sandswap-bg",
            "/mnt/rootfs/",
            "/mnt/rootfs/..",
            "mnt/rootfs",
            "",
            "/mnt/rootfs/.",
            "/mnt",
        ] {
            assert!(
                !validate_mount_point(mp),
                "mount_point {:?} must be rejected",
                mp
            );
        }
    }

    // ── validate_volume_mode: record-driven mount mode ──────────────

    #[test]
    fn volume_mode_record_values_accepted() {
        assert!(validate_volume_mode("flat"));
        assert!(validate_volume_mode("overlay"));
    }

    #[test]
    fn volume_mode_unknown_or_absent_rejected() {
        // The mode comes from the identity record; an absent/unknown value
        // must fail closed instead of defaulting to a layout probe (a flat
        // volume is agent-writable, so the probe is exactly the attack).
        for mode in [
            "", "FLAT", "Overlay", "flat ", "overlay/", "tmpfs", "dir", "auto",
        ] {
            assert!(
                !validate_volume_mode(mode),
                "volume_mode {:?} must be rejected",
                mode
            );
        }
    }

    // ── is_mount_only: empty-command mount semantics ────────────────

    #[test]
    fn mount_only_boundary() {
        // Empty command = mount-only (the cold FileOp path skips the exec).
        assert!(is_mount_only(""));
        // Everything else — including the legacy "true" placeholder and
        // whitespace — is a real shell command and must exec.
        assert!(!is_mount_only("true"));
        assert!(!is_mount_only(" "));
        assert!(!is_mount_only("echo hi"));
    }

    // ── parse_fields: field-count cap ───────────────────────────────

    #[test]
    fn parse_fields_rejects_field_count_over_cap() {
        // MAX_FIELDS+1 zero-length fields: rejected DURING parsing, before
        // the Vecs accumulate (a hostile 16 MiB body of empty fields must not
        // allocate millions of Vec headers).
        let mut body = Vec::new();
        for _ in 0..=MAX_FIELDS {
            body.extend_from_slice(&0u32.to_be_bytes());
        }
        let err = parse_fields(&body).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn parse_fields_accepts_up_to_cap() {
        // MAX_FIELDS fields parse fine (the protocol uses at most 6).
        let mut body = Vec::new();
        for _ in 0..MAX_FIELDS {
            body.extend_from_slice(&0u32.to_be_bytes());
        }
        assert_eq!(parse_fields(&body).unwrap().len(), MAX_FIELDS);
    }

    // ── resolve_timeout: clamp semantics ────────────────────────────

    #[test]
    fn resolve_timeout_zero_selects_default() {
        let d = Duration::from_secs(30);
        assert_eq!(resolve_timeout(0, d, Duration::from_secs(180)), d);
    }

    #[test]
    fn resolve_timeout_passthrough_under_max() {
        assert_eq!(
            resolve_timeout(5000, Duration::from_secs(30), Duration::from_secs(180)),
            Duration::from_millis(5000)
        );
    }

    #[test]
    fn resolve_timeout_clamped_to_max() {
        assert_eq!(
            resolve_timeout(u64::MAX, Duration::from_secs(30), Duration::from_secs(180)),
            Duration::from_secs(180)
        );
    }

    #[test]
    fn resolve_timeout_default_above_max_clamps() {
        // Misconfigured default > max: the max wins (warden is the final
        // authority on the upper bound).
        assert_eq!(
            resolve_timeout(0, Duration::from_secs(600), Duration::from_secs(60)),
            Duration::from_secs(60)
        );
    }

    // ── cg_name_for ─────────────────────────────────────────────────

    #[test]
    fn cg_name_for_rootfs() {
        assert_eq!(cg_name_for("/mnt/rootfs"), "rootfs");
    }

    #[test]
    fn cg_name_for_trailing_slash() {
        assert_eq!(cg_name_for("/mnt/rootfs/"), "rootfs");
    }

    #[test]
    fn cg_name_for_bare_slash() {
        assert_eq!(cg_name_for("/"), "rootfs");
    }

    // ── truncate_log_past_cap: bg-log watchdog core ─────────────────

    #[test]
    fn truncate_log_under_cap_is_noop() {
        let dir = tempfile::Builder::new()
            .prefix("warden_test_bglog")
            .tempdir()
            .unwrap();
        let p = dir.path().join("a.log");
        std::fs::write(&p, vec![b'x'; 100]).unwrap();
        assert!(!truncate_log_past_cap(p.to_str().unwrap(), 1000, 8 * 1024));
        assert_eq!(std::fs::metadata(&p).unwrap().len(), 100);
    }

    #[test]
    fn truncate_log_over_cap_keeps_tail() {
        let dir = tempfile::Builder::new()
            .prefix("warden_test_bglog")
            .tempdir()
            .unwrap();
        let p = dir.path().join("b.log");
        let content: Vec<u8> = (0u8..=255u8).cycle().take(64 * 1024).collect();
        std::fs::write(&p, &content).unwrap();
        assert!(truncate_log_past_cap(p.to_str().unwrap(), 1024, 4096));
        let after = std::fs::read(&p).unwrap();
        assert!(after.len() <= 4096, "tail kept, got {}", after.len());
        // The kept tail must be a suffix of the original content.
        assert_eq!(&after[..], &content[content.len() - after.len()..]);
    }

    #[test]
    fn truncate_log_missing_file_is_noop() {
        assert!(!truncate_log_past_cap("/nonexistent/bg.log", 1024, 4096));
    }

    #[test]
    fn effective_log_cap_total_budget_breach_shrinks_to_tail() {
        // Normal sweep: the configured per-log cap applies.
        assert_eq!(
            effective_log_cap(64 * 1024 * 1024, false, crate::exec::BG_LOG_KEEP),
            64 * 1024 * 1024
        );
        // Aggregate breach: every log is judged against the tail-keep floor,
        // bounding the multi-writer transient in one sweep.
        assert_eq!(
            effective_log_cap(64 * 1024 * 1024, true, crate::exec::BG_LOG_KEEP),
            crate::exec::BG_LOG_KEEP
        );
    }
}

#[cfg(test)]
mod version_echo_tests {
    use super::*;

    /// NEGOTIATED ECHO: the response header stamps resp.version (set by
    /// handle_connection to the request's version), NOT the warden's own
    /// PROTOCOL_VERSION. The out-of-range rejection frame keeps the warden's
    /// own version so an exact-match client classifies the mismatch (see
    /// read_request).
    #[test]
    fn response_header_stamps_negotiated_version_not_own() {
        let mut resp = Response::ok();
        assert_eq!(
            encode_response_header(&resp, &[0u8; NONCE_LEN])[4],
            PROTOCOL_VERSION
        );
        resp.version = 1; // a request's version is echoed as-is
        assert_eq!(encode_response_header(&resp, &[0u8; NONCE_LEN])[4], 1);
        resp.version = 2;
        assert_eq!(encode_response_header(&resp, &[0u8; NONCE_LEN])[4], 2);
    }
}

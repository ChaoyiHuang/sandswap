// Copyright © 2026 Sandswap
//
// SPDX-License-Identifier: Apache-2.0
//
// Front dispatcher on the canonical sandvmm API socket.
//
// One socket serves both control protocols, dispatched per connection by the
// first byte on the wire:
//   - 0x01 (the raw protocol version byte) → the raw control-frame protocol
//     (raw.rs) — vm.set-fs and sandvmm.ping, the per-request hot path;
//   - an ASCII method letter ('G', 'P', ...) → HTTP, byte-pumped to the
//     internal micro_http server (lifecycle operations: vm.create, vm.boot,
//     vm.add-vsock, sandvmm.shutdown — each once per VM, never per request).
//
// The canonical socket keeps the security posture it always had: created by
// sandvmm, owned by the allowed UID, mode 0600 (0660 + the shared api group
// when --api-gid is given). Every accepted connection's SO_PEERCRED is
// verified against the VMM's OWN identity: the sandlot and human
// tooling are different uids, while every sibling VMM/FUSE service on the
// node shares the VMM's uid — DAC cannot tell those apart, so the dispatcher
// refuses a peer that is the sandvmm identity itself. The internal HTTP
// socket is additionally UNLINKED after binding (see
// bind_internal_listener in mod.rs), so the pump is the only route to
// micro_http; the raw path never enters the HTTP parser at all.
//
// Neither the dispatcher nor the raw handler touches VMM device state
// directly: raw ops ride the same ApiRequest elevator as the HTTP handlers
// (crate::api::vm_set_fs / vmm_ping → VMM_SERVICE → VMM thread).

use super::raw::{serve_raw_connection, RAW_DISPATCH_BYTE};
use crate::seccomp_filters::{get_seccomp_filter, Thread};
use crate::{Error as VmmError, Result};
use hypervisor::HypervisorType;
use log::error;
use seccompiler::{apply_filter, SeccompAction};
use std::io::{ErrorKind, Read, Write};
use std::net::Shutdown;
use std::os::fd::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use vmm_sys_util::eventfd::EventFd;

/// Budget for the first byte after connect. A real client (sandlot, curl)
/// writes its first frame/request immediately; anything idling longer than
/// this is a stuck or foreign peer — close it.
const FIRST_BYTE_TIMEOUT: Duration = Duration::from_secs(30);

/// Canonical-socket authentication preface (sandlot ↔ VMM). The sandlot sends
/// a magic byte, a version, and a 32-byte random challenge; the VMM answers
/// `token XOR challenge`. The 32-byte token is delivered to the VMM over an
/// INHERITED FD at spawn (never argv/env/files) and never appears on the
/// wire. A sibling sandvmm that binds a fake listener at this VM's path
/// receives the challenge but cannot compute the response, so the sandlot
/// aborts before sending any command (and before leaking the HMAC volume
/// path in a vm.set-fs frame). Combined with the allowed-uid peer gate,
/// non-sandlot local identities cannot query the real server either.
pub const AUTH_MAGIC: u8 = 0xA5;
pub const AUTH_VERSION: u8 = 1;
const AUTH_CHALLENGE_LEN: usize = 32;
const AUTH_RESP_LEN: usize = 32;

/// Concurrent raw connections cap. sandlot holds ONE persistent raw
/// connection per VM; the cap is a DoS bound, not a concurrency target.
const MAX_RAW_CONNS: usize = 16;

static RAW_CONN_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Start the front dispatcher thread over an already-bound, already-locked
///-down canonical listener. HTTP connections are pumped to
/// `internal_path` (the micro_http server bound by the caller).
pub fn start_dispatcher_thread(
    listener: UnixListener,
    internal_path: Arc<String>,
    seccomp_action: &SeccompAction,
    hypervisor_type: HypervisorType,
    exit_evt: EventFd,
    api_token: Option<[u8; 32]>,
    api_allowed_uid: Option<u32>,
) -> Result<thread::JoinHandle<Result<()>>> {
    // Build the filter on the caller's thread (same pattern as
    // start_http_thread) and move it into the dispatcher thread.
    let filter = get_seccomp_filter(seccomp_action, Thread::Api, hypervisor_type)
        .map_err(VmmError::CreateSeccompFilter)?;

    thread::Builder::new()
        .name("api-dispatch".to_string())
        .spawn(move || {
            if !filter.is_empty() {
                apply_filter(&filter)
                    .map_err(VmmError::ApplySeccompFilter)
                    .map_err(|e| {
                        error!("Error applying seccomp filter on api dispatcher: {:?}", e);
                        exit_evt.write(1).ok();
                        e
                    })?;
            }

            // our own identity, read on the dispatcher thread (the
            // Api seccomp allowlist carries geteuid for exactly this). Every
            // VMM/FUSE service on a node shares this uid.
            // SAFETY: geteuid takes no arguments and cannot fail.
            let own_uid = unsafe { libc::geteuid() };
            std::panic::catch_unwind(AssertUnwindSafe(move || {
                accept_loop(listener, internal_path, own_uid, api_token, api_allowed_uid);
            }))
            .map_err(|_| {
                error!("api dispatcher thread panicked");
                exit_evt.write(1).ok()
            })
            .ok();

            Ok(())
        })
        .map_err(VmmError::HttpThreadSpawn)
}

/// the peer's kernel-attested uid (SO_PEERCRED — a non-root peer
/// cannot forge it), or None when the option cannot be read (the caller
/// fails closed).
fn peer_uid(stream: &UnixStream) -> Option<u32> {
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: valid fd; cred/len are correctly sized and outlive the call.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut libc::ucred as *mut libc::c_void,
            &mut len,
        )
    };
    if rc == 0 {
        Some(cred.uid)
    } else {
        None
    }
}

/// Peer verdict: may a connection whose peer runs as `peer_uid` drive this
/// VM's API surface?
///
/// The legitimate client is ALWAYS a different identity than the VMM itself:
/// the sandlot instance (uid 985 bare-metal, the pod uid in k8s) or human
/// tooling (root). All VMM/FUSE services on a node share ONE uid (987), and
/// the API sockets are 0660 with the shared api group — so DAC alone would
/// let a compromised sibling VM's sandvmm open THIS VM's socket and issue
/// `vm.set-fs` (a cross-tenant export via the sibling's share) or the HTTP
/// lifecycle set (delete/pause/reboot on another tenant's VM). A peer
/// running as our own identity is therefore refused.
///
/// uid 0 is exempt: dev/e2e run the whole stack as root, where both sides
/// share the uid by construction, and a root peer is outside the threat
/// model's boundary anyway (documented known limit).
fn peer_uid_allowed(peer_uid: u32, own_uid: u32, allowed_uid: Option<u32>) -> bool {
    // Root tooling is outside the boundary (it can read the token file /
    // ptrace anyway); everything else must match the configured sandlot uid
    // when one is set.
    if peer_uid == 0 {
        return true;
    }
    match allowed_uid {
        Some(allowed) => peer_uid == allowed,
        None => own_uid == 0 || peer_uid != own_uid,
    }
}

/// Answer the sandlot's authentication challenge: read magic+version+32-byte
/// challenge, reply `token XOR challenge`. Returns false (and the connection
/// must close) on a malformed preface or I/O failure. The token itself is
/// never written.
fn authenticate_server(stream: &mut UnixStream, token: &[u8; 32]) -> bool {
    // Two-stage read: a tokenless raw client's first two bytes are
    // [raw_version, op] (never the auth magic), so reject it immediately
    // instead of blocking for a full 34-byte preface.
    let mut header = [0u8; 2];
    if stream.read_exact(&mut header).is_err() {
        return false;
    }
    if header[0] != AUTH_MAGIC || header[1] != AUTH_VERSION {
        return false;
    }
    let mut challenge = [0u8; AUTH_CHALLENGE_LEN];
    if stream.read_exact(&mut challenge).is_err() {
        return false;
    }
    let mut resp = [0u8; AUTH_RESP_LEN];
    for (i, b) in resp.iter_mut().enumerate() {
        *b = token[i] ^ challenge[i];
    }
    stream.write_all(&resp).is_ok()
}

fn accept_loop(
    listener: UnixListener,
    internal_path: Arc<String>,
    own_uid: u32,
    api_token: Option<[u8; 32]>,
    api_allowed_uid: Option<u32>,
) {
    loop {
        match listener.accept() {
            Ok((stream, _addr)) => {
                // refuse a peer that IS the sandvmm identity (see
                // peer_uid_allowed). Fail closed when the credentials cannot
                // be read: an unverifiable peer must not reach the API.
                match peer_uid(&stream) {
                    Some(uid) if peer_uid_allowed(uid, own_uid, api_allowed_uid) => {}
                    Some(uid) => {
                        error!(
                            "api dispatcher: refusing connection from uid {} (the sandvmm \
                             identity — a sibling VMM/FUSE service must not drive this VM's API)",
                            uid
                        );
                        continue;
                    }
                    None => {
                        error!(
                            "api dispatcher: SO_PEERCRED unreadable — refusing the connection \
                             (fail closed)"
                        );
                        continue;
                    }
                }
                // Per-connection thread: the first-byte peek may block up to
                // FIRST_BYTE_TIMEOUT and must not stall the accept loop. A
                // panic in a connection thread kills only that connection.
                let path = Arc::clone(&internal_path);
                let _ = thread::Builder::new()
                    .name("api-conn".to_string())
                    .spawn(move || conn_main(stream, path, api_token));
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => {
                // Listener gone — the process is shutting down.
                error!("api dispatcher accept failed: {}", e);
                break;
            }
        }
    }
}

fn conn_main(stream: UnixStream, internal_path: Arc<String>, api_token: Option<[u8; 32]>) {
    if stream.set_read_timeout(Some(FIRST_BYTE_TIMEOUT)).is_err() {
        return;
    }
    // Authenticate the SERVER to the sandlot before any command bytes are
    // exchanged. A tokenless VMM (dev/manual) keeps the legacy first-byte
    // path; the sandlot only omits the preface when it has no token.
    if let Some(token) = api_token.as_ref() {
        let mut stream = stream;
        if !authenticate_server(&mut stream, token) {
            return;
        }
        return conn_main_after_auth(stream, internal_path);
    }
    conn_main_after_auth(stream, internal_path);
}

fn conn_main_after_auth(stream: UnixStream, internal_path: Arc<String>) {
    if stream.set_read_timeout(Some(FIRST_BYTE_TIMEOUT)).is_err() {
        return;
    }
    // MSG_PEEK keeps the byte queued: the raw handler's first read consumes
    // it as the protocol version byte of its first header. (std's
    // UnixStream::peek is unstable as of this toolchain, hence the raw
    // recv; glibc implements recv(2) over the recvfrom syscall, which is
    // in the API seccomp allowlist.)
    let mut first = [0u8; 1];
    // SAFETY: valid fd, buf of one byte, flags constant.
    let n = unsafe {
        libc::recv(
            stream.as_raw_fd(),
            first.as_mut_ptr() as *mut libc::c_void,
            1,
            libc::MSG_PEEK,
        )
    };
    if n != 1 {
        return; // EOF, first-byte timeout, or transport error
    }

    match first[0] {
        RAW_DISPATCH_BYTE => {
            // Bounded concurrent raw connections. The decrement is a DROP GUARD:
            // serve_raw_connection runs frame handlers that touch
            // client-controlled data, and an unwind anywhere inside used to skip
            // the plain fetch_sub below — each panic permanently consumed one of
            // the 16 slots, so 16 malformed frames disabled set-fs/ping for the
            // whole VM lifetime (no panic=abort, so the process survived and the
            // leak stayed).
            if RAW_CONN_COUNT.fetch_add(1, Ordering::AcqRel) >= MAX_RAW_CONNS {
                RAW_CONN_COUNT.fetch_sub(1, Ordering::AcqRel);
                return;
            }
            struct RawConnGuard;
            impl Drop for RawConnGuard {
                fn drop(&mut self) {
                    RAW_CONN_COUNT.fetch_sub(1, Ordering::AcqRel);
                }
            }
            let _guard = RawConnGuard;
            // Frames arrive back-to-back from here; drop the timeout and let
            // connection close (VM teardown / process exit) reclaim us.
            let _ = stream.set_read_timeout(None);
            serve_raw_connection(stream);
        }
        b'A'..=b'Z' => {
            // HTTP: pump bytes to the internal micro_http listener.
            match UnixStream::connect(internal_path.as_str()) {
                Ok(internal) => pump(stream, internal),
                Err(e) => {
                    // Client sees EOF and retries through the normal paths.
                    error!(
                        "api dispatcher: connect to internal HTTP socket failed: {}",
                        e
                    );
                }
            }
        }
        _ => {
            // Garbage first byte: close (fail closed).
        }
    }
}

/// Bidirectional byte pump between the external connection and the internal
/// HTTP socket, in two blocking copy loops. An idle keep-alive connection is
/// the normal steady state — both loops parked in read(), never spinning.
/// Whichever direction ends first (EOF or error) shuts its socket down for
/// BOTH directions, which wakes the opposite loop; both threads then exit
/// and all descriptors drop.
fn pump(ext: UnixStream, int: UnixStream) {
    let ext_fwd = match ext.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    };
    let int_fwd = match int.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    };

    // Direction A (thread): external → internal.
    let fwd = thread::Builder::new()
        .name("api-conn-pump".to_string())
        .spawn(move || copy_loop(ext_fwd, int_fwd));

    // Direction B (this thread): internal → external.
    copy_loop(int, ext);

    if let Ok(handle) = fwd {
        let _ = handle.join();
    }
}

fn copy_loop(mut r: UnixStream, mut w: UnixStream) {
    let mut buf = [0u8; 8192];
    loop {
        match r.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if w.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
            Err(ref e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    // Dropping only our handles would leave the socket open (the opposite
    // loop holds dups of both ends). Shut both sockets down for everyone so
    // the opposite loop's blocked read wakes immediately.
    let _ = w.shutdown(Shutdown::Both);
    let _ = r.shutdown(Shutdown::Both);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// regression pin: a peer that is the VMM's OWN identity (every sandvmm/FUSE
    /// service on a node shares one uid) must be refused, while the
    /// different-identity clients (the sandlot, root tooling) stay served.
    /// RED with the verdict returning `true` unconditionally.
    #[test]
    fn peer_uid_verdict_refuses_our_own_identity() {
        // Different identity → served (sandlot 985, k8s pod uid, root).
        assert!(peer_uid_allowed(985, 987, None));
        assert!(peer_uid_allowed(1001, 987, None));
        assert!(peer_uid_allowed(0, 987, None));
        // A sibling VMM/FUSE daemon shares our uid → refused.
        assert!(!peer_uid_allowed(987, 987, None));
        // Root dev/e2e: both sides are root by construction → served.
        assert!(peer_uid_allowed(0, 0, None));

        // With an explicit allowed uid (the sandlot), only that identity
        // (and root tooling) may connect — a compromised sandprov/sandserv
        // in the shared group is refused too.
        assert!(peer_uid_allowed(985, 987, Some(985)));
        assert!(!peer_uid_allowed(986, 987, Some(985)));
        assert!(!peer_uid_allowed(987, 987, Some(985)));
        assert!(peer_uid_allowed(0, 987, Some(985)));
    }

    /// The auth reply is exactly token XOR challenge; it never carries the
    /// token itself, and a wrong magic/version is refused.
    #[test]
    fn auth_server_answers_xor_challenge() {
        let token = [0x5au8; 32];
        let (mut client, mut server) = UnixStream::pair().unwrap();
        let handle = thread::spawn(move || authenticate_server(&mut server, &token));
        let mut prefix = vec![AUTH_MAGIC, AUTH_VERSION];
        let challenge = [0x33u8; 32];
        prefix.extend_from_slice(&challenge);
        client.write_all(&prefix).unwrap();
        let mut resp = [0u8; 32];
        client.read_exact(&mut resp).unwrap();
        for (i, b) in resp.iter().enumerate() {
            assert_eq!(*b, 0x5a ^ 0x33, "response byte {i} is not token XOR challenge");
        }
        assert!(handle.join().unwrap());

        let (mut client2, mut server2) = UnixStream::pair().unwrap();
        let handle2 = thread::spawn(move || authenticate_server(&mut server2, &[1u8; 32]));
        // A tokenless raw client starts with [raw_version, op]; the server
        // must reject it on those two bytes (the trailing write may race the
        // close — ignored).
        let _ = client2.write_all(&[0u8, 1u8]);
        let _ = client2.write_all(&[0u8; 32]);
        assert!(!handle2.join().unwrap());
    }

    /// Plumbing pin: SO_PEERCRED actually reports the connecting
    /// identity. A socketpair's peer is this very process, so the uid read
    /// must equal our euid.
    #[test]
    fn peer_uid_reads_the_connecting_identity() {
        let (a, _b) = UnixStream::pair().unwrap();
        let uid = peer_uid(&a).expect("SO_PEERCRED must be readable on a connected socket");
        // SAFETY: geteuid takes no arguments and cannot fail.
        assert_eq!(uid, unsafe { libc::geteuid() });
    }

    #[test]
    fn test_pump_relays_both_directions_and_closes() {
        // Correct socket semantics: the pump's ext socket PEERS with the
        // external client's socket (bytes written on one end surface on the
        // other — writing on the same end the pump reads from would go
        // nowhere). Same for the internal side.
        let (pump_ext, ext_client) = UnixStream::pair().unwrap();
        let (pump_int, int_server) = UnixStream::pair().unwrap();

        // Fake HTTP server: read a request, write a response, wait for close.
        let server = thread::spawn(move || {
            let mut s = int_server;
            let mut buf = [0u8; 64];
            let n = s.read(&mut buf).unwrap();
            assert_eq!(&buf[..n], b"PUMP-REQ");
            s.write_all(b"PUMP-RESP").unwrap();
            let mut eof = [0u8; 1];
            assert_eq!(s.read(&mut eof).unwrap(), 0); // pump closes us on client close
        });

        let pump_handle = thread::spawn(move || pump(pump_ext, pump_int));

        // External client: request through the pump, response back.
        let mut c = ext_client;
        c.write_all(b"PUMP-REQ").unwrap();
        let mut resp = [0u8; 9];
        c.read_exact(&mut resp).unwrap();
        assert_eq!(&resp, b"PUMP-RESP");
        // Close for real (shutdown, not drop — the socket has no other refs
        // here, but shutdown is the explicit teardown).
        let _ = c.shutdown(Shutdown::Both);
        pump_handle.join().unwrap();
        server.join().unwrap();
    }
}

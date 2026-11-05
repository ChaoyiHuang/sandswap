// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//
// Modified by Sandswap (c) 2026: vm.set-fs route registration for virtio-fs allowed_dirs hot-swap.
//

use self::http_endpoint::{VmActionHandler, VmCreate, VmInfo, VmWaitStart, VmmPing, VmmShutdown};
use crate::api::{ApiError, VmAction};
use crate::seccomp_filters::{get_seccomp_filter, Thread};
use crate::{Error as VmmError, Result};
use core::fmt;
use hypervisor::HypervisorType;
use log::warn;
use micro_http::{Body, HttpServer, MediaType, Method, Request, Response, StatusCode, Version};
use once_cell::sync::Lazy;
use seccompiler::{apply_filter, SeccompAction};
use serde_json::Error as SerdeError;
use std::collections::BTreeMap;
use std::fmt::Display;
use std::fs::File;
use std::os::unix::io::{AsRawFd, IntoRawFd, RawFd};
use std::os::unix::net::UnixListener;
use std::panic::AssertUnwindSafe;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use vmm_sys_util::eventfd::EventFd;

pub mod dispatch;
pub mod http_endpoint;
pub mod raw;

/// Errors associated with VMM management
#[derive(Debug)]
pub enum HttpError {
    /// API request receive error
    SerdeJsonDeserialize(SerdeError),

    /// Attempt to access unsupported HTTP method
    BadRequest,

    /// Undefined endpoints
    NotFound,

    /// Internal Server Error
    InternalServerError,

    /// Error from internal API
    ApiError(ApiError),
}

impl Display for HttpError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::HttpError::*;
        match self {
            BadRequest => write!(f, "Bad Request"),
            NotFound => write!(f, "Not Found"),
            InternalServerError => write!(f, "Internal Server Error"),
            SerdeJsonDeserialize(serde_error) => write!(f, "{}", serde_error),
            ApiError(api_error) => write!(f, "{}", api_error),
        }
    }
}

impl From<serde_json::Error> for HttpError {
    fn from(e: serde_json::Error) -> Self {
        HttpError::SerdeJsonDeserialize(e)
    }
}

const HTTP_ROOT: &str = "/api/v1";

pub fn error_response(error: HttpError, status: StatusCode) -> Response {
    let mut response = Response::new(Version::Http11, status);
    response.set_body(Body::new(format!("{error}")));

    response
}

/// An HTTP endpoint handler interface
pub trait EndpointHandler {
    /// Handles an HTTP request.
    /// After parsing the request, the handler could decide to send an
    /// associated API request down to the VMM API server to e.g. create
    /// or start a VM. The request will block waiting for an answer from the
    /// API server and translate that into an HTTP response.
    fn handle_request(&self, req: &Request) -> Response {
        // Cloning the files here is very important as it dup() the file
        // descriptors, leaving open the one that was received. This way,
        // rebooting the VM will work since the VM will be created from the
        // original file descriptors.
        let files = req.files.iter().map(|f| f.try_clone().unwrap()).collect();
        let res = match req.method() {
            Method::Put => self.put_handler(&req.body, files),
            Method::Get => self.get_handler(&req.body),
            _ => return Response::new(Version::Http11, StatusCode::BadRequest),
        };

        match res {
            Ok(response_body) => {
                if let Some(body) = response_body {
                    let mut response = Response::new(Version::Http11, StatusCode::OK);
                    response.set_body(body);
                    response
                } else {
                    Response::new(Version::Http11, StatusCode::NoContent)
                }
            }
            Err(e @ HttpError::BadRequest) => error_response(e, StatusCode::BadRequest),
            Err(e @ HttpError::SerdeJsonDeserialize(_)) => {
                error_response(e, StatusCode::BadRequest)
            }
            Err(e) => error_response(e, StatusCode::InternalServerError),
        }
    }

    fn put_handler(
        &self,
        _body: &Option<Body>,
        _files: Vec<File>,
    ) -> std::result::Result<Option<Body>, HttpError> {
        Err(HttpError::BadRequest)
    }

    fn get_handler(&self, _body: &Option<Body>) -> std::result::Result<Option<Body>, HttpError> {
        Err(HttpError::BadRequest)
    }
}

/// An HTTP routes structure.
pub struct HttpRoutes {
    /// routes is a hash table mapping endpoint URIs to their endpoint handlers.
    pub routes: BTreeMap<String, Box<dyn EndpointHandler + Sync + Send>>,
}


macro_rules! endpoint {
    ($path:expr) => {
        format!("{}{}", HTTP_ROOT, $path)
    };
}

/// HTTP_ROUTES contain all the cloud-hypervisor HTTP routes.
pub static HTTP_ROUTES: Lazy<HttpRoutes> = Lazy::new(|| {
    let mut r = HttpRoutes {
        routes: BTreeMap::new(),
    };

    // Modified by Sandswap (c) 2026: the `/vm.add-fs` route was removed. The
    // guest gets exactly one virtio-fs device, created at `vm.create` and
    // never hot-plugged; `vm.set-fs` re-whitelists THAT device. Dropping the
    // route (not just the handler) means a request for a second share is not
    // routable at all — it answers 404 like any other unknown endpoint.
    r.routes.insert(
        endpoint!("/vm.set-fs"),
        Box::new(VmActionHandler::new(VmAction::SetFs(Arc::default()))),
    );
    // Modified by Sandswap (c) 2026: the `/vm.add-net` route was removed too.
    // A VM's network device is fixed at `vm.create` (one TAP per VM; guest
    // addressing travels in the kernel cmdline), so attaching a NIC to a
    // running VM would be a second, unaccounted egress path — and nothing in
    // Sandswap ever asked for one. Like `/vm.add-fs`, the whole chain is gone
    // rather than parked behind a refusal.
    r.routes.insert(
        endpoint!("/vm.add-vsock"),
        Box::new(VmActionHandler::new(VmAction::AddVsock(Arc::default()))),
    );
    r.routes.insert(
        endpoint!("/vm.boot"),
        Box::new(VmActionHandler::new(VmAction::Boot)),
    );
    r.routes.insert(
        endpoint!("/vm.counters"),
        Box::new(VmActionHandler::new(VmAction::Counters)),
    );
    r.routes
        .insert(endpoint!("/vm.create"), Box::new(VmCreate {}));
    r.routes.insert(
        endpoint!("/vm.delete"),
        Box::new(VmActionHandler::new(VmAction::Delete)),
    );
    r.routes.insert(endpoint!("/vm.info"), Box::new(VmInfo {}));
    r.routes.insert(
        endpoint!("/vm.pause"),
        Box::new(VmActionHandler::new(VmAction::Pause)),
    );
    r.routes.insert(
        endpoint!("/vm.power-button"),
        Box::new(VmActionHandler::new(VmAction::PowerButton)),
    );
    r.routes.insert(
        endpoint!("/vm.reboot"),
        Box::new(VmActionHandler::new(VmAction::Reboot)),
    );
    r.routes.insert(
        endpoint!("/vm.resize"),
        Box::new(VmActionHandler::new(VmAction::Resize(Arc::default()))),
    );
    r.routes.insert(
        endpoint!("/vm.resize-zone"),
        Box::new(VmActionHandler::new(VmAction::ResizeZone(Arc::default()))),
    );
    r.routes.insert(
        endpoint!("/vm.resume"),
        Box::new(VmActionHandler::new(VmAction::Resume)),
    );
    r.routes.insert(
        endpoint!("/vm.shutdown"),
        Box::new(VmActionHandler::new(VmAction::Shutdown)),
    );
    r.routes
        .insert(endpoint!("/sandvmm.ping"), Box::new(VmmPing {}));
    r.routes
        .insert(endpoint!("/sandvmm.shutdown"), Box::new(VmmShutdown {}));
    r.routes
        .insert(endpoint!("/vm.waitstart"), Box::new(VmWaitStart {}));

    r
});

fn handle_http_request(request: &Request) -> Response {
    let path = request.uri().get_abs_path().to_string();
    let mut response = match HTTP_ROUTES.routes.get(&path) {
        Some(route) => route.handle_request(request),
        None => error_response(HttpError::NotFound, StatusCode::NotFound),
    };

    response.set_server("Cloud Hypervisor API");
    response.set_content_type(MediaType::ApplicationJson);
    response
}

fn start_http_thread(
    mut server: HttpServer,
    seccomp_action: &SeccompAction,
    exit_evt: EventFd,
    hypervisor_type: HypervisorType,
) -> Result<thread::JoinHandle<Result<()>>> {
    // Retrieve seccomp filter for API thread
    let api_seccomp_filter = get_seccomp_filter(seccomp_action, Thread::Api, hypervisor_type)
        .map_err(VmmError::CreateSeccompFilter)?;

    thread::Builder::new()
        .name("http-server".to_string())
        .spawn(move || {
            // Apply seccomp filter for API thread.
            if !api_seccomp_filter.is_empty() {
                apply_filter(&api_seccomp_filter)
                    .map_err(VmmError::ApplySeccompFilter)
                    .map_err(|e| {
                        error!("Error applying seccomp filter: {:?}", e);
                        exit_evt.write(1).ok();
                        e
                    })?;
            }

            std::panic::catch_unwind(AssertUnwindSafe(move || {
                server.start_server().unwrap();
                loop {
                    match server.requests() {
                        Ok(request_vec) => {
                            for server_request in request_vec {
                                if let Err(e) =
                                    server.respond(server_request.process(handle_http_request))
                                {
                                    error!("HTTP server error on response: {}", e);
                                }
                            }
                        }
                        Err(e) => {
                            error!(
                                "HTTP server error on retrieving incoming request. Error: {}",
                                e
                            );
                        }
                    }
                }
            }))
            .map_err(|_| {
                error!("http-server thread panicked");
                exit_evt.write(1).ok()
            })
            .ok();

            Ok(())
        })
        .map_err(VmmError::HttpThreadSpawn)
}

/// Bind a UDS for the API surface and lock it down: remove a stale socket
/// file left by a crashed previous instance, bind, and lock it down under
/// the dedicated-identity model:
///
///   - OWNER is always the sandvmm process identity itself (it binds the
///     socket — uid 987 in production). No chown-to-owner is needed or
///     possible (sandvmm holds zero capabilities).
///   - With --api-gid G (the sandlot shared group): chgrp to G + mode 0660,
///     so the sandlot identity (the sole API client, a member of G) can
///     connect. Changing the group to a group the process belongs to needs
///     NO capabilities (chown(2) rule) — the sandbox setups guarantee
///     membership.
///   - Without --api-gid: mode 0600 owner-only.
///
/// This protects the vm.set-fs endpoint (allowed_dirs) from unauthorized
/// access; the raw-frame protocol rides the same socket and therefore the
/// same DAC boundary.
fn bind_secure_socket(socket_path: &std::path::Path, api_gid: Option<u32>) -> Result<UnixListener> {
    let _ = std::fs::remove_file(socket_path);

    let listener = UnixListener::bind(socket_path).map_err(VmmError::CreateApiServerSocket)?;

    if let Some(gid) = api_gid {
        let c_path = std::ffi::CString::new(socket_path.to_str().unwrap_or("")).map_err(|_| {
            VmmError::CreateApiServerSocket(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "socket path contains null byte",
            ))
        })?;
        // chown(owner unchanged, group): permitted without CAP_CHOWN when the
        // process is a member of the target group.
        unsafe {
            // uid_t is unsigned: "unchanged owner" is (uid_t)-1, i.e. u32::MAX.
            let ret = libc::chown(c_path.as_ptr(), u32::MAX, gid);
            if ret != 0 {
                return Err(VmmError::CreateApiServerSocket(
                    std::io::Error::last_os_error(),
                ));
            }
        }
        std::fs::set_permissions(
            socket_path,
            std::os::unix::fs::PermissionsExt::from_mode(0o660),
        )
        .map_err(VmmError::CreateApiServerSocket)?;
    } else {
        std::fs::set_permissions(
            socket_path,
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        )
        .map_err(VmmError::CreateApiServerSocket)?;
    }

    Ok(listener)
}

/// Prove that connecting through `anchor_fd` reaches `listener`.
///
/// An inode comparison does NOT work for AF_UNIX sockets (the listener fd is
/// a sockfs inode; the path is a filesystem inode — they never compare
/// equal), so the check is functional: drain the accept queue, connect to the
/// anchor's `/proc/self/fd/N` path, and require the connection to arrive on
/// OUR listener. A sibling sandvmm (same uid, shared-group write on the
/// per-VM directory) that swapped its own socket in at the path between bind
/// and O_PATH-open would take the connection instead, and our listener's
/// accept would find nothing — fail closed.
///
/// Startup-only (no client has connected to the internal socket yet), so
/// draining cannot steal a real request.
fn anchor_reaches_listener(listener: &UnixListener, anchor_fd: RawFd) -> std::io::Result<bool> {
    use std::os::unix::io::AsRawFd as _;
    use std::time::{Duration, Instant};
    let lfd = listener.as_raw_fd();
    let orig_flags = unsafe { libc::fcntl(lfd, libc::F_GETFL) };
    if orig_flags < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(lfd, libc::F_SETFL, orig_flags | libc::O_NONBLOCK) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let restore = || unsafe {
        libc::fcntl(lfd, libc::F_SETFL, orig_flags);
    };
    let result = (|| -> std::io::Result<bool> {
        // Drain anything already queued (a sibling's connection, or a racing
        // startup probe) so the next accept is provably ours.
        loop {
            match listener.accept() {
                Ok((s, _)) => drop(s),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        let anchor_path = format!("/proc/self/fd/{anchor_fd}");
        let client = match std::os::unix::net::UnixStream::connect(&anchor_path) {
            Ok(c) => c,
            Err(_) => return Ok(false), // the anchor names nothing connectable
        };
        let deadline = Instant::now() + Duration::from_millis(200);
        let accepted = loop {
            match listener.accept() {
                Ok((s, _)) => break Some(s),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        break None;
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        };
        let reached = accepted.is_some();
        drop(client);
        drop(accepted);
        Ok(reached)
    })();
    restore();
    result
}

/// bind the internal HTTP listener for the dispatcher hop and make
/// it unreachable BY NAME. Returns the listener (its fd is handed to
/// micro_http) plus the `/proc/self/fd/<anchor>` path the dispatcher must
/// connect through.
///
/// The reason this exists: the canonical socket's DAC is 0660 with the
/// SHARED api group, and every VMM/FUSE service on a node runs under the
/// same uid — so neither a group restriction nor an owner-only mode can
/// keep a sibling VM's sandvmm out of a filesystem-path internal socket.
/// Unlinking it closes the name route: only this process holds the listener
/// fd and the O_PATH anchor, and /proc/<this pid>/fd is out of reach for a
/// same-uid non-descendant under the host hardening this deployment
/// requires (kernel.yama.ptrace_scope >= 1, security/verify-host-security.sh
/// check 1). The front dispatcher's SO_PEERCRED verdict (dispatch.rs) covers
/// the canonical socket the same way.
fn bind_internal_listener(path: &str) -> Result<(UnixListener, String)> {
    // Owner-only even though it is about to be unlinked: defense in depth,
    // and it costs nothing — the only client is this process.
    let listener = bind_secure_socket(std::path::Path::new(path), None)?;

    let c_path = std::ffi::CString::new(path).map_err(|_| {
        VmmError::CreateApiServerSocket(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "internal socket path contains null byte",
        ))
    })?;
    // SAFETY: valid path; O_PATH|O_CLOEXEC are plain flag bits.
    let anchor_fd = unsafe { libc::open(c_path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if anchor_fd < 0 {
        return Err(VmmError::CreateApiServerSocket(
            std::io::Error::last_os_error(),
        ));
    }
    // The bind→open window is exploitable by a sibling sandvmm (same uid,
    // shared-group write on the per-VM directory): it can unlink the freshly
    // bound socket and leave its own inode at the path, so the anchor we are
    // about to route every lifecycle request through belongs to the attacker.
    // Prove functionally that the anchor reaches THIS listener (an inode
    // comparison cannot: a socket fd and its path are different inodes).
    match anchor_reaches_listener(&listener, anchor_fd) {
        Ok(true) => {}
        Ok(false) => {
            unsafe { libc::close(anchor_fd) };
            return Err(VmmError::CreateApiServerSocket(std::io::Error::new(
                std::io::ErrorKind::AddrInUse,
                "internal socket path was replaced between bind and anchor (sibling process squatting the name?)",
            )));
        }
        Err(e) => {
            unsafe { libc::close(anchor_fd) };
            return Err(VmmError::CreateApiServerSocket(e));
        }
    }
    let connect_path = format!("/proc/self/fd/{}", anchor_fd);

    // Fail closed: if the name cannot be removed, the internal HTTP surface
    // would stay reachable by every member of the shared group.
    std::fs::remove_file(path).map_err(VmmError::CreateApiServerSocket)?;

    // The anchor must outlive this call (its /proc path IS the connect
    // route); it is closed only by process exit.
    std::mem::forget(unsafe { <std::fs::File as std::os::fd::FromRawFd>::from_raw_fd(anchor_fd) });

    Ok((listener, connect_path))
}

/// Start the dual-protocol API surface on the canonical socket path: the
/// front dispatcher (raw control frames for the per-request hot ops —
/// vm.set-fs, sandvmm.ping — plus an HTTP byte-pump for everything else)
/// in front of the internal micro_http server the pump forwards to.
///
/// HTTP lifecycle operations (vm.create / vm.boot / vm.add-vsock /
/// sandvmm.shutdown) pay one extra localhost hop through the pump; they run
/// once per VM, never per request. The hot ops are answered directly by the
/// raw handler with no HTTP framing and no JSON on either side.
///
/// The internal HTTP socket is bound, anchored and UNLINKED(, see
/// bind_internal_listener): the pump is the only route to micro_http, so the
/// dispatched SO_PEERCRED verdict is the single door into the API.
pub fn start_api_dispatcher(
    path: &str,
    api_gid: Option<u32>,
    api_token: Option<[u8; 32]>,
    api_allowed_uid: Option<u32>,
    seccomp_action: &SeccompAction,
    exit_evt: EventFd,
    hypervisor_type: HypervisorType,
) -> Result<()> {
    let socket_path = PathBuf::from(path);
    let canonical = bind_secure_socket(&socket_path, api_gid)?;

    // Prove the canonical NAME still reaches THIS listener. A sibling sandvmm
    // (same uid, shared-group write on the per-VM directory) can unlink the
    // freshly bound socket and leave its own inode at the path; the sandlot
    // connects by name, so the sibling would receive raw vm.set-fs frames
    // (including the real, HMAC-derived volume path) and could forge replies.
    // This closes the bind→anchor window. A later swap of the name remains a
    // known gap: closing it fully needs a per-VM secret the sibling cannot
    // read, not just a startup proof.
    let c_path = std::ffi::CString::new(path).map_err(|_| {
        VmmError::CreateApiServerSocket(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "socket path contains null byte",
        ))
    })?;
    // SAFETY: valid path; O_PATH|O_CLOEXEC are plain flag bits.
    let anchor_fd = unsafe { libc::open(c_path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if anchor_fd < 0 {
        return Err(VmmError::CreateApiServerSocket(
            std::io::Error::last_os_error(),
        ));
    }
    let anchor_ok = anchor_reaches_listener(&canonical, anchor_fd);
    // SAFETY: fd opened just above and not used afterwards.
    unsafe { libc::close(anchor_fd) };
    match anchor_ok {
        Ok(true) => {}
        Ok(false) => {
            return Err(VmmError::CreateApiServerSocket(std::io::Error::new(
                std::io::ErrorKind::AddrInUse,
                "canonical API socket path was replaced between bind and anchor (sibling process squatting the name?)",
            )))
        }
        Err(e) => return Err(VmmError::CreateApiServerSocket(e)),
    }

    let (internal_listener, internal_connect_path) =
        bind_internal_listener(&format!("{}.http", path))?;
    let internal_path = Arc::new(internal_connect_path);

    // SAFETY: Valid FD just opened
    let server = unsafe { HttpServer::new_from_fd(internal_listener.into_raw_fd()) }
        .map_err(VmmError::CreateApiServer)?;
    let http_exit = exit_evt.try_clone().map_err(VmmError::EventFdClone)?;
    start_http_thread(server, seccomp_action, http_exit, hypervisor_type)?;

    dispatch::start_dispatcher_thread(
        canonical,
        internal_path,
        seccomp_action,
        hypervisor_type,
        exit_evt,
        api_token,
        api_allowed_uid,
    )?;

    Ok(())
}

pub fn start_http_fd_thread(
    fd: RawFd,
    seccomp_action: &SeccompAction,
    exit_evt: EventFd,
    hypervisor_type: HypervisorType,
) -> Result<thread::JoinHandle<Result<()>>> {
    // When using a pre-opened FD, we cannot chmod/chown the socket file.
    // The caller (typically a supervisor) is responsible for setting
    // appropriate permissions before passing the FD.
    // SAFETY: Valid FD
    let server = unsafe { HttpServer::new_from_fd(fd) }.map_err(VmmError::CreateApiServer)?;
    start_http_thread(server, seccomp_action, exit_evt, hypervisor_type)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Requires root (bind + chgrp on real sockets); marked #[ignore].
    //
    // Pins the dedicated-identity socket model: the OWNER is always the
    // binding process (no chown-to-owner — sandvmm holds no CAP_CHOWN),
    // --api-gid only widens the GROUP (a group the process belongs to —
    // chown(2) allows this without capabilities) and bumps the mode to 0660;
    // without it the socket stays 0600 owner-only.
    #[test]
    #[ignore]
    fn api_socket_group_mode_semantics() {
        use std::os::unix::fs::MetadataExt;
        let dir = std::env::temp_dir().join("sandvmm_sock_perm_test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let own_gid = {
            // /proc/self is a dir owned by us; gid membership: use the
            // process's OWN primary gid — always a member.
            use std::os::unix::fs::MetadataExt as _;
            std::fs::metadata("/proc/self/").unwrap().gid()
        };

        // With --api-gid (own primary group): 0660 + that group.
        let p1 = dir.join("s1.sock");
        let _l1 = bind_secure_socket(&p1, Some(own_gid)).expect("bind with gid");
        let md = std::fs::metadata(&p1).unwrap();
        assert_eq!(md.mode() & 0o777, 0o660, "group mode must be 0660");
        assert_eq!(md.gid(), own_gid, "group must be the granted gid");

        // Without: 0600 owner-only.
        let p2 = dir.join("s2.sock");
        let _l2 = bind_secure_socket(&p2, None).expect("bind without gid");
        let md = std::fs::metadata(&p2).unwrap();
        assert_eq!(md.mode() & 0o777, 0o600, "default mode must be 0600");

        drop(_l1);
        drop(_l2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// regression pin: the internal HTTP hop must be reachable ONLY through the
    /// returned /proc/self/fd anchor path — the socket file itself is gone,
    /// so a sibling VMM (which knows the conventional `<sock>.http` name)
    /// cannot connect to micro_http behind the dispatcher's peer check. RED
    /// with the unlink removed: the path still connects.
    #[test]
    fn internal_hop_is_unlinked_and_reachable_via_anchor() {
        use std::io::{Read as _, Write as _};
        let dir = std::env::temp_dir().join(format!("sandvmm_internal_hop_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("vm.sock.http");
        let path_s = path.to_str().unwrap();

        let (listener, connect_path) = bind_internal_listener(path_s).expect("bind internal");
        assert!(
            !path.exists(),
            "the internal socket path must be UNLINKED after binding"
        );
        assert!(
            connect_path.starts_with("/proc/self/fd/"),
            "the dispatcher must connect through the anchor, got {connect_path}"
        );

        // A client using the conventional on-disk name cannot connect...
        assert!(
            std::os::unix::net::UnixStream::connect(path_s).is_err(),
            "the unlinked path must not be connectable"
        );

        // ...but the dispatcher's anchor path does reach the listener.
        let mut client =
            std::os::unix::net::UnixStream::connect(&connect_path).expect("anchor connect");
        let (mut accepted, _) = listener.accept().expect("accept through anchor");
        client.write_all(b"ping").unwrap();
        let mut buf = [0u8; 4];
        accepted.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"ping");

        let _ = std::fs::remove_dir_all(&dir);
    }

    // Modified by Sandswap (c) 2026: pins the single-share invariant at the
    // routing layer. `vm.set-fs` (re-whitelist THE device) is the only
    // virtio-fs mutator; `vm.add-fs` (attach ANOTHER share) must have no route
    // at all, so the request answers 404 like any unknown endpoint instead of
    // being parsed, validated, and possibly accepted by a future edit.
    #[test]
    fn virtiofs_api_surface_is_set_fs_only() {
        let routes = &HTTP_ROUTES.routes;

        assert!(
            routes.contains_key(&endpoint!("/vm.set-fs")),
            "/vm.set-fs must stay routable — it is the agent-switch hot path"
        );
        assert!(
            !routes.contains_key(&endpoint!("/vm.add-fs")),
            "/vm.add-fs must not be routable: a second virtio-fs device is \
             outside the one-share isolation invariant"
        );
        assert!(
            !routes.contains_key(&endpoint!("/vm.add-net")),
            "/vm.add-net must not be routable either: a NIC can only come from \
             vm.create, otherwise it is a second, unaccounted egress path"
        );
    }

    // The COMPLETE route inventory, pinned: adding or removing ANY route
    // fails this test, so every surface change is a conscious decision
    // (each route must be classified as needed-by-sandlot or
    // remove/refuse — an inherited-upstream route nobody dispatches to is
    // exactly how `vm.add-fs` came back once already). The raw-frame op
    // set on the same socket is pinned in raw.rs's tests.
    #[test]
    fn http_route_table_is_pinned() {
        let mut expected = vec![
            "/vm.add-vsock",
            "/vm.boot",
            "/vm.counters",
            "/vm.create",
            "/vm.delete",
            "/vm.info",
            "/vm.pause",
            "/vm.power-button",
            "/vm.reboot",
            "/vm.resize",
            "/vm.resize-zone",
            "/vm.resume",
            "/vm.set-fs",
            "/vm.shutdown",
            "/vm.waitstart",
            "/sandvmm.ping",
            "/sandvmm.shutdown",
        ];
        expected.sort_unstable();

        let mut got: Vec<String> = HTTP_ROUTES
            .routes
            .keys()
            .map(|k| k.strip_prefix(HTTP_ROOT).unwrap_or(k).to_string())
            .collect();
        got.sort_unstable();

        assert_eq!(
            got, expected,
            "the HTTP route table changed — update this pin AND re-classify \
             the added/removed route in the API-surface census before landing"
        );
    }

    /// The bind→anchor race check is functional: connecting through the
    /// anchor must land on OUR listener. A sibling's socket swapped in at the
    /// path takes the connection instead, so the probe answers false and
    /// bind_internal_listener fails closed.
    #[test]
    fn test_internal_socket_anchor_must_reach_the_listener() {
        use std::os::unix::io::AsRawFd;
        use std::os::unix::net::UnixListener;
        let dir = std::env::temp_dir().join(format!("sandvmm_anchor_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let sock_path = dir.join("api.sock");
        let listener = UnixListener::bind(&sock_path).expect("bind test socket");
        let c = std::ffi::CString::new(sock_path.to_str().unwrap()).unwrap();
        let anchor = unsafe { libc::open(c.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
        assert!(anchor >= 0);
        assert!(
            anchor_reaches_listener(&listener, anchor).unwrap(),
            "the anchor of the just-bound socket must reach the listener"
        );

        // A DIFFERENT listener's anchor must not reach ours (this is the
        // squatting-sibling shape: the anchor names a socket that is not the
        // one we bound).
        let squatter_path = dir.join("squat.sock");
        let squatter = UnixListener::bind(&squatter_path).unwrap();
        let c2 = std::ffi::CString::new(squatter_path.to_str().unwrap()).unwrap();
        let other_anchor = unsafe { libc::open(c2.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
        assert!(other_anchor >= 0);
        assert!(
            !anchor_reaches_listener(&listener, other_anchor).unwrap(),
            "another socket's anchor must never be accepted"
        );
        // The listener's blocking mode is restored for its real users.
        let flags = unsafe { libc::fcntl(listener.as_raw_fd(), libc::F_GETFL) };
        assert_eq!(flags & libc::O_NONBLOCK, 0);

        unsafe {
            libc::close(anchor);
            libc::close(other_anchor);
        }
        drop(listener);
        drop(squatter);
        let _ = std::fs::remove_dir_all(&dir);
    }

}

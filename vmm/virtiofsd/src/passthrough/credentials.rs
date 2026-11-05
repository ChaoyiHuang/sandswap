// SPDX-License-Identifier: BSD-3-Clause

use crate::oslib;
use crate::passthrough::util::einval;
use std::io;

/// Restore a credential component after a partially-failed switch. A failed
/// restore leaves the thread with a guest-chosen identity, so fail closed by
/// aborting the VMM (the sandlot replaces a dead sandvmm).
fn abort_on_failed_restore(what: &str, result: io::Result<()>) {
    if let Err(e) = result {
        error!(
            "failed to restore the thread's {what} after a guest-requested credential switch: {e}; \
             aborting the VMM rather than serving the next request under the wrong identity"
        );
        std::process::abort();
    }
}

pub struct UnixCredentials {
    uid: libc::uid_t,
    gid: libc::gid_t,
    sup_gid: Option<u32>,
    keep_capability: bool,
}

impl UnixCredentials {
    pub fn new(uid: libc::uid_t, gid: libc::gid_t) -> Self {
        UnixCredentials {
            uid,
            gid,
            sup_gid: None,
            keep_capability: false,
        }
    }

    /// Set a supplementary group. Set `supported_extension` to `false` to signal that a
    /// supplementary group maybe required, but the guest was not able to tell us which,
    /// so we have to rely on keeping the DAC_OVERRIDE capability.
    pub fn supplementary_gid(self, supported_extension: bool, sup_gid: Option<u32>) -> Self {
        UnixCredentials {
            uid: self.uid,
            gid: self.gid,
            sup_gid,
            keep_capability: !supported_extension,
        }
    }

    /// Changes the effective uid/gid of the current thread to `val`.  When the
    /// returned guard is dropped, the thread's credentials are restored to the
    /// exact real/effective/saved triples observed here.
    ///
    /// A guest uid/gid of 0 is the SERVICE-IDENTITY presentation, not an
    /// impersonation request: the daemon runs unprivileged and cannot switch
    /// to root (it must not try — the old code treated 0 as "no switch"), and
    /// the FUSE egress presents files as root-owned. A target that already
    /// equals the current effective id is likewise a no-op. Any other target
    /// is a real switch whose restore is armed with the exact saved triple.
    pub fn set(self) -> io::Result<Option<UnixCredentialsGuard>> {
        let current_uids = oslib::getresuid()?;
        let current_gids = oslib::getresgid()?;

        let change_uid = self.uid != 0 && self.uid != current_uids.1;
        let change_gid = self.gid != 0 && self.gid != current_gids.1;

        // The supplementary group list is process-wide state shared with the
        // other FUSE workers. Save it before the first mutation and restore
        // exactly this list on drop: dropping to "no groups" (the old
        // behaviour) strips the service identity of the shared volume group
        // for every later request on this thread.
        let mut restore_groups = None;
        if let Some(sup_gid) = self.sup_gid {
            let saved = oslib::getgroups()?;
            if saved.len() != 1 || saved.first() != Some(&sup_gid) {
                oslib::setsupgroup(sup_gid)?;
                restore_groups = Some(saved);
            }
        }

        // We have to change the gid before we change the uid because if we
        // change the uid first then we lose the capability to change the gid.
        // However changing back can happen in any order.
        //
        // A failure after a partial switch must not return without a guard:
        // undo what was already applied, and abort if even that fails (the
        // thread would otherwise keep a guest-chosen credential).
        if change_gid {
            if let Err(e) = oslib::seteffgid(self.gid) {
                if let Some(groups) = restore_groups.take() {
                    abort_on_failed_restore("supplementary groups", oslib::setgroups_all(&groups));
                }
                return Err(e);
            }
        }

        if change_uid {
            if let Err(e) = oslib::seteffuid(self.uid) {
                if change_gid {
                    abort_on_failed_restore(
                        "gid",
                        oslib::setresgid_all(current_gids.0, current_gids.1, current_gids.2),
                    );
                }
                if let Some(groups) = restore_groups.take() {
                    abort_on_failed_restore("supplementary groups", oslib::setgroups_all(&groups));
                }
                return Err(e);
            }
        }

        if change_uid && self.keep_capability {
            // Before kernel 6.3, we don't have access to process supplementary groups.
            // To work around this we can set the `DAC_OVERRIDE` in the effective set.
            // We are allowed to set the capability because we only change the effective
            // user ID, so we still have the 'DAC_OVERRIDE' in the permitted set.
            // After switching back the permitted set is copied to the effective set,
            // so no additional steps are required. A failure is not fatal to the
            // request (the operation proceeds with the normal permission check) but
            // is per-request guest-triggerable noise, so keep it off the log.
            if let Err(e) = crate::util::add_cap_to_eff("DAC_OVERRIDE") {
                debug!("failed to add 'DAC_OVERRIDE' to the effective set of capabilities: {e}");
            }
        }

        if !change_uid && !change_gid && restore_groups.is_none() {
            return Ok(None);
        }

        Ok(Some(UnixCredentialsGuard {
            restore_uid: change_uid.then_some(current_uids),
            restore_gid: change_gid.then_some(current_gids),
            restore_groups,
        }))
    }
}

pub struct UnixCredentialsGuard {
    restore_uid: Option<(libc::uid_t, libc::uid_t, libc::uid_t)>,
    restore_gid: Option<(libc::gid_t, libc::gid_t, libc::gid_t)>,
    restore_groups: Option<Vec<libc::gid_t>>,
}

impl Drop for UnixCredentialsGuard {
    fn drop(&mut self) {
        // A failed restore leaves this thread running with a credential set
        // chosen by the guest while every other request on it assumes the
        // service identity — an identity-confusion primitive, not a
        // recoverable error. Fail closed: abort the process (in-process
        // virtiofsd = the whole sandvmm), which the sandlot observes as a dead
        // VMM and replaces.
        let mut restore_error: Option<(&'static str, io::Error)> = None;

        if let Some((real, effective, saved)) = self.restore_uid {
            if let Err(e) = oslib::setresuid_all(real, effective, saved) {
                restore_error = Some(("uid", e));
            }
        }

        if restore_error.is_none() {
            if let Some((real, effective, saved)) = self.restore_gid {
                if let Err(e) = oslib::setresgid_all(real, effective, saved) {
                    restore_error = Some(("gid", e));
                }
            }
        }

        if restore_error.is_none() {
            if let Some(groups) = self.restore_groups.take() {
                if let Err(e) = oslib::setgroups_all(&groups) {
                    restore_error = Some(("supplementary groups", e));
                }
            }
        }

        if let Some((what, e)) = restore_error {
            abort_on_failed_restore(what, Err(e));
        }
    }
}

pub struct ScopedCaps {
    cap: capng::Capability,
}

impl ScopedCaps {
    fn new(cap_name: &str) -> io::Result<Option<Self>> {
        use capng::{Action, CUpdate, Set, Type};

        let cap = capng::name_to_capability(cap_name).map_err(|_| {
            let err = io::Error::last_os_error();
            error!(
                "couldn't get the capability id for name {}: {:?}",
                cap_name, err
            );
            err
        })?;

        if capng::have_capability(Type::EFFECTIVE, cap) {
            let req = vec![CUpdate {
                action: Action::DROP,
                cap_type: Type::EFFECTIVE,
                capability: cap,
            }];
            capng::update(req).map_err(|e| {
                error!("couldn't drop {} capability: {:?}", cap, e);
                einval()
            })?;
            capng::apply(Set::CAPS).map_err(|e| {
                error!(
                    "couldn't apply capabilities after dropping {}: {:?}",
                    cap, e
                );
                einval()
            })?;
            Ok(Some(Self { cap }))
        } else {
            Ok(None)
        }
    }
}

impl Drop for ScopedCaps {
    fn drop(&mut self) {
        use capng::{Action, CUpdate, Set, Type};

        let req = vec![CUpdate {
            action: Action::ADD,
            cap_type: Type::EFFECTIVE,
            capability: self.cap,
        }];

        if let Err(e) = capng::update(req) {
            panic!("couldn't restore {} capability: {:?}", self.cap, e);
        }
        if let Err(e) = capng::apply(Set::CAPS) {
            panic!(
                "couldn't apply capabilities after restoring {}: {:?}",
                self.cap, e
            );
        }
    }
}

pub fn drop_effective_cap(cap_name: &str) -> io::Result<Option<ScopedCaps>> {
    ScopedCaps::new(cap_name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn is_root() -> bool {
        unsafe { libc::geteuid() == 0 }
    }

    /// A request whose guest uid/gid already equals the server's effective
    /// identity must be a true no-op: no setresuid/setresgid, and no guard
    /// whose restore could fail later. This is the guest choosing the VMM's
    /// own service uid, the case that used to log an error per request.
    #[test]
    fn same_uid_gid_short_circuits() {
        let (_, euid, _) = oslib::getresuid().unwrap();
        let (_, egid, _) = oslib::getresgid().unwrap();
        let guard = UnixCredentials::new(euid, egid).set().unwrap();
        assert!(guard.is_none(), "an unchanged identity must not arm a guard");
    }

    /// A guest request carrying uid/gid 0 is the service-identity
    /// presentation: the unprivileged daemon must not attempt an impossible
    /// setuid(0), and must not arm a restore guard.
    #[test]
    fn guest_root_is_the_service_identity_noop() {
        let guard = UnixCredentials::new(0, 0).set().unwrap();
        assert!(
            guard.is_none(),
            "guest uid/gid 0 must not trigger a credential switch"
        );
    }

    /// A real switch must restore the exact saved triple, not uid/gid 0. As
    /// root, switch to a non-root id and confirm both the switch and the
    /// restore through getresuid/getresgid.
    #[test]
    fn switch_restores_saved_ids() {
        if !is_root() {
            eprintln!("skipping root-only credential switch test");
            return;
        }
        let before_uids = oslib::getresuid().unwrap();
        let before_gids = oslib::getresgid().unwrap();

        {
            let _guard = UnixCredentials::new(65534, 65534).set().unwrap().unwrap();
            let (_, euid, _) = oslib::getresuid().unwrap();
            let (_, egid, _) = oslib::getresgid().unwrap();
            assert_eq!(euid, 65534);
            assert_eq!(egid, 65534);
        }

        assert_eq!(oslib::getresuid().unwrap(), before_uids);
        assert_eq!(oslib::getresgid().unwrap(), before_gids);
    }

    /// Supplementary groups are process-wide and must be restored to the
    /// saved list (not dropped): the service identity's shared-volume group
    /// has to survive a request that temporarily switched to a guest group.
    #[test]
    fn supplementary_groups_are_restored_not_dropped() {
        if !is_root() {
            eprintln!("skipping root-only supplementary group test");
            return;
        }
        let before = oslib::getgroups().unwrap();
        let temp_gid = if before.contains(&1) { 2 } else { 1 };

        {
            let _guard = UnixCredentials::new(0, 0)
                .supplementary_gid(true, Some(temp_gid))
                .set()
                .unwrap()
                .expect("changing the supplementary group must arm a guard");
            assert_eq!(oslib::getgroups().unwrap(), vec![temp_gid]);
        }

        assert_eq!(oslib::getgroups().unwrap(), before);
    }
}

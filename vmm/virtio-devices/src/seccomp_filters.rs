// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Copyright © 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use seccompiler::{
    BpfProgram, Error, SeccompAction, SeccompCmpArgLen as ArgLen, SeccompCmpOp::Eq,
    SeccompCondition as Cond, SeccompFilter, SeccompRule,
};
use std::convert::TryInto;

pub enum Thread {
    VirtioBalloon,
    VirtioBlock,
    VirtioConsole,
    VirtioIommu,
    VirtioMem,
    VirtioNet,
    VirtioNetCtl,
    VirtioPmem,
    VirtioRng,
    VirtioVhostBlock,
    VirtioVhostFs,
    VirtioVhostNet,
    VirtioVhostNetCtl,
    VirtioVsock,
    VirtioWatchdog,
    VirtioFs,
}

/// Shorthand for chaining `SeccompCondition`s with the `and` operator  in a `SeccompRule`.
/// The rule will take the `Allow` action if _all_ the conditions are true.
///
/// [`SeccompCondition`]: struct.SeccompCondition.html
/// [`SeccompRule`]: struct.SeccompRule.html
macro_rules! and {
    ($($x:expr),*) => (SeccompRule::new(vec![$($x),*]).unwrap())
}

/// Shorthand for chaining `SeccompRule`s with the `or` operator in a `SeccompFilter`.
///
/// [`SeccompFilter`]: struct.SeccompFilter.html
/// [`SeccompRule`]: struct.SeccompRule.html
macro_rules! or {
    ($($x:expr,)*) => (vec![$($x),*]);
    ($($x:expr),*) => (vec![$($x),*])
}

// See include/uapi/asm-generic/ioctls.h in the kernel code.
const TIOCGWINSZ: u64 = 0x5413;

// See include/uapi/linux/sched.h in the kernel code. CLONE_FS is the only
// unshare flag the in-process FUSE server uses (one unshare(CLONE_FS) per
// worker thread so per-thread chdir/umask/xattr work does not leak through
// the shared fs_struct); namespace-creating flags stay outside the filter.
const CLONE_FS_FLAG: u64 = libc::CLONE_FS as u64;

// See include/uapi/linux/vfio.h in the kernel code.
const VFIO_IOMMU_MAP_DMA: u64 = 0x3b71;
const VFIO_IOMMU_UNMAP_DMA: u64 = 0x3b72;

// See include/uapi/linux/if_tun.h in the kernel code.
const TUNSETOFFLOAD: u64 = 0x4004_54d0;

fn create_virtio_console_ioctl_seccomp_rule() -> Vec<SeccompRule> {
    or![and![Cond::new(1, ArgLen::Dword, Eq, TIOCGWINSZ).unwrap()]]
}

fn create_virtio_iommu_ioctl_seccomp_rule() -> Vec<SeccompRule> {
    or![
        and![Cond::new(1, ArgLen::Dword, Eq, VFIO_IOMMU_MAP_DMA).unwrap()],
        and![Cond::new(1, ArgLen::Dword, Eq, VFIO_IOMMU_UNMAP_DMA).unwrap()],
    ]
}

fn create_virtio_mem_ioctl_seccomp_rule() -> Vec<SeccompRule> {
    or![
        and![Cond::new(1, ArgLen::Dword, Eq, VFIO_IOMMU_MAP_DMA).unwrap()],
        and![Cond::new(1, ArgLen::Dword, Eq, VFIO_IOMMU_UNMAP_DMA).unwrap()],
    ]
}

fn virtio_balloon_thread_rules() -> Vec<(i64, Vec<SeccompRule>)> {
    vec![(libc::SYS_fallocate, vec![])]
}

fn virtio_block_thread_rules() -> Vec<(i64, Vec<SeccompRule>)> {
    vec![
        (libc::SYS_fallocate, vec![]),
        (libc::SYS_fdatasync, vec![]),
        (libc::SYS_fsync, vec![]),
        (libc::SYS_ftruncate, vec![]),
        (libc::SYS_getrandom, vec![]),
        (libc::SYS_lseek, vec![]),
        (libc::SYS_prctl, vec![]),
        (libc::SYS_pread64, vec![]),
        (libc::SYS_preadv, vec![]),
        (libc::SYS_pwritev, vec![]),
        (libc::SYS_pwrite64, vec![]),
        (libc::SYS_sched_getaffinity, vec![]),
        (libc::SYS_set_robust_list, vec![]),
        (libc::SYS_timerfd_settime, vec![]),
    ]
}

fn virtio_console_thread_rules() -> Vec<(i64, Vec<SeccompRule>)> {
    vec![
        (libc::SYS_ioctl, create_virtio_console_ioctl_seccomp_rule()),
        (libc::SYS_prctl, vec![]),
        (libc::SYS_sched_getaffinity, vec![]),
        (libc::SYS_set_robust_list, vec![]),
    ]
}

fn virtio_iommu_thread_rules() -> Vec<(i64, Vec<SeccompRule>)> {
    vec![(libc::SYS_ioctl, create_virtio_iommu_ioctl_seccomp_rule())]
}

fn virtio_mem_thread_rules() -> Vec<(i64, Vec<SeccompRule>)> {
    vec![
        (libc::SYS_fallocate, vec![]),
        (libc::SYS_ioctl, create_virtio_mem_ioctl_seccomp_rule()),
        (libc::SYS_recvfrom, vec![]),
        (libc::SYS_sendmsg, vec![]),
    ]
}

fn virtio_net_thread_rules() -> Vec<(i64, Vec<SeccompRule>)> {
    vec![
        (libc::SYS_readv, vec![]),
        (libc::SYS_timerfd_settime, vec![]),
        (libc::SYS_writev, vec![]),
    ]
}

fn create_virtio_net_ctl_ioctl_seccomp_rule() -> Vec<SeccompRule> {
    or![and![Cond::new(1, ArgLen::Dword, Eq, TUNSETOFFLOAD).unwrap()],]
}

fn virtio_net_ctl_thread_rules() -> Vec<(i64, Vec<SeccompRule>)> {
    vec![(libc::SYS_ioctl, create_virtio_net_ctl_ioctl_seccomp_rule())]
}

fn virtio_pmem_thread_rules() -> Vec<(i64, Vec<SeccompRule>)> {
    vec![(libc::SYS_fsync, vec![])]
}

fn virtio_rng_thread_rules() -> Vec<(i64, Vec<SeccompRule>)> {
    vec![
        (libc::SYS_prctl, vec![]),
        (libc::SYS_sched_getaffinity, vec![]),
        (libc::SYS_set_robust_list, vec![]),
    ]
}

fn virtio_vhost_fs_thread_rules() -> Vec<(i64, Vec<SeccompRule>)> {
    vec![
        (libc::SYS_connect, vec![]),
        (libc::SYS_nanosleep, vec![]),
        (libc::SYS_pread64, vec![]),
        (libc::SYS_pwrite64, vec![]),
        (libc::SYS_recvmsg, vec![]),
        (libc::SYS_sendmsg, vec![]),
        (libc::SYS_sendto, vec![]),
        (libc::SYS_socket, vec![]),
    ]
}

fn virtio_vhost_net_ctl_thread_rules() -> Vec<(i64, Vec<SeccompRule>)> {
    vec![]
}

fn virtio_vhost_net_thread_rules() -> Vec<(i64, Vec<SeccompRule>)> {
    vec![
        (libc::SYS_accept4, vec![]),
        (libc::SYS_bind, vec![]),
        (libc::SYS_getcwd, vec![]),
        (libc::SYS_listen, vec![]),
        (libc::SYS_recvmsg, vec![]),
        (libc::SYS_sendmsg, vec![]),
        (libc::SYS_sendto, vec![]),
        (libc::SYS_socket, vec![]),
        #[cfg(target_arch = "x86_64")]
        (libc::SYS_unlink, vec![]),
        #[cfg(target_arch = "aarch64")]
        (libc::SYS_unlinkat, vec![]),
    ]
}

fn virtio_vhost_block_thread_rules() -> Vec<(i64, Vec<SeccompRule>)> {
    vec![]
}

fn virtio_vsock_thread_rules() -> Vec<(i64, Vec<SeccompRule>)> {
    // vhost-vsock ERR watchdog: a thin EpollHelper loop watching the shared
    // ERR eventfd — no data-path syscalls, the kernel vhost worker owns the
    // rings. The previous rules (accept4/connect/socket/recvfrom/FIONBIO)
    // belonged to the removed user-space muxer backend and would have
    // SIGSYS-killed the thread on its first epoll_create1.
    vec![
        (libc::SYS_brk, vec![]),
        (libc::SYS_clock_gettime, vec![]),
        (libc::SYS_close, vec![]),
        (libc::SYS_epoll_create1, vec![]),
        (libc::SYS_epoll_ctl, vec![]),
        (libc::SYS_epoll_pwait, vec![]),
        #[cfg(target_arch = "x86_64")]
        (libc::SYS_epoll_wait, vec![]),
        (libc::SYS_exit, vec![]),
        (libc::SYS_futex, vec![]),
        (libc::SYS_madvise, vec![]),
        (libc::SYS_mmap, vec![]),
        (libc::SYS_mprotect, vec![]),
        (libc::SYS_munmap, vec![]),
        (libc::SYS_read, vec![]),
        (libc::SYS_rt_sigaction, vec![]),
        (libc::SYS_rt_sigprocmask, vec![]),
        (libc::SYS_rt_sigreturn, vec![]),
        (libc::SYS_sched_yield, vec![]), // async log
        (libc::SYS_sigaltstack, vec![]),
        (libc::SYS_write, vec![]), // logging + exit_evt/kill_evt on ERR trip
    ]
}

fn virtio_watchdog_thread_rules() -> Vec<(i64, Vec<SeccompRule>)> {
    vec![
        (libc::SYS_prctl, vec![]),
        (libc::SYS_sched_getaffinity, vec![]),
        (libc::SYS_set_robust_list, vec![]),
        (libc::SYS_timerfd_settime, vec![]),
    ]
}

/// `unshare(2)` is allowed only with `CLONE_FS`. The FUSE worker pool calls
/// it once per thread (the fs_struct is per-thread, so chdir/umask and the
/// xattr working-directory dance do not race across workers); namespace
/// flags are outside the daemon's design and must be refused.
fn create_virtio_fs_unshare_rule() -> Vec<SeccompRule> {
    vec![and![Cond::new(0, ArgLen::Dword, Eq, CLONE_FS_FLAG).unwrap()]]
}

fn virtio_fs_thread_rules() -> Vec<(i64, Vec<SeccompRule>)> {
    vec![
        (libc::SYS_accept4, vec![]),
        (libc::SYS_brk, vec![]),
        (libc::SYS_capget, vec![]), // For CAP_FSETID
        (libc::SYS_capset, vec![]),
        (libc::SYS_clock_gettime, vec![]),
        // ── Audit-named gaps (filter audit, see sandlot/vmm/launcher.go
        // seccomp note): the in-process FUSE server issues these from THIS
        // thread and its children (handle_message runs inline on the VirtioFs
        // epoll thread), so enforce mode ("true") trapped them one by one.
        // Each entry cites its call site; the pin test below fails if any is
        // removed again.
        (
            libc::SYS_chmod,
            vec![],
        ), // passthrough setattr/secctx-rollback path-based chmod (fchmod* are listed above)
        (
            libc::SYS_chown,
            vec![],
        ), // secctx rollback: path-based ownership restore (fchownat is listed above)
        (libc::SYS_lchown, vec![]), // rollback on the symlink itself (never follows)
        (libc::SYS_fchown, vec![]), // fd-based chown sibling of fchownat
        (
            libc::SYS_getrandom,
            vec![],
        ), // rustix/rand in the FUSE server (id generation, tokio internals)
        (
            libc::SYS_tgkill,
            vec![],
        ), // thread-directed signal (libc abort/panic path in worker threads)
        // ── Same-class completions (not audit-named, same justification) ──
        (libc::SYS_faccessat, vec![]),    // FUSE OP_ACCESS handler (passthrough access check)
        (libc::SYS_faccessat2, vec![]),   // its modern form (glibc ≥ 2.34)
        (libc::SYS_restart_syscall, vec![]), // interrupted-syscall restart (rt_sigreturn companion)
        (libc::SYS_clone, vec![]),
        (libc::SYS_clone3, vec![]),
        (libc::SYS_close, vec![]),
        (libc::SYS_copy_file_range, vec![]),
        (libc::SYS_dup, vec![]),
        #[cfg(any(
            target_arch = "x86_64",
            target_arch = "s390x",
            target_arch = "powerpc64"
        ))]
        (libc::SYS_epoll_create, vec![]),
        (libc::SYS_epoll_create1, vec![]),
        (libc::SYS_epoll_ctl, vec![]),
        (libc::SYS_epoll_pwait, vec![]),
        #[cfg(any(
            target_arch = "x86_64",
            target_arch = "s390x",
            target_arch = "powerpc64"
        ))]
        (libc::SYS_epoll_wait, vec![]),
        (libc::SYS_eventfd2, vec![]),
        (libc::SYS_exit, vec![]),
        (libc::SYS_exit_group, vec![]),
        (libc::SYS_fallocate, vec![]),
        (libc::SYS_fchdir, vec![]),
        (libc::SYS_fchmod, vec![]),
        (libc::SYS_fchmodat, vec![]),
        (libc::SYS_fchownat, vec![]),
        (libc::SYS_fcntl, vec![]),
        (libc::SYS_fdatasync, vec![]),
        (libc::SYS_fgetxattr, vec![]),
        (libc::SYS_flistxattr, vec![]),
        (libc::SYS_flock, vec![]),
        (libc::SYS_fremovexattr, vec![]),
        (libc::SYS_fsetxattr, vec![]),
        (libc::SYS_fstat, vec![]),
        #[cfg(target_arch = "s390x")]
        (libc::SYS_fstatfs64, vec![]),
        (libc::SYS_fstatfs, vec![]),
        (libc::SYS_fsync, vec![]),
        (libc::SYS_ftruncate, vec![]),
        (libc::SYS_futex, vec![]),
        #[cfg(any(
            target_arch = "x86_64",
            target_arch = "s390x",
            target_arch = "powerpc64"
        ))]
        (libc::SYS_getdents, vec![]),
        (libc::SYS_getdents64, vec![]),
        (libc::SYS_getegid, vec![]),
        (libc::SYS_geteuid, vec![]),
        (libc::SYS_getpid, vec![]),
        (libc::SYS_gettid, vec![]),
        (libc::SYS_gettimeofday, vec![]),
        (libc::SYS_getxattr, vec![]),
        (libc::SYS_linkat, vec![]),
        (libc::SYS_listxattr, vec![]),
        (libc::SYS_lseek, vec![]),
        #[cfg(any(
            target_arch = "x86_64",
            target_arch = "s390x",
            target_arch = "powerpc64"
        ))]
        (libc::SYS_lstat, vec![]),
        (libc::SYS_madvise, vec![]),
        (libc::SYS_mkdirat, vec![]),
        (libc::SYS_mknodat, vec![]),
        (libc::SYS_mmap, vec![]),
        (libc::SYS_mprotect, vec![]),
        (libc::SYS_mremap, vec![]),
        (libc::SYS_munmap, vec![]),
        (libc::SYS_name_to_handle_at, vec![]),
        (libc::SYS_newfstatat, vec![]),
        #[cfg(any(
            target_arch = "x86_64",
            target_arch = "s390x",
            target_arch = "powerpc64"
        ))]
        (libc::SYS_open, vec![]),
        (libc::SYS_openat, vec![]),
        (libc::SYS_openat2, vec![]),
        (libc::SYS_open_by_handle_at, vec![]),
        (libc::SYS_prctl, vec![]),
        (libc::SYS_preadv, vec![]),
        (libc::SYS_prlimit64, vec![]),
        (libc::SYS_pwritev, vec![]),
        (libc::SYS_pwritev2, vec![]),
        (libc::SYS_read, vec![]),
        (libc::SYS_readlinkat, vec![]),
        (libc::SYS_recvmsg, vec![]),
        (libc::SYS_renameat, vec![]),
        (libc::SYS_renameat2, vec![]),
        (libc::SYS_removexattr, vec![]),
        (libc::SYS_rt_sigaction, vec![]),
        (libc::SYS_rt_sigprocmask, vec![]),
        (libc::SYS_rt_sigreturn, vec![]),
        (libc::SYS_sched_getaffinity, vec![]),
        (libc::SYS_sendmsg, vec![]),
        (libc::SYS_set_robust_list, vec![]),
        (libc::SYS_setgroups, vec![]), // oslib::setsupgroup/dropsupgroups
        // The passthrough credential guard saves the current real/effective/
        // saved ids before switching and restores them afterwards; these are
        // read-only queries and must accompany setres{g,u}id. getgroups is
        // issued when the guest FUSE INIT declares CREATE_SUPP_GROUP, so it
        // must be allowed even without CAP_SETGID.
        (libc::SYS_getgroups, vec![]),
        (libc::SYS_getresgid, vec![]),
        (libc::SYS_getresuid, vec![]),
        (libc::SYS_setresgid, vec![]),
        (libc::SYS_setresuid, vec![]),
        //(libc::SYS_setresgid32);  Needed on some platforms,
        //(libc::SYS_setresuid32);  Needed on some platforms
        (libc::SYS_setxattr, vec![]),
        (libc::SYS_sigaltstack, vec![]),
        #[cfg(target_arch = "s390x")]
        (libc::SYS_sigreturn, vec![]),
        (libc::SYS_statx, vec![]),
        (libc::SYS_symlinkat, vec![]),
        (libc::SYS_syncfs, vec![]),
        #[cfg(target_arch = "x86_64")]
        (libc::SYS_time, vec![]), // Rarely needed, except on static builds
        (libc::SYS_umask, vec![]),
        (libc::SYS_unlinkat, vec![]), // unlink/rmdir + secctx rollback
        (libc::SYS_unshare, create_virtio_fs_unshare_rule()),
        (libc::SYS_utimensat, vec![]),
        (libc::SYS_write, vec![]),
        (libc::SYS_writev, vec![]),
        (libc::SYS_timerfd_create, vec![]),
        (libc::SYS_timerfd_settime, vec![]),
    ]
}

pub fn create_virtio_device_ioctl_seccomp_rule() -> Vec<SeccompRule> {
    let mut common_rules = vec![];
    let rules = create_virtio_console_ioctl_seccomp_rule();
    common_rules.extend(rules);
    let rules = create_virtio_net_ctl_ioctl_seccomp_rule();
    common_rules.extend(rules);
    common_rules
}

pub fn virtio_device_thread_rules() -> Vec<(i64, Vec<SeccompRule>)> {
    let mut rules = vec![
        (libc::SYS_gettid, vec![]),
        (libc::SYS_gettimeofday, vec![]),
        (libc::SYS_getuid, vec![]),
        // to support operations in init_backendfs()
        #[cfg(target_arch = "x86_64")]
        (libc::SYS_lstat, vec![]),
        (libc::SYS_prlimit64, vec![]),
    ];

    rules.append(&mut virtio_block_thread_rules());
    rules.retain(|(num, _)| *num != libc::SYS_ioctl);
    rules.append(&mut virtio_net_thread_rules());
    rules.retain(|(num, _)| *num != libc::SYS_ioctl);
    rules.append(&mut virtio_net_ctl_thread_rules());
    rules.retain(|(num, _)| *num != libc::SYS_ioctl);
    rules.append(&mut virtio_pmem_thread_rules());
    rules.retain(|(num, _)| *num != libc::SYS_ioctl);
    rules.append(&mut virtio_rng_thread_rules());
    rules.retain(|(num, _)| *num != libc::SYS_ioctl);
    rules.append(&mut virtio_vsock_thread_rules());
    rules.retain(|(num, _)| *num != libc::SYS_ioctl);
    rules.append(&mut virtio_fs_thread_rules());
    rules.retain(|(num, _)| *num != libc::SYS_ioctl);
    rules.append(&mut virtio_thread_common());
    rules.retain(|(num, _)| *num != libc::SYS_ioctl);

    let mut ioctl_rules = vec![(libc::SYS_ioctl, create_virtio_device_ioctl_seccomp_rule())];
    rules.append(&mut ioctl_rules);

    rules
}

fn get_seccomp_rules(thread_type: Thread) -> Vec<(i64, Vec<SeccompRule>)> {
    let mut rules = match thread_type {
        Thread::VirtioBalloon => virtio_balloon_thread_rules(),
        Thread::VirtioBlock => virtio_block_thread_rules(),
        Thread::VirtioConsole => virtio_console_thread_rules(),
        Thread::VirtioIommu => virtio_iommu_thread_rules(),
        Thread::VirtioMem => virtio_mem_thread_rules(),
        Thread::VirtioNet => virtio_net_thread_rules(),
        Thread::VirtioNetCtl => virtio_net_ctl_thread_rules(),
        Thread::VirtioPmem => virtio_pmem_thread_rules(),
        Thread::VirtioRng => virtio_rng_thread_rules(),
        Thread::VirtioVhostBlock => virtio_vhost_block_thread_rules(),
        Thread::VirtioVhostFs => virtio_vhost_fs_thread_rules(),
        Thread::VirtioVhostNet => virtio_vhost_net_thread_rules(),
        Thread::VirtioVhostNetCtl => virtio_vhost_net_ctl_thread_rules(),
        Thread::VirtioVsock => virtio_vsock_thread_rules(),
        Thread::VirtioWatchdog => virtio_watchdog_thread_rules(),
        Thread::VirtioFs => virtio_fs_thread_rules(),
    };
    rules.append(&mut virtio_thread_common());
    rules
}

fn virtio_thread_common() -> Vec<(i64, Vec<SeccompRule>)> {
    vec![
        (libc::SYS_brk, vec![]),
        (libc::SYS_clock_gettime, vec![]),
        (libc::SYS_close, vec![]),
        (libc::SYS_dup, vec![]),
        (libc::SYS_epoll_create1, vec![]),
        (libc::SYS_epoll_ctl, vec![]),
        (libc::SYS_epoll_pwait, vec![]),
        #[cfg(target_arch = "x86_64")]
        (libc::SYS_epoll_wait, vec![]),
        (libc::SYS_exit, vec![]),
        (libc::SYS_futex, vec![]),
        (libc::SYS_madvise, vec![]),
        (libc::SYS_mmap, vec![]),
        (libc::SYS_mprotect, vec![]),
        (libc::SYS_munmap, vec![]),
        (libc::SYS_openat, vec![]),
        (libc::SYS_read, vec![]),
        (libc::SYS_rt_sigprocmask, vec![]),
        (libc::SYS_rt_sigreturn, vec![]),
        (libc::SYS_sigaltstack, vec![]),
        (libc::SYS_write, vec![]),
    ]
}

/// Generate a BPF program based on the seccomp_action value
pub fn get_seccomp_filter(
    seccomp_action: &SeccompAction,
    thread_type: Thread,
) -> Result<BpfProgram, Error> {
    match seccomp_action {
        SeccompAction::Allow => Ok(vec![]),
        // KillProcess is not a supported mode (the CLI and the sandlot
        // config reject it). If a library caller reaches it anyway, fail
        // CLOSED: install the full Trap filter per thread rather than the
        // historical empty program (which silently disabled seccomp on the
        // guest-facing threads).
        SeccompAction::KillProcess => SeccompFilter::new(
            get_seccomp_rules(thread_type).into_iter().collect(),
            SeccompAction::Trap,
            SeccompAction::Allow,
            std::env::consts::ARCH.try_into().unwrap(),
        )
        .and_then(|filter| filter.try_into())
        .map_err(Error::Backend),
        SeccompAction::Log => SeccompFilter::new(
            get_seccomp_rules(thread_type).into_iter().collect(),
            SeccompAction::Log,
            SeccompAction::Allow,
            std::env::consts::ARCH.try_into().unwrap(),
        )
        .and_then(|filter| filter.try_into())
        .map_err(Error::Backend),
        _ => SeccompFilter::new(
            get_seccomp_rules(thread_type).into_iter().collect(),
            SeccompAction::Trap,
            SeccompAction::Allow,
            std::env::consts::ARCH.try_into().unwrap(),
        )
        .and_then(|filter| filter.try_into())
        .map_err(Error::Backend),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The VirtioFs allow-list must cover every syscall the in-process FUSE
    /// server issues from the device thread and its children — pinned after
    /// the filter audit found enforce mode ("true") trapping them
    /// one by one (launcher.go's seccomp note). Removing any entry re-opens
    /// the gap that keeps `microvm.vmm_seccomp` stuck on "log"; if a removal
    /// is ever deliberate, the e2e enforce-mode battery must be re-run first.
    #[test]
    fn virtio_fs_rules_cover_audit_named_gaps() {
        let rules = virtio_fs_thread_rules();
        let required: [(&str, i64); 12] = [
            ("getgroups", libc::SYS_getgroups),
            ("getresgid", libc::SYS_getresgid),
            ("getresuid", libc::SYS_getresuid),
            ("chmod", libc::SYS_chmod),
            ("chown", libc::SYS_chown),
            ("lchown", libc::SYS_lchown),
            ("fchown", libc::SYS_fchown),
            ("getrandom", libc::SYS_getrandom),
            ("tgkill", libc::SYS_tgkill),
            ("faccessat", libc::SYS_faccessat),
            ("faccessat2", libc::SYS_faccessat2),
            ("restart_syscall", libc::SYS_restart_syscall),
        ];
        for (name, nr) in required {
            assert!(
                rules.iter().any(|(r, _)| *r == nr),
                "virtio_fs_thread_rules must allow {name} ({nr}) — the in-process FUSE server issues it on this thread (filter audit)"
            );
        }
    }

    /// unshare(2) is pinned to CLONE_FS: the FUSE worker pool's
    /// `after_start` hook needs exactly that flag, and any other flag set
    /// (namespace creation) must be trapped by the filter.
    #[test]
    fn virtio_fs_unshare_is_pinned_to_clone_fs() {
        let rules = virtio_fs_thread_rules();
        let unshare: Vec<_> = rules
            .iter()
            .filter(|(nr, _)| *nr == libc::SYS_unshare)
            .flat_map(|(_, r)| r.clone())
            .collect();
        assert_eq!(
            unshare,
            vec![and![Cond::new(0, ArgLen::Dword, Eq, CLONE_FS_FLAG).unwrap()]],
            "virtio_fs_thread_rules must allow unshare(CLONE_FS) only"
        );
    }

    /// io_uring has no caller in the virtio block device (the support probe
    /// is stubbed to false); an unfiltered grant is pure attack surface.
    #[test]
    fn virtio_device_rules_do_not_allow_io_uring() {
        for rules in [
            virtio_fs_thread_rules(),
            virtio_device_thread_rules(),
        ] {
            assert!(
                rules.iter().all(|(nr, _)| *nr != libc::SYS_io_uring_enter
                    && *nr != libc::SYS_io_uring_setup
                    && *nr != libc::SYS_io_uring_register),
                "io_uring syscalls must not be allow-listed"
            );
        }
    }

    /// No duplicates: a doubled syscall number silently shrinks the effective
    /// allow-list surface the review reasoning covers.
    #[test]
    fn virtio_fs_rules_have_no_duplicates() {
        let rules = virtio_fs_thread_rules();
        let mut seen = std::collections::HashSet::new();
        for (nr, _) in &rules {
            assert!(seen.insert(*nr), "duplicate syscall number {nr} in virtio_fs_thread_rules");
        }
    }
}

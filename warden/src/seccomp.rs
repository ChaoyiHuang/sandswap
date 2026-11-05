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
//! Sandswap hardening: deny-list seccomp-BPF filter for agent exec.
//!
//! Pure-Rust, no libseccomp dependency (static musl safe). Installs a BPF
//! program via `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ...)` in the child's
//! `pre_exec`, after `fork` and before `exec`. Only async-signal-safe calls are
//! used inside the install path.
//!
//! Policy: deny-list. We block syscalls that let a chrooted agent read another
//! process's memory, remount/escape the masked proc/dev, create namespaces, or
//! escalate privileges. Everything else is allowed, so arbitrary agent code
//! (pip/apt/node/mysql/browser) keeps working. A denied syscall returns EPERM.
//!
//! The filter first checks `seccomp_data.arch == AUDIT_ARCH_X86_64` (kills the
//! process on any other arch, e.g. x32 ABI bypass) then matches the syscall
//! number against the deny list.

use std::io;

// Stable Linux UAPI constants. libc exports most; we define the rest locally.
const PR_SET_NO_NEW_PRIVS: libc::c_int = 38;
const PR_SET_SECCOMP: libc::c_int = 22;
const SECCOMP_MODE_FILTER: libc::c_int = 2;

// BPF return-action constants (seccomp_action).
const SECCOMP_RET_KILL_PROCESS: u32 = 0x80000000;
const SECCOMP_RET_ERRNO: u32 = 0x00050000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff0000;

// BPF instruction opcodes (linux/filter.h).
const BPF_LD: u16 = 0x00;
const BPF_JMP: u16 = 0x05;
const BPF_RET: u16 = 0x06;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_K: u16 = 0x00;
const BPF_JEQ: u16 = 0x10;
const BPF_JGE: u16 = 0x30;

// seccomp_data field offsets (u32 each).
const OFF_NR: u32 = 0; // offsetof(seccomp_data, nr)
const OFF_ARCH: u32 = 4; // offsetof(seccomp_data, arch)
const OFF_ARG0: u32 = 16; // offsetof(seccomp_data, args[0])

// AUDIT_ARCH_X86_64 = EM_X86_64 (62) | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE.
const AUDIT_ARCH_X86_64: u32 = 0xC000003E;

// errno returned for denied syscalls.
const EPERM: u32 = libc::EPERM as u32;

/// x86_64 syscall numbers denied by the filter.
///
/// Deliberately NOT on this list:
///   - clone3 (435): glibc ≥ 2.34 uses clone3 for pthread_create and treats
///     EPERM as fatal (only ENOSYS triggers the clone() fallback), so denying
///     it would break threaded agent code. Namespace creation via
///     clone3(CLONE_NEWNS|CLONE_NEWUSER...) is inert by POLICY: the shipped
///     guest kernel disables CONFIG_USER_NS at build time (the warden also
///     writes /proc/sys/user/max_user_namespaces=0 for older/dev kernels),
///     so CLONE_NEWUSER fails outright; every other namespace needs
///     CAP_SYS_ADMIN in the initial userns, which neither profile holds. Even
///     if a namespace were created, mount(2), open_tree, move_mount, fsopen,
///     fsconfig, fsmount, fspick and mount_setattr are ALL denied below, and
///     ptrace/process_vm_*/setns (reaching the warden's namespaces) are
///     denied too.
///   - clone (56): needed by virtually all agent runtimes.
///
/// Cross-tenant residue + kernel-attack-surface denials: agents sharing a
/// reused VM run as the
/// same uid 0, and kernel-scoped objects outlive the rule-A process sweep —
///   - keyring trio: the per-uid persistent user keyring survives agent
///     switches and is readable by the next agent (kernel keys are scoped to
///     the user namespace, so no IPC-namespace trick covers them; denial is
///     the whole fix; the warden additionally clears the keyring at unmount
///     as defense-in-depth).
///   - io_uring_setup / userfaultfd: the two canonical sandbox kernel attack
///     surfaces (Docker's default profile and gVisor deny both); a guest
///     kernel compromise collapses every in-guest layer at once.
///   - SysV IPC is NOT denied (legit intra-agent use); its cross-tenant
///     residue is closed by the unmount-time kernel-object sweep in mount.rs.
const DENY_SYSCALLS: &[(u32, &str)] = &[
    (101, "ptrace"),
    // setpriority's target is args[1] (who), not args[0] (which): classic BPF
    // cannot combine "which == PRIO_PROCESS" and "who == self" with the shared
    // arg0 guard, and the kernel's RLIMIT_NICE is not a security boundary the
    // sandbox should depend on. Deny it outright; self renice is the only loss.
    (141, "setpriority"),
    // x86 legacy LDT manipulation: no legitimate 64-bit agent use, and it is
    // a classic kernel-attack-surface member (Docker's profile gates it too).
    (154, "modify_ldt"),
    // ioprio_set's who is args[1] too (args[0] = which). The same-owner check
    // admits a same-uid target (PID 1 and its worker threads included), so the
    // CPU-side scheduler guard alone leaves the block-side retune open. Deny
    // it outright; the agent has no legitimate cross-task I/O-priority use.
    (251, "ioprio_set"),
    // Mount-namespace manipulation, class-completeness half: pivot_root(155) and chroot(161) were the only members of the
    // mount-manipulation class left implicit — inert for the uncapped agent
    // via CAP_SYS_ADMIN/CAP_SYS_CHROOT, but every sibling (mount, fsopen,
    // move_mount, ...) is denied EXPLICITLY, and the host-side systemd filter
    // denies both by name. An explicit deny also keeps the class closed if a
    // future runtime path ever hands the child a capability.
    (155, "pivot_root"),
    (161, "chroot"),
    (165, "mount"),
    (166, "umount2"),
    (167, "swapon"),
    (168, "swapoff"),
    (246, "kexec_load"),
    (248, "add_key"),
    (249, "request_key"),
    (250, "keyctl"),
    (272, "unshare"),
    (298, "perf_event_open"),
    (304, "open_by_handle_at"),
    (308, "setns"),
    (310, "process_vm_readv"),
    (311, "process_vm_writev"),
    (320, "kexec_file_load"),
    (321, "bpf"),
    (323, "userfaultfd"),
    (425, "io_uring_setup"),
    (428, "open_tree"),
    (429, "move_mount"),
    (430, "fsopen"),
    (431, "fsconfig"),
    (432, "fsmount"),
    (433, "fspick"),
    // The rest of the mount API class: mount_setattr(2) rewrites per-mount
    // attributes in a namespace the caller owns (the last live spelling before
    // this entry), and statmount/listmount are the new read-side introspection
    // pair. With CONFIG_USER_NS off (the shipped guest kernel) and no
    // CAP_SYS_ADMIN in either profile the class is already unreachable; the
    // explicit denials keep it closed if a future profile ever hands out a
    // capability. mount(2)/umount2/fsopen/... are denied above.
    (442, "mount_setattr"),
    // open_tree_attr(2) is the same mount-API class as mount_setattr: it
    // rewrites attributes of a mount tree referenced by fd. Same reachability
    // story (CAP_SYS_ADMIN in the owning user namespace); the explicit denial
    // keeps the class closed if a future profile ever hands out a capability.
    (467, "open_tree_attr"),
    // x86_64 syscall NUMBERS matter: statmount=457 and listmount=458. The
    // entries here were 454/455, which on x86_64 are futex_wake/futex_wait —
    // so the introspection pair was NOT denied (the hardening probe reached
    // the kernel and returned EFAULT instead of EPERM) while two legitimate
    // futex variants were denied instead. Pinned by the e2e hardening probe,
    // which uses the kernel headers' numbers.
    (457, "statmount"),
    (458, "listmount"),
    (447, "memfd_secret"),
    // Kernel ring-buffer read: the kmsg cross-tenant
    // residue is closed by MASKED MOUNTS (/dev/kmsg, /proc/kmsg — mount.rs),
    // but syslog(2) reads the same buffer WITHOUT any mount. On a stock kernel
    // dmesg_restrict defaults to 0, so the check is not even capability-gated:
    // an uncapped uid-0 agent could read the PREVIOUS agent's kernel log lines
    // (OOM killer output names its processes). Denying the syscall closes the
    // class the mount masking opened; dmesg(1) is not agent-legitimate.
    (103, "syslog"),
    // POSIX message queues (owner ruling): no agent use case is
    // visible, and background processes can use user-space IPC (pipes/sockets).
    // Denying the syscalls is the sole close for the cross-tenant mqueue leak
    // of the cross-tenant mqueue leak: a tenant cannot create or touch a queue at all, so no unmount
    // sweep is needed. All six mqueue syscalls are denied, not just mq_open,
    // so a pre-existing queue cannot be read either.
    (240, "mq_open"),
    (241, "mq_unlink"),
    (242, "mq_timedsend"),
    (243, "mq_timedreceive"),
    (244, "mq_notify"),
    (245, "mq_getsetattr"),
    // ── Cross-process / kernel-object inspection (same uid 0 in the VM) ──
    // pidfd_getfd steals an fd from another process (the warden's vsock/log
    // fds would be the prize); ptrace/process_vm are already denied, and the
    // warden's PR_SET_DUMPABLE=0 is the second layer. process_madvise /
    // process_mrelease act on another process's memory; kcmp compares kernel
    // objects across processes and is an information oracle. None has an
    // agent use case.
    (438, "pidfd_getfd"),
    // pidfd_getfd is the fd-theft member of this class; the open/signal pair
    // lets a same-uid caller address another task (PID 1's worker threads
    // included) without ptrace. Deny the whole class.
    (434, "pidfd_open"),
    (424, "pidfd_send_signal"),
    (440, "process_madvise"),
    (448, "process_mrelease"),
    (312, "kcmp"),
    // ── Kernel-module / kernel-loader surface ──
    (174, "create_module"),
    (175, "init_module"),
    (176, "delete_module"),
    (313, "finit_module"),
    (177, "get_kernel_syms"),
    (178, "query_module"),
    (134, "uselib"),
    // NOTE: vm86/vm86old are i386-only and have no x86_64 syscall numbers.
    // This table is entered only for AUDIT_ARCH_X86_64, where 112/113 are
    // setsid(2)/setreuid(2) — both documented as ALLOWED (the warden's own
    // setsid runs in pre_exec before the filter; agent code may daemonize or
    // drop privileges). Denying them here was a stale i386-numbering carryover
    // that broke real workloads.
    (139, "sysfs"),
    (156, "_sysctl"),
    (180, "nfsservctl"),
    (136, "ustat"),
    // ── Host-global state (clock, hostname, accounting, quota, IO ports) ──
    // The agent has no capability for these today; the explicit denials keep
    // the classes closed if a future profile ever hands it one.
    (169, "reboot"),
    (170, "sethostname"),
    (171, "setdomainname"),
    (159, "adjtimex"),
    (164, "settimeofday"),
    (227, "clock_settime"),
    (305, "clock_adjtime"),
    (163, "acct"),
    (179, "quotactl"),
    // quotactl_fd(2) is quotactl addressed by an open mount fd (the read-side
    // quota commands need no CAP_SYS_ADMIN, which is why the class is denied
    // outright rather than capability-gated): a tenant must not read or touch
    // host-global quota state. Named explicitly so the class stays complete.
    (443, "quotactl_fd"),
    (172, "iopl"),
    (173, "ioperm"),
    (212, "lookup_dcookie"),
    (300, "fanotify_init"),
    // ── Device nodes / file-handle escape ──
    // mknod is already inert without CAP_MKNOD (the Install profile dropped
    // it); name_to_handle_at + open_by_handle_at is the handle-escape pair,
    // and open_by_handle_at is already denied.
    (133, "mknod"),
    (259, "mknodat"),
    (303, "name_to_handle_at"),
    // ── NUMA policy (host-wide memory policy; Docker's default denies too) ──
    (237, "mbind"),
    (238, "set_mempolicy"),
    // set_mempolicy_home_node(2) extends the same host-global NUMA policy
    // surface (it only acts after a set_mempolicy policy exists, which is
    // already denied — the entry keeps the class complete).
    (450, "set_mempolicy_home_node"),
    (239, "get_mempolicy"),
    (256, "migrate_pages"),
    (279, "move_pages"),
];

// The deny-list SIZE is a documented interface: docs/how-it-works/syscall-surface.md
// and docs/how-it-works/isolation-and-swap.md §7.1 both state the count. A
// deliberate list change must move this pin and both docs in the same commit —
// the same discipline PROTOCOL_VERSION follows — so the code and the docs can
// never silently drift apart again (the comments in exec.rs once said "29"
// while this list held 73; it held 74 while setpriority was the last addition;
// it held 72 after the two stale i386 vm86 entries — which on x86_64 denied
// setsid/setreuid — were removed; it holds 82 after mount_setattr +
// statmount + listmount, pidfd_open + pidfd_send_signal, ioprio_set,
// quotactl_fd, open_tree_attr and set_mempolicy_home_node closed their
// respective classes).
//
// The count is a named constant so the production pin and the test pin cannot
// drift apart; adding/removing an entry is a deliberate one-line update here.
const DENY_SYSCALL_COUNT: usize = 82;
const _: () = assert!(DENY_SYSCALLS.len() == DENY_SYSCALL_COUNT);

/// Syscall numbers whose FIRST argument is a target pid/tid. The agent and the
/// warden share uid/gid 0, and Linux's same-owner checks let a same-uid caller
/// retune ANOTHER task without any capability (`check_prlimit_permission`,
/// `check_same_owner` match on uid/gid alone). The guard therefore admits
/// EXACTLY the self target (`args[0] == 0`) and answers EPERM for every other
/// pid/tid — PID 1, a worker-thread tid, or any third pid. This closes the
/// worker-tid hole the old `args[0] == 1` guard left open. `setpriority` is on
/// the deny list instead (its target is args[1]); its self form is the only
/// loss.
const PID1_GUARDED: &[(u32, &str)] = &[
    (142, "sched_setparam"),
    (144, "sched_setscheduler"),
    (203, "sched_setaffinity"),
    (302, "prlimit64"),
    (314, "sched_setattr"),
];

/// Syscalls whose target pid/tid is `args[0]` and whose `args[0] == 1` must be
/// refused. The warden and the agent share uid/gid 0, so the kernel's
/// same-owner check alone would deliver these signals to PID 1; the only
/// reason that is not already fatal is the kernel's global-init immunity
/// (default-action signals to init are ignored and SIGKILL/SIGSTOP are
/// undeliverable), which is a kernel invariant, not a designed control. The
/// filter now enforces the addressed target itself.
///
/// Non-self targets are otherwise ALLOWED here (unlike PID1_GUARDED): agent
/// workloads legitimately signal their own children and process groups
/// (`kill $!`, `kill -TERM 0`). `tgkill`/`rt_tgsigqueueinfo` carry the thread
/// group id in `args[0]`, so `args[0] == 1` covers every thread of PID 1 —
/// targeting tid 1 necessarily means tgid 1. A broadcast `kill(-1, sig)` is
/// not filtered by argument (the raw argument is -1): PID 1's init immunity
/// remains the backstop for non-addressed signals.
const PID1_SIGNAL_GUARDED: &[(u32, &str)] = &[
    (62, "kill"),
    (129, "rt_sigqueueinfo"),
    (200, "tkill"),
    (234, "tgkill"),
    (297, "rt_tgsigqueueinfo"),
];

/// x32 syscall numbers carry this bit on top of the x86_64 number. The arch
/// check does NOT separate them from native syscalls (x32 reports
/// AUDIT_ARCH_X86_64), so a number with this bit set would otherwise fall
/// through every deny leaf into the ALLOW tail. The far-right leaf — the one
/// every `nr` ABOVE the largest list entry reaches — carries the range check
/// instead, so ordinary syscall numbers spend no extra instruction on it.
const X32_SYSCALL_BIT: u32 = 0x4000_0000;

#[derive(Clone, Copy, PartialEq, Eq)]
enum LeafKind {
    /// Exact-match leaf denies with EPERM.
    Deny,
    /// Exact-match leaf falls into the shared `args[0] == 0 → ALLOW, else EPERM`
    /// self-target block.
    Guard,
    /// Exact-match leaf denies only when `args[0]` equals the value; every
    /// other argument is allowed. Used for `socket(AF_VSOCK)`.
    Arg0Eq(u32),
    /// Exact-match leaf falls into the shared `args[0] == PID 1 → EPERM,
    /// else ALLOW` target block (see PID1_SIGNAL_GUARDED).
    Pid1Target,
}

/// AF_VSOCK: the agent has no legitimate use for a vsock socket. The warden's
/// own listener is created before the filter is installed, and guest outbound
/// traffic goes through virtio-net, never vsock.
const AF_VSOCK: u32 = 40;

/// Build the agent filter as a BALANCED BINARY SEARCH TREE over the sorted
/// syscall numbers. The old linear chain executed up to 2N comparisons per
/// syscall; the tree executes ceil(log2 N)+1 comparisons. `entries` MUST be
/// sorted ascending and distinct.
///
/// Layout (classic BPF; jt/jf are u8 offsets from the NEXT instruction):
///   [LD arch][JEQ arch][RET KILL][LD nr]
///   [tree: N-1 × JGE internal nodes + N × JEQ leaves]
///   [RET ERRNO(EPERM)]   <- deny leaf hit
///   [RET ALLOW]          <- leaf miss / syscall not in the list
///   [LD args[0]][JEQ 0][RET ERRNO][RET ALLOW]   <- shared self-target guard
///   [LD args[0]][JEQ 1][RET ALLOW][RET ERRNO]   <- shared PID-1 target guard
///   [JGE nr, X32_BIT][RET ALLOW][RET ERRNO]     <- far-right range check
///
/// Internal node: `nr >= pivot` → right subtree (which contains the pivot);
/// otherwise fall through to the left subtree. A leaf is one exact `JEQ`;
/// its jt is the deny return, the guard block, or the PID-1 target block;
/// its jf the ALLOW tail. The rightmost leaf (reached exactly for
/// `nr > max(entries)`) has its jf redirected to the x32 range check, so
/// only out-of-range numbers pay for it. All targets are patched once the
/// tail offsets are known.
fn build_agent_program(entries: &[(u32, LeafKind)]) -> Vec<libc::sock_filter> {
    let has_guard = entries.iter().any(|e| e.1 == LeafKind::Guard);
    let has_pid1_target = entries.iter().any(|e| e.1 == LeafKind::Pid1Target);
    let arg0_value = entries.iter().find_map(|e| match e.1 {
        LeafKind::Arg0Eq(v) => Some(v),
        _ => None,
    });
    assert!(
        entries.iter().filter(|e| matches!(e.1, LeafKind::Arg0Eq(_))).count() <= 1,
        "at most one args[0]-equality leaf block is supported"
    );
    let mut prog: Vec<libc::sock_filter> = Vec::with_capacity(2 * entries.len() + 20);

    // Load seccomp_data.arch and kill non-x86_64 ABIs. NOTE: the arch check
    // is necessary but NOT sufficient against x32 — x32 syscalls report
    // AUDIT_ARCH_X86_64 and use nr = 0x40000000|N, which matches no deny
    // leaf. The far-right range check below is what closes them.
    prog.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, OFF_ARCH));
    prog.push(bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0));
    prog.push(bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));

    // Load seccomp_data.nr (syscall number).
    prog.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, OFF_NR));

    if entries.is_empty() {
        // No tree: the only remaining rule is the x32 range check.
        prog.push(bpf_jump(
            BPF_JMP | BPF_JGE | BPF_K,
            X32_SYSCALL_BIT,
            1,
            0,
        ));
        prog.push(bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
        prog.push(bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM));
        return prog;
    }

    // Pre-order emission: node, left subtree, right subtree.
    fn emit(prog: &mut Vec<libc::sock_filter>, entries: &[(u32, LeafKind)]) {
        if entries.len() == 1 {
            // Leaf: exact match; jt/jf are patched to the tail targets below.
            prog.push(bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, entries[0].0, 0, 0));
            return;
        }
        let mid = entries.len() / 2;
        let at = prog.len();
        // nr >= pivot -> right (includes the pivot); else fall into left.
        prog.push(bpf_jump(BPF_JMP | BPF_JGE | BPF_K, entries[mid].0, 0, 0));
        emit(prog, &entries[..mid]);
        // Relative to the instruction after this node, skip the left subtree
        // to land on the right subtree's first instruction.
        let left_len = prog.len() - at - 1;
        prog[at].jt = left_len as u8;
        emit(prog, &entries[mid..]);
    }
    emit(&mut prog, entries);

    let tail = prog.len();
    let deny_ret = tail;
    let miss_ret = tail + 1;
    let guard_start = tail + 2;
    let pid1_start = guard_start + if has_guard { 4 } else { 0 };
    let arg0_start = pid1_start + if has_pid1_target { 4 } else { 0 };
    let x32_start = arg0_start + if arg0_value.is_some() { 4 } else { 0 };

    prog.push(bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM)); // deny hit
    prog.push(bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)); // miss
    if has_guard {
        // Shared target check: args[0] == 0 (self) → ALLOW, else EPERM.
        // Nonzero pid/tid covers PID 1, the warden's worker threads, and any
        // third process: the same-uid cross-task attack is closed.
        prog.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, OFF_ARG0));
        prog.push(bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 0));
        prog.push(bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM));
        prog.push(bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
    }
    if has_pid1_target {
        // Shared signal-target check: args[0] == PID 1 → EPERM, every other
        // target → ALLOW (agent children/process groups stay signalable).
        prog.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, OFF_ARG0));
        prog.push(bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, 1, 1, 0));
        prog.push(bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
        prog.push(bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM));
    }
    if let Some(value) = arg0_value {
        // args[0] == value → EPERM, every other argument → ALLOW.
        prog.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, OFF_ARG0));
        prog.push(bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, value, 1, 0));
        prog.push(bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
        prog.push(bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM));
    }
    // x32 range check: nr >= 0x40000000 → EPERM, else ALLOW.
    prog.push(bpf_jump(
        BPF_JMP | BPF_JGE | BPF_K,
        X32_SYSCALL_BIT,
        1,
        0,
    ));
    prog.push(bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
    prog.push(bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM));

    // Classic-BPF jt/jf are u8: the largest target is the far tail.
    let max_target = prog.len() - 1;
    assert!(
        max_target - 4 <= u8::MAX as usize,
        "agent seccomp list too large for classic-BPF 8-bit jump offsets"
    );
    // Patch every leaf JEQ (index 4 is the arch gate's JEQ — skip it).
    for i in 4..tail {
        if prog[i].code == (BPF_JMP | BPF_JEQ | BPF_K) as u16 {
            let kind = entries
                .iter()
                .find(|e| e.0 == prog[i].k)
                .map(|e| e.1)
                .unwrap_or(LeafKind::Deny);
            prog[i].jt = match kind {
                LeafKind::Guard => (guard_start - i - 1) as u8,
                LeafKind::Pid1Target => (pid1_start - i - 1) as u8,
                LeafKind::Arg0Eq(_) => (arg0_start - i - 1) as u8,
                LeafKind::Deny => (deny_ret - i - 1) as u8,
            };
            prog[i].jf = (miss_ret - i - 1) as u8;
        }
    }
    // The rightmost leaf's miss branch sees exactly `nr > max(entries)`:
    // route it to the x32 range check instead of the plain ALLOW.
    let last_leaf = tail - 1;
    assert_eq!(
        prog[last_leaf].code,
        (BPF_JMP | BPF_JEQ | BPF_K) as u16,
        "rightmost tree instruction must be the max element's leaf"
    );
    prog[last_leaf].jf = (x32_start - last_leaf - 1) as u8;
    prog
}

/// Build a deny-only program (no self-target guard leaves). Kept for the
/// small-list/tree-shape tests; production uses `agent_program`.
#[cfg(test)]
fn build_deny_program(denied: &[u32]) -> Vec<libc::sock_filter> {
    let entries: Vec<(u32, LeafKind)> = denied.iter().map(|&n| (n, LeafKind::Deny)).collect();
    build_agent_program(&entries)
}

/// The production entry set: every DENY_SYSCALLS number plus the self-target
/// guard and PID-1 signal-target numbers (a number can be both; deny wins —
/// the guards are only interesting for syscalls that are otherwise allowed).
fn agent_entries() -> Vec<(u32, LeafKind)> {
    let mut map: std::collections::BTreeMap<u32, LeafKind> = std::collections::BTreeMap::new();
    for &(nr, _) in DENY_SYSCALLS {
        map.insert(nr, LeafKind::Deny);
    }
    for &(nr, _) in PID1_GUARDED {
        map.entry(nr).or_insert(LeafKind::Guard);
    }
    for &(nr, _) in PID1_SIGNAL_GUARDED {
        map.entry(nr).or_insert(LeafKind::Pid1Target);
    }
    // socket(2): deny only AF_VSOCK; every other family (AF_INET/AF_INET6/
    // AF_UNIX/AF_NETLINK/...) stays available.
    map.insert(41, LeafKind::Arg0Eq(AF_VSOCK));
    map.into_iter().collect()
}

/// The agent seccomp filter, built once and cached.
///
/// `DENY_SYSCALLS` stays grouped by security class for readability; the
/// filter needs ascending numbers, so the union with `PID1_GUARDED` is sorted
/// here. The program is pure static data shared as one `Arc` by every
/// pre_exec closure (an Arc clone per exec replaces the full rebuild).
pub fn deny_filter() -> std::sync::Arc<[libc::sock_filter]> {
    static DENY_FILTER: std::sync::OnceLock<std::sync::Arc<[libc::sock_filter]>> =
        std::sync::OnceLock::new();
    DENY_FILTER
        .get_or_init(|| {
            build_agent_program(&agent_entries())
                .into_boxed_slice()
                .into()
        })
        .clone()
}

/// Install a previously-built filter in the current thread via
/// `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)`.
///
/// MUST be called from `pre_exec` (after fork, before exec) and only after
/// `PR_SET_NO_NEW_PRIVS` has been set. Safe to call: no allocation, direct
/// syscall. Async-signal-safe.
pub unsafe fn install(filter: &[libc::sock_filter]) -> io::Result<()> {
    let prog = libc::sock_fprog {
        len: filter.len() as libc::c_ushort,
        filter: filter.as_ptr() as *mut libc::sock_filter,
    };
    let rc = libc::prctl(
        PR_SET_SECCOMP,
        SECCOMP_MODE_FILTER as libc::c_ulong,
        &prog as *const _ as libc::c_ulong,
        0,
        0,
    );
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Set PR_SET_NO_NEW_PRIVS on the current thread. Async-signal-safe.
pub unsafe fn set_no_new_privs() -> io::Result<()> {
    let rc = libc::prctl(PR_SET_NO_NEW_PRIVS, 1 as libc::c_ulong, 0, 0, 0);
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

// ── BPF instruction builders ──────────────────────────────────────────

/// BPF_STMT: a non-jump instruction. `code` = opcode class + size/mode, `k` =
/// the immediate (offset for LD|ABS, action for RET, etc.).
fn bpf_stmt(code: u16, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

/// BPF_JUMP: a conditional jump. `code` = BPF_JMP|<op>|BPF_K. `k` = comparison
/// value. `jt`/`jf` = instruction-index offsets taken on true/false.
fn bpf_jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_is_nonempty_and_consistent() {
        let entries = agent_entries();
        let f = deny_filter();
        // 4 prefix + (N-1 JGE nodes + N JEQ leaves) + 2 tail returns +
        // 4-instruction self-target guard block + (4-instruction args[0]
        // equality block when present) + 3-instruction x32 range check.
        let has_arg0 = entries.iter().any(|e| matches!(e.1, LeafKind::Arg0Eq(_)));
        let has_pid1 = entries.iter().any(|e| e.1 == LeafKind::Pid1Target);
        assert_eq!(
            f.len(),
            2 * entries.len() + 12 + if has_arg0 { 4 } else { 0 } + if has_pid1 { 4 } else { 0 }
        );
        // First instruction loads arch.
        assert_eq!(f[0].code, BPF_LD | BPF_W | BPF_ABS);
        assert_eq!(f[0].k, OFF_ARCH);
        let tree = &f[4..2 * entries.len() + 3];
        assert_eq!(
            tree.iter()
                .filter(|i| i.code == (BPF_JMP | BPF_JGE | BPF_K) as u16)
                .count(),
            entries.len() - 1,
            "one JGE internal node per non-leaf"
        );
        assert_eq!(
            tree.iter()
                .filter(|i| i.code == (BPF_JMP | BPF_JEQ | BPF_K) as u16)
                .count(),
            entries.len(),
            "one exact-match leaf per element"
        );
        // Every guard number is represented as a guard leaf (not denied).
        for &(nr, name) in PID1_GUARDED {
            assert!(
                !DENY_SYSCALLS.iter().any(|&(n, _)| n == nr),
                "guard syscall {name} ({nr}) must not also be on the deny list"
            );
            assert!(entries.iter().any(|&(n, k)| n == nr && k == LeafKind::Guard));
        }
        // Same for the PID-1 signal-target entries.
        for &(nr, name) in PID1_SIGNAL_GUARDED {
            assert!(
                !DENY_SYSCALLS.iter().any(|&(n, _)| n == nr),
                "signal-target syscall {name} ({nr}) must not also be on the deny list"
            );
            assert!(entries
                .iter()
                .any(|&(n, k)| n == nr && k == LeafKind::Pid1Target));
        }
    }

    /// Minimal interpreter for the exact classic-BPF subset the filter uses.
    /// Exercises the generated control flow without privileges.
    fn run_filter(prog: &[libc::sock_filter], arch: u32, nr: u32) -> u32 {
        run_filter_args(prog, arch, nr, 0)
    }

    fn run_filter_args(prog: &[libc::sock_filter], arch: u32, nr: u32, arg0: u64) -> u32 {
        let mut a: u32 = 0;
        let mut pc: usize = 0;
        loop {
            let ins = prog[pc];
            match ins.code {
                c if c == (BPF_LD | BPF_W | BPF_ABS) => {
                    a = match ins.k {
                        OFF_NR => nr,
                        OFF_ARCH => arch,
                        OFF_ARG0 => arg0 as u32,
                        other => panic!("unexpected load offset {other}"),
                    };
                    pc += 1;
                }
                c if c == (BPF_JMP | BPF_JEQ | BPF_K) => {
                    let off = if a == ins.k { ins.jt } else { ins.jf };
                    pc += 1 + off as usize;
                }
                c if c == (BPF_JMP | BPF_JGE | BPF_K) => {
                    let off = if a >= ins.k { ins.jt } else { ins.jf };
                    pc += 1 + off as usize;
                }
                c if c == (BPF_RET | BPF_K) => return ins.k,
                other => panic!("unexpected opcode {other:#x} at pc={pc}"),
            }
        }
    }

    #[test]
    fn binary_search_filter_denies_exactly_the_list() {
        let f = deny_filter();
        for &(nr, name) in DENY_SYSCALLS {
            assert_eq!(
                run_filter(&f, AUDIT_ARCH_X86_64, nr),
                SECCOMP_RET_ERRNO | EPERM,
                "{name} ({nr}) must be denied"
            );
        }
        // Common, deliberately-allowed syscalls (read, write, open, execve,
        // exit, kill, uname, exit_group, openat, newfstatat, clone3).
        for nr in [0u32, 1, 2, 59, 60, 62, 63, 231, 257, 262, 435] {
            assert!(
                !DENY_SYSCALLS.iter().any(|&(n, _)| n == nr),
                "test precondition: {nr} must not be in DENY_SYSCALLS"
            );
            assert_eq!(
                run_filter(&f, AUDIT_ARCH_X86_64, nr),
                SECCOMP_RET_ALLOW,
                "unlisted syscall {nr} must be allowed"
            );
        }
        // A non-x86_64 ABI is killed before the syscall number is examined.
        assert_eq!(
            run_filter(&f, 0x4000_0003, 0),
            SECCOMP_RET_KILL_PROCESS
        );
    }

    #[test]
    fn mount_api_pidfd_and_ioprio_classes_denied() {
        // Named pins for the class-completeness additions: a future edit that
        // "cleans up" one of these entries must fail a test whose name says
        // why it exists (the exhaustive sweep below would still fail, but with
        // no hint about the security class that regressed). The guest kernel
        // build also disables USER_NS, so mount_setattr is unreachable in the
        // shipped image; the denial keeps the mount API closed as a class for
        // older kernels and any future profile that hands out a capability.
        assert_eq!(
            DENY_SYSCALLS.len(),
            DENY_SYSCALL_COUNT,
            "deny-list size pin"
        );
        let f = deny_filter();
        for (nr, name) in [
            (442u32, "mount_setattr"),
            // 457/458 — the x86_64 statmount/listmount numbers. Pinning
            // 454/455 here froze the pair's earlier off-by-N onto the
            // futex_wake/futex_wait slots and left the real syscalls open.
            (457, "statmount"),
            (458, "listmount"),
            (434, "pidfd_open"),
            (424, "pidfd_send_signal"),
            (251, "ioprio_set"),
            (154, "modify_ldt"),
        ] {
            assert!(
                DENY_SYSCALLS.iter().any(|&(n, _)| n == nr),
                "{name} ({nr}) must be on the list"
            );
            assert_eq!(
                run_filter(&f, AUDIT_ARCH_X86_64, nr),
                SECCOMP_RET_ERRNO | EPERM,
                "{name} ({nr}) must be denied"
            );
        }
    }

    #[test]
    fn class_completeness_additions_are_denied() {
        // Number-level pins for the class-completeness entries. The numbers
        // matter on x86_64 (the mount-API pair once sat on the futex slots
        // because the wrong numbers were pinned), so each entry is asserted
        // by NUMBER and name, and the filter verdict is exercised.
        let f = deny_filter();
        for (nr, name) in [
            (443u32, "quotactl_fd"),
            (450, "set_mempolicy_home_node"),
            (467, "open_tree_attr"),
        ] {
            assert!(
                DENY_SYSCALLS.iter().any(|&(n, _)| n == nr),
                "{name} ({nr}) must be on the list"
            );
            assert_eq!(
                run_filter(&f, AUDIT_ARCH_X86_64, nr),
                SECCOMP_RET_ERRNO | EPERM,
                "{name} ({nr}) must be denied"
            );
        }
    }

    #[test]
    fn socket_af_vsock_is_denied_other_families_allowed() {
        let f = deny_filter();
        assert_eq!(
            run_filter_args(&f, AUDIT_ARCH_X86_64, 41, AF_VSOCK as u64),
            SECCOMP_RET_ERRNO | EPERM,
            "socket(AF_VSOCK) must be refused"
        );
        // AF_UNSPEC(0), AF_UNIX(1), AF_INET(2), AF_INET6(10), AF_NETLINK(16):
        // the agent's legitimate socket families stay available.
        for family in [0u64, 1, 2, 10, 16] {
            assert_eq!(
                run_filter_args(&f, AUDIT_ARCH_X86_64, 41, family),
                SECCOMP_RET_ALLOW,
                "socket family {family} must stay allowed"
            );
        }
    }

    #[test]
    fn binary_search_filter_allows_every_unlisted_syscall() {
        // EXHAUSTIVE allow-side sweep (the deny side is exhaustively pinned by
        // binary_search_filter_denies_exactly_the_list; this test only sampled
        // ~11 allowed numbers). A mis-patched leaf offset or a wrong internal
        // JGE target that strands a non-denied number onto RET ERRNO would
        // break arbitrary agent code while every existing test stays green —
        // the interpreter walk over the whole allocated syscall range makes
        // that class impossible to reintroduce silently.
        let f = deny_filter();
        let mut denied = [false; 1024];
        let mut guarded = [false; 1024];
        let mut pid1_targeted = [false; 1024];
        for &(nr, _) in DENY_SYSCALLS {
            assert!(nr < 1024, "pin range must cover the deny list");
            denied[nr as usize] = true;
        }
        for &(nr, _) in PID1_GUARDED {
            assert!(nr < 1024, "pin range must cover the guard list");
            guarded[nr as usize] = true;
        }
        for &(nr, _) in PID1_SIGNAL_GUARDED {
            assert!(nr < 1024, "pin range must cover the signal-target list");
            pid1_targeted[nr as usize] = true;
        }
        for nr in 0..1024u32 {
            if denied[nr as usize] {
                continue;
            }
            // arg0 = 0 (not PID 1): always allowed for non-denied numbers.
            assert_eq!(
                run_filter_args(&f, AUDIT_ARCH_X86_64, nr, 0),
                SECCOMP_RET_ALLOW,
                "unlisted syscall {nr} with arg0=0 must be allowed"
            );
            // arg0 = 1: the self-target guard numbers and the PID-1
            // signal-target numbers are refused; everything else is allowed.
            let want = if guarded[nr as usize] || pid1_targeted[nr as usize] {
                SECCOMP_RET_ERRNO | EPERM
            } else {
                SECCOMP_RET_ALLOW
            };
            assert_eq!(
                run_filter_args(&f, AUDIT_ARCH_X86_64, nr, 1),
                want,
                "syscall {nr} with arg0=1 has the wrong verdict"
            );
        }
        // Beyond the allocated range: ordinary high numbers still ALLOW; x32
        // numbers (>= 0x40000000) are refused by the far-right range check.
        for nr in [1024u32, 4096, 449, X32_SYSCALL_BIT - 1] {
            assert_eq!(
                run_filter(&f, AUDIT_ARCH_X86_64, nr),
                SECCOMP_RET_ALLOW,
                "ordinary high nr {nr} must be allowed"
            );
        }
        for nr in [X32_SYSCALL_BIT, X32_SYSCALL_BIT + 1, X32_SYSCALL_BIT + 257, u32::MAX] {
            assert_eq!(
                run_filter(&f, AUDIT_ARCH_X86_64, nr),
                SECCOMP_RET_ERRNO | EPERM,
                "x32 syscall {nr:#x} must be denied"
            );
        }
    }

    #[test]
    fn self_target_guard_admits_only_self() {
        // The guard admits exactly args[0] == 0 (self). Every other target,
        // including PID 1 and the warden's worker-thread tids, is EPERM.
        let f = deny_filter();
        for &(nr, name) in PID1_GUARDED {
            assert_eq!(
                run_filter_args(&f, AUDIT_ARCH_X86_64, nr, 0),
                SECCOMP_RET_ALLOW,
                "{name} ({nr}) targeting self must be allowed"
            );
            for arg0 in [1u64, 2, 12345] {
                assert_eq!(
                    run_filter_args(&f, AUDIT_ARCH_X86_64, nr, arg0),
                    SECCOMP_RET_ERRNO | EPERM,
                    "{name} ({nr}) targeting pid {arg0} must be denied"
                );
            }
        }
        // setpriority is denied outright: its target is args[1], not args[0].
        assert_eq!(
            run_filter_args(&f, AUDIT_ARCH_X86_64, 141, 0),
            SECCOMP_RET_ERRNO | EPERM,
            "setpriority must be denied outright"
        );
    }

    #[test]
    fn pid1_signal_targets_are_denied_and_other_targets_allowed() {
        // The kernel's global-init immunity is the invariant that protects
        // PID 1 from signals today; the filter must additionally refuse the
        // ADDRESSED target so the protection does not rest on it alone.
        // Every non-PID-1 target stays allowed: agent workloads signal their
        // own children and process groups.
        let f = deny_filter();
        for &(nr, name) in PID1_SIGNAL_GUARDED {
            assert_eq!(
                run_filter_args(&f, AUDIT_ARCH_X86_64, nr, 1),
                SECCOMP_RET_ERRNO | EPERM,
                "{name} ({nr}) targeting PID 1 must be denied"
            );
            for arg0 in [0u64, 2, 12345] {
                assert_eq!(
                    run_filter_args(&f, AUDIT_ARCH_X86_64, nr, arg0),
                    SECCOMP_RET_ALLOW,
                    "{name} ({nr}) targeting pid {arg0} must be allowed"
                );
            }
        }
        // Names/numbers pinned: an off-by-N in the table would otherwise
        // silently guard an unrelated syscall.
        for (nr, name) in [
            (62u32, "kill"),
            (129, "rt_sigqueueinfo"),
            (200, "tkill"),
            (234, "tgkill"),
            (297, "rt_tgsigqueueinfo"),
        ] {
            assert!(
                PID1_SIGNAL_GUARDED
                    .iter()
                    .any(|&(n, nm)| n == nr && nm == name),
                "{name} ({nr}) must be on the PID-1 signal-target list"
            );
        }
    }

    #[test]
    fn binary_search_tree_handles_small_and_empty_lists() {
        let lists: &[&[u32]] = &[&[], &[7], &[2, 9], &[1, 3, 5, 7], &[10, 20, 30, 40, 50]];
        for list in lists {
            let prog = build_deny_program(list);
            for &nr in *list {
                assert_eq!(
                    run_filter(&prog, AUDIT_ARCH_X86_64, nr),
                    SECCOMP_RET_ERRNO | EPERM,
                    "denied {nr} in {list:?}"
                );
            }
            for nr in [0u32, 1, 4, 6, 8, 11, 25, 45, 99] {
                if !list.contains(&nr) {
                    assert_eq!(
                        run_filter(&prog, AUDIT_ARCH_X86_64, nr),
                        SECCOMP_RET_ALLOW,
                        "allowed {nr} in {list:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn mqueue_syscalls_are_denied() {
        // Owner ruling: the whole POSIX mqueue family is denied, so a
        // tenant cannot create, send, receive, notify on or configure a queue.
        for nr in [240u32, 241, 242, 243, 244, 245] {
            assert!(
                DENY_SYSCALLS.iter().any(|(n, _)| *n == nr),
                "syscall {} must be denied",
                nr
            );
        }
    }

    #[test]
    fn dangerous_classes_are_denied() {
        // The allowed surface is "everything not denied"; these classes are
        // explicitly forbidden so a future edit cannot silently drop one.
        let required = [
            "pidfd_getfd", "process_madvise", "process_mrelease", "kcmp",
            "create_module", "init_module", "delete_module", "finit_module",
            "get_kernel_syms", "query_module", "uselib",
            "sysfs", "_sysctl", "nfsservctl", "ustat",
            "reboot", "sethostname", "setdomainname", "adjtimex",
            "settimeofday", "clock_settime", "clock_adjtime", "acct",
            "quotactl", "iopl", "ioperm", "lookup_dcookie", "fanotify_init",
            "quotactl_fd", "open_tree_attr", "set_mempolicy_home_node",
            "mknod", "mknodat", "name_to_handle_at",
            "mbind", "set_mempolicy", "get_mempolicy", "migrate_pages",
            "move_pages",
        ];
        for name in required {
            assert!(
                DENY_SYSCALLS.iter().any(|(_, n)| *n == name),
                "required deny entry {name} is missing"
            );
        }
    }

    #[test]
    fn x86_64_setsid_setreuid_are_allowed() {
        // vm86/vm86old are i386-only; on x86_64 their numbers are
        // setsid(112)/setreuid(113), both documented as allowed. A stale
        // i386-numbered deny here would EPERM every daemonizing workload.
        for nr in [112u32, 113] {
            assert!(
                !DENY_SYSCALLS.iter().any(|(n, _)| *n == nr),
                "syscall {} (setsid/setreuid on x86_64) must NOT be denied",
                nr
            );
        }
    }

    #[test]
    fn deny_list_entries_are_distinct_and_named() {
        let mut seen = std::collections::HashSet::new();
        for &(nr, name) in DENY_SYSCALLS {
            assert!(
                seen.insert(nr),
                "duplicate syscall number {} ({})",
                nr,
                name
            );
            assert!(!name.is_empty());
        }
    }

    /// Spawn `/bin/sh -c cmd` with the deny filter installed in pre_exec
    /// (NO_NEW_PRIVS + PR_SET_SECCOMP survive execve) and return
    /// (stdout, stderr, exit code).
    ///
    /// Holds the SHARED cross-module proc lock (crate::test_sync) for the
    /// whole spawn+wait: parallel exec.rs tests run waitpid(-1) reap probes
    /// that would steal this child's exit status → .output() fails ECHILD
    /// (observed as a flaky deploy-blocking failure).
    fn spawn_with_filter(cmd: &str) -> (String, String, Option<i32>) {
        use std::os::unix::process::CommandExt;
        let _guard = crate::test_sync::proc_lock();
        let filter = deny_filter();
        let mut c = std::process::Command::new("/bin/sh");
        c.arg("-c").arg(cmd);
        unsafe {
            c.pre_exec(move || {
                set_no_new_privs()?;
                install(&filter)?;
                Ok(())
            });
        }
        let out = c.output().expect("spawn sh with seccomp filter");
        (
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
            out.status.code(),
        )
    }

    #[test]
    fn filter_installs_and_allowed_syscalls_work() {
        // Installing the filter must not break exec or ordinary syscalls
        // (read/write/getpid/fork...). Runs unprivileged: seccomp install via
        // PR_SET_SECCOMP + NO_NEW_PRIVS needs no capabilities.
        let (stdout, stderr, code) = spawn_with_filter("echo seccomp-ok; id -u >/dev/null; true");
        assert_eq!(code, Some(0), "filtered shell must run normally");
        assert!(stdout.contains("seccomp-ok"), "stdout: {}", stdout);
        assert!(stderr.is_empty(), "stderr: {}", stderr);
    }

    #[test]
    #[ignore]
    fn filter_denies_unshare_under_root() {
        // Differential test (needs root): WITHOUT the filter, root's
        // `unshare -m` succeeds; WITH the filter it must fail EPERM — proving
        // the denial comes from seccomp, not from missing capabilities.
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("skipping: needs root for the differential control");
            return;
        }
        // Control: no filter → unshare -m succeeds.
        let control = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg("unshare -m -- /bin/true")
            .output()
            .expect("spawn control sh");
        assert_eq!(
            control.status.code(),
            Some(0),
            "control (unfiltered) unshare must succeed under root"
        );
        // Filtered: EPERM.
        let (stdout, stderr, code) = spawn_with_filter("unshare -m -- /bin/true");
        assert_ne!(code, Some(0), "unshare must be denied by the filter");
        assert!(
            stderr.contains("Operation not permitted")
                || stdout.contains("Operation not permitted"),
            "expected EPERM, stderr: {} stdout: {}",
            stderr,
            stdout
        );
    }
}

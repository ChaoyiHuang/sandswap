// Copyright 2026 Chaoyi Huang. All rights reserved.
//
// SPDX-License-Identifier: GPL-2.0-only OR BUSL-1.1
//
// Dual-licensed at your option:
//
//   - GPL-2.0-only, the GNU General Public License, version 2 only, as
//     published by the Free Software Foundation (text: LICENSE-GPL-2.0 in
//     this directory). This is the branch the Linux kernel sees: the
//     program calls GPL-only kernel helpers (bpf_probe_read_kernel),
//     which the kernel exposes only to programs whose `license` ELF
//     declaration is GPL-compatible (the MODULE_LICENSE convention, see
//     the bottom of this file), so the copy compiled into a BPF object
//     and loaded into the kernel is GPL-2.0-only.
//
//   - BUSL-1.1: use of this software is governed by the Business Source
//     License included in the LICENSE file at the root of this repository.
//     As of the Change Date specified in that file, in accordance with
//     the Business Source License, use of this software will be governed
//     by the Apache License, Version 2.0.
//
// vsockguard — BPF LSM access control for Sandswap warden vsock port.
// Threat model: a non-privileged local user on the sandlot host can open an
// AF_VSOCK socket and connect() to any guest CID:port WITHOUT going through any
// device node (AF_VSOCK uses socket(2) directly, not /dev/vhost-vsock). Every
// microVM's warden listens on vsock port 1024 and performs ZERO authentication
// (only a 4-byte frame magic that guards against garbage, not attackers). So a
// local user could connect to a warden, send mount+exec frames, and read/modify
// any agent's persisted data.
// This LSM hook denies connect() to AF_VSOCK port 1024 (the warden port) for
// every UID except the one stored in the `allowed_uid` map (the sandlot service
// UID, written by the loader at attach time). It is fail-open if the map is
// unset: that state only exists briefly before the loader populates it, and the
// warden connection is sandlot-initiated after attach.
// Requirements:
//   - CONFIG_BPF_LSM=y in the kernel
//   - the `bpf` LSM active (listed in /sys/kernel/security/lsm). On distros
//     whose CONFIG_LSM default omits `bpf` (e.g. Ubuntu), add `bpf` to the
//     `lsm=` kernel boot parameter once and reboot. See
//     security/setup-bpf-lsm.sh.
//   - root (CAP_BPF + CAP_SYS_ADMIN) to load/attach.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/* UAPI constants not present in BTF (which carries types, not #defines). */
#define AF_VSOCK    40
#define EPERM       1
#define WARDEN_PORT 1024

/* sockaddr_vm (UAPI, uapi/linux/vm_sockets.h) — not in kernel BTF, so defined
 * here by field. We only read svm_family (offset 0) and svm_port (offset 4). */
struct sockaddr_vm {
    __kernel_sa_family_t svm_family; /* offset 0, u16 */
    unsigned short svm_reserved1;    /* offset 2 */
    unsigned int svm_port;           /* offset 4 */
    unsigned int svm_cid;            /* offset 8 */
};

/* Single-entry array holding the UID allowed to connect() to the warden port.
 * Index 0 = the sandlot service UID. Written once by the loader after attach. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
} allowed_uid SEC(".maps");

/* LSM hook: int socket_connect(struct socket *sock, struct sockaddr *address,
 *                              int addrlen) — fires for ALL address families,
 *                              including AF_VSOCK. Return -EPERM to deny. */
SEC("lsm/socket_connect")
int BPF_PROG(vsockguard_socket_connect, struct socket *sock,
             struct sockaddr *address, int addrlen)
{
    u32 key = 0;
    u32 *allowed = bpf_map_lookup_elem(&allowed_uid, &key);
    /* No configured UID → fail open (loader sets it immediately after attach). */
    if (!allowed)
        return 0;

    if (addrlen < (int)sizeof(struct sockaddr_vm))
        return 0;

    /* `address` is a trusted kernel pointer (LSM hook arg), but the verifier
     * does not track its bounds, so use bpf_probe_read_kernel for safety. */
    __kernel_sa_family_t family = 0;
    bpf_probe_read_kernel(&family, sizeof(family), &address->sa_family);
    if (family != AF_VSOCK)
        return 0;

    u32 port = 0;
    bpf_probe_read_kernel(&port, sizeof(port),
                          &((struct sockaddr_vm *)address)->svm_port);
    if (port != WARDEN_PORT)
        return 0;

    u64 uid_gid = bpf_get_current_uid_gid();
    u32 uid = (u32)uid_gid;
    /* Host root is a TRUST ROOT: it can already detach this program, read
     * the warden session key from process memory, or load its own BPF. The
     * guard exists to stop NON-ROOT local users, so root is admitted (this
     * also keeps dev/root-run sandlots functional). */
    if (uid == 0 || uid == *allowed)
        return 0;

    return -EPERM;
}

/* Kernel-facing license declaration, the MODULE_LICENSE convention: libbpf
 * passes this string to BPF_PROG_LOAD, and the verifier allows the GPL-only
 * helpers used above (bpf_probe_read_kernel) only when it is one of the
 * kernel-recognized GPL-compatible strings ("GPL", "GPL v2", "Dual BSD/GPL",
 * "Dual MIT/GPL", "Dual MPL/GPL", "GPL and additional rights"). It corresponds
 * to the GPL-2.0-only branch of this file's dual license. */
char _license[] SEC("license") = "GPL";

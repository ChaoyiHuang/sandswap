#!/bin/bash
# Copyright 2026 Chaoyi Huang. All rights reserved.
#
# SPDX-License-Identifier: BUSL-1.1
#
# Use of this software is governed by the Business Source License
# included in the LICENSE file at the root of this repository.
#
# As of the Change Date specified in that file, in accordance with
# the Business Source License, use of this software will be governed
# by the Apache License, Version 2.0.
#
# build.sh — Provision the guest kernel for sandvmm (PVH ELF vmlinux).
# Modes:
#   ./build.sh            CUSTOM build (the default): clone
#                         cloud-hypervisor/linux at KERNEL_TAG (7.2.8+), apply
#                         the upstream fix series in kernel/patches/ (git apply
#                         --check first; any failure aborts the build), apply
#                         ch_defconfig + CONFIG_IPV6=y + CONFIG_INET_DIAG_DESTROY=y
#                         (+ dependencies), compile, and VERIFY both features in
#                         the final image. This is the only kernel sandswap
#                         supports: routed-ipv6 needs guest v6, and the warden's
#                         cross-tenant TIME_WAIT sweep needs sock_diag destroy.
#                         The pinned tag's baseline predates several upstream
#                         fixes; kernel/patches/ is that backfill. The series is
#                         part of the artifact identity: its digest and the
#                         built .config digest are written beside the image and
#                         re-checked by `check` and the release packager.
#   ./build.sh download   Dev-only shortcut: fetch the pre-built
#                         cloud-hypervisor release kernel (v6.2). CONFIG_IPV6 is
#                         OFF and sock_diag destroy is ABSENT — routed-ipv6 and
#                         the residue sweep silently no-op. NOT for releases
#                         (package-release.sh refuses it) or any topology using
#                         the egress enabler.
#   ./build.sh check      Verify the artifact's version, config revision,
#                         .config digest and applied patch-set digest.
#   ./build.sh patchset-hash
#                         Print the digest of the upstream fix series.
# Output: output/vmlinux.bin  (sandvmm loads ELF+PVH only — bzImage is NOT
# supported, hence `make vmlinux` and never `make bzImage`).
# Env overrides:
#   KERNEL_URL   download URL (default mode)
#   KERNEL_REPO  git remote of the CH linux tree (custom mode)
#   KERNEL_TAG   tag/branch to build (custom mode)
# Prerequisites (custom mode): flex bison bc libelf-dev libssl-dev, plus
# `git` and a C toolchain. Ubuntu: apt install flex bison bc libelf-dev libssl-dev

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT_DIR="$ROOT/output"

KERNEL_URL="${KERNEL_URL:-https://github.com/cloud-hypervisor/linux/releases/download/ch-release-v6.2-20240908/vmlinux}"
KERNEL_REPO="${KERNEL_REPO:-https://github.com/cloud-hypervisor/linux.git}"
# Pinned CH kernel release tag. The CH linux tree carries a root-level
# ch_defconfig (the config their released vmlinux is built from).
KERNEL_TAG="${KERNEL_TAG:-ch-release-v7.2.8-20261009}"
# Full commit the tag must resolve to. The tag is mutable; the build verifies
# the clone HEAD against this and the sidecar records it.
KERNEL_COMMIT="${KERNEL_COMMIT:-639d0886248cd90799b0b590f7a62a1a3565a815}"

# Upstream fix series applied to the pinned tree before configuration. The
# pinned tag's baseline predates the fixes; the files are upstream stable
# backports (the commit message records the mainline hash). They are applied
# in filename order with `git apply --check` first, so a context drift is a
# named build failure instead of a silently different guest kernel.
KERNEL_PATCH_DIR="${KERNEL_PATCH_DIR:-$SCRIPT_DIR/patches}"

# Attack-surface minimization applied to the guest kernel (see the custom-build
# block). FUSE_FS is deliberately NOT in the disabled list: VIRTIO_FS depends
# on it (fs/fuse/Kconfig); only its optional DAX/passthrough/io_uring legs are
# removed. The revision participates in the artifact-currency check so a
# vmlinux built before this policy can never be silently reused.
KERNEL_CONFIG_REV="kernel-7.2.8-minimize-userns-tun-kvm-debugfs-modules-ikconfig-netfilter-kmalloc-partition-kexec-ftrace-umip-legacyvsys-none-connector-audit-modifyldt-unixdiag-no-afalg-rng-hardening"
# Guest-kernel memory hardening. HARDENED_USERCOPY and the kmalloc partition
# caches are cheap and always required. 7.2.8 renamed the old
# RANDOM_KMALLOC_CACHES knob to the promptful KMALLOC_PARTITION_CACHES (the
# old symbol is a hidden transitional alias and cannot be forced on), so the
# gate/enable below use the new pair. The INIT_ON_* pair is selected by
# KERNEL_INIT_HARDENING (both|alloc|free|none): the dev matrix builds the four
# variants with this override, measures cold/warm exec latency, and the release
# default becomes the strongest variant inside the budget. "both" is the
# intended target; a matrix run may move it to "alloc".
KERNEL_INIT_HARDENING="${KERNEL_INIT_HARDENING:-both}"
KERNEL_DISABLED_OPTS="CONFIG_USER_NS CONFIG_TUN CONFIG_VETH CONFIG_KVM CONFIG_MODULES \
CONFIG_DEBUG_FS CONFIG_USERFAULTFD CONFIG_IO_URING \
CONFIG_BPF_SYSCALL CONFIG_CGROUP_BPF CONFIG_OVERLAY_FS CONFIG_POSIX_MQUEUE \
CONFIG_VSOCKETS_DIAG CONFIG_DEVMEM CONFIG_X86_MSR CONFIG_PROC_KCORE \
CONFIG_FUSE_DAX CONFIG_FUSE_PASSTHROUGH CONFIG_FUSE_IO_URING CONFIG_PACKET \
CONFIG_ZSWAP CONFIG_ZRAM CONFIG_ZSMALLOC CONFIG_ZSMALLOC_STAT \
CONFIG_IKCONFIG CONFIG_IKCONFIG_PROC \
CONFIG_NETFILTER CONFIG_NF_CONNTRACK CONFIG_NF_TABLES CONFIG_NETFILTER_NETLINK \
CONFIG_IP_NF_IPTABLES CONFIG_NF_DEFRAG_IPV4 CONFIG_NF_DEFRAG_IPV6 \
CONFIG_BPF_JIT CONFIG_IO_URING_ZCRX \
CONFIG_KEXEC_FILE CONFIG_KEXEC_CORE \
CONFIG_FTRACE CONFIG_FUNCTION_TRACER CONFIG_KPROBES CONFIG_KPROBE_EVENTS \
CONFIG_LIVEPATCH CONFIG_CONNECTOR CONFIG_AUDIT CONFIG_MODIFY_LDT_SYSCALL \
CONFIG_UNIX_DIAG CONFIG_CRYPTO_USER_API_RNG CONFIG_LEGACY_VSYSCALL_XONLY"
# NOTE: CONFIG_IO_URING_BPF is deliberately NOT in this list. In 7.2.8 it is
# `def_bool y` guarded only by BPF && NET (NOT by IO_URING), and CONFIG_BPF is
# selected by other enabled core code, so olddefconfig always re-enables it.
# It is inert with CONFIG_IO_URING=n — and CONFIG_IO_URING is the symbol the
# gate above enforces. Do not add it back without also disabling CONFIG_BPF
# (which the net stack selects).
KERNEL_REQUIRED_OPTS="CONFIG_VIRTIO_FS CONFIG_FUSE_FS CONFIG_VIRTIO_NET \
CONFIG_VIRTIO_CONSOLE CONFIG_VSOCKETS CONFIG_VIRTIO_PCI CONFIG_IPV6 \
CONFIG_INET_DIAG CONFIG_INET_DIAG_DESTROY"

# check_kernel_config <config>: exit 1 (naming every offender) when an
# enforced-disabled symbol is present or a required one is absent. Run on the
# .config AFTER `make olddefconfig`, so `select` edges are already resolved
# exactly as the build will see them.
# check_kernel_config's hardening baseline: cheap symbols always, INIT_ON_*
# per KERNEL_INIT_HARDENING (validated so a typo cannot silently drop a gate).
# The control-flow/memory-layout set is always required: W^X kernel mappings
# (STRICT_KERNEL_RWX), forward-edge CFI (X86_KERNEL_IBT), base randomization
# (RANDOMIZE_BASE, i.e. KASLR), a guard-paged kernel stack (VMAP_STACK),
# stack canaries (STACKPROTECTOR), fortified string/memory helpers
# (FORTIFY_SOURCE), hardened and randomized slab freelists
# (SLAB_FREELIST_HARDENED / SLAB_FREELIST_RANDOM), and page-table isolation
# (MITIGATION_PAGE_TABLE_ISOLATION, i.e. KPTI).
hardening_required_opts() {
    local out="CONFIG_HARDENED_USERCOPY CONFIG_HARDENED_USERCOPY_DEFAULT_ON CONFIG_KMALLOC_PARTITION_CACHES CONFIG_KMALLOC_PARTITION_RANDOM \
CONFIG_STRICT_KERNEL_RWX CONFIG_X86_KERNEL_IBT CONFIG_RANDOMIZE_BASE \
CONFIG_VMAP_STACK CONFIG_STACKPROTECTOR CONFIG_FORTIFY_SOURCE \
CONFIG_SLAB_FREELIST_HARDENED CONFIG_SLAB_FREELIST_RANDOM \
CONFIG_MITIGATION_PAGE_TABLE_ISOLATION CONFIG_X86_UMIP"
    case "$KERNEL_INIT_HARDENING" in
        both)  out="$out CONFIG_INIT_ON_ALLOC_DEFAULT_ON CONFIG_INIT_ON_FREE_DEFAULT_ON" ;;
        alloc) out="$out CONFIG_INIT_ON_ALLOC_DEFAULT_ON" ;;
        free)  out="$out CONFIG_INIT_ON_FREE_DEFAULT_ON" ;;
        none)  ;;
        *)     echo "KERNEL_INIT_HARDENING must be both|alloc|free|none (got $KERNEL_INIT_HARDENING)" >&2; return 1 ;;
    esac
    printf '%s' "$out"
}

check_kernel_config() {
    local cfg="$1" opt bad=0
    for opt in $KERNEL_DISABLED_OPTS; do
        if grep -qE "^${opt}=(y|m)" "$cfg"; then
            echo "kernel config: ${opt} is enabled — the guest attack-surface minimization requires it disabled (selected by another enabled symbol?)" >&2
            bad=1
        fi
    done
    for opt in $KERNEL_REQUIRED_OPTS; do
        if ! grep -q "^${opt}=y" "$cfg"; then
            echo "kernel config: required ${opt} is missing or not built-in — the guest cannot boot, mount its rootfs, or keep its residue sweep" >&2
            bad=1
        fi
    done
    local hardening
    hardening="$(hardening_required_opts)" || return 1
    for opt in $hardening; do
        if ! grep -q "^${opt}=y" "$cfg"; then
            echo "kernel config: memory-hardening ${opt} is missing — the guest kernel is part of the TCB (a compromise survives the tenant switch); enable it or change KERNEL_INIT_HARDENING" >&2
            bad=1
        fi
    done
    return "$bad"
}

# ── Upstream fix series ──────────────────────────────────────────────
# kernel_patch_names — the series in filename order (numeric prefixes carry
# the order). A missing/empty directory is a policy failure, not "no patches":
# the pinned tag's baseline is known to predate the required fixes.
kernel_patch_names() {
    [[ -d "$KERNEL_PATCH_DIR" ]] || return 1
    find -L "$KERNEL_PATCH_DIR" -maxdepth 1 -type f -name '*.patch' -printf '%f\n' \
        | LC_ALL=C sort
}

# kernel_patchset_hash — sha256 over "<file-sha256>  <file-name>" lines of the
# ordered series. This is the artifact's patch-set identity: editing, adding,
# reordering or removing a patch changes it, so `check` refuses an image built
# from a different series. Paths are made relative (the build clones into a
# random temp dir, so absolute paths would make the digest unstable).
kernel_patchset_hash() {
    local dir="$KERNEL_PATCH_DIR" names f
    names="$(kernel_patch_names)" || return 1
    [[ -n "$names" ]] || return 1
    (
        cd "$dir" || exit 1
        while IFS= read -r f; do
            printf '%s  %s\n' "$(sha256sum "$f" | awk '{print $1}')" "$f"
        done <<<"$names"
    ) | sha256sum | awk '{print $1}'
}

# apply_kernel_patches — apply the series to the tree at $PWD in order. Each
# patch is `git apply --check`ed first; a failure names the patch and aborts
# the build (a silently skipped fix must never ship). A reused
# KERNEL_BUILD_DIR tree may already carry the series, so a patch that is
# fully applied in reverse is skipped instead of failing.
kernel_verify_commit() {
    local got
    got="$(git -C "$SRC" rev-parse HEAD 2>/dev/null)" || {
        echo "kernel tree $SRC is not a git checkout — cannot verify the pinned commit" >&2
        exit 1
    }
    if [[ "$got" != "$KERNEL_COMMIT" ]]; then
        echo "kernel tree HEAD $got does not match the pinned commit $KERNEL_COMMIT — refusing a mutable-tag build" >&2
        exit 1
    fi
}

kernel_check_kconfig_symbols() {
    local opt sym
    for opt in $KERNEL_DISABLED_OPTS $KERNEL_REQUIRED_OPTS; do
        sym="${opt#CONFIG_}"
        if ! grep -rqE "^[[:space:]]*(config|menuconfig)[[:space:]]+${sym}[[:space:]]*$" \
                "$SRC"/ --include='Kconfig*' 2>/dev/null; then
            echo "kernel config: $opt is not a Kconfig symbol in the pinned tree — name drift would make -d/-e silently inert" >&2
            exit 1
        fi
    done
}

apply_kernel_patches() {
    local names f
    names="$(kernel_patch_names)" || {
        echo "kernel patch directory missing: $KERNEL_PATCH_DIR" >&2
        exit 1
    }
    [[ -n "$names" ]] || { echo "no kernel patches in $KERNEL_PATCH_DIR" >&2; exit 1; }
    while IFS= read -r f; do
        if git apply --reverse --check "$KERNEL_PATCH_DIR/$f" >/dev/null 2>&1; then
            echo "  patch already applied: $f"
            continue
        fi
        if ! git apply --check "$KERNEL_PATCH_DIR/$f" >/dev/null 2>&1; then
            echo "kernel patch does not apply to $KERNEL_TAG: $f" >&2
            git apply --check "$KERNEL_PATCH_DIR/$f" >&2 || true
            exit 1
        fi
        git apply "$KERNEL_PATCH_DIR/$f" || {
            echo "kernel patch failed to apply: $f" >&2
            exit 1
        }
        echo "  applied: $f"
    done <<<"$names"
}

MODE="${1:-custom}"

mkdir -p "$OUTPUT_DIR"

# kernel_has_ipv6 probes a vmlinux for compiled-in IPv6: with CONFIG_IPV6=n the
# net/ipv6 objects (and their embedded format strings) are absent —
# "ip6_frag_reasm" only exists in net/ipv6/reassembly.o.
# NB: NO `grep -q`: under pipefail, -q makes grep exit on the first match and
# the upstream producer eats SIGPIPE (141) → the probe FAILS on success.
kernel_has_ipv6() {
    strings "$1" 2>/dev/null | grep "ip6_frag_reasm" > /dev/null
}

# kernel_has_inet_diag_destroy probes a FINISHED image for the sock_diag
# SOCK_DESTROY path. The build-time check runs `nm` on the link product, but
# the shipped artifact is post-RSTRIP — the symbol NAME still survives as a
# string (same probe style as kernel_has_ipv6, same no-`grep -q` rule).
kernel_has_inet_diag_destroy() {
    strings "$1" 2>/dev/null | grep "tcp_diag_destroy" > /dev/null
}

# kernel_has_virtio_console probes a FINISHED image for the virtio-console
# driver (guest hvc0). CONFIG_VIRTIO_CONSOLE=n removes the driver and the
# hvc_console registration; the source-path strings are the proof (the
# sandlot launcher sends console=hvc0 and a File console backend).
kernel_has_virtio_console() {
    strings "$1" 2>/dev/null | grep "drivers/char/virtio_console.c" > /dev/null && \
        strings "$1" 2>/dev/null | grep "hvc_console.c" > /dev/null
}

# kernel_has_earlyprintk probes for CONFIG_EARLY_PRINTK. With it off,
# earlyprintk=ttyS0 is ignored and the pre-hvc0 boot/panic output is lost.
kernel_has_earlyprintk() {
    strings "$1" 2>/dev/null | grep "earlyprintk" > /dev/null
}

# kernel_lacks_vsock_loopback pins the guest-side unreachability of the
# warden vsock port: an in-guest process can only reach the port through a
# vsock loopback transport (connect() to the VM's own CID answers ENODEV
# without one; docs/how-it-works/isolation-and-swap.md "The warden's vsock
# port"). A tag whose defconfig enables CONFIG_VSOCKETS_LOOPBACK would
# silently re-expose the raw protocol to guest code. On the FINISHED artifact
# (post-RSTRIP) this strings probe is best-effort — an absent match is
# vacuous when the symbol was stripped — so the authoritative gate is the
# .config check plus the pre-strip nm check inside the custom build below.
kernel_lacks_vsock_loopback() {
    ! strings "$1" 2>/dev/null | grep "vsock_loopback" > /dev/null
}

# kernel_lacks_x32 pins the x32 syscall ABI off. x32 numbers are
# 0x40000000|N and report AUDIT_ARCH_X86_64, so the agent seccomp filter's
# arch check does NOT separate them; the filter carries a far-right range
# check, but that is defense in depth: a kernel with x32 enabled would
# re-open every denied syscall in its x32 spelling. The config gates the
# build; this symbol probe gates the artifact.
kernel_lacks_x32() {
    ! nm "$1" 2>/dev/null | grep -w "x32_sys_call_table" > /dev/null
}

# kernel_version_of — the version banner baked into a built image
# ("Linux version 7.2.8 ..."), used to prove an existing artifact is the
# PINNED release and not an older/newer kernel left behind in output/.
kernel_version_of() {
    strings "$1" 2>/dev/null | grep -oE "Linux version [0-9]+\.[0-9]+\.[0-9]+" \
        | head -1 | awk '{print $3}'
}

# Expected version = the numeric part of the pinned tag
# (ch-release-v7.2.8-20261009 → 7.2.8).
KERNEL_TAG_VERSION="$(sed -E 's/^[^0-9]*v?([0-9]+\.[0-9]+\.[0-9]+).*/\1/' <<<"$KERNEL_TAG")"

# kernel_policy_hash prints the digest of the config policy inputs. The
# sidecar records it; check recomputes it, so a policy edit that forgets to
# bump KERNEL_CONFIG_REV still forces a rebuild.
kernel_policy_hash() {
    printf '%s\n%s\n%s\n%s\n' "$KERNEL_CONFIG_REV" "$KERNEL_DISABLED_OPTS" \
        "$KERNEL_REQUIRED_OPTS" "$KERNEL_INIT_HARDENING" | sha256sum | awk '{print $1}'
}

# kernel_identity_matches <config-rev-file> <patchset-sha256> — the sidecar
# written beside the image must name this config policy, carry a full .config
# digest (provenance of the exact Kconfig output) and the digest of the patch
# series currently in kernel/patches. The patch-set digest is recomputed, so a
# changed series forces a rebuild; the revision string is the policy guard
# (the pinned version banner is identical across config revisions).
kernel_identity_matches() {
    local rev_file="$1" want_patchset="$2"
    local want_cfg cfg_file got_cfg
    [[ -f "$rev_file" ]] || return 1
    grep -qx "rev=$KERNEL_CONFIG_REV" "$rev_file" || return 1
    grep -qxE 'config_sha256=[0-9a-f]{64}' "$rev_file" || return 1
    grep -qx "patchset_sha256=$want_patchset" "$rev_file" || return 1
    grep -qx "tag=$KERNEL_TAG" "$rev_file" || return 1
    grep -qx "commit=$KERNEL_COMMIT" "$rev_file" || return 1
    grep -qx "init_hardening=$KERNEL_INIT_HARDENING" "$rev_file" || return 1
    grep -qx "policy_sha256=$(kernel_policy_hash)" "$rev_file" || return 1
    # The recorded .config digest must match the saved config beside the image.
    want_cfg="$(awk -F= '$1 == "config_sha256" {print $2}' "$rev_file")"
    cfg_file="${rev_file%.config-rev}.config"
    [[ -f "$cfg_file" ]] || return 1
    got_cfg="$(sha256sum "$cfg_file" | awk '{print $1}')"
    [[ "$got_cfg" == "$want_cfg" ]] || return 1
    return 0
}

# kernel_output_is_current — true when $OUTPUT_DIR/vmlinux.bin IS the pinned
# release with BOTH required features compiled in. The artifact itself carries
# the proof, so a match is never worth a ~20-minute rebuild (an mtime rule
# would force one for a comment edit in this script). Escape hatch:
# KERNEL_FORCE_BUILD=1.
kernel_output_is_current() {
    local img="$OUTPUT_DIR/vmlinux.bin"
    [[ -f "$img" ]] || return 1
    [[ "$(kernel_version_of "$img")" == "$KERNEL_TAG_VERSION" ]] || return 1
    # The build writes "<image>.config-rev" (e.g. vmlinux.bin.config-rev) with
    # rev/config_sha256/patchset_sha256 lines; the legacy vmlinux.config-rev
    # name is still read, but a single-line legacy file cannot match the
    # structured identity and therefore forces the rebuild.
    local rev_file patchset
    rev_file="$OUTPUT_DIR/$(basename "$img").config-rev"
    [[ -f "$rev_file" ]] || rev_file="$OUTPUT_DIR/vmlinux.config-rev"
    patchset="$(kernel_patchset_hash)" || return 1
    kernel_identity_matches "$rev_file" "$patchset" || return 1
    kernel_has_ipv6 "$img" || return 1
    kernel_has_inet_diag_destroy "$img" || return 1
    kernel_has_virtio_console "$img" || return 1
    kernel_has_earlyprintk "$img" || return 1
    kernel_lacks_vsock_loopback "$img" || return 1
    kernel_lacks_x32 "$img" || return 1
    return 0
}

case "$MODE" in
config-check)
    if [[ $# -lt 2 ]]; then
        echo "usage: $0 config-check <config-file>" >&2
        exit 2
    fi
    if check_kernel_config "$2"; then
        echo "kernel config gate: PASS ($2)"
        exit 0
    fi
    echo "kernel config gate: FAIL ($2)" >&2
    exit 1
    ;;
patchset-hash)
    # Digest of the ordered upstream fix series. The release packager compares
    # this against the image's sidecar so a packaged vmlinux provably carries
    # the series in this tree.
    kernel_patchset_hash
    ;;
policy-hash)
    kernel_policy_hash
    ;;
expected-identity)
    printf 'tag=%s\ncommit=%s\ninit_hardening=%s\n' \
        "$KERNEL_TAG" "$KERNEL_COMMIT" "$KERNEL_INIT_HARDENING"
    ;;
check)
    # Content check for build.sh's freshness pass: exit 0 when the artifact is
    # the pinned release with both features, non-zero otherwise (missing,
    # wrong version, or a feature absent).
    if kernel_output_is_current; then
        echo "kernel artifact current: version $KERNEL_TAG_VERSION + CONFIG_IPV6 + CONFIG_INET_DIAG_DESTROY + CONFIG_VIRTIO_CONSOLE + CONFIG_EARLY_PRINTK + no vsock_loopback + no x32 ABI + config-rev $KERNEL_CONFIG_REV + patchset $(kernel_patchset_hash)"
        exit 0
    fi
    echo "kernel artifact missing, wrong version (want $KERNEL_TAG_VERSION), config/patch identity stale, or features absent" >&2
    exit 1
    ;;
custom)
    if [[ "${KERNEL_FORCE_BUILD:-0}" != "1" ]] && kernel_output_is_current; then
        echo "=== Kernel already current — skipping the custom rebuild ==="
        echo "Version:  $(kernel_version_of "$OUTPUT_DIR/vmlinux.bin") (pinned: $KERNEL_TAG)"
        echo "Features: CONFIG_IPV6 + CONFIG_INET_DIAG_DESTROY + CONFIG_VIRTIO_CONSOLE + CONFIG_EARLY_PRINTK present in the artifact"
        echo "Identity: config-rev $KERNEL_CONFIG_REV + patchset $(kernel_patchset_hash)"
        echo "Force:    KERNEL_FORCE_BUILD=1 bash $0 $MODE"
        ls -lh "$OUTPUT_DIR/vmlinux.bin"
        exit 0
    fi
    echo "=== Building custom CH kernel (ch_defconfig + CONFIG_IPV6=y + upstream fix series) ==="
    echo "Repo:      $KERNEL_REPO"
    echo "Tag:       $KERNEL_TAG"
    echo "Patches:   $KERNEL_PATCH_DIR"
    echo "Output:    $OUTPUT_DIR/vmlinux.bin"

    for tool in git make gcc; do
        command -v "$tool" > /dev/null || { echo "missing build tool: $tool" >&2; exit 1; }
    done

    # ── Build-space pre-flight ────────────────────────────────────────
    # The build tree is ~2.5 GB of intermediates and the vmlinux link peaks
    # above 3 GB. Two host shapes have killed this build at the link after a
    # full compile: /tmp mounted as a small tmpfs (ENOSPC regardless of how
    # much the root fs has), and a disk-poor host carrying leftovers. Both
    # are handled here, BEFORE the ~20 minute compile, not at the link:
    #   1. When /tmp cannot hold the build, move TMPDIR to the biggest real
    #      filesystem (/var/tmp/kbuild on the release executor).
    #   2. When even that is under the floor, shed leftovers — the k8s stack
    #      first (a k3s cluster left by a previous deploy leg is the single
    #      biggest reclaimable occupier, and the next k8s leg installs its
    #      own cluster), then crash dumps / journal / package / Go caches.
    # Portable df read: GNU df honors -Pm (1M blocks); the uutils df on newer
    # Ubuntu images rejects -m — fall back to POSIX `df -P -k` and scale. This
    # script is standalone (no common/sh/runtime.sh), so the helper lives here.
    kernel_disk_avail_mb() {
        local out
        if out="$(df -Pm "$1" 2>/dev/null | awk 'NR==2 {print $4}')" && [[ -n "$out" ]]; then
            echo "$out"; return 0
        fi
        out="$(df -P -k "$1" 2>/dev/null | awk 'NR==2 {print $4}')"
        [[ -n "$out" ]] && echo $(( out / 1024 )) || echo 0
    }
    KERNEL_BUILD_NEED_MB=6000
    if [[ -z "${TMPDIR:-}" ]] && (( $(kernel_disk_avail_mb /tmp) < KERNEL_BUILD_NEED_MB )); then
        _tmp_avail=$(kernel_disk_avail_mb /tmp)
        mkdir -p /var/tmp/kbuild
        if (( $(kernel_disk_avail_mb /var/tmp) > _tmp_avail )); then
            export TMPDIR=/var/tmp/kbuild
            echo "build space: /tmp has only ${_tmp_avail}MB free — building under $TMPDIR"
        fi
    fi
    _build_base="${TMPDIR:-/tmp}"
    _avail=$(kernel_disk_avail_mb "$_build_base")
    if (( _avail < KERNEL_BUILD_NEED_MB )); then
        if [[ "${SANDSWAP_ALLOW_DESTRUCTIVE_CLEANUP:-0}" != "1" ]]; then
            echo "build space: ${_avail}MB free on $_build_base (need ~${KERNEL_BUILD_NEED_MB}MB) — refusing to uninstall k3s/vacuum journals/clean caches without explicit opt-in; free space or set SANDSWAP_ALLOW_DESTRUCTIVE_CLEANUP=1" >&2
            exit 1
        fi
        echo "build space: ${_avail}MB free on $_build_base (need ~${KERNEL_BUILD_NEED_MB}MB) — shedding leftovers" >&2
        if [[ -x /usr/local/bin/k3s-uninstall.sh ]]; then
            echo "build space: uninstalling the leftover k3s cluster" >&2
            timeout 300 /usr/local/bin/k3s-uninstall.sh >/dev/null 2>&1 || true
        fi
        rm -rf /var/lib/apport/coredump 2>/dev/null || true
        journalctl --vacuum-size=100M >/dev/null 2>&1 || true
        apt-get clean >/dev/null 2>&1 || true
        if command -v go >/dev/null 2>&1; then go clean -cache >/dev/null 2>&1 || true; fi
        _avail=$(kernel_disk_avail_mb "$_build_base")
        if (( _avail < KERNEL_BUILD_NEED_MB )); then
            echo "build space: still only ${_avail}MB free on $_build_base after cleanup — free space and retry" >&2
            exit 1
        fi
        echo "build space: now ${_avail}MB free on $_build_base"
    fi

    # DEV-ONLY incremental matrix mode: KERNEL_BUILD_DIR reuses one tree so a
    # config variant only recompiles the objects whose CONFIG dependencies
    # changed (minutes, not a fresh ~30-minute clone+build). NEVER use it for a
    # release artifact — the release path below keeps the throwaway-tree
    # guarantee that no intermediates linger on a deploy host.
    # The series is validated and digested BEFORE the compile: the artifact's
    # identity records the digest, and a missing/unreadable series must fail
    # here, not after ~20 minutes of build.
    POLICY_SHA="$(kernel_policy_hash)"
    PATCHSET_SHA="$(kernel_patchset_hash)" || {
        echo "kernel patch series missing or unreadable ($KERNEL_PATCH_DIR) — refusing to build the pinned baseline without the upstream backfill" >&2
        exit 1
    }

    FRESH_TREE=1
    if [[ -n "${KERNEL_BUILD_DIR:-}" ]]; then
        echo "=== DEV matrix mode: reusing $KERNEL_BUILD_DIR (incremental; NOT a release artifact) ===" >&2
        SRC="$KERNEL_BUILD_DIR"
        mkdir -p "$SRC"
        if [[ -d "$SRC/.git" ]]; then
            FRESH_TREE=0
        else
            git clone --depth 1 --branch "$KERNEL_TAG" "$KERNEL_REPO" "$SRC"
        fi
        cd "$SRC"
        kernel_verify_commit
        echo "=== Applying upstream fix series ($PATCHSET_SHA) ==="
        apply_kernel_patches
        if [[ "$FRESH_TREE" == 1 ]]; then
            make ch_defconfig
        fi
    else
        SRC="$(mktemp -d "${TMPDIR:-/tmp}/ch-kernel-build-XXXX")"
        # NOTE: the build tree is intentionally under a temp dir and removed
        # afterwards — it is ~2.5 GB of intermediates that must not linger on a
        # deploy host.
        trap 'rm -rf "$SRC"' EXIT

        git clone --depth 1 --branch "$KERNEL_TAG" "$KERNEL_REPO" "$SRC"
        cd "$SRC"
        kernel_verify_commit
        echo "=== Applying upstream fix series ($PATCHSET_SHA) ==="
        apply_kernel_patches
        make ch_defconfig
    fi
    kernel_check_kconfig_symbols
    # The official CH config ships CONFIG_IPV6 unset; routed-ipv6 needs guest v6.
    ./scripts/config -e CONFIG_IPV6
    # Cross-tenant residue cleanup needs sock_diag SOCK_DESTROY (the ss -K
    # mechanism). ORDER MATTERS: scripts/config -e blindly writes =y without
    # checking dependencies — INET_DIAG_DESTROY requires INET_DIAG, which
    # ch_defconfig leaves unset, and kconfig then DROPS the line silently on
    # the next make (this is exactly how a previous build shipped a kernel
    # whose symbol table lacked inet_diag_destroy while the build stayed
    # green). Enable the dependency first, then the feature.
    ./scripts/config -e CONFIG_INET_DIAG
    ./scripts/config -e CONFIG_INET_DIAG_DESTROY
    # The warden's logs use virtio-console hvc0; the earliest boot/panic output
    # uses earlyprintk=ttyS0. Both must be compiled in (VIRTIO is already set
    # by ch_defconfig for fs/net/vsock; enabling the console depends on it).
    ./scripts/config -e CONFIG_VIRTIO_CONSOLE
    ./scripts/config -e CONFIG_EARLY_PRINTK
    # UMIP traps SGDT/SIDT/SLDT/STR/SMSW in userspace; the legacy vsyscall
    # page is removed entirely (modern glibc uses vDSO).
    ./scripts/config -e CONFIG_X86_UMIP
    ./scripts/config -e CONFIG_LEGACY_VSYSCALL_NONE
    # ── Attack-surface minimization ──────────────────────────────────
    # The guest kernel is the in-VM boundary of last resort: a guest-kernel
    # compromise defeats every in-VM clear and an implant survives the tenant
    # switch (docs/how-it-works/threat-model.md §5). Every subsystem the agent
    # cannot legitimately reach is one less parser in that TCB. FUSE_FS stays:
    # VIRTIO_FS `depends on FUSE_FS` (fs/fuse/Kconfig); only its optional
    # DAX/passthrough/io_uring legs are removed. USER_NS is the enabler for
    # the namespace + mount-API classes the seccomp deny-list closes by
    # policy; the warden also writes user/max_user_namespaces=0 at boot for
    # dev/older kernels.
    for opt in $KERNEL_DISABLED_OPTS; do
        ./scripts/config -d "$opt"
    done
    # Memory hardening (see hardening_required_opts): cheap ones always, the
    # INIT_ON_* pair per KERNEL_INIT_HARDENING.
    ./scripts/config -e CONFIG_HARDENED_USERCOPY
    ./scripts/config -e CONFIG_HARDENED_USERCOPY_DEFAULT_ON
    ./scripts/config -e CONFIG_KMALLOC_PARTITION_CACHES
    ./scripts/config -e CONFIG_KMALLOC_PARTITION_RANDOM
    ./scripts/config -e CONFIG_SLAB_FREELIST_RANDOM
    case "$KERNEL_INIT_HARDENING" in
        both)  ./scripts/config -e CONFIG_INIT_ON_ALLOC_DEFAULT_ON
               ./scripts/config -e CONFIG_INIT_ON_FREE_DEFAULT_ON ;;
        alloc) ./scripts/config -e CONFIG_INIT_ON_ALLOC_DEFAULT_ON
               ./scripts/config -d CONFIG_INIT_ON_FREE_DEFAULT_ON ;;
        free)  ./scripts/config -e CONFIG_INIT_ON_FREE_DEFAULT_ON
               ./scripts/config -d CONFIG_INIT_ON_ALLOC_DEFAULT_ON ;;
        none)  ./scripts/config -d CONFIG_INIT_ON_ALLOC_DEFAULT_ON
               ./scripts/config -d CONFIG_INIT_ON_FREE_DEFAULT_ON ;;
    esac
    # Resolve selects/dependencies exactly as the build will, THEN gate on the
    # resulting .config. `select` edges can re-enable a disabled symbol
    # silently; a required symbol can be dropped by a dependency change. Both
    # are build failures with a named cause, never a silent ship.
    make olddefconfig
    check_kernel_config .config || {
        echo "refusing to build a guest kernel that violates the attack-surface policy" >&2
        exit 1
    }
    # Verify the toggles took in .config (a broken tag layout or a new
    # dependency edge must fail loudly here, not silently ship).
    grep -q "^CONFIG_IPV6=y" .config || { echo "CONFIG_IPV6=y not present in .config" >&2; exit 1; }
    grep -q "^CONFIG_INET_DIAG_DESTROY=y" .config || { echo "CONFIG_INET_DIAG_DESTROY=y not present in .config (dependency dropped it?)" >&2; exit 1; }
    grep -q "^CONFIG_VIRTIO_CONSOLE=y" .config || { echo "CONFIG_VIRTIO_CONSOLE=y not present in .config (VIRTIO dependency missing?)" >&2; exit 1; }
    grep -q "^CONFIG_EARLY_PRINTK=y" .config || { echo "CONFIG_EARLY_PRINTK=y not present in .config" >&2; exit 1; }
    grep -q "^CONFIG_X86_UMIP=y" .config || { echo "CONFIG_X86_UMIP=y not present in .config" >&2; exit 1; }
    grep -q "^CONFIG_LEGACY_VSYSCALL_NONE=y" .config || { echo "CONFIG_LEGACY_VSYSCALL_NONE=y not present in .config" >&2; exit 1; }
    # The warden vsock port must stay guest-UNREACHABLE: an in-guest connect
    # to the VM's own CID needs a vsock loopback transport, and the raw
    # protocol (including the v1 empty-identity warm-op compat window) must
    # never be exposed to guest code. Built-in (=y) or module (=m) both count
    # — this tree ships no modules, but the config gate must not depend on
    # that.
    if grep -qE "^CONFIG_VSOCKETS_LOOPBACK=(y|m)" .config; then
        echo "CONFIG_VSOCKETS_LOOPBACK is set — the warden vsock port would be guest-reachable; refusing" >&2
        exit 1
    fi
    # x32 numbers share AUDIT_ARCH_X86_64 with native syscalls, so an x32-capable
    # guest could spell every denied syscall in its x32 form. Refuse the config.
    if grep -qE "^CONFIG_X86_X32(_ABI)?=(y|m)" .config; then
        echo "CONFIG_X86_X32(_ABI) is set — the agent seccomp deny list would be bypassable via x32 syscall numbers; refusing" >&2
        exit 1
    fi
    make -j"$(nproc)" vmlinux
    [[ -f vmlinux ]] || { echo "make vmlinux produced no image" >&2; exit 1; }
    kernel_has_ipv6 vmlinux || { echo "built kernel lacks IPv6 despite CONFIG_IPV6=y" >&2; exit 1; }
    kernel_has_virtio_console vmlinux || { echo "built kernel lacks virtio-console despite CONFIG_VIRTIO_CONSOLE=y" >&2; exit 1; }
    kernel_has_earlyprintk vmlinux || { echo "built kernel lacks earlyprintk despite CONFIG_EARLY_PRINTK=y" >&2; exit 1; }
    # Symbol-table proof the destroy path is compiled in: tcp_diag_destroy's
    # address is stored in the handler table, so it MUST exist when the feature
    # is present. Probe with nm (NOT readelf -s — it TRUNCATES long symbol
    # names, which once made a healthy kernel fail a name-mismatched probe).
    # (grep WITHOUT -q, matching the kernel_has_ipv6 probe's pipefail note:
    # -q + a 111k-line nm producer = SIGPIPE = false failure under pipefail.)
    nm vmlinux 2>/dev/null | grep -w tcp_diag_destroy > /dev/null \
        || { echo "built kernel lacks tcp_diag_destroy despite CONFIG_INET_DIAG_DESTROY=y" >&2; exit 1; }
    # Pre-strip image: the authoritative loopback absence check (the finished
    # artifact's strings probe can only catch the visible case).
    if nm vmlinux 2>/dev/null | grep -w vsock_loopback_transport > /dev/null; then
        echo "built kernel contains vsock_loopback despite CONFIG_VSOCKETS_LOOPBACK unset — refusing" >&2
        exit 1
    fi
    if nm vmlinux 2>/dev/null | grep -w x32_sys_call_table > /dev/null; then
        echo "built kernel contains the x32 syscall table despite CONFIG_X86_X32 unset — refusing" >&2
        exit 1
    fi
    # Content proof the minimized subsystems are absent from the link product
    # (the .config gate above is authoritative; these probes catch a future
    # Kconfig change that re-derives a symbol under a new name/inline path).
    # nm shows local symbols too, and this image is pre-strip.
    #
    # Syscall probes target the __se_sys_* core (generated by SYSCALL_DEFINE
    # together with the implementation), NOT __x64_sys_*: on this tree the x64
    # entry layer emits __x64_sys_<name> for EVERY table slot as a WEAK NI
    # stub that resolves to sys_ni_syscall when the option is off — the weak
    # stub's presence is config-independent and proves nothing (verified on a
    # USERFAULTFD/BPF/IO_URING=n link: the __x64 stubs are all there as 'W',
    # the __se cores are all absent).
    # CONFIG_FTRACE is a menuconfig with no object of its own; the ftrace core
    # (register_ftrace_function) and the function tracer
    # (ftrace_allocate_ftrace_ops) are the symbols that appear when the tracing
    # infrastructure is compiled in. KPROBE_EVENTS is probed through its
    # exported command helper. The kexec_file syscall's implementation core is
    # __do_sys_kexec_file_load (its __x64_* entry wrapper is a weak stub when
    # the syscall is absent, so it proves nothing).
    for sym in create_user_ns tun_chr_open kvm_init debugfs_create_dir \
               __se_sys_userfaultfd __se_sys_bpf \
               __se_sys_io_uring_setup ovl_fill_super __se_sys_mq_open \
               packet_create nf_tables_newrule nf_conntrack_init_net \
               nfnetlink_rcv iptable_filter_init \
               kernel_kexec __do_sys_kexec_file_load \
               register_ftrace_function ftrace_allocate_ftrace_ops \
               register_kprobe kprobe_event_cmd_init klp_enable_patch; do
        # grep WITHOUT -q (same pipefail note as tcp_diag_destroy above):
        # -q exits at the first match and SIGPIPEs the nm producer, which
        # under pipefail turns a FOUND symbol into a non-zero pipeline —
        # a silent miss for the absence check below, a false failure for
        # the required loop.
        if nm vmlinux 2>/dev/null | grep -w "$sym" > /dev/null; then
            echo "built kernel still contains ${sym} — a disabled subsystem re-entered the image" >&2
            exit 1
        fi
    done
    # nm must actually run; a missing/failing nm used to look like "symbol
    # absent" and silently pass the disabled-symbol checks.
    nm vmlinux >/dev/null 2>&1 || { echo "nm failed on the built vmlinux — cannot verify the symbol gate" >&2; exit 1; }
    # Required features must survive the minimization. virtio_fs/fuse prove
    # the rootfs transport; the rest are covered by the feature probes above.
    for sym in virtio_fs_init fuse_dev_init; do
        nm vmlinux 2>/dev/null | grep -w "$sym" > /dev/null \
            || { echo "built kernel lacks required ${sym} — the guest rootfs transport is broken" >&2; exit 1; }
    done
    OUT_NAME="${KERNEL_OUTPUT_NAME:-vmlinux.bin}"
    CONFIG_SHA256="$(sha256sum .config | awk '{print $1}')"
    mkdir -p "$OUTPUT_DIR"
    cp vmlinux "$OUTPUT_DIR/$OUT_NAME"
    cp .config "$OUTPUT_DIR/${OUT_NAME}.config"
    # Artifact identity: the config policy revision, the exact .config digest
    # (now saved beside the image so `check` can verify the bytes, not just
    # the shape), the policy digest, the pinned tag/commit, the init-hardening
    # variant, and the applied patch-series digest.
    {
        printf 'rev=%s\n' "$KERNEL_CONFIG_REV"
        printf 'config_sha256=%s\n' "$CONFIG_SHA256"
        printf 'patchset_sha256=%s\n' "$PATCHSET_SHA"
        printf 'policy_sha256=%s\n' "$POLICY_SHA"
        printf 'tag=%s\n' "$KERNEL_TAG"
        printf 'commit=%s\n' "$KERNEL_COMMIT"
        printf 'init_hardening=%s\n' "$KERNEL_INIT_HARDENING"
    } > "$OUTPUT_DIR/${OUT_NAME}.config-rev"
    echo ""
    echo "=== Custom kernel built: $OUTPUT_DIR/$OUT_NAME (init-hardening=$KERNEL_INIT_HARDENING) ==="
    echo "=== Identity: rev=$KERNEL_CONFIG_REV config_sha256=$CONFIG_SHA256 patchset_sha256=$PATCHSET_SHA ==="
    ls -lh "$OUTPUT_DIR/$OUT_NAME"
    ;;
download)
    echo "ERROR: the prebuilt v6.2 dev kernel is no longer supported." >&2
    echo "  It lacks CONFIG_IPV6 / INET_DIAG_DESTROY / virtio-console and ships a" >&2
    echo "  much larger attack surface than the pinned 7.2.8 build. Use the default" >&2
    echo "  custom build (bash kernel/build.sh) and let --skip-build verify its version." >&2
    exit 1
    ;;
*)
    echo "usage: $0 [custom|check|download|config-check <file>|patchset-hash|policy-hash|expected-identity]" >&2
    exit 1
    ;;
esac

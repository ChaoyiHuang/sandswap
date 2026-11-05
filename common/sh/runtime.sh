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
# runtime.sh — Shared runtime library for e2e test scripts and the
# bare-metal deploy scripts. Single implementation; both trees source this
# file (deploy/baremetal/common.sh resolves it local-first so an independent
# or trimmed deploy tree can carry a copy next to itself).
#
# This is a LEAF library: it must not set shell options (the caller owns
# `set -euo pipefail`), define exit traps, or source anything else. It only
# repairs PATH, defaults a few path variables, and defines functions.
#
# Contents:
#   - PATH repair (sudo secure_path drops toolchain dirs)
#   - Path defaults: ROOT / OUTPUT / DEPLOY_DIR / VOL_ROOT / LOG_DIR
#   - Logging + pass/fail counters (tc_log_*, tc_pass/tc_fail + aliases)
#   - Process/artifact/tools/dev-node/deploy helpers (tc_*)
#   - vsockguard attach/detach (tc_*)
#   - Dedicated-service-identity helpers (ss_*): the kubelet-model users
#     and the setpriv exec wrapper used by EVERY launch path (systemd
#     units, nohup deploys, e2e, sandctl) so development verification runs
#     under the exact production privilege model.

# ──── PATH repair ────
# sudo resets PATH (secure_path), dropping the standard toolchain install
# locations — a root-run script would report go/cargo as "missing" although
# they are installed. Prepend the well-known dirs when absent (same repair
# build.sh applies). Sourcing this file before building anything covers the
# whole suite under `sudo bash ...`.
for pdir in /usr/local/go/bin "${HOME:-/root}/.cargo/bin" /usr/local/cargo/bin; do
    if [[ -d "$pdir" ]] && [[ ":$PATH:" != *":$pdir:"* ]]; then
        PATH="$pdir:$PATH"
    fi
done
export PATH

# ──── Path defaults ────
# A caller-set value always wins (${VAR:-}); deploy scripts typically set
# ROOT themselves before sourcing.
ROOT="${ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
OUTPUT="${OUTPUT:-$ROOT/output}"

# ──── Production vs e2e filesystem roots ────
# SANDSWAP_E2E_ROOT separates BATTERY runs from a co-located production
# deployment: run-all.sh exports it (/var/lib/sandswap-e2e by default, env-
# overridable) so battery artifacts, volumes and seeds live apart from the
# production root and can never clobber it. Everything else keeps the
# production default: production deploy scripts operate on the production
# root by right, and release-package benchmark / deploy-verification runs
# intentionally exercise the production layout (a deployment is uninstalled
# only by an EXPLICIT uninstall — the consumer decides when). An EXPLICIT
# caller-set DEPLOY_DIR/VOL_ROOT always wins over both.
_E2E_ROOT_DEFAULT="/var/lib/sandswap"
if [[ -n "${SANDSWAP_E2E_ROOT:-}" ]]; then
    _E2E_ROOT_DEFAULT="$SANDSWAP_E2E_ROOT"
fi
DEPLOY_DIR="${DEPLOY_DIR:-$_E2E_ROOT_DEFAULT}"
VOL_ROOT="${VOL_ROOT:-$_E2E_ROOT_DEFAULT/volumes}"
LOG_DIR="${LOG_DIR:-/tmp/sandswap-logs}"
# VSOCKGUARD=0 opts out of the best-effort BPF LSM attach (dev hosts where
# the bpf LSM is not enabled).
VSOCKGUARD="${VSOCKGUARD:-1}"

# ──── Logging & pass/fail counters ────

TC_GREEN='\033[0;32m'; TC_YELLOW='\033[1;33m'; TC_RED='\033[0;31m'; TC_BLUE='\033[0;34m'; TC_CYAN='\033[0;36m'; TC_NC='\033[0m'

tc_log_section() { echo -e "\n${TC_GREEN}═══ $1 ═══${TC_NC}"; }
tc_log_step()    { echo -e "${TC_GREEN}[→]${TC_NC} $1"; }
tc_log_warn()    { echo -e "${TC_YELLOW}[!]${TC_NC} $1"; }
tc_log_error()   { echo -e "${TC_RED}[✗]${TC_NC} $1"; }
tc_log_pass()    { echo -e "${TC_GREEN}[✓]${TC_NC} $1"; }
tc_log_info()    { echo -e "    $1"; }

PASS_COUNT=0; FAIL_COUNT=0
tc_pass() { PASS_COUNT=$((PASS_COUNT + 1)); tc_log_pass "$1"; }
tc_fail() { FAIL_COUNT=$((FAIL_COUNT + 1)); tc_log_error "$1"; }

# tc_skip_suite <reason> — the SUITE-LEVEL skip (skip-budget rule, W4(b)): a
# script that cannot run for environment reasons must be VISIBLE in the
# evidence, never a silent exit-0 that the battery counts as PASS. When
# running under run-all.sh (which sets RUNALL_SKIP_DIR + RUNALL_SCRIPT), a
# marker file is left where the battery's verdict loop looks; the battery
# then classifies the run SKIP instead of PASS. Outside the battery the
# marker machinery is inert and the call still prints + exits 0.
tc_skip_suite() {
    local reason="${1:-unspecified}"
    if [[ -n "${RUNALL_SKIP_DIR:-}" && -n "${RUNALL_SCRIPT:-}" ]]; then
        mkdir -p "$RUNALL_SKIP_DIR"
        # The REASON travels in the marker (not an empty touch): the runner
        # records it in the machine-readable result stream, so a skip can be
        # audited ("environment" vs "silently disabled test") without reading
        # the transcript.
        printf '%s\n' "$reason" > "$RUNALL_SKIP_DIR/$RUNALL_SCRIPT"
    fi
    tc_log_warn "SUITE_SKIPPED: $reason"
    exit 0
}

# Unprefixed aliases for convenience
log_section() { tc_log_section "$@"; }
log_step()    { tc_log_step "$@"; }
log_warn()    { tc_log_warn "$@"; }
log_error()   { tc_log_error "$@"; }
log_pass()    { tc_log_pass "$@"; }
log_info()    { tc_log_info "$@"; }
pass()        { tc_pass "$@"; }
fail()        { tc_fail "$@"; }

# Export color constants for scripts that reference them directly (shellcheck
# cannot see the cross-file use — hence the disables).
# shellcheck disable=SC2034
GREEN="$TC_GREEN"
# shellcheck disable=SC2034
YELLOW="$TC_YELLOW"
# shellcheck disable=SC2034
RED="$TC_RED"
# shellcheck disable=SC2034
BLUE="$TC_BLUE"
# shellcheck disable=SC2034
CYAN="$TC_CYAN"
# shellcheck disable=SC2034
NC="$TC_NC"

# ──── Process management ────

# tc_kill_sandswap_procs — find and kill every sandswap-related process by
# name and PID, then verify none remain. Idempotent and safe under `set -e`.
# Used both before a deploy/test (clean slate) and after (no lingering
# processes).
#
# Cleanup steps:
#   1. Kill by exact name (killall)
#   2. Kill by pattern (pgrep -f, catches full-path invocations)
#   3. Kill processes holding gateway/sandlot ports (3001, 9998)
#   4. Force-kill any survivors by PID
#   5. Free vhost-vsock CIDs (rmmod + modprobe) so new VMs can grab CIDs
#   6. Verify process table is clean
tc_kill_sandswap_procs() {
    local ctx="${1:-cleanup}"
    local remaining
    # Pass 1: by exact name (killall matches comm = truncated basename, which is
    # exactly what our binaries are invoked as). sandns included: a
    # leftover dns process holds UDP/TCP :53 and either blocks the next run's
    # DNS bind or (worse, UDP REUSEADDR lets both bind) silently ANSWERS for
    # it against a foreign etcd — a split-brain that once turned a multi-gw
    # self-test green while its own dns unit had never bound.
    killall -9 sandvmm sandlot gateway sandns 2>/dev/null || true
    # Pass 2: by full binary path. NOTE: `pgrep -x -f <name>` can never match —
    # -x compares the FULL command line to the bare name, which is never equal —
    # so match the actual invocation paths instead. Bare `pgrep -f gateway` would
    # kill unrelated operator processes (tail -f gateway.log, port-forwards...).
    # setpriv-exec'd services keep the binary path as argv[0], so these still
    # match under the dedicated-identity model.
    for pat in \
        "$DEPLOY_DIR/sandvmm" "$DEPLOY_DIR/sandlot" "$DEPLOY_DIR/gateway" "$DEPLOY_DIR/sandns" \
        "$OUTPUT/sandvmm" "$OUTPUT/sandlot" "$OUTPUT/gateway" "$OUTPUT/sandns" \
        /usr/local/bin/sandswap-sandvmm /usr/local/bin/sandswap-sandlot /usr/local/bin/sandswap-gateway \
        /usr/local/bin/sandns; do
        pgrep -f "$pat" 2>/dev/null | xargs -r kill -9 2>/dev/null || true
    done
    # Pass 3: kill processes holding the gateway/sandlot ports.
    # This catches cases where the process name doesn't match (e.g., a wrapper).
    for port in 3001 9998; do
        local pids
        pids=$(ss -tlnp 2>/dev/null | grep ":$port " | grep -oE 'pid=[0-9]+' | grep -oE '[0-9]+' || true)
        if [[ -n "$pids" ]]; then
            echo "$pids" | xargs -r kill -9 2>/dev/null || true
        fi
    done
    sleep 1
    # Pass 4: anything still alive, force-kill by PID. Pattern is path-anchored
    # so operator processes that merely mention the words (tail -f gateway.log,
    # journalctl -u sandswap-gateway, kubectl port-forward svc/gateway) are not
    # killed — only real binary invocations match.
    remaining=$(ps aux 2>/dev/null | grep -E "(^|/)(sandvmm|sandlot|gateway|sandns) |(^|/)sandswap-(sandvmm|sandlot|gateway|sandns) " | grep -vE "grep|bash" || true)
    if [[ -n "$remaining" ]]; then
        echo "$remaining" | awk '{print $2}' | xargs -r kill -9 2>/dev/null || true
        sleep 1
        remaining=$(ps aux 2>/dev/null | grep -E "(^|/)(sandvmm|sandlot|gateway|sandns) |(^|/)sandswap-(sandvmm|sandlot|gateway|sandns) " | grep -vE "grep|bash" || true)
    fi
    # Pass 5: free vhost-vsock CIDs. After sandvmm exits, the kernel reclaims
    # CIDs asynchronously (can take seconds). Unloading and reloading the
    # vhost_vsock module releases all CIDs at once — the most reliable method.
    # Best-effort: if the module is in use (rare), skip and sleep instead.
    if [[ -e /sys/module/vhost_vsock ]]; then
        if rmmod vhost_vsock 2>/dev/null; then
            modprobe vhost_vsock 2>/dev/null || true
            # The devtmpfs node is recreated by the reload WITHOUT any
            # guarantee the udev rule (OWNER=sandvmm, 0600) reapplies in
            # time — a stale or default ownership here denies the NEXT
            # run's sandvmm. Restore explicitly; never gamble on udev.
            if [[ -e /dev/vhost-vsock ]]; then
                chown "$SS_SERVICE_USER_VM" /dev/vhost-vsock 2>/dev/null || true
                chmod 0600 /dev/vhost-vsock 2>/dev/null || true
            fi
            tc_log_info "[$ctx] reloaded vhost_vsock module (freed stale CIDs)"
        else
            # Module in use — wait for natural CID release
            sleep 2
        fi
    fi
    if [[ -n "$remaining" ]]; then
        tc_log_warn "[$ctx] sandswap processes still running after kill:"
        echo "$remaining"
    else
        tc_log_pass "[$ctx] no sandswap processes running"
    fi
}

# Alias
kill_sandswap_procs() { tc_kill_sandswap_procs "$@"; }

# ──── Well-known port sets ────
# The three sets the tree actually sweeps. Scripts that need an exact set pass
# ports explicitly; these cover the common sweeps so a caller cannot quietly
# forget one (the drift that let 3001/9997 leak between runs).
SS_PORTS_PROD_STACK="${SS_PORTS_PROD_STACK:-3000 3100 9998 9997}"   # bare-metal/k8s deployment
SS_PORTS_DEV_STACK="${SS_PORTS_DEV_STACK:-3001 3100 9998}"         # e2e battery
SS_PORTS_ETCD="${SS_PORTS_ETCD:-2379 2380}"                        # client + peer

# ss_kill_ports <port>... — SIGKILL every process LISTENing on the given TCP
# ports. Deliberately uses ss (iproute2, always present) instead of fuser
# (psmisc, missing on minimal hosts): a silently-missing fuser turns every
# "|| true" cleanup into a no-op and leaks the port to the next script.
# Under a caller's `set -e -o pipefail`, grep finding NO listener would kill
# the calling script outright — hence the `|| true` on the pipeline.
ss_kill_ports() {
    local pattern
    pattern=$(IFS='|'; echo "$*")
    local pids
    pids=$(ss -tlnp 2>/dev/null | grep -E ":($pattern) " | grep -oE 'pid=[0-9]+' | grep -oE '[0-9]+' | sort -u || true)
    if [[ -n "$pids" ]]; then
        echo "$pids" | xargs -r kill -9 2>/dev/null || true
    fi
    return 0
}

# ss_kill_etcd — stop any etcd still holding the coordination ports (2379
# client + 2380 peer) and WAIT until both are actually free. An embedded etcd
# takes seconds after SIGTERM to close its peer listener, and a one-shot kill
# does not wait — the NEXT script's etcd then fails to bind. Kill repeatedly
# until both ports are unbound or the ~10s budget elapses. ALWAYS returns 0:
# this is best-effort cleanup, and a non-zero here would flip a successful
# script's exit code from inside its EXIT trap. On timeout the warning names
# the holder so the leak is diagnosable.
ss_kill_etcd() {
    local deadline=$((SECONDS + 10))
    while [ "$SECONDS" -lt "$deadline" ]; do
        if ! ss -tln 2>/dev/null | grep -qE ':(2379|2380) '; then
            return 0
        fi
        ss_kill_ports $SS_PORTS_ETCD
        sleep 0.5
    done
    tc_log_warn "etcd ports 2379/2380 still bound after 10s of kills; holder: $(ss -tlnp 2>/dev/null | grep -E ':(2379|2380) ' | tr '\n' ' ')"
    return 0
}

# ss_wait_until <timeout_sec> <cmd...> — poll until <cmd> succeeds, 0.5s
# intervals; returns 1 on timeout. The single wait primitive: the tree had ~12
# hand-rolled `for i in $(seq 1 N); do … sleep 0.5; done` loops whose budgets
# and success predicates drifted apart.
ss_wait_until() {
    local timeout="$1"; shift
    local deadline=$((SECONDS + timeout))
    while (( SECONDS < deadline )); do
        if "$@" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.5
    done
    return 1
}

# ──── Harness exclusivity + leftover cleanup ────
#
# Every e2e/deploy script assumes a CLEAN host (no sandswap units, binaries or
# volatile runtime state from an earlier run). Two DIFFERENT situations look
# identical from inside a script — and they must be handled oppositely:
#
#   leftover  — the previous run is DEAD; its processes are orphans. Kill them.
#   concurrent — another run is ALIVE right now. Killing its processes (which
#                is exactly what a naive "clean first" does) destroys it and
#                the killer too: two harness instances then alternate killing
#                each other's gateways, and every symptom looks like a product
#                bug (a stale full-matrix run + an individual
#                script produce connection-refused bursts and rc=137
#                "Killed" children that take hours to attribute).
#
# The guard below distinguishes them with a PID file and REFUSES on a live
# peer. Leftover cleanup itself stays with the caller (e2e:
# tc_clean_environment; deploy: ss_stop_leftover_services).
SS_HARNESS_PIDFILE="${SS_HARNESS_PIDFILE:-/run/sandswap-harness.pid}"

# ss_harness_guard — refuse to interfere with another LIVE sandswap harness
# run; otherwise record this process as the current one. Liveness is
# kill -0 + a cmdline sanity check (a recycled PID is not a harness run).
#
# NESTING IS LEGITIMATE: several suites invoke other e2e scripts as children
# (vmm-seccomp → smoke.sh, latency-benchmark-load → the aiagent reference
# benchmark). A child inside the CURRENT run's process tree must be allowed;
# only a SIBLING run (a different tree) is refused. The ancestor walk decides.
# Prints a NAMED refusal and exits 1; this is a precondition, not a warning.
ss_harness_guard() {
    local pid cmd live p cur hops=0
    if [[ -r "$SS_HARNESS_PIDFILE" ]]; then
        read -r pid cmd < "$SS_HARNESS_PIDFILE" 2>/dev/null || true
        if [[ -n "${pid:-}" && "$pid" != "$$" ]] && kill -0 "$pid" 2>/dev/null; then
            live="$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null || true)"
            if [[ "$live" == *"/e2e/"* || "$live" == *"/deploy/"* || "$live" == *"sandswap-harness"* ]]; then
                # Nested? Walk $$'s ancestor chain (bounded) looking for pid.
                cur="$$"
                while (( hops < 32 )); do
                    p="$(awk '/^PPid:/{print $2}' "/proc/$cur/status" 2>/dev/null || true)"
                    [[ -n "$p" && "$p" != "0" && "$p" != "$cur" ]] || break
                    if [[ "$p" == "$pid" ]]; then
                        return 0   # descendant of the live run — keep ITS pidfile
                    fi
                    cur="$p"; hops=$((hops + 1))
                done
                tc_log_error "another sandswap harness run is ACTIVE (pid $pid: ${live:0:200})"
                tc_log_error "refusing to start a second run: it would kill the live run's processes (both then fail as if the product were broken)"
                tc_log_error "stop it first (e.g. kill $pid, or systemctl stop the unit that started it), then re-run"
                exit 1
            fi
        fi
    fi
    printf '%s %s\n' "$$" "${BASH_SOURCE[1]:-harness}" > "$SS_HARNESS_PIDFILE" 2>/dev/null || true
    return 0
}

# ss_stop_leftover_services — stop what a DEAD previous run left behind:
# active sandswap units, stray service binaries, the volatile runtime dir.
# NEVER touches data trees (volumes/templates/etc.). Used by the deploy
# preflights; the e2e tree's tc_clean_environment is the bigger sibling.
ss_stop_leftover_services() {
    ss_harness_guard
    if command -v systemctl >/dev/null 2>&1 \
        && systemctl list-units 'sandswap-*' --state=active --no-legend --no-pager 2>/dev/null | grep -q .; then
        tc_log_warn "stopping sandswap units left by a previous run"
        timeout 30 systemctl stop 'sandswap-*' 2>/dev/null || true
    fi
    tc_kill_sandswap_procs "preflight-leftover" >/dev/null 2>&1 || true
    rm -rf /run/sandswap /run/sandswap-state 2>/dev/null || true
    return 0
}

# ──── Disk / memory guards ────

# ss_df_avail_mb <path> — available space on <path>'s filesystem, in MiB.
# The suite's df surface in ONE place because the coreutils flavor split is
# silent inlined: GNU df honors `-Pm` (1M blocks); the uutils df shipped as
# default on newer Ubuntu images rejects `-m` (prints usage, exit 1), which
# an inline `|| echo 0` turns into a quiet 0 — guards then either never fire
# or fire spuriously. Preferred form is GNU; the fallback is POSIX `df -P -k`
# (both flavors honor it) scaled to MiB. Prints 0 (rc 1) when both fail —
# callers treat that as unknown, never as "plenty".
ss_df_avail_mb() {
    local out
    if out="$(df -Pm "$1" 2>/dev/null | awk 'NR==2 {print $4}')" && [[ -n "$out" ]]; then
        echo "$out"
        return 0
    fi
    out="$(df -P -k "$1" 2>/dev/null | awk 'NR==2 {print $4}')"
    if [[ -z "$out" ]]; then
        echo 0
        return 1
    fi
    echo $(( out / 1024 ))
}
# The disk/memory pre-flight a sweep runs. A full battery or deploy matrix
# fills a disk-poor host slowly (volumes trees, container images, build
# caches) and the failure surfaces mid-run as an ENOSPC in an unrelated
# script. When the root fs (or /tmp) drops under the floor, shed the SAFE
# occupiers — crash dumps, journal, package cache, Go's build cache — and
# log what was freed. k3s is deliberately NOT touched here: a deploy
# phase-K leg owns its cluster and must not find it gone; the kernel
# build's own pre-flight (kernel/build.sh) is what sheds k8s leftovers,
# at build time.

ss_disk_guard() {
    local floor_mb="${MATRIX_DISK_FLOOR_MB:-3072}"
    local avail; avail="$(ss_df_avail_mb /)"
    local tmp_avail; tmp_avail="$(ss_df_avail_mb /tmp)"
    local root_low=0 tmp_low=0
    [[ -n "$avail" ]] && (( avail < floor_mb )) && root_low=1
    [[ -n "$tmp_avail" ]] && (( tmp_avail < 1024 )) && tmp_low=1
    (( root_low || tmp_low )) || return 0
    local before="$avail" why=""
    (( root_low == 1 )) && why="/ at ${avail}MB free"
    (( tmp_low == 1 )) && why="${why:+$why, }/tmp at ${tmp_avail:-?}MB free"
    tc_log_warn "disk guard: $why — shedding caches"
    rm -rf /var/lib/apport/coredump 2>/dev/null || true
    journalctl --vacuum-size=100M >/dev/null 2>&1 || true
    apt-get clean >/dev/null 2>&1 || true
    if command -v go >/dev/null 2>&1; then go clean -cache >/dev/null 2>&1 || true; fi
    if (( tmp_low == 1 )); then
        # /tmp on several executors is a small tmpfs: dropping the page
        # cache is the only reclaim that does not touch another tree.
        sync; echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || true
    fi
    avail="$(ss_df_avail_mb /)"
    tc_log_info "disk guard: freed $(( avail - before ))MB (now ${avail}MB free)"
    return 0
}

# ss_mem_guard — the memory half: a host whose available memory is nearly
# gone starves the next script's VM pool (the guest OOM corner instead of
# a clean failure). Dropping the page cache is the one reclaim available
# without killing anything.
ss_mem_guard() {
    local floor_mb="${MATRIX_MEM_FLOOR_MB:-700}"
    local avail; avail="$(awk '/MemAvailable/ {print int($2/1024)}' /proc/meminfo)"
    [[ -n "$avail" ]] || return 0
    (( avail >= floor_mb )) && return 0
    tc_log_warn "memory guard: MemAvailable ${avail}MB < ${floor_mb}MB — dropping page cache"
    sync; echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || true
    avail="$(awk '/MemAvailable/ {print int($2/1024)}' /proc/meminfo)"
    tc_log_info "memory guard: MemAvailable now ${avail}MB"
    return 0
}

# ──── Artifact / tool / device checks ────

tc_check_artifacts() {
    local bins
    if [[ $# -gt 0 ]]; then
        bins=("$@")
    else
        bins=(vmlinux.bin initramfs.cpio.gz sandvmm gateway sandlot)
    fi
    local missing=()
    for bin in "${bins[@]}"; do
        if [[ ! -f "$OUTPUT/$bin" ]]; then
            missing+=("$bin")
        fi
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        tc_log_error "Missing artifacts: ${missing[*]}"
        tc_log_info "Run: bash build/build.sh all"
        exit 1
    fi
    tc_log_pass "All ${#bins[@]} artifacts present in output/"
}

tc_check_tools() {
    local tools
    if [[ $# -gt 0 ]]; then
        tools=("$@")
    else
        tools=(curl)
    fi
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &>/dev/null; then
            tc_log_error "$tool not found"
            exit 1
        fi
    done
    tc_log_pass "Required tools: ${tools[*]}"
}

# ──── Kernel artifact identity (every --skip-build path) ────
# The dev-only `kernel/build.sh download` variant (v6.2, no IPv6/TIME_WAIT
# sweep, expanded attack surface) must never reach a deployment through
# --skip-build. Deploy scripts call ss_verify_kernel_artifact before using an
# existing output/vmlinux.bin; the pinned version is read from the build script
# itself (single source of truth), and the artifact's baked-in banner is
# compared to it.

# ss_pinned_kernel_version [kernel/build.sh] → the numeric version the repo
# pins (KERNEL_TAG=ch-release-v7.2.8-… → 7.2.8).
ss_pinned_kernel_version() {
    local script="${1:-$ROOT/kernel/build.sh}"
    [[ -f "$script" ]] || return 1
    local tag
    tag="$(grep -m1 '^KERNEL_TAG=' "$script" 2>/dev/null \
        | sed -E 's/^KERNEL_TAG=//; s/^\$\{KERNEL_TAG:-//; s/\}"?$//; s/^"//')"
    [[ -n "$tag" ]] || return 1
    sed -E 's/^[^0-9]*v?([0-9]+\.[0-9]+\.[0-9]+).*/\1/' <<<"$tag"
}

# ss_verify_kernel_artifact [image] [kernel/build.sh] — refuse an artifact
# whose version banner is not the pinned version.
ss_verify_kernel_artifact() {
    # Release packages carry output/.release-stamp (same marker that bypasses
    # bm_build_artifacts): the kernel identity was gated at packaging time by
    # `kernel/build.sh check`, the tarball's SHA256SUMS pins the bits, and
    # kernel/build.sh is not shipped — the local-build footgun this check
    # guards against cannot exist here, so the version cross-check is skipped.
    # Dev trees have no stamp and keep the full check.
    if [[ -f "$OUTPUT/.release-stamp" ]]; then
        tc_log_pass "output/.release-stamp present — release package, kernel pinned by SHA256SUMS, version cross-check skipped"
        return 0
    fi
    local image="${1:-$OUTPUT/vmlinux.bin}"
    local script="${2:-$ROOT/kernel/build.sh}"
    local want got
    want="$(ss_pinned_kernel_version "$script")" \
        || { tc_log_error "cannot read the pinned kernel version from $script"; return 1; }
    if [[ ! -f "$image" ]]; then
        tc_log_error "kernel artifact missing: $image"
        return 1
    fi
    got="$(strings "$image" 2>/dev/null | grep -oE 'Linux version [0-9]+\.[0-9]+\.[0-9]+' | head -1 | awk '{print $3}')"
    if [[ "$got" != "$want" ]]; then
        tc_log_error "kernel artifact $image is version '${got:-unknown}', but this deployment requires the pinned ${want} — refusing to deploy a non-pinned kernel (the dev download variant is not deployable; build with: bash kernel/build.sh)"
        return 1
    fi
    tc_log_pass "kernel artifact version $got matches the pinned $want"
    return 0
}

# ss_ensure_dev_nodes — create the essential device nodes, load vhost_vsock,
# and RE-ASSERT the per-owner modes. Idempotent; safe to call on every run.
#
# This is the ONE implementation (the e2e tree's tc_ensure_dev_nodes and the
# deploy tree's sandswap_setup_dev_nodes were divergent copies — the deploy one
# re-asserted /dev/kvm's 0660 root:kvm and the e2e one did not, so a host whose
# devtmpfs default (0660 root:root) survived a reboot failed only on the e2e
# side, after /dev/kvm had been recreated by the kernel).
#
# Repair runs on EXISTING nodes too: a module reload recreates devtmpfs nodes
# without guaranteeing the udev rules (OWNER=…) reapply, and an id migration
# (usermod) leaves the old numeric owner on nodes udev never touches again.
# Explicit-restore doctrine: never gamble on udev timing.
#
# Device isolation (per-owner, exactly one process identity each):
#   /dev/kvm          OWNER=root GROUP=kvm 0660 — kvm GROUP membership is the
#                     whole grant (verify-host-security check 4 flags 0666).
#   /dev/vhost-vsock  OWNER=sandvmm 0600 — the ONLY user is the VMM (guest CID
#                     registration); sandlot loses it entirely.
#   /dev/vsock        OWNER=sandlot 0600 — defense-in-depth lockdown; the
#                     sandvmm identity (a member of the shared group for
#                     storage) must not reach it.
#   /dev/net/tun      OWNER=root GROUP=<shared> 0660 — sandvmm opens it for the
#                     TAP; it is in the shared group. Without the identities
#                     (dev host) fall back to 0666 so a root-run probe works.
ss_ensure_dev_nodes() {
    tc_log_step "Ensuring essential device nodes and kernel modules..."
    _ensure_dev_node() {
        local path="$1" major="$2" minor="$3" mode="$4"
        if [[ ! -e "$path" ]]; then
            mkdir -p "$(dirname "$path")" 2>/dev/null || true
            mknod "$path" c "$major" "$minor" 2>/dev/null || true
            chmod "$mode" "$path" 2>/dev/null || true
        fi
    }
    _ensure_dev_node /dev/kvm        10 232 660   # KVM (group grant)
    _ensure_dev_node /dev/net/tun    10 200 666   # TUN/TAP for microVM networking
    _ensure_dev_node /dev/urandom     1   9 666   # Entropy source for virtio-rng
    _ensure_dev_node /dev/random      1   8 666   # Blocking entropy source
    # Load vhost-vsock kernel module for zero-VMEXIT vsock transport
    modprobe vhost_vsock 2>/dev/null || true
    if [[ -e /dev/kvm ]] && getent group kvm >/dev/null 2>&1; then
        chown root:kvm /dev/kvm 2>/dev/null || true
        chmod 0660 /dev/kvm 2>/dev/null || true
    fi
    if [[ -e /dev/vhost-vsock ]]; then
        chown "$SS_SERVICE_USER_VM" /dev/vhost-vsock 2>/dev/null || true
        chmod 0600 /dev/vhost-vsock 2>/dev/null || true
    fi
    if [[ -e /dev/vsock ]]; then
        chown "$SS_SERVICE_USER_SL" /dev/vsock 2>/dev/null || true
        chmod 0600 /dev/vsock 2>/dev/null || true
    fi
    if [[ -e /dev/net/tun ]]; then
        if getent group "$SS_SHARED_GROUP" >/dev/null 2>&1; then
            chgrp "$SS_SHARED_GROUP" /dev/net/tun 2>/dev/null || true
            chmod 0660 /dev/net/tun 2>/dev/null || true
        else
            chmod 0666 /dev/net/tun 2>/dev/null || true
        fi
    fi
    tc_log_pass "Device nodes and vhost_vsock ready"
}

# tc_ensure_dev_nodes — e2e-tree alias of ss_ensure_dev_nodes (kept: every
# e2e script calls it by this name).
tc_ensure_dev_nodes() { ss_ensure_dev_nodes "$@"; }

# Aliases
check_artifacts() { tc_check_artifacts "$@"; }
check_tools()     { tc_check_tools "$@"; }
ensure_dev_nodes() { tc_ensure_dev_nodes "$@"; }

# ──── Deploy ────

# tc_deploy_artifacts — copy all binaries and rootfs-template to DEPLOY_DIR
# with size verification.
tc_deploy_artifacts() {
    tc_log_step "Deploying to $DEPLOY_DIR ..."

    mkdir -p "$DEPLOY_DIR"

    for bin in vmlinux.bin initramfs.cpio.gz sandvmm gateway sandlot; do
        if [[ ! -f "$OUTPUT/$bin" ]]; then
            tc_log_error "missing source artifact: $OUTPUT/$bin"
            exit 1
        fi
        cp -f "$OUTPUT/$bin" "$DEPLOY_DIR/$bin"
        if [[ $? -ne 0 ]] || [[ ! -s "$DEPLOY_DIR/$bin" ]]; then
            tc_log_error "failed to copy $bin to $DEPLOY_DIR"
            exit 1
        fi
        # cp PRESERVES an existing destination's mode, so a file once written
        # under a restrictive umask stays unreadable for the service identities
        # forever (measured: an 0600 initramfs the VMM identity could not open,
        # which blocks every VM boot). Set the modes explicitly instead.
        case "$bin" in
            sandvmm|gateway|sandlot) chmod 0755 "$DEPLOY_DIR/$bin" ;;
            *)                       chmod 0644 "$DEPLOY_DIR/$bin" ;;
        esac
        local src_size dst_size
        src_size=$(stat -c%s "$OUTPUT/$bin" 2>/dev/null || echo 0)
        dst_size=$(stat -c%s "$DEPLOY_DIR/$bin" 2>/dev/null || echo 0)
        if [[ "$src_size" != "$dst_size" ]]; then
            tc_log_error "$bin copy mismatch: src=$src_size dst=$dst_size"
            exit 1
        fi
    done

    # bindregdump (egress identity region inspector) — optional artifact;
    # present when the enabler is built. Copied best-effort for conformance
    # tests; core e2e suites do not require it.
    if [[ -f "$OUTPUT/bindregdump" ]]; then
        cp -f "$OUTPUT/bindregdump" "$DEPLOY_DIR/bindregdump"
    fi

    # Rootfs template directory — set up as a versioned flat template:
    #   $DEPLOY_DIR/flat-templates/rootfs/v1/  ← busybox rootfs
    # The SANDSLOT's prov role scans it (-flat-templates
    # $DEPLOY_DIR/flat-templates); ScanFlatTemplates registers "rootfs:v1"
    # (mode=flat). The gateway never reads this tree (no local storage mode).
    if [[ -d "$OUTPUT/rootfs-template" ]]; then
        rm -rf "$DEPLOY_DIR/flat-templates"
        mkdir -p "$DEPLOY_DIR/flat-templates/rootfs/v1"
        cp -a "$OUTPUT/rootfs-template/." "$DEPLOY_DIR/flat-templates/rootfs/v1/"
        if [[ ! -d "$DEPLOY_DIR/flat-templates/rootfs/v1/bin" ]]; then
            tc_log_error "rootfs-template directory copy failed (no bin/ subdir)"
            exit 1
        fi
        # Template contract (docs/operations/template-contract.md): the SEED
        # identity (sandprov, gid = the shared group) must be able to read every
        # entry, and a `cp -a` preserves source ownership — a 0640 root:root file
        # (e.g. the ubuntu tree's etc/.pwd.lock) then fails the sandfs create
        # with an opaque EACCES. Ownership is not repairable by chmod, so grant
        # it here, exactly as the build/deploy scripts do. Best effort when the
        # identities or the tool are absent (dev hosts).
        if getent group "${SS_SHARED_GROUP:-sandlot}" >/dev/null 2>&1; then
            chgrp -R "${SS_SHARED_GROUP:-sandlot}" "$DEPLOY_DIR/flat-templates" 2>/dev/null || true
        fi
        if [[ -x "$OUTPUT/template-tool" ]]; then
            "$OUTPUT/template-tool" normalize "$DEPLOY_DIR/flat-templates" >/dev/null 2>&1 || true
            "$OUTPUT/template-tool" validate "$DEPLOY_DIR/flat-templates" >/dev/null 2>&1 \
                || tc_log_warn "staged template fails offline validation (contract or rootfs shape): $DEPLOY_DIR/flat-templates"
        fi
        tc_log_info "Flat template deployed: $DEPLOY_DIR/flat-templates/rootfs/v1/ (ref: rootfs:v1)"
    else
        tc_log_error "missing rootfs-template directory: $OUTPUT/rootfs-template/"
        exit 1
    fi

    chmod +x "$DEPLOY_DIR/sandvmm" "$DEPLOY_DIR/gateway" "$DEPLOY_DIR/sandlot"
    tc_log_pass "Artifacts deployed (all copies verified, sizes match build output)"
    tc_log_info "Volumes:  $VOL_ROOT"
    tc_log_info "Logs:     $LOG_DIR"
}

# Alias
deploy_artifacts()  { tc_deploy_artifacts "$@"; }

# ──── vsockguard ────

# tc_attach_vsockguard — attach BPF LSM vsock guard. Best-effort: if the
# `bpf` LSM is not active on this host, the loader refuses to attach and
# we warn and continue. Sets VSOCKGUARD_ATTACHED.
# Default pin: the sandlot service identity — under the dedicated-identity
# model it is the ONLY local user allowed to connect() to the warden vsock
# port (uid-0 pins break every non-root sandlot). An explicit argument wins.
tc_attach_vsockguard() {
    local uid="${1:-$(id -u "$SS_SERVICE_USER_SL" 2>/dev/null || echo 0)}"
    VSOCKGUARD_ATTACHED=0
    if [[ "$VSOCKGUARD" == "1" ]] && [[ -x "$ROOT/security/vsockguard-attach.sh" ]]; then
        tc_log_step "Attaching vsockguard (BPF LSM vsock guard)..."
        if bash "$ROOT/security/vsockguard-attach.sh" "$uid" >/tmp/vsg-attach.log 2>&1; then
            tc_log_pass "vsockguard attached (allowed uid=$uid)"
            VSOCKGUARD_ATTACHED=1
        else
            tc_log_warn "vsockguard NOT attached (bpf LSM inactive on this host?)."
            tc_log_warn "  To enable: sudo bash security/setup-bpf-lsm.sh && reboot. Functional test continues."
            cat /tmp/vsg-attach.log | sed 's/^/    /' 2>/dev/null || true
        fi
    fi
}

# tc_detach_vsockguard — detach BPF LSM vsock guard. Best-effort.
tc_detach_vsockguard() {
    if [[ "${VSOCKGUARD_ATTACHED:-0}" == "1" ]] && [[ -x "$ROOT/security/vsockguard-detach.sh" ]]; then
        bash "$ROOT/security/vsockguard-detach.sh" >/dev/null 2>&1 || true
    fi
}

# Aliases
attach_vsockguard() { tc_attach_vsockguard "$@"; }
detach_vsockguard() { tc_detach_vsockguard "$@"; }

# ═══════════════════════════════════════════════════════════════════════
# Dedicated service identity (kubelet model)
# ═══════════════════════════════════════════════════════════════════════
# Every launch path (systemd units, nohup deploys, e2e, sandctl) runs the
# services as dedicated non-root users — development verification uses the
# exact production privilege model, so permission bugs cannot hide behind a
# root-shaped dev environment. The model mirrors kubelet: a per-node daemon
# needs elevated CAPABILITIES, not uid 0 and not sudo.
#
#   sandserv — gateway + sandns (+ etcd in dev clusters): owns credential state
#     (identity-store.json is 0600), no device access
#   sandlot  — sandlot + its sandvmm children: kvm group for /dev/kvm +
#     /dev/vhost-vsock (0660 root:kvm via deploy/udev/99-sandswap-vsock.rules),
#     sandlot primary group for the shared volumes root

# shellcheck disable=SC2034
SS_SERVICE_USER_GW="${SS_SERVICE_USER_GW:-sandserv}"
# shellcheck disable=SC2034
SS_SERVICE_USER_SL="${SS_SERVICE_USER_SL:-sandlot}"
# The VMM identity: sandvmm runs every sandvmm process (VMM + the FUSE
# passthrough daemon that applies guest-requested file operations) SEPARATE
# from sandlot. sandlot is the uid vsockguard trusts on the warden vsock
# port — keeping the guest-data-parsing daemon OFF that uid means a planted
# setuid file, or a full sandvmm compromise, can never reach the warden
# transport identity. sandvmm itself carries ZERO capabilities: sandlot
# spawns it via a uid transition (CAP_SETUID on sandlot), and the kernel
# clears every capability set when the effective uid changes.
# shellcheck disable=SC2034
SS_SERVICE_USER_VM="${SS_SERVICE_USER_VM:-sandvmm}"
# The PROV identity (sandfs/template lifecycle on shared storage). It OWNS the
# volumes root, because it is the only process that may create or remove
# entries there (EnsureVolume, DeleteVolume, the orphan-rename fallback) — the
# FUSE daemon (sandvmm) opens that directory read-only, so a guest-driven
# escape that names something at the share root fails in the KERNEL, not only
# in the daemon's own gate (see ss_prepare_dirs). Defaults to the sandlot
# identity because dev/e2e run the merged `exec,prov` instance as sandlot;
# production deployments (which run a dedicated prov instance) set sandprov.
# shellcheck disable=SC2034
SS_PROV_USER="${SS_PROV_USER:-$SS_SERVICE_USER_SL}"
# shellcheck disable=SC2034
SS_SERVICE_GROUP="${SS_SERVICE_GROUP:-sandserv}"
# The SHARED group on volumes/logs/certs is the sandlot user's PRIMARY group
# (not the sandserv group). The guest never sees host numbers at all — the
# virtiofs daemon presents ownership as 0:0 at the FUSE egress
# (passthrough::present_guest_ownership) — so the group choice is purely a
# HOST-side sharing decision, and the primary group is the only one a
# process's own file creations carry by default:
#   - daemon-created files: group = sandlot primary → gateway (a member)
#     can read/seed alongside them
#   - prov-seeded files (sandprov, the provision identity): created inside
#     setgid-sandlot dirs (VOL_ROOT chain) → group sandlot; group rw
#     (0664/2775) keeps them writable by the daemon
# The gateway/sandns identities join NO group: the storage plane belongs to
# sandprov (seeding) and sandvmm (serving), never to the external-facing
# identity.
# shellcheck disable=SC2034
SS_SHARED_GROUP="${SS_SHARED_GROUP:-sandlot}"

# Pinned identities (stable uid across hosts and deploys — vsockguard pins
# and file ownership depend on the NUMBER). Chosen in the SYSTEM uid range
# (below SYS_UID_MAX 999, so useradd -r stays warning-free) on slots that
# are free of the standard systemd-distro users (messagebus 996,
# systemd-network 998, sshd 988, ...) and of the cloud human users (1000+):
#   sandlot  uid 985, primary group sandlot — exec role of the per-node daemon
#   sandserv uid 986, group sandserv  — external-facing identity (gateway/sandns)
#   sandvmm  uid 987, group sandvmm   — VMM + FUSE passthrough daemon
#   sandprov uid 983, group sandprov  — provision identity (sandfs/template
#                                       lifecycle on shared storage; carries
#                                       the storage grant the gateway sheds)
# Slot choice: 988-995 are DISTRO-occupied on Debian/Ubuntu (sshd 988,
# _chrony 989, systemd-resolve 990 + the render/kvm/clock/sgx/input GROUPS
# 991-995) — pick free-in-BOTH-passwd-and-group slots only. 983 sits directly
# under our 985-987 block and is free on stock Debian/Ubuntu.
# baremetal resolves every pin dynamically (vsockguard attaches
# $(id -u sandlot)), so no hardcoding exists anywhere; a host whose
# 984-987 are already taken fails LOUDLY in ss_ensure_service_users —
# free the slot or export SS_UID_SANDLOT/SS_UID_SANDSERV/SS_UID_SANDVMM/
# SS_UID_SANDPROV with free numbers.
SS_UID_SANDLOT="${SS_UID_SANDLOT:-985}"
SS_UID_SANDSERV="${SS_UID_SANDSERV:-986}"
SS_UID_SANDVMM="${SS_UID_SANDVMM:-987}"
SS_UID_SANDPROV="${SS_UID_SANDPROV:-983}"
# Gids are pinned TOO (same numbers): shared-storage deployments (NFS and
# every numeric-credential distributed fs) carry group ownership as bare
# numbers across nodes — a dynamically-assigned gid breaks the setgid/shared
# group model the moment a volume migrates or a second node mounts. See
# docs/operations/storage.md (storage contract: numeric uid/gid fidelity).
SS_GID_SANDLOT="${SS_GID_SANDLOT:-985}"
SS_GID_SANDSERV="${SS_GID_SANDSERV:-986}"
SS_GID_SANDVMM="${SS_GID_SANDVMM:-987}"
SS_GID_SANDPROV="${SS_GID_SANDPROV:-983}"
# Template-store METADATA group (refs/): prov (writer) + exec sandlot
# (reads refs to mount overlays), deliberately EXCLUDING sandvmm — the FUSE
# daemon reads layer CONTENT through the shared volume group, and has no
# business enumerating the store's ref namespace. Pinned for shared-storage
# numeric fidelity like every other identity group.
SS_GID_TPL="${SS_GID_TPL:-982}"
SS_GROUP_TPL="${SS_GROUP_TPL:-sandtmpl}"

# ── Configurable service identities (occupied-slot resolution) ──
# Defaults stay contract-pinned (985/986/987/983) for fleet uniformity, but a
# host whose slots are already taken by foreign accounts now RESOLVES instead
# of dying:
#   1. an existing same-NAME account is ADOPTED — its number wins (this is
#      what makes re-runs and pre-provisioned hosts work);
#   2. a missing account takes the requested number; on collision it
#      auto-picks a free system-range slot free in BOTH passwd and group,
#      with a loud WARN (single-host safe);
#   3. SS_ID_STRICT=1 restores the old die-on-any-drift behavior for fleets
#      that must stay numerically pinned;
#   4. after resolution the four uids (and gids) must be pairwise DISTINCT
#      and nonzero — ALWAYS fatal otherwise: the identity SPLIT is the
#      load-bearing control (vsockguard trusts sandlot's uid; sandprov alone
#      reads the seed; sandvmm owns the volumes files).
# Shared-storage caveat: uids/gids travel as bare NUMBERS across nodes (NFS
# numeric-credential fidelity) — for multi-node fleets export SS_UID_* /
# SS_GID_* identically on EVERY node instead of relying on per-host auto-pick.
SS_ID_STRICT="${SS_ID_STRICT:-0}"

# ss_pick_free_system_id <kind:uid|gid> <taken...> — first free slot scanning
# the system range downward, free in BOTH databases (keeps passwd and group
# slots unambiguous for the shared-storage contract), skipping every id named
# on the command line.
ss_pick_free_system_id() {
    local kind="$1"; shift
    local id_
    for id_ in $(seq 999 -1 600); do
        case " $* " in *" $id_ "*) continue ;; esac
        getent passwd "$id_" >/dev/null 2>&1 && continue
        getent group  "$id_" >/dev/null 2>&1 && continue
        echo "$id_"; return 0
    done
    return 1
}

# ss_resolve_group <name> <varname> — idempotent group provisioning with the
# adopt / auto-pick semantics above. Exports the resolved gid in varname.
ss_resolve_group() {
    local name="$1" var="$2"
    local want="${!var:-}" cur ent
    # `|| true` inside the substitution: getent exits 2 for an ABSENT group and
    # under the harness's `set -o pipefail` that rc killed the whole resolver
    # before the create branch could run (first hit live: the new sandtmpl
    # group on a host without it — every pre-existing group masked this).
    ent="$(getent group "$name" 2>/dev/null || true)"
    cur="$(printf '%s' "$ent" | cut -d: -f3)"
    if [[ -n "$cur" ]]; then
        if [[ "$cur" != "$want" ]]; then
            if [[ "$SS_ID_STRICT" == 1 ]]; then
                tc_log_error "group '$name' exists with gid $cur, want $want (SS_ID_STRICT=1 — pinned fleet). Fix: free the slot or export SS_GID_* consistently."
                exit 1
            fi
            tc_log_warn "group '$name' adopts existing gid $cur (requested $want) — the resolved value wins on this host"
        fi
        export "$var=$cur"
        return 0
    fi
    if [[ -z "$want" ]]; then
        groupadd -r "$name" || { tc_log_error "groupadd $name failed"; exit 1; }
        export "$var=$(getent group "$name" | cut -d: -f3)"
        return 0
    fi
    if ! groupadd -r -g "$want" "$name" 2>/dev/null; then
        if [[ "$SS_ID_STRICT" == 1 ]]; then
            tc_log_error "groupadd $name failed: gid $want taken (SS_ID_STRICT=1). Free it or export SS_GID_$(_ss_upper "$name") with a free number."
            exit 1
        fi
        local free_
        free_="$(ss_pick_free_system_id gid "$want" "$SS_GID_SANDLOT" "$SS_GID_SANDSERV" "$SS_GID_SANDVMM" "$SS_GID_SANDPROV")" \
            || { tc_log_error "no free system gid found for group $name (600-999 exhausted)"; exit 1; }
        tc_log_warn "gid $want occupied by a foreign account — auto-picking $free_ for group $name (fine single-host; for shared-storage fleets export SS_GID_* identically on EVERY node)"
        want="$free_"
        groupadd -r -g "$want" "$name" || { tc_log_error "groupadd $name (gid $want) failed"; exit 1; }
    fi
    export "$var=$want"
}

# ss_resolve_user <name> <primary-group> <varname> — the user twin of
# ss_resolve_group. Exports the resolved uid in varname.
ss_resolve_user() {
    local name="$1" grp="$2" var="$3"
    local want="${!var:-}" cur
    # `|| true`: id exits nonzero for an ABSENT user; under `set -e` the bare
    # substitution would kill the resolver before the create branch.
    cur="$(id -u "$name" 2>/dev/null || true)"
    if [[ -n "$cur" ]]; then
        if [[ "$cur" != "$want" ]]; then
            if [[ "$SS_ID_STRICT" == 1 ]]; then
                tc_log_error "user '$name' exists with uid $cur, want $want (SS_ID_STRICT=1 — pinned fleet). Fix: free the slot or export SS_UID_* consistently."
                exit 1
            fi
            tc_log_warn "user '$name' adopts existing uid $cur (requested $want) — the resolved value wins on this host"
        fi
        export "$var=$cur"
        return 0
    fi
    if [[ -z "$want" ]]; then
        useradd -r -s /usr/sbin/nologin -g "$grp" "$name" || { tc_log_error "useradd $name failed"; exit 1; }
        tc_log_pass "provisioned system user $name (uid=$(id -u "$name"), gid=$(id -g "$name"), system-allocated)"
        export "$var=$(id -u "$name")"
        return 0
    fi
    if ! useradd -r -u "$want" -s /usr/sbin/nologin -g "$grp" "$name" 2>/dev/null; then
        if [[ "$SS_ID_STRICT" == 1 ]]; then
            tc_log_error "useradd $name failed: uid $want is taken (SS_ID_STRICT=1). Free it or export SS_UID_$(_ss_upper "$name") with a free number and re-run."
            exit 1
        fi
        local free_
        free_="$(ss_pick_free_system_id uid "$want" "$SS_UID_SANDLOT" "$SS_UID_SANDSERV" "$SS_UID_SANDVMM" "$SS_UID_SANDPROV")" \
            || { tc_log_error "no free system uid found for user $name (600-999 exhausted)"; exit 1; }
        tc_log_warn "uid $want occupied by a foreign account (cloud images give 1001 to the first human user — GCP-style hosts hit this) — auto-picking $free_ for user $name (fine single-host; for shared-storage fleets export SS_UID_* identically on EVERY node)"
        want="$free_"
        useradd -r -u "$want" -s /usr/sbin/nologin -g "$grp" "$name" || { tc_log_error "useradd $name (uid $want) failed"; exit 1; }
    fi
    tc_log_pass "provisioned system user $name (uid=$(id -u "$name"), gid=$(id -g "$name"))"
    export "$var=$want"
}

_ss_upper() { echo "$1" | tr '[:lower:]' '[:upper:]'; }

# ss_assert_distinct <label> <ids...> — nonzero and pairwise distinct, or the
# identity split is broken: ALWAYS fatal (no strict-mode opt-out; this is the
# security property, not a deployment preference).
ss_assert_distinct() {
    local label="$1"; shift
    local i j
    for i in "$@"; do
        [[ "$i" =~ ^[0-9]+$ && "$i" -ne 0 ]] || { tc_log_error "$label: '$i' is not a nonzero numeric id"; exit 1; }
    done
    local n=$#
    for ((i=1; i<=n; i++)); do
        for ((j=i+1; j<=n; j++)); do
            [[ "${!i}" == "${!j}" ]] && { tc_log_error "$label must be pairwise DISTINCT (identity split is load-bearing): $*"; exit 1; }
        done
    done
}

# ss_ensure_service_users — idempotently create the service identities,
# resolving occupied slots per the configurable-identity contract above.
# Requires root (callers run host prep as root anyway).
ss_ensure_service_users() {
    if [[ $(id -u) -ne 0 ]]; then
        tc_log_error "ss_ensure_service_users requires root"
        exit 1
    fi
    # Rename migration: the external-facing identity was originally named
    # after the product ("sandswap"); it is now "sandserv". The rename is
    # name-level (usermod/groupmod re-owner nothing — ownership is numeric)
    # and only fires for the legacy name; the resolvers below adopt whatever
    # number the renamed account carries.
    if getent group sandswap >/dev/null 2>&1 && ! getent group sandserv >/dev/null 2>&1; then
        groupmod -n sandserv sandswap || { tc_log_error "groupmod rename sandswap → sandserv failed"; exit 1; }
        tc_log_pass "renamed group sandswap → sandserv"
    fi
    if id -u sandswap >/dev/null 2>&1 && ! id -u sandserv >/dev/null 2>&1; then
        usermod -l sandserv sandswap || { tc_log_error "usermod rename sandswap → sandserv failed"; exit 1; }
        tc_log_pass "renamed user sandswap → sandserv"
    fi

    ss_resolve_group sandlot   SS_GID_SANDLOT
    ss_resolve_group sandserv  SS_GID_SANDSERV
    ss_resolve_group sandvmm   SS_GID_SANDVMM
    ss_resolve_group sandprov  SS_GID_SANDPROV
    ss_resolve_group "$SS_GROUP_TPL" SS_GID_TPL
    ss_assert_distinct service-gids "$SS_GID_SANDLOT" "$SS_GID_SANDSERV" "$SS_GID_SANDVMM" "$SS_GID_SANDPROV" "$SS_GID_TPL"
    ss_resolve_user  sandlot   sandlot   SS_UID_SANDLOT
    ss_resolve_user  sandserv  sandserv  SS_UID_SANDSERV
    ss_resolve_user  sandvmm   sandvmm   SS_UID_SANDVMM
    ss_resolve_user  sandprov  sandprov  SS_UID_SANDPROV
    ss_assert_distinct service-uids "$SS_UID_SANDLOT" "$SS_UID_SANDSERV" "$SS_UID_SANDVMM" "$SS_UID_SANDPROV"

    # NFS manage-gids: the VMM's supplementary set is applied via setpriv, but
    # an NFS server running with manage-gids (the default) does NOT trust the
    # wire gid list — it re-derives groups from its OWN NSS. The shared-group
    # grant must therefore also exist as a real membership, or every cold
    # mount over NFS fails EACCES when the VMM's set-fs validation traverses
    # the volume directory. This does not widen the runtime grant (the spawn
    # still REPLACES the child's groups with exactly kvm+shared) and the
    # volume seed stays root:sandprov.
    if getent group "$SS_SHARED_GROUP" >/dev/null 2>&1; then
        usermod -aG "$SS_SHARED_GROUP" sandvmm 2>/dev/null || \
            gpasswd -a sandvmm "$SS_SHARED_GROUP" >/dev/null 2>&1 || true
    fi

    # Feed the Go-side defaults: sandlot's config.go Defaults() reads these,
    # so microvm.vmm_uid / vmm_gid / api_gid / vmm_groups always match the
    # accounts THIS host actually has (exported into the service env through
    # ss_service_exec's exec chain / the systemd EnvironmentFile).
    export SANDSWAP_VMM_UID="$SS_UID_SANDVMM" \
           SANDSWAP_VMM_GID="$SS_GID_SANDVMM" \
           SANDSWAP_API_GID="$SS_GID_SANDLOT" \
           SANDSWAP_VMM_GROUPS="kvm,$SS_GID_SANDLOT" \
           SANDSWAP_PROV_GID="$SS_GID_SANDPROV" \
           SANDSWAP_TPL_GROUP="$SS_GROUP_TPL"
    # Persist the resolution for the systemd units (EnvironmentFile=—/etc/
    # sandswap/identity.env): numbers only, no secrets, 0644 root:root. The
    # "-" prefix in the units keeps the file OPTIONAL — absent means the
    # compiled defaults (a host provisioned before this mechanism, or a
    # deliberately pinned fleet, changes nothing).
    local idenv="${SANDSWAP_ETC:-/etc/sandswap}/identity.env"
    mkdir -p "$(dirname "$idenv")"
    {
        echo "# Generated by ss_ensure_service_users — resolved service identities (do not hand-edit; re-run host prep)."
        echo "SANDSWAP_VMM_UID=$SS_UID_SANDVMM"
        echo "SANDSWAP_VMM_GID=$SS_GID_SANDVMM"
        echo "SANDSWAP_API_GID=$SS_GID_SANDLOT"
        echo "SANDSWAP_VMM_GROUPS=kvm,$SS_GID_SANDLOT"
        echo "SANDSWAP_PROV_GID=$SS_GID_SANDPROV"
        echo "SS_UID_SANDLOT=$SS_UID_SANDLOT"
        echo "SS_UID_SANDSERV=$SS_UID_SANDSERV"
        echo "SS_UID_SANDVMM=$SS_UID_SANDVMM"
        echo "SS_UID_SANDPROV=$SS_UID_SANDPROV"
        echo "SS_GID_SANDLOT=$SS_GID_SANDLOT"
        echo "SS_GID_SANDSERV=$SS_GID_SANDSERV"
        echo "SS_GID_SANDVMM=$SS_GID_SANDVMM"
        echo "SS_GID_SANDPROV=$SS_GID_SANDPROV"
        echo "SS_GID_TPL=$SS_GID_TPL"
        echo "SANDSWAP_TPL_GROUP=$SS_GROUP_TPL"
    } > "$idenv"
    chmod 0644 "$idenv"
    tc_log_pass "identity resolution persisted to $idenv"
    tc_log_pass "service identities resolved: sandlot=$SS_UID_SANDLOT sandserv=$SS_UID_SANDSERV sandvmm=$SS_UID_SANDVMM sandprov=$SS_UID_SANDPROV (strict=$SS_ID_STRICT)"

    usermod -aG "$SS_SHARED_GROUP" sandprov 2>/dev/null || true
    # Template-store metadata group membership: the writer (prov) and the exec
    # role that mounts overlays from refs. sandvmm is deliberately NOT added —
    # its spawn uses an explicit group list (kvm + the shared volume group).
    usermod -aG "$SS_GROUP_TPL" sandprov 2>/dev/null || true
    usermod -aG "$SS_GROUP_TPL" sandlot 2>/dev/null || true

    # Vestigial membership cleanup: older provisioning models made sandlot a
    # member of the gateway identity's group (986) — the corrected model gives
    # that group NO purpose ("nothing on the host is group-sandserv").
    # Remove it idempotently.
    if id -nG sandlot 2>/dev/null | tr ' ' '\n' | grep -qx sandserv; then
        gpasswd -d sandlot sandserv >/dev/null 2>&1 \
            && tc_log_pass "removed vestigial sandlot membership in group sandserv (986 has no purpose)"
    fi

    # The gateway/sandns identity deliberately holds NO supplementary groups:
    # the storage plane lives in the prov instances (sandprov) and the FUSE
    # passthrough (sandvmm) — the external-facing identity accesses no shared
    # storage at all. A legacy host may still carry the old shared-group
    # membership (pre-split grant); remove it idempotently so the boundary is
    # enforced at the identity level too.
    if id -nG "$SS_SERVICE_USER_GW" 2>/dev/null | tr ' ' '\n' | grep -qx "$SS_SHARED_GROUP"; then
        gpasswd -d "$SS_SERVICE_USER_GW" "$SS_SHARED_GROUP" >/dev/null 2>&1 \
            && tc_log_pass "removed legacy shared-group membership from $SS_SERVICE_USER_GW (gateway accesses no storage)"
    fi
    # kvm group: stock Ubuntu ships /dev/kvm as root:kvm 0660 — group
    # membership is the whole device grant (sandlot reads /dev/kvm fds only
    # indirectly through sandvmm, but membership is harmless and keeps
    # diagnostics possible).
    if getent group kvm >/dev/null 2>&1; then
        usermod -aG kvm sandlot 2>/dev/null || true
    else
        tc_log_warn "no kvm group on this host — add sandlot manually if device perms differ"
    fi

    # vsock device OWNERSHIP now that the identities exist. Every launch path
    # runs this function AFTER creating the users, but device prep may have
    # run BEFORE (chown-by-name silently no-ops on a missing account) —
    # repair here so the owner-isolation model always holds:
    #   /dev/vhost-vsock → OWNER=sandvmm 0600 (the only user is the VMM)
    #   /dev/vsock       → OWNER=sandlot 0600 (defense-in-depth lockdown;
    #                       the sandvmm identity shares the storage group and
    #                       must not reach this device)
    if [[ -e /dev/vhost-vsock ]]; then
        chown "$SS_SERVICE_USER_VM" /dev/vhost-vsock 2>/dev/null || true
        chmod 0600 /dev/vhost-vsock 2>/dev/null || true
    fi
    if [[ -e /dev/vsock ]]; then
        chown "$SS_SERVICE_USER_SL" /dev/vsock 2>/dev/null || true
        chmod 0600 /dev/vsock 2>/dev/null || true
    fi
}

# ss_service_exec <identity> -- <cmd> [args...]
#
# exec-style privilege drop via setpriv (util-linux; Ubuntu 22.04+ ships it).
# `exec` replaces the calling (sub)shell image — setpriv then execs the
# target — so the PID recorded by the caller ($! of the backgrounded call)
# IS the service PID, argv[0] stays the binary path (kill-by-path still
# matches), and no wrapper process lingers.
#
#   sandlot           — node-agent capability set: CAP_NET_ADMIN (TAP/bridge
#                       via netlink) + CAP_SYS_ADMIN (overlay syscall.Mount)
#                       + CAP_SETUID/CAP_SETGID (spawn sandvmm children as
#                       the dedicated VMM uid — the kernel clears every
#                       capability set on the uid transition, so the caps
#                       never reach the child) + CAP_KILL (cross-uid SIGKILL
#                       of sandvmm on destroy/re-adopt cleanup; same-uid
#                       kill is denied after the split).
#                       Identical to the systemd unit (AmbientCapabilities=).
#   sandserv|gateway  — plain drop: no capabilities, no devices.
#   |sandns|etcd
#   root              — explicit escape hatch for host-prep-only helpers
#                       that must stay root (bridge setup, sysctls).
ss_service_exec() {
    local identity="$1"; shift
    [[ "${1:-}" == "--" ]] && shift
    if ! command -v setpriv >/dev/null 2>&1; then
        tc_log_error "setpriv not found — install util-linux (ss_service_exec)"
        exit 1
    fi
    case "$identity" in
        sandlot)
            # sandprov is the volume-name seed's group (root:sandprov 0640):
            # a merged exec,prov instance must read the seed to derive volume
            # names, so the trusted per-node daemon carries it. The sandvmm
            # children do NOT inherit it — launcher.go spawns them through
            # setpriv with an EXPLICIT --groups list (kvm + the shared group),
            # so the FUSE passthrough daemon can never read the seed. This
            # mirrors the systemd units (SupplementaryGroups=kvm sandprov).
            # Only a PROV-bearing instance needs the seed's group: an
            # exec-only node must not be able to read the volume seed. Direct-
            # start deployers that know their roles export
            # SANDSWAP_SANDLOT_ROLES; the default keeps the merged shape's
            # historical grant (the systemd units start exec-only by default
            # and add this group through a drop-in for merged shapes).
            local roles="${SANDSWAP_SANDLOT_ROLES:-exec,prov}"
            local sl_groups="$SS_SHARED_GROUP,kvm"
            if [[ "$roles" == *prov* ]] && getent group "${SANDPROV_GROUP:-sandprov}" >/dev/null 2>&1; then
                sl_groups="$sl_groups,${SANDPROV_GROUP:-sandprov}"
            fi
            # Template-store metadata group: both exec (mounts overlays from
            # refs) and prov (writer) carry it; sandvmm never does.
            if getent group "${SS_GROUP_TPL:-sandtmpl}" >/dev/null 2>&1; then
                sl_groups="$sl_groups,${SS_GROUP_TPL:-sandtmpl}"
            fi
            exec setpriv \
                --reuid="$SS_SERVICE_USER_SL" --regid=sandlot \
                --groups="$sl_groups" \
                --inh-caps=+net_admin,+sys_admin,+setuid,+setgid,+kill \
                --ambient-caps=+net_admin,+sys_admin,+setuid,+setgid,+kill \
                -- "$@"
            ;;
        sandvmm)
            # The dedicated VMM identity (uid-pinned 987). Production spawns
            # go through launcher.go, which runs sandvmm with ZERO capabilities
            # (the network provider pre-creates and owns the TAP, so the VMM's
            # attach is an owner-match TUNSETIFF). This direct-launch path
            # exists for tests that boot a VMM themselves; those are the only
            # callers that need CAP_NET_ADMIN (to bring the TAP up), so the
            # grant is TEST-GATED: SANDSWAP_TEST_VMM_NET_ADMIN=1.
            if [[ "${SANDSWAP_TEST_VMM_NET_ADMIN:-0}" == "1" ]]; then
                exec setpriv \
                    --reuid="$SS_SERVICE_USER_VM" --regid="$SS_SERVICE_USER_VM" \
                    --groups="$SS_SHARED_GROUP,kvm" \
                    --inh-caps=+net_admin \
                    --ambient-caps=+net_admin \
                    -- "$@"
            fi
            exec setpriv \
                --reuid="$SS_SERVICE_USER_VM" --regid="$SS_SERVICE_USER_VM" \
                --groups="$SS_SHARED_GROUP,kvm" \
                --inh-caps=-all \
                --ambient-caps=-all \
                -- "$@"
            ;;
        sandserv|gateway|sandns|etcd)
            # No supplementary groups (--clear-groups is mandatory alongside
            # --regid): the gateway/sandns identities access NO shared storage
            # (the storage plane lives in the prov instances); their
            # credential state is owner-only inside their own state dir.
            exec setpriv \
                --reuid="$SS_SERVICE_USER_GW" --regid="$SS_SERVICE_GROUP" \
                --clear-groups \
                -- "$@"
            ;;
        root)
            exec "$@"
            ;;
        *)
            tc_log_error "ss_service_exec: unknown identity '$identity' (sandlot|sandvmm|sandserv|gateway|sandns|etcd|root)"
            exit 1
            ;;
    esac
}

# ss_prepare_dirs — create + chown the runtime directories the two service
# identities share. Called after any mkdir/rm -rf cycle (tc_clean_environment,
# deploy host-prep) so services never inherit a root-owned tree:
#
#   /run/sandswap   root:sandlot 3770 — sandlot state (vm/<id>, instance-*,
#                     the role lock, staged seed generations). STICKY: the
#                     directory is writable by every sandlot-shared-group
#                     identity (sandlot 985, sandprov 983, sandvmm 987), and
#                     without the sticky bit directory write alone would let
#                     any of them unlink or replace the role lock and any
#                     seed generation it does not own — with it, only an
#                     entry's owner (or root) may remove it.
#   VOL_ROOT        <prov>:sandlot 2710 — the SHARE ROOT. setgid so every
#                     volume created inside inherits the shared group; group
#                     X ONLY (no read, no write) so the FUSE daemon — sandvmm,
#                     uid 987, a member of the shared group — can reach the
#                     volume it is serving but can neither list the root (no
#                     name enumeration of other tenants) nor create, remove or
#                     rename anything AT THE ROOT. That is the fourth isolation layer,
#                     enforced by the kernel rather than by the daemon's own
#                     gate: the only writer here is the prov instance
#                     (EnsureVolume / DeleteVolume / the orphan-rename), which
#                     owns the directory. Everything INSIDE a volume stays
#                     group-rw (0770, setgid inherited), so guest read/write is
#                     untouched — reaching a volume needs x on the root, not w.
#                     identity-store.json (VolRoot's parent) is 0600
#                     sandserv:sandserv — no group bits, so the sandlot user (a
#                     member of every sandlot-group path) still CANNOT read it:
#                     the group shares the tree, the mode isolates the
#                     credentials.
#   LOG_DIR         root:sandlot 2775 — gateway.log (sandserv) +
#                     sandlot.log (sandlot) in one directory.
#
# DEPLOY_DIR stays root-owned: binaries are world-readable/executable, no
# service writes there.
ss_prepare_dirs() {
    if [[ $(id -u) -ne 0 ]]; then
        tc_log_error "ss_prepare_dirs requires root"
        exit 1
    fi
    # 3770 = sticky: shared-group identities create their own entries but
    # cannot remove another identity's (role lock, seed generations). The
    # install below also re-asserts the mode on an existing dir — a deploy or
    # drill that inherited a pre-sticky 2770 tree gets fixed here.
    install -d -m 3770 -o root -g "$SS_SHARED_GROUP" /run/sandswap
    # Per-VM persisted state root: OUTSIDE the shared sandbox tree so sandvmm
    # (a shared-group member) cannot rename/replace a state directory. Same
    # sticky contract as /run/sandswap; each instance creates its 0700 subdir.
    install -d -m 3770 -o root -g "$SS_SHARED_GROUP" /run/sandswap-state
    # The one-sandlot-per-host role lock: pre-created ROOT-owned 0660 so every
    # service identity (sandlot 985 exec instances, sandprov 983 prov
    # instances) can open it O_RDWR. Left to the instances it would be created
    # by whichever started first, owned by that identity with umask-stripped
    # group bits — the other identity then cannot even open it.
    [[ -e /run/sandswap/sandlot.role ]] || \
        install -m 0660 -o root -g "$SS_SHARED_GROUP" /dev/null /run/sandswap/sandlot.role
    mkdir -p "$VOL_ROOT" "$LOG_DIR"
    chown root:"$SS_SHARED_GROUP" "$LOG_DIR"
    chmod 2775 "$LOG_DIR"
    # VOL_ROOT — the virtio-fs SHARE ROOT. Owned by the provision identity
    # (its only writer), group = shared, mode 2710: the daemon's group gets
    # x ONLY — enough to traverse into the volume it serves, not enough to
    # LIST the root (readdir needs r, so the daemon cannot enumerate other
    # tenants' names even if compromised) and not enough to create or remove
    # anything at the root. Guest read/write inside a volume is unaffected
    # (that needs x on the root, and the volume itself is 0770).
    # Also re-asserted every run: a previous run, a stale deploy or a
    # single-process-era StateDirectory chown may have left another shape.
    chown "$SS_PROV_USER":"$SS_SHARED_GROUP" "$VOL_ROOT" 2>/dev/null || true
    chmod 2710 "$VOL_ROOT"
}

# ss_ensure_volume_seed <path> [owner] [mode] — mint the volume-name seed at
# <path> when absent and re-assert its scope. The prov role REQUIRES it (the
# on-disk directory name of every volume is derived from it), and a
# REGENERATED seed orphans every existing name — so an existing non-empty file
# is never rewritten, only re-scoped.
#
# This is the ONE implementation. It replaces three that had drifted apart
# (e2e common.sh: owner-only 0600 under $DEPLOY_DIR; baremetal common.sh:
# root:<prov-group> 0640 under /etc/sandswap; the standalone probes: an inline
# `umask 077; openssl rand -hex 32 > …` root-owned block) — the drift is what
# made a sandlot running as its own identity die "volume_seed_file: open …
# permission denied".
#
#   owner — "<user>" or "<user>:<group>"; default $SS_PROV_USER. A bare user
#           takes its PRIMARY group.
#   mode  — default 0600 (owner-only). Deploy shapes that keep the seed under
#           root use 0640 root:<prov-group> so the service identity can read it
#           while the sandvmm identity (a member of the shared group only,
#           never of the prov group) cannot — a leaked seed makes every volume
#           name guessable again.
ss_ensure_volume_seed() {
    local path="$1"
    local owner="${2:-${SS_VOLUME_SEED_OWNER:-$SS_PROV_USER}}"
    local mode="${3:-${SS_VOLUME_SEED_MODE:-0600}}"
    local user="${owner%%:*}" group="${owner##*:}"
    [[ "$group" == "$owner" ]] && group=""
    [[ -z "$group" ]] && group="$(id -gn "$user" 2>/dev/null || echo "$user")"
    install -d -m 0755 "$(dirname "$path")" 2>/dev/null || true
    if [[ ! -s "$path" ]]; then
        if [[ "${SANDSWAP_VOLUME_SEED_NO_MINT:-0}" == "1" ]]; then
            # An INJECTED seed is not this tooling's to mint: a secret manager,
            # a systemd credential or a tmpfs file materializes it. Minting a
            # replacement here would look like a successful deploy while
            # orphaning every existing volume name — fail closed instead.
            tc_log_error "volume-name seed MISSING at $path and SANDSWAP_VOLUME_SEED_NO_MINT=1: this deployment INJECTS its seed — materialize it before the deploy (see install-baremetal.md, seed injection channels). Refusing to mint a replacement (a new seed orphans every existing volume name)."
            return 1
        fi
        # Atomic install: write beside the target and rename, so a reader (or a
        # crash) can never observe a half-written seed.
        # Subshell: umask 077 must not leak into the caller (it would re-mode
        # every artifact installed afterwards — measured: an 0600 initramfs the
        # VMM identity then cannot read).
        local seed_tmp="${path}.new.$$"
        ( umask 077; openssl rand -hex 32 > "$seed_tmp" )
        mv -f "$seed_tmp" "$path"
        tc_log_info "volume-name seed minted: $path (KEEP — every volume name derives from it)"
    fi
    chown "$user:$group" "$path" 2>/dev/null || true
    chmod "$mode" "$path" 2>/dev/null || true
}

# ss_apply_share_plane <state_root> <volumes_root> [template_dir...] — apply the
# prov-side path contract for a deployment shape:
#
#   <state_root>    root:root 0755 — the deployment state ROOT. It carries the
#                   guest kernel/initramfs in the single-node shape, so the
#                   directory itself must not belong to a service identity
#                   (owner-write would allow rename/replace of the TCB). The
#                   gateway identity's writable state is <state_root>/state,
#                   created 0700 owner <gateway-id> (identity store, locks).
#   <volumes_root>  <prov>:<shared> 2710 — the virtio-fs SHARE ROOT: setgid so
#                   volumes inherit the shared group; group x ONLY, so the FUSE
#                   daemon (sandvmm, shared-group member) can traverse into the
#                   volume it serves but cannot list the root or create/remove
#                   at it (the kernel-enforced isolation layer). The only
#                   writer is the prov instance, which owns it.
#   [template_dir]  <prov>:<shared> 2750 — template stores: the prov identity
#                   writes refs/layers, peers read.
#
# The SHAPE (which identity carries prov) is the single variable SS_PROV_USER:
# merged shapes leave the runtime default (sandlot), dedicated-prov shapes
# export SS_PROV_USER=sandprov. Every caller that also installs systemd units
# must persist the same answer with sandswap_write_prov_user_env.
ss_apply_share_plane() {
    local state_root="$1" volumes_root="$2"; shift 2
    local gw_user="${SS_SERVICE_USER_GW:-sandserv}"
    # The STATE ROOT itself is root-owned 0755: it holds the guest kernel +
    # initramfs (TCB) in some shapes, and a service identity that OWNED the
    # directory could rename/replace those top-level entries without writing
    # them (directory write is enough to unlink an entry). The gateway's
    # writable state lives in the private state/ subdirectory instead.
    install -d -m 0755 -o root -g root "$state_root" 2>/dev/null || true
    install -d -m 0700 -o "$gw_user" -g "$gw_user" "$state_root/state" 2>/dev/null || true
    mkdir -p "$volumes_root" 2>/dev/null || true
    chown "$SS_PROV_USER":"$SS_SHARED_GROUP" "$volumes_root" 2>/dev/null || true
    chmod 2710 "$volumes_root" 2>/dev/null || true
    local d
    for d in "$@"; do
        # CREATE, don't skip: the prov manager mkdirs layers/ under the store
        # at startup and dies EACCES when the store itself is missing or
        # root-owned under a state root the prov identity cannot write (the
        # failure that kills every hand-rolled probe stack).
        mkdir -p "$d" 2>/dev/null || true
        [[ -d "$d" ]] || continue
        chown "$SS_PROV_USER":"$SS_SHARED_GROUP" "$d" 2>/dev/null || true
        chmod 2750 "$d" 2>/dev/null || true
    done
}

# ss_prepare_shared_dir <path> — a staging dir (typically under /tmp) that the
# gateway identity WRITES into (template layers/refs) while root-run scripts
# manage its lifecycle. Wipes + recreates setgid group-write so both
# identities share it. Use this INSTEAD of bare `rm -rf x; mkdir -p x`, which
# leaves a root-owned 755 dir the sandswap gateway cannot write.
ss_prepare_shared_dir() {
    local d
    for d in "$@"; do
        # A previous STORAGE_BACKEND=nfs run can leave an export mounted at
        # the target; rm -rf on a mount point fails EBUSY and aborts every
        # caller. Unmount it first (the nfs profile re-mounts when requested).
        if mountpoint -q "$d" 2>/dev/null; then
            umount "$d" 2>/dev/null || true
        fi
        rm -rf "$d"
        tc_log_info "ss_prepare_shared_dir[$d]: group-var='$SS_SHARED_GROUP' (gid=$(getent group "$SS_SHARED_GROUP" | cut -d: -f3))"
        install -d -m 2770 -o root -g "$SS_SHARED_GROUP" "$d"
        tc_log_info "ss_prepare_shared_dir[$d]: created $(stat -c '%U:%G %a' "$d")"
    done
}

# ── Distributed-storage e2e profile (STORAGE_BACKEND=nfs) ─────────────
# Validates the storage contract (docs/operations/storage.md) on a REAL NFS
# stack: a loopback nfs-kernel-server export mounted over VOL_ROOT (and the
# overlay template dir, where overlayfs-isolation requests it). Numeric
# uid/gid + setgid + overlay-lowerdir + umount-barrier semantics all execute
# through the actual client-server path on this host. Multi-node topologies
# are covered by the placement/failover e2e plus the contract's
# no-cross-node-locking invariant — the shared-disk semantics are what this
# profile proves.

SS_NFS_EXPORT_ROOT="${SS_NFS_EXPORT_ROOT:-/srv/sandswap-nfs}"

# ss_storage_nfs_setup — idempotently provision the loopback export. The
# export root dirs carry the shared-group layout (root:sandlot setgid) so
# files created through the mount inherit it SERVER-side, exactly as a
# production NFS server would.
ss_storage_nfs_setup() {
    if [[ $(id -u) -ne 0 ]]; then
        tc_log_error "ss_storage_nfs_setup requires root"
        exit 1
    fi
    # Both halves matter: exportfs (server) for the loopback export, mount.nfs
    # (client helper) for the row that mounts it. A fresh image usually has
    # neither; installing only the server leaves the mount to fail with the
    # opaque "bad option ... mount.<type> helper program" message.
    if ! command -v exportfs >/dev/null 2>&1 || ! command -v mount.nfs >/dev/null 2>&1; then
        tc_log_step "Installing the NFS server + client (loopback e2e export)..."
        if command -v apt-get >/dev/null 2>&1; then
            export DEBIAN_FRONTEND=noninteractive
            apt-get install -y -qq nfs-kernel-server nfs-common
        elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
            "$(command -v dnf || command -v yum)" install -y -q nfs-utils
        elif command -v zypper >/dev/null 2>&1; then
            zypper --non-interactive install -y nfs-kernel-server nfs-client
        elif command -v pacman >/dev/null 2>&1; then
            pacman -S --noconfirm --needed nfs-utils
        else
            tc_log_error "no supported package manager for the NFS server/client"
            exit 1
        fi || { tc_log_error "NFS install failed — STORAGE_BACKEND=nfs needs an NFS server + client (or set STORAGE_BACKEND=local)"; exit 1; }
    fi
    mkdir -p "$SS_NFS_EXPORT_ROOT/volumes" "$SS_NFS_EXPORT_ROOT/templates"
    chown root:"$SS_SHARED_GROUP" "$SS_NFS_EXPORT_ROOT"
    # Same shapes as ss_prepare_dirs: the share root is prov-owned with the
    # shared group at x-only; the template store is prov-owned and READ-ONLY
    # for everyone else (the FUSE daemon must read layers as overlay lowerdirs
    # but has no business writing template content).
    chown "$SS_PROV_USER":"$SS_SHARED_GROUP" "$SS_NFS_EXPORT_ROOT/volumes" "$SS_NFS_EXPORT_ROOT/templates" 2>/dev/null || true
    chmod 2710 "$SS_NFS_EXPORT_ROOT/volumes"
    chmod 2750 "$SS_NFS_EXPORT_ROOT/templates"
    local exports_file=/etc/exports.d/sandswap-e2e.exports
    # The directory may not exist yet on a fresh nfs-kernel-server install.
    mkdir -p /etc/exports.d
    # ALWAYS rewrite: the export set is exactly the ROOT plus volumes/ and
    # templates/. NFSv4 serves a non-exported parent as a READ-ONLY pseudo-fs
    # node, so omitting the ROOT makes the row's first mkdir fail
    # "Read-only file system". Rewriting is idempotent by content.
    # TEST/E2E ONLY: the loopback export uses a non-squashing root so the
    # test deployer can bootstrap the volume root. Production must NOT copy
    # this: use Kerberos or root_squash,all_squash, pre-create the layout on
    # the storage server, and isolate the storage network
    # (docs/operations/storage.md §4).
    cat > "$exports_file" <<EXPORTS_EOF
# Sandswap e2e loopback export (STORAGE_BACKEND=nfs) — see docs/operations/storage.md
$SS_NFS_EXPORT_ROOT         127.0.0.1(rw,sync,no_subtree_check,no_root_squash)
$SS_NFS_EXPORT_ROOT/volumes  127.0.0.1(rw,sync,no_subtree_check,no_root_squash)
$SS_NFS_EXPORT_ROOT/templates 127.0.0.1(rw,sync,no_subtree_check,no_root_squash)
EXPORTS_EOF
    chmod 0644 "$exports_file"
    exportfs -ra || { tc_log_error "exportfs -ra failed (nfsd unavailable? modprobe nfsd)"; exit 1; }
    tc_log_pass "NFS e2e export ready: $SS_NFS_EXPORT_ROOT (TEST-ONLY non-squashing export)"
}

# ss_storage_nfs_mount <subdir> <mountpoint> — idempotent mount of one
# export subdir at the given path. Safe to call every run: an existing mount
# is detected and left alone (a cleanup rm -rf only clears the CONTENTS of a
# mounted path, never the mount itself).
ss_storage_nfs_mount() {
    local rel="$1" mp="$2"
    mkdir -p "$mp"
    if findmnt -t nfs4 "$mp" >/dev/null 2>&1; then
        tc_log_info "NFS already mounted at $mp"
        return 0
    fi
    # nosuid,nodev: the storage contract requires them on every consumer of
    # shared storage — the virtio-fs passthrough stores guest-requested
    # setuid bits and mknod verbatim, and these flags are what keep planted
    # bits/nodes inert on THIS host (verify-host-security.sh checks the same
    # invariant on production hosts).
    mount -t nfs4 -o nosuid,nodev "127.0.0.1:$SS_NFS_EXPORT_ROOT/$rel" "$mp" \
        || { tc_log_error "NFS mount of 127.0.0.1:$SS_NFS_EXPORT_ROOT/$rel at $mp failed"; exit 1; }
    local _opts
    _opts="$(findmnt -T "$mp" -n -o OPTIONS 2>/dev/null || true)"
    if [[ ",$_opts," == *,nosuid,* && ",$_opts," == *,nodev,* ]]; then
        tc_log_pass "NFS mounted: $mp ← $SS_NFS_EXPORT_ROOT/$rel (nosuid,nodev)"
    else
        tc_log_error "NFS mounted at $mp WITHOUT nosuid,nodev (options: $_opts) — storage contract violation"
        exit 1
    fi
}

# ═══════════════════════════════════════════════════════════════════════
# Script prelude — the ONE call a host-mutating script makes
# ═══════════════════════════════════════════════════════════════════════
# The four contract dimensions a script needs before it can start a stack —
# identities, runtime dirs, device nodes, volume seed — were re-derived BY
# HAND in every script, and each one drifted differently (that is the whole
#.. finding family: scripts missing the seed, scripts hand-chown-
# ing to literal names, scripts not re-asserting device owners after a reboot).
#
# ss_script_host_prep runs them in the ONE correct order, idempotently, and
# prints a single machine-readable line so a log shows what was applied.
#
# Steps, each skippable with SS_PREP_SKIP=comma,list:
#   users    — create the pinned service identities        (needs root)
#   dirs     — /run/sandswap + shared runtime dirs         (needs root)
#   devices  — /dev/kvm, tun, vsock owners + vhost_vsock   (needs root)
#   share    — prov-side ownership of state/volumes/tpl   (needs root)
#   seed     — mint + scope the volume-name seed           (needs root)
#   network  — host bridge + NAT (only when SS_PREP_BRIDGE is set)
#   nfs      — loopback NFS export mounted at the volumes root
#              (only when STORAGE_BACKEND=nfs)
#
# Inputs (all optional; the e2e/deploy conventions are the defaults):
#   SS_PREP_SKIP          e.g. "devices,network"
#   SS_PREP_STATE_ROOT    default: $DEPLOY_DIR
#   SS_PREP_VOLUMES       default: $VOL_ROOT
#   SS_PREP_TEMPLATES     space-separated extra template store dirs
#   SS_PREP_SEED_FILE     default: $DEPLOY_DIR/volume-seed
#   SS_PREP_BRIDGE/SUBNET/GATEWAY/UPLINK
ss_script_host_prep() {
    local skip=",${SS_PREP_SKIP:-},"
    local steps=() failed=0
    _prep_skipped() { [[ "$skip" == *",$1,"* ]]; }

    if ! _prep_skipped users; then
        ss_ensure_service_users >/dev/null 2>&1 || { tc_log_error "prep: ss_ensure_service_users failed"; failed=1; }
        steps+=("users")
    fi
    if ! _prep_skipped dirs; then
        ss_prepare_dirs >/dev/null 2>&1 || { tc_log_error "prep: ss_prepare_dirs failed"; failed=1; }
        steps+=("dirs")
    fi
    if ! _prep_skipped devices; then
        ss_ensure_dev_nodes >/dev/null 2>&1 || { tc_log_error "prep: ss_ensure_dev_nodes failed"; failed=1; }
        steps+=("devices")
    fi
    if ! _prep_skipped share && [[ -n "${SS_PREP_STATE_ROOT:-${DEPLOY_DIR:-}}" ]]; then
        # shellcheck disable=SC2086
        ss_apply_share_plane \
            "${SS_PREP_STATE_ROOT:-$DEPLOY_DIR}" \
            "${SS_PREP_VOLUMES:-$VOL_ROOT}" \
            ${SS_PREP_TEMPLATES:-} >/dev/null 2>&1 \
            || { tc_log_error "prep: ss_apply_share_plane failed"; failed=1; }
        steps+=("share")
    fi
    if ! _prep_skipped seed; then
        local seed_file="${SS_PREP_SEED_FILE:-${DEPLOY_DIR:-}/volume-seed}"
        ss_ensure_volume_seed "$seed_file" >/dev/null 2>&1 \
            || { tc_log_error "prep: ss_ensure_volume_seed failed"; failed=1; }
        steps+=("seed=$seed_file")
    fi
    if ! _prep_skipped network && [[ -n "${SS_PREP_BRIDGE:-}" ]]; then
        ss_host_network_setup "${SS_PREP_BRIDGE}" "${SS_PREP_SUBNET:-10.188.0.0/16}" \
            "${SS_PREP_GATEWAY:-10.188.0.1}" "${SS_PREP_UPLINK:-}" >/dev/null 2>&1 \
            || { tc_log_error "prep: ss_host_network_setup failed"; failed=1; }
        steps+=("network")
    fi
    if ! _prep_skipped nfs && [[ "${STORAGE_BACKEND:-local}" == "nfs" ]]; then
        ss_storage_nfs_setup >/dev/null 2>&1 || { tc_log_error "prep: ss_storage_nfs_setup failed"; failed=1; }
        ss_storage_nfs_mount volumes "${SS_PREP_VOLUMES:-$VOL_ROOT}" >/dev/null 2>&1 \
            || { tc_log_error "prep: ss_storage_nfs_mount failed"; failed=1; }
        steps+=("nfs")
    fi
    echo "PREP: $(printf '%s ' "${steps[@]}")"
    return "$failed"
}

# ss_seed_template <src_template> <dst_leaf> — the ONE sanctioned way to
# stage a template for gateway consumption: copy src into dst_leaf (created
# under a shared root) and normalize. The template contract:
#   1. build-time: build-*-rootfs.sh exits chmod -R a+rX (public read-only
#      content, no 0000/0600 distro oddballs)
#   2. stage-time: the template ROOT must be a shared setgid dir (the
#      gateway identity writes refs/ into it) and the seed readable by BOTH
#      service identities — asserted here, so a forgotten ss_prepare_
#      shared_dir fails HERE instead of as a mysterious gateway EACCES.
# Do NOT hand-roll mkdir+cp -a at call sites; that is how the whack-a-mole
# started. The final chmod is cheap insurance for out-of-tree templates.
ss_seed_template() {
    local src="$1" dst_leaf="$2"
    mkdir -p "$(dirname "$dst_leaf")"
    cp -a "$src/." "$dst_leaf/"
    chmod -R a+rX "$dst_leaf" 2>/dev/null || true
    # The template store's CONSUMER is the sandlot identity (the prov role
    # reads refs/layers; the exec role reads overlay lowerdirs) — NOT the
    # gateway, which never touches storage. Probe with the identity that
    # actually reads the tree.
    if ! sudo -u "$SS_SERVICE_USER_SL" test -r "$dst_leaf" 2>/dev/null; then
        # Only meaningful when run as root with the identities provisioned;
        # a root-run dev shell without users skips the assertion.
        if [[ $(id -u) -eq 0 ]] && id "$SS_SERVICE_USER_SL" >/dev/null 2>&1; then
            tc_log_error "ss_seed_template: $dst_leaf not readable by $SS_SERVICE_USER_SL (root not normalized?)"
            exit 1
        fi
    fi
}

# ss_own_tls_keys <cert_dir> — scope each private key to ONLY the identity
# that loads it. Key inventory:
#   sandlot.key   — the sandlot stream CLIENT cert (the only key the sandlot
#                   user needs)
#   everything else (gateway/stream/human/admin/mcp/etcd...) — sandserv
#   *.crt (incl. ca.crt) — world-readable
# Keys are 0640 owner+PRIMARY-group (sandserv:sandserv, sandlot:sandlot) —
# deliberately NOT the shared group: the shared group exists for volumes,
# not for spreading TLS material across identities, so a compromised sandlot
# process cannot read the gateway's stream/human/mcp/etcd private keys.
ss_own_tls_keys() {
    local d="$1"
    [[ -d "$d" ]] || return 0
    # Dir 755: certificates (incl. the CA — a PUBLIC trust anchor) must be
    # readable by ANY local user: agent developers run clients/verifiers
    # from their own accounts. Private keys carry no other bits.
    chown root:root "$d"
    chmod 755 "$d"
    # Private keys go to the identity that loads them — EXCEPT a CA private
    # key. Only ca.crt belongs on a node; a retained ca.key hands the
    # externally-exposed gateway identity the ability to mint a client
    # certificate for any node id (fleet-wide stream impersonation). Keep it
    # root-only and loudly flag it: the reference cert generator deletes it
    # after signing, so seeing one here means a foreign/hand-made cert dir.
    local kf
    for kf in "$d"/*.key; do
        [[ -e "$kf" ]] || continue
        if [[ "$(basename "$kf")" == "ca.key" ]]; then
            # Dev/test harnesses (e2e tc_gen_certs) deliberately KEEP the CA in
            # the cert dir so per-node pairs can be minted on demand; there it
            # is already root:root 0600 and stays silent. Any other shape (a
            # service-owned or group/world-readable CA key) is the production
            # hazard — fix it and say so loudly.
            local was_owner was_mode
            was_owner="$(stat -c '%U' "$kf" 2>/dev/null || echo '?')"
            was_mode="$(stat -c '%a' "$kf" 2>/dev/null || echo '?')"
            chown root:root "$kf" 2>/dev/null || true
            chmod 600 "$kf" 2>/dev/null || true
            if [[ "$was_owner" != "root" || "$was_mode" != "600" ]]; then
                echo "WARN: ${kf} is a CA private key in the service certificate directory (was ${was_owner}:${was_mode}) — scoped root-only; production must keep the CA key on the issuing machine only" >&2
            fi
            continue
        fi
        chown "$SS_SERVICE_USER_GW:$SS_SERVICE_USER_GW" "$kf" 2>/dev/null || true
        chmod 640 "$kf" 2>/dev/null || true
    done
    # The SANDSLOT STREAM KEY is owner-only (0600). At 0640 it was readable by
    # every member of the sandlot GROUP — which includes the sandvmm identity
    # (987): a compromised FUSE daemon could read the node's stream client key
    # and impersonate this node to the gateway. Nothing but the sandlot process
    # (the owner) ever needs it.
    if [[ -f "$d/sandlot.key" ]]; then
        chown "$SS_SERVICE_USER_SL:$SS_SERVICE_USER_SL" "$d/sandlot.key"
        chmod 600 "$d/sandlot.key"
    fi
    # PER-NODE stream client keys (`sandlot-<node-id>.key`, one per node id the
    # gateway binds — see e2e/common.sh tc_node_cert): same rule as the default
    # pair, owner-only for the sandlot identity. The *.key glob above just
    # chowned them to the gateway identity; this is what un-does that.
    local k
    for k in "$d"/sandlot-*.key; do
        [[ -f "$k" ]] || continue
        chown "$SS_SERVICE_USER_SL:$SS_SERVICE_USER_SL" "$k" 2>/dev/null || true
        chmod 600 "$k"
    done
    # prov.key — the PROV instance's own copy of the stream client key (it
    # runs as sandprov, which is neither the gateway nor the sandlot identity).
    # Scoped here so every re-run of key scoping never reverts it to sandserv
    # via the *.key glob above.
    if [[ -f "$d/prov.key" ]]; then
        chown sandprov:sandprov "$d/prov.key" 2>/dev/null || true
        chmod 600 "$d/prov.key" 2>/dev/null || true
    fi
    chmod 644 "$d"/*.crt 2>/dev/null || true
}

# ═══════════════════════════════════════════════════════════════════════
# Host networking (bridge + NAT) — ONE implementation
# ═══════════════════════════════════════════════════════════════════════
# microVMs reach the outside world through a host bridge + one nftables
# masquerade rule (no dnsmasq, no per-VM daemon: sandlot assigns static guest
# IPs and owns the TAP lifecycle). Two copies of this existed — the e2e
# tc_setup_host_network and the standalone deploy/setup-network.sh — and the
# deploy one carried two things the e2e one lacked (EXTRA_ADDRS for hosts
# running several instances with distinct subnets, and reboot persistence).

# ss_install_forward_chain <uplink> <subnet...> — (re)write the guest FORWARD
# policy in the shared `inet sandswap` table as ONE nft transaction:
#
#   metadata DROP  -> uplink-scoped ACCEPT -> established ACCEPT -> terminal drop
#
# The order is load-bearing: nftables (like iptables) is first-match, so an
# ACCEPT placed ahead of the metadata DROP makes the DROP dead. The previous
# implementation inserted both into the legacy iptables FORWARD chain with
# `-I ... 1`, which pushed the metadata DROP to position 2 forever.
#
# Convergence is a `flush chain` + the rules in the SAME `nft -f` batch: the
# transaction commits atomically, so there is never a moment where the old
# rule is gone and the new one is not yet installed (the fail-open window the
# previous delete-then-add sequence had). The order is read back afterwards —
# a rule set that does not match the intended order is a failure.
ss_install_forward_chain() {
    # A HOST may carry several guest subnets on the one sandbox bridge
    # (EXTRA_ADDRS / colocated instances): every subnet gets its own accept +
    # terminal drop, all in the one transaction, or the extra subnets would
    # lose the metadata guard the chain exists for.
    local uplink="$1"; shift
    if [[ ! "$uplink" =~ ^[A-Za-z0-9_.-]{1,15}$ ]]; then
        tc_log_error "uplink \"$uplink\" is not a plain interface name — refusing to interpolate it into an nft batch"
        return 1
    fi
    local subnet
    if [[ $# -eq 0 ]]; then
        tc_log_error "ss_install_forward_chain: no guest subnet given"
        return 1
    fi
    local rules
    rules='add rule inet sandswap forward ip daddr { 169.254.0.0/16, 100.100.100.200, 169.254.170.2 } counter drop comment "sandswap-v4-metadata-deny"'
    for subnet in "$@"; do
        if [[ ! "$subnet" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,2}$ ]]; then
            tc_log_error "guest subnet \"$subnet\" is not an IPv4 CIDR — refusing to interpolate it into an nft batch"
            return 1
        fi
        rules+=$'\n'"add rule inet sandswap forward ip saddr $subnet oifname \"$uplink\" counter accept comment \"sandswap-guest-uplink-accept\""
        rules+=$'\n'"add rule inet sandswap forward ip daddr $subnet ct state established,related counter accept comment \"sandswap-guest-established-accept\""
        rules+=$'\n'"add rule inet sandswap forward ip saddr $subnet counter drop comment \"sandswap-guest-egress-deny\""
    done
    nft add table inet sandswap 2>/dev/null || true
    if nft list chain inet sandswap forward >/dev/null 2>&1; then
        { echo "flush chain inet sandswap forward"; printf '%s\n' "$rules"; } | nft -f - || return 1
    else
        { echo "add chain inet sandswap forward { type filter hook forward priority filter; policy accept; }"; printf '%s\n' "$rules"; } | nft -f - || return 1
    fi
    # Prove the EFFECTIVE result from the kernel's ruleset, never from the
    # batch we just wrote: ONE metadata drop, and exactly one accept /
    # established / terminal triple per guest subnet — with the metadata drop
    # BEFORE every accept (the historical bug was an ACCEPT at position 1 that
    # pushed the metadata DROP to position 2, making it dead).
    local listing n_meta n_up n_est n_term first_meta first_accept want
    listing="$(nft -a list chain inet sandswap forward 2>/dev/null)" || return 1
    want=$#
    n_meta="$(printf '%s\n' "$listing" | grep -c 'comment "sandswap-v4-metadata-deny"')"
    n_up="$(printf '%s\n' "$listing" | grep -c 'comment "sandswap-guest-uplink-accept"')"
    n_est="$(printf '%s\n' "$listing" | grep -c 'comment "sandswap-guest-established-accept"')"
    n_term="$(printf '%s\n' "$listing" | grep -c 'comment "sandswap-guest-egress-deny"')"
    first_meta="$(printf '%s\n' "$listing" | grep -n 'comment "sandswap-v4-metadata-deny"' | head -1 | cut -d: -f1)"
    first_accept="$(printf '%s\n' "$listing" | grep -nE 'comment "sandswap-guest-(uplink|established)-accept"' | head -1 | cut -d: -f1)"
    if [[ "$n_meta" != "1" || "$n_up" != "$want" || "$n_est" != "$want" || "$n_term" != "$want" ]]; then
        tc_log_error "forward chain readback is not convergent (metadata=$n_meta uplink=$n_up established=$n_est terminal=$n_term, want 1/$want/$want/$want)"
        return 1
    fi
    if [[ -z "$first_meta" || -z "$first_accept" ]] || (( first_meta >= first_accept )); then
        tc_log_error "forward chain ORDER is wrong (first metadata rule at line ${first_meta:-?}, first accept at ${first_accept:-?}) — an ACCEPT ahead of the metadata DROP makes the DROP dead"
        return 1
    fi
    return 0
}

# ss_fwd_tagged_flush — remove every iptables FORWARD rule this framework
# tagged `sandswap-guest-fwd` (the scoped mirrors ss_fwd_policy_guard inserts
# beside a live container runtime). Removal is by the kernel's own -S listing,
# never by a remembered spec: a subnet change between runs would otherwise
# leave the old pair behind.
ss_fwd_tagged_flush() {
    command -v iptables >/dev/null 2>&1 || return 0
    local spec
    while IFS= read -r spec; do
        [[ -n "$spec" ]] || continue
        # shellcheck disable=SC2086  # -S lines are shell-tokenizable; the tag has no spaces
        iptables $spec 2>/dev/null || true
    done < <(iptables -S FORWARD 2>/dev/null | grep -- 'sandswap-guest-fwd' | sed 's/^-A/-D/')
    return 0
}

# ss_fwd_policy_guard <uplink> <subnet...> — the OTHER half of the v4 guest
# forward path. The policy lives in the `inet sandswap` nft chain, but an nft
# ACCEPT is not a terminal verdict: every base chain hooked at the same
# hook+priority also sees the packet, so a container runtime's iptables
# FORWARD policy DROP (kube-router on k3s, docker) black-holes the guest
# egress the nft chain just accepted. Cases, fail-closed:
#   policy ACCEPT  — bare-metal baseline, nothing to do.
#   policy DROP, runtime STOPPED, its chains still listed (KUBE-/DOCKER-/…)
#                   — dead residue: restore the pre-runtime baseline ACCEPT.
#   policy DROP, runtime LIVE — never touch a colocated tenant's posture;
#                   mirror the exact nft scoping into iptables as tagged rules
#                   (metadata DROP first, per-subnet uplink accept, per-subnet
#                   established return), inserted at the top of FORWARD so no
#                   foreign chain preempts them.
#   policy DROP, runtime stopped, NO runtime chains — looks like an operator
#                   firewall decision: REFUSE with the manual step (silently
#                   weakening a deliberate policy is not cleanup).
ss_fwd_policy_guard() {
    local uplink="$1"; shift
    command -v iptables >/dev/null 2>&1 || return 0
    local head policy
    head="$(iptables -S FORWARD 2>/dev/null | head -1)" || return 0
    [[ "$head" == "-P FORWARD "* ]] || return 0
    policy="${head#-P FORWARD }"
    [[ "$policy" == "DROP" ]] || return 0

    local svc runtime_live=0
    if command -v systemctl >/dev/null 2>&1; then
        for svc in docker containerd k3s kubelet; do
            if systemctl is-active --quiet "$svc" 2>/dev/null; then runtime_live=1; break; fi
        done
    fi
    local listing markers
    listing="$(iptables -S FORWARD 2>/dev/null)"
    markers="$(printf '%s\n' "$listing" | grep -cE -- '-j (KUBE-[A-Z-]+|DOCKER[A-Z-]*|CNI-[A-Z-]+|flannel[A-Za-z-]*|weave[A-Za-z-]*|cali[A-Za-z-]+)')"

    if (( runtime_live == 0 )); then
        if (( markers > 0 )); then
            if iptables -P FORWARD ACCEPT 2>/dev/null; then
                ss_fwd_tagged_flush
                tc_log_warn "iptables FORWARD policy DROP was left by a STOPPED container runtime ($markers marker chain(s) still listed) — restored the bare-metal baseline ACCEPT; guest egress stays scoped by inet sandswap, and the runtime re-asserts DROP when it next starts"
                return 0
            fi
            tc_log_error "cannot restore iptables FORWARD policy ACCEPT over dead container-runtime residue — guest egress stays black-holed"
            return 1
        fi
        tc_log_error "iptables FORWARD policy is DROP with no running container runtime and no runtime chains — this looks like an operator firewall decision sandswap must not silently weaken; set the bare-metal baseline yourself (iptables -P FORWARD ACCEPT) or scope sandswap's subnets into that policy, then retry"
        return 1
    fi

    local md subnet pos=1
    ss_fwd_tagged_flush
    for md in 169.254.0.0/16 100.100.100.200 169.254.170.2; do
        iptables -I FORWARD "$pos" -d "$md" -m comment --comment sandswap-guest-fwd -j DROP 2>/dev/null \
            || { tc_log_error "cannot insert the tagged metadata DROP into iptables FORWARD"; return 1; }
        pos=$((pos+1))
    done
    for subnet in "$@"; do
        iptables -I FORWARD "$pos" -s "$subnet" -o "$uplink" -m comment --comment sandswap-guest-fwd -j ACCEPT 2>/dev/null \
            || { tc_log_error "cannot insert the tagged uplink accept for $subnet into iptables FORWARD"; return 1; }
        pos=$((pos+1))
    done
    for subnet in "$@"; do
        iptables -I FORWARD "$pos" -d "$subnet" -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment sandswap-guest-fwd -j ACCEPT 2>/dev/null \
            || { tc_log_error "cannot insert the tagged established return for $subnet into iptables FORWARD"; return 1; }
        pos=$((pos+1))
    done
    tc_log_warn "colocated container runtime holds iptables FORWARD policy DROP — inserted tagged sandswap-guest-fwd mirrors at the top of FORWARD (metadata drop, uplink-scoped accepts, established returns); the runtime's policy itself is untouched"
    return 0
}

# ss_host_network_setup <bridge> <subnet> <gateway> [uplink]
#   EXTRA_ADDRS          — extra gateway CIDRs to add to the bridge (see above)
#   SS_NET_PERSIST=1     — persist net.ipv4.ip_forward=1 (and, for routed-ipv6,
#                          net.ipv6.conf.all/default.forwarding=1) in
#                          /etc/sysctl.d
#   SS_HOST_IPV6_PREFIX  — routed-ipv6 site prefix; when set the host ALSO gets
#                          the v6 half of the setup below. Unset: derived from
#                          SANDSWAP_V6_PREFIX / V6_PREFIX when the backend in
#                          SANDSWAP_NETWORK_BACKEND / NETWORK_BACKEND is
#                          routed-ipv6. Empty = bridge/NAT host, untouched.
# Errors out (exit 1) when the uplink cannot be determined: a bridge with no
# NAT is a silent egress blackhole inside every guest.

# ss_try_install_nftables — best-effort install of the nftables userspace via
# the system package manager, so a fresh cloud image can run the e2e /
# benchmark suite straight from a release package without a manual setup step.
# The network baseline itself stays FAIL-CLOSED: this never substitutes for
# nft — if the install fails, the caller still refuses to bring the network up.
ss_try_install_nftables() {
    command -v nft >/dev/null 2>&1 && return 0
    local mgr
    if command -v apt-get >/dev/null 2>&1; then
        mgr="apt-get install -y nftables"
    elif command -v dnf >/dev/null 2>&1; then
        mgr="dnf install -y nftables"
    elif command -v yum >/dev/null 2>&1; then
        mgr="yum install -y nftables"
    elif command -v zypper >/dev/null 2>&1; then
        mgr="zypper --non-interactive install nftables"
    elif command -v pacman >/dev/null 2>&1; then
        mgr="pacman -Sy --noconfirm nftables"
    else
        tc_log_warn "nft missing and no known package manager — cannot auto-install"
        return 1
    fi
    tc_log_step "nft not found — auto-installing via ${mgr%% *}"
    if ! $mgr >/dev/null 2>&1; then
        tc_log_warn "nftables auto-install failed — install it manually, then re-run"
        return 1
    fi
    if ! command -v nft >/dev/null 2>&1; then
        tc_log_warn "nftables package installed but nft still not on PATH"
        return 1
    fi
    tc_log_pass "nftables auto-installed"
}

ss_host_network_setup() {
    local bridge="$1" subnet="$2" gateway="$3"
    local uplink="${4:-$(ip -o route show default 2>/dev/null | awk '{print $5; exit}')}"
    local prefix="${subnet##*/}"
    if [[ -z "$uplink" ]]; then
        tc_log_error "cannot determine default-route uplink for NAT; pass it explicitly"
        exit 1
    fi
    tc_log_step "Setting up host networking (bridge $bridge, subnet $subnet, NAT via $uplink)..."
    ip link add name "$bridge" type bridge 2>/dev/null || true
    ip addr add "$gateway/$prefix" dev "$bridge" 2>/dev/null || true
    local addr
    for addr in ${EXTRA_ADDRS:-}; do
        ip addr add "$addr" dev "$bridge" 2>/dev/null || true
    done
    ip link set "$bridge" up
    sysctl -w net.ipv4.ip_forward=1 >/dev/null
    if [[ "${SS_NET_PERSIST:-0}" == "1" ]]; then
        # APPEND when missing — a truncating write would silently drop other
        # keys an operator (or the k8s sysctl block) put in this file.
        mkdir -p /etc/sysctl.d
        if ! grep -qs "^net.ipv4.ip_forward" /etc/sysctl.d/99-sandswap.conf 2>/dev/null; then
            echo "net.ipv4.ip_forward=1" >> /etc/sysctl.d/99-sandswap.conf
        fi
    fi
    # nftables masquerade: one rule, not per-VM. The chain is recreated each
    # run so the rule set stays exact.
    #
    # nft is a hard prerequisite: the guest FORWARD policy below is the only
    # thing that keeps a guest's egress off the node's other networks and off
    # the cloud metadata endpoints, and a host without it would run with the
    # platform FORWARD policy (ACCEPT on a plain bare-metal host). Refuse to
    # pretend the network is ready.
    if ! command -v nft >/dev/null 2>&1; then
        ss_try_install_nftables || true
    fi
    if ! command -v nft >/dev/null 2>&1; then
        tc_log_error "nft not found — outbound NAT AND the guest forward isolation policy cannot be installed. Install: apt install nftables"
        exit 1
    fi
    nft add table inet sandswap 2>/dev/null || true
    nft 'delete chain inet sandswap postrouting' 2>/dev/null || true
    nft 'add chain inet sandswap postrouting { type nat hook postrouting priority srcnat; }'
    nft add rule inet sandswap postrouting ip saddr "$subnet" oifname "$uplink" masquerade
    # Guest -> host control-plane isolation: a tenant must not be able to
    # reach ANY host listener over the sandbox bridge (the black-box pass
    # read the anonymous human API at 10.188.0.1:3100 from inside a
    # guest). The public listeners are for EXTERNAL clients; the guest itself
    # only needs DNS and egress. DEFAULT-DENY allowlist scoped to the
    # bridge interface and FAMILY-NEUTRAL: an `inet` chain matches IPv4
    # and IPv6 alike, so the rules must not carry an `ip saddr` qualifier
    # (the previous IPv4-only chain let a guest reach every host IPv6
    # listener over its link-local address). Only the DNS resolver (plus
    # replies to flows the host initiated) is admitted; everything else
    # arriving on the bridge destined to this host is dropped.
    # SS_HOST_ALLOW_PORTS (space-separated TCP/UDP ports, default: DNS
    # only) extends the allowlist for operators who need more. Recreated
    # each run so the rule set stays exact; host-local traffic (loopback)
    # and the uplink are unaffected (the iifname scopes the chain to the
    # sandbox bridge).
    nft 'delete chain inet sandswap input' 2>/dev/null || true
    nft 'add chain inet sandswap input { type filter hook input priority 0; policy accept; }'
    nft add rule inet sandswap input iifname "$bridge" ct state invalid drop
    nft add rule inet sandswap input iifname "$bridge" ct state established,related accept
    local _allow_port
    for _allow_port in ${SS_HOST_ALLOW_PORTS:-53}; do
        nft add rule inet sandswap input iifname "$bridge" udp dport "$_allow_port" accept
        nft add rule inet sandswap input iifname "$bridge" tcp dport "$_allow_port" accept
    done
    unset _allow_port
    nft add rule inet sandswap input iifname "$bridge" counter drop
    tc_log_pass "nftables masquerade installed ($subnet -> $uplink); guest->host default-deny allowlist, IPv4+IPv6 (DNS only by default)"

    # Guest FORWARD policy (the egress half). Hosts running container runtimes
    # (k8s/docker) set the FORWARD policy to DROP; a plain bare-metal host is
    # ACCEPT, which would forward a guest packet to EVERY network the node
    # routes (storage, cluster, management) and to the cloud metadata
    # endpoints through the host's own identity. One dedicated chain, ONE nft
    # transaction:
    #   metadata DROP (must be FIRST: an ACCEPT ahead of it makes it dead)
    #   -> guest egress scoped to the UPLINK
    #   -> established return path
    #   -> terminal drop for everything else sourced from the guest subnet.
    # The chain is flushed+rewritten in a single `nft -f` batch, so there is
    # no window in which the old rule is gone and the new one is not yet in
    # place.
    # Every IPv4 NETWORK configured on the bridge (EXTRA_ADDRS / colocated
    # instances may add more than the primary): the kernel route table prints
    # the network form, while `ip addr` prints the host address with its mask.
    local _fwd_subnets=("$subnet") _bridge_net
    while IFS= read -r _bridge_net; do
        [[ -n "$_bridge_net" ]] || continue
        [[ "$_bridge_net" == "$subnet" ]] && continue
        [[ " ${_fwd_subnets[*]} " == *" $_bridge_net "* ]] && continue
        _fwd_subnets+=("$_bridge_net")
    done < <(ip -4 route show dev "$bridge" proto kernel scope link 2>/dev/null | awk '{print $1}')
    if ! ss_install_forward_chain "$uplink" "${_fwd_subnets[@]}"; then
        tc_log_error "could not install the guest FORWARD policy (inet sandswap forward) — refusing to leave guest egress unpoliced"
        exit 1
    fi
    ss_fwd_policy_guard "$uplink" "${_fwd_subnets[@]}" \
        || { tc_log_error "the iptables FORWARD path is unusable for guest egress — see the guard message above"; exit 1; }
    unset _fwd_subnets _bridge_net
    tc_log_pass "guest FORWARD policy installed for $subnet (metadata dropped, uplink-scoped accept, terminal drop)"
    # ── Routed-IPv6 host half (backend=routed-ipv6 only) ──────────────────
    # TAPs are standalone L3 interfaces, and the sandlot forwards between the
    # per-TAP /64s and the uplink in the HOST IP stack. A routed host therefore
    # needs, in this order:
    #   1. a metadata-endpoint DROP for the routed site prefix (the host's
    #      egress identity must not reach the cloud IMDS over v6 — fire before
    #      forwarding can carry a packet);
    #   2. a guest-egress ACCEPT scoped to the UPLINK (a blanket accept would
    #      also admit guest traffic into every other host network the FORWARD
    #      chain sees: storage, cluster, management) plus the established
    #      return path;
    #   3. IPv6 forwarding enabled on `all` (existing interfaces) AND
    #      `default` (the TAPs created after startup), read back to prove the
    #      write took.
    # The sandlot re-asserts an equivalent metadata drop in its own table at
    # every start (and before it enables forwarding); this block is the
    # host-prep copy, plus the uplink-scoped accepts only host prep can scope.
    # Failure is fatal: forwarding without the guard exposes IMDSv6, and
    # forwarding that silently never turns on is a black-holed egress path
    # inside every guest. Bridge/NAT hosts take none of these steps.
    local v6_prefix="${SS_HOST_IPV6_PREFIX:-}"
    if [[ -z "$v6_prefix" ]]; then
        case "${SANDSWAP_NETWORK_BACKEND:-${NETWORK_BACKEND:-}}" in
            routed-ipv6) v6_prefix="${SANDSWAP_V6_PREFIX:-${V6_PREFIX:-fd00:5341:4e44::/48}}" ;;
        esac
    fi
    if [[ -n "$v6_prefix" ]]; then
        local v6_metadata="fd00:ec2::254/128"
        if [[ ! "$v6_prefix" =~ ^[0-9a-fA-F:]+/[0-9]{1,3}$ ]]; then
            tc_log_error "routed-ipv6 site prefix \"$v6_prefix\" is not a CIDR"
            exit 1
        fi
        if ! command -v ip6tables >/dev/null 2>&1; then
            tc_log_error "routed-ipv6 host setup needs ip6tables (apt install iptables) — refusing to enable forwarding without the metadata and uplink guards"
            exit 1
        fi
        if ! ip6tables -C FORWARD -s "$v6_prefix" -d "$v6_metadata" -j DROP 2>/dev/null; then
            ip6tables -I FORWARD 1 -s "$v6_prefix" -d "$v6_metadata" -j DROP \
                || { tc_log_error "cannot install the v6 metadata DROP for $v6_prefix"; exit 1; }
        fi
        if ! ip6tables -C FORWARD -s "$v6_prefix" -o "$uplink" -j ACCEPT 2>/dev/null; then
            ip6tables -I FORWARD 2 -s "$v6_prefix" -o "$uplink" -j ACCEPT \
                || { tc_log_error "cannot install the v6 uplink-scoped FORWARD accept"; exit 1; }
        fi
        if ! ip6tables -C FORWARD -d "$v6_prefix" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null; then
            ip6tables -I FORWARD 3 -d "$v6_prefix" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT \
                || { tc_log_error "cannot install the v6 FORWARD return-path accept"; exit 1; }
        fi
        if ! sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1 \
            || ! sysctl -w net.ipv6.conf.default.forwarding=1 >/dev/null 2>&1; then
            tc_log_error "cannot enable IPv6 forwarding (net.ipv6.conf.all/default.forwarding) — routed-ipv6 egress is dead without it"
            exit 1
        fi
        local _v6_key
        for _v6_key in net.ipv6.conf.all.forwarding net.ipv6.conf.default.forwarding; do
            if [[ "$(sysctl -n "$_v6_key" 2>/dev/null)" != "1" ]]; then
                tc_log_error "$_v6_key is not 1 after the write — routed-ipv6 needs verified IPv6 forwarding"
                exit 1
            fi
        done
        unset _v6_key
        if [[ "${SS_NET_PERSIST:-0}" == "1" ]]; then
            mkdir -p /etc/sysctl.d
            local _v6_sysctl="/etc/sysctl.d/99-sandswap.conf"
            if ! grep -qs "^net.ipv6.conf.all.forwarding" "$_v6_sysctl" 2>/dev/null; then
                echo "net.ipv6.conf.all.forwarding=1" >> "$_v6_sysctl"
            fi
            if ! grep -qs "^net.ipv6.conf.default.forwarding" "$_v6_sysctl" 2>/dev/null; then
                echo "net.ipv6.conf.default.forwarding=1" >> "$_v6_sysctl"
            fi
            unset _v6_sysctl
        fi
        tc_log_pass "routed-ipv6 host networking ready (prefix $v6_prefix via $uplink; v6 forwarding on; $v6_metadata dropped)"
    fi
    tc_log_pass "Host bridge $bridge ready ($gateway/$prefix)"
}

# ss_stack_residue_clean — delete host state a SIGKILLed previous run (or a
# KEEP_ENV debug run) leaves on a shared box: stale TAP devices and sandlot's
# egress nft tables (the per-TAP anti-spoof baseline installed at sandlot
# startup on every backend, plus the routed-ipv6 stamping table). No other
# teardown removes the baseline tables, so without this the next run's
# "first tap-" selection and baseline-presence assertions can read the
# PREVIOUS run's state as their own result. Idempotent, safe under set -e.
ss_stack_residue_clean() {
    local t
    for t in $(ip -br link show 2>/dev/null | grep '^tap-' | awk '{print $1}'); do
        ip link del "$t" 2>/dev/null || true
    done
    if command -v nft >/dev/null 2>&1; then
        nft delete table netdev sandswap_baseline 2>/dev/null || true
        nft delete table bridge sandswap_baseline 2>/dev/null || true
        nft delete table inet sandswap_routed6 2>/dev/null || true
    fi
    return 0
}

# ss_host_network_teardown — remove this run's TAPs + the NAT table + the
# sandlot egress tables. The bridge itself is left in place (harmless to
# reuse, and a multi-instance host may have other subnets on it).
ss_host_network_teardown() {
    ss_stack_residue_clean
    ss_fwd_tagged_flush
    if command -v nft >/dev/null 2>&1; then
        nft delete table inet sandswap 2>/dev/null || true
    fi
    return 0
}

# ss_container_runtime_clean — bring the host to the state the e2e battery and
# the bare-metal deployers assume: NO container runtime holding netfilter
# posture, ports or memory. k3s/kube-router and docker set the iptables
# FORWARD policy DROP, embed their own containerd, run pods, and generally
# outlive whatever stopped them — a live runtime during a KVM e2e run is an
# environment-contamination factor the prelude must remove, not coexist with
# (the ss_fwd_policy_guard mirrors exist for hosts that cannot stop the
# runtime; this function is the default path). Opt out with
# SANDSWAP_KEEP_CONTAINER_RUNTIME=1 (the docker-driven oidc e2e and the k8s
# deployers, whose runtime k3s IS).
#   order: k3s first (it embeds its own containerd), then kubelet, then
#   docker.service, docker.socket, containerd — stopping docker's socket
#   before the service lets socket activation resurrect it mid-run.
#   fail-closed: a unit still active after its stop is a named error — the
#   round does not proceed on a host it could not clean.
ss_container_runtime_clean() {
    [[ "${SANDSWAP_KEEP_CONTAINER_RUNTIME:-0}" == "1" ]] && return 0
    command -v systemctl >/dev/null 2>&1 || return 0
    local unit any_stopped=0
    for unit in k3s kubelet docker.service docker.socket containerd; do
        if systemctl is-active --quiet "$unit" 2>/dev/null; then
            tc_log_warn "container runtime active: stopping $unit (e2e/deploy prelude — SANDSWAP_KEEP_CONTAINER_RUNTIME=1 keeps it)"
            timeout 45 systemctl stop "$unit" 2>/dev/null || true
            any_stopped=1
        fi
        if systemctl is-active --quiet "$unit" 2>/dev/null; then
            tc_log_error "cannot stop $unit — the host is not clean for this run (kill it or export SANDSWAP_KEEP_CONTAINER_RUNTIME=1 to accept a colocated runtime)"
            return 1
        fi
    done
    # Converge the FORWARD baseline over whatever the stopped runtime left.
    # policy ACCEPT: nothing to do. DROP with runtime chains: dead residue,
    # restore the bare-metal baseline. DROP with none: an operator firewall
    # decision — leave it; ss_fwd_policy_guard at network bring-up refuses it
    # by name instead of silently weakening it.
    if command -v iptables >/dev/null 2>&1; then
        local head policy listing
        head="$(iptables -S FORWARD 2>/dev/null | head -1)" || head=""
        policy="${head#-P FORWARD }"
        if [[ "$head" == "-P FORWARD DROP" ]]; then
            listing="$(iptables -S FORWARD 2>/dev/null)"
            if printf '%s\n' "$listing" | grep -qE -- '-j (KUBE-[A-Z-]+|DOCKER[A-Z-]*|CNI-[A-Z-]+|flannel[A-Za-z-]*|weave[A-Za-z-]*|cali[A-Za-z-]+)'; then
                if iptables -P FORWARD ACCEPT 2>/dev/null; then
                    ss_fwd_tagged_flush
                    tc_log_warn "restored iptables FORWARD policy ACCEPT over stopped-runtime residue (kube-router/docker set DROP; inet sandswap polices guest egress)"
                fi
            fi
        fi
    fi
    (( any_stopped )) && tc_log_pass "container runtime stopped — host at the bare e2e baseline"
    return 0
}

# ss_protect_config <path> <group> — scope a generated sandlot config to
# root:<group> 0640. The prov config may carry an OCI registry credential
# (provision.registry_password/token); the deploy generator's default
# umask (022) would leave it world-readable. The service identity reading it
# is the only non-root reader. Call AFTER every sed -i on the file (sed
# recreates it with umask-default perms).
ss_protect_config() {
    local path="$1" group="$2"
    [[ -f "$path" ]] || return 0
    chown "root:${group}" "$path" 2>/dev/null || true
    chmod 0640 "$path" 2>/dev/null || true
}

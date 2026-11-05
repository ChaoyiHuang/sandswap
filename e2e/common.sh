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
# common.sh — Shared library for Sandswap e2e test scripts.
# Source at the top of each e2e test script:
#   ROOT="$(cd "$(dirname "$0")/.." && pwd)"
#   source "$ROOT/e2e/common.sh"
# The shared runtime (logging, path defaults, process/artifact/vsockguard
# helpers, dedicated-service-identity helpers) lives in common/sh/runtime.sh
# — the single implementation shared with the deploy scripts; this file only
# adds e2e-specific config defaults and test helpers on top of it.
# The library reads config variables from the calling script's scope
# (set them BEFORE sourcing). All have sensible defaults:
#   GATEWAY_ADDR    — gateway HTTP listen addr             (default: :3001)
#   STREAM_ADDR     — gateway gRPC stream addr             (default: :9998)
#   GATEWAY_URL     — gateway HTTP base URL (agent API)    (default: http://localhost:3001)
#   HUMAN_ADDR      — human API listen addr                (default: :3100)
#   HUMAN_URL       — human API base URL (/stats, /human/*)(default: http://localhost:3100)
#   LEASE_MS        — sticky lease window                  (default: 100)
#   MAX_LEASE_SEC   — max background exec lease            (default: 30)
#   POOL_SIZE       — microVM pool size                    (default: 3)
#   VM_MEMORY_MB    — per-VM memory                        (default: 256)
#   SANDLOT_POOL    — sandlot pool spec                    (default: small:${POOL_SIZE})
#   NETWORK_BACKEND — bridge|none                          (default: bridge)
#   NETWORK_BRIDGE  — host bridge name                     (default: br-sandswap)
#   NETWORK_SUBNET  — VM subnet                            (default: 10.188.0.0/16)
#   NETWORK_GATEWAY — VM gateway IP                        (default: 10.188.0.1)
#   NETWORK_DNS     — DNS servers                          (default: 1.1.1.1,8.8.8.8)
#   AUTO_REBUILD    — auto-rebuild stale artifacts         (default: 1)
# Path defaults (ROOT/OUTPUT/DEPLOY_DIR/VOL_ROOT/LOG_DIR) and VSOCKGUARD are
# provided by common/sh/runtime.sh.
# Functions are provided with tc_ prefix. Unprefixed aliases (log_section,
# log_step, etc.) are also defined for convenience — test scripts can use
# either form.
# ═══════════════════════════════════════════════════════════════════════
# 1. Shared runtime + e2e Configuration Defaults
# ═══════════════════════════════════════════════════════════════════════

ROOT="${ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
source "$ROOT/common/sh/runtime.sh"
source "$ROOT/common/sh/stack.sh"

GATEWAY_ADDR="${GATEWAY_ADDR:-:3001}"
STREAM_ADDR="${STREAM_ADDR:-:9998}"
GATEWAY_URL="${GATEWAY_URL:-http://localhost:3001}"
# Human API base URL — /stats and /human/* are on the human listener.
# Derived from the human addr in the gateway config (default :3100).
# The anonymous human control plane refuses a non-loopback bind
# (gateway/app/identity.go) unless -allow-anonymous-human-public is also
# passed — the harness runs anonymous, so the default bind is loopback.
HUMAN_ADDR="${HUMAN_ADDR:-127.0.0.1:3100}"
HUMAN_URL="${HUMAN_URL:-http://localhost:3100}"
LEASE_MS="${LEASE_MS:-100}"
MAX_LEASE_SEC="${MAX_LEASE_SEC:-30}"
POOL_SIZE="${POOL_SIZE:-3}"
VM_MEMORY_MB="${VM_MEMORY_MB:-256}"
# Pool spec: the "small" spec (2 vCPU / 256MB / exec_slots 3) keeps each test
# VM's footprint small so the suite leaves real headroom on memory-tight
# (nested-virt, ~6GB) hosts. CPU oversubscribes freely; memory must not.
SANDLOT_POOL="${SANDLOT_POOL:-small:${POOL_SIZE}}"
NETWORK_BACKEND="${NETWORK_BACKEND:-bridge}"
NETWORK_BRIDGE="${NETWORK_BRIDGE:-br-sandswap}"
NETWORK_SUBNET="${NETWORK_SUBNET:-10.188.0.0/16}"
NETWORK_GATEWAY="${NETWORK_GATEWAY:-10.188.0.1}"
NETWORK_DNS="${NETWORK_DNS:-1.1.1.1,8.8.8.8}"
AUTO_REBUILD="${AUTO_REBUILD:-1}"
BUILD_SH="$ROOT/build/build.sh"

# Default flat template reference (registered by ScanFlatTemplates from -flat-templates).
# All SandFS creations require a template; when none is specified, this default is used.
TC_DEFAULT_TEMPLATE="${TC_DEFAULT_TEMPLATE:-rootfs:v1}"

# ═══════════════════════════════════════════════════════════════════════
# 2. Assertions (logging lives in common/sh/runtime.sh)
# ═══════════════════════════════════════════════════════════════════════

tc_assert_contains() {
    local desc="$1" haystack="$2" needle="$3"
    if echo "$haystack" | grep -q "$needle"; then
        tc_pass "$desc"
    else
        tc_fail "$desc (expected: '$needle')"
        echo "    got: $(echo "$haystack" | head -c 200)"
    fi
}

tc_assert_not_contains() {
    local desc="$1" haystack="$2" needle="$3"
    if echo "$haystack" | grep -q "$needle"; then
        tc_fail "$desc (unexpectedly found: '$needle')"
    else
        tc_pass "$desc"
    fi
}

tc_assert_eq() {
    local desc="$1" actual="$2" expected="$3"
    if [[ "$actual" == "$expected" ]]; then
        tc_pass "$desc"
    else
        tc_fail "$desc (expected: '$expected', got: '$actual')"
    fi
}

tc_json_val() {
    echo "$1" | python3 -c "
import sys,json
try:
    print(json.load(sys.stdin).get('$2',''))
except Exception:
    print('')" 2>/dev/null
    # Always exit 0: callers test the extracted value with [[ -n ]] and run
    # under `set -e` — a failing probe here would kill the caller silently.
    return 0
}

# Unprefixed aliases for the e2e-only assertion helpers (the tc_log_*/pass/
# fail aliases come from common/sh/runtime.sh).
assert_contains()     { tc_assert_contains "$@"; }
assert_not_contains() { tc_assert_not_contains "$@"; }
assert_eq()           { tc_assert_eq "$@"; }
json_val()            { tc_json_val "$@"; }

# ═══════════════════════════════════════════════════════════════════════
# 3. Process Management (kill_sandswap_procs lives in common/sh/runtime.sh)
# ═══════════════════════════════════════════════════════════════════════

# tc_run_vm_pids — print the LIVE sandvmm PIDs this run's sandlot manages,
# read from /run/sandswap-state/default/*/state.json (sorted, unique). This is the
# authoritative "processes we started" record for VM assertions:
#   - /run/sandswap is wiped by tc_clean_environment at script start, so a
#     state.json here can only belong to THIS run — unlike pgrep -x sandvmm,
#     which also counts a leaked-from-a-previous-run process, a concurrent
#     e2e instance, or any foreign sandvmm on a shared host.
#   - It survives sandlot restarts: a re-adopted VM is NOT a child of the new
#     sandlot process, so parent-scoped enumeration would miss it.
# PID-reuse guard: a stale state.json may name a pid the kernel recycled for
# an unrelated process — only pids whose comm is still "sandvmm" are emitted.
tc_run_vm_pids() {
    local st pid
    for st in /run/sandswap-state/default/*/state.json; do
        [[ -f "$st" ]] || continue
        pid=$(python3 -c "import json;print(json.load(open('$st')).get('pid',''))" 2>/dev/null) || pid=""
        [[ "$pid" =~ ^[0-9]+$ ]] || continue
        if [[ -d "/proc/$pid" ]] && [[ "$(cat "/proc/$pid/comm" 2>/dev/null || true)" == "sandvmm" ]]; then
            echo "$pid"
        fi
    done | sort -nu
    return 0
}

# tc_run_vm_ids — print the VM IDs (the /run/sandswap/vm/<id> directory
# names) whose state.json names a LIVE sandvmm PID. Same run-scoping and
# PID-reuse guard as tc_run_vm_pids. Used by re-adopt assertions: a cleanup
# ordering regression (set-fs before unmount) makes the reuse tripwire refuse
# the swap and turns every mounted survivor into a destroy-and-replace, which
# changes this set.
tc_run_vm_ids() {
    local st pid id
    for st in /run/sandswap-state/default/*/state.json; do
        [[ -f "$st" ]] || continue
        pid=$(python3 -c "import json;print(json.load(open('$st')).get('pid',''))" 2>/dev/null) || pid=""
        [[ "$pid" =~ ^[0-9]+$ ]] || continue
        if [[ -d "/proc/$pid" ]] && [[ "$(cat "/proc/$pid/comm" 2>/dev/null || true)" == "sandvmm" ]]; then
            id=$(basename "$(dirname "$st")")
            echo "$id"
        fi
    done | sort -u
}

# tc_descendant_pids <root_pid> [comm] — print the PIDs of live processes in
# root_pid's subtree (root excluded), optionally filtered by comm (process
# name, e.g. "dnsmasq"). Use for "no daemon spawned by OUR stack" assertions:
# a host-wide pgrep counts every same-named process on the box (libvirt's
# dnsmasq, NetworkManager's, an operator's instance) and false-fails healthy
# runs. Reads /proc/*/status (Name: precedes PPid: in every record), walks
# each PPid chain up to root_pid.
tc_descendant_pids() {
    local root="$1" comm="${2:-}"
    [[ -n "$root" && "$root" =~ ^[0-9]+$ && -d "/proc/$root" ]] || return 0
    local -A ppid_map=() pname_map=()
    local pid ppr nm cur hops
    while IFS=$'\t' read -r pid ppr nm; do
        ppid_map["$pid"]="$ppr"
        pname_map["$pid"]="$nm"
    done < <(awk '/^Name:/ { nm = $2 }
                  /^PPid:/ { f = FILENAME; sub(/^\/proc\//, "", f); sub(/\/status$/, "", f); print f "\t" $2 "\t" nm }' \
                  /proc/[0-9]*/status 2>/dev/null)
    for pid in "${!ppid_map[@]}"; do
        [[ -z "$comm" || "${pname_map[$pid]}" == "$comm" ]] || continue
        cur="${ppid_map[$pid]}"
        hops=0
        while [[ -n "$cur" && "$cur" != "0" ]]; do
            if [[ "$cur" == "$root" ]]; then
                echo "$pid"
                break
            fi
            cur="${ppid_map[$cur]:-}"
            (( ++hops > 128 )) && break
        done
    done | sort -nu
    return 0
}

# tc_wait_until <timeout_sec> <cmd...> — poll cmd every 0.5s until it exits 0;
# return 1 on timeout. The uniform replacement for hand-rolled poll loops
# whose timeout branch fell through without failing (vacuous pass). Callers
# under `set -e` must invoke it in a condition: `if tc_wait_until ...; then`.
# (Implementation lives in common/sh/runtime.sh as ss_wait_until, shared with
# the deploy tree; unlike ss_wait_until this keeps the caller's stderr.)
tc_wait_until() {
    local timeout="$1"; shift
    local deadline=$(( SECONDS + timeout ))
    while (( SECONDS < deadline )); do
        if "$@"; then
            return 0
        fi
        sleep 0.5
    done
    return 1
}

# Aliases
run_vm_pids()      { tc_run_vm_pids "$@"; }
descendant_pids()  { tc_descendant_pids "$@"; }
wait_until()       { tc_wait_until "$@"; }

# ═══════════════════════════════════════════════════════════════════════
# 4. Pre-flight Checks
# ═══════════════════════════════════════════════════════════════════════

tc_check_kvm() {
    if [[ -e /dev/kvm ]] && [[ -r /dev/kvm ]]; then
        tc_log_pass "KVM available (/dev/kvm is readable)"
    else
        tc_log_error "KVM not available or not readable — cannot run"
        tc_log_info "Run: sudo chmod 666 /dev/kvm   or add user to kvm group"
        exit 1
    fi
    KVM_MODULE=$(lsmod | grep -o 'kvm_\w*' | head -1 || echo "unknown")
    tc_log_info "KVM module: $KVM_MODULE"
}

tc_check_root() {
    if [[ $EUID -ne 0 ]]; then
        tc_log_error "This script requires root"
        tc_log_info "Run: sudo bash $0"
        exit 1
    fi
    tc_log_pass "Running as root"
}

# (tc_check_artifacts lives in common/sh/runtime.sh)

tc_check_freshness() {
    # Freshness is a property of the ROUND'S START, not of each row. The
    # matrix runner checks (and if needed rebuilds) once in its preflight and
    # exports SANDSWAP_ROUND_FRESH=1 for every row. A per-row re-check lets a
    # mid-round source/artifact touch (a row's scratch build, an install
    # step) turn red on the NEXT row and auto-rebuild the whole set —
    # re-stamping every artifact and invalidating every recorded verdict for
    # a change no row actually depends on.
    # Standalone script runs (no sentinel) keep the full gate.
    if [[ "${SANDSWAP_ROUND_FRESH:-0}" == "1" ]]; then
        tc_log_pass "Round baseline fresh (matrix preflight) — skipping per-row freshness check"
        return 0
    fi
    # Prebuilt release package: output/ ships WITHOUT sources (no build/ tree,
    # no Go/Rust files to compare mtimes against). CI built these artifacts at
    # packaging time, so the gate's question — "artifact older than source?" —
    # is meaningless here; skip instead of failing on the missing build.sh.
    if [[ -f "$ROOT/output/.release-stamp" ]]; then
        tc_log_pass "Prebuilt release package (.release-stamp present) — freshness check skipped"
        return 0
    fi
    if ! bash "$BUILD_SH" check >/tmp/sandswap-freshness.log 2>&1; then
        cat /tmp/sandswap-freshness.log
        if [[ "$AUTO_REBUILD" != "1" ]]; then
            tc_log_error "Artifacts are stale and AUTO_REBUILD=0. Rebuild first: bash build/build.sh all"
            exit 1
        fi
        tc_log_warn "Some artifacts are stale — rebuilding automatically (AUTO_REBUILD=1)..."
        if ! bash "$BUILD_SH" all; then
            tc_log_error "Rebuild failed — see output above"
            exit 1
        fi
        # Re-verify after rebuild; a green `build.sh all` should always pass.
        if ! bash "$BUILD_SH" check >/tmp/sandswap-freshness2.log 2>&1; then
            cat /tmp/sandswap-freshness2.log
            tc_log_error "Artifacts still stale after rebuild — aborting to avoid running old code"
            exit 1
        fi
        tc_log_pass "Artifacts rebuilt and verified fresh"
    else
        tc_log_pass "All artifacts fresh (newer than their sources)"
    fi
}

# (tc_check_tools lives in common/sh/runtime.sh)

# tc_preflight_standard — the common combo: KVM + artifacts + freshness + tools
# Extra tool names can be passed as arguments (beyond the default curl).
tc_preflight_standard() {
    # Mutation-driver exclusion (W4 discipline): a running go-mutate pass
    # holds package files in a MUTATED state between test runs — an
    # AUTO_REBUILD triggered here fails on the mutant, and
    # even a successful build would bake mutant bytes into an artifact.
    # Battery scripts skip loudly instead; the runs are mutually exclusive
    # by scheduling, and the skip is visible in the evidence.
    local mp
    for mp in /var/tmp/r3-installs/mutate-*.pid; do
        [[ -e "$mp" ]] || continue
        local pid
        pid=$(cat "$mp" 2>/dev/null || true)
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            tc_skip_suite "mutation driver active (pid $pid, $(basename "$mp")) — battery runs are mutually exclusive with mutation passes"
        fi
    done
    # Co-location posture: a PRODUCTION deployment (systemd units) on the same
    # host is detected and named. Battery runs are separated by
    # SANDSWAP_E2E_ROOT (set by run-all); a direct script run against the
    # production root while production units are ACTIVE is refused for its
    # own safety — stop the units first, or run with SANDSWAP_E2E_ROOT set.
    # ANY active sandswap unit (gateway/sandlot/sandns/etcd-wrapped names all
    # match the prefix) means a production-like deployment shares this host.
    # Enumerating three instance names missed the single-node shapes
    # (sandswap-gateway.service / sandswap-sandlot.service).
    if systemctl list-units 'sandswap-*' --state=active --no-legend --no-pager 2>/dev/null | grep -q .; then
        if [[ -z "${SANDSWAP_E2E_ROOT:-}" ]]; then
            tc_log_error "production sandswap units are ACTIVE on this host and this script is running against the PRODUCTION root ($DEPLOY_DIR)."
            tc_log_error "refusing to run: stop the units (systemctl stop sandswap-gateway@exec sandswap-gateway@human sandswap-sandlot-instance@main ...) or set SANDSWAP_E2E_ROOT to an isolated root."
            exit 1
        else
            tc_log_warn "production units active; battery running against SANDSWAP_E2E_ROOT=$SANDSWAP_E2E_ROOT (isolated)"
        fi
    fi
    echo "  Host:     $(uname -n)"
    echo "  Arch:     $(uname -m)"
    echo "  Kernel:   $(uname -r)"
    tc_check_kvm
    tc_check_artifacts
    tc_check_freshness
    # python3 is a hard dependency of this library itself (tc_json_val, the
    # /stats parsers) — always required, not opt-in.
    tc_check_tools curl python3 "$@"
}

# (tc_ensure_dev_nodes lives in common/sh/runtime.sh)

# Aliases (ensure_dev_nodes / check_artifacts / check_tools come from
# common/sh/runtime.sh)
check_kvm()       { tc_check_kvm "$@"; }
check_root()      { tc_check_root "$@"; }
check_freshness() { tc_check_freshness "$@"; }
preflight_standard() { tc_preflight_standard "$@"; }

# ═══════════════════════════════════════════════════════════════════════
# 5. Deploy
# ═══════════════════════════════════════════════════════════════════════

# tc_clean_environment — kill stale processes and wipe directories for a
# fresh test run. Creates DEPLOY_DIR, VOL_ROOT, LOG_DIR.

# tc_backup_hosts — snapshot /etc/hosts (and /etc/resolv.conf) for scripts
# that rewrite them. Call BEFORE the first mutation; the script's EXIT trap
# (and the next run's tc_clean_environment, for a SIGKILLed run) calls
# tc_restore_host_files.
tc_backup_host_files() {
    cp /etc/hosts /etc/hosts.sandswap-bak
    tc_log_pass "backed up /etc/hosts (+resolv.conf) for restore on exit"
}

# tc_restore_host_files — restore /etc/hosts & /etc/resolv.conf from the
# backups tc_backup_host_files (or a per-script cp) made. Idempotent; safe to
# call twice (EXIT trap + next run's pre-clean) and safe when no backup exists.
tc_restore_host_files() {
    if [[ -f /etc/hosts.sandswap-bak ]]; then
        cp /etc/hosts.sandswap-bak /etc/hosts
        rm -f /etc/hosts.sandswap-bak
        tc_log_warn "restored /etc/hosts from backup"
    fi
    if [[ -f /etc/resolv.conf.sandswap-bak ]]; then
        rm -f /etc/resolv.conf
        cp /etc/resolv.conf.sandswap-bak /etc/resolv.conf
        rm -f /etc/resolv.conf.sandswap-bak
        tc_log_warn "restored /etc/resolv.conf from backup"
    fi
    return 0
}

# tc_ensure_volume_seed — mint $DEPLOY_DIR/volume-seed when missing and scope
# it to the identity that reads it. The prov role REQUIRES a seed (the on-disk
# directory name of every volume derives from it) and inline prov spawns must
# also pass -volume-seed-file "$DEPLOY_DIR/volume-seed".
#
# Scope: OWNER-ONLY 0600 <prov identity> (the shared helper's default). The
# battery spawns the merged exec,prov sandlot through ss_service_exec as that
# identity with an explicit group list, so an owner-only file is exactly as
# private as the deploy's root:sandprov 0640 — and, unlike a group grant, it
# cannot be inherited by the sandvmm identity (987, member of the shared
# group), which must never be able to read the seed.
#
# The result is VERIFIED, not assumed: ss_ensure_volume_seed swallows a failed
# chown/chmod, and a silent failure left a root-owned seed that the prov
# identity could not read while this function reported success — the suite
# then died later with an unexplained EACCES.
#
# NOTE: this definition and tc_cleanup_deployed_artifacts below used
# to live INSIDE tc_clean_environment's body, so they did not exist until that
# function had run — scripts calling either one standalone (latency-benchmark-
# unmount, latency-benchmark-aiagent) died "command not found". Definitions are
# top-level now.
tc_ensure_volume_seed() {
    local seed="${1:-$DEPLOY_DIR/volume-seed}"
    ss_ensure_volume_seed "$seed"
    local want_owner="${SS_VOLUME_SEED_OWNER:-${SS_PROV_USER:-sandlot}}"
    local want_mode="${SS_VOLUME_SEED_MODE:-0600}"
    want_owner="${want_owner%%:*}"   # a user:group owner still means this user owns it
    want_mode="${want_mode#0}"       # stat prints 600, not 0600
    local owner mode
    owner="$(stat -c '%U' "$seed" 2>/dev/null || echo '?')"
    mode="$(stat -c '%a' "$seed" 2>/dev/null || echo '?')"
    if [[ ! -s "$seed" || "$owner" != "$want_owner" || "$mode" != "$want_mode" ]]; then
        tc_log_error "volume-name seed $seed is ${owner:-missing}:${mode:-?} — the battery needs a non-empty $want_owner $want_mode file (the prov identity that reads it must own it; the sandvmm identity must not be able to read it)"
        return 1
    fi
    return 0
}

# tc_cleanup_deployed_artifacts — remove ONLY the artifacts tc_deploy_artifacts
# copies into $DEPLOY_DIR; NEVER the directory itself. On hosts where
# $DEPLOY_DIR is the bind-mount point and/or carries a co-located
# production deployment, `rm -rf $DEPLOY_DIR` destroys both — a suite doing
# exactly that leaves every later battery script in a half-removed world and
# can take a co-located production deployment's volumes tree with it.
tc_cleanup_deployed_artifacts() {
    local f
    for f in gateway sandlot sandvmm boxout vmlinux.bin initramfs.cpio.gz \
             vsockguard.bpf.o vsockguardctl template-tool bindregdump \
             warden-probe scalepopulator loadprobe; do
        rm -f "$DEPLOY_DIR/$f" 2>/dev/null || true
    done
    rm -rf "$DEPLOY_DIR/certs" "$DEPLOY_DIR/flat-templates" "$DEPLOY_DIR/templates" \
           "$DEPLOY_DIR/volumes" "$DEPLOY_DIR/state" 2>/dev/null || true
    # The seed is battery-minted; drop it so the next suite re-mints with ITS
    # provision user (a stale owner is an EACCES for a different identity).
    rm -f "$DEPLOY_DIR/volume-seed" 2>/dev/null || true
    # Never rmdir $DEPLOY_DIR itself (bind mount point / shared root).
}

tc_clean_environment() {
    # EXCLUSIVITY FIRST: a second harness run must be refused by name, not
    # destroyed by the kill sweep below (two live runs otherwise alternate
    # killing each other's gateways — every symptom then looks like a product
    # regression). Only orphans from a DEAD run are cleaned.
    ss_harness_guard
    tc_log_step "Cleaning up all stale sandswap processes..."
    # Restore host state a previously-aborted script may have mutated. Each
    # test restores its own /etc/hosts & /etc/resolv.conf in its EXIT trap,
    # but a SIGKILL/OOM bypasses traps — without this guard the NEXT run dials
    # a black-holed localhost (disconnect-tolerance points localhost at a dead
    # IP) or keeps a stale DNS override (a resolv.conf-rewriting test).
    tc_restore_host_files
    # systemd units BEFORE the process sweep: killing a unit's processes and
    # leaving the unit active just gets them restarted (Restart=), which the
    # sweep then chases. Stop the services first, then kill whatever is left
    # (crashed units, manual spawns, orphans).
    if command -v systemctl >/dev/null 2>&1 \
        && systemctl list-units 'sandswap-*' --state=active --no-legend --no-pager 2>/dev/null | grep -q .; then
        tc_log_warn "stopping active sandswap units: $(systemctl list-units 'sandswap-*' --state=active --no-legend --no-pager 2>/dev/null | awk '{print $1}' | tr '\n' ' ')"
        timeout 30 systemctl stop 'sandswap-*' 2>/dev/null || true
    fi
    # A container runtime on the host (k3s/kube-router, docker) is an
    # environment-contamination factor for this battery: FORWARD policy DROP,
    # embedded containerd, port/CID/memory contention. Stop it unless the
    # script opted out (oidc needs docker; the k8s deployers ARE k3s).
    ss_container_runtime_clean || exit 1
    rm -f /tmp/sandswap-last-resp.json /tmp/sandswap-last-ms.txt /tmp/sandswap-last-stdout.txt 2>/dev/null || true
    tc_kill_sandswap_procs "pre-test"
    # Host-network residue a SIGKILLed previous run (or a KEEP_ENV debug run)
    # leaves behind: stale TAP devices and sandlot's egress nft tables. Without
    # this, "first tap-" selection and baseline-presence assertions can read
    # the PREVIOUS run's state as this run's result.
    tc_pre_clean_stack
    # The e2e identity store is per-stack (see tc_start_gateway): a new run
    # starts with no agents and no sandfs records, not the previous suite's.
    rm -f "${TC_IDENTITY_STORE:-$DEPLOY_DIR/state/e2e-identity-store.json}" 2>/dev/null || true
    # Unmount any overlay mounts under VOL_ROOT before rm -rf.
    # Without this, rm -rf removes the mount point directory but the mount
    # stays alive referencing a deleted path (EBUSY on subsequent operations).
    tc_unmount_overlays_under "$VOL_ROOT"
    # A previous STORAGE_BACKEND=nfs run leaves its export mounted here. A
    # local run would otherwise execute on NFS silently (volume materialization
    # can exceed the create timeout). The nfs profile re-mounts below.
    if [[ "${STORAGE_BACKEND:-local}" != "nfs" ]] && mountpoint -q "$VOL_ROOT"; then
        umount "$VOL_ROOT" 2>/dev/null || true
    fi
    rm -rf /run/sandswap /run/sandswap-state 2>/dev/null || true
    rm -rf "$VOL_ROOT" 2>/dev/null || true
    # The template store (volumes-dir sibling) is per-run state too: stale
    # refs from a previous suite would point at flat sources that no longer
    # exist (refs are create-only by design).
    rm -rf "$(dirname "$VOL_ROOT")/templates" 2>/dev/null || true
    rm -rf "$LOG_DIR" 2>/dev/null || true
    mkdir -p "$DEPLOY_DIR" "$VOL_ROOT" "$LOG_DIR"
    # Dedicated-identity model (kubelet model): ensure the service users and
    # hand the runtime directories to the identities that must write them.
    # Every e2e starts here, so the whole suite runs services as non-root
    # exactly like production.
    ss_ensure_service_users
    ss_prepare_dirs
    # Volume-name seed (required by the prov role) + the prov-side path
    # contract (state root, share root, template store) — ONE implementation,
    # applied by shape via SS_PROV_USER (see ss_apply_share_plane).
    tc_ensure_volume_seed
    # The template store defaults to the volumes-dir SIBLING (same filesystem);
    # give it the shared-group setgid layout so the prov role can write
    # layers/refs. $DEPLOY_DIR itself is the gateway identity's state root
    # (identity store + lock), mode 0755 so the sandlot identities can still
    # read the binaries and flat-templates inside it.
    ss_apply_share_plane "$DEPLOY_DIR" "$VOL_ROOT" "$(dirname "$VOL_ROOT")/templates"
    # /tmp staging dirs the gateway WRITES into (template layers/refs). A
    # previous ROOT-mode run leaves them root-owned → the sandswap gateway
    # gets EACCES on its first template write. Wipe + pre-own. NOTE: only
    # gateway-written dirs belong here — /tmp/sandswap-flat-templates is
    # script-managed content the gateway merely reads, and wiping it here
    # would destroy what scripts seed BEFORE calling this function.
    # Template dirs are deliberately NOT touched here: they are exclusively
    # managed by each script's ss_prepare_shared_dir call (wipe + recreate,
    # right before the gateway starts). A clean-environment wipe would race
    # scripts that prepare templates BEFORE calling this function — the
    # order contract is: clean → prepare → start gateway.
    # Distributed-storage e2e profile: mount VOL_ROOT over the loopback NFS
    # export so the whole run exercises real client-server storage semantics
    # (see docs/operations/storage.md).
    if [[ "${STORAGE_BACKEND:-local}" == "nfs" ]]; then
        ss_storage_nfs_setup
        ss_storage_nfs_mount volumes "$VOL_ROOT"
    fi
    tc_log_pass "Environment clean (old logs purged)"

    # Ensure NO sandswap process is running before copying binaries,
    # otherwise the copy fails with "Text file busy".
    local still_running
    still_running=$(ps aux 2>/dev/null | grep -E "(^|/)(sandvmm|sandlot|gateway) |(^|/)sandswap-(sandvmm|sandlot|gateway) " | grep -vE "grep|bash" || true)
    if [[ -n "$still_running" ]]; then
        tc_log_warn "sandswap processes running before deploy — killing:"
        echo "$still_running"
        tc_kill_sandswap_procs "pre-deploy"
        still_running=$(ps aux 2>/dev/null | grep -E "(^|/)(sandvmm|sandlot|gateway) |(^|/)sandswap-(sandvmm|sandlot|gateway) " | grep -vE "grep|bash" || true)
        if [[ -n "$still_running" ]]; then
            tc_log_error "cannot kill stale processes, aborting"
            exit 1
        fi
    fi
    tc_log_pass "No sandswap processes running — safe to copy binaries"
}

# (tc_deploy_artifacts lives in common/sh/runtime.sh)

# tc_gen_certs — generate mTLS certs for the gateway<->sandlot stream.
tc_gen_certs() {
    tc_log_step "Generating mTLS certs for gateway<->sandlot stream..."
    CERT_DIR="${CERT_DIR:-$DEPLOY_DIR/certs}"
    # CN = the node id this pair is issued for: the gateway binds a stream's
    # declared node_id to the client certificate CN (exact match), so the
    # default pair must carry the harness's default node id.
    # The harness's single sandlot is MERGED (roles exec,prov by default), and
    # the certificate is the role grant: mint the default pair for the same
    # role set. A prov-only or exec-only run overrides TC_SANDLOT_ROLES.
    SANDLOT_CN="${TC_NODE_ID:-test-node-1}" SANDLOT_ROLES="${TC_SANDLOT_ROLES:-exec,prov}" \
        bash "$ROOT/deploy/gen-certs.sh" "$CERT_DIR" >/dev/null
    # Per-node pairs are minted on demand against THIS CA: a pair left from an
    # earlier deploy dir whose CA was regenerated would be untrusted, so drop
    # them; tc_node_cert re-mints what the run actually starts.
    rm -f "$CERT_DIR"/sandlot-*.crt "$CERT_DIR"/sandlot-*.key 2>/dev/null || true
    ss_own_tls_keys "$CERT_DIR"
    tc_log_pass "mTLS certs ready in $CERT_DIR (keys scoped per service identity)"
}

# tc_node_cert <node-id> [roles] — print the CERT PAIR PREFIX (no extension) to
# use for that node id, minting a per-node pair from the harness CA when the
# pair is missing OR does not grant the requested roles. The gateway binds two
# things to the client certificate: node_id == CN, and every advertised stream
# role must appear as a URI SAN sandswap://role/<role>. A prov instance must
# therefore ask for "prov" here; the default is exec.
tc_node_cert() {
    local node="$1" roles="${2:-exec}" dir="${CERT_DIR:-$DEPLOY_DIR/certs}" cn
    if [[ -f "$dir/sandlot.crt" ]]; then
        cn="$(openssl x509 -in "$dir/sandlot.crt" -noout -subject 2>/dev/null \
              | sed -n 's/.*CN *= *\([^,]*\).*/\1/p')"
        if [[ "$cn" == "$node" ]]; then
            local ok=1 r
            for r in $(printf '%s' "$roles" | tr ',' ' '); do
                openssl x509 -in "$dir/sandlot.crt" -noout -ext subjectAltName 2>/dev/null \
                    | grep -q "sandswap://role/${r}" || { ok=0; break; }
            done
            if [[ "$ok" == 1 ]]; then
                printf '%s\n' "$dir/sandlot"
                return 0
            fi
        fi
    fi
    local grants=1 r
    if [[ ! -f "$dir/sandlot-${node}.crt" ]]; then
        grants=0
    else
        for r in $(printf '%s' "$roles" | tr ',' ' '); do
            openssl x509 -in "$dir/sandlot-${node}.crt" -noout -ext subjectAltName 2>/dev/null \
                | grep -q "sandswap://role/${r}" || { grants=0; break; }
        done
    fi
    if [[ "$grants" == 0 ]]; then
        rm -f "$dir/sandlot-${node}.crt" "$dir/sandlot-${node}.key"
        bash "$ROOT/deploy/gen-certs.sh" --client-cn "${node}:${roles}" "$dir" >/dev/null
    fi
    # Re-scope even a pre-existing pair: a stale key from an earlier run can
    # carry another identity's ownership/mode, and this is the only place
    # that repairs it (an exec sandlot otherwise dies on EACCES for
    # its own per-node key). A handful of chown/chmods, no measurable cost.
    ss_own_tls_keys "$dir"
    printf '%s\n' "$dir/sandlot-${node}"
}

# tc_gen_gateway_config — generate a gateway YAML config file.
# Writes to $1 (path). Uses the current test variables for defaults.
# After calling this, set TC_GATEWAY_CONFIG=<path> and call tc_start_gateway.
tc_gen_gateway_config() {
    local path="$1"
    cat > "$path" <<EOF
vol_root: "${VOL_ROOT}"
mode: ""

agent:
  addr: "${GATEWAY_ADDR}"
  tls_cert: ""
  tls_key: ""
  tls_ca: ""

human:
  addr: "${HUMAN_ADDR}"

stream:
  addr: "${STREAM_ADDR}"
  tls_cert: "${CERT_DIR}/gateway.crt"
  tls_key: "${CERT_DIR}/gateway.key"
  tls_ca: "${CERT_DIR}/ca.crt"

lease:
  sticky_ms: ${LEASE_MS}
  max_sticky_sec: ${MAX_LEASE_SEC}

exec:
  default_timeout_sec: 30
  max_timeout_sec: 180

EOF
    tc_log_pass "Gateway config written to $path"
}

# tc_gen_sandlot_config — generate a sandlot YAML config file.
# Writes to $1 (path). Uses the current test variables for defaults.
# After calling this, set TC_SANDLOT_CONFIG=<path> and call tc_start_sandlot.
tc_gen_sandlot_config() {
    local path="$1"
    cat > "$path" <<EOF
gateway_addr: "localhost${STREAM_ADDR}"
node_id: "${TC_NODE_ID:-test-node-1}"
vmm_binary: "${TC_VMM_BINARY:-$DEPLOY_DIR/sandvmm}"

microvm:
  kernel: "${TC_KERNEL:-$DEPLOY_DIR/vmlinux.bin}"
  initramfs: "${TC_INITRAMFS:-$DEPLOY_DIR/initramfs.cpio.gz}"
  default_vcpus: ${TC_VCPUS:-2}
  default_memory_mb: ${VM_MEMORY_MB}
  volumes_dir: "${VOL_ROOT}"
$(if [[ -n "${TC_WARDEN_LOG:-}" ]]; then echo "  warden_log: \"${TC_WARDEN_LOG}\""; fi)
$(if [[ -n "${TC_WARDEN_MAX_EXEC:-}" ]]; then echo "  warden_max_exec_timeout_sec: ${TC_WARDEN_MAX_EXEC}"; fi)

$(if [[ "${TC_SANDLOT_ROLES:-exec,prov}" == *exec* ]]; then
    printf 'specs:\n  small:\n    vcpus: 1\n    memory_mb: 128\n    exec_slots: 3\n  medium:\n    vcpus: 2\n    memory_mb: %s\n    exec_slots: 3\n\npool: "%s"\n' "${VM_MEMORY_MB}" "${SANDLOT_POOL}"
fi)

# Merged roles: the e2e single sandlot is both the exec node and the storage
# plane. Without "prov" every sandfs create would 503 (no local mode exists
# in the gateway anymore). Exec machinery (specs/pool) is emitted only for
# exec-bearing roles: the config validator refuses a pool on prov-only.
roles: [${TC_SANDLOT_ROLES:-exec,prov}]
provision:
  # templates_dir intentionally unset: resolves to overlayfs_templates (the
  # same store the exec role reads lowerdirs from), then the sibling
  # templates/ dir beside volumes_dir — the legacy /var/sandswap/templates
  # default is gone. Tests that isolate a store pass -overlayfs-templates
  # explicitly.
  flat_templates_dir: "${TC_FLAT_TEMPLATES:-$DEPLOY_DIR/flat-templates}"
  # Volume-name seed: required by the prov role (the on-disk directory name is
  # derived from it). Stable across a run's reconnects — a regenerated seed
  # would orphan the names of volumes created earlier in the same run.
  volume_seed_file: "${TC_VOLUME_SEED_FILE:-$DEPLOY_DIR/volume-seed}"

recycle:
  max_uses: ${TC_MAX_USES:-50}
  # The two other lifetime caps are product defaults (10000 mounts / 300
  # distinct agents). They are emitted explicitly so a benchmark can pin them
  # the same way it pins max_uses — the realistic llm-load model drives
  # hundreds of different agents through each VM, which makes the
  # distinct-agent cap the first recycle trigger there.
  max_mounts: ${TC_MAX_MOUNTS:-10000}
  max_distinct_agents: ${TC_MAX_DISTINCT_AGENTS:-300}
  mem_percent: ${TC_RECYCLE_MEM_PERCENT:-10}
  mem_abs_mb: ${TC_RECYCLE_MEM_ABS_MB:-100}
  min_idle_floor_frac: ${TC_MIN_IDLE_FLOOR:-0}

network:
  backend: "${NETWORK_BACKEND}"
  bridge: "${NETWORK_BRIDGE}"
  subnet: "${NETWORK_SUBNET}"
  gateway: "${NETWORK_GATEWAY}"
  dns: "${NETWORK_DNS}"

tls:
  cert: "$(tc_node_cert "${TC_NODE_ID:-test-node-1}" "${TC_SANDLOT_ROLES:-exec,prov}").crt"
  key: "$(tc_node_cert "${TC_NODE_ID:-test-node-1}" "${TC_SANDLOT_ROLES:-exec,prov}").key"
  ca: "${CERT_DIR}/ca.crt"
EOF
    tc_log_pass "Sandlot config written to $path"
}

# tc_volume_path <sandfs_id> — print the host-side volume directory of a sandfs
# by asking the human API for its record. Since volume names are DERIVED from
# the deployment seed (sandlot/provision/volname), the directory name is NOT
# the sandfs id; suites must resolve it here instead of assuming "$VOL_ROOT/$id".
# Prints nothing (and returns 1) when the record or the API is unavailable, so
# `set -e` callers fail loudly rather than acting on an empty path.
tc_volume_path() { ss_volume_path "$HUMAN_URL" "$1"; }


# tc_create_agent_and_sandfs — create an agent and its SandFS in one call.
# The gateway API requires a two-step process:
#   1. POST /human/agent → {agent_id, api_key}
#   2. POST /human/sandfs {agent_id, name, template, mode, ...} → {sandfs_id, rootfs_path, ...}
# Usage: tc_create_agent_and_sandfs <name> [template_ref] [mode]
#   template_ref: defaults to TC_DEFAULT_TEMPLATE ("rootfs:v1") if not specified
#   mode: "flat" or "overlay"; if omitted, auto-detected (single mode → auto; both → error)
# Sets: TC_AGENT_ID, TC_API_KEY, TC_SANDFS_ID, TC_ROOTFS_PATH
# Returns: JSON with sandfs_id, api_key, agent_id, rootfs_path
tc_create_agent_and_sandfs() {
    # Implementation: ss_agent_and_sandfs (common/sh/stack.sh), which resolves
    # the mode, retries the storage plane's named 503, and sets the SS_* ids;
    # this wrapper maps them onto the TC_* globals the e2e suite reads.
    SS_AGENT_ID=""; SS_API_KEY=""; SS_SANDFS_ID=""; SS_ROOTFS_PATH=""
    ss_agent_and_sandfs "$HUMAN_URL" "$1" "${2:-$TC_DEFAULT_TEMPLATE}" "${3:-}"
    TC_AGENT_ID="$SS_AGENT_ID"
    TC_API_KEY="$SS_API_KEY"
    TC_SANDFS_ID="$SS_SANDFS_ID"
    TC_ROOTFS_PATH="$SS_ROOTFS_PATH"
}

# tc_delete_sandfs — delete a SandFS by ID.
# Usage: tc_delete_sandfs <sandfs_id>
tc_delete_sandfs() { ss_delete_sandfs "$HUMAN_URL" "$1"; }

# Aliases
clean_environment() { tc_clean_environment "$@"; }
gen_certs()               { tc_gen_certs "$@"; }
gen_gateway_config()      { tc_gen_gateway_config "$@"; }
gen_sandlot_config()      { tc_gen_sandlot_config "$@"; }
create_agent_and_sandfs() { tc_create_agent_and_sandfs "$@"; }
delete_sandfs()           { tc_delete_sandfs "$@"; }

# ═══════════════════════════════════════════════════════════════════════
# 6. Service Lifecycle
# ═══════════════════════════════════════════════════════════════════════

# tc_start_gateway — start the gateway process with standard flags plus
# any extra flags passed as arguments. Waits for stream server readiness.
# Sets GATEWAY_PID.
#
# If TC_GATEWAY_CONFIG is set, uses -config mode (all other flags come from
# the config file). Otherwise uses individual CLI flags.
tc_start_gateway() {
    local extra_flags=("$@")
    tc_log_step "Starting gateway (HTTP $GATEWAY_ADDR, stream $STREAM_ADDR)..."

    local gateway_bin="${TC_GATEWAY_BIN:-$DEPLOY_DIR/gateway}"

    # The gateway identity store lives under the gateway-owned state/ dir
    # (H-03: the state root itself is root-owned). Create it here for scripts
    # that start the gateway without tc_clean_environment.
    install -d -m 0700 -o "$SS_SERVICE_USER_GW" -g "$SS_SERVICE_USER_GW" \
        "$DEPLOY_DIR/state" 2>/dev/null || true

    # Ops endpoints on an EXEC-mode agent listener are token-gated
    # (-ops-token-file; empty flag = 404). The battery's pool-ready polls hit
    # those endpoints, so every battery gateway carries a per-run token,
    # exported for the ss_* stats helpers. Single-node/human modes ignore the
    # flag entirely — harmless there. Mint once per run (idempotent).
    export TC_OPS_TOKEN_FILE="${TC_OPS_TOKEN_FILE:-$DEPLOY_DIR/ops.token}"
    if [[ ! -s "$TC_OPS_TOKEN_FILE" ]]; then
        (umask 027; openssl rand -hex 24 > "$TC_OPS_TOKEN_FILE") >/dev/null 2>&1 \
            || { tc_log_error "ops token mint failed"; exit 1; }
        chown "root:$SS_SERVICE_USER_GW" "$TC_OPS_TOKEN_FILE" 2>/dev/null || true
    fi
    export TC_OPS_TOKEN="$(cat "$TC_OPS_TOKEN_FILE")"
    extra_flags+=(-ops-token-file "$TC_OPS_TOKEN_FILE")

    # Dedicated-identity model: the gateway runs as the sandserv user (no
    # capabilities). The ss_service_exec call is backgrounded, so its exec
    # replaces the subshell and $! IS the service PID (setpriv execs in-place).
    # The identity store defaults to a per-e2e file: the production default
    # (VolRoot's parent) is a FIXED path shared by every run, so records of a
    # previous suite's deleted sandfs survived tc_clean_environment and leaked
    # into anything that walks ALL records (the seed-rotation tool's --run
    # refused stale un-stamped entries for volumes that no longer existed).
    # Suites that bring their own store pass -identity-store as an extra flag,
    # which lands AFTER this default and wins (Go's flag package keeps the
    # last occurrence).
    local id_store="${TC_IDENTITY_STORE:-$DEPLOY_DIR/state/e2e-identity-store.json}"
    if [[ -n "${TC_GATEWAY_CONFIG:-}" ]]; then
        # Config-file mode: only -config + overrides
        ss_service_exec sandserv -- "$gateway_bin" \
            -config "$TC_GATEWAY_CONFIG" \
            -agent-addr "$GATEWAY_ADDR" \
            -human-addr "$HUMAN_ADDR" \
            -stream-addr "$STREAM_ADDR" \
            -identity-store "$id_store" \
            -stream-tls-cert "$CERT_DIR/gateway.crt" \
            -stream-tls-key "$CERT_DIR/gateway.key" \
            -stream-tls-ca "$CERT_DIR/ca.crt" \
            -allow-anonymous-human \
            "${extra_flags[@]}" \
            > "$LOG_DIR/gateway.log" 2>&1 &
    else
        # Legacy CLI-flag mode
        ss_service_exec sandserv -- "$gateway_bin" \
            -agent-addr "$GATEWAY_ADDR" \
            -human-addr "$HUMAN_ADDR" \
            -stream-addr "$STREAM_ADDR" \
            -vol-root "$VOL_ROOT" \
            -sticky-ms "$LEASE_MS" \
            -max-sticky-sec "$MAX_LEASE_SEC" \
            -identity-store "$id_store" \
            -stream-tls-cert "$CERT_DIR/gateway.crt" \
            -stream-tls-key "$CERT_DIR/gateway.key" \
            -stream-tls-ca "$CERT_DIR/ca.crt" \
            -allow-anonymous-human \
            "${extra_flags[@]}" \
            > "$LOG_DIR/gateway.log" 2>&1 &
    fi
    GATEWAY_PID=$!

    # Wait for gateway readiness (stream server must be up before sandlot connects)
    local stream_up=0
    for i in $(seq 1 30); do
        sleep 0.3
        if ! kill -0 $GATEWAY_PID 2>/dev/null; then
            tc_log_error "Gateway failed to start"
            echo "=== gateway log ==="
            tail -10 "$LOG_DIR/gateway.log"
            exit 1
        fi
        if ss -tln 2>/dev/null | grep -q "$STREAM_ADDR"; then
            stream_up=1
            break
        fi
    done
    if [[ "$stream_up" != "1" ]]; then
        tc_log_error "Gateway stream listener $STREAM_ADDR never came up (9s wait)"
        echo "=== gateway log ==="
        tail -10 "$LOG_DIR/gateway.log"
        exit 1
    fi

    if ! kill -0 $GATEWAY_PID 2>/dev/null; then
        tc_log_error "Gateway process died"
        tail -10 "$LOG_DIR/gateway.log"
        exit 1
    fi
    tc_log_pass "Gateway running (PID $GATEWAY_PID)"
}

# tc_start_sandlot — start the sandlot process with standard flags plus
# any extra flags. Waits for sandlot to connect to gateway.
# Sets SANDLOT_PID.
#
# If TC_SANDLOT_CONFIG is set, uses -config mode (all other flags come from
# the config file). Otherwise uses individual CLI flags.
# TC_SANDLOT_EXTRA_FLAGS (optional env, word-split on purpose) appends extra
# CLI flags in both modes — e.g. A/B: TC_SANDLOT_EXTRA_FLAGS="-setfs-transport http".
tc_start_sandlot() {
    local extra_flags=("$@")
    tc_log_step "Starting sandlot (connects to gateway gRPC $STREAM_ADDR)..."

    local sandlot_bin="${TC_SANDLOT_BIN:-$DEPLOY_DIR/sandlot}"

    # Dedicated-identity model: sandlot runs as the sandlot user with the
    # kubelet capability set (CAP_NET_ADMIN for TAP/bridge, CAP_SYS_ADMIN for
    # overlay mounts); its sandvmm children inherit the same ambient set.
    if [[ -n "${TC_SANDLOT_CONFIG:-}" ]]; then
        # Config-file mode: only -config + overrides
        ss_service_exec sandlot -- "$sandlot_bin" \
            -config "$TC_SANDLOT_CONFIG" \
            -roles "${TC_SANDLOT_ROLES:-exec,prov}" \
            -allow-insecure-volumes -allow-missing-vsockguard \
            -gateway-addr "localhost$STREAM_ADDR" \
            -tls-cert "$(tc_node_cert "${TC_NODE_ID:-test-node-1}" "${TC_SANDLOT_ROLES:-exec,prov}").crt" \
            -tls-key "$(tc_node_cert "${TC_NODE_ID:-test-node-1}" "${TC_SANDLOT_ROLES:-exec,prov}").key" \
            -tls-ca "$CERT_DIR/ca.crt" \
            ${TC_SANDLOT_EXTRA_FLAGS:-} \
            "${extra_flags[@]}" \
            > "$LOG_DIR/sandlot.log" 2>&1 &
    else
        # Legacy CLI-flag mode.
        # The bridge network flags use an intentional unquoted command
        # substitution: the echo must word-split so each -network-* flag lands
        # as a separate argv element (SC2046).
        # -volume-seed-file carries the volume-name seed as a FILE PATH (the
        # seed itself must never travel as a flag: argv is world-readable), and
        # the prov role refuses to start without it.
        # shellcheck disable=SC2046
        ss_service_exec sandlot -- "$sandlot_bin" \
            -gateway-addr "localhost$STREAM_ADDR" \
            -node-id "${TC_NODE_ID:-test-node-1}" \
            -kernel "${TC_KERNEL:-$DEPLOY_DIR/vmlinux.bin}" \
            -initramfs "${TC_INITRAMFS:-$DEPLOY_DIR/initramfs.cpio.gz}" \
            -vmm-binary "${TC_VMM_BINARY:-$DEPLOY_DIR/sandvmm}" \
            -volumes-dir "$VOL_ROOT" \
            -allow-insecure-volumes -allow-missing-vsockguard \
            -roles "${TC_SANDLOT_ROLES:-exec,prov}" \
            -flat-templates "${TC_FLAT_TEMPLATES:-$DEPLOY_DIR/flat-templates}" \
            -volume-seed-file "${TC_VOLUME_SEED_FILE:-$DEPLOY_DIR/volume-seed}" \
            -default-vcpus "${TC_VCPUS:-2}" \
            -default-memory "$VM_MEMORY_MB" \
            -pool "$SANDLOT_POOL" \
            -network-backend "$NETWORK_BACKEND" \
            $([[ "$NETWORK_BACKEND" == "bridge" ]] && echo \
                -network-bridge "$NETWORK_BRIDGE" \
                -network-subnet "$NETWORK_SUBNET" \
                -network-gateway "$NETWORK_GATEWAY" \
                -network-dns "$NETWORK_DNS") \
            -tls-cert "$(tc_node_cert "${TC_NODE_ID:-test-node-1}" "${TC_SANDLOT_ROLES:-exec,prov}").crt" \
            -tls-key "$(tc_node_cert "${TC_NODE_ID:-test-node-1}" "${TC_SANDLOT_ROLES:-exec,prov}").key" \
            -tls-ca "$CERT_DIR/ca.crt" \
            ${TC_SANDLOT_EXTRA_FLAGS:-} \
            "${extra_flags[@]}" \
            > "$LOG_DIR/sandlot.log" 2>&1 &
    fi
    SANDLOT_PID=$!

    # Wait for sandlot to connect to gateway
    sleep 1
    if ! kill -0 $SANDLOT_PID 2>/dev/null; then
        tc_log_error "Sandlot failed to start"
        echo "=== sandlot log ==="
        tail -10 "$LOG_DIR/sandlot.log"
        exit 1
    fi
    tc_log_pass "Sandlot running (PID $SANDLOT_PID)"
}

# tc_wait_health — wait for the gateway HTTP /health endpoint.
tc_wait_health() {
    tc_log_info "Waiting for gateway HTTP health check..."
    local health=""
    if ss_wait_health "$GATEWAY_URL/health" 15; then
        health=$(curl -s -m 3 "$GATEWAY_URL/health" 2>/dev/null || true)
    fi

    if echo "${health:-}" | grep -q '"status"'; then
        tc_log_pass "Gateway healthy: $health"
    else
        tc_log_error "Gateway health check failed"
        echo "=== gateway log ==="
        tail -10 "$LOG_DIR/gateway.log"
        echo "=== sandlot log ==="
        tail -10 "$LOG_DIR/sandlot.log"
        exit 1
    fi
}

# tc_wait_pool_ready — wait for sandlot pool pre-creation to reach target.
# Usage: tc_wait_pool_ready [target] [stats_url]
#   target    — CLEAN VM count to wait for (default: $POOL_SIZE)
#   stats_url — /stats base URL (default: $HUMAN_URL; distributed topologies
#               pass the exec gateway's URL, whose pool manager owns its VMs)
tc_wait_pool_ready() {
    local target="${1:-$POOL_SIZE}"
    local stats_url="${2:-$HUMAN_URL}"
    tc_log_info "Waiting for sandlot pool pre-creation (target: $target, stats: $stats_url)..."
    local clean
    # Budget: ~2.5 min. On memory-tight hosts the FIRST pool batch can stall in
    # early boot (2×1GB guests faulted in right after the previous stack's
    # teardown, no swap); sandlot's hung-VM detection then destroys+replaces the
    # batch, and the replacements boot clean. That self-heal takes 60-90s here —
    # give it room instead of proceeding with execs that hit NO_COMPUTE_NODES.
    if ss_wait_pool_ready "$target" "$stats_url" 150; then
        clean=$(ss_pool_clean "$stats_url")
        tc_log_pass "Pool ready: ${clean//[[:space:]]/} CLEAN VM(s)"
        return 0
    fi
    # Failing the wait must FAIL the script: every caller treats this as a
    # gate, and proceeding with an empty pool turns every later exec into a
    # confusing NO_COMPUTE_NODES error (or worse, a vacuous pass).
    tc_log_error "Pool did not reach target $target within timeout"
    local pool_stats
    local _auth=()
    [[ -n "${TC_OPS_TOKEN:-}" ]] && _auth=(-H "Authorization: Bearer $TC_OPS_TOKEN")
    pool_stats=$(curl -s -m 5 "${_auth[@]}" "$stats_url/stats" 2>/dev/null || echo '{}')
    tc_log_info "Pool: $pool_stats"
    return 1
}

# Aliases
start_gateway()   { tc_start_gateway "$@"; }
start_sandlot()   { tc_start_sandlot "$@"; }
wait_health()     { tc_wait_health "$@"; }
wait_pool_ready() { tc_wait_pool_ready "$@"; }

# ═══════════════════════════════════════════════════════════════════════
# 7. Network
# ═══════════════════════════════════════════════════════════════════════

# tc_setup_host_network — create the host bridge + ip_forward + nftables
# masquerade (idempotent). Run once before sandlot starts.
tc_setup_host_network() {
    ss_host_network_setup "$NETWORK_BRIDGE" "$NETWORK_SUBNET" "$NETWORK_GATEWAY"
}

# tc_teardown_host_network — remove TAPs left by this run, the nftables NAT
# table, and sandlot's egress tables. The bridge itself is left in place
# (harmless to reuse).
tc_teardown_host_network() { ss_host_network_teardown; }

# tc_pre_clean_stack — delete host state a SIGKILLed previous run (or a
# KEEP_ENV debug run) can leave on the shared box: stale TAP devices and
# sandlot's egress nft tables (the per-TAP baseline anti-spoof installed at
# sandlot startup on every backend, plus the routed-ipv6 stamping table). No
# other teardown removes the baseline tables, so without this the next run's
# "first tap-" selection and baseline-presence assertions can read the
# PREVIOUS run's state as their own result. Idempotent; safe under set -e.
tc_pre_clean_stack() { ss_stack_residue_clean; }

# Aliases
setup_host_network()   { tc_setup_host_network "$@"; }
teardown_host_network() { tc_teardown_host_network "$@"; }

# ═══════════════════════════════════════════════════════════════════════
# 7b. Overlay Mount Cleanup
# ═══════════════════════════════════════════════════════════════════════

# tc_unmount_overlays_under <dir> — unmount any overlay mounts under <dir>.
# Needed before rm -rf: if overlay mounts exist, rm removes the mount point
# directory but the mount stays alive referencing a deleted path (EBUSY on
# subsequent operations).  Idempotent and safe to call when no overlays exist.
tc_unmount_overlays_under() {
    local dir="$1"
    mount | grep "overlay.*$dir" | awk '{print $3}' | while read mp; do
        umount "$mp" 2>/dev/null || true
    done || true
}

# Alias
unmount_overlays_under() { tc_unmount_overlays_under "$@"; }

# (vsockguard attach/detach lives in common/sh/runtime.sh)

# ═══════════════════════════════════════════════════════════════════════
# 9. Shared Test Helpers
# ═══════════════════════════════════════════════════════════════════════

# tc_ensure_identity_exec — the dedicated-identity services must be able to
# EXEC the target path. A dev checkout under a user home with restrictive
# traversal (Debian 13 useradd default is drwx------ on the home) is invisible
# to the sandlot user: every VM launch then dies with fork/exec EACCES and the
# script degrades into a 3-minute "pool did not reach target" timeout — the
# suite's worst kind of non-green. Check with the real service identity and,
# when running as root, add traverse-only (o+x) bits on the /home path chain.
# Auto-fix is deliberately limited to /home: widening anything else (e.g.
# /root) is a host-posture decision that must stay manual.
tc_ensure_identity_exec() {
    local target="$1" dir comp
    if setpriv --reuid=sandlot --regid=sandlot --clear-groups \
        test -x "$target" 2>/dev/null; then
        return 0
    fi
    if [[ "$(id -u)" -ne 0 ]]; then
        tc_log_error "service identity cannot exec $target (and this run is not root): chmod o+x each path component of $(dirname "$target")"
        exit 1
    fi
    local -a chain=()
    dir="$(dirname "$target")"
    while [[ "$dir" != "/" && "$dir" != "." ]]; do
        chain+=("$dir")
        dir="$(dirname "$dir")"
    done
    for comp in "${chain[@]}"; do
        setpriv --reuid=sandlot --regid=sandlot --clear-groups \
            test -x "$comp" 2>/dev/null && continue
        case "$comp" in
            /home/*)
                chmod o+x "$comp"
                tc_log_warn "added traverse (o+x) to $comp — the service identities must reach the dev-tree binaries"
                ;;
            *)
                tc_log_error "service identity cannot exec $target: component $comp needs traverse rights; auto-fix covers /home only"
                tc_log_info "fix manually: sudo chmod o+x $comp"
                exit 1
                ;;
        esac
    done
    setpriv --reuid=sandlot --regid=sandlot --clear-groups test -x "$target" || {
        tc_log_error "$target still not executable by the sandlot identity after traverse fix (check file mode itself)"
        exit 1
    }
}

# tc_use_output_binaries — point the service lifecycle at $OUTPUT instead of
# $DEPLOY_DIR (scripts that run binaries straight from the build tree).
tc_use_output_binaries() {
    TC_GATEWAY_BIN="$OUTPUT/gateway"
    TC_SANDLOT_BIN="$OUTPUT/sandlot"
    TC_KERNEL="$OUTPUT/vmlinux.bin"
    TC_INITRAMFS="$OUTPUT/initramfs.cpio.gz"
    TC_VMM_BINARY="$OUTPUT/sandvmm"
    # The services exec these paths directly — verify it up front (see above).
    tc_ensure_identity_exec "$TC_VMM_BINARY"
}

# tc_install_flat_template — set up a flat-template dir the gateway can scan.
# Usage: tc_install_flat_template [dir]  (default /tmp/sandswap-flat-templates)
# Sets TC_FLAT_TEMPLATES. Fails LOUDLY when output/rootfs-template is missing:
# a silently-empty template dir only surfaces later as an opaque
# template-resolution error from the gateway.
tc_install_flat_template() {
    local dir="${1:-/tmp/sandswap-flat-templates}"
    if [[ ! -d "$OUTPUT/rootfs-template" ]]; then
        tc_log_error "missing rootfs-template directory: $OUTPUT/rootfs-template/"
        tc_log_info "Run: bash build/build-rootfs-template.sh"
        exit 1
    fi
    rm -rf "$dir"
    mkdir -p "$dir/rootfs/v1"
    cp -a "$OUTPUT/rootfs-template/." "$dir/rootfs/v1/"
    if [[ ! -d "$dir/rootfs/v1/bin" ]]; then
        tc_log_error "rootfs-template copy failed (no bin/ subdir in $dir/rootfs/v1)"
        exit 1
    fi
    tc_conform_template_tree "$dir"
    TC_FLAT_TEMPLATES="$dir"
    tc_log_pass "Flat template installed: $dir/rootfs/v1 (ref: rootfs:v1)"
}

# tc_conform_template_tree <dir> — make a staged template tree usable by the
# SEED identity (sandprov/sandlot, gid = the shared group): chgrp the tree and
# run the canonical normalizer/validator (docs/operations/template-contract.md).
#
# Both steps are load-bearing, and skipping them fails at CONSUME time with an
# opaque EACCES: a `cp -a` from output/rootfs-ubuntu leaves 0640 root:root files
# (e.g. etc/.pwd.lock) that the non-root seed identity cannot open — "seed
# sandfs from flat template rootfs:v1: open …/.pwd.lock: permission denied".
# Ownership cannot be repaired by chmod (nor by the seed identity, which has no
# CAP_CHOWN), so it has to happen at staging time — exactly as the build and
# deploy scripts do it. Best effort when the identities are absent (dev hosts):
# the copy then stays root-owned and only root-run dev suites can seed.
tc_conform_template_tree() {
    local dir="$1"
    if getent group "$SS_SHARED_GROUP" >/dev/null 2>&1; then
        chgrp -R "$SS_SHARED_GROUP" "$dir" 2>/dev/null || true
    fi
    if [[ -x "$OUTPUT/template-tool" ]]; then
        "$OUTPUT/template-tool" normalize "$dir" >/dev/null 2>&1 || true
        if ! "$OUTPUT/template-tool" validate "$dir" >/dev/null 2>&1; then
            tc_log_error "template fails offline validation after normalize: $dir"
            "$OUTPUT/template-tool" validate "$dir" || true
            exit 1
        fi
    else
        tc_log_warn "output/template-tool missing — staging without the contract check (bash build/build.sh go)"
    fi
}

# ── HTTP exec helpers ────────────────────────────────────────────

# ── HTTP exec helpers ────────────────────────────────────────────
# The implementations live in common/sh/stack.sh (ss_*), shared with the
# deploy verifiers; these are the e2e-tree names the suite calls.

# tc_gw_exec <api_key> <sandfs_id> <code> [extra_json_fields]
# POST /agent/execute. Output: response body, then "HTTPCODE:<code>" on the
# last line (parse with tc_http_code_of / tc_body_of).
tc_gw_exec() { ss_gw_exec "$@"; }

# tc_gw_exec_retry — tc_gw_exec + bounded retry for the server's retryable
# busy states (SANDBOX_CLEANING after a destroy-and-replace, NO_AVAILABLE_
# SANDBOX on a cold pool), honoring the retry_after_ms pacing the body names.
tc_gw_exec_retry() { ss_gw_exec_retry "$@"; }

# tc_gw_exec_headers — like tc_gw_exec but the LAST output line is
# "LEASE:<hit|>" (the X-Sandbox-Lease response header value).
tc_gw_exec_headers() { ss_gw_exec_headers "$@"; }

# tc_gw_status <api_key> <sandfs_id> <exec_id> — poll background-exec status.
tc_gw_status() { ss_gw_status "$@"; }

# tc_gw_kill <api_key> <sandfs_id> <exec_id> — kill a background exec.
tc_gw_kill() { ss_gw_kill "$@"; }

# tc_http_code_of / tc_body_of — split a tc_gw_exec result.
tc_http_code_of() { ss_http_code_of "$@"; }
tc_body_of()      { ss_body_of "$@"; }

# tc_gw_exec_raw <key> <sandfs_id> <code> [timeout_sec] [retries] — sync exec
# returning the RAW JSON body. The uniform replacement for the per-script
# exec_code/exec_in_vm helpers, which had drifted apart (one with retry, one
# with no curl timeout at all — a hung gateway hung the whole test):
#   - body is JSON-escaped via python3 (no sed-quoting bugs)
#   - curl -m timeout = exec timeout + 15s transport slack, so a stuck call
#     FAILS instead of hanging CI
#   - retries ONLY the transient retryable refusals, honoring retry_after_ms;
#     everything else is returned verbatim so the caller's assertions see real
#     behavior. On curl transport failure the body is empty — assertions on
#     stdout contents then fail honestly instead of passing vacuously.
tc_gw_exec_raw() { ss_gw_exec_raw "$@"; }

# tc_json_stdout — stdout field of a JSON exec response read from stdin
# (pipe tc_gw_exec_raw into it). Empty on parse failure — callers asserting on
# content then fail honestly; callers asserting NOT-contains must pair the
# check with an explicit success assert elsewhere.
tc_json_stdout() { ss_json_stdout "$@"; }

# tc_run_go_suite <repo_subdir> <run_pattern> <packages> [go test args...] —
# build + run a module's Go tests with THREE guards against silent coverage loss:
#   1. vacuous-pass guard: a run pattern matching NO tests fails, not green
#   2. coverage floor: fewer than TC_MIN_TESTS passing tests fails (a RENAMED
#      test shrinks the suite silently otherwise — the pattern still matches
#      its siblings, so guard #1 alone can't see it)
#   3. race detector: -race is ON by default (TC_GO_RACE=0 to opt out on a
#      slow machine). A plain `go test` lets latent data races ship — an
#      ownership-cache race is visible ONLY to the race detector (no plain
#      test exercises the concurrent path).
# Prints the per-test PASS/FAIL lines (and FAIL detail on failure). Returns 1
# if the suite failed, matched nothing, or passed fewer than TC_MIN_TESTS.
tc_run_go_suite() {
    local dir="$1" pattern="$2" packages="$3"; shift 3
    local out rc=0 raceargs=""
    [[ "${TC_GO_RACE:-1}" != "0" ]] && raceargs="-race"
    out=$( (cd "$ROOT/$dir" && go test $raceargs -run "$pattern" -count=1 $packages "$@") 2>&1 ) || rc=$?
    echo "$out" | grep -E '(^--- |^ok |^FAIL|no tests to run)' | grep -v '"level"' || true
    if [[ $rc -ne 0 ]]; then
        tc_log_error "go test FAILED in $dir (rc=$rc)"
        echo "$out" | grep -B2 -A8 '^FAIL' | head -40
        return 1
    fi
    if echo "$out" | grep -q "no tests to run"; then
        tc_log_error "run pattern '$pattern' matched NO tests in $dir — vacuous pass"
        return 1
    fi
    local npass
    npass=$(echo "$out" | grep -c '^--- PASS' || true)
    if [[ -n "${TC_MIN_TESTS:-}" ]] && [[ "$npass" -lt "$TC_MIN_TESTS" ]]; then
        tc_log_error "only $npass tests passed (coverage floor TC_MIN_TESTS=$TC_MIN_TESTS) — a test was renamed/skipped?"
        return 1
    fi
    return 0
}

# tc_json_field <field> — read JSON from stdin, print value of <field>.
# Always exits 0 (like tc_json_val): a non-JSON body (5xx HTML, empty) yields
# an empty string, not a dead caller — under a caller's `set -e`, the failing
# python would otherwise abort the script BEFORE its failure-handling branch.
tc_json_field() { ss_json_field "$@"; }

# tc_stats_clean_vms [stats_url] — CLEAN VM count from GET /stats, tolerating
# every /stats shape this endpoint has had. /stats is served on the HUMAN
# listener, NOT the agent listener — see gateway runSingleNodeMode
# ("NOTE: /human/* and /stats are NOT registered on the agent listener").
tc_stats_clean_vms() { ss_pool_clean "$@"; }

# ── etcd helpers (test-local single-node etcd) ───────────────────

ETCD_DIR="${ETCD_DIR:-/tmp/etcd-v3.6.13-linux-amd64}"
ETCD_ENDPOINT="${ETCD_ENDPOINT:-http://127.0.0.1:2379}"

# tc_etcd_ready — health probe. Prefers etcdctl endpoint health; falls back to
# a raw TCP connect on the client port when etcdctl isn't installed.
tc_etcd_ready() {
    if [[ -n "${ETCDCTL:-}" ]]; then
        "$ETCDCTL" --endpoints "$ETCD_ENDPOINT" endpoint health &>/dev/null
    else
        # /dev/tcp/host/port — NB the endpoint must be split, NOT passed whole:
        # `exec 3<>127.0.0.1:2379` asks bash to open a FILE of that name and
        # always fails, turning every startup wait into a false timeout.
        (exec 3<>"/dev/tcp/${ETCD_ENDPOINT#http://}") &>/dev/null
    fi
}

# tc_ensure_etcd — resolve the etcd/etcdctl binaries: $ETCD_DIR cache first,
# then PATH, then a one-time download to $ETCD_DIR. Sets ETCD (required) and
# ETCDCTL (may be empty — tc_etcd_ready degrades to a TCP probe).
tc_ensure_etcd() {
    if [[ -x "$ETCD_DIR/etcd" ]]; then
        ETCD="$ETCD_DIR/etcd"
        ETCDCTL="$ETCD_DIR/etcdctl"
    elif command -v etcd >/dev/null 2>&1; then
        ETCD="$(command -v etcd)"
        ETCDCTL="$(command -v etcdctl || true)"
    elif [[ -x "$ROOT/output/etcd/etcd" ]]; then
        # Vendored etcd shipped inside a release package (output/etcd/) —
        # lets distributed-topology runs work offline, no download.
        ETCD="$ROOT/output/etcd/etcd"
        ETCDCTL="$ROOT/output/etcd/etcdctl"
    else
        local version="v3.6.13"
        local tgz="etcd-${version}-linux-amd64.tar.gz"
        local url="https://github.com/etcd-io/etcd/releases/download/${version}/${tgz}"
        tc_log_info "etcd not found — downloading ${url}..."
        if ! curl -sL "$url" | tar xz -C /tmp/; then
            tc_log_error "could not download etcd from ${url}"
            exit 1
        fi
        ETCD="$ETCD_DIR/etcd"
        ETCDCTL="$ETCD_DIR/etcdctl"
    fi
    [[ -n "${ETCDCTL:-}" && -x "${ETCDCTL:-}" ]] || ETCDCTL=""
    if [[ ! -x "$ETCD" ]]; then
        tc_log_error "etcd binary missing at $ETCD"
        exit 1
    fi
    tc_log_pass "etcd binary: $ETCD"
}

# tc_start_etcd [name] [data_dir] — stop any leftover etcd, then start a fresh
# single-node instance on $ETCD_ENDPOINT and wait (≤30s) for health. Sets
# ETCD_PID. Returns 1 if etcd never became healthy (callers run under set -e).
tc_start_etcd() {
    local name="${1:-sandswap-e2e}"
    local data_dir="${2:-/tmp/sandswap-e2e-etcd-data}"
    # The etcd-only rows (ownership, dns-staleness, staleness-*) reach this
    # directly without tc_clean_environment, so the service identities the
    # data-dir chown needs may not exist yet on a freshly provisioned host.
    # Ensuring them here is idempotent (getent lookups once the accounts
    # exist) and keeps the rows host-state independent.
    ss_ensure_service_users
    tc_kill_etcd
    rm -rf "$data_dir"
    mkdir -p "$data_dir"
    chown root:"$SS_SERVICE_GROUP" "$data_dir"
    chmod 770 "$data_dir"
    tc_log_step "Starting etcd ($name, data=$data_dir, endpoint=$ETCD_ENDPOINT, user=sandserv)..."
    ss_service_exec etcd -- "$ETCD" \
        --name "$name" \
        --data-dir "$data_dir" \
        --listen-client-urls "$ETCD_ENDPOINT" \
        --advertise-client-urls "$ETCD_ENDPOINT" \
        --listen-peer-urls http://127.0.0.1:2380 \
        --initial-advertise-peer-urls http://127.0.0.1:2380 \
        --initial-cluster "$name=http://127.0.0.1:2380" \
        --log-level error &
    ETCD_PID=$!
    local i
    for i in $(seq 1 60); do
        if tc_etcd_ready; then
            tc_log_pass "etcd started (PID=$ETCD_PID)"
            return 0
        fi
        if ! kill -0 "$ETCD_PID" 2>/dev/null; then
            tc_log_error "etcd process died during startup"
            return 1
        fi
        sleep 0.5
    done
    tc_log_error "etcd did not become healthy within 30s"
    return 1
}

# tc_cleanup_etcd [data_dir] — stop the script's etcd and free the ports.
tc_cleanup_etcd() {
    local data_dir="${1:-}"
    if [[ -n "${ETCD_PID:-}" ]]; then
        kill "$ETCD_PID" 2>/dev/null || true
        wait "$ETCD_PID" 2>/dev/null || true
    fi
    # Belt-and-braces: force-stop any etcd still holding 2379/2380 (a
    # SIGTERM'd etcd can lag past this trap; the next script must be able to bind).
    tc_kill_etcd
    [[ -n "$data_dir" ]] && rm -rf "$data_dir" 2>/dev/null || true
}

# Aliases
use_output_binaries()  { tc_use_output_binaries "$@"; }
install_flat_template(){ tc_install_flat_template "$@"; }
gw_exec()              { tc_gw_exec "$@"; }
gw_exec_retry()        { tc_gw_exec_retry "$@"; }
gw_exec_headers()      { tc_gw_exec_headers "$@"; }
gw_exec_raw()          { tc_gw_exec_raw "$@"; }
json_stdout()          { tc_json_stdout "$@"; }
run_go_suite()         { tc_run_go_suite "$@"; }
backup_host_files()    { tc_backup_host_files "$@"; }
restore_host_files()   { tc_restore_host_files "$@"; }
pre_clean_stack()      { tc_pre_clean_stack "$@"; }
gw_status()            { tc_gw_status "$@"; }
gw_kill()              { tc_gw_kill "$@"; }
http_code_of()         { tc_http_code_of "$@"; }
body_of()              { tc_body_of "$@"; }
json_field()           { tc_json_field "$@"; }
stats_clean_vms()      { tc_stats_clean_vms "$@"; }
clean_vms()            { tc_stats_clean_vms "$@"; }
ensure_etcd()          { tc_ensure_etcd "$@"; }
etcd_ready()           { tc_etcd_ready "$@"; }
start_etcd()           { tc_start_etcd "$@"; }
cleanup_etcd()         { tc_cleanup_etcd "$@"; }

# ═══════════════════════════════════════════════════════════════════════
# 10. Cleanup
# ═══════════════════════════════════════════════════════════════════════

# tc_kill_port <port>... — SIGKILL every process LISTENing on the given TCP
# ports (implementation: ss_kill_ports in common/sh/runtime.sh).
tc_kill_port() { ss_kill_ports "$@"; }

# tc_kill_etcd — stop any etcd still holding the coordination ports and wait
# until they are free. Implementation: ss_kill_etcd (common/sh/runtime.sh),
# shared with the deploy tree and the matrix engine.
tc_kill_etcd() { ss_kill_etcd "$@"; }

# tc_cleanup_default — standard cleanup based on deploy-and-test.sh pattern:
# kill gateway/sandlot PIDs → wait → kill_sandswap_procs → teardown_host_network
# → detach vsockguard → unmount overlays → remove runtime dirs.
# Scripts can define their own cleanup() that calls this first, then adds
# script-specific cleanup (e.g., removing temp template dirs, killing extra
# processes like the OCI registry).
tc_cleanup_default() {
    tc_log_section "Shutdown"
    kill ${GATEWAY_PID:-} 2>/dev/null || true
    kill ${SANDLOT_PID:-} 2>/dev/null || true
    wait ${GATEWAY_PID:-} 2>/dev/null || true
    wait ${SANDLOT_PID:-} 2>/dev/null || true
    # Kill ALL residual sandswap processes by exact name (no dirty state)
    tc_kill_sandswap_procs "trap-cleanup"
    # Stop any etcd still holding the coordination ports.
    tc_kill_etcd
    # Remove leftover TAPs + the nftables NAT table (host network resources).
    # tc_teardown_host_network also drops sandlot's egress nft tables (baseline
    # + routed-ipv6 stamping) via tc_pre_clean_stack — no other teardown
    # removes those, and a stale baseline table would let the NEXT run's
    # presence assertions pass against THIS run's leftovers.
    tc_teardown_host_network
    # Detach vsockguard if this run attached it (best-effort).
    tc_detach_vsockguard
    # Unmount overlay mounts under VOL_ROOT before rm -rf (same reason as
    # tc_clean_environment: stale mounts reference deleted paths otherwise).
    tc_unmount_overlays_under "$VOL_ROOT"
    # Remove runtime state and volumes so the host is clean after test exit.
    # $DEPLOY_DIR is intentionally NOT removed — deployed binaries are reusable
    # and expensive to copy. $LOG_DIR IS removed so the next test starts clean.
    #
    # KEEP_LOGS=1 preserves $LOG_DIR (component logs) for post-mortem — a
    # 503/failure burst in a self-cleaning benchmark otherwise deletes its own
    # evidence (a pidfd reaper-race root cause stays hidden for several
    # runs without it). Every VM has two log files under /run/sandswap/vm/<id>/:
    #   serial.log  — earlyprintk (earliest boot/panic)
    #   console.log — hvc0: kernel log-buffer replay, later printk, warden logs
    # Copy both out when KEEP_LOGS is set, before /run/sandswap is removed.
    if [[ "${KEEP_LOGS:-0}" == "1" ]]; then
        local kept=0
        mkdir -p "$LOG_DIR/serial" "$LOG_DIR/console"
        for f in /run/sandswap/vm/*/serial.log; do
            [[ -f "$f" ]] || continue
            kept=$((kept+1))
            cp -f "$f" "$LOG_DIR/serial/vm-$kept-$(basename "$(dirname "$f")").log" 2>/dev/null || true
        done
        for f in /run/sandswap/vm/*/console.log; do
            [[ -f "$f" ]] || continue
            kept=$((kept+1))
            cp -f "$f" "$LOG_DIR/console/vm-$kept-$(basename "$(dirname "$f")").log" 2>/dev/null || true
        done
        rm -rf "$VOL_ROOT" /run/sandswap 2>/dev/null || true
        tc_log_pass "KEEP_LOGS=1: logs + $kept guest log files (serial+console) kept in $LOG_DIR"
    else
        rm -rf "$VOL_ROOT" /run/sandswap "$LOG_DIR" 2>/dev/null || true
    fi
    echo "All processes stopped."
}

# Alias
cleanup_default() { tc_cleanup_default "$@"; }

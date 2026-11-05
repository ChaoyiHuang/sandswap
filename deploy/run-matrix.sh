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
# run-matrix.sh — the DEPLOY SCRIPT MATRIX: every *.sh under deploy/ gets
# exactly one recorded row (PASS / FAIL / SKIP / BLOCKED-PRODUCT) with its
# reason, wall time, log path and closure hash.
#
# The engine (enumeration + self-check, checkpoint, sweep, closure hash,
# verdict vocabulary, report) lives in common/sh/matrix.sh and is shared with
# e2e/run-matrix.sh. THIS file declares only what is deploy-specific: the
# classification table, the phases, the fixture deploys and the preconditions.
# The two runners are INDEPENDENT — either may be run alone.
#
# Classes:
#   C  self-contained (host prep, generators, cleanup/uninstall, the
#      simulation rehearsals and the multi-node drills that build their own
#      stacks)
#   B  verifies a DEPLOYED stack — the phase deploys one (one-machine-etcd:
#      exec gateway :3000/:9998 + human gateway :3100/:9996 + etcd + an
#      exec/prov sandlot pair), runs the verifiers, then uninstalls
#   K  needs a k3s cluster — the phase installs k3s, runs the leg, verifies,
#      cleans up and uninstalls k3s at the end (clean-machine rule)
#   H  heavy deploys (install services, start them, then uninstall)
#   E  multi-host only — exercised through its --dry-run/validation path
#   F  library (not independently runnable) — valid only when a named
#      consumer has a verdict
#
# Usage:
#   sudo bash deploy/run-matrix.sh --phase C|E|B|K|H|all
#   sudo bash deploy/run-matrix.sh --only 'deploy/baremetal/verify-*' [--force]
#   sudo bash deploy/run-matrix.sh --report | --list
# Env: MATRIX_K8S_LEGS="embedded boxout egress-enabler" (targeted re-run)

set -uo pipefail

ROOT="${ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
# shellcheck disable=SC1091
source "$ROOT/deploy/baremetal/common.sh"
# deploy-lib.sh defines bm_build_artifacts (the preflight's one-shot build
# gate below); common.sh alone does not carry it.
# shellcheck disable=SC1091
source "$ROOT/deploy/baremetal/deploy-lib.sh"

MATRIX_TREE="deploy"
MATRIX_ENUM_ROOT="deploy"
MATRIX_STATE_DIR="${MATRIX_STATE_DIR:-/var/tmp/r3-matrix/deploy}"

# What a deploy verdict depends on — derived from what the rows actually pick
# up (grep every source edge, not a hand-kept list):
#   - the bare-metal/k8s libraries + the shared layers
#   - E2E/COMMON.SH: six rows source the e2e tree's harness directly
#     (verify-cert-rotation, verify-etcd-fence, verify-negative-path,
#     deploy-k8s-embedded, deploy-k8s-boxout, verify-k8s), which is also how
#     deploy/gen-certs.sh and the gen-certs workflow reach them
#   - the ENGINE (common/sh/matrix.sh: verdict vocabulary, reuse policy,
#     closure hashing) and this runner itself (the spec, the phases, the
#     rotation chain, the consumer map) — neither is enumerated, so editing
#     them must invalidate the rows they judged
MATRIX_CLOSURE_FILES=(
    common/sh/runtime.sh common/sh/stack.sh common/sh/matrix.sh
    deploy/baremetal/common.sh deploy/baremetal/deploy-lib.sh
    deploy/k8s/deploy-lib.sh deploy/gen-certs.sh
    e2e/common.sh
    deploy/run-matrix.sh
)

# Build artifacts a row's verdict is evidence about (see the engine's
# matrix_artifact_identity). Any rebuild invalidates reuse; a script edit
# alone does not. Entries must be REAL build outputs with stable presence —
# a missing name or a deploy-staged file that flaps between rounds (the old
# output/etcd entry) silently defeats reuse. The kernel config sidecars are
# vmlinux.bin.config / vmlinux.bin.config-rev (NOT vmlinux.config*).
MATRIX_ARTIFACTS=(
    output/vmlinux.bin output/vmlinux.bin.config-rev output/vmlinux.bin.config
    output/initramfs.cpio.gz
    output/sandvmm output/warden output/warden-probe
    output/gateway output/sandlot output/boxout output/sandns output/sandctl
    output/template-tool output/loadgen output/scalepopulator
    output/vsockguard.bpf.o output/vsockguardctl
    output/eino-sandswap output/openai-sandswap output/keepalive-sandswap
    output/rootfs-template output/rootfs-ubuntu
)

# path|class|timeout|cleanup_after|note|args
MATRIX_SPEC=(
    # ── deploy/baremetal ──
    "deploy/baremetal/cleanup.sh|C|600|-|"
    "deploy/baremetal/deploy-cluster-multi-gw-simulation.sh|H|2700|deploy/baremetal/cleanup.sh|"
    "deploy/baremetal/deploy-cluster-multi-gw.sh|E|900|-|multi-host only: --dry-run + config validation|--dry-run --config deploy/baremetal/cluster-production.sample.yaml"
    "deploy/baremetal/deploy-cluster-one-gw-simulation.sh|H|2700|deploy/baremetal/cleanup.sh|"
    "deploy/baremetal/deploy-cluster-one-gw.sh|H|1800|deploy/baremetal/uninstall.sh|single-box rehearsal: the loopback config prepares the stage + installs all roles|--config deploy/baremetal/cluster-one-gw-local.sample.yaml"
    "deploy/baremetal/deploy-egress-enabler.sh|C|900|-|"
    "deploy/baremetal/deploy-one-machine-etcd.sh|H|1800|deploy/baremetal/uninstall.sh|phase B's fixture + its own row"
    "deploy/baremetal/deploy-single-node.sh|H|1800|deploy/baremetal/uninstall.sh|"
    "deploy/baremetal/gen-baremetal-certs.sh|C|300|-|"
    "deploy/baremetal/rotate-volume-seed.sh|B|1800|-|stateful CLI chain — driven by phase B||stack:3100"
    "deploy/baremetal/sandswap-apply-prov-ownership.sh|C|300|-|"
    "deploy/baremetal/sandswap-ops.sh|B|900|-|operates a DEPLOYED stack|status|stack:3100"
    "deploy/baremetal/setup-host.sh|C|900|-|host prep for the merged shape|--role all"
    "deploy/baremetal/uninstall.sh|C|600|-|"
    "deploy/baremetal/verify-binpack.sh|C|2700|-|"
    "deploy/baremetal/verify-cert-rotation.sh|B|2700|-|needs a deployed stack||stack:3100"
    "deploy/baremetal/verify-eino.sh|B|1800|-|needs a deployed stack + LLM key||stack:3100,3000"
    "deploy/baremetal/verify-etcd-fence.sh|B|1800|-|needs a deployed stack||stack:3100,2379"
    "deploy/baremetal/verify-failover.sh|C|2700|-|"
    "deploy/baremetal/verify-negative-path.sh|B|1800|-|needs a deployed stack||stack:3100"
    # ── deploy (shared) ──
    "deploy/gen-certs.sh|C|300|-|"
    "deploy/setup-network.sh|C|300|-|"
    # ── deploy/k8s ──
    # build-images runs BUILD-ONLY here: the C phase owns no k3s fixture, and
    # the import path is genuinely exercised (and asserted) by the K-phase
    # deployers, which start k3s themselves and deploy from the imported
    # images. A state-dependent import in this row made its verdict hinge on
    # which rows ran before it across rounds.
    "deploy/k8s/build-images.sh|C|1800|-|needs docker; build only (k3s import exercised by the K-phase deployers)|--no-import|extra:deploy/k8s/images"
    "deploy/k8s/deploy-k8s-boxout.sh|K|3600|deploy/k8s/k8s-cleanup.sh|||extra:deploy/k8s/images"
    "deploy/k8s/deploy-k8s-egress-enabler.sh|K|3600|deploy/k8s/k8s-cleanup.sh|||extra:deploy/k8s/images"
    "deploy/k8s/deploy-k8s-embedded.sh|K|3600|deploy/k8s/k8s-cleanup.sh|||extra:deploy/k8s/images"
    "deploy/k8s/gen-k8s-certs.sh|C|300|-|"
    "deploy/k8s/k8s-cleanup.sh|C|900|-|"
    "deploy/k8s/k8s-host-setup.sh|C|900|-|"
    "deploy/k8s/verify-k8s.sh|K|1800|-|needs k3s (scheduled by phase K)||extra:deploy/k8s/images"
    # ── libraries ──
    "deploy/baremetal/common.sh|F|0|-|library"
    "deploy/baremetal/deploy-lib.sh|F|0|-|library"
    "deploy/k8s/deploy-lib.sh|F|0|-|library"
    "deploy/k8s/images/boxout-entrypoint.sh|F|0|-|container entrypoint (boxout image)"
    "deploy/k8s/images/sandlot-entrypoint.sh|F|0|-|container entrypoint (sandlot images)"
    "deploy/run-matrix.sh|F|0|-|this file"
)

MATRIX_LIB_CONSUMERS=(
    "deploy/baremetal/common.sh:deploy/baremetal/sandswap-ops.sh deploy/baremetal/deploy-single-node.sh"
    "deploy/baremetal/deploy-lib.sh:deploy/baremetal/verify-failover.sh deploy/baremetal/verify-binpack.sh"
    "deploy/k8s/deploy-lib.sh:deploy/k8s/deploy-k8s-embedded.sh"
    "deploy/run-matrix.sh:deploy/baremetal/deploy-single-node.sh deploy/k8s/deploy-k8s-embedded.sh"
    "deploy/k8s/images/boxout-entrypoint.sh:deploy/k8s/deploy-k8s-boxout.sh deploy/k8s/deploy-k8s-egress-enabler.sh"
    "deploy/k8s/images/sandlot-entrypoint.sh:deploy/k8s/deploy-k8s-embedded.sh deploy/k8s/deploy-k8s-boxout.sh deploy/k8s/deploy-k8s-egress-enabler.sh"
)

# Final cleanup for a COMPLETE pass: sweep units/processes/TAPs, remove the
# sandswap namespace if one survived, the sandbox bridge, nft table and run
# dirs. Residue after this fails the gate (the engine verifies it).
matrix_final_cleanup() {
    env_sweep
    if command -v kubectl >/dev/null 2>&1 && kubectl get namespace sandswap >/dev/null 2>&1; then
        timeout 300 bash "$ROOT/deploy/k8s/k8s-cleanup.sh" >/dev/null 2>&1 || true
    fi
    if declare -F ss_host_network_teardown >/dev/null 2>&1; then
        ss_host_network_teardown
    fi
    rm -rf /run/sandswap /run/sandswap-state /run/sandswap-boxout 2>/dev/null || true
    ip link del br-sandswap 2>/dev/null || true
}

# ── deploy tree hooks ────────────────────────────────────────────────
matrix_preflight() {
    matrix_host_tools_preflight || exit 1
    # Tree-native checks only: `tc_check_root`/`tc_check_kvm` are e2e-tree
    # helpers, and the deploy tree must not depend on the e2e tree.
    if [[ "$(id -u)" -ne 0 ]]; then
        tc_log_error "this runner requires root"
        exit 1
    fi
    tc_log_pass "Running as root"
    sandswap_check_kvm
    tc_check_artifacts
    # Freshness is established ONCE for the whole pass (check, one rebuild
    # if genuinely stale — BEFORE any verdict is recorded); rows then see
    # SANDSWAP_ROUND_FRESH=1 and skip their per-row build gates, so no row
    # can auto-rebuild the shared set mid-pass and re-stamp every artifact
    # under the recorded verdicts.
    bm_build_artifacts
    export SANDSWAP_ROUND_FRESH=1
}

# Host state a row needs but does not create itself.
matrix_row_precondition() {
    case "$1" in
        deploy/baremetal/deploy-cluster-one-gw.sh)
            # The staged cluster config mounts a LOOPBACK NFS export for
            # shared storage. ss_storage_nfs_setup IS the installer
            # (nfs-kernel-server + nfs-common) and always writes the ROOT
            # export — NFSv4 serves a non-exported parent as a READ-ONLY
            # pseudo-fs node, so the row's first mkdir would fail "Read-only
            # file system". A setup failure is a PREREQUISITE failure.
            tc_log_info "precondition: provisioning the loopback NFS export"
            ss_storage_nfs_setup >/dev/null 2>&1 || {
                tc_log_error "precondition: loopback NFS export setup failed (nfs-kernel-server/nfs-common)"
                return 1
            }
            ;;
    esac
}

# The battery's external-dependency gate: a row whose tool is missing records
# a visible SKIP instead of a FAIL (same contract as the e2e runner's llm/
# docker gates). The k8s deployers bootstrap an INSTALLED-but-stopped daemon
# themselves, so only the standalone image builder gates here.
matrix_row_gate() {
    local need_llm=0 need_docker=0
    case "$1" in
        deploy/baremetal/verify-binpack.sh|deploy/baremetal/verify-eino.sh|deploy/k8s/verify-k8s.sh)
            # These rows drive real eino agents; without an LLM key they are
            # an EXTERNAL-DEPENDENCY SKIP, not a product FAIL — same rule as
            # the e2e tree's needs-llm-key rows. The k8s deployers need the
            # key only for their --verify drill, which the matrix never runs.
            need_llm=1 ;;
    esac
    case "$1" in
        deploy/k8s/build-images.sh|deploy/k8s/deploy-k8s-embedded.sh|deploy/k8s/deploy-k8s-boxout.sh|deploy/k8s/deploy-k8s-egress-enabler.sh|deploy/k8s/verify-k8s.sh)
            # Every K leg builds (or imports) container images; without a
            # docker daemon the row is an EXTERNAL-DEPENDENCY SKIP, not a
            # product FAIL. k3s is separate (the deployers install it).
            need_docker=1 ;;
    esac
    if (( need_llm )) && [[ -z "${DEEPSEEK_API_KEY:-}" && -z "${OPENAI_API_KEY:-}" && -z "${GOOGLE_API_KEY:-}" ]]; then
        echo "needs-llm-key"
        return 10
    fi
    if (( need_docker )) && ! command -v docker >/dev/null 2>&1; then
        echo "needs-docker"
        return 10
    fi
    return 0
}

# Known product refusals (developer guide §5): match the EXACT refusal text —
# a different message is a real failure. The boxout host prep refuses a
# bare-metal sandlot uid on a combined development host (the reserved-uid
# scheme binds the boxout fence); the k8s legs themselves are unaffected —
# they deliver stream certs via the certs-copy initContainer, not the host
# account (proven by the boxout leg passing with the account at 985).
matrix_row_classify() {
    case "$1" in
        deploy/k8s/k8s-host-setup.sh)
            if grep -q "the boxout manifests and vsockguard pin the reserved sandbox uid 65536" "$3" 2>/dev/null; then
                echo "boxout uid pin: host sandlot uid=$(id -u sandlot 2>/dev/null || echo absent) != 65536 (combined dev host; k8s legs unaffected)"
                return 0
            fi ;;
    esac
    return 1
}

# ── Phase B: the deployed-stack verifiers ────────────────────────────
# The B rows verify an OPERATOR-DEPLOYED stack. This phase stands that stack
# up itself (one-machine-etcd), keeps it running for the verifiers, and
# uninstalls it at the end — so the phase is self-contained and the host is
# left clean whether the rows pass or fail.
matrix_phase_B() {
    tc_log_section "PHASE B ($MATRIX_TREE) — one-machine-etcd fixture"
    # --only X must not stand up (or tear down) the fixture unless X is one of
    # this phase's rows: a targeted re-run elsewhere in the tree was starting
    # the whole one-machine-etcd stack (and phase K's k3s legs) and hanging.
    if [[ -n "$ONLY" ]]; then
        local _e _p _c _sel=0
        for _e in "${MATRIX_SPEC[@]}"; do
            IFS='|' read -r _p _c _ <<<"$_e"
            [[ "$_c" == "B" || "$_p" == "deploy/baremetal/deploy-one-machine-etcd.sh" ]] || continue
            [[ "$_p" == $ONLY ]] && _sel=1
        done
        if (( _sel == 0 )); then
            tc_log_info "phase B: --only '$ONLY' selects no B row — skipping the fixture"
            return 0
        fi
    fi
    local busy
    busy="$(ss -tlnH 2>/dev/null | awk '{print $4}' | grep -oE ':(3000|3100|9996|9998|2379)$' | sort -u | tr '\n' ' ')"
    if [[ -n "${busy// /}" ]]; then
        tc_log_warn "phase B: coordination ports already held ($busy) — sweeping"
        env_sweep
    fi
    # Fixture mode starts BEFORE the deployer row: its own post-row residue
    # check would otherwise see the freshly started units as "residue" and
    # sweep them away (the deployer reports a healthy stack
    # and the sweep kills it before the first verifier reads /health).
    MATRIX_FIXTURE=1
    if ! run_row_once deploy/baremetal/deploy-one-machine-etcd.sh "-"; then
        tc_log_error "phase B: the deployer did not come up — every B row records SKIP(needs-deployed-stack)"
        MATRIX_FIXTURE=0
        return 1
    fi
    # Cheap, non-destructive verifiers first; the cert-rotation drill LAST
    # because it replaces the stack's TLS material.
    local row
    for row in deploy/baremetal/verify-negative-path.sh \
               deploy/baremetal/verify-etcd-fence.sh \
               deploy/baremetal/verify-eino.sh \
               deploy/baremetal/verify-cert-rotation.sh \
               deploy/baremetal/sandswap-ops.sh; do
        [[ -n "$ONLY" && "$row" != $ONLY ]] && continue
        [[ "$row" == "deploy/baremetal/sandswap-ops.sh" ]] && run_row_once "$row" "-" status && continue
        run_row_once "$row" "-"
    done
    # The seed-rotation CLI needs a live prov config + volumes tree.
    if [[ -z "$ONLY" || "deploy/baremetal/rotate-volume-seed.sh" == $ONLY ]]; then
        run_rotation_chain
    fi

    tc_log_section "PHASE B — tear the fixture down"
    MATRIX_FIXTURE=0
    ( cd "$ROOT" && timeout --signal=TERM --kill-after=30 900 bash deploy/baremetal/uninstall.sh ) \
        >"$LOGS_DIR/phaseB-uninstall.log" 2>&1 || tc_log_warn "phase B uninstall returned non-zero (see phaseB-uninstall.log)"
    env_sweep
    local residue; residue="$(env_residue)"
    [[ -n "$residue" ]] && tc_log_warn "phase B left residue: $residue"
    return 0
}

# run_rotation_chain — the seed-rotation CLI is a STATEFUL sequence
# (maintenance on → stage → run → promote → maintenance off), not a bare
# invocation: running it argument-less proves nothing. All five legs must pass
# for the row to be PASS; the row's log carries every leg.
run_rotation_chain() {
    local path="deploy/baremetal/rotate-volume-seed.sh"
    local prov_cfg="/etc/sandswap/sandlot-prov.yaml"
    local legs=( "--maintenance on" "--stage" "--run" "--promote" "--maintenance off" )
    local leg rc_all=0 out slug log
    slug="$(echo "$path" | tr '/' '_' | sed 's/\.sh$//')"
    log="$LOGS_DIR/$slug.log"
    tc_log_section "RUN [B] $path (rotation chain: ${#legs[@]} legs)"
    for leg in "${legs[@]}"; do
        # shellcheck disable=SC2086
        out="$( cd "$ROOT" && timeout --signal=TERM --kill-after=30 600 bash "$path" \
                 --prov-config "$prov_cfg" --human-url https://localhost:3100 \
                 --template-tool "$ROOT/output/template-tool" $leg 2>&1 )"
        local rc=$?
        printf '── leg: %s (rc=%s) ──\n%s\n' "$leg" "$rc" "$out" >>"$log"
        if [[ $rc -ne 0 ]]; then
            tc_log_error "rotation leg '$leg' failed (rc=$rc)"
            rc_all=$rc
        else
            tc_log_info "rotation leg '$leg' ok"
        fi
    done
    local verdict=PASS reason=""
    [[ $rc_all -ne 0 ]] && { verdict=FAIL; reason="rotation chain leg failed (see log)"; }
    state_set "$path" B "$verdict" 0 "$rc_all" "$(closure_hash "$path")" "$reason" "$log" "" "matrix"
    if [[ "$verdict" == PASS ]]; then
        tc_log_pass "$path PASS (rotation chain green)"; return 0
    fi
    tc_log_error "$path FAIL ($reason)"; return 1
}

# ── Phase K: the k3s legs ────────────────────────────────────────────
# Per leg: deploy(keep) → verify-k8s → k8s-cleanup. A leg that tears its own
# deployment down (egress-enabler's drill ends with a "zero residue" cleanup)
# gets no verifier row — it verified itself. k3s is installed by the deploy
# leg and uninstalled once at the end (clean-machine rule).
matrix_phase_K() {
    tc_log_section "PHASE K ($MATRIX_TREE) — k3s legs (embedded → boxout → egress)"
    # Same rule as phase B: a --only run elsewhere must not deploy/verify the
    # k3s legs.
    if [[ -n "$ONLY" ]]; then
        local _e _p _c _sel=0
        for _e in "${MATRIX_SPEC[@]}"; do
            IFS='|' read -r _p _c _ <<<"$_e"
            [[ "$_c" == "K" ]] || continue
            [[ "$_p" == $ONLY ]] && _sel=1
        done
        if (( _sel == 0 )); then
            tc_log_info "phase K: --only '$ONLY' selects no K row — skipping the k3s legs"
            return 0
        fi
    fi
    local leg script keeps
    # shellcheck disable=SC2086
    for leg in ${MATRIX_K8S_LEGS:-embedded boxout egress-enabler}; do
        script="deploy/k8s/deploy-k8s-${leg}.sh"
        if [[ -n "$ONLY" && "$script" != $ONLY && "deploy/k8s/verify-k8s.sh" != $ONLY ]]; then
            continue
        fi
        keeps=1
        [[ "$leg" == "egress-enabler" ]] && keeps=0
        tc_log_section "PHASE K — leg $leg"
        # Fixture mode spans the whole leg: the deployer's post-row sweep would
        # destroy the cluster it just created.
        MATRIX_FIXTURE=1
        run_row_once "$script" "-"
        local leg_rc=$?
        if (( leg_rc == 0 )); then
            if [[ "$keeps" == "1" ]]; then
                run_row_once deploy/k8s/verify-k8s.sh "-"
            else
                tc_log_info "leg $leg verifies itself (its own drill ends with a full cleanup) — no verify-k8s row"
            fi
        elif (( leg_rc == 2 )); then
            # Gate SKIP (missing docker): the row recorded SKIP; do not
            # misreport it as a deploy failure or verify against nothing.
            tc_log_warn "leg $leg SKIPPED by a row gate — not deploying"
        else
            tc_log_warn "leg $leg did not deploy — not running verify-k8s against it"
        fi
        tc_log_info "cleaning up leg $leg"
        MATRIX_FIXTURE=0
        ( cd "$ROOT" && timeout --signal=TERM --kill-after=30 900 bash deploy/k8s/k8s-cleanup.sh ) \
            >"$LOGS_DIR/phaseK-cleanup-$leg.log" 2>&1 || tc_log_warn "k8s-cleanup for $leg returned non-zero"
    done
    if [[ -x /usr/local/bin/k3s-uninstall.sh ]]; then
        tc_log_info "uninstalling k3s (clean dev machine)"
        timeout --signal=TERM --kill-after=30 600 /usr/local/bin/k3s-uninstall.sh \
            >"$LOGS_DIR/phaseK-k3s-uninstall.log" 2>&1 || tc_log_warn "k3s-uninstall returned non-zero"
    fi
    return 0
}

# Phase order for "all": the cheap self-contained rows, the dry-run validation
# path, then the fixture phases (B, K) and finally the heavy deploys.
matrix_default_phases() { echo "C E B K H"; }

# ── Engine ───────────────────────────────────────────────────────────
# Sourced LAST: it asserts MATRIX_TREE/MATRIX_ENUM_ROOT and reads the spec,
# the closure list and the consumer map declared above.
# shellcheck disable=SC1091
source "$ROOT/common/sh/matrix.sh"

matrix_main "$@"

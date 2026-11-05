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
# vmm-seccomp.sh — the seccomp-enforcement gate: prove the sandvmm per-thread seccomp
# allow-lists are complete enough to ENFORCE before flipping the default
# (microvm.vmm_seccomp log → true). Two phases, one battery:
#
#   PHASE 1 (audit-clean): run the representative VM battery with
#     microvm.vmm_seccomp=log and assert the kernel log shows ZERO
#     SECCOMP_RET_LOG hits from the sandvmm process — every allow-list gap
#     is visible there as "audit" lines naming the trapped syscall+thread.
#     A non-empty gap list FAILS: enforcement would SIGSYS those threads.
#
#   PHASE 2 (enforce-green): re-run the same battery with
#     microvm.vmm_seccomp=true and assert every op succeeds (no thread
#     death, no VM destroy churn).
#
# Only when BOTH pass is the default flip (launcher.go seccompModeOr +
# config validation) allowed. The filter audit's trapped set
# (chmod/chown, umask(0), getrandom/tgkill, readlinkat — root-caused to
# virtio_fs_thread_rules gaps, fixed with pin tests in
# vmm/virtio-devices/src/seccomp_filters.rs) is exactly what phase 1
# would have caught before any thread died.
#
# Usage: bash e2e/vmm-seccomp.sh   (needs root + /dev/kvm + built output/)
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck disable=SC1091
source "$ROOT/e2e/common.sh"

# Clean-host precondition: every environment-owning script starts from a
# clean host. Leftovers from a DEAD previous run are killed here; a
# CONCURRENT harness run is refused by name (ss_harness_guard), never killed.
tc_clean_environment

log_step "vmm-seccomp: PHASE 1 — audit-clean (log mode, zero RET_LOG hits)"

# The battery drives every host-side syscall surface the FUSE server uses:
# boot, cold mount+exec, file ops incl. chmod/chown-bearing paths (write with
# mode, mkdir), stat/list, unmount/switch, vsock probes.
#
# The seccomp mode is a YAML key (microvm.vmm_seccomp) — the sandlot has no
# CLI flag for it, so the battery runs the deployed sandlot in CONFIG-FILE
# mode with the key injected into the harness-generated config. (Passing a
# nonexistent -vmm-seccomp flag kills the sandlot at the usage dump and makes
# both phases VACUOUS: no VM ever runs, phase 1 sees zero hits, phase 2 has
# nothing to break — a green gate over a stack that never came up. smoke's
# exit status is therefore part of each phase's verdict.)
run_battery() { # <mode> — runs the battery; non-zero when the battery failed
    local mode="$1"
    # NOT under $LOG_DIR: smoke's deploy wipes it mid-run. /tmp/sandswap-* is
    # not in the sweep set.
    local cfg; cfg="$(mktemp /tmp/sandswap-vmmseccomp-${mode}.XXXXXX.yaml)"
    # tc_gen_sandlot_config references CERT_DIR (the tls: block); the harness
    # sets it during the deploy's cert step — we generate BEFORE that, so
    # provide the same default here (tc_gen_certs line ~541). Under set -u an
    # unset CERT_DIR kills the generator mid-heredoc and the sandlot then
    # parses an EMPTY file ("EOF").
    CERT_DIR="${CERT_DIR:-$DEPLOY_DIR/certs}"
    tc_gen_sandlot_config "$cfg"
    sed -i "s/^microvm:\$/microvm:\n  vmm_seccomp: \"$mode\"/" "$cfg"
    chmod 0644 "$cfg"   # the sandlot reads it as uid 985 (mktemp is 0600 root)
    TC_SANDLOT_CONFIG="$cfg" bash "$ROOT/e2e/smoke.sh"
    local rc=$?
    rm -f "$cfg"
    return "$rc"
}

collect_ret_log_hits() {
    # SECCOMP_RET_LOG surfaces as audit type=1326 records (the text form does
    # NOT always contain the word "seccomp" — grep for the type or it silently
    # matches nothing and the gate false-greens). Prefer the journal; fall
    # back to dmesg when journald is absent. The "SECCOMP" keyword form is
    # matched too (kernels configured without audit print that spelling).
    # The window is anchored at PHASE1_SINCE_EPOCH (taken just before the
    # battery), NOT a relative -10min: a fixed window sweeps in the PREVIOUS
    # suite run's traps and fails this run on someone else's gaps. The dmesg
    # fallback (journald absent) cannot filter by time — best-effort there.
    local raw
    if command -v journalctl >/dev/null 2>&1; then
        raw="$(journalctl -k --since "@${PHASE1_SINCE_EPOCH:?PHASE1_SINCE_EPOCH not set}" 2>/dev/null)"
    else
        raw="$(dmesg 2>/dev/null)"
    fi
    printf '%s\n' "$raw" | grep -E "type=1326|SECCOMP" | grep -v "filter deployment" || true
}

# Anchor the audit window at the battery start (see collect_ret_log_hits):
# everything type=1326 BEFORE this instant belongs to another suite run.
PHASE1_SINCE_EPOCH="$(date +%s)"
run_battery "log" || { tc_log_error "PHASE 1 FAILED: the battery itself failed (log mode) — a vacuous zero-hit reading proves nothing"; exit 1; }
hits="$(collect_ret_log_hits)"
if [[ -n "$hits" ]]; then
    tc_log_error "PHASE 1 FAILED: allow-list gaps remain (enforce mode would SIGSYS these):"
    echo "$hits" | head -40
    exit 1
fi
log_step "vmm-seccomp: PHASE 1 clean — no RET_LOG hits across the battery"

log_step "vmm-seccomp: PHASE 2 — enforce-green (true mode, battery must pass)"
run_battery "true" || { tc_log_error "PHASE 2 FAILED: the battery failed under enforce mode"; exit 1; }
log_step "vmm-seccomp: BOTH PHASES GREEN — the microvm.vmm_seccomp default flip (log→true) is now unblocked (sandlot/vmm/launcher.go seccompModeOr + config validation, same commit as docs)"
exit 0

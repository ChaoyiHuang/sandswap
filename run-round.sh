#!/bin/bash
# Copyright 2026 Chaoyang Huang. All rights reserved.
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
# run-round.sh — one-command verification round: the e2e matrix, then the
# deploy matrix, with no flags to remember and no session to keep alive.
#
#   sudo bash run-round.sh            # full round (e2e + deploy)
#   sudo bash run-round.sh --fast     # e2e bench rows skipped
#
# Properties the round needs and this driver provides:
#   - SELF-DAEMONIZING: re-execs itself under nohup, so a foreground shell
#     timeout (or an agent's tool timeout) cannot kill the round mid-row.
#     ROUND_FOREGROUND=1 runs it attached for interactive debugging.
#   - DISK LOGS: one driver log + one log per tree, under
#     /var/tmp/sandswap-round/<stamp>/ — never /tmp (a tmpfs reboot clears it).
#   - RESUME: the matrices' checkpoints persist under /var/tmp/r3-matrix/;
#     after an interruption or a reboot, rerun the SAME command. Rows whose
#     closure and build-artifact identity are unchanged are reused; FAIL and
#     NOT-RUN rows re-execute. No row is ever silently re-greened.
#   - ONE EXIT CODE: the matrix gate (FAIL/NOT RUN) decides each tree's
#     status; the round fails if either tree fails.
#   - TRIAGE SUMMARY: FAIL rows with their reasons are printed at the end.
#
# Environment:
#   ROUND_TREES      trees to run, in order (default: "e2e deploy")
#   ROUND_FOREGROUND 1 = stay attached to the terminal
#   ROUND_LOG_DIR    override the round log directory
#   SANDSWAP_E2E_ROOT / MATRIX_STATE_DIR  honoured by the runners

set -uo pipefail

ROOT="${ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
# shellcheck disable=SC1091
source "$ROOT/e2e/common.sh"

TREES="${ROUND_TREES:-e2e deploy}"
STAMP="${ROUND_STAMP:-$(date -u +%Y%m%dT%H%M%SZ)}"
LOG_ROOT="${ROUND_LOG_DIR:-/var/tmp/sandswap-round/$STAMP}"

if [[ "${ROUND_FOREGROUND:-0}" != "1" && -z "${ROUND_CHILD:-}" ]]; then
    mkdir -p "$LOG_ROOT"
    # ROUND_STAMP carries THIS process's stamp into the re-exec'd child: the
    # child re-evaluates the stamp on its own clock, and a second-boundary
    # rollover between parent and child pointed the advertised log path at a
    # directory the child never wrote to.
    ROUND_CHILD=1 ROUND_STAMP="$STAMP" nohup bash "$0" "$@" >"$LOG_ROOT/driver.log" 2>&1 &
    echo "round started: pid=$! log=$LOG_ROOT/driver.log"
    echo "resume after an interruption or reboot: rerun this command (checkpoints persist)"
    exit 0
fi

mkdir -p "$LOG_ROOT"
printf 'boot_id=%s\nstarted=%s\ntrees=%s\n' \
    "$(cat /proc/sys/kernel/random/boot_id 2>/dev/null || echo unknown)" \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$TREES" > "$LOG_ROOT/round.env"

tc_log_section "ROUND $STAMP — trees: $TREES"
tc_log_info "logs: $LOG_ROOT"

[[ "$(id -u)" -eq 0 ]] || { tc_log_error "run-round.sh must run as root (KVM + host prep)"; exit 1; }

rc=0
for tree in $TREES; do
    case "$tree" in
        e2e)    runner="e2e/run-matrix.sh" ;;
        deploy) runner="deploy/run-matrix.sh" ;;
        *) tc_log_error "unknown tree '$tree' (ROUND_TREES: e2e deploy)"; rc=1; continue ;;
    esac
    tc_log_section "TREE $tree — $runner"
    tree_rc=0
    tree_args=()
    if [[ "$tree" == "e2e" ]]; then
        for a in "$@"; do
            [[ "$a" == "--fast" ]] && tree_args+=("$a")
        done
    fi
    bash "$ROOT/$runner" "${tree_args[@]}" >"$LOG_ROOT/$tree.log" 2>&1 || tree_rc=$?
    if (( tree_rc == 0 )); then
        tc_log_pass "tree $tree: gate PASS (log $LOG_ROOT/$tree.log)"
    else
        tc_log_error "tree $tree: gate FAIL rc=$tree_rc (log $LOG_ROOT/$tree.log)"
        rc=1
    fi
done

# Triage summary — FAIL rows and their reasons from each tree's last report.
python3 - "$LOG_ROOT" <<'ROUND_SUMMARY_PY'
import json, os, sys

log_root = sys.argv[1]
for tree in ("e2e", "deploy"):
    last = os.path.join("/var/tmp/r3-matrix", tree, "last-report.txt")
    if not os.path.isfile(last):
        continue
    try:
        path = open(last).read().strip()
        report = json.load(open(path))
    except Exception:
        continue
    fails = [(p, r.get("reason", "")) for p, r in report.get("rows", {}).items()
             if r.get("verdict") == "FAIL"]
    notrun = [p for p, r in report.get("rows", {}).items()
              if not r.get("verdict")]
    if fails:
        print(f"FAIL rows ({tree}) — log: {log_root}/{tree}.log")
        for p, reason in fails:
            print(f"  {p}  — {reason}")
    if notrun:
        print(f"NOT RUN ({tree}): {len(notrun)} row(s) — rerun the same command to resume")
ROUND_SUMMARY_PY

exit "$rc"

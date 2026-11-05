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
# run-matrix.sh — the E2E SCRIPT MATRIX: every *.sh under e2e/ gets exactly
# one recorded row (PASS / FAIL / SKIP / BLOCKED-PRODUCT) with its reason,
# wall time, log path and closure hash.
#
# The engine (enumeration + self-check, checkpoint, sweep, closure hash,
# verdict vocabulary, report) lives in common/sh/matrix.sh and is shared with
# deploy/run-matrix.sh. THIS file declares only what is e2e-specific: the
# classification table, the phases, the preflight and the sweep additions.
# The two runners are INDEPENDENT — either may be run alone.
#
# Classes:
#   A  battery member — the ordered scripts of the e2e battery. Phase A
#      EXECUTES them per row (one row at a time), so a targeted re-run after a
#      fix re-executes only the affected rows; the battery's llm/docker gating
#      is preserved by matrix_row_gate (--fast skips the tagged bench rows).
#   B  needs a DEPLOYED stack (deploy/run-matrix.sh --phase B deploys one, or
#      any operator deployment on :3000/:3100 will do). No e2e row is class B
#      any more — the self-contained benchmarks replaced the one that was —
#      but the engine's class/fixture machinery stays for the deploy tree.
#   C  self-contained (deploys and cleans up its own throwaway stack, or
#      touches nothing outside /tmp)
#   F  library (not independently runnable) — valid only when a named
#      consumer has a verdict
#
# Usage:
#   sudo bash e2e/run-matrix.sh --phase A|C|B|all
#   sudo bash e2e/run-matrix.sh --only 'e2e/smoke.sh' [--force]
#   sudo bash e2e/run-matrix.sh --fast
#   sudo bash e2e/run-matrix.sh --report | --list

set -uo pipefail

ROOT="${ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"

# ── Battery-root isolation (the battery runs under its own root) ──
# EVERY row but the fixture phase runs in the isolated battery root. Without
# it the rows run against the PRODUCTION root, and the pre-row sweep has
# already stopped the production units — which DISARMS the co-location
# refusal in e2e/common.sh (it fires only while the units are ACTIVE) — so
# the row then rm -rf's the production volumes tree, template store and
# certs and overwrites its binaries (the incident tc_clean_environment
# records). One documented command did this: `--only <battery script>`.
# Exported BEFORE the source below, because common/sh/runtime.sh resolves
# DEPLOY_DIR/VOL_ROOT from SANDSWAP_E2E_ROOT at source time (and old-family
# scripts read ${VOL_ROOT:-/var/lib/sandswap/volumes} even earlier).
export SANDSWAP_E2E_ROOT="${SANDSWAP_E2E_ROOT:-/var/lib/sandswap-e2e}"
mkdir -p "$SANDSWAP_E2E_ROOT"
export DEPLOY_DIR="$SANDSWAP_E2E_ROOT"
export VOL_ROOT="$SANDSWAP_E2E_ROOT/volumes"

# shellcheck disable=SC1091
source "$ROOT/e2e/common.sh"

MATRIX_TREE="e2e"
MATRIX_ENUM_ROOT="e2e"
MATRIX_STATE_DIR="${MATRIX_STATE_DIR:-/var/tmp/r3-matrix/e2e}"

# What an e2e verdict depends on — derived from what the rows actually pick
# up (grep every source/exec edge, not a hand-kept list):
#   - this tree's harness + the shared layers (every e2e script sources
#     e2e/common.sh, which sources common/sh/runtime.sh + stack.sh)
#   - deploy/gen-certs.sh — tc_gen_certs runs it for 35 rows
#   - the check-*.py checkers a row EXECUTES (harness-fault-injection drives
#     all four; e2e/check-handrolled-prelude.py is also the live guard;
#     e2e/check-docs-truth.py is executed by e2e/docs-truth.sh every battery
#     run — the standing docs layer)
#   - the ENGINE (common/sh/matrix.sh: verdict vocabulary, reuse policy,
#     closure hashing) and this runner itself (the spec, the phases, the
#     consumer map) — neither is enumerated, so editing them must invalidate
#     the rows they judged
MATRIX_CLOSURE_FILES=(
    common/sh/runtime.sh common/sh/stack.sh common/sh/matrix.sh
    e2e/common.sh e2e/run-matrix.sh
    e2e/pin.sh
    deploy/baremetal/common.sh deploy/baremetal/deploy-lib.sh
    deploy/gen-certs.sh
    e2e/check-docs-links.py e2e/check-nil-wrap-scan.py e2e/check-handrolled-prelude.py
    e2e/check-warden-path-safety.py e2e/check-docs-truth.py
    deploy/baremetal/check-shape-hardcodes.py
)

# Build artifacts a row's verdict is evidence about (see the engine's
# matrix_artifact_identity). Any rebuild invalidates reuse; a script/fixture
# edit alone does not. Entries must be REAL build outputs with stable
# presence: a name that is missing (or a deploy-staged file that appears and
# disappears between rounds — output/etcd did) flips the identity on every
# pass and silently defeats reuse. The kernel config sidecars are
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
    # ── battery members (phase A: executed per row, same order) ──
    "e2e/docs-truth.sh|A||-|code<->docs parity (static, no stack)||extra:docs"
    "e2e/ownership.sh|A||-|"
    "e2e/dns-staleness.sh|A||-|"
    "e2e/self-pressure-gate.sh|A||-|"
    "e2e/load-shed.sh|A||-|"
    "e2e/staleness-gateway-e2e.sh|A||-|"
    "e2e/staleness-routing-e2e.sh|A||-|"
    "e2e/oidc-keycloak.sh|A||-|needs docker"
    "e2e/resilience.sh|A||-|"
    "e2e/harness-fault-injection.sh|A||-|"
    "e2e/stream-tls-require-ca.sh|A||-|"
    "e2e/memory-identity-persistence.sh|A||-|"
    "e2e/warden-unit.sh|A||-|"
    "e2e/smoke.sh|A||-|"
    "e2e/file-api.sh|A||-|"
    "e2e/parallel-exec.sh|A||-|"
    "e2e/overlayfs-isolation.sh|A||-|"
    "e2e/cross-tenant-residue.sh|A||-|||artifacts:output/rootfs-ubuntu"
    "e2e/template-lifecycle.sh|A||-|"
    "e2e/template-swap.sh|A||-|"
    "e2e/template-ref-isolation.sh|A||-|"
    "e2e/sandfs-delete-lifecycle.sh|A||-|"
    "e2e/lifecycle-split-gateway.sh|A||-|"
    "e2e/multi-agents.sh|A||-|"
    "e2e/mcp.sh|A||-|"
    "e2e/vmm-crash-selfheal.sh|A||-|"
    "e2e/readopt-restart-id-unique.sh|A||-|"
    "e2e/multi-instance-orphan-safety.sh|A||-|"
    "e2e/warden-log-leak-guard.sh|A||-|"
    "e2e/seccomp.sh|A||-|"
    "e2e/kernel-config-gate.sh|A||-|guest-kernel attack-surface gate (synthetic .config)"
    "e2e/host-exec-paths.sh|A||-|privileged components use hostbin's pinned paths"
    "e2e/vmm-api-auth.sh|A||-|"
    "e2e/share-root-gate.sh|A||-|"
    "e2e/volume-seed-rotation.sh|A||-|"
    "e2e/volume-seed-injection.sh|A||-|"
    "e2e/exec-timeout-policy.sh|A||-|"
    "e2e/warden-hostile.sh|A||-|"
    "e2e/protocol-version-e2e.sh|A||-|"
    "e2e/routed-ipv6.sh|A||-|"
    "e2e/egress-identity.sh|A||-|"
    "e2e/config-hotreload.sh|A||-|"
    "e2e/disconnect-tolerance.sh|A||-|"
    "e2e/resilience-e2e.sh|A||-|"
    "e2e/switch-under-adversarial.sh|A||-|"
    "e2e/oci-registry.sh|A||-|"
    "e2e/scale-rehearsal.sh|A||-|||fast:skip"
    "e2e/eino-agent-mcp.sh|A||-|needs llm key||artifacts:output/rootfs-ubuntu"
    "e2e/latency-benchmark-aiagent.sh|A||-|needs llm key||fast:skip"
    "e2e/latency-benchmark-unmount.sh|A||-|||artifacts:output/rootfs-ubuntu fast:skip"
    "e2e/latency-benchmark-load.sh|A||-|||fast:skip"
    "e2e/benchmark-overlayfs.sh|A||-|||fast:skip"
    # ── non-battery ──
    "e2e/framework-unit.sh|C|600|-|"
    "e2e/deploy-tree-pins.sh|C|600|-|deploy-tree install/rotation pins (no stack)||extra:deploy"
    "e2e/warden-chroot-escape.sh|C|1800|-|symlink chroot-escape containment (brings up its own stack; replaces the pool VM twice)"
    "e2e/warden-timing-probe.sh|C|1800|-|"
    "e2e/vmm-seccomp.sh|C|1800|-|sandvmm seccomp log→enforce gate (runs the smoke battery twice)"
    "e2e/build-gate-selftest.sh|C|600|-|build.sh gate self-test (static)"
    "e2e/host-id-check.sh|C|600|-|service identity numbers (static)"
    "e2e/vsockguard-verify-modes.sh|C|600|-|vsockguardctl verify modes (static)"
    "e2e/mount-identity-race.sh|C|1800|-|generation alias binds set-fs to mount"
    "e2e/pool-concurrency.sh|C|900|-|batch create/destroy concurrency"
    "e2e/latency-benchmark-alloc-sweep.sh|C|600|-|planner only (--run is bare-metal-only)|--plan --cores 8 --peaks 1,2,2"
    "e2e/single-node-multi-agent.sh|C|2700|deploy/baremetal/uninstall.sh|single-node MemoryStore + eino multi-agent drill (background-process shape)"
    # ── libraries ──
    "e2e/common.sh|F|0|-|library"
    "e2e/run-matrix.sh|F|0|-|this file"
    "e2e/pin.sh|F|0|-|library — CPU/NUMA pinning used by the latency benchmarks"
)

MATRIX_LIB_CONSUMERS=(
    "e2e/common.sh:e2e/smoke.sh e2e/ownership.sh e2e/warden-unit.sh"
    "e2e/run-matrix.sh:e2e/framework-unit.sh e2e/warden-timing-probe.sh"
    "e2e/pin.sh:e2e/latency-benchmark-aiagent.sh e2e/latency-benchmark-unmount.sh e2e/latency-benchmark-load.sh"
)

# ── e2e tree hooks ───────────────────────────────────────────────────
matrix_preflight() {
    matrix_host_tools_preflight || exit 1
    tc_check_root
    tc_check_kvm
    tc_check_artifacts
    # Freshness is established ONCE here for the whole pass (check, and one
    # rebuild if genuinely stale — BEFORE any verdict is recorded). Rows then
    # see SANDSWAP_ROUND_FRESH=1 and skip their per-row gate: a mid-round
    # source/artifact touch must not auto-rebuild the shared set from inside
    # a row and re-stamp every artifact under the recorded verdicts.
    tc_check_freshness
    export SANDSWAP_ROUND_FRESH=1
}

# /etc/hosts and /etc/resolv.conf backups are an e2e-only hazard (several
# suites rewrite them to test routing); the deploy tree has its own ledger.
matrix_sweep_extra() { tc_restore_host_files; }

# Final cleanup for a COMPLETE pass: sweep everything the rows built and
# remove the shared network artifacts (bridge + nft table + run dirs). A
# residue left after this is a gate failure (the engine verifies it).
matrix_final_cleanup() {
    env_sweep
    if declare -F ss_host_network_teardown >/dev/null 2>&1; then
        ss_host_network_teardown
    fi
    rm -rf /run/sandswap /run/sandswap-state /run/sandswap-boxout 2>/dev/null || true
    ip link del br-sandswap 2>/dev/null || true
}

# The battery's llm/docker tags: return 10 + a reason on stdout to record
# SKIP without executing the script (missing key/docker is an external
# dependency, not a product failure).
matrix_row_gate() {
    case "$1" in
        e2e/eino-agent-mcp.sh|e2e/latency-benchmark-aiagent.sh|e2e/single-node-multi-agent.sh)
            if [[ -z "${DEEPSEEK_API_KEY:-}" && -z "${OPENAI_API_KEY:-}" && -z "${GOOGLE_API_KEY:-}" ]]; then
                echo "needs-llm-key"
                return 10
            fi ;;
        e2e/oidc-keycloak.sh)
            if ! command -v docker >/dev/null 2>&1; then
                echo "needs-docker"
                return 10
            fi ;;
    esac
    return 0
}

# ── Phases ───────────────────────────────────────────────────────────
# A — the battery, executed PER ROW by the engine. Each row is an
# independent matrix row: it gets the pre-row sweep, the closure+artifacts
# reuse probe, and a verdict of its own. A fix to one script therefore
# re-executes that script, not the whole battery.
# MATRIX_NO_BATTERY=1 records the A rows as SKIP(skip:matrix-no-battery)
# instead of leaving them NOT RUN (probes/tests use this).
matrix_phase_A() {
    tc_log_section "PHASE A ($MATRIX_TREE) — battery (per-row)"
    if [[ "${MATRIX_NO_BATTERY:-0}" == "1" ]]; then
        local entry path class
        for entry in "${MATRIX_SPEC[@]}"; do
            IFS='|' read -r path class _ _ _ _ _ <<<"$entry"
            [[ "$class" == "A" ]] || continue
            [[ -n "$ONLY" && "$path" != $ONLY ]] && continue
            matrix_record_skip "$path" A "matrix-no-battery"
        done
        return 0
    fi
    matrix_run_generic A
}

# B — the deployed-stack class. The one e2e row that verified an externally
# deployed stack (latency-under-load.sh) was replaced by the self-contained
# latency-benchmark-load.sh, so no e2e row is class B any more. The class and
# the engine's MATRIX_FIXTURE machinery remain (deploy/run-matrix.sh uses
# them); a future external-fixture row should reintroduce a phase function
# here rather than weaken the self-contained default.

# Phase order for "all": the battery's verdicts (A) first, then this tree's
# self-contained rows (C). No fixture phase exists in this tree.
matrix_default_phases() { echo "A C"; }

# ── Engine ───────────────────────────────────────────────────────────
# Sourced LAST: it asserts MATRIX_TREE/MATRIX_ENUM_ROOT and reads the spec,
# the closure list and the consumer map declared above.
# shellcheck disable=SC1091
source "$ROOT/common/sh/matrix.sh"

matrix_main "$@"

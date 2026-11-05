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
# matrix.sh — the SCRIPT MATRIX engine: everything a `run-matrix.sh` needs
# that is not specific to one tree.
#
# Each tree owns a thin runner — `e2e/run-matrix.sh` and
# `deploy/run-matrix.sh` — that declares ITS scripts (the classification
# table), ITS phases and ITS preconditions, and calls `matrix_main` here. The
# two runners are INDEPENDENT: either can be run alone, against its own
# checkpoint, without the other tree being present or idle.
#
# The engine provides:
#   - enumeration + the self-check that refuses a partial report
#   - the classification lookup and the closure hash (script + the shared
#     files it can source + its argv)
#   - the atomic checkpoint (one row per script, resume after a reboot)
#   - the environment sweep before every row and the residue check after it
#   - run_one / run_row_once, the verdict vocabulary, battery import
#   - the JSON + Markdown report
#
# Contract for a tree runner (all required unless noted):
#   MATRIX_TREE          e2e | deploy        — names the state dir + report
#   MATRIX_ENUM_ROOT     the dir to enumerate (e2e | deploy)
#   MATRIX_SPEC          array of "path|class|timeout|cleanup_after|note|args"
#   MATRIX_LIB_CONSUMERS array of "library:consumer consumer …"
#   MATRIX_CLOSURE_FILES array of shared files a verdict depends on
#   matrix_preflight     function: root/KVM/artifact checks
#   matrix_sweep_extra   function (optional): tree-specific sweep additions
#   matrix_row_precondition <path>  function (optional): host state a row
#                        needs but does not create itself
#   matrix_phase_<X>     function (optional): a phase that needs its own
#                        fixture; if absent the generic loop handles class X
#
# Source AFTER common/sh/runtime.sh (this file does it for standalone use).

if ! declare -F tc_log_step >/dev/null 2>&1; then
    # shellcheck disable=SC1091
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/runtime.sh"
fi

: "${MATRIX_TREE:?matrix.sh: MATRIX_TREE must be set (e2e|deploy) before sourcing}"
: "${MATRIX_ENUM_ROOT:?matrix.sh: MATRIX_ENUM_ROOT must be set}"

# The engine owns its error handling: it must survive a FAILING script and a
# failing probe and keep going (that is the whole point of a matrix). The
# deploy tree's common.sh sets `set -euo pipefail` at its top, so drop `-e`
# here — the same reason the battery runs without it. `-u` and `pipefail`
# stay: they catch real authoring mistakes without aborting on expected
# non-zero returns.
set +e

MATRIX_TIMEOUT_DEFAULT="${MATRIX_TIMEOUT:-2700}"
MATRIX_STATE_DIR="${MATRIX_STATE_DIR:-/var/tmp/r3-matrix/$MATRIX_TREE}"
CHECKPOINT="$MATRIX_STATE_DIR/checkpoint.json"
MATRIX_RAN=()   # rows this invocation actually executed (or recorded a skip for)
RESULTS_DIR="$MATRIX_STATE_DIR/results"
LOGS_DIR="$RESULTS_DIR/logs"
mkdir -p "$RESULTS_DIR" "$LOGS_DIR"

MATRIX_BOOT_ID="$(cat /proc/sys/kernel/random/boot_id)"
MATRIX_HEAD="$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"

# Build-artifact identity — the file set a row's verdict actually ran against.
# The runner declares MATRIX_ARTIFACTS (repo-relative paths; directories are
# walked). Identity is path+size+mtime over the whole set: an incremental
# build that rebuilds ANY declared artifact invalidates every row (correct —
# any row may consume it), while a pure script/doc edit does not. Reuse
# requires this to match the value recorded with the verdict; the closure
# hash alone cannot see a rebuilt output/, and a git revision cannot see an
# UNCOMMITTED rebuild.
matrix_artifact_identity() {
    local f
    for f in "${MATRIX_ARTIFACTS[@]:-}"; do
        [[ -n "$f" ]] || continue
        if [[ -d "$ROOT/$f" ]]; then
            find "$ROOT/$f" -printf '%P %s %T@\n' 2>/dev/null | LC_ALL=C sort
        elif [[ -f "$ROOT/$f" ]]; then
            stat -c '%n %s %Y' "$ROOT/$f" 2>/dev/null
        else
            printf 'MISSING %s\n' "$f"
        fi
    done | sha256sum | cut -c1-16
}
MATRIX_ARTIFACT_ID="$(matrix_artifact_identity)"

# Filled by matrix_enumerate (the self-check). Declared here so the freshness
# gate can consult it under `set -u` even when it is called directly.
ENUMERATED=()

# ── CLI state (parsed by matrix_main) ────────────────────────────────
PHASE="all"; ONLY=""; FORCE=0; FAST=0; REPORT_ONLY=0; LIST=0

# ═══════════════════════════════════════════════════════════════════════
# Classification
# ═══════════════════════════════════════════════════════════════════════
spec_lookup() { # <path> -> "path|class|timeout|cleanup|note|args|requires"
    local p
    for p in "${MATRIX_SPEC[@]}"; do
        [[ "${p%%|*}" == "$1" ]] && { echo "$p"; return 0; }
    done
    return 1
}

# matrix_enumerate — every *.sh under the tree, one entry each.
matrix_enumerate() {
    mapfile -t ENUMERATED < <(cd "$ROOT" && find "$MATRIX_ENUM_ROOT" -name '*.sh' | sort)
    ENUM_COUNT="${#ENUMERATED[@]}"
    SPEC_COUNT="${#MATRIX_SPEC[@]}"
    SELF_MISSING=(); SELF_UNCLASSIFIED=(); SELF_DUPLICATE=()
    local f p
    declare -A _seen=()
    for f in "${ENUMERATED[@]}"; do
        [[ -n "${_seen[$f]:-}" ]] && SELF_DUPLICATE+=("$f")
        _seen[$f]=1
        spec_lookup "$f" >/dev/null || SELF_UNCLASSIFIED+=("$f")
    done
    for p in "${MATRIX_SPEC[@]}"; do
        f="${p%%|*}"
        [[ -f "$ROOT/$f" ]] || SELF_MISSING+=("$f")
    done
}

matrix_selftest() {
    matrix_enumerate
    if [[ "$LIST" == "1" ]]; then
        printf '%-58s %-3s %6s  %s\n' SCRIPT CLASS TIMEOUT NOTE
        local f s _p c t _tmo note args
        for f in "${ENUMERATED[@]}"; do
            s="$(spec_lookup "$f")"
            IFS='|' read -r _p c t _tmo note args _req <<<"$s"
            printf '%-58s %-3s %6s  %s%s\n' "$f" "$c" "$t" "$note" "${args:+ [args: $args]}"
        done
        echo "tree=$MATRIX_TREE enumerated=$ENUM_COUNT spec=$SPEC_COUNT"
        return 3   # caller exits 0
    fi
    if [[ "$ENUM_COUNT" != "$SPEC_COUNT" || "${#SELF_UNCLASSIFIED[@]}" -gt 0 \
          || "${#SELF_MISSING[@]}" -gt 0 || "${#SELF_DUPLICATE[@]}" -gt 0 ]]; then
        tc_log_error "MATRIX SELF-CHECK FAILED ($MATRIX_TREE) — the runner refuses to produce a report it cannot back"
        [[ "$ENUM_COUNT" != "$SPEC_COUNT" ]] && tc_log_error "  enumerated=$ENUM_COUNT but classified=$SPEC_COUNT"
        [[ "${#SELF_MISSING[@]}" -gt 0 ]] && tc_log_error "  classified but absent on disk: ${SELF_MISSING[*]}"
        [[ "${#SELF_UNCLASSIFIED[@]}" -gt 0 ]] && tc_log_error "  present but UNCLASSIFIED: ${SELF_UNCLASSIFIED[*]}"
        [[ "${#SELF_DUPLICATE[@]}" -gt 0 ]] && tc_log_error "  duplicate rows: ${SELF_DUPLICATE[*]}"
        return 1
    fi
    return 0
}

# ═══════════════════════════════════════════════════════════════════════
# Closure hash
# ═══════════════════════════════════════════════════════════════════════
# The hash a verdict was judged on: the script itself + every shared file it
# can transitively source + its ARGS (`setup-host.sh` with no arguments exits
# 1 on usage; the same file with `--role all` does the host prep). A changed
# closure invalidates the verdict — the mechanical answer to "which scripts
# must be re-run after this edit".
# matrix_row_requires <path> — the row's declared prerequisites (7th spec
# field). Tokens: extra:<path>[,<path>] (content folded into the row's
# closure), artifacts:<path>[,...] (aggregate existence preflight),
# stack:<port>[,<port>] (must be LISTENing before the row runs).
matrix_row_requires() {
    local s _p _c _t _cl _note _a req
    s="$(spec_lookup "$1" 2>/dev/null)" || return 0
    IFS='|' read -r _p _c _t _cl _note _a req <<<"$s"
    printf '%s' "${req:-}"
}

# matrix_extra_identity <path> — identity of the row's requires=extra:<path>
# inputs. Rows that scan a tree outside the closure list (docs-truth scans
# docs/, deploy-tree-pins scans deploy/) declare it here, so an edit there
# invalidates ONLY those rows.
matrix_extra_identity() {
    local path="$1" tok p IFS
    for tok in $(matrix_row_requires "$path"); do
        case "$tok" in extra:*) ;; *) continue ;; esac
        IFS=','
        for p in ${tok#extra:}; do
            if [[ -d "$ROOT/$p" ]]; then
                find "$ROOT/$p" -printf '%P %s %T@\n' 2>/dev/null | LC_ALL=C sort
            elif [[ -f "$ROOT/$p" ]]; then
                stat -c '%n %s %Y' "$ROOT/$p" 2>/dev/null
            else
                printf 'MISSING %s\n' "$p"
            fi
        done
        IFS=$' \t\n'
    done | sha256sum | cut -c1-16
}

closure_hash() {
    local script="$1"; shift
    local f
    {
        sha256sum "$ROOT/$script" 2>/dev/null
        for f in "${MATRIX_CLOSURE_FILES[@]}"; do
            [[ -f "$ROOT/$f" ]] && sha256sum "$ROOT/$f"
        done
        printf 'argv:%s\n' "$*"
        printf 'extra:%s\n' "$(matrix_extra_identity "$script")"
    } | sha256sum | cut -c1-16
}

# ═══════════════════════════════════════════════════════════════════════
# Checkpoint
# ═══════════════════════════════════════════════════════════════════════
state_get() { # <path> -> TSV: class verdict seconds rc closure reason log finding at source head
    [[ -f "$CHECKPOINT" ]] || return 0
    python3 - "$CHECKPOINT" "$1" <<'PY'
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception:
    raise SystemExit
r = d.get("rows", {}).get(sys.argv[2])
if r:
    print("\t".join(str(r.get(k, "")) for k in
          ("class", "verdict", "seconds", "rc", "closure", "reason", "log", "finding_id",
           "at", "source", "head", "artifacts")))
PY
}
state_set() { # <path> <class> <verdict> <seconds> <rc> <closure> <reason> <log> <finding_id> <source>
    CHECKPOINT="$CHECKPOINT" MATRIX_HEAD="$MATRIX_HEAD" MATRIX_TREE="$MATRIX_TREE" \
        MATRIX_ARTIFACT_ID="$MATRIX_ARTIFACT_ID" python3 - "$@" <<'PY'
import json, os, sys, tempfile, datetime
cp = os.environ["CHECKPOINT"]
p = sys.argv[1:]
row = {"class": p[1], "verdict": p[2], "seconds": int(p[3] or 0), "rc": int(p[4] or 0),
       "closure": p[5], "reason": p[6], "log": p[7], "finding_id": p[8], "source": p[9],
       "artifacts": os.environ.get("MATRIX_ARTIFACT_ID", ""),
       # The revision the verdict was produced at — a row is only reuse
       # evidence for the revision it ran on (the report's `heads` summary
       # makes a mixed ledger visible instead of labelling every row with
       # the CURRENT checkout).
       "head": os.environ.get("MATRIX_HEAD", ""),
       "at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
       "boot_id": open("/proc/sys/kernel/random/boot_id").read().strip()}
try:
    d = json.load(open(cp))
except FileNotFoundError:
    d = {"tree": os.environ.get("MATRIX_TREE", ""), "boot_id": row["boot_id"],
         "head": row["head"], "rows": {}}
except Exception as e:
    # An existing but unreadable checkpoint is EVIDENCE (a truncated write, a
    # hand-edit, the wrong file), and the rows it holds are the review's
    # ledger: replacing it silently loses them with rc 0 — the caller cannot
    # even see the loss. Only a MISSING file starts a new ledger; anything
    # else must be resolved by a human before the matrix writes again.
    sys.stderr.write("matrix: REFUSING to overwrite unreadable checkpoint %s: %s\n" % (cp, e))
    sys.stderr.write("matrix: move it aside (or point MATRIX_STATE_DIR at a fresh dir) — a ledger is never reset in place\n")
    raise SystemExit(1)
d.setdefault("rows", {})[p[0]] = row
d["updated"] = row["at"]
tmp = tempfile.NamedTemporaryFile("w", dir=os.path.dirname(cp), delete=False)
json.dump(d, tmp, indent=1, sort_keys=True)
tmp.flush(); os.fsync(tmp.fileno()); tmp.close()
os.replace(tmp.name, cp)   # atomic: a reboot mid-write cannot corrupt it
PY
}
state_init() {
    if [[ -f "$CHECKPOINT" ]]; then
        # Resume-from-this-ledger, but never adopt or repair one silently:
        # it must parse, and it must belong to THIS tree. A foreign tree's
        # checkpoint merged into this engine produced a report whose rows
        # and enumeration contradicted each other (e2e rows counted by the
        # deploy report, listed in neither table) — refuse loudly instead.
        CHECKPOINT="$CHECKPOINT" MATRIX_TREE="$MATRIX_TREE" python3 - <<'PY'
import json, os, sys
cp = os.environ["CHECKPOINT"]
tree = os.environ["MATRIX_TREE"]
try:
    d = json.load(open(cp))
except Exception as e:
    sys.stderr.write("matrix: checkpoint %s is unreadable (%s)\n" % (cp, e))
    sys.stderr.write("matrix: refusing to start — move it aside, or point MATRIX_STATE_DIR at a fresh dir\n")
    raise SystemExit(1)
if d.get("tree", "") != tree:
    sys.stderr.write("matrix: checkpoint %s belongs to tree %r, not %r\n" % (cp, d.get("tree", ""), tree))
    sys.stderr.write("matrix: refusing to merge ledgers — each tree owns its own MATRIX_STATE_DIR\n")
    raise SystemExit(1)
PY
        return $?
    fi
    CHECKPOINT="$CHECKPOINT" MATRIX_BOOT_ID="$MATRIX_BOOT_ID" MATRIX_HEAD="$MATRIX_HEAD" \
    MATRIX_TREE="$MATRIX_TREE" python3 - <<'PY'
import json, os, datetime
json.dump({"tree": os.environ["MATRIX_TREE"], "boot_id": os.environ["MATRIX_BOOT_ID"],
           "head": os.environ["MATRIX_HEAD"],
           "created": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
           "rows": {}},
          open(os.environ["CHECKPOINT"], "w"), indent=1, sort_keys=True)
PY
}

# ═══════════════════════════════════════════════════════════════════════
# Environment hygiene
# ═══════════════════════════════════════════════════════════════════════
# BEFORE every row: remove whatever a previous script (or a reboot mid-script)
# left behind, so a residue cannot be misread as this row's result. AFTER
# every row: VERIFY the same list is empty and record any residue IN THE ROW
# (an unclean exit is evidence about that script, not about the next one).
# ss_disk_guard/ss_mem_guard (common/sh/runtime.sh) run inside the sweep, so
# the battery's sweep() and both runners share one implementation.

env_sweep() {
    ss_disk_guard
    ss_mem_guard
    # A unit stuck in "deactivating" makes `systemctl stop` wait forever.
    # Bound the wait; the kill pass below is the actual cleanliness guard.
    timeout 15 systemctl stop 'sandswap-*' 2>/dev/null || true
    tc_kill_sandswap_procs "matrix-sweep" >/dev/null 2>&1 || true
    ss_kill_etcd >/dev/null 2>&1 || true
    ss_stack_residue_clean >/dev/null 2>&1 || true
    rm -rf /run/sandswap /run/sandswap-state 2>/dev/null || true
    if declare -F matrix_sweep_extra >/dev/null 2>&1; then
        matrix_sweep_extra >/dev/null 2>&1 || true
    fi
    return 0
}

env_residue() { # prints a comma-joined list of what is still dirty ("" = clean)
    local out=()
    local procs
    procs="$(pgrep -f '(^|/)(sandvmm|sandlot|gateway|dns)( |$)' 2>/dev/null | tr '\n' ' ' || true)"
    [[ -n "${procs// /}" ]] && out+=("procs:$procs")
    local units
    units="$(systemctl list-units 'sandswap-*' --state=active --no-legend --no-pager 2>/dev/null | awk '{print $1}' | tr '\n' ' ' || true)"
    [[ -n "${units// /}" ]] && out+=("units:$units")
    local taps
    taps="$(ip -br link show 2>/dev/null | awk '/^tap-/{print $1}' | tr '\n' ' ' || true)"
    [[ -n "${taps// /}" ]] && out+=("taps:$taps")
    local ports
    ports="$(ss -tlnH 2>/dev/null | awk '{print $4}' | grep -oE ':(3000|3001|3100|3101|9996|9997|9998|9999|2379|2380)$' | sort -u | tr '\n' ' ' || true)"
    [[ -n "${ports// /}" ]] && out+=("ports:$ports")
    ( IFS=,; echo "${out[*]}" )
}

# matrix_requires_stack_check <path> — 0 when every requires=stack:<port>
# listener is up. Ports are checked on the all/loopback listeners via `ss`.
matrix_requires_stack_check() {
    local path="$1" tok p IFS
    for tok in $(matrix_row_requires "$path"); do
        case "$tok" in stack:*) ;; *) continue ;; esac
        IFS=','
        for p in ${tok#stack:}; do
            if ! ss -tlnH 2>/dev/null | awk '{print $4}' | grep -qE "[:.]${p}\$"; then
                tc_log_error "prerequisite stack: nothing is listening on port $p"
                return 1
            fi
        done
        IFS=$' \t\n'
    done
    return 0
}

# matrix_requires_preflight — the AGGREGATE artifact gate, before any row
# runs: every requires=artifacts:<path> claim in the spec must exist. One
# missing optional artifact (output/rootfs-ubuntu is NOT built by `build.sh
# all`) otherwise surfaces only at the Nth row that consumes it.
matrix_requires_preflight() {
    local entry _p _c _t _cl _note _a req tok p IFS
    local missing=()
    for entry in "${MATRIX_SPEC[@]}"; do
        IFS='|' read -r _p _c _t _cl _note _a req <<<"$entry"
        case "$req" in *artifacts:*) ;; *) continue ;; esac
        for tok in $req; do
            case "$tok" in artifacts:*) ;; *) continue ;; esac
            IFS=','
            for p in ${tok#artifacts:}; do
                [[ -e "$ROOT/$p" ]] || missing+=("$p (required by $_p)")
            done
            IFS=$' \t\n'
        done
    done
    if (( ${#missing[@]} > 0 )); then
        tc_log_error "required build artifacts are missing: ${missing[*]}"
        tc_log_info "build them: bash build/build.sh all   (output/rootfs-ubuntu: bash build/build-ubuntu-rootfs.sh)"
        return 1
    fi
    return 0
}

# matrix_host_tools_preflight — every tool the battery's rows HARD-require, in
# one check before any row runs. A missing test tool (conntrack, numactl, the
# NFS helpers) fails once, up front, with the install command: a per-row
# failure minutes in gives no hint that the host is under-provisioned.
# docker/k3s/kubectl and LLM keys stay OUT: those are external dependencies
# with row-level SKIP gates, not whole-battery prerequisites.
# MATRIX_HOST_TOOLS overrides the list (self-tests / trimmed hosts).
matrix_host_tools_preflight() {
    local tools="${MATRIX_HOST_TOOLS:-curl wget git python3 openssl sqlite3 dig iptables nft \
conntrack numactl taskset setpriv exportfs mount.nfs etcd etcdctl go gcc make clang busybox cpio}"
    local t missing=()
    for t in $tools; do
        command -v "$t" >/dev/null 2>&1 || missing+=("$t")
    done
    # bpftool needs a FUNCTIONAL probe: Ubuntu's linux-tools-common installs a
    # /usr/sbin/bpftool WRAPPER that exits 2 when no linux-tools-<ver> package
    # matches the running kernel, and an existence check would pass it.
    if ! command -v bpftool >/dev/null 2>&1 || ! bpftool version >/dev/null 2>&1; then
        missing+=("bpftool(functional)")
    fi
    if (( ${#missing[@]} > 0 )); then
        tc_log_error "host-tool preflight: missing: ${missing[*]}"
        tc_log_info "install once: sudo bash build/install-deps.sh (installs these tools, incl. the pinned Go)"
        return 1
    fi
    tc_log_pass "host tools present (battery tools + functional bpftool)"
    return 0
}

# matrix_resource_preflight — disk/memory at the START of a run, fail-closed.
# env_sweep runs ss_disk_guard/ss_mem_guard before every row, but a host that
# is already tight must refuse BEFORE a multi-hour run starts. The guards
# shed caches; if the floors are still not met, the run does not start.
matrix_resource_preflight() {
    local rc=0
    if declare -F ss_disk_guard >/dev/null 2>&1; then
        ss_disk_guard || rc=1
        local floor="${MATRIX_DISK_FLOOR_MB:-3072}" avail
        avail="$(ss_df_avail_mb / 2>/dev/null || echo "")"
        if [[ -n "$avail" ]] && (( avail < floor )); then
            tc_log_error "disk preflight: / has ${avail}MB free after the guard (floor ${floor}MB)"
            rc=1
        fi
    fi
    if declare -F ss_mem_guard >/dev/null 2>&1; then
        ss_mem_guard || rc=1
        local mfloor="${MATRIX_MEM_FLOOR_MB:-700}" mavail
        mavail="$(awk '/MemAvailable/ {print int($2/1024)}' /proc/meminfo 2>/dev/null || echo "")"
        if [[ -n "$mavail" ]] && (( mavail < mfloor )); then
            tc_log_error "memory preflight: MemAvailable ${mavail}MB after the guard (floor ${mfloor}MB)"
            rc=1
        fi
    fi
    return "$rc"
}

# matrix_final_verify — the residue a COMPLETE pass must leave at zero:
# processes, units, TAPs, coordination ports, /run sandswap dirs, the sandbox
# bridge, and the sandswap nft table. Printed comma-joined ("" = clean).
matrix_final_verify() {
    local out
    out="$(env_residue 2>/dev/null || true)"
    [[ -d /run/sandswap || -d /run/sandswap-state || -d /run/sandswap-boxout ]] \
        && out="${out:+$out,}rundirs"
    ip link show br-sandswap >/dev/null 2>&1 && out="${out:+$out,}bridge"
    if command -v nft >/dev/null 2>&1 && nft list table inet sandswap >/dev/null 2>&1; then
        out="${out:+$out,}nft:inet-sandswap"
    fi
    printf '%s' "$out"
}

# matrix_record_skip <path> <class> <reason> — record a runner-side SKIP
# without executing the script (used when a phase deliberately does not run
# a row, e.g. MATRIX_NO_BATTERY=1).
matrix_record_skip() {
    local path="$1" class="$2" reason="$3"
    MATRIX_RAN+=("$path")
    state_set "$path" "$class" SKIP 0 0 "$(closure_hash "$path")" "skip:$reason" "-" "" "matrix"
    tc_log_warn "$path SKIP — $reason"
}

# matrix_gate <full-run 1|0> — the CI exit status. A FAIL row always fails
# the gate (including targeted --only runs). In a COMPLETE pass (default
# phase set, no --only) a row with no verdict is also a failure: the board
# must reach every row. BLOCKED-PRODUCT (a registered finding) and SKIP (a
# closed-set external-dependency outcome) are reported, not gate failures.
matrix_gate() {
    local full_run="$1" path v
    local fails=() notrun=()
    if [[ -n "${MATRIX_RESIDUE:-}" ]]; then
        tc_log_error "gate: final cleanup left residue: $MATRIX_RESIDUE"
        return 1
    fi
    local blocked=0 skips=0
    local judged=()
    if [[ "$full_run" == "1" ]]; then
        judged=("${ENUMERATED[@]}")
    else
        # A targeted run (--only / an explicit phase subset) judges ONLY the
        # rows it touched: stale verdicts from earlier rounds elsewhere in the
        # checkpoint are evidence about another tree state, not about this run.
        local seen=" "
        for path in "${MATRIX_RAN[@]:-}"; do
            [[ -n "$path" && "$seen" != *" $path "* ]] || continue
            seen+="$path "
            judged+=("$path")
        done
    fi
    for path in "${judged[@]}"; do
        v="$(state_get "$path" | cut -f2)"
        case "$v" in
            FAIL) fails+=("$path") ;;
            BLOCKED-PRODUCT) blocked=$((blocked + 1)) ;;
            SKIP) skips=$((skips + 1)) ;;
            ""|NOT_RUN) notrun+=("$path") ;;
        esac
    done
    (( blocked > 0 )) && tc_log_warn "gate: $blocked row(s) BLOCKED-PRODUCT (registered finding — reported, not a gate failure)"
    (( skips > 0 )) && tc_log_info "gate: $skips row(s) SKIP (recorded reason — see the report)"
    if (( ${#fails[@]} > 0 )); then
        tc_log_error "gate: ${#fails[@]} FAIL row(s): ${fails[*]}"
        return 1
    fi
    if [[ "$full_run" == "1" ]] && (( ${#notrun[@]} > 0 )); then
        tc_log_error "gate: ${#notrun[@]} row(s) NOT RUN — a complete pass must reach every row: ${notrun[*]}"
        return 1
    fi
    [[ "$full_run" == "1" ]] && tc_log_pass "gate: complete board, no FAIL rows (${#ENUMERATED[@]} rows)"
    return 0
}

# ═══════════════════════════════════════════════════════════════════════
# Running one script
# ═══════════════════════════════════════════════════════════════════════
run_one() { # run_one <path> <class> <timeout> <cleanup_after> [script args...]
    local path="$1" class="$2" tmo="$3" cleanup="$4"; shift 4
    MATRIX_RAN+=("$path")
    local slug log rc verdict reason finding="" dt t0 t1
    slug="$(echo "$path" | tr '/' '_' | sed 's/\.sh$//')"
    log="$LOGS_DIR/$slug.log"
    finding="$(state_get "$path" | cut -f8)"

    tc_log_section "RUN [$class] $path (timeout ${tmo}s)"
    # MATRIX_FIXTURE=1 marks a phase whose rows VERIFY a fixture the phase
    # itself deployed. The sweep must not run there: it stops the units and
    # kills the very processes under test (every verifier would report
    # "no live gateway" against a stack the deployer had just reported
    # healthy). The invariant inverts: the fixture must still be UP
    # before each row, and the phase tears it down and verifies cleanliness
    # once at the end.
    if [[ "${MATRIX_FIXTURE:-0}" == "1" ]]; then
        tc_log_info "fixture mode: skipping the pre-script sweep (the phase owns the stack)"
    else
        env_sweep
    fi
    # --fast: skip the heavy measurement rows (requires=fast:skip). They are
    # still RUN in a normal pass; a fast pass records SKIP so the report shows
    # exactly what was left out.
    if (( FAST == 1 )) && [[ " $(matrix_row_requires "$path") " == *" fast:skip "* ]]; then
        state_set "$path" "$class" SKIP 0 0 "$(closure_hash "$path" "$@")" \
            "fast: skipped by --fast" "$log" "" "matrix"
        tc_log_info "$path SKIP — --fast"
        return 2
    fi
    # Declared prerequisites (requires=stack:<port>): the stack a verifier
    # needs must be UP before the script runs. A missing stack is a row
    # FAILURE with a named prerequisite, never the script's own SUITE_SKIPPED
    # (which exits 0 and has repeatedly looked like a pass).
    if ! matrix_requires_stack_check "$path"; then
        state_set "$path" "$class" FAIL 0 1 "$(closure_hash "$path" "$@")" \
            "prerequisite: declared stack is not listening" "$log" "" "matrix"
        tc_log_error "$path FAIL — requires=stack prerequisite is not up"
        return 1
    fi
    if declare -F matrix_row_precondition >/dev/null 2>&1; then
        # A precondition that cannot establish the row's environment is a
        # FAILURE of the row (its result would be evidence about a different
        # environment), not a silent continue.
        if ! matrix_row_precondition "$path"; then
            state_set "$path" "$class" FAIL 0 1 "$(closure_hash "$path" "$@")" \
                "prerequisite: matrix_row_precondition failed" "$log" "" "matrix"
            tc_log_error "$path FAIL — matrix_row_precondition refused"
            return 1
        fi
    fi
    # Runner-side gating (the battery's llm/docker tags, preserved now that
    # phase A executes rows directly): a gate hook returns 10 + a reason on
    # stdout to record SKIP without running the script.
    if declare -F matrix_row_gate >/dev/null 2>&1; then
        local gate_reason gate_rc=0
        gate_reason="$(matrix_row_gate "$path")" || gate_rc=$?
        if (( gate_rc == 10 )); then
            state_set "$path" "$class" SKIP 0 0 "$(closure_hash "$path" "$@")" \
                "gate:${gate_reason:-skipped}" "$log" "" "matrix"
            tc_log_warn "$path SKIP — gate:${gate_reason:-skipped}"
            return 2
        fi
    fi
    export RUNALL_SKIP_DIR="$MATRIX_STATE_DIR/skips"; mkdir -p "$RUNALL_SKIP_DIR"
    export RUNALL_SCRIPT="$(basename "$path")"
    rm -f "$RUNALL_SKIP_DIR/$RUNALL_SCRIPT"
    t0=$(date +%s)
    ( cd "$ROOT" && KEEP_LOGS=1 timeout --signal=TERM --kill-after=30 "$tmo" bash "$path" "$@" ) >"$log" 2>&1
    rc=$?
    t1=$(date +%s); dt=$((t1 - t0))

    reason=""
    case "$rc" in
        0)
            if [[ -f "$RUNALL_SKIP_DIR/$RUNALL_SCRIPT" ]]; then
                verdict=SKIP; reason="$(head -1 "$RUNALL_SKIP_DIR/$RUNALL_SCRIPT")"
            else
                verdict=PASS
            fi ;;
        124) verdict=FAIL; reason="timeout:${tmo}s" ;;
        143) verdict=FAIL; reason="sigterm (rc=143)" ;;
        *)   verdict=FAIL; reason="rc=$rc" ;;
    esac

    # A known product defect keeps its own verdict: the row failed for a
    # reason already registered as a finding, so it is BLOCKED-PRODUCT (with
    # the finding id) rather than an unexplained FAIL.
    if [[ "$verdict" == "FAIL" && -n "$finding" ]]; then
        verdict=BLOCKED-PRODUCT
    fi

    # A tree may classify a KNOWN PRODUCT REFUSAL the same way: the optional
    # matrix_row_classify <path> <rc> <log> hook matches the refusal's exact
    # text in the row log (the developer guide's expected-refusal rule) and
    # prints a reason to map FAIL → BLOCKED-PRODUCT. A product that refuses
    # by design on this host shape is a reportable outcome, not a gate
    # failure — but only ever on an exact-text match, never on the exit code
    # alone (a refusal with different wording is a real failure).
    if [[ "$verdict" == "FAIL" ]] && declare -F matrix_row_classify >/dev/null 2>&1; then
        local blocked_reason
        blocked_reason="$(matrix_row_classify "$path" "$rc" "$log")"
        if [[ -n "$blocked_reason" ]]; then
            verdict=BLOCKED-PRODUCT
            reason="expected-refusal: $blocked_reason"
        fi
    fi

    if [[ "${MATRIX_FIXTURE:-0}" != "1" ]]; then
        local residue
        residue="$(env_residue)"
        if [[ -n "$residue" ]]; then
            reason="${reason:+$reason; }residue:$residue"
            tc_log_warn "residue after $path: $residue — sweeping"
            env_sweep
        fi
    fi

    if [[ "$cleanup" != "-" && -f "$ROOT/$cleanup" ]]; then
        tc_log_info "post-script cleanup: $cleanup"
        ( cd "$ROOT" && timeout --signal=TERM --kill-after=30 900 bash "$cleanup" ) >>"$log" 2>&1 || \
            tc_log_warn "cleanup $cleanup returned non-zero (see $log)"
        if [[ "${MATRIX_FIXTURE:-0}" != "1" ]]; then
            local r2; r2="$(env_residue)"
            [[ -n "$r2" ]] && tc_log_warn "residue after cleanup: $r2"
        fi
    fi

    state_set "$path" "$class" "$verdict" "$dt" "$rc" "$(closure_hash "$path" "$@")" "$reason" "$log" "$finding" "matrix"
    case "$verdict" in
        PASS) tc_log_pass "$path PASS ($dt""s)"; return 0 ;;
        SKIP) tc_log_warn "$path SKIP ($dt""s) — $reason"; return 2 ;;
        *)    tc_log_error "$path $verdict ($dt""s) — $reason"; return 1 ;;
    esac
}

# run_row_once <path> [cleanup] [args…] — run and record WITHOUT the reuse
# check: a phase that needs a script's SIDE EFFECT (a live stack, a k3s
# cluster) must actually execute it, not replay a verdict from an earlier
# phase that has since torn the environment down.
run_row_once() {
    local path="$1" cleanup="${2:--}"; shift 2
    # Seven fields: path|class|timeout|cleanup|note|args|requires. Reading one
    # column short puts the NEXT column into `_a` (the last variable takes the
    # remainder): first the NOTE leaked into argv ("Unknown argument: phase"),
    # then the REQUIRES token did ("Unknown arg:
    # |stack:3100,3000") — both caught by the deploy matrix's
    # phase B. Keep this read in lockstep with the seven-column spec.
    local s _p c t _cl _note _a _req
    s="$(spec_lookup "$path")" || { tc_log_error "unclassified: $path"; return 1; }
    IFS='|' read -r _p c t _cl _note _a _req <<<"$s"
    [[ -z "$t" || "$t" == "0" ]] && t="$MATRIX_TIMEOUT_DEFAULT"
    [[ -z "$cleanup" ]] && cleanup="-"
    # Explicit args WIN over the spec's; they are never concatenated (passing
    # both ran `sandswap-ops.sh status status` and recorded a closure hash for
    # argv the row was not judged on).
    if [[ $# -gt 0 ]]; then
        set -- "$@"
    else
        # shellcheck disable=SC2086
        set -- ${_a:-}
    fi
    run_one "$path" "$c" "$t" "$cleanup" "$@"
}

# matrix_run_generic <class> — the loop every tree shares: run (or reuse) every
# row of one class, in spec order.
matrix_run_generic() {
    local want="$1" entry path class tmo cleanup note args req prev prev_closure prev_verdict prev_art
    tc_log_section "PHASE $want ($MATRIX_TREE)"
    for entry in "${MATRIX_SPEC[@]}"; do
        IFS='|' read -r path class tmo cleanup note args req <<<"$entry"
        [[ "$class" == "$want" ]] || continue
        [[ "$class" == "F" ]] && continue          # libraries are never "run"
        [[ -n "$ONLY" && "$path" != $ONLY ]] && continue
        prev="$(state_get "$path")"
        if [[ "$FORCE" != "1" && -n "$prev" ]]; then
            prev_closure="$(cut -f5 <<<"$prev")"
            prev_verdict="$(cut -f2 <<<"$prev")"
            prev_art="$(cut -f12 <<<"$prev")"
            # Only a GREEN verdict may be reused. A FAIL is a claim that the
            # script is broken and must be re-verified after the fix (reusing
            # it silently keeps a stale failure on the board).
            # A SKIP is re-tried too: the environment it named may have
            # changed.
            # The probe must hash the SAME string the recorder did: the spec's
            # args included (the recorder hashes `closure_hash "$path" "$@"`,
            # so a probe without ${args} never matched an arg-bearing row and
            # re-ran it on every pass — a full host prep included). Reuse is
            # keyed on the row's ACTUAL inputs: its closure (script + shared
            # files + argv + declared requires=extra trees) and the build-
            # artifact identity. The git revision is recorded for the report
            # but no longer gates reuse: a committed docs-only change must not
            # invalidate every row, and an UNCOMMITTED product rebuild changes
            # the artifacts and must invalidate every row (a HEAD check sees
            # neither correctly).
            # shellcheck disable=SC2086
            if [[ "$prev_art" == "$MATRIX_ARTIFACT_ID" ]] \
               && [[ "$prev_closure" == "$(closure_hash "$path" ${args:-})" ]] \
               && [[ "$prev_verdict" == "PASS" || "$prev_verdict" == "BLOCKED-PRODUCT" ]]; then
                tc_log_info "reuse [$class] $path — $prev_verdict (closure + artifacts unchanged)"
                continue
            fi
        fi
        [[ -z "$tmo" || "$tmo" == "0" ]] && tmo="$MATRIX_TIMEOUT_DEFAULT"
        [[ -z "$cleanup" ]] && cleanup="-"
        # shellcheck disable=SC2086
        run_one "$path" "$class" "$tmo" "$cleanup" ${args:-}
    done
}

# ═══════════════════════════════════════════════════════════════════════
# Library rows
# ═══════════════════════════════════════════════════════════════════════
# A library is never "run", but it still gets exactly one row: PASS when at
# least one named consumer was actually exercised, SKIP(library) otherwise.
finalize_libraries() {
    local entry path class consumers c verdict reason v
    for entry in "${MATRIX_LIB_CONSUMERS[@]}"; do
        path="${entry%%:*}"
        consumers="${entry#*:}"
        verdict="SKIP"; reason="library — no consumer ran in this matrix pass"
        for c in $consumers; do
            v="$(state_get "$c" | cut -f2)"
            if [[ "$v" == "PASS" ]]; then
                verdict="PASS"; reason="library — validated through ${c}"
                break
            elif [[ -n "$v" && "$verdict" != "PASS" ]]; then
                reason="library — consumer ${c} is ${v}, not green"
            fi
        done
        # A library that is ALSO executed as a row keeps its executed verdict;
        # only an earlier LIBRARY row is refreshed here (source is the
        # discriminator — using one value for both froze the runner's own row
        # one edit behind).
        if [[ "$(state_get "$path" | cut -f10)" == "matrix" ]]; then
            tc_log_info "library row: $path — keeps its executed verdict ($(state_get "$path" | cut -f2))"
            continue
        fi
        state_set "$path" F "$verdict" 0 0 "$(closure_hash "$path")" "$reason" "-" "" "library"
        tc_log_info "library row: $path — $verdict ($reason)"
    done
    # Every OTHER F row also needs a verdict: an F row with no consumer map
    # would stay NOT RUN and fail a complete-pass gate, though it is not
    # runnable by construction — SKIP(library) is its verdict.
    for entry in "${MATRIX_SPEC[@]}"; do
        IFS='|' read -r path class _ <<<"$entry"
        [[ "$class" == "F" ]] || continue
        [[ -n "$(state_get "$path" | cut -f2)" ]] && continue
        state_set "$path" F SKIP 0 0 "$(closure_hash "$path")" "library — no consumer mapping" "-" "" "library"
        tc_log_info "library row: $path — SKIP (no consumer mapping)"
    done
}

# ═══════════════════════════════════════════════════════════════════════
# Report
# ═══════════════════════════════════════════════════════════════════════
report() {
    MATRIX_STAMP="${MATRIX_STAMP:-$(date -u +%Y%m%dT%H%M%SZ)}"
    local out_json="$MATRIX_STATE_DIR/script-matrix-$MATRIX_TREE-$MATRIX_STAMP.json"
    local out_md="$MATRIX_STATE_DIR/script-matrix-$MATRIX_TREE-$MATRIX_STAMP.md"
    # `repo_head` names the revision the report is WRITTEN at, so the
    # "clean tree" rule must be machine-checkable from the artifact itself:
    # the dirty-entry count travels with the report (a report produced on an
    # uncommitted tree says so instead of looking like a clean-HEAD record).
    local dirty
    dirty="$(git -C "$ROOT" status --porcelain 2>/dev/null | wc -l | tr -d ' ')"
    CHECKPOINT="$CHECKPOINT" ENUM_COUNT="$ENUM_COUNT" MATRIX_ENUM_ROOT="$MATRIX_ENUM_ROOT" \
    MATRIX_TREE="$MATRIX_TREE" OUT_JSON="$out_json" OUT_MD="$out_md" \
    MATRIX_DIRTY="$dirty" \
    SPEC_JOINED="$(printf '%s\n' "${MATRIX_SPEC[@]}")" \
    ENUMERATED_JOINED="$(printf '%s\n' "${ENUMERATED[@]}")" \
    LIB_JOINED="$(printf '%s\n' "${MATRIX_LIB_CONSUMERS[@]}")" \
    MATRIX_BOOT_ID="$MATRIX_BOOT_ID" MATRIX_HEAD="$MATRIX_HEAD" python3 - <<'PY'
import json, os, collections, datetime

cp = os.environ["CHECKPOINT"]
d = json.load(open(cp)) if os.path.exists(cp) else {"rows": {}}
rows = d.get("rows", {})
enumerated = [x for x in os.environ["ENUMERATED_JOINED"].split("\n") if x]
# A checkpoint row whose path is not in the CURRENT spec belongs to a script
# that was deleted or renamed out of the tree — a stale verdict that says
# nothing about this battery (live case: a FAIL carried for weeks by a
# deleted script, read as a real failure). The spec is the row universe
# (classes A–K plus the F libraries); prune and report what was dropped.
spec_paths = {line.split("|", 1)[0] for line in
              os.environ.get("SPEC_JOINED", "").split("\n") if "|" in line}
stale_pruned = sorted(p for p in rows if p not in spec_paths)
for p in stale_pruned:
    del rows[p]
libs = {}
for line in os.environ["LIB_JOINED"].split("\n"):
    if ":" in line:
        k, v = line.split(":", 1)
        libs[k] = v.split()

def md_cell(s):
    """A reason is script-authored text: an unescaped `|` splits the table
    row into extra columns and a backtick opens a code span inside it."""
    return (str(s).replace("\\", "\\\\").replace("|", "\\|")
            .replace("`", "\\`").replace("\n", " ").strip())

missing = [f for f in enumerated if f not in rows]
duplicate = [f for f, c in collections.Counter(enumerated).items() if c > 1]
f_rows_without_consumer = []
for f, consumers in libs.items():
    if f not in rows:
        continue
    if not any(rows.get(c, {}).get("verdict") in ("PASS", "SKIP", "BLOCKED-PRODUCT") for c in consumers):
        f_rows_without_consumer.append(f)

counts = collections.Counter(r.get("verdict", "?") for r in rows.values())
by_class = collections.Counter(r.get("class", "?") for r in rows.values())
# Which revision each row was actually produced at — the field that makes a
# MIXED ledger visible instead of silently labelling every row with the
# current checkout (`repo_head` is only the revision this report was written
# at). Reuse is head-scoped, so a mixed set means rows from an earlier pass.
heads = collections.Counter((str(r.get("head", "")) or "<none>") for r in rows.values())
j = {
    "tree": os.environ["MATRIX_TREE"],
    "generated": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "boot_id": os.environ["MATRIX_BOOT_ID"],
    "repo_head": os.environ["MATRIX_HEAD"],
    "tree_dirty": int(os.environ.get("MATRIX_DIRTY", "0") or 0),
    "heads": dict(heads),
    "self_check": {
        "enumerated": int(os.environ["ENUM_COUNT"]),
        "rows": len(rows),
        "missing": missing,
        "duplicate": duplicate,
        "unclassified": [],
        "f_rows_without_consumer": f_rows_without_consumer,
        "stale_pruned": stale_pruned,
        "rows_eq_enumerated": int(os.environ["ENUM_COUNT"]) == len(rows) - len(f_rows_without_consumer),
    },
    "counts": dict(counts),
    "counts_by_class": dict(by_class),
    "rows": rows,
}
json.dump(j, open(os.environ["OUT_JSON"], "w"), indent=1, sort_keys=True)

spec_map = {}
for line in os.environ.get("SPEC_JOINED", "").split("\n"):
    if "|" in line:
        spec_map[line.split("|")[0]] = line.split("|")[1]
heads_txt = " · ".join(f"{h[:12]}={n}" for h, n in sorted(heads.items()))
lines = [f"# Script matrix — every .sh under {os.environ['MATRIX_ENUM_ROOT']}/",
         "",
         f"Generated {j['generated']} · repo {os.environ['MATRIX_HEAD'][:12]} · "
         f"tree_dirty={j['tree_dirty']} · boot `{os.environ['MATRIX_BOOT_ID'][:8]}`",
         f"Heads (row counts): {heads_txt or 'none'}",
         f"Enumerated **{os.environ['ENUM_COUNT']}** scripts · rows **{len(rows)}** · "
         + " · ".join(f"{k}={v}" for k, v in sorted(counts.items())),
         "",
         "| script | class | verdict | secs | reason / finding |",
         "|---|---|---|---|---|"]
for f in enumerated:
    r = rows.get(f)
    if not r:
        lines.append(f"| `{f}` | {spec_map.get(f, '?')} | **NOT RUN** | | |")
        continue
    note = r.get("reason", "") or ("finding " + r["finding_id"] if r.get("finding_id") else "")
    lines.append(f"| `{f}` | {r.get('class','')} | {r.get('verdict','')} | {r.get('seconds',0)} | {md_cell(note)} |")
sc = j["self_check"]
lines += ["", "## Self-check", "",
          f"- enumerated == rows: **{sc['rows_eq_enumerated']}** ({sc['enumerated']} enumerated, {len(rows)} rows)",
          f"- missing: {sc['missing'] or 'none'}",
          f"- duplicate: {sc['duplicate'] or 'none'}",
          f"- library rows without a consumer verdict: {sc['f_rows_without_consumer'] or 'none'}"]
open(os.environ["OUT_MD"], "w").write("\n".join(lines) + "\n")
print("wrote", os.environ["OUT_JSON"])
print("wrote", os.environ["OUT_MD"])
print("rows=%d %s" % (len(rows), dict(counts)))
PY
    echo "$out_json" > "$MATRIX_STATE_DIR/last-report.txt"
}

# ═══════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════
matrix_usage() { sed -n '/^# Usage:/,/^$/p' "$MATRIX_RUNNER" | sed 's/^# \{0,1\}//'; }

matrix_parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --phase) PHASE="$2"; shift 2 ;;
            --only) ONLY="$2"; shift 2 ;;
            --force) FORCE=1; shift ;;
            --fast) FAST=1; shift ;;
            --report) REPORT_ONLY=1; shift ;;
            --list) LIST=1; shift ;;
            -h|--help) matrix_usage; exit 0 ;;
            *) echo "unknown flag: $1" >&2; exit 2 ;;
        esac
    done
}

matrix_main() {
    matrix_parse_args "$@"
    if [[ "$REPORT_ONLY" != "1" && "$LIST" != "1" ]]; then
        matrix_preflight
        matrix_requires_preflight || exit 1
        matrix_resource_preflight || exit 1
    fi
    matrix_selftest
    local rc=$?
    [[ $rc -eq 3 ]] && exit 0        # --list
    [[ $rc -ne 0 ]] && exit 1        # self-check failed

    if [[ "$REPORT_ONLY" == "1" ]]; then finalize_libraries; report; exit 0; fi
    # An unusable or foreign ledger is a refusal: state_init exits non-zero
    # (naming the file and the remedy) and the matrix must not proceed to
    # write rows into it or around it.
    state_init || exit 1

    # A "complete pass" is the default phase set with no --only: only that
    # run demands a verdict for every enumerated row (the gate's NOT RUN rule).
    local full_run=0
    [[ "$PHASE" == "all" && -z "$ONLY" ]] && full_run=1

    # Phase list: an explicit --phase X[,Y] wins; "all" (the default) is the
    # tree's own order, declared by the runner.
    if [[ "$PHASE" == "all" ]] && declare -F matrix_default_phases >/dev/null 2>&1; then
        read -r -a MATRIX_PHASES <<< "$(matrix_default_phases)"
    else
        IFS=',' read -r -a MATRIX_PHASES <<< "$PHASE"
    fi
    [[ "${#MATRIX_PHASES[@]}" -gt 0 ]] || MATRIX_PHASES=(C)
    local ph
    for ph in "${MATRIX_PHASES[@]}"; do
        if declare -F "matrix_phase_$ph" >/dev/null 2>&1; then
            "matrix_phase_$ph"
        else
            matrix_run_generic "$ph"
        fi
    done
    if [[ "$full_run" == "1" ]]; then
        tc_log_section "FINAL CLEANUP ($MATRIX_TREE)"
        if declare -F matrix_final_cleanup >/dev/null 2>&1; then
            matrix_final_cleanup
        else
            env_sweep
        fi
        MATRIX_RESIDUE="$(matrix_final_verify 2>/dev/null || true)"
        if [[ -n "$MATRIX_RESIDUE" ]]; then
            tc_log_error "final cleanup left residue: $MATRIX_RESIDUE"
        else
            tc_log_pass "final cleanup: environment clean"
        fi
    fi
    finalize_libraries
    report
    matrix_gate "$full_run" || exit 1
}

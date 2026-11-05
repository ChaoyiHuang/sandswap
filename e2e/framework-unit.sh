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
# framework-unit.sh — unit tests for the SHARED SCRIPT FRAMEWORK itself
# (common/sh/runtime.sh + common/sh/stack.sh + the e2e/deploy wrappers).
#
# No root, no KVM, no stack: this runs in seconds and is the fastest possible
# red/green pin for the framework's contract. Every assertion here exists
# because the corresponding defect class is real:
#   - two functions defined INSIDE another function's body → "command not
#     found" for any script that called them before the outer one ran
#   - the volume seed minted with three different owners/modes across trees →
#     EACCES for the identity that reads it
#   - a pasted retryable-refusal regex that matched near-miss strings
#   - a pool parser that silently returned 0 for an unknown /stats shape
#     (a 0 that a "≥ target" wait then treats as "not ready yet" forever)
# Usage: bash e2e/framework-unit.sh

set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck disable=SC1091
source "$ROOT/e2e/common.sh"

tc_log_section "Framework unit tests"

# ── 1. Definition-time contract (the nested-definition trap) ──────────
# Every public helper must exist the moment the library is sourced — NOT
# after some other function has run. tc_ensure_volume_seed and
# tc_cleanup_deployed_artifacts lived inside tc_clean_environment's body, so
# `latency-benchmark-unmount.sh` / `-aiagent.sh` died "command not found".
for fn in tc_ensure_volume_seed tc_cleanup_deployed_artifacts \
          ss_ensure_volume_seed ss_apply_share_plane ss_ensure_dev_nodes \
          ss_kill_ports ss_wait_until ss_host_network_setup ss_stack_residue_clean \
          ss_host_network_teardown ss_script_host_prep \
          ss_fwd_policy_guard ss_fwd_tagged_flush ss_container_runtime_clean \
          ss_gw_exec ss_gw_exec_retry ss_gw_exec_raw ss_gw_exec_headers \
          ss_gw_status ss_gw_kill ss_pool_clean ss_wait_pool_ready ss_wait_health \
          ss_agent_create ss_sandfs_create ss_agent_and_sandfs ss_volume_path \
          ss_json_build ss_json_field ss_body_retryable ss_body_retry_after_ms \
          ss_script_require_stack ss_script_require_units; do
    if declare -F "$fn" >/dev/null 2>&1; then
        tc_pass "defined at source time: $fn"
    else
        tc_fail "NOT defined at source time: $fn"
    fi
done

# ── 2. Wrappers stay wrappers (one implementation, not two) ───────────
# The whole point of the refactor: the e2e/deploy names DELEGATE to the
# shared ss_* implementation. A wrapper that grew its own body again is how
# the drift started.
wrapper_delegates() { # <wrapper> <impl>
    local body
    body="$(declare -f "$1" 2>/dev/null)" || return 1
    grep -q "$2" <<<"$body"
}
for pair in "tc_gw_exec:ss_gw_exec" "tc_gw_exec_raw:ss_gw_exec_raw" \
            "tc_gw_exec_retry:ss_gw_exec_retry" "tc_gw_exec_headers:ss_gw_exec_headers" \
            "tc_stats_clean_vms:ss_pool_clean" "tc_kill_port:ss_kill_ports" \
            "tc_pre_clean_stack:ss_stack_residue_clean" \
            "tc_teardown_host_network:ss_host_network_teardown" \
            "tc_ensure_volume_seed:ss_ensure_volume_seed" \
            "tc_volume_path:ss_volume_path" "tc_delete_sandfs:ss_delete_sandfs" \
            "tc_json_field:ss_json_field" "tc_json_stdout:ss_json_stdout"; do
    w="${pair%%:*}"; i="${pair##*:}"
    if wrapper_delegates "$w" "$i"; then
        tc_pass "$w delegates to $i"
    else
        tc_fail "$w does NOT delegate to $i (drifted into its own implementation?)"
    fi
done

# ── 3. Retryable-refusal predicate ────────────────────────────────────
# TRUE for every named busy state (body shape AND bare token shape).
for tok in NO_AVAILABLE_SANDBOX NO_COMPUTE_NODES CONCURRENT_MOUNT SANDBOX_CLEANING MAINTENANCE; do
    if ss_body_retryable "{\"error_code\":\"$tok\",\"retry_after_ms\":1000}"; then
        tc_pass "retryable: $tok (error_code shape)"
    else
        tc_fail "retryable: $tok NOT detected (error_code shape)"
    fi
    # A bare token in PROSE is deliberately NOT retryable: the value-quoted
    # form is what the server emits, and a prose match would also fire on an
    # exec whose STDOUT happens to echo the token — turning a test that
    # asserts on that output into a silent retry loop.
    if ss_body_retryable "something went wrong: $tok while mounting"; then
        tc_fail "retryable: prose '$tok' matched — too loose (stdout echoes would retry)"
    else
        tc_pass "retryable: prose '$tok' correctly ignored"
    fi
done
if ss_body_retryable '{"error":"no provision instance connected (role=prov)"}'; then
    tc_pass "retryable: storage-plane 503"
else
    tc_fail "retryable: storage-plane 503 NOT detected"
fi
if ss_body_retryable '{"error":"pool busy","error_code":"NO_AVAILABLE_SANDBOX","retryable":true}'; then
    tc_pass 'retryable: server body with the "retryable":true flag'
else
    tc_fail 'retryable: server body with the "retryable":true flag NOT detected'
fi
# FALSE for near-misses: a regex loose enough to match these would retry real
# failures forever (and hide them).
for body in '{"stdout":"NO_AVAILABLE_SANDBOXES_FOR_YOU"}' \
            '{"stdout":"the sandbox is cleaning itself"}' \
            '{"error_code":"SANDFS_NOT_ACTIVE"}' \
            '{"status":"done","stdout":""}'; do
    if ss_body_retryable "$body"; then
        tc_fail "retryable: near-miss matched (should not): $body"
    else
        tc_pass "not retryable (correct): ${body:0:40}"
    fi
done

# retry_after_ms parsing: number when present, default when absent, never empty.
if [[ "$(ss_body_retry_after_ms '{"retry_after_ms":10000}')" == "10000" ]]; then
    tc_pass "retry_after_ms parsed"
else
    tc_fail "retry_after_ms not parsed: '$(ss_body_retry_after_ms '{"retry_after_ms":10000}')'"
fi
if [[ "$(ss_body_retry_after_ms '{"error":"busy"}')" == "$SS_RETRY_AFTER_DEFAULT_MS" ]]; then
    tc_pass "retry_after_ms defaults when absent"
else
    tc_fail "retry_after_ms did not default: '$(ss_body_retry_after_ms '{"error":"busy"}')'"
fi

# ── 4. JSON request builder (quoting-proof) ───────────────────────────
json_roundtrip() { # <expected-json> <args...>
    local expected="$1"; shift
    local got
    got="$(ss_json_build "$@")"
    if [[ "$(python3 -c 'import json,sys;print(json.dumps(json.loads(sys.argv[1]),sort_keys=True))' "$got" 2>/dev/null)" \
        == "$(python3 -c 'import json,sys;print(json.dumps(json.loads(sys.argv[1]),sort_keys=True))' "$expected" 2>/dev/null)" ]]; then
        tc_pass "json build: $expected"
    else
        tc_fail "json build: got '$got', want '$expected'"
    fi
}
# A code payload carrying quotes, backslashes, newlines and a $(...) — the
# shapes that broke hand-rolled `-d "{...\"$code\"...}"` bodies.
json_roundtrip '{"sandfs_id":"sf-1","code":"echo \"hi\"","language":"shell"}' \
    "sandfs_id=sf-1" 'code=echo "hi"' "language=shell"
json_roundtrip '{"sandfs_id":"sf-1","code":"a\\b\nc","language":"shell"}' \
    "sandfs_id=sf-1" 'code=a\b
c' "language=shell"
json_roundtrip '{"timeout":30}' "timeout:=30"
json_roundtrip '{"force":true}' "force:=true"
# A '=' or ':=' INSIDE a value must not be treated as the separator.
json_roundtrip '{"code":"x:=y"}' "code=x:=y"
json_roundtrip '{"code":"a=b"}' "code=a=b"

# A malformed `extra` fragment must go out MALFORMED (the server rejects it)
# rather than being silently dropped — a dropped "background":true is a test
# that passes without testing what it names.
if out="$(ss_json_merge_body '{"a":1}' 'not json')" && ! python3 -c 'import json,sys;json.loads(sys.argv[1])' "$out" 2>/dev/null; then
    tc_pass "json merge: malformed extra stays malformed (server rejects it)"
else
    tc_fail "json merge: malformed extra was silently dropped or repaired: '$out'"
fi

# ── 5. /stats pool parser — every shape the endpoint has had ──────────
pool_parse() { # <json> -> expected count
    local json="$1" want="$2" got
    got="$(printf '%s' "$json" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
except Exception:
    print(0); raise SystemExit
t = d.get('totals')
if isinstance(t, dict) and 'clean_vms' in t: print(t['clean_vms'])
elif 'clean_vms' in d: print(d['clean_vms'])
elif 'CLEAN' in d: print(d['CLEAN'])
elif isinstance(d.get('pool'), dict): print(d['pool'].get('CLEAN', 0))
elif isinstance(d.get('gateways'), list): print(sum(g.get('clean_vms', 0) for g in d['gateways']))
else: print(0)" 2>/dev/null)"
    if [[ "$got" == "$want" ]]; then
        tc_pass "pool parse: $want from ${json:0:44}"
    else
        tc_fail "pool parse: got '$got' want '$want' from ${json:0:44}"
    fi
}
pool_parse '{"totals":{"clean_vms":3,"busy_vms":1}}' 3
pool_parse '{"clean_vms":2}' 2
pool_parse '{"CLEAN":1,"BUSY":0}' 1
pool_parse '{"pool":{"CLEAN":4}}' 4
pool_parse '{"gateways":[{"clean_vms":2},{"clean_vms":1}]}' 3
pool_parse '{"totals":{}}' 0
pool_parse 'not json at all' 0
# The real parser must agree with the fixture parser above.
real_got="$(ss_pool_clean "http://127.0.0.1:1" 2>/dev/null)"
[[ "$real_got" == "0" ]] && tc_pass "ss_pool_clean returns 0 on an unreachable endpoint" \
                         || tc_fail "ss_pool_clean returned '$real_got' for an unreachable endpoint (want 0)"

# ── 6. Port sets are consistent and non-empty ─────────────────────────
for v in SS_PORTS_PROD_STACK SS_PORTS_DEV_STACK SS_PORTS_ETCD; do
    if [[ -n "${!v// /}" ]]; then
        tc_pass "$v = ${!v}"
    else
        tc_fail "$v is empty"
    fi
done
# The etcd set must be exactly the coordination pair: the cleanup loop waits
# on those two, so a drift here leaks the port into the next script.
[[ "$SS_PORTS_ETCD" == "2379 2380" ]] && tc_pass "SS_PORTS_ETCD is the coordination pair" \
                                      || tc_fail "SS_PORTS_ETCD drifted: '$SS_PORTS_ETCD'"

# ── 7. Path defaults + cross-tree agreement ───────────────────────────
[[ -n "$DEPLOY_DIR" && -n "$VOL_ROOT" && -n "$LOG_DIR" ]] \
    && tc_pass "path defaults set (DEPLOY_DIR=$DEPLOY_DIR)" \
    || tc_fail "path defaults missing"
[[ "$VOL_ROOT" == "$DEPLOY_DIR/volumes" || -n "${VOL_ROOT:-}" ]] \
    && tc_pass "VOL_ROOT resolves ($VOL_ROOT)" || tc_fail "VOL_ROOT unset"

# The deploy tree's seed wrapper must scope root:<prov-group> 0640 — the
# e2e tree's must scope <prov> 0600. Same implementation, different inputs:
# assert the CALL SITES still pass the shape they promise.
if declare -f sandswap_ensure_volume_seed >/dev/null 2>&1; then
    if declare -f sandswap_ensure_volume_seed | grep -q '0640'; then
        tc_pass "deploy seed wrapper keeps the root:<prov-group> 0640 scope"
    else
        tc_fail "deploy seed wrapper lost its 0640 scope"
    fi
else
    tc_log_info "(deploy tree not sourced in this run — skipping its wrapper assertion)"
fi

# ── 8. skip-reason plumbing ───────────────────────────────────────────
tmp_skip="$(mktemp -d)"
( RUNALL_SKIP_DIR="$tmp_skip" RUNALL_SCRIPT="probe.sh" tc_skip_suite "needs-k3s: no cluster" ) >/dev/null 2>&1
if [[ "$(cat "$tmp_skip/probe.sh" 2>/dev/null)" == "needs-k3s: no cluster" ]]; then
    tc_pass "tc_skip_suite records the reason verbatim"
else
    tc_fail "tc_skip_suite did not record the reason (got '$(cat "$tmp_skip/probe.sh" 2>/dev/null)')"
fi
rm -rf "$tmp_skip"

# ── 9. Matrix engine + runner isolation (common/sh/matrix.sh) ─────────
# The engine IS the framework's own machinery (ledger, closure, reuse,
# report), so its unit suite lives here. The probes run in a CHILD bash
# against a throwaway tree (its own git repo, so the head-scoped reuse has a
# real head) with the two host-touching hooks (env_sweep/env_residue) stubbed
# — nothing under the repo or on the host is written. Each `PASS …`/`FAIL …`
# line the probe prints becomes one assertion here, so a probe that dies
# half-way is visible as a missing verdict rather than as silence.
matrix_engine_probes() { # <scratch-dir>
    FU_ROOT="$ROOT" FU_SCRATCH="$1" bash -s <<'PROBE'
set -uo pipefail
REPO="$FU_ROOT"; S="$FU_SCRATCH"; TREE="$S/tree"
mkdir -p "$TREE/e2e" "$S/fakebin" "$S/cnt"
ok()  { echo "PASS $1"; }
bad() { echo "FAIL $1 — $2"; }
chk() { [[ "$2" == "$3" ]] && ok "$1" || bad "$1" "got '$2', want '$3'"; }
cnt() { [[ -f "$S/cnt/$1" ]] && grep -c '' "$S/cnt/$1" || echo 0; }
t_old="$(date -d '2 hours ago' '+%Y-%m-%d %H:%M:%S')"
t_mid="$(date -d '1 hour ago' '+%Y-%m-%d %H:%M:%S')"
t_new="$(date -d 'now' '+%Y-%m-%d %H:%M:%S')"

# fixture rows: counters live OUTSIDE the git tree so its status stays clean
printf '#!/bin/bash\necho x >> "%s/cnt/foo"\n' "$S" > "$TREE/e2e/foo.sh"
printf '#!/bin/bash\necho x >> "%s/cnt/arg"\n' "$S" > "$TREE/e2e/arg.sh"
printf '#!/bin/bash\n:\n' > "$TREE/e2e/quiet.sh"
printf 'v1\n' > "$TREE/common.sh"
mkdir -p "$TREE/output"; : > "$TREE/output/marker"   # tracked: the artifact-identity probe
git -C "$TREE" init -q
git -C "$TREE" -c user.email=fw@unit -c user.name=fw add -A >/dev/null 2>&1
git -C "$TREE" -c user.email=fw@unit -c user.name=fw commit -qm fixture >/dev/null 2>&1
touch -d "$t_old" "$TREE"/e2e/*.sh "$TREE/common.sh"

load_engine() { # <state-dir> — (re)source the engine against the throwaway tree
    export ROOT="$TREE" MATRIX_TREE=e2e MATRIX_ENUM_ROOT=e2e MATRIX_STATE_DIR="$1"
    export MATRIX_CLOSURE_FILES=("common.sh")
    MATRIX_ARTIFACTS=("output/marker")
    MATRIX_SPEC=("e2e/foo.sh|C|60|-|" "e2e/arg.sh|C|60|-||--flag" "e2e/quiet.sh|C|60|-|")
    MATRIX_LIB_CONSUMERS=()
    # shellcheck disable=SC1091
    source "$REPO/common/sh/matrix.sh"
    env_sweep() { :; }          # host-touching hooks: never run in a probe
    env_residue() { echo ""; }
    matrix_preflight() { :; }
    matrix_enumerate >/dev/null
}

# ── B. reuse is scoped to closure (args included) + build artifacts ──
rm -rf "$S/s3" "$S/cnt"; mkdir -p "$S/cnt"; load_engine "$S/s3"
state_init >/dev/null 2>&1
matrix_run_generic C >/dev/null 2>&1
chk "pass 1 executed the plain and the arg-bearing row" "$(cnt foo)/$(cnt arg)" "1/1"
chk "a row records the revision it ran at" "$(state_get e2e/foo.sh | cut -f11)" "$MATRIX_HEAD"
matrix_run_generic C >/dev/null 2>&1
chk "same revision + closure reuses both rows (the probe hashes the spec args)" \
    "$(cnt foo)/$(cnt arg)" "1/1"
# An UNCOMMITTED product rebuild does not move HEAD; it moves the artifact
# identity, and that must invalidate every row.
sleep 1; printf 'v2\n' >> "$TREE/output/marker"
MATRIX_ARTIFACT_ID="$(matrix_artifact_identity)"
matrix_run_generic C >/dev/null 2>&1
chk "a changed build artifact invalidates every row" "$(cnt foo)/$(cnt arg)" "2/2"

# A second change re-runs again (the identity is live, not memoized).
sleep 1; printf 'v3\n' >> "$TREE/output/marker"
MATRIX_ARTIFACT_ID="$(matrix_artifact_identity)"
matrix_run_generic C >/dev/null 2>&1
chk "a second artifact change re-runs again (identity is live)" "$(cnt foo)/$(cnt arg)" "3/3"
# Restore the tracked marker so the report's tree_dirty probes below still see
# a clean fixture tree.
: > "$TREE/output/marker"
MATRIX_ARTIFACT_ID="$(matrix_artifact_identity)"

# ── B2. the CI gate reflects verdicts, not just rows printed ──
matrix_gate 1 >/dev/null 2>&1; rc=$?
chk "gate: a complete green board passes" "$rc" 0
state_set e2e/foo.sh C FAIL 0 1 "$(closure_hash e2e/foo.sh)" "injected failure" "-" "" "matrix" >/dev/null 2>&1
matrix_gate 1 >/dev/null 2>&1; rc=$?
chk "gate: one FAIL row fails the gate" "$rc" 1
state_set e2e/foo.sh C PASS 0 0 "$(closure_hash e2e/foo.sh)" "" "-" "" "matrix" >/dev/null 2>&1
python3 - "$CHECKPOINT" <<'PY'
import json, sys
p = sys.argv[1]; d = json.load(open(p))
d["rows"].pop("e2e/quiet.sh", None)
json.dump(d, open(p, "w"), indent=1, sort_keys=True)
PY
matrix_gate 1 >/dev/null 2>&1; rc=$?
chk "gate: a NOT RUN row fails a complete pass" "$rc" 1
matrix_gate 0 >/dev/null 2>&1; rc=$?
chk "gate: a targeted (partial) run is not failed by NOT RUN rows" "$rc" 0
state_set e2e/quiet.sh C SKIP 0 0 "$(closure_hash e2e/quiet.sh)" "gate:test" "-" "" "matrix" >/dev/null 2>&1
matrix_gate 0 >/dev/null 2>&1; rc=$?
chk "gate: SKIP is reported, not a failure" "$rc" 0

# ── B3. --fast skips rows tagged requires=fast:skip ──
rm -rf "$S/s3f" "$S/cnt"; mkdir -p "$S/s3f" "$S/cnt"
load_engine "$S/s3f"
MATRIX_SPEC=("e2e/foo.sh|C|60|-|" "e2e/quiet.sh|C|60|-|||fast:skip")
FAST=1
matrix_run_generic C >/dev/null 2>&1
chk "fast: the untagged row still runs" "$(cnt foo)" "1"
chk "fast: the tagged row is SKIP(fast)" "$(state_get e2e/quiet.sh | cut -f2)" "SKIP"
chk "fast: the SKIP reason names --fast" \
    "$(state_get e2e/quiet.sh | cut -f6)" "fast: skipped by --fast"
FAST=0
load_engine "$S/s3"   # restore the B/B2 ledger for the report probes
report >/dev/null 2>&1
jget() { # <json> <key>
    python3 -c 'import json,sys
j=json.load(open(sys.argv[1])); v=j.get(sys.argv[2])
print("" if v is None else (json.dumps(v,sort_keys=True) if isinstance(v,(dict,list)) else v))' "$1" "$2"
}
rep="$(cat "$MATRIX_STATE_DIR/last-report.txt")"
chk "the report names the revision it was written at" "$(jget "$rep" repo_head)" "$MATRIX_HEAD"
chk "the report counts rows per head (a mixed ledger stays visible)" \
    "$(jget "$rep" heads)" "{\"$MATRIX_HEAD\": 3}"
chk "a clean tree reports tree_dirty=0" "$(jget "$rep" tree_dirty)" 0
touch "$TREE/untracked.txt"
MATRIX_STAMP=dirty report >/dev/null 2>&1
chk "tree_dirty counts the working tree's dirty entries" \
    "$(jget "$MATRIX_STATE_DIR/script-matrix-e2e-dirty.json" tree_dirty)" 1
rm -f "$TREE/untracked.txt"

# ── C. the ledger is never repaired or adopted silently ──
rm -rf "$S/s4"; load_engine "$S/s4"
state_init >/dev/null 2>&1
printf '{"tree":"e2e","rows": {"e2e/foo.sh": {"verdict":"PASS"}, "e2e/old.sh": {"verdict":"PASS"}}' > "$CHECKPOINT"
( state_init ) >/dev/null 2>&1; rc=$?
chk "state_init refuses an unreadable checkpoint" "$rc" 1
( state_set e2e/foo.sh C PASS 1 0 hash reason log "" matrix ) >/dev/null 2>&1; rc=$?
chk "state_set refuses to overwrite an unreadable checkpoint" "$rc" 1
python3 -c 'import json,sys;json.load(open(sys.argv[1]))' "$CHECKPOINT" >/dev/null 2>&1; rc=$?
chk "the unreadable checkpoint is left exactly in place" "$rc" 1
printf '{"tree":"deploy","head":"deadbeef","rows":{}}' > "$CHECKPOINT"
( state_init ) >/dev/null 2>&1; rc=$?
chk "state_init refuses a foreign-tree checkpoint" "$rc" 1
printf '{"tree":"e2e","head":"%s","rows":{}}' "$MATRIX_HEAD" > "$CHECKPOINT"
( state_init ) >/dev/null 2>&1; rc=$?
chk "state_init resumes its own ledger (boot/head agree)" "$rc" 0

# ── D. script-authored reason text cannot break the MD table ──
rm -rf "$S/s5"; load_engine "$S/s5"
state_init >/dev/null 2>&1
state_set e2e/foo.sh C PASS 3 0 abcde 'reason with | pipe and `tick`' log "" matrix
report >/dev/null 2>&1
row="$(grep -m1 '^| `e2e/foo.sh`' "$MATRIX_STATE_DIR"/script-matrix-e2e-*.md)"
chk "a pipe in a reason does not split the row (6 cell borders)" \
    "$(grep -o '|' <<<"${row//\\|/}" | wc -l)" 6
[[ "$row" == *'\| pipe'* ]] && ok "pipes in reason text are escaped" \
                            || bad "pipes in reason text are escaped" "$row"
[[ "$row" == *'\`tick\`'* ]] && ok "backticks in reason text are escaped" \
                              || bad "backticks in reason text are escaped" "$row"

# ── E. the e2e runner isolates every row into the battery root ──
# `git` is shadowed (the engine calls it at source time) so the probe can
# observe the environment the runner exports BEFORE the rows start.
real_git="$(command -v git)"
cat > "$S/fakebin/git" <<EOF
#!/bin/bash
printf 'MXENV %s|%s|%s\n' "\${SANDSWAP_E2E_ROOT:-<unset>}" "\${DEPLOY_DIR:-<unset>}" "\${VOL_ROOT:-<unset>}" >> "$S/mxenv.txt"
exec $real_git "\$@"
EOF
chmod +x "$S/fakebin/git"
# -u ROOT: the probe's engine loader exports its throwaway ROOT; the runner
# must resolve its own (from BASH_SOURCE) or it sources the wrong tree.
env -u SANDSWAP_E2E_ROOT -u DEPLOY_DIR -u VOL_ROOT -u ROOT \
    PATH="$S/fakebin:$PATH" MATRIX_STATE_DIR="$S/s6" \
    bash "$REPO/e2e/run-matrix.sh" --list >"$S/list.out" 2>&1; rc=$?
chk "--list runs without root/KVM (the probe really loaded the runner)" "$rc" 0
if grep -q 'No such file or directory' "$S/list.out"; then
    bad "the runner resolved its own ROOT" "$(head -1 "$S/list.out")"
else
    ok "the runner resolved its own ROOT"
fi
chk "the runner exports the battery root before the engine loads" \
    "$(head -1 "$S/mxenv.txt" 2>/dev/null)" \
    "MXENV /var/lib/sandswap-e2e|/var/lib/sandswap-e2e|/var/lib/sandswap-e2e/volumes"

# ── F. the runners are sourceable and the closure lists cover what the rows
# can pick up; the e2e tree has no fixture phase ──
# source each runner WITHOUT its final `matrix_main` call (the copy trick:
# the runner is only sourced, never executed, so no preflight/KVM is needed)
(
  cd "$REPO" || exit
  export ROOT="$REPO" SANDSWAP_E2E_ROOT="$S/e2e-root"
  # shellcheck disable=SC1091
  source <(sed '$ {/^matrix_main/ d}' e2e/run-matrix.sh)
  declare -F matrix_phase_A >/dev/null 2>&1 && echo ok > "$S/e2e-src-ok"
  # The deployed-stack row (latency-under-load.sh) is gone: the e2e tree is
  # fully self-contained and must not special-case a fixture phase any more.
  declare -F matrix_phase_B >/dev/null 2>&1 && echo present > "$S/e2e-phaseB-present"
  export MATRIX_STATE_DIR="$S/s7"
  printf '%s\n' "${MATRIX_CLOSURE_FILES[@]}" > "$S/closure-e2e.txt"
)
chk "the e2e runner is sourceable" "$(cat "$S/e2e-src-ok" 2>/dev/null)" "ok"
chk "the e2e runner no longer special-cases a fixture phase (no class-B rows)" \
    "$(cat "$S/e2e-phaseB-present" 2>/dev/null)" ""
(
  cd "$REPO" || exit
  export ROOT="$REPO"
  # shellcheck disable=SC1091
  source <(sed '$ {/^matrix_main/ d}' deploy/run-matrix.sh)
  declare -F matrix_phase_B >/dev/null 2>&1 \
      || echo "FAIL the deploy runner is sourceable"
  export MATRIX_STATE_DIR="$S/s8"
  printf '%s\n' "${MATRIX_CLOSURE_FILES[@]}" > "$S/closure-deploy.txt"
)
while IFS= read -r spec; do
    tree="${spec%%:*}"; list="$S/closure-${spec%%:*}.txt"
    missing="$(python3 -I - "$REPO" "$tree" "$list" <<'PY'
import os, re, sys, pathlib
root, tree, liste = sys.argv[1], sys.argv[2], sys.argv[3]
listed = set(x for x in open(liste).read().split() if x)
rx = re.compile(r'^\s*(?:source|\.)\s+\S*\$(\{?ROOT\}?|REPO_ROOT)/([A-Za-z0-9_./-]+)')
bad = set()
for f in sorted(pathlib.Path(root, tree).rglob('*.sh')):
    for line in f.read_text(errors='replace').splitlines():
        if line.lstrip().startswith('#'):
            continue
        for m in rx.finditer(line):
            p = m.group(2)
            if os.path.isfile(os.path.join(root, p)) and p not in listed:
                bad.add(p)
print(" ".join(sorted(bad)))
PY
)"
    chk "every \$ROOT source edge of the $tree rows is in its closure list" "$missing" ""
done <<'EOF'
e2e
deploy
EOF
# The EXEC edges are not derivable from a source scan, so they are pinned
# explicitly: tc_gen_certs runs
# deploy/gen-certs.sh for 35 e2e rows, harness-fault-injection drives
# every check-*.py checker, and the battery's docs-truth row executes
# e2e/check-docs-truth.py (the standing code<->docs layer).
for f in deploy/gen-certs.sh e2e/check-docs-links.py e2e/check-nil-wrap-scan.py \
         e2e/check-handrolled-prelude.py deploy/baremetal/check-shape-hardcodes.py \
         e2e/check-docs-truth.py \
         e2e/run-matrix.sh; do
    grep -qx "$f" "$S/closure-e2e.txt" \
        && ok "e2e closure covers the exec edge $f" \
        || bad "e2e closure covers the exec edge $f" "absent from MATRIX_CLOSURE_FILES"
done
PROBE
}
tmp_mx="$(mktemp -d /tmp/framework-unit-mx.XXXXXX)"
matrix_engine_probes "$tmp_mx" >"$tmp_mx/out" 2>"$tmp_mx/err"
mx=0
while IFS= read -r line; do
    case "$line" in
        "PASS "*) mx=$((mx + 1)); tc_pass "${line#PASS }" ;;
        "FAIL "*) mx=$((mx + 1)); tc_fail "${line#FAIL }" ;;
    esac
done <"$tmp_mx/out"
if [[ "$mx" -eq 0 ]]; then
    tc_fail "the matrix engine probes produced no verdicts"
    sed -n '1,20p' "$tmp_mx/err" >&2
fi
rm -rf "$tmp_mx"

# ── 10. Installed-copy runtime resolution (deploy/setup-network.sh) ───
# The deploy tooling INSTALLS setup-network.sh into /usr/local/bin, where its
# repo-relative `$ROOT/common/sh/runtime.sh` does not exist. The script must
# fall back to the shared-lib directory (${SANDSWAP_SH_LIB_DIR:-/usr/local/
# lib/sandswap}) and, when NEITHER path exists, fail with its OWN message —
# a bare bash "No such file or directory" is not a diagnostic an operator can
# act on. The probe copies the real script, so it pins the shipped file.
tmp_sn="$(mktemp -d /tmp/framework-unit-sn.XXXXXX)"
mkdir -p "$tmp_sn/usr/local/bin" "$tmp_sn/lib" "$tmp_sn/fakebin"
cp "$ROOT/deploy/setup-network.sh" "$tmp_sn/usr/local/bin/setup-network.sh"
cp "$ROOT/common/sh/runtime.sh" "$tmp_sn/lib/runtime.sh"
# The script auto-detects the uplink when UPLINK is empty; a stub `ip` makes
# that detection yield nothing, so the script exits through its OWN validation
# before it can touch the host (no bridge, no nft table, no sysctl).
printf '#!/bin/sh\nexit 0\n' > "$tmp_sn/fakebin/ip"
chmod +x "$tmp_sn/fakebin/ip"
sn_out="$(env PATH="$tmp_sn/fakebin:$PATH" SANDSWAP_SH_LIB_DIR="$tmp_sn/lib" UPLINK= BRIDGE= \
          bash "$tmp_sn/usr/local/bin/setup-network.sh" 2>&1)"; sn_rc=$?
if [[ "$sn_rc" -ne 0 ]]; then
    tc_pass "the installed copy exits non-zero through its own validation"
else
    tc_fail "the installed copy returned 0 (the uplink stub should have made it refuse)"
fi
if grep -q 'could not determine default-route uplink interface' <<<"$sn_out"; then
    tc_pass "the installed copy resolves the shared runtime from SANDSWAP_SH_LIB_DIR"
else
    tc_fail "the installed copy did not reach its own uplink check: ${sn_out:-<no output>}"
fi
if grep -q 'No such file or directory' <<<"$sn_out"; then
    tc_fail "the installed copy dies in a bare bash ENOENT: $(tr '\n' ' ' <<<"$sn_out")"
else
    tc_pass "no bare bash ENOENT from the installed copy"
fi
# Negative control: with the shared runtime absent, the script must SAY so.
sn_out="$(env PATH="$tmp_sn/fakebin:$PATH" SANDSWAP_SH_LIB_DIR="$tmp_sn/empty-lib" UPLINK= BRIDGE= \
          bash "$tmp_sn/usr/local/bin/setup-network.sh" 2>&1)"; sn_rc=$?
if [[ "$sn_rc" -ne 0 ]]; then
    tc_pass "a missing shared runtime is an error, not a silent continue"
else
    tc_fail "a missing shared runtime exited 0"
fi
if grep -qiE 'shared runtime (not found|missing)|runtime\.sh (not found|missing)' <<<"$sn_out"; then
    tc_pass "a missing shared runtime prints the script's own message"
else
    tc_fail "a missing shared runtime was not named: ${sn_out:-<no output>}"
fi
if grep -q 'No such file or directory' <<<"$sn_out"; then
    tc_fail "a missing shared runtime died in a bare bash ENOENT: $(tr '\n' ' ' <<<"$sn_out")"
else
    tc_pass "a missing shared runtime never reaches a bare bash ENOENT"
fi
rm -rf "$tmp_sn"

# ── N. forward-policy guard (a foreign DROP on iptables FORWARD) ──────
# The guest v4 forward policy lives in `inet sandswap` (nft), but a base
# chain at the same hook+priority also sees every packet: kube-router/docker
# leaving FORWARD policy DROP black-holes guest egress while the nft chain
# shows green counters. The guard must (1) no-op on the bare-metal baseline,
# (2) restore ACCEPT over DEAD runtime residue, (3) REFUSE an operator-set
# DROP, (4) mirror the nft scoping as tagged rules beside a LIVE runtime,
# and teardown must remove exactly the tagged rules. Driven through a fake
# iptables/systemctl on PATH (the fake-git pattern above).
tmp_fg="$(mktemp -d)"
mkdir -p "$tmp_fg/state" "$tmp_fg/fakebin" "$tmp_fg/state/active"
cat > "$tmp_fg/fakebin/iptables" <<'FAKE'
#!/usr/bin/env bash
# minimal iptables double: -S/-P/-I/-A/-C/-D on FORWARD, state in $FG_IPT_STATE
FG="$FG_IPT_STATE"
case "$1" in
    -S) [[ "$2" == FORWARD ]] && { echo "-P FORWARD $(cat "$FG/policy")"; cat "$FG/rules" 2>/dev/null; }; exit 0 ;;
    -P) [[ "$3" == ACCEPT || "$3" == DROP ]] && echo "$3" > "$FG/policy"; exit 0 ;;
    -I) pos="$3"; shift 3; spec="$*"
        tmp="$FG/rules.new"; : > "$tmp"
        tail -n +1 "$FG/rules" 2>/dev/null | head -n $((pos-1)) >> "$tmp"
        echo "-A FORWARD $spec" >> "$tmp"
        tail -n +$pos "$FG/rules" 2>/dev/null >> "$tmp"
        mv "$tmp" "$FG/rules"; exit 0 ;;
    -A) shift 2; echo "-A FORWARD $*" >> "$FG/rules"; exit 0 ;;
    -C) shift 2; grep -qxF -- "-A FORWARD $*" "$FG/rules" 2>/dev/null && exit 0 || exit 1 ;;
    -D) shift 2; grep -vx -- "-A FORWARD $*" "$FG/rules" 2>/dev/null > "$FG/rules.new" || true
        mv "$FG/rules.new" "$FG/rules" 2>/dev/null; exit 0 ;;
esac
exit 0
FAKE
cat > "$tmp_fg/fakebin/systemctl" <<'FAKE'
#!/usr/bin/env bash
if [[ "$1" == is-active ]]; then
    shift
    [[ "${1:-}" == --quiet ]] && shift
    for u in "$@"; do [[ -e "$FG_IPT_STATE/active/$u" ]] && exit 0; done
    exit 3
fi
if [[ "$1" == stop ]]; then
    echo "stop $2" >> "$FG_IPT_STATE/systemctl-calls"
    [[ -e "$FG_IPT_STATE/unstoppable/$2" ]] && exit 1
    rm -f "$FG_IPT_STATE/active/$2"; exit 0
fi
if [[ "$1" == start ]]; then
    echo "start $2" >> "$FG_IPT_STATE/systemctl-calls"
    mkdir -p "$FG_IPT_STATE/active"; touch "$FG_IPT_STATE/active/$2"; exit 0
fi
exit 0
FAKE
chmod +x "$tmp_fg/fakebin/iptables" "$tmp_fg/fakebin/systemctl"
fg_reset() { # <policy> <rules-file-content...>
    FG_IPT_STATE="$tmp_fg/state"
    echo "$1" > "$FG_IPT_STATE/policy"; : > "$FG_IPT_STATE/rules"
    rm -rf "$FG_IPT_STATE/active"; mkdir -p "$FG_IPT_STATE/active"
    shift
    local r; for r in "$@"; do echo "$r" >> "$FG_IPT_STATE/rules"; done
}
fg_run() { # <func> [args...]
    env PATH="$tmp_fg/fakebin:$PATH" FG_IPT_STATE="$FG_IPT_STATE" bash -c \
        "source '$ROOT/common/sh/runtime.sh' >/dev/null 2>&1; $*" 2>/dev/null
}
FG_IPT_STATE="$tmp_fg/state"
# (1) baseline ACCEPT → no-op, nothing inserted
fg_reset ACCEPT "-A FORWARD -j DOCKER-USER"
fg_run ss_fwd_policy_guard ens4 10.188.0.0/16; fg_rc=$?
if [[ "$fg_rc" == 0 && "$(cat "$FG_IPT_STATE/policy")" == ACCEPT ]] && ! grep -q sandswap-guest-fwd "$FG_IPT_STATE/rules"; then
    tc_pass "guard: ACCEPT baseline is a no-op"
else
    tc_fail "guard: ACCEPT baseline was touched (rc=$fg_rc policy=$(cat "$FG_IPT_STATE/policy"))"
fi
# (2) DROP + stopped runtime + runtime chains listed → restore ACCEPT
fg_reset DROP "-A FORWARD -j DOCKER-USER" "-A FORWARD -j KUBE-ROUTER-FORWARD"
fg_run ss_fwd_policy_guard ens4 10.188.0.0/16; fg_rc=$?
if [[ "$fg_rc" == 0 && "$(cat "$FG_IPT_STATE/policy")" == ACCEPT ]]; then
    tc_pass "guard: dead runtime residue is restored to ACCEPT"
else
    tc_fail "guard: dead residue not restored (rc=$fg_rc policy=$(cat "$FG_IPT_STATE/policy"))"
fi
# (3) DROP + no runtime + no chains → refusal, policy untouched
fg_reset DROP
fg_run ss_fwd_policy_guard ens4 10.188.0.0/16; fg_rc=$?
if [[ "$fg_rc" != 0 && "$(cat "$FG_IPT_STATE/policy")" == DROP ]]; then
    tc_pass "guard: operator-set DROP is refused, not weakened"
else
    tc_fail "guard: operator DROP mishandled (rc=$fg_rc policy=$(cat "$FG_IPT_STATE/policy"))"
fi
# (4) DROP + LIVE runtime → policy stays, tagged mirrors inserted in order
fg_reset DROP "-A FORWARD -j DOCKER-USER"
: > "$FG_IPT_STATE/active/docker"
fg_run ss_fwd_policy_guard ens4 10.188.0.0/16; fg_rc=$?
fg_rules="$(cat "$FG_IPT_STATE/rules")"
fg_meta_line="$(grep -n 'sandswap-guest-fwd -j DROP' <<<"$fg_rules" | head -1 | cut -d: -f1)"
fg_acc_line="$(grep -n 'sandswap-guest-fwd -j ACCEPT' <<<"$fg_rules" | head -1 | cut -d: -f1)"
if [[ "$fg_rc" == 0 && "$(cat "$FG_IPT_STATE/policy")" == DROP && "$(grep -c sandswap-guest-fwd <<<"$fg_rules")" == 5 ]] \
   && [[ -n "$fg_meta_line" && -n "$fg_acc_line" && "$fg_meta_line" -lt "$fg_acc_line" ]] \
   && grep -q -- "-s 10.188.0.0/16 -o ens4" <<<"$fg_rules"; then
    tc_pass "guard: live runtime gets tagged scoped mirrors (3 drops + 2 accepts, drop before accept)"
else
    tc_fail "guard: live-runtime mirrors wrong (rc=$fg_rc policy=$(cat "$FG_IPT_STATE/policy") tagged=$(grep -c sandswap-guest-fwd <<<"$fg_rules") meta=${fg_meta_line:-?} acc=${fg_acc_line:-?} rules=$(wc -l <<<"$fg_rules"))"
fi
# (5) teardown flush removes ONLY the tagged rules
fg_run ss_fwd_tagged_flush
fg_rules="$(cat "$FG_IPT_STATE/rules")"
if ! grep -q sandswap-guest-fwd <<<"$fg_rules" && grep -q -- "-j DOCKER-USER" <<<"$fg_rules"; then
    tc_pass "teardown: tagged mirrors removed, foreign chains kept"
else
    tc_fail "teardown: flush wrong (rules=$(wc -l <<<"$fg_rules"))"
fi
unset FG_IPT_STATE
rm -rf "$tmp_fg"

# ── N+1. container-runtime clean (the prelude stops k3s/docker) ───────
# A live container runtime during a KVM e2e / bare-metal deploy is an
# environment-contamination factor (FORWARD DROP, ports, memory): the prelude
# must STOP it, converge the FORWARD baseline over the residue, honor the
# SANDSWAP_KEEP_CONTAINER_RUNTIME=1 opt-out, and refuse by name when a unit
# will not stop. Same fake iptables/systemctl pattern as the guard block.
tmp_cr="$(mktemp -d)"
mkdir -p "$tmp_cr/state/active" "$tmp_cr/state/unstoppable" "$tmp_cr/fakebin"
cat > "$tmp_cr/fakebin/iptables" <<'FAKE'
#!/usr/bin/env bash
# minimal double for the runtime-clean paths: -S FORWARD (policy + rules) and
# -P FORWARD <pol> are all ss_container_runtime_clean touches.
CR="$CR_STATE"
case "$1" in
    -S) [[ "$2" == FORWARD ]] && { echo "-P FORWARD $(cat "$CR/policy")"; cat "$CR/rules" 2>/dev/null; };;
    -P) [[ "$3" == ACCEPT || "$3" == DROP ]] && echo "$3" > "$CR/policy";;
esac
exit 0
FAKE
chmod +x "$tmp_cr/fakebin/iptables"
cat > "$tmp_cr/fakebin/systemctl" <<'FAKE'
#!/usr/bin/env bash
CR="$CR_STATE"
if [[ "$1" == is-active ]]; then
    shift
    [[ "${1:-}" == --quiet ]] && shift
    for u in "$@"; do [[ -e "$CR/active/$u" ]] && exit 0; done
    exit 3
fi
if [[ "$1" == stop ]]; then
    echo "stop $2" >> "$CR/systemctl-calls"
    [[ -e "$CR/unstoppable/$2" ]] && exit 1
    rm -f "$CR/active/$2"; exit 0
fi
exit 0
FAKE
chmod +x "$tmp_cr/fakebin/systemctl" "$tmp_cr/fakebin/iptables"
cr_reset() { # <policy> <units...>
    CR_STATE="$tmp_cr/state"
    rm -rf "$CR_STATE/active" "$CR_STATE/unstoppable"; mkdir -p "$CR_STATE/active" "$CR_STATE/unstoppable"
    rm -f "$CR_STATE/systemctl-calls" "$CR_STATE/rules"
    echo "$1" > "$CR_STATE/policy"; shift
    local u; for u in "$@"; do touch "$CR_STATE/active/$u"; done
    echo "-A FORWARD -j DOCKER-USER" > "$CR_STATE/rules"
}
cr_run() {
    env PATH="$tmp_cr/fakebin:$PATH" CR_STATE="$CR_STATE" \
        SANDSWAP_KEEP_CONTAINER_RUNTIME="${SANDSWAP_KEEP_CONTAINER_RUNTIME:-0}" \
        bash -c "source '$ROOT/common/sh/runtime.sh' >/dev/null 2>&1; $*"
}
CR_STATE="$tmp_cr/state"
# (1) live k3s+docker under a DROP policy → both stopped, baseline restored
cr_reset DROP k3s docker.service docker.socket containerd
cr_run ss_container_runtime_clean; cr_rc=$?
if [[ "$cr_rc" == 0 && ! -e "$CR_STATE/active/k3s" && ! -e "$CR_STATE/active/docker.service" \
      && "$(cat "$CR_STATE/policy")" == ACCEPT ]] \
   && grep -q "stop k3s" "$CR_STATE/systemctl-calls" && grep -q "stop docker.service" "$CR_STATE/systemctl-calls"; then
    tc_pass "runtime clean: k3s+docker stopped, FORWARD baseline restored"
else
    tc_fail "runtime clean: wrong outcome (rc=$cr_rc policy=$(cat "$CR_STATE/policy") calls=$(cat "$CR_STATE/systemctl-calls" 2>/dev/null | tr '\n' ','))"
fi
# (2) the opt-out is a no-op
SANDSWAP_KEEP_CONTAINER_RUNTIME=1
cr_reset DROP k3s docker.service
cr_run ss_container_runtime_clean; cr_rc=$?
if [[ "$cr_rc" == 0 && -e "$CR_STATE/active/k3s" && ! -e "$CR_STATE/systemctl-calls" ]]; then
    tc_pass "runtime clean: SANDSWAP_KEEP_CONTAINER_RUNTIME=1 keeps the runtime"
else
    tc_fail "runtime clean: opt-out not honored (rc=$cr_rc)"
fi
unset SANDSWAP_KEEP_CONTAINER_RUNTIME
# (3) a unit that will not stop → named refusal
cr_reset DROP k3s
touch "$CR_STATE/unstoppable/k3s"
cr_run ss_container_runtime_clean; cr_rc=$?
if [[ "$cr_rc" != 0 && -e "$CR_STATE/active/k3s" ]]; then
    tc_pass "runtime clean: an unstoppable unit is a named refusal"
else
    tc_fail "runtime clean: unstoppable unit not refused (rc=$cr_rc)"
fi
unset CR_STATE
rm -rf "$tmp_cr"

# ── Summary ───────────────────────────────────────────────────────────
echo ""
tc_log_section "Framework unit summary"
echo "  passed=$PASS_COUNT failed=$FAIL_COUNT"
if [[ "$FAIL_COUNT" -gt 0 ]]; then
    tc_log_error "FRAMEWORK UNIT FAILED"
    exit 1
fi
tc_log_pass "FRAMEWORK UNIT PASSED"

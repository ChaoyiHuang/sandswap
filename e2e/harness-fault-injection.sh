#!/usr/bin/env bash
# Copyright 2026 Chaoyi Huang. All rights reserved.
#
# SPDX-License-Identifier: BUSL-1.1
#
# Use of this software is governed by the Business Source License
# included in the LICENSE file at the root of this repository.
#
# As of the Change Date specified in that file, in accordance with
# the Business Source License, your use of this software will be
# governed by the Apache License, Version 2.0.
#
# harness-fault-injection.sh — W4(b): prove the harness can FAIL.
#
# A suite that cannot fail is not evidence (the t2-08 lesson: "gates that
# cannot fail"). Every red we ever reported traces to a human applying a
# sabotage by hand; this drill mechanizes exactly that act so it can ride
# the battery. Three classes, each case = SABOTAGE → run the owning gate →
# assert RED → RESTORE → assert the tree is clean again:
#
#   FI-C  verdict primitives  — tc_pass/tc_fail counting and the
#         `FAIL_COUNT>0 → exit 1` tail that turns asserts into verdicts;
#         the tc_skip_suite marker (skip budget) marks, not passes
#   FI-B  harness tooling     — check-docs-links.py red on an injected
#         broken link (reconcile.py already carries its own 8/8 self-reds)
#   FI-A  go/rust suites      — token-level sabotages at load-bearing pins
#         (namespace Rule 1, the identity wire pin, the common/config GC
#         guard, the warden INSTALL_CAPS decision record); each owning
#         suite MUST go red under sabotage
#
# No go builds run under --fast (the mutation driver may hold the same
# module's files mid-edit — a compile failure would masquerade as the
# expected red for the wrong reason).
#
# Usage: bash e2e/harness-fault-injection.sh [--fast]

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/e2e/common.sh"

# Clean-host precondition: every environment-owning script starts from a
# clean host. Leftovers from a DEAD previous run are killed here; a
# CONCURRENT harness run is refused by name (ss_harness_guard), never killed.
tc_clean_environment

FAST=0
[[ "${1:-}" == "--fast" ]] && FAST=1

# ── restore discipline ─────────────────────────────────────────────
# Every sabotage goes through sab_begin/sab_end: the file is backed up
# before the edit and restored from the copy after the assertion. The
# final tree-cleanliness assertion makes a leaked edit impossible to
# miss — a fault-injection drill that corrupts the tree is worse than
# no drill.
SAB_BACKUPS="$(mktemp -d /tmp/fi-backups.XXXXXX)"
SAB_SEQ=0

sab_begin() { # $1=repo-relative file → returns backup path in SAB_BACKUP
    SAB_SEQ=$((SAB_SEQ + 1))
    SAB_BACKUP="$SAB_BACKUPS/$SAB_SEQ.bak"
    cp "$ROOT/$1" "$SAB_BACKUP"
    # Also capture the ORIGINAL mtime. Restoring the bytes is not enough:
    # the rewrite bumps mtime, and `build.sh check` — the freshness gate every
    # suite runs in preflight — compares each artifact's mtime against its
    # sources. A drill that leaves a Go/Rust source younger than the binaries
    # makes every LATER script in the battery pay a full auto-rebuild
    # (~3 minutes each), for no code change at all.
    SAB_MTIME="$(stat -c '%y' "$ROOT/$1")"
    SAB_FILE="$1"
}

sab_end() { # restore + verify byte-identical
    cp "$SAB_BACKUP" "$ROOT/$SAB_FILE"
    if ! cmp -s "$SAB_BACKUP" "$ROOT/$SAB_FILE"; then
        tc_log_error "RESTORE FAILED for $SAB_FILE — aborting before any further damage"
        exit 1
    fi
    touch -d "$SAB_MTIME" "$ROOT/$SAB_FILE" 2>/dev/null || true
}

# sabotage_apply <file> <python-substitution-old> <new> — exact-string
# replace with a count check: a sabotage that edits nothing must abort
# loudly (a silent no-op sabotage would assert a red the gate may not
# actually produce for the stated reason).
sabotage_apply() { # $1=file $2=old $3=new
    python3 -I - "$ROOT/$1" "$2" "$3" <<'PYEOF'
import sys
path, old, new = sys.argv[1], sys.argv[2], sys.argv[3]
t = open(path).read()
n = t.count(old)
if n != 1:
    sys.exit(f"sabotage site not unique ({n}x) in {path}: {old[:60]!r}")
open(path, "w").write(t.replace(old, new, 1))
PYEOF
}

# suite_red <dir> <go-test-args...> — assert the package suite FAILS.
suite_red() {
    local dir="$1"; shift
    ( cd "$dir" && go test "$@" -count=1 ) > /dev/null 2>&1
    # rc != 0 is the EXPECTED red
}

# ══════════════════════════════════════════════════════════════════
tc_log_section "FI-C: verdict primitives"
# ══════════════════════════════════════════════════════════════════

# The gate every e2e script ends with: asserts feed FAIL_COUNT, the tail
# turns it into an exit code. Prove both directions in child bash.
mini_suite() { # $1=assert-args-pair → child bash running the standard tail
    bash -c '
        source "'"$ROOT"'/e2e/common.sh" >/dev/null 2>&1
        '"$1"'
        if (( FAIL_COUNT > 0 )); then exit 1; fi
        exit 0
    ' 2>/dev/null
}

if mini_suite 'tc_assert_eq "eq ok" hello hello'; then
    tc_pass "FI-C: green suite exits 0"
else
    tc_fail "FI-C: a GREEN mini-suite exited non-zero — the gate fails the innocent"
fi

if mini_suite 'tc_assert_eq "eq broken" hello world'; then
    tc_fail "FI-C: a RED mini-suite exited 0 — THE GATE CANNOT FAIL (t2-08 class)"
else
    tc_pass "FI-C: red suite exits non-zero (assert → FAIL_COUNT → exit 1)"
fi

# tc_skip_suite marker: battery-mode marking, not silent pass
SKIPDIR="$(mktemp -d /tmp/fi-skip.XXXXXX)"
if RUNALL_SKIP_DIR="$SKIPDIR" RUNALL_SCRIPT=fake-script.sh bash -c '
    source "'"$ROOT"'/e2e/common.sh" >/dev/null 2>&1
    tc_skip_suite "fi-drill probe"
' > /dev/null 2>&1; then
    if [[ -f "$SKIPDIR/fake-script.sh" ]]; then
        tc_pass "FI-C: tc_skip_suite leaves the battery marker + exits 0"
    else
        tc_fail "FI-C: tc_skip_suite did not leave the marker — internal skip would count PASS"
    fi
else
    tc_fail "FI-C: tc_skip_suite exited non-zero"
fi
rm -rf "$SKIPDIR"

# ══════════════════════════════════════════════════════════════════
tc_log_section "FI-B: harness tooling"
# ══════════════════════════════════════════════════════════════════

# check-docs-links.py must go red on an injected broken link.
sab_begin "docs/how-it-works/namespaces.md"
sabotage_apply "docs/how-it-works/namespaces.md" \
    "](../reference/human-api.md#namespaces)" "](../reference/human-api-nope.md#namespaces)"
if python3 -I "$ROOT/e2e/check-docs-links.py" > /dev/null 2>&1; then
    tc_fail "FI-B: check-docs-links stayed green over a broken link — the checker cannot fail"
else
    tc_pass "FI-B: check-docs-links went red on an injected broken link"
fi
sab_end

# check-docs-truth.py must be green on the tree AND go red
# on an injected retired term. The deny-list is the cheapest signature to
# inject without touching code; sab_end restores bytes + mtime, so the
# freshness gate sees no edit.
if python3 -I "$ROOT/e2e/check-docs-truth.py" > /dev/null 2>&1; then
    tc_pass "FI-B: code<->docs truth checker clean"
else
    tc_fail "FI-B: code<->docs truth checker is RED on the current tree — run: python3 e2e/check-docs-truth.py"
fi
sab_begin "docs/operations/configuration/boxout.md"
echo "The idle reaper handles stranded sandfs." >> "$ROOT/docs/operations/configuration/boxout.md"
if python3 -I "$ROOT/e2e/check-docs-truth.py" > /dev/null 2>&1; then
    tc_fail "FI-B: check-docs-truth stayed green over an injected retired term — the checker cannot fail"
else
    tc_pass "FI-B: check-docs-truth went red on an injected retired term"
fi
sab_end

# Warden path-safety scan ( class): the warden must never hand an
# agent-replaceable path to a following primitive (.exists(), fs::write,
# create_dir_all, an unanchored mount target). Red-checked on a scratch tree
# with the three signatures injected, so the scan cannot pass vacuously; the
# scratch tree never touches the real one.
if python3 -I "$ROOT/e2e/check-warden-path-safety.py" > /dev/null 2>&1; then
    tc_pass "FI-B: warden path-safety scan clean"
else
    tc_fail "FI-B: warden path-safety scan flagged a following-path site — run: python3 e2e/check-warden-path-safety.py"
fi
WPATH_RED="$(mktemp -d)"
mkdir -p "$WPATH_RED/warden/src"
# The whole tree, recursively: the mount code lives in a module directory,
# and a top-level-only copy silently dropped it after the split (the drill
# then failed on the missing mount.rs — which is how the vacuous-pass window
# was caught in the first place).
cp -r "$ROOT"/warden/src/. "$WPATH_RED/warden/src/"
python3 - "$WPATH_RED" <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]) / "warden/src/mount/hardening.rs"
out = []
for line in p.read_text().splitlines():
    if line.startswith("use anyhow"):
        out.append('fn _fi_probe(p: &str) -> bool { std::path::Path::new(p).exists() }')
        out.append('fn _fi_write(p: &str) { let _ = std::fs::write(p, b"x"); }')
        out.append('fn _fi_mount(mount_point: &str) { let _ = baremount(Path::new("/bin/busybox"), Path::new(&format!("{}/bin/busybox", mount_point)), "none", MsFlags::MS_BIND, "", &LOGGER); }')
    out.append(line)
p.write_text("\n".join(out) + "\n")
PY
if python3 -I "$ROOT/e2e/check-warden-path-safety.py" "$WPATH_RED" > /dev/null 2>&1; then
    tc_fail "FI-B: warden path-safety scan stayed green over injected following-path signatures — the checker cannot fail"
else
    tc_pass "FI-B: warden path-safety scan went red on injected .exists()/fs::write/unanchored-mount signatures"
fi
rm -rf "$WPATH_RED"

# The flipped-nil-check scanner ( class) — its red/green pair is
# self-tested (re-applying the historical mutant must flip it red); the
# battery run asserts the tree is currently clean of the signature.
if python3 -I "$ROOT/e2e/check-nil-wrap-scan.py" > /dev/null 2>&1; then
    tc_pass "FI-B: nil-wrap scan clean (no flipped-nil-check signatures)"
else
    tc_fail "FI-B: nil-wrap scan flagged a flipped-nil-check site — see e2e/check-nil-wrap-scan.py output"
fi

# Deploy-shape hardcode scan ( class): literal identity names in
# deploy-script OWNERSHIP operations must be zero — path ownership derives
# from SS_PROV_USER (sandswap_apply_prov_plane). Self-tested red/green: a
# scratch copy of a deploy script with one injected literal must flip it red.
if python3 -I "$ROOT/deploy/baremetal/check-shape-hardcodes.py" > /dev/null 2>&1; then
    tc_pass "FI-B: deploy-shape hardcode scan clean"
else
    tc_fail "FI-B: deploy-shape hardcode scan flagged a literal-identity ownership site — see deploy/baremetal/check-shape-hardcodes.py"
fi
SHAPE_RED="$(mktemp -d)"
mkdir -p "$SHAPE_RED/deploy/baremetal"
cp "$ROOT/deploy/baremetal/deploy-single-node.sh" "$SHAPE_RED/deploy/baremetal/"
echo 'chown sandprov:sandlot /var/lib/sandswap/volumes' >> "$SHAPE_RED/deploy/baremetal/deploy-single-node.sh"
if python3 -I "$ROOT/deploy/baremetal/check-shape-hardcodes.py" "$SHAPE_RED" > /dev/null 2>&1; then
    tc_fail "FI-B: shape-hardcode scan stayed green over an injected literal — the checker cannot fail"
else
    tc_pass "FI-B: shape-hardcode scan went red on an injected literal"
fi
rm -rf "$SHAPE_RED"

# Hand-rolled-prelude scan ( class): the shared prelude
# (common/sh/{runtime,stack}.sh) is the ONE implementation of identity/dirs/
# devices/seed/retryable/pool parsing — a script that re-implements one of
# them is the drift that produced this round's finding family. Red-checked
# the same way: a scratch tree with one injected hand-rolled seed must flip
# it red, and the scratch tree never touches the real one.
if python3 -I "$ROOT/e2e/check-handrolled-prelude.py" > /dev/null 2>&1; then
    tc_pass "FI-B: hand-rolled-prelude scan clean"
else
    tc_fail "FI-B: hand-rolled-prelude scan flagged a site — run: python3 e2e/check-handrolled-prelude.py"
fi
PRELUDE_RED="$(mktemp -d)"
mkdir -p "$PRELUDE_RED/e2e"
printf '%s\n' '#!/bin/bash' \
    '( umask 077; openssl rand -hex 32 > "$D/volume-seed" )' \
    > "$PRELUDE_RED/e2e/injected.sh"
if python3 -I "$ROOT/e2e/check-handrolled-prelude.py" "$PRELUDE_RED" > /dev/null 2>&1; then
    tc_fail "FI-B: hand-rolled-prelude scan stayed green over an injected seed mint — the checker cannot fail"
else
    tc_pass "FI-B: hand-rolled-prelude scan went red on an injected seed mint"
fi
rm -rf "$PRELUDE_RED"

# ══════════════════════════════════════════════════════════════════
if [[ $FAST -eq 1 ]]; then
    tc_log_warn "FI-A skipped (--fast): go builds would race a concurrent mutation driver"
else
    tc_log_section "FI-A: go suites go red under token sabotage"

    # gateway/handler — namespace Rule 1 disabled ⇒ the enforcement matrix fails
    sab_begin "gateway/handler/namespace.go"
    sabotage_apply "gateway/handler/namespace.go" \
        '	if !scope.Allows(ns) {' \
        '	if false && !scope.Allows(ns) { // FI: Rule 1 disabled'
    if suite_red "$ROOT/gateway" ./handler/ -run TestNamespaceRule1; then
        tc_fail "FI-A: handler namespace matrix stayed green with Rule 1 disabled — pin is weak"
    else
        tc_pass "FI-A: handler Rule-1 matrix red under sabotage"
    fi
    sab_end

    # gateway/identity — the HOT wire pin: encode a SENTINEL namespace into
    # every encoded hot record (semantically wrong, still compiles — the red
    # must come from the pin, never from a compile error).
    sab_begin "gateway/identity/etcd.go"
    sabotage_apply "gateway/identity/etcd.go" \
        '		Namespace:   rec.Namespace,' \
        '		Namespace:   "fi-sentinel",'
    if suite_red "$ROOT/gateway" ./identity/ -run TestSandfsHotWireCarriesNamespace; then
        tc_fail "FI-A: identity hot-wire pin stayed green with a sentinel namespace — pin is weak"
    else
        tc_pass "FI-A: identity hot-wire pin red under sabotage"
    fi
    sab_end

    # (The go set covers one condition-sabotage and one wire-drop — the two
    # classes; the mutation driver sweeps the full site space continuously.
    # Warden's decision-record pin proves the class crosses languages.)

    # warden — INSTALL_CAPS decision-record pin (slow: rust compile)
    if command -v cargo >/dev/null 2>&1; then
        sab_begin "warden/src/exec.rs"
        sabotage_apply "warden/src/exec.rs" \
            'const INSTALL_CAPS: &[i32] = &[0, 1, 2, 3, 4, 5, 6, 7, 10, 29];' \
            'const INSTALL_CAPS: &[i32] = &[0, 1, 2, 3, 4, 5, 6, 7, 10, 27, 29];'
        # exec.rs is a BIN module (main.rs declares `mod exec`); `--lib` now
        # compiles only the extracted lib target and runs zero tests, which
        # exits 0 and looks like a green pin. Target the bin explicitly.
        if ( cd "$ROOT/warden" && cargo test --bin warden install_caps_exact_set ) > /dev/null 2>&1; then
            tc_fail "FI-A: warden INSTALL_CAPS pin stayed green with MKNOD sneaked back — pin is weak"
        else
            tc_pass "FI-A: warden INSTALL_CAPS pin red under sabotage"
        fi
        sab_end
        # sab_end restores the ORIGINAL mtime so the freshness gate does not
        # see a source edit. Cargo then treats exec.rs as unchanged and
        # reuses the SABOTAGED test binary on the next suite. Purge the package's
        # artifacts so the restored source is recompiled.
        ( cd "$ROOT/warden" && cargo clean -p warden ) >/dev/null 2>&1 || true
    else
        tc_log_warn "FI-A warden case skipped: cargo not available (environment, recorded here)"
    fi
fi

# ══════════════════════════════════════════════════════════════════
# Tree cleanliness — sab_end verified each restore byte-identical; the
# backup dir's removal is the last act. A drill that edits the tree is
# worse than no drill.
# ══════════════════════════════════════════════════════════════════
rm -rf "$SAB_BACKUPS"

# ── Summary ─────────────────────────────────────────────────────
tc_log_section "Summary"
echo "  pass=$PASS_COUNT fail=$FAIL_COUNT"
if [[ "$FAIL_COUNT" -gt 0 ]]; then
    tc_log_error "$FAIL_COUNT fault-injection check(s) FAILED — the harness has a gate that cannot fail"
    exit 1
fi
tc_log_pass "Harness fault-injection: every gate proven able to fail"

#!/usr/bin/env python3
# Copyright 2026 Chaoyi Huang. All rights reserved.
#
# SPDX-License-Identifier: BUSL-1.1
#
# check-handrolled-prelude.py — static guard for the HAND-ROLLED PRELUDE class.
#
# Mechanism (why this exists): every feature on this list (storage
# split, four identities, volume-name seed, template store, runtime-dir shape,
# device owners, retryable refusals) added a dimension to what a script must
# set up BEFORE it can run. Each script hand-rolled that setup, so each one
# drifted differently — six broken deploy modes, four ops-CLI
# drifts and a probe with six stacked defects, all of them "the script did its
# own version of a shared contract". The fix is the shared prelude
# (common/sh/runtime.sh + common/sh/stack.sh); THIS file is what stops the
# next script from re-hand-rolling it.
#
# Rules (each is a defect class that actually shipped):
#   R1 seed-mint      hand-rolled `openssl rand -hex 32 > …volume-seed`
#                     → ss_ensure_volume_seed <path> [owner] [mode]
#   R2 identity       literal sandlot/sandserv/sandvmm/sandprov in
#                     chown/chmod/`install -o` → $SS_SERVICE_USER_* / $SS_PROV_USER
#   R3 retryable      a pasted '"…|NO_AVAILABLE_SANDBOX|…"' regex
#                     → ss_body_retryable (one token set, one predicate)
#   R4 pool-parse     inline python parsing of $stats for clean_vms
#                     → ss_pool_clean (five historical shapes, one parser)
#   R5 runtime-dir    hand-made /run/sandswap dirs → ss_prepare_dirs
#   R6 exec-client    a local exec_code()/exec_in_vm() definition
#                     → ss_gw_exec_raw / ss_gw_exec (body escaping, timeouts,
#                       retry_after_ms pacing — every copy had drifted)
#
# Escape hatch: a line ending in (or preceded by a line containing)
# `# prelude-ok: <reason>` is exempt. Reasons must be real — this guard is a
# ratchet, not a wall: exempting a site is a decision someone wrote down.
#
# Usage:
#   python3 e2e/check-handrolled-prelude.py [root]
# Exit 0 = clean, 1 = findings (printed as path:line: rule: text).

import re
import sys
from pathlib import Path

ROOT = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path(__file__).resolve().parents[1]

# Files that ARE the implementation (or the guard's own fixtures).
ALLOW = (
    "common/sh/runtime.sh",
    "common/sh/stack.sh",
    "deploy/baremetal/common.sh",
    "e2e/common.sh",
    "e2e/framework-unit.sh",          # negative fixtures name the patterns
    "e2e/check-handrolled-prelude.py",
    "e2e/harness-fault-injection.sh",  # deliberately PLANTS these to red-test
    "e2e/run-matrix.sh",
    "deploy/k8s/",                    # k8s flow is Secret-based; its own
                                      # adoption is tracked separately
)

IDENTITIES = {"sandprov", "sandlot", "sandserv", "sandvmm"}

RULES = [
    ("R1 seed-mint", re.compile(r"openssl\s+rand\s+-hex\s+32[^\n]*volume-seed")),
    ("R3 retryable", re.compile(
        r"\"(?:NO_AVAILABLE_SANDBOX|NO_COMPUTE_NODES|CONCURRENT_MOUNT|SANDBOX_CLEANING)\"")),
    # An inline PARSE of /stats (the sanctioned wrapper calls are fine: they
    # are `tc_stats_clean_vms` / `clean_vms`, not a python expression).
    ("R4 pool-parse", re.compile(
        r"(?:json\.load|\.get\(|\bin d\b)[^\n]*clean_vms|clean_vms[^\n]*json\.load")),
    # Only the SHARED runtime dir itself (a suite creating its own
    # /run/sandswap/<instance> fixture is testing something else entirely).
    ("R5 runtime-dir", re.compile(r"\b(?:mkdir\s+-p|install\s+-d)[^\n]*?/run/sandswap(?!/)\s*(?:$|\"|')")),
    ("R6 exec-client", re.compile(r"^\s*(?:exec_code|exec_in_vm|exec_cmd)\s*\(\)\s*\{")),
]

OK_MARKS = ("# prelude-ok:", "# shape-ok:")

# Known, deliberately-retained sites: the rule still catches NEW ones, and
# each entry says why this one stays. Keeping them here (rather than as
# scattered in-file comments) is a deliberate choice: the ratchet is
# reviewable in one screen, and a site that disappears shows up as a stale
# entry the next reader can delete.
KNOWN_SITES = {
    # Exec clients that are NOT transport helpers: they are per-suite
    # instrumentation with their own call convention (formatted output, key
    # →sandfs indirection, per-test retry schedules and timing capture).
    # Consolidating them is a rewrite of each test's call sites — tracked as
    # framework backlog, not done in the same change as the plumbing.
    "e2e/smoke.sh": "exec_code() is the suite's OUTPUT FORMATTER (stores the last response, prints a formatted row)",
    "e2e/multi-agents.sh": "exec_code() captures per-attempt latency and keeps an 8-attempt schedule for the agent-switch matrix",
    "e2e/cross-tenant-residue.sh": "exec_code() is the suite's output formatter over a shared helper",
    "e2e/eino-agent-mcp.sh": "exec_code() is the eino runner's output formatter",
    "e2e/overlayfs-isolation.sh": "exec_in_vm() carries the suite's 3-attempt cold-mount schedule",
    "e2e/template-lifecycle.sh": "exec_in_vm() resolves the sandfs id from KEY2SID[\"$key\"] (suite-local indirection)",
    "e2e/template-swap.sh": "exec_in_vm() resolves the sandfs id from KEY2SID[\"$key\"] (suite-local indirection)",
    "e2e/protocol-version-e2e.sh": "clean_vms() parses a caller-supplied stats URL through the suite's own field extractor",
    "e2e/eino-agent-mcp.sh:r4": "parses a /stats body the suite already fetched alongside other fields",
    "deploy/baremetal/sandswap-ops.sh": "display-only per-NODE stats projection (the ops CLI reports node rows, not a pool total)",
}


def known(rel: str, rule: str) -> bool:
    return rel in KNOWN_SITES or f"{rel}:{rule.split()[0].lower()}" in KNOWN_SITES


_MESSAGE_RX = re.compile(r"^\s*(?:log|warn|err|echo|printf|tc_log_\w+|cat\b.*<<)")


def _literal_identity_owner(line: str) -> bool:
    """True when chown/chmod/`install -o` names a LITERAL service identity in
    the USER position. The shared GROUP is legitimately the literal `sandlot`
    (SS_SHARED_GROUP is a constant, not a shape), and a variable user
    ($SS_PROV_USER, $PROV) is exactly what we want — neither is a finding."""
    for m in re.finditer(r"\b(chown|chmod)\b(.*)$", line):
        args = m.group(2).split()
        for a in args:
            if a.startswith("-"):
                continue
            user = a.strip("\"'").split(":")[0]
            if user in IDENTITIES:
                return True
            break                      # only the first non-flag arg is the user
    for m in re.finditer(r"\binstall\b(.*)$", line):
        args = m.group(1).split()
        for i, a in enumerate(args):
            if a == "-o" and i + 1 < len(args):
                if args[i + 1].strip("\"'") in IDENTITIES:
                    return True
    return False


def scan_file(path: Path, rel: str):
    findings = []
    try:
        lines = path.read_text(errors="replace").splitlines()
    except OSError:
        return findings
    for i, line in enumerate(lines):
        if line.lstrip().startswith("#"):
            continue                      # comments describe, never execute
        exempt = any(m in line for m in OK_MARKS) or \
            (i > 0 and any(m in lines[i - 1] for m in OK_MARKS))
        if exempt:
            continue
        hit = None
        if _MESSAGE_RX.match(line):
            continue                  # a MESSAGE mentioning a chown is not one
        if _literal_identity_owner(line):
            hit = "R2 identity"
        else:
            for name, rx in RULES:
                if rx.search(line):
                    hit = name
                    break
        if hit and not known(rel, hit):
            findings.append((f"{rel}:{i + 1}", hit, line.strip()[:110]))
    return findings


def main():
    hits = []
    for tree in ("e2e", "deploy"):
        for f in sorted((ROOT / tree).rglob("*.sh")):
            rel = str(f.relative_to(ROOT))
            if any(rel == a or rel.startswith(a) for a in ALLOW):
                continue
            hits.extend(scan_file(f, rel))

    if not hits:
        print("check-handrolled-prelude: clean (0 findings)")
        return 0

    print(f"check-handrolled-prelude: {len(hits)} hand-rolled prelude site(s)")
    by_rule = {}
    for loc, rule, text in hits:
        by_rule.setdefault(rule, []).append((loc, text))
    for rule in sorted(by_rule):
        print(f"\n{rule}  ({len(by_rule[rule])})")
        for loc, text in by_rule[rule]:
            print(f"  {loc}: {text}")
        hint = {
            "R1 seed-mint": "use: ss_ensure_volume_seed <path> [owner] [mode]",
            "R2 identity": "use: $SS_SERVICE_USER_GW / _SL / _VM / $SS_PROV_USER, or ss_apply_share_plane",
            "R3 retryable": "use: ss_body_retryable <body> (and ss_body_retry_after_ms for pacing)",
            "R4 pool-parse": "use: ss_pool_clean [stats_url]",
            "R5 runtime-dir": "use: ss_prepare_dirs (or ss_script_host_prep)",
            "R6 exec-client": "use: ss_gw_exec_raw / ss_gw_exec / ss_gw_exec_retry",
        }[rule]
        print(f"  → {hint}")
    print("\n" + " / ".join(OK_MARKS) + " <reason> on the line (or the one above) exempts a site.")
    return 1


if __name__ == "__main__":
    sys.exit(main())

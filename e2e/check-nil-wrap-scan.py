#!/usr/bin/env python3
# Copyright 2026 Chaoyi Huang. All rights reserved.
#
# SPDX-License-Identifier: BUSL-1.1
#
# check-nil-wrap-scan.py — static scan for the flipped-nil-check defect class.
#
# Two flipped-nil defects of this class ( `gerr == nil` in CreateSandFS;
# `err == nil` in DeleteAgent's per-sandfs delete) shared one shape:
# a guard `if X == nil {` whose block WRAPS X with `%w` — impossible to
# reach with a non-nil X, so the wrap can only ever format `%!w(<nil>)`
# and the guarded operation's SUCCESS path returns a bogus error. Both
# rode an interrupted mutation pass into a commit and were invisible to
# every untagged unit suite. This scan mechanically catches the class in
# <1s; run it in the battery and before any commit of mutator-era work.
#
# A LEGIT `if err == nil { return v, nil }` (no %w wrap of err) and a nil
# sentinel wrap (`== nil` guard wrapping a DIFFERENT sentinel) do not match.

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKIP_DIRS = {"vmm", "vendor", "node_modules", ".git", "target"}

# Both guard shapes: `if X == nil {` and the INIT form
# `if _, err:= f; err == nil {` ('s exact shape — a simple-form-only
# regex misses it, proven by this scanner's own red/green self-test).
CONDS = (
    re.compile(r"if\s+([A-Za-z_][\w.]*)\s*==\s*nil\s*\{"),
    re.compile(r";\s*([A-Za-z_][\w.]*)\s*==\s*nil\s*\{\s*$"),
)
# The wrap's ARGUMENTS: everything between `%w"` and its closing paren; the
# WRAPPED value is the LAST one (`fmt.Errorf("... %w", sid, err)` wraps err —
# a first-argument regex silently missed exact shape, proven by the
# scanner's red/green self-test).
WRAPARG = re.compile(r'%w"([^)]*)\)')

def guard_body(lines, start):
    """Text INSIDE the guard's own braces (brace-exact — a fixed-size window
    leaks the NEXT block's %w and produces false positives on legitimate
    `if x == nil { return ... }` followed by unrelated error handling)."""
    depth = 0
    out = []
    for ln in lines[start:]:
        depth += ln.count("{") - ln.count("}")
        out.append(ln)
        if depth <= 0:
            break
    body = "\n".join(out)
    body = body[body.find("{") + 1 : body.rfind("}")]
    # Branches after `} else` carry their OWN conditions (e.g. an
    # `else if err != nil` branch wrapping err is legitimate) — truncate.
    cut = body.find("} else")
    if cut >= 0:
        body = body[:cut]
    return body

def wrapped_after_rebind(block, expr):
    """True when the block wraps `expr` BEFORE any statement re-binds a
    variable ending in expr's tail — i.e. the wrapped value IS the guarded
    one. Legit patterns like `if _, err := os.Stat(p); err == nil {
    os.RemoveAll(p); return fmt.Errorf(\"...: %w\", err) }` re-bind err from a
    LATER call and must not match (this scanner's own false-positive class,
    caught by its red/green self-test)."""
    pos_wrap = None
    for wm in WRAPARG.finditer(block):
        args = [a.strip() for a in wm.group(1).split(",") if a.strip()]
        if not args:
            continue
        last = args[-1]
        if last == expr or last == expr.split(".")[-1]:
            pos_wrap = wm.start()
            break
    if pos_wrap is None:
        return False
    head = block[:pos_wrap]
    tail = re.escape(expr.split(".")[-1])
    # Any assignment that (re)binds the tail before the wrap means the
    # wrapped value is NOT the guarded one: `err := f()` or `a, err := f()`.
    rebind = re.compile(r"(?<![\w.])" + tail + r"\s*(?:,\s*\w+\s*)*:=|\w+\s*,\s*" + tail + r"\s*:=")
    return rebind.search(head) is None

hits = []
for f in sorted(ROOT.rglob("*.go")):
    if any(part in SKIP_DIRS for part in f.relative_to(ROOT).parts):
        continue
    try:
        lines = f.read_text().splitlines()
    except OSError:
        continue
    for i, ln in enumerate(lines):
        m = None
        for c in CONDS:
            m = c.search(ln)
            if m:
                break
        if not m:
            continue
        expr = m.group(1)
        block = guard_body(lines, i)
        if wrapped_after_rebind(block, expr):
            hits.append(f"{f.relative_to(ROOT)}:{i + 1}: {ln.strip()[:100]}")

if hits:
    print(f"nil-wrap scan: {len(hits)} suspicious site(s) — an `== nil` guard wrapping its own operand with %w can only format %!w(<nil>):")
    for h in hits:
        print("  " + h)
    sys.exit(1)
print("nil-wrap scan: clean (no flipped-nil-check signatures)")

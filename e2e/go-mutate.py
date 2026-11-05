#!/usr/bin/env python3
"""go-mutate.py — minimal apply-and-test mutation driver for Go packages.

Why this exists: Go has no maintained mutation-testing tool, and assertion
strength must be DEMONSTRATED, not asserted (a suite that passes on a
mutant is a test gap, not a success). This driver applies one mutation at
a time to a package's non-test source, runs the package's tests, and
reports which mutants the suite KILLS (tests fail — good) and which
SURVIVE (tests still pass — a weak-assertion finding to triage).

Operators (boundary/condition flips, applied to space-delimited tokens on
non-comment lines):
    == <-> !=        && <-> ||        < <-> <=        > <-> >=

Limitations (accepted for a v1 driver, survivors get eyeballed anyway):
  - no type-awareness: a match inside a string literal that happens to be
    space-delimited becomes a (trivially killed) junk mutant;
  - one mutation per run of the file set; no higher-order mutants.

Usage:
  tools/go-mutate.py <module-dir> <pkg> [options]
    e.g. tools/go-mutate.py common ./config/
  options: --max-mutants N   cap the run (smoke / CI-budget mode)
           --resume LOG      skip indices already in LOG; append verdicts
                             (spot-instance doctrine: SIGTERM-safe restore,
                             flushed per-mutant progress, resumable runs)
           --list            show candidate sites, mutate nothing
           --seed N          shuffle site order deterministically (default 1)
           --timeout SEC     per-mutant go test timeout (default 300)

Exit code: 0 = run completed (kill rate printed); 1 = baseline or driver
error (tree restored). The working tree is ALWAYS restored — a restore
failure aborts the run loudly.
"""

import argparse
import random
import shutil
import subprocess
import sys
from pathlib import Path

OPS = [
    (" == ", " != "),
    (" != ", " == "),
    (" && ", " || "),
    (" || ", " && "),
    (" < ", " <= "),
    (" <= ", " < "),
    (" > ", " >= "),
    (" >= ", " > "),
]


def find_sites(files):
    """Yield (file, line_no, col, old, new) for every operator site.

    Sites are searched only in the code part of each line (before `//`), so
    trailing comments do not register; the returned column refers to the
    position in the FULL line, and mutation splices at that exact column
    (never "first occurrence on the line", which could hit a comment).
    """
    for f in files:
        for no, line in enumerate(f.read_text().splitlines(), 1):
            stripped = line.lstrip()
            if stripped.startswith("//"):
                continue
            code = line.split("//")[0]
            for old, new in OPS:
                start = 0
                while True:
                    idx = code.find(old, start)
                    if idx < 0:
                        break
                    yield (f, no, idx, old, new)
                    start = idx + 1


def run_tests(module: Path, pkg: str, timeout: int) -> bool:
    """True if `go test` PASSES on the current (mutated) tree."""
    r = subprocess.run(
        ["go", "test", pkg, "-count=1"],
        cwd=module, capture_output=True, text=True, timeout=timeout,
    )
    return r.returncode == 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("module", help="module dir, e.g. 'common' or 'gateway'")
    ap.add_argument("pkg", help="package spec for go test, e.g. './config/'")
    ap.add_argument("--max-mutants", type=int, default=0, help="0 = all")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--timeout", type=int, default=300)
    ap.add_argument("--resume", default="", help="progress logfile: completed mutant indices are skipped; verdicts append")
    args = ap.parse_args()

    module = Path(args.module).resolve()
    if not (module / "go.mod").exists():
        sys.exit(f"no go.mod in {module}")
    pkg_dir = module / args.pkg.lstrip("./").rstrip("/")
    if not pkg_dir.is_dir():
        sys.exit(f"no such package dir: {pkg_dir}")

    files = sorted(
        p for p in pkg_dir.glob("*.go")
        if not p.name.endswith("_test.go")
    )
    if not files:
        sys.exit(f"no non-test Go files in {pkg_dir}")

    sites = list(find_sites(files))
    if not sites:
        sys.exit(f"no mutation sites found in {pkg_dir}")

    random.Random(args.seed).shuffle(sites)
    if args.max_mutants:
        sites = sites[: args.max_mutants]

    if args.list:
        for f, no, col, old, new in sites:
            line = f.read_text().splitlines()[no - 1]
            print(f"{f.name}:{no}:{col}: {old.strip()} -> {new.strip()}  | {line.strip()[:70]}")
        print(f"{len(sites)} site(s)")
        return 0

    # Baseline: the suite must pass BEFORE any mutation, else the run is
    # meaningless (and a red baseline would count as "kills").
    if not run_tests(module, args.pkg, args.timeout):
        sys.exit(f"BASELINE RED: go test {args.pkg} fails before mutating — fix first")
    print(f"baseline green; {len(sites)} mutant(s) to run")

    # Spot-instance doctrine: this host can be stopped at any moment. Three
    # defenses, all necessary (a SIGINT can skip the per-mutant restore and
    # leave a flipped condition in
    # handler/execute.go until the baseline test catches it):
    #   1. signals become exceptions so the finally-restore ALWAYS runs
    #      (SIGTERM — what a spot preemption sends first)
    #   2. the per-mutant restore lives in finally, not in-line
    #   3. every verdict line is flushed immediately — a stop loses at most
    #      the in-flight mutant, and --resume skips completed indices
    import signal, sys as _sys

    class _StopRequested(Exception):
        pass

    def _on_signal(signum, _frame):
        raise _StopRequested(f"signal {signum}")

    _prev_term = signal.signal(signal.SIGTERM, _on_signal)

    killed, survived = [], []
    done = set()
    if args.resume:
        rp = Path(args.resume)
        if rp.exists():
            import re as _re
            for ln in rp.read_text(errors="replace").splitlines():
                m = _re.match(r"\[(\d+)/", ln)
                if m:
                    done.add(int(m.group(1)))
            if done:
                print(f"resume: skipping {len(done)} completed mutant(s)")
    log = open(args.resume, "a") if args.resume else None
    try:
        for i, (f, no, col, old, new) in enumerate(sites, 1):
            if i in done:
                continue
            original = f.read_text()
            # precise splice: mutate exactly at the detected column
            lines = original.splitlines(keepends=True)
            tgt = lines[no - 1]
            assert tgt[col:col + len(old)] == old, f"site drifted: {f}:{no}:{col}"
            lines[no - 1] = tgt[:col] + new + tgt[col + len(old):]
            f.write_text("".join(lines))
            try:
                passed = run_tests(module, args.pkg, args.timeout)
            except subprocess.TimeoutExpired:
                passed = False  # a hang counts as killed (behavior change)
            finally:
                # restore and VERIFY the restore — on ANY exit path, signals
                # included (the finally runs before the exception propagates)
                f.write_text(original)
                if f.read_text() != original:
                    _sys.exit(f"RESTORE FAILED for {f} — aborting, file left mutated??")
            (killed if not passed else survived).append(
                (f.name, no, old.strip(), new.strip())
            )
            verdict = "KILLED" if not passed else "SURVIVED"
            line = f"[{i}/{len(sites)}] {verdict}  {f.name}:{no}  {old.strip()} -> {new.strip()}"
            print(line, flush=True)
            if log:
                log.write(line + "\n")
                log.flush()
    except _StopRequested as stop:
        print(f"STOPPED ({stop}) at mutant {i}/{len(sites)} — tree restored, "
              f"re-run with --resume to continue", flush=True)
        return 2
    finally:
        signal.signal(signal.SIGTERM, _prev_term)
        if log:
            log.close()

    total = len(killed) + len(survived)
    rate = (len(killed) / total * 100) if total else 0.0
    print(f"\nRESULT: {len(killed)}/{total} killed ({rate:.1f}%) · {len(survived)} survived")
    if survived:
        print("survivors (weak-assertion candidates — triage each):")
        for f, no, old, new in survived:
            print(f"  - {f}:{no}: {old} -> {new}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

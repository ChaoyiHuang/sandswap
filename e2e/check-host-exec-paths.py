#!/usr/bin/env python3
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
"""Guard: privileged host utilities must execute through absolute paths.

sandlot (NET_ADMIN+SYS_ADMIN), boxout (root), and the provision plane run
host tools (`nft`, `ip`, `cp`, `setpriv`). A bare exec.Command name resolves
through PATH, so a writable PATH entry is code execution for that identity.
All call sites must go through sandlot/hostbin (which pins absolute paths at
startup); this check fails on a new bare name or a raw LookPath outside it.

Usage: python3 -I e2e/check-host-exec-paths.py [repo-root]
"""

import re
import sys
from pathlib import Path

ROOT = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
SCAN_DIRS = ["sandlot", "boxout"]
ALLOW_FILE = Path("sandlot/hostbin/hostbin.go")

# exec.Command("name", ...) / exec.CommandContext(ctx, "name", ...)
BARE = re.compile(r'exec\.Command\(\s*"([^"/\\]+)"')
BARE_CTX = re.compile(r'exec\.CommandContext\([^,]+,\s*"([^"/\\]+)"')
LOOKPATH = re.compile(r'exec\.LookPath\(\s*"([^"/\\]+)"')


def main() -> int:
    violations = []
    for d in SCAN_DIRS:
        for p in sorted((ROOT / d).rglob("*.go")):
            rel = p.relative_to(ROOT)
            if p.name.endswith("_test.go") or rel == ALLOW_FILE:
                continue
            text = p.read_text(encoding="utf-8", errors="replace")
            for i, line in enumerate(text.splitlines(), 1):
                m = BARE.search(line) or BARE_CTX.search(line)
                if m:
                    violations.append(f"{rel}:{i}: bare exec name {m.group(1)!r} (use hostbin.Path)")
                    continue
                m = LOOKPATH.search(line)
                if m:
                    violations.append(f"{rel}:{i}: raw exec.LookPath {m.group(1)!r} (use hostbin.Path)")
    if violations:
        print("host-exec-path check: FAIL", file=sys.stderr)
        for v in violations:
            print("  - " + v, file=sys.stderr)
        return 1
    print("host-exec-path check: clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())

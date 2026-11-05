#!/usr/bin/env python3
# Copyright 2026 Chaoyi Huang. All rights reserved.
#
# SPDX-License-Identifier: BUSL-1.1
#
# check-shape-hardcodes.py — static guard for the deploy-shape ownership class.
#
# Mechanism (why this exists): the storage-plane split, the four identities and
# the volume-seed feature made PATH OWNERSHIP shape-dependent (see
# sandswap_apply_prov_plane in deploy/baremetal/common.sh for the contract).
# Every hand-written ownership operation in a deploy script is a place the
# shape can drift — the deploy matrix finds five such
# sites across three scripts and three systemd units, each breaking a
# different deploy mode. Ownership must flow from SS_PROV_USER /
# SS_SERVICE_USER_GW, never from a literal identity in a deploy script.
#
# Flags `chown <identity>` / `install ... -o <identity>` with a literal
# sandprov/sandlot/sandserv in deploy/**. Sanctioned exceptions are the
# implementation itself, read-only verifiers and the k8s manifests (uid-based).
# Run with an optional path prefix argument for self-testing.

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
IDENT = r"(?:sandprov|sandlot|sandserv)"
PATTERNS = [
    re.compile(rf"\bchown\b[^|;\n]*\b{IDENT}\b"),
    re.compile(rf"\binstall\b[^|;\n]*-o\s+{IDENT}\b"),
]
# The implementation of the contract + read-only checkers + docs.
ALLOW = (
    "deploy/baremetal/common.sh",
    "deploy/baremetal/sandswap-apply-prov-ownership.sh",
    "deploy/baremetal/setup-host.sh",     # unit-identity declarations (User=)
    "deploy/baremetal/uninstall.sh",
    "deploy/baremetal/cleanup.sh",
    "common/sh/runtime.sh",
    "security/",
    "deploy/k8s/",
)

def scan(root: Path):
    hits = []
    for f in sorted(list(root.glob("deploy/**/*.sh")) + list(root.glob("deploy/**/*.service"))):
        rel = str(f.relative_to(root))
        if any(rel.startswith(a) for a in ALLOW):
            continue
        try:
            lines = f.read_text().splitlines()
        except OSError:
            continue
        for i, ln in enumerate(lines, 1):
            if ln.lstrip().startswith("#"):
                continue
            # A literal used as a ${VAR:-default} fallback is not a hardcode.
            stripped = re.sub(r"\$\{[^}]*\}", "", ln)
            # Line-level, reasoned opt-out: `# shape-ok: <reason>` on the line
            # or the one before it (used ONLY for identity-PINNED service keys
            # that are not shape-dependent — e.g. the per-identity cert scoping
            # mirroring ss_own_tls_keys).
            if "shape-ok:" in ln or (i > 1 and "shape-ok:" in lines[i - 2]):
                continue
            for p in PATTERNS:
                m = p.search(stripped)
                if not m:
                    continue
                # A literal inside a quoted string is documentation/advice
                # (e.g. log "… chown sandprov …"), not an operation: skip when
                # an odd number of double quotes precedes the match.
                if ln[:m.start()].count('"') % 2 == 1:
                    continue
                hits.append(f"{rel}:{i}: {ln.strip()[:110]}")
    return hits

root = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else ROOT
hits = scan(root)
if hits:
    print(f"shape-hardcode scan: {len(hits)} literal-identity ownership site(s) — ownership must derive from SS_PROV_USER (see sandswap_apply_prov_plane):")
    for h in hits:
        print("  " + h)
    sys.exit(1)
print("shape-hardcode scan: clean (no literal ownership identities in deploy scripts)")

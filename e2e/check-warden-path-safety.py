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
"""Warden path-safety scan — the class as a standing gate.

The escape that motivates this gate: in FLAT mode the agent's chroot root IS its
volume, so every `<volume>/…` path the warden hands to the kernel is
agent-replaceable — and the kernel resolves symlinks in bind SOURCES, in mount
TARGETS and in plain open() paths, acting in the WARDEN's namespace. A planted
`rootfs -> /` symlink turned the mount-mode probe (`Path::exists()`, a
FOLLOWING stat) into "bind the warden's own initramfs as the chroot".

Review cannot enumerate that class once; this scan keeps the two mechanical
signatures of it visible, so a re-introduction is caught by the battery rather
than by the next escape drill:

  R1  `.exists()`  — a following stat. Every NON-TEST hit must sit within a
      few lines of a justification comment ("not a security decision",
      "does not follow symlinks", "ALLOW-EXISTS:"); the sanctioned probes are
      `symlink_metadata` / `RootAnchor::symlink_in_rootfs` (fstatat NOFOLLOW).
  R2  `fs::write(` / `File::create(` in the mount tree (`warden/src/mount/`)
      — a following WRITE. Only warden-owned, allow-listed sites may use
      them (the sanctioned agent-path writer is `RootAnchor::write_file`,
      O_NOFOLLOW).
  R3  `create_dir_all(` in the mount tree — follows symlinks in every
      component. Only warden-owned, allow-listed sites may use it directly
      (the sanctioned agent-path helper is `RootAnchor::open_dir`, openat
      NOFOLLOW).
  R4  A mount call whose TARGET argument is an inline `format!` of
      `mount_point`/`virtio_base` — the target must come from
      `RootAnchor::open_dir`/`open_file` (an O_NOFOLLOW fd anchor), never from
      a path the agent can replace between check and mount.
  R5  Canary: the sanctioned helpers must still exist in the mount tree
      (`mount/anchor.rs`) — if one is renamed/removed, this scan's
      allow-lists are stale and it must not keep reading green.

Test code (everything from the first `#[cfg(test)]` in a file onward — the
repo's layout) is skipped: tests plant symlinks deliberately.

Usage: python3 -I e2e/check-warden-path-safety.py [root]
Exit 1 on any violation. `[root]` (default: this script's repo) lets the
fault-injection harness point it at a scratch tree.
"""

import re
import sys
from pathlib import Path

# ── allow-lists (file, substring of the line) -> why it is warden-owned ──
#
# Every entry names a path the WARDEN owns (a constant of its own initramfs,
# a filesystem it mounted itself, or the sanctioned helper's own body), never
# a path under the agent's rootfs or a volume.
WRITE_ALLOW = {
    'fs::write(cg_root.join("cgroup.subtree_control")':
        "cgroupfs root the warden mounts itself (setup_cgroup_v2)",
    "std::fs::write(tmp_resolv":
        "warden-owned /tmp/sandswap-resolv.conf (the bind FALLBACK source)",
    "std::fs::File::create(&p)":
        "masked /proc entry inside the proc mount the warden created",
    "fs::create_dir_all(Path::new(m.dest))":
        "INIT_ROOTFS_MOUNTS: warden-owned mount destinations",
    'fs::create_dir_all("/run")':
        "warden-owned /run",
    "fs::create_dir_all(cg_root)":
        "cgroupfs root the warden mounts itself",
    "fs::create_dir_all(target)":
        "prepare_mount_dir's own body (the sanctioned helper)",
    "std::fs::create_dir_all(VIRTIOFS_MOUNT_POINT)":
        "warden-owned /mnt/volumes mount point",
    "std::fs::create_dir_all(mount_point)":
        "warden-owned /mnt/rootfs chroot root",
    "std::fs::create_dir_all(&pts)":
        "devpts dir inside the /dev tmpfs the warden just mounted",
    'std::fs::write(path, format!("{}\\n", value))':
        "KERNEL_SYSCTL_HARDENING: compile-time /proc/sys paths the warden owns",
}

JUSTIFY_MARKERS = (
    "not a security decision",
    "does not follow symlink",
    "ALLOW-EXISTS:",
)

# The mount tree must keep the fd/lstat discipline available (R5 canary):
# one anchored API replaced the per-target path helpers; the canary tracks
# the CURRENT sanctioned primitives, not the old names.
CANARY = (
    "struct RootAnchor",
    "fn check_component",
    "fn open_dir",
    "fn open_dir_strict",
    "fn open_file",
    "fn write_file",
    "fn symlink_in_rootfs",
)

MOUNT_CALL_RE = re.compile(r"\b(baremount|nix::mount::mount)\s*\(")


def split_args(text, start):
    """Return the top-level comma-separated arguments of the call at `start`."""
    depth, args, cur, i = 1, [], "", start
    while i < len(text) and depth:
        c = text[i]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
            if depth == 0:
                break
        if c == "," and depth == 1:
            args.append(cur)
            cur = ""
        else:
            cur += c
        i += 1
    args.append(cur)
    return args


def non_test_lines(path):
    """(lineno, line) up to the first #[cfg(test)] — tests plant symlinks."""
    out = []
    for i, line in enumerate(path.read_text().splitlines(), 1):
        if re.match(r"\s*#\[cfg\(test\)\]", line):
            break
        out.append((i, line))
    return out


def scan(root: Path):
    violations = []
    src = root / "warden" / "src"
    if not src.is_dir():
        return [f"{src}: not found (wrong root?)"]

    # The whole warden source tree, recursively: the mount code lives in a
    # module directory (mount/), and a glob of only the top level silently
    # stopped reading it after the split — the exact vacuous pass the
    # fault-injection drill caught.
    for f in sorted(src.rglob("*.rs")):
        if f.name == "tests.rs":
            continue  # test module by declaration (mod.rs gates it cfg(test))
        lines = non_test_lines(f)
        text = "\n".join(l for _, l in lines)

        # R1: following stats.
        for i, line in lines:
            if ".exists()" not in line or line.lstrip().startswith("//"):
                continue
            # Comments wrap (and legitimately sit above a fn): join the window's
            # comment text into one string so
            # a justification split across two `//` lines still matches.
            window = " ".join(
                re.sub(r"^\s*(//[/!]?|\*)\s?", "", l)
                for _, l in lines if abs(_ - i) <= 6
            )
            if not any(m in window for m in JUSTIFY_MARKERS):
                violations.append(
                    f"{f.relative_to(src)}:{i}: `.exists()` (follows symlinks) without a "
                    f"justification comment in ±6 lines — use symlink_metadata/"
                    f"is_real_dir, or state why it is not a security decision: "
                    f"{line.strip()[:90]}")

        # R2/R3: following writes/creates, the mount tree only (the code
        # that handles agent-replaceable paths).
        if f.parent.name == "mount" and f.name != "tests.rs":
            for i, line in lines:
                stripped = line.strip()
                if stripped.startswith("//"):
                    continue
                if any(k in line for k in ("fs::write(", "std::fs::write(", "File::create(", "create_dir_all(")):
                    if not any(k in line for k in WRITE_ALLOW):
                        violations.append(
                            f"{f.relative_to(src)}:{i}: following write/create on a "
                            f"potentially agent-controlled path — use "
                            f"write_agent_file/open_agent_file_target/"
                            f"prepare_mount_dir: {stripped[:90]}")

        # R4: mount targets built inline from the agent-reachable bases.
        for m in MOUNT_CALL_RE.finditer(text):
            args = split_args(text, m.end())
            if len(args) < 2:
                continue
            target = args[1]
            if "format!" in target and ("mount_point" in target or "virtio_base" in target):
                line_no = text[:m.start()].count("\n") + 1
                violations.append(
                    f"{f.relative_to(src)}:~{line_no}: mount target is an inline format! "
                    f"of an agent-reachable base — mount targets must come from "
                    f"prepare_mount_dir/open_agent_file_target (fd-anchored): "
                    f"{target.strip()[:90]}")

    # R5: canary — a MISSING anchor file is itself a violation (the old
    # `if is_file()` guard read green when the file vanished).
    anchor_rs = src / "mount" / "anchor.rs"
    if not anchor_rs.is_file():
        violations.append(
            f"{anchor_rs.relative_to(root)}: canary file missing — the "
            f"path-safety helpers moved; update this scan (do not just "
            f"delete the canary)")
    else:
        body = anchor_rs.read_text()
        pure_rs = src.parent / "src" / "pure.rs"
        pure_body = pure_rs.read_text() if pure_rs.is_file() else ""
        for fn in CANARY:
            if fn == "fn check_component":
                if fn not in pure_body:
                    violations.append(
                        f"pure.rs: canary missing `{fn}` — the single-"
                        f"component rule moved; update this scan")
                continue
            if fn not in body:
                violations.append(
                    f"mount/anchor.rs: canary missing `{fn}` — the "
                    f"path-safety helpers were renamed/removed; update this "
                    f"scan's allow-lists (do not just delete the canary)")
    return violations


def main() -> int:
    root = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path(__file__).resolve().parents[1]
    violations = scan(root)
    if violations:
        print(f"warden-path-safety: {len(violations)} violation(s)")
        for v in violations:
            print(f"  - {v}")
        return 1
    print("warden-path-safety: clean (no following-stat/write signatures, "
          "no unanchored mount targets, helpers present)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

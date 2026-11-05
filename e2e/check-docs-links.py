#!/usr/bin/env python3
"""Check that every relative .md link in docs/*.md resolves, anchors included.

Usage: python3 e2e/check-docs-links.py
Exit 0 = all links resolve; exit 1 = broken links listed.
Anchor slugging follows the kramdown/GitHub convention the site uses.

Also validates the backticked repo paths in CLAUDE.md (the index's whole job
is pointing at real files, so a renamed/deleted page must fail this check):
a backtick span qualifies as a repo path when it contains a "/", carries no
shell-prose characters, does not start with "-" or "/", and its first path
component is an existing repo-root directory; `{a,b}` groups are expanded.
"""
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DOCS = REPO / "docs"
LINK_RE = re.compile(r"\]\(([^)#\s]+)(#[^)\s]*)?\)")
BACKTICK_RE = re.compile(r"`([^`\n]+)`")
# A span with any of these is prose (flags, env assignments, code calls,
# absolute URL paths), never a repo-relative path.
PATH_DENY_RE = re.compile(r"[\s=:<>*?!'\"]|\(\)|://")


def anchorify(heading: str) -> str:
    t = heading.strip().lower()
    t = re.sub(r"[^\w\s-]", "", t)  # drop punctuation (em-dashes, parens, ...)
    return re.sub(r"\s", "-", t)    # each space becomes a hyphen


def headings(path: Path) -> set:
    text = path.read_text(encoding="utf-8")
    out = {anchorify(m.group(2)) for m in re.finditer(r"^(#{1,6})\s+(.*)$", text, re.M)}
    out |= set(re.findall(r"\{#([\w-]+)\}", text))
    return out


def expand_braces(span: str) -> list:
    """Expand one `{a,b,c}` group at a time (single level, no nesting)."""
    m = re.search(r"\{([^{}]*)\}", span)
    if not m:
        return [span]
    out = []
    for alt in m.group(1).split(","):
        out.extend(expand_braces(span[: m.start()] + alt.strip() + span[m.end():]))
    return out


def claude_md_paths(text: str):
    """Backticked repo-relative paths in CLAUDE.md → (checked, broken) lists."""
    bad, seen = [], set()
    for m in BACKTICK_RE.finditer(text):
        span = m.group(1).strip().lstrip("./").rstrip("/")
        if "/" not in span or PATH_DENY_RE.search(span) or span.startswith(("-", "{")):
            continue
        first = span.split("/", 1)[0]
        if not (REPO / first).is_dir():
            continue  # prose shorthand or a bare filename next to a full path
        for cand in expand_braces(span):
            seen.add(cand)
            if not (REPO / cand).exists():
                bad.append(f"CLAUDE.md: `{cand}`")
    return seen, bad


broken = []
checked = 0
for page in sorted(DOCS.rglob("*.md")):
    text = page.read_text(encoding="utf-8")
    for m in LINK_RE.finditer(text):
        target, anchor = m.group(1), (m.group(2) or "")[1:]
        if target.startswith(("http://", "https://", "mailto:", "/")):
            continue
        checked += 1
        resolved = (page.parent / target).resolve()
        if not resolved.exists():
            broken.append(f"{page.relative_to(DOCS.parent)}: {target}")
        elif anchor and resolved.suffix == ".md" and anchor not in headings(resolved):
            broken.append(f"{page.relative_to(DOCS.parent)}: {target}#{anchor}")

claude_md = REPO / "CLAUDE.md"
if claude_md.exists():
    seen, cb = claude_md_paths(claude_md.read_text(encoding="utf-8"))
    checked += len(seen)
    broken.extend(cb)

print(f"checked {checked} relative .md links under docs/ (+ CLAUDE.md backticked paths)")
if broken:
    print(f"BROKEN ({len(broken)}):")
    for b in broken:
        print("  " + b)
    sys.exit(1)
print("all links resolve")

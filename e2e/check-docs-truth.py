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
"""check-docs-truth.py — standing code<->docs drift gate.

Mechanical, READ-ONLY checks derived from the code (the authority), not from a
hand-kept copy of it. Each check runs BOTH directions where the direction is
meaningful, so a new flag/route/code/metric and a removed one are caught alike:

  flags     CLI flags registered by `gateway/cmd`, `sandlot/cmd` and
            `boxout/main.go` (`flag.X("name", …)`) vs every backticked `-flag`
            token in `docs/operations/configuration/<component>.md`; and every
            flag in a config page's CLI-flag TABLE row must exist in code.
  keys      YAML key paths from the `yaml:"…"` struct tags (recursively
            expanded from `GatewayConfig` / `SandlotConfig`) vs the matching
            config page; and every dotted key the page names must exist.
  routes    HTTP routes registered in `gateway/app/{exec,human,singlenode}.go`
            plus the `/human/` dispatchers (`gateway/handler/{human,namespace}.go`)
            vs `docs/reference/{agent-api,human-api}.md`; and every route in
            CLAUDE.md's backticked route tokens must exist in code.
  errors    `error_code` string constants emitted by `gateway/**` vs the docs
            (agent-api / human-api / mcp-tools); every SCREAMING_SNAKE code the
            pages name must be emitted by code.
  env       environment variables actually read (`os.Getenv`/`LookupEnv`/
            `ExpandEnv` in Go services, `env::var` + `*_ENV_VAR` constants in
            the warden) vs the docs; and every env var in a configuration page
            must be read by code (or be an explicitly allow-listed
            runtime-native/C-level name).
  mcp       tool names in `gateway/mcp/tools.go` vs the Tools table in
            `docs/reference/mcp-tools.md`, both directions.
  metrics   `sandswap_*` metric names emitted by `gateway/handler/metrics.go`
            vs `docs/integration/prometheus.md`, both directions (the page may
            group names with `_suffix` shorthand, which is expanded).
  terms     canonical-terminology deny-list (retired names only) over
            `docs/**/*.md`.

Allow-lists below are deliberately SMALL and every entry carries its reason.
Add one only for an intentional, permanent omission — never to silence drift
that should be fixed.

Usage: python3 -I e2e/check-docs-truth.py [root]
Exit 0 = every check green; exit 1 = violations listed by check.
Read-only and stdlib-only; well under a second on the full tree.
"""

import re
import sys
from pathlib import Path

# ── allow-lists ──────────────────────────────────────────────────────

# (component, flag) -> reason the flag is absent from the matching config page.
# Empty: every registered flag is documented today. The mechanism exists so a
# future test-only flag can be admitted WITH its reason instead of by deleting
# the check. Example shape:
#   ("sandlot", "some-test-only-flag"): "test-only knob, deliberately undocumented",
FLAG_DOC_EXEMPT = {}

# (component, flag) -> reason a config-page table row names a flag code lacks.
# Empty: every documented flag exists.
FLAG_CODE_EXEMPT = {}

# Env tokens in configuration pages that are NOT environment variables.
ENV_DOC_EXEMPT = {
    "ENOSPC": "POSIX errno discussed in the tmpfs/RLIMIT_AS prose, not an env var",
    "CAP_NET_BIND_SERVICE": "Linux capability name, not an env var",
    "CAP_BPF": "Linux capability name, not an env var",
    "INIT_ON_FREE_DEFAULT_ON": "kernel CONFIG build symbol in the init_on_free prose, not an env var",
}
# Env vars the docs document that are deliberately NOT read by our code.
ENV_CODE_EXEMPT = {
    "GOMEMLIMIT": "Go runtime-native soft memory limit; never read by our code",
}

# SCREAMING_SNAKE tokens in API reference pages that are not error codes.
ERROR_DOC_EXEMPT = {
    "AUTH": "shell variable declared in the human-api curl examples",
    "GET": "HTTP method",
    "POST": "HTTP method",
    "PUT": "HTTP method",
    "DELETE": "HTTP method",
    "PATCH": "HTTP method",
    "HEAD": "HTTP method",
    "OPTIONS": "HTTP method",
}

# File-ish terminal components: a dotted token ending in one of these is a
# path/URL fragment (config.go, build.sh, agent-api.md, boxout.sock, …).
# Dotted tokens with an unknown ROOT are not sandswap config keys and are
# skipped entirely: the pages legitimately reference other namespaces
# (warden.* kernel cmdline, net.ipv4.* sysctls, cgroup.kill, Keycloak's
# user.attribute/access.token, hostnames such as sandswap-stream.local).
KEY_DOC_EXEMPT_SUFFIXES = (
    "go", "sh", "py", "md", "json", "yaml", "yml", "sock", "crt", "key",
    "pem", "bin", "gz", "txt", "conf", "com", "org", "io", "ping", "role",
    "attribute", "token", "e.g",
)

# Retired names: (rule, regex, why it is retired). Case-sensitive on purpose —
# `Sandswap` is the project; the denied spellings are the retired identifiers.
TERMINOLOGY_DENY = [
    ("retired-sandvmm-flag", r"--sandbox-id",
     "the sandvmm --sandbox-id CLI flag is gone (vmm/src/main.rs); the "
     "sandbox id is internal"),
    ("retired-role", r"-roles local",
     "roles are exec|prov|exec,prov only; there is no local role"),
    ("retired-idle-reaper", r"idle reaper",
     "both-dead recovery is the manual reap-stuck tool, not a reaper"),
    ("retired-health-lease", r"lease is alive",
     "the health key has NO lease; liveness is last_healthy_ts staleness"),
    ("retired-rootfs-image", r"virtio-blk hotplug|ext4[- ]image",
     "rootfs is the permanent virtio-fs share; no ext4 image / blk hotplug"),
    ("retired-claim-spelling", r"sandswap-ns",
     "the OIDC claim is `sandswap_ns` (underscore)"),
    ("retired-role-name", r"provision sandlot|provision gateway",
     "the storage role is the prov sandlot; there is no provision gateway"),
    ("retired-986-name", r"\b(?:uid|user|identity)\s+`?sandswap`?\b",
     "the uid-986 identity is `sandserv` (renamed from `sandswap`)"),
    ("retired-seeder", r"gateway\s+seeds\b",
     "the prov instance seeds volumes; the gateway mounts no storage"),
]

# ── paths ────────────────────────────────────────────────────────────

ROOT = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"

FAILURES = []  # (check, message)


def read(path):
    return Path(path).read_text(encoding="utf-8", errors="replace")


def fail(check, msg):
    FAILURES.append((check, msg))


def rel(path):
    try:
        return str(Path(path).relative_to(ROOT))
    except ValueError:
        return str(path)


def docs_markdown():
    """Every docs/**/*.md."""
    yield from sorted(DOCS.rglob("*.md"))


# ── 1. CLI flags ─────────────────────────────────────────────────────

FLAG_REG_RE = re.compile(
    r'flag\.(?:String|Bool|Int|Int64|Float64|Duration|Uint|Uint64)(?:Var)?'
    r'\(\s*"([a-z0-9-]+)"')
DOC_FLAG_RE = re.compile(r"`(-[a-z0-9][a-z0-9-]*)`")
DOC_TABLE_FLAG_RE = re.compile(r"^\|\s*`(-[a-z0-9][a-z0-9-]*)`\s*\|", re.M)


def code_flags(component_dir):
    out = set()
    for f in sorted(Path(component_dir).glob("*.go")):
        if f.name.endswith("_test.go"):
            continue
        out |= set(FLAG_REG_RE.findall(read(f)))
    return out


def check_flags():
    components = [
        ("gateway", ROOT / "gateway/cmd", ROOT / "docs/operations/configuration/gateway.md"),
        ("sandlot", ROOT / "sandlot/cmd", ROOT / "docs/operations/configuration/sandlot.md"),
        ("boxout", ROOT / "boxout", ROOT / "docs/operations/configuration/boxout.md"),
    ]
    total = 0
    for name, codedir, doc in components:
        if not doc.is_file():
            fail("flags", f"{rel(doc)}: missing config page")
            continue
        code = code_flags(codedir)
        if not code:
            fail("flags", f"{rel(codedir)}: no flag registrations found — "
                         f"the extractor or the layout drifted")
            continue
        text = read(doc)
        documented = {m.lstrip("-") for m in DOC_FLAG_RE.findall(text)}
        for flag in sorted(code - documented):
            if (name, flag) in FLAG_DOC_EXEMPT:
                continue
            fail("flags", f"{rel(doc)}: missing flag `-{flag}` "
                         f"(registered in {rel(codedir)})")
        table_flags = {m.lstrip("-") for m in DOC_TABLE_FLAG_RE.findall(text)}
        for flag in sorted(table_flags - code):
            if (name, flag) in FLAG_CODE_EXEMPT:
                continue
            fail("flags", f"{rel(doc)}: documents `-{flag}` in a CLI-flag "
                         f"table row, but {rel(codedir)} does not register it")
        total += len(code)
    return f"flags: {total} registered flags checked against 3 config pages"


# ── 2. YAML keys ─────────────────────────────────────────────────────

YAML_FIELD_RE = re.compile(
    r'^\s*(\w+)\s+([\w\[\]\*\.]+)\s+`yaml:"([^"]*)"`', re.M)
STRUCT_RE = re.compile(r"type\s+(\w+)\s+struct\s*\{(.*?)\n\}", re.S)
# The lookbehind keeps hostnames out (`sandswap-stream.local` must not yield
# the token `stream.local` just because `-` is a regex word boundary).
DOC_DOTTED_RE = re.compile(
    r"(?<![\w.-])([a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+)\b")


def struct_types(path):
    types = {}
    for m in STRUCT_RE.finditer(read(path)):
        fields = [(fm.group(2), fm.group(3))
                  for fm in YAML_FIELD_RE.finditer(m.group(2))]
        types[m.group(1)] = fields
    return types


def yaml_paths(types, root_type, prefix=""):
    out = set()
    for ftype, key in types.get(root_type, []):
        if key in ("", "-"):
            continue
        path = prefix + key
        if ftype in types:
            out |= yaml_paths(types, ftype, path + ".")
        else:
            out.add(path)
    return out


def check_yaml_keys():
    components = [
        ("gateway", ROOT / "gateway/config/config.go", "GatewayConfig",
         ROOT / "docs/operations/configuration/gateway.md"),
        ("sandlot", ROOT / "sandlot/config/config.go", "SandlotConfig",
         ROOT / "docs/operations/configuration/sandlot.md"),
    ]
    all_paths = set()
    per_component = {}
    for name, cfg, root_type, doc in components:
        paths = yaml_paths(struct_types(cfg), root_type)
        if not paths:
            fail("keys", f"{rel(cfg)}: no yaml struct tags found — extractor drift")
            continue
        per_component[name] = (paths, doc, cfg)
        all_paths |= paths
    for paths, doc, cfg in per_component.values():
        text = read(doc)
        backticked = set(re.findall(r"`([^`]+)`", text))
        for path in sorted(paths):
            leaf = path.rsplit(".", 1)[-1]
            # Documented either as the full dotted key, or (top-level keys and
            # table rows that show a leaf) as a backticked token.
            if path not in text and leaf not in backticked:
                fail("keys", f"{rel(doc)}: missing YAML key `{path}` "
                             f"(declared in {rel(cfg)})")
        # Reverse: a dotted token whose root IS a sandswap top-level key (of
        # either component — pages cross-reference each other) must exist.
        roots = {p.split(".", 1)[0] for p in all_paths}
        for token in sorted(set(DOC_DOTTED_RE.findall(text))):
            root = token.split(".", 1)[0]
            if root not in roots:
                continue  # not a sandswap config key (see KEY_DOC_EXEMPT_SUFFIXES note)
            if token in all_paths or token in paths:
                continue
            if token.rsplit(".", 1)[-1] in KEY_DOC_EXEMPT_SUFFIXES:
                continue
            fail("keys", f"{rel(doc)}: documents `{token}`, which no "
                         f"yaml struct tag in either config declares")
    return "keys: YAML key paths checked against the two config pages"


# ── 3. HTTP routes ───────────────────────────────────────────────────

ROUTE_SECTIONS = ("/agent", "/human", "/mcp", "/health", "/ready", "/stats",
                  "/metrics")
DOC_BACKTICK_ROUTE_RE = re.compile(
    r"`((?:GET|POST|PUT|DELETE|PATCH)\s+)?(/[^`\s]+)`")


def norm_route(path):
    """Collapse placeholders so doc and code spellings compare equal."""
    path = path.strip()
    path = path.replace("…", "")
    path = re.sub(r"<[^>]+>", "{x}", path)      # <ns> / <id>
    path = re.sub(r"\{[^}]+\}", "{x}", path)    # {sandfs_id} / {id} / {ref}
    path = re.sub(r"\[[^\]]*\]$", "", path)     # stale [-node] shorthands
    path = re.sub(r"[.,;:]+$", "", path)
    return path.rstrip("/") or "/"


def code_routes():
    routes = set()
    for name in ("exec.go", "human.go", "singlenode.go"):
        text = read(ROOT / "gateway/app" / name)
        routes |= set(re.findall(r'\.Handle(?:Func)?\(\s*"(/[^"]+)"', text))
    # /human/ dispatcher: literal cases and prefix(+suffix) cases.
    h = read(ROOT / "gateway/handler/human.go")
    routes |= set(re.findall(r'path == "(/human/[^"]+)"', h))
    for m in re.finditer(
            r'strings\.HasPrefix\(path,\s*"(/human/[^"]+)"\)'
            r'(?: && strings\.HasSuffix\(path,\s*"([^"]+)"\))?', h):
        prefix, suffix = m.group(1), m.group(2) or ""
        routes.add(prefix + "{id}" + suffix)
    # Namespaced subtree: `rest` is relative to /human/ns/{ns}/.
    ns = read(ROOT / "gateway/handler/namespace.go")
    ns_prefix = "/human/ns/{ns}/"
    for m in re.finditer(r'rest == "([^"]+)"', ns):
        routes.add(ns_prefix + m.group(1))
    for m in re.finditer(r'strings\.HasPrefix\(rest,\s*"([^"]+)"\)', ns):
        routes.add(ns_prefix + m.group(1) + "{id}")
    for m in re.finditer(
            r'strings\.HasPrefix\(rest,\s*"sandfs/"\)(.{0,240}?)'
            r'strings\.HasSuffix\(rest,\s*"([^"]+)"\)', ns, re.S):
        routes.add(ns_prefix + "sandfs/{id}" + m.group(2))
    for action in re.findall(
            r'case "((?:detach|attach|swap|save)-template)":', ns):
        routes.add(ns_prefix + "sandfs/{id}/" + action)
    # Handler-mount prefixes ending in "/" are dispatch roots, not endpoints.
    return {norm_route(r) for r in routes if not r.endswith("/")}


def doc_routes(pages):
    """Route-shaped tokens from the pages, with `· `/suffix` shorthand expanded.

    `/human/sandfs/{id}/detach-template` · `/attach-template` — the second
    token is relative to the first route's parent; expand it so a page that
    groups sibling actions still counts as documenting each one.
    """
    out = set()
    for page in pages:
        for line in read(page).splitlines():
            last_full = None
            for m in DOC_BACKTICK_ROUTE_RE.finditer(line):
                path = m.group(2)
                if not path.startswith("/"):
                    continue
                if any(path == s or path.startswith(s + "/")
                       for s in ROUTE_SECTIONS):
                    last_full = path
                    out.add(norm_route(path))
                elif last_full and "." not in path:
                    parent = last_full.rsplit("/", 1)[0]
                    out.add(norm_route(parent + path))
    return out


def check_routes():
    routes = code_routes()
    if not routes:
        fail("routes", "no gateway routes extracted — extractor or layout drift")
        return "routes: nothing extracted"
    reference = [ROOT / "docs/reference/agent-api.md",
                 ROOT / "docs/reference/human-api.md"]
    documented = doc_routes(reference)
    for route in sorted(routes - documented):
        fail("routes", f"registered route `{route}` is not documented in "
                       f"docs/reference/agent-api.md or human-api.md")
    # CLAUDE.md -> code (reverse direction: it names a subset of endpoints
    # inline — an index, not an endpoint table — so any backticked route
    # token anywhere in the file must match a registration).
    claude = ROOT / "CLAUDE.md"
    if claude.is_file():
        text = read(claude)
        for token in sorted(set(re.findall(r"`(/[a-z][^`\s]*)`", text))):
            if not any(token.startswith(s) for s in ROUTE_SECTIONS):
                continue
            if norm_route(token) not in routes:
                fail("routes", f"CLAUDE.md names `{token}`, "
                               f"but no gateway registration matches")
    return f"routes: {len(routes)} registered routes checked"


# ── 4. Structured error codes ────────────────────────────────────────
ERROR_CODE_RES = (
    re.compile(r'errorCode\s*[:=]\s*"([A-Z][A-Z0-9_]+)"'),
    re.compile(r'error_code"\s*:\s*"([A-Z][A-Z0-9_]+)"'),
    re.compile(r'ErrorCode\s*[:=]\s*"([A-Z][A-Z0-9_]+)"'),
)
DOC_CAP_CODE_RE = re.compile(r"`([A-Z][A-Z0-9_]{2,})`")


def check_error_codes():
    code = set()
    for f in sorted((ROOT / "gateway").rglob("*.go")):
        if f.name.endswith("_test.go"):
            continue
        text = read(f)
        for rx in ERROR_CODE_RES:
            code |= set(rx.findall(text))
    if not code:
        fail("errors", "no error_code literals found in gateway/ — extractor drift")
        return "errors: nothing extracted"
    pages = [ROOT / "docs/reference/agent-api.md",
             ROOT / "docs/reference/human-api.md",
             ROOT / "docs/reference/mcp-tools.md"]
    documented = set()
    for page in pages:
        documented |= set(DOC_CAP_CODE_RE.findall(read(page)))
    for c in sorted(code - documented):
        fail("errors", f"emitted error_code `{c}` is not documented in "
                       f"docs/reference/{{agent-api,human-api,mcp-tools}}.md")
    for token in sorted(documented - code):
        if token in ERROR_DOC_EXEMPT:
            continue
        fail("errors", f"docs name error code `{token}`, but no gateway source "
                       f"emits it")
    return f"errors: {len(code)} emitted error codes checked"


# ── 5. Environment variables ─────────────────────────────────────────

GO_ENV_RE = re.compile(
    r'(?:os\.Getenv|os\.LookupEnv|os\.ExpandEnv)\(\s*"([A-Z][A-Z0-9_]+)"')
RS_ENV_CONST_RE = re.compile(
    r'const\s+[A-Z0-9_]+_ENV_VAR:\s*&str\s*=\s*"([A-Z][A-Z0-9_]+)"')
RS_ENV_LITERAL_RE = re.compile(r'env::var\(\s*"([A-Z][A-Z0-9_]+)"\s*\)')


def code_env_vars():
    env = set()
    # Services plus the operator tools (sandctl, dns) — every env var any
    # shipped Go binary reads must be documented somewhere.
    for d in ("gateway", "sandlot", "boxout", "common", "sandctl", "dns"):
        for f in sorted((ROOT / d).rglob("*.go")):
            if f.name.endswith("_test.go"):
                continue
            env |= set(GO_ENV_RE.findall(read(f)))
    # The warden reads env in config.rs (constant table) and in exec.rs
    # (WARDEN_PIDFD opt-out), so scan every source file.
    for f in sorted((ROOT / "warden/src").glob("*.rs")):
        text = read(f)
        env |= set(RS_ENV_CONST_RE.findall(text))
        env |= set(RS_ENV_LITERAL_RE.findall(text))
    return env


def check_env():
    env = code_env_vars()
    if not env:
        fail("env", "no env reads extracted — extractor drift")
        return "env: nothing extracted"
    all_docs = " ".join(read(p) for p in docs_markdown())
    for var in sorted(env):
        if var not in all_docs:
            fail("env", f"code reads env var `{var}`, but no doc mentions it")
    # Reverse: every env-shaped token in a configuration page must be read.
    for page in sorted((ROOT / "docs/operations/configuration").glob("*.md")):
        for token in sorted(set(DOC_CAP_CODE_RE.findall(read(page)))):
            if token in env or token in ENV_DOC_EXEMPT or token in ENV_CODE_EXEMPT:
                continue
            fail("env", f"{rel(page)}: documents env var `{token}`, but no "
                        f"service code reads it (add it to the page's prose, "
                        f"or allow-list it with a reason)")
    return f"env: {len(env)} code-read env vars checked"


# ── 6. MCP tool names ────────────────────────────────────────────────

MCP_NAME_RE = re.compile(r'Name:\s+"([a-z][a-z0-9_]*)"')


def check_mcp():
    tools_src = ROOT / "gateway/mcp/tools.go"
    page = ROOT / "docs/reference/mcp-tools.md"
    if not tools_src.is_file() or not page.is_file():
        fail("mcp", "gateway/mcp/tools.go or docs/reference/mcp-tools.md missing")
        return "mcp: files missing"
    code = set(MCP_NAME_RE.findall(read(tools_src)))
    text = read(page)
    section = re.search(r"^## Tools\n(.*?)(?=^## )", text, re.S | re.M)
    if not section:
        fail("mcp", "docs/reference/mcp-tools.md: '## Tools' section not found")
        return "mcp: section missing"
    documented = set(re.findall(r"^\|\s*`([a-z][a-z0-9_]*)`\s*\|",
                                section.group(1), re.M))
    for tool in sorted(code - documented):
        fail("mcp", f"tool `{tool}` is registered but absent from the "
                    f"mcp-tools.md Tools table")
    for tool in sorted(documented - code):
        fail("mcp", f"mcp-tools.md documents tool `{tool}`, but buildToolsList "
                    f"does not register it")
    return f"mcp: {len(code)} tool names checked"


# ── 7. /metrics metric names ─────────────────────────────────────────

METRIC_CODE_RE = re.compile(r'"(sandswap_[a-z0-9_]+)"')


def metric_documented(code_metrics):
    """Expand the page's `_suffix` grouping shorthand against full names.

    `sandswap_gateway_clean_vms` / `_total_vms` means
    `sandswap_gateway_total_vms`: for a full token P and shorthand S, accept
    any `P`-prefix + `S` combination that is an actual code metric.
    """
    documented = set()
    page = ROOT / "docs/integration/prometheus.md"
    if not page.is_file():
        return documented, "docs/integration/prometheus.md missing"
    for line in read(page).splitlines():
        last_full = None
        for m in re.finditer(r"`([a-z0-9_]+)`", line):
            token = m.group(1)
            if token.startswith("sandswap_"):
                last_full = token
                documented.add(token)
            elif token.startswith("_") and last_full:
                parts = last_full.split("_")
                short = token.lstrip("_").split("_")
                for k in range(1, len(parts)):
                    candidate = "_".join(parts[:-k] + short)
                    if candidate in code_metrics:
                        documented.add(candidate)
    return documented, None


def check_metrics():
    src = ROOT / "gateway/handler/metrics.go"
    if not src.is_file():
        fail("metrics", "gateway/handler/metrics.go missing")
        return "metrics: file missing"
    code = set(METRIC_CODE_RE.findall(read(src)))
    if not code:
        fail("metrics", "no sandswap_* metric literals found — extractor drift")
        return "metrics: nothing extracted"
    documented, err = metric_documented(code)
    if err:
        fail("metrics", err)
        return "metrics: page missing"
    for name in sorted(code - documented):
        fail("metrics", f"metric `{name}` is emitted but not documented in "
                        f"docs/integration/prometheus.md")
    for name in sorted(documented - code):
        fail("metrics", f"prometheus.md documents `{name}`, but metrics.go "
                        f"never emits it")
    return f"metrics: {len(code)} metric names checked"


# ── 8. Canonical terminology deny-list ───────────────────────────────

def check_terminology():
    compiled = [(rule, re.compile(rx), why) for rule, rx, why in TERMINOLOGY_DENY]
    for page in docs_markdown():
        for lineno, line in enumerate(read(page).splitlines(), 1):
            for rule, rx, why in compiled:
                if rx.search(line):
                    fail("terms", f"{rel(page)}:{lineno}: retired name "
                                  f"({rule}) — {why}")
    return f"terms: {len(compiled)} deny-list rules over the docs tree"


# ── main ─────────────────────────────────────────────────────────────

CHECKS = [
    ("flags", check_flags),
    ("keys", check_yaml_keys),
    ("routes", check_routes),
    ("errors", check_error_codes),
    ("env", check_env),
    ("mcp", check_mcp),
    ("metrics", check_metrics),
    ("terms", check_terminology),
]


def main():
    if not (ROOT / "gateway").is_dir():
        print(f"check-docs-truth: {ROOT}: not a sandswap tree (no gateway/)")
        return 1
    for name, fn in CHECKS:
        try:
            summary = fn()
        except Exception as exc:  # a checker crash must fail loud, not skip
            fail(name, f"check crashed: {exc!r}")
            summary = f"{name}: crashed"
        print(f"  [{name}] {summary}")
    if FAILURES:
        print(f"\ndocs-truth: {len(FAILURES)} violation(s)")
        for check, msg in FAILURES:
            print(f"  - [{check}] {msg}")
        return 1
    print(f"\ndocs-truth: clean ({len(CHECKS)} checks, both directions)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

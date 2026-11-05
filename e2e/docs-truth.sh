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
# docs-truth.sh — the standing code<->docs parity row.
#
# Runs e2e/check-docs-truth.py, which derives the truth from the code and
# fails on drift in BOTH directions: CLI flags, YAML config keys, HTTP routes,
# structured error codes, environment variables, MCP tool names, /metrics
# metric names, and the canonical-terminology deny-list. Read-only, static,
# stdlib-only, ~0.4 s — no root, no KVM, no stack. It is the FIRST row of the
# battery: a broken doc is a release defect that should surface before any
# microVM boots.
#
# Usage: bash e2e/docs-truth.sh   (also a battery row; run-all.sh executes it)
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck disable=SC1091
source "$ROOT/e2e/common.sh"

# Clean-host precondition: every environment-owning script starts from a
# clean host. Leftovers from a DEAD previous run are killed here; a
# CONCURRENT harness run is refused by name (ss_harness_guard), never killed.
tc_clean_environment

if python3 -I "$ROOT/e2e/check-docs-truth.py"; then
    tc_pass "code<->docs truth checks green"
else
    tc_fail "code<->docs drift (named violations above; fix the code or the page)"
fi

# tc_fail only counts; the row's exit code is this tail (the framework-unit
# convention — a suite that exits 0 with FAIL_COUNT>0 would count as PASS).
if [[ "${FAIL_COUNT:-0}" -gt 0 ]]; then
    exit 1
fi
exit 0

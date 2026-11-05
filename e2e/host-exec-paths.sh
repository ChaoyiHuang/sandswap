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
# host-exec-paths.sh — unit wrapper for check-host-exec-paths.py. Fails when a
# privileged component executes a host utility by bare name (PATH-resolved)
# instead of through sandlot/hostbin's pinned absolute path.
#
# Usage: bash e2e/host-exec-paths.sh

set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
exec python3 -I "$ROOT/e2e/check-host-exec-paths.py" "$ROOT"

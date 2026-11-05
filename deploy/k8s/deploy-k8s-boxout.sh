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
# deploy-k8s-boxout.sh — Deploy Sandswap on k3s, boxout sidecar mode (thin entry).
# One-click script with the same phases as deploy-k8s-embedded.sh (see that
# file / deploy-lib.sh for the flow — default keep mode; --verify runs the
# drill + teardown). Boxout mode differences:
#   - boxout container (privileged, UID 0) owns VM lifecycle, network, overlay
#   - sandlot container (unprivileged, RESERVED UID 65536) only handles gRPC +
#     vsock, delegating the privileged path over /run/sandswap/boxout.sock
#   - manifest is sandlot-boxout.yaml; images are boxout (ubuntu, has
#     sandvmm + vsockguardctl) + sandlot-boxout (ubuntu, sandbox binary only)
#   - vsockguard allows UID 65536 (not 0); /run/sandswap is chowned to 65536
#     (the reserved sandbox identity — outside every uid the node allocates
#     on its own; e2e/deploy-tree-pins.sh pins it across all manifests)
# ALL shared logic lives in deploy-lib.sh — this file holds only the mode
# context. Fix bugs there, once, for both modes.
# Prerequisites: same as deploy-k8s-embedded.sh
# Usage:
#   sudo bash deploy/k8s/deploy-k8s-boxout.sh                  # deploy + keep
#   sudo bash deploy/k8s/deploy-k8s-boxout.sh --skip-build
#   sudo DEEPSEEK_API_KEY=sk-xxx bash deploy/k8s/deploy-k8s-boxout.sh --verify [--failover]
#   Verify a kept deployment separately: deploy/k8s/verify-k8s.sh
#   Remove a kept deployment:            deploy/k8s/k8s-cleanup.sh
#   Flags: --skip-build --skip-images --skip-deps --verify [--failover]

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
source "$ROOT/e2e/common.sh"
# k3s IS this deployer's runtime (and build-images needs docker): keep
# the container runtimes the e2e prelude would otherwise stop.
export SANDSWAP_KEEP_CONTAINER_RUNTIME=1
source "$ROOT/deploy/k8s/deploy-lib.sh"

# ── Mode context ─────────────────────────────────────────────────────
MODE_NAME="boxout"
MODE_DESC="boxout (privileged sidecar + unprivileged UID 65536 sandlot)"
VSOCKGUARD_UID=65536
SANDLOT_MANIFEST="$ROOT/deploy/k8s/sandlot-boxout.yaml"
SANDLOT_DS="sandlot-boxout"
SANDLOT_SELECTOR="app=sandlot-boxout"
# Container names dumped on failure (boxout pod has two containers)
SANDLOT_DS_LOG_CONTAINERS="boxout sandlot"
IMAGE_LIST=(sandswap/gateway sandswap/boxout sandswap/sandlot-boxout sandswap/sandns)
# Boxout sidecar is privileged and owns the devices directly — no GID
# injection needed (GIDs are still detected for logging).
NEEDS_GID_INJECTION=false
# Unprivileged sandlot (UID 65536) writes state.json and connects to
# boxout.sock under /run/sandswap
CHOWN_RUN_DIR_UID=65536
SANDBOX_UID=65536
VERIFY_SANDBOX_UID=true
# VM-reuse check greps the boxout container log (it drives VM lifecycle)
VM_REUSE_LOGS=(-l app=sandlot-boxout -c boxout)
VM_REUSE_PATTERN='created VM\|VM created\|new VM\|create_vm'
EINO_BIN_NAME="eino-sandswap-k8s-boxout"

k8s_deploy_main "$@"

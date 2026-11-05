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
# deploy-k8s-embedded.sh — Deploy Sandswap on k3s, embedded mode (thin entry).
# One-click script that:
#   1. Cleans any previous deployment, runs the preflight checks
#   2. Installs k3s (if missing), builds all artifacts + container images
#   3. Generates TLS certificates, applies the K8s manifests
#   4. Waits for readiness, wires CoreDNS → sandswap-sandns, smoke-checks
#      reachability, then LEAVES THE DEPLOYMENT RUNNING (default keep mode)
# With --verify it instead runs the built-in drill (4 agents + 4 sandfs,
# affinity self-test, eino multi-agent run, optional --failover) and tears
# the deployment down afterwards.
# Embedded mode: the sandlot DaemonSet runs as UID 0 (privileged) and owns
# ALL privileged operations itself — sandvmm lifecycle, TAP/bridge network
# provisioning, OverlayFS mounts, /proc re-adopt. The manifest is
# sandlot.yaml; the image is sandswap/sandlot (ubuntu + iproute2 + sandvmm).
# ALL shared logic lives in deploy-lib.sh — this file holds only the mode
# context. Fix bugs there, once, for both modes.
# Prerequisites:
#   - KVM available (/dev/kvm + /dev/vhost-vsock)
#   - Root access
#   - docker (for building container images)
#   - DEEPSEEK_API_KEY or OPENAI_API_KEY — only for --verify (the eino run)
# Usage:
#   sudo bash deploy/k8s/deploy-k8s-embedded.sh                  # deploy + keep
#   sudo bash deploy/k8s/deploy-k8s-embedded.sh --skip-build
#   sudo DEEPSEEK_API_KEY=sk-xxx bash deploy/k8s/deploy-k8s-embedded.sh --verify [--failover]
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
MODE_NAME="embedded"
MODE_DESC="embedded (sandlot runs as UID 0, privileged — owns VM lifecycle)"
VSOCKGUARD_UID=0
SANDLOT_MANIFEST="$ROOT/deploy/k8s/sandlot.yaml"
SANDLOT_DS="sandlot"
SANDLOT_SELECTOR="app=sandlot"
# Container names dumped on failure (embedded DS has a single container)
SANDLOT_DS_LOG_CONTAINERS="sandlot"
# sandswap/sandlot-boxout: the sandlot-prov Deployment (applied unconditionally
# by deploy-lib) runs on that image — the --skip-images preflight must demand it.
IMAGE_LIST=(sandswap/gateway sandswap/sandlot sandswap/sandlot-boxout sandswap/sandns)
# Embedded sandlot accesses /dev/kvm + /dev/vhost-vsock as supplemental
# groups — GIDs are distro-specific, so they are injected into the manifest.
NEEDS_GID_INJECTION=true
CHOWN_RUN_DIR_UID=""
VERIFY_SANDBOX_UID=false
# VM-reuse check greps the sandlot container log
VM_REUSE_LOGS=(-l app=sandlot)
VM_REUSE_PATTERN='created VM\|VM created\|new VM'
EINO_BIN_NAME="eino-sandswap-k8s"

k8s_deploy_main "$@"

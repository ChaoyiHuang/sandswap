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
# build-images.sh — Build Sandswap container images from pre-built binaries.
# Reads binaries from output/ directory. Must run after build.sh.
# For k3s, images are imported directly into the container runtime
# (no external registry needed).
# Usage:
#   bash deploy/k8s/build-images.sh              # build all + import to k3s
#   bash deploy/k8s/build-images.sh --mode embedded  # gateway + sandlot only
#   bash deploy/k8s/build-images.sh --mode boxout    # gateway + boxout + sandlot-boxout
#   bash deploy/k8s/build-images.sh --no-import   # build only, don't import
#   REGISTRY=myregistry.io bash deploy/k8s/build-images.sh  # custom registry prefix
# Prerequisites:
#   - docker (for building images)
#   - k3s (for importing, unless --no-import)
#   - output/gateway, output/sandlot, output/sandvmm (from build.sh)
#   - output/vsockguard.bpf.o, output/vsockguardctl (from build.sh vsockguard)

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUTPUT="$ROOT/output"
IMAGE_TAG="${IMAGE_TAG:-latest}"
REGISTRY="${REGISTRY:-sandswap}"
NO_IMPORT=false
MODE="all"  # all | embedded | boxout

for arg in "$@"; do
    case "$arg" in
        --no-import) NO_IMPORT=true ;;
        --mode=*)    MODE="${arg#--mode=}" ;;
    esac
done

# Validate mode
case "$MODE" in
    embedded|boxout|all) ;;
    *)
        echo "error: unknown mode '$MODE' (use embedded|boxout|all)" >&2
        exit 1
        ;;
esac

# Determine which images/binaries are needed based on mode
NEEDED_BINS=()
NEEDED_IMAGES=()

case "$MODE" in
    embedded)
        # Embedded mode: gateway + sandlot + sandns (ubuntu-based with sandvmm + vsockguard)
        # + sandlot-boxout: the sandlot-prov Deployment (applied in BOTH modes)
        # runs on the minimal sandlot-boxout image — it must exist in k3s here
        # too or the prov pod dies on ErrImageNeverPull.
        NEEDED_BINS=(gateway sandlot sandvmm vsockguard.bpf.o vsockguardctl sandns bindregdump)
        NEEDED_IMAGES=(gateway sandlot sandlot-boxout sandns)
        ;;
    boxout)
        # Boxout mode: gateway (exec + admin) + boxout (with sandvmm + vsockguard) + sandlot-boxout (sandbox binary)
        NEEDED_BINS=(gateway boxout sandlot sandvmm vsockguard.bpf.o vsockguardctl sandns bindregdump)
        NEEDED_IMAGES=(gateway boxout sandlot-boxout sandns)
        ;;
    all)
        # All images
        NEEDED_BINS=(gateway sandlot boxout sandvmm vsockguard.bpf.o vsockguardctl sandns bindregdump)
        NEEDED_IMAGES=(gateway sandlot boxout sandlot-boxout sandns)
        ;;
esac

# Verify binaries exist
for bin in "${NEEDED_BINS[@]}"; do
    if [[ ! -f "$OUTPUT/$bin" ]]; then
        echo "error: $OUTPUT/$bin not found. Run: bash build/build.sh all" >&2
        exit 1
    fi
done

# Docker daemon bootstrap. The k8s deployers bring the daemon up themselves
# (k8s_phase_images); this standalone builder must too: on a clean host (or
# right after a round's final cleanup stopped the runtime) the daemon is down
# and every build dies with "Cannot connect to the Docker daemon" — a fixable
# precondition, not a builder failure.
if ! command -v docker >/dev/null 2>&1; then
    echo "error: docker is not installed (required for image builds)" >&2
    exit 1
fi
if ! docker info >/dev/null 2>&1; then
    echo "docker daemon down — starting docker.socket + docker.service"
    systemctl start docker.socket docker.service 2>/dev/null || true
    for _ in $(seq 1 30); do
        docker info >/dev/null 2>&1 && break
        sleep 1
    done
    docker info >/dev/null 2>&1 || { echo "error: docker daemon did not come up" >&2; exit 1; }
fi

# docker_build — `docker build` on the HOST network by default. Two failure
# classes make docker's own bridge networking the wrong default HERE:
#   1. A systemd-resolved host (127.0.0.53 stub) hands the container a
#      resolver it cannot reach — every apt-get dies with "Temporary failure
#      resolving".
#   2. The k8s deployers install k3s BEFORE building images, and kube-router
#      sets the iptables FORWARD policy to DROP; docker's default-bridge
#      build containers egress through FORWARD and are silently black-holed
#      (apt hangs / "no installation candidate") while the host itself has
#      a clean route.
# Build-time fetches are trusted, root-driven operations — host networking
# carries no downside for these images. Export DOCKER_BUILD_NETWORK=default
# to go back to docker's own networking.
docker_build() {
    local net="${DOCKER_BUILD_NETWORK:-host}"
    if [[ "$net" == "default" ]]; then
        docker build "$@"
    else
        docker build --network "$net" "$@"
    fi
}

# The entrypoint wrappers live in the repo tree but the image build context
# is output/; stage them where the Dockerfiles COPY from.
cp -f "$ROOT/deploy/k8s/images/sandlot-entrypoint.sh" "$OUTPUT/sandlot-entrypoint.sh"
cp -f "$ROOT/deploy/k8s/images/boxout-entrypoint.sh" "$OUTPUT/boxout-entrypoint.sh"

echo "Building Sandswap container images (mode=$MODE)..."

# Gateway image (ubuntu base — static Go binary + ca-certificates + shell)
# Always needed (exec gateway + admin gateway both use this image)
if [[ " ${NEEDED_IMAGES[*]} " =~ " gateway " ]]; then
    echo "  Building $REGISTRY/gateway:$IMAGE_TAG (ubuntu)..."
    docker_build -t "$REGISTRY/gateway:$IMAGE_TAG" \
        -f "$ROOT/deploy/k8s/images/gateway.Dockerfile" "$OUTPUT"
fi

# Sandlot image (ubuntu:22.04 — iproute2 + dynamic sandvmm + vsockguard)
if [[ " ${NEEDED_IMAGES[*]} " =~ " sandlot " ]]; then
    echo "  Building $REGISTRY/sandlot:$IMAGE_TAG (ubuntu+iproute2)..."
    docker_build -t "$REGISTRY/sandlot:$IMAGE_TAG" \
        -f "$ROOT/deploy/k8s/images/sandlot.Dockerfile" "$OUTPUT"
fi

# Boxout image (ubuntu:22.04 — iproute2 + dynamic sandvmm + vsockguard, for boxout sidecar)
if [[ " ${NEEDED_IMAGES[*]} " =~ " boxout " ]]; then
    echo "  Building $REGISTRY/boxout:$IMAGE_TAG (ubuntu+iproute2)..."
    docker_build -t "$REGISTRY/boxout:$IMAGE_TAG" \
        -f "$ROOT/deploy/k8s/images/boxout.Dockerfile" "$OUTPUT"
fi

# Sandlot-boxout image (ubuntu base — sandbox Go binary only, for boxout-mode sandlot)
if [[ " ${NEEDED_IMAGES[*]} " =~ " sandlot-boxout " ]]; then
    echo "  Building $REGISTRY/sandlot-boxout:$IMAGE_TAG (ubuntu)..."
    docker_build -t "$REGISTRY/sandlot-boxout:$IMAGE_TAG" \
        -f "$ROOT/deploy/k8s/images/sandlot-boxout.Dockerfile" "$OUTPUT"
fi

# Sandswap DNS image (ubuntu base — static Go binary, owner-aware resolver :53)
if [[ " ${NEEDED_IMAGES[*]} " =~ " sandns " ]]; then
    echo "  Building $REGISTRY/sandns:$IMAGE_TAG (ubuntu)..."
    docker_build -t "$REGISTRY/sandns:$IMAGE_TAG" \
        -f "$ROOT/deploy/k8s/images/sandns.Dockerfile" "$OUTPUT"
fi

echo ""
echo "Images built:"
# Intentional multi-arg expansion (one image name per word) — SC2046.
# shellcheck disable=SC2046
docker images --format 'table {{.Repository}}\t{{.Tag}}\t{{.Size}}' \
    $(for img in "${NEEDED_IMAGES[@]}"; do echo "$REGISTRY/$img"; done) 2>/dev/null || true

# Import into k3s container runtime (no registry needed)
if [[ "$NO_IMPORT" == "false" ]]; then
    if command -v k3s &>/dev/null; then
        # An INSTALLED k3s may still be stopped (a prior cleanup stops the
        # service but leaves the binary in place). Importing against a
        # stopped containerd dies on an opaque socket error, so bring the
        # service up first — the same recovery the k8s deployers apply.
        if ! systemctl is-active --quiet k3s 2>/dev/null; then
            echo "k3s installed but stopped — starting k3s.service..."
            systemctl start k3s 2>/dev/null || true
        fi
        echo "Waiting for the k3s API..."
        k3s_ready=0
        for _ in $(seq 1 30); do
            if k3s kubectl get --raw /readyz >/dev/null 2>&1; then
                k3s_ready=1
                break
            fi
            sleep 2
        done
        if [[ "$k3s_ready" != "1" ]]; then
            echo "ERROR: k3s did not become ready — cannot import images." >&2
            echo "       Start k3s manually or rerun with --no-import." >&2
            exit 1
        fi
        echo ""
        echo "Importing images into k3s..."
        for img in "${NEEDED_IMAGES[@]}"; do
            docker save "$REGISTRY/$img:$IMAGE_TAG" | k3s ctr -n k8s.io images import -
        done
        echo "Images imported to k3s"
    else
        echo "k3s not found — skipping import (use --no-import to suppress this message)"
    fi
fi

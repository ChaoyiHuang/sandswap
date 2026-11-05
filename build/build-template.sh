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
# build-template.sh — Build and push a Sandswap template to OCI registry
# Templates are OCI artifacts with artifactType: application/vnd.sandswap.template.v1+json
# Usage:
#   ./build-template.sh <template-dir> <tag> [registry]
# Example:
#   ./build-template.sh ./templates/mysql mysql:v1 registry.example.com/sandswap-templates
# Template directory structure:
#   template-dir/
#   ├── template.json        # Template metadata
#   ├── layer-0/             # Base layer (busybox)
#   ├── layer-1/             # Runtime layer (mysql, python, etc.)
#   └── layer-2/             # Config layer (optional)

set -euo pipefail

# Parse args
if [ $# -lt 2 ]; then
    echo "Usage: $0 <template-dir> <tag> [registry]"
    echo ""
    echo "Example:"
    echo "  $0 ./templates/mysql mysql:v1 localhost:5000/sandswap-templates"
    echo ""
    echo "Template directory must contain:"
    echo "  template.json  - Template metadata (name, version, description)"
    echo "  layer-N/       - Layer directories (layer-0, layer-1, ...)"
    exit 1
fi

TEMPLATE_DIR="$1"
TAG="$2"
REGISTRY="${3:-docker.io}"

# Check ORAS is installed
if ! command -v oras &> /dev/null; then
    echo "ERROR: ORAS CLI not found."
    echo "Install: https://oras.land/docs/installation/"
    exit 1
fi

# Check template directory exists
if [ ! -d "$TEMPLATE_DIR" ]; then
    echo "ERROR: Template directory not found: $TEMPLATE_DIR"
    exit 1
fi

# Check template.json exists
TEMPLATE_JSON="$TEMPLATE_DIR/template.json"
if [ ! -f "$TEMPLATE_JSON" ]; then
    echo "ERROR: template.json not found in $TEMPLATE_DIR"
    echo ""
    echo "Example template.json:"
    cat <<'EOF'
{
    "name": "mysql",
    "version": "1.0.0",
    "description": "MySQL 8.0 serverless template",
    "workspace_path": "/workspace",
    "default_timeout": 60,
    "is_serverless": true,
    "idle_timeout": 30
}
EOF
    exit 1
fi

echo "=== Building Sandswap Template ==="
echo "Directory: $TEMPLATE_DIR"
echo "Tag:       $TAG"
echo "Registry:  $REGISTRY"
echo ""

# Read template metadata
TEMPLATE_NAME=$(jq -r '.name' "$TEMPLATE_JSON")
TEMPLATE_VERSION=$(jq -r '.version' "$TEMPLATE_JSON")
TEMPLATE_DESC=$(jq -r '.description' "$TEMPLATE_JSON")
WORKSPACE=$(jq -r '.workspace_path // "/workspace"' "$TEMPLATE_JSON")
DEFAULT_TIMEOUT=$(jq -r '.default_timeout // 30' "$TEMPLATE_JSON")
IS_SERVERLESS=$(jq -r '.is_serverless // false' "$TEMPLATE_JSON")
IDLE_TIMEOUT=$(jq -r '.idle_timeout // 30' "$TEMPLATE_JSON")

echo "Template: $TEMPLATE_NAME v$TEMPLATE_VERSION"
echo "Description: $TEMPLATE_DESC"
echo "Serverless: $IS_SERVERLESS"
echo ""

# Create temp directory for layers
BUILD_DIR=$(mktemp -d)
trap 'rm -rf "$BUILD_DIR"' EXIT

# Find all layer directories
LAYERS=()
for layer_dir in "$TEMPLATE_DIR"/layer-*; do
    [ -d "$layer_dir" ] || continue
    LAYERS+=("$layer_dir")
done

if [ ${#LAYERS[@]} -eq 0 ]; then
    echo "ERROR: No layer directories found (expected layer-0/, layer-1/, ...)"
    exit 1
fi

echo "Found ${#LAYERS[@]} layers"

# Build oras push command
ORAS_ARGS=()
ORAS_ARGS+=("push")
ORAS_ARGS+=("${REGISTRY}/${TAG}")
ORAS_ARGS+=("--artifact-type" "application/vnd.sandswap.template.v1+json")

# Process each layer
for i in "${!LAYERS[@]}"; do
    layer_dir="${LAYERS[$i]}"
    layer_name=$(basename "$layer_dir")
    layer_num=$(echo "$layer_name" | sed 's/layer-//')

    echo "Packing $layer_name..."

    # Create tar.gz
    layer_tar="$BUILD_DIR/layer-${layer_num}.tar.gz"
    tar -C "$layer_dir" -czf "$layer_tar" .

    # Calculate digest
    digest=$(sha256sum "$layer_tar" | cut -d' ' -f1)
    size=$(stat -c%s "$layer_tar")

    echo "  Digest: sha256:$digest"
    echo "  Size:   $(numfmt --to=iec $size)"

    # Add to oras args
    ORAS_ARGS+=("$layer_tar:application/vnd.oci.image.layer.v1.tar+gzip")

    # Add layer annotation
    layer_type="runtime"
    case "$layer_num" in
        0) layer_type="base" ;;
        1) layer_type="runtime" ;;
        2) layer_type="config" ;;
    esac
    ORAS_ARGS+=("--annotation" "sandswap.layer.$layer_num.type=$layer_type")
done

# Add template annotations
ORAS_ARGS+=("--annotation" "sandswap.template.name=$TEMPLATE_NAME")
ORAS_ARGS+=("--annotation" "sandswap.template.version=$TEMPLATE_VERSION")
ORAS_ARGS+=("--annotation" "sandswap.template.description=$TEMPLATE_DESC")
ORAS_ARGS+=("--annotation" "sandswap.template.workspace=$WORKSPACE")
ORAS_ARGS+=("--annotation" "sandswap.template.default_timeout=$DEFAULT_TIMEOUT")
ORAS_ARGS+=("--annotation" "sandswap.template.is_serverless=$IS_SERVERLESS")
ORAS_ARGS+=("--annotation" "sandswap.template.idle_timeout=$IDLE_TIMEOUT")

# Push to registry
echo ""
echo "=== Pushing to registry ==="
echo "oras ${ORAS_ARGS[*]}"

oras "${ORAS_ARGS[@]}"

echo ""
echo "=== Template pushed successfully ==="
echo "Pull with: oras pull ${REGISTRY}/${TAG}"
echo "Use in Sandswap: POST /human/sandfs {\"template\": \"${TAG}\"}"

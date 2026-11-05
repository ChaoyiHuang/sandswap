#!/usr/bin/env bash
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
# Regenerate the Go protobuf bindings for the gateway<->sandlot stream protocol.
# The stream protocol is defined once in common/proto/stream/stream.proto and
# shared by both gateway and sandlot via the common Go module. This script
# regenerates the pb.go files from that single source of truth.
# Usage:
#   bash build/gen-proto.sh            # regenerate common proto
# Prereqs: protoc + protoc-gen-go + protoc-gen-go-grpc on PATH (or in
# $(go env GOPATH)/bin, which this script adds automatically). The generator
# version must match google.golang.org/protobuf in common/go.mod (currently
# v1.36.11); a mismatch produces "plugin failed" or stale-style output.

set -euo pipefail

cd "$(dirname "$0")/.."

# protoc-gen-go / protoc-gen-go-grpc live in GOPATH/bin, which is usually not
# on PATH. Add it so protoc can find them without requiring the user to export.
GOPATH_BIN="$(go env GOPATH)/bin"
export PATH="$PATH:$GOPATH_BIN"

PROTO="common/proto/stream/stream.proto"

command -v protoc         >/dev/null || { echo "ERROR: protoc not found (apt install protobuf-compiler)" >&2; exit 1; }
command -v protoc-gen-go  >/dev/null || { echo "ERROR: protoc-gen-go not found (go install google.golang.org/protobuf/cmd/protoc-gen-go@latest)" >&2; exit 1; }
command -v protoc-gen-go-grpc >/dev/null || { echo "ERROR: protoc-gen-go-grpc not found (go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest)" >&2; exit 1; }

echo "[gen] $PROTO"
cd common
protoc \
    --go_out=. --go_opt=paths=source_relative \
    --go-grpc_out=. --go-grpc_opt=paths=source_relative \
    proto/stream/stream.proto

echo "[gen] done. Build to confirm: bash build/build.sh go"

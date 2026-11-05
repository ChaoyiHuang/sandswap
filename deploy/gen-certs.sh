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
# Generate a self-signed CA + gateway server cert + sandlot client cert for the
# gateway<->sandlot mTLS gRPC stream.
# Usage: bash deploy/gen-certs.sh [output_dir]
# Output (default output/certs):
#   ca.crt / ca.key              — internal CA (both sides trust it)
#   gateway.crt / gateway.key    — gateway server cert (SAN: localhost, 127.0.0.1)
#   sandlot.crt / sandlot.key    — sandlot client cert, CN=$SANDLOT_CN
#
# The client certificate's CN IS the node identity: the gateway binds a
# connection's declared node_id to its certificate CN (exact match), so one
# certificate per node is required — a shared certificate would let any host
# holding it claim another node's id. SANDLOT_CN must therefore be the node id
# this certificate is issued FOR (the host's `-node-id`, default: its
# hostname). bash deploy/gen-certs.sh --client-cn <node-id> [output_dir] mints
# an ADDITIONAL client pair (sandlot-<node-id>.crt/.key) from the same CA for
# multi-node dev setups.
# These are dev/test certs. For production, issue the sandlot client cert per
# node from your real CA and distribute via your secret manager.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# --client-cn <node-id> mints one extra client pair for that node id, leaving
# the standard trio untouched (dev fleets: one cert per sandlot node).
EXTRA_CN=""
if [[ "${1:-}" == "--client-cn" ]]; then
  EXTRA_CN="${2:?--client-cn requires a node id}"
  shift 2
  EXTRA_ROLES="exec"
  if [[ "$EXTRA_CN" == *:* ]]; then
    EXTRA_ROLES="${EXTRA_CN#*:}"
    EXTRA_CN="${EXTRA_CN%%:*}"
  fi
fi
OUT_DIR="${1:-$ROOT/output/certs}"
mkdir -p "$OUT_DIR"
cd "$OUT_DIR"

DAYS=3650

# role_san <roles-csv> — URI SAN entries that grant stream roles
# (sandswap://role/exec|prov). The gateway accepts a declared role only when
# the verified client certificate carries the matching URI.
role_san() {
  local out="" r
  for r in $(printf '%s' "$1" | tr ',' ' '); do
    [[ -z "$r" ]] && continue
    out+="${out:+,}URI:sandswap://role/${r}"
  done
  printf '%s' "$out"
}

# `--client-cn` mints ONE extra pair and touches nothing else: the shared
# trio (CA, gateway, default client) must stay byte-identical across calls —
# re-minting them on every extra-node request would rewrite files a
# concurrently starting sandlot is loading (torn cert/key read).
if [[ -n "$EXTRA_CN" ]]; then
  [[ -f ca.crt && -f ca.key ]] || {
    echo "[gen-certs] --client-cn needs the CA in $OUT_DIR (run without --client-cn first)" >&2
    exit 1
  }
  cat > sandlot.ext <<EOF
extendedKeyUsage = clientAuth
subjectAltName = $(role_san "$EXTRA_ROLES")
EOF
  openssl genrsa -out "sandlot-${EXTRA_CN}.key" 2048 2>/dev/null
  openssl req -new -key "sandlot-${EXTRA_CN}.key" -subj "/CN=${EXTRA_CN}" \
    -out "sandlot-${EXTRA_CN}.csr" 2>/dev/null
  openssl x509 -req -in "sandlot-${EXTRA_CN}.csr" -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out "sandlot-${EXTRA_CN}.crt" -days "$DAYS" -sha256 -extfile sandlot.ext 2>/dev/null
  rm -f "sandlot-${EXTRA_CN}.csr" sandlot.ext
  chmod 600 "sandlot-${EXTRA_CN}.key"
  echo "[gen-certs] client cert for node id ${EXTRA_CN}: sandlot-${EXTRA_CN}.crt/.key"
  exit 0
fi

# ── CA ──────────────────────────────────────────────────────────────────
if [[ ! -f ca.key ]]; then
  openssl genrsa -out ca.key 4096 2>/dev/null
fi
openssl req -x509 -new -nodes -key ca.key -sha256 -days "$DAYS" \
  -subj "/CN=sandswap-ca" -out ca.crt 2>/dev/null

# ── Gateway server cert (SAN must match the host sandlot dials: localhost) ─
cat > gateway.ext <<'EOF'
subjectAltName = DNS:localhost, IP:127.0.0.1
extendedKeyUsage = serverAuth
EOF
openssl genrsa -out gateway.key 2048 2>/dev/null
openssl req -new -key gateway.key -subj "/CN=gateway" -out gateway.csr 2>/dev/null
openssl x509 -req -in gateway.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out gateway.crt -days "$DAYS" -sha256 -extfile gateway.ext 2>/dev/null

# ── Sandlot client cert (clientAuth) ─────────────────────────────────────
cat > sandlot.ext <<EOF
extendedKeyUsage = clientAuth
subjectAltName = $(role_san "${SANDLOT_ROLES:-exec}")
EOF
openssl genrsa -out sandlot.key 2048 2>/dev/null
openssl req -new -key sandlot.key -subj "/CN=${SANDLOT_CN:-sandlot}" -out sandlot.csr 2>/dev/null
openssl x509 -req -in sandlot.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out sandlot.crt -days "$DAYS" -sha256 -extfile sandlot.ext 2>/dev/null


# Clean up intermediates.
rm -f gateway.csr sandlot.csr gateway.ext sandlot.ext ca.srl

chmod 600 ca.key gateway.key sandlot.key
echo "[gen-certs] wrote CA + gateway + sandlot certs to $OUT_DIR:"
find "$OUT_DIR" -maxdepth 1 -type f \( -name '*.crt' -o -name '*.key' \) -printf '%f\n' | sort

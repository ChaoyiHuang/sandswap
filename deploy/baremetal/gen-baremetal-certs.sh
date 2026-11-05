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
# gen-baremetal-certs.sh — Generate TLS certificates for Sandswap bare-metal deployment.
# Generates self-signed certificates for:
#   1. etcd server + client (TLS + mTLS)
#   2. Gateway gRPC stream server (mTLS with sandlot client)
#   3. Gateway MCP HTTP server (TLS)
#   4. Gateway human HTTP server (TLS for /human/* endpoints)
#   5. Sandlot gRPC stream client cert — ONE PER NODE (see the CN rule)
# Output: Individual cert files written to the specified directory.
# Unlike gen-k8s-certs.sh, this outputs flat files (no K8s Secret YAML).
#
# THE CN RULE — the stream client certificate's CN IS the node identity.
# The gateway binds a stream connection's declared node_id to the CN of the
# client certificate it presents, by EXACT match (gateway/stream/server.go
# verifyNodeIdentity): a shared certificate is refused by name. The CN of
# sandlot.crt is therefore SANDLOT_NODE_ID (default: this host's `hostname`,
# which is what `-node-id` itself defaults to) — and it must be the node's
# EFFECTIVE node id, i.e. the configured `-node-id` / `node_id:` value with
# `-<instance.id>` appended when the sandlot config sets an `instance.id`
# (sandlot/cmd/main.go composes it before the hello). Every additional node
# id that needs a certificate on this host gets its own pair via
# `--client-cn <node-id>` → sandlot-<node-id>.crt/.key.
#
# Usage:
#   bash deploy/baremetal/gen-baremetal-certs.sh
#   bash deploy/baremetal/gen-baremetal-certs.sh /path/to/certs
#   bash deploy/baremetal/gen-baremetal-certs.sh /path/to/certs \
#       --sans-dns sandswap.local,sandswap-stream.local \
#       --sans-ip 10.0.1.1,10.0.1.2
# --sans-dns: Additional DNS names for stream.crt and mcp.crt SANs (multi-GW production)
# --sans-ip:  Additional IP addresses for stream.crt, mcp.crt, and human.crt SANs
# --client-cn <node-id>[:<roles>]: mint an extra client pair
#   sandlot-<node-id>.crt/.key from the same CA (repeatable; one host running
#   several sandlot instances — exec + prov, or a simulation's N instances —
#   needs one pair per node id). <roles> is a comma list of role markers
#   (default: exec); the gateway accepts a declared role only when the client
#   certificate carries the matching URI SAN sandswap://role/<role>.
# --client-roles <roles>: role markers for the PRIMARY client pair
#   (default: exec).
# Environment: SANDLOT_NODE_ID=<node-id> names the node the PRIMARY pair
#   (sandlot.crt/.key) is issued for (default: `hostname`).
# These are dev/test certificates. For production, use a real CA + cert manager.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DAYS="${CERT_DAYS:-365}"

# Parse arguments: an optional positional cert dir + optional flags (in any
# order). The CN of the PRIMARY client pair is the node id this host's sandlot
# will declare — see THE CN RULE in the header.
CERT_DIR=""
EXTRA_SANS_DNS=""
EXTRA_SANS_IP=""
CLIENT_CN_EXTRA=()
CLIENT_ROLES="exec"
KEEP_CA_DIR=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --sans-dns)  EXTRA_SANS_DNS="${2:?--sans-dns requires a value}"; shift 2 ;;
        --sans-ip)   EXTRA_SANS_IP="${2:?--sans-ip requires a value}"; shift 2 ;;
        --client-cn) CLIENT_CN_EXTRA+=("${2:?--client-cn requires a node id}"); shift 2 ;;
        --client-roles) CLIENT_ROLES="${2:?--client-roles requires a role list}"; shift 2 ;;
        --keep-ca)   KEEP_CA_DIR="${2:?--keep-ca requires a directory}"; shift 2 ;;
        -*)          echo "Unknown argument: $1" >&2; exit 1 ;;
        *)           CERT_DIR="$1"; shift ;;
    esac
done
CERT_DIR="${CERT_DIR:-$ROOT/output/baremetal-certs}"
# Effective node id of the node this pair is minted FOR. `hostname` matches
# the sandlot's own `-node-id` default, so a deployer that leaves `node_id`
# empty (the sandlot resolves it at startup) needs no further coordination.
# A deployer whose node id is something else (an explicit config value, or a
# node_id + instance.id composition) must pass it here.
SANDLOT_NODE_ID="${SANDLOT_NODE_ID:-$(hostname)}"

# role_uri_sans <roles-csv> — the URI SAN entries that grant stream roles. The
# carrier is an extension (RFC 5280), not a DN field: machine-role grants
# belong there, and every CA (openssl, Vault uri_sans, cert-manager uris)
# supports it.
role_uri_sans() {
    local out="" r
    for r in $(printf '%s' "$1" | tr ',' ' '); do
        [[ -z "$r" ]] && continue
        out+="${out:+,}URI:sandswap://role/${r}"
    done
    printf '%s' "$out"
}
CLIENT_ROLE_SAN="$(role_uri_sans "$CLIENT_ROLES")"
[[ -n "$CLIENT_ROLE_SAN" ]] || { echo "client role list is empty — every stream certificate needs at least one role URI" >&2; exit 1; }

# Build SAN strings for server certs
# Base SANs: localhost + 127.0.0.1
STREAM_SAN_DNS="DNS:localhost"
STREAM_SAN_IP="IP:127.0.0.1"
HUMAN_SAN_DNS="DNS:localhost"
HUMAN_SAN_IP="IP:127.0.0.1"

# Add extra DNS SANs (--sans-dns applies to stream + mcp)
if [[ -n "$EXTRA_SANS_DNS" ]]; then
    IFS=',' read -ra dns_entries <<< "$EXTRA_SANS_DNS"
    for dns in "${dns_entries[@]}"; do
        STREAM_SAN_DNS+=",DNS:${dns}"
        # Only add sandswap.local to mcp SAN, sandswap-stream.local to stream SAN
        # Actually, both should have both for simplicity (GW serves both)
        HUMAN_SAN_DNS+=",DNS:${dns}"
    done
fi

# Add extra IP SANs (--sans-ip applies to stream + mcp + human)
if [[ -n "$EXTRA_SANS_IP" ]]; then
    IFS=',' read -ra ip_entries <<< "$EXTRA_SANS_IP"
    for ip in "${ip_entries[@]}"; do
        STREAM_SAN_IP+=",IP:${ip}"
        HUMAN_SAN_IP+=",IP:${ip}"
    done
fi

STREAM_SAN="${STREAM_SAN_DNS},${STREAM_SAN_IP}"
MCP_SAN="${STREAM_SAN}"  # same SANs as stream
HUMAN_SAN="${HUMAN_SAN_DNS},${HUMAN_SAN_IP}"

# Clean and create cert dir
rm -rf "$CERT_DIR"
mkdir -p "$CERT_DIR"

echo "Generating Sandswap bare-metal TLS certificates (validity: $DAYS days)..."
echo "  Output: $CERT_DIR/"
if [[ -n "$EXTRA_SANS_DNS" ]]; then echo "  Extra DNS SANs: $EXTRA_SANS_DNS"; fi
if [[ -n "$EXTRA_SANS_IP" ]]; then echo "  Extra IP SANs: $EXTRA_SANS_IP"; fi

# ── CA ─────────────────────────────────────────────────────────────
echo "  [1/7] CA..."
openssl req -new -x509 -days "$DAYS" -nodes \
    -newkey rsa:2048 \
    -keyout "$CERT_DIR/ca.key" \
    -out "$CERT_DIR/ca.crt" \
    -subj "/O=Sandswap/CN=Sandswap Internal CA" \
    2>/dev/null

# ── etcd server cert ───────────────────────────────────────────────
echo "  [2/7] etcd server cert..."
# The etcd server must also present the real endpoint names: a multi-host
# deploy dials https://etcd1.example.com:2379 and Go x509 verification fails
# against a localhost-only cert. Extra SANs are appended (localhost/127.0.0.1
# kept so a single-node etcd keeps verifying).
ETCD_EXTRA_SAN=""
if [[ -n "$EXTRA_SANS_DNS" ]]; then
    IFS=',' read -ra etcd_dns <<< "$EXTRA_SANS_DNS"
    for dns in "${etcd_dns[@]}"; do
        [[ -n "$dns" ]] && ETCD_EXTRA_SAN+=",DNS:${dns}"
    done
fi
if [[ -n "$EXTRA_SANS_IP" ]]; then
    IFS=',' read -ra etcd_ips <<< "$EXTRA_SANS_IP"
    for ip in "${etcd_ips[@]}"; do
        [[ -n "$ip" ]] && ETCD_EXTRA_SAN+=",IP:${ip}"
    done
fi
openssl req -new -nodes \
    -newkey rsa:2048 \
    -keyout "$CERT_DIR/etcd-server.key" \
    -out "$CERT_DIR/etcd-server.csr" \
    -subj "/O=Sandswap/CN=etcd-server" \
    2>/dev/null

openssl x509 -req -days "$DAYS" \
    -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" -CAcreateserial \
    -in "$CERT_DIR/etcd-server.csr" \
    -out "$CERT_DIR/etcd-server.crt" \
    -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1${ETCD_EXTRA_SAN}\nextendedKeyUsage=serverAuth") \
    2>/dev/null

# ── etcd client cert (for gateway/sandlot/sandns to connect to etcd) ─────
echo "  [3/7] etcd client cert..."
openssl req -new -nodes \
    -newkey rsa:2048 \
    -keyout "$CERT_DIR/etcd-client.key" \
    -out "$CERT_DIR/etcd-client.csr" \
    -subj "/O=Sandswap/CN=etcd-client" \
    2>/dev/null

openssl x509 -req -days "$DAYS" \
    -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" -CAcreateserial \
    -in "$CERT_DIR/etcd-client.csr" \
    -out "$CERT_DIR/etcd-client.crt" \
    -extfile <(printf "extendedKeyUsage=clientAuth") \
    2>/dev/null

# ── Gateway stream server cert (gRPC mTLS) ────────────────────────
echo "  [4/7] gateway stream server cert..."
openssl req -new -nodes \
    -newkey rsa:2048 \
    -keyout "$CERT_DIR/stream.key" \
    -out "$CERT_DIR/stream.csr" \
    -subj "/O=Sandswap/CN=gateway-stream" \
    2>/dev/null

openssl x509 -req -days "$DAYS" \
    -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" -CAcreateserial \
    -in "$CERT_DIR/stream.csr" \
    -out "$CERT_DIR/stream.crt" \
    -extfile <(printf "subjectAltName=${STREAM_SAN}\nextendedKeyUsage=serverAuth") \
    2>/dev/null

# ── Gateway MCP server cert (HTTP TLS) ────────────────────────────
echo "  [5/7] gateway MCP server cert..."
openssl req -new -nodes \
    -newkey rsa:2048 \
    -keyout "$CERT_DIR/mcp.key" \
    -out "$CERT_DIR/mcp.csr" \
    -subj "/O=Sandswap/CN=gateway-mcp" \
    2>/dev/null

openssl x509 -req -days "$DAYS" \
    -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" -CAcreateserial \
    -in "$CERT_DIR/mcp.csr" \
    -out "$CERT_DIR/mcp.crt" \
    -extfile <(printf "subjectAltName=${MCP_SAN}\nextendedKeyUsage=serverAuth") \
    2>/dev/null

# ── Gateway human server cert (HTTP TLS for /human/* endpoints) ───
echo "  [6/7] gateway human server cert..."
openssl req -new -nodes \
    -newkey rsa:2048 \
    -keyout "$CERT_DIR/human.key" \
    -out "$CERT_DIR/human.csr" \
    -subj "/O=Sandswap/CN=gateway-human" \
    2>/dev/null

openssl x509 -req -days "$DAYS" \
    -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" -CAcreateserial \
    -in "$CERT_DIR/human.csr" \
    -out "$CERT_DIR/human.crt" \
    -extfile <(printf "subjectAltName=${HUMAN_SAN}\nextendedKeyUsage=serverAuth") \
    2>/dev/null

# Also create admin.crt/key as symlink alias for backward compatibility
ln -sf human.crt "$CERT_DIR/admin.crt"
ln -sf human.key "$CERT_DIR/admin.key"

# ── Sandlot client cert (mTLS for gRPC stream) ────────────────────
# CN = the node id (see THE CN RULE in the header). The gateway refuses a
# client certificate whose CN does not equal the node id the instance
# declares, so this is the one thing about this pair that MUST be right.
echo "  [7/7] sandlot client cert (CN=${SANDLOT_NODE_ID})..."
openssl req -new -nodes \
    -newkey rsa:2048 \
    -keyout "$CERT_DIR/sandlot.key" \
    -out "$CERT_DIR/sandlot.csr" \
    -subj "/O=Sandswap/CN=${SANDLOT_NODE_ID}" \
    2>/dev/null

openssl x509 -req -days "$DAYS" \
    -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" -CAcreateserial \
    -in "$CERT_DIR/sandlot.csr" \
    -out "$CERT_DIR/sandlot.crt" \
    -extfile <(printf "extendedKeyUsage=clientAuth\nsubjectAltName=%s" "$CLIENT_ROLE_SAN") \
    2>/dev/null

# ── Extra per-node client certs (--client-cn, repeatable) ─────────
# One pair per ADDITIONAL node id served from this host (an exec + prov pair,
# a simulation hosting N instances). Same CA, same clientAuth EKU; only the
# CN differs — the CN is what the gateway binds.
for spec in ${CLIENT_CN_EXTRA[@]+"${CLIENT_CN_EXTRA[@]}"}; do
    cn="${spec%%:*}"
    roles="${CLIENT_ROLES}"
    [[ "$spec" == *:* ]] && roles="${spec#*:}"
    san="$(role_uri_sans "$roles")"
    [[ -n "$cn" && -n "$san" ]] || { echo "--client-cn value ${spec:?} must be <node-id>[:<roles>] with a non-empty role list" >&2; exit 1; }
    echo "  [7/7] extra sandlot client cert (CN=${cn}, roles=${roles})..."
    openssl req -new -nodes \
        -newkey rsa:2048 \
        -keyout "$CERT_DIR/sandlot-${cn}.key" \
        -out "$CERT_DIR/sandlot-${cn}.csr" \
        -subj "/O=Sandswap/CN=${cn}" \
        2>/dev/null

    openssl x509 -req -days "$DAYS" \
        -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" -CAcreateserial \
        -in "$CERT_DIR/sandlot-${cn}.csr" \
        -out "$CERT_DIR/sandlot-${cn}.crt" \
        -extfile <(printf "extendedKeyUsage=clientAuth\nsubjectAltName=%s" "$san") \
        2>/dev/null
done

# ── Clean up CSRs ─────────────────────────────────────────────────
rm -f "$CERT_DIR"/*.csr "$CERT_DIR"/ca.srl

# ── CA private key: never left in the node's certificate directory ──
# Only ca.crt belongs on a node. A retained CA key lets anyone who reads it
# (the gateway identity runs with service permissions, not root) mint a client
# certificate for ANY node id — fleet-wide control-plane impersonation. The
# default is therefore to delete it after the last signature; operators who
# must re-issue later move it to a root-only directory with --keep-ca.
if [[ -n "$KEEP_CA_DIR" ]]; then
    mkdir -p "$KEEP_CA_DIR"
    install -m 0600 "$CERT_DIR/ca.key" "$KEEP_CA_DIR/ca.key"
    echo "  CA private key moved to ${KEEP_CA_DIR}/ca.key (root-only)"
fi
rm -f "$CERT_DIR/ca.key"

# ── Set permissions ───────────────────────────────────────────────
chmod 600 "$CERT_DIR"/*.key
chmod 644 "$CERT_DIR"/*.crt

echo ""
echo "  Certificates generated in $CERT_DIR/"
ls -la "$CERT_DIR/"
echo ""
echo "  Files:"
echo "    ca.crt                       — CA certificate (the private key is removed)"
echo "    etcd-server.crt, .key        — etcd server (TLS)"
echo "    etcd-client.crt, .key        — etcd client (mTLS)"
echo "    stream.crt, .key             — gateway gRPC stream server (mTLS)"
echo "    mcp.crt, .key                — gateway MCP/agent HTTP server (TLS)"
echo "    human.crt, .key              — gateway human HTTP server (TLS)"
echo "    admin.crt, .key              — symlink → human.* (backward compat)"
echo "    sandlot.crt, .key            — sandlot gRPC stream client (mTLS), CN=${SANDLOT_NODE_ID}"
for cn in ${CLIENT_CN_EXTRA[@]+"${CLIENT_CN_EXTRA[@]}"}; do
    echo "    sandlot-${cn}.crt, .key  — sandlot stream client, CN=${cn}"
done

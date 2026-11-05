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
# gen-k8s-certs.sh — Generate TLS certificates for Sandswap K8s deployment.
# Generates self-signed certificates for:
#   1. etcd server + client (TLS + optional mTLS)
#   2. Gateway gRPC stream server (mTLS with sandlot client)
#   3. Gateway MCP HTTP server (TLS)
#   4. Gateway human HTTP server (TLS for /human/* endpoints)
#   5. Sandlot gRPC stream client — ONE PAIR PER CLUSTER NODE (THE CN RULE)
# Output: K8s Secret YAML written to stdout, ready for kubectl apply.
# Also writes individual cert files to output/k8s-certs/ for reference.
#
# THE CN RULE — the stream client certificate's CN IS the node identity.
# The gateway binds a stream connection's declared node_id to the CN of the
# client certificate it presents, by EXACT match (gateway/stream/server.go
# verifyNodeIdentity); a shared deployment-wide certificate is refused by
# name. Every sandlot pod therefore declares node_id = its Kubernetes NODE
# name (the manifests pass it from `fieldRef: spec.nodeName` — one sandlot per
# node), and gets its own Secret `sandlot-certs-<node>` carrying a pair with
# CN=<node>. The provision Deployment runs a singleton identity of its own
# (`sandlot-prov`) and gets `sandlot-certs-prov`. Node list:
#   SANDSWAP_K8S_NODES="node1 node2"   (space/comma separated), else
#   `kubectl get nodes -o name` (k3s kubectl fallback) when available.
#
# Usage:
#   SANDSWAP_K8S_NODES="n1 n2" bash deploy/k8s/gen-k8s-certs.sh  # generate + print YAML
#   bash deploy/k8s/gen-k8s-certs.sh | kubectl apply -f -  # node list from the cluster
# These are dev/test certificates. For production, use a real CA + cert manager
# (e.g., cert-manager, Vault PKI) and issue one client certificate per node.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CERT_DIR="$ROOT/output/k8s-certs"
DAYS="${CERT_DAYS:-365}"

# Node identities to mint stream client pairs for. Explicit list wins (deploys
# on a host whose kubectl context is not the target cluster); otherwise ask the
# cluster. With neither, fall back to THIS host's name and say so loudly: a
# standalone mint (the script-matrix row, a first PKI on the eventual cluster
# host) still needs a valid pair, and the single-node cluster is exactly this
# host — a multi-node cluster must name its nodes (the deploy lib always
# resolves the live list before calling here, so this fallback is never the
# deploy path).
NODES_RAW="${SANDSWAP_K8S_NODES:-}"
if [[ -z "$NODES_RAW" ]]; then
    if command -v kubectl >/dev/null 2>&1; then
        KUBECTL="kubectl"
    elif command -v k3s >/dev/null 2>&1; then
        KUBECTL="k3s kubectl"
    else
        KUBECTL=""
    fi
    if [[ -n "$KUBECTL" ]]; then
        NODES_RAW="$($KUBECTL get nodes -o name 2>/dev/null | sed 's|^node/||' | tr '\n' ' ')" || NODES_RAW=""
    fi
    if [[ -z "${NODES_RAW// /}" ]]; then
        echo "WARNING: no node list — set SANDSWAP_K8S_NODES=\"<node1> <node2>\", or run where" >&2
        echo "         kubectl/k3s can list the cluster's nodes. Minting client pairs for THIS" >&2
        echo "         host's name only." >&2
        NODES_RAW="$(hostname | tr 'A-Z' 'a-z')"
    fi
fi
# Normalise: commas/spaces/newlines → one entry per array element.
read -ra K8S_NODES <<< "$(printf '%s' "$NODES_RAW" | tr ',\n' '  ')"
if [[ "${#K8S_NODES[@]}" -eq 0 ]]; then
    echo "error: SANDSWAP_K8S_NODES parsed to an empty node list" >&2
    exit 1
fi
# The node name becomes part of a Secret name and a file name — refuse names
# that cannot round-trip (a bad name would produce a Secret the host-side
# fetch can never find). RFC 1123 subdomain, lowercased the way k8s does.
for n in "${K8S_NODES[@]}"; do
    if [[ ! "$n" =~ ^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$ ]]; then
        echo "error: node name '$n' is not a valid DNS subdomain — cannot name sandlot-certs-$n" >&2
        exit 1
    fi
done
# The provision Deployment's singleton node identity (see deploy/k8s/sandlot-prov.yaml).
PROV_NODE_ID="sandlot-prov"

# K8s service names
ETCD_HOST="etcd-0.etcd.sandswap.svc.cluster.local"
# Headless gateway service (both agent :3000 and stream :9998 live here now).
GW_STREAM_HOST="gateway-exec.sandswap.svc.cluster.local"
# Per-pod FQDN wildcard: covers gateway-0..N-1.gateway-exec... (sandlot
# reconnect dials the pod FQDN; the stream server must present a SAN for it).
GW_POD_WILDCARD="*.gateway-exec.sandswap.svc.cluster.local"
GW_MCP_HOST="gateway-exec.sandswap.svc.cluster.local"
GW_HUMAN_HOST="gateway-human.sandswap.svc.cluster.local"
# Owner-aware sandfs zone: every per-sandfs URL
# <sandfs_id>.sandfs.sandswap.local is served by whichever gateway pod receives
# it, so every gateway's MCP cert must cover the wildcard.
SANDFS_WILDCARD="*.sandfs.sandswap.local"

# Clean and create cert dir
rm -rf "$CERT_DIR"
mkdir -p "$CERT_DIR"

echo "Generating Sandswap K8s TLS certificates (validity: $DAYS days)..." >&2
echo "  Output: $CERT_DIR/" >&2

# ── CAs ────────────────────────────────────────────────────────────
# TWO independent CAs:
#   ca.crt       the STREAM CA — signs the gateway listeners and the per-node
#                stream client pairs. A node certificate is a bearer of the
#                node identity toward the gateway, nothing else.
#   ca-etcd.crt  the ETCD CA — signs ONLY etcd server/client material. etcd
#                listens with --client-cert-auth on the node network; if it
#                trusted the stream CA, any compromised sandlot pod holding its
#                own node certificate could read/write the whole /sandswap/**
#                control plane (hostNetwork bypasses NetworkPolicy).
echo "  Generating stream CA..." >&2
openssl req -new -x509 -days "$DAYS" -nodes \
    -newkey rsa:2048 \
    -keyout "$CERT_DIR/ca.key" \
    -out "$CERT_DIR/ca.crt" \
    -subj "/O=Sandswap/CN=Sandswap Internal CA" \
    2>/dev/null

echo "  Generating etcd CA..." >&2
openssl req -new -x509 -days "$DAYS" -nodes \
    -newkey rsa:2048 \
    -keyout "$CERT_DIR/ca-etcd.key" \
    -out "$CERT_DIR/ca-etcd.crt" \
    -subj "/O=Sandswap/CN=Sandswap etcd CA" \
    2>/dev/null

# ── etcd server cert ───────────────────────────────────────────────
echo "  Generating etcd server cert..." >&2
openssl req -new -nodes \
    -newkey rsa:2048 \
    -keyout "$CERT_DIR/etcd-server.key" \
    -out "$CERT_DIR/etcd-server.csr" \
    -subj "/O=Sandswap/CN=etcd-server" \
    2>/dev/null

openssl x509 -req -days "$DAYS" \
    -CA "$CERT_DIR/ca-etcd.crt" -CAkey "$CERT_DIR/ca-etcd.key" -CAcreateserial \
    -in "$CERT_DIR/etcd-server.csr" \
    -out "$CERT_DIR/etcd-server.crt" \
    -extfile <(printf "subjectAltName=DNS:$ETCD_HOST,DNS:etcd-0,DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth") \
    2>/dev/null

# ── etcd client cert (for gateway/sandlot to connect to etcd) ─────
echo "  Generating etcd client cert..." >&2
openssl req -new -nodes \
    -newkey rsa:2048 \
    -keyout "$CERT_DIR/etcd-client.key" \
    -out "$CERT_DIR/etcd-client.csr" \
    -subj "/O=Sandswap/CN=etcd-client" \
    2>/dev/null

openssl x509 -req -days "$DAYS" \
    -CA "$CERT_DIR/ca-etcd.crt" -CAkey "$CERT_DIR/ca-etcd.key" -CAcreateserial \
    -in "$CERT_DIR/etcd-client.csr" \
    -out "$CERT_DIR/etcd-client.crt" \
    -extfile <(printf "extendedKeyUsage=clientAuth") \
    2>/dev/null

# ── Gateway stream server cert (gRPC mTLS) ────────────────────────
echo "  Generating gateway stream server cert..." >&2
openssl req -new -nodes \
    -newkey rsa:2048 \
    -keyout "$CERT_DIR/gateway-stream.key" \
    -out "$CERT_DIR/gateway-stream.csr" \
    -subj "/O=Sandswap/CN=gateway-stream" \
    2>/dev/null

# SANs cover BOTH stream consumer classes: exec-role sandlots (gateway-exec)
# and prov-role instances (gateway-human's stream port) — the Service DNS
# names plus the per-pod wildcards for each.
openssl x509 -req -days "$DAYS" \
    -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" -CAcreateserial \
    -in "$CERT_DIR/gateway-stream.csr" \
    -out "$CERT_DIR/gateway-stream.crt" \
    -extfile <(printf "subjectAltName=DNS:$GW_STREAM_HOST,DNS:$GW_POD_WILDCARD,DNS:$GW_HUMAN_HOST,DNS:*.gateway-human.sandswap.svc.cluster.local,DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth") \
    2>/dev/null

# ── Gateway MCP server cert (HTTP TLS) ────────────────────────────
echo "  Generating gateway MCP server cert..." >&2
openssl req -new -nodes \
    -newkey rsa:2048 \
    -keyout "$CERT_DIR/gateway-agent.key" \
    -out "$CERT_DIR/gateway-agent.csr" \
    -subj "/O=Sandswap/CN=gateway-agent" \
    2>/dev/null

openssl x509 -req -days "$DAYS" \
    -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" -CAcreateserial \
    -in "$CERT_DIR/gateway-agent.csr" \
    -out "$CERT_DIR/gateway-agent.crt" \
    -extfile <(printf "subjectAltName=DNS:$GW_MCP_HOST,DNS:$GW_POD_WILDCARD,DNS:$SANDFS_WILDCARD,DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth") \
    2>/dev/null

# ── Gateway admin server cert (HTTP TLS for /human/* endpoints) ───
echo "  Generating gateway admin server cert..." >&2
openssl req -new -nodes \
    -newkey rsa:2048 \
    -keyout "$CERT_DIR/gateway-human.key" \
    -out "$CERT_DIR/gateway-human.csr" \
    -subj "/O=Sandswap/CN=gateway-human" \
    2>/dev/null

openssl x509 -req -days "$DAYS" \
    -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" -CAcreateserial \
    -in "$CERT_DIR/gateway-human.csr" \
    -out "$CERT_DIR/gateway-human.crt" \
    -extfile <(printf "subjectAltName=DNS:$GW_HUMAN_HOST,DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth") \
    2>/dev/null

# ── Sandlot client certs — ONE PER NODE (mTLS for gRPC stream) ────
# CN = the node id (THE CN RULE in the header). The node's compute pod
# declares node_id = its node name; the provision Deployment declares
# `sandlot-prov`. A pair minted for the wrong identity is refused at the
# handshake, so every id gets its own file here.
mint_client_pair() { # <cert-base-name> <CN> <roles-csv>
    local base="$1" cn="$2" roles="$3" san="" r
    for r in $(printf '%s' "$roles" | tr ',' ' '); do
        [[ -z "$r" ]] && continue
        san+="${san:+,}URI:sandswap://role/${r}"
    done
    [[ -n "$san" ]] || { echo "mint_client_pair: empty role list for ${cn}" >&2; exit 1; }
    echo "  Generating sandlot client cert for CN=$cn (roles=$roles)..." >&2
    openssl req -new -nodes \
        -newkey rsa:2048 \
        -keyout "$CERT_DIR/${base}.key" \
        -out "$CERT_DIR/${base}.csr" \
        -subj "/O=Sandswap/CN=${cn}" \
        2>/dev/null
    openssl x509 -req -days "$DAYS" \
        -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" -CAcreateserial \
        -in "$CERT_DIR/${base}.csr" \
        -out "$CERT_DIR/${base}.crt" \
        -extfile <(printf "extendedKeyUsage=clientAuth\nsubjectAltName=%s" "$san") \
        2>/dev/null
}
NODE_SECRETS=()   # "<secret-name> <cert-base>" per minted pair
for n in "${K8S_NODES[@]}"; do
    mint_client_pair "sandlot-${n}" "$n" exec
    NODE_SECRETS+=("sandlot-certs-${n} sandlot-${n}")
done
mint_client_pair "sandlot-${PROV_NODE_ID}" "$PROV_NODE_ID" prov
NODE_SECRETS+=("sandlot-certs-prov sandlot-${PROV_NODE_ID}")

# Clean up CSRs and CA key (not needed after signing)
rm -f "$CERT_DIR"/*.csr "$CERT_DIR"/ca.key "$CERT_DIR"/ca-etcd.key "$CERT_DIR"/ca.srl

# The openssl calls above swallow stderr; a signing failure (bad extfile,
# disk full) must be caught HERE — an empty data value in the emitted Secret
# YAML applies fine and fails much later at pod TLS handshake, where nothing
# names the real cause. Every material the YAML references must exist and be
# non-empty before we print it.
for f in ca.crt ca-etcd.crt etcd-server.crt etcd-server.key etcd-client.crt etcd-client.key \
         gateway-stream.crt gateway-stream.key gateway-agent.crt gateway-agent.key \
         gateway-human.crt gateway-human.key; do
    if [[ ! -s "$CERT_DIR/$f" ]]; then
        echo "error: $CERT_DIR/$f missing or empty — certificate generation failed" >&2
        exit 1
    fi
done
for entry in "${NODE_SECRETS[@]}"; do
    base="${entry##* }"
    for f in "${base}.crt" "${base}.key"; do
        if [[ ! -s "$CERT_DIR/$f" ]]; then
            echo "error: $CERT_DIR/$f missing or empty — certificate generation failed" >&2
            exit 1
        fi
    done
done

# Boundary test (script-level): the two CAs must be genuinely independent.
# A node stream certificate that verifies against the etcd CA (or an etcd
# client cert that verifies against the stream CA) would reopen the
# "compromised pod = etcd client" path this split exists to close.
_etcd_ca_verifies_node() { openssl verify -CAfile "$CERT_DIR/ca-etcd.crt" "$1" >/dev/null 2>&1; }
_stream_ca_verifies_etcd() { openssl verify -CAfile "$CERT_DIR/ca.crt" "$1" >/dev/null 2>&1; }
if _etcd_ca_verifies_node "$CERT_DIR/etcd-client.crt"; then
    echo "  ✓ boundary: etcd CA verifies etcd client material" >&2
else
    echo "error: the etcd CA does not verify its own client certificate — signing is broken" >&2
    exit 1
fi
for _c in "$CERT_DIR"/sandlot-*.crt "$CERT_DIR"/gateway-*.crt; do
    [[ -f "$_c" ]] || continue
    if _etcd_ca_verifies_node "$_c"; then
        echo "error: $_c verifies against the ETCD CA — a node/gateway certificate must never be an etcd client (independent CAs were not applied)" >&2
        exit 1
    fi
done
if _stream_ca_verifies_etcd "$CERT_DIR/etcd-client.crt"; then
    echo "error: the etcd client certificate verifies against the STREAM CA — etcd material must be signed by ca-etcd only" >&2
    exit 1
fi
echo "  ✓ CA boundary: node/gateway certificates do NOT authenticate to etcd" >&2
unset _c
echo "  Certificates generated in $CERT_DIR/" >&2
ls -la "$CERT_DIR"/ >&2

# ── Generate K8s Secret YAML ──────────────────────────────────────
echo "  Generating K8s Secret YAML..." >&2

b64() { base64 -w0 "$1"; }

cat <<EOF
---
apiVersion: v1
kind: Secret
metadata:
  name: etcd-certs
  namespace: sandswap
type: Opaque
data:
  # CLIENT material only — this Secret is mounted into the gateway /
  # human pods (as an etcd client), and bundling the SERVER private key here
  # put the cluster's etcd server key inside every gateway pod.
  # ca.crt here is the ETCD CA (the consumers' --etcd-ca path is unchanged):
  # node stream certificates are signed by the independent STREAM CA and do
  # not authenticate to etcd.
  ca.crt: $(b64 "$CERT_DIR/ca-etcd.crt")
  client.crt: $(b64 "$CERT_DIR/etcd-client.crt")
  client.key: $(b64 "$CERT_DIR/etcd-client.key")
---
apiVersion: v1
kind: Secret
metadata:
  name: etcd-server-certs
  namespace: sandswap
type: Opaque
data:
  # Server material — consumed ONLY by the etcd StatefulSet. ca-etcd.crt is
  # etcd's --trusted-ca-file: the ONLY CA whose clients etcd accepts.
  server.crt: $(b64 "$CERT_DIR/etcd-server.crt")
  server.key: $(b64 "$CERT_DIR/etcd-server.key")
  ca-etcd.crt: $(b64 "$CERT_DIR/ca-etcd.crt")
---
apiVersion: v1
kind: Secret
metadata:
  name: gateway-certs
  namespace: sandswap
type: Opaque
data:
  ca.crt: $(b64 "$CERT_DIR/ca.crt")
  stream.crt: $(b64 "$CERT_DIR/gateway-stream.crt")
  stream.key: $(b64 "$CERT_DIR/gateway-stream.key")
  agent.crt: $(b64 "$CERT_DIR/gateway-agent.crt")
  agent.key: $(b64 "$CERT_DIR/gateway-agent.key")
  human.crt: $(b64 "$CERT_DIR/gateway-human.crt")
  human.key: $(b64 "$CERT_DIR/gateway-human.key")
EOF

# ── Per-node stream client material: ONE SECRET PER NODE ────────────
# client.crt/client.key carry CN=<node> (THE CN RULE). k8s-host-setup.sh —
# which runs per node — fetches this node's Secret into
# /etc/sandswap/stream-certs/ and the sandlot DaemonSet mounts it (the pod
# never sees another node's key). The `sandlot-certs-prov` Secret is the
# provision Deployment's singleton identity.
for entry in "${NODE_SECRETS[@]}"; do
    secret="${entry%% *}"; base="${entry##* }"
    cat <<EOF
---
apiVersion: v1
kind: Secret
metadata:
  name: ${secret}
  namespace: sandswap
type: Opaque
data:
  ca.crt: $(b64 "$CERT_DIR/ca.crt")
  client.crt: $(b64 "$CERT_DIR/${base}.crt")
  client.key: $(b64 "$CERT_DIR/${base}.key")
EOF
done

echo "" >&2
echo "Per-node stream secrets minted (fetch each on its own node via" >&2
echo "deploy/k8s/k8s-host-setup.sh, which writes /etc/sandswap/stream-certs/):" >&2
for entry in "${NODE_SECRETS[@]}"; do echo "  ${entry%% *}" >&2; done
echo "Certificates generated. To apply to K8s:" >&2
echo "  bash deploy/k8s/gen-k8s-certs.sh | kubectl apply -f -" >&2

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
# test-oci-registry.sh — End-to-end OCI registry integration test.
# Tests the complete template lifecycle:
#   1. Flat template → Create flat SandFS → agent modifications
#   2. SaveAsTemplate → PushTemplate → delete local cache
#   3. PullTemplate → Create overlay SandFS → verify files
#   4. Auto-pull ON CREATE (no explicit pull first) for both modes, with the
#      create response's pull_status asserted ("pulled" first, "cached" after)
# The registry runs htpasswd-authenticated: the prov instance must carry
# credentials for EVERY push/pull above, and unauthenticated access is
# asserted to fail (401) so an auth regression cannot pass silently.
# Auto-downloads OCI registry (distribution/distribution v3.1.1) from GitHub releases.
# Prerequisites:
#   - All artifacts built (bash build/build.sh all)
#   - Root privileges (KVM, mount, etc.)
#   - curl
# Usage: sudo bash e2e/oci-registry.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUTPUT="${OUTPUT:-$ROOT/output}"
source "$ROOT/e2e/common.sh"

OCI_REGISTRY_VERSION="3.1.1"
OCI_REGISTRY_URL="https://github.com/distribution/distribution/releases/download/v${OCI_REGISTRY_VERSION}/registry_${OCI_REGISTRY_VERSION}_linux_amd64.tar.gz"
OCI_REGISTRY_BIN="$OUTPUT/oci-registry"
OCI_REGISTRY_PORT=15000
OCI_REGISTRY_PID=""
# Basic-auth credentials for the local registry. distribution supports ONLY
# bcrypt htpasswd entries (non-bcrypt lines are silently skipped → every
# request 401s). The hash below was generated ONCE at authoring time with
#   python3 -c "import bcrypt; print('sandswaptest:'+bcrypt.hashpw(b'sandswap-e2e', bcrypt.gensalt(rounds=10)).decode())"
# so the script itself has no runtime dependency on python-bcrypt.
OCI_REGISTRY_USER="sandswaptest"
OCI_REGISTRY_PASS="sandswap-e2e"
OCI_REGISTRY_HTPASSWD='sandswaptest:$2b$10$W5K3nYLnK0llrUdeXOy6x.VZ.UXoian20FAGp5P5qZyri1hLtVk5a'
FLAT_DIR=""
OVERLAY_DIR=""
OCI_REGISTRY_DATA=""
OCI_FAILS=0
fail_() { OCI_FAILS=$((OCI_FAILS+1)); log_error "$1"; }

# ── Cleanup ──────────────────────────────────────────────────────
cleanup() {
    # Kill OCI registry (not caught by tc_kill_sandswap_procs — different process name)
    kill ${OCI_REGISTRY_PID:-} 2>/dev/null || true
    wait ${OCI_REGISTRY_PID:-} 2>/dev/null || true
    # Belt-and-braces: free the port even if the kill above raced (same
    # treatment etcd gets in tc_cleanup_etcd).
    tc_kill_port "$OCI_REGISTRY_PORT"
    # Standard cleanup: kill gateway/sandlot, teardown network, detach vsockguard,
    # unmount overlays, remove VOL_ROOT /run/sandswap / LOG_DIR
    tc_cleanup_default
    # Remove OCI-specific temp directories
    rm -rf "${FLAT_DIR:-}" "${OVERLAY_DIR:-}" "${OCI_REGISTRY_DATA:-}" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# ══════════════════════════════════════════════════════════════════
log_section "Phase 0: Pre-flight & Download OCI Registry"
# ══════════════════════════════════════════════════════════════════

tc_check_root
tc_preflight_standard
tc_check_kvm

# Download OCI registry binary if not cached
if [[ ! -x "$OCI_REGISTRY_BIN" ]]; then
    log_step "Downloading OCI registry v${OCI_REGISTRY_VERSION}..."
    curl -sL "$OCI_REGISTRY_URL" | tar xz -C "$OUTPUT" registry
    mv "$OUTPUT/registry" "$OCI_REGISTRY_BIN"
    chmod +x "$OCI_REGISTRY_BIN"
    log_pass "OCI registry binary downloaded"
else
    log_pass "OCI registry binary cached"
fi

# Clean environment
tc_clean_environment
tc_deploy_artifacts
tc_ensure_dev_nodes

# ══════════════════════════════════════════════════════════════════
log_section "Phase 1: Start Local OCI Registry"
# ══════════════════════════════════════════════════════════════════

OCI_REGISTRY_DATA=$(mktemp -d /tmp/sandswap-oci-registry-XXXXXX)

# htpasswd file for registry basic auth (bcrypt entry pinned above).
printf '%s\n' "$OCI_REGISTRY_HTPASSWD" > "$OCI_REGISTRY_DATA/htpasswd"
chmod 600 "$OCI_REGISTRY_DATA/htpasswd"

# Create minimal registry config (htpasswd-authenticated: every push/pull in
# this suite authenticates; the readiness probe below uses the credentials).
cat > "$OCI_REGISTRY_DATA/config.yml" << YAML
version: 0.1
storage:
  filesystem:
    rootdirectory: ${OCI_REGISTRY_DATA}/registry
  delete:
    enabled: true
auth:
  htpasswd:
    realm: sandswap-e2e
    path: ${OCI_REGISTRY_DATA}/htpasswd
http:
  addr: :15000
  headers:
    X-Content-Type-Options: [nosniff]
health:
  storagedriver:
    enabled: true
    interval: 10s
    threshold: 3
YAML

# PRE-CLEAN: a SIGKILLed previous run leaks the registry (different process
# name — tc_clean_environment can't catch it). A leftover registry holds the
# port: the new one fails to bind and dies, but the readiness probe below
# succeeds against the STALE one and the run aborts later on kill -0 with a
# confusing error. Free the port first.
tc_kill_port "$OCI_REGISTRY_PORT"
sleep 0.5
log_step "Starting OCI registry on port $OCI_REGISTRY_PORT..."
"$OCI_REGISTRY_BIN" serve "$OCI_REGISTRY_DATA/config.yml" > "$LOG_DIR/oci-registry.log" 2>&1 &
OCI_REGISTRY_PID=$!

# Wait for registry readiness — the loop result MUST be landed: continuing
# with a dead registry only surfaces later as unrelated push/pull failures.
# The probe carries credentials (an anonymous probe now gets 401 and would
# never turn green); authenticated `{}` also proves the htpasswd file landed
# where the config says — a bad path makes distribution generate a random
# `docker` user instead, which would surface here as a readiness failure.
REGISTRY_UP=0
# shellcheck disable=SC2034  # poll loop counter
for i in $(seq 1 20); do
    sleep 0.5
    if curl -s -u "$OCI_REGISTRY_USER:$OCI_REGISTRY_PASS" "http://localhost:$OCI_REGISTRY_PORT/v2/" 2>/dev/null | grep -q '{}' || \
       curl -s -u "$OCI_REGISTRY_USER:$OCI_REGISTRY_PASS" "http://localhost:$OCI_REGISTRY_PORT/v2/" 2>/dev/null | grep -q 'registry'; then
        REGISTRY_UP=1
        break
    fi
done

if [[ "$REGISTRY_UP" -ne 1 ]] || ! kill -0 $OCI_REGISTRY_PID 2>/dev/null; then
    log_error "OCI registry failed to start (ready=$REGISTRY_UP)"
    cat "$LOG_DIR/oci-registry.log"
    exit 1
fi
log_pass "OCI registry running (PID $OCI_REGISTRY_PID, port $OCI_REGISTRY_PORT, htpasswd auth)"

# Negative check — auth is ACTUALLY enforced, so the credentialed pulls below
# cannot be passing anonymously (fake-green guard). Both the API ping and a
# manifest path must 401 without credentials.
ANON_PING=$(curl -s -o /dev/null -w '%{http_code}' "http://localhost:$OCI_REGISTRY_PORT/v2/")
ANON_MANIFEST=$(curl -s -o /dev/null -w '%{http_code}' "http://localhost:$OCI_REGISTRY_PORT/v2/sandswap-templates/manifests/busybox-v1")
if [[ "$ANON_PING" == "401" && "$ANON_MANIFEST" == "401" ]]; then
    log_pass "Registry rejects unauthenticated access (401 on /v2/ and manifest path)"
else
    fail_ "Registry did NOT enforce auth (ping /v2/=$ANON_PING manifest=$ANON_MANIFEST, want 401/401) — the credentialed pulls below would prove nothing"
fi

# ══════════════════════════════════════════════════════════════════
log_section "Phase 2: Prepare Flat Template Directory"
# ══════════════════════════════════════════════════════════════════

# Both template roots are mktemp (root-700) — the PROV role (the sandlot
# identity) must read the flat tree and write layers/refs into the overlay
# root. ss_prepare_shared_dir replaces the mktemp defaults with shared setgid
# dirs; a bare mktemp leaves the whole scan empty (every lookup fails as
# "other").
FLAT_DIR=$(mktemp -d /tmp/sandswap-flat-templates-XXXXXX)
OVERLAY_DIR=$(mktemp -d /tmp/sandswap-overlay-templates-XXXXXX)
ss_prepare_shared_dir "$FLAT_DIR" "$OVERLAY_DIR"

# Create a flat template: busybox/v1/ containing the rootfs
ss_seed_template "$OUTPUT/rootfs-template" "$FLAT_DIR/busybox/v1"
log_pass "Flat template prepared: $FLAT_DIR/busybox/v1/"

# Create a marker file in the flat template to verify it later
echo "hello-from-flat-template" > "$FLAT_DIR/busybox/v1/tmp/marker.txt"

# ══════════════════════════════════════════════════════════════════
log_section "Phase 3: Start Gateway & Sandlot"
# ══════════════════════════════════════════════════════════════════

tc_setup_host_network
tc_gen_certs

# The gateway carries NO template flags (it has no template manager): the
# store, the flat scan, and the registry all live in the prov role.
log_step "Starting gateway (no storage: template ops relay to the prov role)..."
tc_start_gateway

log_step "Starting sandlot (merged exec,prov — template store + flat scan + credentialed registry)..."
tc_start_sandlot \
    -overlayfs-templates "$OVERLAY_DIR" \
    -flat-templates "$FLAT_DIR" \
    -oci-registry "localhost:$OCI_REGISTRY_PORT/sandswap-templates" \
    -registry-username "$OCI_REGISTRY_USER" \
    -registry-password "$OCI_REGISTRY_PASS"
tc_wait_health
tc_wait_pool_ready

# Verify flat templates were scanned — the listing is a stream RPC to the
# prov role, so this must run AFTER the sandlot is up.
TEMPLATES_RESP=$(curl -s "$HUMAN_URL/human/templates" 2>/dev/null || echo "[]")
log_info "Registered templates: $TEMPLATES_RESP"
echo "$TEMPLATES_RESP" | python3 -c "
import sys, json
ts = json.load(sys.stdin)
for t in ts: print(f'    - {t[\"name\"]}:{t[\"version\"]} (cached: {t[\"cached\"]})')
" 2>/dev/null || log_warn "Could not parse templates response"

# ══════════════════════════════════════════════════════════════════
log_section "Phase 4: Create Flat SandFS & Modify"
# ══════════════════════════════════════════════════════════════════

# Create agent + SandFS (flat mode with busybox:v1 template)
AGENT_RESP=$(curl -s -X POST "$HUMAN_URL/human/agent" \
    -H "Content-Type: application/json" \
    -d '{"name":"test-agent"}')
AGENT_ID=$(echo "$AGENT_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('agent_id',''))" 2>/dev/null)
API_KEY=$(echo "$AGENT_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('api_key',''))" 2>/dev/null)
if [[ -z "$AGENT_ID" || -z "$API_KEY" ]]; then
    log_error "Failed to create agent: $AGENT_RESP"
    exit 1
fi
log_info "Agent created: $AGENT_ID"

SANDFS_RESP=$(curl -s -X POST "$HUMAN_URL/human/sandfs" \
    -H "Content-Type: application/json" \
    -d "{\"agent_id\":\"$AGENT_ID\",\"name\":\"test-sandfs\",\"template\":\"busybox:v1\",\"mode\":\"flat\"}")
SANDFS_ID=$(echo "$SANDFS_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('sandfs_id',''))" 2>/dev/null)

if [[ -z "$SANDFS_ID" ]]; then
    log_error "Failed to create SandFS: $SANDFS_RESP"
    exit 1
fi
log_pass "Flat SandFS created: $SANDFS_ID"

# Verify the marker file from the flat template exists
EXEC_RESP=$(curl -s -X POST "$GATEWAY_URL/agent/execute" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $API_KEY" \
    -d "{\"sandfs_id\":\"$SANDFS_ID\",\"code\":\"cat /tmp/marker.txt\",\"language\":\"shell\",\"timeout\":5}")
MARKER=$(echo "$EXEC_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('stdout','').strip())" 2>/dev/null)
if [[ "$MARKER" == "hello-from-flat-template" ]]; then
    log_pass "Flat template marker found in SandFS"
else
    fail_ "Flat template marker not found: got '$MARKER'"
fi

# Write a new file that we'll verify after save-template → push → pull.
# Use /var/lib/ (inside the rootfs, persists through SaveAsTemplate)
# instead of /tmp/ (tmpfs in overlay mode) or /workspace/ (writable bind
# mount in overlay mode, masks the rootfs content).
EXEC_RESP=$(curl -s -X POST "$GATEWAY_URL/agent/execute" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $API_KEY" \
    -d "{\"sandfs_id\":\"$SANDFS_ID\",\"code\":\"mkdir -p /var/lib && echo saved-template-data > /var/lib/saved.txt\",\"language\":\"shell\",\"timeout\":5}")
EXIT_CODE=$(echo "$EXEC_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('exit_code',-1))" 2>/dev/null)
if [[ "$EXIT_CODE" == "0" ]]; then
    log_pass "Wrote test file to flat SandFS"
else
    fail_ "Failed to write test file"
fi

# ══════════════════════════════════════════════════════════════════
log_section "Phase 5: SaveAsTemplate → PushTemplate"
# ══════════════════════════════════════════════════════════════════

# Save the SandFS as a template
SAVE_RESP=$(curl -s -X POST "$HUMAN_URL/human/sandfs/$SANDFS_ID/save-template" \
    -H "Content-Type: application/json" \
    -d '{"template_ref":"myapp:v1","description":"Test template from OCI integration test"}')
SAVE_REF=$(echo "$SAVE_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('template_ref',''))" 2>/dev/null)

if [[ "$SAVE_REF" == "myapp:v1" ]]; then
    log_pass "SaveAsTemplate succeeded: myapp:v1"
else
    log_error "SaveAsTemplate failed: $SAVE_RESP"
    exit 1
fi

# Verify template appears in ListTemplates
TEMPLATES_RESP=$(curl -s "$HUMAN_URL/human/templates" 2>/dev/null || echo "[]")
echo "$TEMPLATES_RESP" | python3 -c "
import sys, json
ts = json.load(sys.stdin)
found = any(t['name'] == 'myapp' for t in ts)
print('FOUND' if found else 'NOT_FOUND')
" 2>/dev/null | grep -q FOUND && log_pass "myapp:v1 in ListTemplates" || fail_ "myapp:v1 not in ListTemplates"

# Push the template to OCI registry
PUSH_RESP=$(curl -s -X POST "$HUMAN_URL/human/templates/myapp:v1/push" \
    -H "Content-Type: application/json")
PUSH_DIGEST=$(echo "$PUSH_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('digest',''))" 2>/dev/null)

if [[ -n "$PUSH_DIGEST" && "$PUSH_DIGEST" != "" ]]; then
    log_pass "PushTemplate succeeded: digest=$PUSH_DIGEST"
else
    log_error "PushTemplate failed: $PUSH_RESP"
    exit 1
fi

# ══════════════════════════════════════════════════════════════════
log_section "Phase 6: Delete Local Cache & PullTemplate"
# ══════════════════════════════════════════════════════════════════

# Delete the local overlay template cache (simulate a new node). VERIFY
# something was actually there: if sandlot/gateway's on-disk layout drifts,
# these rm's become silent no-ops, the pull is served from cache, and the
# pull path this phase exists to test never runs.
log_step "Deleting local overlay template cache..."
CACHE_HAD_CONTENT=0
[[ -d "$OVERLAY_DIR/layers/local-myapp-v1" ]] && CACHE_HAD_CONTENT=1
[[ -e "$OVERLAY_DIR/refs/myapp_v1.flat.json" || -e "$OVERLAY_DIR/refs/myapp_v1.overlay.json" ]] && CACHE_HAD_CONTENT=1
rm -rf "$OVERLAY_DIR/layers/local-myapp-v1"
rm -f "$OVERLAY_DIR/refs/myapp_v1.flat.json" "$OVERLAY_DIR/refs/myapp_v1.overlay.json"
if [[ "$CACHE_HAD_CONTENT" -eq 1 ]]; then
    log_pass "Local cache cleared (was present, now removed)"
else
    fail_ "template cache was EMPTY before the delete — pull below would test the cache, not the registry (layout drift?)"
fi

# Pull the template from OCI registry
PULL_RESP=$(curl -s -X POST "$HUMAN_URL/human/templates/myapp:v1" \
    -H "Content-Type: application/json")
PULL_STATUS=$(echo "$PULL_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('name',''))" 2>/dev/null)

if [[ "$PULL_STATUS" == "myapp" ]]; then
    log_pass "PullTemplate succeeded: myapp:v1"
else
    log_error "PullTemplate failed: $PULL_RESP"
    exit 1
fi

# ══════════════════════════════════════════════════════════════════
log_section "Phase 7: Create Overlay SandFS from Pulled Template"
# ══════════════════════════════════════════════════════════════════

# Create a new SandFS using the pulled template (overlay mode)
OVERLAY_RESP=$(curl -s -X POST "$HUMAN_URL/human/sandfs" \
    -H "Content-Type: application/json" \
    -d "{\"agent_id\":\"$AGENT_ID\",\"name\":\"overlay-sandfs\",\"template\":\"myapp:v1\",\"mode\":\"overlay\"}")
OVERLAY_ID=$(echo "$OVERLAY_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('sandfs_id',''))" 2>/dev/null)

if [[ -z "$OVERLAY_ID" ]]; then
    log_error "Failed to create overlay SandFS: $OVERLAY_RESP"
    exit 1
fi
log_pass "Overlay SandFS created: $OVERLAY_ID"

# Verify the saved file exists in the overlay SandFS.
# In overlay mode, /var/lib/ is in the read-only rootfs layer (not masked by the workspace/tmpfs mounts).
EXEC_RESP=$(curl -s -X POST "$GATEWAY_URL/agent/execute" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $API_KEY" \
    -d "{\"code\":\"cat /var/lib/saved.txt\",\"language\":\"shell\",\"timeout\":5,\"sandfs_id\":\"$OVERLAY_ID\"}")
SAVED=$(echo "$EXEC_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('stdout','').strip())" 2>/dev/null)
if [[ "$SAVED" == "saved-template-data" ]]; then
    log_pass "Saved file found in overlay SandFS from pulled template"
else
    fail_ "Saved file not found in overlay SandFS: got '$SAVED'"
fi

# Verify the marker file from the original flat template content.
# In overlay mode, /tmp/ is tmpfs so the marker won't be there —
# check the read-only rootfs layer instead.
EXEC_RESP=$(curl -s -X POST "$GATEWAY_URL/agent/execute" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $API_KEY" \
    -d "{\"code\":\"ls -la /tmp/marker.txt 2>&1; cat /tmp/marker.txt 2>&1 || echo MARKER_NOT_IN_TMPFS\",\"language\":\"shell\",\"timeout\":5,\"sandfs_id\":\"$OVERLAY_ID\"}")
MARKER2=$(echo "$EXEC_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('stdout','').strip())" 2>/dev/null)
# INVERTED into a real assertion: the flat rootfs HAS /tmp/marker.txt, and
# overlay mode mounts a fresh tmpfs over /tmp — so the marker MUST be masked.
# The old form (pass on hit, warn on miss) could never fail and tested nothing.
if echo "$MARKER2" | grep -q "hello-from-flat-template"; then
    fail_ "rootfs /tmp/marker.txt VISIBLE in overlay mode — fresh tmpfs masking of /tmp is broken: $MARKER2"
else
    log_pass "rootfs /tmp marker correctly masked by overlay tmpfs"
fi

# ══════════════════════════════════════════════════════════════════
log_section "Phase 8: Flat Template Push → Pull → Flat SandFS from OCI"
# ══════════════════════════════════════════════════════════════════

# The flat-OCI path: push the local busybox:v1 flat template, delete the local
# ref, pull it back (manifest-only — digests recorded, nothing extracted), then
# create a flat SandFS that materializes by streaming the blobs straight into
# the volume.

# Push the local flat template with mode=flat
PUSH_FLAT_RESP=$(curl -s -X POST "$HUMAN_URL/human/templates/busybox:v1/push" \
    -H "Content-Type: application/json" \
    -d '{"mode":"flat"}')
PUSH_FLAT_DIGEST=$(echo "$PUSH_FLAT_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('digest',''))" 2>/dev/null)
if [[ -n "$PUSH_FLAT_DIGEST" && "$PUSH_FLAT_DIGEST" != "None" ]]; then
    log_pass "PushTemplate (flat) succeeded: digest=$PUSH_FLAT_DIGEST"
else
    fail_ "PushTemplate (flat) failed: $PUSH_FLAT_RESP"
fi

# Delete the local flat ref (verify-first, same pattern as Phase 6: a silent
# no-op rm would leave the create below served from the local dir instead of
# the OCI materialization path this phase exists to test).
BUSYBOX_REF="$OVERLAY_DIR/refs/busybox_v1.flat.json"
if [[ ! -e "$BUSYBOX_REF" ]]; then
    fail_ "flat ref $BUSYBOX_REF missing before delete — push did not leave a local ref (layout drift?)"
else
    rm -f "$BUSYBOX_REF"
    log_pass "Local flat ref cleared"
fi

# Layers extracted count must not change across a flat pull (flat pulls read
# the manifest only; extraction happens per-sandfs into the volume, never into
# the shared layers/ cache).
LAYERS_BEFORE=$(find "$OVERLAY_DIR/layers" -maxdepth 1 -mindepth 1 -type d 2>/dev/null | wc -l)

PULL_FLAT_RESP=$(curl -s -X POST "$HUMAN_URL/human/templates/busybox:v1" \
    -H "Content-Type: application/json" \
    -d '{"mode":"flat"}')
PULL_FLAT_NAME=$(echo "$PULL_FLAT_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('name',''))" 2>/dev/null)
if [[ "$PULL_FLAT_NAME" == "busybox" ]]; then
    log_pass "PullTemplate (flat) succeeded"
else
    fail_ "PullTemplate (flat) failed: $PULL_FLAT_RESP"
fi

# The pulled flat ref must record oci_layers and no local layers; and no new
# extraction may have landed in layers/.
REF_CHECK=$(python3 -c "
import json
with open('$BUSYBOX_REF') as f: e = json.load(f)
print('OK' if e.get('oci_layers') and not e.get('layers') else 'BAD')
" 2>/dev/null)
if [[ "$REF_CHECK" == "OK" ]]; then
    log_pass "Flat ref records oci_layers (digests pinned, no local cache)"
else
    fail_ "Flat ref wrong shape after pull (want oci_layers set, layers empty)"
fi
LAYERS_AFTER=$(find "$OVERLAY_DIR/layers" -maxdepth 1 -mindepth 1 -type d 2>/dev/null | wc -l)
if [[ "$LAYERS_AFTER" -eq "$LAYERS_BEFORE" ]]; then
    log_pass "Flat pull extracted nothing into layers/ ($LAYERS_AFTER dirs, unchanged)"
else
    fail_ "Flat pull changed layers/ count: $LAYERS_BEFORE → $LAYERS_AFTER"
fi

# Create a flat SandFS from the OCI-origin template — this streams the blobs
# straight into the new volume.
FLATOCI_RESP=$(curl -s -X POST "$HUMAN_URL/human/sandfs" \
    -H "Content-Type: application/json" \
    -d "{\"agent_id\":\"$AGENT_ID\",\"name\":\"flat-oci-sandfs\",\"template\":\"busybox:v1\",\"mode\":\"flat\"}")
FLATOCI_ID=$(echo "$FLATOCI_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('sandfs_id',''))" 2>/dev/null)
# Volume directory: derived from the deployment seed, NOT the id
FLATOCI_ID_VOL="$(tc_volume_path "$FLATOCI_ID")" || { echo "cannot resolve volume for $FLATOCI_ID" >&2; exit 1; }
if [[ -z "$FLATOCI_ID" ]]; then
    fail_ "Failed to create flat SandFS from OCI template: $FLATOCI_RESP"
else
    log_pass "Flat SandFS created from OCI template: $FLATOCI_ID"
fi

# Marker file must have materialized from the streamed blob, and the volume
# must stay fully writable (the point of flat mode).
if [[ -n "$FLATOCI_ID" ]]; then
    EXEC_RESP=$(curl -s -X POST "$GATEWAY_URL/agent/execute" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $API_KEY" \
        -d "{\"sandfs_id\":\"$FLATOCI_ID\",\"code\":\"cat /tmp/marker.txt && echo flat-oci-ok > /tmp/wrote.txt && cat /tmp/wrote.txt\",\"language\":\"shell\",\"timeout\":5}")
    FLATOCI_OUT=$(echo "$EXEC_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('stdout','').strip())" 2>/dev/null)
    if [[ "$FLATOCI_OUT" == *hello-from-flat-template* && "$FLATOCI_OUT" == *flat-oci-ok* ]]; then
        log_pass "OCI flat SandFS has template content and is writable"
    else
        fail_ "OCI flat SandFS content/writability check failed: got '$FLATOCI_OUT'"
    fi

    # Host-side permission policy: seeded files group-writable (0664 from the
    # template's 0644), directories group-writable + setgid — the shared-group
    # contract the dedicated-identity model requires.
    FLATOCI_VOL="${FLATOCI_ID_VOL}"
    MARKER_PERM=$(stat -c "%a" "$FLATOCI_VOL/tmp/marker.txt" 2>/dev/null)
    if [[ "$MARKER_PERM" == "664" ]]; then
        log_pass "OCI flat materialized file is group-writable (0664)"
    else
        fail_ "OCI flat marker.txt perm = ${MARKER_PERM:-missing}, want 664"
    fi
    TMP_PERM=$(stat -c "%a" "$FLATOCI_VOL/tmp" 2>/dev/null)
    # The template contract normalizes layers/trees to owner-write-only
    # (group/other write cleared), so the built /tmp is sticky 1755; the flat
    # materialization policy ORs setgid+group-write (2770) → 2775. Group write
    # is the agent's path through the shared group; other-write is
    # deliberately gone (the template is shared storage).
    if [[ "$TMP_PERM" == "2775" ]]; then
        log_pass "OCI flat materialized dir is setgid+group-writable (2775; other-write cleared by the contract)"
    else
        fail_ "OCI flat /tmp perm = ${TMP_PERM:-missing}, want 2775"
    fi
fi

# ══════════════════════════════════════════════════════════════════
log_section "Phase 9: Flat Auto-Pull ON CREATE (no explicit pull)"
# ══════════════════════════════════════════════════════════════════

# A create naming a ref that exists ONLY in the registry must pull it on
# demand and report pull_status "pulled" — and the second create from the
# now-local ref must report "cached". Making the ref registry-only takes TWO
# deletions: the ref file AND the source directory under the flat scan root —
# a ref-miss triggers the prov instance's lazy rescan, which would re-register
# busybox:v1 from the local directory and the create would never consult the
# registry (the first run of this phase proved exactly that: "cached").
if [[ ! -e "$BUSYBOX_REF" ]]; then
    fail_ "flat ref $BUSYBOX_REF missing before delete (Phase 8 should have recreated it — layout drift?)"
else
    rm -f "$BUSYBOX_REF"
    log_pass "Local flat ref cleared (registry is now the only source)"
fi
FLAT_TEMPLATE_STASH="$OCI_REGISTRY_DATA/local-flat-stash"
mkdir -p "$FLAT_TEMPLATE_STASH"
mv "$FLAT_DIR/busybox" "$FLAT_TEMPLATE_STASH/busybox"
log_pass "Local flat template dir stashed out of the scan root"
LAYERS_BEFORE=$(find "$OVERLAY_DIR/layers" -maxdepth 1 -mindepth 1 -type d 2>/dev/null | wc -l)

AUTOPULL_FLAT_RESP=$(curl -s -X POST "$HUMAN_URL/human/sandfs" \
    -H "Content-Type: application/json" \
    -d "{\"agent_id\":\"$AGENT_ID\",\"name\":\"autopull-flat\",\"template\":\"busybox:v1\",\"mode\":\"flat\"}")
AUTOPULL_FLAT_ID=$(echo "$AUTOPULL_FLAT_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('sandfs_id',''))" 2>/dev/null)
AUTOPULL_FLAT_STATUS=$(echo "$AUTOPULL_FLAT_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('pull_status',''))" 2>/dev/null)
if [[ -z "$AUTOPULL_FLAT_ID" ]]; then
    fail_ "create flat SandFS from a registry-only ref failed: $AUTOPULL_FLAT_RESP"
else
    log_pass "Flat SandFS created from a registry-only ref: $AUTOPULL_FLAT_ID"
fi
if [[ "$AUTOPULL_FLAT_STATUS" == "pulled" ]]; then
    log_pass "pull_status = pulled (create auto-pulled the manifest)"
else
    fail_ "pull_status = '${AUTOPULL_FLAT_STATUS:-missing}', want 'pulled' — the auto-pull signal did not reach the HTTP response"
fi

# The recreated ref must be OCI-origin (oci_layers, no local layers) — proof
# the registry served the create, not a rescan of the stashed directory.
AUTOPULL_REF_SHAPE=$(python3 -c "
import json
with open('$BUSYBOX_REF') as f: e = json.load(f)
print('OK' if e.get('oci_layers') and not e.get('layers') else 'BAD')
" 2>/dev/null)
if [[ "$AUTOPULL_REF_SHAPE" == "OK" ]]; then
    log_pass "Recreated ref is OCI-origin (digests pinned, no local layer)"
else
    fail_ "recreated flat ref is not OCI-origin (want oci_layers set, layers empty) — the create did not pull from the registry"
fi

# Content must stream from the registry (the local flat dir was never the
# source: the ref was deleted), and the flat auto-pull must not have
# extracted anything into layers/ (manifest-only, same invariant as Phase 8).
if [[ -n "$AUTOPULL_FLAT_ID" ]]; then
    EXEC_RESP=$(curl -s -X POST "$GATEWAY_URL/agent/execute" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $API_KEY" \
        -d "{\"sandfs_id\":\"$AUTOPULL_FLAT_ID\",\"code\":\"cat /tmp/marker.txt\",\"language\":\"shell\",\"timeout\":5}")
    AUTOPULL_FLAT_OUT=$(echo "$EXEC_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('stdout','').strip())" 2>/dev/null)
    if [[ "$AUTOPULL_FLAT_OUT" == "hello-from-flat-template" ]]; then
        log_pass "Auto-pulled flat SandFS has the registry content"
    else
        fail_ "auto-pulled flat SandFS content check failed: got '$AUTOPULL_FLAT_OUT'"
    fi
fi
LAYERS_AFTER=$(find "$OVERLAY_DIR/layers" -maxdepth 1 -mindepth 1 -type d 2>/dev/null | wc -l)
if [[ "$LAYERS_AFTER" -eq "$LAYERS_BEFORE" ]]; then
    log_pass "Flat auto-pull extracted nothing into layers/ (manifest-only)"
else
    fail_ "flat auto-pull changed layers/ count: $LAYERS_BEFORE → $LAYERS_AFTER"
fi

# The ref now exists locally: the next create is a cache hit.
AUTOPULL_FLAT2_STATUS=$(curl -s -X POST "$HUMAN_URL/human/sandfs" \
    -H "Content-Type: application/json" \
    -d "{\"agent_id\":\"$AGENT_ID\",\"name\":\"autopull-flat-2\",\"template\":\"busybox:v1\",\"mode\":\"flat\"}" \
    | python3 -c "import sys,json; print(json.load(sys.stdin).get('pull_status',''))" 2>/dev/null)
if [[ "$AUTOPULL_FLAT2_STATUS" == "cached" ]]; then
    log_pass "second create from the now-local ref reports pull_status = cached"
else
    fail_ "second create pull_status = '${AUTOPULL_FLAT2_STATUS:-missing}', want 'cached'"
fi

# ══════════════════════════════════════════════════════════════════
log_section "Phase 10: Overlay Auto-Pull ON CREATE (registry-only ref)"
# ══════════════════════════════════════════════════════════════════

# Freeze a NEW ref (autopull:v1) from the original flat sandfs, publish it,
# then wipe the local ref + extracted layer so only the registry has it.
# Give the volume UNIQUE content first: myapp:v1 was saved from the same
# volume, so an unchanged copy could push a byte-identical layer — the
# overlay pull below would then dedup into the already-cached sha256-… dir
# and the extraction assertion could not distinguish "extracted by this
# create" from "already cached" (the first run of this phase hit exactly
# that: layers/ 1 → 1 with the dedup hit).
EXEC_RESP=$(curl -s -X POST "$GATEWAY_URL/agent/execute" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $API_KEY" \
    -d "{\"sandfs_id\":\"$SANDFS_ID\",\"code\":\"echo autopull-unique > /var/lib/autopull.txt\",\"language\":\"shell\",\"timeout\":5}")
AUTOPULL_WRITE_CODE=$(echo "$EXEC_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('exit_code',-1))" 2>/dev/null)
if [[ "$AUTOPULL_WRITE_CODE" != "0" ]]; then
    fail_ "failed to write unique content into $SANDFS_ID before save-template: $EXEC_RESP"
fi

AUTOPULL_SAVE=$(curl -s -X POST "$HUMAN_URL/human/sandfs/$SANDFS_ID/save-template" \
    -H "Content-Type: application/json" \
    -d '{"template_ref":"autopull:v1","description":"auto-pull-on-create fixture"}')
AUTOPULL_REF=$(echo "$AUTOPULL_SAVE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('template_ref',''))" 2>/dev/null)
if [[ "$AUTOPULL_REF" == "autopull:v1" ]]; then
    log_pass "SaveAsTemplate succeeded: autopull:v1"
else
    log_error "SaveAsTemplate (autopull:v1) failed: $AUTOPULL_SAVE"
    exit 1
fi

AUTOPULL_PUSH=$(curl -s -X POST "$HUMAN_URL/human/templates/autopull:v1/push" \
    -H "Content-Type: application/json")
if [[ -n "$(echo "$AUTOPULL_PUSH" | python3 -c "import sys,json; print(json.load(sys.stdin).get('digest',''))" 2>/dev/null)" ]]; then
    log_pass "PushTemplate succeeded: autopull:v1"
else
    log_error "PushTemplate (autopull:v1) failed: $AUTOPULL_PUSH"
    exit 1
fi

# Wipe the local copies (verify-first): a silent no-op would let the create
# below be served from the local store and never exercise the auto-pull.
AUTOPULL_LOCAL_REF="$OVERLAY_DIR/refs/autopull_v1.overlay.json"
AUTOPULL_LOCAL_LAYER="$OVERLAY_DIR/layers/local-autopull-v1"
if [[ -e "$AUTOPULL_LOCAL_REF" && -d "$AUTOPULL_LOCAL_LAYER" ]]; then
    rm -f "$AUTOPULL_LOCAL_REF"
    rm -rf "$AUTOPULL_LOCAL_LAYER"
    log_pass "Local ref + layer cleared (registry is now the only source)"
else
    fail_ "save-template left no local ref/layer to delete (want $AUTOPULL_LOCAL_REF + $AUTOPULL_LOCAL_LAYER) — the create below would not test auto-pull (layout drift?)"
fi

LAYERS_BEFORE=$(find "$OVERLAY_DIR/layers" -maxdepth 1 -mindepth 1 -type d 2>/dev/null | wc -l)

AUTOPULL_OVL_RESP=$(curl -s -X POST "$HUMAN_URL/human/sandfs" \
    -H "Content-Type: application/json" \
    -d "{\"agent_id\":\"$AGENT_ID\",\"name\":\"autopull-overlay\",\"template\":\"autopull:v1\",\"mode\":\"overlay\"}")
AUTOPULL_OVL_ID=$(echo "$AUTOPULL_OVL_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('sandfs_id',''))" 2>/dev/null)
AUTOPULL_OVL_STATUS=$(echo "$AUTOPULL_OVL_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('pull_status',''))" 2>/dev/null)
if [[ -z "$AUTOPULL_OVL_ID" ]]; then
    fail_ "create overlay SandFS from a registry-only ref failed: $AUTOPULL_OVL_RESP"
else
    log_pass "Overlay SandFS created from a registry-only ref: $AUTOPULL_OVL_ID"
fi
if [[ "$AUTOPULL_OVL_STATUS" == "pulled" ]]; then
    log_pass "pull_status = pulled (create downloaded + extracted the template)"
else
    fail_ "pull_status = '${AUTOPULL_OVL_STATUS:-missing}', want 'pulled'"
fi

# The overlay auto-pull must have extracted the layer stack into the shared
# content-addressed cache (that IS the overlay create cost model).
LAYERS_AFTER=$(find "$OVERLAY_DIR/layers" -maxdepth 1 -mindepth 1 -type d 2>/dev/null | wc -l)
if [[ "$LAYERS_AFTER" -gt "$LAYERS_BEFORE" ]]; then
    log_pass "Overlay auto-pull extracted layers into the shared cache ($LAYERS_BEFORE → $LAYERS_AFTER)"
else
    fail_ "overlay auto-pull did not populate layers/ ($LAYERS_BEFORE → $LAYERS_AFTER)"
fi

if [[ -n "$AUTOPULL_OVL_ID" ]]; then
    EXEC_RESP=$(curl -s -X POST "$GATEWAY_URL/agent/execute" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $API_KEY" \
        -d "{\"code\":\"cat /var/lib/saved.txt\",\"language\":\"shell\",\"timeout\":5,\"sandfs_id\":\"$AUTOPULL_OVL_ID\"}")
    AUTOPULL_OVL_OUT=$(echo "$EXEC_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('stdout','').strip())" 2>/dev/null)
    if [[ "$AUTOPULL_OVL_OUT" == "saved-template-data" ]]; then
        log_pass "Auto-pulled overlay SandFS serves the downloaded template content"
    else
        fail_ "auto-pulled overlay content check failed: got '$AUTOPULL_OVL_OUT'"
    fi
fi

AUTOPULL_OVL2_STATUS=$(curl -s -X POST "$HUMAN_URL/human/sandfs" \
    -H "Content-Type: application/json" \
    -d "{\"agent_id\":\"$AGENT_ID\",\"name\":\"autopull-overlay-2\",\"template\":\"autopull:v1\",\"mode\":\"overlay\"}" \
    | python3 -c "import sys,json; print(json.load(sys.stdin).get('pull_status',''))" 2>/dev/null)
if [[ "$AUTOPULL_OVL2_STATUS" == "cached" ]]; then
    log_pass "second overlay create reports pull_status = cached"
else
    fail_ "second overlay create pull_status = '${AUTOPULL_OVL2_STATUS:-missing}', want 'cached'"
fi

# ══════════════════════════════════════════════════════════════════
log_section "Results"
# ══════════════════════════════════════════════════════════════════

echo ""
echo -e "${TC_GREEN}═══ OCI Registry Integration Test ═══${TC_NC}"
echo -e "  ${TC_GREEN}✓${TC_NC} htpasswd-authenticated registry (401 enforced without creds)"
echo -e "  ${TC_GREEN}✓${TC_NC} Flat template scan & SandFS creation"
echo -e "  ${TC_GREEN}✓${TC_NC} SaveAsTemplate (flat → overlay mode)"
echo -e "  ${TC_GREEN}✓${TC_NC} PushTemplate to OCI registry"
echo -e "  ${TC_GREEN}✓${TC_NC} PullTemplate from OCI registry"
echo -e "  ${TC_GREEN}✓${TC_NC} Overlay SandFS from pulled template"
echo -e "  ${TC_GREEN}✓${TC_NC} Flat push → pull (digests pinned, no cache) → flat SandFS from OCI"
echo -e "  ${TC_GREEN}✓${TC_NC} Auto-pull ON CREATE, flat + overlay (pull_status pulled → cached)"
if [[ "$OCI_FAILS" -gt 0 ]]; then
    echo -e "  ${TC_RED}✗ $OCI_FAILS assertion(s) failed${TC_NC}"
    exit 1
fi

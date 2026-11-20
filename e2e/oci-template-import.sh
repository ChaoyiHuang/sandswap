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

# oci-template-import.sh — offline OCI image archive → template conversion,
# end to end. `template-tool import` converts a synthetic multi-ARCHIVE
# image (built here with nothing but tar + sha256sum: no docker, no oras,
# no registry) into template trees; the suite then serves SandFS from them
# and asserts the merge semantics INSIDE a guest.
#
# Covered:
#   1. Layer merge semantics visible in the guest: whiteouts (file,
#      directory, legacy 0/0 device), opaque directory, BOTH type
#      transitions (dir→file, file→dir), setuid bit, absolute symlink
#      rewritten tree-relative, the masked-symlink whiteout no-op, and
#      volume control files stripped. Markers never materialize.
#   2. Manifest handling: multi-arch index with arm64 FIRST plus an
#      attestation companion (amd64 must be selected), an UNCOMPRESSED
#      plain-tar layer (docker classic store shape) beside a gzip layer.
#   3. Both consumption modes: flat (copied into the volume) and overlay
#      (template store scan root; read-only base, writable workspace).
#   4. The plain-rootfs-tar path (docker export shape, "./"-rooted tar).
#   5. Negatives: arm64 archive refused (x86_64-only policy), corrupt blob
#      refused (digest), legacy docker-save refused, immutable version
#      directories, and no destination left behind by a failed import.
#
# The executable companion of Building Templates §2
# (docs/building/templates.md#21-automated-template-tool-import).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NETWORK_BACKEND="${NETWORK_BACKEND:-bridge}"
SANDLOT_POOL="small:2"
LEASE_MS="${LEASE_MS:-1000}"
source "$ROOT/e2e/common.sh"

tc_use_output_binaries

IMPORT="$OUTPUT/template-tool"
WORK="$(mktemp -d /tmp/sandswap-oci-import-XXXXXX)"
# The work root must be traversable by the service identities: the template
# store inside it is created shared (ss_prepare_shared_dir) but a 0700
# mktemp parent would block the prov role's path before it gets there.
chmod 0755 "$WORK"
FLAT_DIR="$WORK/flat"
TPL_DIR="$WORK/templates"
IMG_OUT="$WORK/imgs"

cleanup() {
    local exit_code=$?
    tc_cleanup_default
    rm -rf "$WORK" 2>/dev/null || true
    exit "$exit_code"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# ══════════════════════════════════════════════════════════════════
log_section "Phase 0: Pre-flight"
# ══════════════════════════════════════════════════════════════════
tc_check_root
tc_check_artifacts gateway sandlot sandvmm vmlinux.bin initramfs.cpio.gz
tc_preflight_standard
tc_ensure_dev_nodes
[[ -x "$IMPORT" ]] || { log_error "missing $IMPORT (bash build/build.sh go)"; exit 1; }
[[ -d "$OUTPUT/rootfs-template" ]] || { log_error "missing output/rootfs-template (bash build/build.sh rootfs-template)"; exit 1; }
tc_check_kvm
log_pass "artifacts present"

# ══════════════════════════════════════════════════════════════════
log_section "Phase 1: Assemble synthetic image archives (tar + sha256sum)"
# ══════════════════════════════════════════════════════════════════
mkdir -p "$IMG_OUT" "$FLAT_DIR" "$TPL_DIR"

pack_layer() { # pack_layer <srcdir> <out.tar.gz> — gzip, contents only, no root entry
    (cd "$1" && find . -mindepth 1 | LC_ALL=C sort | tar --no-recursion -T - -czf "$2")
}
pack_layer_plain() { # same, UNCOMPRESSED — the docker-save classic-store layer shape
    (cd "$1" && find . -mindepth 1 | LC_ALL=C sort | tar --no-recursion -T - -cf "$2")
}

# lower layer (UNCOMPRESSED tar): the busybox base + every victim the upper
# layer will manipulate, including the masking counterexample (a -> b, b/c)
# and a volume control file.
rm -rf "$WORK/lower" && mkdir -p "$WORK/lower"
cp -a "$OUTPUT/rootfs-template/." "$WORK/lower/"
mkdir -p "$WORK/lower/opt/whdir" "$WORK/lower/opt/typeflip" "$WORK/lower/opt/pkg" "$WORK/lower/b"
echo old > "$WORK/lower/opt/whdir/old"
echo gone > "$WORK/lower/opt/wh-target"
echo was-a-dir > "$WORK/lower/opt/typeflip/y"
echo pkg-a > "$WORK/lower/opt/pkg/a"
echo pkg-b > "$WORK/lower/opt/pkg/b"
echo dev-gone > "$WORK/lower/opt/dev-tgt"
echo was-a-file > "$WORK/lower/opt/flip2"
ln -s b "$WORK/lower/a"
echo keep > "$WORK/lower/b/c"
echo tenant-stamp > "$WORK/lower/.sandfs-id"
pack_layer_plain "$WORK/lower" "$IMG_OUT/lower.tar"

# upper layer (gzip): whiteouts (file/dir/legacy device), opaque, both type
# transitions, setuid, absolute link, and the upper REAL dir masking the
# lower symlink (the .wh.c under it must be a no-op for /b/c).
rm -rf "$WORK/upper" && mkdir -p "$WORK/upper/opt/whdir" "$WORK/upper/bin" "$WORK/upper/opt/flip2" "$WORK/upper/a"
: > "$WORK/upper/opt/.wh.wh-target"
: > "$WORK/upper/opt/.wh.pkg"
mknod "$WORK/upper/opt/.wh.dev-tgt" c 0 0
: > "$WORK/upper/opt/whdir/.wh..wh..opq"
echo new > "$WORK/upper/opt/whdir/new"
echo now-a-file > "$WORK/upper/opt/typeflip"
echo y > "$WORK/upper/opt/flip2/y"
: > "$WORK/upper/a/.wh.c"
echo su-body > "$WORK/upper/bin/su"
chmod 4755 "$WORK/upper/bin/su"
ln -s /usr/bin/marker "$WORK/upper/abslink"
pack_layer "$WORK/upper" "$IMG_OUT/upper.tar.gz"

# blob helper: copy a file into blobs/sha256/<digest>, print "<digest> <size>"
BLOBS="$WORK/layout/blobs/sha256"
blob() {
    local d
    d=$(sha256sum "$1" | cut -d' ' -f1)
    cp "$1" "$BLOBS/$d"
    printf '%s %s\n' "$d" "$(stat -c%s "$1")"
}
MANIFEST_MT='application/vnd.oci.image.manifest.v1+json'
CONFIG_MT='application/vnd.oci.image.config.v1+json'
INDEX_MT='application/vnd.oci.image.index.v1+json'
LAYER_GZ_MT='application/vnd.oci.image.layer.v1.tar+gzip'
LAYER_PLAIN_MT='application/vnd.oci.image.layer.v1.tar'

# One layout carries every blob: the plain lower + gzip upper layers, an
# amd64 image over both, and an arm64 image over one (for the multi-arch
# index and the arm64-only negative).
write_index() { # write_index <out.tar.gz> <manifest entries JSON>
    printf '{"schemaVersion":2,"mediaType":"%s","manifests":[%s]}' \
        "$INDEX_MT" "$2" > "$WORK/layout/index.json"
    echo '{"imageLayoutVersion":"1.0.0"}' > "$WORK/layout/oci-layout"
    tar -C "$WORK/layout" -czf "$1" oci-layout index.json blobs
}
manifest_entry() { # manifest_entry <digest> <size> <os> <arch> [attestation]
    # $5 defaults: an unset fifth arg under set -u would kill the command
    # substitution, silently emit an EMPTY index entry, and produce an
    # unparseable index.json (observed: every content assert downstream then
    # failed against a tree the import never published).
    local att="${5:-}"
    local extra=""
    if [[ "$att" == "attestation" ]]; then
        extra=',"annotations":{"vnd.docker.reference.type":"attestation-manifest"}'
    else
        extra=',"platform":{"architecture":"'$4'","os":"'$3'"}'
    fi
    printf '{"mediaType":"%s","digest":"sha256:%s","size":%s%s}' \
        "$MANIFEST_MT" "$1" "$2" "$extra"
}

rm -rf "$WORK/layout" && mkdir -p "$BLOBS"
read -r LR_D LR_S <<< "$(blob "$IMG_OUT/lower.tar")"
read -r UP_D UP_S <<< "$(blob "$IMG_OUT/upper.tar.gz")"

image_manifest() { # image_manifest <os> <arch> <layer descriptors JSON> → "<digest> <size>"
    printf '{"architecture":"%s","os":"%s","rootfs":{"type":"layers"}}' "$2" "$1" > "$WORK/config.json"
    read -r CFG_D CFG_S <<< "$(blob "$WORK/config.json")"
    printf '{"schemaVersion":2,"mediaType":"%s","config":{"mediaType":"%s","digest":"sha256:%s","size":%s},"layers":[%s]}' \
        "$MANIFEST_MT" "$CONFIG_MT" "$CFG_D" "$CFG_S" "$3" > "$WORK/manifest.json"
    blob "$WORK/manifest.json"
}
LAYER_PLAIN_DESC=$(printf '{"mediaType":"%s","digest":"sha256:%s","size":%s}' "$LAYER_PLAIN_MT" "$LR_D" "$LR_S")
LAYER_GZ_DESC=$(printf '{"mediaType":"%s","digest":"sha256:%s","size":%s}' "$LAYER_GZ_MT" "$UP_D" "$UP_S")

read -r AMD_D AMD_S <<< "$(image_manifest linux amd64 "$LAYER_PLAIN_DESC,$LAYER_GZ_DESC")"
read -r ARM_D ARM_S <<< "$(image_manifest linux arm64 "$LAYER_GZ_DESC")"

# The MAIN archive is a multi-arch index with arm64 FIRST and an attestation
# companion: import must still select the amd64 manifest.
write_index "$IMG_OUT/amd64.tar.gz" \
    "$(manifest_entry "$ARM_D" "$ARM_S" linux arm64),$(manifest_entry "$ARM_D" "$ARM_S" linux arm64 attestation),$(manifest_entry "$AMD_D" "$AMD_S" linux amd64)"
# arm64-ONLY archive (single manifest) for the platform-refusal negative.
write_index "$IMG_OUT/arm64.tar.gz" "$(manifest_entry "$ARM_D" "$ARM_S" linux arm64)"

# corrupt copy: flip a byte inside one layer blob of the multi-arch layout.
rm -rf "$WORK/layout-corrupt" && cp -a "$WORK/layout" "$WORK/layout-corrupt"
CORRUPT_BLOB=$(ls "$WORK/layout-corrupt/blobs/sha256" | head -1)
printf '\xff' | dd of="$WORK/layout-corrupt/blobs/sha256/$CORRUPT_BLOB" bs=1 seek=100 conv=notrunc status=none
tar -C "$WORK/layout-corrupt" -czf "$IMG_OUT/corrupt.tar.gz" oci-layout index.json blobs

# legacy docker save (manifest.json, no OCI layout) + plain rootfs tar.
printf '[{"Config":"x.json","RepoTags":[],"Layers":[]}]' > "$WORK/legacy-manifest.json"
tar -C "$WORK" -czf "$IMG_OUT/legacy.tar.gz" legacy-manifest.json --transform 's|legacy-manifest.json|manifest.json|'
(cd "$OUTPUT/rootfs-template" && tar -C . -czf "$IMG_OUT/rootfs.tar.gz" .)
log_pass "synthetic archives built (multi-arch amd64 [plain+gzip layers], arm64-only, corrupt, legacy, rootfs tar)"

# ══════════════════════════════════════════════════════════════════
log_section "Phase 2: Offline import — negatives first (no stack yet)"
# ══════════════════════════════════════════════════════════════════
neg_refused() { # neg_refused <desc> <expected-substring> <archive>
    local desc="$1" want="$2" archive="$3"
    local out_dir
    out_dir=$(mktemp -d "$WORK/neg-XXXXXX")
    if "$IMPORT" import "$archive" --name neg --version v1 --out "$out_dir" >"$WORK/neg.log" 2>&1; then
        fail "$desc: import SUCCEEDED (wanted refusal mentioning '$want')"
    elif grep -q "$want" "$WORK/neg.log"; then
        pass "$desc: refused as expected"
    else
        fail "$desc: wrong refusal — wanted '$want', got: $(head -c 200 "$WORK/neg.log")"
    fi
    if [[ -e "$out_dir/neg" ]]; then
        fail "$desc: failed import left a name directory behind"
    fi
}
# The arm64 archive refuses either at index selection ("carries no
# linux/amd64 manifest") or at the config platform check ("image is
# linux/arm64 …") — both name the offending architecture.
neg_refused "arm64 archive"      "arm64"              "$IMG_OUT/arm64.tar.gz"
neg_refused "legacy docker save" "legacy docker-save" "$IMG_OUT/legacy.tar.gz"
# Corrupt archive: whichever check fires (gzip framing or digest), the run
# must fail and leave nothing behind.
CORRUPT_OUT=$(mktemp -d "$WORK/neg-XXXXXX")
if "$IMPORT" import "$IMG_OUT/corrupt.tar.gz" --name neg --version v1 --out "$CORRUPT_OUT" >"$WORK/neg.log" 2>&1; then
    fail "corrupt blob: import SUCCEEDED"
elif [[ -e "$CORRUPT_OUT/neg" ]]; then
    fail "corrupt blob: failed import left a name directory behind"
else
    pass "corrupt blob: refused, nothing published"
fi
log_step "negatives: platform/corruption/legacy refusals checked"

# ══════════════════════════════════════════════════════════════════
log_section "Phase 3: Import into the flat scan root + template store"
# ══════════════════════════════════════════════════════════════════
# The store scan root must be the shared setgid dir the prov role writes refs into.
ss_prepare_shared_dir "$TPL_DIR"

if "$IMPORT" import "$IMG_OUT/amd64.tar.gz" --name convimg --version v1 --out "$FLAT_DIR" >"$WORK/flat-import.log" 2>&1; then
    pass "flat import published $FLAT_DIR/convimg/v1"
else
    fail "flat import failed: $(head -c 300 "$WORK/flat-import.log")"
fi
if "$IMPORT" import "$IMG_OUT/amd64.tar.gz" --name convimg --version v1 --out "$FLAT_DIR" >"$WORK/imm.log" 2>&1; then
    fail "re-import over an existing version SUCCEEDED — refs must be immutable"
elif grep -q "immutable" "$WORK/imm.log"; then
    pass "re-import refused (refs are immutable)"
else
    fail "re-import refusal did not mention immutability: $(head -c 200 "$WORK/imm.log")"
fi
if "$IMPORT" import "$IMG_OUT/amd64.tar.gz" --name convimg --version v2 --out "$TPL_DIR" >"$WORK/tpl-import.log" 2>&1; then
    pass "overlay-store import published $TPL_DIR/convimg/v2"
else
    fail "overlay-store import failed: $(head -c 300 "$WORK/tpl-import.log")"
fi
if "$IMPORT" import "$IMG_OUT/rootfs.tar.gz" --name convroot --version v1 --out "$FLAT_DIR" >"$WORK/root-import.log" 2>&1; then
    pass "rootfs-tar import published $FLAT_DIR/convroot/v1"
else
    fail "rootfs-tar import failed: $(head -c 300 "$WORK/root-import.log")"
fi

for t in "$FLAT_DIR/convimg/v1" "$FLAT_DIR/convroot/v1" "$TPL_DIR/convimg/v2"; do
    if "$IMPORT" validate "$t" >"$WORK/validate.log" 2>&1; then
        pass "template-tool validate clean: $t"
    else
        fail "validate failed for $t: $(head -c 300 "$WORK/validate.log")"
    fi
done
# Host-side spot checks of the merge semantics before the guest legs.
# Existence gate first: if the tree is missing, every [[ ! -e ]] assert below
# would pass VACUOUSLY — fail loudly instead.
T="$FLAT_DIR/convimg/v1"
[[ -d "$T" ]] && pass "imported tree published at $T" || fail "imported tree missing at $T (spot checks below would be vacuous)"
[[ ! -e "$T/opt/wh-target" ]] && pass "whiteout removed opt/wh-target (host)" || fail "wh-target survived (host)"
[[ ! -e "$T/opt/whdir/old" ]] && pass "opaque dir hid opt/whdir/old (host)" || fail "opaque failed (host)"
[[ ! -e "$T/opt/pkg" ]] && pass "directory whiteout removed opt/pkg (host)" || fail "opt/pkg survived (host)"
[[ ! -e "$T/opt/dev-tgt" ]] && pass "legacy 0/0 device whiteout removed opt/dev-tgt (host)" || fail "opt/dev-tgt survived (host)"
[[ "$(stat -c%a "$T/bin/su")" == "4755" ]] && pass "setuid 4755 preserved (host)" || fail "setuid lost (host)"
[[ "$(cat "$T/opt/flip2/y")" == "y" ]] && pass "file→dir transition applied (host)" || fail "file→dir failed (host)"
[[ "$(cat "$T/opt/typeflip")" == "now-a-file" ]] && pass "dir→file transition applied (host)" || fail "dir→file failed (host)"
# The masking counterexample: the upper REAL dir a masks the lower symlink
# a→b; its .wh.c is a NO-OP for /b/c (chroot-style resolution would delete
# the wrong file).
[[ "$(cat "$T/b/c")" == "keep" ]] && pass "masked-symlink whiteout is a no-op: /b/c survives (host)" || fail "whiteout deleted /b/c through the masked symlink (host)"
[[ -d "$T/a" && ! -e "$T/a/c" ]] && pass "upper dir a masks the lower symlink, no victim materialized (host)" || fail "masking shape wrong (host)"
[[ ! -e "$T/.sandfs-id" ]] && pass "volume control file stripped (host)" || fail ".sandfs-id survived (host)"
if find "$T" -name '.wh.*' -print -quit | grep -q .; then
    fail "whiteout markers materialized in the template"
else
    pass "whiteout markers never materialize (metadata applied, not content)"
fi

# ══════════════════════════════════════════════════════════════════
log_section "Phase 4: Start stack"
# ══════════════════════════════════════════════════════════════════
tc_clean_environment
if [[ "$NETWORK_BACKEND" == "bridge" ]]; then
    tc_setup_host_network
fi
CERT_DIR="${CERT_DIR:-$DEPLOY_DIR/certs}"
tc_gen_certs
tc_attach_vsockguard
tc_start_gateway
export TC_FLAT_TEMPLATES="$FLAT_DIR"
tc_start_sandlot -overlayfs-templates "$TPL_DIR"
tc_wait_health
log_pass "stack up (gateway + sandlot, flat root = $FLAT_DIR)"

# Guest exec goes through the shared prelude client (body escaping,
# retryable pacing) — no hand-rolled exec helpers (check-handrolled-prelude R6).
declare -A KEY2SID

guest_probe() { # guest_probe <desc> <key> <code> <want-substring> [field=stdout]
    local desc="$1" key="$2" code="$3" want="$4" field="${5:-stdout}"
    local resp got
    # An empty key/sandfs would be an invalid associative subscript; a
    # failed create must read as a failed check, not abort the suite.
    if [[ -z "$key" || -z "${KEY2SID[$key]:-}" ]]; then
        fail "$desc: no sandfs to exec against (create failed earlier)"
        return
    fi
    resp=$(tc_gw_exec_raw "$key" "${KEY2SID[$key]}" "$code" 60 3)
    got=$(echo "$resp" | tc_json_stdout)
    [[ "$field" == "stderr" ]] && got=$(echo "$resp" | tc_json_field stderr)
    if [[ "$got" == *"$want"* ]]; then
        pass "$desc"
    else
        fail "$desc: wanted '$want' in $field, got: $(echo "$resp" | head -c 200)"
    fi
}

# ══════════════════════════════════════════════════════════════════
log_section "Phase 5: Flat SandFS from the converted image"
# ══════════════════════════════════════════════════════════════════
FLAT_RESP=$(tc_create_agent_and_sandfs "conv-user" "convimg:v1" "flat")
FLAT_KEY=$(tc_json_val "$FLAT_RESP" "api_key")
FLAT_SID=$(tc_json_val "$FLAT_RESP" "sandfs_id")
# An empty key is an invalid associative subscript (and would abort under
# set -e) — only track a real create.
[[ -n "$FLAT_KEY" && -n "$FLAT_SID" ]] && KEY2SID[$FLAT_KEY]="$FLAT_SID"
if [[ -n "$FLAT_KEY" && -n "${KEY2SID[$FLAT_KEY]:-}" ]]; then
    pass "flat sandfs created from the converted template"
else
    fail "flat create failed: $(echo "$FLAT_RESP" | head -c 200)"
fi
guest_probe "5.1 whiteout: /opt/wh-target gone in guest"        "$FLAT_KEY" "test ! -e /opt/wh-target && echo gone-ok" "gone-ok"
guest_probe "5.2 opaque: /opt/whdir/old gone in guest"          "$FLAT_KEY" "test ! -e /opt/whdir/old && echo opq-ok"   "opq-ok"
guest_probe "5.3 opaque: /opt/whdir/new present in guest"       "$FLAT_KEY" "cat /opt/whdir/new"                          "new"
guest_probe "5.4 type transition dir→file in guest"             "$FLAT_KEY" "cat /opt/typeflip"                           "now-a-file"
guest_probe "5.5 directory whiteout: /opt/pkg gone in guest"    "$FLAT_KEY" "test ! -e /opt/pkg && echo pkg-ok"          "pkg-ok"
guest_probe "5.6 legacy device whiteout applied in guest"       "$FLAT_KEY" "test ! -e /opt/dev-tgt && echo dev-ok"      "dev-ok"
guest_probe "5.7 type transition file→dir in guest"             "$FLAT_KEY" "cat /opt/flip2/y"                            "y"
# 5.8/5.9 pin the FLAT materialization policy, not a platform bug: a flat volume
# is a private writable copy, and copyfs deliberately rewrites file modes to
# group-writable/other-invisible and strips setuid ((0755 &^ 007) | 660 = 0770).
# The setuid bit's survival is asserted on the OVERLAY leg (6.5), where the
# imported tree is served read-only as-is.
guest_probe "5.8 flat copy applies the volume mode policy"       "$FLAT_KEY" "stat -c %a /bin/su"                          "770"
guest_probe "5.9 absolute symlink is tree-relative in guest"    "$FLAT_KEY" "readlink /abslink | grep -v '^/' && echo rel-ok" "rel-ok"
guest_probe "5.10 masked-symlink whiteout is a no-op (/b/c)"    "$FLAT_KEY" "cat /b/c"                                    "keep"
guest_probe "5.11 upper dir masks the lower symlink"            "$FLAT_KEY" "test -d /a && test ! -e /a/c && echo mask-ok" "mask-ok"
# 5.12: the TEMPLATE must not carry control-file content — but a flat volume
# legitimately writes its OWN .sandfs-id identity stamp at its root, so
# asserting absence would be wrong. Assert the tenant CONTENT never leaked
# instead (passes whether or not the volume stamp is present).
guest_probe "5.12 volume control content never leaked"          "$FLAT_KEY" "grep -q tenant /.sandfs-id 2>/dev/null && echo LEAKED || echo ctrl-ok" "ctrl-ok"

# ══════════════════════════════════════════════════════════════════
log_section "Phase 6: Overlay SandFS from the store-registered import"
# ══════════════════════════════════════════════════════════════════
OV_RESP=$(tc_create_agent_and_sandfs "conv-ov-user" "convimg:v2" "overlay")
OV_KEY=$(tc_json_val "$OV_RESP" "api_key")
OV_SID=$(tc_json_val "$OV_RESP" "sandfs_id")
[[ -n "$OV_KEY" && -n "$OV_SID" ]] && KEY2SID[$OV_KEY]="$OV_SID"
if [[ -n "$OV_KEY" && -n "${KEY2SID[$OV_KEY]:-}" ]]; then
    pass "overlay sandfs created from the store-registered import"
else
    fail "overlay create failed: $(echo "$OV_RESP" | head -c 200)"
fi
guest_probe "6.1 overlay exec works (shell resolves)"           "$OV_KEY" "echo ov-ok"                                 "ov-ok"
guest_probe "6.2 overlay base is read-only"                     "$OV_KEY" "echo x > /opt/ro-test 2>&1 || echo denied"  "denied"
guest_probe "6.3 overlay whiteout applied"                      "$OV_KEY" "test ! -e /opt/wh-target && echo wh-ok"     "wh-ok"
guest_probe "6.4 workspace write persists"                      "$OV_KEY" "echo hi > /workspace/w.txt && cat /workspace/w.txt" "hi"
guest_probe "6.5 setuid bit survives on the read-only base"     "$OV_KEY" "stat -c %a /bin/su"                          "4755"

# ══════════════════════════════════════════════════════════════════
log_section "Phase 7: Plain rootfs tar (docker export shape)"
# ══════════════════════════════════════════════════════════════════
RT_RESP=$(tc_create_agent_and_sandfs "conv-root-user" "convroot:v1" "flat")
RT_KEY=$(tc_json_val "$RT_RESP" "api_key")
RT_SID=$(tc_json_val "$RT_RESP" "sandfs_id")
[[ -n "$RT_KEY" && -n "$RT_SID" ]] && KEY2SID[$RT_KEY]="$RT_SID"
if [[ -n "$RT_KEY" && -n "${KEY2SID[$RT_KEY]:-}" ]]; then
    pass "flat sandfs created from the rootfs-tar template"
else
    fail "rootfs-tar create failed: $(echo "$RT_RESP" | head -c 200)"
fi
guest_probe "7.1 rootfs-tar template execs"                     "$RT_KEY" "echo root-ok"                              "root-ok"

# ══════════════════════════════════════════════════════════════════
log_section "Verdict"
# ══════════════════════════════════════════════════════════════════
if [[ "$FAIL_COUNT" -eq 0 ]]; then
    log_pass "ALL $PASS_COUNT checks passed — OCI image → template conversion serves both modes"
else
    log_error "$FAIL_COUNT check(s) failed"
fi
exit $((FAIL_COUNT > 0))

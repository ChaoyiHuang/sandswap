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
#   6. The group side of the contract: import settles the published
#      tree's group (numeric --group used as-is cross-host, name resolved
#      on this host, default = the --out root's gid) with the setuid bit
#      preserved, the reliant-entry warning, validate --expect-group
#      (match / foreign-gid error carrying the chgrp fix / unresolvable
#      name), the push-only + --group refusal, check-store's group
#      audit (layers/ against the store root's group, writer-internal
#      staging never judged, in-store template trees audited,
#      --expect-group catching a whole store moved from a
#      differently-numbered host), validate over a setgid SCAN ROOT
#      (inheritance makes the settle a no-op; both leaves audited;
#      unconsumed top-level dot dirs ignored), and the NON-OWNER audit: a
#      non-member reports an unlistable subtree exactly once and exits 1,
#      while the owner's audit of the same tree is clean.
#   7. The attach-critical skeleton on a STOCK-image archive: the fixture
#      deliberately drops home/agent (empty home/, nothing under it — the
#      shape every distro image has). The import must create it (the
#      overlay attach binds the volume's home/ onto <rootfs>/home/agent and
#      cannot mkdir it on a read-only root), validate must reject a tree
#      that lacks it (the directly-registered-local-directory path is never
#      healed), and the overlay leg must mount and use it as HOME.
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
# Stock-image shape (item 7): the busybox base carries home/agent, a real
# OCI image does not — empty home/, nothing under it. Drop it so the archive
# genuinely lacks the overlay attach's home bind target and the import has
# to create it; every home/agent assert below is vacuous without this.
rm -rf "$WORK/lower/home/agent"
[[ -d "$WORK/lower/home" && ! -e "$WORK/lower/home/agent" ]] || { log_error "fixture: expected an empty home/ after dropping home/agent"; exit 1; }
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

# Attach-critical skeleton on the stock-image archive (item 7): home/agent
# must be CREATED by the import (reported as a created skeleton dir) and be a
# real directory in every published tree — the warden's overlay attach binds
# the volume's home/ onto <rootfs>/home/agent and cannot mkdir it on a
# read-only root, so a missing one failed EVERY attach ("home mount target
# could not be secured"), each failure destroying a pool VM.
for logf in flat-import.log tpl-import.log; do
    if grep -q "created missing skeleton directories:.*home/agent" "$WORK/$logf"; then
        pass "import created home/agent ($logf)"
    else
        fail "import did not report creating home/agent: $(grep -i skeleton "$WORK/$logf" | head -c 200)"
    fi
done
for t in "$FLAT_DIR/convimg/v1" "$TPL_DIR/convimg/v2"; do
    if [[ -d "$t/home/agent" && ! -L "$t/home/agent" ]]; then
        pass "published tree carries home/agent as a real directory: $t"
    else
        fail "home/agent missing or not a real directory in $t"
    fi
done
# The negative: a tree that lacks it must NOT pass the gate. A directory
# registered directly as a local template (the scan-root shape) is never
# healed by any import path, so validate is the only thing standing between
# such a tree and a pool-eating attach.
rm -rf "$WORK/noagent" && cp -a "$T" "$WORK/noagent" && rmdir "$WORK/noagent/home/agent"
if "$IMPORT" validate "$WORK/noagent" >"$WORK/noagent.log" 2>&1; then
    fail "validate ACCEPTED a tree without home/agent (every attach would fail)"
elif grep -q "home/agent" "$WORK/noagent.log" && grep -qi "error" "$WORK/noagent.log"; then
    pass "validate rejects a tree without home/agent, naming it"
else
    fail "validate refusal for the no-home/agent tree did not name it: $(head -c 300 "$WORK/noagent.log")"
fi
# And the mkdir-on-ENOENT repair the warden attempts cannot be relied on
# either: the same tree, registered as a flat template, is mountable (flat
# binds the whole volume) but HOME would point at nothing. validate is what
# catches it regardless of mode.
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
log_section "Phase 3b: Group grant — settle + offline audit (host-side)"
# ══════════════════════════════════════════════════════════════════
# The main fixture above is deliberately world-readable (zero entries ride
# the group grant — the tree's gid never participates in its serving), so a
# dedicated archive carries the reliant shapes real distro images have:
# /root 0700 and /etc/shadow 0640 (reliant: a file without other-read, a directory without other-list/traverse)
# plus a setuid file to prove the settle pass preserves the special bits.
# Everything here is host-side template-tool work; the stack legs below
# keep serving the world-readable trees.
rm -rf "$WORK/gtree" && mkdir -p "$WORK/gtree/root" "$WORK/gtree/etc"
cp -a "$OUTPUT/rootfs-template/." "$WORK/gtree/"
echo 'root:*:0:0:root:/root:/bin/sh' > "$WORK/gtree/etc/shadow"
echo su-body > "$WORK/gtree/bin/su"
chmod 0700 "$WORK/gtree/root"
chmod 0640 "$WORK/gtree/etc/shadow"
chmod 4755 "$WORK/gtree/bin/su"
pack_layer "$WORK/gtree" "$IMG_OUT/group-layer.tar.gz"
read -r GR_D GR_S <<< "$(blob "$IMG_OUT/group-layer.tar.gz")"
GRP_DESC=$(printf '{"mediaType":"%s","digest":"sha256:%s","size":%s}' "$LAYER_GZ_MT" "$GR_D" "$GR_S")
read -r GRP_D GRP_S <<< "$(image_manifest linux amd64 "$GRP_DESC")"
write_index "$IMG_OUT/group.tar.gz" "$(manifest_entry "$GRP_D" "$GRP_S" linux amd64)"
log_step "group-fixture archive built (reliant: /root 0700, /etc/shadow 0640; setuid /bin/su 4755)"

# Cross-host numeric form: gid 4242 exists as no local group anywhere —
# the NUMBER is the contract, and the import must use it as-is.
GOUT=$(mktemp -d "$WORK/grp-XXXXXX")
if "$IMPORT" import "$IMG_OUT/group.tar.gz" --name gtest --version v1 --out "$GOUT" --group 4242 >"$WORK/grp-import.log" 2>&1; then
    pass "import --group 4242 (numeric, no local group of that number) published"
else
    fail "import --group 4242 failed: $(head -c 300 "$WORK/grp-import.log")"
fi
grep -q "rely on the group grant" "$WORK/grp-import.log" && pass "import warns about the group-grant-reliant entries" || fail "reliant-entry warning missing from the import output"
for p in root etc/shadow bin/su; do
    [[ "$(stat -c%g "$GOUT/gtest/v1/$p")" == 4242 ]] && pass "group settle reached $p (gid 4242)" || fail "$p gid is $(stat -c%g "$GOUT/gtest/v1/$p" 2>/dev/null), want 4242"
done
[[ "$(stat -c%a "$GOUT/gtest/v1/bin/su")" == "4755" ]] && pass "setuid bit survives the group settle" || fail "setuid lost across the settle: $(stat -c%a "$GOUT/gtest/v1/bin/su" 2>/dev/null)"

if "$IMPORT" validate "$GOUT/gtest/v1" --expect-group 4242 >"$WORK/grp-val.log" 2>&1; then
    pass "validate --expect-group 4242 passes on the settled tree"
else
    fail "validate --expect-group 4242 failed: $(head -c 300 "$WORK/grp-val.log")"
fi
if "$IMPORT" validate "$GOUT/gtest/v1" --expect-group 0 >"$WORK/grp-valbad.log" 2>&1; then
    fail "validate --expect-group 0 (foreign gid) SUCCEEDED"
elif grep -q "chgrp -R" "$WORK/grp-valbad.log"; then
    pass "foreign expected gid errors with the manual chgrp -R fix"
else
    fail "foreign-gid refusal carries no fix hint: $(head -c 200 "$WORK/grp-valbad.log")"
fi
if "$IMPORT" validate "$GOUT/gtest/v1" --expect-group no-such-group-xyz >"$WORK/grp-name.log" 2>&1; then
    fail "unresolvable group name accepted by validate"
elif grep -q "does not resolve" "$WORK/grp-name.log"; then
    pass "unresolvable group name refuses with the numeric-gid hint"
else
    fail "unresolvable-name refusal text: $(head -c 200 "$WORK/grp-name.log")"
fi

# Name form and the default (the --out root's gid): two more publishes.
GNAME_OUT=$(mktemp -d "$WORK/grpname-XXXXXX")
if "$IMPORT" import "$IMG_OUT/group.tar.gz" --name gname --version v1 --out "$GNAME_OUT" --group root >"$WORK/grpn-import.log" 2>&1 \
    && "$IMPORT" validate "$GNAME_OUT/gname/v1" --expect-group root >"$WORK/grpn-val.log" 2>&1; then
    pass "name form: --group root settles, --expect-group root passes"
else
    fail "name form failed: $(head -c 200 "$WORK/grpn-import.log")$(head -c 200 "$WORK/grpn-val.log")"
fi
GDEF_OUT=$(mktemp -d "$WORK/grpdef-XXXXXX")
GDEF_GID=$(stat -c%g "$GDEF_OUT")
if "$IMPORT" import "$IMG_OUT/group.tar.gz" --name gdef --version v1 --out "$GDEF_OUT" >"$WORK/grpd-import.log" 2>&1; then
    pass "default-settle import published (no --group)"
else
    fail "default-settle import failed: $(head -c 300 "$WORK/grpd-import.log")"
fi
[[ "$(stat -c%g "$GDEF_OUT/gdef/v1/etc/shadow")" == "$GDEF_GID" ]] && pass "default settle lands the --out root's gid on reliant entries" || fail "reliant entry gid $(stat -c%g "$GDEF_OUT/gdef/v1/etc/shadow" 2>/dev/null) != out root gid $GDEF_GID"
# A private, non-setgid --out root is exactly the flow whose group does not
# survive a later copy into the shared scan root — the import must say so.
grep -q "is not setgid" "$WORK/grpd-import.log" && pass "non-setgid --out root earns the copy-does-not-preserve-group warning" || fail "non-setgid --out warning missing: $(head -c 300 "$WORK/grpd-import.log")"

# The one registry-mode corner the CLI must refuse: --group with no --out
# (a push-only run materializes no local tree, so there is nothing to
# settle). The refusal is validated before any network contact.
if "$IMPORT" import "$IMG_OUT/group.tar.gz" --name gpush --version v1 --push localhost:1/nope --group 4242 >"$WORK/grp-push.log" 2>&1; then
    fail "push-only import with --group SUCCEEDED"
elif grep -q "group requires out" "$WORK/grp-push.log"; then
    pass "push-only + --group refused (nothing local to settle)"
else
    fail "push-only + --group refusal text: $(head -c 200 "$WORK/grp-push.log")"
fi

# check-store audits layers/ against the STORE ROOT's group. A scratch
# store (refs/ + layers/) mirrors the deployment shape: the shared group
# when the identities exist, root otherwise.
GSTORE=$(mktemp -d "$WORK/grpstore-XXXXXX")
GSTORE_GID=0
if getent group "$SS_SHARED_GROUP" >/dev/null 2>&1; then
    GSTORE_GID=$(getent group "$SS_SHARED_GROUP" | cut -d: -f3)
    chgrp "$GSTORE_GID" "$GSTORE"
fi
mkdir -p "$GSTORE/refs" "$GSTORE/layers/local-gaudit-v1/etc"
echo secret > "$GSTORE/layers/local-gaudit-v1/etc/shadow"
chmod 0640 "$GSTORE/layers/local-gaudit-v1/etc/shadow"
chgrp "$((GSTORE_GID + 1))" "$GSTORE/layers/local-gaudit-v1/etc/shadow"
if "$IMPORT" check-store "$GSTORE" >"$WORK/grpstore-bad.log" 2>&1; then
    fail "check-store passed a foreign-gid reliant layer entry"
elif grep -q "relies on the group grant" "$WORK/grpstore-bad.log"; then
    pass "check-store flags the foreign-gid reliant entry (against the store root's group)"
else
    fail "check-store refusal text: $(head -c 300 "$WORK/grpstore-bad.log")"
fi
chgrp -R "$GSTORE_GID" "$GSTORE"
if "$IMPORT" check-store "$GSTORE" >"$WORK/grpstore-ok.log" 2>&1; then
    pass "check-store clean after the re-settle"
else
    fail "check-store still failing after the re-settle: $(head -c 300 "$WORK/grpstore-ok.log")"
fi

# check-store must never judge writer-internal staging: a pull in flight
# keeps its layer under .<layer>.staging-* until the writer has settled it,
# so a foreign gid there is mid-flight state, not a defect. The SAME wrong
# gid in a published layer IS a finding (asserted above).
mkdir -p "$GSTORE/layers/.local-gaudit-v1.staging-123/etc"
echo midflight > "$GSTORE/layers/.local-gaudit-v1.staging-123/etc/shadow"
chmod 0640 "$GSTORE/layers/.local-gaudit-v1.staging-123/etc/shadow"
chgrp "$((GSTORE_GID + 1))" "$GSTORE/layers/.local-gaudit-v1.staging-123/etc/shadow"
if "$IMPORT" check-store "$GSTORE" >"$WORK/grpstore-stg.log" 2>&1; then
    pass "check-store skips writer-internal staging (foreign gid there is mid-flight)"
elif grep -q "group-grant" "$WORK/grpstore-stg.log"; then
    fail "check-store judged writer-internal staging: $(grep -A1 'group-grant' "$WORK/grpstore-stg.log" | head -2)"
else
    fail "check-store with staging present failed for another reason: $(head -c 300 "$WORK/grpstore-stg.log")"
fi
rm -rf "$GSTORE/layers/.local-gaudit-v1.staging-123"

# A template tree registered INSIDE the store outside layers/ (the
# `import --out <store>` shape) is served like a layer tree: its group is
# audited too. An OUTSIDE flat scan-root tree is NOT judged (its group may
# legitimately differ per root — `validate --expect-group` covers it).
mkdir -p "$GSTORE/inplace/v1/etc"
echo secret > "$GSTORE/inplace/v1/etc/shadow"
chmod 0640 "$GSTORE/inplace/v1/etc/shadow"
chgrp -R "$GSTORE_GID" "$GSTORE/inplace"
chgrp "$((GSTORE_GID + 1))" "$GSTORE/inplace/v1/etc/shadow"
printf '{"name":"inplace","version":"v1","mode":"flat","layers":["%s"]}' "$GSTORE/inplace/v1" \
    > "$GSTORE/refs/inplace_v1.flat.json"
if "$IMPORT" check-store "$GSTORE" >"$WORK/grpstore-tree-bad.log" 2>&1; then
    fail "check-store passed a foreign-gid reliant entry in an in-store template tree"
elif grep -q "template tree .*inplace/v1.*relies on the group grant" "$WORK/grpstore-tree-bad.log"; then
    pass "check-store audits in-store template trees (import --out <store> shape)"
else
    fail "in-store tree audit text: $(head -c 300 "$WORK/grpstore-tree-bad.log")"
fi
chgrp -R "$GSTORE_GID" "$GSTORE/inplace"
if "$IMPORT" check-store "$GSTORE" >"$WORK/grpstore-tree-ok.log" 2>&1; then
    pass "in-store tree clean after the re-settle"
else
    fail "in-store tree still failing: $(head -c 300 "$WORK/grpstore-tree-ok.log")"
fi

# Cross-host: --expect-group supplies the TARGET deployment's number. A
# store internally consistent on its own gid is unreachable for consumers
# carrying another — only the external number catches it.
if "$IMPORT" check-store "$GSTORE" --expect-group "$((GSTORE_GID + 7))" >"$WORK/grpstore-xhost.log" 2>&1; then
    fail "check-store --expect-group (foreign) passed an internally consistent store"
elif grep -q "store root carries gid" "$WORK/grpstore-xhost.log"; then
    pass "check-store --expect-group flags the store root carrying a foreign group (cross-host)"
else
    fail "cross-host refusal text: $(head -c 300 "$WORK/grpstore-xhost.log")"
fi
if "$IMPORT" check-store "$GSTORE" --expect-group "$GSTORE_GID" >"$WORK/grpstore-xhost-ok.log" 2>&1; then
    pass "check-store --expect-group matching the store's own group is clean"
else
    fail "matching --expect-group failed: $(head -c 300 "$WORK/grpstore-xhost-ok.log")"
fi
if getent group "$SS_SHARED_GROUP" >/dev/null 2>&1; then
    if "$IMPORT" check-store "$GSTORE" --expect-group "$SS_SHARED_GROUP" >"$WORK/grpstore-xhost-name.log" 2>&1; then
        pass "check-store --expect-group accepts a group NAME (resolved on this host)"
    else
        fail "check-store --expect-group by name failed: $(head -c 300 "$WORK/grpstore-xhost-name.log")"
    fi
fi

# ── validate over a SCAN ROOT (the deployment shape: a setgid shared
# root holding <name>/<version> trees) ────────────────────────────────
# Publishing straight into the scan root is the recommended flow; the
# audit over the root must cover every leaf and the root itself (2750 =
# reliant, gid = shared) while ignoring the <name>/ containers (2755).
GSCAN=$(mktemp -d "$WORK/grpscan-XXXXXX")
chmod 0755 "$GSCAN"
GSCAN_ROOT="$GSCAN/scan"
ss_prepare_shared_dir "$GSCAN_ROOT"
GSCAN_GID=$(stat -c%g "$GSCAN_ROOT")
for v in v1 v2; do
    if "$IMPORT" import "$IMG_OUT/group.tar.gz" --name gscan --version "$v" --out "$GSCAN_ROOT" >"$WORK/grpscan-$v.log" 2>&1; then
        pass "scan-root publish gscan:$v (default settle = root gid $GSCAN_GID, no --group)"
    else
        fail "scan-root publish gscan:$v failed: $(head -c 300 "$WORK/grpscan-$v.log")"
    fi
done
# The scan root is a setgid shared dir, so the published trees must have
# inherited the group at creation: the default settle is a no-op (0 changed)
# and every reliant entry already carries the root's gid.
if grep -q "settled the tree's group" "$WORK/grpscan-v1.log"; then
    fail "setgid scan root publish still needed a settle — inheritance is broken"
else
    pass "setgid scan root: trees inherit the group, settle is a no-op"
fi
[[ "$(stat -c%g "$GSCAN_ROOT/gscan/v1/root")" == "$GSCAN_GID" ]] && pass "reliant entry inherited the scan root's gid" || fail "reliant entry gid $(stat -c%g "$GSCAN_ROOT/gscan/v1/root"), want $GSCAN_GID"
# A top-level dot directory is not consumed by the registration scan, so its
# group must not be judged at all (a root-owned 0700 .junk would otherwise
# fail the audit on a perfectly healthy scan root).
mkdir -p "$GSCAN_ROOT/.junk" && chmod 0700 "$GSCAN_ROOT/.junk"
if "$IMPORT" validate "$GSCAN_ROOT" --expect-group "$GSCAN_GID" >"$WORK/grpscan-val.log" 2>&1; then
    pass "validate --expect-group over the scan root passes (every leaf + the root; unconsumed .junk ignored)"
else
    fail "validate --expect-group over the scan root failed: $(head -c 300 "$WORK/grpscan-val.log")"
fi
rmdir "$GSCAN_ROOT/.junk" 2>/dev/null || rm -rf "$GSCAN_ROOT/.junk"
# Numeric form: the same root audited against a gid the publisher is NOT a
# member of must report the reliant entries — the cross-host audit case.
if "$IMPORT" validate "$GSCAN_ROOT" --expect-group 4242 >"$WORK/grpscan-bad.log" 2>&1; then
    fail "validate --expect-group 4242 over the scan root SUCCEEDED (every leaf is $GSCAN_GID)"
elif [[ "$(grep -c 'relies on the group grant' "$WORK/grpscan-bad.log")" -ge 4 ]]; then
    pass "validate --expect-group 4242 over the scan root flags both leaves (reliant entries)"
else
    fail "scan-root foreign-gid audit under-reported: $(head -c 300 "$WORK/grpscan-bad.log")"
fi

# ── Non-owner audit: the identity running validate is not the owner ──
# A real distro tree carries a 0750 root:root /root. A non-member cannot
# list it. The audit must REPORT that subtree (unreadable — the contract
# below it is unjudged) and still exit 1, instead of dying with a bare
# "permission denied" that tells the operator nothing about the tree.
# Nobody (65534) is on every Linux host; it is not in the root group.
GOWN=$(mktemp -d "$WORK/grpown-XXXXXX")
chmod 0755 "$GOWN"
if "$IMPORT" import "$IMG_OUT/group.tar.gz" --name gown --version v1 --out "$GOWN" --group 0 >"$WORK/grpown-import.log" 2>&1; then
    pass "root-owned tree published for the non-owner audit leg"
else
    fail "root-owned tree publish failed: $(head -c 300 "$WORK/grpown-import.log")"
fi
chmod 0755 "$GOWN/gown" "$GOWN/gown/v1"
# nobody validates root's tree: expect the tree's own gid (0) so the
# reachable part is fully judged; the /root subtree is the one it cannot see.
if setpriv --reuid=65534 --regid=65534 --clear-groups -- "$IMPORT" validate "$GOWN/gown/v1" --expect-group 0 >"$WORK/grpown-val.log" 2>&1; then
    fail "non-owner validate SUCCEEDED on a tree it cannot fully inspect"
elif grep -q "cannot be inspected by this identity" "$WORK/grpown-val.log" && grep -q "/root$" "$WORK/grpown-val.log"; then
    if [[ "$(grep -c 'cannot be inspected' "$WORK/grpown-val.log")" -eq 1 ]]; then
        pass "non-owner validate reports the unreadable /root exactly once and exits 1"
    else
        fail "non-owner validate repeated the unreadable finding: $(grep -c 'cannot be inspected' "$WORK/grpown-val.log")"
    fi
else
    fail "non-owner validate did not produce the unreadable finding: $(head -c 300 "$WORK/grpown-val.log")"
fi
# The owner (root) sees the whole tree: zero unreadable findings, and the
# audit is clean because import settled it to gid 0.
if "$IMPORT" validate "$GOWN/gown/v1" --expect-group 0 >"$WORK/grpown-root.log" 2>&1; then
    pass "owner validate of the same tree is clean (unreadable finding is identity-specific)"
else
    fail "owner validate failed: $(head -c 300 "$WORK/grpown-root.log")"
fi
log_step "group grant: numeric/name/default settle, offline audit, store audit (layers + in-store trees + cross-host), scan root, non-owner audit"

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
# 6.6–6.8 (item 7): the archive had no home/agent; the import created it and
# the attach binds the volume's home/ onto it. It must be the writable HOME
# and persist across execs like workspace/.
guest_probe "6.6 home/agent exists and is writable"             "$OV_KEY" "test -d /home/agent && touch /home/agent/.h && echo home-ok" "home-ok"
guest_probe "6.7 HOME is /home/agent"                           "$OV_KEY" "echo \$HOME"                                "/home/agent"
guest_probe "6.8 home/agent write persists across execs"        "$OV_KEY" "test -e /home/agent/.h && echo home-persist"    "home-persist"

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

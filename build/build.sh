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
# build.sh — Build all sandswap artifacts in one command.
# Usage:
#   ./build.sh                # Build everything (then verify freshness)
#   ./build.sh kernel         # Build only the kernel
#   ./build.sh warden         # Build only the in-VM warden
#   ./build.sh initramfs      # Build warden + initramfs
#   ./build.sh vmm            # Build only the VMM
#   ./build.sh go             # Build gateway + sandlot
#   ./build.sh examples       # Build examples (openai/eino/keepalive-sandswap + loadgen)
#   ./build.sh check          # Verify output/ artifacts are newer than source (no build)
# Freshness guarantee: `build.sh all` rebuilds every component in dependency
# order and then runs verify_freshness, which fails the build if any artifact
# is older than its newest source file. This guarantees the test runs freshly
# compiled code — never stale binaries left over from a partial build.
# Host networking (for microVM outbound access with --network-backend=bridge):
# run `deploy/setup-network.sh` once per host to create the bridge + NAT.
# build.sh does NOT run it automatically — it is an ops step.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# sudo resets PATH (secure_path), dropping the standard toolchain install
# locations — a root-run deploy would report cargo/go as "missing" although
# they are installed. Prepend the well-known dirs when absent.
#
# /usr/local/cargo/bin is deliberately NOT prepended: install-deps exposes the
# toolchain through /usr/local/bin (cargo/rustc symlinks and a rustup wrapper
# that carries RUSTUP_HOME). Prepending the raw cargo dir would shadow the
# wrapper with the bare rustup binary, whose per-user RUSTUP_HOME is empty.
for pdir in /usr/local/go/bin "${HOME:-/root}/.cargo/bin"; do
    if [[ -d "$pdir" ]] && [[ ":$PATH:" != *":$pdir:"* ]]; then
        PATH="$pdir:$PATH"
    fi
done
# The install-deps SYSTEM toolchain must WIN over a per-user rustup that sits
# earlier on PATH (CI runners preinstall one in ~/.cargo/bin: under sudo its
# HOME-based RUSTUP_HOME points at a nonexistent /root/.rustup, so the musl
# probe reads the wrong — empty — toolchain, and the warden build would link
# with it too). /usr/local/bin, never /usr/local/cargo/bin: the wrapper there
# carries RUSTUP_HOME; the raw cargo dir's bare rustup shim does not.
if [[ -x /usr/local/bin/rustup ]]; then
    PATH="/usr/local/bin:$PATH"
fi
export PATH

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

log()  { echo -e "${GREEN}[==]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[!!]${NC} $1"; exit 1; }

check_cmd() { command -v "$1" &>/dev/null || err "$1 not found — install it first"; }

# check_build_deps verifies every tool/library the build needs and, on any
# missing one, prints a one-line hint to install everything at once. This
# turns confusing mid-build failures (e.g. sandvmm link errors, a silent
# 20-byte initramfs) into a single actionable message on a fresh machine.
check_build_deps() {
    local missing=()
    for c in gcc make cargo go busybox cpio clang; do
        command -v "$c" &>/dev/null || missing+=("$c")
    done
    # bpftool needs a FUNCTIONAL probe, not an existence check: Ubuntu's
    # linux-tools wrapper (/usr/sbin/bpftool) sits on PATH but exits 2 on
    # kernels without a matching linux-tools-<ver> package (CI runners).
    if ! command -v bpftool >/dev/null 2>&1 || ! bpftool version >/dev/null 2>&1; then
        missing+=("bpftool (functional: 'bpftool version' must succeed)")
    fi
    # vmm link needs libseccomp + libcap-ng (static archive or shared lib).
    # ldconfig -p can transiently produce no output (fork/exec failure under a
    # loaded host — invisible behind 2>/dev/null), which would report an
    # installed library as missing; fall back to the well-known lib dirs
    # before declaring the dep absent.
    lib_present() {
        ldconfig -p 2>/dev/null | grep -q "$1" && return 0
        ls /usr/lib/x86_64-linux-gnu/"$1"* /lib/x86_64-linux-gnu/"$1"* >/dev/null 2>&1
    }
    if ! lib_present 'libseccomp\.so'; then missing+=("libseccomp-dev"); fi
    if ! lib_present 'libcap-ng\.so'; then missing+=("libcap-ng-dev"); fi
    # warden needs the Rust musl target. Capture the list instead of piping
    # into `grep -q`: under `set -o pipefail`, grep -q exits on the first match
    # and SIGPIPEs rustup, turning a present target into a false failure.
    if command -v rustup >/dev/null 2>&1; then
        local rust_targets
        rust_targets="$(rustup target list --installed 2>/dev/null || true)"
        case "$rust_targets" in
            *x86_64-unknown-linux-musl*) ;;
            *) missing+=("rust-musl-target") ;;
        esac
    fi
    if [[ ${#missing[@]} -gt 0 ]]; then
        err "missing build deps: ${missing[*]}
  Install all at once: sudo bash build/install-deps.sh"
    fi
}

# ── Freshness verification ─────────────────────────────────────────
#
# Every sandswap artifact in output/ must be newer than the newest source
# file it is built from. This catches the #1 source of stale-test bugs:
# editing source (e.g. warden/src/mount.rs) and recompiling only one
# component (e.g. `build.sh warden`) without re-packaging the artifacts
# that embed it (e.g. initramfs.cpio.gz) — so the test runs old code.
#
# verify_freshness compares each artifact's mtime against the newest mtime
# of its declared source set. Returns 0 if all fresh, 1 if any stale.
# Run automatically at the end of `build.sh all`, and as `build.sh check`.

YELLOW='\033[1;33m'

# newest_mtime <file|dir>... — print the newest mtime (seconds since epoch)
# among the given files/dirs (recursing into dirs), or empty if none exist.
# 'target' dirs are pruned: cargo build-script OUT dirs contain GENERATED .rs
# files whose mtime changes on every build — counting them would mark the
# artifact eternally stale.
newest_mtime() {
    find "$@" -type d -name target -prune -o -type f \
        \( -name '*.go' -o -name '*.rs' -o -name '*.proto' -o -name '*.toml' \
           -o -name '*.sh' -o -name '*.bpf.c' -o -name '*.c' -o -name '*.h' \) \
        -printf '%T@\n' 2>/dev/null | sort -rn | sed -n '1p' | cut -d. -f1
}

# mtime_of <file> — seconds since epoch, or empty if missing.
mtime_of() { [[ -e "$1" ]] && stat -c %Y "$1" 2>/dev/null || echo ""; }

# check_one <artifact> <src-file-or-dir>... — compare one artifact vs its
# sources. Prints a status line; sets global STALE_FOUND=1 if stale.
check_one() {
    local artifact="$1"; shift
    local src_newest
    src_newest=$(newest_mtime "$@")
    local art_m
    art_m=$(mtime_of "$artifact")
    if [[ -z "$art_m" ]]; then
        printf "  ${RED}[MISSING]${NC}  %-28s (not built)\n" "$artifact"
        STALE_FOUND=1
        return
    fi
    if [[ -n "$src_newest" ]] && [[ "$src_newest" -gt "$art_m" ]]; then
        printf "  ${RED}[STALE]${NC}    %-28s (artifact %s < source %s)\n" \
            "$artifact" "$(date -d @"$art_m" +%H:%M:%S)" "$(date -d @"$src_newest" +%H:%M:%S)"
        STALE_FOUND=1
    else
        printf "  ${GREEN}[FRESH]${NC}   %-28s\n" "$artifact"
    fi
}

verify_freshness() {
    log "Verifying artifact freshness (output vs source)..."
    STALE_FOUND=0

    # gateway: all Go sources under gateway/ + shared proto in common/
    check_one "$ROOT/output/gateway" \
        "$ROOT/gateway" "$ROOT/common/proto"

    # sandlot: all Go sources under sandlot/ + shared proto in common/
    check_one "$ROOT/output/sandlot" \
        "$ROOT/sandlot" "$ROOT/common/proto"

    # boxout: all Go sources under boxout/ + sandlot/ + shared proto in common/
    check_one "$ROOT/output/boxout" \
        "$ROOT/boxout" "$ROOT/sandlot" "$ROOT/common/proto"

    # dns: all Go sources under dns/
    check_one "$ROOT/output/sandns" \
        "$ROOT/dns"

    # sandctl: all Go sources under sandctl/
    check_one "$ROOT/output/sandctl" \
        "$ROOT/sandctl"

    # openai-sandswap example: all Go sources under examples/openai-sandswap/
    check_one "$ROOT/output/openai-sandswap" \
        "$ROOT/examples/openai-sandswap"

    # eino-sandswap example: all Go sources under examples/eino-sandswap/
    check_one "$ROOT/output/eino-sandswap" \
        "$ROOT/examples/eino-sandswap"

    # keepalive-sandswap example: all Go sources under examples/keepalive-sandswap/
    check_one "$ROOT/output/keepalive-sandswap" \
        "$ROOT/examples/keepalive-sandswap"

    # loadgen: all Go sources under examples/loadgen/ (the load benchmark driver)
    check_one "$ROOT/output/loadgen" \
        "$ROOT/examples/loadgen"

    # sandvmm: all Rust sources under vmm/ (target/ pruned by newest_mtime —
    # cargo OUT dirs hold generated .rs). The dangling comment here used to
    # have NO check_one behind it: an edited vmm source with a stale
    # output/sandvmm sailed through `build.sh check` and e2e ran old VMM code.
    check_one "$ROOT/output/sandvmm" \
        "$ROOT/vmm"

    # kernel: kernel/build.sh downloads/patches/builds output/vmlinux.bin.
    # CONTENT-verified, not mtime-verified: the custom kernel is a ~20-minute
    # build whose output is fully determined by the pinned tag + config, and
    # the artifact carries its own proof (version banner + the two required
    # features — the same probes the build itself runs). An mtime rule would
    # demand a rebuild for a comment edit in kernel/build.sh; the script's
    # `check` mode is the authority instead.
    if bash "$ROOT/kernel/build.sh" check > /dev/null 2>&1; then
        printf "  ${GREEN}[FRESH]${NC}   %-28s (kernel probes: version + features)\n" \
            "$ROOT/output/vmlinux.bin"
    else
        printf "  ${RED}[STALE]${NC}    %-28s (kernel missing / wrong version / features absent)\n" \
            "$ROOT/output/vmlinux.bin"
        STALE_FOUND=1
    fi

    # bindregdump + warden-probe: built by build_go from the sandlot module
    # (separate artifacts — each gets its own freshness row).
    check_one "$ROOT/output/bindregdump" \
        "$ROOT/sandlot" "$ROOT/common/proto"
    check_one "$ROOT/output/warden-probe" \
        "$ROOT/sandlot" "$ROOT/common/proto"
    check_one "$ROOT/output/template-tool" \
        "$ROOT/sandlot" "$ROOT/common/proto"
    check_one "$ROOT/output/scalepopulator" \
        "$ROOT/gateway"


    # initramfs.cpio.gz: embeds the warden binary, so it depends on warden
    # sources AND the initramfs build script. This is the critical check —
    # a recompiled warden must be re-packaged, or the microVM boots old code.
    check_one "$ROOT/output/initramfs.cpio.gz" \
        "$ROOT/warden/src" "$ROOT/warden/Cargo.toml" "$ROOT/initramfs"

    # warden musl binary itself (used to build initramfs)
    check_one "$ROOT/warden/target/x86_64-unknown-linux-musl/release/warden" \
        "$ROOT/warden/src" "$ROOT/warden/Cargo.toml"

    # rootfs-template directory: rebuilt by build-rootfs-template.sh
    check_one "$ROOT/output/rootfs-template" \
        "$ROOT/build/build-rootfs-template.sh"

    # rootfs-ubuntu directory: rebuilt by build-ubuntu-rootfs.sh
    check_one "$ROOT/output/rootfs-ubuntu" \
        "$ROOT/build/build-ubuntu-rootfs.sh"

    # vsockguard: BPF object + loader built from network/vsockguard/.
    # vmlinux.h is generated (kernel-specific) so exclude it from the source set.
    check_one "$ROOT/output/vsockguard.bpf.o" \
        "$ROOT/network/vsockguard/vsockguard.bpf.c"
    check_one "$ROOT/output/vsockguardctl" \
        "$ROOT/network/vsockguard/vsockguardctl.c"

    if [[ "$STALE_FOUND" -ne 0 ]]; then
        echo -e "${YELLOW}[!]${NC} Some artifacts are stale or missing."
        echo -e "${YELLOW}[!]${NC} Run: bash build/build.sh all   (to rebuild everything)"
        return 1
    fi
    log "All artifacts are fresh (newer than their sources)."
    return 0
}

# ── Kernel ────────────────────────────────────────────────────────

build_kernel() {
    log "Building PVH kernel..."
    check_cmd git
    check_cmd wget
    (cd "$ROOT/kernel" && bash build.sh)
    log "Kernel → output/vmlinux.bin"
}

# ── Warden (in-VM, musl static) ────────────────────────────────────

build_warden() {
    log "Building warden..."
    (cd "$ROOT/warden" && bash build.sh)
}

# ── Initramfs ─────────────────────────────────────────────────────

build_initramfs() {
    log "Building initramfs..."

    # Warden must be built first
    local warden_bin
    warden_bin="$ROOT/warden/target/$(uname -m)-unknown-linux-musl/release/warden"
    if [ ! -f "$warden_bin" ]; then
        log "Warden binary not found, building warden first..."
        build_warden
    fi

    # The busybox is NOT the host's: initramfs/build.sh fetches its one pinned
    # build (verified against build/checksums.sh), so the artifact is identical
    # on every build host regardless of the distro's busybox version.
    # cpio is NOT optional: without it the `find | cpio` pipeline silently
    # produces a 20-byte (broken) initramfs instead of failing loudly.
    check_cmd cpio || {
        log "cpio not found. Install: apt install cpio  (or: sudo bash build/install-deps.sh)"
        exit 1
    }

    (cd "$ROOT/initramfs" && WARDEN_BIN="$warden_bin" bash build.sh)
    log "Initramfs → output/initramfs.cpio.gz"
}

# ── VMM (KVM monitor, Rust) ───────────────────────────────────────

build_vmm() {
    log "Building sandvmm (static)..."
    check_cmd cargo

    # Static by default: crt-static glibc + the two native C libs the fork's
    # in-process virtiofsd drags in (libcap-ng for the fs credential switching,
    # libseccomp — unreferenced in-process but the linker must still locate it)
    # linked from their -dev static archives. Upstream cloud-hypervisor ships
    # musl statics because it has NO in-process virtiofsd (external vhost-user
    # daemon, zero C deps); we keep native PassthroughFs and statically link
    # the two C libs instead. Two more non-negotiables:
    #   - GNU ld: rustc >= 1.90 links with rust-lld by default, which produces
    #     a static-glibc binary that segfaults at startup (verified) — hence
    #     linker-features=-lld.
    #   - Keep the default PIC relocation model: crt-static + PIE yields a
    #     static-PIE ELF (ET_DYN, no INTERP) that the kernel loads at a
    #     randomized base = full ASLR. Adding relocation-model=static would
    #     downgrade to a fixed-address ET_EXEC (no ASLR) — the readelf probe
    #     below fails the static path if that ever regresses.
    local libdir
    libdir="/usr/lib/$(gcc -dumpmachine 2>/dev/null || echo x86_64-linux-gnu)"
    local static_env=(
        "LIBCAPNG_LIB_PATH=$libdir"   "LIBCAPNG_LINK_TYPE=static"
        "LIBSECCOMP_LIB_PATH=$libdir" "LIBSECCOMP_LINK_TYPE=static"
    )
    local static_flags="-C target-feature=+crt-static -C linker-features=-lld -A linker_messages"
    # -A linker_messages: silences the ld "Using 'getpwuid'/'initgroups' in
    # statically linked applications" warnings from libcap-ng. Verified safe
    # to silence: the only NSS-using symbol (capng_change_id) has ZERO call
    # sites in this codebase — virtiofsd switches credentials via raw
    # setresuid (oslib::seteffuid), never capng_change_id — and the guest is
    # single-user root, so no NSS lookup is ever exercised. The actual capng
    # usage (apply/clear/get_caps_process/have_capability/update) is
    # NSS-free. Re-add the lint only if capng_change_id gains a caller.
    local static_bin="$ROOT/vmm/target/x86_64-unknown-linux-gnu/release/sandvmm"

    mkdir -p "$ROOT/output"
    # The --version probe guards against silently shipping a broken static
    # link (the lld failure mode was: links green, segfaults at exec); the
    # readelf DYN check pins the static-PIE/ASLR property.
    if env "${static_env[@]}" RUSTFLAGS="$static_flags" \
            cargo build --release --manifest-path "$ROOT/vmm/Cargo.toml" \
                --target x86_64-unknown-linux-gnu -p sandvmm \
        && [[ -x "$static_bin" ]] \
        && "$static_bin" --version >/dev/null 2>&1 \
        && readelf -h "$static_bin" 2>/dev/null | grep -q " DYN "; then
        cp "$static_bin" "$ROOT/output/sandvmm"
        log "sandvmm → output/sandvmm (static, no glibc constraint)"
        return
    fi

    warn "static sandvmm link failed (old rustc without linker-features? missing libcap-ng.a/libseccomp.a?)"
    warn "  falling back to a DYNAMIC build — the binary then requires a matching-host glibc"
    (cd "$ROOT/vmm" && cargo build --release)
    cp "$ROOT/vmm/target/release/sandvmm" "$ROOT/output/sandvmm"
    log "sandvmm → output/sandvmm (dynamic)"
}

# ── Go components ─────────────────────────────────────────────────

build_go() {
    log "Building gateway (static)..."
    check_cmd go

    mkdir -p "$ROOT/output"

    # ── Version stamps (uniform across gateway + sandlot) ──────────────
    # Default: VERSION file (trunk: 0.0.0-dev; release tooling overwrites it
    # with the tag before this step) + git commit + build date. CI can inject
    # its own triple via GO_LDFLAGS_EXTRA (used verbatim for BOTH binaries —
    # pass both gateway/cmd and sandlot/cmd -X sets).
    VERSION_VAL="$(cat "$ROOT/VERSION" 2>/dev/null || echo 0.0.0-dev)"
    COMMIT_VAL="$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
    if [ -n "$(git -C "$ROOT" status --porcelain --untracked-files=no 2>/dev/null)" ]; then
        COMMIT_VAL="${COMMIT_VAL}-dirty"
    fi
    BUILD_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    # NB: BOTH symbol forms per binary — the linker resolves package-main
    # vars as main.X; the import-path form (gateway/cmd.X) is silently
    # ignored on Go ≥1.26 for main packages but is the only form older
    # toolchains accept for some layouts. Emitting both is idempotent.
    GO_STAMP="${GO_LDFLAGS_EXTRA:--X main.Version=${VERSION_VAL} -X main.Commit=${COMMIT_VAL} -X main.BuildTime=${BUILD_TS} -X gateway/cmd.Version=${VERSION_VAL} -X gateway/cmd.Commit=${COMMIT_VAL} -X gateway/cmd.BuildTime=${BUILD_TS} -X sandlot/cmd.Version=${VERSION_VAL} -X sandlot/cmd.Commit=${COMMIT_VAL} -X sandlot/cmd.BuildTime=${BUILD_TS} -X dns.Version=${VERSION_VAL} -X dns.Commit=${COMMIT_VAL} -X dns.BuildTime=${BUILD_TS} -X boxout.Version=${VERSION_VAL} -X boxout.Commit=${COMMIT_VAL} -X boxout.BuildTime=${BUILD_TS} -X sandctl.Version=${VERSION_VAL} -X sandctl.Commit=${COMMIT_VAL} -X sandctl.BuildTime=${BUILD_TS}}"
    log "Version stamps: version=${VERSION_VAL} commit=${COMMIT_VAL} built=${BUILD_TS}"

    (cd "$ROOT/gateway" && CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags "-s -w ${GO_STAMP}" -o "$ROOT/output/gateway" ./cmd/)
    log "Gateway → output/gateway (static)"

    log "Building sandlot (static)..."
    (cd "$ROOT/sandlot" && CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags "-s -w ${GO_STAMP}" -o "$ROOT/output/sandlot" ./cmd/)
    log "Sandlot → output/sandlot (static)"

    log "Building bindregdump (static; egress identity region inspector)..."
    (cd "$ROOT/sandlot" && CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags '-s -w' -o "$ROOT/output/bindregdump" ./cmd/bindregdump/)
    log "bindregdump → output/bindregdump (static)"

    log "Building warden-probe (static; raw vsock warden test/diagnostics client)..."
    (cd "$ROOT/sandlot" && CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags '-s -w' -o "$ROOT/output/warden-probe" ./cmd/warden-probe/)
    log "warden-probe → output/warden-probe (static)"

    log "Building template-tool (template contract: normalize/check/validate/check-store)..."
    (cd "$ROOT/sandlot" && CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags '-s -w' -o "$ROOT/output/template-tool" ./cmd/template-tool/)
    log "template-tool → output/template-tool (static)"

    # scalepopulator: the scale-rehearsal population generator. Built here so
    # e2e/scale-rehearsal.sh has a reproducible artifact instead of an
    # out-of-band "cp /tmp/scalepopulator output/" (the row was red for
    # exactly that missing file).
    log "Building scalepopulator (static; scale-rehearsal population generator)..."
    (cd "$ROOT/gateway" && CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags '-s -w' -o "$ROOT/output/scalepopulator" ./cmd/scalepopulator/)
    log "scalepopulator → output/scalepopulator (static)"

    log "Building boxout (static)..."
    (cd "$ROOT/boxout" && CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags "-s -w ${GO_STAMP}" -o "$ROOT/output/boxout" .)
    log "Boxout → output/boxout (static)"

    log "Building sandns (static)..."
    (cd "$ROOT/dns" && CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags "-s -w ${GO_STAMP}" -o "$ROOT/output/sandns" .)
    log "sandns → output/sandns (static)"

    log "Building sandctl (static)..."
    (cd "$ROOT/sandctl" && CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags "-s -w ${GO_STAMP}" -o "$ROOT/output/sandctl" .)
    log "sandctl → output/sandctl (static)"
}

# ── sandctl (operator CLI) ────────────────────────────────────────

build_sandctl() {
    log "Building sandctl (static)..."
    check_cmd go
    mkdir -p "$ROOT/output"
    (cd "$ROOT/sandctl" && CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags '-s -w' -o "$ROOT/output/sandctl" .)
    log "sandctl → output/sandctl (static)"
}

# ── Examples (openai-sandswap + eino-sandswap + keepalive-sandswap + loadgen) ──

build_examples() {
    log "Building openai-sandswap example (static)..."
    check_cmd go

    mkdir -p "$ROOT/output"
    (cd "$ROOT/examples/openai-sandswap" && CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags '-s -w' -o "$ROOT/output/openai-sandswap" .)
    log "openai-sandswap → output/openai-sandswap (static)"

    log "Building eino-sandswap example (static)..."
    (cd "$ROOT/examples/eino-sandswap" && CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags '-s -w' -o "$ROOT/output/eino-sandswap" .)
    log "eino-sandswap → output/eino-sandswap (static)"

    log "Building keepalive-sandswap example (static)..."
    (cd "$ROOT/examples/keepalive-sandswap" && CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags '-s -w' -o "$ROOT/output/keepalive-sandswap" .)
    log "keepalive-sandswap → output/keepalive-sandswap (static)"

    log "Building loadgen (concurrent load driver, static)..."
    (cd "$ROOT/examples/loadgen" && CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags '-s -w' -o "$ROOT/output/loadgen" .)
    log "loadgen → output/loadgen (static)"
}

# ── Main ──────────────────────────────────────────────────────────

build_all() {
    log "=== Sandswap Build ==="
    check_build_deps

    build_kernel
    build_warden
    build_initramfs
    build_vmm
    build_go
    build_examples
    build_rootfs_template
    build_ubuntu_rootfs
    build_vsockguard

    echo ""
    log "=== All targets built ==="

    # Guarantee: every artifact in output/ is now newer than its source.
    # verify_freshness exits non-zero if any artifact is stale/missing,
    # which (under set -e) fails the whole `build.sh all` — so a green
    # build guarantees the test will run freshly compiled code.
    verify_freshness
    echo ""
    echo "  output/vmlinux.bin          (~12-20 MB)"
    echo "  output/initramfs.cpio.gz     (~5 MB)"
    echo "  output/sandvmm          (~5 MB, static)"
    echo "  output/gateway               (~12-15 MB)"
    echo "  output/sandlot               (~12-15 MB)"
    echo "  output/boxout                (~12-15 MB)"
    echo "  output/sandns                    (~15 MB)"
    echo "  output/sandctl                (~5 MB, operator CLI)"
    echo "  output/openai-sandswap        (example agent, ~10 MB)"
    echo "  output/eino-sandswap          (example agent, ~28 MB)"
    echo "  output/keepalive-sandswap     (keep-alive demo, ~5 MB)"
    echo "  output/loadgen               (concurrent load driver, ~3 MB)"
    echo "  output/rootfs-template         (directory, ~few MB)"
    echo "  output/rootfs-ubuntu           (directory, ~150 MB)"
    echo "  output/vsockguard.bpf.o        (BPF LSM program)"
    echo "  output/vsockguardctl           (libbpf attach/detach control tool)"
    echo ""
    echo "  Deploy: cp -a output/* /var/lib/sandswap/"
}

# ── Rootfs template (seeds agent volumes) ──────────────────────────

build_rootfs_template() {
    log "Building rootfs template (seeds agent volumes)..."
    (cd "$ROOT/build" && bash build-rootfs-template.sh)
    log "Rootfs template → output/rootfs-template/"
}

# ── Ubuntu rootfs template ────────────────────────────────────────

build_ubuntu_rootfs() {
    # The Ubuntu template's package layer is a chroot install (root-only).
    # A complete existing template is kept when the build runs unprivileged;
    # an absent/incomplete one fails with the exact command instead of
    # silently producing a template without python3.
    if [[ "$(id -u)" -ne 0 ]]; then
        if [[ -x "$ROOT/output/rootfs-ubuntu/usr/bin/python3" ]]; then
            warn "Ubuntu rootfs template requires root to rebuild — keeping the existing complete template"
            return 0
        fi
        err "Ubuntu rootfs template requires root (chroot package install): sudo bash build/build.sh all"
    fi
    log "Building Ubuntu rootfs template..."
    (cd "$ROOT/build" && bash build-ubuntu-rootfs.sh)
    log "Ubuntu rootfs template → output/rootfs-ubuntu/"
}

# ── vsockguard (BPF LSM vsock access control) ─────────────────────
#
# Compiles the BPF LSM program (vsockguard.bpf.c → vsockguard.bpf.o) with clang
# and the libbpf control tool (vsockguardctl.c → vsockguardctl) with gcc. Both
# ship in output/. Prereqs: clang, libbpf-dev (provides bpf_helpers.h + libbpf.a),
# bpftool (for vmlinux.h generation, cached). The .o + ctl are deployed to every
# sandlot node; attach/detach is via security/vsockguard-{attach,detach}.sh at
# runtime, which call vsockguardctl.

build_vsockguard() {
    log "Building vsockguard (BPF LSM vsock guard)..."
    local vg="$ROOT/network/vsockguard"
    check_cmd clang
    check_cmd gcc

    # Regenerate vmlinux.h from the running kernel's BTF if missing or
    # content-stale. (Kernel-version-specific; do NOT commit it.) The sysfs
    # btf file's mtime tracks the CLOCK on some kernels, not the boot, so
    # `-nt` fires on every build; dump to a temp file and keep the existing
    # one when the bytes match, so its mtime (and downstream staleness
    # reasoning) stays stable.
    if [ ! -f "$vg/vmlinux.h" ] || \
       [ "/sys/kernel/btf/vmlinux" -nt "$vg/vmlinux.h" ]; then
        check_cmd bpftool
        log "  generating vmlinux.h from /sys/kernel/btf/vmlinux"
        bpftool btf dump file /sys/kernel/btf/vmlinux format c > "$vg/vmlinux.h.new"
        if [ -f "$vg/vmlinux.h" ] && cmp -s "$vg/vmlinux.h.new" "$vg/vmlinux.h"; then
            rm -f "$vg/vmlinux.h.new"
            log "  vmlinux.h content unchanged — kept as-is"
        else
            mv "$vg/vmlinux.h.new" "$vg/vmlinux.h"
        fi
    fi

    # Detect the multiarch include path for libbpf headers (bpf/bpf_helpers.h).
    local inc
    for inc in /usr/include/x86_64-linux-gnu /usr/include/aarch64-linux-gnu /usr/include; do
        if [ -f "$inc/bpf/bpf_helpers.h" ]; then break; fi
    done

    # 1) BPF object. -Wno-missing-declarations silences vmlinux.h forward-decl
    #    noise; -Wno-unused-parameter silences the BPF_PROG macro's `ctx`/unused args.
    #    Compile to a temp file and keep the existing artifact when the bytes
    #    match: an unconditional overwrite re-stamps the mtime on every
    #    invocation, which churns artifact identity and invalidates every
    #    recorded matrix verdict even though nothing changed.
    clang -g -O2 -target bpf -D__TARGET_ARCH_x86 \
        -I"$inc" -Wall -Wextra -Wno-missing-declarations -Wno-unused-parameter \
        -c "$vg/vsockguard.bpf.c" -o "$ROOT/output/vsockguard.bpf.o.new"
    if cmp -s "$ROOT/output/vsockguard.bpf.o.new" "$ROOT/output/vsockguard.bpf.o"; then
        rm -f "$ROOT/output/vsockguard.bpf.o.new"
    else
        mv "$ROOT/output/vsockguard.bpf.o.new" "$ROOT/output/vsockguard.bpf.o"
    fi

    # 2) vsockguardctl — libbpf control tool (attach/detach).
    #    Prefer a fully static link (libbpf + libelf + libz + libzstd baked in)
    #    so the binary runs in any container image (ubuntu:22.04 has libbpf0,
    #    not libbpf1; libbpf ABI differs across distros). Some RHEL-family
    #    repos ship no static libc/libelf (no libelf.a / glibc-static) — fall
    #    back to static-libbpf-only so the build still succeeds there; the
    #    cross-distro libbpf ABI (the reason for static linking) stays covered.
    local ctl_new="$ROOT/output/vsockguardctl.new"
    if ! gcc -O2 -Wall -static "$vg/vsockguardctl.c" -o "$ctl_new" \
            -lbpf -lelf -lz -lzstd 2>/dev/null; then
        log "  fully-static link unavailable (missing .a archives) — linking static-libbpf-only"
        gcc -O2 -Wall "$vg/vsockguardctl.c" -o "$ctl_new" \
            -Wl,-Bstatic -lbpf -Wl,-Bdynamic -lelf -lz -lzstd
    fi
    if cmp -s "$ctl_new" "$ROOT/output/vsockguardctl"; then
        rm -f "$ctl_new"
    else
        mv "$ctl_new" "$ROOT/output/vsockguardctl"
        chmod 0755 "$ROOT/output/vsockguardctl"
    fi

    log "vsockguard → output/vsockguard.bpf.o + output/vsockguardctl"
}

mkdir -p "$ROOT/output"

case "${1:-all}" in
    kernel)    build_kernel ;;
    warden)    build_warden ;;
    initramfs) build_initramfs ;;
    vmm)       build_vmm ;;
    go)        build_go ;;
    sandctl)   build_sandctl ;;
    examples)  build_examples ;;
    proto)     bash "$(dirname "$0")/gen-proto.sh" ;;
    rootfs-template) build_rootfs_template ;;
    ubuntu-rootfs)   build_ubuntu_rootfs ;;
    vsockguard) build_vsockguard ;;
    check)
        verify_freshness || exit 1
        # Syscall decision ledger: every allowed syscall must carry a decision
        # row and every denied syscall must NOT (the deny list and the decision
        # file drifted apart twice before this gate existed).
        census="$(dirname "$0")/../security/seccomp-syscall-census.sh"
        if [ -x "$census" ]; then
            bash "$census" >/dev/null || { echo "seccomp syscall census FAILED (run: bash $census)" >&2; exit 1; }
        fi
        ;;
    deps)      bash "$(dirname "$0")/install-deps.sh" ;;
    all)       build_all ;;
    *)         echo "Usage: $0 {kernel|warden|initramfs|vmm|go|sandctl|proto|rootfs-template|ubuntu-rootfs|vsockguard|deps|check|all}" ;;
esac

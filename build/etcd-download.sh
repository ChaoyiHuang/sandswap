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
# etcd-download.sh — the pinned-checksum etcd download/install helpers.
# Sourced by build/install-deps.sh and by the --verify-selftest mode so the
# checksum gate can be tested without running the package installs.

# etcd_arch — the release tarball's architecture label.
etcd_arch() {
    case "$(uname -m)" in
        x86_64|amd64) echo amd64 ;;
        aarch64|arm64) echo arm64 ;;
        *) return 1 ;;
    esac
}

# etcd_download_verified <version> <arch> <bin-dir> — download the official
# tarball into a PRIVATE mktemp dir, verify it against the pinned checksum,
# and install etcd/etcdctl into <bin-dir>. Refuses unknown versions/arches
# and checksum mismatches; nothing is extracted before the check passes.
etcd_download_verified() {
    local version="$1" arch="$2" bindir="$3"
    local want got tmpdir tgz extracted url
    want="$(etcd_tarball_sha256 "$version" "$arch")" || {
        warn "no pinned checksum for etcd ${version} (${arch}) — refusing an unverified download"
        return 1
    }
    tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/sandswap-etcd.XXXXXX")" || return 1
    tgz="$tmpdir/etcd-${version}-linux-${arch}.tar.gz"
    url="https://github.com/etcd-io/etcd/releases/download/${version}/etcd-${version}-linux-${arch}.tar.gz"
    if command -v curl >/dev/null 2>&1; then
        curl -fL --progress-bar -o "$tgz" "$url" || { rm -rf "$tmpdir"; return 1; }
    elif command -v wget >/dev/null 2>&1; then
        wget -q --show-progress -O "$tgz" "$url" || { rm -rf "$tmpdir"; return 1; }
    else
        rm -rf "$tmpdir"; return 1
    fi
    got="$(sha256sum "$tgz" | awk '{print $1}')"
    if [ "$want" != "$got" ]; then
        warn "etcd tarball SHA256 mismatch (pinned $want, got $got) — refusing to install"
        rm -rf "$tmpdir"; return 1
    fi
    tar xzf "$tgz" -C "$tmpdir" || { rm -rf "$tmpdir"; return 1; }
    extracted="$tmpdir/etcd-${version}-linux-${arch}"
    if [ ! -x "$extracted/etcd" ] || [ ! -x "$extracted/etcdctl" ]; then
        warn "etcd tarball did not contain the expected ${version} binaries"
        rm -rf "$tmpdir"; return 1
    fi
    mkdir -p "$bindir"
    local rc=0
    if ! { install -m 0755 "$extracted/etcd" "$bindir/etcd" \
           && install -m 0755 "$extracted/etcdctl" "$bindir/etcdctl"; }; then
        rc=1
    fi
    rm -rf "$tmpdir"
    return "$rc"
}

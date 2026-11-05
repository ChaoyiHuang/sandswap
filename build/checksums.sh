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
# checksums.sh — pinned checksums for downloads whose bytes become build or
# release inputs. Sourced by install-deps.sh and package-release.sh.
#
# The values are the publisher's published release checksums, fixed here so a
# download is verified against a value that ships with the source tree instead
# of against whatever the network (or a leftover cache) returns. There is no
# fallback: an unknown version/arch/file makes the lookup fail, and every
# caller treats that as "do not use this artifact".

# etcd_tarball_sha256 <version> <arch> — official linux release tarball.
etcd_tarball_sha256() {
    case "$1:$2" in
        v3.6.13:amd64) echo b4928654aed84d90952620c7144555e4186d795e1e7414e65fe0cf6265fd0465 ;;
        v3.6.13:arm64) echo 5ab53ff70301fa9d782fa4b59fdfc1fae49ffdf427a0afb3cd313a93449800fc ;;
        v3.5.16:amd64) echo b414b27a5ad05f7cb01395c447c85d3227e3fb1c176e51757a283b817f645ccc ;;
        v3.5.16:arm64) echo 8e68c55e6d72b791a9e98591c755af36f6f55aa9eca63767822cd8a3817fdb23 ;;
        *) return 1 ;;
    esac
}

# ubuntu_base_sha256 <tarball-basename> — cdimage.ubuntu.com base rootfs.
ubuntu_base_sha256() {
    case "$1" in
        ubuntu-base-24.04.3-base-amd64.tar.gz) echo 6bc2cde3930ad088b3bb46fa45279e96d25bc3810f209850ecbe4722711874f9 ;;
        *) return 1 ;;
    esac
}

# busybox_static_deb_{url,sha256} / busybox_binary_sha256 <pkg-version> <arch>
# — the initramfs busybox (guest TCB). The build fetches this exact published
# .deb instead of using the host's busybox: the host build changes with the
# distro release (Ubuntu 24.04 ships 1.36.1, 26.04 ships 1.37.0) and even
# between package variants of ONE version (26.04 publishes an amd64v3 build
# that is a different binary than its baseline amd64 build), so a host-derived
# busybox silently changes the release artifact and breaks any build host
# carrying another build. URL is Launchpad's archival copy (the pool drops
# superseded versions). The sha256 matches the signed archive index
# (dists/resolute/main/binary-amd64/Packages); the binary sha256 is what the
# initramfs actually packs.
busybox_static_deb_url() {
    case "$1:$2" in
        1.37.0-7ubuntu1:amd64) echo "https://launchpad.net/ubuntu/+archive/primary/+files/busybox-static_1.37.0-7ubuntu1_amd64.deb" ;;
        *) return 1 ;;
    esac
}

busybox_static_deb_sha256() {
    case "$1:$2" in
        1.37.0-7ubuntu1:amd64) echo fd605342f62268753076aa7d9321ff098b36ba53e47434145a9aedc28fd141a4 ;;
        *) return 1 ;;
    esac
}

busybox_binary_sha256() {
    case "$1:$2" in
        1.37.0-7ubuntu1:amd64) echo df12634c17fcdca839ae5dc47d7627b7558511f7645de7c99ccf097a0f28ed5b ;;
        *) return 1 ;;
    esac
}

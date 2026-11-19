// Copyright 2026 Chaoyi Huang. All rights reserved.
//
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE file at the root of this repository.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0.

package preflight

import (
	"crypto/sha256"
	"encoding/hex"
	"log"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	sandlotconfig "sandlot/config"
)

// guestArtifactDir is the root-only location the deployers install the guest
// TCB into, with a SHA256SUMS pin beside it. A sandlot whose kernel/initramfs
// live here verifies both files before the first VM; dev/e2e paths outside
// this directory are exempt (they are not a production TCB location).
const guestArtifactDir = "/usr/local/lib/sandswap/guest"

// VerifyGuestArtifacts enforces the production TCB pin: both files must be
// root-owned, non-group/world-writable regular files, and match SHA256SUMS.
// A missing or mismatched pin is fatal — the guest kernel is the sandbox TCB.
func VerifyGuestArtifacts(cfg *sandlotconfig.SandlotConfig, logger *log.Logger) {
	kernel := cfg.TinyVM.Kernel
	initramfs := cfg.TinyVM.Initramfs
	if filepath.Dir(kernel) != guestArtifactDir || filepath.Dir(initramfs) != guestArtifactDir {
		logger.Printf("guest TCB hash check skipped: kernel/initramfs are outside %s (dev/e2e paths)", guestArtifactDir)
		return
	}
	sumsPath := filepath.Join(guestArtifactDir, "SHA256SUMS")
	sumsInfo, err := os.Lstat(sumsPath)
	if err != nil {
		logger.Fatalf("guest TCB pin %s is unavailable: %v\n  the deployer must install %s with sandswap_install_guest_artifacts", sumsPath, err, guestArtifactDir)
	}
	if !sumsInfo.Mode().IsRegular() || sumsInfo.Mode()&0o022 != 0 {
		logger.Fatalf("guest TCB pin %s is not a non-group/world-writable regular file (mode %04o)", sumsPath, sumsInfo.Mode().Perm())
	}
	if st, ok := sumsInfo.Sys().(*syscall.Stat_t); ok && st.Uid != 0 {
		logger.Fatalf("guest TCB pin %s is owned by uid %d, want root", sumsPath, st.Uid)
	}
	sums, err := os.ReadFile(sumsPath)
	if err != nil {
		logger.Fatalf("cannot read guest TCB pin %s: %v", sumsPath, err)
	}
	want := map[string]string{}
	for _, line := range strings.Split(string(sums), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 {
			want[fields[1]] = fields[0]
		}
	}
	for _, path := range []string{kernel, initramfs} {
		base := filepath.Base(path)
		expected, ok := want[base]
		if !ok {
			logger.Fatalf("guest TCB pin %s has no entry for %s", sumsPath, base)
		}
		fi, err := os.Lstat(path)
		if err != nil {
			logger.Fatalf("guest TCB artifact %s is unavailable: %v", path, err)
		}
		if !fi.Mode().IsRegular() || fi.Mode()&0o022 != 0 {
			logger.Fatalf("guest TCB artifact %s is not a non-group/world-writable regular file (mode %04o)", path, fi.Mode().Perm())
		}
		if st, ok := fi.Sys().(*syscall.Stat_t); ok && st.Uid != 0 {
			logger.Fatalf("guest TCB artifact %s is owned by uid %d, want root", path, st.Uid)
		}
		blob, err := os.ReadFile(path)
		if err != nil {
			logger.Fatalf("cannot read guest TCB artifact %s: %v", path, err)
		}
		sum := sha256.Sum256(blob)
		got := hex.EncodeToString(sum[:])
		if !strings.EqualFold(got, expected) {
			logger.Fatalf("guest TCB artifact %s hash mismatch: got %s, %s says %s", path, got, sumsPath, expected)
		}
		logger.Printf("guest TCB verified: %s sha256=%s", path, got[:16])
	}
}

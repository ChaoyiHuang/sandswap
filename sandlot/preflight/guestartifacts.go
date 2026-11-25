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
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	sandlotconfig "sandlot/config"
)

// GuestTcbDir returns the pinned guest TCB directory in effect: the
// configured tinyvm.guest_tcb_dir, else the built-in default. It is the
// root-only location the deployer installs the guest TCB into, with a
// SHA256SUMS pin beside it.
func GuestTcbDir(cfg *sandlotconfig.SandlotConfig) string {
	if cfg.TinyVM.GuestTcbDir == "" {
		return sandlotconfig.DefaultGuestTcbDir
	}
	return filepath.Clean(cfg.TinyVM.GuestTcbDir)
}

// VerifyGuestArtifacts enforces the production TCB pin on the kernel/initramfs
// PAIR: either both artifacts live under the pinned guest TCB directory and
// are verified (root-owned, non-group/world-writable regular files matching
// SHA256SUMS, with the directory and the pin file themselves root-owned and
// not group/world-writable), or both live outside it and the pair is treated
// as a dev/e2e path (logged, unverified). A mixed pair is refused: with one
// artifact inside and one outside, "the pin passed" would say nothing about
// half the TCB — in particular the initramfs carries the warden (PID 1), so
// silently skipping it would leave the more critical artifact unverified.
// Two typo shapes are refused explicitly: any artifact still under the
// BUILT-IN default TCB directory while the pin directory was configured
// elsewhere (a half-migration, even when both artifacts stayed behind), and
// any other split pair.
func VerifyGuestArtifacts(cfg *sandlotconfig.SandlotConfig, logger *log.Logger) error {
	dir := GuestTcbDir(cfg)
	dirCmp := resolvedDir(dir)
	defaultCmp := resolvedDir(sandlotconfig.DefaultGuestTcbDir)
	var pinned, outside []string
	for _, path := range []string{cfg.TinyVM.Kernel, cfg.TinyVM.Initramfs} {
		artifactDir := resolvedDir(filepath.Dir(filepath.Clean(path)))
		if artifactDir == dirCmp {
			pinned = append(pinned, path)
			continue
		}
		if artifactDir == defaultCmp {
			return fmt.Errorf("guest TCB artifact %s lives in the default TCB directory but tinyvm.guest_tcb_dir pins %s\n"+
				"  move the artifact under the pinned directory (the deployer's sandswap_install_guest_artifacts does all three), or clear guest_tcb_dir; refusing to boot an unverified guest kernel", path, dir)
		}
		outside = append(outside, path)
	}
	if len(pinned) > 0 && len(outside) > 0 {
		return fmt.Errorf("guest TCB artifacts are split between the pinned directory and dev paths: %s is under %s, %s is outside it\n"+
			"  a mixed pair cannot be verified as a whole: move both artifacts under %s with a SHA256SUMS pin (sandswap_install_guest_artifacts does this), or move both outside it for a dev/e2e run", pinned[0], dir, outside[0], dir)
	}
	if len(pinned) == 0 {
		for _, path := range outside {
			logger.Printf("guest TCB hash check skipped: %s is outside %s (dev/e2e path; the pair is unverified)", path, dir)
		}
		return nil
	}
	if err := requireRootOwnedTcbDir(dir); err != nil {
		return err
	}
	sumsPath := filepath.Join(dir, "SHA256SUMS")
	if err := requireRootOwnedRegular(sumsPath); err != nil {
		return fmt.Errorf("guest TCB pin %s is unavailable: %v\n  the deployer must install %s with sandswap_install_guest_artifacts", sumsPath, err, dir)
	}
	sums, err := os.ReadFile(sumsPath)
	if err != nil {
		return fmt.Errorf("cannot read guest TCB pin %s: %v", sumsPath, err)
	}
	want := map[string]string{}
	for _, line := range strings.Split(string(sums), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 {
			want[fields[1]] = fields[0]
		}
	}
	for _, path := range pinned {
		base := filepath.Base(path)
		expected, ok := want[base]
		if !ok {
			return fmt.Errorf("guest TCB pin %s has no entry for %s", sumsPath, base)
		}
		if err := requireRootOwnedRegular(path); err != nil {
			return fmt.Errorf("guest TCB artifact %s: %v", path, err)
		}
		blob, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("cannot read guest TCB artifact %s: %v", path, err)
		}
		sum := sha256.Sum256(blob)
		got := hex.EncodeToString(sum[:])
		if !strings.EqualFold(got, expected) {
			return fmt.Errorf("guest TCB artifact %s hash mismatch: got %s, %s says %s", path, got, sumsPath, expected)
		}
		logger.Printf("guest TCB verified: %s sha256=%s", path, got[:16])
	}
	return nil
}

// resolvedDir returns the canonical form of a directory path for comparison:
// symlinks resolved when the path exists, else the lexically cleaned form.
// The pin directory itself may be a root-owned symlink (see
// requireRootOwnedTcbDir), so "same directory" must not be decided
// textually — an artifact named through the link and one named through the
// target are the same pinned file.
func resolvedDir(path string) string {
	if r, err := filepath.EvalSymlinks(path); err == nil {
		return r
	}
	return filepath.Clean(path)
}

// requireRootOwnedTcbDir requires the TCB directory to resolve to a
// root-owned directory no group/other may write: write access to it is enough
// to rename or replace both the artifacts and the pin, so a service-writable
// directory is no pin at all. A symlinked directory is accepted only when the
// link itself is root-owned (its target is then checked like any directory).
func requireRootOwnedTcbDir(dir string) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("guest TCB directory %s is unavailable: %v", dir, err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		if st, ok := fi.Sys().(*syscall.Stat_t); ok && st.Uid != 0 {
			return fmt.Errorf("guest TCB directory %s is a symlink owned by uid %d, want root", dir, st.Uid)
		}
		if fi, err = os.Stat(dir); err != nil {
			return fmt.Errorf("guest TCB directory %s is unavailable: %v", dir, err)
		}
	}
	if !fi.IsDir() {
		return fmt.Errorf("guest TCB directory %s is not a directory", dir)
	}
	if fi.Mode()&0o022 != 0 {
		return fmt.Errorf("guest TCB directory %s is group/world-writable (mode %04o): directory write alone is enough to replace the TCB", dir, fi.Mode().Perm())
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && st.Uid != 0 {
		return fmt.Errorf("guest TCB directory %s is owned by uid %d, want root", dir, st.Uid)
	}
	return nil
}

// requireRootOwnedRegular requires path to be a regular file (a symlink is
// refused), owned by root and not group/world-writable.
func requireRootOwnedRegular(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() || fi.Mode()&0o022 != 0 {
		return fmt.Errorf("not a non-group/world-writable regular file (mode %04o)", fi.Mode().Perm())
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && st.Uid != 0 {
		return fmt.Errorf("owned by uid %d, want root", st.Uid)
	}
	return nil
}

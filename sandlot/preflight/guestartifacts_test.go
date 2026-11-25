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
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	sandlotconfig "sandlot/config"
)

// installTcb writes a kernel/initramfs pair and its SHA256SUMS pin into dir
// (root-owned 0755, files 0644 — the deployer's layout) and returns a config
// whose TCB directory and artifacts point there.
func installTcb(t *testing.T, dir string) *sandlotconfig.SandlotConfig {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	var sums strings.Builder
	for name, body := range map[string]string{"vmlinux.bin": "kernel-bytes", "initramfs.cpio.gz": "initramfs-bytes"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256([]byte(body))
		sums.WriteString(hex.EncodeToString(sum[:]) + "  " + name + "\n")
	}
	if err := os.WriteFile(filepath.Join(dir, "SHA256SUMS"), []byte(sums.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := sandlotconfig.Defaults()
	cfg.TinyVM.GuestTcbDir = dir
	cfg.TinyVM.Kernel = filepath.Join(dir, "vmlinux.bin")
	cfg.TinyVM.Initramfs = filepath.Join(dir, "initramfs.cpio.gz")
	return &cfg
}

func discardLogger() *log.Logger { return log.New(io.Discard, "", 0) }

// TestGuestTcbDirFallback pins the empty-key contract: an unset
// tinyvm.guest_tcb_dir resolves to the built-in default, so the default
// kernel/initramfs stay pinned without the deployer writing the key.
func TestGuestTcbDirFallback(t *testing.T) {
	cfg := sandlotconfig.Defaults()
	if cfg.TinyVM.GuestTcbDir != sandlotconfig.DefaultGuestTcbDir {
		t.Fatalf("Defaults().TinyVM.GuestTcbDir = %q, want %q", cfg.TinyVM.GuestTcbDir, sandlotconfig.DefaultGuestTcbDir)
	}
	cfg.TinyVM.GuestTcbDir = ""
	if got := GuestTcbDir(&cfg); got != sandlotconfig.DefaultGuestTcbDir {
		t.Fatalf("GuestTcbDir(empty) = %q, want the default %q", got, sandlotconfig.DefaultGuestTcbDir)
	}
	if filepath.Dir(cfg.TinyVM.Kernel) != GuestTcbDir(&cfg) {
		t.Fatalf("the default kernel %q does not live under the pinned directory", cfg.TinyVM.Kernel)
	}
}

// TestVerifyGuestArtifactsRelocatedDir is the relocation contract: a TCB
// installed outside the default directory, declared through
// tinyvm.guest_tcb_dir, is verified exactly like the default one — and a
// tampered artifact is fatal there too (previously such a pair was silently
// exempt as a "dev/e2e path").
func TestVerifyGuestArtifactsRelocatedDir(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("artifact ownership checks require root")
	}
	cfg := installTcb(t, filepath.Join(t.TempDir(), "opt-tcb"))
	lg := discardLogger()
	if err := VerifyGuestArtifacts(cfg, lg); err != nil {
		t.Fatalf("relocated TCB with a matching pin rejected: %v", err)
	}
	if filepath.Dir(cfg.TinyVM.Kernel) == sandlotconfig.DefaultGuestTcbDir {
		t.Fatal("test setup did not relocate the TCB")
	}

	if err := os.WriteFile(cfg.TinyVM.Initramfs, []byte("replaced-bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := VerifyGuestArtifacts(cfg, lg)
	if err == nil || !strings.Contains(err.Error(), "hash mismatch") {
		t.Fatalf("tampered relocated initramfs accepted or misreported: %v", err)
	}

	if err := os.Remove(filepath.Join(cfg.TinyVM.GuestTcbDir, "SHA256SUMS")); err != nil {
		t.Fatal(err)
	}
	err = VerifyGuestArtifacts(cfg, lg)
	if err == nil || !strings.Contains(err.Error(), "pin") {
		t.Fatalf("relocated TCB without its pin accepted or misreported: %v", err)
	}
}

// TestVerifyGuestArtifactsOutsideDirSkipped keeps the dev/e2e exemption: an
// artifact outside the pinned directory is not verified (no pin required).
func TestVerifyGuestArtifactsOutsideDirSkipped(t *testing.T) {
	dir := t.TempDir()
	cfg := sandlotconfig.Defaults()
	cfg.TinyVM.Kernel = filepath.Join(dir, "vmlinux.bin")
	cfg.TinyVM.Initramfs = filepath.Join(dir, "initramfs.cpio.gz")
	if err := os.WriteFile(cfg.TinyVM.Kernel, []byte("unpinned"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := VerifyGuestArtifacts(&cfg, discardLogger()); err != nil {
		t.Fatalf("unpinned dev path refused: %v", err)
	}
}

// TestVerifyGuestArtifactsRefusesMixedPair pins the pair rule: one artifact
// under the pinned directory and the other outside is refused in BOTH orders.
// "The pin passed" for half the TCB says nothing about the other half (the
// initramfs carries the warden, PID 1), so the mixed shape must not boot.
func TestVerifyGuestArtifactsRefusesMixedPair(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "initramfs.cpio.gz")
	cfg := installTcb(t, filepath.Join(t.TempDir(), "tcb"))
	cfg.TinyVM.Initramfs = outside
	err := VerifyGuestArtifacts(cfg, discardLogger())
	if err == nil || !strings.Contains(err.Error(), "split between the pinned directory") {
		t.Fatalf("pinned kernel + outside initramfs accepted or misreported: %v", err)
	}

	// The reverse order must fail the same way (the kernel is the outside one).
	rev := installTcb(t, filepath.Join(t.TempDir(), "tcb2"))
	rev.TinyVM.Kernel = filepath.Join(t.TempDir(), "vmlinux.bin")
	err = VerifyGuestArtifacts(rev, discardLogger())
	if err == nil || !strings.Contains(err.Error(), "split between the pinned directory") {
		t.Fatalf("outside kernel + pinned initramfs accepted or misreported: %v", err)
	}
}

// TestVerifyGuestArtifactsRefusesHalfMigratedTcb pins the misconfiguration
// guard: an artifact left in the BUILT-IN default TCB directory while
// tinyvm.guest_tcb_dir pins a different directory is refused, not treated as
// a dev path. The shape is a typo or a half-migration, and the old
// per-artifact skip would silently drop the integrity check on the very
// kernel the node boots — the failure mode the configurable pin exists to
// remove.
func TestVerifyGuestArtifactsRefusesHalfMigratedTcb(t *testing.T) {
	// Default kernel path still, pin dir moved: the typo shape.
	cfg := sandlotconfig.Defaults()
	cfg.TinyVM.GuestTcbDir = filepath.Join(t.TempDir(), "pinned")
	if err := VerifyGuestArtifacts(&cfg, discardLogger()); err == nil || !strings.Contains(err.Error(), "default TCB directory") {
		t.Fatalf("pinned dir with a default-path kernel accepted or misreported: %v", err)
	}

	// Kernel moved with the pin, initramfs left behind: half-migration.
	half := installTcb(t, filepath.Join(t.TempDir(), "pinned"))
	half.TinyVM.Initramfs = sandlotconfig.DefaultInitramfsPath
	if err := VerifyGuestArtifacts(half, discardLogger()); err == nil || !strings.Contains(err.Error(), "default TCB directory") {
		t.Fatalf("half-migrated initramfs accepted or misreported: %v", err)
	}
}

// TestVerifyGuestArtifactsSymlinkedPinDir pins the directory identity rule: a
// root-owned symlinked pin directory is legitimate, and an artifact named
// through the symlink's TARGET is the same pinned file — not a
// half-migration. The comparison resolves symlinks so the two spellings of
// one directory agree.
func TestVerifyGuestArtifactsSymlinkedPinDir(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("artifact ownership checks require root")
	}
	real := filepath.Join(t.TempDir(), "real-tcb")
	cfg := installTcb(t, real)
	link := filepath.Join(t.TempDir(), "tcb-link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	cfg.TinyVM.GuestTcbDir = link
	if err := VerifyGuestArtifacts(cfg, discardLogger()); err != nil {
		t.Fatalf("artifact named through the symlink target rejected: %v", err)
	}
}

// TestVerifyGuestArtifactsDirMustBeRootControlled pins the directory check:
// guest_tcb_dir may point anywhere, so a directory a service identity can
// write (or own) is refused — its pin would be writable by whoever can
// replace the kernel. A root-owned symlink to such a directory is accepted.
func TestVerifyGuestArtifactsDirMustBeRootControlled(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("artifact ownership checks require root")
	}
	cfg := installTcb(t, filepath.Join(t.TempDir(), "tcb"))
	dir := cfg.TinyVM.GuestTcbDir

	if err := os.Chmod(dir, 0o775); err != nil {
		t.Fatal(err)
	}
	err := VerifyGuestArtifacts(cfg, discardLogger())
	if err == nil || !strings.Contains(err.Error(), "group/world-writable") {
		t.Fatalf("group-writable TCB directory accepted or misreported: %v", err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.Chown(dir, 1234, 1234); err != nil {
		t.Fatal(err)
	}
	err = VerifyGuestArtifacts(cfg, discardLogger())
	if err == nil || !strings.Contains(err.Error(), "want root") {
		t.Fatalf("non-root-owned TCB directory accepted or misreported: %v", err)
	}
	if err := os.Chown(dir, 0, 0); err != nil {
		t.Fatal(err)
	}

	link := filepath.Join(t.TempDir(), "tcb-link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	cfg.TinyVM.GuestTcbDir = link
	cfg.TinyVM.Kernel = filepath.Join(link, "vmlinux.bin")
	cfg.TinyVM.Initramfs = filepath.Join(link, "initramfs.cpio.gz")
	if err := VerifyGuestArtifacts(cfg, discardLogger()); err != nil {
		t.Fatalf("root-owned symlinked TCB directory rejected: %v", err)
	}
	// Lchown, not Chown: the check judges the LINK's owner (chown would
	// follow it and re-owner the target directory instead).
	if err := os.Lchown(link, 1234, 1234); err != nil {
		t.Fatal(err)
	}
	if err := VerifyGuestArtifacts(cfg, discardLogger()); err == nil {
		t.Fatal("non-root-owned symlinked TCB directory accepted")
	}
}

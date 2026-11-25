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
	"io"
	"log"
	"os"
	"path/filepath"
	"testing"

	sandlotconfig "sandlot/config"
)

// TestVerifyVsockguardAttestation pins the startup contract: a missing
// attestation is refused unless the dev admission is set; the file must be a
// root-owned, non-writable regular file; a value naming another uid is
// refused (dev admission downgrades both to a warning).
func TestVerifyVsockguardAttestation(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("attestation ownership check requires root")
	}
	dir := t.TempDir()
	lg := log.New(io.Discard, "", 0)
	missing := filepath.Join(dir, "missing")
	if err := VerifyVsockguardAttestation(missing, 985, false, lg); err == nil {
		t.Fatal("missing attestation accepted without the dev admission")
	}
	if err := VerifyVsockguardAttestation(missing, 985, true, lg); err != nil {
		t.Fatalf("missing attestation rejected with the dev admission: %v", err)
	}

	att := filepath.Join(dir, "vsockguard.allowed_uid")
	if err := os.WriteFile(att, []byte("1234\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(att, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := VerifyVsockguardAttestation(att, 985, false, lg); err == nil {
		t.Fatal("attestation for uid 1234 accepted by a uid-985 sandlot")
	}
	if err := VerifyVsockguardAttestation(att, 985, true, lg); err != nil {
		t.Fatalf("mismatched attestation rejected under the dev admission: %v", err)
	}
	if err := VerifyVsockguardAttestation(att, 1234, false, lg); err != nil {
		t.Fatalf("matching attestation rejected: %v", err)
	}

	if err := os.Chmod(att, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := VerifyVsockguardAttestation(att, 1234, false, lg); err == nil {
		t.Fatal("group/world-writable attestation accepted")
	}

	if err := os.Chmod(att, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(att, []byte("not-a-uid\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := VerifyVsockguardAttestation(att, 1234, false, lg); err == nil {
		t.Fatal("non-numeric attestation accepted")
	}

	link := filepath.Join(dir, "link")
	if err := os.Symlink(att, link); err != nil {
		t.Fatal(err)
	}
	if err := VerifyVsockguardAttestation(link, 1234, false, lg); err == nil {
		t.Fatal("symlinked attestation accepted")
	}
}

// TestVerifyVsockguardPinRelocatedAttestation pins that the startup check
// follows the CONFIGURED attestation path: a sandlot whose deployment wrote
// the file outside the default runtime directory is verified against that
// file, and never against the default location (which may hold a stale file
// for another identity).
func TestVerifyVsockguardPinRelocatedAttestation(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("attestation ownership check requires root")
	}
	lg := log.New(io.Discard, "", 0)
	relocated := filepath.Join(t.TempDir(), "guard", "vsockguard.allowed_uid")
	if err := os.MkdirAll(filepath.Dir(relocated), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(relocated, []byte("985\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := VerifyVsockguardPin(985, relocated, false, lg); err != nil {
		t.Fatalf("relocated attestation for this uid rejected: %v", err)
	}
	if err := VerifyVsockguardPin(983, relocated, false, lg); err == nil {
		t.Fatal("relocated attestation naming another uid accepted")
	}
	if err := VerifyVsockguardPin(983, relocated+".absent", false, lg); err == nil {
		t.Fatal("absent relocated attestation accepted without the dev admission")
	}
	// An emptied key means the built-in default, like tinyvm.guest_tcb_dir.
	cfg := sandlotconfig.Defaults()
	if got := VsockguardAttestation(&cfg); got != sandlotconfig.DefaultVsockguardAttestation {
		t.Fatalf("VsockguardAttestation(defaults) = %q, want %q", got, sandlotconfig.DefaultVsockguardAttestation)
	}
	cfg.VsockguardAttestation = relocated
	if got := VsockguardAttestation(&cfg); got != relocated {
		t.Fatalf("VsockguardAttestation(configured) = %q, want %q", got, relocated)
	}
	cfg.VsockguardAttestation = ""
	if got := VsockguardAttestation(&cfg); got != sandlotconfig.DefaultVsockguardAttestation {
		t.Fatalf("VsockguardAttestation(empty) = %q, want the default %q", got, sandlotconfig.DefaultVsockguardAttestation)
	}
}

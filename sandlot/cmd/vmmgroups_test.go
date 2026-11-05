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

package main

import (
	"io"
	"log"
	"os"
	"path/filepath"
	"testing"
)

// TestResolveVMMGroupsRejectsSandprovGroup pins the startup refusal: the
// sandvmm/FUSE child must never carry the volume-seed group, whether it is
// named directly or arrives through api_gid.
func TestResolveVMMGroupsRejectsSandprovGroup(t *testing.T) {
	t.Setenv("SANDSWAP_PROV_GID", "4242")
	t.Setenv("SS_GID_SANDPROV", "")
	t.Setenv("SANDPROV_GROUP", "")
	lg := log.New(io.Discard, "", 0)

	if _, err := resolveVMMGroups("4242", 985, lg); err == nil {
		t.Fatal("sandprov group accepted in microvm.vmm_groups")
	}
	if _, err := resolveVMMGroups("", 4242, lg); err == nil {
		t.Fatal("sandprov group accepted as api_gid")
	}
	got, err := resolveVMMGroups("985", 986, lg)
	if err != nil {
		t.Fatalf("valid group list rejected: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("resolved groups = %v, want 2 entries", got)
	}
}

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
	if err := verifyVsockguardAttestation(missing, 985, false, lg); err == nil {
		t.Fatal("missing attestation accepted without the dev admission")
	}
	if err := verifyVsockguardAttestation(missing, 985, true, lg); err != nil {
		t.Fatalf("missing attestation rejected with the dev admission: %v", err)
	}

	att := filepath.Join(dir, "vsockguard.allowed_uid")
	if err := os.WriteFile(att, []byte("1234\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(att, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := verifyVsockguardAttestation(att, 985, false, lg); err == nil {
		t.Fatal("attestation for uid 1234 accepted by a uid-985 sandlot")
	}
	if err := verifyVsockguardAttestation(att, 985, true, lg); err != nil {
		t.Fatalf("mismatched attestation rejected under the dev admission: %v", err)
	}
	if err := verifyVsockguardAttestation(att, 1234, false, lg); err != nil {
		t.Fatalf("matching attestation rejected: %v", err)
	}

	if err := os.Chmod(att, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := verifyVsockguardAttestation(att, 1234, false, lg); err == nil {
		t.Fatal("group/world-writable attestation accepted")
	}

	if err := os.Chmod(att, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(att, []byte("not-a-uid\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := verifyVsockguardAttestation(att, 1234, false, lg); err == nil {
		t.Fatal("non-numeric attestation accepted")
	}

	link := filepath.Join(dir, "link")
	if err := os.Symlink(att, link); err != nil {
		t.Fatal(err)
	}
	if err := verifyVsockguardAttestation(link, 1234, false, lg); err == nil {
		t.Fatal("symlinked attestation accepted")
	}
}

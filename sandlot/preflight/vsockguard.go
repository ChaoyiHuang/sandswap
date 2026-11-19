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
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// vsockguardAttestation is the root-written statement that the warden-port BPF
// guard is attached and which uid it allows. The sandlot (uid 985) cannot read
// the bpffs pin itself: /sys/fs/bpf is root-only and bpf_obj_get needs both DAC
// access and BPF privileges. The deploy/attach tooling (root) writes this file
// after a successful attach; the systemd unit re-runs the same check in
// ExecStartPre, so a stale file cannot outlive a detached pin or a reboot.
const vsockguardAttestation = "/run/sandswap/vsockguard.allowed_uid"

// VerifyVsockguardPin proves the warden-port BPF guard is attached AND allows
// THIS sandlot uid. Root sandlots skip the check (root is a trust root and the
// hook admits root); a non-root sandlot verifies the root attestation's
// ownership, mode and value. The dev/test admission downgrades a
// missing/mismatched attestation to a warning.
func VerifyVsockguardPin(sandlotUID uint32, allowMissing bool, logger *log.Logger) error {
	if sandlotUID == 0 {
		logger.Printf("vsockguard: running as root — pin check skipped (root is a trust root and the BPF hook admits root)")
		return nil
	}
	return VerifyVsockguardAttestation(vsockguardAttestation, sandlotUID, allowMissing, logger)
}

// VerifyVsockguardAttestation validates the root-written attestation file at
// path: a regular, non-group/world-writable, root-owned file holding exactly
// this sandlot's uid.
func VerifyVsockguardAttestation(path string, sandlotUID uint32, allowMissing bool, logger *log.Logger) error {
	fi, err := os.Lstat(path)
	if err != nil {
		if allowMissing {
			logger.Printf("WARNING: vsockguard attestation absent (%v) — relying on the per-frame warden HMAC alone (-allow-missing-vsockguard is a DEV/TEST admission)", err)
			return nil
		}
		return fmt.Errorf("vsockguard attestation %s is missing: an exec node must not run without the warden-port BPF guard\n"+
			"  fix: run bash security/vsockguard-attach.sh %d (writes it after a successful attach) or the systemd unit's ExecStartPre; -allow-missing-vsockguard admits a dev/test host", path, sandlotUID)
	}
	if !fi.Mode().IsRegular() || fi.Mode()&0o022 != 0 {
		return fmt.Errorf("vsockguard attestation %s is not a non-group/world-writable regular file (mode %04o)", path, fi.Mode().Perm())
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && st.Uid != 0 {
		return fmt.Errorf("vsockguard attestation %s is owned by uid %d, want root", path, st.Uid)
	}
	data, rerr := os.ReadFile(path)
	if rerr != nil {
		return fmt.Errorf("read vsockguard attestation %s: %w", path, rerr)
	}
	text := strings.TrimSpace(string(data))
	got, perr := strconv.ParseUint(text, 10, 32)
	if perr != nil {
		return fmt.Errorf("vsockguard attestation %s holds %q (want a uid): %w", path, text, perr)
	}
	if uint32(got) != sandlotUID {
		if allowMissing {
			logger.Printf("WARNING: vsockguard allows uid %d but this sandlot runs as %d — proceeding under -allow-missing-vsockguard (DEV/TEST only)", got, sandlotUID)
			return nil
		}
		return fmt.Errorf("vsockguard allows uid %d, but this sandlot runs as uid %d — the guard protects a different identity; re-attach it with the sandlot uid", got, sandlotUID)
	}
	logger.Printf("vsockguard attestation verified: allowed_uid=%d", got)
	return nil
}

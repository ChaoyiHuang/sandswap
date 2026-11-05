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
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// Storage-plane hard precondition (docs/operations/storage.md row 9,
// "volumes mount hardening, invariant 8"): the tree -volumes-dir points at
// must sit on a nosuid,nodev MOUNT. The virtio-fs passthrough stores
// guest-requested setuid/setgid bits and mknod verbatim on the host volume
// (guest-created files carry the sandvmm identity, not the warden-trusted
// uid — the identity split already breaks the escalation chain), so the
// mount flags are what make planted bits INERT. This used to be an
// after-the-fact verify-script check; it is now a refuse-to-start gate so a
// misdeployed node can never serve a tenant with the control silently off.
//
// The explicit admission flag (-allow-insecure-volumes) exists for dev/test
// trees whose scratch paths sit on the root filesystem — the same pattern
// as -allow-colocated-instances: production fixes the mount (a self-bind +
// `remount,bind,nosuid,nodev` needs no dedicated filesystem; the baremetal
// deployer does exactly that), never passes the flag.
func requireSecureVolumesMount(dir string, allowInsecure bool) error {
	if allowInsecure {
		fmt.Fprintln(os.Stderr,
			"WARNING: -allow-insecure-volumes set — guest-planted setuid bits and device nodes on the volumes tree are LIVE (invariant 8 violated). Dev/test only.")
		return nil
	}
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		// Unreadable is not "probably fine": the gate fails closed. The
		// common cause is a not-yet-created directory — create it on a
		// properly mounted filesystem (or let the deployer, which remounts
		// nosuid,nodev itself, provision it).
		return fmt.Errorf(
			"refusing to start: -volumes-dir %s could not be statfs'd (%v) — create it on a nosuid,nodev mount, or pass -allow-insecure-volumes for a dev tree",
			dir, err)
	}
	if !volumesMountSecure(uint64(st.Flags)) {
		return fmt.Errorf(
			"refusing to start: -volumes-dir %s is not on a nosuid,nodev mount (got %s) — the virtio-fs passthrough stores guest-planted setuid bits and mknod verbatim, and only these mount flags make them inert (invariant 8). Fix: mount --bind %s %s && mount -o remount,bind,nosuid,nodev %s (no dedicated filesystem needed), or run on an already-hardened storage mount. -allow-insecure-volumes exists as the explicit dev/test admission.",
			dir, missingMountFlags(uint64(st.Flags)), dir, dir, dir)
	}
	return nil
}

// warnVolumesMountIfInsecure is the non-fatal twin for roles that do NOT
// export the volumes tree to a guest (prov-only, or boxout where the
// privileged sidecar owns the host mount). The mount owner must still harden
// it (invariant 8); a container runtime that drops per-mount flags on a PVC
// bind is exactly why this cannot be a hard gate for those processes.
func warnVolumesMountIfInsecure(dir string) {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		fmt.Fprintf(os.Stderr,
			"WARNING: -volumes-dir %s could not be statfs'd (%v); this role does not export the tree to a guest — the privileged mount owner must harden it (invariant 8)\n",
			dir, err)
		return
	}
	if !volumesMountSecure(uint64(st.Flags)) {
		fmt.Fprintf(os.Stderr,
			"WARNING: -volumes-dir %s is not on a nosuid,nodev mount (%s missing); this instance does not export the tree to a guest (boxout/prov), but the mount owner must harden it (invariant 8)\n",
			dir, missingMountFlags(uint64(st.Flags)))
	}
}

// volumesMountSecure is the pure predicate over statfs(2) mount flags:
// both ST_NOSUID and ST_NODEV must be set. Extracted so the flag semantics
// are unit-testable without a mount.
func volumesMountSecure(flags uint64) bool {
	return flags&unix.ST_NOSUID != 0 && flags&unix.ST_NODEV != 0
}

// missingMountFlags names which of the two required flags are absent, for
// the refusal message ("nosuid,nodev" when both are missing). Pure.
func missingMountFlags(flags uint64) string {
	missing := ""
	if flags&unix.ST_NOSUID == 0 {
		missing = "nosuid"
	}
	if flags&unix.ST_NODEV == 0 {
		if missing != "" {
			missing += ","
		}
		missing += "nodev"
	}
	if missing == "" {
		missing = "neither" // unreachable from the call site; defensive
	}
	return missing
}

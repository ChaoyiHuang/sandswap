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

package pool

import (
	"strings"
	"testing"
)

func TestClassifySecurityEvent(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		// warden warm-op refusals, as the sandlot wraps them verbatim
		{"volume_identity_mismatch: warm op volume identity does not match", ReasonVolumeIdentityMismatch},
		{"exec: volume_identity_missing: warm op carries no mounted-volume identity", ReasonVolumeIdentityMissing},
		// warden unmount final gate
		{"unmount_workspace: guest not clean at unmount: live or zombie process(es) [42]", ReasonUncleanGuest},
		{"unmount_workspace: process sweep could not scan /proc: refusing to reuse this VM", ReasonUncleanGuest},
		// VMM set-fs tripwire via the sandlot wrap
		{"set-fs: PreviousTenantRefs { handles: 1, inode_refs: 0 }", ReasonSetfsTripwire},
		{"set-fs: the previous tenant still holds references", ReasonSetfsTripwire},
		// EBUSY escalation
		{"unmount_workspace: failed to unmount workspace after retry (EBUSY): VM must be destroyed", ReasonUnmountEBUSY},
		// generic shape
		{"destroying VM to maintain exclusive-ownership invariant", ReasonUnknownIsolation},
		// ordinary business failures NEVER count
		{"file_read: open x.txt: no such file or directory", ""},
		{"exec_workspace spawn failed: no space left on device", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := ClassifySecurityEvent(c.in); got != c.want {
			t.Errorf("ClassifySecurityEvent(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestNoteSecurityEventCountsOnlyRefusals(t *testing.T) {
	before := SecurityEventSnapshot()
	NoteSecurityEvent("file_read: open x: no such file") // business failure
	after := SecurityEventSnapshot()
	if len(after) != len(before) {
		t.Fatalf("a business failure must not create a security series: %v", after)
	}
	NoteSecurityEvent("volume_identity_mismatch: ...")
	NoteSecurityEvent("volume_identity_mismatch: ...")
	snap := SecurityEventSnapshot()
	if snap[ReasonVolumeIdentityMismatch]-before[ReasonVolumeIdentityMismatch] != 2 {
		t.Errorf("two notes must count 2, got delta %d", snap[ReasonVolumeIdentityMismatch]-before[ReasonVolumeIdentityMismatch])
	}
}

func TestWriteSecurityMetricsTextShape(t *testing.T) {
	NoteSecurityEvent("volume_identity_missing: ...")
	out := WriteSecurityMetricsText()
	if !strings.Contains(out, "sandswap_security_events_total") ||
		!strings.Contains(out, `reason="`+ReasonVolumeIdentityMissing+`"`) ||
		!strings.Contains(out, "# TYPE sandswap_security_events_total counter") {
		t.Errorf("projection malformed:\n%s", out)
	}
}

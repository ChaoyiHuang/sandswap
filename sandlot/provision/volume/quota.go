// Copyright 2026 Chaoyi Huang. All rights reserved.
//
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE file at the root of this repository.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, this software will be governed by
// the Apache License, Version 2.0.

package volume

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// ErrQuotaStamp is the sentinel for a failed quota-stamp hook: the volume's
// content was seeded but the storage plane's quota attribute could not be
// applied, so the create is refused (fail-closed — a silently unquota'd
// volume is exactly what configuring the hook exists to prevent). The
// provisioning marker is still present at that point, so a retry self-heals
// by wiping and redoing the tree (hook included).
var ErrQuotaStamp = fmt.Errorf("quota stamp failed")

// quotaStampDeadline bounds one hook execution. A package-level var so tests
// can shrink it (the timeout path is otherwise a 10s wait).
var quotaStampDeadline = 10 * time.Second

// quotaStampOutputLimit bounds how much of the hook's combined output rides
// the error message — storage-side tooling can be chatty, and an error line
// is not its log sink.
const quotaStampOutputLimit = 256

// ValidateQuotaStampCmd checks the configured hook at config ingest: empty
// (the default) disables stamping entirely; anything else must be an
// ABSOLUTE path — the hook runs as the provision service identity and argv
// is how it travels, so a relative path would silently resolve against the
// daemon's cwd. Existence is deliberately NOT required here (validation
// would break the k8s ordering where the hook binary is mounted by another
// container); exec fails loudly at first use instead.
func ValidateQuotaStampCmd(cmd string) error {
	if cmd == "" {
		return nil
	}
	if !filepath.IsAbs(cmd) {
		return fmt.Errorf("provision.quota_stamp_cmd must be an absolute path (got %q)", cmd)
	}
	return nil
}

// runQuotaStampCmd invokes the storage plane's quota-stamp hook for one
// freshly seeded volume:
//
//	<cmd> <sandfs-id>          (argv)
//	<stdin>: <volume-path>\n   (one line)
//
// The volume path is the seed-derived, unguessable directory name and MUST
// NOT travel in argv: /proc/<pid>/cmdline is world-readable, and the
// sandvmm identity (987) shares the prov host — a compromised FUSE daemon
// would otherwise harvest every tenant's real directory name during a
// create. stdin is private to the hook process.
//
// exit 0 = stamped (any stdout is dropped); nonzero or timeout = ErrQuotaStamp
// (with the exit status and a truncated output tail for the node log). The
// hook runs as this daemon's identity (sandprov on prov instances) under the
// create op's context.
//
// The CONTRACT belongs to the storage plane — sandswap deliberately ships no
// backend implementation: a quota is only enforceable where 100% of writes
// land (the storage system sees agent writes through virtio-fs AND the
// prov instances' own host-side writes; no sandswap layer sees both). A hook
// maps the one thing sandswap knows — which directory belongs to which
// sandfs — onto the backend's quota primitive: CephFS
// `ceph.quota.max_bytes`, an XFS project-ID assignment, a ZFS dataset
// property, or an external quota manager's CLI. Owner ruling: the concrete
// implementation is the storage operator's, not the tree's.
func runQuotaStampCmd(ctx context.Context, cmd, volPath, sandfsID string) error {
	if cmd == "" {
		return nil
	}
	cctx, cancel := context.WithTimeout(ctx, quotaStampDeadline)
	defer cancel()
	c := exec.CommandContext(cctx, cmd, sandfsID)
	c.Stdin = strings.NewReader(volPath + "\n")
	out, err := c.CombinedOutput()
	if cctx.Err() == context.DeadlineExceeded {
		return fmt.Errorf("%w: quota hook %s timed out after %s (last output: %q)",
			ErrQuotaStamp, cmd, quotaStampDeadline, truncateOut(out))
	}
	if err != nil {
		return fmt.Errorf("%w: quota hook %s exited with %v (output: %q)",
			ErrQuotaStamp, cmd, err, truncateOut(out))
	}
	return nil
}

func truncateOut(out []byte) string {
	s := strings.TrimSpace(string(out))
	if len(s) > quotaStampOutputLimit {
		s = s[len(s)-quotaStampOutputLimit:]
	}
	return s
}

// stampQuota is the EnsureVolume call site seam (also the test seam: tests
// substitute it to avoid exec'ing real binaries). An empty command is a
// deliberate no-op — stamping is opt-in per deployment.
var stampQuota = runQuotaStampCmd

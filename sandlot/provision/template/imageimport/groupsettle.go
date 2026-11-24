// Copyright 2026 Chaoyi Huang. All rights reserved.
//
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE file at the root of this repository.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, the additional use grants set forth in
// that Business Source License, as applicable, are revoked.

package imageimport

import (
	"fmt"
	"os"
	"syscall"

	"sandlot/provision/template"
)

// settlePublishedGroup closes the GROUP side of the template contract on a
// freshly published tree (see template/groupaudit.go for the doctrine).
//
// normalize guarantees the group BITS; this pass guarantees the group
// NUMBER: the tree is settled to the gid of the output root — the directory
// a scan root watches, whose group IS the deployment's shared group — or to
// an explicit --group (numeric gid used as-is for cross-host preparation,
// name resolved on this host). Anyone who could publish into the root can
// settle into its group: root chgrps anything, and a group member chgrps
// their own files to a group they belong to. A settle failure is therefore
// never silently skipped — it is a loud error with the manual fix.
//
// After settling, the tree is re-audited: any group-grant-reliant entry
// still carrying a foreign gid fails the import (the tree stays published —
// immutable refs — but the operator is told exactly what to chgrp).
func settlePublishedGroup(tree, outRoot, groupSpec string, logf func(format string, args ...any)) ([]string, error) {
	var warnings []string

	wantGid := -1
	switch {
	case groupSpec != "":
		gid, err := template.ResolveGroupSpec(groupSpec)
		if err != nil {
			return warnings, fmt.Errorf("--group: %w", err)
		}
		wantGid = gid
	default:
		fi, err := os.Stat(outRoot)
		if err != nil {
			return warnings, fmt.Errorf("settle group: stat output root: %w", err)
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			return warnings, fmt.Errorf("settle group: %s carries no stat information", outRoot)
		}
		wantGid = int(st.Gid)
		if fi.Mode()&os.ModeSetgid == 0 {
			// A deployment scan root is setgid (the chain gives every tree
			// below it the shared group at creation). A private, non-setgid
			// output root means the invoker's group was used instead — which
			// works only until the tree is copied into the shared root
			// (cp -a preserves the invoker's group and every reliant entry
			// EACCESes). Say so now, at the place the choice was made.
			warnings = append(warnings, fmt.Sprintf("the output root %s is not setgid — the tree was settled to its group (gid %d); if this tree will be moved into the deployment's shared scan root, that copy does NOT preserve the group: publish there directly, or re-settle with chgrp -R <shared gid> (or pass --group)", outRoot, wantGid))
			if logf != nil {
				logf("%s", warnings[len(warnings)-1])
			}
		}
	}

	audit, err := template.AuditGroupGrants(tree, wantGid)
	if err != nil {
		return warnings, fmt.Errorf("settle group: audit %s: %w", tree, err)
	}
	if len(audit.Unreachable) > 0 {
		return warnings, fmt.Errorf("settle group: %s has subtrees the audit cannot list as the current identity (%s) — the tree was just extracted by this identity, so this is unexpected; inspect manually: %s", tree, audit.Unreachable[0].Err, audit.Unreachable[0].Path)
	}

	if len(audit.WrongGroup) > 0 {
		changed, cerr := template.SettleTreeGroup(tree, wantGid)
		if cerr != nil {
			return warnings, fmt.Errorf("settle group: the tree carries entries whose gid is not %d and settling failed — run as root or as a member of that group, or fix manually with: chgrp -R %d %s (%w)", wantGid, wantGid, tree, cerr)
		}
		if logf != nil {
			logf("settled the tree's group to gid %d (%d entries changed)", wantGid, changed)
		}
		// The settle may have failed to reach everything it listed as wrong
		// only by erroring — which returns above — so a clean settle plus a
		// re-audit is the belt-and-braces verification.
		audit, err = template.AuditGroupGrants(tree, wantGid)
		if err != nil {
			return warnings, fmt.Errorf("settle group: re-audit %s: %w", tree, err)
		}
		if len(audit.WrongGroup) > 0 {
			return warnings, fmt.Errorf("settle group: %s still carries group-grant entries outside gid %d after settling (e.g. %s) — fix manually with: chgrp -R %d %s", tree, wantGid, audit.WrongGroup[0], wantGid, tree)
		}
	}

	if audit.Reliant > 0 {
		w := fmt.Sprintf("%d entries rely on the group grant (a file without other-read, or a directory without other-list/traverse); their group is gid %d — when moving this tree to a differently-numbered host, re-settle with: chgrp -R <that host's shared gid> (numbers only, see its /etc/sandswap/identity.env)",
			audit.Reliant, wantGid)
		warnings = append(warnings, w)
		if logf != nil {
			logf("%s", w)
		}
	}
	return warnings, nil
}

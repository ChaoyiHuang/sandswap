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

package template

import (
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
)

// The GROUP side of the template contract. NormalizeTemplateTree grants the
// group bits (dirs g+rx, files mirror their owner r/x), and the grant is
// carried by ONE number: the tree's group must be the deployment's shared
// group (the group of the scan root / template store), because the consuming
// identities — the prov instance that copies flat templates, the exec sandlot
// that mounts overlay lowerdirs, and the sandvmm FUSE daemon that performs
// every guest read — hold the shared group as a supplementary group and are
// never the tree's owner. Group NAMES carry per-host variance
// (preflight/vmmgroups.go states the same doctrine); the numbers are the
// contract, which is why ResolveGroupSpec accepts both but the numeric form
// is never resolved against the local group database.

// ResolveGroupSpec turns a --group / --expect-group argument into a gid.
// A numeric argument ("984") is used AS-IS — no local group of that number
// needs to exist, which is exactly what preparing a tree on one host for a
// differently-numbered deployment requires. A name ("sandlot") is resolved
// against THIS machine's group database at invocation time — correct only
// when the command runs on the machine that will serve the tree. A name that
// does not resolve is a hard error (unlike vmm_groups' warn-and-skip "kvm":
// there a missing group fails loudly at the first VM create; here the group
// IS the grant, and skipping would silently produce an unreadable template).
func ResolveGroupSpec(spec string) (int, error) {
	if spec == "" {
		return 0, fmt.Errorf("empty group specification")
	}
	if gid, err := strconv.Atoi(spec); err == nil {
		if gid < 0 || uint64(gid) > 0xFFFFFFFF {
			return 0, fmt.Errorf("group id %q out of range", spec)
		}
		return gid, nil
	}
	g, err := user.LookupGroup(spec)
	if err != nil {
		return 0, fmt.Errorf("group name %q does not resolve on this host (pass the numeric gid for cross-host preparation: see the target's /etc/sandswap/identity.env)", spec)
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return 0, fmt.Errorf("group %q resolves to a non-numeric gid %q", spec, g.Gid)
	}
	return gid, nil
}

// GroupGrantAudit is the result of auditing a tree's group-dependent entries.
type GroupGrantAudit struct {
	// Reliant is the number of entries whose readability rides on the group
	// grant: directories lacking EITHER other-traverse (o+x — path
	// resolution) OR other-list (o+r — the daemon's readdir, every guest
	// `ls`), and regular files without other-read (o+r — the daemon reads
	// content on behalf of the guest). Entries carrying both other bits
	// never need the group, whatever their gid.
	Reliant int
	// WrongGroup lists (bounded) reliant entries whose gid differs from the
	// expected one — each is EACCES for the consuming service identities.
	WrongGroup []string
	// Unreachable lists (bounded) subtrees the walk could not enter — a
	// directory this identity cannot list — each with the error that stopped
	// it. The grant analysis below such a subtree is unjudged.
	Unreachable []UnreachablePath
}

// UnreachablePath names a subtree the audit could not enter and why.
type UnreachablePath struct {
	Path string
	Err  error
}

func (u UnreachablePath) String() string { return u.Path + ": " + u.Err.Error() }

// AuditGroupGrants walks root and reports which entries depend on the
// group grant and which of those carry the wrong gid. expectGid < 0
// disables the wrong-gid comparison (reliant/unreachable are still counted).
// The per-entry stats are lstat, but DISCOVERING the entries needs readdir
// on every parent: a directory the caller cannot list (a 0700 /root owned
// by someone else) surfaces in Unreachable, never as a silent pass.
// skipDir, when non-nil, is consulted for every DIRECTORY below the root
// (the root itself is always walked); a true return prunes that subtree —
// the store audit uses it for writer-internal staging, which is mid-flight
// by definition and must not be judged.
func AuditGroupGrants(root string, expectGid int) (*GroupGrantAudit, error) {
	return AuditGroupGrantsSkipping(root, expectGid, nil)
}

// AuditGroupGrantsSkipping is AuditGroupGrants with a directory prune
// predicate (see skipDir there).
func AuditGroupGrantsSkipping(root string, expectGid int, skipDir func(path string, d fs.DirEntry) bool) (*GroupGrantAudit, error) {
	if fi, err := os.Lstat(root); err != nil {
		return nil, err
	} else if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
		return nil, fmt.Errorf("group-audit root %s is not a real directory", root)
	}
	a := &GroupGrantAudit{}
	keepPath := func(list []string, p string) []string {
		if len(list) < 10 {
			return append(list, p)
		}
		return list
	}
	keepUnreachable := func(list []UnreachablePath, u UnreachablePath) []UnreachablePath {
		if len(list) < 10 {
			return append(list, u)
		}
		return list
	}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			// A subtree the walker cannot enter: record and keep going —
			// sibling findings remain reportable.
			a.Unreachable = keepUnreachable(a.Unreachable, UnreachablePath{Path: path, Err: walkErr})
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return nil // symlink modes are ignored on Linux
		}
		if skipDir != nil && path != root && d.IsDir() && skipDir(path, d) {
			return fs.SkipDir
		}
		info, err := d.Info()
		if err != nil {
			a.Unreachable = keepUnreachable(a.Unreachable, UnreachablePath{Path: path, Err: err})
			return nil
		}
		var reliant bool
		switch {
		case info.IsDir():
			// Both other bits must be present for the group to be irrelevant:
			// o+x lets a non-member resolve paths THROUGH the directory, but
			// the daemon's readdir (every guest `ls`) still needs o+r — a
			// 0751 directory with a foreign gid is traversable yet unlistable.
			reliant = info.Mode().Perm()&(0o005) != 0o005 // needs o+r AND o+x
		case info.Mode().IsRegular():
			reliant = info.Mode().Perm()&0o004 == 0 // no other-read
		default:
			return nil // FIFOs/sockets/devices are never read through the daemon
		}
		if !reliant {
			return nil
		}
		a.Reliant++
		if expectGid >= 0 {
			if st, ok := info.Sys().(*syscall.Stat_t); !ok || int(st.Gid) != expectGid {
				a.WrongGroup = keepPath(a.WrongGroup, path)
			}
		}
		return nil
	})
	if err != nil {
		return a, err
	}
	return a, nil
}

// SettleTreeGroup chgrp's every real entry under root to gid (owner is never
// touched — the contract keeps trees owner-write-only, and a stable owner
// such as root is collision-proof across differently-numbered hosts). Only
// entries whose gid already differs are chown'ed, so a no-op pass stays a
// literal no-op. chown(2) is allowed to clear the set-user-ID/set-group-ID
// bits of a file whose group changed (and some platforms clear them even
// for privileged callers), so the chown'd entry's mode is re-applied when
// it carried special bits — contract rule 3 ("preserved as authored") must
// not depend on the ambient capability quirk. Symlinks are skipped: their
// mode is ignored by Linux and chown would follow the link.
func SettleTreeGroup(root string, gid int) (changed int, err error) {
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.Type()&(fs.ModeSymlink|fs.ModeNamedPipe|fs.ModeSocket|fs.ModeDevice) != 0 {
			return nil
		}
		info, ierr := d.Info()
		if ierr != nil {
			return ierr
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return nil
		}
		if int(st.Gid) == gid {
			return nil
		}
		mode := info.Mode()
		if cerr := os.Chown(path, -1, gid); cerr != nil {
			return fmt.Errorf("chgrp %s to %d: %w", path, gid, cerr)
		}
		if mode&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
			if rerr := os.Chmod(path, mode); rerr != nil {
				return fmt.Errorf("restore %s mode %v after chgrp to %d: %w", path, mode.Perm(), gid, rerr)
			}
		}
		changed++
		return nil
	})
	return changed, err
}

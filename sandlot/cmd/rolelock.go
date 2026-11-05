// Copyright 2026 Chaoyi Huang. All rights reserved.
//
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE file at the root of this repository.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, sandswap's use of this software will be governed
// by the Apache License, Version 2.0.

package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// roleLockPath is the one-sandlot-per-host lock. /run/sandswap is shared by
// every service identity (root:sandlot 2770) so both exec (985) and prov
// (983) instances can hold it. Var (not const) so tests can point it at a
// temp directory.
var roleLockPath = "/run/sandswap/sandlot.role"

// acquireRoleLock enforces the host rule: AT MOST ONE sandlot process per
// host, its roles declared in its own config. The three blessed shapes are
// exec-only (compute host), prov-only (provision host), and exec,prov merged
// (single-node / all-in-one). Two SEPARATE role processes on one host is not
// a shape: process isolation would provide zero resource isolation (the
// NFS/NIC contention is host-level), and the duplicate would collide on
// node-identity state.
//
// allowColocated disables the single-instance rule for the two layouts that
// legitimately need more than one process on a host: the simulation scripts
// (N instances on one machine), and the one-machine-etcd deploy's exec+prov
// PAIR — split gateways give a merged instance no single address to dial, so
// the two roles must span two processes there. A DUPLICATE node_id is
// refused even then — that is a real error in every mode.
//
// The returned release func must be kept for the process lifetime (the flock
// is the lock); it is nil when enforcement was skipped.
func acquireRoleLock(logger *log.Logger, nodeID string, roles []string, allowColocated bool) (func(), error) {
	if err := os.MkdirAll(filepath.Dir(roleLockPath), 0o770); err != nil && !os.IsExist(err) {
		return nil, fmt.Errorf("role-lock: create %s: %w", filepath.Dir(roleLockPath), err)
	}
	// O_NOFOLLOW: the runtime dir is group-writable, so a sibling could plant
	// a symlink at the lock path and turn the open (and the later
	// truncate/write) into an arbitrary-file operation.
	f, err := os.OpenFile(roleLockPath, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o660)
	if err != nil {
		return nil, fmt.Errorf("role-lock: open %s: %w", roleLockPath, err)
	}
	var lst syscall.Stat_t
	if err := syscall.Fstat(int(f.Fd()), &lst); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("role-lock: fstat %s: %w", roleLockPath, err)
	}
	if lst.Mode&syscall.S_IFMT != syscall.S_IFREG {
		_ = f.Close()
		return nil, fmt.Errorf("role-lock: %s is not a regular file", roleLockPath)
	}
	if uid := uint32(os.Geteuid()); lst.Uid != uid && lst.Uid != 0 {
		_ = f.Close()
		return nil, fmt.Errorf("role-lock: %s owned by uid %d, want %d or root", roleLockPath, lst.Uid, uid)
	}
	// Group-writable from birth for whoever creates it first: host prep
	// pre-creates the file root:sandlot 0660, but a scratch dev run may let
	// the first instance create it (umask would strip the group-write bit and
	// lock the OTHER identity out of opening it at all). Chmod is best-effort
	// — only the owner or root can chmod.
	_ = f.Chmod(0o660)

	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		// Held by another live instance: identify it from its recorded line
		// ("pid|node_id|roles") and apply the rule. Read through the SAME fd
		// (never the path again).
		_, _ = f.Seek(0, io.SeekStart)
		other, _ := io.ReadAll(io.LimitReader(f, 4096))
		fields := strings.SplitN(strings.TrimSpace(string(other)), "|", 3)
		otherNode, otherRoles := "?", "?"
		if len(fields) == 3 {
			otherNode, otherRoles = fields[1], fields[2]
		}
		if otherNode == nodeID {
			_ = f.Close()
			return nil, fmt.Errorf("role-lock: node_id %q is already running on this host (pid %s) — node ids must be unique; on a single-sandlot host the id is the hostname", nodeID, fields[0])
		}
		if !allowColocated {
			_ = f.Close()
			return nil, fmt.Errorf("role-lock: this host already runs a sandlot instance (node %q, roles [%s]) — at most ONE sandlot process per host.\n"+
				"  The blessed shapes: exec-only (compute host) | prov-only (provision host) | merged via -roles exec,prov (single-node).\n"+
				"  Multi-process-per-host requires the explicit -allow-colocated-instances admission (the simulation scripts and the one-machine-etcd deploy's exec+prov pair use it; nothing else), with distinct node ids.", otherNode, otherRoles)
		}
		// Simulation mode: proceed without holding the lock.
		logger.Printf("WARNING: -allow-colocated-instances — co-existing with node %q (roles [%s]); permitted for the one-machine exec+prov pair and simulations", otherNode, otherRoles)
		_ = f.Close()
		return nil, nil
	}

	if err := f.Truncate(0); err == nil {
		_, _ = f.WriteAt([]byte(fmt.Sprintf("%d|%s|%s\n", os.Getpid(), nodeID, strings.Join(roles, ","))), 0)
	}
	logger.Printf("role-lock held: node %q roles [%s] (one sandlot process per host)", nodeID, strings.Join(roles, ","))
	return func() { _ = f.Close() }, nil
}

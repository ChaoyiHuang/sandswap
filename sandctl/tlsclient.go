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
	"syscall"
)

// checkClientKeyFile enforces the deployment's credential-isolation contract
// for a caller-supplied TLS client key. The deployers scope every service
// private key to the identity that loads it (sandserv/sandlot, 0640/0600); a
// client command must never be able to borrow one of those keys. A key that is
// group/world accessible, owned by another identity, or reached through a
// symlink is refused by name instead of being handed to the TLS stack.
//
// The CA certificate is PUBLIC material (0644) and is not checked here.
func checkClientKeyFile(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("client key %s: %w", path, err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("client key %s is a symlink — point --client-key at the key file itself", path)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("client key %s is not a regular file (mode %s)", path, fi.Mode())
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("client key %s has mode %04o (group/world access) — client keys must be 0600; "+
			"service identities' keys are never valid client credentials", path, perm)
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && !trustedRunFileOwner(st.Uid) {
		return fmt.Errorf("client key %s is owned by uid %d, neither the invoking uid %d nor root — refusing to load another identity's key",
			path, st.Uid, os.Geteuid())
	}
	return nil
}

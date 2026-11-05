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

// Package hostbin pins the absolute paths of the host utilities sandlot,
// boxout, and the prov instance execute.
//
// Why: these processes run with real privilege (sandlot has NET_ADMIN +
// SYS_ADMIN, boxout is root, prov owns the storage tree). A bare
// exec.Command("nft"/"setpriv") resolves through PATH, so any writable
// directory ahead of the system paths is a code-execution vector for the
// corresponding identity. Init resolves each tool once at startup from a
// fixed candidate list (plus a LookPath fallback that only accepts an
// absolute result); call sites then use Path(), which never re-reads PATH
// after a successful Init.
//
// Link/TAP lifecycle and file copies do NOT use this package: they are
// syscalls/APIs (tap_linux.go's ioctls + RTM_DELLINK, copyfs.CopyDirRecursive),
// not process spawns.
package hostbin

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
)

// candidates is the fixed search order per tool. The common distro locations
// cover merged-/usr and split-/usr layouts; the LookPath fallback exists for
// unusual images but must return an absolute path.
var candidates = map[string][]string{
	"nft":           {"/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft", "/bin/nft"},
	"setpriv":       {"/usr/bin/setpriv", "/bin/setpriv", "/usr/sbin/setpriv", "/sbin/setpriv"},
	"vsockguardctl": {"/usr/local/bin/vsockguardctl", "/sandswap/vsockguardctl", "/usr/bin/vsockguardctl", "/bin/vsockguardctl"},
}

var (
	mu       sync.Mutex
	resolved = map[string]string{}
	inited   bool
)

// Init resolves every pinned tool that exists on this host. Missing tools are
// left unresolved: a prov-only host legitimately lacks nft/ip, and a role's
// call site (BuildProvider, launcher, template save) reports the requirement
// it actually has. Call once at process startup.
func Init() {
	mu.Lock()
	defer mu.Unlock()
	for name, paths := range candidates {
		if p, err := resolve(name, paths); err == nil {
			resolved[name] = p
		}
	}
	inited = true
}

// Require returns a startup error naming every requested tool that could not
// be resolved. Roles that unconditionally need a tool call this after Init.
func Require(names ...string) error {
	var missing []string
	for _, name := range names {
		if Path(name) == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	return fmt.Errorf("required host binaries not found: %v (absolute paths tried: %v)", missing, candidates)
}

// Path returns the pinned absolute path for name. Before Init (tests, small
// utility mains) it resolves once through PATH, but only accepts an absolute
// result; production mains call Init first.
func Path(name string) string {
	mu.Lock()
	defer mu.Unlock()
	if p, ok := resolved[name]; ok {
		return p
	}
	if p, err := exec.LookPath(name); err == nil && filepath.IsAbs(p) {
		// Do NOT cache the fallback: production calls Init once and then uses
		// the pinned map; tests legitimately change PATH between cases, and a
		// cached fallback would leak one test's tool into another's.
		return p
	}
	return ""
}

// MustPath is Path plus a startup error naming the missing tool.
func MustPath(name string) (string, error) {
	if p := Path(name); p != "" {
		return p, nil
	}
	return "", fmt.Errorf("required host binary %q not found (absolute paths tried: %v)", name, candidates[name])
}

func resolve(name string, paths []string) (string, error) {
	for _, p := range paths {
		if executable(p) {
			return p, nil
		}
	}
	if p, err := exec.LookPath(name); err == nil && filepath.IsAbs(p) {
		return p, nil
	}
	return "", fmt.Errorf("required host binary %q not found (absolute paths tried: %v; PATH lookup did not yield an absolute path)", name, paths)
}

func executable(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.Mode().IsRegular() && st.Mode()&0o111 != 0
}

// Initialized reports whether Init completed (diagnostics/tests).
func Initialized() bool {
	mu.Lock()
	defer mu.Unlock()
	return inited
}

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

package runtime

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// TestLoadOrCreateClientToken pins the per-pod admission-token lifecycle:
// first start mints a 64-hex-character token (mode 0400, owned by the
// sandlot uid), a restart REUSES a valid existing token (a boxout restart
// must not invalidate the sandlot's copy), and a malformed file is refused
// rather than silently reminted (the pair must fail closed, not diverge).
func TestLoadOrCreateClientToken(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("token chown to the sandlot uid requires root")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "client-token")

	tok, err := LoadOrCreateClientToken(path, 1001)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if len(tok) != 64 || strings.Trim(tok, "0123456789abcdef") != "" {
		t.Fatalf("minted token %q is not 64 hex characters", tok)
	}
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o400 {
		t.Fatalf("token mode = %04o, want 0400 (readable only by the sandlot uid)", fi.Mode().Perm())
	}
	if stat, ok := fi.Sys().(*syscall.Stat_t); !ok || stat.Uid != 1001 {
		t.Fatalf("token must be owned by the sandlot uid 1001")
	}

	// A restart reuses the existing valid token.
	tok2, err := LoadOrCreateClientToken(path, 1001)
	if err != nil {
		t.Fatalf("reuse: %v", err)
	}
	if tok2 != tok {
		t.Fatalf("restart minted a new token (%q != %q) — the sandlot copy is now invalid", tok2, tok)
	}

	// A malformed file is a loud refusal, never a silent remint.
	if err := os.WriteFile(path, []byte("not-hex"), 0o400); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateClientToken(path, 1001); err == nil ||
		!strings.Contains(err.Error(), "malformed") {
		t.Fatalf("malformed token file must be refused, got %v", err)
	}

	// A valid-hex-but-wrong-length value is equally malformed.
	if err := os.WriteFile(path, []byte("abcd"), 0o400); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateClientToken(path, 1001); err == nil {
		t.Fatal("32-hex-character token (16 bytes) must be refused — the token is a SHA-256 sized secret")
	}
}

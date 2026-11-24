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
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestResolveGroupSpecNumeric(t *testing.T) {
	for _, spec := range []string{"0", "984", "65534"} {
		gid, err := ResolveGroupSpec(spec)
		if err != nil || gid == 0 && spec != "0" {
			t.Fatalf("numeric %q: gid=%d err=%v", spec, gid, err)
		}
	}
	for _, spec := range []string{"-1", "4294967296"} {
		if _, err := ResolveGroupSpec(spec); err == nil {
			t.Fatalf("out-of-range %q accepted", spec)
		}
	}
}

func TestResolveGroupName(t *testing.T) {
	// "root" exists on every POSIX host; the resolved gid must be 0.
	gid, err := ResolveGroupSpec("root")
	if err != nil {
		t.Fatalf("root group does not resolve: %v", err)
	}
	if gid != 0 {
		t.Fatalf("root group resolves to gid %d, want 0", gid)
	}
	if _, err := ResolveGroupSpec("no-such-group-xyz"); err == nil {
		t.Fatal("unknown group name accepted")
	}
}

// auditFixture builds a tree whose group-grant dependency is exactly known:
// open/ and its file carry the other bits (never reliant); locked/ lacks
// other-traverse and both files under it lack other-read (3 reliant entries).
func auditFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "open"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "open", "f.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "locked"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "locked", "secret"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "locked", "also"), []byte("x"), 0o640); err != nil {
		t.Fatal(err)
	}
	// A symlink whose target mode is restrictive must not be counted: Linux
	// ignores symlink modes, and the audit must not follow the link.
	if err := os.Symlink(filepath.Join(root, "locked", "secret"), filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	return root
}

func treeGid(t *testing.T, path string) int {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		t.Skip("no stat_t available")
	}
	return int(st.Gid)
}

func TestAuditGroupGrantsCounts(t *testing.T) {
	root := auditFixture(t)
	a, err := AuditGroupGrants(root, treeGid(t, root))
	if err != nil {
		t.Fatal(err)
	}
	if a.Reliant != 3 {
		t.Fatalf("Reliant = %d, want 3 (locked/ dir + 2 files without other bits)", a.Reliant)
	}
	if len(a.WrongGroup) != 0 || len(a.Unreachable) != 0 {
		t.Fatalf("expected-group match: wrong=%v unreachable=%v", a.WrongGroup, a.Unreachable)
	}

	// A foreign expected gid must flag exactly the reliant entries.
	other := treeGid(t, root) + 1000
	a, err = AuditGroupGrants(root, other)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.WrongGroup) != 3 {
		t.Fatalf("foreign expected gid: WrongGroup = %v, want the 3 reliant entries", a.WrongGroup)
	}
	for _, p := range a.WrongGroup {
		if filepath.Base(p) == "f.txt" || filepath.Base(p) == "link" {
			t.Fatalf("non-reliant entry flagged: %s", p)
		}
	}

	// expectGid < 0 disables the comparison but keeps the counting.
	a, err = AuditGroupGrants(root, -1)
	if err != nil {
		t.Fatal(err)
	}
	if a.Reliant != 3 || len(a.WrongGroup) != 0 {
		t.Fatalf("disabled comparison: Reliant=%d Wrong=%v", a.Reliant, a.WrongGroup)
	}

	if _, err := AuditGroupGrants(filepath.Join(root, "link"), -1); err == nil {
		t.Fatal("symlink root accepted")
	}
}

// TestAuditGroupGrantsDirectoryNeedsBothOtherBits pins the directory rule:
// o+x alone is NOT enough — the daemon's readdir (every guest `ls`) needs
// o+r too. A 0751 directory (traversable, unlistable) with a foreign gid
// must be flagged; only 0755 (both other bits) is free of the group.
func TestAuditGroupGrantsDirectoryNeedsBothOtherBits(t *testing.T) {
	root := t.TempDir()
	for _, m := range []os.FileMode{0o755, 0o751, 0o750} {
		if err := os.Mkdir(filepath.Join(root, fmt.Sprintf("d%o", m)), m); err != nil {
			t.Fatal(err)
		}
	}
	// The temp root carries the test user's gid; expect a foreign one so
	// every reliant entry lands in WrongGroup.
	foreign := treeGid(t, root) + 1000
	a, err := AuditGroupGrants(root, foreign)
	if err != nil {
		t.Fatal(err)
	}
	if a.Reliant != 2 {
		t.Fatalf("Reliant = %d, want 2 (0751 and 0750; 0755 needs no group)", a.Reliant)
	}
	var flagged751 bool
	for _, p := range a.WrongGroup {
		if filepath.Base(p) == "d751" {
			flagged751 = true
		}
		if filepath.Base(p) == "d755" {
			t.Fatalf("0755 directory flagged as group-reliant: %s", p)
		}
	}
	if !flagged751 {
		t.Fatalf("0751 directory (o+x without o+r) not flagged: %v", a.WrongGroup)
	}
}

// TestAuditGroupGrantsSkipping pins the prune predicate: a skipped directory
// and everything under it are never counted, its siblings still are, the
// root itself is never pruned (even if the predicate says so), and a symlink
// pointing INTO the skipped subtree is still just a symlink (never followed,
// never counted — symlink handling is independent of the prune).
func TestAuditGroupGrantsSkipping(t *testing.T) {
	root := t.TempDir()
	mk := func(rel string, m os.FileMode) string {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(p, m); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, m); err != nil {
			t.Fatal(err)
		}
		return p
	}
	mk("staging-x/etc", 0o750) // pruned: 1 dir + the file below = would be 2 reliant
	mk("published/etc", 0o750) // kept: 2 reliant dirs
	write := func(rel string, m os.FileMode) {
		if err := os.WriteFile(filepath.Join(root, rel), []byte("x"), m); err != nil {
			t.Fatal(err)
		}
	}
	write("staging-x/etc/shadow", 0o640)
	write("published/etc/shadow", 0o640)
	// A symlink into the pruned subtree: the walk sees it (parent is listable)
	// and must skip it as a symlink regardless of the prune.
	if err := os.Symlink(filepath.Join(root, "staging-x", "etc", "shadow"), filepath.Join(root, "link-into-staging")); err != nil {
		t.Fatal(err)
	}
	skip := func(path string, d fs.DirEntry) bool {
		return d.IsDir() && strings.HasPrefix(d.Name(), "staging-")
	}
	a, err := AuditGroupGrantsSkipping(root, -1, skip)
	if err != nil {
		t.Fatal(err)
	}
	// published/ + published/etc = 2 dirs; 1 file under published/etc.
	if a.Reliant != 3 {
		t.Fatalf("Reliant = %d, want 3 (pruned subtree must not count)", a.Reliant)
	}
	if len(a.Unreachable) != 0 {
		t.Fatalf("Unreachable = %v, want none", a.Unreachable)
	}
	// The root is never pruned even when the predicate matches its name:
	// a predicate that would prune EVERYTHING still yields the root's own
	// children — here that is the unpruned full count (the TempDir root is
	// 0755, so it never counts as reliant either way).
	rootName := filepath.Base(root)
	a, err = AuditGroupGrantsSkipping(root, -1, func(path string, d fs.DirEntry) bool {
		return d.Name() == rootName
	})
	if err != nil {
		t.Fatal(err)
	}
	// published/ + published/etc + shadow, staging-x/ + staging-x/etc + shadow.
	if a.Reliant != 6 {
		t.Fatalf("root pruned by its own name: Reliant = %d, want 6", a.Reliant)
	}
}

// TestSettleTreeGroup requires root (chown to a foreign gid); the repo's test
// batteries run as root, and non-root runs skip rather than fail.
func TestSettleTreeGroup(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-only (chown to a foreign gid)")
	}
	root := auditFixture(t)
	want := treeGid(t, root)
	foreign := want + 1000
	for _, p := range []string{filepath.Join(root, "locked"), filepath.Join(root, "locked", "secret")} {
		if err := os.Chown(p, -1, foreign); err != nil {
			t.Fatal(err)
		}
	}
	// A setuid file with the foreign gid: the settle changes its group, and
	// chown(2) may clear the special bits (some platforms clear them even
	// for privileged callers) — the settle must restore them (contract
	// rule 3: preserved as authored). The bits are set AFTER the chown that
	// plants the foreign gid, because that chown may itself clear them.
	su := filepath.Join(root, "locked", "su")
	if err := os.WriteFile(su, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(su, -1, foreign); err != nil {
		t.Fatal(err)
	}
	// 0o4755 is NOT a FileMode: the raw 0o4000 bit is silently dropped by
	// os.Chmod — ModeSetuid is 1<<23. Spell the mode out.
	if err := os.Chmod(su, os.FileMode(0o755)|os.ModeSetuid); err != nil {
		t.Fatal(err)
	}
	a, err := AuditGroupGrants(root, want)
	if err != nil {
		t.Fatal(err)
	}
	// The audit flags only RELIANT wrong-group entries (su at 0755|setuid
	// is world-readable, so it is not reliant); the settle chgrps EVERY
	// gid-differing entry — three here.
	if len(a.WrongGroup) != 2 {
		t.Fatalf("pre-settle audit: WrongGroup = %v, want 2", a.WrongGroup)
	}
	changed, err := SettleTreeGroup(root, want)
	if err != nil {
		t.Fatal(err)
	}
	if changed != 3 {
		t.Fatalf("changed = %d, want 3", changed)
	}
	if m := statMode(t, su); m&os.ModeSetuid == 0 || m.Perm() != 0o755 {
		t.Fatalf("setuid lost across a group-changing settle: mode = %v, want setuid|0755", m)
	}
	if got := treeGid(t, su); got != want {
		t.Fatalf("setuid file gid = %d after settle, want %d", got, want)
	}
	if a, err := AuditGroupGrants(root, want); err != nil {
		t.Fatal(err)
	} else if len(a.WrongGroup) != 0 {
		t.Fatal("post-settle audit still reports wrong-group entries")
	}
	// Idempotence: a second settle is a literal no-op.
	if changed, err := SettleTreeGroup(root, want); err != nil || changed != 0 {
		t.Fatalf("second settle: changed=%d err=%v, want 0/nil", changed, err)
	}
}

// TestSettleTreeGroupPreservesSetgidDir pins the DIRECTORY special-bit case:
// a setgid directory (the shape save-as-template layers and real distros
// carry, e.g. /var/local) whose gid changes must keep its setgid bit —
// chown clears it and the settle's mode restore is what brings it back.
func TestSettleTreeGroupPreservesSetgidDir(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-only (chown to a foreign gid)")
	}
	root := auditFixture(t)
	want := treeGid(t, root)
	foreign := want + 1000
	sg := filepath.Join(root, "setgid-dir")
	if err := os.Mkdir(sg, 0o755|os.ModeSetgid); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(sg, -1, foreign); err != nil {
		t.Fatal(err)
	}
	// The chown above may itself have cleared the bit (platform-dependent);
	// re-apply so the test starts from the authored shape.
	if err := os.Chmod(sg, 0o755|os.ModeSetgid); err != nil {
		t.Fatal(err)
	}
	if _, err := SettleTreeGroup(root, want); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(sg)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeSetgid == 0 {
		t.Fatal("setgid bit lost on the directory across the group-changing settle")
	}
	if got := int(fi.Sys().(*syscall.Stat_t).Gid); got != want {
		t.Fatalf("setgid dir gid = %d after settle, want %d", got, want)
	}
}

// statMode returns the FULL mode (Perm() alone would strip setuid/setgid/
// sticky — the very bits the assertions protect).
func statMode(t *testing.T, path string) fs.FileMode {
	t.Helper()
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode()
}

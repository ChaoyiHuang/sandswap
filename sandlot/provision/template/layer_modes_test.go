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

package template

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// Contract: overlay layers must be readable by every consumer identity
// through the shared group — the exec sandlot (985) mounts them as lowerdirs
// and the virtio-fs passthrough daemon (sandvmm 987, supplementary group =
// the sandlot shared group) performs each guest read. Raw tar modes without
// group bits (0700 dirs, 0600 files — agent-chmod'ed content, OCI images)
// would be EACCES inside every guest. See NormalizeTemplateTree.

func mustMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("lstat %s: %v", path, err)
	}
	if fi.Mode().Perm() != want {
		t.Errorf("%s: mode = %04o, want %04o", path, fi.Mode().Perm(), want)
	}
}

func TestNormalizeLayerModes(t *testing.T) {
	root := t.TempDir()
	mk := func(rel string, mode os.FileMode) string {
		t.Helper()
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		// Explicit chmod: MkdirAll applies the ambient umask, and this test
		// must hold under any umask (the premise rule — the probe runs
		// the suite under umask 077).
		if err := os.Chmod(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x"), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil { // umask-proof
			t.Fatal(err)
		}
		return p
	}
	mk("d700/f600", 0o600)
	mk("d700/f400", 0o400)
	mk("d700/f000", 0o000)
	mk("d700/f755", 0o755)
	mk("d755/f644", 0o644)
	mk("d750/f640", 0o640)
	if err := os.Chmod(filepath.Join(root, "d700"), 0o700); err != nil {
		t.Fatal(err)
	}
	// A setuid file must keep its bit across normalization.
	mk("d755/tool", 0o755)
	if err := os.Chmod(filepath.Join(root, "d755/tool"), 0o755|os.ModeSetuid); err != nil {
		t.Fatal(err)
	}
	// A symlink must be skipped (chmod would follow it).
	if err := os.Symlink("d700/f600", filepath.Join(root, "link600")); err != nil {
		t.Fatal(err)
	}

	if _, err := NormalizeTemplateTree(root); err != nil {
		t.Fatalf("NormalizeTemplateTree: %v", err)
	}

	mustMode(t, filepath.Join(root, "d700"), 0o750)      // dir g+rx
	mustMode(t, filepath.Join(root, "d700/f600"), 0o640) // u+r → g+r
	mustMode(t, filepath.Join(root, "d700/f400"), 0o440) // u+r → g+r
	mustMode(t, filepath.Join(root, "d700/f000"), 0o000) // deliberately inaccessible: untouched
	mustMode(t, filepath.Join(root, "d700/f755"), 0o755) // already fine
	mustMode(t, filepath.Join(root, "d755"), 0o755)
	mustMode(t, filepath.Join(root, "d755/f644"), 0o644)
	mustMode(t, filepath.Join(root, "d750/f640"), 0o640)
	fi, err := os.Lstat(filepath.Join(root, "d755/tool"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeSetuid == 0 {
		t.Error("setuid bit lost by normalization")
	}
	if fi.Mode().Perm() != 0o755 {
		t.Errorf("tool: mode = %04o, want 0755", fi.Mode().Perm())
	}
	// The symlink still points at the file (target untouched is asserted
	// above; here: the link itself was not replaced by a regular file).
	if fi, err := os.Lstat(filepath.Join(root, "link600")); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Errorf("symlink clobbered: mode=%v err=%v", fi.Mode(), err)
	}
}

// buildModesTar builds a tar.gz with the restrictive shapes a real image or
// agent-saved template carries.
func buildModesTar(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	add := func(hdr *tar.Header, body string) {
		t.Helper()
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if body != "" {
			if _, err := tw.Write([]byte(body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	add(&tar.Header{Name: "root/", Typeflag: tar.TypeDir, Mode: 0o755}, "")
	add(&tar.Header{Name: "root/private/", Typeflag: tar.TypeDir, Mode: 0o700}, "")
	add(&tar.Header{Name: "root/private/secret", Typeflag: tar.TypeReg, Mode: 0o600, Size: 6}, "s3cret")
	add(&tar.Header{Name: "root/etc/", Typeflag: tar.TypeDir, Mode: 0o755}, "")
	add(&tar.Header{Name: "root/etc/shadow", Typeflag: tar.TypeReg, Mode: 0o640, Size: 2}, "x\n")
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// TestExtractLayerModesGroupReadable runs the REAL overlay-layer pipeline
// (extractTarGzToDir with the layer options + NormalizeTemplateTree, exactly as
// extractLayersToCache wires them) and, when the pinned identities exist,
// proves the daemon identity (987, groups kvm+shared) can read every entry.
func TestExtractLayerModesGroupReadable(t *testing.T) {
	base := t.TempDir()
	for _, d := range []string{base, filepath.Dir(base)} {
		if err := os.Chmod(d, 0o755); err != nil { // t.TempDir() nests 0700 dirs
			t.Fatal(err)
		}
	}
	layersRoot := filepath.Join(base, "layers")
	if err := os.MkdirAll(layersRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	// Production shape: the template store is a setgid shared-group dir
	// (setup-host: install -d -m 2770 -o root -g sandlot), so every layer
	// entry inherits group=sandlot (985) — the grant the daemon reads through.
	if err := os.Chown(layersRoot, 0, 985); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(layersRoot, 0o770|os.ModeSetgid); err != nil {
		t.Fatal(err)
	}
	layerDir := filepath.Join(layersRoot, "sha256-probe")
	if err := os.MkdirAll(layerDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := materializeLayerFromTar(bytes.NewReader(buildModesTar(t)), layerDir); err != nil {
		t.Fatal(err)
	}

	mustMode(t, filepath.Join(layerDir, "root/private"), 0o750)
	mustMode(t, filepath.Join(layerDir, "root/private/secret"), 0o640)
	mustMode(t, filepath.Join(layerDir, "root/etc/shadow"), 0o640) // group bit was already there

	if os.Geteuid() != 0 {
		t.Log("not root: skipping the setpriv daemon-identity readability check")
		return
	}
	if _, err := user.LookupId("987"); err != nil {
		t.Skipf("sandvmm uid 987 absent on this host: %v", err)
	}
	for _, rel := range []string{"root", "root/private", "root/private/secret", "root/etc/shadow"} {
		p := filepath.Join(layerDir, rel)
		cmd := exec.Command("setpriv", "--reuid=987", "--regid=987", "--groups=985",
			"sh", "-c", "if [ -d \"$1\" ]; then ls \"$1\" >/dev/null; else cat \"$1\" >/dev/null; fi", "sh", p)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("daemon identity (987) cannot read %s: %v (%s)", rel, err, out)
		}
	}
}

// TestSaveAsTemplateNormalizesLayerModes pins the save path: a flat volume
// carrying restrictive modes (readable by the provision identity as owner —
// e.g. content copied from a pulled template) must still produce a
// group-readable layer.
func TestSaveAsTemplateNormalizesLayerModes(t *testing.T) {
	templatesDir := t.TempDir()
	overlayBase := t.TempDir()
	// Both store roots carry the production shape: setgid shared group
	// (the volumes root is 2770 root:sandlot, the template store 2770), so
	// volume content and layer entries inherit group=sandlot (985).
	for _, d := range []string{templatesDir, overlayBase} {
		if err := os.Chown(d, 0, 985); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(d, 0o770|os.ModeSetgid); err != nil {
			t.Fatal(err)
		}
	}
	// t.TempDir() nests 0700 root dirs; the daemon identity must be able to
	// traverse to the layer at all.
	if err := os.Chmod(filepath.Dir(templatesDir), 0o755); err != nil {
		t.Fatal(err)
	}
	m, err := NewManager(Config{TemplatesDir: templatesDir, OverlayBase: overlayBase, ResolveVolume: legacyResolver(overlayBase)})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	sandfsDir := filepath.Join(overlayBase, "modes-agent")
	if err := os.MkdirAll(filepath.Join(sandfsDir, "private"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sandfsDir, "private", "secret"), []byte("s3cret"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Content owned by the PROVISION identity with restrictive modes — the
	// shape a pulled template's content has in a flat volume (prov seeds it;
	// the guest cannot chmod foreign-owned files through the daemon). prov
	// reads it as owner; the FUSE daemon (987) does NOT own it and needs the
	// group bits the normalization must add.
	if err := os.Chown(filepath.Join(sandfsDir, "private"), 983, 985); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(sandfsDir, "private"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(filepath.Join(sandfsDir, "private", "secret"), 983, 985); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(sandfsDir, "private", "secret"), 0o600); err != nil {
		t.Fatal(err)
	}

	resp, err := m.SaveAsTemplate(context.Background(), "modes-agent", SaveAsTemplateRequest{TemplateRef: "modes:v1"})
	if err != nil {
		t.Fatalf("SaveAsTemplate: %v", err)
	}
	mustMode(t, filepath.Join(resp.Path, "private"), 0o750)
	mustMode(t, filepath.Join(resp.Path, "private", "secret"), 0o640)

	if os.Geteuid() != 0 {
		return
	}
	if _, err := user.LookupId("987"); err != nil {
		t.Skipf("sandvmm uid 987 absent on this host: %v", err)
	}
	p := filepath.Join(resp.Path, "private", "secret")
	if out, err := exec.Command("setpriv", "--reuid=987", "--regid=987", "--groups=985", "cat", p).CombinedOutput(); err != nil {
		t.Errorf("daemon identity (987) cannot read saved layer %s: %v (%s)", p, err, out)
	}
	// The on-disk uid/gid shape the contract expects (owner = materializer,
	// group = shared group via the setgid store) is asserted where the real
	// identities exist too.
	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("saved layer entry: mode=%04o uid=%d gid=%d", fi.Mode().Perm(), fi.Sys().(*syscall.Stat_t).Uid, fi.Sys().(*syscall.Stat_t).Gid)
}

// unreadablePaths powers the SaveAsTemplate failure diagnostic ("which paths
// can the provision identity not read"). Positive case needs a non-root
// reader, so it runs the test binary itself under setpriv as the prov
// identity (983) — the same trick the launcher tests use for the VMM child.
func TestUnreadablePaths(t *testing.T) {
	base := t.TempDir()
	for _, d := range []string{base, filepath.Dir(base)} {
		if err := os.Chmod(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(base, "open"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(base, "open"), 0o755); err != nil { // umask-proof fixture
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "open", "f"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(base, "open", "f"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := unreadablePaths(base, 5); len(got) != 0 {
		t.Errorf("readable tree reported unreadable paths: %v", got)
	}

	if os.Geteuid() != 0 {
		t.Skip("root needed to setpriv the positive case")
	}
	if _, err := user.LookupId("983"); err != nil {
		t.Skipf("sandprov uid 983 absent on this host: %v", err)
	}
	// Guest-restrictive shapes: a 0700 dir and a 0600 file owned by the
	// sandvmm identity (what an agent's chmod produces in a volume).
	priv := filepath.Join(base, "private")
	if err := os.MkdirAll(priv, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(priv, 987, 985); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(priv, 0o700); err != nil {
		t.Fatal(err)
	}
	// And a 0600 file inside a TRAVERSABLE dir: the file itself must be named
	// (an unreadable dir is reported instead of its contents — stat is
	// impossible there — so both shapes need separate coverage).
	vis := filepath.Join(base, "visible")
	if err := os.MkdirAll(vis, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(vis, 0o755); err != nil { // umask-proof fixture
		t.Fatal(err)
	}
	secret := filepath.Join(vis, "secret")
	if err := os.WriteFile(secret, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(secret, 987, 985); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(secret, 0o600); err != nil {
		t.Fatal(err)
	}

	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("setpriv", "--reuid=983", "--regid=983", "--groups=985",
		exe, "-test.run", "TestUnreadablePathsHelperProcess")
	cmd.Env = append(os.Environ(), "PROBE_UNREADABLE_ROOT="+base)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("helper as 983 failed: %v\n%s", err, out)
	}
	got := strings.TrimSpace(string(out))
	if !strings.Contains(got, filepath.Join("visible", "secret")) {
		t.Errorf("unreadablePaths as 983 did not report the 0600 file; got %q", got)
	}
	if !strings.Contains(got, "private") {
		t.Errorf("unreadablePaths as 983 did not report the 0700 dir; got %q", got)
	}
}

// TestUnreadablePathsHelperProcess is not a test: it is the setpriv child of
// TestUnreadablePaths, printing the paths unreadable to the identity it runs
// as.
func TestUnreadablePathsHelperProcess(t *testing.T) {
	root := os.Getenv("PROBE_UNREADABLE_ROOT")
	if root == "" {
		t.Skip("helper process only")
	}
	fmt.Println(strings.Join(unreadablePaths(root, 5), "\n"))
	os.Exit(0)
}

// The store's own dirs (layers/, refs/) sit on the cross-identity read path
// (exec sandlot reads refs and mounts layers; the FUSE daemon resolves
// through them). Their modes must not depend on the process umask — under a
// restrictive umask MkdirAll alone would leave them owner-only and every
// overlay mount on the node would EACCES.
func TestStoreDirsUmaskImmune(t *testing.T) {
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)
	dir := t.TempDir()
	if _, err := NewManager(Config{TemplatesDir: dir}); err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	for _, sub := range []string{"layers", "refs"} {
		fi, err := os.Stat(filepath.Join(dir, sub))
		if err != nil {
			t.Fatalf("stat %s: %v", sub, err)
		}
		if fi.Mode().Perm() != 0o750 {
			t.Errorf("%s mode = %04o under umask 077, want 2750 (group r-x, no other bits)", sub, fi.Mode().Perm())
		}
	}
	// A written ref file is read by the EXEC identity from the shared store:
	// group-readable regardless of umask.
	src := filepath.Join(dir, "src")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	m, err := NewManager(Config{TemplatesDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.RegisterFlatTemplate("umask:v1", src); err != nil {
		t.Fatalf("RegisterFlatTemplate: %v", err)
	}
	entries, err := os.ReadDir(filepath.Join(dir, "refs"))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range entries {
		fi, err := e.Info()
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o640 {
			t.Errorf("ref %s mode = %04o under umask 077, want 0640 (group-readable, no other bits)", e.Name(), fi.Mode().Perm())
		}
		found = true
	}
	if !found {
		t.Fatal("no ref file written")
	}
}

// TestExtractPreservesSpecialBitsAndSetgidChain pins two extraction-primitive
// contracts:
//  1. a tar's setuid/setgid/sticky bits land faithfully — os.FileMode(rawMode)
//     silently drops the raw 04000/02000/01000 values (Go's syscallMode maps
//     only its own Mode* flags), so a 04755 su used to materialize as 0755;
//  2. directories under a setgid parent STAY setgid — the template store is a
//     setgid chain and that chain is how every entry inherits the shared
//     GROUP the FUSE daemon reads through; an exact-bit chmod would break it
//     for every descendant (their group falls back to the extracting
//     process's gid).
func TestExtractPreservesSpecialBitsAndSetgidChain(t *testing.T) {
	store := filepath.Join(t.TempDir(), "store")
	if err := os.MkdirAll(store, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(store, 0o2775|os.ModeSetgid); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, hdr := range []*tar.Header{
		{Name: "bin/", Typeflag: tar.TypeDir, Mode: 0o755},
		{Name: "bin/su", Typeflag: tar.TypeReg, Mode: 0o4755, Size: 2},
		{Name: "tmp/", Typeflag: tar.TypeDir, Mode: 0o1777},
	} {
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if hdr.Size > 0 {
			if _, err := tw.Write([]byte("x\n")); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	layer := filepath.Join(store, "layers", "sha256-x")
	if err := os.MkdirAll(layer, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := materializeLayerFromTar(bytes.NewReader(buf.Bytes()), layer); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(filepath.Join(layer, "bin", "su"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeSetuid == 0 || fi.Mode().Perm() != 0o755 {
		t.Errorf("bin/su mode = %v, want setuid|0755 (tar 04755)", fi.Mode())
	}
	for _, rel := range []string{"bin", "tmp"} {
		fi, err := os.Lstat(filepath.Join(layer, rel))
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode()&os.ModeSetgid == 0 {
			t.Errorf("%s lost the store's setgid chain (mode=%v)", rel, fi.Mode())
		}
	}
	fi, err = os.Lstat(filepath.Join(layer, "tmp"))
	if err != nil {
		t.Fatal(err)
	}
	// The sticky bit survives, but the template contract is owner-write-only:
	// the tar's 0777 loses group/other write during normalization.
	if fi.Mode()&os.ModeSticky == 0 || fi.Mode().Perm() != 0o755 {
		t.Errorf("tmp mode = %v, want sticky|0755 (tar 01777 normalized)", fi.Mode())
	}
}

// TestValidateTemplateTree pins the validator as the executable form of the
// template contract: it must name EXACTLY the entries NormalizeTemplateTree
// would change (and normalization must drive the violation set to zero).
func TestValidateTemplateTree(t *testing.T) {
	root := t.TempDir()
	for _, d := range []string{root, filepath.Dir(root)} {
		if err := os.Chmod(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	mk := func(rel string, mode os.FileMode) string {
		t.Helper()
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x"), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	// Conformant entries (must NOT be reported).
	mk("ok/file644", 0o644)
	mk("ok/exec755", 0o755)
	okdir := filepath.Join(root, "okdir")
	if err := os.Mkdir(okdir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(okdir, 0o750); err != nil {
		t.Fatal(err)
	}
	// Violations (must be reported, each exactly once). The bad dir's mode is
	// set AFTER the mk calls — mk normalizes its parents to 0755.
	badFile := mk("bad/secret", 0o600)
	badExec := mk("bad/tool", 0o700)
	if err := os.Chmod(filepath.Join(root, "bad"), 0o700); err != nil {
		t.Fatal(err)
	}

	violations, err := ValidateTemplateTree(root)
	if err != nil {
		t.Fatalf("ValidateTemplateTree: %v", err)
	}
	got := map[string]bool{}
	for _, v := range violations {
		got[v.Path] = true
	}
	want := map[string]bool{filepath.Join(root, "bad"): true, badFile: true, badExec: true}
	for p := range want {
		if !got[p] {
			t.Errorf("validator missed %s", p)
		}
	}
	for p := range got {
		if !want[p] {
			t.Errorf("validator over-reported %s", p)
		}
	}
	if _, err := NormalizeTemplateTree(root); err != nil {
		t.Fatal(err)
	}
	if after, err := ValidateTemplateTree(root); err != nil || len(after) != 0 {
		t.Errorf("post-normalize violations = %d (err=%v), want 0", len(after), err)
	}
}

// The refs/ metadata tree belongs to the template metadata group
// (SANDSWAP_TPL_GROUP, default sandtmpl), NOT the shared volume group: the
// FUSE daemon reads layer content through the shared group and must not be
// able to enumerate refs. A numeric env value is used directly (k8s pods carry
// the GID through supplementalGroups and have no /etc/group entry).
// Root-only: chgrp needs CAP_CHOWN unless the process is already a member.
func TestRefsDirUsesTheTemplateMetadataGroup(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root for chgrp")
	}
	dir := t.TempDir()
	const gid = 65533
	t.Setenv("SANDSWAP_TPL_GROUP", "65533")
	if _, err := NewManager(Config{TemplatesDir: dir}); err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	fi, err := os.Stat(filepath.Join(dir, "refs"))
	if err != nil {
		t.Fatal(err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("no stat_t")
	}
	if int(st.Gid) != gid {
		t.Fatalf("refs gid = %d, want %d (metadata group)", st.Gid, gid)
	}
	if fi.Mode().Perm() != 0o750 {
		t.Fatalf("refs mode = %04o, want 2750", fi.Mode().Perm())
	}
	if fi.Mode()&os.ModeSetgid == 0 {
		t.Fatal("refs must stay setgid so ref files inherit the metadata group")
	}
}

// A numeric SANDSWAP_TPL_GROUP is parsed without a group-database lookup; a
// bogus name resolves to -1 (mode-only fallback, never a startup failure).
func TestTplGroupGIDResolution(t *testing.T) {
	t.Setenv("SANDSWAP_TPL_GROUP", "65534")
	if got := tplGroupGID(); got != 65534 {
		t.Fatalf("numeric group = %d, want 65534", got)
	}
	t.Setenv("SANDSWAP_TPL_GROUP", "definitely-not-a-group-xyz")
	if got := tplGroupGID(); got != -1 {
		t.Fatalf("absent group = %d, want -1", got)
	}
}

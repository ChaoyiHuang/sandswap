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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// makeRootfs builds a conformant busybox-style template tree: /bin/sh (a
// real executable file), the full skeleton, sys/tmp, group-accessible modes.
// The root itself is widened to 0755 (t.TempDir is 0700 and the contract
// walk includes the root; same fixture treatment as TestValidateTemplateTree).
func makeRootfs(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, d := range append(append([]string(nil), templateSkeletonDirs...), guestExpectDirs...) {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	sh := filepath.Join(dir, "bin", "sh")
	if err := os.WriteFile(sh, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
}

func hasSeverity(fs []Finding, s Severity) bool {
	for _, f := range fs {
		if f.Severity == s {
			return true
		}
	}
	return false
}

func findingsByRule(fs []Finding, rule string) []Finding {
	var out []Finding
	for _, f := range fs {
		if f.Rule == rule {
			out = append(out, f)
		}
	}
	return out
}

func TestValidateRootfsTree_Conformant(t *testing.T) {
	dir := t.TempDir()
	makeRootfs(t, dir)
	fs, err := ValidateRootfsTree(dir)
	if err != nil {
		t.Fatalf("ValidateRootfsTree: %v", err)
	}
	if len(fs) != 0 {
		t.Fatalf("expected no findings, got: %+v", fs)
	}
}

func TestValidateRootfsTree_ContractViolationsAreErrors(t *testing.T) {
	dir := t.TempDir()
	makeRootfs(t, dir)
	// A directory without group traverse and a 0600 file.
	private := filepath.Join(dir, "opt")
	if err := os.Mkdir(private, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(private, "secret"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	fs, err := ValidateRootfsTree(dir)
	if err != nil {
		t.Fatalf("ValidateRootfsTree: %v", err)
	}
	contract := findingsByRule(fs, "contract")
	if len(contract) == 0 {
		t.Fatalf("expected contract findings, got: %+v", fs)
	}
	for _, f := range contract {
		if f.Severity != SeverityError {
			t.Errorf("contract finding not an error: %+v", f)
		}
	}
}

func TestValidateRootfsTree_BinSh(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(t *testing.T, dir string)
		wantErr bool // expect an error-severity bin-sh finding
	}{
		{
			name:    "missing",
			mutate:  func(t *testing.T, dir string) { os.Remove(filepath.Join(dir, "bin", "sh")) },
			wantErr: true,
		},
		{
			name: "dangling symlink",
			mutate: func(t *testing.T, dir string) {
				p := filepath.Join(dir, "bin", "sh")
				os.Remove(p)
				if err := os.Symlink("nowhere", p); err != nil {
					t.Fatal(err)
				}
			},
			wantErr: true,
		},
		{
			name: "no execute bit",
			mutate: func(t *testing.T, dir string) {
				p := filepath.Join(dir, "bin", "sh")
				if err := os.Chmod(p, 0o644); err != nil {
					t.Fatal(err)
				}
			},
			wantErr: true,
		},
		{
			// A relative symlink inside the tree resolves chroot-style.
			name: "relative symlink to busybox",
			mutate: func(t *testing.T, dir string) {
				if err := os.WriteFile(filepath.Join(dir, "bin", "busybox"), []byte("x"), 0o755); err != nil {
					t.Fatal(err)
				}
				p := filepath.Join(dir, "bin", "sh")
				os.Remove(p)
				if err := os.Symlink("busybox", p); err != nil {
					t.Fatal(err)
				}
			},
			wantErr: false,
		},
		{
			// An ABSOLUTE target is resolved against the TREE ROOT (guest
			// chroot semantics), never the host root: /bin/sh -> /usr/bin/sh
			// names <tree>/usr/bin/sh.
			name: "absolute symlink resolves chroot-style",
			mutate: func(t *testing.T, dir string) {
				if err := os.MkdirAll(filepath.Join(dir, "usr", "bin"), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, "usr", "bin", "sh"), []byte("x"), 0o755); err != nil {
					t.Fatal(err)
				}
				p := filepath.Join(dir, "bin", "sh")
				os.Remove(p)
				if err := os.Symlink("/usr/bin/sh", p); err != nil {
					t.Fatal(err)
				}
			},
			wantErr: false,
		},
		{
			// usr-merge: bin itself is a symlink to usr/bin.
			name: "usr-merge bin symlink",
			mutate: func(t *testing.T, dir string) {
				bin := filepath.Join(dir, "bin")
				os.RemoveAll(bin)
				if err := os.MkdirAll(filepath.Join(dir, "usr", "bin"), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, "usr", "bin", "sh"), []byte("x"), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("usr/bin", bin); err != nil {
					t.Fatal(err)
				}
			},
			wantErr: false,
		},
		{
			// A chain that never lands (self-referential) must terminate.
			name: "symlink loop",
			mutate: func(t *testing.T, dir string) {
				p := filepath.Join(dir, "bin", "sh")
				os.Remove(p)
				if err := os.Symlink("sh", p); err != nil {
					t.Fatal(err)
				}
			},
			wantErr: true,
		},
		{
			// A relative target climbing above the root is refused (the
			// kernel would clamp it at / — not the path that was authored).
			name: "escaping symlink",
			mutate: func(t *testing.T, dir string) {
				if err := os.WriteFile(filepath.Join(dir, "escape-target"), []byte("x"), 0o755); err != nil {
					t.Fatal(err)
				}
				p := filepath.Join(dir, "bin", "sh")
				os.Remove(p)
				if err := os.Symlink("../../escape-target", p); err != nil {
					t.Fatal(err)
				}
			},
			wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			makeRootfs(t, dir)
			tc.mutate(t, dir)
			fs, err := ValidateRootfsTree(dir)
			if err != nil {
				t.Fatalf("ValidateRootfsTree: %v", err)
			}
			got := findingsByRule(fs, "bin-sh")
			if tc.wantErr && len(got) == 0 {
				t.Fatalf("expected a bin-sh finding, got: %+v", fs)
			}
			if !tc.wantErr && len(got) > 0 {
				t.Fatalf("expected no bin-sh finding, got: %+v", got)
			}
			if len(got) > 0 && got[0].Severity != SeverityError {
				t.Errorf("bin-sh finding not an error: %+v", got[0])
			}
		})
	}
}

func TestValidateRootfsTree_ControlFiles(t *testing.T) {
	for _, name := range []string{volumeIdentityFile, provisioningMarkerFile, saveStagingMarker} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			makeRootfs(t, dir)
			if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o644); err != nil {
				t.Fatal(err)
			}
			fs, err := ValidateRootfsTree(dir)
			if err != nil {
				t.Fatalf("ValidateRootfsTree: %v", err)
			}
			got := findingsByRule(fs, "control-file")
			if len(got) != 1 {
				t.Fatalf("expected one control-file finding, got: %+v", fs)
			}
			if got[0].Severity != SeverityError {
				t.Errorf("control-file finding not an error: %+v", got[0])
			}
		})
	}
}

func TestValidateRootfsTree_SpecialFilesAreWarnings(t *testing.T) {
	dir := t.TempDir()
	makeRootfs(t, dir)
	if err := os.MkdirAll(filepath.Join(dir, "run"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(filepath.Join(dir, "run", "pipe"), 0o644); err != nil {
		t.Fatal(err)
	}
	fs, err := ValidateRootfsTree(dir)
	if err != nil {
		t.Fatalf("ValidateRootfsTree: %v", err)
	}
	got := findingsByRule(fs, "special-file")
	if len(got) != 1 {
		t.Fatalf("expected one special-file finding, got: %+v", fs)
	}
	if got[0].Severity != SeverityWarning {
		t.Errorf("special-file finding should be a warning: %+v", got[0])
	}
	if hasSeverity(fs, SeverityError) {
		t.Errorf("a FIFO must not fail the gate: %+v", fs)
	}
}

// TestValidateRootfsTree_ResolvesLikeTheGuest pins the resolver against
// real `chroot` behavior for multi-component symlink chains — the shapes a
// single-component resolver gets wrong in both directions.
func TestValidateRootfsTree_ResolvesLikeTheGuest(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T, dir string)
		ok    bool
	}{
		{
			// A usr-merge chain whose target climbs one level from the
			// RESOLVED parent: works under chroot, must pass. (Applying the
			// target to the LEXICAL parent would look like an escape.)
			name: "usr-merge sh through resolved parent",
			setup: func(t *testing.T, dir string) {
				os.RemoveAll(filepath.Join(dir, "bin"))
				os.MkdirAll(filepath.Join(dir, "usr", "bin"), 0o755)
				os.WriteFile(filepath.Join(dir, "usr", "bin", "busybox"), []byte("x"), 0o755)
				os.Symlink("../../bin/busybox", filepath.Join(dir, "usr", "bin", "sh"))
				os.Symlink("usr/bin", filepath.Join(dir, "bin"))
			},
			ok: true,
		},
		{
			// ../sh2 resolves to a nonexistent entry: the guest exec fails.
			name: "dangling through resolved parent",
			setup: func(t *testing.T, dir string) {
				os.RemoveAll(filepath.Join(dir, "bin"))
				os.MkdirAll(filepath.Join(dir, "usr", "bin"), 0o755)
				os.Symlink("../sh2", filepath.Join(dir, "usr", "bin", "sh"))
				os.Symlink("usr/bin", filepath.Join(dir, "bin"))
			},
			ok: false,
		},
		{
			// An ABSOLUTE target restarts at the tree root; the HOST's
			// /usr/bin/sh must never satisfy it.
			name: "absolute target never touches the host",
			setup: func(t *testing.T, dir string) {
				os.RemoveAll(filepath.Join(dir, "bin"))
				os.MkdirAll(filepath.Join(dir, "usr", "bin"), 0o755)
				os.Symlink("/usr/bin/sh", filepath.Join(dir, "bin"))
			},
			ok: false,
		},
		{
			// "sub/../../bin/busybox" must not cancel `sub`: the guest hits
			// ENOENT on the missing intermediate component.
			name: "intermediate component must exist",
			setup: func(t *testing.T, dir string) {
				os.Remove(filepath.Join(dir, "bin", "sh"))
				os.WriteFile(filepath.Join(dir, "bin", "busybox"), []byte("x"), 0o755)
				os.Symlink("sub/../../bin/busybox", filepath.Join(dir, "bin", "sh"))
			},
			ok: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			makeRootfs(t, dir)
			tc.setup(t, dir)
			fs, err := ValidateRootfsTree(dir)
			if err != nil {
				t.Fatalf("ValidateRootfsTree: %v", err)
			}
			got := findingsByRule(fs, "bin-sh")
			if tc.ok && len(got) > 0 {
				t.Fatalf("working tree rejected: %+v", got)
			}
			if !tc.ok && len(got) == 0 {
				t.Fatalf("broken tree accepted: %+v", fs)
			}
		})
	}
}

// TestValidateRootfsTree_AttachCriticalDirs pins the FATAL class: the
// warden secures dev/proc/workspace/home with open_dir steps that REFUSE the
// whole attach when the target is missing or a symlink (a read-only overlay
// root cannot be mkdirat'ed), so those are errors — unlike bin/etc, which
// degrade.
func TestValidateRootfsTree_AttachCriticalDirs(t *testing.T) {
	for _, name := range attachCriticalDirs {
		t.Run(name+" missing", func(t *testing.T) {
			dir := t.TempDir()
			makeRootfs(t, dir)
			if err := os.RemoveAll(filepath.Join(dir, name)); err != nil {
				t.Fatal(err)
			}
			fs, err := ValidateRootfsTree(dir)
			if err != nil {
				t.Fatalf("ValidateRootfsTree: %v", err)
			}
			got := findingsByRule(fs, "skeleton-dir")
			if len(got) != 1 || got[0].Severity != SeverityError || got[0].Path != filepath.Join(dir, name) {
				t.Fatalf("missing %s not an error-severity finding: %+v", name, fs)
			}
		})
		t.Run(name+" symlinked", func(t *testing.T) {
			dir := t.TempDir()
			makeRootfs(t, dir)
			p := filepath.Join(dir, name)
			os.RemoveAll(p)
			if err := os.Symlink("/tmp", p); err != nil {
				t.Fatal(err)
			}
			fs, err := ValidateRootfsTree(dir)
			if err != nil {
				t.Fatalf("ValidateRootfsTree: %v", err)
			}
			got := findingsByRule(fs, "skeleton-dir")
			if len(got) != 1 || got[0].Severity != SeverityError {
				t.Fatalf("symlinked %s not an error-severity finding: %+v", name, fs)
			}
		})
	}

	// bin/ is the tolerant twin: a usr-merge symlink there is legitimate.
	dir := t.TempDir()
	makeRootfs(t, dir)
	os.RemoveAll(filepath.Join(dir, "bin"))
	os.MkdirAll(filepath.Join(dir, "usr", "bin"), 0o755)
	os.WriteFile(filepath.Join(dir, "usr", "bin", "sh"), []byte("x"), 0o755)
	if err := os.Symlink("usr/bin", filepath.Join(dir, "bin")); err != nil {
		t.Fatal(err)
	}
	fs, err := ValidateRootfsTree(dir)
	if err != nil {
		t.Fatalf("ValidateRootfsTree: %v", err)
	}
	if got := findingsByRule(fs, "skeleton-dir"); len(got) > 0 {
		t.Fatalf("usr-merge bin symlink flagged: %+v", got)
	}

	// A DANGLING symlink at etc/ is an error (the import paths cannot heal
	// it: MkdirAll over an existing entry fails), unlike a missing one.
	dir2 := t.TempDir()
	makeRootfs(t, dir2)
	os.RemoveAll(filepath.Join(dir2, "etc"))
	if err := os.Symlink("/nonexistent", filepath.Join(dir2, "etc")); err != nil {
		t.Fatal(err)
	}
	fs2, err := ValidateRootfsTree(dir2)
	if err != nil {
		t.Fatalf("ValidateRootfsTree: %v", err)
	}
	got := findingsByRule(fs2, "skeleton-dir")
	if len(got) != 1 || got[0].Severity != SeverityError {
		t.Fatalf("dangling etc symlink not an error: %+v", fs2)
	}
}

func TestValidateRootfsTree_SkeletonDirsAreChrootResolved(t *testing.T) {
	// An absolute symlink is judged as the GUEST sees it (against the tree
	// root), never the host: `etc -> /etc` loops back onto itself inside the
	// chroot and must be reported as an error even though the HOST's /etc
	// exists as a directory (os.Stat would have passed it).
	dir := t.TempDir()
	makeRootfs(t, dir)
	etc := filepath.Join(dir, "etc")
	if err := os.RemoveAll(etc); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc", etc); err != nil {
		t.Fatal(err)
	}
	fs, err := ValidateRootfsTree(dir)
	if err != nil {
		t.Fatalf("ValidateRootfsTree: %v", err)
	}
	var got []Finding
	for _, f := range findingsByRule(fs, "skeleton-dir") {
		if f.Path == etc {
			got = append(got, f)
		}
	}
	if len(got) != 1 || got[0].Severity != SeverityError {
		t.Fatalf("expected one error-severity skeleton-dir finding for a self-looping absolute symlink, got: %+v", fs)
	}

	// A relative symlink to a real in-tree directory is fine (the usr-merge
	// shape), and so is an absolute one whose chroot target exists.
	dir2 := t.TempDir()
	makeRootfs(t, dir2)
	if err := os.MkdirAll(filepath.Join(dir2, "usr", "share"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(dir2, "etc")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/usr/share", filepath.Join(dir2, "etc")); err != nil {
		t.Fatal(err)
	}
	fs2, err := ValidateRootfsTree(dir2)
	if err != nil {
		t.Fatalf("ValidateRootfsTree: %v", err)
	}
	for _, f := range findingsByRule(fs2, "skeleton-dir") {
		if f.Path == filepath.Join(dir2, "etc") {
			t.Fatalf("chroot-resolvable absolute symlink wrongly flagged: %+v", f)
		}
	}
}

func TestValidateRootfsTree_SkeletonAndGuestDirs(t *testing.T) {
	dir := t.TempDir()
	makeRootfs(t, dir)
	// Drop one skeleton dir and one guest dir; skeleton must warn, guest must warn.
	if err := os.RemoveAll(filepath.Join(dir, "etc")); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(dir, "sys")); err != nil {
		t.Fatal(err)
	}
	fs, err := ValidateRootfsTree(dir)
	if err != nil {
		t.Fatalf("ValidateRootfsTree: %v", err)
	}
	if got := findingsByRule(fs, "skeleton-dir"); len(got) != 1 || got[0].Severity != SeverityWarning {
		t.Fatalf("expected one skeleton-dir warning, got: %+v", fs)
	}
	if got := findingsByRule(fs, "guest-dir"); len(got) != 1 || got[0].Severity != SeverityWarning {
		t.Fatalf("expected one guest-dir warning, got: %+v", fs)
	}

	// A skeleton name occupied by a FILE is a hard import error.
	dir2 := t.TempDir()
	makeRootfs(t, dir2)
	if err := os.RemoveAll(filepath.Join(dir2, "workspace")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir2, "workspace"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	fs2, err := ValidateRootfsTree(dir2)
	if err != nil {
		t.Fatalf("ValidateRootfsTree: %v", err)
	}
	got := findingsByRule(fs2, "skeleton-dir")
	if len(got) != 1 || got[0].Severity != SeverityError {
		t.Fatalf("expected one skeleton-dir error, got: %+v", fs2)
	}
}

func TestValidateRootfsTree_SymlinkRootRefused(t *testing.T) {
	real := t.TempDir()
	makeRootfs(t, real)
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateRootfsTree(link); err == nil {
		t.Fatal("expected an error for a symlink root")
	}
}

func TestValidateScanRoot(t *testing.T) {
	root := t.TempDir()
	// name/version layout: one good leaf, one broken leaf.
	good := filepath.Join(root, "app", "v1")
	broken := filepath.Join(root, "app", "v2")
	makeRootfs(t, good)
	makeRootfs(t, broken)
	os.Remove(filepath.Join(broken, "bin", "sh"))

	if !IsScanRootDir(root) {
		t.Fatal("scan root not detected")
	}
	fs, err := ValidateScanRoot(root)
	if err != nil {
		t.Fatalf("ValidateScanRoot: %v", err)
	}
	binSh := findingsByRule(fs, "bin-sh")
	if len(binSh) != 1 {
		t.Fatalf("expected exactly one bin-sh finding (from the broken leaf), got: %+v", fs)
	}
	if !strings.HasPrefix(binSh[0].Path, broken) {
		t.Errorf("finding not attributed to the broken leaf: %+v", binSh[0])
	}

	// An unversioned name dir (the rootfs itself) is also a leaf.
	plain := filepath.Join(root, "solo")
	makeRootfs(t, plain)
	os.Remove(filepath.Join(plain, "tmp"))
	fs, err = ValidateScanRoot(root)
	if err != nil {
		t.Fatalf("ValidateScanRoot: %v", err)
	}
	if got := findingsByRule(fs, "guest-dir"); len(got) != 1 {
		t.Fatalf("expected one guest-dir finding from the solo leaf, got: %+v", fs)
	}

	// Empty scan root: a warning, not silence.
	empty := t.TempDir()
	fs, err = ValidateScanRoot(empty)
	if err != nil {
		t.Fatalf("ValidateScanRoot: %v", err)
	}
	if got := findingsByRule(fs, "scan-root"); len(got) != 1 || got[0].Severity != SeverityWarning {
		t.Fatalf("expected a scan-root warning for an empty root, got: %+v", fs)
	}
}

func TestIsStoreShape(t *testing.T) {
	store := t.TempDir()
	if err := os.MkdirAll(filepath.Join(store, "refs"), 0o755); err != nil {
		t.Fatal(err)
	}
	if !IsStoreShape(store) {
		t.Fatal("store with refs/ not detected")
	}
	plain := t.TempDir()
	makeRootfs(t, plain)
	if IsStoreShape(plain) {
		t.Fatal("plain template tree misdetected as a store")
	}
}

func TestIsScanRootDir(t *testing.T) {
	scan := t.TempDir()
	makeRootfs(t, filepath.Join(scan, "rootfs", "v1"))
	if !IsScanRootDir(scan) {
		t.Fatal("name/version layout not detected as a scan root")
	}
	// A template may legally be NAMED bin/etc/… (`flat-templates/bin/v1` is
	// registered as bin:v1); a versioned container under a marker name is
	// still a scan-root child, not evidence that the parent is a rootfs.
	named := t.TempDir()
	makeRootfs(t, filepath.Join(named, "bin", "v1"))
	if !IsScanRootDir(named) {
		t.Fatal("scan root with a template named bin not detected")
	}
	fs, err := ValidateScanRoot(named)
	if err != nil {
		t.Fatalf("ValidateScanRoot: %v", err)
	}
	if len(fs) != 0 {
		t.Fatalf("conformant bin:v1 template produced findings: %+v", fs)
	}
	tree := t.TempDir()
	makeRootfs(t, tree)
	if IsScanRootDir(tree) {
		t.Fatal("single rootfs misdetected as a scan root")
	}
	// A directory of unrelated subdirs is NOT a scan root: the registration
	// scan would register it as one (broken) template, validate treats it
	// as one tree.
	unrelated := t.TempDir()
	if err := os.MkdirAll(filepath.Join(unrelated, "whatever"), 0o755); err != nil {
		t.Fatal(err)
	}
	if IsScanRootDir(unrelated) {
		t.Fatal("directory of unrelated subdirs misdetected as a scan root")
	}
}

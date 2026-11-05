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

package vmm

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// The per-VM API token persistence must round-trip through the sandlot-private
// state dir and must REFUSE a symlinked/foreign/mode-widened state dir or a
// symlinked token file (a sibling sandvmm in the group-writable sandbox dir
// could otherwise redirect the token to a place it can read and then answer
// the sandlot's challenge from a squatted socket).
func TestAPITokenPersistenceRefusesSymlinksAndWideDirs(t *testing.T) {
	base := t.TempDir()
	sandbox := filepath.Join(base, "vm-1")
	if err := os.Mkdir(sandbox, 0o770); err != nil {
		t.Fatal(err)
	}
	token := make([]byte, apiTokenLen)
	for i := range token {
		token[i] = byte(i + 1)
	}
	if err := writeAPIToken(sandbox, token); err != nil {
		t.Fatalf("write token: %v", err)
	}
	if got, err := ReadAPIToken(sandbox); err != nil || string(got) != string(token) {
		t.Fatalf("read token = %x, err=%v, want %x", got, err, token)
	}

	// Symlinked token file → refused (O_NOFOLLOW).
	stateDir := filepath.Join(sandbox, "state")
	evil := filepath.Join(base, "evil-token")
	if err := os.WriteFile(evil, token, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(stateDir, "api-token")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(evil, filepath.Join(stateDir, "api-token")); err != nil {
		t.Fatal(err)
	}
	if got, err := ReadAPIToken(sandbox); err == nil {
		t.Fatalf("symlinked token file was followed: %x", got)
	}
	_ = os.Remove(filepath.Join(stateDir, "api-token"))

	// A mode-widened state dir → refused (and writes fail closed).
	if err := os.Chmod(stateDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if got, err := ReadAPIToken(sandbox); err == nil {
		t.Fatalf("group/world-accessible state dir was accepted: %x", got)
	}
	if err := writeAPIToken(sandbox, token); err == nil {
		t.Fatal("write into a mode-widened state dir must fail closed")
	}

	// A symlinked state dir → refused.
	if err := os.RemoveAll(stateDir); err != nil {
		t.Fatal(err)
	}
	foreign := filepath.Join(base, "foreign-state")
	if err := os.Mkdir(foreign, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(foreign, stateDir); err != nil {
		t.Fatal(err)
	}
	if got, err := ReadAPIToken(sandbox); err == nil {
		t.Fatalf("symlinked state dir was followed: %x", got)
	}
	if err := writeAPIToken(sandbox, token); err == nil {
		t.Fatal("write through a symlinked state dir must fail closed")
	}
}

// TestBuildVMCreateConfigVirtioFsPins pins the virtio-fs device block of the
// vm.create request. These fields carry the VMM-level isolation contract:
//
//   - allowed_dirs MUST be present and empty (an absent field deserializes
//     to None in the VMM = filter INACTIVE = every agent directory visible
//     until the first vm.set-fs — the fail-open boot window).
//   - read_only MUST be false (the agent rootfs is RW).
//   - id/tag identify the permanent device for later vm.set-fs calls.
func TestBuildVMCreateConfigVirtioFsPins(t *testing.T) {
	cfg := Config{
		ID:            "vm-test",
		KernelPath:    "/kernel",
		InitramfsPath: "/initramfs",
		VCPUs:         2,
		MemoryMB:      256,
		VolumesDir:    "/var/sandswap/volumes",
	}
	body, err := json.Marshal(buildVMCreateConfig(cfg, "/tmp/serial.log", "/tmp/console.log"))
	if err != nil {
		t.Fatal(err)
	}

	var parsed struct {
		Fs []struct {
			ID              string `json:"id"`
			Tag             string `json:"tag"`
			BackendFsConfig struct {
				SharedDir   string   `json:"shared_dir"`
				ReadOnly    bool     `json:"read_only"`
				AllowedDirs []string `json:"allowed_dirs"`
			} `json:"backendfs_config"`
		} `json:"fs"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatal(err)
	}

	if len(parsed.Fs) != 1 {
		t.Fatalf("expected exactly 1 fs device, got %d", len(parsed.Fs))
	}
	fs := parsed.Fs[0]
	if fs.ID != "vfs-rootfs" {
		t.Errorf("fs id = %q, want vfs-rootfs", fs.ID)
	}
	if fs.Tag != "sandswap" {
		t.Errorf("fs tag = %q, want sandswap", fs.Tag)
	}
	if fs.BackendFsConfig.SharedDir != "/var/sandswap/volumes" {
		t.Errorf("shared_dir = %q, want /var/sandswap/volumes", fs.BackendFsConfig.SharedDir)
	}
	if fs.BackendFsConfig.ReadOnly {
		t.Error("read_only = true, want false (agent rootfs must be RW)")
	}
	// The fail-closed pin: the field must serialize as a PRESENT empty list,
	// not be omitted (omitted → None → filter inactive at boot).
	if fs.BackendFsConfig.AllowedDirs == nil {
		t.Fatal("allowed_dirs missing from vm.create body: the VMM would deserialize " +
			"it as None (filter inactive — the fail-open boot window)")
	}
	if len(fs.BackendFsConfig.AllowedDirs) != 0 {
		t.Errorf("allowed_dirs = %v, want empty list at create time", fs.BackendFsConfig.AllowedDirs)
	}
	// Belt and braces: the raw JSON must contain the explicit empty array.
	if !strings.Contains(string(body), `"allowed_dirs":[]`) {
		t.Errorf("raw body must contain \"allowed_dirs\":[], got: %s", body)
	}
}

// TestBuildCmdlineInitOnFreePosture pins the free-wipe posture as an EXPLICIT
// cmdline token on every boot: the knob (microvm.init_on_free, default false)
// is the deployment's authority over the kernel config's
// INIT_ON_FREE_DEFAULT_ON, and the effective cmdline is persisted per VM in
// state.json — the posture must be readable off the record. The appended token
// is the LAST occurrence, so a base cmdline carrying its own init_on_free=
// cannot override the configured posture.
func TestBuildCmdlineInitOnFreePosture(t *testing.T) {
	off := buildCmdline(Config{KernelCmdline: "quiet clocksource=kvm-clock"})
	if !hasCmdlineToken(off, "init_on_free=0") {
		t.Errorf("default posture must write init_on_free=0, got %q", off)
	}
	on := buildCmdline(Config{KernelCmdline: "quiet clocksource=kvm-clock", InitOnFree: true})
	if !hasCmdlineToken(on, "init_on_free=1") || hasCmdlineToken(on, "init_on_free=0") {
		t.Errorf("opt-in posture must write exactly init_on_free=1, got %q", on)
	}
	conflicting := buildCmdline(Config{KernelCmdline: "quiet init_on_free=1"})
	if strings.LastIndex(conflicting, "init_on_free=0") < strings.LastIndex(conflicting, "init_on_free=1") {
		t.Errorf("appended posture must be the last occurrence (early_param keeps it), got %q", conflicting)
	}
}

// TestBuildVMCreateConfigLogSinks pins the two per-VM log sinks: serial (File,
// earlyprintk) and virtio-console (File, the main hvc0 log). The paths must be
// distinct — both VMM backends File::create with independent offsets.
func TestBuildVMCreateConfigLogSinks(t *testing.T) {
	dir := "/run/sandswap/vm/vm-logs"
	serialLog, consoleLog := sandboxLogPaths(dir)
	if serialLog != filepath.Join(dir, "serial.log") {
		t.Errorf("serial log = %q, want %q", serialLog, filepath.Join(dir, "serial.log"))
	}
	if consoleLog != filepath.Join(dir, "console.log") {
		t.Errorf("console log = %q, want %q", consoleLog, filepath.Join(dir, "console.log"))
	}
	if serialLog == consoleLog {
		t.Fatal("serial and console log paths must differ (both File::create)")
	}

	cfg := Config{
		ID:            "vm-logs",
		KernelPath:    "/kernel",
		InitramfsPath: "/initramfs",
		VCPUs:         1,
		MemoryMB:      128,
		VolumesDir:    "/var/sandswap/volumes",
	}
	body, err := json.Marshal(buildVMCreateConfig(cfg, serialLog, consoleLog))
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		Serial struct {
			Mode string `json:"mode"`
			File string `json:"file"`
		} `json:"serial"`
		Console struct {
			Mode string `json:"mode"`
			File string `json:"file"`
		} `json:"console"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.Serial.Mode != "File" || parsed.Serial.File != serialLog {
		t.Errorf("serial = %+v, want File %q", parsed.Serial, serialLog)
	}
	if parsed.Console.Mode != "File" || parsed.Console.File != consoleLog {
		t.Errorf("console = %+v, want File %q", parsed.Console, consoleLog)
	}
}

// TestBuildVMCreateConfigNetAttach verifies the virtio-net device is attached
// only when a net spec with a concrete address is provisioned.
func TestBuildVMCreateConfigNetAttach(t *testing.T) {
	base := Config{
		ID:         "vm-test",
		VolumesDir: "/var/sandswap/volumes",
	}

	offline := buildVMCreateConfig(base, "/tmp/serial.log", "/tmp/console.log")
	if _, ok := offline["net"]; ok {
		t.Error("net key present for offline VM (nil NetSpec), want absent")
	}

	v4 := base
	v4.NetSpec = &VMNetSpec{GuestIP: "10.0.0.5"}
	if _, ok := buildVMCreateConfig(v4, "/tmp/serial.log", "/tmp/console.log")["net"]; !ok {
		t.Error("net key missing for VM with GuestIP set")
	}

	empty := base
	empty.NetSpec = &VMNetSpec{} // spec present but no address: still offline
	if _, ok := buildVMCreateConfig(empty, "/tmp/serial.log", "/tmp/console.log")["net"]; ok {
		t.Error("net key present for NetSpec without addresses, want absent")
	}
}

// TestKillFailedLaunchReapsChild pins the launch-failure zombie fix: a launch
// that fails after Start has no monitor goroutine, so killFailedLaunch is the
// SOLE reaper — without its cmd.Wait the SIGKILLed child stays a zombie until
// sandlot exits, and the 60s self-heal retry loop accumulates them without
// bound under any persistent failure mode. After the call the child must be
// fully GONE from /proc (reaped), not merely exited.
func TestKillFailedLaunchReapsChild(t *testing.T) {
	if _, err := exec.LookPath("sleep"); err != nil {
		t.Skip("sleep not available")
	}
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	pid := cmd.Process.Pid
	vm := &RunningVM{ID: "vm-fail", cmd: cmd}

	killFailedLaunch(vm)

	// Reaped = no /proc entry at all. A zombie (state Z) still owns a table
	// entry and would fail this check — that is exactly the old behavior.
	if _, err := os.Stat(fmt.Sprintf("/proc/%d", pid)); err == nil {
		t.Fatalf("pid %d still present in /proc after killFailedLaunch (zombie leak)", pid)
	}
	// A second Kill must not panic on the already-reaped cmd (idempotence on
	// the destroy-retry paths).
	vm.Kill()
}

// TestSandboxDirMode pins the sandbox-dir shape per identity model: the
// split-identity child (different uid than sandlot) must be able to CREATE
// in the dir (0770 + setgid via the shared group), while the same-identity
// legacy shape stays traverse-only 0711.
func TestSandboxDirMode(t *testing.T) {
	mode, setgid := SandboxDirMode(987)
	if mode != 0770 || !setgid {
		t.Fatalf("split identity: mode %o setgid=%v, want 0770+setgid", mode, setgid)
	}
	mode, setgid = SandboxDirMode(0)
	if mode != 0711 || setgid {
		t.Fatalf("same identity: mode %o setgid=%v, want 0711 no setgid", mode, setgid)
	}
}

// TestSandboxRootMode pins the root-dir shape per identity model: the split
// identity (a DIFFERENT-uid sandvmm child) needs the root traversable — the
// same-identity legacy model leaves the root alone (0).
func TestSandboxRootMode(t *testing.T) {
	if m := SandboxRootMode(987); m != 0711 {
		t.Fatalf("split identity: root mode %o, want 0711", m)
	}
	if m := SandboxRootMode(0); m != 0 {
		t.Fatalf("same identity: root mode %o, want 0 (untouched)", m)
	}
}

// TestPrepareSandboxDir pins the shapes prepareSandboxDir produces, including
// the PARENT root: MkdirAll applies the umask, so a root-owned process leaves
// the root at 0750 root:root — which blocks the different-uid child's
// traversal entirely (every launch died with EACCES at socket creation; the
// k8s embedded regression).
func TestPrepareSandboxDir(t *testing.T) {
	t.Run("same-identity", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "vm", "pool-small-1")
		if err := prepareSandboxDir(dir, 0, 0); err != nil {
			t.Fatalf("prepareSandboxDir: %v", err)
		}
		assertDirMode(t, dir, 0711, false)
	})

	t.Run("split-identity", func(t *testing.T) {
		if os.Geteuid() != 0 {
			t.Skip("requires root: chgrp to a foreign gid + setgid")
		}
		base := t.TempDir()
		root := filepath.Join(base, "vm")
		dir := filepath.Join(root, "pool-small-1")
		if err := prepareSandboxDir(dir, 987, 1001); err != nil {
			t.Fatalf("prepareSandboxDir: %v", err)
		}
		assertDirMode(t, root, 0711, false)
		assertDirMode(t, dir, 0770, true)
		var st syscall.Stat_t
		if err := syscall.Stat(dir, &st); err != nil {
			t.Fatal(err)
		}
		if st.Gid != 1001 {
			t.Errorf("sandbox dir gid = %d, want 1001", st.Gid)
		}
	})

	// Functional proof as the child identity itself: after prepareSandboxDir
	// the child can create its socket file; under the old shape (root left at
	// 0750 root:root) it cannot. The negative control pins WHY the root
	// shaping exists — if it ever starts passing, the traversal model changed
	// and needs re-derivation.
	t.Run("child-write", func(t *testing.T) {
		if os.Geteuid() != 0 {
			t.Skip("requires root: setpriv uid transition")
		}
		setpriv, err := exec.LookPath("setpriv")
		if err != nil {
			t.Skip("setpriv not available")
		}
		touch, err := exec.LookPath("touch")
		if err != nil {
			t.Skip("touch not available")
		}
		childTouch := func(dir string) error {
			return exec.Command(setpriv, "--reuid=987", "--regid=987",
				"--groups=1001", "--", touch, filepath.Join(dir, "sandvmm.sock")).Run()
		}

		// NOT t.TempDir(): under a subtest it nests the dir inside a 0700
		// parent, which the child cannot traverse — the temp root would mask
		// the very permission model under test. MkdirTemp puts the tree
		// directly under /tmp (1777).
		base, err := os.MkdirTemp("", "sandboxdir-test-")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(base)
		if err := os.Chmod(base, 0755); err != nil {
			t.Fatal(err)
		}

		root := filepath.Join(base, "vm")
		dir := filepath.Join(root, "pool-small-1")
		if err := prepareSandboxDir(dir, 987, 1001); err != nil {
			t.Fatalf("prepareSandboxDir: %v", err)
		}
		if err := childTouch(dir); err != nil {
			t.Fatalf("child cannot create its socket after prepareSandboxDir: %v", err)
		}

		badRoot := filepath.Join(base, "bad-vm")
		badDir := filepath.Join(badRoot, "pool-small-1")
		if err := os.MkdirAll(badDir, 0770); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(badDir, 0, 1001); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(badDir, 0770|os.ModeSetgid); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(badRoot, 0, 0); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(badRoot, 0750); err != nil {
			t.Fatal(err)
		}
		if err := childTouch(badDir); err == nil {
			t.Fatalf("child wrote under a 0750 root:root parent — the traversal model changed, re-derive it")
		}
	})
}

func assertDirMode(t *testing.T, path string, want os.FileMode, wantSetgid bool) {
	t.Helper()
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if got := os.FileMode(st.Mode).Perm(); got != want {
		t.Errorf("%s mode = %o, want %o", path, got, want)
	}
	if got := st.Mode&syscall.S_ISGID != 0; got != wantSetgid {
		t.Errorf("%s setgid = %v, want %v (mode %o)", path, got, wantSetgid, st.Mode&07777)
	}
}

// TestWrapWithSetprivSetsExplicitGroups pins the supplementary-group contract
// of the sandvmm spawn: the wrapper ALWAYS carries an explicit disposition —
// --groups with exactly the configured gids, or --clear-groups when the list
// is empty. Never neither: an omitted disposition inherits the parent's
// groups, and the merged exec,prov sandlot carries the volume-seed group
// (sandprov) to read the seed. A leak there hands the FUSE passthrough daemon
// the seed, which makes every tenant's volume directory name computable.
func TestWrapWithSetprivSetsExplicitGroups(t *testing.T) {
	if _, err := exec.LookPath("setpriv"); err != nil {
		t.Skip("setpriv not available")
	}

	findFlag := func(argv []string, flag string) int {
		for i, a := range argv {
			if a == flag {
				return i
			}
		}
		return -1
	}

	// With groups: --groups=<csv> replaces the parent's set wholesale.
	cfg := Config{VMMUID: 987, VMMGID: 987, VMMGroups: []uint32{992, 985}}
	argv, err := wrapWithSetpriv(cfg, "/usr/bin/sandvmm", []string{"--api-socket", "/run/x.sock"})
	if err != nil {
		t.Fatalf("wrapWithSetpriv: %v", err)
	}
	if i := findFlag(argv, "--groups"); i < 0 || i+1 >= len(argv) {
		t.Fatalf("--groups missing from %v", argv)
	} else if argv[i+1] != "992,985" {
		t.Fatalf("--groups = %q, want 992,985", argv[i+1])
	}
	if findFlag(argv, "--clear-groups") >= 0 {
		t.Fatalf("--clear-groups must not accompany an explicit list: %v", argv)
	}

	// Empty groups: --clear-groups, never an omitted disposition (inheritance).
	cfg.VMMGroups = nil
	argv, err = wrapWithSetpriv(cfg, "/usr/bin/sandvmm", nil)
	if err != nil {
		t.Fatalf("wrapWithSetpriv (empty groups): %v", err)
	}
	if findFlag(argv, "--clear-groups") < 0 {
		t.Fatalf("empty group list must emit --clear-groups (inheritance is the leak): %v", argv)
	}
	if findFlag(argv, "--groups") >= 0 {
		t.Fatalf("--groups must not be emitted for an empty list: %v", argv)
	}
}

// TestVerifyIdentityStatus pins the four-value identity proof used right after
// the sandvmm spawn: all real/effective/saved/fs ids must equal the VMM
// identity. A saved-uid 0 is the regression this exists to catch.
func TestVerifyIdentityStatus(t *testing.T) {
	mk := func(uid, gid string) string {
		return "Name:\tsandvmm\n" + uid + "\n" + gid + "\n"
	}
	good := mk("Uid:\t987\t987\t987\t987", "Gid:\t987\t987\t987\t987")
	if err := verifyIdentityStatus(good, 987, 987); err != nil {
		t.Fatalf("clean four-value identity rejected: %v", err)
	}

	cases := []struct {
		name, status string
	}{
		{"saved uid 0", mk("Uid:\t987\t987\t0\t987", "Gid:\t987\t987\t987\t987")},
		{"fs gid mismatch", mk("Uid:\t987\t987\t987\t987", "Gid:\t987\t987\t987\t0")},
		{"malformed uid line", "Uid:\t987\t987\nGid:\t987\t987\t987\t987\n"},
	}
	for _, tc := range cases {
		if err := verifyIdentityStatus(tc.status, 987, 987); err == nil {
			t.Errorf("%s accepted", tc.name)
		}
	}
}

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

package core

import (
	"os"
	"path/filepath"
	"testing"

	"sandlot/vmm"
)

// --- isSandswapVMDir ---

// testStatePath mirrors the private-root layout: <state-root>/<vm-id>/state.json.
func testStatePath(sandboxDir string) string {
	clean := filepath.Clean(sandboxDir)
	return filepath.Join(StateRootFor(filepath.Dir(clean)), filepath.Base(clean), "state.json")
}

func TestIsSandswapVMDir(t *testing.T) {
	root := "/run/sandswap/vm"

	tests := []struct {
		name string
		p    string
		want bool
	}{
		{"normal subpath", "/run/sandswap/vm/pool-medium-0", true},
		{"nested subpath", "/run/sandswap/vm/pool-medium-0/sub", true},
		{"empty path", "", false},
		{"dot (root itself)", "/run/sandswap/vm", false},
		{"parent escape", "/run/sandswap", false},
		{"completely different", "/tmp/evil", false},
		{"path traversal", "/run/sandswap/vm/../evil", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isSandswapVMDir(tt.p, root); got != tt.want {
				t.Errorf("isSandswapVMDir(%q, %q) = %v, want %v", tt.p, root, got, tt.want)
			}
		})
	}
}

// --- writeState + loadState round-trip ---

func TestWriteAndLoadState_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	sandboxRoot := dir

	cfg := vmm.Config{
		ID:            "pool-medium-5",
		KernelPath:    "/var/lib/sandswap/vmlinux",
		InitramfsPath: "/var/lib/sandswap/initramfs.cpio.gz",
		VCPUs:         2,
		MemoryMB:      512,
		KernelCmdline: "quiet",
		VMMBinary:     "sandvmm",
		VolumesDir:    "/var/sandswap/volumes",
		SandboxDir:    filepath.Join(dir, "pool-medium-5"),
		GuestCID:      7,
		NetSpec: &vmm.VMNetSpec{
			GuestIP: "10.188.1.5",
			Prefix:  16,
			Gateway: "10.188.0.1",
			DNS:     []string{"1.1.1.1", "8.8.8.8"},
			MAC:     "aa:bb:cc:dd:ee:ff",
			NetConfig: map[string]any{
				"tap": "tap5",
				"mac": "aa:bb:cc:dd:ee:ff",
				"mtu": 1500,
			},
		},
	}

	original := stateFromConfig("pool-medium-5", cfg, filepath.Join(cfg.SandboxDir, "sandvmm.sock"), 12345, "medium")

	if err := writeState(original, sandboxRoot); err != nil {
		t.Fatalf("writeState: %v", err)
	}

	loaded, err := loadState(cfg.SandboxDir)
	if err != nil {
		t.Fatalf("loadState: %v", err)
	}

	// Verify key fields survived round-trip
	if loaded.VMID != original.VMID {
		t.Errorf("VMID = %q, want %q", loaded.VMID, original.VMID)
	}
	if loaded.CID != original.CID {
		t.Errorf("CID = %d, want %d", loaded.CID, original.CID)
	}
	if loaded.PID != original.PID {
		t.Errorf("PID = %d, want %d", loaded.PID, original.PID)
	}
	if loaded.APISocket != original.APISocket {
		t.Errorf("APISocket = %q, want %q", loaded.APISocket, original.APISocket)
	}
	if loaded.SpecID != original.SpecID {
		t.Errorf("SpecID = %q, want %q", loaded.SpecID, original.SpecID)
	}
	if loaded.Config.VCPUs != original.Config.VCPUs {
		t.Errorf("Config.VCPUs = %d, want %d", loaded.Config.VCPUs, original.Config.VCPUs)
	}
	if loaded.Config.MemoryMB != original.Config.MemoryMB {
		t.Errorf("Config.MemoryMB = %d, want %d", loaded.Config.MemoryMB, original.Config.MemoryMB)
	}
	if loaded.Config.KernelPath != original.Config.KernelPath {
		t.Errorf("Config.KernelPath = %q, want %q", loaded.Config.KernelPath, original.Config.KernelPath)
	}
	// NetSpec round-trip
	if loaded.NetSpec == nil {
		t.Fatal("NetSpec should not be nil after round-trip")
	}
	if loaded.NetSpec.GuestIP != original.NetSpec.GuestIP {
		t.Errorf("NetSpec.GuestIP = %q, want %q", loaded.NetSpec.GuestIP, original.NetSpec.GuestIP)
	}
	if loaded.NetSpec.TAP != original.NetSpec.TAP {
		t.Errorf("NetSpec.TAP = %q, want %q", loaded.NetSpec.TAP, original.NetSpec.TAP)
	}
}

// --- stateFromConfig + configFromState round-trip ---

func TestStateFromConfigAndBack(t *testing.T) {
	cfg := vmm.Config{
		ID:            "test-vm",
		KernelPath:    "/custom/vmlinux",
		InitramfsPath: "/custom/initramfs.cpio.gz",
		VCPUs:         4,
		MemoryMB:      1024,
		KernelCmdline: "console=ttyS0",
		VMMBinary:     "/usr/local/bin/sandvmm",
		VolumesDir:    "/data/volumes",
		SandboxDir:    "/run/sandswap/vm/test-vm",
		GuestCID:      42,
	}

	s := stateFromConfig("test-vm", cfg, "/run/sandswap/vm/test-vm/sandvmm.sock", 9999, "large")

	if s.VMID != "test-vm" {
		t.Errorf("VMID = %q, want %q", s.VMID, "test-vm")
	}
	if s.CID != 42 {
		t.Errorf("CID = %d, want 42", s.CID)
	}
	if s.PID != 9999 {
		t.Errorf("PID = %d, want 9999", s.PID)
	}
	if s.SpecID != "large" {
		t.Errorf("SpecID = %q, want %q", s.SpecID, "large")
	}

	// Convert back
	restored := configFromState(&s)
	if restored.ID != cfg.ID {
		t.Errorf("ID = %q, want %q", restored.ID, cfg.ID)
	}
	if restored.VCPUs != cfg.VCPUs {
		t.Errorf("VCPUs = %d, want %d", restored.VCPUs, cfg.VCPUs)
	}
	if restored.MemoryMB != cfg.MemoryMB {
		t.Errorf("MemoryMB = %d, want %d", restored.MemoryMB, cfg.MemoryMB)
	}
	if restored.KernelPath != cfg.KernelPath {
		t.Errorf("KernelPath = %q, want %q", restored.KernelPath, cfg.KernelPath)
	}
	if restored.GuestCID != cfg.GuestCID {
		t.Errorf("GuestCID = %d, want %d", restored.GuestCID, cfg.GuestCID)
	}
}

// --- netSpecToPersisted + netSpecFromPersisted round-trip ---

func TestNetSpecRoundTrip(t *testing.T) {
	original := &vmm.VMNetSpec{
		GuestIP: "10.188.2.100",
		Prefix:  24,
		Gateway: "10.188.2.1",
		DNS:     []string{"8.8.8.8", "1.1.1.1"},
		MAC:     "02:aa:bb:cc:dd:ee",
		NetConfig: map[string]any{
			"tap": "tap100",
			"mac": "02:aa:bb:cc:dd:ee",
			"mtu": 9000,
		},
	}

	persisted := netSpecToPersisted(original)
	restored := netSpecFromPersisted(persisted)

	if restored.GuestIP != original.GuestIP {
		t.Errorf("GuestIP = %q, want %q", restored.GuestIP, original.GuestIP)
	}
	if restored.Prefix != original.Prefix {
		t.Errorf("Prefix = %d, want %d", restored.Prefix, original.Prefix)
	}
	if restored.Gateway != original.Gateway {
		t.Errorf("Gateway = %q, want %q", restored.Gateway, original.Gateway)
	}
	if len(restored.DNS) != len(original.DNS) {
		t.Errorf("DNS len = %d, want %d", len(restored.DNS), len(original.DNS))
	}
	if restored.MAC != original.MAC {
		t.Errorf("MAC = %q, want %q", restored.MAC, original.MAC)
	}
	if restored.NetConfig["tap"] != "tap100" {
		t.Errorf("NetConfig[tap] = %v, want tap100", restored.NetConfig["tap"])
	}
	if restored.NetConfig["mtu"] != 9000 {
		t.Errorf("NetConfig[mtu] = %v, want 9000", restored.NetConfig["mtu"])
	}
}

func TestNetSpecFromPersisted_Nil(t *testing.T) {
	if result := netSpecFromPersisted(nil); result != nil {
		t.Error("nil input should return nil")
	}
}

// --- removeState ---

func TestRemoveState_ExistingFile(t *testing.T) {
	dir := t.TempDir()
	sandboxDir := filepath.Join(dir, "vm-test")
	if err := os.MkdirAll(sandboxDir, 0755); err != nil {
		t.Fatal(err)
	}
	// Write a state file (into the private subdir — see statePath).
	if err := os.MkdirAll(filepath.Dir(testStatePath(sandboxDir)), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(testStatePath(sandboxDir), []byte("{}"), 0644); err != nil {
		t.Fatal(err)
	}
	removeState(sandboxDir)
	if _, err := os.Stat(testStatePath(sandboxDir)); !os.IsNotExist(err) {
		t.Error("state.json should be removed")
	}
}

func TestRemoveState_NonexistentFile(t *testing.T) {
	removeState("/nonexistent/path")
	// Should not panic
}

func TestRemoveState_EmptyDir(t *testing.T) {
	removeState("")
	// Should not panic
}

// --- removeSandboxDir ---

func TestRemoveSandboxDir_ValidPath(t *testing.T) {
	dir := t.TempDir()
	sandboxRoot := dir
	vmDir := filepath.Join(dir, "vm-test")
	if err := os.MkdirAll(vmDir, 0755); err != nil {
		t.Fatal(err)
	}
	removeSandboxDir(vmDir, sandboxRoot)
	if _, err := os.Stat(vmDir); !os.IsNotExist(err) {
		t.Error("sandbox dir should be removed")
	}
}

func TestRemoveSandboxDir_RejectsEscape(t *testing.T) {
	dir := t.TempDir()
	sandboxRoot := filepath.Join(dir, "vm")
	// Path outside sandboxRoot
	removeSandboxDir("/tmp/evil", sandboxRoot)
	// Should not remove anything — just silently skip
	if _, err := os.Stat("/tmp/evil"); os.IsNotExist(err) {
		// Expected: /tmp/evil doesn't exist and wasn't created
	}
}

// --- loadState: missing file ---

func TestLoadState_MissingFile(t *testing.T) {
	_, err := loadState("/nonexistent/dir")
	if err == nil {
		t.Error("expected error for missing state.json")
	}
}

// --- statePath ---

func TestStatePath(t *testing.T) {
	got := testStatePath("/run/sandswap/vm/pool-medium-0")
	want := "/run/sandswap-state/default/pool-medium-0/state.json"
	if got != want {
		t.Errorf("state path = %q, want %q", got, want)
	}
	// An instance-scoped sandbox root maps to its own state root.
	if root := StateRootFor("/run/sandswap/instance-b/vm"); root != "/run/sandswap-state/b" {
		t.Errorf("StateRootFor(instance-b) = %q, want /run/sandswap-state/b", root)
	}
	// The documented instance layout (<base_dir>/<id>/vm) keeps its readable
	// tag under the standard base dir (the multi-instance e2e reads it).
	if root := StateRootFor("/run/sandswap/ib/vm"); root != "/run/sandswap-state/ib" {
		t.Errorf("StateRootFor(ib) = %q, want /run/sandswap-state/ib", root)
	}
}

// TestStateRootForCustomRootsAreDistinct pins the collision fix: two custom
// roots whose parent directory names match must not share a state root (which
// holds state.json + the warden session key).
func TestStateRootForCustomRootsAreDistinct(t *testing.T) {
	a := StateRootFor("/srv/inst-a/tenant/vm")
	b := StateRootFor("/srv/inst-b/tenant/vm")
	if a == b {
		t.Fatalf("custom roots collided on state root %q", a)
	}
}

// SPDX-License-Identifier: Apache-2.0

func TestWriteStateRefusesPathOutsideRoot(t *testing.T) {
	root := t.TempDir()
	s := persistedState{VMID: "vm-x", SandboxDir: "/tmp/evil-vm"}
	if err := writeState(s, root); err == nil {
		t.Error("writeState with sandbox dir outside root = nil error, want error")
	}
}

func TestLoadStateCorruptJSON(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Dir(testStatePath(dir)), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(testStatePath(dir), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadState(dir); err == nil {
		t.Error("loadState on corrupt JSON = nil error, want error")
	}
}

func TestWriteStateExportedRoundTrip(t *testing.T) {
	root := t.TempDir()
	cfg := vmm.Config{
		ID:         "pool-small-3",
		VCPUs:      1,
		MemoryMB:   256,
		GuestCID:   9,
		SandboxDir: filepath.Join(root, "pool-small-3"),
	}
	apiSocket := filepath.Join(cfg.SandboxDir, "sandvmm.sock")

	if err := WriteState("pool-small-3", cfg, apiSocket, 4242, "small", root); err != nil {
		t.Fatalf("WriteState: %v", err)
	}
	loaded, err := loadState(cfg.SandboxDir)
	if err != nil {
		t.Fatalf("loadState: %v", err)
	}
	if loaded.SpecID != "small" || loaded.CID != 9 || loaded.PID != 4242 {
		t.Errorf("loaded state = %+v, want spec=small cid=9 pid=4242", loaded)
	}
}

func TestRemoveStateExported(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Dir(testStatePath(dir)), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(testStatePath(dir), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	RemoveState(dir)
	if _, err := os.Stat(testStatePath(dir)); !os.IsNotExist(err) {
		t.Error("state.json not removed by RemoveState")
	}
}

func TestRemoveSandboxDirExported(t *testing.T) {
	root := t.TempDir()
	vmDir := filepath.Join(root, "vm-a")
	if err := os.MkdirAll(vmDir, 0o700); err != nil {
		t.Fatal(err)
	}
	RemoveSandboxDir(vmDir, root)
	if _, err := os.Stat(vmDir); !os.IsNotExist(err) {
		t.Error("sandbox dir not removed by RemoveSandboxDir")
	}
}

func TestStateFromConfigNilNetSpec(t *testing.T) {
	cfg := vmm.Config{ID: "vm-a", GuestCID: 5}
	s := stateFromConfig("vm-a", cfg, "/run/sandswap/vm/vm-a/sandvmm.sock", 10, "")
	if s.NetSpec != nil {
		t.Errorf("NetSpec = %+v, want nil for config without net", s.NetSpec)
	}
	if s.CreatedAt.IsZero() {
		t.Error("CreatedAt zero after stateFromConfig")
	}
}

func TestStateFromConfigEmptyGuestIPNoNetSpec(t *testing.T) {
	cfg := vmm.Config{NetSpec: &vmm.VMNetSpec{}}
	s := stateFromConfig("vm-a", cfg, "", 0, "")
	if s.NetSpec != nil {
		t.Errorf("NetSpec = %+v, want nil when GuestIP empty", s.NetSpec)
	}
}

func TestNetSpecToPersistedMissingKeys(t *testing.T) {
	p := netSpecToPersisted(&vmm.VMNetSpec{
		GuestIP:   "10.0.0.2",
		NetConfig: map[string]any{},
	})
	if p.TAP != "" || p.MTU != 0 {
		t.Errorf("persisted net = %+v, want empty TAP/MTU for missing keys", p)
	}
}

func TestConfigFromStateWithNetSpec(t *testing.T) {
	s := &persistedState{
		VMID: "vm-a",
		CID:  7,
		NetSpec: &persistedNet{
			GuestIP: "10.0.0.2",
			Prefix:  24,
			MAC:     "aa:bb:cc:dd:ee:01",
			TAP:     "tap7",
		},
	}
	cfg := configFromState(s)
	if cfg.NetSpec == nil {
		t.Fatal("cfg.NetSpec = nil, want restored spec")
	}
	if cfg.NetSpec.GuestIP != "10.0.0.2" {
		t.Errorf("GuestIP = %q, want 10.0.0.2", cfg.NetSpec.GuestIP)
	}
	if mtu, ok := cfg.NetSpec.NetConfig["mtu"].(int); !ok || mtu != 1500 {
		t.Errorf("default mtu = %v, want 1500", cfg.NetSpec.NetConfig["mtu"])
	}

	s.NetSpec.MTU = 9000
	cfg = configFromState(s)
	if mtu, ok := cfg.NetSpec.NetConfig["mtu"].(int); !ok || mtu != 9000 {
		t.Errorf("persisted mtu = %v, want 9000", cfg.NetSpec.NetConfig["mtu"])
	}
}

// The private-dir contract: writeState lands the file in <sandboxDir>/state/
// with the DIRECTORY at 0700 (the per-VM dir's shared 0770+setgid group must
// not be able to unlink/replace state.json — the re-adopt trust input), and
// loadState migrates a legacy <sandboxDir>/state.json into the private dir
// so a restart across the upgrade re-adopts survivors instead of cleaning
// them.
func TestWriteStatePrivateDirShape(t *testing.T) {
	dir := t.TempDir()
	sandboxDir := filepath.Join(dir, "pool-small-1")
	if err := os.MkdirAll(sandboxDir, 0o755); err != nil {
		t.Fatal(err)
	}
	s := persistedState{Version: stateFormatVersion, SandboxDir: sandboxDir, VMID: "pool-small-1"}
	if err := writeState(s, dir); err != nil {
		t.Fatalf("writeState: %v", err)
	}
	statePath := testStatePath(sandboxDir)
	stateDir := filepath.Dir(statePath)
	fi, err := os.Stat(stateDir)
	if err != nil {
		t.Fatalf("private state dir missing: %v", err)
	}
	if fi.Mode().Perm() != 0o700 {
		t.Fatalf("private state dir mode = %o, want 700 (owner-only)", fi.Mode().Perm())
	}
	if _, err := os.Stat(filepath.Join(sandboxDir, "state")); !os.IsNotExist(err) {
		t.Fatalf("state must not live inside the shared sandbox dir (err=%v)", err)
	}
	// Round-trip through the private location.
	got, err := loadState(sandboxDir)
	if err != nil || got.VMID != "pool-small-1" {
		t.Fatalf("loadState after private-dir write: %v %+v", err, got)
	}
	removeState(sandboxDir)
	if _, err := os.Stat(statePath); !os.IsNotExist(err) {
		t.Fatalf("removeState left %s behind", statePath)
	}
}

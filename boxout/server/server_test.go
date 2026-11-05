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

package server

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	sandlotconfig "sandlot/config"
	"sandlot/core"
	"sandlot/network"
	"sandlot/vmm"
)

func newTestServer(volumesDir string) *Server {
	return &Server{
		cfg:      sandlotconfig.Defaults(),
		vmmCfg:   vmm.Config{VolumesDir: volumesDir, TemplatesDir: "/var/sandswap/templates"},
		netProv:  network.NewNoop(),
		logger:   testLogger(),
		vms:      make(map[string]*managedVM),
		overlays: core.NewOverlaySet(testLogger()),
	}
}

func testLogger() *log.Logger {
	return log.New(os.Stderr, "[boxout-test] ", 0)
}

// TestGetPeerUIDNonUnix verifies getPeerUID rejects non-Unix connections
// (the SO_PEERCRED check only applies to AF_UNIX sockets).
func TestGetPeerUIDNonUnix(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	if _, err := getPeerUID(c1); err == nil {
		t.Error("expected error for non-UnixConn")
	}
}

// TestDispatchUnknownType verifies unknown request types get an ok=false
// response carrying the offending type.
func TestDispatchUnknownType(t *testing.T) {
	s := newTestServer("/var/sandswap/volumes")
	resp := s.dispatch(context.Background(), "bogus_type", map[string]any{"type": "bogus_type"})
	if resp["ok"] != false {
		t.Errorf("expected ok=false, got %v", resp["ok"])
	}
	if msg, _ := resp["error"].(string); msg == "" {
		t.Error("expected an error message")
	}
}

// TestHandleCreateVMValidation covers the create_vm parameter whitelist: every
// rejection branch returns before any process launch (no KVM/root needed).
func TestHandleCreateVMValidation(t *testing.T) {
	s := newTestServer("/var/sandswap/volumes")
	cases := []struct {
		name   string
		req    map[string]any
		errSub string
	}{
		{"missing vm_id", map[string]any{}, "missing vm_id"},
		{"vm_id path traversal", map[string]any{"vm_id": "../../etc"}, "must be a single path element"},
		{"vm_id slash", map[string]any{"vm_id": "a/b"}, "must be a single path element"},
		{"vm_id dotdot", map[string]any{"vm_id": ".."}, "must be a single path element"},
		{"warden_log cmdline injection", map[string]any{"vm_id": "vm-1", "warden_log": "info warden.warden_countdown_sec=999999"}, "not a log level"},
		{"warden_log invalid", map[string]any{"vm_id": "vm-1", "warden_log": "verbose"}, "not a log level"},
		{"warden_countdown too large", map[string]any{"vm_id": "vm-1", "warden_countdown_sec": float64(999999999)}, "must be an integer <="},
		{"warden_max_exec too large", map[string]any{"vm_id": "vm-1", "warden_max_exec_timeout_sec": float64(999999999)}, "must be an integer <="},
		{"kernel not allowed", map[string]any{"vm_id": "vm-1", "kernel": "/evil/kernel"}, "kernel path not allowed"},
		{"initramfs not allowed", map[string]any{"vm_id": "vm-1", "initramfs": "/evil/initrd"}, "initramfs path not allowed"},
		{"volumes_dir not allowed", map[string]any{"vm_id": "vm-1", "volumes_dir": "/evil/vol"}, "volumes_dir not allowed"},
		{"sandbox_dir bad prefix", map[string]any{"vm_id": "vm-1", "sandbox_dir": "/tmp/evil"}, "sandbox_dir must be under"},
		{"sandbox_dir traversal", map[string]any{"vm_id": "vm-1", "sandbox_dir": "/run/sandswap/../evil/vm/"}, "path traversal"},
		{"vcpus too many", map[string]any{"vm_id": "vm-1", "vcpus": float64(32)}, "must be an integer in [1, 16]"},
		{"memory too much", map[string]any{"vm_id": "vm-1", "memory_mb": float64(16384)}, "must be an integer in [64, 8192]"},
		{"guest_cid below floor", map[string]any{"vm_id": "vm-1", "guest_cid": float64(2)}, "must be an integer in [3,"},
		{"guest_cid zero", map[string]any{"vm_id": "vm-1", "guest_cid": float64(0)}, "must be an integer in [3,"},
		// A negative float wraps on the uint32 cast (0xFFFF...FB ≥ 3) and used
		// to pass the floor check, failing only later at device activation.
		{"guest_cid negative float", map[string]any{"vm_id": "vm-1", "guest_cid": float64(-5)}, "must be an integer in [3,"},
		{"guest_cid fractional", map[string]any{"vm_id": "vm-1", "guest_cid": float64(3.5)}, "must be an integer in [3,"},
		// Above uint32 the float cast wraps to a small (possibly reserved) CID.
		{"guest_cid above uint32", map[string]any{"vm_id": "vm-1", "guest_cid": float64(5000000000)}, "must be an integer in [3,"},
		{"net_spec unparseable", map[string]any{"vm_id": "vm-1", "net_spec": map[string]any{"GuestIP": 123}}, "parse net_spec"},
	}
	for _, c := range cases {
		resp := s.handleCreateVM(context.Background(), c.req)
		if resp["ok"] != false {
			t.Errorf("%s: expected ok=false, got %v", c.name, resp["ok"])
		}
		if msg, _ := resp["error"].(string); !strings.Contains(msg, c.errSub) {
			t.Errorf("%s: error %q does not contain %q", c.name, msg, c.errSub)
		}
	}
	if len(s.vms) != 0 {
		t.Errorf("rejected requests must not register VMs, got %d", len(s.vms))
	}
	if len(s.reserved) != 0 {
		t.Errorf("rejected requests leaked admission reservations, got %v", s.reserved)
	}
}

// Admission is a RESERVATION, not a bare check: the VM is registered only
// after a multi-second launch, so two concurrent creates must not both pass
// the same bound. Releasing the reservation (a failed create) frees the slot.
func TestAdmitVMReservesAtomically(t *testing.T) {
	s := newTestServer("/var/sandswap/volumes")
	s.SetLimits(1, 0)

	if err := s.admitVM("vm-a", 128); err != nil {
		t.Fatalf("first admission: %v", err)
	}
	if err := s.admitVM("vm-b", 128); err == nil {
		t.Fatal("a second in-flight create must not pass a count bound of 1")
	}
	if err := s.admitVM("vm-a", 128); err == nil {
		t.Fatal("a duplicate in-flight vm_id must be refused")
	}
	s.releaseReservation("vm-a")
	if err := s.admitVM("vm-b", 128); err != nil {
		t.Fatalf("after release the slot must be reusable: %v", err)
	}
	s.releaseReservation("vm-b")

	s.SetLimits(0, 200)
	if err := s.admitVM("vm-c", 150); err != nil {
		t.Fatalf("aggregate: first admission: %v", err)
	}
	if err := s.admitVM("vm-d", 100); err == nil {
		t.Fatal("aggregate bound must count in-flight reservations")
	}
	s.releaseReservation("vm-c")
	if err := s.admitVM("vm-d", 100); err != nil {
		t.Fatalf("aggregate: after release: %v", err)
	}
}

// The network RPCs use vm_id as a resource key and reach the privileged
// provider; they must enforce the same single-path-element grammar as
// create_vm.
func TestNetworkHandlersValidateVMID(t *testing.T) {
	s := newTestServer("/var/sandswap/volumes")
	for _, bad := range []string{"", "../x", "a/b", ".."} {
		if resp := s.handleProvisionNetwork(context.Background(), map[string]any{"vm_id": bad}); resp["ok"] != false {
			t.Errorf("provision vm_id %q must be refused, got %v", bad, resp["ok"])
		}
		if resp := s.handleReleaseNetwork(context.Background(), map[string]any{"vm_id": bad}); resp["ok"] != false {
			t.Errorf("release vm_id %q must be refused, got %v", bad, resp["ok"])
		}
		if resp := s.handleReclaimNetwork(context.Background(), map[string]any{"vm_id": bad}); resp["ok"] != false {
			t.Errorf("reclaim vm_id %q must be refused, got %v", bad, resp["ok"])
		}
	}
}

// TestHandleOverlayValidation covers mount/unmount overlay path validation:
// missing path, outside VolumesDir, and traversal are rejected without any
// mount syscall (CAP_SYS_ADMIN branches untouched).
func TestHandleOverlayValidation(t *testing.T) {
	s := newTestServer("/var/sandswap/volumes")
	cases := []struct {
		name string
		req  map[string]any
	}{
		{"mount missing", map[string]any{}},
		{"mount outside", map[string]any{"volume_path": "/tmp/agent"}},
		{"mount traversal", map[string]any{"volume_path": "/var/sandswap/volumes/../etc"}},
	}
	for _, c := range cases {
		resp := s.handleMountOverlay(context.Background(), c.req)
		if resp["ok"] != false {
			t.Errorf("%s: expected ok=false, got %v (%v)", c.name, resp["ok"], resp["error"])
		}
	}
	unCases := []struct {
		name string
		req  map[string]any
	}{
		{"unmount missing", map[string]any{}},
		{"unmount outside", map[string]any{"volume_path": "/tmp/agent"}},
		{"unmount traversal", map[string]any{"volume_path": "/var/sandswap/volumes/.."}},
	}
	for _, c := range unCases {
		resp := s.handleUnmountOverlay(context.Background(), c.req)
		if resp["ok"] != false {
			t.Errorf("%s: expected ok=false, got %v (%v)", c.name, resp["ok"], resp["error"])
		}
	}
}

// TestOverlayHandlersRefuseEmptyVolumesDir pins the sweep class ("an
// empty configuration value must never silently disable a containment
// check"): the overlay path whitelist is built as VolumesDir+"/", which with
// an EMPTY VolumesDir degenerates to "/" — every absolute path would pass. A
// server with no volumes dir configured must refuse, naming the
// misconfiguration, rather than test containment against "/".
func TestOverlayHandlersRefuseEmptyVolumesDir(t *testing.T) {
	s := newTestServer("")
	for _, path := range []string{"/etc/passwd", "/", "/var/sandswap/volumes/x"} {
		resp := s.handleMountOverlay(context.Background(), map[string]any{"volume_path": path})
		if resp["ok"] != false {
			t.Fatalf("mount_overlay %s: expected refusal with no VolumesDir, got %v", path, resp["ok"])
		}
		if msg, _ := resp["error"].(string); !strings.Contains(msg, "volumes") {
			t.Fatalf("mount_overlay %s: refusal %q must name the missing volumes dir", path, msg)
		}
		resp = s.handleUnmountOverlay(context.Background(), map[string]any{"volume_path": path})
		if resp["ok"] != false {
			t.Fatalf("unmount_overlay %s: expected refusal with no VolumesDir, got %v", path, resp["ok"])
		}
		if msg, _ := resp["error"].(string); !strings.Contains(msg, "volumes") {
			t.Fatalf("unmount_overlay %s: refusal %q must name the missing volumes dir", path, msg)
		}
	}
}

// TestHandleCreateVMNetSpecGrammar pins: the net_spec fields are baked
// into the kernel cmdline (GuestIP/Gateway/GuestIP6/Gateway6/DNS/MAC become
// `warden.*=` tokens that the warden splits on ASCII whitespace), so a value
// carrying whitespace injects independent warden.* arguments from the
// unprivileged side. Every non-matching value must be refused BY NAME before
// anything is launched; a mismatched value must never be "cleaned" in place.
// The legitimate forms below are the exact shapes the two providers emit
// (sandlot/network/bridge_nat.go + routed6.go Provision) with the DNS values
// the deploy tooling configures (deploy/baremetal/common.sh `dns:
// "1.1.1.1,8.8.8.8"`).
func TestHandleCreateVMNetSpecGrammar(t *testing.T) {
	bad := []struct {
		name   string
		spec   map[string]any
		errSub string
	}{
		{"v4 ip with injected warden token", map[string]any{
			"GuestIP": "10.0.0.1 warden.warden_countdown_sec=999999", "Prefix": float64(16), "Gateway": "10.0.0.1",
		}, "guest_ip"},
		{"v4 ip with newline", map[string]any{
			"GuestIP": "10.0.0.1\nwarden.log=debug", "Prefix": float64(16), "Gateway": "10.0.0.1",
		}, "guest_ip"},
		{"gateway with injected warden token", map[string]any{
			"GuestIP": "10.0.0.1", "Prefix": float64(16), "Gateway": "10.0.0.1 warden.max_body_len=999999999",
		}, "gateway"},
		{"v6 ip with injected warden token", map[string]any{
			"GuestIP6": "fd00::1 warden.log=debug", "Prefix6": float64(64), "Gateway6": "fd00::1",
		}, "guest_ip6"},
		{"v6 ip carrying a v4 address", map[string]any{
			"GuestIP6": "10.0.0.1", "Prefix6": float64(64), "Gateway6": "fd00::1",
		}, "guest_ip6"},
		{"dns entry with injected warden token", map[string]any{
			"GuestIP": "10.0.0.1", "Prefix": float64(16), "Gateway": "10.0.0.1",
			"DNS": []any{"1.1.1.1 warden.log=debug"},
		}, "dns"},
		{"dns entry not an address", map[string]any{
			"GuestIP": "10.0.0.1", "Prefix": float64(16), "Gateway": "10.0.0.1",
			"DNS": []any{"resolver.internal"},
		}, "dns"},
		{"mac with injected warden token", map[string]any{
			"GuestIP": "10.0.0.1", "Prefix": float64(16), "Gateway": "10.0.0.1",
			"MAC": "02:00:00:00:00:01 warden.log=debug",
		}, "mac"},
		{"prefix out of range", map[string]any{
			"GuestIP": "10.0.0.1", "Prefix": float64(33), "Gateway": "10.0.0.1",
		}, "prefix"},
		{"v6 prefix out of range", map[string]any{
			"GuestIP6": "fd00::2", "Prefix6": float64(129), "Gateway6": "fd00::1",
		}, "prefix6"},
	}
	for _, c := range bad {
		// The create_vm leg must refuse BEFORE any launch; point the binary at
		// a nonexistent path so a failure to refuse cannot silently "pass" by
		// way of an unrelated launch error.
		s := newTestServer("/var/sandswap/volumes")
		s.vmmCfg.VMMBinary = "/nonexistent/sandvmm-must-not-run"
		// A RED run (validation absent) reaches vmm.Launch, which creates the
		// sandbox dir before failing — remove whatever a failed refusal left.
		vmID := fmt.Sprintf("u7-red-%d", os.Getpid())
		sandbox := filepath.Join("/run/sandswap/vm", vmID)
		t.Cleanup(func() { os.RemoveAll(sandbox) })
		resp := s.handleCreateVM(context.Background(), map[string]any{
			"vm_id": vmID, "sandbox_dir": sandbox,
			"net_spec": c.spec,
		})
		if resp["ok"] != false {
			t.Fatalf("create_vm %s: the injected spec was NOT refused (ok=%v)", c.name, resp["ok"])
		}
		msg, _ := resp["error"].(string)
		if !strings.Contains(msg, "net_spec") || !strings.Contains(msg, c.errSub) {
			t.Fatalf("create_vm %s: refusal %q must be a named net_spec error mentioning %q", c.name, msg, c.errSub)
		}
		// Same spec over reclaim_network: the caller's addressing is not a
		// trust source at all — reclaim refuses without boxout's OWN persisted
		// state, and never relays the injected spec to the provider.
		resp = s.handleReclaimNetwork(context.Background(), map[string]any{"vm_id": "vm-1", "net_spec": c.spec})
		if resp["ok"] != false {
			t.Fatalf("reclaim_network %s: the injected spec was NOT refused (ok=%v)", c.name, resp["ok"])
		}
		if msg, _ := resp["error"].(string); !strings.Contains(msg, "no persisted state") {
			t.Fatalf("reclaim_network %s: refusal %q must name the missing persisted state (caller addressing is ignored)", c.name, msg)
		}
	}

	// A present-but-non-object net_spec must be refused, never silently
	// skipped (a skipped spec silently becomes an offline VM).
	s := newTestServer("/var/sandswap/volumes")
	resp := s.handleCreateVM(context.Background(), map[string]any{"vm_id": "vm-1", "net_spec": "10.0.0.1"})
	if resp["ok"] != false {
		t.Fatalf("a non-object net_spec must be refused, got ok=%v", resp["ok"])
	}
	if msg, _ := resp["error"].(string); !strings.Contains(msg, "net_spec must be an object") {
		t.Fatalf("refusal %q must name the net_spec type problem", msg)
	}

	// Legitimate forms must keep passing the grammar (the handler leg cannot
	// assert ok=true without a VMM; the GRAMMAR is what this asserts — the
	// refusal above must not be reachable through any shape the deploy
	// tooling actually emits).
	good := []vmm.VMNetSpec{
		{ // bridge-nat shape (bridge_nat.go Provision)
			GuestIP: "10.188.0.5", Prefix: 16, Gateway: "10.188.0.1",
			DNS: []string{"1.1.1.1", "8.8.8.8"}, MAC: "02:1a:2b:3c:4d:5e",
			NetConfig: map[string]any{"tap": "tap-0123456789", "mac": "02:1a:2b:3c:4d:5e", "mtu": 1500},
		},
		{ // routed-ipv6 shape (routed6.go Provision)
			GuestIP6: "fd00:5341:4e44:1:9f0b:6f8f:11f7:da88", Prefix6: 64, Gateway6: "fd00:5341:4e44:1::1",
			DNS: []string{"1.1.1.1"}, MAC: "02:aa:bb:cc:dd:ee",
			NetConfig: map[string]any{"tap": "tap-abcdef0123", "mac": "02:aa:bb:cc:dd:ee", "mtu": 1500},
		},
		{ // dual-stack host: both families on one spec
			GuestIP: "10.188.7.42", Prefix: 16, Gateway: "10.188.0.1",
			GuestIP6: "fd00:5341:4e44:7:2222:3333:4444:5555", Prefix6: 64, Gateway6: "fd00:5341:4e44:7::1",
			DNS: []string{"1.1.1.1"}, MAC: "02:00:5e:00:53:01",
		},
		{ // offline (noop backend): no addressing at all
			NetConfig: nil,
		},
	}
	for i, spec := range good {
		if err := spec.Validate(); err != nil {
			t.Errorf("legitimate spec %d was refused: %v", i, err)
		}
	}
}

// TestHandleReadoptVMsValidation covers the sandbox_root whitelist for
// re-adopt scans (invalid roots rejected before any /proc scanning).
func TestHandleReadoptVMsValidation(t *testing.T) {
	s := newTestServer("/var/sandswap/volumes")
	cases := []struct {
		name string
		req  map[string]any
	}{
		{"bad root", map[string]any{"sandbox_root": "/tmp/vm"}},
		{"traversal root", map[string]any{"sandbox_root": "/run/sandswap/../vm"}},
	}
	for _, c := range cases {
		resp := s.handleReadoptVMs(context.Background(), c.req)
		if resp["ok"] != false {
			t.Errorf("%s: expected ok=false, got %v (%v)", c.name, resp["ok"], resp["error"])
		}
	}
}

// TestHandleNetworkNoop exercises provision/release/reclaim against the Noop
// provider (offline backend): all succeed without privileges.
func TestHandleNetworkNoop(t *testing.T) {
	s := newTestServer("/var/sandswap/volumes")

	resp := s.handleProvisionNetwork(context.Background(), map[string]any{"vm_id": "vm-1"})
	if resp["ok"] != true {
		t.Errorf("provision: expected ok=true, got %v (%v)", resp["ok"], resp["error"])
	}
	spec, _ := resp["net_spec"].(vmm.VMNetSpec)
	if spec.GuestIP != "" {
		t.Errorf("noop provision must yield an empty (offline) spec, got %+v", spec)
	}

	if resp := s.handleReleaseNetwork(context.Background(), map[string]any{"vm_id": "vm-1"}); resp["ok"] != true {
		t.Errorf("release: expected ok=true, got %v (%v)", resp["ok"], resp["error"])
	}
	// Reclaim without boxout-owned persisted state is refused: the caller's
	// net_spec is not a trust source, so there is nothing to re-export.
	if resp := s.handleReclaimNetwork(context.Background(), map[string]any{
		"vm_id":    "vm-1",
		"net_spec": map[string]any{"GuestIP": "10.1.2.3", "Gateway": "10.1.0.1", "Prefix": float64(16)},
	}); resp["ok"] != false {
		t.Errorf("reclaim without persisted state: expected ok=false, got %v", resp["ok"])
	}
}

// TestHandleOverlayLifecycleRPCs verifies the overlay tracking RPCs: restore
// rebuilds the set from mountinfo (count reported), cleanup sweeps stale
// entries via the shared OverlaySet, and mount/unmount validation failures
// never touch the tracking set. The mount/unmount success paths need
// CAP_SYS_ADMIN and are covered by the e2e/deploy suites.
func TestHandleOverlayLifecycleRPCs(t *testing.T) {
	s := newTestServer("/var/sandswap/volumes")

	// restore_overlays: ok + a restored count (0 on a bare test namespace).
	r := s.handleRestoreOverlays(context.Background(), nil)
	if r["ok"] != true {
		t.Fatalf("restore_overlays: expected ok=true, got %v", r)
	}
	if _, ok := r["restored"]; !ok {
		t.Error("restore_overlays: response must carry a restored count")
	}

	// cleanup_overlays: ok + cleaned/failed counters over the (empty) set.
	r = s.handleCleanupOverlays(context.Background(), nil)
	if r["ok"] != true {
		t.Fatalf("cleanup_overlays: expected ok=true, got %v", r)
	}
	if r["cleaned"] != 0 || r["failed"] != 0 {
		t.Errorf("cleanup_overlays on an empty set: expected 0/0, got %v/%v", r["cleaned"], r["failed"])
	}

	// Rejected mount/unmount requests must not touch the tracking set.
	before := len(s.overlays.Tracked())
	for _, bad := range []map[string]any{
		{},
		{"volume_path": "/tmp/agent"},
		{"volume_path": "/var/sandswap/volumes/../etc"},
	} {
		if resp := s.handleMountOverlay(context.Background(), bad); resp["ok"] == true {
			t.Fatalf("mount_overlay %v unexpectedly succeeded", bad)
		}
		if resp := s.handleUnmountOverlay(context.Background(), bad); resp["ok"] == true {
			t.Fatalf("unmount_overlay %v unexpectedly succeeded", bad)
		}
	}
	if after := len(s.overlays.Tracked()); after != before {
		t.Errorf("rejected overlay RPCs must not change tracking: before=%d after=%d", before, after)
	}

	// Track/untrack bookkeeping drives the sweep set (the success paths are
	// privileged; here we verify the handlers' bookkeeping contract directly).
	s.overlays.Track("/var/sandswap/volumes/sandfs-deadbeef", "")
	if got := len(s.overlays.Tracked()); got != before+1 {
		t.Errorf("Track: expected set size %d, got %d", before+1, got)
	}
	s.overlays.Untrack("/var/sandswap/volumes/sandfs-deadbeef")
	if got := len(s.overlays.Tracked()); got != before {
		t.Errorf("Untrack: expected set size %d, got %d", before, got)
	}
}

// TestHandleDestroyVMUntracked verifies destroy of an unknown VM is idempotent
// (ok=true, no kill issued when no PID is given).
func TestHandleDestroyVMUntracked(t *testing.T) {
	// The untracked path no longer acts on a bare vm_id: without a validated
	// sandbox_dir there is nothing it may safely do (the old code would kill
	// an arbitrary pid and RemoveAll an arbitrary dir).
	s := newTestServer("/var/sandswap/volumes")
	resp := s.handleDestroyVM(context.Background(), map[string]any{"vm_id": "ghost"})
	if resp["ok"] != false {
		t.Errorf("expected refusal ok=false, got %v", resp["ok"])
	}
	if msg, _ := resp["error"].(string); !strings.Contains(msg, "missing sandbox_dir") {
		t.Errorf("error %q does not name the missing sandbox_dir", msg)
	}
}

// makeTestSandboxDir creates a valid (prefix-shaped) sandbox dir under the
// real /run/sandswap/vm root, removed at test end. Root-gated by callers.
func makeTestSandboxDir(t *testing.T, name string) string {
	t.Helper()
	dir := filepath.Join("/run/sandswap/vm", fmt.Sprintf("%s-%d", name, os.Getpid()))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// startFakeSandvmm starts a bash copy named "sandvmm" whose /proc cmdline
// reads exactly like a real sandvmm invocation — argv0 basename "sandvmm" +
// "--api-socket <apiSocket>" — which is precisely what
// core.IsSandvmmProcWithSocket verifies. Returns the live child once the
// PREDICATE ITSELF confirms readiness: exec.Start() returns after FORK but
// before the child's execve lands, and in that window /proc/<pid>/cmdline
// still shows the test binary's argv (the destroy path would rightly refuse
// to kill a non-sandvmm).
func startFakeSandvmm(t *testing.T, apiSocket string) (*exec.Cmd, core.SandvmmIdentity) {
	t.Helper()
	fakeBin := filepath.Join(t.TempDir(), "sandvmm")
	bashBin, err := exec.LookPath("bash")
	if err != nil {
		t.Fatalf("lookpath bash: %v", err)
	}
	if err := exec.Command("cp", bashBin, fakeBin).Run(); err != nil {
		t.Fatalf("copy fake sandvmm: %v", err)
	}
	if err := os.Chmod(fakeBin, 0o755); err != nil {
		t.Fatalf("chmod fake sandvmm: %v", err)
	}
	// The script must NOT be a single simple command: bash tail-exec-optimizes
	// `bash -c "sleep 300"` into `sleep 300`, replacing argv0 and dropping the
	// --api-socket args from /proc cmdline — the destroy path then rightly
	// refuses to kill a non-sandvmm (a flake that fired once per ~dozen runs).
	// A compound loop keeps bash as the process, so cmdline stays
	// "sandvmm -c <script> --api-socket <path>" for the whole lifetime.
	child := exec.Command(fakeBin, "-c", "trap '' TERM; while :; do sleep 1; done", "--api-socket", apiSocket)
	if err := child.Start(); err != nil {
		t.Fatalf("start child: %v", err)
	}
	t.Cleanup(func() {
		if child.Process != nil {
			child.Process.Kill()
		}
	})
	identity := core.NewSandvmmIdentity(uint32(os.Geteuid()), fakeBin)
	for i := 0; i < 200; i++ {
		if core.IsSandvmmProcWithSocket(child.Process.Pid, apiSocket, identity) {
			return child, identity
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("fake sandvmm pid %d never verified its executable/uid (script or argv broke)", child.Process.Pid)
	return nil, core.SandvmmIdentity{}
}

// TestHandleDestroyVMUntrackedKillsAndCleans verifies the crash/destroy path:
// an UNTRACKED VM (sandlot already dropped it from its map — the warden-hung
// teardown) is still killed by PID and its state/sandbox dir removed via
// sandbox_dir — for a sandbox_dir that PASSES validation and a pid that
// /proc-verified as the sandvmm serving exactly that sandbox. Pins both the
// original leak fix (no early return leaving residue behind) and the boundary
// hardening (validated path + verified pid). Root-gated: creating
// /run/sandswap/vm/... and reading another process's /proc cmdline need it.
func TestHandleDestroyVMUntrackedKillsAndCleans(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to create /run/sandswap/vm and verify a foreign pid's cmdline")
	}
	s := newTestServer("/var/sandswap/volumes")
	sandboxDir := makeTestSandboxDir(t, "boxout-test")
	statePath := filepath.Join(sandboxDir, "state.json")
	if err := os.WriteFile(statePath, []byte("{}"), 0o644); err != nil {
		t.Fatalf("write state: %v", err)
	}

	expectedSocket := filepath.Join(sandboxDir, "sandvmm.sock")
	child, fakeID := startFakeSandvmm(t, expectedSocket)
	// The destroy path's identity check uses the server's configured VMM
	// image/uid; point it at the fake binary the test launched.
	s.vmmCfg.VMMUID = fakeID.UID
	s.vmmCfg.VMMBinary = fakeID.BinaryPath

	resp := s.handleDestroyVM(context.Background(), map[string]any{
		"vm_id":       filepath.Base(sandboxDir),
		"pid":         float64(child.Process.Pid),
		"sandbox_dir": sandboxDir,
		"api_socket":  expectedSocket,
	})
	if resp["ok"] != true {
		t.Fatalf("expected ok=true, got %v (%v)", resp["ok"], resp["error"])
	}

	// Process must be dead (Wait reaps the zombie we created via SIGKILL).
	done := make(chan error, 1)
	go func() { done <- child.Wait() }()
	select {
	case <-done: // exited — good
	case <-time.After(2 * time.Second):
		t.Fatal("untracked destroy did not kill the pid")
	}

	// State + sandbox dir must be gone.
	if _, err := os.Stat(statePath); !os.IsNotExist(err) {
		t.Errorf("state.json still present after untracked destroy (err=%v)", err)
	}
	if _, err := os.Stat(sandboxDir); !os.IsNotExist(err) {
		t.Errorf("sandbox dir still present after untracked destroy (err=%v)", err)
	}
}

// The untracked destroy's signal target is DISCOVERED from /proc by the socket
// derived from the validated sandbox path. Caller-supplied pid/api_socket are
// not trust sources, so they cannot aim the destroy at a process outside the
// named sandbox; naming the sandbox that a sandvmm actually serves cleans it up.
//
// Root-gated: creating /run/sandswap/vm/... and reading a foreign pid's
// /proc cmdline need privilege.
func TestUntrackedDestroyBindsToDiscoveredSandvmm(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to create /run/sandswap/vm and verify a foreign pid's cmdline")
	}
	s := newTestServer("/var/sandswap/volumes")
	siblingDir := makeTestSandboxDir(t, "boxout-sibling")
	siblingSocket := filepath.Join(siblingDir, "sandvmm.sock")
	child, fakeID := startFakeSandvmm(t, siblingSocket)
	s.vmmCfg.VMMUID = fakeID.UID
	s.vmmCfg.VMMBinary = fakeID.BinaryPath
	siblingAlive := func() bool {
		return core.IsSandvmmProcWithSocket(child.Process.Pid, siblingSocket, fakeID)
	}

	// Leg 1: name a DIFFERENT sandbox while supplying the sibling's pid and
	// socket. The scan of the named sandbox finds nothing to signal — the
	// sibling must survive, and only the named dir/state is cleaned.
	otherDir := makeTestSandboxDir(t, "boxout-other")
	otherState := filepath.Join(otherDir, "state.json")
	if err := os.WriteFile(otherState, []byte("{}"), 0o644); err != nil {
		t.Fatalf("write state: %v", err)
	}
	resp := s.handleDestroyVM(context.Background(), map[string]any{
		"vm_id": filepath.Base(otherDir), "pid": float64(child.Process.Pid),
		"sandbox_dir": otherDir, "api_socket": siblingSocket,
	})
	if resp["ok"] != true {
		t.Fatalf("idempotent cleanup of an unserved sandbox refused: %v", resp["error"])
	}
	if !siblingAlive() {
		t.Fatal("caller-supplied pid/api_socket aimed the untracked destroy at a foreign sandvmm")
	}
	if _, err := os.Stat(otherDir); !os.IsNotExist(err) {
		t.Errorf("named sandbox dir still present after untracked destroy (err=%v)", err)
	}

	// Leg 2: naming the sandbox the sibling actually serves discovers its pid
	// from /proc (no pid in the request) and cleans it up.
	resp = s.handleDestroyVM(context.Background(), map[string]any{
		"vm_id": filepath.Base(siblingDir), "sandbox_dir": siblingDir,
	})
	if resp["ok"] != true {
		t.Fatalf("destroy of a served sandbox refused: %v", resp["error"])
	}
	done := make(chan error, 1)
	go func() { done <- child.Wait() }()
	select {
	case <-done: // exited — good
	case <-time.After(2 * time.Second):
		t.Fatal("untracked destroy did not signal the sandvmm holding the sandbox socket")
	}

	// Leg 3: the idempotent no-process shape still cleans dir+state.
	ghostDir := makeTestSandboxDir(t, "boxout-ghost")
	ghostState := filepath.Join(ghostDir, "state.json")
	if err := os.WriteFile(ghostState, []byte("{}"), 0o644); err != nil {
		t.Fatalf("write state: %v", err)
	}
	resp = s.handleDestroyVM(context.Background(), map[string]any{"vm_id": filepath.Base(ghostDir), "sandbox_dir": ghostDir})
	if resp["ok"] != true {
		t.Fatalf("no-process idempotent destroy refused: %v", resp["error"])
	}
	if _, err := os.Stat(ghostDir); !os.IsNotExist(err) {
		t.Errorf("ghost sandbox dir still present after no-process destroy (err=%v)", err)
	}
}

// startBoxoutSocket serves boxout's newline-delimited JSON protocol on a Unix
// socket under t.TempDir(). allowedUID is set to the test process's own UID so
// the SO_PEERCRED check passes without root.
func startBoxoutSocket(t *testing.T) string {
	t.Helper()
	_, sock := startBoxoutSocketSrv(t, nil)
	return sock
}

// startBoxoutSocketSrv is startBoxoutSocket with access to the Server (and an
// optional configure hook) for tests of the RPC resource bounds.
func startBoxoutSocketSrv(t *testing.T, configure func(*Server)) (*Server, string) {
	t.Helper()
	dir := t.TempDir()
	sock := filepath.Join(dir, "test.sock")
	lis, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { lis.Close(); os.Remove(sock) })

	s := newTestServer("/var/sandswap/volumes")
	s.allowedUID = uint32(os.Getuid())
	if configure != nil {
		configure(s)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() {
		for {
			conn, err := lis.Accept()
			if err != nil {
				return
			}
			go s.HandleConn(ctx, conn)
		}
	}()
	time.Sleep(50 * time.Millisecond)
	return s, sock
}

// roundTrip sends one newline-delimited JSON request and reads one response.
func roundTrip(t *testing.T, conn net.Conn, req map[string]any) map[string]any {
	t.Helper()
	line, _ := json.Marshal(req)
	if _, err := conn.Write(append(line, '\n')); err != nil {
		t.Fatalf("write: %v", err)
	}
	rdr := bufio.NewReader(conn)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	raw, err := rdr.ReadBytes('\n')
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal %q: %v", raw, err)
	}
	return m
}

// TestBoxoutSocketEndToEnd drives handleConn over a real Unix socket: peer UID
// matches (same process), requests dispatch, responses echo the request type.
func TestBoxoutSocketEndToEnd(t *testing.T) {
	sock := startBoxoutSocket(t)
	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	m := roundTrip(t, conn, map[string]any{"type": "restore_overlays"})
	if m["type"] != "restore_overlays" || m["ok"] != true {
		t.Errorf("restore_overlays: got %v", m)
	}

	m = roundTrip(t, conn, map[string]any{"type": "cleanup_overlays"})
	if m["type"] != "cleanup_overlays" || m["ok"] != true {
		t.Errorf("cleanup_overlays: got %v", m)
	}

	m = roundTrip(t, conn, map[string]any{"type": "provision_network", "vm_id": "vm-e2e"})
	if m["type"] != "provision_network" || m["ok"] != true {
		t.Errorf("provision_network: got %v", m)
	}

	m = roundTrip(t, conn, map[string]any{"type": "create_vm"})
	if m["type"] != "create_vm" || m["ok"] != false || m["error"] != "missing vm_id" {
		t.Errorf("create_vm validation: got %v", m)
	}

	m = roundTrip(t, conn, map[string]any{"type": "mystery"})
	if m["ok"] != false {
		t.Errorf("unknown type: expected ok=false, got %v", m)
	}
}

// TestBoxoutSocketBadJSON verifies a malformed request line yields an inline
// error response and the connection stays usable for the next request.
func TestBoxoutSocketBadJSON(t *testing.T) {
	sock := startBoxoutSocket(t)
	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	conn.Write([]byte("{not json\n"))
	rdr := bufio.NewReader(conn)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	raw, err := rdr.ReadBytes('\n')
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if m["ok"] != false {
		t.Errorf("expected ok=false for bad JSON, got %v", m)
	}

	m = roundTrip(t, conn, map[string]any{"type": "restore_overlays"})
	if m["ok"] != true {
		t.Errorf("connection should survive a bad line, got %v", m)
	}
}

// TestBoxoutSocketEmptyLinesIgnored verifies empty lines produce no response.
func TestBoxoutSocketEmptyLinesIgnored(t *testing.T) {
	sock := startBoxoutSocket(t)
	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	conn.Write([]byte("\n\n"))
	m := roundTrip(t, conn, map[string]any{"type": "restore_overlays"})
	if m["ok"] != true {
		t.Errorf("empty lines should be skipped, got %v", m)
	}
}

// --- egress identity relay handlers (net_stamp_identity / net_mount_state) ---

// recordingNetProvider captures the identity hooks boxout is asked to run,
// standing in for the privileged routed-ipv6 provider.
type recordingNetProvider struct {
	vmm.NetworkProvider

	vmIDs     []string
	agents    []string
	sandfs    []string
	epochs    []uint64
	mounted   []bool
	gateVMs   []string
	reclaimed map[string]vmm.VMNetSpec
}

func (p *recordingNetProvider) SetMountIdentity(_ context.Context, vmID, agentID, sandfsID string, epoch uint64) {
	p.vmIDs = append(p.vmIDs, vmID)
	p.agents = append(p.agents, agentID)
	p.sandfs = append(p.sandfs, sandfsID)
	p.epochs = append(p.epochs, epoch)
}

func (p *recordingNetProvider) SetMountState(_ context.Context, vmID string, mounted bool) {
	p.gateVMs = append(p.gateVMs, vmID)
	p.mounted = append(p.mounted, mounted)
}

func (p *recordingNetProvider) Reclaim(_ context.Context, vmID string, spec vmm.VMNetSpec) error {
	if p.reclaimed == nil {
		p.reclaimed = make(map[string]vmm.VMNetSpec)
	}
	p.reclaimed[vmID] = spec
	return nil
}

func TestHandleNetStampIdentity(t *testing.T) {
	s := newTestServer("/var/sandswap/volumes")
	rec := &recordingNetProvider{NetworkProvider: s.netProv}
	s.netProv = rec

	resp := s.dispatch(context.Background(), "net_stamp_identity", map[string]any{
		"vm_id":     "vm-9",
		"agent_id":  "agent-a",
		"sandfs_id": "sandfs-b",
		"epoch":     float64(11),
	})
	if resp["ok"] != true {
		t.Fatalf("stamp dispatch must succeed, got %v (%v)", resp["ok"], resp["error"])
	}
	if len(rec.vmIDs) != 1 || rec.vmIDs[0] != "vm-9" || rec.agents[0] != "agent-a" ||
		rec.sandfs[0] != "sandfs-b" || rec.epochs[0] != 11 {
		t.Fatalf("stamper received %+v", rec)
	}

	// Missing vm_id must be rejected loudly.
	resp = s.dispatch(context.Background(), "net_stamp_identity", map[string]any{"agent_id": "a"})
	if resp["ok"] != false {
		t.Fatal("stamp without vm_id must fail")
	}
}

// TestHandleNetStampIdentityUnsupported: providers without identity support
// (bridge backend) are a clean no-op success — the contract degrades to
// unstamped egress, never to a mount failure.
func TestHandleNetStampIdentityUnsupported(t *testing.T) {
	s := newTestServer("/var/sandswap/volumes") // Noop provider: no stamper
	resp := s.dispatch(context.Background(), "net_stamp_identity", map[string]any{"vm_id": "vm-1"})
	if resp["ok"] != true {
		t.Fatalf("unsupported backend must no-op success, got %v (%v)", resp["ok"], resp["error"])
	}
}

func TestHandleNetMountState(t *testing.T) {
	s := newTestServer("/var/sandswap/volumes")
	rec := &recordingNetProvider{NetworkProvider: s.netProv}
	s.netProv = rec

	resp := s.dispatch(context.Background(), "net_mount_state", map[string]any{"vm_id": "vm-5", "mounted": false})
	if resp["ok"] != true {
		t.Fatalf("gate dispatch failed: %v", resp["error"])
	}
	if len(rec.gateVMs) != 1 || rec.gateVMs[0] != "vm-5" || rec.mounted[0] != false {
		t.Fatalf("gater received %+v", rec)
	}
}

// TestHandleReclaimNetworkFullSpec pins that reclaim re-exports the COMPLETE
// net spec (v6 + tap) from boxout's OWN persisted state — routed-ipv6 reclaim
// reconstructs the subnet from guest_ip6 and needs the tap name — while a
// caller-supplied spec is ignored entirely (it is not a trust source).
func TestHandleReclaimNetworkFullSpec(t *testing.T) {
	s := newTestServer("/var/sandswap/volumes")
	base := t.TempDir()
	s.cfg.Instance.BaseDir = base
	rec := &recordingNetProvider{NetworkProvider: s.netProv}
	s.netProv = rec

	ownRoot := InstanceSandboxRoot(s.cfg)
	want := vmm.VMNetSpec{
		GuestIP:  "10.188.7.42",
		Prefix:   16,
		Gateway:  "10.188.0.1",
		GuestIP6: "fd00:5341:4e44:1:1111:2222:3333:4444",
		Prefix6:  64,
		Gateway6: "fd00:5341:4e44:1::1",
		MAC:      "02:aa:bb:cc:dd:ee",
		NetConfig: map[string]any{
			"tap": network.TapNameFor("vm-7"),
			"mtu": 1500,
		},
	}
	cfg := vmm.Config{ID: "vm-7", NetSpec: &want}
	if err := core.WriteState("vm-7", cfg, filepath.Join(ownRoot, "vm-7", "sandvmm.sock"), 1234, "", ownRoot); err != nil {
		t.Skipf("cannot persist state in this environment: %v", err)
	}

	resp := s.dispatch(context.Background(), "reclaim_network", map[string]any{
		"vm_id": "vm-7",
		// A hostile caller spec: different address, different tap. It must
		// never reach the provider.
		"net_spec": map[string]any{
			"GuestIP":  "10.188.9.9",
			"Prefix":   float64(16),
			"Gateway":  "10.188.0.1",
			"GuestIP6": "fd00:5341:4e44:9::9",
			"Prefix6":  float64(64),
			"Gateway6": "fd00:5341:4e44:9::1",
			"MAC":      "02:99:99:99:99:99",
			"NetConfig": map[string]any{
				"tap": network.TapNameFor("victim"),
				"mtu": float64(1500),
			},
		},
	})
	if resp["ok"] != true {
		t.Fatalf("reclaim failed: %v", resp["error"])
	}
	got, ok := rec.reclaimed["vm-7"]
	if !ok {
		t.Fatal("reclaim never reached the provider")
	}
	if got.GuestIP != want.GuestIP || got.GuestIP6 != want.GuestIP6 || got.Prefix6 != 64 ||
		got.Gateway6 != want.Gateway6 || got.MAC != want.MAC {
		t.Fatalf("reclaimed spec is not the persisted one: %+v", got)
	}
	if got.NetConfig["tap"] != network.TapNameFor("vm-7") {
		t.Fatalf("reclaimed spec lost the persisted NetConfig: %+v", got.NetConfig)
	}
}

// --- untracked destroy boundary hardening ---

// TestUntrackedDestroyRefusesForeignTargets drives the privileged-boundary
// refusals: an arbitrary pid (e.g. PID 1), an arbitrary sandbox_dir (/etc/...),
// and a traversal form must ALL be refused with an error — never a silent
// skip, never a partial side effect. This is exactly what a compromised
// sandlot would send to turn boxout into an arbitrary kill/rm primitive.
func TestUntrackedDestroyRefusesForeignTargets(t *testing.T) {
	s := newTestServer("/var/sandswap/volumes")
	cases := []struct {
		name   string
		req    map[string]any
		errSub string
	}{
		{"sandbox_dir outside /run/sandswap", map[string]any{
			"vm_id": "ghost", "sandbox_dir": "/etc/ssh",
		}, "sandbox_dir must be under"},
		{"sandbox_dir traversal", map[string]any{
			"vm_id": "ghost", "sandbox_dir": "/run/sandswap/vm/../../etc",
		}, "path traversal"},
		{"volumes root as sandbox_dir (prefix-shaped but traversal)", map[string]any{
			"vm_id": "ghost", "sandbox_dir": "/run/sandswap/vm/../..",
		}, "path traversal"},
	}
	for _, c := range cases {
		resp := s.handleDestroyVM(context.Background(), c.req)
		if resp["ok"] != false {
			t.Errorf("%s: expected refusal ok=false, got %v", c.name, resp["ok"])
		}
		if msg, _ := resp["error"].(string); !strings.Contains(msg, c.errSub) {
			t.Errorf("%s: error %q does not contain %q", c.name, msg, c.errSub)
		}
	}
}

// A caller-supplied pid is never a signal target: the untracked path scans
// /proc for the sandvmm holding the DERIVED socket of the named sandbox. pid 1
// and the test process itself must survive a request that names them.
func TestUntrackedDestroyNeverSignalsForeignPids(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to create /run/sandswap/vm")
	}
	s := newTestServer("/var/sandswap/volumes")
	for i, pid := range []int{1, os.Getpid()} {
		dir := makeTestSandboxDir(t, fmt.Sprintf("boxout-foreign-%d", i))
		resp := s.handleDestroyVM(context.Background(), map[string]any{
			"vm_id": filepath.Base(dir), "pid": float64(pid), "sandbox_dir": dir,
		})
		if resp["ok"] != true {
			t.Fatalf("pid %d: cleanup refused: %v", pid, resp["error"])
		}
	}
	if err := syscall.Kill(1, 0); err != nil {
		t.Fatalf("pid 1 was signaled by an untracked destroy: %v", err)
	}
	if err := syscall.Kill(os.Getpid(), 0); err != nil {
		t.Fatalf("the test process was signaled by an untracked destroy: %v", err)
	}
}

// TestUntrackedDestroyRefusedDirUntouched verifies a REFUSED untracked
// destroy has zero filesystem side effects: /etc untouched, no RemoveState.
func TestUntrackedDestroyRefusedDirUntouched(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("meaningless as root (DAC would not stop us); the refusal is code-level")
	}
	s := newTestServer("/var/sandswap/volumes")
	resp := s.handleDestroyVM(context.Background(), map[string]any{
		"vm_id": "ghost", "sandbox_dir": "/etc/does-not-exist-xyz",
	})
	if resp["ok"] != false {
		t.Fatal("expected refusal")
	}
}

// TestValidateSandboxDirTrustedRoot pins that the RemoveAll containment root
// derives from the VALIDATED prefix shape, never from the caller path's own
// parent (which would neutralize core.isSandswapVMDir — rel is then always a
// bare basename and every path "passes").
func TestValidateSandboxDirTrustedRoot(t *testing.T) {
	cases := []struct {
		dir  string
		root string
	}{
		{"/run/sandswap/vm/vm-a", "/run/sandswap/vm"},
		{"/run/sandswap/vm/vm-a/vm-b", "/run/sandswap/vm"}, // first shape wins
		{"/run/sandswap/1/vm/vm-a", "/run/sandswap/1/vm"},
		{"/run/sandswap/1/vm/vm-a/deep/dir", "/run/sandswap/1/vm"},
	}
	for _, c := range cases {
		root, err := validateSandboxDir(c.dir)
		if err != nil {
			t.Errorf("%s: %v", c.dir, err)
			continue
		}
		if root != c.root {
			t.Errorf("validateSandboxDir(%s) root = %q, want %q", c.dir, root, c.root)
		}
	}
	for _, bad := range []string{"", "/etc/x", "/run/sandswap/other/x", "/run/sandswap/vm/../..", "relative/vm/x"} {
		if _, err := validateSandboxDir(bad); err == nil {
			t.Errorf("validateSandboxDir(%q) accepted a foreign path", bad)
		}
	}
}

// The boxout hands net_config to a ROOT VMM launch: only the shape its own
// provider emits is accepted. vhost-user, inherited fds, a foreign tap and an
// out-of-range MTU are refused by name; the legitimate shape passes.
func TestValidateBoxoutNetSpec(t *testing.T) {
	vmID := "pool-small-3"
	ownTap := network.TapNameFor(vmID)
	mac := "52:54:00:12:34:56"
	good := vmm.VMNetSpec{
		MAC:       mac,
		NetConfig: map[string]any{"tap": ownTap, "mac": mac, "mtu": 1500},
	}
	if err := validateBoxoutNetSpec(vmID, good); err != nil {
		t.Fatalf("legitimate net_config rejected: %v", err)
	}
	bad := []map[string]any{
		{"vhost_user": true},
		{"vhost_socket": "/tmp/x.sock"},
		{"fd": []any{3, 4}},
		{"tap": "tap-foreign"},
		{"tap": "eth0"},
		{"mac": "52:54:00:aa:bb:cc"},
		{"mtu": 99},
		{"unexpected": "x"},
	}
	for _, cfg := range bad {
		spec := vmm.VMNetSpec{MAC: mac, NetConfig: cfg}
		if err := validateBoxoutNetSpec(vmID, spec); err == nil {
			t.Errorf("net_config %v was accepted, want refusal", cfg)
		}
	}
}

// JSON numbers arrive as float64: an integral mtu is accepted, a fractional one
// is refused.
func TestValidateBoxoutNetSpecJSONNumbers(t *testing.T) {
	vmID := "vm-json"
	spec := vmm.VMNetSpec{NetConfig: map[string]any{"mtu": float64(1500)}}
	if err := validateBoxoutNetSpec(vmID, spec); err != nil {
		t.Fatalf("integral float mtu rejected: %v", err)
	}
	spec.NetConfig["mtu"] = float64(1500.5)
	if err := validateBoxoutNetSpec(vmID, spec); err == nil {
		t.Fatal("fractional mtu accepted")
	}
}

// Network RPCs are admission-controlled: provision_network leases count
// against the boxout VM limit (a compromised sandlot could otherwise create
// unbounded TAPs/nft chains/IP leases), and release frees the slot.
func TestProvisionNetworkLeaseCap(t *testing.T) {
	s := newTestServer("/var/sandswap/volumes")
	s.SetLimits(1, 0)
	ctx := context.Background()

	if resp := s.dispatch(ctx, "provision_network", map[string]any{"vm_id": "net-1"}); resp["ok"] != true {
		t.Fatalf("first provision refused: %v", resp["error"])
	}
	if resp := s.dispatch(ctx, "provision_network", map[string]any{"vm_id": "net-2"}); resp["ok"] != false {
		t.Fatal("network lease cap not enforced: second provision accepted")
	}
	if resp := s.dispatch(ctx, "release_network", map[string]any{"vm_id": "net-1"}); resp["ok"] != true {
		t.Fatalf("release refused: %v", resp["error"])
	}
	if resp := s.dispatch(ctx, "provision_network", map[string]any{"vm_id": "net-2"}); resp["ok"] != true {
		t.Fatalf("provision after release refused: %v", resp["error"])
	}
}

// --- instance-root binding (readopt / create / destroy) ---

// newInstanceTestServer builds a server whose own instance root is
// <t.TempDir>/<id>/vm and creates that root.
func newInstanceTestServer(t *testing.T, id string) (*Server, string) {
	t.Helper()
	s := newTestServer(filepath.Join(t.TempDir(), "volumes"))
	s.cfg.Instance.BaseDir = t.TempDir()
	s.cfg.Instance.ID = id
	root := s.instanceSandboxRoot()
	if err := os.MkdirAll(root, 0o711); err != nil {
		t.Fatalf("mkdir instance root: %v", err)
	}
	return s, root
}

// readopt_vms returns warden session keys, so it must only ever scan (and
// return VMs from) this instance's OWN root: another instance's root, a
// symlinked prefix, and a traversal form are all refused.
func TestHandleReadoptBindsToInstanceRoot(t *testing.T) {
	s, ownRoot := newInstanceTestServer(t, "inst-a")
	ctx := context.Background()

	// Our own root (explicit and defaulted) is accepted; an empty root scans
	// nothing.
	for _, req := range []map[string]any{{}, {"sandbox_root": ownRoot}, {"sandbox_root": ownRoot + "/"}} {
		resp := s.handleReadoptVMs(ctx, req)
		if resp["ok"] != true {
			t.Fatalf("own root %v refused: %v", req, resp["error"])
		}
	}

	sibling := filepath.Join(filepath.Dir(ownRoot), "..", "inst-b", "vm")
	foreign := []struct {
		name string
		root string
	}{
		{"sibling instance root", filepath.Clean(sibling)},
		{"default root while configured for an instance", "/run/sandswap/vm"},
		{"traversal", ownRoot + "/../../inst-b/vm"},
		{"parent dir", filepath.Dir(ownRoot)},
	}
	for _, c := range foreign {
		resp := s.handleReadoptVMs(ctx, map[string]any{"sandbox_root": c.root})
		if resp["ok"] != false {
			t.Errorf("%s: %q was accepted, want refusal", c.name, c.root)
		}
	}

	// A symlinked PREFIX of our own root passes a string comparison but
	// resolves the scan somewhere else: refused outright.
	realBase := t.TempDir()
	if err := os.MkdirAll(filepath.Join(realBase, "inst-c", "vm"), 0o711); err != nil {
		t.Fatal(err)
	}
	linkBase := filepath.Join(t.TempDir(), "base-link")
	if err := os.Symlink(realBase, linkBase); err != nil {
		t.Fatal(err)
	}
	linked := newTestServer(filepath.Join(t.TempDir(), "volumes"))
	linked.cfg.Instance.BaseDir = linkBase
	linked.cfg.Instance.ID = "inst-c"
	if resp := linked.handleReadoptVMs(ctx, map[string]any{}); resp["ok"] != false {
		t.Fatalf("a symlinked sandbox-root prefix must be refused, got ok=%v", resp["ok"])
	}
}

// create_vm and destroy_vm are bound to the same own root: a sandbox_dir in a
// sibling instance's tree must never be created or removed by this sidecar.
// The sandbox_dir grammar itself is rooted at /run/sandswap, so this test
// needs root to materialize the instance trees there.
func TestCreateDestroyBindToInstanceRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to create /run/sandswap instance roots")
	}
	baseA := filepath.Join("/run/sandswap", fmt.Sprintf("boxout-it-a-%d", os.Getpid()))
	baseB := filepath.Join("/run/sandswap", fmt.Sprintf("boxout-it-b-%d", os.Getpid()))
	ownRootA := filepath.Join(baseA, "vm")
	siblingRoot := filepath.Join(baseB, "vm")
	for _, d := range []string{ownRootA, siblingRoot} {
		if err := os.MkdirAll(d, 0o711); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { os.RemoveAll(baseA); os.RemoveAll(baseB) })

	s := newTestServer(filepath.Join(t.TempDir(), "volumes"))
	s.cfg.Instance.BaseDir = baseA
	s.allowInsecureVolumes = true // isolate the root binding from the mount gate
	ctx := context.Background()

	vmID := "vm-bound-1"
	resp := s.handleCreateVM(ctx, map[string]any{
		"vm_id": vmID, "sandbox_dir": filepath.Join(siblingRoot, vmID),
		"warden_session_key": strings.Repeat("ab", 32),
	})
	if resp["ok"] != false {
		t.Fatalf("a create in a sibling instance's root must be refused, got %v", resp["ok"])
	}
	if msg, _ := resp["error"].(string); !strings.Contains(msg, "not this boxout instance's root") {
		t.Fatalf("refusal %q must name the root mismatch", msg)
	}
	if _, err := os.Stat(filepath.Join(siblingRoot, vmID)); !os.IsNotExist(err) {
		t.Fatal("a refused create must not create the sandbox dir")
	}

	resp = s.handleDestroyVM(ctx, map[string]any{
		"vm_id": vmID, "sandbox_dir": filepath.Join(siblingRoot, vmID),
	})
	if resp["ok"] != false {
		t.Fatalf("an untracked destroy in a sibling instance's root must be refused, got %v", resp["ok"])
	}
	if _, err := os.Stat(siblingRoot); err != nil {
		t.Fatalf("a refused destroy must not remove anything: %v", err)
	}
}

// --- template ref + overlay marker hardening (mount_overlay) ---

func TestValidateTemplateRef(t *testing.T) {
	good := []string{"rootfs", "rootfs:v1", "ubuntu_24.04:local", "a.b-c_d:v2.0-rc1"}
	for _, ref := range good {
		if err := validateTemplateRef(ref); err != nil {
			t.Errorf("legitimate ref %q rejected: %v", ref, err)
		}
	}
	bad := []string{
		"", "../evil", "a/b", "..", ".hidden", "name:", ":v1", "a:b:c",
		"rootfs v1", "rootfs\\v1", "rootfs\x00v1", "-leading",
		strings.Repeat("a", maxTemplateRefLen+1),
	}
	for _, ref := range bad {
		if err := validateTemplateRef(ref); err == nil {
			t.Errorf("ref %q was accepted, want refusal", ref)
		}
	}
}

// mount_overlay must refuse an unsafe expected ref and an unsafe .template
// marker before the mount path reaches either (no CAP_SYS_ADMIN needed for the
// refusal branches).
func TestMountOverlayRefAndMarkerHardening(t *testing.T) {
	volRoot := t.TempDir()
	s := newTestServer(volRoot)
	s.vmmCfg.TemplatesDir = t.TempDir()
	vol := filepath.Join(volRoot, "sf-abc")
	if err := os.Mkdir(vol, 0o755); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	// Unsafe expected refs.
	for _, ref := range []string{"../evil", "a/b", "a:b:c", "name:"} {
		resp := s.handleMountOverlay(ctx, map[string]any{"volume_path": vol, "expected_template_ref": ref})
		if resp["ok"] != false {
			t.Errorf("expected ref %q was accepted", ref)
		}
		if msg, _ := resp["error"].(string); !strings.Contains(msg, "expected_template_ref rejected") {
			t.Errorf("expected ref %q: refusal %q must name the ref problem", ref, msg)
		}
	}

	marker := filepath.Join(vol, ".template")
	mk := func(t *testing.T, plant func() error) {
		t.Helper()
		_ = os.Remove(marker)
		if err := plant(); err != nil {
			t.Fatal(err)
		}
	}
	refusal := func(name, want string) {
		t.Helper()
		resp := s.handleMountOverlay(ctx, map[string]any{"volume_path": vol, "expected_template_ref": "rootfs:v1"})
		if resp["ok"] != false {
			t.Fatalf("%s: mount was accepted", name)
		}
		if msg, _ := resp["error"].(string); !strings.Contains(msg, want) {
			t.Fatalf("%s: refusal %q does not contain %q", name, msg, want)
		}
	}

	mk(t, func() error { // FIFO: must not block the mount path
		return syscall.Mkfifo(marker, 0o600)
	})
	refusal("FIFO marker", "not a regular file")

	mk(t, func() error { // symlink: must not read a host file through it
		return os.Symlink("/etc/passwd", marker)
	})
	refusal("symlinked marker", "symbolic link")

	mk(t, func() error { // oversized regular file: must not balloon memory
		return os.WriteFile(marker, make([]byte, 64*1024), 0o644)
	})
	refusal("oversized marker", "not a regular file")

	mk(t, func() error { return os.WriteFile(marker, []byte("   \n"), 0o644) })
	refusal("empty marker", "empty")

	mk(t, func() error { return os.WriteFile(marker, []byte("../../etc/evil"), 0o644) })
	refusal("traversal ref marker", "invalid template ref")

	// A safe marker is not refused by this guard (the mount itself needs
	// CAP_SYS_ADMIN and a real ref store, so it fails further down).
	mk(t, func() error { return os.WriteFile(marker, []byte("rootfs:v1\n"), 0o644) })
	resp := s.handleMountOverlay(ctx, map[string]any{"volume_path": vol, "expected_template_ref": "rootfs:v1"})
	if msg, _ := resp["error"].(string); strings.Contains(msg, "overlay marker") || strings.Contains(msg, "expected_template_ref") {
		t.Fatalf("a safe marker must reach the mount path, got refusal %q", msg)
	}

	// A volume path that is a symlink (or any non-directory) is refused.
	link := filepath.Join(volRoot, "sf-link")
	if err := os.Symlink(t.TempDir(), link); err != nil {
		t.Fatal(err)
	}
	resp = s.handleMountOverlay(ctx, map[string]any{"volume_path": link, "expected_template_ref": "rootfs:v1"})
	if resp["ok"] != false {
		t.Fatal("a symlinked volume_path must be refused")
	}
	if msg, _ := resp["error"].(string); !strings.Contains(msg, "symbolic link") && !strings.Contains(msg, "not a directory") {
		t.Fatalf("refusal %q must name the non-directory/symlinked volume path", msg)
	}
}

// --- volumes nosuid,nodev gate ---

func TestVolumesMountGatePredicate(t *testing.T) {
	if !volumesMountSecure(uint64(unix.ST_NOSUID | unix.ST_NODEV)) {
		t.Fatal("nosuid+nodev must pass the predicate")
	}
	if volumesMountSecure(uint64(unix.ST_NOSUID)) || volumesMountSecure(uint64(unix.ST_NODEV)) || volumesMountSecure(0) {
		t.Fatal("a mount missing either flag must fail the predicate")
	}
	if got := missingVolumeFlags(uint64(unix.ST_NOSUID)); got != "nodev" {
		t.Fatalf("missingVolumeFlags = %q, want nodev", got)
	}
	if got := missingVolumeFlags(0); got != "nosuid,nodev" {
		t.Fatalf("missingVolumeFlags = %q, want nosuid,nodev", got)
	}
	// Unreadable is not "probably fine": the gate fails closed.
	if err := VolumesMountGate(filepath.Join(t.TempDir(), "does-not-exist")); err == nil {
		t.Fatal("an unstatfs-able volumes dir must fail the gate")
	}
}

// create_vm refuses to export a volumes tree whose mount lacks nosuid,nodev,
// and the explicit dev admission bypasses the gate.
func TestCreateVMVolumesMountGate(t *testing.T) {
	volRoot := filepath.Join(t.TempDir(), "missing-volumes")
	s, ownRoot := newInstanceTestServer(t, "inst-a")
	s.vmmCfg.VolumesDir = volRoot
	vmID := "vm-gate-1"
	// No sandbox_dir: the server derives <own root>/<vm_id>, which keeps the
	// request valid until the mount gate (the sandbox_dir grammar is rooted at
	// /run/sandswap and this instance root is a temp tree).
	_ = ownRoot
	req := map[string]any{
		"vm_id": vmID, "warden_session_key": strings.Repeat("cd", 32),
	}
	resp := s.handleCreateVM(context.Background(), req)
	if resp["ok"] != false {
		t.Fatalf("create on an unstatfs-able volumes dir must be refused, got ok=%v", resp["ok"])
	}
	if msg, _ := resp["error"].(string); !strings.Contains(msg, "volumes_dir") {
		t.Fatalf("refusal %q must name the volumes dir", msg)
	}

	// Explicit dev admission: the gate no longer stops the request (the next
	// failure is the launch itself, since no VMM binary exists).
	s.allowInsecureVolumes = true
	s.vmmCfg.VMMBinary = "/nonexistent/sandvmm-must-not-run"
	resp = s.handleCreateVM(context.Background(), req)
	if msg, _ := resp["error"].(string); !strings.Contains(msg, "launch:") {
		t.Fatalf("with the admission set the request must reach the launch path, got %q", msg)
	}
}

// --- RPC bounds ---

// A silent connection is closed after the idle deadline.
func TestHandleConnIdleDeadline(t *testing.T) {
	_, sock := startBoxoutSocketSrv(t, func(s *Server) {
		s.SetRPCBounds(80*time.Millisecond, 0, 0)
	})
	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	start := time.Now()
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("an idle connection must be closed by the server")
	} else if errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("the server did not enforce the idle deadline")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("idle connection closed after %v", elapsed)
	}
}

// Concurrent connections are capped: above the bound the server closes the
// excess instead of spawning another handler.
func TestHandleConnConcurrencyBound(t *testing.T) {
	_, sock := startBoxoutSocketSrv(t, func(s *Server) {
		s.SetRPCBounds(10*time.Second, 0, 1)
	})
	connA, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatalf("dial A: %v", err)
	}
	defer connA.Close()
	// Give the accept loop time to hand connA to HandleConn (which takes the
	// single slot before reading).
	time.Sleep(150 * time.Millisecond)

	connB, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatalf("dial B: %v", err)
	}
	defer connB.Close()
	connB.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := connB.Read(make([]byte, 1)); err == nil {
		t.Fatal("a connection above the cap must be closed without a response")
	}

	// Freeing the slot admits the next connection (the server may take a
	// scheduling moment to observe the close, so retry).
	connA.Close()
	deadline := time.Now().Add(2 * time.Second)
	for {
		connC, err := net.Dial("unix", sock)
		if err != nil {
			t.Fatalf("dial C: %v", err)
		}
		connC.SetDeadline(time.Now().Add(time.Second))
		_, werr := connC.Write([]byte("{\"type\":\"restore_overlays\"}\n"))
		buf := make([]byte, 256)
		n, rerr := connC.Read(buf)
		connC.Close()
		if werr == nil && rerr == nil && strings.Contains(string(buf[:n]), `"ok":true`) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the released connection slot was never reusable (write=%v read=%v)", werr, rerr)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestHandoffAPIToken pins the fd-relative token handoff: a planted symlink at
// the sandbox/state/token path must never redirect the chown/chmod, and the
// happy path transfers ownership while preserving the 0700/0600 modes.
func TestHandoffAPIToken(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("handoff ownership checks require root")
	}
	const targetUID = 12345

	mk := func(t *testing.T) (sandbox, state, token string) {
		t.Helper()
		sandbox = t.TempDir()
		state = filepath.Join(sandbox, "state")
		if err := os.Mkdir(state, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(state, 0o700); err != nil {
			t.Fatal(err)
		}
		token = filepath.Join(state, "api-token")
		if err := os.WriteFile(token, []byte("token"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(token, 0o600); err != nil {
			t.Fatal(err)
		}
		return sandbox, state, token
	}

	t.Run("happy path transfers ownership", func(t *testing.T) {
		sandbox, state, token := mk(t)
		if err := handoffAPIToken(sandbox, targetUID); err != nil {
			t.Fatalf("handoff: %v", err)
		}
		for _, p := range []string{state, token} {
			st, err := os.Stat(p)
			if err != nil {
				t.Fatal(err)
			}
			sys := st.Sys().(*syscall.Stat_t)
			if sys.Uid != targetUID || sys.Gid != targetUID {
				t.Fatalf("%s owner = %d:%d, want %d:%d", p, sys.Uid, sys.Gid, targetUID, targetUID)
			}
		}
		if st, _ := os.Stat(state); st.Mode().Perm() != 0o700 {
			t.Fatalf("state mode = %04o, want 0700", st.Mode().Perm())
		}
		if st, _ := os.Stat(token); st.Mode().Perm() != 0o600 {
			t.Fatalf("token mode = %04o, want 0600", st.Mode().Perm())
		}
	})

	t.Run("symlinked sandbox refused", func(t *testing.T) {
		sandbox, _, _ := mk(t)
		victim := t.TempDir()
		link := filepath.Join(t.TempDir(), "sandbox-link")
		if err := os.Symlink(victim, link); err != nil {
			t.Fatal(err)
		}
		if err := handoffAPIToken(link, targetUID); err == nil {
			t.Fatal("symlinked sandbox dir accepted")
		}
		_ = sandbox
	})

	t.Run("symlinked state refused", func(t *testing.T) {
		sandbox, state, _ := mk(t)
		victim := t.TempDir()
		if err := os.RemoveAll(state); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(victim, state); err != nil {
			t.Fatal(err)
		}
		if err := handoffAPIToken(sandbox, targetUID); err == nil {
			t.Fatal("symlinked state dir accepted")
		}
	})

	t.Run("symlinked token refused", func(t *testing.T) {
		sandbox, _, token := mk(t)
		victim := filepath.Join(t.TempDir(), "victim")
		if err := os.WriteFile(victim, []byte("keep"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(token); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(victim, token); err != nil {
			t.Fatal(err)
		}
		if err := handoffAPIToken(sandbox, targetUID); err == nil {
			t.Fatal("symlinked api token accepted")
		}
		if b, err := os.ReadFile(victim); err != nil || string(b) != "keep" {
			t.Fatalf("victim modified (b=%q err=%v)", b, err)
		}
	})
}

// --- mutual token handshake ---

// TestBoxoutTokenHandshake pins the challenge-response: with a client token
// configured, no request is served before the peer proves possession, and the
// server proves its own possession in return. A wrong token is refused by
// name and the connection is closed without dispatching anything.
func TestBoxoutTokenHandshake(t *testing.T) {
	const token = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	s, sock := startBoxoutSocketSrv(t, func(s *Server) { s.SetClientToken(token) })

	t.Run("correct token", func(t *testing.T) {
		conn, err := net.Dial("unix", sock)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close()
		rdr := bufio.NewReader(conn)
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		raw, err := rdr.ReadBytes('\n')
		if err != nil {
			t.Fatalf("read challenge: %v", err)
		}
		var ch struct {
			Type  string `json:"type"`
			Nonce string `json:"nonce"`
		}
		if err := json.Unmarshal(raw, &ch); err != nil || ch.Type != "auth_challenge" || len(ch.Nonce) != 64 {
			t.Fatalf("challenge = %q (err %v)", raw, err)
		}
		nonce := make([]byte, boxoutAuthNonceBytes)
		if _, err := rand.Read(nonce); err != nil {
			t.Fatal(err)
		}
		resp, _ := json.Marshal(map[string]any{
			"type":  "auth_response",
			"hmac":  authMAC(token, "client:"+ch.Nonce),
			"nonce": hex.EncodeToString(nonce),
		})
		if _, err := conn.Write(append(resp, '\n')); err != nil {
			t.Fatalf("write response: %v", err)
		}
		raw, err = rdr.ReadBytes('\n')
		if err != nil {
			t.Fatalf("read verdict: %v", err)
		}
		var ok struct {
			Type string `json:"type"`
			OK   bool   `json:"ok"`
			HMAC string `json:"hmac"`
		}
		if err := json.Unmarshal(raw, &ok); err != nil || ok.Type != "auth_ok" || !ok.OK {
			t.Fatalf("verdict = %q (err %v)", raw, err)
		}
		if !constantTimeEqual(ok.HMAC, authMAC(token, "server:"+hex.EncodeToString(nonce))) {
			t.Fatalf("server MAC mismatch — the client cannot authenticate the server")
		}
		// The authenticated connection now serves normal requests.
		req, _ := json.Marshal(map[string]any{"type": "restore_overlays"})
		if _, err := conn.Write(append(req, '\n')); err != nil {
			t.Fatalf("write request: %v", err)
		}
		raw, err = rdr.ReadBytes('\n')
		if err != nil {
			t.Fatalf("read response: %v", err)
		}
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil || m["ok"] != true || m["type"] != "restore_overlays" {
			t.Fatalf("response = %q (err %v)", raw, err)
		}
		_ = s
	})

	t.Run("wrong token", func(t *testing.T) {
		conn, err := net.Dial("unix", sock)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close()
		rdr := bufio.NewReader(conn)
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := rdr.ReadBytes('\n'); err != nil {
			t.Fatalf("read challenge: %v", err)
		}
		nonce := make([]byte, boxoutAuthNonceBytes)
		resp, _ := json.Marshal(map[string]any{
			"type":  "auth_response",
			"hmac":  authMAC("wrong-token", "client:"+hex.EncodeToString(nonce)),
			"nonce": hex.EncodeToString(nonce),
		})
		if _, err := conn.Write(append(resp, '\n')); err != nil {
			t.Fatalf("write response: %v", err)
		}
		raw, err := rdr.ReadBytes('\n')
		if err != nil {
			t.Fatalf("read verdict: %v", err)
		}
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil || m["ok"] != false {
			t.Fatalf("wrong-token verdict = %q (err %v)", raw, err)
		}
		// A request sent afterwards is never dispatched (the connection was
		// refused): the server closes; our read yields EOF rather than a
		// response for the request type.
		req, _ := json.Marshal(map[string]any{"type": "restore_overlays"})
		_, _ = conn.Write(append(req, '\n'))
		raw, rerr := rdr.ReadBytes('\n')
		if rerr == nil {
			var after map[string]any
			if json.Unmarshal(raw, &after) == nil && after["ok"] == true {
				t.Fatalf("a request was served on an unauthenticated connection: %q", raw)
			}
		}
	})
}

// TestHandoffStateDir pins the session-key handoff: after core.WriteState the
// private per-VM state dir under the boxout state root is root-owned 0700
// with state.json 0600 — and handoffStateDir re-owns both to the sandlot uid
// keeping the owner-only modes, so the unprivileged sandlot can load the
// warden session key at re-attach (the NAS regression this pins:
// 0700 root-only state left the sandlot keyless, every KEY_DELIVERY was
// refused, and the pool collapsed into broken-pipe dirty destroys). A
// pre-handed-off dir (already the peer uid) must fail closed, not re-chown.
func TestHandoffStateDir(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to write the boxout state root and chown")
	}
	// Hermetic per-run instance root: the default /run/sandswap-state/default
	// layer may legitimately belong to the deployed sandlot uid (985) on a
	// development host, and this test must not depend on the host's state.
	inst := fmt.Sprintf("instance-boxout-handoff-%d", os.Getpid())
	sandboxRoot := filepath.Join("/run/sandswap", inst, "vm")
	sandboxDir := filepath.Join(sandboxRoot, "handoff-state")
	stateRoot := core.StateRootPathFor(sandboxRoot)
	_ = os.RemoveAll(filepath.Join("/run/sandswap", inst))
	_ = os.RemoveAll(stateRoot)
	if err := os.MkdirAll(sandboxDir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", sandboxDir, err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(filepath.Join("/run/sandswap", inst))
		_ = os.RemoveAll(stateRoot)
	})
	peer := 65536

	if err := core.WriteState(filepath.Base(sandboxDir), vmm.Config{SandboxDir: sandboxDir}, "/nonexistent.sock", 1, "", sandboxRoot); err != nil {
		t.Fatalf("WriteState: %v", err)
	}
	dir, err := core.StateDirPath(sandboxDir, sandboxRoot)
	if err != nil {
		t.Fatalf("StateDirPath: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	if err := handoffStateDir(sandboxDir, sandboxRoot, peer); err != nil {
		t.Fatalf("handoffStateDir: %v", err)
	}
	dst, err := os.Stat(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatalf("stat state.json: %v", err)
	}
	if dst.Mode().Perm() != 0o600 || dst.Sys().(*syscall.Stat_t).Uid != uint32(peer) {
		t.Fatalf("state.json after handoff: mode %04o uid %d, want 0600 owned by %d", dst.Mode().Perm(), dst.Sys().(*syscall.Stat_t).Uid, peer)
	}
	dd, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if dd.Mode().Perm() != 0o700 || dd.Sys().(*syscall.Stat_t).Uid != uint32(peer) {
		t.Fatalf("state dir after handoff: mode %04o uid %d, want 0700 owned by %d", dd.Mode().Perm(), dd.Sys().(*syscall.Stat_t).Uid, peer)
	}

	// Idempotent: a second handoff (create_vm retry, ResizePool replace) must
	// succeed without touching the already-handed-off layers.
	if err := handoffStateDir(sandboxDir, sandboxRoot, peer); err != nil {
		t.Fatalf("idempotent re-handoff: %v", err)
	}
	// Fail closed on a FOREIGN owner: neither the writer (root) nor the peer.
	if err := os.Chown(filepath.Join(dir, "state.json"), 1, 1); err == nil {
		if err := handoffStateDir(sandboxDir, sandboxRoot, peer); err == nil {
			t.Fatal("handoff of a foreign-owned state.json must fail closed")
		}
	}
}

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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// fakeVMM is an in-process HTTP server over a Unix socket that mimics the
// sandvmm REST API. It records the last request and returns a configurable
// status/body.
type fakeVMM struct {
	mu       sync.Mutex
	status   int
	respBody string
	method   string
	path     string
	body     []byte
	lis      net.Listener
	srv      *http.Server
}

func newFakeVMM(t *testing.T) *fakeVMM {
	t.Helper()
	dir := t.TempDir()
	sock := filepath.Join(dir, "sandvmm.sock")
	lis, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	f := &fakeVMM{status: http.StatusOK, lis: lis}
	f.srv = &http.Server{Handler: http.HandlerFunc(f.handle)}
	go f.srv.Serve(lis)
	t.Cleanup(func() { f.srv.Close() })
	return f
}

func (f *fakeVMM) handle(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.method = r.Method
	f.path = r.URL.Path
	f.body = body
	status, respBody := f.status, f.respBody
	f.mu.Unlock()
	w.WriteHeader(status)
	fmt.Fprint(w, respBody)
}

func (f *fakeVMM) lastRequest() (method, path string, body []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.method, f.path, append([]byte(nil), f.body...)
}

func (f *fakeVMM) socket() string { return f.lis.Addr().String() }

// --- Client methods against the fake VMM ---

func TestVMMClient_Methods(t *testing.T) {
	// These cases pin the LEGACY HTTP transport for every method; the raw
	// frame protocol has its own suite (raw_client_test.go).
	if err := ConfigureSetFsTransport("http"); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ConfigureSetFsTransport("raw") }()
	tests := []struct {
		name       string
		call       func(ctx context.Context, c *Client) error
		wantMethod string
		wantPath   string
		checkBody  func(t *testing.T, body []byte)
	}{
		{
			name:       "ping",
			wantMethod: http.MethodGet,
			wantPath:   "/api/v1/sandvmm.ping",
			call:       func(ctx context.Context, c *Client) error { return c.Ping(ctx) },
		},
		{
			name:       "create_vm",
			wantMethod: http.MethodPut,
			wantPath:   "/api/v1/vm.create",
			call: func(ctx context.Context, c *Client) error {
				return c.CreateVM(ctx, map[string]interface{}{"memory": map[string]interface{}{"size": 268435456}})
			},
			checkBody: func(t *testing.T, body []byte) {
				var cfg map[string]interface{}
				if err := json.Unmarshal(body, &cfg); err != nil {
					t.Fatalf("create body not valid JSON: %v", err)
				}
				mem := cfg["memory"].(map[string]interface{})
				if mem["size"].(float64) != 268435456 {
					t.Errorf("body memory.size = %v, want 268435456", mem["size"])
				}
			},
		},
		{
			name:       "boot_vm",
			wantMethod: http.MethodPut,
			wantPath:   "/api/v1/vm.boot",
			call:       func(ctx context.Context, c *Client) error { return c.BootVM(ctx) },
		},
		{
			name:       "set_fs",
			wantMethod: http.MethodPut,
			wantPath:   "/api/v1/vm.set-fs",
			call: func(ctx context.Context, c *Client) error {
				return c.SetFs(ctx, "vfs-rootfs", "sandswap", []string{"/var/sandswap/volumes/sandfs-abc"}, "gen0")
			},
			checkBody: func(t *testing.T, body []byte) {
				var cfg map[string]interface{}
				if err := json.Unmarshal(body, &cfg); err != nil {
					t.Fatalf("set-fs body not valid JSON: %v", err)
				}
				if cfg["id"] != "vfs-rootfs" {
					t.Errorf("body id = %v, want vfs-rootfs", cfg["id"])
				}
			},
		},
		{
			name:       "add_vsock",
			wantMethod: http.MethodPut,
			wantPath:   "/api/v1/vm.add-vsock",
			call:       func(ctx context.Context, c *Client) error { return c.AddVsock(ctx, 42) },
			checkBody: func(t *testing.T, body []byte) {
				var cfg map[string]interface{}
				if err := json.Unmarshal(body, &cfg); err != nil {
					t.Fatalf("add-vsock body not valid JSON: %v", err)
				}
				if cfg["cid"].(float64) != 42 {
					t.Errorf("body cid = %v, want 42", cfg["cid"])
				}
			},
		},
		{
			name:       "shutdown_vmm",
			wantMethod: http.MethodPut,
			wantPath:   "/api/v1/sandvmm.shutdown",
			call:       func(ctx context.Context, c *Client) error { return c.ShutdownVMM(ctx) },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeVMM(t)
			c := NewClient(f.socket())
			ctx := context.Background()
			if err := tt.call(ctx, c); err != nil {
				t.Fatalf("call: %v", err)
			}
			gotMethod, gotPath, gotBody := f.lastRequest()
			if gotMethod != tt.wantMethod {
				t.Errorf("method = %q, want %q", gotMethod, tt.wantMethod)
			}
			if gotPath != tt.wantPath {
				t.Errorf("path = %q, want %q", gotPath, tt.wantPath)
			}
			if tt.checkBody != nil {
				tt.checkBody(t, gotBody)
			}
		})
	}
}

func TestVMMClient_HTTPError(t *testing.T) {
	if err := ConfigureSetFsTransport("http"); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ConfigureSetFsTransport("raw") }()
	f := newFakeVMM(t)
	f.mu.Lock()
	f.status = http.StatusInternalServerError
	f.respBody = "VM not found"
	f.mu.Unlock()

	c := NewClient(f.socket())
	err := c.Ping(context.Background())
	if err == nil {
		t.Fatal("Ping should fail on HTTP 500")
	}
	if !strings.Contains(err.Error(), "vmm returned 500") || !strings.Contains(err.Error(), "VM not found") {
		t.Errorf("error = %q, want it to contain status and body", err.Error())
	}
}

func TestVMMClient_MarshalError(t *testing.T) {
	f := newFakeVMM(t)
	c := NewClient(f.socket())

	err := c.CreateVM(context.Background(), make(chan int))
	if err == nil {
		t.Fatal("CreateVM should fail on unmarshalable body")
	}
	if !strings.Contains(err.Error(), "marshal request") {
		t.Errorf("error = %q, want marshal request failure", err.Error())
	}
}

func TestVMMClient_ConnectionError(t *testing.T) {
	if err := ConfigureSetFsTransport("http"); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ConfigureSetFsTransport("raw") }()
	c := NewClient(filepath.Join(t.TempDir(), "no-such.sock"))
	err := c.Ping(context.Background())
	if err == nil {
		t.Fatal("Ping should fail on missing socket")
	}
	if !strings.Contains(err.Error(), "vmm request GET /api/v1/sandvmm.ping") {
		t.Errorf("error = %q, want wrapped request error", err.Error())
	}
}

// --- Attach (re-adopt path) ---

func TestAttach_Success(t *testing.T) {
	// Attach probes with Ping; these cases pin the legacy HTTP transport
	// against the HTTP fake (the raw transport has its own suite).
	if err := ConfigureSetFsTransport("http"); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ConfigureSetFsTransport("raw") }()
	f := newFakeVMM(t)
	vm, err := Attach(context.Background(), AttachConfig{
		ID:        "vm-1",
		APISocket: f.socket(),
		GuestCID:  7,
		PID:       1234,
	}, nil)
	if err != nil {
		t.Fatalf("Attach: %v", err)
	}
	if vm.ID != "vm-1" || vm.GuestCID != 7 {
		t.Errorf("vm identity = (%s, %d), want (vm-1, 7)", vm.ID, vm.GuestCID)
	}
	if vm.APISocket != f.socket() {
		t.Errorf("APISocket = %q, want %q", vm.APISocket, f.socket())
	}
	if !vm.Readopted() {
		t.Error("Readopted() = false, want true")
	}
	if vm.PID() != 1234 {
		t.Errorf("PID() = %d, want 1234", vm.PID())
	}
}

func TestAttach_DeadVMM(t *testing.T) {
	if err := ConfigureSetFsTransport("http"); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ConfigureSetFsTransport("raw") }()
	_, err := Attach(context.Background(), AttachConfig{
		ID:        "vm-1",
		APISocket: filepath.Join(t.TempDir(), "missing.sock"),
	}, nil)
	if err == nil {
		t.Fatal("Attach should fail when the VMM does not respond")
	}
	if !strings.Contains(err.Error(), "attach: vmm vm-1 not responding") {
		t.Errorf("error = %q", err.Error())
	}
}

// --- RunningVM accessors ---

func TestRunningVM_PID_FromExecCmd(t *testing.T) {
	cmd := &exec.Cmd{Process: &os.Process{Pid: 555}}
	vm := &RunningVM{cmd: cmd, pid: 999}
	if got := vm.PID(); got != 555 {
		t.Errorf("PID() = %d, want 555 from cmd.Process", got)
	}
	if vm.Readopted() {
		t.Error("Readopted() = true, want false for fresh VM")
	}
}

func TestRunningVM_Kill_NoProcess(t *testing.T) {
	vm := &RunningVM{}
	vm.Kill()
	if vm.PID() != 0 {
		t.Errorf("PID() = %d, want 0 for empty VM", vm.PID())
	}
}

// --- buildCmdline ---

func TestBuildCmdline(t *testing.T) {
	// buildCmdline appends the free-wipe posture token (init_on_free=, see
	// TestBuildCmdlineInitOnFreePosture) right after the base, so every
	// expected string carries it there by default.
	base := "quiet highres=off clocksource=kvm-clock"
	const posture = " init_on_free=0"
	tests := []struct {
		name string
		cfg  Config
		want string
	}{
		{
			name: "defaults_only",
			cfg:  Config{KernelCmdline: base},
			want: base + posture + " console=hvc0 earlyprintk=ttyS0",
		},
		{
			name: "with_net_spec",
			cfg: Config{
				KernelCmdline: base,
				NetSpec: &VMNetSpec{
					GuestIP: "10.188.0.2",
					Prefix:  16,
					Gateway: "10.188.0.1",
					DNS:     []string{"10.188.0.1", "8.8.8.8"},
					MAC:     "02:aa:bb:cc:dd:ee",
				},
			},
			want: base + posture + " warden.net_ip=10.188.0.2 warden.net_prefix=16 warden.net_gw=10.188.0.1" +
				" warden.net_dns=10.188.0.1,8.8.8.8 warden.net_mac=02:aa:bb:cc:dd:ee console=hvc0 earlyprintk=ttyS0",
		},
		{
			name: "net_spec_empty_guest_ip_ignored",
			cfg: Config{
				KernelCmdline: base,
				NetSpec:       &VMNetSpec{},
			},
			want: base + posture + " console=hvc0 earlyprintk=ttyS0",
		},
		{
			name: "nil_net_spec_with_countdown",
			cfg: Config{
				KernelCmdline:      base,
				WardenCountdownSec: 300,
			},
			want: base + posture + " warden.warden_countdown_sec=300 console=hvc0 earlyprintk=ttyS0",
		},
		{
			name: "ipv6_only_net_spec",
			cfg: Config{
				KernelCmdline: base,
				NetSpec: &VMNetSpec{
					GuestIP6: "fd00:5341:4e44:1:1111:2222:3333:4444",
					Prefix6:  64,
					Gateway6: "fd00:5341:4e44:1::1",
					DNS:      []string{"1.1.1.1"},
					MAC:      "02:00:00:00:00:03",
				},
			},
			want: base + posture + " warden.net_ip6=fd00:5341:4e44:1:1111:2222:3333:4444 warden.net_prefix6=64" +
				" warden.net_gw6=fd00:5341:4e44:1::1" +
				" warden.net_dns=1.1.1.1 warden.net_mac=02:00:00:00:00:03 console=hvc0 earlyprintk=ttyS0",
		},
		{
			name: "dual_stack_net_spec",
			cfg: Config{
				KernelCmdline: base,
				NetSpec: &VMNetSpec{
					GuestIP:  "10.188.0.2",
					Prefix:   16,
					Gateway:  "10.188.0.1",
					GuestIP6: "fd00:5341:4e44:2::42",
					Prefix6:  64,
					Gateway6: "fd00:5341:4e44:2::1",
					DNS:      []string{"1.1.1.1"},
					MAC:      "02:00:00:00:00:04",
				},
			},
			want: base + posture + " warden.net_ip=10.188.0.2 warden.net_prefix=16 warden.net_gw=10.188.0.1" +
				" warden.net_ip6=fd00:5341:4e44:2::42 warden.net_prefix6=64 warden.net_gw6=fd00:5341:4e44:2::1" +
				" warden.net_dns=1.1.1.1 warden.net_mac=02:00:00:00:00:04" +
				" console=hvc0 earlyprintk=ttyS0",
		},
		{
			name: "all_params",
			cfg: Config{
				KernelCmdline:      base,
				WardenCountdownSec: 600,
				NetSpec: &VMNetSpec{
					GuestIP: "192.168.1.10",
					Prefix:  24,
					Gateway: "192.168.1.1",
					DNS:     []string{"1.1.1.1"},
					MAC:     "02:00:00:00:00:02",
				},
			},
			want: base + posture + " warden.net_ip=192.168.1.10 warden.net_prefix=24 warden.net_gw=192.168.1.1" +
				" warden.net_dns=1.1.1.1 warden.net_mac=02:00:00:00:00:02" +
				" warden.warden_countdown_sec=600 console=hvc0 earlyprintk=ttyS0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := buildCmdline(tt.cfg); got != tt.want {
				t.Errorf("buildCmdline() =\n%q\nwant\n%q", got, tt.want)
			}
		})
	}
}

// TestBuildCmdlineHvc0Preferred pins the preferred-console semantics: hvc0 is
// the ONLY console= (so /dev/console, and therefore the warden's stdout, lands
// on the virtio-console); earlyprintk keeps the earliest boot/panic output on
// ttyS0 without making it a console.
func TestBuildCmdlineHvc0Preferred(t *testing.T) {
	got := buildCmdline(Config{KernelCmdline: "quiet clocksource=kvm-clock"})
	if strings.Count(got, "console=") != 1 {
		t.Fatalf("cmdline must carry exactly one console= (hvc0), got %q", got)
	}
	if !strings.HasSuffix(got, "console=hvc0 earlyprintk=ttyS0") {
		t.Fatalf("cmdline must end with console=hvc0 earlyprintk=ttyS0, got %q", got)
	}
}

// TestBuildCmdlineOmitsSessionKey pins the key-delivery contract: the
// per-VM raw-protocol key must never appear on the kernel command line (the
// kernel prints it at KERN_INFO and the debug boot path cannot be trusted to
// keep it quiet). It is delivered over the first host vsock connection.
func TestBuildCmdlineOmitsSessionKey(t *testing.T) {
	key := strings.Repeat("ab", 32)
	got := buildCmdline(Config{
		KernelCmdline:    "quiet clocksource=kvm-clock quiet",
		WardenSessionKey: key,
	})
	if strings.Contains(got, "warden.session_key=") || strings.Contains(got, key) {
		t.Fatalf("cmdline must not carry the session key, got %q", got)
	}
	quiet := 0
	for _, f := range strings.Fields(got) {
		if f == "quiet" {
			quiet++
		}
	}
	if quiet != 2 {
		t.Fatalf("operator quiet tokens must pass through untouched, got %d in %q", quiet, got)
	}
	if !strings.HasSuffix(got, "console=hvc0 earlyprintk=ttyS0") {
		t.Fatalf("console tail changed: %q", got)
	}
}

// TestBuildCmdlineKeepsExplicitKernelDebug: an operator-requested debug token
// is preserved verbatim. Nothing on the command line is secret now, so no
// forced-quiet rewrite is needed.
func TestBuildCmdlineKeepsExplicitKernelDebug(t *testing.T) {
	key := strings.Repeat("ab", 32)
	for _, token := range []string{"debug", "ignore_loglevel", "loglevel=7"} {
		got := buildCmdline(Config{
			KernelCmdline:    "clocksource=kvm-clock " + token,
			WardenSessionKey: key,
		})
		if !strings.Contains(got, token) {
			t.Fatalf("operator token %q was dropped: %q", token, got)
		}
		if strings.Contains(got, "warden.session_key=") {
			t.Fatalf("cmdline must not carry the session key: %q", got)
		}
	}
}

// --- Wait with no cmd (re-adopted VM) ---

func TestRunningVM_Wait_NoCmd(t *testing.T) {
	vm := &RunningVM{}
	if err := vm.Wait(); err != nil {
		t.Errorf("Wait() on re-adopted VM = %v, want nil", err)
	}
}

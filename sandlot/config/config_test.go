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

package config

import (
	"bytes"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"common/config"
)

func TestDefaults(t *testing.T) {
	d := Defaults()
	if d.GatewayAddr != "localhost:9998" {
		t.Errorf("GatewayAddr = %q, want localhost:9998", d.GatewayAddr)
	}
	if d.MicroVM.DefaultVCPUs != 2 {
		t.Errorf("DefaultVCPUs = %d, want 2", d.MicroVM.DefaultVCPUs)
	}
	if d.MicroVM.DefaultMemoryMB != 512 {
		t.Errorf("DefaultMemoryMB = %d, want 512", d.MicroVM.DefaultMemoryMB)
	}
	if d.Recycle.MaxUses != 100000 {
		t.Errorf("Recycle.MaxUses = %d, want 100000", d.Recycle.MaxUses)
	}
	if d.Concurrency.VMCreate != 5 {
		t.Errorf("Concurrency.VMCreate = %d, want 5", d.Concurrency.VMCreate)
	}
	if d.Concurrency.VMDestroy != 10 {
		t.Errorf("Concurrency.VMDestroy = %d, want 10", d.Concurrency.VMDestroy)
	}
	if d.Provision.MaxSparseBytes != 8<<30 {
		t.Errorf("Provision.MaxSparseBytes = %d, want %d", d.Provision.MaxSparseBytes, int64(8<<30))
	}
	if len(d.Specs) != 3 {
		t.Errorf("len(Specs) = %d, want 3", len(d.Specs))
	}
	if d.Instance.CIDRangeStart != 3 {
		t.Errorf("Instance.CIDRangeStart = %d, want 3", d.Instance.CIDRangeStart)
	}
	// The canonical VMM API socket is authenticated by default: DAC alone is
	// one uid boundary (the FUSE daemon shares it).
	if !d.MicroVM.VMMAPIAuth {
		t.Error("MicroVM.VMMAPIAuth = false, want true (default-on per-VM API token)")
	}
	// Free-wipe posture is opt-in: the default boots with init_on_free=0
	// (boot-time bulk clear is redundant in a fresh microVM; init_on_alloc
	// stays on and carries the cross-tenant control).
	if d.MicroVM.InitOnFree {
		t.Error("MicroVM.InitOnFree = true, want false (opt-in posture)")
	}
}

func TestLoadFromFile(t *testing.T) {
	dir := t.TempDir()
	yamlPath := filepath.Join(dir, "sandlot.yaml")

	content := `
gateway_addr: "gateway:9998"
node_id: "node-1"
vmm_binary: "/usr/local/bin/sandvmm"
microvm:
  kernel: "/custom/vmlinux"
  initramfs: "/custom/initramfs.cpio.gz"
  default_vcpus: 4
  default_memory_mb: 1024
  volumes_dir: "/custom/volumes"
  overlayfs_templates: "/custom/templates"
specs:
  small:
    vcpus: 1
    memory_mb: 128
  medium:
    vcpus: 2
    memory_mb: 512
  xl:
    vcpus: 8
    memory_mb: 4096
pool: "small:2,medium:3,xl:1"
recycle:
  max_uses: 100
  mem_percent: 15
  mem_abs_mb: 200
network:
  backend: "bridge"
  bridge: "br-custom"
  subnet: "10.200.0.0/16"
  gateway: "10.200.0.1"
  dns: "8.8.8.8"
tls:
  cert: "/certs/sandlot.pem"
  key: "/certs/sandlot.key"
  ca: "/certs/ca.pem"
instance:
  id: "0"
  base_dir: "/run/sandswap"
  cid_range_start: 3
provision:
  oci_registry: "registry.example.com/repo"
  registry_username: "robot"
  registry_password: "s3cr3t"
  registry_ca: "/certs/registry-ca.pem"
`
	if err := os.WriteFile(yamlPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadFromFile(yamlPath)
	if err != nil {
		t.Fatal(err)
	}

	if cfg.GatewayAddr != "gateway:9998" {
		t.Errorf("GatewayAddr = %q, want gateway:9998", cfg.GatewayAddr)
	}
	if cfg.MicroVM.DefaultVCPUs != 4 {
		t.Errorf("DefaultVCPUs = %d, want 4", cfg.MicroVM.DefaultVCPUs)
	}
	if cfg.MicroVM.DefaultMemoryMB != 1024 {
		t.Errorf("DefaultMemoryMB = %d, want 1024", cfg.MicroVM.DefaultMemoryMB)
	}
	if len(cfg.Specs) != 4 {
		t.Errorf("len(Specs) = %d, want 4 (3 from YAML + large from defaults)", len(cfg.Specs))
	}
	// Custom spec "xl"
	if cfg.Specs["xl"].VCPUs != 8 {
		t.Errorf("Specs[xl].VCPUs = %d, want 8", cfg.Specs["xl"].VCPUs)
	}
	if cfg.Pool != "small:2,medium:3,xl:1" {
		t.Errorf("Pool = %q, want small:2,medium:3,xl:1", cfg.Pool)
	}
	if cfg.Recycle.MaxUses != 100 {
		t.Errorf("Recycle.MaxUses = %d, want 100", cfg.Recycle.MaxUses)
	}
	if cfg.Network.Backend != "bridge" {
		t.Errorf("Network.Backend = %q, want bridge", cfg.Network.Backend)
	}
	if cfg.TLS.Cert != "/certs/sandlot.pem" {
		t.Errorf("TLS.Cert = %q, want /certs/sandlot.pem", cfg.TLS.Cert)
	}
	if cfg.Instance.ID != "0" {
		t.Errorf("Instance.ID = %q, want 0", cfg.Instance.ID)
	}
	if cfg.Provision.OCIRegistry != "registry.example.com/repo" {
		t.Errorf("Provision.OCIRegistry = %q", cfg.Provision.OCIRegistry)
	}
	if cfg.Provision.RegistryUsername != "robot" || cfg.Provision.RegistryPassword != "s3cr3t" {
		t.Errorf("Provision registry credentials = %q/%q", cfg.Provision.RegistryUsername, cfg.Provision.RegistryPassword)
	}
	if cfg.Provision.RegistryCA != "/certs/registry-ca.pem" {
		t.Errorf("Provision.RegistryCA = %q", cfg.Provision.RegistryCA)
	}
}

func TestDiffHotReload(t *testing.T) {
	old := Defaults()
	new := Defaults()
	new.MicroVM.DefaultVCPUs = 4
	new.Recycle.MaxUses = 100

	cs := old.Diff(new)
	if len(cs.HotReload) != 2 {
		t.Errorf("expected 2 hot-reload changes, got %d: %+v", len(cs.HotReload), cs.HotReload)
	}
	if len(cs.RestartReq) != 0 {
		t.Errorf("expected 0 restart-required changes, got %d", len(cs.RestartReq))
	}
}

func TestDiffRestartRequired(t *testing.T) {
	old := Defaults()
	new := Defaults()
	new.GatewayAddr = "gateway:8888"
	new.Network.Backend = "bridge"

	cs := old.Diff(new)
	if len(cs.RestartReq) != 2 {
		t.Errorf("expected 2 restart-required changes, got %d", len(cs.RestartReq))
	}
	if len(cs.HotReload) != 0 {
		t.Errorf("expected 0 hot-reload changes, got %d", len(cs.HotReload))
	}
}

func TestClassifyField(t *testing.T) {
	tests := []struct {
		name string
		want config.ChangeClass
	}{
		{"microvm.kernel", config.ChangeHotReload},
		{"microvm.initramfs", config.ChangeHotReload},
		{"microvm.default_vcpus", config.ChangeHotReload},
		{"microvm.default_memory_mb", config.ChangeHotReload},
		{"pool", config.ChangeHotReload},
		{"recycle.max_uses", config.ChangeHotReload},
		{"recycle.mem_percent", config.ChangeHotReload},
		{"recycle.mem_abs_mb", config.ChangeHotReload},
		{"recycle.min_idle_floor_frac", config.ChangeHotReload},
		// Restart-required
		{"gateway_addr", config.ChangeRestartRequired},
		{"node_id", config.ChangeRestartRequired},
		{"vmm_binary", config.ChangeRestartRequired},
		{"microvm.volumes_dir", config.ChangeRestartRequired},
		{"network.backend", config.ChangeRestartRequired},
		{"tls.cert", config.ChangeRestartRequired},
		{"instance.id", config.ChangeRestartRequired},
		// Provision role (registry + credentials) is restart-required: the
		// ORAS client is built once at startup from the auth material.
		{"provision.oci_registry", config.ChangeRestartRequired},
		{"provision.registry_password", config.ChangeRestartRequired},
		{"provision.registry_token", config.ChangeRestartRequired},
	}
	for _, tt := range tests {
		got := classifyField(tt.name)
		if got != tt.want {
			t.Errorf("classifyField(%q) = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestApplyFlagOverrides(t *testing.T) {
	cfg := Defaults()
	flags := &SandlotFlags{
		DefaultVCPUs:     8,
		MaxUses:          200,
		MinIdleFloorFrac: 0.05,
	}
	explicitSet := map[string]bool{
		"default-vcpus":       true,
		"max-uses":            true,
		"min-idle-floor-frac": true,
	}

	cfg.ApplyFlagOverrides(flags, explicitSet)

	if cfg.MicroVM.DefaultVCPUs != 8 {
		t.Errorf("DefaultVCPUs = %d, want 8 (flag override)", cfg.MicroVM.DefaultVCPUs)
	}
	if cfg.Recycle.MaxUses != 200 {
		t.Errorf("Recycle.MaxUses = %d, want 200 (flag override)", cfg.Recycle.MaxUses)
	}
	if cfg.Recycle.MinIdleFloorFrac != 0.05 {
		t.Errorf("Recycle.MinIdleFloorFrac = %v, want 0.05 (flag override)", cfg.Recycle.MinIdleFloorFrac)
	}
	// Non-overridden field keeps default.
	if cfg.Recycle.MemPercent != 10 {
		t.Errorf("Recycle.MemPercent = %d, want 10 (default)", cfg.Recycle.MemPercent)
	}
}

// The free-wipe posture flag is opt-in: an unset flag must never clobber a
// YAML-provided posture, and an explicit one must win over both the YAML and
// the default (flags keep precedence — the documented contract).
func TestApplyFlagOverrides_InitOnFree(t *testing.T) {
	cfg := Defaults()
	cfg.MicroVM.InitOnFree = true
	flags := &SandlotFlags{InitOnFree: false}
	cfg.ApplyFlagOverrides(flags, map[string]bool{}) // flag not on the command line
	if !cfg.MicroVM.InitOnFree {
		t.Error("unset -init-on-free must not clobber microvm.init_on_free: true")
	}
	flags.InitOnFree = true
	cfg.ApplyFlagOverrides(flags, map[string]bool{"init-on-free": true})
	if !cfg.MicroVM.InitOnFree {
		t.Error("explicit -init-on-free did not apply")
	}
	// And the off direction: YAML true, explicit flag false → false wins.
	cfg.MicroVM.InitOnFree = true
	flags.InitOnFree = false
	cfg.ApplyFlagOverrides(flags, map[string]bool{"init-on-free": true})
	if cfg.MicroVM.InitOnFree {
		t.Error("explicit -init-on-free=false did not override microvm.init_on_free: true")
	}
}

func TestApplyFlagOverrides_RegistryAuth(t *testing.T) {
	cfg := Defaults()
	cfg.Provision.OCIRegistry = "from-yaml.example.com/repo"
	cfg.Provision.RegistryUsername = "yaml-user"
	flags := &SandlotFlags{
		ProvisionOCIRegistry:      "from-flag.example.com/repo",
		ProvisionRegistryUsername: "flag-user",
		ProvisionRegistryPassword: "flag-pass",
	}
	// Only oci-registry and username were explicitly set: the password flag
	// (not on the command line) must NOT clobber anything.
	explicitSet := map[string]bool{"oci-registry": true, "registry-username": true}

	cfg.ApplyFlagOverrides(flags, explicitSet)

	if cfg.Provision.OCIRegistry != "from-flag.example.com/repo" {
		t.Errorf("OCIRegistry = %q, want the flag value", cfg.Provision.OCIRegistry)
	}
	if cfg.Provision.RegistryUsername != "flag-user" {
		t.Errorf("RegistryUsername = %q, want flag-user", cfg.Provision.RegistryUsername)
	}
	if cfg.Provision.RegistryPassword != "" {
		t.Errorf("RegistryPassword = %q, want empty (flag not explicitly set)", cfg.Provision.RegistryPassword)
	}
}

// TestRegistryAuthMethod pins the non-secret label used in the startup log.
func TestRegistryAuthMethod(t *testing.T) {
	tests := []struct {
		name string
		cfg  ProvisionConfig
		want string
	}{
		{"default", ProvisionConfig{}, "anonymous"},
		{"basic", ProvisionConfig{RegistryUsername: "u", RegistryPassword: "p"}, "basic"},
		{"token", ProvisionConfig{RegistryToken: "t"}, "token"},
		{"basic wins over token", ProvisionConfig{RegistryUsername: "u", RegistryToken: "t"}, "basic"},
		{"basic + ca", ProvisionConfig{RegistryUsername: "u", RegistryCA: "/ca"}, "basic+ca"},
		{"anonymous + mtls", ProvisionConfig{RegistryCert: "/c", RegistryKey: "/k"}, "anonymous+mtls"},
		{"everything", ProvisionConfig{RegistryUsername: "u", RegistryCert: "/c", RegistryKey: "/k", RegistryCA: "/ca"}, "basic+mtls+ca"},
	}
	for _, tt := range tests {
		if got := tt.cfg.RegistryAuthMethod(); got != tt.want {
			t.Errorf("%s: RegistryAuthMethod() = %q, want %q", tt.name, got, tt.want)
		}
	}
}

// TestReloadLoggingRedactsSecrets pins the redaction of credential values in
// the reload journal: the FieldChange carries formatted old/new values, so a
// password edit must never print them in the clear.
func TestReloadLoggingRedactsSecrets(t *testing.T) {
	old := Defaults()
	old.Provision.OCIRegistry = "reg.example.com/repo"
	old.Provision.RegistryPassword = "old-secret"
	new := Defaults()
	new.Provision.OCIRegistry = "reg.example.com/repo"
	new.Provision.RegistryPassword = "new-secret"

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	ApplyHotReload(old, new, &HotReloadTargets{}, logger)
	out := buf.String()

	if strings.Contains(out, "old-secret") || strings.Contains(out, "new-secret") {
		t.Errorf("reload log leaked a credential value:\n%s", out)
	}
	if !strings.Contains(out, "provision.registry_password") || !strings.Contains(out, "(redacted)") {
		t.Errorf("reload log missing field name or redaction marker:\n%s", out)
	}
}

func TestRecycleConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		maxUses int
		wantErr bool
	}{
		{"unlimited sentinel", -1, false},
		{"disable", 0, false},
		{"small limit", 1, false},
		{"default limit", 100000, false},
		{"typo negative", -2, true},
		{"large typo negative", -100000, true},
	}
	for _, tt := range tests {
		err := RecycleConfig{MaxUses: tt.maxUses}.Validate()
		if (err != nil) != tt.wantErr {
			t.Errorf("%s: MaxUses=%d Validate() error = %v, wantErr %v",
				tt.name, tt.maxUses, err, tt.wantErr)
		}
	}
}

func TestApplyHotReloadRecycleFields(t *testing.T) {
	// Every hot-reload-classified recycle.* field must actually be applied —
	// a field classified hot-reload but missing from the apply switch is
	// silently inert (this test exists to pin that regression class).
	old := Defaults()
	new := Defaults()
	new.Recycle.MinIdleFloorFrac = 0.25
	new.Recycle.MaxUses = 7
	new.Recycle.MaxMounts = 11
	new.Recycle.MaxDistinctAgents = 1
	new.Recycle.AffinityVMs = 5

	var applied []RecycleConfig
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ApplyHotReload(old, new, &HotReloadTargets{
		UpdateRecycleConfig: func(rc RecycleConfig) {
			applied = append(applied, rc)
		},
	}, logger)

	if len(applied) != 5 {
		t.Fatalf("UpdateRecycleConfig called %d times, want 5 (one per changed recycle field)", len(applied))
	}
	last := applied[len(applied)-1]
	if last.MinIdleFloorFrac != 0.25 || last.MaxUses != 7 ||
		last.MaxMounts != 11 || last.MaxDistinctAgents != 1 || last.AffinityVMs != 5 {
		t.Errorf("applied recycle config = %+v, want MinIdleFloorFrac=0.25 MaxUses=7 MaxMounts=11 MaxDistinctAgents=1 AffinityVMs=5", last)
	}
}

func TestReloadCallbackRejectsInvalidRecycle(t *testing.T) {
	current := config.NewWatchableConfig(Defaults())
	before := current.Get()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cb := NewReloadCallback(current, &HotReloadTargets{
		UpdateRecycleConfig: func(rc RecycleConfig) {
			t.Error("UpdateRecycleConfig must not fire for an invalid reload")
		},
	}, logger)

	cb([]byte("recycle:\n  max_uses: -2\n"))

	// Ingestion validation: the watchable config must keep the last good
	// value so subsequent diffs stay correct.
	if got := current.Get().Recycle.MaxUses; got != before.Recycle.MaxUses {
		t.Errorf("watchable config MaxUses = %d, want unchanged %d", got, before.Recycle.MaxUses)
	}

	// A subsequent valid edit still applies against the retained config.
	var applied *RecycleConfig
	cb2 := NewReloadCallback(current, &HotReloadTargets{
		UpdateRecycleConfig: func(rc RecycleConfig) {
			applied = &rc
		},
	}, logger)
	cb2([]byte("recycle:\n  max_uses: -1\n"))
	if applied == nil {
		t.Fatal("valid reload (max_uses: -1) was not applied")
	}
	if applied.MaxUses != -1 {
		t.Errorf("applied MaxUses = %d, want -1 (unlimited)", applied.MaxUses)
	}
}

// TestSandlotConfigValidate pins the whole-config value bounds enforced at
// startup AND on every hot-reload ingestion (an invalid edit is rejected
// whole): recycle sentinels, microvm default vcpus/memory (the CLI flag path
// int→uint conversion would otherwise silently wrap a negative), stream
// transport caps, and the instance CID range.
func TestSandlotConfigValidate(t *testing.T) {
	cases := []struct {
		name    string
		mut     func(*SandlotConfig)
		wantErr bool
	}{
		{"defaults valid", func(c *SandlotConfig) {}, false},
		{"recycle sentinel unchanged", func(c *SandlotConfig) { c.Recycle.MaxUses = -1 }, false},
		{"recycle other negative invalid", func(c *SandlotConfig) { c.Recycle.MaxUses = -2 }, true},
		{"default vcpus 0 invalid", func(c *SandlotConfig) { c.MicroVM.DefaultVCPUs = 0 }, true},
		{"default memory below boot floor invalid", func(c *SandlotConfig) { c.MicroVM.DefaultMemoryMB = 32 }, true},
		{"default memory at boot floor valid", func(c *SandlotConfig) { c.MicroVM.DefaultMemoryMB = 64 }, false},
		{"stream send buffer 0 invalid", func(c *SandlotConfig) { c.Stream.SendBufferSize = 0 }, true},
		{"stream max concurrent 0 invalid", func(c *SandlotConfig) { c.Stream.MaxConcurrentCommands = 0 }, true},
		{"stream window 0 invalid", func(c *SandlotConfig) { c.Stream.InitialWindow = 0 }, true},
		{"stream msg size below 16MB chain invalid", func(c *SandlotConfig) { c.Stream.MaxMsgSize = 8 << 20 }, true},
		{"cid range start below 3 invalid", func(c *SandlotConfig) { c.Instance.CIDRangeStart = 2 }, true},
		{"cid range end inverted invalid", func(c *SandlotConfig) { c.Instance.CIDRangeStart = 100; c.Instance.CIDRangeEnd = 50 }, true},
		{"cid range end 0 = unset valid", func(c *SandlotConfig) { c.Instance.CIDRangeStart = 100 }, false},
		{"cid range valid", func(c *SandlotConfig) { c.Instance.CIDRangeStart = 100; c.Instance.CIDRangeEnd = 200 }, false},
		// Registry credentials: pairing + "credentials need a registry".
		{"cert without key invalid", func(c *SandlotConfig) {
			c.Provision.OCIRegistry = "reg.example.com/repo"
			c.Provision.RegistryCert = "/certs/client.crt"
		}, true},
		{"key without cert invalid", func(c *SandlotConfig) {
			c.Provision.OCIRegistry = "reg.example.com/repo"
			c.Provision.RegistryKey = "/certs/client.key"
		}, true},
		{"credentials without a registry invalid", func(c *SandlotConfig) {
			c.Provision.RegistryUsername = "u"
			c.Provision.RegistryPassword = "p"
		}, true},
		{"basic auth with registry valid", func(c *SandlotConfig) {
			c.Provision.OCIRegistry = "reg.example.com/repo"
			c.Provision.RegistryUsername = "u"
			c.Provision.RegistryPassword = "p"
		}, false},
		{"token with registry valid", func(c *SandlotConfig) {
			c.Provision.OCIRegistry = "reg.example.com/repo"
			c.Provision.RegistryToken = "t"
		}, false},
		{"mTLS pair + CA with registry valid", func(c *SandlotConfig) {
			c.Provision.OCIRegistry = "reg.example.com/repo"
			c.Provision.RegistryCert = "/certs/client.crt"
			c.Provision.RegistryKey = "/certs/client.key"
			c.Provision.RegistryCA = "/certs/ca.crt"
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Defaults()
			tc.mut(&cfg)
			err := cfg.Validate()
			if (err != nil) != tc.wantErr {
				t.Errorf("Validate() = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

// ── configurable service identities: env override of the pinned defaults ──

// TestVMMSeccompRejectsProcess pins the config-layer rejection of the
// upstream KillProcess mode: it installs empty per-thread filters, so the
// value must never reach sandvmm (which rejects it too).
func TestVMMSeccompRejectsProcess(t *testing.T) {
	cfg := Defaults()
	cfg.MicroVM.VMMSeccomp = "process"
	if err := cfg.Validate(); err == nil {
		t.Fatal("microvm.vmm_seccomp=process accepted")
	}
	for _, ok := range []string{"", "true", "false", "log"} {
		cfg.MicroVM.VMMSeccomp = ok
		if err := cfg.Validate(); err != nil {
			t.Fatalf("microvm.vmm_seccomp=%q rejected: %v", ok, err)
		}
	}
}

// TestMaxSparseBytesValidate pins the template-save size cap: a negative value
// is meaningless, while 0 explicitly selects the built-in default.
func TestMaxSparseBytesValidate(t *testing.T) {
	cfg := Defaults()
	cfg.Provision.MaxSparseBytes = -1
	if err := cfg.Validate(); err == nil {
		t.Fatal("negative provision.max_sparse_bytes accepted")
	}
	cfg.Provision.MaxSparseBytes = 0
	if err := cfg.Validate(); err != nil {
		t.Fatalf("0 (built-in default) rejected: %v", err)
	}
}

// TestConcurrencyConfigValidate pins the batch worker bounds: zero or
// negative would serialize (or deadlock) pool scale-up/down, so both are
// rejected at startup and on config reload.
func TestConcurrencyConfigValidate(t *testing.T) {
	good := ConcurrencyConfig{VMCreate: 1, VMDestroy: 1}
	if err := good.Validate(); err != nil {
		t.Errorf("valid minimal concurrency rejected: %v", err)
	}
	for _, c := range []ConcurrencyConfig{
		{VMCreate: 0, VMDestroy: 1},
		{VMCreate: -1, VMDestroy: 1},
		{VMCreate: 1, VMDestroy: 0},
		{VMCreate: 1, VMDestroy: -1},
	} {
		if err := c.Validate(); err == nil {
			t.Errorf("ConcurrencyConfig %+v accepted, want refusal", c)
		}
	}
}

func TestDefaultsEnvOverridesServiceIdentities(t *testing.T) {
	// The deployer exports the RESOLVED identities (occupied-slot
	// adoption/auto-pick in common/sh/runtime.sh); Defaults must honor them.
	t.Setenv("SANDSWAP_VMM_UID", "601")
	t.Setenv("SANDSWAP_VMM_GID", "602")
	t.Setenv("SANDSWAP_API_GID", "603")
	t.Setenv("SANDSWAP_VMM_GROUPS", "kvm,603")
	cfg := Defaults()
	if cfg.MicroVM.VMMUid != 601 || cfg.MicroVM.VMMGid != 602 || cfg.MicroVM.APIGid != 603 || cfg.MicroVM.VMMGroups != "kvm,603" {
		t.Errorf("env overrides not honored: %+v", cfg.MicroVM)
	}
	// Malformed values fall back to the pinned defaults, not a crash.
	t.Setenv("SANDSWAP_VMM_UID", "not-a-number")
	if got := Defaults().MicroVM.VMMUid; got != 987 {
		t.Errorf("malformed env must fall back to 987, got %d", got)
	}
}

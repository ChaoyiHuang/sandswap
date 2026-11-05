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
//
// Package config defines the Sandlot configuration types, YAML loading,
// and change classification for hot-reload vs restart-required.

package config

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"common/config"

	"bytes"
	"gopkg.in/yaml.v3"

	"sandlot/provision/volname"
)

// MicroVMConfig holds the microVM hardware parameters.
type MicroVMConfig struct {
	Kernel             string `yaml:"kernel"`
	Initramfs          string `yaml:"initramfs"`
	DefaultVCPUs       uint32 `yaml:"default_vcpus"`
	DefaultMemoryMB    uint64 `yaml:"default_memory_mb"`
	VolumesDir         string `yaml:"volumes_dir"`
	OverlayFSTemplates string `yaml:"overlayfs_templates"`
	// VMMUid/VMMGid run every sandvmm process (VMM + the FUSE passthrough
	// daemon) as a dedicated identity SEPARATE from sandlot — the uid
	// vsockguard trusts on the warden vsock port. The uid transition inside
	// the spawn clears every capability set kernel-side, so sandvmm runs
	// with ZERO capabilities. 0/0 = no transition (scratch/dev runs as the
	// parent identity). Contract-pinned: 987 on every node. Restart-required.
	VMMUid uint32 `yaml:"vmm_uid"`
	VMMGid uint32 `yaml:"vmm_gid"`
	// VMMGroups is the supplementary group list for the sandvmm child:
	// entries are numeric gids or group NAMES (names resolved at startup —
	// e.g. "kvm" whose gid varies per host; numbers carry the contract
	// pins, e.g. the sandlot shared group 985 for volume writes). The child
	// needs: kvm (/dev/kvm) + the shared group (volumes, socket chgrp).
	VMMGroups string `yaml:"vmm_groups"`
	// APIGid is the group granted connect access to the sandvmm API sockets
	// (0660 owner:group). Must be a group the sandvmm child belongs to
	// (include it in VMMGroups) and one the sandlot identity is a member of
	// — the sandlot shared group (985) satisfies both. 0 = sockets stay
	// 0600 owner-only (only the sandvmm identity itself / root can connect
	// — usable only with VMMUid=0). Restart-required.
	APIGid uint32 `yaml:"api_gid"`
	// VMMSeccomp selects the sandvmm seccomp mode: "true" (default; Trap —
	// a syscall outside the v28 per-thread allow-list kills the offending
	// process), "log" (installs the same filters with SECCOMP_RET_LOG — a
	// missed rule is logged and allowed; audit mode), "process" (KillProcess)
	// or "false" (no filter, the explicit escape hatch). The per-thread
	// allow-lists were audited with `e2e/vmm-seccomp.sh` (log phase zero
	// RET_LOG hits, enforce phase green) before this default was flipped.
	// Restart-required (VMM spawn argument).
	VMMSeccomp string `yaml:"vmm_seccomp"`
	// VMMAPIAuth enables the per-VM sandvmm canonical-API token/challenge
	// handshake (default TRUE). When on, the launcher mints a
	// 32-byte random token, persists it 0600 under <sandbox>/state for
	// re-adopt, delivers it over an inherited fd, and the client proves the
	// peer knows it before the first protocol byte. When off, the socket
	// relies on DAC + --api-allowed-uid (the peer uid gate stays on either
	// way). Restart-required.
	VMMAPIAuth bool `yaml:"vmm_api_auth"`
	// WardenMaxExecTimeoutSec overrides the in-VM warden's max exec timeout
	// for NEW VMs via the kernel cmdline (0 = warden default 180s). Must stay
	// below resilience.warden_countdown_sec so a max-length exec always
	// finishes before the warden's countdown fires. Restart-required.
	WardenMaxExecTimeoutSec uint32 `yaml:"warden_max_exec_timeout_sec"`
	// WardenLogLevel overrides the warden's log level via the kernel cmdline
	// ("" = warden default info). Set debug for profiling sessions — per-op
	// hot-path timing lines live at debug because their serial-UART drain
	// taxes the measured path. Deliberately RESTART-REQUIRED: an online flip
	// would enable UART-taxed debug logging across every new VM at fleet
	// scale with no friction; the restart is the safety gate.
	WardenLogLevel string `yaml:"warden_log"`
	// InitOnFree re-enables the guest kernel's free-time page wipe
	// (init_on_free=1 on every VM's kernel cmdline). Default false: a fresh
	// microVM's RAM is host anonymous mmap (untouched pages already
	// host-zero) and the kernel config's INIT_ON_FREE_DEFAULT_ON boot-time
	// bulk clear costs ~0.65ms/MB of pure redundancy (boot becomes
	// RAM-independent with the override); init_on_alloc stays on either way
	// and keeps the cross-tenant freed-page channel closed. Set true only
	// for deployments that require the stronger wipe (contents zeroed at
	// free time as well). Security-posture knob: RESTART-REQUIRED, like
	// vmm_seccomp/vmm_api_auth (an online posture flip at fleet scale must
	// not be friction-free); boxout mode reads the shared YAML at startup.
	InitOnFree bool `yaml:"init_on_free"`
}

// SpecEntry defines a single microVM spec's resource parameters.
type SpecEntry struct {
	VCPUs    uint32 `yaml:"vcpus"`
	MemoryMB uint64 `yaml:"memory_mb"`
	// ExecSlots is the per-VM sync-command concurrency: the number of parallel
	// vsock connections sandlot keeps to the VM's warden (one in-flight
	// request per connection). Bounded by guest memory: a full sync exec
	// buffers up to ~2x max_body_len of output, so slots should scale with
	// MemoryMB. 0/omitted = 1 (serial; the memory-safe fallback for custom
	// specs that don't declare it).
	ExecSlots int `yaml:"exec_slots"`
}

// RecycleConfig holds the VM recycle (reclaim) parameters + the min-idle floor.
type RecycleConfig struct {
	// MaxUses destroys+recreates a VM once it has served this many commands
	// (execs and file ops alike; counted per command, warm and cold).
	// -1 = unlimited (never recycle on use count), 0 = disable the use-count
	// trigger. Any other negative value is invalid (Validate rejects it).
	MaxUses int `yaml:"max_uses"`
	// MaxMounts destroys+recreates a VM once it has served this many mount
	// generations (one per successful cold attach; warm ops do not count).
	// -1 = unlimited, 0 = disable this trigger, other negatives invalid.
	MaxMounts int `yaml:"max_mounts"`
	// MaxDistinctAgents caps how many different agents one VM may serve over
	// its lifetime. A new agent on a VM at the cap is refused at selection
	// (or the VM is recycled). -1 = unlimited, 0 = disable, other negatives
	// invalid.
	MaxDistinctAgents int `yaml:"max_distinct_agents"`
	// AffinityVMs is how many recently-used VMs a sandfs prefers to reuse
	// (best-effort, memory-only). 0 disables affinity.
	AffinityVMs int `yaml:"affinity_vms"`
	MemPercent  int `yaml:"mem_percent"`
	MemAbsMB    int `yaml:"mem_abs_mb"`
	// MinIdleFloorFrac is the per-spec minimum CLEAN-VM headroom maintained on
	// top of the pool target (min-idle floor dampener). When > 0, the
	// effective pool target per spec becomes target + max(1, floor(frac*target)),
	// so there is always a spare CLEAN VM ready to absorb a burst — reducing the
	// frequency at which a node tips into zero-clean and triggers load shedding.
	// It does NOT guarantee idle under sustained load (demand grabs the
	// spare); it only pre-creates headroom up to the capped target+floor. 0 =
	// disabled (default). Hot-reloadable.
	MinIdleFloorFrac float64 `yaml:"min_idle_floor_frac"`
}

// Validate checks the recycle config values. MaxUses uses -1 as the "unlimited"
// sentinel (never recycle on use count) and 0 as "disable"; every other negative
// value is rejected so a typo'd negative cannot silently disable the use-count
// trigger. Enforced at startup and on every hot-reload application.
func (r RecycleConfig) Validate() error {
	if r.MaxUses < -1 {
		return fmt.Errorf("recycle.max_uses must be -1 (unlimited) or >= 0 (got %d)", r.MaxUses)
	}
	if r.MaxMounts < -1 {
		return fmt.Errorf("recycle.max_mounts must be -1 (unlimited) or >= 0 (got %d)", r.MaxMounts)
	}
	if r.MaxDistinctAgents < -1 {
		return fmt.Errorf("recycle.max_distinct_agents must be -1 (unlimited) or >= 0 (got %d)", r.MaxDistinctAgents)
	}
	if r.AffinityVMs < 0 {
		return fmt.Errorf("recycle.affinity_vms must be >= 0 (got %d)", r.AffinityVMs)
	}
	return nil
}

// ConcurrencyConfig bounds parallel VM lifecycle work. Batch VM creation and
// batch idle-VM destruction are I/O- and KVM-bound; running them serially
// stretches a pool scale-up across every boot in sequence. Both values are
// restart-required (they size the batch worker pools at startup).
type ConcurrencyConfig struct {
	// VMCreate is the maximum number of microVMs booting at once during a
	// pool scale-up, reconcile fill, or startup pre-create. Default 5.
	VMCreate int `yaml:"vm_create"`
	// VMDestroy is the maximum number of idle microVMs destroyed at once
	// during a pool scale-down. Default 10.
	VMDestroy int `yaml:"vm_destroy"`
}

// Validate checks the concurrency bounds. A zero/negative worker count would
// serialize (or deadlock) a batch, so it is refused instead of silently
// clamped.
func (c ConcurrencyConfig) Validate() error {
	if c.VMCreate < 1 {
		return fmt.Errorf("concurrency.vm_create must be >= 1 (got %d)", c.VMCreate)
	}
	if c.VMDestroy < 1 {
		return fmt.Errorf("concurrency.vm_destroy must be >= 1 (got %d)", c.VMDestroy)
	}
	return nil
}

// MinBootMemoryMB is the minimum memory (MiB) for a microVM to boot the kernel
// + warden and run a minimal workload. Specs (and the microvm default) below
// this are rejected at validation/parse time rather than failing later inside
// KVM with a confusing per-VM error.
const MinBootMemoryMB = 64

// MaxExecSlots bounds a spec's per-VM warden connection-pool size. The
// warden's MAX_CONNS is 16 (the exec pool plus heartbeat probes and
// reconnect bursts); a larger pool would have legal connections refused
// under load. The built-in specs top out at 5; the headroom is for custom
// specs. 0 remains valid ("serial", 1 connection).
const MaxExecSlots = 12

// Validate checks the whole config's value bounds. Enforced at startup AND on
// every hot-reload application (an invalid edit is rejected whole — same rule
// as startup — and the watchable config keeps the last good value):
//   - recycle: see RecycleConfig.Validate
//   - microvm defaults: vcpus/memory must be >= 1 (memory >= MinBootMemoryMB).
//     The CLI flag path converts int → uint32/uint64, where a typo'd negative
//     silently wraps to an absurd value and every VM creation fails with a
//     confusing KVM error; 0 fails the same way without the confusion.
//   - stream: buffers/concurrency/write-timeout >= 1, and the window/message
//     caps share the gateway contract (ValidateStreamCaps). The rpc client
//     clamps <= 0 to hardcoded defaults, silently discarding the operator's
//     value — refused here instead.
//   - instance CID range: start >= 3 (0/1/2 are reserved AF_VSOCK CIDs; the
//     handler silently ignored lower values) and end > start when set (an
//     inverted range exhausts the allocation immediately).
func (c SandlotConfig) Validate() error {
	if err := c.Recycle.Validate(); err != nil {
		return err
	}
	if err := c.Concurrency.Validate(); err != nil {
		return err
	}
	switch c.SetFsTransport {
	case "raw", "http":
	default:
		return fmt.Errorf("setfs_transport must be \"raw\" or \"http\", got %q", c.SetFsTransport)
	}
	if c.MicroVM.DefaultVCPUs < 1 {
		return fmt.Errorf("microvm.default_vcpus must be >= 1, got %d", c.MicroVM.DefaultVCPUs)
	}
	if c.MicroVM.DefaultMemoryMB < MinBootMemoryMB {
		return fmt.Errorf("microvm.default_memory_mb must be >= %d (a smaller VM cannot boot the kernel + warden), got %d",
			MinBootMemoryMB, c.MicroVM.DefaultMemoryMB)
	}
	if (c.MicroVM.VMMUid == 0) != (c.MicroVM.VMMGid == 0) {
		return fmt.Errorf("microvm.vmm_uid and microvm.vmm_gid must be set together (got uid=%d gid=%d)", c.MicroVM.VMMUid, c.MicroVM.VMMGid)
	}
	if c.MicroVM.VMMUid > 0 && c.MicroVM.APIGid == 0 {
		return fmt.Errorf("microvm.api_gid must be > 0 when vmm_uid is set (sandlot could not connect to the 0600 owner-only API sockets of a different identity)")
	}
	switch c.MicroVM.VMMSeccomp {
	case "", "true", "false", "log":
	default:
		return fmt.Errorf("microvm.vmm_seccomp %q: must be true|false|log (log = audit, true = enforce); the upstream KillProcess mode is unsupported because it installs empty per-thread filters", c.MicroVM.VMMSeccomp)
	}
	if c.Stream.SendBufferSize < 1 {
		return fmt.Errorf("stream.send_buffer_size must be >= 1, got %d", c.Stream.SendBufferSize)
	}
	if c.Stream.RecvBufferSize < 1 {
		return fmt.Errorf("stream.recv_buffer_size must be >= 1, got %d", c.Stream.RecvBufferSize)
	}
	if c.Stream.MaxConcurrentCommands < 1 {
		return fmt.Errorf("stream.max_concurrent_commands must be >= 1, got %d", c.Stream.MaxConcurrentCommands)
	}
	if c.Stream.WriteTimeoutSec < 1 {
		return fmt.Errorf("stream.write_timeout_sec must be >= 1, got %d", c.Stream.WriteTimeoutSec)
	}
	if err := config.ValidateStreamCaps(c.Stream.InitialWindow, c.Stream.InitialConnWindow, c.Stream.MaxMsgSize); err != nil {
		return fmt.Errorf("stream: %w", err)
	}
	if c.Instance.CIDRangeStart != 0 && c.Instance.CIDRangeStart < 3 {
		return fmt.Errorf("instance.cid_range_start must be >= 3 (0/1/2 are reserved AF_VSOCK CIDs), got %d", c.Instance.CIDRangeStart)
	}
	if c.Instance.CIDRangeEnd != 0 && c.Instance.CIDRangeEnd <= c.Instance.CIDRangeStart {
		return fmt.Errorf("instance.cid_range_end (%d) must be > cid_range_start (%d): an inverted range exhausts CID allocation immediately",
			c.Instance.CIDRangeEnd, c.Instance.CIDRangeStart)
	}
	// exec_slots is the per-VM warden connection-pool size. The warden's
	// MAX_CONNS is 16 (pool + heartbeat probes + reconnect bursts), so a
	// custom spec above MaxExecSlots would make the warden refuse legal pool
	// connections (WouldBlock/closed) under load. 0 means "serial" (1).
	for name, spec := range c.Specs {
		if spec.ExecSlots < 0 {
			return fmt.Errorf("specs.%s.exec_slots must be >= 0 (0 = serial), got %d", name, spec.ExecSlots)
		}
		if spec.ExecSlots > MaxExecSlots {
			return fmt.Errorf("specs.%s.exec_slots must be <= %d (the warden connection cap, with heartbeat headroom), got %d",
				name, MaxExecSlots, spec.ExecSlots)
		}
	}
	if err := c.validateRoles(); err != nil {
		return err
	}
	if p := c.Provision; p.MaxConcurrentOps < 0 {
		return fmt.Errorf("provision.max_concurrent_ops must be >= 0 (got %d)", p.MaxConcurrentOps)
	} else if p.DefaultDeadlineSec < 0 {
		return fmt.Errorf("provision.default_deadline_sec must be >= 0 (got %d)", p.DefaultDeadlineSec)
	} else if p.ReconnectSec < 0 {
		return fmt.Errorf("provision.reconnect_sec must be >= 0 (got %d)", p.ReconnectSec)
	} else if p.MaxSparseBytes < 0 {
		return fmt.Errorf("provision.max_sparse_bytes must be >= 0 (got %d)", p.MaxSparseBytes)
	}
	if err := c.Provision.validateRegistryAuth(); err != nil {
		return err
	}
	if c.Provision.SeedPollSec < 0 {
		return fmt.Errorf("provision.seed_poll_sec must be >= 0 (0 = default; got %d)", c.Provision.SeedPollSec)
	}
	// Inline twin of volume.ValidateQuotaStampCmd: the config package must
	// not import the provision package (dependency direction), and the check
	// is exactly "empty (disabled) or absolute".
	if c.Provision.QuotaStampCmd != "" && !filepath.IsAbs(c.Provision.QuotaStampCmd) {
		return fmt.Errorf("provision.quota_stamp_cmd must be an absolute path (got %q)", c.Provision.QuotaStampCmd)
	}
	return nil
}

// HasRegistryCredential reports whether any registry credential is configured.
// SeedSourceKind names the injected channel a generation's seed comes from.
// Any third-party injector (an agent rendering a file, a systemd credential, a
// k8s Secret key) lands in the file kind: what the sandlot promises is the
// channel contract, never a vendor integration.
const (
	SeedSourceInline = "inline" // the value in the config file itself
	SeedSourceFile   = "file"   // a file path (tmpfs, credential dir, Secret volume key)
)

// SeedSource describes WHERE a generation's seed is read from, without
// carrying any of it: a path is not a secret, and the inline kind deliberately
// reports no value. The adoption state file, the reload logs and the host
// verifier all need to name the channel without touching the bytes.
type SeedSource struct {
	Generation string // "current" | "next"
	Kind       string // SeedSourceInline | SeedSourceFile | "" (unconfigured)
	Path       string // set when Kind == SeedSourceFile
}

func (s SeedSource) String() string {
	switch s.Kind {
	case SeedSourceFile:
		return "file:" + s.Path
	case SeedSourceInline:
		return "inline"
	default:
		return "unconfigured"
	}
}

// seedRef identifies one generation's configured source. Both generations
// resolve by identical rules, so they share this.
type seedRef struct {
	generation string
	inlineKey  string
	inline     string
	fileKey    string
	file       string
}

func (p ProvisionConfig) currentRef() seedRef {
	return seedRef{"current", "provision.volume_seed", p.VolumeSeed, "provision.volume_seed_file", p.VolumeSeedFile}
}

func (p ProvisionConfig) nextRef() seedRef {
	return seedRef{"next", "provision.volume_seed_next", p.VolumeSeedNext, "provision.volume_seed_next_file", p.VolumeSeedNextFile}
}

// source describes the configured channel WITHOUT reading it: the state file
// records what is configured even while the injector has not materialized it.
func (r seedRef) source() SeedSource {
	switch {
	case r.file != "":
		return SeedSource{Generation: r.generation, Kind: SeedSourceFile, Path: r.file}
	case r.inline != "":
		return SeedSource{Generation: r.generation, Kind: SeedSourceInline}
	default:
		return SeedSource{}
	}
}

func (r seedRef) configured() bool { return r.inline != "" || r.file != "" }

// maxSeedFileBytes bounds a seed source file. A seed is 32 bytes (64 hex or
// 44 base64 chars); 4 KiB leaves room for a trailing newline and a comment
// without letting a writer make the sandlot allocate an unbounded file.
const maxSeedFileBytes = 4 << 10

// raw reads the generation's seed TEXT (undecoded hex or base64): the inline
// value, or the trimmed contents of a file. Setting both is ambiguous. A file
// that cannot be read is an error the CALLER classifies — fatal for the
// current generation, retryable for the next one.
//
// The file channel is injector-supplied by design (Vault/ESO, a systemd
// credential, a tmpfs fetch unit, a k8s Secret key), so the daemon verifies
// the PROVENANCE it can verify: the path is resolved through symlinks (a k8s
// projected Secret is a symlink chain), the target must be a regular file,
// and it must not be group- or world-writable. The channel contract is
// root(or the service identity):<group> 0640; a file another local identity
// can rewrite is an injected generation the fleet must not adopt. Owner is
// restricted to root or the sandlot's own uid for the same reason. The file
// is opened ONCE and fstat'ed on the fd, so a path swap between check and read
// cannot launder a different inode.
func (r seedRef) raw() (string, error) {
	if r.inline != "" && r.file != "" {
		return "", fmt.Errorf("%s and %s are both set — pick one", r.inlineKey, r.fileKey)
	}
	if r.file != "" {
		resolved, err := filepath.EvalSymlinks(r.file)
		if err != nil {
			return "", fmt.Errorf("%s: resolve %q: %w", r.fileKey, r.file, err)
		}
		f, err := os.Open(resolved)
		if err != nil {
			return "", fmt.Errorf("%s: %w", r.fileKey, err)
		}
		defer f.Close()
		fi, err := f.Stat()
		if err != nil {
			return "", fmt.Errorf("%s: stat %q: %w", r.fileKey, resolved, err)
		}
		if !fi.Mode().IsRegular() {
			return "", fmt.Errorf("%s: %q is not a regular file — the seed channel accepts a regular file (or a symlink chain resolving to one)", r.fileKey, r.file)
		}
		if fi.Mode().Perm()&0o022 != 0 {
			return "", fmt.Errorf("%s: %q is group/world-writable (mode %04o) — a local identity could replace the seed generation; scope it root(or the service uid):<shared group> 0640", r.fileKey, resolved, fi.Mode().Perm())
		}
		if st, ok := fi.Sys().(*syscall.Stat_t); ok {
			uid := uint32(st.Uid)
			if uid != 0 && uid != uint32(os.Geteuid()) {
				return "", fmt.Errorf("%s: %q is owned by uid %d, not root or the service identity (%d) — the injector must hand the seed over at the contracted ownership", r.fileKey, resolved, uid, os.Geteuid())
			}
		}
		b, err := io.ReadAll(io.LimitReader(f, maxSeedFileBytes+1))
		if err != nil {
			return "", fmt.Errorf("%s: read: %w", r.fileKey, err)
		}
		if len(b) > maxSeedFileBytes {
			return "", fmt.Errorf("%s: %q exceeds the %d-byte seed file cap", r.fileKey, resolved, maxSeedFileBytes)
		}
		return strings.TrimSpace(string(b)), nil
	}
	return strings.TrimSpace(r.inline), nil
}

// SeedConfigured reports whether a generation ("current" or "next") has a
// source configured. Callers use it instead of spelling the field list out, so
// adding a channel cannot silently miss a call site.
func (p ProvisionConfig) SeedConfigured(generation string) bool {
	if generation == "next" {
		return p.nextRef().configured()
	}
	return p.currentRef().configured()
}

// SeedSources reports both generations' configured channels, current first,
// skipping unconfigured ones.
func (p ProvisionConfig) SeedSources() []SeedSource {
	out := make([]SeedSource, 0, 2)
	for _, ref := range []seedRef{p.currentRef(), p.nextRef()} {
		if src := ref.source(); src.Kind != "" {
			out = append(out, src)
		}
	}
	return out
}

// CurrentSeed resolves the CURRENT generation. Every failure here is fatal for
// the prov role: without a current seed no volume name can be derived.
func (p ProvisionConfig) CurrentSeed() ([]byte, SeedSource, error) {
	ref := p.currentRef()
	raw, err := ref.raw()
	if err != nil {
		return nil, SeedSource{}, fmt.Errorf("provision.volume_seed is required for the prov role (generate one with: openssl rand -hex 32) — the volume directory name is derived from it, and without a seed the on-disk names would be guessable: %w", err)
	}
	seed, derr := volname.DecodeSeed(raw)
	if derr != nil {
		return nil, SeedSource{}, fmt.Errorf("provision.volume_seed: %w", derr)
	}
	return seed, ref.source(), nil
}

// NextSeed resolves the NEXT (staged) generation; (nil, ...,nil) means no
// rotation is configured. A failure here is a DIFFERENT class from a current
// failure: an injector may simply not have materialized the staged file yet,
// so callers retry it (the reload path refuses the transition and waits for
// the next event; the startup path logs and runs unstaged) rather than
// treating it as unstartable.
func (p ProvisionConfig) NextSeed() ([]byte, SeedSource, error) {
	ref := p.nextRef()
	raw, err := ref.raw()
	if err != nil {
		return nil, SeedSource{}, fmt.Errorf("provision.volume_seed_next: %w", err)
	}
	if raw == "" {
		return nil, SeedSource{}, nil
	}
	seed, derr := volname.DecodeSeed(raw)
	if derr != nil {
		return nil, SeedSource{}, fmt.Errorf("provision.volume_seed_next: %w", derr)
	}
	return seed, ref.source(), nil
}

// VolumeSeeds is the strict two-generation form: both must resolve and a next
// equal to the current is refused. Used where an edit must be accepted or
// refused WHOLE (the reload path), never half-applied.
func (p ProvisionConfig) VolumeSeeds() (cur, next []byte, err error) {
	if cur, _, err = p.CurrentSeed(); err != nil {
		return nil, nil, err
	}
	if next, _, err = p.NextSeed(); err != nil {
		return nil, nil, err
	}
	if len(next) > 0 && string(next) == string(cur) {
		return nil, nil, fmt.Errorf("provision.volume_seed_next equals volume_seed — a rotation would rename nothing")
	}
	return cur, next, nil
}

// ResolveSeedFilePaths makes relative volume-seed file paths absolute against
// dir — the config file's directory, which is how the deploy scripts write
// them and what template-tool has always assumed. Without this the daemon
// resolved a relative path against its process CWD, so one config could work
// for the tool and fail for the instance.
func (c *SandlotConfig) ResolveSeedFilePaths(dir string) {
	if dir == "" {
		return
	}
	fix := func(p *string) {
		if *p != "" && !filepath.IsAbs(*p) {
			*p = filepath.Join(dir, *p)
		}
	}
	fix(&c.Provision.VolumeSeedFile)
	fix(&c.Provision.VolumeSeedNextFile)
}

func (p ProvisionConfig) HasRegistryCredential() bool {
	return p.RegistryUsername != "" || p.RegistryPassword != "" || p.RegistryToken != "" ||
		p.RegistryCert != "" || p.RegistryKey != "" || p.RegistryCA != ""
}

// RegistryAuthMethod names the configured credential for logs — never a value.
func (p ProvisionConfig) RegistryAuthMethod() string {
	method := "anonymous"
	switch {
	case p.RegistryUsername != "" || p.RegistryPassword != "":
		method = "basic"
	case p.RegistryToken != "":
		method = "token"
	}
	if p.RegistryCert != "" && p.RegistryKey != "" {
		method += "+mtls"
	}
	if p.RegistryCA != "" {
		method += "+ca"
	}
	return method
}

// validateRegistryAuth rejects credential configurations that cannot work:
// a cert without its key is always a mistake, and credentials with no
// registry to authenticate to would be silently dead config.
func (p ProvisionConfig) validateRegistryAuth() error {
	if (p.RegistryCert == "") != (p.RegistryKey == "") {
		return fmt.Errorf("provision.registry_cert and provision.registry_key must be set together (registry mTLS client pair; got cert=%q key=%q)",
			p.RegistryCert, p.RegistryKey)
	}
	if p.HasRegistryCredential() && p.OCIRegistry == "" {
		return fmt.Errorf("provision.registry_* credentials are set but provision.oci_registry is empty: there is no registry to authenticate to")
	}
	return nil
}

// NormalizedRoles returns the deduplicated role set with the legacy default
// applied: empty/absent roles means ["exec"].
func (c SandlotConfig) NormalizedRoles() []string {
	if len(c.Roles) == 0 {
		return []string{"exec"}
	}
	seen := make(map[string]bool, len(c.Roles))
	out := make([]string, 0, len(c.Roles))
	for _, r := range c.Roles {
		if !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	return out
}

// HasRole reports whether the instance serves the given role.
func (c SandlotConfig) HasRole(role string) bool {
	for _, r := range c.NormalizedRoles() {
		if r == role {
			return true
		}
	}
	return false
}

// validateRoles enforces the role/config matrix: known roles only, and a
// prov-only instance must not carry exec machinery config (a pool, a boxout
// sidecar, or a bridge backend would either create VMs on a storage host or
// dial a sidecar that is not there).
func (c SandlotConfig) validateRoles() error {
	hasExec, hasProv := false, false
	for _, r := range c.NormalizedRoles() {
		switch r {
		case "exec":
			hasExec = true
		case "prov":
			hasProv = true
		default:
			return fmt.Errorf("roles entries must be \"exec\" and/or \"prov\" (got %q in %v)", r, c.Roles)
		}
	}
	if !hasProv {
		return nil // exec-only or empty (legacy): provision config is ignored
	}
	if !hasExec {
		if c.Pool != "" {
			return fmt.Errorf("pool is exec-role config but roles=%v (prov-only instance): remove -pool or add the exec role", c.NormalizedRoles())
		}
		if c.VMMode == "boxout" {
			return fmt.Errorf("vm-mode boxout is exec-role machinery but roles=%v (prov-only instance): use embedded or add the exec role", c.NormalizedRoles())
		}
		if c.Network.Backend != "" && c.Network.Backend != "none" {
			return fmt.Errorf("network backend %q is exec-role machinery but roles=%v (prov-only instance): use none or add the exec role", c.Network.Backend, c.NormalizedRoles())
		}
	}
	return nil
}

// ResilienceConfig holds the tolerance-first resilience timings. All values
// are seconds. The sandlot sends these to the gateway in NodeHello.timing; the
// gateway derives T_safe (presence-key TTL = tolerance + warden_countdown + 1)
// from them and rejects the node's connect if the invariant
// T_safe > T_tolerance + T_warden is violated.
type ResilienceConfig struct {
	// ToleranceSec (T_tolerance): how long the sandlot tolerates a stream
	// outage before it starts cleaning (mount release). During this phase
	// ownership is untouched and the agent sees 503+retry. Default 300.
	ToleranceSec int `yaml:"tolerance_sec"`
	// CleanupSec (T_clean): time budget for the sandlot's mount cleanup
	// (concurrent OP_UNMOUNT + set-fs clear). Must complete before
	// T_tolerance + T_clean. Default 300.
	CleanupSec int `yaml:"cleanup_sec"`
	// WardenCountdownSec (T_warden): the in-VM warden's single countdown, reset
	// only by OP_MEM_STATS heartbeats. Expiry with a live mount exits the warden,
	// killing the VM as a last-resort mount release. Must be >= CleanupSec so the
	// sandlot always has room to unmount normally before the countdown fires.
	// Default 300.
	WardenCountdownSec int `yaml:"warden_countdown_sec"`
	// IsolationSec (T_isolation): how long the sandlot waits after finishing
	// cleanup before reconnecting. Beyond T_safe, so the gateway's ownership release of
	// this node's ownership completes first and no new gateway mounts this
	// node's shared sandfs before every old mount is gone. Default 720.
	IsolationSec int `yaml:"isolation_sec"`
}

// NetworkConfig holds the outbound networking parameters.
type NetworkConfig struct {
	Backend string `yaml:"backend"`
	Bridge  string `yaml:"bridge"`
	Subnet  string `yaml:"subnet"`
	Gateway string `yaml:"gateway"`
	DNS     string `yaml:"dns"`
	// BindBackend enables the egress identity binding region (the enabler for
	// third-party network policy enforcers, docs/how-it-works/egress-enabler.md):
	// "off" (default) | "shm" (tmpfs file) | "bpf" (pinned mmapable BPF array).
	BindBackend string `yaml:"bind_backend"`
	// BindPath overrides the region's default location (shm file path or
	// bpffs pin path). Empty = per-backend default.
	BindPath string `yaml:"bind_path"`
	// EgressBaseline toggles the egress network baseline (source anti-spoof
	// + VM-to-VM isolation): "on" (default) | "off". With "on" (or unset)
	// the node REFUSES TO START when nftables is missing or its tables
	// cannot be installed — without the baseline every tenant TAP shares
	// one unfiltered L2 bridge.
	EgressBaseline string `yaml:"egress_baseline"`
	// VMToVM is the guest-to-guest traffic posture: "deny" (default) | "allow"
	// (multi-agent systems may permit direct VM-to-VM traffic).
	VMToVM string `yaml:"vm_to_vm"`
	// V6Prefix is the routed-ipv6 site prefix. Default: fd00:5341:4e44::/48
	// ("SAND" in ASCII hex). Overridden by -network-v6-prefix.
	V6Prefix string `yaml:"v6_prefix"`
	// IIDTemplate declares the identity-in-address IID layout; empty = random.
	IIDTemplate string `yaml:"iid_template"`
	// RequireEgressBinding refuses to start an EXEC-role instance when no
	// egress identity enabler is configured (neither Carrier A binding
	// backend nor Carrier B routed-ipv6 + iid_template). Production sets
	// this; dev/test leaves it false and gets a loud WARN + the "none"
	// binding projected in /stats.
	RequireEgressBinding bool `yaml:"require_egress_binding"`
}

// EgressBindingMode reports how guest egress is identity-bound on this node:
// "shm"/"bpf" (Carrier A binding region), "routed-ipv6" (Carrier B
// identity-in-address), or "none". A prov-only instance has no egress plane;
// callers gate on HasRole("exec").
func (c *SandlotConfig) EgressBindingMode() string {
	switch c.Network.BindBackend {
	case "shm", "bpf":
		return c.Network.BindBackend
	}
	if c.Network.Backend == "routed-ipv6" && c.Network.IIDTemplate != "" {
		return "routed-ipv6"
	}
	return "none"
}

// TLSConfig holds the TLS parameters.
type TLSConfig struct {
	Cert string `yaml:"cert"`
	Key  string `yaml:"key"`
	CA   string `yaml:"ca"`
}

// InstanceConfig holds multi-instance parameters.
type InstanceConfig struct {
	ID            string `yaml:"id"`
	BaseDir       string `yaml:"base_dir"`
	CIDRangeStart uint32 `yaml:"cid_range_start"`
	CIDRangeEnd   uint32 `yaml:"cid_range_end"`
}

// StreamConfig holds the sandlot<->gateway gRPC stream concurrency and
// transport parameters. All VMCommands from the gateway are received on a
// single bidi stream; these govern how many can be processed concurrently
// and the gRPC/HTTP-2 transport caps. All restart-required (dial options and
// the cmdSem are fixed at startup).
type StreamConfig struct {
	// SendBufferSize is the sendCh capacity for outbound messages
	// (responses/events/heartbeats to the gateway). Default 2000.
	SendBufferSize int `yaml:"send_buffer_size"`
	// RecvBufferSize is the recvCh capacity for incoming gateway commands.
	// Default 2000.
	RecvBufferSize int `yaml:"recv_buffer_size"`
	// MaxConcurrentCommands is the cmdSem: the max VMCommands processed
	// concurrently. The (N+1)th blocks until one finishes. Default 2000.
	MaxConcurrentCommands int `yaml:"max_concurrent_commands"`
	// WriteTimeoutSec is the max wait for a stream.Send; detects half-open TCP
	// and triggers a reconnect. Default 30.
	WriteTimeoutSec int `yaml:"write_timeout_sec"`
	// InitialWindow is the HTTP/2 per-stream flow-control window in bytes.
	// Shared by all in-flight messages on the single bidi stream; must be >=
	// MaxMsgSize and sized for concurrency headroom. Default 64MB.
	InitialWindow int `yaml:"initial_window"`
	// InitialConnWindow is the HTTP/2 per-connection window (>= InitialWindow).
	// Default 128MB.
	InitialConnWindow int `yaml:"initial_conn_window"`
	// MaxMsgSize is the gRPC max send/recv message size in bytes. Bounds a
	// single FileOp read/write payload; must be >= the warden single-op cap
	// (max_file_read_bytes / max_body_len). Default 16MB.
	MaxMsgSize int `yaml:"max_msg_size"`
}

// SandlotConfig is the top-level configuration for the sandlot process.
type SandlotConfig struct {
	// applyErr records the first refusal from ApplyFlagOverrides (a flag value
	// that cannot be represented, caught BEFORE the int→uint cast). cmd turns
	// it into a startup refusal; the reload path refuses the edit whole.
	applyErr error

	// reapplier re-applies the startup CLI-flag overrides to a freshly decoded
	// config (installed by cmd via SetFlagReapplier; see the gateway's twin).
	// The reload callback runs it before Validate/Swap so a file edit never
	// reverts a flag-provided value — without it the first edit cleared the
	// pool spec (`-pool small:2` → nil), which made ResizePool wipe the node's
	// pool maintenance until restart.
	reapplier func(*SandlotConfig)

	GatewayAddr  string               `yaml:"gateway_addr"`
	NodeID       string               `yaml:"node_id"`
	VMMBinary    string               `yaml:"vmm_binary"`
	MicroVM      MicroVMConfig        `yaml:"microvm"`
	Specs        map[string]SpecEntry `yaml:"specs"`
	Pool         string               `yaml:"pool"`
	Recycle      RecycleConfig        `yaml:"recycle"`
	Concurrency  ConcurrencyConfig    `yaml:"concurrency"`
	Network      NetworkConfig        `yaml:"network"`
	TLS          TLSConfig            `yaml:"tls"`
	Instance     InstanceConfig       `yaml:"instance"`
	VMMode       string               `yaml:"vm_mode"`       // "embedded" (default) or "boxout"
	BoxoutSocket string               `yaml:"boxout_socket"` // Unix socket path for boxout mode
	// BoxoutTokenFile is the per-pod admission token shared with boxout
	// (written by boxout at startup). Empty = UID-only admission (tests/dev).
	BoxoutTokenFile string `yaml:"boxout_token_file"`
	// SetFsTransport selects the sandvmm transport for the per-request hot
	// ops (vm.set-fs, sandvmm.ping): "raw" (default — the binary control
	// frame protocol on the same API socket) or "http" (legacy REST).
	// Restart-required: fixed at process start before any VMM client exists.
	SetFsTransport string           `yaml:"setfs_transport"`
	Stream         StreamConfig     `yaml:"stream"`
	Resilience     ResilienceConfig `yaml:"resilience"`

	// Roles selects this instance's capability sets (restart-required):
	//   ["exec"]      — the exec plane (microVM lifecycle, mounts, exec/file
	//                   ops). The historical per-node daemon; also the default
	//                   and the meaning of an empty/absent value.
	//   ["prov"]      — the provision role: sandfs + template lifecycle on
	//                   shared storage. Deploys on provision hosts (or any
	//                   storage-attached host); dials a human/unified gateway.
	//   ["exec","prov"] — the merged single-process form for single-node /
	//                   all-in-one hosts. Only meaningful against a UNIFIED
	//                   gateway (single-node / one-gw topologies): a merged
	//                   instance dialing an exec-only gateway serves only its
	//                   exec half there — deployment generators must not emit
	//                   that shape.
	Roles []string `yaml:"roles"`
	// Provision configures the prov role. Ignored (harmless) on exec-only
	// instances.
	Provision ProvisionConfig `yaml:"provision"`

	// ConfigFilePath is set from -config flag, not from YAML.
	ConfigFilePath string `yaml:"-"`
}

// DefaultSeedPollSec is how often a provision instance re-reads its seed
// sources when provision.seed_poll_sec is unset. The poll exists to cover
// filesystems where inotify never fires (a remote NFS write): the local
// channels — tmpfs, systemd credential dirs, Secret volume symlink swaps — are
// caught by fsnotify within its 200ms debounce.
const DefaultSeedPollSec = 30

// DefaultGatewayAddr is the default gateway stream endpoint (the local
// single-node gateway). It is shared by Defaults() and the -gateway-addr flag
// default so the two cannot drift.
const DefaultGatewayAddr = "localhost:9998"

// Built-in defaults shared by Defaults() and the CLI flag registrations. A
// flag default is the value shown in -help and the value a config file does not
// override: registering it from the same constant Defaults() uses is what
// keeps the two from drifting. Only values PROVEN equal belong here.
const (
	// Guest TCB paths. The kernel and initramfs are the root-only release
	// artifacts: they execute every in-VM clear and are part of the trust
	// boundary, so they live in a root-owned directory no service identity can
	// write (host prep installs them; the sandlot only reads).
	DefaultKernelPath    = "/usr/local/lib/sandswap/guest/vmlinux.bin"
	DefaultInitramfsPath = "/usr/local/lib/sandswap/guest/initramfs.cpio.gz"

	DefaultVMMBinary  = "sandvmm"
	DefaultVolumesDir = "/var/sandswap/volumes"

	DefaultVCPUs    = 2
	DefaultMemoryMB = 512

	DefaultNetworkBackend = "none"
	DefaultNetworkBridge  = "br-sandswap"
	DefaultNetworkSubnet  = "10.188.0.0/16"
	DefaultNetworkGateway = "10.188.0.1"
	DefaultNetworkDNS     = "1.1.1.1,8.8.8.8"
	DefaultV6Prefix       = "fd00:5341:4e44::/48"
	DefaultEgressBaseline = "on"
	DefaultVMToVM         = "deny"

	DefaultMaxUses              = 100000
	DefaultRecycleMemPercent    = 10
	DefaultRecycleMemAbsMB      = 100
	DefaultMinIdleFloorFrac     = 0
	DefaultVMCreateConcurrency  = 5
	DefaultVMDestroyConcurrency = 10

	DefaultVMMode         = "embedded"
	DefaultBoxoutSocket   = "/run/sandswap-boxout/boxout.sock"
	DefaultSetFsTransport = "raw"
	DefaultVMMAPIAuth     = true
	// DefaultInitOnFree is the guest free-wipe posture default (false = boot
	// with init_on_free=0; see MicroVMConfig.InitOnFree for the rationale).
	DefaultInitOnFree = false

	DefaultMaxProvisionOps       = 2
	DefaultProvisionDeadlineSec  = 300
	DefaultProvisionReconnectSec = 300

	// Resilience timings (tolerance-first; the contract chain the gateway
	// validates against its own thresholds).
	DefaultToleranceSec       = 300
	DefaultCleanupSec         = 300
	DefaultWardenCountdownSec = 300
	DefaultIsolationSec       = 720

	// DefaultMaxSparseBytes caps one file's APPARENT size when a tenant volume
	// is copied into a template layer. It is deliberately NOT shared with
	// copyfs.DefaultMaxFileBytes: that one is the copy engine's own fallback,
	// this one is the deployment knob's default, and the two may diverge
	// (copyfs can also run with the cap disabled for trusted sources).
	DefaultMaxSparseBytes int64 = 8 << 30
)

// Service-identity fallbacks. These stay contract-pinned for fleet uniformity;
// hosts with occupied slots resolve different numbers at deploy time and export
// them through the SANDSWAP_* environment (envU32/envStr below), which wins
// over these defaults. The numbers themselves are not security decisions — the
// IDENTITY SPLIT is (each must be nonzero and pairwise distinct); see
// common/sh/runtime.sh ss_ensure_service_users.
const (
	defaultVMMUID    uint32 = 987 // every VMM + the FUSE passthrough daemon
	defaultVMMGID    uint32 = 987
	defaultSharedGID uint32 = 985 // the shared volume group (kvm,985 / api_gid)
)

// EffectiveSeedPollSec is the poll interval to use (0 = the default).
func (p ProvisionConfig) EffectiveSeedPollSec() int {
	if p.SeedPollSec <= 0 {
		return DefaultSeedPollSec
	}
	return p.SeedPollSec
}

// ProvisionConfig is the prov-role (storage plane) configuration.
type ProvisionConfig struct {
	// TemplatesDir is the template store root (layers/ + refs/) on shared
	// storage. Empty = resolved at startup as -overlayfs-templates when
	// that flag is set, else the sibling templates/ directory beside
	// volumes_dir (both roles resolve the SAME store; the exec role
	// reads lowerdirs from it, the prov role writes refs/layers).
	TemplatesDir string `yaml:"templates_dir"`
	// OCIRegistry enables template pull/push/auto-pull (empty = local
	// templates only). The registry egress lives on THIS host — gateway
	// hosts never touch it.
	OCIRegistry string `yaml:"oci_registry"`
	// Registry credentials for OCIRegistry (all optional; empty = anonymous).
	// Basic auth (username/password) wins over the bearer token when both are
	// set; the TLS pair/CA configure the transport INDEPENDENTLY of the
	// credential (basic + private CA, token + mTLS, CA-only all work).
	// No secrets in Defaults() by design — validation refuses any credential
	// without oci_registry, and a cert without its key.
	RegistryUsername string `yaml:"registry_username"`
	RegistryPassword string `yaml:"registry_password"`
	RegistryToken    string `yaml:"registry_token"`
	RegistryCert     string `yaml:"registry_cert"`
	RegistryKey      string `yaml:"registry_key"`
	RegistryCA       string `yaml:"registry_ca"`
	// VolumeSeed is the deployment's volume-name seed (hex or base64, >= 32
	// bytes decoded; generate with `openssl rand -hex 32`). REQUIRED for the
	// prov role: the on-disk name of a sandfs volume is
	// volname.Derive(seed, sandfs_id) — see the volname package for why the
	// name must not be guessable. KEEP THIS VALUE OUT OF GROUP-SANDLOT
	// READABLE FILES: the sandvmm identity is in that group, and a leaked seed
	// makes every name guessable again (deploy tooling scopes this config to
	// root:sandprov 0640).
	VolumeSeed string `yaml:"volume_seed"`
	// VolumeSeedNext stages the NEXT generation for a rotation: with it set,
	// volume operations resolve in both generations (so a partially rotated
	// tree keeps working) and creation is refused until the rotation is
	// promoted. Empty = no rotation staged.
	VolumeSeedNext string `yaml:"volume_seed_next"`
	// VolumeSeedFile reads the current seed from a file instead of the inline
	// value (k8s mounts it from a Secret; the file form keeps the seed out of
	// ConfigMaps and out of any argv). Same for VolumeSeedNextFile. Setting
	// both the inline value and the file for one generation is refused as
	// ambiguous rather than silently preferring one.
	VolumeSeedFile     string `yaml:"volume_seed_file"`
	VolumeSeedNextFile string `yaml:"volume_seed_next_file"`
	// SeedPollSec is how often the provision instance RE-READS its seed
	// sources, in seconds. fsnotify covers local writes (tmpfs, credential
	// dirs, Secret volume symlink swaps) within the 200ms debounce; the poll is
	// what still notices a change on filesystems where inotify never fires
	// (a remote NFS write) — the content compare makes a poll that finds
	// nothing free of side effects. 0 = the default; must be >= 1.
	SeedPollSec int `yaml:"seed_poll_sec"`
	// QuotaStampCmd is the storage plane's quota hook, run once per freshly
	// seeded volume as `<cmd> <sandfs-id>` (argv) with the volume path on
	// stdin as one line (the path is the seed-derived tenant name and must
	// not travel in world-readable argv; exit 0 = stamped, failure refuses
	// the create — see provision/volume/quota.go for the contract). EMPTY
	// (default) = stamping disabled; non-empty must be an ABSOLUTE path.
	// Restart-required (not one of the hot-reloadable volume_seed* keys).
	// The concrete implementation belongs to the storage operator (CephFS
	// xattr / XFS project ID / external quota manager): a quota is only
	// enforceable where every write lands, which is the storage system,
	// never a sandswap layer.
	QuotaStampCmd string `yaml:"quota_stamp_cmd"`
	// FlatTemplatesDir is scanned at startup for local flat templates
	// (directories of files). Empty = no scan.
	FlatTemplatesDir string `yaml:"flat_templates_dir"`
	// MaxConcurrentOps bounds concurrently executing provision commands.
	// Provisioning moves GBs (OCI stream-extract); 2 keeps a host responsive.
	MaxConcurrentOps int `yaml:"max_concurrent_ops"`
	// DefaultDeadlineSec bounds one op when the gateway sends no deadline.
	DefaultDeadlineSec int `yaml:"default_deadline_sec"`
	// ReconnectSec is the prov connection recycle interval: the stream is
	// closed and re-dialed at this age (±20% jitter) so a multi-address
	// gateway list re-spreads and a revived gateway recovers its share of
	// instances without any coordination. 0 = 300s. Exec connections are
	// sticky (ownership) and NEVER recycled.
	ReconnectSec int `yaml:"reconnect_sec"`
	// MaxSparseBytes caps one file's APPARENT size when SaveAsTemplate copies
	// a tenant volume into a template layer. A sparse file's hole is
	// materialized as zeros host-side, so without a cap one file API write at
	// a huge offset can fill shared storage. 0 = the built-in default
	// (8 GiB). Restart-required.
	MaxSparseBytes int64 `yaml:"max_sparse_bytes"`
}

// Defaults returns a SandlotConfig populated with built-in defaults.
func Defaults() SandlotConfig {
	return SandlotConfig{
		GatewayAddr: DefaultGatewayAddr,
		NodeID:      "",
		VMMBinary:   DefaultVMMBinary,
		MicroVM: MicroVMConfig{
			Kernel:          DefaultKernelPath,
			Initramfs:       DefaultInitramfsPath,
			DefaultVCPUs:    DefaultVCPUs,
			DefaultMemoryMB: DefaultMemoryMB,
			VolumesDir:      DefaultVolumesDir,
			// Dedicated sandvmm identity. Defaults stay contract-pinned
			// (uid/gid 987, shared group 985) for fleet uniformity, but the
			// numbers are CONFIGURABLE: hosts whose slots are occupied by
			// foreign accounts resolve differently (common/sh/runtime.sh
			// ss_ensure_service_users adopts/auto-picks, then exports these
			// SANDSWAP_* env vars into the service environment). Env wins
			// over the pinned default; an explicit YAML microvm.vmm_uid
			// still wins over both (config file beats defaults). "kvm"
			// resolves per-host.
			VMMUid:     envU32("SANDSWAP_VMM_UID", defaultVMMUID),
			VMMGid:     envU32("SANDSWAP_VMM_GID", defaultVMMGID),
			VMMGroups:  envStr("SANDSWAP_VMM_GROUPS", "kvm,"+strconv.FormatUint(uint64(defaultSharedGID), 10)),
			APIGid:     envU32("SANDSWAP_API_GID", defaultSharedGID),
			VMMSeccomp: "true",
			// The canonical VMM API socket is authenticated by DEFAULT: a
			// 32-byte per-VM token + challenge preface on every connection.
			// DAC + --api-allowed-uid alone put the API behind a single uid
			// boundary, so anything running as the sandvmm identity (the FUSE
			// passthrough daemon above all) could drive VM lifecycle and
			// set-fs. Explicit `vmm_api_auth: false` / `-vmm-api-auth=false`
			// remains for test tooling that must drive the socket directly.
			VMMAPIAuth: true,
			// Guest free-wipe posture default: OFF (see MicroVMConfig.InitOnFree).
			// The bool's zero value carries it; listed so the default is
			// discoverable next to the other posture pins.
			InitOnFree: false,
		},
		Specs: map[string]SpecEntry{
			// Spec defaults sized for bare-metal deployment: vCPUs are oversubscribed
			// compute (cheap to allocate generously), memory is the hard constraint.
			// exec_slots scales with memory (a full sync exec buffers up to ~2x
			// max_body_len of output). Nested-virtualization hosts override these
			// down via -config.
			"small":  {VCPUs: 2, MemoryMB: 256, ExecSlots: 3},
			"medium": {VCPUs: 4, MemoryMB: 1024, ExecSlots: 4},
			"large":  {VCPUs: 8, MemoryMB: 2048, ExecSlots: 5},
		},
		Pool: "",
		Concurrency: ConcurrencyConfig{
			VMCreate:  DefaultVMCreateConcurrency,
			VMDestroy: DefaultVMDestroyConcurrency,
		},
		Recycle: RecycleConfig{
			MaxUses:           DefaultMaxUses,
			MaxMounts:         10000,
			MaxDistinctAgents: 300,
			AffinityVMs:       3,
			MemPercent:        DefaultRecycleMemPercent,
			MemAbsMB:          DefaultRecycleMemAbsMB,
			MinIdleFloorFrac:  DefaultMinIdleFloorFrac,
		},
		Resilience: ResilienceConfig{
			ToleranceSec:       DefaultToleranceSec,
			CleanupSec:         DefaultCleanupSec,
			WardenCountdownSec: DefaultWardenCountdownSec,
			IsolationSec:       DefaultIsolationSec,
		},
		Roles: []string{"exec"},
		Provision: ProvisionConfig{
			// TemplatesDir defaults empty: resolved at startup as
			// overlayfs_templates (when set) or the sibling templates/
			// directory beside volumes_dir (same filesystem).
			MaxConcurrentOps:   DefaultMaxProvisionOps,
			DefaultDeadlineSec: DefaultProvisionDeadlineSec,
			ReconnectSec:       DefaultProvisionReconnectSec,
			SeedPollSec:        DefaultSeedPollSec,
			MaxSparseBytes:     DefaultMaxSparseBytes,
		},
		Network: NetworkConfig{
			Backend:        DefaultNetworkBackend,
			V6Prefix:       DefaultV6Prefix,
			Bridge:         DefaultNetworkBridge,
			Subnet:         DefaultNetworkSubnet,
			Gateway:        DefaultNetworkGateway,
			DNS:            DefaultNetworkDNS,
			EgressBaseline: DefaultEgressBaseline,
			VMToVM:         DefaultVMToVM,
		},
		Instance: InstanceConfig{
			BaseDir:       "/run/sandswap",
			CIDRangeStart: 3,
			CIDRangeEnd:   0,
		},
		VMMode:          DefaultVMMode,
		BoxoutSocket:    DefaultBoxoutSocket,
		BoxoutTokenFile: "",
		SetFsTransport:  DefaultSetFsTransport,
		Stream: StreamConfig{
			SendBufferSize:        config.DefaultStreamSendBuffer,
			RecvBufferSize:        config.DefaultStreamRecvBuffer,
			MaxConcurrentCommands: config.DefaultStreamMaxConcurrentCommands,
			WriteTimeoutSec:       config.DefaultStreamWriteTimeoutSec,
			InitialWindow:         config.DefaultStreamInitialWindowMB << 20,
			InitialConnWindow:     config.DefaultStreamConnWindowMB << 20,
			MaxMsgSize:            config.DefaultStreamMaxMsgSizeMB << 20,
		},
	}
}

// parseRolesFlag splits the -roles comma list ("exec,prov") into entries.
func parseRolesFlag(s string) []string {
	var out []string
	for _, tok := range strings.Split(s, ",") {
		tok = strings.TrimSpace(tok)
		if tok != "" {
			out = append(out, tok)
		}
	}
	return out
}

// classifyField returns whether a config field change is hot-reloadable or
// requires a restart.
func classifyField(name string) config.ChangeClass {
	switch {
	// microvm.*: hot-reload (affects new VMs only)
	case name == "microvm.kernel", name == "microvm.initramfs",
		name == "microvm.default_vcpus", name == "microvm.default_memory_mb":
		return config.ChangeHotReload
	// pool: hot-reload (adjust pool target)
	case name == "pool":
		return config.ChangeHotReload
	// recycle.*: hot-reload
	case name == "recycle.max_uses", name == "recycle.max_mounts", name == "recycle.max_distinct_agents", name == "recycle.affinity_vms", name == "recycle.mem_percent",
		name == "recycle.mem_abs_mb", name == "recycle.min_idle_floor_frac":
		return config.ChangeHotReload
	// provision.volume_seed*: hot-reload — the rotation window is opened by
	// staging a next generation in the file (no restart, so the fleet keeps its
	// stream connections through the window). The namer enforces which
	// transitions are legal (stage while unchanged; promote staged -> current);
	// ApplySeeds refuses anything else and says so.
	case name == "provision.volume_seed", name == "provision.volume_seed_file",
		name == "provision.volume_seed_next", name == "provision.volume_seed_next_file":
		return config.ChangeHotReload
	// Everything else: restart-required
	default:
		return config.ChangeRestartRequired
	}
}

// Diff compares two SandlotConfig values and returns a ChangeSet.
func (old SandlotConfig) Diff(new SandlotConfig) config.ChangeSet {
	return config.DiffConfigs(old, new, "", classifyField)
}

// LoadFromFile reads and parses a YAML config file.
func LoadFromFile(path string) (SandlotConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return SandlotConfig{}, fmt.Errorf("read config file: %w", err)
	}
	cfg := Defaults()
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true) // strict: a dead/misspelled key is a startup error, not a silent no-op (dns/config.go's lesson)
	if err := dec.Decode(&cfg); err != nil {
		return SandlotConfig{}, fmt.Errorf("parse config file: %w", err)
	}
	// Seed file paths are relative to the CONFIG (how the deploy scripts write
	// them) — resolved here so every consumer, this process and the tools
	// alike, sees the same absolute path. See ResolveSeedFilePaths.
	cfg.ResolveSeedFilePaths(filepath.Dir(path))
	return cfg, nil
}

// SandlotFlags holds the parsed CLI flag values.
type SandlotFlags struct {
	ConfigPath string

	GatewayAddr          string
	NodeID               string
	Kernel               string
	Initramfs            string
	DefaultVCPUs         int
	DefaultMemMB         int
	VMMBinary            string
	VolumesDir           string
	TemplatesDir         string
	PoolSpec             string
	TLSCert              string
	TLSKey               string
	TLSCA                string
	NetworkBackend       string
	NetworkBridge        string
	NetworkSubnet        string
	NetworkGateway       string
	NetworkDNS           string
	NetworkBindBackend   string // -binding-backend
	NetworkBindPath      string // -binding-path
	EgressBaseline       string // -egress-baseline
	VMToVM               string // -vm-to-vm-policy
	V6Prefix             string // -network-v6-prefix
	IIDTemplate          string // -iid-template
	RequireEgressBinding bool   // -require-egress-binding
	MaxUses              int
	RecycleMemPct        int
	RecycleMemAbs        int
	MinIdleFloorFrac     float64 // -min-idle-floor-frac
	VMCreateConcurrency  int     // -vm-create-concurrency
	VMDestroyConcurrency int     // -vm-destroy-concurrency
	VMMode               string
	BoxoutSocket         string
	BoxoutTokenFile      string // -boxout-token-file
	SetFsTransport       string // -setfs-transport
	VMMAPIAuth           bool   // -vmm-api-auth (optional canonical-VMM token handshake; default off)

	// Roles + provision role (restart-required)
	Roles                     string // -roles ("exec", "prov", "exec,prov")
	ProvisionTemplatesDir     string // -templates-dir
	ProvisionOCIRegistry      string // -oci-registry
	ProvisionRegistryUsername string // -registry-username
	ProvisionRegistryPassword string // -registry-password
	ProvisionRegistryToken    string // -registry-token
	ProvisionRegistryCert     string // -registry-cert
	ProvisionRegistryKey      string // -registry-key
	ProvisionRegistryCA       string // -registry-ca
	ProvisionFlatTemplatesDir string // -flat-templates
	// -volume-seed-file / -volume-seed-next-file: paths to the seed files (the
	// seed VALUE never travels as a flag — argv is world-readable).
	ProvisionVolumeSeedFile     string
	ProvisionVolumeSeedNextFile string
	ProvisionMaxConcurrentOps   int // -max-provision-ops
	ProvisionDeadlineSec        int // -provision-deadline-sec
	ProvisionReconnectSec       int // -provision-reconnect-sec

	// Stream concurrency / transport
	StreamSendBuffer      int // -stream-send-buffer
	StreamRecvBuffer      int // -stream-recv-buffer
	MaxConcurrentCommands int // -max-concurrent-commands
	StreamWriteTimeout    int // -stream-write-timeout-sec
	StreamInitialWindow   int // -stream-initial-window-mb
	StreamConnWindow      int // -stream-conn-window-mb
	StreamMaxMsgSize      int // -stream-max-msg-size-mb

	// Resilience timings (tolerance-first; all restart-required)
	ToleranceSec       int // -tolerance-sec
	CleanupSec         int // -cleanup-sec
	WardenCountdownSec int // -warden-countdown-sec
	IsolationSec       int // -isolation-sec

	// Warden cmdline overrides (microvm.* YAML keys; RESTART-REQUIRED —
	// deliberately not hot-reloadable: an online warden_log=debug flip would
	// enable UART-taxed debug logging on every new VM at fleet scale, so the
	// restart is the safety gate. classifyField keeps them restart-required and
	// a microvm.* hot-reload preserves these startup values.)
	WardenMaxExecTimeoutSec int    // -warden-max-exec-timeout-sec
	WardenLogLevel          string // -warden-log
	InitOnFree              bool   // -init-on-free
}

// ApplyFlagOverrides merges explicitly-set CLI flags over the config file values.
// SetFlagReapplier installs the startup flag-override applier (see the
// reapplier field). Exported for cmd, which owns the parsed flags.
// wardenMaxExecTimeoutCeiling bounds the warden's exec timeout. A value above
// the warden countdown lets a max-length exec outlive the last-resort mount
// release; 3600 s (1 h) is far above any legitimate exec and keeps the
// int→uint32 cast well inside range.
const wardenMaxExecTimeoutCeiling = 3600

func (cfg *SandlotConfig) SetFlagReapplier(fn func(*SandlotConfig)) { cfg.reapplier = fn }

// ReapplyStartupFlags copies the startup CLI-flag overrides recorded on src
// onto dst (a freshly decoded config), returning the applier's refusal. The
// applier must come from the STARTUP config — a decoded config carries none.
func ReapplyStartupFlags(src, dst *SandlotConfig) error {
	if src.reapplier == nil {
		return nil
	}
	dst.applyErr = nil
	src.reapplier(dst)
	return dst.applyErr
}

// ApplyError returns the refusal recorded by the last ApplyFlagOverrides /
// ReapplyStartupFlags call (nil when the flags were representable).
func (cfg *SandlotConfig) ApplyError() error { return cfg.applyErr }

func (cfg *SandlotConfig) ApplyFlagOverrides(flags *SandlotFlags, explicitSet map[string]bool) {
	if explicitSet["gateway-addr"] {
		cfg.GatewayAddr = flags.GatewayAddr
	}
	if explicitSet["node-id"] {
		cfg.NodeID = flags.NodeID
	}
	if explicitSet["kernel"] {
		cfg.MicroVM.Kernel = flags.Kernel
	}
	if explicitSet["initramfs"] {
		cfg.MicroVM.Initramfs = flags.Initramfs
	}
	if explicitSet["default-vcpus"] {
		// Refuse the negative BEFORE the int→uint cast: the wrap is silent and
		// Validate() only sees the already-wrapped value (-1 → 4294967295
		// passes a `>= 1` check), which is exactly what this guard exists for.
		if flags.DefaultVCPUs < 1 {
			cfg.applyErr = fmt.Errorf("invalid -default-vcpus %d (must be >= 1)", flags.DefaultVCPUs)
			return
		}
		cfg.MicroVM.DefaultVCPUs = uint32(flags.DefaultVCPUs)
	}
	if explicitSet["default-memory"] {
		if flags.DefaultMemMB < MinBootMemoryMB {
			cfg.applyErr = fmt.Errorf("invalid -default-memory %d (must be >= %d MB)", flags.DefaultMemMB, MinBootMemoryMB)
			return
		}
		cfg.MicroVM.DefaultMemoryMB = uint64(flags.DefaultMemMB)
	}
	if explicitSet["vmm-binary"] {
		cfg.VMMBinary = flags.VMMBinary
	}
	if explicitSet["volumes-dir"] {
		cfg.MicroVM.VolumesDir = flags.VolumesDir
	}
	if explicitSet["overlayfs-templates"] {
		cfg.MicroVM.OverlayFSTemplates = flags.TemplatesDir
	}
	if explicitSet["warden-max-exec-timeout-sec"] {
		// -1 is NOT "unlimited" here (that sentinel belongs to -max-uses): the
		// wrap would set 4294967295, and the warden clamps its countdown UP to
		// the max exec timeout — silently disabling the last-resort mount
		// release for every new VM (resilience red line).
		if flags.WardenMaxExecTimeoutSec < 0 {
			cfg.applyErr = fmt.Errorf("invalid -warden-max-exec-timeout-sec %d (must be >= 0; 0 = warden default)", flags.WardenMaxExecTimeoutSec)
			return
		}
		if flags.WardenMaxExecTimeoutSec > wardenMaxExecTimeoutCeiling {
			// Upper bound too: the int→uint32 cast wraps 4294967296 to 0
			// ("warden default") and an absurd-but-representable value makes the
			// warden clamp its countdown UP to it — the resilience red line.
			cfg.applyErr = fmt.Errorf("invalid -warden-max-exec-timeout-sec %d (must be <= %d)", flags.WardenMaxExecTimeoutSec, wardenMaxExecTimeoutCeiling)
			return
		}
		cfg.MicroVM.WardenMaxExecTimeoutSec = uint32(flags.WardenMaxExecTimeoutSec)
	}
	if explicitSet["warden-log"] {
		cfg.MicroVM.WardenLogLevel = flags.WardenLogLevel
	}
	if explicitSet["init-on-free"] {
		cfg.MicroVM.InitOnFree = flags.InitOnFree
	}
	if explicitSet["pool"] {
		cfg.Pool = flags.PoolSpec
	}
	if explicitSet["tls-cert"] {
		cfg.TLS.Cert = flags.TLSCert
	}
	if explicitSet["tls-key"] {
		cfg.TLS.Key = flags.TLSKey
	}
	if explicitSet["tls-ca"] {
		cfg.TLS.CA = flags.TLSCA
	}
	if explicitSet["network-backend"] {
		cfg.Network.Backend = flags.NetworkBackend
	}
	if explicitSet["network-bridge"] {
		cfg.Network.Bridge = flags.NetworkBridge
	}
	if explicitSet["network-subnet"] {
		cfg.Network.Subnet = flags.NetworkSubnet
	}
	if explicitSet["network-gateway"] {
		cfg.Network.Gateway = flags.NetworkGateway
	}
	if explicitSet["network-dns"] {
		cfg.Network.DNS = flags.NetworkDNS
	}
	if explicitSet["binding-backend"] {
		cfg.Network.BindBackend = flags.NetworkBindBackend
	}
	if explicitSet["binding-path"] {
		cfg.Network.BindPath = flags.NetworkBindPath
	}
	if explicitSet["egress-baseline"] {
		cfg.Network.EgressBaseline = flags.EgressBaseline
	}
	if explicitSet["vm-to-vm-policy"] {
		cfg.Network.VMToVM = flags.VMToVM
	}
	if explicitSet["network-v6-prefix"] {
		cfg.Network.V6Prefix = flags.V6Prefix
	}
	if explicitSet["iid-template"] {
		cfg.Network.IIDTemplate = flags.IIDTemplate
	}
	if explicitSet["require-egress-binding"] {
		cfg.Network.RequireEgressBinding = flags.RequireEgressBinding
	}
	if explicitSet["max-uses"] {
		cfg.Recycle.MaxUses = flags.MaxUses
	}
	if explicitSet["recycle-mem-percent"] {
		cfg.Recycle.MemPercent = flags.RecycleMemPct
	}
	if explicitSet["recycle-mem-abs-mb"] {
		cfg.Recycle.MemAbsMB = flags.RecycleMemAbs
	}
	if explicitSet["min-idle-floor-frac"] {
		cfg.Recycle.MinIdleFloorFrac = flags.MinIdleFloorFrac
	}
	if explicitSet["vm-create-concurrency"] {
		cfg.Concurrency.VMCreate = flags.VMCreateConcurrency
	}
	if explicitSet["vm-destroy-concurrency"] {
		cfg.Concurrency.VMDestroy = flags.VMDestroyConcurrency
	}
	if explicitSet["vm-mode"] {
		cfg.VMMode = flags.VMMode
	}
	if explicitSet["setfs-transport"] {
		cfg.SetFsTransport = flags.SetFsTransport
	}
	if explicitSet["vmm-api-auth"] {
		cfg.MicroVM.VMMAPIAuth = flags.VMMAPIAuth
	}
	if explicitSet["boxout-socket"] {
		cfg.BoxoutSocket = flags.BoxoutSocket
	}
	if explicitSet["boxout-token-file"] {
		cfg.BoxoutTokenFile = flags.BoxoutTokenFile
	}
	if explicitSet["roles"] {
		cfg.Roles = parseRolesFlag(flags.Roles)
	}
	if explicitSet["templates-dir"] {
		cfg.Provision.TemplatesDir = flags.ProvisionTemplatesDir
	}
	if explicitSet["oci-registry"] {
		cfg.Provision.OCIRegistry = flags.ProvisionOCIRegistry
	}
	if explicitSet["registry-username"] {
		cfg.Provision.RegistryUsername = flags.ProvisionRegistryUsername
	}
	if explicitSet["registry-password"] {
		cfg.Provision.RegistryPassword = flags.ProvisionRegistryPassword
	}
	if explicitSet["registry-token"] {
		cfg.Provision.RegistryToken = flags.ProvisionRegistryToken
	}
	if explicitSet["registry-cert"] {
		cfg.Provision.RegistryCert = flags.ProvisionRegistryCert
	}
	if explicitSet["registry-key"] {
		cfg.Provision.RegistryKey = flags.ProvisionRegistryKey
	}
	if explicitSet["registry-ca"] {
		cfg.Provision.RegistryCA = flags.ProvisionRegistryCA
	}
	if explicitSet["flat-templates"] {
		cfg.Provision.FlatTemplatesDir = flags.ProvisionFlatTemplatesDir
	}
	// A seed-file flag is re-pinned on EVERY reload (ReapplyStartupFlags), so a
	// config file that also names one would be silently shadowed: a rotation
	// promoted in the file would never reach the namer, and the live instance
	// would keep serving the old generation while the operator believes the
	// promotion landed. Refuse the ambiguity instead of picking silently.
	if explicitSet["volume-seed-file"] {
		if cfg.Provision.VolumeSeedFile != "" {
			cfg.applyErr = fmt.Errorf("-volume-seed-file and provision.volume_seed_file are both set (%s vs %s) — pick one: the flag is re-pinned on every reload, so the config value would be silently ignored",
				flags.ProvisionVolumeSeedFile, cfg.Provision.VolumeSeedFile)
		} else {
			cfg.Provision.VolumeSeedFile = flags.ProvisionVolumeSeedFile
		}
	}
	if explicitSet["volume-seed-next-file"] {
		if cfg.Provision.VolumeSeedNextFile != "" {
			cfg.applyErr = fmt.Errorf("-volume-seed-next-file and provision.volume_seed_next_file are both set (%s vs %s) — pick one: the flag is re-pinned on every reload, so the config value would be silently ignored",
				flags.ProvisionVolumeSeedNextFile, cfg.Provision.VolumeSeedNextFile)
		} else {
			cfg.Provision.VolumeSeedNextFile = flags.ProvisionVolumeSeedNextFile
		}
	}
	if explicitSet["max-provision-ops"] {
		cfg.Provision.MaxConcurrentOps = flags.ProvisionMaxConcurrentOps
	}
	if explicitSet["provision-deadline-sec"] {
		cfg.Provision.DefaultDeadlineSec = flags.ProvisionDeadlineSec
	}
	if explicitSet["provision-reconnect-sec"] {
		cfg.Provision.ReconnectSec = flags.ProvisionReconnectSec
	}
	// Stream concurrency / transport (MB-valued flags convert to bytes)
	if explicitSet["stream-send-buffer"] {
		cfg.Stream.SendBufferSize = flags.StreamSendBuffer
	}
	if explicitSet["stream-recv-buffer"] {
		cfg.Stream.RecvBufferSize = flags.StreamRecvBuffer
	}
	if explicitSet["max-concurrent-commands"] {
		cfg.Stream.MaxConcurrentCommands = flags.MaxConcurrentCommands
	}
	if explicitSet["stream-write-timeout-sec"] {
		cfg.Stream.WriteTimeoutSec = flags.StreamWriteTimeout
	}
	if explicitSet["stream-initial-window-mb"] {
		cfg.Stream.InitialWindow = flags.StreamInitialWindow << 20
	}
	if explicitSet["stream-conn-window-mb"] {
		cfg.Stream.InitialConnWindow = flags.StreamConnWindow << 20
	}
	if explicitSet["stream-max-msg-size-mb"] {
		cfg.Stream.MaxMsgSize = flags.StreamMaxMsgSize << 20
	}
	if explicitSet["tolerance-sec"] {
		cfg.Resilience.ToleranceSec = flags.ToleranceSec
	}
	if explicitSet["cleanup-sec"] {
		cfg.Resilience.CleanupSec = flags.CleanupSec
	}
	if explicitSet["warden-countdown-sec"] {
		cfg.Resilience.WardenCountdownSec = flags.WardenCountdownSec
	}
	if explicitSet["isolation-sec"] {
		cfg.Resilience.IsolationSec = flags.IsolationSec
	}
}

// envU32 returns the SANDSWAP_* environment override of `def` when set to a
// valid u32, else `def`. Used by Defaults() so the deployer's RESOLVED
// service identities (occupied-slot adoption/auto-pick in
// common/sh/runtime.sh) flow into microvm.vmm_uid/vmm_gid/api_gid without a
// per-host YAML. Malformed values fall back to the default (the deployer
// always exports numbers; a malformed env is a bug to surface at Validate,
// not a startup crash).
func envU32(key string, def uint32) uint32 {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.ParseUint(v, 10, 32); err == nil {
			return uint32(n)
		}
	}
	return def
}

// envStr is envU32's string twin.
func envStr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

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
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"sandlot/vmm"
)

// defaultSandboxRoot is the default on-disk root of per-VM sandbox directories.
// Overridden by Handler.SandboxRoot when multi-instance mode is active.
const defaultSandboxRoot = "/run/sandswap/vm"

// errNoState indicates a sandbox dir has no state.json (either never written,
// e.g. sandlot crashed before the post-Launch write, or already removed).
var errNoState = errors.New("no state.json")

// stateFormatVersion is the state.json format version this binary writes and
// accepts; see persistedState.Version for the upgrade contract.
const stateFormatVersion = 1

// persistedState is the per-VM record written to <sandboxDir>/state.json after
// a successful Launch, so the VM can be re-adopted after a sandlot restart. It
// carries exactly what re-adoption needs and cannot be derived from the API
// socket alone: the guest vsock CID, the sandvmm PID (for force-kill of
// orphans), and the full launch config including the network spec (guest
// IP/TAP/MAC must be re-registered, not re-Provision-ed, or the live TAP would
// be destroyed).
type persistedState struct {
	// Version is the state.json FORMAT version (write side always emits 1).
	// v1 is the only format; a future format bump must keep old binaries
	// failing SAFE: the loader below treats an unknown MAJOR version as
	// no-state (corrupt), so re-adopt cleans the dir and destroy-and-replaces
	// the survivor instead of misreading fields. Forward additions within v1
	// use omitempty fields (old readers ignore them via Go json).
	Version    int           `json:"version"`
	VMID       string        `json:"vm_id"`
	CID        uint32        `json:"cid"`
	PID        int           `json:"pid"`
	SandboxDir string        `json:"sandbox_dir"`
	APISocket  string        `json:"api_socket"`
	CreatedAt  time.Time     `json:"created_at"`
	Config     persistedCfg  `json:"config"`
	NetSpec    *persistedNet `json:"net_spec,omitempty"`
	// SpecID is the VM spec ("small"/"medium"/"large"). Persisted so re-adopted
	// VMs count toward their -pool spec target in preCreateVMs - without it,
	// re-adopted VMs have SpecID="" and preCreateVMs creates the full target on
	// every restart, growing the pool by `target` each restart.
	SpecID string `json:"spec_id,omitempty"`
	// Reuse accounting: cold-mount generations, the generation last counted,
	// and the bounded distinct-agent set. Persisted so a restart cannot reset
	// the recycle budget.
	MountCount      uint64   `json:"mount_count,omitempty"`
	MountCountedGen int64    `json:"mount_counted_gen,omitempty"`
	DistinctAgents  []string `json:"distinct_agents,omitempty"`
}

type persistedCfg struct {
	VCPUs         uint32 `json:"vcpus"`
	MemoryMB      uint64 `json:"memory_mb"`
	KernelPath    string `json:"kernel_path"`
	InitramfsPath string `json:"initramfs_path"`
	KernelCmdline string `json:"kernel_cmdline"`
	VMMBinary     string `json:"vmm_binary"`
	VolumesDir    string `json:"volumes_dir"`
	// WardenSessionKey authenticates every raw warden frame for this VM. It
	// is per-VM, 64 hex characters, and lives only in the owner-only state
	// directory (never in logs).
	WardenSessionKey string `json:"warden_session_key,omitempty"`
}

type persistedNet struct {
	GuestIP  string   `json:"guest_ip"`
	Prefix   int      `json:"prefix"`
	Gateway  string   `json:"gateway"`
	GuestIP6 string   `json:"guest_ip6,omitempty"`
	Prefix6  int      `json:"prefix6,omitempty"`
	Gateway6 string   `json:"gateway6,omitempty"`
	DNS      []string `json:"dns"`
	MAC      string   `json:"mac"`
	TAP      string   `json:"tap"`
	MTU      int      `json:"mtu"`
}

// HasNetwork reports whether the persisted spec carries any guest addressing
// (v4 or v6) — family-agnostic mirror of vmm.VMNetSpec.HasNetwork.
func (p *persistedNet) HasNetwork() bool {
	if p == nil {
		return false
	}
	return p.GuestIP != "" || p.GuestIP6 != ""
}

// defaultStateRoot is the private per-VM state root. It is DELIBERATELY
// outside the sandbox tree: the sandbox dir is group-writable and shared with
// sandvmm, and a group member can rename or replace a child entry regardless
// of that child's own mode. State therefore lives in an instance-scoped
// directory only the writer identity can traverse.
const defaultStateRoot = "/run/sandswap-state"

// StateRootFor maps a sandbox root to the private state root of the same
// instance: /run/sandswap/instance-<id>/vm -> /run/sandswap-state/<id>, the
// default /run/sandswap/vm -> /run/sandswap-state/default. Dev/test roots
// (temporary trees) get a stable per-root tag so concurrent instances stay
// isolated.
func StateRootFor(sandboxRoot string) string {
	clean := filepath.Clean(sandboxRoot)
	parent := filepath.Base(filepath.Dir(clean))
	if filepath.Base(clean) == "vm" {
		if parent == "sandswap" {
			return filepath.Join(defaultStateRoot, "default")
		}
		if strings.HasPrefix(parent, "instance-") && len(parent) > len("instance-") {
			return filepath.Join(defaultStateRoot, strings.TrimPrefix(parent, "instance-"))
		}
		// The documented instance layout is <base_dir>/<instance-id>/vm. Only
		// the STANDARD base dir gets the readable tag: a custom root that
		// merely happens to end in /<name>/vm must hash, or two colocated
		// deployments with the same last component would share state.
		if filepath.Base(filepath.Dir(filepath.Dir(clean))) == "sandswap" && validStateComponent(parent) {
			return filepath.Join(defaultStateRoot, parent)
		}
	}
	// Any other shape (custom deployment roots, tests) is hashed. Using the
	// parent directory name let two colocated instances with roots like
	// /srv/a/tenant/vm and /srv/b/tenant/vm share one state root — mixing
	// state.json (which carries the warden session key) and the instance
	// lock.
	sum := sha256.Sum256([]byte(clean))
	return filepath.Join(defaultStateRoot, "root-"+hex.EncodeToString(sum[:8]))
}

// validStateComponent rejects anything that is not a single, plain path
// component. VM ids and instance tags come from disk-scanned names and config.
func validStateComponent(s string) bool {
	if s == "" || s == "." || s == ".." {
		return false
	}
	return !strings.ContainsRune(s, filepath.Separator) && !strings.ContainsRune(s, 0)
}

// openStateRoot opens (optionally creating) the private state root. The parent
// (/run/sandswap-state) is provisioned by the deploy tooling; boxout (root) can
// create it in a fresh pod. A symlinked root is refused.
func openStateRoot(stateRoot string, create bool) (*os.File, error) {
	if create {
		_ = os.MkdirAll(stateRoot, 0o710)
	}
	fd, err := unix.Open(stateRoot, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), stateRoot), nil
}

// openPrivateStateDir opens (optionally creating) one state component beneath
// an already-open parent with openat2(RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS). The
// component must be owned by THIS writer and is tightened to 0700 on every
// open: a directory squatted by another identity is refused, never used.
func openPrivateStateDir(parentFd int, name string, create bool) (*os.File, error) {
	if !validStateComponent(name) {
		return nil, fmt.Errorf("invalid state path component %q", name)
	}
	if create {
		if err := unix.Mkdirat(parentFd, name, 0o700); err != nil && !errors.Is(err, unix.EEXIST) {
			return nil, fmt.Errorf("mkdir state dir %q: %w", name, err)
		}
	}
	how := unix.OpenHow{
		Flags:   uint64(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC),
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS,
	}
	fd, err := unix.Openat2(parentFd, name, &how)
	if err != nil {
		return nil, &os.PathError{Op: "openat2", Path: name, Err: err}
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		unix.Close(fd)
		return nil, &os.PathError{Op: "fstat", Path: name, Err: err}
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		unix.Close(fd)
		return nil, fmt.Errorf("state component %q is not a directory", name)
	}
	if int(st.Uid) != os.Geteuid() {
		unix.Close(fd)
		return nil, fmt.Errorf("state dir %q is owned by uid %d, not the writer uid %d — refusing to use it", name, st.Uid, os.Geteuid())
	}
	if err := unix.Fchmod(fd, 0o700); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("chmod state dir %q: %w", name, err)
	}
	return os.NewFile(uintptr(fd), name), nil
}

// openStateVMDir opens the per-VM private state directory. The sandbox dir is
// used only to derive the instance tag and the VM id; the state itself never
// lives under it.
func openStateVMDir(sandboxDir string, create bool) (*os.File, *os.File, error) {
	clean := filepath.Clean(sandboxDir)
	vmID := filepath.Base(clean)
	sandboxRoot := filepath.Dir(clean)
	if !validStateComponent(vmID) {
		return nil, nil, fmt.Errorf("invalid VM id %q", vmID)
	}
	rootFd, err := openStateRoot(StateRootFor(sandboxRoot), create)
	if err != nil {
		return nil, nil, err
	}
	vmFd, err := openPrivateStateDir(int(rootFd.Fd()), vmID, create)
	if err != nil {
		rootFd.Close()
		return nil, nil, err
	}
	return rootFd, vmFd, nil
}

// stateTmpPrefix is the temp-file name prefix inside the private state dir.
const stateTmpPrefix = ".state.json."

func randomTmpSuffix() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// writeState atomically writes the VM state to
// <state-root>/<vm-id>/state.json. Every step is fd-relative: the state root
// and the per-VM dir are opened with RESOLVE_NO_SYMLINKS and an owner check,
// the temp file is O_CREAT|O_EXCL|O_NOFOLLOW inside the opened dir, and the
// rename happens between fds — a symlink planted at any name is refused or
// replaced as a link, never followed.
func writeState(s persistedState, sandboxRoot string) error {
	if !isSandswapVMDir(s.SandboxDir, sandboxRoot) {
		return fmt.Errorf("refuse writeState: sandbox dir %q outside %s", s.SandboxDir, sandboxRoot)
	}
	data, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}
	rootFd, vmFd, err := openStateVMDir(s.SandboxDir, true)
	if err != nil {
		return fmt.Errorf("open private state dir: %w", err)
	}
	defer rootFd.Close()
	defer vmFd.Close()

	var tmpName string
	var tmpFd int
	for attempt := 0; attempt < 16; attempt++ {
		tmpName = stateTmpPrefix + randomTmpSuffix()
		tmpFd, err = unix.Openat(int(vmFd.Fd()), tmpName,
			unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
		if errors.Is(err, unix.EEXIST) {
			continue
		}
		break
	}
	if err != nil {
		return fmt.Errorf("create temp state: %w", err)
	}
	tmp := os.NewFile(uintptr(tmpFd), tmpName)
	cleanup := func() { _ = unix.Unlinkat(int(vmFd.Fd()), tmpName, 0) }
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		cleanup()
		return fmt.Errorf("write temp state: %w", err)
	}
	// fsync before rename: on tmpfs this is a near-no-op, but the pattern stays
	// correct if the state root ever moves to disk-backed storage.
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		cleanup()
		return fmt.Errorf("sync temp state: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("close temp state: %w", err)
	}
	if err := unix.Renameat(int(vmFd.Fd()), tmpName, int(vmFd.Fd()), "state.json"); err != nil {
		cleanup()
		return fmt.Errorf("rename state: %w", err)
	}
	return nil
}

// loadState reads and unmarshals a VM's state.json from the private root.
// Returns errNoState (not a hard error) when the file does not exist; a corrupt
// file is treated as no-state too — re-adopt will then clean the dir rather
// than trust garbage. A state.json that is a symlink is treated as no-state
// (never followed).
func loadState(sandboxDir string) (*persistedState, error) {
	rootFd, vmFd, err := openStateVMDir(sandboxDir, false)
	if err != nil {
		if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR) || errors.Is(err, os.ErrNotExist) {
			return nil, errNoState
		}
		return nil, fmt.Errorf("open private state dir: %w", err)
	}
	defer rootFd.Close()
	defer vmFd.Close()

	fd, err := unix.Openat(int(vmFd.Fd()), "state.json", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil, errNoState
		}
		return nil, fmt.Errorf("read state: %w", err)
	}
	f := os.NewFile(uintptr(fd), "state.json")
	defer f.Close()
	// Bounded read: state.json is a small record; an oversized/planted file
	// must not allocate unboundedly. 1 MiB is far above any real one.
	data, err := io.ReadAll(io.LimitReader(f, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read state: %w", err)
	}
	var s persistedState
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("unmarshal state: %w", err)
	}
	if s.Version > stateFormatVersion {
		return nil, fmt.Errorf("state format version %d > supported %d (future format; treating as no-state so re-adopt replaces the VM)", s.Version, stateFormatVersion)
	}
	return &s, nil
}

// removeState deletes state.json (fd-relative; unlinkat never follows a
// symlink) and drops the per-VM dir when it is empty. It does NOT touch the
// sandbox dir.
func removeState(sandboxDir string) {
	if sandboxDir == "" {
		return
	}
	rootFd, vmFd, err := openStateVMDir(sandboxDir, false)
	if err != nil {
		return
	}
	_ = unix.Unlinkat(int(vmFd.Fd()), "state.json", 0)
	vmFd.Close()
	// Best effort: only state.json ever lives in this dir, so it is normally
	// empty now. A non-empty dir is left for the operator to inspect.
	_ = unix.Unlinkat(int(rootFd.Fd()), filepath.Base(filepath.Clean(sandboxDir)), unix.AT_REMOVEDIR)
	rootFd.Close()
}

// removeSandboxDir removes the whole per-VM sandbox directory. The prefix check
// is a guardrail: a zero/relative/escaped SandboxDir must never reach
// RemoveAll, since re-adopt builds paths from disk-scanned dir names.
func removeSandboxDir(sandboxDir, sandboxRoot string) {
	if sandboxRoot == "" {
		sandboxRoot = filepath.Dir(sandboxDir)
	}
	if !isSandswapVMDir(sandboxDir, sandboxRoot) {
		return
	}
	rootFd, err := unix.Open(sandboxRoot, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		// A symlinked/substituted root means the path no longer names the
		// sandbox tree; refuse rather than fall back to RemoveAll.
		return
	}
	defer unix.Close(rootFd)
	rel, err := filepath.Rel(sandboxRoot, sandboxDir)
	if err != nil || rel == "." || strings.HasPrefix(rel, "..") {
		return
	}
	// Pin the target with openat2: RESOLVE_BENEATH forbids escaping the root,
	// RESOLVE_NO_SYMLINKS forbids a swapped entry at every component.
	tfd, err := unix.Openat2(rootFd, rel, &unix.OpenHow{
		Flags:   uint64(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC),
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS,
	})
	if err != nil {
		return
	}
	unix.Close(tfd)
	// Quarantine rename (same parent) keeps the recursive delete off the
	// attacker-controlled historical path; if the rename is impossible (e.g.
	// a mount point), delete through the pinned root fd instead.
	trash := fmt.Sprintf(".trash-%d-%d", os.Getpid(), time.Now().UnixNano())
	if err := unix.Renameat(rootFd, rel, rootFd, trash); err != nil {
		removeChildAt(rootFd, rel)
		return
	}
	removeChildAt(rootFd, trash)
}

// removeChildAt deletes one entry under parentFd without following symlinks:
// directories are opened with O_NOFOLLOW and recursed; everything else is
// unlinked. Deletion is best-effort (permissions, mounts) and never follows a
// planted link.
func removeChildAt(parentFd int, name string) {
	fd, err := unix.Openat(parentFd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		_ = unix.Unlinkat(parentFd, name, 0)
		return
	}
	removeDirContents(fd)
	_ = unix.Unlinkat(parentFd, name, unix.AT_REMOVEDIR)
}

func removeDirContents(fd int) {
	f := os.NewFile(uintptr(fd), "sandbox-dir")
	if f == nil {
		unix.Close(fd)
		return
	}
	entries, err := f.ReadDir(-1)
	if err != nil {
		f.Close()
		return
	}
	for _, e := range entries {
		removeChildAt(int(f.Fd()), e.Name())
	}
	f.Close()
}

// isSandswapVMDir reports whether p is a real path under the sandswap VM root.
// Empty, relative, or escaped paths are rejected — this guards RemoveAll from a
// bad/empty SandboxDir built out of disk-scanned dir names during re-adopt.
func isSandswapVMDir(p, sandboxRoot string) bool {
	if p == "" {
		return false
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(sandboxRoot, abs)
	if err != nil {
		return false
	}
	// rel starts with ".." => escaped outside the VM root; "." => the root
	// itself (not a per-VM dir). Both rejected.
	if rel == "." || strings.HasPrefix(rel, "..") {
		return false
	}
	return true
}

// --- conversions between persistedState and vmm.Config / vmm.VMNetSpec ---

func stateFromConfig(vmID string, cfg vmm.Config, apiSocket string, pid int, specID string) persistedState {
	s := persistedState{
		Version:    stateFormatVersion,
		VMID:       vmID,
		CID:        cfg.GuestCID,
		PID:        pid,
		SandboxDir: cfg.SandboxDir,
		APISocket:  apiSocket,
		CreatedAt:  time.Now(),
		SpecID:     specID,
		Config: persistedCfg{
			VCPUs:            cfg.VCPUs,
			MemoryMB:         cfg.MemoryMB,
			KernelPath:       cfg.KernelPath,
			InitramfsPath:    cfg.InitramfsPath,
			KernelCmdline:    cfg.KernelCmdline,
			VMMBinary:        cfg.VMMBinary,
			VolumesDir:       cfg.VolumesDir,
			WardenSessionKey: cfg.WardenSessionKey,
		},
	}
	if cfg.NetSpec.HasNetwork() {
		s.NetSpec = netSpecToPersisted(cfg.NetSpec)
	}
	return s
}

func netSpecToPersisted(ns *vmm.VMNetSpec) *persistedNet {
	p := &persistedNet{
		GuestIP:  ns.GuestIP,
		Prefix:   ns.Prefix,
		Gateway:  ns.Gateway,
		GuestIP6: ns.GuestIP6,
		Prefix6:  ns.Prefix6,
		Gateway6: ns.Gateway6,
		DNS:      ns.DNS,
		MAC:      ns.MAC,
	}
	if tap, ok := ns.NetConfig["tap"].(string); ok {
		p.TAP = tap
	}
	if mtu, ok := ns.NetConfig["mtu"].(int); ok {
		p.MTU = mtu
	}
	return p
}

func netSpecFromPersisted(p *persistedNet) *vmm.VMNetSpec {
	if p == nil {
		return nil
	}
	ns := &vmm.VMNetSpec{
		GuestIP:  p.GuestIP,
		Prefix:   p.Prefix,
		Gateway:  p.Gateway,
		GuestIP6: p.GuestIP6,
		Prefix6:  p.Prefix6,
		Gateway6: p.Gateway6,
		DNS:      p.DNS,
		MAC:      p.MAC,
		NetConfig: map[string]any{
			"tap": p.TAP,
			"mac": p.MAC,
			"mtu": 1500,
		},
	}
	if p.MTU > 0 {
		ns.NetConfig["mtu"] = p.MTU
	}
	return ns
}

// configFromState rebuilds a vmm.Config from persisted state. The re-adopted VM
// is already booted, so this config is only used for teardown (SandboxDir,
// NetSpec for Release) and re-mount bookkeeping — not to re-launch.
func configFromState(s *persistedState) vmm.Config {
	cfg := vmm.Config{
		ID:               s.VMID,
		VCPUs:            s.Config.VCPUs,
		MemoryMB:         s.Config.MemoryMB,
		KernelPath:       s.Config.KernelPath,
		InitramfsPath:    s.Config.InitramfsPath,
		KernelCmdline:    s.Config.KernelCmdline,
		VMMBinary:        s.Config.VMMBinary,
		VolumesDir:       s.Config.VolumesDir,
		SandboxDir:       s.SandboxDir,
		GuestCID:         s.CID,
		WardenSessionKey: s.Config.WardenSessionKey,
	}
	if s.NetSpec != nil {
		cfg.NetSpec = netSpecFromPersisted(s.NetSpec)
	}
	return cfg
}

// --- Exported wrappers for boxout ---

// StateRootPathFor returns the instance state root for a sandbox root (the
// parent of the per-VM state dirs), exported for boxout's ownership handoff.
func StateRootPathFor(sandboxRoot string) string {
	return StateRootFor(sandboxRoot)
}

// StateDirPath returns the private per-VM state directory (StateRootFor +
// vm id) for a sandbox dir under the given sandbox root. Exported for
// boxout's ownership handoff: boxout (root) writes state.json there, and the
// unprivileged sandlot must read it back at re-attach (it carries the warden
// session key), so boxout hands the directory to the sandlot uid after the
// write. The path is derived exactly as writeState derives it — never
// recomputed by the caller.
func StateDirPath(sandboxDir, sandboxRoot string) (string, error) {
	clean := filepath.Clean(sandboxDir)
	vmID := filepath.Base(clean)
	if !validStateComponent(vmID) {
		return "", fmt.Errorf("invalid VM id %q", vmID)
	}
	if !isSandswapVMDir(clean, filepath.Clean(sandboxRoot)) {
		return "", fmt.Errorf("sandbox dir %q outside %s", sandboxDir, sandboxRoot)
	}
	return filepath.Join(StateRootFor(sandboxRoot), vmID), nil
}

// WriteState is the exported wrapper for writeState, used by boxout to persist
// VM state after launching sandvmm.
func WriteState(vmID string, cfg vmm.Config, apiSocket string, pid int, specID string, sandboxRoot string) error {
	return writeState(stateFromConfig(vmID, cfg, apiSocket, pid, specID), sandboxRoot)
}

// UpdateStateRuntime persists the reuse counters/agent set into the existing
// state.json without touching the launch identity. Used after each successful
// cold mount; a write failure is logged by the caller, never fatal to serving.
func UpdateStateRuntime(sandboxDir, sandboxRoot string, mountCount uint64, countedGen int64, agents []string) error {
	st, err := loadState(sandboxDir)
	if err != nil {
		return err
	}
	st.MountCount = mountCount
	st.MountCountedGen = countedGen
	st.DistinctAgents = append([]string(nil), agents...)
	return writeState(*st, sandboxRoot)
}

// RemoveState is the exported wrapper for removeState.
func RemoveState(sandboxDir string) {
	removeState(sandboxDir)
}

// RemoveSandboxDir is the exported wrapper for removeSandboxDir.
func RemoveSandboxDir(sandboxDir, sandboxRoot string) {
	removeSandboxDir(sandboxDir, sandboxRoot)
}

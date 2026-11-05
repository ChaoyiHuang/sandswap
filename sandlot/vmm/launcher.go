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
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"sandlot/hostbin"
)

// virtioFsReadOnly controls whether the virtio-fs device is created read-only.
// MUST be false: the agent rootfs is RW (pip/apt/file writes must persist).
// The VMM's BackendFsConfig defaults read_only=true, so we override explicitly.
const virtioFsReadOnly = false

// Config holds the parameters for launching a microVM.
type Config struct {
	ID            string
	KernelPath    string
	InitramfsPath string
	VCPUs         uint32
	MemoryMB      uint64
	KernelCmdline string
	SandboxDir    string
	VMMBinary     string
	GuestCID      uint32 // vsock guest CID (0 = default to 3)
	VolumesDir    string // host directory shared via virtio-fs (default /var/sandswap/volumes)
	TemplatesDir  string // template store for OverlayFS lowerdirs ("" = sibling templates/ of VolumesDir, resolved in core/overlay.go)
	// VMMUid/VMMGid run the sandvmm process as the dedicated VMM identity
	// (uid-pinned 987), separate from sandlot. The uid transition in the
	// spawn (SysProcAttr.Credential) clears every capability set kernel-side:
	// sandvmm runs with ZERO capabilities. 0/0 = no transition (scratch runs
	// keep the parent identity).
	VMMUID uint32
	VMMGID uint32
	// APIAllowedUID, when non-zero, is the only non-root uid admitted on the
	// canonical sandvmm API socket (the sandlot identity). It is passed to
	// the VMM as --api-allowed-uid; embedded mode derives it from the
	// launcher's euid, boxout sets it to its -allowed-uid.
	APIAllowedUID uint32
	// SeccompMode is the sandvmm --seccomp value (microvm.vmm_seccomp):
	// "true" (default) enforces the v28 per-thread allow-lists (Trap/SIGSYS);
	// "log" installs them in audit mode; "false" is the explicit escape
	// hatch. "process" (KillProcess) is NOT accepted by sandvmm: it installs
	// Trap only for the combined filter and empty programs for the
	// per-thread filters, i.e. no seccomp on the guest-facing threads.
	// Empty is normalized to "true" at spawn.
	SeccompMode string
	// VMMAPIAuth enables the per-VM API token/challenge handshake on
	// the canonical VMM API socket (microvm.vmm_api_auth / -vmm-api-auth,
	// default true — DefaultVMMAPIAuth). When on, Launch mints a 32-byte random
	// token, persists it 0600 under <sandbox>/state for re-adopt, and passes it
	// over an inherited fd; the client proves the peer knows it before the
	// first protocol byte. When off, no token is minted or passed and the
	// socket relies on DAC + SO_PEERCRED (--api-allowed-uid) alone.
	VMMAPIAuth bool
	// VMMGroups are the child's supplementary groups (resolved by the caller:
	// kvm for /dev/kvm + the sandlot shared group for volume writes and the
	// API-socket chgrp — chgrp to a group the process belongs to needs no
	// capabilities). The spawn sets EXACTLY this list (setpriv --groups) and
	// never inherits the parent's: a merged exec,prov sandlot carries the
	// volume-seed group (sandprov) to read the seed, and that group must not
	// reach the FUSE passthrough daemon. Empty = the child runs with NO
	// supplementary groups (setpriv --clear-groups).
	VMMGroups []uint32
	// APIGid is the group granted connect access to the sandvmm API sockets
	// (0660 owner:group, passed as --api-gid). Must be a group VMMGroups
	// contains. 0 = sockets stay 0600 owner-only.
	APIGID uint32
	// NetSpec, if non-nil with a non-empty GuestIP, attaches a virtio-net
	// device to the VM and passes guest IP/gateway/DNS/MAC to the warden via
	// the kernel cmdline. nil or GuestIP=="" => offline VM (default).
	NetSpec *VMNetSpec
	// WardenCountdownSec (T_warden) is passed to the warden via the kernel
	// cmdline (warden.warden_countdown_sec): the warden's single countdown,
	// reset only by OP_MEM_STATS heartbeats. 0 = leave the warden's own default
	// (300s). Must be >= the sandlot's cleanup budget (T_clean) so the sandlot
	// always has room to unmount normally before the countdown fires.
	WardenCountdownSec uint32
	// WardenMaxExecTimeoutSec is passed to the warden via the kernel cmdline
	// (warden.max_exec_timeout): the warden clamps its countdown up to this
	// bound, so lowering it lowers the effective floor of T_warden. 0 = leave
	// the warden's own default (300s). Only needed when T_warden < 300s.
	WardenMaxExecTimeoutSec uint32
	// WardenLogLevel overrides the warden's log level via the kernel cmdline
	// (warden.log). Empty = the warden's own default (info). Production runs
	// stay at info — per-op hot-path lines (exec/mount timing, status polls)
	// are logged at debug because their serial-UART drain taxes the measured
	// path; profiling sessions set this to "debug" to get them back.
	WardenLogLevel string
	// InitOnFree selects the guest kernel's free-time page-wipe posture,
	// written as an explicit init_on_free= on every VM's kernel cmdline (the
	// effective cmdline is persisted in state.json, so the posture stays
	// auditable per VM). Default false (=0): the guest kernel builds with
	// INIT_ON_FREE_DEFAULT_ON, whose boot-time bulk clear of ALL guest RAM is
	// purely redundant in a fresh microVM — the VMM's guest RAM is host
	// anonymous mmap (untouched pages are already host-zero) and no tenant
	// has run yet — while the measured cost is linear in RAM (~0.65ms/MB on
	// nested virt: ~330ms at 512MB, ~2.4s at 2GB; RAM-independent boot with
	// the override). init_on_alloc stays on either way (it is a separate
	// static key), so the cross-tenant "next allocation reads the previous
	// tenant's freed pages" channel stays closed. true re-enables the kernel
	// config's stronger posture (sensitive contents wiped at free time —
	// shorter lifetime after free, stale-mapping defense) for deployments
	// that require it; that mode also keeps the per-free memset on the exec
	// teardown path. Security-posture knob: restart-required, like
	// vmm_seccomp/vmm_api_auth.
	InitOnFree bool
	// WardenSessionKey is the 64-hex-character per-VM key that authenticates
	// every raw warden frame. It NEVER rides the kernel cmdline: the warden
	// starts uninitialized and the sandlot delivers the key over the first
	// host vsock connection (OP_KEY_DELIVERY). Launch generates one when
	// empty and returns it on RunningVM so the caller can persist it for
	// re-adopt. Never log this value.
	WardenSessionKey string
}

// RunningVM represents a launched microVM.
type RunningVM struct {
	ID        string
	APISocket string
	Client    *Client
	GuestCID  uint32 // vsock guest CID for agent communication
	// APIToken is the optional per-VM canonical-API authentication token
	// (nil when VMMAPIAuth is off). When enabled, the VMM received it over an
	// inherited fd at spawn; the client proves the peer knows it on every
	// connection. Persisted 0600 under <sandbox>/state for re-adopt (readable
	// only by the sandlot identity).
	APIToken []byte
	// WardenSessionKey is the per-VM raw-protocol key the warden received over
	// the first host vsock connection (never the kernel cmdline). Persisted
	// with the VM state so a re-adopted VM can still authenticate after a
	// sandlot restart.
	WardenSessionKey string
	// KernelCmdline is the EFFECTIVE kernel command line the VM booted with
	// (buildCmdline output: the caller's base or the launcher default, plus
	// the warden net/countdown/console params). Persisted with the VM state
	// so host-side assertions and re-adopt see what actually booted, not the
	// pre-defaulting cfg value.
	KernelCmdline string
	cmd           *exec.Cmd
	pid           int  // sandvmm PID (set for re-adopted VMs that have no *exec.Cmd)
	readopted     bool // true if this VM was attached to an existing sandvmm, not launched by us
}

// Readopted reports whether this VM was re-attached to an already-running
// sandvmm process (e.g. after a sandlot restart) rather than launched fresh.
// Re-adopted VMs have no *exec.Cmd, so they cannot be cmd.Wait()-ed; their
// liveness is polled via the VMM API (Ping). See stream.Handler.monitorVM.
func (vm *RunningVM) Readopted() bool { return vm.readopted }

// PID returns the sandvmm process PID (from cmd.Process.Pid for fresh VMs,
// or the persisted pid for re-adopted VMs).
func (vm *RunningVM) PID() int {
	if vm.cmd != nil && vm.cmd.Process != nil {
		return vm.cmd.Process.Pid
	}
	return vm.pid
}

// AttachConfig carries the persisted identity needed to re-attach to a
// sandvmm process that survived a sandlot restart. The process is already
// running and the VM already booted — Attach does NOT exec or re-create it.
type AttachConfig struct {
	ID         string
	APISocket  string
	GuestCID   uint32
	PID        int    // sandvmm process PID (for force-kill on teardown)
	SandboxDir string // token file location (read-only; "" for tests)
	// WardenSessionKey is the per-VM raw-protocol key from the persisted
	// state; the re-adopted VM's warden still expects it.
	WardenSessionKey string
	// VMMAPIAuth requires a readable API token: a survivor whose token is
	// missing/invalid must not be attached without the challenge (a squatted
	// listener would otherwise answer Ping unauthenticated).
	VMMAPIAuth bool
}

// Attach re-attaches to an already-running sandvmm process by its API socket.
// It builds a RunningVM handle (readopted=true, no *exec.Cmd) and confirms the
// VMM is still alive via Ping. Used by ReadoptVMs at sandlot startup to reclaim
// microVMs that survived a sandlot restart.
func Attach(ctx context.Context, cfg AttachConfig, logger *log.Logger) (*RunningVM, error) {
	token, terr := ReadAPIToken(cfg.SandboxDir)
	if terr != nil {
		if cfg.VMMAPIAuth {
			return nil, fmt.Errorf("attach: API token unavailable for VM %s: %w", cfg.ID, terr)
		}
		token = nil // legacy/no-auth shape; compatibility only
	}
	vm := &RunningVM{
		ID:               cfg.ID,
		APISocket:        cfg.APISocket,
		GuestCID:         cfg.GuestCID,
		APIToken:         token,
		WardenSessionKey: cfg.WardenSessionKey,
		pid:              cfg.PID,
		readopted:        true,
	}
	vm.Client = NewClient(cfg.APISocket, token)
	if err := vm.Client.Ping(ctx); err != nil {
		return nil, fmt.Errorf("attach: vmm %s not responding on %s: %w", cfg.ID, cfg.APISocket, err)
	}
	if logger != nil {
		logger.Printf("re-attached VMM %s (api=%s, pid=%d, cid=%d)", cfg.ID, cfg.APISocket, cfg.PID, cfg.GuestCID)
	}
	return vm, nil
}

// prepareSandboxDir creates/repairs the directory shape the sandvmm child
// needs (see Launch for the model rationale).
//
// Split identity (vmmUID>0): the per-VM dir is 0770+setgid, group=apiGid, so
// the DIFFERENT-uid child can create its socket/log files inside and the
// sandlot identity can reach them. The PARENT root gets the same 0711
// traverse-only shape boxout's startup applies to its root — MkdirAll would
// otherwise leave it at 0770-minus-umask (0750 root:root under a root-owned
// process), and a root:root 0750 root locks a different-uid child out of
// traversal entirely: k8s embedded (sandlot runs as root; baremetal runs
// VMMUID=0 and never hit this) died at socket creation with EACCES on every
// launch.
func prepareSandboxDir(sandboxDir string, vmmUID, apiGid uint32) error {
	mode, setgid := SandboxDirMode(vmmUID)
	if rootMode := SandboxRootMode(vmmUID); rootMode != 0 {
		root := filepath.Dir(sandboxDir)
		rfd, err := openDirNoFollow(root, true, rootMode)
		if err != nil {
			return fmt.Errorf("create sandbox root: %w", err)
		}
		// Explicit chmod: MkdirAll applies the umask, which is exactly how
		// the root ended up untraversable for the child.
		if err := unix.Fchmod(rfd, uint32(rootMode.Perm())); err != nil {
			unix.Close(rfd)
			return fmt.Errorf("sandbox root chmod %o: %w", rootMode, err)
		}
		unix.Close(rfd)
	}
	sfd, err := openDirNoFollow(sandboxDir, true, mode)
	if err != nil {
		return fmt.Errorf("create sandbox dir: %w", err)
	}
	defer unix.Close(sfd)
	if vmmUID > 0 {
		// chgrp to the shared group + setgid. Group-membership chown needs no
		// capabilities; failures are fatal (a wrong-group dir would strand the
		// child: it could not create its socket).
		if err := unix.Fchown(sfd, -1, int(apiGid)); err != nil {
			return fmt.Errorf("sandbox dir chgrp %d: %w", apiGid, err)
		}
	}
	want := uint32(mode.Perm())
	if setgid {
		want |= unix.S_ISGID
	}
	if err := unix.Fchmod(sfd, want); err != nil {
		return fmt.Errorf("sandbox dir chmod %o: %w", want, err)
	}
	return nil
}

// EnsureSandboxRoot creates or repairs a sandbox ROOT directory (the parent of
// the per-VM dirs) with the given traverse-only mode. fd-relative: a symlink
// in any component — including a sibling replacing the root itself — fails the
// open instead of being followed.
func EnsureSandboxRoot(root string, mode os.FileMode) error {
	fd, err := openDirNoFollow(root, true, mode)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if err := unix.Fchmod(fd, uint32(mode.Perm())); err != nil {
		return fmt.Errorf("sandbox root chmod %o: %w", mode, err)
	}
	return nil
}

// openDirNoFollow walks an absolute path one component at a time with
// O_NOFOLLOW, creating missing components with mode when create is true. It
// returns a read-only directory fd. A symlink in ANY component (including the
// final one) fails the open: the sandbox tree is writable by the VMM/service
// identities, so a path-based MkdirAll/Chmod/Chown would let a sibling swap a
// parent for a symlink and turn a privileged create into an arbitrary-host
// operation.
func openDirNoFollow(path string, create bool, mode os.FileMode) (int, error) {
	if !filepath.IsAbs(path) {
		abs, err := filepath.Abs(path)
		if err != nil {
			return -1, err
		}
		path = abs
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	for _, comp := range strings.Split(strings.TrimPrefix(filepath.Clean(path), "/"), "/") {
		if comp == "" || comp == "." {
			continue
		}
		nfd, err := unix.Openat(fd, comp, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			if errors.Is(err, unix.ENOENT) && create {
				if merr := unix.Mkdirat(fd, comp, uint32(mode.Perm())); merr != nil && !errors.Is(merr, unix.EEXIST) {
					unix.Close(fd)
					return -1, merr
				}
				nfd, err = unix.Openat(fd, comp, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			}
			if err != nil {
				unix.Close(fd)
				return -1, err
			}
		}
		unix.Close(fd)
		fd = nfd
	}
	return fd, nil
}

// SandboxRootMode reports the mode of the sandbox ROOT — the parent of the
// per-VM dirs — under the given identity model. Split identity: 0711
// traverse-only, so the DIFFERENT-uid child can reach its per-VM dir (boxout's
// startup pins the same shape on its root). Same identity: 0 = leave the root
// alone (the owner is the only user; on baremetal the runtime dir owns its
// shape). Extracted for unit tests.
func SandboxRootMode(vmmUID uint32) os.FileMode {
	if vmmUID > 0 {
		return 0711
	}
	return 0
}

// APITokenPath is the on-disk location of a VM's canonical-API token:
// <sandbox>/state/api-token, inside the sandlot-private 0700 state dir (the
// 0600 file is unreadable by the sandvmm identity). Exported for boxout's
// post-launch ownership handoff.
func APITokenPath(sandboxDir string) string {
	return filepath.Join(sandboxDir, "state", "api-token")
}

// openTokenStateDir opens <sandbox>/state as a directory fd with
// O_NOFOLLOW and verifies the fd is a 0700 directory OWNED BY THIS process.
// The sandbox dir itself is group-writable by the shared sandvmm group, so a
// sibling could otherwise rename/replace `state` and plant a token it knows
// (or a symlink to a directory it can read). An attacker-owned or
// group/world-accessible state dir fails closed: the launch fails (write) or
// the survivor is treated as unattachable (read).
func openTokenStateDir(sandboxDir string, create bool) (*os.File, error) {
	dir := filepath.Join(sandboxDir, "state")
	if create {
		if err := os.Mkdir(dir, 0o700); err != nil && !os.IsExist(err) {
			return nil, fmt.Errorf("create state dir: %w", err)
		}
	}
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open state dir (no-follow): %w", err)
	}
	f := os.NewFile(uintptr(fd), dir)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		f.Close()
		return nil, fmt.Errorf("fstat state dir: %w", err)
	}
	// Must be OUR directory and private. boxout (root) writes it and then
	// chowns it to the sandlot uid; the sandlot's read sees owner==euid.
	if st.Uid != uint32(os.Geteuid()) || st.Mode&0o777 != 0o700 {
		f.Close()
		return nil, fmt.Errorf("state dir %s is not a private directory owned by uid %d (mode %04o, uid %d) — refusing (sibling substitution?)",
			dir, os.Geteuid(), st.Mode&0o777, st.Uid)
	}
	return f, nil
}

// ReadAPIToken returns the persisted token and a typed error when it is
// absent/invalid (a legacy VMM, a failed launch, or a substituted state dir).
// Callers decide whether absence is fatal: Attach fails closed whenever
// VMMAPIAuth is configured, and only tolerates it for the no-auth shape. The
// bytes are never logged. fd-relative + O_NOFOLLOW: the file cannot be a
// symlink and cannot live in a foreign directory.
func ReadAPIToken(sandboxDir string) ([]byte, error) {
	dirFile, err := openTokenStateDir(sandboxDir, false)
	if err != nil {
		return nil, err
	}
	defer dirFile.Close()
	fd, err := unix.Openat(int(dirFile.Fd()), "api-token",
		unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), APITokenPath(sandboxDir))
	defer f.Close()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != uint32(os.Geteuid()) || st.Mode&0o777 != 0o600 {
		return nil, fmt.Errorf("api token is not a 0600 regular file owned by uid %d (mode %04o, uid %d)", os.Geteuid(), st.Mode&0o777, st.Uid)
	}
	token := make([]byte, apiTokenLen)
	if _, err := io.ReadFull(f, token); err != nil {
		return nil, err
	}
	// Reject a file longer than the token (a planted append is not ours).
	var extra [1]byte
	if n, _ := f.Read(extra[:]); n != 0 {
		return nil, fmt.Errorf("api token has trailing bytes")
	}
	return token, nil
}

const apiTokenLen = 32

func newAPIToken() ([]byte, error) {
	token := make([]byte, apiTokenLen)
	if _, err := rand.Read(token); err != nil {
		return nil, fmt.Errorf("generate VMM API token: %w", err)
	}
	return token, nil
}

// writeAPIToken persists the token inside the sandlot-private state dir
// (0700 dir owned by this process, 0600 file, fd-relative atomic rename).
// A stale/replaced tmp file is unlinked first; O_EXCL|O_NOFOLLOW prevents a
// planted symlink from receiving the token.
func writeAPIToken(sandboxDir string, token []byte) error {
	dirFile, err := openTokenStateDir(sandboxDir, true)
	if err != nil {
		return err
	}
	defer dirFile.Close()
	dirFd := int(dirFile.Fd())
	const tmpName = "api-token.tmp"
	_ = unix.Unlinkat(dirFd, tmpName, 0)
	fd, err := unix.Openat(dirFd, tmpName,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return fmt.Errorf("create api token: %w", err)
	}
	f := os.NewFile(uintptr(fd), tmpName)
	if _, err := f.Write(token); err != nil {
		f.Close()
		_ = unix.Unlinkat(dirFd, tmpName, 0)
		return fmt.Errorf("write api token: %w", err)
	}
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		_ = unix.Unlinkat(dirFd, tmpName, 0)
		return fmt.Errorf("chmod api token: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = unix.Unlinkat(dirFd, tmpName, 0)
		return fmt.Errorf("close api token: %w", err)
	}
	if err := unix.Renameat(dirFd, tmpName, dirFd, "api-token"); err != nil {
		_ = unix.Unlinkat(dirFd, tmpName, 0)
		return fmt.Errorf("publish api token: %w", err)
	}
	return nil
}

// Launch starts the sandvmm process and returns a handle to it.
func Launch(ctx context.Context, cfg Config, logger *log.Logger) (*RunningVM, error) {
	if cfg.VMMBinary == "" {
		cfg.VMMBinary = "sandvmm"
	}
	if cfg.SandboxDir == "" {
		cfg.SandboxDir = filepath.Join("/run/sandswap/vm", cfg.ID)
	}
	if cfg.VolumesDir == "" {
		cfg.VolumesDir = "/var/sandswap/volumes"
	}
	if cfg.KernelCmdline == "" {
		// highres=off (copied from upstream example cmdlines) disables the
		// guest's hrtimers, degrading every timer wait to the 4ms periodic
		// tick (HZ=250) — measured as 4ms-quantized exec latency (warm exec
		// 14-23ms vs ~1ms with hrtimers). Keep hrtimers ON.
		// No listen-address param here: the warden ignores one (its vsock
		// port is the compile-time constant in raw_server::PORT).
		cfg.KernelCmdline = "quiet clocksource=kvm-clock"
	}
	// Every VM gets its own raw-protocol key. Callers that need the key for
	// persistence/warmup generate it first (CreateVerifiedVM); a direct Launch
	// still gets a fresh one, returned on RunningVM.
	if cfg.WardenSessionKey == "" {
		key, err := NewWardenSessionKey()
		if err != nil {
			return nil, fmt.Errorf("warden session key: %w", err)
		}
		cfg.WardenSessionKey = key
	}
	// Sandbox dir shape depends on the identity model:
	//   - split identity (VMMUID>0): the sandvmm child (a DIFFERENT uid than
	//     this process) must create its socket and log files inside, and the
	//     sandlot identity must reach the socket — the shared group does both
	//     (0770 + setgid, group = APIGID). setgid makes every child file
	//     (socket, serial/console logs) carry the shared group automatically.
	//   - same identity (VMMUID=0): the legacy 0711 traverse-only shape is
	//     enough (same-uid owner needs nothing more; boxout mode's unprivileged
	//     sandlot only traverses).
	if err := prepareSandboxDir(cfg.SandboxDir, cfg.VMMUID, cfg.APIGID); err != nil {
		return nil, err
	}

	apiSocket := filepath.Join(cfg.SandboxDir, "sandvmm.sock")

	// Remove stale socket
	os.Remove(apiSocket)

	// Start VMM in API-only mode (no --kernel so it won't auto-create a VM).
	// All configuration is done via the HTTP API.
	//
	// Seccomp: the v28 per-thread allow-lists cover the API dispatcher and the
	// in-process virtio-fs server (extended in this tree). Default is "true"
	// (enforce): the filter audit's trapped set (chmod/chown, umask(0),
	// getrandom/tgkill, readlinkat in the fs thread) was root-caused to gaps
	// in virtio_fs_thread_rules and FIXED (vmm/virtio-devices/src/
	// seccomp_filters.rs, with pin tests), and e2e/vmm-seccomp.sh passed both
	// phases (log-mode RET_LOG hits = 0 across the battery, enforce-mode
	// battery green) before the flip. "log" is the audit mode; "false" remains
	// the explicit escape hatch. Re-run the gate before changing the lists.
	args := []string{
		"--api-socket", apiSocket,
		"--seccomp", seccompModeOr(cfg.SeccompMode),
		// Log to stderr instead of the default /data/log/sandvmm/vmm.log.
		// The default path is a hardcoded directory that doesn't exist in K8s
		// containers (readOnlyRootFilesystem prevents its creation).
		// --log-stderr routes all VMM logs to stderr, which k8s captures via
		// kubectl logs — no filesystem write needed.
		"--log-stderr",
	}
	// Deployment path roots: every host path in vm.create (kernel/initramfs,
	// serial/console logs, the virtio-fs share root) must live under one of
	// these. A compromised sandlot cannot point the VMM at arbitrary host files.
	{
		var roots []string
		addRoot := func(p string) {
			if p == "" {
				return
			}
			dir := p
			if fi, err := os.Stat(p); err != nil || !fi.IsDir() {
				dir = filepath.Dir(p)
			}
			if dir == "" || dir == "." || dir == "/" {
				return
			}
			for _, r := range roots {
				if r == dir {
					return
				}
			}
			roots = append(roots, dir)
		}
		addRoot(cfg.VolumesDir)
		addRoot(cfg.KernelPath)
		addRoot(cfg.InitramfsPath)
		addRoot(cfg.SandboxDir)
		for _, r := range roots {
			args = append(args, "--sandswap-allowed-root", r)
		}
	}
	// The API sockets are owned by the sandvmm process identity itself (it
	// binds them). --api-gid widens the group to the shared group (0660) so
	// the sandlot identity — a member — can connect; without it the sockets
	// stay 0600 owner-only.
	if cfg.APIGID > 0 {
		args = append(args, "--api-gid", fmt.Sprintf("%d", cfg.APIGID))
	}
	// The socket's peer-uid gate is ALWAYS on: it stops a sibling VMM/FUSE
	// service (same sandvmm uid) from driving this VM's API. It is independent
	// of the optional token handshake below.
	allowedUID := cfg.APIAllowedUID
	if allowedUID == 0 {
		allowedUID = uint32(os.Geteuid())
	}
	args = append(args, "--api-allowed-uid", strconv.FormatUint(uint64(allowedUID), 10))
	// Per-VM canonical-API authentication token (microvm.vmm_api_auth /
	// -vmm-api-auth, default ON — see DefaultVMMAPIAuth). When enabled:
	// generated here, persisted 0600 in the sandlot-private state dir
	// (re-adopt), and delivered to the VMM over an inherited fd
	// (ExtraFiles[0] == fd 3) — never argv/env. When disabled, no token is
	// minted or passed; the socket relies on DAC + --api-allowed-uid alone.
	var token []byte
	if cfg.VMMAPIAuth {
		var err error
		token, err = newAPIToken()
		if err != nil {
			return nil, err
		}
		if err := writeAPIToken(cfg.SandboxDir, token); err != nil {
			return nil, err
		}
		args = append(args, "--api-token-fd", "3")
	}

	// Identity split: wrap the exec through setpriv (full capability drop
	// around the uid transition — see the SysProcAttr note below for why
	// Credential alone is NOT enough). setpriv execs in place, so the PID
	// recorded below is the sandvmm PID itself.
	vmmBin := cfg.VMMBinary
	if cfg.VMMUID > 0 {
		wrapped, err := wrapWithSetpriv(cfg, vmmBin, args)
		if err != nil {
			return nil, err
		}
		vmmBin, args = wrapped[0], wrapped[1:]
	}
	// exec.CommandContext, NOT exec.Command: the ctx must be
	// context.Background() in production. CommandContext SIGKILLs the child
	// the moment a cancellable ctx fires, which would defeat the re-adopt
	// lifecycle (sandvmm must survive a sandlot exit; orphan cleanup is the
	// startup sweep's job, not a parent-death signal). Every current caller
	// (embeddedManager.CreateVM) passes Background — this comment pins that
	// contract against future callers.
	cmd := exec.CommandContext(ctx, vmmBin, args...)
	var tokenR, tokenW *os.File
	if cfg.VMMAPIAuth {
		var err error
		tokenR, tokenW, err = os.Pipe()
		if err != nil {
			return nil, fmt.Errorf("api token pipe: %w", err)
		}
		cmd.ExtraFiles = []*os.File{tokenR}
	}

	// Pipe output for debugging
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// Put sandvmm in its own process group so terminal SIGINT to sandlot is
	// not propagated to the microVM (a Ctrl-C at the sandlot prompt must not
	// kill running VMs). CRITICAL: we deliberately do NOT set Pdeathsig —
	// sandvmm must survive a sandlot crash/restart so it can be re-adopted;
	// Pdeathsig would SIGKILL every VM the instant sandlot dies, defeating
	// the re-adopt lifecycle. Orphan cleanup is handled explicitly at startup
	// (Handler.ReadoptVMs /proc sweep), not via parent-death signals.
	//
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	logger.Printf("launching VMM: %s --api-socket %s (sandbox %s) cmdline=[%s]",
		cfg.VMMBinary, apiSocket, cfg.ID, redactCmdline(buildCmdline(cfg)))

	if err := cmd.Start(); err != nil {
		if tokenW != nil {
			tokenW.Close()
		}
		if tokenR != nil {
			tokenR.Close()
		}
		return nil, fmt.Errorf("start vmm: %w", err)
	}
	// The identity split is proven, not assumed: setpriv must leave all four
	// uid/gid values at the sandvmm identity (a saved-uid 0 can be reclaimed
	// later). A spawn that fails this is killed before it can serve.
	if cfg.VMMUID > 0 {
		if err := verifyChildIdentity(cmd.Process.Pid, cfg.VMMUID, cfg.VMMGID); err != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			if tokenW != nil {
				tokenW.Close()
			}
			if tokenR != nil {
				tokenR.Close()
			}
			return nil, fmt.Errorf("sandvmm identity check: %w", err)
		}
	}
	if cfg.VMMAPIAuth {
		// The VMM blocks on fd 3 before starting its API. 32 bytes fit in the
		// pipe buffer; close both parent copies immediately after.
		if _, err := tokenW.Write(token); err != nil {
			_ = cmd.Process.Kill()
			tokenW.Close()
			tokenR.Close()
			return nil, fmt.Errorf("deliver VMM API token: %w", err)
		}
		tokenW.Close()
		tokenR.Close()
	}

	cid := cfg.GuestCID
	if cid == 0 {
		cid = 3
	}
	vm := &RunningVM{
		ID:               cfg.ID,
		APISocket:        apiSocket,
		GuestCID:         cid,
		APIToken:         token,
		WardenSessionKey: cfg.WardenSessionKey,
		KernelCmdline:    buildCmdline(cfg),
		cmd:              cmd,
	}

	// Wait for VMM to be ready
	vm.Client = NewClient(apiSocket, token)

	if err := vm.waitReady(ctx, logger); err != nil {
		killFailedLaunch(vm)
		return nil, err
	}

	// Create the VM via HTTP API with full config
	serialLog, consoleLog := sandboxLogPaths(cfg.SandboxDir)
	vmConfig := buildVMCreateConfig(cfg, serialLog, consoleLog)
	if err := vm.Client.CreateVM(ctx, vmConfig); err != nil {
		killFailedLaunch(vm)
		return nil, fmt.Errorf("create vm: %w", err)
	}
	// Add vsock device for host↔guest agent communication (kernel vhost-vsock,
	// routed by guest CID — no host socket path needed). The warden lives on
	// this channel, so a failed add-vsock is an unusable VM: fail the launch
	// here instead of booting a guest whose warden can never answer (it would
	// only be destroyed 15s later by CreateVerifiedVM's boot check, with a
	// misleading "warden not ready" error and a wasted guest boot).
	if err := vm.Client.AddVsock(ctx, vm.GuestCID); err != nil {
		killFailedLaunch(vm)
		return nil, fmt.Errorf("add vsock (cid %d): %w", vm.GuestCID, err)
	}
	if err := vm.Client.BootVM(ctx); err != nil {
		killFailedLaunch(vm)
		return nil, fmt.Errorf("boot vm: %w", err)
	}

	logger.Printf("VMM %s booted (api=%s, pid=%d)", cfg.ID, apiSocket, cmd.Process.Pid)

	return vm, nil
}

// sandboxLogPaths names the two per-VM guest log sinks. They MUST be distinct
// files: both VMM backends File::create (truncate) and keep independent write
// offsets. serial.log carries earlyprintk (earliest boot/panic); console.log
// is the main log (hvc0).
func sandboxLogPaths(sandboxDir string) (serialLog, consoleLog string) {
	return filepath.Join(sandboxDir, "serial.log"),
		filepath.Join(sandboxDir, "console.log")
}

// buildVMCreateConfig assembles the vm.create request body: CPU, memory,
// PVH payload, the two guest log sinks (serial: earlyprintk; console: hvc0),
// the permanent virtio-fs device, and (when a net spec was provisioned) the
// virtio-net device. Pure function — unit-tested in launcher_test.go.
func buildVMCreateConfig(cfg Config, serialLog, consoleLog string) map[string]interface{} {
	vmConfig := map[string]interface{}{
		"cpus": map[string]interface{}{
			"boot_vcpus": cfg.VCPUs,
			"max_vcpus":  cfg.VCPUs,
		},
		"memory": map[string]interface{}{
			"size": cfg.MemoryMB * 1024 * 1024, // bytes
		},
		"payload": map[string]interface{}{
			"kernel":    cfg.KernelPath,
			"initramfs": cfg.InitramfsPath,
			"cmdline":   buildCmdline(cfg),
		},
		"serial": map[string]interface{}{
			"mode": "File",
			"file": serialLog,
		},
		// virtio-console hvc0: the guest's preferred /dev/console, i.e. where
		// the warden's stdout lands. The VMM default is mode Tty (dup of
		// sandvmm's stdout = sandlot's log), so an explicit File backend is
		// mandatory. Distinct from serial.log (both backends File::create).
		"console": map[string]interface{}{
			"mode": "File",
			"file": consoleLog,
		},
		// Virtio-fs device: native PassthroughFs shares the host volumes
		// directory permanently. No hotplug needed — agent switching uses
		// vm.set-fs to update allowed_dirs + bind mount in the guest.
		//
		// allowed_dirs is sent as an explicit empty list. Belt and braces:
		// the VMM's config layer also defaults an absent field to the empty
		// (allow-nothing) list — the filter has no "no filtering" mode — but
		// sending [] keeps the boot window fail-closed independent of that
		// default: no agent directory is visible until SetFs.
		//
		// read_only MUST be false: the agent rootfs is RW (pip/apt/file writes
		// must persist). The VMM's BackendFsConfig defaults read_only=true, so
		// we override it explicitly.
		"fs": []map[string]interface{}{
			{
				"id":  "vfs-rootfs",
				"tag": "sandswap",
				"backendfs_config": map[string]interface{}{
					"shared_dir":   cfg.VolumesDir,
					"read_only":    virtioFsReadOnly,
					"allowed_dirs": []string{},
				},
			},
		},
	}
	// Attach the virtio-net device (a pre-created TAP enslaved to the host
	// bridge) when a net spec was provisioned. Configured at vm.create time,
	// like fs — no vm.add-net follow-up. The guest IP/gateway/DNS/MAC are
	// passed to the warden via the kernel cmdline (see buildCmdline), not here.
	if cfg.NetSpec != nil && (cfg.NetSpec.GuestIP != "" || cfg.NetSpec.GuestIP6 != "") {
		vmConfig["net"] = []map[string]interface{}{cfg.NetSpec.NetConfig}
	}
	return vmConfig
}

// buildCmdline assembles the kernel command line: the base cmdline (from cfg or
// its default), the warden.net_* params describing the guest's static network
// (only when a net spec was provisioned), the warden countdown (T_warden), the
// virtio-console (preferred) and the early serial console.
func buildCmdline(cfg Config) string {
	cmdline := cfg.KernelCmdline
	// Free-wipe posture is EXPLICIT on every boot, not inherited from the
	// kernel config's INIT_ON_FREE_DEFAULT_ON: the knob (microvm.init_on_free,
	// default false) is the deployment's authority, and writing it out makes
	// the persisted effective cmdline record the posture per VM. Appended
	// AFTER the base so an operator-provided init_on_free= in the base cannot
	// win (the kernel's early_param handling keeps the LAST occurrence).
	if cfg.InitOnFree {
		cmdline += " init_on_free=1"
	} else {
		cmdline += " init_on_free=0"
	}
	// Guest static networking (bridge / routed-ipv6 backends, either or both
	// families). DNS and MAC are family-independent: the warden locates the
	// interface by MAC and configures resolv.conf once.
	if ns := cfg.NetSpec; ns != nil && (ns.GuestIP != "" || ns.GuestIP6 != "") {
		if ns.GuestIP != "" {
			cmdline += " warden.net_ip=" + ns.GuestIP +
				fmt.Sprintf(" warden.net_prefix=%d", ns.Prefix) +
				" warden.net_gw=" + ns.Gateway
		}
		if ns.GuestIP6 != "" {
			cmdline += " warden.net_ip6=" + ns.GuestIP6 +
				fmt.Sprintf(" warden.net_prefix6=%d", ns.Prefix6) +
				" warden.net_gw6=" + ns.Gateway6
		}
		cmdline += " warden.net_dns=" + strings.Join(ns.DNS, ",") +
			" warden.net_mac=" + ns.MAC
	}
	if cfg.WardenCountdownSec > 0 {
		cmdline += fmt.Sprintf(" warden.warden_countdown_sec=%d", cfg.WardenCountdownSec)
	}
	if cfg.WardenMaxExecTimeoutSec > 0 {
		cmdline += fmt.Sprintf(" warden.max_exec_timeout=%d", cfg.WardenMaxExecTimeoutSec)
	}
	if cfg.WardenLogLevel != "" {
		cmdline += " warden.log=" + cfg.WardenLogLevel
	}
	// hvc0 is the ONLY console=, so it is the preferred /dev/console: the
	// warden's stdout (and all later kernel printk) lands in console.log.
	// earlyprintk keeps the earliest boot/panic output on ttyS0 → serial.log;
	// it is not a console=, so it does not make ttyS0 preferred.
	cmdline += " console=hvc0 earlyprintk=ttyS0"
	return cmdline
}

// NewWardenSessionKey mints a 32-byte per-VM raw-protocol key as 64 hex
// characters. The key is delivered to the warden over the first host vsock
// connection (OP_KEY_DELIVERY), never on the kernel command line, and is
// never logged.
func NewWardenSessionKey() (string, error) {
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(key[:]), nil
}

// hasCmdlineToken reports whether the space-separated command line carries
// the exact token.
func hasCmdlineToken(cmdline, token string) bool {
	for _, f := range strings.Fields(cmdline) {
		if f == token {
			return true
		}
	}
	return false
}

// redactCmdline removes secret-bearing tokens before a command line is
// written to a log. No secret rides the command line today (the warden key is
// delivered over vsock); the redaction stays as one place so a future token
// cannot leak by omission.
func redactCmdline(cmdline string) string {
	fields := strings.Fields(cmdline)
	for i, f := range fields {
		if strings.HasPrefix(f, "warden.session_key=") {
			fields[i] = "warden.session_key=<redacted>"
		}
	}
	return strings.Join(fields, " ")
}

func (vm *RunningVM) waitReady(ctx context.Context, logger *log.Logger) error {
	// 10ms poll: the static sandvmm binary binds its API socket ~30ms after
	// the spawn, so a 100ms step quantized EVERY launch to ≥100ms of pure
	// wait (first ping at t≈0 always fails while the child is still starting).
	// A failed ping is a fast local connect error (ENOENT/ECONNREFUSED), so
	// the tighter loop costs a handful of cheap attempts, not extra I/O.
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if err := vm.Client.Ping(ctx); err == nil {
			return nil
		}
		time.Sleep(10 * time.Millisecond)
	}
	return fmt.Errorf("vmm did not become ready within 30s")
}

// killFailedLaunch SIGKILLs the sandvmm child of a launch that failed after
// Start and REAPS it (cmd.Wait). A failed launch has no monitor goroutine yet,
// so this caller is the sole waiter — without the Wait, the SIGKILLed child
// stays a zombie until sandlot exits, and a persistent failure mode (the 60s
// self-heal retry loop) accumulates zombies without bound.
func killFailedLaunch(vm *RunningVM) {
	vm.Kill()
	if vm.cmd != nil {
		_ = vm.cmd.Wait()
	}
}

// Kill forcefully terminates the VMM process. For a fresh VM this SIGKILLs the
// child; for a re-adopted VM (no *exec.Cmd) it SIGKILLs by PID — the process
// is not our child so init reaps it, not us.
func (vm *RunningVM) Kill() {
	if vm.cmd != nil && vm.cmd.Process != nil {
		vm.cmd.Process.Kill()
		return
	}
	if vm.pid > 0 {
		// Re-adopted process: not a child, so we can only signal. init reaps.
		_ = syscall.Kill(vm.pid, syscall.SIGKILL)
	}
}

// Shutdown asks the VMM to shut down gracefully via its HTTP API. Used for
// re-adopted VMs (where we own no *exec.Cmd to signal) before a forceful Kill.
func (vm *RunningVM) Shutdown(ctx context.Context) error {
	return vm.Client.ShutdownVMM(ctx)
}

// Wait blocks until the VMM process exits. Only valid for fresh VMs (those we
// launched); re-adopted VMs have no *exec.Cmd and cannot be waitpid-ed (init
// reaps them). Callers monitoring re-adopted VMs use Ping polling instead.
func (vm *RunningVM) Wait() error {
	if vm.cmd != nil {
		return vm.cmd.Wait()
	}
	return nil
}

// SandboxDirMode reports the directory mode Launch uses for the per-VM
// sandbox dir under the given identity model. Split identity (vmmUID>0):
// 0770+setgid with the shared group — the different-uid child must create
// its socket/log files inside. Same identity: 0711 traverse-only.
// Extracted for unit tests.
func SandboxDirMode(vmmUID uint32) (mode os.FileMode, setgid bool) {
	if vmmUID > 0 {
		return 0770, true
	}
	return 0711, false
}

// seccompModeOr normalizes microvm.vmm_seccomp for the --seccomp argument.
// Empty is the documented default: "true" enforces the v28 per-thread
// allow-lists (the gate `e2e/vmm-seccomp.sh` passed both phases before the
// flip). "log" is the audit mode; the config layer validates the value set.
func seccompModeOr(mode string) string {
	if mode == "" {
		return "true"
	}
	return mode
}

// wrapWithSetpriv builds the setpriv wrapper argv for the identity-split
// spawn: setpriv --reuid=<vmm> --regid=<vmm> --groups=<csv>|--clear-groups
// --inh-caps=-all --ambient-caps=-all -- <vmmBinary> <args...>.
//
// Why a wrapper instead of SysProcAttr.Credential: the kernel clears
// capability sets on a uid change ONLY when uid 0 is involved — a
// non-root→non-root setuid (sandlot 985 → sandvmm 987) keeps every set
// (verified live: a raw Credential spawn landed sandvmm with the parent's
// full CapEff). setpriv performs the keepcaps+capset dance around the
// transition, so the exec'd sandvmm starts with EXACTLY ZERO capabilities
// (the network provider pre-creates the persistent TAP owned by this uid
// and pre-configures its MTU/bridge/up state, so even the attach path —
// owner-match TUNSETIFF — needs none; the live form of this invariant is
// verify-host-security.sh's per-process CapEff=0 check).
// It execs in place: the child PID the caller records IS the sandvmm PID,
// and all kill/re-adopt paths see the real process.
//
// Supplementary groups are ALWAYS explicit: --groups replaces the parent's
// set wholesale (setgroups(2)); --clear-groups is emitted when the list is
// empty. Never omit the flag: an omitted disposition inherits the parent's
// groups (the merged execution shape carries the volume-seed group sandprov,
// which the FUSE passthrough daemon must never hold) and newer util-linux
// rejects --regid without one outright.
func wrapWithSetpriv(cfg Config, vmmBin string, args []string) ([]string, error) {
	setpriv := hostbin.Path("setpriv")
	if setpriv == "" {
		return nil, fmt.Errorf("identity split requires setpriv (util-linux): not found at any absolute candidate path\n"+
			"  install util-linux; the sandvmm spawn drops to uid %d with zero capabilities through it", cfg.VMMUID)
	}
	out := []string{
		setpriv,
		"--reuid", fmt.Sprintf("%d", cfg.VMMUID),
		"--regid", fmt.Sprintf("%d", cfg.VMMGID),
	}
	if len(cfg.VMMGroups) > 0 {
		gids := make([]string, len(cfg.VMMGroups))
		for i, g := range cfg.VMMGroups {
			gids[i] = fmt.Sprintf("%d", g)
		}
		out = append(out, "--groups", strings.Join(gids, ","))
	} else {
		out = append(out, "--clear-groups")
	}
	// ZERO capabilities survive. The network provider creates the persistent
	// TAP owned by this uid and pre-configures its MTU/up state, so the VMM's
	// attach path (TUNSETIFF owner match; MTU and enable ioctls skipped when
	// already in the desired state) needs no CAP_NET_ADMIN. The uid (987) is
	// not the warden-trusted one, so the planted-file/compromise chains stay
	// dead, and a TAP-owner grant cannot touch the host's other interfaces or
	// the nftables isolation baseline.
	out = append(out, "--inh-caps=-all", "--ambient-caps=-all", "--", vmmBin)
	return append(out, args...), nil
}

// verifyIdentityStatus checks the four uid and four gid values in a
// /proc/<pid>/status body. setpriv is supposed to leave every one of them at
// the sandvmm identity; a saved-uid 0 left behind would let the FUSE daemon
// later setresuid(-1,0,-1) back to root, collapsing the split the VMM/FUSE
// identity exists for.
func verifyIdentityStatus(status string, wantUID, wantGID uint32) error {
	names := []string{"real", "effective", "saved", "fs"}
	var uidFields, gidFields []string
	for _, line := range strings.Split(status, "\n") {
		switch {
		case strings.HasPrefix(line, "Uid:"):
			uidFields = strings.Fields(line)
		case strings.HasPrefix(line, "Gid:"):
			gidFields = strings.Fields(line)
		}
	}
	check := func(kind string, fields []string, want uint32) error {
		if len(fields) != 5 {
			return fmt.Errorf("cannot parse the %s line from /proc/<pid>/status (%q)", kind, strings.Join(fields, " "))
		}
		for i, name := range names {
			v, err := strconv.ParseUint(fields[i+1], 10, 32)
			if err != nil {
				return fmt.Errorf("parse %s %s id %q: %w", kind, name, fields[i+1], err)
			}
			if uint32(v) != want {
				return fmt.Errorf("sandvmm child %s %s id = %d, want %d (all four must be the VMM identity)", kind, name, v, want)
			}
		}
		return nil
	}
	if err := check("uid", uidFields, wantUID); err != nil {
		return err
	}
	return check("gid", gidFields, wantGID)
}

// verifyChildIdentity reads /proc/<pid>/status until the setpriv wrapper has
// completed its uid transition (the first observation is the wrapper running
// as the PARENT identity, not the VMM) and validates the four-value shape.
// Called right after the spawn: a child that never proves the identity is
// killed instead of being served.
func verifyChildIdentity(pid int, wantUID, wantGID uint32) error {
	path := fmt.Sprintf("/proc/%d/status", pid)
	var lastErr error
	// Up to 2s: concurrent VM creation can delay the exec transition, and a
	// too-short window would fail a healthy launch under load.
	for i := 0; i < 400; i++ {
		data, err := os.ReadFile(path)
		if err == nil {
			if verr := verifyIdentityStatus(string(data), wantUID, wantGID); verr == nil {
				return nil
			} else {
				lastErr = verr
			}
		} else {
			lastErr = err
		}
		time.Sleep(5 * time.Millisecond)
	}
	return fmt.Errorf("sandvmm child identity not observed within 2s: %w", lastErr)
}

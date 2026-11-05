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

// boxout is a privileged VM lifecycle manager that runs as a K8s sidecar
// alongside the unprivileged sandlot. boxout owns:
//   - sandvmm process lifecycle (Launch, Kill, Shutdown)
//   - Network provisioning (TAP/IP via BridgeNAT)
//   - OverlayFS mount/unmount (CAP_SYS_ADMIN)
//   - /proc scanning for re-adopt
//   - Crash detection (pidfdMonitor + cmd.Wait)
// The request protocol lives in the server package; this file is the entry
// point: config, network provider construction, socket setup, and the
// config-file hot-reload watcher.

package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"common/config"
	"sandlot/bindreg"
	sandlotconfig "sandlot/config"
	"sandlot/core"
	"sandlot/hostbin"
	"sandlot/network"
	"sandlot/vmm"

	"boxout/server"

	"bytes"
	"gopkg.in/yaml.v3"
)

var (
	socketPath = flag.String("socket", "/run/sandswap-boxout/boxout.sock", "Unix socket path for sandlot communication (must live in a root-owned, non-shared directory)")
	configPath = flag.String("config", "", "Path to sandlot YAML config file (shares format with sandlot)")
	allowedUID = flag.Int("allowed-uid", 1001, "UID allowed to connect to the boxout socket (should match sandlot service account)")
	// Additional admission controls. SO_PEERCRED authenticates a UID, not the
	// sandlot process: a foreign pod/process that merely shares the UID could
	// otherwise drive root boxout. The token file must live in a pod-private
	// directory readable only by the sidecar pair.
	clientTokenFile = flag.String("client-token-file", "", "Per-pod client-token file shared with sandlot (empty = UID-only admission; not for production)")
	maxVMs          = flag.Int("max-vms", 256, "Maximum concurrent VMs boxout will launch (0 = unbounded)")
	maxTotalMemory  = flag.Int64("max-total-memory-mb", 0, "Aggregate guest memory cap in MiB (0 = 80% of host MemTotal)")

	// Volumes mount gate (invariant 8). Production never sets this: the
	// volumes tree must sit on a nosuid,nodev mount before a VM exports it.
	allowInsecureVolumes = flag.Bool("allow-insecure-volumes", false, "admit a volumes_dir that is NOT on a nosuid,nodev mount (dev/test only; guest-planted setuid bits and device nodes become live)")

	// Network flags (override config)
	networkBackend = flag.String("network-backend", "", "Network backend: none|bridge|routed-ipv6")
	networkBridge  = flag.String("bridge", "", "Host bridge name")
	networkSubnet  = flag.String("subnet", "", "Guest subnet (CIDR)")
	networkGateway = flag.String("gateway", "", "Guest gateway / host bridge IP")
	networkDNS     = flag.String("dns", "", "Comma-separated guest DNS nameservers")
	// Egress enabler flags (override config; same keys as sandlot).
	egressBaseline = flag.String("egress-baseline", "", "Egress network baseline: on|off (default from config; on when unset)")
	vmToVMPolicy   = flag.String("vm-to-vm-policy", "", "Guest-to-guest posture: deny|allow (default from config)")
	v6Prefix       = flag.String("network-v6-prefix", "", "routed-ipv6 site prefix (default from config)")
	iidTemplate    = flag.String("iid-template", "", "IPv6 IID layout for identity-in-address (default from config)")
)

// Version information — set via ldflags at build time (build/build.sh
// stamps every shipped binary uniformly; dev builds show the defaults).
var (
	Version   = "0.0.0-dev"
	Commit    = "unknown"
	BuildTime = "unknown"
)

func main() {
	showVer := flag.Bool("version", false, "Print version and exit")
	flag.Parse()
	if *showVer {
		fmt.Printf("boxout %s (commit %s, built %s)\n", Version, Commit, BuildTime)
		return
	}

	// Pin host utility paths once (nft/ip/cp/setpriv) before any privileged
	// network/VMM command; missing tools are reported by the call site.
	hostbin.Init()

	logger := log.New(os.Stdout, "[boxout] ", log.LstdFlags|log.Lmsgprefix)

	// Load config (same format as sandlot)
	cfg := sandlotconfig.Defaults()
	if *configPath != "" {
		fileCfg, err := sandlotconfig.LoadFromFile(*configPath)
		if err != nil {
			logger.Fatalf("failed to load config: %v", err)
		}
		cfg = fileCfg
		cfg.ConfigFilePath = *configPath
	}

	// Apply CLI overrides for network
	if *networkBackend != "" {
		cfg.Network.Backend = *networkBackend
	}
	if *networkBridge != "" {
		cfg.Network.Bridge = *networkBridge
	}
	if *networkSubnet != "" {
		cfg.Network.Subnet = *networkSubnet
	}
	if *networkGateway != "" {
		cfg.Network.Gateway = *networkGateway
	}
	if *networkDNS != "" {
		cfg.Network.DNS = *networkDNS
	}
	if *egressBaseline != "" {
		cfg.Network.EgressBaseline = *egressBaseline
	}
	if *vmToVMPolicy != "" {
		cfg.Network.VMToVM = *vmToVMPolicy
	}
	if *v6Prefix != "" {
		cfg.Network.V6Prefix = *v6Prefix
	}
	if *iidTemplate != "" {
		cfg.Network.IIDTemplate = *iidTemplate
	}
	// Record the same overrides so the reload path can re-apply them (see
	// startConfigReload): without this the diff compared a flag-applied startup
	// config against a raw file decode and logged phantom "requires a restart"
	// lines for every flag-provided key on each unrelated edit.
	cfg.SetFlagReapplier(func(c *sandlotconfig.SandlotConfig) {
		if *networkBackend != "" {
			c.Network.Backend = *networkBackend
		}
		if *networkBridge != "" {
			c.Network.Bridge = *networkBridge
		}
		if *networkSubnet != "" {
			c.Network.Subnet = *networkSubnet
		}
		if *networkGateway != "" {
			c.Network.Gateway = *networkGateway
		}
		if *networkDNS != "" {
			c.Network.DNS = *networkDNS
		}
		if *egressBaseline != "" {
			c.Network.EgressBaseline = *egressBaseline
		}
		if *vmToVMPolicy != "" {
			c.Network.VMToVM = *vmToVMPolicy
		}
		if *v6Prefix != "" {
			c.Network.V6Prefix = *v6Prefix
		}
		if *iidTemplate != "" {
			c.Network.IIDTemplate = *iidTemplate
		}
	})

	// One boxout per sandbox root. boxout owns host-global state for its root
	// (VM sockets, host-side overlay mounts, the /proc re-adopt scan), so a
	// second instance pointed at the same root races all of it. The lock is
	// fd-validated and lives in the private state root — never in the
	// group-writable runtime dir — and its content is never trusted.
	sandboxRoot := server.InstanceSandboxRoot(cfg)
	instanceLock, err := acquireInstanceLock(core.StateRootFor(sandboxRoot), sandboxRoot, logger)
	if err != nil {
		logger.Fatalf("%v", err)
	}
	defer instanceLock.Close()

	if *allowInsecureVolumes {
		logger.Printf("WARNING: -allow-insecure-volumes set — guest-planted setuid bits and device nodes on the volumes tree are LIVE (invariant 8 violated). Dev/test only.")
	} else if err := server.VolumesMountGate(cfg.MicroVM.VolumesDir); err != nil {
		logger.Printf("WARNING: %v (create_vm will refuse until the mount is fixed)", err)
	}

	// Build network provider (shared factory with sandlot's embedded mode —
	// boxout is the privileged side in k8s, so the baseline and the backend
	// are installed HERE)
	netProv, err := network.BuildProvider(cfg.Network, cfg.MicroVM.VMMUid, logger)
	if err != nil {
		logger.Fatalf("%v", err)
	}

	// Egress identity binding region (bpf carrier, boxout mode): boxout is
	// the privileged side, so it creates + pins the region and hands it to
	// the unprivileged sandlot: bpffs root made traversable (0711), the pin
	// file owned by the sandlot UID with owner-rw (0660). sandlot then opens
	// it via the no-CAP_BPF fallback (BPF_OBJ_GET + mmap write), which is
	// verified end-to-end by TestBPFUnprivilegedWrite in sandlot/bindreg.
	if cfg.Network.BindBackend == "bpf" {
		pinPath := cfg.Network.BindPath
		if pinPath == "" {
			pinPath = bindreg.DefaultBPFPath
		}
		region, err := bindreg.Open(bindreg.Config{Backend: bindreg.BackendBPF, Path: pinPath})
		if err != nil {
			logger.Fatalf("binding region (bpf) at %s: %v", pinPath, err)
		}
		if err := region.Close(); err != nil {
			logger.Printf("warning: binding region close: %v", err)
		}
		if dir := filepath.Dir(pinPath); dir != "/sys/fs/bpf" {
			if err := os.Chmod(dir, 0o711); err != nil {
				logger.Printf("warning: chmod bpffs dir %s: %v", dir, err)
			}
		}
		// The bpffs ROOT ships 0700 root-owned: without the traversal bit the
		// unprivileged sandlot (UID 1001) cannot even stat the pin path, let
		// alone open it. This is the documented operator step — automate it
		// here (idempotent) so the handoff works out of the box.
		if err := os.Chmod("/sys/fs/bpf", 0o711); err != nil {
			logger.Printf("warning: chmod bpffs root /sys/fs/bpf: %v", err)
		}
		if err := os.Chown(pinPath, *allowedUID, *allowedUID); err != nil {
			logger.Printf("warning: chown binding region to uid %d: %v", *allowedUID, err)
		}
		if err := os.Chmod(pinPath, 0o660); err != nil {
			logger.Printf("warning: chmod binding region: %v", err)
		}
		logger.Printf("binding region (bpf) ready for uid %d at %s", *allowedUID, pinPath)
	}

	// VMM config from sandlot config
	vmmCfg := vmm.Config{
		KernelPath:    cfg.MicroVM.Kernel,
		InitramfsPath: cfg.MicroVM.Initramfs,
		VCPUs:         cfg.MicroVM.DefaultVCPUs,
		MemoryMB:      cfg.MicroVM.DefaultMemoryMB,
		VMMBinary:     cfg.VMMBinary,
		VolumesDir:    cfg.MicroVM.VolumesDir,
		TemplatesDir:  cfg.MicroVM.OverlayFSTemplates,
		// sandvmm identity split — the same wiring as the embedded launcher
		// (cmd/main.go): the VMM child drops to the dedicated uid/gid and
		// creates its API sockets 0660 owner:vmm-gid with the APIGID group
		// grant. In k8s the split is numeric (vmm_uid 987, api_gid = the
		// pod's shared group), so the unprivileged sandlot (runAsUser 1001)
		// dials the sockets as a group member. Restart-required like the
		// rest of the identity block: UpdateVMMConfig deliberately does NOT
		// hot-apply these — a live ownership change would strand
		// already-running VMs on the old identity.
		VMMUID:      cfg.MicroVM.VMMUid,
		VMMGID:      cfg.MicroVM.VMMGid,
		VMMGroups:   resolveVMMGroups(cfg.MicroVM.VMMGroups, cfg.MicroVM.APIGid, logger),
		APIGID:      cfg.MicroVM.APIGid,
		SeccompMode: cfg.MicroVM.VMMSeccomp,
		VMMAPIAuth:  cfg.MicroVM.VMMAPIAuth,
		// Guest free-wipe posture from the shared YAML (microvm.init_on_free;
		// default false = init_on_free=0 on every VM cmdline). Restart-required
		// like the rest of this block: the create_vm request does not carry it
		// and the hot-reload subset (kernel/initramfs/vcpus/mem) deliberately
		// excludes posture knobs.
		InitOnFree: cfg.MicroVM.InitOnFree,
	}

	// Ensure the sandbox root dir is traversable by sandlot (allowed UID).
	// vmm.Launch creates per-VM subdirs inside this root; if the root is
	// 0700 (from a previous run or default mkdir), sandlot cannot reach
	// the sandvmm Unix sockets inside.
	// 0711: owner rwx, group/other traverse only — prevents unauthorized
	// users from listing VM directories (no r for group/other).
	if err := vmm.EnsureSandboxRoot(sandboxRoot, 0711); err != nil {
		logger.Fatalf("sandbox root %s: %v", sandboxRoot, err)
	}

	srv := server.New(cfg, vmmCfg, netProv, uint32(*allowedUID), logger)
	srv.SetAllowInsecureVolumes(*allowInsecureVolumes)
	if *clientTokenFile != "" {
		token, terr := loadOrCreateClientToken(*clientTokenFile, *allowedUID)
		if terr != nil {
			logger.Fatalf("client token %s: %v", *clientTokenFile, terr)
		}
		srv.SetClientToken(token)
	} else {
		logger.Printf("WARNING: -client-token-file is not set — boxout admission relies on the peer UID alone")
	}
	totalMemMB := uint64(*maxTotalMemory)
	if totalMemMB == 0 {
		totalMemMB = hostMemoryLimitMB()
	}
	srv.SetLimits(*maxVMs, totalMemMB)
	// Persist the overlay tracking map (volumePath → template ref) beside the
	// socket: a restart restores not just which overlays exist but WHICH
	// template each serves — the swap-staleness check needs the ref, and
	// mountinfo cannot provide it. Best-effort (a lost file costs one
	// remount per volume after restart, never correctness).
	srv.SetOverlayStatePath(filepath.Join(core.StateRootFor(sandboxRoot), "boxout-overlays.json"))

	// Hot-reload the microvm subset from the shared sandlot config file.
	// boxout's create_vm whitelist compares kernel/initramfs against its own
	// vmmCfg: without this watcher, a sandlot-side microvm hot-reload (new
	// kernel path) would have every subsequent create_vm REJECTED until
	// boxout restarts. The two processes watch the same file independently,
	// so a reload can land here up to ~one watch-interval after sandlot's —
	// a create_vm racing that window fails once and the 60s reconcile
	// refills; no cross-process coordination is worth that complexity.
	// Network settings and everything else stay restart-required (the
	// provider is built at startup).
	startConfigReload(cfg, srv, logger)

	// Create and listen on Unix socket.
	//
	// The socket lives in a boxout-DEDICATED, root-owned directory (0711:
	// traverse only) — never in the sandlot-writable runtime dir. There a
	// same-UID process could rename the socket and bind its own listener at
	// the path; with token (and HMAC) authentication that still cannot forge
	// an accepted server response, but the whole class is removed by not
	// sharing the directory at all.
	sockDir := filepath.Dir(*socketPath)
	if err := prepareSocketDir(sockDir); err != nil {
		logger.Fatalf("boxout socket dir %s: %v", sockDir, err)
	}
	// Remove a stale socket. The directory gate above proves no other identity
	// could have placed it there, so anything that is not a socket at the path
	// is a real configuration error, not debris.
	if fi, err := os.Lstat(*socketPath); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			logger.Fatalf("%s exists and is not a socket (mode %v) — refusing to replace it", *socketPath, fi.Mode())
		}
		if err := os.Remove(*socketPath); err != nil {
			logger.Fatalf("remove stale socket %s: %v", *socketPath, err)
		}
	} else if !os.IsNotExist(err) {
		logger.Fatalf("lstat socket %s: %v", *socketPath, err)
	}
	// Bounded retry: a restart racing the previous instance's socket teardown
	// must not turn into a crash-loop (each restart re-opened the
	// socket-permission race window).
	lis, err := listenWithRetry(*socketPath, logger)
	if err != nil {
		logger.Fatalf("listen on %s: %v", *socketPath, err)
	}
	// Hand the socket to the sandlot identity 0600 and VERIFY it: only the
	// sandlot process can connect, and the file at the path is provably the
	// socket this listener created.
	if err := secureListeningSocket(*socketPath, *allowedUID, logger); err != nil {
		lis.Close()
		logger.Fatalf("secure socket %s: %v", *socketPath, err)
	}

	logger.Printf("boxout listening on %s", *socketPath)

	// Handle shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		logger.Printf("received %v, shutting down", sig)
		cancel()
		lis.Close()
	}()

	// Overlay tracking: restore the set from this process's mount namespace at
	// startup (a sidecar restarted within a live pod picks up whatever mounts
	// survived), then reap stale overlays on the same cadence as embedded
	// mode's StartOverlayReaper. The sandlot-side restore_overlays /
	// cleanup_overlays requests (sent at its startup) cover the normal
	// recovery path; the ticker is the same pure-fallback role it plays in
	// embedded mode. The set logs its own results.
	if n := srv.Overlays().RestoreFromMountinfo(vmmCfg.VolumesDir); n > 0 {
		logger.Printf("overlay tracking: %d mount(s) restored from mountinfo", n)
	}
	go func() {
		t := time.NewTicker(core.OverlayReaperInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				srv.Overlays().CleanupStale(core.UnmountOverlay)
			}
		}
	}()

	// Accept connections
	go func() {
		for {
			conn, err := lis.Accept()
			if err != nil {
				select {
				case <-ctx.Done():
					return
				default:
					logger.Printf("accept: %v", err)
					continue
				}
			}
			go srv.HandleConn(ctx, conn)
		}
	}()

	<-ctx.Done()
	logger.Printf("boxout shutting down")
}

// prepareSocketDir creates and validates the boxout socket directory: it must
// be a directory this (root) identity owns and no other identity can write
// (0711 = traverse only). A shared or non-root-owned directory would let a
// same-UID process replace the socket entry at will.
func prepareSocketDir(dir string) error {
	if err := os.MkdirAll(dir, 0o711); err != nil {
		return fmt.Errorf("create: %w", err)
	}
	// MkdirAll honors the umask; normalize explicitly.
	if err := os.Chmod(dir, 0o711); err != nil {
		return fmt.Errorf("chmod: %w", err)
	}
	var st unix.Stat_t
	if err := unix.Lstat(dir, &st); err != nil {
		return fmt.Errorf("lstat: %w", err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return fmt.Errorf("%s is not a directory", dir)
	}
	if st.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("%s is owned by uid %d, not the boxout identity %d — the socket must live in a directory only the sidecar can write", dir, st.Uid, os.Geteuid())
	}
	if st.Mode&0o022 != 0 {
		return fmt.Errorf("%s is group/world-writable (mode %04o) — a same-UID process could replace the socket entry; use a boxout-private directory", dir, st.Mode&0o7777)
	}
	return nil
}

// listenWithRetry binds the Unix socket with a bounded retry. A boxout restart
// racing the previous instance's teardown (the listener takes a moment to
// release the path) must not crash-loop the sidecar.
func listenWithRetry(path string, logger *log.Logger) (net.Listener, error) {
	var lastErr error
	for attempt := 0; attempt < 5; attempt++ {
		lis, err := net.Listen("unix", path)
		if err == nil {
			return lis, nil
		}
		lastErr = err
		logger.Printf("listen %s (attempt %d/5): %v", path, attempt+1, err)
		time.Sleep(time.Duration(attempt+1) * 100 * time.Millisecond)
	}
	return nil, lastErr
}

// secureListeningSocket hands the freshly bound socket to the sandlot identity
// 0600 and VERIFIES the result. Every operation is relative to an O_NOFOLLOW
// directory fd, never a path that resolves from /run: fchmod(2) on the
// listener's own descriptor would act on the sockfs inode, not the filesystem
// entry, so the directory-relative fchownat/fchmodat plus the inode-identity
// post-check is the fd-relative form that actually covers the entry. A
// mismatch (the entry was replaced between bind and chmod) fails startup.
func secureListeningSocket(path string, uid int, logger *log.Logger) error {
	name := filepath.Base(path)
	dirFD, err := unix.Open(filepath.Dir(path), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open socket dir (no-follow): %w", err)
	}
	defer unix.Close(dirFD)
	var before unix.Stat_t
	if err := unix.Fstatat(dirFD, name, &before, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return fmt.Errorf("stat socket (no-follow): %w", err)
	}
	if before.Mode&unix.S_IFMT != unix.S_IFSOCK {
		return fmt.Errorf("%s is not a socket (mode %04o)", path, before.Mode&0o7777)
	}
	if err := unix.Fchownat(dirFD, name, uid, uid, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return fmt.Errorf("chown socket: %w", err)
	}
	if err := unix.Fchmodat(dirFD, name, 0o600, 0); err != nil {
		return fmt.Errorf("chmod socket: %w", err)
	}
	var after unix.Stat_t
	if err := unix.Fstatat(dirFD, name, &after, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return fmt.Errorf("stat socket after chmod: %w", err)
	}
	if after.Ino != before.Ino || after.Dev != before.Dev {
		return fmt.Errorf("socket entry at %s was replaced during permission setup (inode %d→%d) — refusing to serve", path, before.Ino, after.Ino)
	}
	if after.Mode&unix.S_IFMT != unix.S_IFSOCK || after.Uid != uint32(uid) || after.Mode&0o777 != 0o600 {
		return fmt.Errorf("socket %s is mode %04o uid %d after setup, want 0600 uid %d", path, after.Mode&0o7777, after.Uid, uid)
	}
	logger.Printf("socket %s: mode 0600 owner uid %d (verified)", path, uid)
	return nil
}

// startConfigReload watches the sandlot config file and hot-applies the
// microvm subset (kernel, initramfs, default resources). Everything else is
// logged as restart-required — the same classification sandlot applies, so
// the two processes stay consistent.
func startConfigReload(cfg sandlotconfig.SandlotConfig, srv *server.Server, logger *log.Logger) *config.ReloadWatcher {
	if cfg.ConfigFilePath == "" {
		return nil
	}

	watchableCfg := config.NewWatchableConfig(cfg)
	// The startup CLI overrides (bridge/subnet/gateway/dns/…) must be re-applied
	// to every decoded revision, exactly as sandlot and the gateway do: without
	// it each unrelated file edit re-logged phantom "requires a restart" lines
	// for every flag-provided key (the diff compared the flag-applied startup
	// config against a raw file decode).
	_, err := config.NewReloadWatcher(cfg.ConfigFilePath, func(content []byte) {
		newCfg := sandlotconfig.Defaults()
		dec := yaml.NewDecoder(bytes.NewReader(content))
		dec.KnownFields(true) // strict (shares sandlot's config: unknown keys are errors)
		if err := dec.Decode(&newCfg); err != nil {
			logger.Printf("config reload: failed to parse YAML (strict: unknown keys are errors): %v", err)
			return
		}
		prev := watchableCfg.Get()
		if err := sandlotconfig.ReapplyStartupFlags(&prev, &newCfg); err != nil {
			logger.Printf("config reload: refusing the edit (%v); keeping the previous config", err)
			return
		}
		if err := newCfg.Validate(); err != nil {
			logger.Printf("config reload: invalid values (%v); keeping the previous config", err)
			return
		}
		cs := watchableCfg.Swap(newCfg).Diff(newCfg)
		for _, fc := range cs.HotReload {
			switch fc.Name {
			case "microvm.kernel", "microvm.initramfs",
				"microvm.default_vcpus", "microvm.default_memory_mb":
				srv.UpdateVMMConfig(newCfg.MicroVM.Kernel, newCfg.MicroVM.Initramfs,
					newCfg.MicroVM.DefaultVCPUs, newCfg.MicroVM.DefaultMemoryMB)
			}
			// microvm.warden_* are restart-required (the shared classifier
			// marks only microvm.{kernel,initramfs,default_vcpus,
			// default_memory_mb} hot) and are deliberately not applied
			// here: the warden cmdline (countdown / max exec timeout / log)
			// is built per create_vm from this vmmCfg, so a hot-applied
			// change would silently split the node's pool across two cmdline
			// shapes (and an online warden_log=debug flip would tax the
			// guest console on every new VM).
		}
		for _, fc := range cs.RestartReq {
			logger.Printf("config reload: %s changed but requires a restart (not applied): %v -> %v",
				fc.Name, fc.Old, fc.New)
		}
	})
	if err != nil {
		logger.Printf("warning: failed to watch config %s: %v (microvm hot-reload disabled)", cfg.ConfigFilePath, err)
		return nil
	}
	logger.Printf("config hot-reload watcher started (microvm.* only): %s", cfg.ConfigFilePath)
	return nil
}

// resolveVMMGroups turns the microvm.vmm_groups spec (comma-separated
// numeric gids or group NAMES) into the sandvmm child's supplementary group
// list — same contract as the embedded side's resolver (cmd/main.go), kept
// local because the boxout module cannot import sandlot's package main.
// The API gid is always included so the socket chgrp (group-membership
// only, no CAP_CHOWN needed) succeeds. In k8s the spec is numeric by
// construction (deploy-lib host-injects the kvm gid); name lookup stays
// for dev runs, warn-and-skip on unresolvable entries (a missing "kvm"
// group only costs /dev/kvm, surfacing loudly at the first create).
func resolveVMMGroups(spec string, apiGid uint32, logger *log.Logger) []uint32 {
	var out []uint32
	seen := map[uint32]bool{}
	add := func(g uint32) {
		if g != 0 && !seen[g] {
			seen[g] = true
			out = append(out, g)
		}
	}
	for _, tok := range strings.Split(spec, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		if n, err := strconv.ParseUint(tok, 10, 32); err == nil {
			add(uint32(n))
			continue
		}
		g, err := user.LookupGroup(tok)
		if err != nil {
			logger.Printf("warning: microvm.vmm_groups entry %q unresolvable (skipped): %v", tok, err)
			continue
		}
		if n, err := strconv.ParseUint(g.Gid, 10, 32); err == nil {
			add(uint32(n))
		}
	}
	add(apiGid)
	return out
}

// loadOrCreateClientToken reads the per-pod token shared with sandlot, or
// creates it on first start. The file must live in a pod-private directory
// (an emptyDir shared by the two containers), mode 0400 owned by the sandlot
// UID. A pre-existing valid token is reused so a boxout restart does not
// invalidate the sandlot's copy.
func loadOrCreateClientToken(path string, allowedUID int) (string, error) {
	if data, err := os.ReadFile(path); err == nil {
		tok := strings.TrimSpace(string(data))
		if raw, derr := hex.DecodeString(tok); derr == nil && len(raw) == sha256.Size {
			return tok, nil
		}
		return "", fmt.Errorf("existing token file is malformed (want 64 hex characters)")
	} else if !os.IsNotExist(err) {
		return "", err
	}
	var raw [sha256.Size]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	tok := hex.EncodeToString(raw[:])
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(tok+"\n"), 0o400); err != nil {
		return "", err
	}
	if err := os.Chown(tmp, allowedUID, allowedUID); err != nil {
		os.Remove(tmp)
		return "", err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return "", err
	}
	return tok, nil
}

// hostMemoryLimitMB derives the default aggregate cap: 80% of MemTotal.
// 0 on an unreadable /proc/meminfo (the count limit still applies).
func hostMemoryLimitMB() uint64 {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				if kb, err := strconv.ParseUint(fields[1], 10, 64); err == nil {
					return kb / 1024 * 8 / 10
				}
			}
			break
		}
	}
	return 0
}

// acquireInstanceLock enforces one boxout per sandbox root.
//
// boxout owns host-global state for its root — VM API sockets, host-side
// overlay mounts, the /proc re-adopt scan — so a second instance aimed at the
// same root would race every one of those. The lock file lives in the PRIVATE
// per-instance state root (/run/sandswap-state/<tag>, root-owned 0710), which
// the unprivileged sandlot cannot write; the descriptor is validated (regular
// file, owned by this identity, mode 0600) before the flock, so a file planted
// at the lock path makes the start fail closed instead of being "locked
// through". The file's CONTENT is written for operator diagnostics only and is
// never read or used for a decision.
func acquireInstanceLock(stateRoot, sandboxRoot string, logger *log.Logger) (*os.File, error) {
	if err := os.MkdirAll(stateRoot, 0o710); err != nil {
		return nil, fmt.Errorf("boxout lock: create %s: %w", stateRoot, err)
	}
	rfd, err := unix.Open(stateRoot, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("boxout lock: open state root %s (no-follow): %w", stateRoot, err)
	}
	defer unix.Close(rfd)
	var rst unix.Stat_t
	if err := unix.Fstat(rfd, &rst); err != nil {
		return nil, fmt.Errorf("boxout lock: fstat state root: %w", err)
	}
	if rst.Mode&unix.S_IFMT != unix.S_IFDIR || rst.Uid != uint32(os.Geteuid()) {
		return nil, fmt.Errorf("boxout lock: state root %s is not a directory owned by uid %d (mode %04o, uid %d) — refusing to lock in it",
			stateRoot, os.Geteuid(), rst.Mode&0o777, rst.Uid)
	}

	const lockName = "boxout.lock"
	fd, err := unix.Openat(rfd, lockName, unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("boxout lock: open %s/%s (no-follow): %w", stateRoot, lockName, err)
	}
	keep := false
	defer func() {
		if !keep {
			unix.Close(fd)
		}
	}()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, fmt.Errorf("boxout lock: fstat lock file: %w", err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, fmt.Errorf("boxout lock: %s/%s is not a regular file (mode %04o)", stateRoot, lockName, st.Mode&0o777)
	}
	if st.Uid != uint32(os.Geteuid()) {
		return nil, fmt.Errorf("boxout lock: %s/%s is owned by uid %d, not the writer uid %d — refusing to use it",
			stateRoot, lockName, st.Uid, os.Geteuid())
	}
	if err := unix.Fchmod(fd, 0o600); err != nil {
		return nil, fmt.Errorf("boxout lock: chmod lock file: %w", err)
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, fmt.Errorf("another boxout instance already manages %s (lock %s/%s is held) — one boxout per sandbox root",
				sandboxRoot, stateRoot, lockName)
		}
		return nil, fmt.Errorf("boxout lock: flock: %w", err)
	}

	// Diagnostic line only (see the function comment): content is never read.
	_ = unix.Ftruncate(fd, 0)
	_, _ = syscall.Write(fd, []byte(fmt.Sprintf("%d|%s\n", os.Getpid(), sandboxRoot)))

	keep = true
	path := filepath.Join(stateRoot, lockName)
	logger.Printf("instance lock held for sandbox root %s (%s)", sandboxRoot, path)
	return os.NewFile(uintptr(fd), path), nil
}

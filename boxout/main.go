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
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"sandlot/bindreg"
	sandlotconfig "sandlot/config"
	"sandlot/core"
	"sandlot/hostbin"
	"sandlot/network"
	"sandlot/vmm"

	"boxout/runtime"
	"boxout/server"
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
	instanceLock, err := runtime.AcquireInstanceLock(core.StateRootFor(sandboxRoot), sandboxRoot, logger)
	if err != nil {
		logger.Fatalf("%v", err)
	}
	defer instanceLock.Close()

	if *allowInsecureVolumes {
		logger.Printf("WARNING: -allow-insecure-volumes set — guest-planted setuid bits and device nodes on the volumes tree are LIVE (invariant 8 violated). Dev/test only.")
	} else if err := server.VolumesMountGate(cfg.TinyVM.VolumesDir); err != nil {
		logger.Printf("WARNING: %v (create_vm will refuse until the mount is fixed)", err)
	}

	// Build network provider (shared factory with sandlot's embedded mode —
	// boxout is the privileged side in k8s, so the baseline and the backend
	// are installed HERE)
	netProv, err := network.BuildProvider(cfg.Network, cfg.TinyVM.VMMUid, logger)
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
		KernelPath:    cfg.TinyVM.Kernel,
		InitramfsPath: cfg.TinyVM.Initramfs,
		VCPUs:         cfg.TinyVM.DefaultVCPUs,
		MemoryMB:      cfg.TinyVM.DefaultMemoryMB,
		VMMBinary:     cfg.VMMBinary,
		VolumesDir:    cfg.TinyVM.VolumesDir,
		TemplatesDir:  cfg.TinyVM.OverlayFSTemplates,
		// sandvmm identity split — the same wiring as the embedded launcher
		// (cmd/main.go): the VMM child drops to the dedicated uid/gid and
		// creates its API sockets 0660 owner:vmm-gid with the APIGID group
		// grant. In k8s the split is numeric (vmm_uid 987, api_gid = the
		// pod's shared group), so the unprivileged sandlot (runAsUser 1001)
		// dials the sockets as a group member. Restart-required like the
		// rest of the identity block: UpdateVMMConfig deliberately does NOT
		// hot-apply these — a live ownership change would strand
		// already-running VMs on the old identity.
		VMMUID:      cfg.TinyVM.VMMUid,
		VMMGID:      cfg.TinyVM.VMMGid,
		VMMGroups:   runtime.ResolveVMMGroups(cfg.TinyVM.VMMGroups, cfg.TinyVM.APIGid, logger),
		APIGID:      cfg.TinyVM.APIGid,
		SeccompMode: cfg.TinyVM.VMMSeccomp,
		VMMAPIAuth:  cfg.TinyVM.VMMAPIAuth,
		// Guest free-wipe posture from the shared YAML (tinyvm.init_on_free;
		// default false = init_on_free=0 on every VM cmdline). Restart-required
		// like the rest of this block: the create_vm request does not carry it
		// and the hot-reload subset (kernel/initramfs/vcpus/mem) deliberately
		// excludes posture knobs.
		InitOnFree: cfg.TinyVM.InitOnFree,
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
		token, terr := runtime.LoadOrCreateClientToken(*clientTokenFile, *allowedUID)
		if terr != nil {
			logger.Fatalf("client token %s: %v", *clientTokenFile, terr)
		}
		srv.SetClientToken(token)
	} else {
		logger.Printf("WARNING: -client-token-file is not set — boxout admission relies on the peer UID alone")
	}
	totalMemMB := uint64(*maxTotalMemory)
	if totalMemMB == 0 {
		totalMemMB = runtime.HostMemoryLimitMB()
	}
	srv.SetLimits(*maxVMs, totalMemMB)
	// Persist the overlay tracking map (volumePath → template ref) beside the
	// socket: a restart restores not just which overlays exist but WHICH
	// template each serves — the swap-staleness check needs the ref, and
	// mountinfo cannot provide it. Best-effort (a lost file costs one
	// remount per volume after restart, never correctness).
	srv.SetOverlayStatePath(filepath.Join(core.StateRootFor(sandboxRoot), "boxout-overlays.json"))

	// Hot-reload the tinyvm subset from the shared sandlot config file.
	// boxout's create_vm whitelist compares kernel/initramfs against its own
	// vmmCfg: without this watcher, a sandlot-side tinyvm hot-reload (new
	// kernel path) would have every subsequent create_vm REJECTED until
	// boxout restarts. The two processes watch the same file independently,
	// so a reload can land here up to ~one watch-interval after sandlot's —
	// a create_vm racing that window fails once and the 60s reconcile
	// refills; no cross-process coordination is worth that complexity.
	// Network settings and everything else stay restart-required (the
	// provider is built at startup).
	runtime.StartConfigReload(cfg, srv, logger)

	// Create and listen on Unix socket.
	//
	// The socket lives in a boxout-DEDICATED, root-owned directory (0711:
	// traverse only) — never in the sandlot-writable runtime dir. There a
	// same-UID process could rename the socket and bind its own listener at
	// the path; with token (and HMAC) authentication that still cannot forge
	// an accepted server response, but the whole class is removed by not
	// sharing the directory at all.
	sockDir := filepath.Dir(*socketPath)
	if err := runtime.PrepareSocketDir(sockDir); err != nil {
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
	lis, err := runtime.ListenWithRetry(*socketPath, logger)
	if err != nil {
		logger.Fatalf("listen on %s: %v", *socketPath, err)
	}
	// Hand the socket to the sandlot identity 0600 and VERIFY it: only the
	// sandlot process can connect, and the file at the path is provably the
	// socket this listener created.
	if err := runtime.SecureListeningSocket(*socketPath, *allowedUID, logger); err != nil {
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

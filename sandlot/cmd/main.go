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

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"common/config"
	"sandlot/bindreg"
	sandlotconfig "sandlot/config"
	"sandlot/core"
	"sandlot/hostbin"
	"sandlot/network"
	"sandlot/provision/seed"
	"sandlot/provision/template"
	"sandlot/provision/volname"
	"sandlot/provision/volume"
	"sandlot/rpc"
	"sandlot/vmm"
	"sandlot/warden"
)

var (
	configPath    = flag.String("config", "", "Path to YAML config file (optional; CLI flags override config values)")
	gatewayAddr   = flag.String("gateway-addr", sandlotconfig.DefaultGatewayAddr, "Gateway stream server address")
	nodeID        = flag.String("node-id", "", "Unique node identifier (defaults to hostname)")
	kernelPath    = flag.String("kernel", sandlotconfig.DefaultKernelPath, "Path to kernel image")
	initramfsPath = flag.String("initramfs", sandlotconfig.DefaultInitramfsPath, "Path to initramfs")
	defaultVCPUs  = flag.Int("default-vcpus", sandlotconfig.DefaultVCPUs, "Default VM vCPUs")
	defaultMemMB  = flag.Int("default-memory", sandlotconfig.DefaultMemoryMB, "Default VM memory in MB")
	vmmBinary     = flag.String("vmm-binary", sandlotconfig.DefaultVMMBinary, "Path to sandvmm binary")
	volumesDir    = flag.String("volumes-dir", sandlotconfig.DefaultVolumesDir, "Host directory shared via virtio-fs for agent volumes")
	templatesDir  = flag.String("overlayfs-templates", "", "Template store directory (layers/ + refs/) for OverlayFS lowerdirs AND the prov role (empty = <volumes-dir sibling>/templates)")
	poolSpec      = flag.String("pool", "", "Pre-create VM pool: comma-separated spec:count pairs (e.g., 'small:2,medium:3,large:1')")
	tlsCert       = flag.String("tls-cert", "", "TLS client certificate for the gateway stream (mTLS). Empty = plaintext (dev only).")
	tlsKey        = flag.String("tls-key", "", "TLS client private key (required if -tls-cert set)")
	tlsCA         = flag.String("tls-ca", "", "CA bundle to verify the gateway server cert (enables server verification). Empty = skip verify.")

	// Outbound networking for pooled microVMs.
	networkBackend = flag.String("network-backend", sandlotconfig.DefaultNetworkBackend, "outbound net backend: none|bridge|routed-ipv6")
	networkBridge  = flag.String("network-bridge", sandlotconfig.DefaultNetworkBridge, "host bridge (bridge backend)")
	networkSubnet  = flag.String("network-subnet", sandlotconfig.DefaultNetworkSubnet, "guest subnet (CIDR)")
	networkGateway = flag.String("network-gateway", sandlotconfig.DefaultNetworkGateway, "guest gateway / host bridge IP")
	networkDNS     = flag.String("network-dns", sandlotconfig.DefaultNetworkDNS, "comma-separated guest DNS nameservers")

	// Egress identity binding region (third-party network policy enabler).
	bindingBackend       = flag.String("binding-backend", "off", "egress identity binding region carrier: off|shm|bpf (docs/how-it-works/egress-enabler.md)")
	requireEgressBinding = flag.Bool("require-egress-binding", false, "refuse to start an exec-role instance when no egress identity enabler is configured (Carrier A binding-backend=shm|bpf, or Carrier B network-backend=routed-ipv6 + iid-template). Production should set this; unset means a loud WARN + egress_binding=none in /stats")
	bindingPath          = flag.String("binding-path", "", "binding region location override (shm file or bpffs pin path; empty = per-backend default)")
	// Egress network baseline (anti-spoof + VM isolation + mount gate).
	egressBaseline = flag.String("egress-baseline", sandlotconfig.DefaultEgressBaseline, "egress network baseline: on|off (requires nftables; FAIL-CLOSED: missing nftables or a failed table install refuses to start — set off explicitly for a per-VM-only deployment)")
	vmToVMPolicy   = flag.String("vm-to-vm-policy", sandlotconfig.DefaultVMToVM, "guest-to-guest traffic posture: deny|allow")
	// Routed-IPv6 backend (identity-in-address pattern).
	networkV6Prefix = flag.String("network-v6-prefix", sandlotconfig.DefaultV6Prefix, "routed-ipv6 site prefix (multiple-of-8 length, <= /48)")
	iidTemplate     = flag.String("iid-template", "", "IPv6 IID layout for identity-in-address (e.g. \"agent:32,epoch:32\" or \"deployment:16=42,agent:32,epoch:16\"; empty = stamping disabled)")
	debugOpLog      = flag.Bool("debug", false, "Enable per-op success-path logging (mount/exec/unmount/file_op timings, VM boot/ready). Off by default: a busy node performs thousands of ops/sec and these lines flood the log AND sit on the response path (unbuffered stdout write before the handler returns). Error/warning lines are always logged.")
	gogcFlag        = flag.Int("gogc", 0, "GC target percentage (restart-required). 0 = auto: honor the GOGC env var if set, else apply 200 (halves GC frequency vs Go's default 100 for lower tail latency). Positive = force. Negative = rejected (would disable the GC).")
	gomemlimitFlag  = flag.String("gomemlimit", "", "Go runtime soft memory limit, e.g. 512MiB, 8GiB (restart-required). Empty = honor the GOMEMLIMIT env var if set, else no limit. In memory-constrained deployments set it to ~90% of the container/host budget.")

	// Recycle
	maxUses       = flag.Int("max-uses", sandlotconfig.DefaultMaxUses, "Destroy+recreate a VM after it serves this many commands (-1 = unlimited, 0 = disable; other negatives invalid; counts execs and file ops, warm and cold); default 100000 to match config file (raised from 10000: a recycled VM's first ops carry a cold-guest tax and an occasional ~20ms tail — the recycle now effectively only fires on the memory thresholds)")
	recycleMemPct = flag.Int("recycle-mem-percent", sandlotconfig.DefaultRecycleMemPercent, "Recycle when guest MemAvailable < MemTotal × this / 100 (0 = disable)")
	recycleMemAbs = flag.Int("recycle-mem-abs-mb", sandlotconfig.DefaultRecycleMemAbsMB, "Absolute recycle threshold (MiB) of guest MemAvailable (0 = disable). Effective threshold is the lower (min) of the enabled thresholds: pct decides on small VMs, abs decides on large VMs; clamped to ≤ 50% of MemTotal")
	minIdleFloor  = flag.Float64("min-idle-floor-frac", sandlotconfig.DefaultMinIdleFloorFrac, "Maintain per-spec CLEAN headroom of max(1, floor(frac*target)) on top of pool target (min-idle floor dampener; 0 = disabled, 0.05 = 5%). Hot-reloadable.")
	vmCreateConc  = flag.Int("vm-create-concurrency", sandlotconfig.DefaultVMCreateConcurrency, "Maximum microVMs booting at once during pool scale-up / reconcile / startup pre-create (>= 1; restart-required)")
	vmDestroyConc = flag.Int("vm-destroy-concurrency", sandlotconfig.DefaultVMDestroyConcurrency, "Maximum idle microVMs destroyed at once during pool scale-down (>= 1; restart-required)")

	// VM mode
	vmMode          = flag.String("vm-mode", sandlotconfig.DefaultVMMode, "VM lifecycle mode: embedded (default, direct) or boxout (sidecar)")
	boxoutSocket    = flag.String("boxout-socket", sandlotconfig.DefaultBoxoutSocket, "Unix socket path for boxout mode")
	boxoutTokenFile = flag.String("boxout-token-file", "", "Per-pod admission token file shared with boxout (empty = UID-only admission; set this in production boxout deployments)")
	setfsTransport  = flag.String("setfs-transport", sandlotconfig.DefaultSetFsTransport, "Transport for the sandvmm hot ops (vm.set-fs, sandvmm.ping): raw = binary control frames on the same API socket (default, fastest), http = legacy REST over the same socket. Restart-required.")
	vmmAPIAuth      = flag.Bool("vmm-api-auth", sandlotconfig.DefaultVMMAPIAuth, "Per-VM sandvmm canonical-API token/challenge handshake (default ON via the config default). Each VM gets a 32-byte random token delivered over an inherited fd and every connection starts with a challenge-response preface (transport-independent: raw and HTTP framing). Pass -vmm-api-auth=false only for test tooling that drives the socket directly; when off the socket relies on DAC + --api-allowed-uid alone. Restart-required; boxout mode reads microvm.vmm_api_auth from the shared config.")
	initOnFree      = flag.Bool("init-on-free", sandlotconfig.DefaultInitOnFree, "Guest kernel free-time page wipe (init_on_free= on every VM's kernel cmdline). Default false: a fresh microVM's RAM is host anonymous mmap, so the kernel config's INIT_ON_FREE_DEFAULT_ON boot-time bulk clear is pure redundancy measured at ~0.65ms/MB; init_on_alloc stays on either way and keeps the cross-tenant freed-page channel closed. Pass -init-on-free for deployments that require contents wiped at free time as well. Restart-required; boxout mode reads microvm.init_on_free from the shared config.")

	// Stream concurrency / transport (govern in-flight commands from gateway + gRPC/HTTP-2 caps)
	streamSendBuffer      = flag.Int("stream-send-buffer", config.DefaultStreamSendBuffer, "sendCh capacity for outbound messages to gateway (restart)")
	streamRecvBuffer      = flag.Int("stream-recv-buffer", config.DefaultStreamRecvBuffer, "recvCh capacity for incoming gateway commands (restart)")
	maxConcurrentCommands = flag.Int("max-concurrent-commands", config.DefaultStreamMaxConcurrentCommands, "Max VMCommands processed concurrently (cmdSem, restart)")
	streamWriteTimeout    = flag.Int("stream-write-timeout-sec", config.DefaultStreamWriteTimeoutSec, "Max seconds to wait for a stream.Send (half-open detection, restart)")
	streamInitialWindow   = flag.Int("stream-initial-window-mb", config.DefaultStreamInitialWindowMB, "HTTP/2 per-stream flow-control window in MB (>= max-msg-size, restart)")
	streamConnWindow      = flag.Int("stream-conn-window-mb", config.DefaultStreamConnWindowMB, "HTTP/2 per-connection flow-control window in MB (restart)")
	streamMaxMsgSize      = flag.Int("stream-max-msg-size-mb", config.DefaultStreamMaxMsgSizeMB, "gRPC max send/recv message size in MB; >= warden single-op cap (restart)")

	// Resilience timings (tolerance-first; all restart-required). Sent to the
	// gateway in NodeHello.timing; the gateway derives T_safe (presence-key TTL)
	// from these and rejects the connect if T_safe <= T_tolerance + T_warden.
	toleranceSec            = flag.Int("tolerance-sec", sandlotconfig.DefaultToleranceSec, "Stream-outage tolerance before the sandlot starts cleaning mounts (T_tolerance)")
	cleanupSec              = flag.Int("cleanup-sec", sandlotconfig.DefaultCleanupSec, "Time budget for the sandlot's mount cleanup (T_clean; must be <= warden-countdown-sec)")
	wardenCountdownSec      = flag.Int("warden-countdown-sec", sandlotconfig.DefaultWardenCountdownSec, "In-VM warden single countdown, reset only by heartbeats (T_warden)")
	wardenMaxExecTimeoutSec = flag.Int("warden-max-exec-timeout-sec", 0, "In-VM warden max exec timeout passed via kernel cmdline (0 = warden default 180s). Must stay below -warden-countdown-sec (default 300) so a max-length exec always finishes before the warden's countdown fires. Restart-required; also settable as microvm.warden_max_exec_timeout_sec")
	wardenLogLevel          = flag.String("warden-log", "", "In-VM warden log level passed via kernel cmdline (empty = warden default info). Set debug for profiling sessions — per-op hot-path timing lines live at debug because their serial-UART drain taxes the measured path. Restart-required (deliberately NOT hot-reloadable: an online flip would enable UART-taxed debug logging across every new VM at fleet scale); also settable as microvm.warden_log")
	isolationSec            = flag.Int("isolation-sec", sandlotconfig.DefaultIsolationSec, "Wait after cleanup before reconnecting (T_isolation; > T_safe)")
	// allowShortResilienceTimings permits sub-production resilience timings
	// (T_tolerance/T_clean/T_warden < 300s). Production must NEVER set this:
	// short timings collapse the tolerance window and reintroduce the
	// double-mount race the tolerance-first model eliminates
	// (docs/how-it-works/resilience.md).
	// It exists solely for the FAST e2e tests, which exercise the same state
	// machine in seconds instead of minutes.
	allowShortResilienceTimings = flag.Bool("allow-short-resilience-timings", false, "DEBUG/TEST ONLY: permit T_tolerance/T_clean/T_warden below the 300s production floor. Never use in production.")
	allowSeedGenerationMismatch = flag.Bool("allow-seed-generation-mismatch", false, "Start even though the volumes root carries a naming generation NO configured seed derives. Deliberate re-key / disaster recovery ONLY (pair it with the one-time migration): volumes stay unresolvable until that migration runs. It does not weaken the promote completeness gate.")

	// Roles + provision role (all restart-required). Roles selects this
	// instance's capability sets: "exec" (the exec plane, default),
	// "prov" (sandfs + template lifecycle on shared storage), or "exec,prov"
	// (merged single-process form for single-node / all-in-one hosts — only
	// meaningful against a UNIFIED gateway). One sandlot process per host;
	// -allow-colocated-instances is the simulation escape hatch.
	rolesFlag            = flag.String("roles", "exec", "Capability planes this instance serves: exec | prov | exec,prov (restart-required). exec = microVM lifecycle/mount/exec (default). prov = sandfs+template lifecycle on shared storage (dials a human/unified gateway). exec,prov = merged single-process form for single-node hosts.")
	provTemplatesDir     = flag.String("templates-dir", "", "Template store root (layers/ + refs/) for the prov role. Empty = -overlayfs-templates when set, else the sibling templates/ directory beside -volumes-dir (the same store the exec role reads lowerdirs from).")
	provOCIRegistry      = flag.String("oci-registry", "", "OCI registry for template pull/push/auto-pull (prov role; the registry egress lives on THIS host). Empty = local templates only.")
	registryUsername     = flag.String("registry-username", "", "Registry basic-auth username (prov role; requires -oci-registry; restart-required). Prefer the YAML key over the flag: a flag value is visible in /proc/<pid>/cmdline.")
	registryPassword     = flag.String("registry-password", "", "Registry basic-auth password (prov role; requires -oci-registry; restart-required). Prefer provision.registry_password in the config file (0640) over the flag.")
	registryToken        = flag.String("registry-token", "", "Registry bearer token; alternative to username/password (prov role; requires -oci-registry; restart-required). Prefer the YAML key over the flag.")
	registryCert         = flag.String("registry-cert", "", "Registry TLS client certificate file for mTLS (prov role; requires -registry-key; restart-required).")
	registryKey          = flag.String("registry-key", "", "Registry TLS client key file for mTLS (prov role; requires -registry-cert; restart-required).")
	registryCA           = flag.String("registry-ca", "", "Registry CA certificate file (server verification against a private CA; combines with any credential; restart-required).")
	provFlatTemplatesDir = flag.String("flat-templates", "", "Directory scanned at startup for local flat templates (prov role; empty = no scan).")
	// The volume-name seed FILE (never the seed itself: argv is world-readable
	// through /proc/<pid>/cmdline). Required for the prov role — see
	// sandlot/provision/volname.
	provVolumeSeedFile     = flag.String("volume-seed-file", "", "File holding the volume-name seed (prov role; required). KEEP IT OWNER-ONLY for the prov identity: a leaked seed makes every volume name guessable.")
	provVolumeSeedNextFile = flag.String("volume-seed-next-file", "", "File holding the NEXT volume-name seed staged for a rotation (prov role; optional).")
	maxProvisionOps        = flag.Int("max-provision-ops", sandlotconfig.DefaultMaxProvisionOps, "Max concurrently executing provision commands (GB-scale work; the exec command budget is never spent on provisioning).")
	provisionDeadlineSec   = flag.Int("provision-deadline-sec", sandlotconfig.DefaultProvisionDeadlineSec, "Default per-op deadline (seconds) when the gateway sends none.")
	provisionReconnectSec  = flag.Int("provision-reconnect-sec", sandlotconfig.DefaultProvisionReconnectSec, "Prov-only connection recycle interval (seconds, ±20% jitter): a healthy stream is closed and re-dialed so a multi-address gateway list re-spreads and a revived gateway recovers its share. Exec connections are sticky and never recycled.")
	allowColocated         = flag.Bool("allow-colocated-instances", false, "SIMULATION ONLY: permit multiple sandlot instances on one host (the simulation scripts run N nodes per machine). Production hosts run exactly one instance; a duplicate node_id is refused even with this flag.")
	allowInsecureVolumes   = flag.Bool("allow-insecure-volumes", false, "DEV/TEST ONLY: start even when -volumes-dir is NOT on a nosuid,nodev mount. The virtio-fs passthrough stores guest-planted setuid bits and mknod verbatim, and only those mount flags make them inert (invariant 8, docs/operations/storage.md row 9) — production fixes the mount (self-bind + remount,bind,nosuid,nodev; the baremetal deployer does this), never passes this flag.")
	allowMissingVsockguard = flag.Bool("allow-missing-vsockguard", false, "DEV/TEST ONLY: start an embedded exec node without a valid root-written vsockguard attestation (/run/sandswap/vsockguard.allowed_uid). Production nodes attach the warden-port BPF guard (security/vsockguard-attach.sh / the k8s host-setup unit), which writes the attestation; without it the per-frame warden HMAC is the only transport control.")
	showVersion            = flag.Bool("version", false, "Print version and exit")
)

// Version information — set via ldflags at build time (same contract as the
// gateway's). Dev builds fall back to these defaults; release tooling stamps
// all three from the tag/commit/build date (build/build.sh).
var (
	Version   = "0.0.0-dev"
	Commit    = "unknown"
	BuildTime = "unknown"
)

func main() {
	flag.Parse()

	if *showVersion {
		fmt.Printf("sandlot %s (commit %s, built %s)\n", Version, Commit, BuildTime)
		return
	}

	// Pin host utility paths once (nft/ip/cp/setpriv). Missing tools are
	// reported by the role that needs them, not here.
	hostbin.Init()

	// Build config: start with defaults, overlay config file, then CLI flags.
	cfg := sandlotconfig.Defaults()
	if *configPath != "" {
		fileCfg, err := sandlotconfig.LoadFromFile(*configPath)
		if err != nil {
			log.Fatalf("failed to load config file %s: %v", *configPath, err)
		}
		cfg = fileCfg
	}
	cfg.ConfigFilePath = *configPath

	// Build flag values struct and apply CLI overrides.
	flags := &sandlotconfig.SandlotFlags{
		ConfigPath:                  *configPath,
		GatewayAddr:                 *gatewayAddr,
		NodeID:                      *nodeID,
		Kernel:                      *kernelPath,
		Initramfs:                   *initramfsPath,
		DefaultVCPUs:                *defaultVCPUs,
		DefaultMemMB:                *defaultMemMB,
		VMMBinary:                   *vmmBinary,
		VolumesDir:                  *volumesDir,
		TemplatesDir:                *templatesDir,
		PoolSpec:                    *poolSpec,
		TLSCert:                     *tlsCert,
		TLSKey:                      *tlsKey,
		TLSCA:                       *tlsCA,
		NetworkBackend:              *networkBackend,
		NetworkBridge:               *networkBridge,
		NetworkSubnet:               *networkSubnet,
		NetworkGateway:              *networkGateway,
		NetworkDNS:                  *networkDNS,
		NetworkBindBackend:          *bindingBackend,
		NetworkBindPath:             *bindingPath,
		EgressBaseline:              *egressBaseline,
		VMToVM:                      *vmToVMPolicy,
		V6Prefix:                    *networkV6Prefix,
		IIDTemplate:                 *iidTemplate,
		MaxUses:                     *maxUses,
		RecycleMemPct:               *recycleMemPct,
		RecycleMemAbs:               *recycleMemAbs,
		MinIdleFloorFrac:            *minIdleFloor,
		VMCreateConcurrency:         *vmCreateConc,
		VMDestroyConcurrency:        *vmDestroyConc,
		VMMode:                      *vmMode,
		BoxoutSocket:                *boxoutSocket,
		BoxoutTokenFile:             *boxoutTokenFile,
		SetFsTransport:              *setfsTransport,
		VMMAPIAuth:                  *vmmAPIAuth,
		InitOnFree:                  *initOnFree,
		RequireEgressBinding:        *requireEgressBinding,
		StreamSendBuffer:            *streamSendBuffer,
		StreamRecvBuffer:            *streamRecvBuffer,
		MaxConcurrentCommands:       *maxConcurrentCommands,
		StreamWriteTimeout:          *streamWriteTimeout,
		StreamInitialWindow:         *streamInitialWindow,
		StreamConnWindow:            *streamConnWindow,
		StreamMaxMsgSize:            *streamMaxMsgSize,
		ToleranceSec:                *toleranceSec,
		CleanupSec:                  *cleanupSec,
		WardenCountdownSec:          *wardenCountdownSec,
		WardenMaxExecTimeoutSec:     *wardenMaxExecTimeoutSec,
		WardenLogLevel:              *wardenLogLevel,
		IsolationSec:                *isolationSec,
		Roles:                       *rolesFlag,
		ProvisionTemplatesDir:       *provTemplatesDir,
		ProvisionOCIRegistry:        *provOCIRegistry,
		ProvisionRegistryUsername:   *registryUsername,
		ProvisionRegistryPassword:   *registryPassword,
		ProvisionRegistryToken:      *registryToken,
		ProvisionRegistryCert:       *registryCert,
		ProvisionRegistryKey:        *registryKey,
		ProvisionRegistryCA:         *registryCA,
		ProvisionFlatTemplatesDir:   *provFlatTemplatesDir,
		ProvisionVolumeSeedFile:     *provVolumeSeedFile,
		ProvisionVolumeSeedNextFile: *provVolumeSeedNextFile,
		ProvisionMaxConcurrentOps:   *maxProvisionOps,
		ProvisionDeadlineSec:        *provisionDeadlineSec,
		ProvisionReconnectSec:       *provisionReconnectSec,
	}
	explicitSet := config.ExplicitFlags()
	cfg.ApplyFlagOverrides(flags, explicitSet)
	if err := cfg.ApplyError(); err != nil {
		log.Fatalf("invalid flag value: %v", err)
	}
	// The reload path re-applies the same overrides, so a file edit never
	// reverts a flag-provided value.
	cfg.SetFlagReapplier(func(c *sandlotconfig.SandlotConfig) { c.ApplyFlagOverrides(flags, explicitSet) })

	// Value-bound validation (recycle sentinels, microvm default vcpus/memory,
	// stream transport caps, instance CID range). Hot-reload re-validates the
	// whole edited config with the same rule before applying.
	if err := cfg.Validate(); err != nil {
		log.Fatalf("invalid config: %v", err)
	}

	// Storage-plane hard precondition (invariant 8): the volumes tree must
	// sit on a nosuid,nodev mount — fail closed at startup instead of
	// leaving it to the after-the-fact verify script. The explicit
	// admission flag is the dev/test escape hatch (e2e trees use scratch
	// paths on the root filesystem; the baremetal deployer remounts the
	// flags itself, so production never needs it).
	//
	// Scope: the gate belongs to the process that EXPORTS the tree to a
	// guest — the embedded exec role (its VMM/FUSE passthrough serves the
	// host files). In boxout mode the privileged boxout sidecar owns the
	// host mount, and a prov-only instance never exports anything; a
	// container runtime may drop per-mount flags on a PVC bind, so those
	// roles warn instead of refusing (the mount owner must harden it).
	if cfg.VMMode != "boxout" && slices.Contains(cfg.NormalizedRoles(), "exec") {
		if err := requireSecureVolumesMount(cfg.MicroVM.VolumesDir, *allowInsecureVolumes); err != nil {
			log.Fatalf("%v", err)
		}
	} else {
		warnVolumesMountIfInsecure(cfg.MicroVM.VolumesDir)
	}

	// The warden-port BPF guard is a startup precondition for an embedded exec
	// node (defense in depth behind the per-frame HMAC). Boxout-mode sandlots
	// are unprivileged and cannot read the bpffs pin; the host-setup unit owns
	// it there, so verification is skipped with a warning.
	if slices.Contains(cfg.NormalizedRoles(), "exec") {
		if cfg.VMMode == "boxout" {
			log.Printf("vsockguard: pin verification skipped in boxout mode (unprivileged sandlot; the host-setup unit owns the guard)")
		} else if err := verifyVsockguardPin(uint32(os.Geteuid()), *allowMissingVsockguard, log.Default()); err != nil {
			log.Fatalf("%v", err)
		}
	}

	// Fix the set-fs/ping transport at process start, before any VMM client
	// exists (restart-required; hot-reload deliberately does not touch it).
	if err := vmm.ConfigureSetFsTransport(cfg.SetFsTransport); err != nil {
		log.Fatalf("%v", err)
	}

	// Validate resilience invariants. The gateway re-checks the ownership
	// invariant T_safe > T_tolerance + T_warden on connect; here we enforce the
	// local half: T_clean <= T_warden, so cleanup can always finish before the
	// warden countdown (the last-resort release) fires at T_tolerance + T_warden.
	res := cfg.Resilience
	if res.ToleranceSec <= 0 || res.CleanupSec <= 0 || res.WardenCountdownSec <= 0 || res.IsolationSec <= 0 {
		log.Fatalf("resilience timings must all be > 0 (got %+v)", res)
	}
	if res.CleanupSec > res.WardenCountdownSec {
		log.Fatalf("cleanup-sec (%d) must be <= warden-countdown-sec (%d): the warden exits at T_tolerance+T_warden, before cleanup could finish",
			res.CleanupSec, res.WardenCountdownSec)
	}
	// At-most-once invariant for the per-request SO_RCVTIMEO scheme: the cached
	// connection's read cap is warden-countdown-sec, and an exec's read timeout
	// is its own timeout + ReadTimeoutMargin clamped to that cap. If the cap is
	// not strictly above max-exec-timeout + margin, a max-length exec's read
	// fires AT the exec deadline — racing the warden's own timeout response —
	// and a retry can re-execute a command that already ran. Note the warden
	// clamps its own countdown UP to max_exec_timeout, so an effective countdown
	// equal to max_exec_timeout is possible; the margin must survive that clamp.
	// The warden has hard ceilings on both values (config.rs); a larger value
	// would be refused inside the guest after the VM was already launched.
	if cfg.MicroVM.WardenMaxExecTimeoutSec > 3600 {
		log.Fatalf("warden-max-exec-timeout-sec (%d) exceeds the warden's supported maximum (3600s)",
			cfg.MicroVM.WardenMaxExecTimeoutSec)
	}
	if res.WardenCountdownSec > 4200 {
		log.Fatalf("warden-countdown-sec (%d) exceeds the warden's supported maximum (4200s)", res.WardenCountdownSec)
	}

	// The warden raises its EFFECTIVE countdown to max_exec_timeout (its own
	// default is 180s when the sandlot passes none). The gateway anchors T_safe
	// — and therefore the whole mount-release proof — on the configured
	// countdown this node reports, so in a production configuration the two
	// values must not diverge. The Fast/dev timing escape hatch is the only
	// configuration allowed to rely on the warden's clamp.
	effectiveMaxExec := int(cfg.MicroVM.WardenMaxExecTimeoutSec)
	if effectiveMaxExec == 0 {
		effectiveMaxExec = 180 // warden default
	}
	if !*allowShortResilienceTimings && res.WardenCountdownSec <= effectiveMaxExec {
		log.Fatalf("warden-countdown-sec (%d) must be strictly greater than the warden's effective max_exec_timeout (%ds): the warden raises its countdown to the timeout, which would invalidate the gateway's T_safe proof",
			res.WardenCountdownSec, effectiveMaxExec)
	}
	if cfg.MicroVM.WardenMaxExecTimeoutSec > 0 &&
		res.WardenCountdownSec <= int(cfg.MicroVM.WardenMaxExecTimeoutSec)+int(warden.ReadTimeoutMargin/time.Second) {
		if !*allowShortResilienceTimings {
			log.Fatalf("warden-countdown-sec (%d) must be strictly greater than "+
				"warden-max-exec-timeout-sec (%d) + %ds read margin; a max-length exec's transport read "+
				"races the warden's timeout response and a retry may re-execute it. "+
				"Raise -warden-countdown-sec or lower -warden-max-exec-timeout-sec.",
				res.WardenCountdownSec, cfg.MicroVM.WardenMaxExecTimeoutSec, int(warden.ReadTimeoutMargin/time.Second))
		}
		log.Printf("WARNING: warden-countdown-sec (%d) is not greater than "+
			"warden-max-exec-timeout-sec (%d) + %ds read margin (allowed only by -allow-short-resilience-timings)",
			res.WardenCountdownSec, cfg.MicroVM.WardenMaxExecTimeoutSec, int(warden.ReadTimeoutMargin/time.Second))
	}
	// Production floor: T_tolerance, T_clean, and T_warden must each be >= 300s
	// (docs/how-it-works/resilience.md). Sub-300s timings collapse the tolerance
	// window and reintroduce the double-mount race; they are only legal for the
	// FAST e2e tests, which must opt in via -allow-short-resilience-timings.
	const prodFloorSec = 300
	if !*allowShortResilienceTimings {
		if res.ToleranceSec < prodFloorSec || res.CleanupSec < prodFloorSec || res.WardenCountdownSec < prodFloorSec {
			log.Fatalf("resilience timings below the %ds production floor (T_tolerance=%d T_clean=%d T_warden=%d): "+
				"short timings are test-only and reintroduce the double-mount race. "+
				"Set -allow-short-resilience-timings ONLY for FAST e2e tests, never in production.",
				prodFloorSec, res.ToleranceSec, res.CleanupSec, res.WardenCountdownSec)
		}
	} else {
		log.Printf("WARNING: -allow-short-resilience-timings set — sub-300s resilience timings enabled (TEST/DEBUG ONLY, not production-safe)")
	}

	if cfg.NodeID == "" {
		hostname, err := os.Hostname()
		if err != nil {
			log.Fatalf("failed to get hostname: %v", err)
		}
		cfg.NodeID = hostname
	}

	// Compose effective node-id with instance ID for multi-instance support.
	effectiveNodeID := cfg.NodeID
	if cfg.Instance.ID != "" {
		effectiveNodeID = cfg.NodeID + "-" + cfg.Instance.ID
	}

	logger := log.New(os.Stdout, fmt.Sprintf("[sandlot/%s] ", effectiveNodeID), log.LstdFlags|log.Lmsgprefix)

	// Host rule: at most ONE sandlot process per host (exec-only / prov-only /
	// merged are the blessed shapes; separate role processes on one host are
	// not). Refuses loudly before anything starts.
	roleRelease, err := acquireRoleLock(logger, effectiveNodeID, cfg.NormalizedRoles(), *allowColocated)
	if err != nil {
		log.Fatalf("%v", err)
	}
	if roleRelease != nil {
		defer roleRelease()
	}
	roles := cfg.NormalizedRoles()
	logger.Printf("roles: [%s]", strings.Join(roles, ","))

	// GC pacing: applied before any VM work starts (restart-required; see
	// common/config.ApplyGCTuning). The concurrent GC's mark/assist cycles
	// compete with the command handlers for cores — at high exec rates they
	// are a tail-latency source. Default GOGC=200 halves the GC frequency
	// for a proportionally larger heap; -gomemlimit bounds it when constrained.
	gcSt, err := config.ApplyGCTuning(*gogcFlag, *gomemlimitFlag)
	if err != nil {
		logger.Fatalf("gc pacing: %v", err)
	}
	if gcSt.GOGCSet != 0 {
		logger.Printf("gc pacing: GOGC=%d applied (previous %d)", gcSt.GOGCSet, gcSt.GOGCPrev)
	}
	if gcSt.MemLimitSet != 0 {
		logger.Printf("gc soft memory limit: %d bytes applied (previous %d)", gcSt.MemLimitSet, gcSt.MemLimitPrev)
	}

	// Pre-flight: vhost-vsock kernel backend must be available.
	// In boxout mode, sandlot runs as the unprivileged reserved uid and can't
	// open /dev/vhost-vsock;
	// boxout handles this check instead. Skip the pre-flight in boxout mode.
	// Prov-only instances have no KVM duty at all — a provision host needs
	// neither vhost-vsock nor its device lockdown.
	if cfg.HasRole("exec") && cfg.VMMode != "boxout" {
		const vhostVsockDev = "/dev/vhost-vsock"
		if cfg.MicroVM.VMMUid > 0 {
			// Identity-split model: /dev/vhost-vsock is owner-sandvmm 0600 —
			// sandlot itself must NOT be able to open it (that is the device
			// isolation). Verify the OWNER instead: the sandvmm uid must hold
			// it, and this process must carry the caps the split requires
			// (SETUID/SETGID for the spawn transition, KILL for cross-uid
			// teardown) — fail fast here, not per-VM-create with a confusing
			// EPERM.
			st, err := os.Stat(vhostVsockDev)
			if err != nil {
				logger.Fatalf("vhost-vsock not available: %s: %v\n"+
					"  ensure the kernel module is loaded: modprobe vhost_vsock", vhostVsockDev, err)
			}
			if sys, ok := st.Sys().(*syscall.Stat_t); ok && sys.Uid != cfg.MicroVM.VMMUid {
				logger.Fatalf("%s owned by uid %d, want the sandvmm identity %d\n"+
					"  fix: reinstall the udev rule (deploy/udev/99-sandswap-vsock.rules) and re-run host prep", vhostVsockDev, sys.Uid, cfg.MicroVM.VMMUid)
			}
			if err := checkCapsForVMMSpawn(cfg.MicroVM.VMMUid); err != nil {
				logger.Fatalf("%v", err)
			}
		} else if f, err := os.OpenFile(vhostVsockDev, os.O_RDWR, 0); err != nil {
			logger.Fatalf("vhost-vsock not available: cannot open %s: %v\n"+
				"  ensure the kernel module is loaded: modprobe vhost_vsock", vhostVsockDev, err)
		} else {
			f.Close()
		}
	}

	// Guest TCB integrity: production installs the kernel/initramfs in the
	// root-owned guest directory with a SHA256SUMS pin. Verify before the
	// first VM; dev/e2e paths outside that directory are deliberately exempt.
	if cfg.HasRole("exec") {
		verifyGuestArtifacts(&cfg, logger)
	}

	// Default VMM config
	vmmGroups, gerr := resolveVMMGroups(cfg.MicroVM.VMMGroups, cfg.MicroVM.APIGid, logger)
	if gerr != nil {
		logger.Fatalf("%v", gerr)
	}
	vmmCfg := vmm.Config{
		KernelPath:              cfg.MicroVM.Kernel,
		InitramfsPath:           cfg.MicroVM.Initramfs,
		VCPUs:                   cfg.MicroVM.DefaultVCPUs,
		MemoryMB:                cfg.MicroVM.DefaultMemoryMB,
		VMMBinary:               cfg.VMMBinary,
		VolumesDir:              cfg.MicroVM.VolumesDir,
		TemplatesDir:            cfg.MicroVM.OverlayFSTemplates,
		WardenCountdownSec:      uint32(res.WardenCountdownSec),
		WardenMaxExecTimeoutSec: cfg.MicroVM.WardenMaxExecTimeoutSec,
		WardenLogLevel:          cfg.MicroVM.WardenLogLevel,
		VMMUID:                  cfg.MicroVM.VMMUid,
		VMMGID:                  cfg.MicroVM.VMMGid,
		VMMGroups:               vmmGroups,
		APIGID:                  cfg.MicroVM.APIGid,
		SeccompMode:             cfg.MicroVM.VMMSeccomp,
		VMMAPIAuth:              cfg.MicroVM.VMMAPIAuth,
		InitOnFree:              cfg.MicroVM.InitOnFree,
	}

	// Build the outbound-networking provider.
	// In boxout mode, sandlot doesn't do networking directly — boxout handles it.
	// Prov-only instances never run VMs: the provider stays noop and the
	// bridge check is skipped (a provision host owes KVM/bridge nothing).
	var netProv vmm.NetworkProvider = network.NewNoop()
	if cfg.HasRole("exec") && cfg.VMMode != "boxout" {
		netProv, err = network.BuildProvider(cfg.Network, cfg.MicroVM.VMMUid, logger)
		if err != nil {
			logger.Fatalf("%v", err)
		}
		if cfg.Network.Backend == "bridge" {
			if err := network.CheckBridgeReady(cfg.Network.Bridge); err != nil {
				logger.Fatalf("network backend bridge not ready: %v\n"+
					"  run: bash deploy/setup-network.sh", err)
			}
		}
	} else {
		logger.Printf("network backend: delegated to boxout (boxout mode)")
	}

	// TLS config (built once; reused across reconnects).
	tlsCfg, err := rpc.BuildClientTLS(cfg.TLS.Cert, cfg.TLS.Key, cfg.TLS.CA)
	if err != nil {
		logger.Fatalf("invalid TLS config: %v", err)
	}

	// The handler persists across stream reconnects.
	// In embedded mode, the embeddedManager wraps the NetworkProvider for
	// direct privileged calls. In boxout mode, a boxoutManager delegates
	// to the boxout sidecar.
	var vmLifecycle core.VMLifecycleManager
	var handler *core.Handler

	switch cfg.VMMode {
	case "", "embedded":
		// Embedded mode: sandlot does everything directly (current behavior).
		// (The bridge was already checked in the network-backend build above.)
		handler = core.NewHandler(nil, vmmCfg, nil, netProv, logger)
		handler.EnableDebugOp(*debugOpLog)
		vmLifecycle = core.NewEmbeddedManager(handler)
		handler.SetVMLifecycle(vmLifecycle)

	case "boxout":
		// Boxout mode: sandlot delegates privileged ops to boxout sidecar
		// via Unix socket. Sandlot runs as the reserved sandbox uid (65536
		// in the shipped k8s manifests) with no capabilities.
		// No bridge check, no vhost-vsock check — boxout handles those.
		// The manager serves as BOTH the lifecycle manager and h.net: boxout
		// owns the privileged NetworkProvider, so provisioning AND the egress
		// identity hooks (MountGater/IdentityStamper — binding.go discovers
		// them via type assertion) must relay through it.
		bm := core.NewBoxoutManager(cfg.BoxoutSocket, cfg.BoxoutTokenFile, logger)
		vmLifecycle = bm
		handler = core.NewHandler(nil, vmmCfg, bm, bm, logger)
		handler.EnableDebugOp(*debugOpLog)

	default:
		logger.Fatalf("unknown vm-mode %q (want embedded|boxout)", cfg.VMMode)
	}

	// Egress identity binding region (third-party network policy enabler).
	// "off" (default) leaves the hot path and behavior byte-identical to a
	// build without it; "shm"/"bpf" publish (tap-ifindex -> agent/sandfs) at
	// mount and revoke at unmount for node-local enforcers to read.
	switch cfg.Network.BindBackend {
	case "", "off":
		logger.Printf("egress identity binding: off")
	default:
		region, err := bindreg.Open(bindreg.Config{
			Backend: bindreg.Backend(cfg.Network.BindBackend),
			Path:    cfg.Network.BindPath,
		})
		if err != nil {
			logger.Fatalf("binding backend %q: %v", cfg.Network.BindBackend, err)
		}
		handler.SetBindRegion(region)
		logger.Printf("egress identity binding: %s at %s (max_ifindex=%d)",
			cfg.Network.BindBackend, cfg.Network.BindPath, region.MaxIfindex())
		// Advisory only (never a gate): a world-writable region would let any
		// local user forge published identities. The shm carrier already
		// hard-refuses that at open; the bpf carrier cannot — the k8s/boxout
		// handoff legitimately widens the pin so the unprivileged sandlot can
		// write through its mmap.
		rc := (bindreg.Config{
			Backend: bindreg.Backend(cfg.Network.BindBackend),
			Path:    cfg.Network.BindPath,
		}).Resolve()
		if st, serr := os.Stat(rc.Path); serr == nil && st.Mode().Perm()&0o002 != 0 {
			logger.Printf("warning: binding region %s is world-writable — any local user could forge published identities; prefer owner-rw with group/other read-only (docs/deployment/prerequisites.md)", rc.Path)
		}
	}

	// Egress identity binding gate (the enabler production must run): guest
	// egress is attributable to an agent only when Carrier A (binding region)
	// or Carrier B (routed-ipv6 + iid_template) is configured. Unbound is a
	// dev/test posture: WARN + egress_binding=none in /stats, or refuse to
	// start when require_egress_binding is set.
	egressBinding := cfg.EgressBindingMode()
	if cfg.HasRole("exec") {
		if egressBinding == "none" {
			if cfg.Network.RequireEgressBinding {
				logger.Fatalf("egress identity binding is REQUIRED (network.require_egress_binding / -require-egress-binding) but neither Carrier A (binding-backend=shm|bpf) nor Carrier B (network-backend=routed-ipv6 + iid-template) is configured — refusing to start with unattributable guest egress")
			}
			logger.Printf("WARNING: egress identity is NOT bound on this node (neither Carrier A binding-backend nor Carrier B routed-ipv6+iid-template is configured) — a third-party enforcer cannot attribute guest traffic to an agent; dev/test posture only")
		} else {
			logger.Printf("egress identity binding mode: %s", egressBinding)
		}
	}

	// The live config snapshot: the hot-reload callback swaps it, and every
	// reload-aware consumer resolves from the SAME instance — so no consumer
	// can ever read a generation out of a half-applied edit (the seed
	// coordinator reads it on every reconcile).
	liveConfig := config.NewWatchableConfig(cfg)

	// Provision role: the storage executor around the shared
	// template store + volumes root. The registry egress lives HERE, on the
	// provision host — never on gateway hosts.
	var provSvc *core.ProvisionService
	var provPlane *volume.Provisioner
	var namer *volname.Map
	var seedCoord *seed.Coordinator
	if cfg.HasRole("prov") {
		// Store resolution: explicit provision.templates_dir →
		// -overlayfs-templates (the same store the exec role reads lowerdirs
		// from) → the SIBLING of volumes_dir (same filesystem as the volume
		// tree: shared storage in clustered deployments, the local state dir
		// in single-node). The legacy /var/sandswap/templates default is gone
		// — node prep never created it, so a fresh host could not write it.
		templatesDir := cfg.Provision.TemplatesDir
		if templatesDir == "" {
			templatesDir = cfg.MicroVM.OverlayFSTemplates
		}
		if templatesDir == "" {
			templatesDir = filepath.Join(filepath.Dir(cfg.MicroVM.VolumesDir), "templates")
		}
		// The volume-name seed: required, and it must NOT live in a file the
		// sandvmm identity can read (see config.ProvisionConfig.VolumeSeed).
		// Only the CURRENT generation is fatal here: a staged generation whose
		// source is not readable yet (the injector has not materialized it)
		// must not crash-loop the storage plane — the coordinator logs it and
		// the instance starts UNSTAGED.
		curSeed, _, serr := cfg.Provision.CurrentSeed()
		if serr != nil {
			logger.Fatalf("provision volume seed: %v", serr)
		}
		var nerr error
		namer, nerr = volname.NewMap(curSeed)
		if nerr != nil {
			logger.Fatalf("provision volume namer: %v", nerr)
		}
		// The seed coordinator owns every RUNTIME move of the generations: it
		// watches the configured sources, applies stage/promote through the
		// namer's transition table, gates a promotion on the on-disk stamps and
		// records what it adopted. Built (and guarded) BEFORE the store exists
		// so nothing can serve a volume from an unverified generation.
		// NOTE: assignment, not :=. The coordinator must land in the OUTER
		// variable — the reload wiring below runs outside this block, and a
		// shadowed local would leave it nil ("this instance has no provision
		// role" on every seed edit).
		var cerr error
		seedCoord, cerr = seed.New(seed.Options{
			Config:  liveConfig.Get,
			Namer:   namer,
			VolRoot: cfg.MicroVM.VolumesDir,
			// Beside the role lock: the same runtime directory, so the record
			// is tmpfs-backed and shares the lock's one-instance-per-host
			// assumption (a second PROV instance on this host is not a
			// supported shape — exec+prov colocation is, and that has one
			// prov).
			StatePath:               filepath.Join(filepath.Dir(roleLockPath), seed.StateFilename),
			Logger:                  logger,
			AllowGenerationMismatch: *allowSeedGenerationMismatch,
		})
		if cerr != nil {
			logger.Fatalf("provision seed coordinator: %v", cerr)
		}
		if berr := seedCoord.Bootstrap(); berr != nil {
			logger.Fatalf("provision volume seed: %v", berr)
		}
		if gerr := seedCoord.StartupGuard(); gerr != nil {
			logger.Fatalf("provision seed startup guard: %v", gerr)
		}
		resolveVolume := func(id string) (string, error) {
			dir := filepath.Join(cfg.MicroVM.VolumesDir, namer.Current(id))
			if _, err := os.Stat(dir); err == nil {
				return dir, nil
			}
			if namer.HasNext() {
				next := filepath.Join(cfg.MicroVM.VolumesDir, namer.Next(id))
				if _, err := os.Stat(next); err == nil {
					return next, nil
				}
			}
			return "", fmt.Errorf("volume for %s not found under %s", id, cfg.MicroVM.VolumesDir)
		}
		mgr, merr := template.NewManager(template.Config{
			Registry:     cfg.Provision.OCIRegistry,
			TemplatesDir: templatesDir,
			// OverlayBase = the volumes root: the store resolves a sandfs
			// directory as <OverlayBase>/<id> for SaveAsTemplate (volume →
			// template snapshots). This process owns the storage plane, so the
			// path is real here — the gateway never has it.
			OverlayBase:    cfg.MicroVM.VolumesDir,
			ResolveVolume:  resolveVolume,
			MaxSparseBytes: cfg.Provision.MaxSparseBytes,
			// SaveAsTemplate must classify flat vs overlay from a SIGNED
			// stamp, and verify the stamp's sandfs id against the request:
			// the seed-aware verifier lives in the volume package and returns
			// BOTH fields from one verified read. The template package cannot
			// import volume without a cycle.
			VerifyVolumeStamp: func(dir string) (template.VolumeStamp, bool, error) {
				seeds := [][]byte{namer.CurrentSeed()}
				if next := namer.NextSeed(); len(next) > 0 {
					seeds = append(seeds, next)
				}
				info, present, verified, verr := volume.ReadVerifiedVolumeStampForTool(dir, seeds)
				if verr != nil {
					return template.VolumeStamp{}, false, verr
				}
				if !present || !verified {
					return template.VolumeStamp{}, false, nil
				}
				return template.VolumeStamp{SandfsID: info.SandfsID, Mode: info.Mode}, true, nil
			},
			Auth: template.AuthConfig{
				Username: cfg.Provision.RegistryUsername,
				Password: cfg.Provision.RegistryPassword,
				Token:    cfg.Provision.RegistryToken,
				CertFile: cfg.Provision.RegistryCert,
				KeyFile:  cfg.Provision.RegistryKey,
				CAFile:   cfg.Provision.RegistryCA,
			},
		})
		if merr != nil {
			logger.Fatalf("provision template manager: %v", merr)
		}
		if cfg.Provision.FlatTemplatesDir != "" {
			if serr := mgr.ScanFlatTemplates(cfg.Provision.FlatTemplatesDir); serr != nil {
				logger.Printf("WARNING: flat template scan %s: %v", cfg.Provision.FlatTemplatesDir, serr)
			}
		}
		prov, perr := volume.NewWithNamer(cfg.MicroVM.VolumesDir, mgr, namer)
		if perr != nil {
			logger.Fatalf("provision volume namer: %v", perr)
		}
		prov.QuotaStampCmd = cfg.Provision.QuotaStampCmd
		provPlane = prov
		provSvc = core.NewProvisionService(
			prov,
			cfg.Provision.MaxConcurrentOps,
			time.Duration(cfg.Provision.DefaultDeadlineSec)*time.Second,
			logger)
		logger.Printf("provision plane ready: templates=%s registry=%q auth=%s volumes=%s max_ops=%d",
			templatesDir, cfg.Provision.OCIRegistry, cfg.Provision.RegistryAuthMethod(),
			cfg.MicroVM.VolumesDir, cfg.Provision.MaxConcurrentOps)
	}

	// heartbeatNow is a channel that triggers an immediate heartbeat when
	// ResizePool changes the pool (so the gateway reconciles quickly).
	heartbeatNow := make(chan struct{}, 1)
	handler.OnPoolChanged = func() {
		select {
		case heartbeatNow <- struct{}{}:
		default: // already pending
		}
	}

	// Configure multi-instance paths and CID range.
	if cfg.Instance.ID != "" {
		handler.SandboxRoot = filepath.Join(cfg.Instance.BaseDir, cfg.Instance.ID, "vm")
		handler.SetNextCID(cfg.Instance.CIDRangeStart)
		if cfg.Instance.CIDRangeEnd > 0 {
			handler.SetCIDMax(cfg.Instance.CIDRangeEnd)
		}
		// Prefix pool VM IDs with the instance ID so VMs across instances
		// on the same host don't collide in the gateway's byID pool index.
		handler.SetPoolVMIDPrefix(cfg.Instance.ID + "-")
	}

	// Propagate sandbox root to boxout manager (so readopt_vms uses the
	// per-instance path instead of the default /run/sandswap/vm).
	if bm, ok := vmLifecycle.(*core.BoxoutManager); ok && handler.SandboxRoot != "" {
		bm.SetSandboxRoot(handler.SandboxRoot)
	}

	// Re-adopt microVMs that survived a sandlot restart. Exec-role only: a
	// prov-only instance owns no VMs, and its sandbox root may be the shared
	// default (instance.id unset on a co-located exec+prov host) — scanning it
	// here would adopt or orphan-kill the exec instance's live VMs.
	if cfg.HasRole("exec") {
		readoptCtx, readoptCancel := context.WithTimeout(context.Background(), 60*time.Second)
		handler.ReadoptVMs(readoptCtx)
		readoptCancel()
		_, readoptedIDs := handler.ActiveVMs()
		logger.Printf("re-adopt complete: %d VM(s) live", len(readoptedIDs))
	}

	// Reconnect-clean invariant (startup half): the sandlot never enters a
	// stream connection holding a mount, so the gateway's OnConnect always meets
	// a node with zero mounts and needs no transient-state reconstruction. This
	// call covers the process-restart path: re-adopted survivors may still hold
	// the pre-crash session's mounts, and this process has no record of them
	// (bindings are in-memory), so releasing is the only correct action. The
	// other half — releasing before every RECONNECT — lives at the dial site
	// in the runner, so an outage's in-flight commands get the full T_tolerance
	// window to finish first.
	//
	// Placement is deliberate: RIGHT AFTER re-adopt and BEFORE the pool is
	// pre-created. At this point the VM table holds exactly the survivors this
	// is meant for. Running it after preCreateVMs would also sweep the
	// brand-new pool VMs, which are still mid-boot — and a VM that was just
	// created has by construction never been mounted, so there is nothing to
	// release.
	// Exec-role only: survivors are microVMs this instance owns.
	if cfg.HasRole("exec") {
		cleanCtx, cleanCancel := context.WithTimeout(context.Background(), time.Duration(res.CleanupSec)*time.Second)
		handler.ResetSurvivorsToClean(cleanCtx, time.Now().Add(time.Duration(res.CleanupSec)*time.Second))
		cleanCancel()
	}

	// Apply the initial recycle config (incl. min-idle floor) BEFORE the pool
	// is parsed/validated: the floor expands the per-spec target that
	// validatePoolMemory must cover (the reload watcher only fires on file
	// changes, so this is the only startup application).
	handler.UpdateRecycleConfig(cfg.Recycle.MaxUses, cfg.Recycle.MemPercent,
		cfg.Recycle.MemAbsMB, cfg.Recycle.MinIdleFloorFrac)
	handler.UpdateReusePolicy(cfg.Recycle.MaxMounts, cfg.Recycle.MaxDistinctAgents, cfg.Recycle.AffinityVMs)
	handler.UpdateVMBatchConcurrency(cfg.Concurrency.VMCreate, cfg.Concurrency.VMDestroy)

	// Pre-create VM pool from config's pool spec (parse → memory-admission →
	// register specs → top up after re-adopt → converge both directions).
	poolTarget, err := core.SetupPool(handler, cfg, vmmCfg, logger)
	if err != nil {
		logger.Fatalf("%v", err)
	}

	// Start hot-reload watcher if config file is set. The seed leg is a
	// TRIGGER, not a values carrier: the coordinator re-resolves from the live
	// snapshot (with the reader-side integrity check) and applies — one
	// resolution path for the config watcher, the seed source watchers and the
	// poll alike.
	var reconcileSeeds func() error
	if namer != nil && seedCoord != nil {
		reconcileSeeds = func() error { return seedCoord.Reconcile("config-reload") }
		// A seed without a config file cannot be staged: the rotation tooling
		// opens the window by EDITING that file, and this instance has none to
		// watch. Say so at startup instead of letting the operator discover it
		// mid-rotation.
		if cfg.ConfigFilePath == "" {
			logger.Printf("WARNING: this instance carries a volume-name seed but was started without -config — it cannot be staged hot and the rotation tooling cannot open a window here; restart with -config to make it rotatable")
		}
	}
	core.StartConfigReload(&cfg, liveConfig, handler, logger, reconcileSeeds)
	if seedCoord != nil {
		seedCoord.Start()
		defer seedCoord.Stop()
	}

	// SIGINT/SIGTERM: cancel the run loop.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Orphan-debris sweep (prov role): DeleteVolume's orphan-rename fallback
	// converges the operation but leaves the tree on disk; reclaim it here on
	// an age basis when this identity can traverse it, and hand what only root
	// can reclaim to the ops queue beside the volumes root.
	if provPlane != nil {
		go func() {
			sweep := func() {
				removed, queued := provPlane.SweepOrphans(volume.OrphanSweepAge)
				if removed > 0 || queued > 0 {
					logger.Printf("provision orphan sweep: reclaimed=%d queued_for_ops=%d", removed, queued)
				}
			}
			sweep()
			t := time.NewTicker(volume.OrphanSweepInterval)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					sweep()
				}
			}
		}()
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		logger.Printf("received signal %v, closing stream (microVMs left alive for re-adopt)", sig)
		cancel()
	}()

	// Start the independent warden-probe loop. Runs during CONNECTED and
	// TOLERATING — its OP_MEM_STATS heartbeats keep each VM's warden countdown
	// anchor fresh (single countdown). StopProbeLoop cancels it on entering
	// CLEANING so the countdowns can fire as the last-resort mount release.
	// Exec-role only: a prov-only instance owns no VMs and must not heartbeat
	// (or later reap) another instance's microVMs.
	if cfg.HasRole("exec") {
		handler.StartProbeLoop(ctx)
	}

	// State flusher: the single writer for per-VM reuse accounting
	// (mount_count / distinct_agents) in state.json. Started after re-adopt so
	// it never races the startup state writes; the deferred stop performs the
	// final drain before exit.
	// Exec-role only: per-VM reuse accounting. A prov-only instance owns no
	// VMs, and its sandbox root may be shared with a co-located exec instance.
	if cfg.HasRole("exec") {
		handler.StartStateFlusher(ctx)
		defer handler.StopStateFlusher()
	}

	// Tolerance-first reconnect state machine + serve loop (core/runner.go).
	runOpts := core.RunOptions{
		Cfg:             cfg,
		Handler:         handler,
		TLSCfg:          tlsCfg,
		EffectiveNodeID: effectiveNodeID,
		PoolTarget:      poolTarget,
		Logger:          logger,
		HeartbeatNow:    heartbeatNow,
		Provision:       provSvc,
		Roles:           roles,
		EgressBinding:   egressBinding,
	}
	if seedCoord != nil {
		// The heartbeat carries this instance's naming generations: the
		// gateway projects them per node in /stats, which is how a rotation
		// proves the whole prov fleet converged before the window closes.
		runOpts.SeedGenerations = seedCoord.Generations
	}
	core.RunNode(ctx, runOpts)

	logger.Printf("sandlot exiting; %d microVM(s) left alive for re-adopt", func() int {
		c, _ := handler.ActiveVMs()
		return int(c)
	}())
	handler.Stop()
}

// resolveVMMGroups turns the microvm.vmm_groups spec (comma-separated numeric
// gids or group NAMES — names carry per-host variance like "kvm", numbers
// carry the contract pins like 985) into the supplementary group list for
// the sandvmm child. The API gid is always included so the socket chgrp
// (group-membership-only, no CAP_CHOWN) succeeds. Unresolvable names are a
// warn-and-skip (a missing "kvm" group only costs /dev/kvm access, which
// surfaces immediately at the first VM create with a clear error).
func resolveVMMGroups(spec string, apiGid uint32, logger *log.Logger) ([]uint32, error) {
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
	// The volume-seed group must never reach the sandvmm/FUSE child: it reads
	// the seed and every tenant's derived volume name. A group list that
	// resolves to it (by number or name, including api_gid) is refused at
	// startup rather than silently handing the seed to the daemon.
	if forbidden := sandprovGroupID(); forbidden != 0 {
		for _, g := range out {
			if g == forbidden {
				return nil, fmt.Errorf("microvm.vmm_groups/api_gid resolves to the sandprov group %d — the VMM/FUSE child must never carry the volume-seed group; remove it from the group list", g)
			}
		}
	}
	return out, nil
}

// guestArtifactDir is the root-only location the deployers install the guest
// TCB into, with a SHA256SUMS pin beside it. A sandlot whose kernel/initramfs
// live here verifies both files before the first VM; dev/e2e paths outside
// this directory are exempt (they are not a production TCB location).
const guestArtifactDir = "/usr/local/lib/sandswap/guest"

// verifyGuestArtifacts enforces the production TCB pin: both files must be
// root-owned, non-group/world-writable regular files, and match SHA256SUMS.
// A missing or mismatched pin is fatal — the guest kernel is the sandbox TCB.
func verifyGuestArtifacts(cfg *sandlotconfig.SandlotConfig, logger *log.Logger) {
	kernel := cfg.MicroVM.Kernel
	initramfs := cfg.MicroVM.Initramfs
	if filepath.Dir(kernel) != guestArtifactDir || filepath.Dir(initramfs) != guestArtifactDir {
		logger.Printf("guest TCB hash check skipped: kernel/initramfs are outside %s (dev/e2e paths)", guestArtifactDir)
		return
	}
	sumsPath := filepath.Join(guestArtifactDir, "SHA256SUMS")
	sumsInfo, err := os.Lstat(sumsPath)
	if err != nil {
		logger.Fatalf("guest TCB pin %s is unavailable: %v\n  the deployer must install %s with sandswap_install_guest_artifacts", sumsPath, err, guestArtifactDir)
	}
	if !sumsInfo.Mode().IsRegular() || sumsInfo.Mode()&0o022 != 0 {
		logger.Fatalf("guest TCB pin %s is not a non-group/world-writable regular file (mode %04o)", sumsPath, sumsInfo.Mode().Perm())
	}
	if st, ok := sumsInfo.Sys().(*syscall.Stat_t); ok && st.Uid != 0 {
		logger.Fatalf("guest TCB pin %s is owned by uid %d, want root", sumsPath, st.Uid)
	}
	sums, err := os.ReadFile(sumsPath)
	if err != nil {
		logger.Fatalf("cannot read guest TCB pin %s: %v", sumsPath, err)
	}
	want := map[string]string{}
	for _, line := range strings.Split(string(sums), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 {
			want[fields[1]] = fields[0]
		}
	}
	for _, path := range []string{kernel, initramfs} {
		base := filepath.Base(path)
		expected, ok := want[base]
		if !ok {
			logger.Fatalf("guest TCB pin %s has no entry for %s", sumsPath, base)
		}
		fi, err := os.Lstat(path)
		if err != nil {
			logger.Fatalf("guest TCB artifact %s is unavailable: %v", path, err)
		}
		if !fi.Mode().IsRegular() || fi.Mode()&0o022 != 0 {
			logger.Fatalf("guest TCB artifact %s is not a non-group/world-writable regular file (mode %04o)", path, fi.Mode().Perm())
		}
		if st, ok := fi.Sys().(*syscall.Stat_t); ok && st.Uid != 0 {
			logger.Fatalf("guest TCB artifact %s is owned by uid %d, want root", path, st.Uid)
		}
		blob, err := os.ReadFile(path)
		if err != nil {
			logger.Fatalf("cannot read guest TCB artifact %s: %v", path, err)
		}
		sum := sha256.Sum256(blob)
		got := hex.EncodeToString(sum[:])
		if !strings.EqualFold(got, expected) {
			logger.Fatalf("guest TCB artifact %s hash mismatch: got %s, %s says %s", path, got, sumsPath, expected)
		}
		logger.Printf("guest TCB verified: %s sha256=%s", path, got[:16])
	}
}

// vsockguardAttestation is the root-written statement that the warden-port BPF
// guard is attached and which uid it allows. The sandlot (uid 985) cannot read
// the bpffs pin itself: /sys/fs/bpf is root-only and bpf_obj_get needs both DAC
// access and BPF privileges. The deploy/attach tooling (root) writes this file
// after a successful attach; the systemd unit re-runs the same check in
// ExecStartPre, so a stale file cannot outlive a detached pin or a reboot.
const vsockguardAttestation = "/run/sandswap/vsockguard.allowed_uid"

// verifyVsockguardPin proves the warden-port BPF guard is attached AND allows
// THIS sandlot uid. Root sandlots skip the check (root is a trust root and the
// hook admits root); a non-root sandlot verifies the root attestation's
// ownership, mode and value. The dev/test admission downgrades a
// missing/mismatched attestation to a warning.
func verifyVsockguardPin(sandlotUID uint32, allowMissing bool, logger *log.Logger) error {
	if sandlotUID == 0 {
		logger.Printf("vsockguard: running as root — pin check skipped (root is a trust root and the BPF hook admits root)")
		return nil
	}
	return verifyVsockguardAttestation(vsockguardAttestation, sandlotUID, allowMissing, logger)
}

func verifyVsockguardAttestation(path string, sandlotUID uint32, allowMissing bool, logger *log.Logger) error {
	fi, err := os.Lstat(path)
	if err != nil {
		if allowMissing {
			logger.Printf("WARNING: vsockguard attestation absent (%v) — relying on the per-frame warden HMAC alone (-allow-missing-vsockguard is a DEV/TEST admission)", err)
			return nil
		}
		return fmt.Errorf("vsockguard attestation %s is missing: an exec node must not run without the warden-port BPF guard\n"+
			"  fix: run bash security/vsockguard-attach.sh %d (writes it after a successful attach) or the systemd unit's ExecStartPre; -allow-missing-vsockguard admits a dev/test host", path, sandlotUID)
	}
	if !fi.Mode().IsRegular() || fi.Mode()&0o022 != 0 {
		return fmt.Errorf("vsockguard attestation %s is not a non-group/world-writable regular file (mode %04o)", path, fi.Mode().Perm())
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && st.Uid != 0 {
		return fmt.Errorf("vsockguard attestation %s is owned by uid %d, want root", path, st.Uid)
	}
	data, rerr := os.ReadFile(path)
	if rerr != nil {
		return fmt.Errorf("read vsockguard attestation %s: %w", path, rerr)
	}
	text := strings.TrimSpace(string(data))
	got, perr := strconv.ParseUint(text, 10, 32)
	if perr != nil {
		return fmt.Errorf("vsockguard attestation %s holds %q (want a uid): %w", path, text, perr)
	}
	if uint32(got) != sandlotUID {
		if allowMissing {
			logger.Printf("WARNING: vsockguard allows uid %d but this sandlot runs as %d — proceeding under -allow-missing-vsockguard (DEV/TEST only)", got, sandlotUID)
			return nil
		}
		return fmt.Errorf("vsockguard allows uid %d, but this sandlot runs as uid %d — the guard protects a different identity; re-attach it with the sandlot uid", got, sandlotUID)
	}
	logger.Printf("vsockguard attestation verified: allowed_uid=%d", got)
	return nil
}

// sandprovGroupID resolves the provision identity's group id from the
// deployer's environment (SANDSWAP_PROV_GID, then the identity.env key), with
// a name lookup fallback for hosts that predate the export. 0 = unknown (the
// check is skipped rather than failing every host without the account).
func sandprovGroupID() uint32 {
	for _, env := range []string{"SANDSWAP_PROV_GID", "SS_GID_SANDPROV"} {
		if v := strings.TrimSpace(os.Getenv(env)); v != "" {
			if n, err := strconv.ParseUint(v, 10, 32); err == nil {
				return uint32(n)
			}
		}
	}
	name := os.Getenv("SANDPROV_GROUP")
	if name == "" {
		name = "sandprov"
	}
	g, err := user.LookupGroup(name)
	if err != nil {
		return 0
	}
	n, err := strconv.ParseUint(g.Gid, 10, 32)
	if err != nil {
		return 0
	}
	return uint32(n)
}

// checkCapsForVMMSpawn verifies this process can actually perform the
// identity-split spawn and teardown: the uid transition needs
// CAP_SETUID/CAP_SETGID, and killing a different-uid child needs CAP_KILL.
// Failing here (startup) beats failing per-VM-create with a bare EPERM.
func checkCapsForVMMSpawn(vmmUid uint32) error {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return fmt.Errorf("cannot read /proc/self/status for capability pre-flight: %w", err)
	}
	var effHex string
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "CapEff:") {
			effHex = strings.TrimSpace(strings.TrimPrefix(line, "CapEff:"))
		}
	}
	if effHex == "" {
		return fmt.Errorf("no CapEff line in /proc/self/status")
	}
	eff, err := strconv.ParseUint(effHex, 16, 64)
	if err != nil {
		return fmt.Errorf("parse CapEff %q: %w", effHex, err)
	}
	const (
		capSetGID = 1 << 6 // CAP_SETGID (capability 6; 1 is DAC_OVERRIDE)
		capSetUID = 1 << 7 // CAP_SETUID
		capKill   = 1 << 5 // CAP_KILL
	)
	missing := []string{}
	if eff&capSetUID == 0 {
		missing = append(missing, "CAP_SETUID")
	}
	if eff&capSetGID == 0 {
		missing = append(missing, "CAP_SETGID")
	}
	if eff&capKill == 0 {
		missing = append(missing, "CAP_KILL")
	}
	if len(missing) > 0 {
		return fmt.Errorf("sandlot lacks %s — required by the sandvmm identity split (uid %d):\n"+
			"  fix: update the service unit / launch path to AmbientCapabilities=CAP_NET_ADMIN CAP_SYS_ADMIN CAP_SETUID CAP_SETGID CAP_KILL\n"+
			"  (deploy/baremetal/systemd/sandswap-sandlot.service, or common/sh/runtime.sh ss_service_exec)",
			strings.Join(missing, ", "), vmmUid)
	}
	return nil
}

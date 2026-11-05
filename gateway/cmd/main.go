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
// Gateway is the centralized entry point for AI sandfs sandbox execution.
// It provides HTTP API, manages sandfs identity,
// and orchestrates the distributed Clean microVM pool across compute nodes.

package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"common/config"
	gwconfig "gateway/config"
	"gateway/handler"
	"gateway/identity"
	"gateway/lease"
	"gateway/mcp"
	"gateway/pool"

	"gateway/app"
)

// Version information — set via ldflags at build time.
var (
	Version   = "0.0.0-dev"
	Commit    = "unknown"
	BuildTime = "unknown"
)

func main() {
	var (
		showVersion = flag.Bool("version", false, "Print version and exit")
		// -print-mcp-instructions prints the compiled-in agent guide. Inspection
		// / pipe-to-file only — not a required step: a configured-but-missing
		// -mcp-instructions-file is auto-materialized from this same default at
		// startup when the gateway can write it, and the deploy tooling
		// (privileged) materializes it where the gateway cannot.
		printMCP   = flag.Bool("print-mcp-instructions", false, "Print the built-in MCP server instructions (agent guide) and exit — inspection/pipe-to-file; the normal flows materialize the file automatically. Keep the {{max_exec_timeout_sec}} / {{sticky_ms}} placeholders in custom files to render the live sync-exec cap and sticky idleness window")
		configPath = flag.String("config", "", "Path to YAML config file (optional; CLI flags override config values)")
		// Ops-plane credential for the exec-mode agent listener's /stats and
		// /metrics (CLI-only, no YAML key, restart-required — same class as
		// -log-level). Empty (default) = the endpoints are NOT served on the
		// agent listener at all; set = served behind this bearer token. The
		// file's CONTENT is hot-reloaded on mtime change (token rotation is a
		// file write).
		opsTokenFile = flag.String("ops-token-file", "", "Root-owned file holding the bearer token that gates /stats and /metrics on the exec-mode agent listener (empty = those endpoints are disabled there; single-node/human modes keep their OIDC/mTLS gate and ignore this flag)")

		// Top-level
		volRoot  = flag.String("vol-root", gwconfig.DefaultVolRoot, "Shared storage mount for sandfs volumes")
		runMode  = flag.String("mode", "", "Run mode: '' (default=single-node), 'human' (management service), 'exec' (execution gateway)")
		etcdAddr = flag.String("etcd", "", "Comma-separated etcd endpoints (required for --mode human/exec, e.g., 'https://etcd:2379')")

		// Identity + connection lifetime
		gatewayIDFlag  = flag.String("gateway-id", "", "Fixed stable gateway identity. Empty = derive from hostname (k8s pod name in-cluster), pid dropped for restart stability. In k8s inject the pod name here for a clean ID.")
		idleTimeoutSec = flag.Int("idle-timeout", gwconfig.DefaultIdleTimeoutSec, "HTTP keep-alive idle timeout in seconds. Long enough that agents pausing between tool calls keep their connection (connection = affinity anchor). -1 = never close idle connections server-side (ended instead by the client, TCP keepalive, an intermediary, or a restart); values below -1 are rejected. Do not set 0 (Go falls back to ReadTimeout).")
		// Routing addresses: how other components reach THIS gateway.
		gatewayGatewayURLFlag = flag.String("gateway-url", "", "Base URL other components use to reach this gateway for agent traffic: 307 redirect Location + owner-aware DNS CNAME target. k8s in-cluster: https://$(POD_NAME).gateway-exec.$(POD_NAMESPACE).svc.cluster.local:3000. Empty = alive but unroutable (no 307/DNS).")
		gatewayStreamAddrFlag = flag.String("gateway-stream-addr", "", "host:port sandlots use to reconnect to THIS gateway (sandlot last-gateway memory). k8s in-cluster: $(POD_NAME).gateway-exec.$(POD_NAMESPACE).svc.cluster.local:9998.")

		// etcd TLS (client → etcd server)
		etcdTLSCA   = flag.String("etcd-ca", "", "CA bundle to verify the etcd server cert (enables TLS for etcd)")
		etcdTLSCert = flag.String("etcd-cert", "", "Client certificate for etcd mTLS (required when etcd uses --client-cert-auth)")
		etcdTLSKey  = flag.String("etcd-key", "", "Client private key for etcd mTLS (required if -etcd-cert set)")
		// Dev-only: a non-loopback plaintext etcd endpoint is cluster control
		// reachable from the host/pod network. Refused by default; this flag is
		// the explicit opt-out.
		allowInsecureEtcd = flag.Bool("allow-insecure-etcd", false, "Allow a non-loopback etcd endpoint WITHOUT TLS (dev/test only; etcd holds ownership/placement keys). Prefer etcd_ca/etcd_cert/etcd_key or https:// endpoints.")

		// Agent listener (HTTP)
		agentAddr    = flag.String("agent-addr", gwconfig.DefaultAgentAddr, "Agent HTTP listen address (/agent/* endpoints)")
		agentTLSCert = flag.String("agent-tls-cert", "", "Agent TLS server certificate (enables TLS)")
		agentTLSKey  = flag.String("agent-tls-key", "", "Agent TLS server private key (required if -agent-tls-cert set)")
		agentTLSCA   = flag.String("agent-tls-ca", "", "Agent CA bundle to verify client certs (enables mTLS)")

		// Human listener (HTTP)
		humanAddr    = flag.String("human-addr", gwconfig.DefaultHumanAddr, "Human HTTP listen address (/human/* endpoints)")
		humanTLSCert = flag.String("human-tls-cert", "", "Human TLS server certificate (enables TLS)")
		humanTLSKey  = flag.String("human-tls-key", "", "Human TLS server private key (required if -human-tls-cert set)")
		humanTLSCA   = flag.String("human-tls-ca", "", "Human CA bundle to verify client certs (enables mTLS)")

		// Stream listener (gRPC)
		streamAddr = flag.String("stream-addr", gwconfig.DefaultStreamAddr, "gRPC stream listen address for sandlot connections")
		// Storage plane: local (transitional in-process) vs rpc (provision
		// instances over the stream — the gateway host mounts no storage).
		storageOpDeadlineSec = flag.Int("storage-op-deadline-sec", gwconfig.DefaultStorageOpDeadlineSec, "Bounds one storage-plane op in rpc mode, seconds (template pulls can move GBs). Restart-required.")
		streamTLSCert        = flag.String("stream-tls-cert", "", "Stream TLS server certificate (enables TLS)")
		streamTLSKey         = flag.String("stream-tls-key", "", "Stream TLS server private key (required if -stream-tls-cert set)")
		streamTLSCA          = flag.String("stream-tls-ca", "", "Stream CA bundle to verify sandlot client certs (enables mTLS)")

		// Stream concurrency / transport (govern in-flight commands to one sandlot + gRPC/HTTP-2 caps)
		streamSendBuffer    = flag.Int("stream-send-buffer", config.DefaultStreamSendBuffer, "Per-sandlot max in-flight VMCommands before ErrSendQueueFull (restart)")
		streamWriteTimeout  = flag.Int("stream-write-timeout-sec", config.DefaultStreamWriteTimeoutSec, "Max seconds to wait for a stream.Send (half-open detection, restart)")
		streamInitialWindow = flag.Int("stream-initial-window-mb", config.DefaultStreamInitialWindowMB, "HTTP/2 per-stream flow-control window in MB (>= max-msg-size, restart)")
		streamConnWindow    = flag.Int("stream-conn-window-mb", config.DefaultStreamConnWindowMB, "HTTP/2 per-connection flow-control window in MB (restart)")
		streamMaxMsgSize    = flag.Int("stream-max-msg-size-mb", config.DefaultStreamMaxMsgSizeMB, "gRPC max send/recv message size in MB; >= warden single-op cap (restart)")

		// Lease
		stickyMs     = flag.Int("sticky-ms", gwconfig.DefaultStickyMs, "Sticky lease timeout in milliseconds")
		maxStickySec = flag.Int("max-sticky-sec", gwconfig.DefaultMaxStickySec, "Maximum sticky lease hold time in seconds")

		// Exec timeouts
		defaultExecTimeoutSec = flag.Int("default-exec-timeout-sec", gwconfig.DefaultExecTimeoutSec, "Default sync command timeout in seconds when the agent omits timeout (0)")
		maxExecTimeoutSec     = flag.Int("max-exec-timeout-sec", gwconfig.DefaultMaxExecTimeoutSec, "Upper bound on a sync command timeout in seconds; agent values above this are clamped. Must stay below the warden's -warden-countdown-sec (default 300) so a max-length exec always finishes before the warden's countdown fires")
		maxBackgroundLeaseSec = flag.Int("max-background-lease-sec", gwconfig.DefaultMaxBackgroundLeaseSec, "Upper bound on a background exec lease_duration in seconds (absolute run-time cap; polls do not extend it). Default 1h; raise for long-running async tasks")

		// Unmount stats
		unmountStatsPersistSec = flag.Int("unmount-stats-persist-sec", gwconfig.DefaultUnmountStatsPersistSec, "Interval in seconds to async-persist per-node unmount stats to etcd (default 600=10min). Fixed per-node footprint: counters + top-10 slowest unmounts")

		// MCP server
		mcpInstructionsFile = flag.String("mcp-instructions-file", "", "Optional markdown file with the overall MCP server guide for AI agents (served on initialize + the sandswap_guide tool): how Sandswap works, failure semantics, efficient usage. Hot-reloaded on file change (event-driven watcher, ~200ms debounce); a missing file is auto-materialized with the built-in default when writable, else (plus unreadable/oversized (>1MB)/empty) falls back to the built-in default with a warn. Empty = built-in default. Changing the PATH itself requires a restart")

		// Template configuration

		// Authn (OIDC for human endpoints)
		authnIssuer               = flag.String("authn-issuer", "", "OIDC issuer URL for human endpoint auth (empty = no auth)")
		authnClientID             = flag.String("authn-client-id", "", "OAuth2 client_id for OIDC audience validation")
		authnJWKSRefreshSec       = flag.Int("authn-jwks-refresh-sec", gwconfig.DefaultAuthnJWKSRefreshSec, "JWKS cache refresh interval in seconds")
		authnMTLSTrustCert        = flag.Bool("authn-mtls-trust-cert", false, "Trust mTLS client certificates on human listener (full scope)")
		authnScopeHuman           = flag.String("authn-scope-human", gwconfig.DefaultScopeHuman, "Scope required for user-resource /human/* endpoints (sandfs, templates)")
		authnScopeAdmin           = flag.String("authn-scope-admin", gwconfig.DefaultScopeAdmin, "Scope required for /human/agent* endpoints (agent credential minting)")
		authnScopeOps             = flag.String("authn-scope-ops", gwconfig.DefaultScopeOps, "Scope required for /stats, /metrics and /human/ownership/* endpoints (observability + fleet reclamation)")
		allowAnonymousHuman       = flag.Bool("allow-anonymous-human", false, "Explicit opt-out: allow the human listener to start with NO OIDC issuer (everything on the human control plane is then ANONYMOUS). Without this flag a human listener with no authn.issuer refuses to start. The anonymous listener must bind to loopback unless -allow-anonymous-human-public is also set")
		allowAnonymousHumanPublic = flag.Bool("allow-anonymous-human-public", false, "Second explicit acknowledgement required to bind the ANONYMOUS human control plane to a non-loopback address (LAN/ClusterIP exposure). Prefer authn.issuer or a loopback bind + tunnel/NetworkPolicy")

		// Identity store loading (etcd snapshot loader + lazy load-back; human/exec modes)
		identityLoadPageSize       = flag.Int("identity-load-page-size", gwconfig.DefaultIdentityLoadPageSize, "Etcd identity snapshot loader: keys per page (each page stays well under etcd request-size limits)")
		identityLoadWorkers        = flag.Int("identity-load-workers", gwconfig.DefaultIdentityLoadWorkers, "Etcd identity snapshot loader: parallel key-range workers")
		identityFullLoadTimeoutSec = flag.Int("identity-full-load-timeout-sec", gwconfig.DefaultIdentityFullLoadTimeoutSec, "Deadline in seconds for one full identity snapshot load (startup and post-compaction rebuilds)")
		identityLazyLoad           = flag.Bool("identity-lazy-load", true, "On-demand point Gets for identity cache misses after the initial snapshot load (singleflight-collapsed, rate-limited, negative-cached)")
		identityHotOnly            = flag.Bool("identity-hot-only", false, "Skip loading/watching sandfs display metadata (name/description); exec gateways should enable")

		// Single-node identity store (default mode only; human/exec use etcd).
		// Persistence is MANDATORY here — an explicit empty path refuses to
		// start. Corrupt snapshot / wrong version / lock held by another
		// gateway = refuse to start.
		identityStore = flag.String("identity-store", "", "Single-node identity store file: agents + sandfs records survive gateway restarts (default <parent of -vol-root>/identity-store.json; persistence cannot be disabled — an explicit empty value refuses to start; human/exec modes use etcd instead and ignore this)")
		// How long a deleted sandfs id is remembered. Must outlive every
		// plausible stale-cache window; the volume epoch is the primary
		// reuse guard, this is defense in depth.
		tombstoneTTLSec = flag.Int("tombstone-ttl-sec", 604800, "How long a deleted sandfs id is remembered for id-reuse protection (seconds; default 7 days, min 1)")

		// Sched policy
		schedPolicy      = flag.String("sched-policy", "", "Node placement policy: 'binpack' (default) or 'spread'")
		schedWLoad       = flag.Float64("sched-w-load", 0, "Scorer weight on load headroom (0 = default 0.6)")
		schedWHost       = flag.Float64("sched-w-host", 0, "Scorer weight on host headroom (0 = default 0.3)")
		schedWClean      = flag.Float64("sched-w-clean", 0, "Scorer weight on clean VM count (0 = default 0.1)")
		schedWDaily      = flag.Float64("sched-w-daily", 0, "Scorer weight on durable headroom duty_daily (0 = default 0.2)")
		schedWRisk       = flag.Float64("sched-w-risk", 0, "Scorer weight on tail-risk penalty (0 = default 0.15)")
		schedHostCPUHard = flag.Float64("sched-host-cpu-hard", 0, "Reject nodes above this host CPU %% (0 = disabled)")
		schedDutyHard    = flag.Float64("sched-duty-hard", 0, "Reject nodes above this duty_long (0 = disabled)")
		schedFloorFrac   = flag.Float64("sched-floor-frac", 0, "Tail-floor fraction of pool_target for min-clean-window (0 = default 0.2, negative = disable)")

		// voluntary load shedding (default enabled; disable explicitly to opt out).
		enableLoadShed    = flag.Bool("enable-load-shed", true, "Voluntary load shed: release cold-path sandfs ownership when sustained-saturated so DNS re-routes to an idle peer (default on; no-op without an idle peer, hot-reloadable)")
		shedSatSec        = flag.Int("shed-sat-sec", gwconfig.DefaultShedSatSec, "Voluntary load shed: sustained-saturation seconds before shedding (hysteresis)")
		shedRatePerSec    = flag.Int("shed-rate-per-sec", gwconfig.DefaultShedRatePerSec, "Voluntary load shed: max sheds per second (anti-thrash token bucket)")
		shedCooldownSec   = flag.Int("shed-cooldown-sec", gwconfig.DefaultShedCooldownSec, "Voluntary load shed: recentlyShed cooldown window (refuse re-claim so a peer can claim)")
		shedRetryAfterSec = flag.Int("shed-retry-after-sec", gwconfig.DefaultShedRetryAfterSec, "Voluntary load shed: Retry-After hint (sec) on a shed 503 (≈ sandfs DNS zone TTL)")

		// Staleness thresholds: the health key has NO lease (plain key, judged by
		// last_healthy_ts staleness), so these ARE the per-consumer death
		// thresholds. Each consumer picks its own by the cost of judging wrong:
		// routing (cheap) < alerting (early) < takeover guard (expensive).
		routeStaleSec        = flag.Int("route-stale-sec", gwconfig.DefaultRouteStaleSec, "Health staleness (sec) past which DNS routing and the 307 redirect stop routing to an owner. Judging wrong is cheap (a napping owner handles the request once it wakes), so this is the fastest death threshold. Hot-reloadable.")
		claimDeadGuardSec    = flag.Int("claim-dead-guard-sec", gwconfig.DefaultClaimDeadGuardSec, "Idle-claim protection window (sec): how long a dead-owned IDLE sandfs stays dead-and-untouched before a peer CAS-takes-over. Judging wrong is expensive (robbing a live owner), so this sits well past route-stale to ride out naps/GC pauses. Hot-reloadable.")
		alertStaleSec        = flag.Int("alert-stale-sec", gwconfig.DefaultAlertStaleSec, "Health staleness (sec) at which the alert scan warns about an owner with stranded sandfs. Warns before the takeover guard would fire. Hot-reloadable.")
		etcdFenceSec         = flag.Int("etcd-fence-sec", gwconfig.DefaultEtcdFenceSec, "Etcd-partition self-fence (sec): if the health-key write fails continuously this long, actively unmount every sandfs this gateway holds (node streams stay CONNECTED, so pools stay warm and recovery is in-place). Makes \"health stale past fence + T_clean\" provably hold no mounts, which is what makes the time-guarded takeover sound. Must satisfy T_safe > fence + T_warden + 30s (validated per node at connect, and at hot-reload against every connected node). Generous by design: transient etcd blips never fence; recovers automatically. Hot-reloadable.")
		alertScanIntervalSec = flag.Int("alert-scan-interval-sec", gwconfig.DefaultAlertScanIntervalSec, "Staleness-alert-scan cadence (sec, human gateway): a FULL ownership-prefix sweep per pass, so large fleets raise it (300s at a million sandfs ≈ hundreds of thousands of keys per pass). Min 10. Hot-reloadable.")
		ownershipCacheTTLSec = flag.Int("ownership-cache-ttl-sec", gwconfig.DefaultOwnershipCacheTTLSec, "Claim fast-path freshness window (sec): how long a cached ownership entry may serve without re-validating against etcd. THE etcd read-load lever — steady linearizable Gets/s ≈ actively-queried sandfs / TTL, and adding gateways does NOT divide it (each sandfs has exactly one owner gateway). Safety ceiling min(2×-claim-dead-guard-sec, 300) validated at startup and hot-reload (a healthy owner cannot have keys taken over; a stale-serve window ≤ TTL cannot overlap the earliest takeover commit ≈ 2×guard). Raising it only IMPROVES request latency (more fast-path hits). Hot-reloadable.")

		// Log level: info (default) emits errors/warnings + sparse lifecycle
		// events only. debug ADDITIONALLY enables per-op success-path logging
		// (mount/exec/unmount/file dispatch + "execute complete") — off by
		// default because at scale (10k+ sandfs, thousands of ops/sec) it
		// floods the log and puts JSON marshal + stderr writes on the measured
		// path. The gating flag is checked BEFORE any formatting, so a disabled
		// gate costs one atomic load per op.
		logLevelFlag = flag.String("log-level", "info", "Log level: info|debug (debug enables per-op success-path logging on the mount/exec/unmount hot paths; default info = errors/warnings + lifecycle events only)")

		// GC pacing (process-level, restart-required; see common/config.ApplyGCTuning).
		// The concurrent GC's mark/assist cycles compete with hot-path goroutines
		// for cores — at high QPS they show up as P95/P99 tail samples. Default
		// GOGC=200 halves the GC frequency for a proportionally larger heap; set
		// -gomemlimit to bound the heap in memory-constrained deployments.
		gogcFlag       = flag.Int("gogc", 0, "GC target percentage (restart-required). 0 = auto: honor the GOGC env var if set, else apply 200. Positive = force. Negative = rejected (would disable the GC).")
		gomemlimitFlag = flag.String("gomemlimit", "", "Go runtime soft memory limit, e.g. 512MiB, 8GiB (restart-required). Empty = honor the GOMEMLIMIT env var if set, else no limit. In memory-constrained deployments set it to ~90% of the container/host budget.")
	)
	flag.Parse()

	if err := identity.SetTombstoneTTL(time.Duration(*tombstoneTTLSec) * time.Second); err != nil {
		fmt.Fprintf(os.Stderr, "gateway: %v\n", err)
		os.Exit(1)
	}

	if *showVersion {
		fmt.Printf("gateway %s (commit %s, built %s)\n", Version, Commit, BuildTime)
		os.Exit(0)
	}

	if *printMCP {
		fmt.Println(mcp.DefaultInstructions)
		os.Exit(0)
	}

	var slogLevel slog.Level
	switch strings.ToLower(strings.TrimSpace(*logLevelFlag)) {
	case "debug":
		slogLevel = slog.LevelDebug
	case "info", "":
		slogLevel = slog.LevelInfo
	default:
		fmt.Fprintf(os.Stderr, "gateway: invalid -log-level %q (supported: info, debug)\n", *logLevelFlag)
		os.Exit(2)
	}
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slogLevel}))
	// Per-op success-path logs are debug-gated (and pre-formatted only when the
	// gate is open) — see pool/handler package docs. One switch drives both.
	debugOps := slogLevel == slog.LevelDebug
	pool.SetHotPathDebug(debugOps)
	handler.SetDebugLogging(debugOps)
	handler.SetMetricsBuildInfo(Version, Commit)

	// GC pacing: applied before any server work starts (restart-required).
	gcSt, err := config.ApplyGCTuning(*gogcFlag, *gomemlimitFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gateway: %v\n", err)
		os.Exit(2)
	}
	if gcSt.GOGCSet != 0 {
		logger.Info("gc pacing: GOGC applied", "gogc", gcSt.GOGCSet, "previous", gcSt.GOGCPrev)
	}
	if gcSt.MemLimitSet != 0 {
		logger.Info("gc soft memory limit applied", "bytes", gcSt.MemLimitSet, "previous", gcSt.MemLimitPrev)
	}

	// Build config: start with defaults, overlay config file, then CLI flags.
	cfg := gwconfig.Defaults()
	if *configPath != "" {
		fileCfg, err := gwconfig.LoadFromFile(*configPath)
		if err != nil {
			logger.Error("failed to load config file", "path", *configPath, "error", err)
			os.Exit(1)
		}
		cfg = fileCfg
	}
	cfg.ConfigFilePath = *configPath

	// Build flag values struct and apply CLI overrides for explicitly-set flags.
	flags := &gwconfig.GatewayFlags{
		ConfigPath:                *configPath,
		VolRoot:                   *volRoot,
		Mode:                      *runMode,
		Etcd:                      *etcdAddr,
		GatewayID:                 *gatewayIDFlag,
		GatewayURL:                *gatewayGatewayURLFlag,
		GatewayStreamAddr:         *gatewayStreamAddrFlag,
		IdleTimeoutSec:            *idleTimeoutSec,
		EtcdCA:                    *etcdTLSCA,
		EtcdCert:                  *etcdTLSCert,
		EtcdKey:                   *etcdTLSKey,
		AllowInsecureEtcd:         *allowInsecureEtcd,
		AgentAddr:                 *agentAddr,
		AgentTLSCert:              *agentTLSCert,
		AgentTLSKey:               *agentTLSKey,
		AgentTLSCA:                *agentTLSCA,
		HumanAddr:                 *humanAddr,
		HumanTLSCert:              *humanTLSCert,
		HumanTLSKey:               *humanTLSKey,
		HumanTLSCA:                *humanTLSCA,
		StreamAddr:                *streamAddr,
		StreamTLSCert:             *streamTLSCert,
		StreamTLSKey:              *streamTLSKey,
		StreamTLSCA:               *streamTLSCA,
		StorageOpDeadlineSec:      *storageOpDeadlineSec,
		StreamSendBuffer:          *streamSendBuffer,
		StreamWriteTimeout:        *streamWriteTimeout,
		StreamInitialWindow:       *streamInitialWindow,
		StreamConnWindow:          *streamConnWindow,
		StreamMaxMsgSize:          *streamMaxMsgSize,
		StickyMs:                  *stickyMs,
		MaxStickySec:              *maxStickySec,
		MCPInstructionsFile:       *mcpInstructionsFile,
		OpsTokenFile:              *opsTokenFile,
		DefaultExecTimeoutSec:     *defaultExecTimeoutSec,
		MaxExecTimeoutSec:         *maxExecTimeoutSec,
		MaxBackgroundLeaseSec:     *maxBackgroundLeaseSec,
		UnmountStatsPersistSec:    *unmountStatsPersistSec,
		AuthnIssuer:               *authnIssuer,
		AuthnClientID:             *authnClientID,
		AuthnJWKSRefreshSec:       *authnJWKSRefreshSec,
		AuthnMTLSTrustCert:        *authnMTLSTrustCert,
		AuthnScopeHuman:           *authnScopeHuman,
		AuthnScopeAdmin:           *authnScopeAdmin,
		AuthnScopeOps:             *authnScopeOps,
		AllowAnonymousHuman:       *allowAnonymousHuman,
		AllowAnonymousHumanPublic: *allowAnonymousHumanPublic,

		IdentityLoadPageSize:       *identityLoadPageSize,
		IdentityLoadWorkers:        *identityLoadWorkers,
		IdentityFullLoadTimeoutSec: *identityFullLoadTimeoutSec,
		IdentityLazyLoad:           *identityLazyLoad,
		IdentityHotOnly:            *identityHotOnly,
		IdentityStore:              *identityStore,

		SchedPolicy:       *schedPolicy,
		SchedWLoad:        *schedWLoad,
		SchedWHost:        *schedWHost,
		SchedWClean:       *schedWClean,
		SchedWDaily:       *schedWDaily,
		SchedWRisk:        *schedWRisk,
		SchedHostCPUHard:  *schedHostCPUHard,
		SchedDutyHard:     *schedDutyHard,
		SchedFloorFrac:    *schedFloorFrac,
		ShedEnabled:       *enableLoadShed,
		ShedSatSec:        *shedSatSec,
		ShedRatePerSec:    *shedRatePerSec,
		ShedCooldownSec:   *shedCooldownSec,
		ShedRetryAfterSec: *shedRetryAfterSec,

		StalenessRouteStaleSec:        *routeStaleSec,
		StalenessClaimDeadGuardSec:    *claimDeadGuardSec,
		StalenessAlertStaleSec:        *alertStaleSec,
		StalenessEtcdFenceSec:         *etcdFenceSec,
		StalenessAlertScanIntervalSec: *alertScanIntervalSec,
		OwnershipCacheTTLSec:          *ownershipCacheTTLSec,
	}
	explicitSet := config.ExplicitFlags()
	cfg.ApplyFlagOverrides(flags, explicitSet)
	if err := cfg.ValidateStorageDeadline(); err != nil {
		logger.Error("invalid config", "error", err)
		os.Exit(1)
	}
	if err := cfg.ValidateSchedPolicy(); err != nil {
		logger.Error("invalid config", "error", err)
		os.Exit(1)
	}
	if err := cfg.ValidateSelfLoad(); err != nil {
		logger.Error("invalid config", "error", err)
		os.Exit(1)
	}
	// The reload path re-applies the same overrides, so a file edit never
	// reverts a flag-provided value.
	cfg.SetFlagReapplier(func(c *gwconfig.GatewayConfig) { c.ApplyFlagOverrides(flags, explicitSet) })

	// Idle-timeout guard: http.Server treats IdleTimeout==0 as "use
	// ReadTimeout" (30s) — silently far SHORTER than the intended keep-alive
	// window. -1 is the supported "never close idle connections" form
	// (gwconfig.NeverCloseIdle); anything below -1 is a typo (e.g. -3600 that
	// was meant as 3600) and is rejected outright rather than silently
	// meaning "never close".
	switch {
	case cfg.IdleTimeoutSec < -1:
		logger.Error("invalid -idle-timeout: values below -1 are not defined — use a positive number of seconds, 0 is forbidden (ReadTimeout fallback), or -1 to never close idle connections", "value", cfg.IdleTimeoutSec)
		os.Exit(1)
	case cfg.IdleTimeoutSec == 0:
		logger.Warn("-idle-timeout=0 falls back to the 30s ReadTimeout — idle connections dropped after 30s; set a positive value, or -1 to never close")
	case cfg.IdleTimeoutSec == -1:
		logger.Info("-idle-timeout=-1: never closing idle connections server-side (ended instead by the client, TCP keepalive, an intermediary, or a restart)")
	}

	// Background-lease cap guard: execute.go converts the cap to MILLISECONDS
	// in a uint32 — a cap above ~49.7 days would silently wrap to a much
	// shorter value. Reject the misconfiguration instead.
	if cfg.Exec.MaxBackgroundLeaseSec > handler.MaxBackgroundLeaseSecCap {
		logger.Error("invalid -max-background-lease-sec: values above the uint32-millisecond ceiling are not representable as a lease duration",
			"value", cfg.Exec.MaxBackgroundLeaseSec, "max", handler.MaxBackgroundLeaseSecCap)
		os.Exit(1)
	}

	// Etcd exposure guard: a non-loopback plaintext etcd endpoint is cluster
	// control (ownership/placement) reachable from the network. Require TLS or
	// the explicit dev-only opt-out.
	if err := cfg.ValidateEtcd(); err != nil {
		logger.Error("invalid etcd configuration", "error", err)
		os.Exit(1)
	}

	// Lease-knob guard: sticky_ms >= 1 (0 or negative breaks the window-refresh
	// mechanism that lets post-completion concurrent arrivals join the warm VM)
	// and max_sticky_sec >= 1 (<= 0 silently disables the maxHold reaper).
	if err := cfg.ValidateLease(); err != nil {
		logger.Error("invalid lease configuration", "error", err)
		os.Exit(1)
	}

	// Exec-timeout guard: default/max must be >= 1 and max >= default. The
	// ExecuteHandler constructor would silently normalize a violation (max <
	// default becomes the default) — a config the operator did not write.
	if err := cfg.ValidateExec(); err != nil {
		logger.Error("invalid exec configuration", "error", err)
		os.Exit(1)
	}

	// Timing-headroom guard: a maximum-length sync exec plus one health-refresh
	// tick and one node heartbeat must stay inside T_safe, or a max exec could
	// still hold its mount when the presence key that anchors "all mounts
	// released" expires. Validated against the contract-default T_safe here;
	// hot-reload re-checks through the handler's UpdateTimeouts.
	if err := lease.ValidateExecTiming(time.Duration(cfg.Exec.MaxTimeoutSec)*time.Second, lease.DefaultTSafe()); err != nil {
		logger.Error("invalid exec timing configuration", "error", err)
		os.Exit(1)
	}

	// Stream transport guard: windows/message-size caps must hold the shared
	// gateway/sandlot contract (int32 range, window >= message size, 16MB
	// FileOp chain); send buffer and write timeout must be >= 1 (the stream
	// server otherwise silently substitutes defaults).
	if err := cfg.ValidateStreamConcurrency(); err != nil {
		logger.Error("invalid stream configuration", "error", err)
		os.Exit(1)
	}

	// Staleness guard: thresholds >= 1 and the judging-cost ordering — routing
	// and alerting must give up on an owner no later than the takeover guard.
	if err := cfg.ValidateStaleness(); err != nil {
		logger.Error("invalid staleness configuration", "error", err)
		os.Exit(1)
	}

	// Ownership-cache TTL guard: the stale-serve window must stay under the
	// earliest-takeover ceiling min(2×claim-dead-guard, 300) — see
	// ValidateOwnership for the derivation.
	if err := cfg.ValidateOwnership(); err != nil {
		logger.Error("invalid ownership cache TTL configuration", "error", err)
		os.Exit(1)
	}

	// Load-shed guard: a negative cooldown lets the next DNS resolution
	// instantly undo a shed; retry_after <= 0 is silently replaced by a
	// hardcoded 5.
	if err := cfg.ValidateShed(); err != nil {
		logger.Error("invalid shed configuration", "error", err)
		os.Exit(1)
	}

	// Ops token gate (exec mode's agent listener): a configured-but-broken
	// ops credential must refuse to boot — failing later would mean either
	// serving the ops endpoints open or crashing mid-serve. The gate itself
	// re-validates at construction inside RunExecMode.
	if cfg.OpsTokenFile != "" && cfg.Mode == "exec" {
		if _, err := handler.NewOpsTokenGate(cfg.OpsTokenFile, logger); err != nil {
			logger.Error("invalid -ops-token-file", "path", cfg.OpsTokenFile, "error", err)
			os.Exit(1)
		}
	}

	// Route to the appropriate run mode. The mode wiring (identity store,
	// listeners, stream server, hot-reload) lives in gateway/app.
	switch cfg.Mode {
	case "human":
		app.RunHumanMode(logger, &cfg)
		return
	case "exec":
		app.RunExecMode(logger, &cfg)
		return
	case "":
		// Single-node mode (default): execution + human in one process with MemoryStore.
		app.RunSingleNodeMode(logger, &cfg)
	default:
		logger.Error("unknown mode", "mode", cfg.Mode, "valid", "'', 'human', 'exec'")
		os.Exit(1)
	}
}

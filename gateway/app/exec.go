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

package app

import (
	"context"
	"log"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"gateway/handler"
	"gateway/identity"
	"gateway/lease"
	"gateway/maintenance"
	"gateway/mcp"
	"gateway/pool"
	"gateway/stats"
	"gateway/stream"

	gwconfig "gateway/config"
)

// RunExecMode starts the gateway in execution mode: serves /agent/* endpoints
// with EtcdStore (read-only cache from etcd watch). Connects to sandlot
// nodes via gRPC stream. Used in multi-node deployments.
func RunExecMode(logger *slog.Logger, cfg *gwconfig.GatewayConfig) {
	if cfg.Etcd == "" {
		logger.Error("--etcd is required for --mode exec")
		os.Exit(1)
	}
	// Identity lives in etcd here; the single-node store flag does nothing —
	// warn on BOTH a passed flag and a YAML identity_store value, so neither
	// is dropped silently.
	if cfg.IdentityStoreExplicit || cfg.IdentityStore != "" {
		logger.Warn("-identity-store is ignored in exec mode (etcd holds identity; single-node only)")
	}

	logger.Info("starting gateway (exec mode)",
		"agentAddr", cfg.Agent.Addr,
		"streamAddr", cfg.Stream.Addr,
		"etcd", cfg.Etcd,
		"volRoot", cfg.VolRoot,
	)

	// Lease manager and the fixed gateway identity come BEFORE the identity
	// store: the store's record watcher (the split-mode lifecycle drain
	// trigger) closes over them. The watcher body gates on lifecycleReady —
	// closed once the pool/ownership wiring below is complete — so no watch
	// event can observe a half-wired gateway.
	lm := lease.New(
		time.Duration(cfg.Lease.StickyMs)*time.Millisecond,
		time.Duration(cfg.Lease.MaxStickySec)*time.Second,
	)
	gatewayID := resolveGatewayID(cfg, "exec")
	lifecycleReady := make(chan struct{})
	var lifecyclePool *pool.Manager

	// Create EtcdStore (read-only cache from watch) with the lifecycle record
	// watcher: a sandfs flipping to "detaching"/"deleting" that THIS gateway
	// holds (warm lease or etcd ownership) is drained here and settled to
	// "detached" — the exec side of the split-mode template-swap/delete
	// orchestration (the human gateway only writes the status and polls).
	var etcdStore *identity.EtcdStore
	execLoadOpts := append(identityLoadOptions(cfg), identity.WithRecordWatcher(func(sandfsID, status string) {
		switch status {
		case identity.SandfsStatusDetaching, identity.SandfsStatusDeleting:
		default:
			return
		}
		go func() {
			<-lifecycleReady
			drainLifecycleSandfs(lifecyclePool, lm, etcdStore, gatewayID, sandfsID, logger)
		}()
	}))
	endpoints := strings.Split(cfg.Etcd, ",")
	etcdStore, err := identity.NewEtcdStore(endpoints, "/sandswap/identity/", cfg.VolRoot, nil, logger, execLoadOpts...)
	if err != nil {
		logger.Error("failed to create etcd store", "error", err)
		os.Exit(1)
	}
	defer etcdStore.Close()

	streamLogger := log.New(os.Stderr, "[stream] ", log.LstdFlags|log.Lmsgprefix)
	streamSrv := stream.NewServer(gatewayID, streamLogger, cfg.StreamConcurrency.SendBufferSize, time.Duration(cfg.StreamConcurrency.WriteTimeoutSec)*time.Second)
	sandlotClient := pool.NewStreamSandlotClient(streamSrv)

	// Ownership cache: cross-gateway coordination via etcd.
	ownership, err := lease.NewOwnershipCache(etcdStore.Client(), gatewayID, streamSrv, logger)
	if err != nil {
		logger.Error("failed to create ownership cache", "error", err)
		os.Exit(1)
	}
	// Register routing addresses in the /sandswap/gateway/{id} registry key
	// (307 redirect target, owner-aware DNS CNAME target, sandlot last-gateway
	// reconnect addr). Plain key, no lease — survives the gateway's death.
	ownership.SetMaxExecTimeout(time.Duration(cfg.Exec.MaxTimeoutSec) * time.Second)
	ownership.SetRoutingAddrs(cfg.GatewayURL, cfg.GatewayStreamAddr)
	// Joint application: the guard/TTL ceiling invariant is validated against
	// the INCOMING pair. Sequential setters would reject a config-valid pair
	// whenever a leg is checked against the other's default (e.g. a small
	// test/fleet guard with the 30s default TTL still live).
	if err := ownership.SetStalenessAndCacheTTL(
		time.Duration(cfg.Staleness.RouteStaleSec)*time.Second,
		time.Duration(cfg.Staleness.ClaimDeadGuardSec)*time.Second,
		time.Duration(cfg.Staleness.AlertStaleSec)*time.Second,
		time.Duration(cfg.Ownership.CacheTTLSec)*time.Second,
	); err != nil {
		// Startup validation (ValidateStaleness + ValidateOwnership) already
		// guarantees a valid pair, so this can only fire on a wiring bug —
		// loud, not silent.
		logger.Error("startup staleness/cache-TTL pair rejected", "error", err)
		os.Exit(1)
	}
	if err := ownership.SetAlertScanInterval(time.Duration(cfg.Staleness.AlertScanIntervalSec) * time.Second); err != nil {
		logger.Error("startup alert scan interval rejected", "error", err)
		os.Exit(1)
	}
	if cfg.GatewayURL == "" || cfg.GatewayStreamAddr == "" {
		logger.Warn("gateway routing addrs not fully set — 307 redirect and owner-aware DNS will not route to this gateway",
			"gatewayID", gatewayID, "gatewayURL", cfg.GatewayURL, "streamAddr", cfg.GatewayStreamAddr)
	}
	ownership.StartHealthLoop()
	ownership.StartWatch()
	// Owner-release sweep: exec-gateway machinery (its pendingOwnerRelease
	// inputs come from the exec-role stream wiring below). The human gateway
	// constructs the cache too but never starts the sweep.
	ownership.StartOwnerReleaseSweep()
	defer ownership.Close()

	pm := pool.NewManager(sandlotClient, logger)
	pm.SetSchedPolicy(gwconfig.SchedPolicyFromConfig(cfg.Sched))
	lifecyclePool = pm
	// The record watcher can now act (pool + lease wired). Also compensate
	// for statuses written while this process was offline: the startup
	// snapshot already carries them but no watch event ever fired here.
	close(lifecycleReady)
	etcdStore.NotifyInitialStatuses()

	wireStreamCallbacks(streamSrv, pm, lm, sandlotClient, ownership, logger)

	// Per-node unmount stats collector (fixed footprint: counters + top-10 slow).
	// Records mount/unmount latency on the async release path + post-cold-mount;
	// persists a snapshot to etcd every PersistIntervalSec for peer /stats.
	unmountStats := stats.NewUnmountStats(
		stats.DefaultTopN,
		time.Duration(cfg.UnmountStats.PersistIntervalSec)*time.Second,
		etcdStore.Client(),
		gatewayID,
		logger,
	)
	pm.SetUnmountRecorder(unmountStats)
	// 1ms-sticky punctuality: expiry-timer fires that dispatch an unmount
	// report their lag into the same per-node stats.
	wireLeaseFireLag(lm, unmountStats)
	unmountStatsCtx, unmountStatsCancel := context.WithCancel(context.Background())
	defer unmountStatsCancel()
	go unmountStats.StartPersist(unmountStatsCtx)

	// Etcd-partition self-fence: after sustained etcd unreachability the health
	// loop actively unmounts everything this gateway holds. The node streams
	// stay CONNECTED (pools stay warm, recovery is in-place) — the release
	// therefore completes within fence + T_clean, which is why T_safe keeps its
	// original T_tolerance + T_warden + 60s shape with no fence term. After it,
	// "our health key is stale" provably carries no live mount.
	ownership.SetFenceController(nil, func() int {
		return fenceReleaseAllMounts(ownership, lm, pm, sandlotClient, unmountStats, logger)
	}, time.Duration(cfg.Staleness.EtcdFenceSec)*time.Second)

	// Uncovered-mount compensation: when a cold mount's placement publish
	// cannot be confirmed (CAS lost to a foreign/deleted record, or etcd
	// errors past the retry budget), or the watch observes our record deleted
	// while the cache says mounted, the live mount is no longer covered by
	// the ownership record — ForceUnmount tears it down through the same
	// success-gated, SettleUnmount-guarded expiry path as a lease expiry
	// (with the lease layer's backoff retry on unmount failure). This is
	// what keeps "no ownership record ⇒ no live mount" (and therefore the
	// takeover/fence soundness proofs) true on publish races.
	ownership.SetMountCompensator(func(sandfsID, nodeID string) {
		lm.ForceUnmount(sandfsID, nodeID, lm.SpecOf(sandfsID))
	})

	// Lease expiry: unmount the sandfs from the node holding it (its VM returns
	// to CLEAN) and clear the ownership node_id so the sandfs is reroutable.
	// sandlot resolves sandfs_id -> VM; UnmountRootfs is idempotent.
	//
	// Teardown is SUCCESS-GATED: on unmount failure the entry, the bound-VM
	// reservation, and the mounted flag all stay (RetryUnmount re-dispatches
	// with backoff). Releasing them anyway would leak the live mount while the
	// accounting says clean — and a later cold mount on another node would
	// dual-mount the rootfs. A node disconnect (ReleaseByNode) or a successful
	// retry resolves the entry; node-death cleanup is the sandlot's own
	// tolerance chain either way.
	//
	// TODO(batch-unmount): one RPC per expired lease; a burst of simultaneous
	// expiries (load spike ebbing) fans into the same single-unmount command —
	// see the StreamSandlotClient.UnmountRootfs TODO if that ever matters.
	lm.StartExpiryWorker(func(sandfsID, nodeID, spec, volumePath string) {
		if logger.Enabled(context.Background(), slog.LevelDebug) {
			logger.Info("lease expired, unmounting sandfs from node", "sandfsID", sandfsID, "node", nodeID)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		res, err := sandlotClient.UnmountRootfs(ctx, nodeID, sandfsID, volumePath, lm.VolumeEpochOf(sandfsID))
		cancel()
		if unmountStats != nil {
			unmountStats.RecordUnmount(nodeID, sandfsID, "lease-expiry", res, err == nil)
		}
		if err != nil {
			logger.Warn("lease expiry unmount failed; will retry with backoff", "sandfsID", sandfsID, "node", nodeID, "error", err)
			lm.RetryUnmount(sandfsID, nodeID, spec)
			return
		}
		// Exactly-once teardown: lease expiry, the etcd fence, and the
		// ownership publish-failure compensation can all run idempotent
		// unmounts for the same sandfs concurrently — SettleUnmount lets the
		// FIRST settler free the bound reservation and flips the mount state,
		// so a racing settler cannot double-decrement the node's bound count.
		if lm.SettleUnmount(sandfsID) {
			pm.ReleaseBound(nodeID, spec) // free the bound VM -> derived clean rises (reuse nodeA)
			if ownership != nil {
				// Mount state is transient (memory-only): just flip it off. The
				// placement survives unmount — no etcd write on the unmount path.
				ownership.NoteUnmounted(sandfsID)
			}
		}
	})
	defer lm.Close()

	// Self-pressure monitor: process-scoped CPU (vs GOMAXPROCS) + soft-limit
	// memory signals, sustained past selfload.sat_sec. Published inside the
	// load record; the DNS gates routing eligibility on it. Also wraps the
	// agent listener with the in-flight counter (observability only).
	selfMon := lease.NewSelfPressureMonitor(cfg.SelfLoad.CpuHard, cfg.SelfLoad.MemHard, cfg.SelfLoad.SatSec, logger)
	selfMonCtx, selfMonCancel := context.WithCancel(context.Background())
	defer selfMonCancel()
	go selfMon.Start(selfMonCtx)

	// Publish scheduling load to /sandswap/load/{gw} for DNS routing + global
	// /stats view
	loadCtx, loadCancel := context.WithCancel(context.Background())
	defer loadCancel()
	go startLoadPublisher(loadCtx, etcdStore.Client(), gatewayID, pm, selfMon, logger)

	// voluntary load shedding: a peer-load monitor (watches
	// /sandswap/load/ for idle peers) + a ShedController bound to the ownership
	// cache + pool manager. Enabled by default (cfg.Shed.Enabled); when off,
	// ShedController.MaybeShed always returns None and behavior is unchanged.
	peerMon := lease.NewPeerLoadMonitor(etcdStore.Client(), gatewayID, logger)
	peerMonCtx, peerMonCancel := context.WithCancel(context.Background())
	defer peerMonCancel()
	peerMon.Start(peerMonCtx)
	shedCfg := &lease.ShedConfig{}
	shedCfg.Update(cfg.Shed.Enabled, cfg.Shed.SatSec, cfg.Shed.RatePerSec, cfg.Shed.CooldownSec, cfg.Shed.RetryAfterSec)
	shedCtl := lease.NewShedController(shedCfg, pm, ownership, peerMon, logger)
	// Never shed a sandfs whose VM this gateway still holds — deleting its
	// ownership under a live lease opens a dual-mount window until the lease
	// expires (a background exec can hold it for an hour). HasEntry (not
	// HasActiveEntry): an entry stuck UNMOUNTING with a failing unmount RPC
	// still has a LIVE mount — the retry chain can run for minutes.
	shedCtl.SetLocalMountGuard(lm.HasEntry)
	// Background sweep of expired recentlyShed entries (bounds the map).
	go func() {
		t := time.NewTicker(10 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-peerMonCtx.Done():
				return
			case <-t.C:
				ownership.ShedCooldownSweep()
			}
		}
	}()

	// Start gRPC stream server. An exec gateway serves exec-role node
	// connections only: a prov instance dialing here is rejected at the
	// handshake with a named reason (point it at a human/unified gateway).
	startStreamServer(streamSrv, []string{stream.RoleExec}, cfg.Stream.Addr, cfg.Stream.TLSCert, cfg.Stream.TLSKey, cfg.Stream.TLSCA, cfg.StreamConcurrency, logger)
	// An exec gateway has no storage-plane surface at all (no sandfs CRUD,
	// no template endpoints — identity is etcd, execution is delegated). It
	// accepts exec-role node connections only.

	// Shared resilience state.
	ml := lease.NewMountLock()
	ss := lease.NewSandfsState()

	// Register HTTP handlers (execute + agent, no human).
	execHandler := handler.NewExecuteHandler(etcdStore, pm, lm, sandlotClient, ml, ownership, ss, cfg.Exec.DefaultTimeoutSec, cfg.Exec.MaxTimeoutSec, cfg.Exec.MaxBackgroundLeaseSec, logger)
	fileHandler := handler.NewFileHandler(etcdStore, pm, lm, sandlotClient, ml, ownership, ss, logger)
	agentHandler := handler.NewAgentHandler(etcdStore, logger)
	execHandler.SetShedController(shedCtl)
	fileHandler.SetShedController(shedCtl)
	execHandler.SetUnmountRecorder(unmountStats)
	fileHandler.SetUnmountRecorder(unmountStats)
	mcpServer := mcp.NewMCPServer(etcdStore, execHandler, fileHandler, agentHandler, lm, pm, sandlotClient, gatewayID,
		mcp.ResolveInstructions(cfg.MCP.InstructionsFile, logger), logger)
	if cfg.MCP.InstructionsFile != "" {
		mcpInstrCtx, mcpInstrCancel := context.WithCancel(context.Background())
		defer mcpInstrCancel()
		go mcpServer.StartInstructionsFileWatcher(mcpInstrCtx, cfg.MCP.InstructionsFile, logger)
	}

	// Service-refusal switch (see gateway/maintenance): the rotation window is
	// opened through the HUMAN gateway, so this process mirrors the fleet key
	// instead of owning the state. A restart mid-window comes back refusing —
	// the key, not this process's memory, is authoritative.
	maintSwitch := &maintenance.Switch{}
	if cli := etcdStore.Client(); cli != nil {
		maintCtx, maintCancel := context.WithCancel(context.Background())
		defer maintCancel()
		go maintenance.WatchKey(maintCtx, cli, logger, maintSwitch)
	}

	mux := http.NewServeMux()
	mux.Handle("/agent/execute", execHandler)
	mux.HandleFunc("/agent/exec/status", execHandler.HandleExecStatus)
	mux.HandleFunc("/agent/exec/kill", execHandler.HandleExecKill)
	mux.Handle("/agent/file", fileHandler)
	mux.HandleFunc("/agent/sandfs", agentHandler.ListSandFS)
	mux.HandleFunc("/mcp", mcpServer.HandleHTTPRequest)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})
	// Readiness: serve agent traffic only after BOTH the identity snapshot load
	// and the ownership full-load recovery complete. /health stays liveness
	// (200) so a k8s livenessProbe never restarts a gateway that is still
	// warming up. gateUntilReady 503s business routes until then.
	mux.HandleFunc("/ready", func(w http.ResponseWriter, r *http.Request) {
		if etcdStore.Ready() && (ownership == nil || ownership.Ready()) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status":"ready"}`))
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte(`{"status":"not_ready"}`))
		}
	})
	// /stats on the exec agent listener: aggregate the cluster view from etcd
	// (same /sandswap/{load,health,gateway}/ keys the DNS reads) so `sandctl
	// pool` and ops get a multi-gateway report, not 404. exec mode has no human
	// listener, so /stats rides on the agent listener.
	execStatsHandler := handler.NewStatsHandler(pm, logger)
	execStatsHandler.SetStatsClient(etcdStore.Client(), gatewayID)
	execStatsHandler.SetUnmountStats(unmountStats)
	// this listener is the AGENT listener: /stats and /metrics are fleet-wide
	// ops views on a tenant-reachable address, so they are NEVER served
	// unauthenticated here. With -ops-token-file they sit behind a static
	// bearer token (the ops audience is separate from tenant API keys; the
	// human API keeps its OIDC/mTLS gate). Without the flag the endpoints
	// are absent — the fail-closed default. Redaction
	// (SetRedactTenantIDs) stays on as the second layer.
	execStatsHandler.SetRedactTenantIDs(true)
	var statsRoute, metricsRoute http.Handler
	if cfg.OpsTokenFile != "" {
		gate, err := handler.NewOpsTokenGate(cfg.OpsTokenFile, logger)
		if err != nil {
			// Validated at startup (cmd/main.go) — reaching here means the
			// file broke between validation and serving. Serving an ops view
			// with a broken credential file is not an option.
			logger.Error("ops token gate failed to initialize; refusing to start", "path", cfg.OpsTokenFile, "error", err)
			os.Exit(1)
		}
		statsRoute = gate.Wrap(execStatsHandler)
		metricsRoute = gate.Wrap(http.HandlerFunc(execStatsHandler.Metrics))
	} else {
		statsRoute = http.HandlerFunc(handler.OpsEndpointsDisabled)
		metricsRoute = http.HandlerFunc(handler.OpsEndpointsDisabled)
	}
	mux.Handle("/stats", statsRoute)
	mux.Handle("/metrics", metricsRoute)

	server := &http.Server{
		Addr: cfg.Agent.Addr,
		// selfMon.Middleware sits OUTSIDE withRecovery: a recovered panic
		// still unwinds through the in-flight decrement.
		Handler:      selfMon.Middleware(withRecovery(logger, maintSwitch.Middleware(gateUntilReady(etcdStore, mux)))),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: time.Duration(cfg.Exec.MaxTimeoutSec+30) * time.Second,
		IdleTimeout:  cfg.IdleTimeout(),
	}
	if cfg.Agent.TLSCert != "" {
		tlsCfg, err := buildHTTPServerTLS(cfg.Agent.TLSCert, cfg.Agent.TLSKey, cfg.Agent.TLSCA)
		if err != nil {
			logger.Error("invalid agent listener TLS config", "error", err)
			os.Exit(1)
		}
		server.TLSConfig = tlsCfg
		logger.Info("agent HTTP TLS enabled", "mtls", cfg.Agent.TLSCA != "")
	}

	// Start hot-reload if config file path was provided.
	startConfigReload(cfg.ConfigFilePath, cfg, &gwconfig.HotReloadTargets{
		LeaseMgr: lm,
		PoolMgr:  pm,
		UpdateExecTimeouts: func(defaultSec, maxSec int) {
			execHandler.UpdateTimeouts(defaultSec, maxSec)
		},
		UpdateMaxBackgroundLeaseSec: func(sec int) {
			execHandler.UpdateMaxBackgroundLeaseSec(sec)
		},
		UpdateShedConfig: func(enabled bool, satSec, ratePerSec, cooldownSec, retryAfterSec int) {
			shedCfg.Update(enabled, satSec, ratePerSec, cooldownSec, retryAfterSec)
			logger.Info("shed config hot-reloaded", "enabled", enabled, "satSec", satSec,
				"ratePerSec", ratePerSec, "cooldownSec", cooldownSec, "retryAfterSec", retryAfterSec)
		},
		UpdateSelfLoad: func(cpuHard, memHard float64, satSec int) {
			selfMon.Update(cpuHard, memHard, satSec)
			logger.Info("selfload config hot-reloaded", "cpuHard", cpuHard,
				"memHard", memHard, "satSec", satSec)
		},
		UpdateUnmountStatsInterval: func(sec int) {
			unmountStats.UpdateInterval(time.Duration(sec) * time.Second)
			logger.Info("unmount-stats persist interval hot-reloaded", "sec", sec)
		},
		UpdateStalenessThresholds: func(routeSec, guardSec, alertSec int) {
			if err := ownership.SetStalenessThresholds(
				time.Duration(routeSec)*time.Second,
				time.Duration(guardSec)*time.Second,
				time.Duration(alertSec)*time.Second,
			); err != nil {
				// Most likely the guard/TTL pair broke (guard lowered below
				// TTL/2) — keep the previous thresholds; ApplyHotReload already
				// logged the config-level validation verdict.
				logger.Error("staleness thresholds hot-reload refused; keeping previous values", "error", err)
			} else {
				logger.Info("staleness thresholds hot-reloaded",
					"routeSec", routeSec, "guardSec", guardSec, "alertSec", alertSec)
			}
		},
		UpdateFenceSec: func(sec int) {
			// Refuses a value that would break T_safe > fence + warden +
			// heartbeat for any connected node — the reload then keeps the
			// previous threshold (exec mode is the only mode with a fence
			// controller wired).
			if err := ownership.UpdateFenceThreshold(time.Duration(sec) * time.Second); err != nil {
				logger.Error("etcd fence threshold hot-reload refused; keeping previous value", "error", err)
			} else {
				logger.Info("etcd fence threshold hot-reloaded", "sec", sec)
			}
		},
		UpdateOwnershipCacheTTL: func(sec int) {
			if err := ownership.SetCacheTTL(time.Duration(sec) * time.Second); err != nil {
				logger.Error("ownership cache TTL hot-reload refused; keeping previous value", "error", err)
			} else {
				logger.Info("ownership cache TTL hot-reloaded", "sec", sec)
			}
		},
		UpdateStalenessAndCacheTTL: func(routeSec, guardSec, alertSec, ttlSec int) {
			if err := ownership.SetStalenessAndCacheTTL(
				time.Duration(routeSec)*time.Second,
				time.Duration(guardSec)*time.Second,
				time.Duration(alertSec)*time.Second,
				time.Duration(ttlSec)*time.Second,
			); err != nil {
				logger.Error("staleness/cache-TTL pair hot-reload refused; keeping previous values", "error", err)
			} else {
				logger.Info("staleness thresholds + ownership cache TTL hot-reloaded",
					"routeSec", routeSec, "guardSec", guardSec, "alertSec", alertSec, "ttlSec", ttlSec)
			}
		},
		UpdateAlertScanInterval: func(sec int) {
			if err := ownership.SetAlertScanInterval(time.Duration(sec) * time.Second); err != nil {
				logger.Error("alert scan interval hot-reload refused; keeping previous value", "error", err)
			} else {
				logger.Info("alert scan interval hot-reloaded", "sec", sec)
			}
		},
	}, logger)

	logger.Info("exec gateway listening", "agentAddr", cfg.Agent.Addr)
	serveWithGracefulShutdown(server, logger)
}

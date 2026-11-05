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
	"os/signal"
	"syscall"
	"time"

	"gateway/authn"
	gwconfig "gateway/config"
	"gateway/handler"
	"gateway/identity"
	"gateway/lease"
	"gateway/maintenance"
	"gateway/mcp"
	"gateway/pool"
	"gateway/registry"
	"gateway/stats"
	"gateway/stream"
)

// RunSingleNodeMode starts the gateway in single-node mode (default):
// execution + human in one process with MemoryStore. Backward compatible.
// Three independent listeners: agent HTTP, human HTTP, gRPC stream.
func RunSingleNodeMode(logger *slog.Logger, cfg *gwconfig.GatewayConfig) {
	// Single-node mode ignores -etcd entirely (only human/exec modes read it);
	// warn rather than let a misconfigured operator believe etcd is in use.
	if cfg.Etcd != "" {
		logger.Warn("-etcd is ignored in single-node mode (human/exec modes only); using the in-memory identity store",
			"etcd", cfg.Etcd)
	}

	snapPath := cfg.EffectiveIdentityStorePath()
	// Persistence is mandatory in MemoryStore mode: an explicitly-passed empty
	// path must fail loudly, not silently fall back to the default — an
	// operator asking to disable persistence is asking for the exact
	// identity-loss bug this feature fixes (corrupt/locked snapshots also
	// refuse below).
	if cfg.IdentityStoreExplicit && cfg.IdentityStore == "" {
		logger.Error("-identity-store= (empty) is not allowed: persistence is mandatory in single-node mode; unset the flag for the default path or set an explicit path")
		os.Exit(1)
	}
	logger.Info("starting gateway (single-node mode)",
		"agentAddr", cfg.Agent.Addr,
		"humanAddr", cfg.Human.Addr,
		"streamAddr", cfg.Stream.Addr,
		"volRoot", cfg.VolRoot,
		"identityStore", snapPath,
	)

	// Identity outlives the process: load the snapshot (corrupt/wrong version/
	// lock held → refuse to start) BEFORE any listener exists.
	store, err := identity.NewPersistentMemoryStore(cfg.VolRoot, snapPath, logger)
	if err != nil {
		logger.Error("failed to load identity store", "path", snapPath, "error", err)
		os.Exit(1)
	}
	reg := registry.NewWithStore(store, cfg.VolRoot)

	lm := lease.New(
		time.Duration(cfg.Lease.StickyMs)*time.Millisecond,
		time.Duration(cfg.Lease.MaxStickySec)*time.Second,
	)

	streamLogger := log.New(os.Stderr, "[stream] ", log.LstdFlags|log.Lmsgprefix)
	// Same resolved identity as /stats and the MCP server — the HelloAck's
	// gateway id is the sandlot's "last gateway" memory, so it must match the
	// identity every other component derives (a hardcoded "gateway-1" here used
	// to disagree with resolveGatewayID's value).
	streamSrv := stream.NewServer(resolveGatewayID(cfg, "single"), streamLogger, cfg.StreamConcurrency.SendBufferSize, time.Duration(cfg.StreamConcurrency.WriteTimeoutSec)*time.Second)
	sandlotClient := pool.NewStreamSandlotClient(streamSrv)

	pm := pool.NewManager(sandlotClient, logger)
	pm.SetSchedPolicy(gwconfig.SchedPolicyFromConfig(cfg.Sched))
	// bound the storage plane's declared template minimums to the
	// largest advertised spec before they become persistent placement
	// requirements (a value above every spec pins the sandfs into permanent
	// NO_AVAILABLE_SANDBOX).
	reg.SetSpecCeiling(pm.MaxSpecResources)

	wireStreamCallbacks(streamSrv, pm, lm, sandlotClient, nil, logger)

	// Per-node unmount stats collector (single-node: no etcd → in-memory only,
	// surfaced via the local /stats handler). nil cli = StartPersist is a no-op.
	unmountStats := stats.NewUnmountStats(
		stats.DefaultTopN,
		time.Duration(cfg.UnmountStats.PersistIntervalSec)*time.Second,
		nil,
		resolveGatewayID(cfg, "single"),
		logger,
	)
	pm.SetUnmountRecorder(unmountStats)
	// 1ms-sticky punctuality: expiry-timer fires that dispatch an unmount
	// report their lag into the same per-node stats.
	wireLeaseFireLag(lm, unmountStats)

	lm.StartExpiryWorker(func(sandfsID, nodeID, spec, volumePath string) {
		// Success-gated teardown + retry — see the exec-mode wiring above
		// (incl. its TODO(batch-unmount)). SettleUnmount is the exactly-once
		// guard against racing idempotent unmounts double-releasing the bound.
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
		if lm.SettleUnmount(sandfsID) {
			pm.ReleaseBound(nodeID, spec)
		}
	})

	// Single-node is the UNIFIED gateway: it serves both exec-role node
	// connections and prov instances (the storage plane's executors — the
	// local sandlot typically runs merged exec,prov roles).
	startStreamServer(streamSrv, []string{stream.RoleExec, stream.RoleProv}, cfg.Stream.Addr, cfg.Stream.TLSCert, cfg.Stream.TLSKey, cfg.Stream.TLSCA, cfg.StreamConcurrency, logger)
	wireStorageBackend(reg, streamSrv, cfg, logger)

	// Shared resilience state.
	ml := lease.NewMountLock()
	ss := lease.NewSandfsState()

	// Create handlers.
	execHandler := handler.NewExecuteHandler(reg.Store(), pm, lm, sandlotClient, ml, nil, ss, cfg.Exec.DefaultTimeoutSec, cfg.Exec.MaxTimeoutSec, cfg.Exec.MaxBackgroundLeaseSec, logger)
	fileHandler := handler.NewFileHandler(reg.Store(), pm, lm, sandlotClient, ml, nil, ss, logger)
	humanHandler := handler.NewHumanHandler(reg, pm, logger)
	// Inline lifecycle drain: single-node holds the pool + lease in this
	// process, so detach/delete drain directly (no exec-side watch needed).
	humanHandler.SetDrainer(&lease.Drainer{Pool: pm, Lease: lm, Logger: logger})
	// single-node MemoryStore: no etcd → /stats falls back to the local pool
	// manager (SetStatsClient(nil,...) → localStatsReport, same StatsReport
	// shape as the distributed aggregate).
	humanHandler.SetStatsClient(nil, resolveGatewayID(cfg, "single"))
	humanHandler.SetUnmountStats(unmountStats)
	// /health reports the connected provision-instance count in single-node
	// too (same wiring as human mode): with no local storage mode left, 0
	// means every sandfs/template op would 503 — operators and the deploy
	// gates both read it.
	humanHandler.SetProvSeedSource(func() []handler.ProvSeedState {
		return provSeedStates(streamSrv)
	})
	humanHandler.SetEgressBindingSource(func() []handler.EgressBindingState {
		return egressBindingStates(streamSrv)
	})
	humanHandler.SetProvisionerCounter(func() int {
		return len(streamSrv.RoleNodes(stream.RoleProv))
	})
	// ownership is nil in single-node mode — no etcd. shedding is
	// therefore inert here (no peer monitor, no ownership to release); a nil
	// peer ShedController is attached so the handler field is never nil.
	singleShedCfg := &lease.ShedConfig{}
	singleShedCtl := lease.NewShedController(singleShedCfg, pm, nil, nil, logger)
	execHandler.SetShedController(singleShedCtl)
	fileHandler.SetShedController(singleShedCtl)
	execHandler.SetUnmountRecorder(unmountStats)
	fileHandler.SetUnmountRecorder(unmountStats)
	agentHandler := handler.NewAgentHandler(reg.Store(), logger)
	singleNodeID := resolveGatewayID(cfg, "single")
	mcpServer := mcp.NewMCPServer(reg.Store(), execHandler, fileHandler, agentHandler, lm, pm, sandlotClient, singleNodeID,
		mcp.ResolveInstructions(cfg.MCP.InstructionsFile, logger), logger)
	if cfg.MCP.InstructionsFile != "" {
		mcpInstrCtx, mcpInstrCancel := context.WithCancel(context.Background())
		defer mcpInstrCancel()
		go mcpServer.StartInstructionsFileWatcher(mcpInstrCtx, cfg.MCP.InstructionsFile, logger)
	}

	// Agent HTTP mux (:/agent/*, /mcp, /health)
	// Service-refusal switch: the rotation window (and any future operation
	// that must not overlap agent work) flips this at runtime — no restart, so
	// the node streams, the pool and the lease table all survive the window.
	// This process serves the agent listener itself, so no fleet fan-out.
	// Rotation window freeze (SandFS creation): single-node has no etcd, so
	// the LOCAL switch is the whole story — the human and agent listeners are
	// the same process.
	rotSwitch := &maintenance.Switch{}
	humanHandler.SetRotation(rotSwitch)
	maintSwitch := &maintenance.Switch{}
	humanHandler.SetMaintenance(maintSwitch)

	agentMux := http.NewServeMux()
	agentMux.Handle("/agent/execute", execHandler)
	agentMux.HandleFunc("/agent/exec/status", execHandler.HandleExecStatus)
	agentMux.HandleFunc("/agent/exec/kill", execHandler.HandleExecKill)
	agentMux.Handle("/agent/file", fileHandler)
	agentMux.HandleFunc("/agent/sandfs", agentHandler.ListSandFS)
	agentMux.HandleFunc("/mcp", mcpServer.HandleHTTPRequest)
	// NOTE: /human/* and /stats are NOT registered on the agent listener.
	// They are served on the human listener with authn middleware.
	// Registering them here would bypass authentication (CRITICAL security fix).
	agentMux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})
	// Single-node mode has no etcd/ownership to recover — always ready.
	agentMux.HandleFunc("/ready", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ready"}`))
	})

	// Human HTTP mux (:/human/*, /health, /stats)
	// Initialize OIDC authentication for human endpoints.
	oidcProvider, authnMiddleware := initAuthn(cfg, logger)
	if oidcProvider != nil {
		defer oidcProvider.Close()
	}

	humanMux := http.NewServeMux()
	// /human/* scope split — ONE implementation shared with human mode
	// (registerHumanRoutes; see its comment for the blast-radius table).
	registerHumanRoutes(humanMux, cfg, humanHandler, authnMiddleware)
	// /health — unauthenticated
	humanMux.Handle("/health", humanHandler)
	// /ready — unauthenticated, always ready in single-node mode (no etcd recovery).
	// Required so `sandctl health-all` (which probes gateway + human /ready) does
	// not 404 on the human listener.
	humanMux.HandleFunc("/ready", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ready"}`))
	})
	// /stats — ops: OIDC + RequireScope(ops)
	humanMux.Handle("/stats", authnMiddleware(
		authn.RequireScope(resolveScopeOps(cfg))(humanHandler),
	))
	// /metrics — Prometheus projection of the same report /stats serves.
	// Like /stats it lives on the HUMAN listener only (never the agent
	// listener — that would bypass authentication).
	humanMux.Handle("/metrics", authnMiddleware(
		authn.RequireScope(resolveScopeOps(cfg))(http.HandlerFunc(humanHandler.Metrics)),
	))

	// Start agent HTTP listener.
	agentServer := &http.Server{
		Addr: cfg.Agent.Addr,
		// withRecovery mirrors exec mode's agent listener: a handler panic is
		// logged and returned as a clean 500 (keep-alive preserved) instead of
		// a dropped connection / connection-reset. Single-node needs no
		// gateUntilReady — MemoryStore has no warm-up and /ready is always 200.
		Handler:      withRecovery(logger, maintSwitch.Middleware(agentMux)),
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
		agentServer.TLSConfig = tlsCfg
	}
	go func() {
		// A bind failure is FATAL (same rule as exec/human mode): logging and
		// returning left the process alive with NO agent API while the human
		// listener's /health still answered 200 "ok" — a supervisor never
		// restarted it and every agent request got ECONNREFUSED.
		var err error
		if agentServer.TLSConfig != nil {
			logger.Info("agent HTTP TLS enabled", "addr", cfg.Agent.Addr, "mtls", cfg.Agent.TLSCA != "")
			err = agentServer.ListenAndServeTLS("", "")
		} else {
			logger.Info("agent HTTP listening", "addr", cfg.Agent.Addr)
			err = agentServer.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			logger.Error("agent server error — exiting", "error", err)
			os.Exit(1)
		}
	}()

	// Start human HTTP listener.
	humanServer := &http.Server{
		Addr: cfg.Human.Addr,
		// withRecovery mirrors the human-mode listener: a handler panic is
		// logged and returned as a clean JSON 500 (keep-alive preserved)
		// instead of tearing the connection down.
		Handler:     withRecovery(logger, guardHumanPath(humanMux)),
		ReadTimeout: 30 * time.Second,
		// See human.go: the lifecycle/template handlers budget minutes (10 min
		// attach, 5 min delete-template, caller-supplied wait_sec), and Go arms
		// the write deadline at header-read time — 30 s made a long-but-legal
		// request undeliverable.
		WriteTimeout: 11 * time.Minute,
		IdleTimeout:  cfg.IdleTimeout(),
	}
	if cfg.Human.TLSCert != "" {
		tlsCfg, err := buildHTTPServerTLS(cfg.Human.TLSCert, cfg.Human.TLSKey, cfg.Human.TLSCA)
		if err != nil {
			logger.Error("invalid human listener TLS config", "error", err)
			os.Exit(1)
		}
		humanServer.TLSConfig = tlsCfg
	} else if cfg.Authn.Issuer != "" {
		logger.Warn("human API authentication enabled WITHOUT TLS — Bearer tokens travel in cleartext; set -human-tls-cert for production")
	}
	go func() {
		// Fatal for the same reason as the agent listener above: a human
		// gateway that silently loses its human API is worse than one that
		// exits and is restarted.
		var err error
		if humanServer.TLSConfig != nil {
			logger.Info("human HTTP listening", "addr", cfg.Human.Addr, "tls", true, "mtls", cfg.Human.TLSCA != "")
			err = humanServer.ListenAndServeTLS("", "")
		} else {
			logger.Info("human HTTP listening", "addr", cfg.Human.Addr)
			err = humanServer.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			logger.Error("human server error — exiting", "error", err)
			os.Exit(1)
		}
	}()

	// Start hot-reload watcher if config file is set.
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
			singleShedCfg.Update(enabled, satSec, ratePerSec, cooldownSec, retryAfterSec)
		},
		UpdateUnmountStatsInterval: func(sec int) {
			unmountStats.UpdateInterval(time.Duration(sec) * time.Second)
			logger.Info("unmount-stats persist interval hot-reloaded", "sec", sec)
		},
	}, logger)

	// Wait for shutdown signal.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	sig := <-sigCh
	logger.Info("shutting down gracefully", "signal", sig)

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	agentServer.Shutdown(shutdownCtx)
	humanServer.Shutdown(shutdownCtx)
	lm.Close()
	logger.Info("gateway stopped")
}

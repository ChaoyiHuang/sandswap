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
	"os"
	"strings"
	"time"

	"net/http"

	"log/slog"

	"gateway/authn"
	gwconfig "gateway/config"
	"gateway/handler"
	"gateway/identity"
	"gateway/lease"
	"gateway/maintenance"
	"gateway/registry"
	"gateway/stream"
)

// registerHumanRoutes wires the /human/* subtree onto mux, split by blast
// radius (ServeMux longest-pattern wins; the exact-path switches are
// therefore registered alongside the other explicit patterns, ahead of the
// catch-all). Both management modes (RunHumanMode, RunSingleNode) share it so
// the scope split cannot drift between them:
//
//	/human/agent*     — agent credential minting: admin OR ops scope (the
//	                    privileged operator classes; a tenant human token
//	                    still cannot mint credentials).
//	/human/ownership/* — fleet reclamation (incident response): ops scope,
//	                    alongside /stats + /metrics — the on-call audience
//	                    reads the fleet AND unsticks ownership with one scope.
//	/human/maintenance, /human/rotation — FLEET-WIDE switches: ops scope.
//	                    A tenant OIDC token carries exactly sandswap:human
//	                    (the tenant role in the shipped realm), so leaving
//	                    these under the catch-all let ANY tenant 503 all
//	                    agent traffic fleet-wide or close a live seed-rotation
//	                    window mid-flight. mTLS operator certs keep full
//	                    scope, so the rotation tooling is unaffected.
//	/human/templates* — TEMPLATE CREATION IS AN OPS/ADMIN CAPABILITY. The
//	                    store is cluster-level (refs/ + layers/ shared by
//	                    every namespace). GET /human/templates (list only)
//	                    stays human scope: a namespace user may enumerate
//	                    the ops-provided templates and create sandfs/agents
//	                    from them. pull/push/delete and save-as-template
//	                    (gated in the handler, since it is a per-sandfs
//	                    route) require ops/admin: ordinary namespace users
//	                    do not create templates.
//	everything else (sandfs CRUD) — user-resource CRUD: human scope.
func registerHumanRoutes(mux *http.ServeMux, cfg *gwconfig.GatewayConfig, humanHandler http.Handler, authnMiddleware func(http.Handler) http.Handler) {
	agentScoped := authnMiddleware(
		authn.RequireAnyScope(resolveScopeAdmin(cfg), resolveScopeOps(cfg))(humanHandler))
	opsScoped := authnMiddleware(
		authn.RequireScope(resolveScopeOps(cfg))(humanHandler))
	humanScoped := authnMiddleware(
		authn.RequireAnyScope(resolveScopeHuman(cfg), resolveScopeOps(cfg), resolveScopeAdmin(cfg))(humanHandler))
	mux.Handle("/human/agent", agentScoped)
	mux.Handle("/human/agent/", agentScoped)
	mux.Handle("/human/ownership/", opsScoped)
	mux.Handle("/human/maintenance", opsScoped)
	mux.Handle("/human/rotation", opsScoped)
	// List = human (namespaces enumerate ops-provided templates); everything
	// else on the template surface = ops. The exact-path GET is the only
	// read-only operation.
	templatesScoped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/human/templates" {
			humanScoped.ServeHTTP(w, r)
			return
		}
		opsScoped.ServeHTTP(w, r)
	})
	mux.Handle("/human/templates", templatesScoped)
	mux.Handle("/human/templates/", templatesScoped)
	mux.Handle("/human/", humanScoped)
}

// guardHumanPath refuses any percent-encoded human path before ServeMux sees
// it. Human API identifiers (sandfs ids, template refs, namespaces) are ASCII
// tokens and never need escaping; an encoded path makes ServeMux match on the
// escaped form while the handler dispatches on the decoded form. The encoded-path class:
// `%2F` can fall from an ops-only route to the human catch-all and then execute
// the ops handler. Refusing RawPath closes the class for every separator
// spelling instead of enumerating them.
func guardHumanPath(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawPath != "" {
			http.NotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RunHumanMode starts the gateway in human mode: serves /human/* endpoints
// with EtcdStore (read-write). Used in multi-node deployments.
func RunHumanMode(logger *slog.Logger, cfg *gwconfig.GatewayConfig) {
	if cfg.Etcd == "" {
		logger.Error("--etcd is required for --mode human")
		os.Exit(1)
	}
	// Identity lives in etcd here; the single-node store flag does nothing —
	// warn on BOTH a passed flag and a YAML identity_store value, so neither
	// is dropped silently.
	if cfg.IdentityStoreExplicit || cfg.IdentityStore != "" {
		logger.Warn("-identity-store is ignored in human mode (etcd holds identity; single-node only)")
	}

	logger.Info("starting gateway (human mode)",
		"addr", cfg.Human.Addr,
		"etcd", cfg.Etcd,
		"volRoot", cfg.VolRoot,
	)

	// Create EtcdStore.
	endpoints := strings.Split(cfg.Etcd, ",")
	etcdStore, err := identity.NewEtcdStore(endpoints, "/sandswap/identity/", cfg.VolRoot, nil, logger, identityLoadOptions(cfg)...)
	if err != nil {
		logger.Error("failed to create etcd store", "error", err)
		os.Exit(1)
	}
	defer etcdStore.Close()

	// Create registry with EtcdStore.
	reg := registry.NewWithStore(etcdStore, cfg.VolRoot)

	// Storage plane: a stream listener for prov-role instances — the human
	// gateway's storage executors connect HERE (outbound from the instances,
	// same posture as exec nodes), and every sandfs/template op routes to
	// them. The gateway host mounts NO shared storage; ops are a named 503
	// until the first provision instance connects. Prov connections need no
	// pool/lease/ownership callbacks (zero etcd footprint by design) — the
	// server's role routing + the provision client's RoleNodes(prov) are the
	// whole story. The listener is internal-only: bind it to the internal
	// interface / guard it with NetworkPolicy like the exec gateway's :9998.
	streamSrv := stream.NewServer(resolveGatewayID(cfg, "human"), nil, cfg.StreamConcurrency.SendBufferSize, time.Duration(cfg.StreamConcurrency.WriteTimeoutSec)*time.Second)
	startStreamServer(streamSrv, []string{stream.RoleProv}, cfg.Stream.Addr, cfg.Stream.TLSCert, cfg.Stream.TLSKey, cfg.Stream.TLSCA, cfg.StreamConcurrency, logger)
	wireStorageBackend(reg, streamSrv, cfg, logger)

	// Human mode only needs the human handler — no pool, no lease.
	humanHandler := handler.NewHumanHandler(reg, nil, logger)
	// /health reports the connected provision-instance count: 0 means every
	// storage op 503s. The k8s deploy gate and operators both read it.
	humanHandler.SetProvisionerCounter(func() int {
		return len(streamSrv.RoleNodes(stream.RoleProv))
	})
	// Every prov instance dials THIS gateway, so its stream server holds the
	// whole prov fleet's naming generations — the reading a rotation uses to
	// prove convergence before closing the window.
	humanHandler.SetProvSeedSource(func() []handler.ProvSeedState {
		return provSeedStates(streamSrv)
	})
	humanHandler.SetEgressBindingSource(func() []handler.EgressBindingState {
		return egressBindingStates(streamSrv)
	})
	// Human mode has no pool manager but DOES have etcd — /stats aggregates the
	// cluster view from /sandswap/{load,health,gateway}/ (the same keys the DNS
	// reads), producing a multi-gateway report rather than {}.
	humanGWID := resolveGatewayID(cfg, "human")
	humanHandler.SetStatsClient(etcdStore.Client(), humanGWID)
	// the runtime service-refusal switch must work in the SPLIT
	// topology too — the human gateway is where ops reaches it, and the
	// etcd publish (maintenance.Key, FIRST) is what the exec gateways
	// watch. Previously only single-node/exec builds wired it, so
	// /human/maintenance answered 501 in the shipped one-machine shape.
	maintSwitch := &maintenance.Switch{}
	humanHandler.SetMaintenance(maintSwitch)
	// The rotation window freeze (SandFS creation) is a separate switch: it
	// must survive a gateway restart mid-window, so it mirrors the fleet key.
	rotSwitch := &maintenance.Switch{}
	humanHandler.SetRotation(rotSwitch)
	if cli := etcdStore.Client(); cli != nil {
		rotCtx, rotCancel := context.WithCancel(context.Background())
		defer rotCancel()
		go maintenance.WatchKeyFor(rotCtx, cli, logger, rotSwitch, maintenance.RotationKey, "rotation")
	}

	// Create ownership cache for release API (cross-gateway rebalance). The
	// human gateway is ownership-free (it never claims or takes over) — the
	// cache exists solely for the explicit release during delete teardown and
	// the ops reclamation endpoints.
	ownership, err := lease.NewOwnershipCache(etcdStore.Client(), humanGWID, nil, logger)
	if err != nil {
		logger.Warn("failed to create ownership cache for human mode (ownership release API disabled)", "error", err)
	} else {
		humanHandler.SetOwnership(ownership)
		humanHandler.SetStuckReaper(ownership)
		// Joint application: the guard/TTL ceiling invariant is validated
		// against the INCOMING pair (sequential setters would reject a
		// config-valid pair by checking each leg against the other's default).
		if err := ownership.SetStalenessAndCacheTTL(
			time.Duration(cfg.Staleness.RouteStaleSec)*time.Second,
			time.Duration(cfg.Staleness.ClaimDeadGuardSec)*time.Second,
			time.Duration(cfg.Staleness.AlertStaleSec)*time.Second,
			time.Duration(cfg.Ownership.CacheTTLSec)*time.Second,
		); err != nil {
			logger.Error("startup staleness/cache-TTL pair rejected", "error", err)
			os.Exit(1)
		}
		if err := ownership.SetAlertScanInterval(time.Duration(cfg.Staleness.AlertScanIntervalSec) * time.Second); err != nil {
			logger.Error("startup alert scan interval rejected", "error", err)
			os.Exit(1)
		}
		ownership.StartHealthLoop()
		// The owner-release sweep is deliberately NOT started here: it is
		// exec-gateway machinery whose inputs (pendingOwnerRelease) are armed
		// only by the exec-role stream wiring.

		// Staleness alert scan (control-plane only): a periodic full scan
		// that warns about peer gateways whose health has gone stale while
		// sandfs are still owned by them (stranded ownership). Exec gateways
		// detect peer death per-request via Claim's ownerDead instead.
		ownership.StartStalenessAlertScan()
		defer ownership.Close()
	}

	// Hot-reload: staleness thresholds drive the alert scan and the reap-stuck
	// tool's owner-dead gate on this gateway, so they follow config-file edits
	// live.
	startConfigReload(cfg.ConfigFilePath, cfg, &gwconfig.HotReloadTargets{
		UpdateStalenessThresholds: func(routeSec, guardSec, alertSec int) {
			if ownership == nil {
				return
			}
			if err := ownership.SetStalenessThresholds(
				time.Duration(routeSec)*time.Second,
				time.Duration(guardSec)*time.Second,
				time.Duration(alertSec)*time.Second,
			); err != nil {
				logger.Error("staleness thresholds hot-reload refused; keeping previous values", "error", err)
			} else {
				logger.Info("staleness thresholds hot-reloaded",
					"routeSec", routeSec, "guardSec", guardSec, "alertSec", alertSec)
			}
		},
		UpdateOwnershipCacheTTL: func(sec int) {
			if ownership == nil {
				return
			}
			if err := ownership.SetCacheTTL(time.Duration(sec) * time.Second); err != nil {
				logger.Error("ownership cache TTL hot-reload refused; keeping previous value", "error", err)
			} else {
				logger.Info("ownership cache TTL hot-reloaded", "sec", sec)
			}
		},
		UpdateStalenessAndCacheTTL: func(routeSec, guardSec, alertSec, ttlSec int) {
			if ownership == nil {
				return
			}
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
			if ownership == nil {
				return
			}
			if err := ownership.SetAlertScanInterval(time.Duration(sec) * time.Second); err != nil {
				logger.Error("alert scan interval hot-reload refused; keeping previous value", "error", err)
			} else {
				logger.Info("alert scan interval hot-reloaded", "sec", sec)
			}
		},
	}, logger)

	// Initialize OIDC authentication for human endpoints.
	oidcProvider, authnMiddleware := initAuthn(cfg, logger)
	if oidcProvider != nil {
		defer oidcProvider.Close()
	}

	mux := http.NewServeMux()
	registerHumanRoutes(mux, cfg, humanHandler, authnMiddleware)
	// /health — unauthenticated (load balancer / container orchestration)
	mux.Handle("/health", humanHandler)
	// /ready — unauthenticated. Ready once BOTH the etcd identity snapshot is
	// loaded and (belt-and-suspenders) the ownership cache has recovered.
	mux.HandleFunc("/ready", func(w http.ResponseWriter, r *http.Request) {
		if etcdStore.Ready() && (ownership == nil || ownership.Ready()) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status":"ready"}`))
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte(`{"status":"not_ready"}`))
		}
	})
	// /stats — ops: OIDC + RequireScope(ops)
	mux.Handle("/stats", authnMiddleware(
		authn.RequireScope(resolveScopeOps(cfg))(humanHandler),
	))
	// /metrics — Prometheus text projection of the same report /stats serves
	// (same sources, no client library, nothing recorded on request paths).
	// Same auth placement as /stats; alerting/quota live in the external
	// monitoring stack that scrapes this.
	mux.Handle("/metrics", authnMiddleware(
		authn.RequireScope(resolveScopeOps(cfg))(http.HandlerFunc(humanHandler.Metrics)),
	))

	server := &http.Server{
		Addr:        cfg.Human.Addr,
		Handler:     withRecovery(logger, gateUntilReady(etcdStore, guardHumanPath(mux))),
		ReadTimeout: 30 * time.Second,
		// The human handlers legitimately run for minutes: attach/swap-template
		// budget 10 min ("auto-pull can move GBs"), delete-template 5 min, and
		// the lifecycle drain blocks for the caller's wait_sec (the docs tell
		// operators to raise it past a max-length exec: 180 s). Go arms the
		// write deadline when the request HEADERS are read, so the previous 30 s
		// made a `detach-template wait_sec=120` unable to deliver ANY response —
		// the client saw a reset while the drain kept running.
		WriteTimeout: 11 * time.Minute,
		IdleTimeout:  cfg.IdleTimeout(),
	}
	if cfg.Human.TLSCert != "" {
		tlsCfg, err := buildHTTPServerTLS(cfg.Human.TLSCert, cfg.Human.TLSKey, cfg.Human.TLSCA)
		if err != nil {
			logger.Error("invalid human listener TLS config", "error", err)
			os.Exit(1)
		}
		server.TLSConfig = tlsCfg
		logger.Info("human gateway listening", "addr", cfg.Human.Addr, "tls", true, "mtls", cfg.Human.TLSCA != "")
	} else {
		if cfg.Authn.Issuer != "" {
			logger.Warn("human API authentication enabled WITHOUT TLS — Bearer tokens travel in cleartext; set -human-tls-cert for production")
		}
		logger.Info("human gateway listening", "addr", cfg.Human.Addr)
	}
	serveWithGracefulShutdown(server, logger)
}

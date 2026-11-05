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
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"gateway/authn"
	gwconfig "gateway/config"
	"gateway/identity"
)

// resolveGatewayID returns this gateway's fixed identity.
//
// When -gateway-id is set, it is used verbatim (k8s: inject the pod name —
// StatefulSet pod names are stable across restarts, making ownership/registry
// keys survive failover). Otherwise derive a STABLE id from the hostname with
// the mode prefix, dropping os.Getpid() so a restart on the same host (or the
// same k8s pod) keeps the same identity. os.Hostname() in a k8s pod is the pod
// name, so the derived id is already per-pod stable without the flag.
//
// A stable id means a restarted gateway directly reclaims its ownership in
// etcd (owned-by-us fast path) instead of racing a takeover, and the address
// registry / DNS / sandlot last-gateway memory keep working across restarts.
func resolveGatewayID(cfg *gwconfig.GatewayConfig, mode string) string {
	if cfg.GatewayID != "" {
		return cfg.GatewayID
	}
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "unknown"
	}
	return fmt.Sprintf("%s-%s", mode, hostname)
}

// identityLoadOptions translates identity_load config into EtcdStore options.
func identityLoadOptions(cfg *gwconfig.GatewayConfig) []identity.EtcdOption {
	opts := []identity.EtcdOption{
		identity.WithTLS(&identity.EtcdTLSConfig{CAFile: cfg.EtcdCA, CertFile: cfg.EtcdCert, KeyFile: cfg.EtcdKey}),
		identity.WithLazyLoad(cfg.IdentityLoad.LazyLoad),
		identity.WithHotOnly(cfg.IdentityLoad.HotOnly),
	}
	if cfg.IdentityLoad.LoadPageSize > 0 {
		opts = append(opts, identity.WithLoadPageSize(cfg.IdentityLoad.LoadPageSize))
	}
	if cfg.IdentityLoad.LoadWorkers > 0 {
		opts = append(opts, identity.WithLoadWorkers(cfg.IdentityLoad.LoadWorkers))
	}
	if cfg.IdentityLoad.FullLoadTimeoutSec > 0 {
		opts = append(opts, identity.WithFullLoadTimeout(time.Duration(cfg.IdentityLoad.FullLoadTimeoutSec)*time.Second))
	}
	return opts
}

// humanAuthnRefusal returns a named error when the configuration would start
// a human listener with NO authentication and NO explicit opt-out():
// without an issuer every human route — agent-key minting, sandfs CRUD,
// template ops, the fleet-wide switches — would be anonymous, and the
// namespaced tenancy surface void. Silence must not be the way a control
// plane goes unauthenticated: the operator either configures authn.issuer or
// makes the choice explicitly with -allow-anonymous-human (which still logs
// loudly at startup). Extracted from initAuthn so the decision is testable
// without os.Exit.
func humanAuthnRefusal(cfg *gwconfig.GatewayConfig) error {
	if cfg.Authn.Issuer != "" {
		return nil
	}
	if !cfg.Authn.AllowAnonymous {
		return errors.New("refusing to start the human listener without OIDC authentication: configure authn.issuer (-authn-issuer), or acknowledge the risk explicitly with -allow-anonymous-human (the entire human control plane will be ANONYMOUS)")
	}
	// An anonymous control plane mints agent keys and flips fleet-wide
	// switches. Loopback is the default exposure boundary; reaching it from
	// another host must be an operator's deliberate choice, not the default
	// 0.0.0.0 bind inherited from the listen-address flag.
	if !cfg.Authn.AllowAnonymousPublic && !loopbackListenAddr(cfg.Human.Addr) {
		return fmt.Errorf("refusing to expose the ANONYMOUS human control plane on %q: bind a loopback address (127.0.0.1:%s, reach it through an SSH tunnel or a NetworkPolicy), or acknowledge public exposure with -allow-anonymous-human-public", cfg.Human.Addr, portOf(cfg.Human.Addr))
	}
	return nil
}

// loopbackListenAddr reports whether a listen address is loopback-only. An
// empty host (":3100", "0.0.0.0", "::") is NOT loopback.
func loopbackListenAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func portOf(addr string) string {
	if _, port, err := net.SplitHostPort(addr); err == nil {
		return port
	}
	return "3100"
}

// initAuthn initializes the OIDC provider and authentication middleware
// for human endpoints. Returns (nil, passthrough-middleware) if no issuer
// is configured (backward-compatible: no auth).
func initAuthn(cfg *gwconfig.GatewayConfig, logger *slog.Logger) (*authn.OIDCProvider, func(http.Handler) http.Handler) {
	if cfg.Authn.Issuer == "" {
		if err := humanAuthnRefusal(cfg); err != nil {
			logger.Error("startup refused", "error", err)
			os.Exit(1)
		}
		logger.Warn("HUMAN LISTENER STARTING WITHOUT AUTHENTICATION (-allow-anonymous-human): every human endpoint — agent-key minting, sandfs CRUD, template ops, the fleet switches — is ANONYMOUS; anyone who can reach this listener has full control. Scope it by network policy (ACL/NetworkPolicy) or configure authn.issuer")
		return nil, authn.OIDCMiddleware(nil)
	}

	refreshInterval := time.Duration(cfg.Authn.JWKSRefreshSec) * time.Second
	if refreshInterval <= 0 {
		refreshInterval = 1 * time.Hour
	}

	oidcProvider, err := authn.NewOIDCProvider(context.Background(), authn.OIDCConfig{
		Issuer:   cfg.Authn.Issuer,
		ClientID: cfg.Authn.ClientID,
	}, refreshInterval, logger)
	if err != nil {
		logger.Error("failed to initialize OIDC provider", "issuer", cfg.Authn.Issuer, "error", err)
		os.Exit(1)
	}

	var middleware func(http.Handler) http.Handler
	if cfg.Authn.MTLSTrustCert {
		middleware = authn.MTLSOrOIDCMiddleware(oidcProvider)
	} else {
		middleware = authn.OIDCMiddleware(oidcProvider)
	}

	logger.Info("human API authentication enabled",
		"issuer", cfg.Authn.Issuer,
		"scopeHuman", resolveScopeHuman(cfg),
		"scopeOps", resolveScopeOps(cfg),
		"mtls", cfg.Authn.MTLSTrustCert)

	return oidcProvider, middleware
}

// resolveScopeHuman returns the human scope from config, defaulting to authn.ScopeHuman.
func resolveScopeHuman(cfg *gwconfig.GatewayConfig) string {
	if cfg.Authn.ScopeHuman != "" {
		return cfg.Authn.ScopeHuman
	}
	return authn.ScopeHuman
}

// resolveScopeAdmin returns the admin scope from config, defaulting to authn.ScopeAdmin.
func resolveScopeAdmin(cfg *gwconfig.GatewayConfig) string {
	if cfg.Authn.ScopeAdmin != "" {
		return cfg.Authn.ScopeAdmin
	}
	return authn.ScopeAdmin
}

// resolveScopeOps returns the ops scope from config, defaulting to authn.ScopeOps.
func resolveScopeOps(cfg *gwconfig.GatewayConfig) string {
	if cfg.Authn.ScopeOps != "" {
		return cfg.Authn.ScopeOps
	}
	return authn.ScopeOps
}

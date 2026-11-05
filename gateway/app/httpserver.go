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
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"gateway/identity"
)

// gateUntilReady wraps the request mux so that while the etcd identity snapshot
// is still loading, every request except liveness/readiness probes gets a
// fast 503 with Retry-After — never a spurious not-found from an empty cache.
// Once Ready() flips true (snapshot load complete) it passes through untouched.
func gateUntilReady(store *identity.EtcdStore, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !store.Ready() && r.URL.Path != "/health" && r.URL.Path != "/ready" {
			w.Header().Set("Retry-After", "2")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte(`{"error":"identity cache warming up","retry_after_sec":2}`))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// withRecovery wraps an http.Handler with a panic recovery middleware. A panic
// in a handler (e.g. a nil deref deserializing a malformed request) is logged
// and returned as a 500 instead of crashing the goroutine and dropping the
// HTTP connection — the latter would break keep-alive affinity and surface to
// the client as a confusing connection-reset rather than a clean 503+retry.
func withRecovery(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				logger.Error("HTTP handler panic recovered",
					"path", r.URL.Path, "method", r.Method, "panic", rec)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]string{"error": "internal error"})
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// buildHTTPServerTLS builds the TLS config for an HTTP listener (human or agent).
// Uses TLS 1.2+ (broader client compatibility than gRPC stream's 1.3-only).
// If caFile is set, client certificates are required and verified (mTLS);
// otherwise the server authenticates itself but does not require a client cert.
func buildHTTPServerTLS(certFile, keyFile, caFile string) (*tls.Config, error) {
	if certFile == "" || keyFile == "" {
		return nil, fmt.Errorf("TLS cert and key must both be set")
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load server keypair: %w", err)
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read CA bundle: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no valid certs in CA bundle %s", caFile)
		}
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return cfg, nil
}

// serveWithGracefulShutdown starts an HTTP server with SIGTERM/SIGINT graceful
// shutdown. On signal: stops accepting new connections, waits up to 30s for
// in-flight requests to complete, then exits.
// If server.TLSConfig is set, uses ListenAndServeTLS; otherwise plain HTTP.
func serveWithGracefulShutdown(server *http.Server, logger *slog.Logger) {
	go func() {
		var err error
		if server.TLSConfig != nil {
			err = server.ListenAndServeTLS("", "")
		} else {
			err = server.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			logger.Error("server error", "error", err)
			os.Exit(1)
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	sig := <-sigCh
	logger.Info("shutting down gracefully", "signal", sig)

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error("graceful shutdown failed", "error", err)
		os.Exit(1)
	}
	logger.Info("server stopped")
}

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
	"bytes"
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"common/config"

	"gopkg.in/yaml.v3"
)

// Version information — set via ldflags at build time (build/build.sh
// stamps every shipped binary uniformly; dev builds show the defaults).
var (
	Version   = "0.0.0-dev"
	Commit    = "unknown"
	BuildTime = "unknown"
)

func main() {
	configPath := flag.String("config", "", "Path to YAML config file")
	showVer := flag.Bool("version", false, "Print version and exit")
	flag.Parse()
	if *showVer {
		fmt.Printf("dns %s (commit %s, built %s)\n", Version, Commit, BuildTime)
		return
	}

	if *configPath == "" {
		log.Fatal("-config flag is required")
	}

	cfg, err := LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	log.Printf("sandswap-dns starting on %s", cfg.ListenAddr)
	if len(cfg.GuestCIDRs) == 0 {
		log.Printf("WARNING: guest_cidrs is empty — foreign-zone queries are relayed for EVERY source, including sandbox guests (an open recursive resolver on the host). Set guest_cidrs to the sandbox subnet in production.")
	}
	log.Printf("  Stream domain: %s", cfg.Domains.Stream)
	if cfg.Domains.Sandfs != "" {
		log.Printf("  Sandfs zone:   *.%s (owner-aware)", cfg.Domains.Sandfs)
	}
	log.Printf("  Gateways:      self-registered via etcd (/sandswap/gateway/)")
	log.Printf("  Etcd:          %s", cfg.Etcd)
	log.Printf("  TTL:           %ds", cfg.TTL)
	log.Printf("  Sched policy:  %s, duty_hard=%.2f (hot-reloadable via %s)",
		cfg.Scheduling.Policy, cfg.Scheduling.DutyHard, *configPath)
	log.Printf("  Route stale:   %ds (hot-reloadable via %s)", cfg.Staleness.RouteStaleSec, *configPath)
	log.Printf("  Owners cache:  %d entries, ttl=%ds, neg-ttl=%ds, get-conc=%d, etcd-timeout=%dms, rate src=%d/s global=%d/s (restart-required)",
		cfg.Owners.CacheMax, cfg.Owners.CacheTTLSec, cfg.Owners.NegCacheTTLSec,
		cfg.Owners.GetConcurrency, cfg.Owners.EtcdTimeoutMs,
		cfg.Owners.RateLimitPerSource, cfg.Owners.RateLimitGlobal)

	// Sizing knobs -> operational package values. BEFORE NewDNSServer: the
	// owner/forward semaphores are constructed from them at server creation.
	cfg.ApplyOperationalKnobs()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create DNS server
	server, err := NewDNSServer(cfg)
	if err != nil {
		log.Fatalf("Failed to create DNS server: %v", err)
	}
	// Apply the configured owner-branch staleness threshold (defaults to
	// RouteStaleSecDefault; see StalenessConfig). The DNS is a separate process
	// from the gateway, so the gateway's -route-stale-sec does not reach here.
	server.SetRouteStaleThreshold(time.Duration(cfg.Staleness.RouteStaleSec) * time.Second)

	// Start background goroutines (poller, sticky sync, expiry)
	server.Start(ctx)

	// Hot-reload scheduling + staleness from the config file without a restart,
	// mirroring sandlot's config reload (common/config ReloadWatcher).
	watcher, err := config.NewReloadWatcher(*configPath, func(content []byte) {
		applyReloadConfig(server, content)
	})
	if err != nil {
		log.Printf("Warning: failed to watch config %s: %v (policy hot-reload disabled)", *configPath, err)
	} else {
		defer watcher.Stop()
	}

	// Start DNS listener (UDP + TCP) in a goroutine; bind errors surface
	// via the channel instead of being silently swallowed.
	listenErr := make(chan error, 1)
	go func() {
		if err := server.ListenAndServe(); err != nil {
			listenErr <- err
		}
	}()

	// Wait for shutdown signal or listener error
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	for {
		select {
		case sig := <-sigCh:
			if sig == syscall.SIGHUP {
				log.Println("Received SIGHUP: clearing all sticky records")
				server.ClearAllSticky()
				continue
			}
			fmt.Fprintf(os.Stderr, "\nReceived %s, shutting down...\n", sig)
			cancel()
			server.Close()
			return
		case err := <-listenErr:
			log.Fatalf("DNS listener error: %v", err)
		}
	}
}

// applyReloadConfig parses one hot-reload config snapshot and applies the
// hot-reloadable subset (scheduling policy/duty cap, route-staleness
// threshold). The decode target is the FULL Config, not a shadow struct:
// strict decoding rejects every key the target does not know, so a shadow
// carrying only the two hot sections rejects every real config file at its
// first unrelated key and no edit ever hot-applies. Unknown keys are still
// refused loudly.
func applyReloadConfig(server *DNSServer, content []byte) {
	var doc Config
	// Defaults (like LoadConfig) so a file that omits a field keeps the
	// built-in value; an explicit 0 disables duty_hard / keeps the default
	// route_stale_sec.
	doc.Scheduling = SchedulingConfig{Policy: PolicyBinpack, DutyHard: DutyHardDefault}
	doc.Staleness = StalenessConfig{RouteStaleSec: RouteStaleSecDefault}
	dec := yaml.NewDecoder(bytes.NewReader(content))
	dec.KnownFields(true)
	if err := dec.Decode(&doc); err != nil {
		log.Printf("config reload: failed to parse YAML (strict: unknown keys are errors): %v", err)
		return
	}
	// The pre-seeded default is OVERWRITTEN by an explicit `route_stale_sec:
	// 0`, which the `> 0` guard below then ignores — leaving the previous live
	// value in place. The documented meaning of 0 is "keep the default", so
	// restore the default here.
	if doc.Staleness.RouteStaleSec == 0 {
		doc.Staleness.RouteStaleSec = RouteStaleSecDefault
	}
	sc := doc.Scheduling.Normalized()
	if sc.DutyHard < 0 || sc.DutyHard > 1 {
		log.Printf("config reload: ignoring invalid scheduling.duty_hard %v", sc.DutyHard)
	} else if !server.SetScheduling(sc.Policy, sc.DutyHard) {
		log.Printf("config reload: ignoring invalid scheduling config")
	}
	if doc.Staleness.RouteStaleSec < 0 {
		log.Printf("config reload: ignoring invalid staleness.route_stale_sec %v", doc.Staleness.RouteStaleSec)
	} else if doc.Staleness.RouteStaleSec > 0 {
		server.SetRouteStaleThreshold(time.Duration(doc.Staleness.RouteStaleSec) * time.Second)
		log.Printf("config reload: route_stale_sec hot-applied: %ds", doc.Staleness.RouteStaleSec)
	}
}

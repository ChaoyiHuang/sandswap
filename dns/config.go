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
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config holds the sandns configuration. There is NO static gateway
// list: every gateway self-registers its routing addresses into
// /sandswap/gateway/{id} (plain key) at startup, and the DNS builds its
// candidate set entirely from etcd (registry = candidacy, health = liveness,
// load = scoring).
type Config struct {
	ListenAddr         string        `yaml:"listen_addr"`
	Domains            DomainsConfig `yaml:"domains"`
	Etcd               string        `yaml:"etcd"`
	EtcdCA             string        `yaml:"etcd_ca"`
	EtcdCert           string        `yaml:"etcd_cert"`
	EtcdKey            string        `yaml:"etcd_key"`
	TTL                int           `yaml:"ttl"`
	StickyExpire       int           `yaml:"sticky_expire"`
	StickySyncInterval int           `yaml:"sticky_sync_interval"`
	StickySyncBatch    int           `yaml:"sticky_sync_batch"`
	Forwarders         []string      `yaml:"forwarders"`
	// GuestCIDRs lists the sandbox guest source ranges. A query from one of
	// these sources is answered ONLY for the sandswap zones: relaying foreign
	// zones for a guest would turn the control-plane resolver into an open
	// recursive resolver on the host, using the host's egress identity. The
	// guest's own resolver comes from the sandlot's network DNS. Empty = no
	// restriction (dev); production sets the sandbox subnet (10.188.0.0/16 by
	// default).
	GuestCIDRs []string `yaml:"guest_cidrs"`
	// RecursiveACL lists the NON-guest source ranges allowed to use this
	// resolver as a recursive forwarder. Sources outside it (and every guest
	// CIDR) get REFUSED for foreign zones: without an explicit ACL, a spoofed
	// UDP source could drive amplification through the host's egress identity
	// (open-recursive-resolver shape). Default: loopback only — a host querying
	// its own control-plane resolver. Add management ranges explicitly when
	// other hosts must resolve through it.
	//
	// A loopback ACL entry is matched only when the packet also ARRIVED over a
	// loopback-address socket: the source address alone is not proof of local
	// origin (net.ipv4.route_localnet=1 lets a remote sender present
	// 127.0.0.1 to a wildcard listener). Non-loopback entries match by source
	// address (UDP DNS carries no stronger identity).
	RecursiveACL []string         `yaml:"recursive_acl"`
	Scheduling   SchedulingConfig `yaml:"scheduling"`
	Staleness    StalenessConfig  `yaml:"staleness"`
	// Operational sizing knobs (all restart-required: the serving paths read
	// them as plain values, and the semaphores are constructed once at
	// startup). Defaults are chosen to stay reasonable at large fleets — see
	// each field's doc; deployments with different scale/tradeoffs override.
	Owners               OwnersKnobs `yaml:"owners"`
	StickyMax            int         `yaml:"sticky_max"`
	MaxConcurrentQueries int         `yaml:"max_concurrent_queries"`
	ForwardConcurrency   int         `yaml:"forward_concurrency"`
	TCPMaxConns          int         `yaml:"tcp_max_conns"`
}

// OwnersKnobs sizes the on-demand owner cache (the per-sandfs ownership
// lookups backing the sandfs zone). The steady etcd read rate is roughly
// (actively-queried sandfs) / cache_ttl_sec, and the cache must be able to
// hold the hot working set (cache_max) or hit rate collapses into a read
// storm — memory scales at roughly 250B per cached sandfs.
type OwnersKnobs struct {
	// CacheMax bounds the owner cache entries (per-sandfs state). Default
	// 1,000,000 holds a full million-sandfs fleet in ~300MB; smaller fleets
	// only ever hold what they query. Must be >= 1000.
	CacheMax int `yaml:"cache_max"`
	// CacheTTLSec is how stale a positive owner entry may be before it is
	// revalidated against etcd. Larger values cut the etcd read rate
	// proportionally at the cost of slower ownership-change visibility (up to
	// this TTL plus the client-side answer TTL). Default 30 keeps a
	// million-sandfs fleet's read rate comfortable with serializable reads
	// while staying inside the system's takeover envelope. Must be in
	// [1,3600].
	CacheTTLSec int `yaml:"cache_ttl_sec"`
	// NegCacheTTLSec bounds a negative (no-owner) entry. Short so a real
	// first-claim is picked up promptly. Must be in [1,300].
	NegCacheTTLSec int `yaml:"neg_cache_ttl_sec"`
	// EtcdTimeoutMs bounds one on-demand owner etcd Get. Must be in
	// [100,60000].
	EtcdTimeoutMs int `yaml:"etcd_timeout_ms"`
	// GetConcurrency bounds concurrent owner etcd Gets on the query path;
	// beyond the cap lookups fail fast (SERVFAIL/stale) instead of queueing.
	// 0 = unbounded. Otherwise must be in [1,100000].
	GetConcurrency int `yaml:"get_concurrency"`
	// RateLimitPerSource bounds how many etcd-bound owner resolutions one
	// source IP may start per second (cached answers do not count). It keeps
	// valid-shaped ID enumeration from turning a client's query rate into
	// control-plane read amplification. 0 = unlimited. Default 100.
	RateLimitPerSource int `yaml:"rate_limit_per_source"`
	// RateLimitGlobal bounds the resolver-wide etcd-bound owner-resolution
	// rate per second — the backstop when many sources query at once. 0 =
	// unlimited. Default 50000, above a million-sandfs fleet's steady-state
	// revalidation rate (cache_ttl 30s ≈ 33k/s).
	RateLimitGlobal int `yaml:"rate_limit_global"`
}

// RouteStaleSecDefault is the default health-staleness death threshold for the
// DNS owner branch. The health key has no lease, so staleness is the only
// death signal; judging wrong here is cheap (a napping owner handles the
// request fine once it wakes), so this is the fastest death threshold. A live
// owner refreshes its health key every 5s and is never stale at 20s. Keep it
// aligned with (≥) the gateway's -route-stale-sec.
const RouteStaleSecDefault = 20

// StalenessConfig holds the DNS's own health-staleness threshold. The DNS is a
// separate process from the gateway, so the gateway's -route-stale-sec flag
// does not reach it — it has its own config value (same semantics: staleness
// past which the owner branch stops routing to an owner). Hot-reloadable via
// the config-file watcher, like scheduling.*.
type StalenessConfig struct {
	// RouteStaleSec is the staleness (seconds) past which an owner gateway's
	// health record is judged stale and the owner branch stops routing to it.
	// 0 = default (RouteStaleSecDefault).
	RouteStaleSec int `yaml:"route_stale_sec"`
}

// Scheduling policies for gateway routing. The DNS applies the policy to
// UNSOWNED sandfs (no-owner placement) + stream-domain sandlot placement;
// owned sandfs always route to their owner (affinity, orthogonal to policy).
const (
	PolicySpread  = "spread"  // prefer the least-loaded gateway (lowest agg_duty_long)
	PolicyBinpack = "binpack" // prefer the busiest healthy gateway (highest agg_duty_long)
)

// DutyHardDefault is the default gateway-level agg_duty_long hard cap. A
// gateway above it is excluded from routing in BOTH policies, so binpack never
// piles new sandfs onto an overloaded gateway.
const DutyHardDefault = 0.85

// SchedulingConfig holds the gateway-routing policy + saturation cap.
// Hot-reloadable: the config file is watched, and changes apply live.
type SchedulingConfig struct {
	// Policy is PolicyBinpack (default) or PolicySpread.
	//   binpack — new/unowned sandfs land on the busiest healthy gateway; work
	//             packs onto fewer gateways so lightly-loaded ones go idle.
	//   spread  — new/unowned sandfs land on the most idle gateway; load is
	//             distributed to minimize per-gateway contention.
	Policy string `yaml:"policy"`
	// DutyHard is the gateway-level agg_duty_long hard cap (0..1): a gateway at
	// or above it is excluded from routing for new sandfs in both policies.
	// 0 = disabled. Default 0.85 (DutyHardDefault).
	DutyHard float64 `yaml:"duty_hard"`
}

// Normalized returns a SchedulingConfig with the policy defaulted to binpack
// (any value other than PolicySpread → binpack).
func (sc SchedulingConfig) Normalized() SchedulingConfig {
	if sc.Policy != PolicySpread {
		sc.Policy = PolicyBinpack
	}
	return sc
}

// DomainsConfig holds the DNS domain names served by sandswap-dns.
type DomainsConfig struct {
	Agent  string `yaml:"agent"`  // legacy shared agent domain (e.g. sandswap.local) — single-IP round-robin via scheduling; kept for `sandctl dns agent`
	Stream string `yaml:"stream"` // sandlot stream domain (placement)
	// Sandfs is the per-sandfs zone: names are <sandfs_id>.<sandfs>, e.g.
	// sandfs-3fa9c2e1.sandfs.sandswap.local. The DNS resolves each name to its
	// OWNER gateway (C1/C2 owner-aware DNS): it reads /sandswap/owner/{id} then
	// /sandswap/health/{gw} and returns a CNAME (hostname target) or A record
	// (IP target). Empty = the owner-aware zone is disabled.
	Sandfs string `yaml:"sandfs"`
}

// LoadConfig reads and validates the YAML config file. Parsing is STRICT:
// unknown keys are errors, not silently ignored fields (a dead "gateways:"
// section from the pre-self-registration era survived undetected this way —
// strict parsing makes stale config fail at startup where it is visible).
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	cfg := &Config{
		ListenAddr:         "0.0.0.0:53",
		TTL:                10,
		StickyExpire:       1800,
		StickySyncInterval: 5,
		StickySyncBatch:    256,
		Scheduling:         SchedulingConfig{Policy: PolicyBinpack, DutyHard: DutyHardDefault},
		Staleness:          StalenessConfig{RouteStaleSec: RouteStaleSecDefault},
		Owners: OwnersKnobs{
			CacheMax:           1000000,
			CacheTTLSec:        30,
			NegCacheTTLSec:     1,
			EtcdTimeoutMs:      2000,
			GetConcurrency:     256,
			RateLimitPerSource: 100,
			RateLimitGlobal:    50000,
		},
		StickyMax:            65536,
		MaxConcurrentQueries: 2048,
		ForwardConcurrency:   128,
		TCPMaxConns:          256,
		RecursiveACL:         []string{"127.0.0.1/32", "::1/128"},
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	// Normalize domains: lowercase (wire.ParseQuery lowercases query names),
	// no trailing dots.
	cfg.Domains.Agent = strings.ToLower(strings.TrimSuffix(cfg.Domains.Agent, "."))
	cfg.Domains.Stream = strings.ToLower(strings.TrimSuffix(cfg.Domains.Stream, "."))
	cfg.Domains.Sandfs = strings.ToLower(strings.TrimSuffix(cfg.Domains.Sandfs, "."))

	// Validate the routing policy (empty → binpack default).
	switch cfg.Scheduling.Policy {
	case "", PolicySpread, PolicyBinpack:
		cfg.Scheduling = cfg.Scheduling.Normalized()
	default:
		return nil, fmt.Errorf("scheduling.policy must be %q or %q (got %q)",
			PolicySpread, PolicyBinpack, cfg.Scheduling.Policy)
	}
	// DutyHard in [0,1]; 0 disables the cap.
	if cfg.Scheduling.DutyHard < 0 || cfg.Scheduling.DutyHard > 1 {
		return nil, fmt.Errorf("scheduling.duty_hard must be in [0,1] (got %v)", cfg.Scheduling.DutyHard)
	}

	// Route staleness threshold: 0 (unset) keeps the default; negative invalid.
	if cfg.Staleness.RouteStaleSec < 0 {
		return nil, fmt.Errorf("staleness.route_stale_sec must be > 0 (got %v)", cfg.Staleness.RouteStaleSec)
	}
	if cfg.Staleness.RouteStaleSec == 0 {
		cfg.Staleness.RouteStaleSec = RouteStaleSecDefault
	}

	// Numeric sanity: these feed tickers/timestamps — 0 or negative values
	// panic (time.NewTicker(0)) or produce nonsense TTLs.
	if cfg.TTL < 1 || cfg.TTL > 86400 {
		return nil, fmt.Errorf("ttl must be in [1,86400] seconds (got %d)", cfg.TTL)
	}
	if cfg.StickyExpire < 1 {
		return nil, fmt.Errorf("sticky_expire must be >= 1 second (got %d)", cfg.StickyExpire)
	}
	if cfg.StickySyncInterval < 1 {
		return nil, fmt.Errorf("sticky_sync_interval must be >= 1 second (got %d — 0 panics the sync ticker)", cfg.StickySyncInterval)
	}
	if cfg.StickySyncBatch < 0 {
		return nil, fmt.Errorf("sticky_sync_batch must be >= 0 (got %d)", cfg.StickySyncBatch)
	}
	// Sizing knobs (restart-required). Ranges guard against nonsense values
	// that would panic tickers/semaphores or silently disable bounds.
	if cfg.Owners.CacheMax < 1000 {
		return nil, fmt.Errorf("owners.cache_max must be >= 1000 (got %d)", cfg.Owners.CacheMax)
	}
	if cfg.Owners.CacheTTLSec < 1 || cfg.Owners.CacheTTLSec > 3600 {
		return nil, fmt.Errorf("owners.cache_ttl_sec must be in [1,3600] seconds (got %d)", cfg.Owners.CacheTTLSec)
	}
	if cfg.Owners.NegCacheTTLSec < 1 || cfg.Owners.NegCacheTTLSec > 300 {
		return nil, fmt.Errorf("owners.neg_cache_ttl_sec must be in [1,300] seconds (got %d)", cfg.Owners.NegCacheTTLSec)
	}
	if cfg.Owners.EtcdTimeoutMs < 100 || cfg.Owners.EtcdTimeoutMs > 60000 {
		return nil, fmt.Errorf("owners.etcd_timeout_ms must be in [100,60000] (got %d)", cfg.Owners.EtcdTimeoutMs)
	}
	if cfg.Owners.GetConcurrency < 0 || cfg.Owners.GetConcurrency > 100000 {
		return nil, fmt.Errorf("owners.get_concurrency must be in [0,100000], 0 = unbounded (got %d)", cfg.Owners.GetConcurrency)
	}
	if cfg.Owners.RateLimitPerSource < 0 || cfg.Owners.RateLimitPerSource > 1000000 {
		return nil, fmt.Errorf("owners.rate_limit_per_source must be in [0,1000000], 0 = unbounded (got %d)", cfg.Owners.RateLimitPerSource)
	}
	if cfg.Owners.RateLimitGlobal < 0 || cfg.Owners.RateLimitGlobal > 10000000 {
		return nil, fmt.Errorf("owners.rate_limit_global must be in [0,10000000], 0 = unbounded (got %d)", cfg.Owners.RateLimitGlobal)
	}
	if cfg.StickyMax < 1 {
		return nil, fmt.Errorf("sticky_max must be >= 1 (got %d)", cfg.StickyMax)
	}
	if cfg.MaxConcurrentQueries < 16 {
		return nil, fmt.Errorf("max_concurrent_queries must be >= 16 (got %d)", cfg.MaxConcurrentQueries)
	}
	if cfg.ForwardConcurrency < 0 {
		return nil, fmt.Errorf("forward_concurrency must be >= 0, 0 = unbounded (got %d)", cfg.ForwardConcurrency)
	}
	if cfg.TCPMaxConns < 1 {
		return nil, fmt.Errorf("tcp_max_conns must be >= 1 (got %d)", cfg.TCPMaxConns)
	}
	for _, cidr := range cfg.GuestCIDRs {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return nil, fmt.Errorf("guest_cidrs entry %q is not a CIDR: %v", cidr, err)
		}
	}
	for _, fwd := range cfg.Forwarders {
		if _, _, err := net.SplitHostPort(fwd); err != nil {
			return nil, fmt.Errorf("forwarders entry %q must be host:port: %w", fwd, err)
		}
	}
	// Refuse a forwarder that points back at this resolver's own listen port:
	// every forwarded query would re-enter this process, and each in-flight
	// forward holds a forwardConcurrency slot (and a relayTimeout) until the
	// loop is cut — a self-amplifying stall.
	if err := refuseSelfForwarders(cfg.ListenAddr, cfg.Forwarders); err != nil {
		return nil, err
	}

	// Validate
	if cfg.ListenAddr == "" {
		return nil, fmt.Errorf("listen_addr is required")
	}
	if cfg.Domains.Stream == "" {
		return nil, fmt.Errorf("domains.stream is required")
	}
	// The three zones must be disjoint. Agent/stream match EXACTLY and the
	// sandfs zone matches by SUFFIX ("<id>.<sandfs>"), so the one ambiguous
	// shape is an agent/stream domain that itself lives inside the sandfs zone
	// (its exact match would also carry the sandfs suffix and the sandfs
	// dispatch, which runs first, would win with a bogus sandfs ID).
	doms := []struct{ key, val string }{
		{"domains.agent", cfg.Domains.Agent},
		{"domains.stream", cfg.Domains.Stream},
		{"domains.sandfs", cfg.Domains.Sandfs},
	}
	for i := 0; i < len(doms); i++ {
		for j := i + 1; j < len(doms); j++ {
			a, b := strings.ToLower(doms[i].val), strings.ToLower(doms[j].val)
			if a == "" || b == "" {
				continue
			}
			if a == b {
				return nil, fmt.Errorf("%s and %s must differ (both %q)", doms[i].key, doms[j].key, a)
			}
			if doms[j].key == "domains.sandfs" && strings.HasSuffix(a, "."+b) {
				return nil, fmt.Errorf("%s %q lives inside the sandfs zone %q — dispatch would be ambiguous", doms[i].key, a, b)
			}
			if doms[i].key == "domains.sandfs" && strings.HasSuffix(b, "."+a) {
				return nil, fmt.Errorf("%s %q lives inside the sandfs zone %q — dispatch would be ambiguous", doms[j].key, b, a)
			}
		}
	}
	// Gateway candidates are NOT configured here — every gateway self-registers
	// into /sandswap/gateway/{id} at startup and the DNS discovers them via
	// etcd. Before any gateway has registered, stream/agent queries SERVFAIL
	// (the client retries); the sandfs zone falls to its no-owner branch.
	if cfg.Etcd == "" {
		return nil, fmt.Errorf("etcd endpoints are required (gateway candidates + sticky + ownership)")
	}

	return cfg, nil
}

// refuseSelfForwarders rejects a forwarders entry that would re-enter this
// resolver: same port, and an address the configured listener actually
// receives on. That is a provable self-reference for a wildcard listener
// (every local address), for an IP-literal listener (that exact address), and
// for "localhost" (the loopback family Go binds). Other names are not resolved
// here — a config load must not depend on a resolver — so they are treated
// like a wildcard (conservative: any local address on the listen port would
// reach this process). A local resolver on the same port but a DIFFERENT
// specific address the listener does not bind stays legal.
func refuseSelfForwarders(listenAddr string, forwarders []string) error {
	listenHost, listenPort, err := net.SplitHostPort(listenAddr)
	if err != nil {
		// A listen address without a parseable port is rejected by the bind
		// itself; there is no port to compare against here.
		return nil
	}
	listenHost = strings.Trim(listenHost, "[]")
	listenIP := net.ParseIP(listenHost)
	listenIsLocalhost := strings.EqualFold(listenHost, "localhost")
	var local []net.IP
	for _, fwd := range forwarders {
		host, port, err := net.SplitHostPort(fwd)
		if err != nil || port != listenPort {
			continue
		}
		host = strings.Trim(host, "[]")
		fwdIP := net.ParseIP(host)
		fwdIsLocalhost := strings.EqualFold(host, "localhost")
		self := false
		switch {
		case listenIP != nil && !listenIP.IsUnspecified():
			// The listener is bound to exactly this address.
			if fwdIP != nil {
				self = fwdIP.Equal(listenIP)
			} else if fwdIsLocalhost {
				self = listenIP.IsLoopback()
			}
		case listenIsLocalhost:
			// Go binds one loopback family; either loopback spelling or the
			// name itself may reach it.
			self = (fwdIP != nil && fwdIP.IsLoopback()) || fwdIsLocalhost
		default:
			// Wildcard (or a name not classifiable here): the listener receives
			// every local address on the port.
			if local == nil {
				local = hostLocalIPs()
			}
			if fwdIP != nil {
				self = fwdIP.IsLoopback() || ipIn(fwdIP, local)
			}
			self = self || fwdIsLocalhost
		}
		if self {
			return fmt.Errorf("forwarders entry %q points back at this resolver's own listen port %s (self-forwarder loop): every forwarded query re-enters this process until a slot times out", fwd, listenPort)
		}
	}
	return nil
}

// ipIn reports whether ip equals one of ips.
func ipIn(ip net.IP, ips []net.IP) bool {
	for _, c := range ips {
		if c.Equal(ip) {
			return true
		}
	}
	return false
}

// hostLocalIPs returns the addresses assigned to this host's interfaces
// (loopback included). Empty on error — the loopback/localhost literals are
// still recognised without it.
func hostLocalIPs() []net.IP {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var ips []net.IP
	for _, a := range addrs {
		switch v := a.(type) {
		case *net.IPNet:
			ips = append(ips, v.IP)
		case *net.IPAddr:
			ips = append(ips, v.IP)
		}
	}
	return ips
}

// ApplyOperationalKnobs copies the validated sizing values into the
// operational package knobs the serving paths read. Call EXACTLY ONCE at
// startup, BEFORE NewDNSServer (the semaphores are constructed from these
// values). Restart-required by design: the knobs are read on query paths as
// plain values, so a live swap would race them.
func (cfg *Config) ApplyOperationalKnobs() {
	ownerLRUMax = cfg.Owners.CacheMax
	ownerCacheTTL = time.Duration(cfg.Owners.CacheTTLSec) * time.Second
	ownerNegCacheTTL = time.Duration(cfg.Owners.NegCacheTTLSec) * time.Second
	ownerEtcdTimeout = time.Duration(cfg.Owners.EtcdTimeoutMs) * time.Millisecond
	ownerGetConcurrency = cfg.Owners.GetConcurrency
	ownerRatePerSource = cfg.Owners.RateLimitPerSource
	ownerRateGlobal = cfg.Owners.RateLimitGlobal
	stickyMax = cfg.StickyMax
	maxConcurrentQueries = cfg.MaxConcurrentQueries
	forwardConcurrency = cfg.ForwardConcurrency
	maxTCPConns = cfg.TCPMaxConns
}

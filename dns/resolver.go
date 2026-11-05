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
	"container/heap"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"math/rand/v2"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"common/config"

	clientv3 "go.etcd.io/etcd/client/v3"
	"golang.org/x/sync/singleflight"
)

// StickyEntry represents a client-to-gateway sticky mapping (stream domain only:
// a sandlot sticks to the gateway it connected to before, principle 6). The
// record carries the gateway_ID, not its address: addresses are re-read from
// the gateway registry at resolve time, so affinity survives a gateway restart
// that changes its IP (the DNS answers with the new registered address).
type StickyEntry struct {
	GWID      string `json:"gw_id"`
	LastQuery int64  `json:"last_query"` // Unix timestamp
	Created   int64  `json:"created"`    // Unix timestamp
}

// GWInfo holds parsed gateway address info.
type GWInfo struct {
	AgentIP    string // IP portion of addr (e.g., "10.0.1.1")
	AgentPort  int    // Port portion of addr (e.g., 3000)
	StreamIP   string // IP portion of stream_addr
	StreamPort int    // Port portion of stream_addr
}

// ownerHealth is the in-memory view of a gateway's /sandswap/health/{id} record.
// The gateway writes {last_healthy_ts, node_count} there; liveness is judged by
// last_healthy_ts staleness (the key is plain, no lease). The DNS watches these
// keys to learn gateway liveness + compute presence. Routing addresses live in
// the gateway registry (registryByID), NOT here.
type ownerHealth struct {
	// lastHealthyTS is the health value's last_healthy_ts (RFC3339). The
	// continuous liveness signal: a gateway whose value is going stale is
	// failing to refresh (GC pause / value-write failure). gwAliveLocked
	// thresholds this so routing can reroute before the record disappears.
	lastHealthyTS time.Time
	// nodeCount is the owner's connected-sandlot count. 0 = alive but NO compute
	// (fault state) - excluded from sandfs-domain routing until a sandlot connects.
	nodeCount int
}

// gatewayRegistry is the in-memory view of a gateway's /sandswap/gateway/{id}
// record — its routing addresses as CONFIGURATION (plain key, no lease). The
// DNS watches these keys to resolve "where to reach a gateway" (owner branch
// and the no-owner scheduling fallback). Survives the gateway's death so the
// owner branch works during tolerance.
type gatewayRegistry struct {
	gatewayURL string // base agent URL (scheme://host:port) for agent routing
	streamAddr string // host:port sandlots use to reconnect (informational here)
}

// gwLoad is the in-memory view of a gateway's /sandswap/load/{id} record - the
// aggregate scheduling load the exec gateway publishes every ~2s. The DNS uses
// agg_duty_long for headroom scoring + cleanVMs as the routing-capacity gate +
// selfPressured (the gateway process's own sustained resource pressure) as a
// routing-eligibility gate.
type gwLoad struct {
	aggDutyLong   float64
	cleanVMs      uint32
	selfPressured bool
}

// ownerEntry caches an on-demand owner resolution (B4). Two independent
// timestamps, both atomic so the cache-HIT path only needs an RLock:
//   - fetchedAt — when the value was last CONFIRMED against etcd. This is the
//     TTL source: once it is older than the TTL, the next query re-validates,
//     no matter how hot the sandfs is. (A single lastUsed field refreshed on
//     every hit made hot sandfs NEVER revalidate — takeovers were invisible.)
//   - lastUsed — LRU recency only, refreshed on every hit so actively-queried
//     sandfs survive overflow eviction.
//
// Only POSITIVE entries live here (an owner exists). A negative (no-owner)
// resolution goes to ownerNegEntry, a separate bounded cache: a source that
// probes valid-shaped unowned IDs creates one distinct negative per probe, and
// putting those into this LRU would evict the real working set (and turn
// enumeration into cache churn). The gateway_id AND node_id are cached here;
// the routing address is looked up in the gateway registry (registryByID) at
// resolve time, so a gateway restart with a changed address takes effect
// immediately without touching per-sandfs caches. The node_id lets the owner
// branch, when the owner is dead/stale, look up the node's current presence
// holder and route there instead.
//
// prev/next/linked implement the O(1) approximate-LRU list (see evictOwners):
// nodes are moved ONLY by write-lock holders (insert / requeue); the RLock
// hit path never touches them — it just bumps the atomic lastUsed.
type ownerEntry struct {
	id        string // sandfs ID (map key, needed by list-tail eviction)
	gatewayID string
	nodeID    string       // "" = idle, "node-N" = mounted (for presence-directed routing)
	fetchedAt atomic.Int64 // UnixNano — freshness (TTL) source, written only on the slow path
	lastUsed  atomic.Int64 // UnixNano — LRU recency, refreshed on every hit

	prev, next *ownerEntry
	linked     bool

	// heapIdx is this entry's position in ownerExpiry (-1 when it has no live
	// tuple). It exists so the stale-while-error rollback — which moves the
	// entry's fetchedAt FORWARD, i.e. mutates a live heap key — can call
	// heap.Fix and keep the min-heap invariant the expiry loop depends on
	// (without the fix, a rolled-back entry could hide genuinely
	// expired entries below it and defer their eviction past the documented
	// bound).
	heapIdx int
}

// ownerNegEntry is one cached no-owner resolution. Kept in its own bounded map
// (not the owner LRU) so probe traffic cannot displace warm positive entries.
type ownerNegEntry struct {
	fetchedAt int64 // UnixNano — the ownerNegCacheTTL clock
}

// ownerNegCacheMax bounds the negative cache. Owner lookups that reach etcd
// are already limited by ownerRateGlobal per second and a negative entry lives
// ownerNegCacheTTL, so the live set is a few times that rate; the cap is pure
// memory bounding and overflow drops an arbitrary probe entry.
const ownerNegCacheMax = 65536

// ownerLRUMax bounds the owners cache (per-sandfs state must not grow past the
// provisioned RAM). The default holds a full million-sandfs fleet (~250-300MB
// at ~250B/entry): a smaller deployment only ever holds the entries it
// actually queried, so the cap is pure memory bounding, not pre-allocation.
// Configurable via owners.cache_max (restart-required). A var (not const) so
// tests can lower it to exercise overflow eviction cheaply.
var ownerLRUMax = 1000000

// ownerCacheTTL bounds how stale a positive owner entry can be before ownerFor
// re-validates against etcd (B4) — measured from fetchedAt (the last etcd
// confirmation), NOT from the last use, so a hot sandfs still revalidates
// every TTL window and an ownership change becomes visible within one TTL
// (plus the client-side answer TTL).
//
// The read-load lever: the steady etcd Get rate is roughly (actively-queried
// sandfs) / TTL, and the default is sized so a million actively-queried sandfs
// stay comfortable with serializable reads (~33k Gets/s at 30s). The cost is
// takeover visibility: 30s + answer TTL(10s) = ~40s worst case, still inside
// the system's takeover envelope (claim-dead-guard 45s; the dead-owner path
// already waits 20s route-stale + 45s guard). Operators wanting faster
// force-takeover pickup lower it via owners.cache_ttl_sec (restart-required).
var ownerCacheTTL = 30 * time.Second

// ownerNegCacheTTL bounds a negative (no-owner) entry. Short (1s) so a real
// first-claim is picked up promptly, but long enough to absorb retry storms on
// unowned sandfs (avoids etcd read amplification at scale). Configurable via
// owners.neg_cache_ttl_sec (restart-required).
var ownerNegCacheTTL = 1 * time.Second

// ownerErrHold bounds how soon ownerFor retries etcd after a FAILED lookup
// (stale-while-error): the stale entry's fetchedAt is rolled back to
// now-(TTL-ownerErrHold), so the next revalidation attempt happens after
// ~ownerErrHold instead of immediately — a query storm on one sandfs cannot
// hammer a partitioned etcd with timeout-bound Gets.
const ownerErrHold = 500 * time.Millisecond

// ownerEtcdTimeout bounds the on-demand etcd Get on the sandfs query path.
// A var so tests can shrink it (a dead endpoint then fails in ms).
var ownerEtcdTimeout = 2 * time.Second

// defaultDNSRouteStaleThreshold is the default health-staleness threshold for
// the DNS owner branch: once an owner's health record is this stale, the owner
// branch stops routing to it and falls back to presence-directed routing or
// the scheduling fallback. The health key has no lease, so staleness is the
// only death signal; judging wrong is cheap (a napping owner handles the
// request fine once it wakes), so this is the fastest death threshold. A
// normally-alive owner (value refreshed every 5s) is never stale. Overridable
// via staleness.route_stale_sec in the config file (hot-reloadable) and
// SetRouteStaleThreshold (tests shrink it).
const defaultDNSRouteStaleThreshold = 20 * time.Second

// ownerEvictInterval is how often the background evictor drops expired/overflow
// entries. The O(N) scan runs off the query hot path (not on each insert/lookup),
// so it does not add latency to owner resolution.
const ownerEvictInterval = 1 * time.Second

// stickyMax bounds the in-memory sticky map. UDP DNS is unauthenticated: a
// spoofed-source flood could otherwise grow the map (and its etcd mirror)
// without limit. Overflow inserts evict the least-recently-queried entry.
var stickyMax = 65536

// ownerGetConcurrency bounds concurrent on-demand owner etcd Gets triggered by
// the query path. A flood of distinct (garbage) sandfs IDs would otherwise
// park one goroutine per query behind a 2s Get timeout; beyond the cap the
// lookup fails fast (SERVFAIL) instead of queueing. Default sized for the
// large-fleet read rate (Gets/s × per-Get latency ≈ 33k × 3ms ≈ 100, with
// headroom) so legitimate misses are not busy-failed under load. Configurable
// via owners.get_concurrency (restart-required); 0 disables the cap.
var ownerGetConcurrency = 256

// presenceCacheTTL bounds a cached node-presence read (per nodeID). Short on
// purpose: presence flips (node migrates to a live peer, or reconnects) are
// the recovery signal for dead-owned sandfs, and the cache must not become the
// routing chain's bottleneck (every other term is ≥ its scale: owner TTL 30s,
// answer TTL 10s, route-stale 20s). A 1s TTL already collapses a same-node
// query storm to one etcd Get per node per second; longer TTLs only buy
// negligible etcd savings at the price of 503-spillover windows during
// recovery. Fetch-time-based; transport errors are never cached.
var presenceCacheTTL = 1 * time.Second

// presenceCacheEntry is one cached presence read: the holder observed at fetch
// time. The holder is re-JUDGED (health + registry) at answer time, never
// cached as a decision — a holder that died within the TTL falls through
// immediately.
type presenceCacheEntry struct {
	holder    string
	fetchedAt atomic.Int64 // UnixNano
}

// validSandfsID reports whether a sandfs ID has the canonical shape the gateway
// generates ("sandfs-" + [a-z0-9-] chars, 1-64 after the prefix, e.g.
// sandfs-3fa9c2e1). Callers lowercase the ID first (resolvers randomize name
// case per 0x0x0; etcd keys are lowercase). DNS labels may carry arbitrary
// bytes (escapes, slashes); those must be rejected at the dispatch gate with
// NXDOMAIN — they can never be real IDs, and letting them through turns any
// UDP packet into an etcd read (cache-bypassing DoS).
func validSandfsID(id string) bool {
	const prefix = "sandfs-"
	if !strings.HasPrefix(id, prefix) {
		return false
	}
	rest := id[len(prefix):]
	if rest == "" || len(rest) > 64 {
		return false
	}
	for _, r := range rest {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-':
		default:
			return false
		}
	}
	return true
}

// DNSServer implements the Sandswap DNS server. It serves two domains:
//   - sandfs zone <sandfs_id>.<sandfs>: owner-aware (route to the owner gateway,
//     or spread/binpack among healthy gateways when there is no owner).
//   - stream domain: sandlot placement (sticky + spread/binpack).
//
// All gateways are SELF-REGISTERED: the candidate set (addresses) comes from
// the /sandswap/gateway/{id} registry keys (plain, written by each gateway at
// startup), liveness from /sandswap/health/{id}, load from /sandswap/load/{id}.
// There is no static gateway config list — a gateway is a candidate iff it has
// registered. Owners are resolved on-demand (on-demand etcd Gets + LRU cache,
// B4) - a full prefix watch is unbounded RAM + an event storm at millions of
// sandfs.
type DNSServer struct {
	cfg *Config
	// guestNets are the configured sandbox guest ranges (config.guest_cidrs).
	// A query sourced from one of them is REFUSED unless it names a sandswap
	// zone — no foreign-zone relay for tenants.
	guestNets []*net.IPNet
	// recursiveNets are the NON-guest source ranges allowed to forward foreign
	// zones (config.recursive_acl; default loopback only). Sources outside it
	// are REFUSED, so the resolver is never an open recursive resolver.
	recursiveNets []*net.IPNet
	sticky        map[string]*StickyEntry // client_ip -> entry (stream domain)
	dirty         map[string]struct{}     // dirty set for etcd sync
	// mirrored records which client IPs actually HAVE a key in etcd (written
	// by a successful Put and removed by a successful Delete). It is what makes
	// the dirty set bounded: an entry that was EVICTED before the flush ever
	// reached it has nothing to delete, so marking it dirty would queue a
	// pointless Delete RPC and let a spoofed-source flood grow the set without
	// limit. Guarded by mu; lazily created (struct-literal tests).
	mirrored map[string]struct{}
	mu       sync.RWMutex // protects sticky, healthByID, loadByID, registryByID, gwAddrs

	// Owner-aware routing (B4): on-demand owner cache. ownersMu is SEPARATE from
	// mu so owner lookups (the sandfs-domain hot path) do not block the stream
	// domain or the health/load watch handlers. It also guards the node
	// presence read cache (presence) — same query path, same discipline: RLock
	// on the cache-hit path, Lock on the bounded slow-path fill and sweeps.
	ownersMu sync.RWMutex
	owners   map[string]*ownerEntry
	// negOwners caches no-owner resolutions separately from the positive LRU
	// (see ownerNegEntry). Lazily initialized so struct-literal tests work.
	negOwners map[string]*ownerNegEntry
	// rateLimiter bounds the etcd-bound owner-lookup slow path per source and
	// globally (nil = unbounded, as in struct-literal tests).
	rateLimiter *ownerRateLimiter
	// presence caches per-node presence reads (nodeID -> holder at fetch time)
	// for the dead-owner recovery path, collapsing a query storm on dead-owned
	// sandfs that share one mounted node into ~one etcd Get per node per TTL.
	// Lazily initialized (struct-literal construction keeps working); swept by
	// the owner evictor. See presenceRoute.
	presence map[string]*presenceCacheEntry
	// ownerExpiry orders owner-entry refresh records by fetchedAt for O(log N)
	// expiry (a map scan per tick would hold the write lock for tens of
	// milliseconds at the million-entry default cache size). Guarded by
	// ownersMu; tuples are lazily discarded when they no longer match the live
	// entry. See evictOwners.
	ownerExpiry ownerExpiryHeap
	// lruRoot is the O(1) approximate-LRU list sentinel (front = most recent).
	// Lazily initialized (zero value = empty) so struct-literal construction
	// keeps working.
	lruRoot ownerEntry
	sf      singleflight.Group // dedup concurrent misses for the same sandfs
	// ownerSem bounds concurrent on-demand owner etcd Gets (query-path DoS
	// bound). nil = unbounded (struct-literal tests / bootstrap).
	ownerSem chan struct{}

	healthByID   map[string]ownerHealth     // gateway_id -> health record (etcd watch)
	loadByID     map[string]gwLoad          // gateway_id -> load record (etcd watch)
	registryByID map[string]gatewayRegistry // gateway_id -> routing registry (etcd watch, plain key)
	// gwAddrs holds the parsed placement-candidate addresses per gateway_id,
	// built from the self-registered registry keys (watch + periodic re-list):
	// gateway_url -> agent host, stream_addr -> stream host+port. A gateway with
	// an empty stream_addr is an agent-domain candidate only.
	gwAddrs map[string]GWInfo

	// schedConfig holds the live routing policy (binpack | spread), atomically
	// swappable on config-file hot-reload. Nil (tests / bootstrap) = spread.
	schedConfig *config.WatchableConfig[SchedulingConfig]

	etcdClient *clientv3.Client

	// Listeners (self-managed, wire-level; see server.go). Both errors are
	// fatal and surface from ListenAndServe.
	udpConn *net.UDPConn
	tcpLn   net.Listener
	// loopbackUDP are the dedicated host-local sockets bound alongside a
	// wildcard UDP listener. They exist so the recursive ACL can use the
	// packet's INGRESS (a socket bound to a loopback address) instead of
	// trusting the source address (spoofable with route_localnet).
	loopbackUDP []*net.UDPConn
	querySem    chan struct{} // in-flight query bound (flood guard)
	// forwardSem bounds concurrent UPSTREAM forwards (foreign-zone relay), a
	// separate small budget from querySem: a forwarded query holds its slot
	// for up to relayTimeout × len(Forwarders) (sequential upstream attempts),
	// so sharing the query budget would let an upstream flood starve the
	// authoritative answers. Created in ListenAndServe; nil (tests) =
	// unbounded.
	forwardSem chan struct{}

	// routeStaleThreshold is the health-staleness threshold for the owner branch
	// (gwAliveLocked + resolveSandfsOwner). A var-style field set via
	// SetRouteStaleThreshold; defaults to defaultDNSRouteStaleThreshold.
	routeStaleThreshold time.Duration
}

// NewDNSServer creates a new DNS server.
func NewDNSServer(cfg *Config) (*DNSServer, error) {
	s := &DNSServer{
		cfg:                 cfg,
		sticky:              make(map[string]*StickyEntry),
		dirty:               make(map[string]struct{}),
		owners:              make(map[string]*ownerEntry),
		negOwners:           make(map[string]*ownerNegEntry),
		rateLimiter:         newOwnerRateLimiter(),
		healthByID:          make(map[string]ownerHealth),
		loadByID:            make(map[string]gwLoad),
		registryByID:        make(map[string]gatewayRegistry),
		gwAddrs:             make(map[string]GWInfo),
		routeStaleThreshold: defaultDNSRouteStaleThreshold,
	}
	for _, cidr := range cfg.GuestCIDRs {
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("guest_cidrs entry %q: %v", cidr, err)
		}
		s.guestNets = append(s.guestNets, n)
	}
	for _, cidr := range cfg.RecursiveACL {
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("recursive_acl entry %q: %v", cidr, err)
		}
		s.recursiveNets = append(s.recursiveNets, n)
	}
	if ownerGetConcurrency > 0 {
		s.ownerSem = make(chan struct{}, ownerGetConcurrency)
	}

	// Connect to etcd (with mTLS when certs configured - required in k8s where
	// Sandswap's app etcd uses --client-cert-auth).
	tlsCfg, err := etcdTLSConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("build etcd tls config: %w", err)
	}
	cli, err := clientv3.New(clientv3.Config{
		Endpoints:   strings.Split(cfg.Etcd, ","),
		DialTimeout: 5 * time.Second,
		TLS:         tlsCfg,
	})
	if err != nil {
		return nil, fmt.Errorf("connect to etcd: %w", err)
	}
	s.etcdClient = cli

	// Load sticky from etcd (stream-domain sandlot affinity survives a DNS restart).
	s.loadStickyFromEtcd()

	// Initial health/registry/load refresh BEFORE serving. ListenAndServe may
	// start concurrently with Start's watchers, and a query arriving while
	// healthByID is still empty would judge every gateway dead (stream queries
	// SERVFAIL) and, worse, send owned sandfs down the owner-dead branch —
	// whose presence lookup names the live owner itself, so the answer degrades
	// to the scheduling fallback and the non-owner 503s. One synchronous
	// bounded refresh (same pattern as the sticky load above) closes that
	// window; Start's watchers then re-list and take over incrementally.
	s.refreshOwnerAndHealth(context.Background())
	s.presence = make(map[string]*presenceCacheEntry)

	// Set up the live routing policy (hot-reloadable via config-file watch).
	s.schedConfig = config.NewWatchableConfig(cfg.Scheduling.Normalized())

	return s, nil
}

// etcdTLSConfig builds the etcd client TLS config from the config's CA/cert/key.
// Returns nil (plaintext) when no CA is set.
func etcdTLSConfig(cfg *Config) (*tls.Config, error) {
	if cfg.EtcdCA == "" {
		return nil, nil
	}
	pool := x509.NewCertPool()
	caPEM, err := os.ReadFile(cfg.EtcdCA)
	if err != nil {
		return nil, fmt.Errorf("read etcd_ca: %w", err)
	}
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("invalid etcd_ca PEM")
	}
	tlsCfg := &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	if cfg.EtcdCert != "" && cfg.EtcdKey != "" {
		cert, err := tls.LoadX509KeyPair(cfg.EtcdCert, cfg.EtcdKey)
		if err != nil {
			return nil, fmt.Errorf("load etcd client cert: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}
	return tlsCfg, nil
}

// validDNSHost reports whether host is usable as an A/CNAME target: an IP
// literal or a syntactically sane DNS name (labels of [A-Za-z0-9-], 1-63
// bytes, total <= 253). A garbage gateway_url must be excluded from answering,
// not relayed into a junk CNAME the client can never resolve.
func validDNSHost(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}
	if net.ParseIP(host) != nil {
		return true
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for _, r := range label {
			switch {
			case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-':
			default:
				return false
			}
		}
	}
	return true
}

// parseGatewayAddrs parses a gateway's SELF-REGISTERED routing addresses (the
// /sandswap/gateway/{id} registry value) into the DNS-facing address record:
// gateway_url yields the agent host (A/CNAME target), stream_addr the stream
// host+port (A/SRV for sandlot placement). Validation is PER-DOMAIN: an
// unparsable field leaves that field empty (the gateway is ineligible for that
// domain only) and is reported in problems for loud logging — a bad
// stream_addr must not also destroy the gateway's agent-domain candidacy, and
// vice versa. An empty stream_addr (a gateway with no stream, e.g. human mode)
// is valid: the entry is then an agent-domain candidate only.
func parseGatewayAddrs(gatewayURL, streamAddr string) (info GWInfo, problems []string) {
	if gatewayURL != "" {
		u := strings.TrimPrefix(strings.TrimPrefix(gatewayURL, "https://"), "http://")
		if host, port, err := net.SplitHostPort(u); err == nil {
			if p, perr := strconv.Atoi(port); perr == nil {
				info.AgentPort = p
			}
			info.AgentIP = host
		} else {
			// No port (bare host, optionally with a path) — host is all of it.
			info.AgentIP = gatewayURLHost(gatewayURL)
		}
		if !validDNSHost(info.AgentIP) {
			problems = append(problems, fmt.Sprintf("gateway_url %q: invalid host %q", gatewayURL, info.AgentIP))
			info.AgentIP = ""
		}
	}
	if streamAddr != "" {
		host, port, err := net.SplitHostPort(streamAddr)
		if err != nil {
			problems = append(problems, fmt.Sprintf("stream_addr %q: %v", streamAddr, err))
		} else if sp, err := strconv.Atoi(port); err != nil {
			problems = append(problems, fmt.Sprintf("stream_addr %q: invalid port %q", streamAddr, port))
		} else if sp < 1 || sp > 65535 {
			// Out of range is a misregistration, not a usable port: answering it
			// as uint16(sp) (65536 → 0) would serve a plausible-looking SRV
			// record that points nowhere. Same stance as the other
			// misregistered fields — excluded from that domain's placement.
			problems = append(problems, fmt.Sprintf("stream_addr %q: port %d out of range (1-65535)", streamAddr, sp))
		} else {
			info.StreamIP = host
			info.StreamPort = sp
		}
	}
	return info, problems
}

// Start launches background goroutines: sticky sync/expiry, owner-aware etcd
// watch, and the owner-cache background evictor.
func (s *DNSServer) Start(ctx context.Context) {
	go s.syncLoop(ctx)
	go s.expireLoop(ctx)
	go s.ownerEvictor(ctx)
	// Owner-aware DNS: watch /sandswap/health/ and /sandswap/load/ so a sandfs
	// query resolves to its owner gateway (or, on owner death, falls back to
	// spread/binpack among healthy gateways).
	go s.watchOwnerAndHealth(ctx)
}

// watchOwnerAndHealth maintains the healthByID (gateway_id -> addr) and loadByID
// (gateway_id -> load) maps. Owners are resolved ON-DEMAND (on-demand etcd Gets +
// LRU cache, ownerFor) instead of a full prefix watch - at millions of sandfs a
// full owners watch is unbounded RAM + an event storm. An initial full load
// happens before the first query and hands its revision to the watches (no
// list/watch gap); etcd watches provide immediate updates; a periodic full
// re-list is the safety net for missed watch events.
func (s *DNSServer) watchOwnerAndHealth(ctx context.Context) {
	rev := s.refreshOwnerAndHealth(ctx)

	// Safety-net re-list: a missed DELETE (gateway death) could otherwise pin a
	// dead gateway in the maps until the next re-list. 30s bounds staleness.
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.refreshOwnerAndHealth(ctx)
			}
		}
	}()

	go s.watchPrefix(ctx, "/sandswap/health/", rev, s.handleHealthEvent)
	go s.watchPrefix(ctx, "/sandswap/load/", rev, s.handleLoadEvent)
	go s.watchPrefix(ctx, "/sandswap/gateway/", rev, s.handleGatewayEvent)
}

// watchPrefix watches an etcd prefix and calls handler(key, value, deleted) for
// each event, reconnecting on error/close. fromRev chains the watch to a
// preceding list (events between the list snapshot and watch establishment are
// replayed, closing the list/watch gap); on reconnect the watch resumes from
// the last delivered revision, and after an error it falls back to live (rev
// 0) — replaying from a pre-error revision risks an ErrCompacted loop, and the
// 30s safety-net re-list covers that bounded gap instead. Handlers are
// idempotent map upserts/deletes, so replayed events are harmless.
func (s *DNSServer) watchPrefix(ctx context.Context, prefix string, fromRev int64, handler func(key, value string, deleted bool)) {
	rev := fromRev
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		opts := []clientv3.OpOption{clientv3.WithPrefix()}
		if rev > 0 {
			opts = append(opts, clientv3.WithRev(rev))
		}
		wch := s.etcdClient.Watch(ctx, prefix, opts...)
		for resp := range wch {
			if err := resp.Err(); err != nil {
				log.Printf("dns watch %s error: %v (reconnecting live)", prefix, err)
				rev = 0
				break
			}
			if resp.Header != nil && resp.Header.Revision > 0 {
				rev = resp.Header.Revision
			}
			for _, ev := range resp.Events {
				key := string(ev.Kv.Key)
				switch ev.Type {
				case clientv3.EventTypePut:
					handler(key, string(ev.Kv.Value), false)
				case clientv3.EventTypeDelete:
					handler(key, "", true)
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second):
		}
	}
}

// handleLoadEvent updates the loadByID map from a /sandswap/load/{gw} event.
func (s *DNSServer) handleLoadEvent(key, value string, deleted bool) {
	gwID := strings.TrimPrefix(key, "/sandswap/load/")
	s.mu.Lock()
	defer s.mu.Unlock()
	if deleted {
		delete(s.loadByID, gwID)
		return
	}
	var lv struct {
		AggDutyLong   float64 `json:"agg_duty_long"`
		CleanVMs      uint32  `json:"clean_vms"`
		SelfPressured bool    `json:"self_pressured"`
	}
	if err := json.Unmarshal([]byte(value), &lv); err != nil {
		log.Printf("dns: corrupt load value for %s: %v", gwID, err)
		return
	}
	s.loadByID[gwID] = gwLoad{aggDutyLong: lv.AggDutyLong, cleanVMs: lv.CleanVMs, selfPressured: lv.SelfPressured}
}

// handleHealthEvent updates the healthByID map from a /sandswap/health/{gw}
// event. Purely liveness + compute presence (node_count); routing addresses
// come from the gateway registry (handleGatewayEvent).
func (s *DNSServer) handleHealthEvent(key, value string, deleted bool) {
	gwID := strings.TrimPrefix(key, "/sandswap/health/")
	s.mu.Lock()
	defer s.mu.Unlock()
	if deleted {
		delete(s.healthByID, gwID)
		return
	}
	var hv struct {
		NodeCount     int    `json:"node_count"`
		LastHealthyTS string `json:"last_healthy_ts"`
	}
	if err := json.Unmarshal([]byte(value), &hv); err != nil {
		log.Printf("dns: corrupt health value for %s: %v", gwID, err)
		return
	}
	oh := ownerHealth{nodeCount: hv.NodeCount}
	if hv.LastHealthyTS != "" {
		if ts, perr := time.Parse(time.RFC3339, hv.LastHealthyTS); perr == nil {
			oh.lastHealthyTS = ts
		}
	}
	s.healthByID[gwID] = oh
}

// handleGatewayEvent updates the registryByID map and the gwAddrs placement
// candidate table from a /sandswap/gateway/{gw} event. The registry key is a
// PLAIN key holding the gateway's self-registered routing addresses as
// configuration — it survives the gateway's death, so the owner branch keeps
// resolving during tolerance. Registration IS candidacy: a gateway with no
// registry key is not a placement candidate.
func (s *DNSServer) handleGatewayEvent(key, value string, deleted bool) {
	gwID := strings.TrimPrefix(key, "/sandswap/gateway/")
	s.mu.Lock()
	defer s.mu.Unlock()
	if deleted {
		delete(s.registryByID, gwID)
		delete(s.gwAddrs, gwID)
		return
	}
	var rv struct {
		GatewayURL string `json:"gateway_url"`
		StreamAddr string `json:"stream_addr"`
	}
	if err := json.Unmarshal([]byte(value), &rv); err != nil {
		log.Printf("dns: corrupt gateway registry value for %s: %v", gwID, err)
		return
	}
	s.registryByID[gwID] = gatewayRegistry{gatewayURL: rv.GatewayURL, streamAddr: rv.StreamAddr}
	// A misregistered field must be excluded loudly, not answer broken records.
	// Exclusion is per-domain (empty field = ineligible for that domain); the
	// registry record itself is kept — owner routing revalidates the host via
	// gatewayURLToCNAME at resolve time.
	info, problems := parseGatewayAddrs(rv.GatewayURL, rv.StreamAddr)
	for _, p := range problems {
		log.Printf("dns: gateway %s misregistered (%s); excluded from that domain's placement", gwID, p)
	}
	s.gwAddrs[gwID] = info
}

// refreshOwnerAndHealth re-lists the health + load prefixes from etcd (initial
// load + safety-net re-list) and returns the etcd revision the lists ran at, so
// the watches can chain from it (no list/watch gap). Owners are NOT re-listed -
// they are resolved on-demand (ownerFor) to bound memory.
func (s *DNSServer) refreshOwnerAndHealth(ctx context.Context) int64 {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var rev int64

	// healthByID (liveness + compute only; addresses come from the registry).
	if resp, err := s.etcdClient.Get(ctx, "/sandswap/health/", clientv3.WithPrefix()); err == nil {
		if resp.Header != nil {
			rev = resp.Header.Revision
		}
		hb := make(map[string]ownerHealth, len(resp.Kvs))
		for _, kv := range resp.Kvs {
			gwID := strings.TrimPrefix(string(kv.Key), "/sandswap/health/")
			var hv struct {
				NodeCount     int    `json:"node_count"`
				LastHealthyTS string `json:"last_healthy_ts"`
			}
			if json.Unmarshal(kv.Value, &hv) == nil {
				oh := ownerHealth{nodeCount: hv.NodeCount}
				if hv.LastHealthyTS != "" {
					if ts, perr := time.Parse(time.RFC3339, hv.LastHealthyTS); perr == nil {
						oh.lastHealthyTS = ts
					}
				}
				hb[gwID] = oh
			}
		}
		s.mu.Lock()
		s.healthByID = hb
		s.mu.Unlock()
	} else {
		log.Printf("dns: refresh health failed: %v", err)
	}

	// registryByID (routing addresses as configuration) + gwAddrs placement
	// candidates — both rebuilt from the self-registered registry keys.
	if resp, err := s.etcdClient.Get(ctx, "/sandswap/gateway/", clientv3.WithPrefix()); err == nil {
		if resp.Header != nil && resp.Header.Revision > rev {
			rev = resp.Header.Revision
		}
		rb := make(map[string]gatewayRegistry, len(resp.Kvs))
		ga := make(map[string]GWInfo, len(resp.Kvs))
		for _, kv := range resp.Kvs {
			gwID := strings.TrimPrefix(string(kv.Key), "/sandswap/gateway/")
			var rv struct {
				GatewayURL string `json:"gateway_url"`
				StreamAddr string `json:"stream_addr"`
			}
			if json.Unmarshal(kv.Value, &rv) == nil {
				rb[gwID] = gatewayRegistry{gatewayURL: rv.GatewayURL, streamAddr: rv.StreamAddr}
				info, problems := parseGatewayAddrs(rv.GatewayURL, rv.StreamAddr)
				for _, p := range problems {
					log.Printf("dns: gateway %s misregistered (%s); excluded from that domain's placement", gwID, p)
				}
				ga[gwID] = info
			}
		}
		s.mu.Lock()
		s.registryByID = rb
		s.gwAddrs = ga
		s.mu.Unlock()
	} else {
		log.Printf("dns: refresh gateway registry failed: %v", err)
	}

	// loadByID
	if resp, err := s.etcdClient.Get(ctx, "/sandswap/load/", clientv3.WithPrefix()); err == nil {
		if resp.Header != nil && resp.Header.Revision > rev {
			rev = resp.Header.Revision
		}
		lb := make(map[string]gwLoad, len(resp.Kvs))
		for _, kv := range resp.Kvs {
			gwID := strings.TrimPrefix(string(kv.Key), "/sandswap/load/")
			var lv struct {
				AggDutyLong   float64 `json:"agg_duty_long"`
				CleanVMs      uint32  `json:"clean_vms"`
				SelfPressured bool    `json:"self_pressured"`
			}
			if json.Unmarshal(kv.Value, &lv) == nil {
				lb[gwID] = gwLoad{aggDutyLong: lv.AggDutyLong, cleanVMs: lv.CleanVMs, selfPressured: lv.SelfPressured}
			}
		}
		s.mu.Lock()
		s.loadByID = lb
		s.mu.Unlock()
	} else {
		log.Printf("dns: refresh load failed: %v", err)
	}
	return rev
}

// preferHigherLoad reports whether the routing policy is binpack (prefer the
// busiest healthy gateway) vs spread (prefer the idlest). The policy is
// atomically swappable (config hot-reload), so callers read it once per pick.
// A nil schedConfig (tests/bootstrap) defaults to spread.
func (s *DNSServer) preferHigherLoad() bool {
	if s.schedConfig == nil {
		return false
	}
	return s.schedConfig.Get().Policy == PolicyBinpack
}

// dutyHard returns the configured gateway duty cap (0 = disabled). A nil
// schedConfig (tests/bootstrap) means no cap.
func (s *DNSServer) dutyHard() float64 {
	if s.schedConfig == nil {
		return 0
	}
	return s.schedConfig.Get().DutyHard
}

// SetScheduling applies the routing policy + duty cap live (the config-file
// hot-reload path in main.go). Invalid policy or out-of-range duty is rejected
// (current kept).
func (s *DNSServer) SetScheduling(policy string, dutyHard float64) bool {
	if policy != PolicySpread && policy != PolicyBinpack {
		return false
	}
	if dutyHard < 0 || dutyHard > 1 {
		return false
	}
	sc := SchedulingConfig{Policy: policy, DutyHard: dutyHard}
	if s.schedConfig == nil {
		s.schedConfig = config.NewWatchableConfig(sc)
		return true
	}
	s.schedConfig.Swap(sc)
	log.Printf("dns scheduling: policy=%s duty_hard=%.2f", policy, dutyHard)
	return true
}

// pickBySchedulingPolicy returns the host of a gateway chosen by the scheduling
// policy among self-registered healthy gateways that have BOTH a registry
// gateway_url AND compute (node_count > 0). Serves as the no-owner fallback pool
// for the owner-aware sandfs zone. The candidate set comes entirely from the
// self-registered /sandswap/gateway/{id} keys.
// Gateways in the fault state (alive, registry gateway_url set, node_count==0)
// are skipped - they cannot serve until a sandlot reconnects. The selection
// direction follows the scheduling policy: binpack (the configured default —
// SchedulingConfig.Normalized maps any non-"spread" value to binpack) picks the
// busiest healthy gateway (highest agg_duty_long) so new sandfs pack onto
// fewer gateways; spread picks the most idle one (lowest agg_duty_long).
//
// For >2 candidates, power-of-two-choices is used for BOTH policies: pick two
// random candidates and choose the one the policy prefers (spread: lower duty;
// binpack: higher). This breaks the concentration of deterministic-best — for
// spread, the thundering herd within one load-publish window funnels onto the
// single least-loaded gateway; for binpack at fleet scale, every fallback
// answer after a gateway death lands on one absorber, which then compounds.
// With <=2 candidates, selection is deterministic so the common two-gateway
// case stays stable.
func (s *DNSServer) pickBySchedulingPolicy() (host string, ok bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var candidates []string // gateway IDs that are routable
	capDuty := s.dutyHard()
	for gwID, h := range s.healthByID {
		// Must be ALIVE with compute (fresh last_healthy_ts, node_count>0) AND have
		// a ROUTABLE agent address. The gate is the VALIDATED gwAddrs entry,
		// not the raw registry string: parseGatewayAddrs empties AgentIP for a
		// misregistered gateway_url (invalid host), and gating on the raw value
		// would serve that junk as the fallback host — the CNAME encode then
		// fails and every unowned-sandfs answer degrades to SERVFAIL while the
		// watch-time log claims the gateway was "excluded". Same gate as
		// pickGatewayLocked's agent domain (an unregistered gateway has an
		// empty AgentIP too and is excluded).
		// ALIVENESS FIRST: the health key is a PLAIN key (no lease) and is not
		// deleted when a gateway dies, so healthByID keeps a dead gateway's
		// frozen record forever. Only the last_healthy_ts staleness says
		// "dead" — and its /sandswap/load key (10s lease) expires, which makes
		// a corpse look like a "bootstrap" gateway (no load record → every
		// capacity gate below is skipped). Without this gate the fallback
		// prefers the corpse and answers clients a dead address instead of
		// failing closed to SERVFAIL. Same gate as pickGatewayLocked / the
		// owner branch.
		if !s.gwAliveLocked(gwID) {
			continue
		}
		if h.nodeCount == 0 {
			continue
		}
		if s.gwAddrs[gwID].AgentIP == "" {
			continue
		}
		l, haveLoad := s.loadByID[gwID]
		// Capacity gate: a gateway with a load record but zero clean VMs can't
		// serve (routing would 503 at the gateway). No record yet = bootstrap.
		if haveLoad && l.cleanVMs == 0 {
			continue
		}
		// Self-pressure gate: the gateway process itself is under sustained
		// resource pressure (published self_pressured — process CPU vs
		// GOMAXPROCS / soft-limit memory, sustained past a hysteresis window).
		// Steer NEW placement elsewhere. No record yet = bootstrap, pass.
		if haveLoad && l.selfPressured {
			continue
		}
		// Saturation cap (both policies): don't route to an overloaded gateway.
		if capDuty > 0 && haveLoad && l.aggDutyLong >= capDuty {
			continue
		}
		candidates = append(candidates, gwID)
	}
	if len(candidates) == 0 {
		return "", false
	}

	dutyOf := func(gwID string) float64 {
		if l, ok := s.loadByID[gwID]; ok {
			return l.aggDutyLong
		}
		return 0
	}
	hostOf := func(gwID string) string {
		return s.gwAddrs[gwID].AgentIP
	}

	binpack := s.preferHigherLoad()
	if len(candidates) > 2 {
		// Power-of-two-choices for BOTH policies: two distinct random
		// candidates, keep the one the policy prefers (binpack: higher duty;
		// spread: lower). This de-concentrates placement — deterministic-best
		// funnels every query onto one gateway: for spread, the whole
		// thundering herd within one load-publish window; for binpack, at
		// fleet scale, every fallback answer after a gateway death onto a
		// single absorber (which then becomes the busiest and keeps absorbing,
		// compounding with each failure). With <=2 candidates selection stays
		// deterministic so the common two-gateway case is stable.
		i := rand.IntN(len(candidates))
		j := (i + 1 + rand.IntN(len(candidates)-1)) % len(candidates)
		pick := i
		if (binpack && dutyOf(candidates[j]) > dutyOf(candidates[i])) ||
			(!binpack && dutyOf(candidates[j]) < dutyOf(candidates[i])) {
			pick = j
		}
		return hostOf(candidates[pick]), true
	}

	// Deterministic: binpack = highest duty; spread = lowest duty.
	best := candidates[0]
	for _, c := range candidates[1:] {
		if (binpack && dutyOf(c) > dutyOf(best)) || (!binpack && dutyOf(c) < dutyOf(best)) {
			best = c
		}
	}
	return hostOf(best), true
}

// ownerResolution is the owner record read from the ownership key: just the
// gateway ID. The routing address is NOT stored here — it lives in the
// /sandswap/gateway/{gw} registry key and is resolved via registryByID at
// resolve time. This keeps the ownership key a pure per-sandfs claim (no
// per-sandfs address redundancy) and makes a gateway restart with a changed
// address take effect immediately without touching per-sandfs state.
type ownerResolution struct {
	gatewayID string
	nodeID    string // "" = idle, "node-N" = mounted (for presence-directed routing)
}

// resolveOwnerFromEtcd Gets the owner gateway ID (and node_id) for a sandfs
// from etcd on demand (no full prefix watch - bounded memory at millions of
// sandfs). The routing address is NOT here: resolveSandfsOwner looks it up in
// the gateway registry (registryByID) after this call. The node_id lets the
// owner branch, when the owner is dead/stale, look up the node's current
// presence holder and route there instead.
//
// The Get is SERIALIZABLE (served by any member's local state, no quorum
// round-trip): routing already tolerates cache-TTL-scale staleness by design,
// so a possibly ~100ms-stale read is semantically free — and it keeps owner
// lookups answering through etcd leader elections (linearizable reads fail
// during them), shrinking the fail-closed SERVFAIL window to real etcd loss.
//
// Error semantics are three-way: a transport error or a corrupt value returns
// (zero, err) — the caller must NOT treat that as "no owner" (a transient etcd
// blip must not reroute owned sandfs to the scheduling fallback); only zero
// KVs (or a nil client, tests) is a genuine no-owner (zero, nil).
func (s *DNSServer) resolveOwnerFromEtcd(sandfsID string) (ownerResolution, error) {
	if s.etcdClient == nil {
		return ownerResolution{}, nil // nil-client (tests / no etcd): treat as no owner
	}
	ctx, cancel := context.WithTimeout(context.Background(), ownerEtcdTimeout)
	defer cancel()
	resp, err := s.etcdClient.Get(ctx, "/sandswap/owner/"+sandfsID, clientv3.WithSerializable())
	if err != nil {
		return ownerResolution{}, fmt.Errorf("etcd get owner %s: %w", sandfsID, err)
	}
	if len(resp.Kvs) == 0 {
		return ownerResolution{}, nil // genuinely unowned
	}
	var ov struct {
		GatewayID string `json:"gateway_id"`
		NodeID    string `json:"node_id"`
	}
	if err := json.Unmarshal(resp.Kvs[0].Value, &ov); err != nil {
		return ownerResolution{}, fmt.Errorf("corrupt owner value for %s: %w", sandfsID, err)
	}
	return ownerResolution{gatewayID: ov.GatewayID, nodeID: ov.NodeID}, nil
}

// ownerFetch carries the (result, error) pair through the singleflight Do call
// (Do discards the value when fn returns a non-nil error, so the error is
// packed inside the value instead).
type ownerFetch struct {
	res ownerResolution
	err error
}

// errOwnerLookupRateLimited is the LOCAL refusal of the etcd-bound owner-lookup
// slow path: the source (or the resolver as a whole) exceeded its lookup rate.
// It is deliberately not an etcd failure — a stale-known owner is still served
// — and it is never logged per query (a flood would become a log flood).
var errOwnerLookupRateLimited = errors.New("owner lookup rate limited")

// ownerFor returns the owner gateway for a sandfs, using an LRU cache backed by
// on-demand etcd Gets. The positive cache is bounded (ownerLRUMax) and
// TTL-validated from fetchedAt (ownerCacheTTL); no-owner resolutions live in a
// separate bounded cache with a short TTL (ownerNegCacheTTL) so probe traffic
// cannot evict the warm working set. Both TTLs run from the last etcd
// confirmation, NOT the last use, so a continuously-queried sandfs still
// revalidates every TTL window and an ownership change (takeover/release)
// becomes visible within one TTL. Concurrent misses for the same sandfs are
// coalesced via singleflight.
//
// The optional sourceIP charges the etcd-bound slow path to that source's rate
// bucket (and to the global one); cache hits bypass it entirely.
//
// On etcd failure: nothing is cached as negative (a transient error must not
// masquerade as "no owner"); a stale-known entry is served as-is
// (stale-while-error) with its revalidation deferred by ownerErrHold; with no
// prior knowledge the error is propagated and the caller fails closed
// (SERVFAIL) instead of guessing via the scheduling fallback.
//
// The HIT path takes only an RLock and refreshes lastUsed atomically (no write
// lock), so an actively-queried sandfs stays warm without serializing other
// owner lookups. A background evictor (ownerEvictor) drops expired/overflow
// entries off the query path.
func (s *DNSServer) ownerFor(sandfsID string, sourceIP ...string) (ownerResolution, error) {
	source := ""
	if len(sourceIP) > 0 {
		source = sourceIP[0]
	}

	// Fast path: fresh positive entry (RLock + atomic lastUsed refresh) or a
	// fresh cached negative. Freshness is judged by fetchedAt; lastUsed is only
	// LRU recency.
	s.ownersMu.RLock()
	e, ok := s.owners[sandfsID]
	if ok && time.Since(time.Unix(0, e.fetchedAt.Load())) < ownerCacheTTL {
		e.lastUsed.Store(time.Now().UnixNano())
		s.ownersMu.RUnlock()
		return ownerResolution{gatewayID: e.gatewayID, nodeID: e.nodeID}, nil
	}
	if neg, ok := s.negOwners[sandfsID]; ok && time.Since(time.Unix(0, neg.fetchedAt)) < ownerNegCacheTTL {
		s.ownersMu.RUnlock()
		return ownerResolution{}, nil
	}
	s.ownersMu.RUnlock()

	// Slow path: singleflight dedupes concurrent misses for the same sandfs
	// into one etcd Get, then upserts the cache. The rate limiter bounds how
	// fast DISTINCT etcd-bound lookups may start (one token per actual Get;
	// concurrent duplicates share the singleflight result), and the
	// concurrency semaphore bounds in-flight Gets. Beyond either bound the
	// lookup fails fast (stale-while-error / SERVFAIL).
	resIface, _, _ := s.sf.Do(sandfsID, func() (interface{}, error) {
		// In-flight bound first: a busy failure performs no Get, so it must
		// not consume a rate token.
		if s.ownerSem != nil {
			select {
			case s.ownerSem <- struct{}{}:
			default:
				return ownerFetch{err: fmt.Errorf("owner lookup busy (concurrency cap %d)", ownerGetConcurrency)}, nil
			}
			defer func() { <-s.ownerSem }()
		}
		if !s.rateLimiter.allow(source) {
			return ownerFetch{err: errOwnerLookupRateLimited}, nil
		}
		f := ownerFetch{}
		f.res, f.err = s.resolveOwnerFromEtcd(sandfsID)
		return f, nil
	})
	f := resIface.(ownerFetch)

	if f.err != nil {
		// Etcd failed (or the lookup was rate-limited): serve the stale-known
		// value if we have one and defer the retry; never cache the failure as
		// a negative answer. A cached negative is likewise still served: the
		// caller's answer stays "no owner" rather than flipping to SERVFAIL.
		s.ownersMu.Lock()
		if e, ok := s.owners[sandfsID]; ok {
			hold := ownerErrHold
			if hold > ownerCacheTTL {
				hold = ownerCacheTTL / 2
			}
			e.fetchedAt.Store(time.Now().Add(-(ownerCacheTTL - hold)).UnixNano())
			// The entry's key in ownerExpiry just moved FORWARD. A min-heap
			// whose key mutated in place no longer has its minimum at the
			// root, and the expiry loop stops at the first tuple that looks
			// unexpired — so without this Fix a long outage could defer the
			// eviction of OTHER (genuinely expired) entries past the
			// documented bound. heapIdx is maintained by the heap's
			// own Swap/Push/Pop; the guard covers the lazy-deletion case where
			// the tuple was already popped.
			if e.heapIdx >= 0 && e.heapIdx < len(s.ownerExpiry) && s.ownerExpiry[e.heapIdx] == e {
				heap.Fix(&s.ownerExpiry, e.heapIdx)
			}
			s.ownersMu.Unlock()
			if f.err != errOwnerLookupRateLimited {
				log.Printf("dns: owner lookup for %s failed (%v); serving stale cache", sandfsID, f.err)
			}
			return ownerResolution{gatewayID: e.gatewayID, nodeID: e.nodeID}, nil
		}
		if _, ok := s.negOwners[sandfsID]; ok {
			s.ownersMu.Unlock()
			return ownerResolution{}, nil
		}
		s.ownersMu.Unlock()
		return ownerResolution{}, f.err // nothing known: fail closed (SERVFAIL)
	}

	s.ownersMu.Lock()
	defer s.ownersMu.Unlock()
	if f.res.gatewayID == "" {
		// A miss NEVER enters the LRU: it is probe-controlled state, kept only
		// in the bounded negative cache.
		s.storeNegativeLocked(sandfsID)
		return ownerResolution{}, nil
	}
	delete(s.negOwners, sandfsID) // a positive answer supersedes a cached negative
	s.ownerStoreLocked(sandfsID, f.res)
	return f.res, nil
}

// storeNegativeLocked records a no-owner resolution in the bounded negative
// cache. Caller MUST hold s.ownersMu (write).
//
// A fresh no-owner answer SUPERSEDES a stale positive entry for the same ID
// (ownership release / takeover): leaving the stale positive behind would let
// a later etcd error serve the old owner from the stale-while-error path even
// though the newest confirmed state is "no owner".
func (s *DNSServer) storeNegativeLocked(sandfsID string) {
	if s.negOwners == nil {
		s.negOwners = make(map[string]*ownerNegEntry)
	}
	if old, ok := s.owners[sandfsID]; ok {
		s.unlinkLocked(old)
		delete(s.owners, sandfsID)
	}
	if _, ok := s.negOwners[sandfsID]; !ok && len(s.negOwners) >= ownerNegCacheMax {
		// At the cap: drop an arbitrary probe entry. Negatives are
		// low-value state (a wrong drop costs one revalidation), so no
		// recency bookkeeping is warranted.
		for id := range s.negOwners {
			delete(s.negOwners, id)
			break
		}
	}
	s.negOwners[sandfsID] = &ownerNegEntry{fetchedAt: time.Now().UnixNano()}
}

// ownerStoreLocked upserts a fetched POSITIVE resolution into the cache: the
// old entry (if any) is unlinked and replaced at the list front, and the new
// entry is pushed onto the expiry heap (the old entry's heap tuple dies by
// pointer mismatch when popped — lazy deletion). Caller MUST hold s.ownersMu
// (write) and must not pass a no-owner resolution.
func (s *DNSServer) ownerStoreLocked(sandfsID string, res ownerResolution) {
	if old, ok := s.owners[sandfsID]; ok {
		s.unlinkLocked(old)
	}
	now := time.Now().UnixNano()
	e := &ownerEntry{
		id:        sandfsID,
		gatewayID: res.gatewayID,
		nodeID:    res.nodeID,
		heapIdx:   -1, // set by the Push below
	}
	e.fetchedAt.Store(now)
	e.lastUsed.Store(now)
	s.owners[sandfsID] = e
	s.pushFrontLocked(e)
	heap.Push(&s.ownerExpiry, e)
}

// ownerEvictor periodically drops expired and overflow entries from the owners
// cache. Running eviction in the background (rather than on each insert) keeps
// the scan off the query hot path: inserts are O(1), hits are O(1).
func (s *DNSServer) ownerEvictor(ctx context.Context) {
	t := time.NewTicker(ownerEvictInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.evictOwners()
		}
	}
}

// ownerLRUGrace is the overflow-eviction protection window: an entry whose
// lastUsed is within this window is requeued to the list front instead of
// evicted (approximate LRU — hits do not move nodes, they only bump the
// atomic lastUsed; the evictor reconciles). A sandfs queried at least this
// often is never overflow-evicted, preserving the "actively-queried sandfs
// stay warm" property without a write lock on the hit path.
var ownerLRUGrace = 30 * time.Second

// evictOwners drops expired entries and, if the cache is over ownerLRUMax,
// the least-recently-used entries.
//
// Expiry is heap-driven (O(log N) per expired entry): a per-refresh min-heap
// ordered by fetchedAt is popped oldest-first — a full map scan per tick would
// hold the write lock for tens of milliseconds at the million-entry default
// cache size, stalling the RLock hit path once per second. Popped tuples that
// no longer match the live map entry (refetched → different object, or already
// evicted) are lazily discarded; the expiry decision itself reads the LIVE
// fetchedAt, so stale-while-error rollbacks (which defer a dying entry's
// expiry past an etcd outage) are honored — and because the rollback MOVES a
// live key, it re-heapifies through the entry's heapIdx, keeping the
// "root is the minimum" invariant the early break below relies on.
//
// The LRU overflow half is a map + intrusive doubly-linked list: insert and
// tail-eviction are each O(1).
//
// Caller-sensitive: takes the write lock for the whole pass.
func (s *DNSServer) evictOwners() {
	s.ownersMu.Lock()
	defer s.ownersMu.Unlock()
	now := time.Now().UnixNano()

	// Expiry: pop refresh records oldest-first; stop at the first live record
	// that is not yet expired (it is the heap minimum — nothing older hides
	// below it). Rolled-back entries are re-heapified at the moment their key
	// moves (see ownerFor), so this invariant holds exactly rather than
	// approximately: no expired entry can hide below a fresher one.
	for s.ownerExpiry.Len() > 0 {
		e := s.ownerExpiry[0]
		if now-e.fetchedAt.Load() <= int64(ownerCacheTTL) {
			break
		}
		heap.Pop(&s.ownerExpiry)
		if live, ok := s.owners[e.id]; ok && live == e {
			s.unlinkLocked(e)
			delete(s.owners, e.id)
		}
	}

	// Negative-cache sweep: a no-owner probe entry expires after its short
	// TTL, so the map needs no LRU (and never competes with the positive LRU).
	for id, ne := range s.negOwners {
		if now-ne.fetchedAt > int64(ownerNegCacheTTL) {
			delete(s.negOwners, id)
		}
	}

	// Presence cache sweep: bounded by the distinct nodeIDs seen within one
	// TTL (node count at any realistic scale); dirty/foreign nodeIDs age out
	// instead of accumulating.
	for id, pe := range s.presence {
		if now-pe.fetchedAt.Load() > int64(presenceCacheTTL) {
			delete(s.presence, id)
		}
	}

	// Overflow: bound memory by evicting from the list tail. Entries used
	// within ownerLRUGrace are requeued to the front once (hot entries are
	// protected; total requeue work per pass is bounded by the hits since the
	// previous pass); the requeued cap stops the loop when everything is warm
	// — over cap, the coldest-by-position still has to go.
	if len(s.owners) <= ownerLRUMax {
		return
	}
	graceStart := time.Now().Add(-ownerLRUGrace).UnixNano()
	for requeued := 0; len(s.owners) > ownerLRUMax; {
		s.lruInitLocked()
		tail := s.lruRoot.prev
		if tail == &s.lruRoot {
			break // list empty while map over cap (entries seeded unlinked)
		}
		if tail.lastUsed.Load() > graceStart && requeued < len(s.owners) {
			s.unlinkLocked(tail)
			s.pushFrontLocked(tail)
			requeued++
			continue
		}
		s.unlinkLocked(tail)
		delete(s.owners, tail.id)
	}
}

// ownerExpiryHeap is a min-heap of owner entries ordered by fetchedAt (the
// expiry clock), so evictOwners can expire oldest-first in O(log N) instead of
// scanning the whole map under the write lock. Tuples are immutable refresh
// records: a refetch pushes a NEW entry object and the old one's tuple is
// discarded at pop time by pointer mismatch (lazy deletion). Heap size is
// bounded by the refreshes within one TTL window (every tuple becomes poppable
// one TTL after its fetch). Guarded by ownersMu.
type ownerExpiryHeap []*ownerEntry

func (h ownerExpiryHeap) Len() int           { return len(h) }
func (h ownerExpiryHeap) Less(i, j int) bool { return h[i].fetchedAt.Load() < h[j].fetchedAt.Load() }
func (h ownerExpiryHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].heapIdx = i
	h[j].heapIdx = j
}
func (h *ownerExpiryHeap) Push(x any) {
	e := x.(*ownerEntry)
	e.heapIdx = len(*h)
	*h = append(*h, e)
}
func (h *ownerExpiryHeap) Pop() any {
	old := *h
	n := len(old)
	e := old[n-1]
	e.heapIdx = -1 // no live tuple any more
	*h = old[:n-1]
	return e
}

// lruInitLocked wires the sentinel for an empty list (idempotent).
// Caller MUST hold s.ownersMu (write).
func (s *DNSServer) lruInitLocked() {
	if s.lruRoot.next == nil || s.lruRoot.prev == nil {
		s.lruRoot.next = &s.lruRoot
		s.lruRoot.prev = &s.lruRoot
	}
}

// unlinkLocked removes e from the LRU list (no-op when not linked).
// Caller MUST hold s.ownersMu (write).
func (s *DNSServer) unlinkLocked(e *ownerEntry) {
	if !e.linked {
		return
	}
	e.prev.next = e.next
	e.next.prev = e.prev
	e.prev, e.next = nil, nil
	e.linked = false
}

// pushFrontLinked inserts e at the list front (most recent).
// Caller MUST hold s.ownersMu (write).
func (s *DNSServer) pushFrontLocked(e *ownerEntry) {
	s.lruInitLocked()
	e.prev = &s.lruRoot
	e.next = s.lruRoot.next
	s.lruRoot.next.prev = e
	s.lruRoot.next = e
	e.linked = true
}

// resolveSandfsOwner returns the gateway address that should serve a sandfs.
// Returns (cname, ip, ok, err): exactly one of cname/ip is non-empty when ok;
// err non-nil means ownership is UNKNOWN (etcd unreachable, nothing cached) and
// the caller must fail closed (SERVFAIL) — never fall back to scheduling on a
// maybe-owned sandfs.
//
// Owner-fresh path: the owner's health record is fresh (staleness within the
// route-stale threshold) → resolve owner.gateway_id → registry gateway_url
// (the /sandswap/gateway/{gw} plain key). A normally-alive owner (value
// refreshed every 5s, threshold 20s) is always fresh, so the hot path is
// unchanged: ownership is unchanged, only the owner can serve, route there.
// During an etcd outage a stale-known owner is served via ownerFor's
// stale-while-error; the health gate below is in-memory and still applies.
//
// Owner-stale/dead path: the owner's health record is stale past the threshold
// or absent (the owner gateway is dead or partitioned). The owner branch then:
//   - If the sandfs is mounted (node_id != "") and the node's presence key
//     names a DIFFERENT, fresh gateway (the sandlot reconnected to a live peer),
//     route to that peer — presence-directed routing. This is the recovery path
//     for "owner gateway died, sandlot migrated to a live gateway": the sandfs
//     is reachable again at the peer that now holds the node.
//   - Otherwise (idle sandfs, or presence still names the dead owner, or the
//     presence holder is itself stale) return ok=false → the scheduling
//     fallback picks a healthy gateway. The sandfs is genuinely unreachable
//     until ownership transfers (the gateway's time-protected CAS claim or the
//     reaper); rerouting to a random peer would only 503, so the fallback is
//     honest.
//
// The presence Get is a COLD path: it fires only when the owner is stale/dead
// (a dead-owned sandfs), never on the fresh-owner hot path. The owner's
// gateway_url is read from the plain registry key (survives death) so the
// fresh path works during tolerance exactly as before.
//
// sourceIP, when supplied, charges the etcd-bound owner lookup to that
// source's rate bucket; cached answers are unaffected.
func (s *DNSServer) resolveSandfsOwner(sandfsID string, sourceIP ...string) (cname, ip string, ok bool, err error) {
	res, oerr := s.ownerFor(sandfsID, sourceIP...)
	if oerr != nil {
		return "", "", false, oerr
	}
	if res.gatewayID == "" {
		return "", "", false, nil
	}

	s.mu.RLock()
	ownerFresh := s.gwAliveLocked(res.gatewayID)
	reg, haveReg := s.registryByID[res.gatewayID]
	s.mu.RUnlock()

	if ownerFresh {
		// NOTE: the owner branch deliberately does NOT check self-pressure
		// (or any load): owned sandfs must keep reaching their owner — affinity
		// and mount correctness trump placement optimization. Moving owned
		// sandfs off a struggling gateway is the load-shed's job (ownership
		// release), not routing's.
		if !haveReg || reg.gatewayURL == "" {
			return "", "", false, nil
		}
		cn, ip, gok := gatewayURLToCNAME(reg.gatewayURL)
		return cn, ip, gok, nil
	}

	// Owner stale/dead: try presence-directed routing to the gateway currently
	// holding the mounted node, if any.
	if res.nodeID != "" {
		if cn, ip, pok := s.presenceRoute(res.nodeID, res.gatewayID); pok {
			return cn, ip, true, nil
		}
	}
	// No live presence holder: fall through to the scheduling fallback.
	return "", "", false, nil
}

// presenceRoute reads the node's presence key (/sandswap/node/{id}/presence,
// value = the gateway_id currently holding the node) and, if it names a
// DIFFERENT, fresh, routable gateway, returns that gateway's address. Returns
// (addr, true) on success or (zero, false) to let the caller fall through. Cold
// path: only reached when the owner is stale/dead. The presence value is a bare
// gateway_id string (unchanged format).
//
// Bounded and cached: a TTL cache per nodeID collapses the common storm (one
// dead gateway owning many sandfs on the SAME mounted node) into ~one etcd Get
// per node per TTL, and the etcd Get itself shares ownerFor's concurrency
// semaphore — without these, every query on a dead-owned sandfs bypasses all
// of ownerFor's DoS bounds and the recovery window (exactly when the system is
// most fragile) becomes an etcd Get flood. On a busy semaphore the lookup
// falls through to the scheduling fallback (owner already judged dead; 503 +
// retry is the honest answer) so hot-owner revalidation keeps its priority.
func (s *DNSServer) presenceRoute(nodeID, deadOwnerGwID string) (cname, ip string, ok bool) {
	// Cache hit (fetch-fresh within presenceCacheTTL): the cached HOLDER is
	// re-judged below, so a holder that died within the TTL still falls
	// through — only the etcd round-trip is elided. Checked before the
	// nil-client gate: a hit depends on no etcd at all.
	now := time.Now().UnixNano()
	s.ownersMu.RLock()
	pe := s.presence[nodeID]
	if pe != nil && now-pe.fetchedAt.Load() < int64(presenceCacheTTL) {
		holder := pe.holder
		s.ownersMu.RUnlock()
		return s.presenceAnswer(holder, deadOwnerGwID)
	}
	s.ownersMu.RUnlock()

	if s.etcdClient == nil {
		return "", "", false
	}
	if s.ownerSem != nil {
		select {
		case s.ownerSem <- struct{}{}:
		default:
			return "", "", false // bounded: fall through to the scheduling fallback
		}
		defer func() { <-s.ownerSem }()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	resp, err := s.etcdClient.Get(ctx, "/sandswap/node/"+nodeID+"/presence", clientv3.WithSerializable())
	if err != nil {
		// Transport error: NOT cached — a blip must not pin "absent" for a
		// whole TTL and mis-route a recovering node.
		return "", "", false
	}
	holder := ""
	if len(resp.Kvs) > 0 {
		holder = string(resp.Kvs[0].Value)
	}
	s.ownersMu.Lock()
	if s.presence == nil {
		s.presence = make(map[string]*presenceCacheEntry)
	}
	pe = s.presence[nodeID]
	if pe == nil {
		pe = &presenceCacheEntry{}
		s.presence[nodeID] = pe
	}
	pe.holder = holder
	pe.fetchedAt.Store(time.Now().UnixNano())
	s.ownersMu.Unlock()
	return s.presenceAnswer(holder, deadOwnerGwID)
}

// presenceAnswer judges a presence holder (from etcd or the cache) against
// in-memory health + the gateway registry. Only the holder STRING is cached;
// the judgement never is.
func (s *DNSServer) presenceAnswer(holder, deadOwnerGwID string) (cname, ip string, ok bool) {
	if holder == "" || holder == deadOwnerGwID {
		return "", "", false // absent, empty, or still the dead owner → fall through
	}
	s.mu.RLock()
	fresh := s.gwAliveLocked(holder)
	reg, haveReg := s.registryByID[holder]
	s.mu.RUnlock()
	if !fresh || !haveReg || reg.gatewayURL == "" {
		return "", "", false // holder is itself stale/unroutable → fall through
	}
	return gatewayURLToCNAME(reg.gatewayURL)
}

// gatewayURLToCNAME turns a gateway_url into the (cname, ip, ok) DNS answer
// shape: an IP host → (ip); a name host → (cname). The host must be a valid
// A/CNAME target — a garbage self-registered gateway_url must yield ok=false
// (the caller falls back honestly), never a CNAME the client cannot resolve.
func gatewayURLToCNAME(gatewayURL string) (cname, ip string, ok bool) {
	host := gatewayURLHost(gatewayURL)
	if !validDNSHost(host) {
		return "", "", false
	}
	if net.ParseIP(host) != nil {
		return "", host, true
	}
	return host, "", true
}

// gatewayURLHost extracts the host from a base URL like "https://host:port".
func gatewayURLHost(u string) string {
	u = strings.TrimPrefix(u, "https://")
	u = strings.TrimPrefix(u, "http://")
	if host, _, err := net.SplitHostPort(u); err == nil {
		return host
	}
	if i := strings.IndexByte(u, '/'); i >= 0 {
		u = u[:i]
	}
	return u
}

// gwAliveLocked reports whether a registered gateway is alive AND its health
// record is fresh (not stale past the route-stale threshold). Used by placement
// and the owner branch for liveness: a gateway with no health record, or one
// whose value has gone stale past the threshold, is treated as not-alive (the
// health key is a plain key with no lease — death is judged purely by
// last_healthy_ts staleness, and the value timestamp lets routing reroute at
// the threshold instead of waiting for some binary flip). Registration
// (gwAddrs) decides candidacy; the health record decides aliveness. Caller MUST
// hold s.mu.
func (s *DNSServer) gwAliveLocked(gwID string) bool {
	h, ok := s.healthByID[gwID]
	if !ok {
		return false
	}
	return s.freshLocked(h)
}

// freshLocked reports whether a health record is fresh (staleness within the
// route-stale threshold). A record with no timestamp (legacy/old value) is
// treated as fresh — fail-alive on missing data, mirroring the gateway's
// ownerStaleness. Caller MUST hold s.mu.
func (s *DNSServer) freshLocked(h ownerHealth) bool {
	if h.lastHealthyTS.IsZero() {
		return true // no timestamp → trust the lease-key presence (fail-alive)
	}
	return time.Since(h.lastHealthyTS) <= s.routeStaleThreshold
}

// SetRouteStaleThreshold overrides the owner-branch staleness threshold. Tests
// shrink it to drive the state machine in seconds. Zero restores the default.
func (s *DNSServer) SetRouteStaleThreshold(d time.Duration) {
	s.mu.Lock()
	if d > 0 {
		s.routeStaleThreshold = d
	} else {
		s.routeStaleThreshold = defaultDNSRouteStaleThreshold
	}
	s.mu.Unlock()
}

// gwDutyLongLocked returns a gateway's aggregate duty_long from its
// /sandswap/load record (0 if none yet - treated as full headroom). Caller MUST
// hold s.mu (at least RLock).
func (s *DNSServer) gwDutyLongLocked(gwID string) float64 {
	if l, ok := s.loadByID[gwID]; ok {
		return l.aggDutyLong
	}
	return 0
}

// pickGatewayLocked selects a gateway_id per the routing policy among alive
// self-registered gateways: spread -> LOWEST agg_duty_long (headroom); binpack
// -> HIGHEST agg_duty_long (pack onto fewer gateways). requireStream selects
// the domain's address requirement: the stream domain needs a registered
// stream_addr; the agent domain needs a gateway_url host. Stream placement does
// NOT gate on compute or clean VMs - a compute-less gateway is still a valid
// sandlot target (the sandlot connecting brings compute back, no deadlock) -
// but duty_hard DOES gate both domains (binpack's whole backstop; without it a
// saturated gateway keeps absorbing every new sandlot).
// Caller MUST hold s.mu (at least RLock).
func (s *DNSServer) pickGatewayLocked(requireStream bool) string {
	binpack := s.preferHigherLoad()
	capDuty := s.dutyHard()
	bestID := ""
	bestDuty := math.MaxFloat64
	if binpack {
		bestDuty = -math.MaxFloat64
	}
	for gwID, info := range s.gwAddrs {
		if requireStream && info.StreamIP == "" {
			continue
		}
		if !requireStream && info.AgentIP == "" {
			continue
		}
		if !s.gwAliveLocked(gwID) {
			continue
		}
		// Saturation cap (both policies): no load record yet = bootstrap, not
		// excluded — same semantics as pickBySchedulingPolicy.
		if l, ok := s.loadByID[gwID]; ok && capDuty > 0 && l.aggDutyLong >= capDuty {
			continue
		}
		// Self-pressure gate (sustained gateway-process resource pressure):
		// same eligibility semantics as pickBySchedulingPolicy — a gateway
		// under self-pressure is not a placement target for stream/agent
		// placement either. Deliberately NOT applied to the owner branch,
		// presenceRoute, or sticky: owned sandfs must keep reaching their owner
		// (affinity/mount correctness), a presence holder is the only correct
		// answer for a mounted node, and sandlot stickiness survives pressure.
		if l, ok := s.loadByID[gwID]; ok && l.selfPressured {
			continue
		}
		duty := s.gwDutyLongLocked(gwID)
		if (binpack && duty > bestDuty) || (!binpack && duty < bestDuty) {
			bestDuty = duty
			bestID = gwID
		}
	}
	return bestID
}

// resolveAgent implements the legacy shared agent domain (sandswap.local).
// It returns the addresses of the best alive registered gateway via the same
// scheduling policy as stream, but without sticky (agent HTTP is stateless).
// With no registered gateways it returns nil (SERVFAIL) — registration is the
// only candidate source.
func (s *DNSServer) resolveAgent() *GWInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	best := s.pickGatewayLocked(false)
	if best == "" {
		return nil
	}
	info := s.gwAddrs[best]
	return &info
}

// resolveStream implements stream-domain routing: sticky + spread/binpack among
// alive registered gateways. A sandlot sticks to the gateway it used before
// (principle 6); the sticky record carries the gateway_id, so affinity
// survives a gateway restart that changes its IP (the answer uses the newly
// registered address). A dead sticky target is cleared and reselected.
func (s *DNSServer) resolveStream(clientIP string) *GWInfo {
	// Touch throttle window: refreshing LastQuery (a write-lock op) more often
	// than half the sync interval buys nothing — the etcd mirror is flushed at
	// sync cadence anyway.
	touchWindow := time.Duration(s.cfg.StickySyncInterval) * time.Second / 2
	if touchWindow < time.Second {
		touchWindow = time.Second
	}

	s.mu.RLock()

	// 1. Sticky hit + gateway alive (with a registered stream address) -> keep.
	if entry, ok := s.sticky[clientIP]; ok {
		info, registered := s.gwAddrs[entry.GWID]
		if registered && info.StreamIP != "" && s.gwAliveLocked(entry.GWID) {
			needTouch := entry.LastQuery < time.Now().Add(-touchWindow).Unix()
			s.mu.RUnlock()
			if needTouch {
				s.touchSticky(clientIP) // inline (was: a goroutine per hit)
			}
			return &info
		}
		s.mu.RUnlock()
		// Sticky target dead / unregistered -> clear sticky, reselect.
		s.mu.Lock()
		delete(s.sticky, clientIP)
		s.markStickyMirrorDeleteLocked(clientIP)
		s.mu.Unlock()
		s.mu.RLock()
	}

	// 2. Select by policy among alive gateways. The address is copied under
	// the SAME RLock as the pick (still held from above): releasing between
	// pick and read would let a concurrent registry event withdraw the winner's
	// address and hand the caller a zero GWInfo (which serializes as a junk
	// "CNAME .").
	best := s.pickGatewayLocked(true)
	var info GWInfo
	if best != "" {
		info = s.gwAddrs[best]
	}
	s.mu.RUnlock()
	if best == "" {
		return nil
	}
	s.mu.Lock()
	// Cap the sticky map: UDP DNS is unauthenticated, so a spoofed-source
	// flood could otherwise grow it (and its etcd mirror) without limit.
	// Overflow inserts evict via a bounded sample (see evictOneStickyLocked).
	if _, exists := s.sticky[clientIP]; !exists && len(s.sticky) >= stickyMax {
		s.evictOneStickyLocked()
	}
	s.sticky[clientIP] = &StickyEntry{
		GWID:      best,
		LastQuery: time.Now().Unix(),
		Created:   time.Now().Unix(),
	}
	s.markStickyDirtyLocked(clientIP)
	s.mu.Unlock()
	return &info
}

// markStickyDirtyLocked queues a Put for ip. When the queue is at its cap it
// first sweeps the strictly-droppable entries (gone from the live sticky map
// AND never mirrored — nothing to Put, nothing to Delete), so the queue
// tracks live sticky state instead of the flood's distinct-source count: live
// entries are at most stickyMax, so at the 2×stickyMax cap at least half the
// queue is droppable and each sweep removes ≥ half — amortized O(1) per mark,
// and the queue is bounded no matter how many spoofed sources arrive.
// Caller MUST hold s.mu (write).
func (s *DNSServer) markStickyDirtyLocked(ip string) {
	if len(s.dirty) >= 2*stickyMax {
		for k := range s.dirty {
			if _, live := s.sticky[k]; live {
				continue
			}
			if _, mirrored := s.mirrored[k]; mirrored {
				continue
			}
			delete(s.dirty, k)
		}
	}
	s.dirty[ip] = struct{}{}
}

// markStickyMirrorDeleteLocked queues an etcd Delete for ip — but ONLY if the
// IP ever reached etcd. An entry evicted/expired/cleared before any successful
// Put has no mirror to remove; queueing it would emit a pointless RPC per
// churned spoofed source and (under a flood above the flush rate) grow the
// dirty set without bound. Caller MUST hold s.mu (write).
func (s *DNSServer) markStickyMirrorDeleteLocked(ip string) {
	if s.mirrored == nil {
		return // nothing was ever mirrored
	}
	if _, ok := s.mirrored[ip]; ok {
		s.dirty[ip] = struct{}{}
	}
}

// noteStickyMirroredLocked records that ip now has a key in etcd. Caller MUST
// hold s.mu (write).
func (s *DNSServer) noteStickyMirroredLocked(ip string) {
	if s.mirrored == nil {
		s.mirrored = make(map[string]struct{})
	}
	s.mirrored[ip] = struct{}{}
}

// stickyEvictSample is the overflow-eviction sample size: when the sticky map
// is at its cap, eviction looks at this many random entries (a contiguous
// window of Go's randomized map iteration) and drops the least-recently-used
// among them. With fewer entries than the sample size the window is the whole
// map and eviction is exact; the strictly most-recent entry can NEVER be
// chosen (it is never the coldest of any sample — same-second ties may evict
// either, which is fine: they are equally warm).
const stickyEvictSample = 4

// evictOneStickyLocked removes one sticky entry to make room at the cap. The
// previous implementation scanned the whole map (O(stickyMax) ≈ 65536) under
// the write lock on EVERY overflow insert — a spoofed-source flood that keeps
// the map at the cap would serialize all stream resolutions behind that lock.
// Sampling makes the insert O(1) at a small quality cost (a warm entry inside
// an unlucky sample can lose; the client simply re-selects). Caller MUST hold
// s.mu (write).
func (s *DNSServer) evictOneStickyLocked() {
	var victimIP string
	var victim int64 = 1 << 62
	n := 0
	for ip, e := range s.sticky {
		if n++; n > stickyEvictSample {
			break
		}
		if e.LastQuery < victim {
			victim = e.LastQuery
			victimIP = ip
		}
	}
	if victimIP != "" {
		delete(s.sticky, victimIP)
		s.markStickyMirrorDeleteLocked(victimIP) // delete the mirror, if one exists
	}
}

// touchSticky asynchronously updates LastQuery.
func (s *DNSServer) touchSticky(clientIP string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if entry, ok := s.sticky[clientIP]; ok {
		entry.LastQuery = time.Now().Unix()
		s.markStickyDirtyLocked(clientIP)
	}
}

// ClearAllSticky removes all sticky records (on SIGHUP).
func (s *DNSServer) ClearAllSticky() {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := len(s.sticky)
	for ip := range s.sticky {
		s.markStickyMirrorDeleteLocked(ip)
	}
	s.sticky = make(map[string]*StickyEntry)
	log.Printf("Cleared all sticky records (%d entries)", n)
}

// loadStickyFromEtcd loads all sticky records from etcd on startup.
func (s *DNSServer) loadStickyFromEtcd() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := s.etcdClient.Get(ctx, "/sandswap/dns/sticky/", clientv3.WithPrefix())
	if err != nil {
		log.Printf("Warning: failed to load sticky from etcd: %v (starting fresh)", err)
		return
	}

	for _, kv := range resp.Kvs {
		s.adoptStickyRecord(string(kv.Key), kv.Value)
	}
	log.Printf("Loaded %d sticky records from etcd", len(s.sticky))
}

// adoptStickyRecord installs one etcd sticky record. A loaded record already
// HAS an etcd key, so it is registered in the mirror set: without that, its
// later expiry/clear queues no Delete (markStickyMirrorDeleteLocked is a no-op
// for unmirrored keys) and every restart leaks the expired keys in etcd
// forever. Returns false for a corrupt record.
func (s *DNSServer) adoptStickyRecord(key string, value []byte) bool {
	clientIP := strings.TrimPrefix(key, "/sandswap/dns/sticky/")
	var entry StickyEntry
	if err := json.Unmarshal(value, &entry); err != nil {
		log.Printf("Warning: invalid sticky entry for %s: %v", clientIP, err)
		return false
	}
	s.mu.Lock()
	s.sticky[clientIP] = &entry
	s.noteStickyMirroredLocked(clientIP)
	s.mu.Unlock()
	return true
}

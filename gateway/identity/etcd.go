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

package identity

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	rpctypes "go.etcd.io/etcd/api/v3/v3rpc/rpctypes"
	clientv3 "go.etcd.io/etcd/client/v3"
	"go.etcd.io/etcd/client/v3/concurrency"
	"golang.org/x/sync/singleflight"

	"common/util"
)

// ─────────────────────────────────────────────────────────────────────────────
// etcd key layout (all keys live under the store prefix, e.g. "/sandswap/identity/"):
//
//	agent/{api_key_hash}    → agent identity. Keyed by the SHA-256 hex digest of
//	                          the plaintext API key so a cold cache can resolve a
//	                          presented key with a single point Get (the plaintext
//	                          never leaves the caller; only the digest persists).
//	agentid/{agentID}       → ID-ownership index (→ api-key-hash). Makes an
//	                          agent-ID collision atomically claimable at create
//	                          (IDs are 32 random bits — pinned by the 32-bit egress IID field; collisions are real at
//	                          fleet scale); invisible to load/watch (undecodable).
//	sandfs/{sandfsID}       → hot sandfs record: everything the execution hot path
//	                          needs (owner, rootfs path, template/mode, min spec).
//	meta/sandfs/{sandfsID}  → display-only metadata (name, description, created_at).
//	                          Exec gateways run with HotOnly and never load/watch
//	                          this space, cutting the hot-path working set.
//	lock/{resource}         → distributed lock keys for cross-gateway CRUD.
//
// The hot/cold split keeps the resident cache proportional to what request
// serving actually reads, which matters at hundreds-of-thousands-plus sandfs.
// ─────────────────────────────────────────────────────────────────────────────

const (
	// Default loader knobs. The parallel paginated loader reads disjoint key
	// ranges concurrently; each page is far below etcd's request-size limits
	// even when the total dataset reaches millions of records.
	defaultLoadPageSize    = 1000
	defaultLoadWorkers     = 16
	defaultFullLoadTimeout = 120 * time.Second

	// Lazy load-back defaults. A cache miss triggers a point Get against etcd;
	// these bounds stop an authenticated-but-misbehaving client from turning
	// that into unbounded read pressure.
	lazyNegativeTTL     = 3 * time.Second
	lazyNegativeCap     = 10000
	lazyFetchRatePerSec = 50
	// lazyGlobalFetchPerSec caps the TOTAL backfill rate across all keys, so an
	// attacker rotating many distinct invalid keys (each within its per-key
	// budget) cannot multiply that into unbounded etcd read pressure. Defense
	// in depth on top of the per-key limiter; the primary guard is lazy-load
	// being off by default on exec gateways.
	lazyGlobalFetchPerSec = 200
)

// EtcdOption configures optional EtcdStore behavior.
type EtcdOption func(*etcdSettings)

type etcdSettings struct {
	tls             *EtcdTLSConfig
	hotOnly         bool
	lazyLoad        bool
	loadPageSize    int
	loadWorkers     int
	fullLoadTimeout time.Duration
	recordWatcher   func(sandfsID, newStatus string)
}

func newEtcdSettings(opts []EtcdOption) *etcdSettings {
	s := &etcdSettings{
		hotOnly:         false,
		lazyLoad:        true,
		loadPageSize:    defaultLoadPageSize,
		loadWorkers:     defaultLoadWorkers,
		fullLoadTimeout: defaultFullLoadTimeout,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// WithTLS sets client TLS material (CA bundle, optional mTLS cert/key).
func WithTLS(cfg *EtcdTLSConfig) EtcdOption {
	return func(s *etcdSettings) { s.tls = cfg }
}

// WithHotOnly skips loading and watching the display metadata space
// (meta/sandfs/*). Exec gateways should enable this: name/description are
// human-API fields the exec path never reads.
func WithHotOnly(enabled bool) EtcdOption {
	return func(s *etcdSettings) { s.hotOnly = enabled }
}

// WithLazyLoad enables on-demand point Gets for cache misses (default on).
// When disabled, a miss returns not-found without contacting etcd — the cache
// is served strictly from the startup snapshot plus watch events.
func WithLazyLoad(enabled bool) EtcdOption {
	return func(s *etcdSettings) { s.lazyLoad = enabled }
}

// WithLoadPageSize overrides the per-page key count of the parallel loader.
func WithLoadPageSize(n int) EtcdOption {
	return func(s *etcdSettings) {
		if n > 0 {
			s.loadPageSize = n
		}
	}
}

// WithLoadWorkers overrides the parallel loader concurrency.
func WithLoadWorkers(n int) EtcdOption {
	return func(s *etcdSettings) {
		if n > 0 {
			s.loadWorkers = n
		}
	}
}

// WithFullLoadTimeout overrides the context deadline for one full-load pass
// (initial startup and watch-recovery rebuilds alike).
func WithFullLoadTimeout(d time.Duration) EtcdOption {
	return func(s *etcdSettings) {
		if d > 0 {
			s.fullLoadTimeout = d
		}
	}
}

// WithRecordWatcher installs a callback fired on every WATCHED sandfs-record
// status change (id + new status; "" = active). The exec gateway uses it as
// the split-mode drain trigger: seeing "detaching"/"deleting" for a sandfs it
// holds makes it run the drain and write "detached". Fires on this gateway's
// own writes too (etcd echoes them) — the drain is idempotent, so the echo is
// a harmless no-op. Missed events (this process was offline) are compensated
// by NotifyInitialStatuses after startup.
func WithRecordWatcher(fn func(sandfsID, newStatus string)) EtcdOption {
	return func(s *etcdSettings) { s.recordWatcher = fn }
}

// EtcdTLSConfig holds the paths to TLS certificates for the etcd client.
// If all fields are empty, the client uses plaintext (no TLS).
// If Endpoints use https://, TLS is required.
type EtcdTLSConfig struct {
	CAFile   string // CA bundle to verify the etcd server cert (enables server verification)
	CertFile string // Client certificate for mTLS (optional — set if etcd requires client certs)
	KeyFile  string // Client private key (required if CertFile is set)
}

// buildEtcdTLSConfig constructs a *tls.Config from EtcdTLSConfig.
// Returns nil if no TLS config is provided (plaintext mode).
func buildEtcdTLSConfig(cfg *EtcdTLSConfig) (*tls.Config, error) {
	if cfg == nil || (cfg.CAFile == "" && cfg.CertFile == "" && cfg.KeyFile == "") {
		return nil, nil
	}

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	// Load CA bundle for server verification.
	if cfg.CAFile != "" {
		caData, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read etcd CA file %s: %w", cfg.CAFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caData) {
			return nil, fmt.Errorf("no valid certs in etcd CA file %s", cfg.CAFile)
		}
		tlsConfig.RootCAs = pool
	}

	// Load client certificate for mTLS.
	if cfg.CertFile != "" {
		if cfg.KeyFile == "" {
			return nil, fmt.Errorf("etcd client cert specified but no key file")
		}
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("load etcd client cert: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	return tlsConfig, nil
}

// hashAPIKey returns the hex-encoded SHA-256 digest of an agent API key.
// Only digests are persisted in etcd and held in the in-memory index; the
// plaintext exists at creation time and is returned to the operator exactly
// once. Resolution compares digests in constant time.
func hashAPIKey(apiKey string) string {
	sum := sha256.Sum256([]byte(apiKey))
	return hex.EncodeToString(sum[:])
}

// EtcdStore implements Store backed by etcd with a local in-memory cache.
// Used in multi-node deployments where multiple gateway instances share state.
//
// Architecture:
//   - Local cache: in-process maps for hot-path ResolveAgent/GetSandFS (identical
//     latency to MemoryStore). Populated at startup by a parallel paginated
//     snapshot load, then kept current by watch events.
//   - Parallel snapshot load: disjoint key segments (per top-level directory,
//     with the sandfs space bucketed by ID character) are paged concurrently
//     from one cluster revision, so startup cost stays flat as the record count
//     grows into the millions. The finished snapshot replaces the live maps in
//     a single lock hold; readers keep using the previous snapshot meanwhile.
//   - Write-during-load journal: local writes that commit while a background
//     reload is building its snapshot are recorded and re-fetched after the
//     swap, so they can never be rolled back by the rebuilt snapshot.
//   - Watch sync: etcd watch delivers PUT/DELETE events → cache updates with
//     ~2-10ms propagation delay. A plain disconnect replays from the last seen
//     revision without any reload; only a compacted revision forces a rebuild.
//   - Lazy load-back (optional, default on): a cache miss performs a point Get
//     against etcd (singleflight-collapsed, rate-limited per key, with a short
//     negative cache). Disable for strictly snapshot-served behavior.
//   - Distributed locks: etcd lease-based mutex for CreateAgent/DeleteAgent/
//     CreateSandFS/DeleteSandFS to prevent concurrent writes across gateways.
//   - Graceful degradation: if etcd is unreachable, the cache serves stale
//     data. New agent/sandfs creation fails fast; existing sandfs continue working.
type EtcdStore struct {
	client *clientv3.Client
	prefix string // etcd key prefix, e.g., "/sandswap/identity/"
	logger *slog.Logger

	// Settings.
	hotOnly         bool          // skip the meta/sandfs/* display-metadata space
	lazyLoad        bool          // point-Get backfill for cache misses
	loadPageSize    int           // keys per page in the parallel loader
	loadWorkers     int           // concurrency of the parallel loader
	fullLoadTimeout time.Duration // deadline for one full-load pass

	// Live cache. Guarded by mu. Replaced wholesale by fullLoad (copy-on-write
	// snapshot swap) or updated incrementally by watch events and local writes.
	mu              sync.RWMutex
	agents          map[string]*Agent              // agentID → agent
	agentApiKeyToID map[string]string              // api_key_hash → agentID
	sandfs          map[string]*Record             // sandfsID → hot record
	sandfsMeta      map[string]*sandfsMetaInfo     // sandfsID → display metadata (absent when hotOnly)
	sandfsByAgent   map[string]map[string]struct{} // agentID → set of sandfsIDs (reverse index)

	volRoot string // shared storage mount (for ref in error messages)

	// Full-load coordination.
	loading     bool     // a snapshot rebuild is in progress (write paths journal)
	pendingKeys []string // etcd keys mutated locally during the rebuild
	ready       atomic.Bool

	// Lazy load-back machinery.
	sf          singleflight.Group
	neg         negativeCache
	limiter     fetchLimiter       // per-key backfill rate (bounds one hot key)
	globalLimit globalFetchLimiter // total backfill rate across ALL keys (DoS cap)

	// Watch state.
	watchRev     int64 // last processed revision
	watchDone    chan struct{}
	watchStopped chan struct{} // closed when watchLoop has exited
	closeOnce    sync.Once

	// recordWatcher (optional) is fired on watched sandfs-record status
	// changes — see WithRecordWatcher. Read-only after NewEtcdStore.
	recordWatcher func(sandfsID, newStatus string)
}

// NewEtcdStore creates an EtcdStore, loads a consistent cache snapshot
// from etcd (parallel paginated load), and starts the watch sync loop.
//
// tlsCfg is optional — pass nil for plaintext (dev only). For production,
// provide CAFile + CertFile + KeyFile for mTLS (etcd --client-cert-auth).
// Functional options adjust hot-only mode, lazy load-back, and loader tuning.
func NewEtcdStore(etcdEndpoints []string, prefix, volRoot string, tlsCfg *EtcdTLSConfig, logger *slog.Logger, opts ...EtcdOption) (*EtcdStore, error) {
	settings := newEtcdSettings(opts)
	if tlsCfg != nil && settings.tls == nil {
		settings.tls = tlsCfg
	}
	if logger == nil {
		logger = slog.Default()
	}

	// Build TLS config for the etcd client.
	var etcdTLS *tls.Config
	if settings.tls != nil {
		var err error
		etcdTLS, err = buildEtcdTLSConfig(settings.tls)
		if err != nil {
			return nil, fmt.Errorf("etcd TLS config: %w", err)
		}
		// Pin the TLS ServerName to the etcd endpoint host. With a headless etcd
		// Service the FQDN resolves to a pod IP; grpc/etcd's resolver may then
		// present the IP as the TLS authority, which fails verification (the
		// etcd cert carries the FQDN, not the pod IP). Setting ServerName
		// explicitly makes TLS verify against the FQDN regardless of what the
		// resolver dialed.
		if etcdTLS != nil && etcdTLS.ServerName == "" && len(etcdEndpoints) > 0 {
			if host, _, err := net.SplitHostPort(strings.TrimPrefix(etcdEndpoints[0], "https://")); err == nil {
				etcdTLS.ServerName = host
			} else if u := etcdEndpoints[0]; !strings.Contains(u, "://") {
				etcdTLS.ServerName = strings.Split(u, ":")[0]
			}
		}
	}

	clientCfg := clientv3.Config{
		Endpoints:   etcdEndpoints,
		DialTimeout: 5 * time.Second,
		TLS:         etcdTLS,
	}

	cli, err := clientv3.New(clientCfg)
	if err != nil {
		return nil, fmt.Errorf("etcd client: %w", err)
	}

	s := &EtcdStore{
		client:          cli,
		prefix:          prefix,
		logger:          logger,
		hotOnly:         settings.hotOnly,
		lazyLoad:        settings.lazyLoad,
		loadPageSize:    settings.loadPageSize,
		loadWorkers:     settings.loadWorkers,
		fullLoadTimeout: settings.fullLoadTimeout,
		agents:          make(map[string]*Agent),
		agentApiKeyToID: make(map[string]string),
		sandfs:          make(map[string]*Record),
		sandfsMeta:      make(map[string]*sandfsMetaInfo),
		sandfsByAgent:   make(map[string]map[string]struct{}),
		watchDone:       make(chan struct{}),
		watchStopped:    make(chan struct{}),
		// The negative cache is INERT unless ttl/cap are set: put() stores
		// now+ttl (0 = instantly expired) and the len>=cap guard (0) wipes the
		// map on every insert, so every repeated lookup of an absent key issued
		// a fresh etcd Get. Initialize it from the documented constants.
		neg: negativeCache{
			entries: make(map[string]time.Time),
			ttl:     lazyNegativeTTL,
			cap:     lazyNegativeCap,
		},
		recordWatcher: settings.recordWatcher,
	}

	// Initial snapshot load. Blocks until the cache is consistent with etcd;
	// callers gate traffic readiness on Ready().
	if err := s.runFullLoad(context.Background()); err != nil {
		cli.Close()
		return nil, fmt.Errorf("initial etcd load: %w", err)
	}
	s.ready.Store(true)

	s.logger.Info("etcd identity store initialized",
		"prefix", prefix,
		"agents", len(s.agents),
		"sandfs", len(s.sandfs),
		"hotOnly", s.hotOnly,
		"lazyLoad", s.lazyLoad,
		"revision", s.watchRev,
	)

	// Start the watch loop (background goroutine).
	go s.watchLoop()

	return s, nil
}

// Close stops the watch loop and closes the etcd client.
// Close stops the watch loop and closes the etcd client. Idempotent (safe to
// call multiple times): a sync.Once guards the watchDone close so a repeat call
// does not panic on double-close. It waits for watchLoop to observe the signal
// and return before closing the client, so the loop never operates on a closed
// client (which would log spurious errors).
func (s *EtcdStore) Close() {
	s.closeOnce.Do(func() {
		close(s.watchDone)
	})
	// Wait for watchLoop to exit before tearing down the client it uses.
	// Bounded: watchLoop checks watchDone at the top of each iteration and on
	// every watch-response error, so it returns promptly.
	select {
	case <-s.watchStopped:
	case <-time.After(5 * time.Second):
		// Fallback so Close never blocks indefinitely if the loop is stuck in a
		// long full-load rebuild; the client close will unblock it.
	}
	s.client.Close()
}

// Client returns the underlying etcd client so other subsystems (e.g. the
// lease.OwnershipCache) can share the same connection instead of opening a
// second one. The returned client is owned by the store and is closed by
// Close(); callers must not close it.
func (s *EtcdStore) Client() *clientv3.Client {
	return s.client
}

// Ready reports whether the store has completed its initial snapshot load.
// HTTP readiness endpoints should gate agent traffic on this.
func (s *EtcdStore) Ready() bool {
	return s.ready.Load()
}

// ── Key helpers ─────────────────────────────────────────────────

func (s *EtcdStore) agentKeyFor(apiKeyHash string) string {
	return s.prefix + "agent/" + apiKeyHash
}

// agentIDKeyFor is the agent-ID ownership index: agentid/<id> → api-key-hash.
// Agent records live under agent/<api-key-hash> (the hot auth path), so this
// index is what makes an agent-ID collision claimable in one atomic Txn —
// CreateAgent creates it alongside the record and DeleteAgent removes both.
// Readers ignore the prefix (decodeAgent of a hash string fails → skipped),
// so it is invisible to snapshot load, watch, and journal replay.
func (s *EtcdStore) agentIDKeyFor(agentID string) string {
	return s.prefix + "agentid/" + agentID
}

func (s *EtcdStore) sandfsKeyFor(sandfsID string) string {
	return s.prefix + "sandfs/" + sandfsID
}

func (s *EtcdStore) sandfsMetaKeyFor(sandfsID string) string {
	return s.prefix + "meta/sandfs/" + sandfsID
}

func (s *EtcdStore) tombstoneKeyFor(sandfsID string) string {
	return s.prefix + "tombstone/" + sandfsID
}

// putTombstone remembers a deleted sandfs id for TombstoneTTL so a 32-bit id
// redraw cannot immediately resurrect a name whose old record may still sit in
// a lagging gateway's watch cache. Used by BOTH delete paths (single sandfs and
// the agent batch delete — the batch path used to skip it, leaving a reuse gap
// exactly where an agent deletion removes many ids at once). A dedicated lease
// lets the tombstone expire; if the grant fails, a plain key is used (permanent,
// still safe).
func (s *EtcdStore) putTombstone(ctx context.Context, sandfsID string) {
	tombKey := s.tombstoneKeyFor(sandfsID)
	value := time.Now().UTC().Format(time.RFC3339Nano)
	if lease, lerr := s.client.Grant(ctx, int64(TombstoneTTL().Seconds())); lerr == nil {
		if _, perr := s.client.Put(ctx, tombKey, value, clientv3.WithLease(lease.ID)); perr != nil {
			slog.Warn("sandfs tombstone put failed (id reuse remains guarded by the volume epoch)", "sandfs_id", sandfsID, "error", perr)
		}
		return
	}
	if _, perr := s.client.Put(ctx, tombKey, value); perr != nil {
		slog.Warn("sandfs tombstone put failed (id reuse remains guarded by the volume epoch)", "sandfs_id", sandfsID, "error", perr)
	}
}

func (s *EtcdStore) lockKeyFor(resource string) string {
	return s.prefix + "lock/" + resource
}

// ── Agent auth (connection-level) ──────────────────────────────

// ResolveAgent validates an Agent API key and returns the Agent.
// Hot path: local cache lookup keyed by the key's digest + constant-time
// compare (identical semantics to MemoryStore). With lazy load enabled, a
// miss falls back to a singleflight-collapsed point Get against etcd — this
// covers agents created moments ago on another gateway whose watch event has
// not landed yet, and keeps auth working through brief watch outages.
func (s *EtcdStore) ResolveAgent(apiKey string) (*Agent, error) {
	hash := hashAPIKey(apiKey)

	s.mu.RLock()
	id, ok := s.agentApiKeyToID[hash]
	var agent *Agent
	if ok {
		agent = s.agents[id]
	}
	s.mu.RUnlock()

	if ok && agent != nil {
		if subtle.ConstantTimeCompare([]byte(hash), []byte(agent.APIKeyHash)) != 1 {
			return nil, fmt.Errorf("invalid api key")
		}
		return cloneAgent(agent), nil
	}

	if !s.lazyLoad {
		return nil, fmt.Errorf("invalid api key")
	}
	// Global cap first: bounds total backfill pressure across all keys (DoS
	// defense), then the per-key cap bounds a single hot key.
	if !s.globalLimit.allow() || !s.limiter.allow("agent:"+hash) {
		return nil, fmt.Errorf("invalid api key")
	}
	if s.neg.get(s.agentKeyFor(hash)) {
		return nil, fmt.Errorf("invalid api key")
	}

	loaded, err, _ := s.sf.Do("agent/"+hash, func() (any, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		resp, err := s.client.Get(ctx, s.agentKeyFor(hash))
		if err != nil {
			return nil, err
		}
		if len(resp.Kvs) == 0 {
			s.neg.put(s.agentKeyFor(hash))
			return nil, nil
		}
		agent := decodeAgent(resp.Kvs[0].Value)
		if agent == nil {
			return nil, fmt.Errorf("corrupt agent record in etcd")
		}
		s.mu.Lock()
		// Never let a lazy backfill roll the cache BACKWARDS: the Get returned
		// a snapshot at resp revision, and the watch may already have applied a
		// newer write for this key (watchRev >= Get revision). Overwriting then
		// would serve the stale copy until the next unrelated event.
		if resp.Header.Revision >= s.watchRev {
			s.applyAgentPutLocked(agent)
		}
		s.mu.Unlock()
		return agent, nil
	})
	if err != nil {
		// etcd unreachable: surface as invalid rather than a 500 so behavior
		// matches the degraded-cache contract (stale cache serves, misses fail).
		return nil, fmt.Errorf("invalid api key")
	}
	resolved, ok := loaded.(*Agent)
	if !ok || resolved == nil {
		return nil, fmt.Errorf("invalid api key")
	}
	return cloneAgent(resolved), nil
}

// ── SandFS operations (request-level) ──────────────────────────

// GetSandFS returns a fully-populated Record by sandfs ID.
// Hot path: local cache lookup with display metadata merged in. With lazy
// load enabled, a miss falls back to a point Get against etcd (collapsed by
// singleflight, rate-limited per key, negative-cached for absent IDs).
func (s *EtcdStore) GetSandFS(sandfsID string) (*Record, error) {
	s.mu.RLock()
	rec := s.sandfs[sandfsID]
	if rec != nil {
		cp := *rec
		s.mu.RUnlock()
		return s.mergeMetaLazy(&cp), nil
	}
	s.mu.RUnlock()

	if !s.lazyLoad {
		return nil, fmt.Errorf("%w: %s", ErrSandFSNotFound, sandfsID)
	}
	if !s.globalLimit.allow() || !s.limiter.allow("sandfs:"+sandfsID) {
		// A rate-limited read is NOT "the record is missing": a destructive
		// caller must fail closed, never treat the limit as proof of absence.
		return nil, fmt.Errorf("sandfs lookup temporarily limited: %s", sandfsID)
	}

	key := s.sandfsKeyFor(sandfsID)
	if s.neg.get(key) {
		return nil, fmt.Errorf("%w: %s", ErrSandFSNotFound, sandfsID)
	}

	loaded, err, _ := s.sf.Do("sandfs/"+sandfsID, func() (any, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		resp, err := s.client.Get(ctx, key)
		if err != nil {
			return nil, err
		}
		if len(resp.Kvs) == 0 {
			s.neg.put(key)
			return nil, nil
		}
		rec := decodeSandfsRecord(resp.Kvs[0].Value)
		if rec == nil {
			return nil, fmt.Errorf("corrupt sandfs record in etcd")
		}
		s.mu.Lock()
		// A watch event at or past the Get's revision may already have landed a
		// fresher copy (status transitions in particular): a blind backfill
		// would overwrite it with the older snapshot and keep serving stale
		// lifecycle state until the next write.
		if resp.Header.Revision >= s.watchRev {
			s.applySandfsPutLocked(rec)
		}
		s.mu.Unlock()
		// Display metadata is best-effort on the backfill path.
		if !s.hotOnly {
			s.fetchAndApplyMeta(sandfsID)
		}
		return rec, nil
	})
	if err != nil {
		return nil, fmt.Errorf("sandfs lookup failed: %w", err)
	}
	rec, _ = loaded.(*Record)
	if rec == nil {
		return nil, fmt.Errorf("%w: %s", ErrSandFSNotFound, sandfsID)
	}
	return s.mergeMetaLazy(rec), nil
}

// ListSandFSByAgent returns all SandFS records owned by an agent.
// Uses the sandfsByAgent reverse index for O(K) where K is the agent's sandfs
// count (typically 1-5), not O(N) scanning all sandfs (10K+ scalability).
func (s *EtcdStore) ListSandFSByAgent(agentID string) ([]*Record, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	sandfsIDs := s.sandfsByAgent[agentID]
	recs := make([]*Record, 0, len(sandfsIDs))
	for id := range sandfsIDs {
		if rec := s.sandfs[id]; rec != nil {
			recs = append(recs, s.mergeMetaLocked(rec))
		}
	}
	return recs, nil
}

// metaCacheMaxEntries bounds the display-meta cache. Display data is
// no longer part of the full load: the human gateway lazily point-fetches it per
// record and keeps a small bounded cache; the watch refreshes resident entries
// without growing the map.
const metaCacheMaxEntries = 8192

// metaCachePutLocked stores display meta under a hard entry cap (arbitrary
// eviction — display data is refetchable; LRU ordering buys nothing here).
// Caller holds Lock.
func (s *EtcdStore) metaCachePutLocked(id string, m *sandfsMetaInfo) {
	if s.sandfsMeta == nil || m == nil {
		return
	}
	if _, exists := s.sandfsMeta[id]; !exists && len(s.sandfsMeta) >= metaCacheMaxEntries {
		for k := range s.sandfsMeta {
			delete(s.sandfsMeta, k)
			break
		}
	}
	s.sandfsMeta[id] = m
}

// metaForRecord resolves display metadata for one record: bounded cache
// first, else one point Get (cold path — human gateway only). hotOnly stores
// never fetch: the exec plane serves hot records with zero display IO,
// exactly as before (the fix must not touch the exec path).
// Best-effort: on any error the record serves without display fields.
func (s *EtcdStore) metaForRecord(id string) *sandfsMetaInfo {
	if s.hotOnly || s.client == nil {
		return nil
	}
	s.mu.RLock()
	m := s.sandfsMeta[id]
	s.mu.RUnlock()
	if m != nil {
		return m
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	resp, err := s.client.Get(ctx, s.sandfsMetaKeyFor(id))
	if err != nil || len(resp.Kvs) == 0 {
		return nil
	}
	m = decodeSandfsMeta(resp.Kvs[0].Value)
	if m == nil {
		return nil
	}
	s.mu.Lock()
	s.metaCachePutLocked(id, m)
	s.mu.Unlock()
	return m
}

// applyDisplay overlays one meta onto a record (the merge rule shared by the
// cache-only and lazy paths).
func applyDisplay(cp *Record, m *sandfsMetaInfo) {
	cp.Name = m.Name
	cp.Description = m.Description
	if t, err := time.Parse(time.RFC3339Nano, m.CreatedAt); err == nil {
		cp.CreatedAt = t
	}
}

// mergeMetaLazy is the per-record read-path merge (GetSandFS et al): cache hit
// or one point fetch. The record must be caller-private (copied) when it came
// from the shared cache.
func (s *EtcdStore) mergeMetaLazy(rec *Record) *Record {
	if m := s.metaForRecord(rec.ID); m != nil {
		applyDisplay(rec, m)
	}
	return rec
}

// mergeMetaLocked overlays CACHED display metadata onto a hot record copy
// (mass-iteration paths: no per-record IO under a lock). Records without a
// resident cache entry serve hot fields only. Caller holds at least RLock.
func (s *EtcdStore) mergeMetaLocked(rec *Record) *Record {
	cp := *rec
	if m := s.sandfsMeta[rec.ID]; m != nil {
		applyDisplay(&cp, m)
	}
	return &cp
}

// ── Agent CRUD (human interface) ───────────────────────────────

// sandfsMetaInfo is display-only metadata for a sandfs: stored under
// meta/sandfs/{id}, never loaded by HotOnly exec gateways, and merged into
// returned Records for human-API consumers.
type sandfsMetaInfo struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	CreatedAt   string `json:"created_at"`
}

// etcdAgentJSON is the on-disk format for agents in etcd.
// Only the API key DIGEST is persisted — the plaintext exists at creation
// time and is returned to the operator exactly once. The digest doubles as
// the etcd key suffix so a cold cache can resolve a presented key directly.
type etcdAgentJSON struct {
	AgentID     string `json:"agent_id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	APIKeyHash  string `json:"api_key_hash"`
	CreatedAt   string `json:"created_at"`
	// Namespace rides the agent record so the human gateway's watch-fed cache
	// can route per-namespace listing and the uniform-404 check without a
	// per-record fetch. omitempty: pre-namespace rows decode with "" and are
	// normalized on read (Agent.NamespaceOrDefault).
	Namespace string `json:"namespace,omitempty"`
}

// marshalAgentForEtcd serializes an Agent for etcd storage (digest only).
func marshalAgentForEtcd(a *Agent) ([]byte, error) {
	hash := a.APIKeyHash
	if hash == "" && a.APIKey != "" {
		hash = hashAPIKey(a.APIKey)
	}
	return json.Marshal(&etcdAgentJSON{
		AgentID:     a.ID,
		Name:        a.Name,
		Description: a.Description,
		APIKeyHash:  hash,
		CreatedAt:   a.CreatedAt.Format(time.RFC3339Nano),
		Namespace:   a.Namespace,
	})
}

// decodeAgent deserializes an Agent from etcd storage. The plaintext key is
// unrecoverable (by design); APIKey stays empty and APIKeyHash is set.
func decodeAgent(data []byte) *Agent {
	var ej etcdAgentJSON
	if err := json.Unmarshal(data, &ej); err != nil {
		return nil
	}
	createdAt, _ := time.Parse(time.RFC3339Nano, ej.CreatedAt)
	return &Agent{
		ID:          ej.AgentID,
		Name:        ej.Name,
		Description: ej.Description,
		APIKeyHash:  ej.APIKeyHash,
		CreatedAt:   createdAt,
		Namespace:   ej.Namespace,
	}
}

// etcdSandfsJSON is the on-disk HOT record: only fields the execution path
// reads. Display metadata lives separately under meta/sandfs/{id}.
type etcdSandfsJSON struct {
	SandfsID    string `json:"sandfs_id"`
	AgentID     string `json:"agent_id"`
	RootFSPath  string `json:"rootfs_path,omitempty"`
	VolumeEpoch string `json:"volume_epoch,omitempty"`
	Template    string `json:"template,omitempty"`
	Mode        string `json:"mode,omitempty"`
	MinVCPUs    uint32 `json:"min_vcpus,omitempty"`
	MinMemoryMB uint64 `json:"min_memory_mb,omitempty"`
	// Status is the lifecycle gate (""/detaching/detached/deleting). It MUST
	// ride the hot record: the exec gateway's execution gate AND the
	// split-mode drain trigger both read it off the watch stream — dropping
	// it here would silently disable both (a MemoryStore round-trip cannot
	// catch this; the wire shape is the contract).
	Status string `json:"status,omitempty"`
	// Namespace rides the hot record for the same reason as on the agent
	// record: the human gateway's per-namespace listing and uniform-404
	// check read the watch-fed cache, which is built from hot records only.
	// The exec plane ignores the field.
	Namespace string `json:"namespace,omitempty"`
}

// encodeSandfsRecord extracts the hot subset of a Record for etcd storage.
func encodeSandfsRecord(rec *Record) ([]byte, error) {
	return json.Marshal(&etcdSandfsJSON{
		SandfsID:    rec.ID,
		AgentID:     rec.AgentID,
		RootFSPath:  rec.RootFSPath,
		VolumeEpoch: rec.VolumeEpoch,
		Template:    rec.Template,
		Mode:        rec.Mode,
		MinVCPUs:    rec.MinVCPUs,
		MinMemoryMB: rec.MinMemoryMB,
		Status:      rec.Status,
		Namespace:   rec.Namespace,
	})
}

// decodeSandfsRecord parses the hot record subset into a Record.
func decodeSandfsRecord(data []byte) *Record {
	var ej etcdSandfsJSON
	if err := json.Unmarshal(data, &ej); err != nil {
		return nil
	}
	return &Record{
		ID:          ej.SandfsID,
		AgentID:     ej.AgentID,
		RootFSPath:  ej.RootFSPath,
		VolumeEpoch: ej.VolumeEpoch,
		Template:    ej.Template,
		Mode:        ej.Mode,
		MinVCPUs:    ej.MinVCPUs,
		MinMemoryMB: ej.MinMemoryMB,
		Status:      ej.Status,
		Namespace:   ej.Namespace,
	}
}

// encodeSandfsMeta serializes display metadata for etcd storage.
func encodeSandfsMeta(meta *sandfsMetaInfo) ([]byte, error) {
	return json.Marshal(meta)
}

// decodeSandfsMeta parses display metadata from etcd storage.
func decodeSandfsMeta(data []byte) *sandfsMetaInfo {
	var m sandfsMetaInfo
	if err := json.Unmarshal(data, &m); err != nil {
		return nil
	}
	return &m
}

// CreateAgent creates a new Agent with a unique ID and API key.
// Uses an etcd distributed lock to prevent concurrent creates across gateways.
// The ID's 8-hex suffix is 32 random bits (pinned by the egress IID field): collisions are rare but real at
// fleet scale (birthday bound ~77k agents at 50%), and two API keys mapping
// to one agent ID is exactly the identity ambiguity this store must prevent —
// so the create CLAIMS the ID atomically (create-only Txn on the ID-ownership
// index, agentid/<id> → api-key-hash) and regenerates on collision instead of
// overwriting or failing. The local cache cannot serve as the check: it can
// lag a concurrent create's watch event on another gateway; etcd cannot.
func (s *EtcdStore) CreateAgent(req CreateAgentRequest) (*Agent, string, error) {
	desc := strings.TrimSpace(req.Description)
	if err := ValidateDescription(desc); err != nil {
		return nil, "", err
	}
	ns := req.Namespace
	if ns == "" {
		ns = DefaultNamespace
	}
	if !ValidNamespace(ns) {
		return nil, "", fmt.Errorf("invalid namespace: %q", ns)
	}

	key := "sk-sandswap-agent-" + randomHex(32)

	agent := &Agent{
		Name:        req.Name,
		Description: desc,
		APIKey:      key,
		APIKeyHash:  hashAPIKey(key),
		CreatedAt:   time.Now(),
		Namespace:   ns,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	session, err := concurrency.NewSession(s.client, concurrency.WithContext(ctx))
	if err != nil {
		return nil, "", fmt.Errorf("etcd session: %w", err)
	}
	defer session.Close()

	// idClaimMaxDraws bounds the regenerate loop; every draw colliding is
	// probability ~2^-256, past which failing loudly beats looping forever.
	const idClaimMaxDraws = 8
	var id, etcdKey, idKey string
	var data []byte
	for attempt := 0; ; attempt++ {
		id = "agent-" + uuid.New().String()[:8]
		agent.ID = id

		data, err = marshalAgentForEtcd(agent)
		if err != nil {
			return nil, "", fmt.Errorf("marshal agent for etcd: %w", err)
		}
		etcdKey = s.agentKeyFor(agent.APIKeyHash)
		idKey = s.agentIDKeyFor(id)

		// Colliding IDs contend on the same per-ID lock; distinct IDs run in
		// parallel. The lock plus the atomic claim below make the ID unique
		// across gateways.
		mutex := concurrency.NewMutex(session, s.lockKeyFor("agent/"+id))
		if err := mutex.Lock(ctx); err != nil {
			return nil, "", fmt.Errorf("acquire lock: %w", err)
		}

		// Atomic claim: BOTH the ID-ownership key and the api-key record must
		// be fresh. The api-key digest itself is 256-bit random (astronomical
		// to collide), but checking it in the same Txn is free.
		txnResp, terr := s.client.Txn(ctx).
			If(
				clientv3.Compare(clientv3.CreateRevision(idKey), "=", 0),
				clientv3.Compare(clientv3.CreateRevision(etcdKey), "=", 0),
			).
			Then(
				clientv3.OpPut(idKey, agent.APIKeyHash),
				clientv3.OpPut(etcdKey, string(data)),
			).
			Commit()
		mutex.Unlock(ctx)
		if terr != nil {
			return nil, "", fmt.Errorf("etcd claim txn: %w", terr)
		}
		if txnResp.Succeeded {
			break
		}
		if attempt >= idClaimMaxDraws {
			return nil, "", fmt.Errorf("agent id collision persisted after %d draws", idClaimMaxDraws+1)
		}
		// ID (or key) already claimed: regenerate and retry.
	}

	s.journalPending(etcdKey, idKey)

	// Update local cache immediately (don't wait for watch).
	s.mu.Lock()
	s.agents[id] = agent
	s.agentApiKeyToID[agent.APIKeyHash] = id
	s.neg.clear(etcdKey)
	s.mu.Unlock()

	return agent, key, nil
}

// DeleteAgent removes an Agent and all its SandFS records from etcd and cache.
func (s *EtcdStore) DeleteAgent(agentID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	session, err := concurrency.NewSession(s.client, concurrency.WithContext(ctx))
	if err != nil {
		return fmt.Errorf("etcd session: %w", err)
	}
	defer session.Close()

	mutex := concurrency.NewMutex(session, s.lockKeyFor("agent/"+agentID))
	if err := mutex.Lock(ctx); err != nil {
		return fmt.Errorf("acquire lock: %w", err)
	}
	defer mutex.Unlock(ctx)

	// Collect the agent key and owned sandfs from the cache. The reverse index
	// makes this O(K) in the agent's own sandfs count instead of a full scan.
	s.mu.RLock()
	agent := s.agents[agentID]
	var sandfsIDs []string
	for id := range s.sandfsByAgent[agentID] {
		sandfsIDs = append(sandfsIDs, id)
	}
	s.mu.RUnlock()

	if agent == nil {
		// Lazy-load fallback: the agent may exist in etcd but not in the local
		// cache (e.g. created on another gateway and the watch event has not
		// landed yet). Fetch the agent and its owned sandfs from etcd so the
		// delete is complete — deleting the agent key while leaving its sandfs
		// records would orphan them under a non-existent owner. Resolve/GetSandFS
		// backfill misses by direct key; DeleteAgent resolves by agent ID (not the
		// etcd key, which is the API-key hash), so it range-scans the prefixes.
		if !s.lazyLoad {
			return fmt.Errorf("agent not found: %s", agentID)
		}
		fetched, owned := s.fetchAgentAndOwnedSandfsByID(agentID)
		if fetched == nil {
			return fmt.Errorf("agent not found: %s", agentID)
		}
		agent = fetched
		sandfsIDs = owned
	}

	if _, err := s.client.Delete(ctx, s.agentKeyFor(agent.APIKeyHash)); err != nil {
		return fmt.Errorf("etcd delete agent: %w", err)
	}
	// Release the ID-ownership claim so a future create may reuse the ID
	// (recycling on delete still matters for deterministic reuse of an id).
	if _, err := s.client.Delete(ctx, s.agentIDKeyFor(agentID)); err != nil {
		return fmt.Errorf("etcd delete agent id claim: %w", err)
	}

	deletedKeys := []string{s.agentKeyFor(agent.APIKeyHash), s.agentIDKeyFor(agentID)}
	for _, sid := range sandfsIDs {
		// The batch path tombstones every id exactly like the single delete:
		// an agent deletion removes many ids at once, the widest id-reuse
		// window there is.
		s.putTombstone(ctx, sid)
		if _, err := s.client.Delete(ctx, s.sandfsKeyFor(sid)); err != nil {
			return fmt.Errorf("etcd delete sandfs %s: %w", sid, err)
		}
		deletedKeys = append(deletedKeys, s.sandfsKeyFor(sid))
		if !s.hotOnly {
			if _, err := s.client.Delete(ctx, s.sandfsMetaKeyFor(sid)); err != nil {
				return fmt.Errorf("etcd delete sandfs meta %s: %w", sid, err)
			}
			deletedKeys = append(deletedKeys, s.sandfsMetaKeyFor(sid))
		}
	}
	s.journalPending(deletedKeys...)

	// Update local cache immediately.
	s.mu.Lock()
	delete(s.agents, agentID)
	delete(s.agentApiKeyToID, agent.APIKeyHash)
	for _, sid := range sandfsIDs {
		delete(s.sandfs, sid)
		delete(s.sandfsMeta, sid)
		s.removeFromIndexLocked(agentID, sid)
	}
	s.mu.Unlock()

	return nil
}

// ListAgents returns all Agent records from the local cache.
func (s *EtcdStore) ListAgents() ([]*Agent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	agents := make([]*Agent, 0, len(s.agents))
	for _, agent := range s.agents {
		agents = append(agents, cloneAgent(agent))
	}
	return agents, nil
}

// GetAgent returns an Agent by ID from the local cache (cold path: human list
// pagination — the full-load/watch-synced cache is authoritative for the
// control plane; no lazy-load backfill needed).
func (s *EtcdStore) GetAgent(agentID string) (*Agent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	agent, ok := s.agents[agentID]
	if !ok || agent == nil {
		return nil, fmt.Errorf("agent not found: %s", agentID)
	}
	return cloneAgent(agent), nil
}

// ListAgentIDs returns all agent IDs, unsorted (pagination support — avoids
// cloning every record per list page).
func (s *EtcdStore) ListAgentIDs() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ids := make([]string, 0, len(s.agents))
	for id := range s.agents {
		ids = append(ids, id)
	}
	return ids
}

// ListSandFSIDs returns all sandfs IDs, unsorted (pagination support).
func (s *EtcdStore) ListSandFSIDs() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ids := make([]string, 0, len(s.sandfs))
	for id := range s.sandfs {
		ids = append(ids, id)
	}
	return ids
}

// ── Namespace listing (human-API tenancy) ────────────────────

// ListAgentsInNamespace returns clones of every agent in ns, filtered over
// the watch-fed cache (the human gateway's full-fleet view). Normalized
// comparison: legacy empty reads as DefaultNamespace.
func (s *EtcdStore) ListAgentsInNamespace(ns string) []*Agent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Agent, 0)
	for _, a := range s.agents {
		if a.NamespaceOrDefault() == ns {
			out = append(out, cloneAgent(a))
		}
	}
	return out
}

// ListSandFSInNamespace returns clones of every sandfs in ns.
func (s *EtcdStore) ListSandFSInNamespace(ns string) []*Record {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Record, 0)
	for _, r := range s.sandfs {
		if r.NamespaceOrDefault() == ns {
			out = append(out, s.mergeMetaLocked(r))
		}
	}
	return out
}

// ── SandFS CRUD (human interface) ──────────────────────────────

// CreateSandFS creates a new SandFS owned by the specified agent.
// Writes the hot record and the display metadata as ONE etcd transaction so
// other gateways observe them atomically via watch.
func (s *EtcdStore) CreateSandFS(agentID string, req CreateSandFSRequest) (*Record, error) {
	req.Description = strings.TrimSpace(req.Description)
	if err := ValidateDescription(req.Description); err != nil {
		return nil, err
	}
	// Verify agent exists in cache; the sandfs inherits the agent's
	// namespace (immutable pairing — a sandfs can never sit in a different
	// namespace than its agent, and the request carries no namespace of its
	// own so the pair cannot disagree).
	s.mu.RLock()
	agent, agentExists := s.agents[agentID]
	s.mu.RUnlock()
	if !agentExists {
		return nil, fmt.Errorf("agent not found: %s", agentID)
	}

	now := time.Now()

	rec := &Record{
		AgentID:     agentID,
		Template:    req.Template,
		Mode:        req.Mode,
		VolumeEpoch: req.VolumeEpoch,
		// Frozen from the agent at creation; empty only for a pre-namespace
		// legacy agent, which reads back as DefaultNamespace.
		Namespace: agent.Namespace,
		// RootFSPath is set by the caller (Registry) after volume creation.
	}
	meta := &sandfsMetaInfo{
		Name:        req.Name,
		Description: req.Description,
		CreatedAt:   now.Format(time.RFC3339Nano),
	}
	metaData, err := encodeSandfsMeta(meta)
	if err != nil {
		return nil, fmt.Errorf("marshal meta: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// The 8-hex ID suffix is 32 random bits (pinned by the egress IID field) —
	// collisions are rare but real at scale. The claim below is ATOMIC: a
	// CreateRevision==0 compare on the record key (and the meta key when
	// present) means two concurrent draws that pick the same id cannot both
	// commit. A check-then-put would let the loser silently overwrite the
	// winner's record — and both callers would then run volume Ensure/Delete
	// against the same seed-derived directory.
	const sandfsIDMaxDraws = 8
	var id, hotKey string
	var hotData []byte
	var writtenKeys []string
	for attempt := 0; ; attempt++ {
		id = "sandfs-" + uuid.New().String()[:8]
		rec.ID = id
		rec.CreatedAt = now

		hotData, err = encodeSandfsRecord(rec)
		if err != nil {
			return nil, fmt.Errorf("marshal record: %w", err)
		}
		hotKey = s.sandfsKeyFor(id)

		// One transaction writes the hot record and the display metadata so
		// other gateways never observe a half-created sandfs via watch.
		conds := []clientv3.Cmp{
			clientv3.Compare(clientv3.CreateRevision(hotKey), "=", 0),
			// A deleted id is remembered for TombstoneTTL; a draw that
			// lands on one must redraw (a lagging watch cache may still hold
			// the old record).
			clientv3.Compare(clientv3.CreateRevision(s.tombstoneKeyFor(id)), "=", 0),
		}
		ops := []clientv3.Op{clientv3.OpPut(hotKey, string(hotData))}
		if !s.hotOnly {
			metaKey := s.sandfsMetaKeyFor(id)
			conds = append(conds, clientv3.Compare(clientv3.CreateRevision(metaKey), "=", 0))
			ops = append(ops, clientv3.OpPut(metaKey, string(metaData)))
		}
		txnResp, terr := s.client.Txn(ctx).If(conds...).Then(ops...).Commit()
		if terr != nil {
			return nil, fmt.Errorf("etcd claim txn: %w", terr)
		}
		if txnResp.Succeeded {
			writtenKeys = writtenKeys[:0]
			for _, op := range ops {
				writtenKeys = append(writtenKeys, string(op.KeyBytes()))
			}
			break
		}
		if attempt >= sandfsIDMaxDraws {
			return nil, fmt.Errorf("sandfs id collision persisted after %d draws", sandfsIDMaxDraws+1)
		}
		// ID (or its meta key) already claimed: regenerate and retry.
	}

	for _, key := range writtenKeys {
		s.journalPending(key)
	}
	s.neg.clear(hotKey)

	// Update local cache immediately.
	s.mu.Lock()
	s.applySandfsPutLocked(rec)
	if !s.hotOnly {
		s.metaCachePutLocked(id, meta)
	}
	s.mu.Unlock()

	return rec, nil
}

// DeleteSandFS removes a SandFS from etcd and the local cache.
func (s *EtcdStore) DeleteSandFS(sandfsID string) error {
	// Existence check first (Store contract: deleting an unknown sandfs is an
	// error) — GetSandFS carries the full resolution semantics (cache, lazy
	// backfill, negative cache), so deleting never doubles as a blind no-op.
	if _, err := s.GetSandFS(sandfsID); err != nil {
		return err
	}

	hotKey := s.sandfsKeyFor(sandfsID)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	session, err := concurrency.NewSession(s.client, concurrency.WithContext(ctx))
	if err != nil {
		return fmt.Errorf("etcd session: %w", err)
	}
	defer session.Close()

	mutex := concurrency.NewMutex(session, s.lockKeyFor("sandfs/"+sandfsID))
	if err := mutex.Lock(ctx); err != nil {
		return fmt.Errorf("acquire lock: %w", err)
	}
	defer mutex.Unlock(ctx)

	// Remember the id before removing the record: a crash after this point
	// leaves a tombstone (safe) rather than a reusable id.
	s.putTombstone(ctx, sandfsID)

	// One transaction removes the hot record and the display metadata.
	ops := []clientv3.Op{clientv3.OpDelete(hotKey)}
	if !s.hotOnly {
		ops = append(ops, clientv3.OpDelete(s.sandfsMetaKeyFor(sandfsID)))
	}
	if _, err := s.client.Txn(ctx).Then(ops...).Commit(); err != nil {
		return fmt.Errorf("etcd txn delete: %w", err)
	}
	s.journalPending(string(ops[0].KeyBytes()))
	for _, op := range ops[1:] {
		s.journalPending(string(op.KeyBytes()))
	}

	s.mu.Lock()
	if rec, ok := s.sandfs[sandfsID]; ok && rec.AgentID != "" {
		s.removeFromIndexLocked(rec.AgentID, sandfsID)
	}
	delete(s.sandfs, sandfsID)
	delete(s.sandfsMeta, sandfsID)
	s.neg.clear(hotKey)
	s.neg.clear(s.sandfsMetaKeyFor(sandfsID))
	s.mu.Unlock()

	return nil
}

// ListAllSandFS returns all SandFS records from the local cache.
// In HotOnly mode the display fields (Name/Description/CreatedAt) are zero:
// that data lives in the meta space which exec gateways do not carry.
func (s *EtcdStore) ListAllSandFS() ([]*Record, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	recs := make([]*Record, 0, len(s.sandfs))
	for _, rec := range s.sandfs {
		recs = append(recs, s.mergeMetaLocked(rec))
	}
	return recs, nil
}

// ── Field setters ──────────────────────────────────────────────

// SetRootFSPath sets the RootFSPath on an existing record in both etcd and cache.
// Touches only the hot record — the execution path owns this field.
func (s *EtcdStore) SetRootFSPath(sandfsID, rootfsPath string) error {
	return s.updateRecord(sandfsID, func(rec *Record) {
		rec.RootFSPath = rootfsPath
	})
}

// SetMinResources sets the minimum vCPUs/memory on an existing record in both etcd and cache.
func (s *EtcdStore) SetMinResources(sandfsID string, vcpus uint32, memMB uint64) error {
	return s.updateRecord(sandfsID, func(rec *Record) {
		rec.MinVCPUs = vcpus
		rec.MinMemoryMB = memMB
	})
}

// ── Lifecycle (template swap + delete orchestration) ───────────

// SetSandfsStatus writes the lifecycle status (see Record.Status) in etcd and
// cache. Unknown status values are refused at this seam — a typo must never
// silently gate every execution on the sandfs.
func (s *EtcdStore) SetSandfsStatus(sandfsID, status string) error {
	if err := validateStatus(status); err != nil {
		return err
	}
	return s.updateRecord(sandfsID, func(rec *Record) {
		rec.Status = status
	})
}

// UpdateSandfsTemplate completes a template attach in ONE record write: new
// ref, new declared min resources, status back to active. Single-write so a
// concurrent reader never observes the new template with a non-active status.
//
// Only valid from the detached state (see MemoryStore.UpdateSandfsTemplate):
// the attach flow checks "detached" and then runs a potentially multi-minute
// storage swap, so an unconditional write here could complete an attach over a
// deletion that landed meanwhile. Returns ErrSandfsNotDetached, changing
// nothing, when the record moved on.
func (s *EtcdStore) UpdateSandfsTemplate(sandfsID, templateRef string, vcpus uint32, memMB uint64) error {
	return s.updateRecordChecked(sandfsID, func(rec *Record) error {
		if rec.Status != SandfsStatusDetached {
			return ErrSandfsNotDetached
		}
		return nil
	}, func(rec *Record) {
		rec.Template = templateRef
		rec.MinVCPUs = vcpus
		rec.MinMemoryMB = memMB
		rec.Status = ""
	})
}

// CountSandFSByTemplate counts overlay-mode records naming templateRef
// (local-cache scan — the human gateway holds the full cache; no etcd reads).
// Returns the count plus a bounded id sample for the TEMPLATE_IN_USE refusal.
func (s *EtcdStore) CountSandFSByTemplate(templateRef string) (int, []string) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	count := 0
	var sample []string
	for id, rec := range s.sandfs {
		// Ref identity is the ref FILE identity (see MemoryStore): colliding
		// encodings name the same template and must count as in use.
		if rec.Mode == "overlay" && util.RefToFilename(rec.Template) == util.RefToFilename(templateRef) {
			count++
			if len(sample) < templateInUseSampleSize {
				sample = append(sample, id)
			}
		}
	}
	return count, sample
}

// FreshReader is the optional linearizable-read view: a Get that bypasses the
// watch-maintained cache and reads etcd directly (quorum). The exec gateway
// uses it ONLY when the local watch snapshot is already non-active: a tripped
// SANDFS_NOT_ACTIVE gate re-checks before refusing, and a cold mount whose
// under-lock snapshot says detaching/detached/deleting re-checks before it
// refuses (an attach may have completed while the request waited). The normal
// active path — warm or cold — never calls this.
type FreshReader interface {
	GetSandFSFresh(sandfsID string) (*Record, error)
}

// GetSandFSFresh is the linearizable read behind FreshReader: direct etcd Get
// of the hot record key. Returns the record as committed — no watch lag.
func (s *EtcdStore) GetSandFSFresh(sandfsID string) (*Record, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	resp, err := s.client.Get(ctx, s.sandfsKeyFor(sandfsID))
	if err != nil {
		return nil, fmt.Errorf("etcd get: %w", err)
	}
	if len(resp.Kvs) == 0 {
		// Keep the watch-fed cache and the negative cache consistent with this
		// linearizable answer: a stale positive entry (a delete not yet
		// watched) or a stale negative entry must not survive a fresh read.
		s.mu.Lock()
		if resp.Header.Revision >= s.watchRev {
			s.applyDeleteLocked(s.sandfsKeyFor(sandfsID))
		}
		s.neg.clear(s.sandfsKeyFor(sandfsID))
		s.mu.Unlock()
		return nil, fmt.Errorf("%w: %s", ErrSandFSNotFound, sandfsID)
	}
	rec := decodeSandfsRecord(resp.Kvs[0].Value)
	if rec == nil {
		return nil, fmt.Errorf("decode sandfs record: %s", sandfsID)
	}
	// Apply the fresher snapshot under the watch-revision guard (the same one
	// the lazy backfill uses), and clear the negative cache: a destructive
	// caller that just did a linearizable read must not have its next cached
	// read answer from an older view.
	s.mu.Lock()
	if resp.Header.Revision >= s.watchRev {
		s.applySandfsPutLocked(rec)
	}
	s.neg.clear(s.sandfsKeyFor(sandfsID))
	s.mu.Unlock()
	return rec, nil
}

// NotifyInitialStatuses fires the record watcher for every cached record whose
// status is non-active. The exec gateway calls it once after the store is
// ready, compensating for drain-trigger statuses written while this process
// was offline (watch events for them never fired here). No-op when no watcher
// is installed.
func (s *EtcdStore) NotifyInitialStatuses() {
	if s.recordWatcher == nil {
		return
	}
	type pending struct{ id, status string }
	var fires []pending
	s.mu.RLock()
	for id, rec := range s.sandfs {
		if rec.Status != "" {
			fires = append(fires, pending{id, rec.Status})
		}
	}
	s.mu.RUnlock()
	for _, p := range fires {
		s.recordWatcher(p.id, p.status)
	}
	if len(fires) > 0 {
		s.logger.Info("initial lifecycle-status scan fired drain triggers",
			"count", len(fires))
	}
}

// updateRecord reads the hot record from etcd, applies the mutation, and
// writes it back. Uses a distributed lock to prevent concurrent updates from
// losing data. Display metadata is untouched (it lives under a separate key).
func (s *EtcdStore) updateRecord(sandfsID string, mutate func(*Record)) error {
	return s.updateRecordChecked(sandfsID, nil, mutate)
}

// errStatusMismatch is the internal sentinel of a CompareAndSetSandfsStatus
// precondition failure (the caller turns it into an applied=false result).
var errStatusMismatch = errors.New("status mismatch")

// updateRecordChecked is updateRecord with an optional precondition evaluated
// on the freshly-read record UNDER the same distributed lock as the write. A
// precondition error aborts without writing (the record and the cache are left
// untouched).
func (s *EtcdStore) updateRecordChecked(sandfsID string, check func(*Record) error, mutate func(*Record)) error {
	hotKey := s.sandfsKeyFor(sandfsID)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	session, err := concurrency.NewSession(s.client, concurrency.WithContext(ctx))
	if err != nil {
		return fmt.Errorf("etcd session: %w", err)
	}
	defer session.Close()

	mutex := concurrency.NewMutex(session, s.lockKeyFor("sandfs/"+sandfsID))
	if err := mutex.Lock(ctx); err != nil {
		return fmt.Errorf("acquire lock: %w", err)
	}
	defer mutex.Unlock(ctx)

	resp, err := s.client.Get(ctx, hotKey)
	if err != nil {
		return fmt.Errorf("etcd get: %w", err)
	}
	if len(resp.Kvs) == 0 {
		return fmt.Errorf("sandfs not found: %s", sandfsID)
	}

	rec := decodeSandfsRecord(resp.Kvs[0].Value)
	if rec == nil {
		return fmt.Errorf("corrupt sandfs record in etcd")
	}

	if check != nil {
		if err := check(rec); err != nil {
			return err
		}
	}

	mutate(rec)

	data, err := encodeSandfsRecord(rec)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	if _, err := s.client.Put(ctx, hotKey, string(data)); err != nil {
		return fmt.Errorf("etcd put: %w", err)
	}

	s.journalPending(hotKey)

	s.mu.Lock()
	s.applySandfsPutLocked(rec)
	s.mu.Unlock()

	return nil
}

// CompareAndSetSandfsStatus implements StatusCASStore: the transition applies
// only while the record still carries `from`.
func (s *EtcdStore) CompareAndSetSandfsStatus(sandfsID, from, to string) (bool, string, error) {
	if err := validateStatus(from); err != nil {
		return false, "", err
	}
	if err := validateStatus(to); err != nil {
		return false, "", err
	}
	current := ""
	err := s.updateRecordChecked(sandfsID, func(rec *Record) error {
		if rec.Status != from {
			current = rec.Status
			return errStatusMismatch
		}
		return nil
	}, func(rec *Record) {
		rec.Status = to
	})
	if errors.Is(err, errStatusMismatch) {
		return false, current, nil
	}
	if err != nil {
		return false, "", err
	}
	return true, to, nil
}

// ── Index helpers ──────────────────────────────────────────────

// removeFromIndexLocked drops one sandfs from the agent reverse index,
// pruning the per-agent set entirely when it empties. Caller holds Lock.
func (s *EtcdStore) removeFromIndexLocked(agentID, sandfsID string) {
	if set := s.sandfsByAgent[agentID]; set != nil {
		delete(set, sandfsID)
		if len(set) == 0 {
			delete(s.sandfsByAgent, agentID)
		}
	}
}

// applyAgentPutLocked inserts/updates an agent and maintains the digest index.
// Caller holds Lock.
func (s *EtcdStore) applyAgentPutLocked(agent *Agent) {
	if old, ok := s.agents[agent.ID]; ok && old.APIKeyHash != agent.APIKeyHash {
		delete(s.agentApiKeyToID, old.APIKeyHash)
	}
	s.agents[agent.ID] = agent
	if agent.APIKeyHash != "" {
		s.agentApiKeyToID[agent.APIKeyHash] = agent.ID
	}
}

// applySandfsPutLocked inserts/updates a hot sandfs record and maintains the
// reverse index when ownership changed. Caller holds Lock.
func (s *EtcdStore) applySandfsPutLocked(rec *Record) {
	if old, ok := s.sandfs[rec.ID]; ok && old.AgentID != rec.AgentID && old.AgentID != "" {
		s.removeFromIndexLocked(old.AgentID, rec.ID)
	}
	s.sandfs[rec.ID] = rec
	if rec.AgentID != "" {
		if s.sandfsByAgent[rec.AgentID] == nil {
			s.sandfsByAgent[rec.AgentID] = make(map[string]struct{})
		}
		s.sandfsByAgent[rec.AgentID][rec.ID] = struct{}{}
	}
}

// applyPutLocked routes one etcd PUT to the right cache updater.
// Caller holds Lock. Used by both watch events and journal replay.
func (s *EtcdStore) applyPutLocked(key string, value []byte) {
	switch {
	case strings.HasPrefix(key, s.prefix+"agent/"):
		if agent := decodeAgent(value); agent != nil {
			s.applyAgentPutLocked(agent)
		}
	case strings.HasPrefix(key, s.prefix+"meta/sandfs/"):
		if s.hotOnly {
			return
		}
		if m := decodeSandfsMeta(value); m != nil {
			// Refresh resident entries only — the bounded cache must not grow
			// into a full meta mirror via the watch.
			id := strings.TrimPrefix(key, s.prefix+"meta/sandfs/")
			if _, resident := s.sandfsMeta[id]; resident {
				s.metaCachePutLocked(id, m)
			}
		}
	case strings.HasPrefix(key, s.prefix+"sandfs/"):
		if rec := decodeSandfsRecord(value); rec != nil {
			s.applySandfsPutLocked(rec)
		}
	}
}

// applyDeleteLocked routes one etcd DELETE to the right cache eviction.
// Caller holds Lock. Used by both watch events and journal replay.
func (s *EtcdStore) applyDeleteLocked(key string) {
	switch {
	case strings.HasPrefix(key, s.prefix+"agent/"):
		hash := strings.TrimPrefix(key, s.prefix+"agent/")
		// O(1) lookup via the digest index instead of scanning every agent.
		if id, ok := s.agentApiKeyToID[hash]; ok {
			delete(s.agents, id)
		}
		delete(s.agentApiKeyToID, hash)
	case strings.HasPrefix(key, s.prefix+"meta/sandfs/"):
		if s.hotOnly {
			return
		}
		delete(s.sandfsMeta, strings.TrimPrefix(key, s.prefix+"meta/sandfs/"))
	case strings.HasPrefix(key, s.prefix+"sandfs/"):
		id := strings.TrimPrefix(key, s.prefix+"sandfs/")
		if rec, ok := s.sandfs[id]; ok && rec.AgentID != "" {
			s.removeFromIndexLocked(rec.AgentID, id)
		}
		delete(s.sandfs, id)
	}
}

// ── Parallel snapshot loader ───────────────────────────────────

// hexDigits buckets the sandfs key space for parallel loading. SandFS ids are
// "sandfs-" + 8 lowercase hex chars, so the etcd key is "sandfs/sandfs-<hex>";
// splitting on the first hex digit (the char after "sandfs/sandfs-") yields
// evenly-sized disjoint ranges that spread 100k IDs across all workers.
const hexDigits = "0123456789abcdef"

// loadPageMaxRetries bounds one page's retry budget inside a full load.
// Pages read at the pinned snapshot revision are idempotent, so a transient
// slow/failed page retries with exponential backoff instead of aborting the
// whole load (one degraded page used to fail C1 outright).
const (
	loadPageMaxRetries = 5
	loadPageRetryBase  = time.Second
	loadPageRetryCap   = 30 * time.Second
)

// loadPageRetryDelay is the backoff before retry attempt N (1-based),
// doubling from loadPageRetryBase and capped at loadPageRetryCap.
func loadPageRetryDelay(attempt int) time.Duration {
	d := loadPageRetryBase << (attempt - 1)
	if d > loadPageRetryCap {
		d = loadPageRetryCap
	}
	return d
}

// sandfsIDPrefix is the non-hex leading portion of a sandfs ID ("sandfs-").
const sandfsIDPrefix = "sandfs-"

type keyRange struct {
	start string // inclusive
	end   string // exclusive
}

// loadRanges partitions the store prefix into disjoint lexicographic ranges,
// one per top-level directory, with the sandfs directory further bucketed by
// the first hex digit of the ID. The union covers every possible key under the
// prefix. Each range is a half-open interval [start, end); etcd's WithRange
// treats the end key as exclusive, matching this.
func (s *EtcdStore) loadRanges() []keyRange {
	var ranges []keyRange
	// Agent keys are "<prefix>agent/<64hex-digest>": bucket on the digest's
	// first hex digit. The below-'0' bucket is empty in practice (digests
	// begin with a hex digit) and the catch-all reaches "agent0", which sorts
	// after every "agent/*" key because '/' (0x2f) < '0' (0x30) — the union
	// is exact and no bucket is a serial chain anymore.
	ab := s.prefix + "agent/"
	ranges = append(ranges, keyRange{ab, ab + "0"})
	for i := 0; i < len(hexDigits)-1; i++ {
		ranges = append(ranges, keyRange{
			ab + string(hexDigits[i]),
			ab + string(hexDigits[i+1]),
		})
	}
	ranges = append(ranges, keyRange{ab + "f", s.prefix + "agent0"})
	// SandFS keys are "<prefix>sandfs/sandfs-<8hex>". Bucket on the first hex
	// digit after "sandfs/sandfs-" so IDs distribute evenly across workers.
	// bp is the bucket base prefix every sandfs key shares.
	bp := s.prefix + "sandfs/" + sandfsIDPrefix
	ranges = append(ranges, keyRange{s.prefix + "sandfs/", bp + "0"})
	for i := 0; i < len(hexDigits)-1; i++ {
		ranges = append(ranges, keyRange{
			bp + string(hexDigits[i]),
			bp + string(hexDigits[i+1]),
		})
	}
	ranges = append(ranges, keyRange{bp + "f", s.prefix + "sandfs0"})
	// NOTE: meta/ (display data) is deliberately NOT loaded — the human gateway
	// lazily point-fetches it per record behind a bounded cache (the
	// 1M-key meta full load cost minutes of serial chain plus ~0.5-1GB RSS
	// per gateway; the exec plane never carried display data by design).
	return ranges
}

// identitySnapshot is a private cache image assembled by the parallel loader. Each
// worker builds its OWN local snapshot from its disjoint key range; after all
// workers finish, the local snapshots are merged into one (single-threaded, no
// races) which then replaces the live maps in a single lock hold. Writing
// directly to a shared snapshot would race on concurrent map writes once
// correct bucketing spreads sandfs keys across multiple workers.
type identitySnapshot struct {
	agents     map[string]*Agent
	apiKeyToID map[string]string
	sandfs     map[string]*Record
	byAgent    map[string]map[string]struct{}
	kvs        int
}

func newIdentitySnapshot() *identitySnapshot {
	return &identitySnapshot{
		agents:     make(map[string]*Agent),
		apiKeyToID: make(map[string]string),
		sandfs:     make(map[string]*Record),
		byAgent:    make(map[string]map[string]struct{}),
	}
}

func (snap *identitySnapshot) addSandfs(rec *Record) {
	snap.sandfs[rec.ID] = rec
	if rec.AgentID != "" {
		if snap.byAgent[rec.AgentID] == nil {
			snap.byAgent[rec.AgentID] = make(map[string]struct{})
		}
		snap.byAgent[rec.AgentID][rec.ID] = struct{}{}
	}
}

// merge folds another (per-worker) snapshot into this one. The caller holds
// exclusive access to both — merge runs single-threaded after all workers have
// joined, so there are no concurrent map writes.
func (snap *identitySnapshot) merge(other *identitySnapshot) {
	for k, v := range other.agents {
		snap.agents[k] = v
	}
	for k, v := range other.apiKeyToID {
		snap.apiKeyToID[k] = v
	}
	// addSandfs rebuilds both snap.sandfs and the byAgent index.
	for _, rec := range other.sandfs {
		snap.addSandfs(rec)
	}
	snap.kvs += other.kvs
}

// runFullLoad builds a fresh cache snapshot from etcd and swaps it into the
// live store. Called at startup and whenever a watch reconnect discovers its
// starting revision was compacted away.
func (s *EtcdStore) runFullLoad(parent context.Context) error {
	attempt := 0
	for {
		err := s.fullLoadOnce(parent, attempt > 0)
		if err == nil {
			return nil
		}
		// The chosen snapshot revision was compacted mid-read: retry from a
		// fresh (necessarily newer) revision. Anything else is fatal here.
		if errors.Is(err, rpctypes.ErrCompacted) && attempt < 3 {
			attempt++
			s.logger.Warn("etcd identity snapshot revision compacted mid-load, retrying",
				"attempt", attempt, "error", err)
			continue
		}
		return err
	}
}

// fullLoadOnce performs one complete snapshot build.
//
// Consistency: every page of every range is read at ONE cluster revision
// (WithRev), so the assembled snapshot corresponds to a single point in time
// regardless of how long the parallel reads take. When retrying after a
// compaction, useRev=false reads pages linearizably at their own current
// revisions instead — slightly weaker but only used as a fallback.
func (s *EtcdStore) fullLoadOnce(parent context.Context, retryAtCurrentRev bool) error {
	start := time.Now()

	ctx, cancel := context.WithTimeout(parent, s.fullLoadTimeout)
	defer cancel()

	// Mark the rebuild in progress FIRST so concurrent local writes journal
	// their keys for post-swap replay (they must survive the snapshot swap).
	s.mu.Lock()
	s.loading = true
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.loading = false
		s.mu.Unlock()
	}()

	// One lightweight Get pins the snapshot revision for every worker.
	head, err := s.client.Get(ctx, s.prefix, clientv3.WithLimit(1))
	if err != nil {
		return fmt.Errorf("etcd get snapshot revision: %w", err)
	}
	snapRev := head.Header.Revision

	useRev := !retryAtCurrentRev
	snap := newIdentitySnapshot()
	ranges := s.loadRanges()

	sem := make(chan struct{}, max(1, s.loadWorkers))
	var wg sync.WaitGroup
	var mu sync.Mutex
	var firstErr error
	snaps := make([]*identitySnapshot, len(ranges))
	for i, r := range ranges {
		wg.Add(1)
		go func(i int, r keyRange) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			local, err := s.loadRange(ctx, r, snapRev, useRev)
			if err != nil {
				mu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				mu.Unlock()
				return
			}
			snaps[i] = local
		}(i, r)
	}
	wg.Wait()
	if firstErr != nil {
		return firstErr
	}
	// Merge per-worker local snapshots into the shared snapshot. Single-threaded
	// after wg.Wait, so no concurrent map writes.
	for _, local := range snaps {
		snap.merge(local)
	}

	// Swap the finished snapshot into place under one lock hold. Readers keep
	// serving from the previous snapshot until this instant.
	s.mu.Lock()
	s.agents = snap.agents
	s.agentApiKeyToID = snap.apiKeyToID
	s.sandfs = snap.sandfs
	// The display-meta cache is NOT part of the snapshot anymore: it is a
	// bounded lazy cache that survives snapshot swaps.
	s.sandfsByAgent = snap.byAgent
	pending := s.pendingKeys
	s.pendingKeys = nil
	s.watchRev = snapRev
	s.loading = false
	s.mu.Unlock()

	// Replay keys mutated locally while the snapshot was being built, so a
	// write that committed mid-load cannot be rolled back by the swap.
	if len(pending) > 0 {
		s.refreshKeys(pending)
	}

	s.logger.Info("etcd identity snapshot load complete",
		"kvs", snap.kvs, "agents", len(snap.agents), "sandfs", len(snap.sandfs),
		"revision", snapRev, "duration", time.Since(start))
	return nil
}

// loadRange pages one disjoint key range into a fresh LOCAL snapshot and
// returns it. Pages read at a pinned snapshot revision stay consistent with all
// other workers. Each worker owns its local snapshot, so there are no
// concurrent map writes; the caller merges all locals after the workers join.
func (s *EtcdStore) loadRange(ctx context.Context, r keyRange, snapRev int64, useRev bool) (*identitySnapshot, error) {
	opts := []clientv3.OpOption{
		clientv3.WithRange(r.end),
		clientv3.WithLimit(int64(s.loadPageSize)),
	}
	if useRev {
		opts = append(opts, clientv3.WithRev(snapRev))
	}

	local := newIdentitySnapshot()
	cursor := r.start
	retries := 0
	for {
		resp, err := s.client.Get(ctx, cursor, opts...)
		if err != nil {
			if ctx.Err() != nil {
				// Full-load budget exhausted — the operator knob decides.
				return nil, fmt.Errorf("etcd range [%s,%s): %w", r.start, r.end, err)
			}
			retries++
			if retries > loadPageMaxRetries {
				return nil, fmt.Errorf("etcd range [%s,%s) page failed after %d retries: %w",
					r.start, r.end, loadPageMaxRetries, err)
			}
			delay := loadPageRetryDelay(retries)
			s.logger.Warn("identity load page retry (idempotent at the pinned revision)",
				"range", r.start+".."+r.end, "attempt", retries, "delay", delay, "error", err)
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return nil, fmt.Errorf("etcd range [%s,%s): %w", r.start, r.end, ctx.Err())
			}
			continue
		}
		retries = 0
		for _, kv := range resp.Kvs {
			s.decodeIntoSnapshot(string(kv.Key), kv.Value, local)
		}
		if !resp.More {
			return local, nil
		}
		cursor = string(resp.Kvs[len(resp.Kvs)-1].Key) + "\x00"
	}
}

// decodeIntoSnapshot decodes one etcd KV into the snapshot being built.
func (s *EtcdStore) decodeIntoSnapshot(key string, value []byte, snap *identitySnapshot) {
	switch {
	case strings.HasPrefix(key, s.prefix+"agent/"):
		if agent := decodeAgent(value); agent != nil {
			snap.agents[agent.ID] = agent
			if agent.APIKeyHash != "" {
				snap.apiKeyToID[agent.APIKeyHash] = agent.ID
			}
			snap.kvs++
		}
	case strings.HasPrefix(key, s.prefix+"sandfs/"):
		if rec := decodeSandfsRecord(value); rec != nil {
			snap.addSandfs(rec)
			snap.kvs++
		}
	}
}

// journalPending records etcd keys mutated by the local write path while a
// background snapshot rebuild is running, so refreshKeys can restore them
// after the rebuild swaps its snapshot in. Cheap no-op outside rebuilds.
func (s *EtcdStore) journalPending(keys ...string) {
	s.mu.Lock()
	if s.loading {
		s.pendingKeys = append(s.pendingKeys, keys...)
	}
	s.mu.Unlock()
}

// refreshKeys re-fetches the authoritative state of specific keys and applies
// it to the live cache. Used to replay the write-during-load journal.
func (s *EtcdStore) refreshKeys(keys []string) {
	for _, key := range keys {
		if !strings.HasPrefix(key, s.prefix) {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		resp, err := s.client.Get(ctx, key)
		cancel()
		if err != nil {
			s.logger.Warn("etcd identity journal replay get failed",
				"key", key, "error", err)
			continue
		}
		s.mu.Lock()
		if len(resp.Kvs) > 0 {
			s.applyPutLocked(string(resp.Kvs[0].Key), resp.Kvs[0].Value)
		} else {
			s.applyDeleteLocked(key)
		}
		s.mu.Unlock()
	}
}

// ── Watch loop ─────────────────────────────────────────────────

// watchLoop keeps the cache in sync with etcd.
//
// Recovery policy — the whole point of this design is to avoid ever paying a
// full snapshot rebuild for an ordinary disconnect:
//   - Plain disconnect (network blip, server restart): the last processed
//     revision is still readable, so simply resume the watch from watchRev+1.
//     Events buffered during the outage are replayed by etcd.
//   - Compacted revision (watchRev older than etcd's compaction horizon):
//     those events are gone forever — the only correct recovery is a fresh
//     parallel snapshot rebuild, after which the watch resumes normally.
func (s *EtcdStore) watchLoop() {
	backoff := 2 * time.Second
	const maxBackoff = 30 * time.Second

	s.logger.Info("etcd identity watch loop starting",
		"prefix", s.prefix, "startRev", s.watchRev+1, "hotOnly", s.hotOnly)

	for {
		select {
		case <-s.watchDone:
			s.logger.Info("etcd identity watch loop stopped")
			close(s.watchStopped)
			return
		default:
		}

		wctx, wcancel := context.WithCancel(context.Background())
		wch := s.client.Watch(wctx, s.prefix,
			clientv3.WithPrefix(),
			clientv3.WithRev(s.watchRev+1),
			clientv3.WithPrevKV(),
		)

		rebuilt := false
		for resp := range wch {
			if err := resp.Err(); err != nil {
				wcancel()
				if watchNeedsRebuild(err) {
					s.logger.Warn("etcd identity watch revision compacted, rebuilding cache snapshot",
						"compactRev", resp.CompactRevision, "watchRev", s.watchRev)
					ctx, cancel := context.WithTimeout(context.Background(), s.fullLoadTimeout)
					err := s.runFullLoad(ctx)
					cancel()
					if err != nil {
						s.logger.Error("etcd identity rebuild after compaction failed",
							"error", err, "backoff", backoff)
						break
					}
					rebuilt = true
				} else {
					s.logger.Warn("etcd identity watch disconnected, resuming from last revision",
						"error", err, "watchRev", s.watchRev, "backoff", backoff)
				}
				break
			}
			s.applyWatchResponse(resp)
		}
		wcancel()

		if rebuilt {
			backoff = 2 * time.Second
			continue
		}

		// Plain disconnect (or failed rebuild): wait out the backoff, then the
		// loop resumes the watch from watchRev+1 without touching the cache.
		time.Sleep(backoff)
		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

// watchNeedsRebuild reports whether a failed watch response warrants a full
// snapshot rebuild. ErrCompacted ALWAYS does: it means the resume revision
// (watchRev+1) has been compacted away — including the boundary case where the
// compaction horizon lands exactly ON watchRev+1, which an earlier
// `CompactRevision > watchRev+1` guard skipped. Resubscribing at the same gone
// revision fails identically forever while the cache silently freezes
// (cross-gateway visibility AND the split-mode drain triggers ride on this
// watch). Any other error is a plain disconnect: the loop resumes from the
// last processed revision without touching the cache.
func watchNeedsRebuild(err error) bool {
	return errors.Is(err, rpctypes.ErrCompacted)
}

// applyWatchResponse applies every event in one watch response under a single
// lock hold — bulk provisioning storms pay one lock acquisition, not one per
// event. Revision bookkeeping advances only after the batch lands. SandFS
// record status changes are collected under the lock and reported to the
// record watcher (if installed) after it — the drain trigger must never run
// under the cache lock.
func (s *EtcdStore) applyWatchResponse(resp clientv3.WatchResponse) {
	type statusChange struct{ id, status string }
	var changes []statusChange

	s.mu.Lock()
	for _, ev := range resp.Events {
		key := string(ev.Kv.Key)
		switch ev.Type {
		case clientv3.EventTypePut:
			s.applyPutLocked(key, ev.Kv.Value)
			s.neg.clear(key)
			if s.recordWatcher != nil && strings.HasPrefix(key, s.prefix+"sandfs/") {
				if rec := decodeSandfsRecord(ev.Kv.Value); rec != nil {
					changes = append(changes, statusChange{rec.ID, rec.Status})
				}
			}
		case clientv3.EventTypeDelete:
			s.applyDeleteLocked(key)
			s.neg.clear(key)
		}
	}
	s.watchRev = resp.Header.Revision
	s.mu.Unlock()

	for _, c := range changes {
		s.recordWatcher(c.id, c.status)
	}

	if len(resp.Events) > 0 {
		s.logger.Debug("etcd identity watch events applied",
			"count", len(resp.Events), "revision", resp.Header.Revision)
	}
}

// fetchAndApplyMeta best-effort fetches one sandfs display-metadata key into
// the cache. Failures are silent: meta is cosmetic and the watch will fill it.
func (s *EtcdStore) fetchAndApplyMeta(sandfsID string) {
	key := s.sandfsMetaKeyFor(sandfsID)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := s.client.Get(ctx, key)
	if err != nil || len(resp.Kvs) == 0 {
		return
	}
	s.mu.Lock()
	s.applyPutLocked(key, resp.Kvs[0].Value)
	s.mu.Unlock()
}

// fetchAgentAndOwnedSandfsByID range-scans etcd for an agent by ID and the
// sandfs records it owns, populating the local cache. Used as the DeleteAgent
// lazy-load fallback (the etcd agent key is the API-key hash, not the ID, so a
// direct Get is impossible). Returns (nil, nil) if no such agent exists. Cost
// is O(agents + sandfs) — acceptable for a rare admin operation, bounded by the
// context timeout.
func (s *EtcdStore) fetchAgentAndOwnedSandfsByID(agentID string) (*Agent, []string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var agent *Agent
	var owned []string

	// Scan agent/ for the matching ID.
	agentStart := s.prefix + "agent/"
	agentEnd := s.prefix + "agent0"
	cursor := agentStart
	for {
		resp, err := s.client.Get(ctx, cursor,
			clientv3.WithRange(agentEnd), clientv3.WithLimit(int64(s.loadPageSize)))
		if err != nil {
			return nil, nil
		}
		for _, kv := range resp.Kvs {
			if a := decodeAgent(kv.Value); a != nil && a.ID == agentID {
				agent = a
			}
		}
		if !resp.More {
			break
		}
		cursor = string(resp.Kvs[len(resp.Kvs)-1].Key) + "\x00"
	}
	if agent == nil {
		return nil, nil
	}

	// Scan sandfs/ for records owned by this agent.
	sandfsStart := s.prefix + "sandfs/"
	sandfsEnd := s.prefix + "sandfs0"
	cursor = sandfsStart
	for {
		resp, err := s.client.Get(ctx, cursor,
			clientv3.WithRange(sandfsEnd), clientv3.WithLimit(int64(s.loadPageSize)))
		if err != nil {
			break
		}
		for _, kv := range resp.Kvs {
			if rec := decodeSandfsRecord(kv.Value); rec != nil && rec.AgentID == agentID {
				owned = append(owned, rec.ID)
			}
		}
		if !resp.More {
			break
		}
		cursor = string(resp.Kvs[len(resp.Kvs)-1].Key) + "\x00"
	}

	// Cache the agent so the subsequent cache-update step is consistent. The
	// owned sandfs IDs are enough for deletion; the watch reconciles the cache.
	s.mu.Lock()
	s.applyAgentPutLocked(agent)
	s.mu.Unlock()
	return agent, owned
}

// ── Lazy load-back support (negative cache + rate limit) ───────

// negativeCache remembers recently-missed keys so repeated lookups of absent
// IDs do not hammer etcd. Entries expire quickly (seconds); any watch event
// for the same key clears the entry, keeping create-after-404 windows tight.
type negativeCache struct {
	mu      sync.Mutex
	entries map[string]time.Time
	cap     int
	ttl     time.Duration
}

func (n *negativeCache) get(key string) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	expiry, ok := n.entries[key]
	if !ok {
		return false
	}
	if time.Now().After(expiry) {
		delete(n.entries, key)
		return false
	}
	return true
}

func (n *negativeCache) put(key string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.entries == nil {
		n.entries = make(map[string]time.Time)
	}
	// Bound memory: sweep expired entries when over capacity, then evict
	// arbitrary survivors (map order) if still over — good enough for a
	// defensive cache whose entries live seconds.
	if len(n.entries) >= n.cap {
		now := time.Now()
		for k, expiry := range n.entries {
			if now.After(expiry) {
				delete(n.entries, k)
			}
		}
		for k := range n.entries {
			if len(n.entries) < n.cap {
				break
			}
			delete(n.entries, k)
		}
	}
	n.entries[key] = time.Now().Add(n.ttl)
}

func (n *negativeCache) clear(key string) {
	n.mu.Lock()
	delete(n.entries, key)
	n.mu.Unlock()
}

// fetchLimiter is a per-key fixed-window rate limiter bounding how often one
// distinct key may trigger an etcd backfill (default 50/s/key). Keys are
// namespaced ("agent:<hash>", "sandfs:<id>") and the table self-prunes.
type fetchLimiter struct {
	mu      sync.Mutex
	window  time.Duration
	max     int
	counts  map[string]int
	windows map[string]time.Time
}

func (l *fetchLimiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.counts == nil {
		l.counts = make(map[string]int)
		l.windows = make(map[string]time.Time)
		l.window = time.Second
		l.max = lazyFetchRatePerSec
	}
	now := time.Now()
	if start, ok := l.windows[key]; !ok || now.Sub(start) >= l.window {
		l.windows[key] = now
		l.counts[key] = 0
	}
	l.counts[key]++
	allowed := l.counts[key] <= l.max
	// Prune stale windows occasionally to bound memory under key churn.
	if len(l.windows) > 4*lazyNegativeCap && len(l.windows)%1024 == 0 {
		for k, start := range l.windows {
			if now.Sub(start) >= l.window {
				delete(l.windows, k)
				delete(l.counts, k)
			}
		}
	}
	return allowed
}

// globalFetchLimiter is a fixed-window counter bounding the TOTAL etcd backfill
// rate across all keys (default 200/s), independent of the per-key limiter. This
// is the DoS cap: without it, an attacker hitting N distinct keys each gets the
// per-key budget and the aggregate read pressure is unbounded in N.
type globalFetchLimiter struct {
	mu     sync.Mutex
	window time.Time
	count  int
}

// allow reports whether a backfill may proceed under the global rate. Lazily
// initialized so the zero value is ready to use.
func (g *globalFetchLimiter) allow() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := time.Now()
	if now.Sub(g.window) >= time.Second {
		g.window = now
		g.count = 0
	}
	g.count++
	return g.count <= lazyGlobalFetchPerSec
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand.Read failing means the system PRNG is unavailable — a
		// startup-time fatal condition. Generating an all-zero key instead would
		// silently hand every agent the same credential, so fail fast.
		panic(fmt.Sprintf("crypto/rand unavailable: %v", err))
	}
	return hex.EncodeToString(b)
}

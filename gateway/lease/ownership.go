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
// Package lease implements ownership tracking for sandfs instances across
// multiple gateway processes, using etcd as the coordination backend.
// Ownership model (tolerance-first, confirmed-condition switching):
//   - Each sandfs is owned by exactly one gateway at a time.
//   - Ownership is stored in etcd as /sandswap/owner/{sandfs_id} — a PLAIN key
//     with NO lease. It persists until explicitly managed (create / update
//     node_id / owner-release delete / migrated-takeover CAS overwrite). No time-based expiry means no
//     "lease-expiry-triggers-switch" race (the racing-timer model.s root defect).
//   - The owner gateway caches ownership locally for fast-path access.
//   - Switching happens ONLY when a live participant confirms safety:
//     owner-release (owner releases): three-part chain — OnDisconnect(N) fired +
//     T_safe elapsed locally + N's presence key absent + self healthy —
//     then delete every sandfs owned by us on node N.
//     migrated-takeover (other takes over): owner's health key expired AND the sandfs's node
//     has migrated to us (live stream) with its presence key owned by us —
//     then CAS force-takeover.
//   - Transient failures default to tolerance: ownership is NOT moved on health
//     expiry or node disconnect alone; the agent sees 503+retry until a
//     confirmed condition lets a switch happen.
// Node tracking (see docs/how-it-works/resilience.md):
//   - node_id field in the ownership record is the sandfs's PLACEMENT: the
//     node it belongs to (last mounted on). It SURVIVES unmount — mount state
//     is transient and lives only in the owning gateway's memory. Written to
//     etcd only when the placement actually changes (first mount, re-placement,
//     or a takeover that preserves a non-empty placement / fills an empty one
//     with the claim's candidate); steady state is zero writes per
//     execution cycle.
//   - presence key /sandswap/node/{node_id}/presence (lease TTL = T_safe,
//     refreshed by heartbeats) is the etcd-persistent liveness signal: present
//     = connected or disconnected < T_safe; absent = disconnected >= T_safe.
//   - nodeSandfs (in-memory reverse index nodeID → set(sandfsID)) locates the
//     sandfs PLACED on a node for owner-release without scanning all ownership
//     keys.

package lease

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	pb "common/proto/stream"
	"gateway/stream"
	"go.etcd.io/etcd/api/v3/mvccpb"
	rpctypes "go.etcd.io/etcd/api/v3/v3rpc/rpctypes"
	clientv3 "go.etcd.io/etcd/client/v3"
)

// keyRange is a half-open [start, end) etcd key interval — the ownership
// loader's partition unit (the identity loader's local twin).
type keyRange struct{ start, end string }

var (
	// ErrOwnershipConflict means another gateway holds the sandfs and a takeover
	// condition (migrated takeover) is not satisfied. The handler 503s + retries.
	ErrOwnershipConflict = errors.New("ownership conflict: another gateway holds this sandfs")

	// ErrOwnerNodeDown means the gateway owns the sandfs but the sandlot node
	// where the sandfs is mounted is disconnected and its presence key is still
	// alive (disconnected < T_safe → tolerate; it may be reconnecting).
	ErrOwnerNodeDown = errors.New("owner node disconnected")

	// ErrOwnerNoCompute means THIS gateway owns the sandfs but currently has no
	// connected sandlot (node_count == 0, fault state). Rather than succeeding
	// at Claim and then 503-ing at pool.Acquire, the Claim returns this so the
	// handler emits a clean 503 + retry_after. No ownership is released, so a
	// transient sandlot blip does not churn ownership.
	ErrOwnerNoCompute = errors.New("owner gateway has no compute (fault state)")

	// ErrShedCooldown means THIS gateway recently shed ownership of the sandfs
	// (load shedding) and is still in the cooldown window, so it refuses
	// to re-claim a now-unowned sandfs. The handler surfaces this as a shed-503
	// (Retry-After + Connection: close) so the client re-resolves the DNS name
	// and lands on a peer that claims it. Distinct from ErrOwnershipConflict
	// (another gateway holds it) and ErrOwnerNoCompute (we hold it, no compute).
	ErrShedCooldown = errors.New("shed cooldown: recently shed this sandfs, retry to reach a peer")

	// ErrClaimRetryExhausted means the ownership claim loop burned its bounded
	// retry budget on repeated CAS losses or unparseable ownership state
	// (peers keep writing the key between our Get and our CAS). The claim is
	// deliberately bounded instead of unboundedly retrying: callers surface it
	// through the generic 503 + jittered retry path.
	ErrClaimRetryExhausted = errors.New("ownership claim: retry budget exhausted")

	// ErrCoverageLost is returned by BeginDispatch when the ownership
	// covering vanished (sweep/shed/takeover raced the in-flight mount).
	// Retryable: the retry re-claims and typically re-creates the record.
	ErrCoverageLost = errors.New("ownership coverage lost before mount dispatch")

	// Reap-tool refusal sentinels. The manual both-dead reclamation tools
	// (ReapStuckOwnership / ReapStuckNodeOwnership) refuse to touch a target
	// that may still be alive; these sentinels let the HTTP layer classify the
	// refusal as 409 with errors.Is instead of string-matching the message.
	ErrCannotReapSelf   = errors.New("target gateway is this gateway; cannot reap self")
	ErrOwnerStillAlive  = errors.New("owner gateway is alive; cannot reap a live owner")
	ErrNodeStillPresent = errors.New("node is still present (presence key alive or within T_safe); cannot reap a live node")
)

const (
	// ownershipPrefix is the etcd key prefix for ownership records.
	ownershipPrefix = "/sandswap/owner/"
	// healthPrefix is the etcd key prefix for gateway health records.
	healthPrefix = "/sandswap/health/"
	// gatewayPrefix is the etcd key prefix for the per-gateway routing registry
	// (/sandswap/gateway/{gateway_id} → {gateway_url, stream_addr}). A PLAIN key
	// (no lease): routing addresses are configuration, not liveness — they must
	// survive the gateway's death so DNS/307 can still resolve the owner during
	// tolerance, and are rewritten in O(1) when the gateway restarts with a
	// changed address. Orphaned keys from permanently-retired gateways are
	// reclaimed by ops.
	gatewayPrefix = "/sandswap/gateway/"
	// presencePrefix is the etcd key prefix for node presence records
	// (/sandswap/node/{node_id}/presence, lease TTL = T_safe).
	presencePrefix = "/sandswap/node/"

	// defaultTimingToleranceSec / defaultTimingWardenSec are the T_safe fallback
	// values used when a node connects with missing/degenerate timings (the
	// gateway refuses to derive a 60s T_safe from a 0/0 timing).
	defaultTimingToleranceSec = 300
	defaultTimingWardenSec    = 300

	// defaultCacheTTL is the default maximum age of a cached ownership entry
	// before Claim's fast path must re-validate against etcd (overridable via
	// -ownership-cache-ttl-sec; see OwnershipCache.cacheTTLNS for the safety
	// derivation and the validation ceiling).
	defaultCacheTTL = 30 * time.Second

	// RetryAfterMs is the retry-after hint (milliseconds) returned with
	// 503 responses for ownership-related errors.
	RetryAfterMs = 10000

	// retryAfterJitterFraction is the ± fraction applied by
	// JitteredRetryAfterMs (1/4 = ±25%).
	retryAfterJitterFraction = 4

	// ownershipLoadPageSize is the etcd GET page size for the ownership
	// full-load and the staleness/reap scans. Worst-case KV is ~330B (key
	// "/sandswap/owner/sandfs-<64>" + value JSON with long gateway/node ids +
	// gRPC overhead), so 3000 keys/page ≈ 1MB — under etcd's default
	// max-request-bytes (1.5MB) with margin. At a million ownership keys this
	// is 334 serial pages (~1-2s) instead of 1000 (~3-5s) per full load.
	ownershipLoadPageSize = 3000

	// ownershipLoadWorkers is the cold-load concurrency across the bucketed
	// ownership ranges ( follow-up: the serial 334-page scan of a 1M
	// keyspace was the human/exec gateway's cold-start long pole).
	ownershipLoadWorkers = 8

	// ownershipLoadMaxRetries / base bound one page's retry budget: pages read
	// at the pinned snapshot revision are idempotent, so a transient failed
	// page retries with backoff instead of failing the whole load.
	ownershipLoadMaxRetries = 3
	ownershipLoadRetryBase  = time.Second

	// healthRefreshInterval is how often the health key VALUE is refreshed.
	// The health key has NO lease — it is a plain key that is never expired by
	// etcd — so this refresh cadence IS the liveness carrier: last_healthy_ts
	// goes at most this stale for a live gateway, and every consumer judges
	// death by staleness thresholds of its own. It also doubles as the etcd
	// liveness probe for etcdAlive (fail-closed Claim fast-path guard).
	// node_count changes are pushed immediately via TouchHealth.
	healthRefreshInterval = 5 * time.Second

	// Staleness thresholds (defaults; overridable via -route-stale-sec /
	// -claim-dead-guard-sec / -alert-stale-sec). The health key is a PLAIN key
	// (no lease): it is never deleted by TTL, so "key absent" only means "the
	// owner never wrote it". Death is judged purely by the value's
	// last_healthy_ts — a continuous, queryable quantity each consumer
	// thresholds independently by the cost of judging wrong:
	//
	//   routeStaleThreshold — DNS routing + 307 redirect reroute. Judging wrong
	//     is cheap (a napping owner handles the request fine once it wakes), so
	//     this is the fastest threshold. A live owner refreshes every 5s and is
	//     never stale at 20s.
	//   claimDeadGuard — the idle-claim protection window: how long a dead-owned
	//     IDLE sandfs must stay dead-and-untouched before a peer force-takes-over
	//     via CAS. Judging wrong is expensive (robbing a live owner), so this
	//     sits well past route-stale to ride out naps/GC pauses, and far below
	//     T_safe so takeover stays possible within the resilience window.
	//     Mounted sandfs use the migrated-node signal instead; no time guard.
	//   alertStaleThreshold — the alert scan warns about an owner whose health
	//     record is this stale while sandfs are still pointed at it. Early and
	//     cheap: warn before the takeover-side guard would fire.
	//
	// Ordering invariant: route < alert < guard << T_safe.
	defaultRouteStaleThreshold = 20 * time.Second
	defaultClaimDeadGuard      = 45 * time.Second
	defaultAlertStaleThreshold = 30 * time.Second

	// defaultAlertScanInterval is the default staleness-alert-scan cadence
	// (overridable via -alert-scan-interval-sec). The scan is a full ownership
	// prefix sweep on the human gateway (O(all keys) + JSON decode per key) —
	// at a million keys every 30s costs ~1 core continuously, so large fleets
	// raise the interval (e.g. 300s); the per-request Claim path on exec
	// gateways is unaffected either way.
	defaultAlertScanInterval = 30 * time.Second

	// nodeHeartbeatInterval mirrors the sandlot's heartbeat cadence. It appears
	// in the presence-expiry time-order invariant (OnNodeConnect) because a
	// presence lease's clock effectively starts at the LAST keep-alive, which
	// can be a full heartbeat period before the event that stops them.
	nodeHeartbeatInterval = 30 * time.Second
)

// DefaultClaimDeadGuard is the default claim-dead-guard staleness threshold,
// exported for ops views (e.g. /stats Healthy) that judge gateway health
// without direct access to the configured ownership-cache thresholds.
const DefaultClaimDeadGuard = defaultClaimDeadGuard

var (
	// safeMarginSec is the fixed margin added on top of T_tolerance + T_warden to
	// derive T_safe (the presence-key TTL and the owner-release wait). Guarantees the core
	// invariant T_safe > T_tolerance + T_warden: the warden countdown releases a
	// stale mount at T_tolerance + T_warden, strictly before the presence key
	// expires at T_safe, so every cleanup path has finished by the time owner-release / migrated-takeover may
	// switch ownership. Package-level var (not const) so tests can shrink it.
	safeMarginSec = 60

	// ownerReleaseSweepIntervalNS is how often the owner-release background sweep checks the pending
	// disconnect set for three-part-chain releases, in nanoseconds. Package-level
	// var so tests can shrink it. Atomic because a test's Set-for-test write
	// races a PRECEDING test's still-draining sweep goroutine: NewOwnershipCache
	// spawns ownerReleaseSweepLoop whose NewTicker call reads the value, and
	// under -race that first read can still be unscheduled when the next test's
	// setter runs (caught by e2e/ownership.sh as a bare --- FAIL with no
	// assertion line — tc_run_go_suite's summary filter hides race reports).
	ownerReleaseSweepIntervalNS = int64(30 * time.Second)
)

// tSafeForTiming derives T_safe (presence-key TTL) from a node's reported
// timings: T_tolerance + T_warden + safeMarginSec. This is the value owner-release's
// local timer and the presence-key TTL both use, keeping the two anchors in
// lockstep. Degenerate/missing timings fall back to the defaults so a
// misconfigured node cannot get a pathologically short T_safe.
func tSafeForTiming(t *pb.NodeTiming) time.Duration {
	tol, wd := defaultTimingToleranceSec, defaultTimingWardenSec
	if t != nil {
		if t.GetToleranceSec() > 0 {
			tol = int(t.GetToleranceSec())
		}
		if t.GetWardenCountdownSec() > 0 {
			wd = int(t.GetWardenCountdownSec())
		}
	}
	return time.Duration(tol+wd+safeMarginSec) * time.Second
}

// DefaultTSafe is T_safe under the contract-default node timings
// (T_tolerance 300 + T_warden 300 + the 60s margin). Configuration that must
// respect the model before any node has reported its own timing validates
// against this value.
func DefaultTSafe() time.Duration { return tSafeForTiming(nil) }

// ValidateExecTiming checks the gateway-side timing headroom: a maximum-length
// sync exec plus one health-refresh tick and one node heartbeat must still fit
// inside T_safe. The health key is refreshed every healthRefreshInterval and a
// peer can only start judging death after that, while the presence key (TTL =
// T_safe) is the conservative anchor for "every mount release has finished";
// a max exec that could still be running at T_safe would let a live mount
// outlive the presence key, breaking that anchor.
func ValidateExecTiming(maxExecTimeout, tSafe time.Duration) error {
	if maxExecTimeout <= 0 {
		return fmt.Errorf("max exec timeout must be positive, got %v", maxExecTimeout)
	}
	if tSafe <= 0 {
		return fmt.Errorf("T_safe must be positive, got %v", tSafe)
	}
	headroom := healthRefreshInterval + maxExecTimeout + nodeHeartbeatInterval
	if headroom >= tSafe {
		return fmt.Errorf("health tick (%v) + max exec timeout (%v) + heartbeat (%v) = %v must be strictly below T_safe (%v): a maximum-length exec could still hold its mount when the presence key expires",
			healthRefreshInterval, maxExecTimeout, nodeHeartbeatInterval, headroom, tSafe)
	}
	return nil
}

// validateTiming reports whether a node's reported timings respect the model
// invariants: T_warden >= T_clean, T_safe > T_tolerance + T_warden (always
// holds given the +safeMarginSec derivation), and T_isolation > T_safe. The last
// is the deterministic-ownership anchor: the sandlot must stay isolated past
// T_safe so that by the time it can reconnect (and a peer can claim its sandfs),
// the old presence key has expired and the old mounts are provably released. A
// node violating it could re-present a still-mounted sandfs to a new gateway,
// risking a dual-mount. A node with zero timings is degenerate; the gateway
// rejects it rather than guessing.
func validateTiming(t *pb.NodeTiming) error {
	if t == nil {
		return fmt.Errorf("no timing reported")
	}
	if t.GetToleranceSec() == 0 || t.GetWardenCountdownSec() == 0 {
		return fmt.Errorf("degenerate timings (tolerance=%d, warden=%d)",
			t.GetToleranceSec(), t.GetWardenCountdownSec())
	}
	if t.GetCleanupSec() > t.GetWardenCountdownSec() {
		return fmt.Errorf("cleanup(%d) > warden(%d) violates T_warden >= T_clean",
			t.GetCleanupSec(), t.GetWardenCountdownSec())
	}
	// T_isolation > T_safe: the isolation phase must outlast the presence-key
	// TTL so reconnect cannot race the old ownership expiry. T_safe is derived
	// as T_tolerance + T_warden + margin; compare directly so the margin is
	// honored (a node with isolation exactly == tolerance+warden would be too
	// tight once the margin is added).
	tSafe := tSafeForTiming(t)
	isolation := time.Duration(t.GetIsolationSec()) * time.Second
	if t.GetIsolationSec() == 0 || isolation <= tSafe {
		return fmt.Errorf("isolation(%ds) must exceed T_safe(%v) so reconnect cannot race ownership expiry",
			t.GetIsolationSec(), tSafe)
	}
	return nil
}

// OwnershipValue is the JSON value stored in etcd at /sandswap/owner/{sandfs_id}.
// Exported for use in integration tests that simulate external etcd writes.
type OwnershipValue struct {
	GatewayID string `json:"gateway_id"`
	// NodeID is the sandfs's PLACEMENT — the node it belongs to (last mounted
	// on). It survives unmount and is preserved across takeovers; "" only for
	// records never yet placed. Mount state is transient and NOT stored here.
	NodeID string `json:"node_id"`
	// Generation is bumped on create/takeover only; node_id publishes are
	// guarded by ModRevision CAS, not by this counter.
	Generation uint64 `json:"generation"`
	// Routing addresses deliberately live in /sandswap/gateway/{gateway_id}, not
	// here: per-sandfs copies would go stale on a gateway restart with a changed
	// address (rewriting N keys), whereas the registry is one plain key per
	// gateway that survives its death for tolerance.
}

// GatewayHealthValue is the JSON value at /sandswap/health/{gateway_id}.
// It carries liveness (last_healthy_ts staleness — the key is PLAIN, no lease)
// and the connected-sandlot count. Routing addresses deliberately live in
// /sandswap/gateway/{gateway_id}, NOT here: the registry is a plain key that
// survives the gateway's death for tolerance (DNS/307 still resolve the
// owner), and liveness is judged per-consumer by staleness thresholds rather
// than key disappearance. Health staleness is only an owner-release /
// migrated-takeover condition, never a switch trigger on its own.
type GatewayHealthValue struct {
	LastHealthyTS string `json:"last_healthy_ts"`
	// NodeCount is the number of sandlot nodes currently connected. 0 = no
	// compute (fault state); the DNS excludes such a gateway from routing.
	NodeCount int `json:"node_count"`
}

// GatewayRegistryValue is the JSON value at /sandswap/gateway/{gateway_id}.
// It holds the gateway's routing addresses as CONFIGURATION (plain key, no
// lease): they change only when the gateway is reconfigured, never because the
// gateway is momentarily unhealthy. The DNS and the 307 redirect resolve a
// sandfs via ownership.gateway_id → this key's gateway_url, so a gateway that
// restarts with a changed URL rewrites ONE key (O(1)) and every owned sandfs
// immediately routes to the new address — no per-sandfs stale copies.
type GatewayRegistryValue struct {
	GatewayURL string `json:"gateway_url,omitempty"` // base URL agents use to reach this gateway (307 Location, owner-aware DNS target)
	StreamAddr string `json:"stream_addr,omitempty"` // host:port sandlots use to reconnect to THIS gateway
}

// ownershipEntry is the in-memory cache entry for a sandfs's ownership.
//
// State split (tolerance-first: transient facts stay in the process that owns
// them; etcd carries only the stable ownership facts):
//   - placement  — STABLE, persisted. Which node this sandfs belongs to (the
//     last node it was mounted on). Survives unmount: it is an affinity/
//     placement fact, not mount state. Written to etcd only when it changes.
//   - mounted    — TRANSIENT, memory-only, never in etcd. Whether the sandfs
//     is mounted right now (only meaningful while the placement node is
//     connected to us).
//   - suspect    — TRANSIENT, memory-only. Orphan-uncertainty: the sandfs is
//     placed on a node we are NOT connected to and we cannot vouch that no
//     stale mount survives there (it was mounted when the node disconnected,
//     or our process restarted and the node has not reconnected since).
//     Mounting anywhere else could double-mount with that orphan, so Claim
//     503s until the node reconnects (sandlot releases every mount before
//     connecting — the reconnect-clean invariant) or its presence key expires
//     (≥ T_safe → every release path has provably run).
type ownershipEntry struct {
	gatewayID string
	placement string // "" = never placed; otherwise the node this sandfs belongs to
	mounted   bool   // transient: currently mounted (memory only)
	suspect   bool   // transient: orphan-uncertain (see type doc)
	// ownerReleasing marks entries whose ownership record the owner-release
	// sweep is deleting right now. While set (and within
	// ownerReleaseClaimWindow of releasingSince), Claim refuses to re-serve
	// the sandfs: a lazy re-claim in the [cache teardown → etcd delete
	// visible] window would legitimately remount the sandfs (presence is
	// already absent — the sweep's own condition), and the pending delete
	// would then strand that fresh mount without an ownership record (a peer
	// could claim and dual-mount). Cleared by the watch DELETE (entry
	// forgotten), by a fresh create/takeover, or by the window elapsing (the
	// delete failed; the lazy claim path is the backstop).
	ownerReleasing bool
	releasingSince time.Time
	dispatching    bool // cold mount in flight (BeginDispatch→NoteMounted/EndDispatch); sweep+shed must not delete a dispatching entry's record
	// published is the placement value we last know etcd holds — seeded from
	// etcd reads and the watch echo of our own writes. Write elision: a mount
	// whose placement equals published needs no etcd write (the common case
	// under node affinity — steady state is zero writes).
	published  string
	generation uint64
	// modRev is the etcd ModRevision at which we last observed this record
	// (full-load, claim read, watch event, or our own CAS put). It is the
	// compare-and-swap baseline for publishing placement changes in a single
	// round trip; 0 means "no etcd observation yet" (never write blind —
	// ModRevision of a missing key reads as 0, so a 0 compare would recreate
	// a deleted key).
	modRev    int64
	claimTime time.Time // when this entry was last validated against etcd
}

// entryView is an immutable snapshot of the ownershipEntry fields the Claim
// fast path validates. Claim reads these fields WITHOUT holding oc.mu (the
// fast path must stay lock-cheap), while the watch loop / OnNodeDisconnect /
// resolveOrphanSuspect mutate them under oc.mu — reading the live entry would
// be a data race (string fields can even tear). The snapshot is taken under
// the lock in one copy; checkEntry then validates the copy.
type entryView struct {
	gatewayID      string
	placement      string
	mounted        bool
	suspect        bool
	ownerReleasing bool
	releasingSince time.Time
}

// view returns an immutable snapshot of the entry's fast-path-visible fields.
// Caller must hold oc.mu (or otherwise have exclusive access).
func (e *ownershipEntry) view() entryView {
	return entryView{
		gatewayID:      e.gatewayID,
		placement:      e.placement,
		mounted:        e.mounted,
		suspect:        e.suspect,
		ownerReleasing: e.ownerReleasing,
		releasingSince: e.releasingSince,
	}
}

// ownerReleaseClaimWindow bounds how long an owner-releasing tombstone refuses
// claims after the sweep flagged it. The etcd delete normally lands within
// milliseconds (watch DELETE forgets the entry, clearing the flag); the window
// only matters when the batched delete failed outright — past it, claims
// resume and the leftover key is covered by the lazy claim path (the same
// backstop deleteOwnershipBatch already documents).
const ownerReleaseClaimWindow = 30 * time.Second

// OwnershipCache manages sandfs ownership via etcd with local caching.
// In single-node mode (no etcd), this is nil and ownership checks are skipped.
type OwnershipCache struct {
	client    *clientv3.Client
	gatewayID string
	streamSrv *stream.Server // for checking node connectivity
	logger    *slog.Logger

	// maxExecTimeout is the gateway's configured sync-exec cap, used by
	// OnNodeConnect to reject a node whose reported T_safe cannot absorb a
	// maximum-length exec. Set from the gateway config; the contract default is
	// only a fallback for tests/standalone constructors.
	maxExecTimeout time.Duration

	mu    sync.Mutex
	cache map[string]*ownershipEntry // sandfsID → entry

	// nodeSandfs is the reverse index nodeID → set(sandfsID): which sandfs are
	// PLACED on which node (placement index — survives unmount, unlike mount
	// state). Updated on placement changes (first mount / re-placement /
	// owner-release delete / migrated-takeover watch takeover) and rebuilt from
	// the full-load at restart. Lets owner-release locate a node's sandfs
	// without scanning all ownership keys (tens of thousands).
	nodeSandfs map[string]map[string]struct{}

	// pendingOwnerRelease holds nodes that disconnected from us (stream OnDisconnect),
	// mapped to their disconnect time. The owner-release sweep promotes a node to release
	// once disconnect + T_safe has elapsed and its presence key is gone. A
	// reconnect (OnNodeConnect) removes the node, canceling the pending owner-release.
	pendingOwnerRelease map[string]time.Time

	// presenceLeases tracks each connected node's presence lease so heartbeats
	// can KeepAlive it. Removed on disconnect (the key then naturally expires
	// T_safe after the last heartbeat — the exact owner-release anchor).
	presenceLeases map[string]clientv3.LeaseID

	// presenceTTLs records each node's T_safe (derived from its timing) for the
	// owner-release sweep's wait. Keyed per node (timings can differ across nodes).
	presenceTTLs map[string]time.Duration

	// presenceWardenSecs records each connected node's reported warden countdown
	// (NodeHello timing), so UpdateFenceThreshold can re-validate the connect-time
	// invariant T_safe > fence + warden + heartbeat against EVERY live node when
	// the fence threshold changes at runtime (hot-reload). Keyed per node and
	// cleared on disconnect, exactly like presenceTTLs.
	presenceWardenSecs map[string]int

	// presencePending marks nodes that CONNECTED while their presence key could
	// not be written (etcd unavailable at connect). Instead of rejecting the
	// node — which would couple an etcd outage to gateway capacity and let the
	// outage escalate into sandlot CLEANING — the node is admitted and flagged
	// here: regrants are retried on every heartbeat and on etcd recovery, and
	// the lazy owner-release path tolerates a pending node's absent key
	// (in-memory truth: the node IS connected to us right now). Guarded by mu.
	presencePending map[string]bool

	// regrantMu serializes presence-key (re)grants so two concurrent regrants
	// for the same node cannot interleave Grant/Put and leave the key bound to
	// an untracked lease (no KeepAlive → key silently expires). Regrants are
	// rare (only on lease loss/keep-alive failure), so a global mutex is fine.
	regrantMu sync.Mutex

	// recentlyShed tracks sandfs this gateway has voluntarily shed ownership of
	// (load shedding) mapped to the expiry of the cooldown window. During
	// the cooldown, the gateway refuses to re-claim the sandfs (returns shed-503
	// instead of createOwnership) so a peer has a window to claim it. This closes
	// the race where, after a release, the DNS cache window routes the client back
	// to us and we'd immediately re-grab ownership — undoing the shed. Entries are
	// evicted by ShedCooldownSweep (background) and on successful peer-takeover
	// (watch sees a non-self owner re-create the key). Guarded by shedMu.
	recentlyShed map[string]time.Time
	shedMu       sync.Mutex

	// deadSince records when this gateway first observed a dead owner for an
	// IDLE sandfs (node_id empty). It is the time-protected CAS-claim clock: a
	// peer does not immediately grab a dead-owned idle sandfs — it waits the
	// claim-dead-guard window (well past the route-stale threshold, so a nap
	// that recovers never triggers it) so a transiently-unreachable but
	// recovering owner is not robbed of sandfs it still owns. Once the guard
	// elapses (and the owner is still dead), forceTakeover CAS-claims it.
	// Seeded on first dead-idle observation; cleared on owner revival,
	// successful takeover, or the background sweep (mirroring the reaper).
	// Guarded by deadSinceMu.
	deadSince   map[string]time.Time
	deadSinceMu sync.Mutex

	// fenced is the etcd-partition self-fence state: set by the health loop
	// BEFORE it releases every mount, cleared on recovery. While set, no mount
	// confirmation may be recorded — the fence's promise is "this gateway holds
	// no live mount once fencing has run", so a cold mount dispatched before
	// the fence that confirms afterwards is torn down instead. Guarded by mu.
	fenced bool

	// etcdAlive tracks whether the last health-key refresh recently succeeded.
	// When false (etcd partitioned/unreachable), the Claim fast-path is DISABLED
	// so a mount can't be served from the stale cache (fail-closed): without
	// this, UpdateNodeID refreshes claimTime on every mount and the fast-path
	// cache never expires during active traffic + etcd outage. The health
	// refresh interval (healthRefreshInterval) bounds the window.
	etcdAlive atomic.Bool

	// watchDone signals the watch loop, health refresh loop, and owner-release
	// sweep to stop.
	watchDone chan struct{}

	// healthDone signals the health loop to stop.
	healthDone chan struct{}

	// readiness: true once startup recovery (ownership full-load + nodeSandfs
	// rebuild) is complete. The gateway serves agent traffic only after Ready().
	ready atomic.Bool

	// fullLoadRev is the etcd revision at which the full-load snapshot was read.
	// StartWatch begins from fullLoadRev+1 so no ownership events between the
	// snapshot and the watch start are missed.
	fullLoadRev int64

	// watchRev is the revision through which the watch loop has consumed and
	// applied events (seeded from the full-load snapshot revision, advanced
	// after every applied batch). A watch (re)subscription starts at
	// watchRev+1, so restarting the watch never replays already-applied
	// history. Mu-guarded; 0 means "no observation yet" (subscribe from
	// current).
	watchRev int64

	// closeOnce makes Close idempotent: closing watchDone/healthDone twice
	// would panic. Tests and graceful-shutdown paths may call Close more than once.
	closeOnce sync.Once

	// Routing addresses: how other components reach THIS gateway. Folded into
	// the health key (writeHealthKey) and into each ownership key we create
	// (createOwnership/forceTakeover) so the DNS/307 can read our address from
	// the ownership record. Set via SetRoutingAddrs before StartHealthLoop.
	gatewayURL string // base URL for agent traffic (307 Location, DNS CNAME target)
	streamAddr string // host:port for sandlot reconnect to this gateway

	// nodeCountFn, when set, overrides the stream-server connection count used
	// for the health-key node_count. Tests use it to simulate a healthy
	// (compute-present) gateway without a real sandlot connection; nil streamSrv
	// in human mode yields 0, which is correct (the human gateway never claims).
	nodeCountFn func() int

	// Etcd-partition self-fence. When the health-key write has failed
	// continuously for fenceThreshold, this gateway can no longer act as an
	// owner (no presence keep-alives, no health refresh, claims fail closed) —
	// yet in etcd its traces are indistinguishable from a dead gateway's. The
	// fence removes that ambiguity by RELEASING everything it holds:
	// unmountAllFn actively unmounts every mount we own, over the node streams
	// which stay CONNECTED. Keeping the streams is deliberate: the nodes are
	// healthy, their VM pools stay warm, and recovery is in-place — whereas
	// dropping them would push each node through T_tolerance + T_clean +
	// T_isolation (~17min of lost capacity) and would make the release finish
	// only at fence + T_tolerance + T_clean, which no longer fits under T_safe.
	// Active release finishes at fence + T_clean instead, so the original
	// T_safe = T_tolerance + T_warden + 60s formula needs no fence term.
	// fenceFn is invoked with true on fencing and false on recovery so callers
	// can gate other work; nil in local/test mode (never fences).
	fenceFn        func(fenced bool)
	unmountAllFn   func() int
	fenceThreshold time.Duration
	etcdDownSince  time.Time

	// compensateMount tears down a live mount whose ownership covering was
	// lost (see compensateUncoveredMount). Wired via SetMountCompensator;
	// nil in tests.
	compensateMount func(sandfsID, nodeID string)

	// testNodeConnectedFn, when set, overrides the streamSrv connectivity check
	// used by migratedTakeoverAllowed (the "node migrated to us" condition). Tests use it
	// to simulate a live node stream without a real gRPC connection; nil = use
	// streamSrv (production).
	testNodeConnectedFn func(nodeID string) bool

	// Staleness thresholds (configurable via SetStalenessThresholds). See the
	// default* consts. They turn the health key's last_healthy_ts into a
	// per-consumer liveness signal — the health key has no lease, so staleness
	// is the ONLY death signal.
	routeStaleThreshold time.Duration
	claimDeadGuard      time.Duration
	alertStaleThreshold time.Duration

	// cacheTTLNS is the Claim fast-path freshness window (nanoseconds; default
	// defaultCacheTTL, overridable via SetCacheTTL / -ownership-cache-ttl-sec).
	// Atomic so Claim's hot path reads it without oc.mu — it is the etcd
	// read-load lever: the steady revalidation rate is (actively-queried sandfs
	// owned by this gateway) / TTL, and the reads are linearizable, so large
	// fleets raise it (see SetCacheTTL for the safety ceiling derivation).
	cacheTTLNS atomic.Int64

	// alertScanIntervalNS is the staleness-alert-scan cadence (nanoseconds;
	// default defaultAlertScanInterval, overridable via SetAlertScanInterval /
	// -alert-scan-interval-sec). Atomic so the scan loop re-derives its timer
	// on hot-reload (mirrors the lease reaper's re-derive pattern).
	alertScanIntervalNS atomic.Int64

	// releaseBatchSem bounds concurrent owner-release delete Txns across ALL
	// nodes being released (a node can carry thousands of sandfs — hundreds of
	// 128-key batches fired at once would burst etcd with concurrent Txns and
	// delay every other write; 8 in flight spreads the same deletes over a few
	// seconds, well inside the tombstone claim window). Created in the
	// constructors; nil-safe (tests construct via NewOwnershipCacheForTest,
	// which also initializes it).
	releaseBatchSem chan struct{}
}

// NewOwnershipCache creates a new OwnershipCache. The cache does NOT start
// background goroutines — call StartHealthLoop, StartWatch, and (exec gateway
// only) StartOwnerReleaseSweep separately.
func NewOwnershipCache(client *clientv3.Client, gatewayID string, streamSrv *stream.Server, logger *slog.Logger) (*OwnershipCache, error) {
	if logger == nil {
		logger = slog.Default()
	}

	oc := &OwnershipCache{
		client:              client,
		gatewayID:           gatewayID,
		streamSrv:           streamSrv,
		logger:              logger,
		cache:               make(map[string]*ownershipEntry),
		nodeSandfs:          make(map[string]map[string]struct{}),
		pendingOwnerRelease: make(map[string]time.Time),
		presenceLeases:      make(map[string]clientv3.LeaseID),
		presenceTTLs:        make(map[string]time.Duration),
		presenceWardenSecs:  make(map[string]int),
		presencePending:     make(map[string]bool),
		recentlyShed:        make(map[string]time.Time),
		deadSince:           make(map[string]time.Time),
		watchDone:           make(chan struct{}),
		healthDone:          make(chan struct{}),

		routeStaleThreshold: defaultRouteStaleThreshold,
		claimDeadGuard:      defaultClaimDeadGuard,
		alertStaleThreshold: defaultAlertStaleThreshold,
	}
	oc.cacheTTLNS.Store(int64(defaultCacheTTL))
	oc.alertScanIntervalNS.Store(int64(defaultAlertScanInterval))
	oc.releaseBatchSem = make(chan struct{}, releaseBatchConcurrency)

	// Full-load the ownership cache and rebuild nodeSandfs. Blocking — the
	// gateway must not serve agent traffic (readiness) until ownership state is
	// recovered. Degrades to lazy re-claim on load failure.
	if err := oc.bootstrapOwnership(context.Background()); err != nil {
		return nil, err
	}

	// Ownership keys AND the health key have no lease, so there is no
	// keep-alive — the health refresh loop (started by StartHealthLoop) drives
	// etcdAlive from the success/failure of the health-key Put.
	oc.etcdAlive.Store(true) // assume healthy until the first refresh proves otherwise

	return oc, nil
}

// JitteredRetryAfterMs widens a retry-after hint by a uniform ±25%. Correlated
// failures (one node or gateway dying) 503 all their sandfs agents at the same
// instant; clients that retry exactly retry_after_ms later would arrive in
// synchronized waves every interval for the whole resilience window. Jitter at
// the server de-synchronizes even naive clients. Applied ONLY to the
// resilience-clock-bounded class (owner-node-down, ownership-conflict,
// no-compute) where such herds form; local transients (unmount-in-progress,
// concurrent-mount, no-available-sandbox, sandbox-cleaning) keep exact hints.
func JitteredRetryAfterMs(base int64) int {
	if base <= 0 {
		return int(base)
	}
	delta := base / retryAfterJitterFraction
	return int(base - delta + rand.Int63n(2*delta+1))
}

// bootstrapOwnership performs the startup ownership recovery: paginated
// full-load of the ownership prefix, cache population, and nodeSandfs rebuild.
// Ownership keys have no lease, so every key owned by us is real and
// re-adopted as-is — there is no lease recovery and no expiry to wait out.
func (oc *OwnershipCache) bootstrapOwnership(ctx context.Context) error {
	if oc.client == nil {
		oc.ready.Store(true)
		return nil
	}

	loaded, loadErr := oc.fullLoadOwnership(ctx)
	if loadErr != nil {
		// Degrade to lazy claim for SERVING, but do not accept the degradation
		// as permanent: with nodeSandfs empty, the owner-release sweep and the
		// manual reap tools lose every sandfs they never saw a request for (a
		// dead node's unrequested sandfs would stay owned by us forever). A
		// background retry rebuilds the index as soon as etcd is reachable.
		oc.logger.Warn("ownership full-load failed; degrading to lazy claim (background retry started)", "error", loadErr)
		go oc.retryBootstrapLoop()
	}

	oc.mu.Lock()
	for _, it := range loaded {
		if _, exists := oc.cache[it.sandfsID]; !exists {
			oc.cache[it.sandfsID] = it.entry
		}
		// Rebuild the placement index from each key's node_id (no per-key etcd
		// cost — the paginated GET above already read them).
		if it.entry.placement != "" {
			if oc.nodeSandfs[it.entry.placement] == nil {
				oc.nodeSandfs[it.entry.placement] = make(map[string]struct{})
			}
			oc.nodeSandfs[it.entry.placement][it.sandfsID] = struct{}{}
		}
	}
	oc.mu.Unlock()

	oc.logger.Info("ownership full-load complete", "self", len(loaded))
	oc.ready.Store(true)
	return nil
}

// ownershipLoaded is a self-owned ownership record read during the full-load.
type ownershipLoaded struct {
	sandfsID string
	entry    *ownershipEntry
}

// ownershipLoadRanges partitions the ownership keyspace ("/sandswap/owner/
// sandfs-<8hex>") into disjoint half-open ranges: a below-'0' catch-all, 15
// hex buckets, and an 'f'-upward catch-all — the same bucketing the identity
// loader uses, so no bucket is a serial chain and the union is exact.
func ownershipLoadRanges() []keyRange {
	bp := ownershipPrefix + "sandfs-"
	ranges := []keyRange{{ownershipPrefix, bp + "0"}}
	for i := 0; i < len(ownerHexDigits)-1; i++ {
		ranges = append(ranges, keyRange{
			bp + string(ownerHexDigits[i]),
			bp + string(ownerHexDigits[i+1]),
		})
	}
	return append(ranges, keyRange{bp + "f", clientv3.GetPrefixRangeEnd(ownershipPrefix)})
}

const ownerHexDigits = "0123456789abcdef"

// fullLoadOwnership reads the ownership keyspace (bucketed, parallel, pinned
// to ONE snapshot revision) and returns the records owned by THIS gateway.
// The revision pin is a correctness requirement of the parallel form: with
// workers reading at drifting revisions, an update landing between a slow
// worker's read and the (first-completed-page) watch seed would never be
// replayed by the watch. A compaction error on the pinned revision falls
// back to one unpinned serial pass (rare: requires compaction within the
// load window).
func (oc *OwnershipCache) fullLoadOwnership(ctx context.Context) ([]ownershipLoaded, error) {
	loaded, err := oc.fullLoadOwnershipOnce(ctx, true)
	if err == nil {
		return loaded, nil
	}
	if errors.Is(err, rpctypes.ErrCompacted) || strings.Contains(err.Error(), "required revision has been compacted") {
		oc.logger.Warn("ownership snapshot revision compacted mid-load; retrying at current revision", "error", err)
		return oc.fullLoadOwnershipOnce(ctx, false)
	}
	return nil, err
}

func (oc *OwnershipCache) fullLoadOwnershipOnce(ctx context.Context, pinned bool) ([]ownershipLoaded, error) {
	var snapRev int64
	if pinned {
		head, err := oc.client.Get(ctx, ownershipPrefix, clientv3.WithLimit(1))
		if err != nil {
			return nil, fmt.Errorf("etcd get ownership snapshot revision: %w", err)
		}
		snapRev = head.Header.Revision
	}

	ranges := ownershipLoadRanges()
	sem := make(chan struct{}, ownershipLoadWorkers)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var firstErr error
	var loaded []ownershipLoaded

	for _, r := range ranges {
		wg.Add(1)
		go func(r keyRange) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			local, err := oc.loadOwnershipRange(ctx, r, snapRev, pinned)
			if err != nil {
				mu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				mu.Unlock()
				return
			}
			mu.Lock()
			loaded = append(loaded, local...)
			mu.Unlock()
		}(r)
	}
	wg.Wait()
	if firstErr != nil {
		return nil, firstErr
	}

	// Seed the revision bookkeeping from the snapshot (first SUCCESSFUL load
	// only — a background retryBootstrap rebuild must not rewind a watch that
	// has already advanced past its revision).
	oc.mu.Lock()
	if oc.fullLoadRev == 0 {
		oc.fullLoadRev = snapRev
	}
	if oc.watchRev == 0 {
		oc.watchRev = snapRev
	}
	oc.mu.Unlock()
	return loaded, nil
}

// loadOwnershipRange pages one disjoint ownership range, filtering to this
// gateway's records. Retries a failed page with backoff (idempotent when
// pinned); soft-degrades are caller-invisible — only a hard failure surfaces.
func (oc *OwnershipCache) loadOwnershipRange(ctx context.Context, r keyRange, snapRev int64, pinned bool) ([]ownershipLoaded, error) {
	var loaded []ownershipLoaded
	start := r.start
	retries := 0
	for {
		opts := []clientv3.OpOption{clientv3.WithRange(r.end), clientv3.WithLimit(ownershipLoadPageSize)}
		if pinned {
			opts = append(opts, clientv3.WithRev(snapRev))
		}
		resp, err := oc.client.Get(ctx, start, opts...)
		if err != nil {
			retries++
			if retries > ownershipLoadMaxRetries {
				return nil, fmt.Errorf("etcd get ownership range [%s,%s) after %d retries: %w", r.start, r.end, ownershipLoadMaxRetries, err)
			}
			delay := ownershipLoadRetryBase << (retries - 1)
			oc.logger.Warn("ownership load page retry", "range", r.start+".."+r.end, "attempt", retries, "error", err)
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			continue
		}
		retries = 0
		for _, kv := range resp.Kvs {
			sandfsID := strings.TrimPrefix(string(kv.Key), ownershipPrefix)
			var val OwnershipValue
			if err := json.Unmarshal(kv.Value, &val); err != nil {
				continue
			}
			if val.GatewayID != oc.gatewayID {
				continue // owned by another gateway — ignore (not claimed here)
			}
			entry := &ownershipEntry{
				gatewayID:  val.GatewayID,
				placement:  val.NodeID,
				published:  val.NodeID,
				generation: val.Generation,
				modRev:     kv.ModRevision,
				claimTime:  time.Now(),
			}
			// Post-restart the mount state of every placed sandfs is unknown: a
			// mount dispatched before the crash may still be live on its node,
			// and that node has not reconnected yet (reconnecting nodes release
			// every mount before connecting — the reconnect-clean invariant).
			// Mark placed entries on unreachable nodes suspect; OnConnect (node
			// came back clean) or presence expiry (≥ T_safe) resolves.
			if entry.placement != "" && !oc.nodeReachable(entry.placement) {
				entry.suspect = true
			}
			loaded = append(loaded, ownershipLoaded{
				sandfsID: sandfsID,
				entry:    entry,
			})
		}
		if !resp.More {
			return loaded, nil
		}
		start = string(resp.Kvs[len(resp.Kvs)-1].Key) + "\x00"
	}
}

// retryBootstrapLoop re-runs the ownership full-load with backoff until it
// succeeds, then merges the records into the cache and rebuilds nodeSandfs.
// Started only when the startup full-load failed (etcd unreachable at boot).
// Serving keeps working throughout via the lazy Claim path; what this restores
// is the index-backed machinery (owner-release sweep, reap tools) that needs
// the full placement picture. Exits on success or Close.
func (oc *OwnershipCache) retryBootstrapLoop() {
	backoff := 2 * time.Second
	for {
		select {
		case <-oc.watchDone:
			return
		case <-time.After(backoff):
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
		loaded, err := oc.fullLoadOwnership(context.Background())
		if err != nil {
			oc.logger.Warn("ownership full-load retry failed", "error", err, "nextBackoff", backoff.String())
			continue
		}
		oc.mu.Lock()
		for _, it := range loaded {
			if _, exists := oc.cache[it.sandfsID]; !exists {
				oc.cache[it.sandfsID] = it.entry
			}
			if it.entry.placement != "" {
				if oc.nodeSandfs[it.entry.placement] == nil {
					oc.nodeSandfs[it.entry.placement] = make(map[string]struct{})
				}
				oc.nodeSandfs[it.entry.placement][it.sandfsID] = struct{}{}
			}
		}
		oc.mu.Unlock()
		oc.logger.Info("ownership full-load retry succeeded; placement index rebuilt", "self", len(loaded))
		return
	}
}

// Ready reports whether startup recovery (ownership full-load) is complete.
// The gateway's /ready endpoint serves 200 only after Ready.
func (oc *OwnershipCache) Ready() bool {
	return oc.ready.Load()
}

// TouchHealth immediately refreshes the health key value (event-driven). Called
// on sandlot connect/disconnect so node_count changes publish without waiting
// for the safety-net ticker.
func (oc *OwnershipCache) TouchHealth() {
	oc.writeHealthKey()
}

// NewOwnershipCacheForTest builds an OwnershipCache with a nil etcd client for
// tests (the nil-client guards make every method safe without etcd). Not used
// in production.
func NewOwnershipCacheForTest(gatewayID string) *OwnershipCache {
	oc := &OwnershipCache{
		gatewayID:           gatewayID,
		logger:              slog.Default(),
		cache:               make(map[string]*ownershipEntry),
		nodeSandfs:          make(map[string]map[string]struct{}),
		pendingOwnerRelease: make(map[string]time.Time),
		presenceLeases:      make(map[string]clientv3.LeaseID),
		presenceTTLs:        make(map[string]time.Duration),
		presenceWardenSecs:  make(map[string]int),
		presencePending:     make(map[string]bool),
		watchDone:           make(chan struct{}),
		healthDone:          make(chan struct{}),
		recentlyShed:        make(map[string]time.Time),
		nodeCountFn:         func() int { return 1 },
	}
	oc.cacheTTLNS.Store(int64(defaultCacheTTL))
	oc.alertScanIntervalNS.Store(int64(defaultAlertScanInterval))
	oc.releaseBatchSem = make(chan struct{}, releaseBatchConcurrency)
	// Tests assume etcd is reachable so the fast-path cache is exercised.
	oc.etcdAlive.Store(true)
	return oc
}

// SetOwnedForTest inserts a cache entry owned by this gateway with the given
// node_id. Test-only helper.
func (oc *OwnershipCache) SetOwnedForTest(sandfsID, nodeID string) {
	oc.mu.Lock()
	defer oc.mu.Unlock()
	oc.cache[sandfsID] = &ownershipEntry{
		gatewayID:  oc.gatewayID,
		placement:  nodeID,
		published:  nodeID,
		claimTime:  time.Now(),
		generation: 1,
	}
	if nodeID != "" {
		if oc.nodeSandfs[nodeID] == nil {
			oc.nodeSandfs[nodeID] = make(map[string]struct{})
		}
		oc.nodeSandfs[nodeID][sandfsID] = struct{}{}
	}
}

// Close stops all background goroutines. Idempotent: safe to call multiple times
// (double-close of the done channels would otherwise panic). The health key is
// a plain key with no lease, so nothing to revoke on shutdown — the key simply
// goes stale and peers judge this gateway dead by its staleness thresholds.
func (oc *OwnershipCache) Close() {
	oc.closeOnce.Do(func() {
		close(oc.watchDone)
		close(oc.healthDone)
	})
}

// Claim ensures this gateway owns the sandfs and returns its placement node
// for Acquire routing. On the fast path (cached + valid), this is a pure
// in-memory operation (~0.001ms). On the slow path (first access or cache
// expired), it does an etcd Get + CAS (~2ms).
//
// candidate is the node this gateway would place the sandfs on right now
// (pool.PeekNode — selection only, no capacity reserved). It is written into
// the record when the claim CREATES or TAKES OVER it, so a record's node_id is
// never empty while a mount could exist: the ONLY way to reach node_id == "" is
// that node selection itself found nothing, i.e. no mount was ever dispatched.
// That invariant is what lets the takeover path treat an empty placement as
// "provably unmounted" instead of needing a stricter time horizon. It costs no
// extra etcd round trip — the claim CAS was happening anyway — and nothing on
// the mount critical path.
//
// Returns:
//   - placement: hint for pool.Acquire routing (may be "" if never placed)
//   - error: ErrOwnershipConflict, ErrOwnerNodeDown, ErrOwnerNoCompute, or etcd
//     errors
func (oc *OwnershipCache) Claim(sandfsID, candidate string) (placement string, err error) {
	oc.mu.Lock()
	entry, ok := oc.cache[sandfsID]
	var view entryView
	fresh := false
	if ok {
		view = entry.view()
		fresh = time.Since(entry.claimTime) < oc.cacheTTL()
	}
	oc.mu.Unlock()

	// Fast path: cache hit + fresh + etcd reachable. The etcdAlive guard is
	// critical: without it, UpdateNodeID refreshes claimTime on every mount and
	// the cache never expires during active traffic + etcd outage, so the
	// fast-path would serve from a stale cache indefinitely. When etcd is down,
	// fall through to the slow path which fails-closed (etcd Get error -> 503).
	if ok && fresh && oc.etcdAlive.Load() {
		preferred, err := oc.checkEntry(view)
		if oc.client != nil && (err == ErrOwnerNodeDown || err == ErrOwnerNoCompute) {
			// The cache cannot decide these when etcd is available: ErrOwnerNodeDown
			// must fall through to the lazy owner-release path (presence key decides tolerate
			// vs release), and ErrOwnerNoCompute re-validates the node set in etcd.
			// With a nil client (single-node/test mode) the fast-path error stands.
			return oc.claimFromEtcd(sandfsID, candidate)
		}
		return preferred, err
	}

	// Slow path: validate against etcd.
	return oc.claimFromEtcd(sandfsID, candidate)
}

// cacheTTL returns the current Claim fast-path freshness window. Atomic read,
// no lock — this is on the per-request hot path.
func (oc *OwnershipCache) cacheTTL() time.Duration {
	return time.Duration(oc.cacheTTLNS.Load())
}

// checkEntry validates a snapshot of a cached ownership entry and returns the
// placement node or an appropriate error. It does NOT make etcd calls (fast
// path); the orphan-suspect resolution that needs etcd (presence check) lives
// in claimOnce's slow path — an ErrOwnerNodeDown here makes the caller fall
// through to it.
func (oc *OwnershipCache) checkEntry(view entryView) (string, error) {
	if view.gatewayID != oc.gatewayID {
		return "", ErrOwnershipConflict
	}

	// Fault state: we own this sandfs but have NO compute (no sandlot connected).
	// Refuse to serve (503 + retry). No ownership release -> no churn.
	if oc.currentNodeCount() == 0 {
		return "", ErrOwnerNoCompute
	}

	// Orphan-uncertain: placed on a node we cannot vouch for (see
	// ownershipEntry.suspect). Mounting anywhere else could double-mount with
	// the unaccounted orphan. The slow path resolves it against the presence
	// key before serving.
	if view.suspect {
		return "", ErrOwnerNodeDown
	}

	// Owner-release tombstone: the sweep is deleting this record right now.
	// Re-serving (and remounting) inside the delete window would strand the
	// fresh mount when the delete lands. Tolerate (503 + retry) until the
	// delete lands or the window elapses.
	if view.ownerReleasing &&
		(view.releasingSince.IsZero() || time.Since(view.releasingSince) < ownerReleaseClaimWindow) {
		return "", ErrOwnerNodeDown
	}

	// Placement node known-down while mounted: the mount is stranded there.
	// (Normally OnNodeDisconnect flips mounted entries to suspect first; this
	// catches any ordering gap.)
	if view.mounted && !oc.nodeReachable(view.placement) {
		return "", ErrOwnerNodeDown
	}

	return view.placement, nil
}

// nodeReachable reports whether the sandlot node is connected to this gateway.
// A nil streamSrv (tests / human mode) treats every node as reachable — there
// is no connectivity data to contradict it.
func (oc *OwnershipCache) nodeReachable(nodeID string) bool {
	if oc.streamSrv == nil || nodeID == "" {
		return true
	}
	_, err := oc.streamSrv.GetNode(nodeID)
	return err == nil
}

// Claim loop bounds. Each attempt is one full etcd Get + judge + CAS round with
// its own fresh timeout; the loop re-runs only when a CAS lost (a peer wrote
// the key between our Get and our Txn) and the re-read asks us to retry. Beyond
// the budget the state is genuinely thrashing — surface 503 + jittered retry
// instead of recursing without bound (the old tail-call shape could loop
// forever under a pathological key state, e.g. a corrupt value that
// createOwnership's Version==0 CAS could never overwrite).
const (
	claimStepTimeout = 5 * time.Second
	claimMaxAttempts = 4
)

// claimStep is one claim-loop attempt's outcome: either a decided result
// (preferredNode set, retry false) or a request to re-read and re-judge
// (retry true — our CAS lost the race and the key changed under us).
type claimStep struct {
	preferredNode string
	retry         bool
}

// claimFromEtcd reads ownership from etcd and either claims it or returns an error.
// This is the only place the confirmed-condition switching (owner-release lazy path, migrated takeover)
// is decided — every Claim slow path lands here. CAS losses retry through the
// bounded loop in claimFromEtcdCtx instead of recursing.
func (oc *OwnershipCache) claimFromEtcd(sandfsID, candidate string) (string, error) {
	return oc.claimFromEtcdCtx(context.Background(), sandfsID, candidate)
}

func (oc *OwnershipCache) claimFromEtcdCtx(parent context.Context, sandfsID, candidate string) (string, error) {
	// nil client = local/test mode (no etcd, e.g. single-node). Be permissive:
	// allow the request with no preferred node.
	if oc.client == nil {
		return "", nil
	}
	for attempt := 1; ; attempt++ {
		ctx, cancel := context.WithTimeout(parent, claimStepTimeout)
		step, err := oc.claimOnce(ctx, sandfsID, candidate)
		cancel()
		if err != nil {
			return "", err
		}
		if !step.retry {
			return step.preferredNode, nil
		}
		if attempt >= claimMaxAttempts {
			oc.logger.Warn("ownership claim retry budget exhausted",
				"sandfsID", sandfsID, "attempts", attempt)
			return "", ErrClaimRetryExhausted
		}
	}
}

// claimOnce is a single read-and-judge round of the claim loop. A retry step
// means the key changed under us (CAS lost) — the loop re-reads and re-judges.
func (oc *OwnershipCache) claimOnce(ctx context.Context, sandfsID, candidate string) (claimStep, error) {
	key := ownershipPrefix + sandfsID
	resp, err := oc.client.Get(ctx, key)
	if err != nil {
		return claimStep{}, fmt.Errorf("etcd get ownership: %w", err)
	}

	if len(resp.Kvs) == 0 {
		// No owner. Normally we'd claim it — but if we recently shed this sandfs
		// (load shedding) and are still in the cooldown window, refuse to
		// re-claim so a peer has a window to claim it. Without this, a client
		// routed back to us during the DNS cache window would have us immediately
		// re-grab ownership, undoing the shed. The caller surfaces ErrShedCooldown
		// as a shed-503 (the client retries; once the DNS re-resolves to a peer,
		// that peer claims it; once a peer owns it, our shed entry is cleared by
		// the watch and we'd claim normally on a future no-owner event).
		oc.clearDeadSince(sandfsID) // unowned now — no dead owner to time.
		if oc.isRecentlyShed(sandfsID) {
			return claimStep{}, ErrShedCooldown
		}
		return oc.createOwnership(ctx, sandfsID, candidate)
	}

	var val OwnershipValue
	if err := json.Unmarshal(resp.Kvs[0].Value, &val); err != nil {
		// Corrupted value (ops-written key, truncated write, foreign format).
		// Overwrite via a ModRevision CAS, NOT via createOwnership: the
		// Version==0 create CAS can never succeed on an existing key, so
		// createOwnership here would retry forever on the same corrupt bytes
		// (the one deterministic infinite cycle in the old recursive shape).
		// forceTakeover's ModRevision CAS overwrites exactly the bytes we read;
		// if a peer wrote in between, the CAS loses and the loop re-reads what
		// is now (theirs or ours) valid JSON — no cycle, no lost update.
		oc.logger.Warn("corrupted ownership value, overwriting via revision CAS",
			"sandfsID", sandfsID, "error", err)
		oc.clearDeadSince(sandfsID)
		return oc.forceTakeover(ctx, sandfsID, 0, resp.Kvs[0].ModRevision, candidate)
	}

	if val.GatewayID == oc.gatewayID {
		// Already owned by us — any dead-owner clock for this sandfs is stale.
		oc.clearDeadSince(sandfsID)

		// Owned by us — refresh the cache entry from etcd, preserving the
		// transient state (mounted/suspect) that etcd does not carry.
		entry := &ownershipEntry{
			gatewayID:  val.GatewayID,
			placement:  val.NodeID,
			published:  val.NodeID,
			generation: val.Generation,
			modRev:     resp.Kvs[0].ModRevision,
			claimTime:  time.Now(),
		}
		oc.mu.Lock()
		var oldPlacement string
		if old, ok := oc.cache[sandfsID]; ok {
			entry.mounted = old.mounted
			entry.suspect = old.suspect
			// Preserve the in-flight mount flag: a slow-path Claim can race a
			// BeginDispatch that already passed its own check. Dropping the
			// flag would re-expose the entry to the owner-release sweep and to
			// load shedding while the mount is still in flight.
			entry.dispatching = old.dispatching
			// Preserve the owner-release tombstone across the refresh: the
			// sweep's delete may still be in flight, and a re-adopt must not
			// launder the entry back into a servable state (checkEntry gates
			// on it; the watch DELETE or the window clears it).
			entry.ownerReleasing = old.ownerReleasing
			entry.releasingSince = old.releasingSince
			oldPlacement = old.placement
		} else if entry.placement != "" && !oc.nodeReachable(entry.placement) {
			// No prior in-memory state (first sight after a restart, or the
			// full-load raced traffic): mount state unknown and the placement
			// node is not connected to us — orphan-uncertain.
			entry.suspect = true
		}
		oc.cache[sandfsID] = entry
		// Keep the placement index in lockstep (e.g. our own async
		// writeNodeIDInEtcd changed the etcd placement since the old entry):
		// nodeSandfs is the reverse index OnNodeDisconnect /
		// NoteNodeReconnected / owner-release locate a node's sandfs by — an
		// entry whose placement moved without an index move would be invisible
		// to all three.
		oc.updateNodeSandfsLocked(sandfsID, oldPlacement, entry.placement)
		view := entry.view()
		oc.mu.Unlock()

		pref, err := oc.checkEntry(view)
		if err == ErrOwnerNodeDown && view.placement != "" {
			// Placed on a node we're not connected to and the orphan question
			// is open. Resolve it against the presence key — the cross-restart
			// T_safe confirmation. This replaces the old lazy owner-release
			// check: node_id now names the placement node even while idle, so
			// there is always a node to interrogate, and a live owner never
			// needs to release ownership merely to serve an idle sandfs.
			if oc.resolveOrphanSuspect(ctx, sandfsID, entry) {
				// resolveOrphanSuspect mutated the entry under oc.mu; re-snapshot
				// before validating (the live entry is concurrently mutable).
				oc.mu.Lock()
				view = entry.view()
				oc.mu.Unlock()
				pref, err = oc.checkEntry(view)
			}
		}
		return claimStep{preferredNode: pref}, err
	}

	// Owned by another gateway. Takeover from a dead owner requires a
	// CONFIRMED condition that every mount is released:
	//
	//   Signal (immediate): the placement node migrated to us — live stream +
	//   our presence key. A node can only reach a new gateway through
	//   T_tolerance + T_clean + T_isolation > T_safe, and it arrives clean
	//   (reconnect-clean invariant), so every old mount is provably gone.
	//
	//   Time (guarded): the placement node's presence key is ABSENT (gone ≥
	//   T_safe — dead, or its gateway self-fenced and the sandlot released
	//   everything at stream break), or the record was never placed. With the
	//   etcd-partition self-fence, "gateway health stale" no longer admits a
	//   hidden live mount, so the per-sandfs guard clock (claim-dead-guard
	//   window) is a sound wait. The clock is seeded on the FIRST dead
	//   observation so a transiently-unreachable (but recovering) owner is not
	//   robbed; multiple peers each timing the window are safe — the
	//   ModRevision CAS lets exactly one win.
	//
	// Everything else — owner alive, node still present somewhere else, no
	// confirmed condition yet — is tolerated: 503 + retry (the owner recovers,
	// the node migrates, or the guard elapses).
	if oc.ownerDead(ctx, val.GatewayID) {
		if val.NodeID != "" && oc.migratedTakeoverAllowed(ctx, val.NodeID) {
			oc.logger.Info("migrated takeover: taking over ownership from dead gateway (sandlot migrated to us)",
				"sandfsID", sandfsID, "oldGateway", val.GatewayID, "nodeID", val.NodeID)
			return oc.forceTakeover(ctx, sandfsID, val.Generation, resp.Kvs[0].ModRevision, val.NodeID)
		}
		// placement == "" means the owner never got a node for this sandfs, so
		// it never dispatched a mount. The takeover preserves a non-empty
		// placement but REPLACES an empty one with our own candidate, keeping
		// the invariant: an empty value is reachable only while node selection
		// itself found nothing — the instant a claim could select a node, that
		// candidate is written in the same CAS. No mount can exist before it.
		if val.NodeID == "" || oc.nodePresenceGone(ctx, val.NodeID) {
			return oc.claimDeadIdle(ctx, sandfsID, val, resp.Kvs[0].ModRevision, candidate)
		}
	} else {
		// Owner alive — any dead-owner clock for this sandfs is stale (the owner
		// recovered). Clear it so a future death starts a fresh guard window.
		oc.clearDeadSince(sandfsID)
	}
	return claimStep{}, ErrOwnershipConflict
}

// nodePresenceGone reports whether the node's presence key is ABSENT — the
// node has been gone ≥ T_safe, so every mount release path has provably run
// (sandlot releases mounts at stream break since the reconnect-clean
// invariant; the warden countdown backstops a dead node; a self-fenced
// gateway drops its streams, triggering the same release). etcd errors and
// "present" both return false: the caller tolerates rather than churns.
func (oc *OwnershipCache) nodePresenceGone(ctx context.Context, nodeID string) bool {
	state, err := oc.presenceState(ctx, nodeID)
	if err != nil {
		return false // cannot determine — tolerate
	}
	return state == presenceAbsent
}

// claimDeadIdle implements the time-protected CAS claim for a dead owner's
// sandfs whose mounts are provably released but which carried no live signal:
// never-placed records (node_id empty — nothing to interrogate) and placed
// records whose placement node's presence key is gone (see
// nodePresenceGone). It seeds a per-sandfs death clock on the first
// observation and force-takes-over once the claim-dead-guard window elapses;
// within the window it tolerates (503+retry) to give a recovering owner a
// chance. The clock is cleared on owner revival, successful takeover, or the
// background sweep.
//
// A non-empty placement is preserved (the node remains the right affinity —
// it is provably gone, but re-placement costs an etcd write); an EMPTY
// placement is replaced by the claim's candidate: this CAS is the boundary
// after which a mount CAN be dispatched, so the candidate must land in the
// same write or "node_id == ”" would no longer mean "no mount was ever
// dispatched" for the record's new owner.
func (oc *OwnershipCache) claimDeadIdle(ctx context.Context, sandfsID string, val OwnershipValue, modRevision int64, candidate string) (claimStep, error) {
	oc.deadSinceMu.Lock()
	since, seen := oc.deadSince[sandfsID]
	if !seen {
		since = time.Now()
		oc.deadSince[sandfsID] = since
	}
	guard := oc.claimDeadGuard
	oc.deadSinceMu.Unlock()

	if elapsed := time.Since(since); elapsed < guard {
		oc.logger.Info("owner gateway dead but sandfs idle; waiting out the claim-dead guard before CAS takeover",
			"sandfsID", sandfsID, "oldGateway", val.GatewayID,
			"elapsed_sec", int(elapsed.Seconds()), "guard_sec", int(guard.Seconds()))
		return claimStep{}, ErrOwnershipConflict
	}

	// Guard elapsed and owner still dead — CAS-takeover. clearDeadSince on
	// success; on a CAS miss (concurrent modification) forceTakeover returns a
	// retry step and the claim loop re-reads and re-judges (a revived owner
	// clears the clock via the non-dead branch in claimOnce).
	placement := val.NodeID
	if placement == "" {
		placement = candidate // never-placed record: write OUR candidate (see doc comment)
	}
	oc.logger.Info("dead-owner idle sandfs: claim-dead guard elapsed; CAS-taking-over",
		"sandfsID", sandfsID, "oldGateway", val.GatewayID, "guard_sec", int(guard.Seconds()))
	step, err := oc.forceTakeover(ctx, sandfsID, val.Generation, modRevision, placement)
	if err == nil && !step.retry {
		oc.clearDeadSince(sandfsID)
	}
	return step, err
}

// clearDeadSince removes the death clock for a sandfs (owner revived, takeover
// succeeded, or ownership lost).
func (oc *OwnershipCache) clearDeadSince(sandfsID string) {
	oc.deadSinceMu.Lock()
	delete(oc.deadSince, sandfsID)
	oc.deadSinceMu.Unlock()
}

// sweepDeadSince drops death-clock entries that have lingered well past the
// claim-dead guard without being cleared (the sandfs was never re-claimed, so
// the clock was never reset/taken-over). Dropping an entry only restarts the
// clock on the next Claim — it never causes a premature takeover — so this is
// pure unbounded-growth hygiene. Keys left lingering (dead owner, no request
// ever arrives) are inert — the on-demand claim path is the availability
// backstop, and the manual reap-stuck tool is the ops backstop.
func (oc *OwnershipCache) sweepDeadSince() {
	oc.deadSinceMu.Lock()
	guard := oc.claimDeadGuard
	cutoff := time.Now().Add(-4 * guard)
	for id, since := range oc.deadSince {
		if since.Before(cutoff) {
			delete(oc.deadSince, id)
		}
	}
	oc.deadSinceMu.Unlock()
}

// resolveOrphanSuspect resolves a placed entry's orphan-uncertainty against
// the placement node's presence key and reports whether the entry is now
// servable. It replaces the old lazy owner-release check: node_id now names
// the placement node even while idle, so there is always a node to
// interrogate, and a live owner never needs to release ownership merely to
// serve an idle sandfs on another node.
//
// The presence key is the cross-restart T_safe confirmation, and it is
// RELIABLE: OnNodeConnect rejects a node whose presence key cannot be written
// (it is admitted presencePending instead), so a connected-and-accepted node
// always has one. "key ABSENT" therefore means the node has genuinely been
// gone >= T_safe, and every mount-release path has provably run:
//   - key ABSENT → node gone ≥ T_safe → orphan question closed.
//   - key PRESENT owned by another gateway → the node migrated away, which it
//     can only do through T_tolerance + T_clean + T_isolation > T_safe → its
//     mounts are provably released → closed. (Ownership stays with us: we are
//     alive and can serve the sandfs elsewhere.)
//   - key PRESENT owned by us → the node disconnected < T_safe ago → still
//     open; tolerate (the caller surfaces ErrOwnerNodeDown → 503 + retry).
func (oc *OwnershipCache) resolveOrphanSuspect(ctx context.Context, sandfsID string, entry *ownershipEntry) bool {
	// Snapshot what the presence answer will be ABOUT. The etcd query runs
	// without oc.mu, so the entry can move underneath it (a concurrent
	// NoteMounted, a watch update, a takeover). Write-back is only valid when
	// none of those happened.
	oc.mu.Lock()
	placement := entry.placement
	generation := entry.generation
	modRev := entry.modRev
	current, present := oc.cache[sandfsID]
	// presencePending node: it connected while etcd was down (key unwritable)
	// but IS connected to us right now — an absent key here is the pending-
	// regrant window, not a T_safe-gone node. Tolerate; the regrant (heartbeat
	// or etcd recovery) re-anchors the key within a health interval.
	pending := oc.presencePending[placement]
	oc.mu.Unlock()
	if pending {
		return false
	}
	state, err := oc.presenceState(ctx, placement)
	if err != nil {
		// Can't determine (etcd error) — tolerate rather than churn.
		return false
	}
	switch state {
	case presenceSelf:
		// Node disconnected < T_safe ago (our key still alive); it may reconnect.
		return false
	case presenceOther, presenceAbsent:
		oc.mu.Lock()
		// The answer describes the snapshot taken above. If the cache entry was
		// replaced, moved, or rewritten while we asked, the answer is stale —
		// clearing mounted here would erase a fresher mount's record.
		if !present || oc.cache[sandfsID] != current ||
			entry.placement != placement || entry.generation != generation || entry.modRev != modRev {
			oc.mu.Unlock()
			return false
		}
		entry.suspect = false
		entry.mounted = false // any mount there is provably released
		oc.mu.Unlock()
		oc.logger.Info("orphan question resolved via presence; serving placed sandfs",
			"placement", placement, "presenceState", int(state))
		return true
	}
	return false
}

// createOwnership creates a new ownership record in etcd for this gateway.
// Plain key, no lease — ownership persists until explicitly managed. The value
// carries gateway_id + the CANDIDATE PLACEMENT (routing addresses live in
// /sandswap/gateway/{gw}).
//
// Writing the candidate here — not after the mount succeeds — is what makes
// "node_id == \"\"" mean "provably never mounted": the record and its placement
// appear in the same CAS, before any mount is dispatched. An empty candidate
// means node selection found nothing, so no mount will be dispatched either.
// The claim CAS happens regardless, so this costs no extra round trip and adds
// nothing to the mount critical path.
// Called from inside the claim loop with the attempt's ctx; a lost CAS returns
// a retry step instead of recursing.
func (oc *OwnershipCache) createOwnership(ctx context.Context, sandfsID, candidate string) (claimStep, error) {
	val := OwnershipValue{
		GatewayID:  oc.gatewayID,
		NodeID:     candidate,
		Generation: 1,
	}
	data, err := json.Marshal(val)
	if err != nil {
		return claimStep{}, fmt.Errorf("marshal ownership: %w", err)
	}

	key := ownershipPrefix + sandfsID
	// CAS: only create if the key doesn't exist (version 0).
	txnResp, err := oc.client.Txn(ctx).
		If(clientv3.Compare(clientv3.Version(key), "=", 0)).
		Then(clientv3.OpPut(key, string(data))).
		Commit()
	if err != nil {
		return claimStep{}, fmt.Errorf("etcd create ownership CAS: %w", err)
	}
	if !txnResp.Succeeded {
		// Someone else created it between our Get and Txn — the loop re-reads
		// and re-judges the key they wrote.
		return claimStep{retry: true}, nil
	}

	entry := &ownershipEntry{
		gatewayID:  oc.gatewayID,
		placement:  candidate,
		published:  candidate,
		generation: 1,
		modRev:     txnResp.Header.Revision,
		claimTime:  time.Now(),
	}
	oc.mu.Lock()
	oc.cache[sandfsID] = entry
	oc.updateNodeSandfsLocked(sandfsID, "", candidate)
	oc.mu.Unlock()

	return claimStep{preferredNode: candidate}, nil
}

// forceTakeover overwrites an existing ownership record via a ModRevision CAS
// (plain Put, no lease). Called from inside the claim loop with the attempt's
// ctx; the caller has already verified a takeover condition (migrated takeover,
// dead-owner idle guard elapsed, or corrupt value to overwrite). placement is
// the node_id the new record carries: normally the previous record's node_id,
// PRESERVED because the takeover only fires when the placement node's stream is
// provably settled (migrated to us, or gone ≥ T_safe), so the node remains the
// right affinity — keeping it spares the next mount a reschedule and one more
// etcd write. The two exceptions write the claim's own candidate instead: a
// corrupt value (nothing to preserve) and a never-placed record (empty
// node_id — the candidate must land in this CAS or "node_id == ”" would stop
// meaning "no mount was ever dispatched", see claimDeadIdle).
func (oc *OwnershipCache) forceTakeover(ctx context.Context, sandfsID string, oldGen uint64, modRevision int64, placement string) (claimStep, error) {
	newGen := oldGen + 1
	val := OwnershipValue{
		GatewayID:  oc.gatewayID,
		NodeID:     placement,
		Generation: newGen,
	}
	data, err := json.Marshal(val)
	if err != nil {
		return claimStep{}, fmt.Errorf("marshal ownership: %w", err)
	}

	key := ownershipPrefix + sandfsID
	// CAS: only overwrite if the key's modRevision hasn't changed since we read it.
	// This prevents concurrent force-takeovers from racing — if another gateway
	// wrote between our Get and our Txn, the modRevision won't match and the
	// loop re-reads what they wrote.
	txnResp, err := oc.client.Txn(ctx).
		If(clientv3.Compare(clientv3.ModRevision(key), "=", modRevision)).
		Then(clientv3.OpPut(key, string(data))).
		Commit()
	if err != nil {
		return claimStep{}, fmt.Errorf("etcd force takeover CAS: %w", err)
	}
	if !txnResp.Succeeded {
		// Concurrent modification — retry.
		return claimStep{retry: true}, nil
	}

	entry := &ownershipEntry{
		gatewayID:  oc.gatewayID,
		placement:  placement,
		published:  placement,
		generation: newGen,
		modRev:     txnResp.Header.Revision,
		claimTime:  time.Now(),
	}
	oc.mu.Lock()
	oc.cache[sandfsID] = entry
	// Keep the placement index consistent with the preserved placement.
	oc.updateNodeSandfsLocked(sandfsID, "", placement)
	oc.mu.Unlock()

	// return the placement the takeover preserved (or the claim's
	// candidate for empty placements) — an empty hint made pool.Acquire
	// re-score blind, losing the affinity the takeover deliberately kept and
	// paying an extra placement write on the first mount.
	return claimStep{preferredNode: placement}, nil
}

// presenceState is the assessed state of a node's presence key.
type presenceState int

const (
	presenceAbsent presenceState = iota
	presenceSelf                 // key present, value == this gateway (node connected to us or disconnected < T_safe)
	presenceOther                // key present, value != this gateway (node connected to / last touched by another gateway)
)

// presenceKey returns the etcd key for a node's presence record.
func presenceKey(nodeID string) string {
	return presencePrefix + nodeID + "/presence"
}

// presenceState reads a node's presence key and classifies it. err is non-nil
// when the GET failed (etcd unreachable) — callers tolerate rather than churn.
func (oc *OwnershipCache) presenceState(ctx context.Context, nodeID string) (presenceState, error) {
	if fn := testPresenceStateFn.Load(); fn != nil {
		return (*fn)(nodeID)
	}
	if oc.client == nil {
		return presenceSelf, nil // nil-client test mode: assume connected
	}
	resp, err := oc.client.Get(ctx, presenceKey(nodeID))
	if err != nil {
		return presenceAbsent, err
	}
	if len(resp.Kvs) == 0 {
		return presenceAbsent, nil
	}
	if string(resp.Kvs[0].Value) == oc.gatewayID {
		return presenceSelf, nil
	}
	return presenceOther, nil
}

// ownerStaleness returns how stale a gateway's health record is: the elapsed
// time since its last_healthy_ts. It is THE liveness signal — the health key
// has no lease, so staleness is the only death measure and each consumer
// thresholds it independently by its own cost of judging wrong.
//
// Returns (stale, present):
//   - present=false when the key is absent. With no lease this only means the
//     owner never wrote the key (or ops deleted it) — treated as dead.
//   - present=true with stale>=0 when the key exists. A corrupt or missing
//     timestamp, or an etcd error, is treated as fresh-present (stale=0) —
//     fail-alive on bad data, mirroring ownerDead's tolerate-on-error stance, so
//     a malformed value never flips a live gateway to dead.
func (oc *OwnershipCache) ownerStaleness(ctx context.Context, gatewayID string) (stale time.Duration, present bool) {
	if oc.client == nil {
		return 0, true // local/test mode: treat as alive-present.
	}
	resp, err := oc.client.Get(ctx, healthPrefix+gatewayID)
	if err != nil {
		return 0, true // can't determine → fail-alive (tolerate)
	}
	if len(resp.Kvs) == 0 {
		return 0, false // key absent → dead
	}
	var hv GatewayHealthValue
	if err := json.Unmarshal(resp.Kvs[0].Value, &hv); err != nil {
		return 0, true // corrupt value → fail-alive
	}
	if hv.LastHealthyTS == "" {
		return 0, true // no timestamp (legacy value) → fail-alive
	}
	ts, err := time.Parse(time.RFC3339, hv.LastHealthyTS)
	if err != nil {
		return 0, true // unparseable timestamp → fail-alive
	}
	return time.Since(ts), true
}

// ownerDead reports whether another gateway is dead: its health key is absent
// (never written — defensive) OR its last_healthy_ts is stale past the
// claim-dead guard. etcd errors / corrupt values are treated as NOT dead
// (tolerate — don't churn takeovers on transient hiccups). A live gateway
// refreshes its health key every healthRefreshInterval, so staleness past the
// guard reliably means the refresh loop has been failing for that long.
func (oc *OwnershipCache) ownerDead(ctx context.Context, gatewayID string) bool {
	stale, present := oc.ownerStaleness(ctx, gatewayID)
	if !present {
		return true
	}
	oc.mu.Lock()
	guard := oc.claimDeadGuard
	oc.mu.Unlock()
	return stale > guard
}

// selfHealthy reports whether THIS gateway's own health key is alive in etcd —
// owner-release condition (3): the gateway is alive and has the right to release.
// A present-but-stale-past-the-guard key counts as unhealthy (the gateway is not
// refreshing its health record).
func (oc *OwnershipCache) selfHealthy(ctx context.Context) bool {
	stale, present := oc.ownerStaleness(ctx, oc.gatewayID)
	if !present {
		return false
	}
	oc.mu.Lock()
	guard := oc.claimDeadGuard
	oc.mu.Unlock()
	return stale <= guard
}

// migratedTakeoverAllowed checks the migrated-takeover prerequisites for a sandfs owned by a dead gateway
// whose node_id is `nodeID`: the node has a live stream to US and its presence
// key is owned by us (so the node really migrated here, not elsewhere).
func (oc *OwnershipCache) migratedTakeoverAllowed(ctx context.Context, nodeID string) bool {
	oc.mu.Lock()
	fn := oc.testNodeConnectedFn
	oc.mu.Unlock()
	if fn != nil {
		if !fn(nodeID) {
			return false
		}
	} else if oc.streamSrv != nil {
		if _, err := oc.streamSrv.GetNode(nodeID); err != nil {
			return false
		}
	} else {
		return false // no stream server → no local node
	}
	state, err := oc.presenceState(ctx, nodeID)
	if err != nil {
		return false
	}
	return state == presenceSelf
}

// testPresenceStateFn overrides presenceState in tests (nil-client caches
// have no etcd to read; the sweep tests drive absent/other states through
// it). Follows the SetNodeConnectedForTest pattern.
var testPresenceStateFn atomic.Pointer[func(nodeID string) (presenceState, error)]

// SetPresenceStateForTest overrides the presence-key classification used by
// the owner-release sweep and the takeover paths; nil restores the etcd read.
func (oc *OwnershipCache) SetPresenceStateForTest(fn func(nodeID string) (presenceState, error)) {
	testPresenceStateFn.Store(&fn)
}

// forceTakeoverForTest exposes a direct forceTakeover call (unit seam).
func (oc *OwnershipCache) forceTakeoverForTest(sandfsID string, oldGen uint64, modRev int64, placement string) (claimStep, error) {
	return oc.forceTakeover(context.Background(), sandfsID, oldGen, modRev, placement)
}

// handleWatchEventForTest drives the watch handler with a synthetic
// foreign-gateway PUT (unit seam).
func (oc *OwnershipCache) handleWatchEventForTest(sandfsID, foreignGateway string) {
	val, _ := json.Marshal(OwnershipValue{GatewayID: foreignGateway, NodeID: "node-a", Generation: 2})
	oc.handleWatchEvent(&clientv3.Event{
		Type: clientv3.EventTypePut,
		Kv:   &mvccpb.KeyValue{Key: []byte(ownershipPrefix + sandfsID), Value: val, ModRevision: 99},
	})
}

// SetNodeConnectedForTest overrides the node-connectivity check for migrated takeover's
// "node migrated to us" condition. Tests use it to simulate a live node stream
// without a real gRPC connection; pass nil to restore the streamSrv check.
func (oc *OwnershipCache) SetNodeConnectedForTest(fn func(nodeID string) bool) {
	oc.mu.Lock()
	defer oc.mu.Unlock()
	oc.testNodeConnectedFn = fn
}

// NoteMounted records a successful cold mount of sandfsID on node: the
// in-memory mount state flips on, the placement moves to node, and — only when
// the placement actually changed against what etcd holds — a single
// ModRevision-CAS write publishes it. Under node affinity the placement almost
// never changes, so the steady state is ZERO etcd writes per execution cycle:
// unmount clears nothing and the next mount on the same node is elided.
//
// Callers must have Claimed the sandfs (the orphan-suspect question resolved)
// before mounting; this clears the suspect flag on that basis.
func (oc *OwnershipCache) NoteMounted(sandfsID, node string) {
	oc.mu.Lock()
	var gen uint64
	if e, ok := oc.cache[sandfsID]; ok {
		gen = e.generation
	}
	oc.mu.Unlock()
	oc.NoteMountedChecked(sandfsID, node, gen)
}

// NoteMountedChecked is NoteMounted with the dispatch-generation guard. It
// returns true when the confirmation is STALE or a CROSS-NODE duplicate: the
// caller must tear down the mount it just established (the winner is recorded
// by its own owner) instead of retrying the record. A false return keeps the
// normal recording behaviour.
func (oc *OwnershipCache) NoteMountedChecked(sandfsID, node string, dispatchGen uint64) bool {
	if node == "" {
		// A mount without a node is a programming error; unmount has its own
		// entry point (NoteUnmounted). Nothing to place.
		oc.logger.Warn("NoteMounted called with empty node", "sandfsID", sandfsID)
		return false
	}
	// Capture the CAS baseline (modRev) and generation under the lock: the
	// async writer must not race watch events mutating the entry.
	oc.mu.Lock()
	// A confirmation that lands while this gateway is SELF-FENCED belongs to a
	// mount dispatched before the fence: the fence promised (and actively
	// released) every mount, so this one must be torn down instead of recorded.
	if oc.fenced {
		if e, ok := oc.cache[sandfsID]; ok {
			e.dispatching = false
		}
		fn := oc.compensateMount
		oc.mu.Unlock()
		oc.logger.Error("mount confirmation while self-fenced (etcd partition): tearing the mount down",
			"sandfsID", sandfsID, "node", node)
		if fn != nil {
			fn(sandfsID, node)
		}
		return true
	}
	entry, ok := oc.cache[sandfsID]
	var modRev int64
	var generation uint64
	var needsWrite bool
	if ok {
		// The ownership generation moved while this mount was dispatching: a
		// takeover or a peer's CAS superseded the view this dispatch committed
		// to. Recording this node would overwrite the winner's placement.
		if entry.generation != dispatchGen {
			entry.dispatching = false
			oc.mu.Unlock()
			oc.logger.Warn("stale mount confirmation: ownership generation moved during dispatch",
				"sandfsID", sandfsID, "node", node, "dispatch_generation", dispatchGen, "current_generation", entry.generation)
			return true
		}
		// A DIFFERENT node is already recorded as the live mount: this
		// confirmation is the loser of a cross-node double mount. It must be
		// unmounted here; the recorded node keeps serving the sandfs.
		if entry.mounted && entry.placement != "" && entry.placement != node {
			entry.dispatching = false
			oc.mu.Unlock()
			oc.logger.Error("cross-node mount confirmation: another node already owns the mount",
				"sandfsID", sandfsID, "conflicting_node", node, "placed_node", entry.placement)
			return true
		}
		// The entry became orphan-uncertain while this mount was dispatching:
		// the disconnected node may still hold a live mount. Do not confirm or
		// clear suspect; the caller must tear down this new mount and retry
		// after Claim/T_safe resolves the orphan question.
		if entry.suspect {
			entry.dispatching = false
			oc.mu.Unlock()
			oc.logger.Error("mount confirmation while orphan-uncertain: refusing to record a second mount",
				"sandfsID", sandfsID, "node", node)
			return true
		}
		old := entry.placement
		entry.placement = node
		entry.mounted = true
		entry.dispatching = false
		entry.suspect = false
		entry.claimTime = time.Now()
		modRev = entry.modRev
		generation = entry.generation
		needsWrite = entry.published != node
		oc.updateNodeSandfsLocked(sandfsID, old, node)
	}
	oc.mu.Unlock()

	if !ok {
		// No cached entry: the record was deleted under our IN-FLIGHT mount
		// (sweep/shed/takeover raced the [Claim → NoteMounted] window — the
		// exact race BeginDispatch now prevents going forward). The mount we
		// are about to record is UNCOVERED: tearing it down is the safe
		// direction (a peer may already have re-claimed and mounted).
		oc.mu.Lock()
		fn := oc.compensateMount
		oc.mu.Unlock()
		oc.logger.Error("ownership record vanished under the in-flight mount; compensating with unmount",
			"sandfsID", sandfsID, "node", node)
		if fn != nil {
			fn(sandfsID, node)
		}
		return false
	}
	if needsWrite {
		go oc.publishPlacement(sandfsID, node, modRev, generation)
	}
	return false
}

// BeginDispatch verifies the ownership covering is intact and marks the
// sandfs as having a cold mount IN FLIGHT (the fix). Called by
// the exec/file handlers AFTER the MountLock and BEFORE pool.Acquire/the
// mount RPC — the [Claim → NoteMounted] window has no other coverage
// re-check, and the sweep/shed delete paths respect the flag: a delete under
// an in-flight mount left the fresh mount uncovered and a peer's unguarded
// no-owner claim dual-mounted the volume. Cleared by NoteMounted (success)
// or EndDispatch (failure/abort). In-memory only: one lock + map probe on
// the cold path; no etcd traffic, no allocations.
// BeginDispatch marks a cold mount in flight and returns the ownership
// generation it was dispatched under. The generation is echoed back into
// NoteMountedChecked: a confirmation whose generation moved belongs to a
// superseded view (a takeover or a peer's write landed while the mount RPC was
// in flight) and must not rewrite the winner's placement.
func (oc *OwnershipCache) BeginDispatch(sandfsID string) (uint64, error) {
	oc.mu.Lock()
	defer oc.mu.Unlock()
	e, ok := oc.cache[sandfsID]
	if !ok || e.gatewayID != oc.gatewayID || e.ownerReleasing || e.dispatching || e.suspect || oc.fenced {
		return 0, ErrCoverageLost
	}
	e.dispatching = true
	return e.generation, nil
}

// EndDispatch clears the in-flight flag (mount failed or aborted before
// NoteMounted). Idempotent; a no-op on a missing entry.
func (oc *OwnershipCache) EndDispatch(sandfsID string) {
	oc.mu.Lock()
	if e, ok := oc.cache[sandfsID]; ok {
		e.dispatching = false
	}
	oc.mu.Unlock()
}

// Dispatching reports whether a cold mount is in flight for the sandfs
// (exported for the shed controller's local guard composition).
func (oc *OwnershipCache) Dispatching(sandfsID string) bool {
	oc.mu.Lock()
	defer oc.mu.Unlock()
	e, ok := oc.cache[sandfsID]
	return ok && e.dispatching
}

// MountedSandfs returns the sandfs this gateway may hold a live mount for,
// paired with the node it must be released on. Used by the self-fence to
// actively release everything this gateway holds.
//
// The set is deliberately WIDER than mounted==true: a cold mount that is in
// flight (dispatching) has already been dispatched to its candidate node, and
// a suspect entry is orphan-uncertain by definition — the fence's proof
// ("health stale past the fence ⇒ no live mount") must cover both, so both are
// released too (an unmount for a sandfs that is not mounted is an idempotent
// no-op on the node). Entries with no placement have never been dispatched
// anywhere, so there is nothing to address.
func (oc *OwnershipCache) MountedSandfs() map[string]string {
	oc.mu.Lock()
	defer oc.mu.Unlock()
	out := make(map[string]string)
	for sandfsID, entry := range oc.cache {
		if entry.placement == "" {
			continue
		}
		if entry.mounted || entry.dispatching || entry.suspect {
			out[sandfsID] = entry.placement
		}
	}
	return out
}

// NoteUnmounted records that the sandfs's mount was released (sticky-lease
// expiry unmount). Placement is NOT touched — it is an affinity fact that
// survives unmount — and NO etcd write happens: mount state is transient and
// lives only in this process's memory. The next mount flips it back on; if
// that mount lands on the same node (the common case), the published value in
// etcd was never stale and needs no write either.
func (oc *OwnershipCache) NoteUnmounted(sandfsID string) {
	oc.mu.Lock()
	defer oc.mu.Unlock()
	if entry, ok := oc.cache[sandfsID]; ok {
		entry.mounted = false
	}
}

// updateNodeSandfsLocked moves sandfsID from oldNode's set to newNode's set in
// the nodeSandfs reverse index. Caller holds oc.mu.
func (oc *OwnershipCache) updateNodeSandfsLocked(sandfsID, oldNode, newNode string) {
	if oldNode != "" && oldNode != newNode {
		if set, ok := oc.nodeSandfs[oldNode]; ok {
			delete(set, sandfsID)
			if len(set) == 0 {
				delete(oc.nodeSandfs, oldNode)
			}
		}
	}
	if newNode != "" {
		if oc.nodeSandfs[newNode] == nil {
			oc.nodeSandfs[newNode] = make(map[string]struct{})
		}
		oc.nodeSandfs[newNode][sandfsID] = struct{}{}
	}
}

// publishOutcome classifies one placement-publish attempt's result so
// publishPlacement can decide between drop, retry, and compensation.
type publishOutcome int

const (
	publishPublished    publishOutcome = iota // CAS put landed
	publishCASLost                            // key changed under us (record rewritten or deleted)
	publishEtcdError                          // transport/quorum failure — record state unknown
	publishNoBaseline                         // no CAS baseline (modRev == 0); write was skipped
	publishNilClient                          // local/test mode (nil etcd client)
	publishMarshalError                       // value marshal failed (non-retryable)
)

// writeNodeIDInEtcd attempts one node_id publish via a single ModRevision CAS:
// the Put lands only if the record is unchanged since we last observed it
// (entry.modRev). One round trip replaces the old read-modify-write (Get →
// compare generation → plain Put), which cost two quorum ops AND had a
// lost-update window: a peer's forceTakeover landing between that Get and Put
// was silently overwritten (resurrecting our gateway_id over a valid takeover).
//
// The outcome is returned (not just an error): CAS loss and etcd failure have
// different remedies in publishPlacement — a CAS loss against a foreign record
// or a persistent etcd failure leaves the live mount UNCOVERED by the
// ownership record, which the invariant forbids (a peer could claim and
// dual-mount). Generation is written back unchanged: only create/takeover bump
// it (nothing consumes per-mount bumps), and the CAS — not the counter — is
// the guard.
func (oc *OwnershipCache) writeNodeIDInEtcd(sandfsID, nodeID string, modRev int64, generation uint64) (publishOutcome, error) {
	// nil client = local/test mode: the cache is already updated synchronously
	// by the caller; the async etcd mirror is skipped.
	if oc.client == nil {
		return publishNilClient, nil
	}
	if modRev == 0 {
		// No etcd observation for this entry — nothing to CAS against, and a
		// 0-compare would "match" a deleted key and recreate it. Never write
		// blind; the caller re-anchors the baseline.
		oc.logger.Warn("update node_id: no CAS baseline, skipping etcd write",
			"sandfsID", sandfsID)
		return publishNoBaseline, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	key := ownershipPrefix + sandfsID
	val := OwnershipValue{
		GatewayID:  oc.gatewayID,
		NodeID:     nodeID,
		Generation: generation,
	}
	data, err := json.Marshal(val)
	if err != nil {
		return publishMarshalError, err
	}

	txnResp, err := oc.client.Txn(ctx).
		If(clientv3.Compare(clientv3.ModRevision(key), "=", modRev)).
		Then(clientv3.OpPut(key, string(data))).
		Commit()
	if err != nil {
		oc.logger.Warn("update node_id: etcd CAS failed", "sandfsID", sandfsID, "error", err)
		return publishEtcdError, err
	}
	if !txnResp.Succeeded {
		// Key changed under us (peer takeover / owner-release / shed).
		oc.logger.Debug("update node_id: CAS lost, key changed under us", "sandfsID", sandfsID)
		return publishCASLost, nil
	}
	return publishPublished, nil
}

// publishPlacementRetries bounds the etcd-error retry attempts of a placement
// publish before the mount is compensated. Two retries (500ms, 2s backoff)
// cover transient blips without letting a partitioned etcd hold the
// compensating unmount hostage for long.
const publishPlacementRetries = 2

var publishPlacementBackoffs = [...]time.Duration{500 * time.Millisecond, 2 * time.Second}

// publishPlacement publishes a cold mount's placement change with bounded
// retry and fail-safe compensation. Runs on its own goroutine (spawned by
// NoteMounted — never on the request path).
//
// The invariant it enforces: THIS gateway's live mounts are always covered by
// an etcd ownership record naming the mounting node. A publish that cannot be
// confirmed (CAS lost to a foreign/deleted record, or etcd errors past the
// retry budget) breaks that covering — the compensator then tears the mount
// down (unmount + bound release), because "no record ⇒ no live mount" is what
// makes the takeover/fence soundness proofs hold. A CAS loss where the record
// is STILL ours is benign (a concurrent write of our own record won the race;
// the watch echo re-syncs and the next mount's needsWrite retries).
func (oc *OwnershipCache) publishPlacement(sandfsID, nodeID string, modRev int64, generation uint64) {
	for attempt := 0; ; attempt++ {
		outcome, err := oc.writeNodeIDInEtcd(sandfsID, nodeID, modRev, generation)
		switch outcome {
		case publishPublished, publishNilClient, publishMarshalError:
			return
		case publishCASLost:
			if oc.recordStillOurs(sandfsID, &modRev, &generation) {
				// Our own concurrent publish won the race — the record is
				// covered; drop.
				return
			}
			oc.compensateUncoveredMount(sandfsID, nodeID,
				fmt.Sprintf("placement publish lost the CAS to a foreign/deleted record (attempt %d)", attempt+1))
			return
		case publishNoBaseline:
			// Re-read the record to anchor a CAS baseline, then retry the
			// decision tree once. Foreign/absent ⇒ compensate.
			ours, gerr := oc.reanchorBaseline(sandfsID, &modRev, &generation)
			if gerr != nil {
				if attempt >= publishPlacementRetries {
					oc.compensateUncoveredMount(sandfsID, nodeID,
						fmt.Sprintf("placement publish could not re-anchor baseline after %d attempts: %v", attempt+1, gerr))
					return
				}
				time.Sleep(publishPlacementBackoffs[attempt])
				continue
			}
			if !ours {
				oc.compensateUncoveredMount(sandfsID, nodeID, "placement publish found the record foreign/absent (no CAS baseline)")
				return
			}
			continue
		case publishEtcdError:
			if attempt >= publishPlacementRetries {
				oc.compensateUncoveredMount(sandfsID, nodeID,
					fmt.Sprintf("placement publish failed after %d attempts: %v", attempt+1, err))
				return
			}
			time.Sleep(publishPlacementBackoffs[attempt])
		}
	}
}

// recordStillOurs re-reads the record and reports whether it still names THIS
// gateway as owner. When it does, modRev/generation are re-anchored to the
// fresh read so the caller could retry — publishPlacement just drops on true.
// Absent, foreign, corrupt, or unreadable records all return false (fail-safe:
// the caller compensates).
func (oc *OwnershipCache) recordStillOurs(sandfsID string, modRev *int64, generation *uint64) bool {
	if oc.client == nil {
		return true
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	resp, err := oc.client.Get(ctx, ownershipPrefix+sandfsID)
	if err != nil || len(resp.Kvs) == 0 {
		return false
	}
	var val OwnershipValue
	if json.Unmarshal(resp.Kvs[0].Value, &val) != nil {
		return false
	}
	if val.GatewayID != oc.gatewayID {
		return false
	}
	*modRev = resp.Kvs[0].ModRevision
	*generation = val.Generation
	return true
}

// reanchorBaseline anchors a fresh CAS baseline for a record that had none.
// Returns whether the record is ours (and updates modRev/generation in place).
func (oc *OwnershipCache) reanchorBaseline(sandfsID string, modRev *int64, generation *uint64) (bool, error) {
	if oc.client == nil {
		return true, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	resp, err := oc.client.Get(ctx, ownershipPrefix+sandfsID)
	if err != nil {
		return false, err
	}
	if len(resp.Kvs) == 0 {
		return false, nil
	}
	var val OwnershipValue
	if json.Unmarshal(resp.Kvs[0].Value, &val) != nil {
		return false, nil
	}
	if val.GatewayID != oc.gatewayID {
		return false, nil
	}
	*modRev = resp.Kvs[0].ModRevision
	*generation = val.Generation
	return true, nil
}

// compensateUncoveredMount tears down a live mount that has lost its ownership
// covering (publish CAS lost to a foreign/deleted record, etcd errors past the
// retry budget, or the watch observing the record deleted while our cache
// still says mounted). Invokes the compensator wired by SetMountCompensator —
// the lease manager's ForceUnmount (unmount → SettleUnmount-gated bound
// release → NoteUnmounted), with the lease layer's own retry chain on unmount
// failure. nil compensator (tests): logged only.
func (oc *OwnershipCache) compensateUncoveredMount(sandfsID, nodeID, reason string) {
	oc.mu.Lock()
	fn := oc.compensateMount
	oc.mu.Unlock()
	oc.logger.Error("ownership record no longer covers a live mount; compensating with unmount",
		"sandfsID", sandfsID, "node", nodeID, "reason", reason)
	if fn != nil {
		fn(sandfsID, nodeID)
	}
}

// SetMountCompensator wires the compensation callback for uncovered mounts
// (see compensateUncoveredMount). Wired from cmd/main.go with the lease
// manager's ForceUnmount; nil (default, tests) disables compensation.
func (oc *OwnershipCache) SetMountCompensator(fn func(sandfsID, nodeID string)) {
	oc.mu.Lock()
	defer oc.mu.Unlock()
	oc.compensateMount = fn
}

// NoteNodeReconnected handles a sandlot node (re)connecting: every mount it
// held is gone (the reconnect-clean invariant — sandlot releases all mounts
// before connecting, covering both its own restarts and gateway-restart
// reconnections), so the in-memory mount state of everything placed on it
// clears and any orphan-uncertainty resolves. NO etcd write happens and the
// placement is preserved: affinity to the node is exactly what makes the next
// mount land back on it warm. preferred_node is subsumed by placement.
//
// The node's sandfs are located via the nodeSandfs reverse index (O(per-node))
// rather than scanning the whole cache — at tens of thousands of cached
// entries a full scan under oc.mu would stall the Claim fast path for
// milliseconds per reconnecting node.
func (oc *OwnershipCache) NoteNodeReconnected(nodeID string) {
	oc.mu.Lock()
	count := 0
	for sandfsID := range oc.nodeSandfs[nodeID] {
		if entry, ok := oc.cache[sandfsID]; ok {
			entry.mounted = false
			entry.suspect = false
			count++
			// Do NOT refresh claimTime here. The node was disconnected for a
			// while — during that window another gateway may have force-taken-over
			// ownership. Keeping the OLD claimTime forces the next Claim fast-path
			// check (`time.Since(claimTime) < cacheMaxAge`) to fail, so the caller
			// re-validates against etcd (slow path) instead of trusting a stale
			// cache and double-mounting. NoteMounted (real mount) still refreshes.
		}
	}
	oc.mu.Unlock()

	if count > 0 {
		oc.logger.Info("cleared mount state for placed sandfs after node reconnect (placement preserved)",
			"nodeID", nodeID, "count", count)
	}
}

// releaseOwnershipCAS deletes an ownership record only if it still names this
// gateway at a revision we observed. A blind Delete can erase a record a peer
// wrote after a takeover (the etcd-partition recovery window), which would let
// a third gateway claim the sandfs while it is still mounted on the peer.
//
// Loss of the revision CAS re-reads the record: a peer's record is left
// intact, a still-ours record is retried up to the attempt budget, and a
// corrupt value is removed under the observed revision (no peer writes
// corrupt values, so binding the delete to that revision is safe). The
// batched owner-release path uses the same rule; this is the single-key form.
func (oc *OwnershipCache) releaseOwnershipCAS(parent context.Context, sandfsID string, attempts int) error {
	if attempts < 1 {
		attempts = 1
	}
	key := ownershipPrefix + sandfsID
	var lastErr error
	for i := 0; i < attempts; i++ {
		ctx, cancel := context.WithTimeout(parent, 5*time.Second)
		resp, err := oc.client.Get(ctx, key)
		if err != nil {
			cancel()
			lastErr = err
			if i < attempts-1 {
				time.Sleep(time.Second)
			}
			continue
		}
		if len(resp.Kvs) == 0 {
			cancel()
			return nil
		}
		kv := resp.Kvs[0]
		var val OwnershipValue
		if uerr := json.Unmarshal(kv.Value, &val); uerr == nil && val.GatewayID != oc.gatewayID {
			// A peer owns the sandfs now — never delete their record. There is
			// nothing of ours left to release.
			cancel()
			return nil
		}
		tresp, terr := oc.client.Txn(ctx).
			If(clientv3.Compare(clientv3.ModRevision(key), "=", kv.ModRevision)).
			Then(clientv3.OpDelete(key)).
			Commit()
		cancel()
		if terr != nil {
			lastErr = terr
		} else if tresp.Succeeded {
			return nil
		} else {
			// The record changed between the read and the CAS. Re-read rather
			// than falling back to a blind delete.
			lastErr = fmt.Errorf("ownership record for %s changed under the release CAS", sandfsID)
		}
		if i < attempts-1 {
			time.Sleep(time.Second)
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("ownership record for %s could not be released", sandfsID)
	}
	return lastErr
}

// ReleaseOwnership deletes the ownership record from etcd. Called when a
// sandfs is deleted or when the gateway gracefully shuts down.
func (oc *OwnershipCache) ReleaseOwnership(sandfsID string) {
	oc.forgetOwnership(sandfsID)

	if oc.client == nil {
		return // local/test mode: cache-only, no etcd mirror.
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := oc.releaseOwnershipCAS(ctx, sandfsID, 3); err != nil {
			oc.logger.Warn("release ownership: etcd CAS delete failed", "sandfsID", sandfsID, "error", err)
		}
	}()
}

// ReleaseOwnershipSync is the bounded-retry synchronous form used by the
// sandfs deletion teardown: an orphaned ownership key (a plain key with no
// lease, nothing else ever removes it) is unbounded etcd garbage at fleet
// churn, so the delete-time path must KNOW whether it landed instead of
// firing and forgetting. Retries up to `attempts` times (1s apart) and
// returns the last error on persistent failure — the caller surfaces it so
// the operator learns the key is orphaned rather than silently 204-ing.
func (oc *OwnershipCache) ReleaseOwnershipSync(sandfsID string, attempts int) error {
	oc.forgetOwnership(sandfsID)

	if oc.client == nil {
		return nil // local/test mode: cache-only, no etcd mirror.
	}
	return oc.releaseOwnershipCAS(context.Background(), sandfsID, attempts)
}

// deleteOwnership deletes an ownership record we own (owner-release, or the lazy
// path's release). Removes the cache entry AND its nodeSandfs membership.
func (oc *OwnershipCache) deleteOwnership(sandfsID string) {
	oc.forgetOwnership(sandfsID)

	if oc.client == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := oc.releaseOwnershipCAS(ctx, sandfsID, 3); err != nil {
			oc.logger.Warn("delete ownership (owner-release): etcd CAS delete failed", "sandfsID", sandfsID, "error", err)
		}
	}()
}

// ShedOwnership performs a voluntary load shed: this gateway (the owner,
// saturated) releases the sandfs's ownership so the Sandswap DNS re-routes the
// client to an idle peer on the next DNS resolution, and marks the sandfs as
// recently-shed for cooldownSec so we refuse to re-claim it during the DNS
// cache window (preventing the shed from being undone by a client routed back
// to us). The caller MUST have already verified the preconditions:
// cold-path request, sustained saturation, and an idle peer exists.
//
// This is the only non-failure-driven ownership switch in the tolerance-first
// model, so it is conservative (only fires on cold paths, never on warm/sticky
// leases) and gated by the enable-load-shed config flag (default on).
func (oc *OwnershipCache) ShedOwnership(sandfsID string, cooldownSec int) {
	// never shed a sandfs whose cold mount is IN FLIGHT — the
	// pre-claimed waiter's NoteMounted would no-op on the forgotten entry
	// (uncovered live mount) and the shed's designed peer re-claim makes the
	// second mount certain. Skip: shedding is best-effort rebalancing.
	if oc.Dispatching(sandfsID) {
		oc.logger.Info("load shed skipped: cold mount in flight", "sandfsID", sandfsID)
		return
	}
	// An unconfirmed dispatch (a transport error with no proof the mount did
	// not land) is the same hazard: releasing the record would let a peer
	// claim and dual-mount while our mount may be live.
	oc.mu.Lock()
	suspect := false
	if e, ok := oc.cache[sandfsID]; ok {
		suspect = e.suspect
	}
	oc.mu.Unlock()
	if suspect {
		oc.logger.Info("load shed skipped: mount outcome unconfirmed", "sandfsID", sandfsID)
		return
	}
	oc.deleteOwnership(sandfsID)
	if cooldownSec <= 0 {
		cooldownSec = 30
	}
	expiry := time.Now().Add(time.Duration(cooldownSec) * time.Second)
	oc.shedMu.Lock()
	oc.recentlyShed[sandfsID] = expiry
	oc.shedMu.Unlock()
	oc.logger.Info("load shed: released ownership for saturated rebalance",
		"sandfsID", sandfsID, "cooldownSec", cooldownSec)
}

// NoteDispatchUnconfirmed records that a cold-mount command was dispatched but
// its outcome is unknown — a transport error gives no proof the mount did not
// land. The entry becomes orphan-uncertain: a retry cannot dispatch
// (BeginDispatch refuses suspect), a shed cannot release its record, and the
// normal Claim/presence/T_safe or node-reconnect-clean path resolves it.
func (oc *OwnershipCache) NoteDispatchUnconfirmed(sandfsID string) {
	oc.mu.Lock()
	if e, ok := oc.cache[sandfsID]; ok {
		e.suspect = true
		e.dispatching = false
	}
	oc.mu.Unlock()
}

// isRecentlyShed reports whether the sandfs is still in the shed cooldown
// window (we refuse to re-claim it). Also opportunistically evicts an expired
// entry so the map doesn't grow unboundedly between sweep ticks.
func (oc *OwnershipCache) isRecentlyShed(sandfsID string) bool {
	oc.shedMu.Lock()
	defer oc.shedMu.Unlock()
	expiry, ok := oc.recentlyShed[sandfsID]
	if !ok {
		return false
	}
	if time.Now().After(expiry) {
		delete(oc.recentlyShed, sandfsID)
		return false
	}
	return true
}

// ClearShed removes a sandfs from the recently-shed set. Called by the
// ownership watch loop when it observes another gateway create/takeover the
// sandfs (a peer claimed it) — the shed achieved its goal, so the cooldown is
// no longer needed and we can claim normally on a future no-owner event.
func (oc *OwnershipCache) ClearShed(sandfsID string) {
	oc.shedMu.Lock()
	delete(oc.recentlyShed, sandfsID)
	oc.shedMu.Unlock()
}

// ShedCooldownSweep evicts expired recentlyShed entries. Called by a background
// ticker so the map is bounded even if no watch event ever clears an entry
// (e.g. the sandfs is abandoned after a shed).
func (oc *OwnershipCache) ShedCooldownSweep() {
	oc.shedMu.Lock()
	defer oc.shedMu.Unlock()
	now := time.Now()
	for id, expiry := range oc.recentlyShed {
		if now.After(expiry) {
			delete(oc.recentlyShed, id)
		}
	}
}

// forgetOwnership removes a sandfs from the cache and nodeSandfs (no etcd
// write). Used by deleteOwnership, ReleaseOwnership, and the watch loop on
// takeover/delete.
func (oc *OwnershipCache) forgetOwnership(sandfsID string) {
	oc.mu.Lock()
	if entry, ok := oc.cache[sandfsID]; ok {
		oc.updateNodeSandfsLocked(sandfsID, entry.placement, "")
	}
	delete(oc.cache, sandfsID)
	oc.mu.Unlock()
}

// SetRoutingAddrs records this gateway's externally-reachable addresses.
// gatewayURL is the base URL agents use (307 redirects + owner-aware DNS CNAME
// target); streamAddr is host:port sandlots use to reconnect to THIS gateway.
// Both are written into the gateway registry key (plain, no lease); with
// an etcd client this also rewrites the registry immediately so a restart with
// a changed address publishes O(1) globally. Call before StartHealthLoop so the
// initial registry write carries them.
func (oc *OwnershipCache) SetRoutingAddrs(gatewayURL, streamAddr string) {
	oc.mu.Lock()
	oc.gatewayURL = gatewayURL
	oc.streamAddr = streamAddr
	oc.mu.Unlock()
	if oc.client != nil {
		oc.writeGatewayRegistry()
	}
}

// SetNodeCountFunc overrides the node-count source for the health key. Production
// derives it from the stream server's connected sandlots; tests use this to
// simulate a compute-present gateway. Passing nil restores the default.
func (oc *OwnershipCache) SetNodeCountFunc(fn func() int) {
	oc.mu.Lock()
	defer oc.mu.Unlock()
	oc.nodeCountFn = fn
}

// SetFenceController wires the etcd-partition self-fence: when the
// health-key write has failed continuously for `threshold`, the health loop
// calls unmountAllFn to actively release every mount this gateway holds (over
// the node streams, which STAY connected), then fenceFn(true); on recovery it
// calls fenceFn(false).
//
// The fence closes the model's last ambiguity: a gateway whose health key is
// stale because it is etcd-partitioned but ALIVE and serving is
// indistinguishable in etcd from a dead one. Fencing makes "stale past the
// threshold" mean "holds no mounts", which is what makes the time-guarded
// takeover and both-dead reclamation sound. Releasing actively (rather than by
// dropping streams and letting each node run its own T_tolerance + T_clean)
// keeps the release inside fence + T_clean, so T_safe needs no fence term, and
// leaves node capacity warm for an in-place recovery.
//
// unmountAllFn returns the number of mounts it released (for logging); nil in
// local/test mode.
func (oc *OwnershipCache) SetFenceController(fenceFn func(fenced bool), unmountAllFn func() int, threshold time.Duration) {
	oc.mu.Lock()
	defer oc.mu.Unlock()
	oc.fenceFn = fenceFn
	oc.unmountAllFn = unmountAllFn
	if threshold > 0 {
		oc.fenceThreshold = threshold
	}
}

// UpdateFenceThreshold hot-reloads the etcd-partition self-fence threshold
// (staleness.etcd_fence_sec). The same time-order invariant OnNodeConnect
// enforces at connect time must hold for EVERY currently-connected node at the
// new value: T_safe > fence + warden + heartbeat (a peer that sees a node's
// presence key absent concludes "every mount on it is released"; a longer
// fence would let the owner's release legitimately still be in flight past
// that conclusion). A violating value is refused — the caller keeps the
// previous threshold. Deployments should keep -etcd-fence-sec uniform across
// gateways.
//
// Lock order: oc.mu → NodeConnected → stream-server node table. Safe because
// no stream-server path takes that table's write lock and then calls back
// into oc.mu-taking ownership methods while holding it (node add/remove run
// in the callback goroutines before/after OnNodeConnect, not under the table
// lock).
func (oc *OwnershipCache) UpdateFenceThreshold(d time.Duration) error {
	if d <= 0 {
		return fmt.Errorf("etcd fence threshold must be positive, got %v", d)
	}
	oc.mu.Lock()
	defer oc.mu.Unlock()
	for nodeID, tSafe := range oc.presenceTTLs {
		if !oc.NodeConnected(nodeID) {
			continue // disconnected nodes' safety is their own tolerance chain
		}
		warden := oc.presenceWardenSecs[nodeID]
		if warden == 0 {
			warden = defaultTimingWardenSec
		}
		floor := d + time.Duration(warden)*time.Second + nodeHeartbeatInterval
		if tSafe <= floor {
			return fmt.Errorf("new fence threshold %v violates T_safe > fence + warden + heartbeat for connected node %s (tSafe=%v warden=%ds); keeping previous threshold %v",
				d, nodeID, tSafe, warden, oc.fenceThreshold)
		}
	}
	oc.fenceThreshold = d
	return nil
}

// SetStalenessThresholds overrides the health-staleness thresholds. Zero values
// keep the default for that field. Set before StartHealthLoop in production
// (from config flags); tests set small values to drive the state machine in
// seconds. See the default* consts for semantics.
//
// Returns an error (changing nothing) when a new claimDeadGuard would break the
// pair invariant with the live Claim cache TTL: TTL ≤ 2 × guard (see
// SetCacheTTL). Lowering the guard below TTL/2 tightens the safety ceiling
// under the TTL the process is already serving with — refuse the guard change
// (the operator lowers the TTL first), mirroring UpdateFenceThreshold's
// refuse-invariant-breaking-values stance.
func (oc *OwnershipCache) SetStalenessThresholds(routeStale, claimGuard, alertStale time.Duration) error {
	oc.mu.Lock()
	defer oc.mu.Unlock()
	// Validate the guard/TTL pair BEFORE applying anything (all-or-nothing).
	if claimGuard > 0 {
		ceil := 2 * claimGuard
		if ceil > cacheTTLMaxCeil {
			ceil = cacheTTLMaxCeil
		}
		if ttl := time.Duration(oc.cacheTTLNS.Load()); ttl > ceil {
			return fmt.Errorf("claim-dead-guard %v would lower the ownership-cache-TTL safety ceiling (2×guard=%v, abs cap %v) below the live TTL %v; lower -ownership-cache-ttl-sec first or keep the guard",
				claimGuard, 2*claimGuard, cacheTTLMaxCeil, ttl)
		}
	}
	if routeStale > 0 {
		oc.routeStaleThreshold = routeStale
	}
	if claimGuard > 0 {
		oc.claimDeadGuard = claimGuard
	}
	if alertStale > 0 {
		oc.alertStaleThreshold = alertStale
	}
	return nil
}

// SetStalenessAndCacheTTL applies the staleness thresholds and the Claim
// fast-path TTL as ONE all-or-nothing pair. The guard/TTL ceiling invariant
// (TTL ≤ 2 × guard, capped at cacheTTLMaxCeil) is validated against the
// INCOMING guard, not the live one: applying SetStalenessThresholds and
// SetCacheTTL sequentially rejects config-valid pairs whenever one leg is
// validated against the other's OLD value — startup wiring order, and
// hot-reload commits that change both keys at once. Zero route/guard/alert
// values keep the live/default value for that field (mirroring
// SetStalenessThresholds); cacheTTL follows SetCacheTTL semantics with no
// zero sentinel (must be >= 1s).
func (oc *OwnershipCache) SetStalenessAndCacheTTL(routeStale, claimGuard, alertStale, cacheTTL time.Duration) error {
	if cacheTTL < time.Second {
		return fmt.Errorf("ownership cache TTL must be >= 1s, got %v", cacheTTL)
	}
	oc.mu.Lock()
	defer oc.mu.Unlock()
	guard := claimGuard
	if guard <= 0 {
		guard = oc.claimDeadGuard
	}
	if guard <= 0 {
		guard = defaultClaimDeadGuard // unset ⇒ default (same fallback shape as SetCacheTTL)
	}
	ceil := 2 * guard
	if ceil > cacheTTLMaxCeil {
		ceil = cacheTTLMaxCeil
	}
	if cacheTTL > ceil {
		return fmt.Errorf("ownership cache TTL %v exceeds the safety ceiling min(2×claim-dead-guard=%v, %v); takeover-visibility windows could overlap", cacheTTL, 2*guard, cacheTTLMaxCeil)
	}
	if routeStale > 0 {
		oc.routeStaleThreshold = routeStale
	}
	if claimGuard > 0 {
		oc.claimDeadGuard = claimGuard
	}
	if alertStale > 0 {
		oc.alertStaleThreshold = alertStale
	}
	oc.cacheTTLNS.Store(int64(cacheTTL))
	return nil
}

// cacheTTLMaxCeil is the absolute upper bound on the Claim fast-path freshness
// window, independent of claimDeadGuard: a guard raised to an extreme value
// must not let the TTL ceiling drift with it past any sane takeover-visibility
// budget.
const cacheTTLMaxCeil = 300 * time.Second

// SetCacheTTL overrides the Claim fast-path freshness window — the etcd
// revalidation cadence, and with it the gateway's steady etcd read load:
//
//	linearizable Gets/s ≈ (actively-queried sandfs owned by this gateway) / TTL
//
// (Adding gateways does NOT divide this: each sandfs belongs to exactly one
// gateway, so the fleet-wide total is actives/TTL regardless of gateway count.)
//
// Safety derivation (why any value up to the ceiling is sound):
//   - Every claimTime refresh observes truth — the slow path's linearizable
//     Get, the watch echo of our OWN CAS write, or a mount we ourselves
//     dispatched. The TTL therefore never manufactures a wrong belief; it only
//     decides how often a healthy gateway asks etcd for fresh truth (the watch
//     already delivers every ownership event, including takeovers of our keys,
//     within ms; the TTL is the self-heal net for the watch's degraded mode,
//     the ErrCompacted fall-back-to-current case).
//   - While this gateway is healthy (health key refreshed every 5s), NO peer
//     can take over our keys: every takeover path's first gate is ownerDead —
//     health stale past claimDeadGuard. Healthy ⇒ the gate never opens ⇒ any
//     TTL is safe.
//   - The pause/recover corner bounds the ceiling: the earliest a peer's
//     takeover can COMMIT is ownerDead (health stale > guard) + the per-sandfs
//     deadSince guard ≈ 2 × claimDeadGuard after our last health write, while
//     a stale-cache serve requires entry age < TTL. With TTL ≤ 2 × guard the
//     two windows cannot overlap — a pause shorter than 2×guard cannot have
//     produced a committed takeover, and a longer pause has already expired
//     the entry, forcing the first post-recovery Claim onto a fresh read.
//
// Validation: 1s ≤ d ≤ min(2 × claimDeadGuard, cacheTTLMaxCeil). A violating
// value returns an error and changes nothing (startup and hot-reload both
// refuse; the pair is additionally re-checked when the guard changes — see
// SetStalenessThresholds).
func (oc *OwnershipCache) SetCacheTTL(d time.Duration) error {
	if d < time.Second {
		return fmt.Errorf("ownership cache TTL must be >= 1s, got %v", d)
	}
	oc.mu.Lock()
	guard := oc.claimDeadGuard
	oc.mu.Unlock()
	if guard <= 0 {
		guard = defaultClaimDeadGuard // unset ⇒ default (same fallback shape as the timing defaults)
	}
	ceil := 2 * guard
	if ceil > cacheTTLMaxCeil {
		ceil = cacheTTLMaxCeil
	}
	if d > ceil {
		return fmt.Errorf("ownership cache TTL %v exceeds the safety ceiling min(2×claim-dead-guard=%v, %v); takeover-visibility windows could overlap", d, 2*guard, cacheTTLMaxCeil)
	}
	oc.cacheTTLNS.Store(int64(d))
	return nil
}

// SetCacheTTLForTest overrides the Claim fast-path freshness window WITHOUT
// validation — tests drive sub-second TTLs to exercise expiry without sleeping
// (the production validation enforces >= 1s). Restore to defaultCacheTTL after.
func (oc *OwnershipCache) SetCacheTTLForTest(d time.Duration) {
	oc.cacheTTLNS.Store(int64(d))
}

// SetAlertScanInterval overrides the staleness-alert-scan cadence (>= 10s; the
// scan is a full ownership-prefix sweep on the human gateway, so a floor keeps
// a misconfigured 1s value from turning the control plane into a constant
// full scan). Large fleets raise it (e.g. 300s at a million sandfs — the scan
// decodes every ownership value each pass). Returns an error and changes
// nothing on violation.
func (oc *OwnershipCache) SetAlertScanInterval(d time.Duration) error {
	if d < 10*time.Second {
		return fmt.Errorf("alert scan interval must be >= 10s, got %v", d)
	}
	oc.alertScanIntervalNS.Store(int64(d))
	return nil
}

// currentNodeCount returns the number of connected sandlot nodes for the health
// key, using the override fn when set, else the stream server connection count.
func (oc *OwnershipCache) currentNodeCount() int {
	oc.mu.Lock()
	fn := oc.nodeCountFn
	oc.mu.Unlock()
	if fn != nil {
		return fn()
	}
	if oc.streamSrv != nil {
		return len(oc.streamSrv.Nodes())
	}
	return 0
}

// noteHealthWriteFailure stamps the outage anchor on the first failed health
// write and reports whether the outage has now lasted past the fence threshold
// (with the threshold that applied). The anchor is cleared by
// noteHealthWriteSuccess, so only a CONTINUOUS outage can reach the threshold:
// a healed sub-threshold blip must not leave a stale anchor behind, or a later
// single failed write would compute an elapsed time far past the threshold and
// fence — mass-unmounting every mount — on one transient error.
func (oc *OwnershipCache) noteHealthWriteFailure(now time.Time) (down, threshold time.Duration, fire bool) {
	oc.mu.Lock()
	defer oc.mu.Unlock()
	if oc.etcdDownSince.IsZero() {
		oc.etcdDownSince = now
	}
	threshold = oc.fenceThreshold
	down = now.Sub(oc.etcdDownSince)
	return down, threshold, threshold > 0 && down >= threshold
}

// noteHealthWriteSuccess clears the outage anchor (the fence clock) on every
// successful health write — the common recovery point for both a healed blip
// (fence never engaged) and a lifted fence.
func (oc *OwnershipCache) noteHealthWriteSuccess() {
	oc.mu.Lock()
	oc.etcdDownSince = time.Time{}
	oc.mu.Unlock()
}

// StartHealthLoop starts a background goroutine that periodically updates
// this gateway's health key in etcd, and writes the gateway registry key once
// on startup (the routing addresses are configuration — a single write suffices,
// refreshed only when SetRoutingAddrs/WriteGatewayRegistry is called again).
func (oc *OwnershipCache) StartHealthLoop() {
	// Initial writes: the health key (liveness, plain key) and the gateway
	// registry key (routing addresses, plain). SetRoutingAddrs already wrote the
	// registry when it ran; this is the belt-and-suspenders startup registration.
	oc.writeHealthKey()
	oc.writeGatewayRegistry()

	go func() {
		// Refresh ticker — the health key has NO lease, so this cadence is the
		// liveness carrier: last_healthy_ts goes at most healthRefreshInterval
		// stale for a live gateway. The Put result also drives etcdAlive
		// (fail-closed Claim fast-path guard). node_count changes are pushed
		// immediately via TouchHealth (OnConnect/OnDisconnect).
		ticker := time.NewTicker(healthRefreshInterval)
		defer ticker.Stop()

		etcdWasDown := false
		fenced := false
		for {
			select {
			case <-oc.healthDone:
				return
			case <-ticker.C:
				if err := oc.writeHealthKey(); err != nil {
					oc.etcdAlive.Store(false)
					etcdWasDown = true

					// Etcd-partition self-fence: sustained write
					// failure past the fence threshold means this gateway can
					// no longer coordinate (no presence keep-alives, no health
					// refresh, claims fail closed). ACTIVELY release every
					// mount we hold — over the node streams, which stay
					// connected — so "our health key is stale" carries no
					// possibility of a hidden live mount. That is what makes
					// the time-guarded takeover and both-dead reclamation
					// sound, and it completes within fence + T_clean, which is
					// why T_safe needs no fence term. Recovery is in-place: on
					// the first successful write we unfence, re-grant presence
					// and serve again — the nodes never disconnected, so their
					// VM pools stayed warm.
					down, threshold, fire := oc.noteHealthWriteFailure(time.Now())
					oc.mu.Lock()
					fn := oc.fenceFn
					unmountAll := oc.unmountAllFn
					oc.mu.Unlock()
					if fire && !fenced {
						oc.logger.Warn("etcd unreachable past fence threshold; self-fencing (actively releasing all mounts; node streams stay connected)",
							"down_sec", int(down.Seconds()), "threshold_sec", int(threshold.Seconds()))
						fenced = true
						// Publish the fence state BEFORE any release work: a cold
						// mount dispatched before the fence that confirms while the
						// release is still running must be compensated, not recorded
						// (NoteMountedChecked / BeginDispatch gate on it).
						oc.mu.Lock()
						oc.fenced = true
						oc.mu.Unlock()
						if fn != nil {
							fn(true)
						}
						if unmountAll != nil {
							// Runs on its own goroutine: unmounting thousands of
							// mounts must not stall the health/liveness ticker.
							go func() {
								released := unmountAll()
								oc.logger.Warn("self-fence: released all mounts",
									"released", released)
							}()
						}
					}
				} else {
					oc.etcdAlive.Store(true)
					// A successful write ends the outage: clear the fence clock
					// even when the fence never engaged, so a healed blip cannot
					// leave a stale anchor behind (see noteHealthWriteFailure).
					oc.noteHealthWriteSuccess()
					if fenced {
						// Lift the fence: etcd writes work again. The nodes
						// never disconnected, so serving resumes in place — but
						// their presence leases expired during the outage, so
						// re-grant for EVERY connected node (not just the
						// presencePending set below, which only covers nodes
						// that connected while etcd was down).
						fenced = false
						oc.mu.Lock()
						oc.fenced = false
						fn := oc.fenceFn
						oc.mu.Unlock()
						if fn != nil {
							fn(false)
						}
						oc.logger.Info("self-fence lifted: etcd reachable again; re-granting presence for all connected nodes")
						if oc.streamSrv != nil {
							for _, nodeID := range oc.streamSrv.Nodes() {
								go func(id string) {
									if tSafe := oc.tSafeForNode(id); tSafe > 0 {
										_ = oc.regrantPresence(id, tSafe)
									}
								}(nodeID)
							}
						}
					}
					if etcdWasDown {
						// etcd recovered after an outage: re-anchor the presence
						// keys of every node admitted with presencePending
						// (connect during the outage). The 5s health cadence
						// bounds how long a connected node stays unanchored —
						// far tighter than waiting for its next 30s heartbeat.
						etcdWasDown = false
						oc.mu.Lock()
						pending := make([]string, 0, len(oc.presencePending))
						for nodeID := range oc.presencePending {
							pending = append(pending, nodeID)
						}
						oc.mu.Unlock()
						for _, nodeID := range pending {
							go func(id string) {
								if tSafe := oc.tSafeForNode(id); tSafe > 0 {
									_ = oc.regrantPresence(id, tSafe)
								}
							}(nodeID)
						}
					}
				}
			}
		}
	}()

	// Staleness alert scan is started separately (StartStalenessAlertScan) on the
	// human gateway only — it does a full ownership-prefix scan to aggregate
	// stranded sandfs by dead owner, which is a control-plane concern.
}

// StartStalenessAlertScan starts a background loop (human-gateway only) that
// periodically full-scans the ownership prefix, groups sandfs by their owner
// gateway, and warns once per owner whose health record is stale past the alert
// threshold while sandfs are still pointed at it. It is the detection signal
// for "a gateway died and its sandfs are stranded" — surfacing otherwise-silent
// failures (ownership keys persist with no lease, so nothing else fires). Run on
// the human gateway only (the control plane): exec gateways detect peer
// death per-request via Claim's ownerDead. Nil client (single-node/test) is a
// no-op.
func (oc *OwnershipCache) StartStalenessAlertScan() {
	if oc.client == nil {
		return
	}
	go oc.runStalenessAlertScan()
}

// runStalenessAlertScan periodically full-scans ownership and warns about stale
// owners with stranded sandfs. The interval is re-derived from the CURRENT
// value on every iteration (mirroring the lease reaper), so a hot-reloaded
// cadence tightens/loosens the scan on the next tick instead of lagging one
// old-interval behind.
func (oc *OwnershipCache) runStalenessAlertScan() {
	for {
		t := time.NewTimer(time.Duration(oc.alertScanIntervalNS.Load()))
		select {
		case <-oc.healthDone:
			t.Stop()
			return
		case <-t.C:
			if _, err := oc.ScanStaleOwners(context.Background()); err != nil {
				oc.logger.Warn("staleness alert scan failed", "error", err)
			}
		}
	}
}

// ScanStaleOwners full-scans the ownership prefix, groups sandfs by owner, and
// warns once per owner whose health record is stale past the alert threshold
// (or absent). Returns the map of stale owner gatewayID → stranded sandfs count
// (for the reap-stuck tool's dry-run report). O(all ownership keys) per call +
// O(distinct owners) health GETs; intended for the low-frequency management
// plane, not the request hot path.
func (oc *OwnershipCache) ScanStaleOwners(ctx context.Context) (map[string]int, error) {
	if oc.client == nil {
		return nil, nil
	}
	oc.mu.Lock()
	threshold := oc.alertStaleThreshold
	oc.mu.Unlock()

	rangeEnd := clientv3.GetPrefixRangeEnd(ownershipPrefix)
	start := ownershipPrefix
	ownerCounts := make(map[string]int)
	for {
		resp, err := oc.client.Get(ctx, start, clientv3.WithRange(rangeEnd), clientv3.WithLimit(ownershipLoadPageSize))
		if err != nil {
			return nil, fmt.Errorf("etcd get ownership prefix: %w", err)
		}
		for _, kv := range resp.Kvs {
			var val OwnershipValue
			if json.Unmarshal(kv.Value, &val) != nil {
				continue
			}
			// Only stranded sandfs matter: owned by a (possibly dead) gateway that
			// is not us. Self-owned sandfs are this gateway's responsibility, not
			// a peer-death alert.
			if val.GatewayID == "" || val.GatewayID == oc.gatewayID {
				continue
			}
			ownerCounts[val.GatewayID]++
		}
		if !resp.More {
			break
		}
		start = string(resp.Kvs[len(resp.Kvs)-1].Key) + "\x00"
	}

	stale := make(map[string]int)
	sctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	for gwID, count := range ownerCounts {
		d, present := oc.ownerStaleness(sctx, gwID)
		if present && d <= threshold {
			continue
		}
		stale[gwID] = count
		oc.logger.Warn("owner gateway health stale; sandfs stranded on dead owner",
			"owner_gateway_id", gwID,
			"stale_sec", int(d.Seconds()),
			"health_key_present", present,
			"stuck_sandfs", count,
			"hint", "if both the owner and its nodes are permanently gone, reclaim via the human-gateway reap-stuck tool")
	}
	return stale, nil
}

// ReapStuckReport is the result of ReapStuckOwnership.
type ReapStuckReport struct {
	OwnerGatewayID string   `json:"owner_gateway_id"`
	DryRun         bool     `json:"dry_run"`
	Reaped         []string `json:"reaped"` // sandfs ids deleted (or that would be, in dry-run)
	ReapedCount    int      `json:"reaped_count"`
	Skipped        []string `json:"skipped,omitempty"` // sandfs ids skipped (mounted + node presence still alive)
	SkippedCount   int      `json:"skipped_count"`
}

// reapDeleteCAS deletes one ownership record ONLY if it is still the exact
// revision the scan read ("" moved on" ⇒ false, kept). The reaper must never
// blind-delete: between its scan and its delete, a LIVE gateway can CAS-claim
// the very record being examined — an idle dead-owned sandfs is claimable by
// any gateway once the same claim-dead guard elapses, which is precisely the
// traffic pattern (clients retrying every ~1s) that accompanies a dead owner.
// Deleting the fresh owner's record while it holds a mount would re-open the
// sandfs to a second claim elsewhere — dual mount, the one failure the whole
// ownership model exists to prevent. The same ModRevision-CAS discipline
// every other mutator in this file uses.
func (oc *OwnershipCache) reapDeleteCAS(ctx context.Context, sandfsID string, modRev int64) (bool, error) {
	key := ownershipPrefix + sandfsID
	resp, err := oc.client.Txn(ctx).
		If(clientv3.Compare(clientv3.ModRevision(key), "=", modRev)).
		Then(clientv3.OpDelete(key)).
		Commit()
	if err != nil {
		return false, err
	}
	return resp.Succeeded, nil
}

// ReapStuckOwnership is the manual both-dead reclamation tool for a specific
// (permanently dead) owner gateway. It scans the ownership prefix for sandfs
// owned by targetGwID and deletes the records that are safe to reclaim:
//
//   - IDLE sandfs (node_id empty): the owner is dead (health key absent or stale
//     past the claim-dead guard) → reclaim. Mirrors the on-demand claim's per-sandfs
//     semantics but scoped to one operator-named owner and immediate (no
//     retention wait) — the operator has already confirmed the owner is gone.
//   - MOUNTED sandfs (node_id non-empty): reclaim ONLY if the node's presence
//     key is absent (the node has been gone past T_safe, so every cleanup path
//     has finished and there is no live mount to double-mount). If the presence
//     key still exists, SKIP — the node may still be tolerating/cleaning, and
//     deleting ownership under a live mount risks a dual-mount.
//
// Deletes are CAS-guarded one per Txn (a blind batch delete could remove a
// record a live gateway claimed between the scan and the delete — see
// reapDeleteCAS). batchSize bounds the candidates processed per call
// (default 100; the operator repeats until ReapedCount < batch_size). dryRun
// reports what WOULD be deleted without deleting. Intended for the
// human-gateway control plane (operator-driven), NOT the request hot path.
func (oc *OwnershipCache) ReapStuckOwnership(ctx context.Context, targetGwID string, dryRun bool, batchSize int) (*ReapStuckReport, error) {
	if oc.client == nil {
		return nil, fmt.Errorf("no etcd client (single-node mode)")
	}
	if targetGwID == "" {
		return nil, fmt.Errorf("target gateway_id is required")
	}
	if targetGwID == oc.gatewayID {
		return nil, fmt.Errorf("%w (gateway_id=%s)", ErrCannotReapSelf, targetGwID)
	}
	if batchSize <= 0 {
		batchSize = 100
	}

	// Confirm the target owner is dead before reclaiming anything. This is the
	// safety gate: if the owner is alive (or merely stale within the guard), the
	// operator misjudged — refuse to touch its sandfs.
	stale, present := oc.ownerStaleness(ctx, targetGwID)
	oc.mu.Lock()
	guard := oc.claimDeadGuard
	oc.mu.Unlock()
	if present && stale <= guard {
		return nil, fmt.Errorf("%w: owner gateway %s health fresh within %v", ErrOwnerStillAlive, targetGwID, guard)
	}

	// Scan the ownership prefix for sandfs owned by the target.
	rangeEnd := clientv3.GetPrefixRangeEnd(ownershipPrefix)
	start := ownershipPrefix
	var cands []reapCandidate
	for {
		resp, err := oc.client.Get(ctx, start, clientv3.WithRange(rangeEnd), clientv3.WithLimit(ownershipLoadPageSize))
		if err != nil {
			return nil, fmt.Errorf("etcd get ownership prefix: %w", err)
		}
		for _, kv := range resp.Kvs {
			var val OwnershipValue
			if json.Unmarshal(kv.Value, &val) != nil {
				continue
			}
			if val.GatewayID != targetGwID {
				continue
			}
			cands = append(cands, reapCandidate{sandfsID: strings.TrimPrefix(string(kv.Key), ownershipPrefix), nodeID: val.NodeID, modRev: kv.ModRevision})
		}
		if !resp.More {
			break
		}
		start = string(resp.Kvs[len(resp.Kvs)-1].Key) + "\x00"
	}

	report := &ReapStuckReport{OwnerGatewayID: targetGwID, DryRun: dryRun}
	// Partition: idle → reap; mounted → reap only if presence absent.
	var toReap []reapCandidate
	for _, c := range cands {
		if c.nodeID == "" {
			toReap = append(toReap, c)
			continue
		}
		// Mounted: check the node's presence key. Absent → safe to reap.
		presenceCtx, presenceCancel := context.WithTimeout(ctx, 3*time.Second)
		presp, perr := oc.client.Get(presenceCtx, presenceKey(c.nodeID))
		presenceCancel()
		if perr != nil {
			// Can't determine presence → skip (fail-safe: don't risk a live mount).
			report.Skipped = append(report.Skipped, c.sandfsID)
			continue
		}
		if len(presp.Kvs) == 0 {
			toReap = append(toReap, c) // node gone past T_safe
		} else {
			report.Skipped = append(report.Skipped, c.sandfsID) // presence alive → skip
		}
	}
	// Bound one call's work (operator repeats): each candidate now costs one
	// CAS Txn, and a huge node must not blow the handler's 30s budget in one
	// call. batch_size = candidates processed per call.
	if len(toReap) > batchSize {
		report.Skipped = append(report.Skipped, sandfsIDsOf(toReap[batchSize:])...)
		toReap = toReap[:batchSize]
	}

	if dryRun {
		for _, c := range toReap {
			report.Reaped = append(report.Reaped, c.sandfsID)
		}
		report.ReapedCount = len(toReap)
		report.SkippedCount = len(report.Skipped)
		return report, nil
	}

	// CAS-guarded deletes, one Txn per candidate (see reapDeleteCAS for why a
	// blind delete is unsafe). A key that moved on (a live gateway claimed it)
	// is reported skipped, never touched.
	for _, c := range toReap {
		deleted, err := oc.reapDeleteCAS(ctx, c.sandfsID, c.modRev)
		if err != nil {
			oc.logger.Warn("reap-stuck: CAS delete failed; remaining candidates left for retry",
				"owner", targetGwID, "sandfsID", c.sandfsID, "error", err)
			return report, fmt.Errorf("reap delete %s: %w", c.sandfsID, err)
		}
		if deleted {
			report.Reaped = append(report.Reaped, c.sandfsID)
		} else {
			report.Skipped = append(report.Skipped, c.sandfsID)
			oc.logger.Info("reap-stuck: ownership moved on since the scan; left to its current owner",
				"sandfsID", c.sandfsID)
		}
	}
	report.ReapedCount = len(report.Reaped)
	report.SkippedCount = len(report.Skipped)
	oc.logger.Info("reap-stuck: reclaimed dead-owner sandfs",
		"owner", targetGwID, "reaped", report.ReapedCount, "skipped", report.SkippedCount, "dry_run", dryRun)
	return report, nil
}

// reapCandidate is one scan hit of a reap pass: the sandfs, its recorded node
// ("" = idle) and owner, and the ModRevision its delete will CAS against.
type reapCandidate struct {
	sandfsID string
	nodeID   string
	ownerGw  string
	modRev   int64
}

// sandfsIDsOf extracts the ids from scan candidates (report plumbing).
func sandfsIDsOf(cands []reapCandidate) []string {
	out := make([]string, 0, len(cands))
	for _, c := range cands {
		out = append(out, c.sandfsID)
	}
	return out
}

// ReapStuckNodeReport is the result of ReapStuckNodeOwnership.
type ReapStuckNodeReport struct {
	NodeID       string   `json:"node_id"`
	DryRun       bool     `json:"dry_run"`
	Reaped       []string `json:"reaped"` // sandfs ids deleted (or that would be, in dry-run)
	ReapedCount  int      `json:"reaped_count"`
	Skipped      []string `json:"skipped,omitempty"` // sandfs ids skipped (owner still alive)
	SkippedCount int      `json:"skipped_count"`
}

// ReapStuckNodeOwnership is the manual both-dead reclamation tool scoped to a
// sandlot NODE: it reclaims every sandfs currently recorded as mounted on
// targetNodeID whose owner is also dead. It is the node-granularity twin of
// ReapStuckOwnership (which is owner-granularity) — useful when a whole node
// is permanently retired and the operator wants to reclaim all its stranded
// sandfs in one call instead of per dead owner.
//
// Safety gate (same logic as ReapStuckOwnership's mounted branch, but checked
// ONCE for the node rather than per sandfs):
//
//   - The node's presence key /sandswap/node/{node_id}/presence MUST be absent.
//     Presence is leased with TTL = T_safe, so absence means the node has been
//     disconnected ≥ T_safe — every cleanup path (sandlot self-clean, warden
//     countdown) has provably finished, so there is no live mount to
//     double-mount. If the presence key still exists, the node may still be
//     alive/tolerating → REFUSE the whole call (do not touch any of its sandfs).
//   - Each candidate's owner must be dead (health key absent or stale past the
//     claim-dead guard). An alive owner will reclaim via the owner-release
//     three-part chain on its own; an alive owner's sandfs are SKIPPED, not
//     reaped, so the operator does not race a live owner's recovery.
//
// Why this stays manual (not automatic): a gateway partitioned from etcd but
// still connected to its sandlots keeps the mount alive and the warden countdown
// reset, yet its presence key still expires at T_safe (it cannot KeepAlive) —
// indistinguishable in etcd from a truly dead gateway. The operator's
// out-of-band confirmation that the node is really gone is what makes this
// safe; the automatic reaper must not act on this signal. See
// docs/how-it-works/resilience.md.
//
// Deletes are CAS-guarded one per Txn (see reapDeleteCAS); batchSize bounds
// the candidates processed per call (default 100; repeat until
// ReapedCount < batch_size). dryRun reports what WOULD be deleted without
// deleting. Intended for the human-gateway control plane.
func (oc *OwnershipCache) ReapStuckNodeOwnership(ctx context.Context, targetNodeID string, dryRun bool, batchSize int) (*ReapStuckNodeReport, error) {
	if oc.client == nil {
		return nil, fmt.Errorf("no etcd client (single-node mode)")
	}
	if targetNodeID == "" {
		return nil, fmt.Errorf("target node_id is required")
	}
	if batchSize <= 0 {
		batchSize = 100
	}

	// Safety gate: the node's presence key MUST be gone. A present presence
	// key means the node is alive or still within T_safe tolerance — refuse to
	// touch any of its sandfs (the operator may be looking at a stale view, or
	// the node is merely partitioned and will reconnect).
	presenceCtx, presenceCancel := context.WithTimeout(ctx, 3*time.Second)
	presp, perr := oc.client.Get(presenceCtx, presenceKey(targetNodeID))
	presenceCancel()
	if perr != nil {
		return nil, fmt.Errorf("presence get for node %s failed: %w", targetNodeID, perr)
	}
	if len(presp.Kvs) != 0 {
		return nil, fmt.Errorf("%w: node %s", ErrNodeStillPresent, targetNodeID)
	}

	// Scan the ownership prefix for sandfs mounted on the target node.
	rangeEnd := clientv3.GetPrefixRangeEnd(ownershipPrefix)
	start := ownershipPrefix
	var cands []reapCandidate
	for {
		resp, err := oc.client.Get(ctx, start, clientv3.WithRange(rangeEnd), clientv3.WithLimit(ownershipLoadPageSize))
		if err != nil {
			return nil, fmt.Errorf("etcd get ownership prefix: %w", err)
		}
		for _, kv := range resp.Kvs {
			var val OwnershipValue
			if json.Unmarshal(kv.Value, &val) != nil {
				continue
			}
			if val.NodeID != targetNodeID {
				continue
			}
			cands = append(cands, reapCandidate{sandfsID: strings.TrimPrefix(string(kv.Key), ownershipPrefix), nodeID: val.NodeID, ownerGw: val.GatewayID, modRev: kv.ModRevision})
		}
		if !resp.More {
			break
		}
		start = string(resp.Kvs[len(resp.Kvs)-1].Key) + "\x00"
	}

	report := &ReapStuckNodeReport{NodeID: targetNodeID, DryRun: dryRun}
	oc.mu.Lock()
	guard := oc.claimDeadGuard
	oc.mu.Unlock()

	// Per-candidate owner-dead check. An alive owner is skipped (its
	// owner-release chain will reclaim the sandfs; do not race it).
	var toReap []reapCandidate
	for _, c := range cands {
		if c.ownerGw == "" {
			// Unknown owner — cannot judge health. Skip (fail-safe).
			report.Skipped = append(report.Skipped, c.sandfsID)
			continue
		}
		stale, present := oc.ownerStaleness(ctx, c.ownerGw)
		if present && stale <= guard {
			// Owner alive → skip; it will reclaim via owner-release.
			report.Skipped = append(report.Skipped, c.sandfsID)
			continue
		}
		toReap = append(toReap, c)
	}
	// Bound one call's work (operator repeats): each candidate now costs one
	// CAS Txn. batch_size = candidates processed per call.
	if len(toReap) > batchSize {
		report.Skipped = append(report.Skipped, sandfsIDsOf(toReap[batchSize:])...)
		toReap = toReap[:batchSize]
	}

	if dryRun {
		for _, c := range toReap {
			report.Reaped = append(report.Reaped, c.sandfsID)
		}
		report.ReapedCount = len(toReap)
		report.SkippedCount = len(report.Skipped)
		return report, nil
	}

	// CAS-guarded deletes, one Txn per candidate (see reapDeleteCAS).
	for _, c := range toReap {
		deleted, err := oc.reapDeleteCAS(ctx, c.sandfsID, c.modRev)
		if err != nil {
			oc.logger.Warn("reap-stuck-node: CAS delete failed; remaining candidates left for retry",
				"node", targetNodeID, "sandfsID", c.sandfsID, "error", err)
			return report, fmt.Errorf("reap delete %s: %w", c.sandfsID, err)
		}
		if deleted {
			report.Reaped = append(report.Reaped, c.sandfsID)
		} else {
			report.Skipped = append(report.Skipped, c.sandfsID)
			oc.logger.Info("reap-stuck-node: ownership moved on since the scan; left to its current owner",
				"sandfsID", c.sandfsID)
		}
	}
	report.ReapedCount = len(report.Reaped)
	report.SkippedCount = len(report.Skipped)
	oc.logger.Info("reap-stuck-node: reclaimed dead-node sandfs",
		"node", targetNodeID, "reaped", report.ReapedCount, "skipped", report.SkippedCount, "dry_run", dryRun)
	return report, nil
}

// writeHealthKey refreshes this gateway's health key. The health key is a
// PLAIN key (no lease): liveness is carried entirely by last_healthy_ts, so
// the Put success/failure is also the etcd liveness probe (etcdAlive).
// Returns the error so the refresh loop can drive etcdAlive.
func (oc *OwnershipCache) writeHealthKey() error {
	if oc.client == nil {
		return nil // local/test mode: no etcd health key.
	}

	count := oc.currentNodeCount()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	val := GatewayHealthValue{
		LastHealthyTS: time.Now().Format(time.RFC3339),
	}
	// Publish the connected-sandlot count so the DNS can tell "alive but no
	// compute" (fault state — exclude from agent routing) apart from "alive with
	// compute". nil streamSrv (human mode) → 0, and the human gateway is never an
	// agent-routing target anyway (its gateway_url is empty).
	val.NodeCount = count
	data, _ := json.Marshal(val)

	key := healthPrefix + oc.gatewayID
	if _, err := oc.client.Put(ctx, key, string(data)); err != nil {
		oc.logger.Warn("health: put failed", "error", err)
		return err
	}
	return nil
}

// writeGatewayRegistry writes this gateway's routing registry key
// (/sandswap/gateway/{gateway_id}) as a PLAIN key (no lease): gateway_url and
// stream_addr are configuration, not liveness, so they survive the gateway's
// death (the DNS/307 can still resolve the owner during tolerance) and are
// rewritten on restart with a changed address in O(1). nil client no-op.
func (oc *OwnershipCache) writeGatewayRegistry() {
	if oc.client == nil {
		return // local/test mode: no etcd registry key.
	}
	oc.mu.Lock()
	val := GatewayRegistryValue{
		GatewayURL: oc.gatewayURL,
		StreamAddr: oc.streamAddr,
	}
	oc.mu.Unlock()
	data, err := json.Marshal(val)
	if err != nil {
		oc.logger.Warn("registry: marshal", "error", err)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := oc.client.Put(ctx, gatewayPrefix+oc.gatewayID, string(data)); err != nil {
		oc.logger.Warn("registry: put failed", "error", err)
	}
}

// WriteGatewayRegistry immediately rewrites the gateway registry key. Called on
// startup (after SetRoutingAddrs) and on config hot-reload when the routing
// addresses change, so a gateway that restarts with a different gateway_url
// publishes the new address right away — every sandfs it owns resolves to the
// new address on the next DNS query.
func (oc *OwnershipCache) WriteGatewayRegistry() {
	oc.writeGatewayRegistry()
}

// watchKeepaliveIntervalNS is how long the ownership watch may stay silent
// before the loop cancels and resubscribes it, in nanoseconds. This detects
// etcd watch channels that are open but silently dead (slow etcd, network
// degradation). Package-level ATOMIC (mirroring ownerReleaseSweepIntervalNS,
// whose comment records the same trap): a test's
// SetWatchKeepaliveIntervalForTest restore races a still-draining watch
// loop's read under -race.
var watchKeepaliveIntervalNS = int64(30 * time.Second)

// watchKeepalive loads the current keepalive interval.
func watchKeepalive() time.Duration {
	return time.Duration(atomic.LoadInt64(&watchKeepaliveIntervalNS))
}

// StartWatch starts a background goroutine that watches for ownership conflicts.
// If another gateway overwrites our generation, we release the local cache entry
// (and its nodeSandfs membership — migrated-takeover watch takeover). Includes a
// keepalive: if no events arrive within the keepalive interval, the watch is
// canceled and resubscribed.
//
// Resubscription discipline (three invariants):
//   - CANCEL the outgoing watch (wctx) before abandoning its channel. An
//     uncanceled watcher keeps its server-side subscription AND blocks the
//     client's shared watch dispatcher once its unread per-watcher channel
//     fills (clientv3's unicastResponse waits on the substream's unbuffered
//     recvc with no timeout). The ownership watch shares ONE gRPC watch stream
//     with every other watch on the same etcd client (streamKeyFromCtx groups
//     by outgoing metadata, which is empty for both here and the identity
//     store) — a wedged abandoned substream would silently stop BOTH caches
//     from updating, with no error anywhere.
//   - RESUME from watchRev+1, never from the boot snapshot revision. watchRev
//     advances after every applied batch, so a resubscribe replays only the
//     events that arrived while the old subscription was being torn down —
//     resubscribing from the full-load revision instead would replay the
//     cluster's entire event history every keepalive interval (and stale
//     replayed takeovers could evict current cache entries).
//   - Events between cancel and resubscribe are NOT lost: etcd retains them
//     and delivers them on the resumed stream from the bookmark.
func (oc *OwnershipCache) StartWatch() {
	if oc.client == nil {
		return // nil-client defense: no etcd in single-node mode
	}
	go func() {
		for {
			select {
			case <-oc.watchDone:
				return
			default:
			}

			// Resume from the watch bookmark (seeded from the full-load
			// snapshot revision on first subscription). 0 → from current.
			opts := []clientv3.OpOption{clientv3.WithPrefix()}
			oc.mu.Lock()
			resumeRev := oc.watchRev
			oc.mu.Unlock()
			if resumeRev > 0 {
				opts = append(opts, clientv3.WithRev(resumeRev+1))
			}
			wctx, wcancel := context.WithCancel(context.Background())
			wch := oc.client.Watch(wctx, ownershipPrefix, opts...)

			// Per-batch timeout: if no events arrive within the keepalive
			// interval, resubscribe. This detects etcd watch channels that are
			// open but not delivering events (slow etcd, network degradation).
			watchTimer := time.NewTimer(watchKeepalive())
			watchActive := true

			for watchActive {
				select {
				case resp, ok := <-wch:
					if !ok {
						watchActive = false
						break
					}
					// Reset the timer on each event batch.
					if !watchTimer.Stop() {
						select {
						case <-watchTimer.C:
						default:
						}
					}
					watchTimer.Reset(watchKeepalive())

					if err := resp.Err(); err != nil {
						if resp.CompactRevision != 0 {
							// The bookmarked revision was compacted — the
							// undelivered events are gone forever, so the
							// bookmark cannot be honored. Fall back to
							// subscribing from the current revision (fresh
							// cache entries still self-correct via cacheMaxAge,
							// same degraded-but-safe posture as before).
							oc.mu.Lock()
							oc.watchRev = 0
							oc.fullLoadRev = 0
							// compaction means the undelivered events are gone
							// FOREVER — invalidate every cached entry's freshness so the
							// next Claim takes the linearizable slow path instead of
							// fast-path-serving a missed takeover.
							// A subsequent watch event re-freshens naturally.
							for _, e := range oc.cache {
								e.claimTime = time.Time{}
							}
							oc.mu.Unlock()
							oc.logger.Warn("ownership watch: bookmarked revision compacted; watching from current", "compactRev", resp.CompactRevision)
						} else {
							oc.logger.Warn("ownership watch error", "error", err)
						}
						watchActive = false
						break
					}
					for _, ev := range resp.Events {
						oc.handleWatchEvent(ev)
					}
					// Advance the bookmark AFTER the batch has been applied, so
					// a crash between apply and advance at worst replays the
					// batch (idempotent), never skips it.
					oc.mu.Lock()
					if resp.Header.Revision > oc.watchRev {
						oc.watchRev = resp.Header.Revision
					}
					oc.mu.Unlock()

				case <-watchTimer.C:
					// Idle timeout: no ownership writes cluster-wide in the
					// keepalive interval — the steady state this design aims
					// for (zero writes per execution cycle). The restart is
					// routine keepalive (it detects watches that are open but
					// silently dead), NOT an error: warning here would spam
					// forever on a healthy quiet cluster.
					oc.logger.Debug("ownership watch idle; restarting (routine keepalive)")
					watchActive = false

				case <-oc.watchDone:
					wcancel()
					watchTimer.Stop()
					return
				}
			}
			// Cancel the outgoing watch BEFORE abandoning its channel (see the
			// doc comment): this releases the server-side subscription and
			// closes the substream, so it can never wedge the shared
			// dispatcher.
			wcancel()
			watchTimer.Stop()

			// Brief sleep before resubscribing.
			time.Sleep(1 * time.Second)
		}
	}()
}

func (oc *OwnershipCache) handleWatchEvent(ev *clientv3.Event) {
	// Extract sandfsID from key: /sandswap/owner/{sandfs_id}
	key := string(ev.Kv.Key)
	if !strings.HasPrefix(key, ownershipPrefix) {
		return
	}
	sandfsID := strings.TrimPrefix(key, ownershipPrefix)

	switch ev.Type {
	case clientv3.EventTypePut:
		// Fast path: every ownership write in the cluster is delivered to every
		// gateway on this prefix watch. The handler below only ever acts on
		// keys we hold state for (a cached entry or a shed-cooldown record) —
		// probe both maps first and skip the JSON decode entirely otherwise.
		if !oc.interestedIn(sandfsID) {
			return
		}

		var val OwnershipValue
		if err := json.Unmarshal(ev.Kv.Value, &val); err != nil {
			return
		}

		peerClaimedShed := false
		evictedMounted := false
		evictedNode := ""
		oc.mu.Lock()
		entry, ok := oc.cache[sandfsID]
		if ok {
			if val.GatewayID == oc.gatewayID {
				// Our ownership was updated (possibly by our own async etcd write).
				entry.generation = val.Generation
				entry.modRev = ev.Kv.ModRevision
				old := entry.placement
				entry.placement = val.NodeID
				entry.published = val.NodeID
				entry.claimTime = time.Now()
				// A confirmed fresh record of ours covers any pending mount —
				// clear the owner-release tombstone (claims may serve again;
				// if a sweep delete was still in flight it will produce a
				// DELETE event handled below).
				entry.ownerReleasing = false
				entry.releasingSince = time.Time{}
				oc.updateNodeSandfsLocked(sandfsID, old, val.NodeID)
			} else {
				// Another gateway took over — invalidate our cache and drop the
				// sandfs from nodeSandfs (migrated-takeover watch takeover).
				oc.logger.Warn("ownership lost to another gateway",
					"sandfsID", sandfsID, "newGateway", val.GatewayID)
				// symmetric with the DELETE branch — a still-MOUNTED
				// entry being evicted leaves a live mount uncovered; tear it
				// down so nobody trusts the stale local mount (production
				// reachability is gated by the takeover clocks, but the
				// asymmetry also made the first-party compensation e2e
				// timing-dependent).
				evictedMounted = entry.mounted
				evictedNode = entry.placement
				oc.updateNodeSandfsLocked(sandfsID, entry.placement, "")
				delete(oc.cache, sandfsID)
				// A peer claimed a sandfs we recently shed → the shed achieved its
				// goal. Clear the cooldown so a future no-owner event lets us claim
				// normally (no lingering refusal from a shed that already landed).
				peerClaimedShed = true
			}
		} else if val.GatewayID != oc.gatewayID {
			// We had no cached entry (e.g. we shed it, which forgets the cache),
			// and another gateway now owns it. If we recently shed this sandfs,
			// the shed landed — clear the cooldown.
			peerClaimedShed = true
		}
		oc.mu.Unlock()
		if evictedMounted {
			oc.compensateUncoveredMount(sandfsID, evictedNode, "ownership evicted by a foreign takeover while the sandfs was mounted")
		}
		if peerClaimedShed {
			oc.ClearShed(sandfsID)
		}

	case clientv3.EventTypeDelete:
		// A deleted record whose cache entry still claims a live mount leaves
		// that mount UNCOVERED — a peer could claim the sandfs and dual-mount
		// it until our lease expires (a background exec can hold it for an
		// hour). This happens when a deletion races our mount/publish: the
		// owner-release sweep, a manual release, a SandFS deletion, or a shed.
		// Compensate by tearing the mount down (idempotent unmount +
		// SettleUnmount-gated bound release). If the entry was not mounted,
		// the delete is the ordinary outcome of any release path — forget.
		oc.mu.Lock()
		entry, ok := oc.cache[sandfsID]
		wasMounted := ok && entry.mounted
		var mountedNode string
		if wasMounted {
			mountedNode = entry.placement
		}
		oc.mu.Unlock()
		oc.forgetOwnership(sandfsID)
		oc.clearDeadSince(sandfsID) // ownership gone — no dead owner to time.
		if wasMounted {
			oc.compensateUncoveredMount(sandfsID, mountedNode, "ownership record deleted while the sandfs was mounted")
		}
	}
}

// interestedIn reports whether a watch PUT on sandfsID can possibly change our
// state: we either hold a cached ownership entry for it or a shed-cooldown
// record. Every other key is a peer's bookkeeping write whose only observable
// effect on us is nothing — skipping its JSON decode keeps the per-write cost
// of the prefix watch at two map probes regardless of cluster size.
func (oc *OwnershipCache) interestedIn(sandfsID string) bool {
	oc.mu.Lock()
	_, ok := oc.cache[sandfsID]
	oc.mu.Unlock()
	if ok {
		return true
	}
	oc.shedMu.Lock()
	_, shed := oc.recentlyShed[sandfsID]
	oc.shedMu.Unlock()
	return shed
}

// StartOwnerReleaseSweep starts the owner-release background sweep (the
// three-part-chain ticker). Exec-gateway machinery: the sweep acts on
// pendingOwnerRelease entries, armed solely by OnNodeDisconnect — fired only
// from the exec-role stream callbacks, which the human gateway never installs
// (it accepts no exec-role node connections and never claims, so the sweep has
// no inputs there and must not run). Mirrors StartHealthLoop/StartWatch:
// called once at wiring time; nil client is a no-op inside the loop.
func (oc *OwnershipCache) StartOwnerReleaseSweep() {
	go oc.ownerReleaseSweepLoop()
}

// ownerReleaseSweepLoop runs the owner-release background sweep on a fixed interval.
func (oc *OwnershipCache) ownerReleaseSweepLoop() {
	if oc.client == nil {
		return
	}
	ticker := time.NewTicker(time.Duration(atomic.LoadInt64(&ownerReleaseSweepIntervalNS)))
	defer ticker.Stop()
	for {
		select {
		case <-oc.watchDone:
			return
		case <-ticker.C:
			oc.runOwnerReleaseSweep()
			oc.sweepDeadSince()
		}
	}
}

// runOwnerReleaseSweep collects the pending-disconnect nodes whose local T_safe timer has
// elapsed and releases their sandfs ownership when the three-part chain holds.
func (oc *OwnershipCache) runOwnerReleaseSweep() {
	oc.mu.Lock()
	type b1Candidate struct{ nodeID string }
	var candidates []b1Candidate
	for nodeID, discTime := range oc.pendingOwnerRelease {
		tSafe := oc.presenceTTLs[nodeID]
		if tSafe <= 0 {
			continue // no timing recorded (shouldn't happen) — skip
		}
		if time.Since(discTime) >= tSafe {
			candidates = append(candidates, b1Candidate{nodeID})
		}
	}
	oc.mu.Unlock()

	for _, c := range candidates {
		oc.ownerReleaseCheckAndRelease(c.nodeID)
	}
}

// ownerReleaseCheckAndRelease evaluates the three-part chain for a candidate node and, if
// it holds, deletes ownership for every sandfs on that node:
//
//	(0) OnDisconnect fired — the node is in pendingOwnerRelease (checked by runOwnerReleaseSweep).
//	(1) T_safe elapsed locally since OnDisconnect (checked by runOwnerReleaseSweep).
//	(2) presence key absent (or owned by another gateway → the node migrated,
//	    which implies its mounts are released) — checked here via etcd.
//	(3) self healthy — our own health key is alive (checked here via etcd).
func (oc *OwnershipCache) ownerReleaseCheckAndRelease(nodeID string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// (2) presence key absent or not ours.
	state, err := oc.presenceState(ctx, nodeID)
	if err != nil {
		oc.logger.Debug("owner-release: presence get failed (etcd issue); skipping", "nodeID", nodeID, "error", err)
		return
	}
	if state == presenceSelf {
		// Our key is still alive — the node disconnected < T_safe ago (or
		// reconnected without OnConnect clearing pendingOwnerRelease yet). Skip.
		return
	}
	if state == presenceOther {
		// Node migrated to another gateway; its mounts are released (migration
		// implies T_isolation elapsed). Release.
	}

	// (3) self healthy.
	if !oc.selfHealthy(ctx) {
		oc.logger.Debug("owner-release: self not healthy; skipping", "nodeID", nodeID)
		return
	}

	// Release every sandfs mounted on this node (nodeSandfs locates them).
	oc.mu.Lock()
	sandfsIDs := make([]string, 0, len(oc.nodeSandfs[nodeID]))
	for id := range oc.nodeSandfs[nodeID] {
		sandfsIDs = append(sandfsIDs, id)
	}
	delete(oc.pendingOwnerRelease, nodeID)
	oc.mu.Unlock()

	// Batched release: the in-memory entries are flagged ownerReleasing
	// (NOT forgotten — see ownershipEntry.ownerReleasing) so a concurrent lazy
	// Claim cannot remount the sandfs inside the [flag → etcd delete visible]
	// window, while the etcd deletes are grouped into Txns. A node can carry
	// thousands of sandfs — one Raft write per key would mean thousands of
	// round-trips; batches of ownershipDeleteBatchSize cut that proportionally.
	// The batches run under releaseBatchSem (8 in flight) instead of all at
	// once: an extreme-affinity node (tens of thousands of placed sandfs =
	// hundreds of batches) must not burst etcd with concurrent delete Txns.
	// The watch's DELETE event forgets each flagged entry as its delete lands;
	// failures fall back to per-key deletes, and any leftover keys are still
	// covered by the lazy Claim path (see docs/how-it-works/resilience.md) on the
	// next request — past ownerReleaseClaimWindow the tombstone stops refusing
	// claims, so a permanently failed delete cannot wedge the sandfs.
	const ownershipDeleteBatchSize = 128
	oc.logger.Info("owner-release: releasing ownership for sandfs on disconnected node",
		"nodeID", nodeID, "sandfsCount", len(sandfsIDs))
	// Skip entries with a cold mount IN FLIGHT: deleting their
	// record inside the [Claim → NoteMounted] window leaves the fresh mount
	// uncovered (the watch-DELETE compensation gates on mounted, which is
	// still false). The next sweep tick re-evaluates — by then the mount has
	// landed (mounted=true → the normal release path and its compensation
	// apply) or EndDispatch ran.
	oc.mu.Lock()
	releasable := make([]string, 0, len(sandfsIDs))
	for _, id := range sandfsIDs {
		if e, ok := oc.cache[id]; ok && e.dispatching {
			continue
		}
		releasable = append(releasable, id)
	}
	oc.mu.Unlock()

	for i := 0; i < len(releasable); i += ownershipDeleteBatchSize {
		end := i + ownershipDeleteBatchSize
		if end > len(releasable) {
			end = len(releasable)
		}
		batch := releasable[i:end]
		oc.mu.Lock()
		for _, id := range batch {
			if entry, ok := oc.cache[id]; ok {
				entry.ownerReleasing = true
				entry.releasingSince = time.Now()
			}
		}
		oc.mu.Unlock()
		if oc.client != nil {
			go func(ids []string) {
				oc.releaseBatchSem <- struct{}{}
				defer func() { <-oc.releaseBatchSem }()
				oc.deleteOwnershipBatch(ids)
			}(batch)
		}
	}
}

// releaseBatchConcurrency caps concurrent owner-release delete Txns (see
// OwnershipCache.releaseBatchSem).
const releaseBatchConcurrency = 8

// deleteOwnershipBatch deletes a group of ownership keys in Txn batches,
// bound to the ModRevision each key had when the release snapshot was taken.
// A delete that lands AFTER a re-claim re-created the record must lose its CAS
// and leave the new record alone (the previous plain delete silently removed
// the fresh claim's record). On batch CAS loss or transport failure it retries
// each key individually; a key whose CAS is lost is logged and left for the
// lazy Claim path (never deleted).
func (oc *OwnershipCache) deleteOwnershipBatch(ids []string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Snapshot the CAS baseline per key, and refresh the release tombstone:
	// the delete is queued now, so the claim-refusal window must cover the
	// queue+retry delay (otherwise a claim could re-create the record inside
	// the window while this batch is still in flight).
	deletes := make([]ownershipDelete, 0, len(ids))
	oc.mu.Lock()
	for _, id := range ids {
		var rev int64
		if e, ok := oc.cache[id]; ok {
			rev = e.modRev
			if e.ownerReleasing {
				e.releasingSince = time.Now()
			}
		}
		deletes = append(deletes, ownershipDelete{id: id, modRev: rev})
	}
	oc.mu.Unlock()

	oc.executeOwnershipDeletes(ctx, deletes)
}

// ownershipDelete is one owner-release delete bound to the ModRevision the
// record had when the release snapshot was taken.
type ownershipDelete struct {
	id     string
	modRev int64
}

// executeOwnershipDeletes applies the CAS-bounded deletes: one batched Txn
// (all comparisons must pass) with a per-key CAS fallback. A lost CAS is never
// retried as a blind delete.
func (oc *OwnershipCache) executeOwnershipDeletes(ctx context.Context, deletes []ownershipDelete) {
	cmps := make([]clientv3.Cmp, 0, len(deletes))
	ops := make([]clientv3.Op, 0, len(deletes))
	for _, d := range deletes {
		if d.modRev == 0 {
			continue // no baseline (never observed); handled by the per-key path
		}
		key := ownershipPrefix + d.id
		cmps = append(cmps, clientv3.Compare(clientv3.ModRevision(key), "=", d.modRev))
		ops = append(ops, clientv3.OpDelete(key))
	}
	if len(cmps) > 0 {
		resp, err := oc.client.Txn(ctx).If(cmps...).Then(ops...).Commit()
		if err == nil && resp.Succeeded {
			return
		}
		if err != nil {
			oc.logger.Warn("owner-release: batched CAS delete failed; falling back to per-key CAS",
				"count", len(deletes), "error", err)
		} else {
			oc.logger.Info("owner-release: a record changed under the batched delete; falling back to per-key CAS",
				"count", len(deletes))
		}
	}

	for _, d := range deletes {
		dctx, dcancel := context.WithTimeout(context.Background(), 5*time.Second)
		key := ownershipPrefix + d.id
		if d.modRev == 0 {
			// No observed baseline: this key was never in the release snapshot
			// with a revision. Leave it to the lazy Claim path rather than
			// deleting a record we cannot prove is still the released one.
			oc.logger.Warn("owner-release: skipping delete without a ModRevision baseline", "sandfsID", d.id)
			dcancel()
			continue
		}
		resp, err := oc.client.Txn(dctx).
			If(clientv3.Compare(clientv3.ModRevision(key), "=", d.modRev)).
			Then(clientv3.OpDelete(key)).
			Commit()
		if err != nil {
			oc.logger.Warn("delete ownership (owner-release): etcd delete failed", "sandfsID", d.id, "error", err)
		} else if !resp.Succeeded {
			oc.logger.Warn("owner-release: ownership record changed under the delete CAS; leaving the new record intact",
				"sandfsID", d.id)
		}
		dcancel()
	}
}

// OwnershipDeleteForTest is one CAS-bounded owner-release delete.
type OwnershipDeleteForTest struct {
	ID     string
	ModRev int64
}

// OwnershipKeyForTest exposes the ownership key layout to tagged e2e tests.
func OwnershipKeyForTest(sandfsID string) string { return OwnershipKey(sandfsID) }

// DeleteOwnershipKeysCASForTest runs the production CAS-delete path with
// caller-supplied baselines (the delayed-delete scenarios the e2e drives).
func (oc *OwnershipCache) DeleteOwnershipKeysCASForTest(deletes []OwnershipDeleteForTest) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ds := make([]ownershipDelete, 0, len(deletes))
	for _, d := range deletes {
		ds = append(ds, ownershipDelete{id: d.ID, modRev: d.ModRev})
	}
	oc.executeOwnershipDeletes(ctx, ds)
}

// SetSafeMarginSecForTest overrides the T_safe derivation margin so tests can
// use a short presence TTL without waiting the production 60s margin. Restore to
// 60 after the test.
func SetSafeMarginSecForTest(sec int) {
	safeMarginSec = sec
}

// SetOwnerReleaseSweepIntervalForTest overrides the owner-release sweep tick so tests can observe a
// release without waiting the production 30s interval. Restore to 30s after.
func SetOwnerReleaseSweepIntervalForTest(d time.Duration) {
	atomic.StoreInt64(&ownerReleaseSweepIntervalNS, int64(d))
}

// SetWatchKeepaliveIntervalForTest overrides the ownership watch's keepalive
// (idle resubscribe) interval so tests can drive a resubscription without
// waiting the production 30s. Returns the previous value for restoration.
// Must be called BEFORE StartWatch (the watch loop reads the var per
// subscription; the timer uses the value at arm time).
func SetWatchKeepaliveIntervalForTest(d time.Duration) time.Duration {
	prev := atomic.LoadInt64(&watchKeepaliveIntervalNS)
	atomic.StoreInt64(&watchKeepaliveIntervalNS, int64(d))
	return time.Duration(prev)
}

// OnNodeConnect handles a sandlot connect: validates its timings, cancels any
// pending owner-release, and grants + writes its presence key (TTL = T_safe).
// Called from the stream OnConnect callback. Returns an error ONLY if the
// node's timings violate the model invariants — the caller then closes the
// connection and drops the node from the pool.
//
// A presence write failure is TOLERATED, not rejected: rejecting would couple
// an etcd outage to gateway capacity (every reconnecting node dropped while
// already-connected nodes ride the same outage out on best-effort heartbeat
// regrants), and an outage outlasting T_tolerance would escalate into the
// sandlot entering CLEANING and unmounting every mounted sandbox. Instead the
// node is admitted and flagged presencePending: its key is re-granted on every
// heartbeat and the moment etcd recovers, and the lazy owner-release path
// tolerates a pending node's absent key (in-memory truth — the node IS
// connected to us). The original hazard (a gateway restart reading the absent
// key as "node gone >= T_safe" and double-mounting) is closed because a
// restart breaks the stream, forcing a fresh OnNodeConnect whose regrant
// attempt runs before the node is admitted into serving.
// SetMaxExecTimeout records the gateway's configured sync-exec cap so every
// node connect can be checked against its own reported T_safe.
func (oc *OwnershipCache) SetMaxExecTimeout(d time.Duration) {
	oc.mu.Lock()
	oc.maxExecTimeout = d
	oc.mu.Unlock()
}

func (oc *OwnershipCache) OnNodeConnect(nodeID string, timing *pb.NodeTiming) error {
	if err := validateTiming(timing); err != nil {
		oc.logger.Warn("rejecting node: timing violates model invariants",
			"nodeID", nodeID, "error", err)
		return err
	}
	tSafe := tSafeForTiming(timing)

	// Per-node exec headroom: the gateway's maximum sync exec must finish
	// (plus the health tick and one heartbeat) before this node's T_safe.
	oc.mu.Lock()
	maxExec := oc.maxExecTimeout
	oc.mu.Unlock()
	if maxExec > 0 {
		if err := ValidateExecTiming(maxExec, tSafe); err != nil {
			oc.logger.Warn("rejecting node: exec headroom exceeds its T_safe",
				"nodeID", nodeID, "maxExec", maxExec, "tSafe", tSafe, "error", err)
			return err
		}
	}

	// Time-order invariant for the self-fence + time-guarded takeover chain.
	// A peer that sees this node's presence key ABSENT concludes "every mount
	// on it is released". The worst case for that conclusion is an
	// etcd-partitioned (not dead) owner, so the two clocks must not cross:
	//
	//   presence expires at:  partition − heartbeatInterval + T_safe
	//                         (worst case: the last keep-alive landed a full
	//                          heartbeat period before the partition began)
	//   fence release ends:   partition + detect(≤1 health tick) + fence + T_clean
	//                         (the fence unmounts actively over the still-connected
	//                          streams; T_clean ≤ T_warden is enforced separately)
	//
	// Requiring T_safe > fence + T_warden + heartbeatInterval covers it with the
	// health tick to spare. Reject the node rather than serve on a broken safety
	// chain; deployments should keep -etcd-fence-sec uniform across gateways.
	oc.mu.Lock()
	fence := oc.fenceThreshold
	oc.mu.Unlock()
	if fence > 0 {
		floor := fence + time.Duration(timing.GetWardenCountdownSec())*time.Second + nodeHeartbeatInterval
		if tSafe <= floor {
			oc.logger.Warn("rejecting node: T_safe does not exceed fence + warden countdown + heartbeat interval; presence expiry would not imply mount release",
				"nodeID", nodeID, "tSafe", tSafe, "floor", floor, "fenceSec", int(fence.Seconds()),
				"wardenSec", timing.GetWardenCountdownSec(), "heartbeat", nodeHeartbeatInterval)
			return fmt.Errorf("time-order invariant violated: T_safe (%v) must exceed etcd-fence threshold (%v) + warden countdown (%ds) + heartbeat interval (%v)",
				tSafe, fence, timing.GetWardenCountdownSec(), nodeHeartbeatInterval)
		}
	}

	oc.mu.Lock()
	delete(oc.pendingOwnerRelease, nodeID) // reconnect cancels any pending owner-release
	oc.presenceTTLs[nodeID] = tSafe
	// Record the reported warden countdown so a later UpdateFenceThreshold can
	// re-validate this node against the new fence (same formula as above).
	if w := timing.GetWardenCountdownSec(); w > 0 {
		oc.presenceWardenSecs[nodeID] = int(w)
	} else {
		oc.presenceWardenSecs[nodeID] = defaultTimingWardenSec
	}
	// Drop any stale lease entry from a previous connect so a failed regrant
	// below leaves the node visibly unanchored (presenceLeases absent).
	delete(oc.presenceLeases, nodeID)
	delete(oc.presencePending, nodeID)
	oc.mu.Unlock()

	if oc.client == nil {
		return nil // local/test mode
	}

	// Grant + write the presence key. On failure, admit the node with
	// presencePending set (see doc) — the key is re-established asynchronously.
	if err := oc.regrantPresence(nodeID, tSafe); err != nil {
		oc.mu.Lock()
		oc.presencePending[nodeID] = true
		oc.mu.Unlock()
		oc.logger.Warn("presence write failed at connect; admitting node with presence pending (regrant on heartbeat + etcd recovery)",
			"nodeID", nodeID, "error", err)
	}
	return nil
}

// tSafeForNode returns the recorded T_safe for a node (0 when unknown).
func (oc *OwnershipCache) tSafeForNode(nodeID string) time.Duration {
	oc.mu.Lock()
	defer oc.mu.Unlock()
	return oc.presenceTTLs[nodeID]
}

// OnNodeHeartbeat refreshes a connected node's presence key lease. Called from
// the stream OnHeartbeat callback (heartbeats continue while the stream is
// alive; when it breaks they stop, so the key naturally expires T_safe later —
// the exact owner-release anchor).
//
// The etcd RPC runs asynchronously: the callback executes on the stream's
// readLoop goroutine, which also delivers VMCommand responses for this node —
// a synchronous etcd call here would stall response delivery for up to its
// full timeout whenever etcd is slow. Heartbeat frequency is per-node/30s and
// the RPC is context-bounded (2s), so a short-lived goroutine per heartbeat
// stays at O(nodes) in flight.
//
// A missing tracked lease (in-memory state lost, or etcd revoked it while the
// stream stayed alive) triggers a re-grant — otherwise the key would be absent
// even though the node is connected, and the lazy owner-release path would
// release the node's sandfs prematurely.
func (oc *OwnershipCache) OnNodeHeartbeat(nodeID string) {
	oc.mu.Lock()
	leaseID, ok := oc.presenceLeases[nodeID]
	tSafe := oc.presenceTTLs[nodeID]
	oc.mu.Unlock()
	if oc.client == nil {
		return
	}
	if !ok {
		// Lease not tracked: re-establish the presence key so lazy owner-release
		// still sees the node as anchored.
		go oc.regrantPresence(nodeID, tSafe)
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if _, err := oc.client.KeepAliveOnce(ctx, leaseID); err != nil {
			oc.logger.Debug("presence: keep-alive failed; re-granting", "nodeID", nodeID, "error", err)
			oc.regrantPresence(nodeID, tSafe)
		}
	}()
}

// regrantPresence (re)establishes a node's presence key: Grant a lease with
// TTL = T_safe and Put the value, storing the new lease ID. Serialized by
// regrantMu so concurrent grants for the same node cannot interleave Grant/Put.
// Skipped (no-op success) when the node is no longer connected — a heartbeat
// that raced a disconnect must not resurrect a dead node's presence key and
// stall its owner-release by a full T_safe. Returns an error on failure.
// Called on connect (failure ⇒ the node is admitted with presencePending —
// see OnNodeConnect) and on heartbeat when the tracked lease is missing or
// its keep-alive failed (error ignored there — best-effort self-healing).
func (oc *OwnershipCache) regrantPresence(nodeID string, tSafe time.Duration) error {
	if oc.client == nil {
		return nil
	}
	if !oc.NodeConnected(nodeID) {
		// Node already disconnected (heartbeat goroutine raced OnNodeDisconnect):
		// writing the key would anchor a node nobody keeps alive.
		return nil
	}
	if tSafe <= 0 {
		// Defensive: no timing recorded — fall back to the default T_safe shape.
		tSafe = time.Duration(defaultTimingToleranceSec+defaultTimingWardenSec+safeMarginSec) * time.Second
	}
	oc.regrantMu.Lock()
	defer oc.regrantMu.Unlock()

	// Re-check connectedness under the lock: a disconnect may have landed while
	// we queued behind an earlier regrant for this node.
	if !oc.NodeConnected(nodeID) {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := oc.client.Grant(ctx, int64(tSafe.Seconds()))
	if err != nil {
		oc.logger.Warn("presence: grant lease failed", "nodeID", nodeID, "error", err)
		return err
	}
	if _, err := oc.client.Put(ctx, presenceKey(nodeID), oc.gatewayID, clientv3.WithLease(resp.ID)); err != nil {
		oc.logger.Warn("presence: put failed", "nodeID", nodeID, "error", err)
		return err
	}
	oc.mu.Lock()
	oc.presenceLeases[nodeID] = resp.ID
	delete(oc.presencePending, nodeID)
	oc.mu.Unlock()
	return nil
}

// OnNodeDisconnect records a node disconnect in the owner-release pending set (trigger (0))
// and stops tracking its presence lease. The presence key is NOT revoked — it
// naturally expires T_safe after the last heartbeat, which is exactly the anchor
// the owner-release sweep and the lazy path wait for. Called from the stream OnDisconnect
// callback.
func (oc *OwnershipCache) OnNodeDisconnect(nodeID string) {
	oc.mu.Lock()
	oc.pendingOwnerRelease[nodeID] = time.Now()
	delete(oc.presenceLeases, nodeID)
	delete(oc.presencePending, nodeID)
	delete(oc.presenceWardenSecs, nodeID)
	// Mount state on a disconnected node is no longer servable and its fate is
	// no longer observable locally: everything that WAS mounted there becomes
	// orphan-uncertain (a stale mount may survive until the node's own release
	// paths run). Placed-but-unmounted entries are left servable — no mount of
	// ours was live, so there is no orphan to be uncertain about.
	// Located via the nodeSandfs reverse index (O(per-node)) instead of a full
	// cache scan — see NoteNodeReconnected for the lock-contention rationale.
	for sandfsID := range oc.nodeSandfs[nodeID] {
		if entry, ok := oc.cache[sandfsID]; ok {
			// A dispatch that was in flight may land on the disconnected node
			// after this sweep; it is an orphan candidate too.
			if entry.mounted || entry.dispatching {
				entry.suspect = true
			}
			entry.mounted = false
		}
	}
	oc.mu.Unlock()
}

// NodeConnected checks whether a sandlot node is currently connected to this gateway.
// Exposed for use by Claim's node_id check.
func (oc *OwnershipCache) NodeConnected(nodeID string) bool {
	if oc.streamSrv == nil {
		return true // No stream server = assume connected (single-node mode)
	}
	_, err := oc.streamSrv.GetNode(nodeID)
	return err == nil
}

// Client returns the underlying etcd client (nil in single-node/local mode).
func (oc *OwnershipCache) Client() *clientv3.Client {
	if oc == nil {
		return nil
	}
	return oc.client
}

// GatewayID returns this cache's fixed gateway identity.
func (oc *OwnershipCache) GatewayID() string {
	if oc == nil {
		return ""
	}
	return oc.gatewayID
}

// OwnerGatewayURL returns the base URL of the gateway currently owning a sandfs,
// or "" when no redirect should happen. Resolves ownership → gateway_id, then
// the gateway registry key (/sandswap/gateway/{gw}) for the address. Used by the
// 307 redirect: on ErrOwnershipConflict, the handler redirects to the owner (if
// it has a routable gateway_url) instead of 503+retry.
//
// Staleness gate: if the owner's health record is stale past the route-stale
// threshold (or absent — lease expired), NO redirect is returned. Bouncing a
// request to a dead/stale owner would just fail at the owner and waste a hop;
// instead the caller falls through to 503+retry, and the client re-resolves via
// DNS (which also applies the staleness gate and routes to a live gateway). This
// is a cold path (only ErrOwnershipConflict reaches here), so the extra health
// GET is not on the hot path.
func (oc *OwnershipCache) OwnerGatewayURL(ctx context.Context, sandfsID string) string {
	if oc == nil || oc.client == nil {
		return ""
	}
	gwID, err := LookupOwnerGatewayID(ctx, oc.client, sandfsID)
	if err != nil {
		if oc.logger != nil {
			oc.logger.Debug("owner lookup failed (no redirect)",
				"sandfsID", sandfsID, "error", err)
		}
		return ""
	}
	// The caller is the owner — no redirect to self.
	if gwID == oc.gatewayID {
		return ""
	}
	stale, present := oc.ownerStaleness(ctx, gwID)
	oc.mu.Lock()
	threshold := oc.routeStaleThreshold
	oc.mu.Unlock()
	if !present || stale > threshold {
		if oc.logger != nil {
			oc.logger.Info("owner stale/dead; skipping 307 redirect (fall back to 503+retry)",
				"sandfsID", sandfsID, "owner", gwID,
				"stale_sec", int(stale.Seconds()), "health_key_present", present)
		}
		return ""
	}
	return oc.lookupGatewayURL(ctx, gwID)
}

// LookupOwnerGatewayID resolves the gateway_id of the gateway that owns a
// sandfs. Used by the 307 redirect.
//
// Reads the gateway_id straight from the ownership key (/sandswap/owner/
// {sandfs_id} → {gateway_id, node_id, generation}), with NO health-key
// round-trip. The routing address is then read from the gateway registry key
// (/sandswap/gateway/{gw}) — a plain key that survives the owner's death, so
// the redirect works even while the owner is in tolerance: its health key may
// have expired or show node_count==0, but ownership is unchanged, so only the
// owner can serve and the request should go there regardless.
// Returns an error when there is no owner or the ownership record is corrupt.
// ErrNoOwner reports that the ownership key is ABSENT — the one condition that
// proves no gateway can hold the sandfs. Transport/corruption errors are NOT
// this sentinel: callers that use "no owner" to settle a lifecycle transition
// must treat those as "unknown, keep waiting".
var ErrNoOwner = errors.New("no ownership record")

func LookupOwnerGatewayID(ctx context.Context, client *clientv3.Client, sandfsID string) (gatewayID string, err error) {
	if client == nil {
		return "", fmt.Errorf("no etcd client")
	}

	resp, err := client.Get(ctx, ownershipPrefix+sandfsID)
	if err != nil {
		return "", fmt.Errorf("etcd get ownership: %w", err)
	}
	if len(resp.Kvs) == 0 {
		return "", fmt.Errorf("%w for sandfs %s", ErrNoOwner, sandfsID)
	}
	var ov OwnershipValue
	if err := json.Unmarshal(resp.Kvs[0].Value, &ov); err != nil {
		return "", fmt.Errorf("corrupt ownership value: %w", err)
	}
	if ov.GatewayID == "" {
		return "", fmt.Errorf("owner has empty gateway id")
	}
	return ov.GatewayID, nil
}

// OwnershipKey returns the etcd key that holds sandfsID's ownership record.
// Exported for the delete teardown's "wait until the owner released" poll — the
// human gateway in a split deployment is not the owner and cannot delete the
// record itself (the release CAS refuses foreign owners).
func OwnershipKey(sandfsID string) string { return ownershipPrefix + sandfsID }

// ReleaseOwnershipIfOwner deletes sandfsID's ownership record iff it still
// names gatewayID. The drain-settle path runs in the OWNER process, which may
// hold no OwnershipCache entry for the sandfs (a cold mount never completed) —
// this is the cache-independent form of the same rule releaseOwnershipCAS
// enforces: a peer's record is never deleted. Absent keys and foreign records
// are a no-op (nothing of this gateway's is left to release). Retries the
// revision CAS a few times on transport errors / concurrent writes.
func ReleaseOwnershipIfOwner(ctx context.Context, client *clientv3.Client, sandfsID, gatewayID string) error {
	if client == nil || gatewayID == "" {
		return nil
	}
	key := OwnershipKey(sandfsID)
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			timer := time.NewTimer(time.Second)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}
		callCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		resp, err := client.Get(callCtx, key)
		if err != nil {
			cancel()
			lastErr = fmt.Errorf("etcd get ownership: %w", err)
			continue
		}
		if len(resp.Kvs) == 0 {
			cancel()
			return nil
		}
		kv := resp.Kvs[0]
		var val OwnershipValue
		if uerr := json.Unmarshal(kv.Value, &val); uerr == nil && val.GatewayID != gatewayID {
			cancel()
			return nil // a peer owns it now — never delete their record
		}
		tresp, terr := client.Txn(callCtx).
			If(clientv3.Compare(clientv3.ModRevision(key), "=", kv.ModRevision)).
			Then(clientv3.OpDelete(key)).
			Commit()
		cancel()
		if terr != nil {
			lastErr = fmt.Errorf("etcd release CAS: %w", terr)
			continue
		}
		if tresp.Succeeded {
			return nil
		}
		lastErr = fmt.Errorf("ownership record for %s changed under the release CAS", sandfsID)
	}
	return lastErr
}

// lookupGatewayURL reads a gateway's routing address from its registry key
// (/sandswap/gateway/{gw}). Returns "" when the key is absent, corrupt, or the
// gateway registered no address (alive but unroutable).
func (oc *OwnershipCache) lookupGatewayURL(ctx context.Context, gwID string) string {
	if oc.client == nil {
		return ""
	}
	resp, err := oc.client.Get(ctx, gatewayPrefix+gwID)
	if err != nil || len(resp.Kvs) == 0 {
		return ""
	}
	var rv GatewayRegistryValue
	if json.Unmarshal(resp.Kvs[0].Value, &rv) != nil {
		return ""
	}
	return rv.GatewayURL
}

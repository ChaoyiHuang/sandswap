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
// Package handler implements HTTP handlers for the Gateway API.

package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"sync/atomic"
	"time"

	"gateway/identity"
	"gateway/lease"
	"gateway/pool"
	"gateway/stream"
)

// DefaultMaxBackgroundLeaseSec is the default upper bound on an agent-supplied
// lease_duration for background execs. Background execs are fire-and-forget on
// the warden (no warden-side timeout — only sync execs are bounded by
// max_exec_timeout), and status polls do NOT extend the lease, so lease_duration
// is the bg exec's absolute run-time cap: when it elapses the VM is unmounted
// (cgroup.kill clears the bg exec along with all guest processes). The default
// (1h) is a conservative floor; deployments with long-running async tasks
// (model training, long builds) raise it via -max-background-lease-sec. Requests
// above the configured cap are rejected with 400.
const DefaultMaxBackgroundLeaseSec = 60 * 60

// MaxExecuteRequestBodyBytes bounds the /agent/execute HTTP body (the code
// payload is JSON-wrapped, so it is intentionally smaller than /agent/file).
const MaxExecuteRequestBodyBytes = 10 << 20

// MaxBackgroundLeaseSecCap is the representable ceiling for the bg lease cap:
// the request path converts the cap to milliseconds in a uint32, so a cap above
// this many seconds would silently wrap. cmd/main.go rejects startup configs
// past it; UpdateMaxBackgroundLeaseSec ignores hot-reload values past it.
const MaxBackgroundLeaseSecCap = int(^uint32(0) / 1000) // 4,294,967s ≈ 49.7 days

// opDebug gates the per-request success log ("execute complete"). A gateway at
// scale serves thousands of executions per second: the info record costs a
// JSON marshal + stderr write per request AND runs between response encode and
// handler return (i.e. on the client-observed path). Normal completions print
// nothing by default; the gate is checked BEFORE formatting. Enabled by
// `gateway -log-level debug` (wired via SetDebugLogging). Errors/warnings and
// resilience 503s are unaffected — those are the abnormal signals.
var opDebug atomic.Bool

// SetDebugLogging flips the per-request success-log gate. Called once at
// startup from cmd/main.go (log-level debug enables it).
func SetDebugLogging(on bool) { opDebug.Store(on) }

// ExecuteRequest is the request body for POST /agent/execute.
type ExecuteRequest struct {
	SandfsID      string `json:"sandfs_id"` // SandFS instance (required — no implicit default)
	Code          string `json:"code"`
	Language      string `json:"language"`                 // "python", "shell", "node", etc.
	Timeout       int    `json:"timeout,omitempty"`        // seconds; sync command timeout (0 = gateway default)
	Background    bool   `json:"background,omitempty"`     // true = start as background exec, return exec_id
	LeaseDuration int    `json:"lease_duration,omitempty"` // seconds; background exec VM hold (0 = the configured -max-background-lease-sec cap)
}

// ExecuteResponse is the response body for POST /agent/execute.
type ExecuteResponse struct {
	Stdout            string `json:"stdout,omitempty"`
	Stderr            string `json:"stderr,omitempty"`
	ExitCode          int    `json:"exit_code"`
	Error             string `json:"error,omitempty"`
	ExecID            string `json:"exec_id,omitempty"`             // background only
	Status            string `json:"status,omitempty"`              // "done"|"running"|"timed_out"|"killed"|"not_found"|"expired"
	ExecDurationNs    uint64 `json:"exec_duration_ns,omitempty"`    // warden: full exec() call (warm) / warden total incl. mount (cold)
	SandlotDurationNs uint64 `json:"sandlot_duration_ns,omitempty"` // sandlot: dispatch-to-response (ns)
	GatewayDurationNs uint64 `json:"gateway_duration_ns,omitempty"` // gateway: E2E wall time (ns)
}

// ExecuteHandler handles POST /agent/execute — the main sandfs execution endpoint.
type ExecuteHandler struct {
	identityStore identity.Store
	pool          *pool.Manager
	leaseMgr      *lease.Lease
	sandlotClient pool.SandlotClient
	mountLock     *lease.MountLock      // cold mount mutex (nil = disabled)
	ownership     *lease.OwnershipCache // etcd ownership (nil = single-node mode)
	sandfsState   *lease.SandfsState    // AVAILABLE/CLEANING state machine
	shed          *lease.ShedController // voluntary load shed (nil = disabled)
	unmountStats  pool.UnmountRecorder  // per-node unmount stats (nil = disabled)
	logger        *slog.Logger
	// Edge exec-timeout policy (defense in depth; the warden retains its own
	// max_exec_timeout as an independent safety floor). defaultTimeoutMs is the
	// value used when the sandfs omits timeout; maxTimeoutMs clamps agent values.
	// Atomic for hot-reload: UpdateTimeouts() swaps without restarting.
	defaultTimeoutMs atomic.Uint32
	maxTimeoutMs     atomic.Uint32
	// maxBackgroundLeaseSec caps the bg exec lease_duration (absolute run-time
	// cap). Atomic for hot-reload: UpdateMaxBackgroundLeaseSec() swaps without
	// restarting. <=0 at construction falls back to DefaultMaxBackgroundLeaseSec.
	maxBackgroundLeaseSec atomic.Int64
}

// NewExecuteHandler creates a new ExecuteHandler.
func NewExecuteHandler(store identity.Store, pm *pool.Manager, lm *lease.Lease, sc pool.SandlotClient, ml *lease.MountLock, oc *lease.OwnershipCache, ss *lease.SandfsState, defaultTimeoutSec, maxTimeoutSec, maxBgLeaseSec int, logger *slog.Logger) *ExecuteHandler {
	if defaultTimeoutSec <= 0 {
		defaultTimeoutSec = 30
	}
	if maxTimeoutSec <= 0 || maxTimeoutSec < defaultTimeoutSec {
		maxTimeoutSec = defaultTimeoutSec
	}
	if maxBgLeaseSec <= 0 {
		maxBgLeaseSec = DefaultMaxBackgroundLeaseSec
	}
	h := &ExecuteHandler{
		identityStore: store,
		pool:          pm,
		leaseMgr:      lm,
		sandlotClient: sc,
		mountLock:     ml,
		ownership:     oc,
		sandfsState:   ss,
		logger:        logger,
	}
	// Publish the cold-mount lock to the process: the lifecycle drain (which
	// receives only the pool and lease) consults it so it can never settle a
	// sandfs while a cold mount is in flight or queued.
	lease.RegisterDispatchLock(ml)
	h.defaultTimeoutMs.Store(uint32(defaultTimeoutSec) * 1000)
	h.maxTimeoutMs.Store(uint32(maxTimeoutSec) * 1000)
	h.maxBackgroundLeaseSec.Store(int64(maxBgLeaseSec))
	return h
}

// UpdateTimeouts atomically updates the exec timeout values for hot-reload.
// A max timeout that breaks the resilience timing headroom (health tick + max
// exec + heartbeat < T_safe) is REFUSED — the previous value stays, so a
// maximum-length exec can never outlive the presence key that anchors "all
// mounts released".
func (h *ExecuteHandler) UpdateTimeouts(defaultSec, maxSec int) {
	if defaultSec > 0 {
		h.defaultTimeoutMs.Store(uint32(defaultSec) * 1000)
	}
	if maxSec > 0 && maxSec >= defaultSec {
		if err := lease.ValidateExecTiming(time.Duration(maxSec)*time.Second, lease.DefaultTSafe()); err != nil {
			h.logger.Error("exec max timeout hot-reload refused; keeping previous value", "error", err)
			return
		}
		h.maxTimeoutMs.Store(uint32(maxSec) * 1000)
	}
}

// UpdateMaxBackgroundLeaseSec atomically updates the bg lease_duration cap for
// hot-reload. sec <= 0 falls back to DefaultMaxBackgroundLeaseSec; values above
// MaxBackgroundLeaseSecCap are ignored (not representable as uint32 ms — the
// startup validation rejects them there; here keeping the current cap is the
// safe non-disruptive choice).
func (h *ExecuteHandler) UpdateMaxBackgroundLeaseSec(sec int) {
	if sec <= 0 {
		sec = DefaultMaxBackgroundLeaseSec
	}
	if sec > MaxBackgroundLeaseSecCap {
		// Named refusal: the reload log already claimed the field was applied,
		// so silence here reads as success while the cap stays old.
		h.logger.Warn("bg lease cap change IGNORED (above the hard cap)",
			"requested_sec", sec, "cap_sec", MaxBackgroundLeaseSecCap)
		return
	}
	h.maxBackgroundLeaseSec.Store(int64(sec))
}

// SetShedController attaches the load-shed controller. nil (or not
// called) = shedding disabled (default). Wired after construction in cmd/main.go.
func (h *ExecuteHandler) SetShedController(sc *lease.ShedController) {
	h.shed = sc
}

// SetUnmountRecorder wires the per-node unmount stats recorder. nil (or not
// called) = recording disabled. Wired after construction in cmd/main.go.
func (h *ExecuteHandler) SetUnmountRecorder(r pool.UnmountRecorder) {
	h.unmountStats = r
}

// shedColdPath asks the load-shed controller to rebalance a cold-path sandfs
// and returns its action. It CLEARS the in-flight dispatch marker first:
// ShedOwnership deliberately refuses a dispatching entry (a mount may be live),
// so shedding with the flag still set was a guaranteed no-op that nevertheless
// answered ShedActionShed — the client re-resolved DNS straight back to this
// gateway while ownership was never released. Every caller runs after a FAILED
// cold attempt (no node acquired, no VM available, transport error before
// acceptance), so no mount can land and the marker is stale.
func shedColdPath(shed *lease.ShedController, oc *lease.OwnershipCache, sandfsID string) lease.ShedAction {
	if shed == nil {
		return lease.ShedActionNone
	}
	if oc != nil {
		oc.EndDispatch(sandfsID)
	}
	return shed.MaybeShed(sandfsID)
}

// recheckLifecycleGate re-reads the record AFTER the cold-mount lock is
// acquired. The request passed the lifecycle gate before it queued on the
// MountLock (up to 10s), and the drain that flips a sandfs to
// detaching/detached/deleting does not take that lock — so the status must be
// re-validated under it, or a request that waited out a detach/delete mounts a
// volume whose record is already settled.
//
// The NORMAL (active) path must never touch etcd: read the local watch
// snapshot first. A lifecycle transition makes the status non-empty, so only a
// non-active snapshot needs the linearizable re-read below (an attach can have
// completed while the request waited, and the snapshot may still show the old
// transition). A transition that lands after this check is handled by the
// record watcher's drain, the same backstop that unmounts any mount raced by a
// detach/delete. Warm requests never call this at all.
func recheckLifecycleGate(store identity.Store, id *ResolvedIdentity) error {
	// Local snapshot: a watch-cache lookup (a hit on the normal path — the
	// request's auth resolve above already loaded this record).
	rec, err := store.GetSandFS(id.SandfsID)
	if err != nil || rec == nil {
		return &resilienceError{
			code:         http.StatusConflict,
			msg:          "sandfs no longer exists (deleted during the mount wait)",
			errorCode:    "SANDFS_NOT_ACTIVE",
			retryAfterMs: 1000,
		}
	}
	if rec.Status != "" {
		// The snapshot says detaching/detached/deleting. It may be a lagging
		// view of a completed attach, so ask the source of truth. This is the
		// ONLY etcd read of this gate, and it happens only in a lifecycle
		// transition state.
		if fr, ok := store.(identity.FreshReader); ok {
			fresh, ferr := fr.GetSandFSFresh(id.SandfsID)
			if ferr != nil || fresh == nil {
				return &resilienceError{
					code:         http.StatusConflict,
					msg:          "sandfs no longer exists (deleted during the mount wait)",
					errorCode:    "SANDFS_NOT_ACTIVE",
					retryAfterMs: 1000,
				}
			}
			rec = fresh
		}
		if rec.Status != "" {
			return errNotActive(rec.Status)
		}
	}
	// Refresh the snapshot the rest of the cold path uses (the attach may have
	// landed a new template while this request waited).
	id.Status = rec.Status
	id.Template = rec.Template
	id.MinVCPUs = rec.MinVCPUs
	id.MinMemoryMB = rec.MinMemoryMB
	return nil
}

// ResolveTimeoutMs applies the edge policy: 0 (agent omitted) → default; any
// value above max is clamped to max. Exported for MCP server use.
func (h *ExecuteHandler) ResolveTimeoutMs(sandfsSeconds int) uint32 {
	return h.resolveTimeoutMs(sandfsSeconds)
}

// MaxExecTimeoutSec returns the live sync-exec timeout cap (seconds) — the
// hot-reloadable atomic, so callers (e.g. the MCP server rendering the agent
// guide) always see the currently configured value.
func (h *ExecuteHandler) MaxExecTimeoutSec() int {
	return int(h.maxTimeoutMs.Load() / 1000)
}

// resolveTimeoutMs applies the edge policy: 0 (agent omitted) → default; any
// value above max is clamped to max. The warden re-clamps to its own
// max_exec_timeout as the final safety floor.
func (h *ExecuteHandler) resolveTimeoutMs(sandfsSeconds int) uint32 {
	if sandfsSeconds <= 0 {
		return h.defaultTimeoutMs.Load()
	}
	// Multiply in int64 BEFORE narrowing: an unbounded `timeout` seconds value
	// wraps in uint32 (4294968 * 1000 = 704 ms), which sails past the clamp
	// below and kills a "max-length" exec at 0.7 s — or becomes 0 (documented
	// as "warden default") and skips the clamp entirely.
	ms64 := int64(sandfsSeconds) * 1000
	if ms64 > int64(math.MaxUint32) {
		ms64 = int64(math.MaxUint32) // clamped to max below
	}
	ms := uint32(ms64)
	if ms > h.maxTimeoutMs.Load() {
		return h.maxTimeoutMs.Load()
	}
	return ms
}

// ExecuteDirectResult is the result of ExecuteDirect, returned by both the HTTP
// handler and MCP dispatch. It includes the execution result plus metadata
// needed by the HTTP handler (lease hit indicator) and MCP handler (identity).
type ExecuteDirectResult struct {
	Stdout            string
	Stderr            string
	ExitCode          int
	ExecID            string
	Status            string
	ExecDurationNs    uint64
	SandlotDurationNs uint64
	GatewayDurationNs uint64
	LeaseHit          bool
	Identity          *ResolvedIdentity
}

// ExecuteDirect is the direct-call entry point for the execute pipeline.
// It performs the full flow: auth → sandfsState → ownership → lease → acquire →
// mountLock → MountRootfsAndExecute → lease management. Exported for MCP server use.
func (h *ExecuteHandler) ExecuteDirect(ctx context.Context, apiKey string, req ExecuteRequest) (*ExecuteDirectResult, error) {
	start := time.Now()
	// 0. Wire-size gate( sweep, same class as the file-op gates):
	// the wrapped command is the single large field of the mount+exec gRPC
	// message, so an oversize one breaches the stream's message limit on the
	// Send — which CLOSES the node stream and kills every co-tenant in-flight
	// command on that sandlot. The HTTP transport's 10MB body cap keeps
	// requests far below the gate; the MCP transport's 50MB body cap does not,
	// so without this check a large `code` argument reaches the wire. Gated on
	// the WRAPPED command because shQuote inflates each embedded single quote
	// to 4 bytes — the code length alone under-counts the payload. Named
	// client-class refusal (4xx): HTTP renders the 413, MCP a structured tool
	// error (error_code EXEC_TOO_LARGE, retryable:false).
	if len(req.Code) > maxFileOpDataBytes {
		// Cheap lower bound first: the wrap is never shorter than the code, so
		// an oversize code is refused without allocating the wrapped copy.
		return nil, commandTooLargeErr(len(req.Code))
	}
	command := wrapCommand(req.Language, req.Code)
	if len(command) > maxFileOpDataBytes {
		return nil, commandTooLargeErr(len(command))
	}

	// 1. Validate request. lease_duration is the background exec's absolute
	// run-time cap: status polls do NOT extend it (a poll only marks the exec
	// done when it observes completion); when it elapses the VM is unmounted.
	// Reject values above the configured cap up front, before any
	// ownership/mountLock/node resources are acquired (a later reject would
	// leak the held mountLock).
	if req.Code == "" {
		return nil, &execHTTPError{code: http.StatusBadRequest, msg: "code is required"}
	}
	if req.Timeout < 0 {
		return nil, &execHTTPError{code: http.StatusBadRequest, msg: "timeout must be >= 0"}
	}
	if req.LeaseDuration < 0 {
		return nil, &execHTTPError{code: http.StatusBadRequest, msg: "lease_duration must be >= 0"}
	}
	if maxBg := int(h.maxBackgroundLeaseSec.Load()); req.LeaseDuration > maxBg {
		return nil, &execHTTPError{
			code: http.StatusBadRequest,
			msg:  fmt.Sprintf("lease_duration exceeds maximum of %ds", maxBg),
		}
	}

	// 2. sandfs_id is REQUIRED — explicit addressing keeps the request path
	// unambiguous (no per-agent listing on the hot path).
	if req.SandfsID == "" {
		return nil, &execHTTPError{code: http.StatusBadRequest, msg: "sandfs_id is required"}
	}

	// 3. Unified auth + addressing.
	identity, err := ResolveFromRequest(h.identityStore, apiKey, req.SandfsID)
	if err != nil {
		return nil, err
	}

	// 3.5 Lifecycle gate: a sandfs in a template-swap or deletion state refuses
	// new executions (retryable 409). One struct-field compare on the hot path;
	// the store is only consulted when the gate trips (see gateActive).
	if err := gateActive(h.identityStore, identity); err != nil {
		return nil, err
	}

	// 4. Resilience: check sandfsState (AVAILABLE/CLEANING)
	if h.sandfsState != nil && !h.sandfsState.IsAvailable(identity.SandfsID) {
		return nil, &resilienceError{
			code: http.StatusServiceUnavailable, msg: "sandfs is cleaning",
			errorCode: "SANDBOX_CLEANING", retryAfterMs: lease.DefaultRetryAfterMs,
		}
	}

	// 5. Resilience: ownership claim. The claim writes a CANDIDATE PLACEMENT
	// into the ownership record, so the record never says "unplaced" while a
	// mount could exist (PeekNode selects without reserving capacity; the real
	// Acquire below may still land elsewhere and NoteMounted then corrects it).
	// Errors are ignored: no eligible node yields an empty candidate, which is
	// exactly the honest value, and the 503 comes from Acquire below.
	placement := ""
	if h.ownership != nil {
		candidate, _, _ := h.pool.PeekNode("", identity.MinVCPUs, identity.MinMemoryMB)
		placement, err = h.ownership.Claim(identity.SandfsID, candidate)
		if err != nil {
			errorCode := "OWNERSHIP_CONFLICT"
			if err == lease.ErrOwnerNodeDown {
				errorCode = "OWNER_NODE_DOWN"
			}
			if err == lease.ErrOwnerNoCompute {
				errorCode = "OWNER_NO_COMPUTE"
			}
			// redirect: if a healthy, routable OTHER gateway owns this sandfs, 307 the
			// client there so its connection converges onto the owner (affinity
			// anchor). Only when owner-dead/absent/unroutable do we 503 + retry —
			// that retry then force-takes-over HERE, making this gateway the new
			// owner (soft affinity: a dead owner is replaced, not redirected to).
			if err == lease.ErrOwnershipConflict {
				if ownerURL := h.ownership.OwnerGatewayURL(ctx, identity.SandfsID); ownerURL != "" {
					return nil, &OwnerRedirectError{OwnerURL: ownerURL}
				}
			}
			return nil, &resilienceError{
				code: http.StatusServiceUnavailable, msg: err.Error(),
				errorCode: errorCode, retryAfterMs: lease.JitteredRetryAfterMs(lease.RetryAfterMs),
			}
		}
	}

	// 6. Check sticky lease — reuse the warm node if sandfs called recently
	node := ""
	leaseHit := false

	if n, werr := h.leaseMgr.AcquireWait(identity.SandfsID, lease.MountLockWaitTimeout); werr != nil {
		// An unmount is in progress and didn't finish within the wait
		// timeout. 503 + retry - do NOT fall through to a cold mount on another
		// node (would dual-mount while the unmount is still holding the mount).
		return nil, &resilienceError{
			code: http.StatusServiceUnavailable, msg: "unmount in progress, retry",
			errorCode: "UNMOUNT_IN_PROGRESS", retryAfterMs: 1000,
		}
	} else if n != "" {
		node = n
		leaseHit = true
	}

	// 7. Resilience: MountLock for cold mount mutual exclusion (blocking).
	// Acquired BEFORE node selection so a blocked waiter doesn't hold capacity
	// while waiting (up to MountLockWaitTimeout) for the in-progress cold mount
	// to finish. If the holder releases early, AcquireWait returns immediately
	// (the waiter proceeds without a 503 round-trip); only on timeout does it
	// 503 + retry_after. This bounds the sync-command budget the agent is told
	// to respect (keep sync commands < ~10s, use bg exec for longer).
	needsColdMount := !leaseHit
	mountLockHeld := false
	var mountToken *lease.MountLockToken
	if needsColdMount && h.mountLock != nil {
		tok, lockErr := h.mountLock.AcquireWaitDefault(identity.SandfsID)
		if lockErr != nil {
			return nil, &resilienceError{
				code: http.StatusServiceUnavailable, msg: "concurrent mount in progress",
				errorCode: "CONCURRENT_MOUNT", retryAfterMs: 1000,
			}
		}
		mountToken = tok
		mountLockHeld = true
		// ONE deferred release for every path out of this function. Early
		// returns below (lease re-check, BeginDispatch, node acquire, exec
		// errors, panics) must not strand the per-sandfs token — a leaked
		// token blocks every future cold mount for this sandfs until the
		// process restarts. Release is token-scoped: a double/stale release
		// cannot drain a successor's acquisition.
		defer func() {
			if mountLockHeld {
				h.mountLock.Release(mountToken)
			}
		}()
		// Re-check the lease: the holder may have finished and established the
		// lease while we waited. If so, take the warm path and release the lock
		// (no cold mount needed).
		if n, werr := h.leaseMgr.AcquireWait(identity.SandfsID, lease.MountLockWaitTimeout); werr != nil {
			// Unmount in progress - release the lock and 503+retry so
			// the retry blocks at the top AcquireWait until the unmount finishes.
			h.mountLock.Release(mountToken)
			mountLockHeld = false
			return nil, &resilienceError{
				code: http.StatusServiceUnavailable, msg: "unmount in progress, retry",
				errorCode: "UNMOUNT_IN_PROGRESS", retryAfterMs: 1000,
			}
		} else if n != "" {
			node = n
			leaseHit = true
			needsColdMount = false
			h.mountLock.Release(mountToken)
			mountLockHeld = false
		}
	}

	// 7.5 Coverage re-verification for the cold path: the
	// Claim at step 5 may have happened before a MountLock wait of up to
	// MountLockWaitTimeout, and nothing between here and NoteMounted consults
	// ownership. Mark the mount in flight — the sweep and the shed now skip
	// dispatching entries, and a vanished record fails HERE (retry re-claims)
	// instead of landing an uncovered mount. In-memory only: one lock + map
	// probe; no etcd traffic. Cleared by NoteMounted or the deferred
	// EndDispatch on every failure path below.
	dispatchGen := uint64(0)
	if needsColdMount && h.ownership != nil {
		gen, derr := h.ownership.BeginDispatch(identity.SandfsID)
		if derr != nil {
			return nil, &resilienceError{
				code:         http.StatusServiceUnavailable,
				msg:          "ownership changed during the mount wait, retry",
				errorCode:    "OWNERSHIP_LOST",
				retryAfterMs: lease.JitteredRetryAfterMs(1000),
			}
		}
		dispatchGen = gen
		defer h.ownership.EndDispatch(identity.SandfsID)
	}

	// 7.6 Lifecycle re-check UNDER the cold-mount lock: the gate at step 3.5 ran
	// before any MountLock wait, and the drain does not take that lock — a
	// detach/delete that flipped the record while this request queued must stop
	// the mount here (see recheckLifecycleGate).
	if needsColdMount {
		if err := recheckLifecycleGate(h.identityStore, identity); err != nil {
			return nil, err
		}
	}

	// 8. If no warm node, acquire a node with fitting clean capacity.
	// spec is the floor specID resolved from the sandfs's required vcpus/memory
	// against the chosen node's learned spec table; sent to sandlot as min_spec
	// (sandlot best-fits the actual clean VM). Empty on the warm path (VM already
	// bound; min_spec is ignored by sandlot).
	spec := ""
	if node == "" {
		var acqErr error
		node, spec, acqErr = h.pool.Acquire(placement, identity.MinVCPUs, identity.MinMemoryMB)
		if acqErr != nil {
			err = acqErr
			if mountLockHeld {
				h.mountLock.Release(mountToken)
				mountLockHeld = false
			}
			h.logger.Error("failed to acquire node", "sandfsID", identity.SandfsID, "error", err)
			// shed applies to cluster-wide saturation too (no node had
			// clean capacity): if an idle peer gateway exists, shed this sandfs's
			// ownership so the client re-resolves to the peer. Cold-path only.
			if shed := shedColdPath(h.shed, h.ownership, identity.SandfsID); shed != lease.ShedActionNone {
				h.logger.Info("load shed (acquire-fail): saturating sandfs rebalanced to a peer",
					"sandfsID", identity.SandfsID, "shed", shed == lease.ShedActionShed)
				retryMs := h.shed.RetryAfterSec() * 1000
				return nil, &resilienceError{
					code:          http.StatusServiceUnavailable,
					msg:           "gateway saturated, ownership released: reconnect (re-resolve DNS) to reach a peer",
					errorCode:     "SHED_REBALANCE",
					retryAfterMs:  retryMs,
					shedRebalance: true,
				}
			}
			if err.Error() == "no compute nodes connected" {
				// No sandlot connected at all — recovery is deployment-timed;
				// jitter the poll hint (resilience-clock class).
				return nil, &resilienceError{
					code: http.StatusServiceUnavailable, msg: err.Error(),
					errorCode:    "NO_COMPUTE_NODES",
					retryAfterMs: lease.JitteredRetryAfterMs(lease.RetryAfterMs),
				}
			}
			// Over-subscription: a clean VM frees in milliseconds (sticky
			// release / unmount), so retry fast. Matches the bg-start and
			// file-op NO_AVAILABLE_SANDBOX sites.
			return nil, &resilienceError{
				code: http.StatusServiceUnavailable, msg: err.Error(),
				errorCode: "NO_AVAILABLE_SANDBOX", retryAfterMs: 1000,
			}
		}
	}

	// 9. Combined attach+execute via a single gRPC round-trip.
	timeoutMs := h.resolveTimeoutMs(req.Timeout)
	leaseMs := uint32(0)
	if req.Background && req.LeaseDuration == 0 {
		// lease_duration is the bg exec's ABSOLUTE run-time cap and the docs
		// promise a 1h default cap (-max-background-lease-sec). An omitted
		// value must not fall through to the lease layer's far-future
		// placeholder (24h) — an agent spawning bg execs without a duration
		// and never polling would otherwise hold one VM each for a full day
		// (a pool-exhaustion vector). Read at request time so hot-reload of
		// the cap applies to in-flight traffic too.
		leaseMs = uint32(h.maxBackgroundLeaseSec.Load() * 1000)
	} else if req.LeaseDuration > 0 {
		// Validated at step 1 against maxBackgroundLeaseSec (default 1h), so
		// no overflow is possible here (any sane cap * 1000 fits easily in
		// uint32, max ~4.29B).
		leaseMs = uint32(req.LeaseDuration * 1000)
	}
	// `command` was wrapped (with the appropriate interpreter prefix for
	// non-shell languages — the warden always runs `/bin/sh -c <command>`) and
	// wire-gated at step 0; it is NOT rebuilt here().
	execReq := pool.ExecRequest{
		NodeAddr:        node,
		SandfsID:        identity.SandfsID,
		AgentID:         identity.AgentID,
		VolumePath:      identity.RootFSPath,
		VolumeEpoch:     identity.VolumeEpoch,
		Command:         command,
		Background:      req.Background,
		TimeoutMs:       timeoutMs,
		LeaseDurationMs: leaseMs,
		InstallPackages: identity.InstallPackages,
		MinSpec:         spec,
		// "" for flat records: the node ignores any marker when the record
		// expects no template (the flat rootfs is agent-writable).
		TemplateRef: identity.MountTemplateRef(),
		// The mount mode is the RECORD's, forwarded to the warden so a
		// flat volume's agent-planted layout can never choose overlay
		// semantics.
		VolumeMode: identity.Mode,
	}
	// Bound capacity was reserved atomically inside pool.Acquire (cold mount
	// only — the warm path reuses an already-bound VM counted on the prior cold
	// mount). The provisional floor-spec reservation is corrected to the actual
	// spec on response via AdjustBound, or rolled back via ReleaseBound on
	// failure. Do NOT call ReserveBound here — Acquire already did.
	// Bracket the exec RPC with an in-flight refcount so the lease is not
	// released (unmount triggered) while the RPC is in progress. For a sync cold
	// mount the lease entry may not exist yet, in which case BeginExec is a
	// no-op and the mountLock prevents dual-mount instead.
	h.leaseMgr.BeginExec(identity.SandfsID)
	// defer EndExec so a panic in the RPC / retry loop (e.g. a nil-deref in the
	// stream client deserializing a malformed response) does not leave
	// activeExecs > 0 forever — which would permanently wedge the sandfs's
	// lease (canRelease always false → VM never unmounted). EndExec is idempotent
	// (clamps at 0, no-op on a missing entry).
	defer h.leaseMgr.EndExec(identity.SandfsID)
	// The MountLock release defer was registered at acquisition (see above),
	// so it also covers every early return before this point.
	execRes, err := h.sandlotClient.MountRootfsAndExecute(ctx, execReq)

	// 10. L1 retry: transport errors → retry up to 2 times with fresh connection
	if err != nil && IsTransportError(err) {
		for retry := 0; retry < 2; retry++ {
			time.Sleep(50 * time.Millisecond)
			execRes, err = h.sandlotClient.MountRootfsAndExecute(ctx, execReq)
			if err == nil {
				break
			}
			if !IsTransportError(err) {
				break // Non-transport error — don't retry.
			}
		}
	}

	if err != nil {
		// Release the send-time bound reservation on failure.
		if needsColdMount {
			h.pool.ReleaseBound(node, spec)
		}
		// "no available VM on node" (over-subscription / empty pool) is
		// NOT a mount failure - the sandfs isn't dirty. Retry on another node. With
		// the real-time derived clean count, the over-subscribed node's
		// clean is 0, so the retry's pool.Acquire routes elsewhere. Do NOT
		// EnterCleaning (that would 503-block this sandfs for ~12s needlessly).
		if errors.Is(err, pool.ErrNoAvailableSandbox) {
			// voluntary load shed: if the gateway is sustained-saturated
			// and an idle peer exists, release this sandfs's ownership so the DNS
			// re-routes the client to the peer, and signal the client to reconnect
			// (re-resolve). Cold-path only (this branch is cold-path only).
			if shed := shedColdPath(h.shed, h.ownership, identity.SandfsID); shed != lease.ShedActionNone {
				h.logger.Info("load shed: saturating sandfs rebalanced to a peer",
					"node", node, "sandfsID", identity.SandfsID, "shed", shed == lease.ShedActionShed)
				retryMs := h.shed.RetryAfterSec() * 1000
				return nil, &resilienceError{
					code:          http.StatusServiceUnavailable,
					msg:           "gateway saturated, ownership released: reconnect (re-resolve DNS) to reach a peer",
					errorCode:     "SHED_REBALANCE",
					retryAfterMs:  retryMs,
					shedRebalance: true,
				}
			}
			if opDebug.Load() {
				h.logger.Info("no available sandbox on node; retry on another", "node", node, "sandfsID", identity.SandfsID)
			}
			return nil, &resilienceError{
				code: http.StatusServiceUnavailable, msg: "no available sandbox on node, retry",
				errorCode: "NO_AVAILABLE_SANDBOX", retryAfterMs: 1000,
			}
		}
		// Stream-layer transport errors (connection closed / send queue full /
		// node not found): the command never reached the sandlot, so the sandfs
		// is NOT dirty. Do NOT EnterCleaning or fire an async unmount at an
		// already-dead/slow node — that would block the sandfs for ~12s and pile
		// more RPCs on the failing node. Return a short retry so the next
		// attempt re-acquires (possibly on another node after the disconnect
		// propagates).
		if stream.IsStreamTransportError(err) {
			// The command may have reached the node before the reply path
			// broke: the mount outcome is unknown. Keep the ownership entry
			// orphan-uncertain until the node reconnects clean or T_safe
			// resolves it; clearing dispatching alone would re-open the
			// sandfs to a shed/release while our mount may be live.
			if dispatchGen != 0 && h.ownership != nil {
				h.ownership.NoteDispatchUnconfirmed(identity.SandfsID)
			}
			h.logger.Warn("stream transport error; mount outcome unconfirmed (no cleanup)", "node", node, "sandfsID", identity.SandfsID, "error", err)
			return nil, &resilienceError{
				code: http.StatusServiceUnavailable, msg: "node temporarily unreachable, retry",
				errorCode: "NODE_UNAVAILABLE", retryAfterMs: 500,
			}
		}
		h.logger.Error("mount-rootfs-and-execute failed", "node", node, "error", err)

		// L2 cleanup: EnterCleaning → async cleanup → 503
		if h.sandfsState != nil {
			h.sandfsState.EnterCleaning(identity.SandfsID)
		}
		go h.cleanupAfterFailure(identity.SandfsID, node, identity.RootFSPath, identity.VolumeEpoch)

		return nil, &resilienceError{
			code: http.StatusServiceUnavailable, msg: "execution failed, sandbox is cleaning",
			errorCode: "SANDBOX_CLEANING", retryAfterMs: lease.DefaultRetryAfterMs,
		}
	}

	// Correct the provisional bound reservation (under min_spec) to the
	// actual VM spec from the response, and record the spec on the lease so
	// onExpiry's ReleaseBound frees the right spec's bound (real-time clean rises
	// -> nodeA reusable after unmount). Only on cold mount.
	//
	// The node's reported spec is only trusted when the pool can account for
	// it; AdjustBound validates and returns the spec the bound actually sits
	// under, and THAT value — never the raw node report — is what the lease
	// records (a raw unrecognized string would make ReleaseBound a no-op and
	// leak the bound forever).
	appliedSpec := execRes.Spec
	if needsColdMount {
		appliedSpec = h.pool.AdjustBound(node, spec, execRes.Spec)
		h.leaseMgr.SetSpec(identity.SandfsID, appliedSpec)
	} else if !h.pool.ValidSpec(node, appliedSpec) {
		appliedSpec = h.leaseMgr.SpecOf(identity.SandfsID)
	}

	// 11. Update ownership on successful mount. The confirmation carries the
	// generation captured at dispatch: a moved generation or a different
	// recorded node means this mount LOST the ownership race (takeover or a
	// cross-node duplicate). The loser is torn down and the client retries;
	// the winner's mount is never touched.
	if needsColdMount && h.ownership != nil {
		if h.ownership.NoteMountedChecked(identity.SandfsID, node, dispatchGen) {
			abandonConflictingMount(h.sandlotClient, h.pool, h.unmountStats, h.logger,
				identity.SandfsID, node, identity.RootFSPath, identity.VolumeEpoch, appliedSpec)
			return nil, &resilienceError{
				code:         http.StatusServiceUnavailable,
				msg:          "mount conflicted with the ownership record; the duplicate was torn down, retry",
				errorCode:    "MOUNT_CONFLICT",
				retryAfterMs: lease.JitteredRetryAfterMs(1000),
			}
		}
	}
	// Record the cold mount for per-node unmount stats (mount count + last
	// command context for the eventual unmount's slow-entry). Post-response, off
	// the warm path (needsColdMount is false on lease hits).
	if needsColdMount && h.unmountStats != nil {
		h.unmountStats.RecordMount(node, identity.SandfsID, command)
	}

	// 12. Lease management. Background execs register an absolute lease deadline
	// (lease_duration = run-time cap; polls do NOT extend it). Sync execs arm the
	// 100ms sticky window via TouchSync (does not touch bg deadlines). The spec
	// rides along so a newly created entry carries the bound's bucket from birth
	// — SetSpec alone can't do that (it no-ops when the entry doesn't exist yet).
	if req.Background && execRes.ExecID != "" {
		leaseDur := time.Duration(leaseMs) * time.Millisecond
		h.leaseMgr.StartBgExec(identity.SandfsID, node, execRes.ExecID, leaseDur)
		// The entry may have been born HERE (a sandfs's very first exec being a
		// background exec): SetSpec above ran before any entry existed and
		// no-opped, leaving e.Spec empty. onExpiry then called
		// ReleaseBound(node, "") which defaults to the phantom "medium" bucket
		// while the real bound sat on "small" — the bound leaked forever, the
		// VM showed IN_USE on /stats indefinitely, and every later exec on the
		// node 503'd NO_AVAILABLE_SANDBOX. Re-apply now that the entry exists.
		h.leaseMgr.SetSpec(identity.SandfsID, appliedSpec)
	} else if !leaseHit {
		h.leaseMgr.TouchSync(identity.SandfsID, node, appliedSpec)
	} else {
		// Warm path: the sync exec ran on an existing lease; refresh its sticky
		// window without disturbing any active bg deadline.
		h.leaseMgr.TouchSync(identity.SandfsID, node, appliedSpec)
	}
	h.leaseMgr.SetVolumePath(identity.SandfsID, identity.RootFSPath)
	h.leaseMgr.SetVolumeEpoch(identity.SandfsID, identity.VolumeEpoch)

	return &ExecuteDirectResult{
		Stdout:            execRes.Stdout,
		Stderr:            execRes.Stderr,
		ExitCode:          execRes.ExitCode,
		ExecID:            execRes.ExecID,
		Status:            execRes.Status,
		ExecDurationNs:    execRes.ExecDurationNs,
		SandlotDurationNs: execRes.SandlotDurationNs,
		GatewayDurationNs: uint64(time.Since(start).Nanoseconds()),
		LeaseHit:          leaseHit,
		Identity:          identity,
	}, nil
}

// cleanupAfterFailure performs L2 cleanup after an execution failure:
// UnmountRootfs(8s) → ownership release → ExitCleaning. Runs asynchronously with
// a 12s total timeout. No pool.Release — sandlot owns the VM lifecycle; unmounting
// the sandfs returns the VM to CLEAN.
//
// The ownership release is SUCCESS-GATED: on unmount failure the ownership key
// stays (and the lease-side unmount retries via RetryUnmount). Deleting it
// anyway would let a peer claim the sandfs and mount it on another node while
// our VM still holds the live mount — the exact dual-mount L2 cleanup exists
// to prevent. The next request reuses the still-bound VM (placement affinity +
// sandlot's sandfs→VM binding), which is safe, and the retry lands the unmount.
//
// TODO(batch-unmount): single-sandfs RPC per failure; only a mass-failure event
// would batch these — see the StreamSandlotClient.UnmountRootfs TODO.
func (h *ExecuteHandler) cleanupAfterFailure(sandfsID, node, volumePath, volumeEpoch string) {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	// defer ExitCleaning so a panic or a stuck UnmountRootfs (the goroutine
	// continues past ctx cancel if the gRPC client doesn't honor it) does not
	// leave the sandfs in stateCleaning forever — which would 503 every
	// future request permanently. ExitCleaning is idempotent.
	if h.sandfsState != nil {
		defer h.sandfsState.ExitCleaning(sandfsID)
	}

	// UnmountRootfs with 8s timeout.
	unmountCtx, unmountCancel := context.WithTimeout(ctx, 8*time.Second)
	res, err := h.sandlotClient.UnmountRootfs(unmountCtx, node, sandfsID, volumePath, volumeEpoch)
	if err != nil {
		h.logger.Warn("cleanup: unmount failed; will retry with backoff (ownership kept)", "sandfsID", sandfsID, "node", node, "error", err)
	}
	unmountCancel()
	if h.unmountStats != nil {
		h.unmountStats.RecordUnmount(node, sandfsID, "cleanup-after-failure", res, err == nil)
	}
	if err != nil {
		// The unmount failed while the mount may still be live: keep the
		// ownership entry orphan-uncertain, not merely owned. The lease-side
		// retry lands the unmount; until then a shed must not release it.
		if h.ownership != nil {
			h.ownership.NoteDispatchUnconfirmed(sandfsID)
		}
		h.leaseMgr.RetryUnmount(sandfsID, node, h.leaseMgr.SpecOf(sandfsID))
		return
	}

	if h.ownership != nil {
		// Release ownership entirely after L2 cleanup. The sandfs has no
		// active mount and no in-flight exec — preserving the ownership
		// record would force the next request into forceTakeover instead
		// of a clean createOwnership CAS. ReleaseOwnership deletes the
		// etcd key (async), which also clears node_id.
		h.ownership.ReleaseOwnership(sandfsID)
	}

	// ExitCleaning runs via the deferred call at the top of this goroutine.
}

// abandonConflictingMount tears down a cold mount that lost the ownership race
// (its dispatch generation moved, or another node already holds the recorded
// mount). The winner keeps serving the sandfs; only this node's pool
// reservation and guest mount are released. Best-effort and off the response
// path: the caller returns a retryable error immediately.
func abandonConflictingMount(sc pool.SandlotClient, pm *pool.Manager, stats pool.UnmountRecorder, logger *slog.Logger, sandfsID, node, volumePath, volumeEpoch, spec string) {
	pm.ReleaseBound(node, spec)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		res, err := sc.UnmountRootfs(ctx, node, sandfsID, volumePath, volumeEpoch)
		if stats != nil {
			stats.RecordUnmount(node, sandfsID, "mount-conflict", res, err == nil)
		}
		if err != nil {
			logger.Warn("mount-conflict: loser unmount failed", "sandfsID", sandfsID, "node", node, "error", err)
		}
	}()
}

// execHTTPError is a sentinel for HTTP error responses from ExecuteDirect.
type execHTTPError struct {
	code int
	msg  string
	// errorCode is the stable machine-readable name of a client-class refusal
	// (currently the wire-size gate) that the MCP transport projects
	// into a structured tool error. Empty = plain HTTP-shaped error.
	errorCode string
}

func (e *execHTTPError) Error() string { return e.msg }

// commandTooLargeErr is the named client-class refusal() for a wrapped
// exec command that would breach the node stream's gRPC message limit.
func commandTooLargeErr(wrapped int) *execHTTPError {
	return &execHTTPError{
		code:      http.StatusRequestEntityTooLarge,
		msg:       fmt.Sprintf("code too large: the command sent to the sandbox is %d bytes, exceeding the %d-byte single-op wire cap (split the code or write it to a file with file_write)", wrapped, maxFileOpDataBytes),
		errorCode: "EXEC_TOO_LARGE",
	}
}

// RedirectHeader is set on 307 responses and checked on requests (redirect anti-loop).
// A request arriving WITH this header is itself a redirected one (the gateway
// that issued the 307 set it on the response; clients that forward request
// headers — or that we marked via a prior hop — must never be redirected again,
// else an owner↔non-owner pair would ping-pong forever). Custom X-* headers
// survive cross-host redirects in Go/Python/curl, so the marker travels with the
// request when the client echoes it. Clients that don't echo it are bounded by
// their own max-redirect cap (Go: 10) as the hard stop.
const RedirectHeader = "X-Sandswap-Redirected"

// smallJSONBodyLimit is the body size cap for endpoints that accept only small
// JSON payloads (agent/sandfs create, save-template, exec status/kill). 1 MB is
// far more than these tiny bodies ever need, and bounds memory against a client
// that streams an oversized body (ReadTimeout only limits slow bodies, not a
// fast oversized one). The execute (10 MB) and file/MCP (50 MB) endpoints have
// their own larger limits for code/file payloads.
const smallJSONBodyLimit = 1 << 20 // 1 MB

// OwnerRedirectError signals that THIS gateway is not the owner of the sandfs
// and the request should be 307-redirected to the owner gateway (redirect). The HTTP
// layer appends the original request path+query to build the Location. Only
// produced when the owner is healthy AND routable (registered an agent URL);
// owner-dead/absent stays a 503 so the client retry force-takes-over here.
type OwnerRedirectError struct {
	OwnerURL string // base URL of the owner gateway (no trailing slash)
}

func (e *OwnerRedirectError) Error() string { return "redirect to owner gateway: " + e.OwnerURL }

// IsOwnerRedirect extracts the owner base URL from an error.
func IsOwnerRedirect(err error) (string, bool) {
	if e, ok := err.(*OwnerRedirectError); ok {
		return e.OwnerURL, true
	}
	return "", false
}

// redirectLocation builds the 307 Location: owner base URL + original path+query.
// Returns "" when no redirect should happen (request is itself a redirected one).
func redirectLocation(ownerURL string, r *http.Request) string {
	if r.Header.Get(RedirectHeader) == "1" {
		return "" // anti-loop: never redirect a redirected request again
	}
	return ownerURL + r.URL.RequestURI()
}

// writeOwnerRedirect writes a 307 to the owner gateway for the current request,
// respecting the anti-loop header. Returns true if a redirect was written.
func writeOwnerRedirect(w http.ResponseWriter, r *http.Request, ownerURL string) bool {
	loc := redirectLocation(ownerURL, r)
	if loc == "" {
		return false
	}
	w.Header().Set(RedirectHeader, "1")
	http.Redirect(w, r, loc, http.StatusTemporaryRedirect)
	return true
}

// ServeHTTP handles the POST /agent/execute request.
func (h *ExecuteHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	start := time.Now()

	// 1. Extract and validate API key
	apiKey, err := identity.ExtractAPIKey(r)
	if err != nil {
		writeJSONError(w, "missing api key", http.StatusUnauthorized)
		return
	}
	// Validate the key BEFORE reading the body (10 MB): an unauthenticated
	// caller must not make the gateway allocate/decode it. Ownership is
	// re-derived later by ExecuteDirect.
	if h.identityStore == nil {
		writeJSONError(w, "identity store unavailable", http.StatusServiceUnavailable)
		return
	}
	if _, err := h.identityStore.ResolveAgent(apiKey); err != nil {
		writeJSONError(w, "invalid api key", http.StatusUnauthorized)
		return
	}

	// 2. Parse request body (10MB limit, )
	// http.MaxBytesReader returns http.MaxBytesError on overflow → 413.
	limited := http.MaxBytesReader(w, r.Body, MaxExecuteRequestBodyBytes)
	body, err := io.ReadAll(limited)
	if err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			writeJSONError(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		writeJSONError(w, "bad request", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var req ExecuteRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSONError(w, "invalid json", http.StatusBadRequest)
		return
	}

	// 3. Execute via the shared pipeline
	result, err := h.ExecuteDirect(r.Context(), apiKey, req)
	if err != nil {
		// redirect: ownership conflict + healthy owner → 307 to the owner gateway.
		// 307 preserves method + body + headers, so the replayed POST arrives
		// intact at the owner and converges onto the warm connection.
		if ownerURL, ok := IsOwnerRedirect(err); ok {
			if loc := redirectLocation(ownerURL, r); loc != "" {
				w.Header().Set(RedirectHeader, "1")
				http.Redirect(w, r, loc, http.StatusTemporaryRedirect)
				return
			}
			// Anti-loop: this request is itself a redirected one — never redirect
			// again. Return a retryable 503 so the client backs off instead of
			// ping-ponging between gateways forever.
			writeResilienceError(w, &resilienceError{
				code: http.StatusServiceUnavailable, msg: "ownership conflict: redirect loop prevented",
				errorCode: "OWNERSHIP_CONFLICT", retryAfterMs: lease.JitteredRetryAfterMs(lease.RetryAfterMs),
			})
			return
		}
		if he, ok := err.(*execHTTPError); ok {
			writeJSONError(w, he.msg, he.code)
			return
		}
		if he, ok := err.(*authHTTPError); ok {
			writeJSONError(w, he.msg, he.code)
			return
		}
		if _, ok := err.(*resilienceError); ok {
			writeResilienceError(w, err)
			return
		}
		// RPC-level error from MountRootfsAndExecute
		writeJSONError(w, err.Error(), http.StatusBadGateway)
		return
	}

	// 4. Return result
	w.Header().Set("Content-Type", "application/json")
	if result.LeaseHit {
		w.Header().Set("X-Sandbox-Lease", "hit")
	}
	json.NewEncoder(w).Encode(&ExecuteResponse{
		Stdout:            result.Stdout,
		Stderr:            result.Stderr,
		ExitCode:          result.ExitCode,
		ExecID:            result.ExecID,
		Status:            result.Status,
		ExecDurationNs:    result.ExecDurationNs,
		SandlotDurationNs: result.SandlotDurationNs,
		GatewayDurationNs: result.GatewayDurationNs,
	})

	if opDebug.Load() {
		h.logger.Info("execute complete",
			"sandfsID", result.Identity.SandfsID,
			"execID", result.ExecID,
			"leaseHit", result.LeaseHit,
			"latency", time.Since(start).String(),
		)
	}
}

// ExecStatusRequest polls a background exec's liveness + captured log tail.
type ExecStatusRequest struct {
	ExecID   string `json:"exec_id"`
	SandfsID string `json:"sandfs_id"` // which sandfs
}

// ExecStatusResponse is the reply for /exec/status.
type ExecStatusResponse struct {
	Status   string `json:"status"` // running|done|killed|not_found|expired
	ExitCode int    `json:"exit_code,omitempty"`
	Stdout   string `json:"stdout,omitempty"` // captured log tail
	Stderr   string `json:"stderr,omitempty"` // captured stderr tail
	Error    string `json:"error,omitempty"`
}

// ExecKillRequest kills a background exec by exec_id.
type ExecKillRequest struct {
	ExecID   string `json:"exec_id"`
	SandfsID string `json:"sandfs_id"`
}

// ExecStatusDirectResult is the result of ExecStatusDirect.
type ExecStatusDirectResult struct {
	Status   string
	ExitCode int
	Stdout   string
	Stderr   string
}

// ExecStatusDirect is the direct-call entry point for polling a background exec.
// Exported for MCP server use.
func (h *ExecuteHandler) ExecStatusDirect(ctx context.Context, apiKey, sandfsID, execID string) (*ExecStatusDirectResult, error) {
	identity, err := ResolveFromRequest(h.identityStore, apiKey, sandfsID)
	if err != nil {
		return nil, err
	}

	node := h.leaseMgr.Acquire(identity.SandfsID)
	if node != "" {
		// We hold an active lease — this gateway owns the exec. Warm fast path,
		// no etcd read. Bracket the poll RPC so the lease is not released while
		// the RPC is in flight; the poll does NOT extend the bg lease deadline.
		h.leaseMgr.BeginExec(identity.SandfsID)
		// defer EndExec: a panic in the RPC path must not leave activeExecs > 0
		// forever (it would wedge the sandfs's lease — canRelease never true).
		// Mirrors ExecuteDirect's panic-safe bracket. Idempotent.
		defer h.leaseMgr.EndExec(identity.SandfsID)
		res, err := h.sandlotClient.StatusExec(ctx, node, identity.SandfsID, execID)
		if err != nil {
			return nil, err
		}
		// A finished exec (done/killed/not_found) is marked done so the lease
		// re-evaluates for release. "running" leaves the deadline untouched.
		switch res.Status {
		case "done", "killed", "not_found", "timed_out":
			h.leaseMgr.MarkBgDone(identity.SandfsID, execID)
		}
		return &ExecStatusDirectResult{
			Status:   res.Status,
			ExitCode: res.ExitCode,
			Stdout:   res.Stdout,
			Stderr:   res.Stderr,
		}, nil
	}

	// No local lease. Before reporting "expired" (which would make the agent
	// STOP polling and starve the exec via unmount + cgroup.kill), check whether
	// ANOTHER healthy gateway owns this sandfs — the exec may still be running
	// there. If so, redirect the poll to the owner (redirect). Only when the owner is
	// us (lease just expired) or there is no owner is "expired" correct.
	if h.ownership != nil {
		// OwnerGatewayURL returns "" when we own it (no self-redirect), there is
		// no owner, or the owner has no registered registry address.
		if ownerURL := h.ownership.OwnerGatewayURL(ctx, identity.SandfsID); ownerURL != "" {
			return nil, &OwnerRedirectError{OwnerURL: ownerURL}
		}
	}
	return &ExecStatusDirectResult{Status: "expired"}, nil
}

// ExecKillDirectResult is the result of ExecKillDirect.
type ExecKillDirectResult struct {
	Status string // "killed" | "not_found" | "expired"
}

// ExecKillDirect is the direct-call entry point for killing a background exec.
// Exported for MCP server use.
func (h *ExecuteHandler) ExecKillDirect(ctx context.Context, apiKey, sandfsID, execID string) (*ExecKillDirectResult, error) {
	identity, err := ResolveFromRequest(h.identityStore, apiKey, sandfsID)
	if err != nil {
		return nil, err
	}

	node := h.leaseMgr.Acquire(identity.SandfsID)
	if node != "" {
		// We hold the lease — kill here. Bracket the RPC so the lease is not
		// released while the kill is in flight.
		h.leaseMgr.BeginExec(identity.SandfsID)
		defer h.leaseMgr.EndExec(identity.SandfsID) // panic-safe bracket (see ExecStatusDirect)
		err := h.sandlotClient.KillExec(ctx, node, identity.SandfsID, execID)
		if err != nil {
			if errors.Is(err, pool.ErrBgExecNotFound) {
				// no such exec — idempotent, truthfully reported.
				h.leaseMgr.MarkBgDone(identity.SandfsID, execID)
				return &ExecKillDirectResult{Status: "not_found"}, nil
			}
			return nil, err
		}
		// Marking the exec done lets the lease release the VM (if no other bg/sync
		// holds it).
		h.leaseMgr.MarkBgDone(identity.SandfsID, execID)
		return &ExecKillDirectResult{Status: "killed"}, nil
	}

	// No local lease — the exec may live on another gateway's VM. Redirect the
	// kill to the owner when one exists (redirect), else report expired.
	if h.ownership != nil {
		if ownerURL := h.ownership.OwnerGatewayURL(ctx, identity.SandfsID); ownerURL != "" {
			return nil, &OwnerRedirectError{OwnerURL: ownerURL}
		}
	}
	return &ExecKillDirectResult{Status: "expired"}, nil
}

// HandleExecStatus handles POST /agent/exec/status — poll a background exec.
func (h *ExecuteHandler) HandleExecStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	apiKey, err := identity.ExtractAPIKey(r)
	if err != nil {
		writeJSONError(w, "missing api key", http.StatusUnauthorized)
		return
	}
	// Validate the key BEFORE decoding the body: an unauthenticated caller
	// must not drive an allocation, however small, only to answer 401.
	if !verifyAPIKeyHeader(w, r, h.identityStore) {
		return
	}
	var req ExecStatusRequest
	// Bound the body (smallJSONBodyLimit): json.Decoder buffers the whole value,
	// so an unbounded stream from an authenticated-but-hostile client would
	// balloon memory. ReadTimeout only bounds SLOW bodies, not fast big ones.
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, smallJSONBodyLimit)).Decode(&req); err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			writeJSONError(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		writeJSONError(w, "invalid json", http.StatusBadRequest)
		return
	}
	if req.SandfsID == "" {
		writeJSONError(w, "sandfs_id is required", http.StatusBadRequest)
		return
	}
	if req.ExecID == "" {
		writeJSONError(w, "exec_id is required", http.StatusBadRequest)
		return
	}

	result, err := h.ExecStatusDirect(r.Context(), apiKey, req.SandfsID, req.ExecID)
	if err != nil {
		// redirect: exec lives on another gateway — redirect the poll there.
		if ownerURL, ok := IsOwnerRedirect(err); ok {
			if !writeOwnerRedirect(w, r, ownerURL) {
				writeJSONError(w, "ownership conflict", http.StatusServiceUnavailable)
			}
			return
		}
		writeAuthError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ExecStatusResponse{
		Status:   result.Status,
		ExitCode: result.ExitCode,
		Stdout:   result.Stdout,
		Stderr:   result.Stderr,
	})
}

// HandleExecKill handles POST /agent/exec/kill — kill a background exec by exec_id.
func (h *ExecuteHandler) HandleExecKill(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	apiKey, err := identity.ExtractAPIKey(r)
	if err != nil {
		writeJSONError(w, "missing api key", http.StatusUnauthorized)
		return
	}
	if !verifyAPIKeyHeader(w, r, h.identityStore) {
		return
	}
	var req ExecKillRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, smallJSONBodyLimit)).Decode(&req); err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			writeJSONError(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		writeJSONError(w, "invalid json", http.StatusBadRequest)
		return
	}
	if req.SandfsID == "" {
		writeJSONError(w, "sandfs_id is required", http.StatusBadRequest)
		return
	}
	if req.ExecID == "" {
		writeJSONError(w, "exec_id is required", http.StatusBadRequest)
		return
	}

	result, err := h.ExecKillDirect(r.Context(), apiKey, req.SandfsID, req.ExecID)
	if err != nil {
		// redirect: exec lives on another gateway — redirect the kill there.
		if ownerURL, ok := IsOwnerRedirect(err); ok {
			if !writeOwnerRedirect(w, r, ownerURL) {
				writeJSONError(w, "ownership conflict", http.StatusServiceUnavailable)
			}
			return
		}
		writeAuthError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ExecStatusResponse{Status: result.Status})
}

// wrapCommand wraps code with the appropriate interpreter based on language.
// The warden always runs `/bin/sh -c <command>`, so non-shell languages
// need an explicit interpreter prefix. Shell and empty language pass through
// unchanged.
func wrapCommand(language, code string) string {
	switch language {
	case "python", "python3":
		return "python3 -c " + shQuote(code)
	case "node", "javascript", "js":
		return "node -e " + shQuote(code)
	case "ruby", "rb":
		return "ruby -e " + shQuote(code)
	case "shell", "sh", "bash", "":
		return code
	default:
		// Unknown language — pass through as-is (may be a raw shell command).
		return code
	}
}

// shQuote wraps a string in single quotes for safe embedding in a shell command.
// Any embedded single quotes are escaped as '\” (end quote, escaped quote, start quote).
func shQuote(s string) string {
	const q = '\''
	var buf []byte
	buf = append(buf, q)
	for i := 0; i < len(s); i++ {
		if s[i] == q {
			buf = append(buf, q, '\\', q, q)
		} else {
			buf = append(buf, s[i])
		}
	}
	buf = append(buf, q)
	return string(buf)
}

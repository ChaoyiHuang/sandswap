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

package handler

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"
	"unicode/utf8"

	commonconfig "common/config"
	"gateway/identity"

	"gateway/lease"
	"gateway/pool"
	"gateway/stream"
)

// FileHandler handles the unified POST /agent/file endpoint for the Gateway API.
// All 7 file operations (read, write, stat, list_dir, mkdir, remove, rename)
// are dispatched via a single JSON body with an "action" field, routing through
// the shared doFileOp flow: auth → lease/acquire → ensure-mounted → FileOp RPC.
type FileHandler struct {
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
}

// SetShedController attaches the load-shed controller. nil (or not
// called) = shedding disabled (default).
func (h *FileHandler) SetShedController(sc *lease.ShedController) {
	h.shed = sc
}

// SetUnmountRecorder wires the per-node unmount stats recorder. nil (or not
// called) = recording disabled. Wired after construction in cmd/main.go.
func (h *FileHandler) SetUnmountRecorder(r pool.UnmountRecorder) {
	h.unmountStats = r
}
func NewFileHandler(store identity.Store, pm *pool.Manager, lm *lease.Lease, sc pool.SandlotClient, ml *lease.MountLock, oc *lease.OwnershipCache, ss *lease.SandfsState, logger *slog.Logger) *FileHandler {
	// Publish the cold-mount lock to the process (see NewExecuteHandler): the
	// lifecycle drain consults it so it never settles under a dispatch.
	lease.RegisterDispatchLock(ml)
	return &FileHandler{
		identityStore: store,
		pool:          pm,
		leaseMgr:      lm,
		sandlotClient: sc,
		mountLock:     ml,
		ownership:     oc,
		sandfsState:   ss,
		logger:        logger,
	}
}

// FileRequest is the JSON body for POST /agent/file.
// Paths are relative to /workspace inside the sandbox.
type FileRequest struct {
	SandfsID   string `json:"sandfs_id"`             // SandFS instance (required)
	Action     string `json:"action"`                // read|write|stat|list_dir|mkdir|remove|rename
	Path       string `json:"path"`                  // relative to /workspace
	NewPath    string `json:"new_path,omitempty"`    // rename only: destination
	Data       string `json:"data,omitempty"`        // text content (write)
	DataBase64 string `json:"data_base64,omitempty"` // base64-encoded binary content (write)
	Offset     *int64 `json:"offset,omitempty"`      // read/write: byte offset
	Length     *int64 `json:"length,omitempty"`      // read: max bytes (0 = up to cap)
	Append     bool   `json:"append,omitempty"`      // write: append mode (offset = -1)
	Mode       uint32 `json:"mode,omitempty"`        // write/mkdir: permissions (0 = default)
	Recursive  bool   `json:"recursive,omitempty"`   // remove: rm -rf
	Depth      uint32 `json:"depth,omitempty"`       // list_dir: recursion depth
}

// FileResponse is the JSON response for POST /agent/file.
type FileResponse struct {
	Ok         bool            `json:"ok,omitempty"`
	Data       string          `json:"data,omitempty"`        // text content (read, UTF-8)
	DataBase64 string          `json:"data_base64,omitempty"` // base64-encoded binary (read, non-UTF-8)
	IsText     *bool           `json:"is_text,omitempty"`     // nil for non-read ops; true/false for read
	Size       int64           `json:"size,omitempty"`        // byte count (read/write)
	Entries    json.RawMessage `json:"entries,omitempty"`     // list_dir: JSON array
}

// ServeHTTP handles POST /agent/file — the sole file I/O endpoint.
func (h *FileHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, "method not allowed, use POST", http.StatusMethodNotAllowed)
		return
	}
	if r.URL.Path != "/agent/file" {
		writeJSONError(w, "not found", http.StatusNotFound)
		return
	}
	h.handleFileOp(w, r)
}

// maxFileOpDataBytes is the largest single-op FileOp data payload this
// handler forwards.: a payload at/over the chain limit plus the proto
// envelope exceeds the gRPC max message size, and a wire-limit breach is a
// STREAM-LEVEL failure — the node stream resets and every co-tenant command
// in flight on that sandlot dies. The gate sits 64 KiB under the validated
// chain floor, so it is always safe under the startup-enforced caps.
var maxFileOpDataBytes = commonconfig.MaxFileOpPayload(commonconfig.MinFileOpChainBytes)

// MaxFileRequestBodyBytes bounds the /agent/file HTTP body. It is larger than
// the gRPC FileOp payload because base64/JSON inflate a 16MB binary write by
// ~33%; the MCP file_write transport uses the same limit.
const MaxFileRequestBodyBytes = 50 << 20

// SetMaxFileOpDataBytesForTest shrinks the wire-size gate for tests
// (production value is fixed by the chain-floor constant). Restore after.
func SetMaxFileOpDataBytesForTest(n int) (prev int) {
	prev = maxFileOpDataBytes
	maxFileOpDataBytes = n
	return prev
}

// fileOpWireSizeError returns the named refusal for a FileOp whose
// payload would breach the stream's gRPC message limit on the wire, or nil.
// The gate lives HERE — in the shared direct pipeline, not per transport — so
// every caller (HTTP and the MCP tool path) validates identically: the
// MCP transport's 50MB body cap is far above the wire limit, and without this
// check its file_write/file_read calls reached the node stream oversize, where
// the failed Send closes the node stream and kills every co-tenant in-flight
// command on that sandlot.
func fileOpWireSizeError(req pool.FileOpRequest) *fileHTTPError {
	// Paths ride every action and are attacker-controlled: an unbounded one
	// breaches the gRPC message limit (rename carries two) AND drives the
	// warden's O(bytes) ancestor walk. PATH_MAX-1 is the largest resolvable
	// string, so the bound loses nothing.
	if len(req.Path) > commonconfig.MaxFilePathBytes || len(req.NewPath) > commonconfig.MaxFilePathBytes {
		return &fileHTTPError{
			code:      http.StatusRequestEntityTooLarge,
			msg:       fmt.Sprintf("path exceeds %d bytes (PATH_MAX)", commonconfig.MaxFilePathBytes),
			errorCode: "FILE_PATH_TOO_LONG",
		}
	}
	switch req.Action {
	case "write":
		if n := len(req.Data); n > maxFileOpDataBytes {
			return &fileHTTPError{
				code:      http.StatusRequestEntityTooLarge,
				msg:       fmt.Sprintf("data too large: %d bytes exceeds the %d-byte single-op cap (split the write)", n, maxFileOpDataBytes),
				errorCode: "FILE_TOO_LARGE",
			}
		}
	case "read":
		if req.Length > int64(maxFileOpDataBytes) {
			return &fileHTTPError{
				code:      http.StatusRequestEntityTooLarge,
				msg:       fmt.Sprintf("length %d exceeds the %d-byte single-read cap (page the read with offset)", req.Length, maxFileOpDataBytes),
				errorCode: "FILE_TOO_LARGE",
			}
		}
	}
	return nil
}

// handleFileOp dispatches POST /agent/file based on the action field.
func (h *FileHandler) handleFileOp(w http.ResponseWriter, r *http.Request) {
	// Authenticate BEFORE reading the body: a 50 MB body (base64 write) must
	// never be allocated/decoded for an unauthenticated caller. Ownership is
	// still re-derived per-sandfs later.
	if !verifyAPIKeyHeader(w, r, h.identityStore) {
		return
	}
	// Limit body size to 50MB for file operations (large writes may carry
	// base64-encoded data). Matches the design doc's  body size limit.
	// http.MaxBytesReader returns http.MaxBytesError on overflow → 413.
	limited := http.MaxBytesReader(w, r.Body, MaxFileRequestBodyBytes)
	var req FileRequest
	if err := json.NewDecoder(limited).Decode(&req); err != nil {
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
	if req.Action == "" {
		writeJSONError(w, "missing action", http.StatusBadRequest)
		return
	}
	if req.Path == "" && req.Action != "rename" {
		writeJSONError(w, "missing path", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	switch req.Action {
	case "read":
		h.doRead(w, r, req)
	case "write":
		h.doWrite(w, r, req)
	case "stat":
		h.doStat(w, r, req)
	case "list_dir":
		h.doListDir(w, r, req)
	case "mkdir":
		h.doMkdir(w, r, req)
	case "remove":
		h.doRemove(w, r, req)
	case "rename":
		h.doRename(w, r, req)
	default:
		writeJSONError(w, "unknown action", http.StatusBadRequest)
	}
}

// doRead handles action=read: returns file content as text or base64.
func (h *FileHandler) doRead(w http.ResponseWriter, r *http.Request, req FileRequest) {
	var offset, length int64
	if req.Offset != nil {
		offset = *req.Offset
	}
	if req.Length != nil {
		length = *req.Length
	}
	// gate: the read-length wire gate runs inside DoFileOpDirect (the
	// shared direct pipeline) so HTTP and MCP validate identically.

	result, err := h.doFileOp(r, req.SandfsID, pool.FileOpRequest{
		Action: "read",
		Path:   req.Path,
		Offset: offset,
		Length: length,
	})
	if err != nil {
		writeFileError(w, r, err)
		return
	}
	if !result.Success {
		writeFileAppError(w, result.Error)
		return
	}

	resp := FileResponse{Size: int64(len(result.Data))}
	isText := utf8.Valid(result.Data)
	resp.IsText = &isText
	if isText {
		resp.Data = string(result.Data)
	} else {
		resp.DataBase64 = base64.StdEncoding.EncodeToString(result.Data)
	}
	json.NewEncoder(w).Encode(resp)
}

// doWrite handles action=write: accepts text (data) or binary (data_base64).
func (h *FileHandler) doWrite(w http.ResponseWriter, r *http.Request, req FileRequest) {
	var data []byte
	var err error

	switch {
	case req.Data != "" && req.DataBase64 != "":
		writeJSONError(w, "cannot use both data and data_base64", http.StatusBadRequest)
		return
	case req.DataBase64 != "":
		data, err = base64.StdEncoding.DecodeString(req.DataBase64)
		if err != nil {
			writeJSONError(w, "invalid base64 in data_base64", http.StatusBadRequest)
			return
		}
	case req.Data != "":
		data = []byte(req.Data)
	default:
		// Empty write is valid (creates empty file or truncates)
		data = []byte{}
	}

	var offset int64
	if req.Append {
		offset = -1
	} else if req.Offset != nil {
		offset = *req.Offset
	}

	// gate: the write-data wire gate runs inside DoFileOpDirect (the
	// shared direct pipeline) so HTTP and MCP validate identically.

	result, err := h.doFileOp(r, req.SandfsID, pool.FileOpRequest{
		Action: "write",
		Path:   req.Path,
		Offset: offset,
		Mode:   req.Mode,
		Data:   data,
	})
	if err != nil {
		writeFileError(w, r, err)
		return
	}
	if !result.Success {
		writeFileAppError(w, result.Error)
		return
	}

	json.NewEncoder(w).Encode(FileResponse{Ok: true, Size: int64(len(data))})
}

// doStat handles action=stat: returns file metadata as JSON.
func (h *FileHandler) doStat(w http.ResponseWriter, r *http.Request, req FileRequest) {
	result, err := h.doFileOp(r, req.SandfsID, pool.FileOpRequest{
		Action: "stat",
		Path:   req.Path,
	})
	if err != nil {
		writeFileError(w, r, err)
		return
	}
	if !result.Success {
		writeFileAppError(w, result.Error)
		return
	}
	// result.Data is already JSON from warden — pass through.
	w.Write(result.Data)
}

// doListDir handles action=list_dir: returns directory entries as JSON.
func (h *FileHandler) doListDir(w http.ResponseWriter, r *http.Request, req FileRequest) {
	result, err := h.doFileOp(r, req.SandfsID, pool.FileOpRequest{
		Action: "list_dir",
		Path:   req.Path,
		Depth:  req.Depth,
	})
	if err != nil {
		writeFileError(w, r, err)
		return
	}
	if !result.Success {
		writeFileAppError(w, result.Error)
		return
	}
	// Wrap warden's JSON array in {"entries": [...]}.
	json.NewEncoder(w).Encode(map[string]json.RawMessage{
		"entries": json.RawMessage(result.Data),
	})
}

// doMkdir handles action=mkdir.
func (h *FileHandler) doMkdir(w http.ResponseWriter, r *http.Request, req FileRequest) {
	result, err := h.doFileOp(r, req.SandfsID, pool.FileOpRequest{
		Action: "mkdir",
		Path:   req.Path,
		Mode:   req.Mode,
	})
	if err != nil {
		writeFileError(w, r, err)
		return
	}
	if !result.Success {
		writeFileAppError(w, result.Error)
		return
	}
	json.NewEncoder(w).Encode(FileResponse{Ok: true})
}

// doRemove handles action=remove.
func (h *FileHandler) doRemove(w http.ResponseWriter, r *http.Request, req FileRequest) {
	result, err := h.doFileOp(r, req.SandfsID, pool.FileOpRequest{
		Action:    "remove",
		Path:      req.Path,
		Recursive: req.Recursive,
	})
	if err != nil {
		writeFileError(w, r, err)
		return
	}
	if !result.Success {
		writeFileAppError(w, result.Error)
		return
	}
	json.NewEncoder(w).Encode(FileResponse{Ok: true})
}

// doRename handles action=rename.
func (h *FileHandler) doRename(w http.ResponseWriter, r *http.Request, req FileRequest) {
	if req.Path == "" || req.NewPath == "" {
		writeJSONError(w, "missing path or new_path", http.StatusBadRequest)
		return
	}
	result, err := h.doFileOp(r, req.SandfsID, pool.FileOpRequest{
		Action:  "rename",
		Path:    req.Path,
		NewPath: req.NewPath,
	})
	if err != nil {
		writeFileError(w, r, err)
		return
	}
	if !result.Success {
		writeFileAppError(w, result.Error)
		return
	}
	json.NewEncoder(w).Encode(FileResponse{Ok: true})
}

// ── Shared internal flow ───────────────────────────────────────────

// DoFileOpDirect is the direct-call entry point for MCP tool handlers.
// It performs auth + addressing + the file op flow without an HTTP request.
// Exported for MCP server use.
func (h *FileHandler) DoFileOpDirect(ctx context.Context, sandfsID, apiKey string, req pool.FileOpRequest) (pool.FileOpResult, error) {
	// Normalize an omitted/non-positive read length to the single-op cap
	// BEFORE the gate. The warden interprets 0 as "read up to
	// max_file_read_bytes" (16 MiB) — exactly the gRPC message limit — so a
	// default-length read of a large file used to return a payload that
	// breached the node stream's receive limit and reset it (killing every
	// co-tenant in-flight command). The cap leaves the documented 64 KiB
	// envelope headroom.
	if req.Action == "read" && req.Length <= 0 {
		req.Length = int64(maxFileOpDataBytes)
	}
	// wire-size gate — FIRST, before auth and any resource
	// acquisition: it is a pure length check. A payload at/over the gRPC max
	// message size breaches the wire limit on the Send, which CLOSES the node
	// stream and kills every co-tenant in-flight command on that sandlot;
	// prevention is the only fix. Named client-class refusal (4xx): HTTP
	// renders the 413, MCP renders a structured tool error
	// (error_code FILE_TOO_LARGE, retryable:false) via AsNamedClientError.
	if sizeErr := fileOpWireSizeError(req); sizeErr != nil {
		return pool.FileOpResult{}, sizeErr
	}

	identity, err := ResolveFromRequest(h.identityStore, apiKey, sandfsID)
	if err != nil {
		return pool.FileOpResult{}, err
	}

	// Lifecycle gate: a sandfs mid template-swap/deletion refuses file ops
	// (retryable 409) — the volume may be unmounted and, past detach, its
	// rootfs marker is being rewritten. One struct-field compare on the hot
	// path; the store is consulted only when the gate trips (gateActive).
	if err := gateActive(h.identityStore, identity); err != nil {
		return pool.FileOpResult{}, err
	}
	req.AgentID = identity.AgentID

	// Resilience: check sandfsState
	if h.sandfsState != nil && !h.sandfsState.IsAvailable(identity.SandfsID) {
		return pool.FileOpResult{}, &resilienceError{
			code: http.StatusServiceUnavailable, msg: "sandfs is cleaning",
			errorCode: "SANDBOX_CLEANING", retryAfterMs: lease.DefaultRetryAfterMs,
		}
	}

	// Resilience: ownership claim. The claim writes a CANDIDATE PLACEMENT into
	// the ownership record so it never says "unplaced" while a mount could
	// exist (see OwnershipCache.Claim). PeekNode reserves nothing; the real
	// Acquire below may land elsewhere and NoteMounted corrects it then.
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
			// redirect: healthy+routable owner → redirect so the connection converges
			// onto the owner (file ops run on the owner's warm VM, same as exec).
			if err == lease.ErrOwnershipConflict {
				if ownerURL := h.ownership.OwnerGatewayURL(ctx, identity.SandfsID); ownerURL != "" {
					return pool.FileOpResult{}, &OwnerRedirectError{OwnerURL: ownerURL}
				}
			}
			return pool.FileOpResult{}, &resilienceError{
				code: http.StatusServiceUnavailable, msg: err.Error(),
				errorCode: errorCode, retryAfterMs: lease.JitteredRetryAfterMs(lease.RetryAfterMs),
			}
		}
	}

	node := ""
	leaseHit := false

	if n, werr := h.leaseMgr.AcquireWait(identity.SandfsID, lease.MountLockWaitTimeout); werr != nil {
		// An unmount is in progress and didn't finish within the wait
		// timeout. 503 + retry - do NOT fall through to a cold mount on another
		// node (would dual-mount while the unmount is still holding the mount).
		// Mirrors ExecuteDirect; the non-blocking Acquire that was here before let
		// a file op cold-mount on another node during lease-expiry unmount.
		return pool.FileOpResult{}, &resilienceError{
			code: http.StatusServiceUnavailable, msg: "unmount in progress, retry",
			errorCode: "UNMOUNT_IN_PROGRESS", retryAfterMs: 1000,
		}
	} else if n != "" {
		node = n
		leaseHit = true
	}

	// Resilience: MountLock for cold mount (blocking, before node acquire).
	// See execute.go ExecuteDirect for the full rationale: AcquireWait blocks
	// up to MountLockWaitTimeout for an in-progress cold mount, waking immediately
	// on release; 503 + retry_after only on timeout.
	needsColdMount := !leaseHit
	mountLockHeld := false
	var mountToken *lease.MountLockToken
	if needsColdMount && h.mountLock != nil {
		tok, lockErr := h.mountLock.AcquireWaitDefault(identity.SandfsID)
		if lockErr != nil {
			return pool.FileOpResult{}, &resilienceError{
				code: http.StatusServiceUnavailable, msg: "concurrent mount in progress",
				errorCode: "CONCURRENT_MOUNT", retryAfterMs: 1000,
			}
		}
		mountToken = tok
		mountLockHeld = true
		// ONE deferred release for every path out of this function (see
		// execute.go ExecuteDirect): early returns and panics must not strand
		// the per-sandfs token. Release is token-scoped.
		defer func() {
			if mountLockHeld {
				h.mountLock.Release(mountToken)
			}
		}()
		// Re-check lease: holder may have established it while we waited.
		if n, werr := h.leaseMgr.AcquireWait(identity.SandfsID, lease.MountLockWaitTimeout); werr != nil {
			// Unmount in progress - release the lock and 503+retry so
			// the retry blocks at the top AcquireWait until the unmount finishes.
			h.mountLock.Release(mountToken)
			mountLockHeld = false
			return pool.FileOpResult{}, &resilienceError{
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

	// Lifecycle re-check UNDER the cold-mount lock (mirrors ExecuteDirect step
	// 7.6): the gate above ran before any MountLock wait, and the drain does not
	// take that lock — a detach/delete that flipped the record while this
	// request queued must stop the mount here.
	if needsColdMount {
		if err := recheckLifecycleGate(h.identityStore, identity); err != nil {
			return pool.FileOpResult{}, err
		}
	}

	// Coverage re-verification for the cold path (mirrors ExecuteDirect
	// step 7.5): a vanished record must fail HERE instead of
	// landing an uncovered mount; the sweep/shed skip dispatching entries.
	dispatchGen := uint64(0)
	if needsColdMount && h.ownership != nil {
		gen, derr := h.ownership.BeginDispatch(identity.SandfsID)
		if derr != nil {
			return pool.FileOpResult{}, &resilienceError{
				code:         http.StatusServiceUnavailable,
				msg:          "ownership changed during the mount wait, retry",
				errorCode:    "OWNERSHIP_LOST",
				retryAfterMs: lease.JitteredRetryAfterMs(1000),
			}
		}
		dispatchGen = gen
		defer h.ownership.EndDispatch(identity.SandfsID)
	}

	// spec is the floor specID resolved from the sandfs's required vcpus/memory
	// against the chosen node's learned spec table; sent to sandlot as min_spec.
	// Empty on the warm path (VM already bound; min_spec is ignored by sandlot).
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
			h.logger.Error("failed to acquire node for file op", "sandfsID", identity.SandfsID, "error", err)
			// shed (cluster-wide saturation with an idle peer). Mirrors doFileOp
			// and ExecuteDirect so the direct path can also rebalance to a peer.
			if shed := shedColdPath(h.shed, h.ownership, identity.SandfsID); shed != lease.ShedActionNone {
				h.logger.Info("load shed (acquire-fail): saturating sandfs rebalanced to a peer",
					"sandfsID", identity.SandfsID, "shed", shed == lease.ShedActionShed)
				retryMs := h.shed.RetryAfterSec() * 1000
				return pool.FileOpResult{}, &resilienceError{
					code:          http.StatusServiceUnavailable,
					msg:           "gateway saturated, ownership released: reconnect (re-resolve DNS) to reach a peer",
					errorCode:     "SHED_REBALANCE",
					retryAfterMs:  retryMs,
					shedRebalance: true,
				}
			}
			// The PLACEMENT half of "no clean VM anywhere" must carry the
			// same named retryable contract as the node-side half (the
			// errors.Is(ErrNoAvailableSandbox) branch below, and
			// execute.go's acquire fallback): a bare 503 made /agent/file
			// clients stop retrying on a condition that clears in
			// milliseconds.
			if errors.Is(acqErr, pool.ErrNoAvailableSandbox) {
				return pool.FileOpResult{}, &resilienceError{
					code: http.StatusServiceUnavailable, msg: "no available sandbox, retry",
					errorCode: "NO_AVAILABLE_SANDBOX", retryAfterMs: 1000,
				}
			}
			return pool.FileOpResult{}, &fileHTTPError{code: http.StatusServiceUnavailable, msg: err.Error()}
		}
	}

	// ALWAYS carry the record's volume path, warm or cold: it is the identity
	// the node asserts to the warden. Suppressing it on a lease hit made the
	// sandlot derive the identity from the VM's CURRENTLY mounted volume, so
	// a switch between the binding lookup and the warden call could execute
	// this tenant's file op inside the next tenant's volume (the warden
	// confirmed whatever was mounted). One extra ~40-byte proto field on the
	// warm path; no added round trips.
	req.VolumePath = identity.RootFSPath
	req.VolumeEpoch = identity.VolumeEpoch
	req.SandfsID = identity.SandfsID
	req.MinSpec = spec
	// "" for flat records: the node ignores any marker when the record expects
	// no template (the flat rootfs is agent-writable). Overlay records keep the
	// swap-staleness check on the node (cold path only).
	req.TemplateRef = identity.MountTemplateRef()
	// Record-driven mount mode (see ResolvedIdentity.Mode): the warden must
	// never infer flat/overlay from the agent-writable volume layout.
	req.VolumeMode = identity.Mode
	// Bound capacity was reserved atomically inside pool.Acquire (cold mount
	// only — the warm path reuses an already-bound VM counted on the prior cold
	// mount). Corrected to the actual spec on response via AdjustBound, or
	// rolled back via ReleaseBound on failure. Mirrors ExecuteDirect.
	// Bracket the FileOp RPC so the lease is not released while it is in flight.
	h.leaseMgr.BeginExec(identity.SandfsID)
	// defer EndExec + MountLock release so a panic in the RPC / retry loop does
	// not wedge the sandfs's lease (activeExecs > 0 → never unmounts) or leave
	// the MountLock held (blocks all future cold mounts). Both are idempotent.
	defer h.leaseMgr.EndExec(identity.SandfsID)
	// The MountLock release defer was registered at acquisition (see above).
	result, rpcErr := h.sandlotClient.FileOp(ctx, node, req)

	// L1 retry for transport errors
	if rpcErr != nil && IsTransportError(rpcErr) {
		for retry := 0; retry < 2; retry++ {
			time.Sleep(50 * time.Millisecond)
			result, rpcErr = h.sandlotClient.FileOp(ctx, node, req)
			if rpcErr == nil || !IsTransportError(rpcErr) {
				break
			}
		}
	}

	if rpcErr != nil {
		// Release the send-time bound reservation on failure.
		if needsColdMount {
			h.pool.ReleaseBound(node, spec)
		}
		// "no available VM on node" (over-subscription / empty pool) is
		// NOT a mount failure - the sandfs isn't dirty. Retry on another node. With
		// the real-time derived clean count, the over-subscribed node's
		// clean is 0, so the retry's pool.Acquire routes elsewhere. Do NOT
		// EnterCleaning (that would 503-block this sandfs for ~12s needlessly).
		// Mirrors ExecuteDirect.
		if errors.Is(rpcErr, pool.ErrNoAvailableSandbox) {
			// shed (cold-path only): release ownership so the DNS
			// re-routes to an idle peer, and signal the client to reconnect.
			if shed := shedColdPath(h.shed, h.ownership, identity.SandfsID); shed != lease.ShedActionNone {
				h.logger.Info("load shed: saturating sandfs rebalanced to a peer",
					"node", node, "sandfsID", identity.SandfsID, "shed", shed == lease.ShedActionShed)
				retryMs := h.shed.RetryAfterSec() * 1000
				return pool.FileOpResult{}, &resilienceError{
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
			return pool.FileOpResult{}, &resilienceError{
				code: http.StatusServiceUnavailable, msg: "no available sandbox on node, retry",
				errorCode: "NO_AVAILABLE_SANDBOX", retryAfterMs: 1000,
			}
		}
		// Stream-layer transport errors: the command never reached the sandlot,
		// so the sandfs is NOT dirty. Skip EnterCleaning + async unmount (would
		// block ~12s and RPC a dead node); short retry instead.
		if stream.IsStreamTransportError(rpcErr) {
			// Same unconfirmed-dispatch rule as the exec path: the file op
			// may have landed (the mount it joined may be live), so keep the
			// ownership entry orphan-uncertain.
			if dispatchGen != 0 && h.ownership != nil {
				h.ownership.NoteDispatchUnconfirmed(identity.SandfsID)
			}
			h.logger.Warn("stream transport error; mount outcome unconfirmed (no cleanup)", "node", node, "sandfsID", identity.SandfsID, "error", rpcErr)
			return pool.FileOpResult{}, &resilienceError{
				code: http.StatusServiceUnavailable, msg: "node temporarily unreachable, retry",
				errorCode: "NODE_UNAVAILABLE", retryAfterMs: 500,
			}
		}
		h.logger.Error("file_op direct failed", "node", node, "action", req.Action, "error", rpcErr)

		// L2 cleanup: same as the HTTP path — EnterCleaning → async cleanup → 503
		if h.sandfsState != nil {
			h.sandfsState.EnterCleaning(identity.SandfsID)
		}
		go h.cleanupAfterFileFailure(identity.SandfsID, node, identity.RootFSPath, identity.VolumeEpoch)

		return pool.FileOpResult{}, &resilienceError{
			code: http.StatusServiceUnavailable, msg: "file operation failed, sandbox is cleaning",
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
	appliedSpec := result.Spec
	if needsColdMount {
		appliedSpec = h.pool.AdjustBound(node, spec, result.Spec)
		h.leaseMgr.SetSpec(identity.SandfsID, appliedSpec)
	} else if !h.pool.ValidSpec(node, appliedSpec) {
		appliedSpec = h.leaseMgr.SpecOf(identity.SandfsID)
	}

	// Update ownership on successful mount; a stale or cross-node confirmation
	// means this mount lost the race — tear it down and let the client retry.
	if needsColdMount && h.ownership != nil {
		if h.ownership.NoteMountedChecked(identity.SandfsID, node, dispatchGen) {
			abandonConflictingMount(h.sandlotClient, h.pool, h.unmountStats, h.logger,
				identity.SandfsID, node, identity.RootFSPath, identity.VolumeEpoch, appliedSpec)
			return pool.FileOpResult{}, &resilienceError{
				code:         http.StatusServiceUnavailable,
				msg:          "mount conflicted with the ownership record; the duplicate was torn down, retry",
				errorCode:    "MOUNT_CONFLICT",
				retryAfterMs: lease.JitteredRetryAfterMs(1000),
			}
		}
	}
	// Record the cold mount for per-node unmount stats. File-op cold mounts use
	// a placeholder "true" command at the warden level, so the recorded context
	// is the file action (no real command). Post-response, off the warm path.
	if needsColdMount && h.unmountStats != nil {
		h.unmountStats.RecordMount(node, identity.SandfsID, "file:"+req.Action)
	}

	// Mirror ExecuteDirect: TouchSync on BOTH paths, not just the cold one.
	// The warm path must refresh syncStartedAt too — the maxHold reaper bounds
	// a pure-sync lease by time.Since(syncStartedAt) and does NOT consult the
	// continuously refreshed syncStickyUntil, so a file-op-heavy workload whose
	// warm ops never TouchSync would have its VM reaped (unmounted +
	// cold-remounted, with the unmount's drop_caches) once per maxHold window
	// despite active traffic. The spec rides along so a newly created lease
	// entry carries the bound's bucket from birth (SetSpec above no-ops when
	// the entry does not exist yet — see TouchSync) — always the validated
	// appliedSpec, never the raw node report.
	h.leaseMgr.TouchSync(identity.SandfsID, node, appliedSpec)
	h.leaseMgr.SetVolumePath(identity.SandfsID, identity.RootFSPath)
	h.leaseMgr.SetVolumeEpoch(identity.SandfsID, identity.VolumeEpoch)

	return result, nil
}

// doFileOp is the unified internal flow for all file operations:
// auth → the shared DoFileOpDirect pipeline → return result.
//
// The entire post-auth flow (sandfsState → ownership → lease → mountLock →
// acquire → FileOp RPC → L1 retry → L2 cleanup) lives ONCE in DoFileOpDirect,
// which the MCP tool handlers also call — HTTP and MCP behavior stay identical
// by construction instead of by mirrored edits (this file previously carried a
// ~250-line copy of the direct path).
func (h *FileHandler) doFileOp(r *http.Request, sandfsID string, req pool.FileOpRequest) (pool.FileOpResult, error) {
	// 1. Connection-level auth (the direct path re-resolves the agent + address
	// and verifies sandfs ownership).
	apiKey, err := identity.ExtractAPIKey(r)
	if err != nil {
		return pool.FileOpResult{}, &fileHTTPError{code: http.StatusUnauthorized, msg: "missing api key"}
	}
	return h.DoFileOpDirect(r.Context(), sandfsID, apiKey, req)
}

// cleanupAfterFileFailure performs L2 cleanup after a file op failure.
// TODO(batch-unmount): see ExecuteHandler.cleanupAfterFailure.
func (h *FileHandler) cleanupAfterFileFailure(sandfsID, node, volumePath, volumeEpoch string) {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	// defer ExitCleaning so a panic or stuck UnmountRootfs does not leave the
	// sandfs in stateCleaning forever (every future request 503). Idempotent.
	if h.sandfsState != nil {
		defer h.sandfsState.ExitCleaning(sandfsID)
	}

	unmountCtx, unmountCancel := context.WithTimeout(ctx, 8*time.Second)
	res, err := h.sandlotClient.UnmountRootfs(unmountCtx, node, sandfsID, volumePath, volumeEpoch)
	if err != nil {
		h.logger.Warn("cleanup: unmount failed; will retry with backoff (ownership kept)", "sandfsID", sandfsID, "node", node, "error", err)
	}
	unmountCancel()
	if h.unmountStats != nil {
		h.unmountStats.RecordUnmount(node, sandfsID, "cleanup-after-file-failure", res, err == nil)
	}
	if err != nil {
		// Success-gated ownership release — see ExecuteHandler.cleanupAfterFailure.
		// Keep the entry orphan-uncertain while the mount may still be live.
		if h.ownership != nil {
			h.ownership.NoteDispatchUnconfirmed(sandfsID)
		}
		h.leaseMgr.RetryUnmount(sandfsID, node, h.leaseMgr.SpecOf(sandfsID))
		return
	}

	if h.ownership != nil {
		// Release ownership entirely after L2 cleanup (same rationale as
		// ExecuteHandler.cleanupAfterFailure).
		h.ownership.ReleaseOwnership(sandfsID)
	}

	// ExitCleaning runs via the deferred call at the top of this goroutine.
}

// fileHTTPError is a sentinel for HTTP error responses in doFileOp.
type fileHTTPError struct {
	code int
	msg  string
	// errorCode is the stable machine-readable name of a client-class refusal
	// (currently the wire-size gate) that the MCP transport projects
	// into a structured tool error. Empty = plain HTTP-shaped error, rendered
	// by the MCP layer as free text exactly as before.
	errorCode string
}

func (e *fileHTTPError) Error() string { return e.msg }

// AsNamedClientError extracts a named client-class refusal (4xx) from the
// shared handler error types: the message, the HTTP status the HTTP transport
// renders, and the stable error_code the MCP transport projects into a
// structured isError tool result (error_code + retryable:false) instead of a
// free-text blob. ok=false for errors without a stable name — they keep their
// existing rendering.
func AsNamedClientError(err error) (msg string, httpStatus int, errorCode string, ok bool) {
	switch e := err.(type) {
	case *fileHTTPError:
		if e.errorCode != "" {
			return e.msg, e.code, e.errorCode, true
		}
	case *execHTTPError:
		if e.errorCode != "" {
			return e.msg, e.code, e.errorCode, true
		}
	}
	return "", 0, "", false
}

func writeFileError(w http.ResponseWriter, r *http.Request, err error) {
	// redirect: ownership conflict + healthy owner → 307 to the owner gateway.
	if ownerURL, ok := IsOwnerRedirect(err); ok {
		if !writeOwnerRedirect(w, r, ownerURL) {
			writeJSONError(w, "ownership conflict", http.StatusServiceUnavailable)
		}
		return
	}
	// Auth/addressing failures from the shared direct pipeline (invalid api key,
	// sandfs not found, ownership mismatch) carry their HTTP code directly.
	if he, ok := err.(*authHTTPError); ok {
		writeJSONError(w, he.msg, he.code)
		return
	}
	if he, ok := err.(*fileHTTPError); ok {
		writeJSONError(w, he.msg, he.code)
		return
	}
	if _, ok := err.(*resilienceError); ok {
		writeResilienceError(w, err)
		return
	}
	writeJSONError(w, err.Error(), http.StatusInternalServerError)
}

// writeFileAppError writes an application-level file op error (e.g., file not
// found, permission denied) as HTTP 400 with the error message from the warden.
// Unlike writeFileError, this does NOT release the VM — the VM is still healthy,
// only the file operation failed. The error message comes from the warden's
// CODE_APP_ERROR response (carried in FileOpResult.Error).
func writeFileAppError(w http.ResponseWriter, errMsg string) {
	msg := errMsg
	if msg == "" {
		msg = "file operation failed"
	}
	writeJSONError(w, msg, http.StatusBadRequest)
}

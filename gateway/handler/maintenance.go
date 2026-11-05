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
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"gateway/maintenance"
	"gateway/registry"
	"gateway/storage"
)

// handleMaintenance implements POST /human/maintenance — the runtime
// service-refusal switch used by the volume-seed rotation window (and any
// future operation that must not overlap agent work).
//
// Body: {"on": true|false, "reason": "..."} — idempotent. The response echoes
// the resulting state. In split deployments the state is ALSO published to the
// fleet key (maintenance.Key) that the exec gateways watch; in single-node
// mode the local switch is the whole story (the agent listener is in this
// process).
//
// No restart: the switch is an atomic read on the agent request path. A
// gateway restart clears the LOCAL switch, which is why the fleet key is
// authoritative where etcd exists — a restart mid-window comes back still
// refusing.
func (h *HumanHandler) handleMaintenance(w http.ResponseWriter, r *http.Request) {
	if !requireOpsScope(w, r) {
		return
	}
	if h.maintenance == nil {
		writeJSONError(w, "maintenance switch not wired in this mode", http.StatusNotImplemented)
		return
	}
	var req struct {
		On     *bool  `json:"on"`
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeJSONError(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if req.On == nil {
		writeJSONError(w, `field "on" is required (true = refuse agent service, false = resume)`, http.StatusBadRequest)
		return
	}
	on := *req.On
	reason := strings.TrimSpace(req.Reason)
	if on && reason == "" {
		reason = "planned maintenance"
	}
	if !on {
		reason = ""
	}

	// Publish to the fleet key FIRST: a local 503 that the other exec gateways
	// never learn about would leave agent traffic flowing to the nodes while
	// the rotation moves directories.
	if h.etcdClient != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		if on {
			if _, err := h.etcdClient.Put(ctx, maintenance.Key, reason); err != nil {
				writeJSONError(w, fmt.Sprintf("publish maintenance key: %v (NOT entered — nothing changed)", err), http.StatusServiceUnavailable)
				return
			}
		} else {
			if _, err := h.etcdClient.Delete(ctx, maintenance.Key); err != nil {
				writeJSONError(w, fmt.Sprintf("clear maintenance key: %v (still refusing)", err), http.StatusServiceUnavailable)
				return
			}
		}
	}
	h.maintenance.Set(on, reason)
	h.logger.Warn("maintenance switch changed", "refusing_agent_traffic", on, "reason", reason)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"refusing": on,
		"reason":   reason,
	})
}

// handleRotation implements POST /human/rotation — the rotation-window switch.
//
// While it is ON, creating a SandFS is refused fleet-wide. That closes the
// window's last hole: the per-instance freeze (`ErrRotationStaged`) only
// applies on prov instances that are THEMSELVES staged, so a create arriving
// at an instance whose source has not been materialized yet would still land a
// volume named in the generation the rotation is retiring — and `--run` would
// have to chase it. A flag the operator turns on with the window and off at the
// end (after the convergence check) makes the freeze a fleet property.
//
// Body and semantics mirror /human/maintenance, including the fleet-key publish
// FIRST (maintenance.RotationKey) so a restart mid-window comes back still
// frozen.
func (h *HumanHandler) handleRotation(w http.ResponseWriter, r *http.Request) {
	if !requireOpsScope(w, r) {
		return
	}
	if h.rotation == nil {
		writeJSONError(w, "rotation switch not wired in this mode", http.StatusNotImplemented)
		return
	}
	var req struct {
		On     *bool  `json:"on"`
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeJSONError(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if req.On == nil {
		writeJSONError(w, `field "on" is required (true = freeze sandfs creation, false = resume)`, http.StatusBadRequest)
		return
	}
	on := *req.On
	reason := strings.TrimSpace(req.Reason)
	if on && reason == "" {
		reason = "volume-seed rotation"
	}
	if !on {
		reason = ""
	}
	if h.etcdClient != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		if on {
			if _, err := h.etcdClient.Put(ctx, maintenance.RotationKey, reason); err != nil {
				writeJSONError(w, fmt.Sprintf("publish rotation key: %v (NOT entered — nothing changed)", err), http.StatusServiceUnavailable)
				return
			}
		} else {
			if _, err := h.etcdClient.Delete(ctx, maintenance.RotationKey); err != nil {
				writeJSONError(w, fmt.Sprintf("clear rotation key: %v (still frozen)", err), http.StatusServiceUnavailable)
				return
			}
		}
	}
	h.rotation.Set(on, reason)
	h.logger.Warn("rotation window switch changed", "freezing_creation", on, "reason", reason)
	w.Header().Set("Content-Type", "application/json")
	// Same field name /stats projects (MaintenanceState.refusing): for this
	// switch "refusing" means "refusing to create a sandfs".
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"refusing": on,
		"reason":   reason,
	})
}

// rotationRefusal writes the named refusal when the rotation window is open.
// It returns true when the caller must stop (the response is already written).
func (h *HumanHandler) rotationRefusal(w http.ResponseWriter, what string) bool {
	if h.rotation == nil || !h.rotation.On() {
		return false
	}
	_, reason := h.rotation.Snapshot()
	if reason == "" {
		reason = "volume-seed rotation"
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Retry-After", "60")
	w.WriteHeader(http.StatusServiceUnavailable)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":      fmt.Sprintf("%s is refused while a volume-seed rotation window is open (%s): a volume created now would be named in the generation that is being retired", what, reason),
		"error_code": "ROTATION_IN_PROGRESS",
	})
	return true
}

// handleSetRootFSPath implements
// POST /human/sandfs/{id}/rootfs-path {"rootfs_path": "..."}.
//
// It exists for operations that MOVE a volume directory: the volume-name seed
// rotation (see sandlot/provision/volname) renames every directory and then
// must tell the control plane where it landed. The path is validated against
// the volumes root exactly like a path coming back from the storage plane —
// this endpoint must never become a way to point a mount at an arbitrary host
// directory.
func (h *HumanHandler) handleSetRootFSPath(w http.ResponseWriter, r *http.Request, sandfsID string) {
	if !requireOpsScope(w, r) {
		return
	}
	var req struct {
		RootFSPath string `json:"rootfs_path"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&req); err != nil {
		writeJSONError(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	path := strings.TrimSpace(req.RootFSPath)
	if err := registry.ValidateVolumePath(h.registry.VolRoot(), path); err != nil {
		writeJSONError(w, err.Error(), http.StatusBadRequest)
		return
	}
	rec, err := h.identityStore.GetSandFS(sandfsID)
	if err != nil || rec == nil {
		writeJSONError(w, "sandfs not found", http.StatusNotFound)
		return
	}
	// the shape check above only proves the path LOOKS like a volume
	// location under the volumes root — it cannot tell whether the directory
	// IS this sandfs's volume. The proof (the .sandfs-id stamp) lives on the
	// storage plane, where the seed that derives names is available: verify
	// READ-ONLY through a prov command and refuse an unproven repoint. The
	// endpoint exists precisely because a rotation MOVES a volume, so
	// verification is part of its contract, not an obstacle to it.
	ops := h.storageOps()
	if ops == nil {
		h.writeStorageErr(w, storage.ErrNoProvisioner, "set rootfs_path")
		return
	}
	if err := ops.VerifyVolume(r.Context(), sandfsID, path); err != nil {
		h.writeStorageErr(w, err, "set rootfs_path")
		return
	}
	if err := h.identityStore.SetRootFSPath(sandfsID, path); err != nil {
		h.writeStorageErr(w, err, "set rootfs_path")
		return
	}
	h.logger.Warn("rootfs_path updated", "sandfsID", sandfsID, "from", rec.RootFSPath, "to", path)
	w.WriteHeader(http.StatusNoContent)
}

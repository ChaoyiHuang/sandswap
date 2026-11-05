// Copyright 2026 Chaoyi Huang. All rights reserved.
//
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE file at the root of this repository.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, sandswap's use of this software will be governed
// by the Apache License, Version 2.0.

package app

import (
	"context"
	"log/slog"
	"time"

	"gateway/identity"
	"gateway/lease"
	"gateway/pool"
)

// execDrainBudget bounds one exec-side lifecycle drain. Generous versus the
// human-side default wait (15s): the drain is async here (the human gateway
// polls the record), so the budget only needs to outlast the slowest normal
// case — in-flight sync execs waiting out the node-side mount gate.
const execDrainBudget = 60 * time.Second

// drainLifecycleSandfs is the exec-gateway half of the split-mode lifecycle
// orchestration (template detach + sandfs delete): a record flipped to
// "detaching"/"deleting" names a sandfs whose mounts must go. This gateway
// acts ONLY if it holds the sandfs — a warm lease entry, or the etcd
// ownership record naming us (the mount holder may hold no lease entry only
// through a lost-lease edge; ownership is the authoritative second opinion).
// Non-holders stay silent: exactly one holder exists per sandfs (the
// exclusive-ownership invariant), and a no-holder case is settled by the
// human gateway's no-owner escape.
//
// Idempotent end to end: repeated triggers (watch echo, operator re-issue,
// NotifyInitialStatuses) re-run a drain that is at worst a no-op sweep, and
// the settle write is a plain status put.
func drainLifecycleSandfs(pm *pool.Manager, lm *lease.Lease, store *identity.EtcdStore, gatewayID, sandfsID string, logger *slog.Logger) {
	if pm == nil || lm == nil || store == nil {
		return
	}
	if !lm.HasEntry(sandfsID) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		owner, err := lease.LookupOwnerGatewayID(ctx, store.Client(), sandfsID)
		cancel()
		if err != nil || owner != gatewayID {
			// Not ours (or nobody's): the human gateway's no-owner escape or
			// the owner's own watch handles it.
			return
		}
	}
	rec, err := store.GetSandFS(sandfsID)
	if err != nil {
		logger.Warn("lifecycle drain: record vanished", "sandfsID", sandfsID, "error", err)
		return
	}
	// Re-check under the record: the status may have settled (or flipped back
	// to active via an attach) between the trigger and now.
	if rec.Status != identity.SandfsStatusDetaching && rec.Status != identity.SandfsStatusDeleting {
		return
	}

	drainer := &lease.Drainer{Pool: pm, Lease: lm, Logger: logger}
	if drainer.Drain(sandfsID, rec.RootFSPath, rec.VolumeEpoch, execDrainBudget) {
		// Release the ownership key BEFORE publishing the settle: this gateway
		// is the owner (a live lease entry, or the record naming us), and the
		// human gateway's own release in a split deployment is a
		// foreign-refusal no-op. Without this release the plain key outlives the
		// deleted/torn-down sandfs and 307-routes a later sandfs that reuses
		// the id to a gateway that no longer knows it. The helper refuses a
		// record that names another gateway (a takeover during the drain).
		relCtx, relCancel := context.WithTimeout(context.Background(), 10*time.Second)
		if rerr := lease.ReleaseOwnershipIfOwner(relCtx, store.Client(), sandfsID, gatewayID); rerr != nil {
			// The settle write still proceeds: the mounts ARE released, and the
			// human gateway's delete teardown surfaces the orphaned key (it
			// waits for the key to disappear before answering 204).
			logger.Error("lifecycle drain: ownership release failed after settle (orphaned etcd key — reclaim via reap-stuck)",
				"sandfsID", sandfsID, "error", rerr)
		}
		relCancel()

		// Settle with a status CAS: a concurrent delete may have overridden the
		// detach trigger (delete wins), and an attach can only complete from
		// detached — a blind write would resurrect a detached status over the
		// transition that owns the record now.
		applied, current, cerr := store.CompareAndSetSandfsStatus(sandfsID, rec.Status, identity.SandfsStatusDetached)
		if cerr != nil {
			logger.Error("lifecycle drain: settle write failed (human gateway will keep polling; re-issue resumes)",
				"sandfsID", sandfsID, "error", cerr)
			return
		}
		if !applied && current != identity.SandfsStatusDetached {
			logger.Info("lifecycle drain: record moved on before the settle write; leaving it to the current transition",
				"sandfsID", sandfsID, "status", current)
		}
		return
	}
	// Deadline: status stays at the trigger; the human gateway reports 202 and
	// the operator re-issues (the lease retry chain continues meanwhile).
}

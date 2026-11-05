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

package maintenance

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
)

// Key is the fleet-wide maintenance key. It is a PLAIN key with no lease
// (like the ownership and health keys): it persists until ops explicitly
// clears it, so a gateway that restarts mid-window comes back still refusing —
// which is what a rotation needs (a restart must not silently resume service
// while volume directories are moving).
const Key = "/sandswap/maintenance"

// RotationKey is the fleet-wide rotation-window key. Same plain-key semantics
// as Key (no lease: a gateway restarting mid-window comes back still frozen),
// but a DIFFERENT switch on purpose: the rotation window freezes SandFS
// CREATION fleet-wide (a volume created mid-window would be named in the
// generation being retired), while maintenance refuses agent traffic during
// any service window — including ones that have nothing to do with a rotation.
const RotationKey = "/sandswap/rotation"

// ParseKey reports the switch state for a key read/watched value. An absent
// key (found == false) means "serving"; a present key means "refusing", with
// its value as the reason.
func ParseKey(found bool, value string) (on bool, reason string) {
	if !found {
		return false, ""
	}
	return true, value
}

// WatchKey mirrors Key into sw for the lifetime of ctx: it reads the current
// value, then watches for changes, re-establishing the watch with backoff if
// etcd drops. Split deployments need this: the rotation window is opened
// through the HUMAN gateway, but the traffic to refuse arrives at the EXEC
// gateways, which are different processes (and hosts).
//
// A watch error is logged and retried — never fatal: failing to observe a
// maintenance flip must not take a working gateway down.
func WatchKey(ctx context.Context, cli *clientv3.Client, logger *slog.Logger, sw *Switch) {
	WatchKeyFor(ctx, cli, logger, sw, Key, "maintenance")
}

// switchReadTimeout bounds one state read. A package variable only so the
// fail-closed test does not have to wait out the production value.
var switchReadTimeout = 5 * time.Second

// WatchKeyFor is WatchKey for any of the fleet switches (maintenance.Key,
// RotationKey). The log lines carry label so an operator can tell WHICH switch
// flipped.
func WatchKeyFor(ctx context.Context, cli *clientv3.Client, logger *slog.Logger, sw *Switch, key, label string) {
	if cli == nil {
		return
	}
	apply := func(resp *clientv3.GetResponse) {
		if resp.Count == 0 {
			sw.Set(false, "")
			return
		}
		sw.Set(ParseKey(true, string(resp.Kvs[0].Value)))
	}
	// Until one read succeeds the switch fails CLOSED: Watch without a revision
	// does not replay a key written before the watch started, so "assume off"
	// would serve through an already-open maintenance/rotation window until ops
	// rewrites the key. A failed read therefore turns the switch ON with a named
	// reason; the first successful read applies the real state.
	readOK := false
	for ctx.Err() == nil {
		// Bound each read: an unreachable etcd must not park the switch loop
		// (and the fail-closed state behind it) on a single Get.
		readCtx, readCancel := context.WithTimeout(ctx, switchReadTimeout)
		resp, err := cli.Get(readCtx, key)
		readCancel()
		if err != nil {
			if !readOK {
				sw.Set(true, fmt.Sprintf("state unknown: initial read failed: %v", err))
				if logger != nil {
					logger.Warn(label+": initial read failed; refusing until the switch state is readable", "error", err)
				}
			} else if logger != nil {
				logger.Warn(label+": state read failed; keeping the last known switch state", "error", err)
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second):
			}
			continue
		}
		readOK = true
		apply(resp)
		// Watch from the revision AFTER the one just read: a flip between the
		// read and the watch is replayed by etcd, so no state change is missed.
		wch := cli.Watch(ctx, key, clientv3.WithRev(resp.Header.Revision+1))
		for wresp := range wch {
			if wresp.Canceled {
				break
			}
			if err := wresp.Err(); err != nil {
				if logger != nil {
					logger.Warn(label+": watch error", "error", err)
				}
				break
			}
			for _, ev := range wresp.Events {
				on, reason := ParseKey(true, string(ev.Kv.Value))
				if ev.Type == clientv3.EventTypeDelete {
					on, reason = ParseKey(false, "")
				}
				if on != sw.On() && logger != nil {
					logger.Warn(label+": fleet switch changed", "on", on, "reason", reason)
				}
				sw.Set(on, reason)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second):
		}
	}
}

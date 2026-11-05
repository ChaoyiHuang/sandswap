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

package app

import (
	"sort"
	"time"

	"gateway/handler"
	"gateway/stream"
)

// provSeedStates projects the stream server's per-node naming-generation
// reports into the /stats shape. Only nodes that reported one appear (prov-role
// instances), and each carries the AGE of its report: a stale entry means the
// instance stopped reporting, so its generation must not be read as evidence
// that the fleet converged.
func provSeedStates(srv *stream.Server) []handler.ProvSeedState {
	if srv == nil {
		return nil
	}
	reports := srv.NodeSeedReports()
	if len(reports) == 0 {
		return nil
	}
	now := time.Now().Unix()
	out := make([]handler.ProvSeedState, 0, len(reports))
	for _, r := range reports {
		var age int64
		if r.UpdatedUnix > 0 {
			age = now - r.UpdatedUnix
		}
		out = append(out, handler.ProvSeedState{
			NodeID:           r.NodeID,
			Generation:       r.Generation,
			Staged:           r.Staged,
			StagedGeneration: r.StagedGeneration,
			AgeSec:           age,
		})
	}
	return out
}

// egressBindingStates projects each connected node's egress identity-binding
// mode into /stats, sorted by node id so the output is stable for tooling.
func egressBindingStates(srv *stream.Server) []handler.EgressBindingState {
	if srv == nil {
		return nil
	}
	modes := srv.NodeEgressBindings()
	if len(modes) == 0 {
		return nil
	}
	ids := make([]string, 0, len(modes))
	for id := range modes {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]handler.EgressBindingState, 0, len(ids))
	for _, id := range ids {
		out = append(out, handler.EgressBindingState{NodeID: id, Binding: modes[id]})
	}
	return out
}

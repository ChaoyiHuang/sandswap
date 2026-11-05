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

// Package maintenance is the gateway's service-refusal switch: a runtime,
// restart-free way to stop answering AGENT traffic while the control plane
// (human API, stream, DNS) keeps running.
//
// It exists for operations that must not run concurrently with agent work —
// the volume-name seed rotation being the first (docs/operations/storage.md
// and deploy/baremetal/rotate-volume-seed.sh): during the window, volume
// directories are being renamed, so a mount that raced the rotation would
// address a name that is about to move.
//
// Why refuse instead of restarting the gateway: the exec gateway also holds
// the node streams, the pool state and the lease table; a restart drops all of
// them (nodes reconnect, pools re-warm, in-flight execs are lost). Refusing
// agent requests is a ~100 ns check on the request path and leaves every other
// subsystem untouched.
//
// Scope: only the AGENT listener is gated. /health and /ready keep answering
// (an orchestrator must still see the process as alive), and /stats reports
// the state so tooling can poll it.
package maintenance

import (
	"encoding/json"
	"net/http"
	"sync/atomic"
)

// RetryAfterSeconds is advertised on every refused request: the rotation
// window is minutes, not seconds, and a client that retries too eagerly just
// multiplies 503s.
const RetryAfterSeconds = 30

// Switch is the module-level toggle. The zero value is "serving".
type Switch struct {
	on     atomic.Bool
	reason atomic.Pointer[string]
}

// Set flips the switch. reason is shown to refused callers (it is not
// sensitive; keep it short and operational).
func (s *Switch) Set(on bool, reason string) {
	s.reason.Store(&reason)
	s.on.Store(on)
}

// On reports whether the gateway is refusing agent traffic.
func (s *Switch) On() bool { return s.on.Load() }

// Snapshot returns the state and the reason ("" when serving).
func (s *Switch) Snapshot() (bool, string) {
	if !s.on.Load() {
		return false, ""
	}
	if r := s.reason.Load(); r != nil {
		return true, *r
	}
	return true, ""
}

// Middleware wraps an agent-facing handler. Requests other than the liveness
// endpoints are answered 503 with Retry-After while the switch is on.
func (s *Switch) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Liveness/readiness stay open: a refused gateway is still a healthy
		// process, and orchestration must not restart it during the window.
		// Observability stays open too — /stats and /metrics ride the AGENT
		// listener in exec mode, and the rotation tooling polls /stats to watch
		// the drain; refusing them would blind the very operation that opened
		// the window.
		switch r.URL.Path {
		case "/health", "/ready", "/stats", "/metrics":
			next.ServeHTTP(w, r)
			return
		}
		if !s.on.Load() {
			next.ServeHTTP(w, r)
			return
		}
		_, reason := s.Snapshot()
		if reason == "" {
			reason = "gateway maintenance"
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Retry-After", itoa(RetryAfterSeconds))
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":      "gateway is not serving agent requests: " + reason,
			"error_code": "MAINTENANCE",
		})
	})
}

// itoa avoids pulling strconv into a hot path file for one conversion.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

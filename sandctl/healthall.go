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
	"fmt"
	"io"
	"os"
)

// cmdHealthAll probes /health and /ready on the agent and human listeners.
// It is a pure HTTP client command: no local workspace state and no
// credentials, so it works unchanged against any deployment the client
// contract (or explicit flags) points at.
//
// The exit code is the gate: every probe must answer with a transport
// success below 400, or the command fails — deployment checks and scripts
// pipe this directly.
func cmdHealthAll(g Global, args []string) {
	fs := newFlagSet("health-all")
	fs.Parse(args)

	failed, total := probeListeners(g, os.Stdout)
	if failed > 0 {
		fmt.Fprintf(os.Stderr, "health-all: %d of %d probes failed\n", failed, total)
		os.Exit(1)
	}
}

// probeListeners probes /health and /ready on both listeners, printing one
// line per probe, and returns how many probes failed (transport error or an
// HTTP status >= 400 — /health and /ready answer 200 on a healthy stack) out
// of the total. A warming-up gateway answering 503 on /ready fails here by
// design: /ready is the strict signal (docs/deployment/install-kubernetes.md).
func probeListeners(g Global, w io.Writer) (failed, total int) {
	probe := func(name, url, path string) {
		total++
		_, s, err := g.request(url, "GET", path, nil, "", nil)
		switch {
		case err != nil:
			fmt.Fprintf(w, "%-10s %-40s FAIL (%v)\n", name, url+path, err)
			failed++
		case s >= 400:
			fmt.Fprintf(w, "%-10s %-40s FAIL (HTTP %d)\n", name, url+path, s)
			failed++
		default:
			fmt.Fprintf(w, "%-10s %-40s HTTP %d\n", name, url+path, s)
		}
	}
	probe("gateway", g.GatewayURL, "/health")
	probe("gateway", g.GatewayURL, "/ready")
	probe("human", g.HumanURL, "/health")
	probe("human", g.HumanURL, "/ready")
	return failed, total
}

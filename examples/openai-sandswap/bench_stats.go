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

// Shared benchmarking plumbing for the two Sandswap latency benchmark modes
// (SANDSWAP_BENCH_MODE=http|mcp). Both read the gateway's own metrics
// (gateway_duration_ns / sandlot_duration_ns / exec_duration_ns) straight
// from the API response — the designated replacement for the deleted
// log-scraping e2e latency benchmarks.

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strconv"
	"time"
)

// benchConfig holds benchmark parameters, all from the environment.
// Env vars follow the example's style: GATEWAY_URL, SANDSWAP_API_KEY_A/_B,
// SANDSWAP_SANDFS_A/_B, WARM_N, COLD_N, SWITCH_GAP_MS, N_LLM, BENCH_VERBOSE.
type benchConfig struct {
	gatewayURL     string // HTTP agent API base (POST /agent/execute)
	mcpURL         string // MCP Streamable HTTP endpoint (POST .../mcp)
	apiKeyA        string
	apiKeyB        string
	sandfsA        string // required: sandfs instance id (discover via list_sandfs / GET /agent/sandfs)
	sandfsB        string
	warmN          int // back-to-back same-agent calls (sticky lease hit)
	coldN          int // cross-agent alternating rounds (lease expiry → cold mount)
	warmGapMS      int // sleep between warm calls (≪ sticky window, keeps them warm)
	switchGapMS    int // sleep between cold calls; must exceed sticky-ms (default 300)
	switchSettleMS int // sleep after the warm phase, before the first switch call
	nLLM           int // MCP mode only: LLM round-trip samples
	verbose        bool
}

func loadBenchConfig() benchConfig {
	cfg := benchConfig{
		gatewayURL:     getenv("GATEWAY_URL", "http://localhost:3000"),
		apiKeyA:        os.Getenv("SANDSWAP_API_KEY_A"),
		apiKeyB:        os.Getenv("SANDSWAP_API_KEY_B"),
		sandfsA:        os.Getenv("SANDSWAP_SANDFS_A"),
		sandfsB:        os.Getenv("SANDSWAP_SANDFS_B"),
		warmN:          atoiDefault("WARM_N", 30),
		coldN:          atoiDefault("COLD_N", 20),
		warmGapMS:      atoiDefault("WARM_GAP_MS", 5),
		switchGapMS:    atoiDefault("SWITCH_GAP_MS", 300),
		switchSettleMS: atoiDefault("SWITCH_SETTLE_MS", 1000),
		nLLM:           atoiDefault("N_LLM", 5),
		verbose:        os.Getenv("BENCH_VERBOSE") == "1",
	}
	cfg.mcpURL = os.Getenv("SANDSWAP_MCP_URL")
	if cfg.mcpURL == "" {
		cfg.mcpURL = cfg.gatewayURL + "/mcp"
	}
	return cfg
}

// execSample is the per-call timing breakdown for one execute invocation.
// clientMs is the client-observed round trip (HTTP mode: T_http; MCP mode:
// T_mcp); the other three come from the gateway's own measurements.
type execSample struct {
	clientMs  float64 // client-observed wall time (request sent → response received)
	gatewayMs float64 // gateway_duration_ns → ms (gateway E2E, server-side)
	sandlotMs float64 // sandlot_duration_ns → ms (sandlot dispatch→response, incl. vsock RT)
	execMs    float64 // exec_duration_ns → ms (warden share: spawn→wait warm / mount+exec cold)
	warm      bool    // lease hit: HTTP = X-Sandbox-Lease header; MCP = sampling pattern
	exit      int
}

type stats struct {
	n                  int
	min, p50, p95, max float64
}

// computeStats: min/P50/P95/max with
// the same percentile indexing (p50 = sorted[n/2], p95 = sorted[n*95/100]).
func computeStats(vals []float64) stats {
	n := len(vals)
	if n == 0 {
		return stats{}
	}
	sorted := append([]float64(nil), vals...)
	sort.Float64s(sorted)
	p95Idx := n * 95 / 100
	if p95Idx >= n {
		p95Idx = n - 1
	}
	return stats{
		n:   n,
		min: sorted[0],
		p50: sorted[n/2],
		p95: sorted[p95Idx],
		max: sorted[n-1],
	}
}

func (st stats) String() string {
	return fmt.Sprintf("n=%d min=%.3f P50=%.3f P95=%.3f max=%.3f", st.n, st.min, st.p50, st.p95, st.max)
}

// fieldMs extracts one metric column from a sample set.
func fieldMs(samples []execSample, f func(execSample) float64) []float64 {
	out := make([]float64, 0, len(samples))
	for _, s := range samples {
		out = append(out, f(s))
	}
	return out
}

// benchQualityGate — a benchmark over no (or almost no) successful samples is
// a FAILURE, not a green run with "(no samples)" tables: a system whose exec
// path is broken (every call 5xx / transport error) used to exit 0 here and
// CI read the empty tables as a pass. Requires ≥90% of a phase's requested
// samples to have succeeded, and at least one non-zero measurement among them
// (an all-zero distribution means the duration fields are missing from the
// response — instrumentation drift, not speed).
func benchQualityGate(phase string, got, want int, samples []execSample) error {
	if want <= 0 {
		return nil
	}
	min := want * 9 / 10
	if min < 1 {
		min = 1
	}
	if got < min {
		return fmt.Errorf("quality gate [%s]: only %d/%d samples succeeded (want ≥%d) — the exec path is broken; latency numbers would be meaningless", phase, got, want, min)
	}
	nz := 0
	for _, s := range samples {
		if s.clientMs > 0 || s.gatewayMs > 0 {
			nz++
		}
	}
	if nz == 0 {
		return fmt.Errorf("quality gate [%s]: all %d samples have zero duration — response duration fields missing?", phase, got)
	}
	return nil
}

// printMetricTable prints one class's latency table (all values in ms).
func printMetricTable(title string, samples []execSample) {
	fmt.Printf("\n%s\n", title)
	if len(samples) == 0 {
		fmt.Println("  (no samples)")
		return
	}
	fmt.Printf("  %-20s %9s %9s %9s %9s\n", "metric", "min", "P50", "P95", "max")
	rows := []struct {
		name string
		vals []float64
	}{
		{"client round-trip", fieldMs(samples, func(s execSample) float64 { return s.clientMs })},
		{"gateway E2E", fieldMs(samples, func(s execSample) float64 { return s.gatewayMs })},
		{"sandlot", fieldMs(samples, func(s execSample) float64 { return s.sandlotMs })},
		{"exec", fieldMs(samples, func(s execSample) float64 { return s.execMs })},
	}
	for _, r := range rows {
		st := computeStats(r.vals)
		fmt.Printf("  %-20s %9.3f %9.3f %9.3f %9.3f\n", r.name, st.min, st.p50, st.p95, st.max)
	}
}

func printLLMStats(title string, llmMs []float64) {
	if len(llmMs) == 0 {
		fmt.Printf("\n%s: (no samples)\n", title)
		return
	}
	fmt.Printf("\n%s: %s ms\n", title, computeStats(llmMs).String())
}

// printVerbose prints every sample in a flat table (BENCH_VERBOSE=1).
func printVerbose(samples []execSample) {
	fmt.Println("\n  per-sample detail (all in ms):")
	fmt.Printf("  %4s  %-6s %10s %9s %9s %8s %5s\n", "idx", "class", "client", "gateway", "sandlot", "exec", "exit")
	for i, s := range samples {
		class := "cold"
		if s.warm {
			class = "warm"
		}
		fmt.Printf("  %4d  %-6s %10.3f %9.3f %9.3f %8.3f %5d\n", i+1, class, s.clientMs, s.gatewayMs, s.sandlotMs, s.execMs, s.exit)
	}
}

// benchMode returns the configured benchmark mode, "" for the agent loop.
// main dispatches EVERY non-empty value to runBenchmark, so a typo is named
// there instead of silently starting an interactive agent session.
func benchMode() string {
	return os.Getenv("SANDSWAP_BENCH_MODE")
}

// runBenchmark dispatches to the requested benchmark mode.
func runBenchmark(ctx context.Context, mode string) error {
	switch mode {
	case "http":
		return runBenchHTTP(ctx)
	case "mcp":
		return runBenchMCP(ctx)
	}
	return fmt.Errorf("unknown benchmark mode %q (want http|mcp)", mode)
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func atoiDefault(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

// sleepMS sleeps for the given number of milliseconds.
func sleepMS(ms int) {
	time.Sleep(time.Duration(ms) * time.Millisecond)
}

// warmupRetry runs fn until it returns true or ~12s elapse. A fresh stack's
// first call can hit cold-start races (vsock CID conflict etc.); the gateway
// rebuilds the VM, so retry the first call until it lands on a ready VM
// (warmup with retry, tolerating transient vsock CID conflicts).
func warmupRetry(ctx context.Context, fn func() bool) bool {
	for i := 0; i < 15; i++ {
		if fn() {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(800 * time.Millisecond):
		}
	}
	return false
}

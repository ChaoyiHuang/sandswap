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

// HTTP benchmark mode (SANDSWAP_BENCH_MODE=http): measures bare-metal latency
// through the gateway HTTP agent API (POST /agent/execute) directly.
//
// For every call it records:
//   - T_http (clientMs): client-observed full round trip, send → response.
//   - gateway/sandlot/exec (ms): the gateway's own measurements returned in
//     the JSON body (gateway_duration_ns / sandlot_duration_ns / exec_duration_ns).
//   - warm/cold: ground truth from the X-Sandbox-Lease: hit header (set only
//     when the request was served from a sticky lease).
//
// Benchmark cases: 1 warmup (excluded), then
// WARM_N back-to-back `echo hi` to agent A (sticky lease hit), then COLD_N
// rounds alternating `echo a` (A) / `echo b` (B) with a SWITCH_GAP_MS sleep
// (> sticky-ms 100) so each cross-agent call cold-mounts.

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// httpExecResponse mirrors the gateway's ExecuteResponse JSON.
type httpExecResponse struct {
	Stdout            string `json:"stdout"`
	Stderr            string `json:"stderr"`
	ExitCode          int    `json:"exit_code"`
	Status            string `json:"status"`
	ExecDurationNs    uint64 `json:"exec_duration_ns"`
	SandlotDurationNs uint64 `json:"sandlot_duration_ns"`
	GatewayDurationNs uint64 `json:"gateway_duration_ns"`
}

func runBenchHTTP(ctx context.Context) error {
	cfg := loadBenchConfig()
	if cfg.apiKeyA == "" || cfg.apiKeyB == "" {
		return fmt.Errorf("HTTP benchmark requires SANDSWAP_API_KEY_A and SANDSWAP_API_KEY_B")
	}

	client, err := newHTTPBenchClient()
	if err != nil {
		return err
	}

	// exec runs one execute call; ok=false drops failed calls from the stats.
	exec := func(key, sandfsID, code string) (execSample, bool) {
		s, ok, err := httpExecOnce(ctx, client, cfg.gatewayURL, key, sandfsID, code)
		if err != nil {
			fmt.Printf("  [warn] HTTP exec failed: %v\n", err)
			return execSample{}, false
		}
		return s, ok
	}

	fmt.Printf("═══ Sandswap latency benchmark — mode=http ═══\n")
	fmt.Printf("Gateway: %s   warm_n=%d  cold_n=%d  warm_gap_ms=%d  switch_gap_ms=%d  switch_settle_ms=%d\n\n",
		cfg.gatewayURL, cfg.warmN, cfg.coldN, cfg.warmGapMS, cfg.switchGapMS, cfg.switchSettleMS)

	// ── Warmup (excluded) — ride out cold-start races ─────────────
	fmt.Println("Warmup (excluded)...")
	if !warmupRetry(ctx, func() bool {
		_, _, err := httpExecOnce(ctx, client, cfg.gatewayURL, cfg.apiKeyA, cfg.sandfsA, "echo warmup")
		return err == nil
	}) {
		fmt.Println("  [warn] warmup did not succeed, continuing")
	}

	// ── Warm phase: back-to-back calls to agent A (sticky lease) ──
	// A small WARM_GAP_MS sleep between calls (≪ sticky window) keeps each one
	// on the warm lease while avoiding extreme back-to-back hammering.
	fmt.Printf("Warm: %d consecutive calls to agent A (%dms gap)...\n", cfg.warmN, cfg.warmGapMS)
	warmPhase := make([]execSample, 0, cfg.warmN)
	for i := 0; i < cfg.warmN; i++ {
		if s, ok := exec(cfg.apiKeyA, cfg.sandfsA, "echo hi"); ok {
			warmPhase = append(warmPhase, s)
		}
		sleepMS(cfg.warmGapMS)
	}

	// ── Switch phase: alternate A<->B with a gap > sticky-ms ──────
	// Settle past the sticky window (default 1s) first so the warm phase's last
	// call's lease is long expired and the first switch call is a genuine cold
	// mount, not a lease leftover.
	sleepMS(cfg.switchSettleMS)
	fmt.Printf("Switch: %d rounds alternating A<->B (%dms gap, lease expires)...\n", cfg.coldN, cfg.switchGapMS)
	switchPhase := make([]execSample, 0, cfg.coldN*2)
	for i := 0; i < cfg.coldN; i++ {
		if s, ok := exec(cfg.apiKeyA, cfg.sandfsA, "echo a"); ok {
			switchPhase = append(switchPhase, s)
		}
		sleepMS(cfg.switchGapMS)
		if s, ok := exec(cfg.apiKeyB, cfg.sandfsB, "echo b"); ok {
			switchPhase = append(switchPhase, s)
		}
		sleepMS(cfg.switchGapMS)
	}

	// ── Classify by the lease header (ground truth) ───────────────
	// The X-Sandbox-Lease header is authoritative; any phase/header mismatch
	// is surfaced as a warning and the sample bucketed by its true class.
	warm, cold := bucketByLease(warmPhase, switchPhase)

	printMetricTable(fmt.Sprintf("Warm — sticky lease reuse (leaseHit=true, n=%d) [ms]", len(warm)), warm)
	printMetricTable(fmt.Sprintf("Switch — cross-agent cold mount_and_exec (leaseHit=false, n=%d) [ms]", len(cold)), cold)

	if cfg.verbose {
		all := append(append([]execSample{}, warm...), cold...)
		printVerbose(all)
	}
	// Quality gate AFTER the tables (so a failure still prints what it has):
	// a broken exec path must fail the run, not print "(no samples)" and
	// exit 0.
	if err := benchQualityGate("warm", len(warm), cfg.warmN, warm); err != nil {
		return err
	}
	return benchQualityGate("cold", len(cold), cfg.coldN*2, cold)
}

// bucketByLease splits the warm-phase and switch-phase samples by the gateway's
// X-Sandbox-Lease header, warning about any phase/class mismatch.
func bucketByLease(warmPhase, switchPhase []execSample) (warm, cold []execSample) {
	for _, s := range warmPhase {
		if s.warm {
			warm = append(warm, s)
		} else {
			fmt.Println("  [warn] warm-phase call missed the sticky lease (X-Sandbox-Lease absent) — classified cold")
			cold = append(cold, s)
		}
	}
	for _, s := range switchPhase {
		if s.warm {
			fmt.Println("  [warn] switch-phase call hit the sticky lease (likely the first call reusing the warm phase's lease) — classified warm")
			warm = append(warm, s)
		} else {
			cold = append(cold, s)
		}
	}
	return warm, cold
}

// httpExecOnce posts a single execute request and returns the timing breakdown.
func httpExecOnce(ctx context.Context, client *http.Client, baseURL, apiKey, sandfsID, code string) (execSample, bool, error) {
	payload := map[string]any{"code": code, "language": "shell"}
	if sandfsID != "" {
		payload["sandfs_id"] = sandfsID
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return execSample{}, false, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/agent/execute", bytes.NewReader(body))
	if err != nil {
		return execSample{}, false, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)
	// X-Sandswap-Api-Key survives cross-host 307 redirects to an owner gateway
	// (Go's http.Client strips Authorization on cross-host redirects).
	req.Header.Set("X-Sandswap-Api-Key", apiKey)

	start := time.Now()
	resp, err := client.Do(req)
	clientMs := float64(time.Since(start).Nanoseconds()) / 1e6
	if err != nil {
		return execSample{}, false, err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return execSample{}, false, err
	}
	if resp.StatusCode != http.StatusOK {
		return execSample{}, false, fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncate(string(respBody), 200))
	}
	var r httpExecResponse
	if err := json.Unmarshal(respBody, &r); err != nil {
		return execSample{}, false, fmt.Errorf("bad response JSON: %v", err)
	}
	return execSample{
		clientMs:  clientMs,
		gatewayMs: float64(r.GatewayDurationNs) / 1e6,
		sandlotMs: float64(r.SandlotDurationNs) / 1e6,
		execMs:    float64(r.ExecDurationNs) / 1e6,
		warm:      resp.Header.Get("X-Sandbox-Lease") == "hit",
		exit:      r.ExitCode,
	}, true, nil
}

// newHTTPBenchClient returns a keep-alive HTTP client. IdleConnTimeout 0 keeps
// the connection warm (the gateway's own IdleTimeout governs); SANDSWAP_CA_CERT
// is honored for https against a self-signed gateway (as in the MCP client).
// A configured CA that cannot be read or parsed is an ERROR, not a silent
// fallback to the system roots: otherwise the benchmark would run against the
// wrong trust set and fail later with an opaque x509 error.
func newHTTPBenchClient() (*http.Client, error) {
	transport := &http.Transport{IdleConnTimeout: 0}
	if caPath := os.Getenv("SANDSWAP_CA_CERT"); caPath != "" {
		caPEM, err := os.ReadFile(caPath)
		if err != nil {
			return nil, fmt.Errorf("read CA cert %s: %w", caPath, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("failed to append CA cert from %s", caPath)
		}
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}
	}
	return &http.Client{Transport: transport}, nil
}

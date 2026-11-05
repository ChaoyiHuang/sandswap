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
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestPercentile pins the repo-wide nearest-rank convention: sorted[int(n*p)],
// clamped to the last sample. The n=2 case (p50 of [1,2] = 2) is deliberate —
// it is the same index the gateway rings and the benchmark scripts use.
func TestPercentile(t *testing.T) {
	if got := percentile(nil, 0.50); got != 0 {
		t.Errorf("empty percentile = %v, want 0", got)
	}

	one := []time.Duration{7 * time.Millisecond}
	if got := percentile(one, 0.50); got != 7*time.Millisecond {
		t.Errorf("n=1 p50 = %v, want 7ms", got)
	}

	two := []time.Duration{1 * time.Millisecond, 2 * time.Millisecond}
	if got := percentile(two, 0.50); got != 2*time.Millisecond {
		t.Errorf("n=2 p50 = %v, want 2ms (index int(2*0.5)=1)", got)
	}

	hundred := make([]time.Duration, 100)
	for i := range hundred {
		hundred[i] = time.Duration(i+1) * time.Millisecond
	}
	if got := percentile(hundred, 0.50); got != 51*time.Millisecond {
		t.Errorf("n=100 p50 = %v, want 51ms", got)
	}
	if got := percentile(hundred, 0.95); got != 96*time.Millisecond {
		t.Errorf("n=100 p95 = %v, want 96ms", got)
	}
	if got := percentile(hundred, 0.99); got != 100*time.Millisecond {
		t.Errorf("n=100 p99 = %v, want 100ms", got)
	}

	// Monotonic across percentiles.
	p50, p95, p99 := percentile(hundred, 0.50), percentile(hundred, 0.95), percentile(hundred, 0.99)
	if !(p50 <= p95 && p95 <= p99) {
		t.Errorf("percentiles not monotonic: %v %v %v", p50, p95, p99)
	}
}

// TestComputeExpectedExpiries pins the gap semantics:
//   - a gap EQUAL to sticky is not an expiry (strictly greater required);
//   - a gap above sticky is one expiry;
//   - overlap (next start before previous end) is never an expiry;
//   - agents are counted independently.
func TestComputeExpectedExpiries(t *testing.T) {
	us := func(v int64) time.Time { return time.Unix(0, v*1000) }
	mk := func(agent int, startUS, endUS int64) sample {
		return sample{agent: agent, start: us(startUS), end: us(endUS), ok: true}
	}
	samples := []sample{
		// Agent 0: 0.5ms gap (≤1ms) then 3ms gap (>1ms) → 1 expiry.
		mk(0, 0, 1000),
		mk(0, 1500, 2000),
		mk(0, 5000, 6000),
		// Agent 1: gap exactly 1ms → NOT an expiry (boundary pin).
		mk(1, 0, 10000),
		mk(1, 11000, 12000),
		// Agent 2: overlapping requests, then a 6ms gap off the SECOND end
		// (the gap is measured against the preceding request's completion,
		// not the first request's) → 1 expiry.
		mk(2, 0, 10000),
		mk(2, 4000, 5000),
		mk(2, 11000, 12000),
	}
	// Deliberately out of order per agent: computeExpectedExpiries sorts.
	got := computeExpectedExpiries(samples, 3, time.Millisecond)
	if got != 2 {
		t.Fatalf("expected_expiries = %d, want 2 (agent0=1, agent1=0, agent2=1)", got)
	}

	// A wider sticky window absorbs the 3ms gap → only agent 2 remains.
	if got := computeExpectedExpiries(samples, 3, 4*time.Millisecond); got != 1 {
		t.Errorf("expected_expiries(sticky=4ms) = %d, want 1", got)
	}
}

// TestComputeExpectedExpiries_OnlyCompletedRequests pins the corrected
// semantics: a failed request never MOUNTED, so it can neither create nor
// continue an expiry chain. The gap after the last completed request still
// counts (its lease really did expire while the next request failed).
func TestComputeExpectedExpiries_OnlyCompletedRequests(t *testing.T) {
	us := func(v int64) time.Time { return time.Unix(0, v*1000) }
	mk := func(agent int, startUS, endUS int64, ok bool) sample {
		return sample{agent: agent, start: us(startUS), end: us(endUS), ok: ok}
	}

	// Agent 0: OK(0-1ms), FAIL(5ms), OK(10-11ms).
	// (OK→FAIL gap 4ms > 1ms) = one expiry from the OK request; the failed
	// request is not eligible as a predecessor, so FAIL→OK counts nothing.
	got := computeExpectedExpiries([]sample{
		mk(0, 0, 1000, true),
		mk(0, 5000, 6000, false),
		mk(0, 10000, 11000, true),
	}, 1, time.Millisecond)
	if got != 1 {
		t.Fatalf("expected_expiries = %d, want 1 (only the completed request's gap)", got)
	}

	// Agent 0: FAIL(0-1ms), FAIL(5-6ms), OK(10-11ms) → no completed request
	// before any gap → 0.
	got = computeExpectedExpiries([]sample{
		mk(0, 0, 1000, false),
		mk(0, 5000, 6000, false),
		mk(0, 10000, 11000, true),
	}, 1, time.Millisecond)
	if got != 0 {
		t.Fatalf("expected_expiries = %d, want 0 (failed requests never held a lease)", got)
	}
}

// TestComputeExpectedExpiries_RetriedRequest pins the retry-aware gap: a
// request can START a busy attempt inside the sticky window and mount long
// after it. The lease from the previous request expires in between, so the
// expiry must be measured from the mounting attempt (okStart), not the first
// attempt.
func TestComputeExpectedExpiries_RetriedRequest(t *testing.T) {
	us := func(v int64) time.Time { return time.Unix(0, v*1000) }
	prev := sample{agent: 0, start: us(0), end: us(1500), ok: true, okStart: us(0)}

	// First attempt at 1.6ms (inside the window), mount at 30ms → 1 expiry.
	next := sample{agent: 0, start: us(1600), end: us(33000), ok: true, okStart: us(30000)}
	if got := computeExpectedExpiries([]sample{prev, next}, 1, time.Millisecond); got != 1 {
		t.Fatalf("retried request: expected_expiries = %d, want 1", got)
	}

	// The mounting attempt lands at 2.4ms, inside the 1ms window → no expiry.
	next.okStart = us(2400)
	if got := computeExpectedExpiries([]sample{prev, next}, 1, time.Millisecond); got != 0 {
		t.Fatalf("in-window mount: expected_expiries = %d, want 0", got)
	}
}

// TestExecOnceClassification pins the warm/cold ground truth: only a 2xx
// response is classified (header=hit → warm, absent → cold); a non-2xx is an
// error with its named gateway code and is NEVER counted as cold.
func TestExecOnceClassification(t *testing.T) {
	cases := []struct {
		name     string
		status   int
		lease    string
		body     string
		wantOK   bool
		wantWarm bool
		wantCode string
	}{
		{"warm", 200, "hit", `{"status":"done"}`, true, true, ""},
		{"cold", 200, "", `{"status":"done"}`, true, false, ""},
		{"saturated", 503, "", `{"error":"no available sandbox","error_code":"NO_AVAILABLE_SANDBOX"}`, false, false, "HTTP 503 NO_AVAILABLE_SANDBOX"},
		// A non-2xx must never be classified warm even if a header were present
		// (defence in depth: the gateway sets it only on a success response).
		{"error-with-header", 500, "hit", `{"error":"boom"}`, false, false, "HTTP 500"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.lease != "" {
					w.Header().Set("X-Sandbox-Lease", tc.lease)
				}
				w.WriteHeader(tc.status)
				io.WriteString(w, tc.body)
			}))
			defer srv.Close()

			got := execOnce(srv.Client(), srv.URL, agentTarget{Sandfs: "sf"}, 0)
			if got.ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v (err=%q)", got.ok, tc.wantOK, got.err)
			}
			if got.warm != tc.wantWarm {
				t.Errorf("warm = %v, want %v", got.warm, tc.wantWarm)
			}
			if tc.wantCode != "" {
				if class := classifyErr(got); class != tc.wantCode {
					t.Errorf("error class = %q, want %q", class, tc.wantCode)
				}
			}
		})
	}
}

// TestExecOnceServerDurations pins the server-side metric extraction: the
// execute response's gateway/sandlot/exec durations become time.Duration on
// the sample (the client round trip remains the separate start→end span).
func TestExecOnceServerDurations(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Sandbox-Lease", "hit")
		io.WriteString(w, `{"status":"done","gateway_duration_ns":937000,"sandlot_duration_ns":800000,"exec_duration_ns":611000}`)
	}))
	defer srv.Close()
	got := execOnce(srv.Client(), srv.URL, agentTarget{Sandfs: "sf"}, 0)
	if !got.ok {
		t.Fatalf("ok = false (err=%q)", got.err)
	}
	if got.gw != 937*time.Microsecond || got.sandlot != 800*time.Microsecond || got.exec != 611*time.Microsecond {
		t.Fatalf("durations = %v/%v/%v, want 937/800/611µs", got.gw, got.sandlot, got.exec)
	}
}

// TestExecWithRetry pins the busy-retry policy: only NO_AVAILABLE_SANDBOX is
// retried, the attempt count is recorded even when the retry budget runs out,
// and the business latency spans the first attempt → final response.
func TestExecWithRetry(t *testing.T) {
	newServer := func(status int, body string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(status)
			io.WriteString(w, body)
		}))
	}

	// Two busy refusals, then success.
	var mu sync.Mutex
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls++
		n := calls
		mu.Unlock()
		if n <= 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
			io.WriteString(w, `{"error":"no available sandbox","error_code":"NO_AVAILABLE_SANDBOX"}`)
			return
		}
		w.Header().Set("X-Sandbox-Lease", "hit")
		io.WriteString(w, `{"status":"done","gateway_duration_ns":800000}`)
	}))
	defer srv.Close()
	sem := make(chan struct{}, 1)
	start := time.Now()
	s := execWithRetry(srv.Client(), srv.URL, agentTarget{Sandfs: "sf"}, 0,
		5, time.Millisecond, rand.New(rand.NewSource(1)), sem)
	if !s.ok || s.busyAttempts != 2 {
		t.Fatalf("ok=%v busy=%d (want ok after 2 busy attempts)", s.ok, s.busyAttempts)
	}
	if calls != 3 {
		t.Fatalf("attempts = %d, want 3", calls)
	}
	if s.start.Before(start) || !s.end.After(s.start) {
		t.Fatalf("sample span %v..%v does not cover the retries", s.start, s.end)
	}

	// A busy refusal with retries disabled stays an error after one attempt.
	srvBusy := newServer(http.StatusServiceUnavailable,
		`{"error":"no available sandbox","error_code":"NO_AVAILABLE_SANDBOX"}`)
	defer srvBusy.Close()
	s = execWithRetry(srvBusy.Client(), srvBusy.URL, agentTarget{Sandfs: "sf"}, 0,
		0, time.Millisecond, rand.New(rand.NewSource(1)), make(chan struct{}, 1))
	if s.ok || s.busyAttempts != 1 || s.errCode != "NO_AVAILABLE_SANDBOX" {
		t.Fatalf("retry=0: ok=%v busy=%d code=%q", s.ok, s.busyAttempts, s.errCode)
	}

	// Another 503 (maintenance) is NOT capacity pressure and must not retry.
	var maintCalls int
	srvMaint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		maintCalls++
		w.WriteHeader(http.StatusServiceUnavailable)
		io.WriteString(w, `{"error":"maintenance","error_code":"MAINTENANCE"}`)
	}))
	defer srvMaint.Close()
	s = execWithRetry(srvMaint.Client(), srvMaint.URL, agentTarget{Sandfs: "sf"}, 0,
		5, time.Millisecond, rand.New(rand.NewSource(1)), make(chan struct{}, 1))
	if s.ok || s.busyAttempts != 0 || s.errCode != "MAINTENANCE" {
		t.Fatalf("maintenance: ok=%v busy=%d code=%q", s.ok, s.busyAttempts, s.errCode)
	}
	if maintCalls != 1 {
		t.Fatalf("maintenance attempts = %d, want 1 (not a capacity retry)", maintCalls)
	}
}

// TestParseTurnSizes pins the accepted syntaxes and the failure modes: a
// single integer is a fixed turn size, "size:weight" entries are a weighted
// distribution, and the default is 1:40,2:35,3:25.
func TestParseTurnSizes(t *testing.T) {
	w, err := parseTurnSizes("1:40,2:35,3:25")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(w) != 3 || math.Abs(w[0]-0.4) > 1e-9 || math.Abs(w[1]-0.35) > 1e-9 || math.Abs(w[2]-0.25) > 1e-9 {
		t.Fatalf("weights = %v, want [0.4 0.35 0.25]", w)
	}
	if w, err := parseTurnSizes("1"); err != nil || len(w) != 1 || w[0] != 1 {
		t.Fatalf("fixed 1 = %v, %v (want [1])", w, err)
	}
	if w, err := parseTurnSizes("3"); err != nil || len(w) != 3 || w[2] != 1 {
		t.Fatalf("fixed 3 = %v, %v (want [0 0 1])", w, err)
	}
	if w, err := parseTurnSizes("2:100"); err != nil || len(w) != 2 || w[1] != 1 {
		t.Fatalf("single weighted size = %v, %v (want [0 1])", w, err)
	}
	if w, err := parseTurnSizes(""); err != nil || len(w) != 3 {
		t.Fatalf("empty default = %v, %v", w, err)
	}
	for _, bad := range []string{
		"1:40,2",     // weighted form requires every entry to be size:weight
		"0:40",       // size must be >= 1
		"2:40,2:60",  // duplicate size
		"1:-1",       // negative weight
		"1:0,2:0",    // zero weight sum
		"abc",        // not a count
		"101",        // absurd turn size
		"1:40,2:NaN", // non-finite weight
	} {
		if _, err := parseTurnSizes(bad); err == nil {
			t.Errorf("want error for %q", bad)
		}
	}
}

// TestWeightedTurnDistribution pins the draw range and the rough weights.
func TestWeightedTurnDistribution(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	w, _ := parseTurnSizes("1:40,2:35,3:25")
	var counts [3]int
	const n = 100000
	for i := 0; i < n; i++ {
		b := weightedTurn(rng, w)
		if b < 1 || b > 3 {
			t.Fatalf("turn size %d out of range", b)
		}
		counts[b-1]++
	}
	for i, want := range []float64{0.40, 0.35, 0.25} {
		got := float64(counts[i]) / float64(n)
		if math.Abs(got-want) > 0.01 {
			t.Errorf("turn size %d share = %.3f, want %.2f", i+1, got, want)
		}
	}
}

// TestRandBetween pins the inclusive upper bound and the lo==hi degenerate.
func TestRandBetween(t *testing.T) {
	rng := rand.New(rand.NewSource(3))
	for i := 0; i < 1000; i++ {
		if d := randBetween(rng, 5*time.Millisecond, 5*time.Millisecond); d != 5*time.Millisecond {
			t.Fatalf("lo==hi = %v", d)
		}
		if d := randBetween(rng, 2*time.Millisecond, 4*time.Millisecond); d < 2*time.Millisecond || d > 4*time.Millisecond {
			t.Fatalf("randBetween out of range: %v", d)
		}
	}
}

// TestAgentsWorkloadTurnsAndClasses drives the real agents workload against a fake gateway
// that classifies a request warm iff the same sandfs was served within the
// sticky window. It pins the workload shape: each turn = one cold mount plus
// turn-1 warm follow-ups, warmup excluded from the rates.
func TestAgentsWorkloadTurnsAndClasses(t *testing.T) {
	var mu sync.Mutex
	last := map[string]time.Time{}
	const sticky = 50 * time.Millisecond
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			SandfsID string `json:"sandfs_id"`
		}
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &req)
		now := time.Now()
		mu.Lock()
		prev, seen := last[req.SandfsID]
		warm := seen && now.Sub(prev) <= sticky
		last[req.SandfsID] = now
		mu.Unlock()
		if warm {
			w.Header().Set("X-Sandbox-Lease", "hit")
		}
		io.WriteString(w, `{"status":"done","gateway_duration_ns":800000,"sandlot_duration_ns":700000,"exec_duration_ns":600000}`)
	}))
	defer srv.Close()

	dir := t.TempDir()
	var b strings.Builder
	for i := 0; i < 2; i++ {
		fmt.Fprintf(&b, "agent%d key%d sf%d\n", i, i, i)
	}
	path := filepath.Join(dir, "agents.txt")
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	targets, err := loadAgents(path)
	if err != nil {
		t.Fatal(err)
	}
	opts := options{
		gateway:    srv.URL,
		agents:     path,
		agentCount: 2,
		thinkMin:   80 * time.Millisecond,
		thinkMax:   100 * time.Millisecond,
		// Always run a 2-request turn: the test pins the warm follow-up
		// classification, not the turn-size distribution (covered above).
		turnWeights: []float64{0, 1},
		intraGap:    5 * time.Millisecond,
		warmup:      100 * time.Millisecond,
		duration:    400 * time.Millisecond,
		sticky:      sticky,
		seed:        5,
		maxInflight: 8,
	}
	res := runAgents(opts, targets, srv.Client())
	if res.OK == 0 || res.Err != 0 {
		t.Fatalf("ok=%d err=%d (errs=%v)", res.OK, res.Err, res.ErrKinds)
	}
	if res.Cold == 0 || res.Warm == 0 {
		t.Fatalf("warm=%d cold=%d, want both classes exercised", res.Warm, res.Cold)
	}
	if res.ColdStats.N != res.Cold || res.WarmStats.N != res.Warm {
		t.Fatalf("class stats n = %d/%d, want %d/%d", res.ColdStats.N, res.WarmStats.N, res.Cold, res.Warm)
	}
	if res.ColdRPS <= 0 || res.WarmRPS <= 0 {
		t.Fatalf("rates cold=%v warm=%v", res.ColdRPS, res.WarmRPS)
	}
	// A fixed 2-request turn: roughly one warm follow-up per cold turn.
	if res.Warm < res.Cold/2 {
		t.Fatalf("warm=%d cold=%d — warm follow-ups missing", res.Warm, res.Cold)
	}
	if res.WarmHitPct <= 0 || res.WarmHitPct >= 100 {
		t.Fatalf("warm_hit=%.2f, want in (0,100)", res.WarmHitPct)
	}
	if res.Turns < 2*res.Agents/2 {
		t.Fatalf("turns=%d for %d agents — scheduling did not advance", res.Turns, res.Agents)
	}
	// Each turn's first request is cold; cold count should be close to the
	// number of measured turns (allow the turns straddling the window edges).
	if res.Cold < res.Turns || res.Cold > res.Turns+res.Agents {
		t.Fatalf("cold=%d turns=%d agents=%d — cold should track turns", res.Cold, res.Turns, res.Agents)
	}
}

// TestIdealPacing pins the ideal workload: one paced lane per VM, a turn
// every period, no think time, and the mode/lanes/period projection.
func TestIdealPacing(t *testing.T) {
	// No lease header: every paced turn is a cold mount (the gap between
	// turns exceeds the sticky window).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"status":"done","gateway_duration_ns":800000,"sandlot_duration_ns":700000,"exec_duration_ns":600000}`)
	}))
	defer srv.Close()

	dir := t.TempDir()
	var b strings.Builder
	for i := 0; i < 2; i++ {
		fmt.Fprintf(&b, "agent%d key%d sf%d\n", i, i, i)
	}
	path := filepath.Join(dir, "agents.txt")
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	targets, err := loadAgents(path)
	if err != nil {
		t.Fatal(err)
	}
	opts := options{
		gateway:     srv.URL,
		agentCount:  2,
		workload:    "ideal",
		lanes:       2,
		period:      20 * time.Millisecond,
		turnWeights: []float64{1}, // exactly one request per turn
		duration:    200 * time.Millisecond,
		sticky:      time.Millisecond,
		seed:        5,
		maxInflight: 8,
	}
	res := runIdeal(opts, targets, srv.Client())
	if res.Mode != "ideal" || res.Lanes != 2 || res.PeriodMs != 20 {
		t.Fatalf("mode/lanes/period = %q/%d/%.3f, want ideal/2/20", res.Mode, res.Lanes, res.PeriodMs)
	}
	if res.Err != 0 || res.BusyAttempts != 0 {
		t.Fatalf("err=%d busy=%d (want a clean paced run)", res.Err, res.BusyAttempts)
	}
	// 2 lanes x 200ms/20ms = 20 turns at 100 cold/s.
	if res.Cold < 16 || res.Cold > 22 {
		t.Fatalf("cold = %d, want 16..22 (2 lanes x 10 periods)", res.Cold)
	}
	if res.ColdRPS < 80 || res.ColdRPS > 110 {
		t.Fatalf("cold_rps = %.1f, want ~100", res.ColdRPS)
	}
	if res.Warm != 0 {
		t.Fatalf("warm = %d, want 0 with one request per turn", res.Warm)
	}
}

// TestIdealColdBoundary pins the ideal workload's cold guarantee: when a turn
// overruns its period, the next turn still waits for the previous response +
// sticky window. Without that wait the next request lands inside the lease
// window and is served warm, so a "cold-only" probe would silently mix warm
// samples.
func TestIdealColdBoundary(t *testing.T) {
	var mu sync.Mutex
	last := map[string]time.Time{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			SandfsID string `json:"sandfs_id"`
		}
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &req)
		now := time.Now()
		mu.Lock()
		prev, seen := last[req.SandfsID]
		warm := seen && now.Sub(prev) <= 3*time.Millisecond
		mu.Unlock()
		if warm {
			w.Header().Set("X-Sandbox-Lease", "hit")
		}
		// The response outlives the 2 ms period, so the old self-clocking
		// would fire the next turn immediately after it (a warm hit). The
		// lease timestamp is the RESPONSE end.
		time.Sleep(5 * time.Millisecond)
		mu.Lock()
		last[req.SandfsID] = time.Now()
		mu.Unlock()
		io.WriteString(w, `{"status":"done","gateway_duration_ns":800000,"sandlot_duration_ns":700000,"exec_duration_ns":600000}`)
	}))
	defer srv.Close()

	dir := t.TempDir()
	path := filepath.Join(dir, "agents.txt")
	if err := os.WriteFile(path, []byte("agent0 key0 sf0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	targets, err := loadAgents(path)
	if err != nil {
		t.Fatal(err)
	}
	opts := options{
		gateway:     srv.URL,
		agentCount:  1,
		workload:    "ideal",
		lanes:       1,
		period:      2 * time.Millisecond,
		turnWeights: []float64{1},
		duration:    300 * time.Millisecond,
		sticky:      5 * time.Millisecond,
		seed:        5,
		maxInflight: 4,
	}
	res := runIdeal(opts, targets, srv.Client())
	if res.Cold == 0 || res.Warm != 0 {
		t.Fatalf("cold=%d warm=%d, want cold>0 and warm=0 (the next turn must wait out the sticky window)", res.Cold, res.Warm)
	}
}

// TestShapedLaneRotatesAgents pins the shaped workload's core property: a
// lane aggregates MANY agents whose turns queue at the lane, and the lane
// serves them one at a time. Every turn's first request comes from a
// different agent than the previous turn's (cold by addressing), follow-ups
// are immediate (warm), and the agent population is a closed loop.
func TestShapedLaneRotatesAgents(t *testing.T) {
	var mu sync.Mutex
	last := map[string]time.Time{}
	seen := map[string]bool{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			SandfsID string `json:"sandfs_id"`
		}
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &req)
		now := time.Now()
		mu.Lock()
		prev, ok := last[req.SandfsID]
		warm := ok && now.Sub(prev) <= 20*time.Millisecond
		last[req.SandfsID] = now
		seen[req.SandfsID] = true
		mu.Unlock()
		if warm {
			w.Header().Set("X-Sandbox-Lease", "hit")
		}
		io.WriteString(w, `{"status":"done","gateway_duration_ns":300000,"sandlot_duration_ns":200000,"exec_duration_ns":100000}`)
	}))
	defer srv.Close()

	const lanes, k = 1, 4
	dir := t.TempDir()
	var b strings.Builder
	for i := 0; i < lanes*k; i++ {
		fmt.Fprintf(&b, "agent%d key%d sf%d\n", i, i, i)
	}
	path := filepath.Join(dir, "agents.txt")
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	targets, err := loadAgents(path)
	if err != nil {
		t.Fatal(err)
	}
	opts := options{
		gateway:     srv.URL,
		agentCount:  lanes * k,
		workload:    "shaped",
		lanes:       lanes,
		laneAgents:  k,
		period:      time.Millisecond,
		thinkMin:    5 * time.Millisecond,
		thinkMax:    10 * time.Millisecond,
		turnWeights: []float64{0, 1}, // 2 requests per turn: cold + warm
		duration:    400 * time.Millisecond,
		sticky:      20 * time.Millisecond,
		seed:        3,
		maxInflight: 8,
	}
	res := runShaped(opts, targets, srv.Client())
	if res.Mode != "shaped" || res.Lanes != lanes || res.Agents != lanes*k {
		t.Fatalf("mode/lanes/agents = %q/%d/%d, want shaped/%d/%d", res.Mode, res.Lanes, res.Agents, lanes, lanes*k)
	}
	if res.Err != 0 || res.Cold == 0 || res.Warm == 0 {
		t.Fatalf("err=%d cold=%d warm=%d, want all three classes exercised", res.Err, res.Cold, res.Warm)
	}
	mu.Lock()
	n := len(seen)
	mu.Unlock()
	if n < k-1 {
		t.Fatalf("distinct sandfs served = %d, want >= %d of %d (the lane must rotate agents)", n, k-1, k)
	}
}

// TestBuildResultPerClass pins the per-class aggregation and the window
// denominator (rates use the measurement duration, not wall time).
func TestBuildResultPerClass(t *testing.T) {
	now := time.Now()
	mk := func(warm bool, lat time.Duration) sample {
		return sample{start: now, end: now.Add(lat), ok: true, warm: warm,
			gw: lat / 2, sandlot: lat / 3, exec: lat / 4}
	}
	samples := []sample{
		mk(false, 2*time.Millisecond),
		mk(false, 4*time.Millisecond),
		mk(true, 1*time.Millisecond),
		mk(true, 3*time.Millisecond),
		{start: now, end: now, code: 503, errCode: "NO_AVAILABLE_SANDBOX"},
	}
	res := buildResult(samples, 2, 10*time.Second, 100*time.Millisecond, 3, 5)
	if res.OK != 4 || res.Err != 1 {
		t.Fatalf("ok=%d err=%d", res.OK, res.Err)
	}
	if res.Cold != 2 || res.Warm != 2 || res.WarmHitPct != 50 {
		t.Fatalf("cold=%d warm=%d hit=%.1f", res.Cold, res.Warm, res.WarmHitPct)
	}
	if res.ColdRPS != 0.2 || res.WarmRPS != 0.2 || res.RPS != 0.4 {
		t.Fatalf("rates = %v/%v/%v, want 0.2/0.2/0.4", res.ColdRPS, res.WarmRPS, res.RPS)
	}
	if res.ColdStats.N != 2 || res.WarmStats.N != 2 {
		t.Fatalf("class n = %d/%d", res.ColdStats.N, res.WarmStats.N)
	}
	if res.Agents != 2 || res.Turns != 3 || res.MaxInflight != 5 {
		t.Fatalf("meta = agents %d turns %d inflight %d", res.Agents, res.Turns, res.MaxInflight)
	}
}

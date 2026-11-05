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
//
// loadgen — concurrent load driver for the sandswap exec gateway.
//
// The workload is an AI agent population: every agent is an independent
// closed loop that sleeps for an LLM round trip (-think-min-ms..
// -think-max-ms, ~1 s), then issues a turn of 1..N requests
// (-requests-per-turn). The first request of a turn is COLD (the think gap
// outlived the lease); the remaining requests are sent immediately after the
// previous response, so with the benchmark's 1 ms sticky lease they are WARM
// on the same VM. The driver classifies every response from X-Sandbox-Lease
// (ground truth) and reports the two classes separately: rates, client
// latency, and the gateway E2E P95 (gateway_duration_ns — the
// sandswap-attributable latency).
//
// A real agent retries a transient capacity refusal instead of failing its
// turn. The driver therefore retries ONLY HTTP 503 NO_AVAILABLE_SANDBOX
// (-retry-busy additional attempts, full-jitter backoff). A retried request
// keeps its business latency (first attempt → final response) while its
// gateway E2E comes from the successful attempt; -retry-busy 0 disables the
// policy and surfaces the 503 as an error.
//
// -workload ideal is the capability probe, not a business model: one paced
// lane per microVM, each issuing a turn every -period-ms with no between-turn
// think gap.
// A period sweep finds the smallest period at which the pool still refuses
// nothing — the collision-free maximum reuse rate with the VMs continuously
// fed. The agent model (-workload agents, the default) remains the realistic
// measurement.
//
// One http.Client with keep-alive serves all agents; -max-inflight bounds the
// client-side concurrency (it is not a server limit). -warmup-sec of traffic
// is excluded from every statistic, so the reported window is steady state.
//
// Per agent, the driver also computes expected_expiries: the gaps between a
// completed request and the next request START to that agent that exceed
// -sticky-ms. Each such gap is a lease expiry the gateway should fire and
// unmount; the benchmark compares it with the gateway's unmount delta.
//
// Usage:
//
//	loadgen -gateway http://localhost:3001 -agents FILE [-agent-count N] \
//	        [-think-min-ms 900] [-think-max-ms 1500] \
//	        [-requests-per-turn "1:40,2:35,3:25"] [-intra-gap-ms 0] \
//	        [-retry-busy 50] [-retry-backoff-ms 10] \
//	        [-workload agents|ideal|shaped] [-lanes N] [-period-ms P] \
//	        [-lane-agents K] [-hold-ms H] \
//	        -duration SEC [-warmup-sec SEC] [-sticky-ms 1] \
//	        [-seed 1] [-max-inflight 1024] [-json]
//
// -agents FILE lines: "<agent_id> <api_key> <sandfs_id>" (blank/# lines
// ignored); -agent-count 0 drives all lines.
//
// Output: one machine line
//
//	LOADGEN_RESULT {"mode":"agents","agents":...,"ok":...,"err":...,
//	                "busy_attempts":...,"busy_retried":...,"rps":...,
//	                "cold":...,"cold_rps":...,"warm":...,"warm_rps":...,
//	                "warm_hit_pct":...,"duration_sec":...,"turns":...,
//	                "cold_stats":{...},"warm_stats":{...},
//	                "expected_expiries":...,"expected_expiries_all":...,...}
//
// plus a human-readable summary (suppressed by -json). Exit 0 always for a
// completed run; the caller gates on the fields. Usage/IO errors exit 2, and
// any request error is reflected in err.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// maxBodyBytes bounds one response body; an execute response is a few hundred
// bytes, so anything larger is a gateway bug — drain and ignore the excess.
const maxBodyBytes = 1 << 20

type agentTarget struct {
	ID     string
	Key    string
	Sandfs string
}

type options struct {
	gateway     string
	agents      string
	agentCount  int
	workload    string        // "agents" (closed loop) | "ideal" | "shaped" (paced lanes)
	lanes       int           // ideal/shaped: one lane per microVM
	laneAgents  int           // shaped: AI agents aggregated per lane
	hold        time.Duration // shaped: extra VM-occupation budget after sticky
	period      time.Duration
	thinkMin    time.Duration
	thinkMax    time.Duration
	turnWeights []float64 // normalized; index i = P(turn has i+1 requests)
	retryBusy   int       // additional attempts after NO_AVAILABLE_SANDBOX
	retryBase   time.Duration
	intraGap    time.Duration
	duration    time.Duration
	warmup      time.Duration
	sticky      time.Duration
	seed        int64
	maxInflight int
	jsonOnly    bool
}

// sample is one completed (or failed) request observation.
type sample struct {
	agent int
	start time.Time // first attempt's start (business latency includes retries)
	end   time.Time // final response
	// okStart is the start of the attempt that actually mounted (the sticky
	// lease is refreshed from here, not from the first attempt). Zero for a
	// failed request.
	okStart time.Time
	code    int
	warm    bool
	ok      bool
	err     string
	errCode string // gateway error_code from the body (non-2xx), when present
	// busyAttempts counts HTTP 503 NO_AVAILABLE_SANDBOX attempts absorbed by
	// the retry policy (including the final one when the budget ran out).
	busyAttempts int
	// Server-side durations read from the execute response (ns). Zero when
	// the response did not carry them (non-2xx / older gateway).
	gw      time.Duration // gateway_duration_ns: gateway E2E
	sandlot time.Duration // sandlot_duration_ns: sandlot dispatch→response
	exec    time.Duration // exec_duration_ns: warden guest share
}

// isBusy reports the gateway's named capacity refusal — the only class the
// driver retries. Other 503s (maintenance, node unavailable) are faults, not
// pool pressure, and must surface as errors.
func (s sample) isBusy() bool {
	return s.code == http.StatusServiceUnavailable && s.errCode == "NO_AVAILABLE_SANDBOX"
}

// classStats is one class's (warm or cold) latency summary.
type classStats struct {
	N            int     `json:"n"`
	P50Ms        float64 `json:"p50_ms"`
	P95Ms        float64 `json:"p95_ms"`
	P99Ms        float64 `json:"p99_ms"`
	GwN          int     `json:"gw_n"`
	GwP50Ms      float64 `json:"gw_p50_ms"`
	GwP95Ms      float64 `json:"gw_p95_ms"`
	GwP99Ms      float64 `json:"gw_p99_ms"`
	SandlotP95Ms float64 `json:"sandlot_p95_ms"`
	ExecP95Ms    float64 `json:"exec_p95_ms"`
}

// loadResult is the LOADGEN_RESULT payload (field order is the output order).
type loadResult struct {
	Mode   string `json:"mode"`
	Agents int    `json:"agents"`
	// Ideal workload only: the paced lane count and the fixed period.
	Lanes    int     `json:"lanes,omitempty"`
	PeriodMs float64 `json:"period_ms,omitempty"`
	Turns    int     `json:"turns"`
	OK       int     `json:"ok"`
	Err      int     `json:"err"`
	// BusyAttempts is every HTTP 503 NO_AVAILABLE_SANDBOX response (including
	// the ones the retry policy absorbed); BusyRetried is the number of
	// completed requests that needed at least one such retry.
	BusyAttempts int     `json:"busy_attempts"`
	BusyRetried  int     `json:"busy_retried"`
	RPS          float64 `json:"rps"`
	P50Ms        float64 `json:"p50_ms"`
	P95Ms        float64 `json:"p95_ms"`
	P99Ms        float64 `json:"p99_ms"`
	// Server-side (sandswap) percentiles from the execute responses' own
	// gateway_duration_ns / sandlot_duration_ns / exec_duration_ns. GwN is
	// the number of successful samples that carried them.
	GwN          int     `json:"gw_n"`
	GwP50Ms      float64 `json:"gw_p50_ms"`
	GwP95Ms      float64 `json:"gw_p95_ms"`
	GwP99Ms      float64 `json:"gw_p99_ms"`
	SandlotP95Ms float64 `json:"sandlot_p95_ms"`
	ExecP95Ms    float64 `json:"exec_p95_ms"`
	Warm         int     `json:"warm"`
	Cold         int     `json:"cold"`
	// The offered agent population, the turns observed in the measurement
	// window, and the measured window length (the rate denominator — warmup
	// excluded).
	DurationSec float64    `json:"duration_sec"`
	ColdRPS     float64    `json:"cold_rps"`
	WarmRPS     float64    `json:"warm_rps"`
	WarmHitPct  float64    `json:"warm_hit_pct"`
	MaxInflight int        `json:"max_inflight,omitempty"`
	WarmStats   classStats `json:"warm_stats"`
	ColdStats   classStats `json:"cold_stats"`
	// ExpectedExpiries is the measurement-window value; ExpectedExpiriesAll
	// also includes the warm-up turns (the harness compares the latter with
	// the unmount delta, which spans warm-up leases too).
	ExpectedExpiries    int `json:"expected_expiries"`
	ExpectedExpiriesAll int `json:"expected_expiries_all,omitempty"`
	// ErrKinds is human-diagnostics and per-level reporting: failed requests
	// grouped by "HTTP <status> <error_code>" / "transport: ...". Not warm/cold
	// — a failed request mounted nothing.
	ErrKinds map[string]int `json:"err_kinds,omitempty"`
}

func main() {
	var (
		gateway     = flag.String("gateway", "http://localhost:3001", "exec gateway base URL")
		agents      = flag.String("agents", "", "agent list file: lines \"agent_id api_key sandfs_id\"")
		agentCount  = flag.Int("agent-count", 0, "number of agents to drive (0 = all lines)")
		workload    = flag.String("workload", "agents", "workload: agents (AI agent closed loop), ideal (one paced lane per microVM) or shaped (many agents queued per lane, one in-flight request per microVM)")
		lanes       = flag.Int("lanes", 0, "ideal/shaped workload: paced lanes, one per microVM (0 = -agent-count)")
		laneAgents  = flag.Int("lane-agents", 1, "shaped workload: AI agents aggregated behind each lane (size ~ lane_rate x mean think)")
		holdMS      = flag.Int("hold-ms", 12, "shaped workload: hold the lane's VM slot for sticky+hold after the last response (the async unmount budget)")
		periodMS    = flag.Int("period-ms", 0, "ideal/shaped workload: fixed turn period in ms (required)")
		thinkMinMS  = flag.Int("think-min-ms", 900, "minimum think time between turns (ms)")
		thinkMaxMS  = flag.Int("think-max-ms", 1500, "maximum think time between turns (ms)")
		perTurn     = flag.String("requests-per-turn", "1:40,2:35,3:25", "requests per turn: N for a fixed count, or size:weight[,size:weight...]")
		retryBusy   = flag.Int("retry-busy", 50, "additional attempts after HTTP 503 NO_AVAILABLE_SANDBOX (0 = no retry)")
		retryBackMS = flag.Int("retry-backoff-ms", 10, "retry backoff base in ms (full jitter, exponential up to 8x)")
		intraGapMS  = flag.Int("intra-gap-ms", 0, "gap between requests inside a turn (ms); 0 = immediate, warm under the 1 ms sticky")
		duration    = flag.Int("duration", 30, "measurement window in seconds (warmup excluded)")
		warmupSec   = flag.Int("warmup-sec", 10, "traffic to run before the measurement window (s)")
		stickyMS    = flag.Int("sticky-ms", 1, "gateway sticky lease window in ms (expected_expiries threshold)")
		seed        = flag.Int64("seed", 1, "RNG seed (deterministic per agent)")
		maxInflight = flag.Int("max-inflight", 1024, "client-side in-flight request cap")
		jsonOnly    = flag.Bool("json", false, "print only the LOADGEN_RESULT machine line")
	)
	flag.Parse()

	opts := options{
		gateway:     strings.TrimRight(*gateway, "/"),
		agents:      *agents,
		agentCount:  *agentCount,
		workload:    *workload,
		lanes:       *lanes,
		laneAgents:  *laneAgents,
		hold:        time.Duration(*holdMS) * time.Millisecond,
		period:      time.Duration(*periodMS) * time.Millisecond,
		thinkMin:    time.Duration(*thinkMinMS) * time.Millisecond,
		thinkMax:    time.Duration(*thinkMaxMS) * time.Millisecond,
		retryBusy:   *retryBusy,
		retryBase:   time.Duration(*retryBackMS) * time.Millisecond,
		intraGap:    time.Duration(*intraGapMS) * time.Millisecond,
		duration:    time.Duration(*duration) * time.Second,
		warmup:      time.Duration(*warmupSec) * time.Second,
		sticky:      time.Duration(*stickyMS) * time.Millisecond,
		seed:        *seed,
		maxInflight: *maxInflight,
		jsonOnly:    *jsonOnly,
	}
	weights, werr := parseTurnSizes(*perTurn)
	if werr != nil {
		fmt.Fprintln(os.Stderr, "loadgen:", werr)
		os.Exit(2)
	}
	opts.turnWeights = weights

	switch {
	case opts.agents == "":
		fmt.Fprintln(os.Stderr, "loadgen: -agents FILE is required")
		os.Exit(2)
	case opts.agentCount < 0:
		fmt.Fprintln(os.Stderr, "loadgen: -agent-count must be >= 0 (0 = all)")
		os.Exit(2)
	case opts.thinkMin < 0 || opts.thinkMax < opts.thinkMin:
		fmt.Fprintln(os.Stderr, "loadgen: -think-min-ms must be >= 0 and <= -think-max-ms")
		os.Exit(2)
	case opts.intraGap < 0:
		fmt.Fprintln(os.Stderr, "loadgen: -intra-gap-ms must be >= 0")
		os.Exit(2)
	case opts.retryBusy < 0:
		fmt.Fprintln(os.Stderr, "loadgen: -retry-busy must be >= 0")
		os.Exit(2)
	case opts.retryBase < 0:
		fmt.Fprintln(os.Stderr, "loadgen: -retry-backoff-ms must be >= 0")
		os.Exit(2)
	case opts.warmup < 0:
		fmt.Fprintln(os.Stderr, "loadgen: -warmup-sec must be >= 0")
		os.Exit(2)
	case opts.maxInflight < 1:
		fmt.Fprintln(os.Stderr, "loadgen: -max-inflight must be >= 1")
		os.Exit(2)
	case opts.duration < time.Second:
		fmt.Fprintln(os.Stderr, "loadgen: -duration must be >= 1s")
		os.Exit(2)
	case opts.sticky < time.Millisecond:
		fmt.Fprintln(os.Stderr, "loadgen: -sticky-ms must be >= 1")
		os.Exit(2)
	case opts.workload != "agents" && opts.workload != "ideal" && opts.workload != "shaped":
		fmt.Fprintln(os.Stderr, "loadgen: -workload must be agents, ideal or shaped")
		os.Exit(2)
	case (opts.workload == "ideal" || opts.workload == "shaped") && opts.period < time.Millisecond:
		fmt.Fprintf(os.Stderr, "loadgen: -workload %s requires -period-ms >= 1\n", opts.workload)
		os.Exit(2)
	case opts.workload == "shaped" && opts.laneAgents < 1:
		fmt.Fprintln(os.Stderr, "loadgen: -workload shaped requires -lane-agents >= 1")
		os.Exit(2)
	case opts.workload == "shaped" && opts.hold < 0:
		fmt.Fprintln(os.Stderr, "loadgen: -hold-ms must be >= 0")
		os.Exit(2)
	}

	targets, err := loadAgents(opts.agents)
	if err != nil {
		fmt.Fprintln(os.Stderr, "loadgen:", err)
		os.Exit(2)
	}
	if opts.agentCount == 0 {
		opts.agentCount = len(targets)
	}
	if opts.agentCount > len(targets) {
		fmt.Fprintf(os.Stderr, "loadgen: -agent-count %d exceeds the %d agents in %s\n",
			opts.agentCount, len(targets), opts.agents)
		os.Exit(2)
	}
	if opts.agentCount < 1 {
		fmt.Fprintln(os.Stderr, "loadgen: needs at least one agent")
		os.Exit(2)
	}
	// A turn's follow-ups are meant to be WARM: the benchmark's sticky window
	// is 1 ms and the follow-ups are sent immediately. A configured gap that
	// reaches the window would turn them cold.
	if opts.intraGap >= opts.sticky {
		fmt.Fprintf(os.Stderr,
			"loadgen: WARNING: -intra-gap-ms %d >= -sticky-ms %d — follow-up requests will be cold, not warm\n",
			opts.intraGap.Milliseconds(), opts.sticky.Milliseconds())
	}
	// The ideal workload drives one paced lane per microVM. -lanes 0 means
	// "one lane per loaded agent"; -agent-count still bounds the file slice.
	if opts.workload == "ideal" {
		if opts.lanes == 0 {
			opts.lanes = opts.agentCount
		}
		if opts.lanes < 1 || opts.lanes > opts.agentCount {
			fmt.Fprintf(os.Stderr,
				"loadgen: -lanes %d must be in [1, -agent-count %d]\n", opts.lanes, opts.agentCount)
			os.Exit(2)
		}
		opts.agentCount = opts.lanes
	}
	targets = targets[:opts.agentCount]

	res := run(opts, targets)

	if !opts.jsonOnly {
		if res.Mode == "ideal" {
			fmt.Printf("workload=ideal lanes=%d period=%.3fms\n", res.Lanes, res.PeriodMs)
		}
		if res.Mode == "shaped" {
			fmt.Printf("workload=shaped lanes=%d agents/lane=%d total=%d period=%.3fms\n",
				res.Lanes, res.Agents/res.Lanes, res.Agents, res.PeriodMs)
		}
		fmt.Printf("%-6s %8s %8s %9s %9s %9s %9s %9s %9s %9s %8s\n",
			"AGENTS", "OK", "ERR", "RPS", "COLD/S", "WARM/S", "HIT%", "P50_MS", "P95_MS", "GW_P95", "EXP")
		fmt.Printf("%-6d %8d %8d %9.2f %9.2f %9.2f %9.2f %9.3f %9.3f %9.3f %8d\n",
			res.Agents, res.OK, res.Err, res.RPS, res.ColdRPS, res.WarmRPS,
			res.WarmHitPct, res.P50Ms, res.P95Ms, res.GwP95Ms, res.ExpectedExpiries)
		fmt.Printf("      turns=%d window=%.1fs max_inflight=%d  gateway E2E ms: p50=%.3f p95=%.3f p99=%.3f (n=%d)\n",
			res.Turns, res.DurationSec, res.MaxInflight, res.GwP50Ms, res.GwP95Ms, res.GwP99Ms, res.GwN)
		fmt.Printf("      busy retries: attempts=%d retried_requests=%d\n",
			res.BusyAttempts, res.BusyRetried)
		fmt.Printf("      cold: n=%d gw p50=%.3f p95=%.3f p99=%.3f  client p95=%.3f  sandlot p95=%.3f  exec p95=%.3f\n",
			res.ColdStats.N, res.ColdStats.GwP50Ms, res.ColdStats.GwP95Ms, res.ColdStats.GwP99Ms,
			res.ColdStats.P95Ms, res.ColdStats.SandlotP95Ms, res.ColdStats.ExecP95Ms)
		fmt.Printf("      warm: n=%d gw p50=%.3f p95=%.3f p99=%.3f  client p95=%.3f  sandlot p95=%.3f  exec p95=%.3f\n",
			res.WarmStats.N, res.WarmStats.GwP50Ms, res.WarmStats.GwP95Ms, res.WarmStats.GwP99Ms,
			res.WarmStats.P95Ms, res.WarmStats.SandlotP95Ms, res.WarmStats.ExecP95Ms)
		if len(res.ErrKinds) > 0 {
			classes := make([]string, 0, len(res.ErrKinds))
			for k, v := range res.ErrKinds {
				classes = append(classes, fmt.Sprintf("%s=%d", k, v))
			}
			sort.Strings(classes)
			fmt.Printf("      error classes: %s\n", strings.Join(classes, "  "))
		}
	}
	line, err := json.Marshal(res)
	if err != nil {
		fmt.Fprintln(os.Stderr, "loadgen: marshal result:", err)
		os.Exit(2)
	}
	fmt.Printf("LOADGEN_RESULT %s\n", line)
}

// parseTurnSizes parses -requests-per-turn into normalized weights indexed by
// turn size. A single integer N means every turn has exactly N requests
// ("1" = cold-only). The weighted form is "size:weight[,...]" — e.g.
// "1:40,2:35,3:25" draws 1/2/3 requests at 40/35/25. An empty value keeps the
// default distribution.
func parseTurnSizes(s string) ([]float64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return normalizeWeights([]float64{40, 35, 25}), nil
	}
	if !strings.ContainsAny(s, ",:") {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 || n > 100 {
			return nil, fmt.Errorf("-requests-per-turn %q is not a positive request count", s)
		}
		w := make([]float64, n)
		w[n-1] = 1
		return w, nil
	}
	type entry struct {
		size   int
		weight float64
	}
	var entries []entry
	maxSize := 0
	seen := map[int]bool{}
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		k := strings.IndexByte(p, ':')
		if k < 0 {
			return nil, fmt.Errorf("-requests-per-turn entry %q must be size:weight (or a single integer count)", p)
		}
		size, err := strconv.Atoi(strings.TrimSpace(p[:k]))
		if err != nil || size < 1 || size > 100 {
			return nil, fmt.Errorf("-requests-per-turn size %q is not in [1,100]", strings.TrimSpace(p[:k]))
		}
		if seen[size] {
			return nil, fmt.Errorf("-requests-per-turn size %d appears twice", size)
		}
		seen[size] = true
		v, err := strconv.ParseFloat(strings.TrimSpace(p[k+1:]), 64)
		if err != nil || v < 0 || math.IsNaN(v) || math.IsInf(v, 0) {
			return nil, fmt.Errorf("-requests-per-turn weight %q is not a non-negative number", strings.TrimSpace(p[k+1:]))
		}
		entries = append(entries, entry{size: size, weight: v})
		if size > maxSize {
			maxSize = size
		}
	}
	w := make([]float64, maxSize)
	for _, e := range entries {
		w[e.size-1] = e.weight
	}
	sum := 0.0
	for _, v := range w {
		sum += v
	}
	if sum <= 0 {
		return nil, fmt.Errorf("-requests-per-turn weights sum to zero")
	}
	return normalizeWeights(w), nil
}

func normalizeWeights(w []float64) []float64 {
	sum := 0.0
	for _, v := range w {
		sum += v
	}
	if sum <= 0 {
		return w
	}
	out := make([]float64, len(w))
	for i, v := range w {
		out[i] = v / sum
	}
	return out
}

// weightedTurn draws a turn size in [1, len(weights)].
func weightedTurn(rng *rand.Rand, weights []float64) int {
	if len(weights) == 0 {
		return 1
	}
	x := rng.Float64()
	acc := 0.0
	for i, w := range weights {
		acc += w
		if x < acc || i == len(weights)-1 {
			return i + 1
		}
	}
	return len(weights)
}

// run executes the selected workload and builds the result.
func run(opts options, targets []agentTarget) loadResult {
	client, tr := newHTTPClient(opts)
	defer tr.CloseIdleConnections()
	switch opts.workload {
	case "ideal":
		return runIdeal(opts, targets, client)
	case "shaped":
		return runShaped(opts, targets, client)
	}
	return runAgents(opts, targets, client)
}

// newHTTPClient sizes the keep-alive pool for the in-flight cap, not for the
// agent count — thousands of agents spend almost all their time thinking,
// only a few dozen requests overlap.
func newHTTPClient(opts options) (*http.Client, *http.Transport) {
	maxConns := opts.maxInflight
	if maxConns < 1 {
		maxConns = 64
	}
	idle := maxConns
	if idle > 2048 {
		idle = 2048
	}
	tr := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		MaxIdleConns:        idle,
		MaxIdleConnsPerHost: idle,
		MaxConnsPerHost:     maxConns,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  true,
	}
	return &http.Client{Transport: tr, Timeout: 60 * time.Second}, tr
}

// runAgents executes the AI agent model. Each agent runs its own closed loop
// (think → turn of 1..N requests → think), so the offered load adapts to the
// server exactly like real agents do.
func runAgents(opts options, targets []agentTarget, client *http.Client) loadResult {
	start := time.Now()
	measureStart := start.Add(opts.warmup)
	deadline := measureStart.Add(opts.duration)
	perAgent := make([][]sample, len(targets))
	sem := make(chan struct{}, opts.maxInflight)
	var turns atomic.Int64
	var inflight, maxInflight atomic.Int64
	var wg sync.WaitGroup
	for i := range targets {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// Independent deterministic stream per agent: two runs with the
			// same -seed produce the same turn schedule and turn sizes.
			rng := rand.New(rand.NewSource(opts.seed*1_000_003 + int64(i)))
			perAgent[i] = agentLoop(client, opts, targets, i, rng, start, measureStart, deadline, sem, &inflight, &maxInflight, &turns)
		}(i)
	}
	wg.Wait()

	// Measurement window: samples whose request STARTED inside it. Warmup
	// traffic (owner claims, first mounts, adaptive ramp) is excluded.
	var allSamples, samples []sample
	for _, s := range perAgent {
		allSamples = append(allSamples, s...)
		for _, v := range s {
			if !v.start.Before(measureStart) && v.start.Before(deadline) {
				samples = append(samples, v)
			}
		}
	}
	res := buildResult(samples, len(targets), opts.duration, opts.sticky, int(turns.Load()), int(maxInflight.Load()))
	res.ExpectedExpiriesAll = computeExpectedExpiries(allSamples, len(targets), opts.sticky)
	return res
}

// agentLoop is one LLM agent's lifecycle. It is a closed loop: the next turn
// starts -think-min..-think-max after the previous turn's last response.
func agentLoop(client *http.Client, opts options, targets []agentTarget, idx int, rng *rand.Rand,
	start, measureStart, deadline time.Time, sem chan struct{}, inflight, maxInflight *atomic.Int64,
	turns *atomic.Int64) []sample {
	var out []sample

	// Stagger the first turn uniformly over one think window, so a run does
	// not open with every agent firing at t=0 (a thundering herd the real
	// workload never has).
	next := start.Add(randBetween(rng, 0, opts.thinkMax))
	for {
		if now := time.Now(); now.Before(next) {
			time.Sleep(next.Sub(now))
		}
		if !time.Now().Before(deadline) {
			break
		}
		turnStart := time.Now()
		counted := !turnStart.Before(measureStart) && turnStart.Before(deadline)
		out = append(out, runTurn(client, opts, targets[idx], idx, rng, sem, inflight, maxInflight, deadline)...)
		if counted {
			turns.Add(1)
		}
		next = time.Now().Add(randBetween(rng, opts.thinkMin, opts.thinkMax))
	}
	return out
}

// runTurn issues one turn: the first request is cold, and the follow-ups are
// sent immediately so they land inside the sticky window and reuse the VM.
// Both workloads share this shape.
func runTurn(client *http.Client, opts options, a agentTarget, idx int, rng *rand.Rand,
	sem chan struct{}, inflight, maxInflight *atomic.Int64, deadline time.Time) []sample {
	var out []sample
	requests := weightedTurn(rng, opts.turnWeights)
	for j := 0; j < requests; j++ {
		if j > 0 {
			if gap := randBetween(rng, 0, opts.intraGap); gap > 0 {
				time.Sleep(gap)
			}
			if !time.Now().Before(deadline) {
				break
			}
		}
		n := inflight.Add(1)
		for {
			cur := maxInflight.Load()
			if n <= cur || maxInflight.CompareAndSwap(cur, n) {
				break
			}
		}
		s := execWithRetry(client, opts.gateway, a, idx, opts.retryBusy, opts.retryBase, rng, sem)
		inflight.Add(-1)
		out = append(out, s)
	}
	return out
}

// runIdeal is the capability probe: one paced lane per microVM, each issuing
// a turn every -period-ms with no between-turn think gap. The lanes are
// staggered across
// one period so the pool is fed evenly. There is no over-offer — the caller
// sweeps periods and the smallest period with no BUSY attempts is the
// collision-free reuse rate with every VM continuously fed. This is an
// idealized model, not a business workload.
func runIdeal(opts options, targets []agentTarget, client *http.Client) loadResult {
	start := time.Now()
	measureStart := start.Add(opts.warmup)
	deadline := measureStart.Add(opts.duration)
	lanes := opts.lanes
	perLane := make([][]sample, lanes)
	sem := make(chan struct{}, opts.maxInflight)
	var turns atomic.Int64
	var inflight, maxInflight atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < lanes; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(opts.seed*1_000_003 + int64(i)))
			next := start.Add(time.Duration(i) * opts.period / time.Duration(lanes))
			for {
				if now := time.Now(); now.Before(next) {
					time.Sleep(next.Sub(now))
				}
				if !time.Now().Before(deadline) {
					break
				}
				turnStart := time.Now()
				counted := !turnStart.Before(measureStart) && turnStart.Before(deadline)
				turnSamples := runTurn(client, opts, targets[i], i, rng, sem, &inflight, &maxInflight, deadline)
				perLane[i] = append(perLane[i], turnSamples...)
				if counted {
					turns.Add(1)
				}
				// Self-clocked: the next turn starts one period after THIS
				// one started, but never inside the previous lease's sticky
				// window — every turn's first request must be genuinely cold.
				// A turn that overruns the period waits for its last response
				// plus the sticky window; if the pool is still unmounting, the
				// next request shows up as BUSY.
				next = turnStart.Add(opts.period)
				lastEnd := time.Time{}
				for _, s := range turnSamples {
					if s.end.After(lastEnd) {
						lastEnd = s.end
					}
				}
				if cold := lastEnd.Add(opts.sticky); cold.After(next) {
					next = cold
				}
			}
		}(i)
	}
	wg.Wait()

	var allSamples, samples []sample
	for _, s := range perLane {
		allSamples = append(allSamples, s...)
		for _, v := range s {
			if !v.start.Before(measureStart) && v.start.Before(deadline) {
				samples = append(samples, v)
			}
		}
	}
	res := buildResult(samples, lanes, opts.duration, opts.sticky, int(turns.Load()), int(maxInflight.Load()))
	res.Mode = "ideal"
	res.Lanes = lanes
	res.PeriodMs = round3(float64(opts.period) / float64(time.Millisecond))
	res.ExpectedExpiriesAll = computeExpectedExpiries(allSamples, lanes, opts.sticky)
	return res
}

// shapedTurn is one AI agent turn waiting for the lane's server slot.
type shapedTurn struct {
	agent    int // global agent index
	requests int
	done     chan struct{}
}

// runShaped is the traffic-shaped capability probe: every lane aggregates
// MANY AI agents (each with its own sandfs and think time), but the lane
// releases requests to the gateway one at a time — one in-flight cold per
// microVM slot, self-clocked on the previous response plus the sticky window
// plus -hold-ms (the slot's unmount budget).
// Agent turns queue at the lane like cars at a toll gate; the gate opens at
// the VM's cycle rate. Unlike -workload ideal (one agent per lane), the
// offered traffic is a real agent population behind a real admission queue —
// the realistic version of the capability ceiling.
//
// Sizing: one agent offers ~1 cold turn per think interval, so a lane that
// serves R turns/s needs about R x mean-think agents to stay fed. The caller
// sizes -lane-agents from the period sweep point.
func runShaped(opts options, targets []agentTarget, client *http.Client) loadResult {
	start := time.Now()
	measureStart := start.Add(opts.warmup)
	deadline := measureStart.Add(opts.duration)
	lanes := opts.lanes
	perLaneAgents := opts.laneAgents
	total := lanes * perLaneAgents
	perLane := make([][]sample, lanes)
	sem := make(chan struct{}, opts.maxInflight)
	var turns atomic.Int64
	var inflight, maxInflight atomic.Int64
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < lanes; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			serverRng := rand.New(rand.NewSource(opts.seed*2_000_003 + int64(i)))
			turnCh := make(chan shapedTurn, perLaneAgents)
			// The agent population: closed loops (think → enqueue turn → wait
			// until the lane served it → think again), so the queue per lane
			// is bounded by one turn per agent.
			var wgAgents sync.WaitGroup
			for a := 0; a < perLaneAgents; a++ {
				wgAgents.Add(1)
				go func(a int) {
					defer wgAgents.Done()
					idx := i*perLaneAgents + a
					rng := rand.New(rand.NewSource(opts.seed*3_000_007 + int64(idx)))
					next := start.Add(randBetween(rng, 0, opts.thinkMax))
					for {
						select {
						case <-stop:
							return
						default:
						}
						if now := time.Now(); now.Before(next) {
							time.Sleep(next.Sub(now))
						}
						if !time.Now().Before(deadline) {
							return
						}
						t := shapedTurn{
							agent:    idx,
							requests: weightedTurn(rng, opts.turnWeights),
							done:     make(chan struct{}),
						}
						select {
						case turnCh <- t:
						case <-stop:
							return
						}
						select {
						case <-t.done:
						case <-stop:
							return
						}
						next = time.Now().Add(randBetween(rng, opts.thinkMin, opts.thinkMax))
					}
				}(a)
			}
			go func() {
				wgAgents.Wait()
				close(turnCh)
			}()
			// The toll gate: one request in flight, paced at the VM cycle.
			var out []sample
			nextAllowed := time.Time{}
			for t := range turnCh {
				if !time.Now().Before(deadline) {
					close(t.done)
					continue
				}
				if !nextAllowed.IsZero() {
					if now := time.Now(); now.Before(nextAllowed) {
						time.Sleep(nextAllowed.Sub(now))
					}
				}
				if !time.Now().Before(deadline) {
					close(t.done)
					continue
				}
				turnStart := time.Now()
				counted := !turnStart.Before(measureStart) && turnStart.Before(deadline)
				var lastEnd time.Time
				for j := 0; j < t.requests; j++ {
					if !time.Now().Before(deadline) {
						break
					}
					n := inflight.Add(1)
					for {
						cur := maxInflight.Load()
						if n <= cur || maxInflight.CompareAndSwap(cur, n) {
							break
						}
					}
					// Follow-ups (j>0) are sent immediately after the previous
					// response — warm under the sticky window. Between turns
					// the pace above applies.
					s := execWithRetry(client, opts.gateway, targets[t.agent], t.agent,
						opts.retryBusy, opts.retryBase, serverRng, sem)
					inflight.Add(-1)
					out = append(out, s)
					lastEnd = s.end
				}
				// A new turn starts no earlier than one period after this one
				// started, and only after the previous turn's lease expired
				// AND the slot's unmount budget elapsed: the shaper holds the
				// VM slot for sticky + hold, so the async unmount is part of
				// the paced cycle instead of surfacing as BUSY retries.
				nextAllowed = turnStart.Add(opts.period)
				if e := lastEnd.Add(opts.sticky + opts.hold); e.After(nextAllowed) {
					nextAllowed = e
				}
				if counted {
					turns.Add(1)
				}
				close(t.done)
			}
			perLane[i] = out
		}(i)
	}
	go func() {
		time.Sleep(time.Until(deadline.Add(5 * time.Second)))
		close(stop)
	}()
	wg.Wait()

	var allSamples, samples []sample
	for _, s := range perLane {
		allSamples = append(allSamples, s...)
		for _, v := range s {
			if !v.start.Before(measureStart) && v.start.Before(deadline) {
				samples = append(samples, v)
			}
		}
	}
	res := buildResult(samples, total, opts.duration, opts.sticky, int(turns.Load()), int(maxInflight.Load()))
	res.Mode = "shaped"
	res.Lanes = lanes
	res.PeriodMs = round3(float64(opts.period) / float64(time.Millisecond))
	res.ExpectedExpiriesAll = computeExpectedExpiries(allSamples, total, opts.sticky)
	return res
}

func randBetween(rng *rand.Rand, lo, hi time.Duration) time.Duration {
	if hi <= lo {
		return lo
	}
	return lo + time.Duration(rng.Int63n(int64(hi-lo)+1))
}

// execWithRetry performs one request under the busy-retry policy: a
// NO_AVAILABLE_SANDBOX response is retried up to retryBusy more times with
// full-jitter backoff. The semaphore is held per ATTEMPT, so a request waiting
// out a backoff does not consume an in-flight slot (and cannot throttle every
// other agent). The returned sample's start is the first attempt, so its
// client latency is the business-visible one; its gw/sandlot/exec durations
// come from the successful attempt.
func execWithRetry(client *http.Client, gateway string, a agentTarget, agentIdx int,
	retryBusy int, retryBase time.Duration, rng *rand.Rand, sem chan struct{}) sample {
	first := time.Now()
	busy := 0
	var s sample
	var okStart time.Time
	for attempt := 0; ; attempt++ {
		sem <- struct{}{}
		s = execOnce(client, gateway, a, agentIdx)
		<-sem
		if s.ok {
			okStart = s.start
		}
		if !s.isBusy() {
			break
		}
		busy++
		if attempt >= retryBusy {
			break
		}
		if d := retryDelay(rng, retryBase, attempt); d > 0 {
			time.Sleep(d)
		}
	}
	s.start = first
	s.okStart = okStart
	s.busyAttempts = busy
	return s
}

// retryDelay is full-jitter exponential backoff for retry attempt n: uniform
// in [0, base*2^min(n,3)]. A single collision costs a few milliseconds, while
// a saturated pool spreads the retry wave instead of synchronizing it.
func retryDelay(rng *rand.Rand, base time.Duration, attempt int) time.Duration {
	if base <= 0 {
		return 0
	}
	shift := attempt
	if shift > 3 {
		shift = 3
	}
	max := base << shift
	if max <= 0 {
		return 0
	}
	return time.Duration(rng.Int63n(int64(max) + 1))
}

// execOnce posts one sync exec and classifies the outcome. The body is always
// fully drained and closed so the connection returns to the idle pool.
func execOnce(client *http.Client, gateway string, a agentTarget, agentIdx int) sample {
	s := sample{agent: agentIdx, start: time.Now()}
	body := fmt.Sprintf(`{"sandfs_id":%q,"code":"echo ok","timeout":15}`, a.Sandfs)
	req, err := http.NewRequest(http.MethodPost, gateway+"/agent/execute", strings.NewReader(body))
	if err != nil {
		s.end = time.Now()
		s.err = err.Error()
		return s
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+a.Key)
	// X-Sandswap-Api-Key survives cross-host 307 redirects (Go strips the
	// Authorization header on cross-host redirects).
	req.Header.Set("X-Sandswap-Api-Key", a.Key)

	resp, err := client.Do(req)
	if err != nil {
		s.end = time.Now()
		s.err = err.Error()
		return s
	}
	s.code = resp.StatusCode
	leaseHit := resp.Header.Get("X-Sandbox-Lease") == "hit"
	data, readErr := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	s.end = time.Now()
	if readErr != nil {
		s.err = "read body: " + readErr.Error()
		return s
	}
	if resp.StatusCode != http.StatusOK {
		// The gateway's error bodies are {"error":...,"error_code":...} for
		// named resilience states. Capture the code so the caller can tell
		// capacity saturation (NO_AVAILABLE_SANDBOX) from a real failure.
		var eb struct {
			ErrorCode string `json:"error_code"`
		}
		_ = json.Unmarshal(data, &eb)
		s.errCode = eb.ErrorCode
		s.err = fmt.Sprintf("HTTP %d: %s", resp.StatusCode, truncate(string(data), 120))
		return s
	}
	var er struct {
		Status            string `json:"status"`
		Error             string `json:"error"`
		GatewayDurationNs uint64 `json:"gateway_duration_ns"`
		SandlotDurationNs uint64 `json:"sandlot_duration_ns"`
		ExecDurationNs    uint64 `json:"exec_duration_ns"`
	}
	if err := json.Unmarshal(data, &er); err != nil {
		s.err = "decode response: " + err.Error()
		return s
	}
	if er.Error != "" {
		s.err = "gateway: " + er.Error
		return s
	}
	if er.Status != "done" {
		s.err = "status=" + er.Status
		return s
	}
	s.ok = true
	// Warm/cold is only meaningful for a completed request.
	s.warm = leaseHit
	s.gw = time.Duration(er.GatewayDurationNs)
	s.sandlot = time.Duration(er.SandlotDurationNs)
	s.exec = time.Duration(er.ExecDurationNs)
	return s
}

// buildResult aggregates samples into the result, including the per-class
// (warm/cold) summaries.
func buildResult(samples []sample, agents int, duration, sticky time.Duration, turns, maxInflight int) loadResult {
	res := loadResult{
		Mode:        "agents",
		Agents:      agents,
		DurationSec: round3(duration.Seconds()),
		Turns:       turns,
		MaxInflight: maxInflight,
		ErrKinds:    map[string]int{},
	}

	var (
		allLat, allGw, allSand, allExec     []time.Duration
		warmLat, warmGw, warmSand, warmExec []time.Duration
		coldLat, coldGw, coldSand, coldExec []time.Duration
	)
	for _, s := range samples {
		res.BusyAttempts += s.busyAttempts
		if s.ok && s.busyAttempts > 0 {
			res.BusyRetried++
		}
		if !s.ok {
			res.Err++
			res.ErrKinds[classifyErr(s)]++
			continue
		}
		res.OK++
		lat := s.end.Sub(s.start)
		allLat = append(allLat, lat)
		if s.gw > 0 {
			allGw = append(allGw, s.gw)
		}
		if s.sandlot > 0 {
			allSand = append(allSand, s.sandlot)
		}
		if s.exec > 0 {
			allExec = append(allExec, s.exec)
		}
		if s.warm {
			res.Warm++
			warmLat = append(warmLat, lat)
			if s.gw > 0 {
				warmGw = append(warmGw, s.gw)
			}
			if s.sandlot > 0 {
				warmSand = append(warmSand, s.sandlot)
			}
			if s.exec > 0 {
				warmExec = append(warmExec, s.exec)
			}
		} else {
			res.Cold++
			coldLat = append(coldLat, lat)
			if s.gw > 0 {
				coldGw = append(coldGw, s.gw)
			}
			if s.sandlot > 0 {
				coldSand = append(coldSand, s.sandlot)
			}
			if s.exec > 0 {
				coldExec = append(coldExec, s.exec)
			}
		}
	}
	sortDurations(allLat)
	sortDurations(allGw)
	sortDurations(allSand)
	sortDurations(allExec)
	sortDurations(warmLat)
	sortDurations(warmGw)
	sortDurations(warmSand)
	sortDurations(warmExec)
	sortDurations(coldLat)
	sortDurations(coldGw)
	sortDurations(coldSand)
	sortDurations(coldExec)

	if duration > 0 {
		res.RPS = round2(float64(res.OK) / duration.Seconds())
		res.ColdRPS = round2(float64(res.Cold) / duration.Seconds())
		res.WarmRPS = round2(float64(res.Warm) / duration.Seconds())
	}
	if res.Warm+res.Cold > 0 {
		res.WarmHitPct = round2(100 * float64(res.Warm) / float64(res.Warm+res.Cold))
	}
	res.P50Ms = msOf(percentile(allLat, 0.50))
	res.P95Ms = msOf(percentile(allLat, 0.95))
	res.P99Ms = msOf(percentile(allLat, 0.99))
	res.GwN = len(allGw)
	res.GwP50Ms = msOf(percentile(allGw, 0.50))
	res.GwP95Ms = msOf(percentile(allGw, 0.95))
	res.GwP99Ms = msOf(percentile(allGw, 0.99))
	res.SandlotP95Ms = msOf(percentile(allSand, 0.95))
	res.ExecP95Ms = msOf(percentile(allExec, 0.95))
	res.WarmStats = summarize(warmLat, warmGw, warmSand, warmExec)
	res.ColdStats = summarize(coldLat, coldGw, coldSand, coldExec)
	res.ExpectedExpiries = computeExpectedExpiries(samples, agents, sticky)
	return res
}

func summarize(lat, gw, sand, exec []time.Duration) classStats {
	st := classStats{N: len(lat)}
	if len(lat) == 0 {
		return st
	}
	st.P50Ms = msOf(percentile(lat, 0.50))
	st.P95Ms = msOf(percentile(lat, 0.95))
	st.P99Ms = msOf(percentile(lat, 0.99))
	st.GwN = len(gw)
	st.GwP50Ms = msOf(percentile(gw, 0.50))
	st.GwP95Ms = msOf(percentile(gw, 0.95))
	st.GwP99Ms = msOf(percentile(gw, 0.99))
	st.SandlotP95Ms = msOf(percentile(sand, 0.95))
	st.ExecP95Ms = msOf(percentile(exec, 0.95))
	return st
}

func sortDurations(v []time.Duration) {
	sort.Slice(v, func(i, j int) bool { return v[i] < v[j] })
}

// percentile returns the p-th percentile (0..1) of ascending-sorted durations,
// using the repo-wide sorted[int(n*p)] convention (clamped).
func percentile(sorted []time.Duration, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(float64(len(sorted)) * p)
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

// msOf converts a duration to milliseconds with µs resolution.
func msOf(d time.Duration) float64 {
	return math.Round(float64(d)/1e3) / 1e3
}

func round2(v float64) float64 { return math.Round(v*100) / 100 }
func round3(v float64) float64 { return math.Round(v*1000) / 1000 }

// computeExpectedExpiries counts, for each agent independently, the gaps
// between one mounted request's completion and the next mounted request that
// exceed sticky. A lease can only exist after a request that actually
// MOUNTED: failed requests mounted nothing, so they neither create an expiry
// nor continue a lease, and only the completed (ok) samples form the chain.
// The gap starts from the NEXT completed request's okStart (the attempt that
// mounted), not its first attempt: under the retry policy a request can start
// a 503 attempt inside the sticky window and mount long after it, and the
// lease from the previous request expires in between. Overlapping requests
// yield a non-positive gap and are never counted.
func computeExpectedExpiries(samples []sample, agents int, sticky time.Duration) int {
	per := make([][]sample, agents)
	for _, s := range samples {
		if !s.ok || s.agent < 0 || s.agent >= agents {
			continue
		}
		per[s.agent] = append(per[s.agent], s)
	}
	count := 0
	for _, v := range per {
		sort.SliceStable(v, func(i, j int) bool { return v[i].start.Before(v[j].start) })
		for i := 1; i < len(v); i++ {
			start := v[i].okStart
			if start.IsZero() {
				start = v[i].start
			}
			if start.Sub(v[i-1].end) > sticky {
				count++
			}
		}
	}
	return count
}

// loadAgents parses the agent list file.
func loadAgents(path string) ([]agentTarget, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open agents file: %w", err)
	}
	defer f.Close()
	var out []agentTarget
	sc := bufio.NewScanner(f)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 3 {
			return nil, fmt.Errorf("agents file line %d: want \"agent_id api_key sandfs_id\", got %d fields", lineNo, len(fields))
		}
		out = append(out, agentTarget{ID: fields[0], Key: fields[1], Sandfs: fields[2]})
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read agents file: %w", err)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("agents file %s contains no agents", path)
	}
	return out, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// classifyErr reduces a failed sample to a short class for the per-level
// error table: "HTTP 503 NO_AVAILABLE_SANDBOX" (status + named gateway code),
// or "transport: ..." when no HTTP response was received.
func classifyErr(s sample) string {
	if s.code > 0 {
		class := fmt.Sprintf("HTTP %d", s.code)
		if s.errCode != "" {
			class += " " + s.errCode
		}
		return class
	}
	return "transport: " + truncate(s.err, 60)
}

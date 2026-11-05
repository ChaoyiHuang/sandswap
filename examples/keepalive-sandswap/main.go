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
// Command keepalive-sandswap demonstrates the single most effective
// client-side latency optimization for the Sandswap agent HTTP API: hold ONE
// persistent HTTP connection (keep-alive / HTTP/2) for the process lifetime
// and run every command over it, instead of paying TCP connect + TLS
// handshake on every call.
// httptrace proves the reuse: request #1 dials and handshakes; requests
// #2..N report "conn reused" and their latency drops to the round-trip floor.
// Usage:
//	go run . -addr https://gateway:3000 -api-key sk-sandswap-agent-... \
//	         -sandfs-id sandfs-xxx [-ca ca.pem] [-runs 5] [-burst 4] [-pool 8]
// -loop switches to the long-lived-session demo: one command every -think for
// -for, kept warm by a GET /health heartbeat every -ping — the production
// posture for an agent that stays connected and reconnects transparently if
// the connection ever breaks.
// Every flag falls back to the same env var the other examples use
// (SANDSWAP_GATEWAY_URL / SANDSWAP_API_KEY / SANDSWAP_SANDFS_ID /
// SANDSWAP_CA_CERT).

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"os"
	"strings"
	"sync"
	"time"
)

type config struct {
	baseURL  string
	apiKey   string
	sandfsID string
	caPath   string
	code     string
	runs     int
	burst    int
	pool     int
	loop     bool
	think    time.Duration
	forDur   time.Duration
	ping     time.Duration
}

func main() {
	cfg := &config{}
	flag.StringVar(&cfg.baseURL, "addr", envOr("SANDSWAP_GATEWAY_URL"), "gateway base URL, e.g. https://gateway:3000 (env SANDSWAP_GATEWAY_URL)")
	flag.StringVar(&cfg.apiKey, "api-key", envOr("SANDSWAP_API_KEY"), "agent API key (env SANDSWAP_API_KEY)")
	flag.StringVar(&cfg.sandfsID, "sandfs-id", envOr("SANDSWAP_SANDFS_ID"), "SandFS instance to execute in (env SANDSWAP_SANDFS_ID)")
	flag.StringVar(&cfg.caPath, "ca", envOr("SANDSWAP_CA_CERT"), "CA bundle for a self-signed gateway cert (env SANDSWAP_CA_CERT)")
	flag.StringVar(&cfg.code, "code", "echo keep-alive demo", "command to execute")
	flag.IntVar(&cfg.runs, "runs", 5, "sequential executes after the connection is open")
	flag.IntVar(&cfg.burst, "burst", 4, "concurrent executes in the final burst")
	flag.IntVar(&cfg.pool, "pool", 8, "http.Transport.MaxIdleConnsPerHost (idle connections KEPT for reuse)")
	flag.BoolVar(&cfg.loop, "loop", false, "long-lived-session demo: commands every -think for -for, heartbeat every -ping")
	flag.DurationVar(&cfg.think, "think", 5*time.Second, "-loop: pause between commands (agent think-time)")
	flag.DurationVar(&cfg.forDur, "for", 60*time.Second, "-loop: total demo duration")
	flag.DurationVar(&cfg.ping, "ping", 30*time.Second, "-loop: heartbeat GET /health interval, kept below the shortest idle timeout on the path (gateway -idle-timeout, any LB/NAT); 0 = off, which is fine with gateway -idle-timeout -1 and no intermediary. The seconds-scale default is demo compression")
	flag.Parse()

	if cfg.baseURL == "" || cfg.apiKey == "" || cfg.sandfsID == "" {
		fmt.Fprintln(os.Stderr, "required: -addr, -api-key, -sandfs-id (or their env fallbacks)")
		flag.Usage()
		os.Exit(2)
	}
	cfg.baseURL = strings.TrimRight(cfg.baseURL, "/")

	// The ONE client for the whole process. Every request below goes through
	// it — that shared connection pool is the entire optimization.
	client, err := newKeepAliveClient(cfg.pool, cfg.caPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if cfg.loop {
		runLoop(client, cfg)
		return
	}

	fmt.Println("Sandswap keep-alive demo")
	fmt.Printf("  gateway   : %s\n", cfg.baseURL)
	fmt.Printf("  sandfs    : %s\n", cfg.sandfsID)
	fmt.Printf("  transport : keep-alive (IdleConnTimeout=0, MaxIdleConnsPerHost=%d)\n", cfg.pool)
	fmt.Println("  timings   : total = client total: request sent -> response received (whole chain)")
	fmt.Println("              gateway = gateway end-to-end (includes sandlot); sandlot (includes exec); exec = inside the microVM (warden)")
	fmt.Println()

	// -- 1. Warm-up: the only dial + TLS handshake of the whole run. --------
	fmt.Println("[1] GET /health — opens THE connection (dial + handshake, once)")
	body, _, st, err := do(context.Background(), client, http.MethodGet, cfg.baseURL+"/health", cfg.apiKey, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  FAIL: %v\n", err)
		os.Exit(1)
	}
	if st.status != http.StatusOK {
		exitBadStatus(st.status, body)
	}
	fmt.Printf("  %d OK  total=%s  dial=%s  tls=%s  proto=%s  conn=%s\n\n",
		st.status, ms(st.totalMS), ms(st.dialMS), ms(st.tlsMS), st.proto, connWord(st.reused))

	// -- 2. Sequential executes: everything below rides the warm conn. -----
	fmt.Printf("[2] %d sequential POST /agent/execute — all reuse that connection\n", cfg.runs)
	for i := 1; i <= cfg.runs; i++ {
		body, hdr, st, err := exec(context.Background(), client, cfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  #%d FAIL: %v\n", i, err)
			os.Exit(1)
		}
		if st.status != http.StatusOK {
			exitBadStatus(st.status, body)
		}
		var er execResponse
		if err := json.Unmarshal(body, &er); err != nil {
			fmt.Fprintf(os.Stderr, "  #%d FAIL: bad response JSON: %v\n", i, err)
			os.Exit(1)
		}
		fmt.Printf("  #%d  %d  total=%s  gateway=%s  sandlot=%s  exec=%s  conn=%s  lease=%-3s  exit=%s  out=%q\n",
			i, st.status, ms(st.totalMS), ms(nsToMs(er.GatewayDurationNs)),
			ms(nsToMs(er.SandlotDurationNs)), ms(nsToMs(er.ExecDurationNs)),
			connWord(st.reused), lease(hdr), exitWord(er), strings.TrimSpace(er.Stdout))
	}
	fmt.Println()

	// -- 3. Concurrent burst: keep-alive is per POOL, not one socket. -------
	// Over HTTP/1.1 each in-flight request holds its own connection (bursts
	// wider than the pool dial extra ones); over HTTP/2 all requests
	// multiplex over the one connection. Either way, MaxIdleConnsPerHost is
	// what decides how many survive the burst for the NEXT call to reuse.
	fmt.Printf("[3] burst of %d concurrent executes — pool sizing in action\n", cfg.burst)
	results := make([]string, cfg.burst)
	var wg sync.WaitGroup
	for i := 0; i < cfg.burst; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			body, hdr, st, err := exec(context.Background(), client, cfg)
			if err != nil {
				results[i] = fmt.Sprintf("  #%d FAIL: %v", i+1, err)
				return
			}
			if st.status != http.StatusOK {
				results[i] = fmt.Sprintf("  #%d HTTP %d: %s", i+1, st.status, truncate(body, 200))
				return
			}
			var er execResponse
			if err := json.Unmarshal(body, &er); err != nil {
				results[i] = fmt.Sprintf("  #%d FAIL: bad response JSON: %v", i+1, err)
				return
			}
			results[i] = fmt.Sprintf("  #%d  %d  total=%s  gateway=%s  sandlot=%s  exec=%s  conn=%s  lease=%-3s  exit=%s",
				i+1, st.status, ms(st.totalMS), ms(nsToMs(er.GatewayDurationNs)),
				ms(nsToMs(er.SandlotDurationNs)), ms(nsToMs(er.ExecDurationNs)),
				connWord(st.reused), lease(hdr), exitWord(er))
		}(i)
	}
	wg.Wait()
	for _, r := range results {
		fmt.Println(r)
	}

	fmt.Println("\nOne client, one warm pool: no dial/TLS after step [1] unless the burst exceeded -pool.")
}

// newKeepAliveClient returns the *http.Client to reuse for the whole process.
// Three settings carry the demo:
//
//   - IdleConnTimeout: 0 — never close idle connections on the client side;
//     the gateway's -idle-timeout (default 3600s) governs instead. Go's
//     DefaultTransport drops idle connections after 90s, right in the middle
//     of an agent's think-time between tool calls.
//   - MaxIdleConnsPerHost: pool — how many idle connections are KEPT for the
//     next request. The Go default is 2, so a wider burst's connections are
//     torn down immediately and re-paid on the next burst. Size it to your
//     max parallelism.
//   - ForceAttemptHTTP2: true — required once TLSClientConfig is non-nil.
//     With TLS, the gateway negotiates HTTP/2 via ALPN and every concurrent
//     request multiplexes over ONE connection (HTTP/1.1 keep-alive still
//     gives one connection per in-flight request).
func newKeepAliveClient(pool int, caPath string) (*http.Client, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12} // gateway enforces TLS 1.2+
	if caPath != "" {
		caPEM, err := os.ReadFile(caPath)
		if err != nil {
			return nil, fmt.Errorf("read CA cert %s: %w", caPath, err)
		}
		certPool := x509.NewCertPool()
		if !certPool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("no valid certs in CA bundle %s", caPath)
		}
		tlsCfg.RootCAs = certPool
	}
	transport := &http.Transport{
		TLSClientConfig: tlsCfg,
		// TCP keepalive probes (every 30s): detect a half-open connection
		// (peer died without FIN/RST) and keep NAT/LB port mappings alive
		// across long think-times. NOTE: probes do NOT reset the gateway's
		// -idle-timeout — only a real HTTP request does; that is the
		// heartbeat's job (-ping in -loop mode).
		DialContext:         (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		IdleConnTimeout:     0, // client never times out an idle conn
		MaxIdleConns:        0, // unlimited total idle conns
		MaxIdleConnsPerHost: pool,
		ForceAttemptHTTP2:   true,
	}
	// Deliberately NO Client.Timeout: a sync exec may legitimately run up to
	// the gateway's -max-exec-timeout-sec (default max 180s). Bound
	// individual requests with a context instead.
	return &http.Client{Transport: transport}, nil
}

// connStat is what httptrace saw for one request.
type connStat struct {
	status  int
	proto   string // "HTTP/2.0" / "HTTP/1.1" (from the response)
	reused  bool   // rode an already-established connection
	dialMS  float64
	tlsMS   float64
	totalMS float64
}

// do performs one request on the shared client, instrumented with httptrace.
func do(ctx context.Context, c *http.Client, method, url, apiKey string, body []byte) ([]byte, http.Header, connStat, error) {
	var st connStat
	var dialStart, tlsStart time.Time
	trace := &httptrace.ClientTrace{
		ConnectStart: func(network, addr string) { dialStart = time.Now() },
		ConnectDone: func(network, addr string, err error) {
			if err == nil && !dialStart.IsZero() {
				st.dialMS = msSince(dialStart)
			}
		},
		TLSHandshakeStart: func() { tlsStart = time.Now() },
		TLSHandshakeDone: func(_ tls.ConnectionState, err error) {
			if err == nil && !tlsStart.IsZero() {
				st.tlsMS = msSince(tlsStart)
			}
		},
		GotConn: func(info httptrace.GotConnInfo) { st.reused = info.Reused },
	}
	ctx = httptrace.WithClientTrace(ctx, trace)

	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, rd)
	if err != nil {
		return nil, nil, st, err
	}
	req.Header.Set("Content-Type", "application/json")
	// Primary auth. Go's http.Client strips Authorization on cross-host
	// redirects, so ALSO send the custom header below.
	req.Header.Set("Authorization", "Bearer "+apiKey)
	// X-Sandswap-Api-Key survives the cross-host 307 ownership redirect,
	// keeping the replayed request authenticated at the owner gateway.
	req.Header.Set("X-Sandswap-Api-Key", apiKey)

	start := time.Now()
	resp, err := c.Do(req)
	if err != nil {
		return nil, nil, st, err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	st.totalMS = msSince(start)
	st.status = resp.StatusCode
	st.proto = resp.Proto
	return respBody, resp.Header, st, err
}

type execRequest struct {
	SandfsID string `json:"sandfs_id"`
	Code     string `json:"code"`
	Language string `json:"language"`
}

type execResponse struct {
	Stdout            string `json:"stdout"`
	ExitCode          *int   `json:"exit_code"`
	Status            string `json:"status"`
	GatewayDurationNs uint64 `json:"gateway_duration_ns"` // gateway E2E wall time (includes waiting for sandlot)
	SandlotDurationNs uint64 `json:"sandlot_duration_ns"` // sandlot dispatch→response (includes waiting for warden)
	ExecDurationNs    uint64 `json:"exec_duration_ns"`    // warden wall time: spawn + exec inside the microVM
}

func exec(ctx context.Context, c *http.Client, cfg *config) ([]byte, http.Header, connStat, error) {
	payload, err := json.Marshal(execRequest{
		SandfsID: cfg.sandfsID,
		Code:     cfg.code,
		Language: "shell",
	})
	if err != nil {
		return nil, nil, connStat{}, err
	}
	return do(ctx, c, http.MethodPost, cfg.baseURL+"/agent/execute", cfg.apiKey, payload)
}

func health(ctx context.Context, c *http.Client, baseURL, apiKey string) ([]byte, http.Header, connStat, error) {
	return do(ctx, c, http.MethodGet, baseURL+"/health", apiKey, nil)
}

// connTally sums up connection behavior across a whole run.
type connTally struct {
	mu       sync.Mutex
	requests int
	dials    int // requests that had to (re)establish a connection
	failures int
}

func (t *connTally) add(st connStat, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.requests++
	if err != nil {
		t.failures++
		return
	}
	if !st.reused {
		t.dials++
	}
}

func (t *connTally) snapshot() (requests, dials, failures, avoided int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.requests, t.dials, t.failures, t.requests - t.dials - t.failures
}

// runLoop demonstrates the production posture for a long-lived agent session:
//
//   - ONE connection, opened once and kept warm across think-time gaps by a
//     cheap unauthenticated GET /health heartbeat (an HTTP request is the ONLY
//     thing that resets the gateway's -idle-timeout — TCP keepalive probes do
//     not). The heartbeat is only needed when something on the path idles the
//     connection out; with gateway -idle-timeout -1 and no LB/NAT, -ping 0 is
//     fine. The seconds-scale defaults exist so a short run shows the
//     mechanism — production cadence is minutes.
//   - Transparent reconnection: if the connection ever breaks (gateway
//     restart, load-shed, idle timeout, NAT/LB teardown) the next request
//     simply dials a new one — there is NO session state to rebuild, auth
//     rides on every request, so the only cost is one handshake. You see it
//     here as conn=NEW appearing once, after which everything is reused again.
//
// To watch it happen on purpose: run the gateway with -idle-timeout 5 and
// this demo with -think 10s -ping 0 — every other command shows conn=NEW.
// Then add -ping 2s: the heartbeat keeps the idle timer reset and every
// command is conn=reused again. Or just restart the gateway mid-loop.
func runLoop(client *http.Client, cfg *config) {
	tally := &connTally{}
	start := time.Now()
	rel := func() string { return fmt.Sprintf("%5.1fs", time.Since(start).Seconds()) }

	fmt.Println("Sandswap keep-alive LONG-LOOP demo")
	fmt.Printf("  gateway   : %s\n", cfg.baseURL)
	fmt.Printf("  sandfs    : %s\n", cfg.sandfsID)
	fmt.Printf("  cadence   : 1 command / %s think-time, for %s; heartbeat / %s\n",
		cfg.think, cfg.forDur, cfg.ping)
	fmt.Println("  timings   : total = client total: request sent -> response received (whole chain)")
	fmt.Println("              gateway = gateway end-to-end (includes sandlot); sandlot (includes exec); exec = inside the microVM (warden)")
	fmt.Println()

	// Open THE connection.
	body, _, st, err := health(context.Background(), client, cfg.baseURL, cfg.apiKey)
	tally.add(st, err)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  %s  warm-up FAIL: %v\n", rel(), err)
		os.Exit(1)
	}
	if st.status != http.StatusOK {
		exitBadStatus(st.status, body)
	}
	fmt.Printf("  %s  warm-up GET /health  conn=%-6s dial=%s tls=%s proto=%s\n\n",
		rel(), connWord(st.reused), ms(st.dialMS), ms(st.tlsMS), st.proto)

	// Heartbeat goroutine: ping /health every -ping. Log every ping (it IS
	// the mechanism), plus reconnect/failure transitions.
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if cfg.ping <= 0 {
			return
		}
		ticker := time.NewTicker(cfg.ping)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				_, _, pst, perr := health(context.Background(), client, cfg.baseURL, cfg.apiKey)
				tally.add(pst, perr)
				switch {
				case perr != nil:
					fmt.Printf("  %s  ping  GET /health  FAIL: %v — transport redials on the next request\n", rel(), perr)
				case !pst.reused:
					fmt.Printf("  %s  ping  GET /health  conn=NEW     (reconnected — one handshake re-paid, warm again)\n", rel())
				default:
					fmt.Printf("  %s  ping  GET /health  conn=reused (idle timer reset)\n", rel())
				}
			}
		}
	}()

	// Command loop: one exec per think-time tick.
	i := 0
	for time.Since(start) < cfg.forDur {
		i++
		body, hdr, st, err := exec(context.Background(), client, cfg)
		tally.add(st, err)
		switch {
		case err != nil:
			fmt.Printf("  %s  cmd #%-3d FAIL: %v\n", rel(), i, err)
		case st.status != http.StatusOK:
			fmt.Printf("  %s  cmd #%-3d HTTP %d: %s\n", rel(), i, st.status, truncate(body, 160))
		default:
			var er execResponse
			if uerr := json.Unmarshal(body, &er); uerr != nil {
				fmt.Printf("  %s  cmd #%-3d FAIL: bad response JSON: %v\n", rel(), i, uerr)
				break
			}
			fmt.Printf("  %s  cmd #%-3d total=%s gateway=%s sandlot=%s exec=%s conn=%-6s lease=%-3s exit=%s out=%q\n",
				rel(), i, ms(st.totalMS), ms(nsToMs(er.GatewayDurationNs)),
				ms(nsToMs(er.SandlotDurationNs)), ms(nsToMs(er.ExecDurationNs)),
				connWord(st.reused), lease(hdr), exitWord(er), strings.TrimSpace(er.Stdout))
		}
		time.Sleep(cfg.think)
	}
	close(stop)
	wg.Wait()

	reqs, dials, fails, avoided := tally.snapshot()
	fmt.Printf("\n[loop] done: %d requests, %d connection(s) dialed, %d handshake(s) avoided, %d failure(s)\n",
		reqs, dials, avoided, fails)
	fmt.Println("[loop] a conn=NEW line above is the auto-reconnect — nothing else needed; the API is stateless per request.")
}

func envOr(key string) string { return os.Getenv(key) }

func ms(v float64) string { return fmt.Sprintf("%6.2fms", v) }

func msSince(t time.Time) float64 { return float64(time.Since(t).Nanoseconds()) / 1e6 }

func connWord(reused bool) string {
	if reused {
		return "reused"
	}
	return "NEW"
}

func lease(hdr http.Header) string {
	if hdr.Get("X-Sandbox-Lease") == "hit" {
		return "hit"
	}
	return "-"
}

func exitWord(er execResponse) string {
	if er.ExitCode == nil {
		return "-"
	}
	return fmt.Sprintf("%d", *er.ExitCode)
}

func nsToMs(v uint64) float64 { return float64(v) / 1e6 }

func truncate(b []byte, n int) string {
	s := strings.TrimSpace(string(b))
	if len(s) > n {
		s = s[:n] + "…"
	}
	return s
}

func exitBadStatus(status int, body []byte) {
	fmt.Fprintf(os.Stderr, "  HTTP %d: %s\n", status, truncate(body, 300))
	os.Exit(1)
}

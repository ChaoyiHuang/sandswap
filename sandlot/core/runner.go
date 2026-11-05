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

package core

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"math/rand"
	"net"
	"time"

	pb "common/proto/stream"
	sandlotconfig "sandlot/config"
	"sandlot/rpc"
)

// RunOptions carries the sandlot main()'s startup products into the
// reconnect runner: everything here is built once at process start and never
// changes for the process lifetime (restart-required config by design).
type RunOptions struct {
	Cfg             sandlotconfig.SandlotConfig
	Handler         *Handler
	TLSCfg          *tls.Config
	EffectiveNodeID string
	PoolTarget      uint32
	Logger          *log.Logger
	// HeartbeatNow triggers an immediate heartbeat when ResizePool changes the
	// pool (so the gateway reconciles quickly).
	HeartbeatNow <-chan struct{}
	// Provision is the prov-role executor (nil on exec-only instances). The
	// serve loop dispatches ProvisionCommands to it when non-nil.
	Provision *ProvisionService
	// SeedGenerations reports this instance's live naming generations
	// (fingerprints only: staged, current, staged) for the heartbeat, so the
	// gateway's fleet view can prove every prov instance converged before a
	// rotation window closes. Nil on instances without a namer.
	SeedGenerations func() (staged bool, currentFP, stagedFP string)
	// Roles is the normalized role advertisement carried in NodeHello.
	Roles []string
	// EgressBinding is the identity-binding mode in force ("none"/"shm"/"bpf"/
	// "routed-ipv6"), reported in every heartbeat for /stats.
	EgressBinding string
}

// saveCleanupState persists the exec-role resilience phase. Prov-only
// instances skip it: the phase describes held VM mounts, which a prov
// instance never has, and a shared sandbox root must not let one instance
// overwrite the other's recovery state.
func saveCleanupState(root string, s CleanupState, provOnly bool) {
	if provOnly {
		return
	}
	SaveCleanupState(root, s)
}

// RunNode drives the gateway connection lifecycle: the tolerance-first
// reconnect state machine, the per-connection serve loop, heartbeats, and the
// pool self-heal / overlay reaper tickers. Returns when ctx is cancelled.
func RunNode(ctx context.Context, opts RunOptions) {
	handler, logger := opts.Handler, opts.Logger
	res := opts.Cfg.Resilience

	// provOnly selects the prov-role connection semantics: NON-STICKY
	// dialing (no ownership to be loyal to — every reconnect re-picks, which
	// is what re-spreads instances across gateways), no TOLERATING phase on
	// stream break (nothing is held), and connection-age recycling so a
	// multi-address gateway list and a revived gateway recover their share of
	// instances without coordination. Exec (and merged exec,prov) connections
	// stay sticky and unrecycled: mounts and ownership demand it.
	provOnly := len(opts.Roles) == 1 && opts.Roles[0] == "prov"
	recycle := time.Duration(opts.Cfg.Provision.ReconnectSec) * time.Second
	if recycle <= 0 {
		recycle = 300 * time.Second
	}

	// heartbeatNow is a channel that triggers an immediate heartbeat when
	// ResizePool changes the pool (so the gateway reconciles quickly).
	heartbeatNow := opts.HeartbeatNow

	// Reconnect loop — tolerance-first state machine. Phases are persisted in
	// cleanup-state.json so a sandlot restart resumes the exact phase it died in
	// (a restart during TOLERATING must NOT reset the tolerance clock).
	//   ""          → normal connect (any gateway).
	//   tolerating  → stream down < T_tolerance; mounts KEPT (in-flight commands
	//                 keep running over vsock — this window is their grace
	//                 period), probe loop keeps running, only the preferred
	//                 gateway is tried, ownership untouched. Mounts are released
	//                 at the reconnect (before the hello) or when tolerance
	//                 expires, whichever comes first.
	//   cleaning    → tolerance expired (gateway presumed gone); probe loop
	//                 stopped, mounts released within a hard deadline, then done.
	//   done        → cleanup finished; wait out T_isolation before reconnecting.
	backoff := time.Second

	// Sandlot remembers its last gateway. On reconnect, prefer re-dialing
	// the SAME gateway (its pod IP) when it is still a valid candidate, so the
	// node's ownership/lease/pool state and CLEAN VMs stay warm. If the gateway
	// died, its IP drops out of the resolution and we land on a new one.
	gwState := LoadGatewayState(handler.SandboxRoot)
	preferredIP := gwState.LastGatewayIP
	if provOnly {
		// Provision connections carry no state worth returning to — skip the
		// gateway memory entirely so every dial re-picks (spread).
		preferredIP = ""
	} else if preferredIP != "" {
		logger.Printf("last gateway memory: %s (will prefer it on reconnect)", preferredIP)
	}

	// Resume the persisted resilience phase (survives restart). If we died while
	// cleaning/waiting-isolation, stop heartbeats immediately — the warden
	// countdowns (backstopping a mount we never finished clearing) must be able
	// to fire, and clean VMs are unaffected (countdown no-ops when unmounted).
	// Resilience phase is exec-role state: it describes held mounts. A
	// prov-only instance owns no mounts and must never read (or later
	// clobber) the exec instance's state file when both share a sandbox root.
	var cleanupState CleanupState
	if !provOnly {
		cleanupState = LoadCleanupState(handler.SandboxRoot)
	}
	// Crash-while-CONNECTED repair: the disconnect record is only written on an
	// observed stream break, so a crash during a healthy connection persists
	// phase "" and the tolerance clock never starts. With the gateway dead AND
	// DNS unreachable, the loop below would hold the re-adopted mounts forever
	// ("" has no clock, and the probe loop's heartbeats keep the warden
	// countdowns fresh, so they never fire either). Mounts held at start — or
	// survivors whose cleanup hasn't yet proven them clean — therefore
	// re-anchor TOLERATING at now; a live gateway connects within milliseconds
	// and clears it, so the anchor costs nothing.
	if anchored := initialCleanupState(cleanupState, handler.mayHoldUnreleasedMounts(), time.Now()); anchored != cleanupState {
		cleanupState = anchored
		saveCleanupState(handler.SandboxRoot, cleanupState, provOnly)
		logger.Printf("restarted with possibly-held mounts and no persisted outage; anchoring TOLERATING now (tolerance %ds)", res.ToleranceSec)
	}
	if cleanupState.Phase != "" {
		logger.Printf("resuming resilience phase %q (disconnected %s ago)",
			cleanupState.Phase, time.Since(cleanupState.DisconnectTime).Round(time.Second))
		if cleanupState.Phase == CleanupPhaseCleaning || cleanupState.Phase == CleanupPhaseDone {
			handler.StopProbeLoop()
		}
	}

	// The gateway's TLS cert SAN is the SERVICE hostname, so when we dial a
	// specific gateway IP the TLS handshake must still verify against the
	// hostname. Set once (idempotent across reconnects).
	if opts.TLSCfg != nil && opts.TLSCfg.ServerName == "" {
		if host, _, err := net.SplitHostPort(opts.Cfg.GatewayAddr); err == nil {
			opts.TLSCfg.ServerName = host
		}
	}

	for {
		if ctx.Err() != nil {
			break
		}

		switch cleanupState.Phase {
		case CleanupPhaseTolerating:
			// Still within tolerance? The clock is anchored at the persisted
			// disconnect. Once elapsed, enter CLEANING (stop heartbeats so the
			// warden countdowns arm from ~T_tolerance).
			if toleranceElapsed(cleanupState.DisconnectTime, res.ToleranceSec, time.Now()) {
				cleanupState = CleanupState{Phase: CleanupPhaseCleaning, DisconnectTime: cleanupState.DisconnectTime}
				saveCleanupState(handler.SandboxRoot, cleanupState, provOnly)
				handler.StopProbeLoop()
				logger.Printf("stream tolerance expired; entering CLEANING (budget %ds)", res.CleanupSec)
				continue
			}
			// Within tolerance: keep trying the SAME gateway only (failoverAllowed
			// stays false in the connect attempt below).

		case CleanupPhaseCleaning:
			// Release every mount within the hard budget disconnect_time +
			// T_tolerance + T_clean. Unmount failures and budget overruns are
			// force-destroyed (destroyAndReplaceVM); the warden countdown is the
			// backstop for anything still stuck.
			deadline := cleanupState.DisconnectTime.Add(time.Duration(res.ToleranceSec+res.CleanupSec) * time.Second)
			if !provOnly {
				handler.ResetSurvivorsToClean(ctx, deadline)
			}
			cleanupState = CleanupState{Phase: CleanupPhaseDone, DisconnectTime: cleanupState.DisconnectTime}
			saveCleanupState(handler.SandboxRoot, cleanupState, provOnly)
			logger.Printf("cleanup complete; entering DONE (waiting out %ds isolation)", res.IsolationSec)
			continue

		case CleanupPhaseDone:
			// Wait out the remainder of T_isolation before reconnecting — past
			// T_safe, so the gateway's ownership release of this node has
			// completed and no new gateway mounts before every old mount is gone.
			if wait := isolationRemaining(cleanupState.DisconnectTime, res.IsolationSec, time.Now()); wait > 0 {
				logger.Printf("DONE: waiting %v before reconnect", wait.Round(time.Second))
				select {
				case <-time.After(wait):
				case <-ctx.Done():
				}
			}
			if ctx.Err() != nil {
				break
			}
			cleanupState = CleanupState{}
			saveCleanupState(handler.SandboxRoot, cleanupState, provOnly)
			if !provOnly {
				handler.StartProbeLoop(ctx) // resume heartbeats for surviving VMs
			}
			if !provOnly {
				handler.StartGuestLogCapLoop(ctx) // idempotent; never stopped
			}
			continue

		default:
			// "" — normal connect (any gateway).
		}

		count, ids := handler.ActiveVMs()
		hello := &pb.NodeHello{
			NodeId:        opts.EffectiveNodeID,
			Version:       "0.1.0",
			TotalCpus:     readSystemCPUs(),
			TotalMemoryMb: readSystemMemMB(),
			ActiveVmIds:   ids,
			Vms:           handler.VMInfoList(),
			PoolTarget:    opts.PoolTarget,
			Specs:         buildVmSpecs(opts.Cfg.Specs),
			Roles:         opts.Roles,
			Timing: &pb.NodeTiming{
				ToleranceSec:       uint32(res.ToleranceSec),
				CleanupSec:         uint32(res.CleanupSec),
				WardenCountdownSec: uint32(res.WardenCountdownSec),
				IsolationSec:       uint32(res.IsolationSec),
			},
		}
		// Resolve the dial target, preferring the remembered gateway IP.
		// Only during TOLERATING do we refuse a different IP (failoverAllowed=
		// false): ownership hasn't transferred yet, so a fresh gateway wouldn't
		// own the sandfs. Normal connects may land anywhere.
		failoverAllowed := cleanupState.Phase != CleanupPhaseTolerating
		target, connIP, err := resolveGatewayTarget(ctx, opts.Cfg.GatewayAddr, preferredIP, failoverAllowed)
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			logger.Printf("gateway address resolution failed: %v; retry in %v", err, backoff)
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
			}
			backoff = backoff * 2
			if backoff > 60*time.Second {
				backoff = 60 * time.Second
			}
			continue
		}
		logger.Printf("connecting to gateway at %s (%d live VM(s))", target, count)
		rpcCfg := rpc.Config{
			SendBufferSize:    opts.Cfg.Stream.SendBufferSize,
			RecvBufferSize:    opts.Cfg.Stream.RecvBufferSize,
			WriteTimeout:      time.Duration(opts.Cfg.Stream.WriteTimeoutSec) * time.Second,
			InitialWindow:     int32(opts.Cfg.Stream.InitialWindow),
			InitialConnWindow: int32(opts.Cfg.Stream.InitialConnWindow),
			MaxMsgSize:        opts.Cfg.Stream.MaxMsgSize,
			// Reconnect-clean invariant (reconnect half): a gateway is reachable
			// again, so the outage's grace window is over — release every mount
			// before announcing ourselves. Idempotent (clean VMs are ~1ms
			// no-ops), so the CLEANING path having already run is fine. On the
			// STARTUP path this must also wait out the re-adopt cleanups: a
			// survivor's pre-restart guest mount is released asynchronously
			// (redialWarden), and announcing before it lands would hand the
			// gateway a node that still holds a stale mount. Normally ~ms (the
			// warden is already up); a hung warden self-bounds at 15s and the
			// probe loop tears the VM down as hung shortly after.
			BeforeHello: func() {
				wctx, wcancel := context.WithTimeout(ctx, readoptCleanupWait)
				if !handler.WaitReadoptCleanup(wctx) {
					// Survivors whose cleanup is still in flight stay
					// unselectable (readoptPending) and a failed cleanup
					// destroys them, so the node can connect without handing
					// one of them a new mount.
					logger.Printf("re-adopt cleanup still in flight after %v; connecting anyway (stuck survivors are unselectable until cleanup or destroy)", readoptCleanupWait)
				}
				wcancel()
				if !provOnly {
					handler.ResetSurvivorsToClean(ctx, time.Now().Add(time.Duration(res.CleanupSec)*time.Second))
				}
				// Overlay sweep at reconnect: tracked overlays whose volume no
				// longer needs one (.template gone — sandfs deleted, or
				// recreated flat) are unmounted NOW instead of waiting for the
				// daily reaper. Cheap (one marker stat per tracked overlay on
				// this node) and it keeps the reconnect invariant honest: the
				// gateway meets a node with zero mounts, host-side overlays
				// included. (A template SWAP leaves the marker present — that
				// case is caught by the mount-time expected-ref check, not
				// this sweep.)
				handler.vm.CleanupStaleOverlays()
			},
		}
		client, err := rpc.Connect(ctx, target, hello, opts.TLSCfg, logger, rpcCfg)
		if err == nil {
			client.SetEgressBinding(opts.EgressBinding)
		}
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			logger.Printf("connect failed: %v; retry in %v", err, backoff)
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
			}
			backoff = backoff * 2
			if backoff > 60*time.Second {
				backoff = 60 * time.Second
			}
			continue
		}
		backoff = time.Second
		// Connected: clear any in-progress outage state + resume heartbeats.
		if cleanupState.Phase != "" {
			cleanupState = CleanupState{}
			saveCleanupState(handler.SandboxRoot, cleanupState, provOnly)
		}
		if !provOnly {
			handler.StartProbeLoop(ctx) // idempotent if already running
		}
		if !provOnly {
			handler.StartGuestLogCapLoop(ctx) // idempotent; never stopped
		}
		// Remember the gateway we actually connected to (exec/merged only —
		// prov connections are non-sticky by design).
		if !provOnly && connIP != preferredIP {
			preferredIP = connIP
			SaveGatewayState(handler.SandboxRoot, GatewayState{LastGatewayIP: connIP})
		}
		handler.SetClient(client)
		if provOnly {
			// Connection-age recycling: close a HEALTHY stream at
			// reconnect-sec ±20% so the next dial re-picks a gateway. This is
			// the whole rebalancing story for the prov role — a revived
			// gateway recovers its share of instances within one recycle
			// window, with zero coordination.
			recycleCtx, recycleCancel := context.WithCancel(ctx)
			go func() {
				jitter := time.Duration(float64(recycle) * (0.8 + 0.4*rand.Float64()))
				t := time.NewTimer(jitter)
				defer t.Stop()
				select {
				case <-t.C:
					logger.Printf("provision connection recycling after %v (spread rebalance)", jitter.Round(time.Second))
					client.Close()
				case <-recycleCtx.Done():
				case <-client.Done():
				}
			}()
			runServeLoop(ctx, client, handler, logger, heartbeatNow, opts.Cfg.Stream.MaxConcurrentCommands, opts.Provision, opts.SeedGenerations, provOnly)
			recycleCancel()
		} else {
			runServeLoop(ctx, client, handler, logger, heartbeatNow, opts.Cfg.Stream.MaxConcurrentCommands, opts.Provision, opts.SeedGenerations, provOnly)
		}
		client.Close()
		// Stream broke: enter TOLERATING anchored at now. Mounts are deliberately
		// KEPT through this window — T_tolerance is the in-flight-command grace
		// period, and commands run inside the VM over vsock, untouched by the
		// gateway outage. They are released either at the reconnect (the dial site
		// above, before the next hello) or when T_tolerance expires (CLEANING).
		// Provision-only connections hold nothing — reconnect immediately with
		// plain backoff (also the recycle path: the close above lands here).
		if provOnly {
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
			}
			backoff = backoff * 2
			if backoff > 60*time.Second {
				backoff = 60 * time.Second
			}
			continue
		}
		cleanupState = CleanupState{Phase: CleanupPhaseTolerating, DisconnectTime: time.Now()}
		saveCleanupState(handler.SandboxRoot, cleanupState, provOnly)
		logger.Printf("stream disconnected; entering TOLERATING (tolerance %ds; in-flight commands keep running)", res.ToleranceSec)
	}
}

// readoptCleanupWait bounds how long the reconnect path waits for re-adopt
// cleanups (redialWarden: per-VM warden-ready wait ≤15s + one unmount RPC)
// before sending NodeHello. Normal startups finish in milliseconds; the bound
// only bites when a survivor's warden is slow/hung, where holding the
// reconnect longer would buy nothing (the probe loop declares it hung and
// tears it down within seconds of the probes starting).
const readoptCleanupWait = 20 * time.Second

// toleranceElapsed reports whether the TOLERATING grace period has elapsed since
// the persisted disconnect_time: the tolerance clock is anchored to the
// ORIGINAL disconnect (survives a sandlot restart — a restart must NOT reset the
// tolerance, else a crashed-during-tolerance node never cleans up). Pure, for
// unit testing.
func toleranceElapsed(disconnectTime time.Time, toleranceSec int, now time.Time) bool {
	return now.Sub(clampDisconnectTime(disconnectTime, now)) >= time.Duration(toleranceSec)*time.Second
}

// clampDisconnectTime caps a PERSISTED disconnect timestamp at `now`. The value
// crosses a restart as wall-clock JSON (cleanup_state.go), so a backward clock
// step (NTP correction, snapshot restore, bad RTC) can leave it in the future:
// toleranceElapsed would then never fire while the probe loop keeps the wardens
// alive, holding mounts past T_tolerance + T_warden AND past the gateway's
// presence-key T_safe — the dual-mount window the T_safe proof exists to close.
// In-process timestamps keep their monotonic reading, so the clamp only ever
// affects a reloaded value.
func clampDisconnectTime(disconnectTime, now time.Time) time.Time {
	if disconnectTime.After(now) {
		return now
	}
	return disconnectTime
}

// isolationRemaining returns how long the DONE phase still has to wait before
// reconnecting (0 if already past T_isolation). Pure, for unit testing.
func isolationRemaining(disconnectTime time.Time, isolationSec int, now time.Time) time.Duration {
	end := clampDisconnectTime(disconnectTime, now).Add(time.Duration(isolationSec) * time.Second)
	if d := end.Sub(now); d > 0 {
		return d
	}
	return 0
}

// initialCleanupState decides the reconnect phase a starting sandlot enters.
// The persisted phase always wins — a restart resumes the exact phase it died
// in (a restart during TOLERATING must NOT reset the tolerance clock). The one
// repair: a crash while CONNECTED persists phase "" (the disconnect record is
// only written on an observed stream break), so without re-anchoring, a node
// that re-adopted held mounts would have no tolerance clock at all. Pure, for
// unit testing.
func initialCleanupState(persisted CleanupState, mayHoldMounts bool, now time.Time) CleanupState {
	if persisted.Phase != "" || !mayHoldMounts {
		return persisted
	}
	return CleanupState{Phase: CleanupPhaseTolerating, DisconnectTime: now}
}

// hostResolver resolves the gateway Service hostname to candidate IPs.
// net.DefaultResolver in production; overridable in tests (e.g. to simulate the
// remembered gateway IP dropping out of DNS during TOLERATING). A nil
// hostResolver falls back to net.DefaultResolver.
var hostResolver interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
} = net.DefaultResolver

// resolveGatewayTarget resolves the gateway Service host to a concrete IP:port
// to dial, preferring the last-known gateway IP. Returns the dial target
// and the chosen IP.
//
// failoverAllowed=false (TOLERATING): only the remembered gateway is dialed — a
// different gateway hasn't transferred ownership of this node's sandfs yet, so
// dialing it would leave every sandfs ownerless. The remembered IP is dialed
// DIRECTLY even when DNS no longer lists it: a gateway restart briefly evicts
// the old IP from DNS (k8s endpoint propagation), and requiring DNS to
// re-confirm it would idle the sandlot through the whole tolerance window for a
// gateway that returns in seconds. The switch-home prohibition (we only ever
// dial preferredIP, never another gateway) is itself the safety guarantee; the
// DNS membership check adds no safety on top of it. If the gateway is truly
// gone, dialing its dead IP fails fast and the tolerance clock expires into
// CLEANING — no worse than refusing to dial. Normal connects
// (failoverAllowed=true) may land on any resolved gateway.
//
// The same direct dial is the fallback when DNS itself is unreachable or has
// no answer (resolver error / empty set): a DNS outage must not strand the
// node, since the direct dial is safe in every phase (connect-clean releases
// mounts before the hello; etcd ownership bounds any landing) and the gateway
// may be perfectly alive. Each connect attempt re-resolves, so failover
// resumes naturally once DNS recovers.
func resolveGatewayTarget(ctx context.Context, gatewayAddr, preferredIP string, failoverAllowed bool) (target, ip string, err error) {
	host, port, err := net.SplitHostPort(gatewayAddr)
	if err != nil {
		return "", "", fmt.Errorf("parse gateway addr %q: %w", gatewayAddr, err)
	}
	resolver := hostResolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	ips, err := resolver.LookupHost(ctx, host)
	if err != nil || len(ips) == 0 {
		// DNS unavailable. Dial the remembered gateway directly; without a
		// remembered gateway there is nothing to dial — surface the error.
		if preferredIP != "" {
			return net.JoinHostPort(preferredIP, port), preferredIP, nil
		}
		if err != nil {
			return "", "", fmt.Errorf("resolve %q: %w", host, err)
		}
		return "", "", fmt.Errorf("no addresses for %q", host)
	}
	// No preferred gateway (first connect, or the memory was lost): take a
	// candidate. Even during TOLERATING this is accepted — connect-clean makes
	// any landing safe, and with no memory there is no home to stay loyal to.
	if preferredIP == "" {
		pick := pickGatewayIP(ips)
		return net.JoinHostPort(pick, port), pick, nil
	}
	// Prefer the remembered gateway if it's still resolved.
	for _, cand := range ips {
		if cand == preferredIP {
			return net.JoinHostPort(cand, port), cand, nil
		}
	}
	// Preferred gateway dropped from DNS. During TOLERATING, dial the remembered
	// IP directly anyway (see the doc comment above) — do NOT refuse to dial and
	// idle through the tolerance window. Otherwise accept another resolved IP.
	if !failoverAllowed {
		return net.JoinHostPort(preferredIP, port), preferredIP, nil
	}
	pick := pickGatewayIP(ips)
	return net.JoinHostPort(pick, port), pick, nil
}

// gatewayPickIdx is the random-index source for the non-sticky candidate pick
// (first connect / failover). Injectable so tests are deterministic.
var gatewayPickIdx = rand.Intn

// pickGatewayIP picks the dial candidate when there is no sticky preference.
// Headless-Service DNS returns multi-IP answers in a deterministic order;
// always taking ips[0] would herd every first-connect sandlot onto the same
// gateway pod and the last-gateway memory would then freeze that skew
// (bare metal is unaffected: the stream domain is a single health/load-chosen
// answer, so this pick is a no-op there).
func pickGatewayIP(ips []string) string {
	if len(ips) == 1 {
		return ips[0]
	}
	return ips[gatewayPickIdx(len(ips))]
}

// runServeLoop drives a single gateway connection. maxConcurrent bounds the
// cmdSem: the number of VMCommands processed in parallel (from -max-concurrent-commands).
func runServeLoop(ctx context.Context, client *rpc.Client, handler *Handler, logger *log.Logger, heartbeatNow <-chan struct{}, maxConcurrent int, prov *ProvisionService,
	seedGen func() (bool, string, string), provOnly bool) {
	sendHeartbeat(client, handler, logger, seedGen)

	// Scheduling metrics ticker: sample node/host state every 1s so the
	// heartbeat carries meaningful EWMA signals
	go func() {
		metricsTicker := time.NewTicker(1 * time.Second)
		defer metricsTicker.Stop()
		for {
			select {
			case <-metricsTicker.C:
				handler.TickMetrics()
			case <-client.Done():
				return
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				sendHeartbeat(client, handler, logger, seedGen)
			case <-heartbeatNow:
				sendHeartbeat(client, handler, logger, seedGen)
			case <-client.Done():
				return
			case <-ctx.Done():
				return
			}
		}
	}()

	// Pool self-heal ticker: every 60s, fill gaps left by transient VM
	// creation failures (TAP busy, momentary KVM pressure, OOM-aborted
	// scale-up). This lets the pool recover without an operator triggering
	// a config reload. ReconcilePool is a no-op when the pool is already at
	// target; createMu serializes its createPoolVM calls with ResizePool.
	go func() {
		healTicker := time.NewTicker(60 * time.Second)
		defer healTicker.Stop()
		for {
			select {
			case <-healTicker.C:
				// VM-lifecycle machinery is exec-role only. A prov-only
				// instance owns no VMs, and on a co-located host its sandbox
				// root may be the shared default — its reaper must never touch
				// (or kill) the exec instance's live microVMs.
				if provOnly {
					continue
				}
				handler.ReconcilePool()
				handler.ReconcileSandboxDirs(ctx)
			case <-client.Done():
				return
			case <-ctx.Done():
				return
			}
		}
	}()

	// Overlay reaper: daily fallback sweep for stale host-side overlay mounts
	// whose SandFS has been deleted (missing .template marker). Covers the case
	// where this sandlot was offline when the gateway deleted the SandFS; the
	// normal path is the gateway's CleanupOverlay RPC.
	handler.StartOverlayReaper(client.Done())

	conc := maxConcurrent
	if conc <= 0 {
		conc = 64
	}
	cmdSem := make(chan struct{}, conc)

	for {
		select {
		case msg := <-client.Commands():
			if pcmd := msg.GetProvisionCommand(); pcmd != nil {
				// Provision-plane dispatch: bounded concurrency lives INSIDE
				// ProvisionService.Handle (its own semaphore — GB-scale work
				// must not eat the VM command budget), so the serve loop only
				// spawns and replies. Panics degrade the single op, same
				// contract as VM commands.
				if prov == nil {
					// Routing invariant violation (the gateway should never
					// send provision commands to an exec-only connection) —
					// answer loudly instead of dropping silently.
					_ = client.SendProvisionResponse(&pb.ProvisionResponse{
						CommandId: pcmd.GetCommandId(),
						Success:   false,
						Error:     "provision command sent to an instance without the prov role",
						ErrorCode: "INVALID_ARGUMENT",
					})
					continue
				}
				go func() {
					defer func() {
						if r := recover(); r != nil {
							logger.Printf("panic handling provision command %s: %v", pcmd.GetCommandId(), r)
						}
					}()
					resp := prov.Handle(pcmd)
					if err := client.SendProvisionResponse(resp); err != nil {
						logger.Printf("provision response %s: %v", pcmd.GetCommandId(), err)
					}
				}()
				continue
			}
			if cmd := msg.GetVmCommand(); cmd != nil {
				// Acquire a slot with Done/ctx awareness: a BLOCKING send here
				// would pin the serve loop while every slot holds a long
				// command, delaying stream-death detection (and process exit)
				// by up to the longest in-flight command. On Done the command
				// is dropped — the stream is gone, so no reply was possible
				// anyway and the gateway's command timeout retries elsewhere.
				select {
				case cmdSem <- struct{}{}:
				case <-client.Done():
					return
				case <-ctx.Done():
					return
				}
				go func() {
					defer func() { <-cmdSem }()
					// A panic in any single command handler must never take
					// down the whole sandlot process (and with it every VM on
					// the node). Recover here so one bad request degrades only
					// that request; the gateway's command timeout retries it
					// elsewhere.
					defer func() {
						if r := recover(); r != nil {
							logger.Printf("panic handling command %s: %v", cmd.GetCommandId(), r)
						}
					}()
					handler.ProcessCommand(ctx, cmd)
				}()
			}
		case <-client.Done():
			return
		case <-ctx.Done():
			return
		}
	}
}

// sendHeartbeat ships a heartbeat.
func sendHeartbeat(client *rpc.Client, handler *Handler, logger *log.Logger,
	seedGen func() (bool, string, string)) {
	count, ids := handler.ActiveVMs()
	vmMem := handler.VMMemStats()
	specCap := handler.SpecCapacityList()
	metrics := handler.MetricsSnapshot()
	var seedFP, stagedFP string
	var staged bool
	if seedGen != nil {
		staged, seedFP, stagedFP = seedGen()
	}
	if err := client.SendHeartbeat(count, ids, vmMem, specCap, metrics, seedFP, staged, stagedFP); err != nil {
		logger.Printf("heartbeat failed: %v", err)
	}
}

// buildVmSpecs converts the configured spec entries to protobuf VmSpec messages
// for inclusion in NodeHello. The gateway uses these for spec-aware Acquire.
func buildVmSpecs(specs map[string]sandlotconfig.SpecEntry) []*pb.VmSpec {
	result := make([]*pb.VmSpec, 0, len(specs))
	for name, entry := range specs {
		result = append(result, &pb.VmSpec{
			Id:        name,
			Vcpus:     entry.VCPUs,
			ExecSlots: uint32(entry.ExecSlots),
			MemoryMb:  entry.MemoryMB,
		})
	}
	return result
}

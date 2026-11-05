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
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	pb "common/proto/stream"
	gwconfig "gateway/config"
	"gateway/lease"
	"gateway/pool"
	"gateway/registry"
	"gateway/stats"
	"gateway/storage"
	"gateway/stream"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
)

// wireLeaseFireLag binds the lease manager's fire-lag recorder to the gateway's
// unmount stats collector: every expiry-timer callback that actually dispatches
// an unmount at/after its sync sticky deadline contributes to
// /stats unmount_stats[].lease_fire — the metric that proves a 1ms sticky
// window fires on time under load. No-op when either side is absent.
func wireLeaseFireLag(lm *lease.Lease, unmountStats *stats.UnmountStats) {
	if lm == nil || unmountStats == nil {
		return
	}
	lm.SetFireLagRecorder(unmountStats.RecordLeaseFire)
}

// wireStreamCallbacks sets up the stream server callbacks for sandlot
// connection lifecycle events. Shared between single-node and exec modes.
// The ownership parameter may be nil in single-node mode (no etcd).
func wireStreamCallbacks(streamSrv *stream.Server, pm *pool.Manager, lm *lease.Lease, sandlotClient pool.SandlotClient, ownership *lease.OwnershipCache, logger *slog.Logger) {
	streamSrv.OnConnect(func(nc *stream.NodeConnection) {
		logger.Info("sandlot node connected",
			"nodeID", nc.NodeID,
			"version", nc.Version,
			"roles", nc.Roles(),
		)
		// Prov-role connections are storage executors ONLY: no pool
		// registration (placement never sees them), no presence key (prov
		// instances carry ZERO etcd footprint by design), no spec/capacity
		// bookkeeping. Their whole life is the provision command routing in
		// stream.RoleNodes(prov).
		if !nc.HasRole(stream.RoleExec) {
			logger.Info("provision instance connected (storage plane executor)", "nodeID", nc.NodeID)
			return
		}
		pm.AddNode(nc.NodeID)

		// grant the node's presence key (TTL = T_safe) and cancel any pending
		// owner-release for it. Reconnect = the node is back, no release. If the
		// node's timings violate the model invariants, reject it: close the
		// connection and drop it from the pool so the gateway never routes
		// sandfs to a node without a valid T_safe anchor.
		if ownership != nil {
			if err := ownership.OnNodeConnect(nc.NodeID, nc.Info.GetTiming()); err != nil {
				logger.Warn("rejecting sandlot node: invalid resilience timings; closing connection",
					"nodeID", nc.NodeID, "error", err)
				pm.RemoveNode(nc.NodeID)
				nc.Close()
				return
			}
		}

		// Record the node's spec definitions (specID → {vcpus, memory_mb}) from
		// NodeHello.specs. The gateway matches a sandfs's required vcpus/memory
		// against these concrete resources and resolves the floor specID to send
		// to sandlot as min_spec.
		pbSpecs := nc.Info.GetSpecs()
		nodeSpecs := make([]pool.VMSpec, 0, len(pbSpecs))
		for _, s := range pbSpecs {
			if s == nil {
				continue
			}
			nodeSpecs = append(nodeSpecs, pool.VMSpec{ID: s.GetId(), VCPUs: s.GetVcpus(), MemoryMB: s.GetMemoryMb(), ExecSlots: s.GetExecSlots()})
		}
		pm.SetNodeSpecs(nc.NodeID, nodeSpecs)

		// Initial per-spec capacity from NodeHello.vms: re-adopt-light unmounts
		// all survivors on connect, so every live VM is CLEAN. Subsequent
		// heartbeats refine clean counts (as VMs get bound to sandfs).
		counts := map[string]int{}
		for _, vi := range nc.Info.GetVms() {
			spec := vi.SpecId
			if spec == "" {
				spec = "medium"
			}
			counts[spec]++
		}
		caps := make([]pool.SpecCapacity, 0, len(counts))
		for spec, n := range counts {
			caps = append(caps, pool.SpecCapacity{SpecID: spec, Clean: uint32(n), Total: uint32(n)})
		}
		pm.UpdateNodeCapacity(nc.NodeID, caps)

		if ownership != nil {
			ownership.NoteNodeReconnected(nc.NodeID)
			// node_count changed → publish the health key immediately
			// (event-driven, instead of waiting for the safety-net ticker).
			ownership.TouchHealth()
		}

		poolTarget := int(nc.Info.GetPoolTarget())
		appliedPoolTarget := 0
		if poolTarget > 0 {
			var clamped bool
			appliedPoolTarget, clamped = pm.SetNodePoolTarget(nc.NodeID, poolTarget)
			if clamped {
				logger.Warn("node reported a pool_target above the plausible range; clamped",
					"nodeID", nc.NodeID, "reported", poolTarget, "applied", appliedPoolTarget)
			}
		}
		logger.Info("node pool target", "nodeID", nc.NodeID, "poolTarget", appliedPoolTarget, "reported", nc.Info.GetPoolTarget(), "liveVMs", len(nc.Info.GetVms()))
	})

	streamSrv.OnDisconnect(func(nc *stream.NodeConnection) {
		// Prov-only connections were never registered (no pool entry, no
		// presence key, no leases) — nothing to clean, and touching the
		// ownership machinery would give them an etcd footprint they must
		// never have.
		if !nc.HasRole(stream.RoleExec) {
			logger.Info("provision instance disconnected", "nodeID", nc.NodeID)
			return
		}
		nodeID := nc.NodeID
		logger.Info("sandlot node disconnected, dropping capacity and leases", "nodeID", nodeID)
		pm.RemoveNode(nodeID)
		lm.ReleaseByNode(nodeID)
		if ownership != nil {
			// record the node in the owner-release pending set (trigger (0)) — the
			// sweep releases its sandfs ownership after T_safe + presence expiry.
			// No per-node disconnect-clear timer: release is governed by the
			// three-part chain, not a fixed timeout.
			ownership.OnNodeDisconnect(nodeID)
			// node_count dropped → publish the health key immediately.
			ownership.TouchHealth()
		}
	})

	streamSrv.OnHeartbeat(func(nodeID string, vmCount uint32, vmIDs []string, vmMem []*pb.VmMemInfo, specCap []*pb.SpecCapacity, metrics *pb.NodeMetrics) {
		// refresh the node.s presence key lease — while the stream is alive,
		// heartbeats keep the key from expiring; when it breaks they stop, so the
		// key naturally expires T_safe after the last heartbeat.
		if ownership != nil {
			ownership.OnNodeHeartbeat(nodeID)
		}
		caps := make([]pool.SpecCapacity, 0, len(specCap))
		for _, c := range specCap {
			caps = append(caps, pool.SpecCapacity{
				SpecID:         c.SpecId,
				Clean:          c.Clean, // heartbeat view (diagnostics); routing uses derived total-bound
				Total:          c.Total,
				MinCleanWindow: c.MinCleanWindow,
				ZeroCleanCount: c.ZeroCleanCount,
			})
		}
		pm.UpdateNodeCapacity(nodeID, caps)
		if metrics != nil {
			pm.UpdateNodeMetrics(nodeID, pool.NodeMetrics{
				DutyShort:              metrics.DutyShort,
				DutyLong:               metrics.DutyLong,
				DutyDaily:              metrics.DutyDaily,
				DutyVar:                metrics.DutyVar,
				ExecRate:               metrics.ExecRate,
				AvgExecMS:              metrics.AvgExecMs,
				AvgGapMS:               metrics.AvgGapMs,
				HostCPU:                metrics.HostCpuPct,
				HostMemAvailMB:         metrics.HostMemAvailMb,
				ActiveSandfs:           metrics.ActiveSandfs,
				ActiveBgExecs:          metrics.ActiveBgExecs,
				TotalVMs:               metrics.TotalVms,
				IdleDurationMS:         metrics.IdleDurationMs,
				MaxDutyWindow:          metrics.MaxDutyWindow,
				PeakConcurrentExecs:    metrics.PeakConcurrentExecs,
				SlotWaitMS:             metrics.SlotWaitMs,
				SlotWaitEvents:         metrics.SlotWaitEvents,
				RecycleTriggers:        metrics.RecycleTriggers,
				StrandedReservationsMB: metrics.StrandedReservationsMb,
				StrandedCIDs:           metrics.StrandedCids,
			})
		}
	})

	// OnEvent: async VM events pushed by sandlot (VM crash, vsock ready).
	// The stream read loop invokes this callback INLINE (stream/server.go
	// readLoop), so the body must never block: it would stall this node's
	// CommandResponse + heartbeat delivery. Crash handling therefore dispatches
	// to a goroutine — crashes are rare (bounded by pool size) and the work is
	// microseconds.
	streamSrv.OnEvent(func(nc *stream.NodeConnection, ev *pb.VMEvent) {
		nodeID, vmID, msg := nc.NodeID, ev.GetVmId(), ev.GetMessage()
		switch ev.GetType() {
		case pb.VMEventType_VM_EVENT_CRASHED:
			go func() {
				logger.Warn("sandlot reported VM crash",
					"nodeID", nodeID, "vmID", vmID, "message", msg)
				// Scheduling signal only: deprioritize the node for new cold
				// mounts until its heartbeat reconciles Total. No lease release
				// (no vmID→sandfs mapping; node-level cleanup is OnDisconnect's
				// ReleaseByNode) and no Total decrement (the ~30s heartbeat owns
				// capacity via UpdateNodeCapacity).
				if pm != nil {
					pm.NoteVMCrash(nodeID)
				}
			}()
		case pb.VMEventType_VM_EVENT_VSOCK_READY:
			// Explicit no-op: the warden-ready wait happens on the sandlot side
			// (handleCreate's warden-ready goroutine) and the create/mount RPC
			// response already carries success/failure.
		case pb.VMEventType_VM_EVENT_RESOURCE_SHORTAGE:
			// The node rejected a VM creation: its guest-memory admission found
			// the host short. The node does NOT retry on its own — its pool
			// refills only via its 60s reconcile tick and only if memory frees.
			// Log at WARN so the operator sees which node is memory-capped;
			// scheduling already accounts for the shortfall through the
			// heartbeat's per-node clean/total counts, so no extra
			// deprioritization is applied here.
			logger.Warn("sandlot reported host resource shortage; node pool will stay below target until memory frees",
				"nodeID", nodeID, "vmID", vmID, "detail", msg)
		default:
			logger.Debug("unhandled VM event",
				"nodeID", nodeID, "vmID", vmID, "type", ev.GetType())
		}
	})
}

// startStreamServer starts the gRPC stream server for sandlot connections.
// acceptedRoles is the connection-role set this gateway serves, derived from
// its listeners (exec gateway → [exec]; human-only gateway → [prov]; unified
// single-node/one-gw → both) — a connection advertising none of them is
// rejected at the handshake with a named reason.
func startStreamServer(streamSrv *stream.Server, acceptedRoles []string, streamAddr, tlsCert, tlsKey, tlsCA string, cc gwconfig.StreamConcurrencyConfig, logger *slog.Logger) {
	streamSrv.SetAcceptedRoles(acceptedRoles)
	var grpcOpts []grpc.ServerOption
	if tlsCert != "" {
		tlsCfg, err := buildStreamServerTLS(tlsCert, tlsKey, tlsCA)
		if err != nil {
			logger.Error("invalid TLS config", "error", err)
			os.Exit(1)
		}
		grpcOpts = append(grpcOpts, grpc.Creds(credentials.NewTLS(tlsCfg)))
		logger.Info("stream server TLS enabled (mTLS: client certificates verified against -stream-tls-ca)")
	} else {
		logger.Warn("stream server running WITHOUT TLS (plaintext) — every node stream will be REFUSED at the handshake; " +
			"set -stream-tls-cert/-stream-tls-key (and -stream-tls-ca) for production")
	}
	// HTTP/2 flow-control windows + max message size. All commandId-multiplexed
	// responses share one HTTP/2 stream, so the per-stream window must accommodate
	// concurrent in-flight responses (>= max-msg-size, sized for concurrency).
	// MaxMsgSize must be >= the warden single-op cap so a large FileOp payload is
	// never rejected at gRPC after being accepted over HTTP.
	grpcOpts = append(grpcOpts,
		grpc.InitialWindowSize(int32(cc.InitialWindow)),
		grpc.InitialConnWindowSize(int32(cc.InitialConnWindow)),
		grpc.MaxSendMsgSize(cc.MaxMsgSize),
		grpc.MaxRecvMsgSize(cc.MaxMsgSize),
		// keepalive: enforcement policy permits the sandlot client's 6s PING
		// cadence (MinTime 5s < 6s; default 5min would GOAWAY it). ServerParameters
		// ping the client so the gateway also detects a half-open sandlot (~12s)
		// instead of waiting for writeTimeout/heartbeat-stop — the sandlot then
		// enters TOLERATING (state machine) and the presence key stops being
		// refreshed.
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             5 * time.Second,
			PermitWithoutStream: true,
		}),
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time:    10 * time.Second,
			Timeout: 2 * time.Second,
		}),
	)
	logger.Info("stream server concurrency",
		"sendBuffer", cc.SendBufferSize,
		"initialWindowMB", cc.InitialWindow>>20,
		"connWindowMB", cc.InitialConnWindow>>20,
		"maxMsgSizeMB", cc.MaxMsgSize>>20)
	grpcSrv := grpc.NewServer(grpcOpts...)
	pb.RegisterNodeStreamServer(grpcSrv, streamSrv)

	streamLis, err := net.Listen("tcp", streamAddr)
	if err != nil {
		logger.Error("failed to listen on stream address", "addr", streamAddr, "error", err)
		os.Exit(1)
	}
	go func() {
		logger.Info("stream server listening for sandlot connections", "addr", streamAddr)
		if err := grpcSrv.Serve(streamLis); err != nil {
			logger.Error("stream server error", "error", err)
		}
	}()
}

// wireStorageBackend installs the registry's storage-plane executor: the
// stream-backed RPC client routing ops to connected prov-role instances
// (round-robin, retry on transport error, named 503 while none is
// connected). The gateway host mounts NO shared storage; the only thing
// crossing the wire is the op vocabulary + small results.
func wireStorageBackend(reg *registry.Registry, streamSrv *stream.Server, cfg *gwconfig.GatewayConfig, logger *slog.Logger) {
	deadline := time.Duration(cfg.StorageOpDeadlineSec) * time.Second
	if deadline <= 0 {
		deadline = 5 * time.Minute
	}
	reg.SetStorageOps(storage.NewRPC(streamSrv, deadline))
	logger.Info("storage plane: provision instances over the node stream (ops are a named 503 until one connects)", "opDeadline", deadline)
}

// buildStreamServerTLS builds the TLS config for the gateway<->sandlot gRPC
// stream. TLS 1.3 only (1-RTT handshake, strongest ciphers). The stream is
// ALWAYS mTLS: -stream-tls-ca is required and client certificates are
// verified against it. Without a verifying CA, the only node identity check
// is the hello's CN compared to a self-asserted certificate — any host that
// can reach the stream port could present `CN=<victim-node-id>` with its own
// self-signed cert and receive that node's VMCommands (tenant code, file
// data, volume paths). There is deliberately no no-CA mode.
func buildStreamServerTLS(certFile, keyFile, caFile string) (*tls.Config, error) {
	if certFile == "" || keyFile == "" {
		return nil, fmt.Errorf("-stream-tls-cert and -stream-tls-key must both be set")
	}
	if caFile == "" {
		return nil, fmt.Errorf("-stream-tls-ca is required: without a verifying CA any self-signed client certificate whose CN equals a node id is accepted as that node (node impersonation); mint a stream CA and issue per-node certificates from it")
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load server keypair: %w", err)
	}
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read CA bundle: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("no valid certs in CA bundle %s", caFile)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
	}, nil
}

// fenceReleaseAllMounts is the etcd-partition self-fence action: unmount every
// sandfs this gateway currently holds, over the node streams (which stay
// connected). Returns the number of mounts released.
//
// Why release actively instead of dropping the streams and letting each sandlot
// run its own cleanup: (1) the release then finishes within fence + T_clean
// rather than fence + T_tolerance + T_clean, so it still fits under T_safe and
// the presence-expiry proof holds with the original T_safe formula; (2) the
// nodes keep their warm VM pools and never go through T_isolation, so recovery
// is in-place instead of costing ~17min of node capacity per partition blip.
//
// Bounded concurrency: a gateway can hold thousands of mounts and each unmount
// is an RPC. Lease entries are released too, so nothing is left pointing at a
// mount that no longer exists.
//
// TODO(batch-unmount): this is the gateway's largest unmount fan-out —
// potentially thousands of single-sandfs RPCs through 32 workers. If that ever
// becomes a bottleneck, a batch unmount command per node (see the
// StreamSandlotClient.UnmountRootfs TODO) collapses it to one RPC per node.
func fenceReleaseAllMounts(ownership *lease.OwnershipCache, lm *lease.Lease, pm *pool.Manager,
	sandlotClient pool.SandlotClient, unmountStats *stats.UnmountStats, logger *slog.Logger) int {
	mounts := ownership.MountedSandfs()
	if len(mounts) == 0 {
		return 0
	}
	const fenceUnmountWorkers = 32
	sem := make(chan struct{}, fenceUnmountWorkers)
	var wg sync.WaitGroup
	var released atomic.Int64
	for sandfsID, nodeID := range mounts {
		wg.Add(1)
		sem <- struct{}{}
		go func(sandfsID, nodeID string) {
			defer wg.Done()
			defer func() { <-sem }()
			spec := lm.SpecOf(sandfsID)
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			res, err := sandlotClient.UnmountRootfs(ctx, nodeID, sandfsID, lm.VolumePathOf(sandfsID), lm.VolumeEpochOf(sandfsID))
			cancel()
			if unmountStats != nil {
				unmountStats.RecordUnmount(nodeID, sandfsID, "etcd-fence", res, err == nil)
			}
			if err != nil {
				// Success-gated: a failed fence unmount must NOT tear down the
				// entry/bound — "health stale past fence" must keep meaning "no
				// live mounts", so the release keeps retrying until it lands
				// (see the lease-expiry wiring). ForceUnmount (unlike plain
				// RetryUnmount) also covers mounts whose lease entry was lost —
				// the fence's proof must hold for every mount the ownership
				// cache reports, not just the ones with a live lease entry.
				// The fence's soundness argument (release completes within
				// fence + T_clean) assumes transient failures only; a
				// persistent one is operator-visible via the recurring warn.
				logger.Warn("self-fence unmount failed; will retry with backoff", "sandfsID", sandfsID, "node", nodeID, "error", err)
				lm.ForceUnmount(sandfsID, nodeID, spec)
				return
			}
			released.Add(1)
			// Mirror the lease-expiry teardown: settle the lease entry
			// (exactly-once — the entry's own expiry may race this fence
			// unmount) and free the bound VM so the node's derived clean
			// count recovers.
			ownership.NoteUnmounted(sandfsID)
			if lm.SettleUnmount(sandfsID) {
				pm.ReleaseBound(nodeID, spec)
			}
		}(sandfsID, nodeID)
	}
	wg.Wait()
	return int(released.Load())
}

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
// Package config defines the Gateway configuration types, YAML loading,
// and change classification for hot-reload vs restart-required.

package config

import (
	"fmt"
	"math"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"common/config"

	"bytes"
	"gopkg.in/yaml.v3"
)

// DefaultIdentityStoreFilename is the snapshot filename used when
// IdentityStore is empty. It lives in the GATEWAY'S OWN state directory —
// the parent of VolRoot (the systemd unit's StateDirectory), NOT inside the
// volumes tree: the identity snapshot is gateway state, and the volumes tree
// belongs to the storage plane (prov instances + sandvmm's FUSE passthrough)
// — the gateway holds no write access there.
const DefaultIdentityStoreFilename = "identity-store.json"

// EffectiveIdentityStorePath resolves the single-node identity store file.
// Persistence is mandatory in MemoryStore mode, so this NEVER returns "":
// an explicit path wins; otherwise it resolves to the gateway state dir
// (VolRoot's parent). VolRoot must be absolute. An explicit EMPTY
// -identity-store is rejected by cmd before this is consulted — it cannot
// mean "disabled".
func (cfg *GatewayConfig) EffectiveIdentityStorePath() string {
	if cfg.IdentityStore != "" {
		return cfg.IdentityStore
	}
	return filepath.Join(filepath.Dir(cfg.VolRoot), DefaultIdentityStoreFilename)
}

// ListenerConfig holds the address and TLS configuration for a single listener.
type ListenerConfig struct {
	Addr    string `yaml:"addr"`
	TLSCert string `yaml:"tls_cert"`
	TLSKey  string `yaml:"tls_key"`
	TLSCA   string `yaml:"tls_ca"`
}

// StreamConcurrencyConfig holds the gateway<->sandlot gRPC stream concurrency
// and transport parameters. All VMCommands to a sandlot node are multiplexed
// over a single bidi stream (by commandId); these govern how many can be
// in-flight at once and the gRPC/HTTP-2 transport caps. All restart-required
// (gRPC server options are fixed at startup).
type StreamConcurrencyConfig struct {
	// SendBufferSize is the per-node sendCh capacity: the max number of
	// VMCommands in-flight to one sandlot before the gateway fails fast with
	// ErrSendQueueFull (not queued). Default 2000.
	SendBufferSize int `yaml:"send_buffer_size"`
	// WriteTimeoutSec is the max wait for a stream.Send to complete; detects
	// half-open TCP and triggers a full reconnect. Default 30.
	WriteTimeoutSec int `yaml:"write_timeout_sec"`
	// InitialWindow is the HTTP/2 per-stream flow-control window in bytes.
	// Shared by all in-flight responses on the single bidi stream, so it must
	// be >= MaxMsgSize and sized for concurrency headroom. Default 64MB.
	InitialWindow int `yaml:"initial_window"`
	// InitialConnWindow is the HTTP/2 per-connection window in bytes (>=
	// InitialWindow). Default 128MB.
	InitialConnWindow int `yaml:"initial_conn_window"`
	// MaxMsgSize is the gRPC max send/recv message size in bytes. Bounds a
	// single FileOp read/write payload; must be >= the warden single-op cap
	// (max_file_read_bytes / max_body_len) so gRPC is never the bottleneck.
	// Default 16MB.
	MaxMsgSize int `yaml:"max_msg_size"`
}

// LeaseConfig holds the sticky-lease parameters.
type LeaseConfig struct {
	StickyMs     int `yaml:"sticky_ms"`
	MaxStickySec int `yaml:"max_sticky_sec"`
}

// ExecConfig holds the agent-controllable exec timeout parameters.
type ExecConfig struct {
	DefaultTimeoutSec int `yaml:"default_timeout_sec"`
	MaxTimeoutSec     int `yaml:"max_timeout_sec"`
	// MaxBackgroundLeaseSec caps the bg exec lease_duration (absolute run-time
	// cap; status polls do NOT extend it). Default 3600s (1h).
	MaxBackgroundLeaseSec int `yaml:"max_background_lease_sec"`
}

// UnmountStatsConfig holds the per-node unmount stats collector parameters.
// The collector records a FIXED footprint per node (counters + top-10 slowest
// unmounts) on the async release path; PersistIntervalSec controls how often a
// snapshot is async-written to etcd (/sandswap/unmount-stats/{gatewayID}) for
// peer /stats aggregation. Default 600s (10min).
type UnmountStatsConfig struct {
	PersistIntervalSec int `yaml:"persist_interval_sec"`
}

// MCPConfig holds the embedded MCP server parameters.
type MCPConfig struct {
	// InstructionsFile is the optional markdown file with the overall MCP
	// server guide (served on initialize + the sandswap_guide tool). Empty =
	// built-in default text. Loaded at startup and hot-reloaded on file
	// change; a missing/unreadable/oversized file falls back to the default
	// with a Warn (never blocks startup). The PATH itself is restart-required.
	InstructionsFile string `yaml:"instructions_file"`
}

// AuthnConfig holds the OIDC authentication configuration for human endpoints.
type AuthnConfig struct {
	Issuer         string `yaml:"issuer"`           // OIDC issuer URL (empty = no auth)
	ClientID       string `yaml:"client_id"`        // OAuth2 client_id for audience validation
	JWKSRefreshSec int    `yaml:"jwks_refresh_sec"` // JWKS cache refresh interval (default 3600)
	MTLSTrustCert  bool   `yaml:"mtls_trust_cert"`  // Trust mTLS client certificates (default false)
	ScopeHuman     string `yaml:"scope_human"`      // Scope for user-resource CRUD: /human/sandfs, /human/templates (default "sandswap:human")
	ScopeAdmin     string `yaml:"scope_admin"`      // Scope for credential minting: /human/agent* (default "sandswap:admin")
	ScopeOps       string `yaml:"scope_ops"`        // Scope for observability + fleet reclamation: /stats, /metrics, /human/ownership/* (default "sandswap:ops")
	// AllowAnonymous is the EXPLICIT opt-out that lets the human listener
	// start with no issuer configured (the entire human control plane is
	// then anonymous). Without it, a human listener with no issuer refuses
	// to start — silence must not be the way a control plane goes
	// unauthenticated. -allow-anonymous-human.
	AllowAnonymous bool `yaml:"allow_anonymous"`
	// AllowAnonymousPublic permits the anonymous human API on a
	// NON-loopback listen address. Without it, an anonymous human listener is
	// restricted to loopback: the control plane mints agent keys and runs
	// fleet-wide switches, so LAN exposure must be a second, explicit
	// acknowledgement (or, better, authn.issuer).
	AllowAnonymousPublic bool `yaml:"allow_anonymous_public"`
}

// IdentityLoadConfig tunes the etcd-backed identity store's snapshot loader and lazy
// load-back behavior (multi-node human/exec modes only). All restart-required.
type IdentityLoadConfig struct {
	// LoadPageSize is the per-page key count of the parallel snapshot loader.
	// Pages stay far below etcd request-size limits at any scale. Default 1000.
	LoadPageSize int `yaml:"load_page_size"`
	// LoadWorkers bounds the concurrency of the parallel snapshot loader.
	// Default 16.
	LoadWorkers int `yaml:"load_workers"`
	// FullLoadTimeoutSec is the deadline for one full snapshot load (startup
	// and post-compaction rebuilds alike). Default 120.
	FullLoadTimeoutSec int `yaml:"full_load_timeout_sec"`
	// LazyLoad enables on-demand point Gets for cache misses after the initial
	// snapshot load (default true). When disabled the cache is served strictly
	// from the snapshot plus watch events and misses return not-found.
	LazyLoad bool `yaml:"lazy_load"`
	// HotOnly skips loading/watching display metadata (sandfs name/description).
	// Exec gateways should enable it to shrink the resident cache.
	HotOnly bool `yaml:"hot_only"`
}

// SchedConfig holds the node-scheduling policy.
type SchedConfig struct {
	// Policy: "binpack" (default) or "spread". binpack concentrates new placements
	// onto the busiest eligible nodes; spread distributes to the idlest.
	Policy string `yaml:"policy"`
	// Scorer weights (components normalized to [0,1]; 0 uses the built-in
	// default for that weight).
	WLoad  float64 `yaml:"w_load"`  // load headroom
	WHost  float64 `yaml:"w_host"`  // host headroom
	WClean float64 `yaml:"w_clean"` // fitting clean VM count
	WDaily float64 `yaml:"w_daily"` // durable headroom (duty_daily)
	WRisk  float64 `yaml:"w_risk"`  // tail-risk penalty (peak duty + volatility)
	// Hard filter caps (0 disables).
	HostCPUHard float64 `yaml:"host_cpu_hard"`
	DutyHard    float64 `yaml:"duty_hard"`
	// FloorFrac is the tail-floor fraction of pool_target for min_clean_window
	// (0 = default 0.2). A node whose 60s min-clean window for a fitting spec is
	// below the floor is excluded from placement.
	FloorFrac float64 `yaml:"floor_frac"`
}

// GatewayConfig is the top-level configuration for the gateway process.
// It mirrors the YAML structure in gateway.yaml.
type GatewayConfig struct {
	// reapplier re-applies the startup CLI-flag overrides to a freshly decoded
	// config (installed by cmd via SetFlagReapplier). The reload callback runs
	// it before diffing/swapping so the documented precedence ("CLI flags
	// override the config file") also holds ACROSS a reload — without it the
	// first file edit silently reverted every flag-provided value (a
	// -sticky-ms 500 or -etcd-fence-sec 600 dropped back to the file value
	// mid-flight, and restart-required flag-only keys produced phantom
	// "requires restart" warnings on every unrelated edit).
	reapplier func(*GatewayConfig)

	VolRoot  string `yaml:"vol_root"`
	Mode     string `yaml:"mode"`
	Etcd     string `yaml:"etcd"`
	EtcdCA   string `yaml:"etcd_ca"`
	EtcdCert string `yaml:"etcd_cert"`
	EtcdKey  string `yaml:"etcd_key"`
	// AllowInsecureEtcd permits a NON-loopback etcd endpoint without TLS.
	// Default false: a plaintext etcd reachable from the pod/host network is
	// cluster control (ownership/placement writes) available to anyone who can
	// reach it. Explicit opt-out for dev/test topologies only.
	AllowInsecureEtcd bool `yaml:"allow_insecure_etcd"`
	// IdentityStore is the single-node identity store file: the file agents and
	// sandfs records are persisted to and reloaded from across restarts.
	// Empty (default) = <vol_root's PARENT>/identity-store.json — never inside
	// the volumes tree, which belongs to the storage plane (the gateway holds no
	// write grant there).. Persistence itself
	// is MANDATORY in MemoryStore mode (a MemoryStore without a snapshot
	// orphans every identity on restart) — an explicit empty value is a
	// startup error, and human/exec modes ignore this flag (identity in etcd).
	// IdentityLoadConfig above is the MULTI-node etcd loader config — deliberately
	// unrelated.
	IdentityStore string `yaml:"identity_store"`
	// IdentityStoreExplicit records that -identity-store was passed on the
	// command line. cmd uses it to reject an explicit EMPTY value (persistence
	// cannot be disabled) and to warn in etcd modes where the flag is ignored.
	// Not settable via YAML, hence yaml:"-".
	IdentityStoreExplicit bool `yaml:"-"`
	// GatewayID is the fixed, stable identity of this gateway process. When set,
	// it is used verbatim for ownership/registry keys. When empty, the
	// gateway derives a stable ID from the hostname (k8s pod name in-cluster),
	// dropping the pid so it survives restarts. In k8s, inject the pod name via
	// -gateway-id for a clean, explicit ID.
	GatewayID string `yaml:"gateway_id"`
	// GatewayURL is the base URL other components use to reach THIS gateway
	// for agent traffic: 307 redirect Location and the owner-aware DNS CNAME
	// target. In k8s in-cluster: https://gateway-<i>.<svc>.<ns>.svc.cluster.local:3000.
	// Empty = gateway is alive but unroutable (no 307/DNS).
	GatewayURL string `yaml:"gateway_url"`
	// GatewayStreamAddr is the host:port sandlots use to reconnect to THIS gateway
	// (sandlot remembers its last gateway). In k8s in-cluster:
	// gateway-<i>.<svc>.<ns>.svc.cluster.local:9998.
	GatewayStreamAddr string `yaml:"gateway_stream_addr"`
	// IdleTimeoutSec is the HTTP keep-alive idle timeout. Default 3600s
	// (60min): agents that pause between tool calls for up to an hour keep
	// their connection (connection = affinity anchor). Keep ReadHeaderTimeout
	// short separately to stay safe against slowloris. Do NOT set 0 — Go's
	// http.Server falls back to ReadTimeout (30s) for IdleTimeout==0, which is
	// worse. Operators who want longer can set e.g. 10800 (3h). -1 = never
	// close idle connections server-side (see IdleTimeout()); the connection
	// then lives until the client, TCP keepalive, an intermediary (LB/NAT),
	// or a process restart ends it. Values below -1 are invalid — the
	// startup guard in cmd rejects them (a -3600 is a dropped sign, not an
	// intent).
	IdleTimeoutSec int `yaml:"idle_timeout_sec"`
	// OpsTokenFile (CLI-only, no YAML key): bearer-token file gating the
	// exec-mode agent listener's /stats and /metrics. Empty = disabled.
	// Deliberately unserialized: it survives reloads via the flag reaper
	// (ApplyFlagOverrides), never via the config file.
	OpsTokenFile      string
	Agent             ListenerConfig          `yaml:"agent"`
	Human             ListenerConfig          `yaml:"human"`
	Stream            ListenerConfig          `yaml:"stream"`
	StreamConcurrency StreamConcurrencyConfig `yaml:"stream_concurrency"`
	Lease             LeaseConfig             `yaml:"lease"`
	Exec              ExecConfig              `yaml:"exec"`
	UnmountStats      UnmountStatsConfig      `yaml:"unmount_stats"`
	// StorageOpDeadlineSec bounds one storage-plane op on the executing node
	// (template pulls can move GBs). Default 300.
	StorageOpDeadlineSec int                `yaml:"storage_op_deadline_sec"`
	Authn                AuthnConfig        `yaml:"authn"`
	IdentityLoad         IdentityLoadConfig `yaml:"identity_load"`
	Sched                SchedConfig        `yaml:"sched"`
	// MCP holds the embedded MCP server parameters (instructions file).
	MCP MCPConfig `yaml:"mcp"`
	// Shed holds the voluntary load-shed parameters (default enabled). When
	// enabled, a sustained-saturated owner gateway sheds cold-path
	// sandfs ownership so the Sandswap DNS re-routes the client to an idle peer.
	Shed ShedConfig `yaml:"shed"`
	// SelfLoad holds the gateway's self-pressure gate parameters: sustained
	// process-scoped resource pressure (CPU vs GOMAXPROCS, managed memory vs
	// soft limit) that removes the gateway from DNS routing candidacy via the
	// published self_pressured flag. Hot-reloadable; exec mode only.
	SelfLoad SelfLoadConfig `yaml:"selfload"`
	// Staleness holds the health-staleness thresholds that turn the health key's
	// last_healthy_ts into a per-consumer liveness signal (routing/redirect
	// reroute, idle-claim protection, alert scan). Restart-required (timing
	// anchors read at ownership-cache construction).
	Staleness StalenessConfig `yaml:"staleness"`
	// Ownership holds the ownership-cache tuning knobs (the Claim fast-path
	// freshness window — the etcd revalidation cadence). Hot-reloadable.
	Ownership      OwnershipConfig `yaml:"ownership"`
	ConfigFilePath string          `yaml:"-"` // set from -config flag, not from YAML
}

// OwnershipConfig holds the ownership-cache tuning knobs.
type OwnershipConfig struct {
	// CacheTTLSec is the Claim fast-path freshness window: how long a cached
	// ownership entry may be served without re-validating against etcd. It is
	// the etcd read-load lever — the steady linearizable Get rate is
	// (actively-queried sandfs) / TTL, and adding gateways does NOT divide it
	// (each sandfs belongs to exactly one gateway). Safety ceiling (validated
	// at startup, hot-reload, and on every guard change): 1 <= TTL <=
	// min(2 × staleness.claim_dead_guard_sec, 300) — while this gateway is
	// healthy no peer can take over its keys (every takeover gates on owner
	// health stale past the guard), and the earliest a takeover can COMMIT
	// after our absence is ~2 × guard (ownerDead + the per-sandfs deadSince
	// guard), so a stale-cache serve window <= TTL cannot overlap it. Default
	// 30 (aligned with the DNS owner-cache TTL — the same takeover-visibility
	// budget family).
	CacheTTLSec int `yaml:"cache_ttl_sec"`
}

// ShedConfig holds the voluntary load-shed parameters. Hot-reloadable.
// The zero value means disabled: the gateway behaves exactly as before
// (NO_AVAILABLE_SANDBOX 503 on saturation, no ownership migration). The
// built-in default enables shedding; only an explicit `enabled: false` /
// `-enable-load-shed=false` turns it off.
type ShedConfig struct {
	// Enabled turns on shedding. Default true; a no-op without etcd ownership
	// or an idle peer (MaybeShed gates on both).
	Enabled bool `yaml:"enabled"`
	// SatSec: sustained-saturation seconds required before shedding (hysteresis
	// against transient spikes). Default 15.
	SatSec int `yaml:"sat_sec"`
	// RatePerSec: max sheds per second (token-bucket anti-thrash). Default 1.
	RatePerSec int `yaml:"rate_per_sec"`
	// CooldownSec: recentlyShed window during which we refuse to re-claim a shed
	// sandfs (so a peer can claim it). Default 30.
	CooldownSec int `yaml:"cooldown_sec"`
	// RetryAfterSec: Retry-After hint (seconds) sent on a shed 503. Should be
	// ≈ the sandfs DNS zone TTL so a compliant client waits for the record to
	// expire before retrying. Default 5.
	RetryAfterSec int `yaml:"retry_after_sec"`
}

// SelfLoadConfig holds the gateway self-pressure gate parameters: what
// counts as "this gateway process is overloaded" for DNS routing. The
// signals are process-scoped and sustained (EWMA + a sustain window) — see
// lease.SelfPressureMonitor. Hot-reloadable.
type SelfLoadConfig struct {
	// CpuHard is the CPU threshold as a percentage of GOMAXPROCS (0..100;
	// <= 0 disables the CPU signal). On Go 1.25+ GOMAXPROCS honors the cgroup
	// CPU quota, so in containers this is quota saturation and on bare metal
	// real-core saturation. Default 85.
	CpuHard float64 `yaml:"cpu_hard"`
	// MemHard is the memory threshold as managed-memory / soft-limit
	// (0..1; <= 0 disables the memory signal). The soft limit comes from
	// -gomemlimit / GOMEMLIMIT; without one the signal is absent entirely.
	// Default 0.90.
	MemHard float64 `yaml:"mem_hard"`
	// SatSec is how long either signal must stay over its threshold before
	// self_pressured flips (hysteresis against spikes; 0 = immediate).
	// Default 10.
	SatSec int `yaml:"sat_sec"`
}

// StalenessConfig holds the health-staleness thresholds. The health key is a
// PLAIN key (no lease): death is judged purely by the value's last_healthy_ts,
// and each consumer thresholds that staleness independently by its own cost of
// judging wrong — routing (cheap, fast) < alerting (early) < takeover guard
// (expensive, slow). Hot-reloadable.
type StalenessConfig struct {
	// RouteStaleSec is the staleness at which DNS routing and the 307 redirect
	// stop routing to an owner. Judging wrong is cheap (a napping owner
	// handles the request fine once it wakes), so this is the fastest death
	// threshold; a live owner refreshes every 5s and is never stale at 20s.
	// Default 20.
	RouteStaleSec int `yaml:"route_stale_sec"`
	// ClaimDeadGuardSec is the idle-claim protection window: how long a
	// dead-owned IDLE sandfs must stay dead-and-untouched before a peer
	// force-takes-over via CAS. Judging wrong is expensive (robbing a live
	// owner), so this sits well past route-stale to ride out naps/GC pauses,
	// and far below T_safe. Mounted sandfs use the migrated-node signal
	// instead. Default 45.
	ClaimDeadGuardSec int `yaml:"claim_dead_guard_sec"`
	// AlertStaleSec is the staleness at which the alert scan warns about an
	// owner whose health record is stale while sandfs are still pointed at it.
	// Warns before the takeover guard would fire. Default 30.
	AlertStaleSec int `yaml:"alert_stale_sec"`
	// EtcdFenceSec is the etcd-partition self-fence threshold (sec): if the
	// health-key write fails continuously this long, the gateway actively
	// unmounts every sandfs it holds while KEEPING its node streams connected,
	// so "health stale past fence + T_clean" provably holds no mounts (what
	// makes the time-guarded takeover sound) while node pools stay warm for an
	// in-place recovery. Constrained by T_safe > fence + T_warden + 30s
	// (validated per node at connect). Generous by design: transient etcd blips
	// never fence. Default 180.
	EtcdFenceSec int `yaml:"etcd_fence_sec"`
	// AlertScanIntervalSec is the staleness-alert-scan cadence (sec) on the
	// human gateway: a full ownership-prefix sweep (O(all keys) + JSON decode
	// per key). At a million ownership keys a 30s cadence costs ~1 core
	// continuously on the control plane, so large fleets raise it (300s is
	// a sane million-scale value). The floor is 10s (a smaller value would turn
	// the control plane into a constant full scan). Default 30.
	AlertScanIntervalSec int `yaml:"alert_scan_interval_sec"`
}

// Defaults returns a GatewayConfig populated with built-in defaults.
// NeverCloseIdle is the http.Server IdleTimeout value that never fires. Go
// cannot express "no idle timeout" directly — IdleTimeout==0 falls back to
// ReadTimeout, and a negative duration would be a deadline already expired
// (connections closed on first idle) — so a negative IdleTimeoutSec is
// translated to the largest finite duration (~292 years; now+d stays in
// range for any realistic process uptime).
const NeverCloseIdle = time.Duration(math.MaxInt64)

// IdleTimeout converts IdleTimeoutSec into the http.Server.IdleTimeout value.
// -1 = never close idle connections server-side (mapped defensively for any
// negative, though the startup guard rejects values below -1 before this
// runs). Zero is passed through unchanged — http.Server then uses ReadTimeout
// (30s), which is exactly the misconfiguration the startup warning calls out.
func (c *GatewayConfig) IdleTimeout() time.Duration {
	if c.IdleTimeoutSec < 0 {
		return NeverCloseIdle
	}
	return time.Duration(c.IdleTimeoutSec) * time.Second
}

// Defaults shared by the YAML defaults and the CLI flag defaults; the two must
// stay identical (a flag default that differs from Defaults() silently changes
// behavior when the flag is not explicit). Every literal pair that both sides
// used to spell out independently is named here and referenced from both.
const (
	DefaultStickyMs     = 100
	DefaultMaxStickySec = 5

	DefaultAgentAddr  = ":3000"
	DefaultHumanAddr  = ":3100"
	DefaultStreamAddr = ":9998"

	DefaultExecTimeoutSec    = 30
	DefaultMaxExecTimeoutSec = 180

	DefaultVolRoot                = "/var/sandswap/volumes"
	DefaultStorageOpDeadlineSec   = 300
	DefaultIdleTimeoutSec         = 3600 // 60min: connection = affinity anchor
	DefaultMaxBackgroundLeaseSec  = 60 * 60
	DefaultUnmountStatsPersistSec = 600

	// Voluntary load shedding.
	DefaultShedSatSec        = 15
	DefaultShedRatePerSec    = 1
	DefaultShedCooldownSec   = 30
	DefaultShedRetryAfterSec = 5

	// Health staleness thresholds (see the per-field docs on StalenessConfig).
	DefaultRouteStaleSec        = 20
	DefaultClaimDeadGuardSec    = 45
	DefaultAlertStaleSec        = 30
	DefaultEtcdFenceSec         = 180
	DefaultAlertScanIntervalSec = 30
	DefaultOwnershipCacheTTLSec = 30

	// Human-API authentication.
	DefaultAuthnJWKSRefreshSec = 3600
	DefaultScopeHuman          = "sandswap:human"
	DefaultScopeAdmin          = "sandswap:admin"
	DefaultScopeOps            = "sandswap:ops"

	// Etcd identity snapshot loader.
	DefaultIdentityLoadPageSize       = 1000
	DefaultIdentityLoadWorkers        = 16
	DefaultIdentityFullLoadTimeoutSec = 120
)

func Defaults() GatewayConfig {
	return GatewayConfig{
		VolRoot:              DefaultVolRoot,
		Mode:                 "",
		Etcd:                 "",
		StorageOpDeadlineSec: DefaultStorageOpDeadlineSec,
		// 60min idle (default): connection = affinity anchor. Agents that pause
		// between tool calls for up to an hour keep their connection.
		IdleTimeoutSec: DefaultIdleTimeoutSec,
		Agent: ListenerConfig{
			Addr:    DefaultAgentAddr,
			TLSCert: "",
			TLSKey:  "",
			TLSCA:   "",
		},
		Human: ListenerConfig{
			Addr:    DefaultHumanAddr,
			TLSCert: "",
			TLSKey:  "",
			TLSCA:   "",
		},
		Stream: ListenerConfig{
			Addr:    DefaultStreamAddr,
			TLSCert: "",
			TLSKey:  "",
			TLSCA:   "",
		},
		StreamConcurrency: StreamConcurrencyConfig{
			SendBufferSize:    config.DefaultStreamSendBuffer,
			WriteTimeoutSec:   config.DefaultStreamWriteTimeoutSec,
			InitialWindow:     config.DefaultStreamInitialWindowMB << 20,
			InitialConnWindow: config.DefaultStreamConnWindowMB << 20,
			MaxMsgSize:        config.DefaultStreamMaxMsgSizeMB << 20,
		},
		Lease: LeaseConfig{
			StickyMs:     DefaultStickyMs,
			MaxStickySec: DefaultMaxStickySec,
		},
		Exec: ExecConfig{
			DefaultTimeoutSec: DefaultExecTimeoutSec,
			// DefaultMaxExecTimeoutSec matches the warden's default
			// max_exec_timeout and stays strictly below the warden countdown
			// (default 300): the gateway clamp must never admit a sync exec the
			// warden would kill early or the countdown could trip mid-run. Keep
			// the chain gateway max <= warden max_exec_timeout < warden_countdown
			// when any of them is overridden.
			MaxTimeoutSec:         DefaultMaxExecTimeoutSec,
			MaxBackgroundLeaseSec: DefaultMaxBackgroundLeaseSec,
		},
		UnmountStats: UnmountStatsConfig{
			PersistIntervalSec: DefaultUnmountStatsPersistSec,
		},
		Sched: SchedConfig{
			Policy: "binpack",
		},
		Shed: ShedConfig{
			Enabled:       true, // default on
			SatSec:        DefaultShedSatSec,
			RatePerSec:    DefaultShedRatePerSec,
			CooldownSec:   DefaultShedCooldownSec,
			RetryAfterSec: DefaultShedRetryAfterSec,
		},
		SelfLoad: SelfLoadConfig{
			CpuHard: 85,  // % of GOMAXPROCS
			MemHard: 0.9, // managed-mem / soft limit
			SatSec:  10,
		},
		Staleness: StalenessConfig{
			RouteStaleSec:        DefaultRouteStaleSec,
			ClaimDeadGuardSec:    DefaultClaimDeadGuardSec,
			AlertStaleSec:        DefaultAlertStaleSec,
			EtcdFenceSec:         DefaultEtcdFenceSec,
			AlertScanIntervalSec: DefaultAlertScanIntervalSec,
		},
		Ownership: OwnershipConfig{
			CacheTTLSec: DefaultOwnershipCacheTTLSec,
		},
		Authn: AuthnConfig{
			Issuer:         "",
			ClientID:       "",
			JWKSRefreshSec: DefaultAuthnJWKSRefreshSec,
			MTLSTrustCert:  false,
			ScopeHuman:     DefaultScopeHuman,
			ScopeAdmin:     DefaultScopeAdmin,
			ScopeOps:       DefaultScopeOps,
		},
		IdentityLoad: IdentityLoadConfig{
			LoadPageSize:       DefaultIdentityLoadPageSize,
			LoadWorkers:        DefaultIdentityLoadWorkers,
			FullLoadTimeoutSec: DefaultIdentityFullLoadTimeoutSec,
			LazyLoad:           true,
			HotOnly:            false,
		},
	}
}

// ValidateLease checks the lease knobs' lower bounds. sticky_ms must be >= 1:
// concurrent sync commands are safe through two layers — overlapping RPCs are
// held by the lease's in-flight refcount (window-independent), while arrival
// gaps are bridged by the window-refresh chain (every arrival rewrites
// syncStickyUntil = now + window). A 0 window makes each refresh write an
// instantly-stale boundary, so any command arriving right after the previous
// one completes triggers unmount + cold-remount churn instead of joining the
// warm VM. max_sticky_sec must be >= 1: <= 0 silently disables the maxHold
// reaper (the safety net that bounds chatty pure-sync sandboxes).
// ValidateEtcd refuses a plaintext etcd endpoint that is reachable beyond
// loopback. etcd holds ownership/placement keys: a writer can re-route
// sandfs and claim ownerships, so a non-loopback plaintext endpoint is a
// cluster-control exposure, not a tuning choice. TLS (https:// or any of
// etcd_ca/etcd_cert/etcd_key) satisfies the check; otherwise the operator
// must pass an explicit allow_insecure_etcd / -allow-insecure-etcd.
// Single-node mode (empty Etcd) is unaffected.
func (c GatewayConfig) ValidateEtcd() error {
	if c.Etcd == "" {
		return nil
	}
	if (c.EtcdCert == "") != (c.EtcdKey == "") {
		return fmt.Errorf("etcd TLS: etcd_cert and etcd_key must be set together")
	}
	tlsConfigured := c.EtcdCA != "" || c.EtcdCert != "" || c.EtcdKey != ""
	for _, raw := range strings.Split(c.Etcd, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		u, err := url.Parse(raw)
		if err != nil {
			return fmt.Errorf("etcd endpoint %q: %w", raw, err)
		}
		host := u.Hostname()
		if host == "" {
			return fmt.Errorf("etcd endpoint %q has no host", raw)
		}
		if tlsConfigured || strings.EqualFold(u.Scheme, "https") {
			continue
		}
		if isLoopbackHost(host) || c.AllowInsecureEtcd {
			continue
		}
		return fmt.Errorf("etcd endpoint %q is non-loopback and has no TLS — set etcd_ca/etcd_cert/etcd_key (or an https:// endpoint), or pass an explicit allow_insecure_etcd for a dev topology; refusing to expose cluster control in plaintext", raw)
	}
	return nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

func (c GatewayConfig) ValidateLease() error {
	if c.Lease.StickyMs < 1 {
		return fmt.Errorf("lease.sticky_ms must be >= 1 (milliseconds), got %d: a 0-or-negative window breaks the refresh mechanism that lets post-completion concurrent arrivals join the warm VM", c.Lease.StickyMs)
	}
	if c.Lease.MaxStickySec < 1 {
		return fmt.Errorf("lease.max_sticky_sec must be >= 1 (seconds), got %d: <= 0 silently disables the maxHold reaper safety net", c.Lease.MaxStickySec)
	}
	return nil
}

// ValidateExec checks the sync-exec timeout bounds. default/max must both be
// >= 1 and max >= default: the ExecuteHandler constructor normalizes
// out-of-range values (default<=0 → 30, max<default → default) so a typo like
// -max-exec-timeout-sec 2 with default 5 silently becomes 5 — a config the
// operator did not write. Startup refuses instead; the constructor fallbacks
// remain as defense for direct constructions (tests).
func (c GatewayConfig) ValidateExec() error {
	if c.Exec.DefaultTimeoutSec < 1 {
		return fmt.Errorf("exec.default_timeout_sec must be >= 1, got %d", c.Exec.DefaultTimeoutSec)
	}
	if c.Exec.MaxTimeoutSec < 1 {
		return fmt.Errorf("exec.max_timeout_sec must be >= 1, got %d", c.Exec.MaxTimeoutSec)
	}
	if c.Exec.MaxTimeoutSec < c.Exec.DefaultTimeoutSec {
		return fmt.Errorf("exec.max_timeout_sec (%d) must be >= exec.default_timeout_sec (%d): the gateway would silently normalize the max down-clamp otherwise",
			c.Exec.MaxTimeoutSec, c.Exec.DefaultTimeoutSec)
	}
	return nil
}

// ValidateStreamConcurrency checks the stream transport knobs. The window and
// message-size caps share the gateway/sandlot contract (ValidateStreamCaps);
// the per-node send buffer and write timeout must both be >= 1 (the stream
// server clamps <= 0 to defaults, silently discarding the operator's value).
// Restart-required: validated at startup only.
func (c GatewayConfig) ValidateStreamConcurrency() error {
	if c.StreamConcurrency.SendBufferSize < 1 {
		return fmt.Errorf("stream_concurrency.send_buffer_size must be >= 1, got %d", c.StreamConcurrency.SendBufferSize)
	}
	if c.StreamConcurrency.WriteTimeoutSec < 1 {
		return fmt.Errorf("stream_concurrency.write_timeout_sec must be >= 1, got %d", c.StreamConcurrency.WriteTimeoutSec)
	}
	return config.ValidateStreamCaps(c.StreamConcurrency.InitialWindow, c.StreamConcurrency.InitialConnWindow, c.StreamConcurrency.MaxMsgSize)
}

// ValidateStaleness checks the health-staleness thresholds: each >= 1 (<= 0
// would silently keep the default, hiding the operator's intent) and the
// documented judging-cost ordering — the dead-owned takeover guard must not
// fire before the routing/alert thresholds (equal is allowed: e2e compresses
// all three to the same second). Also bounds the alert-scan cadence (>= 10s —
// the scan is a full ownership-prefix sweep on the human gateway).
func (c GatewayConfig) ValidateStaleness() error {
	if err := ValidateStalenessValues(c.Staleness.RouteStaleSec, c.Staleness.ClaimDeadGuardSec, c.Staleness.AlertStaleSec); err != nil {
		return err
	}
	if c.Staleness.AlertScanIntervalSec < 10 {
		return fmt.Errorf("staleness.alert_scan_interval_sec must be >= 10 (got %d): the scan is a full ownership sweep — a smaller cadence turns the management plane into a constant full scan",
			c.Staleness.AlertScanIntervalSec)
	}
	return nil
}

// ValidateOwnership checks the Claim cache TTL against its safety ceiling: the
// stale-cache serve window (<= TTL) must never be able to overlap the earliest
// possible takeover commit (~2 × claim-dead-guard after our absence). The
// ceiling is min(2 × guard, 300). Shared by the startup guard and the
// hot-reload refusal.
func (c GatewayConfig) ValidateOwnership() error {
	ttl := c.Ownership.CacheTTLSec
	guard := c.Staleness.ClaimDeadGuardSec
	if ttl < 1 {
		return fmt.Errorf("ownership.cache_ttl_sec must be >= 1 (got %d): <= 0 silently keeps the default", ttl)
	}
	ceil := 2 * guard
	if ceil > 300 {
		ceil = 300
	}
	if ttl > ceil {
		return fmt.Errorf("ownership.cache_ttl_sec (%d) exceeds the safety ceiling min(2×staleness.claim_dead_guard_sec=%d, 300): while healthy no peer can take over our keys, but a stale-serve window longer than 2×guard could overlap the earliest takeover commit after a pause — lower the TTL or raise the guard",
			ttl, 2*guard)
	}
	return nil
}

// ValidateStalenessValues is the field-level form of ValidateStaleness, shared
// by the startup guard and the hot-reload refusal (which sees raw values).
func ValidateStalenessValues(routeStaleSec, claimDeadGuardSec, alertStaleSec int) error {
	if routeStaleSec < 1 || claimDeadGuardSec < 1 || alertStaleSec < 1 {
		return fmt.Errorf("staleness thresholds must all be >= 1 (got route=%d guard=%d alert=%d): <= 0 silently keeps the default",
			routeStaleSec, claimDeadGuardSec, alertStaleSec)
	}
	if routeStaleSec > claimDeadGuardSec {
		return fmt.Errorf("staleness.route_stale_sec (%d) must be <= staleness.claim_dead_guard_sec (%d): routing must give up on an owner no later than the takeover guard may rob it",
			routeStaleSec, claimDeadGuardSec)
	}
	if alertStaleSec > claimDeadGuardSec {
		return fmt.Errorf("staleness.alert_stale_sec (%d) must be <= staleness.claim_dead_guard_sec (%d): the alert must warn before a takeover can fire",
			alertStaleSec, claimDeadGuardSec)
	}
	return nil
}

// ValidateShed checks the load-shed knobs. CooldownSec must be >= 0: a
// negative window means a just-shed sandfs is immediately re-claimable, so the
// next DNS resolution undoes the shed (thrash). RetryAfterSec must be >= 1 —
// the getter clamps <= 0 to a hardcoded 5, silently discarding the config.
// sat_sec/rate_per_sec keep their documented <= 0 = disable sentinel.
func (c GatewayConfig) ValidateShed() error {
	if c.Shed.CooldownSec < 0 {
		return fmt.Errorf("shed.cooldown_sec must be >= 0, got %d: a negative window lets the next DNS resolution instantly undo a shed", c.Shed.CooldownSec)
	}
	if c.Shed.RetryAfterSec < 1 {
		return fmt.Errorf("shed.retry_after_sec must be >= 1, got %d", c.Shed.RetryAfterSec)
	}
	return nil
}

// classifyField returns whether a config field change is hot-reloadable or
// requires a restart. There is no templates block: template storage (and its
// registry credentials) lives on the prov instances, never on the gateway.
//   - Hot-reload: lease.*, exec.*
//   - Restart-required: everything else (vol_root, mode, etcd, agent.*, human.*, stream.*)
func classifyField(name string) config.ChangeClass {
	switch {
	// Lease: all hot-reloadable.
	case name == "lease.sticky_ms", name == "lease.max_sticky_sec":
		return config.ChangeHotReload
	// Exec: all hot-reloadable (max_background_lease_sec included — the
	// UpdateMaxBackgroundLeaseSec dispatch case and the flag help both promise
	// it; missing it here classified a YAML edit as restart-required and the
	// callback never fired).
	case name == "exec.default_timeout_sec", name == "exec.max_timeout_sec",
		name == "exec.max_background_lease_sec":
		return config.ChangeHotReload
	// Unmount stats persist interval: hot-reloadable (just retunes the ticker).
	case name == "unmount_stats.persist_interval_sec":
		return config.ChangeHotReload
	// Sched policy: all hot-reloadable (binpack/spread + scorer weights + caps).
	case name == "sched.policy", name == "sched.w_load", name == "sched.w_host",
		name == "sched.w_clean", name == "sched.w_daily", name == "sched.w_risk",
		name == "sched.host_cpu_hard", name == "sched.duty_hard", name == "sched.floor_frac":
		return config.ChangeHotReload
	// Shed (load shedding): all hot-reloadable (toggle + params).
	case name == "shed.enabled", name == "shed.sat_sec", name == "shed.rate_per_sec",
		name == "shed.cooldown_sec", name == "shed.retry_after_sec":
		return config.ChangeHotReload
	// Self-pressure gate: all hot-reloadable (atomic thresholds in the
	// SelfPressureMonitor).
	case name == "selfload.cpu_hard", name == "selfload.mem_hard",
		name == "selfload.sat_sec":
		return config.ChangeHotReload
	// Authn: all restart-required (OIDC provider needs re-initialization).
	case name == "authn.issuer", name == "authn.client_id",
		name == "authn.jwks_refresh_sec", name == "authn.mtls_trust_cert",
		name == "authn.scope_human", name == "authn.scope_admin",
		name == "authn.scope_ops":
		return config.ChangeRestartRequired
	// Staleness thresholds: hot-reloadable (the ownership cache re-reads them
	// under its mutex on every use; SetStalenessThresholds is runtime-safe).
	// etcd_fence_sec joins them: UpdateFenceThreshold re-validates the
	// T_safe > fence + warden + heartbeat invariant against every connected
	// node and refuses a violating value. alert_scan_interval_sec is the
	// control-plane scan cadence (SetAlertScanInterval, re-derived by the
	// scan loop each tick); ownership.cache_ttl_sec is the Claim fast-path
	// freshness window (SetCacheTTL, atomic read on the hot path) — both
	// hot-reloadable with the same refuse-invalid-and-keep-old semantics.
	case name == "staleness.route_stale_sec", name == "staleness.claim_dead_guard_sec",
		name == "staleness.alert_stale_sec", name == "staleness.etcd_fence_sec",
		name == "staleness.alert_scan_interval_sec", name == "ownership.cache_ttl_sec":
		return config.ChangeHotReload
	// Everything else: restart-required.
	default:
		return config.ChangeRestartRequired
	}
}

// Diff compares two GatewayConfig values and returns a ChangeSet classifying
// every changed field as hot-reloadable or restart-required.
func (old GatewayConfig) Diff(new GatewayConfig) config.ChangeSet {
	return config.DiffConfigs(old, new, "", classifyField)
}

// LoadFromFile reads and parses a YAML config file.
func LoadFromFile(path string) (GatewayConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return GatewayConfig{}, fmt.Errorf("read config file: %w", err)
	}
	cfg := Defaults()
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true) // strict: a dead/misspelled key is a startup error, not a silent no-op (dns/config.go's lesson)
	if err := dec.Decode(&cfg); err != nil {
		return GatewayConfig{}, fmt.Errorf("parse config file: %w", err)
	}
	return cfg, nil
}

// GatewayFlags holds the parsed CLI flag values. These are the same flags that
// were previously individual variables in main().
type GatewayFlags struct {
	ConfigPath string // -config

	// Top-level
	VolRoot string
	Mode    string
	Etcd    string

	// Single-node identity store file (restart-required; read only by
	// runSingleNodeMode). Explicitness comes from explicitSet, not a field —
	// GatewayConfig.IdentityStoreExplicit is the load-bearing one.
	IdentityStore string // -identity-store

	// Identity + connection lifetime
	GatewayID         string // -gateway-id
	GatewayURL        string // -gateway-url
	GatewayStreamAddr string // -gateway-stream-addr
	IdleTimeoutSec    int    // -idle-timeout
	// OpsTokenFile gates the exec-mode agent listener's /stats and /metrics
	// behind a static bearer token from this root-owned file. CLI-only (no
	// YAML key, like -log-level): an ops credential's location travels in the
	// unit file, not the shared config. Empty = those endpoints are disabled
	// on the agent listener.
	OpsTokenFile string // -ops-token-file

	// etcd TLS
	EtcdCA   string
	EtcdCert string
	EtcdKey  string
	// AllowInsecureEtcd is the explicit dev-only opt-out for a non-loopback
	// plaintext etcd endpoint (see GatewayConfig.ValidateEtcd).
	AllowInsecureEtcd bool

	// Agent listener
	AgentAddr    string
	AgentTLSCert string
	AgentTLSKey  string
	AgentTLSCA   string

	// Human listener
	HumanAddr    string
	HumanTLSCert string
	HumanTLSKey  string
	HumanTLSCA   string

	// Stream listener
	StreamAddr    string
	StreamTLSCert string
	StreamTLSKey  string
	StreamTLSCA   string

	// Storage plane
	StorageOpDeadlineSec int // -storage-op-deadline-sec

	// Stream concurrency / transport
	StreamSendBuffer    int // -stream-send-buffer
	StreamWriteTimeout  int // -stream-write-timeout-sec
	StreamInitialWindow int // -stream-initial-window-mb
	StreamConnWindow    int // -stream-conn-window-mb
	StreamMaxMsgSize    int // -stream-max-msg-size-mb

	// Lease
	StickyMs     int
	MaxStickySec int

	// MCP server
	MCPInstructionsFile string // -mcp-instructions-file

	// Exec
	DefaultExecTimeoutSec int
	MaxExecTimeoutSec     int
	MaxBackgroundLeaseSec int

	// UnmountStats
	UnmountStatsPersistSec int

	// Authn (OIDC for human endpoints)
	AuthnIssuer         string
	AuthnClientID       string
	AuthnJWKSRefreshSec int
	AuthnMTLSTrustCert  bool
	AuthnScopeHuman     string
	AuthnScopeAdmin     string
	AuthnScopeOps       string
	// AllowAnonymousHuman is -allow-anonymous-human: the explicit opt-out
	// from the human-listener startup refusal when no issuer is configured.
	AllowAnonymousHuman bool
	// AllowAnonymousHumanPublic is -allow-anonymous-human-public: the second
	// acknowledgement that permits the anonymous human listener on a
	// non-loopback bind address.
	AllowAnonymousHumanPublic bool

	// Identity store loading (etcd snapshot loader + lazy load-back, human/exec modes)
	IdentityLoadPageSize       int
	IdentityLoadWorkers        int
	IdentityFullLoadTimeoutSec int
	IdentityLazyLoad           bool
	IdentityHotOnly            bool

	// Sched policy
	SchedPolicy      string
	SchedWLoad       float64
	SchedWHost       float64
	SchedWClean      float64
	SchedWDaily      float64
	SchedWRisk       float64
	SchedHostCPUHard float64
	SchedDutyHard    float64
	SchedFloorFrac   float64

	// Shed (load shedding)
	ShedEnabled       bool
	ShedSatSec        int
	ShedRatePerSec    int
	ShedCooldownSec   int
	ShedRetryAfterSec int

	// Staleness thresholds (health-key staleness judgment)
	StalenessRouteStaleSec        int
	StalenessClaimDeadGuardSec    int
	StalenessAlertStaleSec        int
	StalenessEtcdFenceSec         int
	StalenessAlertScanIntervalSec int
	OwnershipCacheTTLSec          int
}

// ApplyFlagOverrides merges explicitly-set CLI flags over the config file values.
// For each field, if the flag was explicitly set (present in explicitSet), the
// flag value overrides the config file value.
// ValidateStorageDeadline refuses a storage-op deadline below 1 second. Split
// out of ApplyFlagOverrides so BOTH the startup path (cmd: log + exit) and the
// hot-reload path (callback: refuse the edit, keep the old config) can apply it
// without a panic.
// ValidateSelfLoad enforces the documented ranges: cpu_hard 0..100, mem_hard
// 0..1, sat_sec >= 0 (and < sat_sec? no — each documented individually). 0 (or
// negative) disables; a value OUT of range used to be accepted silently and
// never tripped, degrading the gate to off.
func (cfg *GatewayConfig) ValidateSelfLoad() error {
	if cfg.SelfLoad.CpuHard < 0 || cfg.SelfLoad.CpuHard > 100 {
		return fmt.Errorf("selfload.cpu_hard %v: must be 0..100 (percent; 0 disables)", cfg.SelfLoad.CpuHard)
	}
	if cfg.SelfLoad.MemHard < 0 || cfg.SelfLoad.MemHard > 1 {
		return fmt.Errorf("selfload.mem_hard %v: must be 0..1 (fraction; 0 disables)", cfg.SelfLoad.MemHard)
	}
	if cfg.SelfLoad.SatSec < 0 {
		return fmt.Errorf("selfload.sat_sec %d: must be >= 0", cfg.SelfLoad.SatSec)
	}
	return nil
}

// ValidateSchedPolicy refuses an unknown scheduling policy name. The DNS
// validates its twin strictly (SetScheduling); without this, `-sched-policy
// span` silently meant binpack — the opposite of the operator's intent, with
// no log anywhere.
func (cfg *GatewayConfig) ValidateSchedPolicy() error {
	switch cfg.Sched.Policy {
	case "", "binpack", "spread":
		return nil
	}
	return fmt.Errorf("sched.policy %q: must be \"binpack\" or \"spread\"", cfg.Sched.Policy)
}

func (cfg *GatewayConfig) ValidateStorageDeadline() error {
	if cfg.StorageOpDeadlineSec < 1 {
		return fmt.Errorf("storage_op_deadline_sec must be >= 1 (got %d)", cfg.StorageOpDeadlineSec)
	}
	return nil
}

// SetFlagReapplier installs the startup flag-override applier (see the
// reapplier field). Exported for cmd, which owns the parsed flags.
func (cfg *GatewayConfig) SetFlagReapplier(fn func(*GatewayConfig)) { cfg.reapplier = fn }

// reapplyStartupFlags copies the startup CLI-flag overrides recorded on src
// onto dst (a freshly decoded config). Package-private: the reload callback
// owns the only call site, and the applier must come from the STARTUP config —
// a decoded config has no reapplier of its own.
func reapplyStartupFlags(src, dst *GatewayConfig) {
	if src.reapplier != nil {
		src.reapplier(dst)
	}
}

func (cfg *GatewayConfig) ApplyFlagOverrides(flags *GatewayFlags, explicitSet map[string]bool) {
	// Top-level
	if explicitSet["vol-root"] {
		cfg.VolRoot = flags.VolRoot
	}
	if explicitSet["mode"] {
		cfg.Mode = flags.Mode
	}
	if explicitSet["etcd"] {
		cfg.Etcd = flags.Etcd
	}
	if explicitSet["gateway-id"] {
		cfg.GatewayID = flags.GatewayID
	}
	if explicitSet["gateway-url"] {
		cfg.GatewayURL = flags.GatewayURL
	}
	if explicitSet["gateway-stream-addr"] {
		cfg.GatewayStreamAddr = flags.GatewayStreamAddr
	}
	if explicitSet["idle-timeout"] {
		cfg.IdleTimeoutSec = flags.IdleTimeoutSec
	}
	if explicitSet["ops-token-file"] {
		cfg.OpsTokenFile = flags.OpsTokenFile
	}
	if explicitSet["mcp-instructions-file"] {
		cfg.MCP.InstructionsFile = flags.MCPInstructionsFile
	}
	if explicitSet["etcd-ca"] {
		cfg.EtcdCA = flags.EtcdCA
	}
	if explicitSet["etcd-cert"] {
		cfg.EtcdCert = flags.EtcdCert
	}
	if explicitSet["etcd-key"] {
		cfg.EtcdKey = flags.EtcdKey
	}
	if explicitSet["allow-insecure-etcd"] {
		cfg.AllowInsecureEtcd = flags.AllowInsecureEtcd
	}
	// Agent listener
	if explicitSet["agent-addr"] {
		cfg.Agent.Addr = flags.AgentAddr
	}
	if explicitSet["agent-tls-cert"] {
		cfg.Agent.TLSCert = flags.AgentTLSCert
	}
	if explicitSet["agent-tls-key"] {
		cfg.Agent.TLSKey = flags.AgentTLSKey
	}
	if explicitSet["agent-tls-ca"] {
		cfg.Agent.TLSCA = flags.AgentTLSCA
	}
	// Human listener
	if explicitSet["human-addr"] {
		cfg.Human.Addr = flags.HumanAddr
	}
	if explicitSet["human-tls-cert"] {
		cfg.Human.TLSCert = flags.HumanTLSCert
	}
	if explicitSet["human-tls-key"] {
		cfg.Human.TLSKey = flags.HumanTLSKey
	}
	if explicitSet["human-tls-ca"] {
		cfg.Human.TLSCA = flags.HumanTLSCA
	}
	// Stream listener
	if explicitSet["stream-addr"] {
		cfg.Stream.Addr = flags.StreamAddr
	}
	if explicitSet["stream-tls-cert"] {
		cfg.Stream.TLSCert = flags.StreamTLSCert
	}
	if explicitSet["stream-tls-key"] {
		cfg.Stream.TLSKey = flags.StreamTLSKey
	}
	if explicitSet["stream-tls-ca"] {
		cfg.Stream.TLSCA = flags.StreamTLSCA
	}
	// Storage plane
	if explicitSet["storage-op-deadline-sec"] {
		cfg.StorageOpDeadlineSec = flags.StorageOpDeadlineSec
	}
	// NB: the value is validated by ValidateStorageDeadline() — called by cmd at
	// startup and by the reload callback before every swap. It used to PANIC
	// here, outside the explicitSet guard: a YAML edit introducing 0 then
	// crashed the process from inside the file-watcher goroutine, with a stack
	// trace that blamed the CLI flag.
	// Stream concurrency / transport (MB-valued flags convert to bytes)
	if explicitSet["stream-send-buffer"] {
		cfg.StreamConcurrency.SendBufferSize = flags.StreamSendBuffer
	}
	if explicitSet["stream-write-timeout-sec"] {
		cfg.StreamConcurrency.WriteTimeoutSec = flags.StreamWriteTimeout
	}
	if explicitSet["stream-initial-window-mb"] {
		cfg.StreamConcurrency.InitialWindow = flags.StreamInitialWindow << 20
	}
	if explicitSet["stream-conn-window-mb"] {
		cfg.StreamConcurrency.InitialConnWindow = flags.StreamConnWindow << 20
	}
	if explicitSet["stream-max-msg-size-mb"] {
		cfg.StreamConcurrency.MaxMsgSize = flags.StreamMaxMsgSize << 20
	}
	// Lease
	if explicitSet["sticky-ms"] {
		cfg.Lease.StickyMs = flags.StickyMs
	}
	if explicitSet["max-sticky-sec"] {
		cfg.Lease.MaxStickySec = flags.MaxStickySec
	}
	// Exec
	if explicitSet["default-exec-timeout-sec"] {
		cfg.Exec.DefaultTimeoutSec = flags.DefaultExecTimeoutSec
	}
	if explicitSet["max-exec-timeout-sec"] {
		cfg.Exec.MaxTimeoutSec = flags.MaxExecTimeoutSec
	}
	if explicitSet["max-background-lease-sec"] {
		cfg.Exec.MaxBackgroundLeaseSec = flags.MaxBackgroundLeaseSec
	}
	// Unmount stats
	if explicitSet["unmount-stats-persist-sec"] {
		cfg.UnmountStats.PersistIntervalSec = flags.UnmountStatsPersistSec
	}
	// Authn
	if explicitSet["authn-issuer"] {
		cfg.Authn.Issuer = flags.AuthnIssuer
	}
	if explicitSet["authn-client-id"] {
		cfg.Authn.ClientID = flags.AuthnClientID
	}
	if explicitSet["authn-jwks-refresh-sec"] {
		cfg.Authn.JWKSRefreshSec = flags.AuthnJWKSRefreshSec
	}
	if explicitSet["authn-mtls-trust-cert"] {
		cfg.Authn.MTLSTrustCert = flags.AuthnMTLSTrustCert
	}
	if explicitSet["authn-scope-human"] {
		cfg.Authn.ScopeHuman = flags.AuthnScopeHuman
	}
	if explicitSet["authn-scope-admin"] {
		cfg.Authn.ScopeAdmin = flags.AuthnScopeAdmin
	}
	if explicitSet["authn-scope-ops"] {
		cfg.Authn.ScopeOps = flags.AuthnScopeOps
	}
	if explicitSet["allow-anonymous-human"] {
		// Flag over config, like every other flag: an explicit
		// -allow-anonymous-human=false revokes a config-file opt-out, which
		// is itself the explicit record when the flag is absent.
		cfg.Authn.AllowAnonymous = flags.AllowAnonymousHuman
	}
	if explicitSet["allow-anonymous-human-public"] {
		cfg.Authn.AllowAnonymousPublic = flags.AllowAnonymousHumanPublic
	}

	// Identity store loading (etcd)
	if explicitSet["identity-load-page-size"] {
		cfg.IdentityLoad.LoadPageSize = flags.IdentityLoadPageSize
	}
	if explicitSet["identity-load-workers"] {
		cfg.IdentityLoad.LoadWorkers = flags.IdentityLoadWorkers
	}
	if explicitSet["identity-full-load-timeout-sec"] {
		cfg.IdentityLoad.FullLoadTimeoutSec = flags.IdentityFullLoadTimeoutSec
	}
	if explicitSet["identity-lazy-load"] {
		cfg.IdentityLoad.LazyLoad = flags.IdentityLazyLoad
	}
	if explicitSet["identity-hot-only"] {
		cfg.IdentityLoad.HotOnly = flags.IdentityHotOnly
	}

	// Single-node identity store. Persistence is mandatory: an explicit
	// empty value is surfaced via IdentityStoreExplicit for runSingleNodeMode
	// to reject; unset leaves the EffectiveIdentityStorePath() default
	// (<vol_root>/<filename>).
	if explicitSet["identity-store"] {
		cfg.IdentityStore = flags.IdentityStore
		cfg.IdentityStoreExplicit = true
	}

	// Sched policy
	if explicitSet["sched-policy"] {
		cfg.Sched.Policy = flags.SchedPolicy
	}
	if explicitSet["sched-w-load"] {
		cfg.Sched.WLoad = flags.SchedWLoad
	}
	if explicitSet["sched-w-host"] {
		cfg.Sched.WHost = flags.SchedWHost
	}
	if explicitSet["sched-w-clean"] {
		cfg.Sched.WClean = flags.SchedWClean
	}
	if explicitSet["sched-w-daily"] {
		cfg.Sched.WDaily = flags.SchedWDaily
	}
	if explicitSet["sched-w-risk"] {
		cfg.Sched.WRisk = flags.SchedWRisk
	}
	if explicitSet["sched-host-cpu-hard"] {
		cfg.Sched.HostCPUHard = flags.SchedHostCPUHard
	}
	if explicitSet["sched-duty-hard"] {
		cfg.Sched.DutyHard = flags.SchedDutyHard
	}
	if explicitSet["sched-floor-frac"] {
		cfg.Sched.FloorFrac = flags.SchedFloorFrac
	}
	if explicitSet["enable-load-shed"] {
		cfg.Shed.Enabled = flags.ShedEnabled
	}
	if explicitSet["shed-sat-sec"] {
		cfg.Shed.SatSec = flags.ShedSatSec
	}
	if explicitSet["shed-rate-per-sec"] {
		cfg.Shed.RatePerSec = flags.ShedRatePerSec
	}
	if explicitSet["shed-cooldown-sec"] {
		cfg.Shed.CooldownSec = flags.ShedCooldownSec
	}
	if explicitSet["shed-retry-after-sec"] {
		cfg.Shed.RetryAfterSec = flags.ShedRetryAfterSec
	}
	// Staleness thresholds
	if explicitSet["route-stale-sec"] {
		cfg.Staleness.RouteStaleSec = flags.StalenessRouteStaleSec
	}
	if explicitSet["claim-dead-guard-sec"] {
		cfg.Staleness.ClaimDeadGuardSec = flags.StalenessClaimDeadGuardSec
	}
	if explicitSet["alert-stale-sec"] {
		cfg.Staleness.AlertStaleSec = flags.StalenessAlertStaleSec
	}
	if explicitSet["etcd-fence-sec"] {
		cfg.Staleness.EtcdFenceSec = flags.StalenessEtcdFenceSec
	}
	if explicitSet["alert-scan-interval-sec"] {
		cfg.Staleness.AlertScanIntervalSec = flags.StalenessAlertScanIntervalSec
	}
	if explicitSet["ownership-cache-ttl-sec"] {
		cfg.Ownership.CacheTTLSec = flags.OwnershipCacheTTLSec
	}
}

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

package config

import (
	"log/slog"
	"time"

	"common/config"

	"gateway/lease"
	"gateway/pool"

	"bytes"
	"gopkg.in/yaml.v3"
)

// HotReloadTargets holds the live managers that can be updated at runtime.
// Passed to ApplyHotReload so it can push new config values without
// requiring a process restart.
type HotReloadTargets struct {
	LeaseMgr *lease.Lease
	PoolMgr  *pool.Manager
	// UpdateExecTimeouts atomically updates the exec timeout values in the
	// ExecuteHandler. We use a function interface to avoid importing the
	// handler package (which would create a circular dep: handler→config→handler).
	UpdateExecTimeouts func(defaultSec, maxSec int)
	// UpdateMaxBackgroundLeaseSec atomically updates the bg lease_duration cap.
	// Function interface for the same circular-dep reason as UpdateExecTimeouts.
	UpdateMaxBackgroundLeaseSec func(sec int)
	// UpdateShedConfig atomically updates the load-shed parameters.
	// Function interface to avoid importing lease (circular: lease does not
	// import config, but keeping the pattern uniform with UpdateExecTimeouts).
	UpdateShedConfig func(enabled bool, satSec, ratePerSec, cooldownSec, retryAfterSec int)
	// UpdateSelfLoad atomically updates the self-pressure gate thresholds on
	// the SelfPressureMonitor. Function interface, same pattern as above.
	UpdateSelfLoad func(cpuHard, memHard float64, satSec int)
	// UpdateUnmountStatsInterval atomically updates the unmount-stats persist
	// interval (seconds). Function interface to avoid importing the stats package
	// (circular: stats→pool, config is a leaf).
	UpdateUnmountStatsInterval func(sec int)
	// UpdateStalenessThresholds atomically updates the health-staleness
	// thresholds (route-stale, claim-dead-guard, alert-stale; seconds) on the
	// ownership cache. Function interface to keep the pattern uniform (config
	// must not import lease's OwnershipCache runtime setters).
	UpdateStalenessThresholds func(routeSec, guardSec, alertSec int)
	// UpdateFenceSec atomically updates the etcd-partition self-fence
	// threshold (seconds). The ownership cache re-validates the
	// T_safe > fence + warden + heartbeat invariant against every connected
	// node and refuses a violating value (the reload keeps the old threshold).
	// Function interface for the same import-isolation reason.
	UpdateFenceSec func(sec int)
	// UpdateOwnershipCacheTTL atomically updates the Claim fast-path freshness
	// window (seconds) — the etcd revalidation cadence. The ownership cache
	// re-validates the TTL ≤ min(2×claim-dead-guard, 300) safety ceiling and
	// refuses a violating value (the reload keeps the old TTL). Function
	// interface for the same import-isolation reason.
	UpdateOwnershipCacheTTL func(sec int)
	// UpdateStalenessAndCacheTTL applies the staleness thresholds AND the
	// Claim fast-path TTL as one validated pair (seconds). A reload commit
	// that changes staleness.claim_dead_guard_sec and ownership.cache_ttl_sec
	// together must be applied jointly: sequential per-key setters reject
	// config-valid pairs by validating each leg against the other's old value.
	// Nil falls back to the sequential UpdateStalenessThresholds /
	// UpdateOwnershipCacheTTL closures (minimal test wiring).
	UpdateStalenessAndCacheTTL func(routeSec, guardSec, alertSec, ttlSec int)
	// UpdateAlertScanInterval atomically updates the staleness-alert-scan
	// cadence (seconds); the scan loop re-derives its timer on the next tick.
	// Refuses values < 10s. Function interface for the same import-isolation
	// reason.
	UpdateAlertScanInterval func(sec int)
}

// ApplyHotReload applies hot-reloadable config changes to live managers.
// Restart-required changes are logged as warnings but NOT applied.
func ApplyHotReload(old, new GatewayConfig, targets *HotReloadTargets, logger *slog.Logger) {
	cs := old.Diff(new)
	if cs.Empty() {
		return
	}

	// Log all changes.
	for _, fc := range cs.HotReload {
		logger.Info("config hot-reload",
			"field", fc.Name, "old", fc.Old, "new", fc.New)
	}
	for _, fc := range cs.RestartReq {
		logger.Warn("config change requires restart",
			"field", fc.Name, "old", fc.Old, "new", fc.New)
	}

	// Apply hot-reloadable changes.
	// Guard against a nil targets: the per-field nil checks below
	// (targets.LeaseMgr != nil, etc.) dereference targets, so a nil top-level
	// pointer would panic on the first hot-reloadable change. Logging above
	// still happens so operators see the would-be change.
	if targets == nil {
		return
	}
	for _, fc := range cs.HotReload {
		switch fc.Name {
		case "lease.sticky_ms":
			// Refuse out-of-range values (keep the old effective window) —
			// same refusal pattern as UpdateFenceSec. < 1 breaks the
			// window-refresh mechanism (see ValidateLease).
			if new.Lease.StickyMs < 1 {
				logger.Warn("config hot-reload refused: lease.sticky_ms must be >= 1; keeping previous value",
					"value", new.Lease.StickyMs)
			} else if targets.LeaseMgr != nil {
				targets.LeaseMgr.UpdateTimeout(time.Duration(new.Lease.StickyMs) * time.Millisecond)
			}
		case "lease.max_sticky_sec":
			// Refuse < 1 (would silently disable the maxHold reaper) — keep old.
			if new.Lease.MaxStickySec < 1 {
				logger.Warn("config hot-reload refused: lease.max_sticky_sec must be >= 1; keeping previous value",
					"value", new.Lease.MaxStickySec)
			} else if targets.LeaseMgr != nil {
				targets.LeaseMgr.UpdateMaxHold(time.Duration(new.Lease.MaxStickySec) * time.Second)
			}
		case "exec.default_timeout_sec", "exec.max_timeout_sec":
			// Same bounds as the startup guard (ValidateExec): refuse and keep
			// the previous timeouts rather than letting the handler silently
			// normalize max<default into a config the operator did not write.
			if new.Exec.DefaultTimeoutSec < 1 || new.Exec.MaxTimeoutSec < 1 || new.Exec.MaxTimeoutSec < new.Exec.DefaultTimeoutSec {
				logger.Warn("config hot-reload refused: exec timeouts must be >= 1 with max >= default; keeping previous values",
					"defaultSec", new.Exec.DefaultTimeoutSec, "maxSec", new.Exec.MaxTimeoutSec)
			} else {
				if new.Exec.MaxTimeoutSec > old.Exec.MaxTimeoutSec {
					// The agent listener's WriteTimeout is derived from the
					// STARTUP max (+30 s) and is not rebuilt on reload: an exec
					// admitted under the new, larger cap can outlive that
					// deadline, and its response write then fails AFTER the work
					// completed. Name it instead of letting the operator
					// discover it as a truncated response.
					logger.Warn("exec.max_timeout_sec raised past the listener's startup write deadline (+30s) — restart the gateway for the new cap to be fully effective",
						"old_max_sec", old.Exec.MaxTimeoutSec, "new_max_sec", new.Exec.MaxTimeoutSec)
				}
				if targets.UpdateExecTimeouts != nil {
					targets.UpdateExecTimeouts(new.Exec.DefaultTimeoutSec, new.Exec.MaxTimeoutSec)
				}
			}
		case "exec.max_background_lease_sec":
			if targets.UpdateMaxBackgroundLeaseSec != nil {
				targets.UpdateMaxBackgroundLeaseSec(new.Exec.MaxBackgroundLeaseSec)
			}
		case "unmount_stats.persist_interval_sec":
			if targets.UpdateUnmountStatsInterval != nil {
				targets.UpdateUnmountStatsInterval(new.UnmountStats.PersistIntervalSec)
			}
		case "staleness.route_stale_sec", "staleness.claim_dead_guard_sec",
			"staleness.alert_stale_sec":
			// Same bounds/ordering as the startup guard (ValidateStaleness):
			// refuse and keep the previous thresholds. Applied JOINTLY with the
			// ownership cache TTL when the joint target is wired, so a commit
			// changing guard+TTL together is one validated pair (the sequential
			// fallback validates the guard against the live TTL).
			if err := ValidateStalenessValues(new.Staleness.RouteStaleSec, new.Staleness.ClaimDeadGuardSec, new.Staleness.AlertStaleSec); err != nil {
				logger.Warn("config hot-reload refused: invalid staleness thresholds; keeping previous values", "error", err)
			} else if targets.UpdateStalenessAndCacheTTL != nil {
				if err := (&GatewayConfig{
					Ownership: new.Ownership,
					Staleness: StalenessConfig{ClaimDeadGuardSec: new.Staleness.ClaimDeadGuardSec},
				}).ValidateOwnership(); err != nil {
					logger.Warn("config hot-reload refused: guard/TTL pair invalid; keeping previous values", "error", err)
				} else {
					targets.UpdateStalenessAndCacheTTL(
						new.Staleness.RouteStaleSec,
						new.Staleness.ClaimDeadGuardSec,
						new.Staleness.AlertStaleSec,
						new.Ownership.CacheTTLSec,
					)
				}
			} else if targets.UpdateStalenessThresholds != nil {
				targets.UpdateStalenessThresholds(
					new.Staleness.RouteStaleSec,
					new.Staleness.ClaimDeadGuardSec,
					new.Staleness.AlertStaleSec,
				)
			}
		case "staleness.etcd_fence_sec":
			if targets.UpdateFenceSec != nil {
				targets.UpdateFenceSec(new.Staleness.EtcdFenceSec)
			}
		case "staleness.alert_scan_interval_sec":
			// Same bounds as the startup guard: refuse < 10s and keep the old
			// cadence (the scan is a full ownership sweep on the human gateway).
			if new.Staleness.AlertScanIntervalSec < 10 {
				logger.Warn("config hot-reload refused: staleness.alert_scan_interval_sec must be >= 10; keeping previous value",
					"value", new.Staleness.AlertScanIntervalSec)
			} else if targets.UpdateAlertScanInterval != nil {
				targets.UpdateAlertScanInterval(new.Staleness.AlertScanIntervalSec)
			}
		case "ownership.cache_ttl_sec":
			// Same pair bound as the startup guard (ValidateOwnership): the
			// stale-serve window must stay under the earliest-takeover ceiling
			// min(2×guard, 300). Applied JOINTLY with the staleness thresholds
			// when the joint target is wired (a commit changing both keys lands
			// on one consistent pair); the sequential fallback re-checks against
			// the live guard.
			if err := (&GatewayConfig{
				Ownership: new.Ownership,
				Staleness: StalenessConfig{ClaimDeadGuardSec: new.Staleness.ClaimDeadGuardSec},
			}).ValidateOwnership(); err != nil {
				logger.Warn("config hot-reload refused: invalid ownership.cache_ttl_sec; keeping previous value", "error", err)
			} else if targets.UpdateStalenessAndCacheTTL != nil {
				targets.UpdateStalenessAndCacheTTL(
					new.Staleness.RouteStaleSec,
					new.Staleness.ClaimDeadGuardSec,
					new.Staleness.AlertStaleSec,
					new.Ownership.CacheTTLSec,
				)
			} else if targets.UpdateOwnershipCacheTTL != nil {
				targets.UpdateOwnershipCacheTTL(new.Ownership.CacheTTLSec)
			}
		case "sched.policy", "sched.w_load", "sched.w_host", "sched.w_clean",
			"sched.w_daily", "sched.w_risk", "sched.host_cpu_hard", "sched.duty_hard",
			"sched.floor_frac":
			if targets.PoolMgr != nil {
				targets.PoolMgr.SetSchedPolicy(SchedPolicyFromConfig(new.Sched))
			}
		case "shed.enabled", "shed.sat_sec", "shed.rate_per_sec",
			"shed.cooldown_sec", "shed.retry_after_sec":
			// Same bounds as the startup guard (ValidateShed): refuse and keep
			// the previous shed config (cooldown < 0 would let the next DNS
			// resolution instantly undo a shed; retry_after < 1 is silently
			// replaced by a hardcoded default downstream).
			if new.Shed.CooldownSec < 0 || new.Shed.RetryAfterSec < 1 {
				logger.Warn("config hot-reload refused: shed.cooldown_sec must be >= 0 and retry_after_sec >= 1; keeping previous values",
					"cooldownSec", new.Shed.CooldownSec, "retryAfterSec", new.Shed.RetryAfterSec)
			} else if targets.UpdateShedConfig != nil {
				targets.UpdateShedConfig(
					new.Shed.Enabled,
					new.Shed.SatSec,
					new.Shed.RatePerSec,
					new.Shed.CooldownSec,
					new.Shed.RetryAfterSec,
				)
			}
		case "selfload.cpu_hard", "selfload.mem_hard", "selfload.sat_sec":
			if targets.UpdateSelfLoad != nil {
				targets.UpdateSelfLoad(
					new.SelfLoad.CpuHard,
					new.SelfLoad.MemHard,
					new.SelfLoad.SatSec,
				)
			}
		}
	}

	logger.Info("config reload applied",
		"hotReload", len(cs.HotReload),
		"restartRequired", len(cs.RestartReq))
}

// NewReloadCallback returns a function suitable for use as a ReloadWatcher
// onChange callback. It parses the YAML content, diffs against the current
// config, and applies hot-reloadable changes.
func NewReloadCallback(current *config.WatchableConfig[GatewayConfig], targets *HotReloadTargets, logger *slog.Logger) func([]byte) {
	return func(content []byte) {
		newCfg := Defaults()
		dec := yaml.NewDecoder(bytes.NewReader(content))
		dec.KnownFields(true) // strict: refuse an edit introducing an unknown key (keep serving the old config)
		if err := dec.Decode(&newCfg); err != nil {
			logger.Error("config reload: failed to parse YAML (strict: unknown keys are errors)", "error", err)
			return
		}
		// Re-apply the STARTUP CLI-flag overrides before diffing: the file
		// supplies values, flags keep precedence (the documented contract).
		// Without this the first edit reverted every flag-provided value.
		// The applier is recorded on the CURRENT (startup) config — a freshly
		// decoded config carries none.
		prev := current.Get()
		reapplyStartupFlags(&prev, &newCfg)
		// Validate at ingestion, BEFORE the Swap: an invalid edit is refused
		// whole and the watchable config keeps the last good value.
		if err := newCfg.ValidateStorageDeadline(); err != nil {
			logger.Error("config reload: invalid values; keeping previous config", "error", err)
			return
		}
		if err := newCfg.ValidateSchedPolicy(); err != nil {
			logger.Error("config reload: invalid values; keeping previous config", "error", err)
			return
		}
		if err := newCfg.ValidateSelfLoad(); err != nil {
			logger.Error("config reload: invalid values; keeping previous config", "error", err)
			return
		}
		oldCfg := current.Swap(newCfg)
		ApplyHotReload(oldCfg, newCfg, targets, logger)
	}
}

// SchedPolicyFromConfig converts a SchedConfig into the pool's SchedPolicy,
// using the built-in binpack defaults for unset weights (0 = default).
// SchedPolicyFromConfig maps the configured policy name to the pool's policy.
// An unknown name is a CONFIG ERROR (the DNS validates its twin strictly):
// silently treating a typo as binpack is the opposite of "spread" intent.
func SchedPolicyFromConfig(c SchedConfig) pool.SchedPolicy {
	p := pool.DefaultSchedPolicy()
	if c.Policy == "spread" {
		p.Binpack = false
	}
	if c.WLoad != 0 {
		p.WLoad = c.WLoad
	}
	if c.WHost != 0 {
		p.WHost = c.WHost
	}
	if c.WClean != 0 {
		p.WClean = c.WClean
	}
	if c.WDaily != 0 {
		p.WDaily = c.WDaily
	}
	if c.WRisk != 0 {
		p.WRisk = c.WRisk
	}
	p.HostCPUHard = c.HostCPUHard
	p.DutyHard = c.DutyHard
	// FloorFrac 0 = default (0.2, floor enabled); negative disables.
	if c.FloorFrac < 0 {
		p.FloorFrac = 0
	} else if c.FloorFrac != 0 {
		p.FloorFrac = c.FloorFrac
	}
	return p
}

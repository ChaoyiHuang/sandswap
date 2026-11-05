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
	"path/filepath"

	"common/config"

	"bytes"
	"gopkg.in/yaml.v3"
)

// HotReloadTargets holds the live components that can be updated at runtime.
type HotReloadTargets struct {
	// UpdateVMMConfig updates the VMM config (kernel, initramfs, vcpus, memory).
	// Affects new VMs only. Nil = not available.
	UpdateVMMConfig func(cfg MicroVMConfig)
	// UpdateRecycleConfig updates the recycle parameters.
	UpdateRecycleConfig func(cfg RecycleConfig)
	// ReconcileSeeds is called when a seed key changed in the config file. It
	// is a TRIGGER, not a values carrier: the implementation (the seed
	// coordinator) re-resolves the generations from the live snapshot, applies
	// the transition through the namer's table (which alone decides what is
	// legal) and records the outcome — so the config watcher, the seed-source
	// watchers and the poll all share ONE resolution path. Nil = no prov role.
	ReconcileSeeds func() error
	// UpdatePoolTarget adjusts the pool target based on the new pool spec string
	// AND the reloaded specs map. The specs map is passed explicitly so
	// the callback uses the post-reload specs, not the stale startup-time cfg.Specs.
	// Even though `specs:` itself is restart-required, the field in the reloaded
	// config reflects the latest value, so pool parsing always uses current specs.
	UpdatePoolTarget func(poolSpec string, specs map[string]SpecEntry)
}

// secretsByField lists config fields whose VALUES must never reach the logs.
// The diff carries formatted old/new values, so a redaction at the log site
// is the only thing standing between an edited password and the journal.
var secretsByField = map[string]bool{
	"provision.registry_password": true,
	"provision.registry_token":    true,
	// The volume-name seed: a diff line carrying it would put the only secret
	// the unguessable directory names rest on into the journal.
	"provision.volume_seed":      true,
	"provision.volume_seed_next": true,
}

// redactValue replaces a secret field's value for logging; non-secret fields
// pass through unchanged.
func redactValue(field, value string) string {
	if secretsByField[field] {
		return "(redacted)"
	}
	return value
}

// ApplyHotReload applies hot-reloadable config changes to live components.
func ApplyHotReload(old, new SandlotConfig, targets *HotReloadTargets, logger *slog.Logger) {
	cs := old.Diff(new)
	if cs.Empty() {
		return
	}

	// Log all changes (secret values redacted).
	for _, fc := range cs.HotReload {
		logger.Info("config hot-reload",
			"field", fc.Name, "old", redactValue(fc.Name, fc.Old), "new", redactValue(fc.Name, fc.New))
	}
	for _, fc := range cs.RestartReq {
		logger.Warn("config change requires restart",
			"field", fc.Name, "old", redactValue(fc.Name, fc.Old), "new", redactValue(fc.Name, fc.New))
	}

	// Apply hot-reloadable changes.
	for _, fc := range cs.HotReload {
		switch fc.Name {
		case "microvm.kernel", "microvm.initramfs",
			"microvm.default_vcpus", "microvm.default_memory_mb":
			if targets.UpdateVMMConfig != nil {
				targets.UpdateVMMConfig(new.MicroVM)
			}
		case "pool":
			if targets.UpdatePoolTarget != nil {
				targets.UpdatePoolTarget(new.Pool, new.Specs)
			}
		case "recycle.max_uses", "recycle.max_mounts", "recycle.max_distinct_agents",
			"recycle.affinity_vms", "recycle.mem_percent", "recycle.mem_abs_mb",
			"recycle.min_idle_floor_frac":
			if targets.UpdateRecycleConfig != nil {
				targets.UpdateRecycleConfig(new.Recycle)
			}
		case "provision.volume_seed", "provision.volume_seed_file",
			"provision.volume_seed_next", "provision.volume_seed_next_file":
			if targets.ReconcileSeeds != nil {
				if err := targets.ReconcileSeeds(); err != nil {
					// The coordinator already logged the classified reason (a
					// tamper refusal, an incomplete rename at promote time, a
					// source not materialized yet). A refusal leaves the live
					// generations untouched — the property the whole rotation
					// design rests on — so this line is the reload-scoped
					// record, not a second diagnosis.
					logger.Error("config reload: volume seed change not applied (live namer unchanged)", "error", err)
				}
			}
		}
	}

	logger.Info("config reload applied",
		"hotReload", len(cs.HotReload),
		"restartRequired", len(cs.RestartReq))
}

// NewReloadCallback returns a function suitable for use as a ReloadWatcher
// onChange callback.
func NewReloadCallback(current *config.WatchableConfig[SandlotConfig], targets *HotReloadTargets, logger *slog.Logger) func([]byte) {
	return func(content []byte) {
		newCfg := Defaults()
		dec := yaml.NewDecoder(bytes.NewReader(content))
		dec.KnownFields(true) // strict: refuse an edit introducing an unknown key (keep serving the old config)
		if err := dec.Decode(&newCfg); err != nil {
			logger.Error("config reload: failed to parse YAML (strict: unknown keys are errors)", "error", err)
			return
		}
		// ConfigFilePath is a yaml:"-" field, so a fresh decode loses it — yet
		// the reloaded config is the SAME file, and the seed path resolution
		// below (and every later reload) needs its directory.
		prev := current.Get()
		newCfg.ConfigFilePath = prev.ConfigFilePath
		// Seed file paths resolve against the CONFIG's directory, exactly as at
		// load time (see ResolveSeedFilePaths) — done BEFORE the flag re-apply
		// so a flag-provided path keeps resolving against the CWD, the
		// operator's own context, rather than being rewritten to the config's.
		newCfg.ResolveSeedFilePaths(filepath.Dir(prev.ConfigFilePath))
		// Re-apply the STARTUP CLI-flag overrides before validating/diffing: the
		// file supplies values, flags keep precedence (the documented contract).
		// Without this the first edit reverted every flag-provided value — a
		// `-pool small:2` run lost its pool spec, which then wiped the node's
		// pool maintenance via ResizePool(nil) until restart.
		if err := ReapplyStartupFlags(&prev, &newCfg); err != nil {
			logger.Error("config reload: flag overrides not representable; keeping previous config", "error", err)
			return
		}
		// Value validation at ingestion, BEFORE the Swap: an invalid edit is
		// rejected whole (same rule as startup) and the watchable config keeps
		// the last good value, so subsequent diffs stay correct.
		if err := newCfg.Validate(); err != nil {
			logger.Error("config reload: invalid values; keeping previous config", "error", err)
			return
		}
		oldCfg := current.Swap(newCfg)
		ApplyHotReload(oldCfg, newCfg, targets, logger)
	}
}

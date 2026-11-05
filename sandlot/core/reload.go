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
	"fmt"
	"log"
	"log/slog"
	"os"

	"common/config"
	sandlotconfig "sandlot/config"
)

// StartConfigReload starts the hot-reload file watcher if a config path is set.
//
// liveConfig is the snapshot the CALLER owns: the callback swaps it, and every
// reload-aware consumer (the seed coordinator) resolves from the same instance,
// so no consumer ever reads a generation out of a half-applied edit.
//
// reconcileSeeds (optional, prov role only) is a TRIGGER, not a values
// carrier: the seed coordinator re-resolves the generations from the live
// snapshot (with the reader-side integrity check), applies the transition
// through the namer's table and records the outcome. A reload that only
// touched something else never reaches it.
func StartConfigReload(cfg *sandlotconfig.SandlotConfig, liveConfig *config.WatchableConfig[sandlotconfig.SandlotConfig],
	handler *Handler, logger *log.Logger, reconcileSeeds func() error) *config.ReloadWatcher {
	if cfg.ConfigFilePath == "" {
		return nil
	}

	slogLogger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	rw, err := config.NewReloadWatcher(cfg.ConfigFilePath, sandlotconfig.NewReloadCallback(liveConfig, &sandlotconfig.HotReloadTargets{
		UpdateVMMConfig: func(microCfg sandlotconfig.MicroVMConfig) {
			// Partial application from the LIVE config: only the four
			// hot-reloadable microvm fields ever change here. Restart-required
			// fields (volumes_dir, overlayfs_templates, the warden cmdline
			// params) keep their startup values — rebuilding the whole
			// vmm.Config from the reloaded file would silently apply them too
			// (and used to silently DROP the warden cmdline fields, since the
			// zero-value rebuild lost them). WardenCountdownSec stays at the
			// startup value (0 below = "keep current" via the handler's
			// zero-value guard): resilience timings are restart-required, and
			// the warden log level is deliberately not hot-reloadable — an
			// online flip to debug would tax the serial UART on the measured
			// path across every new VM at fleet scale; the restart is the
			// safety gate.
			next := handler.CurrentVMMConfig()
			next.KernelPath = microCfg.Kernel
			next.InitramfsPath = microCfg.Initramfs
			next.VCPUs = microCfg.DefaultVCPUs
			next.MemoryMB = microCfg.DefaultMemoryMB
			next.WardenCountdownSec = 0 // keep the startup countdown
			handler.UpdateVMMConfig(next)
			slogLogger.Info("vmm config hot-reloaded (affects new VMs only)",
				"kernel", microCfg.Kernel, "initramfs", microCfg.Initramfs,
				"vcpus", microCfg.DefaultVCPUs, "memoryMB", microCfg.DefaultMemoryMB)
		},
		UpdateRecycleConfig: func(rc sandlotconfig.RecycleConfig) {
			handler.UpdateRecycleConfig(rc.MaxUses, rc.MemPercent, rc.MemAbsMB, rc.MinIdleFloorFrac)
			handler.UpdateReusePolicy(rc.MaxMounts, rc.MaxDistinctAgents, rc.AffinityVMs)
			slogLogger.Info("recycle config hot-reloaded", "maxUses", rc.MaxUses,
				"memPercent", rc.MemPercent, "memAbsMB", rc.MemAbsMB,
				"minIdleFloorFrac", rc.MinIdleFloorFrac)
		},
		ReconcileSeeds: func() error {
			if reconcileSeeds == nil {
				return fmt.Errorf("this instance has no provision role (volume seed ignored)")
			}
			return reconcileSeeds()
		},
		UpdatePoolTarget: func(poolSpec string, specs map[string]sandlotconfig.SpecEntry) {
			if poolSpec == "" {
				slogLogger.Info("pool spec cleared (no pool management)")
				handler.ResizePool(nil, nil)
				return
			}
			// Use the RELOADED specs map (passed in), not the stale
			// startup-time cfg.Specs, so specs+pool joint changes parse correctly.
			poolMap, err := ParsePoolSpec(poolSpec, specs)
			if err != nil {
				slogLogger.Error("invalid pool spec in hot-reload", "pool", poolSpec, "error", err)
				return
			}
			// Hard-reject overcommit configs at hot-reload too. Keep the
			// old pool target (do NOT call ResizePool) so a bad edit doesn't
			// drive the node into OOM. Floor note: the handler's floor here is
			// the last-applied one — if the same reload also changes
			// recycle.min_idle_floor_frac, the recycle callback applies it
			// after this check (field order), so the next reload re-validates
			// with the new floor. The one-cycle lag is bounded by one floor
			// VM's memory.
			if err := ValidatePoolMemory(handler, poolMap, readSystemMemMB()); err != nil {
				slogLogger.Error("pool memory overcommit in hot-reload; keeping previous pool target",
					"pool", poolSpec, "error", err)
				return
			}
			newSpecs := make(map[string]int, len(poolMap))
			specRes := make(map[string]SpecResources, len(poolMap))
			for name, entry := range poolMap {
				newSpecs[name] = entry.count
				specRes[name] = SpecResources{
					VCPUs:     entry.vcpus,
					MemoryMB:  entry.memMB,
					ExecSlots: entry.execSlots,
				}
			}
			slogLogger.Info("pool spec hot-reload: resizing pool", "pool", poolSpec)
			handler.ResizePool(newSpecs, specRes)
		},
	}, slogLogger))
	if err != nil {
		slogLogger.Warn("failed to start config reload watcher", "path", cfg.ConfigFilePath, "error", err)
		return nil
	}
	slogLogger.Info("config hot-reload watcher started", "path", cfg.ConfigFilePath)
	return rw
}

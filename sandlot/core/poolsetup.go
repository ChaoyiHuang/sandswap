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
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	sandlotconfig "sandlot/config"
	"sandlot/vmm"
)

// PoolEntry maps a spec name to VM resource parameters and count.
type PoolEntry struct {
	vcpus     uint32
	memMB     uint64
	execSlots int
	count     int
}

// ParsePoolSpec parses a pool specification string like "small:2,medium:3,large:1".
// Uses the configured specs map to look up resource parameters.
func ParsePoolSpec(spec string, specs map[string]sandlotconfig.SpecEntry) (map[string]PoolEntry, error) {
	result := make(map[string]PoolEntry)
	parts := strings.Split(spec, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		kv := strings.SplitN(part, ":", 2)
		if len(kv) != 2 {
			return nil, fmt.Errorf("invalid spec %q (expected spec:count)", part)
		}
		name := strings.TrimSpace(kv[0])
		countStr := strings.TrimSpace(kv[1])
		n, err := strconv.Atoi(countStr)
		if err != nil {
			return nil, fmt.Errorf("invalid count %q in spec %q: %w", countStr, part, err)
		}
		if n < 0 {
			return nil, fmt.Errorf("negative count %d in spec %q", n, part)
		}
		specEntry, ok := specs[name]
		if !ok {
			available := make([]string, 0, len(specs))
			for k := range specs {
				available = append(available, k)
			}
			return nil, fmt.Errorf("unknown spec %q (available: %s)", name, strings.Join(available, ", "))
		}
		// Reject specs that cannot boot: zero vCPUs fails inside KVM with a
		// confusing per-VM error; memory below the boot floor cannot run the
		// kernel + warden at all.
		if specEntry.VCPUs < 1 {
			return nil, fmt.Errorf("spec %q vcpus must be >= 1, got %d", name, specEntry.VCPUs)
		}
		if specEntry.MemoryMB < sandlotconfig.MinBootMemoryMB {
			return nil, fmt.Errorf("spec %q memory_mb %d below minimum %d", name, specEntry.MemoryMB, sandlotconfig.MinBootMemoryMB)
		}
		result[name] = PoolEntry{
			vcpus:     specEntry.VCPUs,
			memMB:     specEntry.MemoryMB,
			execSlots: specEntry.ExecSlots,
			count:     n,
		}
	}
	return result, nil
}

// memSafetyFactor is the fraction of host MemTotal that the pool is allowed to
// reserve. 80% leaves headroom for the host OS + sandlot + other processes.
const memSafetyFactor = 80

// ValidatePoolMemory checks that the total pool memory (sum of count*memMB per
// spec) fits within the host's MemTotal * safetyFactor. Returns an error if the
// pool would overcommit the host. This is the config-time hard reject;
// createPoolVM additionally checks MemAvailable at runtime for drift.
// ValidatePoolMemory rejects pool configs whose total memory exceeds the host
// budget. The count per spec is the EFFECTIVE target (target + min-idle
// floor, via handler.EffectivePoolTarget) — that is what ResizePool and
// ReconcilePool actually create and keep, so a raw-target check would let the
// real pool silently exceed the budget by the floor extras.
func ValidatePoolMemory(handler *Handler, poolMap map[string]PoolEntry, hostMemMB uint64) error {
	var total uint64
	for _, e := range poolMap {
		total += uint64(handler.EffectivePoolTarget(e.count)) * e.memMB
	}
	limit := hostMemMB * memSafetyFactor / 100
	if total > limit {
		return fmt.Errorf("pool memory %dMB (incl. min-idle floor) exceeds host limit %dMB (%d%% of %dMB MemTotal); reduce pool counts or spec memory",
			total, limit, memSafetyFactor, hostMemMB)
	}
	return nil
}

// SetupPool parses the configured pool spec, hard-rejects memory overcommit,
// registers the initial pool specs (so ResizePool hot-reloads can diff
// correctly), pre-creates the shortfall after re-adopt, and runs the pool
// through the resize path so the live pool matches the target in BOTH
// directions. Returns the pool target (total VM count).
func SetupPool(handler *Handler, cfg sandlotconfig.SandlotConfig, defaultCfg vmm.Config, logger *log.Logger) (uint32, error) {
	if cfg.Pool == "" {
		return 0, nil
	}
	poolMap, err := ParsePoolSpec(cfg.Pool, cfg.Specs)
	if err != nil {
		return 0, fmt.Errorf("invalid pool spec %q: %w", cfg.Pool, err)
	}
	// Hard-reject pool configs whose total memory exceeds the host's
	// safe budget (floor extras included — they are really created).
	if err := ValidatePoolMemory(handler, poolMap, readSystemMemMB()); err != nil {
		return 0, fmt.Errorf("pool memory overcommit: %w", err)
	}
	var poolTarget uint32
	for _, entry := range poolMap {
		poolTarget += uint32(entry.count)
	}
	// Set initial pool specs so ResizePool (hot-reload) can diff correctly.
	initialSpecs := make(map[string]int, len(poolMap))
	initialSpecRes := make(map[string]SpecResources, len(poolMap))
	for name, entry := range poolMap {
		initialSpecs[name] = entry.count
		initialSpecRes[name] = SpecResources{
			VCPUs:     entry.vcpus,
			MemoryMB:  entry.memMB,
			ExecSlots: entry.execSlots,
		}
	}
	handler.SetPoolSpecs(initialSpecs, initialSpecRes)
	PreCreateVMs(handler, poolMap, defaultCfg, logger)
	// Advance nextPoolSeq past all pre-created VMs so subsequent
	// ResizePool calls never generate colliding VM IDs.
	handler.AdvancePoolSeq()
	// preCreateVMs only tops the pool UP (it skips a spec whose re-adopted
	// count already meets the target). Restarting with a SMALLER pool target
	// would therefore leave the excess survivors running forever: they hold
	// their memory, and the orphan sweep never reclaims them because their
	// state.json is valid. Run the pool through the normal resize path so the
	// live pool actually matches the configured target in both directions —
	// scale-up is a no-op here (preCreateVMs just did it), scale-down
	// destroys the excess idle VMs (busy ones are marked pendingDestroy and
	// go on their next unmount).
	handler.ResizePool(initialSpecs, initialSpecRes)
	return poolTarget, nil
}

// PreCreateVMs creates VMs for each spec in the pool map, topping up after re-adopt.
func PreCreateVMs(handler *Handler, poolMap map[string]PoolEntry, defaultCfg vmm.Config, logger *log.Logger) {
	reAdoptedPerSpec := make(map[string]int)
	for _, info := range handler.VMInfoList() {
		if info.SpecId != "" {
			reAdoptedPerSpec[info.SpecId]++
		}
	}

	totalCreate := 0
	for specName, entry := range poolMap {
		if entry.count == 0 {
			continue
		}
		reAdopted := reAdoptedPerSpec[specName]
		shortfall := entry.count - reAdopted
		if shortfall <= 0 {
			logger.Printf("spec %s: %d re-adopted >= %d target; skipping", specName, reAdopted, entry.count)
			continue
		}
		logger.Printf("pre-creating %d VM(s) for spec %s (vcpus=%d, mem=%dMB, concurrency=%d)",
			shortfall, specName, entry.vcpus, entry.memMB, handler.createConcurrency())
		created, fatal := handler.runCreateBatch(shortfall, func() (bool, error) {
			// IDs come from the shared nextPoolSeq counter (already advanced
			// past every re-adopted survivor's seq at re-adopt): deriving them
			// from the survivor count collides with a live survivor whenever
			// the survivor seq set has gaps (recycle/scale-down holes).
			vmID := handler.NextPoolVMID(specName)
			cfg := defaultCfg
			cfg.ID = vmID
			cfg.SandboxDir = filepath.Join(handler.SandboxRoot, vmID)
			cfg.VCPUs = entry.vcpus
			cfg.MemoryMB = entry.memMB

			logger.Printf("pre-creating VM %s (spec=%s, vcpus=%d, mem=%dMB)",
				vmID, specName, entry.vcpus, entry.memMB)

			// CreateVerifiedVM owns admission (memory first — a shortage here
			// creates nothing and is logged as such), CID/network/launch, the
			// synchronous warden check, and full teardown of a VM that does not
			// come up. A startup host that cannot afford the pool simply ends
			// with a smaller pool; the 60s reconcile refills when memory
			// frees up. No retry loop against a failing launch.
			_, err := handler.CreateVerifiedVM(context.Background(), cfg, specName)
			if err != nil && !isFatalCreateError(err) {
				logger.Printf("pre-create VM %s failed: %v (continuing)", vmID, err)
			}
			return err == nil, err
		}, isFatalCreateError)
		totalCreate += created
		if fatal != nil {
			if errors.Is(fatal, ErrInsufficientMemory) {
				logger.Printf("pre-create stopped for spec %s: %v (this spec cannot grow on this host right now)", specName, fatal)
			} else {
				// Node-level: every VM from this initramfs speaks an
				// incompatible warden protocol. Stop pre-creating (the
				// 60s reconcile aborts the same way); redeploy sandlot +
				// kernel/initramfs together.
				logger.Printf("pre-create stopped for spec %s: %v (stopping pre-creation until sandlot + kernel/initramfs are redeployed together)", specName, fatal)
			}
		}
	}
	logger.Printf("pre-created %d VM(s) from pool spec", totalCreate)
}

// readSystemCPUs returns the number of logical CPUs available on the host.
func readSystemCPUs() uint32 {
	return uint32(runtime.NumCPU())
}

// readSystemMemMB returns total system memory in MB.
func readSystemMemMB() uint64 {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				if kb, err := strconv.ParseUint(fields[1], 10, 64); err == nil {
					return kb / 1024
				}
			}
		}
	}
	return 0
}

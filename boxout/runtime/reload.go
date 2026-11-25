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

package runtime

import (
	"bytes"
	"log"

	"gopkg.in/yaml.v3"

	"common/config"
	sandlotconfig "sandlot/config"
	"sandlot/preflight"

	"boxout/server"
)

// StartConfigReload watches the sandlot config file and hot-applies the
// tinyvm subset (kernel, initramfs, default resources). Everything else is
// logged as restart-required — the same classification sandlot applies, so
// the two processes stay consistent.
func StartConfigReload(cfg sandlotconfig.SandlotConfig, srv *server.Server, logger *log.Logger) *config.ReloadWatcher {
	if cfg.ConfigFilePath == "" {
		return nil
	}

	watchableCfg := config.NewWatchableConfig(cfg)
	// The startup CLI overrides (bridge/subnet/gateway/dns/…) must be re-applied
	// to every decoded revision, exactly as sandlot and the gateway do: without
	// it each unrelated file edit re-logged phantom "requires a restart" lines
	// for every flag-provided key (the diff compared the flag-applied startup
	// config against a raw file decode).
	_, err := config.NewReloadWatcher(cfg.ConfigFilePath, func(content []byte) {
		newCfg := sandlotconfig.Defaults()
		dec := yaml.NewDecoder(bytes.NewReader(content))
		dec.KnownFields(true) // strict (shares sandlot's config: unknown keys are errors)
		if err := dec.Decode(&newCfg); err != nil {
			logger.Printf("config reload: failed to parse YAML (strict: unknown keys are errors): %v", err)
			return
		}
		prev := watchableCfg.Get()
		if err := sandlotconfig.ReapplyStartupFlags(&prev, &newCfg); err != nil {
			logger.Printf("config reload: refusing the edit (%v); keeping the previous config", err)
			return
		}
		if err := newCfg.Validate(); err != nil {
			logger.Printf("config reload: invalid values (%v); keeping the previous config", err)
			return
		}
		// A kernel/initramfs edit changes what the next create_vm boots, so it
		// passes the same guest TCB pin check the sandlot's start/reload path
		// runs, BEFORE the swap: a failed check keeps the previous config
		// serving instead of letting the file outrun the verified pair.
		if newCfg.HasRole("exec") &&
			(prev.TinyVM.Kernel != newCfg.TinyVM.Kernel || prev.TinyVM.Initramfs != newCfg.TinyVM.Initramfs) {
			if err := preflight.VerifyGuestArtifacts(&newCfg, logger); err != nil {
				logger.Printf("config reload: guest TCB verification failed (%v); keeping the previous config", err)
				return
			}
		}
		cs := watchableCfg.Swap(newCfg).Diff(newCfg)
		for _, fc := range cs.HotReload {
			switch fc.Name {
			case "tinyvm.kernel", "tinyvm.initramfs",
				"tinyvm.default_vcpus", "tinyvm.default_memory_mb":
				srv.UpdateVMMConfig(newCfg.TinyVM.Kernel, newCfg.TinyVM.Initramfs,
					newCfg.TinyVM.DefaultVCPUs, newCfg.TinyVM.DefaultMemoryMB)
			}
			// tinyvm.warden_* are restart-required (the shared classifier
			// marks only tinyvm.{kernel,initramfs,default_vcpus,
			// default_memory_mb} hot) and are deliberately not applied
			// here: the warden cmdline (countdown / max exec timeout / log)
			// is built per create_vm from this vmmCfg, so a hot-applied
			// change would silently split the node's pool across two cmdline
			// shapes (and an online warden_log=debug flip would tax the
			// guest console on every new VM).
		}
		for _, fc := range cs.RestartReq {
			logger.Printf("config reload: %s changed but requires a restart (not applied): %v -> %v",
				fc.Name, fc.Old, fc.New)
		}
	})
	if err != nil {
		logger.Printf("warning: failed to watch config %s: %v (tinyvm hot-reload disabled)", cfg.ConfigFilePath, err)
		return nil
	}
	logger.Printf("config hot-reload watcher started (tinyvm.* only): %s", cfg.ConfigFilePath)
	return nil
}

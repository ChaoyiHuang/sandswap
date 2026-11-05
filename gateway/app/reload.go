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
	"log/slog"

	"common/config"
	gwconfig "gateway/config"
)

// startConfigReload starts the hot-reload file watcher if a config path is set.
func startConfigReload(configPath string, cfg *gwconfig.GatewayConfig, targets *gwconfig.HotReloadTargets, logger *slog.Logger) *config.ReloadWatcher {
	if configPath == "" {
		return nil
	}

	watchableCfg := config.NewWatchableConfig(*cfg)
	rw, err := config.NewReloadWatcher(configPath, gwconfig.NewReloadCallback(watchableCfg, targets, logger))
	if err != nil {
		logger.Warn("failed to start config reload watcher, continuing without hot-reload", "path", configPath, "error", err)
		return nil
	}
	logger.Info("config hot-reload watcher started", "path", configPath)
	return rw
}

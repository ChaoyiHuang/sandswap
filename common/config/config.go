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
// Package config provides shared configuration infrastructure for Sandswap
// services: atomic config swapping, change classification (hot-reload vs
// restart-required), file watching with debounce, and flag/config/default merge.

package config

import (
	"sync/atomic"
)

// ChangeClass indicates whether a config change can be applied live.
type ChangeClass int

const (
	// ChangeHotReload means the change can be applied immediately without restart.
	ChangeHotReload ChangeClass = iota
	// ChangeRestartRequired means the change requires a process restart to take effect.
	ChangeRestartRequired
)

// FieldChange describes one field that changed between old and new config.
type FieldChange struct {
	Name  string      // e.g. "lease.timeout_ms"
	Old   string      // formatted old value
	New   string      // formatted new value
	Class ChangeClass // hot-reload or restart-required
}

// ChangeSet is the result of diffing old vs new config.
type ChangeSet struct {
	HotReload  []FieldChange // changes that can be applied live
	RestartReq []FieldChange // changes that require restart
}

// Empty returns true if no changes were detected.
func (cs *ChangeSet) Empty() bool {
	return len(cs.HotReload) == 0 && len(cs.RestartReq) == 0
}

// WatchableConfig holds an atomically-swappable config value. Callers read
// via Get() (lock-free via atomic.Value); writers call Swap() which returns
// the old value so the caller can diff old vs new to classify changes.
type WatchableConfig[T any] struct {
	val atomic.Value // holds T
}

// NewWatchableConfig creates a WatchableConfig with an initial value.
func NewWatchableConfig[T any](initial T) *WatchableConfig[T] {
	wc := &WatchableConfig[T]{}
	wc.val.Store(initial)
	return wc
}

// Get returns the current config value. Safe to call concurrently.
func (wc *WatchableConfig[T]) Get() T {
	return wc.val.Load().(T)
}

// Swap atomically replaces the config value and returns the old one.
// The caller should diff old vs new to produce a ChangeSet.
func (wc *WatchableConfig[T]) Swap(new T) (old T) {
	old = wc.Get()
	wc.val.Store(new)
	return old
}

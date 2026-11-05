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
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

// defaultDebounce is the coalescing window for fsnotify events.
// Editors like vim produce multiple CREATE+WRITE events per save; we wait
// this long after the last event before reading the file.
const defaultDebounce = 200 * time.Millisecond

// reloadChCap is the capacity of the reload signal channel. A capacity of 1
// coalesces multiple pending reloads into one: if a reload is already pending
// (or in progress) when a new fsnotify event fires, the new signal is dropped
// via a non-blocking send. This prevents goroutine pile-up and ensures the
// latest file content is always re-read on the next reload (no lost updates,
// no stale queued snapshots).
const reloadChCap = 1

// ReloadWatcher watches a config file for changes and calls onChange with
// the new file content after a debounce period. It handles the common
// editor pattern of write-to-temp + rename by watching the parent directory.
//
// Serialization: onChange is invoked by a single dedicated goroutine
// (processReload), so config-triggered resizes (ResizePool) never run
// concurrently. A reload fired while a previous one is still in flight is
// coalesced into the reloadCh; when the in-flight reload completes, the
// goroutine re-reads the LATEST file content and processes it. This means a
// config change is never applied on top of a still-running resize, and no
// update is lost.
type ReloadWatcher struct {
	watcher  *fsnotify.Watcher
	path     string // absolute path to the config file
	dir      string // absolute path to the parent directory
	filename string // base filename being watched
	debounce time.Duration

	// symlinked is set when the config path resolves through a symlink
	// (kubelet ConfigMap volume): there kubelet updates the config by
	// atomically swapping a "..data" symlink in the parent dir, so no event
	// ever carries the config's own filename — ".."-prefixed dir events are
	// changes of our file as well.
	symlinked bool

	onChange   func(newContent []byte)
	onStop     chan struct{}
	done       chan struct{} // closed when loop() exits
	reloadDone chan struct{} // closed when processReload() exits

	mu    sync.Mutex
	timer *time.Timer // debounce timer

	reloadCh chan struct{} // coalesced reload signal (cap 1)
}

// NewReloadWatcher creates a file watcher for the given config path.
// The onChange callback is invoked with the file content after each change
// (debounced by 200ms). The caller should parse the content and apply changes.
// onChange is called serially: a second change is not processed until the
// first onChange returns.
func NewReloadWatcher(path string, onChange func(newContent []byte)) (*ReloadWatcher, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}

	fw, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	// Watch the parent directory, not the file itself. This handles the
	// vim-style write-to-temp + rename pattern: the original file's inode
	// changes, so watching the file directly would lose events.
	dir := filepath.Dir(absPath)
	filename := filepath.Base(absPath)

	// A symlinked config path (kubelet ConfigMap volume) never sees events for
	// its own filename — kubelet atomically swaps the ..data symlink in the
	// parent dir. Detect once; the ".."-event mode in loop() depends on it.
	// Plain files (bare metal) are unaffected: their behavior is identical.
	symlinked := false
	if resolved, rerr := filepath.EvalSymlinks(absPath); rerr == nil && resolved != absPath {
		symlinked = true
	}

	if err := fw.Add(dir); err != nil {
		fw.Close()
		return nil, err
	}

	rw := &ReloadWatcher{
		watcher:    fw,
		path:       absPath,
		dir:        dir,
		filename:   filename,
		debounce:   defaultDebounce,
		symlinked:  symlinked,
		onChange:   onChange,
		onStop:     make(chan struct{}),
		done:       make(chan struct{}),
		reloadDone: make(chan struct{}),
		reloadCh:   make(chan struct{}, reloadChCap),
	}

	go rw.loop()
	go rw.processReload()

	return rw, nil
}

// loop processes fsnotify events and debounces them before signaling a reload.
func (rw *ReloadWatcher) loop() {
	defer close(rw.done)

	for {
		select {
		case <-rw.onStop:
			return

		case event, ok := <-rw.watcher.Events:
			if !ok {
				return
			}
			// Only react to events on our target file.
			base := filepath.Base(event.Name)
			ours := base == rw.filename
			// ConfigMap mounts: the config path is a symlink; kubelet's
			// update is the atomic swap of "..data" (and creation of its
			// "..<timestamp>" staging dir). Under a symlinked path those are
			// changes of OUR file.
			if rw.symlinked && strings.HasPrefix(base, "..") {
				ours = true
			}
			if !ours {
				continue
			}
			if event.Has(fsnotify.Create) || event.Has(fsnotify.Write) || event.Has(fsnotify.Rename) {
				rw.resetTimer()
			}

		case err, ok := <-rw.watcher.Errors:
			if !ok {
				return
			}
			slog.Error("config reload watcher error", "path", rw.path, "error", err)
		}
	}
}

// resetTimer (re)starts the debounce timer. When it fires, a reload is
// signaled to processReload via reloadCh. The timer callback does NOT call
// onChange directly - it only signals, so a slow resize never blocks the
// fsnotify loop and never piles up goroutines.
func (rw *ReloadWatcher) resetTimer() {
	rw.mu.Lock()
	defer rw.mu.Unlock()

	if rw.timer != nil {
		rw.timer.Stop()
	}
	rw.timer = time.AfterFunc(rw.debounce, func() {
		// Non-blocking send: if a reload is already pending (channel full)
		// or in progress (channel will be drained next), drop this signal.
		// processReload always re-reads the latest file content, so dropping
		// a signal never loses an update - the next reload picks up the
		// newest file state.
		select {
		case rw.reloadCh <- struct{}{}:
		default:
		}
	})
}

// processReload is the single goroutine that runs onChange. It serializes
// config-triggered resizes: only one onChange (and thus one ResizePool) runs
// at a time. After each reload completes, it checks for a pending signal
// (set during the in-flight reload) and, if present, processes another reload
// with the latest file content.
func (rw *ReloadWatcher) processReload() {
	defer close(rw.reloadDone)
	for {
		select {
		case <-rw.onStop:
			return
		case <-rw.reloadCh:
			// Re-read the file on every reload so we always apply the LATEST
			// content, never a stale snapshot queued during a prior reload.
			content, err := os.ReadFile(rw.path)
			if err != nil {
				slog.Error("config reload: failed to read file", "path", rw.path, "error", err)
				continue
			}
			rw.onChange(content)
			// Loop back to select. If reloadCh has a pending signal (a change
			// arrived during the in-flight onChange), process it immediately;
			// otherwise block until the next signal.
		}
	}
}

// Stop shuts down the watcher. It is safe to call multiple times.
func (rw *ReloadWatcher) Stop() {
	rw.mu.Lock()
	if rw.timer != nil {
		rw.timer.Stop()
		rw.timer = nil
	}
	rw.mu.Unlock()

	// Signal the loops to stop. Non-blocking in case Stop is called twice.
	select {
	case <-rw.onStop:
		// Already closed.
	default:
		close(rw.onStop)
	}

	rw.watcher.Close()

	// Wait for both goroutines to finish so onChange is not called after
	// Stop returns.
	<-rw.done
	<-rw.reloadDone
}

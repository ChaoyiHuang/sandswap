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

package identity

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

// This file makes MemoryStore durable across gateway restarts in single-node
// mode: every mutating Store method rewrites a full JSON snapshot (hash-only
// credentials, mirroring the etcd path), and NewPersistentMemoryStore loads it
// back at startup. Without it a restart orphans every agent api key and volume
// directory even though the underlying storage survives.
//
// Semantics:
//   - Persistence is opt-in per store instance (snapshotPath == "" disables
//     it); registry.New keeps building plain non-persisting stores for tests.
//   - Writes are tmp+rename in the target directory, fsync'd, mode 0600.
//     Best-effort: a failed write is logged, never returned — the request has
//     already mutated memory, and the next successful mutation rewrites the
//     complete state (full snapshot, no journal to replay).
//   - persistLocked is called only from methods already holding s.mu for
//     writing, which serializes mutation+persist: two writers can never
//     interleave their snapshots.

// IdentityStoreVersion is the on-disk snapshot format version. A mismatch is a
// startup error, never a best-effort migration: an unknown future format may
// have different credential semantics.
const IdentityStoreVersion = 1

// storeTmpSuffix is appended to the snapshot path for the atomic-write
// temporary. Same directory as the target so os.Rename cannot cross a
// filesystem boundary.
const storeTmpSuffix = ".tmp"

// storeLockSuffix is appended to the snapshot path for the exclusive-hold lock
// file guarding against two gateways sharing one volRoot.
const storeLockSuffix = ".lock"

// errNoIdentitySnapshot reports that the snapshot file does not exist yet — a
// normal first-boot condition, not an error.
var errNoIdentitySnapshot = errors.New("no identity store snapshot")

// snapshotAgent is the on-disk form of an Agent. Only the API key DIGEST is
// persisted — the plaintext exists at creation time and is returned to the
// operator exactly once (same contract as the etcd path). Agent itself cannot
// be marshaled: APIKey and APIKeyHash are json:"-".
type snapshotAgent struct {
	AgentID     string    `json:"agent_id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	APIKeyHash  string    `json:"api_key_hash"`
	CreatedAt   time.Time `json:"created_at"`
	// Namespace is part of the tenancy identity: dropping it on reload would
	// re-home the agent in `default` and defeat the namespace rules.
	Namespace string `json:"namespace,omitempty"`
}

// snapshotRecord mirrors identity.Record field-for-field so the file format is
// versioned independently of struct evolution.
type snapshotRecord struct {
	ID          string    `json:"sandfs_id"`
	AgentID     string    `json:"agent_id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	RootFSPath  string    `json:"rootfs_path"`
	Template    string    `json:"template,omitempty"`
	Mode        string    `json:"mode,omitempty"`
	MinVCPUs    uint32    `json:"min_vcpus,omitempty"`
	MinMemoryMB uint64    `json:"min_memory_mb,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	// Status is the lifecycle gate (detaching/detached/deleting). It must
	// survive a restart: a volume whose delete/swap was in flight must not
	// come back ACTIVE and accept execs.
	Status      string `json:"status,omitempty"`
	VolumeEpoch string `json:"volume_epoch,omitempty"`
	// Namespace is the record's tenancy label. Dropping it would move every
	// namespaced record to `default` on the next load.
	Namespace string `json:"namespace,omitempty"`
}

// storeSnapshot is the envelope. SavedAt is informational only — never used
// for logic.

type storeSnapshot struct {
	Version    int                  `json:"version"`
	SavedAt    time.Time            `json:"saved_at"`
	Agents     []snapshotAgent      `json:"agents"`
	SandFS     []snapshotRecord     `json:"sandfs"`
	Tombstones map[string]time.Time `json:"tombstones,omitempty"`
}

// NewPersistentMemoryStore creates a MemoryStore that snapshots every mutation
// to path and loads the existing snapshot back. Order matters: acquire the
// exclusive state lock BEFORE loading, so a second gateway sharing this
// volRoot fails loudly instead of silently overwriting identity data
// (last-writer-wins on rename). Production always passes a non-empty path
// (persistence is mandatory in MemoryStore mode; cmd rejects an explicit
// empty value before getting here) — path == "" remains tolerated for tests.
//
// Error returns are startup-fatal by contract: a corrupt snapshot or version
// mismatch must refuse to start (starting empty would silently orphan every
// volume directory — the exact failure this file exists to prevent).
func NewPersistentMemoryStore(volRoot, path string, logger *slog.Logger) (*MemoryStore, error) {
	s := NewMemoryStore(volRoot)
	if logger == nil {
		logger = slog.Default()
	}
	s.logger = logger
	if path == "" {
		return s, nil
	}
	lockFile, err := acquireIdentityStoreLock(path)
	if err != nil {
		return nil, err
	}
	s.lockFile = lockFile // held open for the process lifetime; closing releases the flock
	s.snapshotPath = path
	if err := s.loadSnapshot(volRoot, path, logger); err != nil {
		lockFile.Close()
		return nil, err
	}
	return s, nil
}

// acquireIdentityStoreLock takes an exclusive non-blocking flock on <path>.lock.
// The lock is advisory but sufficient: the only writer of the snapshot is this
// package. The kernel releases it on process death, so a crashed gateway can
// never leave a stale lock blocking restart.
func acquireIdentityStoreLock(path string) (*os.File, error) {
	lockPath := path + storeLockSuffix
	// First boot on a fresh vol-root: the snapshot dir does not exist yet, and
	// the O_CREATE below cannot create intermediate dirs (cold start = empty
	// store, not an error). The save path creates it too — keep both in step.
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create identity store dir %s: %w", filepath.Dir(path), err)
	}
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open identity store lock %s: %w", lockPath, err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("identity store %s is held by another gateway (%w); refusing to start", path, err)
	}
	return f, nil
}

// Close releases the state lock (and with it the store's exclusive right to
// write the snapshot). The gateway process normally holds the lock for its
// whole lifetime and the kernel frees it on exit; Close exists so a successor
// store can take over in the same process — restart-simulation tests, and any
// future graceful-shutdown handover. It does NOT flush or otherwise touch the
// snapshot: every mutation already persisted. Idempotent; persistence stays
// enabled after Close (persist attempts will simply log write errors), so
// Close is a handover point, not a disable switch.
func (s *MemoryStore) Close() error {
	if s.lockFile == nil {
		return nil
	}
	err := s.lockFile.Close()
	s.lockFile = nil
	return err
}

// loadSnapshot reads and restores the snapshot. Missing file → start empty
// (first boot, or -vol-root moved). Corrupt JSON / wrong version → error
// (caller fails fast).
func (s *MemoryStore) loadSnapshot(volRoot, path string, logger *slog.Logger) error {
	snap, err := readIdentityStoreFile(path)
	if err != nil {
		if errors.Is(err, errNoIdentitySnapshot) {
			logger.Info("no identity store snapshot; starting empty", "path", path)
			warnOrphanVolumeDirs(volRoot, nil, logger)
			return nil
		}
		return err
	}
	if snap.Version != IdentityStoreVersion {
		return fmt.Errorf("unsupported identity store snapshot version %d in %s (want %d)", snap.Version, path, IdentityStoreVersion)
	}

	s.mu.Lock()
	agents, sandfs, dropped := s.restoreLocked(snap, volRoot, logger)
	// A deleted id must stay dead across a restart: the snapshot persists the
	// tombstone map, and dropping it here would let a reused 32-bit id
	// resurrect a name whose stale record may still exist on a peer.
	for id, t := range snap.Tombstones {
		s.tombstones[id] = t
	}
	// known is keyed by on-disk volume DIRECTORY name, not sandfs id: the
	// record carries the seed-derived path and the directory name is what the
	// orphan scan can compare against.
	known := make(map[string]bool, len(s.sandfs))
	for _, rec := range s.sandfs {
		if rec.RootFSPath != "" {
			known[filepath.Base(rec.RootFSPath)] = true
		}
	}
	s.mu.Unlock()

	logger.Info("loaded identity store snapshot", "agents", agents, "sandfs", sandfs, "dropped", dropped, "path", path)
	warnOrphanVolumeDirs(volRoot, known, logger)

	// Remove a tmp file left behind by a writer that died mid-write. Best
	// effort — its presence never blocks anything.
	if err := os.Remove(path + storeTmpSuffix); err != nil && !os.IsNotExist(err) {
		logger.Warn("cannot remove stale identity store snapshot tmp", "path", path+storeTmpSuffix, "error", err)
	}
	return nil
}

// readIdentityStoreFile loads the snapshot bytes. A missing file is the
// errNoIdentitySnapshot sentinel; anything unreadable or unparseable is a wrapped
// error (corrupt = refuse to start).
func readIdentityStoreFile(path string) (*storeSnapshot, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errNoIdentitySnapshot
		}
		return nil, fmt.Errorf("read identity store snapshot %s: %w", path, err)
	}
	var snap storeSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, fmt.Errorf("corrupt identity store snapshot %s: %w", path, err)
	}
	return &snap, nil
}

// restoreLocked injects snapshot records directly into the maps (in-package,
// bypassing newPublicID and key generation — loaded identities are verbatim).
// Malformed entries are skipped with a warning, never fatal: one bad record
// must not take down every other identity on the host.
// Caller holds s.mu for writing.
func (s *MemoryStore) restoreLocked(snap *storeSnapshot, volRoot string, logger *slog.Logger) (loadedAgents, loadedSandfs, dropped int) {
	for _, sa := range snap.Agents {
		switch {
		case sa.AgentID == "" || sa.APIKeyHash == "":
			logger.Warn("identity store snapshot: dropping agent with missing identity", "agent_id", sa.AgentID)
			dropped++
		case s.agents[sa.AgentID] != nil:
			logger.Warn("identity store snapshot: duplicate agent id, keeping first", "agent_id", sa.AgentID)
			dropped++
		case s.agentApiKeyToID[sa.APIKeyHash] != "":
			logger.Warn("identity store snapshot: duplicate api key hash, keeping first", "agent_id", sa.AgentID)
			dropped++
		default:
			s.agents[sa.AgentID] = &Agent{ID: sa.AgentID, Name: sa.Name, Description: sa.Description, APIKeyHash: sa.APIKeyHash, CreatedAt: sa.CreatedAt, Namespace: sa.Namespace}
			s.agentApiKeyToID[sa.APIKeyHash] = sa.AgentID
			loadedAgents++
		}
	}

	for _, sr := range snap.SandFS {
		switch {
		case sr.ID == "":
			logger.Warn("identity store snapshot: dropping sandfs with empty id")
			dropped++
		case s.sandfs[sr.ID] != nil:
			logger.Warn("identity store snapshot: duplicate sandfs id, keeping first", "sandfs_id", sr.ID)
			dropped++
		case sr.RootFSPath == "":
			// Crash window in Registry.CreateSandFS between store.CreateSandFS
			// and SetRootFSPath: the volume was never usable, so the record
			// has no value. The leftover directory (if any) is picked up by
			// the orphan scan below.
			logger.Warn("identity store snapshot: dropping sandfs with no rootfs (incomplete creation)", "sandfs_id", sr.ID)
			dropped++
		case !rootfsPathUnderVolRoot(volRoot, sr.RootFSPath):
			// A hand-edited or cross-host-restored snapshot must not be able
			// to point a mount at an arbitrary host directory: RootFSPath
			// feeds the virtio-fs allowed_dirs filter.
			logger.Warn("identity store snapshot: dropping sandfs whose rootfs escapes the volume root", "sandfs_id", sr.ID, "rootfs_path", sr.RootFSPath, "vol_root", volRoot)
			dropped++
		case validateStatus(sr.Status) != nil:
			// An unknown lifecycle value cannot be trusted as a gate: dropping
			// the record is fail-closed (the volume is found by the orphan
			// scan); keeping it as ACTIVE would be fail-open.
			logger.Warn("identity store snapshot: dropping sandfs with invalid lifecycle status", "sandfs_id", sr.ID, "status", sr.Status)
			dropped++
		default:
			if _, ok := s.agents[sr.AgentID]; !ok {
				logger.Warn("identity store snapshot: sandfs owner agent missing, keeping record", "sandfs_id", sr.ID, "agent_id", sr.AgentID)
			}
			s.sandfs[sr.ID] = &Record{
				ID:          sr.ID,
				AgentID:     sr.AgentID,
				Name:        sr.Name,
				Description: sr.Description,
				RootFSPath:  sr.RootFSPath,
				Template:    sr.Template,
				Mode:        sr.Mode,
				MinVCPUs:    sr.MinVCPUs,
				MinMemoryMB: sr.MinMemoryMB,
				CreatedAt:   sr.CreatedAt,
				Status:      sr.Status,
				VolumeEpoch: sr.VolumeEpoch,
				Namespace:   sr.Namespace,
			}
			if sr.AgentID != "" {
				s.sandfsByAgent[sr.AgentID] = append(s.sandfsByAgent[sr.AgentID], sr.ID)
			}
			loadedSandfs++
		}
	}
	return loadedAgents, loadedSandfs, dropped
}

// rootfsPathUnderVolRoot reports whether p is a real path strictly under
// volRoot (never the root itself, never escaping via ".."). Mirrors
// isSandswapVMDir in sandlot/core/state.go.
func rootfsPathUnderVolRoot(volRoot, p string) bool {
	if p == "" || volRoot == "" {
		return false
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return false
	}
	rootAbs, err := filepath.Abs(volRoot)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(rootAbs, abs)
	if err != nil {
		return false
	}
	return rel != "." && rel != ".." && !strings.HasPrefix(rel, "../")
}

// snapshotLocked builds the current in-memory state as a snapshot. Both
// slices are sorted by ID so the file bytes are deterministic — map iteration
// order would otherwise churn the file on every mutation.
// Caller holds s.mu (read or write).
func (s *MemoryStore) snapshotLocked() *storeSnapshot {
	snap := &storeSnapshot{
		Version: IdentityStoreVersion,
		SavedAt: time.Now(),
		Agents:  make([]snapshotAgent, 0, len(s.agents)),
		SandFS:  make([]snapshotRecord, 0, len(s.sandfs)),
	}
	for _, a := range s.agents {
		snap.Agents = append(snap.Agents, snapshotAgent{
			AgentID:     a.ID,
			Name:        a.Name,
			Description: a.Description,
			APIKeyHash:  a.APIKeyHash,
			CreatedAt:   a.CreatedAt,
			Namespace:   a.Namespace,
		})
	}
	sort.Slice(snap.Agents, func(i, j int) bool { return snap.Agents[i].AgentID < snap.Agents[j].AgentID })
	for _, r := range s.sandfs {
		snap.SandFS = append(snap.SandFS, snapshotRecord{
			ID:          r.ID,
			AgentID:     r.AgentID,
			Name:        r.Name,
			Description: r.Description,
			RootFSPath:  r.RootFSPath,
			Template:    r.Template,
			Mode:        r.Mode,
			MinVCPUs:    r.MinVCPUs,
			MinMemoryMB: r.MinMemoryMB,
			CreatedAt:   r.CreatedAt,
			Status:      r.Status,
			VolumeEpoch: r.VolumeEpoch,
			Namespace:   r.Namespace,
		})
	}
	sort.Slice(snap.SandFS, func(i, j int) bool { return snap.SandFS[i].ID < snap.SandFS[j].ID })
	if len(s.tombstones) > 0 {
		snap.Tombstones = make(map[string]time.Time, len(s.tombstones))
		for id, t := range s.tombstones {
			snap.Tombstones[id] = t
		}
	}
	return snap
}

// persistLocked rewrites the full snapshot file. Call only from mutating
// methods while s.mu is write-held, and only on success paths. Best-effort:
// failures are logged, never returned — see the file comment.
func (s *MemoryStore) persistLocked() {
	if s.snapshotPath == "" {
		return
	}
	if err := writeIdentityStoreFile(s.snapshotPath, s.snapshotLocked()); err != nil {
		s.logger.Error("failed to persist identity store snapshot", "path", s.snapshotPath, "error", err)
	}
}

// writeIdentityStoreFile atomically replaces the snapshot: MarshalIndent →
// write <path>.tmp in the SAME directory (rename must not cross filesystems)
// → fsync → rename. Mode 0600: the file holds agent credential digests and
// the sandfs records they own — whoever reads it can impersonate any agent.
func writeIdentityStoreFile(path string, snap *storeSnapshot) error {
	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal identity store snapshot: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create identity store snapshot dir: %w", err)
	}
	tmpPath := path + storeTmpSuffix
	f, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("create identity store snapshot tmp %s: %w", tmpPath, err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("write identity store snapshot tmp: %w", err)
	}
	// Durable before the rename: this file IS the identity store, so a power
	// loss between rename and data hit must not roll it back to a previous
	// version (or an empty directory = all identities lost).
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("sync identity store snapshot tmp: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("close identity store snapshot tmp: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("rename identity store snapshot into place: %w", err)
	}
	// Best-effort directory fsync: without it a power loss can drop the
	// rename itself, reverting to the previous snapshot — consistent, but the
	// mutations the caller believes persisted would silently roll back.
	if d, err := os.Open(filepath.Dir(path)); err == nil {
		d.Sync()
		d.Close()
	}
	return nil
}

// warnOrphanVolumeDirs logs volume directories under volRoot that no identity
// record claims. Warn-only: records are never auto-imported (owner, template
// and mode metadata are unknowable from the directory) and never deleted.
// The volume-directory shape filter keeps the snapshot/lock/tmp files,
// lost+found and any template dirs out of the report.
func warnOrphanVolumeDirs(volRoot string, known map[string]bool, logger *slog.Logger) {
	entries, err := os.ReadDir(volRoot)
	if err != nil {
		if !os.IsNotExist(err) {
			logger.Warn("cannot scan volume root for orphan directories", "vol_root", volRoot, "error", err)
		}
		return
	}
	for _, e := range entries {
		if !e.IsDir() || !isVolumeDirName(e.Name()) || known[e.Name()] {
			continue
		}
		logger.Warn("orphan volume directory (no identity record); inspect or remove manually",
			"path", filepath.Join(volRoot, e.Name()))
	}
}

// volumeDirPrefix and volumeDirHashLen mirror the on-disk name shape produced
// by sandlot/provision/volname (`sf-` + 26 lowercase base32 characters). The
// gateway and sandlot are separate Go modules and the gateway must never learn
// the seed, so the shape — not the derivation — is duplicated here. The
// authority for a KNOWN volume is the record's RootFSPath; this filter only
// decides which unclaimed directories look like volumes worth warning about.
const (
	volumeDirPrefix  = "sf-"
	volumeDirHashLen = 26
)

// isVolumeDirName reports whether name has the seed-derived volume directory
// shape.
func isVolumeDirName(name string) bool {
	if !strings.HasPrefix(name, volumeDirPrefix) {
		return false
	}
	rest := name[len(volumeDirPrefix):]
	if len(rest) != volumeDirHashLen {
		return false
	}
	for _, c := range rest {
		if !((c >= 'a' && c <= 'z') || (c >= '2' && c <= '7')) {
			return false
		}
	}
	return true
}

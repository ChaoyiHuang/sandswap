// Copyright 2026 Chaoyi Huang. All rights reserved.
//
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE file at the root of this repository.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, sandswap's use of this software will be governed
// by the Apache License, Version 2.0.

// Package registry manages SandFS (sandbox filesystem) identity and storage mapping.
// Each SandFS has a unique ID, an owner Agent, and a persistent directory on shared
// storage that serves as the microVM's root filesystem (mounted via virtio-fs + OverlayFS).
// Registry delegates auth/identity operations to identity.Store and delegates
// every shared-storage MANIPULATION to the storage plane (gateway/storage.Ops
// — ProvisionCommands over the node stream to prov-role sandlot instances;
// the gateway host mounts no shared storage). In single-node mode,
// identity.Store is a MemoryStore (in-process maps); in multi-node mode, it
// is an EtcdStore (etcd + local cache).

package registry

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"

	"gateway/identity"
	"gateway/pool"
	"gateway/storage"
)

// ErrSandfsNotDeleting refuses a terminal delete unless the record is already
// in the deleting state (or provably absent). The human delete path sets that
// gate before calling Delete; the guard makes the invariant structural for any
// future caller — a volume must never be removed under a live attachment.
var ErrSandfsNotDeleting = errors.New("sandfs is not in the deleting state")

// Registry stores SandFS records and resolves API keys to SandFS identities.
// It composes identity.Store for identity management; the storage half lives
// behind the storage.Ops seam.
type Registry struct {
	store   identity.Store // auth/identity storage (MemoryStore or EtcdStore)
	volRoot string         // shared storage root: path convention only (string joins for exec-node RPCs), never a mount
	storage storage.Ops    // storage-plane executor; nil = unavailable (named 503, never a silent fallback)
	// specCeiling returns the largest advertised VM spec (vcpus, memory_mb)
	// the deployment can schedule. Storage-plane-declared minimum resources
	// are clamped to it before they become a persistent placement
	// requirement(). nil = the built-in table's ceiling (human mode,
	// which holds no pool). Set once at wiring, read-only afterwards.
	specCeilingFn func() (uint32, uint64)
}

// New creates a new Registry with the given identity store and shared storage root.
func New(volRoot string) *Registry {
	return &Registry{
		store:   identity.NewMemoryStore(volRoot),
		volRoot: volRoot,
	}
}

// NewWithStore creates a new Registry with an explicit identity store.
// Used when the caller provides a pre-configured store (e.g., EtcdStore in multi-node).
func NewWithStore(store identity.Store, volRoot string) *Registry {
	return &Registry{
		store:   store,
		volRoot: volRoot,
	}
}

// SetStorageOps installs the storage-plane executor (the stream-backed RPC
// one — provision instances).
func (r *Registry) SetStorageOps(ops storage.Ops) {
	r.storage = ops
}

// Storage returns the storage-plane executor (nil = plane unavailable).
func (r *Registry) Storage() storage.Ops {
	return r.storage
}

// SetSpecCeiling installs the live provider of the largest advertised spec.
// Single-node wiring passes the pool's MaxSpecResources; unset (human mode,
// tests) means the built-in table's ceiling applies.
func (r *Registry) SetSpecCeiling(fn func() (uint32, uint64)) {
	r.specCeilingFn = fn
}

// specCeiling resolves the ceiling (see SetSpecCeiling).
func (r *Registry) specCeiling() (uint32, uint64) {
	if r.specCeilingFn != nil {
		return r.specCeilingFn()
	}
	return pool.StaticMaxSpecResources()
}

// Store returns the underlying identity store (for stream/watch integration).
func (r *Registry) Store() identity.Store {
	return r.store
}

// VolRoot returns the shared storage root directory for SandFS volumes.
// This is a PATH CONVENTION (joined for exec-node RPC payloads), not a mount:
// in rpc mode the gateway host mounts no storage at all.
func (r *Registry) VolRoot() string {
	return r.volRoot
}

// VolumeRoot returns the shared storage root directory.
func (r *Registry) VolumeRoot() string {
	return r.volRoot
}

// Get returns a SandFS record by ID.
func (r *Registry) Get(sandfsID string) (*identity.Record, error) {
	return r.store.GetSandFS(sandfsID)
}

// ValidateVolumePath enforces the containment rule every rootfs path must
// satisfy before it may be stored or handed to a mount: absolute,
// filepath.Clean-stable, and strictly inside volRoot. It is the ONE
// implementation of that rule — the create ingress (CreateSandFS: the path
// arrives from the storage plane, which is untrusted input) and the operator
// re-point endpoint (POST /human/sandfs/{id}/rootfs-path) both call it, so the
// two can never drift. The identity store's snapshot loader additionally
// applies the rule to persisted records at load time; that is read-time
// defense, this is the write-time one.
func ValidateVolumePath(volRoot, path string) error {
	if path == "" {
		return fmt.Errorf("rootfs_path is required")
	}
	if !filepath.IsAbs(path) {
		return fmt.Errorf("rootfs_path must be absolute")
	}
	clean := filepath.Clean(path)
	if clean != path {
		return fmt.Errorf("rootfs_path must be a clean path (got %q, want %q)", path, clean)
	}
	root := filepath.Clean(volRoot)
	if !strings.HasPrefix(clean, root+string(filepath.Separator)) {
		return fmt.Errorf("rootfs_path must live under the volumes root %s", root)
	}
	if filepath.Base(clean) == ".." || strings.Contains(clean, "/../") {
		return fmt.Errorf("rootfs_path must not traverse")
	}
	return nil
}

// CreateSandFS creates a new SandFS with a dedicated directory on shared storage.
// A template reference and mode ("flat" | "overlay") are both required — mode is
// not auto-detected. The context bounds template downloads (flat templates
// materialized from an OCI registry can move substantial data).
// Returns the sandfs record (no API key — auth is via the agent's API key) and
// pulled: whether the materialization auto-pulled the ref from the OCI
// registry because it was missing from the local store (the create response's
// pull_status: "pulled" vs "cached").
//
// Ordering contract (unchanged from the in-process era): the identity record
// is created first, the volume materialized second, and ANY failure removes
// both — a partially-created volume must never outlive its record (the
// node-side .provisioning marker additionally self-heals partial trees on
// retry).
func (r *Registry) CreateSandFS(ctx context.Context, agentID string, req identity.CreateSandFSRequest) (*identity.Record, bool, error) {
	// 1. Template is required
	if req.Template == "" {
		return nil, false, fmt.Errorf("template is required: specify a template reference (e.g., \"ubuntu:24.04\")")
	}

	// 2. Mode is required (no auto-detect)
	if req.Mode != "flat" && req.Mode != "overlay" {
		return nil, false, fmt.Errorf("mode is required: must be \"flat\" or \"overlay\"")
	}

	// Storage plane must be available (named 503 upstream, never a silent
	// partial create).
	if r.storage == nil {
		// Wrap the sentinel (%w): the handler's writeStorageErr classifies
		// ErrNoProvisioner into the named retryable 503 — a plain-text error
		// here made errors.Is unreachable and the API answered an anonymous
		// 500 (reproduced by e2e/negative-path-gates.sh).
		return nil, false, fmt.Errorf("storage plane unavailable: no local template manager and no provision instance connected: %w", storage.ErrNoProvisioner)
	}

	// Mint the per-volume identity used by the signed stamp and every cold
	// mount. It is independent of the (32-bit) sandfs id: an id reused by a
	// later create gets a different epoch, so a stale record cannot mount the
	// new owner's volume.
	if req.VolumeEpoch == "" {
		var eb [16]byte
		if _, err := rand.Read(eb[:]); err != nil {
			return nil, false, fmt.Errorf("mint volume epoch: %w", err)
		}
		req.VolumeEpoch = hex.EncodeToString(eb[:])
	}

	// 3. Create the identity record via identity store
	rec, err := r.store.CreateSandFS(agentID, req)
	if err != nil {
		return nil, false, fmt.Errorf("create sandfs identity: %w", err)
	}

	// 4. Clear whatever already sits at this id's derived name, then
	// materialize the storage volume (executor-side: mkdir + setgid layout,
	// seed by mode, auto-pull, .provisioning self-heal).
	//
	// The clear is what makes the create path's "an existing complete volume
	// with a matching stamp is adopted (idempotent create)" short-circuit safe
	// on the NODE: the id was just minted against the live-record table, so no
	// LIVE record can own a directory at the derived name — anything found
	// there is debris from a DIFFERENT create (an orphan left behind by a
	// create whose cleanup raced its own materialization), and adopting it
	// would serve the old tenant's content to the new one once the 32-bit id
	// space hands the same id out again. DeleteVolume is stamp-checked and
	// treats ENOENT as success, so a normal create pays one stat.
	if err := r.storage.DeleteVolume(rec.ID); err != nil {
		r.store.DeleteSandFS(rec.ID)
		return nil, false, fmt.Errorf("clear any prior directory at the new volume's name: %w", err)
	}
	res, err := r.storage.EnsureVolume(ctx, rec.ID, req.Mode, req.Template, req.VolumeEpoch)
	if err != nil {
		// Remove BOTH the identity record AND the partial volume: the
		// executor may leave a marker-tagged partial tree for a retry to
		// self-heal, but this create FAILED — nothing will retry it, so
		// clean it now.
		r.store.DeleteSandFS(rec.ID)
		if delErr := r.storage.DeleteVolume(rec.ID); delErr != nil {
			slog.Warn("cleanup of failed sandfs creation left a partial volume",
				"sandfsID", rec.ID, "error", delErr)
		}
		return nil, false, fmt.Errorf("create sandfs: %w", err)
	}

	// 4b. The storage plane's answer is untrusted input: the record's
	// rootfs_path is what the exec node later hands to the VMM's allowed_dirs
	// filter verbatim, so it must sit strictly inside THIS deployment's
	// volumes root before it is recorded. A prov instance answering a path
	// outside the root (host escape attempt, misconfigured node) must fail the
	// create, not be stored — the node-side reply check is the same rule
	// applied where the path is derived, and the snapshot loader drops
	// escaping records on restart, but neither covers this write.
	if verr := ValidateVolumePath(r.volRoot, res.RootfsPath); verr != nil {
		// The raw answer is logged (operator diagnosis) but NOT echoed to the
		// HTTP caller: it is an arbitrary string from a possibly hostile node.
		slog.Warn("create sandfs: storage plane returned an unusable rootfs path (create refused)",
			"sandfsID", rec.ID, "rootfs_path", res.RootfsPath, "error", verr)
		r.store.DeleteSandFS(rec.ID)
		if delErr := r.storage.DeleteVolume(rec.ID); delErr != nil {
			slog.Warn("cleanup of failed sandfs creation left a partial volume",
				"sandfsID", rec.ID, "error", delErr)
		}
		return nil, false, fmt.Errorf("storage plane returned an unusable rootfs path (create refused; see the gateway log)")
	}

	// 5. Update the record with the rootfs path and minimum resources.
	// An explicit request value takes precedence over the template's default.
	vcpus := req.VCPUs
	memMB := req.MemoryMB
	if vcpus == 0 && memMB == 0 && res.MinOK {
		vcpus = res.MinVCPUs
		memMB = res.MinMemoryMB
		// the storage plane's declared minimum is untrusted input
		// that becomes a PERSISTENT placement requirement (exec-side
		// Pool.Acquire on every mount). A value above the largest advertised
		// spec would pin the sandfs into permanent NO_AVAILABLE_SANDBOX —
		// clamp to the ceiling and warn (the record stays usable).
		ceilV, ceilM := r.specCeiling()
		if vcpus > ceilV || memMB > ceilM {
			slog.Warn("create sandfs: storage plane declared minimum resources above the largest advertised spec; clamped",
				"sandfsID", rec.ID, "declaredVCPUs", vcpus, "declaredMemoryMB", memMB,
				"ceilingVCPUs", ceilV, "ceilingMemoryMB", ceilM)
			if vcpus > ceilV {
				vcpus = ceilV
			}
			if memMB > ceilM {
				memMB = ceilM
			}
		}
	}
	if err := r.store.SetRootFSPath(rec.ID, res.RootfsPath); err != nil {
		r.store.DeleteSandFS(rec.ID)
		if delErr := r.storage.DeleteVolume(rec.ID); delErr != nil {
			slog.Warn("cleanup of failed sandfs creation left a partial volume",
				"sandfsID", rec.ID, "error", delErr)
		}
		return nil, false, fmt.Errorf("set rootfs_path: %w", err)
	}
	if vcpus != 0 || memMB != 0 {
		if err := r.store.SetMinResources(rec.ID, vcpus, memMB); err != nil {
			slog.Warn("failed to set min resources for sandfs (optional metadata; creation continues)",
				"sandfsID", rec.ID, "error", err)
		}
	}

	return rec, res.Pulled, nil
}

// Delete removes a SandFS and its storage directory. The full teardown
// ordering (unmount sweep → overlay cleanup on exec nodes → this terminal
// pure-FS delete → ownership release) is orchestrated by the handler; the
// executor-side DeleteVolume treats ENOENT as success.
func (r *Registry) Delete(sandfsID string) error {
	if r.storage == nil {
		return fmt.Errorf("storage plane unavailable: cannot delete volume for %s", sandfsID)
	}
	// Precondition: the record must already be in the deleting state, or
	// provably absent. A record read failure is NOT absence — an etcd outage
	// must not turn into "delete the volume anyway".
	rec, err := r.store.GetSandFS(sandfsID)
	if errors.Is(err, identity.ErrSandFSNotFound) {
		// A cache miss is re-checked linearly when the store has that seam: a
		// lagging negative cache must not license the terminal deletion of a
		// record that still exists.
		if fr, ok := r.store.(identity.FreshReader); ok {
			fresh, ferr := fr.GetSandFSFresh(sandfsID)
			switch {
			case errors.Is(ferr, identity.ErrSandFSNotFound):
				rec, err = nil, nil
			case ferr != nil:
				return fmt.Errorf("delete sandfs %s: confirm absent: %w", sandfsID, ferr)
			default:
				rec, err = fresh, nil
			}
		} else {
			rec, err = nil, nil
		}
	}
	switch {
	case err != nil:
		return fmt.Errorf("delete sandfs %s: read record: %w", sandfsID, err)
	case rec != nil && rec.Status != identity.SandfsStatusDeleting:
		return fmt.Errorf("%w: sandfs %s status is %q", ErrSandfsNotDeleting, sandfsID, rec.Status)
	}
	if err := r.storage.DeleteVolume(sandfsID); err != nil {
		return fmt.Errorf("remove sandfs: %w", err)
	}
	// The gate makes the record deletion race-free with the volume deletion;
	// a record that vanished underneath us is already in the desired state.
	if err := r.store.DeleteSandFS(sandfsID); err != nil && !errors.Is(err, identity.ErrSandFSNotFound) {
		return err
	}
	return nil
}

// List returns all SandFS records.
func (r *Registry) List() []*identity.Record {
	recs, _ := r.store.ListAllSandFS()
	return recs
}

// ListSandFSByAgent returns all SandFS records owned by an agent.
func (r *Registry) ListSandFSByAgent(agentID string) ([]*identity.Record, error) {
	return r.store.ListSandFSByAgent(agentID)
}

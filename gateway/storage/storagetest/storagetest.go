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

// Package storagetest is the test double for the gateway's storage-plane
// seam. It implements storage.Ops with REAL local volume directories (mkdir
// under a temp root — enough for handler tests whose exec/file paths run
// against mocked nodes) plus knobs for injecting node-side failures.
//
// It deliberately has NO dependency on the node-side provision code: the
// gateway module is storage-plane-clean, and so are its tests. Real seeding
// semantics are tested where they live (sandlot/provision/volume).
package storagetest

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"gateway/storage"
)

// Ops is a configurable storage.Ops double over a temp root.
type Ops struct {
	VolRoot string

	mu        sync.Mutex
	Ensured   []string // sandfs ids passed to EnsureVolume
	Deleted   []string
	ensureErr map[string]error // per-id injected failure

	// ensurePulled is the auto-pull signal every EnsureVolume/SwapTemplate
	// reports (the create response's pull_status). Test-scoped knob.
	ensurePulled bool

	// rootfsPathOverride, when non-empty, is the path EnsureVolume answers
	// with (no directory work) — the knob for the ingress pins: a storage
	// plane that answers a path outside the volumes root, or names another
	// volume inside it.
	rootfsPathOverride string

	// BeforeEnsure, when non-nil, runs at the TOP of EnsureVolume (before the
	// double materializes anything): how a test plants the state that must
	// already exist at the id's derived name when the create arrives (an
	// orphaned tree from an earlier create).
	BeforeEnsure func(sandfsID string)

	// volumeAlias, when non-empty, collapses every volume path onto one
	// directory name under VolRoot (see SetVolumeAlias).
	volumeAlias string

	templates []storage.TemplateInfo

	// minVCPUs/minMemoryMB/minOK: the template-declared minimum resources
	// EnsureVolume answers with. Armed by SetMinResources; the zero value
	// keeps MinOK=false (the historical double behavior).
	minVCPUs    uint32
	minMemoryMB uint64
	minOK       bool
}

// New creates the double rooted at dir.
func New(dir string) *Ops {
	return &Ops{VolRoot: dir, ensureErr: map[string]error{}}
}

// FailEnsure injects a node-side failure for one sandfs id.
func (o *Ops) FailEnsure(sandfsID string, err error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.ensureErr[sandfsID] = err
}

// SetEnsurePulled makes subsequent EnsureVolume/SwapTemplate calls report the
// auto-pull signal (pins the pull_status plumbing in handler tests).
func (o *Ops) SetEnsurePulled(pulled bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.ensurePulled = pulled
}

// SetMinResources arms the template-declared minimum resources EnsureVolume
// answers with (MinOK=true) — the prov-declared value the create path clamps
// () or applies verbatim.
func (o *Ops) SetMinResources(vcpus uint32, memMB uint64) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.minVCPUs, o.minMemoryMB, o.minOK = vcpus, memMB, true
}

// minResultLocked folds the armed minimums into an EnsureResult (caller holds o.mu).
func (o *Ops) minResultLocked(res *storage.EnsureResult) *storage.EnsureResult {
	if o.minOK {
		res.MinVCPUs, res.MinMemoryMB, res.MinOK = o.minVCPUs, o.minMemoryMB, true
	}
	return res
}

// SetRootfsPathOverride makes EnsureVolume answer with path verbatim, doing no
// directory work — for pins on the gateway's ingress validation of an
// untrusted storage-plane answer.
func (o *Ops) SetRootfsPathOverride(path string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.rootfsPathOverride = path
}

// SetVolumeAlias makes every volume path the double resolves use name under
// VolRoot instead of the passed sandfs id — how a test models two creates
// whose derived on-disk names coincide (the 32-bit id space handing the same
// id out twice, so the seed-derived directory name is the same).
func (o *Ops) SetVolumeAlias(name string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.volumeAlias = name
}

// volPathLocked resolves the volume directory (caller holds o.mu).
func (o *Ops) volPathLocked(sandfsID string) string {
	if o.volumeAlias != "" {
		return filepath.Join(o.VolRoot, o.volumeAlias)
	}
	return filepath.Join(o.VolRoot, sandfsID)
}

func (o *Ops) EnsureVolume(_ context.Context, sandfsID, mode, templateRef string, volumeEpoch ...string) (*storage.EnsureResult, error) {
	// Outside the lock: the hook is test code and must be free to touch the
	// filesystem (or the double) without deadlocking.
	if o.BeforeEnsure != nil {
		o.BeforeEnsure(sandfsID)
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.Ensured = append(o.Ensured, sandfsID)
	if err := o.ensureErr[sandfsID]; err != nil {
		return nil, err
	}
	if o.rootfsPathOverride != "" {
		return o.minResultLocked(&storage.EnsureResult{RootfsPath: o.rootfsPathOverride, Pulled: o.ensurePulled}), nil
	}
	vol := o.volPathLocked(sandfsID)
	if err := os.MkdirAll(vol, 0o770); err != nil {
		return nil, err
	}
	if mode == "overlay" {
		for _, d := range []string{"workspace", "home", "rootfs"} {
			if err := os.MkdirAll(filepath.Join(vol, d), 0o770); err != nil {
				return nil, err
			}
		}
		_ = os.WriteFile(filepath.Join(vol, ".template"), []byte(templateRef), 0o644)
	}
	return o.minResultLocked(&storage.EnsureResult{RootfsPath: vol, Pulled: o.ensurePulled}), nil
}

func (o *Ops) DeleteVolume(sandfsID string) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.Deleted = append(o.Deleted, sandfsID)
	return os.RemoveAll(o.volPathLocked(sandfsID))
}

// VerifyVolume models the node's READ-ONLY identity check behind the
// rootfs-path repoint endpoint: the directory must exist and be the one this
// id resolves to. The real stamp semantics (.sandfs-id content, symlink and
// partial-run refusals) live node-side and are tested in
// sandlot/provision/volume; the double keeps the identity BINDING, which is
// what the endpoint's handler must depend on.
func (o *Ops) VerifyVolume(_ context.Context, sandfsID, rootfsPath string) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	want := o.volPathLocked(sandfsID)
	if filepath.Clean(rootfsPath) != filepath.Clean(want) {
		return &NodeError{Code: "VOLUME_IDENTITY_MISMATCH", Msg: fmt.Sprintf("storagetest: %s is not %s's volume (want %s)", rootfsPath, sandfsID, want)}
	}
	info, err := os.Lstat(want)
	if err != nil || !info.IsDir() {
		return &NodeError{Code: "VOLUME_IDENTITY_MISMATCH", Msg: fmt.Sprintf("storagetest: %s does not exist as a directory", want)}
	}
	return nil
}

// NodeError is a node-side business failure with the wire error_code — the
// double's stand-in for the rpc implementation's nodeError (which is
// unexported). Callers detect it via storage.NodeErrorCode.
type NodeError struct {
	Code string
	Msg  string
}

func (e *NodeError) Error() string { return e.Code + ": " + e.Msg }

// ErrorCode makes storage.NodeErrorCode recognize the double's failures with
// the same mapping production errors go through.
func (e *NodeError) ErrorCode() string { return e.Code }

func (o *Ops) PullTemplate(_ context.Context, ref, _ string) (*storage.PullResult, error) {
	return nil, fmt.Errorf("storagetest: pull not supported (%s)", ref)
}

func (o *Ops) PushTemplate(_ context.Context, ref, _ string) (*storage.PushResult, error) {
	return nil, fmt.Errorf("storagetest: push not supported (%s)", ref)
}

func (o *Ops) SaveAsTemplate(sandfsID string, req storage.SaveAsRequest) (*storage.SaveResult, error) {
	return nil, fmt.Errorf("storagetest: save not supported (%s→%s)", sandfsID, req.TemplateRef)
}

// SetTemplates primes the ListTemplates view.
func (o *Ops) SetTemplates(list []storage.TemplateInfo) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.templates = list
}

func (o *Ops) ListTemplates() []storage.TemplateInfo {
	o.mu.Lock()
	defer o.mu.Unlock()
	out := make([]storage.TemplateInfo, len(o.templates))
	copy(out, o.templates)
	return out
}

// DetectTemplateMode reports "flat" for every ref ending in ":v1", else "" —
// enough for the push-auto-detect handler tests.
func (o *Ops) DetectTemplateMode(ref string) string {
	if filepath.Ext(ref) != "" || len(ref) > 3 && ref[len(ref)-3:] == ":v1" {
		return "flat"
	}
	return ""
}

// SwapTemplate mirrors the node-side marker rewrite: verifies the volume is
// an overlay volume with a marker, applies the home policy, rewrites the
// marker. Idempotent per (ref, policy).
func (o *Ops) SwapTemplate(_ context.Context, sandfsID, templateRef, homePolicy string) (*storage.EnsureResult, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	vol := o.volPathLocked(sandfsID)
	marker := filepath.Join(vol, ".template")
	cur, err := os.ReadFile(marker)
	if err != nil {
		return nil, fmt.Errorf("storagetest: %s is not an overlay volume (no .template marker)", sandfsID)
	}
	if string(cur) == templateRef {
		return o.minResultLocked(&storage.EnsureResult{RootfsPath: vol}), nil // idempotent
	}
	switch homePolicy {
	case "", storage.HomeKeep:
	case storage.HomeReset:
		if err := os.RemoveAll(filepath.Join(vol, "home")); err != nil {
			return nil, err
		}
		if err := os.MkdirAll(filepath.Join(vol, "home"), 0o770); err != nil {
			return nil, err
		}
	case storage.HomeArchive:
		home := filepath.Join(vol, "home")
		if err := os.Rename(home, home+".pre-attach-test"); err != nil && !os.IsNotExist(err) {
			return nil, err
		}
		if err := os.MkdirAll(home, 0o770); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("storagetest: unknown home policy %q", homePolicy)
	}
	if err := os.WriteFile(marker, []byte(templateRef), 0o644); err != nil {
		return nil, err
	}
	return o.minResultLocked(&storage.EnsureResult{RootfsPath: vol, Pulled: o.ensurePulled}), nil
}

// DeleteTemplate refuses when a tracked volume's marker still names the ref.
func (o *Ops) DeleteTemplate(_ context.Context, templateRef, mode string, force bool) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if !force && mode != "flat" {
		entries, err := os.ReadDir(o.VolRoot)
		if err != nil {
			return nil // no volumes at all
		}
		var sample []string
		count := 0
		for _, e := range entries {
			cur, err := os.ReadFile(filepath.Join(o.VolRoot, e.Name(), ".template"))
			if err == nil && string(cur) == templateRef {
				count++
				if len(sample) < 10 {
					sample = append(sample, e.Name())
				}
			}
		}
		if count > 0 {
			return &storage.TemplateInUseError{Count: count, Sample: sample}
		}
	}
	return nil
}

func (o *Ops) Mode() string { return "storagetest" }

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

// Package storage is the gateway's ONLY view of the storage plane — and it
// is FULLY gateway-local: the types below are defined here, not borrowed from
// the node-side provision code, so the gateway module carries no dependency
// on the sandlot module at all. Every sandfs-volume and template operation
// goes through the Ops interface; the sole implementation is the RPC one
// (ProvisionCommands over the node stream to prov-role instances). A nil Ops
// means the storage plane is unavailable: handlers surface a named 503,
// never a silent fallback. The gateway host mounts NO shared storage.
package storage

import (
	"context"
	"fmt"
)

// Ops is the storage-plane seam. All operations are idempotent; all
// arguments are validated AGAIN on the executing node (the node never trusts
// the gateway's strings).
type Ops interface {
	// EnsureVolume idempotently materializes sandfsID's volume from
	// templateRef in the given mode, returning the volume path and the
	// template's declared minimum resources.
	EnsureVolume(ctx context.Context, sandfsID, mode, templateRef string, volumeEpoch ...string) (*EnsureResult, error)
	// DeleteVolume removes the volume directory (ENOENT = success).
	DeleteVolume(sandfsID string) error
	// VerifyVolume proves the caller-supplied directory is sandfsID's volume
	// (contained under the node's volumes root + an exact .sandfs-id stamp
	// match). READ-ONLY: nothing is created or modified — this is the
	// identity gate behind the rootfs-path repoint endpoint, whose whole
	// purpose is to accept a path a rotation MOVED a volume to. A refusal
	// returns a node business error whose NodeErrorCode(err) is
	// "VOLUME_IDENTITY_MISMATCH" (the directory is missing, unstamped,
	// mid-provisioning, a symlink, or stamped for another sandfs).
	VerifyVolume(ctx context.Context, sandfsID, rootfsPath string) error

	// PullTemplate pulls a ref from the OCI registry into the executing
	// node's template store (mode "flat"|"overlay"; empty = overlay).
	PullTemplate(ctx context.Context, templateRef, mode string) (*PullResult, error)
	// PushTemplate pushes a stored ref to the OCI registry.
	PushTemplate(ctx context.Context, templateRef, mode string) (*PushResult, error)
	// SaveAsTemplate snapshots a flat sandfs into a local template.
	SaveAsTemplate(sandfsID string, req SaveAsRequest) (*SaveResult, error)
	// ListTemplates enumerates the executing node's template store.
	ListTemplates() []TemplateInfo
	// DetectTemplateMode returns "overlay" or "flat" for an existing ref
	// (overlay preferred), "" when neither exists.
	DetectTemplateMode(templateRef string) string
	// SwapTemplate re-points a DETACHED overlay sandfs's volume at a new
	// read-only template (marker rewrite + /home policy). homePolicy:
	// "keep" | "archive" | "reset". Returns the new template's declared min
	// resources (the record-update input). The caller must have verified the
	// record status is "detached" before issuing this.
	SwapTemplate(ctx context.Context, sandfsID, templateRef, homePolicy string) (*EnsureResult, error)
	// DeleteTemplate removes a template ref and its then-unreferenced layers.
	// mode "flat"|"overlay"; empty = auto-detect. Returns *TemplateInUseError
	// when overlay volumes still reference the ref (unless force).
	DeleteTemplate(ctx context.Context, templateRef, mode string, force bool) error
	// Mode names the implementation for logs and /stats ("rpc").
	Mode() string
}

// EnsureResult carries everything a sandfs creation needs from the storage
// plane in ONE round trip: the volume path, the template's declared minimum
// resources (the create-time sizing input), and whether the op auto-pulled
// the ref from the OCI registry (the create response's pull_status).
type EnsureResult struct {
	RootfsPath  string
	MinVCPUs    uint32
	MinMemoryMB uint64
	MinOK       bool
	Pulled      bool
}

// PullResult is the display identity of a pulled template (the gateway's HTTP
// response surfaces these verbatim; the full manifest stays node-side).
type PullResult struct {
	Name    string
	Version string
}

// PushResult is the registry-push outcome.
type PushResult struct {
	TemplateRef string
	Digest      string
	Layers      []string
	Size        int64
	PushTimeMs  int64
}

// SaveAsRequest is the volume→template snapshot request.
type SaveAsRequest struct {
	TemplateRef string
	Description string
	VCPUs       uint32 // 0 = source sandfs's value
	MemoryMB    uint64 // 0 = source sandfs's value
}

// SaveResult is the snapshot outcome (the local template path on the node).
type SaveResult struct {
	TemplateRef string
	Path        string
	SizeKB      int64
}

// TemplateInfo is one local template (one mode of one ref) — the neutral
// listing shape.
type TemplateInfo struct {
	Name        string
	Version     string
	Description string
	Mode        string
	MinVCPUs    uint32
	MinMemoryMB uint64
}

// HomePolicy values for SwapTemplate.
const (
	HomeKeep    = "keep"    // /home/agent content carries over (default)
	HomeArchive = "archive" // rename to home.pre-attach-<ts>; fresh empty home
	HomeReset   = "reset"   // wipe + recreate
)

// TemplateInUseError is DeleteTemplate's structured refusal: overlay volumes
// still name the ref in their .template marker. Carries the count and a
// sample of sandfs ids for the HTTP 409 payload.
type TemplateInUseError struct {
	Count  int
	Sample []string
}

func (e *TemplateInUseError) Error() string {
	return fmt.Sprintf("template in use by %d sandfs (e.g. %v)", e.Count, e.Sample)
}

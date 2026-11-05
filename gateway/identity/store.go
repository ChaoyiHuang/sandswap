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
// Package identity defines the store interface for Agent and SandFS identity
// records. It abstracts over in-memory maps (single-node) and
// etcd-backed storage (multi-node) so the execution hot path (ResolveAgent)
// has the same code path regardless of deployment topology.
// Identity model:
//	Agent (API key, connection-level auth) → owns → SandFS (sandfs_id, request-level addressing)
// The Agent API key authenticates the connection. The sandfs_id in the request
// body selects which sandbox to operate on. ResolveFromRequest performs both
// steps and verifies the agent owns the requested sandfs.

package identity

import (
	"errors"
	"fmt"
	"regexp"
	"time"
	"unicode/utf8"
)

// ErrSandFSNotFound is the sentinel for a missing sandfs record. Callers must
// distinguish it from a store failure: a delete may proceed against a record
// that is genuinely gone (the volume cleanup still runs), but an etcd outage
// must never degrade into "the record is missing, delete the volume anyway".
var ErrSandFSNotFound = errors.New("sandfs not found")

// Agent represents an AI agent caller with a connection-level API key.
// An agent owns one or more SandFS instances.
//
// API key handling: only the SHA-256 hex digest of the key is persisted
// (etcd value) and indexed in memory; the plaintext exists solely at
// CreateAgent time when it is returned to the operator exactly once.
// Agents loaded from etcd (created by another gateway) have an empty
// APIKey and a populated APIKeyHash — resolution compares digests only.
type Agent struct {
	ID          string    `json:"agent_id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"` // ≤200 runes, human-facing
	APIKey      string    `json:"-"`                     // plaintext sk-sandswap-agent-xxx; empty unless created by this process
	APIKeyHash  string    `json:"-"`                     // sha256 hex of the plaintext; always populated
	CreatedAt   time.Time `json:"created_at"`
	// Namespace is the human-API tenancy dimension. It is assigned at
	// creation from the /human/ns/{ns}/agent path (or "default" on the
	// unscoped admin surface), immutable for the agent's lifetime, and
	// inherited by every SandFS the agent owns. The namespace registry is
	// IMPLICIT: no namespace object exists anywhere in the system — the IdP's
	// sandswap_ns claim is the authority for who may act in a namespace, and
	// records merely carry the name (see docs/how-it-works/namespaces.md).
	// Empty = pre-namespace legacy data, normalized to "default" on read
	// (NamespaceOrDefault); new writes always set it explicitly.
	Namespace string `json:"namespace,omitempty"`
}

// cloneAgent returns a shallow copy of an Agent so callers receive a private
// value they cannot mutate through to the cached record (Agent has only
// value-type fields, so a shallow copy is a complete copy). Mirrors the Record
// copy convention used by the listing/read paths.
func cloneAgent(a *Agent) *Agent {
	if a == nil {
		return nil
	}
	cp := *a
	return &cp
}

// MaxDescriptionRunes is the shared description limit for Agent and SandFS
// records. It is a character (rune) limit, not a byte limit.
const MaxDescriptionRunes = 200

// ValidateDescription enforces the shared 200-rune, valid-UTF-8 rule.
func ValidateDescription(desc string) error {
	if !utf8.ValidString(desc) {
		return fmt.Errorf("description is not valid UTF-8")
	}
	if utf8.RuneCountInString(desc) > MaxDescriptionRunes {
		return fmt.Errorf("description exceeds %d characters", MaxDescriptionRunes)
	}
	return nil
}

// Record represents a SandFS identity and its storage mapping.
// This is the read-only view used by the execution gateway on the /agent/execute
// hot path. The human service has additional write methods.
type Record struct {
	ID          string `json:"sandfs_id"`
	AgentID     string `json:"agent_id"` // owner agent
	Name        string `json:"name"`
	Description string `json:"description"` // ≤200 chars, for agent discovery (set at creation by human)
	RootFSPath  string `json:"rootfs_path"` // rootfs path for warden bind mount
	// VolumeEpoch is the random per-create volume identity. It rides the hot
	// record and the signed stamp so a stale record for a reused sandfs id
	// cannot mount a newer owner's volume.
	VolumeEpoch string    `json:"volume_epoch,omitempty"`
	Template    string    `json:"template"`                // template ref (e.g., "mysql:v1")
	Mode        string    `json:"mode,omitempty"`          // "flat" | "overlay"; determines how template is consumed
	MinVCPUs    uint32    `json:"min_vcpus,omitempty"`     // minimum vCPUs; 0 = no requirement
	MinMemoryMB uint64    `json:"min_memory_mb,omitempty"` // minimum memory MB; 0 = no requirement
	CreatedAt   time.Time `json:"created_at"`
	// Status is the lifecycle gate for the execution hot path (checked as a
	// plain struct-field comparison — never a network call):
	//   "" (active)      — normal serving
	//   "detaching"      — template swap initiated: new execs/file ops refused
	//                      (409 SANDFS_NOT_ACTIVE); the mount holder drains
	//   "detached"       — mounts provably released cluster-wide; the only
	//                      state an attach-template accepts
	//   "deleting"       — sandfs deletion initiated: same exec gate; the
	//                      drain's settle signal is the shared "detached",
	//                      after which the terminal volume/record/ownership
	//                      deletion proceeds
	// Both "detaching" and "deleting" are drain TRIGGERS: the gateway holding
	// the sandfs's mounts (inline when it owns the pool, or via the identity
	// watch on split deployments) runs the drain and writes "detached".
	Status string `json:"status,omitempty"`
	// Namespace is the owning agent's namespace, frozen at creation (the
	// agent's namespace is immutable, so the pair can never diverge). It
	// rides the HOT record, not the display meta: the human gateway's
	// watch-fed full-fleet cache is the view per-namespace listing and the
	// uniform-404 namespace check read, and that cache is built from hot
	// records only (the same reasoning that put Status here). The exec
	// plane ignores it entirely.
	Namespace string `json:"namespace,omitempty"`
}

// DefaultNamespace is the namespace of records created before namespaces
// existed (empty field) and of agents created through the unscoped admin
// surface. Reads normalize an empty Namespace to this value; a tenant
// operator granted "default" sees legacy records exactly like explicit ones.
const DefaultNamespace = "default"

// namespacePattern is the shared name grammar: a DNS-label-like segment —
// lowercase letter first, letters/digits/hyphens inside, letter or digit
// last, max 63 chars (no leading/trailing hyphen, exactly like a DNS label).
// Strict lowercase keeps path routing case-insensitive-by-construction (no
// case-folding disputes between IdP claims and URL paths).
var namespacePattern = regexp.MustCompile(`^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$`)

// ValidNamespace reports whether ns is a legal namespace name. The wildcard
// "*" is NOT a valid namespace — it exists only inside the OIDC claim set.
func ValidNamespace(ns string) bool {
	return namespacePattern.MatchString(ns)
}

// NamespaceOrDefault normalizes a record's namespace for comparison: legacy
// rows written before the field existed read as "default".
func (a *Agent) NamespaceOrDefault() string {
	if a.Namespace == "" {
		return DefaultNamespace
	}
	return a.Namespace
}

// NamespaceOrDefault is the Record twin of Agent.NamespaceOrDefault.
func (r *Record) NamespaceOrDefault() string {
	if r.Namespace == "" {
		return DefaultNamespace
	}
	return r.Namespace
}

// NamespaceLister is the optional per-namespace listing view. Both real
// stores implement it by filtering their watch-fed cache; a custom store
// without it falls back to the full list + in-memory filter (same contract,
// only viable at small scale — the same split PagedLister makes).
type NamespaceLister interface {
	// GetAgent returns an Agent by ID (the same cold-path view method
	// PagedLister carries; duplicated here so the namespace surface needs
	// only one optional-interface assertion).
	GetAgent(agentID string) (*Agent, error)
	// ListAgentsInNamespace returns clones of every agent whose normalized
	// namespace equals ns, unsorted.
	ListAgentsInNamespace(ns string) []*Agent
	// ListSandFSInNamespace returns clones of every sandfs whose normalized
	// namespace equals ns, unsorted.
	ListSandFSInNamespace(ns string) []*Record
}

// SandFS lifecycle statuses (Record.Status). See the Record doc for semantics.
const (
	SandfsStatusDetaching = "detaching"
	SandfsStatusDetached  = "detached"
	SandfsStatusDeleting  = "deleting"
)

// IsActive reports whether the sandfs accepts executions and file operations.
// A single struct-field check on the hot path — the record is already read
// from the local cache during request resolution.
func (r *Record) IsActive() bool {
	return r.Status == ""
}

// UsesOverlayFS returns true if this sandfs uses OverlayFS (overlay-mode template).
// Flat-mode SandFS (template set but mode=flat) return false — they use bind-mount.
func (r *Record) UsesOverlayFS() bool {
	return r.Template != "" && r.Mode != "flat"
}

// AllowsPackageInstall reports whether OS package installation is permitted in
// this sandfs. Derived from mode: flat mode retains ambient caps so apt/dpkg
// work; overlay mode drops all caps (maximum isolation). Not stored per-record.
func (r *Record) AllowsPackageInstall() bool {
	return r.Mode == "flat"
}

// Store is the interface for Agent and SandFS authentication and metadata.
// Two implementations exist:
//   - MemoryStore: in-process maps, zero external dependencies (single-node)
//   - EtcdStore: etcd-backed with local cache + watch sync (multi-node)
//
// Both implementations share the same ResolveAgent/GetSandFS code paths on the
// /agent/execute hot path, ensuring identical latency characteristics.
type Store interface {
	// ── Agent auth (connection-level) ──────────────────────────────

	// ResolveAgent validates an Agent API key and returns the Agent.
	// This is on the /agent/execute hot path and MUST be a local in-memory
	// lookup — no network calls.
	ResolveAgent(apiKey string) (*Agent, error)

	// ── SandFS operations (request-level) ──────────────────────────

	// GetSandFS returns a Record by sandfs ID. Also on the hot path.
	GetSandFS(sandfsID string) (*Record, error)

	// ListSandFSByAgent returns all SandFS records owned by an agent.
	// Used by the agent discovery endpoint (GET /agent/sandfs).
	ListSandFSByAgent(agentID string) ([]*Record, error)

	// ── Agent CRUD (human interface) ───────────────────────────────

	// CreateAgent creates a new Agent with a unique ID and API key.
	// Returns the agent and the plaintext API key (returned exactly once).
	CreateAgent(req CreateAgentRequest) (*Agent, string, error)

	// DeleteAgent removes an Agent and all its SandFS records.
	DeleteAgent(agentID string) error

	// ListAgents returns all Agent records.
	ListAgents() ([]*Agent, error)

	// ── SandFS CRUD (human interface) ──────────────────────────────

	// CreateSandFS creates a new SandFS owned by the specified agent.
	// Returns the record (no per-sandfs API key — auth is via the agent's key).
	CreateSandFS(agentID string, req CreateSandFSRequest) (*Record, error)

	// DeleteSandFS removes a SandFS.
	DeleteSandFS(sandfsID string) error

	// ListAllSandFS returns all SandFS records (operator view).
	ListAllSandFS() ([]*Record, error)

	// ── Field setters (called by Registry after volume creation) ───

	// SetRootFSPath sets the RootFSPath on an existing record.
	SetRootFSPath(sandfsID, rootfsPath string) error

	// SetMinResources sets the minimum vCPUs/memory on an existing record.
	SetMinResources(sandfsID string, vcpus uint32, memMB uint64) error

	// ── Lifecycle (template swap + delete orchestration) ───────────

	// SetSandfsStatus writes the lifecycle status on an existing record
	// ("detaching" | "detached" | "deleting"; "" = active). The status is the
	// execution gate AND the drain trigger — see Record.Status.
	SetSandfsStatus(sandfsID, status string) error

	// UpdateSandfsTemplate completes a template attach in ONE record write:
	// new template ref, the new template's declared min resources, and status
	// back to active. Single-write so a concurrent reader never observes the
	// new template with a non-active status (or vice versa).
	UpdateSandfsTemplate(sandfsID, templateRef string, vcpus uint32, memMB uint64) error

	// CountSandFSByTemplate counts records whose Template equals templateRef
	// and Mode is overlay (overlay volumes carry a runtime dependency on the
	// template's layers; flat volumes copied content at creation and do not).
	// Returns the count plus a bounded sample of sandfs ids (the
	// TEMPLATE_IN_USE refusal payload). Scans the local cache — no etcd reads.
	CountSandFSByTemplate(templateRef string) (count int, sample []string)
}

// PagedLister is the COLD-PATH pagination view over the identity store,
// deliberately separate from Store: the hot-path contract (ResolveAgent /
// GetSandFS / ListSandFSByAgent — all an agent's execution and discovery ever
// need) stays minimal, while the human gateway's fleet-wide list endpoints
// (GET /human/sandfs, /human/agent) page by ID without materializing every
// record per page (at a million records that is hundreds of MB of transient
// clones per call otherwise). Both MemoryStore and EtcdStore implement it;
// consumers type-assert their Store and fall back to the full-list Store
// methods when a custom implementation lacks it.
type PagedLister interface {
	// GetAgent returns an Agent by ID.
	GetAgent(agentID string) (*Agent, error)
	// ListAgentIDs returns all agent IDs, unsorted.
	ListAgentIDs() []string
	// ListSandFSIDs returns all sandfs IDs, unsorted.
	ListSandFSIDs() []string
}

// CreateAgentRequest is the request to create a new Agent.
type CreateAgentRequest struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	// Namespace stamps the new agent's namespace. Empty means DefaultNamespace
	// (the unscoped admin surface); the namespaced handler always sets it from
	// the path. Validated by the store: an invalid name is a caller bug, not
	// a data shape, so both stores refuse it.
	Namespace string `json:"namespace,omitempty"`
}

// CreateSandFSRequest is the request to create a new SandFS.
type CreateSandFSRequest struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"` // ≤200 chars, for agent discovery
	Template    string `json:"template,omitempty"`    // Template reference (e.g., "mysql:v1")
	Mode        string `json:"mode,omitempty"`        // "flat" | "overlay" (required)
	VCPUs       uint32 `json:"vcpus,omitempty"`       // minimum vCPUs; overrides the template default
	MemoryMB    uint64 `json:"memory_mb,omitempty"`   // minimum memory MB; overrides the template default
	VolumeEpoch string `json:"volume_epoch,omitempty"`
}

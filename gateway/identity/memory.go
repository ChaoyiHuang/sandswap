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
	"crypto/subtle"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"common/util"
)

// MemoryStore implements Store with in-process maps.
// Used in single-node deployments where the gateway runs as a single process
// with no external state store. All operations are local in-memory lookups.
//
// Like the etcd store, agents are indexed by API key DIGEST only — the
// plaintext exists solely in the value returned by CreateAgent. When a
// snapshotPath is configured (NewPersistentMemoryStore), every successful
// mutation rewrites the full snapshot file (identity_store.go); with no path,
// persistence is inert and the store behaves as before.
type MemoryStore struct {
	mu              sync.RWMutex
	agents          map[string]*Agent   // agentID → agent
	agentApiKeyToID map[string]string   // api_key_hash (sha256 hex) → agentID
	sandfs          map[string]*Record  // sandfsID → record
	sandfsByAgent   map[string][]string // agentID → []sandfsID (reverse index for O(1) ListSandFSByAgent)
	volRoot         string              // shared storage mount point
	// tombstones remembers deleted sandfs ids for TombstoneTTL so a
	// 32-bit id redraw cannot immediately resurrect a name whose old record
	// may still sit in a lagging gateway's watch cache.
	tombstones map[string]time.Time

	// Persistence state, written once by NewPersistentMemoryStore before the
	// store is shared with any goroutine; snapshotPath is also read under
	// s.mu by the persist hooks. snapshotPath == "" disables persistence.
	snapshotPath string
	logger       *slog.Logger
	lockFile     *os.File // <snapshotPath>.lock, held open for the process lifetime
}

// NewMemoryStore creates a new in-memory store implementing identity.Store
// (agents + sandfs records, single-node).
func NewMemoryStore(volRoot string) *MemoryStore {
	return &MemoryStore{
		agents:          make(map[string]*Agent),
		agentApiKeyToID: make(map[string]string),
		sandfs:          make(map[string]*Record),
		sandfsByAgent:   make(map[string][]string),
		volRoot:         volRoot,
		tombstones:      make(map[string]time.Time),
	}
}

// ── Agent auth (connection-level) ──────────────────────────────

// ResolveAgent validates an Agent API key and returns the Agent.
// Hot path: one sha256 + local in-memory map lookup + constant-time digest
// compare — the same resolution pattern as the etcd store.
func (s *MemoryStore) ResolveAgent(apiKey string) (*Agent, error) {
	if apiKey == "" {
		return nil, fmt.Errorf("invalid api key")
	}
	hash := hashAPIKey(apiKey)

	s.mu.RLock()
	defer s.mu.RUnlock()

	agentID, ok := s.agentApiKeyToID[hash]
	if !ok {
		return nil, fmt.Errorf("invalid api key")
	}
	agent := s.agents[agentID]
	if agent == nil {
		return nil, fmt.Errorf("invalid api key")
	}
	if subtle.ConstantTimeCompare([]byte(hash), []byte(agent.APIKeyHash)) != 1 {
		return nil, fmt.Errorf("invalid api key")
	}
	return cloneAgent(agent), nil
}

// ── SandFS operations (request-level) ──────────────────────────

// GetSandFS returns a Record by sandfs ID.
//
// The returned record is a PRIVATE COPY. It used to be the store-owned object
// (a hot-path allocation saving), but writers mutate that same object IN PLACE
// under the store lock while readers kept using it after the lock was released
// — an unsynchronized read of a field another goroutine was writing (the race
// detector's exact shape, and real torn reads for the lifecycle status).
// Readers now get a snapshot; the asymmetry with EtcdStore's merged copy is
// gone.
func (s *MemoryStore) GetSandFS(sandfsID string) (*Record, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rec, ok := s.sandfs[sandfsID]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrSandFSNotFound, sandfsID)
	}
	cp := *rec // deep copy: Record is all value types
	return &cp, nil
}

// ListSandFSByAgent returns all SandFS records owned by an agent.
// Uses the sandfsByAgent reverse index for O(1) lookup.
func (s *MemoryStore) ListSandFSByAgent(agentID string) ([]*Record, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	ids, ok := s.sandfsByAgent[agentID]
	if !ok {
		return nil, nil
	}
	recs := make([]*Record, 0, len(ids))
	for _, id := range ids {
		if rec, ok := s.sandfs[id]; ok {
			cp := *rec // deep copy: Record is all value types
			recs = append(recs, &cp)
		}
	}
	return recs, nil
}

// ── Agent CRUD (human interface) ───────────────────────────────

// newPublicID generates an opaque public id with a 32-bit random suffix
// (8 hex chars). The WIDTH IS AN EGRESS-CONTRACT CONSTRAINT, not an
// arbitrary choice: the routed-IPv6 identity template embeds the id's 8-hex
// suffix VERBATIM in a 32-bit IID field (sandlot/network/iid.go
// idFieldBits rejects anything longer), so a longer suffix would make
// Build() fail and degrade every mount to unstamped egress. Uniqueness is
// preserved by regenerate-on-collision (the atomic claim in EtcdStore and
// the exists() loop here).
func newPublicID(prefix string, exists func(id string) bool) (string, error) {
	for attempt := 0; attempt < 8; attempt++ {
		id := prefix + uuid.New().String()[:8]
		if !exists(id) {
			return id, nil
		}
	}
	return "", fmt.Errorf("id collision persisted after 8 draws (%s*)", prefix)
}

// CreateAgent creates a new Agent with a unique ID and API key.
// Returns the agent and the plaintext API key (returned exactly once).
// The stored record carries only the digest — like the etcd store, the
// plaintext never outlives this call.
func (s *MemoryStore) CreateAgent(req CreateAgentRequest) (*Agent, string, error) {
	desc := strings.TrimSpace(req.Description)
	if err := ValidateDescription(desc); err != nil {
		return nil, "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	id, err := newPublicID("agent-", func(id string) bool {
		_, ok := s.agents[id]
		return ok
	})
	if err != nil {
		return nil, "", err
	}
	key := "sk-sandswap-agent-" + randomHex(32)
	keyHash := hashAPIKey(key)
	// 256-bit random: a collision is a 2^-256 event, so a loud error (not a
	// regenerate loop) is the right response — the etcd store's Txn checks
	// the same condition atomically.
	if _, taken := s.agentApiKeyToID[keyHash]; taken {
		return nil, "", fmt.Errorf("api key collision (2^-256 event)")
	}

	ns := req.Namespace
	if ns == "" {
		ns = DefaultNamespace
	}
	if !ValidNamespace(ns) {
		return nil, "", fmt.Errorf("invalid namespace: %q", ns)
	}

	agent := &Agent{
		ID:          id,
		Name:        req.Name,
		Description: desc,
		APIKeyHash:  keyHash,
		CreatedAt:   time.Now(),
		Namespace:   ns,
	}

	s.agents[id] = agent
	s.agentApiKeyToID[keyHash] = id
	s.persistLocked()

	// Hand back a private copy carrying the plaintext exactly once; the map
	// record stays digest-only.
	out := cloneAgent(agent)
	out.APIKey = key
	return out, key, nil
}

// DeleteAgent removes an Agent and all its SandFS records.
func (s *MemoryStore) DeleteAgent(agentID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	agent, ok := s.agents[agentID]
	if !ok {
		return fmt.Errorf("agent not found: %s", agentID)
	}

	// Remove all sandfs owned by this agent
	for _, rec := range s.sandfs {
		if rec.AgentID == agentID {
			delete(s.sandfs, rec.ID)
			// Tombstone every batch-deleted id (same TTL as the single delete):
			// a 32-bit id redraw must not immediately reuse an id whose old
			// record may still sit in a lagging gateway's watch cache.
			s.tombstones[rec.ID] = time.Now()
		}
	}
	delete(s.sandfsByAgent, agentID)

	// The index is keyed by digest; the hash comes off the fetched record.
	if agent.APIKeyHash != "" {
		delete(s.agentApiKeyToID, agent.APIKeyHash)
	}
	delete(s.agents, agentID)
	s.persistLocked()

	return nil
}

// ListAgents returns all Agent records.
func (s *MemoryStore) ListAgents() ([]*Agent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	agents := make([]*Agent, 0, len(s.agents))
	for _, agent := range s.agents {
		agents = append(agents, cloneAgent(agent))
	}
	return agents, nil
}

// GetAgent returns an Agent by ID (cold path: human list pagination).
func (s *MemoryStore) GetAgent(agentID string) (*Agent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	agent, ok := s.agents[agentID]
	if !ok || agent == nil {
		return nil, fmt.Errorf("agent not found: %s", agentID)
	}
	return cloneAgent(agent), nil
}

// ListAgentIDs returns all agent IDs, unsorted (pagination support).
func (s *MemoryStore) ListAgentIDs() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ids := make([]string, 0, len(s.agents))
	for id := range s.agents {
		ids = append(ids, id)
	}
	return ids
}

// ListSandFSIDs returns all sandfs IDs, unsorted (pagination support).
func (s *MemoryStore) ListSandFSIDs() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ids := make([]string, 0, len(s.sandfs))
	for id := range s.sandfs {
		ids = append(ids, id)
	}
	return ids
}

// ── Namespace listing (human-API tenancy) ────────────────────

// ListAgentsInNamespace returns clones of every agent in ns (normalized
// comparison — legacy empty reads as DefaultNamespace).
func (s *MemoryStore) ListAgentsInNamespace(ns string) []*Agent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Agent, 0)
	for _, a := range s.agents {
		if a.NamespaceOrDefault() == ns {
			out = append(out, cloneAgent(a))
		}
	}
	return out
}

// ListSandFSInNamespace returns clones of every sandfs in ns.
func (s *MemoryStore) ListSandFSInNamespace(ns string) []*Record {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Record, 0)
	for _, r := range s.sandfs {
		if r.NamespaceOrDefault() == ns {
			cp := *r // deep copy: Record is all value types
			out = append(out, &cp)
		}
	}
	return out
}

// ── SandFS CRUD (human interface) ──────────────────────────────

// CreateSandFS creates a new SandFS owned by the specified agent.
// No per-sandfs API key — auth is via the agent's API key.
func (s *MemoryStore) CreateSandFS(agentID string, req CreateSandFSRequest) (*Record, error) {
	req.Description = strings.TrimSpace(req.Description)
	if err := ValidateDescription(req.Description); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	// Verify agent exists; the sandfs inherits the agent's namespace
	// (immutable pairing — same rule as the etcd store, and the request
	// carries no namespace so the pair cannot disagree).
	agent, ok := s.agents[agentID]
	if !ok {
		return nil, fmt.Errorf("agent not found: %s", agentID)
	}

	// Regenerate on collision (see newPublicID): a duplicate ID would
	// silently replace the previous sandfs record.
	id, err := newPublicID("sandfs-", func(id string) bool {
		if _, ok := s.sandfs[id]; ok {
			return true
		}
		if t, ok := s.tombstones[id]; ok {
			if time.Since(t) < TombstoneTTL() {
				return true
			}
			delete(s.tombstones, id)
		}
		return false
	})
	if err != nil {
		return nil, err
	}

	rec := &Record{
		ID:          id,
		AgentID:     agentID,
		Name:        req.Name,
		Description: req.Description,
		Template:    req.Template,
		Mode:        req.Mode,
		VolumeEpoch: req.VolumeEpoch,
		CreatedAt:   time.Now(),
		Namespace:   agent.Namespace,
		// RootFSPath is set by the caller (Registry) after volume creation.
	}

	s.sandfs[id] = rec
	s.sandfsByAgent[agentID] = append(s.sandfsByAgent[agentID], id)
	s.persistLocked()

	// Return the store-owned object deliberately: the create caller (registry)
	// fills RootFSPath/min-resources through the store methods right after this
	// returns and expects to observe them on `rec`. Readers cannot alias it —
	// GetSandFS/list paths hand out copies.
	return rec, nil
}

// DeleteSandFS removes a SandFS.
func (s *MemoryStore) DeleteSandFS(sandfsID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, ok := s.sandfs[sandfsID]
	if !ok {
		return fmt.Errorf("%w: %s", ErrSandFSNotFound, sandfsID)
	}

	delete(s.sandfs, sandfsID)
	s.tombstones[sandfsID] = time.Now()
	// Remove from sandfsByAgent reverse index.
	if ids, ok := s.sandfsByAgent[rec.AgentID]; ok {
		for i, id := range ids {
			if id == sandfsID {
				s.sandfsByAgent[rec.AgentID] = append(ids[:i], ids[i+1:]...)
				break
			}
		}
	}
	s.persistLocked()
	return nil
}

// ListAllSandFS returns all SandFS records (operator view).
func (s *MemoryStore) ListAllSandFS() ([]*Record, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	recs := make([]*Record, 0, len(s.sandfs))
	for _, rec := range s.sandfs {
		cp := *rec // deep copy: Record is all value types
		recs = append(recs, &cp)
	}
	return recs, nil
}

// ── Field setters ──────────────────────────────────────────────

// Setters mutate the store-owned record IN PLACE under the write lock. Readers
// never observe that mutation: every read path (GetSandFS, ListSandFSByAgent,
// ListAllSandFS, the namespace lists) hands out a copy taken under the lock, so
// a snapshot is immune to later writes. The one caller holding the live object
// is CreateSandFS's caller, which fills the record right after creation
// (registry: rootfs path + min resources) — those writes must be visible on
// the returned record, which is why the object is not copy-on-write.

// SetRootFSPath sets the RootFSPath on an existing record.
// Returns an error if the sandfs does not exist, matching EtcdStore.
func (s *MemoryStore) SetRootFSPath(sandfsID, rootfsPath string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, ok := s.sandfs[sandfsID]
	if !ok {
		return fmt.Errorf("sandfs not found: %s", sandfsID)
	}
	rec.RootFSPath = rootfsPath
	s.persistLocked()
	return nil
}

// SetMinResources sets the minimum vCPUs/memory on an existing record.
// Returns an error if the sandfs does not exist, matching EtcdStore.
func (s *MemoryStore) SetMinResources(sandfsID string, vcpus uint32, memMB uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, ok := s.sandfs[sandfsID]
	if !ok {
		return fmt.Errorf("sandfs not found: %s", sandfsID)
	}
	rec.MinVCPUs = vcpus
	rec.MinMemoryMB = memMB
	s.persistLocked()
	return nil
}

// ── Lifecycle (template swap + delete orchestration) ───────────

// ErrSandfsNotDetached is returned by UpdateSandfsTemplate when the record is
// not in the detached state: completing an attach from any other status would
// overwrite a concurrent delete/swap transition (check-then-act). The caller
// re-reads the record and reports the state it found.
var ErrSandfsNotDetached = fmt.Errorf("sandfs is not in the detached lifecycle state")

// StatusCASStore is the optional conditional-write seam for lifecycle status
// transitions. Both shipped stores implement it; the human handler asserts it
// and falls back to a check-then-act write only for stores without the seam
// (test doubles). The compare is on the STATUS, never the etcd revision: two
// gateways may hold records at different revisions and still need the same
// "only if still detaching" decision.
type StatusCASStore interface {
	// CompareAndSetSandfsStatus applies to only when the record currently
	// carries from. When it does not apply, current is the status the record
	// carried ("" = active). An error means neither applied nor observed.
	CompareAndSetSandfsStatus(sandfsID, from, to string) (applied bool, current string, err error)
}

// CompareAndSetSandfsStatus implements StatusCASStore.
func (s *MemoryStore) CompareAndSetSandfsStatus(sandfsID, from, to string) (bool, string, error) {
	if err := validateStatus(from); err != nil {
		return false, "", err
	}
	if err := validateStatus(to); err != nil {
		return false, "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, ok := s.sandfs[sandfsID]
	if !ok {
		return false, "", fmt.Errorf("sandfs not found: %s", sandfsID)
	}
	if rec.Status != from {
		return false, rec.Status, nil
	}
	rec.Status = to
	s.persistLocked()
	return true, to, nil
}

// SetSandfsStatus writes the lifecycle status (see Record.Status). Error if
// the sandfs does not exist or the status value is not a known lifecycle
// status — a typo must never silently gate every execution on the sandfs.
// Lifecycle orchestration should prefer CompareAndSetSandfsStatus: this
// unconditional form can overwrite a concurrent transition.
func (s *MemoryStore) SetSandfsStatus(sandfsID, status string) error {
	if err := validateStatus(status); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, ok := s.sandfs[sandfsID]
	if !ok {
		return fmt.Errorf("sandfs not found: %s", sandfsID)
	}
	rec.Status = status
	s.persistLocked()
	return nil
}

// UpdateSandfsTemplate completes a template attach in one write: new ref, new
// declared min resources, status back to active.
//
// Only valid from the detached state: the attach flow checks "detached" and
// then runs a potentially multi-minute storage swap, so an unconditional write
// here could complete an attach over a deletion (or a newer detach) that landed
// meanwhile — resurrecting a sandfs the operator is tearing down. Returns
// ErrSandfsNotDetached (and changes nothing) when the record moved on.
func (s *MemoryStore) UpdateSandfsTemplate(sandfsID, templateRef string, vcpus uint32, memMB uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, ok := s.sandfs[sandfsID]
	if !ok {
		return fmt.Errorf("sandfs not found: %s", sandfsID)
	}
	if rec.Status != SandfsStatusDetached {
		return ErrSandfsNotDetached
	}
	rec.Template = templateRef
	rec.MinVCPUs = vcpus
	rec.MinMemoryMB = memMB
	rec.Status = ""
	s.persistLocked()
	return nil
}

// CountSandFSByTemplate counts overlay-mode records naming templateRef
// (local-cache scan; bounded sample of ids).
func (s *MemoryStore) CountSandFSByTemplate(templateRef string) (int, []string) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	count := 0
	var sample []string
	for id, rec := range s.sandfs {
		// Ref identity is the ref FILE identity: the ref->filename encoding
		// is not injective, so "a:b_c" and "a_b:c" name the same template.
		// A raw-string compare would let a colliding ref miss a live volume.
		if rec.Mode == "overlay" && util.RefToFilename(rec.Template) == util.RefToFilename(templateRef) {
			count++
			if len(sample) < templateInUseSampleSize {
				sample = append(sample, id)
			}
		}
	}
	return count, sample
}

// templateInUseSampleSize bounds the TEMPLATE_IN_USE refusal payload.
const templateInUseSampleSize = 10

// validateStatus rejects unknown lifecycle status strings at the store seam —
// both store implementations share it.
func validateStatus(status string) error {
	switch status {
	case "", SandfsStatusDetaching, SandfsStatusDetached, SandfsStatusDeleting:
		return nil
	}
	return fmt.Errorf("invalid sandfs status %q", status)
}

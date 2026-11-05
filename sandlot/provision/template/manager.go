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
// Package template manages rootfs templates using a unified layers/ + refs/ storage.
// Templates come from two sources: local directories (auto-discovered from TemplatesDir
// or registered via RegisterLocalTemplate) and OCI registries (pulled via PullTemplate).
// Both sources are stored in the same unified directory structure under TemplatesDir:
//	<TemplatesDir>/
//	  layers/
//	    sha256-<digest16>/   ← OCI layers (extracted rootfs dirs, content-addressed)
//	    local-<name>-<ver>/  ← SaveAsTemplate output (local template versions)
//	  refs/
//	    sqlite_v1.json       ← {"layers": ["/abs/path/to/sqlite/v1"], ...} (local)
//	    mysql_v1.json        ← {"layers": ["sha256-ccc...","sha256-bbb..."], ...} (OCI)
//	  sqlite/                ← Local template source (auto-scanned by NewManager)
//	    v1/                  ← rootfs directory
// Ref files map a template reference (e.g. "sqlite:v1") to its layer stack. Local
// templates store absolute paths; OCI templates store relative paths under layersDir.
// The layer stack is consumed by sandlot/core's OverlayFS mounting (overlay volumes)
// and by volume materialization (flat copies / OCI stream-extract).
// On startup, NewManager automatically scans TemplatesDir for local template
// subdirectories (e.g., sqlite/v1/) and registers them. Internal directories
// (layers/, refs/) are skipped during the scan.

package template

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"golang.org/x/sync/singleflight"
	"golang.org/x/sys/unix"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/content/file"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"

	"common/util"
	"sandlot/provision/copyfs"
)

// Sandswap artifact types
const (
	ArtifactTypeTemplate    = "application/vnd.sandswap.template.v1+json"
	MediaTypeTemplateConfig = "application/vnd.sandswap.template.config.v1+json"
	MediaTypeLayerGzip      = "application/vnd.oci.image.layer.v1.tar+gzip"
)

// Volume control files that must never become template content (the
// canonical definitions live in the volume package, which imports this one —
// the names are the contract and are pinned by SaveAsTemplate's test):
// the identity stamp (.sandfs-id — the source tenant's id, generation
// fingerprint and creation time) and the partial-run marker (.provisioning).
const (
	volumeIdentityFile     = ".sandfs-id"
	provisioningMarkerFile = ".provisioning"
)

// saveStagingMarker marks a layers/local-<ref> dir created by THIS save call:
// the aborted-run heal may only wipe directories carrying it — a
// hand-made operator directory at the same name must be refused, not wiped.
const saveStagingMarker = ".save-staging"

// TemplateManifest describes a rootfs template.
type TemplateManifest struct {
	Name           string            `json:"name"`
	Version        string            `json:"version"`
	Description    string            `json:"description"`
	WorkspacePath  string            `json:"workspace_path"`
	DefaultTimeout int               `json:"default_timeout"`
	IsServerless   bool              `json:"is_serverless"`
	IdleTimeout    int               `json:"idle_timeout"`
	Layers         []LayerInfo       `json:"layers"`
	Entrypoint     []string          `json:"entrypoint"`
	Env            map[string]string `json:"env"`
}

// LayerInfo describes a single layer in the template.
type LayerInfo struct {
	Digest      string `json:"digest"`
	Size        int64  `json:"size"`
	MediaType   string `json:"media_type"`
	Type        string `json:"type"`
	Description string `json:"description"`
	Cached      bool   `json:"cached,omitempty"`
}

// AuthConfig holds registry authentication configuration.
type AuthConfig struct {
	Username string
	Password string
	Token    string
	CertFile string
	KeyFile  string
	CAFile   string
}

// RefEntry is the on-disk ref file format that maps a template reference to its layer stack.
// Layers can be absolute paths (local templates) or relative paths under layersDir (OCI layers).
type RefEntry struct {
	Name        string   `json:"name"`
	Version     string   `json:"version"`
	Description string   `json:"description,omitempty"`
	Mode        string   `json:"mode,omitempty"` // "flat" | "overlay"; empty defaults to "overlay"
	Layers      []string `json:"layers"`
	// OCILayers records the OCI layer blobs (bottom→top) for flat templates
	// pulled from an OCI registry. Unlike Layers (local directories), these
	// are never cached on disk: every flat SandFS creation re-streams the
	// blobs directly into its volume (ExtractFlatFromOCI). Recording the
	// digests pins the content — re-pushing the same tag later does not
	// change what existing refs materialize. Byte-level dedup of the
	// resulting volumes is the storage backend's concern, not ours.
	OCILayers   []LayerRef `json:"oci_layers,omitempty"`
	MinVCPUs    uint32     `json:"min_vcpus,omitempty"`     // minimum vCPUs for sandfs created from this template
	MinMemoryMB uint64     `json:"min_memory_mb,omitempty"` // minimum memory MB for sandfs created from this template
}

// LayerRef identifies one OCI layer blob by digest. Content-addressed: every
// consumer verifies the fetched bytes against this digest while streaming
// (content.VerifyReader on the flat path; the oras content store's Push
// verification on the overlay path) — see ExtractFlatFromOCI.
type LayerRef struct {
	Digest string `json:"digest"`
	Size   int64  `json:"size"`
}

// GetMode returns the template mode. Empty string defaults to "overlay" for
// backward compatibility with existing ref files that lack the mode field.
func (e *RefEntry) GetMode() string {
	if e.Mode == "" {
		return "overlay"
	}
	return e.Mode
}

// Manager handles template operations: pull, cache, save, push.
// All template metadata is stored in ref files under refsDir, and layer data
// (either extracted rootfs directories or absolute path references) is managed
// through the unified layers/ + refs/ structure.
//
// Disk (refs/ directory) is the sole source of truth. There is no in-memory
// template cache — ListLocalTemplates() scans refs/ on every call, and
// LoadRefEntry() reads from disk each time. This ensures multi-gateway
// consistency on shared storage without etcd coordination.
//
// Ref files use mode-suffixed filenames to allow same-name flat/overlay
// templates to coexist: refs/ubuntu_24.04.flat.json vs refs/ubuntu_24.04.overlay.json.
//
// On startup, NewManager auto-scans TemplatesDir for local template
// subdirectories (e.g., sqlite/v1/) and registers them alongside any
// templates discovered from existing ref files.
type Manager struct {
	templatesDir string // root of layers/ + refs/
	overlayBase  string // equals volRoot, where flat SaveAsTemplate reads the source volume
	// resolveVolume maps a sandfs ID to its on-disk volume directory. Injected
	// by the prov instance (it holds the name seed); nil in store-only uses,
	// where SaveAsTemplate then refuses instead of guessing a path.
	resolveVolume func(sandfsID string) (string, error)
	repo          *remote.Repository // optional OCI registry
	registry      string             // OCI registry URL (empty = local-only mode)
	// pullSF collapses concurrent PullTemplate extractions of the same layer
	// digest. Two pulls of the same ref (or two refs sharing a layer) would
	// otherwise both see the layer absent, both MkdirAll, and interleave writes
	// into the same layer directory — corrupting the cached layer permanently.
	pullSF singleflight.Group
	// scanMu serializes rescans and guards flatDirs. Discovery (the directory
	// walks that write ref files) runs at startup AND lazily on reader misses —
	// rescan() — so a template directory dropped into a scan root becomes
	// usable without a gateway restart (shared-store fleets included: ref
	// writes are atomic tmp+rename, so racing gateways converge).
	scanMu   sync.Mutex
	flatDirs []string // -flat-templates scan roots, re-walked by rescan()

	// maxSparseBytes caps one file's apparent size when a tenant volume is
	// copied into a template layer (provision.max_sparse_bytes). 0 = the
	// copyfs default.
	maxSparseBytes int64

	// verifyVolumeStamp is the prov instance's signed-stamp verifier. The
	// template package cannot import volume (cycle), so the seed-aware
	// verifier is injected. nil (tests/store-only uses) falls back to the
	// legacy unsigned parse; the prov role always injects it.
	verifyVolumeStamp func(volumeDir string) (stamp VolumeStamp, signed bool, err error)
}

// VolumeStamp is the verified view of a volume's identity stamp: the fields the
// MAC covers and that a caller may trust when the verifier reports signed.
type VolumeStamp struct {
	SandfsID string
	Mode     string
	// Verified is set by the manager when the injected verifier authenticated
	// these fields. Only a verified stamp's sandfs_id may be compared against
	// a request: an unsigned/legacy stamp's id is tenant-chosen (in flat mode
	// the volume root is the agent's chroot).
	Verified bool
}

// Config is the configuration for the template manager.
type Config struct {
	Registry     string
	TemplatesDir string // root directory for layers/ + refs/ storage
	OverlayBase  string
	// ResolveVolume maps a sandfs ID to its on-disk volume directory. The
	// prov instance injects the seed-aware resolver (see volname); the
	// manager itself never learns the seed.
	ResolveVolume func(sandfsID string) (string, error)
	// MaxSparseBytes caps one file's apparent size when SaveAsTemplate copies
	// a tenant volume (provision.max_sparse_bytes). 0 = the copyfs default.
	MaxSparseBytes int64
	// VerifyVolumeStamp verifies a volume's signed identity stamp and returns
	// its id and mode from ONE read. signed=false means the stamp is absent or
	// unsigned (legacy): the agent-writable .template marker then decides. The
	// prov role injects the seed-aware verifier; leaving it nil is only for
	// tests/store-only uses (the manager then trusts the unsigned stamp as
	// before).
	VerifyVolumeStamp func(volumeDir string) (stamp VolumeStamp, signed bool, err error)
	Auth              AuthConfig
}

// tplGroupGID resolves the template-store metadata group (refs/): the group
// that contains the provision identity and every exec sandlot but NOT the
// sandvmm identity. Environment SANDSWAP_TPL_GROUP (written into
// /etc/sandswap/identity.env by host prep), default "sandtmpl". -1 means the
// group is absent on this host — the store then keeps the shared volume group
// (mode tightening still applies; the metadata split is a deployment layer).
func tplGroupGID() int {
	name := os.Getenv("SANDSWAP_TPL_GROUP")
	if name == "" {
		name = "sandtmpl"
	}
	// A numeric value is used directly: k8s pods carry the GID through
	// supplementalGroups and have no /etc/group entry to look up.
	if gid, err := strconv.Atoi(name); err == nil && gid >= 0 {
		return gid
	}
	g, err := user.LookupGroup(name)
	if err != nil {
		return -1
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return -1
	}
	return gid
}

// NewManager creates a new template manager.
// If cfg.Registry is empty, the manager operates in local-only mode (no OCI
// registry) and templates must be registered via RegisterLocalTemplate or
// discovered by the automatic scan of TemplatesDir.
//
// On startup, the manager:
//  1. Creates the layers/ and refs/ subdirectories if they don't exist.
//  2. Loads any previously written ref files (scanRefs).
//  3. Auto-scans TemplatesDir for local template subdirectories (e.g.,
//     sqlite/v1/) and registers them via ScanLocalTemplates.
func NewManager(cfg Config) (*Manager, error) {
	var repo *remote.Repository
	if cfg.Registry != "" {
		var err error
		repo, err = remote.NewRepository(cfg.Registry)
		if err != nil {
			return nil, fmt.Errorf("create repository: %w", err)
		}
		authClient, err := cfg.Auth.toClient()
		if err != nil {
			return nil, fmt.Errorf("setup auth: %w", err)
		}
		repo.Client = authClient

		// Auto-detect plain HTTP for local registries (e.g., localhost:15000/repo).
		// The OCI distribution spec requires TLS for non-localhost endpoints.
		if strings.HasPrefix(cfg.Registry, "localhost") || strings.HasPrefix(cfg.Registry, "127.0.0.1") {
			repo.PlainHTTP = true
		}
	}

	// Create the unified storage directory structure. Both dirs sit on the
	// cross-identity read path — the exec sandlot (985) reads refs and mounts
	// layers, and the FUSE daemon (987) resolves paths through them — so
	// their modes must not depend on the process umask: MkdirAll applies it,
	// and under a restrictive umask the store would be owner-only and every
	// overlay mount on the node would EACCES. Explicit chmod after MkdirAll —
	// the same pattern as the volumes and sandbox dirs.
	for _, d := range []string{filepath.Join(cfg.TemplatesDir, "layers"), filepath.Join(cfg.TemplatesDir, "refs")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return nil, fmt.Errorf("create %s: %w", d, err)
		}
		// setgid is PRESERVED, not cleared: the store root is a setgid chain
		// (templates/ 2770 root:<shared group>) and that chain is how every
		// entry below inherits the shared group — the grant the FUSE daemon
		// (987) and the exec sandlot (985) read through. Chmod-ing to a bare
		// 0755 here would silently break the chain for every layer dir created
		// afterwards (their group would fall back to sandprov's primary gid).
		// 2750: group r-x for the provision/exec identities, NO other bits.
		// The setgid chain still passes the shared group to every entry
		// created below.
		if err := os.Chmod(d, 0o750|os.ModeSetgid); err != nil {
			// A pre-existing store dir owned by ANOTHER identity (root:root
			// 0755 from a host-prep step that ran before the provision identity
			// existed) cannot be chmod'ed by sandprov — no CAP_FOWNER. Dying
			// here turned a cosmetic mode fix into a dead prov instance, while
			// the real question (can this identity WRITE the store?) is answered
			// loudly by the first write. Warn and carry on; the setgid bit is
			// an inheritance nicety, and the group grant it exists for cannot be
			// set by chmod anyway.
			log.Printf("template store: cannot chmod %s (%v) — continuing; if the store is not writable by this identity, the first template write will fail with EACCES", d, err)
		}
	}

	// The refs/ directory is the store's metadata tree. Its group is the
	// template metadata group (prov + exec sandlot), NOT the shared volume
	// group: the FUSE daemon (sandvmm) reads layer CONTENT through the shared
	// group and has no business enumerating refs. Best-effort: a host without
	// the group keeps the shared group (status quo) rather than refusing to
	// start; the mode still blocks every other local user.
	if gid := tplGroupGID(); gid >= 0 {
		refs := filepath.Join(cfg.TemplatesDir, "refs")
		if err := os.Chown(refs, -1, gid); err != nil {
			log.Printf("template store: cannot chgrp %s to the metadata group: %v — refs keep the shared group", refs, err)
		}
	}

	m := &Manager{
		templatesDir:      cfg.TemplatesDir,
		overlayBase:       cfg.OverlayBase,
		resolveVolume:     cfg.ResolveVolume,
		repo:              repo,
		registry:          cfg.Registry,
		maxSparseBytes:    cfg.MaxSparseBytes,
		verifyVolumeStamp: cfg.VerifyVolumeStamp,
	}

	// Discover previously registered templates from ref files
	if err := m.scanRefs(); err != nil {
		return nil, fmt.Errorf("scan refs: %w", err)
	}

	// Auto-scan TemplatesDir for local template subdirectories (e.g., sqlite/v1/)
	if err := m.ScanLocalTemplates(cfg.TemplatesDir); err != nil {
		return nil, fmt.Errorf("scan local templates: %w", err)
	}

	return m, nil
}

// templateSkeletonDirs are the directories every agent rootfs template must
// carry: the warden binds/mounts INTO them at attach time (busybox hot-bind
// under bin/, resolv.conf under etc/, masked proc and minimal dev), and an
// OVERLAY template's merged root is read-only — the warden cannot create a
// missing one at mount time, it can only fall back (busybox) or degrade
// (no /etc for resolv.conf). Flat volumes could be created at runtime, but
// the fix belongs at TEMPLATE BUILD time so a defect is caught once at
// import rather than surfacing per attach (owner decision).
var templateSkeletonDirs = []string{"bin", "etc", "dev", "proc", "workspace", "home"}

// ensureTemplateSkeleton creates any missing skeleton directories under dir
// and returns the names it created (empty when the template was already
// well-formed). Idempotent; existing entries are left untouched.
func ensureTemplateSkeleton(dir string) ([]string, error) {
	var created []string
	for _, name := range templateSkeletonDirs {
		p := filepath.Join(dir, name)
		if info, err := os.Stat(p); err == nil {
			if !info.IsDir() {
				return created, fmt.Errorf("template skeleton: %s exists but is not a directory", p)
			}
			continue
		} else if !os.IsNotExist(err) {
			return created, fmt.Errorf("template skeleton: stat %s: %w", p, err)
		}
		if err := os.MkdirAll(p, 0o755); err != nil {
			return created, fmt.Errorf("template skeleton: create %s: %w", p, err)
		}
		created = append(created, name)
	}
	return created, nil
}

// layersDir returns the path to the layers/ subdirectory.
func (m *Manager) layersDir() string {
	return filepath.Join(m.templatesDir, "layers")
}

// TemplatesDir returns the root templates directory (for external code that
// needs to read ref files directly, e.g., registry reading min_spec).
func (m *Manager) TemplatesDir() string {
	return m.templatesDir
}

// refsDir returns the path to the refs/ subdirectory.
func (m *Manager) refsDir() string {
	return filepath.Join(m.templatesDir, "refs")
}

// resolveLayerPath resolves a layer identifier to a full directory path.
// Absolute paths (local templates) are returned as-is.
// Relative paths (OCI layers) are resolved relative to layersDir.
// UNCHECKED — it is the raw resolution used by writers (push packs whatever
// the ref names into an artifact). Read paths that seed tenant content must
// go through ResolveFlatLayerPath (flat) or core.validateLayerID (overlay),
// which enforce the store trust boundary.
func (m *Manager) resolveLayerPath(layerID string) string {
	if filepath.IsAbs(layerID) {
		return layerID
	}
	return filepath.Join(m.layersDir(), layerID)
}

// ErrFlatLayerOutsideStore is the refusal class for a flat template layer
// path that resolves outside every configured content root. The flat twin of
// the overlay path's core.validateLayerID: ref files live on shared storage
// and a peer node or a tampered store can rewrite them, so the layer path is
// judged at CONSUME time, before copyDirRecursive seeds it into a tenant
// volume — the same placement as the overlay validator (which runs at mount).
var ErrFlatLayerOutsideStore = fmt.Errorf("flat template layer path outside the template store")

// flatLayerRoots returns the content roots a flat template's layer path may
// resolve inside: the template store itself plus every operator-configured
// -flat-templates scan root. The store alone is NOT the boundary — the
// shipped baremetal configuration keeps flat templates in a sibling
// directory (flat-templates/ beside templates/), so the roots an operator
// configured on this host are. Anything else — /etc, a tenant volume, any
// directory no configured root covers — is refused.
func (m *Manager) flatLayerRoots() []string {
	m.scanMu.Lock()
	roots := make([]string, 0, 1+len(m.flatDirs))
	roots = append(roots, m.templatesDir)
	roots = append(roots, m.flatDirs...)
	m.scanMu.Unlock()
	return roots
}

// withinRoot reports whether p is strictly inside root (lexically; both
// sides may be uncleaned — filepath.Rel cleans them). The root itself does
// not count: naming the store root as the layer would copy refs/ and
// layers/ into a tenant volume. Same semantics as core.pathWithin.
func withinRoot(p, root string) bool {
	rel, err := filepath.Rel(root, p)
	if err != nil {
		return false
	}
	return rel != "." && !strings.HasPrefix(rel, "..")
}

// ResolveFlatLayerPath validates the flat-template layer trust boundary and
// returns the layer directory to seed a flat volume from.
//
// Absolute identifiers (the local-template format written by
// RegisterFlatTemplate/ScanFlatTemplates) must resolve strictly inside one
// of flatLayerRoots(); relative identifiers (the OCI layer format) must stay
// under the store's layers/ dir. Both legs are lexical first; a passing path
// is then resolved with EvalSymlinks and re-checked, because a lexically
// contained path can still traverse a symlink out of the root (the overlay
// resolve-time leg, mirrored). A path that does not resolve (missing layer)
// is returned as-is: the caller's stat reports the not-found cause.
func (m *Manager) ResolveFlatLayerPath(layerID string) (string, error) {
	if layerID == "" || layerID == "." {
		return "", fmt.Errorf("%w: empty layer id", ErrFlatLayerOutsideStore)
	}
	path := m.resolveLayerPath(layerID)
	roots := m.flatLayerRoots()
	inside := false
	for _, root := range roots {
		if withinRoot(path, root) {
			inside = true
			break
		}
	}
	if !inside {
		return "", fmt.Errorf("%w: %q resolves to %s, outside every configured template root", ErrFlatLayerOutsideStore, layerID, path)
	}
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		for _, root := range roots {
			resolvedRoot, rerr := filepath.EvalSymlinks(root)
			if rerr != nil {
				continue // root absent on this host: nothing under it resolves either
			}
			if withinRoot(resolved, resolvedRoot) {
				return path, nil
			}
		}
		return "", fmt.Errorf("%w: %q resolves via symlinks to %s, outside every configured template root", ErrFlatLayerOutsideStore, layerID, resolved)
	}
	return path, nil
}

// resolveOverlayLayerPath is the overlay twin of ResolveFlatLayerPath for the
// PACKING side (PushTemplate): an absolute layer id (a locally registered
// template) must resolve strictly inside the template store, a relative one
// (the OCI layer format) strictly under layers/, and a symlinked component may
// not move the resolved path out of that root. It mirrors the mount-time
// validator (sandlot/core's validateLayerID) — a ref file lives on shared
// storage and a peer node or a tampered store can rewrite it, so the packing
// side must not pack a local host path into a published artifact (information
// disclosure) just because the ref named it.
func (m *Manager) resolveOverlayLayerPath(layerID string) (string, error) {
	if layerID == "" || layerID == "." {
		return "", fmt.Errorf("empty layer id")
	}
	if strings.ContainsAny(layerID, ":,") {
		return "", fmt.Errorf("layer id %q contains a mount-option separator", layerID)
	}
	path := m.resolveLayerPath(layerID)
	root := m.templatesDir
	if !filepath.IsAbs(layerID) {
		root = filepath.Join(m.templatesDir, "layers")
	}
	if !withinRoot(filepath.Clean(path), filepath.Clean(root)) {
		return "", fmt.Errorf("layer %q resolves to %s, outside the template store root %s", layerID, path, root)
	}
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		resolvedRoot, rerr := filepath.EvalSymlinks(root)
		if rerr != nil || !withinRoot(resolved, resolvedRoot) {
			return "", fmt.Errorf("layer %q resolves via symlinks to %s, outside the template store root %s", layerID, resolved, root)
		}
	}
	return path, nil
}

// refFileExists reports whether a ref entry file for (ref, mode) already
// exists in refs/.//
// Discovery registration (the scan walks, incl. the lazy rescan that makes
// new template directories usable without a restart) is idempotent-
// create-only: an existing ref file is the authoritative point-in-time
// record — written by pull/push/save-as-template or an earlier scan — and
// must NEVER be rewritten by a later discovery walk. Otherwise the lazy
// rescan would silently "heal" a refs file an operator (or attacker)
// tampered with, laundering it back to a legal state before the sandlot's
// mount-time layer validation ever sees it — reopening the host-path
// injection window the refs trust boundary exists to close (e2e
// overlayfs-isolation 8.1). Deliberate ref writers (PullTemplate,
// SaveAsTemplate, writeRefFile callers) are unaffected.
func (m *Manager) refFileExists(ref, mode string) bool {
	filename := util.RefToFilename(ref) + "." + mode + ".json"
	_, err := os.Stat(filepath.Join(m.refsDir(), filename))
	return err == nil
}

// RefEntryExists reports whether the entry's backing store is actually
// present on this host.
//
// Ref files are durable point-in-time records: discovery never deletes them
// (a temporarily unmounted NFS scan root must not permanently erase refs),
// so a template directory removed after registration leaves its ref behind.
// Existence is therefore judged at READ time: a local-directory template
// (Layers) exists iff every layer directory is on disk; an OCI-backed flat
// template (OCILayers) has nothing local to stat (blobs re-stream at each
// creation), so the ref itself counts as existing.
func (m *Manager) RefEntryExists(entry *RefEntry) bool {
	if len(entry.OCILayers) > 0 {
		return true
	}
	if len(entry.Layers) == 0 {
		return false
	}
	for _, layer := range entry.Layers {
		path := m.resolveLayerPath(layer)
		if info, err := os.Stat(path); err != nil || !info.IsDir() {
			return false
		}
	}
	return true
}

// DeleteTemplate removes one ref file and garbage-collects the layers/ entries
// that no remaining ref names. The in-use check over volumes is the CALLER's
// (Provisioner.DeleteTemplate — it owns the volumes root); this method is the
// template-store half. Serialized with pull/save/scan under scanMu so a
// concurrent pull of the same ref cannot interleave with the ref delete.
//
// Layer reachability: layers are content-addressed and SHARED across refs
// (two tags over the same base layer). After removing the target ref file,
// every remaining ref's Layers are unioned; only layers/ entries outside the
// union are deleted. Absolute-path Layers (the local-template format) are
// never touched — they may be scan roots shared with the filesystem's own
// layout. Conservative by construction: a concurrent cross-instance delete
// that computed its union earlier can only LEAK a shared layer, never remove
// one a live ref names; a concurrent PULL re-extracts on cache miss
// (content-addressed, self-healing).
func (m *Manager) DeleteTemplate(templateRef, mode string) error {
	if err := validateRef(templateRef); err != nil {
		return err
	}
	if mode != "flat" && mode != "overlay" {
		return fmt.Errorf("mode must be \"flat\" or \"overlay\" (got %q)", mode)
	}

	m.scanMu.Lock()
	defer m.scanMu.Unlock()

	refFile := filepath.Join(m.refsDir(), util.RefToFilename(templateRef)+"."+mode+".json")
	if _, err := os.Stat(refFile); err != nil {
		return fmt.Errorf("template %s (%s) not found: %w", templateRef, mode, err)
	}
	// The ref file's entry must name the ref being deleted. Without this, a
	// colliding ref (same filename, different name:version) could delete a
	// ref that the in-use scan did not recognize as the same template.
	if _, err := m.loadRefFile(templateRef, mode); err != nil {
		return err
	}
	if err := os.Remove(refFile); err != nil {
		return fmt.Errorf("remove ref file: %w", err)
	}

	// Union the layers of every remaining ref (both modes — flat and overlay
	// refs share the layers/ space).
	reachable := map[string]struct{}{}
	entries, err := os.ReadDir(m.refsDir())
	if err != nil {
		// Ref file is already gone (the primary goal); the GC sweep failing to
		// LIST is a leak, not a corruption — report it but keep the ref delete.
		return fmt.Errorf("ref deleted, but layer GC could not list refs: %w", err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(m.refsDir(), e.Name()))
		if err != nil {
			continue
		}
		var ref RefEntry
		if json.Unmarshal(data, &ref) != nil {
			continue
		}
		for _, layer := range ref.Layers {
			if !filepath.IsAbs(layer) {
				reachable[layer] = struct{}{}
			}
		}
	}

	// GC: remove layers/ entries (and only those — never absolute-path
	// local-template dirs) that no remaining ref names.
	layerEntries, err := os.ReadDir(m.layersDir())
	if err != nil {
		return nil // same conservative skip as above
	}
	for _, e := range layerEntries {
		if _, ok := reachable[e.Name()]; ok {
			continue
		}
		// A layer slot is ALWAYS a directory. A file or symlink at the name
		// (a poisoned or partial publish) must be reaped too — skipping it
		// would pin the digest forever while no ref can use it.
		isDir := e.IsDir()
		// Cross-instance grace: another prov instance may be extracting this
		// very layer right now (its ref file is written only AFTER extraction,
		// so the layer is not yet reachable anywhere). The singleflight below
		// is per-process and cannot see that pull. A layer directory whose
		// mtime is recent is left alone; a later delete/GC pass reaps it once
		// the window has passed (a leak is acceptable, corruption is not).
		if fi, ierr := e.Info(); ierr == nil && time.Since(fi.ModTime()) < layerGCGrace {
			continue
		}
		// serialize with in-flight extractions of the SAME digest —
		// a concurrent pull sharing this layer could be mid-extraction (or
		// about to copy its staging dir into place); removing the dir under
		// it silently corrupted the layer recorded in the pull's ref. The
		// singleflight also makes the reachability re-check racy-by-design
		// only ACROSS instances (which cannot share state); the age check
		// above closes the remaining cross-instance window.
		name := e.Name()
		if _, err, _ := m.pullSF.Do(name, func() (any, error) {
			layerPath := filepath.Join(m.layersDir(), name)
			if isDir {
				_ = os.RemoveAll(layerPath)
			} else {
				_ = os.Remove(layerPath)
			}
			// Leak on failure, not corruption — keep going; the operator can
			// re-run the delete.
			return nil, nil
		}); err != nil {
			continue
		}
	}
	return nil
}

// layerGCGrace is the cross-instance pull/GC grace window. A layer directory
// younger than this is never removed by DeleteTemplate's reachability GC: the
// ref that will name it is written after extraction completes on ANOTHER
// instance, and that instance cannot be seen by this process's singleflight.
const layerGCGrace = 10 * time.Minute

// ErrRefExists is returned when a ref file already exists. Ref files are
// IMMUTABLE once written: the ref->filename encoding is not injective
// (':' and '_' both encode to '_'), so an overwrite either replaces the same
// ref (a re-point of every volume mounting it) or a DIFFERENT ref that merely
// encodes to the same filename (a cross-tenant rootfs substitution). The
// only safe overwrite is an explicit delete followed by a fresh create under
// the in-use gate; there is deliberately no force-write path here.
var ErrRefExists = errors.New("template ref already exists")

// ErrRefIdentityMismatch is returned when a ref file's entry names a
// different name:version than the ref it was loaded/written as. The
// ref->filename encoding is not injective, so this is the collision signal
// (or a tampered ref): the reader must not serve it and the writer must not
// create it.
var ErrRefIdentityMismatch = errors.New("ref entry does not name the requested ref")

// renameNoReplace publishes tmp at dst only if dst does not exist, atomically.
// RENAME_NOREPLACE is the native form; filesystems that reject the flag
// (EINVAL) or kernels without renameat2 (ENOSYS) fall back to link(2), which
// is also create-if-absent for a same-directory destination.
func renameNoReplace(tmp, dst string) error {
	err := unix.Renameat2(unix.AT_FDCWD, tmp, unix.AT_FDCWD, dst, unix.RENAME_NOREPLACE)
	if err == nil {
		return nil
	}
	if errors.Is(err, unix.EEXIST) {
		return ErrRefExists
	}
	if errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EINVAL) || errors.Is(err, unix.EOPNOTSUPP) {
		if lerr := os.Link(tmp, dst); lerr != nil {
			if errors.Is(lerr, fs.ErrExist) {
				return ErrRefExists
			}
			return lerr
		}
		_ = os.Remove(tmp)
		return nil
	}
	return err
}

// renameDirNoReplace publishes a COMPLETED staging directory at dst only if
// dst does not exist. RENAME_NOREPLACE is the native form; on filesystems
// that reject the flag, os.Rename is used after a create-if-absent check —
// rename(2) only replaces an EMPTY destination directory, and every layer
// carries at least its tree (the empty-directory corner replaces an equally
// empty content-addressed layer, which is harmless).
func renameDirNoReplace(staging, dst string) error {
	err := unix.Renameat2(unix.AT_FDCWD, staging, unix.AT_FDCWD, dst, unix.RENAME_NOREPLACE)
	if err == nil {
		return nil
	}
	if errors.Is(err, unix.EEXIST) || errors.Is(err, unix.ENOTEMPTY) {
		return ErrRefExists
	}
	if errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EINVAL) || errors.Is(err, unix.EOPNOTSUPP) {
		if _, serr := os.Lstat(dst); serr == nil {
			return ErrRefExists
		}
		if rerr := os.Rename(staging, dst); rerr != nil {
			if errors.Is(rerr, fs.ErrExist) || errors.Is(rerr, unix.ENOTEMPTY) {
				return ErrRefExists
			}
			return rerr
		}
		return nil
	}
	return err
}

// layerStagingMaxAge bounds how long a staging directory left by a killed
// extraction may survive. In-flight extractions refresh the directory mtime
// as entries are created, and every provision op carries a wire deadline far
// below this age, so a staging dir older than this is debris — not another
// instance's work in progress. Cleanup is best-effort: a live extraction on a
// shared store must never be disturbed by a stale sweep.
const layerStagingMaxAge = time.Hour

func (m *Manager) reapStaleLayerStaging(layerDirName string) {
	matches, err := filepath.Glob(filepath.Join(m.layersDir(), "."+layerDirName+".staging-*"))
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-layerStagingMaxAge)
	for _, path := range matches {
		info, err := os.Stat(path)
		if err != nil || !info.IsDir() || !info.ModTime().Before(cutoff) {
			continue
		}
		if err := os.RemoveAll(path); err == nil {
			slog.Warn("template: removed stale layer staging dir", "path", path)
		}
	}
}

// writeRefFile writes a NEW ref entry to the refs/ directory. It refuses to
// replace an existing file (ErrRefExists) and binds the entry's Name/Version
// to the ref it is written under, so a ref file can always be checked against
// the ref a reader asked for (see loadRefFile).
//
// The write stays atomic (temp file in the same directory + no-replace
// publish), so a concurrent reader sees either a complete file or none.
func (m *Manager) writeRefFile(ref string, entry RefEntry) error {
	if err := validateRef(ref); err != nil {
		return err
	}
	// The entry must name the ref it is written under. Empty legacy fields
	// are filled from the ref; a NON-empty mismatch is a caller bug or an
	// attempt to write one ref's entry under another ref's filename (the
	// collision class this check exists to close).
	name, version := parseTemplateRef(ref)
	if entry.Name == "" {
		entry.Name = name
	}
	if entry.Version == "" {
		entry.Version = version
	}
	if entry.Name != name || entry.Version != version {
		return fmt.Errorf("%w: entry names %q:%q, refusing to write it under ref %q", ErrRefIdentityMismatch, entry.Name, entry.Version, ref)
	}
	mode := entry.GetMode()
	filename := util.RefToFilename(ref) + "." + mode + ".json"
	path := filepath.Join(m.refsDir(), filename)
	data, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal ref entry: %w", err)
	}
	// Atomic write: write to a UNIQUE temp file in the same directory, then
	// publish without replacing. Two writers (instances sharing the store, or
	// a save racing a pull) must never share the temp path — a fixed name
	// lets one truncate the other's half-written file before either publishes.
	tmpF, err := os.CreateTemp(m.refsDir(), ".ref-*.tmp")
	if err != nil {
		return fmt.Errorf("create ref temp file: %w", err)
	}
	tmpPath := tmpF.Name()
	if _, err := tmpF.Write(data); err != nil {
		tmpF.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("write ref file (tmp): %w", err)
	}
	if err := tmpF.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("close ref file (tmp): %w", err)
	}
	// Refs belong to the metadata group (the directory is setgid, so this is
	// normally a no-op; an explicit chgrp repairs a store created before the
	// group existed and protects against a non-setgid legacy dir).
	if gid := tplGroupGID(); gid >= 0 {
		if err := os.Chown(tmpPath, -1, gid); err != nil {
			log.Printf("template store: cannot chgrp ref %s to the metadata group: %v", tmpPath, err)
		}
	}
	// Ref files are read by the EXEC sandlot identity (985) — the store is
	// shared across identities, so the mode must not depend on the process
	// umask (under umask 077 the file would be owner-only and every overlay
	// mount on the node would fail to load its ref).
	if err := os.Chmod(tmpPath, 0640); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("chmod ref file (tmp): %w", err)
	}
	if err := renameNoReplace(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		if errors.Is(err, ErrRefExists) {
			return fmt.Errorf("%w: %s (refs are immutable; delete it first)", ErrRefExists, ref)
		}
		return fmt.Errorf("publish ref file: %w", err)
	}
	return nil
}

// loadRefFile reads a ref entry from the refs/ directory and verifies that the
// entry actually names the requested ref. The filename encoding is not
// injective, so without this check a ref written as "a_b:c" would be served
// to a caller asking for "a:b_c" (same refs/a_b_c.overlay.json) — the
// cross-tenant rootfs-substitution primitive. Legacy entries with empty
// Name/Version are accepted (the encoding predates the fields); every new
// writeRefFile fills them.
func (m *Manager) loadRefFile(ref, mode string) (*RefEntry, error) {
	if err := validateRef(ref); err != nil {
		return nil, err
	}
	filename := util.RefToFilename(ref) + "." + mode + ".json"
	path := filepath.Join(m.refsDir(), filename)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read ref file %s: %w", filename, err)
	}
	var entry RefEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, fmt.Errorf("parse ref file %s: %w", filename, err)
	}
	name, version := parseTemplateRef(ref)
	if entry.Name != "" && entry.Version != "" &&
		(entry.Name != name || entry.Version != version) {
		return nil, fmt.Errorf(
			"%w: ref file %s names %q:%q but was loaded as %q (a ref is only valid under the exact name:version it was written for)",
			ErrRefIdentityMismatch, filename, entry.Name, entry.Version, ref)
	}
	return &entry, nil
}

// scanRefs reads all ref files from the refs/ directory and validates them.
// This is called at startup to discover previously registered templates.
// It does NOT populate an in-memory cache — disk is the source of truth.
// Supports both new format (mode-suffixed: name_version.mode.json) and
// legacy format (no mode suffix: name_version.json → assumed overlay).
func (m *Manager) scanRefs() error {
	entries, err := os.ReadDir(m.refsDir())
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read refs dir: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		path := filepath.Join(m.refsDir(), entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			continue // skip unreadable files
		}

		var ref RefEntry
		if err := json.Unmarshal(data, &ref); err != nil {
			continue // skip malformed files
		}

		// Verify that at least the first layer exists
		if len(ref.Layers) > 0 {
			firstLayer := m.resolveLayerPath(ref.Layers[0])
			if _, err := os.Stat(firstLayer); err != nil {
				continue // skip refs with missing layers
			}
		}
	}

	return nil
}

// PullTemplate registers a template from the OCI registry and writes a ref
// file. The two modes differ in what gets materialized locally:
//
//   - overlay: every layer blob is downloaded and extracted into
//     layers/sha256-<digest>/ (content-addressed; layers already on disk are
//     skipped — pull dedup). The extracted directories become shared
//     read-only lowerdirs, so this one-time extraction serves every sandfs
//     created from the template.
//   - flat: only the manifest is read; the layer digests are recorded in the
//     ref file (OCILayers) and NOTHING is downloaded or extracted. Each flat
//     SandFS creation streams the blobs straight into its own volume
//     (ExtractFlatFromOCI) — a flat volume is writable and privately owned,
//     so a local cache would have no reuse; byte-level dedup is the storage
//     backend's concern.
func (m *Manager) PullTemplate(ctx context.Context, templateRef, mode string) (*TemplateManifest, error) {
	if err := validateRef(templateRef); err != nil {
		return nil, err
	}
	if mode == "" {
		mode = "overlay"
	}
	if mode != "flat" && mode != "overlay" {
		return nil, fmt.Errorf("invalid mode %q: must be \"flat\" or \"overlay\"", mode)
	}
	// Ref files are immutable. A pull of an existing ref must not re-point it
	// (every volume mounting the ref would silently swap rootfs, and a
	// colliding ref filename can replace a DIFFERENT ref's content). Delete
	// the ref under the in-use gate first, then pull. Checked before any
	// registry I/O so an existing ref costs no download.
	if m.refFileExists(templateRef, mode) {
		return nil, fmt.Errorf("%w: %s (mode %s)", ErrRefExists, templateRef, mode)
	}
	if m.repo == nil {
		return nil, fmt.Errorf("no OCI registry configured; use local templates instead")
	}

	// Convert templateRef (e.g., "myapp:v1") to a valid OCI tag.
	// OCI tags must match [a-zA-Z0-9_.-]+ and cannot contain colons.
	ociTag := strings.ReplaceAll(templateRef, ":", "-")

	var layerPaths []string
	var ociLayers []LayerRef
	var manifest ocispec.Manifest

	if mode == "overlay" {
		// Download the OCI artifact to a temporary directory
		tmpDir, err := os.MkdirTemp("", "sandswap-pull-")
		if err != nil {
			return nil, fmt.Errorf("create temp dir: %w", err)
		}
		defer os.RemoveAll(tmpDir)

		cacheStore, err := file.New(tmpDir)
		if err != nil {
			return nil, fmt.Errorf("create cache store: %w", err)
		}
		defer cacheStore.Close()

		manifestDesc, err := oras.Copy(ctx, m.repo, ociTag, cacheStore, "", oras.DefaultCopyOptions)
		if err != nil {
			return nil, fmt.Errorf("pull template: %w", err)
		}

		manifest, err = readManifestFromStore(ctx, cacheStore, manifestDesc)
		if err != nil {
			return nil, err
		}

		layerPaths, err = m.extractLayersToCache(ctx, cacheStore, manifest.Layers)
		if err != nil {
			return nil, err
		}
	} else {
		var err error
		manifest, err = m.fetchManifest(ctx, ociTag)
		if err != nil {
			return nil, err
		}
		ociLayers = make([]LayerRef, len(manifest.Layers))
		for i, layerDesc := range manifest.Layers {
			ociLayers[i] = LayerRef{Digest: layerDesc.Digest.String(), Size: layerDesc.Size}
		}
	}

	name, version := parseTemplateRef(templateRef)
	entry := RefEntry{
		Name:      name,
		Version:   version,
		Mode:      mode,
		Layers:    layerPaths,
		OCILayers: ociLayers,
	}
	if err := m.writeRefFile(templateRef, entry); err != nil {
		return nil, fmt.Errorf("write ref file: %w", err)
	}

	tmpl := &TemplateManifest{
		Name:          name,
		Version:       version,
		WorkspacePath: "/workspace",
	}

	return tmpl, nil
}

// fetchManifest resolves an OCI tag to its manifest without downloading any
// layer blobs. Used by flat-mode pulls: the blobs stream directly into each
// SandFS volume at creation time, so the pull itself needs nothing but the
// digest list.
func (m *Manager) fetchManifest(ctx context.Context, ociTag string) (ocispec.Manifest, error) {
	desc, err := m.repo.Resolve(ctx, ociTag)
	if err != nil {
		return ocispec.Manifest{}, fmt.Errorf("resolve %s: %w", ociTag, err)
	}
	rc, err := m.repo.Fetch(ctx, desc)
	if err != nil {
		return ocispec.Manifest{}, fmt.Errorf("fetch manifest: %w", err)
	}
	defer rc.Close()
	data, err := io.ReadAll(rc)
	if err != nil {
		return ocispec.Manifest{}, fmt.Errorf("read manifest: %w", err)
	}
	var manifest ocispec.Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return ocispec.Manifest{}, fmt.Errorf("parse manifest: %w", err)
	}
	return manifest, nil
}

// readManifestFromStore reads and parses the manifest from the pull cache store.
func readManifestFromStore(ctx context.Context, store *file.Store, desc ocispec.Descriptor) (ocispec.Manifest, error) {
	manifestReader, err := store.Fetch(ctx, desc)
	if err != nil {
		return ocispec.Manifest{}, fmt.Errorf("fetch manifest: %w", err)
	}
	manifestData, err := io.ReadAll(manifestReader)
	manifestReader.Close()
	if err != nil {
		return ocispec.Manifest{}, fmt.Errorf("read manifest: %w", err)
	}
	var manifest ocispec.Manifest
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		return ocispec.Manifest{}, fmt.Errorf("parse manifest: %w", err)
	}
	return manifest, nil
}

// extractLayersToCache extracts each OCI layer into layers/sha256-<digest>/
// and returns the layer directory names (relative to layersDir). Layers
// already on disk are skipped (pull dedup).
func (m *Manager) extractLayersToCache(ctx context.Context, cacheStore *file.Store, layerDescs []ocispec.Descriptor) ([]string, error) {
	var layerPaths []string
	for _, layerDesc := range layerDescs {
		// The digest becomes a filesystem path component. A manifest is
		// registry-controlled data; validate the descriptor locally before
		// joining it (oras also verifies content, but the path must not depend
		// on that check happening first).
		if err := layerDesc.Digest.Validate(); err != nil {
			return nil, fmt.Errorf("invalid layer digest %q: %w", layerDesc.Digest.String(), err)
		}
		// Compute the layer directory name from the digest
		// e.g., "sha256:abc123def456..." → "sha256-abc123def456"
		digest := layerDesc.Digest.String()
		shortDigest := strings.ReplaceAll(digest, ":", "-")
		layerDirName := shortDigest
		layerDir := filepath.Join(m.layersDir(), layerDirName)

		// Skip if already extracted (pull dedup). Re-checked inside the
		// singleflight body too, so two concurrent pulls of a shared layer
		// collapse to one extraction.
		if info, err := os.Stat(layerDir); err == nil && info.IsDir() {
			layerPaths = append(layerPaths, layerDirName)
			continue
		}

		// Extract under singleflight keyed by digest: concurrent pulls of the
		// same ref (or different refs sharing a layer) collapse to a single
		// extraction. Without this, two callers both see the layer absent,
		// both MkdirAll, and interleave file writes — corrupting the cached
		// layer for all future sandfs.
		_, err, _ := m.pullSF.Do(layerDirName, func() (any, error) {
			// Re-check after winning the singleflight race: a prior call may
			// have just finished extracting this layer.
			if info, err := os.Stat(layerDir); err == nil && info.IsDir() {
				return nil, nil
			}
			// Extract into a UNIQUELY NAMED staging dir and publish with a
			// no-replace rename — the content-addressed name must only ever
			// appear COMPLETE, and two instances sharing the store (k8s pods
			// all run as PID 1) must never share a staging path. A killed
			// extraction (or any host-level death) previously left a partial
			// dir at the final name that the dedup stat above trusted forever,
			// silently poisoning every ref sharing the digest. rename(2) is
			// atomic on the same filesystem: readers see absent or complete.
			m.reapStaleLayerStaging(layerDirName)
			staging, err := os.MkdirTemp(m.layersDir(), "."+layerDirName+".staging-")
			if err != nil {
				return nil, fmt.Errorf("create layer staging dir: %w", err)
			}
			// Fetch the layer blob from the cache store
			layerReader, err := cacheStore.Fetch(ctx, layerDesc)
			if err != nil {
				os.RemoveAll(staging)
				return nil, fmt.Errorf("fetch layer %s: %w", digest, err)
			}
			// Extract the tar.gz layer into the staging directory
			if err := materializeLayerFromTar(layerReader, staging); err != nil {
				layerReader.Close()
				os.RemoveAll(staging)
				return nil, fmt.Errorf("materialize layer %s: %w", digest, err)
			}
			layerReader.Close()
			if err := renameDirNoReplace(staging, layerDir); err != nil {
				os.RemoveAll(staging)
				// Lost a cross-process race at rename time (another instance
				// finished first) — but only a REAL DIRECTORY proves the
				// winner published a complete layer. A symlink/file at the
				// content-addressed name is poisoning, not a race.
				if errors.Is(err, ErrRefExists) {
					fi, lerr := os.Lstat(layerDir)
					if lerr != nil || !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
						return nil, fmt.Errorf("layer %s exists but is not a directory (refusing a poisoned or partial layer)", layerDir)
					}
					return nil, nil
				}
				return nil, fmt.Errorf("install layer %s: %w", digest, err)
			}
			return nil, nil
		})
		if err != nil {
			return nil, err
		}

		layerPaths = append(layerPaths, layerDirName)
	}
	// The merged overlay view takes directories from the TOP layer: creating
	// the skeleton there makes it visible through the merged root without
	// rewriting any lower (content-addressed, possibly shared) layer.
	if len(layerPaths) > 0 {
		top := filepath.Join(m.layersDir(), layerPaths[len(layerPaths)-1])
		if created, err := ensureTemplateSkeleton(top); err != nil {
			return nil, err
		} else if len(created) > 0 {
			slog.Info("template skeleton created in the top layer",
				"layer", layerPaths[len(layerPaths)-1], "dirs", created)
		}
	}
	return layerPaths, nil
}

// ExtractFlatFromOCI materializes a flat SandFS volume from OCI layer blobs.
// Each layer (bottom→top, as recorded in the ref file) is streamed from the
// registry and extracted straight into dstDir — one pass, no intermediate
// storage, no cross-sandfs sharing. Later layers overwrite earlier entries
// (regular-file opens use O_TRUNC), matching lowerdir stacking semantics.
// There is no whiteout handling: sandswap both produces and consumes this
// format, and its packer never emits conflicting layer stacks.
//
// Each blob is verified against its recorded digest while streaming
// (content.VerifyReader, ) — bytes that do not match fail the
// extraction instead of being materialized.
func (m *Manager) ExtractFlatFromOCI(ctx context.Context, layers []LayerRef, dstDir string) error {
	if m.repo == nil {
		return fmt.Errorf("no OCI registry configured: cannot materialize OCI-origin flat template")
	}
	if len(layers) == 0 {
		return fmt.Errorf("template records no OCI layers")
	}
	for i, layer := range layers {
		d, err := digest.Parse(layer.Digest)
		if err != nil {
			return fmt.Errorf("layer %d digest %q: %w", i, layer.Digest, err)
		}
		desc := ocispec.Descriptor{
			Digest:    d,
			Size:      layer.Size,
			MediaType: MediaTypeLayerGzip,
		}
		rc, err := m.repo.Fetch(ctx, desc)
		if err != nil {
			return fmt.Errorf("fetch layer %d (%s): %w", i, layer.Digest, err)
		}
		// the remote blob store's Fetch verifies only Content-Length
		// and the (self-declared) Docker-Content-Digest header — the BODY is
		// never hashed by that layer. Wrap it in a VerifyReader so bytes that
		// do not match the ref-recorded digest FAIL here instead of being
		// extracted (the digest pin "re-pushing the same tag does not change
		// what existing refs materialize" depends on this).
		vr := content.NewVerifyReader(rc, desc)
		err = extractTarGzToDir(vr, dstDir, extractOptions{flatVolume: true})
		if err == nil {
			// The tar reader stops at end-of-archive; drain what remains of
			// the blob (gzip trailer, any padding) so Verify sees the WHOLE
			// stream, then hash-check it. A mismatch fails the extraction —
			// EnsureVolume's error path leaves the .provisioning marker, so
			// the unverified content is wiped by the retry, never consumed.
			if _, derr := io.Copy(io.Discard, vr); derr != nil {
				err = derr
			} else if verr := vr.Verify(); verr != nil {
				err = verr
			}
		}
		if cerr := rc.Close(); cerr != nil && err == nil {
			err = cerr
		}
		if err != nil {
			return fmt.Errorf("extract layer %d into volume: %w", i, err)
		}
	}
	// Flat materialization: the volume dir IS the rootfs tree, so the
	// skeleton is created here (once per volume creation, host-side mkdir —
	// zero guest FUSE cost).
	if _, err := ensureTemplateSkeleton(dstDir); err != nil {
		return err
	}
	return nil
}

// PushTemplateRequest is the request to push a locally saved template to OCI registry.
type PushTemplateRequest struct {
	TemplateRef string `json:"template_ref"` // e.g., "myapp:v1" (informational; the ref comes from the URL path)
	Mode        string `json:"mode"`         // "flat" | "overlay"; empty = auto-detect (overlay ref first)
}

// PullTemplateRequest is the optional body for pulling a template from an OCI
// registry. An empty body pulls in overlay mode (the historical behavior).
type PullTemplateRequest struct {
	Mode string `json:"mode"` // "flat" | "overlay"; empty defaults to "overlay"
}

// PushTemplateResponse is the response after pushing a template to OCI registry.
type PushTemplateResponse struct {
	TemplateRef string   `json:"template_ref"`
	Digest      string   `json:"digest"`
	Layers      []string `json:"layers"`
	Size        int64    `json:"size"`
	PushTimeMs  int64    `json:"push_time_ms"`
}

// PushTemplate pushes a locally stored template to the OCI registry.
// The template must already exist in the template store (created by
// SaveAsTemplate or registered from a local directory). OCI-origin flat
// templates (no local content, only recorded digests) are rejected — there
// is nothing local to pack. This packages the template layers as tar.gz,
// creates an OCI artifact, and pushes it via ORAS. The artifact records its
// mode in the config blob's template_mode, consumed by flat-mode pulls.
func (m *Manager) PushTemplate(ctx context.Context, templateRef, mode string) (*PushTemplateResponse, error) {
	if mode == "" {
		mode = "overlay"
	}
	if mode != "flat" && mode != "overlay" {
		return nil, fmt.Errorf("invalid mode %q: must be \"flat\" or \"overlay\"", mode)
	}
	if m.repo == nil {
		return nil, fmt.Errorf("no OCI registry configured; cannot push templates")
	}

	entry, err := m.loadRefFile(templateRef, mode)
	if err != nil {
		// Keep the cause: a corrupt ref file and a missing ref file read
		// identically to the operator without it.
		return nil, fmt.Errorf("%s template not found: %s: %w", mode, templateRef, err)
	}
	if len(entry.Layers) == 0 && len(entry.OCILayers) > 0 {
		return nil, fmt.Errorf("template %s is OCI-origin (no local content to push); push a locally registered template instead", templateRef)
	}
	if len(entry.Layers) == 0 {
		return nil, fmt.Errorf("template %s (%s) records no local layers; nothing to push", templateRef, mode)
	}

	// Create a temporary build directory
	buildDir, err := os.MkdirTemp("", "sandswap-push-")
	if err != nil {
		return nil, fmt.Errorf("create build dir: %w", err)
	}
	defer os.RemoveAll(buildDir)

	store, err := file.New(buildDir)
	if err != nil {
		return nil, fmt.Errorf("create store: %w", err)
	}
	defer store.Close()

	// Pack each layer as tar.gz and add to the store
	var layers []ocispec.Descriptor
	for i, layerID := range entry.Layers {
		// Containment before any read: a ref file is shared-storage input and
		// the packing side would otherwise Stat/pack an absolute path named by
		// it verbatim (a local host file published into the registry). Flat
		// refs may name a configured flat-template root; overlay refs must stay
		// inside the template store.
		var layerPath string
		var perr error
		if mode == "flat" {
			layerPath, perr = m.ResolveFlatLayerPath(layerID)
		} else {
			layerPath, perr = m.resolveOverlayLayerPath(layerID)
		}
		if perr != nil {
			return nil, fmt.Errorf("pack layer %d: %w", i, perr)
		}
		if info, err := os.Stat(layerPath); err != nil || !info.IsDir() {
			return nil, fmt.Errorf("layer %d not found: %s", i, layerPath)
		}

		layerArchive := filepath.Join(buildDir, fmt.Sprintf("layer-%d.tar.gz", i))
		if err := packTarGz(layerPath, layerArchive); err != nil {
			return nil, fmt.Errorf("pack layer %d: %w", i, err)
		}

		desc, err := store.Add(ctx, fmt.Sprintf("layer-%d", i), MediaTypeLayerGzip, layerArchive)
		if err != nil {
			return nil, fmt.Errorf("add layer %d: %w", i, err)
		}
		desc.Annotations = map[string]string{
			"sandswap.layer.type":        "rootfs",
			"sandswap.layer.description": fmt.Sprintf("Layer %d of template %s", i, templateRef),
		}
		layers = append(layers, desc)
	}

	// Create config
	config := map[string]interface{}{
		"workspace_path":  "/workspace",
		"template_mode":   mode,
		"default_timeout": 30,
	}
	configData, _ := json.Marshal(config)
	configFile := filepath.Join(buildDir, "config.json")
	if err := os.WriteFile(configFile, configData, 0640); err != nil {
		return nil, fmt.Errorf("write config: %w", err)
	}
	configDesc, err := store.Add(ctx, "config", MediaTypeTemplateConfig, configFile)
	if err != nil {
		return nil, fmt.Errorf("add config: %w", err)
	}

	annotations := map[string]string{
		"sandswap.template.name":        entry.Name,
		"sandswap.template.version":     entry.Version,
		"sandswap.template.description": entry.Description,
	}

	manifestDesc, err := oras.Pack(ctx, store, ArtifactTypeTemplate, layers, oras.PackOptions{
		ConfigDescriptor:    &configDesc,
		ManifestAnnotations: annotations,
		PackImageManifest:   true, // OCI Image Manifest for broad registry compatibility
	})
	if err != nil {
		return nil, fmt.Errorf("pack artifact: %w", err)
	}

	// Tag the packed manifest so oras.Copy can resolve it by reference.
	// Use a digest-based tag to avoid colon conflicts with OCI reference parsing.
	pushTag := "push-" + manifestDesc.Digest.Encoded()[:16]
	if err := store.Tag(ctx, manifestDesc, pushTag); err != nil {
		return nil, fmt.Errorf("tag manifest: %w", err)
	}

	// Convert templateRef (e.g., "myapp:v1") to a valid OCI tag.
	// OCI tags must match [a-zA-Z0-9_.-]+ and cannot contain colons.
	ociTag := strings.ReplaceAll(templateRef, ":", "-")

	pushStart := time.Now()
	_, err = oras.Copy(ctx, store, pushTag, m.repo, ociTag, oras.DefaultCopyOptions)
	if err != nil {
		return nil, fmt.Errorf("push template: %w", err)
	}

	totalSize := int64(0)
	layerDigests := make([]string, len(layers))
	for i, l := range layers {
		totalSize += l.Size
		layerDigests[i] = l.Digest.String()
	}

	return &PushTemplateResponse{
		TemplateRef: templateRef,
		Digest:      manifestDesc.Digest.String(),
		Layers:      layerDigests,
		Size:        totalSize,
		PushTimeMs:  time.Since(pushStart).Milliseconds(),
	}, nil
}

// ListLocalTemplates returns all locally stored template refs by scanning the
// refs/ directory on disk. Only templates whose ref file exists AND whose
// backing store is still present are returned (RefEntryExists — a template
// directory deleted after registration leaves a durable ref file behind, and
// listing a ghost that no create could ever mount would mislead; re-creating
// the directory restores the template instantly via the kept ref).
// OCI registry templates are NOT included — they are available for SandFS
// creation via auto-pull but not listed here. Callers should document this
// distinction to users.
func (m *Manager) ListLocalTemplates() []string {
	// Lazy discovery: pick up template directories dropped into scan roots
	// since startup, so listings match what a create would find.
	m.rescan()
	entries, err := os.ReadDir(m.refsDir())
	if err != nil {
		return nil
	}

	seen := make(map[string]bool)
	var result []string
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		base := strings.TrimSuffix(entry.Name(), ".json")
		// Strip the mode suffix (.flat or .overlay). Only known mode suffixes are
		// stripped so versions containing '.' (e.g. "24.04") are preserved.
		// Legacy ref files without a mode suffix are left untouched.
		if strings.HasSuffix(base, ".flat") {
			base = strings.TrimSuffix(base, ".flat")
		} else if strings.HasSuffix(base, ".overlay") {
			base = strings.TrimSuffix(base, ".overlay")
		}
		templateRef := filenameToRef(base)
		if seen[templateRef] {
			continue
		}
		// Existence is judged at read time (RefEntryExists): a template
		// directory deleted after registration leaves its durable ref file
		// behind, and the listing must not present that ghost — a create
		// against it could never mount. The ref itself is kept on disk so a
		// directory re-created at the same path is immediately usable again.
		data, err := os.ReadFile(filepath.Join(m.refsDir(), entry.Name()))
		if err != nil {
			continue
		}
		var refEntry RefEntry
		if json.Unmarshal(data, &refEntry) != nil || !m.RefEntryExists(&refEntry) {
			continue
		}
		seen[templateRef] = true
		result = append(result, templateRef)
	}
	return result
}

// LoadRefEntry loads and returns the ref entry for a template reference.
// Requires mode to construct the mode-suffixed filename.
// Exported for use by registry/sandfs.go.
// LoadRefEntry loads and returns the ref entry for a template reference.
// Requires mode to construct the mode-suffixed filename. A miss re-runs the
// local-template discovery walks once before failing, so a directory dropped
// into a scan root is found without a gateway restart.
// Exported for use by registry/sandfs.go.
func (m *Manager) LoadRefEntry(templateRef, mode string) (*RefEntry, error) {
	entry, err := m.loadRefFile(templateRef, mode)
	if err == nil {
		return entry, nil
	}
	m.rescan()
	return m.loadRefFile(templateRef, mode)
}

// rescan re-runs the discovery walks (templates dir + every flat scan root
// seen so far), best-effort: scan errors are swallowed — a subsequent miss
// simply behaves as before. Serialized so concurrent readers share one walk;
// discovery only ever CREATES ref files (refFileExists gate), and the writes
// themselves are atomic (writeRefFile tmp+rename), so gateways racing on
// shared storage converge on identical files — while an existing (possibly
// tampered) ref is left for the mount-time layer validation to judge.
func (m *Manager) rescan() {
	m.scanMu.Lock()
	dirs := append([]string(nil), m.flatDirs...)
	m.scanMu.Unlock()

	_ = m.ScanLocalTemplates(m.templatesDir)
	for _, dir := range dirs {
		_ = m.ScanFlatTemplates(dir)
	}
}

// ResolveLayerPath resolves a layer identifier to a full directory path.
// Exported for use by registry/sandfs.go.
func (m *Manager) ResolveLayerPath(layerID string) string {
	return m.resolveLayerPath(layerID)
}

// GetTemplate returns the manifest for a cached template.
// Reads from disk (refs/ directory) — no in-memory cache; a miss re-runs
// the discovery walks once (lazy local-template pickup, no restart).
func (m *Manager) GetTemplate(templateRef, mode string) (*TemplateManifest, error) {
	entry, err := m.LoadRefEntry(templateRef, mode)
	if err != nil {
		return nil, fmt.Errorf("template not found: %s (mode=%s): %w", templateRef, mode, err)
	}
	return &TemplateManifest{
		Name:          entry.Name,
		Version:       entry.Version,
		Description:   entry.Description,
		WorkspacePath: "/workspace",
	}, nil
}

// RegisterLocalTemplate registers a local directory as a template's lowerdir.
// The directory must exist and be a valid rootfs. This allows OverlayFS-based
// sandfs creation without an OCI registry.
// templateRef uses "name:version" format (e.g., "sqlite:v1", "python:v2").
// Unversioned refs like "sqlite" are also supported for backward compatibility.
//
// The resolved absolute path of the directory is stored directly in the ref file.
// No symlink or copy is made — OverlayFS will use the original directory as lowerdir.
//
// Idempotent-create-only: if the ref file already exists it is left untouched
// and nil is returned (see refFileExists for why discovery must never rewrite
// an existing ref).
func (m *Manager) RegisterLocalTemplate(templateRef, dirPath string) error {
	if err := validateRef(templateRef); err != nil {
		return err
	}
	if m.refFileExists(templateRef, "overlay") {
		return nil
	}
	absPath, err := filepath.Abs(dirPath)
	if err != nil {
		return fmt.Errorf("resolve path: %w", err)
	}
	if info, err := os.Stat(absPath); err != nil {
		return fmt.Errorf("template directory not found: %s", absPath)
	} else if !info.IsDir() {
		return fmt.Errorf("template path is not a directory: %s", absPath)
	}

	// Parse name and version from templateRef
	name, version := parseTemplateRef(templateRef)

	// Write the ref file with the absolute path as the layer
	entry := RefEntry{
		Name:    name,
		Version: version,
		Mode:    "overlay",
		Layers:  []string{absPath},
	}
	if err := m.writeRefFile(templateRef, entry); err != nil {
		return fmt.Errorf("write ref file: %w", err)
	}

	return nil
}

// RegisterFlatTemplate registers a local directory as a flat template.
// Unlike RegisterLocalTemplate (which stores as overlay mode), this sets
// mode="flat" in the ref file, indicating the template should be consumed
// via `cp -a` rather than OverlayFS lowerdir mount.
// The ref file is written to the overlayfs-templates/refs/ directory (unified storage),
// but the Layers field stores the absolute path to the flat template directory.
//
// Idempotent-create-only: if the ref file already exists it is left untouched
// and nil is returned (see refFileExists for why discovery must never rewrite
// an existing ref).
func (m *Manager) RegisterFlatTemplate(templateRef, dirPath string) error {
	if err := validateRef(templateRef); err != nil {
		return err
	}
	if m.refFileExists(templateRef, "flat") {
		return nil
	}
	absPath, err := filepath.Abs(dirPath)
	if err != nil {
		return fmt.Errorf("resolve path: %w", err)
	}
	if info, err := os.Stat(absPath); err != nil {
		return fmt.Errorf("flat template directory not found: %s", absPath)
	} else if !info.IsDir() {
		return fmt.Errorf("flat template path is not a directory: %s", absPath)
	}

	// Template-contract check: a flat template seeds volumes at create time —
	// flat seeding repairs modes at consume (copyDirRecursive/extract add the
	// group bits), so a violation here is not fatal, but it IS how a producer
	// finds out (the alternative is a silently non-conformant artifact and an
	// EACCES in some future overlay consumption). Warn with a bounded sample;
	// fix with `template-tool normalize <dir>`.
	if violations, verr := ValidateTemplateTree(absPath); verr != nil {
		slog.Warn("flat template contract check failed to walk the tree", "ref", templateRef, "path", absPath, "error", verr)
	} else if len(violations) > 0 {
		sample := make([]string, 0, 5)
		for i, v := range violations {
			if i == 5 {
				break
			}
			sample = append(sample, fmt.Sprintf("%s (%04o: %s)", v.Path, v.Mode, v.Reason))
		}
		slog.Warn("flat template violates the template contract (group access missing); flat seeding repairs it at consume, but producers should run template-tool normalize",
			"ref", templateRef, "violations", len(violations), "sample", sample)
	}

	name, version := parseTemplateRef(templateRef)

	entry := RefEntry{
		Name:    name,
		Version: version,
		Mode:    "flat",
		Layers:  []string{absPath},
	}
	if err := m.writeRefFile(templateRef, entry); err != nil {
		return fmt.Errorf("write ref file: %w", err)
	}

	return nil
}

// ScanLocalTemplates scans a directory for local template subdirectories
// and registers each one. This is called automatically by NewManager on
// TemplatesDir, but can also be called manually to scan an external directory.
//
// Supports two directory layouts:
//
//  1. Versioned (recommended for distributed FS dedup):
//     localDir/sqlite/v1/   → templateRef "sqlite:v1"
//     localDir/sqlite/v2/   → templateRef "sqlite:v2"
//     localDir/python/v1/   → templateRef "python:v1"
//
//  2. Flat (backward compatible):
//     localDir/sqlite/      → templateRef "sqlite" (version "local")
//     localDir/python/      → templateRef "python" (version "local")
//
// Detection: if a subdirectory contains only directories (no bin/, etc.),
// it is treated as a name/ with version/ subdirectories. Otherwise it is
// treated as a flat rootfs.
func (m *Manager) ScanLocalTemplates(localDir string) error {
	entries, err := os.ReadDir(localDir)
	if err != nil {
		return fmt.Errorf("read local templates dir: %w", err)
	}

	registered := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		// Skip internal directories that are part of the unified storage layout
		if entry.Name() == "layers" || entry.Name() == "refs" {
			continue
		}
		namePath := filepath.Join(localDir, entry.Name())

		// Check if this is a versioned template (name/ containing version dirs)
		// or a flat template (name/ is the rootfs itself).
		if isVersionedTemplateDir(namePath) {
			// Versioned: scan version subdirectories
			verEntries, err := os.ReadDir(namePath)
			if err != nil {
				continue
			}
			for _, ve := range verEntries {
				if !ve.IsDir() {
					continue
				}
				verPath := filepath.Join(namePath, ve.Name())
				templateRef := entry.Name() + ":" + ve.Name()
				if err := m.RegisterLocalTemplate(templateRef, verPath); err != nil {
					continue
				}
				registered++
			}
		} else {
			// Flat: directory name = template reference (backward compatible)
			if err := m.RegisterLocalTemplate(entry.Name(), namePath); err != nil {
				continue
			}
			registered++
		}
	}

	return nil
}

// ScanFlatTemplates scans a directory for flat template subdirectories
// and registers each one with mode="flat". Directory layout:
//
//	flatTemplatesDir/
//	  ubuntu/
//	    24.04/    → "ubuntu:24.04" (mode=flat)
//	    26.04/    → "ubuntu:26.04" (mode=flat)
//	  alpine/
//	    3.20/     → "alpine:3.20" (mode=flat)
//
// Reuses the same versioned/flat detection heuristics as ScanLocalTemplates,
// but always registers as mode="flat" (consumed via cp -a, not OverlayFS).
// The scan root is remembered for lazy rescans (rescan), so directories
// dropped here after startup are discovered on the next reader miss.
func (m *Manager) ScanFlatTemplates(flatTemplatesDir string) error {
	m.scanMu.Lock()
	known := false
	for _, d := range m.flatDirs {
		if d == flatTemplatesDir {
			known = true
			break
		}
	}
	if !known {
		m.flatDirs = append(m.flatDirs, flatTemplatesDir)
	}
	m.scanMu.Unlock()

	entries, err := os.ReadDir(flatTemplatesDir)
	if err != nil {
		return fmt.Errorf("read flat templates dir: %w", err)
	}

	registered := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		namePath := filepath.Join(flatTemplatesDir, entry.Name())

		// Check if this is a versioned template (name/ containing version dirs)
		// or a flat template (name/ is the rootfs itself).
		if isVersionedTemplateDir(namePath) {
			// Versioned: scan version subdirectories
			verEntries, err := os.ReadDir(namePath)
			if err != nil {
				continue
			}
			for _, ve := range verEntries {
				if !ve.IsDir() {
					continue
				}
				verPath := filepath.Join(namePath, ve.Name())
				templateRef := entry.Name() + ":" + ve.Name()
				if err := m.RegisterFlatTemplate(templateRef, verPath); err != nil {
					continue
				}
				registered++
			}
		} else {
			// Flat: directory name = template reference
			if err := m.RegisterFlatTemplate(entry.Name(), namePath); err != nil {
				continue
			}
			registered++
		}
	}

	return nil
}

type SaveAsTemplateRequest struct {
	TemplateRef string `json:"template_ref"` // e.g., "sqlite:v2"
	Description string `json:"description"`
	VCPUs       uint32 `json:"vcpus,omitempty"`     // minimum vCPUs; defaults to the source sandfs's value
	MemoryMB    uint64 `json:"memory_mb,omitempty"` // minimum memory MB; defaults to the source sandfs's value
}

// SaveAsTemplateResponse is the response after saving a SandFS as a local template.
type SaveAsTemplateResponse struct {
	TemplateRef string `json:"template_ref"`
	Path        string `json:"path"`
	SizeKB      int64  `json:"size_kb"`
}

// lockRefSave serializes save-template work for one ref across every process
// sharing the store. flock is released by the kernel when the holder dies, so
// a crashed save never leaves a lock that must be broken by hand. The caller
// holds the returned unlock for the whole check-copy-publish sequence.
func (m *Manager) lockRefSave(ctx context.Context, ref string) (func(), error) {
	name := "." + util.RefToFilename(ref) + ".save.lock"
	path := filepath.Join(m.refsDir(), name)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0640)
	if err != nil {
		return nil, fmt.Errorf("open save lock %s: %w", name, err)
	}
	for {
		err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) && !errors.Is(err, unix.EINTR) {
			f.Close()
			return nil, fmt.Errorf("lock save %s: %w", ref, err)
		}
		select {
		case <-ctx.Done():
			f.Close()
			return nil, ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
	return func() {
		_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
		_ = f.Close()
	}, nil
}

// SaveAsTemplate saves a flat SandFS's rootfs as a new local overlay template.
// Only flat SandFS (bind-mount mode, no .template marker) can be saved.
// Overlay SandFS (with .template marker) are rejected because their rootfs
// is a read-only overlay mount — agent writes live in the separate writable
// workspace/home bind mounts, not in the rootfs.
//
// The saved template is written to layers/local-<name>-<ver>/ under the
// overlayfs-templates directory, and registered with mode="overlay" so it
// can be used as an OverlayFS lowerdir for future SandFS instances.
// The ctx bounds the copy: save-as-template moves GBs on shared storage, and
// an unbounded cp would hold a provision semaphore slot past the wire deadline
// the gateway already gave up on.
// volumeIdentityStamp is the prov-written identity stamp file every
// volume carries (same contract as provision/volume.VolumeIdentityFile; the
// template package cannot import volume without a cycle).
const volumeIdentityStamp = ".sandfs-id"

// regularFileExists reports whether path is a REGULAR file, without following a
// final symlink. The `.template` marker lives in a flat volume's agent-writable
// root: os.Stat would resolve a tenant-planted symlink against the host
// filesystem, and a symlink must not be treated as the storage plane's marker.
func regularFileExists(path string) bool {
	fi, err := os.Lstat(path)
	return err == nil && fi.Mode().IsRegular()
}

// volumeStamp returns the volume's authoritative identity stamp. When the
// prov instance injected a verifier, only a SIGNED stamp is trusted; an
// absent or unsigned stamp is legacy and falls through to the .template marker.
// Without a verifier (tests/store-only uses) the unsigned stamp is parsed as
// before.
func (m *Manager) volumeStamp(dir string) (VolumeStamp, bool, error) {
	if m.verifyVolumeStamp == nil {
		mode, present, err := readVolumeStampMode(dir)
		if err != nil || !present {
			return VolumeStamp{}, false, err
		}
		return VolumeStamp{Mode: mode}, true, nil
	}
	stamp, signed, err := m.verifyVolumeStamp(dir)
	if err != nil {
		return VolumeStamp{}, false, err
	}
	if signed {
		stamp.Verified = true
		return stamp, true, nil
	}
	return VolumeStamp{}, false, nil
}

// readVolumeStampMode reads the signed stamp's mode field safely. The second
// return is false when no stamp exists (legacy unsigned volume).
func readVolumeStampMode(dir string) (string, bool, error) {
	data, usable, err := util.ReadMarkerFile(filepath.Join(dir, volumeIdentityStamp))
	if err != nil {
		if os.IsNotExist(err) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("read volume stamp: %w", err)
	}
	if !usable {
		return "", false, fmt.Errorf("volume stamp %s is not a regular file of bounded size", volumeIdentityStamp)
	}
	for _, line := range strings.Split(string(data), "\n") {
		key, val, ok := strings.Cut(strings.TrimSpace(line), ":")
		if ok && strings.TrimSpace(key) == "mode" {
			return strings.TrimSpace(val), true, nil
		}
	}
	return "", true, nil
}

func (m *Manager) SaveAsTemplate(ctx context.Context, sandfsID string, req SaveAsTemplateRequest) (*SaveAsTemplateResponse, error) {
	// The volume directory is resolved by the CALLER's resolver (the provision
	// plane owns the seed): since names are derived from a deployment seed they
	// are no longer the sandfs ID joined onto the volumes root (see volname).
	resolve := m.resolveVolume
	if resolve == nil {
		return nil, fmt.Errorf("template manager has no volume resolver configured")
	}
	sandfsDir, err := resolve(sandfsID)
	if err != nil {
		return nil, err
	}

	if _, err := os.Stat(sandfsDir); os.IsNotExist(err) {
		return nil, fmt.Errorf("sandfs not found: %s", sandfsID)
	}

	// Only flat SandFS can be saved as template. The signed volume stamp is
	// the authority on the volume's mode; the agent-writable `.template`
	// marker is consulted only for unsigned legacy volumes. A tenant can
	// create `.template` in a flat volume's root (its chroot), which used to
	// block its own backups permanently and misclassify flat templates.
	templateMarker := filepath.Join(sandfsDir, ".template")
	stamp, stamped, serr := m.volumeStamp(sandfsDir)
	if serr != nil {
		return nil, serr
	}
	if stamped {
		// The stamp's sandfs_id is covered by the same MAC that made it
		// trusted: a volume whose verified stamp names a DIFFERENT sandfs is a
		// hand-rename, a restore or a half-applied rotation. Snapshotting it
		// would publish another tenant's data as this sandfs's template. The
		// comparison is meaningful only for a VERIFIED stamp (no verifier =
		// store-only test use, where the id is unauthenticated).
		if stamp.Verified && stamp.SandfsID != sandfsID {
			return nil, fmt.Errorf("cannot save %s as template: the volume's identity stamp names a different sandfs — refusing to snapshot a mis-renamed or restored volume (inspect the seed generations)", sandfsID)
		}
		if stamp.Mode != "" {
			if stamp.Mode != "flat" {
				return nil, fmt.Errorf("cannot save %s SandFS as template: rootfs is not a flat volume; agent writes live in workspace/home, not the rootfs", stamp.Mode)
			}
		} else if regularFileExists(templateMarker) {
			return nil, fmt.Errorf("cannot save overlay SandFS as template: rootfs is a read-only overlay; agent writes live in workspace/home, not the rootfs")
		}
	} else if regularFileExists(templateMarker) {
		return nil, fmt.Errorf("cannot save overlay SandFS as template: rootfs is a read-only overlay; agent writes live in workspace/home, not the rootfs")
	}

	// Determine target directory for the new template.
	// validateRef rejects path traversal in name/version (used below in
	// layerDirName and the ref filename), preventing a crafted template_ref
	// from escaping layers/ or refs/.
	if err := validateRef(req.TemplateRef); err != nil {
		return nil, err
	}
	name, version := parseTemplateRef(req.TemplateRef)
	if name == "" || version == "" || version == "local" {
		return nil, fmt.Errorf("template_ref must be in name:version format (e.g., \"sqlite:v2\"), got: %s", req.TemplateRef)
	}

	// Serialize the whole check-copy-publish sequence for this ref across
	// processes sharing the store. The lock is an flock: the kernel releases
	// it when the holder dies, so a crashed save cannot leave a lock behind.
	unlock, err := m.lockRefSave(ctx, req.TemplateRef)
	if err != nil {
		return nil, err
	}
	defer unlock()

	// IMMUTABILITY, checked BEFORE the copy: if refs/<RefToFilename(ref)>.overlay.json
	// already exists, this save must not replace it. The previous guard was
	// keyed on the target directory `local-<name>-<version>`, which a
	// colliding ref (different name/version partition, same filename) does
	// not share — so an attacker could overwrite another tenant's ref while
	// writing a fresh directory. Ref identity is the ref FILE, not the layer
	// dir.
	if m.refFileExists(req.TemplateRef, "overlay") {
		return nil, fmt.Errorf("%w: %s (a template ref is immutable; delete it first)", ErrRefExists, req.TemplateRef)
	}

	// Target: layersDir/local-<name>-<version>/
	layerDirName := fmt.Sprintf("local-%s-%s", name, version)
	targetDir := filepath.Join(m.layersDir(), layerDirName)

	// publishMarker proves "a save published into targetDir" across the crash
	// window between the atomic rename and the ref write. It lives BESIDE the
	// layer directory (layers/ is dot-entry debris to every reader and the GC
	// reaps it), never inside it: a control file inside the layer would show up
	// at the merged root of every guest booted from the template.
	publishMarker := filepath.Join(m.layersDir(), "."+layerDirName+".publishing")

	if _, err := os.Stat(targetDir); err == nil {
		// A COMPLETED save always ends with the ref file written last. A
		// target directory whose ref is MISSING is therefore an aborted run
		// (the copy crashed mid-way — e.g. a provision-op transport failure
		// retried on another instance): move it aside and redo, the same
		// partial-run discipline EnsureVolume applies via its .provisioning
		// marker. Without this, the retry wedges permanently: "template already
		// exists" is a business error, so the storage-plane retry loop stops
		// there and the half-copied dir blocks the name until manual cleanup.
		// The move is an atomic rename so only one attempt can claim the
		// debris; the directory is then removed OUTSIDE the published name.
		if m.refFileExists(req.TemplateRef, "overlay") {
			return nil, fmt.Errorf("template already exists: %s at %s", req.TemplateRef, targetDir)
		}
		// Ownership of the debris: either the in-directory marker a previous
		// build wrote before its copy, or the sibling publish marker this
		// save's own crash window leaves behind (rename published, ref not
		// yet written). Neither present => not a save's debris.
		_, inDirMarkerErr := os.Stat(filepath.Join(targetDir, saveStagingMarker))
		_, publishMarkerErr := os.Stat(publishMarker)
		if inDirMarkerErr != nil && publishMarkerErr != nil {
			// No ref AND no save marker: this directory was not left
			// by an aborted save — refuse loudly instead of wiping foreign
			// content.
			return nil, fmt.Errorf("target %s exists without a template ref and without a sandfs save marker — refusing to wipe a foreign directory; move it aside or pick another name", targetDir)
		}
		slog.Warn("template: partial save target found without a ref (aborted run); moving it aside and redoing",
			"ref", req.TemplateRef, "path", targetDir)
		quarantine, qerr := os.CreateTemp(m.layersDir(), "."+layerDirName+".stale-")
		if qerr != nil {
			return nil, fmt.Errorf("create quarantine name for partial save target: %w", qerr)
		}
		quarantinePath := quarantine.Name()
		quarantine.Close()
		os.Remove(quarantinePath)
		if err := os.Rename(targetDir, quarantinePath); err != nil {
			return nil, fmt.Errorf("quarantine partial save target: %w", err)
		}
		os.RemoveAll(quarantinePath)
	} else if os.IsNotExist(err) {
		// No target: a publish marker here is debris from a crash BEFORE the
		// rename (the staging dir it protected is reaped by its own age
		// sweep). Drop it so the next save starts from a clean slate.
		os.Remove(publishMarker)
	}

	// Build the layer in a directory only this call can name, then publish it
	// atomically. A failed or killed save must never leave a partial directory
	// at the final name, and two saves must never write into the same
	// directory.
	stagingDir, err := os.MkdirTemp(m.layersDir(), "."+layerDirName+".staging-")
	if err != nil {
		return nil, fmt.Errorf("create template staging dir: %w", err)
	}
	published := false
	defer func() {
		if !published {
			os.RemoveAll(stagingDir)
		}
	}()

	if err := os.WriteFile(filepath.Join(stagingDir, saveStagingMarker), []byte("save in progress\n"), 0644); err != nil {
		return nil, fmt.Errorf("write save staging marker: %w", err)
	}

	// For flat SandFS: the entire sandfsDir IS the rootfs (bind-mount mode).
	// Copy the whole directory content in-process (archive semantics: modes,
	// mtimes, symlinks), so no `cp` process is spawned and the seed-derived
	// source path never appears in an argv. The source is walked by directory
	// fd; a component exchanged for a symlink cannot redirect the copy to a
	// host path.
	//
	// RootMode 0700: the staging root must NOT inherit the source volume
	// root's mode. Staging lives under layers/ (setgid, shared volume group
	// writable), and that group includes the FUSE daemon (sandvmm) — a
	// group-writable staging root would let a compromised daemon inject
	// entries into the copy window. The owner (the provision identity) can
	// still build the tree; NormalizeTemplateTree below widens it to the
	// layer contract (g+rx, no g+w) before anything is published.
	if err := copyfs.CopyDirArchiveContextLimit(ctx, sandfsDir, stagingDir, copyfs.Limits{
		MaxFileBytes: m.maxSparseBytes,
		RootMode:     0o700,
	}); err != nil {
		// Distinguish the known legitimate failure — guest content the
		// provision identity cannot read (an agent's chmod 600/700; the
		// FUSE daemon stores guest modes verbatim) — from generic copy
		// errors, and name the offending paths.
		if bad := unreadablePaths(sandfsDir, 5); len(bad) > 0 {
			return nil, fmt.Errorf("copy flat sandfs to template: %w (not readable by the provision identity — chmod them group-readable or remove them, then retry: %s)", err, strings.Join(bad, ", "))
		}
		return nil, fmt.Errorf("copy flat sandfs to template: %w", err)
	}
	// Same readability policy as OCI-pulled layers (see NormalizeTemplateTree):
	// a source tree carrying restrictive modes (e.g. a pulled template's
	// 0700/0600 content, readable by prov as the owner) must not become a
	// layer that is EACCES inside guests.
	if changed, err := NormalizeTemplateTree(stagingDir); err != nil {
		return nil, fmt.Errorf("normalize template layer modes: %w", err)
	} else if changed > 0 {
		slog.Warn("template: saved layer normalized to the contract", "path", stagingDir, "entries", changed)
	}

	// Strip the volume tree's control files from the copy. `cp -a .` took
	// everything, and the identity stamp (.sandfs-id: source tenant's id,
	// generation fingerprint, creation time) plus the partial-run marker
	// (.provisioning) are VOLUME state, never template content — the saved
	// layer is consumed as an overlay lowerdir, so anything left here shows
	// up at the merged root of every guest booted from the template: the
	// stamp would leak the source tenant's metadata across tenants. Removal
	// happens BEFORE the ref write, so a template that somehow kept them is
	// never consumable.
	for _, control := range []string{volumeIdentityFile, provisioningMarkerFile, saveStagingMarker} {
		if err := os.Remove(filepath.Join(stagingDir, control)); err != nil && !os.IsNotExist(err) {
			return nil, fmt.Errorf("strip volume control file %s from the saved layer: %w", control, err)
		}
	}

	// Skeleton guarantee at template build time (see templateSkeletonDirs):
	// a saved template missing bin/etc/dev/proc would surface as a degraded
	// attach (busybox fallback, no resolv.conf) with no template-side signal.
	if created, err := ensureTemplateSkeleton(stagingDir); err != nil {
		return nil, err
	} else if len(created) > 0 {
		slog.Info("template skeleton created for saved template", "ref", req.TemplateRef, "dirs", created)
	}

	// Publish only a COMPLETE tree, without replacing anything. Under the
	// per-ref lock the final name cannot belong to another save; a leftover or
	// an external writer is refused rather than overwritten.
	//
	// The publish marker is installed BEFORE the rename and removed only after
	// the ref write: a crash in that window leaves a target directory with no
	// ref, and the marker is what tells the next attempt (the heal branch
	// above) that the debris is a save's own — without it the branch was
	// unreachable (the in-directory marker is stripped before the publish) and
	// the ref name stayed wedged until an operator moved the directory.
	if err := os.WriteFile(publishMarker, []byte("save publish in progress\n"), 0o644); err != nil {
		return nil, fmt.Errorf("write save publish marker: %w", err)
	}
	defer os.Remove(publishMarker)
	if err := renameDirNoReplace(stagingDir, targetDir); err != nil {
		return nil, fmt.Errorf("publish saved template dir: %w", err)
	}
	published = true

	// Write ref file with relative layer path and mode="overlay"
	// (saved templates are consumed as overlay lowerdir — the most efficient way)
	entry := RefEntry{
		Name:        name,
		Version:     version,
		Description: req.Description,
		Mode:        "overlay",
		Layers:      []string{layerDirName},
		MinVCPUs:    req.VCPUs,
		MinMemoryMB: req.MemoryMB,
	}
	if err := m.writeRefFile(req.TemplateRef, entry); err != nil {
		os.RemoveAll(targetDir)
		return nil, fmt.Errorf("write ref file: %w", err)
	}

	// Calculate size
	var totalSize int64
	filepath.Walk(targetDir, func(_ string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			totalSize += info.Size()
		}
		return nil
	})

	return &SaveAsTemplateResponse{
		TemplateRef: req.TemplateRef,
		Path:        targetDir,
		SizeKB:      totalSize / 1024,
	}, nil
}

// parseTemplateRef splits a template reference into name and version.
// "sqlite:v1" → ("sqlite", "v1")
// "sqlite"    → ("sqlite", "local")
func parseTemplateRef(ref string) (name, version string) {
	parts := strings.SplitN(ref, ":", 2)
	name = parts[0]
	if len(parts) == 2 {
		version = parts[1]
	} else {
		version = "local"
	}
	return
}

// refComponentRe matches a single template ref component (name or version):
// alphanumeric start, then alphanumeric/dot/dash/underscore. This rejects path
// separators (/), parent traversal (..), null bytes, and colons — preventing a
// crafted ref from escaping the refs/ or layers/ directories via filepath.Join.
var refComponentRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]*$`)

// validateRef checks that a template reference is safe to use in filesystem
// paths. A ref is "name:version" (or bare "name"); each component must match
// refComponentRe. Rejects "../../etc", "a/b", "name:v1:extra" (SplitN already
// limits to 2, but the colon-in-version case is caught by the component check).
// Call this at every entry point that accepts a ref from external input
// (PullTemplate, SaveAsTemplate, Register*).
func validateRef(ref string) error {
	name, version := parseTemplateRef(ref)
	if !refComponentRe.MatchString(name) {
		return fmt.Errorf("invalid template ref %q: name must match ^[a-zA-Z0-9][a-zA-Z0-9._-]*$", ref)
	}
	// version "local" is the default when no colon is present; still validate it.
	if !refComponentRe.MatchString(version) {
		return fmt.Errorf("invalid template ref %q: version must match ^[a-zA-Z0-9][a-zA-Z0-9._-]*$", ref)
	}
	return nil
}

// filenameToRef converts a ref filename base (without .json and mode suffix)
// back to a template reference. "ubuntu_24.04" → "ubuntu:24.04"
func filenameToRef(base string) string {
	lastUnderscore := strings.LastIndex(base, "_")
	if lastUnderscore >= 0 {
		return base[:lastUnderscore] + ":" + base[lastUnderscore+1:]
	}
	return base
}

// HasOCIRegistry returns true if an OCI registry is configured.
func (m *Manager) HasOCIRegistry() bool {
	return m.repo != nil
}

// isVersionedTemplateDir returns true if the directory looks like a template
// name container (containing version subdirectories) rather than a rootfs itself.
// Heuristic: if all subdirectories lack typical rootfs markers (bin/, etc/, usr/),
// treat it as a versioned container.
func isVersionedTemplateDir(dir string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) == 0 {
		return false
	}

	// If the directory itself looks like a rootfs (has bin/ or etc/), it's flat
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		switch e.Name() {
		case "bin", "etc", "usr", "lib", "sbin", "var":
			return false // This IS a rootfs
		}
	}

	// Check if subdirectories look like versions (heuristic: they contain rootfs markers)
	// or if there are only directories (no files = likely a version container)
	hasFiles := false
	for _, e := range entries {
		if !e.IsDir() {
			hasFiles = true
			break
		}
	}

	if hasFiles {
		return false // Files at top level → likely a rootfs (flat)
	}

	// All entries are directories — check if any looks like a rootfs
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		subPath := filepath.Join(dir, e.Name())
		if isRootfsDir(subPath) {
			return true
		}
	}

	return false
}

// isRootfsDir checks if a directory looks like a root filesystem.
func isRootfsDir(dir string) bool {
	// Check for typical rootfs markers
	for _, marker := range []string{"bin", "etc", "usr"} {
		if info, err := os.Stat(filepath.Join(dir, marker)); err == nil && info.IsDir() {
			return true
		}
	}
	return false
}

// toClient builds the ORAS registry client. Credential selection and TLS
// transport are INDEPENDENT axes: basic auth / bearer token / anonymous pick
// the credential (first non-empty wins, in that order), while the cert/key
// pair (mTLS) and the CA file (server verification against a private CA)
// apply whenever set — so the common private-registry shapes all work:
// basic-auth + private CA, token + mTLS, CA-only, and so on. A cert without
// its key is rejected: it is always a configuration mistake, and silently
// falling back to anonymous would surface far away as an auth failure.
func (a AuthConfig) toClient() (*auth.Client, error) {
	client := &auth.Client{}

	switch {
	case a.Username != "" || a.Password != "":
		client.Credential = func(ctx context.Context, reg string) (auth.Credential, error) {
			return auth.Credential{
				Username: a.Username,
				Password: a.Password,
			}, nil
		}
	case a.Token != "":
		client.Credential = func(ctx context.Context, reg string) (auth.Credential, error) {
			return auth.Credential{
				AccessToken: a.Token,
			}, nil
		}
	default:
		client.Credential = auth.StaticCredential("", auth.EmptyCredential)
	}

	if a.CertFile == "" && a.KeyFile == "" && a.CAFile == "" {
		return client, nil
	}

	if (a.CertFile == "") != (a.KeyFile == "") {
		return nil, fmt.Errorf("registry TLS client cert requires both cert and key (got cert=%q key=%q)", a.CertFile, a.KeyFile)
	}

	tlsConfig := &tls.Config{}
	if a.CertFile != "" {
		cert, err := tls.LoadX509KeyPair(a.CertFile, a.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("load client cert: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	if a.CAFile != "" {
		caData, err := os.ReadFile(a.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read CA cert: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caData) {
			return nil, fmt.Errorf("read CA cert: no PEM certificates found in %s", a.CAFile)
		}
		tlsConfig.RootCAs = pool
	}

	client.Client = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}
	return client, nil
}

// packTarGz packages srcDir as a gzip-compressed tar. Every Close is explicit
// and its error propagated: the gzip/tar writers flush on Close, so an ENOSPC
// (or a failed final block write) surfaces ONLY there — a deferred Close that
// dropped it returned nil for a truncated archive, which PushTemplate then
// published to the registry as a complete layer.
func packTarGz(srcDir, dstPath string) error {
	f, err := os.Create(dstPath)
	if err != nil {
		return err
	}
	// closeAll closes in dependency order (tar → gzip → file), keeps the first
	// error, and is safe to call more than once. On the walk-error path it is
	// called explicitly; the deferred call then only releases the file.
	gzw := gzip.NewWriter(f)
	tw := tar.NewWriter(gzw)
	var closeErr error
	closed := false
	closeAll := func() error {
		if closed {
			return closeErr
		}
		closed = true
		if err := tw.Close(); err != nil {
			closeErr = fmt.Errorf("finish tar stream: %w", err)
		}
		if err := gzw.Close(); err != nil && closeErr == nil {
			closeErr = fmt.Errorf("finish gzip stream: %w", err)
		}
		if err := f.Close(); err != nil && closeErr == nil {
			closeErr = fmt.Errorf("close archive: %w", err)
		}
		return closeErr
	}
	defer func() {
		// Best-effort flush on an early return; the explicit call below is
		// what reports success-path errors.
		if !closed {
			_ = closeAll()
		}
	}()

	walkErr := filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		relPath, _ := filepath.Rel(srcDir, path)
		if relPath == "." {
			return nil
		}

		// A tenant can plant a FIFO (or socket/device) in its volume; a
		// template save preserves it, and os.Open on a FIFO blocks forever,
		// wedging PushTemplate and one provision slot. Only regular files,
		// directories, and symlinks are packaged.
		if !info.IsDir() && info.Mode()&os.ModeSymlink == 0 && !info.Mode().IsRegular() {
			return nil
		}

		// Read symlink target before creating header — FileInfoHeader doesn't
		// populate Linkname from os.FileInfo alone.
		linkTarget := ""
		if info.Mode()&os.ModeSymlink != 0 {
			linkTarget, err = os.Readlink(path)
			if err != nil {
				return fmt.Errorf("readlink %s: %w", path, err)
			}
		}

		header, err := tar.FileInfoHeader(info, linkTarget)
		if err != nil {
			return err
		}
		header.Name = relPath

		if err := tw.WriteHeader(header); err != nil {
			return err
		}

		if !info.IsDir() && info.Mode()&os.ModeSymlink == 0 {
			file, err := os.Open(path)
			if err != nil {
				return err
			}
			_, cerr := io.Copy(tw, file)
			if ferr := file.Close(); ferr != nil && cerr == nil {
				cerr = fmt.Errorf("close %s: %w", path, ferr)
			}
			return cerr
		}

		return nil
	})
	if walkErr != nil {
		return walkErr
	}
	return closeAll()
}

// materializeLayerFromTar is the single materialization point for overlay
// layers from an OCI archive: extract + apply the layer readability policy
// (NormalizeTemplateTree). The two steps must not be separable — a caller that
// extracts without normalizing reintroduces the EACCES-in-guest class for
// content whose tar modes carry no group bits (see NormalizeTemplateTree).
func materializeLayerFromTar(reader io.Reader, layerDir string) error {
	if err := extractTarGzToDir(reader, layerDir, extractOptions{}); err != nil {
		return err
	}
	changed, err := NormalizeTemplateTree(layerDir)
	if err != nil {
		return err
	}
	if changed > 0 {
		// The backstop repaired a non-contract-conformant artifact. Production
		// entry points normalize at the source (build scripts / SaveAsTemplate
		// via template-tool), so this is the observable signal that a template
		// arrived raw — a pulled artifact from outside the standard flow.
		slog.Warn("template: layer off-contract at materialization; normalized (producer should run template-tool normalize)",
			"path", layerDir, "entries", changed)
	}
	return nil
}

// NormalizeTemplateTree applies the TEMPLATE CONTRACT (see
// docs/operations/template-contract.md) to a materialized template tree and
// reports how many entries it changed. It makes a freshly materialized overlay
// layer (or a saved template's copied tree) readable by every consumer
// identity through the shared group.
//
// Every layer read happens under a service identity that is NOT the file's
// owner: prov materializes layers as sandprov (983), then the exec sandlot
// (985) mounts them as read-only lowerdirs and the virtio-fs passthrough
// daemon (sandvmm, 987, whose supplementary group IS the sandlot shared
// group) performs each guest file access. An entry with no group bits — a
// 0700 dir or a 0600/0400 file, common in agent-chmod'ed content (ssh keys,
// secrets) and in OCI images (/root is 0700, host keys 0600) — is EACCES for
// the daemon, i.e. EACCES inside every guest mounted from the template.
// The flat-volume materialization paths already apply this doctrine
// (copyDirRecursive and extractTarGzToDir's flatVolume branch add group
// bits); layers must not be the one place that keeps raw modes. Project-built
// templates are additionally normalized at the source (build/*.sh
// `chmod -R a+rX`), so this pass is what makes agent-saved and OCI-pulled
// content behave the same.
//
// Policy: directories get g+rx (the daemon needs traverse AND list); regular
// files mirror their owner bits into the group (g+r if u+r, g+x if u+x) —
// mirroring rather than unconditional keeps a deliberately inaccessible file
// (mode 0000) inaccessible while every usable file becomes group-readable.
// Group and other WRITE bits are cleared on every entry: a template layer is
// owner-write-only, so a tenant-chmod'ed 0777 file cannot let the rest of the
// shared volume group rewrite a layer every tenant boots from. Owner bits and
// setuid/setgid/sticky are preserved; symlink modes are irrelevant on Linux
// (their target's mode governs) and chmod would follow the link, so they are
// skipped. A SYMLINK ROOT is refused outright: WalkDir would visit it as a
// link and silently normalize nothing.
func NormalizeTemplateTree(root string) (changed int, err error) {
	if fi, lerr := os.Lstat(root); lerr != nil {
		return 0, lerr
	} else if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
		return 0, fmt.Errorf("template root %s is not a real directory", root)
	}
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		info, derr := d.Info()
		if derr != nil {
			return derr
		}
		mode := info.Mode()
		want := mode
		switch {
		case d.IsDir():
			want = (mode | 0o050) &^ 0o022
		case mode.IsRegular():
			if mode&0o400 != 0 {
				want |= 0o040
			}
			if mode&0o100 != 0 {
				want |= 0o010
			}
			want &^= 0o022
		default:
			return nil // FIFOs/sockets/devices: never read through the daemon
		}
		if want == mode {
			return nil
		}
		if cerr := os.Chmod(path, want); cerr != nil {
			return cerr
		}
		changed++
		return nil
	})
	return changed, err
}

// TemplateContractViolation names one entry that breaks the template contract.
type TemplateContractViolation struct {
	Path   string
	Mode   os.FileMode
	Reason string
}

// ValidateTemplateTree reports every entry of a template tree that violates
// the contract (NormalizeTemplateTree would have to change it). Used by the
// template-tool CLI's --check gate, by flat-template registration (warn), and
// by the tests that pin the contract. Read-only: never mutates.
func ValidateTemplateTree(root string) ([]TemplateContractViolation, error) {
	var out []TemplateContractViolation
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		info, derr := d.Info()
		if derr != nil {
			return derr
		}
		mode := info.Mode()
		switch {
		case d.IsDir():
			if mode&0o050 != 0o050 {
				out = append(out, TemplateContractViolation{
					Path: path, Mode: mode.Perm(),
					Reason: "directory not group traversable+listable (needs g+rx)",
				})
			}
		case mode.IsRegular():
			need := os.FileMode(0)
			if mode&0o400 != 0 {
				need |= 0o040
			}
			if mode&0o100 != 0 {
				need |= 0o010
			}
			if mode&need != need {
				out = append(out, TemplateContractViolation{
					Path: path, Mode: mode.Perm(),
					Reason: "file not group readable/executable for the reader identities (needs g+r/g+x mirroring the owner bits)",
				})
			}
		}
		if mode.Perm()&0o022 != 0 {
			out = append(out, TemplateContractViolation{
				Path: path, Mode: mode.Perm(),
				Reason: "group/other write bit set (template layers are owner-write-only)",
			})
		}
		return nil
	})
	return out, err
}

// unreadablePaths walks root as the CURRENT identity and returns up to max
// paths that cannot be listed (directories) or opened (regular files). It
// exists to turn `cp -a`'s opaque "exit status 1" on a flat volume carrying
// restrictive guest content (an agent's chmod 600/700) into an actionable
// error: the provision identity legitimately cannot read such content, and
// the operator needs to know WHICH paths to relax. Failure-path only.
func unreadablePaths(root string, max int) []string {
	var bad []string
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if len(bad) >= max {
			return fs.SkipAll
		}
		if err != nil {
			bad = append(bad, path)
			return nil
		}
		switch {
		case d.IsDir():
			f, err := os.Open(path)
			if err != nil {
				bad = append(bad, path)
				return fs.SkipDir
			}
			_, rerr := f.Readdirnames(1)
			f.Close()
			if rerr != nil && rerr != io.EOF {
				bad = append(bad, path)
				return fs.SkipDir
			}
		case d.Type().IsRegular():
			f, err := os.Open(path)
			if err != nil {
				bad = append(bad, path)
				return nil
			}
			f.Close()
		}
		return nil
	})
	return bad
}

// maxExtractedLayerBytes caps the decompressed size of one materialized
// layer — 8 GiB: above every legitimate rootfs layer, far below
// exhausting the shared store from one crafted blob. Package-level var so
// tests can shrink it (the safeMarginSec pattern).
var maxExtractedLayerBytes = int64(8) << 30

// maxExtractedLayerEntries caps the number of tar entries one materialized
// layer may contain: the byte cap alone bills an EMPTY file at 512 B
// (one header), so one legal-size blob can still mint ~16.7M inodes in the
// shared store — headers and inodes bill, not bytes. 2^20 = 1,048,576: a full
// distro rootfs is ~10^5 entries and even the largest legitimate dev images
// stay under ~3×10^5, so the cap leaves ~3× headroom over anything real while
// bounding the worst-case inode bill per layer at ~1M. Package-level var so
// tests can shrink it (the maxExtractedLayerBytes pattern).
var maxExtractedLayerEntries = 1 << 20

// cappedReader errors once more than `remaining` bytes have been read from
// the wrapped stream.
type cappedReader struct {
	r         io.Reader
	remaining int64
}

func (c *cappedReader) Read(p []byte) (int, error) {
	if c.remaining <= 0 {
		return 0, fmt.Errorf("layer exceeds the decompressed-size cap (%d bytes)", maxExtractedLayerBytes)
	}
	if int64(len(p)) > c.remaining {
		p = p[:c.remaining]
	}
	n, err := c.r.Read(p)
	c.remaining -= int64(n)
	return n, err
}

// tarModeToFileMode converts a tar header's raw Linux mode (which carries the
// S_ISUID/S_ISGID/S_ISVTX bits as 04000/02000/01000) into an os.FileMode that
// os.Chmod/open apply faithfully. os.FileMode(rawMode) silently DROPS those
// bits: Go's syscallMode only maps the ModeSetuid/ModeSetgid/ModeSticky FLAGS
// (1<<23..1<<20), never the raw values — so a 04755 setuid binary in a tar
// previously landed 0755 (fidelity bug: `su`/`umount` lose their setuid bit
// on a materialized rootfs; the local-seeding path via copyDirRecursive keeps
// it, so OCI-materialized content silently diverged).
func tarModeToFileMode(raw int64) os.FileMode {
	fm := os.FileMode(raw).Perm()
	if raw&0o4000 != 0 {
		fm |= os.ModeSetuid
	}
	if raw&0o2000 != 0 {
		fm |= os.ModeSetgid
	}
	if raw&0o1000 != 0 {
		fm |= os.ModeSticky
	}
	return fm
}

// extractOptions parameterizes extractTarGzToDir's on-disk policy.
type extractOptions struct {
	// flatVolume applies the writable-volume permission policy used when a
	// layer is materialized as a flat SandFS volume (as opposed to a shared
	// read-only overlay lowerdir): files become group-writable, directories
	// group-writable + setgid, and file mtimes are restored from the tar
	// headers — the same contract as the local-template seeding path
	// (copyDirRecursive in registry). Tar uid/gid are ALWAYS ignored by both
	// policies: extraction runs as the gateway identity, which is exactly
	// what the dedicated-identity model requires (the setgid volume root
	// keeps the group consistent without any chown).
	flatVolume bool
}

// extractTarGzToDir extracts a tar.gz stream into the target directory.
// The stream is expected to contain a rootfs directory tree.
//
// Security: this defends against Zip Slip / tar-symlink-to-anywhere attacks.
// A malicious tarball (e.g. from a compromised OCI registry) could craft an
// entry name like "../../etc/cron.d/evil" to write outside `dir`, or a symlink
// whose target escapes `dir` so a subsequent regular-file entry follows it and
// writes to an arbitrary host path. Every extracted path is validated to stay
// within `dir`; relative escaping symlinks are rejected and absolute symlinks
// are rewritten to tree-relative equivalents (so a follow-through write lands
// inside `dir` while guest-chroot semantics are unchanged). This runs as the
// gateway user, so a breakout is host RCE — the containment check is mandatory.
func extractTarGzToDir(reader io.Reader, dir string, opts extractOptions) error {
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return fmt.Errorf("resolve target dir: %w", err)
	}
	// Ensure the target directory exists before validating extracted paths
	// against it.
	if err := os.MkdirAll(absDir, 0755); err != nil {
		return fmt.Errorf("create target dir: %w", err)
	}
	sep := string(os.PathSeparator)

	// safeJoin joins dir + name and verifies the result stays within dir.
	// filepath.Join cleans ".." but does not reject it, so an entry like
	// "../../etc/x" would clean to "/etc/x" — outside dir. We catch that here.
	// A "." / empty / absolute entry resolves to the extraction ROOT itself:
	// a TypeSymlink with that name would remove the staging dir and replace it
	// with a symlink, which the layer publish would then accept (and the GC's
	// directory check would skip forever).
	safeJoin := func(name string) (string, error) {
		clean := filepath.Clean(name)
		if name == "" || clean == "." || filepath.IsAbs(name) {
			return "", fmt.Errorf("tar entry %q is a root or absolute entry", name)
		}
		target := filepath.Join(absDir, name)
		if target == absDir || !isWithinDir(target, absDir, sep) {
			return "", fmt.Errorf("tar entry %q escapes extraction dir", name)
		}
		return target, nil
	}

	gzr, err := gzip.NewReader(reader)
	if err != nil {
		return fmt.Errorf("create gzip reader: %w", err)
	}
	defer gzr.Close()

	// bound the DECOMPRESSED stream. A small hostile blob can expand
	// ~1000x (a 42KB layer wrote 41.9MB in the blind probe, no error); the
	// cap turns a cheap registry DoS on the shared store into a loud error.
	// 8 GiB sits far above any legitimate distro layer, far below "fill the
	// disk". The reader errors (not a silent truncation) so extraction fails
	// with a named cause.
	tr := tar.NewReader(&cappedReader{r: gzr, remaining: maxExtractedLayerBytes})
	entries := 0
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read tar entry: %w", err)
		}
		// Bound the entry COUNT as well as the bytes. Every tar
		// header costs at least 512 decompressed bytes, so the byte cap alone
		// admits ~16.7M empty-file entries — each one an inode in the shared
		// store. Loud error, not a silent stop.
		entries++
		if entries > maxExtractedLayerEntries {
			return fmt.Errorf("layer exceeds the entry-count cap (%d entries)", maxExtractedLayerEntries)
		}

		target, err := safeJoin(header.Name)
		if err != nil {
			return err
		}

		// Runtime-accurate symlink-ancestor containment: the lexical safeJoin above cannot see link
		// shifts. A "shallow link" compound (`q -> "."` then `q/x -> ".."`)
		// passes every lexical check yet resolves one level ABOVE the
		// extraction base at runtime — an arbitrary-write primitive for a
		// hostile registry, with err == nil throughout. Refuse ANY entry
		// (file/dir/link) whose ancestor path component is a symlink ON
		// DISK (this archive's own or a prior layer's): tar members under a
		// symlinked directory are pathological, and this is the only check
		// that is accurate regardless of lexical math.
		if hasSymlinkAncestor(absDir, target) {
			slog.Warn("tar extraction: skipping entry under a symlinked ancestor (containment)",
				"entry", header.Name, "target", target)
			continue
		}

		switch header.Typeflag {
		case tar.TypeDir:
			mode := os.FileMode(header.Mode)
			if err := os.MkdirAll(target, mode); err != nil {
				return fmt.Errorf("mkdir %s: %w", target, err)
			}
			if opts.flatVolume {
				// Group-writable + setgid, mirroring copyDirRecursive: the
				// volume is shared between the two service identities
				// (gateway seeds, sandlot serves, agent writes through), so
				// every directory must carry group access and propagate the
				// group. Chmod is required — MkdirAll applies the umask.
				if err := os.Chmod(target, mode.Perm()|0o2770|os.ModeSetgid); err != nil {
					return fmt.Errorf("chmod dir %s: %w", target, err)
				}
			} else {
				// Layer materialization is a DETERMINISTIC primitive: land the
				// tar's exact mode (setuid/setgid/sticky included) regardless
				// of the process umask, and let the caller's policy pass
				// (materializeLayerFromTar → normalizeLayerModes) decide the
				// sharing bits.
				//
				// The INHERITED setgid is preserved explicitly: the template
				// store is a setgid chain (store root 2770 root:<shared group>),
				// and that chain is how every entry below it gets the shared
				// GROUP — the grant the FUSE daemon (987) reads through.
				// Chmod-ing to the tar's own bits (which rarely carry setgid)
				// would break the chain for every descendant: their group
				// would fall back to the extracting process's gid (sandprov),
				// and the daemon would EACCES again.
				cur, err := os.Stat(target)
				if err != nil {
					return fmt.Errorf("stat dir %s: %w", target, err)
				}
				want := tarModeToFileMode(header.Mode)
				if cur.Mode()&os.ModeSetgid != 0 {
					want |= os.ModeSetgid
				}
				if err := os.Chmod(target, want); err != nil {
					return fmt.Errorf("chmod dir %s: %w", target, err)
				}
			}
		case tar.TypeReg:
			createMode := tarModeToFileMode(header.Mode)
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return fmt.Errorf("mkdir parent %s: %w", filepath.Dir(target), err)
			}
			// Tar semantics: a later regular-file entry REPLACES an earlier
			// symlink of the same name. Unlink it first — opening through it
			// (with or without O_NOFOLLOW) is wrong: following writes the
			// link target, refusing breaks legitimate layers that replace a
			// link with a file. After this Lstat, O_NOFOLLOW below is a
			// belt-and-braces check against a racing replacement.
			if fi, lerr := os.Lstat(target); lerr == nil && fi.Mode()&os.ModeSymlink != 0 {
				if rerr := os.Remove(target); rerr != nil {
					return fmt.Errorf("replace symlink %s: %w", target, rerr)
				}
			}
			// O_NOFOLLOW is load-bearing: the runtime symlink-ancestor check
			// above does not cover the FINAL component. A TypeSymlink entry
			// (or a hardlink to one, see TypeLink) can leave `target` as a
			// symlink; opening it without O_NOFOLLOW follows its target and
			// writes outside dir (the hardlink-relocation escape).
			f, err := os.OpenFile(target,
				os.O_CREATE|os.O_WRONLY|os.O_TRUNC|unix.O_NOFOLLOW, createMode)
			if err != nil {
				return fmt.Errorf("create file %s: %w", target, err)
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return fmt.Errorf("write file %s: %w", target, err)
			}
			f.Close()
			if opts.flatVolume {
				// Group-writable (0644→0664, 0755→0775): the agent must be
				// able to modify template content. Chmod after write — the
				// umask would otherwise strip the group-write bit at create.
				if err := os.Chmod(target, createMode|0o060); err != nil {
					return fmt.Errorf("chmod file %s: %w", target, err)
				}
				restoreMtime(target, header)
			} else {
				// Deterministic layer primitive (see the TypeDir branch):
				// exact tar mode incl. setuid/setgid/sticky, umask-independent.
				if err := os.Chmod(target, tarModeToFileMode(header.Mode)); err != nil {
					return fmt.Errorf("chmod file %s: %w", target, err)
				}
			}
		case tar.TypeSymlink:
			if target == absDir {
				return fmt.Errorf("symlink entry %q targets the extraction root itself", header.Name)
			}
			// Contain symlinks to the extraction dir. Relative targets that
			// escape dir (e.g. ../../etc) are rejected outright; ABSOLUTE
			// targets ("/usr/bin/mawk" — standard in distro rootfs layers, e.g.
			// /etc/alternatives/* or merged-/usr layout) are rewritten to an
			// equivalent tree-relative link so a later regular-file entry that
			// follows it still writes INSIDE dir instead of at the absolute
			// host path.
			linkname, err := normalizeLinkTarget(header.Linkname, target, absDir, sep)
			if err != nil {
				return fmt.Errorf("symlink %s -> %s: %w", target, header.Linkname, err)
			}
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return fmt.Errorf("mkdir parent %s: %w", filepath.Dir(target), err)
			}
			os.Remove(target) // remove if exists
			if err := os.Symlink(linkname, target); err != nil {
				return fmt.Errorf("create symlink %s: %w", target, err)
			}
		case tar.TypeLink:
			// Hard link target must also be within the extraction dir.
			linkTarget, err := safeJoin(header.Linkname)
			if err != nil {
				return fmt.Errorf("hardlink %s -> %s: %w", target, header.Linkname, err)
			}
			// link(2) does NOT follow a symlink source, so linking a symlink
			// entry creates a second name for the SYMLINK itself. That
			// relocates the link's relative target to the new parent without
			// re-validating it against dir: a source validated in a deep
			// directory (e.g. a/b/c/d/x -> ../../../../outside) resolves
			// OUTSIDE dir once hardlinked to dir/y, and a later TypeReg
			// through it writes outside the extraction tree. Such a hardlink
			// has no legitimate rootfs use; refuse it. Only regular files may
			// be hardlink sources.
			srcInfo, err := os.Lstat(linkTarget)
			if err != nil {
				return fmt.Errorf("hardlink %s -> %s: stat source: %w", target, header.Linkname, err)
			}
			if srcInfo.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("hardlink %s -> %s: refusing a hardlink to a symlink (it can relocate the link target outside the extraction dir)", target, header.Linkname)
			}
			if !srcInfo.Mode().IsRegular() {
				return fmt.Errorf("hardlink %s -> %s: source is not a regular file (%s)", target, header.Linkname, srcInfo.Mode().Type())
			}
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return fmt.Errorf("mkdir parent %s: %w", filepath.Dir(target), err)
			}
			os.Remove(target)
			if err := os.Link(linkTarget, target); err != nil {
				// Hard link may fail across devices; fall back to copy.
				// O_NOFOLLOW on both ends: the source was Lstat-checked as a
				// regular file, but open-by-path can race a replacement, and
				// the destination must not resolve a planted symlink.
				src, err := os.OpenFile(linkTarget, os.O_RDONLY|unix.O_NOFOLLOW, 0)
				if err != nil {
					return fmt.Errorf("hardlink fallback open %s: %w", linkTarget, err)
				}
				defer src.Close()
				dst, err := os.OpenFile(target,
					os.O_CREATE|os.O_WRONLY|os.O_TRUNC|unix.O_NOFOLLOW,
					tarModeToFileMode(header.Mode))
				if err != nil {
					return fmt.Errorf("hardlink fallback create %s: %w", target, err)
				}
				defer dst.Close()
				if _, err := io.Copy(dst, src); err != nil {
					return fmt.Errorf("hardlink fallback copy %s: %w", target, err)
				}
				if opts.flatVolume {
					if err := os.Chmod(target, tarModeToFileMode(header.Mode)|0o060); err != nil {
						return fmt.Errorf("chmod hardlink copy %s: %w", target, err)
					}
					restoreMtime(target, header)
				} else {
					// Deterministic layer primitive (see the TypeDir branch).
					if err := os.Chmod(target, tarModeToFileMode(header.Mode)); err != nil {
						return fmt.Errorf("chmod hardlink copy %s: %w", target, err)
					}
				}
			}
		}
	}

	return nil
}

// restoreMtime restores a flat-volume file's timestamps from its tar header
// (best-effort, matching copyDirRecursive's Utimes behavior — a filesystem
// that refuses utimes must not fail the whole extraction). Directories are
// skipped deliberately: their mtime keeps moving as entries land inside.
func restoreMtime(path string, header *tar.Header) {
	atime := header.AccessTime
	if atime.IsZero() {
		atime = header.ModTime
	}
	if header.ModTime.IsZero() {
		return
	}
	_ = os.Chtimes(path, atime, header.ModTime)
}

// isWithinDir reports whether target is equal to or inside dir. Both must be
// absolute and cleaned. The separator suffix ensures "dir" does not match a
// sibling like "dir-evil" (a prefix-only check would let "dir" + "../dir-evil"
// pass after cleaning).
// hasSymlinkAncestor reports whether any ancestor DIRECTORY component of
// target (between dir and target's own basename) is a symlink on disk.
// Runtime-accurate: unlike lexical path math, it consults the filesystem
// with Lstat, so a planted link shifts nothing past this check.
func hasSymlinkAncestor(dir, target string) bool {
	rel, err := filepath.Rel(dir, target)
	if err != nil || rel == "." || !strings.HasPrefix(target, dir+string(os.PathSeparator)) {
		return false // outside or the root itself — the caller's lexical checks govern
	}
	acc := dir
	for _, comp := range strings.Split(rel, string(os.PathSeparator))[:strings.Count(rel, string(os.PathSeparator))] {
		acc = filepath.Join(acc, comp)
		if fi, err := os.Lstat(acc); err == nil && fi.Mode()&os.ModeSymlink != 0 {
			return true
		}
	}
	return false
}

func isWithinDir(target, dir, sep string) bool {
	if target == dir {
		return true
	}
	return strings.HasPrefix(target, dir+sep)
}

// normalizeLinkTarget validates a tar symlink's Linkname and returns the
// linkname to create on disk. Relative targets are returned verbatim after
// verifying they resolve inside the extraction dir. ABSOLUTE targets are
// rewritten to an equivalent path-relative link: "/usr/bin/mawk" from
// <dir>/etc/alternatives/awk becomes "../../usr/bin/mawk". The rewritten
// resolution is identical inside the guest chroot (where the extraction dir
// is the rootfs root) but keeps host-side containment — an absolute link left
// on disk would resolve against the REAL filesystem during extraction, letting
// a later regular-file entry write through it anywhere on the host.
func normalizeLinkTarget(linkname, symlinkPath, dir, sep string) (string, error) {
	if linkname == "" {
		return "", fmt.Errorf("empty link target")
	}
	if filepath.IsAbs(linkname) {
		resolved := filepath.Join(dir, linkname)
		if !isWithinDir(resolved, dir, sep) {
			return "", fmt.Errorf("absolute link target %q escapes extraction dir", linkname)
		}
		rel, err := filepath.Rel(filepath.Dir(symlinkPath), resolved)
		if err != nil {
			return "", fmt.Errorf("relative link target for %q: %w", linkname, err)
		}
		return rel, nil
	}
	// Resolve the link relative to its parent directory and check containment.
	resolved := filepath.Join(filepath.Dir(symlinkPath), linkname)
	if !isWithinDir(resolved, dir, sep) {
		return "", fmt.Errorf("link target escapes extraction dir")
	}
	return linkname, nil
}

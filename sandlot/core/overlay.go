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

package core

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"common/util"
	"sandlot/vmm"
)

// --- OverlayFS read-only mount ---

// overlayRefEntry mirrors the template manager's RefEntry JSON format.
// Sandlot reads this directly from the refs/ directory to build the
// OverlayFS lowerdir list — no dependency on the gateway's template package.
type overlayRefEntry struct {
	Name        string   `json:"name"`
	Version     string   `json:"version"`
	Description string   `json:"description,omitempty"`
	Mode        string   `json:"mode,omitempty"` // "flat" | "overlay"; empty defaults to "overlay"
	Layers      []string `json:"layers"`
}

// splitRefForIdentity mirrors the template manager's parseTemplateRef for the
// identity check on a ref entry. A ref is "name:version"; a bare ref has the
// implicit version "local". validateRef upstream rejects extra colons, so a
// first-colon split is exact for every ref that reaches here.
func splitRefForIdentity(ref string) (name, version string) {
	if n, v, ok := strings.Cut(ref, ":"); ok {
		return n, v
	}
	return ref, "local"
}

// getCachedRefEntry loads a ref entry, using the in-memory cache if available.
// Template refs are immutable after creation, so the cache never needs invalidation.
// Searches for mode-suffixed ref files: refs/<name>_<version>.overlay.json first,
// then refs/<name>_<version>.flat.json (overlay is preferred for SandFS mounts).
func (h *Handler) getCachedRefEntry(templatesDir, ref string) (*overlayRefEntry, error) {
	h.overlayMu.RLock()
	if entry, ok := h.overlayCache[ref]; ok {
		h.overlayMu.RUnlock()
		return entry, nil
	}
	h.overlayMu.RUnlock()

	// Cache miss: search for mode-suffixed ref files on disk.
	refBase := util.RefToFilename(ref)
	var refData []byte
	for _, mode := range []string{"overlay", "flat"} {
		refFile := filepath.Join(templatesDir, "refs", refBase+"."+mode+".json")
		data, err := os.ReadFile(refFile)
		if err == nil {
			refData = data
			break
		}
	}
	if refData == nil {
		return nil, fmt.Errorf("ref file not found for template %s in %s/refs/", ref, templatesDir)
	}

	var entry overlayRefEntry
	if err := json.Unmarshal(refData, &entry); err != nil {
		return nil, fmt.Errorf("parse ref file for template %s: %w", ref, err)
	}
	// The ref filename encoding is not injective (':' and '_' both encode to
	// '_'): refs/a_b_c.overlay.json is reachable as "a:b_c" and "a_b:c". A
	// ref entry therefore has to prove which ref it belongs to; without this
	// check a ref written for one name:version is mounted for the other — a
	// cross-tenant rootfs substitution. Legacy entries with empty Name/Version
	// are accepted (the fields predate this check); every current writer fills
	// them.
	refName, refVersion := splitRefForIdentity(ref)
	if entry.Name != "" && entry.Version != "" &&
		(entry.Name != refName || entry.Version != refVersion) {
		return nil, fmt.Errorf(
			"ref file for template %s names %q:%q — refusing a colliding or tampered ref",
			ref, entry.Name, entry.Version)
	}
	if len(entry.Layers) == 0 {
		return nil, fmt.Errorf("template %s has no layers", ref)
	}
	// Refs files come from the control plane (template manager writes them;
	// an OCI pull or a peer node on the shared templates dir can too). The
	// layer IDs become overlayfs LOWERDIRS — mount anything the ref names
	// read-only into every guest created from the template. Trust boundary:
	// layer IDs must stay inside the templates dir (relative under layers/,
	// absolute within templatesDir — the local-template format). A ref naming
	// /etc or escaping via .. refuses to mount instead of exposing the host.
	// The symlink leg of the check happens at resolve time (EvalSymlinks
	// followed by containment), since a lexical path can pass while pointing
	// through a symlink.
	for i, layerID := range entry.Layers {
		if err := validateLayerID(templatesDir, layerID); err != nil {
			return nil, fmt.Errorf("template %s layer %d (%q): %w", ref, i, layerID, err)
		}
	}

	// Store in cache.
	h.overlayMu.Lock()
	h.overlayCache[ref] = &entry
	h.overlayMu.Unlock()
	return &entry, nil
}

// validateLayerID enforces the layer-ID trust boundary at ref-load time:
// relative IDs resolve under <templatesDir>/layers/, absolute IDs (the local
// template format) must already be inside templatesDir. Lexical check only —
// the symlink leg runs after EvalSymlinks in ensureReadonlyOverlayMounted.
func validateLayerID(templatesDir, layerID string) error {
	if layerID == "" {
		return fmt.Errorf("empty layer id")
	}
	// The id is interpolated into the overlay `lowerdir=` mount option, where
	// ':' separates lowerdirs and ',' separates mount options. A ref file is
	// untrusted input on the cross-instance/shared-store boundary: refuse the
	// separators before any path check (a crafted `x:/etc` would otherwise
	// pass the lexical containment walk and add /etc as a lowerdir).
	if strings.ContainsAny(layerID, ":,") {
		return fmt.Errorf("layer id %q contains a mount-option separator (':' or ',')", layerID)
	}
	if filepath.IsAbs(layerID) {
		if !pathWithin(layerID, templatesDir) {
			return fmt.Errorf("absolute path outside templates dir %s", templatesDir)
		}
		return nil
	}
	if !pathWithin(filepath.Join(templatesDir, "layers", layerID), filepath.Join(templatesDir, "layers")) {
		return fmt.Errorf("relative id escapes layers dir")
	}
	return nil
}

// pathWithin reports whether p is strictly inside dir (both cleaned,
// lexically; dir itself does not count).
func pathWithin(p, dir string) bool {
	rel, err := filepath.Rel(dir, p)
	if err != nil {
		return false
	}
	return rel != "." && !strings.HasPrefix(rel, "..")
}

// ensureReadonlyOverlayMounted mounts a read-only overlay at $volRoot/sandfs-xxx/rootfs
// using the template layers as lowerdir. No upperdir or workdir — this avoids
// the kernel's ovl_make_workdir() check, which rejects upperdirs on
// filesystems lacking RENAME_WHITEOUT + trusted.* xattr (NFS among them).
// All writable paths (workspace, home) are independent writable bind mounts
// handled by the warden.
//
// For overlay SandFS (has .template marker): mounts the read-only overlay.
// For flat SandFS (no .template marker): returns nil — bind-mount mode, no overlay needed.
//
// The overlay mount itself is host-local kernel state — it is not replicated
// or coordinated through the storage backend.
// Idempotent: if already mounted, returns nil. On successful mount (or if
// already mounted), the volumePath is recorded in mountedOverlays for the
// daily reaper to track.
// expectedRef is the template ref the gateway's identity record expects this
// volume to serve. The fast path compares it with the ref this node's overlay
// was mounted from (tracked per volume): a mismatch means the template was
// swapped while this node held the old overlay — the stale overlay is
// unmounted and remounted from the volume's .template marker (storage truth;
// the marker is written before the record in the attach flow). This is the
// swap-correctness backstop for nodes that were offline during a swap.
//
// An EMPTY expectedRef is a positive statement, not "no opinion": the
// gateway fills it from the identity record (MountTemplateRef) and sends ""
// exactly for flat sandfs — where the volume root IS the agent's chroot
// root, so anything at the marker path was written by the AGENT and must be
// ignored entirely (the first branch below; a planted symlink/FIFO would be
// a host read or a hang, and a planted regular file would flip the volume
// into an unresolvable overlay mount). A template swap never changes a flat
// record into an overlay one in place, so no legitimate flow needs the
// marker here. NOTE for future protocol work: because "" now DECIDES the
// mount mode, the field's zero value is semantic — a peer that predates the
// field omits it and would read as flat; add-only proto
// evolution does not cover that, which is why this shipped pre-release as a
// v1-defining semantic (see docs/reference/protocols.md).
//
// Returns the ref actually backing the mount ("" for flat volumes — no
// overlay).
func (h *Handler) ensureReadonlyOverlayMounted(volumePath, expectedRef string) (string, error) {
	sandfsDir := volumePath // volumePath is now $volRoot/sandfs-xxx
	mountDir := filepath.Join(sandfsDir, "rootfs")

	// No template expected (the gateway sends "" for flat records): mount
	// FLAT and ignore anything at the marker path. In flat mode the volume
	// root IS the agent's chroot root, so a `.template` there was written by
	// the agent, never by the storage plane — and a storage-plane marker is storage
	// truth only for overlay volumes. Do NOT follow it (a planted
	// symlink/FIFO is a host read / a hang — see util.ReadMarkerFile; a
	// planted regular file would flip the volume into an unresolvable
	// overlay mount) and do NOT delete it (inside a flat rootfs the name is
	// the agent's own file: e.g. a project directory or config template —
	// removing it would delete agent data).
	if expectedRef == "" {
		if _, err := os.Lstat(filepath.Join(sandfsDir, ".template")); err == nil {
			h.logger.Printf("overlay: %s has a .template marker but the record expects no template (flat SandFS) — ignoring it (the flat rootfs is agent-writable; the plane writes markers only for overlay volumes)", sandfsDir)
		}
		return "", nil
	}

	// Fast path: if we already track this overlay it is mounted — the map is
	// authoritative (cleanupHostOverlay trusts it too), so skip the
	// /proc/self/mountinfo scan that every cold mount would otherwise pay.
	// A tracked-ref mismatch with the expectation is a stale overlay from
	// before a template swap: tear it down and remount from the marker.
	h.overlayMu.RLock()
	trackedRef, tracked := h.mountedOverlays[sandfsDir]
	h.overlayMu.RUnlock()
	if tracked {
		if expectedRef == "" || trackedRef == expectedRef {
			return trackedRef, nil
		}
		h.logger.Printf("stale overlay at %s (mounted for %q, expected %q — template swapped while this node held it); remounting",
			mountDir, trackedRef, expectedRef)
		if err := h.cleanupHostOverlay(sandfsDir); err != nil {
			return "", fmt.Errorf("unmount stale overlay for %s: %w", sandfsDir, err)
		}
	}

	// Check if already mounted by reading /proc/self/mountinfo.
	if isMountPoint(mountDir) {
		// Already mounted (e.g. restored from mountinfo at startup without a
		// persisted ref): mount stays; read the marker to learn WHICH ref it
		// should serve. A marker/expectation disagreement remounts from the
		// marker (an untracked mount may predate a swap — never trust it).
		ref, flat, merr := readTemplateMarker(sandfsDir)
		if merr != nil {
			return "", merr
		}
		if flat {
			h.trackOverlay(sandfsDir, "")
			return "", nil
		}
		if expectedRef != "" && ref != expectedRef {
			if err := h.cleanupHostOverlay(sandfsDir); err != nil {
				return "", fmt.Errorf("unmount divergent overlay for %s: %w", sandfsDir, err)
			}
		} else {
			h.trackOverlay(sandfsDir, ref)
			return ref, nil
		}
	}

	// Read .template marker
	ref, flat, err := readTemplateMarker(sandfsDir)
	if err != nil {
		return "", err
	}
	if flat {
		// No template marker → bind-mount mode, no overlay needed
		return "", nil
	}

	if expectedRef != "" && ref != expectedRef {
		// The marker is storage truth (attach writes it before the record);
		// mount what it names and surface the divergence.
		h.logger.Printf("overlay marker for %s names %q but the gateway expects %q — mounting the marker's ref (divergent record?)",
			sandfsDir, ref, expectedRef)
	}

	// Load ref entry to get layers. vmmCfg is read under h.mu: UpdateVMMConfig
	// (hot-reload) rewrites the whole struct under the same lock, and an
	// unguarded read is a data race (same class wardenCountdown guards against).
	h.mu.RLock()
	templatesDir := h.vmmCfg.TemplatesDir
	volumesDir := h.vmmCfg.VolumesDir
	h.mu.RUnlock()
	if templatesDir == "" {
		// Same resolution as the prov side (cmd/main.go): the store's
		// default is the sibling templates/ directory beside the volumes
		// dir — same filesystem as the volume tree, so shared-storage
		// deployments cover it. The legacy /var/sandswap/templates is
		// gone: node prep never created it, so this fallback would hunt
		// layers in a directory that does not exist.
		templatesDir = filepath.Join(filepath.Dir(volumesDir), "templates")
	}
	entry, err := h.getCachedRefEntry(templatesDir, ref)
	if err != nil {
		return "", fmt.Errorf("load ref %s: %w", ref, err)
	}

	// Build lowerdir list
	var lowerdirs []string
	// The templates dir itself may be a symlink — resolve the ROOT once so the
	// per-layer containment check below compares like with like.
	resolvedRoot, err := filepath.EvalSymlinks(templatesDir)
	if err != nil {
		return "", fmt.Errorf("resolve templates dir %s: %w", templatesDir, err)
	}
	for _, layerID := range entry.Layers {
		layerPath := resolveLayerPath(templatesDir, layerID)
		resolved, err := filepath.EvalSymlinks(layerPath)
		if err != nil {
			return "", fmt.Errorf("resolve layer path %s: %w", layerID, err)
		}
		// Symlink leg of the layer-ID trust boundary: the lexical check at
		// ref-load time passed, but the path may traverse a symlink out of the
		// templates dir — a layer symlinked to /etc must refuse to mount, not
		// expose the host read-only into the guest.
		if !pathWithin(resolved, resolvedRoot) {
			return "", fmt.Errorf("layer %q resolves to %s, outside templates dir %s", layerID, resolved, resolvedRoot)
		}
		lowerdirs = append(lowerdirs, resolved)
	}

	// Linux kernel requires at least 2 lowerdirs when upperdir is absent
	// ("overlayfs: at least 2 lowerdir are needed while upperdir nonexistent").
	// If there's only one layer, append an empty directory as a second lowerdir.
	// The empty lowerdir contributes no files and has no semantic effect.
	if len(lowerdirs) < 2 {
		emptyDir := filepath.Join(templatesDir, ".empty-layer")
		if err := os.MkdirAll(emptyDir, 0755); err != nil {
			return "", fmt.Errorf("mkdir empty lowerdir %s: %w", emptyDir, err)
		}
		// Explicit chmod: both dirs below sit on the cross-identity read path
		// (the FUSE daemon resolves through them), and MkdirAll would apply a
		// restrictive umask — 0700 would lock the daemon out of the mount.
		// fd-relative: a sibling could swap the just-created entry for a
		// symlink between MkdirAll and chmod; O_NOFOLLOW refuses it.
		efd, oerr := unix.Open(emptyDir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if oerr != nil {
			return "", fmt.Errorf("open empty lowerdir %s: %w", emptyDir, oerr)
		}
		cerr := unix.Fchmod(efd, 0o755)
		unix.Close(efd)
		if cerr != nil {
			return "", fmt.Errorf("chmod empty lowerdir %s: %w", emptyDir, cerr)
		}
		lowerdirs = append(lowerdirs, emptyDir)
	}

	// Create/open the mount point without following a symlink at either the
	// volume root or `rootfs`. In flat mode the volume root IS the agent's
	// chroot, so a planted `rootfs -> <host dir>` would otherwise turn the
	// mkdir/chmod/mount below into a host mount primitive on an arbitrary
	// path. The O_PATH fd pins the directory for the mount call.
	mountFd, mountTarget, err := prepareOverlayMountDir(sandfsDir)
	if err != nil {
		return "", err
	}
	defer unix.Close(mountFd)

	// Mount read-only overlay (no upperdir, no workdir). The target is the
	// /proc/self/fd magic link, so no path component is re-resolved.
	opts := fmt.Sprintf("lowerdir=%s,ro", strings.Join(lowerdirs, ":"))
	if err := syscall.Mount("overlay", mountTarget, "overlay", syscall.MS_RDONLY, opts); err != nil {
		// EBUSY means already mounted (race with concurrent call) — treat as
		// success; the trackOverlay below lands the tracking (idempotent map
		// write, so double-tracking is harmless).
		if err == syscall.EBUSY {
			h.trackOverlay(sandfsDir, ref)
			return ref, nil
		}
		return "", fmt.Errorf("mount read-only overlay at %s: %w", mountDir, err)
	}

	h.logger.Printf("mounted read-only overlay at %s for template %s (%d layers)", mountDir, ref, len(lowerdirs))

	// Track this mount for the overlay reaper. Only this node's overlays
	// are tracked — the reaper iterates this set, not the shared filesystem.
	h.trackOverlay(sandfsDir, ref)
	return ref, nil
}

// readTemplateMarker reads the volume's .template marker. flat=true means a
// flat volume (no overlay). A missing volume dir is an error; a missing
// marker in an existing dir is the flat case.
func readTemplateMarker(sandfsDir string) (ref string, flat bool, err error) {
	marker := filepath.Join(sandfsDir, ".template")
	// Symlink/FIFO/oversized-safe read: in flat mode the volume root IS the
	// agent's chroot root, so the marker path is agent-writable. Following a
	// planted symlink would read a host file; opening a planted FIFO would
	// block this mount path forever. A non-regular entry is never a marker
	// the storage plane wrote — treat it as "no marker" (the flat volume keeps
	// working) instead of following or blocking on it.
	data, ok, err := util.ReadMarkerFile(marker)
	if err != nil {
		if os.IsNotExist(err) {
			if _, derr := os.Stat(sandfsDir); derr != nil {
				return "", false, fmt.Errorf("volume dir %s: %w", sandfsDir, derr)
			}
			return "", true, nil // existing dir, no marker: flat volume
		}
		return "", false, err
	}
	if !ok {
		log.Printf("overlay: %s is not a regular marker file (planted symlink/FIFO/oversized?) — treating as flat", marker)
		return "", true, nil
	}
	if len(data) == 0 {
		return "", true, nil
	}
	return strings.TrimSpace(string(data)), false, nil
}

// trackOverlay records (and persists) the ref backing a volume's overlay on
// this node. Persistence (overlays.json, atomic tmp+rename, same discipline
// as state.json) lets a restart restore not just the mounted set but WHICH
// template each mount serves — the swap-staleness fast path depends on it (a
// restored mount with an unknown ref forces one remount on its next cold
// mount). Best-effort: a persistence failure only costs that remount.
func (h *Handler) trackOverlay(volumePath, ref string) {
	h.overlayMu.Lock()
	h.mountedOverlays[volumePath] = ref
	h.overlayMu.Unlock()
	h.persistOverlays()
}

// overlaysStatePath is the node-local persistence file for the overlay
// tracking map. Lives in the instance's PRIVATE state root beside state.json —
// node-local by design (the map describes THIS node's host-local mounts) and
// out of the group-writable sandbox tree, where a planted symlink would
// redirect the load.
func (h *Handler) overlaysStatePath() string {
	if h.SandboxRoot == "" {
		return ""
	}
	return filepath.Join(StateRootFor(h.SandboxRoot), "overlays.json")
}

// persistedOverlays is the JSON shape of overlays.json.
type persistedOverlays struct {
	// Mounted maps volumePath → template ref ("" = flat/unknown).
	Mounted map[string]string `json:"mounted"`
}

// persistOverlays writes the tracking map atomically (tmp+rename).
func (h *Handler) persistOverlays() {
	path := h.overlaysStatePath()
	if path == "" {
		return
	}
	h.overlayMu.RLock()
	snapshot := make(map[string]string, len(h.mountedOverlays))
	for k, v := range h.mountedOverlays {
		snapshot[k] = v
	}
	h.overlayMu.RUnlock()
	_ = PersistOverlayRefs(path, snapshot)
}

// loadPersistedOverlays reads overlays.json (missing file = empty map). The
// file sits in a privileged state dir but the path may have been swapped: open
// O_NOFOLLOW, require a regular file, and bound the read.
func loadPersistedOverlays(path string) map[string]string {
	out := map[string]string{}
	if path == "" {
		return out
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return out
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > 1<<20 {
		return out
	}
	data, err := io.ReadAll(io.LimitReader(f, 1<<20))
	if err != nil {
		return out
	}
	var p persistedOverlays
	if json.Unmarshal(data, &p) != nil || p.Mounted == nil {
		return out
	}
	return p.Mounted
}

// PersistOverlayRefs writes an overlay-tracking map to path atomically
// (tmp+rename). Exported for the boxout sidecar, which holds its own
// OverlaySet and persists it beside its socket. Best-effort semantics at
// every caller: a failure only costs one remount after the next restart.
func PersistOverlayRefs(path string, m map[string]string) error {
	if path == "" {
		return nil
	}
	data, err := json.Marshal(persistedOverlays{Mounted: m})
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	// The private state root may not exist yet (tmpfs after a reboot).
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".overlays-*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }()
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	return nil
}

// LoadOverlayRefs reads a persisted overlay-tracking map (missing file =
// empty). The boxout mirror of loadPersistedOverlays.
func LoadOverlayRefs(path string) map[string]string {
	return loadPersistedOverlays(path)
}

// Snapshot returns a copy of the tracking map (path → ref).
func (s *OverlaySet) Snapshot() map[string]string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]string, len(s.mounted))
	for k, v := range s.mounted {
		out[k] = v
	}
	return out
}

// isMountPoint checks if a path is currently a mount point by reading
// /proc/self/mountinfo. Used by ensureReadonlyOverlayMounted (idempotency
// check) and by cleanupHostOverlay (skip if not mounted). Not used by the
// reaper — the reaper iterates the in-memory mountedOverlays set instead.
func isMountPoint(path string) bool {
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return false
	}
	path = strings.TrimSuffix(path, "/")
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 5 && fields[4] == path {
			return true
		}
	}
	return false
}

// resolveLayerPath resolves a layer ID to an absolute path.
// If the layerID is an absolute path, return it as-is (local template).
// Otherwise, treat it as relative to templatesDir/layers/.
func resolveLayerPath(templatesDir, layerID string) string {
	if filepath.IsAbs(layerID) {
		return layerID
	}
	return filepath.Join(templatesDir, "layers", layerID)
}

// --- Host-side overlay cleanup ---

// cleanupHostOverlay unmounts a read-only overlay at <volumePath>/rootfs/.
// Called by the CleanupOverlay RPC (gateway requests this before deleting a SandFS)
// and by the periodic overlay reaper for stale mounts.
// Idempotent: returns nil if the overlay is not mounted.
// Removes the volumePath from the in-memory mountedOverlays set on success.
//
// Performance: skips the isMountPoint scan of /proc/self/mountinfo when the
// volumePath is in the mountedOverlays set (reaper path — already known to be
// mounted). Only the RPC path (volumePath may not be on this node) falls back
// to isMountPoint.
// prepareOverlayMountDir creates/opens <volume>/rootfs and returns its O_PATH
// fd plus the /proc/self/fd target to mount on. The volume root and the
// `rootfs` entry are both opened component-wise with O_NOFOLLOW|O_DIRECTORY:
// in flat mode the tenant can replace either with a symlink, and a path-based
// mkdir/chmod/mount would follow it into a host path. Mkdirat on an existing
// symlink returns EEXIST and the following O_NOFOLLOW open refuses it.
func prepareOverlayMountDir(volumePath string) (int, string, error) {
	vfd, err := unix.Open(volumePath, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, "", fmt.Errorf("open volume dir %s (symlink or non-directory?): %w", volumePath, err)
	}
	defer unix.Close(vfd)

	if err := unix.Mkdirat(vfd, "rootfs", 0o755); err != nil && !errors.Is(err, unix.EEXIST) {
		return -1, "", fmt.Errorf("mkdir mount point %s/rootfs: %w", volumePath, err)
	}
	fd, err := unix.Openat(vfd, "rootfs", unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, "", fmt.Errorf("open mount point %s/rootfs (planted symlink or non-directory?): %w", volumePath, err)
	}
	// chmod needs a real (non-O_PATH) fd; keep the same no-follow walk.
	cfd, err := unix.Openat(vfd, "rootfs", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		unix.Close(fd)
		return -1, "", fmt.Errorf("open mount point %s/rootfs for chmod: %w", volumePath, err)
	}
	if err := unix.Fchmod(cfd, 0o755); err != nil {
		unix.Close(cfd)
		unix.Close(fd)
		return -1, "", fmt.Errorf("chmod mount point %s/rootfs: %w", volumePath, err)
	}
	unix.Close(cfd)
	return fd, fmt.Sprintf("/proc/self/fd/%d", fd), nil
}

// openVerifiedMountTarget opens <volume>/rootfs O_PATH|O_NOFOLLOW for an
// unmount, returning ok=false when the entry is absent or is not a real
// directory. A symlink must never reach umount2 (the final component is
// agent-controlled in a flat volume).
func openVerifiedMountTarget(volumePath string) (fd int, target string, ok bool) {
	vfd, err := unix.Open(volumePath, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, "", false
	}
	defer unix.Close(vfd)
	rfd, err := unix.Openat(vfd, "rootfs", unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, "", false
	}
	return rfd, fmt.Sprintf("/proc/self/fd/%d", rfd), true
}

func (h *Handler) cleanupHostOverlay(volumePath string) error {
	mountDir := filepath.Join(volumePath, "rootfs")

	// Fast path: if we're tracking this overlay, go straight to unmount
	// without scanning /proc/self/mountinfo (saves ~0.5-5ms at scale).
	h.overlayMu.RLock()
	_, tracked := h.mountedOverlays[volumePath]
	h.overlayMu.RUnlock()

	if !tracked {
		// Not tracked — either (a) this node never mounted it (RPC for a
		// different node's overlay), or (b) it was already unmounted
		// externally. Check mountinfo to distinguish.
		if !isMountPoint(mountDir) {
			return nil
		}
	}

	// Unmount through an O_PATH fd, not the path string: the final component
	// is inside an agent-writable volume and umount2(2) follows a symlink.
	targetFd, target, ok := openVerifiedMountTarget(volumePath)
	if !ok {
		// Missing or replaced by a symlink/non-directory: there is no mount
		// point we can safely name. Drop the tracking entry and move on.
		h.untrackOverlay(volumePath)
		return nil
	}
	defer unix.Close(targetFd)
	if err := syscall.Unmount(target, syscall.MNT_DETACH); err != nil {
		// EINVAL: not a mount point (already unmounted externally).
		// ENOENT: mount point directory doesn't exist (SandFS deleted on the
		// shared backend).
		// Both are harmless — clean up the tracking set and return success.
		if err == syscall.EINVAL || err == syscall.ENOENT {
			h.untrackOverlay(volumePath)
			return nil
		}
		return fmt.Errorf("unmount overlay at %s: %w", mountDir, err)
	}
	h.untrackOverlay(volumePath)
	h.logger.Printf("cleaned up host overlay at %s", mountDir)
	return nil
}

// untrackOverlay drops a volume from the tracking map. Deliberately does NOT
// persist: the restore path (restoreMountedOverlaysFromMountinfo) treats
// /proc/self/mountinfo as the existence truth and MergeRefs only fills refs
// for mounts that actually exist — a stale persisted entry for an unmounted
// overlay is dropped at restore, so writing the file on every unmount (the
// per-idle-cycle lease-expiry path!) buys nothing. The in-memory delete is
// enough; the next track-side persist rewrites a clean map.
func (h *Handler) untrackOverlay(volumePath string) {
	h.overlayMu.Lock()
	delete(h.mountedOverlays, volumePath)
	h.overlayMu.Unlock()
}

// restoreMountedOverlaysFromMountinfo rebuilds the in-memory mountedOverlays map
// by parsing /proc/self/mountinfo for overlay mounts under the volumes
// directory, MERGED with the persisted overlays.json ref map: mountinfo says
// a mount exists, the persisted map says WHICH template ref it serves. A
// mount with no persisted ref (deleted/absent state file, first run after
// this change) restores with an unknown ref ("") — its next cold mount
// remounts once from the marker (the safe direction: never trust an
// unattributed mount after a template swap). Called once at startup (in
// ReadoptVMs) to recover after a sandlot restart. This is the ONLY time we
// scan mountinfo — the periodic reaper only iterates the in-memory map,
// which is O(this node's mounts) not O(all SandFS on shared storage).
func (h *Handler) restoreMountedOverlaysFromMountinfo() {
	// Under h.mu for the same reason as ensureReadonlyOverlayMounted's
	// TemplatesDir read: UpdateVMMConfig replaces the struct on hot-reload.
	h.mu.RLock()
	volumesDir := h.vmmCfg.VolumesDir
	h.mu.RUnlock()
	if volumesDir == "" {
		volumesDir = "/var/sandswap/volumes"
	}

	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return
	}

	paths := parseOverlayMountsFromMountinfo(data, volumesDir)
	if len(paths) == 0 {
		return
	}
	persisted := loadPersistedOverlays(h.overlaysStatePath())
	h.overlayMu.Lock()
	for _, p := range paths {
		h.mountedOverlays[p] = persisted[p] // "" when unknown
	}
	h.overlayMu.Unlock()
	h.logger.Printf("restored %d mounted overlay entries from mountinfo (%d with a known template ref)",
		len(paths), countKnownRefs(persisted, paths))
}

// countKnownRefs counts how many restored paths carry a persisted ref.
func countKnownRefs(persisted map[string]string, paths []string) int {
	n := 0
	for _, p := range paths {
		if persisted[p] != "" {
			n++
		}
	}
	return n
}

// parseOverlayMountsFromMountinfo extracts volume paths from mountinfo data for
// overlay mounts under volumesDir that are at <volumesDir>/<id>/rootfs.
// Extracted as a pure function for testability.
func parseOverlayMountsFromMountinfo(data []byte, volumesDir string) []string {
	var paths []string
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 9 {
			continue
		}
		// fields[4] = mount point, fields[8] = filesystem type
		mountPoint := fields[4]
		fsType := fields[8]
		if fsType != "overlay" {
			continue
		}
		// Match overlay mounts at <volumesDir>/<sandfs-id>/rootfs
		if !strings.HasPrefix(mountPoint, volumesDir+"/") {
			continue
		}
		rel := strings.TrimPrefix(mountPoint, volumesDir+"/")
		parts := strings.SplitN(rel, "/", 2)
		if len(parts) != 2 || parts[1] != "rootfs" {
			continue
		}
		paths = append(paths, filepath.Join(volumesDir, parts[0]))
	}
	return paths
}

// cleanupStaleOverlays checks only the overlays tracked in the in-memory
// mountedOverlays set (populated by ensureReadonlyOverlayMounted and restored
// from mountinfo at startup). For each tracked overlay, if the .template marker
// is gone (SandFS deleted on shared storage), unmount the stale overlay.
//
// This is O(this node's mounts) — typically tens to low hundreds — not O(all
// SandFS directories on shared storage), which could be hundreds of thousands.
// Processing is batched (reaperBatchSize per tick) to avoid blocking the main
// loop when there are many stale mounts.
func (h *Handler) cleanupStaleOverlays() {
	h.overlayMu.RLock()
	paths := make([]string, 0, len(h.mountedOverlays))
	for p := range h.mountedOverlays {
		paths = append(paths, p)
	}
	h.overlayMu.RUnlock()

	var cleaned, failed int
	for i, volumePath := range paths {
		// Check if the SandFS still has a .template marker on shared storage.
		// If .template is gone, the SandFS was deleted → stale overlay.
		// Lstat: presence of the ENTRY is what matters, never follow it (only
		// overlay volumes are tracked here, and their roots are not
		// agent-writable — this is the same no-follow discipline as
		// util.ReadMarkerFile, kept uniform).
		templateMarker := filepath.Join(volumePath, ".template")
		if _, err := os.Lstat(templateMarker); err == nil {
			continue // still a valid overlay SandFS
		}
		// Also check: if the volume directory itself is gone, definitely stale.
		// On a network filesystem, a deleted directory may appear as a stale file handle or
		// an empty dir — either way, .template is gone, so we unmount.
		if err := h.cleanupHostOverlay(volumePath); err != nil {
			h.logger.Printf("reaper: failed to unmount stale overlay at %s: %v", volumePath, err)
			failed++
		} else {
			cleaned++
		}

		// Batch pause: yield every reaperBatchSize entries to avoid holding
		// CPU/lock for too long when there are many stale mounts.
		if (i+1)%reaperBatchSize == 0 {
			time.Sleep(reaperBatchPause)
		}
	}
	if cleaned > 0 || failed > 0 {
		h.logger.Printf("reaper: cleaned %d stale overlays (%d failed)", cleaned, failed)
	}
}

// StartOverlayReaper starts the daily overlay reaper goroutine. Called by
// runServeLoop after the gateway stream is connected. The reaper scans only the
// in-memory mountedOverlays set (not the shared filesystem), so it scales to
// large deployments without scanning hundreds of thousands of shared-storage
// entries.
func (h *Handler) StartOverlayReaper(done <-chan struct{}) {
	go func() {
		ticker := time.NewTicker(reaperInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				h.cleanupStaleOverlays()
			case <-done:
				return
			}
		}
	}()
}

// reaperInterval is how often the overlay reaper scans for stale mounts.
// Daily: this is a pure fallback mechanism. The CleanupOverlay RPC handles the
// normal case (gateway sends it before deleting a SandFS), and the startup
// sweep in ReadoptVMs handles the offline-during-delete case. The reaper only
// needs to catch edge cases that slip through both layers.
const reaperInterval = 24 * time.Hour

// reaperBatchSize is the number of overlay checks before yielding.
const reaperBatchSize = 100

// reaperBatchPause is the sleep between batches to avoid blocking.
const reaperBatchPause = 100 * time.Millisecond

// --- Shared overlay tracking (exported for the boxout sidecar) ---

// OverlaySet tracks which volume paths currently carry a host-side read-only
// overlay mount, and WHICH template ref each mount serves (the swap-
// staleness fast path compares it with the expected ref carried by every
// mount command). Embedded mode keeps this state on the Handler
// (h.mountedOverlays, persisted to overlays.json); in Kubernetes/boxout mode
// the mounts happen in the sidecar process, so the sidecar holds its own set
// (best-effort persisted beside its socket). The recovery (mountinfo parse)
// and stale-reaping (marker check + batched unmount) semantics live here
// once so both modes share them exactly.
//
// The set is the reaper's whole world: cleanup iterates ONLY tracked paths —
// O(this node's mounts), never O(all SandFS on shared storage).
type OverlaySet struct {
	mu      sync.RWMutex
	mounted map[string]string // volumePath → template ref ("" = flat/unknown)
	logger  *log.Logger
}

// NewOverlaySet creates an empty tracking set. A nil logger is tolerated
// (methods stay silent).
func NewOverlaySet(logger *log.Logger) *OverlaySet {
	return &OverlaySet{
		mounted: make(map[string]string),
		logger:  logger,
	}
}

// Track records volumePath as carrying a live overlay mount serving ref
// ("" = unknown) — idempotent.
func (s *OverlaySet) Track(volumePath, ref string) {
	s.mu.Lock()
	s.mounted[volumePath] = ref
	s.mu.Unlock()
}

// Untrack drops volumePath from the tracking set (idempotent).
func (s *OverlaySet) Untrack(volumePath string) {
	s.mu.Lock()
	delete(s.mounted, volumePath)
	s.mu.Unlock()
}

// RefOf returns the tracked template ref for volumePath ("" when untracked or
// tracked-with-unknown-ref).
func (s *OverlaySet) RefOf(volumePath string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.mounted[volumePath]
}

// Tracked returns a snapshot of the tracked volume paths.
func (s *OverlaySet) Tracked() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.mounted))
	for p := range s.mounted {
		out = append(out, p)
	}
	return out
}

// RestoreFromMountinfoData rebuilds the tracking set from raw mountinfo bytes:
// overlay mounts at <volumesDir>/<sandfs-id>/rootfs become tracked entries
// with UNKNOWN refs ("" — a restored mount's ref cannot be derived from
// mountinfo; the caller merges a persisted ref map separately, or leaves the
// entry unknown and the next mount command's expected-ref check remounts
// once). Data-injected form of RestoreFromMountinfo so the parse-and-track
// behavior is unit-testable without a live mount namespace.
func (s *OverlaySet) RestoreFromMountinfoData(data []byte, volumesDir string) int {
	paths := parseOverlayMountsFromMountinfo(data, volumesDir)
	s.mu.Lock()
	for _, p := range paths {
		s.mounted[p] = ""
	}
	s.mu.Unlock()
	return len(paths)
}

// MergeRefs fills the ref for tracked paths that a persisted state file
// attributes (mountinfo says the mount exists; the persisted map says what it
// serves). Untracked paths in the persisted map are ignored — mountinfo is
// the existence truth.
func (s *OverlaySet) MergeRefs(persisted map[string]string) int {
	s.mu.Lock()
	n := 0
	for p, ref := range persisted {
		if _, ok := s.mounted[p]; ok && ref != "" {
			s.mounted[p] = ref
			n++
		}
	}
	s.mu.Unlock()
	return n
}

// RestoreFromMountinfo rebuilds the tracking set from this process's
// /proc/self/mountinfo. For boxout this is the authoritative source: the
// sidecar's mount namespace is where the overlays live in Kubernetes mode.
// Returns the number of restored entries.
func (s *OverlaySet) RestoreFromMountinfo(volumesDir string) int {
	if volumesDir == "" {
		volumesDir = "/var/sandswap/volumes"
	}
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return 0
	}
	n := s.RestoreFromMountinfoData(data, volumesDir)
	if n > 0 && s.logger != nil {
		s.logger.Printf("restored %d mounted overlay entries from mountinfo", n)
	}
	return n
}

// CleanupStale unmounts tracked overlays whose SandFS has been deleted (the
// .template marker is gone on shared storage). unmount performs the actual
// host-side unmount (core.UnmountOverlay at the call site — injected so tests
// need no CAP_SYS_ADMIN). Returns (cleaned, failed). Batched exactly like the
// embedded reaper (reaperBatchSize per pause) so a large stale set never
// blocks the caller's event loop for long.
func (s *OverlaySet) CleanupStale(unmount func(volumePath string) error) (cleaned, failed int) {
	s.mu.RLock()
	paths := make([]string, 0, len(s.mounted))
	for p := range s.mounted {
		paths = append(paths, p)
	}
	s.mu.RUnlock()

	for i, volumePath := range paths {
		if !overlayStale(volumePath) {
			continue // still a valid overlay SandFS
		}
		if err := unmount(volumePath); err != nil {
			failed++
			if s.logger != nil {
				s.logger.Printf("overlay sweep: failed to unmount stale overlay at %s: %v", volumePath, err)
			}
		} else {
			s.Untrack(volumePath)
			cleaned++
		}
		if (i+1)%reaperBatchSize == 0 {
			time.Sleep(reaperBatchPause)
		}
	}
	if (cleaned > 0 || failed > 0) && s.logger != nil {
		s.logger.Printf("overlay sweep: cleaned %d stale overlays (%d failed)", cleaned, failed)
	}
	return cleaned, failed
}

// overlayStale reports whether the SandFS at volumePath no longer needs its
// overlay: the .template marker is gone (SandFS deleted, or recreated flat).
// On a network filesystem a deleted directory surfaces the same way (missing marker / stale
// handle), so one check covers both.
func overlayStale(volumePath string) bool {
	// Lstat: existence of the entry is what matters; never follow it (see
	// util.ReadMarkerFile for why marker paths are treated as untrusted).
	_, err := os.Lstat(filepath.Join(volumePath, ".template"))
	return err != nil
}

// OverlayReaperInterval is the exported form of reaperInterval, shared by the
// boxout sidecar's periodic sweep so both modes reap on the same cadence.
const OverlayReaperInterval = reaperInterval

// --- Exported wrappers for boxout ---

// MountOverlay mounts (or verifies) a read-only overlay at <volumePath>/rootfs
// and returns the template ref backing the mount. Exported for boxout to call
// (it has CAP_SYS_ADMIN for syscall.Mount). expectedRef is the gateway's
// expectation from the identity record ("" = no opinion); trackedRef is the
// caller's tracking-set value for this volume ("" = unknown/untracked). A
// tracked/expected mismatch — or an untracked mount whose marker disagrees
// with the expectation — remounts from the marker (storage truth).
func MountOverlay(volumePath, templatesDir, expectedRef, trackedRef string) (string, error) {
	h := &Handler{
		vmmCfg: vmm.Config{
			TemplatesDir: templatesDir,
		},
		logger:          log.New(os.Stderr, "[boxout-overlay] ", log.LstdFlags),
		overlayCache:    make(map[string]*overlayRefEntry),
		mountedOverlays: make(map[string]string),
	}
	if trackedRef != "" {
		// Seed the tracking so the ensure's fast path can compare — the
		// caller's set already knows this mount exists and what it serves.
		h.mountedOverlays[volumePath] = trackedRef
	}
	return h.ensureReadonlyOverlayMounted(volumePath, expectedRef)
}

// UnmountOverlay unmounts the overlay at <volumePath>/rootfs. Exported for
// boxout to call.
func UnmountOverlay(volumePath string) error {
	h := &Handler{
		logger:          log.New(os.Stderr, "[boxout-overlay] ", log.LstdFlags),
		mountedOverlays: make(map[string]string),
	}
	return h.cleanupHostOverlay(volumePath)
}

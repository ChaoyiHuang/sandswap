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
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"testing"
	"time"

	pb "common/proto/stream"
	"common/util"
	"sandlot/vmm"
)

// --- mountedOverlays tracking ---

func TestMountedOverlays_TrackingOnMount(t *testing.T) {
	h := newTestHandler()

	// Simulate: ensureReadonlyOverlayMounted would add to set
	volPath := "/vol/sandfs-test1"
	h.overlayMu.Lock()
	h.mountedOverlays[volPath] = "test-ref"
	h.overlayMu.Unlock()

	h.overlayMu.RLock()
	_, ok := h.mountedOverlays[volPath]
	h.overlayMu.RUnlock()
	if !ok {
		t.Error("expected volumePath to be tracked after mount")
	}
}

func TestMountedOverlays_RemovedOnCleanup(t *testing.T) {
	h := newTestHandler()

	volPath := "/vol/sandfs-test1"
	h.overlayMu.Lock()
	h.mountedOverlays[volPath] = "test-ref"
	h.overlayMu.Unlock()

	// cleanupHostOverlay for a tracked but not actually mounted path:
	// since it's tracked, it skips isMountPoint and goes straight to Unmount.
	// Unmount on a non-existent mount returns EINVAL, which is now handled.
	err := h.cleanupHostOverlay(volPath)
	if err != nil {
		t.Errorf("cleanupHostOverlay should succeed for tracked but unmounted path: %v", err)
	}

	h.overlayMu.RLock()
	_, ok := h.mountedOverlays[volPath]
	h.overlayMu.RUnlock()
	if ok {
		t.Error("expected volumePath to be removed from tracking after cleanup")
	}
}

func TestMountedOverlays_UntrackedNotMountedIsNoop(t *testing.T) {
	h := newTestHandler()

	// cleanupHostOverlay for an untracked, not-mounted path: should return nil
	err := h.cleanupHostOverlay("/vol/nonexistent")
	if err != nil {
		t.Errorf("cleanupHostOverlay should return nil for untracked+unmounted: %v", err)
	}
}

// --- cleanupHostOverlay ---

func TestCleanupHostOverlay_FastPathSkipMountinfo(t *testing.T) {
	h := newTestHandler()
	volPath := "/vol/sandfs-fast"
	h.overlayMu.Lock()
	h.mountedOverlays[volPath] = "test-ref"
	h.overlayMu.Unlock()

	// Tracked but not actually mounted → Unmount returns EINVAL → handled as nil
	err := h.cleanupHostOverlay(volPath)
	if err != nil {
		t.Errorf("expected nil for tracked+EINVAL, got: %v", err)
	}

	h.overlayMu.RLock()
	_, ok := h.mountedOverlays[volPath]
	h.overlayMu.RUnlock()
	if ok {
		t.Error("should be removed from tracking after EINVAL cleanup")
	}
}

func TestCleanupHostOverlay_UntrackedFallbackToMountinfo(t *testing.T) {
	h := newTestHandler()

	// Untracked and not mounted → isMountPoint returns false → nil
	err := h.cleanupHostOverlay("/vol/sandfs-untracked")
	if err != nil {
		t.Errorf("expected nil for untracked+not-mounted, got: %v", err)
	}
}

// --- cleanupStaleOverlays ---

func TestCleanupStaleOverlays_ValidOverlayNotCleaned(t *testing.T) {
	h := newTestHandler()

	// Create a temp dir that looks like a valid SandFS (has .template)
	tmpDir := t.TempDir()
	sandfsDir := filepath.Join(tmpDir, "sandfs-test1")
	rootfsDir := filepath.Join(sandfsDir, "rootfs")
	if err := os.MkdirAll(rootfsDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sandfsDir, ".template"), []byte("ubuntu_v1"), 0644); err != nil {
		t.Fatal(err)
	}

	// Track it
	h.overlayMu.Lock()
	h.mountedOverlays[sandfsDir] = "test-ref"
	h.overlayMu.Unlock()

	h.cleanupStaleOverlays()

	// Should still be tracked (not stale — .template exists)
	h.overlayMu.RLock()
	_, ok := h.mountedOverlays[sandfsDir]
	h.overlayMu.RUnlock()
	if !ok {
		t.Error("valid overlay should not be cleaned up")
	}
}

func TestCleanupStaleOverlays_StaleOverlayCleaned(t *testing.T) {
	h := newTestHandler()

	// Create a temp dir that looks like a stale SandFS (no .template)
	tmpDir := t.TempDir()
	sandfsDir := filepath.Join(tmpDir, "sandfs-stale")
	rootfsDir := filepath.Join(sandfsDir, "rootfs")
	if err := os.MkdirAll(rootfsDir, 0755); err != nil {
		t.Fatal(err)
	}
	// No .template file → SandFS was deleted

	// Track it
	h.overlayMu.Lock()
	h.mountedOverlays[sandfsDir] = "test-ref"
	h.overlayMu.Unlock()

	h.cleanupStaleOverlays()

	// Should be removed from tracking (stale — no .template)
	h.overlayMu.RLock()
	_, ok := h.mountedOverlays[sandfsDir]
	h.overlayMu.RUnlock()
	if ok {
		t.Error("stale overlay should be removed from tracking")
	}
}

func TestCleanupStaleOverlays_OnlyIteratesTrackedSet(t *testing.T) {
	h := newTestHandler()

	// Create two SandFS dirs: one valid, one stale
	tmpDir := t.TempDir()
	validDir := filepath.Join(tmpDir, "sandfs-valid")
	staleDir := filepath.Join(tmpDir, "sandfs-stale")
	for _, d := range []string{validDir, staleDir} {
		if err := os.MkdirAll(filepath.Join(d, "rootfs"), 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(validDir, ".template"), []byte("ubuntu_v1"), 0644); err != nil {
		t.Fatal(err)
	}
	// staleDir has no .template

	// Track both
	h.overlayMu.Lock()
	h.mountedOverlays[validDir] = "test-ref"
	h.mountedOverlays[staleDir] = "test-ref"
	h.overlayMu.Unlock()

	h.cleanupStaleOverlays()

	// Only stale should be removed
	h.overlayMu.RLock()
	_, validOk := h.mountedOverlays[validDir]
	_, staleOk := h.mountedOverlays[staleDir]
	h.overlayMu.RUnlock()

	if !validOk {
		t.Error("valid overlay should remain tracked")
	}
	if staleOk {
		t.Error("stale overlay should be removed from tracking")
	}
}

func TestCleanupStaleOverlays_EmptySetIsNoop(t *testing.T) {
	h := newTestHandler()
	// No overlays tracked — should not panic or error
	h.cleanupStaleOverlays()
}

// --- restoreMountedOverlaysFromMountinfo ---

func TestRestoreMountedOverlaysFromMountinfo_ParsesOverlayMounts(t *testing.T) {
	h := newTestHandler()
	h.vmmCfg.VolumesDir = "/var/sandswap/volumes"

	// Build a fake mountinfo line for an overlay mount
	// Format: ID Parent Major Minor Root MountPoint Options Optional Fields Fstype MountSource SuperOptions
	fakeMountinfo := "36 35 0:52 / /var/sandswap/volumes/sandfs-test1/rootfs rw,relatime - overlay overlay lowerdir=/a:/b,ro\n" +
		"37 35 0:53 / /var/sandswap/volumes/sandfs-test2/rootfs rw,relatime - overlay overlay lowerdir=/c:/d,ro\n" +
		"38 35 0:54 / /mnt/other/rootfs rw,relatime - overlay overlay lowerdir=/e:/f,ro\n" + // different base
		"39 35 0:55 / /var/sandswap/volumes/sandfs-test3/workspace rw,relatime - nfs4 nfs4 rw\n" // not overlay

	// Write fake mountinfo to a temp file and monkey-patch the read
	tmpFile := filepath.Join(t.TempDir(), "mountinfo")
	if err := os.WriteFile(tmpFile, []byte(fakeMountinfo), 0644); err != nil {
		t.Fatal(err)
	}

	// We can't easily redirect the os.ReadFile("/proc/self/mountinfo") call,
	// so we test the parsing logic directly by calling the function.
	// Instead, verify the parsing logic with a helper.
	data, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatal(err)
	}

	found := parseOverlayMountsFromMountinfo(data, h.vmmCfg.VolumesDir)
	if len(found) != 2 {
		t.Errorf("expected 2 overlay mounts, got %d: %v", len(found), found)
	}
	expected1 := "/var/sandswap/volumes/sandfs-test1"
	expected2 := "/var/sandswap/volumes/sandfs-test2"
	if found[0] != expected1 {
		t.Errorf("first mount: got %q, want %q", found[0], expected1)
	}
	if found[1] != expected2 {
		t.Errorf("second mount: got %q, want %q", found[1], expected2)
	}
}

func TestRestoreMountedOverlaysFromMountinfo_IgnoresNonOverlayMounts(t *testing.T) {
	fakeMountinfo := "36 35 0:52 / /var/sandswap/volumes/sandfs-test1/rootfs rw - ext4 /dev/sda1 rw\n"
	found := parseOverlayMountsFromMountinfo([]byte(fakeMountinfo), "/var/sandswap/volumes")
	if len(found) != 0 {
		t.Errorf("expected 0 mounts for non-overlay fstype, got %d", len(found))
	}
}

func TestRestoreMountedOverlaysFromMountinfo_IgnoresNonRootfsPaths(t *testing.T) {
	// An overlay mount at a non-rootfs subpath (e.g., workspace) should be ignored
	fakeMountinfo := "36 35 0:52 / /var/sandswap/volumes/sandfs-test1/workspace rw - overlay overlay lowerdir=/a\n"
	found := parseOverlayMountsFromMountinfo([]byte(fakeMountinfo), "/var/sandswap/volumes")
	if len(found) != 0 {
		t.Errorf("expected 0 mounts for non-rootfs overlay, got %d", len(found))
	}
}

func TestRestoreMountedOverlaysFromMountinfo_EmptyInput(t *testing.T) {
	found := parseOverlayMountsFromMountinfo([]byte(""), "/var/sandswap/volumes")
	if len(found) != 0 {
		t.Errorf("expected 0 mounts for empty input, got %d", len(found))
	}
}

// --- reaper batch constants ---

func TestReaperBatchConstants(t *testing.T) {
	if reaperBatchSize <= 0 {
		t.Error("reaperBatchSize must be positive")
	}
	if reaperBatchPause <= 0 {
		t.Error("reaperBatchPause must be positive")
	}
	if reaperInterval < time.Hour {
		t.Errorf("reaperInterval should be at least 1 hour, got %v", reaperInterval)
	}
}

// --- handleCleanupOverlay RPC ---

func TestHandleCleanupOverlay_Success(t *testing.T) {
	h := newTestHandler()
	// For a path not tracked and not mounted, should succeed
	cmd := &pb.VMCommand{CommandId: "cmd-1"}
	req := &pb.CleanupOverlay{VolumePath: "/vol/nonexistent"}
	resp := h.handleCleanupOverlay(context.TODO(), cmd, req)
	if !resp.Success {
		t.Errorf("expected success for unmounted path, got error: %s", resp.Error)
	}
}

func TestHandleCleanupOverlay_EmptyPath(t *testing.T) {
	h := newTestHandler()
	cmd := &pb.VMCommand{CommandId: "cmd-2"}
	req := &pb.CleanupOverlay{VolumePath: ""}
	resp := h.handleCleanupOverlay(context.TODO(), cmd, req)
	// Empty path → not tracked, not mounted → should succeed (idempotent)
	if !resp.Success {
		t.Errorf("expected success for empty path, got error: %s", resp.Error)
	}
}

// --- layer-ID trust boundary (ref-load validation) ---

func TestValidateLayerID(t *testing.T) {
	tpl := "/var/sandswap/templates"
	cases := []struct {
		name    string
		layerID string
		wantErr bool
	}{
		{"digest relative", "sha256-abc123", false},
		{"local-dir relative", "local-busybox-v1", false},
		{"nested relative", "sha256-abc/sub", false},
		{"empty", "", true},
		{"parent escape", "../evil", true},
		{"nested escape", "sub/../../evil", true},
		{"absolute inside templates", tpl + "/layers/sha256-abc", false},
		{"absolute outside templates", "/etc", true},
		{"absolute escape via ..", tpl + "/../etc", true},
		{"absolute root", "/", true},
	}
	for _, c := range cases {
		err := validateLayerID(tpl, c.layerID)
		if (err != nil) != c.wantErr {
			t.Errorf("%s: validateLayerID(%q) err = %v, wantErr %v", c.name, c.layerID, err, c.wantErr)
		}
	}
}

// TestGetCachedRefEntryRejectsHostPaths pins the attack the validation exists
// for: a refs file (written by a compromised control plane, malicious OCI
// pull, or a peer node on the shared templates dir) naming /etc as a layer
// must refuse to load — accepting it would mount the host directory
// read-only into every guest created from the template.
func TestGetCachedRefEntryRejectsHostPaths(t *testing.T) {
	h := newTestHandler()
	tpl := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tpl, "refs"), 0o755); err != nil {
		t.Fatal(err)
	}
	ref := "rootfs:v1"
	refFile := filepath.Join(tpl, "refs", util.RefToFilename(ref)+".overlay.json")
	good := filepath.Join(tpl, "layers", "sha256-good")

	// Benign ref loads and caches.
	goodRef := fmt.Sprintf(`{"name":"rootfs","version":"v1","layers":["%s","sha256-rel"]}`, good)
	if err := os.WriteFile(refFile, []byte(goodRef), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := h.getCachedRefEntry(tpl, ref); err != nil {
		t.Fatalf("benign ref rejected: %v", err)
	}

	// Host-path layer: refused (and the earlier cached entry is NOT poisoned —
	// each ref name is its own cache key, so use a second ref for the attack).
	evilRef := "evil:v9"
	evilFile := filepath.Join(tpl, "refs", util.RefToFilename(evilRef)+".overlay.json")
	evil := `{"name":"evil","version":"v9","layers":["/etc"]}`
	if err := os.WriteFile(evilFile, []byte(evil), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := h.getCachedRefEntry(tpl, evilRef); err == nil {
		t.Fatal("ref naming /etc as a layer was accepted — the layer-ID trust boundary is open")
	}

	// Relative escape form: also refused.
	escRef := "esc:v1"
	escFile := filepath.Join(tpl, "refs", util.RefToFilename(escRef)+".flat.json")
	if err := os.WriteFile(escFile, []byte(`{"name":"esc","version":"v1","layers":["../../etc"]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := h.getCachedRefEntry(tpl, escRef); err == nil {
		t.Fatal("relative ../ escape layer was accepted")
	}
}

// --- OverlaySet (shared with the boxout sidecar) ---

// TestOverlaySet_TrackUntrackSnapshot covers the bookkeeping primitives: Track
// is idempotent, Untrack drops exactly the named entry, Tracked returns a
// snapshot the caller may mutate freely.
func TestOverlaySet_TrackUntrackSnapshot(t *testing.T) {
	s := NewOverlaySet(nil)
	s.Track("/vol/sandfs-a", "")
	s.Track("/vol/sandfs-a", "") // idempotent
	s.Track("/vol/sandfs-b", "")
	if got := s.Tracked(); len(got) != 2 {
		t.Fatalf("expected 2 tracked entries, got %d (%v)", len(got), got)
	}
	// The append writes into the returned snapshot's (possibly aliased) backing
	// array — the assertion below proves the set itself stays unaffected.
	_ = append(s.Tracked(), "/vol/sandfs-c")
	if got := s.Tracked(); len(got) != 2 {
		t.Fatalf("mutating the snapshot must not touch the set, got %d", len(got))
	}
	s.Untrack("/vol/sandfs-a")
	s.Untrack("/vol/sandfs-a") // idempotent
	if got := s.Tracked(); len(got) != 1 || got[0] != "/vol/sandfs-b" {
		t.Fatalf("expected only sandfs-b left, got %v", got)
	}
}

// TestOverlaySet_RestoreFromMountinfoData verifies the data-injected restore:
// overlay mounts under <volumesDir>/<id>/rootfs are tracked; other overlay
// mounts, non-overlay mounts, and non-rootfs paths are ignored. Must stay in
// lockstep with TestRestoreMountedOverlaysFromMountinfo_ParsesOverlayMounts
// (the Handler-level twin).
func TestOverlaySet_RestoreFromMountinfoData(t *testing.T) {
	s := NewOverlaySet(nil)
	data := []byte(
		"36 35 0:1 / / rw - ext4 /dev/sda1 rw\n" +
			"37 35 0:2 / /var/sandswap/volumes/sandfs-aaaa/rootfs ro - overlay overlay rw,lowerdir=/x\n" +
			"38 35 0:3 / /var/sandswap/volumes/sandfs-bbbb/rootfs ro - overlay overlay rw,lowerdir=/y\n" +
			"39 35 0:4 / /var/sandswap/volumes/sandfs-cccc/workspace rw - nfs srv:/x rw\n" + // wrong fstype
			"40 35 0:5 / /var/sandswap/volumes/sandfs-dddd ro - overlay overlay rw\n" + // not /rootfs
			"41 35 0:6 / /elsewhere/overlay/rootfs ro - overlay overlay rw\n") // outside volumesDir
	n := s.RestoreFromMountinfoData(data, "/var/sandswap/volumes")
	if n != 2 {
		t.Fatalf("expected 2 restored entries, got %d", n)
	}
	tracked := s.Tracked()
	want := map[string]bool{
		"/var/sandswap/volumes/sandfs-aaaa": false,
		"/var/sandswap/volumes/sandfs-bbbb": false,
	}
	for _, p := range tracked {
		if _, ok := want[p]; !ok {
			t.Fatalf("unexpected tracked path %q", p)
		}
		want[p] = true
	}
	for p, seen := range want {
		if !seen {
			t.Errorf("expected %q to be tracked", p)
		}
	}
}

// TestOverlaySet_CleanupStale covers the sweep: only entries whose .template
// marker is gone are unmounted (and untracked); live overlays are left alone;
// unmount failures keep the entry tracked and count as failed.
func TestOverlaySet_CleanupStale(t *testing.T) {
	dir := t.TempDir()
	liveVol := filepath.Join(dir, "sandfs-live")
	staleVol := filepath.Join(dir, "sandfs-stale")
	errVol := filepath.Join(dir, "sandfs-err")
	for _, d := range []string{liveVol, staleVol, errVol} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// live keeps its .template marker; stale/err have theirs deleted.
	if err := os.WriteFile(filepath.Join(liveVol, ".template"), []byte("t:v1"), 0o644); err != nil {
		t.Fatal(err)
	}

	s := NewOverlaySet(nil)
	s.Track(liveVol, "")
	s.Track(staleVol, "")
	s.Track(errVol, "")

	var unmounted []string
	cleaned, failed := s.CleanupStale(func(volumePath string) error {
		if volumePath == errVol {
			return fmt.Errorf("simulated EBUSY")
		}
		unmounted = append(unmounted, volumePath)
		return nil
	})
	if cleaned != 1 || failed != 1 {
		t.Fatalf("expected cleaned=1 failed=1, got cleaned=%d failed=%d", cleaned, failed)
	}
	if len(unmounted) != 1 || unmounted[0] != staleVol {
		t.Fatalf("expected only the stale volume unmounted, got %v", unmounted)
	}
	// live stays tracked; stale is untracked; err stays tracked for the next sweep.
	remaining := map[string]bool{}
	for _, p := range s.Tracked() {
		remaining[p] = true
	}
	if !remaining[liveVol] {
		t.Error("live overlay must stay tracked")
	}
	if remaining[staleVol] {
		t.Error("cleaned stale overlay must be untracked")
	}
	if !remaining[errVol] {
		t.Error("failed unmount must stay tracked for the next sweep")
	}
}

// TestOverlaySet_CleanupStaleEmpty covers the no-op sweep.
func TestOverlaySet_CleanupStaleEmpty(t *testing.T) {
	s := NewOverlaySet(nil)
	cleaned, failed := s.CleanupStale(func(string) error { t.Fatal("unmount must not run"); return nil })
	if cleaned != 0 || failed != 0 {
		t.Fatalf("expected 0/0 on empty set, got %d/%d", cleaned, failed)
	}
}

// TestOverlayConfigReadUnderHotReloadRace drives the two formerly-unguarded
// vmmCfg reads (TemplatesDir in ensureReadonlyOverlayMounted, VolumesDir in
// restoreMountedOverlaysFromMountinfo) against a concurrent UpdateVMMConfig
// loop. Under -race this is the detector for the data race the RLocks close:
// UpdateVMMConfig rewrites the whole struct under h.mu, and the cold-path
// readers used to touch it bare. The volume path carries no .template marker,
// so the mount function returns early (nil) — exactly the cheap prefix the
// racing read sits in.
func TestOverlayConfigReadUnderHotReloadRace(t *testing.T) {
	h := newTestHandler()
	volRoot := t.TempDir()
	sandfsDir := filepath.Join(volRoot, "sandfs-race")
	if err := os.MkdirAll(sandfsDir, 0o755); err != nil {
		t.Fatal(err)
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		i := 0
		for {
			select {
			case <-stop:
				return
			default:
			}
			i++
			h.UpdateVMMConfig(vmm.Config{
				TemplatesDir: fmt.Sprintf("/tmp/tpl-%d", i),
				VolumesDir:   fmt.Sprintf("/var/sandswap/volumes-%d", i),
			})
			runtime.Gosched()
		}
	}()

	// Both cold-path readers hammer in parallel with the rewriter.
	for i := 0; i < 50; i++ {
		if _, err := h.ensureReadonlyOverlayMounted(sandfsDir, ""); err != nil {
			t.Fatalf("ensureReadonlyOverlayMounted under reload: %v", err)
		}
		h.restoreMountedOverlaysFromMountinfo()
	}

	close(stop)
	wg.Wait()
}

// ── ref tracking + persistence (template swap correctness) ──────────

func TestReadTemplateMarker(t *testing.T) {
	dir := t.TempDir()

	// Flat volume: existing dir, no marker.
	if err := os.MkdirAll(filepath.Join(dir, "flat-vol"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, flat, err := readTemplateMarker(filepath.Join(dir, "flat-vol")); err != nil {
		t.Fatalf("readTemplateMarker empty dir: %v", err)
	} else if !flat {
		t.Fatal("empty dir must read as flat")
	}

	// Overlay volume: marker names the ref.
	ov := filepath.Join(dir, "ov-vol")
	if err := os.MkdirAll(ov, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ov, ".template"), []byte("app:v2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ref, flat, err := readTemplateMarker(ov)
	if err != nil || flat || ref != "app:v2" {
		t.Fatalf("readTemplateMarker overlay: ref=%q flat=%v err=%v", ref, flat, err)
	}

	// Missing volume dir entirely: an error (a cold mount on a deleted volume
	// must not be mistaken for the flat case).
	if _, _, err := readTemplateMarker(filepath.Join(dir, "gone")); err == nil {
		t.Fatal("missing volume dir must error")
	}
}

func TestOverlaySetRefTrackingAndMerge(t *testing.T) {
	s := NewOverlaySet(nil)
	s.Track("/vol/a", "app:v1")
	s.Track("/vol/b", "")

	if got := s.RefOf("/vol/a"); got != "app:v1" {
		t.Fatalf("RefOf(a) = %q", got)
	}
	if got := s.RefOf("/vol/b"); got != "" {
		t.Fatalf("RefOf(b) = %q, want empty (unknown)", got)
	}
	if got := s.RefOf("/vol/zzz"); got != "" {
		t.Fatalf("RefOf(unknown) = %q", got)
	}

	// Merge persisted refs: only already-tracked paths take a ref.
	merged := s.MergeRefs(map[string]string{
		"/vol/a": "app:v9", // tracked — ref overwritten (restore path: persisted is the only source)
		"/vol/b": "app:v2", // tracked with unknown ref — filled
		"/vol/c": "app:v1", // NOT tracked (no mount) — ignored
	})
	if merged != 2 {
		t.Fatalf("merged = %d, want 2", merged)
	}
	if s.RefOf("/vol/a") != "app:v9" || s.RefOf("/vol/b") != "app:v2" {
		t.Fatalf("refs after merge: a=%q b=%q", s.RefOf("/vol/a"), s.RefOf("/vol/b"))
	}

	// Snapshot reflects the map.
	snap := s.Snapshot()
	if snap["/vol/a"] != "app:v9" || snap["/vol/b"] != "app:v2" {
		t.Fatalf("snapshot: %v", snap)
	}
}

func TestPersistOverlayRefsRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "overlays.json")
	m := map[string]string{"/vol/a": "app:v1", "/vol/b": ""}
	if err := PersistOverlayRefs(path, m); err != nil {
		t.Fatalf("persist: %v", err)
	}
	got := LoadOverlayRefs(path)
	if len(got) != 2 || got["/vol/a"] != "app:v1" || got["/vol/b"] != "" {
		t.Fatalf("round-trip: %v", got)
	}
	// Missing file → empty map, not an error.
	if got := LoadOverlayRefs(filepath.Join(t.TempDir(), "nope.json")); len(got) != 0 {
		t.Fatalf("missing file: %v", got)
	}
}

// --- readTemplateMarker: planted-marker hardening ---

func TestReadTemplateMarker_RegularMarkerReadsRef(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".template"), []byte("app:v1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ref, flat, err := readTemplateMarker(dir)
	if err != nil || flat || ref != "app:v1" {
		t.Fatalf("regular marker: ref=%q flat=%v err=%v", ref, flat, err)
	}
}

func TestReadTemplateMarker_NoMarkerIsFlat(t *testing.T) {
	ref, flat, err := readTemplateMarker(t.TempDir())
	if err != nil || !flat || ref != "" {
		t.Fatalf("no marker: ref=%q flat=%v err=%v", ref, flat, err)
	}
}

func TestReadTemplateMarker_PlantedSymlinkAndFifoAreNotFollowed(t *testing.T) {
	// In flat mode the volume root IS the agent's chroot root, so the marker
	// path is agent-writable. A planted symlink must not be FOLLOWED (the
	// old os.ReadFile would resolve it against the HOST root = arbitrary
	// host-file read) and a planted FIFO must not BLOCK the mount path.
	// Both read as "no marker" → the flat volume keeps working.
	dir := t.TempDir()
	secret := filepath.Join(dir, "host-secret")
	if err := os.WriteFile(secret, []byte("SECRET"), 0o600); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(dir, ".template")

	if err := os.Symlink(secret, marker); err != nil {
		t.Fatal(err)
	}
	ref, flat, err := readTemplateMarker(dir)
	if err != nil || !flat || ref != "" {
		t.Fatalf("planted symlink must read as flat (never followed): ref=%q flat=%v err=%v", ref, flat, err)
	}
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}

	if err := syscall.Mkfifo(marker, 0o644); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}
	type result struct {
		ref  string
		flat bool
		err  error
	}
	done := make(chan result, 1)
	go func() {
		r, f, e := readTemplateMarker(dir)
		done <- result{r, f, e}
	}()
	select {
	case got := <-done:
		if got.err != nil || !got.flat || got.ref != "" {
			t.Fatalf("planted FIFO must read as flat (never opened): ref=%q flat=%v err=%v", got.ref, got.flat, got.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("readTemplateMarker BLOCKED on a planted FIFO — the mount path would wedge")
	}
}

// TestLoadOverlayRefsRefusesSymlink pins the safe load: the state file path
// lives in a privileged state dir, but a swapped symlink must not make the
// reader trust an arbitrary JSON file.
func TestLoadOverlayRefsRefusesSymlink(t *testing.T) {
	victim := filepath.Join(t.TempDir(), "victim.json")
	if err := os.WriteFile(victim, []byte(`{"mounted":{"/vol":"evil:v1"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "overlays.json")
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}
	if got := LoadOverlayRefs(link); len(got) != 0 {
		t.Fatalf("symlinked state file was followed: %v", got)
	}

	realPath := filepath.Join(t.TempDir(), "real.json")
	if err := os.WriteFile(realPath, []byte(`{"mounted":{"/vol":"ok:v1"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := LoadOverlayRefs(realPath); got["/vol"] != "ok:v1" {
		t.Fatalf("regular state file did not load: %v", got)
	}
}

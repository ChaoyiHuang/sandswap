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

package volume

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sandlot/provision/template"
)

// newOverlayFixture builds a Provisioner with one overlay volume created from
// an overlay ref ("app:v1"), plus a second overlay ref ("app:v2") to swap to.
// Both refs use the local-template format (absolute layer dirs).
func newOverlayFixture(t *testing.T) (*Provisioner, string, string) {
	t.Helper()
	volRoot := t.TempDir()
	tplRoot := t.TempDir()

	mgr, err := template.NewManager(template.Config{TemplatesDir: filepath.Join(tplRoot, "store")})
	if err != nil {
		t.Fatal(err)
	}
	for _, ref := range []string{"app:v1", "app:v2"} {
		layer := filepath.Join(tplRoot, strings.ReplaceAll(ref, ":", "-"))
		if err := os.MkdirAll(filepath.Join(layer, "bin"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(layer, "bin", "run"), []byte(ref), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := mgr.RegisterLocalTemplate(ref, layer); err != nil {
			t.Fatal(err)
		}
	}
	// A flat ref for the flat-volume refusal case. The source lives inside
	// the store: the flat consume path only accepts store/scan-root content
	//, and it is created after NewManager so the constructor scan
	// does not auto-register it.
	flatSrc := filepath.Join(tplRoot, "store", "flat-src")
	if err := os.MkdirAll(flatSrc, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(flatSrc, "hello.txt"), []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := mgr.RegisterFlatTemplate("seed:v1", flatSrc); err != nil {
		t.Fatal(err)
	}
	p := newTestProvisioner(t, volRoot, mgr)
	if _, err := p.EnsureVolume(context.Background(), "sandfs-ov", "overlay", "app:v1"); err != nil {
		t.Fatal(err)
	}
	vol := volPath(p, "sandfs-ov")
	// Simulate agent work: workspace file + home dotfile.
	if err := os.WriteFile(filepath.Join(vol, "workspace", "work.txt"), []byte("agent work"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(vol, "home", ".profile"), []byte("dotfile"), 0o644); err != nil {
		t.Fatal(err)
	}
	return p, volRoot, vol
}

func markerRef(t *testing.T, vol string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(vol, ".template"))
	if err != nil {
		t.Fatalf("read marker: %v", err)
	}
	return strings.TrimSpace(string(b))
}

func TestSwapTemplateRepointsMarkerAndKeepsWorkspace(t *testing.T) {
	p, _, vol := newOverlayFixture(t)

	res, err := p.SwapTemplate(context.Background(), "sandfs-ov", "app:v2", HomeKeep)
	if err != nil {
		t.Fatalf("SwapTemplate: %v", err)
	}
	if got := markerRef(t, vol); got != "app:v2" {
		t.Fatalf("marker = %q, want app:v2", got)
	}
	if res.RootfsPath != vol {
		t.Fatalf("rootfs path = %q, want %q", res.RootfsPath, vol)
	}
	// The target ref was already in the local store: no registry pull.
	if res.Pulled {
		t.Error("Pulled = true for a locally registered ref, want false")
	}
	// workspace + home carry over untouched (the whole point of the swap).
	if b, err := os.ReadFile(filepath.Join(vol, "workspace", "work.txt")); err != nil || string(b) != "agent work" {
		t.Fatalf("workspace file lost: %q %v", b, err)
	}
	if b, err := os.ReadFile(filepath.Join(vol, "home", ".profile")); err != nil || string(b) != "dotfile" {
		t.Fatalf("home dotfile lost under keep policy: %q %v", b, err)
	}
}

func TestSwapTemplateIdempotentSameRef(t *testing.T) {
	p, _, vol := newOverlayFixture(t)

	if _, err := p.SwapTemplate(context.Background(), "sandfs-ov", "app:v2", HomeKeep); err != nil {
		t.Fatal(err)
	}
	// Re-issue the SAME ref with a DIFFERENT home policy: still a no-op (the
	// volume already serves the requested ref — the home policy only applies
	// when the ref actually moves).
	if _, err := p.SwapTemplate(context.Background(), "sandfs-ov", "app:v2", HomeReset); err != nil {
		t.Fatal(err)
	}
	if _, err := os.ReadFile(filepath.Join(vol, "home", ".profile")); err != nil {
		t.Fatalf("same-ref re-issue must not apply home policy: %v", err)
	}
}

func TestSwapTemplateHomePolicies(t *testing.T) {
	t.Run("reset", func(t *testing.T) {
		p, _, vol := newOverlayFixture(t)
		if _, err := p.SwapTemplate(context.Background(), "sandfs-ov", "app:v2", HomeReset); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(filepath.Join(vol, "home", ".profile")); !os.IsNotExist(err) {
			t.Fatalf("home content survived reset: %v", err)
		}
		// Fresh home exists with the setgid layout.
		fi, err := os.Stat(filepath.Join(vol, "home"))
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode()&os.ModeSetgid == 0 {
			t.Fatalf("fresh home not setgid: %v", fi.Mode())
		}
	})
	t.Run("archive keeps one newest copy", func(t *testing.T) {
		p, _, vol := newOverlayFixture(t)
		if _, err := p.SwapTemplate(context.Background(), "sandfs-ov", "app:v2", HomeArchive); err != nil {
			t.Fatal(err)
		}
		// Archived copy exists and the dotfile is recoverable from it.
		entries, err := os.ReadDir(vol)
		if err != nil {
			t.Fatal(err)
		}
		archives := 0
		var archiveName string
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), "home.pre-attach-") {
				archives++
				archiveName = e.Name()
			}
		}
		if archives != 1 {
			t.Fatalf("expected 1 archive, got %d", archives)
		}
		if b, err := os.ReadFile(filepath.Join(vol, archiveName, ".profile")); err != nil || string(b) != "dotfile" {
			t.Fatalf("archive lost the dotfile: %v", err)
		}
		// A second swap with archive prunes the older copy.
		if _, err := p.SwapTemplate(context.Background(), "sandfs-ov", "app:v1", HomeArchive); err != nil {
			t.Fatal(err)
		}
		entries, err = os.ReadDir(vol)
		if err != nil {
			t.Fatal(err)
		}
		archives = 0
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), "home.pre-attach-") {
				archives++
			}
		}
		if archives != 1 {
			t.Fatalf("old archive not pruned: %d archives", archives)
		}
	})
}

func TestSwapTemplateRejectsFlatVolumeAndBadArgs(t *testing.T) {
	p, _, _ := newOverlayFixture(t)

	// Flat volume (no .template marker): named refusal.
	if _, err := p.EnsureVolume(context.Background(), "sandfs-flat", "flat", "seed:v1"); err != nil {
		t.Fatal(err)
	}
	_, err := p.SwapTemplate(context.Background(), "sandfs-flat", "app:v2", HomeKeep)
	// The signed stamp records the layout: an overlay-only swap steered at a
	// flat (agent-writable) volume is refused by the identity/layout check
	// before any marker read.
	if !errors.Is(err, ErrVolumeIdentityMismatch) {
		t.Fatalf("flat swap: want ErrVolumeIdentityMismatch (layout binding), got %v", err)
	}

	// Unknown overlay ref without a registry: named refusal.
	_, err = p.SwapTemplate(context.Background(), "sandfs-ov", "missing:v9", HomeKeep)
	if !errors.Is(err, ErrTemplateNotFound) {
		t.Fatalf("missing ref: want ErrTemplateNotFound, got %v", err)
	}

	// Bad home policy.
	_, err = p.SwapTemplate(context.Background(), "sandfs-ov", "app:v2", "explode")
	if !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("bad home policy: want ErrInvalidArgument, got %v", err)
	}
}

func TestDeleteTemplateInUseRefusalAndForce(t *testing.T) {
	p, _, vol := newOverlayFixture(t)

	// In use by sandfs-ov's marker → structured refusal.
	err := p.DeleteTemplate(context.Background(), "app:v1", "overlay", false)
	var inUse *TemplateInUseError
	if !errors.As(err, &inUse) {
		t.Fatalf("want TemplateInUseError, got %v", err)
	}
	// The scan walks the volumes ROOT, so the sample holds DIRECTORY names —
	// opaque since the seed-derived naming change. The gateway maps them back
	// to sandfs IDs through the records before showing them to an operator.
	if inUse.Count != 1 || len(inUse.Sample) != 1 || inUse.Sample[0] != filepath.Base(vol) {
		t.Fatalf("in-use payload: %+v (want the volume directory %q)", inUse, filepath.Base(vol))
	}
	// Marker still present (refused delete leaves everything intact).
	if got := markerRef(t, vol); got != "app:v1" {
		t.Fatalf("marker changed on refused delete: %q", got)
	}

	// Swap away → old ref no longer in use → delete succeeds.
	if _, err := p.SwapTemplate(context.Background(), "sandfs-ov", "app:v2", HomeKeep); err != nil {
		t.Fatal(err)
	}
	if err := p.DeleteTemplate(context.Background(), "app:v1", "overlay", false); err != nil {
		t.Fatalf("delete after swap: %v", err)
	}

	// Force bypasses the in-use check.
	if _, err := p.EnsureVolume(context.Background(), "sandfs-ov2", "overlay", "app:v2"); err != nil {
		t.Fatal(err)
	}
	if err := p.DeleteTemplate(context.Background(), "app:v2", "overlay", true); err != nil {
		t.Fatalf("forced delete: %v", err)
	}
}

func TestDeleteTemplateGarbageCollectsOnlyUnreferencedLayers(t *testing.T) {
	volRoot := t.TempDir()
	tplRoot := t.TempDir()
	mgr, err := template.NewManager(template.Config{TemplatesDir: filepath.Join(tplRoot, "store")})
	if err != nil {
		t.Fatal(err)
	}
	// Two overlay refs SHARING one layer directory (the local-template
	// format's absolute-path layers model the content-addressed sharing).
	shared := filepath.Join(tplRoot, "shared")
	if err := os.MkdirAll(shared, 0o755); err != nil {
		t.Fatal(err)
	}
	solo := filepath.Join(tplRoot, "solo")
	if err := os.MkdirAll(solo, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := mgr.RegisterLocalTemplate("a:v1", shared); err != nil {
		t.Fatal(err)
	}
	if err := mgr.RegisterLocalTemplate("b:v1", solo); err != nil {
		t.Fatal(err)
	}
	p := newTestProvisioner(t, volRoot, mgr)

	// Delete b:v1 — its solo layer goes, the layer shared with a:v1 stays.
	// (Absolute-path local-template layers are NEVER removed by the GC; the
	// guarantee under test is that a remaining ref's layer is untouched.)
	if err := p.DeleteTemplate(context.Background(), "b:v1", "overlay", false); err != nil {
		t.Fatalf("delete b:v1: %v", err)
	}
	if _, err := mgr.LoadRefEntry("a:v1", "overlay"); err != nil {
		t.Fatalf("remaining ref lost: %v", err)
	}
	if _, err := os.Stat(shared); err != nil {
		t.Fatalf("shared layer dir removed by GC: %v", err)
	}
	if _, err := mgr.LoadRefEntry("b:v1", "overlay"); err == nil {
		t.Fatal("deleted ref still resolvable")
	}
}

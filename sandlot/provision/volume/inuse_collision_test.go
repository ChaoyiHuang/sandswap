// Copyright 2026 Chaoyi Huang. All rights reserved.
//
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE file at the root of this repository.

package volume

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"sandlot/provision/template"
)

// The delete gate's in-use scan must compare the ref FILE identity, not the
// raw string: RefToFilename is not injective ('a:b_c' and 'a_b:c' name the
// same refs/a_b_c.overlay.json), so a raw compare lets a colliding ref miss a
// live volume and delete the template out from under it.
func TestScanTemplateInUseMatchesCollidingRefEncoding(t *testing.T) {
	volRoot := t.TempDir()
	tplRoot := t.TempDir()
	mgr, err := template.NewManager(template.Config{TemplatesDir: filepath.Join(tplRoot, "store")})
	if err != nil {
		t.Fatal(err)
	}
	layer := filepath.Join(tplRoot, "layer-app_x-v1")
	if err := os.MkdirAll(filepath.Join(layer, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(layer, "bin", "run"), []byte("app"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := mgr.RegisterLocalTemplate("app_x:v1", layer); err != nil {
		t.Fatal(err)
	}
	p := newTestProvisioner(t, volRoot, mgr)
	if _, err := p.EnsureVolume(context.Background(), "sandfs-collide", "overlay", "app_x:v1"); err != nil {
		t.Fatal(err)
	}

	for _, probe := range []string{"app_x:v1", "app:x_v1"} {
		count, sample, err := p.scanTemplateInUse(context.Background(), probe)
		if err != nil {
			t.Fatalf("scan %q: %v", probe, err)
		}
		if count != 1 {
			t.Fatalf("scan %q counted %d volumes, want 1 (collision must be the same identity)", probe, count)
		}
		want := p.volumeName("sandfs-collide")
		if len(sample) != 1 || sample[0] != want {
			t.Fatalf("scan %q sample = %v, want [%s]", probe, sample, want)
		}
	}
}

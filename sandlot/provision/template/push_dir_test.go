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

package template

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/content/file"
)

// TestPushTemplateArtifactToStore pins the artifact shape PushTemplate and
// the standalone import push share: OCI image manifest, sandswap config
// media type, one gzip layer per directory, annotations (including the
// caller's producer metadata), tag <name>-<version>. The destination is a
// file.Store — an oras.Target, so the packing path is exercised without a
// registry.
func TestPushTemplateArtifactToStore(t *testing.T) {
	layerDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(layerDir, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(layerDir, "etc", "x"), []byte("layer content"), 0o644); err != nil {
		t.Fatal(err)
	}

	dst, err := file.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer dst.Close()

	resp, err := pushTemplateArtifact(context.Background(), dst, "conv:v3", "overlay", "a converted image",
		[]string{layerDir}, map[string]string{"sandswap.template.source.image": "oci:sha256:abc"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.TemplateRef != "conv:v3" || len(resp.Layers) != 1 || resp.Size <= 0 {
		t.Fatalf("response = %+v", resp)
	}

	// Resolve by the tag the prov instance's pull path derives from the ref.
	desc, err := dst.Resolve(context.Background(), "conv-v3")
	if err != nil {
		t.Fatalf("resolve conv-v3: %v", err)
	}
	rc, err := dst.Fetch(context.Background(), desc)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(rc)
	rc.Close()
	if err != nil {
		t.Fatal(err)
	}
	var manifest ocispec.Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatalf("manifest is not JSON: %v", err)
	}
	// PackImageManifest artifacts carry the sandswap identity in the CONFIG
	// media type + annotations (oras's image-manifest path leaves
	// ArtifactType empty — the existing PushTemplate behavior, and the
	// consuming pull path reads neither).
	if manifest.MediaType != "" && manifest.MediaType != ocispec.MediaTypeImageManifest {
		t.Fatalf("mediaType = %q", manifest.MediaType)
	}
	if manifest.Config.MediaType != MediaTypeTemplateConfig {
		t.Fatalf("config media type = %q", manifest.Config.MediaType)
	}
	if len(manifest.Layers) != 1 || manifest.Layers[0].MediaType != MediaTypeLayerGzip {
		t.Fatalf("layers = %+v", manifest.Layers)
	}
	want := map[string]string{
		"sandswap.template.name":         "conv",
		"sandswap.template.version":      "v3",
		"sandswap.template.description":  "a converted image",
		"sandswap.template.source.image": "oci:sha256:abc",
	}
	for k, v := range want {
		if manifest.Annotations[k] != v {
			t.Fatalf("annotation %s = %q, want %q", k, manifest.Annotations[k], v)
		}
	}

	// The config blob records the mode.
	cfgRc, err := dst.Fetch(context.Background(), manifest.Config)
	if err != nil {
		t.Fatal(err)
	}
	cfgData, _ := io.ReadAll(cfgRc)
	cfgRc.Close()
	var cfg map[string]any
	if err := json.Unmarshal(cfgData, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg["template_mode"] != "overlay" {
		t.Fatalf("template_mode = %v", cfg["template_mode"])
	}

	// The layer round-trips the tree.
	layerRc, err := dst.Fetch(context.Background(), manifest.Layers[0])
	if err != nil {
		t.Fatal(err)
	}
	zr, err := gzip.NewReader(layerRc)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(zr)
	found := false
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if hdr.Name == "etc/x" {
			var buf bytes.Buffer
			if _, err := io.Copy(&buf, tr); err != nil {
				t.Fatal(err)
			}
			if buf.String() != "layer content" {
				t.Fatalf("etc/x = %q", buf.String())
			}
			found = true
		}
	}
	layerRc.Close()
	zr.Close()
	if !found {
		t.Fatal("etc/x missing from the packed layer")
	}
}

func TestNewRegistryRepositoryLoopbackDetection(t *testing.T) {
	cases := map[string]bool{
		"localhost:5000/repo":      true,
		"localhost/repo":           true,
		"LOCALHOST:5000/repo":      true, // host comparison is case-insensitive
		"127.0.0.1:15000/x":        true,
		"[::1]:5000/x":             true,
		"localhost.evil.example/r": false, // prefix match must NOT downgrade TLS
		"registry.example.com/r":   false,
	}
	for ref, wantPlain := range cases {
		if ref == "[::1]:5000/x" {
			// oras-go's reference grammar rejects bracketed hosts on some
			// versions; the case only pins OUR parser, skip if upstream
			// refuses the reference at construction.
			if _, err := NewRegistryRepository(ref, AuthConfig{}); err != nil {
				continue
			}
		}
		repo, err := NewRegistryRepository(ref, AuthConfig{})
		if err != nil {
			t.Fatalf("%s: %v", ref, err)
		}
		if repo.PlainHTTP != wantPlain {
			t.Fatalf("%s: PlainHTTP = %v, want %v", ref, repo.PlainHTTP, wantPlain)
		}
	}
}

func TestPushTemplateDirsValidatesRequest(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	cases := []struct {
		name string
		req  PushTemplateDirRequest
		want string
	}{
		{"no registry", PushTemplateDirRequest{TemplateRef: "a:v1", LayerDirs: []string{dir}}, "no OCI registry"},
		{"tagged registry target", PushTemplateDirRequest{Registry: "r.example/x:someone-elses-tag", TemplateRef: "a:v1", LayerDirs: []string{dir}}, "carries a tag/digest"},
		{"bad ref", PushTemplateDirRequest{Registry: "r.example/x", TemplateRef: "../evil", LayerDirs: []string{dir}}, "invalid template ref"},
		{"no layers", PushTemplateDirRequest{Registry: "r.example/x", TemplateRef: "a:v1"}, "no layer directories"},
		{"layer not a dir", PushTemplateDirRequest{Registry: "r.example/x", TemplateRef: "a:v1", LayerDirs: []string{filepath.Join(dir, "missing")}}, "not a directory"},
	}
	for _, tc := range cases {
		if _, err := PushTemplateDirs(ctx, tc.req); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: err = %v, want %q", tc.name, err, tc.want)
		}
	}
}

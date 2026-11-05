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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/content/file"
)

// Two instances sharing the store (k8s pods all run as PID 1, so a
// PID-derived name collides) saving the same ref must produce exactly one
// published template and one immutability error — never a published layer
// whose directory the loser removes.
func TestSaveAsTemplateConcurrentSameRef(t *testing.T) {
	templatesDir := t.TempDir()
	overlayBase := t.TempDir()

	managers := make([]*Manager, 2)
	for i := range managers {
		m, err := NewManager(Config{TemplatesDir: templatesDir, OverlayBase: overlayBase, ResolveVolume: legacyResolver(overlayBase)})
		if err != nil {
			t.Fatalf("NewManager: %v", err)
		}
		managers[i] = m

		dir := filepath.Join(overlayBase, fmt.Sprintf("flat-%d", i))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("from-%d.txt", i)), []byte(fmt.Sprintf("source-%d", i)), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	start := make(chan struct{})
	errs := make([]error, len(managers))
	var wg sync.WaitGroup
	for i := range managers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, errs[i] = managers[i].SaveAsTemplate(context.Background(), fmt.Sprintf("flat-%d", i), SaveAsTemplateRequest{TemplateRef: "race:v1"})
		}(i)
	}
	close(start)
	wg.Wait()

	var ok, exists int
	for _, err := range errs {
		switch {
		case err == nil:
			ok++
		case errors.Is(err, ErrRefExists):
			exists++
		default:
			t.Fatalf("unexpected save error: %v", err)
		}
	}
	if ok != 1 || exists != 1 {
		t.Fatalf("saves: %d ok, %d ErrRefExists, want 1/1", ok, exists)
	}

	entry, err := managers[0].LoadRefEntry("race:v1", "overlay")
	if err != nil {
		t.Fatalf("LoadRefEntry: %v", err)
	}
	layerDir := managers[0].ResolveLayerPath(entry.Layers[0])
	if _, err := os.Stat(layerDir); err != nil {
		t.Fatalf("published layer dir missing: %v", err)
	}
	// The published layer is ONE source's complete tree — never a blend, and
	// never a tree the losing save removed after publication.
	present := 0
	for i := 0; i < 2; i++ {
		path := filepath.Join(layerDir, fmt.Sprintf("from-%d.txt", i))
		data, err := os.ReadFile(path)
		if err == nil {
			present++
			if want := fmt.Sprintf("source-%d", i); string(data) != want {
				t.Fatalf("%s = %q, want %q", path, data, want)
			}
		} else if !os.IsNotExist(err) {
			t.Fatalf("stat %s: %v", path, err)
		}
	}
	if present != 1 {
		t.Fatalf("published layer contains %d source markers, want exactly 1", present)
	}

	if matches, _ := filepath.Glob(filepath.Join(templatesDir, "layers", ".local-race-v1.staging-*")); len(matches) != 0 {
		t.Fatalf("staging dirs left behind: %v", matches)
	}
}

// A directory left at the final name by an interrupted save (marker present,
// no ref) is replaced by a new save; nothing else may be wiped.
func TestSaveAsTemplateReplacesAbortedTarget(t *testing.T) {
	templatesDir := t.TempDir()
	overlayBase := t.TempDir()
	m, err := NewManager(Config{TemplatesDir: templatesDir, OverlayBase: overlayBase, ResolveVolume: legacyResolver(overlayBase)})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	target := filepath.Join(templatesDir, "layers", "local-recover-v1")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, saveStagingMarker), []byte("save in progress\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "junk.txt"), []byte("junk"), 0o644); err != nil {
		t.Fatal(err)
	}

	sandfsDir := filepath.Join(overlayBase, "flat-recover")
	if err := os.MkdirAll(sandfsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sandfsDir, "fresh.txt"), []byte("fresh"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := m.SaveAsTemplate(context.Background(), "flat-recover", SaveAsTemplateRequest{TemplateRef: "recover:v1"}); err != nil {
		t.Fatalf("SaveAsTemplate: %v", err)
	}
	if _, err := os.Stat(filepath.Join(target, "fresh.txt")); err != nil {
		t.Fatalf("fresh content missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(target, "junk.txt")); !os.IsNotExist(err) {
		t.Fatalf("aborted target content survived (err=%v)", err)
	}
}

// extractLayersToCache from two managers over the same store runs the same
// digest concurrently in-process (the k8s case has two processes with the same
// PID). Exactly one complete layer may appear; the other loses the publish
// without corrupting or duplicating it.
func TestExtractLayersToCacheConcurrentSameDigest(t *testing.T) {
	templatesDir := t.TempDir()
	overlayBase := t.TempDir()

	blob := makeLayerBlob(t, 200)
	desc := ocispec.Descriptor{
		MediaType: ocispec.MediaTypeImageLayerGzip,
		Digest:    digest.FromBytes(blob),
		Size:      int64(len(blob)),
	}

	stores := make([]*file.Store, 2)
	managers := make([]*Manager, 2)
	for i := range managers {
		store, err := file.New(t.TempDir())
		if err != nil {
			t.Fatalf("file.New: %v", err)
		}
		defer store.Close()
		stores[i] = store
		if err := store.Push(context.Background(), desc, bytes.NewReader(blob)); err != nil {
			t.Fatalf("store.Push: %v", err)
		}
		m, err := NewManager(Config{TemplatesDir: templatesDir, OverlayBase: overlayBase, ResolveVolume: legacyResolver(overlayBase)})
		if err != nil {
			t.Fatalf("NewManager: %v", err)
		}
		managers[i] = m
	}

	start := make(chan struct{})
	errs := make([]error, len(managers))
	var wg sync.WaitGroup
	for i := range managers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, errs[i] = managers[i].extractLayersToCache(context.Background(), stores[i], []ocispec.Descriptor{desc})
		}(i)
	}
	close(start)
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("extract %d: %v", i, err)
		}
	}

	short := strings.ReplaceAll(desc.Digest.String(), ":", "-")
	layerDir := filepath.Join(templatesDir, "layers", short)
	for i := 0; i < 200; i++ {
		path := filepath.Join(layerDir, fmt.Sprintf("file-%03d", i))
		if data, err := os.ReadFile(path); err != nil || string(data) != fmt.Sprintf("content-%03d", i) {
			t.Fatalf("%s = %q, %v", path, data, err)
		}
	}
	if matches, _ := filepath.Glob(filepath.Join(templatesDir, "layers", "."+short+".staging-*")); len(matches) != 0 {
		t.Fatalf("staging dirs left behind: %v", matches)
	}
}

func makeLayerBlob(t *testing.T, files int) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for i := 0; i < files; i++ {
		content := []byte(fmt.Sprintf("content-%03d", i))
		hdr := &tar.Header{
			Name:     fmt.Sprintf("file-%03d", i),
			Mode:     0o644,
			Size:     int64(len(content)),
			Typeflag: tar.TypeReg,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

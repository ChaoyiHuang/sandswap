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
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/file"
	"oras.land/oras-go/v2/registry"
	"oras.land/oras-go/v2/registry/remote"
)

// NewRegistryRepository builds the authenticated remote repository shared by
// every registry operation (pull, push). Plain HTTP is auto-detected for
// loopback endpoints — the OCI distribution spec's TLS carve-out — by parsing
// the reference's HOST, not a string prefix: a registry literally named
// "localhost.example" is a remote endpoint and must not silently downgrade
// to plaintext.
func NewRegistryRepository(registryRef string, auth AuthConfig) (*remote.Repository, error) {
	repo, err := remote.NewRepository(registryRef)
	if err != nil {
		return nil, fmt.Errorf("create repository: %w", err)
	}
	authClient, err := auth.toClient()
	if err != nil {
		return nil, fmt.Errorf("setup auth: %w", err)
	}
	repo.Client = authClient
	if isLoopbackRegistry(registryRef) {
		repo.PlainHTTP = true
	}
	return repo, nil
}

// isLoopbackRegistry reports whether the reference's host part is a loopback
// endpoint (localhost / 127.0.0.1 / ::1), port included in the parse.
func isLoopbackRegistry(registryRef string) bool {
	ref, err := registry.ParseReference(registryRef)
	if err != nil {
		return false
	}
	host := strings.ToLower(ref.Registry)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	switch host {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	return false
}

// pushTemplateArtifact packs the given layer directories (paths the CALLER
// has already resolved and trusts — the manager enforces its store trust
// boundary before calling this, offline callers name their own trees) as a
// Sandswap template artifact and copies it to dst. The artifact tag is the
// template ref with ':'→'-' (OCI tags carry no colons — the form the prov
// instance's pull path expects); mode and description land in the config
// blob and annotations; extraAnnotations are merged in as producer metadata.
func pushTemplateArtifact(ctx context.Context, dst oras.Target, templateRef, mode, description string, layerPaths []string, extraAnnotations map[string]string) (*PushTemplateResponse, error) {
	if len(layerPaths) == 0 {
		return nil, fmt.Errorf("template %s records no local layers; nothing to push", templateRef)
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
	for i, layerPath := range layerPaths {
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

	name, version := parseTemplateRef(templateRef)
	annotations := map[string]string{
		"sandswap.template.name":        name,
		"sandswap.template.version":     version,
		"sandswap.template.description": description,
	}
	for k, v := range extraAnnotations {
		annotations[k] = v
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
	_, err = oras.Copy(ctx, store, pushTag, dst, ociTag, oras.DefaultCopyOptions)
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

// PushTemplateDirRequest pushes operator-supplied layer directories as a
// Sandswap template artifact — the standalone path used by offline tools
// (template-tool import) that hold a finished tree but no template store,
// no ref files, and no running stack.
type PushTemplateDirRequest struct {
	// Registry is the target repository reference
	// ("registry.example.com/sandswap-templates").
	Registry string
	// Auth carries the registry credentials (any of the prov instance's
	// methods: basic / token / mTLS / private CA).
	Auth AuthConfig
	// TemplateRef is "name:version"; the artifact tag is name-version.
	TemplateRef string
	// Description lands in the artifact annotations.
	Description string
	// LayerDirs are the layer directories, bottom→top (one merged tree for
	// a converted image).
	LayerDirs []string
	// Annotations are extra producer metadata (e.g. the source image digest).
	Annotations map[string]string
}

// PushTemplateDirs validates the request, builds the authenticated target,
// and pushes the artifact. It performs NO store trust-boundary resolution —
// the caller names the directories explicitly, so there is no shared-storage
// ref to launder a path through (that check belongs to PushTemplate, which
// reads paths from a ref file).
//
// There is deliberately NO mode parameter: the artifact is mode-agnostic
// (the same tag pulls as flat or overlay — the mode lives in the consuming
// side's local ref file, never in the artifact). The config blob's
// template_mode is recorded as "overlay" — the platform's default mode
// everywhere else too (PullTemplate/PushTemplate/save-as-template) — and
// currently has no consumer. It stays non-empty ON PURPOSE: every existing
// artifact carries "flat"|"overlay" there, and an empty string would mint a
// third shape the first future reader has to special-case.
func PushTemplateDirs(ctx context.Context, req PushTemplateDirRequest) (*PushTemplateResponse, error) {
	if req.Registry == "" {
		return nil, fmt.Errorf("no OCI registry given")
	}
	// The destination must be a REPOSITORY: the artifact tag is always
	// <name>-<version>. A tag/digest on the target would be silently
	// ignored by the push (oras uses the tag we pass), so refuse it loudly
	// instead of letting the operator believe it took effect.
	if ref, err := registry.ParseReference(req.Registry); err == nil && ref.Reference != "" {
		return nil, fmt.Errorf("push target %q carries a tag/digest; the artifact tag is always <name>-<version> — pass a repository reference only", req.Registry)
	}
	if err := validateRef(req.TemplateRef); err != nil {
		return nil, err
	}
	if len(req.LayerDirs) == 0 {
		return nil, fmt.Errorf("no layer directories given")
	}
	paths := make([]string, len(req.LayerDirs))
	for i, d := range req.LayerDirs {
		abs, err := filepath.Abs(d)
		if err != nil {
			return nil, fmt.Errorf("layer %d: %w", i, err)
		}
		if info, err := os.Stat(abs); err != nil || !info.IsDir() {
			return nil, fmt.Errorf("layer %d not a directory: %s", i, abs)
		}
		paths[i] = abs
	}
	repo, err := NewRegistryRepository(req.Registry, req.Auth)
	if err != nil {
		return nil, err
	}
	// "overlay": the platform-default mode, kept non-empty for config-shape
	// compatibility with every existing artifact (see the comment above).
	return pushTemplateArtifact(ctx, repo, req.TemplateRef, "overlay", req.Description, paths, req.Annotations)
}

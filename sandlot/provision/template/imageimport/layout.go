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

package imageimport

import (
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"golang.org/x/sys/unix"
)

// Docker (distribution v2) media types — the OCI spec constants cover the
// OCI spellings only, and docker-save archives carry the docker ones.
const (
	mediaTypeDockerManifest = "application/vnd.docker.distribution.manifest.v2+json"
	mediaTypeDockerList     = "application/vnd.docker.distribution.manifest.list.v2+json"
	mediaTypeDockerConfig   = "application/vnd.docker.container.image.v1+json"
	mediaTypeDockerLayerGz  = "application/vnd.docker.image.rootfs.diff.tar.gzip"
)

// manifestMediaTypes / indexMediaTypes / configMediaTypes are the allowlists
// for the descriptors an import walks through. Anything else (schema1,
// sandswap artifacts, unknown) is refused with the media type named.
func isManifestMediaType(mt string) bool {
	return mt == ocispec.MediaTypeImageManifest || mt == mediaTypeDockerManifest
}

func isIndexMediaType(mt string) bool {
	return mt == ocispec.MediaTypeImageIndex || mt == mediaTypeDockerList
}

func isConfigMediaType(mt string) bool {
	return mt == ocispec.MediaTypeImageConfig || mt == mediaTypeDockerConfig
}

// checkLayerMediaType validates one layer descriptor BEFORE any blob bytes
// are read. The extraction path supports gzip and plain tar; zstd needs a
// dependency this repo does not carry, and foreign/nondistributable blobs
// cannot be assumed present.
func checkLayerMediaType(desc ocispec.Descriptor) error {
	switch desc.MediaType {
	case ocispec.MediaTypeImageLayerGzip, ocispec.MediaTypeImageLayer, mediaTypeDockerLayerGz:
		return nil
	case ocispec.MediaTypeImageLayerZstd, ocispec.MediaTypeImageLayerNonDistributable:
		return fmt.Errorf("layer %s: media type %q is not supported by the offline importer (re-export with gzip or plain tar layers)", shortDigest(desc.Digest), desc.MediaType)
	}
	if strings.Contains(desc.MediaType, "zstd") || strings.Contains(desc.MediaType, "foreign") ||
		strings.Contains(desc.MediaType, "nondistributable") {
		return fmt.Errorf("layer %s: media type %q is not supported by the offline importer (re-export with gzip or plain tar layers)", shortDigest(desc.Digest), desc.MediaType)
	}
	return fmt.Errorf("layer %s: unknown media type %q", shortDigest(desc.Digest), desc.MediaType)
}

func shortDigest(d digest.Digest) string {
	s := d.String()
	if len(s) > 7+19 {
		return s[:19] + "…"
	}
	return s
}

// maxMetadataBytes bounds index.json / manifest / config reads. These are
// small JSON documents in every real archive; 8 MiB is generous and still
// bounded against a crafted layout.
const maxMetadataBytes = 8 << 20

// layout is an opened OCI image-layout directory (oci-layout + index.json +
// blobs/). Every blob read through it is verified against its descriptor's
// digest AND size — a layout directory is untrusted input like a registry.
type layout struct {
	root string
}

type layoutMarker struct {
	ImageLayoutVersion string `json:"imageLayoutVersion"`
}

// isLayoutDir reports whether dir carries the OCI image-layout markers.
func isLayoutDir(dir string) bool {
	for _, name := range []string{"oci-layout", "index.json"} {
		fi, err := os.Lstat(filepath.Join(dir, name))
		if err != nil || !fi.Mode().IsRegular() {
			return false
		}
	}
	return true
}

// openLayout validates the layout markers and returns the reader.
func openLayout(root string) (*layout, error) {
	if !isLayoutDir(root) {
		return nil, fmt.Errorf("%s is not an OCI image layout (missing oci-layout/index.json)", root)
	}
	data, err := readSmallFile(filepath.Join(root, "oci-layout"), 4096)
	if err != nil {
		return nil, fmt.Errorf("read oci-layout: %w", err)
	}
	var marker layoutMarker
	if err := json.Unmarshal(data, &marker); err != nil {
		return nil, fmt.Errorf("parse oci-layout: %w", err)
	}
	if marker.ImageLayoutVersion != "1.0.0" {
		return nil, fmt.Errorf("unsupported image layout version %q (want 1.0.0)", marker.ImageLayoutVersion)
	}
	return &layout{root: root}, nil
}

// readSmallFile reads a regular file (O_NOFOLLOW, size-capped).
func readSmallFile(path string, cap int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if fi.Size() > cap {
		return nil, fmt.Errorf("%s is %d bytes (cap %d)", path, fi.Size(), cap)
	}
	return io.ReadAll(io.LimitReader(f, cap+1))
}

// blobPath maps a digest to its layout path. The digest grammar (validated
// by digest.Parse) admits no path separators or traversal, so the join is
// safe; O_NOFOLLOW at open time covers a planted symlink at the blob name.
func (l *layout) blobPath(dgst digest.Digest) (string, error) {
	if err := dgst.Validate(); err != nil {
		return "", fmt.Errorf("invalid digest %q: %w", dgst.String(), err)
	}
	return filepath.Join(l.root, "blobs", dgst.Algorithm().String(), dgst.Encoded()), nil
}

// openBlob opens a blob for streaming after checking it is a regular file
// of exactly the descriptor's size. Digest verification is the caller's job
// over the bytes it reads (see extractVerifiedBlob / readVerifiedJSON).
func (l *layout) openBlob(desc ocispec.Descriptor) (*os.File, error) {
	p, err := l.blobPath(desc.Digest)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(p, os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open blob %s: %w", shortDigest(desc.Digest), err)
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		f.Close()
		return nil, fmt.Errorf("blob %s is not a regular file", shortDigest(desc.Digest))
	}
	if fi.Size() != desc.Size {
		f.Close()
		return nil, fmt.Errorf("blob %s size mismatch: descriptor says %d bytes, file has %d",
			shortDigest(desc.Digest), desc.Size, fi.Size())
	}
	return f, nil
}

// verifyBytes hashes data and compares it against the descriptor.
func verifyBytes(data []byte, desc ocispec.Descriptor) error {
	if int64(len(data)) != desc.Size {
		return fmt.Errorf("%s size mismatch: descriptor says %d bytes, content has %d",
			kindOf(desc), desc.Size, len(data))
	}
	if err := desc.Digest.Validate(); err != nil {
		return fmt.Errorf("%s invalid digest: %w", kindOf(desc), err)
	}
	algo := desc.Digest.Algorithm()
	if !algo.Available() {
		return fmt.Errorf("%s digest algorithm %s is not available", kindOf(desc), algo)
	}
	if algo.FromBytes(data) != desc.Digest {
		return fmt.Errorf("%s digest mismatch for %s", kindOf(desc), shortDigest(desc.Digest))
	}
	return nil
}

func kindOf(desc ocispec.Descriptor) string {
	switch {
	case isConfigMediaType(desc.MediaType):
		return "config"
	case isManifestMediaType(desc.MediaType):
		return "manifest"
	case isIndexMediaType(desc.MediaType):
		return "index"
	}
	return "blob"
}

// readVerifiedJSON reads a metadata blob fully, verifies digest+size, and
// unmarshals it.
func (l *layout) readVerifiedJSON(desc ocispec.Descriptor, v any) error {
	f, err := l.openBlob(desc)
	if err != nil {
		return err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxMetadataBytes+1))
	if err != nil {
		return fmt.Errorf("read %s: %w", kindOf(desc), err)
	}
	if int64(len(data)) > maxMetadataBytes {
		return fmt.Errorf("%s exceeds the %d-byte metadata cap", kindOf(desc), maxMetadataBytes)
	}
	if err := verifyBytes(data, desc); err != nil {
		return err
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("parse %s %s: %w", kindOf(desc), shortDigest(desc.Digest), err)
	}
	return nil
}

// newHasher returns a hasher for the descriptor's digest algorithm plus the
// digest builder. Any algorithm go-digest has registered is usable (real
// layers are sha256; sha512 exists in the wild and costs nothing to accept).
func newHasher(desc ocispec.Descriptor) (hash.Hash, func() digest.Digest, error) {
	if err := desc.Digest.Validate(); err != nil {
		return nil, nil, fmt.Errorf("invalid layer digest %q: %w", desc.Digest.String(), err)
	}
	algo := desc.Digest.Algorithm()
	if !algo.Available() {
		return nil, nil, fmt.Errorf("layer %s: digest algorithm %s is not available in this build",
			shortDigest(desc.Digest), algo)
	}
	h := algo.Hash()
	// NewDigestFromBytes wraps the RAW digest bytes; Algorithm.FromBytes
	// hashes its argument (content bytes) and would double-hash here.
	return h, func() digest.Digest { return digest.NewDigestFromBytes(algo, h.Sum(nil)) }, nil
}

// resolvedImage is the selected image manifest plus what the importer knows
// about its origin.
type resolvedImage struct {
	manifest ocispec.Manifest
	// digest identifies the selected image manifest (after platform
	// selection through any nesting) — the identity recorded in the result.
	digest digest.Digest
}

// resolveImage walks index.json to the single image manifest matching want.
func resolveImage(l *layout, want ocispec.Platform) (*resolvedImage, error) {
	data, err := readSmallFile(filepath.Join(l.root, "index.json"), maxMetadataBytes)
	if err != nil {
		return nil, fmt.Errorf("read index.json: %w", err)
	}
	var index ocispec.Index
	if err := json.Unmarshal(data, &index); err != nil {
		return nil, fmt.Errorf("parse index.json: %w", err)
	}
	if len(index.Manifests) == 0 {
		return nil, fmt.Errorf("index.json references no manifests")
	}
	visited := map[digest.Digest]bool{}
	return selectManifest(l, index.Manifests, want, "index.json", 0, visited)
}

// maxManifestDepth bounds nested-index walking (an index pointing at an
// index pointing at …); the visited set breaks cycles by digest.
const maxManifestDepth = 4

// attestationAnnotation is the docker/buildx convention marking provenance
// and SBOM attestation manifests inside an index; they are not images.
const attestationAnnotationKey = "vnd.docker.reference.type"

// isAttestation reports a provenance/SBOM companion entry, not an image.
// Either the annotation says so, or (buildx style) the entry carries no
// platform while a sibling does — a lone platform-less entry is the image
// itself (single-arch archives do exactly that).
func isAttestation(desc ocispec.Descriptor, siblingHasPlatform bool) bool {
	if desc.Annotations != nil && desc.Annotations[attestationAnnotationKey] == "attestation-manifest" {
		return true
	}
	return desc.Platform == nil && siblingHasPlatform
}

// selectManifest picks the image manifest for the wanted platform from one
// index level, recursing through nested indexes with bounds.
func selectManifest(l *layout, descs []ocispec.Descriptor, want ocispec.Platform, from string, depth int, visited map[digest.Digest]bool) (*resolvedImage, error) {
	if depth > maxManifestDepth {
		return nil, fmt.Errorf("manifest nesting deeper than %d levels", maxManifestDepth)
	}

	siblingHasPlatform := false
	for _, d := range descs {
		if d.Platform != nil {
			siblingHasPlatform = true
			break
		}
	}

	var candidates []ocispec.Descriptor
	var real []ocispec.Descriptor
	for _, d := range descs {
		if isAttestation(d, siblingHasPlatform) {
			continue
		}
		real = append(real, d)
		if d.Platform != nil && platformMatches(want, *d.Platform) {
			candidates = append(candidates, d)
		}
	}
	if len(real) == 0 {
		return nil, fmt.Errorf("%s references only attestation manifests (no image)", from)
	}
	switch {
	case len(candidates) == 1:
	case len(real) == 1:
		// Single non-attestation entry with absent/unmatched platform: take
		// it — the config check below still verifies the platform.
		candidates = real
	default:
		var listed []string
		for _, d := range real {
			if d.Platform == nil {
				listed = append(listed, "unknown platform")
			} else {
				listed = append(listed, d.Platform.OS+"/"+d.Platform.Architecture+variantSuffix(d.Platform.Variant))
			}
		}
		if len(candidates) == 0 {
			return nil, fmt.Errorf("%s carries no %s/%s manifest (available: %s)",
				from, want.OS, want.Architecture, strings.Join(listed, ", "))
		}
		return nil, fmt.Errorf("%s is ambiguous: %d manifests match %s/%s (available: %s); re-export a single-platform archive",
			from, len(candidates), want.OS, want.Architecture, strings.Join(listed, ", "))
	}

	desc := candidates[0]
	if err := desc.Digest.Validate(); err != nil {
		return nil, fmt.Errorf("%s entry digest %q: %w", from, desc.Digest.String(), err)
	}
	if visited[desc.Digest] {
		return nil, fmt.Errorf("manifest chain contains a cycle at %s", shortDigest(desc.Digest))
	}
	visited[desc.Digest] = true

	if isIndexMediaType(desc.MediaType) {
		var nested ocispec.Index
		if err := l.readVerifiedJSON(desc, &nested); err != nil {
			return nil, err
		}
		if len(nested.Manifests) == 0 {
			return nil, fmt.Errorf("nested index %s references no manifests", shortDigest(desc.Digest))
		}
		sub, err := selectManifest(l, nested.Manifests, want, "index "+shortDigest(desc.Digest), depth+1, visited)
		if err != nil {
			return nil, err
		}
		return sub, nil
	}
	if !isManifestMediaType(desc.MediaType) {
		return nil, fmt.Errorf("%s entry %s is a %q, not an image manifest (schema1 and artifact manifests are not supported)",
			from, shortDigest(desc.Digest), desc.MediaType)
	}

	var manifest ocispec.Manifest
	if err := l.readVerifiedJSON(desc, &manifest); err != nil {
		return nil, err
	}
	if len(manifest.Layers) == 0 {
		return nil, fmt.Errorf("image manifest %s references no layers", shortDigest(desc.Digest))
	}
	// The config blob must be a container image config with a platform
	// matching the selection — this also rejects non-image artifacts whose
	// manifests happen to parse.
	if !isConfigMediaType(manifest.Config.MediaType) {
		return nil, fmt.Errorf("image manifest %s has config media type %q (not a container image)",
			shortDigest(desc.Digest), manifest.Config.MediaType)
	}
	var img ocispec.Image
	if err := l.readVerifiedJSON(manifest.Config, &img); err != nil {
		return nil, err
	}
	if img.OS != want.OS || img.Architecture != want.Architecture {
		return nil, fmt.Errorf("image is %s/%s but %s/%s was requested",
			img.OS, img.Architecture, want.OS, want.Architecture)
	}
	return &resolvedImage{manifest: manifest, digest: desc.Digest}, nil
}

// platformMatches compares os/arch exactly and, when the WANTED variant is
// non-empty, the variant too (arm64's empty variant reads as v8, matching
// the convention registries use).
func platformMatches(want, got ocispec.Platform) bool {
	if want.OS != got.OS || want.Architecture != got.Architecture {
		return false
	}
	if want.Variant == "" {
		return true
	}
	wv, gv := want.Variant, got.Variant
	if want.Architecture == "arm64" {
		if wv == "" {
			wv = "v8"
		}
		if gv == "" {
			gv = "v8"
		}
	}
	return wv == gv
}

func variantSuffix(v string) string {
	if v == "" {
		return ""
	}
	return "/" + v
}

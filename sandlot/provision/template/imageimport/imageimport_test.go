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
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"sandlot/provision/template"
)

// ── tar/layer builders ─────────────────────────────────────────────

type tarEntry struct {
	name     string
	typeflag byte
	mode     int64
	data     string
	linkname string
	devmajor int64
	devminor int64
}

func buildTar(t *testing.T, entries []tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		hdr := &tar.Header{
			Name:     e.name,
			Typeflag: e.typeflag,
			Mode:     e.mode,
			Size:     int64(len(e.data)),
			Linkname: e.linkname,
			Devmajor: e.devmajor,
			Devminor: e.devminor,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("write header %s: %v", e.name, err)
		}
		if e.typeflag == tar.TypeReg && len(e.data) > 0 {
			if _, err := tw.Write([]byte(e.data)); err != nil {
				t.Fatalf("write data %s: %v", e.name, err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	return buf.Bytes()
}

func gz(b []byte) []byte {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write(b)
	zw.Close()
	return buf.Bytes()
}

// baseLayerEntries is a minimal contract-clean rootfs layer: /bin/sh (via a
// busybox symlink), skeleton dirs, an /etc file.
func baseLayerEntries() []tarEntry {
	return []tarEntry{
		{name: "bin/", typeflag: tar.TypeDir, mode: 0o755},
		{name: "bin/busybox", typeflag: tar.TypeReg, mode: 0o755, data: "fake busybox"},
		{name: "bin/sh", typeflag: tar.TypeSymlink, mode: 0o777, linkname: "busybox"},
		{name: "etc/", typeflag: tar.TypeDir, mode: 0o755},
		{name: "etc/os-release", typeflag: tar.TypeReg, mode: 0o644, data: "ID=test\n"},
		{name: "usr/", typeflag: tar.TypeDir, mode: 0o755},
		{name: "usr/bin/", typeflag: tar.TypeDir, mode: 0o755},
		{name: "dev/", typeflag: tar.TypeDir, mode: 0o755},
		{name: "proc/", typeflag: tar.TypeDir, mode: 0o555},
		{name: "tmp/", typeflag: tar.TypeDir, mode: 0o1777},
	}
}

// ── OCI layout builder ─────────────────────────────────────────────

type testLayout struct {
	t    *testing.T
	dir  string
	blob map[digest.Digest][]byte
}

func newTestLayout(t *testing.T) *testLayout {
	t.Helper()
	dir := t.TempDir()
	write(t, filepath.Join(dir, "oci-layout"), `{"imageLayoutVersion":"1.0.0"}`)
	return &testLayout{t: t, dir: dir, blob: map[digest.Digest][]byte{}}
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func (l *testLayout) addBlob(mediaType string, content []byte) ocispec.Descriptor {
	l.t.Helper()
	sum := sha256.Sum256(content)
	d := digest.NewDigestFromEncoded(digest.SHA256, hex.EncodeToString(sum[:]))
	l.blob[d] = content
	p := filepath.Join(l.dir, "blobs", "sha256", d.Encoded())
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		l.t.Fatal(err)
	}
	if err := os.WriteFile(p, content, 0o644); err != nil {
		l.t.Fatal(err)
	}
	return ocispec.Descriptor{Digest: d, Size: int64(len(content)), MediaType: mediaType}
}

// addLayer packs a gzip layer blob from tar entries.
func (l *testLayout) addLayer(entries []tarEntry) ocispec.Descriptor {
	l.t.Helper()
	return l.addBlob(ocispec.MediaTypeImageLayerGzip, gz(buildTar(l.t, entries)))
}

// addImage writes a config + image manifest and returns the manifest
// descriptor (platform set from os/arch).
func (l *testLayout) addImage(osName, arch string, layers []ocispec.Descriptor, mutateManifest func(*ocispec.Manifest)) ocispec.Descriptor {
	l.t.Helper()
	cfg := map[string]any{"os": osName, "architecture": arch, "rootfs": map[string]any{"type": "layers"}}
	cfgData, _ := json.Marshal(cfg)
	cfgDesc := l.addBlob(ocispec.MediaTypeImageConfig, cfgData)
	m := ocispec.Manifest{
		MediaType: ocispec.MediaTypeImageManifest,
		Config:    cfgDesc,
		Layers:    layers,
	}
	if mutateManifest != nil {
		mutateManifest(&m)
	}
	mData, _ := json.Marshal(m)
	return l.addBlob(ocispec.MediaTypeImageManifest, mData)
}

func (l *testLayout) finishIndex(descs ...ocispec.Descriptor) {
	l.t.Helper()
	idx := ocispec.Index{MediaType: ocispec.MediaTypeImageIndex, Manifests: descs}
	data, _ := json.Marshal(idx)
	write(l.t, filepath.Join(l.dir, "index.json"), string(data))
}

// simpleImage finishes a single-arch layout over the given layers.
func (l *testLayout) simpleImage(layers ...ocispec.Descriptor) {
	l.t.Helper()
	l.finishIndex(l.addImage("linux", "amd64", layers, nil))
}

// dirToTarGz packs a directory tree into a gzipped tar (for archive-mode
// tests over a built layout).
func dirToTarGz(t *testing.T, root string) string {
	t.Helper()
	var entries []tarEntry
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || path == root {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		name := filepath.ToSlash(rel)
		info, ierr := d.Info()
		if ierr != nil {
			return ierr
		}
		mode := int64(info.Mode().Perm())
		switch {
		case d.IsDir():
			entries = append(entries, tarEntry{name: name + "/", typeflag: tar.TypeDir, mode: mode})
		case info.Mode()&os.ModeSymlink != 0:
			target, lerr := os.Readlink(path)
			if lerr != nil {
				return lerr
			}
			entries = append(entries, tarEntry{name: name, typeflag: tar.TypeSymlink, mode: 0o777, linkname: target})
		default:
			data, rerr := os.ReadFile(path)
			if rerr != nil {
				return rerr
			}
			entries = append(entries, tarEntry{name: name, typeflag: tar.TypeReg, mode: mode, data: string(data)})
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "archive.tar.gz")
	if err := os.WriteFile(p, gz(buildTar(t, entries)), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// ── import runner ──────────────────────────────────────────────────

func runImport(t *testing.T, src string) (*Result, error) {
	t.Helper()
	out := t.TempDir()
	res, err := Import(Options{Src: src, Name: "img", Version: "v1", Out: out})
	if err == nil {
		// Every published tree must pass the full offline gate on its own
		// terms — assert it here once for all success-path tests.
		findings, ferr := template.ValidateRootfsTree(res.Path)
		if ferr != nil {
			t.Fatalf("post-publish validate: %v", ferr)
		}
		for _, f := range findings {
			if f.Severity == template.SeverityError {
				t.Fatalf("post-publish validate error: %s: %s", f.Path, f.Detail)
			}
		}
	}
	return res, err
}

func readTreeFile(t *testing.T, root, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(b)
}

func treeExists(t *testing.T, root, rel string) bool {
	t.Helper()
	_, err := os.Lstat(filepath.Join(root, rel))
	return err == nil
}

// ── format detection / classification ──────────────────────────────

func TestImportLayoutDirInput(t *testing.T) {
	l := newTestLayout(t)
	base := l.addLayer(baseLayerEntries())
	l.simpleImage(base)
	res, err := runImport(t, l.dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := readTreeFile(t, res.Path, "etc/os-release"); got != "ID=test\n" {
		t.Fatalf("os-release = %q", got)
	}
	if !treeExists(t, res.Path, "workspace") || !treeExists(t, res.Path, "sys") {
		t.Fatal("skeleton/sys not created")
	}
}

// A stock image carries an empty home/ (or none at all); the overlay attach
// binds the volume's home/ onto <rootfs>/home/agent and cannot create the
// target on a read-only overlay root, so the published tree must carry it
// as a REAL directory. The base layer here has no home/ at all, and the
// second case has the empty-home shape every stock distro image has.
func TestImportPublishesHomeAgent(t *testing.T) {
	for _, tc := range []struct {
		desc string
		base []tarEntry
	}{
		{"no home at all", baseLayerEntries()},
		{"empty home/", append(baseLayerEntries(), tarEntry{name: "home/", typeflag: tar.TypeDir, mode: 0o755})},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			l := newTestLayout(t)
			l.simpleImage(l.addLayer(tc.base))
			res, err := runImport(t, l.dir)
			if err != nil {
				t.Fatal(err)
			}
			p := filepath.Join(res.Path, "home", "agent")
			info, err := os.Lstat(p)
			if err != nil {
				t.Fatalf("home/agent not published: %v", err)
			}
			if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				t.Fatalf("home/agent must be a real directory, got mode %v", info.Mode())
			}
		})
	}
}

func TestImportLayoutArchiveGzipAndPlain(t *testing.T) {
	l := newTestLayout(t)
	base := l.addLayer(baseLayerEntries())
	l.simpleImage(base)

	arch := dirToTarGz(t, l.dir)
	if _, err := runImport(t, arch); err != nil {
		t.Fatalf("gzip archive: %v", err)
	}

	plain := strings.TrimSuffix(arch, ".gz") + ".tar"
	// Re-pack the same layout as a plain tar.
	if err := os.WriteFile(plain, buildTar(t, layoutDirEntries(t, l.dir)), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := runImport(t, plain); err != nil {
		t.Fatalf("plain tar archive: %v", err)
	}
}

func layoutDirEntries(t *testing.T, root string) []tarEntry {
	t.Helper()
	var entries []tarEntry
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || path == root {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		name := filepath.ToSlash(rel)
		info, _ := d.Info()
		if d.IsDir() {
			entries = append(entries, tarEntry{name: name + "/", typeflag: tar.TypeDir, mode: int64(info.Mode().Perm())})
			return nil
		}
		data, _ := os.ReadFile(path)
		entries = append(entries, tarEntry{name: name, typeflag: tar.TypeReg, mode: 0o644, data: string(data)})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return entries
}

func TestImportWrappedLayoutArchive(t *testing.T) {
	l := newTestLayout(t)
	base := l.addLayer(baseLayerEntries())
	l.simpleImage(base)
	// Wrap the layout under a single top-level directory.
	inner := layoutDirEntries(t, l.dir)
	wrapped := make([]tarEntry, 0, len(inner)+1)
	wrapped = append(wrapped, tarEntry{name: "wrap/", typeflag: tar.TypeDir, mode: 0o755})
	for _, e := range inner {
		e.name = "wrap/" + e.name
		wrapped = append(wrapped, e)
	}
	p := filepath.Join(t.TempDir(), "wrapped.tar")
	if err := os.WriteFile(p, buildTar(t, wrapped), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := runImport(t, p); err != nil {
		t.Fatalf("wrapped layout: %v", err)
	}
}

func TestImportLegacyDockerSaveRefused(t *testing.T) {
	p := filepath.Join(t.TempDir(), "legacy.tar")
	entries := []tarEntry{
		{name: "manifest.json", typeflag: tar.TypeReg, mode: 0o644, data: `[{"Config":"x.json","RepoTags":[],"Layers":[]}]`},
	}
	if err := os.WriteFile(p, buildTar(t, entries), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := runImport(t, p)
	if err == nil || !strings.Contains(err.Error(), "legacy docker-save") {
		t.Fatalf("err = %v, want legacy docker-save refusal", err)
	}
}

func TestImportIncompleteLayoutRefused(t *testing.T) {
	cases := map[string][]tarEntry{
		"blobs without markers": {{name: "blobs/", typeflag: tar.TypeDir, mode: 0o755}},
		"oci-layout without index": {
			{name: "oci-layout", typeflag: tar.TypeReg, mode: 0o644, data: `{"imageLayoutVersion":"1.0.0"}`},
		},
	}
	for name, entries := range cases {
		p := filepath.Join(t.TempDir(), "broken.tar")
		if err := os.WriteFile(p, buildTar(t, entries), 0o644); err != nil {
			t.Fatal(err)
		}
		_, err := runImport(t, p)
		if err == nil || !strings.Contains(err.Error(), "incomplete OCI image layout") {
			t.Fatalf("%s: err = %v, want incomplete layout refusal", name, err)
		}
	}
}

func TestImportZstdArchiveRefused(t *testing.T) {
	p := filepath.Join(t.TempDir(), "zst.tar")
	if err := os.WriteFile(p, []byte{0x28, 0xb5, 0x2f, 0xfd, 0, 0}, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := runImport(t, p)
	if err == nil || !strings.Contains(err.Error(), "zstd") {
		t.Fatalf("err = %v, want zstd refusal", err)
	}
}

func TestImportXzAndBzip2ArchivesRefused(t *testing.T) {
	for name, magic := range map[string][]byte{
		"xz":    {0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00},
		"bzip2": {0x42, 0x5a, 0x68, 0x31, 0, 0},
	} {
		p := filepath.Join(t.TempDir(), name+".tar")
		if err := os.WriteFile(p, append(append([]byte{}, magic...), 0, 0), 0o644); err != nil {
			t.Fatal(err)
		}
		_, err := runImport(t, p)
		if err == nil || !strings.Contains(err.Error(), name) {
			t.Fatalf("%s: err = %v, want named refusal", name, err)
		}
	}
}

func TestImportGzipOuterArchiveAccepted(t *testing.T) {
	// The outer archive may be gzip-compressed (docker save writes .tar;
	// a gzipped repack must pass the same path).
	l := newTestLayout(t)
	base := l.addLayer(baseLayerEntries())
	l.simpleImage(base)
	arch := dirToTarGz(t, l.dir) // already gzip
	if _, err := runImport(t, arch); err != nil {
		t.Fatalf("gzip outer archive: %v", err)
	}
}

func TestImportRootfsTar(t *testing.T) {
	p := filepath.Join(t.TempDir(), "rootfs.tar.gz")
	entries := append(baseLayerEntries(),
		tarEntry{name: "home/agent/", typeflag: tar.TypeDir, mode: 0o755},
	)
	if err := os.WriteFile(p, gz(buildTar(t, entries)), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := runImport(t, p)
	if err != nil {
		t.Fatal(err)
	}
	if res.Source != "rootfs" {
		t.Fatalf("source = %q", res.Source)
	}
	if got := readTreeFile(t, res.Path, "bin/busybox"); got != "fake busybox" {
		t.Fatalf("busybox = %q", got)
	}
	// A plain rootfs carries no platform metadata; the import must say so.
	warned := false
	for _, w := range res.Warnings {
		if strings.Contains(w, "platform metadata") && strings.Contains(w, "linux/amd64") {
			warned = true
		}
	}
	if !warned {
		t.Fatalf("rootfs import did not warn about the unverifiable platform: %v", res.Warnings)
	}
}

func TestImportRootfsTarSingleTopDirRefused(t *testing.T) {
	p := filepath.Join(t.TempDir(), "bad.tar")
	entries := []tarEntry{
		{name: "rootfs/", typeflag: tar.TypeDir, mode: 0o755},
		{name: "rootfs/x", typeflag: tar.TypeReg, mode: 0o644, data: "x"},
	}
	if err := os.WriteFile(p, buildTar(t, entries), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := runImport(t, p)
	if err == nil || !strings.Contains(err.Error(), "tar -C") {
		t.Fatalf("err = %v, want repack hint", err)
	}
}

func TestImportRootfsDirInput(t *testing.T) {
	src := t.TempDir()
	for _, e := range baseLayerEntries() {
		p := filepath.Join(src, filepath.FromSlash(e.name))
		switch e.typeflag {
		case tar.TypeDir:
			os.MkdirAll(p, os.FileMode(e.mode))
		case tar.TypeReg:
			os.MkdirAll(filepath.Dir(p), 0o755)
			os.WriteFile(p, []byte(e.data), os.FileMode(e.mode))
		case tar.TypeSymlink:
			os.Symlink(e.linkname, p)
		}
	}
	res, err := runImport(t, src)
	if err != nil {
		t.Fatal(err)
	}
	if !treeExists(t, res.Path, "bin/sh") {
		t.Fatal("bin/sh missing")
	}
	// The source directory must not be mutated by the policy pass.
	if treeExists(t, src, "workspace") || treeExists(t, src, "sys") {
		t.Fatal("policy pass mutated the source rootfs directory")
	}
}

// ── manifest resolution ────────────────────────────────────────────

func TestImportMultiArchPicksAmd64(t *testing.T) {
	l := newTestLayout(t)
	base := l.addLayer(baseLayerEntries())
	arm := l.addLayer([]tarEntry{
		{name: "bin/", typeflag: tar.TypeDir, mode: 0o755},
		{name: "bin/sh", typeflag: tar.TypeReg, mode: 0o755, data: "arm"},
	})
	armDesc := l.addImage("linux", "arm64", []ocispec.Descriptor{arm}, func(m *ocispec.Manifest) {})
	amdDesc := l.addImage("linux", "amd64", []ocispec.Descriptor{base}, nil)
	// arm64 FIRST: selection must be by platform, not by order.
	l.finishIndex(withPlatform(armDesc, "linux", "arm64"), withPlatform(amdDesc, "linux", "amd64"))

	res, err := runImport(t, l.dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := readTreeFile(t, res.Path, "etc/os-release"); got != "ID=test\n" {
		t.Fatal("amd64 image not selected")
	}
}

func withPlatform(d ocispec.Descriptor, osName, arch string) ocispec.Descriptor {
	d.Platform = &ocispec.Platform{OS: osName, Architecture: arch}
	return d
}

func TestImportMultiArchNoMatchListsPlatforms(t *testing.T) {
	l := newTestLayout(t)
	base := l.addLayer(baseLayerEntries())
	d := l.addImage("linux", "arm64", []ocispec.Descriptor{base}, nil)
	l.finishIndex(withPlatform(d, "linux", "arm64"))

	_, err := runImport(t, l.dir)
	if err == nil || !strings.Contains(err.Error(), "arm64") || !strings.Contains(err.Error(), "amd64") {
		t.Fatalf("err = %v, want platform listing", err)
	}
}

func TestImportAttestationEntriesSkipped(t *testing.T) {
	l := newTestLayout(t)
	base := l.addLayer(baseLayerEntries())
	img := l.addImage("linux", "amd64", []ocispec.Descriptor{base}, nil)
	att := l.addBlob(ocispec.MediaTypeImageManifest, []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{},"layers":[]}`))
	att.Annotations = map[string]string{"vnd.docker.reference.type": "attestation-manifest"}
	l.finishIndex(img, att)

	if _, err := runImport(t, l.dir); err != nil {
		t.Fatalf("attestation companion broke selection: %v", err)
	}
}

func TestImportNestedIndex(t *testing.T) {
	l := newTestLayout(t)
	base := l.addLayer(baseLayerEntries())
	img := withPlatform(l.addImage("linux", "amd64", []ocispec.Descriptor{base}, nil), "linux", "amd64")
	innerData, _ := json.Marshal(ocispec.Index{MediaType: ocispec.MediaTypeImageIndex, Manifests: []ocispec.Descriptor{img}})
	inner := l.addBlob(ocispec.MediaTypeImageIndex, innerData)
	l.finishIndex(inner)

	if _, err := runImport(t, l.dir); err != nil {
		t.Fatalf("nested index: %v", err)
	}
}

func TestImportConfigPlatformMismatch(t *testing.T) {
	l := newTestLayout(t)
	base := l.addLayer(baseLayerEntries())
	l.simpleImageLayersArch("linux", "arm64", base)
	_, err := runImport(t, l.dir)
	if err == nil || !strings.Contains(err.Error(), "arm64") {
		t.Fatalf("err = %v, want arch mismatch", err)
	}
}

func (l *testLayout) simpleImageLayersArch(osName, arch string, layers ...ocispec.Descriptor) {
	l.finishIndex(l.addImage(osName, arch, layers, nil))
}

func TestImportCorruptLayerBlobRefused(t *testing.T) {
	l := newTestLayout(t)
	base := l.addLayer(baseLayerEntries())
	l.simpleImage(base)
	// Flip one byte of the layer blob on disk: whichever check fires first
	// (gzip framing here, digest comparison on a subtler tamper), the
	// corrupt blob must never materialize a template.
	p := filepath.Join(l.dir, "blobs", "sha256", base.Digest.Encoded())
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	data[0] ^= 0xff
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = runImport(t, l.dir)
	if err == nil {
		t.Fatal("corrupt layer blob accepted")
	}
}

func TestNewHasherSupportsSha512(t *testing.T) {
	content := []byte("layer bytes for sha512")
	sum := sha512.Sum512(content)
	d := digest.NewDigestFromEncoded(digest.SHA512, hex.EncodeToString(sum[:]))
	h, digestOf, err := newHasher(ocispec.Descriptor{
		Digest: d, Size: int64(len(content)), MediaType: ocispec.MediaTypeImageLayerGzip,
	})
	if err != nil {
		t.Fatalf("sha512 descriptor refused: %v", err)
	}
	h.Write(content)
	if got := digestOf(); got != d {
		t.Fatalf("hasher = %s, want %s", got, d)
	}
}

func TestVerifyBytesDetectsTamperedContent(t *testing.T) {
	content := []byte("layer bytes")
	sum := sha256.Sum256(content)
	desc := ocispec.Descriptor{
		Digest:    digest.NewDigestFromEncoded(digest.SHA256, hex.EncodeToString(sum[:])),
		Size:      int64(len(content)),
		MediaType: ocispec.MediaTypeImageLayerGzip,
	}
	if err := verifyBytes(content, desc); err != nil {
		t.Fatalf("clean content rejected: %v", err)
	}
	tampered := append([]byte{}, content...)
	tampered[0] ^= 0x01
	if err := verifyBytes(tampered, desc); err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("err = %v, want digest mismatch", err)
	}
	wrongSize := desc
	wrongSize.Size++
	if err := verifyBytes(content, wrongSize); err == nil || !strings.Contains(err.Error(), "size mismatch") {
		t.Fatalf("err = %v, want size mismatch", err)
	}
}

func TestImportUncompressedAndDockerLayerMediaAccepted(t *testing.T) {
	// docker save on the classic store emits UNCOMPRESSED layers
	// (vnd.oci.image.layer.v1.tar); docker schema2 images use the docker
	// gzip media type. Both must extract end to end.
	for name, mt := range map[string]string{
		"plain-tar layer":   ocispec.MediaTypeImageLayer,
		"docker gzip layer": mediaTypeDockerLayerGz,
	} {
		l := newTestLayout(t)
		var content []byte
		if mt == ocispec.MediaTypeImageLayer {
			content = buildTar(t, baseLayerEntries())
		} else {
			content = gz(buildTar(t, baseLayerEntries()))
		}
		layer := l.addBlob(mt, content)
		l.simpleImage(layer)
		res, err := runImport(t, l.dir)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := readTreeFile(t, res.Path, "etc/os-release"); got != "ID=test\n" {
			t.Fatalf("%s: os-release = %q", name, got)
		}
	}
}

func TestImportZstdLayerMediaRefusedBeforeBlobRead(t *testing.T) {
	l := newTestLayout(t)
	base := l.addLayer(baseLayerEntries())
	zstd := ocispec.Descriptor{
		Digest:    base.Digest,
		Size:      base.Size,
		MediaType: ocispec.MediaTypeImageLayerZstd,
	}
	l.simpleImage(zstd)
	_, err := runImport(t, l.dir)
	if err == nil || !strings.Contains(err.Error(), "zstd") {
		t.Fatalf("err = %v, want zstd media-type refusal", err)
	}
}

// ── layer merge semantics ──────────────────────────────────────────

func twoLayerImage(t *testing.T, lower, upper []tarEntry) string {
	l := newTestLayout(t)
	l.simpleImage(l.addLayer(lower), l.addLayer(upper))
	return l.dir
}

func TestMergeWhiteoutFile(t *testing.T) {
	src := twoLayerImage(t,
		baseLayerEntries(),
		[]tarEntry{{name: "etc/.wh.os-release", typeflag: tar.TypeReg, mode: 0o644}},
	)
	res, err := runImport(t, src)
	if err != nil {
		t.Fatal(err)
	}
	if treeExists(t, res.Path, "etc/os-release") {
		t.Fatal("os-release survived its whiteout")
	}
}

func TestWhiteoutMarkersNeverMaterialize(t *testing.T) {
	lower := append(baseLayerEntries(),
		tarEntry{name: "opt/d/", typeflag: tar.TypeDir, mode: 0o755},
		tarEntry{name: "opt/d/old", typeflag: tar.TypeReg, mode: 0o644, data: "old"},
	)
	upper := []tarEntry{
		{name: "etc/.wh.os-release", typeflag: tar.TypeReg, mode: 0o644},
		{name: "opt/d/.wh..wh..opq", typeflag: tar.TypeReg, mode: 0o644},
		{name: "opt/d/new", typeflag: tar.TypeReg, mode: 0o644, data: "new"},
	}
	res, err := runImport(t, twoLayerImage(t, lower, upper))
	if err != nil {
		t.Fatal(err)
	}
	err = filepath.WalkDir(res.Path, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if strings.HasPrefix(d.Name(), whiteoutPrefix) {
			t.Errorf("whiteout marker materialized in the template: %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestMergeWhiteoutDirectory(t *testing.T) {
	lower := append(baseLayerEntries(),
		tarEntry{name: "opt/pkg/", typeflag: tar.TypeDir, mode: 0o755},
		tarEntry{name: "opt/pkg/file", typeflag: tar.TypeReg, mode: 0o644, data: "x"},
	)
	src := twoLayerImage(t, lower,
		[]tarEntry{{name: "opt/.wh.pkg", typeflag: tar.TypeReg, mode: 0o644}})
	res, err := runImport(t, src)
	if err != nil {
		t.Fatal(err)
	}
	if treeExists(t, res.Path, "opt/pkg") {
		t.Fatal("opt/pkg survived its whiteout")
	}
}

func TestMergeOpaqueDir(t *testing.T) {
	lower := append(baseLayerEntries(),
		tarEntry{name: "opt/d/", typeflag: tar.TypeDir, mode: 0o755},
		tarEntry{name: "opt/d/old", typeflag: tar.TypeReg, mode: 0o644, data: "old"},
	)
	upper := []tarEntry{
		{name: "opt/d/", typeflag: tar.TypeDir, mode: 0o755},
		{name: "opt/d/.wh..wh..opq", typeflag: tar.TypeReg, mode: 0o644},
		{name: "opt/d/new", typeflag: tar.TypeReg, mode: 0o644, data: "new"},
	}
	res, err := runImport(t, twoLayerImage(t, lower, upper))
	if err != nil {
		t.Fatal(err)
	}
	if treeExists(t, res.Path, "opt/d/old") {
		t.Fatal("opaque dir did not hide the lower child")
	}
	if got := readTreeFile(t, res.Path, "opt/d/new"); got != "new" {
		t.Fatal("upper child lost")
	}
}

func TestMergeRootOpaque(t *testing.T) {
	// The upper layer re-provides its own /bin/sh — an opaque root wipes
	// every lower entry, and validation gates the merged tree on /bin/sh.
	upper := []tarEntry{
		{name: ".wh..wh..opq", typeflag: tar.TypeReg, mode: 0o644},
		{name: "bin/", typeflag: tar.TypeDir, mode: 0o755},
		{name: "bin/busybox", typeflag: tar.TypeReg, mode: 0o755, data: "bb"},
		{name: "bin/sh", typeflag: tar.TypeSymlink, mode: 0o777, linkname: "busybox"},
		{name: "etc/", typeflag: tar.TypeDir, mode: 0o755},
		{name: "etc/fresh", typeflag: tar.TypeReg, mode: 0o644, data: "fresh"},
	}
	lower := []tarEntry{
		{name: "bin/", typeflag: tar.TypeDir, mode: 0o755},
		{name: "bin/busybox", typeflag: tar.TypeReg, mode: 0o755, data: "old bb"},
		{name: "bin/sh", typeflag: tar.TypeSymlink, mode: 0o777, linkname: "busybox"},
		{name: "etc/", typeflag: tar.TypeDir, mode: 0o755},
		{name: "etc/old", typeflag: tar.TypeReg, mode: 0o644, data: "old"},
		{name: "var/", typeflag: tar.TypeDir, mode: 0o755},
		{name: "var/log/", typeflag: tar.TypeDir, mode: 0o755},
	}
	res, err := runImport(t, twoLayerImage(t, lower, upper))
	if err != nil {
		t.Fatal(err)
	}
	if treeExists(t, res.Path, "var") {
		t.Fatal("root opaque did not clear the tree")
	}
	if treeExists(t, res.Path, "etc/old") {
		t.Fatal("root opaque did not clear etc/")
	}
	if !treeExists(t, res.Path, "etc/fresh") {
		t.Fatal("upper content lost")
	}
	if got := readTreeFile(t, res.Path, "bin/busybox"); got != "bb" {
		t.Fatalf("lower busybox survived the opaque root: %q", got)
	}
}

func TestMergeSameLayerWhiteoutThenReadd(t *testing.T) {
	upper := []tarEntry{
		{name: "etc/.wh.os-release", typeflag: tar.TypeReg, mode: 0o644},
		{name: "etc/os-release", typeflag: tar.TypeReg, mode: 0o644, data: "ID=new\n"},
	}
	res, err := runImport(t, twoLayerImage(t, baseLayerEntries(), upper))
	if err != nil {
		t.Fatal(err)
	}
	if got := readTreeFile(t, res.Path, "etc/os-release"); got != "ID=new\n" {
		t.Fatalf("same-layer re-add lost: %q", got)
	}
}

func TestMergeWhiteoutThroughLowerSymlinkIsNoOp(t *testing.T) {
	// The masking counterexample: lower has a -> b and b/c; the upper layer
	// places a REAL directory a containing .wh.c. Overlay semantics: the
	// upper dir masks the lower symlink; /b/c must survive.
	lower := append(baseLayerEntries(),
		tarEntry{name: "a", typeflag: tar.TypeSymlink, mode: 0o777, linkname: "b"},
		tarEntry{name: "b/", typeflag: tar.TypeDir, mode: 0o755},
		tarEntry{name: "b/c", typeflag: tar.TypeReg, mode: 0o644, data: "keep"},
	)
	upper := []tarEntry{
		{name: "a/", typeflag: tar.TypeDir, mode: 0o755},
		{name: "a/.wh.c", typeflag: tar.TypeReg, mode: 0o644},
	}
	res, err := runImport(t, twoLayerImage(t, lower, upper))
	if err != nil {
		t.Fatal(err)
	}
	if got := readTreeFile(t, res.Path, "b/c"); got != "keep" {
		t.Fatal("b/c was deleted through the masked lower symlink")
	}
	if fi, err := os.Lstat(filepath.Join(res.Path, "a")); err != nil || !fi.IsDir() {
		t.Fatal("a is not the upper real directory")
	}
	if treeExists(t, res.Path, "a/c") {
		t.Fatal("whiteout victim materialized")
	}
}

func TestMergeOpaqueThroughLowerSymlinkIsNoOp(t *testing.T) {
	lower := append(baseLayerEntries(),
		tarEntry{name: "a", typeflag: tar.TypeSymlink, mode: 0o777, linkname: "b"},
		tarEntry{name: "b/", typeflag: tar.TypeDir, mode: 0o755},
		tarEntry{name: "b/c", typeflag: tar.TypeReg, mode: 0o644, data: "keep"},
	)
	upper := []tarEntry{
		{name: "a/", typeflag: tar.TypeDir, mode: 0o755},
		{name: "a/.wh..wh..opq", typeflag: tar.TypeReg, mode: 0o644},
	}
	res, err := runImport(t, twoLayerImage(t, lower, upper))
	if err != nil {
		t.Fatal(err)
	}
	if got := readTreeFile(t, res.Path, "b/c"); got != "keep" {
		t.Fatal("opaque wiped the symlink target's children")
	}
}

func TestMergeInvalidWhiteoutNames(t *testing.T) {
	for _, marker := range []string{".wh...", ".wh..", ".wh.a/b", ".wh..wh.plnk"} {
		entries := []tarEntry{{name: "etc/" + marker, typeflag: tar.TypeReg, mode: 0o644}}
		_, err := runImport(t, twoLayerImage(t, baseLayerEntries(), entries))
		if err == nil {
			t.Fatalf("marker %q accepted", marker)
		}
	}
	// A whiteout marker that is a directory is refused too.
	dirMarker := []tarEntry{{name: "etc/.wh.x/", typeflag: tar.TypeDir, mode: 0o755}}
	if _, err := runImport(t, twoLayerImage(t, baseLayerEntries(), dirMarker)); err == nil {
		t.Fatal("directory whiteout accepted")
	}
}

func TestMergeLegacyDeviceWhiteoutApplied(t *testing.T) {
	lower := append(baseLayerEntries(),
		tarEntry{name: "opt/old/", typeflag: tar.TypeDir, mode: 0o755},
		tarEntry{name: "opt/old/f", typeflag: tar.TypeReg, mode: 0o644, data: "x"},
	)
	upper := []tarEntry{
		{name: "opt/.wh.old", typeflag: tar.TypeChar, mode: 0, devmajor: 0, devminor: 0},
	}
	res, err := runImport(t, twoLayerImage(t, lower, upper))
	if err != nil {
		t.Fatal(err)
	}
	if treeExists(t, res.Path, "opt/old") {
		t.Fatal("legacy 0/0 device whiteout not applied")
	}
}

func TestMergeTypeTransitions(t *testing.T) {
	// dir → file
	res, err := runImport(t, twoLayerImage(t,
		append(baseLayerEntries(),
			tarEntry{name: "x/", typeflag: tar.TypeDir, mode: 0o755},
			tarEntry{name: "x/y", typeflag: tar.TypeReg, mode: 0o644, data: "y"},
		),
		[]tarEntry{{name: "x", typeflag: tar.TypeReg, mode: 0o644, data: "now a file"}}))
	if err != nil {
		t.Fatal(err)
	}
	if got := readTreeFile(t, res.Path, "x"); got != "now a file" {
		t.Fatalf("dir→file failed: %q", got)
	}
}

func TestMergeFileToDir(t *testing.T) {
	res, err := runImport(t, twoLayerImage(t,
		append(baseLayerEntries(), tarEntry{name: "x", typeflag: tar.TypeReg, mode: 0o644, data: "was a file"}),
		[]tarEntry{
			{name: "x/", typeflag: tar.TypeDir, mode: 0o755},
			{name: "x/y", typeflag: tar.TypeReg, mode: 0o644, data: "y"},
		}))
	if err != nil {
		t.Fatal(err)
	}
	if got := readTreeFile(t, res.Path, "x/y"); got != "y" {
		t.Fatalf("file→dir failed: %q", got)
	}
}

func TestMergeDirModeAppliedAfterChildren(t *testing.T) {
	lower := append(baseLayerEntries(),
		tarEntry{name: "m/", typeflag: tar.TypeDir, mode: 0o755},
		tarEntry{name: "m/f", typeflag: tar.TypeReg, mode: 0o644, data: "f"},
	)
	upper := []tarEntry{
		{name: "m/", typeflag: tar.TypeDir, mode: 0o555},
		{name: "m/g", typeflag: tar.TypeReg, mode: 0o644, data: "g"},
	}
	res, err := runImport(t, twoLayerImage(t, lower, upper))
	if err != nil {
		t.Fatal(err)
	}
	if !treeExists(t, res.Path, "m/f") || !treeExists(t, res.Path, "m/g") {
		t.Fatal("children lost")
	}
	fi, err := os.Lstat(filepath.Join(res.Path, "m"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o555 {
		t.Fatalf("m mode = %o, want 555", fi.Mode().Perm())
	}
}

func TestMergeHardlinkIdentityPreserved(t *testing.T) {
	entries := append(baseLayerEntries(),
		tarEntry{name: "f1", typeflag: tar.TypeReg, mode: 0o644, data: "same inode"},
		tarEntry{name: "f2", typeflag: tar.TypeLink, mode: 0o644, linkname: "f1"},
	)
	l := newTestLayout(t)
	l.simpleImage(l.addLayer(entries))
	res, err := runImport(t, l.dir)
	if err != nil {
		t.Fatal(err)
	}
	fi1, err1 := os.Lstat(filepath.Join(res.Path, "f1"))
	fi2, err2 := os.Lstat(filepath.Join(res.Path, "f2"))
	if err1 != nil || err2 != nil {
		t.Fatalf("hardlinks missing: %v %v", err1, err2)
	}
	if !os.SameFile(fi1, fi2) {
		t.Fatal("hardlink identity lost in the merge")
	}
}

func TestMergeSetuidSurvivesNormalize(t *testing.T) {
	entries := append(baseLayerEntries(),
		tarEntry{name: "bin/su", typeflag: tar.TypeReg, mode: 0o4755, data: "setuid binary"},
	)
	l := newTestLayout(t)
	l.simpleImage(l.addLayer(entries))
	res, err := runImport(t, l.dir)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(filepath.Join(res.Path, "bin/su"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeSetuid == 0 {
		t.Fatalf("setuid bit lost: %o", fi.Mode().Perm())
	}
	if fi.Mode().Perm() != 0o755 {
		t.Fatalf("perm = %o, want 755 (normalize keeps owner bits)", fi.Mode().Perm())
	}
}

func TestMergeAbsoluteSymlinkRewritten(t *testing.T) {
	entries := append(baseLayerEntries(),
		tarEntry{name: "etc/alternatives/awk", typeflag: tar.TypeSymlink, mode: 0o777, linkname: "/usr/bin/mawk"},
	)
	l := newTestLayout(t)
	l.simpleImage(l.addLayer(entries))
	res, err := runImport(t, l.dir)
	if err != nil {
		t.Fatal(err)
	}
	target, err := os.Readlink(filepath.Join(res.Path, "etc/alternatives/awk"))
	if err != nil {
		t.Fatal(err)
	}
	if filepath.IsAbs(target) {
		t.Fatalf("absolute symlink left on disk: %q", target)
	}
	// The rewritten link must still resolve to the same tree location as
	// the guest would see it.
	resolved := filepath.Join(filepath.Dir(filepath.Join(res.Path, "etc/alternatives/awk")), target)
	if !strings.HasPrefix(resolved, res.Path+string(os.PathSeparator)) {
		t.Fatalf("rewritten link escapes the tree: %q", resolved)
	}
}

func TestMergeSymlinkAncestorSkipFailsImport(t *testing.T) {
	// A layer entry under a symlinked ancestor is skipped by the audited
	// extractor — content loss the importer must fail on.
	entries := append(baseLayerEntries(),
		tarEntry{name: "s", typeflag: tar.TypeSymlink, mode: 0o777, linkname: "bin"},
		tarEntry{name: "s/inner", typeflag: tar.TypeReg, mode: 0o644, data: "lost"},
	)
	l := newTestLayout(t)
	l.simpleImage(l.addLayer(entries))
	_, err := runImport(t, l.dir)
	if err == nil || !strings.Contains(err.Error(), "symlinked ancestor") {
		t.Fatalf("err = %v, want symlink-ancestor content-loss refusal", err)
	}
}

// ── policy / publish ───────────────────────────────────────────────

func TestPolicyControlFilesStripped(t *testing.T) {
	entries := append(baseLayerEntries(),
		tarEntry{name: ".sandfs-id", typeflag: tar.TypeReg, mode: 0o644, data: "tenant stamp"},
		tarEntry{name: ".provisioning", typeflag: tar.TypeReg, mode: 0o644, data: "x"},
	)
	l := newTestLayout(t)
	l.simpleImage(l.addLayer(entries))
	res, err := runImport(t, l.dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range template.VolumeControlFiles() {
		if treeExists(t, res.Path, name) {
			t.Fatalf("%s survived the policy pass", name)
		}
	}
}

func TestPolicyMissingBinShFailsAndPublishesNothing(t *testing.T) {
	entries := []tarEntry{
		{name: "etc/", typeflag: tar.TypeDir, mode: 0o755},
		{name: "usr/", typeflag: tar.TypeDir, mode: 0o755},
	}
	l := newTestLayout(t)
	l.simpleImage(l.addLayer(entries))

	out := t.TempDir()
	_, err := Import(Options{Src: l.dir, Name: "img", Version: "v1", Out: out})
	if err == nil || !strings.Contains(err.Error(), "/bin/sh") && !strings.Contains(err.Error(), "bin-sh") {
		t.Fatalf("err = %v, want /bin/sh validation failure", err)
	}
	if treeExists(t, out, "img") {
		t.Fatal("failed import published or created the name directory")
	}
	matches, _ := filepath.Glob(filepath.Join(out, ".template-import-*"))
	if len(matches) != 0 {
		t.Fatalf("staging debris left behind: %v", matches)
	}
}

func TestPublishRefusesExistingDestination(t *testing.T) {
	l := newTestLayout(t)
	base := l.addLayer(baseLayerEntries())
	l.simpleImage(base)

	out := t.TempDir()
	if _, err := Import(Options{Src: l.dir, Name: "img", Version: "v1", Out: out}); err != nil {
		t.Fatal(err)
	}
	_, err := Import(Options{Src: l.dir, Name: "img", Version: "v1", Out: out})
	if err == nil || !strings.Contains(err.Error(), "immutable") {
		t.Fatalf("err = %v, want immutability refusal", err)
	}
	// A different version still works.
	if _, err := Import(Options{Src: l.dir, Name: "img", Version: "v2", Out: out}); err != nil {
		t.Fatalf("v2 after v1: %v", err)
	}
}

func TestPublishRefusesSymlinkedOrFileNames(t *testing.T) {
	l := newTestLayout(t)
	base := l.addLayer(baseLayerEntries())
	l.simpleImage(base)

	out := t.TempDir()
	elsewhere := t.TempDir()
	if err := os.Symlink(elsewhere, filepath.Join(out, "img")); err != nil {
		t.Fatal(err)
	}
	if _, err := Import(Options{Src: l.dir, Name: "img", Version: "v1", Out: out}); err == nil {
		t.Fatal("symlinked name directory accepted")
	}
	if _, err := os.Lstat(filepath.Join(elsewhere, "v1")); err == nil {
		t.Fatal("publish wrote through the name-directory symlink")
	}

	out2 := t.TempDir()
	if err := os.WriteFile(filepath.Join(out2, "img"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Import(Options{Src: l.dir, Name: "img", Version: "v1", Out: out2}); err == nil {
		t.Fatal("file at the name path accepted")
	}
}

func TestPushOnlyFailureLeavesNoLocalOutput(t *testing.T) {
	l := newTestLayout(t)
	base := l.addLayer(baseLayerEntries())
	l.simpleImage(base)
	// Port 1 on loopback refuses immediately: the conversion succeeds and
	// only the push leg fails.
	res, err := Import(Options{Src: l.dir, Name: "img", Version: "v1", Push: "127.0.0.1:1/repo"})
	if err == nil {
		t.Fatal("push to a closed port SUCCEEDED")
	}
	if !strings.Contains(err.Error(), "push to 127.0.0.1:1") {
		t.Fatalf("err = %v, want the push leg named", err)
	}
	if res == nil || res.Path != "" {
		t.Fatalf("push-only result = %+v, want Path empty", res)
	}
}

func TestCombinedPushFailureKeepsLocalTemplate(t *testing.T) {
	l := newTestLayout(t)
	base := l.addLayer(baseLayerEntries())
	l.simpleImage(base)
	out := t.TempDir()
	res, err := Import(Options{Src: l.dir, Name: "img", Version: "v1", Out: out, Push: "127.0.0.1:1/repo"})
	if err == nil {
		t.Fatal("push to a closed port SUCCEEDED")
	}
	if !strings.Contains(err.Error(), "local template, if any, is kept") {
		t.Fatalf("err = %v, want the kept-local-template note", err)
	}
	if res == nil || res.Path == "" {
		t.Fatalf("combined result = %+v, want the local path", res)
	}
	// The local template is complete and valid — a failed push must not
	// roll it back.
	findings, ferr := template.ValidateRootfsTree(res.Path)
	if ferr != nil {
		t.Fatalf("kept local template unreadable: %v", ferr)
	}
	for _, f := range findings {
		if f.Severity == template.SeverityError {
			t.Fatalf("kept local template invalid: %s: %s", f.Path, f.Detail)
		}
	}
	if !treeExists(t, res.Path, "bin/sh") {
		t.Fatal("kept local template lacks /bin/sh")
	}
}

func TestPublishReservedNamesRefused(t *testing.T) {
	l := newTestLayout(t)
	base := l.addLayer(baseLayerEntries())
	l.simpleImage(base)
	out := t.TempDir()
	for _, tc := range []struct{ name, version string }{
		{"layers", "v1"}, {"refs", "v1"}, {"img", "bin"}, {"img", "usr"},
	} {
		_, err := Import(Options{Src: l.dir, Name: tc.name, Version: tc.version, Out: out})
		if err == nil {
			t.Fatalf("reserved %s:%s accepted", tc.name, tc.version)
		}
	}
}

func TestPlatformPolicy(t *testing.T) {
	l := newTestLayout(t)
	base := l.addLayer(baseLayerEntries())
	l.simpleImage(base)
	for _, p := range []string{"linux/arm64", "darwin/amd64", "amd64", "linux/", "linux/amd64/v2/extra", "/amd64"} {
		if _, err := Import(Options{Src: l.dir, Name: "img", Version: "v1", Out: t.TempDir(), Platform: p}); err == nil {
			t.Fatalf("platform %q accepted", p)
		}
	}
	// amd64 variants are noise ("v1"/"v2" spell the default) — accepted and
	// normalized away. Fresh out per run: a published ref is immutable.
	for _, p := range []string{"", "linux/amd64", "linux/amd64/v1"} {
		if _, err := Import(Options{Src: l.dir, Name: "img", Version: "v1", Out: t.TempDir(), Platform: p}); err != nil {
			t.Fatalf("platform %q refused: %v", p, err)
		}
	}
}

// Silence the unused-helper linters for helpers used only in sibling test
// files later on.
var _ = errors.Is
var _ = fmt.Sprintf
var _ = io.Discard

// TestImportSettlesPublishedGroup pins the group side of the import end to
// end: the published tree's group-grant-reliant entries (and every other
// entry whose gid differs) end up on the expected gid, the setuid bit
// survives the settle, and the reliant warning is emitted. As root a
// foreign gid exercises the real chgrp path; as a normal user the settle is
// a no-op onto the caller's own gid (which still must hold).
func TestImportSettlesPublishedGroup(t *testing.T) {
	p := filepath.Join(t.TempDir(), "rootfs.tar.gz")
	entries := append(baseLayerEntries(),
		tarEntry{name: "root/", typeflag: tar.TypeDir, mode: 0o700},
		tarEntry{name: "etc/shadow", typeflag: tar.TypeReg, mode: 0o640, data: "shadow"},
		tarEntry{name: "bin/su", typeflag: tar.TypeReg, mode: 0o4755, data: "su"},
	)
	if err := os.WriteFile(p, gz(buildTar(t, entries)), 0o644); err != nil {
		t.Fatal(err)
	}

	want := os.Getegid()
	if os.Geteuid() == 0 {
		want = 4242 // root can settle onto any gid; a foreign one exercises chgrp
	}
	out := t.TempDir()
	res, err := Import(Options{Src: p, Name: "img", Version: "v1", Out: out, Group: fmt.Sprint(want)})
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	for _, rel := range []string{"root", "etc/shadow", "bin/su"} {
		fi, err := os.Lstat(filepath.Join(res.Path, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatal(err)
		}
		if got := int(fi.Sys().(*syscall.Stat_t).Gid); got != want {
			t.Fatalf("%s gid = %d, want %d", rel, got, want)
		}
	}
	su, err := os.Lstat(filepath.Join(res.Path, "bin", "su"))
	if err != nil {
		t.Fatal(err)
	}
	if su.Mode()&os.ModeSetuid == 0 {
		t.Fatalf("setuid bit lost across the settle: mode = %v", su.Mode())
	}
	warned := false
	for _, w := range res.Warnings {
		if strings.Contains(w, "rely on the group grant") {
			warned = true
		}
	}
	if !warned {
		t.Fatalf("reliant-entry warning missing: %v", res.Warnings)
	}

	// Default settle (no --group): the output root's own gid, and — because
	// a plain t.TempDir is NOT setgid — the warning that a later copy into
	// the shared scan root does not preserve the group.
	defOut := t.TempDir()
	res, err = Import(Options{Src: p, Name: "img", Version: "v3", Out: defOut})
	if err != nil {
		t.Fatalf("default-settle Import: %v", err)
	}
	ofi, err := os.Stat(defOut)
	if err != nil {
		t.Fatal(err)
	}
	defGid := int(ofi.Sys().(*syscall.Stat_t).Gid)
	sfi, err := os.Lstat(filepath.Join(res.Path, "etc", "shadow"))
	if err != nil {
		t.Fatal(err)
	}
	if got := int(sfi.Sys().(*syscall.Stat_t).Gid); got != defGid {
		t.Fatalf("default settle gid = %d, want the out root's %d", got, defGid)
	}
	setgidWarned := false
	for _, w := range res.Warnings {
		if strings.Contains(w, "is not setgid") {
			setgidWarned = true
		}
	}
	if !setgidWarned {
		t.Fatalf("non-setgid output root warning missing: %v", res.Warnings)
	}

	// --group is meaningless without --out: a push-only run materializes no
	// local tree. The refusal happens before any network contact.
	if _, err := Import(Options{Src: p, Name: "img", Version: "v2", Push: "localhost:1/nope", Group: "4242"}); err == nil || !strings.Contains(err.Error(), "group requires out") {
		t.Fatalf("push-only + group: err = %v, want the 'group requires out' refusal", err)
	}
}

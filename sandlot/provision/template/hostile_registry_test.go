// Copyright 2026 Chaoyang Huang. All rights reserved.
//
// SPDX-License-Identifier: BUSL-1.1
//
// Adversarial pins for the template pull/extract paths: an in-process
// hostile OCI registry (mutable blob store, lying Docker-Content-Digest
// headers, per-blob delays) driving the REAL Manager. The
// escape/poison/swap defeats are REQUIRED failures of the attack.

package template

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// hostileRegistry is a minimal OCI distribution server whose blob store is
// mutable at runtime (bait-and-switch) and whose responses can lie in the
// Docker-Content-Digest header.
type ent struct {
	name     string
	typeflag byte
	linkname string
	mode     int64
	data     string
}

func buildTarGz(t *testing.T, ents []ent) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range ents {
		hdr := &tar.Header{Name: e.name, Mode: e.mode}
		switch e.typeflag {
		case tar.TypeDir:
			hdr.Typeflag = tar.TypeDir
			if err := tw.WriteHeader(hdr); err != nil {
				t.Fatal(err)
			}
		case tar.TypeSymlink:
			hdr.Typeflag = tar.TypeSymlink
			hdr.Linkname = e.linkname
			if err := tw.WriteHeader(hdr); err != nil {
				t.Fatal(err)
			}
		case tar.TypeLink:
			hdr.Typeflag = tar.TypeLink
			hdr.Linkname = e.linkname
			if err := tw.WriteHeader(hdr); err != nil {
				t.Fatal(err)
			}
		default:
			if e.typeflag == 0 || e.typeflag == tar.TypeReg {
				hdr.Typeflag = tar.TypeReg
				hdr.Size = int64(len(e.data))
				if err := tw.WriteHeader(hdr); err != nil {
					t.Fatal(err)
				}
				if _, err := tw.Write([]byte(e.data)); err != nil {
					t.Fatal(err)
				}
			} else { // char/block/fifo: header-only entries
				hdr.Typeflag = e.typeflag
				if err := tw.WriteHeader(hdr); err != nil {
					t.Fatal(err)
				}
			}
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

// sentinel creates the classic escape witness: a file OUTSIDE the extraction
// dir the attacker would want to touch, plus its parent.
func sentinel(t *testing.T, base string) (outsideDir string, witness string) {
	t.Helper()
	outsideDir = filepath.Join(base, "outside")
	if err := os.MkdirAll(outsideDir, 0755); err != nil {
		t.Fatal(err)
	}
	witness = filepath.Join(outsideDir, "owned")
	if err := os.WriteFile(witness, []byte("clean"), 0644); err != nil {
		t.Fatal(err)
	}
	return
}

func runExtract(t *testing.T, ents []ent, opts extractOptions) (dir string, err error) {
	t.Helper()
	base := t.TempDir()
	dir = filepath.Join(base, "target")
	sentinel(t, base)
	err = extractTarGzToDir(bytes.NewReader(buildTarGz(t, ents)), dir, opts)
	return dir, err
}

func exists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}

// ---- expected-blocked battery ----

type hostileRegistry struct {
	mu              sync.Mutex
	blobs           map[string][]byte // digest -> bytes
	gzipLen         map[string]int    // digest -> declared size override
	manifestsByTag  map[string][]byte
	manifestsByDgst map[string][]byte
	srv             *httptest.Server
	blobGets        map[string]int
	delays          map[string]time.Duration
}

func newHostileRegistry(t *testing.T) *hostileRegistry {
	h := &hostileRegistry{
		blobs:           map[string][]byte{},
		manifestsByTag:  map[string][]byte{},
		manifestsByDgst: map[string][]byte{},
		blobGets:        map[string]int{},
		delays:          map[string]time.Duration{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v2/", func(w http.ResponseWriter, r *http.Request) {
		rest := strings.TrimPrefix(r.URL.Path, "/v2/")
		switch {
		case rest == "" || rest == "/":
			w.WriteHeader(http.StatusOK)
		case strings.Contains(rest, "/manifests/"):
			ref := rest[strings.LastIndex(rest, "/")+1:]
			h.mu.Lock()
			defer h.mu.Unlock()
			var body []byte
			if strings.Contains(ref, ":") {
				body = h.manifestsByDgst[ref]
			} else {
				body = h.manifestsByTag[ref]
				if body != nil {
					d := digest.FromBytes(body)
					w.Header().Set("Docker-Content-Digest", d.String())
					h.manifestsByDgst[d.String()] = body
				}
			}
			if body == nil {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", ocispec.MediaTypeImageManifest)
			w.Header().Set("Content-Length", fmt.Sprint(len(body)))
			if r.Method == http.MethodHead {
				w.WriteHeader(http.StatusOK)
				return
			}
			w.Write(body)
		case strings.Contains(rest, "/blobs/"):
			d := rest[strings.LastIndex(rest, "/")+1:]
			h.mu.Lock()
			b, ok := h.blobs[d]
			n := h.blobGets[d]
			h.blobGets[d] = n + 1
			delay := h.delays[d]
			h.mu.Unlock()
			if delay > 0 {
				time.Sleep(delay)
			}
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			// Lie exactly like a hostile registry can: header says the
			// requested digest, body is whatever we want.
			w.Header().Set("Docker-Content-Digest", d)
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Content-Length", fmt.Sprint(len(b)))
			w.Write(b)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	h.srv = httptest.NewServer(mux)
	t.Cleanup(h.srv.Close)
	return h
}

func (h *hostileRegistry) putBlob(b []byte) string {
	d := digest.FromBytes(b).String()
	h.mu.Lock()
	h.blobs[d] = b
	h.mu.Unlock()
	return d
}

func (h *hostileRegistry) setDelay(d string, dl time.Duration) {
	h.mu.Lock()
	h.delays[d] = dl
	h.mu.Unlock()
}

func (h *hostileRegistry) swapBlob(d string, b []byte) {
	h.mu.Lock()
	h.blobs[d] = b
	h.mu.Unlock()
}

func (h *hostileRegistry) blobGetCount(d string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.blobGets[d]
}

// putManifest builds and registers an image manifest naming the given layer
// descriptors (+config). Returns the tag.
func (h *hostileRegistry) putManifest(tag string, layerDescs []ocispec.Descriptor) {
	cfg := []byte(`{"workspace_path":"/workspace","template_mode":"overlay"}`)
	cfgDesc := ocispec.Descriptor{
		MediaType: MediaTypeTemplateConfig,
		Digest:    digest.FromBytes(cfg),
		Size:      int64(len(cfg)),
	}
	h.putBlob(cfg)
	m := ocispec.Manifest{
		MediaType:    ocispec.MediaTypeImageManifest,
		ArtifactType: ArtifactTypeTemplate,
		Config:       cfgDesc,
		Layers:       layerDescs,
	}
	mb, _ := json.Marshal(m)
	h.mu.Lock()
	h.manifestsByTag[tag] = mb
	h.manifestsByDgst[digest.FromBytes(mb).String()] = mb
	h.mu.Unlock()
}

func (h *hostileRegistry) addr() string {
	return strings.TrimPrefix(h.srv.URL, "http://")
}

func padTo(b []byte, n int) []byte {
	if len(b) >= n {
		return b
	}
	return append(b, make([]byte, n-len(b))...)
}

// makeGzip pads a gzip payload to exactly n bytes (trailing NULs after the
// gzip member; the tar reader stops at end-of-archive before reaching them).
func makeGzip(t *testing.T, ents []ent, n int) []byte {
	t.Helper()
	raw := buildTarGz(t, ents)
	return padTo(raw, n)
}

func newMgr(t *testing.T, dir, reg string) *Manager {
	t.Helper()
	m, err := NewManager(Config{
		Registry:     reg,
		TemplatesDir: dir,
	})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// escapeEnts builds the shallow-link escape tar entries with `pairs`
// (shift,up) pairs: names <p1>/<x1>/<p2>/<x2>/.../<file> land `pairs` levels
// ABOVE the extraction dir.
func escapeEnts(pairs int, filename, content string) []ent {
	var ents []ent
	prefix := ""
	for i := 0; i < pairs; i++ {
		ents = append(ents,
			ent{name: prefix + fmt.Sprintf("q%d", i), typeflag: tar.TypeSymlink, linkname: "."},
			ent{name: prefix + fmt.Sprintf("q%d/x%d", i, i), typeflag: tar.TypeSymlink, linkname: ".."},
		)
		prefix += fmt.Sprintf("q%d/x%d/", i, i)
	}
	ents = append(ents, ent{name: prefix + filename, data: content, mode: 0644})
	return ents
}

// ---- E2E-1: overlay pull plants a file OUTSIDE the template store ----

func TestHostile_E2E_OverlayEscapeOutsideStore(t *testing.T) {
	base := t.TempDir()
	store := filepath.Join(base, "templates") // TemplatesDir
	h := newHostileRegistry(t)

	// 3 pairs => writes land at parent(store) = base, outside the store.
	payload := makeGzip(t, escapeEnts(3, "planted-by-registry", "PWNED-OUTSIDE-STORE"), 1<<16)
	desc := ocispec.Descriptor{
		MediaType: MediaTypeLayerGzip,
		Digest:    digest.FromBytes(payload),
		Size:      int64(len(payload)),
	}
	h.putBlob(payload)
	h.putManifest("evil-v1", []ocispec.Descriptor{desc})

	m := newMgr(t, store, h.addr()+"/test")
	if _, err := m.PullTemplate(context.Background(), "evil:v1", "overlay"); err != nil {
		t.Fatalf("pull failed (registry side effect?): %v", err)
	}
	// Where did PWNED land? Walk ABOVE base too — each (q,x) pair climbs one
	// directory, and the layer dir sits 3 levels below base.
	walkRoot := filepath.Dir(base)
	var hits []string
	filepath.Walk(walkRoot, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if b, rerr := os.ReadFile(p); rerr == nil && bytes.Contains(b, []byte("PWNED-OUTSIDE-STORE")) {
			hits = append(hits, p)
		}
		return nil
	})
	// fix (pinned): the shallow-link compound must be CONTAINED —
	// nothing may land outside the store; the entries under the symlinked
	// ancestor are skipped. (The naive extraction plants a file
	// OUTSIDE the store with err==nil; the pin requires the opposite.)
	for _, hit := range hits {
		if !strings.HasPrefix(hit, store+string(os.PathSeparator)) {
			t.Fatalf("ESCAPE (overlay pull) — containment broken: %s", hit)
		}
	}
	for _, hit := range hits {
		t.Logf("contained witness inside the store: %s", hit)
	}
}

// ---- E2E-2: flat create plants a file in the VOLUMES ROOT (cross-tenant) ----

func TestHostile_E2E_FlatEscapeIntoVolumesRoot(t *testing.T) {
	base := t.TempDir()
	volumes := filepath.Join(base, "volumes")
	if err := os.MkdirAll(volumes, 0o770); err != nil {
		t.Fatal(err)
	}
	h := newHostileRegistry(t)

	// 1 pair => writes land at parent(volume dir) = volumes root.
	payload := makeGzip(t, escapeEnts(1, "PWNED-IN-VOLROOT", "evil"), 1<<16)
	desc := ocispec.Descriptor{
		MediaType: MediaTypeLayerGzip,
		Digest:    digest.FromBytes(payload),
		Size:      int64(len(payload)),
	}
	h.putBlob(payload)
	h.putManifest("evilflat-v1", []ocispec.Descriptor{desc})

	store := filepath.Join(base, "templates")
	m := newMgr(t, store, h.addr()+"/test")
	if _, err := m.PullTemplate(context.Background(), "evilflat:v1", "flat"); err != nil {
		t.Fatalf("flat pull failed: %v", err)
	}

	dst := filepath.Join(volumes, "sf-victimvolume")
	if err := os.MkdirAll(dst, 0o770); err != nil {
		t.Fatal(err)
	}
	// fix (pinned): the extraction may succeed (skipped entries) or
	// fail, but the witness must NEVER appear in the volumes root.
	_ = m.ExtractFlatFromOCI(context.Background(), []LayerRef{
		{Digest: desc.Digest.String(), Size: desc.Size},
	}, dst)
	if b, rerr := os.ReadFile(filepath.Join(volumes, "PWNED-IN-VOLROOT")); rerr == nil {
		t.Fatalf("ESCAPE (flat create) — containment broken: %q", b)
	}
}

// ---- E2E-3: digest bait-and-switch on the flat path ----

func TestHostile_E2E_FlatDigestBaitAndSwitch(t *testing.T) {
	base := t.TempDir()
	h := newHostileRegistry(t)

	benign := makeGzip(t, []ent{{name: "hello", data: "benign", mode: 0644}}, 1<<16)
	benignLen := len(benign)
	d := digest.FromBytes(benign).String()
	desc := ocispec.Descriptor{
		MediaType: MediaTypeLayerGzip,
		Digest:    digest.FromBytes(benign),
		Size:      int64(benignLen),
	}
	h.putBlob(benign)
	h.putManifest("swap-v1", []ocispec.Descriptor{desc})

	store := filepath.Join(base, "templates")
	m := newMgr(t, store, h.addr()+"/test")
	if _, err := m.PullTemplate(context.Background(), "swap:v1", "flat"); err != nil {
		t.Fatalf("flat pull failed: %v", err)
	}
	entry, err := m.LoadRefEntry("swap:v1", "flat")
	if err != nil {
		t.Fatal(err)
	}
	if len(entry.OCILayers) != 1 || entry.OCILayers[0].Digest != d {
		t.Fatalf("unexpected ref layers: %+v", entry.OCILayers)
	}

	// Registry turns hostile AFTER the pin: different bytes, same digest,
	// same length, honest-looking headers.
	evil := makeGzip(t, []ent{{name: "hello", data: "EVIL-SWAPPED-CONTENT", mode: 0644}}, benignLen)
	if len(evil) != benignLen {
		t.Fatalf("padding failed: %d != %d", len(evil), benignLen)
	}
	h.swapBlob(d, evil)

	vol := filepath.Join(base, "volume")
	if err := os.MkdirAll(vol, 0o770); err != nil {
		t.Fatal(err)
	}
	// fix (pinned): bytes not matching the recorded digest MUST fail
	// the extraction. (The naive extraction accepts the same swap silently
	// with err==nil; the pin requires the rejection.) The volume is left for
	// EnsureVolume's marker-based retry wipe — the contract is the ERROR.
	err = m.ExtractFlatFromOCI(context.Background(), entry.OCILayers, vol)
	t.Logf("ExtractFlatFromOCI err=%v; blob fetched %d times", err, h.blobGetCount(d))
	if err == nil {
		b, _ := os.ReadFile(filepath.Join(vol, "hello"))
		t.Fatalf("DIGEST PIN BROKEN: mismatched bytes extracted without error (content=%q)", b)
	}
}

// ---- E2E-4 (control): same swap against the OVERLAY path ----

func TestHostile_E2E_OverlayDigestSwapControl(t *testing.T) {
	base := t.TempDir()
	h := newHostileRegistry(t)

	benign := makeGzip(t, []ent{{name: "hello", data: "benign", mode: 0644}}, 1<<16)
	benignLen := len(benign)
	desc := ocispec.Descriptor{
		MediaType: MediaTypeLayerGzip,
		Digest:    digest.FromBytes(benign),
		Size:      int64(benignLen),
	}
	h.putBlob(benign)
	h.putManifest("ctrl-v1", []ocispec.Descriptor{desc})

	store := filepath.Join(base, "templates")
	m := newMgr(t, store, h.addr()+"/test")
	if _, err := m.PullTemplate(context.Background(), "ctrl:v1", "overlay"); err != nil {
		t.Fatalf("control pull failed: %v", err)
	}

	// re-pull after removing the local layer + ref, with swapped bytes.
	layerName := strings.ReplaceAll(desc.Digest.String(), ":", "-")
	if err := os.RemoveAll(filepath.Join(store, "layers", layerName)); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(store, "refs", "ctrl_v1.overlay.json")); err != nil {
		t.Fatal(err)
	}
	evil := makeGzip(t, []ent{{name: "hello", data: "EVIL", mode: 0644}}, benignLen)
	h.swapBlob(desc.Digest.String(), evil)

	_, err := m.PullTemplate(context.Background(), "ctrl:v1", "overlay")
	t.Logf("overlay re-pull with swapped bytes: err=%v", err)
	if err == nil {
		t.Fatalf("overlay path ACCEPTED swapped bytes")
	}
	if !strings.Contains(err.Error(), "digest") && !strings.Contains(err.Error(), "mismatch") && !strings.Contains(err.Error(), "size") {
		t.Logf("note: error is not digest-worded: %v", err)
	}
}

// ---- E2E-5: poisoned layer cache (confused operator / crashed extraction) ----

func TestHostile_E2E_PoisonedLayerCacheTrustedByDedup(t *testing.T) {
	base := t.TempDir()
	h := newHostileRegistry(t)

	payload := makeGzip(t, []ent{{name: "real.txt", data: "REAL-CONTENT", mode: 0644}}, 1<<15)
	desc := ocispec.Descriptor{
		MediaType: MediaTypeLayerGzip,
		Digest:    digest.FromBytes(payload),
		Size:      int64(len(payload)),
	}
	h.putBlob(payload)

	store := filepath.Join(base, "templates")
	m := newMgr(t, store, h.addr()+"/test")

	// fix (pinned): simulate a KILLED extraction — the crash can now
	// only leave STAGING debris (never a partial dir at the final name,
	// because rename(2) is atomic). The dedup must ignore staging debris and
	// produce a complete layer.
	finalDir := filepath.Join(store, "layers", strings.ReplaceAll(desc.Digest.String(), ":", "-"))
	staging := filepath.Join(store, "layers", "."+strings.ReplaceAll(desc.Digest.String(), ":", "-")+".staging-99999")
	if err := os.MkdirAll(staging, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staging, "PARTIAL-JUNK"), []byte("junk"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Also make sure the FINAL name does not exist (the crash never renamed).
	if _, err := os.Stat(finalDir); err == nil {
		t.Fatal("precondition: final layer dir must not exist")
	}

	h.putManifest("poison-v1", []ocispec.Descriptor{desc})
	if _, err := m.PullTemplate(context.Background(), "poison:v1", "overlay"); err != nil {
		t.Fatalf("pull failed: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(finalDir, "real.txt"))
	if err != nil || string(b) != "REAL-CONTENT" {
		t.Fatalf("layer not materialized correctly after staging debris: b=%q err=%v", b, err)
	}
	if _, err := os.Stat(filepath.Join(finalDir, "PARTIAL-JUNK")); err == nil {
		t.Fatal("CACHE POISONING: staging debris leaked into the final layer")
	}
}

func TestHostile_E2E_GCRacesConcurrentPull(t *testing.T) {
	base := t.TempDir()
	store := filepath.Join(base, "templates")
	h := newHostileRegistry(t)

	// a layer with enough content that extraction takes measurable time
	var ents []ent
	for i := 0; i < 300; i++ {
		ents = append(ents, ent{name: fmt.Sprintf("data/f%03d", i), data: strings.Repeat("x", 4096), mode: 0644})
	}
	payload := buildTarGz(t, ents)
	desc := ocispec.Descriptor{
		MediaType: MediaTypeLayerGzip,
		Digest:    digest.FromBytes(payload),
		Size:      int64(len(payload)),
	}
	d := desc.Digest.String()
	layerName := strings.ReplaceAll(d, ":", "-")
	h.putBlob(payload)
	h.setDelay(d, 1200*time.Millisecond) // hold the blob back so the race window opens
	h.putManifest("race-a-v1", []ocispec.Descriptor{desc})
	h.putManifest("race-b-v1", []ocispec.Descriptor{desc})

	m := newMgr(t, store, h.addr()+"/test")
	// Confused-operator state: ref A exists but names a layer NOT on disk
	// (refs/ restored from backup without layers/). B shares the layer.
	if err := m.writeRefFile("race-a:v1", RefEntry{Name: "race-a", Version: "v1", Mode: "overlay", Layers: []string{layerName}}); err != nil {
		t.Fatal(err)
	}

	// fire the delete when the layer dir APPEARS (extraction in progress)
	go func() {
		for i := 0; i < 20000; i++ {
			if _, serr := os.Stat(filepath.Join(store, "layers", layerName)); serr == nil {
				break
			}
			time.Sleep(2 * time.Millisecond)
		}
		if err := m.DeleteTemplate("race-a:v1", "overlay"); err != nil {
			t.Logf("DeleteTemplate err=%v", err)
		}
	}()
	var err error
	done := make(chan struct{})
	go func() {
		_, err = m.PullTemplate(context.Background(), "race-b:v1", "overlay")
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatalf("pull wedged")
	}
	layerPath := filepath.Join(store, "layers", layerName)
	refB, refErr := m.LoadRefEntry("race-b:v1", "overlay")

	var files int
	filepath.Walk(layerPath, func(p string, info os.FileInfo, werr error) error {
		if werr == nil && !info.IsDir() {
			files++
		}
		return nil
	})
	t.Logf("pull err=%v; refB err=%v layers=%v; layer dir files=%d/300; RefEntryExists=%v",
		err, refErr, refB != nil && len(refB.Layers) > 0, files, refB != nil && m.RefEntryExists(refB))
	if refErr == nil && m.RefEntryExists(refB) && files < 300 {
		t.Fatalf("RACE CONFIRMED: pull succeeded, ref B recorded, but the shared layer is CORRUPT (%d/300 files) — every sandfs from B mounts truncated content with no error", files)
	}
	if files == 300 {
		t.Logf("no corruption observed in this run (timing); see analysis")
	}
}

// Controls: malformed layer digests and empty layer lists refuse cleanly.
func TestHostile_E2E_FlatMalformedDigests(t *testing.T) {
	base := t.TempDir()
	h := newHostileRegistry(t)
	h.putManifest("bad1-v1", []ocispec.Descriptor{})
	m := newMgr(t, filepath.Join(base, "templates"), h.addr()+"/test")
	if _, err := m.PullTemplate(context.Background(), "bad1:v1", "flat"); err != nil {
		t.Logf("zero-layer flat pull refused at pull: %v", err)
	}
	entry := RefEntry{Mode: "flat", OCILayers: []LayerRef{{Digest: "not-a-digest", Size: 10}}}
	if err := m.ExtractFlatFromOCI(context.Background(), entry.OCILayers, filepath.Join(base, "v")); err == nil {
		t.Fatalf("garbage digest accepted")
	} else {
		t.Logf("garbage digest refused: %v", err)
	}
}

// TestHostile_LayerStagingObserver pins actual guarantee: the
// content-addressed FINAL name must never exist in a partial state — the
// staging+rename discipline means an observer polling during extraction sees
// the dir either absent or complete (a killed process can then only strand
// STAGING debris, which dedup ignores). RED with the staging disabled
// (extraction writes into the final name: the observer catches partial
// counts).
func TestHostile_LayerStagingObserver(t *testing.T) {
	base := t.TempDir()
	h := newHostileRegistry(t)

	const fileCount = 20000
	ents := make([]ent, 0, fileCount)
	for i := 0; i < fileCount; i++ {
		ents = append(ents, ent{name: fmt.Sprintf("f%05d", i), data: "x", mode: 0644})
	}
	payload := makeGzip(t, ents, 0)
	desc := ocispec.Descriptor{
		MediaType: MediaTypeLayerGzip,
		Digest:    digest.FromBytes(payload),
		Size:      int64(len(payload)),
	}
	h.putBlob(payload)
	h.putManifest("stage-v1", []ocispec.Descriptor{desc})

	store := filepath.Join(base, "templates")
	m := newMgr(t, store, h.addr()+"/test")
	finalDir := filepath.Join(store, "layers", strings.ReplaceAll(desc.Digest.String(), ":", "-"))

	stop := make(chan struct{})
	var sawPartial atomic.Bool
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			if fi, err := os.Stat(finalDir); err == nil && fi.IsDir() {
				var n int
				filepath.Walk(finalDir, func(_ string, info os.FileInfo, werr error) error {
					if werr == nil && !info.IsDir() {
						n++
					}
					return nil
				})
				if n < fileCount {
					sawPartial.Store(true)
					return
				}
			}
			time.Sleep(200 * time.Microsecond)
		}
	}()

	if _, err := m.PullTemplate(context.Background(), "stage:v1", "overlay"); err != nil {
		close(stop)
		t.Fatalf("pull failed: %v", err)
	}
	close(stop)
	if sawPartial.Load() {
		t.Fatal("POISONED WINDOW: the final layer name existed in a PARTIAL state during extraction ")
	}
}

// TestHostile_GzipAmplificationCapped pins: a small blob whose
// decompressed stream exceeds the cap must FAIL the extraction with a named
// cause (the band pass: 42KB -> 41.9MB, no cap, no error). The cap is
// shrunk for the test (package var, the safeMarginSec pattern). RED with
// the cap removed.
func TestHostile_GzipAmplificationCapped(t *testing.T) {
	old := maxExtractedLayerBytes
	maxExtractedLayerBytes = 1 << 20 // 1 MiB: the 40 MiB bomb exceeds it
	defer func() { maxExtractedLayerBytes = old }()

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	chunk := bytes.Repeat([]byte{0}, 1<<20)
	for i := 0; i < 40; i++ {
		hdr := &tar.Header{Name: fmt.Sprintf("bomb/b%03d", i), Typeflag: tar.TypeReg, Size: int64(len(chunk)), Mode: 0644}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(chunk); err != nil {
			t.Fatal(err)
		}
	}
	tw.Close()
	gz.Close()

	dir := t.TempDir()
	err := extractTarGzToDir(bytes.NewReader(buf.Bytes()), dir, extractOptions{flatVolume: true})
	if err == nil {
		t.Fatalf("amplification NOT capped: %d compressed bytes expanded without error", buf.Len())
	}
	if !strings.Contains(err.Error(), "decompressed-size cap") {
		t.Fatalf("unexpected error (want the cap): %v", err)
	}
	t.Logf("capped: %v", err)
}

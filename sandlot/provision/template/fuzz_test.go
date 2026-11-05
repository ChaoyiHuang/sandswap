package template

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// FuzzExtractTarGzToDir attacks the tar.gz extraction containment with
// arbitrary tar streams. This function materializes registry-supplied layers
// (a hostile registry is a declared attacker): a breakout is host RCE —
// the extractor runs as the provision identity. The fuzz input is the RAW
// tar stream; the harness gzips it so the fuzzer spends its budget on the
// tar layer (names, typeflags, link targets, modes), not on gzip framing.
//
// Invariants asserted per input:
//  1. no panic / hang
//  2. nothing materializes BESIDE the extraction dir (zip-slip one level up)
//  3. every created symlink is tree-relative and stays within the dir when
//     joined from the link's own path (the absolute→rewrite contract)
//
// Run: go test . -run '^$' -fuzz FuzzExtractTarGzToDir -fuzztime 60s
func FuzzExtractTarGzToDir(f *testing.F) {
	f.Add(mustTar(f, tarEntry{typ: tar.TypeDir, name: "rootfs"},
		tarEntry{typ: tar.TypeReg, name: "rootfs/etc/passwd", body: "root:x:0:0\n"},
		tarEntry{typ: tar.TypeSymlink, name: "rootfs/bin/sh", link: "/usr/bin/mawk"},
		tarEntry{typ: tar.TypeReg, name: "rootfs/bin/real-sh", body: "#!/bin/sh\n"}), false)
	f.Add(mustTar(f, tarEntry{typ: tar.TypeReg, name: "../../escape.txt", body: "x"}), false)
	f.Add(mustTar(f, tarEntry{typ: tar.TypeSymlink, name: "lnk", link: "../../../../etc/passwd"},
		tarEntry{typ: tar.TypeReg, name: "through", body: "x"}), true)
	f.Add(mustTar(f, tarEntry{typ: tar.TypeSymlink, name: "abs", link: "/etc/hosts"},
		tarEntry{typ: tar.TypeReg, name: "abs-follow", body: "x"}), false)
	f.Add(mustTar(f, tarEntry{typ: tar.TypeLink, name: "hard", link: "../../outside"},
		tarEntry{typ: tar.TypeReg, name: "src", body: "x"}), true)
	f.Add(mustTar(f, tarEntry{typ: tar.TypeReg, name: strings.Repeat("d/", 200) + "deep", body: "x"}), false)
	f.Add(mustTar(f, tarEntry{typ: tar.TypeReg, name: "weird", body: "x", mode: 0o7777}), true)
	f.Add(mustTar(f, tarEntry{typ: tar.TypeReg, name: "suid", body: "x", mode: 0o4755}), false)
	f.Add([]byte("not a gzip stream at all"), false)
	f.Add(mustTar(f, tarEntry{typ: tar.TypeDir, name: "rootfs", mode: 0o755},
		tarEntry{typ: tar.TypeReg, name: "rootfs/f", body: "x", mode: 0o600}), true)

	f.Fuzz(func(t *testing.T, raw []byte, flat bool) {
		// Extraction + tree walk per iteration is filesystem-heavy; cap the
		// input so the fuzzer explores tar SHAPES (names, typeflags, link
		// targets) instead of burning seconds on megabyte bodies.
		if len(raw) > 1<<13 {
			t.Skip("oversized input")
		}
		var gz bytes.Buffer
		zw := gzip.NewWriter(&gz)
		// Writing to a bytes.Buffer cannot fail.
		_, _ = zw.Write(raw)
		_ = zw.Close()

		parent := t.TempDir()
		dir := filepath.Join(parent, "extract")
		opts := extractOptions{flatVolume: flat}
		// Errors are legitimate outcomes (containment rejections, bad tar,
		// bad gzip). Only panics and escapes are failures.
		_ = extractTarGzToDir(bytes.NewReader(gz.Bytes()), dir, opts)

		// Invariant 2: nothing beside the extraction dir.
		entries, err := os.ReadDir(parent)
		if err != nil {
			t.Fatalf("read parent: %v", err)
		}
		if len(entries) != 1 || entries[0].Name() != "extract" {
			t.Fatalf("materialized beside the extraction dir: %d entries", len(entries))
		}

		// Invariant 3: every symlink is tree-relative and contained.
		sep := string(os.PathSeparator)
		_ = filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
			if err != nil || info.Mode()&os.ModeSymlink == 0 {
				return nil // dangling targets and non-links: fine
			}
			target, _ := os.Readlink(p)
			if filepath.IsAbs(target) {
				t.Errorf("absolute symlink survived at %s -> %s", p, target)
				return nil
			}
			joined := filepath.Join(filepath.Dir(p), target)
			if !isWithinDir(joined, dir, sep) {
				t.Errorf("symlink escapes: %s -> %s (joins to %s)", p, target, joined)
			}
			return nil
		})
	})
}

type tarEntry struct {
	typ  byte
	name string
	link string
	body string
	mode int64
}

func mustTar(f *testing.F, entries ...tarEntry) []byte {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		mode := e.mode
		if mode == 0 {
			if e.typ == tar.TypeDir {
				mode = 0o755
			} else {
				mode = 0o644
			}
		}
		hdr := &tar.Header{
			Typeflag: e.typ,
			Name:     e.name,
			Linkname: e.link,
			Mode:     mode,
			Size:     int64(len(e.body)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			f.Fatalf("seed tar header: %v", err)
		}
		if e.body != "" {
			if _, err := io.WriteString(tw, e.body); err != nil {
				f.Fatalf("seed tar body: %v", err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		f.Fatalf("seed tar close: %v", err)
	}
	return buf.Bytes()
}

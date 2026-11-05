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

package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// openTestRunRoot builds an isolated workspace and anchors it.
func openTestRunRoot(t *testing.T) (*os.File, string) {
	t.Helper()
	dir := t.TempDir()
	root, err := openRunRoot(dir, true)
	if err != nil {
		t.Fatalf("openRunRoot: %v", err)
	}
	t.Cleanup(func() { root.Close() })
	return root, dir
}

// A symlinked run root is refused: the anchor exists precisely so later
// operations cannot be redirected by a name another writer can replace.
func TestOpenRunRootRefusesSymlink(t *testing.T) {
	base := t.TempDir()
	real := filepath.Join(base, "real-run")
	if err := os.Mkdir(real, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "run-link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if f, err := openRunRoot(link, false); err == nil {
		f.Close()
		t.Fatal("a symlinked run root must be refused")
	}
}

func TestOpenRunFileRejectsTraversalComponent(t *testing.T) {
	root, _ := openTestRunRoot(t)
	for _, bad := range []string{"../etc/passwd", "a/b", "", ".", "..", "x\x00y"} {
		if f, err := openRunFile(root, bad, syscall.O_RDONLY, 0); err == nil {
			f.Close()
			t.Errorf("component %q was accepted", bad)
		}
	}
}

// writeRunFileAtomic replaces a planted symlink instead of writing through it,
// and the published entry is a regular file owned by the caller.
func TestWriteRunFileAtomicReplacesSymlink(t *testing.T) {
	root, dir := openTestRunRoot(t)
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("keep\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(dir, "agents.json")); err != nil {
		t.Fatal(err)
	}
	payload := []byte("gateway_url=http://gw-after:3000\n")
	if err := writeRunFileAtomic(root, "agents.json", payload, 0o600, 0, 0, false); err != nil {
		t.Fatalf("writeRunFileAtomic: %v", err)
	}
	if data, _ := os.ReadFile(victim); string(data) != "keep\n" {
		t.Fatalf("the symlink target was overwritten: %q", data)
	}
	fi, err := lstatRunEntry(root, "agents.json")
	if err != nil {
		t.Fatal(err)
	}
	if !fi.Mode().IsRegular() {
		t.Fatalf("the published entry is %s, want a regular file", fi.Mode().Type())
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("published mode = %04o, want 0600", fi.Mode().Perm())
	}
	data, err := os.ReadFile(filepath.Join(dir, "agents.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != string(payload) {
		t.Fatalf("published content: %q", data)
	}
}

// readRunFile refuses non-regular entries (FIFO, directory) by name.
func TestReadRunFileRefusesSpecialFiles(t *testing.T) {
	root, dir := openTestRunRoot(t)
	if err := syscall.Mkfifo(filepath.Join(dir, "pipe"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readRunFile(root, "pipe", maxRunFileBytes); err == nil {
		t.Fatal("a FIFO must be refused")
	}
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readRunFile(root, "sub", maxRunFileBytes); err == nil {
		t.Fatal("a directory must be refused")
	}
}

// The key cache is published atomically: 0600, and a symlink planted at the
// name is replaced, never written through.
func TestSaveAgentsAtomic(t *testing.T) {
	g := Defaults()
	g.RunDir = t.TempDir()
	if err := saveAgents(g, []AgentRecord{{AgentID: "a1", APIKey: "sk", Name: "n"}}); err != nil {
		t.Fatalf("saveAgents: %v", err)
	}
	fi, err := os.Stat(filepath.Join(g.RunDir, "agents.json"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("agents.json mode = %04o, want 0600", fi.Mode().Perm())
	}
	if got := loadAgents(g); len(got) != 1 || got[0].APIKey != "sk" {
		t.Fatalf("roundtrip: %+v", got)
	}

	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(g.RunDir, "agents.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(g.RunDir, "agents.json")); err != nil {
		t.Fatal(err)
	}
	if err := saveAgents(g, []AgentRecord{{AgentID: "a2", APIKey: "sk2", Name: "n2"}}); err != nil {
		t.Fatalf("saveAgents over a planted symlink: %v", err)
	}
	if data, _ := os.ReadFile(victim); string(data) != "keep" {
		t.Fatalf("the symlink target was modified: %q", data)
	}
	if got := loadAgents(g); len(got) != 1 || got[0].AgentID != "a2" {
		t.Fatalf("planted-name replacement: %+v", got)
	}
}

// loadAgents refuses a cache that group/world can read: it holds live API keys.
func TestLoadAgentsRefusesLoosePermissions(t *testing.T) {
	g := Defaults()
	g.RunDir = t.TempDir()
	if err := saveAgents(g, []AgentRecord{{AgentID: "a1", APIKey: "sk", Name: "n"}}); err != nil {
		t.Fatal(err)
	}
	if got := loadAgents(g); len(got) != 1 {
		t.Fatalf("0600 cache must load, got %+v", got)
	}
	if err := os.Chmod(filepath.Join(g.RunDir, "agents.json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := loadAgents(g); len(got) != 0 {
		t.Fatalf("a 0644 cache must be refused, got %+v", got)
	}
}

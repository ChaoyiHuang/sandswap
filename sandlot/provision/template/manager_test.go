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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"common/util"
	"context"
)

// TestManager_PullTemplate tests template pulling from a mock registry.
func TestManager_PullTemplate(t *testing.T) {
	// Create temp directories
	templatesDir := t.TempDir()
	overlayBase := t.TempDir()

	// Create mock template layers
	templateDir := t.TempDir()
	createMockTemplate(t, templateDir, "test-template", "1.0.0")

	// Create manager (anonymous auth for testing)
	cfg := Config{
		Registry:     "localhost:5000/sandswap-templates", // Would use mock in real test
		TemplatesDir: templatesDir,
		OverlayBase:  overlayBase,
	}

	// Note: In a real test, we would use a mock registry or local registry
	// For now, we test the local caching logic
	m, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	// Verify layers/ and refs/ directories were created
	if _, err := os.Stat(filepath.Join(templatesDir, "layers")); os.IsNotExist(err) {
		t.Error("Layers directory not created")
	}
	if _, err := os.Stat(filepath.Join(templatesDir, "refs")); os.IsNotExist(err) {
		t.Error("Refs directory not created")
	}

	_ = m // Use in actual pull test with mock registry
}

// TestManager_RegisterLocalTemplate tests registering a local directory as an overlay template.
func TestManager_RegisterLocalTemplate(t *testing.T) {
	templatesDir := t.TempDir()
	overlayBase := t.TempDir()

	cfg := Config{
		TemplatesDir: templatesDir,
		OverlayBase:  overlayBase,
	}
	m, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	// Create a local template directory
	localDir := t.TempDir()
	createMockRootfs(t, localDir)

	// Register it (overlay mode)
	if err := m.RegisterLocalTemplate("test:v1", localDir); err != nil {
		t.Fatalf("RegisterLocalTemplate: %v", err)
	}

	// Verify ref file was created with mode suffix
	refFile := filepath.Join(templatesDir, "refs", "test_v1.overlay.json")
	if _, err := os.Stat(refFile); os.IsNotExist(err) {
		t.Fatalf("Ref file not created: %s", refFile)
	}

	// Verify ref file content
	ref, err := m.loadRefFile("test:v1", "overlay")
	if err != nil {
		t.Fatalf("loadRefFile: %v", err)
	}
	if ref.Name != "test" || ref.Version != "v1" {
		t.Errorf("Ref entry: got name=%s version=%s, want test/v1", ref.Name, ref.Version)
	}
	if ref.GetMode() != "overlay" {
		t.Errorf("Ref mode: got %s, want overlay", ref.GetMode())
	}
	if len(ref.Layers) != 1 {
		t.Fatalf("Ref layers: got %d, want 1", len(ref.Layers))
	}
	// Layer path should be the resolved absolute path
	absLocal, _ := filepath.Abs(localDir)
	if ref.Layers[0] != absLocal {
		t.Errorf("Ref layer path: got %s, want %s", ref.Layers[0], absLocal)
	}

	// Verify template is accessible via GetTemplate
	tmpl, err := m.GetTemplate("test:v1", "overlay")
	if err != nil {
		t.Fatalf("GetTemplate: %v", err)
	}
	if tmpl.Name != "test" || tmpl.Version != "v1" {
		t.Errorf("Template: got name=%s version=%s", tmpl.Name, tmpl.Version)
	}
}

// TestManager_RegisterFlatTemplate tests registering a local directory as a flat template.
func TestManager_RegisterFlatTemplate(t *testing.T) {
	templatesDir := t.TempDir()
	overlayBase := t.TempDir()

	cfg := Config{
		TemplatesDir: templatesDir,
		OverlayBase:  overlayBase,
	}
	m, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	localDir := t.TempDir()
	createMockRootfs(t, localDir)

	if err := m.RegisterFlatTemplate("ubuntu:24.04", localDir); err != nil {
		t.Fatalf("RegisterFlatTemplate: %v", err)
	}

	// Verify ref file was created with flat mode suffix
	refFile := filepath.Join(templatesDir, "refs", "ubuntu_24.04.flat.json")
	if _, err := os.Stat(refFile); os.IsNotExist(err) {
		t.Fatalf("Flat ref file not created: %s", refFile)
	}

	// Verify ref file content
	ref, err := m.loadRefFile("ubuntu:24.04", "flat")
	if err != nil {
		t.Fatalf("loadRefFile: %v", err)
	}
	if ref.Name != "ubuntu" || ref.Version != "24.04" {
		t.Errorf("Ref entry: got name=%s version=%s, want ubuntu/24.04", ref.Name, ref.Version)
	}
	if ref.GetMode() != "flat" {
		t.Errorf("Ref mode: got %s, want flat", ref.GetMode())
	}
}

// TestManager_SameNameFlatAndOverlay tests that same-name templates can coexist
// with different modes.
func TestManager_SameNameFlatAndOverlay(t *testing.T) {
	templatesDir := t.TempDir()
	overlayBase := t.TempDir()

	cfg := Config{
		TemplatesDir: templatesDir,
		OverlayBase:  overlayBase,
	}
	m, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	flatDir := t.TempDir()
	createMockRootfs(t, flatDir)
	overlayDir := t.TempDir()
	createMockRootfs(t, overlayDir)

	// Register both flat and overlay with the same ref
	if err := m.RegisterFlatTemplate("myapp:v1", flatDir); err != nil {
		t.Fatalf("RegisterFlatTemplate: %v", err)
	}
	if err := m.RegisterLocalTemplate("myapp:v1", overlayDir); err != nil {
		t.Fatalf("RegisterLocalTemplate: %v", err)
	}

	// Both ref files should exist
	if _, err := os.Stat(filepath.Join(templatesDir, "refs", "myapp_v1.flat.json")); os.IsNotExist(err) {
		t.Error("Flat ref file not created")
	}
	if _, err := os.Stat(filepath.Join(templatesDir, "refs", "myapp_v1.overlay.json")); os.IsNotExist(err) {
		t.Error("Overlay ref file not created")
	}

	// Both should be loadable with their respective modes
	flatRef, err := m.LoadRefEntry("myapp:v1", "flat")
	if err != nil {
		t.Fatalf("LoadRefEntry flat: %v", err)
	}
	if flatRef.GetMode() != "flat" {
		t.Errorf("Flat ref mode: got %s", flatRef.GetMode())
	}

	overlayRef, err := m.LoadRefEntry("myapp:v1", "overlay")
	if err != nil {
		t.Fatalf("LoadRefEntry overlay: %v", err)
	}
	if overlayRef.GetMode() != "overlay" {
		t.Errorf("Overlay ref mode: got %s", overlayRef.GetMode())
	}
}

// TestManager_ScanLocalTemplates tests auto-scanning TemplatesDir for local templates.
func TestManager_ScanLocalTemplates(t *testing.T) {
	templatesDir := t.TempDir()
	overlayBase := t.TempDir()

	// Create versioned local templates INSIDE templatesDir
	// (NewManager auto-scans templatesDir for these)
	sqliteDir := filepath.Join(templatesDir, "sqlite", "v1")
	if err := os.MkdirAll(sqliteDir, 0755); err != nil {
		t.Fatal(err)
	}
	createMockRootfs(t, sqliteDir)

	pythonDir := filepath.Join(templatesDir, "python", "v1")
	if err := os.MkdirAll(pythonDir, 0755); err != nil {
		t.Fatal(err)
	}
	createMockRootfs(t, pythonDir)

	cfg := Config{
		TemplatesDir: templatesDir,
		OverlayBase:  overlayBase,
	}
	m, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	// Verify both templates were auto-discovered
	refs := m.ListLocalTemplates()
	if len(refs) < 2 {
		t.Errorf("Expected at least 2 templates, got %d: %v", len(refs), refs)
	}

	tmpl1, err := m.GetTemplate("sqlite:v1", "overlay")
	if err != nil {
		t.Errorf("GetTemplate sqlite:v1 overlay: %v", err)
	} else if tmpl1.Name != "sqlite" || tmpl1.Version != "v1" {
		t.Errorf("Template sqlite:v1: got name=%s version=%s", tmpl1.Name, tmpl1.Version)
	}

	tmpl2, err := m.GetTemplate("python:v1", "overlay")
	if err != nil {
		t.Errorf("GetTemplate python:v1 overlay: %v", err)
	} else if tmpl2.Name != "python" || tmpl2.Version != "v1" {
		t.Errorf("Template python:v1: got name=%s version=%s", tmpl2.Name, tmpl2.Version)
	}
}

// TestManager_scanRefs tests that ref files are loaded on startup.
func TestManager_scanRefs(t *testing.T) {
	templatesDir := t.TempDir()
	overlayBase := t.TempDir()

	// Create a local template and register it with the first manager
	localDir := t.TempDir()
	createMockRootfs(t, localDir)

	cfg := Config{
		TemplatesDir: templatesDir,
		OverlayBase:  overlayBase,
	}
	m1, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager 1: %v", err)
	}
	if err := m1.RegisterLocalTemplate("persist:v1", localDir); err != nil {
		t.Fatalf("RegisterLocalTemplate: %v", err)
	}

	// Create a second manager with the same templatesDir — it should discover the ref file
	m2, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager 2: %v", err)
	}

	tmpl, err := m2.GetTemplate("persist:v1", "overlay")
	if err != nil {
		t.Fatalf("GetTemplate after restart: %v", err)
	}
	if tmpl.Name != "persist" || tmpl.Version != "v1" {
		t.Errorf("Template after restart: got name=%s version=%s", tmpl.Name, tmpl.Version)
	}
}

// TestManager_ListLocalTemplates tests that ListLocalTemplates scans disk.
func TestManager_ListLocalTemplates(t *testing.T) {
	templatesDir := t.TempDir()
	overlayBase := t.TempDir()

	cfg := Config{
		TemplatesDir: templatesDir,
		OverlayBase:  overlayBase,
	}
	m, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	localDir1 := t.TempDir()
	createMockRootfs(t, localDir1)
	localDir2 := t.TempDir()
	createMockRootfs(t, localDir2)

	if err := m.RegisterFlatTemplate("app1:v1", localDir1); err != nil {
		t.Fatalf("RegisterFlatTemplate app1: %v", err)
	}
	if err := m.RegisterLocalTemplate("app2:v1", localDir2); err != nil {
		t.Fatalf("RegisterLocalTemplate app2: %v", err)
	}

	refs := m.ListLocalTemplates()
	if len(refs) != 2 {
		t.Errorf("Expected 2 templates, got %d: %v", len(refs), refs)
	}

	// Verify both are present
	found1, found2 := false, false
	for _, ref := range refs {
		if ref == "app1:v1" {
			found1 = true
		}
		if ref == "app2:v1" {
			found2 = true
		}
	}
	if !found1 {
		t.Error("app1:v1 not in ListLocalTemplates")
	}
	if !found2 {
		t.Error("app2:v1 not in ListLocalTemplates")
	}
}

// TestManager_SaveAsTemplate tests saving a flat SandFS as a local template.
func TestManager_SaveAsTemplate(t *testing.T) {
	templatesDir := t.TempDir()
	overlayBase := t.TempDir()

	cfg := Config{
		TemplatesDir:  templatesDir,
		OverlayBase:   overlayBase,
		ResolveVolume: legacyResolver(overlayBase),
	}
	m, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	// Create a flat SandFS directory (no .template marker) under overlayBase.
	// SaveAsTemplate only works for flat SandFS (no overlay .template marker).
	sandfsDir := filepath.Join(overlayBase, "test-save-agent")
	if err := os.MkdirAll(sandfsDir, 0755); err != nil {
		t.Fatal(err)
	}
	createMockRootfs(t, sandfsDir)

	// Write a file to simulate agent activity
	if err := os.WriteFile(filepath.Join(sandfsDir, "agent-created.txt"), []byte("hello"), 0644); err != nil {
		t.Fatal(err)
	}

	// Save as new template
	resp, err := m.SaveAsTemplate(context.Background(), "test-save-agent", SaveAsTemplateRequest{
		TemplateRef: "saved:v1",
		Description: "Saved from test agent",
	})
	if err != nil {
		t.Fatalf("SaveAsTemplate: %v", err)
	}

	// Verify the response
	if resp.TemplateRef != "saved:v1" {
		t.Errorf("TemplateRef: got %s, want saved:v1", resp.TemplateRef)
	}
	if _, err := os.Stat(resp.Path); os.IsNotExist(err) {
		t.Errorf("Template path does not exist: %s", resp.Path)
	}

	// Verify the saved template has the agent's file
	if _, err := os.Stat(filepath.Join(resp.Path, "agent-created.txt")); os.IsNotExist(err) {
		t.Error("Saved template missing agent-created.txt")
	}

	// Verify the new template is registered (overlay mode — SaveAsTemplate
	// always saves as overlay for efficient lowerdir consumption)
	tmpl, err := m.GetTemplate("saved:v1", "overlay")
	if err != nil {
		t.Fatalf("GetTemplate saved:v1 overlay: %v", err)
	}
	if tmpl.Name != "saved" || tmpl.Version != "v1" {
		t.Errorf("Template: got name=%s version=%s", tmpl.Name, tmpl.Version)
	}
}

// TestManager_SaveAsTemplateHealsAbortedRun pins the aborted-save heal: a
// target directory whose ref file is MISSING is a crashed previous run (the
// ref is written LAST on success), so a retry must wipe and redo instead of
// wedging on "template already exists" — the storage-plane retry loop treats
// that as a final business error, and without the heal a half-copied
// directory would block the template name until manual cleanup.
func TestManager_SaveAsTemplateHealsAbortedRun(t *testing.T) {
	templatesDir := t.TempDir()
	overlayBase := t.TempDir()
	cfg := Config{
		TemplatesDir:  templatesDir,
		OverlayBase:   overlayBase,
		ResolveVolume: legacyResolver(overlayBase),
	}
	m, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	sandfsDir := filepath.Join(overlayBase, "agent-x")
	if err := os.MkdirAll(sandfsDir, 0755); err != nil {
		t.Fatal(err)
	}
	createMockRootfs(t, sandfsDir)
	if err := os.WriteFile(filepath.Join(sandfsDir, "real-content.txt"), []byte("real"), 0644); err != nil {
		t.Fatal(err)
	}

	// Simulate the aborted run: the target layer directory exists (partial
	// copy), but the ref file was never written.
	partial := filepath.Join(templatesDir, "layers", "local-healed-v1")
	if err := os.MkdirAll(partial, 0755); err != nil {
		t.Fatal(err)
	}
	// A real aborted run leaves the save-staging marker (the heal
	// only wipes sandfs-created dirs).
	if err := os.WriteFile(filepath.Join(partial, ".save-staging"), []byte("save in progress\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(partial, "half-copied.bin"), []byte("junk"), 0644); err != nil {
		t.Fatal(err)
	}

	resp, err := m.SaveAsTemplate(context.Background(), "agent-x", SaveAsTemplateRequest{TemplateRef: "healed:v1"})
	if err != nil {
		t.Fatalf("SaveAsTemplate must heal the aborted run, got: %v", err)
	}
	// The healed layer carries the real content, not the partial junk.
	if _, err := os.Stat(filepath.Join(resp.Path, "real-content.txt")); err != nil {
		t.Errorf("healed template missing the real content: %v", err)
	}
	if _, err := os.Stat(filepath.Join(resp.Path, "half-copied.bin")); !os.IsNotExist(err) {
		t.Errorf("partial-run junk survived the heal: %v", err)
	}
	if _, err := m.GetTemplate("healed:v1", "overlay"); err != nil {
		t.Errorf("healed template not registered: %v", err)
	}

	// A COMPLETE save (ref present) must still refuse: that is a real
	// duplicate, not an aborted run.
	if _, err := m.SaveAsTemplate(context.Background(), "agent-x", SaveAsTemplateRequest{TemplateRef: "healed:v1"}); err == nil {
		t.Error("re-saving over a completed template must refuse (already exists)")
	}
}

// TestManager_SaveAsTemplateRejectsOverlay tests that overlay SandFS cannot be saved.
func TestManager_SaveAsTemplateRejectsOverlay(t *testing.T) {
	templatesDir := t.TempDir()
	overlayBase := t.TempDir()

	cfg := Config{
		TemplatesDir: templatesDir,
		OverlayBase:  overlayBase,
	}
	m, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	// Create a fake overlay SandFS directory with .template marker
	sandfsDir := filepath.Join(overlayBase, "overlay-sandfs-1")
	if err := os.MkdirAll(sandfsDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sandfsDir, ".template"), []byte("base:v1"), 0644); err != nil {
		t.Fatal(err)
	}

	// SaveAsTemplate should reject overlay SandFS
	_, err = m.SaveAsTemplate(context.Background(), "overlay-sandfs-1", SaveAsTemplateRequest{
		TemplateRef: "should:v1",
	})
	if err == nil {
		t.Fatal("expected error when saving overlay SandFS as template")
	}
}

// TestManager_HasOCIRegistry tests the HasOCIRegistry method.
func TestManager_HasOCIRegistry(t *testing.T) {
	templatesDir := t.TempDir()
	overlayBase := t.TempDir()

	// Without OCI registry
	cfg := Config{
		TemplatesDir: templatesDir,
		OverlayBase:  overlayBase,
	}
	m, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if m.HasOCIRegistry() {
		t.Error("HasOCIRegistry should be false without registry config")
	}

	// With OCI registry (will fail to connect, but config is set)
	cfg2 := Config{
		Registry:     "localhost:5000/test",
		TemplatesDir: t.TempDir(),
		OverlayBase:  overlayBase,
	}
	m2, err := NewManager(cfg2)
	if err != nil {
		t.Fatalf("NewManager with registry: %v", err)
	}
	if !m2.HasOCIRegistry() {
		t.Error("HasOCIRegistry should be true with registry config")
	}
}

// TestManager_RefFilenameWithMode tests the ref filename format with mode suffix.
func TestManager_RefFilenameWithMode(t *testing.T) {
	templatesDir := t.TempDir()
	overlayBase := t.TempDir()

	cfg := Config{
		TemplatesDir: templatesDir,
		OverlayBase:  overlayBase,
	}
	m, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	localDir := t.TempDir()
	createMockRootfs(t, localDir)

	// Register flat template
	if err := m.RegisterFlatTemplate("myapp:v2", localDir); err != nil {
		t.Fatalf("RegisterFlatTemplate: %v", err)
	}

	// Verify the ref file has .flat.json suffix
	expected := filepath.Join(templatesDir, "refs", "myapp_v2.flat.json")
	if _, err := os.Stat(expected); os.IsNotExist(err) {
		t.Errorf("Expected ref file %s not found", expected)
	}

	// Register overlay template with same name
	if err := m.RegisterLocalTemplate("myapp:v2", localDir); err != nil {
		t.Fatalf("RegisterLocalTemplate: %v", err)
	}

	// Verify the overlay ref file has .overlay.json suffix
	expectedOverlay := filepath.Join(templatesDir, "refs", "myapp_v2.overlay.json")
	if _, err := os.Stat(expectedOverlay); os.IsNotExist(err) {
		t.Errorf("Expected overlay ref file %s not found", expectedOverlay)
	}

	// Both should still exist
	if _, err := os.Stat(expected); os.IsNotExist(err) {
		t.Error("Flat ref file disappeared after overlay registration")
	}
}

// TestRefToFilename tests the ref filename sanitization.
func TestRefToFilename(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"sqlite:v1", "sqlite_v1"},
		{"mysql:v2", "mysql_v2"},
		{"simple", "simple"},
		{"a:b:c", "a_b_c"},
	}
	for _, tt := range tests {
		got := util.RefToFilename(tt.input)
		if got != tt.expected {
			t.Errorf("util.RefToFilename(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

// TestFilenameToRef tests the filename-to-ref conversion.
func TestFilenameToRef(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"sqlite_v1", "sqlite:v1"},
		{"mysql_v2", "mysql:v2"},
		{"simple", "simple"},
		{"ubuntu_24.04", "ubuntu:24.04"},
		{"my_app_v1", "my_app:v1"},
	}
	for _, tt := range tests {
		got := filenameToRef(tt.input)
		if got != tt.expected {
			t.Errorf("filenameToRef(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

// TestAuthConfig_ToClient tests authentication configuration. The credential
// axis (basic / bearer / anonymous) and the TLS axis (mTLS pair, CA) are
// independent — combinations must configure BOTH.
func TestAuthConfig_ToClient(t *testing.T) {
	certPath, keyPath := generateTestCert(t)
	tests := []struct {
		name    string
		config  AuthConfig
		wantTLS bool // expect a custom http.Client (cert/key/ca configured)
	}{
		{
			name: "username/password",
			config: AuthConfig{
				Username: "testuser",
				Password: "testpass",
			},
		},
		{
			name: "bearer token",
			config: AuthConfig{
				Token: "test-token-12345",
			},
		},
		{
			name:   "anonymous",
			config: AuthConfig{},
		},
		{
			// The Harbor shape: basic auth over TLS with a private CA — the
			// credential AND the TLS transport must both be configured.
			name: "username/password + CA",
			config: AuthConfig{
				Username: "testuser",
				Password: "testpass",
				CAFile:   certPath,
			},
			wantTLS: true,
		},
		{
			name: "bearer token + mTLS",
			config: AuthConfig{
				Token:    "test-token-12345",
				CertFile: certPath,
				KeyFile:  keyPath,
			},
			wantTLS: true,
		},
		{
			name:    "CA-only (server verification, no client cert)",
			config:  AuthConfig{CAFile: certPath},
			wantTLS: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := tt.config.toClient()
			if err != nil {
				t.Fatalf("toClient: %v", err)
			}
			if client == nil {
				t.Fatal("Client is nil")
			}
			if (client.Client != nil) != tt.wantTLS {
				t.Errorf("custom http.Client configured = %v, want %v", client.Client != nil, tt.wantTLS)
			}
			if client.Credential == nil {
				t.Fatal("Credential func must always be set")
			}
			// The credential must still be the configured one when TLS is added.
			cred, err := client.Credential(context.Background(), "example.com")
			if err != nil {
				t.Fatalf("Credential: %v", err)
			}
			switch {
			case tt.config.Username != "":
				if cred.Username != tt.config.Username || cred.Password != tt.config.Password {
					t.Errorf("credential = %q/%q, want %q/%q", cred.Username, cred.Password, tt.config.Username, tt.config.Password)
				}
			case tt.config.Token != "":
				if cred.AccessToken != tt.config.Token {
					t.Errorf("access token = %q, want %q", cred.AccessToken, tt.config.Token)
				}
			default:
				if cred.Username != "" || cred.AccessToken != "" {
					t.Errorf("expected anonymous credential, got %+v", cred)
				}
			}
		})
	}
}

// Helper functions

func createMockTemplate(t *testing.T, dir, name, version string) {
	t.Helper()

	// Create template.json
	templateJSON := `{
		"name": "` + name + `",
		"version": "` + version + `",
		"description": "Test template",
		"workspace_path": "/workspace"
	}`

	if err := os.WriteFile(filepath.Join(dir, "template.json"), []byte(templateJSON), 0644); err != nil {
		t.Fatal(err)
	}

	// Create some directories
	for _, subdir := range []string{"bin", "etc", "workspace"} {
		if err := os.MkdirAll(filepath.Join(dir, subdir), 0755); err != nil {
			t.Fatal(err)
		}
	}
}

func createMockRootfs(t *testing.T, dir string) {
	t.Helper()

	// Create a minimal rootfs structure
	for _, subdir := range []string{"bin", "etc", "usr", "workspace"} {
		if err := os.MkdirAll(filepath.Join(dir, subdir), 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "test.txt"), []byte("test content"), 0644); err != nil {
		t.Fatal(err)
	}
}

func createMockRootfsWithFiles(t *testing.T, dir string, fileCount int) {
	t.Helper()

	// Create a minimal rootfs structure
	for _, subdir := range []string{"bin", "etc", "usr", "workspace"} {
		if err := os.MkdirAll(filepath.Join(dir, subdir), 0755); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < fileCount; i++ {
		content := fmt.Sprintf("file content %d", i)
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("file-%d.txt", i)), []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
}

// createMockOCILayer creates an OCI-style layer under layers/sha256-<digest>/.
// Returns the short digest (first 16 chars of sha256 hex).
func createMockOCILayer(t *testing.T, templatesDir, name string) string {
	t.Helper()

	// Create tar.gz content
	var buf bytes.Buffer
	gzw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gzw)

	content := fmt.Sprintf("layer content for %s", name)
	hdr := &tar.Header{
		Name: name + ".txt",
		Mode: 0644,
		Size: int64(len(content)),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	tw.Close()
	gzw.Close()

	// Calculate digest
	hash := sha256.Sum256(buf.Bytes())
	digest := hex.EncodeToString(hash[:])
	shortDigest := "sha256-" + digest[:16]

	// Create layer directory
	layerPath := filepath.Join(templatesDir, "layers", shortDigest)
	if err := os.MkdirAll(layerPath, 0755); err != nil {
		t.Fatal(err)
	}

	// Extract the tar.gz to the layer directory
	if err := extractTarGz(bytes.NewReader(buf.Bytes()), layerPath); err != nil {
		t.Fatal(err)
	}

	return shortDigest
}

func extractTarGz(r io.Reader, dest string) error {
	gzr, err := gzip.NewReader(r)
	if err != nil {
		return err
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		target := filepath.Join(dest, hdr.Name)

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, os.FileMode(hdr.Mode)); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return err
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY, os.FileMode(hdr.Mode))
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return err
			}
			f.Close()
		}
	}
	return nil
}

func verifyTarGzContains(archivePath, filename string) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer f.Close()

	gzr, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if hdr.Name == filename {
			return nil
		}
	}

	return fmt.Errorf("file %s not found in archive", filename)
}

// TestManager_LazyRescanNoRestart pins the no-restart discovery contract: a
// template directory dropped into a scan root AFTER the manager started must
// be found by the next reader (list, LoadRefEntry, GetTemplate) — discovery
// walks re-run lazily on reader misses, never requiring a gateway restart.
func TestManager_LazyRescanNoRestart(t *testing.T) {
	templatesDir := t.TempDir()
	overlayBase := t.TempDir()
	flatDir := t.TempDir()

	// Startup state: one flat template, no overlay templates.
	startFlat := filepath.Join(flatDir, "ubuntu", "24.04")
	if err := os.MkdirAll(startFlat, 0755); err != nil {
		t.Fatal(err)
	}
	createMockRootfs(t, startFlat)

	m, err := NewManager(Config{TemplatesDir: templatesDir, OverlayBase: overlayBase, ResolveVolume: legacyResolver(overlayBase)})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if err := m.ScanFlatTemplates(flatDir); err != nil {
		t.Fatalf("ScanFlatTemplates: %v", err)
	}

	// After startup: drop a new flat template dir AND a new overlay source
	// dir into their scan roots — simulating an operator (or a peer gateway
	// on shared storage) adding templates without restarting this gateway.
	newFlat := filepath.Join(flatDir, "alpine", "3.20")
	if err := os.MkdirAll(newFlat, 0755); err != nil {
		t.Fatal(err)
	}
	createMockRootfs(t, newFlat)
	newOverlay := filepath.Join(templatesDir, "sqlite", "v2")
	if err := os.MkdirAll(newOverlay, 0755); err != nil {
		t.Fatal(err)
	}
	createMockRootfs(t, newOverlay)

	// Listing discovers both without any restart.
	refs := m.ListLocalTemplates()
	got := map[string]bool{}
	for _, r := range refs {
		got[r] = true
	}
	for _, want := range []string{"ubuntu:24.04", "alpine:3.20", "sqlite:v2"} {
		if !got[want] {
			t.Errorf("ListLocalTemplates missing %q after post-startup drop: %v", want, refs)
		}
	}

	// Create-path lookup discovers the flat template and resolves its layer
	// to the dropped directory (absolute path in the ref file).
	entry, err := m.LoadRefEntry("alpine:3.20", "flat")
	if err != nil {
		t.Fatalf("LoadRefEntry alpine:3.20 flat: %v", err)
	}
	if entry.GetMode() != "flat" || len(entry.Layers) != 1 || entry.Layers[0] != newFlat {
		t.Errorf("alpine:3.20 ref = %+v, want mode=flat layers=[%s]", entry, newFlat)
	}

	// Same for the overlay source dir (mode overlay, absolute path).
	overlayEntry, err := m.LoadRefEntry("sqlite:v2", "overlay")
	if err != nil {
		t.Fatalf("LoadRefEntry sqlite:v2 overlay: %v", err)
	}
	if len(overlayEntry.Layers) != 1 || overlayEntry.Layers[0] != newOverlay {
		t.Errorf("sqlite:v2 ref layers = %v, want [%s]", overlayEntry.Layers, newOverlay)
	}
	if _, err := m.GetTemplate("sqlite:v2", "overlay"); err != nil {
		t.Errorf("GetTemplate sqlite:v2 overlay: %v", err)
	}

	// Sanity: a genuinely unknown ref still fails after the rescan attempt.
	if _, err := m.LoadRefEntry("nosuch:v9", "flat"); err == nil {
		t.Error("LoadRefEntry nosuch:v9 flat: expected error, got nil")
	}
}

// TestManager_RescanConcurrent exercises concurrent readers hitting the lazy
// rescan path at once (plus a concurrent scan registration) — the walks are
// serialized and ref writes are atomic, so this must be race-clean.
func TestManager_RescanConcurrent(t *testing.T) {
	templatesDir := t.TempDir()
	overlayBase := t.TempDir()
	flatDir := t.TempDir()

	m, err := NewManager(Config{TemplatesDir: templatesDir, OverlayBase: overlayBase, ResolveVolume: legacyResolver(overlayBase)})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	done := make(chan struct{})
	for i := 0; i < 8; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			for j := 0; j < 20; j++ {
				_, _ = m.LoadRefEntry("ghost:v1", "flat") // always misses → rescan each time
				_ = m.ListLocalTemplates()
			}
		}()
	}
	// Meanwhile a template appears mid-rescan-storm.
	newFlat := filepath.Join(flatDir, "late", "v1")
	if err := os.MkdirAll(newFlat, 0755); err != nil {
		t.Fatal(err)
	}
	createMockRootfs(t, newFlat)
	if err := m.ScanFlatTemplates(flatDir); err != nil {
		t.Fatalf("ScanFlatTemplates: %v", err)
	}

	for i := 0; i < 8; i++ {
		<-done
	}

	// The storm registered the flat root; a final lookup must find it.
	if _, err := m.LoadRefEntry("late:v1", "flat"); err != nil {
		t.Errorf("LoadRefEntry late:v1 flat after concurrent rescans: %v", err)
	}
}

// TestManager_RescanNeverRewritesExistingRef pins the discovery trust rule:
// the lazy rescan (which makes new template directories usable without a
// restart) must only CREATE ref files — an existing ref is the authoritative
// record and is never "healed" by a later walk. Otherwise a tampered refs
// file (e.g. layers:["/etc"] host-path injection) would be silently
// regenerated back to a legal state before the sandlot's mount-time layer
// validation ever sees it (e2e overlayfs-isolation 8.1).
func TestManager_RescanNeverRewritesExistingRef(t *testing.T) {
	templatesDir := t.TempDir()
	overlayBase := t.TempDir()

	// evil/v1 exists as a directory; the startup scan registers it.
	evilDir := filepath.Join(templatesDir, "evil", "v1")
	if err := os.MkdirAll(evilDir, 0755); err != nil {
		t.Fatal(err)
	}
	createMockRootfs(t, evilDir)

	m, err := NewManager(Config{TemplatesDir: templatesDir, OverlayBase: overlayBase, ResolveVolume: legacyResolver(overlayBase)})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	refFile := filepath.Join(m.refsDir(), "evil_v1.overlay.json")
	if _, err := os.Stat(refFile); err != nil {
		t.Fatalf("startup scan did not register evil:v1: %v", err)
	}

	// Tamper the ref exactly like the e2e does: valid JSON, hostile layer.
	tampered := `{"name":"evil","version":"v1","mode":"overlay","layers":["/etc"]}`
	if err := os.WriteFile(refFile, []byte(tampered), 0644); err != nil {
		t.Fatal(err)
	}

	// A brand-new template directory elsewhere in the scan root plus a
	// reader miss trigger the lazy rescan — the new template MUST be
	// discovered (the no-restart feature) while the tampered ref MUST be
	// left byte-identical (the trust boundary).
	newDir := filepath.Join(templatesDir, "alpine", "3.20")
	if err := os.MkdirAll(newDir, 0755); err != nil {
		t.Fatal(err)
	}
	createMockRootfs(t, newDir)
	if _, err := m.LoadRefEntry("alpine:3.20", "overlay"); err != nil {
		t.Fatalf("lazy rescan did not discover the new template: %v", err)
	}

	got, err := os.ReadFile(refFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != tampered {
		t.Fatalf("rescan rewrote the existing ref — discovery must be create-only.\n got: %s", string(got))
	}

	// RegisterLocalTemplate/RegisterFlatTemplate are no-ops for existing
	// refs, and still register absent ones.
	if err := m.RegisterLocalTemplate("evil:v1", evilDir); err != nil {
		t.Fatalf("re-register should be an idempotent no-op: %v", err)
	}
	got, _ = os.ReadFile(refFile)
	if string(got) != tampered {
		t.Fatalf("explicit discovery re-registration rewrote the ref")
	}
}

// TestManager_DeletedTemplateReflectsReality pins the deletion half of the
// lifecycle contract: refs are durable records (never pruned by discovery),
// but every READ surface reflects actual existence — a template directory
// deleted after registration disappears from the listing, creation would
// fail fast, and re-creating the directory at the same path restores the
// template instantly (the kept ref is reused, still no restart).
func TestManager_DeletedTemplateReflectsReality(t *testing.T) {
	templatesDir := t.TempDir()
	overlayBase := t.TempDir()

	dir := filepath.Join(templatesDir, "gone", "v1")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	createMockRootfs(t, dir)

	m, err := NewManager(Config{TemplatesDir: templatesDir, OverlayBase: overlayBase, ResolveVolume: legacyResolver(overlayBase)})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if !contains(m.ListLocalTemplates(), "gone:v1") {
		t.Fatalf("registered template missing from list: %v", m.ListLocalTemplates())
	}
	entry, err := m.LoadRefEntry("gone:v1", "overlay")
	if err != nil || !m.RefEntryExists(entry) {
		t.Fatalf("RefEntryExists should hold while the directory exists")
	}

	// Delete the backing directory; the ref file stays (durable record).
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if contains(m.ListLocalTemplates(), "gone:v1") {
		t.Fatalf("ghost template still listed after its directory was deleted")
	}
	if fresh, _ := m.LoadRefEntry("gone:v1", "overlay"); m.RefEntryExists(fresh) {
		t.Fatalf("RefEntryExists should be false for a deleted template")
	}
	if _, err := os.Stat(filepath.Join(m.refsDir(), "gone_v1.overlay.json")); err != nil {
		t.Fatalf("ref file must survive deletion (durable record): %v", err)
	}

	// Re-create the directory at the same path: the template returns via the
	// kept ref — no restart, no re-registration.
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	createMockRootfs(t, dir)
	if !contains(m.ListLocalTemplates(), "gone:v1") {
		t.Fatalf("re-created template not listed via its kept ref: %v", m.ListLocalTemplates())
	}

	// OCI-backed flat refs have nothing local to stat — they always count as
	// existing (the ref is the record; blobs re-stream at creation).
	if err := os.MkdirAll(filepath.Join(m.refsDir()), 0755); err != nil {
		t.Fatal(err)
	}
	ociRef := `{"name":"remote","version":"v1","mode":"flat","oci_layers":[{"digest":"sha256:aaaaaaaa","size":1}]}`
	if err := os.WriteFile(filepath.Join(m.refsDir(), "remote_v1.flat.json"), []byte(ociRef), 0644); err != nil {
		t.Fatal(err)
	}
	if !contains(m.ListLocalTemplates(), "remote:v1") {
		t.Fatalf("OCI-backed ref should be listed regardless of local dirs: %v", m.ListLocalTemplates())
	}
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

// legacyResolver is the identity resolver the fixtures use: their volumes live
// at <overlayBase>/<id>, so resolving means joining. Production injects the
// seed-aware resolver instead (see sandlot/provision/volname).
func legacyResolver(overlayBase string) func(string) (string, error) {
	return func(id string) (string, error) {
		return filepath.Join(overlayBase, id), nil
	}
}

// Template completeness: every template must carry the directories the warden mounts
// into — an overlay template's merged root is read-only, so a missing one
// cannot be created at attach time and degrades silently (busybox fallback,
// no resolv.conf). The guarantee lives at template BUILD/IMPORT time.
func TestEnsureTemplateSkeleton(t *testing.T) {
	dir := t.TempDir()
	// A template that already has some entries keeps them untouched.
	if err := os.MkdirAll(filepath.Join(dir, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(dir, "bin", "busybox")
	if err := os.WriteFile(marker, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	created, err := ensureTemplateSkeleton(dir)
	if err != nil {
		t.Fatalf("ensureTemplateSkeleton: %v", err)
	}
	if len(created) == 0 {
		t.Fatalf("expected missing skeleton dirs to be created, got none")
	}
	for _, name := range templateSkeletonDirs {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil || !info.IsDir() {
			t.Fatalf("skeleton dir %q missing after ensure (err=%v)", name, err)
		}
	}
	if b, err := os.ReadFile(marker); err != nil || string(b) != "x" {
		t.Fatalf("existing template content must be preserved (err=%v content=%q)", err, b)
	}
	// Idempotent: second call creates nothing.
	if created2, err := ensureTemplateSkeleton(dir); err != nil || len(created2) != 0 {
		t.Fatalf("second ensure must be a no-op, got created=%v err=%v", created2, err)
	}
	// A file where a directory belongs is a template defect, not silently ok.
	if err := os.Remove(filepath.Join(dir, "proc")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "proc"), []byte("not a dir"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ensureTemplateSkeleton(dir); err == nil {
		t.Fatalf("a non-directory at a skeleton name must be reported")
	}
}

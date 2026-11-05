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

package mcp

import (
	"strings"
	"testing"

	"gateway/identity"
)

// TestBuildToolsList_Catalog verifies the tool catalog is complete and every
// expected tool name is present with a well-formed schema (type=object +
// properties map + required array where applicable).
func TestBuildToolsList_Catalog(t *testing.T) {
	env := newTestEnv(t)
	tools := env.server.buildToolsList(env.agentID)

	// Every tool name the dispatch switch expects must be present - a missing
	// tool here would make dispatchToolCall return "unknown tool" for it.
	wantNames := map[string]bool{
		"execute": false, "file_read": false, "file_write": false, "file_stat": false,
		"file_list_dir": false, "file_mkdir": false, "file_remove": false, "file_rename": false,
		"exec_status": false, "exec_kill": false, "list_sandfs": false, "sandswap_guide": false,
	}
	if len(tools) != len(wantNames) {
		t.Errorf("tool count = %d, want %d", len(tools), len(wantNames))
	}
	for _, tl := range tools {
		if _, ok := wantNames[tl.Name]; !ok {
			t.Errorf("unexpected tool name %q", tl.Name)
		}
		wantNames[tl.Name] = true

		// Schema well-formedness: must be an object with a properties map.
		schemaType, _ := tl.InputSchema["type"].(string)
		if schemaType != "object" {
			t.Errorf("tool %q: schema type = %q, want object", tl.Name, schemaType)
		}
		props, ok := tl.InputSchema["properties"].(map[string]interface{})
		if !ok {
			t.Errorf("tool %q: properties not a map", tl.Name)
			continue
		}
		// The sandfs_id property (when present) must be a string with the enum
		// populated from the agent's sandfs instances.
		if sandfsProp, has := props["sandfs_id"]; has {
			sp, ok := sandfsProp.(map[string]interface{})
			if !ok {
				t.Errorf("tool %q: sandfs_id property not a map", tl.Name)
			} else if sp["type"] != "string" {
				t.Errorf("tool %q: sandfs_id type = %v, want string", tl.Name, sp["type"])
			}
			enum, _ := sp["enum"].([]string)
			if len(enum) != 1 || enum[0] != env.sandfsID {
				t.Errorf("tool %q: sandfs_id enum = %v, want [%s]", tl.Name, enum, env.sandfsID)
			}
		}
	}
	// Confirm no expected name was missing.
	for name, seen := range wantNames {
		if !seen {
			t.Errorf("missing tool %q from catalog", name)
		}
	}
}

// TestBuildToolsList_RequiredFields verifies each tool declares the correct
// required fields (these are what MCP clients validate before calling).
func TestBuildToolsList_RequiredFields(t *testing.T) {
	env := newTestEnv(t)
	tools := env.server.buildToolsList(env.agentID)

	wantRequired := map[string][]string{
		"execute":       {"sandfs_id", "code", "language"},
		"file_read":     {"sandfs_id", "path"},
		"file_write":    {"sandfs_id", "path"},
		"file_stat":     {"sandfs_id", "path"},
		"file_list_dir": {"sandfs_id", "path"},
		"file_mkdir":    {"sandfs_id", "path"},
		"file_remove":   {"sandfs_id", "path"},
		"file_rename":   {"sandfs_id", "path", "new_path"},
		"exec_status":   {"sandfs_id", "exec_id"},
		"exec_kill":     {"sandfs_id", "exec_id"},
		// list_sandfs has no required fields.
	}
	for _, tl := range tools {
		want, ok := wantRequired[tl.Name]
		if !ok {
			continue // list_sandfs
		}
		raw, has := tl.InputSchema["required"]
		if tl.Name == "list_sandfs" {
			if has {
				t.Errorf("list_sandfs should have no 'required' field, got %v", raw)
			}
			continue
		}
		req, ok := raw.([]string)
		if !ok {
			t.Errorf("tool %q: required not []string: %T", tl.Name, raw)
			continue
		}
		if len(req) != len(want) {
			t.Errorf("tool %q: required len = %d, want %d (%v)", tl.Name, len(req), len(want), want)
			continue
		}
		wantSet := map[string]bool{}
		for _, w := range want {
			wantSet[w] = true
		}
		for _, r := range req {
			if !wantSet[r] {
				t.Errorf("tool %q: unexpected required field %q", tl.Name, r)
			}
		}
	}
}

// TestBuildToolsList_SandfsEnumAndDescription verifies the agent's sandfs
// instances are embedded into the execute tool description and the sandfs_id
// enum of every tool.
func TestBuildToolsList_SandfsEnumAndDescription(t *testing.T) {
	env := newTestEnv(t)
	second := env.addSandfs("second-sandfs")
	tools := env.server.buildToolsList(env.agentID)

	// Find the execute tool and check its description mentions both sandfs.
	var execTool *mcpTool
	for i := range tools {
		if tools[i].Name == "execute" {
			execTool = &tools[i]
		}
	}
	if execTool == nil {
		t.Fatal("execute tool not found")
	}
	if !strings.Contains(execTool.Description, env.sandfsID) {
		t.Errorf("execute description missing first sandfs_id %q:\n%s", env.sandfsID, execTool.Description)
	}
	if !strings.Contains(execTool.Description, second) {
		t.Errorf("execute description missing second sandfs_id %q:\n%s", second, execTool.Description)
	}
	// The description should include the sandfs name.
	if !strings.Contains(execTool.Description, "test-sandfs") {
		t.Errorf("execute description missing sandfs name 'test-sandfs':\n%s", execTool.Description)
	}

	// Every tool with a sandfs_id property should have a 2-element enum.
	for _, tl := range tools {
		props, _ := tl.InputSchema["properties"].(map[string]interface{})
		if sandfsProp, has := props["sandfs_id"]; has {
			sp, _ := sandfsProp.(map[string]interface{})
			enum, _ := sp["enum"].([]string)
			if len(enum) != 2 {
				t.Errorf("tool %q: sandfs_id enum len = %d, want 2", tl.Name, len(enum))
			}
		}
	}
}

// TestBuildToolsList_EmptySandfs verifies that an agent with no sandfs still
// gets a valid tools list (no enum on sandfs_id, no sandfs in description).
func TestBuildToolsList_EmptySandfs(t *testing.T) {
	env := newTestEnv(t)
	if err := env.store.DeleteSandFS(env.sandfsID); err != nil {
		t.Fatal(err)
	}
	tools := env.server.buildToolsList(env.agentID)
	if len(tools) == 0 {
		t.Fatal("expected non-empty tools list even with no sandfs")
	}
	for _, tl := range tools {
		props, _ := tl.InputSchema["properties"].(map[string]interface{})
		if sandfsProp, has := props["sandfs_id"]; has {
			sp, _ := sandfsProp.(map[string]interface{})
			if _, hasEnum := sp["enum"]; hasEnum {
				t.Errorf("tool %q: sandfs_id should have no enum when agent has no sandfs", tl.Name)
			}
		}
	}
}

// TestBuildToolsList_DescriptionFallback verifies a sandfs with an empty
// description gets the "(no description)" fallback in the execute description.
func TestBuildToolsList_DescriptionFallback(t *testing.T) {
	env := newTestEnv(t)
	// Add a sandfs with no description.
	rec, err := env.store.CreateSandFS(env.agentID, identity.CreateSandFSRequest{
		Name: "no-desc-sandfs",
		// Description intentionally empty
	})
	if err != nil {
		t.Fatalf("create sandfs: %v", err)
	}
	_ = env.store.SetRootFSPath(rec.ID, "/tmp/x")

	tools := env.server.buildToolsList(env.agentID)
	var execTool *mcpTool
	for i := range tools {
		if tools[i].Name == "execute" {
			execTool = &tools[i]
		}
	}
	if !strings.Contains(execTool.Description, "(no description)") {
		t.Errorf("expected '(no description)' fallback in execute description:\n%s", execTool.Description)
	}
}

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
	"encoding/json"
	"fmt"
	"io"
	"os"
	"syscall"
)

// maxAgentsFileBytes bounds the agent-key cache read. The cache holds one
// record per agent (id/key/name); anything larger is not a file this tool
// wrote.
const maxAgentsFileBytes = 4 << 20

// AgentRecord is one entry in run/agents.json — the api_key returned by
// POST /human/agent is shown exactly once, so sandctl caches it so later
// `--agent <id>` calls can resolve the key without re-asking the user.
type AgentRecord struct {
	AgentID string `json:"agent_id"`
	APIKey  string `json:"api_key"`
	Name    string `json:"name"`
}

// loadAgents reads run/agents.json (returns empty list if absent). The file
// lives in a directory the invoking user controls, so it is opened below the
// anchored run root: a planted symlink/FIFO is refused rather than followed or
// blocked on. The cache holds live API keys, so a file another identity owns
// or that group/world can read is refused with a warning instead of silently
// trusting it.
func loadAgents(g Global) []AgentRecord {
	root, err := openRunRoot(g.RunDir, false)
	if err != nil {
		return nil
	}
	defer root.Close()
	f, err := openRunFile(root, "agents.json", syscall.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() > maxAgentsFileBytes {
		return nil
	}
	if perm := st.Mode().Perm(); perm&0o077 != 0 {
		fmt.Fprintf(os.Stderr, "warning: %s has mode %04o (group/world access) — refusing to use cached API keys; chmod 600 it\n",
			g.AgentsFile(), perm)
		return nil
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); ok && !trustedRunFileOwner(sys.Uid) {
		fmt.Fprintf(os.Stderr, "warning: %s is owned by uid %d, neither the invoking uid %d nor root — refusing to use cached API keys\n",
			g.AgentsFile(), sys.Uid, os.Geteuid())
		return nil
	}
	data, err := io.ReadAll(io.LimitReader(f, maxAgentsFileBytes))
	if err != nil {
		return nil
	}
	var recs []AgentRecord
	_ = json.Unmarshal(data, &recs)
	return recs
}

// saveAgents writes the full agent list back to run/agents.json. The run
// directory belongs to the invoking user (client commands never run through a
// sudo workspace), so the atomic temp+rename path always applies; the file is
// a regular 0600 entry even when a symlink sits at the name.
func saveAgents(g Global, recs []AgentRecord) error {
	data, err := json.MarshalIndent(recs, "", "  ")
	if err != nil {
		return err
	}
	root, err := openRunRoot(g.RunDir, true)
	if err != nil {
		return err
	}
	defer root.Close()
	// 0600: the file caches every agent's plaintext api_key (the gateway
	// returns it exactly once), so it is credential material.
	return writeRunFileAtomic(root, "agents.json", data, 0o600, os.Geteuid(), os.Getegid(), false)
}

// addAgent appends a new record (dedup by agent_id).
func addAgent(g Global, rec AgentRecord) error {
	recs := loadAgents(g)
	for i, r := range recs {
		if r.AgentID == rec.AgentID {
			recs[i] = rec
			return saveAgents(g, recs)
		}
	}
	recs = append(recs, rec)
	return saveAgents(g, recs)
}

// resolveAgentKey returns the API key for an agent id: explicit --api-key wins,
// else run/agents.json lookup.
func resolveAgentKey(g Global, agentID, explicitKey string) (string, error) {
	if explicitKey != "" {
		return explicitKey, nil
	}
	if agentID == "" {
		return "", fmt.Errorf("either --api-key or --agent <id> is required")
	}
	for _, r := range loadAgents(g) {
		if r.AgentID == agentID {
			return r.APIKey, nil
		}
	}
	return "", fmt.Errorf("agent %q not found in %s (pass --api-key explicitly)", agentID, g.AgentsFile())
}

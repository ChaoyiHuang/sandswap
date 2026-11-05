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

package handler_test

import (
	"context"
	"strings"
	"testing"

	"common/config"
	"gateway/handler"
	"gateway/pool"
)

// A workspace path longer than PATH_MAX can neither resolve nor fit the wire;
// the gate (before auth, before any acquisition) must name the refusal. The
// warden enforces the same bound as defense in depth.
func TestFileOp_WireGateRejectsOversizedPaths(t *testing.T) {
	fh, _, reg, apiKey, agentID := setupFileGateway(t)
	sandfsID := createFileTestSandFS(t, reg, agentID)
	long := strings.Repeat("a", config.MaxFilePathBytes+1)

	for _, req := range []pool.FileOpRequest{
		{Action: "stat", Path: long},
		{Action: "rename", Path: "x", NewPath: long},
	} {
		_, err := fh.DoFileOpDirect(context.Background(), sandfsID, apiKey, req)
		if err == nil {
			t.Fatalf("%s with a >PATH_MAX path must be refused", req.Action)
		}
		_, _, code, ok := handler.AsNamedClientError(err)
		if !ok || code != "FILE_PATH_TOO_LONG" {
			t.Fatalf("%s: expected named FILE_PATH_TOO_LONG, got ok=%v code=%q err=%v", req.Action, ok, code, err)
		}
	}
}

// A read with an omitted (or non-positive) length must be normalized to the
// single-op wire cap: the warden reads up to max_file_read_bytes for length 0,
// and that payload plus the gRPC envelope breaches the node stream's message
// limit (a stream reset kills every co-tenant in-flight command).
func TestFileOp_DefaultReadLengthIsClampedToTheWireCap(t *testing.T) {
	fh, sc, reg, apiKey, agentID := setupFileGateway(t)
	sandfsID := createFileTestSandFS(t, reg, agentID)
	sc.result = pool.FileOpResult{Data: []byte("ok"), Success: true}

	const cap = 1024
	prev := handler.SetMaxFileOpDataBytesForTest(cap)
	defer handler.SetMaxFileOpDataBytesForTest(prev)

	for _, body := range []string{
		`{"sandfs_id":"` + sandfsID + `","action":"read","path":"f"}`,
		`{"sandfs_id":"` + sandfsID + `","action":"read","path":"f","length":-5}`,
	} {
		w := doFileRequest(t, fh, apiKey, body)
		if w.Code != 200 {
			t.Fatalf("read must succeed, got %d: %s", w.Code, w.Body.String())
		}
		if got := sc.lastFileReq().Length; got != cap {
			t.Fatalf("default read length must be clamped to %d, got %d", cap, got)
		}
	}

	// An explicit over-cap length keeps its named refusal.
	_, err := fh.DoFileOpDirect(context.Background(), sandfsID, apiKey, pool.FileOpRequest{
		Action: "read", Path: "f", Length: cap + 1,
	})
	if err == nil {
		t.Fatal("an over-cap read length must be refused")
	}
	_, _, code, ok := handler.AsNamedClientError(err)
	if !ok || code != "FILE_TOO_LARGE" {
		t.Fatalf("expected named FILE_TOO_LARGE, got ok=%v code=%q err=%v", ok, code, err)
	}
}

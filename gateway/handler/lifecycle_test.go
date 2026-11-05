// Copyright 2026 Chaoyi Huang. All rights reserved.
//
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE file at the root of this repository.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, sandswap's use of this software will be governed
// by the Apache License, Version 2.0.

package handler_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gateway/handler"
	"gateway/identity"
	"gateway/lease"
	"gateway/pool"
	"gateway/storage"
	"gateway/storage/storagetest"
)

// setSandfsStatus flips the record's lifecycle status directly.
func setSandfsStatus(t *testing.T, gw *testGateway, sandfsID, status string) {
	t.Helper()
	if err := gw.reg.Store().SetSandfsStatus(sandfsID, status); err != nil {
		t.Fatalf("SetSandfsStatus(%q): %v", status, err)
	}
}

// TestExecuteGateRefusesNonActiveSandfs pins the lifecycle gate: an exec
// against a sandfs mid swap/deletion is refused with a retryable 409 carrying
// the SANDFS_NOT_ACTIVE error code, and the file path is gated identically.
func TestExecuteGateRefusesNonActiveSandfs(t *testing.T) {
	gw := setupTestGateway(t)
	sandfsID := createTestSandFS(t, gw, "gated")
	setSandfsStatus(t, gw, sandfsID, identity.SandfsStatusDetaching)

	// ExecuteDirect: named 409.
	_, err := gw.execHandler.ExecuteDirect(context.Background(), gw.agentAPIKey, handler.ExecuteRequest{
		SandfsID: sandfsID,
		Code:     "echo hi",
	})
	if err == nil {
		t.Fatal("expected gate refusal, got success")
	}
	msg, code, retryable, _, _, ok := handler.AsResilienceError(err)
	if !ok {
		t.Fatalf("expected resilienceError, got %T: %v", err, err)
	}
	if code != "SANDFS_NOT_ACTIVE" {
		t.Fatalf("error_code = %q, want SANDFS_NOT_ACTIVE (msg %q)", code, msg)
	}
	if !retryable {
		t.Fatal("gate refusal must be retryable")
	}

	// File op path: same named refusal.
	_, err = gw.fileHandler.DoFileOpDirect(context.Background(), sandfsID, gw.agentAPIKey, fileOpReadRequest("x.txt"))
	if err == nil {
		t.Fatal("expected file gate refusal, got success")
	}
	_, code, _, _, _, ok = handler.AsResilienceError(err)
	if !ok || code != "SANDFS_NOT_ACTIVE" {
		t.Fatalf("file gate: code=%q ok=%v err=%v", code, ok, err)
	}

	// An ACTIVE sandfs passes the gate untouched.
	other := createTestSandFS(t, gw, "active")
	if _, err := gw.execHandler.ExecuteDirect(context.Background(), gw.agentAPIKey, handler.ExecuteRequest{
		SandfsID: other,
		Code:     "echo hi",
	}); err != nil {
		t.Fatalf("active sandfs must not be gated: %v", err)
	}
}

// fileOpReadRequest builds a minimal read FileOpRequest.
func fileOpReadRequest(path string) pool.FileOpRequest {
	return pool.FileOpRequest{Action: "read", Path: path}
}

// TestDetachAttachTemplateFlow drives the full swap lifecycle through the
// human endpoints with the INLINE drainer (single-node shape): detach settles
// to "detached", execs are gated meanwhile, attach re-points the volume and
// returns the record to active, and the workspace survives.
func TestDetachAttachTemplateFlow(t *testing.T) {
	gw := setupTestGateway(t)
	gw.humanHandler.SetDrainer(&lease.Drainer{Pool: gw.pm, Lease: gw.lm, Logger: nil})

	// An overlay sandfs (the storagetest double materializes the overlay
	// layout: workspace/ + home/ + .template marker).
	rec, _, err := gw.reg.CreateSandFS(t.Context(), gw.agentID, identity.CreateSandFSRequest{
		Name:     "swap-me",
		Template: "test:v1",
		Mode:     "overlay",
	})
	if err != nil {
		t.Fatalf("create overlay sandfs: %v", err)
	}
	sandfsID := rec.ID

	// Agent work in the workspace (written directly to the volume dir: the
	// stub sandlot client's FileOp is a canned success, so persistence is
	// asserted at the storage layer — which is what the swap must preserve).
	workspaceFile := filepath.Join(gw.reg.VolRoot(), sandfsID, "workspace", "work.txt")
	if err := os.MkdirAll(filepath.Dir(workspaceFile), 0o770); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(workspaceFile, []byte("agent work"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Flat sandfs refuses detach with a named 400.
	flat := createTestSandFS(t, gw, "flat-one")
	w := doHumanRequest(gw.humanHandler, "POST", "/human/sandfs/"+flat+"/detach-template", "{}")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("flat detach: expected 400, got %d (%s)", w.Code, w.Body.String())
	}

	// Attach before detach: 409.
	w = doHumanRequest(gw.humanHandler, "POST", "/human/sandfs/"+sandfsID+"/attach-template", `{"template_ref":"test:v2"}`)
	if w.Code != http.StatusConflict {
		t.Fatalf("attach before detach: expected 409, got %d (%s)", w.Code, w.Body.String())
	}

	// Detach: settles inline (no lease entry, stub nodes report unmounted).
	w = doHumanRequest(gw.humanHandler, "POST", "/human/sandfs/"+sandfsID+"/detach-template", "{}")
	if w.Code != http.StatusOK {
		t.Fatalf("detach: expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	var detachResp struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &detachResp); err != nil || detachResp.Status != "detached" {
		t.Fatalf("detach status: %+v %v", detachResp, err)
	}

	// While detached: execs and file ops are gated.
	if _, err := gw.execHandler.ExecuteDirect(context.Background(), gw.agentAPIKey, handler.ExecuteRequest{
		SandfsID: sandfsID, Code: "echo hi",
	}); err == nil {
		t.Fatal("exec during detached must be gated")
	}

	// GET single sandfs reports the status.
	w = doHumanRequest(gw.humanHandler, "GET", "/human/sandfs/"+sandfsID, "")
	if w.Code != http.StatusOK {
		t.Fatalf("get sandfs: %d", w.Code)
	}
	var got struct {
		Status string `json:"status"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	if got.Status != "detached" {
		t.Fatalf("get status = %q, want detached", got.Status)
	}

	// Attach to a new ref: volume marker swapped, record back to active.
	w = doHumanRequest(gw.humanHandler, "POST", "/human/sandfs/"+sandfsID+"/attach-template", `{"template_ref":"test:v2"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("attach: expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	fresh, err := gw.reg.Store().GetSandFS(sandfsID)
	if err != nil {
		t.Fatal(err)
	}
	if fresh.Status != "" || fresh.Template != "test:v2" {
		t.Fatalf("record after attach: status=%q template=%q", fresh.Status, fresh.Template)
	}
	// Workspace carried over through the swap (untouched on storage).
	if b, err := os.ReadFile(workspaceFile); err != nil || string(b) != "agent work" {
		t.Fatalf("workspace content after swap: %q %v", b, err)
	}

	// One-shot swap endpoint on a fresh overlay sandfs.
	rec2, _, err := gw.reg.CreateSandFS(t.Context(), gw.agentID, identity.CreateSandFSRequest{
		Name: "swap-once", Template: "test:v1", Mode: "overlay",
	})
	if err != nil {
		t.Fatal(err)
	}
	w = doHumanRequest(gw.humanHandler, "POST", "/human/sandfs/"+rec2.ID+"/swap-template", `{"template_ref":"test:v2"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("swap-template: expected 200, got %d (%s)", w.Code, w.Body.String())
	}
	fresh2, _ := gw.reg.Store().GetSandFS(rec2.ID)
	if fresh2.Template != "test:v2" || fresh2.Status != "" {
		t.Fatalf("swap-template result: %+v", fresh2)
	}
}

// TestDeleteTemplateRefusesWhileInUse pins layer 1 of the in-use check: the
// gateway's own records refuse the delete before the storage plane is touched.
func TestDeleteTemplateRefusesWhileInUse(t *testing.T) {
	gw := setupTestGateway(t)
	rec, _, err := gw.reg.CreateSandFS(t.Context(), gw.agentID, identity.CreateSandFSRequest{
		Name: "holds-template", Template: "test:v1", Mode: "overlay",
	})
	if err != nil {
		t.Fatal(err)
	}

	// In use by the overlay record → 409 without touching the storage plane.
	w := doHumanRequest(gw.humanHandler, "DELETE", "/human/templates/test:v1", `{}`)
	if w.Code != http.StatusConflict {
		t.Fatalf("in-use delete: expected 409, got %d (%s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "TEMPLATE_IN_USE") {
		t.Fatalf("409 body lacks TEMPLATE_IN_USE: %s", w.Body.String())
	}

	// After the sandfs is deleted the record no longer holds the ref.
	if w := doHumanRequest(gw.humanHandler, "DELETE", "/human/sandfs/"+rec.ID, ""); w.Code != http.StatusNoContent {
		t.Fatalf("delete sandfs: %d (%s)", w.Code, w.Body.String())
	}
	// The storagetest double now refuses on the marker scan (layer 2) since
	// DeleteVolume removed the volume — so the delete reaches the storage plane and
	// succeeds.
	w = doHumanRequest(gw.humanHandler, "DELETE", "/human/templates/test:v1", `{}`)
	if w.Code != http.StatusNoContent {
		t.Fatalf("delete after release: expected 204, got %d (%s)", w.Code, w.Body.String())
	}
}

// TestDeleteSandfsSetsLifecycleGate verifies the delete path writes the
// "deleting" gate before terminal deletion: during the drain window new execs
// are refused even if the record still exists.
func TestDeleteSandfsSetsLifecycleGate(t *testing.T) {
	gw := setupTestGateway(t)
	gw.humanHandler.SetDrainer(&lease.Drainer{Pool: gw.pm, Lease: gw.lm, Logger: nil})
	sandfsID := createTestSandFS(t, gw, "deleteme")

	if w := doHumanRequest(gw.humanHandler, "DELETE", "/human/sandfs/"+sandfsID, ""); w.Code != http.StatusNoContent {
		t.Fatalf("delete: %d (%s)", w.Code, w.Body.String())
	}
	// Record gone → exec resolves to 404.
	_, err := gw.execHandler.ExecuteDirect(context.Background(), gw.agentAPIKey, handler.ExecuteRequest{
		SandfsID: sandfsID, Code: "echo hi",
	})
	if err == nil {
		t.Fatal("exec on deleted sandfs must fail")
	}
}

// movedPathOps wraps the storage double and answers every SwapTemplate with a
// path the record does not name — the compromised/confused provisioner shape.
type movedPathOps struct{ storage.Ops }

func (o *movedPathOps) SwapTemplate(ctx context.Context, sandfsID, templateRef, homePolicy string) (*storage.EnsureResult, error) {
	res, err := o.Ops.SwapTemplate(ctx, sandfsID, templateRef, homePolicy)
	if err != nil {
		return nil, err
	}
	res.RootfsPath += "-moved"
	return res, nil
}

// The swap rewrites the volume IN PLACE: a storage executor that answers a
// different rootfs path must not be allowed to move the record's volume (the
// exec nodes verified the recorded path, and provisioning names are not
// gateway-derivable). The request is refused before the record is updated.
func TestSwapRefusesAMovedRootfsPath(t *testing.T) {
	gw := setupTestGateway(t)
	rec, _, err := gw.reg.CreateSandFS(t.Context(), gw.agentID, identity.CreateSandFSRequest{
		Name: "moving", Template: "test:v1", Mode: "overlay",
	})
	if err != nil {
		t.Fatal(err)
	}
	gw.reg.SetStorageOps(&movedPathOps{Ops: gw.storage})
	// Attach requires the detached lifecycle state; drive it directly so the
	// storage answer is what the assertion hinges on.
	setSandfsStatus(t, gw, rec.ID, identity.SandfsStatusDetached)

	w := doHumanRequest(gw.humanHandler, "POST", "/human/sandfs/"+rec.ID+"/attach-template",
		`{"template_ref":"test:v2"}`)
	if w.Code != http.StatusBadGateway {
		t.Fatalf("attach with a moved rootfs path: want 502, got %d (%s)", w.Code, w.Body.String())
	}
	// The record must still name the original volume and template.
	after, err := gw.reg.Store().GetSandFS(rec.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.RootFSPath != rec.RootFSPath || after.Template != rec.Template {
		t.Fatalf("record changed despite the refusal: path %q→%q template %q→%q",
			rec.RootFSPath, after.RootFSPath, rec.Template, after.Template)
	}
}

// TestStorageDoubleSwapTemplate pins the storagetest double's SwapTemplate
// behavior used by the flow tests above (marker rewrite + home policy).
func TestStorageDoubleSwapTemplate(t *testing.T) {
	double := storagetest.New(t.TempDir())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, err := double.EnsureVolume(ctx, "sandfs-x", "overlay", "a:v1"); err != nil {
		t.Fatal(err)
	}
	res, err := double.SwapTemplate(ctx, "sandfs-x", "b:v2", storage.HomeReset)
	if err != nil {
		t.Fatal(err)
	}
	if res.RootfsPath == "" {
		t.Fatal("double returned empty rootfs path")
	}
	// In-use refusal through the double's marker scan.
	err = double.DeleteTemplate(ctx, "b:v2", "", false)
	if _, ok := err.(*storage.TemplateInUseError); !ok {
		t.Fatalf("double DeleteTemplate: want TemplateInUseError, got %v", err)
	}
	if err := double.DeleteTemplate(ctx, "b:v2", "", true); err != nil {
		t.Fatalf("double force delete: %v", err)
	}
}

// TestSwapEndpointsRefuseWhileDeleting pins the lifecycle-ownership rule: a
// deletion in flight owns the record — detach/swap must not flip it back to
// "detaching" (which would enable a mid-delete attach "resurrection").
func TestSwapEndpointsRefuseWhileDeleting(t *testing.T) {
	gw := setupTestGateway(t)
	rec, _, err := gw.reg.CreateSandFS(t.Context(), gw.agentID, identity.CreateSandFSRequest{
		Name: "dying", Template: "test:v1", Mode: "overlay",
	})
	if err != nil {
		t.Fatal(err)
	}
	setSandfsStatus(t, gw, rec.ID, identity.SandfsStatusDeleting)

	w := doHumanRequest(gw.humanHandler, "POST", "/human/sandfs/"+rec.ID+"/detach-template", "{}")
	if w.Code != http.StatusConflict {
		t.Fatalf("detach during deleting: expected 409, got %d (%s)", w.Code, w.Body.String())
	}
	w = doHumanRequest(gw.humanHandler, "POST", "/human/sandfs/"+rec.ID+"/swap-template", `{"template_ref":"test:v2"}`)
	if w.Code != http.StatusConflict {
		t.Fatalf("swap during deleting: expected 409, got %d (%s)", w.Code, w.Body.String())
	}
	// The status must be untouched (delete keeps ownership).
	fresh, _ := gw.reg.Store().GetSandFS(rec.ID)
	if fresh.Status != identity.SandfsStatusDeleting {
		t.Fatalf("status overwritten by refused op: %q", fresh.Status)
	}
}

// TestColdMountRechecksLifecycleGateUnderMountLock pins the post-MountLock
// re-check: a request that passed the lifecycle gate and then queued on the
// cold-mount lock must NOT mount after a detach/delete flipped the record while
// it waited (the drain does not take that lock, so the gate has to be
// re-validated under it).
func TestColdMountRechecksLifecycleGateUnderMountLock(t *testing.T) {
	gw := setupTestGateway(t)
	sf := createTestSandFS(t, gw, "gate-recheck")

	ml := lease.NewMountLock()
	execH := handler.NewExecuteHandler(gw.reg.Store(), gw.pm, gw.lm, pool.NewStubSandlotClient(), ml, nil, lease.NewSandfsState(), 30, 300, 0, slog.New(slog.DiscardHandler))

	// Hold the cold-mount lock like an in-flight mount for the same sandfs.
	tok, err := ml.Acquire(sf)
	if err != nil {
		t.Fatalf("hold mount lock: %v", err)
	}
	errCh := make(chan error, 1)
	go func() {
		_, err := execH.ExecuteDirect(context.Background(), gw.agentAPIKey, handler.ExecuteRequest{SandfsID: sf, Code: "true"})
		errCh <- err
	}()
	// Let the request reach the MountLock wait (its gate check already passed).
	time.Sleep(200 * time.Millisecond)
	setSandfsStatus(t, gw, sf, identity.SandfsStatusDetaching)
	ml.Release(tok)

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("cold mount proceeded after the record left the active state")
		}
		_, code, _, _, _, ok := handler.AsResilienceError(err)
		if !ok || code != "SANDFS_NOT_ACTIVE" {
			t.Fatalf("error = %v (code %q), want SANDFS_NOT_ACTIVE", err, code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("request did not complete after the mount lock was released")
	}
}

// TestDetachWaitsForInFlightColdMount pins the drain-side of the same race: a
// cold mount for the sandfs (holding the process's MountLock) keeps detach from
// settling, and the re-issued detach settles once the dispatch is gone — the
// drain must never write "detached" under a mount that is still landing.
func TestDetachWaitsForInFlightColdMount(t *testing.T) {
	gw := setupTestGateway(t)
	rec, _, err := gw.reg.CreateSandFS(t.Context(), gw.agentID, identity.CreateSandFSRequest{
		Name: "drain-inflight", Template: "test:v1", Mode: "overlay",
	})
	if err != nil {
		t.Fatal(err)
	}
	// Wire the inline drain like single-node, and an exec handler whose
	// MountLock becomes the process's registered dispatch probe.
	gw.humanHandler.SetDrainer(&lease.Drainer{Pool: gw.pm, Lease: gw.lm, Logger: nil})
	ml := lease.NewMountLock()
	_ = handler.NewExecuteHandler(gw.reg.Store(), gw.pm, gw.lm, pool.NewStubSandlotClient(), ml, nil, lease.NewSandfsState(), 30, 300, 0, slog.New(slog.DiscardHandler))

	tok, err := ml.Acquire(rec.ID) // a cold mount in flight for this sandfs
	if err != nil {
		t.Fatal(err)
	}
	w := doHumanRequest(gw.humanHandler, "POST", "/human/sandfs/"+rec.ID+"/detach-template", `{"wait_sec":1}`)
	if w.Code != http.StatusAccepted {
		t.Fatalf("detach under an in-flight mount: code = %d (want 202; body %s)", w.Code, w.Body.String())
	}
	fresh, _ := gw.reg.Store().GetSandFS(rec.ID)
	if fresh.Status == identity.SandfsStatusDetached {
		t.Fatal("drain settled detached while a cold mount was in flight")
	}

	ml.Release(tok)
	w = doHumanRequest(gw.humanHandler, "POST", "/human/sandfs/"+rec.ID+"/detach-template", `{"wait_sec":2}`)
	if w.Code != http.StatusOK {
		t.Fatalf("re-issued detach after the dispatch cleared: code = %d (body %s)", w.Code, w.Body.String())
	}
	fresh, _ = gw.reg.Store().GetSandFS(rec.ID)
	if fresh.Status != identity.SandfsStatusDetached {
		t.Fatalf("status = %q, want detached", fresh.Status)
	}
}

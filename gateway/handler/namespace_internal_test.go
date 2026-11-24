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

package handler

// Projection pins for the namespace (tenant) response views.
//
// The namespace surface serves strict ALLOW-LIST projections of the identity
// records, not the records themselves. These tests fail when the projection
// and the record types drift: a new record field must be explicitly classified
// as tenant-visible (projected) or admin-only (listed in the hidden set), so a
// future storage-side field can never silently leak to a tenant.

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"gateway/identity"
)

// jsonNames returns every JSON field name a struct type declares, skipping
// fields tagged json:"-". An untagged exported field marshals under its Go
// name, so it is classified the same way.
func jsonNames(t reflect.Type) map[string]reflect.StructField {
	out := make(map[string]reflect.StructField, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		raw := f.Tag.Get("json")
		if raw == "-" {
			continue
		}
		name := strings.Split(raw, ",")[0]
		if name == "" {
			name = f.Name
		}
		out[name] = f
	}
	return out
}

// TestNSSandFSViewIsStrictProjection pins the classification of every
// identity.Record field. rootfs_path (host volume directory) and volume_epoch
// (mount-identity secret) are the only fields a tenant must never see; all
// others must be projected. A new Record field fails this test until it is
// classified one way or the other.
func TestNSSandFSViewIsStrictProjection(t *testing.T) {
	recordFields := jsonNames(reflect.TypeOf(identity.Record{}))
	viewFields := jsonNames(reflect.TypeOf(nsSandFSView{}))

	adminOnly := map[string]bool{
		"rootfs_path":  true,
		"volume_epoch": true,
	}
	viewOnly := map[string]bool{
		"pull_status": true, // create response only; no record counterpart
	}

	for name := range adminOnly {
		if _, ok := recordFields[name]; !ok {
			t.Errorf("hidden-set field %q no longer exists on identity.Record — update the classification", name)
		}
		if _, ok := viewFields[name]; ok {
			t.Errorf("tenant view must NOT carry the admin-only field %q", name)
		}
	}
	for name := range recordFields {
		if adminOnly[name] {
			continue
		}
		if _, ok := viewFields[name]; !ok {
			t.Errorf("identity.Record field %q is neither projected into nsSandFSView nor listed as admin-only", name)
		}
	}
	for name := range viewFields {
		if _, ok := recordFields[name]; ok {
			continue
		}
		if !viewOnly[name] {
			t.Errorf("nsSandFSView field %q has no identity.Record counterpart and is not an allowed view-only field", name)
		}
	}
}

// TestNSAgentViewIsStrictProjection is the Agent twin: Agent declares no
// admin-only fields today (the credential material is json:"-"), so every
// JSON-visible field must be projected.
func TestNSAgentViewIsStrictProjection(t *testing.T) {
	agentFields := jsonNames(reflect.TypeOf(identity.Agent{}))
	viewFields := jsonNames(reflect.TypeOf(nsAgentView{}))

	for name := range agentFields {
		if _, ok := viewFields[name]; !ok {
			t.Errorf("identity.Agent field %q is not projected into nsAgentView", name)
		}
	}
	for name := range viewFields {
		if _, ok := agentFields[name]; !ok {
			t.Errorf("nsAgentView field %q has no identity.Agent counterpart", name)
		}
	}
}

// TestNSSandFSViewOutput pins the encoded bytes: a fully populated record
// (including the storage-side fields and their values) projects without
// either secret appearing anywhere in the JSON.
func TestNSSandFSViewOutput(t *testing.T) {
	rec := &identity.Record{
		ID:          "sandfs-tenant-1",
		AgentID:     "agent-tenant-1",
		Name:        "work",
		Description: "tenant sandbox",
		RootFSPath:  "/var/lib/sandswap/volumes/seed-derived-secret",
		VolumeEpoch: "epoch-secret-value",
		Template:    "ubuntu:24.04",
		Mode:        "overlay",
		MinVCPUs:    2,
		MinMemoryMB: 512,
		CreatedAt:   time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC),
		Status:      identity.SandfsStatusDetaching,
		Namespace:   "acme",
	}
	body, err := json.Marshal(nsSandFSViewOf(rec))
	if err != nil {
		t.Fatalf("marshal view: %v", err)
	}
	got := string(body)
	for _, secret := range []string{
		"rootfs_path", "volume_epoch",
		rec.RootFSPath, rec.VolumeEpoch,
	} {
		if strings.Contains(got, secret) {
			t.Errorf("tenant view leaks %q: %s", secret, got)
		}
	}

	var obj map[string]json.RawMessage
	if err := json.Unmarshal(body, &obj); err != nil {
		t.Fatalf("decode view: %v", err)
	}
	want := map[string]bool{
		"sandfs_id": true, "agent_id": true, "name": true, "description": true,
		"template": true, "mode": true, "min_vcpus": true, "min_memory_mb": true,
		"created_at": true, "status": true, "namespace": true,
	}
	for key := range obj {
		if !want[key] {
			t.Errorf("unexpected tenant-view key %q: %s", key, got)
		}
	}
	for key := range want {
		if _, ok := obj[key]; !ok {
			t.Errorf("tenant view missing %q: %s", key, got)
		}
	}

	var createdAt string
	if err := json.Unmarshal(obj["created_at"], &createdAt); err != nil {
		t.Fatalf("decode created_at: %v", err)
	}
	if _, err := time.Parse(time.RFC3339Nano, createdAt); err != nil {
		t.Errorf("created_at is not RFC 3339: %q (%v)", createdAt, err)
	}
}

// TestNSAgentViewOutput pins that the agent projection carries the tenant
// metadata and none of the credential material.
func TestNSAgentViewOutput(t *testing.T) {
	a := &identity.Agent{
		ID:          "agent-tenant-1",
		Name:        "ci-bot",
		Description: "tenant agent",
		APIKey:      "sk-sandswap-agent-plaintext-secret",
		APIKeyHash:  "hash-secret-value",
		CreatedAt:   time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC),
		Namespace:   "acme",
	}
	body, err := json.Marshal(nsAgentViewOf(a))
	if err != nil {
		t.Fatalf("marshal view: %v", err)
	}
	got := string(body)
	for _, secret := range []string{
		"api_key", "api_key_hash", a.APIKey, a.APIKeyHash,
	} {
		if strings.Contains(got, secret) {
			t.Errorf("tenant agent view leaks %q: %s", secret, got)
		}
	}

	var obj map[string]json.RawMessage
	if err := json.Unmarshal(body, &obj); err != nil {
		t.Fatalf("decode view: %v", err)
	}
	want := map[string]bool{
		"agent_id": true, "name": true, "description": true,
		"created_at": true, "namespace": true,
	}
	for key := range obj {
		if !want[key] {
			t.Errorf("unexpected tenant-agent key %q: %s", key, got)
		}
	}
	for key := range want {
		if _, ok := obj[key]; !ok {
			t.Errorf("tenant agent view missing %q: %s", key, got)
		}
	}
}

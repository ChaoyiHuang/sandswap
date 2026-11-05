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

package storage

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	pb "common/proto/stream"

	"gateway/stream"
)

// ErrNoProvisioner is returned when no prov-role instance is connected. The
// HTTP layer turns it into a named 503 ("storage plane unavailable; retry or
// check the prov instances") — never a silent fallback.
var ErrNoProvisioner = fmt.Errorf("no provision instance connected (role=prov)")

// RPCOps executes storage-plane operations on a prov-role sandlot instance
// over the node stream. The gateway holds NO storage access in this mode:
// paths are resolved node-side, blobs stream between the prov instance and
// the registry (never through the gateway), and the only thing crossing the
// stream is the small op vocabulary + its results.
type RPCOps struct {
	srv *stream.Server

	// defaultDeadline bounds a single op on the node when the caller's
	// context has no earlier deadline (template pulls can move GBs).
	defaultDeadline time.Duration

	// rr is the round-robin cursor for spreading ops across connected prov
	// instances (shared storage makes any instance a valid executor).
	rr atomic.Uint64
}

// NewRPC builds the stream-backed implementation.
func NewRPC(srv *stream.Server, defaultDeadline time.Duration) *RPCOps {
	if defaultDeadline <= 0 {
		defaultDeadline = 5 * time.Minute
	}
	return &RPCOps{srv: srv, defaultDeadline: defaultDeadline}
}

func (r *RPCOps) Mode() string { return "rpc" }

// pick returns the connected prov instances, rotated round-robin so the
// caller's first candidate walks the set across successive ops.
func (r *RPCOps) pick() []*stream.NodeConnection {
	conns := r.srv.RoleNodes(stream.RoleProv)
	if len(conns) <= 1 {
		return conns
	}
	// Native modulo of the wrapping counter — big.Int arithmetic here bought
	// three heap allocations per op for the same answer.
	n := r.rr.Add(1)
	rot := int(n % uint64(len(conns)))
	return append(conns[rot:], conns[:rot]...)
}

// roundTrip sends the command to the prov instances in order: a TRANSPORT
// failure (send error, connection death, deadline without response) retries
// the next instance — ops are idempotent, so a retry can never double-apply.
// A node-side BUSINESS error (success=false) returns immediately.
func (r *RPCOps) roundTrip(ctx context.Context, build func(id string, deadline time.Duration) *pb.ProvisionCommand) (*pb.ProvisionResponse, error) {
	conns := r.pick()
	if len(conns) == 0 {
		return nil, ErrNoProvisioner
	}

	dl := r.defaultDeadline
	if d, ok := ctx.Deadline(); ok {
		if rem := time.Until(d); rem < dl {
			dl = rem
		}
	}

	var lastErr error
	for _, nc := range conns {
		cmdCtx, cancel := context.WithTimeout(ctx, dl)
		cmd := build(newCommandID(), dl)
		resp, err := r.sendOne(cmdCtx, nc, cmd)
		cancel()
		if err == nil {
			return resp, nil
		}
		lastErr = err
		// Business errors are final; transport errors fall through to the
		// next instance.
		if !isTransportError(err) {
			return nil, err
		}
	}
	return nil, lastErr
}

// nodeError carries a node-side business failure (success=false) so callers
// can distinguish it from transport failures.
type nodeError struct{ resp *pb.ProvisionResponse }

func (e *nodeError) Error() string {
	code := e.resp.GetErrorCode()
	if code == "" {
		return e.resp.GetError()
	}
	return fmt.Sprintf("%s: %s", code, e.resp.GetError())
}

// NodeErrorCode extracts the structured class from a node business error, ""
// otherwise. Recognizes the rpc implementation's nodeError, and any error
// carrying an ErrorCode() string method (the storagetest double's shape, so a
// handler test exercises the same code mapping as production).
func NodeErrorCode(err error) string {
	if ne, ok := err.(*nodeError); ok {
		return ne.resp.GetErrorCode()
	}
	var coded interface{ ErrorCode() string }
	if errors.As(err, &coded) {
		return coded.ErrorCode()
	}
	return ""
}

func isTransportError(err error) bool {
	_, ok := err.(*nodeError)
	return !ok
}

func (r *RPCOps) sendOne(ctx context.Context, nc *stream.NodeConnection, cmd *pb.ProvisionCommand) (*pb.ProvisionResponse, error) {
	ch, err := nc.SendProvisionCommand(cmd)
	if err != nil {
		return nil, fmt.Errorf("send to %s: %w", nc.NodeID, err)
	}
	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("provision op on %s: %w", nc.NodeID, ctx.Err())
	case resp := <-ch:
		if resp == nil {
			return nil, fmt.Errorf("provision op on %s: connection closed", nc.NodeID)
		}
		if !resp.GetSuccess() {
			return nil, &nodeError{resp: resp}
		}
		return resp, nil
	}
}

func newCommandID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("prov-%d", time.Now().UnixNano())
	}
	return "prov-" + hex.EncodeToString(b[:])
}

// ── Ops implementation ─────────────────────────────────────────────────────

func (r *RPCOps) EnsureVolume(ctx context.Context, sandfsID, mode, templateRef string, epochs ...string) (*EnsureResult, error) {
	volumeEpoch := ""
	if len(epochs) > 0 {
		volumeEpoch = epochs[0]
	}
	resp, err := r.roundTrip(ctx, func(id string, deadline time.Duration) *pb.ProvisionCommand {
		return &pb.ProvisionCommand{
			CommandId:  id,
			DeadlineMs: uint64(deadline.Milliseconds()),
			Action: &pb.ProvisionCommand_EnsureVolume{
				EnsureVolume: &pb.EnsureVolume{
					SandfsId:    sandfsID,
					Mode:        mode,
					TemplateRef: templateRef,
					VolumeEpoch: volumeEpoch,
				},
			},
		}
	})
	if err != nil {
		return nil, err
	}
	return &EnsureResult{
		RootfsPath:  resp.GetRootfsPath(),
		MinVCPUs:    resp.GetMinVcpus(),
		MinMemoryMB: resp.GetMinMemoryMb(),
		MinOK:       resp.GetMinVcpus() > 0 || resp.GetMinMemoryMb() > 0,
		Pulled:      resp.GetPulled(),
	}, nil
}

func (r *RPCOps) DeleteVolume(sandfsID string) error {
	_, err := r.roundTrip(context.Background(), func(id string, deadline time.Duration) *pb.ProvisionCommand {
		return &pb.ProvisionCommand{
			CommandId:  id,
			DeadlineMs: uint64(deadline.Milliseconds()),
			Action: &pb.ProvisionCommand_DeleteVolume{
				DeleteVolume: &pb.DeleteVolume{SandfsId: sandfsID},
			},
		}
	})
	return err
}

func (r *RPCOps) VerifyVolume(ctx context.Context, sandfsID, rootfsPath string) error {
	_, err := r.roundTrip(ctx, func(id string, deadline time.Duration) *pb.ProvisionCommand {
		return &pb.ProvisionCommand{
			CommandId:  id,
			DeadlineMs: uint64(deadline.Milliseconds()),
			Action: &pb.ProvisionCommand_VerifyVolume{
				VerifyVolume: &pb.VerifyVolume{SandfsId: sandfsID, RootfsPath: rootfsPath},
			},
		}
	})
	return err
}

func (r *RPCOps) PullTemplate(ctx context.Context, templateRef, mode string) (*PullResult, error) {
	resp, err := r.roundTrip(ctx, func(id string, deadline time.Duration) *pb.ProvisionCommand {
		return &pb.ProvisionCommand{
			CommandId:  id,
			DeadlineMs: uint64(deadline.Milliseconds()),
			Action: &pb.ProvisionCommand_PullTemplate{
				PullTemplate: &pb.PullTemplate{TemplateRef: templateRef, Mode: mode},
			},
		}
	})
	if err != nil {
		return nil, err
	}
	return &PullResult{Name: resp.GetName(), Version: resp.GetVersion()}, nil
}

func (r *RPCOps) PushTemplate(ctx context.Context, templateRef, mode string) (*PushResult, error) {
	resp, err := r.roundTrip(ctx, func(id string, deadline time.Duration) *pb.ProvisionCommand {
		return &pb.ProvisionCommand{
			CommandId:  id,
			DeadlineMs: uint64(deadline.Milliseconds()),
			Action: &pb.ProvisionCommand_PushTemplate{
				PushTemplate: &pb.PushTemplate{TemplateRef: templateRef, Mode: mode},
			},
		}
	})
	if err != nil {
		return nil, err
	}
	return &PushResult{
		TemplateRef: templateRef,
		Digest:      resp.GetDigest(),
		Layers:      resp.GetPushLayers(),
		Size:        resp.GetSizeBytes(),
		PushTimeMs:  resp.GetPushTimeMs(),
	}, nil
}

func (r *RPCOps) SaveAsTemplate(sandfsID string, req SaveAsRequest) (*SaveResult, error) {
	resp, err := r.roundTrip(context.Background(), func(id string, deadline time.Duration) *pb.ProvisionCommand {
		return &pb.ProvisionCommand{
			CommandId:  id,
			DeadlineMs: uint64(deadline.Milliseconds()),
			Action: &pb.ProvisionCommand_SaveAsTemplate{
				SaveAsTemplate: &pb.SaveAsTemplate{
					SandfsId:    sandfsID,
					TemplateRef: req.TemplateRef,
					Description: req.Description,
					Vcpus:       req.VCPUs,
					MemoryMb:    req.MemoryMB,
				},
			},
		}
	})
	if err != nil {
		return nil, err
	}
	return &SaveResult{TemplateRef: req.TemplateRef, Path: resp.GetPath(), SizeKB: resp.GetSizeKb()}, nil
}

func (r *RPCOps) ListTemplates() []TemplateInfo {
	resp, err := r.roundTrip(context.Background(), func(id string, deadline time.Duration) *pb.ProvisionCommand {
		return &pb.ProvisionCommand{
			CommandId:  id,
			DeadlineMs: uint64(deadline.Milliseconds()),
			Action:     &pb.ProvisionCommand_ListTemplates{ListTemplates: &pb.ListTemplates{}},
		}
	})
	if err != nil {
		// The list endpoint's historical behavior on an unavailable storage
		// plane is an empty array; the /stats endpoint carries the availability signal.
		return []TemplateInfo{}
	}
	out := make([]TemplateInfo, 0, len(resp.GetTemplates()))
	for _, t := range resp.GetTemplates() {
		out = append(out, TemplateInfo{
			Name:        t.GetName(),
			Version:     t.GetVersion(),
			Description: t.GetDescription(),
			Mode:        t.GetMode(),
			MinVCPUs:    t.GetMinVcpus(),
			MinMemoryMB: t.GetMinMemoryMb(),
		})
	}
	return out
}

func (r *RPCOps) DetectTemplateMode(templateRef string) string {
	resp, err := r.roundTrip(context.Background(), func(id string, deadline time.Duration) *pb.ProvisionCommand {
		return &pb.ProvisionCommand{
			CommandId:  id,
			DeadlineMs: uint64(deadline.Milliseconds()),
			Action:     &pb.ProvisionCommand_StatTemplate{StatTemplate: &pb.StatTemplate{TemplateRef: templateRef}},
		}
	})
	if err != nil {
		return ""
	}
	for _, m := range resp.GetModes() {
		if m == "overlay" {
			return "overlay"
		}
	}
	for _, m := range resp.GetModes() {
		if m == "flat" {
			return "flat"
		}
	}
	return ""
}

func (r *RPCOps) SwapTemplate(ctx context.Context, sandfsID, templateRef, homePolicy string) (*EnsureResult, error) {
	resp, err := r.roundTrip(ctx, func(id string, deadline time.Duration) *pb.ProvisionCommand {
		return &pb.ProvisionCommand{
			CommandId:  id,
			DeadlineMs: uint64(deadline.Milliseconds()),
			Action: &pb.ProvisionCommand_SwapTemplate{
				SwapTemplate: &pb.SwapTemplate{
					SandfsId:    sandfsID,
					TemplateRef: templateRef,
					HomePolicy:  homePolicy,
				},
			},
		}
	})
	if err != nil {
		return nil, err
	}
	return &EnsureResult{
		RootfsPath:  resp.GetRootfsPath(),
		MinVCPUs:    resp.GetMinVcpus(),
		MinMemoryMB: resp.GetMinMemoryMb(),
		MinOK:       resp.GetMinVcpus() > 0 || resp.GetMinMemoryMb() > 0,
		Pulled:      resp.GetPulled(),
	}, nil
}

func (r *RPCOps) DeleteTemplate(ctx context.Context, templateRef, mode string, force bool) error {
	_, err := r.roundTrip(ctx, func(id string, deadline time.Duration) *pb.ProvisionCommand {
		return &pb.ProvisionCommand{
			CommandId:  id,
			DeadlineMs: uint64(deadline.Milliseconds()),
			Action: &pb.ProvisionCommand_DeleteTemplate{
				DeleteTemplate: &pb.DeleteTemplate{
					TemplateRef: templateRef,
					Mode:        mode,
					Force:       force,
				},
			},
		}
	})
	if ne, ok := err.(*nodeError); ok && ne.resp.GetErrorCode() == "TEMPLATE_IN_USE" {
		return &TemplateInUseError{
			Count:  int(ne.resp.GetInUseCount()),
			Sample: ne.resp.GetInUseSample(),
		}
	}
	return err
}

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

package core

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	pb "common/proto/stream"
	"sandlot/provision/template"
	"sandlot/provision/volume"
)

// ProvisionService executes prov-role commands (sandfs + template
// lifecycle on shared storage) inside a prov-role sandlot instance. It is the
// node-side mirror of the gateway's storage.Ops RPC client: bounded
// concurrency (provisioning moves GBs — an unbounded burst would starve the
// host), per-op deadlines from the wire (0 = configured default), and
// structured error codes the gateway maps without substring matching.
type ProvisionService struct {
	volumes         *volume.Provisioner
	sem             chan struct{}
	defaultDeadline time.Duration
	logger          *log.Logger
}

// NewProvisionService builds the executor. maxConcurrent <= 0 means 2 (the
// config default); defaultDeadline <= 0 means 5 minutes.
func NewProvisionService(volumes *volume.Provisioner, maxConcurrent int, defaultDeadline time.Duration, logger *log.Logger) *ProvisionService {
	if maxConcurrent <= 0 {
		maxConcurrent = 2
	}
	if defaultDeadline <= 0 {
		defaultDeadline = 5 * time.Minute
	}
	if logger == nil {
		logger = log.Default()
	}
	return &ProvisionService{
		volumes:         volumes,
		sem:             make(chan struct{}, maxConcurrent),
		defaultDeadline: defaultDeadline,
		logger:          logger,
	}
}

// Handle executes one ProvisionCommand and returns the response. Concurrency
// is bounded: a command waits on the semaphore until either a slot frees or
// its deadline expires (the response names which).
func (s *ProvisionService) Handle(cmd *pb.ProvisionCommand) *pb.ProvisionResponse {
	started := time.Now()
	resp := s.handle(cmd)
	resp.CommandId = cmd.GetCommandId()
	resp.DurationNs = uint64(time.Since(started))
	return resp
}

func (s *ProvisionService) handle(cmd *pb.ProvisionCommand) *pb.ProvisionResponse {
	deadline := s.defaultDeadline
	if d := cmd.GetDeadlineMs(); d > 0 {
		deadline = time.Duration(d) * time.Millisecond
	}
	ctx, cancel := context.WithTimeout(context.Background(), deadline)
	defer cancel()

	select {
	case s.sem <- struct{}{}:
		defer func() { <-s.sem }()
	case <-ctx.Done():
		return errResp(cmd, fmt.Errorf("provision concurrency budget exhausted (deadline %v)", deadline), "")
	}

	switch action := cmd.GetAction().(type) {
	case *pb.ProvisionCommand_EnsureVolume:
		return s.ensureVolume(ctx, action.EnsureVolume)
	case *pb.ProvisionCommand_DeleteVolume:
		return s.deleteVolume(ctx, action.DeleteVolume)
	case *pb.ProvisionCommand_PullTemplate:
		return s.pullTemplate(ctx, action.PullTemplate)
	case *pb.ProvisionCommand_PushTemplate:
		return s.pushTemplate(ctx, action.PushTemplate)
	case *pb.ProvisionCommand_SaveAsTemplate:
		return s.saveAsTemplate(ctx, action.SaveAsTemplate)
	case *pb.ProvisionCommand_ListTemplates:
		return s.listTemplates()
	case *pb.ProvisionCommand_StatTemplate:
		return s.statTemplate(action.StatTemplate)
	case *pb.ProvisionCommand_SwapTemplate:
		return s.swapTemplate(ctx, action.SwapTemplate)
	case *pb.ProvisionCommand_DeleteTemplate:
		return s.deleteTemplate(ctx, action.DeleteTemplate)
	case *pb.ProvisionCommand_VerifyVolume:
		return s.verifyVolume(action.VerifyVolume)
	default:
		return errResp(cmd, fmt.Errorf("unknown provision action %T", action), "INVALID_ARGUMENT")
	}
}

func (s *ProvisionService) ensureVolume(ctx context.Context, a *pb.EnsureVolume) *pb.ProvisionResponse {
	res, err := s.volumes.EnsureVolume(ctx, a.GetSandfsId(), a.GetMode(), a.GetTemplateRef(), a.GetVolumeEpoch())
	if err != nil {
		return errResp(&pb.ProvisionCommand{}, err, classifyErr(err))
	}
	return &pb.ProvisionResponse{
		Success:     true,
		RootfsPath:  res.RootfsPath,
		MinVcpus:    res.MinVCPUs,
		MinMemoryMb: res.MinMemoryMB,
		Pulled:      res.Pulled,
	}
}

func (s *ProvisionService) deleteVolume(ctx context.Context, a *pb.DeleteVolume) *pb.ProvisionResponse {
	if err := s.volumes.DeleteVolume(ctx, a.GetSandfsId()); err != nil {
		return errResp(&pb.ProvisionCommand{}, err, classifyErr(err))
	}
	return &pb.ProvisionResponse{Success: true}
}

func (s *ProvisionService) pullTemplate(ctx context.Context, a *pb.PullTemplate) *pb.ProvisionResponse {
	if err := volume.ValidateTemplateRef(a.GetTemplateRef()); err != nil {
		return errResp(&pb.ProvisionCommand{}, err, "INVALID_ARGUMENT")
	}
	mode := a.GetMode()
	if mode == "" {
		mode = "overlay"
	}
	tmpl, err := s.volumes.Templates.PullTemplate(ctx, a.GetTemplateRef(), mode)
	if err != nil {
		return errResp(&pb.ProvisionCommand{}, err, classifyErr(err))
	}
	name, version := "", ""
	if tmpl != nil {
		name, version = tmpl.Name, tmpl.Version
	}
	return &pb.ProvisionResponse{Success: true, Name: name, Version: version}
}

func (s *ProvisionService) pushTemplate(ctx context.Context, a *pb.PushTemplate) *pb.ProvisionResponse {
	if err := volume.ValidateTemplateRef(a.GetTemplateRef()); err != nil {
		return errResp(&pb.ProvisionCommand{}, err, "INVALID_ARGUMENT")
	}
	mode := a.GetMode()
	if mode == "" {
		mode = s.detectMode(a.GetTemplateRef())
		if mode == "" {
			return errResp(&pb.ProvisionCommand{}, volume.ErrTemplateNotFound,
				"TEMPLATE_NOT_FOUND")
		}
	}
	resp, err := s.volumes.Templates.PushTemplate(ctx, a.GetTemplateRef(), mode)
	if err != nil {
		return errResp(&pb.ProvisionCommand{}, err, classifyErr(err))
	}
	return &pb.ProvisionResponse{
		Success:    true,
		Digest:     resp.Digest,
		SizeBytes:  resp.Size,
		PushTimeMs: resp.PushTimeMs,
		PushLayers: resp.Layers,
	}
}

// saveAsTemplate passes the wire ctx through: the copy moves GBs and must be
// bounded by the command's deadline, not run on past it holding a semaphore slot.
func (s *ProvisionService) saveAsTemplate(ctx context.Context, a *pb.SaveAsTemplate) *pb.ProvisionResponse {
	if err := volume.ValidateSandfsID(a.GetSandfsId()); err != nil {
		return errResp(&pb.ProvisionCommand{}, err, "INVALID_ARGUMENT")
	}
	if err := volume.ValidateTemplateRef(a.GetTemplateRef()); err != nil {
		return errResp(&pb.ProvisionCommand{}, err, "INVALID_ARGUMENT")
	}
	resp, err := s.volumes.Templates.SaveAsTemplate(ctx, a.GetSandfsId(), template.SaveAsTemplateRequest{
		TemplateRef: a.GetTemplateRef(),
		Description: a.GetDescription(),
		VCPUs:       a.GetVcpus(),
		MemoryMB:    a.GetMemoryMb(),
	})
	if err != nil {
		return errResp(&pb.ProvisionCommand{}, err, classifyErr(err))
	}
	return &pb.ProvisionResponse{Success: true, Path: resp.Path, SizeKb: resp.SizeKB}
}

func (s *ProvisionService) listTemplates() *pb.ProvisionResponse {
	refs := s.volumes.Templates.ListLocalTemplates()
	out := make([]*pb.TemplateSummary, 0, len(refs)*2)
	for _, ref := range refs {
		for _, mode := range []string{"overlay", "flat"} {
			tmpl, err := s.volumes.Templates.GetTemplate(ref, mode)
			if err != nil {
				continue
			}
			entry, lerr := s.volumes.Templates.LoadRefEntry(ref, mode)
			sum := &pb.TemplateSummary{
				Ref:         ref,
				Mode:        mode,
				Description: tmpl.Description,
				Name:        tmpl.Name,
				Version:     tmpl.Version,
			}
			if lerr == nil {
				sum.MinVcpus = entry.MinVCPUs
				sum.MinMemoryMb = entry.MinMemoryMB
			}
			out = append(out, sum)
		}
	}
	return &pb.ProvisionResponse{Success: true, Templates: out}
}

func (s *ProvisionService) statTemplate(a *pb.StatTemplate) *pb.ProvisionResponse {
	if err := volume.ValidateTemplateRef(a.GetTemplateRef()); err != nil {
		return errResp(&pb.ProvisionCommand{}, err, "INVALID_ARGUMENT")
	}
	resp := &pb.ProvisionResponse{Success: true}
	found := false
	for _, mode := range []string{"overlay", "flat"} {
		if _, err := s.volumes.Templates.LoadRefEntry(a.GetTemplateRef(), mode); err == nil {
			resp.Modes = append(resp.GetModes(), mode)
			found = true
		}
	}
	if !found {
		return errResp(&pb.ProvisionCommand{},
			fmt.Errorf("%w: %q has neither an overlay nor a flat ref", volume.ErrTemplateNotFound, a.GetTemplateRef()),
			"TEMPLATE_NOT_FOUND")
	}
	resp.MinVcpus, resp.MinMemoryMb, _ = s.volumes.StatTemplate(a.GetTemplateRef())
	return resp
}

func (s *ProvisionService) detectMode(ref string) string {
	if _, err := s.volumes.Templates.LoadRefEntry(ref, "overlay"); err == nil {
		return "overlay"
	}
	if _, err := s.volumes.Templates.LoadRefEntry(ref, "flat"); err == nil {
		return "flat"
	}
	return ""
}

func (s *ProvisionService) swapTemplate(ctx context.Context, a *pb.SwapTemplate) *pb.ProvisionResponse {
	res, err := s.volumes.SwapTemplate(ctx, a.GetSandfsId(), a.GetTemplateRef(), a.GetHomePolicy())
	if err != nil {
		return errResp(&pb.ProvisionCommand{}, err, classifyErr(err))
	}
	return &pb.ProvisionResponse{
		Success:     true,
		RootfsPath:  res.RootfsPath,
		MinVcpus:    res.MinVCPUs,
		MinMemoryMb: res.MinMemoryMB,
		Pulled:      res.Pulled,
	}
}

// verifyVolume is the READ-ONLY identity check behind the gateway's
// rootfs-path repoint endpoint: prove the caller-supplied directory is this
// sandfs's volume (contained under the volumes root + exact .sandfs-id stamp)
// before the record may point at it. Nothing is created or modified.
func (s *ProvisionService) verifyVolume(a *pb.VerifyVolume) *pb.ProvisionResponse {
	if err := s.volumes.VerifyVolumeIdentity(a.GetSandfsId(), a.GetRootfsPath()); err != nil {
		return errResp(&pb.ProvisionCommand{}, err, classifyErr(err))
	}
	return &pb.ProvisionResponse{Success: true}
}

func (s *ProvisionService) deleteTemplate(ctx context.Context, a *pb.DeleteTemplate) *pb.ProvisionResponse {
	err := s.volumes.DeleteTemplate(ctx, a.GetTemplateRef(), a.GetMode(), a.GetForce())
	if err != nil {
		var inUse *volume.TemplateInUseError
		if errors.As(err, &inUse) {
			return &pb.ProvisionResponse{
				Success:     false,
				Error:       err.Error(),
				ErrorCode:   "TEMPLATE_IN_USE",
				InUseCount:  uint32(inUse.Count),
				InUseSample: inUse.Sample,
			}
		}
		return errResp(&pb.ProvisionCommand{}, err, classifyErr(err))
	}
	return &pb.ProvisionResponse{Success: true}
}

// errResp builds a failure response. code is the structured class; the human
// text always rides along for the operator.
func errResp(cmd *pb.ProvisionCommand, err error, code string) *pb.ProvisionResponse {
	return &pb.ProvisionResponse{
		CommandId: cmd.GetCommandId(),
		Success:   false,
		Error:     err.Error(),
		ErrorCode: code,
	}
}

// classifyErr maps sentinel error classes to wire error_code values.
func classifyErr(err error) string {
	switch {
	case errors.Is(err, volume.ErrInvalidArgument):
		return "INVALID_ARGUMENT"
	case errors.Is(err, volume.ErrTemplateNotFound):
		return "TEMPLATE_NOT_FOUND"
	case errors.Is(err, volume.ErrTemplateExists):
		return "TEMPLATE_EXISTS"
	case errors.Is(err, volume.ErrTemplateIdentityMismatch):
		return "TEMPLATE_IDENTITY_MISMATCH"
	case errors.Is(err, volume.ErrVolumeIdentityMismatch):
		// named class on the wire (was: empty code + raw text that
		// embedded the seed-derived path). The gateway maps it to a 409.
		return "VOLUME_IDENTITY_MISMATCH"
	case errors.Is(err, volume.ErrRotationStaged):
		return "ROTATION_STAGED"
	case errors.Is(err, volume.ErrQuotaStamp):
		return "QUOTA_STAMP_FAILED"
	default:
		return ""
	}
}

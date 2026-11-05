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

// Package volume is the storage-plane executor for sandfs volume lifecycle:
// materializing a volume directory from a template (flat copy, OCI blob
// stream-extract, or the overlay workspace/home layout) and deleting it.
// It is consumed in-process by a prov-role sandlot instance and (during the
// storage-plane transition) by the gateway's local mode. Everything here is
// IDEMPOTENT: EnsureVolume self-heals partial runs through a .provisioning
// marker, DeleteVolume treats ENOENT as success — a retry on another node is
// always safe.
package volume

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"common/util"
	"sandlot/provision/copyfs"
	"sandlot/provision/template"
	"sandlot/provision/volname"
)

// Provisioner executes volume lifecycle operations under one volumes root.
// volumeLogRef is the log-safe reference to a volume directory. The on-disk
// name is seed-derived and addressable on the shared store, so provision logs
// must not print it (a tenant-triggerable line would hand out the name of the
// directory it is attached to). The short hash keeps lines correlatable
// without leaking the name.
func volumeLogRef(path string) string {
	sum := sha256.Sum256([]byte(path))
	return "vol-" + hex.EncodeToString(sum[:8])
}

type Provisioner struct {
	// VolRoot is the shared-storage volumes directory (identical absolute
	// path on every node — the storage contract's requirement 1).
	VolRoot string
	// Templates resolves refs, auto-pulls, and materializes content.
	Templates *template.Manager
	// QuotaStampCmd is the storage plane's quota hook (provision.
	// quota_stamp_cmd; empty = stamping disabled). Executed once per freshly
	// seeded volume, BEFORE the identity stamp is written (so a valid signed
	// stamp proves content + quota finalized) and before the partial-run
	// marker comes off — see quota.go for the contract. Restart-required
	// config (not part of the hot-reloadable seed keys).
	QuotaStampCmd string
	// Names maps a sandfs ID to its on-disk directory name (see package
	// volname). nil = the seed was not configured, which is only reachable in
	// tests: the prov role refuses to start without one.
	Names *volname.Map

	// testHookEnsureVolumeSeeded, when non-nil, runs on the calling goroutine
	// after the volume content is seeded and before the volume is finalized
	// (identity stamp + marker removal). Test seam: it is how the mid-create
	// seed-rotation interleaving is driven deterministically — see
	// TestEnsureVolumeRefusesWhenGenerationMovesMidCreate.
	testHookEnsureVolumeSeeded func()

	// testHookReplyRootfsPath, when non-nil, rewrites the path a completed
	// EnsureVolume/SwapTemplate replies with. Test seam for the reply
	// containment guard (checkReplyPath): the path a real run derives is always
	// inside VolRoot, so the only way to exercise the refusal deterministically
	// is to hand the op a (simulated) subverted derivation.
	testHookReplyRootfsPath func(string) string
}

// New creates a Provisioner. seed is the deployment's volume-name seed (see
// volname); an empty seed leaves the namer nil (tests, scratch builds).
func New(volRoot string, mgr *template.Manager, seed []byte) (*Provisioner, error) {
	p := &Provisioner{VolRoot: volRoot, Templates: mgr}
	if len(seed) > 0 {
		m, err := volname.NewMap(seed)
		if err != nil {
			return nil, err
		}
		p.Names = m
	}
	return p, nil
}

// NewWithNamer builds a Provisioner around an existing seed map — the form
// main.go uses so the template manager and the provisioner resolve volume
// directories through ONE namer (and a config reload updates both).
func NewWithNamer(volRoot string, mgr *template.Manager, namer *volname.Map) (*Provisioner, error) {
	if namer == nil {
		return nil, fmt.Errorf("volume namer is required for the prov role")
	}
	return &Provisioner{VolRoot: volRoot, Templates: mgr, Names: namer}, nil
}

// hasProvisioningMarker reports whether the directory carries the partial-run
// marker (a wiped-and-redone tree, which therefore has no valid stamp yet).
//
// The marker lives in an agent-writable volume root in flat mode, so only a
// REGULAR file counts: os.Stat used to follow a tenant-planted symlink (for
// example `.provisioning -> /etc/shadow`) into the host filesystem — a host
// path-existence oracle and a way to make the "garbage cleanup" exemption fire
// without a real marker. A symlink, FIFO or directory is tenant debris, never a
// marker.
func hasProvisioningMarker(volPath string) bool {
	fi, err := os.Lstat(filepath.Join(volPath, provisioningMarker))
	return err == nil && fi.Mode().IsRegular()
}

// volumeName returns the directory name for id under the deployment seed. The
// fallback (ID == name) exists ONLY for Provisioners built without a namer —
// i.e. tests that predate the seed; every production path sets one.
func (p *Provisioner) volumeName(id string) string {
	if p.Names == nil {
		return id
	}
	return p.Names.Current(id)
}

// resolveVolPath returns the directory of an EXISTING volume: the current
// generation's name, or — while a rotation is staged — the next generation's,
// so operations keep working for volumes the rotation has not reached yet.
// Existence is the discriminator, which makes the choice self-healing: a
// rename interrupted between the filesystem and the record converges on the
// next attempt because whichever name exists is the one returned.
func (p *Provisioner) resolveVolPath(id string) (string, error) {
	if p.Names == nil {
		return filepath.Join(p.VolRoot, id), nil
	}
	cur := filepath.Join(p.VolRoot, p.Names.Current(id))
	if _, err := os.Stat(cur); err == nil {
		return cur, nil
	}
	if p.Names.HasNext() {
		next := filepath.Join(p.VolRoot, p.Names.Next(id))
		if _, err := os.Stat(next); err == nil {
			return next, nil
		}
	}
	return "", fmt.Errorf("%w: volume for %s not found under %s", ErrInvalidArgument, id, p.VolRoot)
}

// checkReplyPath refuses a rootfs path outside this instance's volumes root.
// The path a run derives always lands under VolRoot, so a failure here means
// the derivation itself was subverted — and the gateway stores whatever this
// op answers, then feeds it to the VMM's allowed_dirs filter on the next
// mount. Defense in depth behind the gateway's own ingress check
// (registry.ValidateVolumePath): neither side of the stream trusts the
// other's strings.
func checkReplyPath(volRoot, volPath string) error {
	root := filepath.Clean(volRoot)
	clean := filepath.Clean(volPath)
	if clean == root || !strings.HasPrefix(clean, root+string(filepath.Separator)) {
		return fmt.Errorf("%w: refusing to reply with a volume path outside %s", ErrInvalidArgument, root)
	}
	return nil
}

// replyRootfsPath is the single point every EnsureResult.RootfsPath passes
// through: the test seam (if armed) then the containment guard.
func (p *Provisioner) replyRootfsPath(volPath string) (string, error) {
	if p.testHookReplyRootfsPath != nil {
		volPath = p.testHookReplyRootfsPath(volPath)
	}
	if err := checkReplyPath(p.VolRoot, volPath); err != nil {
		return "", err
	}
	return volPath, nil
}

// EnsureResult carries everything a sandfs creation needs from the storage
// plane in ONE round trip: the volume path, the template's declared minimum
// resources (the create-time sizing input), and whether this run auto-pulled
// the ref from the OCI registry (the gateway's create response surfaces that
// as pull_status "pulled" vs "cached").
type EnsureResult struct {
	RootfsPath  string
	MinVCPUs    uint32
	MinMemoryMB uint64
	MinOK       bool
	Pulled      bool
}

// provisioningMarker is written into a volume directory at the start of an
// EnsureVolume run and removed on success. A later run that finds it marks a
// PARTIAL creation (process died mid-seed) — the stale tree is wiped and
// redone instead of being mistaken for a complete volume.
const provisioningMarker = ".provisioning"

// validSandfsID is the node-side defense against caller-supplied path
// components: a sandfs id is one path element of letters, digits, dots,
// underscores and hyphens. The charset alone excludes separators and ".."
// traversal; the length bound keeps joined paths well under PATH_MAX.
var validSandfsID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// Sentinel error classes the RPC executor maps to structured error_code
// values (the gateway never substring-matches node errors).
var (
	// ErrInvalidArgument: malformed id/ref rejected by node-side validation.
	ErrInvalidArgument = fmt.Errorf("invalid argument")
	// ErrRotationStaged refuses volume creation while a seed rotation is
	// staged: the window freezes creates so that no volume is left in a
	// generation the rotation list does not cover.
	ErrRotationStaged = fmt.Errorf("volume seed rotation staged")
	// ErrTemplateNotFound: ref missing locally with no auto-pull available.
	ErrTemplateNotFound = fmt.Errorf("template not found")
	// ErrTemplateExists: the ref file already exists. Ref files are
	// immutable (an overwrite re-points every volume mounting it, and the
	// ref->filename encoding is not injective, so it can also replace a
	// DIFFERENT tenant's ref).
	ErrTemplateExists = template.ErrRefExists
	// ErrTemplateIdentityMismatch: the ref file's entry names a different
	// name:version (the filename-collision/tamper signal).
	ErrTemplateIdentityMismatch = template.ErrRefIdentityMismatch
)

// TemplateInUseError is DeleteTemplate's refusal: overlay volumes still name
// the ref in their .template marker. Carries the count and a bounded id
// sample for the wire (the gateway's HTTP 409 payload).
type TemplateInUseError struct {
	Count  int
	Sample []string
}

func (e *TemplateInUseError) Error() string {
	return fmt.Sprintf("template in use by %d overlay sandfs (e.g. %v)", e.Count, e.Sample)
}

// HomePolicy values for SwapTemplate.
const (
	HomeKeep    = "keep"
	HomeArchive = "archive"
	HomeReset   = "reset"
)

// ValidateSandfsID rejects anything that is not a single safe path element.
// The storage plane NEVER trusts the gateway's strings — the same discipline
// as the warden's hostile-frame handling.
func ValidateSandfsID(id string) error {
	if !validSandfsID.MatchString(id) || strings.Contains(id, "..") {
		return fmt.Errorf("invalid sandfs_id %q: must be a single path element of [A-Za-z0-9._-], max 128 chars", id)
	}
	return nil
}

// ValidateTemplateRef applies the same element-level check to template refs.
func ValidateTemplateRef(ref string) error {
	if ref == "" || len(ref) > 256 || strings.ContainsAny(ref, "/\\\x00") || strings.Contains(ref, "..") {
		return fmt.Errorf("invalid template_ref %q", ref)
	}
	return nil
}

// requireStampOwnership is the destructive-op half of the identity-stamp
// guard (stamp.go): DeleteVolume and SwapTemplate must never touch a
// directory they cannot PROVE belongs to the named sandfs. The name is
// derived, so a directory that landed at the wrong derived name (a
// hand-rename, a half-applied rotation, a restored backup) would otherwise
// be destroyed or rewritten as a silent cross-tenant hit — the exact
// accident the stamp exists to catch. A directory carrying the partial-run
// marker is exempt: it is garbage by definition, and cleaning it is the
// self-heal path.
func (p *Provisioner) requireStampOwnership(volPath, sandfsID, op, expectedMode string) error {
	// Read the stamp FIRST. A `.provisioning` marker only explains a missing
	// stamp (a materialization in progress); it must not shadow a stamp that
	// is present — the marker lives in the same agent-writable volume root,
	// so letting it short-circuit the check would let a tenant opt out of the
	// signature/mode verification with one `touch`.
	st, ok, err := readVolumeStamp(volPath)
	if err != nil {
		// Both sentinels ride the error: ErrVolumeIdentityMismatch keeps every
		// refusal classified, and ErrVolumeStampUnreadable lets a destructive
		// cleanup converge by quarantine instead of refusing forever.
		return fmt.Errorf("%w: %s: cannot read the identity stamp under %s: %w — inspect the seed generations before touching it", ErrVolumeIdentityMismatch, op, volPath, err)
	}
	if !ok {
		if hasProvisioningMarker(volPath) {
			return nil
		}
		return fmt.Errorf("%w: %s: %s carries no %s stamp — run the storage-plane migration to stamp existing volumes", ErrVolumeIdentityMismatch, op, volPath, VolumeIdentityFile)
	}
	if st.SandfsID != sandfsID {
		return fmt.Errorf("%w: %s: %s is stamped for %s — do NOT touch it; inspect the seed generations", ErrVolumeIdentityMismatch, op, volPath, st.SandfsID)
	}
	// The signature is the proof: the tenant can replace this file in flat
	// mode, so a stamp that is unsigned or does not verify against a live
	// generation seed is never trusted for a destructive op.
	if !p.stampSignatureOK(volPath, st) {
		return fmt.Errorf("%w: %s: %s carries a stamp that is unsigned or whose signature does not verify (tampered or copied from another volume) — do NOT touch it; inspect the directory", ErrVolumeIdentityMismatch, op, volPath)
	}
	// Layout binding: an overlay-only operation must not be steered at a flat
	// (agent-writable) volume — the signed stamp records the mode the prov
	// instance created it with.
	if expectedMode != "" && st.Mode != expectedMode {
		return fmt.Errorf("%w: %s: %s is stamped mode %q, not %q — refusing %s on a volume of the wrong layout", ErrVolumeIdentityMismatch, op, volPath, st.Mode, expectedMode, op)
	}
	return nil
}

// stampSeeds is every generation seed a stamp may legitimately be signed
// with: the current one and, during a rotation window, the staged one.
func (p *Provisioner) stampSeeds() [][]byte {
	if p.Names == nil {
		return nil
	}
	seeds := [][]byte{p.Names.CurrentSeed()}
	if next := p.Names.NextSeed(); len(next) > 0 {
		seeds = append(seeds, next)
	}
	return seeds
}

func (p *Provisioner) stampSignatureOK(volPath string, st volumeStamp) bool {
	return verifyVolumeStamp(volPath, st, p.stampSeeds())
}

// VerifyVolumeIdentity is the READ-ONLY identity check behind the gateway's
// rootfs-path repoint endpoint: the volume-seed rotation MOVES volume
// directories and the control plane must then be told where they landed.
// Without this proof the endpoint would let a caller point a sandfs record at
// any directory under the volumes root, and the exec node would mount it. The
// check is the same stamp rule the destructive ops use
// (requireStampOwnership), with one deliberate difference: a path that is not
// a real directory (a symlink planted at the derived name) is refused outright.
// The partial-run marker is not an authority either way: alongside a valid
// signed stamp it is tenant debris (the stamp is the completion proof, written
// after the quota hook), while a marker with NO stamp is mid-provisioning and
// must never be adopted. Nothing here creates or modifies anything (contrast
// EnsureVolume, which materializes a missing path — a repoint verification must
// not have that side effect).
func (p *Provisioner) VerifyVolumeIdentity(sandfsID, volPath string) error {
	if err := ValidateSandfsID(sandfsID); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidArgument, err)
	}
	// Same containment class as the reply guard: a path outside the volumes
	// root is a malformed argument, never an identity question.
	if err := checkReplyPath(p.VolRoot, volPath); err != nil {
		return err
	}
	clean := filepath.Clean(volPath)
	info, err := os.Lstat(clean)
	if err != nil {
		return fmt.Errorf("%w: cannot stat %s (%v) — the directory must exist before the record can be pointed at it", ErrVolumeIdentityMismatch, clean, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("%w: %s is not a real directory (mode %s) — a volume is never a symlink", ErrVolumeIdentityMismatch, clean, info.Mode())
	}
	st, ok, err := readVolumeStamp(clean)
	if err != nil {
		return fmt.Errorf("%w: cannot read the identity stamp under %s (%v) — inspect the seed generations", ErrVolumeIdentityMismatch, clean, err)
	}
	if !ok {
		if hasProvisioningMarker(clean) {
			return fmt.Errorf("%w: %s is mid-provisioning (partial run) — not a complete volume", ErrVolumeIdentityMismatch, clean)
		}
		return fmt.Errorf("%w: %s carries no %s stamp — it is not a provisioned volume", ErrVolumeIdentityMismatch, clean, VolumeIdentityFile)
	}
	if st.SandfsID != sandfsID {
		return fmt.Errorf("%w: %s is stamped for %s", ErrVolumeIdentityMismatch, clean, st.SandfsID)
	}
	// This endpoint's whole security argument is that the stamp proves the
	// directory belongs to the sandfs. For a flat volume the tenant can
	// replace the file, so an UNSIGNED (legacy) stamp proves nothing here and
	// is refused: run the rotation migration to sign existing volumes. A
	// signed stamp must verify against a live generation seed.
	if !p.stampSignatureOK(clean, st) {
		return fmt.Errorf("%w: %s carries a stamp that is unsigned or whose signature does not verify (tampered, or copied from another volume)", ErrVolumeIdentityMismatch, clean)
	}
	return nil
}

// EnsureVolume idempotently materializes sandfsID's volume directory:
// mkdir + setgid shared-group layout, seed per mode, and the template's
// declared min resources. Partial runs self-heal via the provisioning marker.
func (p *Provisioner) EnsureVolume(ctx context.Context, sandfsID, mode, templateRef string, epochs ...string) (*EnsureResult, error) {
	volumeEpoch := ""
	if len(epochs) > 0 {
		volumeEpoch = epochs[0]
	}
	if err := validateVolumeEpoch(volumeEpoch); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidArgument, err)
	}
	if err := ValidateSandfsID(sandfsID); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidArgument, err)
	}
	if mode != "flat" && mode != "overlay" {
		return nil, fmt.Errorf("%w: mode must be \"flat\" or \"overlay\" (got %q)", ErrInvalidArgument, mode)
	}
	if err := ValidateTemplateRef(templateRef); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidArgument, err)
	}
	if p.Templates == nil {
		return nil, fmt.Errorf("no template manager configured: cannot resolve template %q", templateRef)
	}

	// A staged rotation means names are MOVING: creating a volume now would
	// land it in a generation the rotation list does not cover, so refuse
	// until the seed is promoted (or the staging is aborted). The gateway
	// surfaces this as a named refusal while the maintenance window is open.
	if p.Names != nil && p.Names.HasNext() {
		return nil, fmt.Errorf("%w: volume seed rotation is staged — creating during the window would strand the volume in the old generation", ErrRotationStaged)
	}

	// Snapshot the naming generation ONCE: the directory name and the identity
	// stamp must derive from the SAME bytes. Deriving the name here and
	// reading the current seed again at the end (minutes later, after the
	// template copy / OCI stream) let a promote that landed in between leave a
	// volume NAMED in the retired generation but STAMPED with the live one —
	// invisible to the startup guard, delete answering false success, a
	// re-create building a second tree. The finalize check below closes the
	// remaining window (a promote landing while this volume seeds) loudly.
	var nameSeed []byte
	volName := sandfsID
	if p.Names != nil {
		nameSeed = p.Names.CurrentSeed()
		volName = volname.Derive(nameSeed, sandfsID)
	}
	volPath := filepath.Join(p.VolRoot, volName)

	// The volumes root is host-prep property: 2710 <prov>:<shared-group> setgid,
	// group TRAVERSE-ONLY (the daemon can reach volumes but never list or write
	// at the root — isolation layer 4), created by ss_prepare_dirs / host prep.
	// The provision identity must NOT create it implicitly — MkdirAll would
	// mint it owned by prov with prov's group (and umask-stripped bits), and
	// every volume inside would then carry the wrong group: the exec sandlot
	// (985) could not traverse and the FUSE daemon (987) could not write,
	// breaking mounts and agent writes for the whole node. A missing root is an
	// unprepared host: fail with the actionable setup step instead of minting a
	// broken shape.
	if _, err := os.Stat(p.VolRoot); err != nil {
		return nil, fmt.Errorf("volumes root %s unusable: %w (host prep creates it as 2710 <prov>:<shared-group> setgid — run deploy/baremetal/setup-host.sh or the k8s host prep; the provision identity never creates it)", p.VolRoot, err)
	}

	// An EXISTING directory must belong to THIS sandfs, and a valid signed
	// stamp is the COMPLETION PROOF: the fresh-create path runs the quota hook
	// BEFORE writing the stamp, so a signed stamp means content + quota are
	// finalized. The stamp is the authority, not a marker: in flat mode the
	// volume root is the agent's chroot, so the tenant can plant
	// `.provisioning` (and can even plant it beside a perfectly valid volume).
	// A mismatch or an unverifiable stamp still refuses loudly (seed
	// generations diverged, restored backup, hand-rename, tampering).
	if _, statErr := os.Stat(volPath); statErr == nil {
		st, ok, serr := readVolumeStamp(volPath)
		if serr != nil {
			return nil, fmt.Errorf("%w: read stamp under %s: %v", ErrVolumeIdentityMismatch, volPath, serr)
		}
		if ok {
			if st.SandfsID != sandfsID {
				return nil, fmt.Errorf("%w: %s is stamped for %s — do NOT attach; inspect the seed generations (a rotation or restore went wrong)", ErrVolumeIdentityMismatch, volPath, st.SandfsID)
			}
			if !p.stampSignatureOK(volPath, st) {
				// The tenant can rewrite this file in flat mode; an unsigned
				// or non-verifying stamp is a forgery or a copy from another
				// volume. Never attach a mount to it.
				return nil, fmt.Errorf("%w: %s carries a stamp that is unsigned or whose signature does not verify (tampered or copied from another volume) — do NOT attach", ErrVolumeIdentityMismatch, volPath)
			}
			// A marker beside a valid stamp is tenant debris or a crash
			// between the stamp write and the marker removal. Never wipe a
			// stamped volume: re-run the quota hook (idempotent set; this
			// also finalizes a volume left by the old stamp-then-quota order)
			// and clear the marker, then answer idempotently.
			if hasProvisioningMarker(volPath) {
				if qerr := stampQuota(ctx, p.QuotaStampCmd, volPath, sandfsID); qerr != nil {
					return nil, qerr
				}
				if rerr := os.Remove(filepath.Join(volPath, provisioningMarker)); rerr != nil && !os.IsNotExist(rerr) {
					return nil, fmt.Errorf("remove stale provisioning marker: %w", rerr)
				}
				slog.Warn("provision: cleared a provisioning marker beside a valid identity stamp (tenant-planted or interrupted finalize)",
					"sandfsID", sandfsID, "volume", volumeLogRef(volPath))
			}
			// An existing complete volume is never re-seeded, whatever ref
			// this call names: a create retry is a true no-op, and a
			// different-ref re-ensure cannot mix a second template's content
			// into a live tenant volume.
			slog.Info("provision: volume already complete; skipping re-seed (idempotent create)",
				"sandfsID", sandfsID, "volume", volumeLogRef(volPath), "requested_template", templateRef)
			reply, rerr := p.replyRootfsPath(volPath)
			if rerr != nil {
				return nil, rerr
			}
			res := &EnsureResult{RootfsPath: reply}
			res.MinVCPUs, res.MinMemoryMB, res.MinOK = p.StatTemplate(templateRef)
			return res, nil
		}
		// No stamp. Only a REGULAR .provisioning marker identifies a genuine
		// partial run (the stamp is written last); a tree with neither is
		// pre-stamp layout or foreign debris — refuse rather than guess.
		if !hasProvisioningMarker(volPath) {
			return nil, fmt.Errorf("%w: %s carries no %s stamp (created before stamping, or not by this plane) — run the storage-plane migration to stamp existing volumes", ErrVolumeIdentityMismatch, volPath, VolumeIdentityFile)
		}
		// Self-heal a partial run: the previous attempt died mid-seed. The
		// tree is garbage (no identity record points at a half-seeded
		// volume) — wipe and redo.
		slog.Warn("provision: wiping partial volume from an interrupted run",
			"sandfsID", sandfsID, "volume", volumeLogRef(volPath))
		if err := os.RemoveAll(volPath); err != nil {
			return nil, fmt.Errorf("wipe partial volume: %w", err)
		}
	}

	// Dedicated-identity model: the creating process (gateway-local mode:
	// sandserv, prov instances: sandprov) seeds the volume; sandvmm (primary
	// group sandlot) serves it via virtio-fs and the agent writes through it.
	// The shared group is the sandlot user's PRIMARY group: volRoot carries it
	// setgid (ss_prepare_dirs), so this dir and everything created inside land
	// group sandlot with group access — the service identities share the tree
	// without either being root. (Chmod is required — umask would strip the
	// group-write bit from the MkdirAll mode.)
	if err := os.MkdirAll(volPath, 0o770); err != nil {
		return nil, fmt.Errorf("mkdir volume %s: %w", volPath, err)
	}
	if err := os.Chmod(volPath, 0o2770|os.ModeSetgid); err != nil {
		os.RemoveAll(volPath)
		return nil, fmt.Errorf("chmod volume %s: %w", volPath, err)
	}
	// Marker LAST-pre-seed: from here on, a crash leaves a healable state.
	if err := os.WriteFile(filepath.Join(volPath, provisioningMarker), []byte("provisioning\n"), 0o644); err != nil {
		os.RemoveAll(volPath)
		return nil, fmt.Errorf("write provisioning marker: %w", err)
	}

	var rootfsPath string
	var pulled bool
	var err error
	switch mode {
	case "flat":
		rootfsPath, pulled, err = p.createFromFlatTemplate(ctx, volPath, templateRef)
	case "overlay":
		rootfsPath, pulled, err = p.createFromOverlayTemplate(ctx, volPath, templateRef)
	}
	if err != nil {
		// Leave the partial tree (marker present) so a retry self-heals; the
		// CALLER's failure path may also RemoveAll — both are safe.
		return nil, fmt.Errorf("create sandfs: %w", err)
	}

	if p.testHookEnsureVolumeSeeded != nil {
		p.testHookEnsureVolumeSeeded()
	}

	// Storage-plane quota stamp (provision.quota_stamp_cmd, empty = no-op)
	// runs BEFORE the identity stamp. The signed stamp is the completion
	// proof (content + quota finalized), so a stamped tree can never be an
	// unquota'd volume — and a marker found beside a valid stamp later is
	// tenant debris rather than a reason to wipe the tree. A failure leaves
	// the partial-run marker in place; the next attempt wipes and redoes
	// (hook included). The hook is already re-runnable on retry by design
	// (the old order also re-ran it after a crash before marker removal).
	if err := stampQuota(ctx, p.QuotaStampCmd, volPath, sandfsID); err != nil {
		// Already carries the ErrQuotaStamp sentinel (and the hook's exit
		// status + output tail); no re-wrap.
		return nil, err
	}

	// Stamp the finished volume, then clear the partial-run marker. A crash
	// between the two leaves a stamped tree with a marker; the ensure path
	// treats that as complete (it re-runs the idempotent quota hook and
	// clears the marker) instead of wiping the tenant's data.
	if p.Names != nil {
		if err := writeVolumeStamp(volPath, sandfsID, mode, nameSeed, time.Now().Unix(), volumeEpoch); err != nil {
			return nil, err
		}
		// The name was derived from the generation snapshotted at ENTRY, while
		// this create can spend minutes seeding. A promote landing in between
		// (the rotation's rename step skips this directory — it still carries
		// the .provisioning marker — and --run skips records with no
		// rootfs_path yet) would leave the volume named in the RETIRED
		// generation, with a success response handing that path out as the
		// record's rootfs_path: every later resolve looks up the new
		// generation's name and misses it, delete answers false success, and a
		// re-create builds a second tree. Re-derive the name under the CURRENT
		// generation and fail loudly instead; the marker stays, so the
		// directory is partial-run garbage by definition (self-healed or
		// ops-cleaned), and a retry materializes a fresh volume under the new
		// generation.
		if got := p.Names.Current(sandfsID); got != volName {
			return nil, fmt.Errorf("%w: volume %s was materialized while the seed generation moved (the current generation now derives %s) — refusing to finalize a volume named in a retired generation; retry the create", ErrRotationStaged, volPath, got)
		}
	}

	if err := os.Remove(filepath.Join(volPath, provisioningMarker)); err != nil {
		return nil, fmt.Errorf("remove provisioning marker: %w", err)
	}

	reply, err := p.replyRootfsPath(rootfsPath)
	if err != nil {
		return nil, err
	}
	res := &EnsureResult{RootfsPath: reply, Pulled: pulled}
	res.MinVCPUs, res.MinMemoryMB, res.MinOK = p.StatTemplate(templateRef)
	return res, nil
}

// Orphan debris from removeAllOrRename: a tree whose guest-created modes block
// direct removal is renamed to .<volume>.orphan-<unix> beside the volumes root.
// That converges the DELETE (the record goes, the id is reusable), but the data
// stays on disk — a reclaim needs an identity that can traverse the
// guest-owned entries, i.e. root (the provision identity is deliberately not
// the owner). The sweeper below reclaims what the current identity CAN remove
// and records the rest in a root-readable queue file for ops.
const (
	// OrphanSweepAge is how old an orphan must be before a sweep touches it.
	// A fresh orphan may belong to a delete that is still finishing; an hour is
	// far beyond any provision op deadline (seconds), so nothing in flight is
	// disturbed.
	OrphanSweepAge = time.Hour
	// OrphanSweepInterval is the prov daemon's sweep cadence.
	OrphanSweepInterval = time.Hour
	// orphanSweepTimeout bounds ONE orphan's removal. The tree is
	// guest-controlled (millions of entries are possible); the walk is
	// cancellation-aware, so a hostile tree costs one bounded sweep slot
	// instead of stalling the loop.
	orphanSweepTimeout = 5 * time.Minute
	// orphanQueueFile is the ops channel for orphans the provision identity
	// cannot reclaim: one volume directory name per line. It lives at the
	// volumes root (the provision identity owns it; the shared group has
	// traverse-only access there), mode 0600 — a seed-derived name must not
	// become readable by the FUSE daemon's group. Root can always read it.
	orphanQueueFile = ".orphan-queue"
	// orphanQueueMaxEntries caps the queue so a recurring failure cannot grow
	// it without bound; ordering is oldest-first and the file is ops-owned
	// once written.
	orphanQueueMaxEntries = 4096
)

// orphanDirPattern matches exactly the names removeAllOrRename produces; the
// dot prefix keeps them invisible to ScanGenerationStamps and scanTemplateInUse.
var orphanDirPattern = regexp.MustCompile(`^\..+\.orphan-[0-9]+$`)

// SweepOrphans reclaims age-based orphan-rename debris under the volumes root.
// Safety properties, all fail-closed:
//   - candidates are DIRECT children of the volumes root whose name matches
//     the exact orphan shape and whose Lstat is a real directory (never a
//     symlink, so nothing is followed outside the root);
//   - only entries older than maxAge are touched (a just-renamed orphan may
//     still belong to a finishing delete);
//   - removal goes through the cancellation-aware bottom-up walk, so a tree
//     the provision identity cannot traverse fails as a whole and is queued
//     for ops instead of being half-removed silently.
//
// Returns how many orphans were reclaimed and how many were recorded for ops.
func (p *Provisioner) SweepOrphans(maxAge time.Duration) (removed, queued int) {
	if maxAge <= 0 {
		maxAge = OrphanSweepAge
	}
	root := filepath.Clean(p.VolRoot)
	entries, err := os.ReadDir(root)
	if err != nil {
		if !os.IsNotExist(err) {
			slog.Warn("provision: orphan sweep cannot read the volumes root", "root", root, "error", err)
		}
		return 0, 0
	}
	now := time.Now()
	var failed []string
	for _, e := range entries {
		name := e.Name()
		if !orphanDirPattern.MatchString(name) || !e.IsDir() {
			continue
		}
		info, ierr := e.Info()
		if ierr != nil || now.Sub(info.ModTime()) < maxAge {
			continue
		}
		volPath := filepath.Join(root, name)
		if filepath.Dir(volPath) != root {
			continue // defensive: a matched name is one component by construction
		}
		if fi, lerr := os.Lstat(volPath); lerr != nil || fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), orphanSweepTimeout)
		rerr := removeAllContext(ctx, volPath)
		cancel()
		if rerr != nil {
			failed = append(failed, name)
			slog.Warn("provision: orphan sweep could not reclaim an orphan (queued for ops)",
				"orphan", volumeLogRef(volPath), "error", rerr)
			continue
		}
		removed++
	}
	if len(failed) > 0 {
		p.recordOrphans(failed)
	}
	return removed, len(failed)
}

// recordOrphans appends the names the sweeper could not reclaim to the ops
// queue, deduplicating against the existing content and capping the file.
func (p *Provisioner) recordOrphans(names []string) {
	path := filepath.Join(p.VolRoot, orphanQueueFile)
	existing := map[string]bool{}
	if data, err := os.ReadFile(path); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if line = strings.TrimSpace(line); line != "" {
				existing[line] = true
			}
		}
	}
	prior := len(existing)
	var add []string
	for _, name := range names {
		if !existing[name] {
			existing[name] = true
			add = append(add, name)
		}
	}
	if len(add) == 0 {
		return
	}
	allowed := orphanQueueMaxEntries - prior
	if allowed <= 0 {
		slog.Warn("provision: orphan queue is full; remaining orphans stay unreclaimed until ops drains it",
			"queue", volumeLogRef(path), "entries", prior)
		return
	}
	if len(add) > allowed {
		slog.Warn("provision: orphan queue is nearly full; recording only part of this sweep",
			"queue", volumeLogRef(path), "entries", prior, "dropped", len(add)-allowed)
		add = add[:allowed]
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		slog.Warn("provision: cannot record unreclaimed orphans for ops", "queue", volumeLogRef(path), "error", err)
		return
	}
	defer f.Close()
	for _, name := range add {
		if _, werr := fmt.Fprintf(f, "%s\n", name); werr != nil {
			slog.Warn("provision: cannot append to the orphan queue", "queue", volumeLogRef(path), "error", werr)
			return
		}
	}
}

// removeAllOrRename removes dir, converging via a sibling orphan-rename when
// direct removal is blocked. Guest-created entries land on the share owned by
// the sandvmm identity (987) with whatever modes the agent chose — a
// directory without the group-write bit (mkdir 700 ~/.ssh, chmod 700 build
// dirs) cannot be unlinked/rmdir'd by this process (sandprov, group sandlot,
// no caps, deliberately NOT the owner), so RemoveAll failing on a
// guest-populated tree is an EXPECTED condition, not an exceptional one.
// rename(2) needs only the PARENT directory's write permission, and every
// parent here (the volumes root, a volume directory) is group-writable
// without the sticky bit — so the whole tree is moved aside atomically and
// the operation converges: the caller can clear the record and reuse the id.
// The orphan (dot-prefixed, timestamped; invisible to sandfs-id scans) is
// reclaimed by the age-based orphan sweeper (SweepOrphans) when this identity
// can traverse the tree, and is recorded in the ops queue at the volumes root
// when only root can.
//
// Returns the orphan path when the fallback fired, "" on direct removal.
func removeAllOrRename(ctx context.Context, dir string) (string, error) {
	if err := removeAllContext(ctx, dir); err != nil {
		// A cancelled/deadlined operation must NOT rename the tree aside: the
		// caller reports the failure and frees the provision slot, leaving the
		// volume untouched for a retry.
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		orphan := filepath.Join(filepath.Dir(dir),
			fmt.Sprintf(".%s.orphan-%d", filepath.Base(dir), time.Now().Unix()))
		if rerr := os.Rename(dir, orphan); rerr != nil {
			return "", fmt.Errorf("remove %s: %w (orphan-rename fallback also failed: %v)", dir, err, rerr)
		}
		slog.Warn("provision: guest-planted modes blocked direct removal; renamed aside as orphan",
			"volume", volumeLogRef(dir), "orphan", volumeLogRef(orphan), "removeAllError", err)
		return orphan, nil
	}
	return "", nil
}

// removeAllContext is a cancellation-aware recursive delete. os.RemoveAll has
// no cancellation point: a large or slow tree holds one of the provision
// slots until it finishes. This walk checks the context between entries and
// removes files bottom-up (directories last), never following symlinks.
func removeAllContext(ctx context.Context, dir string) error {
	var dirs []string
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, walkErr error) error {
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			dirs = append(dirs, path)
			return nil
		}
		return os.Remove(path)
	})
	if err != nil {
		return err
	}
	for i := len(dirs) - 1; i >= 0; i-- {
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		if rerr := os.Remove(dirs[i]); rerr != nil {
			return rerr
		}
	}
	return nil
}

// quarantineVolume moves a volume directory aside under a dot-prefixed,
// timestamped name in the volumes root WITHOUT erasing anything. It exists for
// a destructive cleanup whose identity proof is UNREADABLE (a guest-planted
// symlink/FIFO/oversized stamp — an agent-writable flat volume root): refusing
// forever would let the tenant block its own deletion, while deleting would
// act without proof. The rename needs only write permission on the parent (the
// provision identity owns the volumes root), so it converges where removal
// cannot; the data stays for ops inspection and the dot-prefixed name is
// invisible to every volume scan.
//
// The delete op carries no volume epoch (the wire op is sandfs-id only), so
// the match here is the RECORD's seed-derived path — the only ownership
// evidence available at the node. The mount path already refuses to serve the
// directory (an unreadable stamp fails every identity check), so quarantine
// changes availability for ops, never exposure.
func (p *Provisioner) quarantineVolume(volPath, reason string) error {
	orphan := filepath.Join(p.VolRoot,
		fmt.Sprintf(".%s.orphan-%d", filepath.Base(volPath), time.Now().Unix()))
	if err := os.Rename(volPath, orphan); err != nil {
		return fmt.Errorf("quarantine %s: %w (identity proof unreadable: %v)", volPath, err, reason)
	}
	slog.Warn("provision: destructive cleanup QUARANTINED a volume whose identity stamp is unreadable (data preserved for ops; the record's id is now reusable)",
		"volume", volumeLogRef(volPath), "orphan", volumeLogRef(orphan), "reason", reason)
	return nil
}

// DeleteVolume removes the volume directory (ENOENT = success). The safety
// unmount covers a host-side overlay mount at <vol>/rootfs left behind by an
// offline node — the primary cleanup path is the gateway-orchestrated
// unmount sweep + overlay cleanup on exec-role connections BEFORE this call.
// A tree whose guest-created modes block direct removal converges via the
// orphan-rename fallback (see removeAllOrRename): the delete succeeds, the
// id becomes reusable, and the orphan directory is handed to the age-based
// sweeper / ops queue (see SweepOrphans).
func (p *Provisioner) DeleteVolume(ctx context.Context, sandfsID string) error {
	if err := ValidateSandfsID(sandfsID); err != nil {
		return err
	}
	volPath, err := p.resolveVolPath(sandfsID)
	if err != nil {
		// ENOENT = success is this op's contract: a volume that is already gone
		// (or never existed) is deleted.
		return nil
	}
	// Destructive op: prove the directory belongs to this sandfs before
	// removing it (a wrong-generation rename landing here must be a loud
	// refusal, not a cross-tenant rm -rf). A stamp that exists but cannot be
	// read is the one refusal a delete must not turn into a permanent block
	// (the tenant controls that file in a flat volume): quarantine instead —
	// nothing is erased, the id becomes reusable, and ops can inspect the
	// preserved tree.
	ownershipErr := p.requireStampOwnership(volPath, sandfsID, "delete volume", "")
	if ownershipErr != nil && !errors.Is(ownershipErr, ErrVolumeStampUnreadable) {
		return ownershipErr
	}
	// Safety unmount on BOTH paths, BEFORE the directory moves: a host-side
	// overlay left at <vol>/rootfs (an offline node's cleanup) follows the
	// dentry through the rename — quarantining a tree with a live mount would
	// hand ops an EBUSY orphan. Unmount through an O_PATH fd, never the path:
	// `rootfs` lives inside an agent-writable flat volume and umount2(2)
	// follows a final symlink. A symlink/non-directory is simply not a mount
	// point we can name — skip.
	if fd, target, ok := openVerifiedVolumeMountTarget(volPath); ok {
		_ = syscall.Unmount(target, syscall.MNT_DETACH)
		unix.Close(fd)
	}
	if ownershipErr != nil {
		return p.quarantineVolume(volPath, ownershipErr.Error())
	}
	if _, err := removeAllOrRename(ctx, volPath); err != nil {
		return fmt.Errorf("remove sandfs: %w", err)
	}
	return nil
}

// SwapTemplate re-points a DETACHED overlay sandfs's volume at a new
// read-only template: validates/auto-pulls the ref, applies the /home
// policy, and atomically rewrites the .template marker. workspace/ is never
// touched — the whole point of the swap is that agent work carries over.
// The caller (the gateway) only issues this while the record status is
// "detached" (mounts provably released cluster-wide), so no overlay is live
// while the marker moves. Idempotent: re-sending the same (ref, policy) is a
// no-op.
func (p *Provisioner) SwapTemplate(ctx context.Context, sandfsID, templateRef, homePolicy string) (*EnsureResult, error) {
	if err := ValidateSandfsID(sandfsID); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidArgument, err)
	}
	if err := ValidateTemplateRef(templateRef); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidArgument, err)
	}
	switch homePolicy {
	case "", HomeKeep, HomeArchive, HomeReset:
	default:
		return nil, fmt.Errorf("%w: home policy must be keep|archive|reset (got %q)", ErrInvalidArgument, homePolicy)
	}
	if p.Templates == nil {
		return nil, fmt.Errorf("no template manager configured: cannot resolve template %q", templateRef)
	}

	volPath, err := p.resolveVolPath(sandfsID)
	if err != nil {
		return nil, err
	}
	// Content-rewriting op: the same ownership proof as deletion (a swap on a
	// mis-renamed directory would move another tenant's /home aside).
	if err := p.requireStampOwnership(volPath, sandfsID, "swap template", "overlay"); err != nil {
		return nil, err
	}

	// Overlay volumes only: the .template marker is the swap target (a flat
	// volume copied its template content at creation — there is nothing to
	// re-point). The symlink/FIFO-safe read guards a planted marker (in flat
	// mode the volume root is the agent's chroot root; see util.ReadMarkerFile).
	cur, ok, err := util.ReadMarkerFile(filepath.Join(volPath, ".template"))
	if err != nil {
		return nil, fmt.Errorf("%w: %s is not an overlay volume (no .template marker): %v", ErrInvalidArgument, sandfsID, err)
	}
	if !ok {
		return nil, fmt.Errorf("%w: %s has a non-regular .template marker — refusing to treat it as an overlay volume", ErrInvalidArgument, sandfsID)
	}
	if strings.TrimSpace(string(cur)) == templateRef {
		// Idempotent re-issue of the same ref: nothing to move.
		reply, rerr := p.replyRootfsPath(volPath)
		if rerr != nil {
			return nil, rerr
		}
		res := &EnsureResult{RootfsPath: reply}
		res.MinVCPUs, res.MinMemoryMB, res.MinOK = p.StatTemplate(templateRef)
		return res, nil
	}

	// Resolve the new ref with the same auto-pull + durable-record fail-fast
	// as createFromOverlayTemplate: a ref whose layers were hand-removed
	// must fail HERE, not at every dependent volume's next cold mount.
	pulled := false
	ref, err := p.Templates.LoadRefEntry(templateRef, "overlay")
	if err != nil {
		if p.Templates.HasOCIRegistry() {
			if _, pullErr := p.Templates.PullTemplate(ctx, templateRef, "overlay"); pullErr != nil {
				return nil, fmt.Errorf("overlay template %s not found locally and auto-pull failed: %w", templateRef, pullErr)
			}
			pulled = true
			ref, err = p.Templates.LoadRefEntry(templateRef, "overlay")
			if err != nil {
				return nil, fmt.Errorf("reload overlay ref %s after pull: %w", templateRef, err)
			}
		} else {
			return nil, fmt.Errorf("%w: load overlay ref %s: %v", ErrTemplateNotFound, templateRef, err)
		}
	}
	if !p.Templates.RefEntryExists(ref) {
		return nil, fmt.Errorf("%w: overlay %s source missing (template deleted?)", ErrTemplateNotFound, templateRef)
	}

	// /home policy: keep (nothing), archive (rename + fresh home, keep only
	// the newest archive), reset (wipe + fresh home).
	if err := p.applyHomePolicy(ctx, volPath, homePolicy); err != nil {
		return nil, err
	}

	// Marker rewrite LAST and atomic: everything before this point is
	// side-effect-only on home/ (recoverable by re-issue); from this point
	// the volume serves the new template.
	if err := writeTemplateMarker(volPath, templateRef); err != nil {
		return nil, err
	}

	reply, err := p.replyRootfsPath(volPath)
	if err != nil {
		return nil, err
	}
	res := &EnsureResult{RootfsPath: reply, Pulled: pulled}
	res.MinVCPUs, res.MinMemoryMB, res.MinOK = p.StatTemplate(templateRef)
	return res, nil
}

// applyHomePolicy moves or resets the volume's writable /home according to
// the swap request. workspace/ is deliberately out of scope — it is the
// agent's work product and always carries over. home/ is guest-populated, so
// every removal here goes through the orphan-rename fallback: a restrictive
// agent-chosen mode inside home/ must never fail the swap (same failure
// class as DeleteVolume).
func (p *Provisioner) applyHomePolicy(ctx context.Context, volPath, homePolicy string) error {
	home := filepath.Join(volPath, "home")
	switch homePolicy {
	case "", HomeKeep:
		return nil
	case HomeReset:
		if _, err := removeAllOrRename(ctx, home); err != nil {
			return fmt.Errorf("reset home: %w", err)
		}
	case HomeArchive:
		// Rename the current home aside (timestamped; agent-recoverable via
		// the file API by an operator), prune older archives (one kept), then
		// recreate fresh — same setgid layout as creation. Pruning an older
		// archive uses the orphan fallback for the same guest-mode reason.
		entries, _ := os.ReadDir(volPath)
		for _, e := range entries {
			name := e.Name()
			if strings.HasPrefix(name, "home.pre-attach-") {
				if _, err := removeAllOrRename(ctx, filepath.Join(volPath, name)); err != nil {
					return fmt.Errorf("prune old home archive %s: %w", name, err)
				}
			}
		}
		if err := os.Rename(home, filepath.Join(volPath, "home.pre-attach-"+strconv.FormatInt(time.Now().Unix(), 10))); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("archive home: %w", err)
		}
	}
	return ensureRealHomeDir(volPath)
}

// ensureRealHomeDir creates/opens <vol>/home without following a planted
// symlink and applies the setgid 02770 layout. The final component lives in a
// possibly agent-writable volume root; a path-based MkdirAll/Chmod on
// `home -> <host dir>` would chmod an arbitrary host directory. Open the
// volume root and walk one component with O_NOFOLLOW instead.
func ensureRealHomeDir(volPath string) error {
	vfd, err := unix.Open(volPath, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open volume root %s: %w", volPath, err)
	}
	defer unix.Close(vfd)
	if err := unix.Mkdirat(vfd, "home", 0o770); err != nil && !errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("mkdir home: %w", err)
	}
	hfd, err := unix.Openat(vfd, "home", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("home is a symlink or non-directory (refusing to chmod through it): %w", err)
	}
	defer unix.Close(hfd)
	if err := unix.Fchmod(hfd, 0o2770); err != nil {
		return fmt.Errorf("chmod home: %w", err)
	}
	return nil
}

// openVerifiedVolumeMountTarget opens <vol>/rootfs O_PATH|O_NOFOLLOW for an
// unmount. ok=false when the entry is missing or is not a real directory; a
// symlink must never reach umount2.
func openVerifiedVolumeMountTarget(volPath string) (fd int, target string, ok bool) {
	vfd, err := unix.Open(volPath, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, "", false
	}
	defer unix.Close(vfd)
	rfd, err := unix.Openat(vfd, "rootfs", unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, "", false
	}
	return rfd, fmt.Sprintf("/proc/self/fd/%d", rfd), true
}

// writeTemplateMarker atomically rewrites the volume's .template marker
// (tmp+rename, same discipline as ref files — a concurrent overlay mount on
// another node reads either the old or the new complete ref, never partial).
func writeTemplateMarker(volPath, templateRef string) error {
	marker := filepath.Join(volPath, ".template")
	// CreateTemp opens O_CREAT|O_EXCL|O_RDWR with an unpredictable suffix: a
	// pre-planted symlink named `.template.tmp` (the old fixed tmp name) is
	// never followed, and the random name cannot be squatted in advance. The
	// final rename replaces the marker entry itself (it does not follow it).
	f, err := os.CreateTemp(volPath, ".template.tmp-*")
	if err != nil {
		return fmt.Errorf("create template marker temp: %w", err)
	}
	tmp := f.Name()
	if _, err := f.WriteString(templateRef); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("write template marker (tmp): %w", err)
	}
	// The marker is read by the EXEC sandlot identity (985) at mount time
	// (storage truth for the overlay ref): explicit chmod so a restrictive
	// umask cannot make it owner-only.
	if err := f.Chmod(0o644); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("chmod template marker (tmp): %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("close template marker (tmp): %w", err)
	}
	if err := os.Rename(tmp, marker); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("rename template marker: %w", err)
	}
	return nil
}

// inUseScanWorkers bounds the parallelism of DeleteTemplate's volume marker
// scan. One stat per volume on shared storage (~1ms); 64 workers keep a
// 10k-volume fleet under ~200ms.
const inUseScanWorkers = 64

// DeleteTemplate removes a template ref (and its then-unreferenced layers).
// Overlay templates carry a runtime dependency — every overlay volume's
// .template marker names the ref and every cold mount reads refs/+layers/ —
// so the delete refuses with *TemplateInUseError while any volume still
// names it (bounded parallel marker scan; catches orphan volumes whose
// identity records are gone). Flat templates skip the scan: flat volumes
// copy content at creation and hold no runtime dependency. force skips the
// check (operator escape hatch).
func (p *Provisioner) DeleteTemplate(ctx context.Context, templateRef, mode string, force bool) error {
	if err := ValidateTemplateRef(templateRef); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidArgument, err)
	}
	if p.Templates == nil {
		return fmt.Errorf("no template manager configured")
	}
	if mode == "" {
		// Auto-detect, overlay first (same preference as push/stat).
		if _, err := p.Templates.LoadRefEntry(templateRef, "overlay"); err == nil {
			mode = "overlay"
		} else if _, err := p.Templates.LoadRefEntry(templateRef, "flat"); err == nil {
			mode = "flat"
		} else {
			return fmt.Errorf("%w: template %s has neither an overlay nor a flat ref", ErrTemplateNotFound, templateRef)
		}
	}
	if mode != "flat" && mode != "overlay" {
		return fmt.Errorf("%w: mode must be \"flat\" or \"overlay\" (got %q)", ErrInvalidArgument, mode)
	}

	if mode == "overlay" && !force {
		count, sample, err := p.scanTemplateInUse(ctx, templateRef)
		if err != nil {
			return err
		}
		if count > 0 {
			return &TemplateInUseError{Count: count, Sample: sample}
		}
	}
	return p.Templates.DeleteTemplate(templateRef, mode)
}

// scanTemplateInUse counts volumes whose .template marker names templateRef
// (bounded parallel stat workload; ctx-bounded).
func (p *Provisioner) scanTemplateInUse(ctx context.Context, templateRef string) (int, []string, error) {
	entries, err := os.ReadDir(p.VolRoot)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil, nil
		}
		return 0, nil, fmt.Errorf("scan volumes: %w", err)
	}
	var candidates []string
	for _, e := range entries {
		name := e.Name()
		// Dot-prefixed entries are never volumes: the orphan-rename fallback
		// (removeAllOrRename) parks unremovable trees as .<name>.orphan-<ts>
		// right here, and the partial-run/tmp files are dot-prefixed too. An
		// orphan whose .template still names the ref must not pin it — the
		// sandfs it belonged to is gone, so the template has no user left.
		if !e.IsDir() || strings.HasPrefix(name, ".") {
			continue
		}
		candidates = append(candidates, name)
	}

	var (
		mu     sync.Mutex
		count  int
		sample []string
		wg     sync.WaitGroup
	)
	sem := make(chan struct{}, inUseScanWorkers)
	for _, id := range candidates {
		if err := ctx.Err(); err != nil {
			wg.Wait()
			return count, sample, err
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(id string) {
			defer wg.Done()
			defer func() { <-sem }()
			data, ok, err := util.ReadMarkerFile(filepath.Join(p.VolRoot, id, ".template"))
			// In-use identity is the ref FILE identity, not the raw string:
			// RefToFilename is not injective ('a:b_c' and 'a_b:c' both encode
			// to refs/a_b_c.overlay.json), and a collision must not hide a
			// live volume from the delete gate.
			if err != nil || !ok || util.RefToFilename(strings.TrimSpace(string(data))) != util.RefToFilename(templateRef) {
				return
			}
			// a.template marker alone is plantable by a tenant in a
			// FLAT volume (a deleted-template DoS). Real overlay volumes
			// always carry the layout signature (workspace/ + home/, created
			// together with the marker) — require it, so a planted marker
			// without the layout cannot pin a template.
			for _, sub := range []string{"workspace", "home"} {
				// Lstat, not Stat: these entries live in the agent-writable
				// volume root. A symlink is tenant debris, not the overlay
				// layout signature, and must never be resolved host-side.
				if fi, serr := os.Lstat(filepath.Join(p.VolRoot, id, sub)); serr != nil || !fi.IsDir() {
					return
				}
			}
			// The layout signature alone is still plantable: a flat volume's
			// directory IS the agent's chroot, so the agent can mint
			// workspace/, home/ and the marker itself. The identity stamp is
			// the node-side evidence the agent does not choose — the create
			// asked for the mode, the storage plane wrote it. A stamp WITHOUT a mode
			// (written before the field existed) keeps the layout-only answer,
			// because turning a live overlay volume's template deletion loose
			// is worse than the pin it leaves possible for legacy volumes.
			//
			// A "flat" claim (any non-overlay mode) unpins the volume whether
			// or not its signature verifies. A verified claim is the storage plane's
			// own record. An unverified one is attacker-chosen — but it can
			// only unpin THIS volume: every other volume is classified on its
			// own stamp, so a live overlay volume anywhere else still pins the
			// ref, and a volume whose stamp fails verification cannot be
			// mounted as an overlay anyway. Treating it conservatively instead
			// let one planted stamp (and, after a guest-kernel rewrite, even an
			// authentic flat volume) block the template's deletion forever.
			volPath := filepath.Join(p.VolRoot, id)
			if st, ok, serr := readVolumeStamp(volPath); serr == nil && ok && st.Mode != "" && st.Mode != "overlay" {
				return
			}
			mu.Lock()
			count++
			if len(sample) < 10 {
				sample = append(sample, id)
			}
			mu.Unlock()
		}(id)
	}
	wg.Wait()
	return count, sample, ctx.Err()
}

// StatTemplate reads the template's declared minimum resources. Returns
// ok=false when the manager is unset, no ref file exists, or it declares no
// requirement. Mode-agnostic: overlay first (the common case), then flat.
func (p *Provisioner) StatTemplate(templateRef string) (vcpus uint32, memMB uint64, ok bool) {
	if p.Templates == nil || p.Templates.TemplatesDir() == "" {
		return 0, 0, false
	}
	for _, mode := range []string{"overlay", "flat"} {
		ref, err := p.Templates.LoadRefEntry(templateRef, mode)
		if err != nil {
			continue
		}
		if ref.MinVCPUs == 0 && ref.MinMemoryMB == 0 {
			return 0, 0, false
		}
		return ref.MinVCPUs, ref.MinMemoryMB, true
	}
	return 0, 0, false
}

// createFromFlatTemplate creates a flat volume from one of two content
// sources recorded in the flat ref file: a local template directory (Layers,
// seeded via copyDirRecursive) or OCI origin (OCILayers — every blob is
// streamed from the registry and extracted straight into the volume; no
// local cache, dedup is the storage backend's concern). A missing ref
// auto-pulls first (manifest only — digests recorded into the ref) when an
// OCI registry is configured. No .template marker — the whole directory is
// the rootfs (bind-mount mode, fully writable). The pulled return reports
// whether the ref came from the registry in THIS call.
func (p *Provisioner) createFromFlatTemplate(ctx context.Context, volPath, templateRef string) (string, bool, error) {
	pulled := false
	ref, err := p.Templates.LoadRefEntry(templateRef, "flat")
	if err != nil {
		if p.Templates.HasOCIRegistry() {
			if _, pullErr := p.Templates.PullTemplate(ctx, templateRef, "flat"); pullErr != nil {
				return "", false, fmt.Errorf("flat template %s not found locally and auto-pull failed: %w", templateRef, pullErr)
			}
			pulled = true
			ref, err = p.Templates.LoadRefEntry(templateRef, "flat")
			if err != nil {
				return "", false, fmt.Errorf("reload flat ref %s after pull: %w", templateRef, err)
			}
		} else {
			return "", false, fmt.Errorf("%w: load flat ref %s: %v", ErrTemplateNotFound, templateRef, err)
		}
	}

	// OCI origin: stream-extract each layer directly into the volume.
	if len(ref.OCILayers) > 0 {
		if err := p.Templates.ExtractFlatFromOCI(ctx, ref.OCILayers, volPath); err != nil {
			return "", false, fmt.Errorf("materialize flat template %s from OCI: %w", templateRef, err)
		}
		return volPath, pulled, nil
	}

	// Local directory origin: copy the template content into the volume.
	if len(ref.Layers) == 0 {
		return "", false, fmt.Errorf("flat template %s has no layers", templateRef)
	}

	// The layer path is judged against the template store's trust boundary
	// here: refs live on shared storage, so a tampered ref must not be
	// able to point copyDirRecursive at /etc or another tenant's volume. The
	// checked resolve refuses anything outside the store and its configured
	// flat scan roots (the overlay path pays the same check at mount).
	srcPath, err := p.Templates.ResolveFlatLayerPath(ref.Layers[0])
	if err != nil {
		return "", false, fmt.Errorf("flat template %s: %w", templateRef, err)
	}
	if info, err := os.Stat(srcPath); err != nil || !info.IsDir() {
		return "", false, fmt.Errorf("flat template source not found: %s", srcPath)
	}

	// No defensive parent creation: EnsureVolume has already verified the
	// volumes root exists with the host-prep shape (2710 <prov>:<shared-group>);
	// an implicit MkdirAll here would mint a mis-grouped root instead of
	// surfacing the unprepared host.

	if err := copyfs.CopyDirRecursiveContext(ctx, srcPath, volPath); err != nil {
		return "", false, fmt.Errorf("seed sandfs from flat template %s: %w", templateRef, err)
	}
	return volPath, pulled, nil
}

// createFromOverlayTemplate creates the overlay volume layout: rootfs/
// (host-side overlay mount point), workspace/ and home/ (writable), and the
// .template marker. A missing overlay ref auto-pulls when a registry is
// configured — under the CALLER's context, so the gateway's storage-op
// deadline bounds the (potentially GB-scale) download instead of it running
// unbounded in the background. Fail fast when the ref is a durable record of
// a deleted template: without this the creation would succeed (dirs + marker
// only) and every exec fail at mount time with a confusing
// lowerdir-not-found error.
func (p *Provisioner) createFromOverlayTemplate(ctx context.Context, volPath, templateRef string) (string, bool, error) {
	pulled := false
	ref, err := p.Templates.LoadRefEntry(templateRef, "overlay")
	if err != nil {
		if p.Templates.HasOCIRegistry() {
			if _, pullErr := p.Templates.PullTemplate(ctx, templateRef, "overlay"); pullErr != nil {
				return "", false, fmt.Errorf("overlay template %s not found locally and auto-pull failed: %w", templateRef, pullErr)
			}
			pulled = true
			ref, err = p.Templates.LoadRefEntry(templateRef, "overlay")
			if err != nil {
				return "", false, fmt.Errorf("reload overlay ref %s after pull: %w", templateRef, err)
			}
		} else {
			return "", false, fmt.Errorf("%w: load overlay ref %s: %v", ErrTemplateNotFound, templateRef, err)
		}
	}
	if !p.Templates.RefEntryExists(ref) {
		return "", false, fmt.Errorf("%w: overlay %s source missing (template deleted?)", ErrTemplateNotFound, templateRef)
	}

	if err := os.MkdirAll(filepath.Join(volPath, "workspace"), 0o770); err != nil {
		return "", false, fmt.Errorf("mkdir workspace: %w", err)
	}
	if err := os.Chmod(filepath.Join(volPath, "workspace"), 0o2770|os.ModeSetgid); err != nil {
		return "", false, fmt.Errorf("chmod workspace: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(volPath, "home"), 0o770); err != nil {
		return "", false, fmt.Errorf("mkdir home: %w", err)
	}
	if err := os.Chmod(filepath.Join(volPath, "home"), 0o2770|os.ModeSetgid); err != nil {
		return "", false, fmt.Errorf("chmod home: %w", err)
	}
	if err := os.WriteFile(filepath.Join(volPath, ".template"), []byte(templateRef), 0644); err != nil {
		return "", false, fmt.Errorf("write .template marker: %w", err)
	}
	// Read cross-identity by the exec sandlot at mount time — umask-immune.
	if err := os.Chmod(filepath.Join(volPath, ".template"), 0644); err != nil {
		return "", false, fmt.Errorf("chmod .template marker: %w", err)
	}
	return volPath, pulled, nil
}

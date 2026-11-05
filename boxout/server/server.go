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

// Package server implements the boxout request protocol: the privileged VM
// lifecycle operations (sandvmm launch/kill/shutdown, network provisioning,
// host-side OverlayFS mount/unmount, /proc re-adopt, crash detection) served
// to the unprivileged sandlot over a newline-delimited JSON Unix socket.
// boxout communicates with sandlot over a Unix socket using newline-delimited
// JSON. sandlot sends requests; boxout dispatches them and returns responses.
package server

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"common/util"
	sandlotconfig "sandlot/config"
	"sandlot/core"
	"sandlot/network"
	"sandlot/provision/volume"
	"sandlot/vmm"
)

// managedVM tracks a VM launched by boxout.
type managedVM struct {
	VM     *vmm.RunningVM
	Cfg    vmm.Config
	WaitCh chan error // closed when sandvmm exits
	SpecID string
}

// Server handles requests from sandlot over the Unix socket.
//
// Concurrency: sandlot's BoxoutManager dials a NEW connection per request, so
// handleConn runs concurrently for many requests at once. mu guards vms and
// vmmCfg (vmmCfg is also swapped by the config hot-reload). Critical sections
// copy out what they need and never do IO under the lock.
type Server struct {
	mu         sync.Mutex
	cfg        sandlotconfig.SandlotConfig
	vmmCfg     vmm.Config
	allowedUID uint32
	netProv    vmm.NetworkProvider
	logger     *log.Logger
	vms        map[string]*managedVM // vmID → managedVM
	overlays   *core.OverlaySet      // host-side overlay mounts owned by this sidecar
	// overlayStatePath persists the overlay tracking map (volumePath →
	// template ref) across sidecar restarts — the ref half is what the
	// swap-staleness check needs and mountinfo cannot provide.
	overlayStatePath string
	// clientToken authenticates the peer IN ADDITION to SO_PEERCRED. The UID
	// check alone admits any host process/pod that can run as the sandlot
	// UID; the token lives in a pod-private directory readable only by the
	// real sidecar pair. Empty = UID-only (tests / explicitly unconfigured).
	clientToken string
	// Admission limits. maxVMs bounds the VM count; maxTotalMemMB bounds the
	// aggregate memory (0 = no aggregate bound). Both are enforced by
	// boxout itself — the unprivileged sandlot is the party being contained.
	maxVMs        int
	maxTotalMemMB uint64
	// reserved holds admission reservations for creates in flight (vmID →
	// requested memory MB). Guarded by mu; a reservation is released on every
	// failure path and replaced by the vms entry on success.
	reserved map[string]uint64
	// netLeases tracks VM ids that hold a PROVISIONED network (TAP, nft
	// chains, IP lease) — from provision_network until release/destroy. Without
	// it the network RPCs bypass admitVM entirely: a compromised sandlot could
	// create unbounded TAPs/chains/IPs on the host.
	netLeases map[string]struct{}

	// allowInsecureVolumes is the explicit dev/test admission for the
	// volumes nosuid,nodev gate (mirrors sandlot's -allow-insecure-volumes).
	// Production never sets it: the gate is what makes guest-planted setuid
	// bits and device nodes on the shared tree inert (invariant 8).
	allowInsecureVolumes bool

	// RPC resource bounds. Every sandlot request arrives on its own
	// connection, so an unbounded accept loop lets a compromised peer pin the
	// privileged sidecar's descriptors/goroutines forever. Zero values mean
	// "use the defaults" (tests build Server literals).
	idleTimeout  time.Duration
	writeTimeout time.Duration
	maxConns     int
	connSem      chan struct{}
	semOnce      sync.Once
}

// RPC resource defaults. The idle bound matches the sandlot client's per-round
// -trip 60s relay deadline, so a healthy caller is never cut off; the
// connection bound is far above the pool's concurrent lifecycle fan-out.
const (
	defaultRPCIdleTimeout  = 60 * time.Second
	defaultRPCWriteTimeout = 30 * time.Second
	defaultMaxConns        = 256
)

// defaultInstanceBaseDir mirrors sandlot/config Defaults().Instance.BaseDir.
const defaultInstanceBaseDir = "/run/sandswap"

// InstanceSandboxRoot derives a boxout's own instance sandbox root from the
// shared sandlot config — the same expression sandlot/cmd/main.go uses
// (filepath.Join(base_dir, instance.id, "vm")). With the default config this is
// /run/sandswap/vm; with instance.id set it is <base_dir>/<id>/vm.
func InstanceSandboxRoot(cfg sandlotconfig.SandlotConfig) string {
	base := cfg.Instance.BaseDir
	if base == "" {
		base = defaultInstanceBaseDir
	}
	return filepath.Clean(filepath.Join(base, cfg.Instance.ID, "vm"))
}

// instanceSandboxRoot returns this server's own root. cfg is immutable after
// New (the hot-reload path only swaps vmm defaults), so no lock is needed.
func (s *Server) instanceSandboxRoot() string {
	return InstanceSandboxRoot(s.cfg)
}

// SetAllowInsecureVolumes is the explicit dev/test admission for the volumes
// mount gate (same contract as sandlot's -allow-insecure-volumes).
func (s *Server) SetAllowInsecureVolumes(allow bool) { s.allowInsecureVolumes = allow }

// SetRPCBounds installs the connection-idle / response-write deadlines and
// the concurrent-connection cap (zero/negative keeps the package defaults).
// Must be called before serving.
func (s *Server) SetRPCBounds(idle, write time.Duration, maxConns int) {
	if idle > 0 {
		s.idleTimeout = idle
	}
	if write > 0 {
		s.writeTimeout = write
	}
	if maxConns > 0 {
		s.maxConns = maxConns
	}
}

// maxConnsLimit resolves the configured cap against the default.
func (s *Server) maxConnsLimit() int {
	if s.maxConns > 0 {
		return s.maxConns
	}
	return defaultMaxConns
}

// acquireConnSlot reserves one concurrent-connection slot. It is created
// lazily so a Server built as a struct literal still enforces a bound.
func (s *Server) acquireConnSlot() bool {
	s.semOnce.Do(func() { s.connSem = make(chan struct{}, s.maxConnsLimit()) })
	select {
	case s.connSem <- struct{}{}:
		return true
	default:
		return false
	}
}

func (s *Server) releaseConnSlot() { <-s.connSem }

// idleReadTimeout / writeDeadline resolve the configured values.
func (s *Server) idleReadTimeout() time.Duration {
	if s.idleTimeout > 0 {
		return s.idleTimeout
	}
	return defaultRPCIdleTimeout
}

func (s *Server) writeDeadline() time.Duration {
	if s.writeTimeout > 0 {
		return s.writeTimeout
	}
	return defaultRPCWriteTimeout
}

// SetClientToken installs the per-pod client token (empty disables the check).
func (s *Server) SetClientToken(token string) { s.clientToken = token }

// SetLimits installs the VM admission limits (0 = unbounded for that axis).
func (s *Server) SetLimits(maxVMs int, maxTotalMemMB uint64) {
	s.maxVMs = maxVMs
	s.maxTotalMemMB = maxTotalMemMB
}

// constantTimeEqual compares two strings without an early exit (length is not
// secret in this protocol).
func constantTimeEqual(a, b string) bool {
	if len(a) != len(b) {
		// Still walk the shorter string to keep the comparison uniform for
		// the common same-length case; length mismatch is a refusal anyway.
		return false
	}
	var diff byte
	for i := 0; i < len(a); i++ {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

// admitVM enforces the count and aggregate-memory bounds under the server
// lock AND reserves the slot. Reserving (not merely checking) is what makes
// admission atomic: the VM is registered only after a multi-second launch,
// so a bare check let two concurrent creates pass the same bound and both
// launch. The reservation is released on every failure path and replaced by
// the real registration on success.
func (s *Server) admitVM(vmID string, memoryMB uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.reserved == nil {
		s.reserved = make(map[string]uint64)
	}
	if _, ok := s.vms[vmID]; ok {
		return fmt.Errorf("boxout already runs a VM with id %q", vmID)
	}
	if _, ok := s.reserved[vmID]; ok {
		return fmt.Errorf("boxout is already creating a VM with id %q", vmID)
	}
	if s.maxVMs > 0 && len(s.vms)+len(s.reserved) >= s.maxVMs {
		return fmt.Errorf("boxout VM limit reached (%d)", s.maxVMs)
	}
	if s.maxTotalMemMB > 0 {
		var used uint64
		for _, vm := range s.vms {
			used += vm.Cfg.MemoryMB
		}
		for _, mb := range s.reserved {
			used += mb
		}
		if used+memoryMB > s.maxTotalMemMB {
			return fmt.Errorf("boxout aggregate memory limit reached (%d MB used + %d MB requested > %d MB)", used, memoryMB, s.maxTotalMemMB)
		}
	}
	s.reserved[vmID] = memoryMB
	return nil
}

// releaseReservation drops an admission reservation (create failed before the
// VM was registered).
func (s *Server) releaseReservation(vmID string) {
	s.mu.Lock()
	delete(s.reserved, vmID)
	s.mu.Unlock()
}

// New creates a boxout server bound to the given config and network provider.
// allowedUID is the sandlot UID admitted by the SO_PEERCRED check (from
// -allowed-uid; must match the sandlot service account).
func New(cfg sandlotconfig.SandlotConfig, vmmCfg vmm.Config, netProv vmm.NetworkProvider, allowedUID uint32, logger *log.Logger) *Server {
	return &Server{
		cfg:        cfg,
		vmmCfg:     vmmCfg,
		allowedUID: allowedUID,
		netProv:    netProv,
		logger:     logger,
		vms:        make(map[string]*managedVM),
		overlays:   core.NewOverlaySet(logger),
	}
}

// UpdateVMMConfig applies a hot-reloaded microvm subset to the server's VMM
// defaults: only the hot-reloadable fields (kernel, initramfs, default
// resources). Restart-required fields (volumes_dir, overlayfs_templates) keep
// their startup values — boxout must stay field-for-field consistent with the
// sandlot's classification, since create_vm's parameter whitelist compares
// against these values.
func (s *Server) UpdateVMMConfig(kernel, initramfs string, vcpus uint32, memMB uint64) {
	s.mu.Lock()
	s.vmmCfg.KernelPath = kernel
	s.vmmCfg.InitramfsPath = initramfs
	s.vmmCfg.VCPUs = vcpus
	s.vmmCfg.MemoryMB = memMB
	s.mu.Unlock()
	s.logger.Printf("boxout vmm config hot-reloaded: kernel=%s initramfs=%s vcpus=%d mem=%dMB",
		kernel, initramfs, vcpus, memMB)
}

// currentVMMConfig snapshots the VMM defaults under the lock.
func (s *Server) currentVMMConfig() vmm.Config {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.vmmCfg
}

// sandvmmIdentity is the expected process identity for orphan/re-adopt
// verification: the configured VMM uid and executable image. Resolved per
// control-plane call (one stat) so a changed config is honored.
func (s *Server) sandvmmIdentity() core.SandvmmIdentity {
	cfg := s.currentVMMConfig()
	return core.NewSandvmmIdentity(cfg.VMMUID, cfg.VMMBinary)
}

// VolumesDir returns the configured volumes directory (whitelist root for
// overlay RPCs).
func (s *Server) VolumesDir() string {
	return s.currentVMMConfig().VolumesDir
}

// Overlays exposes the host-side overlay tracking set (restore + stale sweep
// are driven by the boxout main's startup path and reaper ticker).
func (s *Server) Overlays() *core.OverlaySet {
	return s.overlays
}

// HandleConn handles a single sandlot connection. Each connection processes
// one request at a time (request-response, newline-delimited JSON).
//
// Resource bounds: at most maxConnsLimit() connections are served at once
// (sandlot dials a fresh connection per request, so this is the sidecar's
// concurrency bound), every read carries an idle deadline and every response a
// write deadline. Without them a peer that connects and never speaks — or
// stops reading — pins a goroutine and a descriptor indefinitely.
func (s *Server) HandleConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	if !s.acquireConnSlot() {
		s.logger.Printf("reject connection: %d concurrent RPC connections already open", s.maxConnsLimit())
		return
	}
	defer s.releaseConnSlot()

	// SO_PEERCRED verification: only the allowed UID may connect.
	uid, err := getPeerUID(conn)
	if err != nil || uid != s.allowedUID {
		s.logger.Printf("reject connection: uid=%d err=%v (expected %d)", uid, err, s.allowedUID)
		return
	}

	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 0, 64*1024), boxoutMaxRequestLine)

	// Mutual token authentication BEFORE any request is served: a foreign
	// process/pod that merely shares the sandlot UID cannot drive root boxout,
	// and the client learns it reached the real sidecar (a squatter cannot
	// answer the challenge without the token). The token never crosses the
	// wire; only HMACs over fresh nonces do.
	if s.clientToken != "" {
		if !s.authenticateConn(conn, scanner) {
			return
		}
	}

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		// Re-armed per line: a silent connection is closed after the idle
		// bound; an active one may keep its connection as long as it likes.
		if err := conn.SetReadDeadline(time.Now().Add(s.idleReadTimeout())); err != nil {
			return
		}
		if !scanner.Scan() {
			return
		}
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var req map[string]any
		if err := json.Unmarshal(line, &req); err != nil {
			s.sendError(conn, "", fmt.Sprintf("parse request: %v", err))
			continue
		}

		reqType, _ := req["type"].(string)
		resp := s.dispatch(ctx, reqType, req)
		resp["type"] = reqType

		data, _ := json.Marshal(resp)
		_ = conn.SetWriteDeadline(time.Now().Add(s.writeDeadline()))
		if _, err := conn.Write(append(data, '\n')); err != nil {
			return
		}
	}
}

// boxoutAuthNonceBytes is the size of each handshake nonce (256-bit, so the
// HMAC transcripts cannot be replayed or precomputed).
const boxoutAuthNonceBytes = 32

// boxoutAuthChallengeType / boxoutAuthResponseType / boxoutAuthOKType are the
// handshake message types (the client implementation mirrors them).
const (
	boxoutAuthChallengeType = "auth_challenge"
	boxoutAuthResponseType  = "auth_response"
	boxoutAuthOKType        = "auth_ok"
)

// authMAC renders HMAC-SHA256(token, labeled message) as lowercase hex.
func authMAC(token, msg string) string {
	m := hmac.New(sha256.New, []byte(token))
	_, _ = io.WriteString(m, msg)
	return hex.EncodeToString(m.Sum(nil))
}

// writeJSONLine writes one newline-terminated JSON message under the RPC write
// deadline.
func (s *Server) writeJSONLine(conn net.Conn, msg map[string]any) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	_ = conn.SetWriteDeadline(time.Now().Add(s.writeDeadline()))
	_, err = conn.Write(append(data, '\n'))
	return err
}

// authenticateConn runs the token challenge-response:
//
//	server → {"type":"auth_challenge","nonce":S}
//	client → {"type":"auth_response","hmac":HMAC(token,"client:"+S),"nonce":C}
//	server → {"type":"auth_ok","hmac":HMAC(token,"server:"+C)}
//
// The client verifies the final HMAC, so BOTH sides learn the peer holds the
// token (the per-request token field this replaced only proved the client's).
// Any mismatch is a silent-ish refusal: the reason is logged locally, never
// echoed to the peer.
func (s *Server) authenticateConn(conn net.Conn, scanner *bufio.Scanner) bool {
	serverNonce := make([]byte, boxoutAuthNonceBytes)
	if _, err := rand.Read(serverNonce); err != nil {
		s.logger.Printf("boxout auth: nonce: %v", err)
		return false
	}
	serverNonceHex := hex.EncodeToString(serverNonce)
	if err := s.writeJSONLine(conn, map[string]any{
		"type":  boxoutAuthChallengeType,
		"nonce": serverNonceHex,
	}); err != nil {
		return false
	}
	if err := conn.SetReadDeadline(time.Now().Add(s.idleReadTimeout())); err != nil {
		return false
	}
	if !scanner.Scan() {
		s.logger.Printf("boxout auth: peer closed before responding")
		return false
	}
	var resp struct {
		Type  string `json:"type"`
		HMAC  string `json:"hmac"`
		Nonce string `json:"nonce"`
	}
	if err := json.Unmarshal(scanner.Bytes(), &resp); err != nil || resp.Type != boxoutAuthResponseType {
		s.logger.Printf("boxout auth: malformed response")
		_ = s.writeJSONLine(conn, map[string]any{"type": boxoutAuthResponseType, "ok": false, "error": "authentication failed"})
		return false
	}
	clientNonce, nerr := hex.DecodeString(resp.Nonce)
	if nerr != nil || len(clientNonce) != boxoutAuthNonceBytes {
		s.logger.Printf("boxout auth: bad client nonce")
		_ = s.writeJSONLine(conn, map[string]any{"type": boxoutAuthResponseType, "ok": false, "error": "authentication failed"})
		return false
	}
	if !constantTimeEqual(resp.HMAC, authMAC(s.clientToken, "client:"+serverNonceHex)) {
		s.logger.Printf("boxout auth: client token mismatch — refusing the connection (a peer that merely shares the sandlot uid cannot drive boxout)")
		_ = s.writeJSONLine(conn, map[string]any{"type": boxoutAuthResponseType, "ok": false, "error": "authentication failed"})
		return false
	}
	if err := s.writeJSONLine(conn, map[string]any{
		"type": boxoutAuthOKType,
		"ok":   true,
		"hmac": authMAC(s.clientToken, "server:"+resp.Nonce),
	}); err != nil {
		return false
	}
	return true
}

// boxoutMaxRequestLine bounds one newline-delimited request.
const boxoutMaxRequestLine = 1024 * 1024

// dispatch routes a request to the appropriate handler.
func (s *Server) dispatch(ctx context.Context, reqType string, req map[string]any) map[string]any {
	switch reqType {
	case "create_vm":
		return s.handleCreateVM(ctx, req)
	case "destroy_vm":
		return s.handleDestroyVM(ctx, req)
	case "provision_network":
		return s.handleProvisionNetwork(ctx, req)
	case "release_network":
		return s.handleReleaseNetwork(ctx, req)
	case "reclaim_network":
		return s.handleReclaimNetwork(ctx, req)
	case "mount_overlay":
		return s.handleMountOverlay(ctx, req)
	case "unmount_overlay":
		return s.handleUnmountOverlay(ctx, req)
	case "verify_volume_id":
		return s.handleVerifyVolumeID(ctx, req)
	case "net_stamp_identity":
		return s.handleNetStampIdentity(ctx, req)
	case "net_mount_state":
		return s.handleNetMountState(ctx, req)
	case "readopt_vms":
		return s.handleReadoptVMs(ctx, req)
	case "restore_overlays":
		return s.handleRestoreOverlays(ctx, req)
	case "cleanup_overlays":
		return s.handleCleanupOverlays(ctx, req)
	default:
		return map[string]any{"ok": false, "error": fmt.Sprintf("unknown request type: %s", reqType)}
	}
}

// boxoutVMIDRe is the vm_id grammar: one path element, no '/', no "..".
// vm_id derives /run/sandswap/vm/<vm_id> when the caller omits sandbox_dir.
var boxoutVMIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// maxWardenTimingSec bounds the warden timings the unprivileged sandlot may
// choose. They anchor the mount-release safety proof (T_warden); a day is far
// above any legitimate value and far below "never expires".
const maxWardenTimingSec = 86400

// validWardenLogLevel accepts exactly the tokens the warden's
// parse_log_level recognizes. Anything else (above all, whitespace) would be
// injected into the guest kernel cmdline.
func validWardenLogLevel(level string) bool {
	switch level {
	case "trace", "debug", "info", "warn", "error", "critical", "fatal", "panic":
		return true
	default:
		return false
	}
}

// guestCIDRange derives the admissible guest-CID window from the shared
// sandlot config (instance.cid_range_start/cid_range_end). The floor is 3
// (0/1/2 are AF_VSOCK reserved); an unset/invalid end leaves the top at
// 0xFFFFFFFE — VMADDR_CID_ANY (0xFFFFFFFF) is reserved and never admitted.
func (s *Server) guestCIDRange() (uint32, uint32) {
	lo := s.cfg.Instance.CIDRangeStart
	if lo < 3 {
		lo = 3
	}
	hi := s.cfg.Instance.CIDRangeEnd
	if hi == 0 || hi <= lo || hi >= math.MaxUint32 {
		hi = math.MaxUint32 - 1
	}
	return lo, hi
}

// validateBoxoutNetSpec bounds the caller-supplied net_config to the shape
// this host's own network provider emits. The boxout is ROOT and hands the map
// to sandvmm's vm.create: an unvalidated map admits vhost_user/vhost_socket
// (connect to an arbitrary Unix socket), fd= (dup an arbitrary inherited fd)
// and a tap override (attach another VM's interface). The sandlot is
// UNPRIVILEGED in boxout mode, so these are privilege-escalation primitives.
//
// Only these keys are legitimate; anything else is refused by name:
//
//	tap  = the deterministic TAP this node created for vmID
//	mac  = the spec's own MAC
//	mtu  = a sane 576..65535 value
func validateBoxoutNetSpec(vmID string, spec vmm.VMNetSpec) error {
	if spec.NetConfig == nil {
		return nil
	}
	expectedTap := network.TapNameFor(vmID)
	for k := range spec.NetConfig {
		switch k {
		case "tap", "mac", "mtu":
		default:
			return fmt.Errorf("net_config key %q is not permitted (only tap/mac/mtu from the node's own provider)", k)
		}
	}
	if v, ok := spec.NetConfig["tap"]; ok {
		tap, ok := v.(string)
		if !ok || tap != expectedTap {
			return fmt.Errorf("net_config tap %v does not match this VM's TAP %q", v, expectedTap)
		}
	}
	if v, ok := spec.NetConfig["mac"]; ok {
		mac, ok := v.(string)
		if !ok || (spec.MAC != "" && mac != spec.MAC) {
			return fmt.Errorf("net_config mac %v does not match the spec MAC %q", v, spec.MAC)
		}
	}
	if v, ok := spec.NetConfig["mtu"]; ok {
		var mtu int
		switch n := v.(type) {
		case int:
			mtu = n
		case float64:
			if n != math.Trunc(n) {
				return fmt.Errorf("net_config mtu %v is not an integer", v)
			}
			mtu = int(n)
		default:
			return fmt.Errorf("net_config mtu %v has an unexpected type", v)
		}
		if mtu < 576 || mtu > 65535 {
			return fmt.Errorf("net_config mtu %d out of range 576..65535", mtu)
		}
	}
	return nil
}

// handleCreateVM launches a sandvmm process and returns its identity.
func (s *Server) handleCreateVM(ctx context.Context, req map[string]any) map[string]any {
	vmID, _ := req["vm_id"].(string)
	if vmID == "" {
		return map[string]any{"ok": false, "error": "missing vm_id"}
	}
	// vm_id is used as a SINGLE PATH ELEMENT (it derives
	// /run/sandswap/vm/<vm_id> in the launcher when sandbox_dir is omitted,
	// and it keys state.json / the VM map). The peer is the unprivileged
	// sandlot; without this check a vm_id of "../../etc" makes boxout (root)
	// chmod/chgrp/create files at an attacker-chosen path.
	if !boxoutVMIDRe.MatchString(vmID) {
		return map[string]any{"ok": false, "error": fmt.Sprintf("vm_id %q must be a single path element matching ^[A-Za-z0-9][A-Za-z0-9._-]*$ (no '/', no '..')", vmID)}
	}

	base := s.currentVMMConfig()
	cfg := base // copy defaults

	// Parameter whitelist: only allow pre-configured paths and bounded resources.
	if v, ok := req["kernel"].(string); ok && v != "" {
		if v != base.KernelPath {
			return map[string]any{"ok": false, "error": fmt.Sprintf("kernel path not allowed: %s", v)}
		}
		cfg.KernelPath = v
	}
	if v, ok := req["initramfs"].(string); ok && v != "" {
		if v != base.InitramfsPath {
			return map[string]any{"ok": false, "error": fmt.Sprintf("initramfs path not allowed: %s", v)}
		}
		cfg.InitramfsPath = v
	}
	if v, ok := req["volumes_dir"].(string); ok && v != "" {
		if v != base.VolumesDir {
			return map[string]any{"ok": false, "error": fmt.Sprintf("volumes_dir not allowed: %s", v)}
		}
		cfg.VolumesDir = v
	}
	// Bind the sandbox dir to THIS instance's own root. A create aimed at a
	// sibling instance's tree would later be returned by that sibling's
	// re-adopt scan (warden session key included), so the root is compared
	// against the root this sidecar derives from its own config — never against
	// a shape parsed out of the caller's path.
	ownRoot := s.instanceSandboxRoot()
	if v, ok := req["sandbox_dir"].(string); ok && v != "" {
		root, derr := validateCreateSandboxDir(v, vmID)
		if derr != nil {
			return map[string]any{"ok": false, "error": derr.Error()}
		}
		if root != ownRoot {
			return map[string]any{"ok": false, "error": fmt.Sprintf(
				"sandbox_dir root %q is not this boxout instance's root %q", root, ownRoot)}
		}
	}
	cfg.SandboxDir = filepath.Join(ownRoot, vmID)
	// Symlinked prefixes (above all the sandbox root itself) would redirect
	// the launcher's root-side mkdir/chown/chmod and the later RemoveAll.
	if err := refuseSymlinkedPath(cfg.SandboxDir); err != nil {
		return map[string]any{"ok": false, "error": fmt.Sprintf("sandbox_dir refused: %v", err)}
	}
	if v, ok := req["guest_cid"].(float64); ok {
		// CID 1 (local) and 2 (host) are kernel-reserved; sandlot's allocator
		// range starts at 3 — anything below is malformed or hostile. The
		// admissible window is the CONFIGURED allocator range (0/0 when unset):
		// a caller may not pick a CID outside the range this host hands out.
		// Compare in float BEFORE the uint32 cast: a negative float wraps to a
		// huge uint32, silently passing the floor (and failing only later at
		// device activation); a fractional CID is malformed outright.
		// VMADDR_CID_ANY (0xFFFFFFFF) is reserved and never admissible.
		lo, hi := s.guestCIDRange()
		if v != math.Trunc(v) || v < float64(lo) || v > float64(hi) {
			return map[string]any{"ok": false, "error": fmt.Sprintf("guest_cid %v must be an integer in [%d, %d] (the configured instance CID range; 0xFFFFFFFF is reserved)", v, lo, hi)}
		}
		cfg.GuestCID = uint32(v)
	}
	if v, ok := req["vcpus"].(float64); ok {
		// Lower bound and integrality are load-bearing: 0 (or 0.x, truncated to
		// 0) booted a VM outside every admission/spec assumption, and a
		// fractional value silently became a different size than requested.
		if v != math.Trunc(v) || v < 1 || v > 16 {
			return map[string]any{"ok": false, "error": fmt.Sprintf("vcpus %v must be an integer in [1, 16]", v)}
		}
		cfg.VCPUs = uint32(v)
	}
	if v, ok := req["memory_mb"].(float64); ok {
		// A 0/fractional memory_mb passed admission (admitVM summed 0 MB) and
		// the kernel could not boot below MinBootMemoryMB.
		if v != math.Trunc(v) || v < sandlotconfig.MinBootMemoryMB || v > 8192 {
			return map[string]any{"ok": false, "error": fmt.Sprintf("memory_mb %v must be an integer in [%d, 8192]", v, sandlotconfig.MinBootMemoryMB)}
		}
		cfg.MemoryMB = uint64(v)
	}
	// Admission bounds are enforced by boxout itself: the unprivileged
	// sandlot is the peer being contained, so its own pool accounting is not
	// a trust anchor.
	if aerr := s.admitVM(vmID, cfg.MemoryMB); aerr != nil {
		return map[string]any{"ok": false, "error": aerr.Error()}
	}
	// Every path below (validation refusals, launch failure) releases the
	// reservation; success replaces it with the registered VM.
	registered := false
	defer func() {
		if !registered {
			s.releaseReservation(vmID)
		}
	}()
	// Structured guest networking + warden params — replacing the former
	// free-form kernel_cmdline passthrough (removed: sandlot never set it, and
	// an arbitrary cmdline from the unprivileged side is an unnecessary
	// injection surface). The fields map 1:1 onto vmm.Config, which
	// buildVMCreateConfig/buildCmdline turn into the vm.create net device and
	// warden.* cmdline exactly as embedded mode does.
	//
	// The spec is validated against the strict grammar BEFORE anything is
	// launched: GuestIP/Gateway/GuestIP6/Gateway6/DNS/MAC are concatenated
	// into the kernel cmdline, and the warden splits it on ASCII whitespace —
	// an unchecked value carrying a space would inject independent warden.*
	// parameters. A non-matching value is refused by name; never "cleaned".
	if rawNet, present := req["net_spec"]; present {
		ns, ok := rawNet.(map[string]any)
		if !ok {
			// Present but not an object: refuse loudly, never skip silently
			// (a skipped spec silently becomes an offline VM).
			return map[string]any{"ok": false, "error": fmt.Sprintf("net_spec must be an object, got %T", rawNet)}
		}
		var spec vmm.VMNetSpec
		raw, err := json.Marshal(ns)
		if err != nil {
			return map[string]any{"ok": false, "error": fmt.Sprintf("net_spec: %v", err)}
		}
		if err := json.Unmarshal(raw, &spec); err != nil {
			return map[string]any{"ok": false, "error": fmt.Sprintf("parse net_spec: %v", err)}
		}
		if err := spec.Validate(); err != nil {
			return map[string]any{"ok": false, "error": fmt.Sprintf("net_spec rejected: %v", err)}
		}
		if err := validateBoxoutNetSpec(vmID, spec); err != nil {
			return map[string]any{"ok": false, "error": fmt.Sprintf("net_spec rejected: %v", err)}
		}
		if spec.HasNetwork() {
			cfg.NetSpec = &spec
		}
	}
	if v, ok := req["warden_countdown_sec"].(float64); ok && v > 0 {
		if v != math.Trunc(v) || v > maxWardenTimingSec {
			return map[string]any{"ok": false, "error": fmt.Sprintf("warden_countdown_sec %v must be an integer <= %d", v, maxWardenTimingSec)}
		}
		cfg.WardenCountdownSec = uint32(v)
	}
	if v, ok := req["warden_max_exec_timeout_sec"].(float64); ok && v > 0 {
		if v != math.Trunc(v) || v > maxWardenTimingSec {
			return map[string]any{"ok": false, "error": fmt.Sprintf("warden_max_exec_timeout_sec %v must be an integer <= %d", v, maxWardenTimingSec)}
		}
		cfg.WardenMaxExecTimeoutSec = uint32(v)
	}
	if v, ok := req["warden_log"].(string); ok && v != "" {
		// This string is concatenated into the guest kernel cmdline as
		// `warden.log=<v>` (launcher.buildCmdline). The warden splits its
		// cmdline on whitespace, so a value with a space injects independent
		// warden.* parameters (countdown/max_exec/agent_mem_percent/...),
		// overriding the values boxout just pinned. Only the exact log-level
		// tokens the warden's parse_log_level accepts are legal.
		if !validWardenLogLevel(v) {
			return map[string]any{"ok": false, "error": fmt.Sprintf("warden_log %q is not a log level (trace|debug|info|warn|error|critical|fatal|panic); the value is injected into the kernel cmdline and must not contain whitespace", v)}
		}
		cfg.WardenLogLevel = v
	}
	// Per-VM raw-protocol key. REQUIRED: boxout builds the kernel cmdline, but
	// the sandlot outside this sidecar is the party that authenticates to the
	// warden — a boxout-generated key would be unknown to it, so there is no
	// safe fallback.
	if v, ok := req["warden_session_key"].(string); ok && v != "" {
		raw, derr := hex.DecodeString(v)
		if derr != nil || len(raw) != sha256.Size {
			return map[string]any{"ok": false, "error": "warden_session_key must be 64 hex characters (32 bytes)"}
		}
		cfg.WardenSessionKey = v
	}
	if cfg.WardenSessionKey == "" {
		return map[string]any{"ok": false, "error": "warden_session_key is required (per-VM raw-protocol authentication)"}
	}

	// The sandvmm identity fields (VMMUID/VMMGID/VMMGroups/APIGID) flow in
	// from the shared sandlot config this sidecar watches (microvm.* hot
	// reload) — boxout runs as root, so the uid transition needs no
	// capabilities here. The API sockets end up owned by the sandvmm
	// identity with the APIGID group grant; sandlot connects as a member
	// of that group (k8s: set microvm.api_gid / vmm_groups to the pod's
	// shared group, e.g. fsGroup).

	// The canonical API socket admits only the sandlot identity (plus root):
	// the VMM enforces this via SO_PEERCRED. Every sandvmm shares the VMM
	// uid, so this is what stops a compromised sibling from querying another
	// VM's API. The optional per-VM token (microvm.vmm_api_auth) additionally
	// stops a fake/squatted listener from impersonating the server.
	cfg.APIAllowedUID = s.allowedUID

	// Storage-plane hard precondition (invariant 8): the volumes tree is
	// exported to the guest through the virtio-fs passthrough, which stores
	// guest-requested setuid bits and mknod verbatim. Only nosuid,nodev mount
	// flags make those inert, so a misdeployed (or replaced) volumes mount is
	// refused before any VM can export it. -allow-insecure-volumes is the
	// explicit dev/test admission. Placed after request validation (a bad
	// request gets its named error) and before the launch (no side effect).
	if err := s.checkVolumesMount(cfg.VolumesDir); err != nil {
		return map[string]any{"ok": false, "error": err.Error()}
	}

	s.logger.Printf("create_vm: launching %s (cid=%d, vcpus=%d, mem=%dMB)",
		vmID, cfg.GuestCID, cfg.VCPUs, cfg.MemoryMB)

	vm, err := vmm.Launch(context.Background(), cfg, s.logger)
	if err != nil {
		return map[string]any{"ok": false, "error": fmt.Sprintf("launch: %v", err)}
	}

	if cfg.VMMAPIAuth {
		// The launcher wrote the per-VM API token as root-0600 in the sandbox
		// state dir. Hand it to the sandlot uid (the only client) and keep the
		// state dir private: the sandvmm identity must not read either. The
		// handoff is fd-relative with O_NOFOLLOW and verifies the pre-handoff
		// owner/mode: the sandbox dir is group-writable, so a path-based
		// chown/chmod could follow a symlink planted at `state` and turn root
		// into an arbitrary-host-file primitive. Failure is fatal.
		if err := handoffAPIToken(cfg.SandboxDir, int(s.allowedUID)); err != nil {
			vm.Kill()
			core.RemoveState(cfg.SandboxDir)
			core.RemoveSandboxDir(cfg.SandboxDir, s.instanceSandboxRoot())
			return map[string]any{"ok": false, "error": fmt.Sprintf("api token handoff: %v", err)}
		}
	}

	// sandvmm handles its own socket permissions via --allowed-uid
	// (0600 + chown allowedUID:allowedUID). No chmod needed here.

	// Write state.json for re-adopt into the boxout-private state root (never
	// inside the shared sandbox dir).
	if err := core.WriteState(vmID, cfg, vm.APISocket, vm.PID(), "", s.instanceSandboxRoot()); err != nil {
		s.logger.Printf("write state for %s (non-fatal): %v", vmID, err)
	} else if err := handoffStateDir(cfg.SandboxDir, s.instanceSandboxRoot(), int(s.allowedUID)); err != nil {
		// state.json carries the warden session key: without this handoff the
		// hardened state root (0700 root-only) leaves the unprivileged sandlot
		// unable to load the key at re-attach — its KEY_DELIVERY is refused by
		// the warden, and every mount collapses into broken-pipe dirty
		// destroys. Failure is fatal for the same
		// reason the API-token handoff is: a VM the owner cannot drive is
		// worse than no VM.
		vm.Kill()
		core.RemoveState(cfg.SandboxDir)
		core.RemoveSandboxDir(cfg.SandboxDir, s.instanceSandboxRoot())
		return map[string]any{"ok": false, "error": fmt.Sprintf("state dir handoff: %v", err)}
	}
	// The launcher's prepareSandboxDir already applied the traverse-only
	// 0711 shape to this VM dir (fd-relative, O_NOFOLLOW); a second
	// path-based chmod here would re-introduce the symlink hazard.

	mvm := &managedVM{
		VM:     vm,
		Cfg:    cfg,
		WaitCh: make(chan error, 1),
	}
	s.mu.Lock()
	s.vms[vmID] = mvm
	delete(s.reserved, vmID)
	s.mu.Unlock()
	registered = true

	// Monitor VM exit
	go func() {
		err := vm.Wait()
		mvm.WaitCh <- err
		close(mvm.WaitCh)
		s.logger.Printf("VM %s exited: %v", vmID, err)
	}()

	return map[string]any{
		"ok":         true,
		"api_socket": vm.APISocket,
		"pid":        vm.PID(),
	}
}

// handoffStateDir hands the per-VM PRIVATE state directory (state.json with
// the warden session key) to the sandlot identity, with the same discipline
// as handoffAPIToken: fd-relative opens with O_NOFOLLOW, pre-checks that the
// directory is root-owned 0700 and state.json root-owned 0600 (a substituted
// or pre-handed-off target fails closed), then chown to the peer uid keeping
// the owner-only modes.
func handoffStateDir(sandboxDir, sandboxRoot string, uid int) error {
	// The STATE ROOT layer first (…/sandswap-state/<instance>): it is also
	// owner-checked by the sandlot's openStateRoot, so a root-owned 0700 root
	// layer denies the sandlot even before the per-VM dir is reached. Idempotent
	// across create_vm calls: an already-handed-off layer (owner == uid) passes.
	// The state root keeps its creation mode 0710 (openStateRoot's MkdirAll
	// mode — group traverse); only the OWNER changes.
	if err := handoffStateLayer(core.StateRootPathFor(sandboxRoot), uid, false, 0o710); err != nil {
		return fmt.Errorf("state root: %w", err)
	}
	dir, err := core.StateDirPath(sandboxDir, sandboxRoot)
	if err != nil {
		return fmt.Errorf("state dir path: %w", err)
	}
	if err := handoffStateLayer(dir, uid, false, 0o700); err != nil {
		return fmt.Errorf("state vm dir: %w", err)
	}
	return handoffStateLayer(filepath.Join(dir, "state.json"), uid, true, 0o600)
}

// handoffStateLayer hands ONE state layer (directory or state.json) to the
// sandlot uid: fd-relative + O_NOFOLLOW, owner must be root (fresh, from the
// writer) or already the peer uid (idempotent re-handoff), mode preserved
// (0700 dir / 0600 file). A foreign owner fails closed.
func handoffStateLayer(path string, uid int, isFile bool, mode uint32) error {
	openFlags := unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC
	if isFile {
		openFlags = unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC
	}
	fd, err := unix.Open(path, openFlags, 0)
	if err != nil {
		return fmt.Errorf("open (no-follow): %w", err)
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return fmt.Errorf("fstat: %w", err)
	}
	var wantType uint32 = unix.S_IFDIR
	if isFile {
		wantType = unix.S_IFREG
	}
	if st.Mode&unix.S_IFMT != wantType || st.Mode&0o777 != mode {
		return fmt.Errorf("mode %04o (type %o), want %04o %s", st.Mode&0o777, st.Mode&unix.S_IFMT, mode, map[bool]string{true: "regular file", false: "directory"}[isFile])
	}
	if st.Uid != uint32(os.Geteuid()) && st.Uid != uint32(uid) {
		return fmt.Errorf("owner uid %d is neither the writer (root) nor the peer (%d)", st.Uid, uid)
	}
	if st.Uid == uint32(uid) {
		return nil // already handed off
	}
	if err := unix.Fchown(fd, uid, uid); err != nil {
		return fmt.Errorf("chown: %w", err)
	}
	if err := unix.Fchmod(fd, mode); err != nil {
		return fmt.Errorf("chmod: %w", err)
	}
	return nil
}

// handoffAPIToken transfers the launcher-created API token to the sandlot
// identity. Every lookup is fd-relative and O_NOFOLLOW; the pre-handoff
// owner/mode checks make a substituted state dir or token file fail closed
// instead of receiving a privileged chown/chmod.
func handoffAPIToken(sandboxDir string, uid int) error {
	dfd, err := unix.Open(sandboxDir, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open sandbox dir (no-follow): %w", err)
	}
	defer unix.Close(dfd)
	sfd, err := unix.Openat(dfd, "state", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open state dir (no-follow): %w", err)
	}
	defer unix.Close(sfd)
	var st unix.Stat_t
	if err := unix.Fstat(sfd, &st); err != nil {
		return fmt.Errorf("fstat state dir: %w", err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != uint32(os.Geteuid()) || st.Mode&0o777 != 0o700 {
		return fmt.Errorf("state dir is not a root-owned 0700 directory (mode %04o, uid %d)", st.Mode&0o777, st.Uid)
	}
	tfd, err := unix.Openat(sfd, "api-token", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open api token (no-follow): %w", err)
	}
	defer unix.Close(tfd)
	var ts unix.Stat_t
	if err := unix.Fstat(tfd, &ts); err != nil {
		return fmt.Errorf("fstat api token: %w", err)
	}
	if ts.Mode&unix.S_IFMT != unix.S_IFREG || ts.Uid != uint32(os.Geteuid()) || ts.Mode&0o777 != 0o600 {
		return fmt.Errorf("api token is not a root-owned 0600 regular file (mode %04o, uid %d)", ts.Mode&0o777, ts.Uid)
	}
	if err := unix.Fchown(sfd, uid, uid); err != nil {
		return fmt.Errorf("chown state dir: %w", err)
	}
	if err := unix.Fchmod(sfd, 0o700); err != nil {
		return fmt.Errorf("chmod state dir: %w", err)
	}
	if err := unix.Fchown(tfd, uid, uid); err != nil {
		return fmt.Errorf("chown api token: %w", err)
	}
	if err := unix.Fchmod(tfd, 0o600); err != nil {
		return fmt.Errorf("chmod api token: %w", err)
	}
	return nil
}

// validateSandboxDir enforces the create_vm sandbox_dir rules on ANY
// caller-supplied path: under /run/sandswap/vm/ or /run/sandswap/<id>/vm/,
// no "..". Returns "" and (via the error return) the reason on refusal. The
// same validation gates create_vm and the untracked destroy path — a path
// that passes RemoveState/RemoveSandboxDir must never be attacker-steerable.
// validateCreateSandboxDir validates a caller-supplied sandbox_dir for a
// specific vm_id: the path must be EXACTLY <root>/<vm_id> for one of the two
// supported root shapes, and no component below /run/sandswap may be a
// symlink. This binds the path to the VM identity — a caller cannot pick an
// arbitrary subdirectory (or a symlinked prefix) and turn boxout's root
// mkdir/chmod/chown/RemoveAll into a host primitive.
func validateCreateSandboxDir(sandboxDir, vmID string) (string, error) {
	root, err := validateSandboxDir(sandboxDir)
	if err != nil {
		return "", err
	}
	if !boxoutVMIDRe.MatchString(vmID) {
		return "", fmt.Errorf("invalid vm_id %q", vmID)
	}
	clean := filepath.Clean(sandboxDir)
	if clean != filepath.Join(root, vmID) {
		return "", fmt.Errorf("sandbox_dir %q must be exactly %s", sandboxDir, filepath.Join(root, vmID))
	}
	if err := refuseSymlinkComponents(clean); err != nil {
		return "", err
	}
	// Return the TRUSTED ROOT (not the full path): callers use it as the
	// containment root for RemoveSandboxDir, whose isSandswapVMDir check
	// rejects a root equal to the target itself.
	return root, nil
}

// refuseSymlinkedPath walks every component of an absolute path with Lstat and
// refuses a symlink anywhere in it. A missing tail is accepted (the launch path
// creates it as root); a symlinked PREFIX — the sandbox root above all — is
// exactly the redirection this guards against, and a string comparison of the
// path cannot see it.
func refuseSymlinkedPath(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("path %q is not absolute", path)
	}
	cur := string(filepath.Separator)
	trimmed := strings.TrimPrefix(filepath.Clean(path), string(filepath.Separator))
	for _, part := range strings.Split(trimmed, string(filepath.Separator)) {
		if part == "" {
			continue
		}
		cur = filepath.Join(cur, part)
		fi, err := os.Lstat(cur)
		if err != nil {
			if os.IsNotExist(err) {
				return nil // the remainder will be created by the launcher
			}
			return fmt.Errorf("lstat %s: %w", cur, err)
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s is a symlink", cur)
		}
	}
	return nil
}

// refuseSymlinkComponents walks /run/sandswap → path with Lstat and refuses a
// symlink in any component. A root-owned runtime directory makes this
// unreachable in the shipped deployment; it is the defense for a runtime dir
// that an unprivileged identity can write.
func refuseSymlinkComponents(path string) error {
	const base = "/run/sandswap"
	if !strings.HasPrefix(path, base+"/") {
		return fmt.Errorf("path %q is not under %s", path, base)
	}
	cur := base
	if fi, err := os.Lstat(cur); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symlink", cur)
	}
	for _, part := range strings.Split(strings.TrimPrefix(path, base+"/"), "/") {
		if part == "" {
			continue
		}
		cur = filepath.Join(cur, part)
		fi, err := os.Lstat(cur)
		if err != nil {
			if os.IsNotExist(err) {
				return nil // the remainder will be created by prepareSandboxDir
			}
			return fmt.Errorf("lstat %s: %w", cur, err)
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s is a symlink", cur)
		}
	}
	return nil
}

func validateSandboxDir(sandboxDir string) (string, error) {
	if sandboxDir == "" {
		return "", fmt.Errorf("missing sandbox_dir")
	}
	validPrefix := strings.HasPrefix(sandboxDir, "/run/sandswap/vm/") || (strings.HasPrefix(sandboxDir, "/run/sandswap/") && strings.Contains(sandboxDir, "/vm/"))
	if !validPrefix {
		return "", fmt.Errorf("sandbox_dir must be under /run/sandswap/vm/ or /run/sandswap/<id>/vm/")
	}
	if strings.Contains(sandboxDir, "..") {
		return "", fmt.Errorf("sandbox_dir contains path traversal")
	}
	// The trusted sandbox ROOT derives from the validated prefix shape, NEVER
	// from the caller's path itself (filepath.Dir(sandboxDir) would let
	// sandboxDir's own parent neutralize core's containment check — rel is
	// then always a bare basename).
	switch {
	case strings.HasPrefix(sandboxDir, "/run/sandswap/vm/"):
		return "/run/sandswap/vm", nil
	default:
		// Multi-instance shape /run/sandswap/<id>/vm/<vm>: the root is the
		// FIRST "/vm" directory segment after /run/sandswap/ (LastIndex would
		// pick up a "/vm" inside the per-VM dir name itself).
		if idx := strings.Index(sandboxDir, "/vm/"); idx > 0 {
			return sandboxDir[:idx+3], nil
		}
		return "", fmt.Errorf("sandbox_dir has no /vm/ segment")
	}
}

// handleDestroyVM kills a sandvmm process and cleans up.
func (s *Server) handleDestroyVM(ctx context.Context, req map[string]any) map[string]any {
	vmID, _ := req["vm_id"].(string)
	readopted, _ := req["readopted"].(bool)
	sandboxDir, _ := req["sandbox_dir"].(string)

	s.mu.Lock()
	mvm, ok := s.vms[vmID]
	s.mu.Unlock()
	if !ok {
		// Untracked destroy ("sandlot already dropped it" — crash/destroy
		// path). This is the boundary where a compromised sandlot could
		// otherwise aim root privileges at arbitrary host targets, so every
		// caller-supplied value is validated BEFORE any action, and a failed
		// validation is a loud error — never a silent skip, never a partial
		// side effect.
		root, verr := validateCreateSandboxDir(sandboxDir, vmID)
		if verr != nil {
			s.logger.Printf("destroy_vm: refusing untracked destroy of %q: %v", vmID, verr)
			return map[string]any{"ok": false, "error": fmt.Sprintf("untracked destroy refused: %v", verr)}
		}
		// Only VMs recorded under THIS instance's root may be destroyed
		// untracked: the path is about to receive a root kill + RemoveAll, and
		// a sibling instance's tree (or any other shape someone convinces the
		// prefix check of) is not ours to manage.
		if own := s.instanceSandboxRoot(); root != own {
			s.logger.Printf("destroy_vm: refusing untracked destroy of %q: root %q is not this instance's %q", vmID, root, own)
			return map[string]any{"ok": false, "error": fmt.Sprintf(
				"untracked destroy refused: sandbox_dir root %q is not this boxout instance's root %q", root, own)}
		}
		// The pid must provably be the sandvmm serving the sandbox we are
		// about to remove: /proc/<pid>/cmdline is sandvmm AND its
		// --api-socket lives under the validated sandbox dir. A bare
		// syscall.Kill on a caller-supplied pid would be an arbitrary
		// host-process kill as root.
		// Discover the sandvmm serving THIS sandbox from /proc; the request's
		// pid/api_socket fields are NOT trust sources (the old OR accepted a
		// caller-supplied socket, so naming any sandvmm's socket was an
		// arbitrary root SIGKILL). The derived socket path is the only target
		// this path can ever signal; when no process holds it, the destroy is
		// a state/dir cleanup (idempotent).
		expectedSocket := filepath.Join(sandboxDir, "sandvmm.sock")
		// Kill through a pidfd opened before the identity check (the pid came
		// from /proc, never from the request), and treat a failed signal as a
		// FAILED destroy: removing state under a sandvmm that is still alive
		// is exactly how the next re-adopt picks up a zombie.
		if pid, kerr := core.KillSandvmmForSocket(expectedSocket, s.sandvmmIdentity()); kerr != nil {
			s.logger.Printf("destroy_vm: untracked destroy of %q: sandvmm pid %d: %v", vmID, pid, kerr)
			return map[string]any{"ok": false, "error": fmt.Sprintf("untracked destroy: sandvmm kill failed: %v", kerr)}
		}
		// Release the network lease this VM held. Untracked destroys are the
		// scale-down path for re-adopted VMs (boxout restarted, so s.vms is
		// empty while the TAP/nft rules/IP lease are live); without this they
		// leak until the node reboots.
		s.mu.Lock()
		_, leased := s.netLeases[vmID]
		s.mu.Unlock()
		if leased {
			if err := s.netProv.Release(ctx, vmID); err != nil {
				s.logger.Printf("destroy_vm: untracked destroy of %q: network release: %v", vmID, err)
				return map[string]any{"ok": false, "error": fmt.Sprintf("untracked destroy: network release failed: %v", err)}
			}
			s.mu.Lock()
			delete(s.netLeases, vmID)
			s.mu.Unlock()
		}
		core.RemoveState(sandboxDir)
		// RemoveAll's containment root is the TRUSTED root derived above —
		// core.isSandswapVMDir then actually contains (passing the caller
		// path's own parent would neutralize it).
		core.RemoveSandboxDir(sandboxDir, root)
		return map[string]any{"ok": true} // idempotent
	}

	// Kill the sandvmm process
	if readopted {
		mvm.VM.Shutdown(ctx)
		// Wait briefly for shutdown
		select {
		case <-mvm.WaitCh:
		case <-time.After(5 * time.Second):
			mvm.VM.Kill()
		}
	} else {
		mvm.VM.Kill()
		// Wait for the process to exit
		select {
		case <-mvm.WaitCh:
		case <-time.After(10 * time.Second):
			s.logger.Printf("destroy_vm: timed out waiting for VM %s", vmID)
		}
	}

	// Release network
	s.netProv.Release(ctx, vmID)
	s.mu.Lock()
	delete(s.netLeases, vmID)
	s.mu.Unlock()

	// Remove state + sandbox dir (tracked path: paths come from boxout's own
	// managedVM record, not from the request).
	core.RemoveState(mvm.Cfg.SandboxDir)
	core.RemoveSandboxDir(mvm.Cfg.SandboxDir, s.instanceSandboxRoot())

	s.mu.Lock()
	delete(s.vms, vmID)
	s.mu.Unlock()

	return map[string]any{"ok": true}
}

// handleProvisionNetwork provisions network resources for a VM.
func (s *Server) handleProvisionNetwork(ctx context.Context, req map[string]any) map[string]any {
	vmID, _ := req["vm_id"].(string)
	if !boxoutVMIDRe.MatchString(vmID) {
		return map[string]any{"ok": false, "error": fmt.Sprintf("vm_id %q is not a single path element", vmID)}
	}
	s.mu.Lock()
	if s.netLeases == nil {
		s.netLeases = make(map[string]struct{})
	}
	if _, ok := s.netLeases[vmID]; ok {
		s.mu.Unlock()
		return map[string]any{"ok": false, "error": fmt.Sprintf("network for %q is already provisioned", vmID)}
	}
	if s.maxVMs > 0 && len(s.netLeases) >= s.maxVMs {
		s.mu.Unlock()
		return map[string]any{"ok": false, "error": fmt.Sprintf("boxout network lease limit reached (%d)", s.maxVMs)}
	}
	s.netLeases[vmID] = struct{}{}
	s.mu.Unlock()
	spec, err := s.netProv.Provision(ctx, vmID)
	if err != nil {
		s.mu.Lock()
		delete(s.netLeases, vmID)
		s.mu.Unlock()
		return map[string]any{"ok": false, "error": err.Error()}
	}
	return map[string]any{"ok": true, "net_spec": spec}
}

// handleReleaseNetwork releases network resources for a VM. The vm_id must be
// in the network-lease table: without that membership check a compromised
// sandlot could name ANY regex-valid id and tear down a co-tenant's (or a
// sibling instance's) TAP, nft rules and IP lease.
func (s *Server) handleReleaseNetwork(ctx context.Context, req map[string]any) map[string]any {
	vmID, _ := req["vm_id"].(string)
	if !boxoutVMIDRe.MatchString(vmID) {
		return map[string]any{"ok": false, "error": fmt.Sprintf("vm_id %q is not a single path element", vmID)}
	}
	s.mu.Lock()
	_, leased := s.netLeases[vmID]
	s.mu.Unlock()
	if !leased {
		return map[string]any{"ok": false, "error": fmt.Sprintf("network for %q is not provisioned on this boxout instance (refusing to release a lease this instance does not hold)", vmID)}
	}
	err := s.netProv.Release(ctx, vmID)
	s.mu.Lock()
	delete(s.netLeases, vmID)
	s.mu.Unlock()
	if err != nil {
		return map[string]any{"ok": false, "error": err.Error()}
	}
	return map[string]any{"ok": true}
}

// handleReclaimNetwork re-registers network resources for a re-adopted VM.
//
// The addressing comes from boxout's OWN persisted state for the VM — never
// from the request: a caller-supplied guest IP/MAC/DNS would let a
// compromised sandlot reserve an arbitrary address, replay the anti-spoof
// rules with its own source identity, and poison the allocator. The bound is
// the same maxVMs admission provision_network uses.
func (s *Server) handleReclaimNetwork(ctx context.Context, req map[string]any) map[string]any {
	vmID, _ := req["vm_id"].(string)
	if !boxoutVMIDRe.MatchString(vmID) {
		return map[string]any{"ok": false, "error": fmt.Sprintf("vm_id %q is not a single path element", vmID)}
	}
	// Admission: same bound as provision_network, atomically with the
	// duplicate check.
	s.mu.Lock()
	if s.netLeases == nil {
		s.netLeases = make(map[string]struct{})
	}
	if _, ok := s.netLeases[vmID]; ok {
		s.mu.Unlock()
		return map[string]any{"ok": false, "error": fmt.Sprintf("network for %q is already provisioned", vmID)}
	}
	if s.maxVMs > 0 && len(s.netLeases) >= s.maxVMs {
		s.mu.Unlock()
		return map[string]any{"ok": false, "error": fmt.Sprintf("boxout network lease limit reached (%d)", s.maxVMs)}
	}
	s.mu.Unlock()

	spec, known := core.PersistedNetSpec(s.instanceSandboxRoot(), vmID)
	if !known {
		return map[string]any{"ok": false, "error": fmt.Sprintf("reclaim %s: no persisted state for this VM under this boxout instance (cannot derive its network identity)", vmID)}
	}
	if spec == nil {
		// The VM was launched without guest networking (backend=none): there
		// is nothing to reclaim, and no lease is recorded.
		return map[string]any{"ok": true}
	}
	if err := s.netProv.Reclaim(ctx, vmID, *spec); err != nil {
		return map[string]any{"ok": false, "error": err.Error()}
	}
	s.mu.Lock()
	s.netLeases[vmID] = struct{}{}
	s.mu.Unlock()
	return map[string]any{"ok": true}
}

// handleNetStampIdentity relays the mount-time egress identity stamp
// (docs/how-it-works/egress-enabler.md) to the privileged network provider.
// Providers without identity support (e.g. the bridge backend) are a clean
// no-op: the stamp is derived state, and "unstamped egress" is exactly the
// degradation the contract prescribes — never a mount failure.
func (s *Server) handleNetStampIdentity(ctx context.Context, req map[string]any) map[string]any {
	vmID, _ := req["vm_id"].(string)
	if vmID == "" {
		return map[string]any{"ok": false, "error": "missing vm_id"}
	}
	stamper, ok := s.netProv.(vmm.IdentityStamper)
	if !ok {
		s.logger.Printf("net_stamp_identity %s: network backend %T does not stamp identities (no-op)", vmID, s.netProv)
		return map[string]any{"ok": true}
	}
	agentID, _ := req["agent_id"].(string)
	sandfsID, _ := req["sandfs_id"].(string)
	epochF, _ := req["epoch"].(float64)
	stamper.SetMountIdentity(ctx, vmID, agentID, sandfsID, uint64(epochF))
	return map[string]any{"ok": true}
}

// handleNetMountState relays the mount gate (the unmount side removes the
// identity stamp). Same no-op semantics for providers without
// the gate.
func (s *Server) handleNetMountState(ctx context.Context, req map[string]any) map[string]any {
	vmID, _ := req["vm_id"].(string)
	if vmID == "" {
		return map[string]any{"ok": false, "error": "missing vm_id"}
	}
	gater, ok := s.netProv.(vmm.MountGater)
	if !ok {
		return map[string]any{"ok": true}
	}
	mounted, _ := req["mounted"].(bool)
	gater.SetMountState(ctx, vmID, mounted)
	return map[string]any{"ok": true}
}

// maxTrackedOverlays bounds the overlay tracking map. The map is per-node and
// persisted as a whole on every change; an unbounded map (a compromised
// sandlot asking mount_overlay for every path it can name) turns each mount
// into an O(N) file rewrite and eventually OOMs the sidecar. Entries are only
// added for volumes that actually carry an overlay mount, so the bound is far
// above any real node's overlay count.
const maxTrackedOverlays = 4096

// volumeRelPath validates a caller-supplied volume path against the volumes
// root and returns the single path component under it. Volumes are DIRECT
// children of the root, so a nested or traversing path is refused.
func volumeRelPath(volumesDir, volumePath string) (string, error) {
	if volumesDir == "" {
		return "", errors.New("no volumes_dir configured — refusing rather than testing containment against the empty string")
	}
	if strings.Contains(volumePath, "..") {
		return "", errors.New("volume_path contains path traversal")
	}
	root := filepath.Clean(volumesDir)
	p := filepath.Clean(volumePath)
	if !strings.HasPrefix(p, root+"/") {
		return "", fmt.Errorf("volume_path must be under %s", volumesDir)
	}
	rel := strings.TrimPrefix(p, root+"/")
	if rel == "" || strings.Contains(rel, "/") {
		return "", fmt.Errorf("volume_path must be a direct child of %s", volumesDir)
	}
	return rel, nil
}

// openVolumeBeneath resolves rel beneath the volumes root with
// openat2(RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS) and returns an O_PATH fd for
// the directory. Kernel resolution replaces the previous lexical prefix test:
// a symlinked volume (plantable through the virtio-fs share) can no longer
// redirect the privileged mount/umount or the marker read to another host
// path.
func openVolumeBeneath(volumesDir, rel string) (int, error) {
	rootFD, err := unix.Open(volumesDir, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, fmt.Errorf("open volumes root %s: %w", volumesDir, err)
	}
	defer unix.Close(rootFD)
	fd, err := unix.Openat2(rootFD, rel, &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS,
	})
	if err != nil {
		return -1, fmt.Errorf("open volume %s beneath %s (symlinks and escapes are refused): %w", rel, volumesDir, err)
	}
	return fd, nil
}

// handleMountOverlay mounts (or verifies) a read-only OverlayFS. The optional
// expected_template_ref is the identity record's template ref: a mismatch with
// the ref this sidecar's overlay currently serves (tracked per volume) means
// the template was swapped while this node held the old overlay — the stale
// mount is replaced from the volume's .template marker. The response carries
// the ref actually backing the mount for the sidecar's tracking.
func (s *Server) handleMountOverlay(ctx context.Context, req map[string]any) map[string]any {
	volumePath, _ := req["volume_path"].(string)
	if volumePath == "" {
		return map[string]any{"ok": false, "error": "missing volume_path"}
	}
	expectedRef, _ := req["expected_template_ref"].(string)
	cfgSnap := s.currentVMMConfig()
	rel, rerr := volumeRelPath(cfgSnap.VolumesDir, volumePath)
	if rerr != nil {
		return map[string]any{"ok": false, "error": rerr.Error()}
	}
	// The ref ends up in a refs/<name>_<version>.json path and in the marker's
	// storage-truth read: validate it with the template store's grammar before
	// it reaches either. (The store's RefToFilename only maps ':', so an
	// unvalidated '/' or '..' walks out of refs/.)
	if expectedRef != "" {
		if err := validateTemplateRef(expectedRef); err != nil {
			return map[string]any{"ok": false, "error": fmt.Sprintf("expected_template_ref rejected: %v", err)}
		}
	}
	// Kernel-resolved containment: a real directory, a direct child of the
	// volumes root, no symlink anywhere below it. Also the volume directory
	// itself must be a real directory: a symlink here would move the marker
	// read and the overlay mount to an attacker-chosen host path.
	vfd, verr := openVolumeBeneath(cfgSnap.VolumesDir, rel)
	if verr != nil {
		return map[string]any{"ok": false, "error": verr.Error()}
	}
	defer unix.Close(vfd)
	if expectedRef != "" {
		// Overlay volumes carry a storage-plane-written .template marker. Read and
		// validate it through the hardened, fd-relative reader BEFORE the
		// mount path does: a planted symlink/FIFO/device/oversized entry is
		// refused instead of silently degrading the volume to a flat mount,
		// and a marker naming a traversal-shaped ref is refused instead of
		// being routed into the refs/ store.
		if err := checkOverlayMarkerAt(vfd, volumePath); err != nil {
			return map[string]any{"ok": false, "error": err.Error()}
		}
	}
	snap := s.overlays.Snapshot()
	trackedRefPrev, tracked := snap[volumePath]
	if !tracked && len(snap) >= maxTrackedOverlays {
		return map[string]any{"ok": false, "error": fmt.Sprintf("overlay tracking limit reached (%d volumes) — refusing to track another overlay on this node", maxTrackedOverlays)}
	}
	if trackedRefPrev != "" {
		// The tracking map is boxout-owned, but a stale/edited entry must not
		// reach the same ref-file path; treat an invalid one as unknown.
		if err := validateTemplateRef(trackedRefPrev); err != nil {
			s.logger.Printf("mount_overlay: ignoring invalid tracked ref %q for %s: %v", trackedRefPrev, volumePath, err)
			trackedRefPrev = ""
		}
	}
	mountedRef, err := core.MountOverlay(volumePath, cfgSnap.TemplatesDir, expectedRef, trackedRefPrev)
	if err != nil {
		return map[string]any{"ok": false, "error": err.Error()}
	}
	// Tracking is for OVERLAY mounts only: a flat volume ("" returned by the
	// mount path) has no overlay to sweep or swap, and tracking it made every
	// flat mount pay the whole-state persist rewrite.
	if mountedRef == "" {
		if tracked {
			s.overlays.Untrack(volumePath)
			s.persistOverlayState()
		}
		return map[string]any{"ok": true, "mounted_template_ref": mountedRef}
	}
	// Track for the stale-overlay sweep + the next expected-ref comparison
	// (restore/cleanup parity with embedded mode's Handler.mountedOverlays).
	// Persist only when the tracked state actually changed.
	if !tracked || trackedRefPrev != mountedRef {
		s.overlays.Track(volumePath, mountedRef)
		s.persistOverlayState()
	}
	return map[string]any{"ok": true, "mounted_template_ref": mountedRef}
}

// maxTemplateRefLen bounds a template ref. A ref longer than a filesystem
// filename component (NAME_MAX) can never name a refs/ entry, so it is refused
// instead of being turned into an arbitrarily long path.
const maxTemplateRefLen = 255

// boxoutRefComponentRe matches one template-ref component. Mirrors the
// template store's validator (sandlot/provision/template manager.go,
// refComponentRe): alphanumeric start, then alphanumeric/dot/dash/underscore.
// That grammar excludes '/', NUL, empty components and a leading '.', so it
// also excludes '..'.
var boxoutRefComponentRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]*$`)

// validateTemplateRef applies the template store's ref rules to a ref arriving
// over the boxout RPC. A ref is "name[:version]" (bare name = version "local");
// each component must match boxoutRefComponentRe. Kept local because boxout is
// a separate module and the store's validator is unexported — the two must stay
// in sync (the ref is used to build refs/<name>_<version>.<mode>.json, where
// RefToFilename only maps ':').
func validateTemplateRef(ref string) error {
	if ref == "" {
		return errors.New("empty template ref")
	}
	if len(ref) > maxTemplateRefLen {
		return fmt.Errorf("template ref is %d bytes, above the %d-byte cap", len(ref), maxTemplateRefLen)
	}
	name, version := ref, "local"
	if n, v, ok := strings.Cut(ref, ":"); ok {
		name, version = n, v
	}
	if !boxoutRefComponentRe.MatchString(name) {
		return fmt.Errorf("invalid template ref %q: name must match ^[a-zA-Z0-9][a-zA-Z0-9._-]*$", ref)
	}
	if !boxoutRefComponentRe.MatchString(version) {
		return fmt.Errorf("invalid template ref %q: version must match ^[a-zA-Z0-9][a-zA-Z0-9._-]*$", ref)
	}
	return nil
}

// checkOverlayMarkerAt reads <volume>/.template through the volume directory
// fd with openat2(RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS) and validates the ref
// it names. In an OVERLAY volume the marker is written by the storage plane (storage truth);
// the volume root is nonetheless reached through the virtio-fs passthrough,
// so the guest can plant entries there. A symlink would turn the read into an
// arbitrary host-file read, a FIFO would block the mount path, a device node
// (/dev/zero) would balloon memory, and a ref with '/' escapes the refs/
// store. A missing marker keeps the pre-existing behavior (the core treats
// the volume as flat).
func checkOverlayMarkerAt(dirFD int, volumePath string) error {
	fd, err := unix.Openat2(dirFD, ".template", &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS,
	})
	if err != nil {
		if err == unix.ENOENT {
			return nil
		}
		return fmt.Errorf("overlay marker for %s: %w", volumePath, err)
	}
	f := os.NewFile(uintptr(fd), ".template")
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return fmt.Errorf("overlay marker for %s: %w", volumePath, err)
	}
	if !st.Mode().IsRegular() || st.Size() > util.MaxMarkerBytes {
		return fmt.Errorf("overlay marker for %s is not a regular file (planted symlink, FIFO, device node or oversized entry) — refusing the mount", volumePath)
	}
	data, err := io.ReadAll(io.LimitReader(f, util.MaxMarkerBytes))
	if err != nil {
		return fmt.Errorf("overlay marker for %s: %w", volumePath, err)
	}
	ref := strings.TrimSpace(string(data))
	if ref == "" {
		return fmt.Errorf("overlay marker for %s is empty — refusing the mount", volumePath)
	}
	if err := validateTemplateRef(ref); err != nil {
		return fmt.Errorf("overlay marker for %s names an invalid template ref: %w", volumePath, err)
	}
	return nil
}

// VolumesMountGate is the storage-plane precondition for boxout mode (the
// embedded sandlot enforces the same rule at startup): the volumes tree must
// sit on a nosuid,nodev mount, because the virtio-fs passthrough stores
// guest-requested setuid bits and mknod verbatim. Unreadable is not "probably
// fine" — the gate fails closed.
func VolumesMountGate(dir string) error {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return fmt.Errorf("volumes_dir %s could not be statfs'd (%v) — mount it nosuid,nodev, or pass -allow-insecure-volumes for a dev tree", dir, err)
	}
	if !volumesMountSecure(uint64(st.Flags)) {
		return fmt.Errorf("volumes_dir %s is not on a nosuid,nodev mount (missing %s) — the virtio-fs passthrough stores guest-planted setuid bits and device nodes verbatim, so create_vm is refused (invariant 8); fix the mount or pass -allow-insecure-volumes for a dev tree",
			dir, missingVolumeFlags(uint64(st.Flags)))
	}
	return nil
}

// checkVolumesMount applies the gate unless the explicit dev/test admission is
// set.
func (s *Server) checkVolumesMount(dir string) error {
	if s.allowInsecureVolumes {
		return nil
	}
	return VolumesMountGate(dir)
}

// volumesMountSecure is the pure predicate: both ST_NOSUID and ST_NODEV must be
// set on the mount holding the volumes tree.
func volumesMountSecure(flags uint64) bool {
	return flags&unix.ST_NOSUID != 0 && flags&unix.ST_NODEV != 0
}

// missingVolumeFlags names which required flags are absent, for the refusal
// message.
func missingVolumeFlags(flags uint64) string {
	var missing []string
	if flags&unix.ST_NOSUID == 0 {
		missing = append(missing, "nosuid")
	}
	if flags&unix.ST_NODEV == 0 {
		missing = append(missing, "nodev")
	}
	if len(missing) == 0 {
		return "neither" // unreachable from the call site; defensive
	}
	return strings.Join(missing, ",")
}

// handleVerifyVolumeID answers the exec node's cold-mount identity check
// : the volume directory must carry an identity stamp naming the
// requested sandfs. Containment is enforced here (boxout owns the volumes
// root when sandlot is unprivileged) with kernel resolution, then the
// seedless stamp check runs. The error is detailed for the sandlot's LOCAL
// log; it must not be forwarded to an agent (the volume path is a host-side
// secret).
func (s *Server) handleVerifyVolumeID(ctx context.Context, req map[string]any) map[string]any {
	volumePath, _ := req["volume_path"].(string)
	sandfsID, _ := req["sandfs_id"].(string)
	volumeEpoch, _ := req["volume_epoch"].(string)
	if volumePath == "" {
		return map[string]any{"ok": false, "error": "missing volume_path"}
	}
	if sandfsID == "" {
		return map[string]any{"ok": false, "error": "missing sandfs_id"}
	}
	cfgSnap := s.currentVMMConfig()
	rel, rerr := volumeRelPath(cfgSnap.VolumesDir, volumePath)
	if rerr != nil {
		return map[string]any{"ok": false, "error": rerr.Error()}
	}
	vfd, verr := openVolumeBeneath(cfgSnap.VolumesDir, rel)
	if verr != nil {
		return map[string]any{"ok": false, "error": verr.Error()}
	}
	_ = unix.Close(vfd)
	if err := volume.CheckVolumeID(filepath.Join(filepath.Clean(cfgSnap.VolumesDir), rel), sandfsID, volumeEpoch); err != nil {
		return map[string]any{"ok": false, "error": err.Error()}
	}
	return map[string]any{"ok": true}
}

// handleUnmountOverlay unmounts an OverlayFS.
func (s *Server) handleUnmountOverlay(ctx context.Context, req map[string]any) map[string]any {
	volumePath, _ := req["volume_path"].(string)
	if volumePath == "" {
		return map[string]any{"ok": false, "error": "missing volume_path"}
	}
	volumesDir := s.currentVMMConfig().VolumesDir
	rel, rerr := volumeRelPath(volumesDir, volumePath)
	if rerr != nil {
		return map[string]any{"ok": false, "error": rerr.Error()}
	}
	vfd, verr := openVolumeBeneath(volumesDir, rel)
	if verr != nil {
		return map[string]any{"ok": false, "error": verr.Error()}
	}
	_ = unix.Close(vfd)
	err := core.UnmountOverlay(volumePath)
	if err != nil {
		return map[string]any{"ok": false, "error": err.Error()}
	}
	// Untrack, persisting only when the tracked state actually changed: the
	// per-idle-cycle lease-expiry path unmounts flat volumes that are no
	// longer tracked at all, so it must not rewrite the state file.
	if _, tracked := s.overlays.Snapshot()[volumePath]; tracked {
		s.overlays.Untrack(volumePath)
		s.persistOverlayState()
	}
	return map[string]any{"ok": true}
}

// handleReadoptVMs scans for surviving sandvmm processes — strictly inside this
// boxout instance's OWN sandbox root.
//
// The response carries each VM's warden session key (the re-adopting sandlot
// needs it), so an accepted out-of-root sandbox_root is a confused-deputy
// primitive: a second, colocated instance could ask this sidecar to enumerate
// a sibling's VMs and hand over their keys. The root is therefore not matched
// against a path SHAPE parsed from the request; it must equal the root derived
// from this sidecar's own config, must have no symlink in any component
// (a symlinked prefix resolves the scan elsewhere while passing a string
// comparison), and the records returned are re-checked to be direct children
// of that root.
func (s *Server) handleReadoptVMs(ctx context.Context, req map[string]any) map[string]any {
	ownRoot := s.instanceSandboxRoot()
	sandboxRoot, _ := req["sandbox_root"].(string)
	if sandboxRoot == "" {
		sandboxRoot = ownRoot
	}
	if clean := filepath.Clean(sandboxRoot); clean != ownRoot {
		return map[string]any{"ok": false, "error": fmt.Sprintf(
			"sandbox_root %q is not this boxout instance's own root %q — a re-adopt scan may only return VMs this instance owns",
			sandboxRoot, ownRoot)}
	}
	if err := refuseSymlinkedPath(ownRoot); err != nil {
		return map[string]any{"ok": false, "error": fmt.Sprintf("sandbox_root refused: %v", err)}
	}

	infos, err := core.ReadoptVMsFromDisk(ctx, ownRoot, s.netProv, s.currentVMMConfig().VMMAPIAuth, s.logger, s.sandvmmIdentity())
	if err != nil {
		return map[string]any{"ok": false, "error": err.Error()}
	}

	// Defense in depth: core derives each record from a directory entry of the
	// scanned root, but the session key must never ride a record whose sandbox
	// dir is not a direct child of OUR root.
	filtered := make([]map[string]any, 0, len(infos))
	s.mu.Lock()
	if s.netLeases == nil {
		s.netLeases = make(map[string]struct{})
	}
	for _, info := range infos {
		dir, _ := info["sandbox_dir"].(string)
		if filepath.Clean(filepath.Dir(filepath.Clean(dir))) != ownRoot {
			s.logger.Printf("readopt_vms: dropping VM record %v whose sandbox dir is outside this instance's root %s",
				info["vm_id"], ownRoot)
			continue
		}
		filtered = append(filtered, info)
		// The scan just reclaimed this VM's network in-process. Register the
		// lease so release_network membership and the untracked-destroy
		// release path see it — otherwise a boxout restart orphaned every
		// surviving VM's TAP/nft rules/IP lease.
		if info["net_spec"] != nil {
			if vmID, ok := info["vm_id"].(string); ok && vmID != "" {
				s.netLeases[vmID] = struct{}{}
			}
		}
	}
	s.mu.Unlock()
	return map[string]any{"ok": true, "vms": filtered}
}

// handleRestoreOverlays rebuilds the overlay tracking set from this process's
// mountinfo, merged with the persisted ref map (mountinfo says a mount exists;
// the persisted state says WHICH template ref it serves — a restored mount
// with an unknown ref remounts once from the marker on its next mount
// command, the safe direction after a swap). In boxout mode the sidecar owns
// the mounts, so its mount namespace is the authoritative source — the mirror
// of embedded mode's restoreMountedOverlaysFromMountinfo at sandlot startup.
// Called by sandlot at its ReadoptVMs (startup) half of the reconnect-clean
// invariant.
func (s *Server) handleRestoreOverlays(ctx context.Context, req map[string]any) map[string]any {
	volumesDir := s.currentVMMConfig().VolumesDir
	if volumesDir == "" {
		volumesDir = "/var/sandswap/volumes"
	}
	n := s.overlays.RestoreFromMountinfo(volumesDir)
	merged := s.overlays.MergeRefs(core.LoadOverlayRefs(s.overlayStatePath))
	return map[string]any{"ok": true, "restored": n, "refs_merged": merged}
}

// SetOverlayStatePath wires the persistence file for the overlay tracking map
// (best-effort; lives beside the socket — node-local by design).
func (s *Server) SetOverlayStatePath(path string) {
	s.overlayStatePath = path
}

// persistOverlayState writes the tracking map atomically.
func (s *Server) persistOverlayState() {
	if s.overlayStatePath == "" {
		return
	}
	_ = core.PersistOverlayRefs(s.overlayStatePath, s.overlays.Snapshot())
}

// handleCleanupOverlays unmounts tracked overlays whose SandFS has been
// deleted while this sidecar held them (the .template marker is gone on shared
// storage). Mirrors embedded mode's cleanupStaleOverlays — the startup sweep
// half; the periodic half runs on the boxout-side reaper ticker.
func (s *Server) handleCleanupOverlays(ctx context.Context, req map[string]any) map[string]any {
	cleaned, failed := s.overlays.CleanupStale(core.UnmountOverlay)
	return map[string]any{"ok": true, "cleaned": cleaned, "failed": failed}
}

// getPeerUID returns the UID of the process on the other end of a Unix
// socket connection, using SO_PEERCRED. This is kernel-enforced and
// cannot be forged by the connecting process.
//
// The lookup goes through SyscallConn().Control rather than UnixConn.File():
// File() dup's the descriptor and can put the ORIGINAL socket into blocking
// mode, which detaches it from the runtime poller and silently disables the
// read/write deadlines this connection's RPC bounds depend on.
func getPeerUID(conn net.Conn) (uint32, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, fmt.Errorf("not a UnixConn")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cred *syscall.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if credErr != nil {
		return 0, credErr
	}
	if cred == nil {
		return 0, fmt.Errorf("SO_PEERCRED returned no credentials")
	}
	return cred.Uid, nil
}

// sendError writes an error response under the same write deadline as a normal
// response.
func (s *Server) sendError(conn net.Conn, reqType string, errMsg string) {
	resp := map[string]any{
		"type":  reqType,
		"ok":    false,
		"error": errMsg,
	}
	data, _ := json.Marshal(resp)
	_ = conn.SetWriteDeadline(time.Now().Add(s.writeDeadline()))
	_, _ = conn.Write(append(data, '\n'))
}

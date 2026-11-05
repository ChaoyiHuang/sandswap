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

package core

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"sandlot/vmm"
)

// BoxoutManager implements VMLifecycleManager by delegating to a boxout
// sidecar process over a Unix socket. Used in boxout mode (K8s DaemonSet
// where sandlot runs as the RESERVED sandbox uid 65536 with no privileges —
// k8s manifests + vsockguard pin that exact value, see
// docs/deployment/prerequisites.md).
//
// Protocol: newline-delimited JSON over Unix socket. Each request has a
// "type" field. Responses have a "type" matching the request plus an "ok"
// boolean. Error responses have an "error" string.
type BoxoutManager struct {
	socketPath  string
	sandboxRoot string // per-instance sandbox root (e.g. /run/sandswap/1/vm)
	logger      *log.Logger
	// tokenFile is the per-pod admission token shared with boxout (empty =
	// UID-only, tests/dev). It is re-read on every request so a boxout
	// restart that rotates the token heals without restarting sandlot.
	tokenFile string
}

// NewBoxoutManager creates a BoxoutManager that connects to boxout at the
// given Unix socket path. Exported for use by sandlot/cmd/main.go, which
// passes the returned manager BOTH as the VMLifecycleManager and as the
// Handler's NetworkProvider: in boxout mode boxout owns the privileged
// provider, so h.net must reach it (network provisioning aliases plus the
// optional MountGater/IdentityStamper hooks — see those methods).
func NewBoxoutManager(socketPath, tokenFile string, logger *log.Logger) *BoxoutManager {
	return &BoxoutManager{
		socketPath:  socketPath,
		sandboxRoot: defaultSandboxRoot,
		tokenFile:   tokenFile,
		logger:      logger,
	}
}

// SetSandboxRoot sets the per-instance sandbox root path.
// Must be called before ReadoptVMs if using multi-instance mode.
func (m *BoxoutManager) SetSandboxRoot(root string) {
	m.sandboxRoot = root
}

// --- JSON protocol types ---

type boxoutRequest struct {
	Type string `json:"type"`

	// create_vm
	VMID                    string         `json:"vm_id,omitempty"`
	Kernel                  string         `json:"kernel,omitempty"`
	Initramfs               string         `json:"initramfs,omitempty"`
	VolumesDir              string         `json:"volumes_dir,omitempty"`
	SandboxDir              string         `json:"sandbox_dir,omitempty"`
	GuestCID                uint32         `json:"guest_cid,omitempty"`
	VCPUs                   uint32         `json:"vcpus,omitempty"`
	MemoryMB                uint64         `json:"memory_mb,omitempty"`
	NetSpec                 *vmm.VMNetSpec `json:"net_spec,omitempty"`
	WardenCountdownSec      uint32         `json:"warden_countdown_sec,omitempty"`
	WardenMaxExecTimeoutSec uint32         `json:"warden_max_exec_timeout_sec,omitempty"`
	WardenLogLevel          string         `json:"warden_log,omitempty"`
	// WardenSessionKey is the per-VM raw-protocol key. It must ride this
	// request: boxout builds the kernel cmdline, and the sandlot outside the
	// sidecar is the only party that will authenticate to the warden.
	WardenSessionKey string `json:"warden_session_key,omitempty"`

	// destroy_vm
	APISocket string `json:"api_socket,omitempty"`
	PID       int    `json:"pid,omitempty"`
	Readopted bool   `json:"readopted,omitempty"`

	// provision_network / release_network
	// (vm_id only)

	// reclaim_network (shares NetSpec with create_vm above)

	// mount_overlay / unmount_overlay
	VolumePath string `json:"volume_path,omitempty"`
	// ExpectedTemplateRef (mount_overlay): the identity record's template ref.
	// Boxout compares it with its tracked overlay ref and remounts from the
	// volume's .template marker on a swap-stale mismatch.
	ExpectedTemplateRef string `json:"expected_template_ref,omitempty"`

	// net_stamp_identity (egress identity contract) and
	// verify_volume_id (cold-mount identity check): both carry the
	// sandfs id; the request Type selects which.
	AgentID     string `json:"agent_id,omitempty"`
	SandfsID    string `json:"sandfs_id,omitempty"`
	VolumeEpoch string `json:"volume_epoch,omitempty"`
	Epoch       uint64 `json:"epoch,omitempty"`

	// net_mount_state (mount gate; false is the meaningful value, true is a
	// faithful relay of the mount-side call)
	Mounted bool `json:"mounted"`

	// readopt_vms
	SandboxRoot string `json:"sandbox_root,omitempty"`
}

type boxoutResponse struct {
	Type  string `json:"type"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`

	// create_vm
	APISocketResp string `json:"api_socket,omitempty"`
	PIDResp       int    `json:"pid,omitempty"`

	// provision_network
	NetSpecResp *vmm.VMNetSpec `json:"net_spec,omitempty"`

	// readopt_vms
	VMs []boxoutReadoptedVM `json:"vms,omitempty"`

	// mount_overlay: the template ref actually backing the mount (the
	// marker's ref — storage truth), for the sidecar's tracking set.
	MountedTemplateRef *string `json:"mounted_template_ref,omitempty"`
}

type boxoutReadoptedVM struct {
	VMID            string          `json:"vm_id"`
	APISocket       string          `json:"api_socket"`
	GuestCID        uint32          `json:"guest_cid"`
	PID             int             `json:"pid"`
	SpecID          string          `json:"spec_id"`
	SandboxDir      string          `json:"sandbox_dir"`
	NetSpec         *vmm.VMNetSpec  `json:"net_spec"`
	Config          json.RawMessage `json:"config"`
	MountCount      uint64          `json:"mount_count"`
	MountCountedGen int64           `json:"mount_counted_gen"`
	DistinctAgents  []string        `json:"distinct_agents"`
}

// boxoutCrashEvent is the JSON message boxout sends for crash events.
type boxoutCrashEvent struct {
	Type  string `json:"type"`
	VMID  string `json:"vm_id"`
	Error string `json:"error"`
}

// --- VMLifecycleManager implementation ---

// CreateVM sends a create_vm request to boxout. Guest networking and warden
// countdown/log params ride as STRUCTURED fields (net_spec /
// warden_countdown_sec / warden_max_exec_timeout_sec / warden_log) — the
// former free-form kernel_cmdline passthrough was removed (no producer ever
// set it; an arbitrary cmdline from the unprivileged side is an unnecessary
// injection surface). NetSpec must be carried here explicitly: boxout's
// buildCmdline/buildVMCreateConfig need it for the vm.create net device and
// the warden.net_* cmdline, exactly as embedded mode gets it in-process.
func (m *BoxoutManager) CreateVM(ctx context.Context, cfg vmm.Config) (*VMLifecycleInfo, error) {
	req := boxoutRequest{
		Type:                    "create_vm",
		VMID:                    cfg.ID,
		Kernel:                  cfg.KernelPath,
		Initramfs:               cfg.InitramfsPath,
		VolumesDir:              cfg.VolumesDir,
		SandboxDir:              cfg.SandboxDir,
		GuestCID:                cfg.GuestCID,
		VCPUs:                   cfg.VCPUs,
		MemoryMB:                cfg.MemoryMB,
		NetSpec:                 cfg.NetSpec,
		WardenCountdownSec:      cfg.WardenCountdownSec,
		WardenMaxExecTimeoutSec: cfg.WardenMaxExecTimeoutSec,
		WardenLogLevel:          cfg.WardenLogLevel,
		WardenSessionKey:        cfg.WardenSessionKey,
	}
	resp, err := m.roundTrip(ctx, req)
	if err != nil {
		return nil, err
	}

	info := &VMLifecycleInfo{
		VMID:      cfg.ID,
		APISocket: resp.APISocketResp,
		GuestCID:  cfg.GuestCID,
		PID:       resp.PIDResp,
		NetSpec:   cfg.NetSpec,
	}
	return info, nil
}

// DestroyVM sends a destroy_vm request to boxout. boxout kills the process by
// PID (even when untracked) and removes state/sandbox dir via sandbox_dir.
func (m *BoxoutManager) DestroyVM(ctx context.Context, target *DestroyTarget) error {
	if target == nil {
		return nil
	}
	_, err := m.roundTrip(ctx, boxoutRequest{
		Type:       "destroy_vm",
		VMID:       target.VMID,
		APISocket:  target.APISocket,
		PID:        target.PID,
		Readopted:  target.Readopted,
		SandboxDir: target.SandboxDir,
	})
	return err
}

// ProvisionNetwork sends a provision_network request to boxout.
func (m *BoxoutManager) ProvisionNetwork(ctx context.Context, vmID string) (vmm.VMNetSpec, error) {
	resp, err := m.roundTrip(ctx, boxoutRequest{
		Type: "provision_network",
		VMID: vmID,
	})
	if err != nil {
		return vmm.VMNetSpec{}, err
	}
	if resp.NetSpecResp != nil {
		return *resp.NetSpecResp, nil
	}
	return vmm.VMNetSpec{}, nil
}

// ReleaseNetwork sends a release_network request to boxout.
func (m *BoxoutManager) ReleaseNetwork(ctx context.Context, vmID string) error {
	_, err := m.roundTrip(ctx, boxoutRequest{
		Type: "release_network",
		VMID: vmID,
	})
	return err
}

// ReclaimNetwork sends a reclaim_network request to boxout.
func (m *BoxoutManager) ReclaimNetwork(ctx context.Context, vmID string, spec vmm.VMNetSpec) error {
	_, err := m.roundTrip(ctx, boxoutRequest{
		Type:    "reclaim_network",
		VMID:    vmID,
		NetSpec: &spec,
	})
	return err
}

// MountOverlay sends a mount_overlay request to boxout. expectedRef is the
// identity record's template ref — boxout's tracking set compares it with the
// ref its mount serves and remounts from the marker on a swap-stale mismatch.
// Returns the ref actually backing the mount.
func (m *BoxoutManager) MountOverlay(ctx context.Context, volumePath, expectedRef string) (string, error) {
	resp, err := m.roundTrip(ctx, boxoutRequest{
		Type:                "mount_overlay",
		VolumePath:          volumePath,
		ExpectedTemplateRef: expectedRef,
	})
	if err != nil {
		return "", err
	}
	if resp.MountedTemplateRef != nil {
		return *resp.MountedTemplateRef, nil
	}
	return "", nil
}

// VerifyVolumeID sends a verify_volume_id request to boxout: the sidecar owns
// volumes-dir access when sandlot runs as the unprivileged reserved UID.
func (m *BoxoutManager) VerifyVolumeID(ctx context.Context, sandfsID, volumePath, volumeEpoch string) error {
	_, err := m.roundTrip(ctx, boxoutRequest{
		Type:        "verify_volume_id",
		SandfsID:    sandfsID,
		VolumePath:  volumePath,
		VolumeEpoch: volumeEpoch,
	})
	return err
}

// UnmountOverlay sends an unmount_overlay request to boxout.
func (m *BoxoutManager) UnmountOverlay(ctx context.Context, volumePath string) error {
	_, err := m.roundTrip(ctx, boxoutRequest{
		Type:       "unmount_overlay",
		VolumePath: volumePath,
	})
	return err
}

// ReadoptVMs sends a readopt_vms request to boxout and converts the response
// to []ReadoptedVMInfo.
func (m *BoxoutManager) ReadoptVMs(ctx context.Context) ([]ReadoptedVMInfo, error) {
	resp, err := m.roundTrip(ctx, boxoutRequest{
		Type:        "readopt_vms",
		SandboxRoot: m.sandboxRoot,
	})
	if err != nil {
		return nil, err
	}

	var results []ReadoptedVMInfo
	for _, vm := range resp.VMs {
		var cfg vmm.Config
		if len(vm.Config) > 0 {
			if err := json.Unmarshal(vm.Config, &cfg); err != nil {
				m.logger.Printf("re-adopt: unmarshal config for VM %s: %v", vm.VMID, err)
				continue
			}
		}
		results = append(results, ReadoptedVMInfo{
			VMID:            vm.VMID,
			APISocket:       vm.APISocket,
			GuestCID:        vm.GuestCID,
			PID:             vm.PID,
			SpecID:          vm.SpecID,
			NetSpec:         vm.NetSpec,
			SandboxDir:      vm.SandboxDir,
			Cfg:             cfg,
			MountCount:      vm.MountCount,
			MountCountedGen: vm.MountCountedGen,
			DistinctAgents:  vm.DistinctAgents,
		})
	}
	return results, nil
}

// RestoreMountedOverlays sends a restore_overlays request to boxout.
func (m *BoxoutManager) RestoreMountedOverlays() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, _ = m.roundTrip(ctx, boxoutRequest{Type: "restore_overlays"})
}

// CleanupStaleOverlays sends a cleanup_overlays request to boxout.
func (m *BoxoutManager) CleanupStaleOverlays() {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	_, _ = m.roundTrip(ctx, boxoutRequest{Type: "cleanup_overlays"})
}

// Stop is a no-op in boxout mode — the manager keeps no long-lived state
// (each roundTrip opens and closes its own socket connection).
func (m *BoxoutManager) Stop() {}

// --- vmm.NetworkProvider conformance + egress identity hooks ---
//
// In boxout mode the manager ALSO serves as the Handler's NetworkProvider
// (h.net): boxout owns the privileged provider implementation, so everything
// h.net is asked for must cross the Unix socket. Provisioning aliases below
// are the exact operations VMLifecycleManager already exposes; the identity
// hooks are how the egress-identity stamp reaches boxout's routed-ipv6
// provider (docs/how-it-works/egress-enabler.md).

// identityRelayTimeout bounds the stamp/gate round trips. binding.go calls
// these synchronously on the mount/unmount path with context.Background();
// without this bound a wedged boxout would stall mounts (and worse, unmounts)
// indefinitely. The underlying operation is µs-class netlink — this budget is
// pure transport slack.
const identityRelayTimeout = 3 * time.Second

// defaultRelayTimeout bounds every OTHER round trip whose caller supplied no
// deadline (lifecycle ops like create_vm can take seconds — the bound only
// exists so a wedged boxout turns into a bounded error, never an indefinite
// stall of the pool manager).
const defaultRelayTimeout = 60 * time.Second

// maxRelayLineLen caps one boxout response line. Responses are small JSON
// documents; a peer that streams an unterminated line cannot grow the relay's
// memory without bound.
const maxRelayLineLen = 1 << 20

// relayCtx returns ctx with the identity deadline applied when it carries
// none of its own.
func relayCtx(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return context.WithCancel(ctx) // no-op cancel keeps call sites uniform
	}
	return context.WithTimeout(ctx, identityRelayTimeout)
}

// Provision relays network provisioning (embedded-mode NetworkProvider
// contract; boxout runs it privileged).
func (m *BoxoutManager) Provision(ctx context.Context, vmID string) (vmm.VMNetSpec, error) {
	return m.ProvisionNetwork(ctx, vmID)
}

// Release relays network release.
func (m *BoxoutManager) Release(ctx context.Context, vmID string) error {
	return m.ReleaseNetwork(ctx, vmID)
}

// Reclaim relays network re-registration for a re-adopted VM.
func (m *BoxoutManager) Reclaim(ctx context.Context, vmID string, spec vmm.VMNetSpec) error {
	return m.ReclaimNetwork(ctx, vmID, spec)
}

// SetMountState implements vmm.MountGater: forward the mount/unmount state so
// boxout's provider can remove the identity stamp at unmount. Failures are
// logged and otherwise ignored — the stamp is derived state;
// a missed unstamp is self-healing (the next mount replaces the element, and
// TAP teardown at Release removes address and rules with the device).
func (m *BoxoutManager) SetMountState(ctx context.Context, vmID string, mounted bool) {
	rctx, cancel := relayCtx(ctx)
	defer cancel()
	if _, err := m.roundTrip(rctx, boxoutRequest{
		Type:    "net_mount_state",
		VMID:    vmID,
		Mounted: mounted,
	}); err != nil {
		m.logger.Printf("boxout mount-state relay %s (mounted=%v): %v", vmID, mounted, err)
	}
}

// SetMountIdentity implements vmm.IdentityStamper: forward the published
// binding so boxout stamps the TAP's egress with the identity-encoded source
// address. Strictly AFTER the binding-region publish (the caller's order) and
// failure-tolerant by contract: the region stays authoritative, egress
// degrades to unstamped ("unknown → deny" at enforcement points).
func (m *BoxoutManager) SetMountIdentity(ctx context.Context, vmID, agentID, sandfsID string, epoch uint64) {
	rctx, cancel := relayCtx(ctx)
	defer cancel()
	if _, err := m.roundTrip(rctx, boxoutRequest{
		Type:     "net_stamp_identity",
		VMID:     vmID,
		AgentID:  agentID,
		SandfsID: sandfsID,
		Epoch:    epoch,
	}); err != nil {
		m.logger.Printf("boxout identity-stamp relay %s (epoch %d): %v (egress stays unstamped)", vmID, epoch, err)
	}
}

// --- Unix socket transport ---

// roundTrip sends a request to boxout and reads the response.
func (m *BoxoutManager) roundTrip(ctx context.Context, req boxoutRequest) (*boxoutResponse, error) {
	// Always carry a deadline — for the DIAL TOO, not just the socket. Callers
	// on lifecycle paths pass a bare context; dial() polls for the socket to
	// appear and, with no deadline and no cancellation, that loop spins until
	// the process dies — the unbounded stall this file's comments promise never
	// happens ("a wedged boxout must turn into a bounded error, never an
	// indefinite stall of the pool manager").
	ctx, cancel := context.WithTimeout(ctx, defaultRelayTimeout)
	defer cancel()

	conn, err := m.dial(ctx)
	if err != nil {
		return nil, fmt.Errorf("boxout dial: %w", err)
	}
	defer conn.Close()

	deadline, _ := ctx.Deadline()
	conn.SetDeadline(deadline)

	br := bufio.NewReaderSize(conn, 4096)

	// Mutual token authentication before the request: the client proves it
	// holds the per-pod token, and the SERVER proves it holds the same secret
	// (a squatter at the socket path cannot answer the challenge). Read per
	// connection so a boxout restart that rotates the token heals without
	// restarting this process.
	if m.tokenFile != "" {
		raw, terr := os.ReadFile(m.tokenFile)
		if terr != nil {
			return nil, fmt.Errorf("boxout token: %w", terr)
		}
		if err := m.authenticate(br, conn, strings.TrimSpace(string(raw))); err != nil {
			return nil, err
		}
	}

	// Send request
	data, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("boxout marshal: %w", err)
	}
	if _, err := fmt.Fprintf(conn, "%s\n", data); err != nil {
		return nil, fmt.Errorf("boxout write: %w", err)
	}

	// Read response
	line, err := readLineFrom(br)
	if err != nil {
		return nil, fmt.Errorf("boxout read: %w", err)
	}

	var resp boxoutResponse
	if err := json.Unmarshal(line, &resp); err != nil {
		return nil, fmt.Errorf("boxout unmarshal: %w", err)
	}

	if !resp.OK {
		return nil, fmt.Errorf("boxout %s failed: %s", req.Type, resp.Error)
	}

	return &resp, nil
}

// boxoutAuthNonceBytes mirrors the server's nonce size.
const boxoutAuthNonceBytes = 32

// authMAC renders HMAC-SHA256(token, labeled message) as lowercase hex — the
// same transcript as boxout/server's authMAC.
func authMAC(token, msg string) string {
	m := hmac.New(sha256.New, []byte(token))
	_, _ = io.WriteString(m, msg)
	return hex.EncodeToString(m.Sum(nil))
}

// constantTimeMACEqual compares two hex MACs without an early exit.
func constantTimeMACEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := 0; i < len(a); i++ {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

// authenticate runs the token challenge-response with the server:
//
//	server → auth_challenge(nonce=S)
//	client → auth_response(hmac=HMAC(token,"client:"+S), nonce=C)
//	server → auth_ok(hmac=HMAC(token,"server:"+C))
//
// The final check authenticates the SERVER: only a peer holding the token can
// produce it, so a same-UID process that squatted the socket path cannot
// harvest requests or impersonate the sidecar.
func (m *BoxoutManager) authenticate(br *bufio.Reader, conn net.Conn, token string) error {
	if token == "" {
		return fmt.Errorf("boxout auth: configured token file is empty — refusing to connect without a secret")
	}
	chLine, err := readLineFrom(br)
	if err != nil {
		return fmt.Errorf("boxout auth: read challenge: %w", err)
	}
	var ch struct {
		Type  string `json:"type"`
		Nonce string `json:"nonce"`
	}
	if err := json.Unmarshal(chLine, &ch); err != nil || ch.Type != "auth_challenge" {
		return fmt.Errorf("boxout auth: expected an auth_challenge from %s (got %q) — the peer does not authenticate; refusing to send requests", m.socketPath, truncateForLog(string(chLine)))
	}
	nonce := make([]byte, boxoutAuthNonceBytes)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("boxout auth: nonce: %w", err)
	}
	nonceHex := hex.EncodeToString(nonce)
	respLine, _ := json.Marshal(map[string]any{
		"type":  "auth_response",
		"hmac":  authMAC(token, "client:"+ch.Nonce),
		"nonce": nonceHex,
	})
	if _, err := fmt.Fprintf(conn, "%s\n", respLine); err != nil {
		return fmt.Errorf("boxout auth: write response: %w", err)
	}
	okLine, err := readLineFrom(br)
	if err != nil {
		return fmt.Errorf("boxout auth: read verdict: %w", err)
	}
	var verdict struct {
		Type  string `json:"type"`
		OK    bool   `json:"ok"`
		HMAC  string `json:"hmac"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(okLine, &verdict); err != nil || verdict.Type != "auth_ok" || !verdict.OK {
		return fmt.Errorf("boxout auth refused: %s", truncateForLog(string(okLine)))
	}
	if !constantTimeMACEqual(verdict.HMAC, authMAC(token, "server:"+nonceHex)) {
		return fmt.Errorf("boxout auth: server response MAC mismatch — the peer at %s does not hold the shared token; refusing to continue", m.socketPath)
	}
	return nil
}

// truncateForLog bounds a peer-supplied line echoed into an error.
func truncateForLog(s string) string {
	const max = 200
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}

// dial connects to the boxout Unix socket, refusing anything but the expected
// socket: the path must be a Unix socket owned by root or this process and not
// group/world-writable (a same-UID squatter is possible without the directory
// isolation, and this is the file-level backstop), and the connected peer must
// be root or this process.
func (m *BoxoutManager) dial(ctx context.Context) (net.Conn, error) {
	// Wait for the socket to exist (boxout may still be starting up). One
	// re-armed ticker instead of a time.After per iteration (timer-heap
	// churn while boxout takes seconds to come up).
	poll := time.NewTicker(100 * time.Millisecond)
	defer poll.Stop()
	deadline, hasDeadline := ctx.Deadline()
	var lastErr error
	for {
		if _, statErr := os.Lstat(m.socketPath); statErr == nil {
			conn, err := dialVerified(m.socketPath)
			if err == nil {
				return conn, nil
			}
			lastErr = err
		} else {
			lastErr = statErr
		}
		if hasDeadline && time.Now().After(deadline) {
			return nil, fmt.Errorf("boxout socket %s not usable (timeout): %v", m.socketPath, lastErr)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-poll.C:
		}
	}
}

// dialVerified applies the socket-file checks and the peer-uid check.
func dialVerified(path string) (net.Conn, error) {
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		return nil, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFSOCK {
		return nil, fmt.Errorf("%s is not a unix socket (mode %04o)", path, st.Mode&0o7777)
	}
	euid := uint32(os.Geteuid())
	if st.Uid != 0 && st.Uid != euid {
		return nil, fmt.Errorf("%s is owned by uid %d, neither root nor this process (uid %d) — refusing a foreign socket", path, st.Uid, euid)
	}
	if st.Mode&0o022 != 0 {
		return nil, fmt.Errorf("%s is group/world-writable (mode %04o) — refusing to connect", path, st.Mode&0o7777)
	}
	conn, err := net.DialTimeout("unix", path, 5*time.Second)
	if err != nil {
		return nil, err
	}
	peerUID, err := unixPeerUID(conn)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("boxout peer credentials: %w", err)
	}
	if peerUID != 0 && peerUID != euid {
		_ = conn.Close()
		return nil, fmt.Errorf("boxout peer uid %d is neither root nor this process (uid %d) — refusing the connection", peerUID, euid)
	}
	return conn, nil
}

// unixPeerUID reads SO_PEERCRED from a connected Unix socket.
func unixPeerUID(conn net.Conn) (uint32, error) {
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

// readLine reads a newline-terminated line from the buffered reader, capped at
// maxRelayLineLen so a misbehaving peer cannot grow memory without bound.
func readLineFrom(br *bufio.Reader) ([]byte, error) {
	var buf []byte
	for {
		chunk, err := br.ReadSlice('\n')
		buf = append(buf, chunk...)
		if err == io.EOF && len(buf) == 0 {
			return nil, err
		}
		if err == bufio.ErrBufferFull {
			if len(buf) > maxRelayLineLen {
				return nil, fmt.Errorf("boxout response line exceeds %d bytes", maxRelayLineLen)
			}
			continue // line longer than the bufio buffer: keep reading
		}
		if err != nil {
			return nil, err
		}
		return buf[:len(buf)-1], nil // strip the newline
	}
}

// readLine reads one line from an unbuffered reader (kept for callers that do
// not share a buffered reader with a handshake).
func readLine(r io.Reader) ([]byte, error) {
	return readLineFrom(bufio.NewReaderSize(r, 4096))
}

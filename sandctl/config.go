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
//
// Package main implements sandctl, the Sandswap client CLI: the gateway HTTPS
// API client, DNS querying, and read-only pool/health views. Deployment and
// component lifecycle belong to deploy/baremetal; sandctl never starts, stops
// or configures a component.

package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// DefaultClientEnvPath is the client contract the deployers write once a
// deployment is healthy. It carries PUBLIC material only: listener URLs, the
// CA trust anchor, and (for the distributed shape) the etcd endpoint. It never
// names a private key — sandctl must not be handed a service identity's
// credential.
const DefaultClientEnvPath = "/etc/sandswap/sandctl.env"

// ClientEnvOverrideEnv names an alternative client contract file. When set,
// the file must exist and be readable; a missing override is an error rather
// than a silent fallback to the default path.
const ClientEnvOverrideEnv = "SANDSWAP_SANDCTL_ENV"

// Global holds the cross-command options resolved from defaults → client
// contract → CLI flags. Every command shares one instance (set in main).
type Global struct {
	RunDir     string // agent-key cache root (default ./run)
	BinDir     string // where output binaries live (default ./output; vendored etcdctl)
	GatewayURL string // agent listener base URL
	HumanURL   string // human listener base URL
	DNSAddr    string // DNS server address (no port → :53 implied)
	Etcd       string // etcd client endpoint (pool / dns sticky)

	// TLS for the HTTPS listeners and etcd. The client contract sets TLS=true
	// together with https URLs; the CA is the PUBLIC trust anchor.
	TLS        bool
	CA         string
	ClientCert string // optional mTLS client certificate (caller-owned)
	ClientKey  string // optional mTLS client key (caller-owned, 0600)
	Insecure   bool

	// Output controls
	Raw    bool // don't pretty-print JSON
	DryRun bool // print the HTTP request, don't send
}

// Default listener ports (the gateway contract: agent 3000, human 3100).
const (
	defaultGatewayAgentPort = 3000
	defaultGatewayHumanPort = 3100
)

// Defaults returns a Global populated with built-in defaults. Loopback is
// spelled 127.0.0.1: the gateway certs carry both localhost and 127.0.0.1,
// while a host whose `localhost` resolves to ::1 would miss a v4-only
// listener.
func Defaults() Global {
	return Global{
		RunDir:     "./run",
		BinDir:     "./output",
		GatewayURL: fmt.Sprintf("http://127.0.0.1:%d", defaultGatewayAgentPort),
		HumanURL:   fmt.Sprintf("http://127.0.0.1:%d", defaultGatewayHumanPort),
		DNSAddr:    "127.0.0.1:8053",
		Etcd:       "http://127.0.0.1:2379",
	}
}

// CertsDir is the client-side certificate directory for relative --ca /
// --client-cert paths. The deploy's CA is absolute (the client contract), so
// this only serves hand-written flag values.
func (g Global) CertsDir() string { return filepath.Join(g.RunDir, "certs") }

// AgentsFile is the local agent-key cache (0600, owned by the invoking user).
func (g Global) AgentsFile() string { return filepath.Join(g.RunDir, "agents.json") }

// CertPath resolves a cert name under CertsDir (or an explicit path as-is).
func (g Global) CertPath(name string) string {
	if filepath.IsAbs(name) {
		return name
	}
	return filepath.Join(g.CertsDir(), name)
}

// LoadEnv overlays the client contract onto g for keys the caller did not set
// on the CLI. Sources, in order:
//
//  1. SANDSWAP_SANDCTL_ENV (explicit; missing/unreadable is an ERROR)
//  2. /etc/sandswap/sandctl.env (deployer-written; absent → no env)
//
// CLI flags always win. <run-dir> holds the agent-key cache only; it is not
// a configuration source.
func (g *Global) LoadEnv(explicitSet map[string]bool) error {
	path := strings.TrimSpace(os.Getenv(ClientEnvOverrideEnv))
	explicit := path != ""
	if path == "" {
		path = DefaultClientEnvPath
	}

	data, fi, err := readClientEnv(path)
	if err != nil {
		if !explicit && errors.Is(err, os.ErrNotExist) {
			return nil // no deployment contract: built-in defaults apply
		}
		return err
	}
	// The contract names the URLs, CA and TLS toggles later commands act on,
	// and sandctl may run as root. It must be root/self-owned and not
	// group/world writable.
	if err := checkEnvFileTrust(fi); err != nil {
		return fmt.Errorf("client env %s: %w", path, err)
	}

	vals := make(map[string]string)
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		vals[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("client env %s: %w", path, err)
	}

	// Apply each env value unless the CLI set the corresponding flag
	// explicitly. flagName is the CLI flag (dashes); envName is the contract
	// key (underscores). The contract never carries run_dir: the agent cache
	// is always local to the invoking user.
	apply := func(flagName, envName string, set func(string)) {
		if explicitSet[flagName] {
			return
		}
		if v, ok := vals[envName]; ok && v != "" {
			set(v)
		}
	}
	apply("bin-dir", "bin_dir", func(v string) { g.BinDir = v })
	apply("gateway-url", "gateway_url", func(v string) { g.GatewayURL = v })
	apply("human-url", "human_url", func(v string) { g.HumanURL = v })
	apply("dns-addr", "dns_addr", func(v string) { g.DNSAddr = v })
	apply("etcd", "etcd", func(v string) { g.Etcd = v })
	apply("tls", "tls", func(v string) { g.TLS = v == "true" || v == "1" })
	apply("ca", "ca", func(v string) { g.CA = v })
	apply("client-cert", "client_cert", func(v string) { g.ClientCert = v })
	apply("client-key", "client_key", func(v string) { g.ClientKey = v })
	apply("insecure", "insecure", func(v string) { g.Insecure = v == "true" || v == "1" })
	return nil
}

// readClientEnv opens the contract without following symlinks, refuses
// anything but a small regular file, and returns its content + metadata. The
// caller applies the ownership/mode trust check.
func readClientEnv(path string) ([]byte, os.FileInfo, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("client env %s: %w", path, err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, nil, fmt.Errorf("client env %s: %w", path, err)
	}
	if !fi.Mode().IsRegular() {
		return nil, fi, fmt.Errorf("client env %s is not a regular file (mode %s)", path, fi.Mode())
	}
	if fi.Size() > maxRunFileBytes {
		return nil, fi, fmt.Errorf("client env %s is %d bytes, above the %d-byte cap",
			path, fi.Size(), maxRunFileBytes)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxRunFileBytes))
	if err != nil {
		return nil, fi, fmt.Errorf("client env %s: %w", path, err)
	}
	return data, fi, nil
}

// checkEnvFileTrust refuses a client contract that another identity wrote or
// that a group/world member can rewrite: the file names the URLs, the CA and
// the TLS toggles later commands act on.
func checkEnvFileTrust(fi os.FileInfo) error {
	sys, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	if !trustedRunFileOwner(sys.Uid) {
		return fmt.Errorf("owner uid %d is neither the invoking uid %d nor root — refusing to adopt %s",
			sys.Uid, os.Geteuid(), fi.Name())
	}
	if perm := fi.Mode().Perm(); perm&0o022 != 0 {
		return fmt.Errorf("mode %04o is group/world writable — refusing to adopt %s", perm, fi.Name())
	}
	return nil
}

// trustedRunFileOwner reports whether a client file was written by an
// identity this invocation may trust: this process or root. Client commands
// run as the invoking user; extending trust to any third uid would widen the
// client credential boundary.
func trustedRunFileOwner(owner uint32) bool {
	return owner == uint32(os.Geteuid()) || owner == 0
}

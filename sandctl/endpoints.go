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
	"net/url"
	"path/filepath"
	"strings"
)

// absRunDir resolves RunDir to an absolute path. The agent-key cache path is
// stored absolute so the cache resolves regardless of the caller's CWD.
func (g Global) absRunDir() string {
	a, err := filepath.Abs(g.RunDir)
	if err != nil {
		return g.RunDir
	}
	return a
}

// etcdLocalURL is the loopback endpoint of the etcd a deployment installs;
// the scheme follows --tls. It formats the endpoint a consumer uses when the
// configured --etcd value is the local one.
func (g Global) etcdLocalURL() string {
	if g.TLS {
		return "https://127.0.0.1:2379"
	}
	return "http://127.0.0.1:2379"
}

// etcdClientURL is the endpoint etcd-backed queries reach etcd at. An explicit
// non-loopback --etcd wins verbatim; the loopback default is recognized as
// "the local etcd" so its scheme follows --tls (and the deployer's client
// contract, which sets both consistently).
func (g Global) etcdClientURL() string {
	if g.Etcd != "" && !isLocalEtcdURL(g.Etcd) {
		return g.Etcd
	}
	return g.etcdLocalURL()
}

// isLocalEtcdURL reports whether the configured endpoint is the local etcd
// listener (loopback address on the fixed client port 2379). Anything else is
// a remote endpoint and is used verbatim.
func isLocalEtcdURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	host := u.Hostname()
	if host != "127.0.0.1" && host != "localhost" && host != "::1" {
		return false
	}
	return u.Port() == "" || u.Port() == "2379"
}

// splitHostPort splits "host:port" or "host" into host + port (default if absent).
func splitHostPort(addr, defPort string) (string, string) {
	if i := strings.LastIndex(addr, ":"); i >= 0 {
		return addr[:i], addr[i+1:]
	}
	return addr, defPort
}

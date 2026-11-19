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

package app

import (
	"crypto/tls"
	"testing"
)

// TestBuildHTTPServerTLS verifies the HTTP listener TLS builder: missing
// cert/key errors; valid material yields TLS 1.2+; a CA enables mTLS.
func TestBuildHTTPServerTLS(t *testing.T) {
	if _, err := buildHTTPServerTLS("", "", ""); err == nil {
		t.Error("expected error for missing cert/key")
	}

	ca, cert, key := genServerCert(t)
	cfg, err := buildHTTPServerTLS(cert, key, "")
	if err != nil {
		t.Fatalf("build (no CA): %v", err)
	}
	if len(cfg.Certificates) != 1 {
		t.Error("expected 1 server cert")
	}
	if cfg.MinVersion < tls.VersionTLS12 {
		t.Errorf("HTTP MinVersion = %v, want >= TLS 1.2", cfg.MinVersion)
	}

	cfgMTLS, err := buildHTTPServerTLS(cert, key, ca)
	if err != nil {
		t.Fatalf("build (mTLS): %v", err)
	}
	if cfgMTLS.ClientCAs == nil || cfgMTLS.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Error("CA should enable required-client-cert mTLS")
	}
}

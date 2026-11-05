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

package warden

import "testing"

// The per-request authentication cost is pure CPU: the nonce is a
// per-connection random prefix plus a counter (no syscall), and the tag is
// HMAC-SHA256 over a ~40-byte fixed header. These benchmarks pin that cost so
// the cold/warm latency budget can be stated with numbers, not adjectives.

var benchKey = [32]byte{0x5a}

func BenchmarkRequestTag(b *testing.B) {
	var nonce [nonceLen]byte
	var bm [bodyMACLen]byte
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		nonce[15] = byte(i)
		_ = requestTag(benchKey[:], protocolVersion, opExec, 1024, &nonce, &bm)
	}
}

func BenchmarkResponseTag(b *testing.B) {
	var nonce [nonceLen]byte
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		nonce[15] = byte(i)
		_ = responseTag(benchKey[:], &nonce, protocolVersion, codeOk, 0, 1024, 0, uint64(i), 0)
	}
}

func BenchmarkNextNonce(b *testing.B) {
	c := newClient(nil, 42, 0, benchKey[:], [8]byte{1, 2, 3, 4, 5, 6, 7, 8})
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = c.nextNonce()
	}
}

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

// The upstream forwarder lives in server.go (forwardRaw) on top of
// dns/wire.Relay: non-sandswap queries are relayed as OPAQUE bytes (EDNS,
// DNSSEC and upstream compression pass through untouched) with the transport
// following the inbound side (a TCP-originated query must not be forwarded
// over UDP — see wire.Relay). The tests are in forwarder_test.go, which keeps
// miekg/dns as a reference implementation for byte-level differential checks.

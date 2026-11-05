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

package network

import (
	"errors"
	"strings"
	"testing"
)

// The startup guard must accept ONLY the terminal drop for this bridge. A
// conditional drop (`ct state invalid drop`) is a much narrower rule; before
// this pin any line containing the bridge and "drop" satisfied the check, so a
// host missing the real guard started silently exposed.
func TestVerifyHostInputGuardRequiresTheTerminalDrop(t *testing.T) {
	chain := func(rules ...string) string {
		return "table inet sandswap {\n\tchain input {\n\t\ttype filter hook input priority filter; policy accept;\n" +
			strings.Join(rules, "\n") + "\n\t}\n}"
	}
	cases := []struct {
		name    string
		out     string
		wantErr bool
	}{
		{
			name: "terminal drop with counter",
			out: chain(
				`iifname "br-sand" ct state invalid drop # handle 3`,
				`iifname "br-sand" udp dport 53 accept # handle 4`,
				`iifname "br-sand" counter packets 12 bytes 900 drop # handle 5`,
			),
		},
		{
			name: "terminal drop without counter",
			out:  chain(`iifname "br-sand" drop # handle 9`),
		},
		{
			name:    "conditional drop alone is not the guard",
			out:     chain(`iifname "br-sand" ct state invalid drop # handle 3`),
			wantErr: true,
		},
		{
			name:    "accept rules only",
			out:     chain(`iifname "br-sand" tcp dport 53 accept # handle 4`),
			wantErr: true,
		},
		{
			name:    "drop for another bridge",
			out:     chain(`iifname "br-other" counter packets 0 bytes 0 drop # handle 5`),
			wantErr: true,
		},
		{
			name:    "prefix match must not satisfy the guard",
			out:     chain(`iifname "br-sandx" counter packets 0 bytes 0 drop # handle 5`),
			wantErr: true,
		},
		{
			// A regular/forward-hooked chain can carry the same rule text and
			// filter nothing the bridge sends to this host.
			name: "wrong hook type is not the guard",
			out: "table inet sandswap {\n\tchain input {\n\t\ttype filter hook forward priority filter; policy accept;\n" +
				`iifname "br-sand" counter packets 0 bytes 0 drop # handle 5` + "\n\t}\n}",
			wantErr: true,
		},
		{
			name: "regular chain without a hook is not the guard",
			out: "table inet sandswap {\n\tchain input {\n" +
				`iifname "br-sand" counter packets 0 bytes 0 drop # handle 5` + "\n\t}\n}",
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			old := nftListChain
			nftListChain = func(family, table, chain string) (string, error) { return tc.out, nil }
			defer func() { nftListChain = old }()
			err := VerifyHostInputGuard("br-sand")
			if (err != nil) != tc.wantErr {
				t.Fatalf("VerifyHostInputGuard error = %v, wantErr %v", err, tc.wantErr)
			}
			if tc.wantErr && err != nil && !strings.Contains(err.Error(), "terminal drop") && !strings.Contains(err.Error(), "INPUT-hook") {
				t.Fatalf("refusal must name the terminal-drop rule, got: %v", err)
			}
		})
	}

	// An unreadable chain is a refusal too (host prep never ran).
	old := nftListChain
	nftListChain = func(family, table, chain string) (string, error) { return "", errors.New("no such table") }
	defer func() { nftListChain = old }()
	if err := VerifyHostInputGuard("br-sand"); err == nil {
		t.Fatal("an absent chain must refuse startup")
	}
}

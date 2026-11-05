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
// bindregdump — inspect a Sandswap egress identity binding region.
// Ops tool and vendor reference reader: prints every occupied slot as
// `ifindex state epoch agent sandfs vm`, plus the header summary. Reads the
// region through the same mmap+seqlock path third-party enforcers use, so it
// doubles as a live sanity check of the contract.
// Usage:
//	bindregdump [-backend shm|bpf] [-path <region path>] [-watch] [-create]
// -watch polls the header's global change counter and reprints on change
// (demonstrating the documented polling pattern for enforcers).
// Default is read-only: the tool never creates a region and never holds
// write access (a root-run dump against a non-root-owned region keeps
// working). Pass -create to open writer mode — creating the region when
// absent (bootstrapping an empty one before sandlot starts, or probing
// carrier support); the writer-side owner/mode checks then apply.

package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"sandlot/bindreg"
)

func main() {
	backend := flag.String("backend", "shm", "region carrier: shm|bpf")
	path := flag.String("path", "", "region path (empty = per-backend default)")
	watch := flag.Bool("watch", false, "poll and reprint on change")
	create := flag.Bool("create", false, "open writer mode (create the region if absent)")
	flag.Parse()

	cfg := bindreg.Config{
		Backend:  bindreg.Backend(*backend),
		Path:     *path,
		ReadOnly: !*create,
	}
	region, err := bindreg.Open(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "bindregdump: %v\n", err)
		os.Exit(1)
	}
	defer region.Close()

	printRegion := func() {
		fmt.Printf("# backend=%s max_ifindex=%d global_seq=%d\n",
			*backend, region.MaxIfindex(), region.GlobalSeq())
		count := 0
		for idx := uint32(0); idx < region.MaxIfindex(); idx++ {
			e, ok, err := region.Lookup(idx)
			if err != nil || !ok {
				continue // stale read (writer in flight) or empty slot: next pass
			}
			state := "unbound"
			if e.State == bindreg.StateMounted {
				state = "mounted"
			}
			fmt.Printf("%d %s epoch=%d agent=%s sandfs=%s vm=%s\n",
				idx, state, e.MountEpoch, e.AgentID, e.SandfsID, e.VMID)
			count++
		}
		fmt.Printf("# %d entries\n", count)
	}

	if !*watch {
		printRegion()
		return
	}
	last := region.GlobalSeq()
	printRegion()
	for {
		time.Sleep(200 * time.Millisecond)
		if cur := region.GlobalSeq(); cur != last {
			last = cur
			printRegion()
		}
	}
}

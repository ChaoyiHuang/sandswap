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
	"context"
	"fmt"
	"time"
)

// quarantinedVM is a VM whose DestroyVM did not confirm death. Its CID and
// memory reservation stay held (reusing the CID while the process might still
// own the vsock device is unsafe), and the node stops creating new VMs until
// the retry loop confirms the process is gone. That is deliberately
// conservative: while the orphan is alive it may still export its old volume
// through the in-process virtio-fs filter.
type quarantinedVM struct {
	target *DestroyTarget
	cid    uint32
	memMB  uint64
}

const defaultQuarantineRetryDelay = 5 * time.Second
const maxQuarantineRetryDelay = 5 * time.Minute

// noteQuarantined records a failed destroy and starts the retry loop. The
// caller has already removed the VM from h.vms and must NOT have released its
// CID or memory reservation.
func (h *Handler) noteQuarantined(vmID string, target *DestroyTarget, cid uint32, memMB uint64) {
	if target == nil {
		return
	}
	h.quarantineMu.Lock()
	if h.quarantine == nil {
		h.quarantine = make(map[string]*quarantinedVM)
	}
	if _, exists := h.quarantine[vmID]; exists {
		h.quarantineMu.Unlock()
		return
	}
	h.quarantine[vmID] = &quarantinedVM{target: target, cid: cid, memMB: memMB}
	h.quarantineMu.Unlock()
	go h.retryQuarantinedDestroy(vmID)
}

func (h *Handler) quarantinedCount() int {
	h.quarantineMu.Lock()
	defer h.quarantineMu.Unlock()
	return len(h.quarantine)
}

func (h *Handler) retryQuarantinedDestroy(vmID string) {
	if h.vm == nil {
		return
	}
	delay := h.quarantineRetryDelay
	if delay <= 0 {
		delay = defaultQuarantineRetryDelay
	}
	for {
		time.Sleep(delay)
		h.quarantineMu.Lock()
		q := h.quarantine[vmID]
		h.quarantineMu.Unlock()
		if q == nil {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		err := h.vm.DestroyVM(ctx, q.target)
		cancel()
		if err == nil {
			// Confirmed dead: remove the quarantine BEFORE releasing the CID
			// and memory, so a concurrent CreateVerifiedVM sees the gate drop
			// only once the resources are actually reusable.
			h.quarantineMu.Lock()
			delete(h.quarantine, vmID)
			h.quarantineMu.Unlock()
			h.releaseCID(q.cid)
			if h.memLedger != nil {
				h.memLedger.release(q.memMB)
			}
			h.logger.Printf("quarantine: VM %s destroy confirmed on retry; node unquarantined", vmID)
			return
		}
		h.logger.Printf("quarantine: VM %s destroy retry failed (will retry in %s): %v", vmID, delay, err)
		if delay < maxQuarantineRetryDelay {
			delay *= 2
			if delay > maxQuarantineRetryDelay {
				delay = maxQuarantineRetryDelay
			}
		}
	}
}

// errNodeQuarantined is the named refusal returned to VM-creation callers
// while an orphan destroy is unresolved.
func (h *Handler) errNodeQuarantined() error {
	n := h.quarantinedCount()
	if n == 0 {
		return nil
	}
	return fmt.Errorf("node quarantined: %d VM(s) failed to destroy and may still hold an old volume export; refusing new VM creation until the orphan is confirmed dead (sandlot logs: quarantine)", n)
}

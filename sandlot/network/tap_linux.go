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

//go:build linux

package network

import (
	"errors"
	"fmt"
	"net"
	"unsafe"

	"golang.org/x/sys/unix"
)

// TAP lifecycle through ioctls/syscalls instead of `ip` command lines.
//
// The provider is the privileged side (sandlot embedded has CAP_NET_ADMIN,
// boxout is root), so it can drive /dev/net/tun and the interface ioctls
// directly. This removes four process spawns per VM provision (the cold
// path) and removes the PATH/argv surface entirely:
//
//   create:  TUNSETIFF + TUNSETOWNER + TUNSETPERSIST
//   master:  SIOCBRADDIF (bridge port index)
//   MTU:     SIOCSIFMTU
//   up:      SIOCGIFFLAGS + SIOCSIFFLAGS
//   delete:  RTM_DELLINK (the same kernel API `ip link del` uses)
//
// The TAP is persistent because the provider closes its fd before the VMM
// attaches by owner match. Delete goes through the existing hand-rolled
// rtnetlink helper (nl.go), so no process is spawned and no new dependency
// is introduced.

// Function vars so the provider logic is unit-testable without CAP_NET_ADMIN.
var (
	createPersistentTAPFn = createPersistentTAP
	deletePersistentTAPFn = deletePersistentTAP
	setTAPMasterFn        = setTAPMaster
	setTAPMTUFn           = setTAPMTU
	setTAPUpFn            = setTAPUp
	tapExistsFn           = tapExists
)

func tapExists(name string) bool {
	_, err := net.InterfaceByName(name)
	return err == nil
}

func tapIndex(name string) (int, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return 0, err
	}
	return iface.Index, nil
}

func openTUN(name string) (int, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, fmt.Errorf("open /dev/net/tun: %w", err)
	}
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		unix.Close(fd)
		return -1, fmt.Errorf("ifreq %q: %w", name, err)
	}
	ifr.SetUint16(unix.IFF_TAP | unix.IFF_NO_PI)
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		unix.Close(fd)
		return -1, fmt.Errorf("TUNSETIFF %q: %w", name, err)
	}
	return fd, nil
}

// tapHasAttachedQueue probes whether a process currently holds a TUNSETIFF
// binding on the persistent TAP. /sys/class/net/<tap>/tun_flags exists for the
// device's whole life once any queue was ever attached (the flaky "stale TAP
// looks active" signal); the kernel's EBUSY on a second NON-multi-queue attach
// is the real attachment test. The probe's own attach is released immediately —
// TUNSETPERSIST keeps the device, so a stale TAP is not disturbed.
func tapHasAttachedQueue(name string) (bool, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return false, fmt.Errorf("open /dev/net/tun: %w", err)
	}
	defer unix.Close(fd)
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		return false, fmt.Errorf("ifreq %q: %w", name, err)
	}
	ifr.SetUint16(unix.IFF_TAP | unix.IFF_NO_PI)
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		if errors.Is(err, unix.EBUSY) {
			return true, nil
		}
		return false, fmt.Errorf("TUNSETIFF probe %q: %w", name, err)
	}
	return false, nil
}

// tapHasAttachedQueueFn is the test seam for the attachment probe.
var tapHasAttachedQueueFn = tapHasAttachedQueue

func createPersistentTAP(name string, owner uint32) error {
	fd, err := openTUN(name)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if err := unix.IoctlSetInt(fd, unix.TUNSETOWNER, int(owner)); err != nil {
		return fmt.Errorf("TUNSETOWNER %q=%d: %w", name, owner, err)
	}
	if err := unix.IoctlSetInt(fd, unix.TUNSETPERSIST, 1); err != nil {
		return fmt.Errorf("TUNSETPERSIST %q=1: %w", name, err)
	}
	return nil
}

func deletePersistentTAP(name string) error {
	// RTM_DELLINK is the kernel API `ip link del` itself uses. It works even
	// when a process still holds an active TUNSETIFF binding (the destroy
	// path wants exactly that: the VM is going away, and its TAP must not
	// survive). A missing interface is success (idempotent Release).
	idx, err := tapIndex(name)
	if err != nil {
		if !tapExists(name) {
			return nil
		}
		return fmt.Errorf("ifindex %q: %w", name, err)
	}
	ifi := unix.IfInfomsg{Family: unix.AF_UNSPEC, Index: int32(idx)}
	payload := (*(*[unix.SizeofIfInfomsg]byte)(unsafe.Pointer(&ifi)))[:]
	msg := nlMsg(unix.RTM_DELLINK, unix.NLM_F_REQUEST|unix.NLM_F_ACK, nlSeqBase, payload, nil)
	if err := nlTalk(unix.NETLINK_ROUTE, msg); err != nil {
		return fmt.Errorf("RTM_DELLINK %q: %w", name, err)
	}
	return nil
}

func setTAPMaster(tap, bridge string) error {
	idx, err := tapIndex(tap)
	if err != nil {
		return fmt.Errorf("ifindex %q: %w", tap, err)
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("socket for SIOCBRADDIF: %w", err)
	}
	defer unix.Close(fd)
	ifr, err := unix.NewIfreq(bridge)
	if err != nil {
		return fmt.Errorf("ifreq bridge %q: %w", bridge, err)
	}
	ifr.SetUint32(uint32(idx))
	if err := unix.IoctlIfreq(fd, unix.SIOCBRADDIF, ifr); err != nil {
		return fmt.Errorf("SIOCBRADDIF %q -> %q: %w", tap, bridge, err)
	}
	return nil
}

func setTAPMTU(name string, mtu int) error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("socket for SIOCSIFMTU: %w", err)
	}
	defer unix.Close(fd)
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		return fmt.Errorf("ifreq %q: %w", name, err)
	}
	ifr.SetUint32(uint32(mtu))
	if err := unix.IoctlIfreq(fd, unix.SIOCSIFMTU, ifr); err != nil {
		return fmt.Errorf("SIOCSIFMTU %q=%d: %w", name, mtu, err)
	}
	return nil
}

func setTAPUp(name string) error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("socket for SIOCSIFFLAGS: %w", err)
	}
	defer unix.Close(fd)
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		return fmt.Errorf("ifreq %q: %w", name, err)
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, ifr); err != nil {
		return fmt.Errorf("SIOCGIFFLAGS %q: %w", name, err)
	}
	ifr.SetUint16(ifr.Uint16() | unix.IFF_UP)
	if err := unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifr); err != nil {
		return fmt.Errorf("SIOCSIFFLAGS %q up: %w", name, err)
	}
	return nil
}

---
title: Vsockguard
nav_order: 13
parent: How It Works
---

# vsockguard — BPF LSM vsock access control

> **Scope.** This page covers **active impersonation** only — a local user
> `connect()`ing to a warden and sending mount/exec frames. The complementary
> threat, **passive sniffing** of an existing sandlot↔warden vsock connection,
> is not vsockguard's job; it is prevented by the host security invariants in
> [Host Prerequisites](../deployment/prerequisites.md) (and verified by
> `security/verify-host-security.sh`). Both layers must hold.

## 1. Problem

Every Sandswap microVM's warden listens on **vsock port 1024**. Its per-frame
authentication (a 32-byte per-VM session key, delivered over the first host
connection; every request carries a tag verified before the body is read) is
what actually stops a caller who has not been handed the key. vsockguard is
**defense in depth on top of that**: it keeps every other uid from reaching
the port at all, so unauthenticated probes never reach warden parsing code.
A non-privileged local user on the sandlot host can otherwise reach any
warden with a few lines of code:

```c
int fd = socket(AF_VSOCK, SOCK_STREAM, 0);          // any UID, no device node
struct sockaddr_vm sa = { .svm_family = AF_VSOCK,
                          .svm_cid = 3,              // guest CID (guessable: 3,4,5…)
                          .svm_port = 1024 };
connect(fd, (struct sockaddr *)&sa, sizeof(sa));     // straight into the warden
// then send mount_workspace + exec frames → read/modify/delete agent data
```

The root cause: **AF_VSOCK bypasses the device nodes entirely.** Opening
the socket needs no device node — `socket(AF_VSOCK, …)` succeeds for any
uid, and the enforcement point is `connect()`. `/dev/vhost-vsock`
(0600, the sandvmm identity) only gates *CID registration* (creating a new
vsock device for a VM); it does **not** gate *connecting* to an existing
CID. So `chmod`/udev on the device nodes cannot close this path. Only an
in-kernel hook on `connect()` itself can deny it.

## 2. Solution

A BPF LSM program attached to the `socket_connect` LSM hook denies `connect()`
to `AF_VSOCK` port `1024` for every UID except one stored in a map (the sandlot
service UID, written by the loader at attach time). All other address families
and ports are passed through untouched.

**Hook coverage (defense-in-depth scope).** Only `socket_connect` is hooked:
`sendto()`/`sendmsg()` on an UNCONNECTED datagram socket do not pass through
that hook, so a DGRAM sender is not covered. The warden transport is a
connected `SOCK_STREAM` (whose `connect()` is covered), so this is a coverage
gap for the defensive layer, not a live bypass of it — a local user still
cannot drive the warden without the session key.

```
               connect(fd, {AF_VSOCK, cid, 1024})
                            │
                security_socket_connect()          ← LSM hook
                            │
                 bpf_lsm_socket_connect()          ← bpf LSM (must be active!)
                            │
                 ┌──────────▼──────────┐
                 │  vsockguard BPF prog │
                 │  uid == allowed_uid? │
                 └──────────┬──────────┘
                   no ↙           ↘ yes
              return -EPERM      return 0 (allow)
```

## 3. Files

| Path | Role |
|------|------|
| `network/vsockguard/vsockguard.bpf.c` | BPF LSM program (C, compiled by clang) |
| `network/vsockguard/vsockguardctl.c` | libbpf control tool: `attach`/`detach` (issues `BPF_LINK_CREATE`; bpftool v7.x has no LSM-link subcommand) |
| `network/vsockguard/vmlinux.h` | generated (kernel-specific, NOT committed) from `/sys/kernel/btf/vmlinux` |
| `build/build.sh` `vsockguard` target | compiles `.bpf.o` + `vsockguardctl` → `output/` |
| `security/vsockguard-attach.sh [uid]` | load + attach + seed `allowed_uid` map |
| `security/vsockguard-detach.sh` | detach + unpin |
| `security/setup-bpf-lsm.sh` | one-time kernel boot config to activate the `bpf` LSM |
| `security/vsockguard-verify.sh` | READ-ONLY enforcement check: reads the existing pin's `allowed_uid`, probes as that uid and as nobody/sandvmm, and never attaches/detaches. `--self-test` (only when NO pin exists) attaches a temporary one and detaches only what it created. |
| `e2e/` KVM test scripts (via `tc_attach_vsockguard`/`tc_cleanup_default`) | attach before the test run, detach in cleanup |
| [Host Prerequisites](../deployment/prerequisites.md) | per-node host requirements: boot config, udev, sysctls, vsockguard attach |

The hook admits the pinned service UID and **host root** (root is a trust
root — it can detach the program or read the session key anyway); every
other UID is denied the warden port. Because `/sys/fs/bpf` is root-only, the
non-root sandlot cannot read the pin itself: the root-run attach tool writes
`/run/sandswap/vsockguard.allowed_uid` **after a successful attach**, the
systemd unit re-proves the live pin in a root `ExecStartPre` at every start,
and the sandlot validates the file's root ownership/mode and uid. `detach`
removes it. Build output:
`output/vsockguard.bpf.o` + `output/vsockguardctl`. The
attachment is pinned under `/sys/fs/bpf/vsockguard/` (`prog`, `link`,
`allowed_uid`) so it survives the ctl process exiting; `detach` removes all
three.

## 4. ⚠️ Critical requirement: the `bpf` LSM must be active

BPF LSM hooks only fire if `bpf` is in the kernel's active LSM list. Many
distros (e.g. Ubuntu) ship `CONFIG_LSM` that **omits `bpf`**, so the
`bpf_lsm_socket_connect` callback is never registered. In that state:

- the BPF program **loads and "attaches" successfully** (the link pins fine), BUT
- `security_socket_connect()` **never calls** `bpf_lsm_socket_connect`, so
- the program is a **silent no-op** — `connect()` is never denied.

This is the dangerous failure mode: the tooling reports a successful
attach while enforcement is absent.

**Mitigation:** `vsockguardctl attach` **refuses to attach** unless `bpf` is
present in `/sys/kernel/security/lsm`, so the failure becomes an explicit
error instead of silent non-enforcement. To activate `bpf` (one-time, same requirement as Tetragon/Falco) — full
step-by-step in [Host Prerequisites](../deployment/prerequisites.md):

```bash
sudo bash security/setup-bpf-lsm.sh   # adds bpf to the lsm= boot parameter
sudo reboot
cat /sys/kernel/security/lsm          # must list 'bpf'
```

Then attach:

```bash
sudo bash security/vsockguard-attach.sh            # pins the sandlot SERVICE account
sudo bash security/vsockguard-attach.sh --uid 985  # explicit override
```

With no argument the tool resolves the **sandlot service account** (`id -u
sandlot`; `SANDSWAP_VSOCKGUARD_UID` overrides). It never falls back to
`SUDO_UID`: the invoking operator's uid is not the warden client, and
attaching for the wrong uid silently fences the real sandlot out.

## 5. Verify enforcement

The sanctioned end-to-end check is `security/vsockguard-verify.sh`, which
builds a tiny `socket(AF_VSOCK)+connect()` probe (`vsgtest`) and runs it
against the EXISTING pinned program: it reads the pin's `allowed_uid` and
probes as that UID (allowed) and as `nobody`/`sandvmm` (denied). It never
attaches or detaches a production pin. On a host with no pin, the explicit
`--self-test` mode attaches a temporary program, probes it, and detaches only
the pin it created; it refuses to run when a production pin is present. To
check by hand after an attach (with `bpf` LSM active):

```bash
# allowed uid (the one passed to attach) → not denied (proceeds to ECONNREFUSED,
# since nothing listens at host CID 2 — the point is it was NOT EPERM)
sudo -u '#<allowed-uid>' /tmp/vsgtest 2 1024   # → ENODEV or ECONNREFUSED

# any other uid → DENIED by vsockguard
sudo -u nobody /tmp/vsgtest 2 1024             # → EPERM ("✅ DENIED by vsockguard")

# the VMM identity (sandvmm, 987) → DENIED — it must never reach the warden port
sudo -u sandvmm /tmp/vsgtest 2 1024            # → EPERM
```

`EPERM`/`EACCES` = hook fired and denied; any other errno on the non-allowed
UID = the hook is NOT firing (re-check the `bpf` LSM list). The sanctioned
`vsockguard-verify.sh` runs exactly these three probes — root allowed,
`nobody` denied, `sandvmm` denied — as its pass/fail gate.

## 6. Operational notes

- **Root can always bypass.** Root can `bpftool link detach` the program or
  `cat /proc/<vmm_pid>/mem`. This is consistent with the KVM trust model: a
  user who controls the hypervisor host owns all VMs. vsockguard closes the
  *non-privileged local user* path only.
- **Guest-to-guest is neither blocked by this filter nor routed by the
  host — measured, not assumed.** The hook keys on the *host* UID, and a
  guest's `connect()` carries no host UID, so this filter is not what
  confines a guest. Measured on the shipped stack: a guest's
  `connect()` to another VM's CID times out (with or without the host's
  `vsock_loopback` loaded), and to its own CID — the warden's real port — it
  fails `ENODEV`, because the shipped guest kernel has no vsock loopback
  transport. Both are kernel/config properties, not designed controls — which
  is why the raw protocol now authenticates every frame independently of the
  transport: each VM has a 32-byte session key (minted by the sandlot at
  creation and delivered over the first host connection via
  `OP_KEY_DELIVERY`; never on the kernel command line), every request
  carries a nonce + HMAC-SHA256
  tag verified before the body is read, and every response carries a tag
  bound to that nonce. vsockguard is therefore defense-in-depth, not the
  boundary: a kernel/transport change that made the port reachable in-guest
  would still meet the per-frame authentication ([Isolation and
  Swap](isolation-and-swap.md), "The warden's vsock port").
- **No fail-open window in the attach flow.** The ctl seeds `allowed_uid`
  BEFORE the LSM link attaches, and the single-entry map exists from load
  time — so the program's `!allowed` branch is defensive and unreachable:
  the configured UID governs every decision from the first one. (The old
  "briefly fail-open before the loader seeds" wording described an earlier
  design, not this one.)
- **Pass the sandlot UID explicitly.** With no argument,
  `vsockguard-attach.sh` allows the *invoking* user's UID (`SUDO_UID`) —
  convenient on an interactive development machine, wrong on a node: the
  sandlot service account would be denied every warden connect (a visible
  failure, not a security hole). Production deploys and the e2e harness
  always pass the explicit UID (985).
- **Idempotent.** `vsockguard-attach.sh` detaches any prior attachment first;
  `vsockguard-detach.sh` is a no-op if not attached.

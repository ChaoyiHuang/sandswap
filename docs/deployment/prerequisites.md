---
title: Host Prerequisites
nav_order: 1
parent: Deployment
---

# Host Prerequisites

What every machine must satisfy **before** Sandswap is installed on it.
The page is organized by theme:

- §2 — kernel, hardware, and the bpf LSM (the platform everything runs on);
- §3 — service identities;
- §4 — vsock transport protection: the threat, the data path, and the
  controls that close it (vsockguard, sysctls, device nodes) with the
  sufficiency argument at the end;
- §5–§6 — the volumes mount flags and clock synchronization;
- §7 — the egress identity binding region (enabler nodes only), with its
  own threat model and controls;
- §8 — verification and the summary checklist.

The requirements are the same for bare-metal and Kubernetes deployments
unless a section says otherwise — differences are called out inline and
consolidated in the tables of §3 and §7.5.

## 1. Pre-deploy checklist (every node)

Run each check on every node, in order. The sanctioned sweep at the end
exits non-zero on any failed invariant — run it after setup and after any
kernel or sysctl change:

| # | Check | Command | Expected | Fixed by |
|---|---|---|---|---|
| 1 | kernel, KVM, vhost-vsock (sandlot hosts) | `uname -r && ls /dev/kvm /dev/vhost-vsock` | kernel ≥ 5.10; both device paths exist | [§2.1](#21-kernel-version-and-kvmvhost-vsock-devices) |
| 2 | `bpf` LSM active | `cat /sys/kernel/security/lsm` | contains the token `bpf` | [§2.2](#22-bpf-lsm-activation-boot-time-reboot-required) |
| 3 | anti-sniff sysctls | `cat /proc/sys/kernel/yama/ptrace_scope /proc/sys/kernel/perf_event_paranoid` | ≥ 1 and ≥ 2 | [§4.3](#43-anti-sniff-sysctls) |
| 4 | device nodes not world-open | `ls -l /dev/kvm /dev/vhost-vsock /dev/vsock /dev/net/tun` | `/dev/kvm` exactly `0660 root:kvm`; the rest `0660`/`0600` with pinned owners — never `0666` | [§4.4](#44-device-node-permissions-udev-lockdown) |
| 5 | service identities exist | `id sandlot && id sandvmm` (+ `id sandserv && id sandprov` on bare metal) | all resolve, non-login | [§3](#3-service-identities) |
| 6 | volumes mount flags (shared-storage nodes) | `findmnt -T <vol_root> -n -o OPTIONS` | contains `nosuid,nodev` | [§5](#5-volumes-filesystem-mount-flags-nosuidnodev) |
| 7 | network isolation baseline (VM-serving nodes) | `command -v nft && nft list table netdev sandswap_baseline` | `nft` present; the table exists once a sandlot runs | [§2.6](#26-nftables-network-isolation-baseline) |
| 8 | full invariant sweep | `sudo bash security/verify-host-security.sh` | exit 0, remediation hints on failure | [§8](#8-verification-and-summary-checklist) |

## 2. Kernel, hardware, and LSM

### 2.1 Kernel version and KVM/vhost-vsock devices

Every node that runs microVMs (exec sandlot nodes, both modes) needs:

- kernel ≥ 5.10;
- `/dev/kvm` (hardware virtualization);
- `/dev/vhost-vsock` — `modprobe vhost_vsock`, persisted via
  `/etc/modules-load.d/sandswap.conf` (both `setup-host.sh` and
  `deploy/k8s/k8s-host-setup.sh` do this; a node that has not loaded the
  module since boot has no node for the udev rule to bind, which
  crash-loops an ownership-checking pod).

Most managed Kubernetes node pools rule themselves out here — bring your
own nodes or metal. Gateway-only hosts (human gateways, prov sandlots on
storage-only hosts) need none of this.

### 2.2 bpf LSM activation (boot-time; reboot required)

vsockguard attaches a BPF LSM program to `socket_connect`. BPF LSM hooks
only fire if `bpf` is in the kernel's active LSM list. **Most distros
(Ubuntu, Debian) ship `CONFIG_LSM` without `bpf`**, so without this step an
attached program is a **silent no-op** — the link pins fine but `connect()`
is never denied. The loader refuses to attach in that state.

Check whether it is already active:

```bash
cat /sys/kernel/security/lsm
# must contain the token "bpf", e.g.:
# lockdown,capability,landlock,yama,apparmor,ima,evm,bpf
```

If `bpf` is absent, the helper script applies the boot config
(idempotent; Debian/Ubuntu GRUB):

```bash
sudo bash security/setup-bpf-lsm.sh
sudo reboot
```

`setup-bpf-lsm.sh` resolves the **effective** `GRUB_CMDLINE_LINUX_DEFAULT`
definition (see the cloud-image override note below), appends `,bpf` to the
existing LSM list inside an `lsm=` token, runs `update-grub`, and verifies
`lsm=...bpf` actually reached `/boot/grub/grub.cfg` — exiting non-zero if
it did not.

What it does, spelled out (for non-Debian or manual application):

1. Find which file **last** defines `GRUB_CMDLINE_LINUX_DEFAULT`. GRUB
   sources `/etc/default/grub` then `/etc/default/grub.d/*.cfg` in lexical
   order; a **later assignment wins**. Set the `lsm=` token there (or, if
   none exists, in `/etc/default/grub`):

   ```
   lsm=lockdown,capability,landlock,yama,apparmor,ima,evm,bpf
   ```

   Use the **current** list from `cat /sys/kernel/security/lsm` with `,bpf`
   appended — do **not** drop existing LSMs (landlock/apparmor/etc.). If an
   `lsm=` token is already present, replace it; otherwise append it.

2. Regenerate the GRUB config:

   ```bash
   sudo update-grub          # Debian/Ubuntu
   # or, on RHEL/Fedora:
   sudo grub2-mkconfig -o /boot/grub2/grub.cfg
   ```

3. Verify the change reached the actual boot config (the common failure
   mode):

   ```bash
   grep -o 'lsm=[^ ]*' /boot/grub/grub.cfg   # must show ...bpf
   ```

4. Reboot, then verify `cat /sys/kernel/security/lsm` lists `bpf`.

> This is the same one-time requirement as Tetragon / Falco / systemd's
> BPF LSM features. It is a boot-time setting — there is no runtime toggle.

**Cloud-image override trap (GCP / AWS / Azure Ubuntu images).** On cloud
Ubuntu images, `/etc/default/grub.d/50-cloudimg-settings.cfg` redefines
`GRUB_CMDLINE_LINUX_DEFAULT="console=ttyS0,115200"`. Because it is sourced
*after* `/etc/default/grub`, it overrides any `lsm=` you put in
`/etc/default/grub` — and `update-grub` produces a `grub.cfg` with **no
`lsm=`** at all. The result: a green-looking script run, but `bpf` never
activates after reboot, and vsockguard stays a silent no-op.
`setup-bpf-lsm.sh` handles this by editing the effective (last-sourced)
file and verifying `grub.cfg` post-`update-grub`. If you apply the change
manually, edit `50-cloudimg-settings.cfg` (or whichever `grub.d/*.cfg` is
the effective one), not `/etc/default/grub`.

### 2.3 Kernel configuration requirements

At runtime the kernel must have `CONFIG_BPF_LSM=y` and
`CONFIG_DEBUG_INFO_BTF=y` (virtually all modern GCP/AWS/Azure kernels do):

```bash
grep -E 'CONFIG_BPF_LSM|CONFIG_DEBUG_INFO_BTF' /boot/config-$(uname -r)
# CONFIG_BPF_LSM=y
# CONFIG_DEBUG_INFO_BTF=y
```

### 2.4 TAP device access (`/dev/net/tun`)

The VM networking path creates per-VM TAP devices, so the VMM identity
needs `/dev/net/tun`. Bare-metal host prep installs a udev rule
(`0660`, group `kvm` — the same admission group as `/dev/kvm`; every
VM-creating identity is already a kvm member) as part of `setup-host.sh`.
In Kubernetes the device reaches the pod via the injected device grants
(§3, mode table).

### 2.5 Build prerequisites (build hosts only)

Nodes that only RUN Sandswap need no toolchain. The host that builds
vsockguard (or runs `build.sh`) needs:

```bash
sudo apt install -y clang libbpf-dev bpftool   # vsockguard build (BPF C + libbpf control tool)
sudo apt install -y busybox-static             # initramfs
```

The Go and Rust toolchains are **pinned, version-exact installs** (Go 1.26.3,
Rust 1.99.1 — see [Building §1](../building/index.md#1-build-requirements));
`sudo bash build/install-deps.sh` installs both idempotently with the warden
musl target. A distro `rustc` package or an unpinned rustup default is not a
substitute — only the pinned versions are validated. `bpftool` is not needed
at runtime.

### 2.6 nftables network isolation baseline (runtime nodes with a network backend)

Every tenant TAP is enslaved to one shared L2 bridge, so the network
isolation between tenants is NOT the bridge — it is the nftables baseline
the sandlot installs: the per-TAP source anti-spoof (a guest may only emit
its assigned address), the bridge-forward VM-to-VM deny (tenant↔tenant
frames are dropped), and the guest→host default-deny allowlist on the
bridge interface (guests may reach only the DNS resolver; every host
listener — agent/human/stream included — is unreachable over the
bridge IP).

Runtime nodes with `network.backend: bridge` or `routed-ipv6` therefore
need `nftables` installed, and the requirement is **fail-closed**: a
sandlot configured for networking refuses to start when `nft` is missing
or the baseline tables cannot be installed, instead of serving tenants on
an unfiltered shared bridge. The guest→host input chain itself is installed
by host prep (`common/sh/runtime.sh`; `SS_HOST_ALLOW_PORTS` extends the
allowlist); on the bridge backend the sandlot additionally verifies at
startup that the chain carries a drop rule scoped to ITS bridge and refuses
to start when it is absent (a skipped host prep, a renamed bridge, or
flushed rules must not become a silent exposure).

Guest egress through the host IP stack is governed by the `inet sandswap`
table's **forward** chain, not by iptables: the deployer installs it as one
`nft -f` transaction — a metadata/link-local DROP
(`169.254.0.0/16`, `100.100.100.200`, `169.254.170.2`), an uplink-scoped
ACCEPT for the guest subnet, an established/related ACCEPT back to the
subnet, and a TERMINAL drop for the subnet — and read-back asserts the order
(the metadata DROP must precede every ACCEPT, or an ACCEPT makes it dead).
There is no iptables FORWARD policy left to inspect; `ip_forward` is persisted only
on sandlot/bridge roles (`SANDSWAP_ENABLE_IP_FORWARD`), so a
gateway/provision-only host routes nothing for guests. Operators add
storage/cluster/management drops to the same nft table. The routed-ipv6 backend
installs its per-TAP guard itself, matching by interface (not by source
prefix, so a forged source cannot bypass it). The sanctioned opt-outs are an explicit
`network.egress_baseline: off` (accepting per-VM-only isolation) or
`network.backend: none` (offline). `security/verify-host-security.sh`
check 12 re-asserts all three layers on any host that carries the sandbox
bridge.

```bash
sudo apt install -y nftables    # runtime nodes with a network backend
```

### 2.6b Egress policy controller (external; SYN / response-stream risk)

The node-local baseline above protects the bridge and per-TAP source
identity. It does **not** protect the host's egress path from the
SYN/response-stream class: a tenant can emit packets whose replies are
expensive for the upstream, and the node has no authority over the
provider's edge. That risk is carried by a stateful **egress policy
controller** (cloud security group / provider firewall / an operator-managed
stateful firewall in front of the node) — sandswap does not integrate with
one; the deployment must supply it.

The controller must satisfy three preconditions:

1. **Stateful filtering that explicitly drops inbound bare SYN.** Inbound
   `tcp flags & (syn|ack) == syn` is dropped at the edge; only a SYN-ACK
   belonging to an existing outbound conntrack entry may enter. (An
   "established,related accept + drop" rule alone is not enough: an inbound
   bare SYN is NEW and would be admitted by a naive default.)
2. **ICMP only when related.** Unsolicited inbound echo-request/echo-reply
   is dropped; ICMP errors (`destination-unreachable`, `time-exceeded`,
   `packet-too-big`) are admitted only with `ct state related` to an
   outbound flow.
3. **Kernel backfill as depth.** The `kernel/patches/` series the build
   applies (network/UDP/IP hygiene, the futex private-hash UAF, the
   legacy-AIO/eventfd/epoll recursion, and the netlink `net_cookie`
   hashing + `sk_filter` header reset) is part of the node's defense in
   depth; keep it when re-pinning the kernel (the patch-set hash is part
   of the artifact identity).

**Acceptance procedure** (run against the deployed edge; record the
counters, not just the policy text):

```bash
# 1. Inbound bare SYN from an external host must be dropped (counter for the
#    explicit rule increments; no SYN-ACK leaves the node).
sudo conntrack -L -p tcp | grep -c 'SYN_SENT'   # baseline
sudo nft list ruleset | grep -n 'syn'           # the explicit bare-SYN drop
# From a second host: nmap -sS -Pn <node> (or hping3 -S -p <port>) → no reply.

# 2. A first packet that is a SYN-ACK (reverse-SYN injection) must be dropped:
#    it is NEW, and only conntrack-matched SYN-ACKs may pass.
sudo conntrack -F; # then send a forged SYN-ACK from a test client → counter rises, no RST/ACK.

# 3. Unsolicited ICMP echo/echo-reply must be dropped; an ICMP error related
#    to an outbound flow must pass.
ping -c1 <node>            # from outside: no reply
# start an outbound flow from the node (e.g. curl), then have the peer send
# an ICMP port-unreachable for its 5-tuple → delivered (ct state related).

# 4. Loopback/SYN hygiene backfill present: the kernel patch-set hash in
#    output/vmlinux.config-rev matches the release manifest.
```

A deployment that cannot enforce (1) and (2) at its edge and also serves
untrusted tenants is outside the supported posture; the risk is
provider-side, not tunable inside the guest or the node.

### 2.7 Stream mTLS certificates (every node)

The gateway↔sandlot stream is mutually authenticated and **always**
certificate-bearing (even with `--no-tls` for the HTTP listeners). Each node
gets its own client certificate, and the certificate is the whole
authorization surface:

- **CN = node id** — the gateway binds `hello.node_id` to the certificate CN
  by exact match (a shared deployment certificate is refused by name).
- **Roles live in URI SANs** — `sandswap://role/exec` and/or
  `sandswap://role/prov`. A connection may advertise only roles its
  certificate grants; a certificate with no role URI authorizes nothing.
  Issuing a certificate for a new prov node is the ONLY step to scale
  provisioning — there is no gateway node-id allowlist to edit.
- **No CA private key on nodes** — only `ca.crt` belongs on a node. A CA key
  on the node lets the externally-exposed gateway identity mint a client
  certificate for any node id (fleet impersonation); the reference
  generators delete it after signing.

The reference generators (`deploy/baremetal/gen-baremetal-certs.sh`,
`deploy/k8s/gen-k8s-certs.sh`, `deploy/gen-certs.sh`) mint the URI SANs:
`--client-roles exec,prov` for a merged primary pair, and
`--client-cn <node-id>:prov` for a provision node. A production PKI must
carry the same URI SANs (Vault `uri_sans`, cert-manager `uris`).

## 3. Service identities

The services run under **dedicated, non-login UIDs** no untrusted user can
log in as: `ptrace_scope` (§4.3) only blocks *cross-UID* ptrace — if an
untrusted user shares the sandlot UID, they can ptrace it regardless.

**Bare metal** — `deploy/baremetal/setup-host.sh` creates the pinned set on
every node, unconditionally:

| Identity (contract-default uid) | Runs | Note |
|---|---|---|
| `sandlot` (985) | exec sandlot | the UID vsockguard allows on the warden port |
| `sandserv` (986) | exec/human gateways, sandns | no capabilities, no storage access |
| `sandvmm` (987) | every sandvmm process (VMM + its virtio-fs server) | **zero capabilities** via a setpriv wrapper; the TAP is pre-created/owned/pre-configured by the network provider |
| `sandprov` (983) | prov sandlot | the only shared-storage writer |
| `sandtmpl` (group, GID 982) | membership: `sandprov` + `sandlot` | template-store METADATA group: `refs/` is 2750 `sandtmpl`; the FUSE daemon (`sandvmm`) reads layer CONTENT through the shared volume group and is deliberately NOT a member, so it cannot enumerate refs. Pinned for shared-storage fleets like every other identity (`SS_GID_TPL`); host prep exports `SANDSWAP_TPL_GROUP` (the group name or a bare numeric GID, which is what the k8s pods carry) so the prov instance chgrps `refs/` without a group-database lookup |

The numbers above are the **contract defaults**, not a hard requirement on a
single host: the bare-metal resolver adopts an existing account with the
same name, and when a slot is occupied by a stock account (cloud images ship
`uuidd` 985 / `_chrony` 986 / `sshd` 987) it auto-picks a free system uid and
records the resolution in `/etc/sandswap/identity.env`. Every consumer —
systemd units, hand-written test units, the sandlot's VMM spawn — reads that
file, so no deploy path may hardcode 985/986/987. For a shared-storage
fleet, export the same `SS_UID_*`/`SS_GID_*` values on every node.

The full capability table is in
[Install — Bare Metal → Service identities](install-baremetal.md#10-service-identities-and-permissions).
Manually, the essentials:

```bash
sudo groupadd -r sandlot
sudo useradd -r -s /sbin/nologin -g sandlot sandlot
```

**Kubernetes** — `deploy/k8s/k8s-host-setup.sh` creates the host accounts
the node-level machinery needs:

- `sandlot` **pinned at the RESERVED sandbox UID 65536** (the pod
  manifests hardcode `runAsUser` 65536, the boxout-mode vsockguard allowlist
  and the boxout `--allowed-uid`; letting `useradd` pick an ordinary uid
  would silently mismatch them — and an ordinary uid is the defect: this uid
  is the host-identity gate to the warden port and the boxout socket, so it
  must sit **outside every range the node allocates on its own** — above
  `UID_MAX` 60000 and below the common userns subuid floor 100000, e.g.
  65536. `useradd` warns that the value is out of range; that is intended.
  The `e2e/deploy-tree-pins.sh` U22 pin asserts every manifest and deploy
  script states the SAME reserved value, so a revert to a collidable uid
  (like 1001, Ubuntu's first human user) fails the drill);
- `sandvmm` at the **host-resolved** uid (contract default 987) — the pod
  never runs as this uid; it exists purely so the udev `OWNER=` grants
  resolve to a real (never-loggable) identity. `k8s-host-setup.sh` adopts an
  existing account or auto-picks a free uid, and deploy-lib injects the
  resolved uid/gid into the manifests.

The remaining separation (sandserv/sandprov) is enforced by the pods
themselves — separate containers, not host accounts.

### Mode summary

| | Bare metal | k8s embedded | k8s boxout |
|---|---|---|---|
| sandlot runs as | `sandlot` (985) | root (UID 0, privileged container) | 65536 (reserved), all caps dropped |
| vsockguard allows | UID 985 | UID 0 | UID 65536 (reserved) |
| `/dev/kvm` + `/dev/vhost-vsock` access | systemd `SupplementaryGroups=kvm`; vsock nodes per-OWNER (§4.4) | supplemental GID injection into the pod manifest (distro GIDs differ, injected at deploy) | the boxout sidecar (root) owns the devices directly |

## 4. vsock transport protection

The warden vsock transport is what carries mount and exec commands to every
microVM, so it is the primary target for a non-root local user on an exec
sandlot node. Two attack classes shape the requirements of this section:

- **Active impersonation** — a non-root local user `connect()`s to a warden
  vsock port and sends mount/exec frames as if it were sandlot. Closed by
  **vsockguard** (§4.2), a BPF LSM hook denying the warden port to every
  UID except the one sandlot runs as.
- **Passive sniffing** — a non-root local user observes an *existing*
  sandlot↔warden vsock connection. No single control exists; it is closed
  by the combination of the anti-sniff sysctls (§4.3), the dedicated
  service identities (§3), and the locked device nodes (§4.4). vsockguard
  alone does not stop sniffing; the invariants alone do not stop
  impersonation — both layers must hold.

### 4.1 The data path has no user-space intermediary

Sandswap uses the **kernel vhost-vsock backend**: the vsock data path runs
in a kernel vhost worker, and the VMM hands guest memory + virtqueues to
that worker at device `activate()`. The consequence that matters for
sniffing:

```
sandlot ──AF_VSOCK── kernel vhost-vsock worker ── guest (warden)
            ↑                          ↑
       sandlot's own              KVM-protected
       socket buffer              guest memory
       (ptrace-protected)         (dev:kvm-gated)
```

**There is no user-space process on the data path holding plaintext
payloads.** This is the central reason sniffing is hard: there is no
middle-man process to `ptrace`. The old user-space
`VsockMuxer`/UDS-broker backend (removed) *did* hold plaintext in a
user-space process and would have been a sniff target for any same-UID
attacker — the kernel-vhost switch eliminated that surface.

The plaintext exists in exactly two places, each protected by a different
mechanism: sandlot's own socket buffers (ptrace-gated, invariant 1) and
the guest's memory (KVM-gated, invariant 4). An attacker who controls
neither endpoint cannot reach either copy.

### 4.2 vsockguard (impersonation control)

vsockguard closes the impersonation attack: a BPF LSM program on
`socket_connect` denying AF_VSOCK port 1024 for every UID except the one
sandlot runs as. Requirements: the `bpf` LSM active (§2.2) and the kernel
config from §2.3.

```bash
bash build/build.sh vsockguard     # → output/vsockguard.bpf.o + output/vsockguardctl
sudo bash security/vsockguard-attach.sh <sandlot-uid>
```

**The allowed UID must match the identity sandlot runs as on that node** —
the mode table in §3: `985` bare metal, `0` k8s embedded, `65536` (the
reserved sandbox identity) k8s boxout. The k8s deployers verify the pinned UID against the deployed mode
(a stale pin fails the preflight) and re-attach on mode change. On bare
metal, `setup-host.sh` attaches automatically with the sandlot UID.

Verify enforcement, and detach for teardown:

```bash
sudo bash security/vsockguard-verify.sh        # READ-ONLY: probes the existing pin (allowed UID vs nobody/sandvmm); no attach/detach
# On a host with NO production pin, the explicit self-test attaches a temporary one:
sudo bash security/vsockguard-verify.sh --self-test --uid 0
sudo bash security/vsockguard-detach.sh        # only for a pin this host should not keep
```

**⚠ `bpf` LSM must be active** (§2.2) or the attached program is a silent
no-op — `vsockguardctl` refuses to attach in that state;
`security/setup-bpf-lsm.sh` enables it (reboot required).

### 4.3 Anti-sniff sysctls

Two sysctls must hold so a non-root user cannot (a) ptrace the exec sandlot
to read its socket buffers, or (b) attach eBPF kprobes/tracepoints that
read the vsock payload from the kernel vhost worker. Persist them:

```bash
# blocks cross-UID ptrace of sandlot (reading its vsock socket buffer / /proc/<pid>/mem)
echo 'kernel.yama.ptrace_scope = 1' | sudo tee /etc/sysctl.d/99-sandswap-ptrace.conf
# blocks non-root eBPF/perf tracing that could read the vsock data path
echo 'kernel.perf_event_paranoid = 4' | sudo tee /etc/sysctl.d/99-sandswap-perf.conf
sudo sysctl --system >/dev/null
```

Required values: `ptrace_scope ≥ 1`, `perf_event_paranoid ≥ 2` (`4` is
strictest and is this repo's default). Both are runtime sysctls — no
reboot needed, and the `sysctl.d` drop-ins make them survive reboot. With
`ptrace_scope=1`, a process may only ptrace its own descendants; cross-UID
`PTRACE_ATTACH` returns `EPERM`, blocking the most direct sniff path.
`perf_event_paranoid=2` is the minimum that blocks `CAP_PERFMON`-less
payload tracing.

### 4.4 Device-node permissions (udev lockdown)

`/dev/kvm`, `/dev/vhost-vsock`, and `/dev/vsock` must not be world-open —
a world-open node lets a non-root user read guest memory or virtqueue
contents directly (§4.5). The udev rule pins all three:

```bash
sudo install -m 644 deploy/udev/99-sandswap-vsock.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules
sudo udevadm trigger                           # re-applies modes to existing nodes
```

This sets (see `deploy/udev/99-sandswap-vsock.rules`):

```
KERNEL=="vhost-vsock", MODE="0600", OWNER="sandvmm"
KERNEL=="vsock",       MODE="0600", OWNER="sandlot"
```

- `/dev/kvm` stays `0660 root:kvm` **exactly** — the kvm group is the standard
  grant and the only VM-creation admission, so any deviation (0640, an extra
  group) admits identities the threat model does not; the running sandlot
  identity must be a `kvm` member or every VM creation fails. `security/verify-host-security.sh`
  (check 4) asserts both, and it also covers `/dev/net/tun` (TAP creation —
  the deploy rule scopes it `0660 root:kvm`; it must never be world-writable).
- `/dev/vhost-vsock` gates **CID registration** (creating a vsock device
  for a VM). It does NOT gate `connect()` to existing CIDs (that is
  vsockguard's job), but a user who can open it can register arbitrary
  CIDs or trigger kernel issues.
- `/dev/vsock` ships `0666` by default. AF_VSOCK `connect()` does not go
  through it (vsockguard, not the node, gates connection), but it is
  tightened anyway as defense-in-depth.

The two vsock devices are **per-OWNER isolated** — exactly one process
identity each, no shared group: the sandvmm identity legitimately joins
the sandlot shared group for storage and would regain any group-granted
device. `/dev/vhost-vsock` → `sandvmm` (only the VMM registers guest
CIDs), `/dev/vsock` → `sandlot` (device-door defense in depth; the
sandvmm identity must never hold any vsock device). Installed by the udev
rule; repaired after module reloads and identity creation by
`common/sh/runtime.sh`. On bare metal the
`sandswap-vsock-retune.service` oneshot ASSERTS both devices at boot
(`/dev/vhost-vsock` must be `sandvmm:600`, `/dev/vsock` `sandlot:600`) and
fails the unit on any mismatch — a udev rule that never applied now
surfaces as a failed unit before any sandlot starts, instead of a
sandlot crash-loop. Checked by `security/verify-host-security.sh`
(check 7) and probed live by `e2e/seccomp.sh` (IdentitySplit).

### 4.5 The transport invariants and why they suffice

| # | Invariant | Required value | Blocks |
|---|-----------|----------------|-------|
| 1 | `kernel.yama.ptrace_scope` | `≥ 1` | cross-UID `ptrace` of sandlot / reading its socket buffers or `/proc/<pid>/mem` |
| 2 | `kernel.perf_event_paranoid` | `≥ 2` | eBPF kprobe/tracepoint that reads vsock payload from the kernel worker |
| 3 | sandlot/sandvmm run under a UID **not shared** with untrusted users | separate UID | same-UID `ptrace`/`/proc/<pid>/*` access (invariant 1 only blocks *cross*-UID) |
| 4 | `/dev/kvm` and `/dev/vhost-vsock` not world-accessible | `/dev/kvm` `0660 root:kvm`; the vsock nodes `0600` per-OWNER (`vhost-vsock`→`sandvmm`, `vsock`→`sandlot`) | reading guest memory / virtqueue contents directly |

A non-root attacker has four theoretical paths to vsock plaintext; each is
blocked by exactly one invariant:

| Attack path | Blocked by |
|-------------|------------|
| `ptrace` sandlot, read its socket buffer / `/proc/<pid>/mem` | #1 (ptrace_scope) + #3 (separate UID) |
| `tcpdump` / `AF_PACKET` on the vsock traffic | **N/A** — vsock has no netdev, isn't on any capture point (and `AF_PACKET` needs `CAP_NET_RAW` anyway) |
| eBPF kprobe/tracepoint reading vsock payload from the kernel worker | #2 (perf_event_paranoid) |
| open `/dev/kvm` or `/dev/vhost-vsock` to read guest memory / virtqueue | #4 (device perms) |
| ptrace a user-space vsock broker holding plaintext | **N/A** — kernel-vhost backend means no such process exists |

There is no fifth path: the plaintext lives only in sandlot's buffer
(ptrace-gated) and guest memory (KVM-gated), and no user-space process
sits between them. An attacker who is neither root, nor sandlot's UID, nor
in the kvm group cannot reach either copy.

## 5. Volumes filesystem mount flags (`nosuid,nodev`)

The virtio-fs passthrough applies guest-requested mode bits (including
setuid/setgid) and `mknod` verbatim on the host volume. A setuid binary
planted inside a guest reaches the host file intact, owned by the sandvmm
identity (987) — NOT the vsockguard-trusted uid, so the identity split
already breaks the escalation chain at the uid layer. These mount flags
are the host-side belt: they keep planted bits inert (and planted device
nodes non-devices) even on a host that skipped the split.

Mount the volumes filesystem `nosuid,nodev` (and consider `noexec` — the
host has no legitimate execution need there) on **every** consumer host of
shared storage; a missing flag on one host is a hole on that host. The
guest-side containment (the warden's `NO_NEW_PRIVS` + `nosuid` share
mounts) is asserted in `e2e/seccomp.sh`; storage-contract row 9 in
[Storage](../operations/storage.md) carries the same requirement.

```bash
findmnt -T /var/lib/sandswap -n -o TARGET,OPTIONS   # expect nosuid,nodev
# fix: remount -o remount,nosuid,nodev <mount>  + fstab entry
```

## 6. Clock synchronization and etcd lifecycle (not security invariants)

Keep gateway and sandns hosts under NTP/chrony discipline with drift well
under `route_stale_sec` (20 s default). The health key's `last_healthy_ts`
is written with the gateway's clock and compared with the sandns host's
clock; a sandns host running >20 s ahead declares every gateway dead
(cluster-wide SERVFAIL), one running behind delays death detection.

etcd lifecycle (multi-gateway deployments) — quota sizing, auto-compaction,
defrag, snapshot backup, and NOSPACE recovery — is covered in
[etcd Operations](../operations/etcd.md): revision history grows without
compaction and an exhausted quota fails the control plane closed.

## 7. Egress identity binding region (Carrier A / enabler nodes only)

This section applies only to **Carrier A** nodes running sandlot with
`-binding-backend=shm` or `-binding-backend=bpf` (the binding-region
carrier of the egress identity enabler — [Egress Enabler Contract](../how-it-works/egress-enabler.md)).
With the default `off` the region does not exist and none of this is in
play. **Carrier B** (`-network-backend=routed-ipv6` + `-iid-template`,
identity-in-IPv6 address) does not use this region; its identity is carried
in the source address (Contract §3.2). The invariants below apply only to
Carrier A. It has its own threat model, its own invariants (5–7, on top of
the transport invariants 1–4 of §4.5), and its own deployment shapes.

### 7.1 What the region is, and which half of the threat matters

The region is a node-local shared table `(tap ifindex) → {state,
mount_epoch, agent_id, sandfs_id, vm_id}` that third-party enforcers read
to attribute egress. Its two exposures are not equal:

- **Unauthorized read** = tenant-topology metadata (which TAP carries
  which agent, remount epochs). The region holds **no secrets**: the ids
  are identifiers, not credentials (identity material never enters the
  guest, and nothing credential-shaped ever enters the region). Low
  sensitivity; its main value to an attacker is targeting.
- **Unauthorized write** = identity forgery. A forged entry flips an
  unbound attachment past an enforcer's default-deny, impersonates another
  agent, or masks a live mount — poisoning every enforcement decision
  built on the region and breaking the contract's headline "identity is
  unforgeable" guarantee. **Write integrity is the hard requirement** —
  the same trust-event class as a vsockguard bypass, guarded by a
  different mechanism.

### 7.2 Why no vsockguard-style guard is needed

vsockguard must live in the kernel because AF_VSOCK `connect()` traverses
**no permission checkpoint at all** — no device node, no DAC, no
namespace. Both region carriers sit behind access control the kernel
already enforces:

| Carrier | Gate | Write set | Read set |
|---|---|---|---|
| `shm` file | ordinary file DAC (created `0640`) | owner (sandlot) only | owner + file group (true read-only sharing) |
| `bpf` pin | bpffs DAC on the pin, `CAP_BPF`/`CAP_SYS_ADMIN` to create, `unprivileged_bpf_disabled` on `bpf()` | whoever the pin's DAC allows (sandlot/boxout) | **= the write set** — opening the pin is an O_RDWR open, so read access does not exist as a separate grant (see below) |

**The `bpf` pin has no read-only access mode (empirical, kernel ≥ 5.5
uAPI).** `BPF_OBJ_GET` accepts `file_flags=0` only — `BPF_F_RDONLY` /
`BPF_F_WRONLY` are rejected (`EINVAL`) — and the resulting open is
`O_RDWR`: a caller needs **both read and write** permission on the pin
file, and the fd then permits `mmap` `PROT_WRITE` and
`BPF_MAP_UPDATE_ELEM`. Consequences:

- A `0640` pin with a "vendor read group" does **not** give the vendor
  read-only access — it locks the vendor out entirely (`EACCES` on
  `BPF_OBJ_GET`). Sharing the pin means granting write.
- Treat every group/other access bit on the pin as a **write grant**. A
  group-readable pin is by definition group-writable and trustworthy only
  while the group is dedicated (the k8s boxout handoff `0660` shape).
- Userspace consumers that must remain read-only have no pin-based path;
  kernel-context readers (tc/XDP/LSM programs) are unaffected — they reach
  the map through their own loaded program, not through the pin's DAC.

A BPF LSM `file_open` guard would duplicate the DAC decision. It remains
an option for high-assurance deployments that want a single UID allowlist
enforced independently of file modes — it is not required.

### 7.3 Invariants 5–7 (on top of invariants 1–4)

| # | Invariant | Blocks |
|---|-----------|--------|
| 5 | `shm` region file never group- or world-writable (write set = owner only); `bpf` pin never world-writable, group bits only for the dedicated sandlot/boxout gid (on a pin, group = write grant) | any other local user forging bindings |
| 6 | region owned by the sandlot identity; the writer re-verifies ownership and mode at open and refuses a foreign file loudly | pre-creation squatting / symlink planting in the world-writable `/dev/shm` (the attacker who creates the region file before sandlot's first start would own every identity sandlot publishes into it) |
| 7 | the region's group contains only trusted identities (shm: read-only vendor enforcers; bpf: the dedicated sandlot gid — group membership is write access); the sandlot UID is not shared with untrusted users (invariant 3 again) | metadata disclosure (shm); same-UID forgery (DAC cannot separate processes sharing a UID) |

### 7.4 Why these are sufficient

| Attack path | Blocked by |
|-------------|------------|
| read via group membership | **intended** — the group is the vendor enforcer interface; invariant 7 keeps it trusted |
| write as another non-root user | #5 (DAC write bits) |
| write as the same UID | #3 + #7 — same trust level as ptrace; not a *different* user's attack |
| replace the region before first start (file/symlink/hardlink in `/dev/shm`) | #6 — open-time ownership + mode check, `O_NOFOLLOW`; remediation is deleting the planted file |
| reach the map via the `bpf()` syscall | `CAP_BPF`/`unprivileged_bpf_disabled` (mind the k8s caveat in §7.5) |
| root | trust model — whoever controls the host owns all VMs (same boundary as the vsockguard bypass) |

### 7.5 Deployment shapes

- **Bare metal (embedded, sandlot as root or the sandlot account):** the
  shm file lands `0640` owned by the running uid; put the vendor
  enforcer's account in the file's group — a dedicated `sandbind`-style
  group, kept clean of everything else:

  ```bash
  sudo groupadd -r sandbind
  sudo usermod -aG sandbind <enforcer-account>
  ```

- **k8s / boxout, `bpf` carrier:** the privileged boxout sidecar creates +
  pins the region and hands it to the unprivileged sandlot as
  `chown <sandlot-uid>` `0660` — the write bit is what the unprivileged
  writer needs for its mmap. The group (the sandlot gid) must stay
  dedicated (group bits on a pin are write grants — §7.2). Never `0666`.
- **k8s, `shm` carrier is POD-LOCAL:** `/dev/shm` inside the sandlot pod
  is not the host's — an enforcer in another pod cannot read the region.
  Either hostPath-mount `/dev/shm` (the mode discipline then applies
  host-wide) or use the `bpf` carrier for cross-pod/kernel-context
  readers.
- **`unprivileged_bpf_disabled=2` caveat:** stricter is not automatically
  safer here — it can also block the `BPF_OBJ_GET` the unprivileged k8s
  sandlot writer depends on. Verify on the target kernel
  (`TestBPFUnprivilegedWrite` in `sandlot/bindreg`).
- **One writer per path:** a second sandlot instance (different uid)
  sharing a region path fails loudly at open — correct single-writer
  semantics, not a regression.
- **Readers must watch for replacement:** the region file deliberately
  survives restarts; after a delete-and-recreate (e.g. UID migration),
  old mappings keep reading the frozen old inode while publishes go to the
  new one. Enforcers watch `st_dev`/`st_ino` and treat a change as full
  invalidation ([Egress Enabler Contract](../how-it-works/egress-enabler.md) §4.6).

## 8. Verification and summary checklist

### 8.1 The invariant sweep

```bash
sudo bash security/verify-host-security.sh
```

Thirteen checks. Checks the transport invariants 1–4 (sysctls, service
account, device admissions incl. the exact `/dev/kvm` shape and
`/dev/net/tun`, per-OWNER vsock device ownership), the volumes mount flags
(§5) and **share-root permissions resolved from the configured sandlot
YAMLs** (every `microvm.volumes_dir` / template directory found, not a
hard-coded `/var/lib/sandswap`), the volume-seed scope (fails when a
sandvmm process can read it), whether the vsockguard BPF hook is actually
pinned and matches the sandlot UID (check 10), the boxout socket scoping
(check 11), the guest→host/VM-to-VM network baseline plus the HOST
`inet sandswap forward` chain — rule shape/order AND a packet probe from a
throwaway netns that must see the metadata and terminal-guest drops
increment (check 12), and the guest TCB's ownership/hash pin (check 13:
root-owned, not group/world-writable directories, `SHA256SUMS` verified
when present). On nodes with the egress identity enabler enabled it also
checks the binding region (shm owner/mode, bpffs pin/directory
permissions). `fs.protected_symlinks` and `unprivileged_bpf_disabled`
appear as advisory warnings. Exits non-zero with a remediation hint if any
invariant fails (warnings never do). Run it on every node after setup
**and** after any kernel/sysctl change — a regression in any one invariant
reopens the impersonation/sniffing/forgery surface.

### 8.2 Summary checklist

- [ ] kernel ≥ 5.10; `/dev/kvm` + `/dev/vhost-vsock` present, `vhost_vsock` persisted in `modules-load.d`
- [ ] `cat /sys/kernel/security/lsm` lists `bpf` (else `setup-bpf-lsm.sh` + reboot)
- [ ] `CONFIG_BPF_LSM=y` and `CONFIG_DEBUG_INFO_BTF=y` in the kernel config
- [ ] `clang`, `libbpf-dev` installed (build hosts); `bpftool` optional (vmlinux.h regen)
- [ ] udev rule installed → `/dev/kvm` 0660 root:kvm, `/dev/vhost-vsock`/`/dev/vsock` 0600 per-OWNER (NOT 0666)
- [ ] service identities exist, non-login, and every install path consumes the RESOLVED values (`/etc/sandswap/identity.env`); bare metal: all four + the `sandtmpl` group; k8s: `sandlot` pinned to the reserved 65536 + `sandvmm` host-resolved (contract default 987), `sandtmpl` injected as supplemental GID 982 on every exec/prov pod
- [ ] `ptrace_scope ≥ 1` and `perf_event_paranoid ≥ 2` persisted via sysctl.d
- [ ] `output/vsockguard.bpf.o` + `output/vsockguardctl` deployed to the node
- [ ] `vsockguard-attach.sh` run with the mode's UID (no argument pins the sandlot SERVICE account; k8s: 0 embedded / 65536 boxout); `vsockguard-verify.sh` passes
- [ ] volumes filesystem mounted `nosuid,nodev` on every consumer host
- [ ] `verify-host-security.sh` passes (transport invariants + volumes flags + binding-region checks hold)
- [ ] enabler nodes only: `sandbind` (or equivalent) reader group exists, region file/pin `0640`/`0660`, never group/world-writable

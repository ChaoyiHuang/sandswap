---
title: Install — Bare Metal
nav_order: 3
parent: Deployment
---

# Install — Bare Metal

> **Scope of the bundled scripts.** The deploy scripts and sample YAML
> under `deploy/baremetal/` serve two purposes in Sandswap: they are the
> executable proof that Sandswap deploys and works in each deployment mode
> (the e2e battery drives them as such), and they are reference
> implementations of the mechanics — what gets installed where, which
> units start in which order, what verification looks like. **They are not
> production scripts.** A production deployment designs its own automation
> on top of them: its own deploy scripts, its own verification, a staging
> rehearsal, and a staged production rollout.

Deploying Sandswap on VMs or physical hosts with systemd — the reference
topologies range from a single node to a production cluster. For the
Kubernetes flavors see [Install — Kubernetes](install-kubernetes.md); for
trying things out locally first, see the
[Quick Start](../getting-started/index.md). Host-level requirements
(kernel, identities, security invariants) are in
[Host Prerequisites](prerequisites.md) — this page assumes they hold.


## 1. Deployment model

The exec sandlot owns the microVM lifecycle directly — there is no
containerd/shim layer: it spawns one sandvmm process per microVM over a
Unix-socket HTTP API, provisions networking, and performs the SandFS
mounts. Sandlot dials the gateway; the gateway never connects in. Bare
metal is Sandswap's natural deployment environment.

**Bare metal runs embedded mode only**: sandlot directly launches the VMM,
provisions networking, and performs mounts. The boxout sidecar pattern is a
Kubernetes-specific privilege-splitting mode (see
[Topologies](../how-it-works/topologies.md)).

Routing in multi-gateway production is provided by sandns, the owner-aware
DNS service (etcd-driven) — the design lives in
[Ownership & DNS](../how-it-works/ownership-and-dns.md); this page covers
only its deployment and the agent-side DNS configuration.

## 2. Topologies

| | Single node | Small cluster | Production cluster |
|---|---|---|---|
| Gateway | 1, merged single-node, MemoryStore | 1 host, co-located exec + human gateways, EtcdStore | 2+ exec + 2+ human gateways, EtcdStore |
| Sandlot | 1, same host | N, separate hosts | N, separate hosts |
| etcd | none | none (optional co-located single-node) | 3-node cluster |
| DNS routing | none (localhost) | none (direct gateway address) | sandns |
| Shared storage | local disk | shared filesystem | shared filesystem |
| HTTP TLS | optional (`--no-tls` for dev; the node stream is always mTLS) | recommended | required |
| Failure recovery | none (single point) | gateway single point; sandlots scale | full-chain HA |

The production floor is redundancy for every control-plane component:
**2+ exec gateways, 2+ human gateways, 2+ prov sandlot instances** (the
storage plane), and a 3-node etcd cluster. Any single instance of those is
a single point of failure.

## 3. Prerequisites

All hosts:

| Dependency | Version | Notes |
|------|------|------|
| Linux kernel | ≥ 5.10 | vhost-vsock, BPF LSM, overlayfs |
| KVM | available | `ls /dev/kvm` exists (exec sandlot hosts) |
| vhost_vsock | module loaded | `modprobe vhost_vsock` (exec sandlot hosts) |
| BPF LSM | kernel-enabled | `/sys/kernel/security/lsm` contains `bpf` (see [Host Prerequisites §2.2](prerequisites.md#22-bpf-lsm-activation-boot-time-reboot-required)) |
| etcd | ≥ 3.5 | production cluster only |
| Shared filesystem | — | small/production clusters (Cloud FS / NFS / CephFS / …) |

One build host: Go ≥ 1.26, Rust + musl target, clang + libbpf-dev,
busybox-static (see [Building](../building/index.md) — or simply
`sudo bash build/install-deps.sh`).

## 4. Artifacts and distribution

This page assumes a released build is available — one build serves every
topology; how to produce it is [Building](../building/index.md)
(`build.sh all` emits `output/`: gateway, sandlot, sandvmm, sandns, sandctl,
warden, the guest kernel + initramfs, vsockguard, and the rootfs template).

The cluster deploy scripts prepare a self-contained stage bundle that
carries the artifacts; the operator ships it to each node, and every host
installs its own role from it. Per host, the notable destinations are:

| Artifact | Destination | On |
|------|---------|---------|
| gateway | `/usr/local/bin/sandswap-gateway` | gateway hosts |
| sandlot / sandvmm | `/usr/local/bin/sandswap-sandlot` / `-sandvmm` | exec sandlot hosts |
| sandns | `/usr/local/bin/sandns` | sandns host |
| vmlinux.bin, initramfs.cpio.gz | `/usr/local/lib/sandswap/guest/` (root:root 0755 dir, 0644 files, with a generated `SHA256SUMS`) | exec sandlot hosts — the guest kernel is the in-VM TCB; it must never live in a service-writable directory |
| vsockguard.bpf.o, vsockguardctl | `/usr/local/lib/sandswap/` / `/usr/local/bin/` | exec sandlot hosts |
| rootfs-template/ | shared `flat-templates/rootfs/v1/` | shared storage |
| certs | `/etc/sandswap/certs/` | all |
| generated YAML configs | `/etc/sandswap/*.yaml` | per role |
| systemd units | `/etc/systemd/system/sandswap-*.service` | per role |

## 5. Single-node deployment

One machine running the merged single-node gateway + an exec sandlot
(embedded mode). Local disk, optional TLS on the HTTP listeners — the
gateway↔sandlot stream always uses mTLS certificates.

```bash
sudo bash deploy/baremetal/deploy-single-node.sh [--skip-build] [--no-tls] [--keep] [--pool SPEC]
```

What it does, in order: build artifacts (or skip) → `setup-host.sh --role
all` (sysctls, `/dev/net/tun`, directories, vhost_vsock, the
`br-sandswap` bridge, vsockguard attach, udev rules) → generate TLS certs
(always: the stream requires them) → install gateway + `sandswap-gateway.service` → wait for
`/health` → install sandlot + sandvmm + kernel + initramfs + templates →
generate `sandlot.yaml` (`gateway_addr: localhost:9998`) → start
`sandswap-sandlot.service` → wait for pool readiness → write
`/etc/sandswap/sandctl.env` — the public client contract (gateway/human
URLs, TLS toggle, CA path; `root:root` `0644`, never a private key) that
`sandctl` reads automatically — → verify.

Verification:

```bash
systemctl status sandswap-gateway sandswap-sandlot
curl -sk https://localhost:3000/health
curl -sk https://localhost:3100/stats | jq .   # /stats lives on the human listener
journalctl -u sandswap-sandlot -f
```

Expected:

- `systemctl status` — both units `active (running)`; the sandlot log line
  `pool ready` after the initial VMs boot.
- `/health` — `{"status":"ok","pool":{"CLEAN":<N>,"IN_USE":0,"node_count":1}}`
  with `CLEAN` at the configured pool target.
- `journalctl -f` — heartbeat lines only in the default log level; per-op
  lines appear with `-debug`.

Day-2 checks:

```bash
# Hot-reload the pool (edit config; the watcher applies it):
sed -i 's/pool: "medium:3"/pool: "medium:5"/' /etc/sandswap/sandlot.yaml

# Graceful restart (verifies VM re-adopt):
systemctl restart sandswap-sandlot   # surviving VMs re-adopted, gateway reconciles
```

## 6. Small-cluster deployment

One gateway host + N exec sandlots, all reading/writing one shared
filesystem. Good for staging and small teams, up to ~20 concurrent agents.
The gateway host runs **exec + human gateways co-located**
(`sandswap-gateway@exec` on :3000/:9998, `@human` on :3100 with its prov
stream on :9996 — the co-located exec gateway owns :9998) against an
**EtcdStore** — identity and SandFS records survive gateway restarts. No
sandns — sandlots dial the gateway service address directly. Unless
`etcd.endpoints` points at an existing cluster, the script installs a
co-located single-node etcd (mTLS) on the gateway host; move etcd to a
3-node cluster before adding a second exec gateway.

Deployment is **local-only** (no ssh in the deployer — remote rollout is the
orchestrator's job: Ansible, rsync, or by hand). The control host prepares a
self-describing **stage bundle**; every target host installs its own role from
it:

```bash
# control host: prepare the stage (no installs):
bash deploy/baremetal/deploy-cluster-one-gw.sh --config cluster-simple.yaml --role prepare
# each target host (stage shipped alongside the tree):
bash deploy/baremetal/deploy-cluster-one-gw.sh --stage <tree>/output/baremetal-onegw --role gateway|sandlot
# single box, one command (prepare + all roles + verify):
bash deploy/baremetal/deploy-cluster-one-gw.sh --config cluster-simple.yaml
```

`cluster-simple.yaml` (full sample in
`deploy/baremetal/cluster-simple.sample.yaml`):

```yaml
gateway:
  host: gateway1.example.com    # service address; the script binds the fixed
                                # default ports 3000/3100/9998 (no per-port
                                # overrides in this file)

# etcd — OPTIONAL: omit to have the script install a co-located single-node
# etcd (mTLS) on the gateway host; set endpoints to use an existing cluster:
# etcd:
#   endpoints:
#     - "https://etcd1.example.com:2379"

shared_storage:
  type: nfs                    # nfs | cfs | cpfs | cephfs | pre-mounted
  mount_point: /mnt/sandswap   # every node mounts the same path
  nfs_server: nfs1.example.com
  nfs_export: /export/sandswap

sandlots:
  - host: sandlot1.example.com
    node_id: sandlot-1
    pool: "medium:5"
    subnet: "10.188.1.0/24"          # optional; per-node guest VM subnet
    net_gateway_ip: "10.188.1.1"     # guest-network bridge IP on that host
                                     # (optional, default 10.188.0.1; IPv4
                                     # inside subnet, .1 by convention) — NOT
                                     # the gateway service address
```

Manual equivalent — what the script does per host, step by step:

1. Mount the shared filesystem on every host (per §8).
2. Run host prep on every host. A host running a prov sandlot instance gets
   `provision` or `all`; compute nodes get `sandlot`:

   ```bash
   sudo bash deploy/baremetal/setup-host.sh --role <gateway|sandlot|provision|all>
   ```

   Sandlot hosts additionally set up KVM, `vhost_vsock`, the bridge with the
   per-node `--subnet`/`--gateway-ip`, and vsockguard. The bridge setup also
   installs an nftables input rule dropping guest-subnet traffic to the host
   control ports (3000/3001/3100/9998): a tenant must not reach the
   gateway/human API through the host end of the sandbox bridge. A
   hand-managed bridge must apply the same rule (it is in
   `deploy/setup-network.sh` via `ss_host_network_setup`).
3. Install binaries + certs, and scope the key files to the service
   identities ([§9.1](#91-private-key-ownership-on-each-node)).
4. Mint the volume-name seed on the gateway host (the script runs this
   automatically; a manual prov install must not skip it):

   ```bash
   sudo bash -c 'install -d -m 0750 /etc/sandswap && openssl rand -out /etc/sandswap/volume-seed 32'
   sudo chown root:sandprov /etc/sandswap/volume-seed && chmod 0640 /etc/sandswap/volume-seed
   ```

   See [Volume-seed rotation](#142-volume-seed-rotation) before rotating it.
5. On the gateway host, run the co-located etcd (`sandswap-etcd.service`;
   the deploy script generates this unit) and write
   `/etc/sandswap/gateway-exec.yaml` + `gateway-human.yaml` (mode
   exec/human, etcd endpoints) for `sandswap-gateway@exec`/`@human`.
6. Materialize the MCP instructions file once (the gateway runs read-only
   in production and cannot create it):

   ```bash
   /usr/local/bin/sandswap-gateway -print-mcp-instructions > /etc/sandswap/mcp-instructions.md
   ```

7. On each node, write `/etc/sandswap/sandlot.yaml`:
   `gateway_addr: "<gateway-host>:9998"`, the per-node
   `network.subnet`/`gateway`, `volumes_dir` on the shared mount.
8. Enable and start the services:

   ```bash
   sudo systemctl enable --now sandswap-etcd sandswap-gateway@exec sandswap-gateway@human sandswap-sandlot
   ```

Verify from the build host. In cluster shapes `/stats` lives on the **human
listener (`:3100`)** — scripts probing `:3000` time out:

```bash
curl -sk https://gateway1:3100/stats | jq .
```

Expected output (keys per connected node; `CLEAN` at the pool targets):

```json
{"CLEAN": 5, "IN_USE": 0, "node_count": 1}
```

Check the storage plane is reachable (`provisioners` ≥ 1 — storage ops 503
at 0):

```bash
curl -sk https://gateway1:3100/health | jq .
```

Expected output: `{"status":"ok","provisioners":1}` (no `pool` key on a
human gateway).

## 7. Production-cluster deployment

2+ exec gateways + 2+ human gateways + a 3-node etcd cluster + N exec
sandlots + 2+ prov sandlot instances + sandns, all on shared storage,
everything TLS. The bundled `deploy-cluster-multi-gw.sh` and its sample
YAML are a reference implementation of the mechanics; the shape they deploy
(one human gateway, one prov instance) is a rehearsal minimum, not the
production floor above.

Size and maintain the etcd cluster per [etcd Operations](../operations/etcd.md)
(quota, auto-compaction, backups) — the deploy scripts assume an existing
healthy cluster.

Deployment order (dependencies):

```
etcd cluster (no deps)
    ├──→ exec gateways (need etcd)
    │         └──→ sandns (needs gateway health/load keys)
    └──→ human gateway (needs etcd)
              └──→ sandlots (need the DNS stream domain + a reachable gateway stream)
```

```bash
# Prepare cluster-production.yaml (exec/human gateways, sandlots, dns, shared_storage, etcd)
bash deploy/baremetal/deploy-cluster-multi-gw.sh --config cluster-production.yaml --dry-run
bash deploy/baremetal/deploy-cluster-multi-gw.sh --config cluster-production.yaml
```

The script: builds → generates TLS certs with multi-node SANs → deploys etcd
(if needed) → installs `sandswap-gateway@exec` on each exec host and
`@human` on the human host → installs sandns on the sandns host →
installs each sandlot with `gateway_addr: "sandswap-stream.local:9998"` (a
DNS name, not a dead IP) and `/etc/resolv.conf` pointing at sandns →
verifies every `/health`, DNS resolution, and the sandlot streams.

DNS verification (manual; `sandctl dns stream|agent|resolve` performs the
same queries with a built-in resolver and needs no `dig`):

```bash
dig @dns1 sandswap.local +short
dig @dns1 sandswap-stream.local +short
dig @dns1 google.com +short
```

Expected: the first two answer an exec gateway IP (agent discovery domain /
stream domain); the third answers forwarded addresses (forwarder works). An
empty answer or SERVFAIL on the first two means the gateway registry keys
are missing — check the gateways connected to etcd.

Post-deploy, run the verification drills against the real topology. Every
etcd-backed bare-metal deployment (`deploy-one-machine-etcd.sh` and the
cluster shapes) answers these three, which break a plane and assert the
gates fire — each restores what it broke, on every exit path:

```bash
sudo bash deploy/baremetal/verify-negative-path.sh   # storage plane down → named 503 · restore · unknown template → 422 · lifecycle gate → 404
sudo bash deploy/baremetal/verify-etcd-fence.sh      # etcd partition → self-fence fires: mounts released, node streams kept, in-place recovery
sudo bash deploy/baremetal/verify-cert-rotation.sh   # rotate the whole PKI → restart every unit → re-converge → end-to-end exec on the new material
sudo bash security/verify-host-security.sh           # host invariants (device ownership, volumes mount flags, identity isolation)
```

Multi-gateway shapes additionally:

```bash
sudo bash deploy/baremetal/verify-binpack.sh   # DNS binpack concentration on a real two-gateway topology
sudo bash deploy/baremetal/verify-eino.sh      # multi-agent end-to-end (needs an LLM key)
sudo bash deploy/baremetal/verify-failover.sh  # cross-gateway failover via the DNS stream name
```

The single-node service deployment (§5) is verified by its inline checks
above; the drills need the etcd-backed topology (a `sandswap-sandlot-prov`
unit and a gateway identity to partition).

### 7.1 The etcd cluster

```bash
etcd \
  --name etcd-1 \
  --listen-client-urls https://$ETCD_IP:2379,https://127.0.0.1:2379 \
  --advertise-client-urls https://$ETCD_IP:2379 \
  --listen-peer-urls https://$ETCD_IP:2380 \
  --initial-advertise-peer-urls https://$ETCD_IP:2380 \
  --initial-cluster $ETCD_PEERS \
  --initial-cluster-token sandswap-etcd \
  --initial-cluster-state new \
  --peer-cert-file /etc/etcd/certs/etcd-server.crt \
  --peer-key-file /etc/etcd/certs/etcd-server.key \
  --peer-trusted-ca-file /etc/etcd/certs/ca.crt \
  --cert-file /etc/etcd/certs/etcd-server.crt \
  --key-file /etc/etcd/certs/etcd-server.key \
  --trusted-ca-file /etc/etcd/certs/ca.crt \
  --data-dir /var/lib/etcd/data

etcdctl --endpoints=https://etcd-1:2379 --cacert=... --cert=... --key=... endpoint health
```

Run etcd under systemd as well. The co-located variant is generated by
`deploy-one-machine-etcd.sh` (it writes `sandswap-etcd.service` inline);
`deploy/baremetal/systemd/` ships the static units only.

## 8. Shared filesystem

`vol_root` (and the template directories) must sit on storage every gateway
and sandlot can read/write concurrently.

Requirements:

| Requirement | Why |
|------|------|
| Multi-node concurrent read/write | every sandlot instance (exec and prov) touches vol_root |
| Share-root bootstrap as root | the deployment bootstraps the **share root** — the exported directory backing `vol_root` — with root privileges (mkdir/chown/setgid); with `root_squash` those operations land as `nobody` and the shared-group layout breaks. The service identities themselves never run as root ([Storage contract](../operations/storage.md)) |
| Works as overlayfs lowerdir | read-only overlay lowerdirs live here (no upperdir/workdir, so any filesystem works) |
| Hard links / rename | template-layer dedup relies on hard links |
| POSIX semantics | ordinary Linux file operations |
| Low latency | template ops and file I/O go through it |

**NFS root handling**: with the default `root_squash` (root → nobody),
the root-run bootstrap of the share root (mkdir/chown/setgid) gets
permission-denied and the shared-group layout breaks. Do that bootstrap as
**local root on the storage server** (one-time); at runtime, export with
`sec=krb5p`, or with `root_squash,all_squash` plus 2770/0660 modes and
network isolation. NFS `sec=sys` uses AUTH_SYS, whose uid/gid are
client-supplied; a reachable guest can claim uid 0 / gid 985, so a
non-squashing export is a root-equivalent grant. Never export to `*`, the
sandbox subnet, or an IP that guest traffic can NAT to; see [Storage §4](../operations/storage.md#4-production-storage-isolation-must--the-storage-service-is-not-a-tenant-network)
for the full control set. On the NFS server:

```bash
# /etc/exports — replace with the compute nodes' dedicated STORAGE IPs.
# Do NOT use '*', the sandbox subnet, or the node's general/uplink IP.
# Preferred: Kerberos (sec=krb5p). Fallback: squash all identities
# (pre-create the layout on the storage server as local root first).
# /export/sandswap <compute-node-storage-ip>(rw,sync,no_subtree_check,sec=krb5p)
/export/sandswap  <compute-node-storage-ip>(rw,sync,no_subtree_check,root_squash,all_squash)
```

Mount the export `nosuid,nodev` on every consumer host —
[Host Prerequisites §5](prerequisites.md#5-volumes-filesystem-mount-flags-nosuidnodev).

## 9. TLS certificates

`deploy/baremetal/gen-baremetal-certs.sh` generates ca/stream/mcp/admin
server certs and the sandlot **stream client certs** — one pair per node id:
the gateway binds a stream hello's declared `node_id` to the presented client
certificate's CN by **exact match** (`gateway/stream/server.go`
`verifyNodeIdentity`), and a shared deployment-wide certificate is refused by
name. The pair's CN is the node's **effective node id**: its `node_id` value
(or the `hostname` default) with `-<instance.id>` appended when the sandlot
config sets an instance id. Mint the node's own pair with
`SANDLOT_NODE_ID=<effective-id>` (the default pair, `sandlot.crt/.key`) and any
additional node id served from the same host with
`--client-cn <node-id>` (→ `sandlot-<node-id>.crt/.key`); point each instance's
`tls:` block at its own pair. For production, extend the SANs:

```bash
SANDLOT_NODE_ID="$(hostname)" bash gen-baremetal-certs.sh [cert_dir] \
    --sans-dns "sandswap.local,sandswap-stream.local,*.sandfs.sandswap.local" \
    --sans-ip "10.0.1.1,10.0.1.2" \
    --client-cn sandlot-prov          # one --client-cn per extra node id
```

SAN requirements:

| Cert | SAN must include | Why |
|------|-------------|------|
| stream.crt (gateway gRPC server) | `sandswap-stream.local` + each gateway IP | sandlots dial the DNS name; TLS validates it |
| mcp.crt (gateway agent server) | `sandswap.local` + `*.sandfs.sandswap.local` (wildcard) + **every exec gateway IP** | agents use per-sandfs URLs (wildcard), and a cross-host 307 redirect lands on `https://<owner-ip>:3000` (IP SAN) — **production certs must contain all exec gateway IPs or 307-following fails TLS** |
| admin.crt (gateway human server) | gateway IPs / names | humans reach it directly, not via DNS |
| sandlot `<pair>.crt` (client) | nothing special | the SAN is unread by the gateway — the **CN** is the identity, and it must equal the node's `node_id` exactly |

Ship each node only the pair whose CN is its own node id (plus `ca.crt`); a
pair that can claim another node's id belongs on no host but the one it names.

The certificates are not optional in any deployment shape: the gateway
refuses a certificate-less stream outright, so the bare-metal deployers'
`--no-tls` flag makes only the HTTP listeners (agent/human) plaintext — the
stream listener and every sandlot client still present mTLS certs.

### 9.1 Private-key ownership on each node

The generated keys are root-only `0600`, while the units run as dedicated
service identities — the four-identity pinned set (`sandlot` / `sandserv` /
`sandvmm` / `sandprov`; `setup-host.sh` creates it unconditionally on every
node, see [§10](#10-service-identities-and-permissions)).
After copying certs to a node,
scope each key to the identity that loads it:

```bash
source deploy/baremetal/common.sh   # ships ss_own_tls_keys
ss_own_tls_keys /etc/sandswap/certs
```

The single-node and cluster deploys do this automatically; a manual
multi-node install (`deploy-cluster-multi-gw.sh` prints the per-node
commands, it does not install) must run it on every node that loads a
keypair, or the gateway/sandlot units fail to start with
`open .../stream.key: permission denied`.

## 10. Service identities and permissions

### 10.1 Path ownership by deployment shape

Recent features (storage-plane split, four identities, per-OWNER devices, the
volume-name seed) made path ownership **shape-dependent**: who OWNS the
storage-plane paths is whoever CARRIES the prov role in this deployment.

| Shape | Prov carrier | Deployers |
|---|---|---|
| **merged** | the one sandlot process, `roles [exec,prov]`, runs as `sandlot` | `deploy-single-node.sh`, `e2e/single-node-multi-agent.sh` |
| **dedicated-prov** | a separate prov instance running as `sandprov` | `deploy-one-machine-etcd.sh`, the cluster scripts + simulations, `verify-binpack` |

The contract (implemented ONCE in `deploy/baremetal/common.sh` →
`sandswap_apply_prov_plane`; the systemd units re-assert the ownership half at
every start via `/usr/local/lib/sandswap/apply-prov-ownership`, which reads
`/etc/sandswap/prov-user.env` written by the deployer):

| Path | Owner : group | Mode | Why |
|---|---|---|---|
| `/etc/sandswap` | root : root | 0755 | config root |
| `/etc/sandswap/volume-seed` | root : `sandprov` | 0640 | name derivation secret — prov reads, sandvmm must not; minted once, never regenerated. The group is the `sandprov` account on EVERY shape: a dedicated prov instance runs AS sandprov, and the merged `exec,prov` sandlot carries sandprov as a SUPPLIED supplementary group (the sandvmm spawn replaces its own group set, so the grant never reaches the VMM/FUSE daemon) |
| `/var/lib/sandswap` | root : root | 0755 | state root; the gateway's writable identity store + lock live in the private `state/` subdirectory (0700, gateway identity — unit shapes get that from `StateDirectory`), never at the root |
| `/usr/local/lib/sandswap/guest` | root : root | 0755 (files 0644 + `SHA256SUMS`) | the guest TCB (kernel + initramfs). Executed as the in-VM root of trust and therefore never writable — not even renamable — by a service identity; the sandlot verifies the hashes at start |
| `/var/lib/sandswap/volumes` | *prov identity* : shared group | 2710 | the virtio-fs share root: prov creates/removes, the FUSE daemon traverses only (no readdir, no create) |
| `/var/lib/sandswap/templates`, `flat-templates`, `overlay-templates` | *prov identity* : shared group | 2750 | stores the prov writes and the daemon reads layer content; the `refs/` metadata tree inside is group `sandtmpl` (982 — prov + exec sandlot, never sandvmm) |

Never hand-chown these paths in a deploy script: derive from `SS_PROV_USER`
(and call `sandswap_write_prov_user_env` so the units agree).
`deploy/baremetal/check-shape-hardcodes.py` enforces the rule mechanically
(runs in the e2e battery's harness drill); `security/verify-host-security.sh`
asserts the live result against `prov-user.env` after every deploy.



`setup-host.sh` creates the same pinned identity set on every node,
unconditionally. Four dedicated non-login identities run everything (each
unit's `User=` selects one), plus the group-only `sandtmpl` metadata group.
The design rule: **every privileged surface is
fenced to exactly one identity**, so compromising one component does not
confer its neighbors' powers (the rationale lives in
[Threat Model](../how-it-works/threat-model.md)).

| Identity (uid) | Runs (unit `User=`) | Capabilities / groups | May touch | Deliberately never has |
|---|---|---|---|---|
| `sandlot` (985) | exec sandlot instances (VMM lifecycle, mounts, vsock client) | `AmbientCapabilities=NET_ADMIN SYS_ADMIN SETUID SETGID KILL` + `SupplementaryGroups=kvm sandprov sandtmpl` (sandprov is the seed grant for the merged exec,prov shape; sandtmpl is the template-refs metadata grant; the sandvmm spawn replaces its own group set and never inherits either); spawns sandvmm | `/dev/kvm`, `/dev/vsock` (0600 owner), the volumes group | nothing narrower to note — this is the trusted executor; vsockguard allows exactly this uid on the warden port |
| `sandserv` (986) | gateway + sandns units | no capabilities, no supplementary groups | its TLS keys, config, state dir | **no shared-storage access at all**: no volumes/templates mounts, no fsGroup, no registry egress |
| `sandvmm` (987) | every sandvmm process + the in-VMM FUSE daemon | **zero capabilities**, via a setpriv wrapper (the TAP is pre-created by the network provider owned by this uid and pre-configured) | `/dev/vhost-vsock` (0600 owner) | never the warden-trusted uid: guest-planted setuid files land owned by 987 and cannot reach the warden transport |
| `sandprov` (983) | prov sandlot instances | no capabilities, no kvm, no vsock devices; supplementary `sandlot` group (the shared-storage grant) + `sandtmpl` | volumes/templates trees, the volume-seed file (`root:sandprov` `0640`), the OCI registry egress | never compute: no KVM, no VMs, no vsock |
| `sandtmpl` (group, gid 982) | — (a supplementary group, never a `User=`) | membership `sandprov` + `sandlot`; pinned by host prep (`SS_GID_TPL`), exported as `SANDSWAP_TPL_GROUP` | the `refs/` metadata tree in the template stores | **never `sandvmm`**: the FUSE daemon reads layer content through the shared group but cannot enumerate refs |

Operator rules that fall out of the split:

- Do not widen an identity's groups, capabilities, or file modes "to make
  it work". A permission failure means the workload is on the wrong
  identity — move it, do not grant.
- The role lock (`-roles exec|prov|exec,prov`) enforces **one sandlot
  process per host**; a duplicate is refused at startup.
  `-allow-colocated-instances` is the explicit admission for the simulation
  scripts and the one-machine-etcd deploy's exec+prov pair.
- The volume-seed file is scoped `root:sandprov` `0640` on every shape:
  a leaked seed makes every volume's on-disk name guessable (see
  [Volume-seed rotation](#142-volume-seed-rotation)). The dedicated prov
  instance runs as sandprov; the merged `exec,prov` sandlot gets the group
  as a supplementary grant (§10.1), which the sandvmm spawn drops.
- Guest-planted setuid bits reach the host owned by `sandvmm` (987) — inert
  by the identity split; the volumes mount flags (`nosuid,nodev`) are the
  second layer ([Host Prerequisites §5](prerequisites.md#5-volumes-filesystem-mount-flags-nosuidnodev)).

## 11. systemd services

Units live in `deploy/baremetal/systemd/`:

| Unit | Runs as | Purpose |
|---|---|---|
| `sandswap-gateway.service` | `sandserv` | merged single-node gateway |
| `sandswap-gateway@.service` | `sandserv` | `@exec`/`@human` instances (reads `/etc/sandswap/gateway-<instance>.yaml`) |
| `sandswap-sandlot.service` | `sandlot` | exec-role sandlot (embedded) |
| `sandswap-sandlot-instance@.service` | `sandlot` | additional exec sandlot instances on one host (simulations; `instance.id` namespaces VM ids) |
| `sandswap-sandlot-prov.service` | `sandprov` | prov sandlot (storage plane) |
| `sandswap-sandns.service` | `sandserv` | sandns |
| `sandswap-network.service` | root, oneshot | `br-sandswap` bridge + NAT; ordered `Before=` the sandlot units |
| `sandswap-vsock-retune.service` | root, oneshot | triggers udev and then ASSERTS both vsock devices at boot (`/dev/vhost-vsock` `sandvmm:600`, `/dev/vsock` `sandlot:600`); a mismatch fails the unit — ordered before any sandlot starts, so a rule that never applied cannot become a sandlot crash-loop |

Properties worth knowing:

- **Gateway/sandns are sandboxed** (`NoNewPrivileges`, `ProtectSystem=strict`,
  `RuntimeDirectory=sandswap`, `ReadWritePaths=...`). The
  `RuntimeDirectory` matters: under `ProtectSystem=strict`, a
  `ReadWritePaths` entry pointing at a directory that does not exist fails
  the whole namespace setup (`status=226/NAMESPACE`).
- **The exec sandlot runs as `sandlot` (985) with the ambient capability
  set from §10** (KVM, vhost-vsock, mounts, network namespaces) — no
  `NoNewPrivileges`/`ProtectSystem` for it.
- **Sandlot uses `KillMode=process`**: `systemctl stop/restart` signals only
  the sandlot main process; child sandvmm processes stay alive in memory and
  are re-adopted at restart. This is what makes rolling sandlot upgrades
  zero-downtime.
- **Gateway@ template instances** read `/etc/sandswap/gateway-<instance>.yaml`
  (`systemctl enable sandswap-gateway@exec`).
- Cluster mode: `vol_root` is on the shared mount — the deploy scripts
  create/mount it before starting services, and the path must appear in the
  unit's `ReadWritePaths`.
- The identity each unit runs as is the four-identity split — see
  [§10](#10-service-identities-and-permissions).

## 12. Configuration examples

Full flag/YAML reference is per component under
[Configuration](../operations/configuration/index.md); these are the deployment-shaped
examples the scripts generate.

### 12.1 Exec gateway (gateway-exec.yaml)

```yaml
mode: exec
vol_root: /mnt/sandswap/volumes

# REQUIRED for multi-gateway production:
#   gateway_id          unique per exec gateway (colliding ids corrupt ownership/health keys)
#   gateway_url         https://<THIS GW IP>:<agent_port> — per-sandfs DNS A-record
#                       target + 307 redirect Location; registered in the
#                       /sandswap/gateway/{id} registry key
#   gateway_stream_addr <THIS GW IP>:<stream_port> — registered in the registry key
#   idle_timeout_sec    long keep-alive; the agent connection is the affinity anchor
gateway_id: gw-exec-1
gateway_url: "https://10.0.2.1:3000"
gateway_stream_addr: "10.0.2.1:9998"
idle_timeout_sec: 3600

etcd: "https://etcd1:2379,https://etcd2:2379,https://etcd3:2379"
etcd_ca: /etc/sandswap/certs/ca.crt
etcd_cert: /etc/sandswap/certs/etcd-client.crt
etcd_key: /etc/sandswap/certs/etcd-client.key

agent:
  addr: "0.0.0.0:3000"
  tls_cert: /etc/sandswap/certs/mcp.crt
  tls_key: /etc/sandswap/certs/mcp.key
stream:
  addr: "0.0.0.0:9998"
  tls_cert: /etc/sandswap/certs/stream.crt
  tls_key: /etc/sandswap/certs/stream.key
  tls_ca: /etc/sandswap/certs/ca.crt

lease: { sticky_ms: 100, max_sticky_sec: 5 }
exec: { default_timeout_sec: 30, max_timeout_sec: 180 }
```

There is no gateway-side template configuration: the gateway mounts no
shared storage and owns no template store — SandFS/template operations
route over the stream to a prov sandlot instance
([Storage plane split](../how-it-works/architecture.md)), and the flat-template scan root
is the prov sandlot's `-flat-templates` (§12.3 below shows where the
prov-side paths land).

### 12.2 Human gateway (gateway-human.yaml)

```yaml
mode: human
vol_root: /mnt/sandswap/volumes

etcd: "https://etcd1:2379,https://etcd2:2379,https://etcd3:2379"
etcd_ca: /etc/sandswap/certs/ca.crt
etcd_cert: /etc/sandswap/certs/etcd-client.crt
etcd_key: /etc/sandswap/certs/etcd-client.key

human:
  addr: "0.0.0.0:3100"
  tls_cert: /etc/sandswap/certs/admin.crt
  tls_key: /etc/sandswap/certs/admin.key
stream:
  addr: "0.0.0.0:9996"   # prov-only listener; :9998 is the co-located exec gateway's
  tls_cert: /etc/sandswap/certs/stream.crt
  tls_key: /etc/sandswap/certs/stream.key
  tls_ca: /etc/sandswap/certs/ca.crt
```

> Do not copy stale OIDC examples: a non-empty `authn.issuer` enables OIDC
> and the gateway does `.well-known/openid-configuration` discovery at
> startup — an unreachable issuer exits the process. With NO issuer the human
> listener **refuses to start** unless the operator opts out explicitly with
> `authn: {allow_anonymous: true}` (flag `-allow-anonymous-human`), which
> logs a Warn naming the full anonymous blast radius. **Production MUST use
> OIDC or mTLS; anonymous mode is development/test only and must never be
> used in production.** Configure `authn.issuer` (or mTLS) and bind the human
> listener to the management network or an independent netns; never expect a
> bare human gateway to come up unauthenticated.

### 12.3 Exec sandlot (sandlot.yaml, embedded mode)

```yaml
gateway_addr: "sandswap-stream.local:9998"   # DNS name in production;
                                             # localhost:9998 single-node;
                                             # gw-host:9998 small cluster
node_id: "sandlot-X"
vm_mode: embedded
vmm_binary: /usr/local/bin/sandswap-sandvmm

microvm:
  kernel: /usr/local/lib/sandswap/guest/vmlinux.bin
  initramfs: /usr/local/lib/sandswap/guest/initramfs.cpio.gz
  default_vcpus: 2
  default_memory_mb: 512
  volumes_dir: /mnt/sandswap/volumes

specs:
  small:  { vcpus: 2, memory_mb: 256,  exec_slots: 3 }
  medium: { vcpus: 4, memory_mb: 1024, exec_slots: 4 }
  large:  { vcpus: 8, memory_mb: 2048, exec_slots: 5 }

pool: "medium:5"

recycle:
  # max_uses omitted = default 100000 (recycle fires on the memory
  # thresholds; a low use-count pays the cold-guest tax on every recycle)
  mem_percent: 10
  mem_abs_mb: 100

network:
  backend: bridge
  bridge: br-sandswap
  subnet: 10.188.X.0/24
  gateway: 10.188.X.1
  dns: "1.1.1.1,8.8.8.8"

tls:
  # The pair whose CN IS this node's identity (node_id above) — see §9 and
  # THE CN RULE in gen-baremetal-certs.sh. The gateway refuses a mismatch by
  # name, so a shared pair does not connect.
  cert: /etc/sandswap/certs/sandlot.crt
  key: /etc/sandswap/certs/sandlot.key
  ca: /etc/sandswap/certs/ca.crt
```

A **prov sandlot** on a storage host uses the same shape with
`-roles prov` (systemd unit `sandswap-sandlot-prov.service`): no pool, no
VM fields — instead the prov-role keys (`templates_dir`,
`oci_registry` + `-registry-*` credentials, and the REQUIRED
`volume_seed_file` pointing at `/etc/sandswap/volume-seed`). See the
prov-role flag list in [Configuration → Sandlot](../operations/configuration/sandlot.md).

### 12.4 Production sandns (sandns.yaml)

```yaml
listen_addr: "0.0.0.0:53"

domains:
  agent: sandswap.local           # agent discovery bootstrap (GET /agent/sandfs; any exec GW answers)
  stream: sandswap-stream.local   # sandlot stream domain
  sandfs: sandfs.sandswap.local   # per-sandfs owner-aware zone:
                                  #   <sandfs_id>.sandfs.sandswap.local → owner GW A record
                                  #   (candidates come entirely from etcd self-registration —
                                  #   no static gateway list)

etcd: "https://etcd1:2379,https://etcd2:2379,https://etcd3:2379"
etcd_ca: /etc/sandswap/certs/ca.crt
etcd_cert: /etc/sandswap/certs/etcd-client.crt
etcd_key: /etc/sandswap/certs/etcd-client.key

ttl: 10                          # DNS TTL (seconds)
sticky_expire: 1800              # sticky records expire after 30min without queries
sticky_sync_interval: 5          # sticky → etcd sync interval (seconds)
sticky_sync_batch: 256           # flush early when ≥ N dirty records

forwarders:
  - 8.8.8.8:53
  - 8.8.4.4:53
```

> Routing semantics: the agent placement and sandlot stream domains stay
> bin-packing (placement); the per-sandfs zone is owner-aware. Agent-facing
> routing additionally requires the target to have `node_count > 0` — a
> gateway with no sandlots is in a failure state and is not routed agents
> until one connects. Stream-domain placement ignores node_count (a
> compute-less gateway must still be selectable so it can recover).

## 13. Agent-side DNS configuration

Agent hosts must resolve the sandswap domains via sandns. Three
options:

```bash
# 1) resolv.conf direct (simplest, few agent hosts)
nameserver 10.0.1.100   # sandns
nameserver 8.8.8.8      # fallback

# 2) systemd-resolved (Ubuntu default) — /etc/systemd/resolved.conf
[Resolve]
DNS=10.0.1.100
FallbackDNS=8.8.8.8

# 3) dnsmasq forward (intercepts only sandswap domains) —
#    /etc/NetworkManager/dnsmasq.d/sandswap.conf
#    server=/sandswap.local/ also covers *.sandswap.local (per-sandfs zone)
server=/sandswap.local/10.0.1.100
server=/sandswap-stream.local/10.0.1.100
```

Agent MCP base URL — **one URL per sandfs (the affinity path)**:

```
https://<sandfs_id>.sandfs.sandswap.local:3000/mcp
```

- The per-sandfs zone resolves to the **owner gateway's IP** (owner-aware);
  after a reconnect the first request lands directly on the owner, zero
  redirects. If the owner fails (no sandlots), resolution falls to another
  healthy gateway which takes over.
- The shared domain `https://sandswap.local:3000/mcp` remains as a
  backward-compat fallback (old agents keep working; client-IP sticky +
  307 converge).
- Cross-host 307 following (`https://<owner-ip>:3000/...`) needs the
  `X-Sandswap-Api-Key` header — Go's `http.Client` strips `Authorization`
  on cross-host redirects but not custom headers.

**Sandlot hosts too**: the system resolver must resolve
`sandswap-stream.local`. Beware systemd-resolved's stub (127.0.0.53) which
special-cases `.local` as mDNS:

```bash
# /etc/systemd/resolved.conf.d/sandswap.conf
[Resolve]
DNS=127.0.0.1
Domains=~sandswap.local ~sandswap-stream.local
MulticastDNS=no
```

or simply put the sandns IP as the first `nameserver` in
`/etc/resolv.conf`.

## 14. Operations

### 14.1 The sandswap-ops.sh CLI

```bash
sandswap-ops.sh status                      # cluster state (nodes, pools, agents)
sandswap-ops.sh health                      # probe every gateway /health
sandswap-ops.sh logs gateway [N]            # journalctl tail
sandswap-ops.sh start/stop/restart <svc>    # systemctl wrapper
sandswap-ops.sh pool list                   # every sandlot's pool state
sandswap-ops.sh pool resize <node> <spec>   # hot-reload pool size
sandswap-ops.sh pool drain <node>           # drain to 0 gracefully
sandswap-ops.sh scale add-sandlot ...       # add a sandlot node
sandswap-ops.sh scale remove-sandlot ...    # remove a sandlot node
sandswap-ops.sh consolidate                 # smart rebalance
sandswap-ops.sh consolidate --full          # full rebalance
```

`consolidate` rebalances after long-run drift (e.g. traffic piled onto one
gateway after a failover): it reads every gateway's `/stats`, computes the
target distribution, releases ownership of sandfs that should move
(`POST /human/ownership/release/{sandfs_id}` on the human gateway), and
clears the affected DNS sticky records — the released clients re-resolve,
bin-packing sends them to idle gateways, and the new gateway claims. Untouched
sandfs are not disturbed. `--full` releases everything and clears all sticky
records (use when the gateway set itself changed). This is an operator
decision, not automatic.

### 14.2 Volume-seed rotation

The volume-name seed (`/etc/sandswap/volume-seed`, `root:sandprov` `0640`)
derives every SandFS volume's on-disk directory name — it is what keeps a
compromised FUSE daemon from guessing other tenants' directories. Rotation
revokes the paths an attacker accumulated. The window is manual by design
(service stops and resumes on purpose), driven by
`deploy/baremetal/rotate-volume-seed.sh` on a prov host:

```bash
rotate-volume-seed.sh --prov-config /etc/sandswap/sandlot-prov.yaml \
    --human-url https://localhost:3100 --maintenance on    # agents get 503 + Retry-After
rotate-volume-seed.sh ... --status   # config vs running instance vs disk, side by side
rotate-volume-seed.sh ... --stage    # install the next seed into the prov config
rotate-volume-seed.sh ... --run      # rename every volume + update its record
rotate-volume-seed.sh ... --promote  # staged seed becomes current
rotate-volume-seed.sh ... --maintenance off
```

Wait for the mounts to drain after `--maintenance on` (the gateway release
completes within fence + `T_clean`; `/stats` shows `IN_USE` → 0) before
`--stage`. Never rotate without the maintenance window: a rename under live
mounts is exactly what the drain prevents.

**Every step is verified against the running instance, not against a log line.**
The prov instance records what it adopted in
`/run/sandswap/volume-seed-state.json` (generation fingerprints, the staged
generation, the configured channels and any refusal), and the tool waits on
that record:

- `--stage` returns only once the RUNNING instance has adopted the staged
  generation — until then creation is not actually frozen, so proceeding to
  `--run` would rename volumes the live namer resolves by their old names. A
  staged source the instance cannot read (a file the injector has not
  materialized, wrong ownership) is reported here, not midway through a run.
- `--run` refuses unless that adoption is visible.
- `--promote` refuses unless the rename completed (no volume may still carry
  the pre-promote generation), and the instance refuses the promotion
  independently, before it drops the old generation. After the pointer moves,
  the tool waits until the instance reports the new current generation.

`--status` prints the three views side by side (config / running instance /
disk) — run it before opening a window and after closing one. `--migrate` is
the one-time legacy conversion (`<id>` names → derived names, no staging).

**Never rewrite the file the current generation points at, and never delete a
generation file.** A rotation always points the config at a NEW file; an
aborted window (a staged key cleared after `--run` started renaming) is
recovered by re-staging the SAME file — the tool never deletes one, and a
freshly minted seed would orphan the volumes that were already renamed.

**Multiple prov instances**: the gateway spreads storage ops across prov
instances, so every prov host must be staged and promoted for the fleet to
agree. Add `--prov-hosts h1,h2` to `--stage` and `--promote`: the stage fans
the SAME generation file out to every host (minting per host would rename
different volumes in different directions) and every remote step keeps its own
adoption assertion. Closing the window is gated: `--rotation off` and
`--maintenance off` compare each connected prov instance's reported generation
(its heartbeat, projected in `/stats` as `prov_seeds`) against the local
config and REFUSE while a known instance still reports the retired generation —
waiting up to 45 s first, since the view lags one heartbeat. An instance that
reports nothing at all (an older binary) closes with a warning. A host that
missed an update entirely is also caught by its own startup guard when it
restarts: it refuses to start against a tree no configured generation derives.

### 14.3 Seed injection channels

The prov instance reads each generation from ONE source, named per generation
in its config (`provision.volume_seed` inline, or `provision.volume_seed_file`).
Only the sandlot derives names from it; supplying the bytes is the operator's
(or a secret manager's) job. The channel contract — what any injector must
honour — is:

- **One file per generation.** A rotation points the config at a NEW path; the
  file a live generation points at is never rewritten. Generation-labeled names
  (`gen-3`, `gen-4`) make that visible in `ls`.
- **Atomic writes** (temp file in the same directory + `mv`). The instance
  re-reads on fsnotify within ~200ms and a torn value is refused, but a stable
  torn value would look like an ordinary edit.
- **Scope** `root:sandprov` `0640` (`SANDPROV_GROUP`), directory `0750` (tmpfs
  directories included): only the prov identity reads the seed — the prov
  units carry `SupplementaryGroups=… sandprov` — while the sandvmm identity
  must not (every sandvmm spawn sets its supplementary groups explicitly,
  `setpriv --groups`, so the merged sandlot's grant is never inherited), and
  nobody else may replace it. A world-writable parent directory
  defeats the file's own mode.
- **Never delete a generation file** — re-staging the same file is the
  recovery path for an aborted window.

Three shapes, in increasing strength:

| Shape | Where the seed lives | Notes |
|---|---|---|
| Persistent file (default) | `/etc/sandswap/volume-seed`, minted once | Survives reboots; present in images and backups. Fine for closed labs |
| **Tmpfs, fetched at boot** | `/run/sandswap/seed/gen-N`, materialized by a fetcher | Nothing on disk: the disk never holds the plaintext seed. `deploy/baremetal/seed-fetch.sh.template` is the hook — copy it to `/usr/local/lib/sandswap/seed-fetch.sh`, replace `fetch_generation()` with your store's read, `systemctl enable sandswap-seed-fetch` |
| **systemd credential** | `$CREDENTIALS_DIRECTORY/gen-N`, sealed at rest | `LoadCredentialEncrypted=gen-3:/etc/credstore.encrypted/gen-3`: the disk holds ciphertext bound to this machine and the unit reads plaintext from unswappable memory. Needs systemd ≥ 250 (v247 has the credential framework, v250 the ENCRYPTED variant). Seal with `systemd-creds encrypt --with-key=host` when TPM2 is unavailable — the host key lands in `/var/lib/systemd/credential.secret`; the TPM2 path (`--with-key=tpm2`) additionally needs the tss2 userspace libraries (`systemd-analyze has-tpm2` reports which half is missing). Check the class systemd assigned with `systemd-creds list` (secure = unswappable memory, insecure = a mode other than 0400). Rotation is restart-based (credentials are fixed at service start) |

`sandswap-seed-fetch.service` is deliberately NOT `Requires=`d by the prov
unit: a failed fetch must not keep the instance down — the instance itself
refuses to start without a readable CURRENT generation, which is the guard that
matters. Set `SANDSWAP_VOLUME_SEED_NO_MINT=1` in an injected deployment: the
deployer then refuses to mint a replacement seed when one is missing, instead
of silently orphaning every volume name.

**"Nothing on disk" is a set of host policies, not a property of tmpfs**: a
plain tmpfs file's pages can be swapped, and the instance holds the seed in its
own memory for its whole life. Disable swap (or use zram / encrypted swap),
disable hibernation and kdump, and keep `LimitCORE=0` (already set in the
shipped unit) on every prov host. systemd credentials are the strongest shape
here (documented unswappable memory); `systemd-creds list` reports each
credential as secure / weak / insecure.

**The disk is the authority, not the config.** On startup the instance reads
every volume's `.sandfs-id` generation stamp. A stamp naming a FOREIGN
generation (one NO configured seed derives — a source replaced under the
deployment, a rollback, a botched restore) refuses startup: serving from there
would silently split tenants — `delete` answers false success and `create`
builds a second tree. The deliberate re-key / disaster-recovery path is
`-allow-seed-generation-mismatch`, paired with the one-time migration. An
UNVERIFIED stamp (unsigned or tampered — a compromised guest kernel can rewrite
the tenant-writable file) does NOT crash-loop the storage plane: it is
reported and recorded as a WARNING, the affected volume is refused by
create/swap and by the mount identity check, a delete QUARANTINES it
(orphan-rename, data preserved), and the promote gate still refuses the tree — so one tampered stamp cannot
take the provision role down or hijack a rotation. A
config edit that moves the current generation outside the stage → run → promote
window is refused at runtime and reported in the adoption record; it is never
adopted, and the next restart refuses to start until it is fixed.

### 14.4 Rolling upgrade (zero downtime)

```bash
bash build/build.sh all

# gateways one at a time (keep the previous binary for rollback):
for gw in gw-exec1 gw-exec2; do
  scp output/gateway $gw:/tmp/sandswap-gateway.new
  ssh $gw sudo cp /usr/local/bin/sandswap-gateway /usr/local/bin/sandswap-gateway.prev
  ssh $gw sudo cp /tmp/sandswap-gateway.new /usr/local/bin/sandswap-gateway
  ssh $gw sudo systemctl restart sandswap-gateway@exec
  until curl -sk https://$gw:3000/health; do sleep 1; done
done

# sandlots one at a time — KillMode=process keeps sandvmm children alive;
# the restarted sandlot re-adopts them and reconnects the stream:
for sl in sandlot1 sandlot2; do
  scp output/sandlot output/sandvmm $sl:/tmp/
  ssh $sl sudo cp /tmp/sandlot /usr/local/bin/sandswap-sandlot
  ssh $sl sudo cp /tmp/sandvmm /usr/local/bin/sandswap-sandvmm
  ssh $sl sudo systemctl restart sandswap-sandlot
  sleep 5 && ssh $sl systemctl status sandswap-sandlot
done

# sandns last:
ssh dns1 sudo cp /tmp/sandns.new /usr/local/bin/sandns && ssh dns1 sudo systemctl restart sandswap-sandns
```

Rollback = restore the `.prev` binary and restart.

### 14.5 Scaling

**Add a sandlot**: `sandswap-ops.sh scale add-sandlot <host> <node_id>
["medium:5"] [subnet] [net-gateway-ip]` (prints the manual steps — or do them
yourself: `setup-host.sh --role sandlot`, install binaries, generate YAML (a compute node runs `-roles exec`; a storage host runs `-roles prov` and dials the human/unified gateway),
enable the service). The sandlot connects, the gateway reconciles it, sandns
picks it up automatically.

**Add an exec gateway**: install gateway + certs, `systemctl enable --now
sandswap-gateway@exec` — sandns discovers it via its self-registered registry
key (no gateway list to edit). Extend the TLS cert SANs with the new IP and
redistribute where 307-following matters.

## 15. The bare-metal script family

Everything under `deploy/baremetal/`, and when to reach for each:

| Script | What it is | When |
|---|---|---|
| `deploy-single-node.sh` | one host, gateway + sandlot, end to end (`--skip-build --no-tls --keep --pool SPEC`; `--no-tls` = plaintext HTTP listeners, stream mTLS always); after the pool gate it writes the `/etc/sandswap/sandctl.env` client contract | dev/eval |
| `deploy-one-machine-etcd.sh` | the one-machine etcd topology for real: co-located mTLS etcd + exec/human gateways + one exec + one prov sandlot on one host (`--pool`, `--no-tls`, `--skip-build`; `--no-tls` = plaintext HTTP + etcd, stream mTLS always); after its gates it writes the client contract with the etcd endpoint | single box with etcd / staging |
| `deploy-cluster-one-gw.sh` | the small-cluster shape (1 GW host + N sandlot hosts), **local-only by design (no ssh)**: `--role prepare` builds a self-describing stage bundle (certs minus ca.key, per-node configs, the cluster config) on the control host; each target host runs `--role gateway\|sandlot\|all` (auto-detected) and installs **locally** from the stage; `--config` alone = single-box rehearsal (prepare + all roles + verify). Ship the release tree + stage to every host yourself or via Ansible/rsync | small clusters; single-box rehearsals |
| `deploy-cluster-multi-gw.sh` | YAML-driven production cluster: etcd + exec/human gateways + sandns + sandlots | production |
| `deploy-cluster-one-gw-simulation.sh` | the small cluster **simulated on one host** (multi-instance sandlots via `instance.id`) | no spare hosts |
| `deploy-cluster-multi-gw-simulation.sh` | the production topology simulated on one host | no spare hosts |
| `deploy-egress-enabler.sh` | deploy + verify the egress identity enabler on a bare-metal node — 4 combinations of network backend {bridge, routed-ipv6} × binding carrier {shm, bpf} (`--binding-backend shm\|bpf`, `--routed-ipv6` restrict the matrix) | enabler nodes (see [Egress Enabler Contract](../how-it-works/egress-enabler.md)) |
| `rotate-volume-seed.sh` | volume-name seed rotation/migration in a maintenance window (see [Volume-seed rotation](#142-volume-seed-rotation)) | prov hosts, rare |
| `e2e/single-node-multi-agent.sh` | single-node MemoryStore + background-process shape: the e2e pattern, not a deployer; it deploys its own stack then verifies the eino multi-agent drill | e2e battery (kvm llm heavy) |
| `setup-host.sh` | per-host prep only (`--role gateway\|sandlot\|provision\|all`): sysctls, `/dev/net/tun`, vhost_vsock, directories, `br-sandswap`, vsockguard attach, udev, service identities (sandlot/sandserv/sandvmm/sandprov). `provision` = storage-attached hosts running the prov sandlot — no KVM/vsock/bridge duty | manual installs; called by the deployers |
| `gen-baremetal-certs.sh` | TLS cert generation with SAN control | manual/custom installs |
| `common.sh` / `deploy-lib.sh` | shared helpers: `bm_*` remote-exec primitives, preflight, the side-effect ledger | library — not run directly |
| `sandswap-ops.sh` | day-2 ops CLI (see [Operations](#14-operations)) | after deploy |
| `verify-binpack.sh` / `verify-eino.sh` / `verify-failover.sh` | post-deploy verifications: DNS binpack concentration on a real topology; the eino multi-agent run; sandlot cross-gateway failover via the DNS stream name | after deploy |
| `verify-etcd-fence.sh` | chaos drill: iptables-partitions the gateway's etcd connections (owner-match on the sandserv uid) and asserts the self-fence fires in order — mounts released, node streams kept, in-place recovery after the partition heals | after `deploy-one-machine-etcd.sh` |
| `verify-negative-path.sh` | chaos drill: breaks the storage plane and the error paths of the deployed stack (prov unit stopped, unknown template ref, lifecycle-gated sandfs) and asserts every gate answers a named retryable refusal — never a silent success, never a bare 500; restores each breakage on every exit path | after `deploy-one-machine-etcd.sh` |
| `verify-cert-rotation.sh` | PKI drill: rotates the whole bare-metal PKI (fresh CA + leafs via `gen-baremetal-certs.sh`, restart every unit), asserts TLS pinning fails closed during the mismatch window and the fleet re-converges with changed fingerprints | after `deploy-one-machine-etcd.sh`, before trusting a rotation |
| `cleanup.sh` | kill all local sandswap processes + host state from a **simulation** run | after simulations |
| `uninstall.sh` | remove everything the systemd deployers installed (binaries, units, configs, certs) | decommission |

## 16. Troubleshooting

Symptoms seen in real deployments, one row each:

| Symptom | Cause | Fix |
|---|---|---|
| Pool-wait scripts probing `:3000/stats` time out | single-node/human gateways register `/stats` on the **human listener (`:3100`)**, never on `:3000`; only an exec-mode gateway serves it on the agent listener (it has no human listener) | probe the listener the mode serves: `:3100` on single-node/human gateways, `:3000` on exec gateways |
| A second sandlot's VMs vanish from the gateway map | two sandlot instances without distinct `instance.id` generate colliding VM IDs; the gateway drops the second node's VMs | set `instance.id` per instance (the deploy scripts do it automatically) |
| Gateway unit fails with `status=226/NAMESPACE` | under `ProtectSystem=strict`, a `ReadWritePaths` entry pointing at a missing directory fails the whole namespace setup | create the directory (or fix the path) before starting the unit |
| Unit fails with `open .../stream.key: permission denied` | key files are root-only `0600`; the service identity cannot read them | run `ss_own_tls_keys /etc/sandswap/certs` on every node that loads a keypair ([§9.1](#91-private-key-ownership-on-each-node)) |
| Re-deploy fails with `Text file busy` | old processes still hold the binaries | stop the services before replacing binaries (the deploy scripts do); then redeploy |
| Sandlot hosts cannot resolve `sandswap-stream.local` | systemd-resolved's stub (127.0.0.53) special-cases `.local` as mDNS | add the sandns drop-in from [Agent-side DNS configuration](#13-agent-side-dns-configuration) or put the sandns IP first in `/etc/resolv.conf` |
| 307 redirect following fails TLS validation | production `mcp.crt` lacks the new exec gateway's IP in its SANs | regenerate certs with every exec gateway IP (see the SAN table in §9) and redistribute |
| sandns health probes log TLS errors | `sandns` binds UDP+TCP 53 with `SO_REUSEADDR` (coexists with systemd-resolved) and probes gateway health over insecure TLS by design — self-signed intranet checks | expected behavior; not an error |

Uninstall/cleanup: `deploy/baremetal/cleanup.sh` (simulation runs) and
`uninstall.sh` (systemd deploys).

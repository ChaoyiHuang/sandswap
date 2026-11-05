---
title: Install — Kubernetes
nav_order: 4
parent: Deployment
---

# Install — Kubernetes

> **Scope of the bundled scripts.** The deploy scripts and manifests under
> `deploy/k8s/` serve two purposes in Sandswap: they are the executable
> proof that Sandswap deploys and works in each deployment mode (embedded,
> boxout — the e2e battery drives them as such), and they are reference
> implementations of the mechanics — which workloads run with which
> privileges, how the manifests wire together, what verification looks
> like. **They are not production scripts.** A production deployment
> designs its own automation on top of them: its own deploy scripts, its
> own verification, a staging rehearsal, and a staged production rollout.

Deploying Sandswap on Kubernetes via the k3s-based tooling, in either
privilege mode — **embedded** (privileged sandlot) or **boxout**
(unprivileged sandlot + privileged boxout sidecar). The design trade-off
between the two is in [Topologies](../how-it-works/topologies.md); bare
metal is [here](install-baremetal.md). Host-level requirements (kernel,
KVM, bpf LSM, vsockguard) are in [Host Prerequisites](prerequisites.md).

## 1. Prerequisites

| # | Check | Command | Expected |
|---|---|---|---|
| 1 | kernel, KVM, vhost-vsock on every node | `uname -r && ls /dev/kvm /dev/vhost-vsock` | kernel ≥ 5.10; both device paths exist. This rules out most managed node pools — bring your own nodes or metal |
| 2 | `bpf` LSM active (vsockguard enforcement) | `cat /sys/kernel/security/lsm` | contains `bpf` |
| 3 | per-node host prerequisites | — | [Host Prerequisites](prerequisites.md); `deploy/k8s/k8s-host-setup.sh --mode embedded|boxout` automates the Kubernetes variant (`--verify` to check only; `--stream-certs-only` re-fetches just this node's stream client pair). The mode is persisted (`/etc/sandswap/deploy-mode.env`) and selects the vsockguard UID the node pins: **0** for embedded, the reserved sandlot UID **65536** for boxout — a mismatch with the existing pin fails `--verify` and is detached/re-attached on a real run |
| 4 | root on the nodes | — | — |
| 5 | `docker` on the build host | `docker version` | server + client versions print |
| 6 | LLM key for the verification drill | env | `DEEPSEEK_API_KEY` or `OPENAI_API_KEY` (only needed with `--verify` / `verify-k8s.sh`) |

The deploy's own **preflight** re-runs the node checks (KVM, vhost-vsock,
kernel, docker, BPF LSM, the vsockguard pin) and reports all findings at
once before touching the cluster.

### 1.1 Volumes storage must be hardened (invariant 8)

The `sandswap-volumes` / `sandswap-templates` PVCs hold the guest-writable
share root. The virtio-fs passthrough stores guest-requested setuid bits and
`mknod` verbatim, so that tree must live on a `nosuid,nodev` mount.

A **host-side self-bind is not sufficient for pods**: the container runtime's
bind of a PVC drops the per-mount flags. Two things make the shipped
deployment safe:

- the embedded sandlot and the boxout sidecar images carry an entrypoint
  wrapper that re-creates `nosuid,nodev` in the container's own mount
  namespace (both run privileged; the unprivileged prov / boxout sandlot
  warns and relies on the privileged owner);
- the backing filesystem should additionally be mounted `nosuid,nodev` at
  the provisioner root (superblock flags survive the runtime bind). With the
  default local-path provisioner:

  ```sh
  # dedicated filesystem (loop/ext4 here; any block device works)
  truncate -s 3G /var/lib/sandswap-k8s-store.img
  mkfs.ext4 -q -F /var/lib/sandswap-k8s-store.img
  mount -o loop,nosuid,nodev /var/lib/sandswap-k8s-store.img /var/lib/rancher/k3s/storage
  systemctl restart k3s   # the provisioner's hostPath bind must re-resolve
  ```

  Create no PVs before the mount; existing PV directories on the old
  filesystem are hidden by the mount. A production storage class should point
  at a volume already mounted this way (NFS/CephFS mounts with `nosuid,nodev`,
  or a dedicated local filesystem).

## 2. Deployment modes

| | embedded | boxout |
|---|---|---|
| sandlot UID | 0 (privileged container) | 65536 (the reserved sandbox identity), all caps dropped |
| vsockguard allows | UID 0 | UID 65536 (reserved) |
| `/run/sandswap` ownership | root | chowned to 65536 for the sandlot's own state/role-lock files; the boxout SOCKET lives in the separate root-owned `/run/sandswap-boxout` (0711, sandlot traverses only) |
| VM lifecycle logs | sandlot container | boxout container |
| Device access | supplemental GID injection for `/dev/kvm` + `/dev/vhost-vsock` (distro GIDs differ, injected into the manifest at deploy) | the boxout sidecar owns the devices directly |

Pick **embedded** when the cluster nodes are effectively yours and you
want the simplest possible pod — it is the **default recommendation**.
Pick **boxout** only when cluster policy minimizes privileged workloads or
wants the privilege boundary audited in one place. Boxout is a posture
choice, not an upgrade: it adds a second privileged component, an extra
UDS hop on the management path, and a wider surface to monitor and upgrade
— adding a component does not by itself make performance, reliability, or
security better (see [Topologies](../how-it-works/topologies.md)). The hot
path (set-fs, warden vsock, lease) runs unprivileged either way.

## 3. Deploying

```bash
sudo bash deploy/k8s/deploy-k8s-embedded.sh            # embedded mode
sudo bash deploy/k8s/deploy-k8s-boxout.sh              # boxout mode
# Flags: --skip-build --skip-images --skip-deps --verify [--failover]
```

Both are thin entry points over a shared `deploy-lib.sh` (one
implementation, both modes). By default the run **deploys and keeps**:

1. Cleans any previous deployment; runs **preflight** checks — all
   findings reported at once.
2. Installs k3s if missing; builds all artifacts and the container images.
3. Generates TLS certificates (`gen-k8s-certs.sh`): server material plus
   **one stream client pair per cluster node** — the gateway binds a stream
   hello's `node_id` to the presented certificate's CN by exact match, so the
   generator mints `sandlot-certs-<node>` per node (CN = node name) and
   `sandlot-certs-prov` for the provision Deployment; the node list comes from
   `SANDSWAP_K8S_NODES` or `kubectl get nodes`.
4. Applies the manifests (§3.1) — including the
   `gateway-mcp-instructions` ConfigMap seeded from
   `output/gateway -print-mcp-instructions` (the gateway container cannot
   write it itself). It then materializes the per-node stream pair on this
   host (`bash deploy/k8s/k8s-host-setup.sh --stream-certs-only`, which runs
   per node and writes `/etc/sandswap/stream-certs/`) and verifies every
   node's Secret exists.
5. Waits for readiness; wires CoreDNS → sandswap-sandns (§5); smoke-checks
   reachability, then **leaves the deployment running** and prints the
   hand-over summary (management access, verification, teardown). A failed
   deploy tears itself down instead.

Expected finish: the hand-over summary on stdout and every pod `Running`
(`kubectl -n sandswap get pods -o wide`). A failed step tears the
deployment down and exits non-zero — rerun after fixing the reported
check.

With `--verify` the run becomes a self-testing drill: after step 5 it
creates 4 agents + sandfs via the human API, runs the affinity self-test
and the eino multi-agent end-to-end test (`--failover` additionally
exercises the gateway-failover scenario), prints the results, and tears
the deployment down afterwards — deploy-as-regression-run, the behavior
the flagless invocation had before keep became the default.

### 3.1 What gets deployed

| Manifest | What |
|----------|------|
| `namespace.yaml`, `volumes.yaml` | namespace + shared-storage mounts |
| `etcd.yaml` | the etcd cluster backing the gateways |
| `gateway.yaml` / `human.yaml` | exec gateway(s) + human gateway (Deployment + Service). Neither mounts shared storage: sandfs/template ops route over the human gateway's stream listener to a prov pod |
| `sandlot.yaml` | **embedded** DaemonSet: privileged (UID 0), owns sandvmm/TAP/overlay/re-adopt itself — compute nodes, `-roles exec`. One pod per node; `--node-id` comes from `fieldRef: spec.nodeName` and `/certs` from that node's hostPath (`/etc/sandswap/stream-certs`, materialized by `k8s-host-setup.sh` from `sandlot-certs-<node>`); supplemental GID 982 (`sandtmpl`, the template-refs metadata group — exec mounts overlays from `refs/`, and it is never granted to sandvmm) |
| `sandlot-prov.yaml` | **prov role** Deployment: unprivileged (`runAsNonRoot`, no capabilities/devices/hostNetwork), mounts the volumes/templates PVCs RW (supplemental GID 982, `sandtmpl`, for the template-refs metadata — `SANDSWAP_TPL_GROUP=982`, so `refs/` is chgrp'd without a group-database lookup) and dials the human gateway. Singleton node id `sandlot-prov` with its own `sandlot-certs-prov` Secret (`strategy: Recreate` — a second replica would need its own node id + pair). Scale replicas with provisioning load, not fleet size. External OCI registries need an egress rule (template in `networkpolicy.yaml`) |
| `sandlot-boxout.yaml` | **boxout** DaemonSet: two containers — privileged `boxout` (UID 0: VM lifecycle, network, overlay) + unprivileged `sandlot` (UID 65536 — the reserved sandbox identity, opaque to every default-allocated id on the node: gRPC + vsock hot path only); pod-level supplemental GID 982 (`sandtmpl`) for resolving overlay refs — pod-level is the only form Kubernetes offers (container `securityContext` has no such field), the root side carries the group inertly, and sandvmm never inherits it (the setpriv identity split sets its groups wholesale); same per-node node id + cert materialization as `sandlot.yaml` |
| `sandns.yaml` | sandns (owner-aware routing; CoreDNS forwards the sandswap zones to it) |
| `configmaps.yaml`, `secrets.yaml`, `networkpolicy.yaml` | generated gateway/sandlot configs (from `deploy-lib.sh`), certs, default-deny policy |
| `seccomp/sandlot-seccomp.json` | sandlot seccomp profile |

Images are built from `deploy/k8s/images/*.Dockerfile` (ubuntu
base): `sandswap/gateway`, `sandswap/sandlot`, `sandswap/boxout`,
`sandswap/sandlot-boxout`, `sandswap/sandns`.

## 4. Verification and teardown

### 4.1 Verify a kept deployment

```bash
sudo env DEEPSEEK_API_KEY=sk-xxx bash deploy/k8s/verify-k8s.sh [--failover]
```

`verify-k8s.sh` runs the same drill as `--verify` against the deployment
a keep-mode deploy left running (it auto-detects embedded vs boxout from
the deployed DaemonSet). Expected: it creates 4 agents + SandFS via the
human API, runs the affinity self-test and the eino multi-agent run, and
prints pass/fail per drill step — exit 0 means the deployment serves real
agent traffic. It never tears the deployment down — only its own
host-side access aids (human port-forward, exec-gateway `/etc/hosts` pin)
are reverted on exit.

### 4.2 Teardown

```bash
sudo bash deploy/k8s/k8s-cleanup.sh
```

Removes the namespace, manifests, and the ledgered host-side changes —
including a deployment kept running by the default keep mode.

The **side-effect ledger** printed at the end lists everything the run
changed outside the cluster (host packages, k3s install, files), so cleanup
is explicit.

## 5. The sandns service in Kubernetes

`sandns.yaml` deploys sandns as a cluster Service (`sandswap-sandns`); the
deploy wires **CoreDNS to forward the sandswap zones** to it, so pods keep
their normal resolver and still resolve `sandswap.local`,
`sandswap-stream.local`, and `<sandfs_id>.sandfs.sandswap.local`. Verify
from inside the cluster:

```bash
kubectl run -it --rm dig --image=registry.k8s.io/e2e-test-images/jessie-dnsutils -- dig @sandswap-sandns sandswap.local
```

Day-2 behavior (adding/retiring gateways, sticky records, staleness
alignment) is identical to bare metal and covered in
[Troubleshooting → sandns](../operations/troubleshooting.md#5-sandns-day-2-operations);
the config reference is
[sandns configuration](../operations/configuration/sandns.md).

## 6. Egress identity enabler

`deploy/k8s/deploy-k8s-egress-enabler.sh` deploys the variant with
the egress identity enabler enabled (binding region + stamping — see
[Egress Enabler Contract](../how-it-works/egress-enabler.md)). By default it
verifies two embedded-mode scenarios — `bpf+bridge` and `shm+routed-ipv6`,
the diagonal covering every feature-switch condition — each as a full
deploy → verify → cleanup lifecycle (no LLM key needed). `--all` runs the
full 8-variant matrix; the dimension flags restrict it.

## 7. Operational notes

- **Upgrading across the reserved sandbox uid**: a deployment created before
  the reserved-uid change (65536) has volume/template trees on the PVC whose
  setgid group is the old shared gid. `k8s-host-setup.sh` refuses an existing
  `sandlot` account with a different uid; after `usermod -u 65536 sandlot`,
  also re-group the storage trees **while the sandlot/prov pods are stopped**
  (the share root is re-scoped by the setup init container, the child
  directories are not):

  ```bash
  chgrp -R 65536 /path/to/volumes /path/to/templates
  ```

  Without this, pre-upgrade volumes are unreadable by the new identity and
  mounts fail with EACCES. There is no automatic recursive migration: a
  `chgrp -R` over a live PVC is an operator decision.

- **Guest TCB hostPath**: `/var/lib/sandswap` (mounted into the pods as
  `/sandswap-host`) carries the kernel/initramfs and is the guest root of
  trust. It must be root:root 0755 with 0644 artifacts — a pod-side
  identity can traverse/read but never rename or replace an entry. The
  sandlot verifies `SHA256SUMS` at start when the artifacts resolve under
  the default guest-TCB directory; the k8s configs set the explicit
  `/sandswap-host/...` paths, so the hash step applies to bare-metal shapes
  (where the default path is the root-only guest directory).
- **hostNetwork sandlots**: the sandlot DaemonSet runs hostNetwork — it
  must reach the guest TAPs and the boxout socket; NetworkPolicy does not
  govern hostNetwork pods (cluster-wide rules still apply to the gateways).
- **Production egress policy (hostNetwork/guest traffic)**: NetworkPolicy
  also does not cover guest TAP traffic forwarded through the host. A
  production deployment must not use the test/reference blanket FORWARD
  ACCEPT; enable the egress enabler (Carrier A `-binding-backend=shm|bpf`
  or Carrier B `-network-backend=routed-ipv6` + `-iid-template`), deploy a
  third-party enforcer with default-deny, and use a host endpoint policy
  (Cilium/Calico) for hostNetwork sources. The human gateway must use
  OIDC/mTLS on the management network or an independent netns; anonymous
  mode is development/test only and must never be used in production.
- **Readiness**: the manifest probes `/health` for both the readiness and
  liveness probes (liveness stays up through a warming-up gateway);
  `/ready` is the stricter signal — it flips ready only after the
  identity/ownership full load — and is what `sandctl health-all`
  probe.
- **VM re-adopt on pod restart**: sandvmm child processes survive sandlot
  container restarts by design (`KillMode` equivalent: only the main
  process is signalled); the restarted sandlot re-adopts surviving VMs and
  reconnects — the connect-clean invariant (see
  [Resilience](../how-it-works/resilience.md), the sandlot self-protection
  section) makes this safe.
- **instance.id**: multi-node pools namespace their VM IDs by the pod's
  instance identity — the manifests set it automatically.
- **Namespaced tenancy (OIDC)**: the namespaced `/human/ns/{ns}/…` surface
  needs the human gateway's `authn:` block — add it to the `human-config`
  ConfigMap and roll the deployment:

  ```yaml
  authn:
    issuer: https://keycloak.example.com/realms/sandswap
    client_id: sandswap
    scope_human: sandswap:human
    scope_admin: sandswap:admin
    scope_ops: sandswap:ops
  ```

  **Production MUST use OIDC or mTLS; anonymous mode must never be used in
  production.** The shipped human manifest's explicit
  `--allow-anonymous-human` is test/reference scaffolding: it lets a
  development listener start without an issuer, and a listener with neither
  an issuer nor that opt-out refuses to start. For production, replace it
  with `authn.issuer` (OIDC) or mTLS, and bind the human Service to the
  management network or an independent netns. With a non-empty issuer the
  gateway does OIDC discovery at startup — an unreachable issuer exits the
  process, so configure it only when the IdP is actually reachable from the
  pod. The namespace itself is IdP-owned (a `sandswap_ns` claim; there is no
  registry) — see [Namespaces](../how-it-works/namespaces.md).
- **Volume-name seed rotation**: `sandswap-volume-seed` holds **one key per
  naming generation** (the ConfigMap's `volume_seed_file` /
  `volume_seed_next_file` are the POINTER — which key is current, which is
  staged). The Secret is created once and preserved across teardown (the
  cleanup backs up EVERY generation key and the next deploy restores them all).
  A rotation never rewrites the key a live generation points at: it adds a new
  one. The pointer moves are ConfigMap edits, so the prov pod **hot-reloads**
  them (kubelet syncs a mounted ConfigMap within ~1 min; the instance re-reads
  on fsnotify) — no `rollout restart`:

  ```bash
  # 1) maintenance on (gateways refuse agent traffic; no restart)
  curl -sk -X POST https://<human-gw>:3100/human/maintenance -d '{"on":true,"reason":"seed rotation"}'
  # 2) wait for the drain (/stats in_use reaches 0), then add the next
  #    generation as a NEW key and point the ConfigMap at it. The file appears
  #    in the pod's mount within ~1 min; the instance adopts it (creation
  #    frozen) and records that in /run/sandswap/volume-seed-state.json.
  kubectl -n sandswap patch secret sandswap-volume-seed \
      -p "{\"data\":{\"gen-4\":\"$(base64 -w0 < next-seed)\"}}"
  kubectl -n sandswap patch configmap sandlot-prov-config --type merge \
      -p '{"data":{"sandlot-prov.yaml":"...volume_seed_next_file: /sandswap-seed/gen-4..."}}'
  # 3) run the rename where the volumes tree lives (the prov pod), with the
  #    tool copied in — the config mount is read-only, so the stage/promote
  #    POINTER edits happen through kubectl above, never through the tool.
  #    --run refuses until the instance's adoption record shows the staged
  #    generation (assert it here the same way).
  kubectl -n sandswap cp output/template-tool <prov-pod>:/tmp/template-tool
  kubectl -n sandswap cp deploy/baremetal/rotate-volume-seed.sh <prov-pod>:/tmp/
  kubectl -n sandswap exec <prov-pod> -- /tmp/template-tool seed-scan \
      --prov-config /config/sandlot-prov.yaml           # pre-flight: gate must pass
  kubectl -n sandswap exec <prov-pod> -- /tmp/rotate-volume-seed.sh \
      --prov-config /config/sandlot-prov.yaml \
      --human-url https://gateway-human.sandswap.svc.cluster.local:3100 \
      --template-tool /tmp/template-tool --run
  # 4) promote: re-point volume_seed_file at the new key and drop the staged
  #    one. The instance refuses the promotion while any volume still carries
  #    the pre-promote generation (its own daemon-side gate, independent of
  #    the tool), so a premature promote cannot land. Wait until the pod's
  #    /run/sandswap/volume-seed-state.json reports the NEW current
  #    fingerprint before turning maintenance off; a refusal leaves the old
  #    generation live and the staging intact — the safe state.
  ```

  Both pointer moves are also verified against the fleet: `/stats` carries
  every prov pod's reported generation (`prov_seeds`, from its heartbeat), and
  the tool's `--rotation off` refuses to close the window while any instance
  still reports the retired generation (it waits up to 45 s first — the view
  lags one heartbeat). With `replicas: 1` that is one entry; with more, all of
  them must converge, which a shared ConfigMap gives you for free (kubelet
  syncs each pod within ~1 min).

  An abort is recovered by re-staging the SAME key — never delete a generation
  key, and never mint a replacement seed. A deployment whose Secret is owned by
  an external secret manager (External Secrets Operator, the Secrets Store CSI
  driver, Vault) sets `SANDSWAP_VOLUME_SEED_NO_MINT=1` so the deployer refuses
  to mint instead of silently orphaning every volume name; note that ESO must
  merge its Secret data (`mergePolicy: Merge`) or a re-sync drops the staged
  generation key.

  Rotation semantics (why, and what the generations mean) are in
  [Isolation and swap](../how-it-works/isolation-and-swap.md) (the
  volume-naming layer), the storage contract's volume-naming row in
  [Storage](../operations/storage.md), and the channel contract in
  [Install bare metal](install-baremetal.md) (the seed-channel section).
- **Node reboot**: `k8s-host-setup.sh` installs the vsock udev rule and
  persists `vhost_vsock` in `/etc/modules-load.d/sandswap.conf`, so a reboot
  re-applies the device ownership (owner `sandvmm` 0600 / `sandlot` 0600). If
  the sandlot pod crash-loops with "want the sandvmm identity <uid>" after a
  node upgrade or a hand-rolled reboot, re-run
  `bash deploy/k8s/k8s-host-setup.sh --verify` on that node — every check
  names its own fix. A node whose sandlot pod dies with a missing
  `/etc/sandswap/stream-certs/client.crt`, or is refused at the stream
  handshake ("certificate CN ... does not match declared node_id"), is missing
  its own pair: `bash deploy/k8s/k8s-host-setup.sh --stream-certs-only`
  re-fetches it (add `--node <name>` when the k8s node name differs from the
  hostname).

---
title: Quick Start
nav_order: 2
---

# Quick Start

This is a step-by-step command guide for running Sandswap on a single dev
machine. Copy-paste each command in order. Two ways to get the software are
covered — a self-contained release package (no toolchain) and a source build
(developers) — then two deployment modes, plus an operator-extras section
(deployment files / client flags):

- **Release package**: unpack and run — every binary, the guest kernel, and
  etcd are prebuilt.
- **Source build**: build everything from the checkout (`build.sh all`).
- **Mode 1 — Single-node mode**: one gateway (in-process store, no
  external persistence) + one sandlot. The simplest way to try the API.
- **Mode 2 — Distributed mode**: exec gateway + etcd + sandlot, with a
  human gateway + prov sandlot for CRUD. Exercises the full distributed path
  (etcd-backed ownership, TLS/mTLS).

Deployment is always done by `deploy/baremetal/*` (systemd). `sandctl` is a
**client**: after a deploy it drives the API, DNS and pool/health views.

## 1. Getting the software

The bare-metal deployers (and every component they start) expect artifacts
under `output/`. Both paths below produce that layout; the commands in the
rest of this page are identical for both.

### 1.1 Using a release package

Download the release tarball, verify it against the release's `SHA256SUMS`
(`sha256sum -c SHA256SUMS` — the deploy tree trusts the checksums plus the
`output/.release-stamp` instead of re-deriving the kernel identity), and
unpack it into a directory the Sandswap service identities can traverse —
**`/opt/sandswap` is the recommended location**:

```bash
sudo mkdir -p /opt/sandswap
sudo tar xzf sandswap-<ver>-linux-amd64.tar.gz -C /opt/sandswap --strip-components=1
cd /opt/sandswap
```

### 1.2 Source builds: get the source

```bash
git clone https://github.com/ChaoyiHuang/sandswap.git
cd sandswap
```

Every command below uses repo-relative paths (`build/…`, `output/…`), so run
them from the repository root.

### 1.3 Source builds: one-time host dependencies

Release package users skip this section — the package already carries every
binary and the vendored etcd.

```bash
sudo bash build/install-deps.sh
# idempotent: gcc/make/go/clang/libbpf-dev/bpftool/busybox/cpio/
# libseccomp-dev/libcap-ng-dev/curl/wget/git + rustup musl target + etcd v3.6.13
# + the e2e/deploy test tools (conntrack, numactl, nfs-kernel-server,
#   nfs-common, openssl, iptables, util-linux).
# etcd is auto-downloaded if missing (checks `etcd` on PATH; otherwise downloads
# into a fresh mktemp dir and verifies the built-in SHA-256 pin before installing
# to /usr/local/bin — there is no /tmp cache trust). Override via ETCD_VERSION=v3.x.y.
# Go >= 1.26 is a separate install: https://go.dev/dl/.
```

### 1.4 Source builds: build everything

```bash
sudo bash build/build.sh all
```

The Ubuntu rootfs template layer is a chroot package install, so the full
build runs as root. An unprivileged `bash build/build.sh all` keeps an
existing complete template and fails with this command when none exists.

Builds in dependency order (`kernel → warden → initramfs → vmm → go →
rootfs-template → vsockguard`) then runs a freshness check, producing
`output/{vmlinux.bin,initramfs.cpio.gz,sandvmm,warden,gateway,sandlot,boxout,sandns,sandctl}`
among others. The full artifact table and per-target details are in
[Building](../building/index.md).

### 1.5 Source builds: verify

```bash
bash build/build.sh check   # fails if any output/ is missing or stale
ls -lh output/{vmlinux.bin,initramfs.cpio.gz,sandvmm,warden,gateway,sandlot,sandns,sandctl}
which etcd etcdctl          # source builds only; release packages use output/etcd/
```

### 1.6 The deployed layout

The bare-metal deployers install a systemd stack; nothing is generated into
the checkout. The paths every mode shares:

```
/etc/sandswap/
  gateway.yaml, gateway-exec.yaml, gateway-human.yaml   # gateway configs
  sandlot.yaml, sandlot-prov.yaml                       # node configs
  certs/                                                # TLS + stream mTLS pairs
  identity.env                                          # RESOLVED service ids
  sandctl.env                                           # public client contract
/var/lib/sandswap/
  volumes/ templates/ flat-templates/ state/            # agent + template storage
/usr/local/bin/sandswap-{gateway,sandlot,sandvmm}       # service binaries
/usr/local/lib/sandswap/guest/                          # guest TCB (root-only)
```

`sandctl` reads `/etc/sandswap/sandctl.env` automatically (public URLs + CA;
never a private key). Its only local state is the agent-key cache
`run/agents.json` under `--run-dir` (default `./run`, `0600`, owned by the
invoking user).

---

## 2. Mode 1 — Single-node mode

The simplest mode: one gateway (in-process `MemoryStore`, no external
persistence) + one sandlot, installed as systemd services. The node stream
always uses per-node mTLS: the gateway binds the hello's `node_id` to the
client certificate CN and refuses a certificate-less stream. **No etcd, no
DNS needed** — the gateway holds all state in memory and the sandlot connects
to it directly. HTTP listeners use TLS by default.

### 2.1 Deploy gateway + sandlot

```bash
sudo bash deploy/baremetal/deploy-single-node.sh --skip-build
```

The deployer prepares the host (service identities, udev, sysctls), mints the
certificates, seeds the `rootfs:v1` template, installs and enables
`sandswap-gateway.service` + `sandswap-sandlot.service`, waits for the pool
(`CLEAN >= 3`), and only then writes `/etc/sandswap/sandctl.env`.
`--no-tls` makes the HTTP listeners plaintext (stream mTLS stays on);
`--pool SPEC` changes the warm pool.

### 2.2 Check status

```bash
systemctl status sandswap-gateway sandswap-sandlot --no-pager
journalctl -u sandswap-sandlot -n 50 --no-pager
deploy/baremetal/sandswap-ops.sh status      # cluster/health view
output/sandctl health-all                    # probes /health + /ready
```

### 2.3 Create an agent

```bash
output/sandctl api agent create --name demo
```

Returns `agent_id` + `api_key`. The key is cached in `run/agents.json`, so
subsequent `--agent <id>` calls resolve it automatically — no need to copy it.

### 2.4 Create a SandFS

```bash
output/sandctl api sandfs create --agent <agent_id> --name s1 \
    --template rootfs:v1 --mode flat --vcpus 2 --memory-mb 512
```

`rootfs:v1` is the busybox template included with `build.sh all` — the
deployer seeds it to `/var/lib/sandswap/flat-templates/rootfs/v1/`.
`--vcpus` / `--memory-mb` are concrete resource requirements. Note the
returned `sandfs_id` — every execution call addresses its target sandbox with
it explicitly.

### 2.5 Execute code

```bash
output/sandctl api execute --agent <agent_id> --sandfs <sandfs_id> \
    --code 'echo hi' --language shell
```

Returns `stdout`, `exit_code`, and per-stage timings.

### 2.6 File I/O

```bash
output/sandctl api file --agent <agent_id> --sandfs <sandfs_id> \
    --action write --path hello.txt --data 'hi'
output/sandctl api file --agent <agent_id> --sandfs <sandfs_id> \
    --action read  --path hello.txt
output/sandctl api file --agent <agent_id> --sandfs <sandfs_id> \
    --action list_dir --path / --depth 1
```

### 2.7 Background exec

```bash
# Start a background task (returns exec_id immediately)
output/sandctl api execute --agent <agent_id> --sandfs <sandfs_id> \
    --code 'sleep 30' --background --lease 60

# Poll status
output/sandctl api exec-status <exec_id> --agent <agent_id> --sandfs <sandfs_id>

# Kill it
output/sandctl api exec-kill <exec_id> --agent <agent_id> --sandfs <sandfs_id>
```

### 2.8 Pool & health

```bash
output/sandctl pool            # cluster pool view (single-node: local /stats)
output/sandctl health-all      # probe gateway + human /health + /ready
deploy/baremetal/sandswap-ops.sh logs gateway 50   # journalctl tail
```

### 2.9 List / delete

```bash
output/sandctl api sandfs list
output/sandctl api agent list
output/sandctl api template list
output/sandctl api sandfs delete <sandfs_id>
output/sandctl api agent delete <agent_id>
```

### 2.10 Clean up

```bash
sudo bash deploy/baremetal/uninstall.sh
```

Stops and disables the units, detaches vsockguard, and removes the host
mutations. The default removes `/var/lib/sandswap` (all agent data);
`--keep-data` preserves the agent volumes.

---

## 3. Mode 2 — Distributed mode

Distributed mode: the gateway uses `EtcdStore` (persists to etcd) and the
whole chain is TLS/mTLS. One exec gateway serves `/agent/*`; one human
gateway serves the control plane (`/human/*`, SandFS/template CRUD,
ownership). This guide runs both on one machine with separate ports, sharing
one etcd.

### 3.1 Deploy etcd + exec gateway + sandlot (+ human gateway + prov sandlot)

```bash
sudo bash deploy/baremetal/deploy-one-machine-etcd.sh --skip-build
```

The deployer installs and enables `sandswap-etcd.service`,
`sandswap-gateway@exec.service` (`:3000` agent, `:9998` stream),
`sandswap-gateway@human.service` (`:3100` human, `:9996` prov stream),
`sandswap-sandlot-instance@main.service` (exec pool) and
`sandswap-sandlot-prov.service` (storage plane). It gates on the pool and on
the human gateway reporting `provisioners >= 1`, then writes
`/etc/sandswap/sandctl.env` with the exec/human URLs and the etcd endpoint.
`--no-tls` makes HTTP and etcd plaintext (stream mTLS stays on).

### 3.2 Check status

```bash
systemctl status 'sandswap-gateway@exec' 'sandswap-gateway@human' \
    sandswap-etcd sandswap-sandlot-instance@main sandswap-sandlot-prov --no-pager
deploy/baremetal/sandswap-ops.sh status
output/sandctl health-all
```

`sandswap-ops.sh status` shows both gateways and the pool; the human gateway
reports the connected prov instances:

```bash
curl --cacert /etc/sandswap/certs/ca.crt https://127.0.0.1:3100/health
# → {"provisioners":1,"status":"ok"}
```

The shipped human listener is anonymous on loopback (the unit passes
`-allow-anonymous-human`); a production human gateway must use OIDC or mTLS
instead.

### 3.3 The human gateway and prov sandlot

- **`sandswap-gateway@human`** — the human gateway: `mode: human`, serving
  the human API on `:3100` (SandFS/template CRUD, ownership ops), with a
  prov-only stream on `:9996`.
- **`sandswap-sandlot-prov`** — the prov sandlot: a sandlot instance running
  the provision role (node id `prov-1`, its own per-node certificate) that
  dials `:9996` and executes every sandfs/template storage op. It has no VM
  pool.

### 3.4 Create agent + SandFS (via the human gateway)

```bash
output/sandctl api agent create --name dist-demo
output/sandctl api sandfs create --agent <agent_id> \
    --name s1 --template rootfs:v1 --mode flat --vcpus 2 --memory-mb 512
```

`sandctl` reads `human_url` from the client contract, so CRUD commands hit
the human gateway automatically. Creating the SandFS writes its ownership to
etcd. Note the returned `sandfs_id`.

### 3.5 Execute code (via the exec gateway, owner-routed)

```bash
output/sandctl api execute --agent <agent_id> --sandfs <sandfs_id> \
    --code 'echo distributed-ok'
```

The exec gateway (`:3000`) receives the request, looks up ownership in etcd,
and routes to the sandlot holding the SandFS. The agent key is resolved from
`run/agents.json` (created in 3.4), so no `--api-key` is needed.

### 3.6 File I/O

File I/O goes through the **exec gateway** (`/agent/file` on `:3000`), same as
execute. `--sandfs` is required — requests address their sandbox explicitly:

```bash
output/sandctl api file --agent <agent_id> --sandfs <sandfs_id> \
    --action write --path d.txt --data dist
output/sandctl api file --agent <agent_id> --sandfs <sandfs_id> \
    --action read --path d.txt
```

### 3.7 Background exec

```bash
output/sandctl api execute --agent <agent_id> --sandfs <sandfs_id> \
    --code 'sleep 20' --background --lease 60
output/sandctl api exec-status <exec_id> --agent <agent_id> --sandfs <sandfs_id>
output/sandctl api exec-kill   <exec_id> --agent <agent_id> --sandfs <sandfs_id>
```

### 3.8 Pool (multi-gateway)

```bash
output/sandctl pool          # both gateways and their nodes
output/sandctl pool --raw
```

`pool` tries etcd first. The deploy's etcd client key belongs to the
`sandserv` identity, so an ordinary user sees the `/stats` fallback (the same
aggregate view, served anonymously on the human listener). Run it as root if
you want the direct-etcd path.

You can also `curl` the human gateway's `/stats`:

```bash
curl --cacert /etc/sandswap/certs/ca.crt https://127.0.0.1:3100/stats | python3 -m json.tool
```

The exec gateway (`:3000`) gates `/stats` and `/metrics` behind
`-ops-token-file` — disabled (404) by default; see
[gateway configuration](../operations/configuration/gateway.md).

### 3.9 Other commands

```bash
output/sandctl health-all
output/sandctl api sandfs list
output/sandctl api ownership release <sandfs_id>
```

This topology does not run sandns; the `dns` commands need a DNS-bearing
deployment.

### 3.10 Clean up

```bash
sudo bash deploy/baremetal/uninstall.sh
```

Stops and disables every unit (both gateways, both sandlots, etcd), removes
the host mutations, and deletes `/var/lib/sandswap` unless `--keep-data`.
Verify no residuals:

```bash
pgrep -af 'sandvmm|sandswap-(gateway|sandlot|etcd)' || echo "clean"
ss -ltn | grep -E ':(3000|3100|9998|2379)' || echo "ports clean"
```

---

## 4. Operator extras: deployment files & client flags

Everything above installs through `deploy/baremetal`; this section is for
operating it by hand.

**Deployment files.** The deployers generate `/etc/sandswap/*.yaml` (plain
YAML, fully editable) and the systemd units. Edit, then restart:

```bash
sudo vi /etc/sandswap/gateway.yaml
sudo systemctl restart sandswap-gateway
sudo journalctl -u sandswap-gateway -n 50 --no-pager
```

**Client contract.** `/etc/sandswap/sandctl.env` is `root:root 0644` and
carries public material only (URLs, TLS toggle, CA path; plus the etcd
endpoint in the distributed shape). `sandctl` reads it automatically; set
`SANDSWAP_SANDCTL_ENV` to point at another file. It never names a private
key, and `sandctl` never reads a service identity's key. `--client-cert` /
`--client-key` are for mTLS deployments and must be caller-owned `0600`
files.

**Global flags.** Global flags go before the subcommand and override the
contract:

```
--run-dir --bin-dir --gateway-url --human-url --dns-addr --etcd
--tls --ca --client-cert --client-key --insecure --raw --dry-run
```

`--dry-run` prints the HTTP request without sending; `--raw` skips JSON
pretty-printing. See [sandctl](../operations/sandctl.md) for the full command
& flag reference.

Measured latency (command-execution path + asynchronous unmount), with
reproduction scripts, lives in [Benchmark](../benchmark/index.md).

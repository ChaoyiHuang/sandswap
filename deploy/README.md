# Sandswap Developer Deployment Scripts

> ## ⚠ Developer validation / reference implementation — NOT a production installer
>
> This directory is **developer tooling**. The scripts under `deploy/` exist to
> bring up test clusters, to drive the e2e battery, and to serve as executable
> reference implementations of the installation mechanics (what is installed
> where, unit ordering, verification shape). They are **not** supported
> production installers.
>
> They assume a disposable host/cluster and may:
>
> - run as root and create/modify service users, groups and directories;
> - export a loopback NFS test share (non-squashing) and mount test volumes;
> - start gateways with `-allow-anonymous-human`;
> - `chmod 666 /dev/net/tun` and attach vsockguard with test UIDs;
> - install blanket FORWARD rules and other test-only network shortcuts;
> - delete `/run/sandswap`, test volumes, etcd state and processes.
>
> **Do not run these scripts unmodified on a production host or cluster, and do
> not copy their settings into production.** Production deployments must follow
> [Install — Bare Metal](../docs/deployment/install-baremetal.md) or
> [Install — Kubernetes](../docs/deployment/install-kubernetes.md) plus the
> [Operations](../docs/operations/index.md) hardening, and must design their own
> automation, staging rehearsal and staged rollout. In particular, production
> storage follows [Storage §4](../docs/operations/storage.md#4-production-storage-isolation-must--the-storage-service-is-not-a-tenant-network):
> Kerberos or squashed NFS exports, storage-network isolation, default-deny
> guest egress, and 2770/0660 volume modes.
>
> If you are an operator looking for the install path, start at
> [docs/deployment](../docs/deployment/index.md) — not here.

## What is here

| Path | Purpose | Production? |
|---|---|---|
| `baremetal/` | Bare-metal test deployers, sample cluster YAML, systemd units, cert/seed tools, verification drills (`verify-*.sh`) | No — validation/reference; `verify-*.sh` are verification aids, not an acceptance substitute |
| `k8s/` | Kubernetes manifests, deploy-lib, image build and host setup for the k3s-based test topology | No — validation/reference |
| `setup-network.sh` | Test/validation bridge + NAT setup; called by the deployers | No — production network isolation is operator-owned |
| `gen-certs.sh`, `baremetal/gen-baremetal-certs.sh`, `k8s/gen-k8s-certs.sh` | Test PKI generation | No — production PKI is operator-owned |
| `run-matrix.sh` | Test matrix runner (uses a loopback NFS test export) | No |
| `udev/` | Device-permission rules used by the test host prep | Reference only |

> Test-only settings that must never be promoted: anonymous human control
> plane, loopback NFS test export, `chmod 666 /dev/net/tun`, blanket FORWARD
> ACCEPT, and the test PKI/CA material. See
> [docs/deployment/index.md](../docs/deployment/index.md) and
> [docs/operations/storage.md](../docs/operations/storage.md#4-production-storage-isolation-must--the-storage-service-is-not-a-tenant-network).

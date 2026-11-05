---
title: Deployment
nav_order: 8
has_children: true
permalink: /deployment/
---

# Deployment

> **`deploy/` is developer validation tooling — not a production installer.**
> The scripts under `deploy/` exist to bring up test clusters and to validate
> the stack end to end; they are also the reference implementations of the
> installation mechanics (what is installed where, unit ordering, verification
> shape). They assume a disposable host/cluster, may run as root, create or
> modify service users, export a loopback NFS test share, start human
> gateways with `-allow-anonymous-human`, `chmod 666 /dev/net/tun`, and install
> blanket FORWARD rules. Those settings are **test scaffolding**; they are not
> production-safe. A production deployment designs its own automation, staging
> rehearsal, and rollout on top of the install guides below plus the
> [Operations](../operations/index.md) hardening, and must not copy the test
> settings into a production host. `deploy/baremetal/verify-*.sh` scripts are
> verification aids for an already-deployed stack; they are still not a
> substitute for the production checklist.

> **Production must also enable the egress enabler.** Sandswap provides the
> per-agent identity binding and the TAP choke point; it does not ship a
> production egress policy. Select **Carrier A** (`-binding-backend=shm|bpf`)
> or **Carrier B** (`-network-backend=routed-ipv6` + `-iid-template`), and
> deploy a third-party enforcer with a default-deny allowlist (metadata,
> storage and cluster CIDRs are the deployer's policy). See
> [Egress Enabler Contract](../how-it-works/egress-enabler.md) and
> [Egress Integration](../integration/egress-integration.md).

> **Production human control plane:** must use **OIDC or mTLS**. Anonymous
> mode (`-allow-anonymous-human` / `authn.allow_anonymous`) is
> **development/test only and must never be used in production**. Bind the
> human listener to the management network or an independent netns; do not
> co-locate it with the sandvmm network identity.

Deploying Sandswap on real hosts. The section order matches the order you
perform the steps in.

1. **[Host Prerequisites](prerequisites.md)** — what every machine must satisfy before install: the pre-deploy checklist, kernel/hardware, service identities, device permissions, sysctls, vsockguard, and the volumes mount flags (common to bare-metal and Kubernetes; differences called out per deployment mode).
2. **[Install — Bare Metal](install-baremetal.md)** — systemd-based deployment on VMs or physical hosts.
3. **[Install — Kubernetes](install-kubernetes.md)** — Kubernetes deployment (k3s-based tooling); embedded mode is the default, boxout is an option for stricter isolation requirements.

After the install, verify the running system per topology — commands with
expected outputs live at the end of each topology section in
[Install — Bare Metal](install-baremetal.md), and the failure→fix table is
[Deployment troubleshooting](install-baremetal.md#16-troubleshooting).

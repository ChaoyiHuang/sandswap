# Sandswap

<div align="center">
  <b>183x TinyVM Reuse per Second · AI Agent Rotation ~6 ms<br/>
     Warm ~0.958 ms · Cold ~2.323 ms · Swap (async.) ~3.106 ms<br/>
  (benchmarked on bare-metal KVM)</b>
</div>

```
                              ┌─────┐
  resolve gateway addr - - - ►│ dns │  owner-aware, etcd-driven routing
                              └─────┘  (multi-gateway deployments only)
  ┌- - - - - - - - - - - - - - ┘ 
  ▼
AI agents ──HTTP/MCP──► gateway ──gRPC stream──► sandlot (node) ──KVM──► tinyVM
                           │                        │                       │
                  auth · pool · lease      virtio-fs allow-dir       warden (PID 1)
                   ownership (etcd)       vsock exec/mount/swap       agent sandfs
```

## Under the hood

A compute-and-disk decoupled tinyVM architecture built from scratch
for AI Agents:

- ⚡ **Pure-compute tinyVM**: Only a custom hardened guest kernel + PID 1
  warden. Zero baked-in rootfs.
- ⚡ **Dynamic SandFS swap**: The agent's rootfs directory (SandFS) is mounted
  via virtio-fs allow-dirs on demand (~2.3 ms cold, ~0.96 ms warm), keeping
  files and pip/apt installs persistent.
- ⚡ **Zero legacy overhead**: No boot, no image pull,
  no snapshot/suspend/resume/restore.
- ⚡ **Millisecond reclamation**: Once idle past a configurable threshold
  (down to 1 ms), SandFS swaps out asynchronously off the response path
  (~3.1 ms), scrubbing state for the next agent.
- ⚡ **4-layer strict isolation**: A custom-hardened guest kernel, PID 1
  warden, purpose-built sandvmm, and host defenses enforce 4-layer
  isolation — matching or exceeding traditional VMs.

In bare-metal KVM benchmarks, a single tinyVM can be reused ideally up to
183 times per second. An agent's reasoning takes seconds while commands
run in milliseconds, so one tinyVM rotates across 50–100 agents —
cutting sandbox cost by 50–100x.

Agents run commands over two surfaces with identical semantics — HTTPS
and MCP(with zero code changes). Every path is engineered for ultra-low
latency, and isolation security is never traded for speed. The same
architecture extends to serverless scenarios as well.

Refer to the [Load Benchmark Report](docs/benchmark/baremetal-load.md),
[Benchmark Report](docs/benchmark/baremetal.md), and
[Reproducing](docs/benchmark/reproducing.md).

## Quick start

### Requirements

Linux with KVM (`/dev/kvm`, `/dev/vhost-vsock`); host kernel ≥ 5.10 covers
everything. Build prerequisites: see
[Building](docs/building/index.md).

### For AI agents

Copy-paste the block below to try Sandswap end to end on one machine —
download the prebuilt release (no Go/Rust toolchain), deploy, watch real
AI agents work against it, then uninstall:

```bash
# resolve the latest release tag (or pin one, e.g. VER=v0.1.0)
VER=$(curl -fsSL -o /dev/null -w '%{url_effective}' \
    https://github.com/ChaoyiHuang/sandswap/releases/latest | awk -F/ '{print $NF}')
echo "latest release: ${VER}"

# download + verify + extract
curl -fLO "https://github.com/ChaoyiHuang/sandswap/releases/download/${VER}/sandswap-${VER}-linux-amd64.tar.gz"
curl -fLO "https://github.com/ChaoyiHuang/sandswap/releases/download/${VER}/SHA256SUMS"
sha256sum -c SHA256SUMS
tar xzf "sandswap-${VER}-linux-amd64.tar.gz" && cd "sandswap-${VER}-linux-amd64"

# deploy single node (systemd services, dedicated non-root identities)
sudo bash deploy/baremetal/deploy-single-node.sh --skip-build

# 3 real AI agents against the deployment: creates the agents + sandfs and
# prints every LLM↔sandbox interaction
# (key: DEEPSEEK_API_KEY, or OPENAI_API_KEY / GOOGLE_API_KEY)
sudo env DEEPSEEK_API_KEY=sk-... \
    bash deploy/baremetal/verify-eino.sh --agent-count 3

# uninstall (--keep-data preserves the /var/lib/sandswap agent volumes)
sudo bash deploy/baremetal/uninstall.sh
```

Agents themselves need no SDK and no code changes — point the tool backend
at Sandswap, authenticate with an API key, address one SandFS by its
`sandfs_id` over either surface (same semantics):
[MCP](docs/integration/agent-mcp.md) (`POST /mcp`, 12 tools) ·
[HTTP](docs/integration/agent-http.md) (`POST /agent/execute`,
`POST /agent/file`).

### For humans

Build, install the single-node systemd stack, then drive it with `sandctl`:

```bash
git clone https://github.com/ChaoyiHuang/sandswap.git
cd sandswap
sudo bash build/install-deps.sh    # one-time toolchain
sudo bash build/build.sh all       # kernel → warden → initramfs → vmm → go (+ rootfs chroot)
# Install gateway + sandlot (+ warm VM pool) as systemd services. The
# deployer writes /etc/sandswap/sandctl.env — the public client contract
# (TLS URLs + CA, no private keys) sandctl reads automatically.
sudo bash deploy/baremetal/deploy-single-node.sh --skip-build
# The API client runs as your normal user: no sudo, no service credentials.
output/sandctl api agent create --name demo
output/sandctl api sandfs create --agent <agent_id> --name s1 \
    --template rootfs:v1 --mode flat --vcpus 2 --memory-mb 512
output/sandctl api execute --agent <agent_id> --sandfs <sandfs_id> \
    --code 'echo hi' --language shell
# Lifecycle + logs: systemctl / journalctl / deploy/baremetal/sandswap-ops.sh
# Remove the stack: sudo bash deploy/baremetal/uninstall.sh
```

Full walkthrough (including distributed mode with etcd + DNS + TLS):
[Quick Start](docs/getting-started/index.md).

## Talk & write-ups

- **CNCF AI TCG (November 2026)** —
    ["Sandswap: ultra efficient sandboxes for AI agents"](https://chaoyihuang.github.io/posts/blog/sandswap-ultra-high-efficient-sandbox-for-ai-agents.html) — Walkthrough
    of compute-disk decoupling, guest kernel hardening, four layers isolation,
    ultra low latency engineering, etc.

## Documentation

The full documentation lives in [`docs/`](docs/) and is published as a
GitHub Pages site (Jekyll + just-the-docs).

- **[Getting Started](docs/getting-started/index.md)** — copy-paste
  walkthrough on one dev machine: single-node mode and distributed mode
  (etcd + DNS + TLS).
- **[Benchmark](docs/benchmark/index.md)** — measured reports with
  reproduction scripts: [bare metal](docs/benchmark/baremetal.md) ·
  [bare metal load](docs/benchmark/baremetal-load.md) ·
  [nested virtualization](docs/benchmark/nested-virt.md) ·
  [nested virtualization load](docs/benchmark/nested-virt-load.md) ·
  [reproducing](docs/benchmark/reproducing.md).
- **[How It Works](docs/how-it-works/index.md)** — the system from the
  outside in: concepts, architecture, design principles, topologies,
  SandFS, templates, isolation & swap, guest kernel hardening,
  VM lifecycle, ownership & DNS, resilience, vsockguard, egress enabler,
  threat model — plus one page per component
  (gateway · sandlot · sandvmm · warden · boxout · dns).
- **[Integration](docs/integration/index.md)** — connecting clients and
  surrounding systems: human/agent HTTP, MCP, auth, VMM, storage backends,
  OCI registry, Prometheus, egress integration.
- **[Building](docs/building/index.md)** — compile from source:
  prerequisites, every `build.sh` target and output, template images,
  common failure modes.
- **[Testing](docs/testing/index.md)** — the self-contained e2e suite,
  `run-matrix.sh`, and the full per-script catalog.
- **[Deployment](docs/deployment/index.md)** — host
  [prerequisites & hardening](docs/deployment/prerequisites.md) ·
  [bare metal](docs/deployment/install-baremetal.md) ·
  [Kubernetes](docs/deployment/install-kubernetes.md).
- **[Operations](docs/operations/index.md)** — per-component
  [configuration](docs/operations/configuration/index.md), the
  [sandctl](docs/operations/sandctl.md) CLI, [etcd](docs/operations/etcd.md),
  [storage](docs/operations/storage.md),
  [templates](docs/operations/template-contract.md),
  [observability](docs/operations/observability.md),
  [release](docs/operations/release.md),
  [troubleshooting](docs/operations/troubleshooting.md).
- **[Reference](docs/reference/index.md)** — lookup:
  [agent API](docs/reference/agent-api.md) ·
  [human API](docs/reference/human-api.md) ·
  [MCP tools](docs/reference/mcp-tools.md) ·
  [internal protocols](docs/reference/protocols.md) ·
  [FAQ](docs/reference/faq.md).

## Repository layout

```
common/       shared proto definitions (gateway↔sandlot gRPC protocol)
gateway/      HTTP API server, gRPC stream server, pool manager (Go)
sandlot/      per-node daemon: VMM lifecycle, SandFS swap in/out (Go)
boxout/       privileged VM-lifecycle sidecar for K8s (Go)
dns/          owner-aware routing DNS (Go)
sandctl/      human CLI (Go, stdlib-only)
vmm/          KVM virtual machine monitor (Rust, fork of Cloud Hypervisor, enhanced)
warden/       in-VM PID 1 agent (Rust)
network/vsockguard/  BPF LSM vsock transport guard (C)
initramfs/    minimal initramfs: warden + busybox
kernel/       guest kernel: pinned source tree + hardening
templates/    rootfs templates (busybox base, sqlite, …)
examples/     example agents: Eino, openai-go, keepalive client
e2e/          self-contained end-to-end test scripts
build/        build scripts (all components + freshness check)
deploy/       deployment scripts (baremetal + k8s)
security/     vsockguard attach/verify + host-security tooling
docs/         the documentation site (this is what GitHub Pages publishes)
```

## Community chat

A Discord server where enthusiasts can share experience and ideas and
help one another:
[https://discord.gg/STkNKJ5m65](https://discord.gg/STkNKJ5m65).
If a formal community is established later, this server may be closed.

## BSL · Donation · Community

**Chaoyi Huang** — the original author of Sandswap, a cancer survivor, a fully
independent developer, not employed by or affiliated with any company or
organization.

**Why BSL 1.1?** The Business Source License is a funding mechanism, not a
restriction for its own sake. Sandswap is free for individuals, startups,
and the vast majority of companies — any use, including production, forever.
The BSL terms attach conditions to exactly one group: **Revenue Threshold
Entities** (annual revenue ≥ US$1B in any of 2026–2028), which need a
production-use grant from the Licensor. This gives Sandswap's largest
beneficiaries a direct way to support the project: a **one-time donation**
in exchange for a BSL production grant. The purpose is simple and personal —
so that no matter what the future brings, the original author can secure a
healthy financial situation for the family.

**Two years, then fully open.** The BSL window is deliberately short and
fixed: every version released before the Change Date automatically becomes
[Apache-2.0](https://www.apache.org/licenses/LICENSE-2.0) on
**November 30, 2028** — no action by anyone, ever — and versions first
released after that date are Apache-2.0 from the start. Development,
testing, QA, staging, and evaluation use are unrestricted for everyone
throughout.

**Community.** Due to ongoing health challenges, the author unfortunately
cannot commit much time to community building and will only be able to
offer support on important directions and topics. Sandswap therefore
depends on its users to sustain it: companies and individuals — especially
those who donated to obtain the BSL production grant — are warmly
encouraged to take the initiative in building a sustainable community,
whether by answering questions, triaging bugs, developing features,
reviewing PRs, hardening for production, improving documentation,
stewarding integrations, or leading governance and outreach.

## License

See [LICENSE](LICENSE) · [License FAQ](LICENSE-FAQ.md) · [CLA](CLA.md) ·
[NOTICE](NOTICE).

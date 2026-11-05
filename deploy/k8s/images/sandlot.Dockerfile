# Sandswap Sandlot — Ubuntu-based image with iproute2 and vsockguard.
#
# Uses ubuntu:22.04 as base because:
#   1. sandvmm (Rust VMM) is dynamically linked and needs glibc + libcap-ng
#   2. iproute2 is required for bridge networking (ip tuntap/bridge commands
#      in sandlot/network/bridge_nat.go) when --network-backend=bridge
#   3. vsockguard BPF object + loader are included for per-node vsock transport
#      protection (attached by init container)
#
# The sandlot Go binary itself is static (CGO_ENABLED=0), but the sandvmm
# Rust binary cannot be statically linked due to its C dependency on libcap-ng.
#
# Runs as UID 0 (root). On cgroup v2 kernels, K8s uses eBPF for device
# management and non-privileged containers cannot access hostPath CharDevice
# volumes (/dev/kvm, /dev/vhost-vsock). Additionally, Linux capabilities are
# only effective for UID 0 — sandlot needs CAP_SYS_ADMIN (mount/umount) and
# CAP_NET_ADMIN (ip tuntap/bridge). The K8s pod uses privileged: true for
# cgroup device access, with capabilities: drop ALL + add SYS_ADMIN, NET_ADMIN
# to document the 2 capabilities actually used (note: privileged overrides
# drop/add, so these serve as intent documentation).
#
# Future improvement: CDI device injection (the device plugin API is in
# maintenance mode; its replacement is DRA on top of CDI, which containerd
# ≥1.6 and CRI-O implement natively) would allow removing privileged and
# running as the bare-metal sandlot identity with ambient capabilities —
# see the security block in deploy/k8s/sandlot.yaml.
#
# Build:
#   cd output && docker build -t sandswap/sandlot:latest -f ../deploy/k8s/images/sandlot.Dockerfile .
#
# The build context must contain:
#   sandlot            (static Go binary)
#   sandvmm            (dynamic Rust binary)
#   vsockguard.bpf.o   (BPF LSM program)
#   vsockguardctl      (libbpf control tool)
FROM ubuntu:22.04
# Acquire::Retries: mirror fetches flake transiently (slow periods, one DNS
# lookup failing) — a 5x retry rides those out instead of failing the whole
# leg with "Package has no installation candidate".
RUN apt-get -o Acquire::Retries=5 update && \
    apt-get -o Acquire::Retries=5 install -y --no-install-recommends iproute2 nftables util-linux && \
    rm -rf /var/lib/apt/lists/*
# util-linux ships setpriv — REQUIRED: the sandvmm identity-split spawn
# (uid 987 + exactly CAP_NET_ADMIN) is a setpriv wrapper exec.
COPY sandlot /sandlot
COPY sandvmm /sandvmm
COPY vsockguard.bpf.o /sandswap/vsockguard.bpf.o
COPY vsockguardctl /sandswap/vsockguardctl
COPY bindregdump /sandswap/bindregdump
# Invariant 8: re-create nosuid,nodev on the PVC-backed volumes tree in the
# container's own mount namespace (the runtime bind drops the host flags).
COPY sandlot-entrypoint.sh /entrypoint.sh
RUN chmod 0755 /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]

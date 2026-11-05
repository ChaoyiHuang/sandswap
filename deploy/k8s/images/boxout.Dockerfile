# Boxout container image — privileged VM lifecycle manager.
#
# Runs as UID 0 with CAP_SYS_ADMIN + CAP_NET_ADMIN. Owns:
#   - sandvmm process lifecycle (Launch, Kill, Shutdown)
#   - Network provisioning (TAP/IP via BridgeNAT — requires iproute2)
#   - OverlayFS mount/unmount (CAP_SYS_ADMIN)
#   - /proc scanning for re-adopt
#   - Crash detection (pidfdMonitor + cmd.Wait)
#   - vsockguard BPF LSM attach (init container only)
#
# Uses ubuntu:22.04 as base because:
#   1. sandvmm (Rust VMM) is dynamically linked and needs glibc + libcap-ng
#   2. iproute2 is required for bridge networking (ip tuntap/bridge commands)
#   3. nftables is required for the egress network baseline (per-tap source
#      anti-spoof + VM-to-VM posture) and the routed-ipv6 identity stamps —
#      without it the baseline silently degrades to off (WARNING at startup)
#   4. vsockguard BPF object + loader are included for vsock transport protection
#
# Build:
#   cd output && docker build -t sandswap/boxout:latest -f ../deploy/k8s/images/boxout.Dockerfile .
#
# The build context must contain:
#   boxout             (static Go binary)
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
COPY boxout /boxout
COPY sandvmm /sandvmm
COPY vsockguard.bpf.o /sandswap/vsockguard.bpf.o
COPY vsockguardctl /sandswap/vsockguardctl
COPY bindregdump /sandswap/bindregdump
# Invariant 8: the boxout sidecar owns the host volumes mount; re-create
# nosuid,nodev in its container namespace (the runtime bind drops the flags).
COPY boxout-entrypoint.sh /entrypoint.sh
RUN chmod 0755 /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]

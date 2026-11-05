# Sandlot container image — boxout mode (unprivileged, RESERVED UID 65536) AND the
# provision-plane Deployment (sandlot-prov).
#
# All Sandswap images share the ubuntu:22.04 base. The sandlot binary is
# static (CGO_ENABLED=0). Neither consumer needs:
#   - sandvmm (owned by the boxout sidecar; the prov pod never creates VMs)
#   - iproute2 (network ops delegated to boxout; prov does no host networking)
#   - vsockguard (attached by the DaemonSet's init container)
# The base keeps a shell so post-deploy verification can exec in
# (e.g. `kubectl exec ... -- id` to confirm the UID) — scratch images made
# that impossible and forced spec-based checks instead.
#
# ca-certificates: REQUIRED by the prov role — OCI template pull/push moved
# to the provision plane with the storage split, and a Go binary verifies
# registry TLS against the SYSTEM store (empty on a bare ubuntu base → every
# public-registry pull fails with "certificate signed by unknown authority").
#
# Build:
#   cd output && docker build -t sandswap/sandlot-boxout:latest -f ../deploy/k8s/images/sandlot-boxout.Dockerfile .
FROM ubuntu:22.04
# Acquire::Retries: mirror fetches flake transiently (slow periods, one DNS
# lookup failing) — a 5x retry rides those out instead of failing the whole
# leg with "Package has no installation candidate".
RUN apt-get -o Acquire::Retries=5 update && \
    apt-get -o Acquire::Retries=5 install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*
COPY sandlot /sandlot
COPY bindregdump /sandswap/bindregdump
ENTRYPOINT ["/sandlot"]

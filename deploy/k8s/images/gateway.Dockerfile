# Sandswap Gateway — Ubuntu-based image (static Go binary).
#
# All Sandswap images share the ubuntu:22.04 base. The gateway binary is
# static (CGO_ENABLED=0) so it needs no glibc — the base exists so that:
#   1. there is a shell for kubectl exec debugging (scratch/distroless images
#      turned every "exec in and look" diagnostic into a dead end)
#   2. ca-certificates is present for any future outbound TLS with system
#      verification. NB the gateway itself mounts NO storage and does NO OCI
#      pulls since the storage split — template registry traffic belongs to
#      the prov pods (see sandlot-boxout.Dockerfile); the gateway's etcd and
#      stream TLS use mounted certs and never touch the system store
#
# Build:
#   cd output && docker build -t sandswap/gateway:latest -f ../deploy/k8s/images/gateway.Dockerfile .
#
# The build context must contain: gateway (static Go binary)
FROM ubuntu:22.04
# Acquire::Retries: mirror fetches flake transiently (slow periods, one DNS
# lookup failing) — a 5x retry rides those out instead of failing the whole
# leg with "Package has no installation candidate".
RUN apt-get -o Acquire::Retries=5 update && \
    apt-get -o Acquire::Retries=5 install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*
COPY gateway /gateway
EXPOSE 3000 9998
ENTRYPOINT ["/gateway"]

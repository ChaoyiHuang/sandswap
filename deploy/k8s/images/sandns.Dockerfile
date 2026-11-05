# Sandswap DNS — Ubuntu-based image (static Go binary).
#
# All Sandswap images share the ubuntu:22.04 base. The sandns binary is static
# (CGO_ENABLED=0) and needs no packages: it listens on :53 UDP+TCP and reads
# its etcd mTLS certs from the etcd-certs Secret. The base keeps a shell for
# kubectl exec debugging (scratch/distroless images made every diagnostic
# that assumed a shell a dead end).
#
# Build:
#   cd output && docker build -t sandswap/sandns:latest -f ../deploy/k8s/images/sandns.Dockerfile .
#
# The build context must contain: sandns (static Go binary)
FROM ubuntu:22.04
COPY sandns /sandns
EXPOSE 53
ENTRYPOINT ["/sandns"]

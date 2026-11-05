#!/bin/sh
# Sandswap embedded-sandlot entrypoint (invariant 8).
#
# Why this exists: the K8s container runtime bind-mounts a PVC into the
# container and the bind's per-mount flags do NOT carry the host's
# nosuid,nodev (containerd's bind+remount drops them). The sandlot refuses
# to start when its -volumes-dir is not on such a mount — a deliberate
# fail-closed gate, because the virtio-fs passthrough stores guest-planted
# setuid bits and mknod verbatim. Re-create the flags INSIDE this container's
# mount namespace (the embedded sandlot runs privileged) before exec'ing the
# real binary. Idempotent: skips a mount that already carries both flags.
set -e

for d in /sandswap/volumes /sandswap/overlay-templates; do
    [ -d "$d" ] || continue
    opts=$(awk -v d="$d" '$2==d {print $4}' /proc/mounts | head -1)
    case "$opts" in
        *nosuid*nodev*|*nodev*nosuid*) ;;
        *)
            mount --bind "$d" "$d"
            mount -o remount,bind,nosuid,nodev "$d"
            ;;
    esac
done

exec /sandlot "$@"

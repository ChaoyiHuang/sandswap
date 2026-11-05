#!/bin/sh
# Sandswap boxout entrypoint (invariant 8).
#
# The boxout sidecar is the privileged owner of the host-side volumes tree
# in boxout mode. Its container runtime bind of a PVC drops the per-mount
# nosuid,nodev flags, so re-create them in THIS container's namespace (the
# sidecar runs privileged) before exec'ing the real binary. Idempotent.
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

exec /boxout "$@"

#!/bin/sh
# sandswap-apply-prov-ownership — the systemd units' ExecStartPost: re-assert
# the prov-side path ownership for THIS deployment's shape at every unit
# start (a stale hand-chown, an old deploy or a changed shape must not
# survive). Reads /etc/sandswap/prov-user.env (written by the deployer;
# SS_PROV_USER=sandprov for a dedicated prov instance, sandlot for the merged
# exec,prov shape); default sandprov keeps dedicated shapes safe.
#
# This is the INCARNATION of deploy/baremetal/common.sh's
# sandswap_apply_prov_plane for the unit context (no bash, no lib sourcing in
# ExecStartPost) — keep the two in lockstep; the ownership matrix lives in
# that function's comment.
set -u
[ -f /etc/sandswap/prov-user.env ] && . /etc/sandswap/prov-user.env
PROV="${SS_PROV_USER:-sandprov}"
if [ -d /var/lib/sandswap/volumes ]; then
    chown "$PROV":sandlot /var/lib/sandswap/volumes
    chmod 2710 /var/lib/sandswap/volumes
fi
for d in templates flat-templates overlay-templates; do
    p=/var/lib/sandswap/$d
    if [ -d "$p" ]; then
        chown "$PROV":sandlot "$p"
        chmod 2750 "$p"
    fi
done

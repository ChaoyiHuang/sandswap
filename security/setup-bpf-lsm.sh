#!/bin/bash
# Copyright 2026 Chaoyi Huang. All rights reserved.
#
# SPDX-License-Identifier: BUSL-1.1
#
# Use of this software is governed by the Business Source License
# included in the LICENSE file at the root of this repository.
#
# As of the Change Date specified in that file, in accordance with
# the Business Source License, use of this software will be governed
# by the Apache License, Version 2.0.
#
# setup-bpf-lsm.sh — one-time enablement of the `bpf` LSM for vsockguard.
# vsockguard attaches a BPF LSM program to socket_connect to deny non-sandlot
# UIDs from connect()-ing to the warden vsock port. BPF LSM hooks only fire if
# the `bpf` LSM is in the kernel's active LSM list (/sys/kernel/security/lsm).
# Many distros (e.g. Ubuntu) ship with CONFIG_LSM that omits `bpf`, so the hook
# is unregistered and an attached program is a SILENT no-op. This script adds
# `bpf` to the `lsm=` kernel boot parameter (idempotent) and asks the operator
# to reboot — after which vsockguard can actually enforce.
# This is the same one-time requirement as Tetragon / Falco / systemd BPF LSM.
# Must run as root. Only the boot parameter changes; nothing else is modified.

set -euo pipefail

LSM_FILE="/sys/kernel/security/lsm"

if [ "$(id -u)" -ne 0 ]; then
    echo "error: must run as root (sudo)" >&2
    exit 1
fi

# Already active?
if grep -qE '(^|,)bpf(,|$)' "$LSM_FILE" 2>/dev/null; then
    echo "bpf LSM already active: $(cat "$LSM_FILE")"
    echo "Nothing to do. vsockguard can be attached."
    exit 0
fi

current="$(cat "$LSM_FILE" 2>/dev/null || echo "")"
target="${current:+${current},}bpf"
echo "Current LSM list: ${current:-<empty>}"
echo "Target  LSM list: ${target}"
new_lsm="lsm=${target}"

# ── Find the effective GRUB_CMDLINE_LINUX_DEFAULT definition ────────────────
#
# GRUB sources /etc/default/grub then /etc/default/grub.d/*.cfg (in lexical
# order). A later assignment WINS — so on GCP/AWS Ubuntu images, the cloud
# snippet (e.g. 50-cloudimg-settings.cfg) overrides anything in /etc/default/grub.
# Editing only /etc/default/grub is a no-op there (the lsm= never reaches
# grub.cfg). We must edit whichever file is the LAST to define the var.
#
# Resolve order: /etc/default/grub first, then grub.d/*.cfg sorted, last writer wins.
all_files=()
[[ -f /etc/default/grub ]] && all_files+=(/etc/default/grub)
if [[ -d /etc/default/grub.d ]]; then
    while IFS= read -r f; do all_files+=("$f"); done < <(find /etc/default/grub.d -maxdepth 1 -type f -name '*.cfg' | sort)
fi

# Last file that actually defines GRUB_CMDLINE_LINUX_DEFAULT.
effective_file=""
for f in "${all_files[@]}"; do
    if grep -q '^GRUB_CMDLINE_LINUX_DEFAULT=' "$f"; then
        effective_file="$f"
    fi
done

if [[ -z "$effective_file" ]]; then
    echo "error: no GRUB_CMDLINE_LINUX_DEFAULT found in /etc/default/grub or grub.d/" >&2
    echo "       (non-Debian? set $new_lsm in your bootloader manually)" >&2
    exit 1
fi

# Read the CURRENT effective value (from the effective file, which wins).
cur_default="$(awk -F= '/^GRUB_CMDLINE_LINUX_DEFAULT=/{sub(/^GRUB_CMDLINE_LINUX_DEFAULT=/,""); gsub(/^"|"$/,""); print}' "$effective_file")"

# Build new value: replace an existing lsm= token, else append.
if echo " $cur_default " | grep -qE ' lsm=[^ ]+ '; then
    new_default="$(echo " $cur_default " | sed -E "s/ lsm=[^ ]+ / ${new_lsm} /" | sed -E 's/^ //; s/ $//')"
else
    new_default="${cur_default}${cur_default:+ }${new_lsm}"
fi

echo "Effective file:   $effective_file"
echo "Effective before: $cur_default"
echo "Effective after:  $new_default"

# Warn if /etc/default/grub also defines it but is shadowed by grub.d/.
shadowed=()
for f in "${all_files[@]}"; do
    if [[ "$f" != "$effective_file" ]] && grep -q '^GRUB_CMDLINE_LINUX_DEFAULT=' "$f"; then
        shadowed+=("$f")
    fi
done
if [[ ${#shadowed[@]} -gt 0 ]]; then
    echo "  (note: /etc/default/grub's value is overridden by $(basename "$effective_file");"
    echo "   editing the effective file directly.)"
fi

# Rewrite the effective file's GRUB_CMDLINE_LINUX_DEFAULT to the computed value.
if [[ "$new_default" == "$cur_default" ]]; then
    echo "No change to the value."
else
    sed -i -E "s|^GRUB_CMDLINE_LINUX_DEFAULT=.*|GRUB_CMDLINE_LINUX_DEFAULT=\"${new_default}\"|" "$effective_file"
    echo "Updated $effective_file:"
    grep '^GRUB_CMDLINE_LINUX_DEFAULT=' "$effective_file"
fi

# Regenerate grub.cfg.
if command -v update-grub >/dev/null 2>&1; then
    update-grub >/dev/null
elif command -v grub2-mkconfig >/dev/null 2>&1; then
    grub2-mkconfig -o /boot/grub2/grub.cfg >/dev/null
else
    echo "warning: no update-grub / grub2-mkconfig found; regenerate grub config manually." >&2
fi

# ── CRITICAL verification: confirm lsm= actually reached grub.cfg ───────────
# This catches the "edited /etc/default/grub but grub.d overrides it" failure
# that otherwise leaves a green-looking script with zero effect.
grub_cfg=""
for c in /boot/grub/grub.cfg /boot/grub2/grub.cfg; do
    [[ -f "$c" ]] && grub_cfg="$c" && break
done
if [[ -n "$grub_cfg" ]]; then
    if grep -q "lsm=[^ ]*bpf" "$grub_cfg"; then
        echo "✓ verified: grub.cfg contains lsm=...bpf ($grub_cfg)"
    else
        echo "✗ ERROR: lsm=...bpf is NOT in $grub_cfg after update-grub." >&2
        echo "  The change did not reach the actual boot config." >&2
        echo "  Check /etc/default/grub.d/*.cfg for an overriding GRUB_CMDLINE_LINUX_DEFAULT" >&2
        echo "  and edit the effective (last-sourced) file manually." >&2
        exit 1
    fi
fi

echo ""
echo "Done. REBOOT NOW to activate the bpf LSM:"
echo "  sudo reboot"
echo "After reboot verify with: cat $LSM_FILE   (must list 'bpf')"
echo "Then attach vsockguard:  bash security/vsockguard-attach.sh <sandlot-uid>"

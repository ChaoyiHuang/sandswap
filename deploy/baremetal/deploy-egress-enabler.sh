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
# deploy-egress-enabler.sh — Deploy + test the EGRESS IDENTITY ENABLER on baremetal.
# Dedicated, self-contained entry point for the egress identity feature
# (docs/how-it-works/egress-enabler.md): it turns ON the enabler switches, runs the
# normal single-node deploy with them, verifies the FEATURE end-to-end on the
# deployed system, and then cleans everything up. The plain deploy
# (deploy-single-node.sh) and its verification are untouched — all enabler
# configuration travels through environment variables that default to off.
# DEFAULT (no arguments) runs the FULL variant matrix — every deployment
# combination of the feature switches, each as a complete lifecycle:
#   network backend {bridge, routed-ipv6} × binding carrier {shm, bpf}
#   1. bridge    + shm    (the default configuration)
#   2. bridge    + bpf    (bpffs carrier: kernel ≥ 5.5)
#   3. routed-v6 + shm    (identity-in-address; needs guest kernel w/ IPv6)
#   4. routed-v6 + bpf    (both switches together)
# Flags FILTER the matrix (they restrict, never extend):
#   --binding-backend shm|bpf   only this carrier
#   --routed-ipv6               only the routed-ipv6 variants
#   --bridge                    only the bridge variants
#   --skip-cleanup              leave the LAST variant deployed (no teardown)
# Per-variant lifecycle (mirrors the deploy discipline):
#   clean start (cleanup.sh) → deploy with enabler on → feature verify
#   → full cleanup (cleanup.sh) → zero-residue check
# What is verified, on the REAL deployed stack (systemd gateway+sandlot):
#   E1  binding region opened by sandlot (startup banner, carrier from --backend)
#   E2  egress baseline active (per-tap anti-spoof chains + exactly ONE
#       vm2vm rule — no duplicate stacking)
#   E3  region lifecycle: during a held mount the region reads
#       `mounted epoch=N agent=<id> sandfs=<id>`; after unmount the SAME slot
#       reads `unbound` with the SAME epoch and identity cleared
#   E4  the exec really ran with network (guest default route present) —
#       guards the silent-offline-VM failure class (v4 route on bridge, v6 on
#       routed-ipv6)
#   E5  (routed-ipv6) identity stamp address + SNAT map element on the TAP
#       during the mount, removed after unmount

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
source "$ROOT/deploy/baremetal/common.sh"

# ── Flags (matrix filters) ────────────────────────────────────────────────
FILTER_BACKEND=""   # "" = both carriers
FILTER_NET=""       # "" = both network backends
SKIP_CLEANUP=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --binding-backend) FILTER_BACKEND="$2"; shift 2 ;;
        --routed-ipv6)     FILTER_NET="routed-ipv6"; shift ;;
        --bridge)          FILTER_NET="bridge"; shift ;;
        --skip-cleanup)    SKIP_CLEANUP=1; shift ;;
        *) echo "unknown flag: $1 (want --binding-backend shm|bpf | --routed-ipv6 | --bridge | --skip-cleanup)" >&2; exit 1 ;;
    esac
done
case "$FILTER_BACKEND" in ""|shm|bpf) ;; *) echo "--binding-backend must be shm|bpf" >&2; exit 1 ;; esac
case "$FILTER_NET" in ""|bridge|routed-ipv6) ;; *) echo "network filter must be bridge|routed-ipv6" >&2; exit 1 ;; esac

# ── Variant matrix ────────────────────────────────────────────────────────
VARIANTS=()
for net in bridge routed-ipv6; do
    [[ -n "$FILTER_NET" && "$net" != "$FILTER_NET" ]] && continue
    for carrier in shm bpf; do
        [[ -n "$FILTER_BACKEND" && "$carrier" != "$FILTER_BACKEND" ]] && continue
        VARIANTS+=("$net|$carrier")
    done
done
if [[ ${#VARIANTS[@]} -eq 0 ]]; then
    echo "flag filter selected no variants" >&2; exit 1
fi
echo "═══ Egress identity enabler: ${#VARIANTS[@]} variant(s) to verify ═══"
printf '    %s\n' "${VARIANTS[@]//|/ + }"

# ── Prerequisites (self-contained: the script prepares what it needs) ─────
# kernel_has_ipv6 — CONFIG_IPV6 probe (official CH release kernels ship with
# it OFF; the string below only exists in net/ipv6/reassembly.o).
# NB: NO `grep -q`: under pipefail, -q makes grep exit on the first match and
# the upstream producer eats SIGPIPE (141) → the probe FAILS on success. Let
# grep drain its input instead.
kernel_has_ipv6() {
    strings "$ROOT/output/vmlinux.bin" 2>/dev/null | grep "ip6_frag_reasm" > /dev/null
}

needs_v6=0
for v in "${VARIANTS[@]}"; do [[ "$v" == routed-ipv6* ]] && needs_v6=1; done
if [[ "$needs_v6" == "1" ]]; then
    if kernel_has_ipv6; then
        log "guest kernel has CONFIG_IPV6 (routed-ipv6 variants OK)"
    else
        log "output/vmlinux.bin lacks CONFIG_IPV6 — building the custom kernel (one-time, ~15min)"
        bash "$ROOT/kernel/build.sh" custom
        kernel_has_ipv6 || { log_error "custom kernel build finished but the image still lacks IPv6"; exit 1; }
    fi
fi

enabler_pass() { echo -e "\033[0;32m[✓]\033[0m $*"; }
enabler_fail() { echo -e "\033[0;31m[✗]\033[0m $*"; }

# ── Per-variant lifecycle ─────────────────────────────────────────────────
# run_variant <net> <carrier> [keep] — deploy with the switches on, verify,
# clean up. Exported SANDSWAP_* keys are consumed by
# sandswap_generate_sandlot_config (common.sh); empty values mean "off", so
# each variant starts from the plain config and adds only its own switches.
# A deploy or verify failure is RECORDED, cleaned up, and the matrix continues
# (never leave a broken deployment for the next variant to inherit).
run_variant() {
    local net="$1" carrier="$2" keep="${3:-}"
    local routed6=0
    [[ "$net" == "routed-ipv6" ]] && routed6=1

    log "═══ [$net + $carrier] [1/4] Clean start ═══"
    bash "$ROOT/deploy/baremetal/cleanup.sh" > "/tmp/enabler-clean-${net}-${carrier}-start.log" 2>&1 || true

    # The bpf carrier needs `bpf(2)` — and the sandlot unit's
    # SystemCallFilter=@system-service deliberately EXCLUDES it (the syscall
    # is in @privileged/@bpf, not in @system-service), so a correct ambient
    # CAP_SYS_ADMIN still gets EPERM from seccomp: "cannot create mmapable
    # array map (operation not permitted ...)"
    # (the k8s legs never hit it: privileged containers carry no
    # such filter). The enabler node OPTS IN with a drop-in — the default
    # posture of every other deployment keeps the filter intact. Written
    # BEFORE the deploy so the unit's first start already carries it;
    # removed in the cleanup leg below and by cleanup.sh.
    DROPIN_DIR=/etc/systemd/system/sandswap-sandlot.service.d
    if [[ "$carrier" == "bpf" ]]; then
        install -d -m 0755 "$DROPIN_DIR"
        cat > "$DROPIN_DIR/egress-bpf.conf" <<'EOF'
# Egress identity enabler — bpf carrier (installed by deploy-egress-enabler.sh).
# Allows bpf(2) through the unit's syscall filter; the region create still
# requires ambient CAP_SYS_ADMIN (already granted) and bpffs DAC on the pin.
[Service]
SystemCallFilter=bpf
EOF
        systemctl daemon-reload 2>/dev/null || true
        log "bpf carrier: syscall-filter drop-in installed ($DROPIN_DIR/egress-bpf.conf)"
    else
        rm -f "$DROPIN_DIR/egress-bpf.conf" 2>/dev/null || true
    fi

    log "═══ [$net + $carrier] [2/4] Deploy with the enabler on ═══"
    # EGRESS_POOL bounds the VM pool this drill deploys (default 3, the drill's
    # documented shape). Smaller hosts can lower it: the assertions need more
    # than ONE VM, not a specific count.
    local pool="${EGRESS_POOL:-3}"
    if ! SANDSWAP_BINDING_BACKEND="$carrier" \
         SANDSWAP_VM_TO_VM_POLICY="deny" \
         SANDSWAP_NETWORK_BACKEND="$net" \
         SANDSWAP_IID_TEMPLATE="$([[ $routed6 == 1 ]] && echo 'agent:32,sandfs:32' || echo '')" \
         bash "$ROOT/deploy/baremetal/deploy-single-node.sh" --pool "medium:${pool}"; then
        enabler_fail "deploy failed (log above); variant recorded as failed"
        FAILED_VARIANTS+=("$net+$carrier(deploy)")
        bash "$ROOT/deploy/baremetal/cleanup.sh" > "/tmp/enabler-clean-${net}-${carrier}-abort.log" 2>&1 || true
        return 0
    fi
    # sandswap_wait_for_pool's err() exits — run it in a subshell so a failed
    # wait fails THIS variant instead of the whole matrix.
    if ! ( sandswap_wait_for_pool "localhost:3100" "$pool" 120 ); then
        enabler_fail "pool did not come up"
        FAILED_VARIANTS+=("$net+$carrier(pool)")
        bash "$ROOT/deploy/baremetal/cleanup.sh" > "/tmp/enabler-clean-${net}-${carrier}-abort.log" 2>&1 || true
        return 0
    fi

    log "═══ [$net + $carrier] [3/4] Feature verification ═══"
    if ! BINDING_BACKEND="$carrier" ROUTED_IPV6="$routed6" enabler_verify; then
        FAILED_VARIANTS+=("$net+$carrier(verify)")
    fi

    if [[ "$keep" == "keep" ]]; then
        log "═══ [$net + $carrier] [4/4] Cleanup SKIPPED (--skip-cleanup); deployment left running ═══"
        return 0
    fi
    log "═══ [$net + $carrier] [4/4] Full cleanup (leave no residue) ═══"
    bash "$ROOT/deploy/baremetal/cleanup.sh" > "/tmp/enabler-clean-${net}-${carrier}-end.log" 2>&1 || true
    check_residue || FAILED_VARIANTS+=("$net+$carrier(residue)")
    return 0
}

# check_residue — zero-residue assertion after cleanup.
#
# The process check gets a bounded grace first: cleanup sends SIGTERM and the
# sandlot's own shutdown is asynchronous (it may be mid-reconnect when the
# gateway goes away — observed as "residue: processes = 1" while the process
# exited a moment later). Everything else is checked
# immediately — the fs/net residue is removed synchronously by cleanup.
check_residue() {
    local rc=0 cmd name n
    local i
    for i in $(seq 1 10); do
        pgrep -f '^/usr/local/bin/sandswap-(sandvmm|sandlot|gateway|dns)' >/dev/null 2>&1 || break
        sleep 1
    done
    # Anchored to the installed binary path: a bare -f pattern self-matches any
    # shell whose command text CONTAINS the pattern (eval strings, polls) — the
    # pgrep self-match trap, re-found here as a phantom "residue".
    for chk in "pgrep -c -f '^/usr/local/bin/sandswap-(sandvmm|sandlot|gateway|dns)':processes" \
               "ip link show br-sandswap 2>/dev/null | wc -l":bridge \
               "ip -o link show 2>/dev/null | grep -c tap-":taps \
               "nft list tables 2>/dev/null | grep -c sandswap":nftables \
               "ls /run/sandswap 2>/dev/null | wc -l":run-dir \
               "ls /var/lib/sandswap 2>/dev/null | wc -l":var-lib \
               "ls /dev/shm/sandswap-bindings 2>/dev/null | wc -l":shm-region \
               "ls /sys/fs/bpf/sandswap 2>/dev/null | wc -l":bpf-pin; do
        cmd="${chk%%:*}"; name="${chk##*:}"
        # `| tail -1` + `|| true`: pgrep/grep -c exit 1 on no match, and `|| echo 0`
        # would append a second 0, misreading "clean" as a leftover.
        n=$(eval "$cmd" 2>/dev/null | tail -1 || true)
        n=${n:-0}
        if [[ "$n" != "0" ]]; then
            enabler_fail "residue: $name = $n"; rc=1
        fi
    done
    if [[ "$rc" == "0" ]]; then
        enabler_pass "zero residue after cleanup"
    fi
    return $rc
}

# enabler_verify — feature assertions against the deployed stack. Reads
# BINDING_BACKEND (shm|bpf) and ROUTED_IPV6 (0|1) from the environment.
enabler_verify() {
    local rc=0
    local HUMAN="https://localhost:3100" GW="https://localhost:3000"

    # E1: sandlot opened the region with the requested carrier.
    # NB: capture-then-grep — `journalctl | grep -q` under pipefail fails on a
    # match when grep -q closes the pipe early and journalctl eats SIGPIPE (141).
    # Window = the unit's current activation, not a wall-clock guess: a full
    # variant lifecycle (cleanup → deploy → pool wait → verify) can overrun a
    # fixed "10 minutes ago" and drop the startup banner from the window,
    # while a WIDER fixed window would match a PREVIOUS variant's banner.
    local unit_start jlog
    unit_start=$(systemctl show -p ActiveEnterTimestamp --value sandswap-sandlot 2>/dev/null || true)
    jlog=$(journalctl -u sandswap-sandlot --since "${unit_start:-@0}" --no-pager 2>/dev/null || true)
    # NO grep -q on a pipe: it exits on the first match, the producer eats
    # SIGPIPE, and pipefail turns a successful match into a failed check.
    if echo "$jlog" | grep -E "egress identity binding: $BINDING_BACKEND" >/dev/null; then
        enabler_pass "E1: binding region opened ($BINDING_BACKEND)"
    else
        enabler_fail "E1: no 'egress identity binding: $BINDING_BACKEND' in sandlot log"; rc=1
    fi

    # E2: baseline chains + exactly one vm2vm rule. The anti-spoof rule is
    # `ip saddr` on bridge and `ip6 saddr` on routed-ipv6 — match either.
    if nft list table netdev sandswap_baseline 2>/dev/null | grep -E "ip6? saddr !=" >/dev/null; then
        enabler_pass "E2: per-tap anti-spoof chains present"
    else
        enabler_fail "E2: netdev baseline chain missing"; rc=1
    fi
    local vm2vm
    vm2vm=$(nft list chain bridge sandswap_baseline fwdgate 2>/dev/null | grep -c "vm2vm-deny" || true)
    if [[ "$vm2vm" == "1" ]]; then
        enabler_pass "E2: vm2vm posture rule present exactly once"
    else
        enabler_fail "E2: vm2vm rule count = $vm2vm (want 1)"; rc=1
    fi

    # E3/E4(/E5): real exec through the gateway; hold the mount open and read
    # the region mid-flight.
    local agent key aid sfsid
    agent=$(curl -sk -X POST "$HUMAN/human/agent" -H "Content-Type: application/json" -d '{"name":"enabler-verify"}')
    key=$(echo "$agent" | python3 -c "import sys,json;print(json.load(sys.stdin).get('api_key',''))")
    aid=$(echo "$agent" | python3 -c "import sys,json;print(json.load(sys.stdin).get('agent_id',''))")
    local sfs
    sfs=$(curl -sk -X POST "$HUMAN/human/sandfs" -H "Authorization: Bearer $key" -H "Content-Type: application/json" \
        -d "{\"agent_id\":\"$aid\",\"name\":\"enabler-verify\",\"template\":\"rootfs:v1\",\"mode\":\"flat\"}")
    sfsid=$(echo "$sfs" | python3 -c "import sys,json;print(json.load(sys.stdin).get('sandfs_id',''))")
    if [[ -z "$key" || -z "$aid" || -z "$sfsid" ]]; then
        enabler_fail "agent/sandfs creation failed (agent=$aid sandfs=$sfsid)"; return 1
    fi
    enabler_pass "test agent ready ($aid / $sfsid)"

    # E4 route probe follows the backend: bridge guests have a v4 default
    # route, routed-ipv6 guests have ONLY a v6 one.
    local route_cmd="ip -o -4 route show default | grep -E default >/dev/null"
    [[ "$ROUTED_IPV6" == "1" ]] && route_cmd="ip -o -6 route show default | grep -E default >/dev/null"
    curl -sk -X POST "$GW/agent/execute" -H "Authorization: Bearer $key" -H "Content-Type: application/json" \
        -d "{\"sandfs_id\":\"$sfsid\",\"code\":\"sleep 12; $route_cmd && echo net-ok\",\"language\":\"shell\",\"timeout\":60}" \
        > /tmp/enabler-exec.json &
    local bgpid=$!
    sleep 6

    local REGION_PATH="/dev/shm/sandswap-bindings"
    local REGION_ARGS=(-backend "$BINDING_BACKEND")
    if [[ "$BINDING_BACKEND" == "bpf" ]]; then
        REGION_PATH="/sys/fs/bpf/sandswap/bindings"
    fi

    # E3: region DURING the mount.
    local dump
    dump=$("$ROOT/output/bindregdump" "${REGION_ARGS[@]}" -path "$REGION_PATH" 2>/dev/null || true)
    if echo "$dump" | grep -E "mounted .*agent=$aid .*sandfs=$sfsid" >/dev/null; then
        enabler_pass "E3: region shows the mount during exec ($(echo "$dump" | grep mounted | head -1))"
    else
        enabler_fail "E3: no mounted region entry for this exec: $(echo "$dump" | tail -2 | tr '\n' ' ')"; rc=1
    fi
    local epoch ifidx
    # Anchor on THIS test's mount line, not "any mounted line": with a
    # multi-VM pool another tenant's mount could otherwise win the race.
    local mounted_line
    mounted_line=$(echo "$dump" | grep "mounted .*agent=$aid .*sandfs=$sfsid" | head -1)
    epoch=$(echo "$mounted_line" | python3 -c "import sys,re;m=re.search(r'epoch=(\d+)',sys.stdin.read());print(m.group(1) if m else '')")
    ifidx=$(echo "$mounted_line" | awk '{print $1}')

    # E5 (routed-ipv6): identity stamp on the TAP + SNAT element. The tap is
    # derived from the MOUNTED slot's ifindex — a multi-VM pool keeps CLEAN
    # VMs with their own TAPs and NO stamp (stamping happens at mount), so
    # picking the host's first tap makes this check flaky.
    if [[ "$ROUTED_IPV6" == "1" ]]; then
        local tap=""
        local p
        if [[ -n "$ifidx" ]]; then
            for p in /sys/class/net/*/ifindex; do
                if [[ "$(cat "$p" 2>/dev/null)" == "$ifidx" ]]; then
                    tap=$(basename "$(dirname "$p")")
                    break
                fi
            done
        fi
        if [[ -n "$tap" ]] && nft list map inet sandswap_routed6 "stamp_${tap//-/_}" 2>/dev/null | grep -E "elements" >/dev/null; then
            enabler_pass "E5: identity SNAT map element present ($tap)"
        else
            enabler_fail "E5: SNAT stamp element missing on ${tap:-<no tap>} (mounted ifindex: ${ifidx:-none})"; rc=1
        fi
    fi

    wait $bgpid || true
    local exec_out
    exec_out=$(python3 -c "import json;d=json.load(open('/tmp/enabler-exec.json'));print(d.get('exit_code'),d.get('stdout','').strip())" 2>/dev/null || echo "? ?")
    if [[ "$exec_out" == *"0 net-ok"* ]]; then
        enabler_pass "E4: exec ran with guest networking ($exec_out)"
    else
        enabler_fail "E4: exec did not confirm networking: $exec_out"; rc=1
    fi

    # E3 (cont.): region AFTER unmount — assert on the SAME slot this exec
    # mounted (the pool has several VMs; the first unbound line may belong to
    # another attachment with an older epoch).
    local revoked=""
    for _ in $(seq 1 20); do
        dump=$("$ROOT/output/bindregdump" "${REGION_ARGS[@]}" -path "$REGION_PATH" 2>/dev/null || true)
        revoked=$(echo "$dump" | awk -v i="$ifidx" '$1 == i && $2 == "unbound"' | head -1)
        [[ -n "$revoked" ]] && break
        sleep 1
    done
    local repoch
    repoch=$(echo "$revoked" | python3 -c "import sys,re;m=re.search(r'epoch=(\d+)',sys.stdin.read());print(m.group(1) if m else '')" 2>/dev/null)
    if [[ -n "$revoked" && "$repoch" == "$epoch" && "$revoked" == *"agent= "* ]]; then
        enabler_pass "E3: after unmount — unbound, epoch preserved ($repoch), identity cleared"
    else
        enabler_fail "E3: revoke assertion failed (entry: ${revoked:-<none>}, epoch $epoch → $repoch)"; rc=1
    fi
    return $rc
}

# ── Drive the matrix ──────────────────────────────────────────────────────
FAILED_VARIANTS=()
for v in "${VARIANTS[@]}"; do
    net="${v%%|*}"; carrier="${v##*|}"
    echo ""
    log "═══════════ VARIANT: $net + $carrier ═══════════"
    keep=""
    # --skip-cleanup applies to the LAST variant: it stays deployed for
    # interactive inspection; every variant before it is fully cleaned.
    if [[ "$SKIP_CLEANUP" == "1" && "$v" == "${VARIANTS[-1]}" ]]; then
        keep="keep"
    fi
    run_variant "$net" "$carrier" "$keep"
done

echo ""
if [[ ${#FAILED_VARIANTS[@]} -eq 0 ]]; then
    log "═══ EGRESS IDENTITY ENABLER: ALL ${#VARIANTS[@]} VARIANT(S) PASSED ═══"
    exit 0
else
    log "═══ EGRESS IDENTITY ENABLER: FAILED — ${FAILED_VARIANTS[*]} ═══"
    exit 1
fi

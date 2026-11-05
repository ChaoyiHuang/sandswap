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
# deploy-k8s-egress-enabler.sh — Deploy + verify the EGRESS IDENTITY ENABLER
# on k3s (baremetal's counterpart: deploy/baremetal/deploy-egress-enabler.sh).
# Dedicated, self-contained entry for the egress identity feature
# (docs/how-it-works/egress-enabler.md). The plain k8s deploys and their tests are
# untouched: this script generates a ConfigMap overlay that turns the enabler
# keys ON, runs the normal k8s deploy with it, verifies the FEATURE inside the
# cluster, then tears everything down.
# DEFAULT (no arguments) verifies TWO scenarios — embedded mode, the diagonal
# that covers every feature-switch condition with the fewest runs:
#   embedded + bpf  + bridge       (recommended carrier; seccomp bpf(2) proof)
#   embedded + shm  + routed-ipv6  (pod-local carrier; identity-in-address)
# Two passing covers carrier {bpf,shm} × network {bridge,routed-ipv6}; the
# full matrix is opt-in. Any dimension flag below switches to matrix mode and
# RESTRICTS the matrix (original filter semantics — they never extend it):
#   --mode boxout|embedded       only this vm-mode
#   --binding-backend bpf|shm    only this carrier
#   --routed-ipv6 | --bridge     only this network backend
#   --all                        the FULL matrix — every combination of the
#                                feature switches, each as a complete lifecycle:
#                                  vm-mode {boxout, embedded}
#                                  × carrier {bpf, shm}
#                                  × network {bridge, routed-ipv6}
#   --skip-cleanup               leave the LAST variant deployed
#   --skip-build | --skip-deps   forwarded to the per-variant deploy: reuse the
#                                artifacts from the last build.sh run instead of
#                                recompiling (the kernel rebuild alone is ~20min
#                                per variant) — for verification runs on a tree
#                                whose artifacts are already fresh
# Per-variant lifecycle: clean start → deploy (enabler on, default keep mode)
# → feature verify in cluster → full cleanup (k8s-cleanup.sh) → zero-residue
# check.
# What is verified, on the REAL deployed cluster:
#   E1  sandlot opened the binding region — in boxout mode under the Localhost
#       seccomp profile (the pod runs unprivileged, UID 65536), so a populated
#       bpf region is direct proof the seccomp bpf(2) allowance works
#   E2  baseline chains exist (privileged network owner container)
#   E3  region lifecycle: during a held exec the region reads `mounted
#       epoch=N agent=<id>`; after unmount the SAME slot reads `unbound`,
#       epoch preserved
#   E4  exec ran through the cluster stack
#   E5  (routed-ipv6) identity SNAT map element in the privileged container

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
KUBECTL="kubectl"

# ── Flags ────────────────────────────────────────────────────────────────
FILTER_MODE=""
FILTER_BACKEND=""
FILTER_NET=""
ALL_MATRIX=0
SKIP_CLEANUP=0
DEPLOY_FLAGS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --mode)           FILTER_MODE="$2"; shift 2 ;;
        --binding-backend) FILTER_BACKEND="$2"; shift 2 ;;
        --routed-ipv6)    FILTER_NET="routed-ipv6"; shift ;;
        --bridge)         FILTER_NET="bridge"; shift ;;
        --all)            ALL_MATRIX=1; shift ;;
        --skip-cleanup)   SKIP_CLEANUP=1; shift ;;
        --skip-build)     DEPLOY_FLAGS+=(--skip-build); shift ;;
        --skip-deps)      DEPLOY_FLAGS+=(--skip-deps); shift ;;
        *) echo "unknown flag: $1 (want --mode boxout|embedded | --binding-backend bpf|shm | --routed-ipv6 | --bridge | --all | --skip-cleanup | --skip-build | --skip-deps)" >&2; exit 1 ;;
    esac
done
case "$FILTER_MODE" in ""|boxout|embedded) ;; *) echo "--mode must be boxout|embedded" >&2; exit 1 ;; esac
case "$FILTER_BACKEND" in ""|bpf|shm) ;; *) echo "--binding-backend must be bpf|shm" >&2; exit 1 ;; esac
case "$FILTER_NET" in ""|bridge|routed-ipv6) ;; *) echo "network filter must be bridge|routed-ipv6" >&2; exit 1 ;; esac

# ── Variant selection ────────────────────────────────────────────────────
# Default: TWO embedded scenarios — the diagonal covering every condition
# (carrier × network). Any flag (or --all) selects matrix mode instead, with
# the flags restricting the full matrix as they always did.
VARIANTS=()
if [[ "$ALL_MATRIX" == "1" || -n "$FILTER_MODE$FILTER_BACKEND$FILTER_NET" ]]; then
    for mode in boxout embedded; do
        [[ -n "$FILTER_MODE" && "$mode" != "$FILTER_MODE" ]] && continue
        for carrier in bpf shm; do
            [[ -n "$FILTER_BACKEND" && "$carrier" != "$FILTER_BACKEND" ]] && continue
            for net in bridge routed-ipv6; do
                [[ -n "$FILTER_NET" && "$net" != "$FILTER_NET" ]] && continue
                VARIANTS+=("$mode|$carrier|$net")
            done
        done
    done
else
    VARIANTS+=("embedded|bpf|bridge" "embedded|shm|routed-ipv6")
fi
if [[ ${#VARIANTS[@]} -eq 0 ]]; then
    echo "flag filter selected no variants" >&2; exit 1
fi
echo "═══ Egress identity enabler (k8s): ${#VARIANTS[@]} variant(s) to verify ═══"
printf '    %s\n' "${VARIANTS[@]//|/ + }"

# ── Prerequisites (self-contained) ────────────────────────────────────────
# kernel_has_ipv6 — CONFIG_IPV6 probe (official CH release kernels ship with
# it OFF; the string below only exists in net/ipv6/reassembly.o).
# NB: NO `grep -q`: under pipefail, -q makes grep exit on the first match and
# the upstream producer eats SIGPIPE (141) → the probe FAILS on success. Let
# grep drain its input instead.
kernel_has_ipv6() {
    strings "$ROOT/output/vmlinux.bin" 2>/dev/null | grep "ip6_frag_reasm" > /dev/null
}

needs_v6=0
for v in "${VARIANTS[@]}"; do [[ "$v" == *"|routed-ipv6" ]] && needs_v6=1; done
if [[ "$needs_v6" == "1" ]]; then
    if kernel_has_ipv6; then
        echo "guest kernel has CONFIG_IPV6 (routed-ipv6 variants OK)"
    else
        echo "output/vmlinux.bin lacks CONFIG_IPV6 — building the custom kernel (one-time, ~15min)"
        bash "$ROOT/kernel/build.sh" custom
        kernel_has_ipv6 || { echo "custom kernel build finished but the image still lacks IPv6" >&2; exit 1; }
    fi
fi

# No LLM key gate: the underlying deploys run in default keep mode (the eino
# drill is NOT part of them anymore — it moved to --verify / verify-k8s.sh),
# and the feature verification below is pure curl/kubectl/bindregdump.

enabler_pass() { echo -e "\033[0;32m[✓]\033[0m $*"; }
enabler_fail() { echo -e "\033[0;31m[✗]\033[0m $*"; }

GW_FQDN="gateway-0.gateway-exec.sandswap.svc.cluster.local"
PF_PID=""

# ensure_host_plane — the deploy's keep-mode exit reverts its port-forward
# and hosts pin (only the K8s objects are preserved). This verification needs
# the host-side control plane, so re-establish it here and record it for
# our own cleanup.
ensure_host_plane() {
    kubectl -n sandswap port-forward "svc/gateway-human" 3100:3100 > /dev/null 2>&1 &
    PF_PID=$!
    local ok=""
    for _ in $(seq 1 15); do
        if curl -sfk https://localhost:3100/health > /dev/null 2>&1; then ok=1; break; fi
        sleep 1
    done
    if [[ -z "$ok" ]]; then
        enabler_fail "host plane: human gateway port-forward did not come up"
        return 1
    fi
    local gwip
    gwip=$(kubectl -n sandswap get pod -l app=gateway -o jsonpath='{.items[0].status.podIP}' 2>/dev/null)
    if [[ -z "$gwip" ]]; then
        enabler_fail "host plane: no gateway pod IP"
        return 1
    fi
    sed -i "/$GW_FQDN/d" /etc/hosts 2>/dev/null || true
    echo "$gwip $GW_FQDN" >> /etc/hosts
    enabler_pass "host plane ready (pf pid $PF_PID, $GW_FQDN → $gwip)"
}

drop_host_plane() {
    [[ -n "$PF_PID" ]] && kill "$PF_PID" 2>/dev/null || true
    pkill -f "kubectl.*port-forward.*3100" 2>/dev/null || true
    sed -i "/$GW_FQDN/d" /etc/hosts 2>/dev/null || true
}

# gen_enabler_configmap — copy the repo ConfigMaps and ACTIVATE the enabler
# keys in the sandlot.yaml network block (the repo file ships them commented).
# `backend:` is an EXISTING key in the base file: its value is REWRITTEN (a
# second `backend:` line would be a duplicate mapping key — Go's yaml rejects
# the whole file), the other enabler keys are appended after the `dns:` line.
gen_enabler_configmap() {
    local out="$1" carrier="$2" net="$3"
    cp "$ROOT/deploy/k8s/configmaps.yaml" "$out"
    # "on" is quoted: bare `on` is a YAML-1.1 boolean (PyYAML et al.) — quoting
    # keeps it a string in every parser.
    local keys="      bind_backend: $carrier"$'\n'"      egress_baseline: \"on\""$'\n'"      vm_to_vm: deny"
    if [[ "$net" == "routed-ipv6" ]]; then
        keys="$keys"$'\n'"      v6_prefix: fd00:5341:4e44::/48"$'\n'"      iid_template: \"agent:32,sandfs:32\""
    fi
    python3 - "$out" "$keys" "$net" << 'PYEOF'
import sys
path, keys, net = sys.argv[1], sys.argv[2], sys.argv[3]
lines = open(path).read().splitlines(keepends=True)
out, inserted = [], False
for ln in lines:
    if net == "routed-ipv6" and ln.rstrip("\n") == "      backend: bridge":
        ln = "      backend: routed-ipv6\n"
    out.append(ln)
    if not inserted and ln.rstrip("\n") == '      dns: "1.1.1.1,8.8.8.8"':
        out.append(keys + "\n")
        inserted = True
if not inserted:
    sys.exit("configmap anchor 'dns: 1.1.1.1,8.8.8.8' not found")
open(path, "w").write("".join(out))
PYEOF
    # The overlay must parse as YAML — a silent parse failure means the deploy
    # would come up with the DEFAULT (enabler-off) config: fail loudly instead.
    python3 -c "import yaml,sys; docs=list(yaml.safe_load_all(open('$out'))); assert any(d and 'sandlot.yaml' in d.get('data',{}) for d in docs), 'sandlot configmap missing'" \
        || { echo "generated ConfigMap overlay failed to parse" >&2; return 1; }
}

# enabler_verify — feature assertions against the deployed cluster. Reads
# MODE / BINDING_BACKEND / ROUTED_IPV6 from the environment.
enabler_verify() {
    local rc=0
    local HUMAN="https://localhost:3100" GW="https://$GW_FQDN:3000"
    ensure_host_plane || return 1

    local DS_NAME="sandlot" DS_CONTAINER="sandlot" nftbox="sandlot"
    if [[ "$MODE" == "boxout" ]]; then
        DS_NAME="sandlot-boxout"; nftbox="boxout"
    fi
    local REGION_PATH="/sys/fs/bpf/sandswap/bindings"
    if [[ "$BINDING_BACKEND" == "shm" ]]; then
        REGION_PATH="/dev/shm/sandswap-bindings"   # pod-local
    fi

    # E2: baseline inside the privileged network owner. The anti-spoof rule is
    # `ip saddr` on bridge and `ip6 saddr` on routed-ipv6 — match either.
    # capture-then-grep: SIGPIPE-safe under pipefail (see baremetal counterpart)
    local fwd
    fwd=$($KUBECTL -n sandswap exec "ds/$DS_NAME" -c "$nftbox" -- \
        nft list chain bridge sandswap_baseline fwdgate 2>/dev/null || true)
    if echo "$fwd" | grep -q "vm2vm-deny"; then
        enabler_pass "E2: baseline vm2vm rule present ($nftbox container)"
    else
        enabler_fail "E2: baseline vm2vm rule missing in $nftbox"; rc=1
    fi

    # Real exec through the cluster gateway; hold the mount and read the region.
    local agent key aid sfsid
    agent=$(curl -sk -X POST "$HUMAN/human/agent" -H "Content-Type: application/json" -d '{"name":"egress-enabler-verify"}')
    key=$(echo "$agent" | python3 -c "import sys,json;print(json.load(sys.stdin).get('api_key',''))")
    aid=$(echo "$agent" | python3 -c "import sys,json;print(json.load(sys.stdin).get('agent_id',''))")
    local sfs
    sfs=$(curl -sk -X POST "$HUMAN/human/sandfs" -H "Authorization: Bearer $key" -H "Content-Type: application/json" \
        -d "{\"agent_id\":\"$aid\",\"name\":\"egress-enabler-verify\",\"template\":\"rootfs:v1\",\"mode\":\"flat\"}")
    sfsid=$(echo "$sfs" | python3 -c "import sys,json;print(json.load(sys.stdin).get('sandfs_id',''))")
    if [[ -z "$key" || -z "$aid" || -z "$sfsid" ]]; then
        enabler_fail "agent/sandfs creation failed (agent=$aid sandfs=$sfsid resp: $(echo "$sfs" | head -c 120))"; return 1
    fi
    enabler_pass "test agent ready ($aid / $sfsid)"

    curl -sk -X POST "$GW/agent/execute" -H "Authorization: Bearer $key" -H "Content-Type: application/json" \
        -d "{\"sandfs_id\":\"$sfsid\",\"code\":\"sleep 20; echo net-ok\",\"language\":\"shell\",\"timeout\":60}" \
        > /tmp/enabler-k8s-exec.json &
    local bgpid=$!
    sleep 6

    # E1+E3: region DURING the mount — a populated entry under seccomp IS the
    # deployment proof for the bpf(2) allowance.
    local dump
    dump=$($KUBECTL -n sandswap exec "ds/$DS_NAME" -c "$DS_CONTAINER" -- \
        /sandswap/bindregdump -backend "$BINDING_BACKEND" -path "$REGION_PATH" 2>/dev/null || true)
    if echo "$dump" | grep -q "mounted .*agent=$aid .*sandfs=$sfsid"; then
        enabler_pass "E1/E3: region shows the mount ($(echo "$dump" | grep mounted | head -1))"
    else
        enabler_fail "E1/E3: no mounted entry for this exec (dump: $(echo "$dump" | tail -2 | tr '\n' ' '))"; rc=1
    fi
    local epoch ifidx
    # Anchor on THIS test's mount line, not "any mounted line": with a
    # multi-VM pool another tenant's mount could otherwise win the race.
    local mounted_line
    mounted_line=$(echo "$dump" | grep "mounted .*agent=$aid .*sandfs=$sfsid" | head -1)
    epoch=$(echo "$mounted_line" | python3 -c "import sys,re;m=re.search(r'epoch=(\d+)',sys.stdin.read());print(m.group(1) if m else '')")
    ifidx=$(echo "$mounted_line" | awk '{print $1}')

    # E5 (routed-ipv6): identity SNAT element in the privileged container.
    # The tap is derived from the MOUNTED slot's ifindex — a multi-VM pool
    # keeps CLEAN VMs with their own TAPs and NO stamp (stamping happens at
    # mount), so picking the first tap makes this check flaky. The element
    # itself is polled for a few seconds inside the held mount (the exec
    # above sleeps 20s to leave room): a single-shot check raced slow
    # stamping. On a miss the failure carries the sandlot stamp log lines —
    # the enabler degrades silently to unstamped egress on its error paths,
    # and those lines name the exact path that fired.
    if [[ "$ROUTED_IPV6" == "1" ]]; then
        local tap e5_hit=0
        tap=$($KUBECTL -n sandswap exec "ds/$DS_NAME" -c "$nftbox" -- \
            sh -c "ip -o link show 2>/dev/null | awk -F': ' -v i=$ifidx '\$1 == i {print \$2}'" 2>/dev/null | tr -d '\r' || true)
        tap="${tap%%@*}"   # strip an @peer suffix, keep the bare tap name
        for _ in $(seq 1 6); do
            if [[ -n "$tap" ]] && $KUBECTL -n sandswap exec "ds/$DS_NAME" -c "$nftbox" -- \
                nft list map inet sandswap_routed6 "stamp_${tap//-/_}" 2>/dev/null | grep -q "elements"; then
                enabler_pass "E5: identity SNAT map element present ($tap)"
                e5_hit=1
                break
            fi
            sleep 1
        done
        if (( ! e5_hit )); then
            local stamp_log
            stamp_log=$($KUBECTL -n sandswap logs "ds/$DS_NAME" -c "$DS_CONTAINER" --tail=100 2>/dev/null \
                | grep "routed6 stamp" | tail -3 | tr '\n' ' ' || true)
            enabler_fail "E5: SNAT stamp element missing on ${tap:-<no tap>} (mounted ifindex: ${ifidx:-none}); sandlot stamp log: ${stamp_log:-<none>}"
            rc=1
        fi
    fi

    wait $bgpid || true
    local exec_out
    exec_out=$(python3 -c "import json;d=json.load(open('/tmp/enabler-k8s-exec.json'));print(d.get('exit_code'),d.get('stdout','').strip())" 2>/dev/null || echo "? ?")
    if [[ "$exec_out" == *"0 net-ok"* ]]; then
        enabler_pass "E4: exec ran through the cluster stack ($exec_out)"
    else
        enabler_fail "E4: exec did not complete: $exec_out"; rc=1
    fi

    # E3 (cont.): region AFTER unmount — on the SAME slot this exec mounted
    # (the pool has multiple VMs; the first unbound line may belong to another
    # attachment with an older epoch).
    local revoked="" dump2
    for _ in $(seq 1 20); do
        dump2=$($KUBECTL -n sandswap exec "ds/$DS_NAME" -c "$DS_CONTAINER" -- \
            /sandswap/bindregdump -backend "$BINDING_BACKEND" -path "$REGION_PATH" 2>/dev/null || true)
        revoked=$(echo "$dump2" | awk -v i="$ifidx" '$1 == i && $2 == "unbound"' | head -1)
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

# check_residue — zero-residue assertion after cleanup.
check_residue() {
    local rc=0 cmd name n
    for chk in "kubectl get ns 2>/dev/null | grep -c sandswap":namespace \
               "kubectl get pv 2>/dev/null | grep -c sandswap":pv \
               "grep -c sandswap /etc/hosts 2>/dev/null":hosts-pin \
               "ls /sys/fs/bpf/vsockguard 2>/dev/null | wc -l":bpf-pin \
               "ls /dev/shm/sandswap-bindings 2>/dev/null | wc -l":shm-region \
               "ls /sys/fs/bpf/sandswap 2>/dev/null | wc -l":bpf-region \
               "pgrep -c -f 'kubectl.*port-forward'":port-forward; do
        cmd="${chk%%:*}"; name="${chk##*:}"
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

# ── Per-variant lifecycle ─────────────────────────────────────────────────
# run_variant <mode> <carrier> <net> [keep] — a deploy/verify failure is
# RECORDED, cleaned up, and the matrix continues.
run_variant() {
    local mode="$1" carrier="$2" net="$3" keep="${4:-}"
    local routed6=0
    [[ "$net" == "routed-ipv6" ]] && routed6=1
    local DEPLOY_SCRIPT="$ROOT/deploy/k8s/deploy-k8s-embedded.sh"
    [[ "$mode" == "boxout" ]] && DEPLOY_SCRIPT="$ROOT/deploy/k8s/deploy-k8s-boxout.sh"

    echo "═══ [$mode + $carrier + $net] [1/5] Clean start ═══"
    bash "$ROOT/deploy/k8s/k8s-cleanup.sh" > "/tmp/enabler-k8s-clean-${mode}-${carrier}-${net}-start.log" 2>&1 || true

    echo "═══ [$mode + $carrier + $net] [2/5] Generate enabler ConfigMap ═══"
    local K8S_CONFIGMAP_FILE
    K8S_CONFIGMAP_FILE="$(mktemp /tmp/sandswap-configmaps-enabler-XXXX.yaml)"
    if ! gen_enabler_configmap "$K8S_CONFIGMAP_FILE" "$carrier" "$net"; then
        enabler_fail "ConfigMap overlay generation failed"
        FAILED_VARIANTS+=("$mode+$carrier+$net(configmap)")
        rm -f "$K8S_CONFIGMAP_FILE"
        return 0
    fi
    export K8S_CONFIGMAP_FILE

    echo "═══ [$mode + $carrier + $net] [3/5] Deploy (default keep mode: resources stay up for verification) ═══"
    if ! bash "$DEPLOY_SCRIPT" "${DEPLOY_FLAGS[@]}"; then
        enabler_fail "deploy failed; variant recorded as failed"
        FAILED_VARIANTS+=("$mode+$carrier+$net(deploy)")
        drop_host_plane
        bash "$ROOT/deploy/k8s/k8s-cleanup.sh" > "/tmp/enabler-k8s-clean-${mode}-${carrier}-${net}-abort.log" 2>&1 || true
        rm -f "$K8S_CONFIGMAP_FILE"
        return 0
    fi

    echo "═══ [$mode + $carrier + $net] [4/5] Feature verification in cluster ═══"
    if ! MODE="$mode" BINDING_BACKEND="$carrier" ROUTED_IPV6="$routed6" enabler_verify; then
        FAILED_VARIANTS+=("$mode+$carrier+$net(verify)")
    fi

    if [[ "$keep" == "keep" ]]; then
        echo "═══ [$mode + $carrier + $net] [5/5] Cleanup SKIPPED (--skip-cleanup); deployment left running ═══"
        rm -f "$K8S_CONFIGMAP_FILE"
        return 0
    fi
    echo "═══ [$mode + $carrier + $net] [5/5] Full cleanup (leave no residue) ═══"
    drop_host_plane
    bash "$ROOT/deploy/k8s/k8s-cleanup.sh" > "/tmp/enabler-k8s-clean-${mode}-${carrier}-${net}-end.log" 2>&1 || true
    rm -f "$K8S_CONFIGMAP_FILE"
    check_residue || FAILED_VARIANTS+=("$mode+$carrier+$net(residue)")
    return 0
}

# ── Drive the matrix ──────────────────────────────────────────────────────
FAILED_VARIANTS=()
for v in "${VARIANTS[@]}"; do
    IFS='|' read -r mode carrier net <<< "$v"
    echo ""
    echo "═══════════ VARIANT: $mode + $carrier + $net ═══════════"
    keep=""
    # --skip-cleanup applies to the LAST variant: it stays deployed for
    # interactive inspection; every variant before it is fully cleaned.
    if [[ "$SKIP_CLEANUP" == "1" && "$v" == "${VARIANTS[-1]}" ]]; then
        keep="keep"
    fi
    run_variant "$mode" "$carrier" "$net" "$keep"
done

echo ""
if [[ ${#FAILED_VARIANTS[@]} -eq 0 ]]; then
    echo "═══ EGRESS IDENTITY ENABLER (k8s): ALL ${#VARIANTS[@]} VARIANT(S) PASSED ═══"
    exit 0
else
    echo "═══ EGRESS IDENTITY ENABLER (k8s): FAILED — ${FAILED_VARIANTS[*]} ═══"
    exit 1
fi

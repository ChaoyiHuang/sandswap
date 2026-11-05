#!/usr/bin/env bash
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
# pin.sh — shared bare-metal CPU/NUMA pinning for the latency benchmarks.
#
# The bare-metal reports are measured with the host stack (gateway, sandlot,
# benchmark client) on a small set of whole physical cores and every microVM
# on its own CPU slice of the SAME NUMA node, with the VM's guest RAM bound to
# that node (numactl --physcpubind/--membind).  An unpinned run leaves the
# placement to the host scheduler; the same binary then varies by 0.1ms+ warm
# P50 across runs because a VM's vCPU or vhost/virtiofs thread can land on a
# sibling thread of a stack core or on the far NUMA node.  Pinning removes
# that variance; it changes no sandswap security property (it is a pure
# scheduling/memory policy on the benchmark side).
#
# Nested virtualization does NOT use pinning: the L1 guest vCPUs are already
# scheduled by the outer hypervisor, and binding them to L1 CPUs only adds
# noise.  PIN_MODE=auto (the default) therefore resolves to 1 on bare metal
# and 0 under any hypervisor.
#
# Consumers:
#   e2e/latency-benchmark-aiagent.sh
#   e2e/latency-benchmark-unmount.sh
# The load benchmark has its own richer partitioner (per-role stack layout,
# per-level host CPU accounting) and only reuses tc_pin_resolve_mode.

# tc_pin_host_nested — 0 = bare metal, 1 = nested/VM.
tc_pin_host_nested() {
    local virt hyper
    virt="$(systemd-detect-virt 2>/dev/null || true)"
    virt="${virt//$'\n'/}"
    hyper=$(grep -c -m1 '^flags.* hypervisor' /proc/cpuinfo 2>/dev/null) || true
    if [[ ( "$virt" == "none" || -z "$virt" ) && "${hyper:-0}" -eq 0 ]]; then
        echo 0
    else
        echo 1
    fi
}

# tc_pin_resolve_mode <nested 0|1> — echo the effective PIN_MODE (0|1).
# PIN_MODE=auto (default): bare metal -> 1, nested -> 0.
tc_pin_resolve_mode() {
    local nested="${1:-$(tc_pin_host_nested)}"
    case "${PIN_MODE:-auto}" in
        0|1) echo "${PIN_MODE}" ;;
        auto) if [[ "$nested" == "0" ]]; then echo 1; else echo 0; fi ;;
        *) echo "PIN_MODE must be auto|0|1 (got '${PIN_MODE}')" >&2; return 1 ;;
    esac
}

# tc_pin_topology <stack_cores> <slices> <slice_cpus>
#
# Chooses whole physical cores on ONE NUMA node:
#   - the LAST <stack_cores> physical cores (BOTH SMT threads) for the host
#     stack (gateway, sandlot, benchmark client);
#   - the <slices> VM slices immediately before them. A slice owns COMPLETE
#     physical cores: <slice_cpus> logical CPUs are rounded up to whole
#     sibling groups (2 logical CPUs = one whole core on an SMT host), so a
#     microVM never spans two physical cores. This is what keeps a VM's
#     vCPU/vhost/virtiofs threads on one core and avoids cross-core
#     scheduling jitter.
# <slice_cpus>=1 is the logical-core mapping (one thread per VM, one VM per
# core); <slice_cpus>=2 is the default (one whole core per VM).
# Buying the high CPU numbers keeps the stack off the low CPUs where the NIC
# IRQs normally live.  Sets globals:
#   PIN_PREF_NODE      preferred NUMA node id
#   PIN_ONLINE_SPEC    all online CPUs (kernel cpulist)
#   PIN_STACK_CPUS     stack CPU list (all threads of the reserved cores)
#   PIN_SLICE_SPECS    semicolon list "cpus:node;cpus:node;..."
# Returns non-zero (with a message) when the topology cannot host the plan.
tc_pin_topology() {
    local stack_cores="${1:-8}" slices="${2:-3}" slice_cpus="${3:-2}" out
    out="$(python3 - "$stack_cores" "$slices" "$slice_cpus" <<'PY'
import sys, math

stack_n, slices_n, per_slice = (max(1, int(x)) for x in sys.argv[1:4])

def expand(spec):
    out = set()
    for part in spec.replace(" ", "").split(","):
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            out.update(range(int(a), int(b) + 1))
        else:
            out.add(int(part))
    return out

def compress(cpus):
    cpus = sorted(cpus)
    if not cpus:
        return ""
    runs, start, prev = [], cpus[0], cpus[0]
    for c in cpus[1:]:
        if c == prev + 1:
            prev = c
        else:
            runs.append((start, prev)); start = prev = c
    runs.append((start, prev))
    return ",".join(str(a) if a == b else "%d-%d" % (a, b) for a, b in runs)

def rd(path):
    try:
        return open(path).read().strip()
    except OSError:
        return ""

online = expand(rd("/sys/devices/system/cpu/online"))
if not online:
    print("pin: cannot read /sys/devices/system/cpu/online", file=sys.stderr)
    sys.exit(2)
nodes = sorted(int(n) for n in expand(rd("/sys/devices/system/node/online"))) or [0]
node_of = {}
for n in nodes:
    for c in expand(rd("/sys/devices/system/node/node%d/cpulist" % n)) & online:
        node_of[c] = n
for c in sorted(online):
    node_of.setdefault(c, nodes[0])

# Physical cores as complete sibling groups. Both threads stay together.
cores, seen = [], set()
for c in sorted(online):
    grp = tuple(sorted(expand(rd("/sys/devices/system/cpu/cpu%d/topology/thread_siblings_list" % c)) & online)) or (c,)
    if grp in seen:
        continue
    seen.add(grp)
    cores.append({"cpus": grp, "node": node_of[c], "min": min(grp)})

by_node = {}
for c in cores:
    by_node.setdefault(c["node"], []).append(c)
pref = sorted(by_node, key=lambda n: (-len(by_node[n]), n))[0]
node_cores = sorted(by_node[pref], key=lambda c: c["min"])

if per_slice == 1:
    # Logical-core mapping: one thread per VM, one VM per physical core.
    cores_per_slice = 1
else:
    # Whole-core mapping: round up to complete sibling groups.
    threads = len(node_cores[0]["cpus"])
    cores_per_slice = max(1, math.ceil(per_slice / threads))

need = stack_n + slices_n * cores_per_slice
if len(node_cores) < need:
    print("pin: node %d has %d cores but the plan needs %d (stack=%d + %d slices x %d core(s))"
          % (pref, len(node_cores), need, stack_n, slices_n, cores_per_slice), file=sys.stderr)
    sys.exit(2)

stack = node_cores[-stack_n:]
vm_cores = node_cores[len(node_cores) - stack_n - slices_n * cores_per_slice:len(node_cores) - stack_n]
slices = []
for i in range(slices_n):
    grp = vm_cores[i * cores_per_slice:(i + 1) * cores_per_slice]
    if per_slice == 1:
        cpus = [c["min"] for c in grp]
    else:
        cpus = [x for c in grp for x in c["cpus"]]
    slices.append("%s:%d" % (compress(cpus), pref))

print("PIN_PREF_NODE=%d" % pref)
print("PIN_ONLINE_SPEC=%s" % compress(online))
print("PIN_STACK_CPUS=%s" % compress([x for c in stack for x in c["cpus"]]))
print("PIN_SLICE_SPECS='%s'" % ";".join(slices))
PY
)" || return 1
    eval "$out"
}

# tc_pin_reexec_if_needed <script path> [args...]
#
# Re-executes the benchmark under taskset(1) so every child (gateway, sandlot
# and the benchmark client) inherits the stack cores.  The VMM shim widens its
# own affinity again before numactl (libnuma validates --physcpubind against
# the caller's CURRENT mask, so a child that inherited only the stack cores
# would reject the VM slice as out of range).
tc_pin_reexec_if_needed() {
    local script="$1"; shift
    [[ "${SANDSWAP_PIN_REEXEC:-0}" == "1" ]] && return 0
    [[ "${PIN_MODE:-0}" == "1" ]] || return 0
    tc_pin_topology "${PIN_STACK_CORES:-8}" "${PIN_SLICES:-3}" "${PIN_SLICE_CPUS:-2}" || return 1
    export PIN_STACK_CPUS PIN_SLICE_SPECS PIN_PREF_NODE PIN_ONLINE_SPEC
    log_info "pinning host stack to CPUs $PIN_STACK_CPUS; VM slices: $PIN_SLICE_SPECS"
    exec taskset -c "$PIN_STACK_CPUS" env SANDSWAP_PIN_REEXEC=1 bash "$script" "$@"
}

# tc_pin_setup <deploy_dir> <real_vmm> <pool_size>
#
# Generates the per-VM numactl shim and points TC_VMM_BINARY at it.  Must run
# after tc_deploy_artifacts (the real VMM is in DEPLOY_DIR) and before
# tc_start_sandlot / tc_gen_sandlot_config.  Idempotent.
tc_pin_setup() {
    local deploy="$1" real="$2" pool="${3:-3}"
    [[ "${PIN_MODE:-0}" == "1" ]] || return 0
    if [[ -z "${PIN_SLICE_SPECS:-}" ]]; then
        tc_pin_topology "${PIN_STACK_CORES:-8}" "${PIN_SLICES:-$pool}" "${PIN_SLICE_CPUS:-2}" || return 1
    fi
    local dir="$deploy/pinned" map numactl_bin
    numactl_bin="$(command -v numactl)" || {
        printf 'pin: numactl not found — install it or set PIN_MODE=0\n' >&2
        return 1
    }
    [[ -x "$real" ]] || { printf 'pin: real VMM not executable: %s\n' "$real" >&2; return 1; }
    install -d -m 0755 "$dir" || return 1
    cp -f "$real" "$dir/sandvmm-real" || return 1
    chmod 0755 "$dir/sandvmm-real"
    map="$dir/slice-map"
    : > "$map"
    local spec
    for spec in ${PIN_SLICE_SPECS//;/ }; do
        printf '%s %s\n' "${spec%%:*}" "${spec##*:}" >> "$map"
    done
    chmod 0644 "$map"
    local wrapper="$dir/sandvmm"
    cat > "$wrapper" <<EOF
#!/bin/bash
# Generated by e2e/pin.sh — per-VM CPU slice + NUMA memory binding shim.
set -euo pipefail
# Widen this process's affinity before numactl: the sandlot is pinned to the
# stack cores, and libnuma rejects --physcpubind entries outside the current
# allowed mask.  The process is single-tenant; widening is transient.
max=\$(( \$(getconf _NPROCESSORS_CONF) - 1 ))
taskset -p -c "0-\$max" \$\$ >/dev/null 2>&1 || true
api=''
prev=''
for a in "\$@"; do
    case "\$a" in
        --api-socket=*) api="\${a#--api-socket=}"; break ;;
    esac
    if [[ "\$prev" == "--api-socket" ]]; then api="\$a"; break; fi
    prev="\$a"
done
if [[ -z "\$api" ]]; then
    echo "sandvmm-pin: no --api-socket in argv; refusing to run unpinned" >&2
    exit 70
fi
vmid="\${api%/*}"; vmid="\${vmid##*/}"
if [[ ! "\$vmid" =~ -([0-9]+)\$ ]]; then
    echo "sandvmm-pin: VM id '\$vmid' carries no creation sequence; refusing to run unpinned" >&2
    exit 70
fi
seq="\${BASH_REMATCH[1]}"
mapfile -t lines < "$map"
n="\${#lines[@]}"
if (( n < 1 )); then
    echo "sandvmm-pin: empty slice map $map" >&2
    exit 70
fi
read -r cpus node <<< "\${lines[\$((seq % n))]}"
exec "$numactl_bin" --physcpubind="\$cpus" --membind="\$node" "$dir/sandvmm-real" "\$@"
EOF
    chmod 0755 "$wrapper" || return 1
    export TC_VMM_BINARY="$wrapper"
    if [[ -n "${SANDSWAP_VMM_UID:-}" ]] && command -v setpriv >/dev/null 2>&1; then
        setpriv --reuid="$SANDSWAP_VMM_UID" --regid="${SANDSWAP_VMM_GID:-$SANDSWAP_VMM_UID}" \
            --clear-groups test -x "$wrapper" \
            || { printf 'pin: sandvmm identity (%s) cannot execute %s\n' "$SANDSWAP_VMM_UID" "$wrapper" >&2; return 1; }
        setpriv --reuid="$SANDSWAP_VMM_UID" --regid="${SANDSWAP_VMM_GID:-$SANDSWAP_VMM_UID}" \
            --clear-groups test -r "$map" \
            || { printf 'pin: sandvmm identity (%s) cannot read %s\n' "$SANDSWAP_VMM_UID" "$map" >&2; return 1; }
    fi
    log_pass "bare-metal pinning: stack CPUs ${PIN_STACK_CPUS:-?}, VM slices ${PIN_SLICE_SPECS} (VMM shim: $wrapper)"
}

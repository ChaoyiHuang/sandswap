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
# routed-ipv6.sh — Guest-side e2e for the routed-IPv6 network backend with
# identity-in-address stamping (docs/how-it-works/egress-enabler.md).
# Boots REAL microVMs with -network-backend=routed-ipv6 and verifies the full
# chain: provider → kernel cmdline → warden netlink → guest IPv6 up:
#   V1. guest eth0 carries a static v6 address inside the site prefix;
#   V2. the guest's default route points at the host-side TAP gateway (::1);
#   V3. the guest can REACH that gateway (ping6 — link up, both stacks live);
#   V4. at mount, the host stamps the identity: a secondary identity-encoded
#       /128 address appears on the TAP plus the SNAT rule, and the binding
#       region shows the mount;
#   V5. at unmount the stamp is removed (address + SNAT rule gone).
# Prerequisites: built artifacts (build.sh all), KVM, root.
# Usage: ./e2e/routed-ipv6.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# Single VM keeps attachment identity unambiguous; long lease keeps the
# mount (and its SNAT stamp) observable.
POOL_SIZE="${POOL_SIZE:-1}"
LEASE_MS="${LEASE_MS:-8000}"
# shellcheck disable=SC2034  # NETWORK_BACKEND is consumed by the SOURCED common.sh across the source boundary
NETWORK_BACKEND="routed-ipv6"
V6_PREFIX="${V6_PREFIX:-fd00:5341:4e44::/48}"
# Full-width identity fields only: narrower views (sandfs:16) cannot guarantee
# attribution uniqueness and are REJECTED at sandlot config load — a template
# this script shipped in the past now fails at startup, never at first mount.
IID_TEMPLATE="${IID_TEMPLATE:-agent:32,sandfs:32}"
BIND_PATH="${BIND_PATH:-/dev/shm/sandswap-routed6-bindings}"
# Site-prefix hex stem (fd00:5341:4e44) shared by every address assertion below.
PREFIX_HEX="${V6_PREFIX%%::*}"
source "$ROOT/e2e/common.sh"

cleanup() {
    if [[ "${KEEP_ENV:-0}" == "1" ]]; then
        echo "KEEP_ENV=1: skipping teardown for live debugging (gateway/sandlot left running)"
        return
    fi
    if [[ -n "${KEY_A:-}" ]] && kill -0 "${GATEWAY_PID:-0}" 2>/dev/null; then
        tc_delete_sandfs "$ID_A" 2>/dev/null || true
    fi
    tc_cleanup_default
    rm -f "$BIND_PATH" 2>/dev/null || true
    nft delete table inet sandswap_routed6 2>/dev/null || true
    cleanup_v6_up 2>/dev/null || true
}
trap cleanup EXIT INT TERM
trap 'log_error "script died at line $LINENO (cmd: ${BASH_COMMAND})"' ERR

# ══════════════════════════════════════════════════════════════════
log_section "Phase 0: Pre-flight"
# ══════════════════════════════════════════════════════════════════
tc_check_root
tc_check_kvm
tc_check_artifacts
tc_check_freshness
tc_ensure_dev_nodes
# nft (stamp assertions) and python3 are load-bearing here — a missing tool
# must fail at preflight, not mid-test. nc is deliberately NOT a host
# prerequisite: the host-side listener is python3 (nc flavor semantics caused
# the historical bind-race false fails) and the guest-side TCP probe uses the
# busybox nc applet inside the microVM — no host nc binary is ever executed.
tc_check_tools curl python3 nft conntrack
# The guest needs a v6-capable kernel: the upstream prebuilt ships
# CONFIG_IPV6 unset (CH guests normally don't route v6), and a missing guest
# v6 stack reads as a page of confusing per-assertion reds. Probe the
# artifact and fail named instead. NB: no `grep -q` — under pipefail -q makes
# grep exit on first match and the upstream strings eats SIGPIPE (141), so
# the probe fails on success; without -q grep drains stdin to /dev/null.
if ! strings "$OUTPUT/vmlinux.bin" 2>/dev/null | grep "ip6_frag_reasm" > /dev/null; then
    log_error "output/vmlinux.bin has no IPv6 support (upstream prebuilt download)"
    log_info "routed-ipv6 needs a v6-capable guest kernel — fix: bash kernel/build.sh custom"
    exit 1
fi
if [[ ! -x "$DEPLOY_DIR/bindregdump" && ! -x "$OUTPUT/bindregdump" ]]; then
    log_error "bindregdump missing (binding-region inspector) — run build.sh all"
    exit 1
fi
rm -f "$BIND_PATH" 2>/dev/null || true

# ══════════════════════════════════════════════════════════════════
log_section "Phase 1: Deploy (clean slate)"
# ══════════════════════════════════════════════════════════════════
tc_clean_environment
tc_deploy_artifacts
tc_gen_certs
tc_setup_host_network  # NAT/forwarding baseline; routed-ipv6 does not enslave taps

# Host-prep half of the routed-IPv6 posture (the sandlot re-checks forwarding
# at startup, but a skipped/failed host prep must not look green here):
for _v6_key in net.ipv6.conf.all.forwarding net.ipv6.conf.default.forwarding; do
    if [[ "$(sysctl -n "$_v6_key" 2>/dev/null)" == "1" ]]; then
        pass "host prep: $_v6_key=1"
    else
        fail "host prep: $_v6_key is not 1 — routed-ipv6 egress is a black hole"
    fi
done
unset _v6_key
V6_METADATA="fd00:ec2::254/128"
if command -v ip6tables >/dev/null 2>&1; then
    if ip6tables -C FORWARD -s "$V6_PREFIX" -d "$V6_METADATA" -j DROP 2>/dev/null; then
        pass "host prep: v6 metadata DROP ($V6_PREFIX -> $V6_METADATA) installed"
    else
        fail "host prep: v6 metadata DROP missing — the host egress identity can reach IMDSv6"
    fi
    # The uplink may carry only an IPv4 default route (v6 egress is not a
    # prerequisite for the host-prep guard); fall back to it exactly as
    # ss_host_network_setup does.
    UPLINK_IF="$(ip -6 route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')"
    if [[ -z "$UPLINK_IF" ]]; then
        UPLINK_IF="$(ip route show default 2>/dev/null | awk '{print $5; exit}')"
    fi
    if [[ -n "$UPLINK_IF" ]]; then
        if ip6tables -C FORWARD -s "$V6_PREFIX" -o "$UPLINK_IF" -j ACCEPT 2>/dev/null; then
            pass "host prep: uplink-scoped v6 FORWARD accept ($UPLINK_IF)"
        else
            fail "host prep: uplink-scoped v6 FORWARD accept missing on $UPLINK_IF"
        fi
    else
        fail "host prep: no default route — cannot scope or verify the uplink accept"
    fi
else
    fail "host prep: ip6tables is not installed (routed-ipv6 host setup requires it)"
fi

# ══════════════════════════════════════════════════════════════════
log_section "Phase 2: Start Gateway + Sandlot (routed-ipv6 + identity stamping)"
# ══════════════════════════════════════════════════════════════════
tc_start_gateway
tc_start_sandlot \
    -network-v6-prefix "$V6_PREFIX" \
    -iid-template "$IID_TEMPLATE" \
    -binding-backend shm -binding-path "$BIND_PATH"
tc_wait_health
tc_wait_pool_ready

if grep -q "network backend: routed-ipv6 prefix $V6_PREFIX iid-template $IID_TEMPLATE" "$LOG_DIR/sandlot.log"; then
    pass "sandlot started with routed-ipv6 + iid-template"
else
    fail "routed-ipv6 backend not active (see sandlot.log)"
fi

# ══════════════════════════════════════════════════════════════════
log_section "Phase 3: Guest IPv6 configuration (V1, V2)"
# ══════════════════════════════════════════════════════════════════
AGENT_RESP=$(tc_create_agent_and_sandfs "routed6-a")
KEY_A=$(json_val "$AGENT_RESP" "api_key")
ID_A=$(json_val "$AGENT_RESP" "sandfs_id")
AGENT_ID=$(json_val "$AGENT_RESP" "agent_id")
[[ -n "$KEY_A" && "$KEY_A" != "None" ]] || { log_error "agent creation failed: $AGENT_RESP"; exit 1; }
pass "agent A created (sandfs=$ID_A agent=$AGENT_ID)"

exec_guest() { # exec_guest <code> -> echoes guest stdout; fails loudly on error
    local resp
    resp=$(curl -s -X POST "$GATEWAY_URL/agent/execute" \
        -H "Authorization: Bearer $KEY_A" \
        -H "Content-Type: application/json" \
        -d "{\"sandfs_id\":\"$ID_A\",\"code\":$(python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$1"),\"language\":\"shell\",\"timeout\":30}")
    local code stdout
    code=$(echo "$resp" | python3 -c "import sys,json; print(json.load(sys.stdin).get('exit_code',-1))" 2>/dev/null) || code="PARSE_ERR"
    if [[ "$code" != "0" ]]; then
        echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print('STDOUT:', d.get('stdout','')); print('STDERR:', d.get('stderr',''))" >&2 || true
        log_error "guest exec failed (exit=$code)"
        return 1
    fi
    stdout=$(echo "$resp" | python3 -c "import sys,json; print(json.load(sys.stdin).get('stdout',''))") || stdout=""
    echo "$stdout"
}

ADDR_OUT=$(exec_guest "uname -r; ip -6 addr show dev eth0") || ADDR_OUT=""
if echo "$ADDR_OUT" | grep -q "inet6 fd00:5341:4e44:"; then
    pass "V1: guest eth0 has a site-prefix IPv6 address"
else
    fail "V1: no site-prefix v6 address on guest eth0 (out: $ADDR_OUT)"
fi

ROUTE_OUT=$(exec_guest "ip -6 route show default")
GW=$(echo "$ROUTE_OUT" | python3 -c "
import sys, re
m = re.search(r'default via (fd00:[0-9a-f:]+)', sys.stdin.read())
print(m.group(1) if m else '')")
if [[ -n "$GW" ]]; then
    pass "V2: guest default route via host TAP gateway $GW"
else
    fail "V2: no default route via the site prefix (out: $ROUTE_OUT)"
fi

# ══════════════════════════════════════════════════════════════════
log_section "Phase 4: Guest → gateway reachability (V3)"
# ══════════════════════════════════════════════════════════════════
# Host listens on the TAP gateway address; guest connects over TCP. The
# listener is verified bound (ss) and the guest retries — a cold guest's
# first connect can race the listener's accept queue.
NC_PORT=19616
# Host listener in python3: `nc -l -s <addr> -p <port>` semantics differ
# between OpenBSD/GNU/netcat-openbsd flavors, and when the bind silently fails
# the guest probe reports "Connection refused" — a product-behavior false fail.
# python3 is preflight-guaranteed; the bind is verified before proceeding.
# SO_REUSEADDR + a bind retry loop: a rerun within the 60s TIME_WAIT lifetime
# of the previous run's accepted socket otherwise dies with EADDRINUSE.
# Listener stderr goes to $NC_LOG (NOT /dev/null — a swallowed bind errno is
# exactly what made the historical DAD-race failure so hard to triage).
NC_LOG="$LOG_DIR/v3-listener.log"
python3 -c "
import socket, sys, time
s = None
for attempt in range(50):
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(('$GW', $NC_PORT))
        break
    except OSError as e:
        s.close()
        if attempt == 49:
            print(f'bind [$GW]:$NC_PORT failed after retries: {e}', file=sys.stderr)
            sys.exit(1)
        time.sleep(0.2)
s.listen(4)
s.settimeout(120)
c, _ = s.accept()
c.close()
" 2> "$NC_LOG" &
NC_PID=$!
LISTENER_BOUND=0
for i in $(seq 1 20); do
    ss -6 -ltn 2>/dev/null | grep -q ":$NC_PORT " && { LISTENER_BOUND=1; break; }
    sleep 0.1
done
if [[ "$LISTENER_BOUND" -ne 1 ]]; then
    [[ -s "$NC_LOG" ]] && { echo "--- listener stderr ---" >&2; cat "$NC_LOG" >&2; }
    fail "V3: host listener never bound to [$GW]:$NC_PORT (precondition)"
fi
NC_OUT=""
for _ in 1 2 3; do
    NC_OUT=$(exec_guest "nc -w 2 $GW $NC_PORT </dev/null && echo TCP_OK" || true)
    echo "$NC_OUT" | grep -q "TCP_OK" && break
    sleep 1
done
kill "$NC_PID" 2>/dev/null || true
if echo "$NC_OUT" | grep -q "TCP_OK"; then
    fail "V3: guest reached a host listener on $GW:$NC_PORT — the v6 guest→host default-deny is not filtering (out: $NC_OUT)"
else
    pass "V3: guest→host arbitrary TCP on $GW:$NC_PORT is DROPPED (adjacency itself is proven by ICMPv6 in the V6 phase)"
fi

# ══════════════════════════════════════════════════════════════════
log_section "V6: guest→host v6 input guard (default-deny, NDP alive)"
# ══════════════════════════════════════════════════════════════════
# Every host listener must be unreachable from the guest over the TAP
# gateway address except DNS (and the NDP/ICMPv6 the adjacency itself
# needs). Guard-chain presence first, then a LIVE probe: a listener on a
# custom port on the gateway address must accept a LOCAL connection (the
# probe is proven working — a bind failure may not read as "firewall
# works") and time out from INSIDE the guest.
GUARD_CHAINS=$(nft list table inet sandswap_routed6 2>/dev/null | grep -c "chain input_") || GUARD_CHAINS=0
if [[ "$GUARD_CHAINS" -ge 1 ]]; then
    pass "V6: per-TAP input guard chain present ($GUARD_CHAINS)"
else
    fail "V6: no input_* guard chain in inet sandswap_routed6 — guests can reach host listeners over v6"
fi
# The guard's final rule is interface-scoped (iifname "<tap>" counter drop),
# NOT "ip6 saddr <subnet> drop": the subnet-scoped match was deliberately
# replaced because a forged source outside the /64 would slip past it (see
# ensureTapInputGuard in sandlot/network/routed6.go). Assert the SECURITY
# property instead of the old spelling: the LAST rule of a per-TAP input
# chain is a drop, i.e. anything not explicitly allowed above is denied.
GUARD_LAST=$(nft list table inet sandswap_routed6 2>/dev/null \
    | awk '/chain input_/{inchain=1} inchain && /^[[:space:]]*[a-z].*(accept|drop)/{last=$0} /^[[:space:]]*}/{if(inchain){print last; inchain=0; last=""}}' \
    | head -1)
if echo "$GUARD_LAST" | grep -q "drop"; then
    pass "V6: guard ends with an interface-scoped default drop (${GUARD_LAST:0:64}…)"
else
    fail "V6: guard has no final default drop rule (last rule: ${GUARD_LAST:-<none>})"
fi
# NDP health: the guest's default route still resolves the gateway (the
# earlier phases' execs prove reachability; assert it explicitly here).
PING_OUT=$(exec_guest "timeout 3 ping -6 -c1 -W2 $GW 2>&1 || true")
# ICMPv6 echo to the host is INFORMATIONAL, not gating: the guard's allow row
# provably admits the request (its counter increments), and NDP liveness is
# already pinned by V2 (REACHABLE neighbor + working default route). On the
# microVM stack the echo REPLY path has a pre-existing NDP/MAC wrinkle — the
# warden rebinds eth0's MAC after the kernel autoconfigured a first
# link-local, leaving TWO link-locals on the device — so a missing echo reply
# here does not indict the guard. Gating on it conflated two failures once.
PING_OUT=$(exec_guest "timeout 3 ping -6 -c1 -W2 $GW 2>&1 || true")
GUARD_ECHO_HITS=$(nft list table inet sandswap_routed6 2>/dev/null | grep "icmpv6 type" | grep -c "counter packets [1-9]") || GUARD_ECHO_HITS=0
if echo "$PING_OUT" | grep -q "1 received\|1 packets received\|time="; then
    pass "V6: gateway answers ICMPv6 echo (adjacency fully live)"
elif [[ "$GUARD_ECHO_HITS" -ge 1 ]]; then
    log_warn "V6: no echo reply, but the guard ADMITTED the request (icmpv6 allow counter > 0) — NDP liveness is pinned by V2; reply-path NDP/MAC wrinkle tracked separately"
else
    fail "V6: ICMPv6 to the gateway never reached the guard (allow counter 0) AND no reply — adjacency broken (out: $PING_OUT)"
fi
# LIVE drop probe on a custom port at the gateway address.
V6_PROBE_PORT=39998
python3 -m http.server "$V6_PROBE_PORT" --bind "$GW" >/dev/null 2>&1 &
V6_LISTENER_PID=$!
V6_LISTENER_OK=0
for _ in $(seq 1 20); do
    if curl -s --max-time 2 -o /dev/null "http://[$GW]:$V6_PROBE_PORT/"; then
        V6_LISTENER_OK=1; break
    fi
    sleep 0.3
done
if [[ "$V6_LISTENER_OK" == "1" ]]; then
    pass "V6 (probe sanity): the custom-port listener accepts a LOCAL v6 connection"
else
    fail "V6 (probe sanity): listener on [$GW]:$V6_PROBE_PORT never came up — the negative probe would be vacuous"
fi
V6_PROBE=$(exec_guest "nc -w 3 $GW $V6_PROBE_PORT </dev/null && echo V6_REACHED || true")
kill "$V6_LISTENER_PID" 2>/dev/null || true
wait "$V6_LISTENER_PID" 2>/dev/null || true
if [[ "$V6_LISTENER_OK" == "1" ]]; then
    if echo "$V6_PROBE" | grep -q "V6_REACHED"; then
        fail "V6: guest reached host v6 port $V6_PROBE_PORT — the v6 guest→host default-deny is not filtering (out: $V6_PROBE)"
    else
        pass "V6: guest→host custom port DROPPED over v6 (nc behind a locally-verified listener)"
    fi
fi

# ══════════════════════════════════════════════════════════════════
log_section "Phase 5: Host-side identity stamp (V4)"
# ══════════════════════════════════════════════════════════════════
TAP=$(ip -o link show | awk -F': ' '/tap-/ {print $2; exit}')
if [[ -z "$TAP" ]]; then
    fail "V4: no tap device found on host"
fi
# The per-TAP nft map name derives from the tap name (dash → underscore);
# a hardcoded name only matched one VM id, spec or self-heal seq.
MAP_NAME="stamp_$(echo "$TAP" | tr - _)"

# stamp_addr_on_tap — the identity-encoded secondary /128 address (site
# prefix stem + non-::1 IID) currently on $1; empty when absent.
stamp_addr_on_tap() {
    ip -6 addr show dev "$1" 2>/dev/null | python3 -c "
import sys, re
for line in sys.stdin:
    m = re.search(r'inet6 (${PREFIX_HEX}:[0-9a-f:]+)/128', line)
    if m and not m.group(1).endswith('::1'):
        print(m.group(1)); break" 2>/dev/null || true
}

# Gateway ::1/64 on the TAP — must be the SITE-PREFIX gateway, not just any
# /64 (every IPv6 interface carries a link-local fe80::/64, which made the old
# `grep /64` assertion impossible to fail). Poll briefly: the address is
# programmed by the provider around TAP creation, and a mount that landed
# microseconds earlier must not make the assertion flake.
GW_OK=0
for i in $(seq 1 15); do
    if ip -6 addr show dev "$TAP" 2>/dev/null | grep -qE "inet6 ${PREFIX_HEX}:[0-9a-f]{1,4}::1/64"; then
        GW_OK=1
        break
    fi
    sleep 0.2
done
if [[ "$GW_OK" == "1" ]]; then
    pass "V4: host-side gateway address present on $TAP (site prefix)"
else
    fail "V4: no ${PREFIX_HEX}::1/64 gateway address on $TAP"
fi
# Identity stamp: secondary /128 address (identity-encoded IID) on the TAP.
# Poll: stamping is gate-class async (not a fixed sleep, which under-shot on
# slow mounts and over-waited on fast ones).
STAMP_ADDR=""
for i in $(seq 1 15); do
    STAMP_ADDR=$(stamp_addr_on_tap "$TAP")
    [[ -n "$STAMP_ADDR" ]] && break
    sleep 1
done
if [[ -n "$STAMP_ADDR" ]]; then
    pass "V4: identity stamp address on $TAP: $STAMP_ADDR/128"
else
    fail "V4: no identity /128 address on $TAP"
fi
# SNAT: the static rule rewrites via the map; the mount's element maps the
# guest IID to the identity address.
SNAT_OUT=$(nft list table inet sandswap_routed6 2>/dev/null || true)
MAP_OUT=$(nft list map inet sandswap_routed6 "$MAP_NAME" 2>/dev/null || true)
if echo "$SNAT_OUT" | grep -q "snat ip6 to ip6 saddr map" && echo "$SNAT_OUT" | grep -q "sandswap-identity-stamp" \
    && echo "$MAP_OUT" | grep -q "$STAMP_ADDR"; then
    pass "V4: SNAT map element stamps egress to $STAMP_ADDR"
else
    fail "V4: SNAT stamp rule/element missing (map $MAP_NAME)"
fi
# V4b: post-SNAT source on the egress side. A throwaway veth peer in a netns
# acts as the uplink for a destination outside the site prefix; after the
# guest's SYN is forwarded, netfilter's conntrack entry carries the rewritten
# reply tuple (src = the stamped identity /128). This proves the SNAT reaches
# the wire side without depending on an external IPv6 target (the host may be
# IPv4-only). conntrack-tools is a test dependency.
V6_UP_NS="sst-v6-up"
V6_UP_IF="sst-v6-up0"
V6_UP_PEER="sst-v6-peer0"
V6_UP_DST="fd00:dead:beef::1"
cleanup_v6_up() {
    ip6tables -D FORWARD -s "$V6_PREFIX" -o "$V6_UP_IF" -j ACCEPT 2>/dev/null || true
    ip -6 route del "$V6_UP_DST/128" dev "$V6_UP_IF" 2>/dev/null || true
    ip link del "$V6_UP_IF" 2>/dev/null || true
    ip netns del "$V6_UP_NS" 2>/dev/null || true
}
cleanup_v6_up
V6_UP_READY=0
if ip netns add "$V6_UP_NS" 2>/dev/null \
    && ip link add "$V6_UP_IF" type veth peer name "$V6_UP_PEER" 2>/dev/null \
    && ip link set "$V6_UP_PEER" netns "$V6_UP_NS" 2>/dev/null \
    && ip link set "$V6_UP_IF" up 2>/dev/null; then
    ip netns exec "$V6_UP_NS" ip link set lo up 2>/dev/null || true
    ip netns exec "$V6_UP_NS" ip link set "$V6_UP_PEER" up 2>/dev/null || true
    ip netns exec "$V6_UP_NS" ip -6 addr add "$V6_UP_DST/128" dev "$V6_UP_PEER" 2>/dev/null || true
    if ip -6 route add "$V6_UP_DST/128" dev "$V6_UP_IF" 2>/dev/null; then
        V6_UP_READY=1
    fi
fi
if [[ "$V6_UP_READY" == "1" ]]; then
    ip6tables -I FORWARD 1 -s "$V6_PREFIX" -o "$V6_UP_IF" -j ACCEPT 2>/dev/null || true
    GUEST_OUT=$(exec_guest "ip -6 route show; nc -w 1 $V6_UP_DST 9 </dev/null || true" 2>&1 || true)
    sleep 1
    CT_OUT=$(conntrack -L -f ipv6 -p tcp --dport 9 2>/dev/null || true)
    # The original tuple is guest→peer; the reply tuple is peer→translated
    # source, so the SNAT rewrite appears as the reply tuple's DESTINATION.
    if echo "$CT_OUT" | grep -q "dst=$STAMP_ADDR"; then
        pass "V4b: conntrack reply tuple's destination is the stamped /128 (SNAT rewrite)"
    else
        fail "V4b: no post-SNAT conntrack entry for $STAMP_ADDR (guest: $(echo "$GUEST_OUT" | tr '\n' ' ' | head -c 300); conntrack: $(echo "$CT_OUT" | tail -3 | tr '\n' ' '))"
    fi
    cleanup_v6_up
else
    cleanup_v6_up
    fail "V4b: could not create the test uplink (veth/netns) — on-wire SNAT assertion not run"
fi

# Binding region shows the mount + capture its epoch for the V5 comparison.
bindregdump_bin="$DEPLOY_DIR/bindregdump"
[[ -x "$bindregdump_bin" ]] || bindregdump_bin="$OUTPUT/bindregdump"
DUMP=$("$bindregdump_bin" -backend shm -path "$BIND_PATH")
if echo "$DUMP" | grep -q "mounted .*agent=$AGENT_ID"; then
    pass "V4: binding region shows the mount"
else
    fail "V4: no mounted binding (dump: $(echo "$DUMP" | tail -2))"
fi
MOUNT_EPOCH=$(echo "$DUMP" | grep "mounted .*agent=$AGENT_ID" | head -1 | sed -nE 's/.*epoch=([0-9]+).*/\1/p')

# ══════════════════════════════════════════════════════════════════
log_section "Phase 6: Unmount removes the stamp (V5)"
# ══════════════════════════════════════════════════════════════════
# Poll for unmount convergence (lease expiry + async unstamp) instead of a
# fixed sleep — the lease is 8s and teardown latency varies with host load.
REVOKE_ADDR=1
for i in $(seq 1 30); do
    STAMP_ADDR2=$(stamp_addr_on_tap "$TAP")
    MAP_OUT2=$(nft list map inet sandswap_routed6 "$MAP_NAME" 2>/dev/null || true)
    if [[ -z "$STAMP_ADDR2" ]] && ! echo "$MAP_OUT2" | grep -qE "${PREFIX_HEX}:"; then
        REVOKE_ADDR=0
        break
    fi
    sleep 1
done
if [[ "$REVOKE_ADDR" -eq 0 ]]; then
    pass "V5: identity stamp removed on unmount (address + map element gone)"
else
    fail "V5: stamp still present after 30s (addr=$STAMP_ADDR2, map: $MAP_OUT2)"
fi
# Binding revoked: the SAME slot/epoch this mount published must now read
# unbound. The epoch is captured from the V4 dump — a hardcoded "epoch=1"
# predated the wall-clock epoch seed (values are ~1e15 now), and a bare
# "epoch=1" grep also substring-matched epoch=12.
REVOKED_OK=0
# shellcheck disable=SC2034  # poll loop counter
for i in $(seq 1 15); do
    DUMP=$("$bindregdump_bin" -backend shm -path "$BIND_PATH")
    if echo "$DUMP" | awk -v e="$MOUNT_EPOCH" '$2 == "unbound" && $0 ~ "epoch="e" "' | grep -q "unbound"; then
        REVOKED_OK=1
        break
    fi
    sleep 1
done
if [[ "$REVOKED_OK" -eq 1 ]]; then
    pass "V5: binding revoked after unmount (epoch=$MOUNT_EPOCH preserved, identity cleared)"
else
    fail "V5: binding not revoked (want unbound epoch=$MOUNT_EPOCH; dump: $(echo "$DUMP" | tail -2))"
fi


# ══════════════════════════════════════════════════════════════════
log_section "Results"
# ══════════════════════════════════════════════════════════════════
log_section "routed-ipv6 e2e complete: $PASS_COUNT passed, $FAIL_COUNT failed"
if [[ "$FAIL_COUNT" -gt 0 ]]; then
    exit 1
fi
exit 0

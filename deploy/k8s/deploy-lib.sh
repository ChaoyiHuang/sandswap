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
# deploy-lib.sh — shared implementation for the Sandswap k3s deploy scripts.
# deploy-k8s-embedded.sh and deploy-k8s-boxout.sh are thin entry points that
# differ ONLY in their mode context (which manifest, which images, which UID
# vsockguard pins, which logs the VM-reuse check greps). Everything else —
# host prep, image build/import, cert generation, manifest apply, readiness
# waits, CoreDNS wiring, reachability smoke, the verification drill
# (agent/SandFS creation, affinity self-test, eino run, failover, analysis),
# cleanup — lives here ONCE.
# (Before this library existed the same ~900 lines were copied into both
# scripts and every fix had to be made twice — the ones made once were the
# recurring "new bug each run" source.)
# An entry script sets the mode context below, sources e2e/common.sh + this
# file, and calls k8s_deploy_main "$@".
# Two run modes:
#   keep (default)   deploy through the reachability smoke, then HAND OVER the
#                    running deployment (verify later with verify-k8s.sh;
#                    remove with k8s-cleanup.sh). A FAILED deploy tears down.
#   --verify         the built-in drill: run the verification phases
#                    (agents + affinity + eino [+ --failover]) and tear the
#                    deployment down afterwards — deploy-as-self-test.
# ── Mode context (set by the entry script) ──────────────────────────
#   MODE_NAME          embedded | boxout            (display + build-images --mode)
#   MODE_DESC          one-line description for the preflight banner
#   VSOCKGUARD_UID     0 | 65536                    (UID the init container pins)
#   SANDLOT_MANIFEST   absolute path to the DaemonSet manifest
#   SANDLOT_DS         DaemonSet name (sandlot | sandlot-boxout)
#   SANDLOT_SELECTOR   label selector (app=sandlot | app=sandlot-boxout)
#   IMAGE_LIST         images the mode needs in k3s (for --skip-images verify)
#   NEEDS_GID_INJECTION  true → sed-inject /dev/kvm + /dev/vhost-vsock GIDs
#                        into the manifest (k8s cannot template
#                        supplementalGroups; embedded runs the devices as
#                        supplemental groups, boxout uses a privileged sidecar)
#   CHOWN_RUN_DIR_UID  "" | 65536                   (chown /run/sandswap for the
#                        unprivileged sandbox UID in boxout mode)
#   VERIFY_SANDBOX_UID true → verify the DaemonSet's sandlot container runs
#                        as SANDBOX_UID after rollout
#   VM_REUSE_LOGS      kubectl logs selector args for the VM-reuse check
#   VM_REUSE_PATTERN   grep pattern counting VM creations in those logs
#   EINO_BIN_NAME      binary/log name for the eino phase
# ── Side-effect ledger ──────────────────────────────────────────────
# Every mutation this script makes outside the k8s API is recorded with
# se_record(). Entries marked EPHEMERAL are reversed by se_replay_ephemeral —
# called by preflight (to recover state from a crashed previous run) and by
# cleanup. New host-mutating code MUST record + add a reversal case here;
# that is what stops "deploy wrote it, cleanup forgot it" residue bugs.
# KEEP entries persist across deploys (host sysctls, bridges, artifacts) and
# are recorded for observability only.
# ════════════════════════════════════════════════════════════════════
# Side-effect ledger
# ════════════════════════════════════════════════════════════════════

# SECURITY: the ledger is root-run tooling input, so it lives in a ROOT-ONLY
# directory (a world-writable /tmp ledger let a local user plant entries that
# root later replayed). Every detail is validated against a per-type whitelist
# before use, never interpolated into sed, and rm/kill operate on type-checked
# paths/pids only.
SE_LEDGER_DIR="${SE_LEDGER_DIR:-${DEPLOY_DIR:-/var/lib/sandswap}/deploy-ledger}"
SE_LEDGER="${SE_LEDGER:-$SE_LEDGER_DIR/sideeffects.log}"

# se_ledger_ready — root-owned 0700 directory + root-owned, non-group/world-
# writable ledger file (symlinks refused).
se_ledger_ready() {
    install -d -m 0700 -o root -g root "$SE_LEDGER_DIR" 2>/dev/null || return 1
    [[ -L "$SE_LEDGER_DIR" ]] && return 1
    [[ "$(stat -c '%U' "$SE_LEDGER_DIR" 2>/dev/null)" == "root" ]] || return 1
    [[ "$(stat -c '%a' "$SE_LEDGER_DIR" 2>/dev/null)" == "700" ]] || return 1
    if [[ -e "$SE_LEDGER" || -L "$SE_LEDGER" ]]; then
        [[ -L "$SE_LEDGER" ]] && return 1
        [[ "$(stat -c '%U' "$SE_LEDGER" 2>/dev/null)" == "root" ]] || return 1
        local mode
        mode="$(stat -c '%a' "$SE_LEDGER" 2>/dev/null || echo '')"
        [[ "$mode" =~ ^[0-7]{3,4}$ ]] || return 1
        (( (8#$mode & 8#022) == 0 )) || return 1
    fi
    return 0
}

# se_valid_detail <type> <detail> — the detail whitelist (see the bare-metal
# lib's twin; the types and shapes must stay in lockstep).
se_valid_detail() {
    local type="$1" detail="$2"
    case "$type" in
        sysctl-file|chown|chmod|hostdir|devnode|bridge|seccomp|coredns-zone|bpf-pin)
            return 0
            ;;
    esac
    [[ -n "$detail" ]] || return 1
    case "$type" in
        hosts-pin)
            # A hostname/label literal (never a regex or sed program).
            [[ "$detail" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]]
            ;;
        port-forward|tmpfile)
            [[ "$detail" =~ ^/[A-Za-z0-9._/-]+$ ]] && [[ "$detail" != "/" ]] && [[ "$detail" != *..* ]] \
                && [[ "$detail" == /*/* ]]
            ;;
        *)
            return 1
            ;;
    esac
}

se_record() { # se_record <KEEP|EPHEMERAL> <type> <detail...>
    # NB: only args 3+ are the detail — "$*" here would splice the scope and
    # type into the detail column, and every detail-USING reversal below
    # (hosts-pin / port-forward / tmpfile) would silently no-op.
    local scope="$1" type="$2"
    shift 2
    local detail="$*"
    if ! se_valid_detail "$type" "$detail"; then
        log_warn "ledger: refused a '$type' entry whose detail is not whitelisted: ${detail:0:120}"
        return 0
    fi
    if ! se_ledger_ready; then
        log_warn "ledger: refusing to record into $SE_LEDGER (needs a root-owned 0700 directory and a root-owned ledger file)"
        return 0
    fi
    printf '%s\t%s\t%s\t%s\n' "$(date +%s)" "$scope" "$type" "$detail" >> "$SE_LEDGER"
}

# _se_hosts_filter <literal> — delete every /etc/hosts line CONTAINING the
# literal (grep -F; no regex, no sed program).
_se_hosts_filter() {
    local lit="$1" tmp
    tmp="$(mktemp "${TMPDIR:-/tmp}/.se-hosts.XXXXXX")" || return 1
    grep -vF -- "$lit" /etc/hosts > "$tmp" 2>/dev/null || true
    cat "$tmp" > /etc/hosts
    rm -f "$tmp"
}

# Reverse EPHEMERAL ledger entries. Two classes:
#   host-run aids       hosts-pin, port-forward, tmpfile — belong to the RUN
#                       (host-side access helpers); always safe to revert.
#   deployment-attached seccomp, coredns-zone, bpf-pin — belong to the
#                       DEPLOYMENT (the live cluster needs them: kubelet
#                       profile, in-cluster per-sandfs routing, vsockguard);
#                       reverting them breaks a kept deployment. Reverted
#                       only on teardown; k8s-cleanup.sh holds canonical
#                       copies of those reversals (it cannot source this
#                       file without dragging in e2e/common.sh) — keep in
#                       sync.
# Optional $1 "aids" reverts only the host-run aids (keep-mode exit).
# Idempotent — each reversal checks for the residue's presence first, so
# replaying a clean ledger is a no-op.
se_replay_ephemeral() {
    local aids_only="${1:-}"
    if [[ ! -e "$SE_LEDGER" && ! -L "$SE_LEDGER" ]]; then
        return 0
    fi
    if ! se_ledger_ready; then
        log_warn "ledger: $SE_LEDGER failed the owner/mode/symlink check — NOT replaying it (moved aside)"
        mv -f "$SE_LEDGER" "$SE_LEDGER.rejected" 2>/dev/null || rm -f -- "$SE_LEDGER"
        return 0
    fi
    local reversed=0
    # shellcheck disable=SC2094
    while IFS=$'\t' read -r _ scope type detail; do
        [[ "$scope" == "EPHEMERAL" ]] || continue
        if ! se_valid_detail "$type" "$detail"; then
            log_warn "ledger: skipping a '$type' entry with a non-whitelisted detail"
            continue
        fi
        # Deployment-attached classes are skipped by the aids-only replay
        # (keep-mode exit): the live cluster still needs them.
        if [[ -n "$aids_only" ]]; then
            case "$type" in
                seccomp|coredns-zone|bpf-pin) continue ;;
            esac
        fi
        case "$type" in
            hosts-pin)
                if grep -qF -- "$detail" /etc/hosts 2>/dev/null; then
                    _se_hosts_filter "$detail" || true
                    reversed=$((reversed + 1))
                fi
                ;;
            port-forward)
                if [[ -f "$detail" && ! -L "$detail" ]]; then
                    local _pid
                    _pid="$(cat "$detail" 2>/dev/null || true)"
                    if [[ "$_pid" =~ ^[0-9]+$ ]] && (( _pid > 1 && _pid != $$ )); then
                        kill "$_pid" 2>/dev/null || true
                    fi
                    rm -f -- "$detail"
                    reversed=$((reversed + 1))
                fi
                ;;
            tmpfile)
                if [[ -L "$detail" ]]; then
                    rm -f -- "$detail"
                    reversed=$((reversed + 1))
                elif [[ -f "$detail" || -d "$detail" ]]; then
                    rm -rf -- "$detail"
                    reversed=$((reversed + 1))
                fi
                ;;
            seccomp)
                if [[ -d /var/lib/kubelet/seccomp/sandswap ]]; then
                    rm -rf /var/lib/kubelet/seccomp/sandswap
                    reversed=$((reversed + 1))
                fi
                ;;
            coredns-zone)
                if $KUBECTL get configmap coredns -n kube-system >/dev/null 2>&1 \
                   && $KUBECTL get configmap coredns -n kube-system -o jsonpath='{.data.Corefile}' 2>/dev/null | grep -q 'sandfs\.sandswap\.local'; then
                    local tmp
                    tmp=$(mktemp)
                    $KUBECTL get configmap coredns -n kube-system -o jsonpath='{.data.Corefile}' 2>/dev/null \
                        | python3 -c "
import re, sys
sys.stdout.write(re.sub(r'\nsandfs\.sandswap\.local:53 \{[^}]*\}\n?', '\n', sys.stdin.read()))" > "$tmp"
                    local patch
                    patch=$(python3 -c "import json; print(json.dumps({'data': {'Corefile': open('$tmp').read()}}))")
                    if $KUBECTL patch configmap coredns -n kube-system --type merge -p "$patch" >/dev/null 2>&1; then
                        $KUBECTL rollout restart deployment/coredns -n kube-system >/dev/null 2>&1 || true
                        reversed=$((reversed + 1))
                    fi
                    rm -f "$tmp"
                fi
                ;;
            bpf-pin)
                if [[ -e /sys/fs/bpf/vsockguard/link ]]; then
                    if [[ -x "$OUTPUT/vsockguardctl" ]]; then
                        "$OUTPUT/vsockguardctl" detach /sys/fs/bpf/vsockguard/link \
                            /sys/fs/bpf/vsockguard/prog /sys/fs/bpf/vsockguard/allowed_uid 2>/dev/null || true
                    fi
                    rm -f /sys/fs/bpf/vsockguard/link /sys/fs/bpf/vsockguard/prog /sys/fs/bpf/vsockguard/allowed_uid 2>/dev/null || true
                    rmdir /sys/fs/bpf/vsockguard 2>/dev/null || true
                    reversed=$((reversed + 1))
                fi
                ;;
            # KEEP types — recorded for observability, nothing to reverse.
            sysctl-file|chown|hostdir|devnode|bridge) ;;
            *) log_warn "ledger: unknown side-effect type '$type' (detail: $detail)" ;;
        esac
    done < "$SE_LEDGER"
    if [[ "$reversed" -gt 0 ]]; then
        log_pass "Side-effect ledger: reversed $reversed leftover mutation(s)"
    fi
    mv "$SE_LEDGER" "$SE_LEDGER.done" 2>/dev/null || rm -f -- "$SE_LEDGER"
}

# ════════════════════════════════════════════════════════════════════
# Shared constants + flags
# ════════════════════════════════════════════════════════════════════

NAMESPACE="sandswap"
DEPLOY_DIR="${DEPLOY_DIR:-/var/lib/sandswap}"
K3S_KUBECONFIG="/etc/rancher/k3s/k3s.yaml"
GW_FQDN="gateway-0.gateway-exec.sandswap.svc.cluster.local"
AGENT_COUNT=4
POOL_SIZE=2
EINO_TEST_BUDGET_SECS="${EINO_TEST_BUDGET_SECS:-600}"
KUBECTL="kubectl"
PF_PIDS=()
SKIP_BUILD=false
SKIP_IMAGES=false
SKIP_DEPS=false
TEST_FAILOVER=false
VERIFY_MODE=false
# Default keep mode: a successful deploy leaves the cluster running (cleanup
# reverts only the run's host-side access aids — port-forward, /etc/hosts
# pin). The --verify drill flips this to full teardown-on-exit.
KEEP_ON_EXIT=true

k8s_parse_flags() {
    for arg in "$@"; do
        case "$arg" in
            --skip-build)   SKIP_BUILD=true ;;
            --skip-images)  SKIP_IMAGES=true ;;
            --skip-deps)    SKIP_DEPS=true ;;
            --failover)     TEST_FAILOVER=true ;;
            --verify)       VERIFY_MODE=true; KEEP_ON_EXIT=false ;;
            --keep)         log_info "--keep is the default now (a successful deploy stays up) — no-op" ;;
            *) log_warn "unknown flag: $arg" ;;
        esac
    done
}

# ════════════════════════════════════════════════════════════════════
# Cleanup (wired to EXIT/INT/TERM by k8s_deploy_main)
# ════════════════════════════════════════════════════════════════════

cleanup() {
    log_step "Cleaning up..."

    # Kill port-forward watchdogs. Each watchdog traps TERM/INT/EXIT and kills
    # its own kubectl port-forward child, so this single kill tears down both.
    for pid in "${PF_PIDS[@]:-}"; do
        kill "$pid" 2>/dev/null || true
    done
    # Wait briefly for the watchdogs to tear down their children, then sweep
    # any strays (orphaned kubectl port-forwards, watchdogs that already exited
    # before this trap ran) by port AND by command pattern.
    sleep 1
    for port in 3000 3100; do
        tc_kill_port "$port"
    done
    pkill -f "kubectl.*port-forward.*$NAMESPACE" 2>/dev/null || true
    rm -f /tmp/sandswap-pf-*.pid /tmp/sandswap-pf-*.sh

    # Delete K8s resources (unless a keep-mode run succeeded)
    if [[ "$KEEP_ON_EXIT" != "true" ]]; then
        $KUBECTL delete namespace "$NAMESPACE" --ignore-not-found=true --wait=false 2>/dev/null || true
        # Namespace gone → the coredns sandfs zone forwards to a dead ClusterIP
        # and the /etc/hosts pin points at a dead pod IP. Strip both.
        bash "$ROOT/deploy/k8s/k8s-cleanup.sh" >/dev/null 2>&1 || true
    else
        log_info "Namespace $NAMESPACE preserved (keep mode — verify-k8s.sh / k8s-cleanup.sh next)"
    fi

    # Reverse this run's ephemeral side effects from the ledger (second sweep —
    # k8s-cleanup.sh above handles the same classes in the teardown branch; the
    # ledger also covers anything added later whose k8s-cleanup counterpart
    # does not exist yet). Keep mode reverts only the host-run aids — the
    # deployment-attached effects (seccomp profile, coredns zone, vsockguard
    # pin) stay with the live cluster until k8s-cleanup.sh.
    if [[ "$KEEP_ON_EXIT" == "true" ]]; then
        se_replay_ephemeral aids
    else
        se_replay_ephemeral
    fi

    # Note: do NOT delete the host network bridge (br-sandswap) here.
    # It is a persistent host resource that must survive across deploys.
    # Deleting it causes sandlot crash-loops on re-deploy.

    log_pass "Cleanup done"
}

# EXIT-trap wrapper: keep mode + SUCCESS → KEEP_ON_EXIT stays true (namespace
# kept, only the run's host-side access aids reverted). Everything else — any
# failure, interrupt, or the --verify drill (KEEP_ON_EXIT already false) —
# tears the deployment fully down.
k8s_exit_trap() {
    local rc=$?
    [[ $rc -eq 0 ]] || KEEP_ON_EXIT=false
    cleanup
}

# ════════════════════════════════════════════════════════════════════
# Preflight — read-only checks, report ALL failures at once
# ════════════════════════════════════════════════════════════════════
# Hard-fails only on conditions nothing downstream can fix (missing KVM,
# wrong vsockguard pin, occupied ports, no disk/memory). Environmental facts
# that later phases auto-handle (no BPF LSM → vsockguard auto-skip; missing
# docker/k3s → installed/built later) are reported as info/warn.

PF_ERRORS=()

pf_fail() { PF_ERRORS+=("$1"); log_error "$1"; }
pf_warn() { log_warn "$1"; }
pf_info() { log_info "$1"; }

k8s_preflight() {
    log_section "Preflight (all checks reported before any mutation)"

    # Recover side effects left by a crashed previous run BEFORE checking.
    # (The k8s-cleanup.sh run above already handles the same classes; this
    # consumes the ledger so the checks below see the true post-cleanup state.)
    se_replay_ephemeral

    echo "  Host:     $(uname -n)"
    echo "  Arch:     $(uname -m)"
    echo "  Kernel:   $(uname -r)"
    echo "  Mode:     $MODE_DESC"
    echo "  Agents:   $AGENT_COUNT"
    echo "  Pool:     $POOL_SIZE VMs per node"

    # Root — everything below (BPF pins, kubelet dirs, chown) needs it.
    if [[ "$(id -u)" -ne 0 ]]; then
        pf_fail "must run as root (sudo)"
    fi

    # LLM key: hard requirement for the verification drill (the 4-agent eino
    # run is part of what "deployed and verified" means there); keep-mode
    # deploys only warn — the key matters when --verify / verify-k8s.sh runs.
    if [[ -z "${DEEPSEEK_API_KEY:-}" ]] && [[ -z "${OPENAI_API_KEY:-}" ]] && [[ -z "${GOOGLE_API_KEY:-}" ]]; then
        if [[ "$VERIFY_MODE" == "true" ]]; then
            pf_fail "no LLM API key set (DEEPSEEK_API_KEY / OPENAI_API_KEY / GOOGLE_API_KEY) — required by the --verify drill"
        else
            pf_warn "no LLM API key set — needed only for verification (--verify / verify-k8s.sh eino run)"
        fi
    fi
    if [[ -n "${DEEPSEEK_API_KEY:-}" ]]; then
        LLM_BACKEND="deepseek"
    elif [[ -n "${OPENAI_API_KEY:-}" ]]; then
        LLM_BACKEND="openai"
    elif [[ -n "${GOOGLE_API_KEY:-}" ]]; then
        LLM_BACKEND="gemini"
    else
        LLM_BACKEND="none"
    fi
    if [[ "$LLM_BACKEND" == "none" ]]; then
        log_info "LLM backend: none (set a key for the eino verification)"
    else
        log_pass "LLM backend: $LLM_BACKEND"
    fi

    # KVM + vsock devices.
    if [[ -e /dev/kvm ]] && [[ -r /dev/kvm ]]; then
        log_pass "/dev/kvm present (GID $(stat -c '%g' /dev/kvm))"
    else
        pf_fail "/dev/kvm not found or not readable — KVM unavailable"
    fi
    if [[ -e /dev/vhost-vsock ]]; then
        log_pass "/dev/vhost-vsock present (GID $(stat -c '%g' /dev/vhost-vsock))"
    else
        pf_fail "/dev/vhost-vsock not found — vsock unavailable"
    fi

    # BPF LSM state. Absent → the deploy auto-sets SANDSWAP_SKIP_VSOCKGUARD=1
    # (vsock isolation degraded — acceptable only on test/dev kernels).
    if grep -qE '(^|,)bpf(,|$)' /sys/kernel/security/lsm 2>/dev/null; then
        log_pass "BPF LSM active — vsockguard will enforce (allowed UID=$VSOCKGUARD_UID)"
    else
        pf_warn "BPF LSM not active — vsockguard will be SKIPPED (test/dev only)"
        pf_warn "  production requires: bash deploy/k8s/k8s-host-setup.sh --mode $MODE_NAME && reboot"
    fi

read_allowed_uid() { # → allowed UID string, or "" when unreadable
    # allowed_uid is a PINNED BPF MAP, not a regular file: `cat` prints the
    # kernel's debug banner ("# WARNING!! ...") followed by "key: value" lines.
    # Take the first parseable entry's value.
    local out
    out="$(cat /sys/fs/bpf/vsockguard/allowed_uid 2>/dev/null || true)"
    echo "$out" | grep -E '^[0-9]+:' | head -1 | sed 's/^[0-9]*:[[:space:]]*//'
}
    # vsockguard pin residue. The pin is HOST-global and mode-specific: an
    # embedded deploy pins allowed_uid=0, a boxout deploy pins 65536. A stale
    # pin for the OTHER UID makes the init container hard-fail mid-deploy —
    # catch it here, name the fix.
    if [[ -e /sys/fs/bpf/vsockguard/allowed_uid ]]; then
        pinned="$(read_allowed_uid)"
        if [[ -n "$pinned" && "$pinned" == "$VSOCKGUARD_UID" ]]; then
            log_pass "vsockguard pin already matches this mode (allowed_uid=$pinned)"
        else
            pf_fail "vsockguard pinned for UID $pinned but $MODE_NAME mode needs UID $VSOCKGUARD_UID"
            pf_fail "  fix: bash deploy/k8s/k8s-cleanup.sh (detaches), then re-deploy"
        fi
    else
        log_pass "no stale vsockguard pin"
    fi

    # Container runtime + cluster access. Both are auto-provisioned later, so
    # absence here is informational unless the corresponding skip-flag says
    # the auto-provisioning will not run.
    if [[ "$SKIP_IMAGES" == "true" ]]; then
        local missing="" img
        for img in "${IMAGE_LIST[@]}"; do
            # IMAGE_LIST entries are bare names ("sandswap/gateway") while ctr
            # normalizes to fully-qualified refs ("docker.io/sandswap/gateway:latest")
            # — anchor on the slash/line-start before and the colon after the
            # name, or a present image is always reported missing.
            [[ -z "$(k3s ctr -n k8s.io images ls -q 2>/dev/null | grep -E "(^|/)$img:")" ]] && missing="$missing $img"
        done
        if [[ -n "$missing" ]]; then
            pf_fail "--skip-images but image(s) not in k3s:$missing"
        else
            log_pass "all mode images present in k3s${missing:-}"
        fi
    else
        if command -v docker &>/dev/null; then
            log_pass "docker available for image builds"
        else
            pf_info "docker not found — install-deps/build phase will attempt to provide it"
        fi
    fi
    if ! command -v k3s &>/dev/null && ! command -v kubectl &>/dev/null; then
        pf_info "k3s/kubectl not found — will be installed by this script"
    fi

    # Cluster API + a schedulable node (kubectl works against k3s.yaml).
    if [[ -f "$K3S_KUBECONFIG" ]]; then
        export KUBECONFIG="$K3S_KUBECONFIG"
    fi
    if command -v kubectl &>/dev/null || command -v k3s &>/dev/null; then
        local notready
        notready=$(kubectl get nodes --no-headers 2>/dev/null | grep -vc ' Ready' || true)
        if kubectl get nodes &>/dev/null; then
            local total
            # || true: a transient kubectl failure right after the successful
            # probe above must read as "0 nodes" (pf_fail below), not as a
            # silent set -o pipefail death.
            total=0
            total=$(kubectl get nodes --no-headers 2>/dev/null | wc -l) || true
            if [[ "${total:-0}" -gt 0 ]] && [[ "${notready:-0}" -eq 0 ]]; then
                log_pass "K8s API reachable, $total node(s) Ready"
            else
                pf_fail "K8s API reachable but $notready/$total node(s) not Ready"
            fi
        else
            pf_info "K8s API not reachable yet (k3s may still be starting/being installed)"
        fi
    fi

    # Host ports the harness needs (human port-forward :3100; :3000 swept by
    # cleanup). A baremetal leftover holding them fails Phase 6 confusingly.
    local port pids
    for port in 3000 3100; do
        pids=$(ss -tlnp 2>/dev/null | grep ":$port " | grep -oE 'pid=[0-9]+' | grep -oE '[0-9]+' | sort -u || true)
        if [[ -n "$pids" ]]; then
            for pid in $pids; do
                pf_fail "host port $port held by PID $pid ($(ps -o comm= -p "$pid" 2>/dev/null || echo '?')) — not a sandswap process"
            done
        fi
    done

    # Orphan sandswap host processes (usually a baremetal run) — they hold
    # CIDs, /run/sandswap state and /dev/kvm; k8s-cleanup kills them, so any
    # survivor here means that sweep failed.
    local orphans
    orphans=$(pgrep -f "(^|/)(sandvmm|sandlot|gateway)( |$)" 2>/dev/null | while read -r opid; do
        [[ "$opid" != "$$" ]] && ps -o comm= -p "$opid" 2>/dev/null | grep -qE '^(sandvmm|sandlot|gateway)$' && echo "$opid"
    done || true)
    if [[ -n "$orphans" ]]; then
        pf_warn "orphan sandswap host processes: $(echo "$orphans" | tr '\n' ' ')"
        pf_warn "  k8s-cleanup.sh should have killed these — inspect before continuing"
    fi

    # Disk: ubuntu rootfs template (~150M) is copied to $DEPLOY_DIR and seeded
    # into every agent volume on the PVC; images add ~300M to docker + k3s.
    # df needs an existing path — cleanup removes $DEPLOY_DIR, so walk up to
    # the nearest existing ancestor (same filesystem).
    local avail_mb df_target="$DEPLOY_DIR"
    while [[ ! -e "$df_target" && "$df_target" != "/" ]]; do
        df_target="$(dirname "$df_target")"
    done
    avail_mb="$(ss_df_avail_mb "$df_target")"
    if [[ "${avail_mb:-0}" -lt 1500 ]]; then
        pf_fail "only ${avail_mb}MB free on $DEPLOY_DIR filesystem (need ≥1500MB)"
    elif [[ "${avail_mb:-0}" -lt 3000 ]]; then
        pf_warn "${avail_mb}MB free on $DEPLOY_DIR filesystem — tight for images + rootfs + volumes"
    else
        log_pass "disk: ${avail_mb}MB free on $DEPLOY_DIR filesystem"
    fi

    # Memory: build + pool (small:2 guests) + k3s control plane.
    local availmem
    availmem=$(awk '/MemAvailable/{print int($2/1024)}' /proc/meminfo 2>/dev/null || echo 0)
    if [[ "${availmem:-0}" -lt 1500 ]]; then
        pf_fail "only ${availmem}MB MemAvailable (need ≥1500MB for build + small pool)"
    elif [[ "${availmem:-0}" -lt 2500 ]]; then
        pf_warn "${availmem}MB MemAvailable — VM creation may fail under memory pressure"
    else
        log_pass "memory: ${availmem}MB MemAvailable"
    fi

    # Report everything at once — a fresh machine should not need five runs to
    # discover five unmet preconditions.
    if [[ "${#PF_ERRORS[@]}" -gt 0 ]]; then
        log_error "preflight: ${#PF_ERRORS[@]} blocking problem(s):"
        local e
        for e in "${PF_ERRORS[@]}"; do
            log_error "  - $e"
        done
        exit 1
    fi
    log_pass "Preflight passed (all blocking checks green)"
}

# ════════════════════════════════════════════════════════════════════
# Phase 0: build + tools
# ════════════════════════════════════════════════════════════════════

k8s_phase_build() {
    tc_check_kvm

    # Install build + deploy dependencies on a fresh machine (idempotent apt +
    # rustup). build.sh all hard-checks for these and would otherwise fail with
    # a hint; auto-installing here makes the one-click path actually one-click.
    # Skip with --skip-deps (deps already present, offline, no sudo).
    if [[ "$SKIP_DEPS" == "false" ]]; then
        log_step "Checking/installing build + deploy dependencies..."
        bash "$ROOT/build/install-deps.sh"
        log_pass "Dependencies ready"
    else
        log_info "Skipping dependency install (--skip-deps)"
    fi

    if [[ "$SKIP_BUILD" == "false" ]]; then
        # The matrix runner establishes freshness ONCE in its preflight and
        # exports SANDSWAP_ROUND_FRESH=1 (see bm_build_artifacts) — never
        # re-check, and never auto-rebuild, the shared set from inside a row.
        # Outside a round, freshness-gate instead of building unconditionally:
        # a green check means the build would be a no-op — only build when
        # something is stale.
        if [[ "${SANDSWAP_ROUND_FRESH:-0}" == "1" ]]; then
            log_pass "Round baseline fresh (matrix preflight) — skipping per-leg build check"
        elif bash "$ROOT/build/build.sh" check >/dev/null 2>&1; then
            log_pass "Artifacts fresh (build.sh check green) — skipping rebuild"
        else
        log_step "Building all artifacts..."
        # Keep the FULL output on disk — `| tail -5` alone destroys the failure
        # evidence (a failing warden unit suite once showed only "3 failed"
        # with no test names, turning a flake investigation into guesswork).
        mkdir -p "${LOG_DIR:-/tmp/sandswap-deploy-logs}"
        if ! bash "$ROOT/build/build.sh" all 2>&1 | tee "${LOG_DIR:-/tmp/sandswap-deploy-logs}/build-all.log" | tail -5; then
            echo "[error] build.sh all FAILED — full output: ${LOG_DIR:-/tmp/sandswap-deploy-logs}/build-all.log" >&2
            tail -60 "${LOG_DIR:-/tmp/sandswap-deploy-logs}/build-all.log" >&2
            exit 1
        fi
        log_pass "All artifacts built"
        fi
    else
        log_info "Skipping build (--skip-build)"
        # The reused kernel must be the PINNED build — the dev `download`
        # variant (v6.2) lacks IPv6 + the TIME_WAIT sweep and ships the
        # expanded attack surface the threat model assumes away.
        if ! ss_verify_kernel_artifact "$OUTPUT/vmlinux.bin" "$ROOT/kernel/build.sh"; then
            log_error "refusing --skip-build with a non-pinned kernel artifact under output/"
            exit 1
        fi
    fi

    tc_check_artifacts

    # Ubuntu rootfs — build automatically if missing
    ROOTFS_UBUNTU="${ROOTFS_UBUNTU:-$OUTPUT/rootfs-ubuntu}"
    if [[ ! -d "$ROOTFS_UBUNTU" ]] || [[ ! -d "$ROOTFS_UBUNTU/bin" ]]; then
        log_warn "Ubuntu rootfs template not found — building automatically..."
        bash "$ROOT/build/build-ubuntu-rootfs.sh"
        log_pass "Ubuntu rootfs template built"
    fi
    log_pass "Ubuntu rootfs template present: $ROOTFS_UBUNTU/"

    tc_check_tools curl python3 dig

    if [[ "$SKIP_IMAGES" == "false" ]]; then
        if ! command -v docker &>/dev/null; then
            log_error "docker not found — required for building container images"
            log_info "Install docker or use --skip-images (with pre-built images)"
            exit 1
        fi
        log_pass "docker available for image builds"
    fi

    # Install k3s if not present. The upstream installer fetches the binary
    # from github releases — a transient network blip must not fail the whole
    # deploy row. Bounded retry; the presence check after the loop is the
    # verdict (a half-finished install leaves no k3s on PATH).
    if ! command -v k3s &>/dev/null && ! command -v kubectl &>/dev/null; then
        log_step "Installing k3s..."
        local k3s_try
        for k3s_try in 1 2 3; do
            if curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC="--write-kubeconfig-mode=644" sh -; then
                break
            fi
            if (( k3s_try < 3 )); then
                log_warn "k3s install attempt $k3s_try failed — retrying in $((k3s_try * 5))s"
                sleep $((k3s_try * 5))
            fi
        done
        if ! command -v k3s &>/dev/null; then
            log_error "k3s not installed after 3 attempts (network unreachable?)"
            exit 1
        fi
        KUBECTL="k3s kubectl"
        log_pass "k3s installed"
    else
        if command -v k3s &>/dev/null; then
            KUBECTL="k3s kubectl"
            log_pass "k3s already installed"
            # The e2e/baremetal prelude stops container runtimes
            # (ss_container_runtime_clean): an INSTALLED k3s may still be
            # stopped. The deployer needs the API — start it instead of
            # waiting 60s for a server that will never come.
            if ! systemctl is-active --quiet k3s 2>/dev/null; then
                log_step "k3s installed but stopped — starting k3s.service"
                systemctl start k3s 2>/dev/null || true
            fi
        else
            log_pass "kubectl already available"
        fi
    fi

    log_step "Waiting for K8s API server..."
    for i in $(seq 1 30); do
        if $KUBECTL get nodes &>/dev/null; then
            break
        fi
        sleep 2
    done
    if ! $KUBECTL get nodes &>/dev/null; then
        log_error "K8s API server not ready after 60s"
        exit 1
    fi
    log_pass "K8s API server ready"

    if [[ -f "$K3S_KUBECONFIG" ]]; then
        export KUBECONFIG="$K3S_KUBECONFIG"
    fi
}

# ════════════════════════════════════════════════════════════════════
# Phase 1: host preparation (recorded in the ledger)
# ════════════════════════════════════════════════════════════════════

k8s_phase_host_prep() {
    # Dev-host doctrine (same discipline as the e2e suites' tc_clean_environment):
    # every deploy run prepares its OWN pre-run environment — it never assumes
    # what a previous run, a previous topology, or a reboot left behind. Three
    # idempotent re-asserts, each closing a measured failure:
    #
    #   1. stale HOST-side sandswap services (a baremetal topology previously
    #      deployed on this host) — a running host sandlot holds the role-lock
    #      flock on /run/sandswap/sandlot.role, which the compute pod (hostPath
    #      /run/sandswap) needs; stale etcd/gateway units also hold ports;
    #   2. /run/sandswap leftovers (a baremetal run's state.json would make the
    #      pod's sandlot try to RE-ADOPT foreign VMs; instance dirs confuse the
    #      CID allocator) — cleaned, then recreated with the run's ownership;
    #   3. device ownership: the udev rule is correct but the vhost_vsock
    #      module routinely loads AFTER udev's coldplug, so /dev/vhost-vsock
    #      lands root-owned after a reboot and the sandlot identity-split guard
    #      fail-fasts ("owned by uid 0, want the sandvmm identity 987" —
    #      measured on this host). Explicit restore, same doctrine as
    #      tc_ensure_dev_nodes: never gamble on udev timing.
    log_step "Re-asserting host state (per-run env prep: stale units, /run/sandswap, device owners)..."
    local unit
    for unit in $(systemctl list-units --type=service --all --no-legend 2>/dev/null \
            | awk '$1 ~ /^sandswap-(sandlot|gateway|sandns|etcd)/ {print $1}'); do
        if systemctl is-active --quiet "$unit" 2>/dev/null || systemctl is-enabled --quiet "$unit" 2>/dev/null; then
            systemctl stop "$unit" 2>/dev/null || true
            systemctl disable "$unit" 2>/dev/null || true
            log_info "stopped/disabled leftover host service: $unit (belongs to a previous non-k8s topology)"
        fi
    done
    # reset-failed so a prior crash's unit state cannot confuse later checks.
    systemctl reset-failed 'sandswap-*' 2>/dev/null || true

    rm -rf /run/sandswap /run/sandswap-state
    log_info "cleaned /run/sandswap (previous topology's state must not leak into this run's pods)"

    if [[ -e /dev/vhost-vsock ]] || modprobe vhost_vsock 2>/dev/null; then
        if ! grep -qx vhost_vsock /etc/modules-load.d/sandswap.conf 2>/dev/null; then
            echo "vhost_vsock" >> /etc/modules-load.d/sandswap.conf 2>/dev/null || true
        fi
        udevadm trigger --action=add --name-match=vhost-vsock 2>/dev/null || true
        udevadm trigger --action=add --name-match=vsock 2>/dev/null || true
        sleep 1
        chown sandvmm:sandvmm /dev/vhost-vsock 2>/dev/null && chmod 0600 /dev/vhost-vsock
        chown sandlot:root /dev/vsock 2>/dev/null && chmod 0600 /dev/vsock
        log_pass "device owners re-asserted: $(stat -c '%n %U:%a' /dev/vhost-vsock /dev/vsock 2>/dev/null | tr '\n' ' ')"
    else
        log_warn "/dev/vhost-vsock absent and module unloadable — vsock pods will fail (no vhost_vsock on this kernel?)"
    fi

    # Invariant 8 on the PVC storage root: the local-path provisioner hands
    # pods a plain bind mount, which does NOT carry nosuid,nodev; the sandlot
    # then refuses to start on its own -volumes-dir. A self-bind + bind-remount
    # on the host root makes every pod's bind of a subtree inherit both flags
    # (per-mount flags are copied by bind mounts). Idempotent.
    local lp_root="${K3S_STORAGE_ROOT:-/var/lib/rancher/k3s/storage}"
    mkdir -p "$lp_root"
    local lp_opts
    lp_opts=$(findmnt -n -o OPTIONS "$lp_root" 2>/dev/null || true)
    if [[ "$lp_opts" == *nosuid* && "$lp_opts" == *nodev* ]]; then
        log_pass "PVC storage root hardened: $lp_root (nosuid,nodev)"
    elif mount --bind "$lp_root" "$lp_root" 2>/dev/null && mount -o remount,bind,nosuid,nodev "$lp_root" 2>/dev/null; then
        log_pass "PVC storage root hardened: $lp_root (self-bind nosuid,nodev)"
    else
        log_error "could not harden $lp_root with nosuid,nodev — sandlot pods refuse to start (invariant 8)"
        exit 1
    fi

    log_step "Deploying artifacts to $DEPLOY_DIR ..."
    tc_deploy_artifacts

    # Replace busybox rootfs with Ubuntu rootfs
    log_step "Deploying Ubuntu rootfs template (replacing default busybox)..."
    rm -rf "$DEPLOY_DIR/flat-templates/rootfs/v1"
    mkdir -p "$DEPLOY_DIR/flat-templates/rootfs/v1"
    cp -a "$ROOTFS_UBUNTU/." "$DEPLOY_DIR/flat-templates/rootfs/v1/"
    # Template contract: extraction assigns uid 1000 and the ubuntu tree keeps
    # group-only modes (/etc/shadow 0640) — normalize + verify through the
    # canonical tool so the prov identity can actually read every entry.
    if [[ -x "$OUTPUT/template-tool" ]]; then
        "$OUTPUT/template-tool" normalize "$DEPLOY_DIR/flat-templates" >/dev/null
        "$OUTPUT/template-tool" validate "$DEPLOY_DIR/flat-templates" \
            || { log_error "template fails offline validation after normalize"; exit 1; }
    fi
    if [[ ! -d "$DEPLOY_DIR/flat-templates/rootfs/v1/bin" ]]; then
        log_error "Ubuntu rootfs-template directory copy failed"
        exit 1
    fi
    log_pass "Ubuntu rootfs template deployed ($(du -sh "$DEPLOY_DIR/flat-templates/rootfs/v1" | cut -f1))"

    mkdir -p /run/sandswap /run/sandswap-state
    # Private per-VM state root: boxout (root) creates the 0700 instance dirs;
    # the sandlot never traverses it in boxout mode.
    chmod 711 /run/sandswap-state
    # Boxout's OWN socket directory: root-owned 0711 (traverse only), separate
    # from the sandlot-writable /run/sandswap. The sidecar binds
    # /run/sandswap-boxout/boxout.sock there and hands the socket to the
    # sandlot uid 0600; keeping it out of the shared runtime dir removes the
    # socket-replacement class entirely.
    mkdir -p /run/sandswap-boxout
    chown root:root /run/sandswap-boxout
    chmod 0711 /run/sandswap-boxout
    se_record KEEP hostdir /run/sandswap
    se_record KEEP hostdir /run/sandswap-state
    se_record KEEP hostdir /run/sandswap-boxout

    # Host-local file ownership.
    log_step "Setting ownership for host-local files..."
    # The flat-templates staging tree has NO in-cluster consumer anymore (the
    # storage split moved flat-template scanning into the prov pod reading the
    # templates PVC — this host tree is only the tar-pipe SOURCE seeded into
    # the PVC below, read by root). It stays root-owned; the ONLY hostPath
    # consumer of $DEPLOY_DIR is the kernel/initramfs pair:
    chmod a+r "$DEPLOY_DIR/vmlinux.bin" "$DEPLOY_DIR/initramfs.cpio.gz" 2>/dev/null || true
    # TCB directory ownership: the kernel/initramfs hostPath is mounted into
    # every sandlot pod, and the guest kernel is the TCB — the directory must
    # be root-owned 0755 so no pod-side identity can rename/replace it.
    chown root:root "$DEPLOY_DIR" 2>/dev/null || true
    chmod 0755 "$DEPLOY_DIR" 2>/dev/null || true
    # ...readable by the unprivileged boxout-mode sandlot (embedded runs as
    # root and does not care, but a+r costs nothing).
    log_pass "Host file ownership set"

    # /run/sandswap ownership: boxout mode's sandlot (UID 65536) writes
    # state.json and connects to boxout.sock there.
    if [[ -n "$CHOWN_RUN_DIR_UID" ]]; then
        chown "$CHOWN_RUN_DIR_UID:$CHOWN_RUN_DIR_UID" /run/sandswap 2>/dev/null || true
        # 0755: the owner (the reserved sandbox uid) can write; group/other may
        # only traverse. 0775 exposed write to the group (verify-host-security
        # FAILs it). Per-VM state now lives in /run/sandswap-state.
        chmod 755 /run/sandswap
        se_record KEEP chown /run/sandswap
        log_pass "/run/sandswap writable by UID $CHOWN_RUN_DIR_UID and root"
    else
        log_pass "/run/sandswap directory ready"
    fi

    # Auto-detect KVM device GIDs.
    KVM_GID=$(stat -c '%g' /dev/kvm)
    VHOST_VSOCK_GID=$(stat -c '%g' /dev/vhost-vsock)
    log_pass "KVM device GIDs: /dev/kvm=$KVM_GID, /dev/vhost-vsock=$VHOST_VSOCK_GID"

    # Build the DaemonSet manifest we will apply. k8s cannot template
    # supplementalGroups and the manifest must not be edited in place (the
    # placeholder pattern stops matching after the first injection), so all
    # injection goes into a temp copy. Recorded in the ledger as a tmpfile.
    SANDLOT_YAML_TMP=$(mktemp "${TMPDIR:-/tmp}/sandlot-manifest-XXXXXX.yaml")
    se_record EPHEMERAL tmpfile "$SANDLOT_YAML_TMP"
    if [[ "$NEEDS_GID_INJECTION" == "true" ]]; then
        # supplementalGroups grants device access without privileged mode or
        # udev rules (GIDs vary: Ubuntu server=104, cloud=108, GCP=992, RHEL=36).
        #
        # The placeholder value is literally 992 and the injection target is the
        # HOST's kvm gid — which on GCP images IS 992. There the sed is
        # legitimately a no-op, so testing "did the output change" (grep the
        # OUTPUT for "- 992") cannot tell a correct no-op from comment drift and
        # would false-fail every GCP deploy. Split it: placeholder EXISTENCE is
        # checked on the input, injected gids on the output.
        local kvm_ph="- 992  # /dev/kvm GID"
        local vsock_ph="- 992  # /dev/vhost-vsock GID"
        local vmm_uid_ph="value: \"987\"  # /dev/sandvmm UID placeholder"
        if ! grep -q -- "$kvm_ph" "$SANDLOT_MANIFEST" \
           || ! grep -q -- "$vsock_ph" "$SANDLOT_MANIFEST" \
           || ! grep -q -- "$vmm_uid_ph" "$SANDLOT_MANIFEST"; then
            log_error "DaemonSet GID/UID placeholder missing in $SANDLOT_MANIFEST (manifest drifted?) — aborting before a device-less sandlot is deployed"
            exit 1
        fi
        VMM_UID=$(id -u sandvmm 2>/dev/null) || {
            log_error "sandvmm account not resolvable — run deploy/k8s/k8s-host-setup.sh on this node (it adopts or creates the identity; this deploy injects the resolved uid/gid)"
            exit 1
        }
        sed "s|$kvm_ph|- $KVM_GID  # /dev/kvm GID|" "$SANDLOT_MANIFEST" \
            | sed "s|$vsock_ph|- $VHOST_VSOCK_GID  # /dev/vhost-vsock GID|" \
            | sed "s|$vmm_uid_ph|value: \"$VMM_UID\"  # /dev/sandvmm UID (host-resolved)|" \
            > "$SANDLOT_YAML_TMP"
        # Post-check: the output must carry the HOST gids (a sed that failed to
        # match leaves 992 behind when the host gid differs; when the host gid
        # IS 992 the input check above already proved the placeholder existed).
        if ! grep -q -- "- $KVM_GID  # /dev/kvm GID" "$SANDLOT_YAML_TMP" \
           || ! grep -q -- "- $VHOST_VSOCK_GID  # /dev/vhost-vsock GID" "$SANDLOT_YAML_TMP" \
           || ! grep -q -- "value: \"$VMM_UID\"  # /dev/sandvmm UID" "$SANDLOT_YAML_TMP"; then
            log_error "DaemonSet GID/UID injection failed — aborting before a device-less sandlot is deployed"
            exit 1
        fi
        log_pass "Injected supplementalGroups: /dev/kvm=$KVM_GID, /dev/vhost-vsock=$VHOST_VSOCK_GID; SANDSWAP_VMM_UID=$VMM_UID"
    else
        # Boxout mode: the privileged sidecar owns the devices; GIDs are
        # detected for logging only.
        cp "$SANDLOT_MANIFEST" "$SANDLOT_YAML_TMP"
    fi

    # Host kernel without the bpf LSM → vsockguard cannot enforce; auto-skip
    # the attach instead of hard-failing every pod (test/dev only).
    if ! grep -qE '(^|,)bpf(,|$)' /sys/kernel/security/lsm 2>/dev/null; then
        log_warn "BPF LSM not active in /sys/kernel/security/lsm — sandlot vsockguard will be SKIPPED"
        log_warn "  (test/dev kernels only; production requires: bash k8s-host-setup.sh && reboot)"
        sed -i 's/              value: "0"/              value: "1"  # vsockguard skip (no BPF LSM)/' "$SANDLOT_YAML_TMP"
    fi

    # /dev/net/tun must exist for `ip tuntap add` (TUNSETIFF ioctl).
    if [ ! -e /dev/net/tun ]; then
        mkdir -p /dev/net
        mknod /dev/net/tun c 10 200
        se_record KEEP devnode /dev/net/tun
        log_pass "Created /dev/net/tun (10,200)"
    fi
    # The MODE is pinned on every run, not only at creation: a node that ran
    # the bare-metal suite carries a 0660 root:<bare-metal-group> node, and
    # the in-pod sandvmm child (numeric pod uid/gid + its own supplementary
    # groups) then loses the DAC race at open(2) before the owner-match
    # TUNSETIFF can even matter — the pool dies at OpenTap EPERM on every
    # create. The VMM spawn carries ZERO capabilities, so it cannot widen the
    # node itself; instead the node grants exactly the group the VMM child
    # keeps (vmm_groups includes the host kvm gid, and setpriv REPLACES its
    # group list with exactly that set). 0666 would let every local user open
    # /dev/net/tun — docs/deployment/prerequisites.md forbids it.
    chown root:"$KVM_GID" /dev/net/tun
    chmod 0660 /dev/net/tun
    se_record KEEP chown /dev/net/tun
    se_record KEEP chmod /dev/net/tun

    # Remove stale udev rules from previous deploys (supplementalGroups or the
    # privileged sidecar replaces them).
    rm -f /etc/udev/rules.d/99-sandswap-kvm.rules /etc/udev/rules.d/99-sandswap-vhost-vsock.rules 2>/dev/null || true

    # Host security sysctls for vsockguard defense-in-depth (host layer — see
    # networkpolicy.yaml for why NetworkPolicy cannot cover hostNetwork pods).
    log_step "Setting host security sysctls..."
    # Persist max(current, floor) for both keys — writing the bare floor would
    # silently DOWNGRADE a stronger host (k8s-host-setup.sh pins
    # perf_event_paranoid=4 in 99-sandswap-perf.conf; "99-sandswap.conf" sorts
    # after it and would win at boot), while skipping the line entirely when
    # the running value is already >= floor loses the setting on reboot (the
    # runtime value may itself have come from the previous run's file).
    # Mirrors set_sysctl in k8s-host-setup.sh.
    PTRACE_NOW="$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null || echo 1)"
    [[ "$PTRACE_NOW" -lt 1 ]] && PTRACE_NOW=1
    PARANOID_NOW="$(cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null || echo 2)"
    [[ "$PARANOID_NOW" -lt 2 ]] && PARANOID_NOW=2
    SYSCTL_FILE="/etc/sysctl.d/99-sandswap.conf"
    {
        echo "# Sandswap host security sysctls"
        echo "# ptrace_scope >= 1: blocks cross-UID ptrace (vsockguard anti-sniff)"
        echo "kernel.yama.ptrace_scope = $PTRACE_NOW"
        echo "# perf_event_paranoid >= 2: blocks non-root eBPF kprobe tracing"
        echo "kernel.perf_event_paranoid = $PARANOID_NOW"
        echo "# ip_forward: microVM outbound NAT via host bridge"
        echo "net.ipv4.ip_forward = 1"
    } > "$SYSCTL_FILE"
    se_record KEEP sysctl-file "$SYSCTL_FILE"
    # Apply immediately (non-fatal if some fail in container env)
    sysctl -p "$SYSCTL_FILE" 2>/dev/null || true
    log_pass "Host security sysctls set ($SYSCTL_FILE)"

    # Host bridge for microVM outbound networking
    log_step "Setting up host network bridge..."
    if bash "$ROOT/deploy/setup-network.sh" 2>&1; then
        se_record KEEP bridge br-sandswap
        log_pass "Host network bridge ready"
    else
        # The script now refuses (non-zero) when nft is missing or the guest
        # FORWARD policy cannot be installed: continuing would run VMs whose
        # egress bypasses the metadata/terminal drops.
        log_error "Host network bridge setup FAILED — guest egress would be unpoliced; install nftables and re-run"
        exit 1
    fi

    # Host security check (best-effort — warns if invariants not met)
    log_step "Checking host security invariants..."
    if [[ -x "$ROOT/security/verify-host-security.sh" ]]; then
        if bash "$ROOT/security/verify-host-security.sh" >/dev/null 2>&1; then
            log_pass "Host security invariants verified"
        else
            log_warn "Host security invariants NOT met — vsockguard may not be active"
            log_warn "  Run: sudo bash deploy/k8s/k8s-host-setup.sh --mode $MODE_NAME (one-time per node)"
        fi
    else
        log_info "verify-host-security.sh not found — skipping host security check"
    fi

    log_pass "Host preparation complete"
}

# ════════════════════════════════════════════════════════════════════
# Phase 2: container images
# ════════════════════════════════════════════════════════════════════

k8s_phase_images() {
    if [[ "$SKIP_IMAGES" == "false" ]]; then
        # The e2e/baremetal prelude stops container runtimes
        # (ss_container_runtime_clean) and this deployer's exemption only
        # keeps a RUNNING docker — it does not start one. The image build
        # needs the daemon: bring it up instead of assuming it.
        if ! docker info >/dev/null 2>&1; then
            log_step "docker daemon down — starting docker.socket + docker.service"
            systemctl start docker.socket docker.service 2>/dev/null || true
            local _docker_tries=0
            while ! docker info >/dev/null 2>&1 && (( _docker_tries < 30 )); do
                sleep 1; _docker_tries=$((_docker_tries+1))
            done
            if ! docker info >/dev/null 2>&1; then
                log_error "docker daemon would not start — cannot build images"
                exit 1
            fi
        fi
        log_step "Building container images + importing to k3s ($MODE_NAME mode)..."
        bash "$ROOT/deploy/k8s/build-images.sh" --mode="$MODE_NAME" 2>&1 | tail -10
        log_pass "Container images built and imported"
    else
        log_info "Skipping image build (--skip-images)"
        # NOTE: do NOT use `grep -q` on the live pipe — under pipefail, grep -q
        # exits on the first match and closes the pipe, SIGPIPE-ing k3s ctr
        # mid-write so the pipeline fails spuriously.
        local missing="" img
        for img in "${IMAGE_LIST[@]}"; do
            # IMAGE_LIST entries are bare names ("sandswap/gateway") while ctr
            # normalizes to fully-qualified refs ("docker.io/sandswap/gateway:latest")
            # — anchor on the slash/line-start before and the colon after the
            # name, or a present image is always reported missing.
            [[ -z "$(k3s ctr -n k8s.io images ls -q 2>/dev/null | grep -E "(^|/)$img:")" ]] && missing="$missing $img"
        done
        if [[ -n "$missing" ]]; then
            log_error "image(s) not found in k3s:$missing — build first or import manually"
            exit 1
        fi
        log_pass "Container images already present in k3s"
    fi
}

# ════════════════════════════════════════════════════════════════════
# Phase 3+4: certificates + manifests
# ════════════════════════════════════════════════════════════════════

# k8s_nodes — one cluster node name per line. An explicit SANDSWAP_K8S_NODES
# wins (a deploy whose kubectl context is not the target cluster still mints
# the right pairs); else the live cluster.
k8s_nodes() {
    if [[ -n "${SANDSWAP_K8S_NODES:-}" ]]; then
        printf '%s' "$SANDSWAP_K8S_NODES" | tr ',\n' '  ' | tr ' ' '\n' | grep -v '^$'
        return 0
    fi
    $KUBECTL get nodes -o name 2>/dev/null | sed 's|^node/||'
}

# k8s_local_node — the cluster node this deploy is RUNNING on, or empty. A k8s
# node name need not equal the shell hostname (kubeadm defaults to the FQDN),
# so match the name first, then the addresses the node itself reports.
k8s_local_node() {
    local n cand addrs
    local -a cands=("$(hostname)" "$(hostname -f 2>/dev/null || true)")
    local ip
    for ip in $(hostname -I 2>/dev/null || true); do cands+=("$ip"); done
    while IFS= read -r n; do
        [[ -n "$n" ]] || continue
        for cand in "${cands[@]}"; do
            [[ -n "$cand" && "${n,,}" == "${cand,,}" ]] && { printf '%s\n' "$n"; return 0; }
        done
        addrs="$($KUBECTL get node "$n" -o jsonpath='{range .status.addresses[*]}{.address}{"\n"}{end}' 2>/dev/null || true)"
        for cand in "${cands[@]}"; do
            [[ -n "$cand" ]] && printf '%s\n' "$addrs" | grep -qxF -- "$cand" && { printf '%s\n' "$n"; return 0; }
        done
    done <<< "$(k8s_nodes)"
    return 0
}

k8s_phase_apply() {
    # NEVER rotate an existing PKI under a running cluster. The old
    # flow regenerated the entire CA on EVERY apply (executed: two runs, two
    # CA fingerprints) and applied it with no workload restart — a redeploy
    # over a kept cluster left mixed-generation mTLS material until every pod
    # happened to restart. Certificates are now generated ONCE (or on an
    # explicit SANDSWAP_FORCE_CERT_REGEN=1) and kept as-is afterwards, exactly
    # like the seed Secret.
    local regen=0
    if ! $KUBECTL -n "$NAMESPACE" get secret gateway-certs &>/dev/null; then
        regen=1
    elif [[ "${SANDSWAP_FORCE_CERT_REGEN:-0}" == "1" ]]; then
        regen=1
        log_step "SANDSWAP_FORCE_CERT_REGEN=1 — rotating the PKI (restart every workload afterwards)"
    fi
    if [[ "$regen" == "1" ]]; then
        log_step "Generating K8s TLS certificates..."
        # The generator mints ONE stream client pair per cluster node (CN =
        # node name — the gateway binds hello.node_id == CN by exact match).
        # Pin the node list here so the mint and the per-node checks below
        # agree: an explicit SANDSWAP_K8S_NODES wins, else the live cluster.
        if [[ -z "${SANDSWAP_K8S_NODES:-}" ]]; then
            SANDSWAP_K8S_NODES="$(k8s_nodes | tr '\n' ' ')"
            export SANDSWAP_K8S_NODES
        fi
        CERTS_YAML=$(SANDSWAP_K8S_NODES="$SANDSWAP_K8S_NODES" bash "$ROOT/deploy/k8s/gen-k8s-certs.sh" 2>/dev/null | grep -A1000 "^---")
        if [[ -z "$CERTS_YAML" ]]; then
            log_error "Certificate generation failed"
            exit 1
        fi
        log_pass "TLS certificates generated (per-node stream pairs for: $SANDSWAP_K8S_NODES)"
    else
        log_step "Keeping existing TLS certificates (redeploy over a live cluster — see )"
        log_pass "PKI preserved (gateway-certs Secret already present; SANDSWAP_FORCE_CERT_REGEN=1 to rotate)"
    fi

    log_step "Applying K8s manifests ($MODE_NAME mode)..."

    # Seccomp profile for the sandbox container (allows AF_VSOCK socket()).
    # Installed out-of-band on the host kubelet dir — a fact no manifest can
    # express; recorded in the ledger so cleanup/replay removes it.
    SECCOMP_DIR="/var/lib/kubelet/seccomp/sandswap"
    mkdir -p "$SECCOMP_DIR"
    cp "$ROOT/deploy/k8s/seccomp/sandlot-seccomp.json" "$SECCOMP_DIR/"
    se_record EPHEMERAL seccomp "$SECCOMP_DIR"
    log_pass "Seccomp profile installed to $SECCOMP_DIR/sandlot-seccomp.json"

    # Namespace first (other manifests depend on it), plus the label the
    # NetworkPolicy namespaceSelector needs (k3s may not auto-add it; without
    # it the default-deny policy blocks ALL traffic including DNS).
    $KUBECTL apply -f "$ROOT/deploy/k8s/namespace.yaml"
    $KUBECTL label namespace "$NAMESPACE" kubernetes.io/metadata.name="$NAMESPACE" --overwrite

    if [[ "$regen" == "1" ]]; then
        echo "$CERTS_YAML" | $KUBECTL apply -f -
    fi

    # The sandlot ConfigMap carries the sandvmm identity-split keys
    # (microvm.vmm_uid/gid/groups/api_gid). The child's supplementary groups
    # are REPLACED by the setpriv spawn, so microvm.vmm_groups must carry the
    # HOST kvm gid (not a name — the image's /etc/group kvm gid rarely
    # matches the host's) — inject it the same way as the DaemonSet
    # supplementalGroups, in BOTH modes (boxout's 987 child needs /dev/kvm
    # just as much; the placeholder stops matching after the first
    # injection). Applied from a temp copy; ledger-recorded.
    local cm_src="${K8S_CONFIGMAP_FILE:-$ROOT/deploy/k8s/configmaps.yaml}"
    if [[ -z "$KVM_GID" ]]; then
        KVM_GID=$(stat -c '%g' /dev/kvm)
    fi
    local cm_tmp
    cm_tmp=$(mktemp "${TMPDIR:-/tmp}/sandlot-configmap-XXXXXX.yaml")
    se_record EPHEMERAL tmpfile "$cm_tmp"
    # The sandvmm identity is host-resolved (occupied-slot auto-pick on
    # GCP-style hosts), so the uid/gid pair is injected like the kvm gid;
    # hardcoded contract numbers would fail the in-pod device owner check.
    VMM_UID=$(id -u sandvmm 2>/dev/null) || {
        log_error "sandvmm account not resolvable — run deploy/k8s/k8s-host-setup.sh on this node (it adopts or creates the identity; this deploy injects the resolved uid/gid)"
        exit 1
    }
    # || true on the assignment: getent exits 2 when the group is absent and
    # pipefail turns that into a script-killing failure BEFORE the friendly
    # guard below could run. The guard is the verdict.
    VMM_GID="$(getent group sandvmm 2>/dev/null | cut -d: -f3)" || true
    [[ -n "$VMM_GID" ]] || {
        log_error "sandvmm group not resolvable — run deploy/k8s/k8s-host-setup.sh on this node"
        exit 1
    }
    sed -e "s/__KVM_GID__/$KVM_GID/" -e "s/__SANDVMM_UID__/$VMM_UID/" -e "s/__SANDVMM_GID__/$VMM_GID/" "$cm_src" > "$cm_tmp"
    if grep -q "__KVM_GID__" "$cm_tmp" || grep -q "__SANDVMM_UID__" "$cm_tmp" || grep -q "__SANDVMM_GID__" "$cm_tmp"; then
        log_error "configmap identity injection failed (placeholder unmatched) — aborting before a sandvmm child without /dev/kvm access is deployed"
        exit 1
    fi
    log_pass "ConfigMap: injected kvm gid $KVM_GID + sandvmm uid/gid $VMM_UID/$VMM_GID (sandvmm child device access)"
    $KUBECTL apply -f "$cm_tmp"

    # Seed the MCP agent-guide ConfigMap from the gateway binary's compiled-in
    # default (single source of truth — no second copy in the repo). Generate-
    # once: an existing ConfigMap — possibly operator-edited — is never
    # overwritten; delete it to re-seed from a newer binary. Ops edits the
    # ConfigMap directly; kubelet's atomic symlink swap lands in the pod and
    # the gateway's file watcher hot-reloads (~200ms). The volume mount in
    # gateway.yaml requires this ConfigMap to exist, so a missing binary is
    # fatal here (the deploy build phase produces it).
    if ! $KUBECTL -n "$NAMESPACE" get configmap gateway-mcp-instructions &>/dev/null; then
        local mcp_tmp
        mcp_tmp=$(mktemp)
        if ! "$OUTPUT/gateway" -print-mcp-instructions > "$mcp_tmp" 2>/dev/null || [[ ! -s "$mcp_tmp" ]]; then
            rm -f "$mcp_tmp"
            log_error "cannot seed gateway-mcp-instructions: $OUTPUT/gateway -print-mcp-instructions failed (rebuild output/?)"
            exit 1
        fi
        $KUBECTL -n "$NAMESPACE" create configmap gateway-mcp-instructions \
            --from-file=mcp-instructions.md="$mcp_tmp"
        rm -f "$mcp_tmp"
        log_pass "MCP instructions ConfigMap seeded from the gateway default"
    fi
    # Volume-name seed Secret (prov role): create ONCE, never
    # regenerate. A different seed would orphan every existing volume name
    # (names are derived from it — sandlot/provision/volname), so an existing
    # Secret is kept as-is even across teardown/redeploy cycles; k8s-cleanup
    # likewise leaves it. Rotation is a deliberate operator window
    # (rotate-volume-seed.sh), never a redeploy side effect.
    if ! $KUBECTL -n "$NAMESPACE" get secret sandswap-volume-seed &>/dev/null; then
        if [[ "${SANDSWAP_VOLUME_SEED_NO_MINT:-0}" == "1" ]]; then
            # This deployment INJECTS its seed (an external secret manager owns
            # the Secret and its generation keys). Minting here would look like
            # a successful deploy while orphaning every existing volume name.
            log_error "SANDSWAP_VOLUME_SEED_NO_MINT=1 but the sandswap-volume-seed Secret does not exist — create it from your secret store (one key per generation, the ConfigMap names the current one) before deploying; refusing to mint a replacement"
            return 1
        fi
        # prefer the teardown backups (k8s-cleanup.sh) — re-minting a
        # fresh seed makes every pre-teardown volume name unresolvable. Every
        # generation key is restored, not just the legacy one: dropping a
        # staged generation would strand a half-rotated tree.
        local seed_tmp backup_args=() b
        seed_tmp=$(mktemp)
        se_record EPHEMERAL tmpfile "$seed_tmp"
        if [[ -s /etc/sandswap/volume-seed ]]; then
            cp /etc/sandswap/volume-seed "$seed_tmp"
            backup_args+=(--from-file=volume-seed="$seed_tmp")
            log_pass "Volume-name seed restored from /etc/sandswap/volume-seed (post-teardown backup)"
        fi
        shopt -s nullglob
        for b in /etc/sandswap/volume-seed.*; do
            local key="${b##*/volume-seed.}"
            backup_args+=(--from-file="$key=$b")
            log_pass "Volume-name generation '$key' restored from $b (post-teardown backup)"
        done
        shopt -u nullglob
        if [[ "${#backup_args[@]}" -eq 0 ]]; then
            # umask-isolated mint (0600 file; the subshell keeps the umask from
            # leaking into later artifact installs — lesson).
            ( umask 077; openssl rand -hex 32 > "$seed_tmp" )
            backup_args+=(--from-file=volume-seed="$seed_tmp")
            log_pass "Volume-name seed Secret created (KEEP IT — every sandfs name derives from it)"
        fi
        $KUBECTL -n "$NAMESPACE" create secret generic sandswap-volume-seed "${backup_args[@]}"
        rm -f "$seed_tmp"
    else
        log_pass "Volume-name seed Secret already present (kept as-is)"
    fi
    $KUBECTL apply -f "$ROOT/deploy/k8s/volumes.yaml"
    $KUBECTL apply -f "$ROOT/deploy/k8s/etcd.yaml"
    $KUBECTL apply -f "$ROOT/deploy/k8s/gateway.yaml"
    $KUBECTL apply -f "$ROOT/deploy/k8s/sandns.yaml"
    # DaemonSet manifest with GID/LSM injection applied (temp copy from Phase 1)
    $KUBECTL apply -f "$SANDLOT_YAML_TMP"
    rm -f "$SANDLOT_YAML_TMP"
    $KUBECTL apply -f "$ROOT/deploy/k8s/human.yaml"
    $KUBECTL apply -f "$ROOT/deploy/k8s/sandlot-prov.yaml"
    $KUBECTL apply -f "$ROOT/deploy/k8s/networkpolicy.yaml"

    log_pass "K8s manifests applied"
}

# ════════════════════════════════════════════════════════════════════
# Phase 4b: per-node stream client certificates
# ════════════════════════════════════════════════════════════════════
# The gateway binds a stream hello's declared node_id to the presented client
# certificate's CN by EXACT match (gateway/stream/server.go
# verifyNodeIdentity): every sandlot pod declares node_id = its NODE name and
# every node must carry ITS OWN pair in /etc/sandswap/stream-certs (fetched by
# k8s-host-setup.sh from the per-node Secret sandlot-certs-<node>); the
# provision Deployment has the singleton identity `sandlot-prov`
# (sandlot-certs-prov). This phase proves a Secret exists for every node,
# materializes the material on the node this deploy is RUNNING ON, and names
# the command for every other node. A missing pair is a pod that starts and
# then cannot open a stream at all (refused at the handshake by name).
k8s_phase_stream_certs() {
    log_step "Verifying per-node stream certificates..."

    local prov_secret="sandlot-certs-prov"
    if ! $KUBECTL -n "$NAMESPACE" get secret "$prov_secret" &>/dev/null; then
        log_error "Secret $prov_secret is missing — the provision Deployment cannot connect"
        log_error "  (re-mint the PKI: SANDSWAP_FORCE_CERT_REGEN=1 bash deploy/k8s/deploy-k8s-*.sh, or run gen-k8s-certs.sh and apply it)"
        exit 1
    fi

    local nodes node missing="" count=0
    nodes="$(k8s_nodes)"
    if [[ -z "${nodes// /}" ]]; then
        log_error "no cluster nodes resolved (kubectl get nodes returned nothing and SANDSWAP_K8S_NODES is unset) — cannot verify per-node stream certificates"
        exit 1
    fi
    while IFS= read -r node; do
        [[ -n "$node" ]] || continue
        count=$((count + 1))
        $KUBECTL -n "$NAMESPACE" get secret "sandlot-certs-${node}" &>/dev/null || missing="$missing $node"
    done <<< "$nodes"
    if [[ -n "$missing" ]]; then
        log_error "no stream client Secret for node(s):$missing"
        log_error "  (the PKI was minted for a different node list — an existing PKI is preserved by default,"
        log_error "   so a NEW node needs them minted + applied:"
        log_error "   SANDSWAP_K8S_NODES=\"$(printf '%s' "$nodes" | tr '\n' ' ')\" bash $ROOT/deploy/k8s/gen-k8s-certs.sh | $KUBECTL apply -f - )"
        exit 1
    fi
    log_pass "per-node stream client Secrets present ($count node(s) + the prov singleton)"

    # Materialize the local node's hostPath now: the deploy is expected to be
    # one command on a cluster host (the single-box k3s shape), and the
    # DaemonSet pod on THIS node would otherwise fail its certs-copy init
    # container. Idempotent (install(1) over the existing files).
    local local_node
    local_node="$(k8s_local_node)"
    if [[ -n "$local_node" ]]; then
        log_step "Fetching this node's stream certificate ($local_node)..."
        if bash "$ROOT/deploy/k8s/k8s-host-setup.sh" --stream-certs-only --node "$local_node" >/dev/null 2>&1; then
            log_pass "stream cert materialized on this node: /etc/sandswap/stream-certs (node $local_node)"
        else
            log_error "could not materialize the stream cert for node $local_node — the sandlot pod on this node cannot start"
            log_error "  diagnose: bash $ROOT/deploy/k8s/k8s-host-setup.sh --stream-certs-only --node $local_node"
            exit 1
        fi
    else
        log_warn "this host is not a cluster node — materialize the stream cert on every node:"
        while IFS= read -r node; do
            [[ -n "$node" ]] || continue
            log_warn "  on $node: sudo bash deploy/k8s/k8s-host-setup.sh --stream-certs-only --node $node"
        done <<< "$nodes"
    fi
}

# ════════════════════════════════════════════════════════════════════
# Phase 5: readiness waits
# ════════════════════════════════════════════════════════════════════
# "Ready" here means scheduling + probes; the REAL readiness check is the
# end-to-end execute poll in Phase 7 (the sandbox DaemonSet has no probes —
# a hostNetwork/privileged pod has nothing meaningful to probe).

k8s_wait() { # k8s_wait <tries> <check-cmd...>
    local tries="$1"
    shift
    for i in $(seq 1 "$tries"); do
        if "$@" &>/dev/null; then
            return 0
        fi
        sleep 3
    done
    return 1
}

k8s_phase_wait_ready() {
    log_step "Waiting for PVCs to be bound..."
    for i in $(seq 1 30); do
        VOLS_BOUND=$($KUBECTL get pvc sandswap-volumes -n "$NAMESPACE" -o jsonpath='{.status.phase}' 2>/dev/null || echo "")
        TMPL_BOUND=$($KUBECTL get pvc sandswap-templates -n "$NAMESPACE" -o jsonpath='{.status.phase}' 2>/dev/null || echo "")
        if [[ "$VOLS_BOUND" == "Bound" ]] && [[ "$TMPL_BOUND" == "Bound" ]]; then
            break
        fi
        sleep 2
    done
    if ! $KUBECTL get pvc sandswap-volumes -n "$NAMESPACE" -o jsonpath='{.status.phase}' 2>/dev/null | grep -q Bound; then
        log_error "PVC sandswap-volumes not bound"
        $KUBECTL describe pvc sandswap-volumes -n "$NAMESPACE" 2>/dev/null || true
        exit 1
    fi
    if ! $KUBECTL get pvc sandswap-templates -n "$NAMESPACE" -o jsonpath='{.status.phase}' 2>/dev/null | grep -q Bound; then
        log_error "PVC sandswap-templates not bound"
        $KUBECTL describe pvc sandswap-templates -n "$NAMESPACE" 2>/dev/null || true
        exit 1
    fi
    log_pass "PVCs bound (sandswap-volumes, sandswap-templates)"

    log_step "Waiting for etcd pod..."
    if ! k8s_wait 60 $KUBECTL wait pod/etcd-0 -n "$NAMESPACE" --for=condition=ready --timeout=5s; then
        log_error "etcd pod not ready"
        $KUBECTL describe pod/etcd-0 -n "$NAMESPACE" 2>/dev/null || true
        exit 1
    fi
    log_pass "etcd pod ready"
    # etcd uses mTLS for authentication (--client-cert-auth on the server,
    # --etcd-cert/--etcd-key on the gateway). No username/password setup needed.

    log_step "Waiting for gateway pods (StatefulSet)..."
    for i in $(seq 1 60); do
        READY=$($KUBECTL get statefulset gateway -n "$NAMESPACE" -o jsonpath='{.status.readyReplicas}' 2>/dev/null || echo "0")
        if [[ "$READY" -ge 1 ]]; then
            break
        fi
        sleep 3
    done
    READY=$($KUBECTL get statefulset gateway -n "$NAMESPACE" -o jsonpath='{.status.readyReplicas}' 2>/dev/null || echo "0")
    if [[ "$READY" -lt 1 ]]; then
        log_error "Gateway pods not ready (readyReplicas=$READY)"
        $KUBECTL describe statefulset gateway -n "$NAMESPACE" 2>/dev/null || true
        $KUBECTL logs -n "$NAMESPACE" -l app=gateway --tail=20 2>/dev/null || true
        exit 1
    fi
    log_pass "Gateway pods ready ($READY/$READY)"

    log_step "Waiting for sandswap-sandns pods..."
    for i in $(seq 1 60); do
        DNS_READY=$($KUBECTL get deployment sandswap-sandns -n "$NAMESPACE" -o jsonpath='{.status.readyReplicas}' 2>/dev/null || echo "0")
        if [[ "$DNS_READY" -ge 1 ]]; then
            break
        fi
        sleep 3
    done
    DNS_READY=$($KUBECTL get deployment sandswap-sandns -n "$NAMESPACE" -o jsonpath='{.status.readyReplicas}' 2>/dev/null || echo "0")
    if [[ "$DNS_READY" -lt 1 ]]; then
        log_error "sandswap-sandns pods not ready"
        $KUBECTL logs -n "$NAMESPACE" -l app=sandswap-sandns --tail=20 2>/dev/null || true
        exit 1
    fi
    log_pass "sandswap-sandns pods ready ($DNS_READY)"

    log_step "Waiting for $SANDLOT_DS pods..."
    for i in $(seq 1 90); do
        READY=$($KUBECTL get daemonset "$SANDLOT_DS" -n "$NAMESPACE" -o jsonpath='{.status.numberReady}' 2>/dev/null || echo "0")
        DESIRED=$($KUBECTL get daemonset "$SANDLOT_DS" -n "$NAMESPACE" -o jsonpath='{.status.desiredNumberScheduled}' 2>/dev/null || echo "0")
        if [[ "$READY" == "$DESIRED" ]] && [[ "$READY" -gt 0 ]]; then
            break
        fi
        sleep 3
    done
    READY=$($KUBECTL get daemonset "$SANDLOT_DS" -n "$NAMESPACE" -o jsonpath='{.status.numberReady}' 2>/dev/null || echo "0")
    # -eq (not == "0"): numberReady is omitempty — a stuck-at-zero DaemonSet
    # reports an EMPTY field (jsonpath prints nothing, exit 0), and "" == "0"
    # is false while (( "" )) evaluates as 0. The string form would false-pass
    # readiness and lose the container-log dump below.
    if [[ "$READY" -eq 0 ]]; then
        log_error "$SANDLOT_DS pods not ready"
        $KUBECTL describe daemonset "$SANDLOT_DS" -n "$NAMESPACE" 2>/dev/null || true
        for c in $SANDLOT_DS_LOG_CONTAINERS; do
            $KUBECTL logs -n "$NAMESPACE" -l "$SANDLOT_SELECTOR" -c "$c" --tail=30 2>/dev/null || true
        done
        exit 1
    fi
    log_pass "$SANDLOT_DS pods ready ($READY)"

    log_step "Waiting for admin gateway pod..."
    for i in $(seq 1 60); do
        READY=$($KUBECTL get deployment gateway-human -n "$NAMESPACE" -o jsonpath='{.status.readyReplicas}' 2>/dev/null || echo "0")
        if [[ "$READY" == "1" ]]; then
            break
        fi
        sleep 3
    done
    READY=$($KUBECTL get deployment gateway-human -n "$NAMESPACE" -o jsonpath='{.status.readyReplicas}' 2>/dev/null || echo "0")
    if [[ "$READY" != "1" ]]; then
        log_error "Human gateway pod not ready (readyReplicas=$READY)"
        $KUBECTL describe deployment gateway-human -n "$NAMESPACE" 2>/dev/null || true
        $KUBECTL logs -n "$NAMESPACE" -l app=gateway-human --tail=20 2>/dev/null || true
        exit 1
    fi
    log_pass "Human gateway pod ready"

    # The prov role: the human gateway has NO storage of its own — every
    # sandfs/template op routes over its stream to a sandlot-prov pod. The
    # drill creates a sandfs, so this must be up before the reachability/
    # agents phases; a missing prov pod surfaces there as a named 503.
    log_step "Waiting for sandlot-prov pod (provision plane)..."
    for i in $(seq 1 40); do
        PROV_READY=$($KUBECTL get deployment sandlot-prov -n "$NAMESPACE" -o jsonpath='{.status.readyReplicas}' 2>/dev/null || echo "0")
        if [[ "${PROV_READY:-0}" -ge 1 ]]; then
            break
        fi
        sleep 3
    done
    PROV_READY=$($KUBECTL get deployment sandlot-prov -n "$NAMESPACE" -o jsonpath='{.status.readyReplicas}' 2>/dev/null || echo "0")
    if [[ "${PROV_READY:-0}" -lt 1 ]]; then
        log_error "sandlot-prov pod not ready (readyReplicas=$PROV_READY) — storage ops would 503"
        $KUBECTL describe deployment sandlot-prov -n "$NAMESPACE" 2>/dev/null || true
        $KUBECTL logs -n "$NAMESPACE" -l app=sandlot-prov --tail=20 2>/dev/null || true
        exit 1
    fi
    log_pass "sandlot-prov pod ready (provision plane)"

    # Seed flat templates into the SHARED templates PVC. The prov pods scan
    # <templates PVC>/flat (sandlot-prov-config) — NOT a node hostPath — so
    # the host-side staging tree ($DEPLOY_DIR/flat-templates) is piped into
    # the running prov pod: it owns the PVC mount, runs as the uid the PVC
    # lands as, and needs no extra image. Idempotent (replaces rootfs in
    # place); the prov rescans lazily on first reference so rootfs:v1 needs
    # no pod restart. A silently-empty PVC would 503 every rootfs:v1 create
    # downstream, so the landing is verified before moving on.
    if [[ -d "$DEPLOY_DIR/flat-templates/rootfs/v1" ]]; then
        log_step "Seeding flat templates into the templates PVC (via the prov pod)..."
        PROV_POD=$($KUBECTL get pod -n "$NAMESPACE" -l app=sandlot-prov \
            -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
        if [[ -z "$PROV_POD" ]]; then
            log_error "no sandlot-prov pod found for flat-template staging"
            exit 1
        fi
        # The prov pod can be briefly mid-restart right after readiness
        # (the Deployment's Recreate strategy + the init mount). Retry the
        # exec-based staging instead of treating a transient "container not
        # found" as a permanent deploy failure.
        seed_ok=0
        for _seed_try in 1 2 3 4 5; do
            if $KUBECTL exec -n "$NAMESPACE" "$PROV_POD" -- \
                    rm -rf /sandswap/overlay-templates/flat/rootfs 2>/dev/null \
               && $KUBECTL exec -n "$NAMESPACE" "$PROV_POD" -- \
                    mkdir -p /sandswap/overlay-templates/flat 2>/dev/null; then
                seed_ok=1
                break
            fi
            sleep 3
        done
        if [[ "$seed_ok" != "1" ]]; then
            log_error "seed exec into $PROV_POD failed after 5 tries"
            $KUBECTL get pod -n "$NAMESPACE" "$PROV_POD" -o wide 2>/dev/null || true
            $KUBECTL describe pod -n "$NAMESPACE" "$PROV_POD" 2>/dev/null | tail -40 || true
            $KUBECTL logs -n "$NAMESPACE" "$PROV_POD" -c sandlot-prov --tail=40 2>/dev/null || true
            exit 1
        fi
        if tar -C "$DEPLOY_DIR/flat-templates" -cf - rootfs \
            | $KUBECTL exec -i -n "$NAMESPACE" "$PROV_POD" -- \
                tar -xf - -C /sandswap/overlay-templates/flat; then
            if $KUBECTL exec -n "$NAMESPACE" "$PROV_POD" -- \
                test -d /sandswap/overlay-templates/flat/rootfs/v1/bin; then
                log_pass "Flat templates seeded (rootfs:v1 inside the shared templates PVC)"
            else
                log_error "flat-template staging verified empty — rootfs:v1 would not resolve"
                exit 1
            fi
        else
            log_error "tar pipe into the sandlot-prov pod failed"
            exit 1
        fi
    fi


    # Verify the sandbox actually runs unprivileged (boxout mode). Read
    # runAsUser from the pod spec — exec-based checks (`id`) work too now that
    # every image is ubuntu-based, but the spec is the source of truth.
    if [[ "$VERIFY_SANDBOX_UID" == "true" ]]; then
        log_step "Verifying sandlot container runs as UID $SANDBOX_UID..."
        POD_UID=$($KUBECTL get daemonset "$SANDLOT_DS" -n "$NAMESPACE" \
            -o jsonpath='{.spec.template.spec.containers[?(@.name=="sandlot")].securityContext.runAsUser}' 2>/dev/null || echo "unknown")
        if [[ "$POD_UID" == "$SANDBOX_UID" ]]; then
            log_pass "Sandlot container verified: runAsUser=$POD_UID (unprivileged)"
        else
            log_warn "Sandlot container runAsUser=$POD_UID (expected $SANDBOX_UID)"
        fi
    fi

    echo ""
    $KUBECTL get pods -n "$NAMESPACE" -o wide
    echo ""
}

# ════════════════════════════════════════════════════════════════════
# Phase 5a: pod-side security invariants (asserted on EVERY deploy and
# verify drill — these are the in-pod halves of the isolation layers that
# a manifest cannot guarantee by itself)
# ════════════════════════════════════════════════════════════════════

# Assert one "stat expectation" in a pod. Two failure classes, handled
# differently: a WRONG MODE is a real invariant violation → fail immediately;
# a transient exec error ("container not found" during a restart window) is
# retried before failing — the DS readiness gate can pass on a pod that then
# restarts, and an observation window must not be mistaken for a violation.
k8s_assert_stat() { # <pod> <container> <path> <want-mode> <want-uid> <label>
    local pod="$1" container="$2" path="$3" want_mode="$4" want_uid="$5" label="$6"
    local got try
    for try in 1 2 3 4; do
        got=$($KUBECTL exec -n "$NAMESPACE" "$pod" -c "$container" -- \
            stat -c '%a %u' "$path" 2>&1)
        if [[ $? -eq 0 ]]; then
            break
        fi
        if (( try == 4 )); then
            log_error "$label: cannot stat $path in $pod/$container after 4 tries: $got"
            exit 1
        fi
        log_warn "$label: exec not ready yet (${try}/4): $got — retrying"
        sleep 5
    done
    if [[ "$got" != "$want_mode $want_uid" ]]; then
        log_error "$label: $path is '$got', want '$want_mode $want_uid'"
        log_error "  (the file-mode layer behind this assertion is not in force — see the certs-copy/init-container comments in the manifest)"
        exit 1
    fi
    log_pass "$label: $path = $got"
}

k8s_phase_security_invariants() {
    log_step "Asserting pod-side security invariants..."

    # The compute pod's certs: the node stream client key
    # must be mode-0400 and readable ONLY by the sandlot container's uid —
    # never by the in-pod sandvmm identity (987). defaultMode on a Secret
    # volume is NOT dependable (this k3s writes Secret files 0777 regardless
    # — probed live), so the certs-copy init container re-materializes them:
    # embedded (root pod) → uid 0, boxout (UID 65536 pod, and 987 shares that
    # group) → uid 65536.
    local sandlot_pod sandlot_uid
    sandlot_pod=$($KUBECTL get pod -n "$NAMESPACE" -l "$SANDLOT_SELECTOR" \
        -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
    [[ -n "$sandlot_pod" ]] || { log_error "no pod for $SANDLOT_SELECTOR"; exit 1; }
    # Gate on the pod being ACTUALLY ready (the DS-level count above can pass
    # on a pod that then restarts): 60s, then the per-assertion retries below.
    if ! $KUBECTL wait -n "$NAMESPACE" --for=condition=ready "pod/$sandlot_pod" \
            --timeout=60s &>/dev/null; then
        log_error "compute pod $sandlot_pod not ready: $($KUBECTL -n "$NAMESPACE" get pod "$sandlot_pod" -o jsonpath='{.status.phase}{" restarts="}{.status.containerStatuses[0].restartCount}' 2>/dev/null)"
        $KUBECTL -n "$NAMESPACE" logs "$sandlot_pod" --all-containers --tail=15 2>/dev/null || true
        exit 1
    fi
    case "$MODE_NAME" in
        embedded) sandlot_uid=0 ;;
        boxout)   sandlot_uid=65536 ;;
        *) log_error "unknown MODE_NAME: $MODE_NAME"; exit 1 ;;
    esac
    k8s_assert_stat "$sandlot_pod" sandlot /certs/client.key 400 "$sandlot_uid" \
        "compute pod stream key"

    # The share root + template store (isolation layer 4 / storage contract
    # rows 10b+): traverse-only volumes root (no list, no write for the FUSE
    # daemon's group), prov-owned read-only template store. Re-asserted by
    # the prep init container on every pod start; asserted here so a regression
    # in that container cannot pass silently.
    k8s_assert_stat "$sandlot_pod" sandlot /sandswap/volumes 2710 1000 "share root"
    k8s_assert_stat "$sandlot_pod" sandlot /sandswap/overlay-templates 2750 1000 "template store"

    # The provision pod (both modes ship it): stream key 0400 (its own uid —
    # the pod is non-root 1000), and the volume-name seed present (the prov
    # role refuses to boot without it, so readiness already proves the read;
    # the assertion documents the invariant and catches a mounted-but-empty
    # Secret).
    local prov_pod
    prov_pod=$($KUBECTL get pod -n "$NAMESPACE" -l app=sandlot-prov \
        -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
    [[ -n "$prov_pod" ]] || { log_error "no sandlot-prov pod found"; exit 1; }
    k8s_assert_stat "$prov_pod" sandlot-prov /certs/client.key 400 1000 "prov stream key"
    if ! $KUBECTL exec -n "$NAMESPACE" "$prov_pod" -c sandlot-prov -- \
            sh -c 'test -s /sandswap-seed/volume-seed' 2>/dev/null; then
        log_error "prov pod: /sandswap-seed/volume-seed missing or empty (the volume-name seed Secret is not mounted?)"
        exit 1
    fi
    log_pass "prov pod: volume-name seed present"
}

# ════════════════════════════════════════════════════════════════════
# Phase 5b: CoreDNS wiring
# ════════════════════════════════════════════════════════════════════

k8s_phase_wire_coredns() {
    # Make in-cluster pods resolve <sandfs_id>.sandfs.sandswap.local through
    # the sandswap-sandns Service. CoreDNS gets a zone block forwarding
    # sandfs.sandswap.local to the sandswap-sandns ClusterIP; CoreDNS then chases
    # the returned CNAME (to the owner gateway's headless FQDN) back into the
    # cluster. This mutates a CLUSTER-GLOBAL component — always reverted via
    # the ledger on cleanup (a stale zone blackholes per-sandfs lookups
    # cluster-wide once the namespace is gone).
    DNS_IP=$($KUBECTL get svc sandswap-sandns -n "$NAMESPACE" -o jsonpath='{.spec.clusterIP}' 2>/dev/null || echo "")
    if [[ -z "$DNS_IP" ]]; then
        log_error "sandswap-sandns Service has no ClusterIP"
        exit 1
    fi

    COREFILE_TMP=$(mktemp)
    se_record EPHEMERAL tmpfile "$COREFILE_TMP"
    $KUBECTL get configmap coredns -n kube-system -o jsonpath='{.data.Corefile}' > "$COREFILE_TMP" 2>/dev/null
    # Add the sandfs zone, or refresh its forward target if the sandswap-sandns
    # Service ClusterIP changed since a previous deploy (a recreated Service
    # gets a new IP — the stale one would silently blackhole every per-sandfs
    # lookup).
    python3 - "$COREFILE_TMP" "$DNS_IP" <<'PYEOF'
import re, sys
path, dns_ip = sys.argv[1], sys.argv[2]
text = open(path).read()
if "sandfs.sandswap.local" in text:
    text = re.sub(r"(sandfs\.sandswap\.local:53 \{[^}]*?forward \. )\S+",
                  r"\g<1>" + dns_ip, text, flags=re.S)
else:
    text += "\nsandfs.sandswap.local:53 {\n    errors\n    forward . " + dns_ip + "\n}\n"
open(path, "w").write(text)
PYEOF
    if ! $KUBECTL get configmap coredns -n kube-system -o jsonpath='{.data.Corefile}' 2>/dev/null | diff -q - "$COREFILE_TMP" >/dev/null 2>&1; then
        # JSON merge patch: replaces ONLY the Corefile key. (create+replace here
        # used to wipe k3s's NodeHosts key from the ConfigMap; the coredns pod
        # volume references that key, so it stuck in ContainerCreating forever
        # and cluster DNS died.)
        PATCH=$(python3 -c "
import json
print(json.dumps({'data': {'Corefile': open('$COREFILE_TMP').read()}}))
")
        $KUBECTL patch configmap coredns -n kube-system --type merge -p "$PATCH" >/dev/null
        $KUBECTL rollout restart deployment/coredns -n kube-system 2>/dev/null || true
        se_record EPHEMERAL coredns-zone
        log_pass "CoreDNS: sandfs.sandswap.local → $DNS_IP (restarted coredns)"
    else
        log_pass "CoreDNS: sandfs.sandswap.local forward already correct"
    fi
    rm -f "$COREFILE_TMP"
}

# ════════════════════════════════════════════════════════════════════
# Phase 6: human port-forward + exec-gateway reachability
# ════════════════════════════════════════════════════════════════════

# start_port_forward — resilient port-forward that auto-reconnects. Writes a
# watchdog script (each watchdog traps TERM/INT/EXIT and kills its own
# kubectl port-forward child) and records the pid file in the ledger.
# Usage: start_port_forward <label_selector> <local_port> <remote_port>
start_port_forward() {
    local selector="$1"
    local local_port="$2"
    local remote_port="$3"
    local pid_file="/tmp/sandswap-pf-${local_port}.pid"
    local script_file="/tmp/sandswap-pf-${local_port}.sh"

    # Kill any previous watchdog
    if [[ -f "$pid_file" ]]; then
        kill "$(cat "$pid_file")" 2>/dev/null || true
        rm -f "$pid_file"
    fi

    # Write a watchdog script to a file — avoids subshell/quoting issues
    cat > "$script_file" <<SCRIPT
#!/bin/bash
export KUBECONFIG="${KUBECONFIG:-/etc/rancher/k3s/k3s.yaml}"
# Tear down the live port-forward child on any exit (incl. SIGTERM from the
# parent cleanup trap). Without this, killing the watchdog leaves the
# kubectl port-forward child orphaned onto init, still holding the port.
trap '[[ -n "\$child" ]] && kill \$child 2>/dev/null; exit 0' TERM INT EXIT
child=""
while true; do
    pod=\$(kubectl get pods -n "$NAMESPACE" -l "$selector" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
    if [[ -z "\$pod" ]]; then
        sleep 2
        continue
    fi
    # Free the port from any stale orphaned port-forward (ss-based: lsof is
    # not part of the base image set and silently no-ops when missing).
    ss -tlnp 2>/dev/null | grep ":$local_port " | grep -oE 'pid=[0-9]+' | grep -oE '[0-9]+' | sort -u | xargs -r kill 2>/dev/null || true
    sleep 0.5
    kubectl port-forward -n "$NAMESPACE" "\$pod" "$local_port:$remote_port" 2>/dev/null &
    child=\$!
    wait \$child 2>/dev/null
    child=""
    sleep 1
done
SCRIPT
    chmod +x "$script_file"
    nohup bash "$script_file" >/dev/null 2>&1 &
    local watchdog_pid=$!
    echo "$watchdog_pid" > "$pid_file"
    se_record EPHEMERAL port-forward "$pid_file"
    PF_PIDS+=("$watchdog_pid")
}

k8s_phase_reachability() {
    # Real agents are IN-CLUSTER pods and reach the gateway via the per-sandfs
    # URL — https://<sandfs_id>.sandfs.sandswap.local:3000/mcp — resolved by
    # CoreDNS → sandswap-sandns → owner gateway. The EXEC gateway has NO
    # port-forward: its traffic is pod-to-pod over CNI. This host-side harness
    # reaches it through the headless Service FQDN mapped to a gateway pod IP
    # in /etc/hosts (the FQDN is in the cert SAN, so TLS validates) — the host
    # standing in for an in-cluster agent. The HUMAN gateway keeps a
    # port-forward as the control plane for host-side agent/SandFS CRUD.

    log_step "Starting human gateway port-forward (3100 → 3100)..."
    start_port_forward "app=gateway-human" 3100 3100

    # The human listener is TLS in the default deployment and plaintext
    # under --no-tls: detect the shape once from the first successful health
    # read and point HUMAN_URL at it. Every later human-API call (the
    # provisioners gate below, /stats, the CRUD phases) shares the answer —
    # hardcoding either scheme here breaks the other mode silently.
    HUMAN_URL=""
    for i in $(seq 1 15); do
        sleep 1
        for u in "https://localhost:3100" "http://localhost:3100"; do
            if curl -sk --max-time 3 "$u/health" 2>/dev/null | grep -q '"status"'; then
                HUMAN_URL="$u"
                break
            fi
        done
        [[ -n "$HUMAN_URL" ]] && break
    done
    if [[ -z "$HUMAN_URL" ]]; then
        log_error "Port-forward to human gateway not working after 15s (no health on either scheme)"
        exit 1
    fi
    log_pass "Human gateway port-forward active on :3100 ($HUMAN_URL)"

    # Pod-ready is NOT prov-connected: the instance still has to complete the
    # mTLS dial (and a fresh deploy may have raced a connection-refused during
    # startup). The human gateway reports the connected provision-instance
    # count on /health as "provisioners" — gate on it so the drill never
    # races a not-yet-connected storage plane.
    log_step "Waiting for the provisioning plane to register (health.provisioners >= 1)..."
    local pv_ok=0
    for i in $(seq 1 40); do
        PV_HEALTH=$(curl -sk --max-time 3 "$HUMAN_URL/health" 2>/dev/null || echo "")
        if echo "$PV_HEALTH" | grep -qE '"provisioners":[[:space:]]*[1-9]'; then
            pv_ok=1
            break
        fi
        sleep 3
    done
    if [[ "$pv_ok" != "1" ]]; then
        log_error "no provision instance registered (health: ${PV_HEALTH:-unreachable}) — storage ops would 503"
        $KUBECTL logs -n "$NAMESPACE" -l app=sandlot-prov --tail=20 2>/dev/null || true
        exit 1
    fi
    log_pass "provision instance registered (storage plane live)"

    # Exec-gateway pin (ledger-tracked; cleanup + preflight replay remove it)
    GW_POD_IP=$($KUBECTL get pod -n "$NAMESPACE" -l app=gateway -o jsonpath='{.items[0].status.podIP}' 2>/dev/null || echo "")
    if [[ -z "$GW_POD_IP" ]]; then
        log_error "No gateway pod IP found"
        exit 1
    fi
    sed -i "/$GW_FQDN/d" /etc/hosts 2>/dev/null || true
    echo "$GW_POD_IP $GW_FQDN" >> /etc/hosts
    se_record EPHEMERAL hosts-pin "$GW_FQDN"
    GATEWAY_URL="https://$GW_FQDN:3000"
    log_pass "Exec gateway reachable at $GATEWAY_URL (host /etc/hosts → $GW_POD_IP)"

    # Compute-node registration wait: pod-ready ≠ stream-connected. The
    # sandlot DaemonSet has no readiness probe (nothing meaningful to probe
    # on a hostNetwork/privileged pod), so poll the gateway's own view
    # (human /stats reads node presence from etcd) until the node stream
    # lands — otherwise the keep-mode hand-over (and every immediate
    # consumer: verify-k8s.sh, the egress enabler) races NO_COMPUTE_NODES
    # on its first exec.
    log_step "Waiting for the sandlot node to register with the gateway..."
    local node_count=0 i
    for i in $(seq 1 60); do
        node_count=$(curl -sk --max-time 5 "$HUMAN_URL/stats" | python3 -c "import sys,json; print(json.load(sys.stdin).get('totals',{}).get('node_count',0))" 2>/dev/null || echo 0)
        [[ "$node_count" -ge 1 ]] && break
        sleep 3
    done
    if [[ "$node_count" -ge 1 ]]; then
        log_pass "Compute node registered (node_count=$node_count)"
    else
        log_error "Compute node did not register within 180s (/stats node_count stayed 0)"
        log_step "Dumping sandlot logs..."
        for c in $SANDLOT_DS_LOG_CONTAINERS; do
            $KUBECTL logs -n "$NAMESPACE" -l "$SANDLOT_SELECTOR" -c "$c" --tail=30 2>/dev/null || true
        done
        exit 1
    fi
}

# ════════════════════════════════════════════════════════════════════
# Phase 7: agents + SandFS + first-reachability poll
# ════════════════════════════════════════════════════════════════════

# k8s_human_post retries a human-gateway POST until the response carries the
# required key. The first writes to a fresh cluster race etcd session
# establishment; a single-shot curl turned one transient empty reply into a
# full deploy teardown at the verify stage.
k8s_human_post() {
    local path="$1" required_key="$2" payload="$3"
    local attempt resp
    for attempt in 1 2 3; do
        resp=$(curl -sk -X POST "$HUMAN_URL$path" \
            -H "Content-Type: application/json" \
            -d "$payload" || echo '{}')
        # NB: the conditional expression NEEDS the else branch — `sys.exit(0 if X)`
        # is a SyntaxError, silently swallowed by 2>/dev/null into a check that
        # always fails.
        if echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); sys.exit(0 if d.get('$required_key') else 1)" 2>/dev/null; then
            echo "$resp"
            return 0
        fi
        log_warn "human API $path attempt $attempt missing '$required_key' (resp: $(echo "$resp" | head -c 120)); retrying"
        sleep 3
    done
    echo "$resp"
    return 1
}

k8s_phase_agents() {
    API_KEYS=()
    SANDFS_IDS=()

    local i
    for i in $(seq 1 "$AGENT_COUNT"); do
        local AGENT_NAME="eino-agent-$i"
        local SANDFS_NAME="eino-sandfs-$i"

        log_step "Creating agent $i ($AGENT_NAME)..."
        # NB: never write AGENT_RESP="${AGENT_RESP:-{}}" as a fallback — when
        # the variable is set, bash's brace matching turns that expansion into
        # "<value>}" (a literal trailing brace) and corrupts the JSON.
        AGENT_RESP=$(k8s_human_post "/human/agent" "api_key" "{\"name\":\"$AGENT_NAME\"}")
        AGENT_KEY=$(echo "$AGENT_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('api_key',''))" 2>/dev/null || echo "")
        AGENT_ID=$(echo "$AGENT_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('agent_id',''))" 2>/dev/null || echo "")

        if [[ -z "$AGENT_KEY" ]] || [[ -z "$AGENT_ID" ]]; then
            log_error "Failed to create agent $i: $AGENT_RESP"
            exit 1
        fi
        log_pass "Agent $i created: $AGENT_ID"

        # Create sandfs — flat mode. The package-install profile is derived
        # from the sandfs mode (flat → install profile; see docs/reference/human-api.md),
        # not a per-request flag, so no install_packages field is sent.
        log_step "Creating sandfs $i ($SANDFS_NAME)..."
        SANDFS_RESP=$(k8s_human_post "/human/sandfs" "sandfs_id" \
            "{\"agent_id\":\"$AGENT_ID\",\"name\":\"$SANDFS_NAME\",\"description\":\"Agent $i sandbox\",\"template\":\"rootfs:v1\",\"mode\":\"flat\"}")
        SANDFS_ID=$(echo "$SANDFS_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('sandfs_id',''))" 2>/dev/null || echo "")

        if [[ -z "$SANDFS_ID" ]]; then
            log_error "Failed to create sandfs $i: $SANDFS_RESP"
            exit 1
        fi
        log_pass "SandFS $i created: $SANDFS_ID"

        API_KEYS+=("$AGENT_KEY")
        SANDFS_IDS+=("$SANDFS_ID")
    done

    # Wait for etcd watch to propagate agent data to exec gateway pods.
    log_step "Waiting for etcd watch sync (5s)..."
    sleep 5

    # Verify the exec gateway can resolve the API keys with a test MCP
    # initialize — catches watch sync failures before the expensive eino run.
    log_step "Verifying exec gateway can resolve API keys..."
    VERIFY_KEY="${API_KEYS[0]}"
    VERIFY_RESP=$(curl -sk -X POST "$GATEWAY_URL/mcp" \
        -H "Authorization: Bearer $VERIFY_KEY" \
        -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"verify","version":"1.0.0"}}}' 2>/dev/null || echo '')

    if echo "$VERIFY_RESP" | grep -q '"invalid api key"'; then
        log_error "Exec gateway cannot resolve API keys — etcd watch may not have synced"
        log_error "API key used: ${VERIFY_KEY:0:20}..."
        log_error "Response: $VERIFY_RESP"
        log_step "Dumping gateway logs..."
        $KUBECTL logs -n "$NAMESPACE" -l app=gateway --tail=30 2>/dev/null || true
        exit 1
    fi

    if echo "$VERIFY_RESP" | grep -q '"result"'; then
        log_pass "Exec gateway resolved API key successfully (MCP session works)"
    else
        log_warn "Unexpected MCP response: ${VERIFY_RESP:0:200}"
    fi

    # Wait for the sandlot gRPC stream AND the sandbox pool: poll with a
    # lightweight execute request. Success means the full path works:
    # harness → gateway pod → pool.Acquire → sandlot → VM. NO_COMPUTE_NODES
    # means the sandlot stream landed on another gateway replica (with >1
    # replicas) — affinity shifts or sandlot reconnects resolve it.
    log_step "Waiting for compute node to be reachable via gateway..."
    NODE_READY=false
    for i in $(seq 1 90); do
        TEST_RESP=$(curl -sk -X POST "$GATEWAY_URL/agent/execute" \
            -H "Authorization: Bearer ${API_KEYS[0]}" \
            -H "Content-Type: application/json" \
            -d "{\"sandfs_id\":\"${SANDFS_IDS[0]}\",\"code\":\"echo ready\",\"language\":\"shell\",\"timeout\":5}" 2>/dev/null || echo '')
        if echo "$TEST_RESP" | grep -q '"status":"done\|"status": "done"'; then
            NODE_READY=true
            log_pass "Compute node reachable via gateway (execute succeeded)"
            break
        fi
        if echo "$TEST_RESP" | grep -q 'NO_COMPUTE_NODES'; then
            log_info "Gateway reports no compute nodes yet (attempt $i)..."
        elif echo "$TEST_RESP" | grep -q 'no available sandbox'; then
            NODE_READY=true
            log_pass "Compute node registered (VMs still creating)"
            break
        fi
        sleep 2
    done
    if [[ "$NODE_READY" != "true" ]]; then
        log_error "Compute node not reachable after 180s"
        log_step "Dumping sandbox + gateway logs..."
        for c in $SANDLOT_DS_LOG_CONTAINERS; do
            $KUBECTL logs -n "$NAMESPACE" -l "$SANDLOT_SELECTOR" -c "$c" --tail=30 2>/dev/null || true
        done
        $KUBECTL logs -n "$NAMESPACE" -l app=gateway --tail=30 2>/dev/null || true
        exit 1
    fi
}

# ════════════════════════════════════════════════════════════════════
# Phase 7b: overlay-template sandfs (the sandtmpl regression path)
# ════════════════════════════════════════════════════════════════════
# The exec sandlot resolves overlay refs by reading refs/*.json from the
# template store itself (sandlot/core/overlay.go); refs/ is group-scoped to
# sandtmpl (gid 982) by the prov pod, so an exec pod without the
# supplemental GID gets EACCES → "ref file not found" on every overlay-mode
# execute. Flat drills never touch this path (flat mode reads no refs),
# which is exactly how a manifest could ship without the group. Save a
# template from an existing flat sandfs (save-template produces an overlay
# ref), create an overlay-mode sandfs from it, execute, assert done.
k8s_phase_overlay_template() {
    log_step "Overlay-template path: save-template → overlay sandfs → execute..."
    # Refs are immutable: a rerun against the KEPT deployment must not
    # collide with the previous drill's saved ref — version at RUN time.
    local ov_ref resp save_resp ov_agent_id ov_agent_key ov_sandfs exec_resp i
    local ok=false
    ov_ref="verify-ov:v$(date +%s)"

    save_resp=$(k8s_human_post "/human/sandfs/${SANDFS_IDS[0]}/save-template" "template_ref" \
        "{\"template_ref\":\"$ov_ref\",\"description\":\"k8s drill overlay ref\"}") \
        || { log_error "save-template failed: $save_resp"; exit 1; }
    log_pass "Overlay template saved: $ov_ref"

    # A dedicated agent keeps the overlay sandfs out of the eino phase's
    # bookkeeping (SANDFS_IDS feeds affinity + failover).
    resp=$(k8s_human_post "/human/agent" "agent_id" "{\"name\":\"verify-overlay-agent\"}")
    ov_agent_id=$(echo "$resp" | python3 -c "import sys,json; print(json.load(sys.stdin).get('agent_id',''))" 2>/dev/null || echo "")
    ov_agent_key=$(echo "$resp" | python3 -c "import sys,json; print(json.load(sys.stdin).get('api_key',''))" 2>/dev/null || echo "")
    [[ -n "$ov_agent_id" && -n "$ov_agent_key" ]] || { log_error "overlay agent create failed: $resp"; exit 1; }

    resp=$(k8s_human_post "/human/sandfs" "sandfs_id" \
        "{\"agent_id\":\"$ov_agent_id\",\"name\":\"verify-overlay-sandfs\",\"template\":\"$ov_ref\",\"mode\":\"overlay\"}")
    ov_sandfs=$(echo "$resp" | python3 -c "import sys,json; print(json.load(sys.stdin).get('sandfs_id',''))" 2>/dev/null || echo "")
    [[ -n "$ov_sandfs" ]] || { log_error "overlay sandfs create failed: $resp"; exit 1; }

    # The overlay mount happens at execute time: this is the exact call that
    # EACCES'd in boxout mode when the exec pod lacked the sandtmpl GID.
    for i in $(seq 1 30); do
        exec_resp=$(curl -sk -X POST "$GATEWAY_URL/agent/execute" \
            -H "Authorization: Bearer $ov_agent_key" \
            -H "Content-Type: application/json" \
            -d "{\"sandfs_id\":\"$ov_sandfs\",\"code\":\"echo overlay-ok\",\"language\":\"shell\",\"timeout\":10}" 2>/dev/null || echo '')
        if echo "$exec_resp" | grep -q '"status":"done\|"status": "done"'; then
            ok=true
            break
        fi
        # Ref-resolution failure is terminal, not slow — report it with the
        # likely cause instead of burning the whole retry budget.
        if echo "$exec_resp" | grep -qi 'ref file not found'; then
            log_error "exec pod cannot resolve the overlay ref — is the sandtmpl supplemental GID 982 on the sandlot container? ($exec_resp)"
            exit 1
        fi
        sleep 2
    done
    if [[ "$ok" != "true" ]]; then
        log_error "overlay sandfs execute did not complete: ${exec_resp:0:200}"
        exit 1
    fi
    log_pass "Overlay sandfs executed (exec pod read the sandtmpl-scoped refs/)"
}

# ════════════════════════════════════════════════════════════════════
# Phase 8: affinity self-test (no LLM — the verification drill's base proof)
# ════════════════════════════════════════════════════════════════════
# Non-LLM verification of the affinity path:
#   - owner-aware DNS: the per-sandfs URL resolves (via sandswap-sandns) and,
#     after the first execute, to the OWNER gateway
#   - execute through the in-cluster path: a real microVM exec
#   - 307: with a 2nd gateway replica, a non-owner request redirects to owner

verify_affinity() {
    local sf="${SANDFS_IDS[0]}" key="${API_KEYS[0]}"
    local gw_ip dns_ip dig_out
    local fail=0

    # sandswap-sandns loads ownership via its etcd watch, which syncs
    # asynchronously after pod start — a single dig right after sandfs
    # creation races that sync. Retry briefly before declaring failure.
    dns_ip=$($KUBECTL get svc sandswap-sandns -n "$NAMESPACE" -o jsonpath='{.spec.clusterIP}')
    dig_out=""
    for _ in $(seq 1 10); do
        # || true + query bounds: dig exits non-zero on a timeout; with set -o
        # pipefail an unguarded non-zero would kill the script silently before
        # the "no answer" error below can speak.
        dig_out=$(dig "@$dns_ip" "$sf.sandfs.sandswap.local" A +short +time=2 +tries=1 2>/dev/null | head -1 || true)
        [[ -n "$dig_out" ]] && break
        sleep 3
    done
    if [[ -n "$dig_out" ]]; then
        log_pass "owner-aware DNS: $sf.sandfs.sandswap.local → $dig_out"
    else
        log_error "owner-aware DNS: no answer for $sf.sandfs.sandswap.local"
        fail=1
    fi

    # Execute through the in-cluster path (real microVM).
    gw_ip=$($KUBECTL get pod -n "$NAMESPACE" -l app=gateway -o jsonpath='{.items[0].status.podIP}')
    local exec_out
    exec_out=$(timeout 90 curl -sk --resolve "$sf.sandfs.sandswap.local:3000:$gw_ip" \
        -X POST "https://$sf.sandfs.sandswap.local:3000/agent/execute" \
        -H "Authorization: Bearer $key" -H "Content-Type: application/json" \
        -d "{\"sandfs_id\":\"$sf\",\"code\":\"echo affinity_self_test_ok\",\"language\":\"shell\"}" 2>/dev/null)
    if echo "$exec_out" | grep -q 'affinity_self_test_ok'; then
        log_pass "in-cluster execute via sandfs URL: OK"
    else
        log_error "in-cluster execute via sandfs URL FAILED: $(echo "$exec_out" | head -c 200)"
        fail=1
    fi

    # 307: if a 2nd gateway replica exists, a non-owner request must 307→owner.
    local gw_count
    gw_count=$($KUBECTL get pods -n "$NAMESPACE" -l app=gateway --no-headers 2>/dev/null | wc -l)
    if [[ "$gw_count" -ge 2 ]]; then
        local gw2_ip loc
        gw2_ip=$($KUBECTL get pod -n "$NAMESPACE" -l app=gateway -o jsonpath='{.items[1].status.podIP}')
        loc=$(timeout 30 curl -sk -o /dev/null -D - --resolve "$sf.sandfs.sandswap.local:3000:$gw2_ip" \
            -X POST "https://$sf.sandfs.sandswap.local:3000/agent/execute" \
            -H "Authorization: Bearer $key" -H "Content-Type: application/json" \
            -d "{\"sandfs_id\":\"$sf\",\"code\":\"echo x\",\"language\":\"shell\"}" 2>/dev/null | grep -i '^location:' | head -1)
        if echo "$loc" | grep -qi 'gateway-0\.\|gateway-exec'; then
            log_pass "307 redirect-to-owner: non-owner → $loc"
        else
            log_error "307 redirect-to-owner FAILED: $loc"
            fail=1
        fi
    fi

    return "$fail"
}

k8s_phase_affinity() {
    log_step "Running affinity self-test (owner-aware DNS + in-cluster execute)..."
    if verify_affinity; then
        log_pass "Affinity self-test PASSED"
    else
        log_error "Affinity self-test FAILED — see above"
        exit 1
    fi
}

# ════════════════════════════════════════════════════════════════════
# Phase 8b+9: eino 4-agent test + log analysis
# ════════════════════════════════════════════════════════════════════

k8s_phase_eino() {
    log_step "Building Eino example binary..."
    EINO_DIR="$ROOT/examples/eino-sandswap"
    EINO_BIN="$LOG_DIR/$EINO_BIN_NAME"
    cd "$EINO_DIR" || exit 1
    # Ensure go is in PATH (sudo may not preserve the user's PATH)
    export PATH="$PATH:/usr/local/go/bin"
    go build -o "$EINO_BIN" . 2>&1
    log_pass "Eino example binary built"

    log_step "Running $AGENT_COUNT-agent piped test (pool size=$POOL_SIZE, budget=${EINO_TEST_BUDGET_SECS}s, $MODE_NAME mode)..."
    echo ""

    EINO_EXIT=0
    (
        echo "1:Use the execute tool to run this shell command: echo hello_from_agent_1"
        sleep 15
        echo "2:Use the execute tool to run this shell command: echo hello_from_agent_2"
        sleep 15
        echo "3:Use the execute tool to run this shell command: echo hello_from_agent_3"
        sleep 15
        echo "4:Use the execute tool to run this shell command: echo hello_from_agent_4"
        sleep 15
        echo "1:Use the file_write tool to write the text 'agent1 marker content' to a file called agent1_marker.txt"
        sleep 15
        # Same agent reads back (write→read persistence). A different agent
        # reading this file can only fail: cross-agent volume isolation is a
        # core product guarantee (asserted as invisibility in
        # e2e/multi-agents.sh B1/C1) — the baremetal lib (bm_run_eino) and
        # verify-eino.sh use this same agent-1 form.
        echo "1:Use the file_read tool to read the file agent1_marker.txt back from the sandbox filesystem. You must call the tool, do not answer from memory."
        sleep 15
        echo "3:Use the execute tool with background=true and lease_duration=30 to start this shell command in the background: sleep 5 && echo bg_complete_marker. IMPORTANT: Do NOT call exec_status after starting the background exec. Just reply that the background task has been started and stop."
        sleep 20
        echo "4:Use the execute tool to run this shell command: echo agent4_final"
        sleep 15
        echo "exit"
    ) | timeout "$EINO_TEST_BUDGET_SECS" env \
        SANDSWAP_API_KEY_1="${API_KEYS[0]}" \
        SANDSWAP_API_KEY_2="${API_KEYS[1]}" \
        SANDSWAP_API_KEY_3="${API_KEYS[2]}" \
        SANDSWAP_API_KEY_4="${API_KEYS[3]}" \
        SANDSWAP_MCP_URL="$GATEWAY_URL/mcp" \
        SANDSWAP_CA_CERT="$ROOT/output/k8s-certs/ca.crt" \
        DEEPSEEK_API_KEY="${DEEPSEEK_API_KEY:-}" \
        DEEPSEEK_MODEL="${DEEPSEEK_MODEL:-deepseek-flash}" \
        OPENAI_API_KEY="${OPENAI_API_KEY:-}" \
        GOOGLE_API_KEY="${GOOGLE_API_KEY:-}" \
        "$EINO_BIN" 2>&1 | tee "$LOG_DIR/$EINO_LOG_NAME" || EINO_EXIT=$?

    echo ""
}

k8s_phase_analyze() {
    EINO_LOG="$LOG_DIR/$EINO_LOG_NAME"

    if [[ ! -f "$EINO_LOG" ]] || [[ ! -s "$EINO_LOG" ]]; then
        fail "Eino multi-agent log is empty or missing"
        return
    fi

    if grep -q "multi-agent ready" "$EINO_LOG"; then
        pass "Eino multi-agent started in piped mode"
    else
        fail "Eino multi-agent did not start correctly"
    fi

    TOOL_COUNT=$(grep -c "tools discovered" "$EINO_LOG" || true)
    if [[ "$TOOL_COUNT" -ge "$AGENT_COUNT" ]]; then
        pass "All agents discovered MCP tools ($TOOL_COUNT tool entries found)"
    else
        fail "Not all agents discovered MCP tools (found $TOOL_COUNT, expected >= $AGENT_COUNT)"
    fi

    local i
    for i in 1 2 3 4; do
        if grep -q "hello_from_agent_$i" "$EINO_LOG"; then
            pass "Agent $i executed shell command"
        else
            fail "Agent $i shell command not found in output"
        fi
    done

    # Write→read persistence: the marker text must appear in a file_read
    # TOOL RESULT, not just the write prompt/response echo — grepping the bare
    # marker would pass vacuously on the prompt echo alone (the prompt itself
    # contains the string). Same two-stage tolerant form as bm_analyze_eino.
    if grep -Eq "file_read[^\n]*agent1 marker content" "$EINO_LOG"; then
        pass "Agent 1 marker write + read-back confirmed"
    elif grep -q "agent1 marker content" "$EINO_LOG" && grep -q "file_read" "$EINO_LOG"; then
        pass "Agent 1 marker write + read-back confirmed (tolerant format match)"
    else
        fail "Agent 1 marker write/read-back not confirmed"
    fi

    # bg_complete_marker = the guest command's output reaching the log;
    # "background task has been started" = the model's confirmation reply.
    # Grepping the bare word "background" is satisfied by the PROMPT echo
    # itself and can never fail.
    if grep -q "bg_complete_marker" "$EINO_LOG" || grep -q "background task has been started" "$EINO_LOG"; then
        pass "Background exec was exercised"
    else
        fail "Background exec not confirmed"
    fi

    if grep -q "agent4_final" "$EINO_LOG"; then
        pass "Agent 4 executed final command (warm path)"
    else
        fail "Agent 4 final command not found"
    fi

    # ── VM reuse ────────────────────────────────────────────────────
    log_step "Checking VM reuse across agents..."
    local VM_LOGS
    VM_LOGS=$($KUBECTL logs -n "$NAMESPACE" "${VM_REUSE_LOGS[@]}" --tail=200 2>/dev/null || true)
    VM_CREATE_COUNT=$(echo "$VM_LOGS" | grep -ci "$VM_REUSE_PATTERN" || true)
    if [[ "$VM_CREATE_COUNT" -le "$POOL_SIZE" ]]; then
        pass "VM reuse confirmed: $VM_CREATE_COUNT VMs created (pool size=$POOL_SIZE)"
    else
        log_warn "VM create count ($VM_CREATE_COUNT) exceeds pool size ($POOL_SIZE) — check $SANDLOT_DS logs"
    fi

    # ── MCP path ────────────────────────────────────────────────────
    # The MCP server is stateless (MCP 2026-07-28 RC: no Mcp-Session-Id, no
    # initialize handshake required — see gateway/mcp/server.go). Tool-call
    # count in the eino log is the positive signal that the stateless MCP
    # request path served all agents.
    log_step "Checking MCP tool-call path..."
    TOOL_CALLS=$(grep -cE 'tool call|tool result|"tools/call"' "$EINO_LOG" 2>/dev/null || true)
    if [[ "$TOOL_CALLS" -ge "$AGENT_COUNT" ]]; then
        pass "MCP tool-call path served $TOOL_CALLS invocations (stateless, >= $AGENT_COUNT agents)"
    else
        log_warn "Only $TOOL_CALLS MCP tool calls observed (expected >= $AGENT_COUNT)"
    fi
}

# ════════════════════════════════════════════════════════════════════
# Phase 10: optional gateway failover test
# ════════════════════════════════════════════════════════════════════

k8s_phase_failover() {
    if [[ "$TEST_FAILOVER" != "true" ]]; then
        log_info "Failover test skipped (use --failover to enable)"
        return
    fi
    log_step "Killing one gateway pod to test failover..."

    GW_POD=$($KUBECTL get pods -n "$NAMESPACE" -l app=gateway -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
    log_info "Deleting pod $GW_POD..."
    $KUBECTL delete pod "$GW_POD" -n "$NAMESPACE" --force --grace-period=0

    sleep 10

    READY=$($KUBECTL get statefulset gateway -n "$NAMESPACE" -o jsonpath='{.status.readyReplicas}' 2>/dev/null || echo "0")
    if [[ "$READY" -ge 1 ]]; then
        pass "Gateway statefulset recovered ($READY ready pods)"
    else
        fail "Gateway statefulset not recovered after pod kill"
    fi

    # Re-point the /etc/hosts pin at the new pod.
    sleep 3
    NEW_GW_IP=$($KUBECTL get pod -n "$NAMESPACE" -l app=gateway -o jsonpath='{.items[0].status.podIP}' 2>/dev/null || echo "")
    if [[ -n "$NEW_GW_IP" ]]; then
        sed -i "/$GW_FQDN/d" /etc/hosts
        echo "$NEW_GW_IP $GW_FQDN" >> /etc/hosts
    fi

    if curl -sfk "$GATEWAY_URL/health" &>/dev/null; then
        pass "Gateway health check passes after failover"
    else
        fail "Gateway health check fails after failover"
    fi
}

# ════════════════════════════════════════════════════════════════════
# Phase 11: verification summary + honest exit
# ════════════════════════════════════════════════════════════════════

k8s_phase_summary() {
    echo ""
    echo "┌─────────────────────────────────────────────────────────┐"
    echo "│  Sandswap K8s Verification Results ($MODE_NAME mode)"
    echo "├─────────────────────────────────────────────────────────┤"
    echo "│  K8s Namespace:  $NAMESPACE"
    echo "│  VM Mode:        $MODE_DESC"
    echo "│  Gateway Pods:   $($KUBECTL get statefulset gateway -n "$NAMESPACE" -o jsonpath='{.status.readyReplicas}' 2>/dev/null || echo '?')/1"
    echo "│  Sandlot Pods:   $($KUBECTL get daemonset "$SANDLOT_DS" -n "$NAMESPACE" -o jsonpath='{.status.numberReady}' 2>/dev/null || echo '?')/$($KUBECTL get daemonset "$SANDLOT_DS" -n "$NAMESPACE" -o jsonpath='{.status.desiredNumberScheduled}' 2>/dev/null || echo '?')"
    echo "│  Human Pod:      $($KUBECTL get deployment gateway-human -n "$NAMESPACE" -o jsonpath='{.status.readyReplicas}' 2>/dev/null || echo '?')/1"
    echo "│  Agents:         $AGENT_COUNT"
    echo "│  SandFS:         $AGENT_COUNT"
    echo "│  Pool Size:      $POOL_SIZE VMs/node"
    echo "│  LLM Backend:    $LLM_BACKEND"
    echo "│  Eino Exit Code: $EINO_EXIT"
    echo "│  Test Log:       $LOG_DIR/$EINO_LOG_NAME"
    echo "└─────────────────────────────────────────────────────────┘"
    echo ""

    # FAIL_COUNT is incremented by fail()/tc_fail across all phases — an
    # honest exit code must honor it (a red log with exit 0 is how regressions
    # hide).
    if [[ "${FAIL_COUNT:-0}" -gt 0 ]]; then
        log_error "$FAIL_COUNT check(s) failed — see the [FAIL] lines above"
        exit 1
    fi
    if [[ "$EINO_EXIT" -eq 0 ]]; then
        log_pass "All tests PASSED ($MODE_NAME mode: affinity self-test + eino)"
        exit 0
    else
        log_warn "Eino test exited with code $EINO_EXIT (LLM-dependent, optional)."
        log_warn "  The affinity self-test (Phase 8) already PASSED — the affinity modifications are verified."
        log_warn "  Run eino separately with a valid LLM key to exercise the multi-agent flow."
        exit 0
    fi
}

# ════════════════════════════════════════════════════════════════════
# Keep-mode hand-over summary (default run mode)
# ════════════════════════════════════════════════════════════════════

k8s_phase_keep_summary() {
    echo ""
    echo "┌─────────────────────────────────────────────────────────┐"
    echo "│  Sandswap K8s Deployment READY ($MODE_NAME mode)"
    echo "├─────────────────────────────────────────────────────────┤"
    echo "│  K8s Namespace:  $NAMESPACE"
    echo "│  VM Mode:        $MODE_DESC"
    echo "│  Gateway Pods:   $($KUBECTL get statefulset gateway -n "$NAMESPACE" -o jsonpath='{.status.readyReplicas}' 2>/dev/null || echo '?')/1"
    echo "│  Sandlot Pods:   $($KUBECTL get daemonset "$SANDLOT_DS" -n "$NAMESPACE" -o jsonpath='{.status.numberReady}' 2>/dev/null || echo '?')/$($KUBECTL get daemonset "$SANDLOT_DS" -n "$NAMESPACE" -o jsonpath='{.status.desiredNumberScheduled}' 2>/dev/null || echo '?')"
    echo "│  Human Pod:      $($KUBECTL get deployment gateway-human -n "$NAMESPACE" -o jsonpath='{.status.readyReplicas}' 2>/dev/null || echo '?')/1"
    echo "│  LLM Backend:    $LLM_BACKEND"
    echo "├─────────────────────────────────────────────────────────┤"
    echo "│  The deployment stays RUNNING (default keep mode)."
    echo "│"
    echo "│  Management API (from this host):"
    echo "│    kubectl port-forward -n $NAMESPACE deploy/gateway-human 3100:3100"
    echo "│    → https://localhost:3100  (agent/SandFS CRUD, /health)"
    echo "│"
    echo "│  Verify the deployment:"
    echo "│    sudo env DEEPSEEK_API_KEY=sk-... bash deploy/k8s/verify-k8s.sh [--failover]"
    echo "│"
    echo "│  Remove the deployment:"
    echo "│    sudo bash deploy/k8s/k8s-cleanup.sh"
    echo "│"
    echo "│  This run's host-side access aids (human port-forward, the"
    echo "│  exec-gateway /etc/hosts pin) are reverted on exit; the CoreDNS"
    echo "│  sandfs zone and br-sandswap bridge stay until k8s-cleanup.sh."
    echo "└─────────────────────────────────────────────────────────┘"
    echo ""
    log_pass "Deployment kept running (default keep mode)"
}

# ════════════════════════════════════════════════════════════════════
# Main
# ════════════════════════════════════════════════════════════════════

k8s_deploy_main() {
    k8s_parse_flags "$@"

    # Derive the eino log name from the binary name (mode-distinct logs).
    EINO_LOG_NAME="${EINO_BIN_NAME}-test.log"
    # Sandbox failure-log containers: embedded has one container ("sandlot"),
    # boxout two ("boxout" + "sandlot").
    if [[ -z "${SANDLOT_DS_LOG_CONTAINERS:-}" ]]; then
        SANDLOT_DS_LOG_CONTAINERS="$SANDLOT_DS"
    fi

    # --failover is a drill modifier: without the drill there is nothing to fail over.
    if [[ "$TEST_FAILOVER" == "true" && "$VERIFY_MODE" != "true" ]]; then
        log_warn "--failover applies only to the --verify drill (or verify-k8s.sh) — ignoring"
        TEST_FAILOVER=false
    fi

    # Clean previous deployment FIRST (both modes), then wire the trap so a
    # crash anywhere still tears down.
    log_step "Cleaning previous deployment..."
    bash "$ROOT/deploy/k8s/k8s-cleanup.sh"
    PF_PIDS=()
    # EXIT runs cleanup on any exit path. Cleanup honors KEEP_ON_EXIT: a
    # SUCCESSFUL keep-mode run keeps the namespace (reverting only the run's
    # host-side access aids), while any failure — and every --verify drill —
    # tears the deployment fully down (a half-deployed cluster serves no one).
    # INT/TERM additionally STOP the run after cleanup (without the explicit
    # exit, bash would resume the deploy mid-phase on the freshly cleaned
    # environment).
    trap k8s_exit_trap EXIT
    trap 'KEEP_ON_EXIT=false; cleanup; exit 130' INT TERM

    k8s_preflight
    k8s_phase_build
    k8s_phase_host_prep
    k8s_phase_images
    k8s_phase_apply
    k8s_phase_stream_certs
    k8s_phase_wait_ready
    k8s_phase_security_invariants
    k8s_phase_wire_coredns
    k8s_phase_reachability
    if [[ "$VERIFY_MODE" == "true" ]]; then
        k8s_phase_agents
        k8s_phase_overlay_template
        k8s_phase_affinity
        k8s_phase_eino
        k8s_phase_analyze
        k8s_phase_failover
        k8s_phase_summary
    else
        k8s_phase_keep_summary
    fi
}

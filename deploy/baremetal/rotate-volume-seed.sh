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
# rotate-volume-seed.sh — rotate (or migrate) the volume-name seed that derives
# every sandfs volume's on-disk directory name (sandlot/provision/volname).
#
# Why rotate: the names are what keeps a compromised FUSE daemon from finding
# other tenants' directories (the share root is traversal-only, so guessing —
# not listing — is the remaining path; a rotation also REVOKES the paths an
# attacker accumulated while serving earlier tenants).
#
# The window (manual, as designed — service stops and resumes on purpose):
#   1. maintenance on     — every gateway refuses agent traffic (no restart:
#                           node streams, pools and leases all survive)
#   2. wait for the drain — mounts released everywhere
#   3. stage              — mint the next seed into the prov config
#   4. run                — rename every volume + update its record
#   5. promote            — next becomes current; the config's staged key clears
#   6. maintenance off    — service resumes
#
# Usage (run on a PROV host; it needs the volumes tree and the prov config):
#   rotate-volume-seed.sh --prov-config /etc/sandswap/sandlot-prov.yaml \
#                         --human-url https://localhost:3100 [--human-token TOKEN] \
#                         --template-tool output/template-tool \
#                         --maintenance on|off|status   --rotation on|off|status
#   (multi-prov fleets: add --prov-hosts h1,h2[,h3] to --stage/--promote; the
#    fan-out covers EXACTLY the listed hosts — list this host explicitly when
#    it runs a prov instance. The window may only close once EVERY instance
#    reports the promoted generation, which --rotation off / --maintenance off
#    verify — a laggard would keep naming volumes in the retired generation)
#   (--remote-script / --remote-prov-config / --remote-template-tool override
#    the remote paths when a prov host differs from this one)
#   rotate-volume-seed.sh ... --stage      # mint + install the next seed, add
#                          #               volume_seed_next_file to the config
#                          #               (--seed-file PATH to install your own)
#   rotate-volume-seed.sh ... --run        # rename to the STAGED seed + update records
#   rotate-volume-seed.sh ... --promote    # staged seed becomes current
#   rotate-volume-seed.sh ... --migrate    # one-time: legacy <id> names -> derived names (no staging)
#   rotate-volume-seed.sh ... --status     # config vs running instance vs disk, side by side
#   (--state-file PATH overrides the adoption record's location;
#    SANDSWAP_SEED_STATE_FILE does the same via the environment)
#
# Everything is idempotent and resumable: --run skips volumes already renamed
# (source gone, target present) and --migrate uses the same code path.
#
# Where the seed comes from does not matter to this tool: the config names a
# generation's source (an inline value, or a FILE that any injector — a Vault
# agent, an External Secrets Operator, a systemd credential, a plain script —
# can materialize). What matters is that the pointer only ever moves through
# stage → run → promote, and that EVERY step is verified against the running
# instance's adoption record rather than against a log line or a sleep.
# A new generation therefore lands at a NEW path: never rewrite the file the
# current generation points at, and never delete a generation file (re-staging
# the same file is the supported way to recover an aborted window).
#
# --status prints the three views side by side (config / running instance /
# disk); run it before opening a window and after closing one.
#
# Seed-file scope: --stage installs the next seed with the SAME owner/mode as
# the current seed file (falling back to the prov config's owner, mode 0640) —
# whatever identity runs the prov instance must be able to READ it (the reload
# leg reads it as the service user; an unreadable staged file is silently
# refused by the live namer), while the sandvmm identity must not. The minted
# seed is scoped root:sandprov (the DEDICATED provision group) by
# sandswap_ensure_volume_seed, so following the current file's scope keeps the
# staged generation on that group even in the merged shape.
set -euo pipefail

PROV_CONFIG="/etc/sandswap/sandlot-prov.yaml"
HUMAN_URL="https://localhost:3100"
HUMAN_TOKEN="${HUMAN_TOKEN:-}"
TEMPLATE_TOOL=""
ACTION=""
STAGE_SEED_FILE=""
# The running prov instance's adoption record (seed coordinator). Every step
# that MOVES volumes asserts against it: the config naming a generation is not
# the same as the running process having adopted it, and the gap is exactly
# where a rotation goes wrong.
STATE_FILE="${SANDSWAP_SEED_STATE_FILE:-/run/sandswap/volume-seed-state.json}"
# Multi-instance fleets: every prov host must apply the same stage/promote, and
# the window may only close once EVERY instance reports the retired generation
# (storage ops are spread across prov instances — one straggler splits tenants).
PROV_HOSTS="${SANDSWAP_PROV_HOSTS:-}"
REMOTE_PROV_CONFIG=""
REMOTE_TEMPLATE_TOOL=""
REMOTE_SCRIPT=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --prov-config) PROV_CONFIG="$2"; shift 2 ;;
        --human-url) HUMAN_URL="$2"; shift 2 ;;
        --human-token) HUMAN_TOKEN="$2"; shift 2 ;;
        --template-tool) TEMPLATE_TOOL="$2"; shift 2 ;;
        --maintenance) ACTION="maintenance:$2"; shift 2 ;;
        --stage) ACTION="stage"; shift ;;
        --seed-file) STAGE_SEED_FILE="$2"; shift 2 ;;
        --run) ACTION="run"; shift ;;
        --promote) ACTION="promote"; shift ;;
        --migrate) ACTION="migrate"; shift ;;
        --status) ACTION="status"; shift ;;
        --state-file) STATE_FILE="$2"; shift 2 ;;
        --rotation) ACTION="rotation:$2"; shift 2 ;;
        --prov-hosts) PROV_HOSTS="$2"; shift 2 ;;
        --remote-prov-config) REMOTE_PROV_CONFIG="$2"; shift 2 ;;
        --remote-template-tool) REMOTE_TEMPLATE_TOOL="$2"; shift 2 ;;
        --remote-script) REMOTE_SCRIPT="$2"; shift 2 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

log()  { echo "[rotate-seed] $*"; }
fail() { echo "[rotate-seed] ERROR: $*" >&2; exit 1; }

[[ -n "$ACTION" ]] || fail "pick an action: --maintenance on|off|status | --run | --promote | --migrate"
[[ -f "$PROV_CONFIG" ]] || fail "prov config not found: $PROV_CONFIG"
[[ -n "$TEMPLATE_TOOL" && -x "$TEMPLATE_TOOL" ]] || fail "--template-tool must point at the built template-tool binary"
command -v python3 >/dev/null || fail "python3 is required"

human_get() { # path
    local args=(-sk -m 20 "$HUMAN_URL$1")
    [[ -n "$HUMAN_TOKEN" ]] && args+=(-H "Authorization: Bearer $HUMAN_TOKEN")
    curl "${args[@]}"
}

# state_field FIELD -> the running instance's adoption record value, or empty.
# Booleans render as true/false; a missing record also renders empty (the
# caller decides whether that is fatal).
state_field() {
    [[ -f "$STATE_FILE" ]] || return 0
    python3 - "$STATE_FILE" "$1" <<'PY'
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception:
    sys.exit(0)
v = d.get(sys.argv[2])
if v is None:
    print("")
elif isinstance(v, bool):
    print("true" if v else "false")
elif isinstance(v, (list, dict)):
    print(json.dumps(v))
else:
    print(v)
PY
}

# wait_for_state FIELD WANT TIMEOUT_SEC DESCRIPTION -> 0 when the running
# instance's record reaches WANT. The reload leg is asynchronous (fsnotify
# debounce on bare metal, ~1min kubelet sync on k8s), so every step that
# depends on the instance having moved waits for the RECORD, never for a sleep
# and never for a journal grep.
wait_for_state() {
    local field="$1" want="$2" timeout="$3" what="${4:-the running instance to adopt the change}" deadline got
    deadline=$(( $(date +%s) + timeout ))
    while :; do
        got="$(state_field "$field")"
        [[ "$got" == "$want" ]] && return 0
        if [[ "$(date +%s)" -ge "$deadline" ]]; then
            log "still waiting for $what ($field='$got', want '$want')"
            return 1
        fi
        sleep 0.3
    done
}

# config_generation_fingerprint current|next -> the generation's non-secret
# fingerprint, resolved through the same loader the daemon uses.
config_generation_fingerprint() {
    "$TEMPLATE_TOOL" volume-name --prov-config "$PROV_CONFIG" --generation "$1" --fingerprint
}

# run_remote HOST [args...] — apply this same script on a prov host over ssh.
# The remote paths default to the local ones (same layout fleet-wide); override
# with --remote-* when a host differs. Every remote step keeps its own
# adoption assertion — the fan-out never trusts the local host's view.
run_remote() {
    local host="$1"; shift
    local script="${REMOTE_SCRIPT:-$0}"
    local args=(--prov-config "${REMOTE_PROV_CONFIG:-$PROV_CONFIG}"
                --template-tool "${REMOTE_TEMPLATE_TOOL:-$TEMPLATE_TOOL}")
    [[ -n "$HUMAN_URL" ]] && args+=(--human-url "$HUMAN_URL")
    [[ -n "$HUMAN_TOKEN" ]] && args+=(--human-token "$HUMAN_TOKEN")
    ssh -o BatchMode=yes "$host" "$script" "${args[@]}" "$@"
}

# run_remote_cmd HOST cmd... — one plumbing command on a prov host (mktemp /
# install / rm for the seed transfer). Not the rotation script itself; that is
# run_remote's job.
run_remote_cmd() {
    local host="$1"; shift
    ssh -o BatchMode=yes "$host" "$@"
}

# fanout_local_note ACTION — --prov-hosts covers EXACTLY the listed hosts; the
# host running this tool is NOT implied. Say so explicitly: a local prov
# instance silently left on the retired generation keeps naming volumes in it,
# and the close-window gate then refuses with it as the laggard.
fanout_local_note() {
    log "note: $1 covers exactly the hosts in --prov-hosts — the host running this tool ($(hostname)) is included only if it is listed there"
}

# fleet_seeds -> one line per prov instance, straight from the human gateway's
# /stats prov_seeds projection (each instance's heartbeat carries its naming
# generations; fingerprints only).
fleet_seeds() {
    human_get /stats | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(0)
for s in d.get("prov_seeds") or []:
    print("  %s: generation=%s staged=%s staged_generation=%s age=%ss" % (
        s.get("node_id"), s.get("generation") or "<none>",
        bool(s.get("staged")), s.get("staged_generation") or "-", s.get("age_sec")))'
}

# fleet_converged EXPECTED_FP -> 0 when every reporting prov instance is on
# EXPECTED_FP with nothing staged.
#   1 = at least one laggard (printed to stderr)
#   2 = NO instance reported a generation at all (nothing to verify: an older
#       sandlot binary, or the storage plane is not connected)
# The distinction is the point: "known to disagree" must block closing the
# window, while "cannot tell" must not — a rolling upgrade would otherwise be
# unable to leave maintenance.
fleet_converged() {
    local want="$1"
    human_get /stats | python3 -c '
import json, sys
want = sys.argv[1]
d = json.load(sys.stdin)
seeds = d.get("prov_seeds") or []
if not seeds:
    sys.exit(2)
bad = [s for s in seeds if (s.get("generation") or "") != want or s.get("staged")]
for s in bad:
    print("  laggard: node=%s generation=%s staged=%s age=%ss" % (
        s.get("node_id"), s.get("generation") or "<none>",
        bool(s.get("staged")), s.get("age_sec")), file=sys.stderr)
sys.exit(1 if bad else 0)
' "$want"
}

# close_window_gate — run before turning the window off. Refuses on a KNOWN
# disagreement; warns (and proceeds) when no instance reports a generation.
close_window_gate() {
    local fp rc deadline
    fp="$(config_generation_fingerprint current)" || return 0  # no seed configured: nothing to verify
    # The fleet view is HEARTBEAT-driven (each instance reports its generations
    # every ~30s), so a pointer that moved seconds ago is not yet visible.
    # Wait for convergence with a bounded retry; only a persistent
    # disagreement blocks the close.
    deadline=$(( $(date +%s) + 45 ))
    while :; do
        set +e
        fleet_converged "$fp"
        rc=$?
        set -e
        [[ "$rc" == 0 || "$(date +%s)" -ge "$deadline" ]] && break
        log "waiting for the prov fleet to report $fp (the fleet view lags a heartbeat)…"
        sleep 3
    done
    case "$rc" in
        0) log "fleet converged: every connected prov instance derives names from $fp" ;;
        1) fail "the prov fleet has NOT converged on $fp (see the laggards above) — closing the window now would leave those instances naming volumes in the retired generation. Apply the same stage/promote on every prov host (--prov-hosts), then retry." ;;
        2) log "WARNING: no prov instance reported a naming generation in /stats (older binary, or the storage plane is not connected) — closing the window without a convergence proof" ;;
    esac
}
# human_post PATH BODY -> the response body on stdout for a 2xx response.
# Anything else prints the status + body to stderr and returns non-zero: a
# REFUSED update (400 validation, 404 record gone, 5xx store error) must be a
# failure — curl without a status check exits 0 for every HTTP response, so a
# refusal would otherwise be reported as a successful switch (the record left
# naming a retired path while the window closes).
human_post() { # path body
    local args=(-sk -m 60 -X POST "$HUMAN_URL$1" -H "Content-Type: application/json" -d "$2" -w $'\n%{http_code}')
    [[ -n "$HUMAN_TOKEN" ]] && args+=(-H "Authorization: Bearer $HUMAN_TOKEN")
    local out code
    out="$(curl "${args[@]}")" || return 1
    code="${out##*$'\n'}"
    if [[ ! "$code" =~ ^2 ]]; then
        printf '[rotate-seed] ERROR: POST %s answered HTTP %s: %s\n' "$1" "$code" "${out%$'\n'*}" >&2
        return 1
    fi
    printf '%s\n' "${out%$'\n'*}"
}

seed_file() { # current|next -> path (or empty when inline/absent)
    python3 - "$PROV_CONFIG" "$1" <<'PY'
import sys, os
path, which = sys.argv[1], sys.argv[2]
key = "volume_seed_file" if which == "current" else "volume_seed_next_file"
inline = "volume_seed" if which == "current" else "volume_seed_next"
want = inline
for line in open(path):
    line = line.split("#", 1)[0].strip()
    if line.startswith(key + ":"):
        want = key
        v = line.split(":", 1)[1].strip().strip('"')
        print(v if os.path.isabs(v) else os.path.join(os.path.dirname(path), v))
        break
    if line.startswith(inline + ":") and line.split(":", 1)[1].strip():
        want = inline
if want == inline:
    print("")
PY
}

vol_root() { # the volumes root, from the same config
    python3 - "$PROV_CONFIG" <<'PY'
import sys
for line in open(sys.argv[1]):
    line = line.split("#", 1)[0].strip()
    if line.startswith("volumes_dir:"):
        print(line.split(":", 1)[1].strip().strip('"'))
        break
PY
}

# canonical PATH -> the path with symlinks and ".." resolved (falls back to the
# literal path where readlink -f cannot run). Used to decide whether two
# spellings name the SAME file.
canonical() {
    readlink -f "$1" 2>/dev/null || printf '%s\n' "$1"
}

case "$ACTION" in
stage)
    # Multi-host fleets: ONE staged generation, applied on every prov host.
    # Minting per host would stage a different generation on each — the rename
    # would then move different volumes in different directions.
    if [[ -n "$PROV_HOSTS" ]]; then
        [[ -n "$STAGE_SEED_FILE" ]] || fail "with --prov-hosts, --stage requires --seed-file: every prov host must install the SAME staged generation (mint once, distribute, then stage)"
        [[ -s "$STAGE_SEED_FILE" ]] || fail "--seed-file $STAGE_SEED_FILE is empty or missing"
        fanout_local_note "this --stage fan-out"
        # The transfer file carries the fleet seed: it lands under a remote
        # mktemp (never a predictable name another local user could squat or
        # read) and is removed on EVERY exit path. The generation file the
        # remote config ends up naming is a SECOND mktemp, created in the prov
        # config's own directory — never /tmp: after --promote that path is the
        # live generation every volume name derives from, so it must sit on
        # the same root-only, non-volatile filesystem as the local default.
        host=""
        remote_tmp=""
        cleanup_remote_tmp() {
            [[ -n "$remote_tmp" && -n "$host" ]] || return 0
            run_remote_cmd "$host" rm -f "$remote_tmp" >/dev/null 2>&1 || true
        }
        trap 'cleanup_remote_tmp' EXIT
        trap 'cleanup_remote_tmp; exit 130' INT TERM
        for host in $(echo "$PROV_HOSTS" | tr ',' ' '); do
            [[ -n "$host" ]] || continue
            log "staging on $host…"
            remote_tmp="$(run_remote_cmd "$host" mktemp /tmp/sandswap-seed-stage.XXXXXX)" \
                || { remote_tmp=""; fail "cannot create a transfer path on $host"; }
            local_remote_cfg="${REMOTE_PROV_CONFIG:-$PROV_CONFIG}"
            remote_final="$(run_remote_cmd "$host" mktemp -p "$(dirname "$local_remote_cfg")" volume-seed-next.XXXXXX)" \
                || fail "cannot create the generation file on $host (is $(dirname "$local_remote_cfg") writable there?)"
            scp -q -o BatchMode=yes "$STAGE_SEED_FILE" "$host:$remote_tmp" \
                || fail "copying the staged seed to $host failed"
            run_remote_cmd "$host" install -m 0640 "$remote_tmp" "$remote_final" \
                || fail "installing the staged generation on $host failed"
            run_remote_cmd "$host" rm -f "$remote_tmp" || true
            remote_tmp=""
            # --seed-file POINTS the remote config at $remote_final (an
            # injected generation file at its final path is never copied onto
            # itself) — the same contract the single-host path keeps.
            run_remote "$host" --stage --seed-file "$remote_final" \
                || fail "staging on $host failed (the generation file stays at $remote_final there — remove it deliberately if you re-stage)"
        done
        trap - EXIT INT TERM
        log "staged (and adoption-verified) on every host in --prov-hosts"
        exit 0
    fi
    # Mint (or install) the next seed and add volume_seed_next_file to the
    # prov config. The prov instance hot-reloads it within ~200ms; the staged
    # generation freezes creation until promoted.
    if python3 - "$PROV_CONFIG" <<'PY'
import sys, re
sys.exit(0 if re.search(r'^\s*volume_seed_next(_file)?\s*:', open(sys.argv[1]).read(), re.M) else 1)
PY
    then
        fail "a staged seed already exists — promote or remove volume_seed_next[_file] first"
    fi
    # The default target carries the generation's own identity
    # (volume-seed-next-<UTC>-<pid>): a bare volume-seed-next would be exactly
    # the path the PREVIOUS promote re-pointed volume_seed_file at, so the
    # second rotation would rewrite the file the LIVE generation reads — the
    # one thing the channel contract forbids (the instance refuses the change
    # as tampering, and a restart then refuses to start).
    next_file="${STAGE_SEED_FILE:-$(dirname "$PROV_CONFIG")/volume-seed-next-$(date -u +%Y%m%dT%H%M%SZ)-$$}"
    if [[ -n "$STAGE_SEED_FILE" ]]; then
        [[ -s "$STAGE_SEED_FILE" ]] || fail "--seed-file $STAGE_SEED_FILE is empty or missing"
        [[ "$STAGE_SEED_FILE" == /* ]] || fail "--seed-file must be absolute (the config references it by path)"
    fi
    # Hard refusal BEFORE anything is written: the current generation's file is
    # read by the running instance's live namer, and every existing volume name
    # derives from it. Rewriting it is never a rotation.
    cur_file="$(seed_file current)"
    if [[ -n "$cur_file" && "$(canonical "$next_file")" == "$(canonical "$cur_file")" ]]; then
        fail "refusing to write $next_file: the CURRENT generation points at it (the running instance would classify the rewrite as tampering and a restart would refuse to start). A rotation always lands at a NEW path — pass a different --seed-file, or drop --seed-file to mint."
    fi
    if [[ -n "$STAGE_SEED_FILE" ]]; then
        # An INJECTED generation file (a tmpfs channel's gen-N, a credential)
        # already sits at its final path: installing it onto itself fails, and
        # copying it elsewhere would defeat the "one file per generation"
        # contract. Point the config at it instead — the scoping/presence
        # checks below still apply.
        if [[ "$STAGE_SEED_FILE" != "$next_file" ]]; then
            install -m 0640 "$STAGE_SEED_FILE" "$next_file"
        fi
    else
        "$TEMPLATE_TOOL" seed-generate --out "$next_file"
    fi
    # Scope like the CURRENT seed (the running prov identity must read it on
    # reload; the sandvmm identity must not). Fall back to the config's owner.
    ref="$(seed_file current)"
    [[ -n "$ref" && -f "$ref" ]] || ref="$PROV_CONFIG"
    chown --reference="$ref" "$next_file" 2>/dev/null || true
    chmod 0640 "$next_file"
    python3 - "$PROV_CONFIG" "$next_file" <<'PY'
import sys, re, os, tempfile

def write_atomic(path, text):
    # Atomic AND identity-preserving: truncate-then-write could leave a
    # HALF-WRITTEN config (the daemon re-reads it within its 200ms debounce),
    # and mkstemp is 0600 root — so the target's mode/owner must be carried
    # over, or a rename silently locks the service identity out of its own
    # config.
    d = os.path.dirname(os.path.abspath(path)) or "."
    try:
        st = os.stat(path)
        mode, uid, gid = st.st_mode & 0o7777, st.st_uid, st.st_gid
    except FileNotFoundError:
        mode, uid, gid = 0o600, -1, -1
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".rotate-seed.")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
        if uid >= 0:
            try:
                os.chown(tmp, uid, gid)
            except PermissionError:
                pass
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise

path, next_file = sys.argv[1], sys.argv[2]
src = open(path).read().splitlines()
out, at = [], None
for line in src:
    out.append(line)
    if re.match(r'\s*volume_seed(_file)?\s*:', line):
        at = len(out)  # insert right after the current-generation key
if at is None:
    # no current-generation key in the file: put it inside provision:, or
    # append a provision block (the tool runs on a prov config).
    for i, line in enumerate(out):
        if re.match(r'^provision\s*:\s*$', line):
            at = i + 1
            break
if at is None:
    out += ["provision:", f"  volume_seed_next_file: {next_file}"]
else:
    out.insert(at, f"  volume_seed_next_file: {next_file}")
write_atomic(path, "\n".join(out) + "\n")
print(f"[rotate-seed] staged next generation: {next_file}")
PY
    # The window is only OPEN once the RUNNING instance has adopted the staged
    # generation (creation frozen). The file naming it is not enough: a staged
    # source the instance cannot read is silently ignored by design.
    fp_next="$(config_generation_fingerprint next)" \
        || fail "cannot resolve the staged generation from $PROV_CONFIG"
    if ! wait_for_state staged_fingerprint "$fp_next" 20; then
        fail "the running prov instance has NOT adopted the staged generation (fingerprint $fp_next) — creation is NOT frozen yet. Check that the instance can read the staged source and look for its \"volume seed generations updated\" line; do not start --run until it has."
    fi
    log "staged AND adopted by the running instance (fingerprint $fp_next; creation is frozen until promote)"
    ;;
maintenance:on)
    human_post /human/maintenance '{"on":true,"reason":"volume seed rotation"}' > /dev/null \
        || fail "the gateway refused the maintenance switch (see the HTTP status above) — agents are NOT being refused, do not proceed with the rotation"
    log "maintenance ON — agent traffic is refused cluster-wide"
    ;;
maintenance:off)
    # Refuse to resume service while the prov fleet is KNOWN to disagree about
    # the naming generation: an instance still on the retired generation names
    # volumes that every other instance (and every record) can no longer
    # resolve — delete answers false success, create builds a second tree.
    close_window_gate
    human_post /human/maintenance '{"on":false}' > /dev/null \
        || fail "the gateway refused to resume service (see the HTTP status above) — the fleet is STILL refusing agent traffic"
    log "maintenance OFF — agent traffic resumed"
    ;;
rotation:on)
    human_post /human/rotation '{"on":true,"reason":"volume seed rotation"}' > /dev/null \
        || fail "the gateway refused to open the rotation window (see the HTTP status above) — creating a sandfs is NOT frozen"
    log "rotation window OPEN — creating a sandfs is refused fleet-wide until --rotation off"
    ;;
rotation:off)
    close_window_gate
    human_post /human/rotation '{"on":false}' > /dev/null \
        || fail "the gateway refused to close the rotation window (see the HTTP status above) — sandfs creation is still frozen fleet-wide"
    log "rotation window CLOSED — sandfs creation resumed"
    ;;
rotation:status)
    human_get /stats | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d.get("rotation") or {"freezing_creation": False})'
    echo "prov fleet naming generations:"
    fleet_seeds
    ;;
maintenance:status)
    human_get /stats | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d.get("maintenance") or {"refusing": False})'
    ;;
run|migrate)
    VOL_ROOT="$(vol_root)"
    [[ -d "$VOL_ROOT" ]] || fail "volumes root not found: $VOL_ROOT"
    GENERATION=next
    [[ "$ACTION" == "migrate" ]] && GENERATION=current
    # Guard: never rename anything unless the fleet is refusing agent traffic.
    if ! human_get /stats | python3 -c 'import sys,json; sys.exit(0 if (json.load(sys.stdin).get("maintenance") or {}).get("refusing") else 1)'; then
        fail "the fleet is NOT in maintenance — run --maintenance on first (the window is manual by design)"
    fi
    # Guard: the staged seed must exist before anything moves.
    if [[ "$GENERATION" == "next" ]] && [[ -z "$(seed_file next)" ]]; then
        # inline staged seed: probe by deriving a name and seeing it differ
        if ! "$TEMPLATE_TOOL" volume-name --prov-config "$PROV_CONFIG" --id probe --generation next >/dev/null 2>&1; then
            fail "no seed is staged (set provision.volume_seed_next[_file] and reload the prov instance)"
        fi
    fi
    # The config naming a staged generation is not the same as the running
    # instance having adopted it (200ms debounce on bare metal, ~1min kubelet
    # sync on k8s). Renaming inside that gap moves volumes the live namer still
    # resolves by the OLD name — the split this tool exists to prevent.
    if [[ "$GENERATION" == "next" ]]; then
        fp_next="$(config_generation_fingerprint next)" \
            || fail "cannot resolve the staged generation from $PROV_CONFIG"
        if [[ "$(state_field staged)" != "true" || "$(state_field staged_fingerprint)" != "$fp_next" ]]; then
            fail "the running prov instance has not adopted the staged generation (record: staged=$(state_field staged) fp=$(state_field staged_fingerprint), want $fp_next) — wait for adoption before renaming (record: $STATE_FILE)"
        fi
        log "live adoption verified: the running instance is staged on $fp_next"
    fi
    log "listing records…"
    # Cursor-paginated: /human/sandfs caps one page at limit=1000, and a
    # fleet-scale rotation must cover every record, not the first page.
    list_ids() {
        local cursor="" page ids
        while :; do
            page="$(human_get "/human/sandfs?limit=1000${cursor:+&cursor=$cursor}")"
            ids="$(printf '%s' "$page" | python3 -c '
import sys, json
d = json.load(sys.stdin)
for it in d.get("items", []):
    print(it.get("sandfs_id") or it.get("id"))')" || fail "record listing is not JSON: ${page:0:120}"
            printf '%s\n' "$ids"
            cursor="$(printf '%s' "$page" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("next_cursor") or "")')"
            [[ -n "$cursor" ]] || break
        done
    }
    IDS="$(list_ids)"
    total=0; moved=0; skipped=0; failed=0
    for id in $IDS; do
        total=$((total+1))
        rec="$(human_get "/human/sandfs/$id")"
        from="$(printf '%s' "$rec" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("rootfs_path",""))')"
        [[ -n "$from" ]] || { log "SKIP $id (no rootfs_path)"; skipped=$((skipped+1)); continue; }
        name="$("$TEMPLATE_TOOL" volume-name --prov-config "$PROV_CONFIG" --id "$id" --generation "$GENERATION")" \
            || { log "SKIP $id (cannot derive target name)"; failed=$((failed+1)); continue; }
        to="$(dirname "$from")/$name"
        if [[ "$from" == "$to" ]]; then
            skipped=$((skipped+1)); continue
        fi
        # The volume identity stamp is the authority on WHICH sandfs a
        # directory belongs to (the name is derived and cannot be verified by
        # inspection). Refuse to move a directory that is stamped for another
        # id: that is the seed-mix-up / botched-restore signature.
        # Read the stamp ONLY through the hardened tool: in flat mode the file
        # sits in the tenant's chroot, where grep/redirection FOLLOW a planted
        # symlink (a root-run arbitrary host-file read/write). The tool refuses
        # symlinks/FIFOs/oversize entries instead.
        stamped="$("$TEMPLATE_TOOL" volume-stamp-read --volume "$from" --field sandfs_id 2>/dev/null)" \
            || { log "FAIL $id: $from/.sandfs-id is unreadable or unsafe (planted symlink/FIFO/oversize?) — NOT touching it"; failed=$((failed+1)); continue; }
        if [[ -n "$stamped" ]]; then
            if [[ "$stamped" != "$id" ]]; then
                log "FAIL $id: $from is stamped for $stamped — NOT touching it (inspect the seed generations)"
                failed=$((failed+1)); continue
            fi
        elif [[ "$ACTION" == "migrate" ]]; then
            : # pre-stamp volume: the migration is what introduces the stamp
        elif [[ -d "$to" && ! -d "$from" ]]; then
            : # already rotated: the re-stamp below repairs a half-finished run
        else
            log "FAIL $id: $from carries no .sandfs-id stamp — run --migrate first"
            failed=$((failed+1)); continue
        fi
        if [[ -d "$to" && ! -d "$from" ]]; then
            log "already rotated: $id -> $(basename "$to") — re-stamp and record update still run (a previous run may have died between the rename and the re-stamp)"
        elif [[ -d "$from" ]]; then
            # Overlay volumes have a live mount at <vol>/rootfs; renaming a
            # directory that contains a mount point fails with EBUSY, so the
            # drain (which the maintenance window triggers) must have released
            # it. Report rather than force.
            if ! mv -T "$from" "$to" 2>/dev/null; then
                log "FAIL $id: rename $from -> $to refused (still mounted? drain first)"; failed=$((failed+1)); continue
            fi
        else
            log "FAIL $id: neither $from nor $to exists"; failed=$((failed+1)); continue
        fi
        # NOTE: both the moved and the already-rotated branches fall through
        # to the re-stamp + record update below (original behavior, kept):
        # this is what repairs a previous run that died between the rename and
        # the re-stamp — and the promote gate added below keys on exactly that
        # stamp, so the fall-through is what lets a re-run unblock promotion.
        # Re-stamp: the id binding is unchanged, but the generation fingerprint
        # must follow the name (that is how a later op can tell which
        # generation a directory's name belongs to). created_unix carries the
        # volume's ORIGIN — the rename is not a new birth, so the old stamp's
        # value survives when present.
        # Re-sign through the tool: CreateTemp (O_EXCL) + rename, so a planted
        # symlink at any stamp/temp name is replaced, never followed — the old
        # shell-redirection form truncated an arbitrary HOST file as root. The
        # tool preserves mode/created from the existing stamp only when that
        # stamp's signature verifies (a tenant-chosen value is never re-signed
        # into authority) and binds the new generation.
        "$TEMPLATE_TOOL" volume-stamp-write --prov-config "$PROV_CONFIG" --volume "$to" --id "$id" --generation "$GENERATION" \
            --previous-name "$(basename "$from")" \
            || { log "FAIL $id: renamed but could not re-stamp ($to)"; failed=$((failed+1)); continue; }
        if ! human_post "/human/sandfs/$id/rootfs-path" "{\"rootfs_path\":\"$to\"}" >/dev/null; then
            log "FAIL $id: record update refused (volume is at $(basename "$to"))"; failed=$((failed+1)); continue
        fi
        moved=$((moved+1))
    done
    log "action=$ACTION total=$total moved=$moved skipped=$skipped failed=$failed"
    if [[ "$failed" -gt 0 ]]; then
        fail "$failed volume(s) need attention — re-run after fixing (idempotent)"
    fi
    # The staged generation must not have moved while the tree was being
    # renamed: a mid-run swap renames toward a generation the promote gate
    # cannot see, leaving a mixed tree that promotes cleanly and resolves
    # nothing.
    if [[ "$GENERATION" == "next" ]]; then
        fp_after="$(config_generation_fingerprint next)" \
            || fail "cannot re-resolve the staged generation — do NOT promote; inspect $PROV_CONFIG"
        if [[ "$fp_after" != "$fp_next" ]]; then
            fail "the staged generation CHANGED during the run ($fp_next -> $fp_after): some volumes are now named for the old staged generation. Do NOT promote — abort (clear volume_seed_next), re-stage deliberately and re-run (idempotent)."
        fi
    fi
    # Anything created during the window would not be in the list above.
    left="$(list_ids | grep -c . || true)"
    [[ "$left" == "$total" ]] || log "WARNING: record count changed during the run ($total -> $left); re-run --run to cover the new records"
    ;;
promote)
    # Multi-host fleets: the pointer must move on EVERY prov host. A host left
    # behind keeps resolving names from the retired generation while every
    # record points at the new ones — delete answers false success there and
    # create builds a second tree.
    if [[ -n "$PROV_HOSTS" ]]; then
        fanout_local_note "this --promote fan-out"
        for host in $(echo "$PROV_HOSTS" | tr ',' ' '); do
            [[ -n "$host" ]] || continue
            log "promoting on $host…"
            run_remote "$host" --promote || fail "promotion on $host failed"
        done
        log "promoted (and adoption-verified) on every host in --prov-hosts"
        log "now close the window: --rotation off   (it refuses until every instance reports convergence)"
        exit 0
    fi
    # Guard: the window must still be open — promotion is applied while the
    # fleet refuses agent traffic, exactly like --run.
    if ! human_get /stats | python3 -c 'import sys,json; sys.exit(0 if (json.load(sys.stdin).get("maintenance") or {}).get("refusing") else 1)'; then
        fail "the fleet is NOT in maintenance — run --maintenance on first (the window is manual by design)"
    fi
    # COMPLETENESS GATE: promotion drops the old generation, so every volume
    # still carrying it (or carrying no usable stamp at all) becomes
    # permanently unresolvable — the identity stamp cannot rescue it (it lives
    # INSIDE the directory the new generation can no longer derive): delete
    # answers false success, create builds a second tree for the tenant. This
    # is the SAME reading the prov instance takes before it applies the
    # transition (one implementation, two enforcement points: here for the
    # operator's pre-flight, there for the daemon).
    if ! "$TEMPLATE_TOOL" seed-scan --prov-config "$PROV_CONFIG"; then
        fail "refuse to promote: the completeness gate did not pass (see the scan above). Complete --run (and --migrate for the unstamped) first."
    fi
    # next becomes current. Two shapes, and the rewrite must leave the config
    # with EXACTLY ONE current-generation key (volume_seed and volume_seed_file
    # together are refused at load):
    #   staged via FILE and current via FILE  -> re-point volume_seed_file at
    #     the staged file (each generation keeps its own file; pointing the
    #     key back is the rollback) and drop the staged keys;
    #   staged via FILE, current inline       -> write the staged content into
    #     the inline key and drop the staged keys;
    #   staged inline                          -> swap the two inline keys.
    # The prov instance hot-reloads the file.
    staged_file="$(seed_file next)"
    if [[ -n "$staged_file" ]]; then
        [[ -s "$staged_file" ]] || fail "staged seed file $staged_file is empty"
        # the seed is read by python FROM the file, never passed as
        # argv — /proc/<pid>/cmdline is world-readable (an unprivileged local
        # user read the fleet seed from the old form; the project's own docs
        # call out exactly this pattern for registry credentials).
        python3 - "$PROV_CONFIG" "$staged_file" <<'PY'
import sys, re, os, tempfile

def write_atomic(path, text):
    # Atomic AND identity-preserving: mkstemp is 0600 root, so the target's
    # mode/owner must be carried over — the daemon reads this config as a
    # service identity (root:<service group> 0640), and a rename that silently
    # "fixed" the mode would lock it out of its own config.
    d = os.path.dirname(os.path.abspath(path)) or "."
    try:
        st = os.stat(path)
        mode, uid, gid = st.st_mode & 0o7777, st.st_uid, st.st_gid
    except FileNotFoundError:
        mode, uid, gid = 0o600, -1, -1
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".rotate-seed.")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
        if uid >= 0:
            try:
                os.chown(tmp, uid, gid)
            except PermissionError:
                pass
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise

path, staged_file = sys.argv[1], sys.argv[2]
seed = open(staged_file).read().strip()
src = open(path).read().splitlines()
out, pointed, inlined, cleared = [], False, False, False
for line in src:
    if re.match(r'\s*volume_seed_file\s*:', line):
        out.append(re.sub(r'(\s*volume_seed_file\s*:\s*).*$', rf'\g<1>{staged_file}', line))
        pointed = True
    elif re.match(r'\s*volume_seed\s*:', line):
        out.append(re.sub(r'(\s*volume_seed\s*:\s*).*$', rf'\g<1>{seed}', line))
        inlined = True
    elif re.match(r'\s*volume_seed_next\s*:', line) or re.match(r'\s*volume_seed_next_file\s*:', line):
        cleared = True
    else:
        out.append(line)
if pointed and inlined:
    sys.exit("ERROR: config has both volume_seed and volume_seed_file — fix the config first")
if not pointed and not inlined:
    out.append(f"volume_seed: {seed}")
write_atomic(path, "\n".join(out) + "\n")
shape = "re-pointed volume_seed_file" if pointed else "wrote inline volume_seed"
print(f"[rotate-seed] promoted staged seed ({shape}; cleared staged keys: {cleared})")
PY
    else
        # inline staged value: swap the two keys
        python3 - "$PROV_CONFIG" <<'PY'
import sys, re, os, tempfile

def write_atomic(path, text):
    # Atomic AND identity-preserving: mkstemp is 0600 root, so the target's
    # mode/owner must be carried over — the daemon reads this config as a
    # service identity (root:<service group> 0640), and a rename that silently
    # "fixed" the mode would lock it out of its own config.
    d = os.path.dirname(os.path.abspath(path)) or "."
    try:
        st = os.stat(path)
        mode, uid, gid = st.st_mode & 0o7777, st.st_uid, st.st_gid
    except FileNotFoundError:
        mode, uid, gid = 0o600, -1, -1
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".rotate-seed.")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
        if uid >= 0:
            try:
                os.chown(tmp, uid, gid)
            except PermissionError:
                pass
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise

path = sys.argv[1]
src = open(path).read()
m = re.search(r'^\s*volume_seed_next\s*:\s*(\S+)\s*$', src, re.M)
if not m:
    sys.exit("ERROR: no staged inline seed to promote")
seed = m.group(1)
src = re.sub(r'^\s*volume_seed\s*:.*$', f'volume_seed: {seed}', src, count=1, flags=re.M)
src = re.sub(r'^\s*volume_seed_next\s*:.*$\n?', '', src, flags=re.M)
write_atomic(path, src)
print("[rotate-seed] promoted staged seed (inline)")
PY
    fi
    # The config now names the new generation; the rotation is complete only
    # once the RUNNING instance says so (its namer is what resolves volumes).
    # Turning maintenance off before that leaves an instance serving the old
    # generation while every record points at the new names.
    fp_new="$(config_generation_fingerprint current)" \
        || fail "cannot resolve the promoted generation from $PROV_CONFIG"
    if wait_for_state current_fingerprint "$fp_new" 20; then
        log "promoted AND adopted by the running instance (fingerprint $fp_new)"
    else
        fail "the config names the promoted generation ($fp_new) but the running instance reports current=$(state_field current_fingerprint) — do NOT turn maintenance off. Check its log for a refused transition (record: $STATE_FILE); a refusal leaves the OLD generation live and the staging intact, which is the safe state."
    fi
    ;;
status)
    # Channel-agnostic pre-flight and post-rotation audit: what the CONFIG
    # names, what the RUNNING instance adopted, and what the DISK says. The
    # three can disagree, and every disagreement has a different fix — that is
    # exactly why they are printed side by side instead of inferred from a log.
    echo "── config: $PROV_CONFIG"
    cur_ref="$(seed_file current)"; next_ref="$(seed_file next)"
    if cur_fp="$(config_generation_fingerprint current 2>/dev/null)"; then
        echo "   current: ${cur_ref:-<inline value>} (fingerprint $cur_fp)"
    else
        echo "   current: NOT RESOLVABLE — the prov instance cannot start without it"
    fi
    if [[ -n "$next_ref" ]] || "$TEMPLATE_TOOL" volume-name --prov-config "$PROV_CONFIG" --generation next --fingerprint >/dev/null 2>&1; then
        if next_fp="$(config_generation_fingerprint next 2>/dev/null)"; then
            echo "   staged:  ${next_ref:-<inline value>} (fingerprint $next_fp)"
        else
            echo "   staged:  ${next_ref:-<inline value>} — NOT RESOLVABLE yet (the injector may not have materialized it)"
        fi
    else
        echo "   staged:  none (no rotation window open)"
    fi
    echo
    echo "── running instance: $STATE_FILE"
    if [[ -f "$STATE_FILE" ]]; then
        python3 - "$STATE_FILE" <<'PY'
import datetime, json, sys
d = json.load(open(sys.argv[1]))
adopted = d.get("adopted_unix") or 0
print(f"   pid={d.get('pid')}  record written {datetime.datetime.fromtimestamp(adopted).isoformat(timespec='seconds')}")
staged = d.get("staged_fingerprint") or ""
print(f"   live current={d.get('current_fingerprint')}  staged={bool(d.get('staged'))} {staged}".rstrip())
print(f"   last transition={d.get('last_transition')}")
for s in d.get("sources") or []:
    print(f"   source {s.get('generation'):<7} {s.get('kind')}:{s.get('path','')}  resolved={s.get('resolved')}")
sc = d.get("startup_scan")
if sc:
    print(f"   startup scan: sampled={sc.get('sampled')} foreign={sc.get('foreign')} "
          f"unstamped={sc.get('unstamped')} pre_generation={sc.get('pre_generation')} complete={sc.get('complete')}")
if d.get("last_error"):
    print(f"   LAST ERROR: {d['last_error']}")
PY
    else
        echo "   no adoption record — the instance has not started (or is not a prov instance)"
    fi
    echo
    echo "── prov fleet (from the human gateway's /stats)"
    human_get /stats | python3 -c 'import sys,json
d = json.load(sys.stdin)
print("   rotation window:", d.get("rotation") or {"freezing_creation": False})' 2>/dev/null \
        || echo "   (cannot read /stats)"
    fleet_seeds
    echo
    echo "── volumes root"
    "$TEMPLATE_TOOL" seed-scan --prov-config "$PROV_CONFIG" || true
    ;;
*)
    fail "unhandled action: $ACTION"
    ;;
esac

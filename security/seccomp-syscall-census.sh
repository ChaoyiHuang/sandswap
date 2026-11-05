#!/usr/bin/env bash
# seccomp-syscall-census.sh — mechanical diff of the warden's deny-list
# against the x86_64 syscall universe, with a per-survivor decision record.
#
# What it guards: the warden's seccomp filter is a DENY list beside the
# pinned x86_64 syscall universe, so every syscall NOT on the list is an
# implicit allow. Implicit allows rot: a kernel merge adds syscalls, the
# warden's list stays, and nobody re-decides. This script makes each allow
# an EXPLICIT, recorded decision:
#
#   security/seccomp-allowlist-decisions.txt   one line per allowed syscall:
#                                              <name><TAB><reason>
#
# Modes:
#   ./seccomp-syscall-census.sh            check mode — exits 1 on any
#                                          violation (missing/stale/TODO
#                                          decisions, deny-list typos)
#   ./seccomp-syscall-census.sh --init     (re)generate the decisions
#                                          template; every non-denied
#                                          syscall starts as TODO
#   ./seccomp-syscall-census.sh --table    print the full census table
#                                          (one line per syscall: decision
#                                          + reason) for the review record
#
# Sources are parsed, never hand-maintained: the deny list comes from
# warden/src/seccomp.rs; the universe comes from the PINNED header in this
# repository (x86_64 ABI), not the CI runner's linux-libc-dev. A runner header
# older than the pinned kernel lacks newer syscalls (mseal, *xattrat, listns,
# ...), which made every newer decision row look stale. UNISTD_HDR overrides
# the universe for a kernel-tree cross-check; regenerate the pinned file on
# every kernel rebase (see its header comment).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WARDEN_SECCOMP="$REPO_ROOT/warden/src/seccomp.rs"
UNISTD="${UNISTD_HDR:-$REPO_ROOT/security/syscall-universe-x86_64.h}"
DECISIONS="$REPO_ROOT/security/seccomp-allowlist-decisions.txt"

MODE=check
case "${1:-}" in
  --init) MODE=init ;;
  --table) MODE=table ;;
  "") MODE=check ;;
  *) echo "usage: $0 [--init|--table]" >&2; exit 2 ;;
esac

for f in "$WARDEN_SECCOMP" "$UNISTD"; do
  [[ -f $f ]] || { echo "MISSING source: $f" >&2; exit 2; }
done

# --- deny list: (nr, "name") pairs from DENY_SYSCALLS -----------------
declare -A DENY_NR   # name -> nr
deny_count=0
while read -r nr name; do
  [[ -n $nr ]] || continue
  DENY_NR[$name]=$nr
  deny_count=$((deny_count + 1))
done < <(sed -n '/^const DENY_SYSCALLS/,/^];/p' "$WARDEN_SECCOMP" \
           | grep -oE '\([0-9]+, "[a-z0-9_]+"\)' \
           | tr -d '()",' | awk '{print $1, $2}')

if (( deny_count == 0 )); then
  echo "VIOLATION: deny list parsed empty from $WARDEN_SECCOMP (parser drift?)" >&2
  exit 1
fi

# --- universe: __NR_name nr from the header ----------------------------
declare -A UNI_NR    # name -> nr
uni_count=0
while read -r name nr; do
  UNI_NR[$name]=$nr
  uni_count=$((uni_count + 1))
done < <(awk '/^#define __NR_[a-z0-9_]+ [0-9]+$/ {
                sub(/^__NR_/, "", $2); print $2, $3
              }' "$UNISTD")

# --- check A: deny entries exist in the universe with matching nr ------
violations=0
for name in "${!DENY_NR[@]}"; do
  if [[ -z ${UNI_NR[$name]+x} ]]; then
    echo "VIOLATION: denied syscall '$name' not in the universe header (typo or stale)" >&2
    violations=$((violations + 1))
  elif [[ ${UNI_NR[$name]} != "${DENY_NR[$name]}" ]]; then
    echo "VIOLATION: '$name' denied as nr ${DENY_NR[$name]} but the header says ${UNI_NR[$name]}" >&2
    violations=$((violations + 1))
  fi
done

# --- the allow set: universe minus denied ------------------------------
declare -A DECISION  # name -> reason
if [[ $MODE == init ]]; then
  : > "$DECISIONS"
  for name in "${!UNI_NR[@]}"; do
    [[ -n ${DENY_NR[$name]+x} ]] && continue
    printf '%s\tTODO\n' "$name" >> "$DECISIONS"
  done
  LC_ALL=C sort -o "$DECISIONS" "$DECISIONS"
  allowed=$(grep -c . "$DECISIONS")
  echo "INIT: wrote $allowed TODO decision rows to $DECISIONS"
  echo "     fill every TODO with the allow reason, then run this script in check mode"
  exit 0
fi

if [[ ! -f $DECISIONS ]]; then
  echo "VIOLATION: $DECISIONS missing — run with --init first" >&2
  exit 1
fi
while IFS=$'\t' read -r name reason; do
  [[ -n $name ]] || continue
  DECISION[$name]=$reason
done < "$DECISIONS"

# --- check B: every non-denied syscall carries a real decision ---------
# --- check C: no stale decision rows -----------------------------------
missing=0
for name in "${!UNI_NR[@]}"; do
  [[ -n ${DENY_NR[$name]+x} ]] && continue
  reason=${DECISION[$name]:-}
  if [[ -z $reason || $reason == TODO ]]; then
    echo "VIOLATION: allowed syscall '$name' has no decision row (or TODO) in $DECISIONS" >&2
    missing=$((missing + 1))
  fi
done
violations=$((violations + missing))

for name in "${!DECISION[@]}"; do
  if [[ -z ${UNI_NR[$name]+x} ]]; then
    echo "VIOLATION: decision row for '$name' but no such syscall in the universe (stale row)" >&2
    violations=$((violations + 1))
  elif [[ -n ${DENY_NR[$name]+x} ]]; then
    echo "VIOLATION: decision row for '$name' but it IS denied (remove the row)" >&2
    violations=$((violations + 1))
  fi
done

# --- report ------------------------------------------------------------
decided=0
for name in "${!UNI_NR[@]}"; do
  [[ -n ${DENY_NR[$name]+x} ]] && continue
  reason=${DECISION[$name]:-}
  [[ -n $reason && $reason != TODO ]] && decided=$((decided + 1))
done

echo "SECCOMP CENSUS: universe=$uni_count denied=$deny_count allow-decided=$decided"

if [[ $MODE == table ]]; then
  printf '%-24s %-7s %s\n' SYSCALL DECISION REASON
  for name in $(LC_ALL=C sort <<<"${!UNI_NR[@]}"); do
    if [[ -n ${DENY_NR[$name]+x} ]]; then
      printf '%-24s %-7s %s\n' "$name" deny "seccomp deny-list (nr ${DENY_NR[$name]})"
    else
      printf '%-24s %-7s %s\n' "$name" allow "${DECISION[$name]:-<NO DECISION>}"
    fi
  done
fi

if (( violations > 0 )); then
  echo "SECCOMP CENSUS: $violations violation(s)" >&2
  exit 1
fi
echo "SECCOMP CENSUS: clean"

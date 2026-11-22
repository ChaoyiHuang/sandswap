#!/usr/bin/env bash
# release-contributors.sh — emit the "Contributors" section (markdown) for
# a release: every commit author between the previous published release
# and the released ref, deduped by GitHub account, as an avatar wall;
# authors without a linked GitHub account get a plain-text line instead.
#
# Runs in the release workflow right after packaging (which rewrites
# dist/RELEASE_NOTES.md) and before gh release create/edit, appended to
# the notes. The workflow checkout is shallow, so the data comes from the
# GitHub API (releases + compare endpoints), not git log.
#
# Usage:
#   release-contributors.sh <tag> [head-ref] [base-ref]
#
#   <tag>       the version tag being released; used to exclude the
#               release itself when auto-detecting the previous one
#   <head-ref>  ref whose authors are credited; defaults to <tag>. Pass
#               the commit sha when the tag does not exist yet (dispatch
#               dry runs) or must not be resolved again (re-runs)
#   <base-ref>  previous release point; defaults to the newest published
#               non-draft release tag other than <tag>
#
# Output: the section on stdout (empty when there is nothing to list);
# diagnostics on stderr. Bot accounts ([bot]-suffixed logins) are
# excluded; a name that also appears on a linked commit is not repeated
# in the unlinked line.
set -euo pipefail

TAG="${1:?usage: release-contributors.sh <tag> [head-ref] [base-ref]}"
HEAD_REF="${2:-$TAG}"
BASE_REF="${3:-}"

REPO="${GITHUB_REPOSITORY:-}"
if [ -z "$REPO" ]; then
	echo "release-contributors: GITHUB_REPOSITORY not set (export it for local runs)" >&2
	exit 1
fi
command -v gh >/dev/null 2>&1 || {
	echo "release-contributors: gh CLI not found" >&2
	exit 1
}

if [ -z "$BASE_REF" ]; then
	RELEASES="$(gh api "repos/$REPO/releases?per_page=100" \
		--jq '.[] | select(.draft == false) | .tag_name')" || {
		echo "release-contributors: cannot list releases of $REPO" >&2
		exit 1
	}
	BASE_REF="$(printf '%s\n' "$RELEASES" | grep -v -x -- "$TAG" | head -n1 || true)"
	if [ -z "$BASE_REF" ]; then
		echo "release-contributors: no previous published release — skipping section" >&2
		exit 0
	fi
fi

echo "release-contributors: crediting authors of $BASE_REF...$HEAD_REF" >&2
PAIRS="$(gh api "repos/$REPO/compare/$BASE_REF...$HEAD_REF" \
	--jq '.commits[]?
	      | [ (.author.login // ""),
	          (.commit.author.name // "" | gsub("[\\t\\n]"; " ")) ]
	      | @tsv')" || {
	echo "release-contributors: compare $BASE_REF...$HEAD_REF failed" >&2
	exit 1
}

# Linked logins (bots excluded), and the lowercased git names of those
# same authors — an unlinked commit under an already-credited name must
# not list the person twice.
LOGINS="$(printf '%s\n' "$PAIRS" |
	awk 'BEGIN { FS = "\t" } $1 != "" && $1 !~ /\[bot\]$/ { print $1 }' |
	sort -u)"
LINKED_NAMES="$(printf '%s\n' "$PAIRS" |
	awk 'BEGIN { FS = "\t" } $1 != "" && $1 !~ /\[bot\]$/ { print tolower($2) }' |
	sort -u)"
UNLINKED="$(printf '%s\n' "$PAIRS" |
	awk 'BEGIN { FS = "\t" } $1 == "" && $2 != "" { print $2 }' |
	sort -u |
	awk -v linked="$LINKED_NAMES" '
		BEGIN { n = split(linked, K, "\n"); for (i = 1; i <= n; i++) if (K[i] != "") skip[K[i]] = 1 }
		!(tolower($0) in skip)')"

if [ -z "$LOGINS" ] && [ -z "$UNLINKED" ]; then
	echo "release-contributors: no commit authors in $BASE_REF...$HEAD_REF — skipping section" >&2
	exit 0
fi

echo ""
echo "## Contributors"
echo ""
echo "Thanks to everyone who contributed to this release:"
echo ""
while IFS= read -r login; do
	[ -n "$login" ] || continue
	printf '<a href="https://github.com/%s"><img src="https://github.com/%s.png" width="40" height="40" alt="%s"/></a>\n' \
		"$login" "$login" "$login"
done <<<"$LOGINS"
if [ -n "$UNLINKED" ]; then
	NAMES="$(printf '%s\n' "$UNLINKED" | paste -sd ',' - | sed 's/,/, /g')"
	echo ""
	echo "Also contributing, without a GitHub account linked to their commits: $NAMES."
fi

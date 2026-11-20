#!/usr/bin/env bash
# The gate of a real release (the `gate` job of .github/workflows/images.yml). It refuses anything but
#   1. a TAG named vMAJOR.MINOR.PATCH or vMAJOR.MINOR.PATCH-rc.N (no leading zeros, no `latest`, no branch),
#   2. whose commit is an ancestor of origin/main (the tag may be older than main's head, but main must contain it), and
#   3. on which the `ci` workflow has a successful push run on main (the full suite ran on exactly this commit and passed).
# Output: `version=<tag>` and `commit=<sha>` lines on stdout (the job appends them to $GITHUB_OUTPUT).
#
#   deploy/images/release-gate.sh                 the real gate; reads GITHUB_REF_TYPE, GITHUB_REF_NAME, GITHUB_SHA, GITHUB_REPOSITORY, GH_TOKEN
#   deploy/images/release-gate.sh --check-version v1.2.3   only the name rule (used by the tests; exit 0 or 1)
set -euo pipefail
VERSION_RE='^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-rc\.[1-9][0-9]*)?$'
if [ "${1:-}" = --check-version ]; then [[ "${2:-}" =~ $VERSION_RE ]]; exit $?; fi

fail() { echo "release-gate: REFUSED: $*" >&2; exit 1; }
: "${GITHUB_REF_TYPE:?}"; : "${GITHUB_REF_NAME:?}"; : "${GITHUB_SHA:?}"; : "${GITHUB_REPOSITORY:?}"
[ "$GITHUB_REF_TYPE" = tag ] || fail "run the workflow from a tag, not from $GITHUB_REF_TYPE '$GITHUB_REF_NAME' (gh workflow run images.yml --ref vX.Y.Z -f publish=true)"
[[ "$GITHUB_REF_NAME" =~ $VERSION_RE ]] || fail "tag '$GITHUB_REF_NAME' is not vMAJOR.MINOR.PATCH or vMAJOR.MINOR.PATCH-rc.N"
cd "$(dirname "$0")/../.."
# The checkout is a full clone (fetch-depth: 0); the tag's commit must be what the workflow runs, and main must contain it.
[ "$(git rev-parse HEAD)" = "$GITHUB_SHA" ] || fail "checked-out commit $(git rev-parse HEAD) is not the run's commit $GITHUB_SHA"
git fetch --no-tags --quiet origin main || fail "cannot fetch origin/main"
git merge-base --is-ancestor "$GITHUB_SHA" origin/main || fail "commit $GITHUB_SHA is not on main: tag a commit that main contains"
# CI on exactly this commit, from a push to main (a pull-request run of the same commit does not count: the merge commit differs).
n="$(gh run list --repo "$GITHUB_REPOSITORY" --workflow ci.yml --commit "$GITHUB_SHA" --branch main --event push --status success --json databaseId --jq length)"
[ "$n" -ge 1 ] || fail "no successful ci.yml run on main for commit $GITHUB_SHA (wait for CI, or fix and tag again)"
echo "release-gate: ok: $GITHUB_REF_NAME at $GITHUB_SHA, on main, ci green" >&2
echo "version=$GITHUB_REF_NAME"
echo "commit=$GITHUB_SHA"

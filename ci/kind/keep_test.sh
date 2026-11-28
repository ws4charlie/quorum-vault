#!/usr/bin/env bash
# Tests of keep mode's local guards (no cluster needed; kind.yml runs it before kind-up): the keep dir is never inside the repository, and
# kind-gate-forget removes only a lane keep dir and asks first.   ci/kind/keep_test.sh
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
t="$(mktemp -d)"; trap 'rm -rf "$t"' EXIT
export QV_KIND_KUBECONFIG="$t/kubeconfig" QV_KIND_NAME=qv-kind-keeptest
fail=0; ok() { echo "ok: $*"; }; bad() { echo "FAIL: $*"; fail=1; }
kd() { ( . "$here/lib.sh"; keep_dir ) 2>/dev/null; }
root="$(cd "$here/../.." && pwd)"

[ "$(HOME=/h QV_KIND_KEEP_DIR= kd)" = /h/.qv-kind-keep/qv-kind-keeptest ] && ok "default ~/.qv-kind-keep/<name>" || bad "default keep dir: $(HOME=/h QV_KIND_KEEP_DIR= kd)"
[ "$(QV_KIND_KEEP_DIR="$t/k/" kd)" = "$t/k" ] && ok "QV_KIND_KEEP_DIR wins" || bad "QV_KIND_KEEP_DIR not used"
for d in "$root" "$root/ci/kind/.work/x" "$root/../$(basename "$root")/k" relative/dir "$t/a/../b"; do
  QV_KIND_KEEP_DIR="$d" kd > /dev/null && bad "keep dir $d accepted" || ok "keep dir $d refused"
done
# the main checkout of a worktree is the repository too
top="$(git -C "$root" rev-parse --path-format=absolute --git-common-dir)"; top="${top%/.git}"
QV_KIND_KEEP_DIR="$top/keep" kd > /dev/null && bad "keep dir in the main checkout accepted" || ok "keep dir in the main checkout refused"

# forget: a dir without the mark is never removed; with it, only after YES=1 (no terminal here)
mkdir -p "$t/other" && touch "$t/other/f"
QV_KIND_KEEP_DIR="$t/other" YES=1 "$here/forget.sh" < /dev/null > /dev/null 2>&1 && bad "forget removed a dir without the mark" || { [ -f "$t/other/f" ] && ok "forget refuses an unmarked dir" || bad "unmarked dir damaged"; }
mkdir -p "$t/keep" && echo x > "$t/keep/.qv-kind-keep"
QV_KIND_KEEP_DIR="$t/keep" "$here/forget.sh" < /dev/null > /dev/null 2>&1 && bad "forget without YES and without a terminal ran" || { [ -d "$t/keep" ] && ok "forget asks first (no terminal: refused)" || bad "keep dir gone without YES"; }
QV_KIND_KEEP_DIR="$t/keep" YES=1 "$here/forget.sh" < /dev/null > /dev/null 2>&1 && [ ! -e "$t/keep" ] && ok "forget YES=1 removes the keep dir" || bad "forget YES=1 did not remove it"
QV_KIND_KEEP_DIR="$t/keep" YES=1 "$here/forget.sh" < /dev/null > /dev/null 2>&1 && ok "forget with no keep dir is a no-op" || bad "forget with no keep dir failed"
rm -rf "$root/ci/kind/.work/qv-kind-keeptest"   # lib.sh makes the work dir of the name it is given
[ "$fail" = 0 ] && echo "keep_test: all ok" || echo "keep_test: FAILED"
exit "$fail"

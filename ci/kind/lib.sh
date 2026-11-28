#!/usr/bin/env bash
# Shared by the scripts of the kind lane. Source it; it sets the names that make the cluster this checkout's own.
set -euo pipefail
QV_KIND_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
KDIR="$QV_KIND_ROOT/ci/kind"
# shellcheck source=versions.env
. "$KDIR/versions.env"
# One cluster per checkout (PR #104 names the compose projects the same way), so two checkouts and the compose e2e never collide.
QV_KIND_NAME="${QV_KIND_NAME:-qv-kind-$(printf %s "$QV_KIND_ROOT" | shasum | cut -c1-6)}"
CTX="kind-$QV_KIND_NAME"
WORK="$KDIR/.work/$QV_KIND_NAME"            # generated, gitignored: CAs, passwords, values files, test keys. Nothing in it is ever committed.
NS_BIZ=qv; NS_SIGN=qv-signing; NS_B=qv-party-b; NS_C=qv-party-c
NS_PTEST=qv-ptest                           # the namespace the policy chart labels (policy.sh); not part of ALL_NS
ALL_NS="$NS_BIZ $NS_SIGN $NS_B $NS_C"
export QV_KIND_CHAIN_ID="${QV_KIND_CHAIN_ID:-84532}" # the lane's EVM chain id (anvil, kindcfg, kindwd, the load target), decided only here; 84532 = Base Sepolia (Gate x402, USDC EIP-3009)
export KUBECONFIG="${QV_KIND_KUBECONFIG:-$WORK/kubeconfig}"
mkdir -p "$WORK"
k()  { kubectl --context "$CTX" "$@"; }
kn() { local ns="$1"; shift; kubectl --context "$CTX" -n "$ns" "$@"; }
hm() { helm --kube-context "$CTX" "$@"; }
log() { printf '\033[1m== %s\033[0m  (%ss)\n' "$*" "$SECONDS" >&2; }
arch() { case "$(uname -m)" in arm64|aarch64) echo arm64;; *) echo amd64;; esac; }
# The tag of an image, from `repo:tag|digest` lines
pinned_tag() { printf '%s\n' "$PINNED_IMAGES" | awk -F'|' 'NF==2{print $1}'; }
pinned_digest() { printf '%s\n' "$PINNED_IMAGES" | awk -F'|' -v t="$1" '$1==t{print $2}'; }
# docker pull with a bounded retry: 4 tries, 10s/20s/40s apart (a registry rate limit or a network blip failed the nightly of 2026-11-26). The last
# failure stops the lane with docker's own message.
pull_retry() {
  local ref="$1" try out
  for try in 1 2 3 4; do
    if out="$(docker pull -q --platform "linux/$(arch)" "$ref" 2>&1)"; then return 0; fi
    [ "$try" = 4 ] && break
    echo "pull $ref failed (try $try of 4), again in $((10 * 2 ** (try - 1)))s: $out" >&2
    sleep $((10 * 2 ** (try - 1)))
  done
  echo "pull $ref failed 4 times: $out" >&2
  return 1
}
# Pull by digest, retag, load into the node. Docker's containerd image store cannot `kind load docker-image` a multi-arch image, so ONE archive is made for this
# platform and loaded once (a single save is also much faster than one per image).
pull_pinned() {
  # Always pull BY DIGEST (instant when the content is there) and retag that exact image: a tag that already exists locally may be another image (a moved tag, a local build).
  local tag dig repo
  while IFS='|' read -r tag dig; do
    [ -n "$tag" ] || continue
    repo="${tag%:*}"
    pull_retry "$repo@$dig"
    docker tag "$repo@$dig" "$tag"
  done <<<"$(printf '%s\n' "$PINNED_IMAGES")"
}
load_images() {
  local tar="$WORK/images.tar"
  docker save --platform "linux/$(arch)" "$@" -o "$tar" 2>/dev/null || docker save "$@" -o "$tar"
  kind load image-archive "$tar" --name "$QV_KIND_NAME" >/dev/null
  rm -f "$tar"
}

# A port-forward on a FREE local port, ready before it returns (two checkouts, or two runs, never share one; one can never talk to the other's store).
#   pf_start NAMESPACE TARGET REMOTE_PORT   sets PF_PORT and PF_PID; stop with pf_stop
pf_start() {
  local ns="$1" target="$2" remote="$3" log; log="$(mktemp "$WORK/pf.XXXXXX")"; PF_LOG="$log"   # the forward's own output stays until pf_stop: a forward that drops by itself must say why
  kubectl --context "$CTX" -n "$ns" port-forward "$target" ":$remote" >"$log" 2>&1 &
  PF_PID=$!; disown "$PF_PID" 2> /dev/null || true   # no "Terminated" job message when it is stopped
  local i
  for i in $(seq 100); do
    PF_PORT="$(sed -n 's/^Forwarding from 127.0.0.1:\([0-9]*\) ->.*/\1/p' "$log" | head -1)"
    [ -n "$PF_PORT" ] && return 0
    kill -0 "$PF_PID" 2>/dev/null || { cat "$log" >&2; rm -f "$log"; PF_LOG=""; return 1; }
    sleep 0.2
  done
  cat "$log" >&2; rm -f "$log"; PF_LOG=""; kill "$PF_PID" 2>/dev/null; return 1
}
# The trust bundles qv-certs made in a namespace (immutable ConfigMaps, `qv-trust-<zone>-<hash>`), as helm flags: the charts take them as the CA file of their certificate volumes.
trust_args() {
  local ns="$1" z n
  for z in business signing; do
    n="$(kn "$ns" get configmap -l "quorumvault.io/trust-bundle=$z" -o jsonpath='{.items[0].metadata.name}' 2> /dev/null || true)"   # no bundle in this namespace (qv-certs not installed there): empty, the chart keeps the CA of its Secret
    if [ -n "$n" ]; then printf -- '--set tls.trust.%s=%s ' "$z" "$n"; fi
  done
  return 0
}
# Waits for each background job by pid: a bare `wait` returns 0 whatever the jobs returned, so a failed `helm upgrade ... &` would pass. Fails if any job failed (after all have ended).
#   job_a & pa=$!; job_b & pb=$!; wait_all "$pa" "$pb"
wait_all() { local p rc=0; for p in "$@"; do wait "$p" || rc=1; done; return $rc; }
# Stops the port-forward. One that is already gone (it dropped by itself) is not an error of the stop, but it is reported with its own output: the connection broke while the caller was using it.
pf_stop() {
  if [ -n "${PF_PID:-}" ]; then
    if kill -0 "$PF_PID" 2>/dev/null; then kill "$PF_PID" 2>/dev/null || true
    else echo "pf_stop: the port-forward (pid $PF_PID) had already exited; its output:" >&2; sed 's/^/  | /' "${PF_LOG:-/dev/null}" >&2 2>/dev/null || true; fi
  fi
  [ -z "${PF_LOG:-}" ] || rm -f "$PF_LOG"
  PF_PID=""; PF_LOG=""; return 0
}

# A failing command in a setup script must say which one and where (set -e alone exits silently: a CI run once stopped right after "guard databases" with no error text). Call it right after sourcing this file.
trace_failures() { set -E; trap 'echo "FAILED (exit $?): ${BASH_SOURCE[0]##*/}:$LINENO: $BASH_COMMAND" >&2' ERR; }

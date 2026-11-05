#!/usr/bin/env bash
# End-to-end demo against a running server (go run ./cmd/quorumvault):
#   1. HSM hot wallet: policy + allowlist, small tx (allowed -> signed),
#      large tx (needs approval -> second actor approves -> signed)
#   2. the "mpc" backend is gone from /v1 (the demo is HSM-only): creating one is refused with a pointer to /v2
#   3. HSM cold wallet: 1 wei still needs 2 approvals
#   4. offline check of every raw tx (recovered sender == wallet address),
#      GET /audit/verify
# Prints raw txs, tx hashes and latencies. Requires curl and jq.
#
# Env: QV_URL (default http://localhost:8080), QV_BIN (default: go run
# ./cmd/quorumvault, used for the offline verify-tx check).
#
# Default mode: nonces are 0 (fresh wallets), fees are the server defaults,
# nothing is broadcast (start the server without SEPOLIA_RPC_URL).
#
# Local-chain mode (--local, or SEPOLIA_RPC_URL set in this script's env): the
# server must run with the same SEPOLIA_RPC_URL (default http://127.0.0.1:8545,
# `make chain-up`). The script refuses unless that node is a local anvil with
# chain ID 11155111, funds each demo wallet with anvil_setBalance, leaves nonce
# and fees to the server (filled from the node), and prints each tx's receipt.
set -euo pipefail

URL="${QV_URL:-http://localhost:8080}"
LOCAL=0
if [[ "${1:-}" == "--local" ]]; then LOCAL=1; fi
if [[ -n "${SEPOLIA_RPC_URL:-}" ]]; then LOCAL=1; fi
RPC="${SEPOLIA_RPC_URL:-http://127.0.0.1:8545}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST="0x000000000000000000000000000000000000dEaD"
RUN="$(date +%s)"
if [[ -n "${QV_BIN:-}" ]]; then VERIFY=("$QV_BIN" verify-tx); else VERIFY=(go run "$ROOT/cmd/quorumvault" verify-tx); fi

command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }

# call METHOD PATH ACTOR [JSON]: sets BODY, LAST_CODE and LAST_SECS (no subshell,
# so callers see them).
call() {
  local method=$1 path=$2 actor=$3 body=${4:-} out
  local args=(-sS -X "$method" "$URL$path" -H 'Content-Type: application/json' -w '\n%{http_code} %{time_total}')
  if [[ -n "$actor" ]]; then args+=(-H "X-Actor: $actor"); fi
  if [[ -n "$body" ]]; then args+=(-d "$body"); fi
  out="$(curl "${args[@]}")"
  read -r LAST_CODE LAST_SECS <<<"$(tail -n1 <<<"$out")"
  BODY="$(sed '$d' <<<"$out")"
}
ms() { awk -v s="$1" 'BEGIN { printf "%.1f", s * 1000 }'; }
step() { printf '\n== %s\n' "$*"; }
expect() { [[ "$LAST_CODE" == "$1" ]] || { echo "unexpected HTTP $LAST_CODE (want $1)" >&2; exit 1; }; }

# rpc METHOD PARAMS_JSON: prints the JSON-RPC result (fails on an RPC error).
rpc() {
  local out
  out="$(curl -sS -X POST "$RPC" -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$1\",\"params\":$2}")"
  if [[ "$(jq -r '.error // empty' <<<"$out")" != "" ]]; then echo "rpc $1: $out" >&2; exit 1; fi
  jq -c .result <<<"$out"
}
now_ms() { perl -MTime::HiRes=time -e 'printf "%.1f", time * 1000'; }

# Safety: local mode talks only to a local anvil node impersonating Sepolia.
check_local_chain() {
  local host client chain
  host="$(sed -E 's#^[a-z]+://(\[[^]]*\]|[^/:]*).*#\1#' <<<"$RPC")"
  case "$host" in
    localhost|127.0.0.1|"[::1]"|anvil) ;;
    *) echo "refusing RPC host '$host': local mode needs localhost/127.0.0.1/[::1]/anvil" >&2; exit 1 ;;
  esac
  [[ "$RPC" == http://* ]] || { echo "refusing RPC URL '$RPC': plain http to a local node only" >&2; exit 1; }
  client="$(rpc web3_clientVersion '[]' | jq -r .)"
  [[ "$client" == *anvil* ]] || { echo "refusing node '$client': not anvil" >&2; exit 1; }
  chain="$(rpc eth_chainId '[]' | jq -r .)"
  [[ "$((chain))" == 11155111 ]] || { echo "refusing chain id $((chain)): want 11155111" >&2; exit 1; }
  echo "local chain: $client at $RPC, chain id $((chain)) (Sepolia), block $(( $(rpc eth_blockNumber '[]' | jq -r .) ))"
}

FUND_WEI_HEX=0x8ac7230489e80000 # 10 ETH
fund() { # address
  rpc anvil_setBalance "[\"$1\",\"$FUND_WEI_HEX\"]" >/dev/null
  echo "funded $1 with 10 ETH via anvil_setBalance (balance $(rpc eth_getBalance "[\"$1\",\"latest\"]" | jq -r .))"
}

# receipt TX_HASH LABEL: waits for the receipt, prints it, records latencies.
receipt() {
  local t0 r st i
  t0="$(now_ms)"
  for i in $(seq 1 100); do
    r="$(rpc eth_getTransactionReceipt "[\"$1\"]")"
    [[ "$r" != null ]] && break
    sleep 0.05
  done
  [[ "$r" != null ]] || { echo "no receipt for $1" >&2; exit 1; }
  st="$(jq -r .status <<<"$r")"
  echo "  receipt (poll $i): block=$(( $(jq -r .blockNumber <<<"$r") )) status=$(( st )) gasUsed=$(( $(jq -r .gasUsed <<<"$r") )) effectiveGasPrice=$(( $(jq -r .effectiveGasPrice <<<"$r") )) wei from=$(jq -r .from <<<"$r")"
  [[ "$st" == 0x1 ]] || { echo "tx $1 reverted" >&2; exit 1; }
  record "$2: broadcast (eth_sendRawTransaction)" "-" "$(jq -r '.timings_ms.broadcast // "-"' <<<"$REQ")"
  record "$2: receipt fetched (poll $i, curl+jq)" "$(awk -v a="$t0" -v b="$(now_ms)" 'BEGIN { printf "%.1f", b - a }')" "-"
}

SUMMARY=()
record() { SUMMARY+=("$(printf '| %-58s | %9s | %9s |' "$1" "$2" "$3")"); }

wallet() { # name tier backend -> sets WID, ADDR
  call POST /wallets admin "{\"name\":\"$1-$RUN\",\"tier\":\"$2\",\"backend\":\"$3\"}"; expect 201
  WID="$(jq -r .wallet.id <<<"$BODY")"; ADDR="$(jq -r .key.address <<<"$BODY")"
  echo "wallet $1 ($2/$3) id=$WID address=$ADDR create=$(ms "$LAST_SECS")ms"
  if [[ $LOCAL == 1 ]]; then fund "$ADDR"; fi
  call PUT "/wallets/$WID/policy" admin '{"daily_limit_wei":"1000000000000000000","per_tx_limit_wei":"500000000000000000",
    "approval_threshold_wei":"10000000000000000","velocity_max_tx":10,"velocity_window_seconds":3600,"required_approvals":0}'
  expect 200; echo "policy $(jq -c '{approval_threshold_wei, per_tx_limit_wei, daily_limit_wei, required_approvals}' <<<"$BODY")"
  call POST "/wallets/$WID/allowlist" admin "{\"address\":\"$DEST\",\"label\":\"burn\"}"
  expect 201; echo "allowlist $(jq -c 'map(.address)' <<<"$BODY")"
}

submit() { # wei -> sets REQ (response) and RID
  local nonce=',"nonce":0'
  if [[ $LOCAL == 1 ]]; then nonce=''; fi # the server fills nonce + fees from the node
  call POST /sign-requests alice "{\"wallet_id\":\"$WID\",\"to\":\"$DEST\",\"value_wei\":\"$1\"$nonce}"; expect 201
  REQ=$BODY
  RID="$(jq -r .request.id <<<"$REQ")"
  echo "request $RID value=$1 wei -> status=$(jq -r .request.status <<<"$REQ") decision=$(jq -c .request.decision <<<"$REQ") http=$(ms "$LAST_SECS")ms"
}

approve() { # actor -> sets REQ
  call POST "/sign-requests/$RID/approve" "$1" '{"comment":"looks right"}'; expect 200
  REQ=$BODY
  echo "approve by $1 -> status=$(jq -r .request.status <<<"$REQ") tally=$(jq -c .tally <<<"$REQ") http=$(ms "$LAST_SECS")ms"
}

show_signed() { # label
  [[ "$(jq -r .request.status <<<"$REQ")" == signed ]] || { echo "not signed: $(jq -c . <<<"$REQ")" >&2; exit 1; }
  local raw hash from
  raw="$(jq -r .request.raw_tx <<<"$REQ")"; hash="$(jq -r .request.tx_hash <<<"$REQ")"; from="$(jq -r .from <<<"$REQ")"
  echo "  signed: tx_hash=$hash"
  echo "  from (server-recovered) = $from   wallet = $ADDR"
  echo "  raw_tx = $raw"
  if [[ -n "$(jq -r '.broadcast // empty' <<<"$REQ")" ]]; then echo "  broadcast: $(jq -r .broadcast <<<"$REQ")"; fi
  if [[ $LOCAL == 1 ]]; then
    [[ "$(jq -r '.broadcast // empty' <<<"$REQ")" == ok ]] || { echo "not broadcast: is the server running with SEPOLIA_RPC_URL=$RPC?" >&2; exit 1; }
    receipt "$hash" "$1"
  fi
  echo "  offline verify-tx:"
  "${VERIFY[@]}" "$raw" "$ADDR" | sed 's/^/    /'
  record "$1: sign ceremony" "-" "$(jq -r .timings_ms.sign <<<"$REQ")"
  SIGNED+=("$1|$hash|$from")
}
SIGNED=()

step "health"
call GET /healthz ""; expect 200; jq -c . <<<"$BODY"
if [[ $LOCAL == 1 ]]; then check_local_chain; fi

step "1a. HSM hot wallet: create, policy (approval over 0.01 ETH), allowlist"
wallet demo-hsm-hot hot hsm
HSM_ADDR=$ADDR

step "1b. HSM: 0.001 ETH -> allowed, signed in-token"
submit 1000000000000000
show_signed "HSM (hot, allow)"
record "HSM e2e request (POST, allow -> signed)" "$(ms "$LAST_SECS")" "$(jq -r .timings_ms.total <<<"$REQ")"

step "1c. HSM: 0.1 ETH -> pending_approval; alice cannot self-approve; bob approves"
submit 100000000000000000
call POST "/sign-requests/$RID/approve" alice '{}'; expect 403; echo "self-approve by alice -> HTTP $LAST_CODE $(jq -c . <<<"$BODY")"
approve bob
show_signed "HSM (hot, approved)"
record "HSM approve call (vote -> signed)" "$(ms "$LAST_SECS")" "$(jq -r .timings_ms.total <<<"$REQ")"

step "2. the mpc backend is no longer part of /v1"
call POST /wallets admin "{\"name\":\"demo-mpc-$RUN\",\"tier\":\"hot\",\"backend\":\"mpc\"}"; expect 422
echo "mpc wallet -> HTTP $LAST_CODE $(jq -c . <<<"$BODY")"
grep -q "/v2" <<<"$BODY" || { echo "the refusal does not point to /v2" >&2; exit 1; }

step "3. HSM cold wallet: 1 wei still needs 2 approvals"
wallet demo-hsm-cold cold hsm
COLD_RID=""
submit 1
COLD_RID=$RID
approve bob
approve carol
show_signed "HSM (cold, approved)"
record "HSM cold final approve (vote -> signed)" "$(ms "$LAST_SECS")" "$(jq -r .timings_ms.total <<<"$REQ")"

step "4. audit trail for the cold request, and chain verification"
call GET "/audit?request_id=$COLD_RID" ""; jq -r '.[] | "  #\(.seq) \(.type) by \(.actor)"' <<<"$BODY"
call GET /audit/verify ""; expect 200; echo "audit verify: $(jq -c . <<<"$BODY")"
[[ "$(jq -r .ok <<<"$BODY")" == true ]] || { echo "audit chain broken" >&2; exit 1; }

if [[ $LOCAL == 1 ]]; then step "summary: Sepolia (chain 11155111) EIP-1559 txs, mined on local anvil"; else
step "summary: signed Sepolia (chain 11155111) EIP-1559 txs"; fi
for s in "${SIGNED[@]}"; do IFS='|' read -r l h f <<<"$s"; printf '  %-28s %s  from %s\n' "$l" "$h" "$f"; done
echo
echo "client ms = curl time_total; server ms = timings_ms (sign = backend ceremony only, else whole call)"
echo "| Step                                                       | client ms | server ms |"
echo "|------------------------------------------------------------|----------:|----------:|"
printf '%s\n' "${SUMMARY[@]}"

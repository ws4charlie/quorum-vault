#!/usr/bin/env bash
# End-to-end demo against a running server (go run ./cmd/quorumvault):
#   1. HSM hot wallet: policy + allowlist, small tx (allowed -> signed),
#      large tx (needs approval -> second actor approves -> signed)
#   2. MPC hot wallet: small tx signed by the 2-of-3 threshold
#   3. MPC cold wallet: 1 wei still needs 2 approvals; signed by all 3 parties
#   4. offline check of every raw tx (recovered sender == wallet address),
#      GET /audit/verify
# Prints raw txs, tx hashes and latencies. Requires curl and jq.
#
# Env: QV_URL (default http://localhost:8080), QV_BIN (default: go run
# ./cmd/quorumvault, used for the offline verify-tx check).
# Nonces are 0 (fresh wallets); fees are the server defaults unless the server
# has SEPOLIA_RPC_URL, which then also broadcasts (bonus; needs a funded address).
set -euo pipefail

URL="${QV_URL:-http://localhost:8080}"
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

SUMMARY=()
record() { SUMMARY+=("$(printf '| %-48s | %9s | %9s |' "$1" "$2" "$3")"); }

wallet() { # name tier backend -> sets WID, ADDR
  call POST /wallets admin "{\"name\":\"$1-$RUN\",\"tier\":\"$2\",\"backend\":\"$3\"}"; expect 201
  WID="$(jq -r .wallet.id <<<"$BODY")"; ADDR="$(jq -r .key.address <<<"$BODY")"
  echo "wallet $1 ($2/$3) id=$WID address=$ADDR create=$(ms "$LAST_SECS")ms"
  if [[ "$3" == mpc ]]; then record "MPC DKG keygen (POST /wallets $2)" "$(ms "$LAST_SECS")" "-"; fi
  call PUT "/wallets/$WID/policy" admin '{"daily_limit_wei":"1000000000000000000","per_tx_limit_wei":"500000000000000000",
    "approval_threshold_wei":"10000000000000000","velocity_max_tx":10,"velocity_window_seconds":3600,"required_approvals":0}'
  expect 200; echo "policy $(jq -c '{approval_threshold_wei, per_tx_limit_wei, daily_limit_wei, required_approvals}' <<<"$BODY")"
  call POST "/wallets/$WID/allowlist" admin "{\"address\":\"$DEST\",\"label\":\"burn\"}"
  expect 201; echo "allowlist $(jq -c 'map(.address)' <<<"$BODY")"
}

submit() { # wei -> sets REQ (response) and RID
  call POST /sign-requests alice "{\"wallet_id\":\"$WID\",\"to\":\"$DEST\",\"value_wei\":\"$1\",\"nonce\":0}"; expect 201
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
  echo "  offline verify-tx:"
  "${VERIFY[@]}" "$raw" "$ADDR" | sed 's/^/    /'
  record "$1: sign ceremony" "-" "$(jq -r .timings_ms.sign <<<"$REQ")"
  SIGNED+=("$1|$hash|$from")
}
SIGNED=()

step "health"
call GET /healthz ""; expect 200; jq -c . <<<"$BODY"

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

step "2. MPC hot wallet: 2-of-3 threshold signing"
wallet demo-mpc-hot hot mpc
submit 1000000000000000
show_signed "MPC 2-of-3 (hot, allow)"
record "MPC 2-of-3 e2e request (POST, allow -> signed)" "$(ms "$LAST_SECS")" "$(jq -r .timings_ms.total <<<"$REQ")"
call GET "/audit?request_id=$RID" ""; echo "  participants: $(jq -c '.[] | select(.type=="sign.completed") | .payload.participants' <<<"$BODY")"

step "3. MPC cold wallet: 1 wei still needs 2 approvals; full 3-of-3 quorum"
wallet demo-mpc-cold cold mpc
COLD_RID=""
submit 1
COLD_RID=$RID
approve bob
approve carol
show_signed "MPC 3-of-3 (cold, approved)"
record "MPC 3-of-3 final approve (vote -> signed)" "$(ms "$LAST_SECS")" "$(jq -r .timings_ms.total <<<"$REQ")"
call GET "/audit?request_id=$RID" ""; echo "  participants: $(jq -c '.[] | select(.type=="sign.completed") | .payload.participants' <<<"$BODY")"

step "4. audit trail for the cold request, and chain verification"
call GET "/audit?request_id=$COLD_RID" ""; jq -r '.[] | "  #\(.seq) \(.type) by \(.actor)"' <<<"$BODY"
call GET /audit/verify ""; expect 200; echo "audit verify: $(jq -c . <<<"$BODY")"
[[ "$(jq -r .ok <<<"$BODY")" == true ]] || { echo "audit chain broken" >&2; exit 1; }

step "summary: signed Sepolia (chain 11155111) EIP-1559 txs"
for s in "${SIGNED[@]}"; do IFS='|' read -r l h f <<<"$s"; printf '  %-28s %s  from %s\n' "$l" "$h" "$f"; done
echo
echo "client ms = curl time_total; server ms = timings_ms (sign = backend ceremony only, else whole call)"
echo "| Step                                             | client ms | server ms |"
echo "|--------------------------------------------------|----------:|----------:|"
printf '%s\n' "${SUMMARY[@]}"

#!/usr/bin/env bash
# Phase 3b: what the withdrawal cases need around the DKG result, all generated into the gitignored work dir: the factory on the local chain, the signing config (approvers, both chains'
# hot keys, the parties' addresses and pins), the cosigner copy of it, and the two custody configs. Then the cosigners of B and C are upgraded to the real signing config.
# Run by charts.sh after the DKG. `signing.sh core` installs qv-signing-core (after the business chart, whose migration makes the gateway's database role). Idempotent.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$QV_KIND_ROOT"
S="$WORK/secrets"; C="$WORK/cfg"
pin() { kn "$1" get secret "$2" -o jsonpath='{.data.tls\.crt}' | base64 -d | openssl x509 -noout -pubkey | openssl pkey -pubin -outform DER | openssl dgst -sha256 -hex | awk '{print $NF}'; }

case "${1:-configs}" in
configs)
  KEYS="$WORK/keys.json"; [ -s "$KEYS" ] || { echo "signing.sh: no $KEYS (dkg.sh first)" >&2; exit 1; }
  log "local chain: deposit factory"
  CHAIN="$WORK/chain.json"
  if [ ! -s "$CHAIN" ]; then
    trap pf_stop EXIT
    pf_start "$NS_BIZ" svc/anvil 8545
    go run ./ci/kind/tools/kindcfg chain -rpc "http://127.0.0.1:$PF_PORT" -hot "$(jq -r .address "$KEYS")" > "$CHAIN"
    pf_stop
  fi
  [ -s "$S/auto-approver.seed" ] || ( umask 077; openssl rand -hex 32 > "$S/auto-approver.seed" )
  ( umask 077; kn "$NS_BIZ" get secret chain-credentials -o jsonpath='{.data.BTC_RPC_USER}' | base64 -d > "$S/btc-rpc-user"; kn "$NS_BIZ" get secret chain-credentials -o jsonpath='{.data.BTC_RPC_PASSWORD}' | base64 -d > "$S/btc-rpc-pass" )
  jq -n --arg a "$(pin $NS_SIGN qv-signing-mpc-party-a-tls)" --arg b "$(pin $NS_B qv-signing-mpc-party-b-tls)" --arg c "$(pin $NS_C qv-signing-mpc-party-c-tls)" --arg ns "$NS_SIGN" \
    '{gateway_cert:"/etc/qv/party-tls", a:{address:"qv-party-a-caller.qv-signing.svc:7001",pin:$a}, b:{address:"qv-party-b-caller.qv-party-b.svc:7001",pin:$b}, c:{address:"qv-party-c-caller.qv-party-c.svc:7001",pin:$c}}' > "$WORK/pins.json"
  go run ./ci/kind/tools/kindcfg gen -keys "$KEYS" -pins "$WORK/pins.json" -factory "$(jq -r .factory "$CHAIN")" -height "$(jq -r .height "$CHAIN")" -btc-height 0 \
    -auto-seed "$S/auto-approver.seed" -out "$C" -btc-user-file "$S/btc-rpc-user" -btc-pass-file "$S/btc-rpc-pass"
  log "cosigners of B and C: the real signing config"
  jq '{cosigner:{config:.}}' "$C/cosigner.json" > "$WORK/cosigner-config.yaml"
  for r in b c; do
    ns="$NS_B"; [ "$r" = c ] && ns="$NS_C"
    hm upgrade --install "qv-party-$r" deploy/helm/qv-party -n "$ns" --set role="$(echo $r | tr a-z A-Z)" -f deploy/helm/qv-party/values-kind.yaml -f "$WORK/party-$r.yaml" -f "$WORK/cosigner-config.yaml" --wait --timeout 6m > /dev/null &
  done
  wait
  ;;
core)
  log "qv-signing-core"
  # every signer is an MPC signer: no HSM in the gateway pod (the softhsm of values-kind is for a pkcs11 signer, which the lane has none of)
  hm upgrade --install qv-signing-core deploy/helm/qv-signing-core -n "$NS_SIGN" -f deploy/helm/qv-signing-core/values-kind.yaml --set hsm.mode=none \
    --set-file config.signing="$C/signing.json" --wait --timeout 6m > /dev/null
  ;;
esac

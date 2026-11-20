#!/usr/bin/env bash
# The DKGs through party A's caller port: `hot-0`, an ECDSA 2-of-3 keyset over the three party pods (the EVM hot shard: its root key is the hot key, as the e2e suite's 3-party mode), and
# `btc-0`, the HD keyset the Bitcoin account derives from. Writes the public values the configs need (hot key and address, regtest account xpub) to $WORK/keys.json. Skips when that file exists. kindctl is the lane's operator tool here: it makes the
# one call through a port-forward and reads back the public keys; the admin seed stays in the gitignored work dir. (qv-party-admin does the same from the operator Job; the lane keeps one tool
# because the Job needs a signed file per call and a second Job image for the reads.)
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$QV_KIND_ROOT"
OUT="$WORK/keys.json"; [ -s "$OUT" ] && { echo "DKG done: $(cat "$OUT")"; exit 0; }
g() { kn "$NS_SIGN" get secret qv-signing-gateway-party-tls -o jsonpath="{.data.$1}" | base64 -d; }
g 'tls\.crt' > "$WORK/gwp.crt"; ( umask 077; g 'tls\.key' > "$WORK/gwp.key" )
PA="$(kn "$NS_SIGN" get secret qv-signing-mpc-party-a-tls -o jsonpath='{.data.tls\.crt}' | base64 -d | openssl x509 -noout -pubkey | openssl pkey -pubin -outform DER | openssl dgst -sha256 -hex | awk '{print $NF}')"
for ns in $NS_SIGN $NS_B $NS_C; do kn "$ns" wait --for=condition=Ready pod -l app.kubernetes.io/name=qv-party --timeout=180s >/dev/null; done
trap pf_stop EXIT
pf_start "$NS_SIGN" svc/qv-party-a-caller 7001
K=(-addr 127.0.0.1:$PF_PORT -cert "$WORK/gwp.crt" -key "$WORK/gwp.key" -pin "$PA" -id hot-0)
# A pod is Ready before its peer port takes calls on a cold cluster ("connection refused" from A to B), so a DKG that fails before it starts is tried again
retry() { local i; for i in 1 2 3 4 5 6; do "$@" && return 0; sleep 10; done; return 1; }
# each DKG is made once; its public result is kept in the work dir, and kindctl rebuilds it from the party's keyset status if a run lost it (the key made, the file never written)
[ -s "$WORK/hot-0.json" ] || retry go run ./ci/kind/tools/kindctl dkg "${K[@]}" -seed "$WORK/secrets/admin.seed" -scheme ecdsa-2of3 > "$WORK/hot-0.json"
[ -s "$WORK/btc-0.xpub" ] || { retry go run ./ci/kind/tools/kindctl dkg "${K[@]/hot-0/btc-0}" -seed "$WORK/secrets/admin.seed" -scheme hd > /dev/null
  go run ./ci/kind/tools/kindctl xpub "${K[@]/hot-0/btc-0}" > "$WORK/btc-0.xpub"; }
jq --arg x "$(cat "$WORK/btc-0.xpub")" '. + {btc_keyset: "btc-0", xpub: $x}' "$WORK/hot-0.json" > "$OUT"
echo "DKG done: $(cat "$OUT")"

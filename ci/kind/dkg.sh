#!/usr/bin/env bash
# The DKG of the hot keyset through party A's caller port (what `qv-party-admin` will do from a Job, PR #112): 2-of-3 over the three party pods. Writes the keyset's public key and address to
# $WORK/hot-0.json. Skips when that file exists. kindctl is the lane's stand-in for the operator CLI; the admin seed stays in the gitignored work dir.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$QV_KIND_ROOT"
OUT="$WORK/hot-0.json"; [ -s "$OUT" ] && { echo "DKG done: $(cat "$OUT")"; exit 0; }
g() { kn "$NS_SIGN" get secret qv-signing-gateway-party-tls -o jsonpath="{.data.$1}" | base64 -d; }
g 'tls\.crt' > "$WORK/gwp.crt"; ( umask 077; g 'tls\.key' > "$WORK/gwp.key" )
PA="$(kn "$NS_SIGN" get secret qv-signing-mpc-party-a-tls -o jsonpath='{.data.tls\.crt}' | base64 -d | openssl x509 -noout -pubkey | openssl pkey -pubin -outform DER | openssl dgst -sha256 -hex | awk '{print $NF}')"
for ns in $NS_SIGN $NS_B $NS_C; do kn "$ns" wait --for=condition=Ready pod -l app.kubernetes.io/name=qv-party --timeout=180s >/dev/null; done
trap pf_stop EXIT
pf_start "$NS_SIGN" svc/qv-party-a-caller 7001
go run ./ci/kind/tools/kindctl dkg -addr 127.0.0.1:$PF_PORT -cert "$WORK/gwp.crt" -key "$WORK/gwp.key" -pin "$PA" -seed "$WORK/secrets/admin.seed" -id hot-0 > "$OUT"
echo "DKG done: $(cat "$OUT")"

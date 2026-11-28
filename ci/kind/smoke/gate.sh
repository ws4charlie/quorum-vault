#!/usr/bin/env bash
# Case: AgentGate onboarding (ci/kind/gate.sh) proves its output contract. With a Gate key made at test time:
#   1. gate.sh onboards it into namespace agentgate
#   2. a pod in agentgate with ONLY the output files (and Gate's own key) mounted gets a token by client credentials, calls /v2/gate/signatures with a signed
#      credential for a 0.01 USDC EIP-3009 payment (200), checks the signature against the token's EIP-712 domain and wallet_address, and submits
#      transferWithAuthorization to anvil: it mines and pays the payee (tools/kindgatepay)
#   3. gate.sh again changes nothing: same output files, no pod of the core, the gateway or the cosigners replaced, the same gate setting version
#   4. Reconcile is clean: the books followed the chain through the payment and the top-up (the lane's gas booking first, as every paying case does)
#   5. the network: from agentgate the business database is refused; from another namespace the core's port is refused
# Run after the cases that withdraw ETH (withdraw, crash) and after upgrade: the gate setting makes hot shard 0 Gate-governed (every asset of it), and
# upgrade reinstalls qv-business with values-kind.yaml alone.
. "$(dirname "${BASH_SOURCE[0]}")/wd-lib.sh"; set +e
rc=0; bad() { echo "FAIL: $*"; rc=1; }
GNS=agentgate OTHER=qv-gate-other POD=kind-gate-smoke img=nginx:1.27-alpine
d="$WORK/gate-smoke"; rm -rf "$d"; mkdir -p "$d"; chmod 700 "$d"
trap 'wd_down; kn "$GNS" delete pod "$POD" --wait=false >/dev/null 2>&1; kn "$GNS" delete secret kind-gate-out kind-gate-key >/dev/null 2>&1; k delete namespace "$OTHER" --wait=false >/dev/null 2>&1; rm -rf "$d"' EXIT
t0=$SECONDS
go run ./ci/kind/tools/kindgate keygen -out "$d/key" || { bad "keygen"; exit 1; }
KID="kind-smoke-$(date +%s)"

echo "-- onboard"
ci/kind/gate.sh --pubkey "$d/key/gate.pub" --kid "$KID" --namespace "$GNS" --fund 1000000 --out "$d/out" || { bad "gate.sh failed"; exit 1; }
for f in vault_url ca.crt tls.crt tls.key token_url token_ca.crt client_id client_secret audience wallet_id wallet_address chain_id rpc_url usdc_address; do
  [ -s "$d/out/$f" ] || bad "output file $f is missing or empty"
done
[ "$(cat "$d/out/chain_id")" = "$QV_KIND_CHAIN_ID" ] || bad "chain_id is $(cat "$d/out/chain_id"), want the lane's $QV_KIND_CHAIN_ID"
openssl x509 -in "$d/out/tls.crt" -noout -text 2>/dev/null | grep -q 'URI:spiffe://quorumvault/business/agentgate' || bad "tls.crt is not spiffe://quorumvault/business/agentgate"
grep -rqs "$(cat "$d/out/client_secret")" "$QV_KIND_ROOT" --include='*.yaml' --include='*.json' --exclude-dir=.work && bad "the client secret is in a repository file"

echo "-- pay from a pod in $GNS with only the output files"
CGO_ENABLED=0 GOOS=linux GOARCH="$(arch)" go build -o "$d/kindgatepay" ./ci/kind/tools/kindgatepay || bad "build kindgatepay"
kn "$GNS" create secret generic kind-gate-out --from-file="$d/out" > /dev/null
kn "$GNS" create secret generic kind-gate-key --from-file=gate.key="$d/key/gate.key" > /dev/null
jq -n --arg ns "$GNS" --arg n "$POD" --arg img "$img" '{apiVersion:"v1",kind:"Pod",metadata:{name:$n,namespace:$ns,labels:{app:"kind-gate-smoke"}},
  spec:{restartPolicy:"Never",automountServiceAccountToken:false,containers:[{name:"gate",image:$img,imagePullPolicy:"IfNotPresent",command:["sleep","600"],
    volumeMounts:[{name:"out",mountPath:"/out",readOnly:true},{name:"key",mountPath:"/gate",readOnly:true}]}],
  volumes:[{name:"out",secret:{secretName:"kind-gate-out",defaultMode:256}},{name:"key",secret:{secretName:"kind-gate-key",defaultMode:256}}]}}' | k apply -f - > /dev/null
kn "$GNS" wait --for=condition=Ready "pod/$POD" --timeout=90s > /dev/null || bad "the Gate pod did not start"
kn "$GNS" cp "$d/kindgatepay" "$POD:/tmp/kindgatepay" > /dev/null && kn "$GNS" exec "$POD" -- chmod 755 /tmp/kindgatepay || bad "copy kindgatepay into the pod"
res="$(kn "$GNS" exec "$POD" -- /tmp/kindgatepay -out /out -key /gate/gate.key -kid "$KID" -amount 10000)"; prc=$?
echo "payment: $res"
[ $prc = 0 ] && [ "$(jq -r .signer <<< "$res" 2>/dev/null | tr A-Z a-z)" = "$(tr A-Z a-z < "$d/out/wallet_address")" ] || bad "the payment from the Gate pod failed"

echo "-- a second run changes nothing"
snap() {
  ( cd "$d/out" && shasum ./* )
  kn "$NS_BIZ" get pods -l app.kubernetes.io/instance=qv-business -o json | jq -r '[.items[] | select(.metadata.deletionTimestamp==null) | .metadata.uid] | sort | join(",")'
  for ns in $NS_SIGN $NS_B $NS_C; do kn "$ns" get pods -o json | jq -r '[.items[] | select(.metadata.deletionTimestamp==null and (.metadata.name|test("^qv-guard")|not)) | .metadata.uid] | sort | join(",")'; done
  jq -c . "$WORK/gate/applied.json"
}
before="$(snap)"
cp -R "$d/out" "$d/out1"
ci/kind/gate.sh --pubkey "$d/key/gate.pub" --kid "$KID" --namespace "$GNS" --fund 1000000 --out "$d/out" > "$d/rerun.log" 2>&1 || { cat "$d/rerun.log"; bad "the second gate.sh failed"; }
grep -q "nothing to apply" "$d/rerun.log" || bad "the second run applied a gate setting again"
grep -q "nothing booked\|no mint to book\|minted 10000 " "$d/rerun.log" || bad "the second run did not top up exactly the 0.01 USDC paid: $(grep -E 'usdc:|books:' "$d/rerun.log")"
after="$(snap)"
[ "$before" = "$after" ] || { bad "the second run changed something"; diff <(echo "$before") <(echo "$after"); }

echo "-- Reconcile"
wd_up; fund_hot > /dev/null || bad "fund_hot"
wd reconcile || bad "Reconcile is not clean after the payment and the top-up"
wd_down

echo "-- the network"
probe() { # ns host port -> 0 when the TCP connect works (as smoke/netpol.sh: it waits for the pod's policy to be programmed first)
  local ns="$1" host="$2" port="$3" name="probe-$RANDOM" ph out
  k -n "$ns" run "$name" --image=$img --image-pull-policy=IfNotPresent --restart=Never --command -- sh -c "sleep 6; nc -z -w 3 $host $port && echo OPEN || echo CLOSED" > /dev/null
  for _ in $(seq 60); do ph="$(k -n "$ns" get pod "$name" -o jsonpath='{.status.phase}')"; [ "$ph" = Succeeded ] || [ "$ph" = Failed ] && break; sleep 1; done
  out="$(k -n "$ns" logs "$name" 2>/dev/null)"; k -n "$ns" delete pod "$name" --wait=false > /dev/null
  [ "$out" = OPEN ]
}
core_ip="$(kn "$NS_BIZ" get svc qv-core -o jsonpath='{.spec.clusterIP}')"; db_ip="$(kn "$NS_BIZ" get svc qv-business-db-rw -o jsonpath='{.spec.clusterIP}')"
probe "$GNS" "$core_ip" 8443 || bad "control: $GNS cannot reach the core's port: the refusals below would prove nothing"
probe "$GNS" "$db_ip" 5432 && bad "$GNS reached the business database"
k create namespace "$OTHER" --dry-run=client -o yaml | k apply -f - > /dev/null
probe "$OTHER" "$core_ip" 8443 && bad "namespace $OTHER reached the core's port (only $GNS may)"
echo "gate case: $((SECONDS - t0)) s"
exit $rc

#!/usr/bin/env bash
# Case: tee-sim, a SIMULATED enclave (teesim.sh does the install; DESTRUCTIVE: it replaces the three parties, so it runs last). Shows: three attested parties ready with sealed TLS keys and no HSM mounted,
# a broker per party that released keys (audit log), a DKG through party A, and a restarted party that attests again and is ready without a human.
. "$(dirname "${BASH_SOURCE[0]}")/../lib.sh"; set +e
rc=0; bad() { echo "FAIL: $*"; rc=1; }
"$KDIR/teesim.sh" || { echo "teesim.sh failed"; exit 1; }
T="$WORK/tee"
for r in a b c; do
  case $r in a) ns=$NS_SIGN;; b) ns=$NS_B;; c) ns=$NS_C;; esac
  kn "$ns" wait --for=condition=Ready pod -l app.kubernetes.io/name=qv-party --timeout=120s >/dev/null || bad "party $r not ready"
  vols="$(kn "$ns" get statefulset "qv-party-$r" -o jsonpath='{.spec.template.spec.volumes[*].name}')"
  case " $vols " in *" hsm-pin "*|*" party-tls "*|*" hsm-module "*|*" softhsm-conf "*) bad "party $r still mounts an HSM or TLS-key volume: $vols";; esac
  kn "$ns" exec "qv-party-$r-0" -c mpc-party -- ls /var/lib/qv/party/data/tls-key.sealed.json >/dev/null 2>&1 || bad "party $r has no sealed TLS key in its data volume"
  n="$(kn "qv-broker-$r" exec "qv-tee-broker-$r-0" -- cat /var/lib/qv/broker/audit.log 2>/dev/null | grep -c '"outcome":"released"')"
  [ "${n:-0}" -ge 2 ] || bad "broker $r audit log has $n successful releases (want the enrolment and the start)"
  plog="$(kn "$ns" logs "qv-party-$r-0" -c mpc-party 2>/dev/null)"   # captured first: grep -q on a pipe can end it early
  case "$plog" in *QV-SIMULATED-ENCLAVE*) ;; *) bad "party $r does not log the simulation marker";; esac
done
[ -s "$T/tee-0.json" ] || bad "no DKG result"
# a restart: the party asks its broker again, the key comes back, no operator step
kn "$NS_B" delete pod qv-party-b-0 >/dev/null
sleep 5; kn "$NS_B" wait --for=condition=Ready pod/qv-party-b-0 --timeout=180s >/dev/null || bad "party B did not come back after a restart"
exit $rc

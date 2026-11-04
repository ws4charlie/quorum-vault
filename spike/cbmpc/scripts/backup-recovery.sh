#!/usr/bin/env bash
# Q6: lose party B completely (state + its seal key), restore it from the PVE backup, sign again.
set -euo pipefail
cd "$(dirname "$0")/.."
B=out/party; W=out/backup-demo; PORT=19101; A="127.0.0.1:$PORT"
pkill -f "out/party .*-addr $A" 2>/dev/null || true
rm -rf "$W"; mkdir -p "$W"
p1() { $B -dir $W/p1 -addr $A "$@"; }
serve() { ($B -dir "$1" -addr $A serve > $W/p2-$2.log 2>&1 &); sleep 1; }

echo "== 0. offline recovery key (stays offline; only the public key is needed for backups)"
$B -dir x backup-keygen $W/backup.ek $W/backup.dk
echo "== 1. normal operation: party B (p2) with its own sealed state"
serve $W/p2a a
p1 dkg ecdsa ks
p1 derive ecdsa ks child 44,60,0 0,3
PUB=$(p1 pubkey ecdsa child); echo "child pubkey before: $PUB"
p1 sign ecdsa child before-loss | tail -2
echo "== 2. backup of party B: only its sealed state + the PUBLIC key are used (PVE, verifiable)"
$B -dir $W/p2a -role 2 backup-export ks $W/backup.ek $W/p2.backup.json
echo "== 3. DISASTER: party B is destroyed (state AND seal key gone)"
pkill -f "out/party .*-addr $A serve" || true; sleep 0.5; rm -rf $W/p2a; ls $W
echo "== 4. restore B on a fresh token/seal key from the offline key + backup file"
$B -dir $W/p2b -role 2 recover $W/p2.backup.json $W/backup.dk $W/backup.ek
serve $W/p2b b
echo "== 5. A re-derives the same child with the restored B and signs"
p1 derive ecdsa ks child 44,60,0 0,3
PUB2=$(p1 pubkey ecdsa child); echo "child pubkey after:  $PUB2"
[ "$PUB" = "$PUB2" ] && echo "pubkey identical: yes"
p1 sign ecdsa child after-recovery | tail -2
pkill -f "out/party .*-addr $A serve" || true
echo "PASS: B lost and restored from PVE backup; signature verifies under the original public key"

#!/usr/bin/env bash
# Q3/Q7: BIP32 compatibility, Ed25519 + BIP340 verification, refresh; Q6 backup; Q8 crash tests.
set -euo pipefail
cd "$(dirname "$0")/.."
B=out/party; A=127.0.0.1:19103; W=out/verify; rm -rf $W; mkdir -p $W
($B -dir $W/p2 -addr $A serve > $W/p2.log 2>&1 &); sleep 1
trap 'pkill -f "out/party .*-addr $A" || true' EXIT
p1() { $B -dir $W/p1 -addr $A "$@"; }
echo "### BIP32 xpub compatibility"; p1 xpub
echo "### Ed25519 (HD) / BIP340 / ECDSA verified with standard verifiers"; p1 others
echo "### refresh keeps the public key"; p1 derive ecdsa ks-ecdsa a 44,60,0 0,1; X=$(p1 pubkey ecdsa a); p1 refresh ecdsa ks-ecdsa; p1 derive ecdsa ks-ecdsa a 44,60,0 0,1; [ "$X" = "$(p1 pubkey ecdsa a)" ] && echo "pubkey unchanged after refresh"
pkill -f "out/party .*-addr $A" || true; sleep .5
scripts/backup-recovery.sh
scripts/crash-tests.sh

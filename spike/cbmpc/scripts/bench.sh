#!/usr/bin/env bash
# Q5: measurements between two separate processes; loopback, then 20 ms simulated RTT (10 ms each way).
set -euo pipefail
cd "$(dirname "$0")/.."
B=out/party; A=127.0.0.1:19104; W=out/bench; D=${BENCH_SECONDS:-8}; rm -rf $W; mkdir -p $W
run() { # $1 = one-way delay
  pkill -f "out/party .*-addr $A" 2>/dev/null || true; sleep .3
  ($B -dir $W/p2 -addr $A -delay $1 serve > $W/p2.log 2>&1 &); sleep 1
  P=($B -dir $W/p1 -addr $A -delay $1)
  "${P[@]}" dkg ecdsa ks >/dev/null; "${P[@]}" derive ecdsa ks k 44,60,0 0,1 >/dev/null
  "${P[@]}" dkg eddsa ke >/dev/null; "${P[@]}" derive eddsa ke s 44,501 0,1 >/dev/null
  "${P[@]}" bench dkg ecdsa 10; "${P[@]}" bench derive ecdsa ks 100
  "${P[@]}" bench sign ecdsa k 1,8,32 $D; "${P[@]}" bench sign eddsa s 1,8,32 $D
}
echo "### loopback"; run 0s
echo "### 20 ms RTT"; run 10ms
pkill -f "out/party .*-addr $A" || true

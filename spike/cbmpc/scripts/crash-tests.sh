#!/usr/bin/env bash
# Q8: crash behaviour and isolation. p2 = the peer process, p1 = caller.
cd "$(dirname "$0")/.."
B=out/party; W=out/crash-demo; A="127.0.0.1:19102"
pkill -f "out/party .*-addr $A" 2>/dev/null; rm -rf $W; mkdir -p $W
p1() { $B -dir $W/p1 -addr $A -timeout 3s "$@"; }
start() { ($B -dir $W/p2 -addr $A -timeout 3s serve >> $W/p2.log 2>&1 &); sleep 0.8; }
alive() { pgrep -f "out/party .*-addr $A.* serve" >/dev/null && echo "peer process: ALIVE" || echo "peer process: DEAD"; }
start; p1 dkg ecdsa ks >/dev/null; p1 derive ecdsa ks k 44,60,0 0,1 >/dev/null; p1 sign ecdsa k warm | tail -1

for kind in 1 2 3; do
  case $kind in 1) n="C++ abort()";; 2) n="NULL dereference (SIGSEGV)";; 3) n="Go panic";; esac
  echo "== crash inside peer: $n"
  p1 crash $kind 2>&1 | grep "caller sees"; sleep 0.6; alive
  start; echo "-- peer restarted; caller signs again:"; p1 sign ecdsa k after-crash$kind | tail -2 | tr '\n' ' '; echo
done

echo "== kill -9 the peer in the middle of a signing loop"
( p1 loopsign k 400 > $W/loop.log 2>&1; echo "caller exit code $?" >> $W/loop.log ) &
sleep 1.2; echo "$(date +%H:%M:%S.%3N) kill -9 peer"; pkill -9 -f "out/party .*-addr $A.* serve"; sleep 1
tail -3 $W/loop.log
start; echo "-- peer restarted; caller signs again:"; p1 sign ecdsa k after-kill | tail -2 | tr '\n' ' '; echo

echo "== hung peer (SIGSTOP) -> caller must time out, not hang"
PID=$(pgrep -f "out/party .*-addr $A.* serve"); kill -STOP $PID
/usr/bin/time -p $B -dir $W/p1 -addr $A -timeout 3s sign ecdsa k hung 2>&1 | tail -4; kill -CONT $PID; sleep 0.5; kill -9 $PID; sleep 0.3
start

echo "== kill -9 the CALLER (p1) mid-signature; peer must survive"
( $B -dir $W/p1 -addr $A -timeout 3s loopsign k 400 > $W/loop2.log 2>&1 & echo $! > $W/p1.pid ); sleep 1.2; kill -9 $(cat $W/p1.pid); sleep 1; alive
echo "-- caller restarted:"; p1 sign ecdsa k after-caller-kill | tail -2 | tr '\n' ' '; echo

echo "== malformed protocol messages from the caller side (peer must not die)"
p1 fuzz k 2>&1 | tail -6; alive
p1 sign ecdsa k after-fuzz | tail -2 | tr '\n' ' '; echo
echo "== peer log:"; grep -v "^p2 listening" $W/p2.log | tail -12
pkill -f "out/party .*-addr $A" 2>/dev/null

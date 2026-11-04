#!/usr/bin/env bash
# ONE COMMAND: scripts/demo.sh
# Builds cb-mpc (pinned) + the spike, starts anvil (docker) and party B, then runs the EVM closed loop:
# DKG -> derive HD child -> sign an EIP-1559 digest with 2-party MPC -> mined on anvil -> sender == derived address.
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.docker/bin:$HOME/go/bin:$PATH"
scripts/fetch-build-cbmpc.sh
mkdir -p out
CGO_ENABLED=1 go build -o out/party ./cmd/party 2>&1 | grep -v '^ld: \|^# ' || true
go build -o out/ethdemo ./cmd/ethdemo
docker rm -f qv-anvil-p5a >/dev/null 2>&1 || true
docker run -d --rm --name qv-anvil-p5a -p 127.0.0.1:18545:8545 ghcr.io/foundry-rs/foundry:v1.8.5 "anvil --host 0.0.0.0 --chain-id 11155111" >/dev/null
cleanup() { docker rm -f qv-anvil-p5a >/dev/null 2>&1 || true; pkill -f "out/party .*-addr 127.0.0.1:19001" 2>/dev/null || true; }
trap cleanup EXIT
for i in $(seq 1 50); do curl -s -X POST -H 'content-type: application/json' --data '{"jsonrpc":"2.0","id":1,"method":"eth_chainId"}' http://127.0.0.1:18545 >/dev/null && break; sleep 0.2; done
rm -rf out/demo; mkdir -p out/demo
(out/party -dir out/demo/p2 -addr 127.0.0.1:19001 serve > out/demo/p2.log 2>&1 &)
sleep 1
out/ethdemo -p1dir out/demo/p1 -addr 127.0.0.1:19001 -rpc http://127.0.0.1:18545

#!/usr/bin/env bash
# Case: one EVM and one Bitcoin withdrawal, signed by the pods (gateway -> party A, cosigner B, ECDSA 2-of-3 for the EVM hot key, HD keyset for the Bitcoin key), approved by the auto approver
# of the worker, paid on the local chain exactly once, Reconcile clean after each. The deposits are real deposits to the customer's address; the sweep of the EVM deposit is signed by the pods too.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/wd-lib.sh"
trap wd_down EXIT
echo "-- EVM"
use_custody evm
# gas money on the hot shard: on the chain (kindcfg chain did that) and in the books (the operator's step)
fund_hot
# -hot: setup waits for the deposit to be SWEPT into the hot shard by the pods, not only for the balance
wd setup -asset ETH -customer kind-eth -amount 5000000000000000000 -hot "$(evm_hot)"
OUT="$(wd pay -asset ETH -customer kind-eth -amount 10000000000000000)"; echo "$OUT"
wd settle -asset ETH -id "$(jq -r .id <<< "$OUT")" -to "$(jq -r .to <<< "$OUT")" -amount 10000000000000000

echo "-- Bitcoin"
use_custody btc
HOT="$(jq -r '.chain.btc.hot_shards[0].address' "$C/custody-btc.json")"
wd setup -asset BTC -customer kind-btc -amount 50000000 -hot "$HOT" -hot-sats 20000000
OUT="$(wd pay -asset BTC -customer kind-btc -amount 1000000)"; echo "$OUT"
wd settle -asset BTC -id "$(jq -r .id <<< "$OUT")" -to "$(jq -r .to <<< "$OUT")" -amount 1000000
use_custody evm

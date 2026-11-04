#!/usr/bin/env bash
# Rebuilds the bytecode that internal/chain/evm embeds. Uses the pinned Foundry
# image (solc 0.8.26, cancun, no metadata hash, see foundry.toml), so the output
# is byte-for-byte reproducible. Run from anywhere; commit the changed files.
set -euo pipefail
export PATH="$HOME/.docker/bin:$PATH"
root="$(cd "$(dirname "$0")/.." && pwd)"
image="ghcr.io/foundry-rs/foundry:v1.8.5"
art="internal/chain/evm/artifacts"
mkdir -p "$root/$art" "$root/internal/chain/evm/testdata"
docker run --rm -v "$root":/repo -w /repo/contracts --entrypoint sh "$image" -c "
  set -e
  forge build >/dev/null
  forge inspect Forwarder bytecode        > /repo/$art/Forwarder.bin
  forge inspect ForwarderFactory bytecode > /repo/$art/ForwarderFactory.bin
  forge inspect ForwarderFactory abi --json > /repo/$art/ForwarderFactory.abi.json
  forge inspect Forwarder abi --json      > /repo/$art/Forwarder.abi.json
  forge inspect UsdtLike bytecode         > /repo/internal/chain/evm/testdata/UsdtLike.bin
  forge inspect SweepFactory bytecode     > /repo/internal/chain/evm/testdata/SweepFactory.bin
  forge inspect SweepFactory abi --json   > /repo/internal/chain/evm/testdata/SweepFactory.abi.json
  forge inspect FalseToken bytecode       > /repo/internal/chain/evm/testdata/FalseToken.bin
  forge inspect BoolToken bytecode        > /repo/internal/chain/evm/testdata/BoolToken.bin
  forge inspect UsdtLike abi --json       > /repo/internal/chain/evm/testdata/Token.abi.json
  rm -rf out cache
"
echo "rebuilt $art (Forwarder, ForwarderFactory) and testdata (mock tokens)"

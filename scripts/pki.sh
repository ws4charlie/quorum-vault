#!/usr/bin/env bash
# Makes the development certificate authorities (one per trust zone) and short-lived certificates for every service, under data/pki
# (gitignored; override with QV_PKI_DIR). Nothing is committed: like the PINs and the Keycloak passwords, they are made on your machine.
# CI and scripts/e2e-all.sh call it too, so every run has fresh ones. Run it again at any time to rotate the certificates: services pick the
# new files up without a restart. An existing CA is kept; delete data/pki to start over.
#   scripts/pki.sh                 CAs if missing, then all certificates (QV_PKI_LEAF_TTL, default 72h)
#   scripts/pki.sh renew [-every]  keep issuing until stopped
# It also makes the test CA of the simulated TEE attester (data/pki/tee).
# Production does not use this: the operator's PKI provides the files (docs/runbooks/certificates.md).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
export QV_PKI_DIR="${QV_PKI_DIR:-$ROOT/data/pki}"
mkdir -p "$(dirname "$QV_PKI_DIR")"
BIN="${QV_PKI_BIN:-$ROOT/bin/qv-pki}"
if [ ! -x "$BIN" ] || [ -n "$(find cmd/qv-pki internal/pki -newer "$BIN" -name '*.go' 2>/dev/null | head -1)" ]; then
  go build -o "$BIN" ./cmd/qv-pki
fi
if [ "${1:-}" = renew ]; then shift; exec "$BIN" renew "$@"; fi
"$BIN" init
"$BIN" issue
# Test CA of the simulated TEE attester (mock AWS Nitro documents, research/TEE.md): root and intermediate under $QV_PKI_DIR/tee. Built only with
# -tags teesim, so no production binary contains it; production verifies against the vendor's root. QV_PKI_TEE=0 skips it.
if [ "${QV_PKI_TEE:-1}" != 0 ]; then
  TEE_BIN="${QV_ATTEST_CA_BIN:-$ROOT/bin/qv-attest-ca}"
  if [ ! -x "$TEE_BIN" ] || [ -n "$(find mpc-party/internal/attest -newer "$TEE_BIN" -name '*.go' 2>/dev/null | head -1)" ]; then
    (cd mpc-party && go build -tags teesim -o "$TEE_BIN" ./internal/attest/cmd/qv-attest-ca)
  fi
  "$TEE_BIN" -dir "$QV_PKI_DIR/tee"
fi
echo "pki: certificates in $QV_PKI_DIR (valid ${QV_PKI_LEAF_TTL:-72h})"

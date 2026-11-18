#!/usr/bin/env bash
# Makes the development certificate authorities (one per trust zone) and short-lived certificates for every service, under data/pki
# (gitignored; override with QV_PKI_DIR). Nothing is committed: like the PINs and the Keycloak passwords, they are made on your machine.
# CI and scripts/e2e-all.sh call it too, so every run has fresh ones. Run it again at any time to rotate the certificates: services pick the
# new files up without a restart. An existing CA is kept; delete data/pki to start over.
#   scripts/pki.sh                 CAs if missing, then all certificates (QV_PKI_LEAF_TTL, default 72h)
#   scripts/pki.sh renew [-every]  keep issuing until stopped
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
echo "pki: certificates in $QV_PKI_DIR (valid ${QV_PKI_LEAF_TTL:-72h})"

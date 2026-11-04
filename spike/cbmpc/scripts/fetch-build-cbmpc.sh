#!/usr/bin/env bash
# Fetch cb-mpc at a PINNED commit into the gitignored .deps/ and build it natively (macOS arm64/x86_64, Linux).
# Needs: git, cmake (>=3.20), a C++17 compiler (clang 20+ recommended), make, curl, perl. Nothing is installed system-wide.
set -euo pipefail
cd "$(dirname "$0")/.."
TAG=v0.2.2
COMMIT=2f2c4f1005729bd575b6f17bce8a47478df7ce78      # cb-mpc v0.2.2, first release with both ECDSA-2PC fixes (GHSA-h3cp-c5xm-jjj8)
D="$PWD/.deps"; SRC="$D/cb-mpc"; SSL="$D/openssl-3.6.4-install"
mkdir -p "$D"
if [ ! -d "$SRC/.git" ]; then git clone -q --depth 1 --branch "$TAG" https://github.com/coinbase/cb-mpc "$SRC"; fi
[ "$(git -C "$SRC" rev-parse HEAD)" = "$COMMIT" ] || { echo "cb-mpc HEAD != pinned $COMMIT" >&2; exit 1; }
git -C "$SRC" submodule update --init --depth 1 vendors/secp256k1 vendors/googletest
if [ ! -f "$SSL/lib/libcrypto.a" ] && [ ! -f "$SSL/lib64/libcrypto.a" ]; then
  # cb-mpc needs its own patched static OpenSSL 3.6.4 (script verifies the tarball SHA-256)
  export CBMPC_OPENSSL_ROOT="$SSL"
  case "$(uname -s)-$(uname -m)" in
    Darwin-arm64)  (cd "$SRC" && bash scripts/openssl/build-static-openssl-macos-m1.sh) ;;
    Darwin-x86_64) (cd "$SRC" && bash scripts/openssl/build-static-openssl-macos.sh) ;;
    Linux-*)       (cd "$SRC" && bash scripts/openssl/build-static-openssl-linux.sh) ;;
  esac
fi
ln -sfn "$SSL" "$D/openssl"
cmake -S "$SRC" -B "$SRC/build/Release" -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=OFF -DCBMPC_OPENSSL_ROOT="$SSL" >/dev/null
cmake --build "$SRC/build/Release" -j"$( (nproc || sysctl -n hw.ncpu) 2>/dev/null)" >/dev/null
ls -la "$SRC/lib/Release/libcbmpc.a"

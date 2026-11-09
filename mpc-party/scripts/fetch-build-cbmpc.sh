#!/usr/bin/env bash
# Fetch cb-mpc at the commit pinned in ../cbmpc.pin into the gitignored .deps/ and build it
# (static OpenSSL 3.6.4 + libcbmpc.a). No sudo, nothing installed system-wide.
# Needs: git, cmake >= 3.20, ninja or make, a C++17 compiler (clang recommended), curl, perl, tar.
# Works on macOS arm64/x86_64 and Linux x86_64/arm64.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=../cbmpc.pin
. "$ROOT/cbmpc.pin"
D="$ROOT/.deps"
SRC="$D/cb-mpc"
SSL="$D/openssl-3.6.4-install"
SELF_SHA="$( (shasum -a 256 "$0" 2>/dev/null || sha256sum "$0") | cut -d' ' -f1)"
STAMP="$D/BUILD_STAMP"
WANT="commit=$CBMPC_COMMIT script=$SELF_SHA"

mkdir -p "$D"
if [ -f "$STAMP" ] && [ "$(cat "$STAMP")" = "$WANT" ] && [ -f "$SRC/lib/Release/libcbmpc.a" ]; then
  echo "cb-mpc $CBMPC_TAG ($CBMPC_COMMIT) already built"; exit 0
fi
rm -f "$STAMP"

if [ ! -d "$SRC/.git" ]; then
  git clone -q --depth 1 --branch "$CBMPC_TAG" https://github.com/coinbase/cb-mpc "$SRC"
fi
HEAD_NOW="$(git -C "$SRC" rev-parse HEAD)"
if [ "$HEAD_NOW" != "$CBMPC_COMMIT" ]; then
  echo "FATAL: cb-mpc source is at $HEAD_NOW but the pin is $CBMPC_COMMIT ($CBMPC_TAG). Delete $SRC or fix cbmpc.pin." >&2
  exit 1
fi
if [ -n "$(git -C "$SRC" status --porcelain --untracked-files=no)" ]; then
  echo "FATAL: $SRC has local modifications" >&2; exit 1
fi
git -C "$SRC" submodule update --init --depth 1 vendors/secp256k1 vendors/googletest

if [ ! -f "$SSL/lib/libcrypto.a" ] && [ ! -f "$SSL/lib64/libcrypto.a" ]; then
  # cb-mpc's own build script for its patched static OpenSSL; it checks the tarball SHA-256.
  # Upstream scripts download into /tmp; run a copy that uses a private work dir instead.
  export CBMPC_OPENSSL_ROOT="$SSL"
  case "$(uname -s)-$(uname -m)" in
    Darwin-arm64)  S=build-static-openssl-macos-m1.sh ;;
    Darwin-x86_64) S=build-static-openssl-macos.sh ;;
    Linux-*)       S=build-static-openssl-linux.sh ;;
    *) echo "unsupported platform $(uname -sm)" >&2; exit 1 ;;
  esac
  WORK="$D/openssl-work"; rm -rf "$WORK"; mkdir -p "$WORK"
  sed "s#^cd /tmp\$#cd \"$WORK\"#" "$SRC/scripts/openssl/$S" > "$D/$S"
  grep -q "cd \"$WORK\"" "$D/$S" || { echo "FATAL: upstream openssl script layout changed ($S)" >&2; exit 1; }
  (cd "$SRC" && bash "$D/$S")
  rm -rf "$WORK"
fi
ln -sfn "$(basename "$SSL")" "$D/openssl"   # relative: the cache can move

GEN=()
command -v ninja >/dev/null 2>&1 && GEN=(-G Ninja)
cmake -S "$SRC" -B "$SRC/build/Release" ${GEN[@]+"${GEN[@]}"} -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=OFF \
  -DCBMPC_OPENSSL_ROOT="$SSL" >/dev/null
cmake --build "$SRC/build/Release" -j"$( (nproc || sysctl -n hw.ncpu) 2>/dev/null || echo 2)" >/dev/null
test -f "$SRC/lib/Release/libcbmpc.a"
echo "$WANT" > "$STAMP"
ls -la "$SRC/lib/Release/libcbmpc.a"
echo "built cb-mpc $CBMPC_TAG ($CBMPC_COMMIT)"

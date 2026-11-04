#!/usr/bin/env bash
# Install the C++ toolchain that cb-mpc is built with on Debian/Ubuntu (what CI's ubuntu-latest needs): clang-20 from
# apt.llvm.org (the same source as cb-mpc's own Dockerfile), cmake, ninja, perl, curl. Needs root or sudo.
# The LLVM signing key is checked against its published fingerprint before it is trusted.
set -euo pipefail
SUDO=""; [ "$(id -u)" = 0 ] || SUDO="sudo"
LLVM_KEY_FPR="6084F3CF814B57C1CF12EFD515CF4D18AF4F7421"
CODENAME="$(. /etc/os-release && echo "${VERSION_CODENAME}")"
$SUDO apt-get update -qq
$SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
  ca-certificates curl gnupg git cmake ninja-build make perl xz-utils >/dev/null
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
curl -fsSL https://apt.llvm.org/llvm-snapshot.gpg.key -o "$TMP/llvm.key"
GOT="$(gpg --show-keys --with-colons "$TMP/llvm.key" | awk -F: '/^fpr/ {print $10}' | tr '\n' ' ')"
case " $GOT " in *" $LLVM_KEY_FPR "*) ;; *) echo "FATAL: LLVM apt key fingerprint mismatch: $GOT" >&2; exit 1 ;; esac
gpg --dearmor <"$TMP/llvm.key" | $SUDO tee /usr/share/keyrings/llvm-archive-keyring.gpg >/dev/null
echo "deb [signed-by=/usr/share/keyrings/llvm-archive-keyring.gpg] http://apt.llvm.org/${CODENAME}/ llvm-toolchain-${CODENAME}-20 main" \
  | $SUDO tee /etc/apt/sources.list.d/llvm20.list >/dev/null
$SUDO apt-get update -qq
$SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends clang-20 >/dev/null
clang-20 --version | head -1
cmake --version | head -1

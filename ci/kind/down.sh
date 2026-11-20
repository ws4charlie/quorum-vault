#!/usr/bin/env bash
# Removes this checkout's kind cluster and its generated files.   make kind-down
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
kind delete cluster --name "$QV_KIND_NAME" || true
rm -rf "$WORK"
echo "removed $QV_KIND_NAME"

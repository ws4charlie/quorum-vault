#!/usr/bin/env bash
# Removes this checkout's kind cluster and its generated files.   make kind-down
# The keep dir (Gate's keyset hot-1, keep mode: README "Keep mode") is outside the work dir and is never removed here: make kind-gate-forget does that.
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
kind delete cluster --name "$QV_KIND_NAME" || true   # down is idempotent: no cluster is not an error
rm -rf "$WORK"
echo "removed $QV_KIND_NAME"
if k="$(keep_dir 2>/dev/null)" && [ -f "$k/$KEEP_MARK" ]; then echo "kept $k (Gate's keyset hot-1, address $(jq -r '.address // "?"' "$k/hot-1.json" 2>/dev/null || echo '?')): make kind-gate-forget deletes it"; fi

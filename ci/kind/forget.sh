#!/usr/bin/env bash
# Deletes this cluster's keep dir (Gate's keyset hot-1 kept by keep mode, README "Keep mode"): the next kind-gate makes a new key and address.
#   make kind-gate-forget [YES=1]      asks first unless YES=1
# It removes only a lane keep dir (one with the mark gate.sh writes), never another directory QV_KIND_KEEP_DIR may point at.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
KEEP="$(keep_dir)"
[ -e "$KEEP" ] || { echo "no keep dir for $QV_KIND_NAME ($KEEP): nothing to forget"; exit 0; }
[ -d "$KEEP" ] && [ -f "$KEEP/$KEEP_MARK" ] || { echo "forget.sh: $KEEP is not a lane keep dir (no $KEEP_MARK): not removed" >&2; exit 1; }
addr="$(jq -r '.address // "?"' "$KEEP/hot-1.json" 2>/dev/null || echo '?')"
if [ "${YES:-}" != 1 ]; then
  [ -t 0 ] || { echo "forget.sh: not a terminal: give YES=1 to delete $KEEP" >&2; exit 2; }
  printf 'Delete %s (Gate keyset hot-1, address %s)? The key cannot be recovered; funds on that address are lost to the lane. Type yes: ' "$KEEP" "$addr"
  read -r ans; [ "$ans" = yes ] || { echo "kept $KEEP"; exit 1; }
fi
rm -rf "$KEEP"
echo "removed $KEEP (address $addr is forgotten)"

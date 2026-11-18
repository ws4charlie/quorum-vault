#!/bin/sh
# Starts the gate and reloads it when its certificate files change (nginx reads them at start and reload only).
set -u
sum() { cksum /pki/tls.crt /pki/ca.crt 2>/dev/null | tr -d '\n'; }
last="$(sum)"
( while sleep "${QV_TLS_SYNC:-10}"; do now="$(sum)"; [ "$now" = "$last" ] || { last="$now"; nginx -s reload; }; done ) &
exec nginx -g 'daemon off;'

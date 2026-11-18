#!/bin/bash
# Starts Redpanda and, once it is up, makes the access rules (acl.sh, with the admin certificate); the health check waits for them
# (/tmp/acl-ready), so "healthy" means the broker takes TLS clients and the rules are in place.
set -u
# Redpanda reloads a certificate when its file changes (inotify), which events from a host bind mount do not always carry (Docker on macOS). So it reads
# a local copy, and this loop overwrites the copy in place when the mounted files change: a rotated certificate then needs no restart anywhere.
mkdir -p /tmp/tls
sync_tls() { cp /pki/tls.key /tmp/tls/tls.key.new && cp /pki/ca.crt /tmp/tls/ca.crt && cp /pki/tls.crt /tmp/tls/tls.crt.new && cat /tmp/tls/tls.key.new > /tmp/tls/tls.key && cat /tmp/tls/tls.crt.new > /tmp/tls/tls.crt; }
sync_tls
( while sleep "${QV_TLS_SYNC:-5}"; do cmp -s /pki/tls.crt /tmp/tls/tls.crt.new || sync_tls; done ) &
(
  until rpk cluster health -X brokers=localhost:9092 -X tls.enabled=true -X tls.ca=/pki/ca.crt -X tls.cert=/admin/tls.crt -X tls.key=/admin/tls.key 2>/dev/null | grep -qE 'Healthy:.+true'; do sleep 2; done
  until /bin/bash /cfg/acl.sh; do sleep 2; done
  touch /tmp/acl-ready
) &
exec /entrypoint.sh "$@"

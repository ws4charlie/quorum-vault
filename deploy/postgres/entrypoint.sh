#!/bin/sh
# Starts Postgres with TLS and client-certificate authentication only. Mounted files (read-only): /pki (tls.crt, tls.key, ca.crt of this server: the
# server's own certificate and the ONE authority whose clients it accepts), /cfg/pg_hba.conf and /cfg/pg_ident.conf.
# Postgres wants the key owned by its user with mode 0600, which a bind mount cannot give, so the files are copied. A loop copies them again when they
# change and reloads the server, which is how a rotated server certificate is picked up without a restart.
set -eu
copy() {
  mkdir -p /tls
  cp /pki/tls.crt /pki/tls.key /pki/ca.crt /cfg/pg_hba.conf /cfg/pg_ident.conf /tls/
  chown postgres /tls/* 2>/dev/null || true
  chmod 600 /tls/tls.key
}
copy
( while sleep "${QV_PG_TLS_RELOAD:-30}"; do
    if ! cmp -s /pki/tls.crt /tls/tls.crt || ! cmp -s /pki/ca.crt /tls/ca.crt; then
      copy && psql -U "$POSTGRES_USER" -d postgres -qtc 'select pg_reload_conf()' >/dev/null 2>&1 || true
    fi
  done ) &
exec docker-entrypoint.sh postgres \
  -c ssl=on -c ssl_cert_file=/tls/tls.crt -c ssl_key_file=/tls/tls.key -c ssl_ca_file=/tls/ca.crt -c ssl_min_protocol_version=TLSv1.3 \
  -c hba_file=/tls/pg_hba.conf -c ident_file=/tls/pg_ident.conf

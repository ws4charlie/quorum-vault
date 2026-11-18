# Service certificates: rotating, renewing, and what production must supply

Every service reaches its peers with a certificate from its zone's private CA. Certificates are short-lived (hours to days) and each service re-reads its files on a timer, so renewal is "put new files in place".

## Names and zones

- Name: a URI SAN `spiffe://quorumvault/<zone>/<service>`, plus DNS names (and IPs) for the host-name check on server certificates.
- Zones: `business` (core, worker, relay, archiver, guardian, and the stores they use) and `signing` (gateway, cosigner, parties and their guard databases). One CA each; a service trusts only its own zone's CA. A link that crosses zones is explicit: the business CA issues a `*-link` visitor certificate to the signing-zone program (see `internal/pki/catalog.go`).
- A server keeps an allow-list of names per endpoint. For qv-core: `-service-allow` (default `business/guardian,business/worker`); services calling with a client-credentials token must show one of them. People send a bearer token and no certificate.

## What a service needs

Three files per identity, flags or `QV_TLS_CERT`, `QV_TLS_KEY`, `QV_TLS_CA` (and `QV_TLS_RELOAD`, default `1m`, how often they are re-read):

| File | Content |
|---|---|
| certificate | PEM leaf, with the URI SAN above; usage server, client, or both as the service needs |
| key | its private key (never shared between services) |
| CA bundle | the zone's CA certificate; several during a CA roll |

A service refuses to start on an expired or not-yet-valid certificate, on one its CA bundle did not sign, or on one named for the other zone. Plain http needs `QV_ALLOW_PLAINTEXT=1` and `QV_ENV=dev`; production refuses it.

## Development

```bash
scripts/pki.sh                 # make the CAs if missing, then every certificate (QV_PKI_LEAF_TTL, default 72h)
scripts/pki.sh renew -every 24h  # keep issuing until stopped
```

Files land in `data/pki/<zone>/<service>/{tls.crt,tls.key,ca.crt}` (`QV_PKI_DIR` moves them). Running the script again rotates: files are replaced atomically, services pick them up within their reload interval. Delete `data/pki` to start over (every service then needs its files and a restart, since the CAs changed).

## Production: what the operator supplies

- A CA per zone, from the organisation's own PKI, with its key in an HSM or equivalent. QuorumVault never holds a CA key.
- Certificates for every service in `internal/pki/catalog.go`, with the URI SAN and the DNS names the clients dial, valid for days at most, renewed by an agent (Vault PKI, cert-manager, step-ca or similar) that rewrites the three files in place. Write the key before the certificate and replace files atomically (rename); a service that reloads a half-written pair keeps the old one and tries again.
- Renew at about one third of the lifetime left. The alert `QVTLSCertExpiringSoon` fires under 4 hours.

## Postgres

Every database connection is TLS with a client certificate; there is no password and no plain connection. The DSN must say `sslmode=verify-full` (a service refuses anything weaker; the development switch above is the only exception). A service gives its certificate by the same three files, so the pool dials every new connection with the file as it is then.

- **Who may connect.** Postgres cannot check a URI name. It trusts the ONE authority in `ssl_ca_file` and maps the certificate's common name (the service name) to a role in `pg_ident.conf`, with `hostssl ... cert map=...` in `pg_hba.conf`. A name that is not in the map is refused, whatever authority signed it. The files for development are in `deploy/postgres`.
- **Two servers.** The business database trusts only the business authority. The replay-guard databases of the gateway and the cosigner are on a separate server that trusts only the signing authority.
- **The one link between the zones.** The gateway reads the job queue in the business database. It does that with a second identity, `business/gateway-link`, a certificate the BUSINESS authority issued (flags `-link-tls-cert`, `-link-tls-key`, `-link-tls-ca`), which the map sends to the restricted role `qv_gateway` and to no other. The business server never trusts the signing authority, and the signing-zone certificate of the gateway is useless against it.
- **Server certificates** are copied into the container by `deploy/postgres/entrypoint.sh`, which copies them again when they change and reloads Postgres. In production use your own mechanism (`pg_ctl reload` after replacing the files).
- **Tests** read `DATABASE_URL` (business) and `QV_SIGNING_DB_URL` (signing zone), each naming the admin certificate files. `make` passes both; for `go test` by hand see `.env.example`.

## Checking and alerts

- Each service exports `qv_tls_cert_seconds_to_expiry{name,zone,kind="leaf"|"ca"}` and `qv_tls_cert_reload_failures_total` (qv-core: `-metrics-listen`, loopback only). Rules: `monitoring/tls-cert.rules.yml`.
- `qv-pki check -cert <file> -min 1h` exits non-zero when a certificate is about to run out.
- `QVTLSCertReloadFailing`: new files are on disk but unusable (half-written pair, wrong CA or zone, already expired). The service logs the reason and keeps the old certificate until it expires.

## Rolling a CA

1. Make the new CA and add its certificate to the CA bundle of every service in the zone (the bundle may hold both); wait for the reload interval.
2. Issue new leaf certificates from the new CA and replace the files.
3. When no certificate of the old CA is in use, remove it from the bundles.

## Clock skew

A certificate is valid from five minutes before it was issued. A machine more than that behind refuses it with "not valid before ... check this machine's clock". Fix the clock; do not widen the window.

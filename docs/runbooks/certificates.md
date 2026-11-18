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

## Kafka

Redpanda takes TLS with a client certificate from the business authority only, on every listener. The principal is the certificate's common name (the service name), mapped by `kafka_mtls_principal_mapping_rules`, and ACLs say what each name may do (`deploy/redpanda/acl.sh`, applied when the broker starts):

| Name | May |
|---|---|
| `relay` | publish and create the `qv.` topics |
| `gateway-link`, `cosigner-link` | publish to `qv.audit.heads` only |
| `archiver` | read `qv.audit.heads` in its consumer group |
| `admin` | everything (superuser: operators, tests) |

A name without a rule connects and can do nothing. The signing zone's programs publish their audit heads through the business-issued link certificates (the second explicit link between the zones); flags `-link-tls-*` on the gateway and the cosigner. Redpanda reads a copy of its certificate files that `deploy/redpanda/start.sh` refreshes, so a renewed server certificate needs no restart. In production use your own mechanism and the same ACLs.

## Temporal

The frontend takes TLS and requires a client certificate signed by the business authority; the files are re-read every minute (`TEMPORAL_TLS_REFRESH_INTERVAL`). The cluster's own traffic uses the same certificate, with the internal frontend for the system worker, and Temporal's database (`temporal-db`) is a TLS-only Postgres like the others (the certificate named `temporal` maps to role `temporal`). Clients present their own certificate and check the frontend's name (`business/temporal`).

Temporal checks the authority but not the NAME of a client certificate (its authorizer works on tokens, not certificates), so a name-checking gate sits in front of it (below).

## The archive store, the identity provider, and metrics

- **Archive store (S3).** The archiver reaches it over https only, with a client certificate (`-archive-tls-*`, the same three files as a service identity) and checks the store's name (`business/seaweedfs`). SeaweedFS verifies the client certificate against the business authority but cannot check its name; the access key identifies the caller. AWS S3 is reached as usual, without these flags.
- **Identity provider.** Keycloak in development serves https only, with a certificate of the business authority. The core takes the issuer URL as https (production refuses http) and trusts a private authority through `-oidc-ca-file` (`QV_OIDC_CA_FILE`); a public provider needs nothing. People's browsers and the token endpoint need no client certificate.
- **Metrics.** Plain http, on a loopback address only (the services refuse any other `-metrics-listen`): `qv-core`, `qv-relay`, `qv-anchor-archiver` and `qv-cosigner` publish `qv_tls_cert_seconds_to_expiry` that way; the gateway writes it into the textfile directory beside its MPC metrics (`*-tls.prom`); a scraper elsewhere reaches them through the host's own agent or a tunnel. The MPC parties' metrics port is their own (below).
- **The MPC parties** keep pinned certificates between the gateway and the parties and between the parties: a pin names exactly one certificate and has no CA to compromise, so for three parties it is stricter than a zone CA, and moving it adds a trust anchor for no gain. The cost is manual rotation (see the MPC runbooks). The catalog already holds the names `signing/mpc-party-a|b|c` for the day the mesh moves.
- **Temporal's names.** Temporal checks only the authority, so the frontend is not published: `temporal-gate` (nginx, TCP and TLS) is, and it admits the names `worker`, `core` and `admin` and closes the connection of every other certificate. Its log line per connection shows the name and the decision. In production put the same gate, or an authorizer plugin, in front of the frontend and keep the frontend itself on a private network.

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

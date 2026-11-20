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

## On Kubernetes

Chart `deploy/helm/qv-certs` (README there) makes the certificates; nothing else does.

- **Who issues.** cert-manager, from a Vault or OpenBao PKI, one issuer per zone. The CA keys stay in Vault; no cluster holds one, and a signing cluster's Vault role can sign only that cluster's names. A cluster's workload gets a link certificate (`gateway-link`, `cosigner-link-b`, `cosigner-link-c`) through a second issuer on the business PKI whose role signs those names and no others. kind and CI make a throwaway CA at install time instead.
- **Which names.** The list is generated from `internal/pki/catalog.go` (`go generate ./internal/pki`); a test fails when the chart and the catalog differ. Each catalog entry says which cluster holds it; the Secret is `qv-<name>-tls` (business) or `qv-signing-<name>-tls` (signing). Operator identities (`admin`) are not made in clusters; an operator asks the issuer.
- **Renewal.** cert-manager renews at one third of the lifetime left (72 h certificates, renewed 24 h ahead) with a new key each time. Services re-read the files every minute from the mounted Secret (a volume, never `subPath`), so nothing restarts. Trust comes from the ConfigMap `qv-trust-<zone>-<hash>` (immutable; the name carries a content hash), not from cert-manager's `ca.crt`; it changes only when an operator changes it (a CA roll: add the new CA to the bundle (a new ConfigMap name: point the services at it), wait, reissue, remove the old one).
- **Pinned identities** (`mpc-party-a|b|c`, `gateway-party`, `cosigner-socket`, `attest-broker`, `attest-caller-a|b|c`) live one year, are renewed 45 days ahead, and keep their key (`rotationPolicy: Never`), so a renewal changes no pin. To change a pinned key on purpose (yearly, or a suspected leak): delete the Secret of that Certificate in its cluster; cert-manager makes a new key; print the new pin (see "Printing a pin") and follow the key-rotation steps there, adding the new pin on every peer before the presenting side restarts. On a leak, remove the old pin at once.
- **Expiry alerts** are the ones above (`monitoring/tls-cert.rules.yml`, `QVTLSCertExpiringSoon`, `QVPinnedCertExpiringSoon`); a cert-manager `Certificate` that stays not Ready is a failed renewal: look at its `CertificateRequest` events.
- **The migration Job** has its own name, `migrator`, mapped to the owner role like `admin` (`deploy/postgres/business.pg_ident.conf`), so the Job's Secret opens nothing else.
- **Cosigner names.** Cosigners B and C have names of their own, see "Cosigner names" below.

## Cosigner names

Each cosigner has its own names; a certificate of one is no use as the other.

| Cosigner | Signing certificate (guard database client) | Link certificate (Kafka, audit heads) | Postgres role | Audit source |
|---|---|---|---|---|
| B | `cosigner-b` | `cosigner-link-b` | `qv_cosigner_b_guard` | `cosigner-b` |
| C | `cosigner-c` | `cosigner-link-c` | `qv_cosigner_c_guard` | `cosigner-c` |

Where the name is checked:
- **Postgres** (`deploy/postgres/signing.pg_ident.conf`): the certificate name maps to the role, and a role connects only to its own database. C's certificate at B's database is refused, with either role name (`TestGuardRolesAreSeparated`).
- **Kafka** (`deploy/redpanda/acl.sh`): `cosigner-link-b` and `cosigner-link-c` may publish `qv.audit.heads` and nothing else.
- **The cosigner itself.** It learns its role from its certificate and refuses to start unless the signing certificate is `cosigner-b` or `cosigner-c` and the link certificate is the matching `cosigner-link-<role>`. A reloaded file with another name is refused and the process keeps its own. It publishes its heads under its own name and labels its certificate metrics `qv-cosigner-b` / `qv-cosigner-link-b`. `qv-cosigner verify` needs `-source cosigner-b|cosigner-c` (`cosigner` for heads published before the split).
- **The party-to-cosigner socket** is checked by pinned key, as before; the gateway never calls a cosigner, so it has no name to check there.
- **Vault (production)**: the link issuer of cluster `party-b` signs `cosigner-link-b` only, and `party-c` signs `cosigner-link-c` only.

### Moving a running system from the shared name to the two names

Servers first, so they accept both names for a bounded time; then clients, one cosigner at a time; then remove the old name. Roll C first, then B. While one cosigner restarts its party answers "unavailable", so signing runs on the other pair (A+B or A+C); never restart both cosigners at once. No signing stops.

Per cosigner (role `b` or `c`):
1. **Accept both.**
   - Kafka: run the new `acl.sh` (adds `cosigner-link-b` and `-c`; the old `cosigner-link` rule stays).
   - Postgres of that cluster: the guard database **keeps its name** (`qv_cosigner_guard`; it holds the replay records and the audit chain, and the chart default keeps pointing at it, so the pod finds its history). Create `qv_cosigner_<role>_guard`, move ownership only (`ALTER DATABASE qv_cosigner_guard OWNER TO`, `REASSIGN OWNED BY qv_cosigner_guard TO qv_cosigner_<role>_guard`), `GRANT qv_cosigner_<role>_guard TO qv_cosigner_guard` so the running pod keeps working, and add `qv cosigner-<role> qv_cosigner_<role>_guard` to the map **beside** the old `qv cosigner qv_cosigner_guard` line.
2. **Issue.** Upgrade `qv-certs`: it now issues `cosigner-<role>` and `cosigner-link-<role>` in this cluster.
   Before step 3: **a cosigner cannot tell an empty guard database from a new install, so it does not refuse to start on one.** If the chart or the role points at a wrong or new database the cosigner starts with no replay history and no audit chain: before the switch, check that the database in `QV_COSIGNER_GUARD_DSN` is the old one (`SELECT count(*) FROM audit_log`) and compare after the switch.
3. **Switch.** Upgrade `qv-party` (new image, default Secrets and role of the new names). The pod restarts. Check the log line `"cosigner":"cosigner-<role>"`, a published head under that source and a signature through the party.
4. **Remove the old name** after both cosigners run on the new names: delete the old `cosigner-link` ACL rule, the old map line, the membership and the old **role** `qv_cosigner_guard` (never the database of that name), and the old Secrets.
5. **Test the refusal.** Keep a copy of the old certificate files before step 4 and try them after: Postgres and Kafka must refuse them. Also try C's new certificate at B's database: refused.

The compose files and the e2e stacks need no step: they take the files from `qv-pki`, which issues the new names.

## Postgres

Every database connection is TLS with a client certificate; there is no password and no plain connection. The DSN must say `sslmode=verify-full` (a service refuses anything weaker; the development switch above is the only exception). A service gives its certificate by the same three files, so the pool dials every new connection with the file as it is then.

- **Who may connect.** Postgres cannot check a URI name. It trusts the ONE authority in `ssl_ca_file` and maps the certificate's common name (the service name) to a role in `pg_ident.conf`, with `hostssl ... cert map=...` in `pg_hba.conf`. A name that is not in the map is refused, whatever authority signed it. The files for development are in `deploy/postgres`.
- **One role per service.** The map sends each name to a role of its own, not to the owner: `core` to `qv_core`, `worker` to `qv_worker`, `relay` to `qv_relay`, `archiver` to `qv_archiver` (no rights: it never connects), `gateway-link` to `qv_gateway`. Only `admin` is the owner role `qv`, for migrations and operator tools. A login role must equal the DSN user, so each service's DSN names its own role (`postgres://qv_core@...`). The rights are in migration `0030_service_roles.sql`; how to run migrations and enable login is in [database roles](database-roles.md).
- **Two servers.** The business database trusts only the business authority. The replay-guard databases of the gateway and the cosigner are on a separate server that trusts only the signing authority; there `gateway` maps to `qv_gateway_guard`, `cosigner-b` to `qv_cosigner_b_guard` and `cosigner-c` to `qv_cosigner_c_guard`, each the owner of its own guard database.
- **The one link between the zones.** The gateway reads the job queue in the business database. It does that with a second identity, `business/gateway-link`, a certificate the BUSINESS authority issued (flags `-link-tls-cert`, `-link-tls-key`, `-link-tls-ca`), which the map sends to the restricted role `qv_gateway` and to no other. The business server never trusts the signing authority, and the signing-zone certificate of the gateway is useless against it.
- **Server certificates** are copied into the container by `deploy/postgres/entrypoint.sh`, which copies them again when they change and reloads Postgres. In production use your own mechanism (`pg_ctl reload` after replacing the files).
- **Tests** read `DATABASE_URL` (business) and `QV_SIGNING_DB_URL` (signing zone), each naming the admin certificate files. `make` passes both; for `go test` by hand see `.env.example`.

## Kafka

Redpanda takes TLS with a client certificate from the business authority only, on every listener. The principal is the certificate's common name (the service name), mapped by `kafka_mtls_principal_mapping_rules`, and ACLs say what each name may do (`deploy/redpanda/acl.sh`, applied when the broker starts):

| Name | May |
|---|---|
| `relay` | publish and create the `qv.` topics |
| `gateway-link`, `cosigner-link-b`, `cosigner-link-c` | publish to `qv.audit.heads` only |
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
- **Metrics in a pod (decision D12).** A scraper in a cluster reaches a pod address, not its loopback. *Business zone* (`qv-core`, `qv-relay`, `qv-anchor-archiver`): set `QV_METRICS_ALLOW_NON_LOOPBACK=1` (off by default) and `-metrics-listen 0.0.0.0:<port>`; a network policy must then admit only the Prometheus. *Signing zone* (`qv-cosigner`, `qv-gateway`, `mpc-party`): the switch is ignored by `qv-cosigner`, which stays on loopback; nothing scrapes into the zone. A sidecar in the same pod reads `127.0.0.1` (or the gateway's textfile directory on a shared `emptyDir`) and remote-writes outward. The party's `metrics_listen` has no loopback rule: bind it to `127.0.0.1` in the signing zone so only the sidecar reaches it.
- **Party-to-cosigner channel.** The pinned certificates of both ends export the same metric: `qv-cosigner-socket` (cosigner, `-metrics-listen`) and `mpc-party-<role>` (party, `metrics_listen`), `kind="leaf"`. Both are read once at start; the alert `QVPinnedCertExpiringSoon` warns 30 days ahead, and the two hour-level alerts cover them too.
- **The MPC parties** keep pinned keys between the gateway and the parties and between the parties: a pin names exactly one public key and has no CA to compromise, so for three parties it is stricter than a zone CA, and moving it adds a trust anchor for no gain. The catalog already holds the names `signing/mpc-party-a|b|c` for the day the mesh moves. A pin is the SHA-256 of the certificate's public key (SubjectPublicKeyInfo, SPKI), in hex; since this change it is no longer the hash of the whole certificate, so an automatic renewal with the same key (cert-manager `rotationPolicy: Never`) changes no pin and needs no config edit. The certificate must still be inside its validity period. An old-style pin (hash of the whole certificate) is not accepted: the refusal names the scheme ("pins are the SHA-256 of the public key (SPKI), not of the certificate ... replace it with ..."), and the log line gives the pin to use.
- **The party's cosigner channel** (the unix socket between party B or C and its own `qv-cosigner`) is mutual TLS with pinned keys, so a process that merely owns the socket path cannot answer "allow". The cosigner has its own certificate (`-socket-cert`, `-socket-key`) and pins the ONE party it serves (`-party-pins`: B's cosigner pins B's key, C's pins C's); the party pins the cosigner's key (`authorizer.cosigner_pins`) and presents its own `cert_file`. Both refuse to start without the material or with an expired certificate, and every failed handshake is "unavailable", never "allow". Plain text needs `QV_ALLOW_PLAINTEXT=1` and `QV_ENV=dev` or `test`; production refuses it. **Renewal with the same key:** nothing to configure; the pins stay valid (see "Printing a pin"). **Key rotation (restart, no CA):** (1) make the new key and certificate and print its pin; (2) add the new pin next to the old one on the side that trusts it and restart that process (`authorizer.cosigner_pins` and the party, or `-party-pins` and the cosigner); (3) put the new key and certificate in place on the presenting side and restart it; (4) remove the old pin and restart again. Renew before expiry: an expired certificate stops the channel (the party then cannot sign) until replaced.
- **Temporal's names.** Temporal checks only the authority, so the frontend is not published: `temporal-gate` (nginx, TCP and TLS) is, and it admits the names `worker`, `core` and `admin` and closes the connection of every other certificate. Its log line per connection shows the name and the decision. In production put the same gate, or an authorizer plugin, in front of the frontend and keep the frontend itself on a private network.

## Printing a pin

The pin of a certificate (`peer_pins`, `caller_pins`, `peer_a_pins`, `peer_b_pins`, `peer_c_pins`, `authorizer.cosigner_pins`, `-party-pins`, the gateway's `server_pin`, `qv-btc-xpub -server-pin`) is the SHA-256 of its public key:

```bash
openssl x509 -in party.crt -pubkey -noout | openssl pkey -pubin -outform DER | openssl dgst -sha256 -r | cut -d' ' -f1
```

A test checks this command against the code's value. Do not use `openssl x509 -fingerprint`: that hashes the whole certificate (the old scheme) and is refused.

- **Renewal with the same key** (cert-manager `rotationPolicy: Never`, or `openssl x509 -req` with the old key): the pin does not change. Install the new certificate and restart the process that presents it; no peer config changes.
- **The trade-off.** With whole-certificate pins a stolen private key was useful only until that certificate expired; with key pins, whoever holds the key can issue a new certificate for it, so the validity check no longer bounds a stolen key. The bound is now your key rotation: rotate every pinned key on a fixed schedule (at least yearly, or when someone who could read it leaves), and on a suspected leak rotate the key and remove its old pin at once, without waiting for the certificate to expire.
- **Key rotation**, one link at a time: add the new key's pin next to the old one on every peer that trusts it and restart them; deploy the new key and certificate on the presenting side and restart it; then remove the old pin and restart the peers. With `rotationPolicy: Always` this cannot be automatic: set `Never` on the certificates of pinned links.

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

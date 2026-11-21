# qv-certs: certificates on Kubernetes

Makes the cert-manager `Issuer` objects, one `Certificate` per identity of this cluster, and the per-zone trust bundles. It deploys no pod. Install it **once per cluster**, before the other charts, and tell it which cluster it is.

The list of identities is **generated from the catalog** (`internal/pki/catalog.go`) into `catalog.json` (`go generate ./internal/pki`). A Go test fails when the file and the catalog differ, and `ci/helm` fails when the render and the file differ, so the chart cannot drift from the code.

| `cluster` | Holds | Issuers |
|---|---|---|
| `business` | core, worker, relay, archiver, guardian, migrator, and the servers (Postgres, Temporal, Kafka, Keycloak, SeaweedFS) | `qv-business` |
| `signing-core` | gateway, party A, the guard database, the pinned links of A, `gateway-link` | `qv-signing`, `qv-business-link` |
| `party-b`, `party-c` | party and cosigner, the guard database, the cosigner socket, `cosigner-link-<role>` | `qv-signing`, `qv-business-link` |
| `broker` | the attestation broker's server certificate | `qv-signing` |
| `all` | everything (kind and CI only; needs `issuers.mode: ca`) | `qv-business`, `qv-signing` |

## Secret names (the contract with the other charts)

Each Certificate writes one Secret with `tls.crt`, `tls.key`, `ca.crt`. The name comes from the catalog name by one rule (Go: `pki.SecretName`; chart: helper `qv-certs.secretName`; the chart refuses to render when the two disagree):

| Zone | Secret |
|---|---|
| business (and the `*-link` names) | `qv-<name>-tls`, e.g. `qv-core-tls`, `qv-migrator-tls`, `qv-gateway-link-tls` |
| signing | `qv-signing-<name>-tls`, e.g. `qv-signing-gateway-tls`, `qv-signing-mpc-party-b-tls`, `qv-signing-cosigner-socket-tls` |

Charts that need a certificate copy the rule and read the Secret as a **volume, never `subPath`** (a subPath mount does not update; the services re-read the files every minute). The business chart's names (`qv-core-tls`, `qv-worker-tls`, `qv-relay-tls`, `qv-archiver-tls`) are unchanged; its migration Job now takes `qv-migrator-tls` (certificate name `migrator`, Postgres role `qv`). A test checks every Secret the business chart asks for in production against this chart's business render.

Pods that use a certificate in a party cluster: party `mpc-party-<role>` (peer port, caller port, and the channel to its cosigner), cosigner `cosigner-b` or `cosigner-c` (each its own name; client of the audit heads is `cosigner-link-b` or `-c`; its socket certificate is `cosigner-socket`), gateway `gateway` (signing CA), `gateway-link` (business databases and Kafka) and `gateway-party` (pinned client certificate on the parties' caller ports). The broker's callers use `attest-caller-<role>`.

## Trust: the bundle, not `ca.crt`

Mount the ConfigMap `qv-trust-<zone>-<hash>` (key `ca.crt`; label `quorumvault.io/trust-bundle=<zone>`; find the name with `kubectl -n <ns> get configmap -l quorumvault.io/trust-bundle=<zone> -o name` or `helm template`) as the CA file of a service, not the `ca.crt` inside the certificate Secret. cert-manager fills that file only for some issuers and changes it when the issuer's chain changes; a trust anchor must change only when an operator changes it. The bundle is therefore **immutable** and the last 10 hex characters of its name are a hash of its content: a changed CA is a new ConfigMap, the consumer changes one reference, and the old one is deleted by the listed writer (`qv-policy` refuses a mutable or unhashed ConfigMap in a signing cluster). The bundle comes from values (`--set-file trust.business=...`), is public, holds several CAs during a CA roll, and exists only for the zones the cluster holds identities of. trust-manager is not used: it is one more controller with cluster-wide rights in clusters whose admin is the thing being defended, to distribute two public files that change a few times a year.

## Issuers

- **Production (`issuers.mode: vault`)**: one cert-manager `Issuer` per zone, talking to Vault or OpenBao PKI with the cluster's own login (cert-manager asks Kubernetes for a token of a dedicated service account, which the chart makes with the minimal Role). **No CA key is in any cluster**, no Secret is rendered, no AppRole or token is in values. The chart refuses `http://` Vault addresses and empty settings.
- **kind and CI (`issuers.mode: ca`)**: a self-signed bootstrap, then a CA certificate per zone made by cert-manager when the chart is installed (key in a Secret of that cluster), then a CA issuer per zone. Nothing is in the repository.
- **Link certificates** (`gateway-link` in signing-core, `cosigner-link-b` in party-b, `cosigner-link-c` in party-c) are signed by the **business** authority for a workload in a signing cluster. They use a second issuer, `qv-business-link`, that points at a Vault role which can sign only that cluster's link names. In `ca` mode, outside kind's single cluster, it points at the business CA Secret named by `issuers.ca.linkSecretName` (development only: the business CA key would be in that cluster).

### Vault roles (one per cluster and zone)

The restriction is Vault's, not the chart's: a cluster's cert-manager can ask for only what its role lets it sign. Make the roles with `allow_any_name=false`, `enforce_hostnames=false`, `allow_ip_sans=true`, `server_flag`/`client_flag` as the catalog says, `key_type=ec`, `key_bits=256`, `max_ttl` at least the pinned lifetime for the roles that sign pinned names (8760h), and a Kubernetes-auth role bound to the service account and namespace of this release.

| Role (cluster) | `allowed_uri_sans` | `allowed_domains` for CN and DNS |
|---|---|---|
| `business-cluster` (business) | `spiffe://quorumvault/business/<name>` for the business names | those names and the DNS names of the servers |
| `signing-core` (signing PKI) | `spiffe://quorumvault/signing/{gateway,gateway-party,mpc-party-a,attest-caller-a,signing-db,admin}` | the same CNs |
| `party-b`, `party-c` (signing PKI) | ``.../signing/{cosigner-<role>,cosigner-socket,mpc-party-<role>,attest-caller-<role>,signing-db,admin}` | the same CNs |
| `broker` (signing PKI) | `.../signing/attest-broker` | `attest-broker` |
| `link-signing-core`, `link-party-b`, `link-party-c` (business PKI) | `spiffe://quorumvault/business/gateway-link` (signing-core), `.../business/cosigner-link-b` (party-b), `.../business/cosigner-link-c` (party-c) | `gateway-link` (signing-core); `cosigner-link-b` (party-b); `cosigner-link-c` (party-c): only that cluster's own name |

Because the CN is part of what Postgres and Kafka read, a role that can sign `core` as a CN must never be given to a signing cluster: keep the link roles on their own names.

## Pinned identities

Peers pin these by public key, so a renewal must keep the key: their Certificate sets `privateKey.rotationPolicy: Never` (all others `Always`) and lives one year, renewed 45 days ahead. They are `mpc-party-a|b|c`, `gateway-party`, `cosigner-socket`, `attest-broker`, `attest-caller-a|b|c`. A test fails if a pinned name could rotate its key. To **change** a pinned key, delete the Certificate's Secret (a new key and a new pin) and follow the key-rotation steps in `docs/runbooks/certificates.md`.

## Operator identities

`admin` (both zones) is for people and tools. It is not rendered in production (`operatorCertificates: false`): an owner-level client certificate must not sit in a Secret in a cluster. Operators get it from the issuer when they need it. kind renders it.

## kind: two steps

The CA does not exist before the first install, so the trust bundle cannot be in the first render:

```bash
helm install qv-certs deploy/helm/qv-certs -n qv -f deploy/helm/qv-certs/values-kind.yaml
kubectl -n qv get secret qv-business-ca -o jsonpath='{.data.tls\.crt}' | base64 -d > /tmp/business-ca.pem
kubectl -n qv get secret qv-signing-ca  -o jsonpath='{.data.tls\.crt}' | base64 -d > /tmp/signing-ca.pem
helm upgrade qv-certs deploy/helm/qv-certs -n qv -f deploy/helm/qv-certs/values-kind.yaml --set-file trust.business=/tmp/business-ca.pem --set-file trust.signing=/tmp/signing-ca.pem
```

## Checks

`ci/helm/certs-check.sh` (part of `make helm-check` and the helm workflow) lints and renders every cluster and kind, and validates the output with kubeconform against the Kubernetes schemas and the cert-manager CRD schemas from `datreeio/CRDs-catalog`, pinned to a commit. `ci/helm/certs_test.go` checks: each catalog identity appears exactly once, in the clusters the catalog names and nowhere else; no Secret, private key or PEM outside a trust bundle; pinned names never rotate keys; no signing issuer in the business cluster and the reverse, link names the only business-signed certificates in a signing cluster; no CA in production renders; refusals (no cluster, `all` with Vault, `http` Vault, empty trust); the business chart's Secret names are made here.

## Not in this chart

Per-namespace approval of who may request which name (cert-manager `approver-policy`, not researched), alerts (already in `monitoring/tls-cert.rules.yml`), the Vault side (mounts, roles, policies), and the services' own certificate flags (D3, D6, D7).

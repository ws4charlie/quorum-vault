# qv-business

Helm chart for the business zone: `qv-core`, `qv-worker`, `qv-relay`, `qv-anchor-archiver`, the database migration job and, optionally, the approval page (`qv-approval-web`). It creates no database, broker, Temporal or bucket and no certificate: it names them. Design: the Kubernetes deployment note (task D3); image contract: [`deploy/images/README.md`](../../images/README.md) and its machine-readable form [`contract.json`](../../images/contract.json).

One release serves **one chain cell**: `qv-core` and `qv-worker` each read one custody config, and the Temporal task queue is per chain. A second chain is a second release (set `archiver.enabled=false` there; one archiver reads the shared audit topic).

## What it deploys

| Piece | Kind | Replicas | Notes |
|---|---|---|---|
| core | Deployment, Service, Ingress | 2 | HTTPS on 8443, PDB `minAvailable: 1`, health-listener probes |
| worker | Deployment | 2 | PDB; queue `qv-core-<chain>` unless `worker.taskQueue` is set |
| relay | Deployment | 2 | `FOR UPDATE SKIP LOCKED` makes two safe; PDB |
| archiver | Deployment | 1 | refuses a bucket without Object Lock |
| migrate | two Helm hook Jobs | n/a | before install and upgrade, see below |
| approval page (optional, `approval.enabled`, **off**) | Deployment, Service, Ingress | 2 | own host, own origin; see "The approval page" |
| NetworkPolicies | default deny + one allow per path | n/a | see "Network" |

Every pod: uid/gid 65532, `runAsNonRoot`, read-only root filesystem, all capabilities dropped, no privilege escalation, seccomp `RuntimeDefault`, no host namespaces, service account token not mounted (the archiver may opt in for workload identity), requests and limits set. No process listens on a metrics port a scraper can reach: metrics are loopback-only in the binaries (decision D12), so the chart creates no metrics Service.

## Render and check

```bash
helm template qv deploy/helm/qv-business -n qv                                       # production defaults
helm template qv deploy/helm/qv-business -n qv -f deploy/helm/qv-business/values-kind.yaml
make helm-check                                                                      # lint, schema validation, policy and contract tests
```

`make helm-check` needs `helm` and `kubeconform` (`brew install helm kubeconform`). CI runs the same script in the `helm` workflow for changes under `deploy/helm/**` and `ci/helm/**`, with pinned, checksum-verified tools. The tests live in [`ci/helm`](../../../ci/helm): `TestPolicy*` (security rules over the rendered manifests) and `TestContract*` (the chart against `contract.json`); each check also has a test that breaks a manifest and wants the violation.

Production images are referenced **by digest**. The digests in `values.yaml` are all-zero placeholders and the chart **refuses to render** them: the release pipeline sets the real ones (from `deploy/images/publish.sh`) with `--set` or a values file. The checks use `ci/helm/ci-digests.yaml`. `values-kind.yaml` uses local tags.

Tested with Helm 4.3.2 (the chart is `apiVersion: v2`).

## The approval page

`approval.enabled: true` adds `qv-approval-web`: a static file server for the approvers' page (`web/approval`) that writes the page's `/config.json` from its settings. It holds no state, no secret, no database and makes no connection; the approver's *browser* talks to the identity provider and to the core.

| Setting | Meaning |
|---|---|
| `approval.ingress.host` (+ `className`, `tlsSecret`) | The page's own host. TLS ends at the Ingress; inside the cluster the page speaks plain http on `approval.port` (8090). |
| core's `-approval-origins` | **Not a value you set.** The chart writes `QV_APPROVAL_ORIGINS=https://<approval.ingress.host>` into the core's ConfigMap from the same value, so the page's origin and the core's CORS list cannot disagree. |
| `approval.clientId`, `oidc.issuer` | The page's public OIDC client and the identity provider (the same issuer the core trusts). Register the client with the page's origin as redirect URI. |
| the page's `api` | `https://<ingress.public.host>`, the core's public host. |
| `approval.assetDecimals`, `approval.maxLoginAge` | Display only / the page's sign-in age (keep it under the core's step-up age). |

- **Its own origin.** The host must differ from the core's (`ingress.public.host`, and `ingress.passthrough.host` when on): the chart **refuses to render** otherwise. A passkey is bound to the page's origin, and a page served from the API's origin would let any script of the API run as the page.
- **Network.** One NetworkPolicy admits the ingress controller to the page's port and nothing else. No egress rule selects the page's pods (the chart's DNS rule excludes them), so under the default deny it cannot open a connection, DNS included.
- **Pod.** The chart's hardening (uid 65532, read-only root filesystem, no capabilities, seccomp), no volume, 2 replicas with a PDB. Probes are `httpGet /config.json` (the server has no health listener).
- Tested in `ci/helm` (`approval_test.go`): off by default; on, it passes the policy and contract checks; the origin is one value; the same host is refused; no egress; ingress only from the controller.

## Configuration and secrets

| What | Where |
|---|---|
| Plain settings (addresses, OIDC, flags' environment) | one ConfigMap per component |
| The **whole custody config** (chain RPC URL, `rpc_user`, `rpc_password`, addresses, limits) | An existing Secret, `custody.existingSecret`, key `custody.key` (default `config.json`), mounted read-only at `/etc/qv/custody`. The chart renders no custody config. |
| Certificates and keys | Secret volumes mounted read-only, made by cert-manager (task D5); referenced by name under `tls.*` |
| Auto-approver seed (worker) | Secret `custody.autoApprover.secretName`, mounted as a file |
| Archive keys | Secret `archive.credentialsSecret` as files, or empty for workload identity |

The Secret is made outside the chart (External Secrets, sealed secrets, the kind lane's setup) and must hold one JSON file in the shape of `internal/custody/config.example.json`: the file `qv-core` and `qv-worker` read with `-config`. Both read the same Secret. The policy test refuses a ConfigMap with secret-looking fields, a password in a URL, a PEM block, or any Secret object in the chart's output. A later code task may split the credentials into their own file, so that only they need to be secret.

Database access: each service's DSN names its own role (`qv_core`, `qv_worker`, `qv_relay`) and the files of its own certificate; there is no password. Key files are mounted mode 0440 with `fsGroup` 65532, so only the image's user reads them.

## Migration

Two Helm hooks, `pre-install` and `pre-upgrade`, run before the Deployments are created or changed:

1. `qv-migrate` (hook weight -5) applies pending migrations as the owner role (certificate `migrator`, Postgres role `qv`; the Secret name is `tls.admin.secretName`, default `qv-migrator-tls`). Migrations must be backward compatible by one release, because old pods keep running while the new ones start.
2. `qv-migrate -enable-login` (weight -4) runs `ALTER ROLE ... LOGIN` for the service roles. It is **off by default** (`migration.enableLogin: false`) and on in `values-kind.yaml`. In production the database operator enables login for the roles (for example CloudNativePG managed roles); the binary's own flag is for development.

**Why a hook and not a separate step.** A hook gives the order with `helm upgrade` and with Flux's helm-controller (hooks run) and Argo CD (hooks map to PreSync) without extra tooling, and the migration is tied to the chart version that needs it. The services check at start that no migration is pending and refuse to run otherwise, so a skipped or failed hook fails safe: the new pods crash-loop and the old ones keep serving. If a deployment tool ignores hooks, run the same Job as its own step before the release; the templates are in `templates/migrate.yaml`.

The hook Jobs need the `admin` certificate Secret and the database to exist at install time. Hook objects (service account, network policy of the job) are created with the hook and are not removed by `helm uninstall`.

## Network

- **Default deny** for ingress and egress of every pod in the namespace, then one allow per path: DNS; each component to the dependencies it uses (Postgres, Kafka, Temporal gate, and for core, worker and archiver the IdP, chain nodes and archive store); the ingress controller and same-namespace pods to the core port.
- **Nothing pushes in from the signing zone.** The only ingress from outside the namespace besides the ingress controller is the **signing link**: `network.signingLink.from` may reach the business Postgres on 5432 (the gateway reads the job queue) and Redpanda on 9092 (the gateway and cosigners publish audit heads). With the list empty, no such rule exists. In production these peers are the private endpoint addresses of the signing clusters; a NetworkPolicy sees addresses, so the cloud network rules (no route from business into a signing VPC) are the other half, see the design note §7. The policy test fails on any other ingress from outside the namespace.
- **Ingress for the core.** People log in at the identity provider and come with bearer tokens; they need no certificate. So the public Ingress ends TLS at the controller (a certificate for the public name) and **re-encrypts** to the core, which serves TLS itself and checks a client certificate only when one is shown. Services (guardian, admin) present a certificate **and** a token (`docs/identity.md`); a certificate does not survive a terminating controller, so those callers reach the core inside the cluster, or through the second, private Ingress (`ingress.passthrough`, TLS passthrough on a private class), which passes the TLS session through untouched. The annotations are for ingress-nginx; other controllers or the Gateway API set their own through `ingress.*.annotations`.
- NetworkPolicy matches addresses, not names: `network.idp`, `network.chain` and `network.archive` default to public addresses (not the private ranges) on 443. Narrow them to the provider's addresses or private endpoints.
- `network.dependencyPolicies` also renders the minimum allow rules for the dependencies' own pods, because the default deny covers the namespace. Operators (CloudNativePG, Redpanda, Temporal charts) bring the rest (replication, API server access).

## Probes

Every component (core, worker, relay, archiver) runs the health listener of PR #97 (`QV_HEALTH_LISTEN=0.0.0.0:<healthPort>`, default 9100): plain http, `/readyz` for the startup and readiness probes (ready = start-up finished and the dependencies answer; a failing probe only takes the pod out of service), `/livez` for the liveness probe (the process answers; it never looks at a dependency). `probes.mode` is `health` (default), `tcp` (core only has a port to test) or `none`. The kubelet's probe comes from the node and is not governed by the namespace's network policy; nothing else may use the port.

## What the dependencies must provide

| Dependency | Must provide | Reference behaviour |
|---|---|---|
| Postgres (CloudNativePG) | server certificate for `database.host`; client CA = the business CA; `pg_hba` `hostssl ... cert map=...` and `hostnossl reject`; `pg_ident` mapping certificate names `core`, `worker`, `relay`, `archiver`, `gateway-link`, `admin`, `migrator` to roles `qv_core`, `qv_worker`, `qv_relay`, `qv_archiver`, `qv_gateway`, `qv`, `qv`; the database `quorumvault` owned by `qv` | [`deploy/postgres`](../../postgres) |
| Redpanda | mTLS on the Kafka listener, principal mapping rule from the certificate's CN; ACLs by name (relay writes the outbox topics and audit heads; archiver reads audit heads in its group; the signing link names publish heads only); the relay creates its topics (the ACLs allow it) | [`deploy/redpanda`](../../redpanda) |
| Temporal | the frontend reachable only through the **name gate** that admits the certificate names `worker`, `core`, `admin`; the namespace in `temporal.namespace` | [`deploy/temporal-gate`](../../temporal-gate) |
| Audit bucket | an S3 bucket with Object Lock in COMPLIANCE mode and default retention of at least `archive.retention`, in a separate account, write-only for the archiver | `docs/runbooks/audit-archive.md` |
| cert-manager (task D5) | Secrets `qv-core-tls`, `qv-worker-tls`, `qv-relay-tls`, `qv-archiver-tls`, `qv-admin-tls` with `tls.crt`, `tls.key`, `ca.crt`; certificate names as in `internal/pki/catalog.go` | `docs/runbooks/certificates.md` |
| Operator-made Secrets | the custody config, the auto-approver seed, archive keys if used | n/a |

## Known limits

- Hook resources (the migration job's service account and network policies) are not removed by `helm uninstall`.
- Default egress to the IdP, chain nodes and archive store is "public addresses on 443"; narrow it per deployment (NetworkPolicy has no names).

- Nothing here was installed on a cluster (the kind lane is task D8). The tests prove the manifests follow the rules and the image contract, not that the pods start.
- Same logic in kind and production: only the values differ (images by tag, replica counts, requests, the dependency peers, the ingress host).

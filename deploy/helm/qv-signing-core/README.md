# qv-signing-core

Helm chart for the gateway half of the **signing-core cluster**: `qv-gateway`, and an off-by-default Job for the operators' signed settings. It creates no database, no HSM, no certificate and no party: it names them. Party A runs in the same cluster and is deployed by the party chart (`qv-party`). Design: the Kubernetes deployment note (§2, §3, §5, §7, §10); image contract: [`deploy/images/README.md`](../../images/README.md) and [`contract.json`](../../images/contract.json).

Four clusters exist: business, **signing-core** (this chart and party A), party B with its cosigner, party C with its cosigner. The gateway is not trusted by design (`docs/signing-zone.md`): taking it over does not get a payment nobody approved. It is therefore allowed to share a cluster with party A.

## What it deploys

| Piece | Kind | Notes |
|---|---|---|
| gateway | Deployment, 2 replicas, ServiceAccount, PDB | no Service, no port a peer may use; `/livez` and `/readyz` on 9100 for the kubelet |
| configuration | immutable ConfigMaps | the signing config and the environment; the name carries a hash of the content |
| signed-setting Job | Job, **off** | `signedSettings.job.enabled`; see "Signed settings" |
| metrics agent | sidecar, **off** | `metrics.agent.enabled`; Grafana Alloy, remote-writes outward |
| NetworkPolicies | default deny + one egress rule per peer | no ingress from outside the pod |
| SoftHSM volume and token Job | kind only | `hsm.mode: softhsm` (needs `env: dev`) |

Every pod: uid/gid 65532, `runAsNonRoot`, read-only root filesystem, all capabilities dropped, no privilege escalation, seccomp `RuntimeDefault`, no host namespaces, service account token not mounted, requests and limits set. Images by digest; the all-zero placeholder digests are refused at render time.

## Render and check

```bash
helm template qv deploy/helm/qv-signing-core -n qvs -f ci/helm/signing-core-ci.yaml                                          # production values (+ the test inputs)
helm template qv deploy/helm/qv-signing-core -n qvs -f ci/helm/signing-core-ci.yaml -f deploy/helm/qv-signing-core/values-kind.yaml
make helm-check                                                                                                                # both charts: lint, schema, policy, contract
```

`values.yaml` alone does not render: the digests are placeholders and these values have no default: `config.signing`, `jobs.host`, `kafka.brokers`, `hsm.pkcs11.volume`, `network.jobsDb.peers`, `network.kafka.peers`, `network.parties.b.peers`. The release pipeline or the config repo sets them. `ci/helm/signing-core-ci.yaml` holds made-up values for the checks. The tests are in [`ci/helm/signing_core_test.go`](../../../ci/helm/signing_core_test.go): the business chart's policy and contract checks, and the rules below, each with a test that breaks a manifest and wants the violation.

## Replicas and rollout

**Two replicas, rolling update with `maxUnavailable: 0`.** Read from the code, not assumed:

| Shared state | Why two gateways are safe |
|---|---|
| Job queue | `signjob.Claim` uses `FOR UPDATE SKIP LOCKED` and a lease: two gateways never hold the same job; a dead one's job is reclaimed when its lease ends |
| Replay guard | decisions run in one transaction under a per-chain advisory lock (`internal/gateway/store.go`), so two instances serialise on the database; the schema is created under an advisory lock, so two starting at once do not race |
| Audit chain | the chainer takes an advisory lock |
| HSM | each process opens its own PKCS#11 session; CloudHSM serves many clients |
| MPC routing | each gateway probes the parties itself; the preferred pair is read from the guard database |

A rolling update keeps one gateway serving. On SIGTERM the gateway claims no new job (`/readyz` goes 503) and waits up to `sign_timeout` for signer calls in flight; then it exits 1 if one still runs (nothing is lost: an unstored signature was never released). So `terminationGracePeriodSeconds` is at least `sign_timeout` + 30 s: the chart refuses a smaller value, and a test compares it with the `sign_timeout` of the config. `PodDisruptionBudget`: `minAvailable: 1`.

**kind runs one replica with `Recreate`**: its SoftHSM token is one directory on a `ReadWriteOnce` volume, and two gateways must never run together on it. That is a property of SoftHSM, not of the gateway. Not used in production.

## HSM

Only signers whose `backend` is not `mpc` use the HSM; with MPC signers only, set `hsm.mode: none`.

| | Production (`pkcs11`) | kind (`softhsm`) |
|---|---|---|
| Module | the vendor's PKCS#11 module, **not in the image** (`qv-gateway` is a glibc image that `dlopen`s it). It comes from a volume (`hsm.pkcs11.volume`, any volume source) mounted read-only at `<mountPath>/lib`; `QV_PKCS11_LIB` names the file | `/usr/lib/softhsm/libsofthsm2.so` in the `qv-gateway-dev` image |
| Client config | `hsm.pkcs11.clientConfig`: files for `<mountPath>/etc` (CloudHSM: `cloudhsm-pkcs11.json` with the cluster address, `customerCA.crt`). Public data. Immutable ConfigMap | none |
| PIN | Secret `hsm.pin.secretName`, key `pin`, mounted as a **file** at `/etc/qv/hsm-pin/pin` (mode 0440, group = `fsGroup`; `QV_HSM_PIN_FILE`). The gateway accepts 0440 and refuses a world bit or a group write bit; `QV_HSM_PIN` in the environment is refused outside dev and test | the same, plus key `so-pin` for the token Job; made by the kind setup, random, never in the repo |
| `QV_ENV` | unset (production: the binary refuses SoftHSM) | `dev` |
| Token | made by the HSM operator | a `ReadWriteOnce` volume and a Helm hook Job that runs `softhsm2-util --init-token` (idempotent) |

**What the image task must provide for CloudHSM.** A module volume source with the client SDK 5 PKCS#11 library `libcloudhsm_pkcs11.so` and its dependent libraries. The simplest is a small image that holds `/opt/cloudhsm/lib` and is mounted as a Kubernetes image volume (`{image: {reference: <digest>}}`, Kubernetes 1.33+), or a PVC filled once. The library must run on the glibc base of the gateway image. CloudHSM's client reads its configuration and the cluster CA from `/opt/cloudhsm/etc` (this is why `mountPath` defaults to `/opt/cloudhsm`). **[Unverified]** against a real CloudHSM: I did not run it; the first real run must confirm the paths and that the library's own dependencies are present.

SoftHSM never appears in production values: the chart refuses `hsm.mode: softhsm` without `env: dev`, refuses `env: dev` with a real HSM, and a policy test fails if the word SoftHSM or `QV_ENV` appears in the production render.

## Guard database

Referenced, not bundled: a CloudNativePG cluster in the **same namespace**, with its own certificate authority and no route to or from the other clusters. What it must provide:

| Item | Value |
|---|---|
| Database and owner | `qv_gateway_guard`, owned by the role `qv_gateway_guard` (`deploy/postgres/signing_roles.sql`). The gateway applies its own schema at start (`gateway.OpenGuard`, advisory-locked) with that role, so no migration Job is needed for tables |
| Roles | `qv_gateway_guard` (and `qv_cosigner_b_guard` / `qv_cosigner_c_guard` for the cosigners, in their clusters). Created by `qv-migrate -zone signing`, run as a Job by this cluster's operators with the owner credentials (never `-enable-login` in production: the database operator enables login) |
| Login | certificate only: `pg_hba` `hostssl ... cert`, `hostnossl reject`, and a `pg_ident` map from certificate name `signing/gateway` to the role `qv_gateway_guard` (certificate name `gateway`, issued by the **signing** CA) |
| Server certificate | issued by the signing CA, DNS names include `guard.host` (`verify-full`) |
| Pod labels | `cnpg.io/cluster: qv-guard` (change `network.guardDb.peers` to match) so the chart's rule that admits the gateway applies |
| Backups | no point-in-time restore to an earlier time without an operator decision: it forgets replay guards |

## The business side (the signing link)

The gateway reads the job queue from the **business Postgres** (role `qv_gateway`) and publishes audit heads to the **business Kafka**, both with the **link certificate** `business/gateway-link` issued by the **business** CA (`tls.gatewayLink.secretName`, mounted at `/etc/qv/link-tls`). The signing certificate (`signing/gateway`, `tls.gateway.secretName`, `/etc/qv/tls`) is for the guard database. The parties' caller ports take the pinned client certificate `signing/gateway-party` (`tls.gatewayParty.secretName`, `/etc/qv/party-tls`); the parties pin its public key, which never rotates.

`jobs.host`, `kafka.brokers` and `network.jobsDb.peers`, `network.kafka.peers` are the private endpoints of the business cluster: addresses (`ipBlock`), because a NetworkPolicy matches addresses, not names. The business chart's `network.signingLink.from` must list this cluster's side of those endpoints. Business and signing VPCs are not peered: the endpoint service is what connects them, outward from here. Nothing in the business cluster has a route into this one (a cloud network rule, tested from the business side; a NetworkPolicy cannot express it).

## Parties

The gateway reaches the **caller port** of party A (this cluster), of party B, and, for the route monitor, of party C: `network.parties.{a,b,c}` (peers and port). B and C are private endpoint addresses. Their addresses and pins are in the signing config (`signers.*.coordinators`, `mpc_route.parties`); the gateway's client certificate and key paths in that file point at `/etc/qv/party-tls/tls.crt` and `tls.key`.

**What the party chart (D7) must provide** so that A accepts the gateway: pods labelled `app.kubernetes.io/name: qv-party` and `quorumvault.io/party: "A"` (the default of `network.parties.a.peers`; change it if the labels differ), and an ingress rule that admits pods labelled `app.kubernetes.io/component: gateway` and `quorumvault.io/zone: signing` on the caller port (the party chart takes this from `network.callerIngress.from`, which the operator sets; A's caller port is 7001 by default). This chart adds only the gateway's egress; the namespace default deny means A's ingress is A's chart's job. Both charts may render a default-deny policy: two identical policies are harmless.

## Signed settings

The MPC route, fee caps, approver registry and keyset state are applied to the guard database by operators with `qv-route`, `qv-fee-caps`, `qv-approvers`, `qv-keysets`. **No signing key ever enters the cluster.** `sign` runs on each operator's own machine. Only `show` and `apply` run in the cluster, as a Job from the `qv-tools-signing` image, logging in to the guard database with the gateway's certificate (role `qv_gateway_guard`).

Who: only this cluster's operators (they hold `create` on Jobs and ConfigMaps in the namespace; nobody else has standing access). With the cluster policies (`deploy/policy/qv-policy`) installed, the signed-files ConfigMap must be **immutable with a content hash at the end of its name**, and the person creating or deleting it must be one of the policy's `configWriters` (the GitOps identity or a group the operators' break-glass-free write access is mapped to; ask the cluster's policy owners). The Job template refuses a name without the hash.

```bash
# 1. on the operators' machines: sign, then gather the files (see docs/runbooks/mpc-signing-pair.md, approvers.md, btc-fee-caps.md, mpc-keyset-freeze.md)
# 2. put the signed files into an IMMUTABLE ConfigMap whose name ends in a hash of the files (10 hex characters)
H=$(cat route-1.json route-2.json | sha256sum | cut -c1-10)
kubectl -n qvs create configmap "qv-signed-route-7-$H" --from-file=route-1.json --from-file=route-2.json --dry-run=client -o yaml \
  | kubectl patch --local -f - -p '{"immutable":true}' -o yaml | kubectl -n qvs apply -f -
# 3. render the Job (the same release values) and apply it
helm template qv deploy/helm/qv-signing-core -n qvs -f <the release values> \
  --set signedSettings.job.enabled=true --set signedSettings.job.tool=route --set signedSettings.job.action=apply \
  --set signedSettings.job.revision=7 --set signedSettings.job.configMap="qv-signed-route-7-$H" \
  --set 'signedSettings.job.files={route-1.json,route-2.json}' \
  -s templates/signed-setting-job.yaml | kubectl -n qvs apply -f -
# 4. read the result; the Job is deleted after a day
kubectl -n qvs logs job/qv-apply-route-7
kubectl -n qvs delete configmap "qv-signed-route-7-$H"
```

`action=show` prints the current setting and the next sequence number (the number the operators need before they sign). `tool` is `route`, `fee-caps`, `approvers` or `keysets`; `extraArgs` carries a tool's own flags (`["-chain","btc-main"]` for fee-caps). The Job runs one tool, takes `/etc/qv/config/config.json` (the same signing config: the tool checks every signature against its approvers and operators), mounts the guard login certificate and the two ConfigMaps, and nothing else. Egress: the guard database only. A test renders the Job and fails if it runs another binary, runs `sign`, gets a key or identity argument, or mounts another Secret.

The signature check is in the tool and in the gateway (rows without valid approver signatures are ignored with an ALERT), so a forged ConfigMap changes nothing.

## Network

Default deny for the namespace, then, for this release:

| From | To | Port |
|---|---|---|
| any pod of the release | DNS (`kube-system`) | 53 |
| gateway | guard database pods (`network.guardDb`) | 5432 |
| gateway | business Postgres endpoint (`network.jobsDb`) | 5432 |
| gateway | business Kafka endpoint (`network.kafka`) | 9092 |
| gateway | party A, B, C caller ports (`network.parties`) | 7001, 7002, 7003 |
| gateway | metrics endpoint (`network.metricsRemoteWrite`), only with the agent | 443 |
| signed-setting Job | guard database | 5432 |
| release pods (gateway, Job) | accepted by the guard database pods | 5432 |

**No ingress from outside the pod, none from another namespace or address**: there is no Ingress and no Service at all. The health port serves the kubelet (probes are node-local and are not governed by NetworkPolicy on the usual CNIs). **No egress to 0.0.0.0/0**, no internet. An empty peer list fails the render, because `to: []` would mean everywhere. Enforcement needs a CNI that implements NetworkPolicy.

## Metrics

The gateway opens no port: it writes `mpc.prom` (route and party health) and `mpc-tls.prom` (certificate expiry) to `/var/lib/qv/metrics`, a writable `emptyDir` (`QV_MPC_METRICS_FILE`). A signing cluster takes **no inbound scrape**. With `metrics.agent.enabled` a sidecar (Grafana Alloy, `images.agent`, digest pinned in `deploy/images/contract.json`) reads those files in the pod (the textfile collector) and remote-writes **outward** to `metrics.agent.remoteWrite.url` with the client certificate in the Secret `metrics.agent.remoteWrite.tlsSecret` (`tls.crt`, `tls.key`, `ca.crt`; no token); `metrics.agent.cluster` (required) is sent on every series as `qv_cluster`; egress to that endpoint is one named rule. Off by default. The Alloy configuration passes `alloy validate`; it was not run against a real endpoint (kind lane). Same sidecar as in `qv-party`; see `qv-monitoring`. The alert rules stay central (`monitoring/`).

## Configuration and secrets

| What | Where |
|---|---|
| The signing config (approvers, bounds, chains, signers, `mpc_route`, party addresses and pins) | `config.signing` (JSON, `--set-file`). **No secret in it**: the keys are public keys, the pins are certificate hashes, the addresses are addresses, the signers name a token label and a key id. An **immutable ConfigMap** named `<release>-config-<hash>`: a change is a new ConfigMap and a rollout, never an edit in place. The config repo's two-person rule is the control; the other checkers (cosigners B and C) hold their own copies in their own clusters |
| Plain settings (DSNs without password, Kafka, probe address, metrics file, TLS file paths) | immutable ConfigMap `<release>-gateway-env-<hash>` |
| Certificates and keys | Secret volumes from cert-manager (task D5), mode 0440 with `fsGroup` 65532: `tls.gateway`, `tls.gatewayParty`, `tls.gatewayLink`. `tls.trust.signing` and `tls.trust.business` name the qv-certs trust bundles: set, they are the CA files of the signing and the link certificate volumes instead of cert-manager's `ca.crt` |
| HSM PIN | a Secret that exists already (External Secrets); mounted as a file (`QV_HSM_PIN_FILE`), never an environment variable |

The chart renders no Secret. The policy test refuses a Secret object, a PEM private key, a password in a URL, a secret-named value in a ConfigMap, and an inline secret in an environment variable.

## Test and production

The same templates and the same binary logic. What differs is configuration only: `env` (`""` or `dev`), `hsm.mode`, image references (digest or tag; `-dev` image with SoftHSM), `replicas`, `strategy`, resources, the PDB and spread switches, and the peer lists. The checks run on both renders.

## Known limits

- **PIN as a file: done.** The gateway reads `QV_HSM_PIN_FILE` (`docs/runbooks/hsm-pin.md`); the chart mounts the Secret's `pin` key as a file and never sets `QV_HSM_PIN`. A policy test fails the render if `QV_HSM_PIN` is an environment variable.
- The CloudHSM module path and client-config location, and the Alloy sidecar, are not run here (see above).
- The kind lane (`ci/kind/`, `make kind-up`; the kind workflow in CI) installs this chart and runs its smoke cases against the pods.
- Party A's ingress rule for the gateway, and the business chart's `signingLink.from`, are in other charts.

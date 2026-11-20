# qv-party

Helm chart for **one MPC party** of the 2-of-3 signer: `mpc-party` and, for parties B and C, their own `qv-cosigner` in the same pod. Install it three times (releases `qv-party-a`, `qv-party-b`, `qv-party-c`), **each in its own cluster**: A in the signing-core cluster next to the gateway, B and C in clusters of their own. It creates no database, broker, HSM or certificate: it names them. Design: the Kubernetes deployment note (task D7); image contract: [`deploy/images/README.md`](../../images/README.md) and [`contract.json`](../../images/contract.json). Conventions follow [`qv-business`](../qv-business/README.md).

## What a party pod is

| Role | Containers | Authorizer | Listens on | Dials |
|---|---|---|---|---|
| A (coordinator) | `mpc-party` | `pinned-caller`: its pinned caller, the gateway, has already decided | caller port | B and C (peer ports) |
| B | `mpc-party`, `qv-cosigner` | `cosigner`: asks its own cosigner on a unix socket, fails closed | caller port (health only for callers), peer port | C; the cosigner: its guard database, Kafka |
| C | `mpc-party`, `qv-cosigner` | same | caller port, peer port | the cosigner only; C dials no party |

- **One StatefulSet, exactly one replica**, one data volume (`ReadWriteOncePod` in production). The schema accepts only `replicas: 1`.
- **The socket.** The two containers share an in-memory `emptyDir` at `/run/qv`; the cosigner creates `cosigner.sock` there, mode 0600, owner only, so both run as the same uid (65532). The channel is mutual TLS with pinned certificates, so sharing a pod does not weaken it: each container mounts **only its own** certificate and key Secret (the party never sees the cosigner's key and the other way round). The test fails if a third container, or the wrong container, mounts the socket or a key.
- **No cosigner for A.** A's independent check is the gateway's own guard plus B's and C's cosigners (`docs/signing-zone.md`); the chart renders nothing cosigner-shaped for role A, and a test checks it.
- Every container: uid/gid 65532, `runAsNonRoot`, read-only root filesystem, no capabilities, seccomp `RuntimeDefault`, requests and limits, service-account token not mounted, no host namespaces. Production images by **digest** only; the all-zero digests in `values.yaml` are placeholders and the chart refuses to render them.

## Render and check

```bash
helm template qv-party-b deploy/helm/qv-party -n qv --set role=B -f my-values-b.yaml        # production
helm template qv-party-b deploy/helm/qv-party -n qv --set role=B -f my-values-b.yaml -f deploy/helm/qv-party/values-kind.yaml
make helm-check                                                                              # lint, schemas, policy and contract tests, all charts
```

`ci/helm/party-check.sh` lints, renders and validates (kubeconform) every role for production and kind; `ci/helm/party_test.go` holds the checks. They apply the business chart's policy test and the image contract to this chart, and add: one replica and one volume, no overlap in updates, the socket shared by exactly the two containers, each key in its own container, no SoftHSM / `QV_ENV` / `-dev` image in production, no Ingress, a private load balancer only, PIN and keys only from Secrets, `party.json` valid for its role (a mirror of `mpc-party/internal/server/config.go`), default-deny network policies with no internet path, and what a role must not render. Each check has a test that breaks a manifest and wants the violation (about 100 cases).

## Values you must set

| Value | What |
|---|---|
| `role` | `A`, `B` or `C` |
| `images.party.digest`, `images.cosigner.digest` | from `deploy/images/publish.sh` (B and C also need the cosigner) |
| `adminKeys`, `callerPins`, `adminMaxAgeSeconds` | the operators' Ed25519 public keys; the certificates (pins) allowed on the caller port: the gateway, the operators' tool |
| `peers.a/b/c.pins`, `peers.b/c.address` | the other parties' certificate pins (SHA-256 of the public key) and, for A and B, where their peer ports are reached. A: `b` and `c`. B: `a` and `c`. C: `a` and `b` (pins only) |
| `hsm.module.path`, `hsm.module.volume`, `hsm.pinSecret`, `hsm.token` | production HSM, see below |
| `cosigner.*` (B, C) | `config` (the cosigner's own signing-zone config, public data), `socketPins` (the cosigner's socket certificate, which the party checks), `partyPins` (this party's certificate, which the cosigner checks), `database`, `kafka` |
| `tls.*` | names of the certificate Secrets (made by cert-manager, task D5): `qv-signing-mpc-party-<role>-tls`, `qv-signing-cosigner-<role>-tls`, `qv-cosigner-link-<role>-tls` (the defaults: each cosigner has its own names), `qv-signing-cosigner-socket-tls`, each with `tls.crt`, `tls.key`, `ca.crt` |
| `network.*`, `service.*` | the private endpoints and addresses, see "Network" |

The party config (`party.json`) and the cosigner's config are rendered into **immutable ConfigMaps whose names carry a hash of the content**: a change is a new ConfigMap and a rollout, never an edit in place. They hold public keys, pins, addresses and limits only. The policy test refuses a secret-looking field, a PEM block or any Secret object in the output.

## HSM and the PIN

| | Production | kind |
|---|---|---|
| Module | the vendor's PKCS#11 library from a volume you name: `hsm.module.volume` (any volume source) is mounted read-only at `/etc/qv/hsm`, `hsm.module.path` lies under it. The image contains none | SoftHSM from the `-dev` image |
| Token | the label `hsm.token` (default `qv-party-1`, `-2`, `-3` for A, B, C), made by the HSM's operators | made once by an init container on the data volume (`softhsm-init`), idempotent |
| PIN | Secret `hsm.pinSecret`, key `pin`, mounted as a **file**, mode 0440, group = `fsGroup`; `pin_file` in the config. The party accepts 0440 and refuses a world bit or a group write bit | same, from a development Secret |
| `QV_ENV` | not set. The party refuses SoftHSM in production | `dev` (only in kind) |
| Network | `network.hsm` opens the HSM's addresses and ports (a network HSM) | none |

The PIN is never an environment variable and never in values. SoftHSM is a development tool: the chart refuses `hsm.softhsm.enabled` with an image referenced by digest, and the policy test refuses SoftHSM, `QV_ENV` or a `-dev` image in any production render. **Deviation from the task text:** the token is made by an init container, not a Job. A Job and the party pod cannot both mount a one-pod volume, and the pod's first start needs the token; the init container runs in the pod, before the party, and does nothing when the token exists.

`mlockall` (the party locks its memory so secrets are not swapped) needs a memlock limit from the container runtime; a non-root container gets no benefit from `CAP_IPC_LOCK`, and the chart adds no capability. If the limit is too low the party logs "may be swapped" at start. Set the memlock ulimit on the node group or runtime.

Attested mode replaces the HSM: see "Attested mode" below.

## Attested mode (`sealer.type: attested`)

**The enclave is simulated.** The mode needs the tee-sim image (`mpc-party-teesim`, by tag) and `env` dev or test; the chart refuses it otherwise, and refuses any `attested.attester.type` but `mock` (there is no production attester yet). Procedure: `docs/runbooks/tee-broker.md`, "On Kubernetes". The broker is the chart `qv-attest-broker`, one per party, in another trust zone.

What changes in the pod: no HSM PIN, no PKCS#11 module, no SoftHSM init container; with `attested.tlsSealed` (default) no TLS key Secret either (the key is made inside the party and kept sealed in the data volume). It gains the Secret `attested.linkSecret` (certificate for the link to the broker; default `mpc-party-<role>-broker-link-tls`), the TEST CA Secret `attested.attester.mock.caSecret`, the egress rule `network.broker`, and `QV_ENV`.

Values: `attested.broker.url` and `.pins`, `attested.attester.type: mock`, `attested.attester.mock.caSecret`, `network.broker.to`, `env`. `values-kind-teesim.yaml` is the local layer (after `values-kind.yaml`).

**Phases.** The data volume has one user, so the two steps that run while the party does not are phases of the release (`attested.phase`, with `attested.stopPartyAck=true`; migrate also `attested.migrate.partyStopped=true` after you scaled the party to zero); each renders its Job and no StatefulSet:
| Phase | Job | Rule |
|---|---|---|
| `enrol` | `mpc-party tls-init -config enroll.json`: makes and seals the TLS key, prints the pin in its log | first install only: the chart refuses it when the StatefulSet exists (`lookup`, at a real install or upgrade); the Job is idempotent. It creates the data volume (kept by Helm; the StatefulSet finds it by name). Its config file is its own measurement |
| `migrate` | `mpc-party migrate-seal -from party-pkcs11.json -to party.json` | one way; needs the old `hsm.*` values and `attested.tlsSealed=false` (the certificate and its pin stay). `-to` is the running config |
Then `attested.phase=run` starts the party on the same volume.

The backup Job is refused in this mode (it would need the attester): run `kubectl exec <pod> -- mpc-party backup export ...` in the running pod.

## Update, restart and node loss

- **Update.** `RollingUpdate` on one replica stops the old pod, waits until it is gone, then creates the new one: two pods of one party never run at once. If one did (a bug, a forced delete on a live node), the second `mpc-party` would exit at start with "in use by another mpc-party process" (an exclusive `flock` on `<data_dir>/.lock`), and the `ReadWriteOncePod` volume cannot be mounted twice. A share is never in two places.
- **Stop.** The party stops accepting, finishes sessions for `limits.shutdownGraceMs` (default 10 s), cuts the rest. `terminationGracePeriodSeconds` is that plus 20 s (30 s by default). The cosigner needs 10 s. No PodDisruptionBudget: a budget of zero would block node drains; plan a drain with the operators and route around the party being drained with the preferred-pair setting (`docs/runbooks/mpc-signing-pair.md`): A and B must stay reachable for two-party keys.
- **Restart.** The same volume comes back, the kernel has dropped the lock, the party opens the HSM token, loads its sealed shares, and reconciles with its peers before it serves a keyset (a self-test signs with the share). The cosigner's socket directory is empty at every start; a party that starts before its cosigner is "unavailable" for decisions (it fails closed) and recovers on its own. One thing a restart does forget: the **admin-signature replay set is in memory**, so a captured admin request can be replayed once, within `adminMaxAgeSeconds` (300 s) of its signing, if the party restarts in that window.
- **Ready** means: data directory locked, sealer open, listeners up, certificate valid. It **does not** look at the other parties: if it did, one party's outage would take every pod out of service. Probes: kubelet `httpGet` on the health port (9100 party, 9101 cosigner; plain http, `/livez` and `/readyz`, nothing else). The party's gRPC `Health` stays on the mutual-TLS caller port for monitoring.
- **Node loss.** The node dies, the pod sits in `Terminating`, the StatefulSet does **not** start a replacement (that is the point). Signing continues with the other two parties. When the node is confirmed gone (the cloud console says so; for a node that may still run, do not force anything), Kubernetes may be told so (the `node.kubernetes.io/out-of-service` taint, or deleting the pod and the node object), the volume detaches and the new pod mounts it. Never force-delete the pod of a node that might still be running. A replica on another node with the same cloud volume works only after the cloud has detached it from the dead node.

## Backup and restore

What lives where: the sealed shares are on the data volume, sealed under a key in the party's HSM. **The volume alone is useless without the HSM token, and the HSM key alone is useless without the volume.**

**A lost volume (or a lost HSM key) loses the share.** The other two parties still sign (any two do), but the lost party is gone until a backup is restored. The backups are the only way back, so they matter as much as the HSM:

1. After every DKG and every refresh the party logs that existing backups are stale (`Health` shows `backup_stale`). Take a new backup each time: `mpc-party backup export -config … -keyset <id> -recovery-public recovery.public -out <file>`. It unseals through the party's HSM, writes a file encrypted to the recovery **public** key (PVE), verifies it and records the verified generation.
2. **Run it where the volume is.** Either in the running pod, with the output on a volume (set `backup.outputClaim`; it is mounted at `/var/lib/qv/backup`, so a file written there can be shipped from that volume):
   ```bash
   kubectl -n <ns> exec qv-party-b-0 -c mpc-party -- mpc-party backup export -config /etc/qv/config/party.json -keyset <id> -recovery-public <path to the public key> -out /var/lib/qv/backup/<id>-g<N>-B.backup
   ```
   or as the Job in `templates/backup-job.yaml` (`backup.job.enabled`, **off by default**; set `keysetId`, `outputFile`, `recoveryPublicConfigMap`, and a new `name` per run). The Job mounts the data volume, which one pod can hold: **stop the party first** (scale the StatefulSet to 0, run the Job, scale back) so it is a maintenance step, not a routine one. The Job needs only the recovery public key. No admin key, recovery private key or other secret is in the chart.
3. Move the file to that party's own storage (a bucket in the party's own account). Different people hold A's, B's and C's backups; nobody holds two plus the recovery private key (`docs/runbooks/mpc-backup-restore.md`).

**Restore** into a **new, empty** data volume (`mpc-party backup restore` refuses a directory that is not empty): delete the PVC `data-<release>-0` (after the old pod is gone) and let the StatefulSet make a fresh one, make sure the HSM token exists (a new wrap key is made at first use; the restore seals the shares under it), run the restore with the recovery private key held by the custodians, then start the party. It reconciles with its peers: a backup older than the peers' generation is refused and nothing is signed with a stale share (`docs/runbooks/mpc-backup-restore.md`, "Restore"). The chart has no restore Job on purpose; see "Known limits".

A **volume snapshot** is a convenience for a quick rollback of the volume, not a backup: it is sealed under the HSM key of that moment and may be an older generation than the peers'.

## Network

Default deny for ingress and egress of every pod in the namespace, then one allow per path. A rule with an empty peer list is not rendered (an empty `from` or `to` would mean everyone). Peers are raw NetworkPolicy peers (`ipBlock`, `podSelector`, `namespaceSelector`) because between clusters a NetworkPolicy sees addresses only.

| Direction | Allowed | Values |
|---|---|---|
| in, caller port | the gateway (A: its pods; B and C: its private endpoint), and the operators' pods of this namespace (label `quorumvault.io/party-operator: "true"`) | `network.callerIngress.from`, `operator.podLabel` |
| in, peer port (B, C) | only the parties that dial this one, through their private endpoints | `network.peerIngress.from` |
| out, peers | A: B and C; B: C; C: nobody | `network.peerEgress.to` |
| out, cosigner (B, C) | its guard database; the business Kafka over the explicit link, outward only | `network.guardDatabase`, `network.kafka` |
| out, HSM | a network HSM's addresses and ports | `network.hsm` |
| out, DNS | cluster DNS | `network.dns` |

Nothing else: no internet, nothing into the health or metrics ports, no ingress from anywhere else. The tests fail on a rule open to `0.0.0.0/0`, on an egress rule without `to`, and on an unknown port. **Kubelet probes** come from the node, which most CNIs allow regardless of policy; check yours.

**Between clusters** the parties reach each other through private endpoints (an internal TCP load balancer per port, in front of a PrivateLink-style endpoint service). The chart provides the Service shape: `service.caller` and `service.peer` take `type: LoadBalancer` **only** with the internal-load-balancer annotations of your cloud in `annotations` and the parties' addresses in `sourceRanges` (the chart refuses otherwise; the test also refuses a public one). TCP only: the pinned mutual TLS passes through, nothing terminates it. In kind the services stay `ClusterIP`. Business and signing clusters have no other path: cloud network rules (no route from business into a signing VPC) are the other half of the rule, outside this chart.

**Never an Ingress.** There is none, and a test fails if one appears.

## Operators

DKG, refresh, freeze, unfreeze and the backup are done by that party's own operators **inside the party's cluster** (design decision D13), never through a public path:

- **Admin calls** go to the caller port of the coordinator (A; they are signed with an operator's Ed25519 key and verified by every party against its own `adminKeys`). Run the operators' tool as a Job or a bastion pod **in the namespace of the party you call**, labelled `quorumvault.io/party-operator: "true"`: the chart's policies let exactly such pods reach the caller port and nothing else, and let the party accept them there. The pod's client certificate must be one of `callerPins`.
- **No admin key is stored in the cluster.** The Ed25519 key stays with the operator; only the signature enters the cluster. The chart has no Secret for it.
- Operators of party A cannot touch B or C: each cluster has its own operators and its own IAM; nobody has admin on two party clusters.
- The tool is `qv-party-admin` (image `qv-tools-signing`). `sign` runs on the operator's machine; `send` (`dkg`, `refresh`, `unfreeze`) and `status` run in the cluster. The step-by-step ceremony is `docs/runbooks/key-ceremony.md`.
- **The operator Job** (`operator.job.enabled`, off by default; one call per Job): `command` is `dkg`, `refresh`, `unfreeze` or `status`; `authConfigMap` holds the signed file as key `auth.json` (public data, valid for `adminMaxAgeSeconds`, once per party: create it right before the Job); `callerCertSecret` is a Secret (`tls.crt`, `tls.key`) made for the ceremony with a certificate that is in `callerPins`; `partyPin` is the pin of this party's certificate. The Job calls this release's own caller Service, so run it in the coordinator's (A's) cluster for the signed commands and `status` in each party's cluster. The pod carries the operator label and mounts only those two objects; it has no service account token.

## Metrics

Both processes serve their metrics on **loopback only** inside the pod (`127.0.0.1:9102` party, `127.0.0.1:9104` cosigner): a signing cluster takes no inbound scrape. The chart creates no metrics Service. Monitoring uses an in-cluster agent that scrapes the loopback ports from a sidecar and **remote-writes outward**. With `metrics.agent.enabled` the chart adds that agent as a sidecar (Grafana Alloy, digest pinned in `deploy/images/contract.json`): it scrapes the loopback ports of the pod (party; cosigner for B and C) and remote-writes **outward** to `metrics.agent.remoteWrite.url` with the client certificate in `metrics.agent.remoteWrite.tlsSecret` (`tls.crt`, `tls.key`, `ca.crt`). `metrics.agent.cluster` (required) names this cluster; every series is sent with `qv_cluster=<that name>` and `party=<role>`, set by the chart (`externalLabels` can add others, not replace these). `network.metricsRemoteWrite.to` names the endpoint and is required (one egress rule, port 443; a NetworkPolicy applies to the whole pod). Off by default. The configuration passes `alloy validate`; not run against a real endpoint yet. The rules live in `monitoring/`; see chart `qv-monitoring`.

## What the cluster must provide

| Need | For |
|---|---|
| Kubernetes 1.30+ and a CNI that enforces NetworkPolicy | default deny |
| A CSI volume class that supports `ReadWriteOncePod` and `flock` (block volumes; check NFS) | the data volume. In kind: `ReadWriteOnce` |
| cert-manager (or the operators' own process) | the Secrets above, with long-lived pinned certificates (renewal changes the certificate; pins are over the public key, so a renewal with the same key keeps them) |
| The qv-certs trust bundles `qv-trust-signing-<hash>` and `qv-trust-business-<hash>`, named in `tls.trust.signing` and `tls.trust.business` | the CA files of the certificate volumes (projected next to the Secret's `tls.crt` and `tls.key`, instead of cert-manager's `ca.crt`); empty is development only |
| A guard database per cosigner, its own, never the gateway's, reached with the certificate name `cosigner-b` or `cosigner-c` (Postgres role `qv_cosigner_b_guard` or `qv_cosigner_c_guard`; the database keeps the name `qv_cosigner_guard`) | B, C |
| The HSM with the token and the PIN Secret | production |
| Private endpoints to the other parties, the business Kafka and the guard database | between clusters |
| A secret store for the PIN Secret in **that party's own** cluster and account | production |

## Known limits

- Nothing here was installed on a cluster (the kind lane is task D8). The tests prove that the manifests follow the rules and the image contract, not that the pods start.
- **Restore with a cloud HSM (open, on the lead's backlog).** `mpc-party backup restore` needs the party's HSM and the recovery private key together; for an HSM reachable only from the party's cluster it would run in a pod there with the key delivered by the custodians. Undecided, so the chart has no restore Job.
- `mlockall` depends on the node's memlock limit (above).
- **Admin tool (open, backlog).** No in-cluster tool exists for the signed admin calls (DKG, refresh, freeze, unfreeze); the chart gives only the pod label and the network path.
- **Metrics agent.** Built (off by default); first real remote-write is for the kind lane.
- Tested with Helm 4.3.2 (the chart is `apiVersion: v2`).

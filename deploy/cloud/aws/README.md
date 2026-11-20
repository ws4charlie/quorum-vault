# AWS reference deployment (Terraform)

**Status: written and checked without an AWS account. Never applied.** Nothing here has created a resource; the checks are static (format, validate, a mocked-provider test, lint, a scan).
The first real apply is described in [`docs/runbooks/aws-first-deploy.md`](../../../docs/runbooks/aws-first-deploy.md), with its costs and the list of things only an account can show.

It builds the shape of [`docs/deployment.md`](../../../docs/deployment.md) on AWS: four clusters in four accounts, plus one audit account.

```
deploy/cloud/aws/
  cidrs.json  paths.json      the address plan and THE list of paths between domains (one source of truth, read by every root)
  modules/                    small, first-party; no community module
  roots/{business,signing-core,party-b,party-c,audit}   one state, one account, one set of credentials each
  values/                     what Terraform outputs feed which chart value
  check.sh                    every account-free check (CI runs the same file)
```

## Design note

**Accounts.** An AWS Organization with five member accounts and a separate management account that holds nothing else: `business`, `signing-core`, `party-b`, `party-c`, `audit`.
Two parties never share an account or an administrator. The audit account holds what the others must not be able to delete: the audit-head archive, CloudTrail and flow logs. **Why the audit account is its own root.** The archive and the logs are worth something only if the people they record cannot delete or rewrite them. Any domain's administrators can change
that domain's own account (stop a trail, empty a bucket, destroy a key), so the store must be in an account none of them controls. Object Lock in COMPLIANCE mode stops even the audit administrators from deleting
before the retention ends, but it does not stop a bucket policy or a key from being changed: only separation does. **Who administers it:** a small group that belongs to no domain (for example security or compliance, not
the business, signing-core, party-b or party-c teams), with its own Identity Center permission set and its own Terraform role; the management-account owner can reach it only to create it. A person with access to the audit account must
not hold a role in a party account, and the reverse. The audit root creates no network and no cluster, so it has no run-time dependency on a domain.

Shared: nothing
at run time (no shared VPC, no shared state, no shared keys). Shared by hand only: the organization, single sign-on, and the guardrail policies (SCPs) in the runbook.

**Networks.** One VPC per domain, address ranges that never overlap (`cidrs.json`). No peering, no transit gateway, no VPN. The signing and party VPCs have no internet gateway, no NAT and no route out
(tested). The business VPC has NAT (chain nodes, identity provider) and no route into any other VPC. A domain reaches another only through a PrivateLink endpoint service (internal NLB, TCP: the pinned mutual TLS
is not terminated), allow-listed to named accounts, each new connection accepted by a person:

| # | Source → destination | Port | Crosses by |
|---|---|---|---|
| 1 | signing-core gateway → business Postgres (jobs) | 5432 | endpoint service `postgres` of business, consumer signing-core |
| 2 | signing-core gateway → business Redpanda (audit heads) | 9092-9094 | endpoint service `kafka` of business |
| 3 | party-b cosigner → business Redpanda | 9092-9094 | same service, consumer party-b |
| 4 | party-c cosigner → business Redpanda | 9092-9094 | same service, consumer party-c |
| 5 | gateway → party B caller | 7002 | endpoint service `caller` of party-b, consumer signing-core |
| 6 | gateway → party C caller (route monitor) | 7003 | `caller` of party-c |
| 7 | party A → party B peer | 7003 | `peer` of party-b, consumer signing-core |
| 8 | party A → party C peer | 7003 | `peer` of party-c |
| 9 | party B → party C peer | 7003 | `peer` of party-c, consumer party-b |
| 10 (off) | signing-core, party-b, party-c → business metrics | 443 | optional `monitoring` of business (remote write, outward only) |
| 11 | archiver (business) → audit-head bucket | 443 | S3 bucket policy for one named role through the VPC's S3 gateway endpoint, no network path |
| 12 | every account → audit account (CloudTrail, flow logs) | 443 | AWS log services writing into Object Lock buckets |

Party A's caller port and the gateway are in one cluster: no cross-domain path. Nothing starts in business. Nothing enters the signing core. The list is `paths.json`; the tests fail if a path starts in business or if an endpoint service names an account that has no path.
Names: each consumer VPC has a private zone `qv.internal` with a name per endpoint (`business-kafka.qv.internal`, ...). The charts' certificates need those names as DNS names (qv-certs).

**Where operators enter.** The Kubernetes API is private in every cluster (no public endpoint, no creator admin, no `aws-auth`). An operator holds an IAM Identity Center role of THAT account, listed in `operators`
(an EKS access entry). The way in is an SSM Session Manager port forward through a tiny host with no inbound rule (`enable_ops_host`, off by default); kubectl runs on the operator's machine with the operator's own identity, so the
cluster audit log names the person. Admin calls (DKG, refresh, unfreeze, backup) run as a Job inside the party's namespace, as the charts say (decision D13). Nobody has a role in two party accounts.

**State.** Databases are CloudNativePG **in the cluster**, not RDS: certificate name → role (`pg_ident`) with our own client CA is the design of `docs/runbooks/database-roles.md`, and AWS documents no way to
keep it on RDS (research note, S5). Terraform makes the AWS side only: a backup bucket under a customer key and a role for one service account. Redpanda and Temporal are in-cluster charts. A guard database is never restored
to an older point without the runbook's decision. The audit-head archive is S3 with Object Lock, COMPLIANCE, 2555 days (what the archiver runbook and the chart state), in the audit account, with the archiver allowed Put and Get only and denied everything that deletes or shortens retention.

**HSMs.** CloudHSM per party in the party's own account, module `hsm`, **off by default** (hourly billing). Terraform creates the cluster and the HSMs; the initialisation (cluster certificate, crypto officer, the crypto user the sealer logs in as) is by hand, so Terraform never sees a PIN. It depends on the CloudHSM sealer change (D12, not yet merged); until then use SoftHSM only in a throw-away test.

**Keys.** One customer key per purpose and account (disks, Secrets and Secrets Manager, logs, backups); rotation on; every action spelled out in the key policy (no `kms:*`, no partial wildcard); the account's own IAM administers them; named roles of other accounts only where a path needs it (the archiver and the audit key).
IAM roles for service accounts, one role per service account, trust pinned to one namespace and name; the module refuses `kms:*`, `cloudhsm:*`, `s3:*` or any `*`. The pods with AWS rights: EBS CSI driver, External Secrets (one path prefix), the database pods (their backup bucket), the archiver (the audit bucket), the load balancer controller (business, party-b, party-c).

**Registry.** Images stay on ghcr.io and are pulled by digest. Signing clusters have no internet, so each account has an ECR pull-through cache (module `registry`): ECR fetches from ghcr.io, nodes pull through VPC endpoints. Cache repositories are immutable and encrypted. A read-only ghcr token is made by hand into Secrets Manager.

**DNS and certificates.** Terraform creates no certificate, no CA, no public DNS and no ACM entry: `qv-certs` is the in-cluster authority and Vault holds the CA keys (a separate piece, not built here). Terraform creates only the private zone for the endpoint names. How people reach the core API is not decided here: no public listener exists.

**State of Terraform.** One S3 bucket per domain in that domain's account (made by hand), encrypted with that account's key, native lock file. No `terraform_remote_state` anywhere: values cross domains as plain outputs copied by a person. No secret is created or read by Terraform, so none is in state; the state holds ARNs, addresses and the public HSM certificate request.

**Versions.** Terraform 1.17.2, `hashicorp/aws` exactly 6.67.0 (lock files with hashes in each root). No third-party module: each would run with administrator rights, and everything needed is a first-party resource.

## Two phases
The endpoint services need load balancers that the charts create. So each root is applied twice: phase 1 builds accounts, networks, clusters, keys and buckets; after the charts made their `LoadBalancer` Services,
phase 2 sets `nlb_services` (provider side) and then `endpoint_service_names` (consumer side). The audit root has a phase 2 too (`archiver_role_exists`).

## What this does not do
Install anything into a cluster (Helm, cert-manager, External Secrets, CloudNativePG, the load balancer controller, Flux): that is the charts' and a later task. Nitro enclaves and the KMS adapter (T7). The load test (P4). Vault. Central monitoring.
See "What is still unproven" in the runbook.

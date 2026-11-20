# Runbook: the first deploy on AWS

The Terraform in [`deploy/cloud/aws`](../../deploy/cloud/aws/README.md) builds four clusters in four AWS accounts and an audit account. **It has never been applied.** It was written and checked with no account:
format, validate, a mocked-provider test of the isolation rules, lint and a security scan (`deploy/cloud/aws/check.sh`). Whatever only a real account can show is listed at the end. Read the design note in its README first.

## 1. What a person makes by hand

Terraform does not make these, on purpose: each needs the management account or a secret.

| What | How | Who |
|---|---|---|
| The organization and a **management account** that holds nothing else | AWS Organizations | the owner of the company's AWS relationship |
| Five member accounts: `business`, `signing-core`, `party-b`, `party-c`, `audit` | Organizations, one root e-mail each | same |
| Single sign-on (IAM Identity Center) and **one permission set per account**; nobody gets a role in two party accounts | Identity Center | same, then each domain's lead |
| Guardrail policies (SCPs) on the member accounts: deny leaving the organization; deny `cloudtrail:StopLogging`, `cloudtrail:DeleteTrail`, `ec2:DeleteFlowLogs`; deny `ec2:CreateVpcPeeringConnection`, `ec2:CreateTransitGateway`, `ec2:CreateInternetGateway` and `ec2:CreateNatGateway` in `signing-core`, `party-b`, `party-c`; deny `s3:PutAccountPublicAccessBlock` changes; limit regions | Organizations | same |
| A **state bucket in each account** (own account, versioning on, public access blocked, default encryption with a key of that account, `alias/qv-tfstate`, bucket policy: that account's Terraform role only) | console or CLI, once | each domain's lead |
| A read-only token for ghcr.io in **each** workload account's Secrets Manager, secret name starting `ecr-pullthroughcache/` | console | each domain's lead |
| The Identity Center role ARNs that may use each cluster (variable `operators`) | copy from Identity Center | each domain's lead |

**Who holds which credentials.** One person (or small group) per domain holds the Terraform role of that account, and nothing else. The `audit` account has its own, different people. No one holds credentials of two party accounts. CI holds none (the workflow has no role, no secret and no network path to AWS).
Because every root sets `allowed_account_ids`, applying with the wrong account's credentials fails before anything changes.

Each root: copy `backend.hcl.example` to `backend.hcl` and `terraform.tfvars.example` to `terraform.tfvars` in your own configuration repository (both are git-ignored here), then `terraform init -backend-config=backend.hcl`.

## 2. Apply order

The endpoint services need load balancers that the charts create, so each root is applied twice. Steps in order:

| # | Where | What |
|---|---|---|
| 1 | `roots/audit` | `terraform apply`. Buckets (Object Lock, COMPLIANCE), keys. The archive admits nobody but this account yet |
| 2 | `roots/business`, `roots/party-b`, `roots/party-c`, `roots/signing-core` | `terraform apply` each (any order, by different people). Accounts' baseline, network, cluster, keys, backup buckets, roles |
| 3 | `roots/audit` | set `archiver_role_exists = true`, apply. Now the archiver role of the business account may put and read, and is denied everything else |
| 4 | each cluster | through the ops host (below): install what the charts assume: the AWS Load Balancer Controller (role in the output `lb_controller_role_arn`), External Secrets (`eso_role_arn`), CloudNativePG, cert-manager, then the charts with `deploy/cloud/aws/values/*.yaml` |
| 5 | `roots/business`, `roots/party-b`, `roots/party-c` | set `nlb_services` to the `namespace/service` of the `LoadBalancer` Services the charts made, apply. Output `endpoint_services` |
| 6 | the provider's account | accept each connection request (`aws ec2 describe-vpc-endpoint-connections`, then `accept-vpc-endpoint-connections`): a person reads the consumer's account number first |
| 7 | `roots/signing-core`, `roots/party-b`, `roots/party-c` | copy the service names into `endpoint_service_names` (path id → name), apply. Outputs `endpoint_ips` |
| 8 | charts | put the endpoint addresses and the HSM addresses into the NetworkPolicy values (`values/*.yaml`), upgrade |
| 9 | party accounts, only if `enable_cloudhsm` | initialise the CloudHSM by hand (cluster certificate, crypto officer, crypto user for the sealer); the PIN goes into Secrets Manager under `qv/<domain>/`, never into Terraform |

**Reaching a private cluster.** Set `enable_ops_host = true` and apply. An operator starts a Session Manager port forward to the cluster endpoint
(`aws ssm start-session --target <ops_host_instance_id> --document-name AWS-StartPortForwardingSessionToRemoteHost --parameters host=<endpoint host>,portNumber=443,localPortNumber=8443`),
points kubectl at `https://localhost:8443` with the cluster's name as TLS server name, and uses their own Identity Center login. Turn the host off when nobody needs it.

## 3. What it costs to leave running

Prices are on-demand, in US dollars, as the pages stated them on 2026-11-20; the pages did not show a Frankfurt rate, so check your region in the [pricing calculator](https://calculator.aws/). **Hourly items are marked ⏱.**

| Item | Price (source) | Count in the smallest useful footprint (2 zones) | Per hour |
|---|---|---|---|
| ⏱ EKS control plane | $0.10 per cluster-hour, standard support ([EKS pricing](https://aws.amazon.com/eks/pricing/)) | 4 | 0.40 |
| ⏱ NAT gateway (business only) | $0.045 per hour + $0.045 per GB (the page's US East (Ohio) example; [VPC pricing](https://aws.amazon.com/vpc/pricing/)) | 2 | 0.09 |
| ⏱ Interface endpoints (AWS services and the PrivateLink links) | $0.01 per ENI-hour (an example on the [PrivateLink pricing](https://aws.amazon.com/privatelink/pricing/) page, not a rate table; **check**) + $0.01 per GB | about 80 ENIs: 8 and 13 and 10 and 9 endpoints, two zones each | 0.80 |
| ⏱ Network load balancers for the endpoint services | $0.0225 per hour + LCU ([ELB pricing](https://aws.amazon.com/elasticloadbalancing/pricing/)) | 6 | 0.14 |
| ⏱ Worker nodes | not readable from the pricing page: look up `m7i.large` ([EC2 on-demand](https://aws.amazon.com/ec2/pricing/on-demand/)) | 2 per cluster, 8 | ? |
| ⏱ CloudHSM (off by default) | not readable: look up hsm1.medium / hsm2m.medium ([CloudHSM pricing](https://aws.amazon.com/cloudhsm/pricing/)); billed from creation, per HSM | 0, or 1 per party | ? |
| ⏱ Ops host | a `t3.micro`, look up | 0 or 1 | ? |
| Disks, backups, logs | per GB-month ([EBS pricing](https://aws.amazon.com/ebs/pricing/), S3, CloudWatch) | about 100 GB per node | ? |
| KMS keys, Secrets Manager, ECR | per key / secret / GB-month | about 20 keys | ? |

**Sum of the priced hourly items: about $1.43 per hour, about $1,040 for a 730-hour month, before nodes, HSMs, disks and traffic.** The endpoints are the largest part, which is why the small footprint matters. Nodes and HSMs are the unknowns: fill them in from the calculator before the first apply.
The audit buckets are Object Lock COMPLIANCE: what is written there **stays and is billed until its retention ends**, in a test account too.

## 4. Small footprint for the load test

For a throw-away account set (design decision D14):

- `availability_zones` with two zones, one node group of two `m7i.large` (`min_size = 2`, `desired_size = 2`) per cluster, `enable_cloudhsm = false` (SoftHSM, and say so in the measurement), `enable_ops_host = true` only while operators work, no optional path.
- In the `audit` root set `audit_heads_retention_days = 1` and `log_retention_days = 1`, and in the business chart `archive.retention: 24h`. **Only in an account set that will be closed**: the lock cannot be lifted by anyone, so a long retention in a test account is a long bill.
- The load test (P4) runs on this shape; larger nodes are a change of `node_groups` and nothing else.

## 5. Teardown

Order matters: nothing may be deleted while something still uses it.

1. In each cluster, uninstall the charts (this removes the load balancers and the `LoadBalancer` Services). Wait until the NLBs are gone.
2. `terraform destroy` the consumers (`signing-core`, then `party-b`, `party-c`) after emptying `endpoint_service_names`; then the providers after emptying `nlb_services`.
3. Destroy `business`, `party-b`, `party-c`, `signing-core`. If CloudHSM was on, the HSMs go first (they bill by the hour), then the cluster.
4. The audit buckets **cannot be emptied or deleted** while their retention runs: `terraform destroy` fails on them. Remove them from state (`terraform state rm`) and let them expire, or leave the audit account open until they do. Closing an account does not shorten retention (AWS's rule for Object Lock; confirm in the Object Lock documentation before relying on it).
5. KMS keys are scheduled for deletion (30 days) and bill until then. ECR repositories made by the pull-through cache: delete them by hand.
6. The state buckets, the ghcr secrets, the Identity Center assignments and the accounts: by hand.

## 6. What is still unproven

- Nothing has been applied. Every resource argument was checked by the provider's schema (`validate`) and by a mocked test, not by AWS. Expect small errors on the first apply.
- The load balancer controller's policy is a hand-made subset of the upstream one: compare it with the upstream file of the version you install ([`policies/README.md`](../../deploy/cloud/aws/modules/irsa/policies/README.md)).
- Kafka through one network load balancer needs one listener per broker and advertised addresses that match the endpoint names (ports 9092-9094 are assumed): the Redpanda values must be set to match. Not tried.
- NetworkPolicy peers: PrivateLink traffic reaches pods from the NLB's addresses (private subnets), not from the other VPC. The values files use subnet ranges for the business side.
- ECR pull-through cache with digests and Kyverno image-signature checks: the signatures live next to the images on ghcr.io; whether the cache serves them to the admission check is unconfirmed. `qv-policy`'s registry value must name the ECR host.
- The chart default `network.archive` allows public addresses on 443 (the S3 gateway endpoint carries that traffic inside AWS); narrow it with the S3 prefix list if you can.
- EKS add-on versions are the cluster's defaults; the Kubernetes version default is 1.32 (the charts need 1.30 or later). Check what EKS offers when you apply.
- The control-plane (API-server audit) logs stay in a CloudWatch log group of the workload account. They are not yet copied to the audit account.
- CloudHSM: the sealer change (D12) is not merged; the HSM addresses and ports are right for the client library, the rest is by hand and untested.

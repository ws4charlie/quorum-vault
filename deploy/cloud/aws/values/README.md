# Chart values for the AWS shape

One file per cluster. Each value that comes from Terraform is written as `<output: root.name>`; replace it with the real output (`terraform output -json`) in your own
config repository. **No file here holds a secret**, and the placeholders are not valid values: the charts refuse to render until they are replaced.
`../check.sh` (step `values`) checks them two ways: `values_test.py` (every key exists in the chart's `values.yaml`) and `render_test.py`, which renders each chart with its AWS values (`helm template`) and asserts that every non-optional path of `../paths.json` has its allow rule on both ends (all endpoint interfaces, the ports) and that nothing else is open. Known chart gaps are listed in `KNOWN_GAPS` there.

Use them as a second `-f` file after the chart's own `values.yaml`: `helm install ... -f values.yaml -f deploy/cloud/aws/values/business.yaml`.

## Chart assumptions the AWS shape touches

| Assumption in the charts | On AWS | Action |
|---|---|---|
| `qv-policy` accepts a `LoadBalancer` only with `quorumvault.io/endpoint: private` and the internal annotations (AWS default: `aws-load-balancer-type: external` + `scheme: internal`) | the party files set exactly these, plus `nlb-target-type: ip`; the load balancer controller makes the NLB, Terraform then reads it by its stack tag (`nlb_services`) | none; add `nlb-target-type` to the policy only if you want to force it |
| `storageClassName: ""` = cluster default | EKS's default `gp2` class is unencrypted by a customer key | make a `qv-gp3-encrypted` StorageClass (`ebs.csi.aws.com`, `type: gp3`, `encrypted: "true"`, `kmsKeyId` = the output key, `WaitForFirstConsumer`) and name it in the party files. **Not in any chart yet** (lead) |
| Party volume `ReadWriteOncePod` | supported by the EBS CSI driver on 1.29+ | none. An EBS volume lives in one zone: a party pod cannot move to another zone without restoring (plan for it) |
| Kubernetes minimum 1.30 (every chart: `kubeVersion: ">=1.30.0-0"`) | `kubernetes_version` refuses below 1.30; default 1.32 | check what EKS offers |
| NetworkPolicy enforced by the CNI | the VPC CNI add-on is set to `enableNetworkPolicy` | none |
| PrivateLink peers in NetworkPolicy | the target sees NLB addresses, not the consumer VPC | use the private subnet ranges (business) and the endpoint addresses (consumers), as the files show |
| Image host `ghcr.io/...` by digest | pulled through the account's ECR cache: `<account>.dkr.ecr.<region>.amazonaws.com/ghcr/ws4charlie/quorum-vault/...` | set `images.*.repository` and `qv-policy` `registry` to the ECR host (output `ecr_registry`); the digests stay |
| Archiver credentials | `credentialsSecret: ""` + IRSA annotation + `automountToken: true` | as in `business.yaml` |
| Service-account names (archiver, database pods) | roles are bound to `qv-business-archiver`, `qv-business-db`, `qv-temporal-db`, `qv-guard` | must equal what `helm template` renders; they are Terraform variables |
| Guard database in another namespace | the party and signing-core charts select the database pods in their own namespace, and the database policies they render apply there | run the guard database in the **same namespace** as the release (Terraform `namespace_database` defaults to `qv-signing`, `qv-party-b`, `qv-party-c`) |
| One Kafka port (`network.kafka.port`) in `qv-signing-core` and `qv-business` | three brokers behind the endpoint: 9092, 9093, 9094 | **chart change for the lead**: take a list of ports; until then only 9092 is open (tracked in `render_test.py`) |
| PrivateLink sources on a party's caller and peer ports | the NLB nodes' addresses: this VPC's private subnets (output `private_subnet_cidrs`) | `network.callerIngress.from` and `peerIngress.from` in `party-b.yaml`, `party-c.yaml` |

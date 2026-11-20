# Business domain: core, workers, relay, archiver, Kafka (Redpanda), Temporal, the ledger database. Holds no key material.
# This is the only domain with a way out to the internet (NAT), because it talks to chain nodes and the identity provider.
# It has NO route to any other domain: other domains reach it through two endpoint services (Postgres, Kafka) and, if switched on, one for metrics.

locals {
  domain  = "business"
  name    = "qv-${local.domain}"
  account = var.account_ids[local.domain]

  flow_bucket_arn = "arn:aws:s3:::${var.bucket_prefix}-qv-flowlogs"
  trail_bucket    = "${var.bucket_prefix}-qv-cloudtrail"
  heads_bucket    = "${var.bucket_prefix}-qv-audit-heads"

  # What the cluster needs from AWS without leaving the VPC. Each interface endpoint bills per zone and hour.
  endpoints = concat(
    ["ecr.api", "ecr.dkr", "sts", "logs", "ec2", "elasticloadbalancing", "secretsmanager", "kms"],
    var.enable_ops_host ? ["ssm", "ssmmessages", "ec2messages"] : [],
  )

  databases = {
    ledger   = { service_account = "qv-business-db", bucket = "${var.bucket_prefix}-${local.name}-backup-ledger" }
    temporal = { service_account = "qv-temporal-db", bucket = "${var.bucket_prefix}-${local.name}-backup-temporal" }
  }
}

module "paths" {
  source                 = "../../modules/paths"
  domain                 = local.domain
  account_ids            = var.account_ids
  enabled_optional_paths = var.enabled_optional_paths
}

# --- account ---

module "kms_ebs" {
  source       = "../../modules/kms"
  name         = "${local.name}-ebs"
  description  = "Disks and volumes of the business cluster"
  account_id   = local.account
  region       = var.region
  via_services = ["ec2"]
}

module "kms_secrets" {
  source       = "../../modules/kms"
  name         = "${local.name}-secrets"
  description  = "Kubernetes Secrets in etcd and Secrets Manager"
  account_id   = local.account
  region       = var.region
  via_services = ["secretsmanager"]
}

module "kms_logs" {
  source             = "../../modules/kms"
  name               = "${local.name}-logs"
  description        = "Control-plane logs"
  account_id         = local.account
  region             = var.region
  service_principals = ["logs.${var.region}.amazonaws.com"]
}

module "kms_backup" {
  source      = "../../modules/kms"
  name        = "${local.name}-backup"
  description = "Database backups and the container image cache"
  account_id  = local.account
  region      = var.region
}

module "baseline" {
  source                 = "../../modules/baseline"
  name                   = local.name
  ebs_kms_key_arn        = module.kms_ebs.arn
  cloudtrail_bucket_name = local.trail_bucket
}

# --- network and cluster ---

module "network" {
  source              = "../../modules/network"
  name                = local.name
  region              = var.region
  vpc_cidr            = module.paths.domain_cidr
  availability_zones  = var.availability_zones
  egress_mode         = "nat"
  interface_endpoints = local.endpoints
  flow_log_bucket_arn = local.flow_bucket_arn
  cluster_name        = local.name
}

module "cluster" {
  source              = "../../modules/cluster"
  name                = local.name
  region              = var.region
  account_id          = local.account
  kubernetes_version  = var.kubernetes_version
  vpc_id              = module.network.vpc_id
  subnet_ids          = module.network.private_subnet_ids
  secrets_kms_key_arn = module.kms_secrets.arn
  ebs_kms_key_arn     = module.kms_ebs.arn
  logs_kms_key_arn    = module.kms_logs.arn
  log_retention_days  = var.log_retention_days
  access_entries      = var.operators
  api_allowed_cidrs   = [module.network.vpc_cidr]
  node_groups         = var.node_groups
}

module "registry" {
  source                  = "../../modules/registry"
  region                  = var.region
  account_id              = local.account
  upstream_credential_arn = var.ecr_upstream_credential_arn
  kms_key_arn             = module.kms_backup.arn
}

module "ops_host" {
  source      = "../../modules/ops-host"
  enabled     = var.enable_ops_host
  name        = local.name
  vpc_id      = module.network.vpc_id
  vpc_cidr    = module.network.vpc_cidr
  subnet_id   = module.network.private_subnet_ids[0]
  kms_key_arn = module.kms_ebs.arn
}

# --- pods that need AWS: each has its own role, for one service account ---

module "database" {
  for_each           = local.databases
  source             = "../../modules/database"
  name               = "qv-${each.key}"
  backup_bucket_name = each.value.bucket
  kms_key_arn        = module.kms_backup.arn
  oidc_provider_arn  = module.cluster.oidc_provider_arn
  oidc_issuer_url    = module.cluster.oidc_issuer_url
  namespace          = var.namespaces.database
  service_account    = each.value.service_account
}

# The archiver: write-only into the audit account's bucket. The same deny list as in docs/runbooks/audit-archive.md, and nothing else.
module "archiver" {
  source            = "../../modules/irsa"
  name              = "qv-archiver"
  oidc_provider_arn = module.cluster.oidc_provider_arn
  oidc_issuer_url   = module.cluster.oidc_issuer_url
  namespace         = var.namespaces.business
  service_account   = var.archiver_service_account
  policy_statements = [
    {
      Effect   = "Allow"
      Action   = ["s3:PutObject", "s3:GetObject", "s3:GetObjectVersion"]
      Resource = "arn:aws:s3:::${local.heads_bucket}/heads/*"
    },
    {
      Effect   = "Allow"
      Action   = ["s3:ListBucket", "s3:ListBucketVersions", "s3:GetBucketObjectLockConfiguration", "s3:GetBucketVersioning"]
      Resource = "arn:aws:s3:::${local.heads_bucket}"
    },
    {
      Effect    = "Allow"
      Action    = ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"]
      Resource  = "arn:aws:kms:${var.region}:${var.account_ids["audit"]}:key/*"
      Condition = { "ForAnyValue:StringEquals" = { "kms:ResourceAliases" = "alias/qv-audit-heads" } }
    },
    {
      Effect = "Deny"
      Action = [
        "s3:DeleteObject", "s3:DeleteObjectVersion", "s3:BypassGovernanceRetention", "s3:PutObjectRetention", "s3:PutObjectLegalHold",
        "s3:PutBucketObjectLockConfiguration", "s3:PutLifecycleConfiguration", "s3:PutBucketVersioning", "s3:DeleteBucket", "s3:PutBucketPolicy",
      ]
      Resource = ["arn:aws:s3:::${local.heads_bucket}", "arn:aws:s3:::${local.heads_bucket}/*"]
    },
  ]
}

# External Secrets: reads only the secrets under qv/business/ and decrypts only with this account's secrets key.
module "eso" {
  source            = "../../modules/irsa"
  name              = "${local.name}-external-secrets"
  oidc_provider_arn = module.cluster.oidc_provider_arn
  oidc_issuer_url   = module.cluster.oidc_issuer_url
  namespace         = "external-secrets"
  service_account   = "external-secrets"
  policy_statements = [
    {
      Effect   = "Allow"
      Action   = ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"]
      Resource = "arn:aws:secretsmanager:${var.region}:${local.account}:secret:qv/${local.domain}/*"
    },
    {
      Effect   = "Allow"
      Action   = ["kms:Decrypt", "kms:DescribeKey"]
      Resource = module.kms_secrets.arn
    },
  ]
}

# The AWS Load Balancer Controller: makes the internal network load balancers the charts ask for (Service type LoadBalancer, internal annotations).
# Network load balancers only (no ALB, no WAF, no Shield): the policy is the NLB subset of the upstream one.
module "lb_controller" {
  source            = "../../modules/irsa"
  name              = "${local.name}-lb-controller"
  oidc_provider_arn = module.cluster.oidc_provider_arn
  oidc_issuer_url   = module.cluster.oidc_issuer_url
  namespace         = "kube-system"
  service_account   = "aws-load-balancer-controller"
  policy_statements = jsondecode(file("${path.module}/../../modules/irsa/policies/lb-controller-nlb.json"))
}

# --- the way other domains reach this one: PHASE 2, after the charts made the load balancers ---

data "aws_lb" "service" {
  for_each = var.nlb_services
  tags     = { "service.k8s.aws/stack" = each.value }
}

module "private_link" {
  source = "../../modules/private-link"
  name   = local.name
  services = {
    for s, nlb in data.aws_lb.service : s => {
      nlb_arn             = nlb.arn
      allowed_account_ids = module.paths.provides[s].allowed_account_ids
    }
  }
  vpc_id     = module.network.vpc_id
  vpc_cidr   = module.network.vpc_cidr
  subnet_ids = module.network.private_subnet_ids
}

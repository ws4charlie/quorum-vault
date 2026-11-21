# Signing core: the gateway and party A.
# No internet: there is no internet gateway, no NAT and no route out of the VPC. Images come from the account's ECR cache through endpoints.
# This domain only CALLS OUT through the endpoints below.

locals {
  domain  = "signing-core"
  name    = "qv-signing-core"
  account = var.account_ids[local.domain]

  flow_bucket_arn = "arn:aws:s3:::${var.bucket_prefix}-qv-flowlogs"
  trail_bucket    = "${var.bucket_prefix}-qv-cloudtrail"

  endpoints = concat(
    ["ecr.api", "ecr.dkr", "sts", "logs", "ec2", "secretsmanager", "kms"],
    var.enable_ops_host ? ["ssm", "ssmmessages", "ec2messages"] : [],
  )
}

module "paths" {
  source                 = "../../modules/paths"
  domain                 = local.domain
  account_ids            = var.account_ids
  enabled_optional_paths = var.enabled_optional_paths
}

module "kms_ebs" {
  source       = "../../modules/kms"
  name         = "${local.name}-ebs"
  description  = "Disks and volumes of the signing-core cluster"
  account_id   = local.account
  region       = var.region
  via_services = ["ec2"]
}

module "kms_secrets" {
  source       = "../../modules/kms"
  name         = "${local.name}-secrets"
  description  = "Kubernetes Secrets in etcd and Secrets Manager (the HSM PIN)"
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
  description = "Guard-database backups, the party's backup bucket and the container image cache"
  account_id  = local.account
  region      = var.region
}

module "baseline" {
  source                 = "../../modules/baseline"
  name                   = local.name
  ebs_kms_key_arn        = module.kms_ebs.arn
  cloudtrail_bucket_name = local.trail_bucket
}

module "network" {
  source              = "../../modules/network"
  name                = local.name
  region              = var.region
  vpc_cidr            = module.paths.domain_cidr
  availability_zones  = var.availability_zones
  egress_mode         = "isolated"
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

# The HSM of this party, in this party's account. Off unless enabled.
module "hsm" {
  source                   = "../../modules/hsm"
  enabled                  = var.enable_cloudhsm
  name                     = local.name
  subnet_ids               = module.network.private_subnet_ids
  hsm_count                = var.hsm_count
  client_security_group_id = module.cluster.cluster_security_group_id
}

# The guard database's backups (gateway's replay guard and audit chain). Never restore one to an older point without the runbook's decision.
module "database" {
  source             = "../../modules/database"
  name               = "qv-guard"
  backup_bucket_name = "${var.bucket_prefix}-${local.name}-backup-guard"
  kms_key_arn        = module.kms_backup.arn
  oidc_provider_arn  = module.cluster.oidc_provider_arn
  oidc_issuer_url    = module.cluster.oidc_issuer_url
  namespace          = var.namespace_database
  service_account    = "qv-guard"
}

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

# --- the links this domain opens towards others: PHASE 2, after the provider roots gave their endpoint service names ---

locals {
  links = {
    for id, c in module.paths.consumes : id => { service_name = var.endpoint_service_names[id], ports = c.ports, dns = c.dns }
    if contains(keys(var.endpoint_service_names), id)
  }
}

module "private_link" {
  source     = "../../modules/private-link"
  name       = local.name
  links      = local.links
  vpc_id     = module.network.vpc_id
  vpc_cidr   = module.network.vpc_cidr
  subnet_ids = module.network.private_subnet_ids
}

# The audit account: the only place that holds the audit-head archive (S3 Object Lock, COMPLIANCE) and the logs the workload accounts cannot delete.
# It has no network, no cluster and no workload. Its administrators are not the administrators of any domain.

locals {
  domain           = "audit"
  name             = "qv-${local.domain}"
  account          = var.account_ids[local.domain]
  workload_domains = ["business", "signing-core", "party-b", "party-c"]
  all_domains      = concat(local.workload_domains, ["audit"])

  heads_bucket = "${var.bucket_prefix}-qv-audit-heads"
  trail_bucket = "${var.bucket_prefix}-qv-cloudtrail"
  flow_bucket  = "${var.bucket_prefix}-qv-flowlogs"

  archiver_arn = "arn:aws:iam::${var.account_ids["business"]}:role/${var.archiver_role_name}"

  # The deny list of docs/runbooks/audit-archive.md, applied to the archiver in the bucket as well as in its own policy.
  archiver_denied = [
    "s3:DeleteObject", "s3:DeleteObjectVersion", "s3:BypassGovernanceRetention", "s3:PutObjectRetention", "s3:PutObjectLegalHold",
    "s3:PutBucketObjectLockConfiguration", "s3:PutLifecycleConfiguration", "s3:PutBucketVersioning", "s3:DeleteBucket", "s3:PutBucketPolicy",
  ]
}

module "baseline" {
  source                 = "../../modules/baseline"
  name                   = local.name
  ebs_kms_key_arn        = module.kms_ebs.arn
  cloudtrail_bucket_name = module.trail_bucket.name
  depends_on             = [module.trail_bucket]
}

module "kms_ebs" {
  source       = "../../modules/kms"
  name         = "${local.name}-ebs"
  description  = "Default EBS key of the audit account"
  account_id   = local.account
  region       = var.region
  via_services = ["ec2"]
}

# The archive's key: named roles of the business account may use it, nobody else outside this account.
module "kms_heads" {
  source             = "../../modules/kms"
  name               = "qv-audit-heads"
  description        = "Encrypts the audit-head archive"
  account_id         = local.account
  region             = var.region
  external_user_arns = [local.archiver_arn]
}

module "kms_logs" {
  source             = "../../modules/kms"
  name               = "qv-audit-logs"
  description        = "Encrypts CloudTrail and flow logs delivered by the other accounts"
  account_id         = local.account
  region             = var.region
  service_principals = ["cloudtrail.amazonaws.com", "delivery.logs.amazonaws.com"]
  source_account_ids = [for d in local.all_domains : var.account_ids[d]]
}

module "heads_bucket" {
  source      = "../../modules/bucket"
  name        = local.heads_bucket
  kms_key_arn = module.kms_heads.arn
  object_lock = { enabled = true, days = var.audit_heads_retention_days }
  extra_policy_statements = [
    {
      Sid       = "ArchiverReadAndPut"
      Effect    = "Allow"
      Principal = { AWS = local.archiver_arn }
      Action    = ["s3:PutObject", "s3:GetObject", "s3:GetObjectVersion"]
      Resource  = "arn:aws:s3:::${local.heads_bucket}/heads/*"
    },
    {
      Sid       = "ArchiverList"
      Effect    = "Allow"
      Principal = { AWS = local.archiver_arn }
      Action    = ["s3:ListBucket", "s3:ListBucketVersions", "s3:GetBucketObjectLockConfiguration", "s3:GetBucketVersioning"]
      Resource  = "arn:aws:s3:::${local.heads_bucket}"
    },
    {
      Sid       = "ArchiverNeverChangesOrDeletes"
      Effect    = "Deny"
      Principal = { AWS = local.archiver_arn }
      Action    = local.archiver_denied
      Resource  = ["arn:aws:s3:::${local.heads_bucket}", "arn:aws:s3:::${local.heads_bucket}/*"]
    },
  ]
}

module "trail_bucket" {
  source      = "../../modules/bucket"
  name        = local.trail_bucket
  kms_key_arn = module.kms_logs.arn
  object_lock = { enabled = true, days = var.log_retention_days }
  extra_policy_statements = [
    {
      Sid       = "CloudTrailAclCheck"
      Effect    = "Allow"
      Principal = { Service = "cloudtrail.amazonaws.com" }
      Action    = "s3:GetBucketAcl"
      Resource  = "arn:aws:s3:::${local.trail_bucket}"
      Condition = { StringEquals = { "aws:SourceArn" = [for d in local.all_domains : "arn:aws:cloudtrail:${var.region}:${var.account_ids[d]}:trail/qv-${d}-trail"] } }
    },
    {
      Sid       = "CloudTrailWrite"
      Effect    = "Allow"
      Principal = { Service = "cloudtrail.amazonaws.com" }
      Action    = "s3:PutObject"
      Resource  = [for d in local.all_domains : "arn:aws:s3:::${local.trail_bucket}/qv-${d}/AWSLogs/${var.account_ids[d]}/*"]
      Condition = { StringEquals = { "aws:SourceArn" = [for d in local.all_domains : "arn:aws:cloudtrail:${var.region}:${var.account_ids[d]}:trail/qv-${d}-trail"] } }
    },
  ]
}

module "flow_bucket" {
  source      = "../../modules/bucket"
  name        = local.flow_bucket
  kms_key_arn = module.kms_logs.arn
  object_lock = { enabled = true, days = var.log_retention_days }
  extra_policy_statements = [
    {
      Sid       = "FlowLogsWrite"
      Effect    = "Allow"
      Principal = { Service = "delivery.logs.amazonaws.com" }
      Action    = "s3:PutObject"
      Resource  = [for d in local.workload_domains : "arn:aws:s3:::${local.flow_bucket}/qv-${d}/AWSLogs/${var.account_ids[d]}/*"]
      Condition = { StringEquals = { "aws:SourceAccount" = [for d in local.workload_domains : var.account_ids[d]] } }
    },
    {
      Sid       = "FlowLogsCheck"
      Effect    = "Allow"
      Principal = { Service = "delivery.logs.amazonaws.com" }
      Action    = ["s3:GetBucketAcl", "s3:ListBucket"]
      Resource  = "arn:aws:s3:::${local.flow_bucket}"
      Condition = { StringEquals = { "aws:SourceAccount" = [for d in local.workload_domains : var.account_ids[d]] } }
    },
  ]
}

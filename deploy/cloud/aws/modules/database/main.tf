# The AWS side of an in-cluster PostgreSQL (CloudNativePG): a backup bucket under a customer key and the role that the database pods use to write to it.
# The database itself is NOT made here. It stays in the cluster because the certificate-name-to-role map (docs/runbooks/database-roles.md) needs a server
# that accepts our own client CA and a pg_ident map; Amazon RDS does not document either (deploy/cloud/aws/README.md, "State").
# A backup of a guard database must never be restored to an older point without an operator's decision (the replay guard goes with it): see the runbook.

module "backups" {
  source                 = "../bucket"
  name                   = var.backup_bucket_name
  kms_key_arn            = var.kms_key_arn
  noncurrent_expiry_days = var.noncurrent_expiry_days
}

module "role" {
  source            = "../irsa"
  name              = "${var.name}-backup"
  oidc_provider_arn = var.oidc_provider_arn
  oidc_issuer_url   = var.oidc_issuer_url
  namespace         = var.namespace
  service_account   = var.service_account
  policy_statements = [
    {
      Effect   = "Allow"
      Action   = ["s3:ListBucket", "s3:GetBucketLocation"]
      Resource = module.backups.arn
    },
    {
      Effect   = "Allow"
      Action   = ["s3:PutObject", "s3:GetObject", "s3:DeleteObject", "s3:AbortMultipartUpload", "s3:ListMultipartUploadParts"]
      Resource = "${module.backups.arn}/${var.name}/*"
    },
    {
      Effect   = "Allow"
      Action   = ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey", "kms:DescribeKey"]
      Resource = var.kms_key_arn
    },
  ]
}

# What every account gets: nothing public, encrypted disks by default, IMDSv2 by default, a password policy for the few IAM users that may exist,
# and a CloudTrail that writes to the audit account. The organization, the accounts and the guardrail policies (SCPs) are made by hand: see the runbook.

resource "aws_s3_account_public_access_block" "this" {
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_ebs_encryption_by_default" "this" {
  enabled = true
}

resource "aws_ebs_default_kms_key" "this" {
  key_arn    = var.ebs_kms_key_arn
  depends_on = [aws_ebs_encryption_by_default.this]
}

resource "aws_ec2_instance_metadata_defaults" "this" {
  http_tokens                 = "required"
  http_put_response_hop_limit = 1
}

resource "aws_iam_account_password_policy" "this" {
  minimum_password_length        = var.password_min_length
  require_lowercase_characters   = true
  require_uppercase_characters   = true
  require_numbers                = true
  require_symbols                = true
  password_reuse_prevention      = 24
  max_password_age               = 90
  allow_users_to_change_password = true
}

# No kms_key_id on purpose: the trail is encrypted by the audit bucket's own key, which lives in the audit account.
# A key owned by this account could be scheduled for deletion by this account's administrators, and the log would become unreadable.
resource "aws_cloudtrail" "this" {
  name                          = "${var.name}-trail"
  s3_bucket_name                = var.cloudtrail_bucket_name
  s3_key_prefix                 = var.name
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true
}

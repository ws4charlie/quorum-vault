mock_provider "aws" {}

variables {
  name                   = "qv-test"
  ebs_kms_key_arn        = "arn:aws:kms:eu-central-1:111111111111:key/e"
  cloudtrail_bucket_name = "acme-qv-cloudtrail"
}

run "account_defaults_are_private_encrypted_and_logged_elsewhere" {
  assert {
    condition     = aws_s3_account_public_access_block.this.block_public_acls && aws_s3_account_public_access_block.this.block_public_policy && aws_s3_account_public_access_block.this.ignore_public_acls && aws_s3_account_public_access_block.this.restrict_public_buckets
    error_message = "no public bucket in the account"
  }
  assert {
    condition     = aws_ebs_encryption_by_default.this.enabled && aws_ebs_default_kms_key.this.key_arn == "arn:aws:kms:eu-central-1:111111111111:key/e"
    error_message = "disks are encrypted by default with the account's customer key"
  }
  assert {
    condition     = aws_ec2_instance_metadata_defaults.this.http_tokens == "required" && aws_ec2_instance_metadata_defaults.this.http_put_response_hop_limit == 1
    error_message = "IMDSv2 only by default"
  }
  assert {
    condition     = output.log_file_validation && aws_cloudtrail.this.is_multi_region_trail && aws_cloudtrail.this.s3_bucket_name == "acme-qv-cloudtrail"
    error_message = "a multi-region trail with log-file validation delivers to the audit account's bucket"
  }
}

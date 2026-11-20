output "arn" {
  value = aws_s3_bucket.this.arn
}

output "name" {
  value = aws_s3_bucket.this.bucket
}

output "policy" {
  value = aws_s3_bucket_policy.this.policy
}

output "lock_mode" {
  value = var.object_lock.enabled ? aws_s3_bucket_object_lock_configuration.this[0].rule[0].default_retention[0].mode : "NONE"
}

output "lock_days" {
  value = var.object_lock.enabled ? aws_s3_bucket_object_lock_configuration.this[0].rule[0].default_retention[0].days : 0
}

output "public_access_blocked" {
  value = aws_s3_bucket_public_access_block.this.block_public_acls && aws_s3_bucket_public_access_block.this.block_public_policy && aws_s3_bucket_public_access_block.this.ignore_public_acls && aws_s3_bucket_public_access_block.this.restrict_public_buckets
}

output "encryption_key" {
  value = tolist(aws_s3_bucket_server_side_encryption_configuration.this.rule)[0].apply_server_side_encryption_by_default[0].kms_master_key_id
}

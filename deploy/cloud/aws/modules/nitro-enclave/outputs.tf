output "key_arn" {
  description = "ARN of the enclave key."
  value       = aws_kms_key.this.arn
}

output "key_id" {
  description = "Id of the enclave key."
  value       = aws_kms_key.this.key_id
}

output "policy" {
  description = "The key policy, JSON."
  value       = aws_kms_key.this.policy
}

output "parent_role_arn" {
  description = "The parent instance role (null when not created)."
  value       = var.create_parent_role ? aws_iam_role.parent[0].arn : null
}

output "parent_instance_profile_arn" {
  description = "The parent instance profile (null when not created)."
  value       = var.create_parent_role ? aws_iam_instance_profile.parent[0].arn : null
}

output "launch_template_id" {
  description = "The enclave host launch template (null when not created)."
  value       = var.create_launch_template ? aws_launch_template.host[0].id : null
}

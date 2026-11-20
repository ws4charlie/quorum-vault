output "role_arn" {
  value = aws_iam_role.this.arn
}

output "policy" {
  value = aws_iam_role_policy.this.policy
}

output "trust" {
  value = aws_iam_role.this.assume_role_policy
}

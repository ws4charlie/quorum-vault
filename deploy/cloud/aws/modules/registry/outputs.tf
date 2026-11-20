output "prefix" {
  value = aws_ecr_pull_through_cache_rule.ghcr.ecr_repository_prefix
}

output "registry_id" {
  value = aws_ecr_pull_through_cache_rule.ghcr.registry_id
}

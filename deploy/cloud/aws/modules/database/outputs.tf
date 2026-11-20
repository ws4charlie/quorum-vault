output "backup_bucket" {
  value = module.backups.name
}

output "role_arn" {
  value = module.role.role_arn
}

output "policy" {
  value = module.role.policy
}

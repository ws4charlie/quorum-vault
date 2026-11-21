output "audit_heads_bucket" {
  description = "Chart value qv-business archive.bucket."
  value       = module.heads_bucket.name
}

output "audit_heads_key_arn" {
  value = module.kms_heads.arn
}

output "cloudtrail_bucket" {
  value = module.trail_bucket.name
}

output "flowlogs_bucket_arn" {
  value = module.flow_bucket.arn
}

output "audit_heads_lock" {
  value = { mode = module.heads_bucket.lock_mode, days = module.heads_bucket.lock_days }
}

output "policies" {
  description = "Resource policies, for the tests."
  value = {
    heads_bucket = module.heads_bucket.policy
    trail_bucket = module.trail_bucket.policy
    flow_bucket  = module.flow_bucket.policy
    heads_key    = module.kms_heads.policy
    logs_key     = module.kms_logs.policy
  }
}

output "locks" {
  value = {
    heads = { mode = module.heads_bucket.lock_mode, days = module.heads_bucket.lock_days }
    trail = { mode = module.trail_bucket.lock_mode, days = module.trail_bucket.lock_days }
    flow  = { mode = module.flow_bucket.lock_mode, days = module.flow_bucket.lock_days }
  }
}

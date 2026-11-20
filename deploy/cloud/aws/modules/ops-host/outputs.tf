output "instance_id" {
  value = var.enabled ? aws_instance.this[0].id : null
}

output "enabled" {
  value = var.enabled
}

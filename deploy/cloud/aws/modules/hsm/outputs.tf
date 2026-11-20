output "enabled" {
  value = var.enabled
}

output "cluster_id" {
  value = var.enabled ? aws_cloudhsm_v2_cluster.this[0].cluster_id : null
}

output "hsm_ips" {
  description = "Addresses of the HSMs: the peers of network.hsm in the qv-party chart (ports 2223 to 2225)."
  value       = [for h in aws_cloudhsm_v2_hsm.this : h.ip_address]
}

output "cluster_name" {
  value = module.cluster.name
}

output "cluster_endpoint" {
  value = module.cluster.endpoint
}

output "vpc_cidr" {
  value = module.network.vpc_cidr
}

output "ops_host_instance_id" {
  value = module.ops_host.instance_id
}

output "ecr_registry" {
  value = "${local.account}.dkr.ecr.${var.region}.amazonaws.com/${module.registry.prefix}"
}

output "kms_keys" {
  value = {
    ebs     = module.kms_ebs.arn
    secrets = module.kms_secrets.arn
    backup  = module.kms_backup.arn
  }
}

output "eso_role_arn" {
  value = module.eso.role_arn
}

output "guard_backup" {
  value = { bucket = module.database.backup_bucket, role_arn = module.database.role_arn }
}

output "hsm" {
  description = "Chart value network.hsm.to: the HSM addresses (ports 2223 to 2225). Empty while CloudHSM is off."
  value       = { enabled = module.hsm.enabled, ips = module.hsm.hsm_ips }
}

output "endpoint_ips" {
  description = "PHASE 2. Per path: the private addresses of the endpoint in this VPC. They are the peers of the chart's network rules."
  value       = module.private_link.endpoint_ips
}

output "endpoint_services" {
  description = "PHASE 2. Give to the consumers' roots (variable endpoint_service_names): service => name."
  value       = module.private_link.service_names
}

output "policies" {
  description = "Every IAM policy this root writes (for the tests)."
  value = merge(
    { eso = module.eso.policy, database = module.database.policy },
    { for k, v in module.cluster.policies : "cluster-${k}" => v if k != "pull_through" },

  )
}

output "endpoint_public_access" {
  value = module.cluster.endpoint_public_access
}

output "route_destinations" {
  value = module.network.route_destinations
}

output "has_internet_gateway" {
  value = length(module.network.internet_gateway_ids) > 0
}

output "allowed_principals" {
  value = module.private_link.allowed_principals
}

output "provides" {
  value = module.paths.provides
}

output "consumes" {
  value = module.paths.consumes
}

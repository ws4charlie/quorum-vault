output "cluster_name" {
  value = module.cluster.name
}

output "cluster_endpoint" {
  value = module.cluster.endpoint
}

output "vpc_cidr" {
  value = module.network.vpc_cidr
}

output "private_subnet_cidrs" {
  description = "Source addresses the business pods see for PrivateLink traffic: the NLB nodes sit in these subnets (qv-business network.signingLink.from)."
  value       = module.network.private_subnet_cidrs
}

output "endpoint_services" {
  description = "PHASE 2. Give these to the other roots (variable endpoint_service_names): path => service name."
  value       = module.private_link.service_names
}

output "ops_host_instance_id" {
  value = module.ops_host.instance_id
}

output "node_role_arn" {
  value = module.cluster.node_role_arn
}

output "ecr_registry" {
  description = "Image host to put in the charts: <account>.dkr.ecr.<region>.amazonaws.com/<prefix>/ws4charlie/quorum-vault/..."
  value       = "${local.account}.dkr.ecr.${var.region}.amazonaws.com/${module.registry.prefix}"
}

output "kms_keys" {
  value = {
    ebs     = module.kms_ebs.arn
    secrets = module.kms_secrets.arn
    backup  = module.kms_backup.arn
  }
}

output "archiver_role_arn" {
  description = "Chart value qv-business archiver.serviceAccount.annotations[eks.amazonaws.com/role-arn]."
  value       = module.archiver.role_arn
}

output "eso_role_arn" {
  value = module.eso.role_arn
}

output "lb_controller_role_arn" {
  value = module.lb_controller.role_arn
}

output "database_backups" {
  value = { for k, d in module.database : k => { bucket = d.backup_bucket, role_arn = d.role_arn } }
}

output "policies" {
  description = "Every IAM policy this root writes (for the tests)."
  value = merge(
    { archiver = module.archiver.policy, eso = module.eso.policy, lb_controller = module.lb_controller.policy },
    { for k, d in module.database : "db-${k}" => d.policy },
    { for k, v in module.cluster.policies : "cluster-${k}" => v if k != "pull_through" },
  )
}

output "endpoint_public_access" {
  value = module.cluster.endpoint_public_access
}

output "route_destinations" {
  value = module.network.route_destinations
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

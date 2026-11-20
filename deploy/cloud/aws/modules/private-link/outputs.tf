output "service_names" {
  description = "Provider side: endpoint service name per service. Give these to the consumers' roots (variable endpoint_service_names)."
  value       = { for k, s in aws_vpc_endpoint_service.this : k => s.service_name }
}

output "allowed_principals" {
  description = "Provider side: service => accounts allowed to connect."
  value       = { for k, v in var.services : k => sort(v.allowed_account_ids) }
}

output "acceptance_required" {
  value = { for k, s in aws_vpc_endpoint_service.this : k => s.acceptance_required }
}

output "endpoint_ips" {
  description = "Consumer side: private addresses of each endpoint, per path id. They are the peers in the charts' NetworkPolicy values."
  value = {
    for k in keys(var.links) : k => [for i in range(length(var.subnet_ids)) : data.aws_network_interface.link["${k}/${i}"].private_ip]
  }
}

output "dns_names" {
  value = { for l in var.links : l.dns => true }
}

output "link_ports" {
  description = "Consumer side: ports opened per path id."
  value       = { for k, v in var.links : k => v.ports }
}

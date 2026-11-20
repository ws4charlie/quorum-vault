output "vpc_id" {
  value = aws_vpc.this.id
}

output "vpc_cidr" {
  value = aws_vpc.this.cidr_block
}

output "private_subnet_ids" {
  description = "In the order of availability_zones."
  value       = [for z in var.availability_zones : aws_subnet.private[z].id]
}

output "private_subnet_cidrs" {
  value = [for z in var.availability_zones : aws_subnet.private[z].cidr_block]
}

output "endpoint_security_group_id" {
  value = aws_security_group.endpoints.id
}

output "internet_gateway_ids" {
  value = [for g in aws_internet_gateway.this : g.id]
}

output "nat_gateway_ids" {
  value = [for g in aws_nat_gateway.this : g.id]
}

output "route_destinations" {
  description = "Every route this module creates, as destination cidr. In isolated mode the list is empty: the only route of a subnet is the local VPC route and the S3 gateway endpoint."
  value       = concat([for r in aws_route.private_default : r.destination_cidr_block], [for r in aws_route.public_default : r.destination_cidr_block])
}

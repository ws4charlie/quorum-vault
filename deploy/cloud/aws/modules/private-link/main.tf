# The only way between two trust domains: a PrivateLink endpoint service in the provider's account (an internal NLB, TCP, no TLS termination:
# the pinned mutual TLS passes through) and an interface endpoint in the consumer's VPC. One direction, one named account, named ports.
# No peering, no transit gateway: the two VPCs never share a route.

# --- provider ---

resource "aws_vpc_endpoint_service" "this" {
  for_each                   = var.services
  acceptance_required        = var.acceptance_required
  network_load_balancer_arns = [each.value.nlb_arn]
  tags                       = { Name = "${var.name}-${each.key}" }
}

locals {
  principals = merge([
    for s, v in var.services : {
      for a in v.allowed_account_ids : "${s}/${a}" => { service = s, account = a }
    }
  ]...)
}

resource "aws_vpc_endpoint_service_allowed_principal" "this" {
  for_each                = local.principals
  vpc_endpoint_service_id = aws_vpc_endpoint_service.this[each.value.service].id
  principal_arn           = "arn:aws:iam::${each.value.account}:root"
}

# --- consumer ---

resource "aws_security_group" "link" {
  for_each    = var.links
  name        = "${var.name}-${each.key}"
  description = "Endpoint ${each.key}: this VPC may open the listed ports, nothing else"
  vpc_id      = var.vpc_id
  tags        = { Name = "${var.name}-${each.key}" }
}

resource "aws_vpc_security_group_ingress_rule" "link" {
  for_each = merge([
    for k, l in var.links : { for p in l.ports : "${k}/${p}" => { link = k, port = p } }
  ]...)
  security_group_id = aws_security_group.link[each.value.link].id
  description       = "port ${each.value.port} from this VPC"
  cidr_ipv4         = var.vpc_cidr
  ip_protocol       = "tcp"
  from_port         = each.value.port
  to_port           = each.value.port
}

resource "aws_vpc_endpoint" "link" {
  for_each            = var.links
  vpc_id              = var.vpc_id
  service_name        = each.value.service_name
  vpc_endpoint_type   = "Interface"
  subnet_ids          = var.subnet_ids
  security_group_ids  = [aws_security_group.link[each.key].id]
  private_dns_enabled = false
  tags                = { Name = "${var.name}-${each.key}" }
}

resource "aws_route53_zone" "internal" {
  count   = length(var.links) > 0 ? 1 : 0
  name    = var.zone_name
  comment = "Names of the endpoints of other domains; visible inside this VPC only"
  vpc {
    vpc_id = var.vpc_id
  }
}

locals {
  dns_names = length(var.links) == 0 ? {} : { for n in distinct([for l in var.links : l.dns]) : n => [for k, l in var.links : k if l.dns == n][0] }
}

resource "aws_route53_record" "link" {
  for_each = local.dns_names
  zone_id  = aws_route53_zone.internal[0].zone_id
  name     = each.key
  type     = "CNAME"
  ttl      = 60
  records  = [try(aws_vpc_endpoint.link[each.value].dns_entry[0].dns_name, "")]
}

# Addresses of the endpoint interfaces: the charts' NetworkPolicies name these (a NetworkPolicy sees addresses, not names).
data "aws_network_interface" "link" {
  for_each = merge([
    for k in keys(var.links) : { for i in range(length(var.subnet_ids)) : "${k}/${i}" => { link = k, index = i } }
  ]...)
  id = try(tolist(aws_vpc_endpoint.link[each.value.link].network_interface_ids)[each.value.index], "")
}

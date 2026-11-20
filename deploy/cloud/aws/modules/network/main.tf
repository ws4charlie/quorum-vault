# One VPC per trust domain. Private subnets only, except the NAT mode of the business domain, which also has small public subnets for the NAT gateways.
# There is no peering, no transit gateway and no VPN here: the only way out of a domain is a PrivateLink endpoint (module private-link).

locals {
  zones         = { for i, z in var.availability_zones : z => i }
  private_cidrs = { for z, i in local.zones : z => cidrsubnet(var.vpc_cidr, 4, i) }
  public_cidrs  = { for z, i in local.zones : z => cidrsubnet(var.vpc_cidr, 8, 200 + i) }
  nat           = var.egress_mode == "nat"
}

resource "aws_vpc" "this" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = var.name }
}

# The default security group allows nothing: no rule, in or out.
resource "aws_default_security_group" "this" {
  vpc_id = aws_vpc.this.id
}

resource "aws_subnet" "private" {
  for_each                = local.zones
  vpc_id                  = aws_vpc.this.id
  availability_zone       = each.key
  cidr_block              = local.private_cidrs[each.key]
  map_public_ip_on_launch = false
  tags = {
    Name                                        = "${var.name}-private-${each.key}"
    "kubernetes.io/role/internal-elb"           = "1"
    "kubernetes.io/cluster/${var.cluster_name}" = "shared"
  }
}

resource "aws_route_table" "private" {
  for_each = local.zones
  vpc_id   = aws_vpc.this.id
  tags     = { Name = "${var.name}-private-${each.key}" }
}

resource "aws_route_table_association" "private" {
  for_each       = local.zones
  subnet_id      = aws_subnet.private[each.key].id
  route_table_id = aws_route_table.private[each.key].id
}

# --- NAT mode only ---

resource "aws_internet_gateway" "this" {
  count  = local.nat ? 1 : 0
  vpc_id = aws_vpc.this.id
  tags   = { Name = var.name }
}

resource "aws_subnet" "public" {
  for_each                = local.nat ? local.zones : {}
  vpc_id                  = aws_vpc.this.id
  availability_zone       = each.key
  cidr_block              = local.public_cidrs[each.key]
  map_public_ip_on_launch = false
  tags                    = { Name = "${var.name}-public-${each.key}" }
}

resource "aws_route_table" "public" {
  count  = local.nat ? 1 : 0
  vpc_id = aws_vpc.this.id
  tags   = { Name = "${var.name}-public" }
}

resource "aws_route" "public_default" {
  count                  = local.nat ? 1 : 0
  route_table_id         = aws_route_table.public[0].id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.this[0].id
}

resource "aws_route_table_association" "public" {
  for_each       = local.nat ? local.zones : {}
  subnet_id      = aws_subnet.public[each.key].id
  route_table_id = aws_route_table.public[0].id
}

resource "aws_eip" "nat" {
  for_each = local.nat ? local.zones : {}
  domain   = "vpc"
  tags     = { Name = "${var.name}-nat-${each.key}" }
}

resource "aws_nat_gateway" "this" {
  for_each      = local.nat ? local.zones : {}
  allocation_id = aws_eip.nat[each.key].id
  subnet_id     = aws_subnet.public[each.key].id
  tags          = { Name = "${var.name}-${each.key}" }
  depends_on    = [aws_internet_gateway.this]
}

resource "aws_route" "private_default" {
  for_each               = local.nat ? local.zones : {}
  route_table_id         = aws_route_table.private[each.key].id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.this[each.key].id
}

# --- AWS services without leaving the VPC ---

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.this.id
  service_name      = "com.amazonaws.${var.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [for z in var.availability_zones : aws_route_table.private[z].id]
  tags              = { Name = "${var.name}-s3" }
}

resource "aws_security_group" "endpoints" {
  name        = "${var.name}-endpoints"
  description = "Interface endpoints of ${var.name}: HTTPS from inside the VPC only"
  vpc_id      = aws_vpc.this.id
  tags        = { Name = "${var.name}-endpoints" }
}

resource "aws_vpc_security_group_ingress_rule" "endpoints_https" {
  security_group_id = aws_security_group.endpoints.id
  description       = "HTTPS from this VPC"
  cidr_ipv4         = var.vpc_cidr
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
}

resource "aws_vpc_endpoint" "interface" {
  for_each            = toset(var.interface_endpoints)
  vpc_id              = aws_vpc.this.id
  service_name        = "com.amazonaws.${var.region}.${each.key}"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [for z in var.availability_zones : aws_subnet.private[z].id]
  security_group_ids  = [aws_security_group.endpoints.id]
  private_dns_enabled = true
  tags                = { Name = "${var.name}-${each.key}" }
}

# --- Flow logs go to the audit account: the domain's own administrators cannot delete them ---

resource "aws_flow_log" "this" {
  vpc_id                   = aws_vpc.this.id
  traffic_type             = "ALL"
  log_destination_type     = "s3"
  log_destination          = "${var.flow_log_bucket_arn}/${var.name}/"
  max_aggregation_interval = 60
  tags                     = { Name = var.name }
}

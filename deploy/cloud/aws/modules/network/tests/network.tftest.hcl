mock_provider "aws" {}

variables {
  name                = "qv-test"
  region              = "eu-central-1"
  vpc_cidr            = "10.30.0.0/16"
  availability_zones  = ["eu-central-1a", "eu-central-1b", "eu-central-1c"]
  interface_endpoints = ["ecr.api", "sts"]
  flow_log_bucket_arn = "arn:aws:s3:::qv-test-flowlogs"
  cluster_name        = "qv-test"
}

run "isolated_has_no_way_out" {
  variables {
    egress_mode = "isolated"
  }
  assert {
    condition     = length(aws_internet_gateway.this) == 0 && length(aws_nat_gateway.this) == 0 && length(aws_eip.nat) == 0
    error_message = "an isolated VPC has no internet gateway, no NAT gateway and no address"
  }
  assert {
    condition     = length(output.route_destinations) == 0
    error_message = "an isolated VPC has no route besides the local one and the S3 gateway endpoint"
  }
  assert {
    condition     = length(aws_subnet.public) == 0
    error_message = "an isolated VPC has no public subnet"
  }
  assert {
    condition     = alltrue([for s in aws_subnet.private : s.map_public_ip_on_launch == false])
    error_message = "no subnet hands out public addresses"
  }
}

run "nat_mode_routes_only_to_nat" {
  variables {
    egress_mode = "nat"
  }
  assert {
    condition     = length(aws_nat_gateway.this) == 3 && length(aws_route.private_default) == 3
    error_message = "one NAT gateway and one default route per zone"
  }
  assert {
    condition     = alltrue([for r in aws_route.private_default : r.destination_cidr_block == "0.0.0.0/0"]) && alltrue([for s in aws_subnet.public : s.map_public_ip_on_launch == false])
    error_message = "private subnets default to the NAT; no subnet hands out public addresses"
  }
}

run "no_peering_no_world_ingress_flow_logs_on" {
  variables {
    egress_mode = "isolated"
  }
  assert {
    condition     = aws_vpc_security_group_ingress_rule.endpoints_https.cidr_ipv4 == "10.30.0.0/16" && aws_vpc_security_group_ingress_rule.endpoints_https.from_port == 443
    error_message = "endpoints accept HTTPS from the VPC only"
  }
  assert {
    condition     = aws_flow_log.this.traffic_type == "ALL" && aws_flow_log.this.log_destination_type == "s3"
    error_message = "flow logs record all traffic to a bucket"
  }
  assert {
    condition     = length(aws_default_security_group.this.ingress) == 0 && length(aws_default_security_group.this.egress) == 0
    error_message = "the default security group has no rules"
  }
}

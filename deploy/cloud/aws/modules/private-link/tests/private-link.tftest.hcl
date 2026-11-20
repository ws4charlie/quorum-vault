mock_provider "aws" {}

variables {
  name       = "qv-test"
  vpc_id     = "vpc-0123"
  vpc_cidr   = "10.30.0.0/16"
  subnet_ids = ["subnet-a", "subnet-b"]
}

run "provider_allows_only_named_accounts_and_a_person_accepts" {
  variables {
    services = {
      caller = { nlb_arn = "arn:aws:elasticloadbalancing:eu-central-1:333333333333:loadbalancer/net/x/1", allowed_account_ids = ["222222222222"] }
    }
  }
  assert {
    condition     = jsonencode(output.allowed_principals) == jsonencode({ caller = ["222222222222"] })
    error_message = "one endpoint service, one allowed account"
  }
  assert {
    condition     = output.acceptance_required["caller"]
    error_message = "every new connection is accepted by a person"
  }
  assert {
    condition     = alltrue([for k, p in aws_vpc_endpoint_service_allowed_principal.this : endswith(p.principal_arn, ":root") && can(regex("^arn:aws:iam::[0-9]{12}:root$", p.principal_arn))])
    error_message = "principals are account roots, never *"
  }
}

run "an_endpoint_service_without_consumers_is_refused" {
  command = plan
  variables {
    services = {
      caller = { nlb_arn = "arn:aws:elasticloadbalancing:eu-central-1:333333333333:loadbalancer/net/x/1", allowed_account_ids = [] }
    }
  }
  expect_failures = [var.services]
}

run "consumer_opens_listed_ports_from_its_own_vpc_only" {
  variables {
    links = {
      gateway-heads = { service_name = "com.amazonaws.vpce.eu-central-1.vpce-svc-0abc", ports = [9092, 9093], dns = "business-kafka.qv.internal" }
    }
  }
  assert {
    condition     = alltrue([for k, r in aws_vpc_security_group_ingress_rule.link : r.cidr_ipv4 == "10.30.0.0/16"])
    error_message = "the endpoint accepts connections from this VPC only"
  }
  assert {
    condition     = jsonencode(sort([for k, r in aws_vpc_security_group_ingress_rule.link : tostring(r.from_port)])) == jsonencode(["9092", "9093"])
    error_message = "only the listed ports"
  }
  assert {
    condition     = alltrue([for k, e in aws_vpc_endpoint.link : e.vpc_endpoint_type == "Interface" && e.private_dns_enabled == false])
    error_message = "interface endpoints; names come from the private zone"
  }
}

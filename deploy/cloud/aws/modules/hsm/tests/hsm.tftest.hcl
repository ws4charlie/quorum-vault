mock_provider "aws" {}

variables {
  name                     = "qv-test"
  subnet_ids               = ["subnet-a", "subnet-b", "subnet-c"]
  client_security_group_id = "sg-0123"
}

run "off_by_default_because_it_bills_by_the_hour" {
  assert {
    condition     = length(aws_cloudhsm_v2_cluster.this) == 0 && length(aws_cloudhsm_v2_hsm.this) == 0
    error_message = "no cluster and no HSM unless enabled"
  }
}

run "enabled_makes_two_hsms_reachable_from_the_nodes_only" {
  variables {
    enabled = true
  }
  assert {
    condition     = length(aws_cloudhsm_v2_hsm.this) == 2
    error_message = "two HSMs by default"
  }
  assert {
    condition     = aws_vpc_security_group_ingress_rule.nodes[0].referenced_security_group_id == "sg-0123" && aws_vpc_security_group_ingress_rule.nodes[0].cidr_ipv4 == null
    error_message = "ingress from the node security group, not from an address range"
  }
}

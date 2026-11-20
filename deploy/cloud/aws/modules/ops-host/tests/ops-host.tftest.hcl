mock_provider "aws" {
  mock_resource "aws_iam_role" {
    defaults = { arn = "arn:aws:iam::111111111111:role/mock" }
  }
}

variables {
  name        = "qv-test"
  vpc_id      = "vpc-0123"
  vpc_cidr    = "10.30.0.0/16"
  subnet_id   = "subnet-a"
  kms_key_arn = "arn:aws:kms:eu-central-1:111111111111:key/k"
}

run "off_by_default" {
  assert {
    condition     = length(aws_instance.this) == 0
    error_message = "no host unless asked"
  }
}

run "host_has_no_door_in_and_imdsv2" {
  variables {
    enabled = true
  }
  assert {
    condition     = aws_instance.this[0].metadata_options[0].http_tokens == "required" && aws_instance.this[0].associate_public_ip_address != true
    error_message = "IMDSv2 only, no public address"
  }
  assert {
    condition     = aws_vpc_security_group_egress_rule.https[0].cidr_ipv4 == "10.30.0.0/16"
    error_message = "egress to the VPC only"
  }
}

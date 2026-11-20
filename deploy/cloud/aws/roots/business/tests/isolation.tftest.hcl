mock_provider "aws" {
  mock_resource "aws_iam_role" {
    defaults = { arn = "arn:aws:iam::111111111111:role/mock" }
  }
  mock_resource "aws_iam_openid_connect_provider" {
    defaults = { arn = "arn:aws:iam::111111111111:oidc-provider/oidc.eks.eu-central-1.amazonaws.com/id/ABC" }
  }
  mock_resource "aws_launch_template" {
    defaults = { id = "lt-0123456789abcdef0", latest_version = 1 }
  }
  mock_resource "aws_eks_cluster" {
    defaults = {
      arn      = "arn:aws:eks:eu-central-1:111111111111:cluster/mock"
      endpoint = "https://ABC.gr7.eu-central-1.eks.amazonaws.com"
      identity = [{ oidc = [{ issuer = "https://oidc.eks.eu-central-1.amazonaws.com/id/ABC" }] }]
    }
  }
  mock_resource "aws_kms_key" {
    defaults = { arn = "arn:aws:kms:eu-central-1:111111111111:key/mock" }
  }
  mock_resource "aws_s3_bucket" {
    defaults = { arn = "arn:aws:s3:::mock" }
  }
  mock_resource "aws_cloudwatch_log_group" {
    defaults = { arn = "arn:aws:logs:eu-central-1:111111111111:log-group:mock" }
  }
  mock_data "aws_lb" {
    defaults = { arn = "arn:aws:elasticloadbalancing:eu-central-1:111111111111:loadbalancer/net/mock/1" }
  }
}

variables {
  region             = "eu-central-1"
  availability_zones = ["eu-central-1a", "eu-central-1b", "eu-central-1c"]
  bucket_prefix      = "acme"
  account_ids = {
    business     = "111111111111"
    signing-core = "222222222222"
    party-b      = "333333333333"
    party-c      = "444444444444"
    audit        = "555555555555"
  }
  operators                   = { ops = { principal_arn = "arn:aws:iam::333333333333:role/ops", policy = "AmazonEKSClusterAdminPolicy" } }
  ecr_upstream_credential_arn = "arn:aws:secretsmanager:eu-central-1:333333333333:secret:ecr-pullthroughcache/ghcr-AbCdEf"
}


run "business_reaches_nobody" {
  assert {
    condition     = length(output.consumes) == 0
    error_message = "no path starts in the business domain"
  }
  assert {
    condition     = output.endpoint_public_access == false
    error_message = "the Kubernetes API has no public endpoint"
  }
  assert {
    condition     = length(output.route_destinations) == 4 && alltrue([for r in output.route_destinations : r == "0.0.0.0/0"])
    error_message = "the only routes are the default routes: three private ones to the NAT gateways and the NAT subnets' one to the internet gateway (chain nodes and the identity provider). No peering, no other range."
  }
  assert {
    condition = alltrue([
      for k, p in output.policies : alltrue([
        for st in jsondecode(p).Statement : alltrue([for a in flatten([st.Action]) : !can(regex("\\*", a))])
      ])
    ])
    error_message = "no IAM policy of this root uses a wildcard action (no kms:*, cloudhsm:*, s3:*, ec2:*, bare *)"
  }
}

run "phase_2_only_signing_side_domains_may_connect" {
  variables {
    nlb_services = { postgres = "qv-business/qv-ledger-link", kafka = "qv-business/qv-redpanda-link" }
  }
  assert {
    condition     = jsonencode(output.allowed_principals) == jsonencode({ kafka = ["222222222222", "333333333333", "444444444444"], postgres = ["222222222222"] })
    error_message = "Postgres: the signing core only. Kafka: signing core, party B, party C. Nobody else."
  }
}

run "metrics_endpoint_only_when_switched_on_and_for_named_domains" {
  variables {
    enabled_optional_paths = ["metrics-party-b"]
    nlb_services           = { monitoring = "qv-monitoring/qv-remote-write" }
  }
  assert {
    condition     = jsonencode(output.allowed_principals) == jsonencode({ monitoring = ["333333333333"] })
    error_message = "the metrics endpoint admits party B only"
  }
}

run "archiver_may_only_put_and_read_and_never_delete" {
  assert {
    condition = (
      alltrue([for st in jsondecode(output.policies["archiver"]).Statement : st.Effect == "Deny" || !anytrue([for a in flatten([st.Action]) : contains(["s3:DeleteObject", "s3:DeleteObjectVersion", "s3:PutBucketPolicy", "s3:PutObjectRetention", "s3:BypassGovernanceRetention"], a)])])
      && anytrue([for st in jsondecode(output.policies["archiver"]).Statement : st.Effect == "Deny" && contains(flatten([st.Action]), "s3:DeleteObjectVersion")])
    )
    error_message = "the archiver is allowed to put and read, and explicitly denied everything that deletes or shortens retention"
  }
}

run "lb_controller_can_tag_a_security_group_it_creates" {
  assert {
    condition = anytrue([
      for st in jsondecode(output.policies["lb_controller"]).Statement :
      contains(flatten([st.Action]), "ec2:CreateTags") && try(st.Condition.StringEquals["ec2:CreateAction"], "") == "CreateSecurityGroup" && try(st.Condition.Null["aws:RequestTag/elbv2.k8s.aws/cluster"], "") == "false"
    ])
    error_message = "creation-time tagging of a new security group needs its own statement (request tag present, create action CreateSecurityGroup)"
  }
}

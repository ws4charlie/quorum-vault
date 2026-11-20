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


run "phase_1_private_no_way_out_no_endpoint_yet" {
  assert {
    condition     = output.endpoint_public_access == false
    error_message = "the Kubernetes API has no public endpoint"
  }
  assert {
    condition     = output.has_internet_gateway == false && length(output.route_destinations) == 0
    error_message = "no internet gateway, no NAT, no route besides the local one: nothing leaves this VPC except through an endpoint"
  }
  assert {
    condition     = output.hsm.enabled == false && length(output.hsm.ips) == 0
    error_message = "CloudHSM is off by default (hourly billing)"
  }
  assert {
    condition     = length(output.allowed_principals) == 0
    error_message = "before phase 2 no endpoint service exists"
  }
  assert {
    condition     = output.ops_host_instance_id == null
    error_message = "no ops host unless asked"
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

run "phase_2_endpoint_services_are_open_to_named_accounts_only" {
  variables {
    nlb_services           = { caller = "qv-party-b/qv-party-caller", peer = "qv-party-b/qv-party-peer" }
    endpoint_service_names = { cosigner-b-heads = "com.amazonaws.vpce.eu-central-1.vpce-svc-k", b-party-c-peer = "com.amazonaws.vpce.eu-central-1.vpce-svc-c" }
  }
  assert {
    condition     = jsonencode(output.allowed_principals) == jsonencode({ caller = ["222222222222"], peer = ["222222222222"] })
    error_message = "only the accounts of the domains that dial this party may connect"
  }
  assert {
    condition     = length(output.endpoint_ips) == 2 && alltrue([for k, v in output.consumes : contains(["business", "party-c"], v.to)])
    error_message = "this party calls out only to the domains named in paths.json"
  }
}

run "cloudhsm_when_asked" {
  variables {
    enable_cloudhsm = true
    hsm_count       = 2
  }
  assert {
    condition     = output.hsm.enabled
    error_message = "CloudHSM can be switched on"
  }
}

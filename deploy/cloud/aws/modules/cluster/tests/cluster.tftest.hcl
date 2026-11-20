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
      arn      = "arn:aws:eks:eu-central-1:111111111111:cluster/qv-test"
      endpoint = "https://ABC.gr7.eu-central-1.eks.amazonaws.com"
      identity = [{ oidc = [{ issuer = "https://oidc.eks.eu-central-1.amazonaws.com/id/ABC" }] }]
    }
  }
}

variables {
  name                = "qv-test"
  region              = "eu-central-1"
  account_id          = "111111111111"
  vpc_id              = "vpc-0123"
  subnet_ids          = ["subnet-a", "subnet-b"]
  secrets_kms_key_arn = "arn:aws:kms:eu-central-1:111111111111:key/s"
  ebs_kms_key_arn     = "arn:aws:kms:eu-central-1:111111111111:key/e"
  logs_kms_key_arn    = "arn:aws:kms:eu-central-1:111111111111:key/l"
  api_allowed_cidrs   = ["10.30.0.0/16"]
  access_entries      = { ops = { principal_arn = "arn:aws:iam::111111111111:role/ops", policy = "AmazonEKSClusterAdminPolicy" } }
  node_groups         = { main = { instance_types = ["m7i.large"], min_size = 2, max_size = 3, desired_size = 2 } }
}

run "private_encrypted_no_creator_admin" {
  assert {
    condition     = aws_eks_cluster.this.vpc_config[0].endpoint_public_access == false && aws_eks_cluster.this.vpc_config[0].endpoint_private_access == true
    error_message = "the API endpoint is private"
  }
  assert {
    condition     = aws_eks_cluster.this.access_config[0].bootstrap_cluster_creator_admin_permissions == false && aws_eks_cluster.this.access_config[0].authentication_mode == "API"
    error_message = "no creator admin, no aws-auth map"
  }
  assert {
    condition     = contains(aws_eks_cluster.this.encryption_config[0].resources, "secrets")
    error_message = "Secrets are encrypted in etcd with the customer key"
  }
  assert {
    condition     = length(aws_eks_cluster.this.enabled_cluster_log_types) == 5
    error_message = "every control-plane log type is on"
  }
  assert {
    condition     = alltrue([for k, t in aws_launch_template.node : t.metadata_options[0].http_tokens == "required" && t.metadata_options[0].http_put_response_hop_limit == 1])
    error_message = "IMDSv2 only, hop limit 1: a pod cannot read the node's credentials"
  }
  assert {
    condition     = alltrue([for k, t in aws_launch_template.node : alltrue([for b in t.block_device_mappings : tostring(b.ebs[0].encrypted) == "true"])])
    error_message = "node disks are encrypted"
  }
  assert {
    condition     = alltrue([for k, r in aws_vpc_security_group_ingress_rule.api : r.cidr_ipv4 != "0.0.0.0/0"])
    error_message = "the API security group is never open to the world"
  }
}

run "kubernetes_before_1_30_is_refused" {
  command = plan
  variables {
    kubernetes_version = "1.29"
  }
  expect_failures = [var.kubernetes_version]
}

run "open_api_is_refused" {
  command = plan
  variables {
    api_allowed_cidrs = ["0.0.0.0/0"]
  }
  expect_failures = [var.api_allowed_cidrs]
}

run "a_cluster_nobody_can_use_is_refused" {
  command = plan
  variables {
    access_entries = {}
  }
  expect_failures = [var.access_entries]
}

run "ebs_csi_driver_can_delete_only_what_it_owns" {
  assert {
    condition = alltrue([
      for st in jsondecode(output.policies.ebs_csi).Statement :
      !anytrue([for a in flatten([st.Action]) : contains(["ec2:DeleteVolume", "ec2:DeleteSnapshot", "ec2:DeleteTags"], a)]) || can(st.Condition)
    ])
    error_message = "every delete (volume, snapshot, tag) needs an ownership-tag condition"
  }
  assert {
    condition = alltrue([
      for st in jsondecode(output.policies.ebs_csi).Statement :
      !contains(flatten([st.Action]), "ec2:CreateTags") || (can(st.Condition.StringEquals["ec2:CreateAction"]) && st.Effect == "Allow")
    ])
    error_message = "ownership tags can be added only in the call that creates the volume or snapshot"
  }
}

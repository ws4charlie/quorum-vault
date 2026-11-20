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


run "audit_archive_is_compliance_locked_for_seven_years" {
  assert {
    condition     = output.audit_heads_lock.mode == "COMPLIANCE" && output.audit_heads_lock.days == 2555
    error_message = "the audit-head archive uses COMPLIANCE mode and the 2555 days the archiver runbook and the chart state"
  }
  assert {
    condition     = alltrue([for k, l in output.locks : l.mode == "COMPLIANCE"])
    error_message = "every bucket of the audit account is locked in COMPLIANCE mode"
  }
}

run "workload_accounts_cannot_delete_logs_or_heads" {
  assert {
    condition = alltrue([
      for k in ["heads_bucket", "trail_bucket", "flow_bucket"] : alltrue([
        for st in jsondecode(output.policies[k]).Statement :
        st.Effect == "Deny" || !anytrue([for a in flatten([st.Action]) : can(regex("Delete|Retention|BypassGovernance|PutBucketPolicy|PutLifecycle|PutBucketVersioning|PutBucketObjectLock|PutObjectLegalHold", a))])
      ])
    ])
    error_message = "no bucket policy of the audit account allows a delete, a retention change or a policy change to anyone"
  }
  assert {
    condition = alltrue([
      for k in ["trail_bucket", "flow_bucket"] : alltrue([
        for st in jsondecode(output.policies[k]).Statement :
        st.Effect == "Deny" || can(st.Principal.Service)
      ])
    ])
    error_message = "log buckets accept writes from the AWS log services only, never from a workload account's own principals"
  }
  assert {
    condition = anytrue([
      for st in jsondecode(output.policies["heads_bucket"]).Statement :
      st.Effect == "Deny" && try(st.Principal.AWS, "") == "arn:aws:iam::111111111111:role/qv-archiver" && contains(flatten([st.Action]), "s3:DeleteObjectVersion")
    ])
    error_message = "the archiver is denied deletes in the bucket policy too"
  }
}

run "audit_keys_do_not_trust_workload_accounts_roots" {
  assert {
    condition     = !strcontains(output.policies["heads_key"], "222222222222") && !strcontains(output.policies["heads_key"], "333333333333")
    error_message = "only the business archiver role (and the audit account itself) may use the archive key"
  }
}

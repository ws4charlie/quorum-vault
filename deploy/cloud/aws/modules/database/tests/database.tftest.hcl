mock_provider "aws" {
  mock_resource "aws_s3_bucket" {
    defaults = { arn = "arn:aws:s3:::acme-backup" }
  }
}

variables {
  name               = "qv-guard"
  backup_bucket_name = "acme-backup"
  kms_key_arn        = "arn:aws:kms:eu-central-1:111111111111:key/k"
  oidc_provider_arn  = "arn:aws:iam::111111111111:oidc-provider/oidc.eks.eu-central-1.amazonaws.com/id/ABC"
  oidc_issuer_url    = "https://oidc.eks.eu-central-1.amazonaws.com/id/ABC"
  namespace          = "qv-party-b"
  service_account    = "qv-guard"
}

run "database_pods_write_only_their_own_prefix" {
  assert {
    condition     = alltrue([for st in jsondecode(output.policy).Statement : alltrue([for a in flatten([st.Action]) : !can(regex("\\*", a))])])
    error_message = "no wildcard action"
  }
  assert {
    condition     = anytrue([for st in jsondecode(output.policy).Statement : try(endswith(st.Resource, "/qv-guard/*"), false)])
    error_message = "object access is limited to the database's own prefix"
  }
}

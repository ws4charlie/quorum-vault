mock_provider "aws" {
  mock_resource "aws_iam_role" {
    defaults = { arn = "arn:aws:iam::111111111111:role/qv-ecr-repository-creation" }
  }
}

variables {
  region                  = "eu-central-1"
  account_id              = "111111111111"
  kms_key_arn             = "arn:aws:kms:eu-central-1:111111111111:key/k"
  upstream_credential_arn = "arn:aws:secretsmanager:eu-central-1:111111111111:secret:ecr-pullthroughcache/ghcr-AbCdEf"
}

run "cache_repositories_are_immutable_encrypted_and_made_by_a_role" {
  assert {
    condition     = aws_ecr_repository_creation_template.cache.image_tag_mutability == "IMMUTABLE" && aws_ecr_repository_creation_template.cache.custom_role_arn == "arn:aws:iam::111111111111:role/qv-ecr-repository-creation"
    error_message = "a template with a customer key needs a repository creation role; tags are immutable"
  }
  assert {
    condition     = alltrue([for st in jsondecode(aws_iam_role_policy.creation.policy).Statement : alltrue([for a in flatten([st.Action]) : !can(regex("\\*", a))])])
    error_message = "the creation role has no wildcard action"
  }
}

run "secret_must_be_named_for_the_cache" {
  command = plan
  variables {
    upstream_credential_arn = "arn:aws:secretsmanager:eu-central-1:111111111111:secret:other-AbCdEf"
  }
  expect_failures = [var.upstream_credential_arn]
}

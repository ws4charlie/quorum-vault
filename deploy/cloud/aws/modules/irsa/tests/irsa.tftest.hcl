mock_provider "aws" {}

variables {
  name              = "qv-test"
  oidc_provider_arn = "arn:aws:iam::111111111111:oidc-provider/oidc.eks.eu-central-1.amazonaws.com/id/ABC"
  oidc_issuer_url   = "https://oidc.eks.eu-central-1.amazonaws.com/id/ABC"
  namespace         = "qv"
  service_account   = "archiver"
  policy_statements = [{ Effect = "Allow", Action = ["s3:GetObject"], Resource = "arn:aws:s3:::b/*" }]
}

run "trust_names_one_service_account" {
  assert {
    condition     = jsondecode(output.trust).Statement[0].Condition.StringEquals["oidc.eks.eu-central-1.amazonaws.com/id/ABC:sub"] == "system:serviceaccount:qv:archiver"
    error_message = "one subject"
  }
  assert {
    condition     = jsondecode(output.trust).Statement[0].Condition.StringEquals["oidc.eks.eu-central-1.amazonaws.com/id/ABC:aud"] == "sts.amazonaws.com"
    error_message = "audience is sts"
  }
}

run "service_wide_wildcards_are_refused" {
  command = plan
  variables {
    policy_statements = [{ Effect = "Allow", Action = ["kms:*"], Resource = "*" }]
  }
  expect_failures = [var.policy_statements]
}

run "bare_star_is_refused" {
  command = plan
  variables {
    policy_statements = [{ Effect = "Allow", Action = "*", Resource = "*" }]
  }
  expect_failures = [var.policy_statements]
}

run "cloudhsm_and_s3_wildcards_are_refused" {
  command = plan
  variables {
    policy_statements = [{ Effect = "Allow", Action = ["cloudhsm:*"], Resource = "*" }, { Effect = "Allow", Action = ["s3:*"], Resource = "*" }]
  }
  expect_failures = [var.policy_statements]
}

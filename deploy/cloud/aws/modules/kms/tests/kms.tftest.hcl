mock_provider "aws" {}

variables {
  name        = "qv-test"
  description = "test"
  account_id  = "111111111111"
  region      = "eu-central-1"
}

run "no_wildcard_actions_and_no_world_principal_without_conditions" {
  variables {
    via_services       = ["ec2"]
    service_principals = ["logs.eu-central-1.amazonaws.com"]
    external_user_arns = ["arn:aws:iam::222222222222:role/qv-archiver"]
  }
  assert {
    condition     = alltrue([for s in jsondecode(output.policy).Statement : alltrue([for a in flatten([s.Action]) : !can(regex("\\*", a))])])
    error_message = "key policy actions are spelled out: no kms:* and no partial wildcard"
  }
  assert {
    condition = alltrue([
      for s in jsondecode(output.policy).Statement :
      try(s.Principal.AWS != "*", true) || (can(s.Condition.StringEquals["kms:CallerAccount"]) && can(s.Condition.StringEquals["kms:ViaService"]))
    ])
    error_message = "a statement for any principal needs the caller-account and via-service conditions"
  }
  assert {
    condition     = alltrue([for s in jsondecode(output.policy).Statement : !contains(try(flatten([s.Action]), []), "kms:PutKeyPolicy") || try(s.Principal.AWS == "arn:aws:iam::111111111111:root", false)])
    error_message = "only the account's own IAM can change the key policy"
  }
  assert {
    condition     = aws_kms_key.this.enable_key_rotation
    error_message = "rotation is on"
  }
}

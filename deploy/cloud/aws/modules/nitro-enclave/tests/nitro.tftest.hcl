mock_provider "aws" {
  mock_resource "aws_iam_role" {
    defaults = { arn = "arn:aws:iam::111111111111:role/qv-party-a-parent" }
  }
  mock_resource "aws_iam_instance_profile" {
    defaults = { arn = "arn:aws:iam::111111111111:instance-profile/qv-party-a-parent" }
  }
  mock_resource "aws_kms_key" {
    defaults = { arn = "arn:aws:kms:eu-central-1:111111111111:key/11111111-2222-3333-4444-555555555555", key_id = "11111111-2222-3333-4444-555555555555" }
  }
}

variables {
  name        = "qv-party-a"
  description = "enclave key of party A"
  account_id  = "111111111111"
  ami_id      = "ami-0123456789abcdef0"
  allowed_images = [{
    name = "v1.0.0"
    pcrs = {
      "0" = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "1" = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
      "2" = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
      "8" = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
    }
  }]
}

run "every_use_statement_carries_the_pcr_conditions" {
  assert {
    # every Allow statement of a non-root principal names ImageSha384, PCR0 and the other listed PCRs
    condition = alltrue([
      for s in jsondecode(output.policy).Statement :
      s.Effect != "Allow" || try(s.Principal.AWS == "arn:aws:iam::111111111111:root", false) || try(s.Sid == "KeyAdministrators", false) ||
      alltrue([for k in ["kms:RecipientAttestation:ImageSha384", "kms:RecipientAttestation:PCR0", "kms:RecipientAttestation:PCR1", "kms:RecipientAttestation:PCR2", "kms:RecipientAttestation:PCR8"] : contains(keys(s.Condition.StringEqualsIgnoreCase), k)])
    ])
    error_message = "a statement that allows use has no PCR condition"
  }
  assert {
    condition     = length([for s in jsondecode(output.policy).Statement : s if startswith(s.Sid, "AllowEnclave")]) == 1
    error_message = "one allowed image, one statement"
  }
}

run "no_statement_allows_use_without_a_condition" {
  assert {
    # the test the task asks for: a policy statement that allows a use action and has no condition fails the check
    condition = alltrue([
      for s in jsondecode(output.policy).Statement :
      s.Effect != "Allow" || !anytrue([for a in flatten([s.Action]) : contains(["kms:Decrypt", "kms:GenerateDataKey", "kms:Encrypt", "kms:GenerateDataKeyWithoutPlaintext"], a)]) || can(s.Condition.StringEqualsIgnoreCase)
    ])
    error_message = "an Allow statement for a use action has no PCR condition"
  }
}

run "the_account_root_and_admins_can_administer_but_not_use" {
  variables {
    key_admin_role_arns = ["arn:aws:iam::111111111111:role/qv-key-admin"]
  }
  assert {
    condition = alltrue([
      for s in jsondecode(output.policy).Statement :
      s.Effect != "Allow" || !(try(s.Principal.AWS == "arn:aws:iam::111111111111:root", false) || s.Sid == "KeyAdministrators") ||
      !anytrue([for a in flatten([s.Action]) : contains(["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey", "kms:GenerateDataKeyWithoutPlaintext", "kms:ReEncryptFrom", "kms:ReEncryptTo", "kms:CreateGrant"], a)])
    ])
    error_message = "the root or an administrator may use the key: an IAM policy could then bypass the PCR conditions"
  }
}

run "use_without_an_attestation_document_is_denied_for_everyone" {
  assert {
    condition = anytrue([
      for s in jsondecode(output.policy).Statement :
      s.Effect == "Deny" && s.Principal.AWS == "*" && s.Condition.Null["kms:RecipientAttestation:ImageSha384"] == "true" &&
      alltrue([for a in ["kms:Decrypt", "kms:GenerateDataKey", "kms:GenerateDataKeyWithoutPlaintext", "kms:Encrypt"] : contains(s.Action, a)])
    ])
    error_message = "there is no deny for use without an attestation document"
  }
}

run "no_wildcards" {
  assert {
    condition     = alltrue([for s in jsondecode(output.policy).Statement : alltrue([for a in flatten([s.Action]) : !can(regex("\\*", a))])])
    error_message = "key policy actions are spelled out"
  }
  assert {
    condition     = alltrue([for s in jsondecode(output.policy).Statement : s.Effect != "Allow" || try(s.Principal.AWS != "*", true)])
    error_message = "an Allow for any principal"
  }
  assert {
    condition     = aws_kms_key.this.enable_key_rotation
    error_message = "rotation is on"
  }
}

run "an_upgrade_lists_two_images_and_each_has_its_own_statement" {
  variables {
    allowed_images = [
      { name = "v1.0.0", pcrs = { "0" = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" } },
      { name = "v1.1.0", pcrs = { "0" = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" } },
    ]
  }
  assert {
    condition     = length([for s in jsondecode(output.policy).Statement : s if startswith(s.Sid, "AllowEnclave")]) == 2
    error_message = "two images, two statements"
  }
}

run "the_parent_role_may_call_only_this_key_and_only_with_a_recipient" {
  assert {
    condition     = jsondecode(aws_iam_role_policy.use_key[0].policy).Statement[0].Condition.Null["kms:RecipientAttestation:ImageSha384"] == "false"
    error_message = "the role's policy does not require a recipient"
  }
  assert {
    condition     = join(",", sort(flatten([jsondecode(aws_iam_role_policy.use_key[0].policy).Statement[0].Action]))) == "kms:Decrypt,kms:GenerateDataKey"
    error_message = "the role may do more than Decrypt and GenerateDataKey"
  }
  assert {
    condition     = length(jsondecode(aws_iam_role_policy.use_key[0].policy).Statement) == 1
    error_message = "one statement"
  }
}

run "the_host_is_an_enclave_host_with_imdsv2_and_encrypted_disks" {
  assert {
    condition     = aws_launch_template.host[0].enclave_options[0].enabled
    error_message = "enclaves are not enabled on the launch template"
  }
  assert {
    condition     = aws_launch_template.host[0].metadata_options[0].http_tokens == "required" && aws_launch_template.host[0].metadata_options[0].http_put_response_hop_limit == 1
    error_message = "IMDSv2 only, hop limit 1"
  }
  assert {
    condition     = aws_launch_template.host[0].block_device_mappings[0].ebs[0].encrypted
    error_message = "unencrypted root volume"
  }
  assert {
    condition     = !aws_launch_template.host[0].hibernation_options[0].configured
    error_message = "enclaves and hibernation do not mix"
  }
}

# ---- the refusals: each is a plan that must fail ----

run "no_image_no_key_policy" {
  command = plan
  variables {
    allowed_images = []
  }
  expect_failures = [var.allowed_images]
}

run "an_image_without_pcr0_is_refused" {
  command = plan
  variables {
    allowed_images = [{ name = "x", pcrs = { "1" = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" } }]
  }
  expect_failures = [var.allowed_images]
}

run "an_all_zero_pcr_is_refused_it_is_a_debug_enclave" {
  command = plan
  variables {
    allowed_images = [{ name = "x", pcrs = { "0" = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" } }]
  }
  expect_failures = [var.allowed_images]
}

run "a_pcr_of_the_wrong_length_is_refused" {
  command = plan
  variables {
    allowed_images = [{ name = "x", pcrs = { "0" = "aaaa" } }]
  }
  expect_failures = [var.allowed_images]
}

run "upper_case_hex_is_refused_so_the_policy_and_the_allowlist_say_the_same_thing" {
  command = plan
  variables {
    allowed_images = [{ name = "x", pcrs = { "0" = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" } }]
  }
  expect_failures = [var.allowed_images]
}

run "a_bad_image_name_is_refused" {
  command = plan
  variables {
    allowed_images = [{ name = "bad name!", pcrs = { "0" = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" } }]
  }
  expect_failures = [var.allowed_images]
}

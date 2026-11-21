mock_provider "aws" {}

variables {
  name        = "qv-test-bucket"
  kms_key_arn = "arn:aws:kms:eu-central-1:111111111111:key/test"
}

run "plain_bucket_is_private_encrypted_and_tls_only" {
  assert {
    condition     = output.public_access_blocked
    error_message = "all four public-access blocks"
  }
  assert {
    condition     = output.encryption_key == "arn:aws:kms:eu-central-1:111111111111:key/test"
    error_message = "default encryption uses the customer key"
  }
  assert {
    condition     = output.lock_mode == "NONE"
    error_message = "no lock unless asked"
  }
  assert {
    condition     = anytrue([for s in jsondecode(output.policy).Statement : s.Sid == "DenyInsecureTransport" && s.Effect == "Deny"])
    error_message = "plain HTTP is denied"
  }
}

run "locked_bucket_is_compliance_mode" {
  variables {
    object_lock = { enabled = true, days = 2555 }
  }
  assert {
    condition     = output.lock_mode == "COMPLIANCE" && output.lock_days == 2555
    error_message = "the audit archive is locked in COMPLIANCE mode for 7 years"
  }
}

run "lock_without_retention_is_refused" {
  command = plan
  variables {
    object_lock = { enabled = true, days = 0 }
  }
  expect_failures = [var.object_lock]
}

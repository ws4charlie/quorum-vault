# One customer-managed key. Every action is spelled out: no kms:* and no partial wildcard.
# Who may use the key: the account's own IAM (the root statement delegates the listed actions to IAM policies),
# AWS services on behalf of this account (via_services), service principals (limited by aws:SourceAccount) and named roles of other accounts.

locals {
  admin_actions = [
    "kms:CancelKeyDeletion", "kms:CreateAlias", "kms:DeleteAlias", "kms:DescribeKey", "kms:DisableKey", "kms:DisableKeyRotation",
    "kms:EnableKey", "kms:EnableKeyRotation", "kms:GetKeyPolicy", "kms:GetKeyRotationStatus", "kms:ListGrants", "kms:ListKeyPolicies",
    "kms:ListResourceTags", "kms:PutKeyPolicy", "kms:RevokeGrant", "kms:ScheduleKeyDeletion", "kms:TagResource", "kms:UntagResource",
    "kms:UpdateAlias", "kms:UpdateKeyDescription",
  ]
  use_actions = [
    "kms:Decrypt", "kms:DescribeKey", "kms:Encrypt", "kms:GenerateDataKey", "kms:GenerateDataKeyWithoutPlaintext",
    "kms:ReEncryptFrom", "kms:ReEncryptTo", "kms:CreateGrant",
  ]
  external_use_actions = ["kms:Decrypt", "kms:DescribeKey", "kms:Encrypt", "kms:GenerateDataKey"]
  service_use_actions  = ["kms:Decrypt", "kms:DescribeKey", "kms:Encrypt", "kms:GenerateDataKey", "kms:GenerateDataKeyWithoutPlaintext", "kms:ReEncryptFrom", "kms:ReEncryptTo"]

  source_accounts = length(var.source_account_ids) > 0 ? var.source_account_ids : [var.account_id]

  statements = concat(
    [{
      Sid       = "AccountRootDelegatesToIam"
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::${var.account_id}:root" }
      Action    = concat(local.admin_actions, local.use_actions)
      Resource  = "*"
    }],
    length(var.external_user_arns) == 0 ? [] : [{
      Sid       = "NamedRolesOfOtherAccounts"
      Effect    = "Allow"
      Principal = { AWS = var.external_user_arns }
      Action    = local.external_use_actions
      Resource  = "*"
    }],
    [for s in var.via_services : {
      Sid       = "ViaService${replace(title(s), "-", "")}"
      Effect    = "Allow"
      Principal = { AWS = "*" }
      Action    = local.use_actions
      Resource  = "*"
      Condition = { StringEquals = {
        "kms:CallerAccount" = var.account_id
        "kms:ViaService"    = "${s}.${var.region}.amazonaws.com"
      } }
    }],
    length(var.service_principals) == 0 ? [] : [{
      Sid       = "ServicePrincipals"
      Effect    = "Allow"
      Principal = { Service = var.service_principals }
      Action    = local.service_use_actions
      Resource  = "*"
      Condition = { StringEquals = { "aws:SourceAccount" = local.source_accounts } }
    }],
  )
}

resource "aws_kms_key" "this" {
  description             = var.description
  enable_key_rotation     = true
  deletion_window_in_days = var.deletion_window_days
  policy                  = jsonencode({ Version = "2012-10-17", Statement = local.statements })
}

resource "aws_kms_alias" "this" {
  name          = "alias/${var.name}"
  target_key_id = aws_kms_key.this.key_id
}

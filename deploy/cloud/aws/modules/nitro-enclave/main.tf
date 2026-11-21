# The enclave key of one party and what may use it. The security rests on three statements, each tested offline (tests/nitro.tftest.hcl):
#  1. Use needs a PCR match: a statement per allowed image allows kms:Decrypt and kms:GenerateDataKey to the party's role only when the attestation document
#     in the request carries exactly that image's PCRs (kms:RecipientAttestation:ImageSha384 is PCR0, kms:RecipientAttestation:PCR<n> the others,
#     StringEqualsIgnoreCase, as the documentation shows). [KMS-COND] https://docs.aws.amazon.com/kms/latest/developerguide/conditions-nitro-enclave.html
#  2. No use without attestation, by anyone: an explicit Deny on every data-key action when the request has no attestation document (condition Null on
#     kms:RecipientAttestation:ImageSha384), so not even the account's administrators can read a data key outside an enclave.
#  3. The account's IAM cannot grant use: the root statement delegates administration only, never the use actions, so an IAM policy cannot add a way around 1.
# What the documentation does not say and only the first real call shows: that statement 2's Null condition behaves as written (docs/runbooks/nitro-first-run.md,
# "KMS condition evaluation"). If it did not, statements 1 and 3 still hold.

locals {
  admin_actions = [
    "kms:CancelKeyDeletion", "kms:CreateAlias", "kms:DeleteAlias", "kms:DescribeKey", "kms:DisableKey", "kms:DisableKeyRotation",
    "kms:EnableKey", "kms:EnableKeyRotation", "kms:GetKeyPolicy", "kms:GetKeyRotationStatus", "kms:ListGrants", "kms:ListKeyPolicies",
    "kms:ListResourceTags", "kms:PutKeyPolicy", "kms:RevokeGrant", "kms:ScheduleKeyDeletion", "kms:TagResource", "kms:UntagResource",
    "kms:UpdateAlias", "kms:UpdateKeyDescription",
  ]
  # what the enclave calls: Decrypt to open a stored data key, GenerateDataKey to make a new one (the answer carries no plaintext when a recipient is given)
  enclave_actions = ["kms:Decrypt", "kms:GenerateDataKey"]
  # every action that could hand out key material or encrypt under the key, for the deny
  data_actions = [
    "kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey", "kms:GenerateDataKeyWithoutPlaintext", "kms:GenerateDataKeyPair",
    "kms:GenerateDataKeyPairWithoutPlaintext", "kms:ReEncryptFrom", "kms:ReEncryptTo", "kms:DeriveSharedSecret",
  ]

  role_arns = concat(
    var.create_parent_role ? [aws_iam_role.parent[0].arn] : [],
    [for n in var.party_role_names : "arn:aws:iam::${var.account_id}:role/${n}"],
  )

  image_statements = [for i in var.allowed_images : {
    Sid       = "AllowEnclave${replace(i.name, "/[^A-Za-z0-9]/", "")}"
    Effect    = "Allow"
    Principal = { AWS = local.role_arns }
    Action    = local.enclave_actions
    Resource  = "*"
    Condition = {
      StringEqualsIgnoreCase = merge(
        { for n, v in i.pcrs : n == "0" ? "kms:RecipientAttestation:ImageSha384" : "kms:RecipientAttestation:PCR${n}" => lower(v) },
        # the documentation's own example names PCR0 both ways; both must hold
        { "kms:RecipientAttestation:PCR0" = lower(i.pcrs["0"]) },
      )
    }
  }]

  statements = concat(
    [{
      Sid       = "AccountRootDelegatesAdministrationOnly"
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::${var.account_id}:root" }
      Action    = local.admin_actions
      Resource  = "*"
    }],
    length(var.key_admin_role_arns) == 0 ? [] : [{
      Sid       = "KeyAdministrators"
      Effect    = "Allow"
      Principal = { AWS = var.key_admin_role_arns }
      Action    = local.admin_actions
      Resource  = "*"
    }],
    local.image_statements,
    [{
      Sid       = "DenyUseWithoutAnAttestationDocument"
      Effect    = "Deny"
      Principal = { AWS = "*" }
      Action    = local.data_actions
      Resource  = "*"
      Condition = { Null = { "kms:RecipientAttestation:ImageSha384" = "true" } }
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

# ---- the party's parent instance role ----
# The parent is NOT trusted with the key: it holds the instance role, and the role alone cannot use the key (statement 1 needs an attestation document that only the
# enclave can make). What the role may do is limited to this key, to the two calls, and only with a recipient (the same Null test as an IAM condition).

resource "aws_iam_role" "parent" {
  count = var.create_parent_role ? 1 : 0
  name  = "${var.name}-parent"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "ec2.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}

resource "aws_iam_role_policy" "use_key" {
  count = var.create_parent_role ? 1 : 0
  name  = "use-the-enclave-key"
  role  = aws_iam_role.parent[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "UseTheEnclaveKeyWithAnAttestationDocumentOnly"
      Effect    = "Allow"
      Action    = local.enclave_actions
      Resource  = aws_kms_key.this.arn
      Condition = { Null = { "kms:RecipientAttestation:ImageSha384" = "false" } }
    }]
  })
}

resource "aws_iam_instance_profile" "parent" {
  count = var.create_parent_role ? 1 : 0
  name  = "${var.name}-parent"
  role  = aws_iam_role.parent[0].name
}

# ---- the enclave host ----
# A launch template for an Auto Scaling group or an EKS managed node group. enclave_options turns the Nitro Enclaves feature on at launch (it cannot be changed
# later). IMDSv2 only, with a hop limit of 1: the credential forwarder runs on the host, not in a container. No public address is set here (the subnet decides).
# [AWS-DOC] https://docs.aws.amazon.com/enclaves/latest/user/getting-started.html (read 2026-11-20): enable at launch, no hibernation, Nitro-based types.

resource "aws_launch_template" "host" {
  count         = var.create_launch_template ? 1 : 0
  name_prefix   = "${var.name}-host-"
  description   = "Nitro Enclaves host for ${var.name}"
  image_id      = var.ami_id
  instance_type = var.instance_type

  enclave_options {
    enabled = true
  }

  hibernation_options {
    configured = false
  }

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "disabled"
  }

  dynamic "iam_instance_profile" {
    for_each = var.create_parent_role ? [1] : []
    content {
      arn = aws_iam_instance_profile.parent[0].arn
    }
  }

  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      volume_size = var.root_volume_gb
      volume_type = "gp3"
      encrypted   = true
      kms_key_id  = var.ebs_kms_key_arn == "" ? null : var.ebs_kms_key_arn
    }
  }

  monitoring {
    enabled = true
  }

  tag_specifications {
    resource_type = "instance"
    tags          = { Name = "${var.name}-enclave-host", "qv:role" = "nitro-enclave-host" }
  }
}

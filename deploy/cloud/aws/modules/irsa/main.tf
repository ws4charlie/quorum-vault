# A role that exactly one Kubernetes service account may assume (IAM roles for service accounts).
# The trust names the cluster's OIDC provider, the audience sts.amazonaws.com and ONE subject: system:serviceaccount:<namespace>:<name>.

locals {
  issuer = replace(var.oidc_issuer_url, "https://", "")
}

resource "aws_iam_role" "this" {
  name = var.name
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = var.oidc_provider_arn }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = { StringEquals = {
        "${local.issuer}:aud" = "sts.amazonaws.com"
        "${local.issuer}:sub" = "system:serviceaccount:${var.namespace}:${var.service_account}"
      } }
    }]
  })
}

resource "aws_iam_role_policy" "this" {
  name   = "permissions"
  role   = aws_iam_role.this.id
  policy = jsonencode({ Version = "2012-10-17", Statement = var.policy_statements })
}

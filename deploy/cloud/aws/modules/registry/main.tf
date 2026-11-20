# Images stay on ghcr.io and are pulled BY DIGEST. Signing clusters have no internet, so each account runs an ECR pull-through cache: ECR (on the AWS side)
# fetches from ghcr.io, the nodes pull from ECR through VPC endpoints. A digest names the same bytes in both places.
# Repositories made by the cache are encrypted with the account's key and their tags cannot be moved.

resource "aws_ecr_pull_through_cache_rule" "ghcr" {
  ecr_repository_prefix = var.prefix
  upstream_registry_url = "ghcr.io"
  credential_arn        = var.upstream_credential_arn
}

# A template that sets KMS encryption (or tags) needs a repository creation role: "This role must be provided when using repository tags and/or KMS in the template, otherwise
# the repository creation will fail" (https://docs.aws.amazon.com/AmazonECR/latest/userguide/repository-creation-templates.html, read 2026-11-20). The role must be in this account
# (API_CreateRepositoryCreationTemplate, customRoleArn). UNVERIFIED until the first apply: the documentation pages read do not state the role's trust principal or its permissions.
# The role below is the narrowest guess: trusted by the ECR service, it may create and tag repositories under the prefix and use the one key through grants.
resource "aws_iam_role" "creation" {
  name = "qv-ecr-repository-creation"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ecr.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = { StringEquals = { "aws:SourceAccount" = var.account_id } }
    }]
  })
}

resource "aws_iam_role_policy" "creation" {
  name = "create-cache-repositories"
  role = aws_iam_role.creation.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["ecr:CreateRepository", "ecr:TagResource", "ecr:PutLifecyclePolicy", "ecr:SetRepositoryPolicy"]
        Resource = "arn:aws:ecr:${var.region}:${var.account_id}:repository/${var.prefix}/*"
      },
      {
        Effect   = "Allow"
        Action   = ["kms:DescribeKey", "kms:CreateGrant", "kms:RetireGrant"]
        Resource = var.kms_key_arn
      },
    ]
  })
}

resource "aws_ecr_repository_creation_template" "cache" {
  prefix               = var.prefix
  applied_for          = ["PULL_THROUGH_CACHE"]
  image_tag_mutability = "IMMUTABLE"
  custom_role_arn      = aws_iam_role.creation.arn

  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = var.kms_key_arn
  }
}

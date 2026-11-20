# Images stay on ghcr.io and are pulled BY DIGEST. Signing clusters have no internet, so each account runs an ECR pull-through cache: ECR (on the AWS side)
# fetches from ghcr.io, the nodes pull from ECR through VPC endpoints. A digest names the same bytes in both places.
# Repositories made by the cache are encrypted with the account's key and their tags cannot be moved.

resource "aws_ecr_pull_through_cache_rule" "ghcr" {
  ecr_repository_prefix = var.prefix
  upstream_registry_url = "ghcr.io"
  credential_arn        = var.upstream_credential_arn
}

resource "aws_ecr_repository_creation_template" "cache" {
  prefix               = var.prefix
  applied_for          = ["PULL_THROUGH_CACHE"]
  image_tag_mutability = "IMMUTABLE"

  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = var.kms_key_arn
  }
}

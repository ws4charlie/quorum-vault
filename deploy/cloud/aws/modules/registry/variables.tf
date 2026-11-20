variable "prefix" {
  description = "Repository prefix in this account's ECR; images appear as <registry>/<prefix>/<upstream path>."
  type        = string
  default     = "ghcr"
}

variable "upstream_credential_arn" {
  description = "ARN of a Secrets Manager secret (name starting ecr-pullthroughcache/) that holds a read-only token for ghcr.io. Made BY HAND; Terraform only names it."
  type        = string

  validation {
    condition     = can(regex("^arn:aws:secretsmanager:[a-z0-9-]+:[0-9]{12}:secret:ecr-pullthroughcache/", var.upstream_credential_arn))
    error_message = "the secret's name must start with ecr-pullthroughcache/"
  }
}

variable "kms_key_arn" {
  type = string
}

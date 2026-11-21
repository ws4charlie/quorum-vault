variable "name" {
  type = string
}

variable "oidc_provider_arn" {
  type = string
}

variable "oidc_issuer_url" {
  description = "Issuer URL of the cluster (https://oidc.eks...)."
  type        = string
}

variable "namespace" {
  type = string
}

variable "service_account" {
  type = string
}

variable "policy_statements" {
  description = "IAM statements for the role. Wildcard actions are refused here (the account-wide ones: kms, cloudhsm, s3, iam, sts, and a bare *)."
  type        = any

  validation {
    condition = alltrue([
      for s in var.policy_statements :
      alltrue([for a in flatten([s.Action]) : !can(regex("^(\\*|[a-z0-9-]+:\\*)$", a))])
    ])
    error_message = "no statement may use a bare * or a service-wide wildcard such as kms:* or s3:*"
  }
}

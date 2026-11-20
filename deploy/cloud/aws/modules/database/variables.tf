variable "name" {
  description = "Name of the database cluster (the CloudNativePG Cluster), for example qv-business, qv-guard, qv-temporal."
  type        = string
}

variable "backup_bucket_name" {
  type = string
}

variable "kms_key_arn" {
  description = "Key for the backup bucket and for the role that writes to it."
  type        = string
}

variable "oidc_provider_arn" {
  type = string
}

variable "oidc_issuer_url" {
  type = string
}

variable "namespace" {
  type = string
}

variable "service_account" {
  description = "Service account the CloudNativePG pods run as (the operator names it after the cluster)."
  type        = string
}

variable "noncurrent_expiry_days" {
  type    = number
  default = 35
}

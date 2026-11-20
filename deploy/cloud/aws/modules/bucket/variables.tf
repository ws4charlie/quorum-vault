variable "name" {
  description = "Bucket name (globally unique)."
  type        = string
}

variable "kms_key_arn" {
  description = "Customer-managed key for default encryption."
  type        = string
}

variable "object_lock" {
  description = "Object Lock: only COMPLIANCE is accepted, because a mode that an administrator can lift is not a record. Object Lock can only be enabled at creation and cannot be undone."
  type = object({
    enabled = bool
    days    = number
  })
  default = { enabled = false, days = 0 }

  validation {
    condition     = !var.object_lock.enabled || var.object_lock.days >= 1
    error_message = "an enabled Object Lock needs a retention of at least 1 day"
  }
}

variable "noncurrent_expiry_days" {
  description = "Delete noncurrent versions after this many days (0 = keep). Never set on a locked bucket."
  type        = number
  default     = 0

  validation {
    condition     = var.noncurrent_expiry_days >= 0
    error_message = "must not be negative"
  }
}

variable "extra_policy_statements" {
  description = "More bucket policy statements (list of IAM statement objects). The TLS-only deny is always present."
  type        = any
  default     = []
}

variable "force_destroy" {
  description = "Allow destroy with objects in it. Never true for a locked bucket (the lock would refuse anyway)."
  type        = bool
  default     = false
}

variable "region" {
  type = string
}

variable "account_ids" {
  description = "Account id of every domain: business, signing-core, party-b, party-c, audit."
  type        = map(string)

  validation {
    condition     = alltrue([for d in ["business", "signing-core", "party-b", "party-c", "audit"] : can(regex("^[0-9]{12}$", lookup(var.account_ids, d, "")))])
    error_message = "give a 12-digit account id for business, signing-core, party-b, party-c and audit"
  }
}

variable "bucket_prefix" {
  description = "Prefix that makes the bucket names unique (for example your organization name). The other roots compute the same names."
  type        = string
}

variable "audit_heads_retention_days" {
  description = "Default retention of the audit-head archive in COMPLIANCE mode. 2555 days (7 years) is what the archiver runbook and the chart state; the archiver refuses less than it is told. A shorter value is for a throw-away test account only: the lock cannot be lifted by anyone."
  type        = number
  default     = 2555

  validation {
    condition     = var.audit_heads_retention_days >= 1
    error_message = "at least one day"
  }
}

variable "log_retention_days" {
  description = "COMPLIANCE retention of CloudTrail and flow logs."
  type        = number
  default     = 365
}

variable "archiver_role_name" {
  description = "Name of the role the archiver assumes in the BUSINESS account (made by the business root)."
  type        = string
  default     = "qv-archiver"
}

variable "archiver_role_exists" {
  description = "PHASE 2. false on the first apply (the business root has not made the archiver role yet; AWS refuses a policy that names a role that does not exist). Set true after the business root is applied: the archive bucket and its key then admit that one role."
  type        = bool
  default     = false
}

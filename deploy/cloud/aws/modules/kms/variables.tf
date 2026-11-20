variable "name" {
  description = "Short name; the alias is alias/<name>."
  type        = string
}

variable "description" {
  type = string
}

variable "account_id" {
  description = "Account that owns the key."
  type        = string
}

variable "region" {
  type = string
}

variable "via_services" {
  description = "AWS services (short names such as ec2, secretsmanager) that may use the key on behalf of any principal of this account that is allowed by IAM."
  type        = list(string)
  default     = []
}

variable "service_principals" {
  description = "Service principals (for example logs.eu-central-1.amazonaws.com, cloudtrail.amazonaws.com) that may use the key; limited to this account by aws:SourceAccount."
  type        = list(string)
  default     = []
}

variable "source_account_ids" {
  description = "Accounts whose services may use the key through service_principals (default: this account)."
  type        = list(string)
  default     = []
}

variable "external_user_arns" {
  description = "Roles in OTHER accounts that may use the key (the archiver writing to the audit bucket). They must exist when the key is created."
  type        = list(string)
  default     = []
}

variable "deletion_window_days" {
  type    = number
  default = 30
}

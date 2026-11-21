variable "domain" {
  description = "The trust domain of the root that calls this module: business, signing-core, party-b or party-c."
  type        = string

  validation {
    condition     = contains(["business", "signing-core", "party-b", "party-c"], var.domain)
    error_message = "unknown domain"
  }
}

variable "account_ids" {
  description = "Account id of every domain (12 digits). Needed to allow-list the consumers of an endpoint service."
  type        = map(string)
}

variable "enabled_optional_paths" {
  description = "Ids of optional paths (paths.json) to switch on."
  type        = list(string)
  default     = []
}

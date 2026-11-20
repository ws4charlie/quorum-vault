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

variable "availability_zones" {
  description = "Two zones for the small footprint, three for production."
  type        = list(string)
}

variable "bucket_prefix" {
  description = "Same value as in the audit root: it makes the audit bucket names (flow logs, CloudTrail)."
  type        = string
}

variable "kubernetes_version" {
  type    = string
  default = "1.32"
}

variable "node_groups" {
  type = map(object({
    instance_types = list(string)
    min_size       = number
    max_size       = number
    desired_size   = number
    disk_gb        = optional(number, 100)
    labels         = optional(map(string), {})
    taints = optional(list(object({
      key    = string
      value  = string
      effect = string
    })), [])
  }))
  default = {
    main = { instance_types = ["m7i.xlarge"], min_size = 2, max_size = 4, desired_size = 2 }
  }
}

variable "operators" {
  description = "People or roles that may use the cluster API (IAM Identity Center roles, usually). Name them: nobody has access otherwise."
  type = map(object({
    principal_arn = string
    policy        = string
    namespaces    = optional(list(string), [])
  }))
}

variable "ecr_upstream_credential_arn" {
  description = "Secrets Manager secret (name starts ecr-pullthroughcache/) with a read-only ghcr.io token, made by hand."
  type        = string
}

variable "enable_ops_host" {
  description = "The SSM-only host operators forward the Kubernetes API through. Small, but it bills every hour."
  type        = bool
  default     = false
}

variable "enabled_optional_paths" {
  type    = list(string)
  default = []
}

variable "log_retention_days" {
  type    = number
  default = 365
}

variable "namespace_database" {
  description = "Namespace of the guard database (CloudNativePG cluster qv-guard)."
  type        = string
  default     = "qv-data"
}

variable "endpoint_service_names" {
  description = "PHASE 2. path id (paths.json) => endpoint service name, copied from the provider root's output endpoint_services. Empty in phase 1: no endpoint yet."
  type        = map(string)
  default     = {}
}

variable "enable_cloudhsm" {
  description = "CloudHSM for this party. OFF by default: it bills every hour from the moment an HSM exists. Use SoftHSM only in a throw-away test (the code refuses it elsewhere)."
  type        = bool
  default     = false
}

variable "hsm_count" {
  type    = number
  default = 2
}

variable "nlb_services" {
  description = "PHASE 2. service name (caller, peer) => namespace/service of the LoadBalancer Service the qv-party chart created. Empty in phase 1: no endpoint service yet."
  type        = map(string)
  default     = {}
}

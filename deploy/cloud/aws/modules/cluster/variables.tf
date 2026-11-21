variable "name" {
  type = string
}

variable "region" {
  type = string
}

variable "account_id" {
  type = string
}

variable "kubernetes_version" {
  description = "The charts need 1.30 or later (qv-policy uses ValidatingAdmissionPolicy)."
  type        = string
  default     = "1.32"

  validation {
    condition     = tonumber(split(".", var.kubernetes_version)[0]) > 1 || tonumber(split(".", var.kubernetes_version)[1]) >= 30
    error_message = "the charts require Kubernetes 1.30 or later"
  }
}

variable "vpc_id" {
  type = string
}

variable "subnet_ids" {
  type = list(string)
}

variable "secrets_kms_key_arn" {
  description = "Key for envelope encryption of Kubernetes Secrets in etcd."
  type        = string
}

variable "ebs_kms_key_arn" {
  description = "Key for the nodes' disks and for the volumes the CSI driver creates."
  type        = string
}

variable "logs_kms_key_arn" {
  description = "Key for the control-plane log group."
  type        = string
}

variable "log_retention_days" {
  type    = number
  default = 365
}

variable "access_entries" {
  description = "Who may use the cluster API. There is no creator admin and no aws-auth map. policy is one of AmazonEKSClusterAdminPolicy, AmazonEKSAdminPolicy, AmazonEKSEditPolicy, AmazonEKSViewPolicy; namespaces empty = whole cluster."
  type = map(object({
    principal_arn = string
    policy        = string
    namespaces    = optional(list(string), [])
  }))

  validation {
    condition     = length(var.access_entries) >= 1
    error_message = "name at least one principal, or nobody can use the cluster"
  }
  validation {
    condition     = alltrue([for e in var.access_entries : contains(["AmazonEKSClusterAdminPolicy", "AmazonEKSAdminPolicy", "AmazonEKSEditPolicy", "AmazonEKSViewPolicy"], e.policy)])
    error_message = "unknown access policy"
  }
}

variable "api_allowed_cidrs" {
  description = "Ranges that may reach the private API endpoint. Never the world."
  type        = list(string)

  validation {
    condition     = length(var.api_allowed_cidrs) >= 1 && !contains(var.api_allowed_cidrs, "0.0.0.0/0")
    error_message = "name the ranges; 0.0.0.0/0 is refused"
  }
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
}

variable "pull_through_prefix" {
  description = "ECR pull-through cache prefix the nodes may create repositories under (module registry). Empty = no pull-through permission."
  type        = string
  default     = "ghcr"
}

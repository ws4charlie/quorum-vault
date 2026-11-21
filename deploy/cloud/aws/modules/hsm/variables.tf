variable "enabled" {
  description = "OFF by default: CloudHSM bills every hour from the moment an HSM exists, whether it is used or not."
  type        = bool
  default     = false
}

variable "name" {
  type = string
}

variable "subnet_ids" {
  description = "One subnet per zone. One HSM per subnet, up to hsm_count."
  type        = list(string)
}

variable "hsm_count" {
  description = "1 for a throw-away test, 2 or more for anything that must survive a zone loss."
  type        = number
  default     = 2

  validation {
    condition     = var.hsm_count >= 1 && var.hsm_count <= 3
    error_message = "one to three HSMs"
  }
}

variable "hsm_type" {
  type    = string
  default = "hsm2m.medium"
}

variable "client_security_group_id" {
  description = "Security group of the nodes (the cluster security group) that may reach the HSMs."
  type        = string
}

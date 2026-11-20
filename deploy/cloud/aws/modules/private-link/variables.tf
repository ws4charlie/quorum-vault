variable "name" {
  type = string
}

variable "services" {
  description = "PROVIDER side: endpoint services this domain offers. Key = service name from paths.json; nlb_arn = the internal network load balancer the chart's Service created; allowed_account_ids = the only accounts that may connect."
  type = map(object({
    nlb_arn             = string
    allowed_account_ids = list(string)
  }))
  default = {}

  validation {
    condition     = alltrue([for s in var.services : length(s.allowed_account_ids) > 0 && alltrue([for a in s.allowed_account_ids : can(regex("^[0-9]{12}$", a))])])
    error_message = "every endpoint service names the 12-digit accounts that may connect, and at least one"
  }
}

variable "acceptance_required" {
  description = "A person accepts every new connection to an endpoint service (a deliberate step, recorded in CloudTrail)."
  type        = bool
  default     = true
}

variable "links" {
  description = "CONSUMER side: endpoints this domain opens to services of other domains. Key = path id; service_name comes from the provider's output."
  type = map(object({
    service_name = string
    ports        = list(number)
    dns          = string
  }))
  default = {}
}

variable "vpc_id" {
  type = string
}

variable "vpc_cidr" {
  type = string
}

variable "subnet_ids" {
  type = list(string)
}

variable "zone_name" {
  description = "Private DNS zone for the names in the certificates' DNS SANs (qv.internal). Exists only inside this VPC."
  type        = string
  default     = "qv.internal"
}

variable "name" {
  type = string
}

variable "region" {
  type = string
}

variable "vpc_cidr" {
  description = "From cidrs.json (the address plan). Ranges of the four domains never overlap."
  type        = string
}

variable "availability_zones" {
  description = "Two or three zones. Two is the small-footprint variant."
  type        = list(string)

  validation {
    condition     = length(var.availability_zones) >= 2 && length(var.availability_zones) <= 3
    error_message = "use two or three availability zones"
  }
}

variable "egress_mode" {
  description = "isolated: no internet gateway, no NAT, no route out of the VPC (signing domains). nat: one NAT gateway per zone (business domain only: chain nodes and the identity provider)."
  type        = string

  validation {
    condition     = contains(["isolated", "nat"], var.egress_mode)
    error_message = "egress_mode is isolated or nat"
  }
}

variable "interface_endpoints" {
  description = "Short names of AWS services reached through interface endpoints (ecr.api, ecr.dkr, sts, logs, ...). Each endpoint bills per zone and hour."
  type        = list(string)
  default     = []
}

variable "flow_log_bucket_arn" {
  description = "Bucket in the AUDIT account that receives the VPC flow logs."
  type        = string
}

variable "cluster_name" {
  description = "Cluster that will use the subnets (load balancer discovery tags)."
  type        = string
}

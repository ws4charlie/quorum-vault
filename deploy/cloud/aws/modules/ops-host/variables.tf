variable "enabled" {
  description = "OFF by default. A small instance that does nothing but forward a port: operators reach the private Kubernetes API through an SSM session on it."
  type        = bool
  default     = false
}

variable "name" {
  type = string
}

variable "vpc_id" {
  type = string
}

variable "vpc_cidr" {
  type = string
}

variable "subnet_id" {
  type = string
}

variable "kms_key_arn" {
  type = string
}

variable "instance_type" {
  type    = string
  default = "t3.micro"
}

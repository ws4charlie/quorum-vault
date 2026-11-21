variable "name" {
  type = string
}

variable "ebs_kms_key_arn" {
  description = "Default key for every new EBS volume of the account."
  type        = string
}

variable "cloudtrail_bucket_name" {
  description = "Bucket in the AUDIT account that receives this account's CloudTrail log. Workload accounts cannot delete from it."
  type        = string
}

variable "password_min_length" {
  type    = number
  default = 14
}

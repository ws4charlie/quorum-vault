variable "name" {
  description = "Short name of the party's enclave key; the alias is alias/<name> and the role is <name>-parent."
  type        = string
}

variable "description" {
  description = "Description of the key."
  type        = string
}

variable "account_id" {
  description = "Account that owns the key."
  type        = string
}

variable "allowed_images" {
  description = <<-EOT
    The enclave images that may use the key: one entry per release that may run (an upgrade lists the old and the new one together, and drops the old one
    afterwards). pcrs maps a PCR number to its value, 96 lower-case hex characters (SHA-384); "0" (the image) is required. Produce the list from the signed
    allowlist with deploy/cloud/aws/nitro/allowlist-to-tfvars.py. An empty list, a missing PCR0, an all-zero value (what a debug-mode enclave reports) or a value
    that is not 96 hex characters is refused: a key policy without a PCR condition would let any enclave, or any caller with the role, use the key.
  EOT
  type = list(object({
    name = string
    pcrs = map(string)
  }))

  validation {
    condition     = length(var.allowed_images) >= 1
    error_message = "allowed_images needs at least one image: a key policy without a PCR condition is refused."
  }
  validation {
    condition     = alltrue([for i in var.allowed_images : can(regex("^[A-Za-z0-9_.-]{1,40}$", i.name))])
    error_message = "an image name is 1 to 40 characters of A-Z a-z 0-9 _ . -"
  }
  validation {
    condition     = alltrue([for i in var.allowed_images : contains(keys(i.pcrs), "0")])
    error_message = "every image needs PCR0 (kms:RecipientAttestation:ImageSha384)."
  }
  validation {
    condition = alltrue([
      for i in var.allowed_images : alltrue([
        for n, v in i.pcrs : can(regex("^(0|[1-9][0-9]?)$", n)) && can(regex("^[0-9a-f]{96}$", v)) && !can(regex("^0{96}$", v))
      ])
    ])
    error_message = "a PCR is a number (0 to 99) with a value of 96 lower-case hex characters that is not all zero (an all-zero PCR is a debug-mode enclave)."
  }
}

variable "party_role_names" {
  description = "Names of the IAM roles (the parent instance's role of each host of this party) that may call the key. The module makes one role by default (see create_parent_role)."
  type        = list(string)
  default     = []
}

variable "create_parent_role" {
  description = "Make the instance role and profile of the party's enclave host: it may call only this key, and only with an attestation document."
  type        = bool
  default     = true
}

variable "key_admin_role_arns" {
  description = "Roles that may change the key policy and manage the key (never use it). Changing an allowed image is a key-policy change: give it to two people, with CloudTrail."
  type        = list(string)
  default     = []
}

variable "deletion_window_days" {
  description = "Waiting time before a scheduled key deletion."
  type        = number
  default     = 30
}

# ---- the enclave host (a launch template for an Auto Scaling group or an EKS managed node group) ----

variable "create_launch_template" {
  description = "Make the launch template of the enclave host."
  type        = bool
  default     = true
}

variable "instance_type" {
  description = "A Nitro-based type with enough vCPUs and memory for the parent plus the enclave (the enclave takes cores and memory away from the parent). Nitro Enclaves need a type with at least 4 vCPUs on x86 and no hibernation; see docs/runbooks/nitro-first-run.md."
  type        = string
  default     = "m6i.xlarge"
}

variable "ami_id" {
  description = "An Amazon Linux 2023 AMI of the instance type's architecture (the enclave image must be built for the same architecture)."
  type        = string
  default     = ""
}

variable "root_volume_gb" {
  description = "Size of the host root volume."
  type        = number
  default     = 50
}

variable "ebs_kms_key_arn" {
  description = "Customer key for the instance's EBS volumes."
  type        = string
  default     = ""
}

terraform {
  required_version = ">= 1.10.0, < 2.0.0"

  # Remote state: one bucket per domain, in that domain's own account, encrypted with its own key, locked with a lock file in the bucket (no table).
  # Nothing is set here: `terraform init -backend-config=backend.hcl` (see backend.hcl.example). `init -backend=false` is what CI runs.
  backend "s3" {
    use_lockfile = true
    encrypt      = true
  }

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "= 6.67.0"
    }
  }
}

provider "aws" {
  region              = var.region
  allowed_account_ids = [var.account_ids["party-c"]]

  default_tags {
    tags = {
      project = "quorum-vault"
      domain  = "party-c"
    }
  }
}

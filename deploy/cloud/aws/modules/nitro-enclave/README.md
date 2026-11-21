# nitro-enclave

The enclave key of one MPC party and what may use it (task T7-prep; written and tested against a mocked provider, **never applied**: there was no AWS account).

- `aws_kms_key` whose policy lets the party's role call `kms:Decrypt` and `kms:GenerateDataKey` only with an attestation document whose PCRs equal one of `allowed_images`; denies every use without a document to everyone; delegates administration, never use, to the account.
- The party's parent instance role and profile: may call only this key, only with a recipient.
- A launch template for the enclave host (Nitro Enclaves on, IMDSv2 only, encrypted disks).

```hcl
module "enclave_a" {
  source         = "../../modules/nitro-enclave"
  name           = "qv-party-a"
  description    = "Enclave key of party A"
  account_id     = var.account_id
  ami_id         = var.enclave_host_ami
  allowed_images = jsondecode(file("party-a.auto.tfvars.json")).allowed_images   # made by nitro/allowlist-to-tfvars.py
}
```

`allowed_images` comes from the signed allowlist (`../../nitro/allowlist-to-tfvars.py`), so the broker and KMS enforce one list. Changing it is a key-policy change: two people, CloudTrail. How an image's PCRs are made: `deploy/images/eif-build.sh`. First run: `docs/runbooks/nitro-first-run.md`.

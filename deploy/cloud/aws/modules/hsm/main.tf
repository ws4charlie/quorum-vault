# AWS CloudHSM for ONE party, in that party's own account. Off by default (hourly billing).
# Creating the cluster is not initialising it: the cluster certificate, the first crypto officer and the crypto user that the party's sealer logs in as
# are made by hand by the party's operators (runbook aws-first-deploy.md). Terraform never sees a PIN, a user name or a password.

resource "aws_cloudhsm_v2_cluster" "this" {
  count      = var.enabled ? 1 : 0
  hsm_type   = var.hsm_type
  subnet_ids = var.subnet_ids
  tags       = { Name = var.name }
}

resource "aws_cloudhsm_v2_hsm" "this" {
  count      = var.enabled ? min(var.hsm_count, length(var.subnet_ids)) : 0
  cluster_id = aws_cloudhsm_v2_cluster.this[0].cluster_id
  subnet_id  = var.subnet_ids[count.index]
}

# The HSMs accept the client library on 2223 to 2225 from the nodes only.
resource "aws_vpc_security_group_ingress_rule" "nodes" {
  count                        = var.enabled ? 1 : 0
  security_group_id            = aws_cloudhsm_v2_cluster.this[0].security_group_id
  description                  = "CloudHSM client ports from the cluster nodes"
  referenced_security_group_id = var.client_security_group_id
  ip_protocol                  = "tcp"
  from_port                    = 2223
  to_port                      = 2225
}

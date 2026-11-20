output "name" {
  value = aws_eks_cluster.this.name
}

output "endpoint" {
  description = "Private API endpoint; reachable only from inside the VPC."
  value       = aws_eks_cluster.this.endpoint
}

output "cluster_security_group_id" {
  description = "The security group EKS puts on nodes and control-plane interfaces."
  value       = aws_eks_cluster.this.vpc_config[0].cluster_security_group_id
}

output "api_security_group_id" {
  value = aws_security_group.api.id
}

output "oidc_provider_arn" {
  value = aws_iam_openid_connect_provider.this.arn
}

output "oidc_issuer_url" {
  value = aws_eks_cluster.this.identity[0].oidc[0].issuer
}

output "node_role_arn" {
  value = aws_iam_role.node.arn
}

output "endpoint_public_access" {
  value = aws_eks_cluster.this.vpc_config[0].endpoint_public_access
}

output "policies" {
  description = "Every inline or customer policy this module makes (for the tests)."
  value = {
    cluster_kms  = aws_iam_role_policy.cluster_kms.policy
    ebs_csi      = module.ebs_csi.policy
    pull_through = [for p in aws_iam_role_policy.node_pull_through : p.policy]
  }
}

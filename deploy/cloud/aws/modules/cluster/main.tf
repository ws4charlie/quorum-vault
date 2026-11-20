# One private EKS cluster. No public API endpoint; no creator admin; Secrets encrypted with a customer key; every control-plane log type on;
# network policy enforced by the VPC CNI; nodes with IMDSv2 only (hop limit 1, so no pod can read the node's credentials) and encrypted disks.

locals {
  kms_use = ["kms:Decrypt", "kms:DescribeKey", "kms:Encrypt", "kms:GenerateDataKey", "kms:GenerateDataKeyWithoutPlaintext", "kms:ReEncryptFrom", "kms:ReEncryptTo", "kms:CreateGrant"]
}

# --- cluster role ---

resource "aws_iam_role" "cluster" {
  name = "${var.name}-cluster"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "eks.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}

resource "aws_iam_role_policy_attachment" "cluster" {
  role       = aws_iam_role.cluster.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
}

resource "aws_iam_role_policy" "cluster_kms" {
  name = "secrets-key"
  role = aws_iam_role.cluster.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["kms:Decrypt", "kms:DescribeKey", "kms:Encrypt", "kms:ListGrants"]
      Resource = var.secrets_kms_key_arn
    }]
  })
}

# --- API access: a security group for the private endpoint, open to named ranges only ---

resource "aws_security_group" "api" {
  name        = "${var.name}-api"
  description = "Kubernetes API of ${var.name}: HTTPS from named ranges only"
  vpc_id      = var.vpc_id
  tags        = { Name = "${var.name}-api" }
}

resource "aws_vpc_security_group_ingress_rule" "api" {
  for_each          = toset(var.api_allowed_cidrs)
  security_group_id = aws_security_group.api.id
  description       = "Kubernetes API from ${each.key}"
  cidr_ipv4         = each.key
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
}

resource "aws_cloudwatch_log_group" "cluster" {
  name              = "/aws/eks/${var.name}/cluster"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.logs_kms_key_arn
}

resource "aws_eks_cluster" "this" {
  name     = var.name
  version  = var.kubernetes_version
  role_arn = aws_iam_role.cluster.arn

  access_config {
    authentication_mode                         = "API"
    bootstrap_cluster_creator_admin_permissions = false
  }

  vpc_config {
    subnet_ids              = var.subnet_ids
    security_group_ids      = [aws_security_group.api.id]
    endpoint_private_access = true
    endpoint_public_access  = false
  }

  encryption_config {
    resources = ["secrets"]
    provider {
      key_arn = var.secrets_kms_key_arn
    }
  }

  enabled_cluster_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]

  depends_on = [aws_iam_role_policy_attachment.cluster, aws_iam_role_policy.cluster_kms, aws_cloudwatch_log_group.cluster]
}

resource "aws_eks_access_entry" "this" {
  for_each      = var.access_entries
  cluster_name  = aws_eks_cluster.this.name
  principal_arn = each.value.principal_arn
  type          = "STANDARD"
}

resource "aws_eks_access_policy_association" "this" {
  for_each      = var.access_entries
  cluster_name  = aws_eks_cluster.this.name
  principal_arn = each.value.principal_arn
  policy_arn    = "arn:aws:eks::aws:cluster-access-policy/${each.value.policy}"

  access_scope {
    type       = length(each.value.namespaces) > 0 ? "namespace" : "cluster"
    namespaces = length(each.value.namespaces) > 0 ? each.value.namespaces : null
  }
  depends_on = [aws_eks_access_entry.this]
}

# --- IAM roles for service accounts ---

resource "aws_iam_openid_connect_provider" "this" {
  url            = aws_eks_cluster.this.identity[0].oidc[0].issuer
  client_id_list = ["sts.amazonaws.com"]
}

# --- nodes ---

resource "aws_iam_role" "node" {
  name = "${var.name}-node"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "ec2.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}

# AWS-managed, narrow policies: join the cluster, run the VPC CNI, pull images from ECR. No SSM, no S3, nothing else.
resource "aws_iam_role_policy_attachment" "node" {
  for_each = toset([
    "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy",
    "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy",
    "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryPullOnly",
  ])
  role       = aws_iam_role.node.name
  policy_arn = each.value
}

# The first pull of an image through the ECR pull-through cache creates the repository: allowed under one prefix only.
resource "aws_iam_role_policy" "node_pull_through" {
  count = var.pull_through_prefix == "" ? 0 : 1
  name  = "pull-through-cache"
  role  = aws_iam_role.node.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["ecr:BatchImportUpstreamImage", "ecr:CreateRepository"]
      Resource = "arn:aws:ecr:${var.region}:${var.account_id}:repository/${var.pull_through_prefix}/*"
    }]
  })
}

resource "aws_launch_template" "node" {
  for_each    = var.node_groups
  name_prefix = "${var.name}-${each.key}-"

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      volume_size           = each.value.disk_gb
      volume_type           = "gp3"
      encrypted             = true
      kms_key_id            = var.ebs_kms_key_arn
      delete_on_termination = true
    }
  }

  tag_specifications {
    resource_type = "instance"
    tags          = { Name = "${var.name}-${each.key}" }
  }
}

resource "aws_eks_node_group" "this" {
  for_each        = var.node_groups
  cluster_name    = aws_eks_cluster.this.name
  node_group_name = each.key
  node_role_arn   = aws_iam_role.node.arn
  subnet_ids      = var.subnet_ids
  instance_types  = each.value.instance_types
  ami_type        = "AL2023_x86_64_STANDARD"
  labels          = each.value.labels

  scaling_config {
    min_size     = each.value.min_size
    max_size     = each.value.max_size
    desired_size = each.value.desired_size
  }

  update_config {
    max_unavailable = 1
  }

  launch_template {
    id      = aws_launch_template.node[each.key].id
    version = aws_launch_template.node[each.key].latest_version
  }

  dynamic "taint" {
    for_each = each.value.taints
    content {
      key    = taint.value.key
      value  = taint.value.value
      effect = taint.value.effect
    }
  }

  depends_on = [aws_iam_role_policy_attachment.node]

  lifecycle {
    ignore_changes = [scaling_config[0].desired_size]
  }
}

# --- EBS CSI driver: its own role, limited to the cluster's disk key ---

module "ebs_csi" {
  source            = "../irsa"
  name              = "${var.name}-ebs-csi"
  oidc_provider_arn = aws_iam_openid_connect_provider.this.arn
  oidc_issuer_url   = aws_eks_cluster.this.identity[0].oidc[0].issuer
  namespace         = "kube-system"
  service_account   = "ebs-csi-controller-sa"
  # Follows AWS's managed policy AmazonEBSCSIDriverPolicy (v15, read 2026-11-20: https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AmazonEBSCSIDriverPolicy.html),
  # written out here and NOT attached, because of these differences:
  #   - dropped: ec2:CopyVolumes, ec2:LockSnapshot, ec2:EnableFastSnapshotRestores (not used by the charts);
  #   - ec2:DeleteTags only on volumes and snapshots that carry the driver's ownership tag (the managed policy allows it on every volume and snapshot);
  #   - the kms statement (the managed policy has none; this key is the only one the driver may use).
  # Delete calls need an ownership tag; the tag can be added only in the call that creates the volume or snapshot (ec2:CreateAction), never later,
  # so the driver cannot claim an existing volume of another workload and then delete it.
  policy_statements = [
    {
      Effect = "Allow"
      Action = [
        "ec2:DescribeAvailabilityZones", "ec2:DescribeInstances", "ec2:DescribeInstanceTypes", "ec2:DescribeSnapshots", "ec2:DescribeTags",
        "ec2:DescribeVolumes", "ec2:DescribeVolumesModifications", "ec2:DescribeVolumeStatus",
      ]
      Resource = "*"
    },
    { Effect = "Allow", Action = ["ec2:CreateSnapshot", "ec2:ModifyVolume"], Resource = "arn:aws:ec2:*:*:volume/*" },
    { Effect = "Allow", Action = ["ec2:AttachVolume", "ec2:DetachVolume"], Resource = ["arn:aws:ec2:*:*:volume/*", "arn:aws:ec2:*:*:instance/*"] },
    { Effect = "Allow", Action = ["ec2:CreateVolume", "ec2:EnableFastSnapshotRestores"], Resource = "arn:aws:ec2:*:*:snapshot/*" },
    {
      Effect    = "Allow"
      Action    = ["ec2:CreateTags"]
      Resource  = ["arn:aws:ec2:*:*:volume/*", "arn:aws:ec2:*:*:snapshot/*"]
      Condition = { StringEquals = { "ec2:CreateAction" = ["CreateVolume", "CreateSnapshot"] } }
    },
    {
      Effect    = "Allow"
      Action    = ["ec2:DeleteTags"]
      Resource  = ["arn:aws:ec2:*:*:volume/*", "arn:aws:ec2:*:*:snapshot/*"]
      Condition = { StringLike = { "ec2:ResourceTag/ebs.csi.aws.com/cluster" = "true" } }
    },
    {
      Effect    = "Allow"
      Action    = ["ec2:CreateVolume"]
      Resource  = "arn:aws:ec2:*:*:volume/*"
      Condition = { StringLike = { "aws:RequestTag/ebs.csi.aws.com/cluster" = "true" } }
    },
    {
      Effect    = "Allow"
      Action    = ["ec2:CreateVolume"]
      Resource  = "arn:aws:ec2:*:*:volume/*"
      Condition = { StringLike = { "aws:RequestTag/CSIVolumeName" = "*" } }
    },
    {
      Effect    = "Allow"
      Action    = ["ec2:DeleteVolume"]
      Resource  = "arn:aws:ec2:*:*:volume/*"
      Condition = { StringLike = { "ec2:ResourceTag/ebs.csi.aws.com/cluster" = "true" } }
    },
    {
      Effect    = "Allow"
      Action    = ["ec2:DeleteVolume"]
      Resource  = "arn:aws:ec2:*:*:volume/*"
      Condition = { StringLike = { "ec2:ResourceTag/CSIVolumeName" = "*" } }
    },
    {
      Effect    = "Allow"
      Action    = ["ec2:DeleteVolume"]
      Resource  = "arn:aws:ec2:*:*:volume/*"
      Condition = { StringLike = { "ec2:ResourceTag/kubernetes.io/created-for/pvc/name" = "*" } }
    },
    {
      Effect    = "Allow"
      Action    = ["ec2:CreateSnapshot"]
      Resource  = "arn:aws:ec2:*:*:snapshot/*"
      Condition = { StringLike = { "aws:RequestTag/CSIVolumeSnapshotName" = "*" } }
    },
    {
      Effect    = "Allow"
      Action    = ["ec2:CreateSnapshot"]
      Resource  = "arn:aws:ec2:*:*:snapshot/*"
      Condition = { StringLike = { "aws:RequestTag/ebs.csi.aws.com/cluster" = "true" } }
    },
    {
      Effect    = "Allow"
      Action    = ["ec2:DeleteSnapshot"]
      Resource  = "arn:aws:ec2:*:*:snapshot/*"
      Condition = { StringLike = { "ec2:ResourceTag/CSIVolumeSnapshotName" = "*" } }
    },
    {
      Effect    = "Allow"
      Action    = ["ec2:DeleteSnapshot"]
      Resource  = "arn:aws:ec2:*:*:snapshot/*"
      Condition = { StringLike = { "ec2:ResourceTag/ebs.csi.aws.com/cluster" = "true" } }
    },
    {
      Effect   = "Allow"
      Action   = local.kms_use
      Resource = var.ebs_kms_key_arn
    },
  ]
}

resource "aws_eks_addon" "vpc_cni" {
  cluster_name                = aws_eks_cluster.this.name
  addon_name                  = "vpc-cni"
  resolve_conflicts_on_update = "OVERWRITE"
  configuration_values        = jsonencode({ enableNetworkPolicy = "true" })
}

resource "aws_eks_addon" "kube_proxy" {
  cluster_name = aws_eks_cluster.this.name
  addon_name   = "kube-proxy"
}

resource "aws_eks_addon" "coredns" {
  cluster_name = aws_eks_cluster.this.name
  addon_name   = "coredns"
  depends_on   = [aws_eks_node_group.this]
}

resource "aws_eks_addon" "ebs_csi" {
  cluster_name             = aws_eks_cluster.this.name
  addon_name               = "aws-ebs-csi-driver"
  service_account_role_arn = module.ebs_csi.role_arn
  depends_on               = [aws_eks_node_group.this]
}

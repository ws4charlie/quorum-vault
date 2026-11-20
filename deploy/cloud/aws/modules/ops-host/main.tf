# The way in for operators: no inbound rule, no key pair, no public address. An operator starts an SSM Session Manager port forward to the cluster's private
# API endpoint through this host and runs kubectl on their own machine with their own identity (their EKS access entry), so the cluster's audit log names them.
# The host's own role can only register with SSM; it has no access to the cluster.

data "aws_ssm_parameter" "ami" {
  count = var.enabled ? 1 : 0
  name  = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
}

resource "aws_iam_role" "this" {
  count = var.enabled ? 1 : 0
  name  = "${var.name}-ops-host"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "ec2.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}

resource "aws_iam_role_policy_attachment" "ssm" {
  count      = var.enabled ? 1 : 0
  role       = aws_iam_role.this[0].name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "this" {
  count = var.enabled ? 1 : 0
  name  = "${var.name}-ops-host"
  role  = aws_iam_role.this[0].name
}

resource "aws_security_group" "this" {
  count       = var.enabled ? 1 : 0
  name        = "${var.name}-ops-host"
  description = "Ops host: no inbound rule; HTTPS to the VPC only (SSM endpoints and the Kubernetes API)"
  vpc_id      = var.vpc_id
}

resource "aws_vpc_security_group_egress_rule" "https" {
  count             = var.enabled ? 1 : 0
  security_group_id = aws_security_group.this[0].id
  description       = "HTTPS inside this VPC"
  cidr_ipv4         = var.vpc_cidr
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
}

resource "aws_instance" "this" {
  count                  = var.enabled ? 1 : 0
  ami                    = data.aws_ssm_parameter.ami[0].value
  instance_type          = var.instance_type
  subnet_id              = var.subnet_id
  vpc_security_group_ids = [aws_security_group.this[0].id]
  iam_instance_profile   = aws_iam_instance_profile.this[0].name
  monitoring             = true

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  root_block_device {
    encrypted  = true
    kms_key_id = var.kms_key_arn
  }

  tags = { Name = "${var.name}-ops-host" }
}

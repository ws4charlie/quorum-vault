# lb-controller-nlb.json

The subset of the AWS Load Balancer Controller's IAM policy that **network** load balancers need (no ALB, WAF, Shield, ACM or Cognito). It follows the upstream file
(`kubernetes-sigs/aws-load-balancer-controller`, [docs/install/iam_policy.json](https://github.com/kubernetes-sigs/aws-load-balancer-controller/blob/main/docs/install/iam_policy.json) on the main branch, read 2026-11-20; the file carries no version) statement by statement for
the actions kept, including the creation-time tagging statements (a security group is tagged in the same call that creates it, so the tag cannot be required on the resource yet):
`ec2:CreateTags` is allowed on a new security group only with `ec2:CreateAction = CreateSecurityGroup` and the cluster tag in the request; later tag changes only on resources that already have the cluster tag.

Dropped from upstream: statements for application load balancers, listener rules, WAF, Shield, ACM, Cognito and the capacity-reservation and IP-pool actions. It is a copy of a moving
file: before the first apply compare it with the upstream file of the controller version you install, and add what the controller reports as denied. It has no `elasticloadbalancing:*`, `ec2:*` or bare `*`.

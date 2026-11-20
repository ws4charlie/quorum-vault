# lb-controller-nlb.json

The subset of the AWS Load Balancer Controller's IAM policy that **network** load balancers need (no ALB, WAF, Shield or ACM). Written from the upstream policy
(kubernetes-sigs/aws-load-balancer-controller, `docs/install/iam_policy.json`) and **not diffed against the version of the controller you install**: before the first apply,
compare it with the upstream file of that version and add what the controller reports as denied. It stays free of `elasticloadbalancing:*`, `ec2:*` and any bare `*`.

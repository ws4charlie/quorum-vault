# Break-glass access to a signing cluster

When this applies: something is wrong inside a gateway, cosigner, party or broker pod and the normal tools (logs, metrics, the operators' CLI, a new release) cannot fix it. Nobody has standing access. Read-only access (`qv:readers`) is separate and needs no approval.

Design: [Deployment](../deployment.md), "How each process is kept safe". Rules in force: chart `deploy/policy/qv-policy` (`qv-no-exec`, RBAC role `qv-break-glass`).

## Who may get access

- Only the operators of **that** cluster's domain (party A with the gateway, party B, party C, broker). Nobody gets access to two party clusters, at any time: separate IAM identities, reviewed quarterly.
- A requester and an approver, two different people, both from that domain. The requester cannot approve their own request.
- The business cluster has its own break-glass role, same two-person rule.

## How

1. **Request** in the change channel of that domain: cluster, namespace, reason, the exact action, expected duration (at most 4 hours). Link the alert or incident.
2. **Approve**: the second person writes "approved" with the same ticket id. Nobody else's approval counts.
3. **Grant** (`<CLOUD: placeholder for the cloud task>`): the cloud IAM role that maps to the Kubernetes group `qv:break-glass` is assumed through the cloud's access-approval feature with session recording on. The grant expires by itself at the end of the window. Nothing is added to the cluster: `qv-break-glass` is bound to nobody by default, and the binding to the group is created through the GitOps repository only for the window, by the approver (`breakGlass.subjects` in the `qv-policy` values) and removed afterwards.
4. **Work**: `kubectl exec`, `kubectl debug` or `port-forward` as the granted identity. Admission (`qv-no-exec`) allows these calls only for members of `qv:break-glass`; everyone else, including `system:masters`, is refused. The debug container must itself pass the pod rules (registry, non-root, no privilege): use an image from the allowed registry, by digest.
5. **Close**: the requester posts what was done and found; the approver removes the binding and confirms the IAM session has ended. If anything was changed by hand, open a task so the change goes through a release.

## What is logged, and where

| Record | Where | Notes |
|---|---|---|
| Who asked, who approved, why, the window | the change ticket | the only place the second approval is visible |
| Every API call (exec, attach, debug, port-forward, deletes), with user and groups | the API-server audit log, shipped write-only to the audit account (`<CLOUD: log destination, placeholder>`) | audit policy must record `pods/exec`, `pods/attach`, `pods/portforward`, `pods/ephemeralcontainers` at `RequestResponse`/`Metadata` level |
| The terminal session | the cloud's session recorder (`<CLOUD: placeholder>`) | content of an exec session is not in the audit log |
| Refused attempts | the same audit log (`Forbidden` from the admission policy) and the policy's Audit action | an alert on any `qv-no-exec` refusal in a signing cluster is expected |

## What admission can and cannot enforce

- **Can:** refuse exec, attach, port-forward and ephemeral containers on pods in the labelled namespaces unless the caller is in `qv:break-glass`; refuse debug containers that are root, privileged or from another registry.
- **Cannot:** know that a second person approved (that is IAM and the ticket); stop a cluster-admin from deleting the policy or the binding (the audit log and the other checkers catch that); stop `kubectl debug node/<name>` or any pod in a namespace this chart does not label (node access is cloud IAM: no SSH or SSM to the nodes of a party cluster without the same two-person rule); read the memory of a process from the node.
- **Must be RBAC and IAM:** who is in `qv:break-glass`; that `system:masters` and cluster-admin are not given to people; that no identity has admin in two party clusters.

## After use

- Confirm the binding is gone: `kubectl get rolebinding -A | grep qv-break-glass` shows nothing.
- If a share-holding pod (party) was entered, treat the party as **possibly exposed**. The API audit log records that an exec happened, not what was typed or read, so it cannot clear anyone. Only the recorded session (the cloud session recorder, step 3) can: review it with a second person. If the recording is missing, incomplete or unreadable, the question stays **unresolved, which means possibly exposed**. Then follow `docs/runbooks/mpc-failures.md` (key refresh or replacement) and tell the other parties' operators.

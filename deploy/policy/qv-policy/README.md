# qv-policy

Rules the **cluster** enforces, installed once per cluster by that cluster's own operators. The application charts already render hardened pods and default-deny network policies, and `ci/helm` tests that output. That guards against a mistake in our charts. It does not stop someone with access to the cluster from applying something else. This chart adds the checks the API server runs on every request.

## What is installed

| Kind | What | Engine |
|---|---|---|
| Namespaces | Pod Security `restricted` (enforce, audit, warn; version pinned), label `quorumvault.io/policy: enforced` | API server (built in) |
| `qv-pods` | registry prefix, digest, no `-dev` image, no dev switch (`QV_ENV` dev or test, SoftHSM, `QV_ALLOW_PLAINTEXT`, `QV_DEV_ACTOR_HEADER`, `QV_OIDC_TEST_JWKS`), no hostNetwork/PID/IPC, hostPath, privileged, added capability, root, privilege escalation. Signing kinds also: only hash-named (immutable) ConfigMaps, no ServiceAccount token unless listed | ValidatingAdmissionPolicy |
| `qv-services` | no NodePort; LoadBalancer only with `quorumvault.io/endpoint: private` (the annotation the party chart sets); no externalIPs | ValidatingAdmissionPolicy |
| `qv-no-ingress` (signing kinds) | no Ingress, no Gateway API route | ValidatingAdmissionPolicy |
| `qv-configmaps` | signing kinds: every ConfigMap `immutable: true`. Production: no dev switch or SoftHSM path in the data | ValidatingAdmissionPolicy |
| `qv-configmap-writers` (production, signing kinds) | only the GitOps identity (`configWriters`) may create, change or delete a ConfigMap | ValidatingAdmissionPolicy |
| `qv-no-exec` (signing kinds) | exec, attach, port-forward and ephemeral (debug) containers only for the `breakGlass.group` | ValidatingAdmissionPolicy |
| `qv-verify-images` (production) | cosign signature of every image, by the publish job's identity | Kyverno, this one rule only |
| RBAC | `qv-read-only` (no Secrets, no exec) bound per namespace; `qv-break-glass` bound to **nobody** unless `breakGlass.subjects` is set. RoleBindings only, never a ClusterRoleBinding | RBAC |

Cluster kinds: `business`, `signing-core` (gateway and party A), `party` (one party, B or C: exactly one namespace), `broker`. `business` omits the signing-only rules; the business chart's ConfigMaps are not immutable today (see "Known gaps").

## Engine choice

In a signing cluster the cluster administrator is not fully trusted, so the checks should depend on as little as possible.

- **ValidatingAdmissionPolicy** runs inside the API server: no extra controller, no webhook to keep alive, no network call, nothing a second admin tool can quietly replace. Everything that is a pure function of the request uses it.
- **Signature check needs Kyverno.** CEL cannot reach a registry or the transparency log. Kyverno runs **one** `verifyImages` rule and nothing else (no mutation, no generate). `failurePolicy: Fail`: if Kyverno is down, pods are refused. Alternative with a smaller surface: the Sigstore policy-controller (`ClusterImagePolicy`); switch if the operators prefer it, the rule is the same identity.

**Limit, stated plainly.** Admission is not a defence against a cluster-admin: that person can delete a policy or a binding. These rules stop mistakes, lesser identities and stray tooling, and they make a deliberate bypass a visible, audited act (the API-server audit log is shipped to the audit account). What a cluster-admin cannot reach is the *other* checker's copy (the gateway, cosigner B and cosigner C each live in their own cluster).

## Signatures and how images are signed

`.github/workflows/images.yml` signs every pushed digest keyless (GitHub OIDC, `cosign sign`) in the manual publish job. The policy therefore checks an identity, not a key: issuer `https://token.actions.githubusercontent.com`, subject `…/.github/workflows/images.yml@refs/heads/main` (`signature.keyless.*`). The default subject is derived from the workflow file; **confirm it against the first real signature** before the first production install:

```bash
cosign verify ghcr.io/<owner>/quorum-vault/qv-core@sha256:<digest> \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '<signature.keyless.subjectRegExp>'
```

If the images are signed with a key you hold, use `signature.mode: key` and `signature.key.publicKey`. Production refuses to render with `signature.enabled: false`.

## Install

One release per cluster, by that cluster's operators, before any application chart:

```bash
helm upgrade --install qv-policy deploy/policy/qv-policy -n kube-system \
  --set clusterKind=signing-core --set 'namespaces={qvs}' \
  --set registry=ghcr.io/<owner>/quorum-vault \
  --set 'configWriters.users={system:serviceaccount:flux-system:kustomize-controller}'
```

Prerequisites: Kubernetes 1.30 or later (ValidatingAdmissionPolicy is GA); Kyverno 1.13 or later (admission controller only) in production; namespaces that already exist keep their workloads, Helm only adds the labels (`helm.sh/resource-policy: keep`: uninstall never deletes a namespace). The kind values (`values-kind.yaml`) are the whole difference for a local cluster: tags allowed, signatures off, registry `qv-image`, no writer list. Anything else the rules refuse in kind is a real finding.

## Tests (no cluster)

`ci/helm/policy-check.sh` (part of `make helm-check` and the helm workflow): lint, render each kind in production and kind mode, validate against the Kubernetes and Kyverno CRD schemas, then `ci/helm/qvpolicy`:

- the rendered policies are evaluated with CEL (`cel-go`, pinned) and Pod Security `restricted` with the API server's own checks (`pod-security-admission`, pinned);
- **the real production renders of `qv-business`, `qv-signing-core` and `qv-party` (A, B, C, plus a private LoadBalancer) must pass every rule**, so drift in a chart fails here;
- one manifest per rule must be denied, with the message checked, and the run fails if a rule has no denied example;
- the kind renders pass the kind policies and are refused by the production policies;
- the chart refuses wrong values; RBAC has no Secrets, no wildcard, no ClusterRoleBinding, break-glass bound to nobody by default.

Not reproduced offline: the API server's type checking of the expressions, the CEL cost limit, and the cosign verification itself (needs the registry; Kyverno's offline CLI cannot verify signatures). The kind lane covers these.

## Live tests for the kind lane

Run in a kind cluster with this chart in kind mode plus a **production-mode copy of the rules in a second namespace** where a case needs them, plus Kyverno with a local registry and a test key (`signature.mode: key`):

1. Every policy is Ready: `kubectl get validatingadmissionpolicy` shows no `status.typeChecking.expressionWarnings`, and the bindings exist.
2. Unsigned image refused: pod with an image signed by nobody (production mode, key mode with a test key) is denied by `qv-verify-images`; a pod with the signed image is admitted.
3. Tag instead of digest refused; image from another registry refused.
4. ConfigMap edit refused: as a user not in `configWriters`, `kubectl edit` and `delete` of a chart ConfigMap are denied; a mutable ConfigMap is refused on create.
5. `kubectl exec`, `kubectl debug` (ephemeral container) and `port-forward` into the gateway and party pods are refused for a user outside the break-glass group, and allowed for a member.
6. A NodePort Service and a public LoadBalancer Service are refused; the party's private LoadBalancer is admitted.
7. An Ingress is refused in the signing-core namespace.
8. A pod with `hostNetwork`, `hostPath`, `privileged` or an added capability is refused; a pod with an automounted ServiceAccount token is refused.
9. With the application charts installed in production mode (made-up digests do not matter for the policies, signatures do): every pod starts.
10. CEL cost: no policy is rejected with "estimated cost exceeds budget" at creation.

## Known gaps

- **`qv-business` ConfigMaps are not immutable** (`qv-core-env`, `qv-worker-env`, …, no hash in the name). The business cluster therefore runs without the immutable-ConfigMap rules. Fixing it is a chart change (kind-lane hand).
- Admission cannot see the contents of a ConfigMap a pod mounts, only its name; the hash-in-name rule plus "every ConfigMap in the namespace is immutable" closes that for ConfigMaps created after the policy exists. Create the policy before the first application release.
- `kubectl debug node/…` and any pod in a namespace this chart does not label are outside these rules. That is RBAC and cloud IAM (see `docs/runbooks/break-glass.md`).
- `exec` is checked by group membership only; admission does not know about the second approver. The two-person step is in IAM.

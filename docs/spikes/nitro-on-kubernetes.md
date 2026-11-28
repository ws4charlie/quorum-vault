# Nitro enclaves and the Kubernetes charts: options

Written 2026-11-20 for task T7-prep. Nothing here has run: there is no AWS account. Sources are AWS pages read on that date (named in the text); what they do not say is marked **unverified**.

## The problem

A Nitro enclave is not a container. `nitro-cli run-enclave` on an EC2 host starts a small virtual machine from an enclave image file (EIF), takes CPUs and memory away from the host, and gives it no network and no disk: its only link is vsock to the parent instance (AWS "Nitro Enclaves concepts"). Up to four enclaves run per parent, enclaves cannot talk to each other, and they die when the parent stops ("Nitro Enclaves considerations"). A pod can start one only if it can reach the host's enclave device, and the party's chart (`deploy/helm/qv-party`) assumes a process that has a network, a data directory and a mounted config. Three things must therefore exist outside the enclave on the parent: a **launcher** (nitro-cli), a **network bridge** (TCP in, vsock to the enclave; vsock out to KMS), and a **blob store** (the enclave has no disk, so the sealed shares live on the parent and travel over vsock).

What the host can and cannot do with these: it sees every byte that crosses vsock except what the enclave encrypts. TLS to KMS ends inside the enclave; the party's mutual TLS to peers and the gateway ends inside the enclave; the blob store holds only ciphertext (shares sealed under keys the host never gets). The host can stop, delay or drop traffic and roll the blob store back (denial of service and the rollback case already in `docs/limits.md`), and it can start an enclave from another image, which then fails the KMS key policy (different PCRs).

## The options

| | A. Device plugin and one privileged pod that launches and serves | B. A launcher DaemonSet on enclave nodes and a proxy pod per party | C. Parties on plain EC2 outside Kubernetes (first run) |
|---|---|---|---|
| Shape | The party's StatefulSet pod gets `aws.ec2.nitro/nitro_enclaves: 1`, runs nitro-cli, the bridge and the blob store in one pod | A DaemonSet on a tainted node pool runs nitro-cli and the vsock-proxy for that node; the party's StatefulSet pod becomes the proxy: TCP listeners, blob store on its PVC, metrics relay | An instance per party from the launch template (`modules/nitro-enclave`), systemd units: allocator, vsock-proxy, bridge, blob store, `nitro-cli run-enclave` |
| Uses | AWS's Kubernetes device plugin (`aws-nitro-enclaves-k8s-device-plugin`) and its tutorial for EKS ("Using Nitro Enclaves with Amazon EKS") | the same plugin, but the privileged part is one small, reviewed DaemonSet | nothing of Kubernetes |
| Privilege | The party pod is privileged, in the namespace that holds the party's PIN-free secrets and its TLS key files | Only the launcher is privileged; the proxy pod stays under Pod Security `restricted` | An instance role and an operator with SSH or SSM |
| Party chart changes | Large (below) | Large, but the app pod keeps its shape | None |
| Policy chart (#119) changes | `qv-pods` and Pod Security must allow a privileged party pod in a signing namespace: the opposite of what the chart enforces | A narrow exception for one named DaemonSet in one namespace, by digest; everything else stays | None; the cluster does not see the party |
| Cost | One node pool of enclave hosts, sized for parent plus enclave | The same, plus a second pod per party | An instance per party, outside the cluster's monitoring, policies and GitOps |
| Breaks | The AWS page warns that every pod on a node with the plugin can reach the enclave over vsock; here the party pod and the enclave share a trust boundary the chart wanted to keep apart | The same warning applies to the node: only proxy pods and the launcher may run on enclave nodes (taint, node selector, admission rule), and the enclave's own pinned mutual TLS stops anyone else from calling it | The first run is not Kubernetes: Prometheus, NetworkPolicies, the `qv-policy` rules, image signature checks and GitOps do not apply to it |
| First run | Slower to debug: a problem could be Kubernetes, the plugin, the bridge or the enclave | Same | Fastest: one machine, one terminal, a problem is the enclave or it is not |

## Recommendation

**C for the first run, B for production, A not at all.**

- C isolates the questions the first day exists to answer (does the document verify, does KMS accept the PCRs, how long does a start take) from Kubernetes questions, and needs no chart change.
- B keeps what the charts already enforce (default-deny network policies, restricted pods, signed images, immutable ConfigMaps) for everything but one small launcher, and keeps the party's pod count, names and PVC. A puts launcher, bridge, blob store and the TLS key files into one privileged pod.
- The checklist (`docs/runbooks/nitro-first-run.md`) is written for C. Steps that are the same under B say so.

## What changes in the charts (listed, not done)

Party chart (`deploy/helm/qv-party`, #111, #136), for B:
1. Values: `enclave.enabled`, the EIF and its PCRs (as data the launcher reads: a ConfigMap or an OCI artifact, never a rebuilt image), `enclave.cpuCount`, `enclave.memoryMiB`, vsock ports, the KMS key id, region and the proxy port; `attested.release.type: kms` beside the broker mode.
2. A `qv-enclave-launcher` DaemonSet: image with nitro-cli and the EIF pulled by digest, `aws.ec2.nitro/nitro_enclaves` limit, node selector and toleration for the enclave pool, the per-node vsock-proxy (allowlist: the KMS endpoint of the region only), the credential forwarder to the instance metadata service on a vsock port. Privileged; its own namespace or a labelled one.
3. The StatefulSet becomes the proxy: no SoftHSM init container, no HSM PIN secret, no `party.json` mount (the configuration is inside the EIF; `configmaps.yaml` becomes the source for `eif-build.sh --config-dir`, so a configuration change is a new EIF and a new allowlist entry); containers: the bridge (TCP listener to the enclave's vsock port, both directions), the blob store on the PVC, a metrics and log relay. Probes ask the bridge, which asks the enclave over vsock.
4. Config in the enclave: `sealer.type: attested`, `sealer.attester.type: nitro`, `sealer.release.type: kms` (flags that exist since this task).
5. Network policies: unchanged for TCP (the proxy pod is where the traffic arrives); add egress for the launcher to the ECR endpoint and to nothing else; no policy can describe vsock, so the node pool rule above is the control.
6. The attested-jobs (`attested-jobs.yaml`, migrate-seal) assume the broker; the KMS mode needs its own migration notes (docs/runbooks/tee-broker.md covers the broker only).

Policy chart (`deploy/policy/qv-policy`, #119):
1. Pod Security `restricted` on the signing namespaces refuses the privileged launcher: put the launcher in its own namespace with `privileged` enforcement and nothing else in it.
2. `qv-pods`: an exception for exactly that DaemonSet by name, namespace and digest; a new rule that no other pod may request `aws.ec2.nitro/nitro_enclaves` or tolerate the enclave pool's taint.
3. `qv-no-exec` stays as it is, and matters more: a shell in the launcher pod is a shell on the parent.
4. `qv-verify-images`: the launcher image is signed like the rest; the EIF is not an image: its PCRs are what the key policy checks, so no signature rule applies.

Not a chart change but needed before B works, and not written yet (see "What is still missing" in the runbook): the enclave-side bridge, a blob-store backend for the party's stores (the party already hides its storage behind `KeyStore`, `JobStore` and `FreezeStore`), and a way for the cosigner's unix-socket channel to reach a party in an enclave.

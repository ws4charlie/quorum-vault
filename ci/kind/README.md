# The kind lane

A local Kubernetes cluster (kind) that installs the **real charts** (`deploy/helm/*`, with their `values-kind.yaml`) and runs a small smoke set against them. It is separate from the compose e2e groups, which stay as they are. The production shape is Kubernetes; this lane exists so that test and production differ in configuration only.

```bash
make kind-up      # cluster + dependencies + charts (builds missing images first)
make kind-smoke   # the smoke set
make kind-down    # removes this checkout's cluster and generated files
```

Prerequisites: `docker`, `kind`, `kubectl`, `helm`, `openssl`, `jq`, `go` (and `psql` for one role check). The cluster is named per checkout (`qv-kind-<hash of the path>`, override with `QV_KIND_NAME`), so two checkouts and the compose e2e never collide.

## What it installs

| Piece | How |
|---|---|
| Cluster | one kind node, image pinned by digest (`versions.env`, `kind.yaml`). Default CNI (kindnet): **it enforces NetworkPolicy** (ingress and egress, verified with a control pair, `smoke/netpol.sh`), so no second CNI is needed |
| Namespaces | `qv` (business), `qv-signing` (gateway, party A), `qv-party-b`, `qv-party-c`. **Isolation between domains is NetworkPolicy-level only here**: one cluster, one control plane, one node. It does not show what four separate clusters give |
| cert-manager, CloudNativePG | Helm, chart versions pinned |
| Postgres | CloudNativePG, one instance per database, the same `pg_hba`/`pg_ident` files as compose, TLS 1.3 and client certificates only |
| Redpanda, Temporal + name gate, Keycloak (dev realm), SeaweedFS (Object Lock), anvil, bitcoind (regtest) | plain manifests in `deps/`, the same flags and scripts as compose, images by digest |
| Certificates | `qv-certs` once per namespace (`issuers.ca.existing`: every namespace issues under the same two authorities, which `up.sh` generates with openssl into the gitignored work dir) |
| Business chart | `qv-business` (EVM custody config; the Bitcoin one is switched in by the `withdraw` case) |
| Signing zone | `qv-party` ×3 (A in `qv-signing`, B and C in their namespaces, SoftHSM shares), `qv-signing-core` (the gateway, no HSM: every signer is an MPC signer) |
| Keys and configs | `dkg.sh`: an ECDSA 2-of-3 keyset `hot-0` (the EVM hot key) and an HD keyset `btc-0` (the Bitcoin account), made through party A's caller port by `tools/kindctl` with a generated admin key. `signing.sh`: deploys the deposit factory on anvil, then `tools/kindcfg` writes the signing config (auto approver, both hot keys, the parties' addresses and pins), the cosigners' copy, and the two custody configs. Every file is parsed by the services' own parsers before it is used |

Images: third-party ones are pulled **by digest** and loaded into the node; the service images are built from the checkout (`deploy/images/build.sh`) and loaded. The cluster pulls nothing itself. Everything generated (CAs, passwords, keys) is in `ci/kind/.work/<name>/`, gitignored; nothing secret is in the repository.

Solana is **not** in the kind lane (the validator image is 778 MB and not needed for install-to-ready); it stays covered by compose.

## Smoke cases

`make kind-smoke` runs, in this order (`ci/kind/smoke/run.sh [case ...]`):

| Case | What it shows |
|---|---|
| `install` | every pod ready, the migration hook ran, roles log in with their certificates |
| `netpol` | an unlisted pod cannot reach Postgres, a listed one can; business pods cannot reach the signing zone except where the charts say; the gateway pod cannot reach the internet |
| `withdraw` | an EVM and a Bitcoin withdrawal through the real pods: Keycloak token, deposit on the local chain, request, auto approval, signing by the gateway with parties A and B (cosigner B authorises), broadcast, confirmation, **exactly one payout** of the amount, Reconcile clean. The EVM deposit is swept by the pods too |
| `crash` | party A deleted while the sign job is in flight, the worker deleted right after the job exists, the gateway rolled while signing: each withdrawal still pays once and Reconcile stays clean |
| `upgrade` | a no-change `helm upgrade` replaces no pod; a changed value rolls the pods that read it and core stays available (a prober dials it twice a second: no refused connection) |
| `admission` | the cluster policies (`deploy/policy/qv-policy`, installed by `policy.sh` in kind mode for the namespace `qv-ptest` only) are live: every policy has its binding and no type-checking warning; each denied example is refused by the real API server **with the policy's own message** (foreign registry, hostNetwork, hostPath, privileged, added capability, root, escalation, automounted token, mutable ConfigMap, NodePort, public LoadBalancer, externalIPs, Ingress; Pod Security `restricted` in `qv-ptest`), the controls are admitted (conforming pod, immutable ConfigMap, private LoadBalancer), and exec, port-forward and debug into a pod are refused outside the break-glass group and, for a member, reach the pod (the runtime answers the exec, the forward is ready, the ephemeral container is added). The helpers can fail: a negative control passes an admitted manifest to `deny` and requires it to register a failure (checked: a denied example made admissible turns the case red) |
| `certs` | rotation without restart: the core's certificate Secret is deleted, cert-manager issues a new one, and the same pod (same uid, no restart) serves it about a minute later, trusted by the authority; an expired certificate refuses start: the core's own pod template with a certificate that expired two days ago (made by `tools/kindcert` from the lane's authority) exits with the service's expiry message |
| `teesim` | **simulated enclave**; run last because it replaces the three parties (new keys). A broker per party in its own namespace (chart `qv-attest-broker`), the parties in attested mode with sealed TLS keys and no HSM, the enrolment Jobs, signed allowlists made by the lane, a DKG through party A, and a restarted party that attests again. Not shown: a signature (the gateway's config would need the new pins), isolation (the evidence is a mock) |

`smoke/run.sh --pending` lists what is not done. `withdraw` and `crash` drive the pods from the host through port-forwards (`tools/kindwd`); the person tokens come from the dev realm's test-only login (`qv-e2e`, as `e2e/idp`), passwords from the gitignored work dir. kind's qv-core runs `QV_ENV=dev` (`core.env: dev` in `deploy/helm/qv-business/values-kind.yaml`) because the smoke logs in with the dev realm's e2e clients, which a production core refuses; TLS stays on everywhere (`QV_ALLOW_PLAINTEXT` is not set).

## Trust bundles

The charts take the CA file of their certificate volumes from the `qv-certs` trust bundle (`qv-trust-<zone>-<hash>`, an immutable ConfigMap) and not from the `ca.crt` cert-manager puts into each Secret: a projected volume (`tls.crt` and `tls.key` from the Secret, `ca.crt` from the bundle). `tls.trust.<zone>` names the bundle in each chart; the lane finds the names with `trust_args` in `lib.sh`. Empty, the charts behave as before.

## Measured here (a Mac, Docker VM 24 GiB, images cached)

| | |
|---|---|
| `make kind-up`, cold (cluster, dependencies, three parties, DKGs, both charts) | 236 s |
| `make kind-smoke` (all five cases) | 225 s |
| Node memory with everything running | 3.9 GiB |

CI prints the same numbers for the runner (`.github/workflows/kind.yml`).

## What is not done

Nothing pending in the lane's own cases. Admission: only the rules that kind mode keeps are live-tested. The production-only rules (digest, the cosign signature check by Kyverno, development switches in a pod or ConfigMap, the ConfigMap writer list) need production mode, which needs Kyverno and a signed test image: later. The policy is installed for one namespace of its own, not for the lane's namespaces: the lane port-forwards into the signing namespaces, which the exec rule refuses outside the break-glass group. `tools/kindctl` makes the DKG calls (`qv-party-admin` needs a signed file per call and one connection per party; the lane has one port-forward and reads the public keys back in the same tool).

## What it cannot show

One cluster, simulated HSM (SoftHSM on a volume, `QV_ENV=dev`), no cloud, no real network between domains, no Vault. Tee-sim uses a mock enclave evidence.

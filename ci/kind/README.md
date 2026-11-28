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

Images: third-party ones are pulled **by digest** and loaded into the node; the service images are built from the checkout (`deploy/images/build.sh`) and loaded. The cluster pulls nothing itself. A pull is tried 4 times (10, 20, 40 s apart). `check-pins.sh` (run by the helm workflow on every change under `ci/kind/`) fails when a lane file names an image that is not pinned in `versions.env`, not built by the lane and not exempt, or when a pin is unused. Everything generated (CAs, passwords, keys) is in `ci/kind/.work/<name>/`, gitignored; nothing secret is in the repository.

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
| `gate` | AgentGate onboarding (below): `gate.sh` with a Gate key made at test time; a pod in namespace `agentgate` with **only the output files** (and Gate's own key) mounted gets a token by client credentials, calls `/v2/gate/signatures` for a 0.01 USDC EIP-3009 payment (200), checks the signature against the token's EIP-712 domain and `wallet_address`, and submits `transferWithAuthorization` to anvil (it mines and pays). A second `gate.sh` changes nothing (same files, no pod replaced, same setting version; the funding tops up only what was paid). Reconcile is clean. From `agentgate` the business database is refused, from another namespace the core's port is refused. The same call without Gate's client certificate, and one without a credential, are refused. An ETH withdrawal (the `withdraw` helper) still pays from shard 0, and Gate's shard 1 has sent nothing. Runs in any order and again on the same cluster: Gate has its own hot shard |
| `teesim` | **simulated enclave**; run last because it replaces the three parties (new keys). A broker per party in its own namespace (chart `qv-attest-broker`), the parties in attested mode with sealed TLS keys and no HSM, the enrolment Jobs, signed allowlists made by the lane, a DKG through party A, and a restarted party that attests again. Not shown: a signature (the gateway's config would need the new pins), isolation (the evidence is a mock) |

`smoke/run.sh --pending` lists what is not done. Each case's output also goes to `QV_KIND_SMOKE_LOGS` (default `.work/<name>/smoke-logs/<case>.log`), and the full output of every failed case is printed again at the end; CI uploads these logs and `up`'s as the artifact `kind-logs` on failure. `withdraw` and `crash` drive the pods from the host through port-forwards (`tools/kindwd`); the person tokens come from the dev realm's test-only login (`qv-e2e`, as `e2e/idp`), passwords from the gitignored work dir. kind's qv-core runs `QV_ENV=dev` (`core.env: dev` in `deploy/helm/qv-business/values-kind.yaml`) because the smoke logs in with the dev realm's e2e clients, which a production core refuses; TLS stays on everywhere (`QV_ALLOW_PLAINTEXT` is not set).

## AgentGate onboarding

One idempotent command, after `make kind-up`, connects an AgentGate to this cluster and writes what it needs into a directory:

```bash
make kind-gate PUBKEY=gate.pub KID=gate-1 FUND=1000000 OUT=/abs/out    # NAMESPACE=agentgate by default
"$QV_REPO/ci/kind/gate.sh" --pubkey gate.pub --kid gate-1 --namespace agentgate --fund 1000000 --out out   # from another repository
```

| Input | Meaning |
|---|---|
| `--pubkey` | Gate's Ed25519 public key: base64url (as `agentgate` keygen prints it), base64, hex or PEM |
| `--kid` | its key id in the gate setting |
| `--namespace` | where Gate runs; only this namespace gets the network access below (default `agentgate`) |
| `--fund` | USDC base units the Gate wallet holds afterwards (a top-up, not an addition) |
| `--out` | the output directory. Relative paths are read against the caller's directory (with `make -C`, give absolute ones). `QV_KIND_NAME` picks the cluster |

It writes one file per value (the PHASE2 onboarding contract); Gate maps them 1:1 to its `AG_VAULT_*` and `AG_RPC_URL` settings:

| File | Value here |
|---|---|
| `vault_url` | `https://qv-core.qv.svc:8443` (a Service named as the core's server certificate is) |
| `ca.crt`, `token_ca.crt` | the business CA (it signs the core's and Keycloak's server certificates) |
| `tls.crt`, `tls.key` | Gate's client certificate `spiffe://quorumvault/business/agentgate` (Secret `qv-agentgate-tls`) |
| `token_url` | `https://keycloak.qv.svc:8443/realms/quorumvault/protocol/openid-connect/token` |
| `client_id`, `client_secret` | the Keycloak client `agentgate` (client credentials only, realm role `gate` and no other); the secret is written here and nowhere else |
| `audience` | `qv-kind`: the credential audience, the same in the core's gate section and the signed gate setting |
| `wallet_id`, `wallet_address` | the Gate-governed wallet (made once) and its address: Gate's own EVM hot shard 1, an MPC 2-of-3 keyset `hot-1` that `gate.sh` makes |
| `chain_id`, `rpc_url`, `usdc_address` | the lane's chain id (`lib.sh`, Base Sepolia's), `http://anvil.qv.svc:8545`, the mock USDC with EIP-3009 (EIP-712 name `USDC`, version `2`, 6 decimals) |

What it changes, all from the gitignored work dir (`.work/<name>/gate/`): a DKG of keyset `hot-1` on the three parties (once) for Gate's hot shard 1; the mock USDC is deployed once (reused while anvil has it) and minted up to `--fund`, each mint booked as the operator's seed; the gateway's and both cosigners' configs get shard 1, USDC with x402 on it and two zone operators (keys made once); the gate setting (Gate's key, the wallet, fast lane 0.05 USDC per payment, 0.50 USDC per hour, 1 USDC per day) is signed by both operators and applied to the three guard databases with `qv-approvers`; Keycloak gets the role and the client; `qv-business` gets the gate section in the custody config and `agentgate.enabled`, `oidc.serviceClients=agentgate` from an overlay values file in the work dir (`values-business-gate.yaml`; `lib.sh` `biz_values` gives every later upgrade of the chart, such as the `upgrade` case's, the same values; `values-kind.yaml` is unchanged, so a plain `kind-up` stays as it was); NetworkPolicies let `--namespace` reach the core's 8443, Keycloak's 8443 and anvil's 8545, nothing else. A second run changes nothing: no second client, wallet, keyset or token, no new setting version, no pod replaced. Runs are serialised by a lock dir; a run killed halfway is finished by the next one (the core is restarted until a restart with the current config has completed).

Gate governs its whole shard (every asset), so it has its own: Vault's shard 0 keeps paying Vault's withdrawals (a withdrawal takes the shard with the most free balance of its asset, the first on a tie; nothing books ETH on shard 1) and receives the sweeps (`sweep_destination`). One gap the config cannot close: a Vault **USDC** withdrawal would pick shard 1 while it holds the most USDC, and the zone refuses it (the lane has no Vault USDC flow). `make kind-up` again puts the lane's own configs back on the zone; run `kind-gate` again after it.

## Keep mode (Gate's key survives kind-down)

Opt-in: `make kind-gate ... KEEP=1` (or `QV_KIND_KEEP_GATE=1` in the environment; `make kind-smoke KEEP=1` passes it to the `gate` case). Gate's keyset `hot-1`, and so `wallet_address` and `wallet_id`, then stays the same across `make kind-down` / `make kind-up`, so a testnet address funded once keeps its funds. Without it nothing changes.

| Step | What happens |
|---|---|
| First `kind-gate` in keep mode | after the DKG each party exports its own encrypted share of `hot-1` inside its pod (`mpc-party backup export`, under a recovery key made once); the keep dir gets the three backups, the recovery key pair, `hot-1.json` (public) and `wallet_id` |
| `kind-down` | removes the cluster and `.work`; the keep dir stays (it says so) |
| `kind-up`, then `kind-gate` in keep mode | party A has no `hot-1`, so instead of a DKG each party restores its share (`mpc-party backup restore -no-records`: the lane never changes its admin set or recovery-key registry), the three parties restart, reconcile and prove the keyset, and party A's keyset status (read only, `kindctl status`) must give the kept address, or `kind-gate` fails. The rest of `kind-gate` runs as usual (token, zone, books, Keycloak) |
| Again on the same cluster | nothing restored or exported; the address is checked against the keep dir |
| `make kind-gate-forget` | deletes the keep dir (asks first unless `YES=1`; removes only a dir with the lane's mark). The next `kind-gate` makes a new key and address |

The keep dir is `~/.qv-kind-keep/<cluster name>/` (`QV_KIND_KEEP_DIR` wins; `lib.sh` `keep_dir` refuses a path inside the repository), mode 0700, files 0600, with a `README`. It is **testnet-only key material**: the three backups plus `recovery.private` are the whole signing key. Nothing prints it. The cluster name comes from the checkout's path (`QV_KIND_NAME`), so the keep dir belongs to one checkout unless the name is set. A cluster whose parties already hold a different `hot-1` (for example `kind-gate` ran there without keep mode) is refused with the two addresses: `kind-down` and `kind-up`, or `kind-gate-forget`. Only `hot-1` is kept: `hot-0`, `btc-0` and everything else are new on every `kind-up`. `teesim` replaces the parties, so keep mode on that cluster ends with it (the keep dir is untouched). `ci/kind/keep_test.sh` tests the keep dir and forget guards without a cluster; CI runs it, and the `gate` case once in keep mode (the save path). The restore needs a second `kind-up` (about 3 minutes more) and is shown locally (KS1a report), not in CI.

## Trust bundles

The charts take the CA file of their certificate volumes from the `qv-certs` trust bundle (`qv-trust-<zone>-<hash>`, an immutable ConfigMap) and not from the `ca.crt` cert-manager puts into each Secret: a projected volume (`tls.crt` and `tls.key` from the Secret, `ca.crt` from the bundle). `tls.trust.<zone>` names the bundle in each chart; the lane finds the names with `trust_args` in `lib.sh`. Empty, the charts behave as before.

## Measured here (a Mac, Docker VM 24 GiB, images cached)

| | |
|---|---|
| `make kind-up`, cold (cluster, dependencies, three parties, DKGs, both charts; service images already built) | 182–188 s (2026-11-28) |
| `make kind-gate`, first run (DKG of `hot-1`, token, zone and core configs, setting, Keycloak) / again with no change | 38 s / about 12 s |
| `make kind-smoke`, all nine cases (install 1, netpol 111, withdraw 36, crash 50, upgrade 67, admission 4, certs 117, gate 75, teesim 80 s) | about 540 s |
| Node memory with everything running | 3.9 GiB (measured before the gate case; not measured again) |

CI prints the same numbers for the runner (`.github/workflows/kind.yml`).

## What is not done

Nothing pending in the lane's own cases. Admission: only the rules that kind mode keeps are live-tested. The production-only rules (digest, the cosign signature check by Kyverno, development switches in a pod or ConfigMap, the ConfigMap writer list) need production mode, which needs Kyverno and a signed test image: later. The policy is installed for one namespace of its own, not for the lane's namespaces: the lane port-forwards into the signing namespaces, which the exec rule refuses outside the break-glass group. `tools/kindctl` makes the DKG calls (`qv-party-admin` needs a signed file per call and one connection per party; the lane has one port-forward and reads the public keys back in the same tool).

## What it cannot show

One cluster, simulated HSM (SoftHSM on a volume, `QV_ENV=dev`), no cloud, no real network between domains, no Vault. Tee-sim uses a mock enclave evidence.

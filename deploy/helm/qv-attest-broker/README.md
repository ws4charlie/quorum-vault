# qv-attest-broker

The attestation release broker of **one MPC party**: it checks the party's attestation against a signed allowlist and releases that party's sealing key (`docs/runbooks/tee-broker.md`, "On Kubernetes"). **The enclave is simulated** (task T4); the chart is checked by tests, no cluster has run it.

## Where it runs
Its own trust zone: a cluster that neither this party's operators nor the business zone administer. **One release per party** (the chart lists exactly one party): a broker for all three would let one administrator release every key. It reaches DNS and its HSM and nothing else; only this party's pods reach it, on the mutual-TLS port.

## What a release holds
| Object | What |
|---|---|
| StatefulSet, 1 replica (the schema refuses more) | the broker; the old pod stops before the new one starts (single writer: nonces in memory, one audit chain) |
| ConfigMap `config-<hash>`, `allowlist-<hash>` | immutable; the allowlist is the signed JSON as you pass it, mounted as one file |
| Service | the mutual-TLS port only; `ClusterIP`, or a private `LoadBalancer` (annotations and source ranges required) |
| NetworkPolicies | default deny; DNS; ingress from `network.partyIngress.from` on the mutual-TLS port; optional scraper on the health port; HSM egress only if you name it |
| PodDisruptionBudget | `maxUnavailable: 0`: a drain waits for you |
| volume `data` (ReadWriteOncePod) | the audit log (and, in development, the SoftHSM token) |

## Values you must set
`party.role`, `party.callerPins` (pins of the party's broker-link certificate), `images.broker.digest`, `operators.keys` and `minOperators`, `trustRoots.configMap` (public PEM; an immutable ConfigMap named with a 10-hex hash of the file), `allowlist.file` (`--set-file allowlist.file=allowlist.json`), `hsm.module.path` and `hsm.module.volume`, `network.partyIngress.from`. Secrets you create: the HSM PIN (`hsm.pinSecret`, key `pin`), and from `qv-certs` the broker's certificate `qv-attest-broker-<role>-tls` (tls.crt, tls.key; the party pins its public key).

## Rules the chart enforces
- Image by digest (the all-zero placeholder is refused); `env` empty in production. `env: dev|test` needs an image by tag.
- SoftHSM (`hsm.softhsm.enabled`) and `simulation: true` (the tee-sim image, which accepts a TEST ONLY evidence root) only with `env` dev or test and an image by tag. Neither can be rendered with production values.
- No PIN or key in a ConfigMap or environment variable.
- The PIN path: production mounts the Secret at `/etc/qv/hsm-pin/pin`. **The broker refuses a PIN file with a group bit and kubelet adds one under `fsGroup`**, so this needs `ReadPIN` to accept 0440 (as the gateway does; the broker's owner, T6). Development stages a 0400 copy with an init container.

## Operating
- **Allowlist change:** a new `allowlist.file` is a new ConfigMap and a rollout (about a minute without a broker; running parties keep signing). Whoever can upgrade the release can install an older signed list: signatures stop forgery, not rollback.
- **Drain a node:** check no party is restarting or in a DKG, then delete the pod yourself.
- **Lost volume / HSM:** see the runbook ("Key storage").
- Metrics (`/metrics`) are on the health port, plain http, not published by the Service; `network.metricsIngress.from` names a scraper (policy purpose `metrics-scrape`).

## Check
`ci/helm/broker-check.sh` (lint, render production and kind values, kubeconform) and the Go tests in `ci/helm` (`broker_test.go`, `qvpolicy/broker_test.go`); `make helm-check` runs both. `values-kind.yaml` is the tee-sim development values (image `qv-image/qv-attest-broker-teesim`, built with `deploy/images/build.sh qv-attest-broker-teesim`).

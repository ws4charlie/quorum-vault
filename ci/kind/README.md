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
| Business chart | `qv-business` |

Images: third-party ones are pulled **by digest** and loaded into the node; the service images are built from the checkout (`deploy/images/build.sh`) and loaded. The cluster pulls nothing itself. Everything generated (CAs, passwords, keys) is in `ci/kind/.work/<name>/`, gitignored; nothing secret is in the repository.

Solana is **not** in the kind lane (the validator image is 778 MB and not needed for install-to-ready); it stays covered by compose.

## Status (this is the first of three stacked pieces)

Done: cluster, dependencies, certificates, `qv-business` installed and ready (migration hook, role login, health-listener probes, archiver with its Object Lock bucket), smoke cases `install`, `netpol` (business part), `upgrade`.

Not done yet (listed by `ci/kind/smoke/run.sh --pending`): `qv-signing-core` and the three `qv-party` releases, the DKG they need, the EVM and Bitcoin withdrawals, the pod-kill cases, the trust-bundle switch (charts still mount the Secret's `ca.crt`), and the CI workflow's nightly part.

## What it cannot show

One cluster, simulated HSM (SoftHSM on a volume, `QV_ENV=dev`), no cloud, no real network between domains, no Vault. Certificate rotation, admission policies and tee-sim are later, marked as pending, not half-tested.

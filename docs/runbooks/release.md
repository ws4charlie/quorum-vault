# Runbook: releasing the container images (manual)

QuorumVault ships as container images, one per binary (`deploy/images/README.md`). Releases are **manual**: a person tags, starts the workflow and checks the result. The images are **public** on `ghcr.io/ws4charlie/quorum-vault/<name>` (12 packages, listed in `deploy/images/images.sh`). Nothing here runs by itself and no pull request can publish.

## The rules

- **Version.** Tags are `vMAJOR.MINOR.PATCH`, created on `main` only (no leading zeros). A release candidate is `vMAJOR.MINOR.PATCH-rc.N` (N from 1), also on `main`, for staging: `deploy/images/manifest-values.py` refuses it unless `--allow-rc`. MAJOR: a change that needs a coordinated rollout (image contract, a migration the previous release cannot run on). MINOR: features, backward-compatible migrations. PATCH: fixes only.
- **Images** are tagged with the version **and** always referenced by digest (`repository@sha256:…`) in charts and policies. There is no `latest`. A published version is never overwritten: `publish.sh` refuses a tag that already exists, so a fix is a new patch version.
- **Only production images** are released. The `-dev` images (SoftHSM) and the simulated-enclave build are never published, under any name: the release set is `qv_release_images` in `images.sh`, `publish.sh` refuses a `-dev` or tee-sim name, and the manifest check fails on one.
- **The workflow refuses anything else.** `release-gate.sh` (the `gate` job) accepts only a tag with a valid name whose commit is contained in `origin/main` and has a successful `ci` push run on `main` for exactly that commit. It reads GitHub's run list with a read-only token (`actions: read`).
- **Signature.** Cosign keyless, GitHub OIDC. A verifier must expect exactly:
  - issuer `https://token.actions.githubusercontent.com`
  - identity `https://github.com/ws4charlie/quorum-vault/.github/workflows/images.yml@refs/tags/vX.Y.Z` (for a policy: the regular expression `^https://github\.com/ws4charlie/quorum-vault/\.github/workflows/images\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$`, which leaves release candidates out)

  The signature covers the image index, which holds the image, its SBOM (SPDX) and its provenance (SLSA, `mode=max`). The manifest is signed the same way (`release-<version>.json.sigstore.json`).

Restrict who can create `v*` tags: a repository ruleset on `v*` tags (create only by maintainers) and, in Settings → Environments, required reviewers on the `release` environment the publish job uses.

## Before

1. `main` is green: the `ci` workflow passed on the commit you will tag (`gh run list --workflow ci.yml --branch main --commit <sha>`). The gate checks this again.
2. Changelog since the last tag: `git log --oneline vPREV..<sha>`; write the release notes from it.
3. Migrations are **backward compatible with the previous release**: `git diff vPREV..<sha> --stat -- migrations/ mpc-party/`. The previous release's binaries must run on the new schema (expand now, contract in a later release), because rollback restores old binaries, never the schema (see Rollback). A migration that breaks the previous release is split over two releases.
4. Which charts changed: `git diff vPREV..<sha> --stat -- deploy/helm/`. Each changed chart gets its own rollout (see After).
5. The party image changes the TEE measurement: if `mpc-party` or its inputs changed, the new measurement must be on the attestation allowlist **before** the new party image runs (`tee-broker.md`, "Change the allowlist"). Plan the overlap.
6. Dry run on a branch: `gh workflow run images.yml --ref <branch> -f publish=false` (every pull request already runs it). It builds the release images, runs the smoke test and the secret check, computes the digests and writes a manifest, and pushes and signs nothing.

## Release

1. Tag the commit and push the tag: `git tag -a vX.Y.Z <sha> -m "QuorumVault vX.Y.Z" && git push origin vX.Y.Z`.
2. Start the workflow from the tag: `gh workflow run images.yml --ref vX.Y.Z -f publish=true`, then `gh run watch`.
3. The jobs: `gate` (refuses a branch, a bad name, a commit off `main`, red CI) → `build` and `repro` (all images, and two from-scratch binary builds with equal SHA-256) → `publish`:
   - builds the release images and runs `smoke.sh` and `check-secrets.sh` **before** anything is pushed (no secret-looking file in any layer, no other-zone binary, non-root, no test-only code); one failure stops the release with nothing pushed;
   - pushes every image by digest with SBOM and provenance, signs each digest, writes `release-vX.Y.Z.json` and signs it;
   - pulls the pushed images by digest and runs `check-secrets.sh` again, then `verify-release.sh` (signature and identity, tag → digest, SBOM and provenance attached).
4. Look at the run: all 12 images in the log, the verify step green, the artifact `release-vX.Y.Z` present. A red `publish` job after the push step means images **are** public: go to "A bad image was published".
5. **First release only:** GitHub creates each package **private**. Check the 12 packages (Packages in the repository) and make each one public (Package settings → Danger Zone → Change visibility). Do it only after step 4 is green; see "Visibility facts" for what it means.

## After

1. Attach the manifest to a GitHub Release (the job has no permission to create one, on purpose):
   `gh run download <run-id> -n release-vX.Y.Z -D rel && gh release create vX.Y.Z rel/release-vX.Y.Z.json rel/release-vX.Y.Z.json.sigstore.json --notes-file notes.md` (add `--prerelease` for a candidate).
2. Verify from the outside, as anyone could: `deploy/images/verify-release.sh rel/release-vX.Y.Z.json`.
3. Chart values from the manifest, never by hand: `deploy/images/manifest-values.py rel/release-vX.Y.Z.json --all --out-dir values/` writes `images-qv-business.yaml`, `images-qv-party.yaml`, `images-qv-signing-core.yaml`. In the deployment repository or values file, apply them **last** (`helm upgrade … -f values.yaml -f images-<chart>.yaml`). The charts refuse all-zero placeholder digests. `qv-certs` runs no image. The Grafana Alloy image of `qv-signing-core` is not ours: pin it separately.
4. Roll out per chart and cluster, in this order: business database migrations first (`qv-migrate` Job of `qv-business`, then the signing clusters' `qv-migrate -zone signing` Jobs), then the services. Signing clusters are rolled by their own operators.
5. Attestation allowlist: build the enclave image (EIF) from the `mpc-party` **digest** in the manifest, compute its measurement (`qv-attest-ca measure`, PR #115, when it is in `main`; otherwise the tool of your enclave platform), and add it to the signed allowlist with overlap (`tee-broker.md`). The manifest's `partyMeasurement` block names the digest and says `pcr0` was not computed at build time: nothing at build time knows the enclave platform.
6. Release notes: what changed, migrations, charts that changed, the allowlist change, known issues.

## How a release reaches the clusters

- Clusters **pull from `ghcr.io` by digest**. The pull is done by the node's container runtime, not by a pod, so the charts' default-deny NetworkPolicies do not apply to it, and the charts open no pod egress to a registry. What must exist is **node egress to `ghcr.io` over 443**, plus the host GitHub redirects blob downloads to (test with a pull from a node; do not assume the name).
- **Business cluster:** pull directly. **Signing clusters and party clusters** often have no internet egress for nodes: use a **mirror** inside the network (the choice the charts allow, not the default). Copy each image with its signature and attestations so digests stay equal: `cosign copy ghcr.io/ws4charlie/quorum-vault/<name>@<digest> <mirror>/<name>` (or `skopeo copy --all --preserve-digests`), then generate values with `manifest-values.py … --registry <mirror>`. Same digests, other repository.
- The charts take a digest, so a mirror cannot serve other bytes; a signature policy (the policy chart) verifies the signature on the pulled digest with the identity above.

## Verification commands

```bash
# signature and signer (anyone; cosign v2+)
cosign verify \
  --certificate-identity "https://github.com/ws4charlie/quorum-vault/.github/workflows/images.yml@refs/tags/vX.Y.Z" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/ws4charlie/quorum-vault/qv-core@sha256:<digest>

# SBOM (SPDX) and provenance attached to the index
docker buildx imagetools inspect ghcr.io/ws4charlie/quorum-vault/qv-core@sha256:<digest> --format '{{ json .SBOM }}'
docker buildx imagetools inspect ghcr.io/ws4charlie/quorum-vault/qv-core@sha256:<digest> --format '{{ json .Provenance }}'

# the whole manifest against the registry: every signature and identity, tag → digest, SBOM and provenance, the manifest's own signature
deploy/images/verify-release.sh release-vX.Y.Z.json

# the manifest file itself
cosign verify-blob --bundle release-vX.Y.Z.json.sigstore.json \
  --certificate-identity "https://github.com/ws4charlie/quorum-vault/.github/workflows/images.yml@refs/tags/vX.Y.Z" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com release-vX.Y.Z.json
```

The manifest (`schema 1`) holds, per image, the name, repository, digest, zone and binaries; the source commit and tag; the signer identity and issuer; and `partyMeasurement`.

## Rollback

Deploy the previous release's manifest: regenerate the values from `release-vPREV.json` with `manifest-values.py` and upgrade the charts. The previous digests stay in the registry and stay signed.
**Database migrations are forward-only.** Nothing reverts a schema, and no image rollback does. So rolling back is safe only to the previous release, which by the "Before" rule runs on the new schema; the new columns and tables simply stay unused. Never roll back across a release whose migration broke its predecessor (the rule forbids shipping one). Money-path state (ledger, guard databases, MPC shares) is never restored by a rollback: for those see `mpc-backup-restore.md` and `database-roles.md`. Rolling the party image back needs the old measurement still on the allowlist: keep the overlap until the new release is accepted.

## A bad image was published

A public package cannot be made private again, and anyone may already have pulled the image: assume it is out. In this order:
1. Stop rollout: do not deploy the version anywhere; roll back clusters that did (above).
2. If a **secret** was in an image (`check-secrets.sh` should have stopped it): treat it as leaked and rotate it, whatever you do to the image. Deleting never un-leaks it.
3. Revoke the measurement: publish an allowlist without the party image's entry (`tee-broker.md`, "Change the allowlist"): new releases of data keys are refused at once; a running party keeps its keys until it restarts.
4. Delete the version (Package settings → the version → Delete, or the REST API with a token that has admin on the package; the workflow's repository has it for packages the workflow published). It works only while that version has **at most 5,000 downloads**; above that GitHub Support must do it. A deleted version can be restored for 30 days: do not restore it. The signature stays in the public transparency log whatever you delete.
5. Publish a fixed **new** version (`vX.Y.(Z+1)`): never reuse the tag. Mark the GitHub Release of the bad version as withdrawn in its notes and name the fix.
6. Write down what happened and why the checks did not catch it; add the check.

## Visibility facts

Confirmed on 2026-11-20 from GitHub's documentation (pages under https://docs.github.com/en/packages/): `learn-github-packages/configuring-a-packages-access-control-and-visibility`, `learn-github-packages/deleting-and-restoring-a-package`, `working-with-a-github-packages-registry/working-with-the-container-registry`:
- A package first pushed to `ghcr.io` is **private** by default. Making it public is a manual step in the package's settings, and the page says: once a package is public, **it cannot be made private again**. (The lead's earlier statement was right.)
- A **public** package can be pulled by anyone **without signing in**. Linked to a repository by the label `org.opencontainers.image.source` (the images carry it), it inherits that repository's permissions by default; the workflow's token may push because the repository has admin on a package its workflow created.
- A version of a public package can be **deleted** only if it has **no more than 5,000 downloads**; a public package with a version above that cannot be deleted by its owner (contact GitHub Support). A deleted package or version can be restored within 30 days if the name is unused. Deleting does not recall copies already pulled.
- What a public package exposes: the image layers (the binaries of this public repository, plus the distroless base), the image configuration and labels, the SBOM (every dependency and version) and the provenance attestation (builder, commit, workflow run, build arguments). The repository is already public, so no source or history is new; **nothing secret may be in an image**, and `check-secrets.sh` enforces that on every layer before and after the push. Configuration, certificates, keys and PINs are never in an image; they are mounted at run time.

## Failures

| What you see | Meaning | Do |
|---|---|---|
| `gate`: `REFUSED … not vMAJOR.MINOR.PATCH` | wrong tag name or run from a branch | tag correctly, start with `--ref vX.Y.Z` |
| `gate`: `not on main` | tag points at a commit `main` does not contain | merge, tag the merge commit |
| `gate`: `no successful ci.yml run on main` | CI still running or red for this commit | wait, or fix on `main` and tag the new commit |
| `publish.sh: … already exists` | this version was published (or half published) | new patch version; for a half-published one see "A bad image was published" |
| `check-secrets.sh` FAIL before the push | a secret-looking file, another zone's binary or root in an image | fix the image build; nothing was pushed |
| `verify-release.sh` FAIL after the push | the pushed result does not match | treat as a bad image until explained |

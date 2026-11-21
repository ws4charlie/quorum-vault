# Nitro first run: checklist for the first day on real hardware

The Nitro path is **written and tested against fakes. It has never run on a Nitro host.** No AWS account existed, so nothing here needed one, and every number below that comes from AWS comes from its documentation (pages read 2026-11-20; names in the text), not from a run. This page turns what the simulation cannot prove into checks with a pass rule, in the order to do them. Design background: `research/TEE.md`; the Kubernetes question: `docs/spikes/nitro-on-kubernetes.md`.

## What exists, and what is still missing

| Exists (tested against fakes and one real AWS document) | Where |
|---|---|
| Verifier of real attestation documents, pinned AWS root (SHA-256 `641a0321...bb5b`), every refusal tested | `mpc-party/internal/attest` (`nitro.go`, `nitro_root.go`, `nitro_real_test.go`) |
| NSM attester (`/dev/nsm` ioctl, serde CBOR request) | `attest/nsm*.go` |
| KMS release: SigV4 client, `Recipient` calls, CMS `EnvelopedData` reader, instance-role credentials, vsock dialer | `attest/kmsrelease` |
| Sealer on KMS (`sealer.type: attested`, `attester.type: nitro`, `release.type: kms`) | `internal/server/sealer_attested_*.go` |
| Allowlist entries with PCR1, PCR2 and PCR8; one list for the broker and the KMS key policy | `attest/allowlist.go`, `deploy/cloud/aws/nitro/` |
| EIF build, reproducible; probe image | `deploy/images/eif-build.sh`, `Dockerfile.eif*` |
| Terraform: key and policy, party role, launch template | `deploy/cloud/aws/modules/nitro-enclave` |
| First-hardware probe (`mpc-party nitro-probe`) | `internal/nitroprobe` |

**Still missing: a party cannot yet run in an enclave.** The first day checks mechanisms (documents, PCRs, KMS), not a running party. Needed before a party runs, in the order they block it:
1. **Inbound listeners.** An enclave has no network. The party's TCP listeners (gateway and peer port, health) need a bridge pair: parent side `TCP-LISTEN` to `VSOCK-CONNECT`, enclave side the reverse to `127.0.0.1` (and `lo` brought up inside the enclave).
2. **Storage.** The enclave has no disk. The party's `data_dir` (sealed shares, state, freeze records, stored signatures) must live on the parent and reach the enclave over vsock: a blob-store service on the parent and a store backend in the party (the party already hides its storage behind `KeyStore`, `JobStore`, `FreezeStore`).
3. **Cosigner channel.** Party B asks its cosigner over a unix socket; that needs a vsock transport or an authenticated TCP path (research/TEE.md, T5).
4. **Logs and metrics** leave only through vsock: a relay.
5. **The TLS identity** (`tlsident`) inside the enclave: today it reads files.
Each is small, none exists. Plan them as a task before the second day.

## Before you start

| What | Value | Source |
|---|---|---|
| Account, region, a VPC subnet with a route to the KMS endpoint (public endpoint or the `kms` VPC endpoint of the Terraform roots) | yours | |
| Instance type | a Nitro-based type with enough CPUs and memory for the parent and the enclave, **not** `*.large` or `*.metal` of the families that exclude them: `m6i.xlarge` is on the list ("all except m6i.large, m6i.metal"). Same architecture as the EIF you built (x86_64 or arm64): the PCRs are per architecture | AWS "Nitro Enclaves" page, Requirements |
| Enclaves enabled at launch (cannot be switched on later), no hibernation | `enclave_options { enabled = true }` in `modules/nitro-enclave` | same |
| Up to 4 enclaves per parent; they cannot talk to each other; they stop when the parent stops | | same, Considerations |
| Software on the parent | Amazon Linux 2023: `dnf install aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel socat` (the first two names exist; verified by installing them in a container) | |
| What you need on your laptop or CI | Docker with buildx 0.13 or newer, Terraform, Python 3 | |

**Costs** (nothing is billed for the feature itself: "no additional charges for using AWS Nitro Enclaves other than ... Amazon EC2 instances and any other AWS services", AWS Nitro Enclaves page). The first day costs the instance hours plus: a KMS key at $1 per month, prorated hourly, and $0.03 per 10,000 requests beyond the free tier (AWS KMS pricing page; a customer key scheduled for deletion costs nothing). The probe makes about 4 KMS calls per run. Look up the on-demand hourly rate of the chosen type on https://aws.amazon.com/ec2/pricing/on-demand/ (not read for this page, so no figure is given): a day on one instance is its hourly rate times 24, and four hours are enough for steps 1 to 8.

## Steps

Every step lists the command, what it should print, and the **pass rule**. Stop at the first failure and write down the output.

### 1. Build the image twice (no hardware, any Linux or Docker Desktop)

Take the released party image by digest from the release manifest (`images.mpc-party.ref`) and the deployment's measured configuration for this party (directory with `party.json`, never in git).

```bash
deploy/images/eif-build.sh --repro --party-image <repo>@sha256:<digest> --config-dir <dir> --out out-a --epoch <manifest sourceDateEpoch>
```

Prints `two from-scratch builds give the same PCRs`, then `PCR0`, `PCR1`, `PCR2` (96 hex each). **Pass:** the line above, **and** a second person on another machine gets the same three values from the same inputs. `build-info.json` lists what the values depend on (image digest, config hash, epoch, nitro-cli 1.5.0 and the hashes of its kernel blobs, architecture). Verified on a laptop with a stand-in image: two builds with `--no-cache` and touched files gave identical PCRs, while a different `--epoch` changed PCR0 and PCR2 and PCR1 stayed the same. PCR1 is the kernel and boot ramfs, so it changes only with the nitro-cli package. `nitro-cli build-enclave` needs Linux and Docker only; it does not need an enclave-capable host (AWS "nitro-cli build-enclave"; confirmed by running it).

Sign the image if the key policy should also check PCR8 (recommended): add `--sign-key key.pem --sign-cert cert.pem` (ECDSA key, held by the release owners, not on the parent). PCR8 then appears; PCR0 does not change.

### 2. Put the image on the allowlist and the key policy (offline)

```bash
deploy/cloud/aws/nitro/nitro-cli-to-allowlist.py --party A --version v1.4.0 --input out-a/nitro-cli.out
```

Prints one `qv-attest-broker allowlist add ... -pcr 1=... -pcr 2=...` line; run it, sign with `min_operators` operators (`tee-broker.md`), check with `allowlist show -operators`. Then, only after `show` says valid:

```bash
deploy/cloud/aws/nitro/allowlist-to-tfvars.py --party A < allowlist.json > party-a.auto.tfvars.json
```

Feed `allowed_images` to `modules/nitro-enclave`, review `terraform plan` (two people) and apply. **Pass:** the plan shows a key policy with one `AllowEnclave...` statement per image, each with `ImageSha384`, `PCR0`, `PCR1`, `PCR2` (and `PCR8`), plus the deny statement for use without an attestation document. The script refuses an empty list, all-zero PCRs and an unsigned file; the Terraform variable refuses them again.

### 3. Prepare the host

On the parent (values are the documented ones; adjust memory and CPUs to the probe first, to the party later):

```bash
sudo dnf install -y aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel socat
# /etc/nitro_enclaves/allocator.yaml: memory_mib: 1024   cpu_count: 2     (the allocator takes them from the parent)
sudo systemctl enable --now nitro-enclaves-allocator.service
# /etc/nitro_enclaves/vsock-proxy.yaml: allowlist: - {address: kms.<region>.amazonaws.com, port: 443}
vsock-proxy 8000 kms.<region>.amazonaws.com 443 &          # AWS's proxy: bytes only; TLS ends in the enclave
socat VSOCK-LISTEN:8001,fork,reuseaddr TCP:169.254.169.254:80 &   # instance role credentials for the enclave (IMDSv2)
```

`vsock-proxy` serves a handful of connections at once (`-w`, default 4; AWS vsock-proxy README); the party's KMS client opens one connection per call and never holds two. **Unverified:** that `socat` on Amazon Linux 2023 is new enough for `VSOCK-LISTEN`; if not, build it or use the vsock-proxy for IMDS (it takes an address and a port: add `169.254.169.254` port 80 to its allowlist and run a second proxy on port 8001).

### 4. Run the probe in debug mode first (what a refusal looks like)

Build the probe image (same released image, different entry point; its PCRs differ from the party's) with a `probe.json` such as `{"report_vsock_port":9100,"expect_pcr0":"<the probe's PCR0>"}`; add the `kms` object (`key_id`, `region`, `vsock_port` 8000, `creds_vsock_port` 8001) for steps 6 and 7.

```bash
deploy/images/eif-build.sh --probe --party-image <repo>@sha256:<digest> --config-dir probecfg --out probe-out --epoch <epoch>
socat VSOCK-LISTEN:9100,fork - &      # prints the report
sudo nitro-cli run-enclave --cpu-count 2 --memory 1024 --enclave-cid 16 --eif-path probe-out/party.eif --debug-mode
```

**Pass:** the report says `verified false` with `debug` in the error (the production verifier refuses all-zero PCRs: AWS documents that an enclave started with `--debug-mode` reports all-zero PCRs), and, with `kms` configured, `AccessDeniedException`. Then `sudo nitro-cli terminate-enclave --all`.

### 5. Run the probe for real, without KMS

Same command without `--debug-mode` and with `probe.json` without `kms`.

**Pass:** `document verified by the production verifier: true`; `debug mode: false`; `PCR0 equals the build's: true`; the document is about 4.5 to 6 KB (a real one in the tests is 4461 bytes, `testdata/nitro`); `clock skew` within a few seconds; `rng: "nsm-hwrng"`. These show: the NSM ioctl layer works; the chain verifies to the pinned AWS root on real hardware; the PCRs a real enclave reports are the ones `nitro-cli` printed. If the clock skew is large or the rng is another source, fix that before going on (TLS to KMS needs a correct clock; the enclave kernel's clock source is **unverified** here).

### 6. KMS with the probe's PCRs

Temporarily add the probe image to `allowed_images` (its own name, `probe`), apply, run the probe with `kms` configured.

**Pass:** `KMS: GenerateDataKey ... ms, Decrypt ... ms, keys equal true`. That one line shows: the SigV4 signing is accepted, the instance-role credentials arrive over vsock, TLS to the real endpoint works through the proxy, the `Recipient` document is accepted, the real `CiphertextForRecipient` parses (BER, RSAES-OAEP SHA-256, AES-256-CBC), and `EncryptionContext` round-trips. In CloudTrail the `GenerateDataKey` and `Decrypt` events show the enclave's image digest: it must equal the probe's PCR0 (AWS KMS condition keys page: the value "is also included in CloudTrail events").

### 7. The negative cases (AWS KMS's own condition evaluation)

Each must fail, and each failure is a pass:

| Do | Expect |
|---|---|
| Change one hex digit of PCR0 in the key policy, apply, rerun the probe | `AccessDeniedException` |
| Remove PCR8 or PCR1 from the policy and add a wrong one | `AccessDeniedException` (a PCR in the policy that the document does not match) |
| Upper-case the PCR0 value in the policy (hand edit) | still allowed (`StringEqualsIgnoreCase`); put it back to lower case |
| With an administrator's credentials, call `aws kms decrypt` on a stored blob from the shell | `AccessDeniedException` (the deny statement; if this call succeeds, statement 2 of `modules/nitro-enclave/main.tf` does not work as written: report it, the other two statements still hold) |
| Call `aws kms decrypt` with the parent role's credentials and no recipient | `AccessDeniedException` |
| Run the probe with the policy limited to `v1` but the probe signed with another certificate (PCR8 differs) | `AccessDeniedException` |

### 8. Remove the probe and the temporary entries

Take `probe` out of `allowed_images`, apply, check the key policy shows only released images.

## What the simulation could not prove, as checks

| Simulation cannot prove | Check | Pass rule |
|---|---|---|
| Memory isolation and confidentiality | Run without `--debug-mode` (steps 5 to 7). Try `sudo nitro-cli console --enclave-id <id>` and read the parent's process list and `/proc` for the enclave's memory | The console is refused outside debug mode; nothing of the enclave's memory is in a parent process. This confirms the mode only: the isolation itself is AWS's and is not testable by us |
| Real hardware measures what the build measured | Step 5 (PCR0 in the document equals `nitro-cli`'s) and step 6 (KMS accepts that PCR0) | Equal, on the first try |
| The vendor's chain, revocation and TCB handling | Step 5: verified by the production verifier. We pin the root and do not check revocation (AWS documents the chain, not CRLs) | `verified true`. Revocation stays unchecked: stated in `docs/limits.md` |
| AWS KMS's own condition evaluation | Step 7 | Every row as listed |
| vsock and proxy behaviour and limits | Run the probe's KMS round trip 200 times in a loop from the parent (`nitro-cli run-enclave` per run, or after the party exists, the start-up with 200 generations) and watch `vsock-proxy` logs (`journalctl -eu nitro-enclaves-vsock-proxy`) | No connection errors; time per call stable; note the maximum |
| Overhead and memory (EPC does not exist on Nitro; the question is the enclave's RAM) | Probe `mem_total_mib` and `heap_alloc_mib`; later the party's resident memory inside the enclave while it signs | Record both; size `memory_mib` with 2x headroom over the party's peak. **No party RSS number exists yet** (T4 never measured one) |
| Side channels and physical attacks | Not testable here | Accepted and listed in `research/TEE.md` and `docs/limits.md` |
| Rollback with real storage | Needs the blob store (missing, above). Repeat the simulation's rollback tests (`TestAttestedRollbackOfTheDataDirectory`, `TestAttestedDeletedFreezeRecordIsStillFrozenByThePeer`) against it | Same results as in simulation |

What this task added and could not test without hardware (each is covered by a step above): the NSM ioctl layer (step 5); the vsock dialer (step 6; it passes against the kernel's own loopback in a privileged container); the clock and entropy inside the enclave (step 5); the real KMS answer format (step 6); the `Recipient` freshness window of KMS, which AWS does not state (if step 6 fails with a timestamp complaint, the document is older than KMS accepts: make the document right before the call; the client already does).

## What to measure and write down

| Measure | From | Compare with |
|---|---|---|
| Attestation time (NSM call) | probe `attest_ms` | the mock: microseconds |
| RSA-2048 key generation in the enclave | `rsa_keygen_ms` | n/a (new) |
| One `GenerateDataKey` and one `Decrypt` through vsock and the proxy | `generate_data_key_ms`, `decrypt_ms` | the broker in simulation: `docs/measurements/tee-sim.md` |
| Start-up with N keysets | the party, when it can run: N+1 `Decrypt` calls (one per generation, one for the local key), each its own attestation | `docs/measurements/tee-sim.md` (broker: 2N+2 calls) |
| vsock overhead per signing round | the party, when it can run: sign p50/p95 in the enclave minus the same on the host | 101 ms p50 for 2-of-3 ECDSA, 9 rounds (`docs/measurements/mpc.md`) |
| Memory | probe `mem_total_mib`, `heap_alloc_mib`; the party's resident set | none |

## Tear down

```bash
sudo nitro-cli terminate-enclave --all
# stop the socat and vsock-proxy processes, then
terraform destroy -target=module.<enclave key module>      # or schedule key deletion; the window is deletion_window_days (30)
```

Terminate the instance (its enclaves stop with it), delete the EIF files and the probe's config, and remove the test entries from the allowlist and the tfvars. A KMS key scheduled for deletion costs nothing (AWS KMS pricing page). Keep `build-info.json` and the recorded outputs with the first-run notes.

## Stop and ask if

A step needs a credential you were not given; step 7's administrator row succeeds; step 5 reports `debug mode: true` for an image started without `--debug-mode`; two builders disagree in step 1.

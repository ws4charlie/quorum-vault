# CloudHSM sealer: checklist for the first run on real hardware

The party seals its key shares with a wrap key in an HSM through PKCS#11. `sealer.provider: cloudhsm` selects the rules of AWS CloudHSM. **Everything here is proven only against documentation and a test double. No CloudHSM hardware has run it.** This page is the list of what to create, what to run and what to measure on the first real cluster.

## What differs from SoftHSM, and how sure we are

Sources are AWS CloudHSM user guide pages for Client SDK 5, read on 2026-11-20 (base `https://docs.aws.amazon.com/cloudhsm/latest/userguide/`).

| Topic | Rule | Source | Status | What the code does |
|---|---|---|---|---|
| AES-GCM IV | The HSM makes the 12-byte IV; the caller cannot supply it. With `CKM_AES_GCM` it is written into the IV field of the parameters; the vendor mechanism `CKM_CLOUDHSM_AES_GCM` prepends it to the ciphertext instead | `pkcs11-mechanisms.html`, `manage-aes-key-wrapping.html` | documented | Standard mechanism; the IV is read back from the parameter block after the call and stored in the envelope. An all-zero IV is refused |
| GCM data size | 16224 bytes per call, both GCM mechanisms; no multipart (update calls fail with `CKR_MECHANISM_INVALID`) | `pkcs11-mechanisms.html`, `ki-pkcs11-sdk.html` | documented | Plaintext is cut into parts of 16000 bytes, each with its own IV; the part number and count are bound into the associated data |
| GCM tag length, associated-data limit | not found | | **unverified** | Tag is 128 bits as before. Run the hardware test with the largest associated data the party uses |
| Login | PIN argument of `C_Login` is `user:password` of a crypto user (CU) | `pkcs11-pin.html` | documented | The profile requires that shape; the PIN comes from `pin_file` only (`pin_env` is refused) |
| Sessions | Read-only sessions are not supported; open read-write | `ki-pkcs11-sdk.html` | documented | Always read-write |
| Throttling | Throttled calls return `CKR_FUNCTION_FAILED` (`CKR_DEVICE_ERROR` from `C_GetAttributeValue` before 5.18.0); retry with backoff | `ki-pkcs11-sdk.html` | documented | Up to 3 tries with 100 ms and 200 ms backoff, each on a fresh login; a failed decrypt is never retried on `CKR_FUNCTION_FAILED` (it may be how a bad tag looks) |
| Lost HSM or session | what the library returns, whether the login survives, whether `C_Initialize` must be redone | pages empty or not fetched | **unverified** | Session and device errors trigger a new login session and a retry. The test double only drops sessions |
| Key attributes | CloudHSM supports a subset; `CKA_SENSITIVE` honoured; `CKA_DERIVE=TRUE` unsupported | `pkcs11-attributes.html` | partly | Template has no `CKA_PRIVATE`. Whether `CKA_PRIVATE`, `CKA_LABEL`, `CKA_TOKEN`, `CKA_EXTRACTABLE` are accepted: **unverified** (the attribute tables were not read); the hardware test finds out |
| Find by label | not found | | **unverified** | Lookup by class and label as today |
| Token label and slots | not found (the multi-slot page was not read) | | **unverified** | If no token has the configured label and the module offers exactly one, it is used and a warning is logged |
| Key wrap | `CKM_CLOUDHSM_AES_KEY_WRAP_{NO_PAD,PKCS5_PAD,ZERO_PAD}` exist; `CKM_AES_KEY_WRAP_PAD` not found | `pkcs11-mechanisms.html`, `manage-aes-key-wrapping.html` | documented | Not used. The design encrypts shares under the wrap key (the key never leaves the HSM); wrapping would add nothing |
| Single-HSM cluster | `disable_key_availability_check` must be true | `pkcs11-library-install.html` | documented | Do not run one HSM in production (see below) |
| Config file path, cluster certificate path, SDK version | not found on the pages read | | **unverified** | Take them from the install guide for the SDK version you install |

## Envelope format

| Version | Written by | Shape |
|---|---|---|
| 1 | provider `softhsm` | `{"v":1,"iv","ct"}`, IV made by the party |
| 2 | attested sealer | not this sealer |
| 3 | provider `cloudhsm` | `{"v":3,"p":"cloudhsm","id","len","parts":[{"iv","ct"}…]}`, IVs made by the HSM; every part is bound to a random per-seal id, its index, the part count and the total length |

Both providers open both versions. Old data (version 1) opens unchanged. A data directory sealed under SoftHSM is **not** moved to CloudHSM by this: the wrap key is another key. Move a party with a backup restore (below).

## Create (once per party account)

1. A CloudHSM cluster in the party's own account and VPC, **two HSMs in different Availability Zones** (one HSM cannot survive its AZ; AWS documents the single-HSM workaround as a switch, not a recommendation).
2. Initialize the cluster and install the cluster certificate (the install guide for your SDK version). The signing key of that certificate is the party's own.
3. Create a crypto user for the party (`user:password`). Use a long random password. Put `user:password` in the Secret named by `hsm.pinSecret`, key `pin`.
4. Do not create the wrap key by hand: the party creates `qv-share-wrap` on first start (AES-256, persistent, sensitive, not extractable, encrypt and decrypt). Check afterwards with the CloudHSM CLI that exactly one key has that label and that it is not extractable.
5. Add the other crypto users of your admin team as **separate** users; the party's user is never used by a person.

## Run the contract test against the cluster

From a host in the VPC with the client library installed (this is not run in CI: the file has the build tag `cloudhsm_hw`):

```bash
cd mpc-party
QV_CLOUDHSM_LIB=/opt/cloudhsm/lib/libcloudhsm_pkcs11.so \
QV_CLOUDHSM_PIN_FILE=/path/to/pin-file \
QV_ENV=test go test -tags cloudhsm_hw -count=1 -v -run CloudHSMHardware ./internal/server/
```

The pin file holds `user:password` and has mode 0400. Expect `TestCloudHSMHardwareContract` to pass: it seals and opens sizes from 0 to three parts, a restart, wrong associated data, tampered and malformed envelopes. **Any failure is a finding**: file it with the exact PKCS#11 return code. The likely ones are an attribute the HSM refuses in the key template, a different token label, and a different return code for a failed tag (the code treats it as a failed open only if a probe round trip still works).

## Measure

`TestCloudHSMHardwareLatency` logs p50 and p99 of seal and open (about 1.5 KB, one caller) and the rate of one caller. `QV_CLOUDHSM_OPS` sets the count (default 200). Then repeat from several pods at once to see the cluster's rate and its throttling. Record the numbers in `docs/measurements/`; a party seals on key creation, refresh and generation change, and opens on start, so the rate matters for restarts of many parties, not for signing.

## Loss of an HSM, of the cluster, of the key

| Case | What happens | What to do |
|---|---|---|
| One HSM of two is gone | Calls retry on the other; throttling may show | Replace the HSM; nothing for the party |
| Connection lost | Calls fail as UNAVAILABLE after 3 tries; the party answers UNAVAILABLE and does not crash | Restore the route; the next call logs in again |
| Cluster deleted, or the wrap key deleted | Every sealed share of the party is unreadable | Restore the party from its backup (next section) |
| Wrap key exposed | It cannot be: it is not extractable | n/a |

## Backup and restore with the wrap key in CloudHSM

The party's backup (`docs/runbooks/mpc-backup-restore.md`) is encrypted to a recovery key and does not depend on the sealer. Restoring re-seals the share under whatever sealer the restored party is configured with. The wrap key is not part of the backup and cannot be (not extractable).

| Option | Meaning | Verdict |
|---|---|---|
| A. Backups only | Keep the share backups; after losing the cluster, make a new cluster, new wrap key, restore each keyset from its backup | **Recommended.** No new secret to keep; the same path as every other restore |
| B. Also back up the cluster | CloudHSM keeps its own backups, and a cluster can be restored from one into the same account and region | Extra safety against operator mistakes in the cluster; does not replace A. Check the retention and who can delete the backups |
| C. Copy the wrap key to a second HSM | Needs wrapping the key out (extractable or wrap-with-trusted) | **Not recommended**: it weakens the main property of the design |

Rule that follows: a party is restorable only if its share backups are current ([the backup runbook](mpc-backup-restore.md) says when they go stale). Drill option A once on the first cluster: delete the key in a test cluster, restore, sign.

## Cost

AWS bills each HSM per hour while it exists, with no upfront cost. The page `https://aws.amazon.com/cloudhsm/pricing/` (read 2026-11-20) gave **no hourly figure and no effective date**; use the AWS pricing calculator for your region on the day you create the cluster. Two HSMs per party, three parties: six HSMs. **Unverified.**

## What the party chart needs

See the report of task D12 (this page is not the place for chart values until the chart owner applies them): the client library and its configuration, the cluster certificate, egress to the HSM network interfaces, the PIN Secret.

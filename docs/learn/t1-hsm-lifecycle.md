# T1 — HSM key lifecycle

What T1 built: secp256k1 signing keys that are generated inside a SoftHSM token and never leave it, a Postgres key registry that moves every key through `active -> sign_only -> retired`, and an `hsmsigner` that plugs the token into the shared `signer.Signer` interface.

| Layer | File | Job |
|---|---|---|
| Raw PKCS#11 | [internal/hsm/keys.go](../../internal/hsm/keys.go), [internal/hsm/sign.go](../../internal/hsm/sign.go) | generate, find, sign, destroy key objects |
| Adapter | [internal/hsmsigner/hsmsigner.go](../../internal/hsmsigner/hsmsigner.go) | `KeyGenerator` + `Signer` for the HSM backend |
| Registry | [internal/keys/keys.go](../../internal/keys/keys.go) | wallets, key versions, lifecycle, rotation, audit events |

## 1. Generating a key: the templates, attribute by attribute

`Token.GenerateECKeyPair` ([keys.go:57](../../internal/hsm/keys.go#L57)) calls `C_GenerateKeyPair` with mechanism `CKM_EC_KEY_PAIR_GEN` and two templates. The token builds both objects; the private scalar is created inside the token.

Public key template:

| Attribute | Value | Why |
|---|---|---|
| `CKA_CLASS` | `CKO_PUBLIC_KEY` | object type |
| `CKA_KEY_TYPE` | `CKK_EC` | elliptic-curve key |
| `CKA_TOKEN` | true | persistent: stored in the token, survives the session |
| `CKA_VERIFY` | true | may verify signatures |
| `CKA_EC_PARAMS` | DER OID of the curve | picks the curve: secp256k1 = `06 05 2B 81 04 00 0A`, P-256 = `06 08 2A 86 48 CE 3D 03 01 07` |
| `CKA_LABEL` | `qv-<walletID>-v<version>` | human-readable name |
| `CKA_ID` | 16 random bytes | the stable handle we look keys up by |

Private key template:

| Attribute | Value | Why |
|---|---|---|
| `CKA_CLASS` | `CKO_PRIVATE_KEY` | object type |
| `CKA_KEY_TYPE` | `CKK_EC` | |
| `CKA_TOKEN` | true | persistent |
| `CKA_PRIVATE` | true | only visible after `C_Login` as the user |
| `CKA_SENSITIVE` | true | the secret value (`CKA_VALUE`) can never be read in plaintext |
| `CKA_EXTRACTABLE` | false | cannot be exported even wrapped under another key (`C_WrapKey`) |
| `CKA_SIGN` | true | may be used with `C_Sign` |
| `CKA_LABEL`, `CKA_ID` | same as the public key | pairs the two halves |

PKCS#11 makes `SENSITIVE` one-way (false -> true only) and `EXTRACTABLE` one-way (true -> false only), so nobody can later relax them. [keys_test.go](../../internal/hsm/keys_test.go) `TestPrivateKeyNotExportable` proves it: reading `CKA_VALUE` fails with `CKR_ATTRIBUTE_SENSITIVE`.

The public key comes back in `CKA_EC_POINT` as a DER OCTET STRING around the point: `04 41 | 04 X Y`. `unwrapECPoint` ([keys.go:107](../../internal/hsm/keys.go#L107)) strips the wrapper (and also accepts a raw `04 X Y`, which some modules return).

**Why look up by `CKA_ID`, not object handle?** Handles are numbers valid only within the current application session; they change after a restart. `findObject` ([keys.go:151](../../internal/hsm/keys.go#L151)) searches by `CKA_CLASS` + `CKA_ID` with `C_FindObjectsInit / C_FindObjects / C_FindObjectsFinal`. `Final` runs in a `defer` because the session goes back to a pool: a session left in "find" mode would make the next caller's operations fail with `CKR_OPERATION_ACTIVE`.

## 2. Signing: CKM_ECDSA, raw r||s, low-S

`Token.SignECDSA` ([sign.go:20](../../internal/hsm/sign.go#L20)):

1. Find the private key by `CKA_ID` (missing -> `hsm.ErrKeyNotFound`).
2. Read its `CKA_EC_PARAMS` to know the curve.
3. `C_SignInit(CKM_ECDSA)` + `C_Sign(digest)`.

`CKM_ECDSA` signs the bytes you give it as the hash; it does no hashing itself. So the caller passes the 32-byte Ethereum digest (Keccak-256 of the tx). Variants like `CKM_ECDSA_SHA256` would hash again and produce a signature of the wrong message.

The output is raw `r || s` (32 + 32 bytes), not DER. Ethereum then needs **low-S**: for every valid `(r, s)`, `(r, N - s)` is also valid. EIP-2 accepts only `s <= N/2` so a signature cannot be changed into a second valid one (malleability). About half of raw HSM signatures are high-S; `signer.NormalizeLowS` flips them ([sign.go:55](../../internal/hsm/sign.go#L55)). The HSM does not give the recovery id `v`; T4 finds it by trying `v = 0, 1` and checking which recovers the key's address (`hsmsigner_test.go` does the same check).

## 3. The adapter

- `hsmsigner.NewGenerator(tok)` ([hsmsigner.go:30](../../internal/hsmsigner/hsmsigner.go#L30)): random 16-byte `CKA_ID`, label `qv-<walletID>-v<version>`, secp256k1, address = `crypto.PubkeyToAddress(pub).Hex()` (EIP-55 checksum).
- The generator also has `DestroyKey`, which satisfies `keys.KeyDestroyer`; the registry uses it on retire and to clean up a key whose DB insert failed.
- `hsmsigner.New(tok, key)` refuses non-HSM keys. `SignDigest` returns `Participants: ["hsm:<token label>"]` and verifies the signature against the stored public key before returning it.

## 4. The registry and the lifecycle

```
          Rotate               Retire
active ----------> sign_only ---------> retired (HSM private key destroyed)
```

Only these two transitions exist (`checkTransition`, [keys.go:342](../../internal/keys/keys.go#L342)); anything else is `ErrInvalidTransition`. A DB partial unique index allows at most one `active` key per wallet.

**The drain rule** (`AuthorizeSign`, [keys.go:352](../../internal/keys/keys.go#L352)). Every sign request is bound to the wallet's active key when it is created.

| Key state | May sign |
|---|---|
| `active` | requests bound to it |
| `sign_only` | requests bound to it AND created strictly before its `sign_only_at` |
| `retired` | nothing |

Why drain instead of switching instantly? Requests already approved (possibly by two humans for a cold wallet) are bound to the old key. Re-binding them to the new key would change what the approvers saw (a different from-address). Draining lets them finish while no new work reaches the old key. Both timestamps come from Postgres `now()`, so app-server clock skew cannot move a request across the boundary.

**Rotate** ([keys.go:234](../../internal/keys/keys.go#L234)):

1. Read the highest version N; generate key N+1 in the HSM **before** the DB transaction (keygen can be slow, MPC keygen very slow; do not hold row locks during it).
2. In one transaction: `SELECT ... FOR UPDATE` on the wallet row and its key rows, re-read the highest version, demote the active key to `sign_only`, insert N+1 as `active`.
3. If the transaction fails, destroy the new HSM key (`r.discard`), so no orphan key that the registry does not know about remains in the token.
4. If another rotation committed N+1 first, step 2 sees the version changed; the new key is discarded and Rotate retries (up to 3 times, then `ErrConflict`). So two concurrent rotations serialize: v1 -> v2 -> v3, never two active keys (`TestConcurrentRotate`).

**Retire** ([keys.go:307](../../internal/keys/keys.go#L307)): locks the key row, checks `sign_only -> retired`, updates the row, then destroys the private key (`C_DestroyObject`) **before commit**. If the destroy fails, the transaction rolls back and the key is still `sign_only` (retry later). If the commit fails after the destroy, a retry finds the object already gone (treated as success) and commits. Either way a `retired` row never has a live private key.

**Why destroy on retire?** "Retired" in the DB is only a promise kept by our code. Anyone with the token PIN (a bug, an insider, a stolen backup of the token directory plus PIN) could still call `C_Sign` directly. Destroying the object makes retirement a property of the hardware: the key cannot sign, ever. The public key and DB metadata stay, so old signatures can still be verified and the audit trail still names the address. MPC keys only change state here; deleting shares is T3/T4's decision.

**Audit**: create -> `wallet.created`, `key.generated`; rotate -> `key.generated`, `key.state_changed`, `key.rotated`; retire -> `key.state_changed`, `key.destroyed` (HSM only). Events are emitted after commit; an audit failure is returned to the caller as "done but not fully audited".

## 5. Gotchas hit

- Brew SoftHSM 2.7.0 accepted secp256k1 directly (it links OpenSSL 3); no P-256 fallback was needed. P-256 is still tested to prove the generic path.
- `C_FindObjectsFinal` must always run, even on error, because sessions are pooled.
- Retire ordering (destroy inside the tx, idempotent destroy) is what makes partial failures safe.
- Rotation concurrency: in Postgres READ COMMITTED, `FOR UPDATE` only locks rows that existed when the statement started, so the version is re-read in a separate statement after taking the locks.

## Quiz

1. Which two private-key attributes keep the scalar inside the token, and how do they differ?
2. Why are keys looked up by `CKA_ID` instead of the object handle from `C_GenerateKeyPair`?
3. What goes wrong if you sign an Ethereum digest with `CKM_ECDSA_SHA256`?
4. What format does `CKM_ECDSA` return, and what does Ethereum additionally need?
5. Why does Ethereum reject high-S signatures?
6. A request was created bound to v1 one second after v1 became `sign_only`. Can v1 sign it? Why?
7. Why is the new key generated before the rotation transaction, and what happens if the transaction fails?
8. Two rotations of the same wallet start at the same moment. What is the final state?
9. Why does Retire destroy the private key before committing instead of after?
10. Why keep the public key after retirement?
11. Which transitions return `ErrInvalidTransition`?

<details>
<summary>Answers</summary>

1. `CKA_SENSITIVE=true`: the value can never be read in plaintext. `CKA_EXTRACTABLE=false`: it cannot be exported even wrapped (encrypted) under another key. Both are one-way.
2. Handles are only valid for the running application and can change after restart; `CKA_ID` is stored in the object and stable. We keep it in `keys.hsm_key_id`.
3. The token hashes the digest again with SHA-256, so the signature covers `SHA256(keccak)` and no Ethereum node will recover the right sender.
4. Raw `r || s`, 32 bytes each (no DER). Ethereum needs low-S and a recovery id `v` (found by trial recovery).
5. `(r, N-s)` is also valid; accepting both lets anyone change a tx's signature (and its hash) without the key. EIP-2 accepts only `s <= N/2`.
6. No. A `sign_only` key signs only requests bound to it AND created before `sign_only_at`; this one came after, so `ErrKeyNotUsable`.
7. Keygen can be slow and should not hold row locks. On failure the new key is destroyed so the token has no key the registry does not know about.
8. Both succeed one after the other: v2 then v3 (v3 active, v1 and v2 `sign_only`). The loser sees the version changed, discards its key and retries. Never two active keys.
9. If the destroy fails, the rollback leaves the key `sign_only` and Retire can be retried. Destroying after commit could leave a `retired` row with a live private key if the process died in between.
10. To verify old signatures and keep the address in the audit trail and history.
11. `active -> retired`, `sign_only -> active`, `retired -> anything`, and any same-state "transition".

</details>

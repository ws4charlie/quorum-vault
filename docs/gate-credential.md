# Gate credential

[中文](zh/gate-credential.md)

AgentGate decides whether an AI agent may make a payment. QuorumVault holds the keys that make it. The Gate credential is the one document that joins them: a short-lived, signed permission for exactly one payment. The signing zone signs a payment from a Gate-governed wallet only when it carries a credential that verifies. This page is the contract; AgentGate and QuorumVault implement their sides from it and from the shared [test vectors](#test-vectors), and neither imports the other's code.

Status: the verifier package and the vectors are done. The zone checks, the signing API and the EIP-3009 kind are written here and built in later tasks, marked below.

## The credential

One JSON object. Every field is required; a field that is not in this table is refused.

| Field | Type | Format and limits |
|:---|:---|:---|
| `v` | integer | `1`. Any other value is refused |
| `kid` | string | Id of the Gate signing key. 1 to 64 characters of `A-Z a-z 0-9 . _ -` |
| `credential_id` | string | Unique per credential. Lower-case UUID text, `8-4-4-4-12` |
| `obligation_id` | string | Gate's id for the payment; one obligation may have several credentials. Opaque. 1 to 128 printable ASCII characters |
| `audience` | string | The Vault deployment, for example `qv-staging`. 1 to 64 characters of `a-z 0-9 . _ -`, starting with a letter or digit |
| `wallet_id` | string | The paying wallet's id in Vault. Lower-case UUID text |
| `chain` | string | CAIP-2 chain id. In version 1 only `eip155:<decimal id>`, no leading zero, for example `eip155:84532` |
| `asset` | string | `native` for the chain's coin, otherwise the token contract address as `0x` and 40 lower-case hex digits |
| `payee` | string | The recipient: `0x` and 40 lower-case hex digits. Mixed-case (checksum) text is refused, so there is one spelling |
| `amount` | string | Integer minor units (wei, token units) as decimal digits: no sign, no leading zero, no point, at least 1, at most 2^256 − 1 |
| `issued_at` | integer | Unix seconds, at least 1 |
| `expires_at` | integer | Unix seconds, after `issued_at` |
| `policy_version` | string | Opaque. 1 to 64 printable ASCII characters |
| `decision_reason` | string | Opaque. 1 to 256 printable ASCII characters |
| `sig` | string | The signature (below). Not part of the signed bytes |

"Printable ASCII" is the characters from space (0x20) to tilde (0x7E). Integers are written in plain decimal and stay below 2^53, so both sides hold them exactly. `obligation_id`, `policy_version` and `decision_reason` are never interpreted by Vault: they are recorded and echoed into the audit trail as they are. A credential larger than 4096 bytes is refused.

The parser is strict. It refuses a field that appears twice, an unknown field, a missing field, a value of the wrong JSON type (an amount written as a number, a time written as a string), a number with a sign, a point or an exponent, and any text after the object. Unknown fields are never ignored: a future version adds fields only with a new `v`.

## Encoding and signature

**Encoding: JSON Canonicalization (RFC 8785).** Both sides already speak JSON, and the rule is a standard that libraries exist for. Because every string above is printable ASCII and every number is a non-negative integer below 2^53, the RFC reduces to four rules, which a side without a library can write in a few lines: member names in byte order, no white space, integers in plain decimal, and only the quote and the backslash escaped (as `\"` and `\\`). A fixed field order would be as safe; JCS was chosen because a field added in a later version needs no new order table.

**What is signed.** The bytes `qv-gate-credential-v1`, a line feed, then the canonical form of the object without `sig`. The prefix separates these signatures from any other use of the key.

**Envelope.** The credential sent is the object with one more member, `sig`: the Ed25519 signature (RFC 8032) of 64 bytes, in base64url without padding. Padding, other alphabets and other lengths are refused. The verifier does not trust the order or layout of the text it received: it parses, recomputes the canonical form, and verifies that. A reordered or re-spaced copy of a valid credential therefore verifies.

**The signature covers `payee`, `amount`, `asset`, `chain`, `wallet_id`, `audience`, the times and the opaque fields.** Changing any of them after signing fails the signature.

## Keys and rotation

Gate signs with an Ed25519 key that exists only for this purpose. Vault holds public keys only, in the configuration of each checker in the signing zone (the gateway and both cosigners), never in anything the business side can write. A key is a `kid` and its 32-byte public key in base64url without padding. A node refuses to start with an invalid audience, no key, a bad `kid` or a wrong key length.

- **Several keys are active at once.** To rotate: add the new key to every checker, then Gate starts signing with it, then, after the old key's last credential has expired (the maximum lifetime plus the skew), remove the old key.
- **An unknown `kid` is refused** as `kid_unknown`. Vault never tries the other keys, so a credential cannot choose which key checks it. A credential that names one key but was signed by another fails as `signature_invalid`.
- **Retiring a key** is removing it. There is no revocation list: credentials live for minutes.

## Checks at the signing zone

Every checker in the zone runs these in order and stops at the first failure. Each failure has a stable code, is written to the audit trail and is returned to the caller. There is no flag, build option or setting that turns a check off.

| # | Check | Code | Field |
|:--|:---|:---|:---|
| 0 | The wallet is Gate-governed. A credential for any other wallet is refused, so a misconfiguration is loud | `wallet_not_gate_governed` | |
| 1 | A credential is present | `credential_missing` | |
| 2 | It parses under the strict rules above | `credential_malformed` | the field |
| 3 | `kid` is in the key set | `kid_unknown` | `kid` |
| 4 | The signature verifies over the signed bytes | `signature_invalid` | |
| 5 | `audience` equals this deployment's name | `audience_mismatch` | `audience` |
| 6 | `wallet_id` equals the paying wallet | `wallet_mismatch` | `wallet_id` |
| 7 | `expires_at − issued_at` is at most the maximum lifetime | `ttl_too_long` | `expires_at` |
| 8 | `issued_at` is not later than now + skew | `not_yet_valid` | `issued_at` |
| 9 | now is earlier than `expires_at` + skew | `expired` | `expires_at` |
| 10 | `chain`, then `asset`, then `payee`, then `amount` equal what the zone decoded from the bytes it will sign | `payment_mismatch` | the first that differs |
| 11 | For EIP-3009: the authorization's own window lies inside the credential's | `authorization_window` | |
| 12 | `credential_id` was not used before at this checker; the record is written in the same transaction as the decision | `replayed` | |
| 13 | The payment is within the wallet's fast-lane limits | `fast_lane_cap` | |

Checks 1 to 11 are pure and are implemented and tested in this task; checks 0, 12 and 13 need the zone's state and are built in the zone-enforcement task. The zone trusts nothing beside the payload: step 10 compares with what the zone itself decoded, never with a request field.

**Clock.** Each checker uses its own clock. The skew allowance is 30 seconds by default and configurable up to 5 minutes; it widens both ends of the window.

**Maximum lifetime.** 10 minutes by default; configurable between 1 second and 1 hour. A credential is a bearer permission until it is used, so the shorter the life, the less a stolen one is worth, and the shorter the replay records must live. Gate needs seconds to mint and call; minutes is room enough for one retry.

## What a credential is bound to

Vault decodes the payload it is about to sign and builds the payment `{chain, asset, payee, amount, wallet_id}` from the bytes. Strings are compared exactly, after the zone writes addresses in lower case.

| Payment kind | `chain` | `asset` | `payee` | `amount` | Conditions |
|:---|:---|:---|:---|:---|:---|
| EVM native transfer | the transaction's chain id | `native` | `to` | `value` | no calldata |
| EVM token transfer | the transaction's chain id | `to` (the token contract) | first argument of `transfer(address,uint256)` | its second argument | `value` is 0; the calldata is exactly this call; `approve`, `transferFrom` and other calls are not payable with a credential |
| EIP-3009 `transferWithAuthorization` (built in the x402 task) | `domain.chainId` | `domain.verifyingContract` | `to` | `value` | `from` is the paying wallet's address; `validAfter` is at least `issued_at` and `validBefore` at most `expires_at`; `validAfter` is before `validBefore` |

One credential pays one payment. A second payload under the same `credential_id` is refused.

## Gate-governed wallets and the fast lane

A **Gate-governed wallet** is marked in a signed setting of the signing zone: a quorum of zone operators signs it, it is versioned, and the gateway and every cosigner enforce it. A Gate-governed wallet pays nothing without a verified credential, by any path. Other wallets keep today's rules. **Internal moves** (sweeps, refills, drains, cold moves, consolidations, rebalances) need no credential.

With a valid credential, a payment from a Gate-governed wallet needs no human approval (Gate's approval is the approval), if it is within all three limits of the same signed setting, kept per wallet and asset in that asset's minor units:

| Limit | Meaning |
|:---|:---|
| per payment | the largest single `amount` |
| per hour | the total of credential-only payments in the last 60 minutes |
| per day | the total of credential-only payments in the last 24 hours |

Above any limit the payment is refused as `fast_lane_cap`; there is no fallback to a human approval in this version. An asset with no limit set has all three at 0. A signed authorization counts when the zone signs it, not when it is used on chain. Each checker counts from its own records, and any one refusing stops the signature.

## The signing API

*Implemented in a later task; the shape is fixed here.* Gate calls Vault; Vault never calls Gate. The caller is the AgentGate service, authenticated by its own client certificate with a role that allows this one call.

**Request.** One JSON object: `wallet_id`; `kind`, either `evm_transfer` or `evm_eip3009`; `payload`, the thing to sign (for `evm_transfer` the unsigned transaction, for `evm_eip3009` the EIP-712 typed data; the exact encodings are fixed with the API); and `credential`, the credential object as above.

**Response.** On success, 200 with `credential_id`, `wallet_id`, `kind`, and the signature. On refusal, an error object with `code` (from the table), `field` when there is one, and a message; never a signature.

| Status | Codes |
|:---|:---|
| 400 | `request_invalid`, `credential_missing`, `credential_malformed` |
| 403 | `client_not_authorized`, `wallet_not_gate_governed`, `kid_unknown`, `signature_invalid`, `audience_mismatch`, `wallet_mismatch`, `ttl_too_long`, `not_yet_valid`, `expired`, `payment_mismatch`, `authorization_window`, `fast_lane_cap` |
| 409 | `replayed` |
| 422 | `payload_invalid` (the zone cannot decode the payload into a payment of this kind) |
| 503 | a refusal that may succeed on retry, such as a checker being unreachable |

**Idempotency by `credential_id`.** The same request again (same `wallet_id`, `kind`, `payload` and credential) returns the stored result and never signs a second time. The same `credential_id` with a different payload is refused as `replayed`. Only successes are stored. If a signature was made but its answer was lost before it was stored, the retry is refused by the checkers; Gate then mints a new credential with a new `credential_id`.

## Replay records and audit

Each checker records every `credential_id` it accepts, in its own guard database, with the decision, and a second use is refused (the first use wins, atomically). A record is kept until `expires_at` + skew + 1 day; pruning removes nothing that could still verify, and the extra day is for troubleshooting. The business core keeps its own table, which serves the API's idempotency and is not the rule.

Every accept and every refusal is written to the checker's audit trail in the same transaction as the decision: `credential_id`, `obligation_id`, `policy_version`, `decision_reason`, `wallet_id`, the payment, the error code and field, and which checker. A credential that did not parse is recorded by size and hash only, since its text is not trusted.

## Test vectors

`testdata/gate-credential/vectors.json` holds a fixed clock, a key set of two keys with their `kid`s, and named cases, each with the exact credential text, the signed bytes in hex, the payment the zone decoded and the expected result with its code. It covers a valid credential for each payment kind, a credential signed by the second key, every refusal above that needs no state, and a replay pair. AgentGate copies the file unchanged; both repositories must pass every case. The keys are derived from public strings and are marked TEST ONLY; nothing else in either repository holds key material for this contract.

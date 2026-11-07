# P7-3 — The Bitcoin verifier and the guard

The signing zone (gateway, and party B's cosigner, which runs the same code from its own config and guard database) can decide whether to
sign one input of a Bitcoin transaction, with no chain access and without trusting the business zone. No broadcasting here: that is P7-4.

## The payload and the digest

[Payload](../../internal/chain/btc/payload.go) is strict JSON (unknown fields refused): `version`, `locktime`, `inputs` (txid, vout, value in
satoshis, derivation `path`, `sequence`), `outputs` (address, value). The input a job signs is not in it: it follows from the job's key
reference and digest. The key reference is the path, `"<branch>/<index>"`: branch 0 is the deposit branch, branch 1 the hot shards, below the
account key m/84'/coin'/0'.

[`btc.BuildUnsigned(payload, account)`](../../internal/chain/btc/unsigned.go) returns the transaction, its txid and the BIP143 digest of every
input. P7-4 builds jobs with it and the verifier checks them with it, so both compute the same digests. It takes the account xpub because
every input's script is the P2WPKH of the key derived from it at the input's path. It uses btcd's `CalcWitnessSigHash`; the published BIP143
native P2WPKH vector and a second, independent implementation written from the BIP text on random transactions both agree with it.

SIGHASH_ALL is the only type, by construction: the digest is computed with it fixed. A digest over SIGHASH_NONE, SINGLE or ANYONECANPAY is
a different number, no input's digest, and the verifier refuses it (tested). The assembler appends the byte 0x01 to the signature.

## What Verify checks, per job

1. The payload is version 2, locktime 0, every sequence is 0xfffffffd (signals RBF, no relative lock), 1 to `max_inputs` inputs, no
   outpoint twice, every path on branch 0 or 1 with a non-hardened index.
2. The job's digest is the sighash of exactly one input, and the job's key reference is that input's path. The key of every input
   is derived from the zone's xpub; nothing about key ownership comes from the business zone.
3. Outputs are P2WPKH, P2WSH, P2TR, P2PKH or P2SH for the configured network, none below the dust limit of its form; no `OP_RETURN` (an
   output is an address, a script field is refused as an unknown field).
4. Fee = inputs minus outputs, at most `max_tx_fee_sats`, and at most `max_fee_rate` satoshis per virtual byte of the transaction with
   P2WPKH witnesses (the estimate is never below the real size).
5. **Every kind is bound to the partition it names**, as the EVM verifier binds the sender: the job's key partition equals the intent's, and the
   partition must have a pinned shard in the zone's config (its ID parsed with `partition.Parse`: entity/chain/BTC/hot/pool/shard). By intent kind:

| Kind | Inputs | Outputs |
|---|---|---|
| withdrawal | every input at the partition's own shard path | first output: exactly the amount to the intent's destination; at most one more, change to **that same shard** only |
| to-cold | as withdrawal | as withdrawal; the destination is the cold address of the partition's **pool** (`<pool>/native`), not any cold address |
| consolidate | at least two, every input at the partition's own shard path | one output, to the partition's own shard; the intent's destination is that shard and its amount is the sum of the inputs |
| sweep | branch 0, every input is the intent's `From` | one output, to the partition's own shard |
| cancel | any (the guard binds them, see below) | one output to the partition's own shard. Nothing else |

A consolidation moves no value, so a compromised core can cost only fee with it: at most `consolidations_per_hour` times `max_tx_fee_sats` an hour (see
[p7-6d-btc-consolidation.md](p7-6d-btc-consolidation.md)).

There is no rebalance on Bitcoin: the kind falls to the default refusal, and a config with two hot shards in one pool does not start. Because a withdrawal or to-cold spends only the partition's own shard key and a sweep or cancel only one address, one transaction
has one key (and several outpoints, each a claim with its own pin).

**Sweep amount.** The intent's amount is the sum of the inputs: what leaves the deposit address, before the fee. The output is that amount minus
the fee, so the ledger moves the amount and books the difference to the fee account.

**The guard's view** ([BTCCodec](../../internal/gateway/btccodec.go)): claims are outpoints `<txid>:<vout>`; pins are the input values; the
transaction identity is the txid; there is one fee component, the absolute fee; the sender is the path of the first input (the same for every job
of one transaction, which the guard's "same sender" rule needs); `OwnsSender` is true for a valid path on an allowed branch (derivation, not a
list of addresses); `CheckSigner` compares the key that would sign with the derived key of the input being signed; `Canonical` decodes an
address for the configured network and refuses another network's (the allowlist and the pinned addresses use it; case of bech32 never matters).

## The segwit v0 fee attack, and the pins

BIP143 commits a signature to its own input's value only. Take real values A = 150,000 and B = 150,000 sats and outputs of 200,000: the
fee is 100,000, over the cap. Payload P_A says A = 150,000 and B = 70,000 (fee 20,000, passes every check); P_B says A = 70,000 and B = 150,000
(fee 20,000, passes). A's signature under P_A and B's under P_B are both valid for the one real transaction. Both payloads have the same txid.

Closed in the guard, chain-neutrally ([decider.go](../../internal/gateway/decider.go)):

- **Pins.** A claim carries an opaque pin set by the codec (Bitcoin: the input's value). A claim that exists and is named again with another pin
  is refused (`replay_pin_changed`), in every path and for every intent. Here the second signature names A with 70,000 against the 150,000 the first
  one pinned. Also refused with two intents.
- **Identity.** A transaction identity signed under one payload hash is refused under another (`replay_identity_reused`), on any intent. A replacement
  is a new transaction, so it has a new txid.

Upgrade of a guard database: `store.sql` adds `exclusive_claims.pin` (default empty: EVM claims have none) and `signed_digests.tx_identity`, nothing is
rewritten, and the P7-1 upgrade test still passes.

## Replacements and cancel

A later attempt of an intent spends exactly the same inputs with the same pins, keeps destination and amount (the intent hash is part of the check),
and pays more: the guard's same-claims rule and `FeesRaised` give that, so at most one transaction of an intent can confirm.

**A cancel may only spend what is claimed.** A cancel needs no approval, and the verifier has no database, so it cannot tell a claimed input from a
stranger's. The guard does, through the codec (`StrictCancelCodec`, true for Bitcoin, not for EVM, where a cancel may free a reserved nonce nothing
was signed at): every claim of the cancel must already exist (with the same pin, checked before), all under one signed intent, of the cancel's own
partition (the guard records the partition of each intent), and together they are all of that intent's claims. Otherwise `replay_cancel_claims`.
Without it a cancel could spend any input, a deposit output included, under no intent.

A refused attempt can leave signatures behind (input 0 signed, input 1 refused; "signing failed twice"). Bitcoin has a cancel for that: a
transaction that spends the same inputs back to a pinned hot shard, taking over the claims as on EVM (the pins must be the same). Once it is
signed, the half-signed transaction can never be finished at the guard (`replay_nonce_cancelled`) and can never confirm. This task verifies it;
`BuildCancel` is P7-4 and returns `ErrNotSupported` only when nothing of the attempt was ever signed.

## Signing under many keys

A partition's signer for Bitcoin is a key tree: signer entry `backend: "mpc"` with `keyset_id` and `hardened_path` (the account path) instead of
`key_id` and `public_key`. For a job, the gateway takes the path from the key reference and asks party A to `Derive` it (idempotent: the same key
id and public key come back), then signs through that key. `gateway.CheckSigners` refuses to start unless every Bitcoin hot partition has such a signer
on the account path of the network. Party B's cosigner needs nothing: it checks the key party A names against its own derivation.

## Every attack and its refusal

| Attack | Refused as |
|---|---|
| Combined-signature fee attack, one intent or two, either order | `replay_pin_changed` (guard, and again at the cosigner) |
| Same txid, same values, another payload (an input under another key) | `replay_identity_reused` |
| Change to an unpinned address | `tx_mismatch`: not the partition's own shard |
| A third output | `tx_mismatch`: at most the payment and one change |
| Destination changed; amount off by one satoshi; payment hidden as the second output | `tx_mismatch`: the first output pays ... the intent is ... |
| Input key outside the xpub (the key named is not the derived one) | `ErrSigner` at the gateway, `signer_key_mismatch` at the cosigner |
| Path outside the allowed branches (branch 2, three levels, hardened) | `tx_mismatch`: derivation ... |
| A deposit input in a withdrawal | `tx_mismatch`: not on branch 1 |
| Digest of an input the job does not name; an unrelated digest; a digest over another SIGHASH | `tx_mismatch`: the digest is for input n ... / is the sighash of none of the inputs |
| Fee above the cap; fee rate above the cap; too many inputs | `tx_mismatch`: exceeds the cap / sat/vB / the limit |
| Dust output; `OP_RETURN` (a script field, or an output with no address) | `tx_mismatch`: below the dust limit / unknown field / output n |
| Locktime set; version 1; RBF not signalled (0xffffffff or 0xfffffffe) | `tx_mismatch` |
| Same outpoint under two intents | `replay_nonce_taken` |
| A replacement with different inputs, one input fewer | `replay_nonce_changed` |
| A replacement with a lower fee | `replay_fee_not_higher` |
| A replacement that changes destination or amount | `replay_intent_conflict` (the intent hash differs) |
| Cancel with an extra output; cancel to an unpinned address | `tx_mismatch` |
| Cancel with another value for an input | `replay_pin_changed` |
| Finishing a half-signed attempt after its cancel | `replay_nonce_cancelled` |
| Wrong-network destination in the intent; in the payload; in config (xpub, cold address, allowlist entry, hot shard off its path, missing cap) | `tx_mismatch` / the zone refuses to start |

Tests: [btc/verify_test.go](../../internal/chain/btc/verify_test.go) (the verifier alone), [gateway/btc_test.go](../../internal/gateway/btc_test.go) (guard, replacements,
cancel, config), [cosigner/btc_test.go](../../internal/cosigner/btc_test.go) (a rogue gateway), and `e2e/btc/sign_test.go` (a two-input transaction
under two different MPC-derived keys, a withdrawal under the hot shard's key and a sweep under a deposit address's key, through the gateway and the cosigner on real mpc-party, validated by `txscript`).

# Spike: Taproot (P2TR key-path) for MPC keys

**Recommendation: no-go for now.** One wallet is worth a second look later: the hot shard, if consolidation-heavy traffic grows. Deposits and cold are no-go. The blocker is not Bitcoin but our signing stack: cb-mpc v0.2.2 has no HD Schnorr and no tweak, and the cold HSM path has no BIP340.

Question: should hot shards, deposit addresses or the cold wallet move from P2WPKH to P2TR key-path spends, signed with the 2-party BIP340 Schnorr we already wrap? Evidence is from this repo at commit 3d08180 (cb-mpc v0.2.2 source in `mpc-party/.deps`) and the public sources at the end. Statements about other exchanges' current behaviour come from trackers and press, not their documentation, and need checking before anyone relies on them.

## What each wallet would need

| Wallet | Key today | What P2TR needs | Verdict |
|---|---|---|---|
| Deposits | 2-party HD ECDSA, non-hardened path `[0, i]`, address derived by the core from the account xpub | An HD Schnorr key, so every customer gets an address from the public key alone | Blocked: no HD for Schnorr in cb-mpc |
| Hot shards | 2-party HD ECDSA, path `[1, i]`, pinned in the zone | One non-HD BIP340 key per shard (exists), tweaked | Possible, with new keysets |
| Cold | ECDSA key in a SoftHSM token, signed offline | A PKCS#11 BIP340 or raw-scalar signature | Blocked: no standard mechanism |

## What cb-mpc and the zone offer

- **BIP340 2-party signing exists, non-HD.** `DKGBIP340`, `Sign`, `XOnlyPublicKey` wrap `schnorr_2p` (the BIP340 variant). The key blob holds a role, the curve, the compressed public key and one additive scalar share (`cb-mpc:api/schnorr2pc.cpp`).
- **No HD for Schnorr.** HD keysets exist only for ECDSA and Ed25519 (`hd_keyset_ecdsa_2p`, `hd_keyset_eddsa_2p`). A derived ECDSA key is an ECDSA key (it carries the Paillier material) and cannot sign BIP340. Deposit addresses per customer would need either one key per customer (a DKG each: not viable at our scale) or our own derivation on top of cb-mpc internals.
- **No tweak.** The words "tweak" and "taproot" do not occur in the cb-mpc source. The BIP341 key-only tweak (no script tree) is additive: `Q' = P + t·G`, with `t = taggedhash("TapTweak", P_x)`, and `P` first negated when its y is odd. On additive shares this is easy in principle: negate both shares if needed and add `t` to one share. But cb-mpc gives no call for it. We would have to rewrite the key blob (`x_share` of one party and `Q`) in our wrapper, which is an undocumented internal format that every cb-mpc upgrade could break, and a second party must agree on the same tweak. That is exactly the kind of change the Schnorr code path's audit would have to cover.
- **The zone.** The verifier, the sighash code (`BuildUnsigned`, BIP143) and the guard know only P2WPKH inputs and an ECDSA signer key. P2TR needs BIP341 sighash with all previous outputs, a 64-byte signature check, a `SignerKey` that is x-only, and new rules for dust, vsize estimates and the fee-bump reserve. The cosigner shares this code.
- **The cold signer.** It signs ECDSA through PKCS#11 (SoftHSM). SoftHSM lists RSA, ECDSA, DSA, EdDSA, GOST and MAC mechanisms; no search turned up a BIP340 mechanism in PKCS#11 or SoftHSM. A Taproot cold wallet would need a different signer or a vendor extension.

## What it saves

Sizes from Bitcoin Optech: a P2WPKH input is 68 vbytes and a P2TR key-path input 57.5, an output 31 against 43. Taproot saves about 10.5 vbytes per input and costs about 12 per output. A 2-in 2-out transaction is 208.5 vbytes as P2WPKH and 211.5 as P2TR, so a withdrawal gains nothing. Only input-heavy transactions win: a consolidation of 20 inputs into one output saves about 200 of roughly 1,400 vbytes (about 15%), or 10 sats per 1 sat/vB of fee rate per input. At the 5–10 sat/vB our tests assume that is 50–100 sats per saved input; at 50 sat/vB it is 525 sats. Real savings would be on consolidation and cold moves only.

Privacy: a key-path spend looks like any other P2TR spend, and a single-sig wallet does not stand out from an MPC wallet, as it does not with P2WPKH today. Batches and consolidations remain identifiable by their shape.

## What it costs

- New keysets and new addresses for each wallet; deposit customers would need new addresses, and old coins stay on P2WPKH until swept, so both formats run side by side for a long time.
- A migration of pinned addresses in the zone, the core and every cosigner, with the same-config rule ([fee caps](../runbooks/btc-fee-caps.md)) extended to P2TR sizes.
- A re-audit of `schnorr_2p` and of our tweak code, and a second signing path in the verifier, the guard, the cosigner and the cold signer.
- Tests: new golden vectors (BIP341 test vectors), every recovery test again for P2TR (bump, cancel, CPFP, batch), and a regtest e2e per wallet.
- Unknowns we did not measure: BIP340 2-party signing latency in our network, and whether cb-mpc's BIP340 key can be refreshed and backed up (PVE) like our ECDSA keys.

## What exchanges do

Evidence is mixed and dated. Kraken is reported to support P2TR withdrawals and, on request, deposits; Coinbase reportedly allowed sends to `bc1p` addresses only in October 2024 and does not take Taproot deposits; Binance's position is unsettled in these sources, with an older report of a withdrawal to a `bc1p` address being refused. The main obstacle named is software that cannot build transactions to bech32m addresses. For us this matters as the destination of customer withdrawals: our own destination checks already decode P2TR (`DustLimit` and `MaxTxVSize` count it), so paying to Taproot works today, and nothing here depends on our own wallets being Taproot.

## Recommendation

No-go. The saving is small for a withdrawal-shaped workload, the deposit wallet cannot be built without HD Schnorr, the cold wallet has no signer, and the hot wallet needs a tweak that cb-mpc does not provide. Revisit when one of these changes:

1. cb-mpc adds HD Schnorr and a BIP341 tweak, or accepts a public additive tweak in `sign`.
2. Consolidation or cold-move fees become a large share of cost.
3. A cold signer with BIP340 is chosen for other reasons.

If it becomes go, split it as: (a) a spike on the tweak with BIP341 vectors against a patched or upstream cb-mpc; (b) hot shard only: the zone's P2TR verifier, sighash and guard, behind a config switch; (c) consolidation and to-cold moves spending P2TR; (d) deposits and cold last, each its own task.

## Sources

- BIP 340 (Schnorr signatures), BIP 341 (Taproot, key tweak), BIP 86 (key-path-only derivation), BIP 350 (bech32m): <https://github.com/bitcoin/bips>
- Bitcoin Optech, June 2021 newsletter, input and output sizes: <https://bitcoinops.org/en/newsletters/2021/06/30/>
- Bitcoin Optech, preparing for Taproot: <https://bitcoinops.org/en/preparing-for-taproot/>
- Bech32 adoption: <https://en.bitcoin.it/wiki/Bech32_adoption>
- Taproot support by exchanges (trackers and press, to be checked against each exchange): <https://www.spark.money/tools/bitcoin-segwit-adoption-tracker>, <https://unchainedcrypto.com/coinbase-activates-bitcoin-taproot-transfers/>, <https://www.crowdfundinsider.com/?p=200147>
- SoftHSM mechanisms: <https://www.mintlify.com/softhsm/SoftHSMv2/pkcs11/mechanisms>
- In this repo: `mpc-party/README.md`, `mpc-party/internal/cbmpc/sign.go`, cb-mpc v0.2.2 `cb-mpc:src/cbmpc/api/schnorr2pc.cpp` and `cb-mpc:src/cbmpc/protocol`.

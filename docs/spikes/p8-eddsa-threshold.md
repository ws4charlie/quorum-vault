# Threshold Ed25519 (2-of-3) in the cb-mpc wrapper: go or no-go

Solana hot keys are meant to be 2-of-3 Ed25519 keysets on parties A, B and C, the way EVM hot keys are 2-of-3 ECDSA since E23. This note says whether cb-mpc's multi-party EdDSA is fit for that, after wrapping it, testing it and reading its source. cb-mpc stays at v0.2.2. Numbers are in [the measurements](../measurements/mpc.md); the source review is in `mpc-party/UPSTREAM_REVIEW.md`.

## Recommendation: go, with conditions

The library does what P8 needs through its public API, the wrapper holds the same standard as the ECDSA threshold calls, and no security problem turned up. Threshold signing is as fast as the 2-party Ed25519 path or faster, far below the 3x limit set for this task. The conditions are about how little outside review this code has had, and about one property of Ed25519 here: signatures are randomized.

| Question | Answer |
|---|---|
| Does cb-mpc support Ed25519 with an access structure, so any two of three sign while DKG and refresh need all three? | Yes. `eddsa_mp` has the same API and key blob as `ecdsa_mp`: DKG, refresh and signing with an access structure, no HD |
| Are the signatures standard? | Yes. Go's `crypto/ed25519` verifies them (RFC 8032 verification) for every pair and both receivers. A Solana validator accepts them |
| Fast enough? | Yes. Sign is about as fast as 2-party Ed25519 and costs a fraction of ECDSA's: three messages, no oblivious transfer |
| Security review | No defect found. Gaps listed below |

## What differs from the ECDSA threshold calls

- **One wrapper, two schemes.** A threshold key now carries its scheme. DKG, refresh, sign, self-test, load, backup and restore are the same calls with the scheme as a parameter; the ECDSA entry points keep their names and behaviour. The transport (a mesh of pairwise links), error kinds, secret handling, wipe and cancellation are shared, not copied.
- **Messages, not digests.** Ed25519 signs the whole message (a Solana transaction message), not a 32-byte hash. The wrapper accepts messages up to a fixed cap well above the largest Solana message.
- **Randomized signatures.** cb-mpc's EdDSA draws fresh nonces, so signing one message twice gives two different valid signatures. That is fine for Solana, but the custody layer must sign a message once, store the signature, and rebroadcast the stored one. A retry through another pair must not re-sign.
- **The signature goes to one receiver.** As with ECDSA, only the chosen receiver gets it; the other signer learns nothing about success.
- **Backup is the same.** One scalar per member, encrypted to the offline recovery key per generation with the existing single-recipient proof of correct encryption, on the Ed25519 curve; the scheme is part of the backup label, so an Ed25519 backup cannot be restored into an ECDSA slot. Restoring a lost member, refreshing and running the self-test works as for ECDSA.

## How it was tested

Every pair signs with both receivers, over memory links and over loopback TCP. Refresh keeps the public key and changes the shares, and old and new shares never mix: a mixed pair never produces a signature. Malicious peers: every message of DKG, signing, refresh and the self-test is corrupted, truncated, emptied, extended or replayed, and an honest member always ends in a cryptographic or transport error, never a wrong signature. Also covered: 32 concurrent signing sessions under the race detector, fuzzing of the new entry points, and a golden fixture that pins the key blob layout the shim copies from cb-mpc.

## Open finding from E23-3, checked for Ed25519

In ECDSA pair signing, a single flipped byte in the middle of the third message was ignored about half the time. Every signature that came out still verified, so it is no signature risk, but it means part of that message is not checked. Ed25519 signing does not show it: no corrupted message at any position was tolerated in the tests. The ECDSA finding is still open and not reported upstream.

## Conditions

1. **Self-test after every DKG and refresh**, on all three, before old shares are dropped. Same rule as E23-2: refresh can succeed and leave shares that do not sign together.
2. **Sign once, store, rebroadcast.** The service keeps the first signature per job and never produces a second one for the same message because a pair failed. Decide, before P8-2, what a retry through another pair does.
3. **Small hot balances and independent cosigner checks stay.** Two compromised members hold the key; that is the 2-of-3 model, and B and C each judging every intent in their own trust domain is what protects it.
4. **Get an outside look at `eddsa_mp` before balances grow.** The signing protocol is short and readable, but we know of no outside review of it, the access-structure layer is newer than the one audit, and the protocol specification could not be read for this review (the files in the checkout were not fetched).
5. **Re-read at every pin change.** Watch upstream advisories and issues; a Schnorr signing bug fixed in v0.2.2 (output written before verification) shows this area moves.

## Limits

- Abort is without blame: an error does not name the cheating member, and the non-receiver of a signature cannot tell whether it was good.
- The load path checks the share against its own point but not the group key against all shares; every signing and the self-test do.
- Not measured: slow or lossy networks (add one round trip per message on a real link), more than three parties, memory use.
- The 2-party Ed25519 path that will hold deposit keys is unchanged and was not reviewed again here.

# Upstream review before pinning (P5b-1, 2026-11-04)

Question: pin v0.2.2, or something newer? Result: **pin v0.2.2 (`2f2c4f1`)**. Go decision from P5a unchanged.

## Tags and HEAD

| Item | Result |
|---|---|
| Tags / releases | `v0.2.2` (2026-09-01) is the newest; before it v0.2.1, v0.2.0, v0.1.1, cb-mpc-v0.1.0 |
| `v0.2.2..HEAD` | one commit, `0b71670` "fix: harden refresh and backup integration guidance (#137)" |
| Files in that commit | README, SECURE_USAGE.md, demo-api/pve/*, header comments in `include/cbmpc/api/ecdsa_2p.h`, `api/pve_batch_ac.h`, `api/tdh2.h` and the C API twins. **Nothing under `src/`**: no change to ECDSA-2PC, HD keysets, Paillier, ZK, Ed25519 or Schnorr code |
| Decision | HEAD is documentation only; a tag is a better pin than an untagged commit. Stay on v0.2.2 |

Read in the docs-only commit, relevant to us (we follow all of it):
- **Refresh coordination** (`SECURE_USAGE.md`): "a successful local refresh call does not confirm that every party has switched". Matches what our tests found: see README "Things you must know" 1-2 and `Keyset.SelfTest`.
- **ECDSA-2P P1 backup limitations**: PVE verifies `X mod q` only; after refresh P1's exact share can exceed q and its stripped blob keeps the Paillier private key and `c_key`; `attach_private_scalar` for P1 checks the exact Paillier plaintext. Our `Split`/`Join` implements exactly that (exact x from `c_key`), and `TestBackupRestoreBothParties/ecdsa-after-refresh-x-over-q` covers it.
- PVE-AC / TDH2 partial decryptions are sensitive: not used by us (single-recipient PVE only).

## GHSA-h3cp-c5xm-jjj8 (re-read, via the GitHub security-advisories API)

"Security vulnerabilities in ECDSA-2PC", severity high, published 2026-10-27, last updated 2026-10-27. Affected `>= 0.1.0, < 0.2.2`, patched `0.2.2`. Two bugs: key generation (fixed in 0.1.1) and signing (fixed in 0.2.2); "may affect the security of ECDSA-2PC keys **when a protocol participant acts maliciously**". Reporters: Pranamya and Cantina (keygen), 99poros via HackerOne (signing). "Coinbase production environment is unaffected." No CVE, no technical details, `vulnerable_functions` empty. **No new detail since P5a.** "Upgrading does not reverse any prior key compromise": irrelevant, we have no key from < 0.2.2.

Consequence for us: the library is young (two soundness bugs in the protocol we use, found 19 months after the audit). Our threat model already assumes one party may be compromised, which is the model these bugs live in; hot balances stay small; party B re-verifies every intent (P5b-3); keep watching the advisories page.

## Cure53 audit (`docs/cure53-audit.pdf`)

The file in the repo is a Git LFS pointer (131 bytes). I downloaded the real PDF (622,992 bytes) from `media.githubusercontent.com/media/coinbase/cb-mpc/v0.2.2/docs/cure53-audit.pdf`, checked its SHA-256 against the pointer's oid (`86eb1a46…78e3a`, equal), and extracted the text with `pypdf` in a throwaway venv. Read in full (21 pages as printed, "CBS-02", Cure53, 21 March 2025). Nothing here is from a web summary.

- Scope: audited commit `abcea54` (Q4 2024, 25 days, 3 testers). High priority: EdDSA, Ed25519, commitments, DRBG, secret sharing, **MPC protocols, Paillier**, RSA, ElGamal, ECC, **ZK**, BigNum. The HD keyset layer, the `api/` wrapper layer, PVE batch API and the 2-party ECDSA signing fixes of 2026 did **not exist or were not the focus**: v0.2.2 contains much code the audit never saw.
- 9 findings, 2 vulnerabilities, all marked fixed and verified by Cure53 on 2025-01-06:

| ID | Severity | What | Touches code we use? |
|---|---|---|---|
| CBS-02-004 | High | `ECC-Refresh-MP` does not check that received points are in the prime-order subgroup (`src/cbmpc/protocol/ec_dkg.cpp`) | **No**: that is the multi-party refresh. We use 2-party refresh (`hd_keyset_*_2p`, `ecdsa_2p`). Same class of check (curve.check on received points) matters for our 2PC; upstream tests cover rejection |
| CBS-02-003 | Low | `ECC-Refresh-MP` lacks consensus check on sid / Q / Q_j | No (multi-party). Relevant lesson: sid agreement. We always use jointly generated sids (never pass our own) |
| CBS-02-006 | Medium | `paillier_t::generate` lacks p != q and gcd(N, (p-1)(q-1)) = 1 checks | **Yes**: P1's Paillier key in every ECDSA keyset. Fixed upstream |
| CBS-02-001 | Info | Ed25519 signing uses random nonces (RAND_bytes), a Schnorr variant with EdDSA formatting; nonce reuse would leak the key | **Yes** (Solana). Documented effect: signatures are randomized (we store the first). In 2PC both parties contribute nonce shares |
| CBS-02-002 | Info | `mod_t::_inv` has variable-time branching | Used by everything; fixed upstream; side channels stay a risk of an HSM-less host (shares live in process memory) |
| CBS-02-005, -008, -009, -010 | Info | spec/code tag naming, missing parameter checks in `fischlin.h` / `small_primes.h`, batch-exponentiation performance hints, typos | `small_primes.h` bound check is in the Paillier ZK path; fixed upstream |

- Conclusion of the report: no algorithmic errors or major omissions found in scope; "all outstanding security issues fully addressed" as of 2025-01-06.
- Reading for our decision: the audit is evidence about the library core as of Dec 2024, not about v0.2.2's ECDSA-2PC signing path, which the 2026 advisory shows still had a soundness bug. **It does not change the go decision**; it reinforces conditions 1 and 4 of the spike (watch upstream, small hot balances, party B verifies intents).

---

# Multi-party ECDSA (`ecdsa_mp` with an access structure) for 2-of-3 (E23-1, 2026-11-08)

Question: is the threshold ECDSA of v0.2.2 fit to hold EVM hot keys 2-of-3? Result in [docs/spikes/e23-threshold.md](../docs/spikes/e23-threshold.md): **go with conditions**. Source read at the pinned commit `2f2c4f1` (no move of `cbmpc.pin`); GitHub state read on 2026-11-08 (`gh api`).

## What it is (confirmed from source)

| Item | Finding |
|---|---|
| Public API | `include/cbmpc/api/ecdsa_mp.h`: `dkg_ac`, `refresh_ac`, `sign_ac`, `get_public_key_compressed`, `get_public_share_compressed`, `detach_private_scalar`, `attach_private_scalar`. No HD. secp256k1 and P-256 only |
| Names | The lead's reading was right. DKG and refresh: "all parties in `job.party_names` must be online"; `quorum_party_names` says who contributes (we pass all three). Signing: "only the parties in `job.party_names` need be online", and any subset that satisfies the access structure works, in any combination |
| Protocol, DKG / refresh | `key_share_mp_t::dkg_or_refresh_ac`, `src/cbmpc/protocol/ec_dkg.cpp`; spec `ec-dkg-spec.pdf` §4.3 "EC-DKG-Threshold-MP" and "EC-Threshold-Refresh-MP", after Chen-Lindell 2024 (CL24, per upstream issue #61). Each quorum member shares a random secret over the access-structure tree (Feldman-style: public points for every internal node), commits to the points and a batch discrete-log proof, then opens. Everybody checks the opening, the proof, `curve.check` on every point, and its own share against the ancestors' public data. Refresh is the same with a sharing of ZERO: the root point is forced to infinity, not read from the message |
| Protocol, signing | `ecdsa_mp.cpp` (`ecdsampc::sign`), spec `ecdsa-mpc-spec.pdf`, theory note says: based on Haitner, Lindell, Nof, Ranellucci, "Fast Secure Multiparty ECDSA with Practical Distributed Key Generation and Applications to Cryptocurrency Custody" (CCS 2018, eprint 2018/987), rev. 2023-05-29, with the multiplication of Haitner-Makriyannis-Ranellucci-Tsfadia (Eurocrypt 2022) over random-sender OT. **Full-threshold among the signers**: `sign_ac` first turns this party's access-structure share into an additive share for the online quorum (`to_additive_share`, Lagrange coefficients of the chosen set) and then runs the n-of-n protocol on those. For us: a pair is a 2-of-2 protocol |
| Security claimed | Malicious security, dishonest majority, security **with abort** (no identifiable abort, no guaranteed output). The final signature is checked against Q before it is released (`pub.verify`); the output buffer is cleared on error |
| Proofs and when | DKG / refresh: batch DL (`uc_batch_dl_t`) per contributor, hash commitment to the points, consistency hash `h_consistency` over curve, all pids, quorum, sid; `h_all` agreement on the commitments. Signing, in order: commitment + DL proof for the per-signature ElGamal key (round 1-2); PVW base OTs, 256 per pair, run **from scratch every signature** (rounds 2-4, `SECURE_USAGE.md` says so); ElGamal commitments to k_i, rho_i with `uc_elgamal_com` proofs (round 3); OT-extension tail (rounds 4-5); `elgamal_com_mult`, `uc_elgamal_com` for rho_k, rho_x (round 5); `uc_elgamal_com_mult_private_scalar` (round 6); DH proofs and `elgamal_com_pub_share_equ` for K_i (round 7); two more `pub_share_equ` proofs when the shares go to the receiver (round 8). Consistency hashes `h_consistency`, `h`, `h2` are compared across all parties |
| State | None per signature: no presignatures, no stored OT results, no nonce state. The key blob is x_i plus public points. A failed or repeated signing leaves nothing to reconcile. Good for crash safety; costs the base OTs on every signature (125 KB and about 100 ms per pair) |
| Blob | Version 2 (`ac_key_blob_version_v1`) of `key_blob_v1_t`: version, curve, **party name**, Q, map name -> Qi, x_i. Name-bound, not index-bound. **The access structure is not stored in it**: the caller passes it to `sign_ac` / `refresh_ac` (upstream test `SignAcRejectsWrongAccessStructure` covers a wrong one). We always pass the constant `Threshold(2, {qv-t0, qv-t1, qv-t2})`. The load path checks the self binding (x_i*G == Qi) but not Q against the Qis; that check happens in every `sign_ac` (`to_additive_share` rebuilds the Qis and `sign` refuses `SUM(Qis) != Q`) |
| Upstream tests | `tests/unit/api/test_ecdsa_mp_ac.cpp` (about 40 tests: DKG/refresh/sign with 4 parties and a nested structure, wrong structure, malformed trees, garbage / zero / oversized blobs, wrong quorum, **`SignRound3NullCurveElgComFromMaliciousPeerRejected`**, detach/attach), `tests/unit/protocol/test_ecdsa_mp.cpp` (n = 2, 5, 10, output cleared on verification failure, invalid OT role map), `test_ec_dkg.cpp` |

## Advisories and issues touching it

- **GHSA-h3cp-c5xm-jjj8** (high, 2026-10-27, `>= 0.1.0, < 0.2.2`, patched 0.2.2): "Security vulnerabilities in ECDSA-2PC". It names the 2-party protocol (Paillier-based). It is the only advisory on the repository. **Nothing is published about `ecdsa_mp`**; that is absence of evidence, not a clean bill: the advisory has no technical detail, and the same reporters read the same repository.
- Issues (all closed): #7 spec typo in EC-DKG-Threshold-MP step 5(f) (x_i*G = Q_i, not Q; the code checks Q_i); #38 `reconstruct_pub_additive_shares` wrong for some AND/threshold trees (maintainer: threshold must be at least 2, "use OR for 1-of-n"; we use Threshold(2, 3 leaves) and sign with all three pairs in tests); #28 only parties 0,1 could sign a 2-of-3 (fixed upstream; our tests sign every pair, both receivers); #61 CL24 versus spec, no defect; #118 Schnorr candidate signature exposed before verification (Schnorr, not ECDSA; the ECDSA code assigns `sig` only after `pub.verify`).
- Cure53 (CBS-02, Dec 2024, audited commit `abcea54`): **CBS-02-004 (High)** `ECC-Refresh-MP` accepted points outside the prime-order subgroup, and **CBS-02-003 (Low)** no consensus check on sid / Q / Q_j. These are findings in the family we now use. Fixed and verified by Cure53 in Jan 2025; in v0.2.2 `dkg_or_refresh_ac` has `curve.check` on every received point, `h_consistency` over sid and parties, `h_all` over the commitments. The access-structure API layer (`api/ecdsa_mp.cpp`, `dkg_ac` and friends) is newer than the audit.

## What worries me

1. **Not audited as shipped.** Cure53 saw the protocol core before the `api/` layer and the access-structure code of 2025-26. The 2-party protocol had two soundness bugs found 19 months after its audit (the advisory). `ecdsa_mp` has had fewer eyes and no public finding, which is not the same as none.
2. **Abort without blame.** A failed proof does not say which party cheated. Our wrapper knows which link a bad message came in on, but the error does not carry it (a gap; E23-2 can log the peer of the last receive). A malicious member can always make a signature fail or freeze a keyset (denial of service, not theft), as with the 2-party path.
3. **Dishonest-majority model, 2-of-3.** Two colluding or compromised members hold the key. That is the stated design, not a flaw, but the cosigner independence (B and C in different trust domains) is what protects the key; the protocol does not.
4. **DKG / refresh can succeed and still leave unusable shares** (README point 1 for the 2-party path). For threshold we measured the other way: in 128 tampered DKG runs and 128 tampered refresh runs none ended with all parties succeeding; all failed closed (`testMaliciousCeremony`). Do not read that as a guarantee; `SelfTest` is mandatory.
5. **Per-signature cost of 256 base OTs and 125 KB per party** (about 25x the 2-party bytes). Fine on a LAN or one region; on a wide-area link every round costs one RTT, 9 rounds.
6. **No access structure in the blob, names are part of the key.** A wrong constant in a later release would silently make shares unusable (golden test pins it). Party names `qv-t0..2` must never change.
7. **Blob confidentiality is ours.** x_i is a single 32-byte scalar in a blob that also holds all public points; seal it exactly like the 2-party shares (the HSM sealer of P5b-4 takes any byte string).
8. **Constant-time / side channels** are as for the rest of cb-mpc (see the P5b-1 review): shares live in process memory; the constant-time note in `docs/` is LFS and was not re-read.

## Pinned internals (golden-tested)

`shim.cpp` mirrors the access-structure key blob (`tkey_blob_t`, from `key_blob_v1_t` in `src/cbmpc/api/ecdsa_mp.cpp`, version 2) to read the party name, Q, Qi and to validate before loading. `TestGoldenThreshold` pins the layout, the names, the detach output and the sha256 of the public blob, and runs sign, refresh and the self-test on fixture shares (`testdata/golden_tecdsa.json`, TEST-ONLY). Everything else uses the public API.

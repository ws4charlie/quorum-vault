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

---

# Multi-party EdDSA (`eddsa_mp` with an access structure) for 2-of-3 (P8-1, 2026-11-08)

Question: is the threshold Ed25519 of v0.2.2 fit to hold Solana hot keys 2-of-3? Result in [docs/spikes/p8-eddsa-threshold.md](../docs/spikes/p8-eddsa-threshold.md): **go with conditions**. Source read at the pinned commit `2f2c4f1` (no move of `cbmpc.pin`; v0.2.2 is still the newest tag); GitHub state read on 2026-11-08 (`gh api`). The Schnorr spec and theory PDFs in the checkout are Git LFS pointers, so they were **not read**: the protocol attribution below is read from the code, not from the paper.

## What it is (confirmed from source)

| Item | Finding |
|---|---|
| Public API | `include/cbmpc/api/eddsa_mp.h`: the same eight functions as `ecdsa_mp` (`dkg_ac`, `refresh_ac`, `sign_ac`, public key and share point, detach/attach scalar), ed25519 only. Signature is 64 bytes `R || s`. No HD |
| Shape the lead asked about | Confirmed. The header says DKG and refresh need **all** parties in `job.party_names` online; `sign_ac` needs only the signers, and works for any subset that satisfies the access structure. Signatures are standard Ed25519: `schnorr_mp.cpp` computes `e = SHA-512(R \|\| Q \|\| m)` and `s = sum(e*x_i + k_i)`, and the result verifies with Go's `crypto/ed25519.Verify` (RFC 8032 verification), for every pair and both receivers, in our tests |
| Protocol, DKG / refresh | Not Schnorr-specific: `eddsa_mp::dkg_ac` and `refresh_ac` call the same `key_share_mp_t::dkg_or_refresh_ac` (`ec_dkg.cpp`) as ECDSA, with the curve set to Ed25519. Everything in the E23-1 review of that code applies. `eddsa_mp.cpp` differs from `ecdsa_mp.cpp` only in the curve checks (it adds an explicit subgroup check on Q and every Qi when it reads a blob) |
| Protocol, signing | `src/cbmpc/protocol/schnorr_mp.cpp` (189 lines), `sign_batch`. After `sign_ac` has turned the access-structure share into an additive share of the two signers (Lagrange), it runs an n-of-n Schnorr in **three messages**: (1) commitment to the nonce points `R_i` (bound to a fresh per-party `sid_i` and the party id) plus a consistency hash of messages, Q and all Qi; (2) the session id (hash of all `sid_i`), the opening of the commitment, `R_i`, and a UC batch discrete-log proof (`uc_batch_dl_t`) of `k_i`; (3) `s_i = e*x_i + k_i`, sent only to the receiver. This is the shape of Lindell's three-round multiparty Schnorr with full simulatability (eprint 2022/374): commit-and-reveal nonces, so the Wagner-style attack on plain multi-party Schnorr does not apply. Inferred from the code, not confirmed from the spec |
| Checks | Key sanity first (`x_i*G == Qi`, `sum(Qi) == Q`, party name matches); then `h_consistency` equal on all parties, `sid` and `h` (hash of the commitments) equal, `curve.check` on every received `R_j` (on curve, prime-order subgroup, not infinity), the batch DL proof, and the commitment opening. The receiver sums the `s_j`, builds `R || s`, and **verifies it against Q before it assigns the output** (the output is untouched on error) |
| Security claimed | Malicious security with abort and no identifiable abort, as for ECDSA. A bad `s_j` from the other signer makes the receiver's verification fail: denial of service, never a wrong signature. The non-receiver never learns whether the signature verified |
| Randomized, not RFC 8032 deterministic | Each `k_i` is fresh random (`bn_t::rand`). `SECURE_USAGE.md` says so: "our implementation of EdDSA is actually just Schnorr over Ed25519 and is probabilistic", fine if the same message is never signed twice, which is why the custody layer signs a message once and rebroadcasts the stored signature (PLAN). Tested: two signatures over one message differ and both verify |
| State | None per signature and no stored OT results. The blob is x_i plus public points, version 2, the same layout as `ecdsa_mp` (`key_blob_v1_t`); name-bound, access structure not stored (we always pass the constant one) |
| Upstream tests | `tests/unit/api/test_eddsa_mp_ac.cpp` and `tests/unit/protocol/test_eddsa_mp.cpp` exist at the pin (`test_eddsa_mp_ac.cpp`: DKG, refresh and sign with 4 parties, wrong access structure, insufficient quorum, garbage and oversized blobs, bad attach inputs; `test_schnorr_mp.cpp`: EdDSA and BIP340 with 4 parties, and "verification failure clears signature outputs", the #118 fix). Listed from the test names, not read line by line |

## Advisories and issues touching it

- **GHSA-h3cp-c5xm-jjj8** names ECDSA-2PC only, and is the only advisory. Nothing is published on Schnorr or `eddsa_mp`: absence of evidence, as in E23-1.
- **#118 and #94** (closed): Schnorr 2P and MP `sign_batch` wrote the candidate signature into the caller's output **before** the final verification; on failure the caller's buffer still held it. The maintainer called #94 unintentional. **Fixed in v0.2.2**: the code at the pin builds `candidate_sigs` and moves it to `sigs` only after verification. (Lindell's comment on #118: the harm is limited, since the receiver can always obtain the signature anyway.) The Go wrapper also checks every signature itself and never keeps an output on error.
- **#47** (closed): refreshing an `EDDSAMPCThresholdDKGRequest` key failed with "Q does not match the sum of Qis" because the reporter used the n-of-n refresh on an access-structure share. We use `refresh_ac` for threshold shares, and refresh is tested (golden fixture included).
- **#61** (closed): the refresh protocol keeps a commitment CL24 says is unnecessary. Harmless (extra, not missing).
- **#134** (closed, Schnorr **2-party**): spec inconsistency about whether message 1 commits to the DL proof. Not the multi-party code; it touches the 2-party Ed25519 HD path that keeps the deposit keys.
- No open issues. Cure53 (see the first section): EdDSA, Ed25519, commitments, MPC protocols and ZK were in its high-priority scope, and none of its findings names multi-party Schnorr signing; **CBS-02-001** (info) is the random Ed25519 nonce, the randomization stated above. The checkout here has no git history, so I could not establish whether `schnorr_mp.cpp` already existed at the audited commit `abcea54` or was reached by the testers. Treat it as: possibly in scope, not confirmed, not covered by anything I could read.

## What worries me

1. **Less outside review than anything else we run.** Short code (the whole signing protocol is 189 lines) is a good sign; but nothing says an outside party has read it, the access-structure layer postdates the audit, and the spec could not be read here. Same condition as E23-1, stronger.
2. **Abort without blame** and a **receiver-only view**: a bad `s_j` shows up as "ed25519 verify failed" on the receiver, with no name. A malicious signer can deny service; the non-receiver cannot tell whether the signature was good.
3. **Dishonest-majority model, 2-of-3:** two compromised members hold the key. Design, not defect.
4. **DKG / refresh can succeed and still leave unusable shares** (README point 1). In our tests 128 tampered DKG and 128 tampered refresh runs all failed closed, not a guarantee: `SelfTest` stays mandatory.
5. **Randomized signatures:** a second signing of the same message gives a different valid signature. For Solana this is harmless, but it is a rule the service must keep (sign once, store, rebroadcast); replaying a signing job through another pair must be decided, not left to chance.
6. **Name-bound blob, no access structure in it,** as for ECDSA (golden-pinned).
7. **Blob confidentiality is ours**, as for ECDSA.

## The E23-3 open finding, and whether EdDSA has it

Recorded from E23-3: in an `ecdsa_mp` pair signature, one flipped byte in the **middle of message index 2** (the third message A sends) was ignored about half of the time (13 of 25 in-process trials; indices 0, 1, 3, 4 and 5 were detected 150 of 150). Every signature that came out verified, so it is no signature risk, and it was **not reported upstream** by us. It means some bytes of that ECDSA message are not checked or not used. Open until someone reads `ecdsa_mp.cpp` round 3 for the unused part.

For EdDSA I looked for the same class of defect two ways. By source: every field of messages 1 and 2 is compared, hashed or fed into a verified proof, and message 3 (`s_i`) is summed into the signature that is verified. By test (`TestMaliciousPeerEdThresholdSign`, `TestEdThresholdFlippedByteIsDetected`): every message index, both directions, eight mutations (three single-bit flips, truncation, empty, extension, replay of the previous message, replay from an earlier session), all six pair and receiver combinations, 240 runs: all 240 ended in `Cryptographic` on the honest side, none in success; and 25 random single-byte flips per message index, five indices: 0 of 125 ignored. **No index is tolerated.** Not proof: a sample, and a byte inside a proof's padding that nobody checks would show up only by luck.

## Pinned internals (golden-tested)

`shim.cpp` mirrors the same access-structure key blob for both schemes (`tkey_blob_t`; the Ed25519 and ECDSA upstream structs are identical) and now takes the scheme as a parameter, so there is one code path. `TestGoldenEdThreshold` pins the layout, names, detach output and public-blob hash, and runs sign, refresh and the self-test on fixture shares (`testdata/golden_teddsa.json`, TEST-ONLY). The ECDSA fixture is untouched and passes unchanged.

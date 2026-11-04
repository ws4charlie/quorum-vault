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

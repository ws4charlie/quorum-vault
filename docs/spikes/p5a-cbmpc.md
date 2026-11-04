# P5a — can Coinbase cb-mpc be the hot-wallet signer?

Spike by the P5a hand, 2026-11-04. Code: `spike/cbmpc/` (throwaway). Reproduce: `spike/cbmpc/scripts/demo.sh`.
Pinned: **cb-mpc v0.2.2, commit `2f2c4f1005729bd575b6f17bce8a47478df7ce78`** (2026-08-31, MIT). Machine: Apple M3 Pro, 12 cores, macOS arm64; Linux checked in an arm64 Debian container.

## Recommendation: **GO**, with four conditions

2-party ECDSA (Lindell17) with HD derivation works end to end across two processes: DKG, derive, sign, mined on anvil, sender equals the derived address. Non-hardened children match stock BIP32. Ed25519 and BIP340 signatures verify with standard verifiers. 50 sig/s per chain needs about 3 cores in total (both parties) for ECDSA. A lost party was restored from a verifiable backup. Killing a party mid-signature is survivable.

Conditions:
1. **Pin v0.2.2 or later, and watch the repo.** v0.2.2 is the first release with the fix for both bugs in advisory GHSA-h3cp-c5xm-jjj8 ("Security vulnerabilities in ECDSA-2PC", High, published 2026-10-27, affects >= 0.1.0 and < 0.2.2; keygen bug fixed in 0.1.1, signing bug in 0.2.2). Details of the bugs are not public. Two soundness bugs in the very protocol we want mean the library is still young: budget for upgrades and a re-audit read at P5b start. `HEAD` is already ahead of the tag (`0b71670`); re-check the diff then.
2. **`mpc-party` must catch every C++ exception at the C boundary.** `cb_assert` failure *throws* (`src/cbmpc/core/error.cpp:91`) and the C++ HD API does not catch it; a throw through cgo is `std::terminate`. The spike shim has a `try/catch(...)` per entry, untested because I could not trigger an assertion (Q8).
3. **We need three things the public API lacks**, so P5b either carries a small patch or uses `include-internal/`: the chain code of the hardened node (xpub for P7/P8), secret-share export for HD keysets (backup), Ed25519 equivalent of the node export. All three are small (about 60 lines, done for ECDSA in this spike), but they depend on internal layout, so they must be pinned by tests (Q3, Q6).
4. **Party B must verify what it signs.** `sign()` takes a digest only, and only P1 receives the signature. B must receive the signed intent and re-run `chain.TxVerifier` before it joins the protocol; otherwise B is a blind co-signer (design section).

If condition 1 turns out badly (more soundness bugs), the fallback is not to keep GG20 in production: it keeps the demo path only, and hot funds stay small. I did not evaluate other libraries.

## Answers

### Q1 Build
| Item | Result |
|---|---|
| Source | `git clone --branch v0.2.2`, verify `HEAD == 2f2c4f1…`, init submodules `vendors/secp256k1` (Coinbase fork, MIT) and `vendors/googletest` only |
| Toolchain | CMake >= 3.16 (`CMakeLists.txt:1`), C++17. Upstream recommends Clang 20+ (their Dockerfile uses clang-20 20.1.8); AppleClang 21 built it fine here |
| OpenSSL | **Custom static OpenSSL 3.6.4** built by their script (patched `curve25519.c`, many `no-*` options; the script checks the tarball SHA-256). System OpenSSL does not work. Installs to `/usr/local/opt/openssl@3.6.4` unless `CBMPC_OPENSSL_ROOT` is set; my script sets it inside `.deps/` (no sudo) |
| macOS arm64 | `scripts/fetch-build-cbmpc.sh`: OpenSSL 27 s wall (80 s CPU), library 6.6 s wall (40 s CPU). Whole `demo.sh` from an empty checkout, including clone, Go build and docker anvil start: **38 s** |
| Linux | `docker build` of their `Dockerfile` (clang-20, OpenSSL 3.6.4): 73 s cold. Then library + unit tests in the container: 35 s. **195 upstream unit tests passed** (ECDSA-2PC, HD keysets, Schnorr-2PC, EdDSA-2PC, PVE batch, Paillier/Pedersen ZK) in 6.5 s. This was arm64 Linux; **x86_64 `ubuntu-latest` not tried** (their CMake has separate arm64 and x86_64 branches, `cmake/compilation_flags.cmake:40-46`) |
| Sizes | `libcbmpc.a` 5.4 MB; `party` binary (Go + cgo, static cb-mpc and OpenSSL) 16 MB |
| License | MIT (`LICENSE.md`); secp256k1 fork MIT; OpenSSL Apache-2.0 |
| CI | About 120 s of CPU for OpenSSL plus library: roughly 1 to 2 minutes on a 4-vCPU runner, plus about 1 minute to install clang-20. Cache `.deps/` keyed on tag plus script hash and it drops to seconds. Only the `mpc-party` job needs C++; every other job stays pure Go |

Link conflict found: **go-ethereum's cgo libsecp256k1 and cb-mpc's vendored secp256k1 export the same symbols** (`secp256k1_ecmult_gen_prec_table`, `secp256k1_pre_g`, `secp256k1_pre_g_128`); linking both into one Go binary fails with duplicate symbols. This supports the plan to keep cb-mpc in its own binary. In the spike, `cmd/ethdemo` (go-ethereum) calls `cmd/party` (cb-mpc) as a subprocess.

### Q2 Lindell17 safety
BitForge's Lindell17 attack (Fireblocks, CVE-2023-33242 family) extracts the key one bit per failed or crafted signing attempt when the verifier does not enforce the paper's proofs. In cb-mpc 2-party ECDSA (Lindell17-style, Paillier-based) these checks exist:

| Check | Where (v0.2.2) |
|---|---|
| Modulus size is exactly the expected bit size, and large enough for `3·lg q + 3·stat + com + 1` | `src/cbmpc/protocol/ecdsa_2p.cpp:61-66` |
| Ciphertext `c_key` is a valid Paillier ciphertext (gcd check) | `ecdsa_2p.cpp:71` |
| Paillier modulus is a valid key (interactive proof) and has no small factors | `ecdsa_2p.cpp:73`; `src/cbmpc/zk/zk_paillier.cpp:33`, `:86` (`check_integer_with_small_primes`) |
| PDL proof: `c_key` encrypts the discrete log of P1's share point `Q1` | `ecdsa_2p.cpp:78`; `zk_paillier.cpp:~500-530`; response bound `:520-521` (the bound was corrected by upstream commit "fix: correct response range bound in Paillier-DL ZK verification (#136)", the last commit before the tag) |
| `c_key` encrypts the same value as a Pedersen commitment, and that value is in range `[0, q)` | `ecdsa_2p.cpp:82-83` (`equal.verify`, `range.verify`) |
| Signing: P2 proves its homomorphic message is well formed (integer-commitment proof with range checks on every response) | `ecdsa_2p.cpp:351` prove, `:383` verify, `:569-591` range checks; `verify_cipher` on the result `:389` |
| Final signature is verified against the public key before it is returned | `ecdsa_2p.cpp:406-410` |
| Refresh re-proves the new Paillier key and plaintext equality | `ecdsa_2p.cpp:143-206` |

Failed signature handling: the public API only exposes `sign()`, which runs the full proof mode (`api/ecdsa2pc.cpp:178-179` → `sign_batch_impl(... SIGN_MODE_DEFAULT)`). `SECURE_USAGE.md` ("Two-party ECDSA signing") says this mode "behaves like a standard MPC protocol (no special operational caveats)". The faster `sign_with_global_abort()` is the one that leaks a bit when a cheat happens (`E_ECDSA_2P_BIT_LEAK`, `ecdsa_2p.cpp:410`), and it is **not exposed** by the public C++ or C API. **Rule for us: never use the internal global-abort variant.** With the default mode a failed session does not require burning the key. We still treat a protocol-level error as an incident (design section).

Open advisories: **GHSA-h3cp-c5xm-jjj8**, see condition 1; patched in the version we pin. Cure53 audited the library in Q4 2024 (report dated March 2025, two exploitable findings of which one High, all verified fixed by 2025-01-06 per Cure53; PDF in `docs/cure53-audit.pdf`, which I could not read here because no PDF tool is installed; the summary comes from a web search). I could not confirm whether the High finding is the BitForge class. The Oct 2026 advisory shows bugs survived that audit.

What I did not do: I did not attack the implementation (no malicious-P1 test). Evidence is code reading plus the upstream test suite (`ZKVerifierRejection.PaillierProofsRejectMalformedAndTamperedTranscripts` passes).

### Q3 HD derivation
C++ API only (`include/cbmpc/api/`; the C API and cb-mpc-go have no HD):

```cpp
// ECDSA (secp256k1 or P-256)                                   // hd_keyset_ecdsa_2p.h
error_t dkg(const job_2p_t&, curve_id, buf_t& keyset_blob);
error_t refresh(const job_2p_t&, mem_t keyset_blob, buf_t& new_keyset_blob);
error_t derive_ecdsa_2p_keys(const job_2p_t&, mem_t keyset_blob, const bip32_path_t& hardened_path,
        const std::vector<bip32_path_t>& non_hardened_paths, buf_t& sid, std::vector<buf_t>& out_ecdsa_2p_key_blobs);
error_t extract_root_public_key_compressed(mem_t keyset_blob, buf_t& out_Q);
// Ed25519: same four functions in hd_keyset_eddsa_2p.h, derive_eddsa_2p_keys
```
The derived blobs plug into `ecdsa_2p::sign` / `eddsa_2p::sign`. One DKG (180 ms) makes one keyset per curve; every address is one `derive` (**1.45 ms**, one MPC round trip).

How derivation works (`protocol/hd_keyset_ecdsa_2p.cpp:105-170`):
- Hardened step: the keyset holds an extra shared random key `K`. Both parties compute a distributed VRF on the hardened path (`Z = k·H(path)`, with a DH-equality proof each), hash `Z` into a scalar `delta` and a 32-byte chain code. Derived `Q = Q_root + delta·G`. It needs both parties online. The "hardened path" is any vector of `uint32`, hashed to a curve point; it is not BIP32 hardened-index arithmetic.
- Non-hardened steps (`protocol/hd_tree_bip32.cpp:20`): `HMAC-SHA512(chain_code, point || index)`, `child = parent + I_L·G`. This is BIP32 CKDpub.

**Does a child public key match standard BIP32?** Yes, from the account node. I exported the node's public key and chain code, built an `xpub` from them, and let btcsuite `hdkeychain` derive children; cb-mpc's derived key matched on 5 of 5 paths including two-level paths (see `scripts/verify-all.sh` output below). Limits:
- The chain code is **not returned by the public API**; I got it with a copy of the VRF step in `shim.cpp` (`qv_hd_node_ecdsa`), which uses `include-internal/`. P7 needs this (xpub for deposit addresses). Same for Ed25519 (not done).
- The master is not a BIP32 seed. You cannot import an existing seed or match a hardware wallet's `m/44'/60'/0'`; the account-level xpub is a valid xpub, but the parent path is cb-mpc's own.
- Ed25519 uses the same BIP32-style non-hardened rule on Edwards points (`hd_keyset_eddsa_2p.cpp:152`), not SLIP-0010 (which has no non-hardened Ed25519) nor BIP32-Ed25519 (Khovratovich-Law). Stock Solana wallets cannot derive these children from an xpub; only our own cell can, using (account pubkey, chain code). That is all P8 needs.

Public-data-only derivation: given `(Q_account, chain_code)` anyone derives all non-hardened child public keys, addresses included, with no MPC. Hardened steps and signing need both parties. **2-party only in this version**: no HD for multi-party ECDSA/EdDSA.

### Q4 Transport
Interface (`include/cbmpc/core/job.h`): a blocking `data_transport_i` with `send(party, bytes)`, `receive(party, buf)`, `receive_all`. There is no library timeout, no cancellation and no framing: if a call blocks forever the protocol blocks forever. `SECURE_USAGE.md` says the transport must be authenticated and encrypted (TLS) and warns to unblock `receive` on abort. The caller supplies party names and session IDs.

Cost per signature, measured on the wire (data frames only, my framing excluded):

| Protocol | Messages (P1→P2 + P2→P1) | Bytes P1→P2 / P2→P1 | Round trips |
|---|---|---|---|
| ECDSA 2PC `sign` | 3 + 3 | 3.2 KB / 7.2 KB | 3 (the first one is the joint session-ID agreement) |
| Ed25519 2PC `sign` | 2 + 2 | 3.2 KB / 3.1 KB | 2 |
| HD `derive` | 1 + 1 | small | 1 |

Bridge to Go (this spike, `cbmpc/cbmpc.go`, `cmd/party/mux.go`): the C++ `data_transport_i` implementation in `shim.cpp` calls two exported Go functions (`qv_go_send`, `qv_go_recv`); each protocol run is one blocking cgo call on its own OS thread, with a `runtime/cgo.Handle` pointing at a Go `Transport`. A session mux carries many sessions over one connection (frame = length, session ID, kind, payload; kinds: open, data, abort, fin). In production this is a gRPC bidirectional stream per session (or per peer with a session ID field) over mTLS. Cost of a blocked session: one OS thread; 32 concurrent sessions ran fine.

Failure modes, all tested (Q8): peer dies → `Recv` returns an error immediately and the C++ call returns an error code; peer hangs → per-message receive timeout (3 s in the test, caller returned after 3.01 s); abort → an abort frame wakes the peer's blocked `Recv`; session end needs a completion handshake (without it a client can exit while the peer still computes; I hit this bug and added `fin`).

### Q5 Performance
Two OS processes, loopback TCP, both on the same 12-core M3 Pro (so they compete for cores), secp256k1 child key, 8 s per concurrency level. Command: `scripts/bench.sh`. CPU per signature is process CPU time (user+sys) divided by signatures. Raw output:

```
### loopback
dkg ecdsa n=10 p50=170.678209ms p99=229.31675ms max=309.860667ms
derive ecdsa n=100 p50=1.452333ms p99=1.655792ms max=1.836958ms
  per sign: p1->p2 3225 B in 3.0 msgs, p2->p1 7173 B in 3.0 msgs
sign ecdsa conc=1  n=164 fails=0  20.4 sig/s  p50=48.875ms p99=50.097ms  cpu/sig p1=21.8ms p2=28.4ms  (cores busy: p1 0.45 p2 0.58)
  per sign: p1->p2 3225 B in 3.0 msgs, p2->p1 7173 B in 3.0 msgs
sign ecdsa conc=8  n=1045 fails=0  129.7 sig/s  p50=60.69ms p99=76.652ms  cpu/sig p1=27.6ms p2=35.7ms  (cores busy: p1 3.58 p2 4.63)
  per sign: p1->p2 3225 B in 3.0 msgs, p2->p1 7173 B in 3.0 msgs
sign ecdsa conc=32 n=1233 fails=0  152.0 sig/s  p50=208.868ms p99=337.784ms  cpu/sig p1=32.6ms p2=41.8ms  (cores busy: p1 4.96 p2 6.35)
  per sign: p1->p2 3178 B in 2.0 msgs, p2->p1 3147 B in 2.0 msgs
sign eddsa conc=1  n=1200 fails=0  149.9 sig/s  p50=6.659ms p99=7.028ms  cpu/sig p1=3.5ms p2=3.4ms  (cores busy: p1 0.52 p2 0.51)
  per sign: p1->p2 3178 B in 2.0 msgs, p2->p1 3147 B in 2.0 msgs
sign eddsa conc=8  n=8151 fails=0  1017.9 sig/s  p50=7.602ms p99=10.699ms  cpu/sig p1=4.0ms p2=4.0ms  (cores busy: p1 4.10 p2 4.08)
  per sign: p1->p2 3178 B in 2.0 msgs, p2->p1 3147 B in 2.0 msgs
sign eddsa conc=32 n=10465 fails=0  1305.3 sig/s  p50=23.392ms p99=52.288ms  cpu/sig p1=4.5ms p2=4.3ms  (cores busy: p1 5.89 p2 5.60)
### 20 ms RTT
dkg ecdsa n=10 p50=225.329667ms p99=258.235709ms max=366.520542ms
derive ecdsa n=100 p50=47.190417ms p99=50.090125ms max=50.102625ms
  per sign: p1->p2 3225 B in 3.0 msgs, p2->p1 7173 B in 3.0 msgs
sign ecdsa conc=1  n=70 fails=0  8.7 sig/s  p50=115.223ms p99=117.585ms  cpu/sig p1=23.4ms p2=32.7ms  (cores busy: p1 0.20 p2 0.28)
  per sign: p1->p2 3225 B in 3.0 msgs, p2->p1 7173 B in 3.0 msgs
sign ecdsa conc=8  n=581 fails=0  71.9 sig/s  p50=110.417ms p99=119.645ms  cpu/sig p1=23.6ms p2=30.6ms  (cores busy: p1 1.69 p2 2.20)
  per sign: p1->p2 3225 B in 3.0 msgs, p2->p1 7173 B in 3.0 msgs
sign ecdsa conc=32 n=1224 fails=0  150.7 sig/s  p50=206.901ms p99=307.625ms  cpu/sig p1=33.2ms p2=40.8ms  (cores busy: p1 5.00 p2 6.15)
  per sign: p1->p2 3178 B in 2.0 msgs, p2->p1 3147 B in 2.0 msgs
sign eddsa conc=1  n=135 fails=0  16.8 sig/s  p50=60.052ms p99=61.55ms  cpu/sig p1=8.5ms p2=8.1ms  (cores busy: p1 0.14 p2 0.14)
  per sign: p1->p2 3178 B in 2.0 msgs, p2->p1 3147 B in 2.0 msgs
sign eddsa conc=8  n=1104 fails=0  137.9 sig/s  p50=58.172ms p99=59.521ms  cpu/sig p1=7.6ms p2=7.8ms  (cores busy: p1 1.05 p2 1.08)
  per sign: p1->p2 3178 B in 2.0 msgs, p2->p1 3147 B in 2.0 msgs
sign eddsa conc=32 n=5280 fails=0  658.2 sig/s  p50=48.303ms p99=51.311ms  cpu/sig p1=4.0ms p2=3.9ms  (cores busy: p1 2.64 p2 2.57)
```
Reading it:
- **DKG** (ECDSA, includes a fresh Paillier key and proofs): p50 about 170 ms, p99 about 230 ms. **Derive**: p50 1.45 ms. **Refresh**: 112 to 152 ms.
- **ECDSA sign latency**: p50 about 49 ms at concurrency 1 (about 21 sig/s per stream), 121 ms with a 20 ms RTT (3 round trips plus open and fin).
- **CPU per ECDSA signature**: about 22 ms on P1 and 28 ms on P2 at low load, rising to 33 and 42 ms at 32 concurrent sessions on this shared machine. **Ed25519**: 3.5 ms per party.
- **Throughput**: ECDSA about 130 sig/s at concurrency 8, saturating near 150 sig/s when both parties share the 12 cores. With 20 ms RTT: 70 sig/s at concurrency 8 (latency bound), 150 at 32. Ed25519: about 1,000 sig/s at concurrency 8.
- **Is 50 sig/s per chain reachable?** Yes for ECDSA. 50 × (22 to 33 ms) = 1.1 to 1.7 cores on P1 and 50 × (28 to 42 ms) = 1.4 to 2.1 cores on P2 (light to heavy load); with headroom, **provision 4 vCPU per party per ECDSA chain**, and use concurrency of at least 8 per party so a 20 ms RTT does not cap throughput (at 20 ms RTT, concurrency 4 would give only about 33 sig/s). M3 cores are faster than typical cloud vCPUs, so treat core counts as a floor and re-measure on target hardware. EdDSA (Solana) needs about a tenth of the CPU. All of this is per process; the hot wallet can also be split into K shards (child addresses), which parallelizes nonce handling but not CPU.
- No presigning in v0.2.2, so every signature pays the full protocol. Passing a pre-agreed `sid` would remove one round trip, but `SECURE_USAGE.md` requires the session ID to be jointly generated; I kept the default.

### Q6 Shares and backup
Formats (all opaque versioned blobs, `convert()`-serialized, defined in `src/cbmpc/api/*.cpp`):

| Object | P1 (Paillier owner) | P2 |
|---|---|---|
| ECDSA HD keyset | about 1.2 KB (1,635 B as sealed envelope) | 919 B |
| ECDSA derived key blob | about 1.1 KB (1,543 B sealed) | not measured |
| Ed25519 keyset / derived key | 255 B / 167 B, sealed envelope, as seen on P1 | not measured |

Sealing: the blobs are plain bytes, so they fit the existing `internal/mpc/seal` envelope (`{"v":1,"iv":…,"ct":…}`, AES-256-GCM, 12-byte IV, AAD-bound). The spike writes exactly that envelope with a software key (`cmd/party/party.go`, AAD = `qv-p5a|p<n>|<name>`); wiring it to PKCS#11 is plumbing, not a research question. Blob parsers validate format only, not authenticity (`SECURE_USAGE.md`), so only load blobs you sealed yourself, which GCM guarantees.

Zeroization: `buf_t` frees with `memset_s` (`include/cbmpc/core/buf.h:21-22`), big numbers with `BN_clear_free` (`src/cbmpc/crypto/base_bn.cpp:93`). Not covered: copies in the Go heap (my wrapper copies blobs into Go slices, which the GC does not wipe), swap and core dumps. `mpc-party` must set `RLIMIT_CORE=0`, `PR_SET_DUMPABLE=0`, mlock, and keep blobs in C memory, wiped after use. I wipe the C copy in `take()` but not the Go copy.

Offline backup (PVE = publicly verifiable encryption, `api/pve_batch_single_recipient.h`): the public API gives PVE for scalars but **no export/import for HD keysets** (the single-key ECDSA/EdDSA APIs have `detach_private_scalar` / `attach_private_scalar`, HD keysets do not). I wrote the split/join in the shim by mirroring the blob struct (`keyset_blob_v1_t`, `api/hd_keyset_ecdsa_2p.cpp`), so it depends on the v0.2.2 layout and needs a test that pins it. Procedure (`scripts/backup-recovery.sh`):
1. Offline: generate an RSA backup key pair (`generate_base_pke_rsa_keypair`); only the public key goes online.
2. Per party: split the keyset into scalars `(x, k)` plus the rest, `PVE-encrypt` both scalars to the public key with a label binding party and keyset, and **verify** the ciphertext against the public share points `x·G` and `k·G` without any secret. Ciphertext is 49 KB.
3. Store ciphertext plus the stripped blob away from the party.
4. Restore on a fresh token: verify, decrypt with the offline key, join, seal under the new key.

Caveat: P1's stripped blob **still contains the Paillier private key** (`SECURE_USAGE.md`, ECDSA-2P P1 detachment). For P1 the whole stripped blob must be encrypted to the offline key too; PVE alone is not enough. Also: PVE reduces scalars mod q, but P1's share is an integer representative that can exceed q after refresh; the API documents `attach_private_scalar` as checking `(x mod q)·G`, so I believe restore is fine, but I only tested restore on P2 and without a prior refresh. Anyone holding the offline key plus both parties' backups holds the full private key, so the offline key needs the cold-tier ceremony and the two backups must be stored apart.

Proof of one full recovery (party B lost, restored, signing again; same public key; signature verified):
```
== 0. offline recovery key (stays offline; only the public key is needed for backups)
backup-keygen: ek 271 bytes, dk 531 bytes (dk goes offline)
== 1. normal operation: party B (p2) with its own sealed state
hd-dkg ecdsa ks ok in 482.354333ms
hd-derive child ok in 1.837125ms
child pubkey before: 03d51b0f7fc03f70f65d878634978fadbdf137427780e61a078de1ad7e607bfd6d
sign ok in 49.397625ms
verified=true
== 2. backup of party B: only its sealed state + the PUBLIC key are used (PVE, verifiable)
backup-export: keyset blob 919 B, stripped 855 B, PVE ciphertext 49135 B; PVE verified against public share points without the decryption key
== 3. DISASTER: party B is destroyed (state AND seal key gone)
backup.dk
backup.ek
p1
p2-a.log
p2.backup.json
== 4. restore B on a fresh token/seal key from the offline key + backup file
recover: keyset "ks" rebuilt (919 B) and sealed into out/backup-demo/p2b
== 5. A re-derives the same child with the restored B and signs
hd-derive child ok in 3.633792ms
child pubkey after:  03d51b0f7fc03f70f65d878634978fadbdf137427780e61a078de1ad7e607bfd6d
pubkey identical: yes
sign ok in 53.304334ms
verified=true
PASS: B lost and restored from PVE backup; signature verifies under the original public key
```
Note on the settled design: with 2 parties there is no "third share". The offline "third" element is each party's PVE backup; two online parties plus an offline recovery key.

### Q7 Other chains
| Chain | Result |
|---|---|
| Ed25519 (Solana) | HD keyset on Ed25519, derived child key, signature verified with Go `crypto/ed25519.Verify` = true. Signatures are randomized (two signatures over one message differ), so store the first and rebroadcast it |
| BIP340 Schnorr (Bitcoin taproot) | `schnorr_2p` produced a 64-byte signature that btcec `schnorr.Verify` accepts, x-only key via `extract_public_key_xonly` |
| Same key material? | **No.** ECDSA/secp256k1 HD keysets, Ed25519 HD keysets and Schnorr keys are separate. There is **no HD for Schnorr** in v0.2.2 (`schnorr_2p.h` has dkg, refresh, sign only). A taproot key can therefore not be a derived child of the ECDSA keyset. For P7 either use P2WPKH/P2PKH addresses from the ECDSA xpub (fully supported and proven) or accept one non-HD Schnorr key per taproot address (not practical for per-user deposits) |

Verification output is in `scripts/verify-all.sh` below.

### Q8 Crash behaviour
Results (`scripts/crash-tests.sh`; full output in `scripts/verify-all.sh` below):

| Event | What the caller sees | Peer / recovery |
|---|---|---|
| C++ `abort()` inside the peer | `peer connection lost` at once | peer process dead; restart reloads sealed state; next sign OK (about 65 ms) |
| NULL dereference (SIGSEGV) in the peer | same | same |
| Go panic in the peer | same | same |
| `kill -9` the peer mid-signature loop | the in-flight sign fails 26 to 29 ms later with a transport error; earlier ones were fine | restart, next sign OK |
| Peer hung (`SIGSTOP`) | error after the receive timeout (3.01 s) | no leak; peer resumes later |
| `kill -9` the caller mid-signature | n/a | peer stayed alive, session aborted, next sign OK |
| Malformed or oversized (2 MB) protocol messages | n/a | peer returned converter errors, stayed alive (a smoke test, not a fuzzing campaign) |

What the C++ library does on its own: `cb_assert` throws `assertion_failed_t` (`src/cbmpc/core/error.cpp:65-91`). The library's C API wraps its calls in `catch (const std::bad_alloc&)` and `catch (...)` (`src/cbmpc/c_api/ecdsa2pc.cpp:64-71`), but the C++ HD API we need does not, so an uncaught throw ends the process (same effect as the abort test). The final shim wraps every entry in `try/catch(...)` returning an error code; I did not manage to trigger an assertion through the public API, so that path is compiled but untested. I did not provoke an out-of-memory condition; the library bounds blob inputs to 1 MiB (`api/mem_util.h`) but peer messages are bounded only by what the transport allows, so `mpc-party` must cap frame size and run under cgroup memory limits. Isolation works: a crash costs one process and one in-flight signature; nothing else in the system links C++.

Consequences for the gateway: a transport failure is a retryable event with a new session; the signature from a failed session never exists, so no half-signed state. The nonce and the sign job stay as they are; the retry rules are in the design.

## Prototype: one command

`spike/cbmpc/scripts/demo.sh` needs git, cmake, a C++ compiler, Go and docker. It builds everything, starts anvil (`qv-anvil-p5a`, port 18545, chain 11155111), starts party B, runs the flow, and stops anvil on exit. Output (first run from an empty `.deps/` took 38 s in total; this is the re-run with the final shim):

```
== DKG (one per master key)
hd-dkg ecdsa ks-ecdsa ok in 475.293ms
== derive child key (hardened path 44/60/0 via VRF, non-hardened 0/7)
hd-derive evm-child ok in 1.752959ms
child pub  02eabca7e7ac94423dfbb3621243aa6f3dc0717ba9dd725bfb085eb52d9c10f330
child addr 0x55179DA022Bb3f18CA5cC94aCE221286bf22fedd
funded     1000000000000000000 wei on chain 11155111
MPC sign (incl. process start + connect) 67.669583ms
DER sig 30440220502076b9edc7ffe86d570c94bf5e66dab0d5a2a1ba95bb07321989ce269454c902200ca82e7150831757ccd6c08eb7e0adc722f47e3b2aa654a9c1e84b0230a4fec9 (s flipped to low-S: false)
tx 0x578a7bc9dd02ad28998cc92e452f3860ced84567087b9695391da0e0d2704ec5 mined in block 2, status 1
sender per chain  0x55179DA022Bb3f18CA5cC94aCE221286bf22fedd
derived address   0x55179DA022Bb3f18CA5cC94aCE221286bf22fedd
PASS: EIP-1559 tx signed by 2-party MPC (HD child key) mined on anvil; sender == derived address (total 797.544333ms)
```
How it maps to the plan: `cmd/party` is one party (`serve` = B; other commands = A), `cmd/ethdemo` is the Ethereum side. Both talk through the session mux over a plain local TCP socket. gRPC and mTLS are discussed, not built.

Other scripts: `verify-all.sh` (BIP32, Ed25519, BIP340, refresh, backup, crash), `bench.sh`, `backup-recovery.sh`, `crash-tests.sh`. Verification output:
```
### BIP32 xpub compatibility
account node (hardened step via VRF): pub 030c1b13e2004838112be185b70f0904c9c3486da95f7169cbdf83e232377751f8
                                      chain code 966a22781b8d0e72f60b4b900afd7790995a1063f1574f9ef80e86ea91ca00c1
xpub: xpub6BemYiVEULcbqMBEZfjbk3MAxmAN8UKsgPVKJ7uyn4LGExA5m4b1dHAJ8pRP7MoDFu2H6DQeeGNAg67wy2imjCgtFAoq2Kv43QRAP4ntrdA
path [0         ] cb-mpc 034cb4e6b7ba...  stock BIP32 034cb4e6b7ba...  match=true
path [1         ] cb-mpc 024a36227ef1...  stock BIP32 024a36227ef1...  match=true
path [0          0         ] cb-mpc 028802034fe7...  stock BIP32 028802034fe7...  match=true
path [1          5         ] cb-mpc 0202e19b61fb...  stock BIP32 0202e19b61fb...  match=true
path [0          4242      ] cb-mpc 0305a7457c98...  stock BIP32 0305a7457c98...  match=true
PASS: non-hardened children from (Q, chain code) agree with stock BIP32 CKDpub
### Ed25519 (HD) / BIP340 / ECDSA verified with standard verifiers
Ed25519 HD child pub f90ccfbec13d3e644e818f4f54d7cc798652c49c1abb2411fef87b40f4de7a4c
  sig 1c6add1998371f71e8bd7362f9694f1b2659c74dd91e45094e63088edf1b700a46c4fb75c9d08b61631d837bb97d27066d1ed360c3e39ecd175ffa15ecd0d10c
  crypto/ed25519.Verify = true
  second signature over same message identical = false (randomized)
BIP340 x-only pub a28ce7c58c2751ba8181f470e479024727ff37bb3932af7ecf5f8448f9a7075d
  sig 2eda501738bd7ed39dfb7926f29265b8dabcb7363ed06ca0084c4a625b79302a0b7e93572ddc35354a33ed358aa423641526bdf3aca71de6072bf47b7d7d7fc9
  btcec schnorr.Verify = true
ECDSA secp256k1 (plain 2PC key) btcec Verify = true
### refresh keeps the public key
hd-derive a ok in 1.785833ms
hd-refresh ks-ecdsa ok in 151.812916ms
hd-derive a ok in 1.74925ms
pubkey unchanged after refresh
== 0. offline recovery key (stays offline; only the public key is needed for backups)
backup-keygen: ek 271 bytes, dk 531 bytes (dk goes offline)
== 1. normal operation: party B (p2) with its own sealed state
hd-dkg ecdsa ks ok in 482.354333ms
hd-derive child ok in 1.837125ms
child pubkey before: 03d51b0f7fc03f70f65d878634978fadbdf137427780e61a078de1ad7e607bfd6d
sign ok in 49.397625ms
verified=true
== 2. backup of party B: only its sealed state + the PUBLIC key are used (PVE, verifiable)
backup-export: keyset blob 919 B, stripped 855 B, PVE ciphertext 49135 B; PVE verified against public share points without the decryption key
== 3. DISASTER: party B is destroyed (state AND seal key gone)
backup.dk
backup.ek
p1
p2-a.log
p2.backup.json
== 4. restore B on a fresh token/seal key from the offline key + backup file
recover: keyset "ks" rebuilt (919 B) and sealed into out/backup-demo/p2b
== 5. A re-derives the same child with the restored B and signs
hd-derive child ok in 3.633792ms
child pubkey after:  03d51b0f7fc03f70f65d878634978fadbdf137427780e61a078de1ad7e607bfd6d
pubkey identical: yes
sign ok in 53.304334ms
verified=true
PASS: B lost and restored from PVE backup; signature verifies under the original public key
verified=true
== crash inside peer: C++ abort()
crash kind=1 -> caller sees: peer connection lost
peer process: DEAD
-- peer restarted; caller signs again:
sign ok in 63.937833ms verified=true 
== crash inside peer: NULL dereference (SIGSEGV)
crash kind=2 -> caller sees: peer connection lost
peer process: DEAD
-- peer restarted; caller signs again:
sign ok in 66.158958ms verified=true 
== crash inside peer: Go panic
crash kind=3 -> caller sees: peer connection lost
peer process: DEAD
-- peer restarted; caller signs again:
sign ok in 62.153209ms verified=true 
== kill -9 the peer in the middle of a signing loop
14:04:53.3N kill -9 peer
14:04:52.982 sign #16 ok 49ms
14:04:53.032 sign #17 FAILED after 29ms: cb-mpc error 0xe000001
caller exit code 3
-- peer restarted; caller signs again:
sign ok in 65.928334ms verified=true 
== hung peer (SIGSTOP) -> caller must time out, not hang
FATAL: cb-mpc error 0xe000001
real 3.01
user 0.00
sys 0.00
== kill -9 the CALLER (p1) mid-signature; peer must survive
peer process: ALIVE
-- caller restarted:
sign ok in 52.705834ms verified=true 
== malformed protocol messages from the caller side (peer must not die)
garbage #0 (0 bytes): peer replied/err = <nil>
garbage #1 (1 bytes): peer replied/err = <nil>
garbage #2 (100 bytes): peer replied/err = <nil>
garbage #3 (4096 bytes): peer replied/err = <nil>
garbage #4 (2097152 bytes): peer replied/err = <nil>
peer process: ALIVE
sign ok in 48.572709ms verified=true 
== peer log:
	/Users/charlie/dev/quorum-vault/.claude/worktrees/wizardly-kirch-a623e2/spike/cbmpc/cmd/party/mux.go:106 +0x350
p2 session 2 op=sign failed: cb-mpc error 0xe000001
Error code -16580607
p2 session 2 op=sign failed: cb-mpc error 0x-fcffff
Error code -16711677: Converter error(read)
p2 session 4 op=sign failed: cb-mpc error 0x-fefffd
Error code -16711678
p2 session 6 op=sign failed: cb-mpc error 0x-fefffe
Error code -16711678
p2 session 8 op=sign failed: cb-mpc error 0x-fefffe
Error code -16711678
p2 session 10 op=sign failed: cb-mpc error 0x-fefffe
```

## Design for `mpc-party`

**Process model.** Two `mpc-party` processes (A and B), separate hosts, separate HSMs and operators. Only they link C++. A = coordinator: receives sign requests from the gateway and is the only party that learns the signature. B = follower. Each holds its sealed keysets; the keyset is decrypted by the HSM at start and kept in locked memory; derived key blobs are re-derived on demand (1.5 ms) or cached with a size cap.

**API (gRPC over mTLS, both directions pinned to each other's certificate).**
- `Dkg(keyset_id, curve)` (admin, A drives B)
- `Node(keyset_id, hardened_path) → {pubkey, chain_code}` for xpub export (P7, P8)
- `Derive(keyset_id, hardened_path, path) → key_id, pubkey`
- `Sign(key_id, intent, digest, job_id) → signature` (A only; idempotent on `job_id`: the first signature is stored and returned on retry)
- `Refresh(keyset_id)` (two-phase, see below)
- `BackupExport` / `Restore` (offline tooling, not a network API)
- Peer stream: `Session(stream)` carrying the same frames as the spike mux (open, data, abort, fin).

`signer.Signer` adapter in the gateway: calls A's `Sign`. The gateway code does not change.

**B must not blind-sign.** A forwards the signed intent package with the open frame; B re-verifies approver signatures and re-runs the policy and `chain.TxVerifier` against the digest *before* it starts the protocol. Without this, compromising A alone is enough to make B sign anything.

**Limits.** Per-message receive timeout (spike: 3 s; start at 5 s), total session timeout, max concurrent sessions per peer (2 × cores), max frame size (1 MiB), max sessions per second per key, unknown session IDs dropped. One thread per active session.

**What the gateway does when a signature fails.**
| Error | Action |
|---|---|
| Transport: peer gone, timeout, cancel | Retry with a fresh session up to N times with backoff; no key action; keep the sign job `signing` until one succeeds or the job's deadline passes |
| Cryptographic: `E_CRYPTO`, converter/format error, proof failure, final-verification failure | Treat as a possible malicious or corrupted peer: do not retry automatically beyond once; **freeze the keyset on both sides**, page a human; after investigation run `Refresh` (112 to 152 ms) or restore from backup. Not required by the library for `sign()`, but cheap insurance |
| `E_ECDSA_2P_BIT_LEAK` | cannot occur with the public API; if the internal global-abort variant is ever adopted, freeze the key and refresh before any further signing |
| Success | Verify signature locally (low-S, recovers to the derived address) before storing; store the first successful signature per job and re-broadcast it, never re-sign (Ed25519 and ECDSA are both randomized) |

cb-mpc already outputs low-S (`ecdsa_2p.cpp:400-401`), the demo needed no flip.

**Refresh is atomic or it is a disaster.** After a refresh the old and new shares do not mix. Refresh = two-phase: both parties write the new keyset beside the old one, exchange a commit, then switch; keep the old keyset until both confirm. Derived key blobs from before the refresh become invalid and must be re-derived (cheap).

**Backup procedure.** As in Q6: offline recovery key, per-party PVE export plus encrypted stripped blob, verified at creation, restore drill each quarter, offline key under the cold ceremony, the two parties' backups stored apart.

**Capacity.** Per ECDSA chain: 4 vCPU per party, sessions concurrency 8 to 16, parties in the same region (RTT 1 ms gives about 50 ms per signature, 20 ms RTT gives 120 ms).

## Task split for the real work (P5b)

1. **P5b-1 cb-mpc wrapper** (`internal/cbmpc` or the `mpc-party` module): the shim with `catch(...)` at every entry, the chain-code export (ECDSA and Ed25519) and the keyset split/join, Go bindings, golden tests that pin the v0.2.2 blob layout and the BIP32 vector, fetch-and-cache build script, CI job (x86_64 Linux, clang-20), a pinned-version check.
2. **P5b-2 `mpc-party` service**: proto, gRPC + mTLS peer streams, session mux, limits and timeouts, `Dkg/Node/Derive/Sign/Refresh`, cgroup and core-dump settings.
3. **P5b-3 Signer integration**: `signer.Signer` adapter, B-side intent verification, error classification, keyset freeze, idempotent sign-once-store-signature.
4. **P5b-4 HSM sealing and backup**: PKCS#11 envelope for blobs (reuse `internal/mpc/seal`), PVE backup/restore tooling, P1 Paillier-key handling, two-phase refresh, runbook and restore drill.
5. **P5b-5 Failure and load tests, GG20 swap**: kill/hang/partition tests (Toxiproxy), 50 sig/s soak on target hardware, replace GG20 in the demo path, docs.
P7 and P8 need only P5b-1 and the `Node` call.

## Risks
| Risk | Level | Note |
|---|---|---|
| Young protocol code: two ECDSA-2PC soundness bugs fixed in v0.1.1 and v0.2.2 | High | upgrade process, subscribe to advisories, re-audit read, small hot balances |
| Internal-header dependence (chain code, HD backup) | Medium | pinned version plus golden tests; ask upstream to expose both, or fork-patch with a script |
| C++ exception or crash in `mpc-party` | Medium | catch at boundary; process isolation proven; two parties give redundancy only if both are not hit by the same malformed input |
| No presigning, full protocol each time | Low | 50/s is affordable; latency is 3 round trips |
| Go heap copies of secrets, no mlock in the spike | Medium | keep blobs in C memory, wipe, no core dumps |
| Only P2 restore tested; P1 holds a Paillier private key | Medium | test P1 recovery (also after a refresh) in P5b-4 |
| Linux x86_64 not built here | Low | add CI job in P5b-1 |
| No HD for Schnorr | Medium for P7 | use P2WPKH from the ECDSA xpub, decide in P7 |
| Ed25519 and non-hardened rules are cb-mpc's own, not SLIP-0010 | Low | only our cell derives; document |
| Both parties' backups plus the offline key equal the whole key | Medium | cold ceremony, separate storage |
| Cure53 report not read | Low | read it in P5b-1 |


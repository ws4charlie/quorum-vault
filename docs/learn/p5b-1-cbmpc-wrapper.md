# P5b-1 — Wrapping cb-mpc: a separate module, a tested C boundary

P5a showed that Coinbase's cb-mpc can be our hot signer. P5b-1 turns the spike's throwaway shim into a library
with tests: its own Go module, a C++ boundary that cannot crash the process, typed errors, wipeable secrets,
golden tests that pin the parts we copied from cb-mpc's internals, and a CI job. No service yet (that is P5b-2).

## What was built

| Piece | Where | Job |
|---|---|---|
| Own Go module | [mpc-party/go.mod](../../mpc-party/go.mod) | keeps C++ and cb-mpc's libsecp256k1 away from go-ethereum and the root build |
| Pin | [mpc-party/cbmpc.pin](../../mpc-party/cbmpc.pin) | one place that says which cb-mpc commit we run |
| Build script | [fetch-build-cbmpc.sh](../../mpc-party/scripts/fetch-build-cbmpc.sh) | clone, verify the commit, build static OpenSSL + library, no sudo |
| C shim | [shim.cpp](../../mpc-party/internal/cbmpc/shim.cpp), [shim.h](../../mpc-party/internal/cbmpc/shim.h) | C ABI; `try/catch` around every entry point |
| Go API | [hd.go](../../mpc-party/internal/cbmpc/hd.go), [sign.go](../../mpc-party/internal/cbmpc/sign.go), [backup.go](../../mpc-party/internal/cbmpc/backup.go) | DKG, Refresh, Derive, NodeExport, Sign, Split/Join, PVE |
| Transport | [transport.go](../../mpc-party/internal/cbmpc/transport.go) | blocking `Send/Recv(ctx)`; context-aware, timeouts, frame cap |
| Errors | [errors.go](../../mpc-party/internal/cbmpc/errors.go) | `Transport` / `Cryptographic` / `Internal` |
| Secrets | [secret.go](../../mpc-party/internal/cbmpc/secret.go) | key material in C memory, `Wipe()` |
| Golden tests | [golden_test.go](../../mpc-party/internal/cbmpc/golden_test.go), [testdata/golden.json](../../mpc-party/internal/cbmpc/testdata/golden.json) | pin the blob layout and the chain-code derivation |
| CI job | [ci.yml](../../.github/workflows/ci.yml) `mpc-party` | build with cache, `go vet`, `go test -race`, short fuzz |

## Why a separate Go module

cb-mpc ships its own copy of libsecp256k1 (a Coinbase fork). go-ethereum links a different copy through cgo. Both
export symbols with the same names (`secp256k1_ecmult_gen_prec_table`, `secp256k1_pre_g`, ...), so one binary that
contains both fails to link. Two ways out: a separate process, or a separate module that never meets go-ethereum.
We do both: `mpc-party/` has its own `go.mod`, the root module never imports it, and
[isolation_test.go](../../mpc-party/internal/cbmpc/isolation_test.go) fails if go-ethereum ever enters its dependency
graph. The side effect is the one we wanted anyway: the root `go build ./...` and the `test` and `e2e` CI jobs need no
C++ compiler.

## Lindell17 and what the proofs check

Two-party ECDSA here is a Lindell-2017-style protocol. P1 holds a share `x1`, P2 holds `x2`; the public key is the sum of
the two public shares (cb-mpc's HD step adds `delta` to P1's share, so the sharing is additive). P1 also has a Paillier
key pair and sends `c_key = Enc(x1)` to P2. To sign, P2 computes on the ciphertext (homomorphically) and P1 decrypts.
P2 never learns `x1`. The danger is that P1 can lie about the ciphertext, and P2 can lie in its computation:
if the other side does not check, every failed signature leaks a bit of the key (the BitForge attacks on other
implementations). cb-mpc's checks, which is why we only ever call the public `sign()`:

- the Paillier modulus has the right size, no small factors, and P1 proves it is a valid key (zero knowledge);
- `c_key` really encrypts the discrete log of P1's public share (PDL proof);
- it encrypts the same value as a commitment and that value is in range `[0, q)` (range proof);
- when signing, P2 proves its homomorphic message is well formed (range checks on every response);
- the final signature is verified against the public key before it is returned.

The faster `sign_with_global_abort` skips some of these and leaks one bit when a cheat is detected. It is internal and
the shim never calls it ([shim.cpp `qv_2p_sign`](../../mpc-party/internal/cbmpc/shim.cpp)). Even so, the library had two
soundness bugs in exactly this protocol, fixed in v0.1.1 (keygen) and v0.2.2 (signing): hence the pin and
[UPSTREAM_REVIEW.md](../../mpc-party/UPSTREAM_REVIEW.md).

## How HD works here

BIP32 hardened derivation needs the private key of the parent. Nobody holds it, so cb-mpc replaces it with a
distributed VRF. The keyset holds a second shared secret `K` (shares `k1`, `k2`). For a "hardened path" (any list of
`uint32`, hashed to a curve point `P`) both parties compute `Z = k·P` together, each proving with a Diffie-Hellman
equality proof that its half is honest. `Z` is hashed into a scalar `delta` and a 32-byte **chain code**. The node's
public key is `Q + delta·G`. That step needs both parties online. Below it, derivation is plain BIP32 CKDpub:
`HMAC-SHA512(chain_code, pubkey || index)`, `child = parent + I_L·G`.

Consequences, all tested in [bip32_test.go](../../mpc-party/internal/cbmpc/bip32_test.go):

- `(node public key, chain code)` is an xpub. Anyone derives all non-hardened child public keys without MPC. Children
  equal what `Derive` returns, checked against btcutil's `hdkeychain` and against a 20-line pure-Go CKDpub.
- The hardened path is cb-mpc's own vector of `uint32`, not BIP32's `index + 2^31` arithmetic, and the master is not a
  BIP32 seed: you cannot import a hardware wallet's `m/44'/60'/0'`.
- Ed25519 uses the same rule on Edwards points (not SLIP-0010). Only our own cell can derive Solana children.
- The public API does not return the chain code. [qv_hd_node](../../mpc-party/internal/cbmpc/shim.cpp) copies the VRF step
  from cb-mpc's internals to get it. That is why the golden tests exist.

## The C boundary

`cb_assert` in cb-mpc **throws** a C++ exception, and the HD API does not catch it. An exception that unwinds into cgo
calls `std::terminate`: the process dies. Every `qv_*` function sits between `QV_TRY` and `QV_CATCH`
([shim.cpp:41](../../mpc-party/internal/cbmpc/shim.cpp)), which turn `bad_alloc`, `assertion_failed_t`, other
`std::exception` and `catch (...)` into error codes. The spike could not trigger a throw; now
`TestBoundaryCatchesExceptions` calls a test-only entry that throws each kind, and `TestAssertionInsideLibraryIsCaught`
flips bytes in a P1 backup blob until cb-mpc's own Paillier code asserts. The malicious-peer test also provoked asserts
through flipped protocol bytes, so the boundary matters for real.

Go callbacks from C++ (`Send`, `Recv`) recover from panics too: a Go panic must not unwind through C++ frames.

## Error classes

| Kind | Typical causes | What P5b-3 does |
|---|---|---|
| `Transport` | peer gone, timeout, context cancelled | retry with a fresh session; keys are fine |
| `Cryptographic` | proof failed, message did not parse, frame too large, final signature check, C++ assert on peer data | freeze the keyset, page a human |
| `Internal` | bad argument, wiped secret, layout mismatch, out of memory | alert, no blind retry |

The classification is made in Go ([errors.go classify](../../mpc-party/internal/cbmpc/errors.go)) from what the Go side
saw (a transport error it recorded wins over the numeric code) and the cb-mpc error category in bits 16-23 of the code.

## Backup

A keyset is `(x, k)` plus public data and, for P1, a Paillier key. `Split` takes `x mod q` and `k` out as 32-byte
scalars and returns a stripped blob. PVE (publicly verifiable encryption) encrypts the scalars to an offline RSA key
and produces a ciphertext that **anyone can check against the public points** `x·G` and `k·G` without the private key.
Restore decrypts, checks the points again and joins.

The trap is P1 after a `Refresh`. Its `x` is kept as an integer that can exceed `q` (it is the Paillier plaintext), PVE
only sees `x mod q`, and the stripped blob still contains the Paillier private key and `c_key`. `Join` decrypts
`c_key` to get the exact `x` and requires it to match. So P1's stripped blob must be protected like the whole keyset,
and ciphertext and stripped blob must be from the same refresh version (tests for both:
[backup_test.go](../../mpc-party/internal/cbmpc/backup_test.go)).

## Gotchas hit

- cb-mpc writes every error to stderr by default; a hostile peer can spam it. The shim installs a no-op log hook.
- A tampered Refresh message can leave **both** sides reporting success with shares that do not work together. Use
  `SelfTest` on every new share set before dropping the old one ([hd.go SelfTest](../../mpc-party/internal/cbmpc/hd.go)).
- P2 never sees the signature, so P2's success tells nothing about whether a signature exists.
- A completion ack matters: the first version of the two-process test raced because the parent moved on before
  process B stored its result.
- The upstream OpenSSL script downloads into `/tmp`; our build script runs a copy that uses a private work directory.
- `go test` flags like `-update-golden` must come after the package path.

## Quiz

1. Why can't the root module just import this wrapper?
2. What does an uncaught C++ exception do inside a cgo call, and where do we stop it?
3. What is a "chain code" and why does the public cb-mpc API not give it to us?
4. Why do we never call `sign_with_global_abort`?
5. What does the PDL proof in Lindell17 convince P2 of?
6. After a refresh, P1's exact share can be larger than the curve order. Where does the exact value come from on restore?
7. Which party receives the ECDSA signature, and what does a `nil` error from the other party prove?
8. A peer flips one byte in a Refresh message. Both parties return no error. What do you do before deleting the old shares?
9. Which golden test fails if cb-mpc reorders the fields of its keyset blob, and what does the message tell you to read?
10. How is an error classified as `Cryptographic` versus `Transport` when the C++ code only returns a number?

<details>
<summary>Answers</summary>

1. cb-mpc's vendored libsecp256k1 and go-ethereum's cgo copy export the same symbols; one binary with both does not
   link, and the root build must stay free of C++.
2. It calls `std::terminate` and kills the process. Every shim entry point catches it (`QV_TRY`/`QV_CATCH`) and returns a code.
3. 32 bytes that, with the node's public key, make an xpub so anyone can derive non-hardened children. The public API
   computes it inside the hardened step and discards it; we copy that step from the internal headers.
4. It skips proofs and leaks a bit of the key when a cheat is detected. Only the default `sign()` runs the full proofs.
5. That `c_key` encrypts the discrete log of P1's public share: P1 cannot feed P2 a ciphertext of something else.
6. From decrypting `c_key` with the Paillier private key kept in P1's stripped blob; PVE carries only `x mod q`.
7. P1. P2's `nil` only says the protocol ran, not that a valid signature exists.
8. Run `SelfTest` on the new shares (P1 checks the signature and tells P2); only then drop the old shares.
9. `TestGolden/*` (join(split(blob)) not byte-identical, scalars not where expected). The message names the upstream
   files `src/cbmpc/api/hd_keyset_*_2p.cpp` and `src/cbmpc/protocol/hd_keyset_*_2p.cpp` and points to the README upgrade steps.
10. The Go session records what it saw first (context cancel, transport error, oversize frame); otherwise the cb-mpc
    category in the code decides (network = transport, crypto = cryptographic, everything raised on peer data during a
    protocol = cryptographic, local failures = internal).

</details>
